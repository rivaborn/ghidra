/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.opinion.console;

import java.io.IOException;

/**
 * Decoder for Microsoft LZX (the CAB / XCompress variant used by XEX "normal" compression):
 * a stream of 32 KB frames, 16-bit little-endian bit words read most-significant bit first,
 * verbatim, aligned-offset and uncompressed blocks, Huffman tree lengths sent as deltas through
 * a 20-symbol pretree, repeated-offset registers R0-R2, and the optional x86 E8 call
 * translation announced by the stream's first bit.
 */
public final class XexLzxDecoder {

	private static final int MIN_MATCH = 2;
	private static final int NUM_CHARS = 256;
	private static final int NUM_PRIMARY_LENGTHS = 7;
	private static final int NUM_SECONDARY_LENGTHS = 249;
	private static final int PRETREE_SYMBOLS = 20;
	private static final int ALIGNED_SYMBOLS = 8;
	private static final int FRAME_SIZE = 32768;
	private static final int BLOCK_VERBATIM = 1, BLOCK_ALIGNED = 2, BLOCK_UNCOMPRESSED = 3;
	private static final int[] POSITION_SLOTS = { 30, 32, 34, 36, 38, 42, 50 };
	private static final int[] EXTRA_BITS = new int[51];
	private static final int[] POSITION_BASE = new int[51];

	static {
		for (int i = 0, j = 0; i < 51; i += 2) {
			EXTRA_BITS[i] = j;
			if (i + 1 < 51) {
				EXTRA_BITS[i + 1] = j;
			}
			if (i != 0 && j < 17) {
				j++;
			}
		}
		for (int i = 0, j = 0; i < 51; i++) {
			POSITION_BASE[i] = j;
			j += 1 << EXTRA_BITS[i];
		}
	}

	// input
	private final byte[] in;
	private int inPos;
	private final int inEnd;
	private long bitBuffer; // bits are kept left-aligned in the low 32+16 bits
	private int bitsLeft;

	// window
	private final int windowSize;
	private final byte[] window;
	private final int mainElements;

	private XexLzxDecoder(byte[] in, int off, int len, int windowBits) {
		this.in = in;
		this.inPos = off;
		this.inEnd = off + len;
		this.windowSize = 1 << windowBits;
		this.window = new byte[windowSize];
		this.mainElements = NUM_CHARS + (POSITION_SLOTS[windowBits - 15] << 3);
	}

	/**
	 * Decompresses an LZX stream.
	 *
	 * @param in compressed bytes (for XEX: the chunks of all blocks, concatenated)
	 * @param off start offset in {@code in}
	 * @param len compressed length
	 * @param windowSize LZX window size in bytes (power of two, 32 KB .. 2 MB)
	 * @param outLength number of bytes to produce
	 * @return the decompressed bytes
	 * @throws IOException if the stream is malformed
	 */
	public static byte[] decompress(byte[] in, int off, int len, int windowSize, int outLength)
			throws IOException {
		int bits = Integer.numberOfTrailingZeros(windowSize);
		if (Integer.bitCount(windowSize) != 1 || bits < 15 || bits > 21) {
			throw new IOException("LZX window size " + windowSize + " not supported (32 KB-2 MB)");
		}
		return new XexLzxDecoder(in, off, len, bits).run(outLength);
	}

	// ---- bit input (16-bit little-endian words, MSB first)

	private void readWord() {
		int b0 = inPos < inEnd ? in[inPos] & 0xff : 0;
		int b1 = inPos + 1 < inEnd ? in[inPos + 1] & 0xff : 0;
		inPos += 2;
		bitBuffer |= ((long) ((b1 << 8) | b0)) << (48 - 16 - bitsLeft);
		bitsLeft += 16;
	}

	private void ensure(int n) {
		while (bitsLeft < n) {
			readWord();
		}
	}

	private int peek(int n) {
		return (int) ((bitBuffer >>> (48 - n)) & ((1L << n) - 1));
	}

	private void remove(int n) {
		bitBuffer = (bitBuffer << n) & 0xFFFFFFFFFFFFL;
		bitsLeft -= n;
	}

	private int readBits(int n) {
		if (n == 0) {
			return 0;
		}
		ensure(n);
		int v = peek(n);
		remove(n);
		return v;
	}

	private void checkInput() throws IOException {
		if (inPos > inEnd + 4) {
			throw new IOException("LZX: compressed data overrun");
		}
	}

	// ---- canonical Huffman

	private static final class Tree {
		final int[] count = new int[17];
		final int[] firstCode = new int[17];
		final int[] firstIndex = new int[17];
		int[] sorted;
		boolean empty;

		void build(byte[] lens, int n) throws IOException {
			java.util.Arrays.fill(count, 0);
			for (int i = 0; i < n; i++) {
				count[lens[i]]++;
			}
			count[0] = 0;
			int total = 0;
			for (int l = 1; l <= 16; l++) {
				total += count[l];
			}
			empty = total == 0;
			if (empty) {
				return;
			}
			int code = 0, idx = 0;
			long space = 0;
			for (int l = 1; l <= 16; l++) {
				code = (code + (l > 1 ? count[l - 1] : 0)) << (l > 1 ? 1 : 0);
				firstCode[l] = code;
				firstIndex[l] = idx;
				idx += count[l];
				space += (long) count[l] << (16 - l);
			}
			if (space > 1L << 16) {
				throw new IOException("LZX: over-subscribed Huffman table");
			}
			sorted = new int[total];
			int[] next = new int[17];
			for (int l = 1; l <= 16; l++) {
				next[l] = firstIndex[l];
			}
			for (int i = 0; i < n; i++) {
				if (lens[i] != 0) {
					sorted[next[lens[i]]++] = i;
				}
			}
		}
	}

	private int decode(Tree t) throws IOException {
		if (t.empty) {
			throw new IOException("LZX: symbol from an empty Huffman table");
		}
		ensure(16);
		int bits = peek(16);
		for (int l = 1; l <= 16; l++) {
			int code = bits >>> (16 - l);
			int d = code - t.firstCode[l];
			if (d >= 0 && d < t.count[l]) {
				remove(l);
				return t.sorted[t.firstIndex[l] + d];
			}
		}
		throw new IOException("LZX: invalid Huffman code");
	}

	// ---- tree lengths

	private final byte[] pretreeLen = new byte[PRETREE_SYMBOLS];
	private final Tree pretree = new Tree();

	private void readLengths(byte[] lens, int first, int last) throws IOException {
		for (int i = 0; i < PRETREE_SYMBOLS; i++) {
			pretreeLen[i] = (byte) readBits(4);
		}
		pretree.build(pretreeLen, PRETREE_SYMBOLS);
		int x = first;
		while (x < last) {
			int z = decode(pretree);
			if (z == 17) {
				int y = readBits(4) + 4;
				while (y-- > 0 && x < last) {
					lens[x++] = 0;
				}
			}
			else if (z == 18) {
				int y = readBits(5) + 20;
				while (y-- > 0 && x < last) {
					lens[x++] = 0;
				}
			}
			else if (z == 19) {
				int y = readBits(1) + 4;
				z = decode(pretree);
				int v = lens[x] - z;
				if (v < 0) {
					v += 17;
				}
				while (y-- > 0 && x < last) {
					lens[x++] = (byte) v;
				}
			}
			else {
				int v = lens[x] - z;
				if (v < 0) {
					v += 17;
				}
				lens[x++] = (byte) v;
			}
		}
	}

	// ---- main loop

	private byte[] run(int outLength) throws IOException {
		byte[] out = new byte[outLength];
		byte[] mainLen = new byte[mainElements];
		byte[] lengthLen = new byte[NUM_SECONDARY_LENGTHS];
		byte[] alignedLen = new byte[ALIGNED_SYMBOLS];
		Tree mainTree = new Tree(), lengthTree = new Tree(), alignedTree = new Tree();
		int r0 = 1, r1 = 1, r2 = 1;
		int blockType = 0, blockLength = 0, blockRemaining = 0;
		boolean intelStarted = false;
		int intelFileSize = 0, intelCurPos = 0;
		int windowPosn = 0, framePosn = 0, outPos = 0, frame = 0;

		// stream header: E8 translation flag and file size
		if (readBits(1) == 1) {
			int hi = readBits(16), lo = readBits(16);
			intelFileSize = (hi << 16) | lo;
		}

		while (outPos < outLength) {
			int frameSize = Math.min(FRAME_SIZE, outLength - outPos);
			int bytesTodo = framePosn + frameSize - windowPosn;
			while (bytesTodo > 0) {
				if (blockRemaining == 0) {
					if (blockType == BLOCK_UNCOMPRESSED && (blockLength & 1) != 0) {
						inPos++; // pad byte after an odd-length uncompressed block
					}
					blockType = readBits(3);
					int hi = readBits(16), lo = readBits(8);
					blockRemaining = blockLength = (hi << 8) | lo;
					switch (blockType) {
						case BLOCK_ALIGNED:
							for (int i = 0; i < ALIGNED_SYMBOLS; i++) {
								alignedLen[i] = (byte) readBits(3);
							}
							alignedTree.build(alignedLen, ALIGNED_SYMBOLS);
							// fall through
						case BLOCK_VERBATIM:
							readLengths(mainLen, 0, NUM_CHARS);
							readLengths(mainLen, NUM_CHARS, mainElements);
							mainTree.build(mainLen, mainElements);
							if (mainLen[0xE8] != 0) {
								intelStarted = true;
							}
							readLengths(lengthLen, 0, NUM_SECONDARY_LENGTHS);
							lengthTree.build(lengthLen, NUM_SECONDARY_LENGTHS);
							break;
						case BLOCK_UNCOMPRESSED:
							intelStarted = true;
							// align to the next 16-bit word (1-16 bits are skipped)
							if (bitsLeft == 0) {
								ensure(16);
							}
							bitsLeft = 0;
							bitBuffer = 0;
							if (inPos + 12 > inEnd) {
								throw new IOException("LZX: truncated uncompressed block");
							}
							r0 = le32(in, inPos);
							r1 = le32(in, inPos + 4);
							r2 = le32(in, inPos + 8);
							inPos += 12;
							break;
						default:
							throw new IOException("LZX: bad block type " + blockType);
					}
				}
				checkInput();

				int thisRun = Math.min(blockRemaining, bytesTodo);
				bytesTodo -= thisRun;
				blockRemaining -= thisRun;

				if (blockType == BLOCK_UNCOMPRESSED) {
					if (inPos + thisRun > inEnd) {
						throw new IOException("LZX: truncated uncompressed data");
					}
					System.arraycopy(in, inPos, window, windowPosn, thisRun);
					inPos += thisRun;
					windowPosn += thisRun;
					thisRun = 0;
				}
				while (thisRun > 0) {
					int sym = decode(mainTree);
					if (sym < NUM_CHARS) {
						window[windowPosn++] = (byte) sym;
						thisRun--;
						continue;
					}
					sym -= NUM_CHARS;
					int matchLength = sym & NUM_PRIMARY_LENGTHS;
					if (matchLength == NUM_PRIMARY_LENGTHS) {
						matchLength += decode(lengthTree);
					}
					matchLength += MIN_MATCH;
					int slot = sym >>> 3;
					int matchOffset;
					switch (slot) {
						case 0:
							matchOffset = r0;
							break;
						case 1:
							matchOffset = r1;
							r1 = r0;
							r0 = matchOffset;
							break;
						case 2:
							matchOffset = r2;
							r2 = r0;
							r0 = matchOffset;
							break;
						case 3:
							matchOffset = 1;
							r2 = r1;
							r1 = r0;
							r0 = matchOffset;
							break;
						default: {
							int extra = slot >= 36 ? 17 : EXTRA_BITS[slot];
							matchOffset = POSITION_BASE[slot] - 2;
							if (blockType == BLOCK_ALIGNED) {
								if (extra > 3) {
									matchOffset += readBits(extra - 3) << 3;
									matchOffset += decode(alignedTree);
								}
								else if (extra == 3) {
									matchOffset += decode(alignedTree);
								}
								else if (extra > 0) {
									matchOffset += readBits(extra);
								}
								else {
									matchOffset = 1;
								}
							}
							else {
								matchOffset += readBits(extra);
							}
							r2 = r1;
							r1 = r0;
							r0 = matchOffset;
						}
					}
					if (windowPosn + matchLength > windowSize) {
						throw new IOException("LZX: match runs past the window");
					}
					if (matchOffset <= 0 || matchOffset > windowSize) {
						throw new IOException("LZX: bad match offset " + matchOffset);
					}
					int src = windowPosn - matchOffset;
					if (src < 0) {
						src += windowSize;
					}
					for (int i = 0; i < matchLength; i++) {
						window[windowPosn++] = window[src];
						src = (src + 1) & (windowSize - 1);
					}
					thisRun -= matchLength;
				}
				if (thisRun < 0) {
					if (-thisRun > blockRemaining) {
						throw new IOException("LZX: match overruns the block");
					}
					blockRemaining += thisRun;
				}
			}
			if (windowPosn - framePosn != frameSize) {
				throw new IOException("LZX: frame did not end on a frame boundary");
			}
			// re-align the bit stream to 16 bits at the end of each frame
			if (bitsLeft > 0) {
				ensure(16);
			}
			if ((bitsLeft & 15) != 0) {
				remove(bitsLeft & 15);
			}

			System.arraycopy(window, framePosn, out, outPos, frameSize);
			if (intelStarted && intelFileSize != 0 && frame <= 32768 && frameSize > 10) {
				undoE8(out, outPos, frameSize, intelCurPos, intelFileSize);
			}
			intelCurPos += frameSize;
			outPos += frameSize;
			framePosn += frameSize;
			if (framePosn == windowSize) {
				framePosn = 0;
			}
			if (windowPosn == windowSize) {
				windowPosn = 0;
			}
			frame++;
		}
		return out;
	}

	private static void undoE8(byte[] b, int start, int size, int curPos, int fileSize) {
		int p = start, end = start + size - 10;
		while (p < end) {
			if ((b[p++] & 0xff) != 0xE8) {
				curPos++;
				continue;
			}
			int abs = le32(b, p);
			if (abs >= -curPos && abs < fileSize) {
				int rel = abs >= 0 ? abs - curPos : abs + fileSize;
				b[p] = (byte) rel;
				b[p + 1] = (byte) (rel >>> 8);
				b[p + 2] = (byte) (rel >>> 16);
				b[p + 3] = (byte) (rel >>> 24);
			}
			p += 4;
			curPos += 5;
		}
	}

	private static int le32(byte[] b, int o) {
		return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8) | ((b[o + 2] & 0xff) << 16) |
			((b[o + 3] & 0xff) << 24);
	}
}
