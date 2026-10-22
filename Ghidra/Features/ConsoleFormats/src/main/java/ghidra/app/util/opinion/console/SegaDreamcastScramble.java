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

/**
 * The Dreamcast boot ROM's 1ST_READ.BIN scrambling, used when a disc boots as a MIL-CD
 * (CD-R "self-boot" discs): the boot ROM reads the file in 32-byte slices and scatters them
 * through a pseudo-random permutation, so the file on disc must be stored scrambled.
 * <p>
 * Algorithm: a 16-bit seed is set to the file size (low 16 bits). The file is processed in
 * chunks: as many 2 MB chunks as fit, then the chunk size halves (1 MB, 512 KB, ... 32 bytes),
 * each size used while the remaining size allows; a final tail shorter than 32 bytes is copied
 * unchanged. Within a chunk of n slices an index table idx[i] = i is shuffled from the top:
 * for i = n-1 down to 0, x = (rand() * i) &gt;&gt; 16, swap idx[i] and idx[x], and the next 32
 * bytes of the stored (scrambled) file go to slice idx[i] of the chunk. rand() is
 * seed = (seed * 2109 + 9273) &amp; 0x7FFF; return (seed + 0xC000) &amp; 0xFFFF.
 */
public final class SegaDreamcastScramble {

	private static final int MAXCHUNK = 2048 * 1024;
	private static final int SLICE = 32;

	private int seed;

	private SegaDreamcastScramble(int size) {
		seed = size & 0xffff;
	}

	private int rand() {
		seed = (seed * 2109 + 9273) & 0x7fff;
		return (seed + 0xc000) & 0xffff;
	}

	/** Descrambles a stored (scrambled) 1ST_READ.BIN into the image the boot ROM runs. */
	public static byte[] descramble(byte[] stored) {
		return run(stored, true);
	}

	/** Inverse of {@link #descramble}: what a self-boot disc stores. */
	public static byte[] scramble(byte[] plain) {
		return run(plain, false);
	}

	private static byte[] run(byte[] in, boolean descramble) {
		SegaDreamcastScramble r = new SegaDreamcastScramble(in.length);
		byte[] out = new byte[in.length];
		int base = 0; // chunk start in the plain image
		int seq = 0; // sequential position in the stored file
		int remaining = in.length;
		for (int chunk = MAXCHUNK; chunk >= SLICE; chunk >>= 1) {
			while (remaining >= chunk) {
				int n = chunk / SLICE;
				int[] idx = new int[n];
				for (int i = 0; i < n; i++) {
					idx[i] = i;
				}
				for (int i = n - 1; i >= 0; i--) {
					int x = (int) (((long) r.rand() * i) >> 16);
					int t = idx[i];
					idx[i] = idx[x];
					idx[x] = t;
					int plainPos = base + SLICE * idx[i];
					if (descramble) {
						System.arraycopy(in, seq, out, plainPos, SLICE);
					}
					else {
						System.arraycopy(in, plainPos, out, seq, SLICE);
					}
					seq += SLICE;
				}
				base += chunk;
				remaining -= chunk;
			}
		}
		System.arraycopy(in, seq, out, base, remaining); // tail (< 32 bytes), seq == base here
		return out;
	}

	/**
	 * Code-likeness score of a little-endian SH-4 image that depends on byte order across
	 * 32-byte slices (a plain opcode count would not: scrambling permutes whole slices and keeps
	 * every aligned word). Counts, in the first 256 KB, the PC-relative loads
	 * {@code mov.l @(disp,PC),Rn} (0xDnnn) whose literal (at (pc &amp; ~3) + 4 + disp*4) is a
	 * plausible Dreamcast pointer: 0x8Cxxxxxx / 0x0Cxxxxxx / 0xACxxxxxx (system RAM) or
	 * 0xA0000000-0xA5FFFFFF (hardware, VRAM).
	 */
	public static int score(byte[] image) {
		int n = Math.min(image.length, 0x40000) & ~1;
		int s = 0;
		for (int i = 0; i < n; i += 2) {
			int w = (image[i] & 0xff) | ((image[i + 1] & 0xff) << 8);
			if ((w & 0xF000) != 0xD000) {
				continue;
			}
			int t = (i & ~3) + 4 + (w & 0xff) * 4;
			if (t + 4 > image.length) {
				continue;
			}
			long v = (image[t] & 0xffL) | ((image[t + 1] & 0xffL) << 8) |
				((image[t + 2] & 0xffL) << 16) | ((image[t + 3] & 0xffL) << 24);
			int top = (int) (v >>> 24);
			if (top == 0x8C || top == 0x0C || top == 0xAC || (v >= 0xA0000000L && v < 0xA6000000L)) {
				s++;
			}
		}
		return s;
	}

	/**
	 * Heuristic: the file is scrambled when its descrambled form scores more than 1.25 times the
	 * stored form plus 8 (see {@link #score}). Files under 64 bytes are never called scrambled.
	 */
	public static boolean looksScrambled(byte[] stored) {
		if (stored.length < 64) {
			return false;
		}
		int plain = score(stored);
		int desc = score(descramble(stored));
		return desc * 4 > plain * 5 + 32;
	}
}
