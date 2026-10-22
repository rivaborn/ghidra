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
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.ByteProvider;

/**
 * Read-only view of the data area of a Saturn / Dreamcast disc image (or of a bare IP.BIN):
 * 2048-byte user-data sectors ({@code .iso}, Dreamcast GD-ROM high-density {@code track03.iso},
 * a bare IP.BIN) or raw 2352-byte sectors ({@code .bin}, {@code track03.bin}) with the 12-byte
 * sync pattern 00 FF*10 00 at offset 0, Mode 1 (user data at +16) or Mode 2 Form 1 (user data at
 * +24), chosen by the mode byte at +15.
 * <p>
 * Also locates a file in the ISO 9660 root directory. Directory extents are absolute disc LBAs,
 * while the image may start at a later LBA (GD-ROM track 3 starts at LBA 45000, a MIL-CD data
 * session usually at 11702); the image's start LBA is found by trying 0, 45000, 11702 and 150
 * and keeping the first one at which the root directory's first record is "." pointing to the
 * root extent itself.
 */
public class SegaDiscImage {

	public static final int SECTOR = 2048;

	private final ByteProvider provider;
	private final int rawSize; // 2048 or 2352
	private final int dataOffset; // 0, 16 or 24

	public SegaDiscImage(ByteProvider provider) throws IOException {
		this.provider = provider;
		byte[] head = SegaLoaderBase.read(provider, 0, 16);
		boolean sync = head.length == 16 && head[0] == 0 && head[11] == 0;
		for (int i = 1; sync && i < 11; i++) {
			sync = (head[i] & 0xff) == 0xff;
		}
		if (sync) {
			rawSize = 2352;
			dataOffset = head[15] == 2 ? 24 : 16;
		}
		else {
			rawSize = 2048;
			dataOffset = 0;
		}
	}

	/** File offset of the user data of the boot area (where "SEGA SEGA..." must be). */
	public static long bootDataOffset(ByteProvider provider) throws IOException {
		return new SegaDiscImage(provider).dataOffset;
	}

	public boolean isRaw() {
		return rawSize == 2352;
	}

	public long sectorCount() throws IOException {
		return provider.length() / rawSize;
	}

	/** Reads {@code length} bytes of user data starting at user-data byte {@code offset}. */
	public byte[] read(long offset, int length) throws IOException {
		if (!isRaw()) {
			return SegaLoaderBase.read(provider, offset, length);
		}
		byte[] out = new byte[length];
		int done = 0;
		while (done < length) {
			long pos = offset + done;
			long sector = pos / SECTOR;
			int in = (int) (pos % SECTOR);
			int n = Math.min(SECTOR - in, length - done);
			long file = sector * rawSize + dataOffset + in;
			if (file + n > provider.length()) {
				byte[] b = new byte[done];
				System.arraycopy(out, 0, b, 0, done);
				return b;
			}
			System.arraycopy(provider.readBytes(file, n), 0, out, done, n);
			done += n;
		}
		return out;
	}

	/** Location of a file in the image: user-data offset and length. */
	public record Entry(String name, long offset, long length, long lba, long baseLba) {}

	/**
	 * Finds a file in the root directory; {@code name == null} returns the first file record
	 * (not a directory, not "." / ".."), which is the Saturn boot ROM's first read file.
	 */
	public Entry findRootFile(String name) throws IOException {
		byte[] pvd = read(16L * SECTOR, SECTOR);
		if (pvd.length < 190 || pvd[0] != 1 || !new String(pvd, 1, 5, StandardCharsets.US_ASCII)
				.equals("CD001")) {
			return null;
		}
		long rootLba = SegaLoaderBase.u32le(pvd, 156 + 2);
		long rootLen = SegaLoaderBase.u32le(pvd, 156 + 10);
		for (long base : new long[] { 0, 45000, 11702, 150 }) {
			if (rootLba < base) {
				continue;
			}
			byte[] dir = read((rootLba - base) * SECTOR, (int) Math.min(rootLen, 0x10000));
			if (dir.length < 34 || dir[0] == 0 || dir[32] != 1 || dir[33] != 0 ||
				SegaLoaderBase.u32le(dir, 2) != rootLba) {
				continue;
			}
			int p = 0;
			while (p + 33 < dir.length) {
				int len = dir[p] & 0xff;
				if (len == 0) { // records do not cross sectors: skip to the next sector
					p = (p / SECTOR + 1) * SECTOR;
					continue;
				}
				int nameLen = dir[p + 32] & 0xff;
				boolean isDir = (dir[p + 25] & 2) != 0;
				if (p + 33 + nameLen > dir.length) {
					break;
				}
				String n = new String(dir, p + 33, nameLen, StandardCharsets.ISO_8859_1);
				int semi = n.indexOf(';');
				if (semi >= 0) {
					n = n.substring(0, semi);
				}
				if (n.endsWith(".")) {
					n = n.substring(0, n.length() - 1);
				}
				boolean special = nameLen == 1 && (dir[p + 33] == 0 || dir[p + 33] == 1);
				if (!special && !isDir && (name == null || n.equalsIgnoreCase(name.trim()))) {
					long lba = SegaLoaderBase.u32le(dir, p + 2);
					long size = SegaLoaderBase.u32le(dir, p + 10);
					return new Entry(n, (lba - base) * SECTOR, size, lba, base);
				}
				p += len;
			}
			return null;
		}
		return null;
	}
}
