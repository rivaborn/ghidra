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

import static ghidra.app.util.opinion.console.MicroFormatsSupport.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;

/**
 * Xbox 360 executable (XEX2). The optional headers give the base address, entry point, import
 * libraries and the file format (encryption none/AES, compression none/basic/normal LZX). The
 * image is decrypted when a key file is supplied (the file's session key is decrypted with the
 * supplied key, then the image with AES-128-CBC, IV 0), decompressed, and its PE sections are
 * mapped at the base address. Imports become xboxkrnl.exe / xam.xex ... externals by ordinal.
 * <p>
 * Keys are never stored in the program, the log or the repository: they are read from the file
 * named by the loader option or by the {@code XEX_KEYS_FILE} environment variable (one 32-hex-
 * digit key per line, '#' comments allowed, or a raw binary file of 16-byte keys) and only the
 * index of the key that worked is recorded.
 */
public class Xex2Loader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Xbox 360 Executable (XEX2)";
	static final LanguageCompilerSpecPair LANG =
		new LanguageCompilerSpecPair("PowerPC:BE:64:64-32addr", "default");
	public static final String OPT_KEY_FILE = "XEX2 key file";
	public static final String OPT_EXPORT_NAMES = "Xbox export names file";
	static final String ENV_KEYS = "XEX_KEYS_FILE";
	static final String ENV_EXPORT_NAMES = "XBOX_EXPORT_NAMES";

	static final int KEY_FILE_FORMAT = 0x000003FF;
	static final int KEY_ENTRY_POINT = 0x00010100;
	static final int KEY_IMAGE_BASE = 0x00010201;
	static final int KEY_ORIGINAL_BASE = 0x00010001;
	static final int KEY_IMPORT_LIBRARIES = 0x000103FF;
	static final int KEY_ORIGINAL_PE_NAME = 0x000183FF;
	static final int KEY_STATIC_LIBRARIES = 0x000200FF;
	static final int KEY_TLS_INFO = 0x00020104;
	static final int KEY_STACK_SIZE = 0x00020200;
	static final int KEY_SYSTEM_FLAGS = 0x00030000;
	static final int KEY_EXECUTION_INFO = 0x00040006;

	/** Parsed XEX2 header. */
	static final class Header {
		long moduleFlags, peOffset, securityOffset;
		final Map<Integer, Long> opt = new LinkedHashMap<>();

		long imageSize, loadAddress;
		byte[] fileKey = new byte[16];

		int encryption, compression;
		long windowSize, firstBlockSize;
		byte[] firstBlockHash = new byte[20];
		final List<long[]> basicBlocks = new ArrayList<>();

		boolean has(int key) {
			return opt.containsKey(key);
		}

		long get(int key) {
			return opt.get(key);
		}
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 0;
	}

	static Header parseHeader(byte[] f) throws IOException {
		if (f.length < 0x18 || f[0] != 'X' || f[1] != 'E' || f[2] != 'X' || f[3] != '2') {
			throw new IOException("not XEX2");
		}
		Header h = new Header();
		h.moduleFlags = u32be(f, 4);
		h.peOffset = u32be(f, 8);
		h.securityOffset = u32be(f, 0x10);
		long count = u32be(f, 0x14);
		if (h.peOffset > f.length || h.securityOffset + 0x184 > f.length || count > 256 ||
			0x18 + count * 8 > f.length) {
			throw new IOException("XEX2 header offsets out of range");
		}
		for (int i = 0; i < count; i++) {
			int key = (int) u32be(f, 0x18 + i * 8);
			h.opt.put(key, u32be(f, 0x18 + i * 8 + 4));
		}
		int s = (int) h.securityOffset;
		h.imageSize = u32be(f, s + 4);
		h.loadAddress = u32be(f, s + 0x110);
		System.arraycopy(f, s + 0x150, h.fileKey, 0, 16);
		if (h.has(KEY_FILE_FORMAT)) {
			int o = (int) h.get(KEY_FILE_FORMAT);
			if (o + 8 > f.length) {
				throw new IOException("file format info out of range");
			}
			long infoSize = u32be(f, o);
			h.encryption = u16be(f, o + 4);
			h.compression = u16be(f, o + 6);
			if (h.compression == 1) {
				for (int p = o + 8; p + 8 <= o + infoSize && p + 8 <= f.length; p += 8) {
					h.basicBlocks.add(new long[] { u32be(f, p), u32be(f, p + 4) });
				}
			}
			else if (h.compression == 2) {
				if (o + 36 > f.length) {
					throw new IOException("normal compression info out of range");
				}
				h.windowSize = u32be(f, o + 8);
				h.firstBlockSize = u32be(f, o + 12);
				System.arraycopy(f, o + 16, h.firstBlockHash, 0, 20);
			}
		}
		return h;
	}

	/** {@return the data of an offset-type optional header, or null} */
	static int optOffset(Header h, int key, byte[] f) {
		if (!h.has(key) || (key & 0xFF) <= 1) {
			return -1;
		}
		long o = h.get(key);
		return o >= 0 && o < f.length ? (int) o : -1;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < 0x200) {
			return specs;
		}
		byte[] m = provider.readBytes(0, 4);
		if (m[0] != 'X' || m[1] != 'E' || m[2] != 'X' || m[3] != '2') {
			return specs;
		}
		try {
			int need = (int) Math.min(provider.length(), 0x100000);
			Header h = parseHeader(provider.readBytes(0, need));
			long base = h.has(KEY_IMAGE_BASE) ? h.get(KEY_IMAGE_BASE) : h.loadAddress;
			specs.add(new LoadSpec(this, base, LANG, true));
		}
		catch (IOException e) {
			// not a usable XEX2
		}
		return specs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		list.add(new Option(OPT_KEY_FILE, "", String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-xexKeyFile"));
		list.add(new Option(OPT_EXPORT_NAMES, "", String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-xboxExportNames"));
		return list;
	}

	// ---- keys and decryption

	/** Reads 16-byte keys from a text (hex per line) or binary file; never logs them. */
	static List<byte[]> readKeys(String path, MessageLog log) {
		List<byte[]> keys = new ArrayList<>();
		if (path == null || path.isBlank()) {
			return keys;
		}
		File f = new File(path.trim());
		try {
			byte[] raw = Files.readAllBytes(f.toPath());
			String text = new String(raw, StandardCharsets.ISO_8859_1);
			boolean isText = text.chars().allMatch(c -> c == '\r' || c == '\n' || c == '\t' ||
				(c >= 0x20 && c < 0x7F));
			if (isText) {
				for (String line : text.split("\\R")) {
					int hash = line.indexOf('#');
					String hex = (hash >= 0 ? line.substring(0, hash) : line)
							.replaceAll("[^0-9A-Fa-f]", "");
					if (hex.length() == 32) {
						byte[] k = new byte[16];
						for (int i = 0; i < 16; i++) {
							k[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
						}
						keys.add(k);
					}
				}
			}
			else if (raw.length % 16 == 0) {
				for (int i = 0; i < raw.length; i += 16) {
					keys.add(Arrays.copyOfRange(raw, i, i + 16));
				}
			}
			if (keys.isEmpty()) {
				log.appendMsg("XEX2 key file " + f + " holds no 16-byte keys");
			}
		}
		catch (IOException e) {
			log.appendMsg("Cannot read XEX2 key file " + f + ": " + e.getMessage());
		}
		return keys;
	}

	static byte[] sessionKey(byte[] key, byte[] fileKey) throws GeneralSecurityException {
		Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
		c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
		return c.doFinal(fileKey);
	}

	static byte[] decryptCbc(byte[] session, byte[] data) throws GeneralSecurityException {
		Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
		c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(session, "AES"),
			new IvParameterSpec(new byte[16]));
		byte[] out = data.clone();
		int whole = data.length & ~15;
		if (whole > 0) {
			byte[] dec = c.doFinal(data, 0, whole);
			System.arraycopy(dec, 0, out, 0, whole);
		}
		return out;
	}

	/** Decompresses the (decrypted) data region into the memory image. */
	static byte[] decompress(Header h, byte[] data, MessageLog log) throws IOException {
		int size = (int) h.imageSize;
		switch (h.compression) {
			case 0: {
				return Arrays.copyOf(data, size);
			}
			case 1: {
				byte[] img = new byte[size];
				int in = 0, out = 0;
				for (long[] b : h.basicBlocks) {
					int d = (int) b[0], z = (int) b[1];
					if (in + d > data.length || out + d > size) {
						throw new IOException("basic compression block out of range");
					}
					System.arraycopy(data, in, img, out, d);
					in += d;
					out += d + z;
				}
				return img;
			}
			case 2: {
				java.io.ByteArrayOutputStream lzx = new java.io.ByteArrayOutputStream();
				int pos = 0;
				long blockSize = h.firstBlockSize;
				byte[] hash = h.firstBlockHash;
				int mismatches = 0;
				while (blockSize != 0) {
					if (blockSize < 24 || pos + blockSize > data.length) {
						throw new IOException("normal compression block chain out of range");
					}
					if (!Arrays.equals(sha1(data, pos, (int) blockSize), hash)) {
						mismatches++;
					}
					long next = u32be(data, pos);
					byte[] nextHash = Arrays.copyOfRange(data, pos + 4, pos + 24);
					int p = pos + 24, end = (int) (pos + blockSize);
					while (p + 2 <= end) {
						int chunk = u16be(data, p);
						p += 2;
						if (chunk == 0) {
							break;
						}
						if (p + chunk > end) {
							throw new IOException("LZX chunk runs past its block");
						}
						lzx.write(data, p, chunk);
						p += chunk;
					}
					pos = end;
					blockSize = next;
					hash = nextHash;
				}
				if (mismatches > 0 && log != null) {
					log.appendMsg("XEX2: " + mismatches + " compressed block hash mismatch(es)");
				}
				byte[] c = lzx.toByteArray();
				return XexLzxDecoder.decompress(c, 0, c.length, (int) h.windowSize, size);
			}
			case 3:
				throw new IOException("XEX2 delta (patch) compression is not supported");
			default:
				throw new IOException("unknown XEX2 compression type " + h.compression);
		}
	}

	static byte[] sha1(byte[] b, int off, int len) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(b, off, len);
			return md.digest();
		}
		catch (GeneralSecurityException e) {
			return new byte[20];
		}
	}

	static boolean looksLikePe(byte[] img) {
		if (img.length < 0x40 || img[0] != 'M' || img[1] != 'Z') {
			return false;
		}
		long lfa = u32le(img, 0x3C);
		return lfa + 4 <= img.length && img[(int) lfa] == 'P' && img[(int) lfa + 1] == 'E';
	}

	// ---- load

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		MessageLog log = settings.log();
		ByteProvider p = settings.provider();
		byte[] f = p.readBytes(0, p.length());
		Header h = parseHeader(f);
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		long base = h.has(KEY_IMAGE_BASE) ? h.get(KEY_IMAGE_BASE) : h.loadAddress;
		byte[] data = Arrays.copyOfRange(f, (int) h.peOffset, f.length);

		String[] comp = { "none", "basic (zero-fill blocks)", "normal (LZX)", "delta" };
		property(program, "XEX2 compression",
			h.compression < comp.length ? comp[h.compression] : "type " + h.compression);
		property(program, "XEX2 encryption", h.encryption == 0 ? "none" : "AES-128-CBC");

		byte[] image = null;
		if (h.encryption == 0) {
			image = decompress(h, data, log);
		}
		else {
			String keyFile = OptionUtils.getOption(OPT_KEY_FILE, settings.options(), "");
			if (keyFile.isBlank() && System.getenv(ENV_KEYS) != null) {
				keyFile = System.getenv(ENV_KEYS);
			}
			List<byte[]> keys = readKeys(keyFile, log);
			if (keys.isEmpty()) {
				throw new IOException("This XEX2 is encrypted. Supply a key file with the loader " +
					"option '" + OPT_KEY_FILE + "' (-loader-xexKeyFile <path>) or the " + ENV_KEYS +
					" environment variable.");
			}
			for (int i = 0; i < keys.size() && image == null; i++) {
				try {
					byte[] dec = decryptCbc(sessionKey(keys.get(i), h.fileKey), data);
					byte[] img = decompress(h, dec, null);
					if (looksLikePe(img)) {
						image = img;
						property(program, "XEX2 key used", "key #" + (i + 1) + " of the key file");
					}
				}
				catch (IOException | GeneralSecurityException e) {
					// wrong key: try the next one
				}
			}
			if (image == null) {
				throw new IOException("None of the " + keys.size() +
					" key(s) in the key file decrypts this XEX2");
			}
		}

		try {
			program.setImageBase(space.getAddress(base), true);
		}
		catch (Exception e) {
			log.appendMsg("Cannot set image base: " + e.getMessage());
		}
		FileBytes fb = MemoryBlockUtils.createFileBytes(program, p, settings.monitor());
		try {
			MemoryBlockUtils.createInitializedBlock(program, true, "XEX_HEADER",
				AddressSpace.OTHER_SPACE.getAddress(0), fb, 0, h.peOffset,
				"XEX2 header (not part of the loaded image)", null, true, false, false, log);
		}
		catch (AddressOverflowException e) {
			log.appendMsg("Cannot map the XEX2 header: " + e.getMessage());
		}

		List<String> sectionNames = mapPe(program, space, base, image, log, settings);
		property(program, "XEX2 base address", hex(base, 8));
		property(program, "XEX2 image size", hex(h.imageSize, 8));
		property(program, "XEX2 module flags", hex(h.moduleFlags, 8));
		recordHeaders(program, h, f);

		String names = OptionUtils.getOption(OPT_EXPORT_NAMES, settings.options(), "");
		if (names.isBlank() && System.getenv(ENV_EXPORT_NAMES) != null) {
			names = System.getenv(ENV_EXPORT_NAMES);
		}
		Map<String, Map<Integer, String>> override = readExportNames(names, log);
		imports(program, space, base, image, h, f, override, log);
		if (sectionNames.contains(".pdata")) {
			pdata(program, space, log);
		}

		if (h.has(KEY_ENTRY_POINT)) {
			Address e = space.getAddress(h.get(KEY_ENTRY_POINT));
			property(program, "XEX2 entry point", e.toString());
			entry(program, e, "entry", log);
			program.getListing()
					.setComment(e, CommentType.PLATE,
						"XEX2 entry point. Note: VMX128 (Xenon) vector instructions are not " +
							"decoded by the stock PowerPC language.");
		}
	}

	/** Maps the PE inside the image (memory layout). Returns the section names. */
	private List<String> mapPe(Program program, AddressSpace space, long base, byte[] img,
			MessageLog log, ImporterSettings settings) {
		List<String> names = new ArrayList<>();
		if (!looksLikePe(img)) {
			log.appendMsg("XEX2 image has no PE header; mapped as one block");
			bytesBlock(program, "image", space.getAddress(base), img, 0, img.length, false, true,
				true, true, "XEX2 image", log, settings.monitor());
			return names;
		}
		int pe = (int) u32le(img, 0x3C);
		int machine = u16le(img, pe + 4);
		int nsec = u16le(img, pe + 6);
		int optSize = u16le(img, pe + 20);
		int opt = pe + 24;
		long sizeOfHeaders = opt + 60 <= img.length ? u32le(img, opt + 60) : 0x1000;
		property(program, "XEX2 PE machine",
			hex(machine, 4) + (machine == 0x1F2 ? " (PowerPC big-endian)" : ""));
		int secTab = opt + optSize;
		long firstVa = Long.MAX_VALUE;
		for (int i = 0; i < nsec; i++) {
			int s = secTab + i * 40;
			if (s + 40 <= img.length) {
				firstVa = Math.min(firstVa, u32le(img, s + 12));
			}
		}
		long hdrLen = Math.min(Math.min(sizeOfHeaders, firstVa), img.length);
		bytesBlock(program, "PE_HEADERS", space.getAddress(base), img, 0, (int) hdrLen, false,
			true, false, false, "PE header of the XEX2 image", log, settings.monitor());
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < nsec; i++) {
			int s = secTab + i * 40;
			if (s + 40 > img.length) {
				break;
			}
			String name = XbeLoader.cString(img, s, 8);
			if (name.isEmpty()) {
				name = "section" + i;
			}
			long vsize = u32le(img, s + 8), va = u32le(img, s + 12), rawSize = u32le(img, s + 16);
			long chars = u32le(img, s + 36);
			long size = vsize != 0 ? vsize : rawSize;
			boolean w = (chars & 0x80000000L) != 0, x = (chars & 0x20000000L) != 0;
			names.add(name);
			sb.append(String.format("%s va=%08X size=%X chars=%08X%n", name, base + va, size,
				chars));
			long init = Math.max(0, Math.min(size, img.length - va));
			Address start = space.getAddress(base + va);
			if (init > 0) {
				bytesBlock(program, name, start, img, (int) va, (int) init, null, true, w, x,
					"PE section " + i, log, settings.monitor());
			}
			if (size > init) {
				Address rest = start.add(init);
				uninitBlock(program, name + ".bss", rest, size - init,
					overlaps(program, rest, size - init), true, w, x, false,
					"PE section " + i + " beyond the image", log);
			}
		}
		property(program, "XEX2 PE sections", sb.toString().trim());
		return names;
	}

	private void recordHeaders(Program program, Header h, byte[] f) {
		int o = optOffset(h, KEY_EXECUTION_INFO, f);
		if (o >= 0 && o + 24 <= f.length) {
			long titleId = u32be(f, o + 12);
			property(program, "XEX2 title ID", hex(titleId, 8));
			property(program, "XEX2 media ID", hex(u32be(f, o), 8));
			property(program, "XEX2 version", hex(u32be(f, o + 4), 8));
			property(program, "XEX2 base version", hex(u32be(f, o + 8), 8));
			property(program, "XEX2 disc", (f[o + 18] & 0xff) + "/" + (f[o + 19] & 0xff));
		}
		o = optOffset(h, KEY_ORIGINAL_PE_NAME, f);
		if (o >= 0 && o + 4 <= f.length) {
			property(program, "XEX2 original PE name",
				XbeLoader.cString(f, o + 4, (int) Math.min(256, u32be(f, o))));
		}
		if (h.has(KEY_STACK_SIZE)) {
			property(program, "XEX2 default stack size", hex(h.get(KEY_STACK_SIZE), 8));
		}
		if (h.has(KEY_SYSTEM_FLAGS)) {
			property(program, "XEX2 system flags", hex(h.get(KEY_SYSTEM_FLAGS), 8));
		}
		if (h.has(KEY_ORIGINAL_BASE)) {
			property(program, "XEX2 original base address", hex(h.get(KEY_ORIGINAL_BASE), 8));
		}
		o = optOffset(h, KEY_STATIC_LIBRARIES, f);
		if (o >= 0 && o + 4 <= f.length) {
			long size = u32be(f, o);
			StringBuilder sb = new StringBuilder();
			for (int p = o + 4; p + 16 <= o + size && p + 16 <= f.length; p += 16) {
				sb.append(String.format("%s %d.%d.%d.%d%n", XbeLoader.cString(f, p, 8),
					u16be(f, p + 8), u16be(f, p + 10), u16be(f, p + 12), u16be(f, p + 14) & 0xFF));
			}
			property(program, "XEX2 static libraries (XDK)", sb.toString().trim());
		}
		o = optOffset(h, KEY_TLS_INFO, f);
		if (o >= 0 && o + 16 <= f.length) {
			property(program, "XEX2 TLS",
				String.format("slots %d, data %s, raw size %X, data size %X", u32be(f, o),
					hex(u32be(f, o + 4), 8), u32be(f, o + 8), u32be(f, o + 12)));
		}
	}

	private static String version(long v) {
		return String.format("%d.%d.%d.%d", (v >>> 28) & 0xF, (v >>> 24) & 0xF,
			(v >>> 8) & 0xFFFF, v & 0xFF);
	}

	private void imports(Program program, AddressSpace space, long base, byte[] img, Header h,
			byte[] f, Map<String, Map<Integer, String>> override, MessageLog log) {
		int o = optOffset(h, KEY_IMPORT_LIBRARIES, f);
		if (o < 0 || o + 12 > f.length) {
			return;
		}
		long strSize = u32be(f, o + 4);
		int libCount = (int) u32be(f, o + 8);
		List<String> strings = new ArrayList<>();
		int sp = o + 12, send = (int) Math.min(f.length, o + 12 + strSize);
		while (sp < send && strings.size() < libCount) {
			String s = XbeLoader.cString(f, sp, send - sp);
			strings.add(s);
			sp += s.length() + 1;
			while (sp < send && f[sp] == 0) {
				sp++; // padding
			}
		}
		int lp = send;
		StringBuilder libs = new StringBuilder();
		ExternalManager em = program.getExternalManager();
		int total = 0;
		for (int l = 0; l < libCount && lp + 0x28 <= f.length; l++) {
			long size = u32be(f, lp);
			int nameIndex = u16be(f, lp + 0x24);
			int count = u16be(f, lp + 0x26);
			String lib = nameIndex < strings.size() ? strings.get(nameIndex) : "lib" + l;
			libs.append(String.format("%s %s (min %s), %d records%n", lib,
				version(u32be(f, lp + 0x1C)), version(u32be(f, lp + 0x20)), count));
			Map<Integer, String> names =
				override.getOrDefault(lib.toLowerCase(Locale.ROOT), Map.of());
			// ordinals that have a thunk are functions
			Set<Integer> thunked = new HashSet<>();
			List<long[]> records = new ArrayList<>();
			for (int i = 0; i < count && lp + 0x28 + 4 * i + 4 <= f.length; i++) {
				long addr = u32be(f, lp + 0x28 + 4 * i);
				long off = addr - base;
				if (off < 0 || off + 4 > img.length) {
					continue;
				}
				long v = u32be(img, (int) off);
				records.add(new long[] { addr, v });
				if ((v >>> 24) == 1) {
					thunked.add((int) (v & 0xFFFF));
				}
			}
			for (long[] r : records) {
				int type = (int) (r[1] >>> 24), ord = (int) (r[1] & 0xFFFF);
				String name = names.getOrDefault(ord, Xbox360Ordinals.name(lib, ord));
				Address a = space.getAddress(r[0]);
				try {
					boolean function = thunked.contains(ord) && !Xbox360Ordinals.DATA.contains(name);
					ExternalLocation loc = function
							? em.addExtFunction(lib, name, null, SourceType.IMPORTED)
							: em.addExtLocation(lib, name, null, SourceType.IMPORTED);
					if (type == 0) {
						DataUtilities.createData(program, a, Pointer32DataType.dataType, 4,
							DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
						Reference ref = program.getReferenceManager()
								.addExternalReference(a, 0, loc, SourceType.IMPORTED,
									RefType.DATA);
						program.getReferenceManager().setPrimary(ref, true);
						label(program, a, "__imp_" + name, true, log);
					}
					else if (type == 1) {
						Function ext = loc.getFunction();
						FunctionManager fm = program.getFunctionManager();
						if (ext != null && fm.getFunctionAt(a) == null) {
							fm.createThunkFunction(null, null, a, new AddressSet(a, a.add(15)),
								ext, SourceType.IMPORTED);
						}
						DataUtilities.createData(program, a, new ArrayDataType(
							DWordDataType.dataType, 4, 4), 16,
							DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
					}
					program.getListing()
							.setComment(a, CommentType.EOL, String.format(
								"%s ordinal %d (%s)", lib, ord, type == 1 ? "thunk" : "import"));
					total++;
				}
				catch (Exception e) {
					log.appendMsg("Import " + lib + " #" + ord + ": " + e.getMessage());
				}
			}
			lp += (int) Math.max(size, 0x28);
		}
		property(program, "XEX2 import libraries", libs.toString().trim());
		property(program, "XEX2 import records", Integer.toString(total));
	}

	/** Creates functions at the .pdata runtime-function begin addresses. */
	private void pdata(Program program, AddressSpace space, MessageLog log) {
		MemoryBlock b = program.getMemory().getBlock(".pdata");
		if (b == null || !b.isInitialized()) {
			return;
		}
		int n = 0;
		try {
			for (long off = 0; off + 8 <= b.getSize(); off += 8) {
				long begin = program.getMemory().getInt(b.getStart().add(off)) & 0xFFFFFFFFL;
				if (begin == 0) {
					break;
				}
				Address a = space.getAddress(begin);
				MemoryBlock cb = program.getMemory().getBlock(a);
				if (cb != null && cb.isExecute()) {
					AbstractProgramLoader.markAsFunction(program, null, a);
					n++;
				}
			}
		}
		catch (Exception e) {
			log.appendMsg(".pdata: " + e.getMessage());
		}
		property(program, "XEX2 .pdata functions", Integer.toString(n));
	}
}
