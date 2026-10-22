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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;

/**
 * Original Xbox executable (XBE): "XBEH" image header loaded at the base address (usually
 * 0x10000), sections at their virtual addresses, entry point and kernel thunk table address
 * decoded with the retail / debug / Chihiro XOR keys (the one whose decoded addresses land in
 * the image wins), kernel imports by ordinal from xboxkrnl.exe, certificate and XDK library
 * versions recorded.
 */
public class XbeLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Xbox Executable (XBE)";
	static final LanguageCompilerSpecPair LANG =
		new LanguageCompilerSpecPair("x86:LE:32:default", "windows");
	public static final String OPT_EXPORT_NAMES = "Xbox export names file";
	static final String ENV_EXPORT_NAMES = "XBOX_EXPORT_NAMES";

	static final int HEADER_SIZE = 0x178;
	static final int SECTION_HEADER_SIZE = 0x38;

	/** Entry / thunk XOR pairs: format constants that decode two header fields (not secrets). */
	private static final long[][] XOR_PAIRS =
		{ { 0xA8FC57ABL, 0x5B6D40B6L }, { 0x94859D4BL, 0xEFB1F152L }, { 0x40B5C16EL, 0x2290059DL } };
	private static final String[] XOR_KIND = { "retail", "debug", "Chihiro" };

	record Section(int index, String name, long flags, long va, long vsize, long raw,
			long rawSize) {
		boolean contains(long a) {
			return a >= va && a < va + Math.max(vsize, 1);
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

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < HEADER_SIZE) {
			return specs;
		}
		byte[] h = provider.readBytes(0, HEADER_SIZE);
		if (h[0] != 'X' || h[1] != 'B' || h[2] != 'E' || h[3] != 'H') {
			return specs;
		}
		long base = u32le(h, 0x104);
		long sizeOfHeaders = u32le(h, 0x108);
		long nsec = u32le(h, 0x11C);
		long secAddr = u32le(h, 0x120);
		if (base == 0 || base >= 0x80000000L || (base & 0xFFF) != 0 ||
			sizeOfHeaders < HEADER_SIZE || sizeOfHeaders > provider.length() || nsec == 0 ||
			nsec > 0x400 || secAddr < base || secAddr + nsec * SECTION_HEADER_SIZE > base +
				sizeOfHeaders) {
			return specs;
		}
		specs.add(new LoadSpec(this, base, LANG, true));
		return specs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		list.add(new Option(OPT_EXPORT_NAMES, "", String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-xboxExportNames"));
		return list;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		MessageLog log = settings.log();
		ByteProvider p = settings.provider();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		byte[] h = p.readBytes(0, HEADER_SIZE);
		long base = u32le(h, 0x104);
		long sizeOfHeaders = u32le(h, 0x108);
		int nsec = (int) u32le(h, 0x11C);
		long secAddr = u32le(h, 0x120);
		byte[] hdrs = p.readBytes(0, Math.min(sizeOfHeaders, p.length()));

		try {
			program.setImageBase(space.getAddress(base), true);
		}
		catch (Exception e) {
			log.appendMsg("Cannot set image base: " + e.getMessage());
		}
		FileBytes fb = MemoryBlockUtils.createFileBytes(program, p, settings.monitor());
		fileBlock(program, "HEADERS", space.getAddress(base), fb, 0, hdrs.length, false, true,
			false, false, "XBE image header, certificate, section headers", log);

		// sections
		List<Section> sections = new ArrayList<>();
		StringBuilder secText = new StringBuilder();
		for (int i = 0; i < nsec; i++) {
			int off = (int) (secAddr - base) + i * SECTION_HEADER_SIZE;
			long flags = u32le(hdrs, off);
			long va = u32le(hdrs, off + 4), vsize = u32le(hdrs, off + 8);
			long raw = u32le(hdrs, off + 0x0C), rawSize = u32le(hdrs, off + 0x10);
			String name = cString(hdrs, u32le(hdrs, off + 0x14) - base, 32);
			if (name.isEmpty()) {
				name = "section" + i;
			}
			Section s = new Section(i, name, flags, va, vsize, raw, rawSize);
			sections.add(s);
			secText.append(String.format("%s va=%08X vsize=%X raw=%X rawsize=%X flags=%X%n",
				name, va, vsize, raw, rawSize, flags));
			mapSection(program, space, fb, p.length(), s, log);
		}
		property(program, "XBE sections", secText.toString().trim());
		property(program, "XBE base address", hex(base, 8));

		// entry point and kernel thunk table: pick the XOR pair that decodes into the image
		long encEntry = u32le(h, 0x128), encThunk = u32le(h, 0x158);
		int kind = -1;
		for (int k = 0; k < XOR_PAIRS.length && kind < 0; k++) {
			long e = encEntry ^ XOR_PAIRS[k][0], t = encThunk ^ XOR_PAIRS[k][1];
			if (inSection(sections, e, true) && inSection(sections, t, false)) {
				kind = k;
			}
		}
		for (int k = 0; k < XOR_PAIRS.length && kind < 0; k++) {
			if (inSection(sections, encEntry ^ XOR_PAIRS[k][0], false)) {
				kind = k;
			}
		}
		if (kind < 0) {
			log.appendMsg("XBE: no known key decodes the entry point into a section; " +
				"assuming retail");
			kind = 0;
		}
		long entry = encEntry ^ XOR_PAIRS[kind][0];
		long thunk = encThunk ^ XOR_PAIRS[kind][1];
		property(program, "XBE type", XOR_KIND[kind]);
		property(program, "XBE entry point", hex(entry, 8));
		property(program, "XBE kernel thunk table", hex(thunk, 8));

		markHeader(program, space, base, hdrs, sections, secAddr, log);
		String names = OptionUtils.getOption(OPT_EXPORT_NAMES, settings.options(), "");
		if (names.isBlank() && System.getenv(ENV_EXPORT_NAMES) != null) {
			names = System.getenv(ENV_EXPORT_NAMES);
		}
		Map<Integer, String> override = readExportNames(names, log)
				.getOrDefault(XboxKernelOrdinals.LIBRARY, Map.of());
		int imports = kernelImports(program, space, thunk, override, log);
		property(program, "XBE kernel imports", Integer.toString(imports));

		certificate(program, space, base, hdrs, u32le(h, 0x118), log);
		libraries(program, space, base, hdrs, h, log);
		long tls = u32le(h, 0x12C);
		if (tls != 0) {
			property(program, "XBE TLS directory", hex(tls, 8));
			label(program, space.getAddress(tls), "_tls_used", true, log);
			try {
				DataUtilities.createData(program, space.getAddress(tls), tlsType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}
			catch (Exception e) {
				// TLS outside mapped memory
			}
		}
		String dbg = cString(hdrs, u32le(h, 0x150) - base, 260);
		if (!dbg.isEmpty()) {
			property(program, "XBE debug file name", dbg);
		}
		String dbgPath = cString(hdrs, u32le(h, 0x14C) - base, 260);
		if (!dbgPath.isEmpty()) {
			property(program, "XBE debug path", dbgPath);
		}
		property(program, "XBE time/date", hex(u32le(h, 0x114), 8));
		property(program, "XBE init flags", hex(u32le(h, 0x124), 8));
		if (u32le(h, 0x170) != 0) {
			label(program, space.getAddress(u32le(h, 0x170)), "xbe_logo_bitmap", true, log);
		}
		entry(program, space.getAddress(entry), "entry", log);
	}

	private static boolean inSection(List<Section> sections, long a, boolean exec) {
		for (Section s : sections) {
			if (s.contains(a) && (!exec || (s.flags() & 4) != 0)) {
				return true;
			}
		}
		return false;
	}

	private void mapSection(Program program, AddressSpace space, FileBytes fb, long fileLen,
			Section s, MessageLog log) {
		boolean w = (s.flags() & 1) != 0, x = (s.flags() & 4) != 0;
		long init = Math.min(s.rawSize(), s.vsize());
		if (s.raw() + init > fileLen) {
			init = Math.max(0, fileLen - s.raw());
			log.appendMsg("Section " + s.name() + " raw data past end of file; truncated");
		}
		String comment = String.format("XBE section %d, flags 0x%X", s.index(), s.flags());
		if (init > 0) {
			fileBlock(program, s.name(), space.getAddress(s.va()), fb, s.raw(), init, null, true,
				w, x, comment, log);
		}
		if (s.vsize() > init) {
			Address start = space.getAddress(s.va() + init);
			uninitBlock(program, init > 0 ? s.name() + ".bss" : s.name(), start,
				s.vsize() - init, overlaps(program, start, s.vsize() - init), true, w, x, false,
				comment + " (zero-filled part)", log);
		}
	}

	private int kernelImports(Program program, AddressSpace space, long thunk,
			Map<Integer, String> override, MessageLog log) {
		Address a = space.getAddress(thunk);
		if (!program.getMemory().contains(a)) {
			log.appendMsg("Kernel thunk table " + a + " is not mapped");
			return 0;
		}
		label(program, a, "xboxkrnl_thunk_table", true, log);
		ExternalManager em = program.getExternalManager();
		int n = 0;
		for (int i = 0; i < 1024; i++) {
			Address slot = a.add(4L * i);
			long v;
			try {
				v = program.getMemory().getInt(slot) & 0xFFFFFFFFL;
			}
			catch (Exception e) {
				break;
			}
			if (v == 0) {
				break;
			}
			if ((v & 0x80000000L) == 0) {
				log.appendMsg("Kernel thunk " + slot + " is not an ordinal import; stopping");
				break;
			}
			int ord = (int) (v & 0x7FFFFFFF);
			String name = override.getOrDefault(ord, XboxKernelOrdinals.name(ord));
			try {
				ExternalLocation loc = XboxKernelOrdinals.DATA.contains(name)
						? em.addExtLocation(XboxKernelOrdinals.LIBRARY, name, null,
							SourceType.IMPORTED)
						: em.addExtFunction(XboxKernelOrdinals.LIBRARY, name, null,
							SourceType.IMPORTED);
				DataUtilities.createData(program, slot, PointerDataType.dataType, 4,
					DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				Reference r = program.getReferenceManager()
						.addExternalReference(slot, 0, loc, SourceType.IMPORTED, RefType.DATA);
				program.getReferenceManager().setPrimary(r, true);
				label(program, slot, "__imp_" + name, true, log);
				program.getListing()
						.setComment(slot, CommentType.EOL, "xboxkrnl.exe ordinal " + ord);
				n++;
			}
			catch (Exception e) {
				log.appendMsg("Kernel import " + ord + ": " + e.getMessage());
			}
		}
		return n;
	}

	private void certificate(Program program, AddressSpace space, long base, byte[] hdrs,
			long certVa, MessageLog log) {
		int off = (int) (certVa - base);
		if (certVa == 0 || off < 0 || off + 0xB0 > hdrs.length) {
			return;
		}
		long titleId = u32le(hdrs, off + 0x08);
		String title = new String(hdrs, off + 0x0C, 0x50, StandardCharsets.UTF_16LE);
		int z = title.indexOf('\0');
		title = z >= 0 ? title.substring(0, z) : title;
		property(program, "XBE title ID", hex(titleId, 8) + " (" + titleIdText(titleId) + ")");
		property(program, "XBE title name", title);
		property(program, "XBE allowed media", hex(u32le(hdrs, off + 0x9C), 8));
		property(program, "XBE game region", hex(u32le(hdrs, off + 0xA0), 8));
		property(program, "XBE game ratings", hex(u32le(hdrs, off + 0xA4), 8));
		property(program, "XBE disk number", Long.toString(u32le(hdrs, off + 0xA8)));
		property(program, "XBE version", hex(u32le(hdrs, off + 0xAC), 8));
		Address a = space.getAddress(certVa);
		label(program, a, "xbe_certificate", true, log);
		try {
			StructureDataType c = new StructureDataType("XBE_CERTIFICATE", 0);
			c.add(DWordDataType.dataType, "SizeOfCertificate", null);
			c.add(DWordDataType.dataType, "TimeDate", null);
			c.add(DWordDataType.dataType, "TitleID", null);
			c.add(new ArrayDataType(WideChar16DataType.dataType, 40, 2), "TitleName", null);
			c.add(new ArrayDataType(DWordDataType.dataType, 16, 4), "AlternateTitleIDs", null);
			c.add(DWordDataType.dataType, "AllowedMedia", null);
			c.add(DWordDataType.dataType, "GameRegion", null);
			c.add(DWordDataType.dataType, "GameRatings", null);
			c.add(DWordDataType.dataType, "DiskNumber", null);
			c.add(DWordDataType.dataType, "Version", null);
			DataUtilities.createData(program, a, c, -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
		}
		catch (Exception e) {
			log.appendMsg("Certificate markup: " + e.getMessage());
		}
	}

	private static String titleIdText(long id) {
		char c1 = (char) ((id >> 24) & 0xff), c2 = (char) ((id >> 16) & 0xff);
		if (Character.isLetterOrDigit(c1) && Character.isLetterOrDigit(c2)) {
			return "" + c1 + c2 + "-" + String.format("%03d", id & 0xFFFF);
		}
		return "?";
	}

	private void libraries(Program program, AddressSpace space, long base, byte[] hdrs, byte[] h,
			MessageLog log) {
		long count = u32le(h, 0x160), va = u32le(h, 0x164);
		int off = (int) (va - base);
		if (va == 0 || count == 0 || count > 256 || off < 0 || off + count * 16 > hdrs.length) {
			return;
		}
		StructureDataType lib = new StructureDataType("XBE_LIBRARY_VERSION", 0);
		lib.add(new ArrayDataType(CharDataType.dataType, 8, 1), "LibraryName", null);
		lib.add(WordDataType.dataType, "MajorVersion", null);
		lib.add(WordDataType.dataType, "MinorVersion", null);
		lib.add(WordDataType.dataType, "BuildVersion", null);
		lib.add(WordDataType.dataType, "Flags", "QFE 0-12, approved 13-14, debug 15");
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < count; i++) {
			int o = off + i * 16;
			String name = cString(hdrs, o, 8);
			int flags = u16le(hdrs, o + 14);
			sb.append(String.format("%s %d.%d.%d QFE %d%s%n", name, u16le(hdrs, o + 8),
				u16le(hdrs, o + 10), u16le(hdrs, o + 12), flags & 0x1FFF,
				(flags & 0x8000) != 0 ? " debug" : ""));
		}
		property(program, "XBE libraries (XDK)", sb.toString().trim());
		try {
			Address a = space.getAddress(va);
			label(program, a, "xbe_library_versions", true, log);
			DataUtilities.createData(program, a, new ArrayDataType(lib, (int) count, 16), -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
		}
		catch (Exception e) {
			log.appendMsg("Library version markup: " + e.getMessage());
		}
		long kernelLib = u32le(h, 0x168);
		if (kernelLib != 0) {
			label(program, space.getAddress(kernelLib), "xbe_kernel_library_version", true, log);
		}
		long xapiLib = u32le(h, 0x16C);
		if (xapiLib != 0) {
			label(program, space.getAddress(xapiLib), "xbe_xapi_library_version", true, log);
		}
	}

	private void markHeader(Program program, AddressSpace space, long base, byte[] hdrs,
			List<Section> sections, long secAddr, MessageLog log) {
		StructureDataType st = new StructureDataType("XBE_IMAGE_HEADER", 0);
		st.add(new ArrayDataType(CharDataType.dataType, 4, 1), "Magic", null);
		st.add(new ArrayDataType(ByteDataType.dataType, 256, 1), "DigitalSignature", null);
		String[] fields = { "BaseAddress", "SizeOfHeaders", "SizeOfImage", "SizeOfImageHeader",
			"TimeDate", "CertificateAddress", "NumberOfSections", "SectionHeadersAddress",
			"InitializationFlags", "EntryPoint_Encoded", "TlsAddress", "PeStackCommit",
			"PeHeapReserve", "PeHeapCommit", "PeBaseAddress", "PeSizeOfImage", "PeChecksum",
			"PeTimeDate", "DebugPathNameAddress", "DebugFileNameAddress",
			"DebugUnicodeFileNameAddress", "KernelImageThunkAddress_Encoded",
			"NonKernelImportDirectoryAddress", "NumberOfLibraryVersions",
			"LibraryVersionsAddress", "KernelLibraryVersionAddress",
			"XapiLibraryVersionAddress", "LogoBitmapAddress", "LogoBitmapSize" };
		for (String f : fields) {
			st.add(DWordDataType.dataType, f, null);
		}
		StructureDataType sec = new StructureDataType("XBE_SECTION_HEADER", 0);
		String[] sf = { "Flags", "VirtualAddress", "VirtualSize", "RawAddress", "RawSize",
			"SectionNameAddress", "SectionNameRefCount", "HeadSharedPageRefCountAddress",
			"TailSharedPageRefCountAddress" };
		for (String f : sf) {
			sec.add(DWordDataType.dataType, f, null);
		}
		sec.add(new ArrayDataType(ByteDataType.dataType, 20, 1), "SectionDigest", null);
		try {
			Address a = space.getAddress(base);
			DataUtilities.createData(program, a, st, -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			label(program, a, "xbe_image_header", true, log);
			Address s = space.getAddress(secAddr);
			DataUtilities.createData(program, s,
				new ArrayDataType(sec, sections.size(), SECTION_HEADER_SIZE), -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			label(program, s, "xbe_section_headers", true, log);
		}
		catch (Exception e) {
			log.appendMsg("Header markup: " + e.getMessage());
		}
	}

	private static StructureDataType tlsType() {
		StructureDataType t = new StructureDataType("XBE_TLS", 0);
		for (String f : new String[] { "StartAddressOfRawData", "EndAddressOfRawData",
			"AddressOfIndex", "AddressOfCallbacks", "SizeOfZeroFill", "Characteristics" }) {
			t.add(DWordDataType.dataType, f, null);
		}
		return t;
	}

	static String cString(byte[] b, long off, int max) {
		if (off < 0 || off >= b.length) {
			return "";
		}
		int o = (int) off;
		int e = o;
		while (e < b.length && e - o < max && b[e] != 0) {
			e++;
		}
		return new String(b, o, e - o, StandardCharsets.ISO_8859_1);
	}
}
