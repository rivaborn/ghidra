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

import static ghidra.app.util.opinion.console.ConsoleExeSupport.*;

import java.io.IOException;
import java.util.*;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Wii U RPX executables and RPL libraries (Cafe OS).
 * <p>
 * These are ELF32 big-endian PowerPC files with e_ident[EI_OSABI] = 0xCA, e_ident[EI_ABIVERSION]
 * = 0xFE and e_type = 0xFE01. Sections flagged SHF_RPL_ZLIB (0x08000000) hold a u32
 * decompressed size followed by a zlib stream. Imports live in .fimport_&lt;module&gt; /
 * .dimport_&lt;module&gt; sections (SHT_RPL_IMPORTS 0x80000002), exports in .fexport / .dexport
 * (SHT_RPL_EXPORTS 0x80000001), the RPL file info in SHT_RPL_FILEINFO (0x80000004) and section
 * CRCs in SHT_RPL_CRCS (0x80000003). Sections are loaded at their link addresses, RELA
 * relocations are applied, imports become thunks to external functions of their module.
 */
public class RpxLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Wii U RPX/RPL";

	static final int SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_RELA = 4,
			SHT_NOBITS = 8;
	static final int SHT_RPL_EXPORTS = 0x80000001, SHT_RPL_IMPORTS = 0x80000002,
			SHT_RPL_CRCS = 0x80000003, SHT_RPL_FILEINFO = 0x80000004;
	static final long SHF_WRITE = 1, SHF_ALLOC = 2, SHF_EXECINSTR = 4, SHF_RPL_ZLIB = 0x08000000L;
	static final int R_PPC_EMB_SDA21 = 109;
	static final int R_PPC_DTPMOD32 = 68, R_PPC_DTPREL32 = 78;

	static final String OPT_RELOCS = "Apply relocations";

	record Section(int index, String name, int type, long flags, long addr, long offset,
			long size, int link, int info, long entsize) {
	}

	record Sym(String name, long value, long size, int type, int bind, int shndx) {
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
		return 40;
	}

	/** Detection: ELF32 BE PowerPC, OSABI 0xCA, ABI version 0xFE, e_type 0xFE01. */
	public static boolean isRpx(byte[] h, long fileLength) {
		if (h.length < 0x34 || fileLength < 0x34) {
			return false;
		}
		if (h[0] != 0x7F || h[1] != 'E' || h[2] != 'L' || h[3] != 'F' || h[4] != 1 || h[5] != 2 ||
			(h[7] & 0xFF) != 0xCA || (h[8] & 0xFF) != 0xFE) {
			return false;
		}
		if (be16(h, 0x10) != 0xFE01 || be16(h, 0x12) != 20) {
			return false;
		}
		long shoff = u(be32(h, 0x20));
		int shentsize = be16(h, 0x2E), shnum = be16(h, 0x30);
		return shentsize == 0x28 && shnum > 0 && shoff + (long) shnum * 0x28 <= fileLength;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() >= 0x34 && isRpx(provider.readBytes(0, 0x34), provider.length())) {
			specs.add(new LoadSpec(this, 0, gekkoOrDefault(getLanguageService()), true));
		}
		return specs;
	}

	private static List<Option> myOptions() {
		return List.of(new Option(OPT_RELOCS, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-applyRelocations"));
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		list.addAll(myOptions());
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String r = validateTypes(options, myOptions());
		return r != null ? r : super.validateOptions(provider, loadSpec, options, program);
	}

	/** Section contents, inflated when SHF_RPL_ZLIB is set. */
	static byte[] sectionData(ByteProvider p, Section s) throws IOException {
		if (s.type() == SHT_NOBITS || s.size() == 0) {
			return new byte[0];
		}
		if (s.offset() + s.size() > p.length()) {
			throw new IOException("Section " + s.name() + " extends past the end of the file");
		}
		byte[] raw = p.readBytes(s.offset(), s.size());
		if ((s.flags() & SHF_RPL_ZLIB) == 0) {
			return raw;
		}
		long outSize = u(be32(raw, 0));
		if (outSize > 0x10000000L) {
			throw new IOException("Section " + s.name() + ": bad inflated size");
		}
		byte[] out = new byte[(int) outSize];
		Inflater inf = new Inflater();
		try {
			inf.setInput(raw, 4, raw.length - 4);
			int n = 0;
			while (n < out.length && !inf.finished()) {
				int k = inf.inflate(out, n, out.length - n);
				if (k == 0 && (inf.needsInput() || inf.needsDictionary())) {
					break;
				}
				n += k;
			}
			if (n != out.length) {
				throw new IOException("Section " + s.name() + ": inflated " + n + " of " +
					out.length + " bytes");
			}
		}
		catch (DataFormatException e) {
			throw new IOException("Section " + s.name() + ": " + e.getMessage());
		}
		finally {
			inf.end();
		}
		return out;
	}

	static String cstr(byte[] b, long off) {
		if (off < 0 || off >= b.length) {
			return "";
		}
		int e = (int) off;
		while (e < b.length && b[e] != 0) {
			e++;
		}
		return new String(b, (int) off, e - (int) off, java.nio.charset.StandardCharsets.UTF_8);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		byte[] eh = provider.readBytes(0, 0x34);
		if (!isRpx(eh, provider.length())) {
			throw new IOException("Not an RPX/RPL file");
		}
		long entry = u(be32(eh, 0x18));
		long shoff = u(be32(eh, 0x20));
		int shnum = be16(eh, 0x30), shstrndx = be16(eh, 0x32);

		// section headers
		byte[] sh = provider.readBytes(shoff, shnum * 0x28L);
		Section[] raw = new Section[shnum];
		for (int i = 0; i < shnum; i++) {
			int o = i * 0x28;
			raw[i] = new Section(i, "", be32(sh, o + 4), u(be32(sh, o + 8)), u(be32(sh, o + 12)),
				u(be32(sh, o + 16)), u(be32(sh, o + 20)), be32(sh, o + 24), be32(sh, o + 28),
				u(be32(sh, o + 36)));
		}
		byte[] shstr = shstrndx < shnum ? sectionData(provider, raw[shstrndx]) : new byte[0];
		Section[] secs = new Section[shnum];
		for (int i = 0; i < shnum; i++) {
			int nameOff = be32(sh, i * 0x28);
			Section r = raw[i];
			secs[i] = new Section(i, cstr(shstr, nameOff), r.type(), r.flags(), r.addr(),
				r.offset(), r.size(), r.link(), r.info(), r.entsize());
		}
		Map<Integer, byte[]> data = new HashMap<>();
		for (Section s : secs) {
			if (s.type() != SHT_NOBITS && s.size() > 0 && s.index() != 0) {
				data.put(s.index(), sectionData(provider, s));
			}
		}

		// load allocated sections
		AddressSet codeRange = new AddressSet();
		StringBuilder map = new StringBuilder();
		for (Section s : secs) {
			monitor.checkCancelled();
			if ((s.flags() & SHF_ALLOC) == 0 || s.addr() == 0 || s.size() == 0) {
				continue;
			}
			boolean w = (s.flags() & SHF_WRITE) != 0, x = (s.flags() & SHF_EXECINSTR) != 0;
			String name = s.name().isEmpty() ? "section" + s.index() : s.name();
			String comment = "RPX section " + s.index() +
				((s.flags() & SHF_RPL_ZLIB) != 0 ? " (zlib-inflated)" : "");
			if (s.type() == SHT_NOBITS) {
				uninitBlock(program, name, s.addr(), s.size(), true, w, x, false, comment, log);
			}
			else {
				byte[] d = data.get(s.index());
				bytesBlock(program, name, s.addr(), d, true, w, x, comment, log, monitor);
			}
			if (x) {
				long memLen = s.type() == SHT_NOBITS ? s.size() : data.get(s.index()).length;
				codeRange.add(addr(program, s.addr()), addr(program, s.addr() + memLen - 1));
			}
			long memSize = s.type() == SHT_NOBITS ? s.size() : data.get(s.index()).length;
			map.append(name).append(' ').append(hex(s.addr())).append('+').append(
				hex(memSize)).append("; ");
		}

		// file info
		long sdaBase = 0, sda2Base = 0, fiFlags = 0;
		for (Section s : secs) {
			if (s.type() == SHT_RPL_FILEINFO) {
				byte[] fi = data.get(s.index());
				if (fi != null && fi.length >= 0x38) {
					info(program, "RPX file info version", hex(u(be32(fi, 0))));
					info(program, "RPX text/data/load size", hex(u(be32(fi, 4))) + " / " +
						hex(u(be32(fi, 0xC))) + " / " + hex(u(be32(fi, 0x14))));
					sdaBase = u(be32(fi, 0x24));
					sda2Base = u(be32(fi, 0x28));
					info(program, "RPX sdaBase (r13) / sda2Base (r2)",
						hex(sdaBase) + " / " + hex(sda2Base));
					info(program, "RPX stack size", hex(u(be32(fi, 0x2C))));
					fiFlags = u(be32(fi, 0x34));
					info(program, "RPX file info flags", hex(fiFlags) +
						((fiFlags & 2) != 0 ? " (RPX)" : " (RPL)"));
					if (fi.length >= 0x48) {
						info(program, "RPX heap size", hex(u(be32(fi, 0x38))));
					}
					if (fi.length >= 0x58) {
						info(program, "RPX Cafe SDK version", Long.toString(u(be32(fi, 0x50))) +
							" rev " + u(be32(fi, 0x54)));
					}
				}
			}
		}

		// symbols
		Map<Integer, Sym[]> symtabs = new HashMap<>();
		for (Section s : secs) {
			if (s.type() != SHT_SYMTAB) {
				continue;
			}
			byte[] st = data.get(s.index());
			byte[] str = s.link() > 0 && s.link() < shnum ? data.get(s.link()) : null;
			if (st == null) {
				continue;
			}
			Sym[] syms = new Sym[st.length / 16];
			for (int i = 0; i < syms.length; i++) {
				int o = i * 16;
				int infoB = st[o + 12] & 0xFF;
				syms[i] = new Sym(str != null ? cstr(str, u(be32(st, o))) : "",
					u(be32(st, o + 4)), u(be32(st, o + 8)), infoB & 0xF, infoB >>> 4,
					be16(st, o + 14));
			}
			symtabs.put(s.index(), syms);
		}

		SymbolTable symbolTable = program.getSymbolTable();
		ExternalManager em = program.getExternalManager();
		int imports = 0, labelled = 0;
		Set<String> modules = new TreeSet<>();
		for (Sym[] syms : symtabs.values()) {
			for (Sym sym : syms) {
				if (sym.name().isEmpty() || sym.shndx() == 0 || sym.shndx() >= shnum ||
					sym.type() == 3 /* STT_SECTION */ || sym.type() == 4 /* STT_FILE */) {
					continue;
				}
				Section s = secs[sym.shndx()];
				Address a = addr(program, sym.value());
				if (s.type() == SHT_RPL_IMPORTS) {
					String module = s.name().replaceFirst("^\\.[fd]import_", "");
					modules.add(module);
					boolean func = s.name().startsWith(".fimport_");
					if (makeImport(program, em, module, sym.name(), a, func, log)) {
						imports++;
					}
					continue;
				}
				if (!program.getMemory().contains(a)) {
					continue;
				}
				label(program, a, sym.name());
				labelled++;
				if (sym.type() == 2 /* STT_FUNC */) {
					AbstractProgramLoader.markAsFunction(program, sym.name(), a);
				}
			}
		}

		// exports
		int exports = 0;
		for (Section s : secs) {
			if (s.type() != SHT_RPL_EXPORTS) {
				continue;
			}
			byte[] d = data.get(s.index());
			if (d == null || d.length < 8) {
				continue;
			}
			long count = u(be32(d, 0));
			boolean func = s.name().equals(".fexport");
			for (int i = 0; i < count && 8 + i * 8 + 8 <= d.length; i++) {
				long value = u(be32(d, 8 + i * 8));
				long nameOff = u(be32(d, 12 + i * 8)) & 0x7FFFFFFFL;
				String name = cstr(d, nameOff);
				Address a = addr(program, value);
				if (name.isEmpty() || !program.getMemory().contains(a)) {
					continue;
				}
				label(program, a, name);
				symbolTable.addExternalEntryPoint(a);
				if (func) {
					AbstractProgramLoader.markAsFunction(program, name, a);
				}
				exports++;
			}
		}

		// relocations
		int applied = 0, failed = 0;
		Map<Integer, Integer> unsupported = new TreeMap<>();
		if (optionBool(options, OPT_RELOCS, true)) {
			for (Section s : secs) {
				if (s.type() != SHT_RELA) {
					continue;
				}
				byte[] d = data.get(s.index());
				Sym[] syms = symtabs.get(s.link());
				if (d == null || syms == null) {
					continue;
				}
				for (int o = 0; o + 12 <= d.length; o += 12) {
					monitor.checkCancelled();
					long offset = u(be32(d, o));
					int info = be32(d, o + 4);
					int type = info & 0xFF;
					int symIndex = info >>> 8;
					long addend = be32(d, o + 8);
					Sym sym = symIndex < syms.length ? syms[symIndex] : null;
					long value = (sym != null ? sym.value() : 0) + addend;
					Address at = addr(program, offset);
					int status;
					if (type == R_PPC_EMB_SDA21) {
						status = applySda21(program.getMemory(), at, value, sdaBase, sda2Base);
					}
					else if (type == R_PPC_DTPMOD32 || type == R_PPC_DTPREL32) {
						status = RELOC_UNSUPPORTED; // TLS: resolved by the Cafe loader
					}
					else {
						status = applyPpcRelocation(program, at, type, value);
					}
					if (status == RELOC_OK) {
						applied++;
					}
					else if (status == RELOC_UNSUPPORTED) {
						unsupported.merge(type, 1, Integer::sum);
					}
					else {
						failed++;
					}
					recordRelocation(program, at, type, value,
						type == R_PPC_EMB_SDA21 ? 4 : ppcRelocationLength(type),
						status == RELOC_OK, sym != null ? sym.name() : null);
				}
			}
		}

		// small-data registers over the code
		if (!codeRange.isEmpty()) {
			if (sdaBase != 0) {
				setRegister(program, "r13", codeRange.getMinAddress().getOffset(),
					codeRange.getMaxAddress().getOffset(), sdaBase, log);
			}
			if (sda2Base != 0) {
				setRegister(program, "r2", codeRange.getMinAddress().getOffset(),
					codeRange.getMaxAddress().getOffset(), sda2Base, log);
			}
		}

		Symbol existing = symbolTable.getPrimarySymbol(addr(program, entry));
		entry(program, entry, existing != null && existing.getSource() != SourceType.DEFAULT
				? existing.getName()
				: "entry");

		StructureDataType hs = struct("Elf32_Ehdr_Cafe", "e_ident_magic", bytes(4), "ei_class",
			u8(), "ei_data", u8(), "ei_version", u8(), "ei_osabi", u8(), "ei_abiversion", u8(),
			"ei_pad", bytes(7), "e_type", u16(), "e_machine", u16(), "e_version", u32(),
			"e_entry", u32(), "e_phoff", u32(), "e_shoff", u32(), "e_flags", u32(), "e_ehsize",
			u16(), "e_phentsize", u16(), "e_phnum", u16(), "e_shentsize", u16(), "e_shnum",
			u16(), "e_shstrndx", u16());
		headerBlock(program, eh, hs, "RPX_ELF_HEADER", log);

		info(program, "RPX entry", hex(entry));
		info(program, "RPX sections", map.toString().trim());
		info(program, "RPX imports", imports + " from " + modules);
		info(program, "RPX exports", Integer.toString(exports));
		info(program, "RPX symbols labelled", Integer.toString(labelled));
		info(program, "RPX relocations", applied + " applied, " + failed + " failed, " +
			"unsupported by type " + unsupported);
	}

	/** Creates an external function/data location and a thunk/label at the import slot. */
	private static boolean makeImport(Program program, ExternalManager em, String module,
			String name, Address slot, boolean func, MessageLog log) {
		try {
			if (func) {
				ExternalLocation loc = em.addExtFunction(module, name, null, SourceType.IMPORTED);
				if (program.getMemory().contains(slot)) {
					FunctionManager fm = program.getFunctionManager();
					Function f = fm.getFunctionAt(slot);
					if (f == null) {
						f = fm.createFunction(null, slot, new AddressSet(slot), SourceType.IMPORTED);
					}
					f.setThunkedFunction(loc.getFunction());
				}
			}
			else {
				ExternalLocation loc = em.addExtLocation(module, name, null, SourceType.IMPORTED);
				if (program.getMemory().contains(slot)) {
					Namespace ns = program.getSymbolTable().getNamespace(module + "_imports", null);
					if (ns == null) {
						ns = program.getSymbolTable().createNameSpace(null, module + "_imports",
							SourceType.IMPORTED);
					}
					program.getSymbolTable().createLabel(slot, name, ns, SourceType.IMPORTED);
					program.getReferenceManager()
							.addExternalReference(slot, 0, loc, SourceType.IMPORTED,
								RefType.DATA);
				}
			}
			return true;
		}
		catch (Exception e) {
			log.appendMsg("Import " + module + "::" + name + ": " + e.getMessage());
			return false;
		}
	}

	/** R_PPC_EMB_SDA21: rA := r13 (or r2) and d16 := value - base. */
	private static int applySda21(Memory mem, Address at, long value, long sdaBase,
			long sda2Base) {
		try {
			int insn = mem.getInt(at, true);
			long d13 = value - sdaBase, d2 = value - sda2Base;
			int reg;
			long d;
			if (sdaBase != 0 && d13 >= -0x8000 && d13 <= 0x7FFF) {
				reg = 13;
				d = d13;
			}
			else if (sda2Base != 0 && d2 >= -0x8000 && d2 <= 0x7FFF) {
				reg = 2;
				d = d2;
			}
			else if (value <= 0x7FFF) {
				reg = 0;
				d = value;
			}
			else {
				return RELOC_OVERFLOW;
			}
			insn = (insn & 0xFFE00000) | (reg << 16) | ((int) d & 0xFFFF);
			mem.setInt(at, insn, true);
			return RELOC_OK;
		}
		catch (MemoryAccessException e) {
			return RELOC_NO_MEMORY;
		}
	}
}
