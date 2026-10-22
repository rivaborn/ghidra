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
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;

/**
 * MSX cartridge ROM (.rom/.mx1/.mx2): "AB" header (INIT +2, STATEMENT +4, DEVICE +6, TEXT +8),
 * plain ROMs at 0x4000 / 0x8000 / 0x0000, and the ASCII8, ASCII16, Konami and Konami SCC
 * MegaROM mappers (banks beyond the initial mapping become overlay blocks).
 */
public class MsxRomLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "MSX Cartridge ROM";
	static final LanguageCompilerSpecPair LANG = new LanguageCompilerSpecPair("z80:LE:16:default",
		"default");

	public static final String OPT_MAPPER = "MSX mapper";
	public static final String OPT_WINDOW = "MSX bank window";
	static final String AUTO = "auto";
	static final List<String> MAPPERS =
		List.of(AUTO, "plain", "ASCII8", "ASCII16", "Konami", "KonamiSCC");

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.GENERIC_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 60;
	}

	/** Where the "AB" header is: file offset 0 or 0x4000, or -1. */
	static int headerOffset(byte[] b, long fileLength) {
		if (validHeader(b, 0)) {
			// a 48 KB / 64 KB image with page 0 first carries the header at 0x4000
			if ((fileLength == 0xC000 || fileLength == 0x10000) && validHeader(b, 0x4000)) {
				return 0x4000;
			}
			return 0;
		}
		if (fileLength >= 0x8000 && fileLength <= 0x10000 && validHeader(b, 0x4000)) {
			return 0x4000;
		}
		return -1;
	}

	static boolean validHeader(byte[] b, int off) {
		if (b.length < off + 0x10 || b[off] != 'A' || b[off + 1] != 'B') {
			return false;
		}
		int init = u16le(b, off + 2), stmt = u16le(b, off + 4), dev = u16le(b, off + 6),
				text = u16le(b, off + 8);
		for (int v : new int[] { init, stmt, dev, text }) {
			if (v != 0 && (v < 0x4000 || v > 0xBFFF)) {
				return false;
			}
		}
		return init != 0 || text != 0;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		long len = provider.length();
		if (len < 0x10 || len > 0x800000) {
			return specs;
		}
		byte[] probe = provider.readBytes(0, Math.min(len, 0x4010));
		int hdr = headerOffset(probe, len);
		if (hdr < 0) {
			return specs;
		}
		String ext = extension(provider);
		boolean extOk = ext.equals("rom") || ext.equals("mx1") || ext.equals("mx2");
		boolean reservedZero = true;
		for (int i = 0x0A; i < 0x10; i++) {
			reservedZero &= probe[hdr + i] == 0;
		}
		if (extOk || (len % 0x2000 == 0 && reservedZero)) {
			specs.add(new LoadSpec(this, 0, LANG, true));
		}
		return specs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		list.add(new Option(OPT_MAPPER, AUTO, String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-msxMapper"));
		list.add(new Option(OPT_WINDOW, AUTO, String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-msxBankWindow"));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null) {
			for (Option o : options) {
				if (o.getName().equals(OPT_MAPPER)) {
					String v = String.valueOf(o.getValue());
					if (MAPPERS.stream().noneMatch(m -> m.equalsIgnoreCase(v))) {
						return OPT_MAPPER + " must be one of " + MAPPERS;
					}
				}
				else if (o.getName().equals(OPT_WINDOW)) {
					String v = String.valueOf(o.getValue());
					if (!v.equalsIgnoreCase(AUTO) && parseWindow(v) < 0) {
						return OPT_WINDOW + " must be auto, 0x4000, 0x6000, 0x8000 or 0xA000";
					}
				}
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	static int parseWindow(String v) {
		try {
			String s = v.trim().toLowerCase(Locale.ROOT);
			int w = Integer.parseInt(s.startsWith("0x") ? s.substring(2) : s, 16);
			return (w == 0x4000 || w == 0x6000 || w == 0x8000 || w == 0xA000) ? w : -1;
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, ImporterSettings settings) {
		// none for z80
	}

	/** Mapper description: bank size, windows, and the register that selects each window. */
	record Mapper(String name, int bankSize, int[] windows, int[] registers, int[] initialBanks,
			boolean firstWindowFixed) {}

	static Mapper mapper(String name) {
		switch (name.toUpperCase(Locale.ROOT)) {
			case "ASCII8":
				return new Mapper("ASCII8", 0x2000, new int[] { 0x4000, 0x6000, 0x8000, 0xA000 },
					new int[] { 0x6000, 0x6800, 0x7000, 0x7800 }, new int[] { 0, 1, 2, 3 }, false);
			case "ASCII16":
				return new Mapper("ASCII16", 0x4000, new int[] { 0x4000, 0x8000 },
					new int[] { 0x6000, 0x7000 }, new int[] { 0, 1 }, false);
			case "KONAMI":
				return new Mapper("Konami", 0x2000, new int[] { 0x4000, 0x6000, 0x8000, 0xA000 },
					new int[] { -1, 0x6000, 0x8000, 0xA000 }, new int[] { 0, 1, 2, 3 }, true);
			case "KONAMISCC":
				return new Mapper("KonamiSCC", 0x2000,
					new int[] { 0x4000, 0x6000, 0x8000, 0xA000 },
					new int[] { 0x5000, 0x7000, 0x9000, 0xB000 }, new int[] { 0, 1, 2, 3 }, false);
			default:
				return null;
		}
	}

	/**
	 * Counts {@code LD (nnnn),A} (0x32 nn nn) by target address and guesses the mapper.
	 * Returns {ASCII8, ASCII16, Konami, KonamiSCC} scores in {@code scores}.
	 */
	static String guessMapper(byte[] rom, Map<Integer, Integer> writes, int[] scores) {
		for (int i = 0; i + 2 < rom.length; i++) {
			if ((rom[i] & 0xff) == 0x32) {
				int a = u16le(rom, i + 1);
				if (a >= 0x4000 && a < 0xC000) {
					writes.merge(a, 1, Integer::sum);
				}
			}
		}
		int ascii8 = 0, ascii16 = 0, konami = 0, scc = 0;
		for (Map.Entry<Integer, Integer> e : writes.entrySet()) {
			int n = e.getValue();
			switch (e.getKey()) {
				case 0x5000, 0x9000, 0xB000 -> scc += n;
				case 0x4000, 0x8000, 0xA000 -> konami += n;
				case 0x6800, 0x7800 -> ascii8 += n;
				case 0x6000 -> {
					konami += n;
					ascii8 += n;
					ascii16 += n;
				}
				case 0x7000 -> {
					scc += n;
					ascii8 += n;
					ascii16 += n;
				}
				case 0x77FF -> ascii16 += n;
				default -> {
					// not a mapper register
				}
			}
		}
		scores[0] = ascii8;
		scores[1] = ascii16;
		scores[2] = konami;
		scores[3] = scc;
		// ties resolve in this order: KonamiSCC, Konami, ASCII16, ASCII8
		String best = "ASCII8";
		int bestScore = ascii8;
		if (ascii16 >= bestScore) {
			best = "ASCII16";
			bestScore = ascii16;
		}
		if (konami >= bestScore && konami > 0) {
			best = "Konami";
			bestScore = konami;
		}
		if (scc >= bestScore && scc > 0) {
			best = "KonamiSCC";
		}
		return best;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		MessageLog log = settings.log();
		ByteProvider p = settings.provider();
		AddressSpace mem = program.getAddressFactory().getDefaultAddressSpace();
		AddressSpace io = program.getAddressFactory().getAddressSpace("io");
		byte[] rom = p.readBytes(0, p.length());
		FileBytes fb = MemoryBlockUtils.createFileBytes(program, p, settings.monitor());

		int hdr = headerOffset(rom, rom.length);
		if (hdr < 0) {
			throw new IOException("No MSX \"AB\" header");
		}
		String opt = OptionUtils.getOption(OPT_MAPPER, settings.options(), AUTO);
		String winOpt = OptionUtils.getOption(OPT_WINDOW, settings.options(), AUTO);

		Map<Integer, Integer> writes = new TreeMap<>();
		int[] scores = new int[4];
		String guessed = guessMapper(rom, writes, scores);
		boolean needsMapper = rom.length > 0x10000 || (rom.length == 0x10000 && hdr == 0);
		String chosen;
		if (!opt.equalsIgnoreCase(AUTO)) {
			chosen = opt;
		}
		else {
			chosen = needsMapper ? guessed : "plain";
		}
		property(program, "MSX mapper scores (ASCII8/ASCII16/Konami/KonamiSCC)",
			scores[0] + "/" + scores[1] + "/" + scores[2] + "/" + scores[3]);
		property(program, "MSX mapper", chosen + (opt.equalsIgnoreCase(AUTO) ? " (auto)" : ""));

		int base;
		Mapper m = mapper(chosen);
		if (m == null) {
			// plain ROM
			if (hdr == 0x4000) {
				base = 0x0000;
			}
			else {
				int init = u16le(rom, 2), text = u16le(rom, 8);
				int key = init != 0 ? init : text;
				base = (rom.length <= 0x4000 && key >= 0x8000) ? 0x8000 : 0x4000;
			}
			int size = Math.min(rom.length, 0x10000 - base);
			if (size < rom.length) {
				log.appendMsg("ROM larger than the space above " + hex(base, 4) +
					"; only the first " + hex(size, 4) + " bytes mapped (use a mapper option)");
			}
			fileBlock(program, "ROM", mem.getAddress(base), fb, 0, size, false, true, false, true,
				"cartridge ROM", log);
		}
		else {
			base = 0x4000;
			mapBanks(program, mem, fb, rom, m, writes, winOpt, log);
		}

		// BIOS, RAM, I/O
		boolean biosVisible = !program.getMemory().contains(mem.getAddress(0));
		fillGaps(program, mem, "BIOS", 0x0000, 0x3FFF, true, false, true, false,
			"MSX BIOS ROM (slot 0, not loaded)", log);
		fillGaps(program, mem, "PAGE2", 0x8000, 0xBFFF, true, true, true, false,
			"page 2 (other slot / RAM)", log);
		fillGaps(program, mem, "RAM", 0xC000, 0xFFFF, true, true, true, false,
			"RAM (system work area from 0xF380)", log);
		if (io != null) {
			uninitBlock(program, "IO_PORTS", io.getAddress(0), 0x100, false, true, true, false,
				true, "Z80 I/O ports", log);
			labelTable(program, io, IO_PORTS, log);
		}
		if (biosVisible) {
			for (Object[] row : BIOS) {
				externalRoutine(program, "MSX_BIOS", (String) row[1],
					mem.getAddress(((Number) row[0]).longValue()), log);
			}
		}
		labelTable(program, mem, SYSTEM_VARS, log);

		// header
		Address h = mem.getAddress(hdr == 0x4000 ? 0x4000 : base);
		int init = u16le(rom, hdr + 2), stmt = u16le(rom, hdr + 4), dev = u16le(rom, hdr + 6),
				text = u16le(rom, hdr + 8);
		markHeader(program, h, log);
		property(program, "MSX header", String.format(
			"at %s: INIT %s STATEMENT %s DEVICE %s TEXT %s", h, hex(init, 4), hex(stmt, 4),
			hex(dev, 4), hex(text, 4)));
		if (init != 0) {
			entry(program, mem.getAddress(init), "INIT", log);
		}
		if (stmt != 0) {
			entry(program, mem.getAddress(stmt), "STATEMENT", log);
		}
		if (dev != 0) {
			entry(program, mem.getAddress(dev), "DEVICE", log);
		}
		if (text != 0) {
			label(program, mem.getAddress(text), "BASIC_TEXT", true, log);
		}
	}

	private void mapBanks(Program program, AddressSpace mem, FileBytes fb, byte[] rom, Mapper m,
			Map<Integer, Integer> writes, String winOpt, MessageLog log) {
		int banks = (rom.length + m.bankSize() - 1) / m.bankSize();
		if (rom.length % m.bankSize() != 0) {
			log.appendMsg("ROM size is not a multiple of the bank size; last bank is partial");
		}
		// home window for banks outside the initial mapping
		int home;
		int forced = winOpt.equalsIgnoreCase(AUTO) ? -1 : parseWindow(winOpt);
		if (forced >= 0) {
			home = forced;
			if (m.bankSize() == 0x4000 && home != 0x4000 && home != 0x8000) {
				home = home < 0x8000 ? 0x4000 : 0x8000;
			}
		}
		else {
			home = -1;
			int best = -1;
			for (int w = 0; w < m.windows().length; w++) {
				if (m.registers()[w] < 0) {
					continue;
				}
				int n = writes.getOrDefault(m.registers()[w], 0);
				if (m.name().equals("ASCII16") && w == 1) {
					n += writes.getOrDefault(0x77FF, 0);
				}
				if (n > best) {
					best = n;
					home = m.windows()[w];
				}
			}
		}
		property(program, "MSX bank window", hex(home, 4) + (forced >= 0 ? " (forced)" : ""));

		Set<Integer> initial = new HashSet<>();
		for (int w = 0; w < m.windows().length; w++) {
			int bank = m.initialBanks()[w];
			if (bank >= banks) {
				continue;
			}
			initial.add(bank);
			int off = bank * m.bankSize();
			fileBlock(program, String.format("BANK%02d", bank), mem.getAddress(m.windows()[w]),
				fb, off, Math.min(m.bankSize(), rom.length - off), false, true, false, true,
				String.format("%s bank %d (file 0x%X) in its initial window", m.name(), bank, off),
				log);
			if (m.registers()[w] >= 0) {
				label(program, mem.getAddress(m.registers()[w]),
					String.format("MAPPER_SEL_%04X", m.windows()[w]), true, log);
			}
		}
		for (int bank = 0; bank < banks; bank++) {
			if (initial.contains(bank)) {
				continue;
			}
			int off = bank * m.bankSize();
			fileBlock(program, String.format("BANK%02d", bank), mem.getAddress(home), fb, off,
				Math.min(m.bankSize(), rom.length - off), true, true, false, true,
				String.format("%s bank %d (file 0x%X), overlay of window %s", m.name(), bank, off,
					hex(home, 4)),
				log);
		}
		if (m.name().equals("ASCII16")) {
			label(program, mem.getAddress(0x77FF), "MAPPER_SEL_8000_ALT", false, log);
		}
		if (m.name().equals("KonamiSCC")) {
			label(program, mem.getAddress(0x9800), "SCC_WAVEFORM", true, log);
			label(program, mem.getAddress(0x9880), "SCC_FREQUENCY", true, log);
			label(program, mem.getAddress(0x988A), "SCC_VOLUME", true, log);
			label(program, mem.getAddress(0x988F), "SCC_ENABLE", true, log);
		}
	}

	private static void markHeader(Program program, Address h, MessageLog log) {
		try {
			program.getListing().createData(h, new StringDataType(), 2);
			for (int i = 0; i < 4; i++) {
				program.getListing().createData(h.add(2 + 2 * i), PointerDataType.dataType);
			}
			program.getListing()
					.setComment(h, CommentType.PLATE,
						"MSX cartridge header: ID, INIT, STATEMENT, DEVICE, TEXT");
			label(program, h, "ROM_HEADER", true, log);
		}
		catch (CodeUnitInsertionException e) {
			log.appendMsg("Cannot mark up header: " + e.getMessage());
		}
	}

	static final Object[][] IO_PORTS = { { 0x98, "VDP_DATA" }, { 0x99, "VDP_CTRL" },
		{ 0x9A, "VDP_PALETTE" }, { 0x9B, "VDP_INDIRECT" }, { 0xA0, "PSG_ADDR" },
		{ 0xA1, "PSG_WRITE" }, { 0xA2, "PSG_READ" }, { 0xA8, "PPI_A_SLOTSEL" },
		{ 0xA9, "PPI_B_KEYROW" }, { 0xAA, "PPI_C" }, { 0xAB, "PPI_CTRL" },
		{ 0xFC, "MAPPER_PAGE0" }, { 0xFD, "MAPPER_PAGE1" }, { 0xFE, "MAPPER_PAGE2" },
		{ 0xFF, "MAPPER_PAGE3" } };

	static final Object[][] SYSTEM_VARS = { { 0xF3AE, "LINL40" }, { 0xF3DB, "CLIKSW" },
		{ 0xFCC1, "EXPTBL" }, { 0xFCC5, "SLTTBL" }, { 0xFD9A, "H_KEYI" }, { 0xFD9F, "H_TIMI" },
		{ 0xFFFF, "SUBSLOT_REG" } };

	/** MSX BIOS jump table (0x0000-0x0159). */
	static final Object[][] BIOS = { { 0x0000, "CHKRAM" }, { 0x0008, "SYNCHR" },
		{ 0x000C, "RDSLT" }, { 0x0010, "CHRGTR" }, { 0x0014, "WRSLT" }, { 0x0018, "OUTDO" },
		{ 0x001C, "CALSLT" }, { 0x0020, "DCOMPR" }, { 0x0024, "ENASLT" }, { 0x0028, "GETYPR" },
		{ 0x0030, "CALLF" }, { 0x0038, "KEYINT" }, { 0x003B, "INITIO" }, { 0x003E, "INIFNK" },
		{ 0x0041, "DISSCR" }, { 0x0044, "ENASCR" }, { 0x0047, "WRTVDP" }, { 0x004A, "RDVRM" },
		{ 0x004D, "WRTVRM" }, { 0x0050, "SETRD" }, { 0x0053, "SETWRT" }, { 0x0056, "FILVRM" },
		{ 0x0059, "LDIRMV" }, { 0x005C, "LDIRVM" }, { 0x005F, "CHGMOD" }, { 0x0062, "CHGCLR" },
		{ 0x0066, "NMI" }, { 0x0069, "CLRSPR" }, { 0x006C, "INITXT" }, { 0x006F, "INIT32" },
		{ 0x0072, "INIGRP" }, { 0x0075, "INIMLT" }, { 0x0078, "SETTXT" }, { 0x007B, "SETT32" },
		{ 0x007E, "SETGRP" }, { 0x0081, "SETMLT" }, { 0x0084, "CALPAT" }, { 0x0087, "CALATR" },
		{ 0x008A, "GSPSIZ" }, { 0x008D, "GRPPRT" }, { 0x0090, "GICINI" }, { 0x0093, "WRTPSG" },
		{ 0x0096, "RDPSG" }, { 0x0099, "STRTMS" }, { 0x009C, "CHSNS" }, { 0x009F, "CHGET" },
		{ 0x00A2, "CHPUT" }, { 0x00A5, "LPTOUT" }, { 0x00A8, "LPTSTT" }, { 0x00AB, "CNVCHR" },
		{ 0x00AE, "PINLIN" }, { 0x00B1, "INLIN" }, { 0x00B4, "QINLIN" }, { 0x00B7, "BREAKX" },
		{ 0x00BA, "ISCNTC" }, { 0x00BD, "CKCNTC" }, { 0x00C0, "BEEP" }, { 0x00C3, "CLS" },
		{ 0x00C6, "POSIT" }, { 0x00C9, "FNKSB" }, { 0x00CC, "ERAFNK" }, { 0x00CF, "DSPFNK" },
		{ 0x00D2, "TOTEXT" }, { 0x00D5, "GTSTCK" }, { 0x00D8, "GTTRIG" }, { 0x00DB, "GTPAD" },
		{ 0x00DE, "GTPDL" }, { 0x00E1, "TAPION" }, { 0x00E4, "TAPIN" }, { 0x00E7, "TAPIOF" },
		{ 0x00EA, "TAPOON" }, { 0x00ED, "TAPOUT" }, { 0x00F0, "TAPOOF" }, { 0x00F3, "STMOTR" },
		{ 0x00F6, "LFTQ" }, { 0x00F9, "PUTQ" }, { 0x00FC, "RIGHTC" }, { 0x00FF, "LEFTC" },
		{ 0x0102, "UPC" }, { 0x0105, "TUPC" }, { 0x0108, "DOWNC" }, { 0x010B, "TDOWNC" },
		{ 0x010E, "SCALXY" }, { 0x0111, "MAPXY" }, { 0x0114, "FETCHC" }, { 0x0117, "STOREC" },
		{ 0x011A, "SETATR" }, { 0x011D, "READC" }, { 0x0120, "SETC" }, { 0x0123, "NSETCX" },
		{ 0x0126, "GTASPC" }, { 0x0129, "PNTINI" }, { 0x012C, "SCANR" }, { 0x012F, "SCANL" },
		{ 0x0132, "CHGCAP" }, { 0x0135, "CHGSND" }, { 0x0138, "RSLREG" }, { 0x013B, "WSLREG" },
		{ 0x013E, "RDVDP" }, { 0x0141, "SNSMAT" }, { 0x0144, "PHYDIO" }, { 0x0147, "FORMAT" },
		{ 0x014A, "ISFLIO" }, { 0x014D, "OUTDLP" }, { 0x0150, "GETVCP" }, { 0x0153, "GETVC2" },
		{ 0x0156, "KILBUF" }, { 0x0159, "CALBAS" } };
}
