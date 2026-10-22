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

import static ghidra.app.util.opinion.console.NintendoCartUtil.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Super Nintendo / Super Famicom cartridge images (.sfc / .smc).
 * <p>
 * The internal header (at ROM offset 0x7FC0 for LoROM, 0xFFC0 for HiROM, 0x40FFC0 for ExHiROM,
 * after an optional 512-byte copier header) is located by scoring each candidate. ROM is mapped
 * into the 65816's 24-bit address space the way the cartridge board decodes it: every ROM bank
 * once at its canonical address, plus (optionally) byte-mapped mirror views. WRAM, the low-RAM
 * mirror, the PPU / CPU / DMA registers and SRAM are created as uninitialized blocks, the
 * native and emulation vectors are labelled and RESET is the entry point (in emulation mode).
 */
public class SnesLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Super Nintendo (SNES) ROM";
	public static final String LANGUAGE_ID = "65816:LE:24:default";
	public static final String COMPILER_ID = "default";

	public static final String OPT_MAPPING = "SNES ROM mapping";
	public static final String OPT_BANKS = "SNES LoROM canonical banks";
	public static final String OPT_MIRRORS = "SNES ROM and low-area mirrors";
	public static final String OPT_COPIER = "SNES copier header";

	/** Cartridge address decoding. */
	public enum Mapping {
		LOROM(0x7FC0, "LoROM"), HIROM(0xFFC0, "HiROM"), EXHIROM(0x40FFC0, "ExHiROM");

		public final int headerOffset;
		public final String label;

		Mapping(int headerOffset, String label) {
			this.headerOffset = headerOffset;
			this.label = label;
		}
	}

	/** Parsed internal header and its detection score. */
	public static final class SnesHeader {
		public int copierHeader;       // 0 or 512
		public long romSize;           // file size minus copier header
		public Mapping mapping;
		public int score;
		public byte[] hdr = new byte[0x40]; // ROM[headerOffset .. +0x40)
		public byte[] ext = new byte[0x10]; // ROM[headerOffset-0x10 .. headerOffset)
		public int computedChecksum = -1;

		public int mapMode() {
			return hdr[0x15] & 0xFF;
		}

		public int romType() {
			return hdr[0x16] & 0xFF;
		}

		public int romSizeByte() {
			return hdr[0x17] & 0xFF;
		}

		public int sramSizeByte() {
			return hdr[0x18] & 0xFF;
		}

		public int region() {
			return hdr[0x19] & 0xFF;
		}

		public int developer() {
			return hdr[0x1A] & 0xFF;
		}

		public int version() {
			return hdr[0x1B] & 0xFF;
		}

		public int complement() {
			return u16(hdr, 0x1C);
		}

		public int checksum() {
			return u16(hdr, 0x1E);
		}

		/** Vector at CPU address $00:FFE0+off (off = 0x00..0x1F). */
		public int vector(int off) {
			return u16(hdr, 0x20 + off);
		}

		public boolean isFast() {
			return (mapMode() & 0x10) != 0;
		}

		public String title() {
			return ascii(hdr, 0, 21);
		}

		public long sramSize() {
			int n = sramSizeByte();
			return (n == 0 || n > 0x0A) ? 0 : (1024L << n);
		}

		public long expansionRamSize() {
			if (developer() != 0x33) {
				return 0;
			}
			int n = ext[0x0D] & 0xFF;
			return (n == 0 || n > 0x0A) ? 0 : (1024L << n);
		}

		public int coprocessor() {
			return (romType() & 0x0F) >= 3 ? (romType() >> 4) : -1;
		}
	}

	private static int u16(byte[] b, int off) {
		return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
	}

	// Opcodes a reset handler plausibly starts with (SEI, CLC, SEC, STZ, JMP, JML, REP, SEP,
	// LDA#, LDX#, LDY#, JSR, JSL, BRA, STA abs, STA long, NOP, CLD, XCE).
	private static final Set<Integer> RESET_OPCODES = Set.of(0x78, 0x18, 0x38, 0x9C, 0x4C, 0x5C,
		0xC2, 0xE2, 0xA9, 0xA2, 0xA0, 0x20, 0x22, 0x80, 0x8D, 0x8F, 0xEA, 0xD8, 0xFB);

	/**
	 * Finds the internal header. With {@code force} null, every candidate location must pass the
	 * mandatory checks and the best score (at least 4) wins; otherwise the forced location is
	 * parsed without checks.
	 *
	 * @param provider the file
	 * @param force forced mapping or null
	 * @param copier forced copier-header size (0 / 512) or -1 for automatic (size % 1024 == 512)
	 * @return the header, or null if this is not a SNES ROM
	 * @throws IOException on read error
	 */
	public static SnesHeader detect(ByteProvider provider, Mapping force, int copier)
			throws IOException {
		long len = provider.length();
		if (len < 0x8000 || len > 0x1000000) {
			return null;
		}
		int cop = copier >= 0 ? copier : ((len % 1024) == 512 ? 512 : 0);
		long romSize = len - cop;
		SnesHeader best = null;
		for (Mapping m : Mapping.values()) {
			if (force != null && m != force) {
				continue;
			}
			if (m.headerOffset + 0x40 > romSize) {
				continue;
			}
			SnesHeader h = new SnesHeader();
			h.copierHeader = cop;
			h.romSize = romSize;
			h.mapping = m;
			h.hdr = provider.readBytes(cop + m.headerOffset, 0x40);
			h.ext = provider.readBytes(cop + m.headerOffset - 0x10, 0x10);
			h.score = score(provider, h, force != null);
			if (h.score < 0) {
				continue;
			}
			if (best == null || h.score > best.score) {
				best = h;
			}
		}
		if (best == null || (force == null && best.score < 4)) {
			return null;
		}
		return best;
	}

	private static boolean modeMatches(Mapping m, int mode) {
		if ((mode & 0xE0) != 0x20) {
			return false;
		}
		int lo = mode & 0x0F;
		return switch (m) {
			case LOROM -> lo == 0x0 || lo == 0x2 || lo == 0x3;
			case HIROM -> lo == 0x1 || lo == 0xA;
			case EXHIROM -> lo == 0x5;
		};
	}

	private static int score(ByteProvider provider, SnesHeader h, boolean forced)
			throws IOException {
		int reset = h.vector(0x1C);
		if (!forced) {
			if (!modeMatches(h.mapping, h.mapMode()) || reset < 0x8000) {
				return -1;
			}
		}
		int s = 0;
		if (((h.complement() + h.checksum()) & 0xFFFF) == 0xFFFF) {
			s += 4;
			h.computedChecksum = computeChecksum(provider, h.copierHeader, h.romSize);
			if (h.computedChecksum == h.checksum()) {
				s += 2;
			}
		}
		long resetFile = cpuToRom(h.mapping, reset);
		if (resetFile >= 0 && resetFile < h.romSize) {
			int op = provider.readByte(h.copierHeader + resetFile) & 0xFF;
			if (RESET_OPCODES.contains(op)) {
				s += 2;
			}
		}
		int printable = 0;
		for (int i = 0; i < 21; i++) {
			int c = h.hdr[i] & 0xFF;
			if ((c >= 0x20 && c < 0x7F) || (c >= 0xA0 && c <= 0xDF)) {
				printable++;
			}
		}
		if (printable == 21) {
			s += 2;
		}
		else if (printable >= 16) {
			s += 1;
		}
		int rs = h.romSizeByte();
		if (rs >= 0x08 && rs <= 0x0D) {
			long declared = 1024L << rs;
			if (declared >= h.romSize / 2 && declared <= h.romSize * 2) {
				s += 1;
			}
		}
		if (h.sramSizeByte() <= 0x07) {
			s += 1;
		}
		return s;
	}

	/** 16-bit sum of all ROM bytes, the non-power-of-two tail repeated to the next power of 2. */
	static int computeChecksum(ByteProvider provider, int cop, long romSize) throws IOException {
		long pow = Long.highestOneBit(romSize);
		long head = sum(provider, cop, pow);
		long rest = romSize - pow;
		if (rest == 0) {
			return (int) (head & 0xFFFF);
		}
		long tail = sum(provider, cop + pow, rest);
		long mult = (pow % rest == 0) ? pow / rest : 1;
		return (int) ((head + tail * mult) & 0xFFFF);
	}

	private static long sum(ByteProvider provider, long off, long n) throws IOException {
		long s = 0;
		final int chunk = 0x10000;
		for (long p = 0; p < n; p += chunk) {
			byte[] b = provider.readBytes(off + p, (int) Math.min(chunk, n - p));
			for (byte x : b) {
				s += x & 0xFF;
			}
		}
		return s;
	}

	/** ROM offset seen at CPU bank $00 address {@code addr} (0x8000-0xFFFF), per mapping. */
	static long cpuToRom(Mapping m, int addr) {
		if (addr < 0x8000) {
			return -1;
		}
		return switch (m) {
			case LOROM -> addr - 0x8000;
			case HIROM -> addr;
			case EXHIROM -> 0x400000L + addr;
		};
	}

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
		return 50;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (detect(provider, null, -1) == null) {
			return specs;
		}
		if (!languageExists(getLanguageService(), LANGUAGE_ID)) {
			return specs;
		}
		specs.add(new LoadSpec(this, 0,
			new LanguageCompilerSpecPair(LANGUAGE_ID, COMPILER_ID), true));
		return specs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(new Option(OPT_MAPPING, "auto", String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesMapping"));
		list.add(new Option(OPT_BANKS, "auto", String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesLoRomBanks"));
		list.add(new Option(OPT_MIRRORS, Boolean.TRUE, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesMirrors"));
		list.add(new Option(OPT_COPIER, "auto", String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesCopierHeader"));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String err = checkChoice(options, OPT_MAPPING, "auto", "lorom", "hirom", "exhirom");
		if (err == null) {
			err = checkChoice(options, OPT_BANKS, "auto", "00", "80");
		}
		if (err == null) {
			err = checkChoice(options, OPT_COPIER, "auto", "yes", "no");
		}
		if (err != null) {
			return err;
		}
		List<Option> rest = new ArrayList<>();
		for (Option o : options) {
			if (!o.getName().startsWith("SNES ")) {
				rest.add(o);
			}
		}
		return super.validateOptions(provider, loadSpec, rest, program);
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, ImporterSettings settings) {
		// The loader creates the whole memory map itself.
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		String mapOpt = stringOption(options, OPT_MAPPING, "auto").toLowerCase();
		Mapping force = switch (mapOpt) {
			case "lorom" -> Mapping.LOROM;
			case "hirom" -> Mapping.HIROM;
			case "exhirom" -> Mapping.EXHIROM;
			default -> null;
		};
		String copOpt = stringOption(options, OPT_COPIER, "auto").toLowerCase();
		int copier = copOpt.equals("yes") ? 512 : copOpt.equals("no") ? 0 : -1;
		SnesHeader h = detect(provider, force, copier);
		if (h == null && force == null) {
			// Forced copier size may have hidden the header; retry automatically.
			h = detect(provider, null, -1);
		}
		if (h == null) {
			throw new IOException("No SNES internal header found" +
				(force != null ? " at the " + force.label + " location" : ""));
		}
		if (h.computedChecksum < 0) {
			h.computedChecksum = computeChecksum(provider, h.copierHeader, h.romSize);
		}

		monitor.setMessage("Mapping SNES " + h.mapping.label + " ROM");
		FileBytes fb = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
		boolean mirrors = boolOption(options, OPT_MIRRORS, true);

		String banksOpt = stringOption(options, OPT_BANKS, "auto");
		int loromBase = banksOpt.equals("80") ? 0x80
				: banksOpt.equals("00") ? 0x00 : (h.isFast() ? 0x80 : 0x00);

		switch (h.mapping) {
			case LOROM -> mapLoRom(program, fb, ram, h, loromBase, mirrors, log, monitor);
			case HIROM -> mapHiRom(program, fb, ram, h, false, mirrors, log, monitor);
			case EXHIROM -> mapHiRom(program, fb, ram, h, true, mirrors, log, monitor);
		}

		mapRamAndIo(program, ram, h, mirrors, log);
		labelVectors(program, ram, log);
		writeInfo(program, h, loromBase);
	}

	private static Address a(AddressSpace ram, int bank, int off) {
		return ram.getAddress(((long) bank << 16) | (off & 0xFFFF));
	}

	private void mapLoRom(Program program, FileBytes fb, AddressSpace ram, SnesHeader h,
			int base, boolean mirrors, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		long nb = (h.romSize + 0x7FFF) / 0x8000;
		if (nb > 0x80) {
			log.appendMsg("LoROM image larger than 4 MB: only the first 4 MB are mapped " +
				"(ExLoROM is not supported)");
			nb = 0x80;
		}
		for (int i = 0; i < nb; i++) {
			monitor.checkCancelled();
			long off = (long) i * 0x8000;
			long len = Math.min(0x8000, h.romSize - off);
			int canon;
			if (base == 0x80) {
				canon = 0x80 + i;
			}
			else {
				canon = i < 0x7E ? i : 0x80 + i;
			}
			Address start = a(ram, canon, 0x8000);
			romBlock(program, fb, "rom_" + hex(i, 2), start, h.copierHeader + off, len, false,
				String.format("ROM bank %02X (file 0x%06X) at $%02X:8000", i, off, canon), log);
			int other = canon ^ 0x80;
			if (other == 0x7E || other == 0x7F) {
				continue;
			}
			if (mirrors || (other == 0x00)) {
				mirrorBlock(program, "rom_" + hex(i, 2) + "_m" + hex(other, 2),
					a(ram, other, 0x8000), start, len, false, true, false,
					String.format("mirror of ROM bank %02X ($%02X:8000)", i, canon), log);
			}
		}
	}

	private void mapHiRom(Program program, FileBytes fb, AddressSpace ram, SnesHeader h,
			boolean ex, boolean mirrors, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		long nb = (h.romSize + 0xFFFF) / 0x10000;
		long max = ex ? 0x40 + 0x3E : 0x40;
		if (nb > max) {
			log.appendMsg("ROM larger than the " + (ex ? "ExHiROM" : "HiROM") +
				" address space: only " + max + " banks are mapped");
			nb = max;
		}
		for (int i = 0; i < nb; i++) {
			monitor.checkCancelled();
			long off = (long) i * 0x10000;
			long len = Math.min(0x10000, h.romSize - off);
			int canon = (i < 0x40) ? 0xC0 + i : 0x40 + (i - 0x40);
			Address start = a(ram, canon, 0);
			romBlock(program, fb, "rom_" + hex(i, 2), start, h.copierHeader + off, len, false,
				String.format("ROM bank %02X (file 0x%06X) at $%02X:0000", i, off, canon), log);
			// Upper-half (:8000-FFFF) view in the system banks.
			int sys = ex ? (i < 0x40 ? 0x80 + i : (i - 0x40)) : i; // $00-$3F view
			if (len > 0x8000) {
				Address hiSrc = a(ram, canon, 0x8000);
				boolean needed = (ex ? (i == 0x40) : (i == 0)); // provides $00:8000 (vectors)
				if (!ex) {
					if (mirrors || needed) {
						mirrorBlock(program, "rom_" + hex(i, 2) + "_m" + hex(sys, 2),
							a(ram, sys, 0x8000), hiSrc, len - 0x8000, false, true, false,
							String.format("upper half of ROM bank %02X", i), log);
					}
					if (mirrors) {
						mirrorBlock(program, "rom_" + hex(i, 2) + "_m" + hex(0x80 + i, 2),
							a(ram, 0x80 + i, 0x8000), hiSrc, len - 0x8000, false, true, false,
							String.format("upper half of ROM bank %02X", i), log);
					}
				}
				else if (mirrors || needed) {
					mirrorBlock(program, "rom_" + hex(i, 2) + "_m" + hex(sys, 2),
						a(ram, sys, 0x8000), hiSrc, len - 0x8000, false, true, false,
						String.format("upper half of ROM bank %02X", i), log);
				}
			}
			// HiROM: $40-$7D full-bank view of the first 62 banks.
			if (!ex && mirrors && i < 0x3E) {
				mirrorBlock(program, "rom_" + hex(i, 2) + "_m" + hex(0x40 + i, 2),
					a(ram, 0x40 + i, 0), start, len, false, true, false,
					String.format("mirror of ROM bank %02X", i), log);
			}
		}
	}

	// PPU registers $2100-$21FF
	private static final String[][] PPU_REGS = {
		{ "2100", "INIDISP", "display control (forced blank, brightness)" },
		{ "2101", "OBSEL", "object size and character base" },
		{ "2102", "OAMADDL", "OAM address low" }, { "2103", "OAMADDH", "OAM address high" },
		{ "2104", "OAMDATA", "OAM data write" }, { "2105", "BGMODE", "BG mode and tile size" },
		{ "2106", "MOSAIC", "mosaic" }, { "2107", "BG1SC", "BG1 tilemap address/size" },
		{ "2108", "BG2SC", "BG2 tilemap address/size" },
		{ "2109", "BG3SC", "BG3 tilemap address/size" },
		{ "210A", "BG4SC", "BG4 tilemap address/size" },
		{ "210B", "BG12NBA", "BG1/2 character base" },
		{ "210C", "BG34NBA", "BG3/4 character base" }, { "210D", "BG1HOFS", "BG1 H scroll" },
		{ "210E", "BG1VOFS", "BG1 V scroll" }, { "210F", "BG2HOFS", "BG2 H scroll" },
		{ "2110", "BG2VOFS", "BG2 V scroll" }, { "2111", "BG3HOFS", "BG3 H scroll" },
		{ "2112", "BG3VOFS", "BG3 V scroll" }, { "2113", "BG4HOFS", "BG4 H scroll" },
		{ "2114", "BG4VOFS", "BG4 V scroll" }, { "2115", "VMAIN", "VRAM address increment" },
		{ "2116", "VMADDL", "VRAM address low" }, { "2117", "VMADDH", "VRAM address high" },
		{ "2118", "VMDATAL", "VRAM data write low" },
		{ "2119", "VMDATAH", "VRAM data write high" },
		{ "211A", "M7SEL", "mode 7 settings" }, { "211B", "M7A", "mode 7 matrix A" },
		{ "211C", "M7B", "mode 7 matrix B" }, { "211D", "M7C", "mode 7 matrix C" },
		{ "211E", "M7D", "mode 7 matrix D" }, { "211F", "M7X", "mode 7 center X" },
		{ "2120", "M7Y", "mode 7 center Y" }, { "2121", "CGADD", "CGRAM address" },
		{ "2122", "CGDATA", "CGRAM data write" }, { "2123", "W12SEL", "window mask BG1/2" },
		{ "2124", "W34SEL", "window mask BG3/4" }, { "2125", "WOBJSEL", "window mask OBJ/color" },
		{ "2126", "WH0", "window 1 left" }, { "2127", "WH1", "window 1 right" },
		{ "2128", "WH2", "window 2 left" }, { "2129", "WH3", "window 2 right" },
		{ "212A", "WBGLOG", "window logic BG" }, { "212B", "WOBJLOG", "window logic OBJ/color" },
		{ "212C", "TM", "main screen designation" }, { "212D", "TS", "sub screen designation" },
		{ "212E", "TMW", "main screen window mask" }, { "212F", "TSW", "sub screen window mask" },
		{ "2130", "CGWSEL", "color math control A" }, { "2131", "CGADSUB", "color math control B" },
		{ "2132", "COLDATA", "fixed color data" }, { "2133", "SETINI", "screen mode select" },
		{ "2134", "MPYL", "multiply result low" }, { "2135", "MPYM", "multiply result middle" },
		{ "2136", "MPYH", "multiply result high" }, { "2137", "SLHV", "latch H/V counter" },
		{ "2138", "OAMDATAREAD", "OAM data read" },
		{ "2139", "VMDATALREAD", "VRAM data read low" },
		{ "213A", "VMDATAHREAD", "VRAM data read high" },
		{ "213B", "CGDATAREAD", "CGRAM data read" },
		{ "213C", "OPHCT", "H counter latch" }, { "213D", "OPVCT", "V counter latch" },
		{ "213E", "STAT77", "PPU1 status" }, { "213F", "STAT78", "PPU2 status" },
		{ "2140", "APUIO0", "APU I/O port 0" }, { "2141", "APUIO1", "APU I/O port 1" },
		{ "2142", "APUIO2", "APU I/O port 2" }, { "2143", "APUIO3", "APU I/O port 3" },
		{ "2180", "WMDATA", "WRAM data port" }, { "2181", "WMADDL", "WRAM address low" },
		{ "2182", "WMADDM", "WRAM address middle" }, { "2183", "WMADDH", "WRAM address high" } };

	// Joypad serial ports and CPU registers $4016-$4017, $4200-$421F
	private static final String[][] CPU_REGS = {
		{ "4016", "JOYSER0", "joypad serial port 1 / latch" },
		{ "4017", "JOYSER1", "joypad serial port 2" },
		{ "4200", "NMITIMEN", "NMI / IRQ / auto-joypad enable" },
		{ "4201", "WRIO", "programmable I/O port out" },
		{ "4202", "WRMPYA", "multiplicand" }, { "4203", "WRMPYB", "multiplier (starts)" },
		{ "4204", "WRDIVL", "dividend low" }, { "4205", "WRDIVH", "dividend high" },
		{ "4206", "WRDIVB", "divisor (starts)" }, { "4207", "HTIMEL", "H timer low" },
		{ "4208", "HTIMEH", "H timer high" }, { "4209", "VTIMEL", "V timer low" },
		{ "420A", "VTIMEH", "V timer high" }, { "420B", "MDMAEN", "general DMA enable" },
		{ "420C", "HDMAEN", "HDMA enable" }, { "420D", "MEMSEL", "FastROM select" },
		{ "4210", "RDNMI", "NMI flag / CPU version" }, { "4211", "TIMEUP", "IRQ flag" },
		{ "4212", "HVBJOY", "H/V blank and joypad status" },
		{ "4213", "RDIO", "programmable I/O port in" },
		{ "4214", "RDDIVL", "quotient low" }, { "4215", "RDDIVH", "quotient high" },
		{ "4216", "RDMPYL", "product / remainder low" },
		{ "4217", "RDMPYH", "product / remainder high" },
		{ "4218", "JOY1L", "joypad 1 low" }, { "4219", "JOY1H", "joypad 1 high" },
		{ "421A", "JOY2L", "joypad 2 low" }, { "421B", "JOY2H", "joypad 2 high" },
		{ "421C", "JOY3L", "joypad 3 low" }, { "421D", "JOY3H", "joypad 3 high" },
		{ "421E", "JOY4L", "joypad 4 low" }, { "421F", "JOY4H", "joypad 4 high" } };

	// DMA channel registers $43x0-$43xB
	private static final String[][] DMA_REGS = { { "0", "DMAP", "DMA/HDMA parameters" },
		{ "1", "BBAD", "B-bus address" }, { "2", "A1TL", "A-bus address low" },
		{ "3", "A1TH", "A-bus address high" }, { "4", "A1B", "A-bus bank" },
		{ "5", "DASL", "byte count low / HDMA indirect address low" },
		{ "6", "DASH", "byte count high / HDMA indirect address high" },
		{ "7", "DASB", "HDMA indirect bank" }, { "8", "A2AL", "HDMA table address low" },
		{ "9", "A2AH", "HDMA table address high" }, { "A", "NTRL", "HDMA line counter" },
		{ "B", "UNUSED", "unused (read/write)" } };

	private void mapRamAndIo(Program program, AddressSpace ram, SnesHeader h, boolean mirrors,
			MessageLog log) {
		Address wram = a(ram, 0x7E, 0);
		ramBlock(program, "WRAM", wram, 0x20000, false, true, false,
			"work RAM $7E0000-$7FFFFF (128 KB)", log);
		mirrorBlock(program, "WRAM_LOW", a(ram, 0x00, 0), wram, 0x2000, true, true, false,
			"low 8 KB of WRAM (mirrored in banks $00-$3F/$80-$BF)", log);
		ramBlock(program, "PPU_REGS", a(ram, 0x00, 0x2100), 0x100, false, false, true,
			"PPU / APU port / WRAM port registers", log);
		ramBlock(program, "JOY_REGS", a(ram, 0x00, 0x4016), 2, false, false, true,
			"old-style joypad ports", log);
		ramBlock(program, "CPU_REGS", a(ram, 0x00, 0x4200), 0x200, false, false, true,
			"CPU (S-CPU) and DMA registers", log);
		if (mirrors) {
			mirrorBlock(program, "WRAM_LOW_80", a(ram, 0x80, 0), wram, 0x2000, true, true,
				false, "low 8 KB of WRAM (bank $80 view)", log);
			mirrorBlock(program, "PPU_REGS_80", a(ram, 0x80, 0x2100), a(ram, 0, 0x2100), 0x100,
				true, false, true, "PPU registers (bank $80 view)", log);
			mirrorBlock(program, "JOY_REGS_80", a(ram, 0x80, 0x4016), a(ram, 0, 0x4016), 2,
				true, false, true, "joypad ports (bank $80 view)", log);
			mirrorBlock(program, "CPU_REGS_80", a(ram, 0x80, 0x4200), a(ram, 0, 0x4200), 0x200,
				true, false, true, "CPU / DMA registers (bank $80 view)", log);
		}
		int[] banks = mirrors ? new int[] { 0x00, 0x80 } : new int[] { 0x00 };
		for (int bank : banks) {
			for (String[] r : PPU_REGS) {
				label(program, a(ram, bank, Integer.parseInt(r[0], 16)), r[1],
					bank == 0 ? r[2] : null, true);
			}
			for (String[] r : CPU_REGS) {
				label(program, a(ram, bank, Integer.parseInt(r[0], 16)), r[1],
					bank == 0 ? r[2] : null, true);
			}
			for (int ch = 0; ch < 8; ch++) {
				for (String[] r : DMA_REGS) {
					int off = 0x4300 | (ch << 4) | Integer.parseInt(r[0], 16);
					label(program, a(ram, bank, off), r[1] + ch,
						bank == 0 ? "DMA channel " + ch + ": " + r[2] : null, true);
				}
			}
		}
		// Cartridge SRAM
		long sram = h.sramSize();
		String sramName = "SRAM";
		if (sram == 0 && h.coprocessor() == 1) { // SuperFX: GSU RAM in the expansion header
			sram = h.expansionRamSize();
			sramName = "GSU_RAM";
		}
		if (sram > 0) {
			if (h.mapping == Mapping.LOROM) {
				for (int k = 0; k * 0x8000L < sram && k < 0x0E; k++) {
					long len = Math.min(0x8000, sram - k * 0x8000L);
					ramBlock(program, k == 0 ? sramName : sramName + "_" + hex(0x70 + k, 2),
						a(ram, 0x70 + k, 0), len, false, false, false,
						"cartridge RAM (" + sram / 1024 + " KB) at $70-$7D:0000-7FFF", log);
				}
			}
			else {
				for (int k = 0; k * 0x2000L < sram && k < 0x10; k++) {
					long len = Math.min(0x2000, sram - k * 0x2000L);
					ramBlock(program, k == 0 ? sramName : sramName + "_" + hex(0x30 + k, 2),
						a(ram, 0x30 + k, 0x6000), len, false, false, false,
						"cartridge RAM (" + sram / 1024 + " KB) at $30-$3F:6000-7FFF", log);
				}
			}
		}
	}

	// Vector table at $00:FFE0-FFFF: offset, word label, handler label, emulation-mode handler
	private static final Object[][] VECTORS = {
		{ 0x04, "VEC_COP_NATIVE", "COP_native", false },
		{ 0x06, "VEC_BRK_NATIVE", "BRK_native", false },
		{ 0x08, "VEC_ABORT_NATIVE", "ABORT_native", false },
		{ 0x0A, "VEC_NMI_NATIVE", "NMI_native", false },
		{ 0x0E, "VEC_IRQ_NATIVE", "IRQ_native", false },
		{ 0x14, "VEC_COP_EMU", "COP_emu", true },
		{ 0x18, "VEC_ABORT_EMU", "ABORT_emu", true },
		{ 0x1A, "VEC_NMI_EMU", "NMI_emu", true },
		{ 0x1C, "VEC_RESET", "RESET", true },
		{ 0x1E, "VEC_IRQ_BRK_EMU", "IRQ_BRK_emu", true } };

	private void labelVectors(Program program, AddressSpace ram, MessageLog log) {
		Set<Integer> nativeTargets = new HashSet<>();
		Map<Integer, Boolean> emuTargets = new LinkedHashMap<>();
		for (Object[] v : VECTORS) {
			Address va = a(ram, 0, 0xFFE0 + (Integer) v[0]);
			if (!program.getMemory().contains(va)) {
				log.appendMsg("Vector " + v[1] + " at " + va + " is not mapped");
				continue;
			}
			label(program, va, (String) v[1], null, true);
			data(program, va, new Pointer16DataType());
			int target;
			try {
				target = program.getMemory().getShort(va) & 0xFFFF;
			}
			catch (Exception e) {
				continue;
			}
			if (target == 0x0000 || target == 0xFFFF) {
				continue;
			}
			Address ta = a(ram, 0, target);
			MemoryBlock tb = program.getMemory().getBlock(ta);
			if (tb == null) {
				continue;
			}
			String name = (String) v[2];
			boolean code = target >= 0x8000 && (tb.isInitialized() || tb.isMapped());
			if (code) {
				entry(program, ta, name, true);
				if ((Boolean) v[3]) {
					emuTargets.put(target, name.equals("RESET"));
				}
				else {
					nativeTargets.add(target);
				}
			}
			else {
				// e.g. a vector into a WRAM trampoline: label only
				label(program, ta, name, null, false);
			}
		}
		for (Map.Entry<Integer, Boolean> e : emuTargets.entrySet()) {
			int t = e.getKey();
			if (!e.getValue() && nativeTargets.contains(t)) {
				continue; // shared handler: leave the default (native) context
			}
			Address ta = a(ram, 0, t);
			setRegister(program, "emode", ta, ta, 1, log);
			setRegister(program, "mflag", ta, ta, 1, log);
			setRegister(program, "xflag", ta, ta, 1, log);
			if (e.getValue()) {
				// Hardware reset state: DBR = 0, D = 0, PBR = 0, emulation mode.
				setRegister(program, "DBR", ta, ta, 0, log);
				setRegister(program, "D", ta, ta, 0, log);
				setRegister(program, "EF", ta, ta, 1, log);
				setRegister(program, "MF", ta, ta, 1, log);
				setRegister(program, "XF", ta, ta, 1, log);
			}
		}
		Address reset = null;
		for (Map.Entry<Integer, Boolean> e : emuTargets.entrySet()) {
			if (e.getValue()) {
				reset = a(ram, 0, e.getKey());
			}
		}
		if (reset == null) {
			log.appendMsg("RESET vector does not point into ROM");
		}
	}

	private static final String[] COPROC = { "DSP", "SuperFX (GSU)", "OBC1", "SA-1", "S-DD1",
		"S-RTC", "?", "?", "?", "?", "?", "?", "?", "?", "other (Super Game Boy / Satellaview)",
		"custom" };

	private static final String[] REGIONS = { "Japan", "North America", "Europe",
		"Scandinavia", "Finland", "Denmark", "France", "Netherlands", "Spain", "Germany", "Italy",
		"China", "Indonesia", "Korea", "Global", "Canada", "Brazil", "Australia" };

	static String chipset(SnesHeader h) {
		int t = h.romType();
		String base = switch (t & 0x0F) {
			case 0 -> "ROM";
			case 1 -> "ROM+RAM";
			case 2 -> "ROM+RAM+battery";
			case 3 -> "ROM+coprocessor";
			case 4 -> "ROM+coprocessor+RAM";
			case 5 -> "ROM+coprocessor+RAM+battery";
			case 6 -> "ROM+coprocessor+battery";
			default -> "unknown";
		};
		if ((t & 0x0F) >= 3 && (t & 0x0F) <= 6) {
			String c = COPROC[t >> 4];
			if ((t >> 4) == 0xF && h.developer() == 0x33) {
				c = switch (h.ext[0x0F] & 0xFF) {
					case 0x00 -> "SPC7110";
					case 0x01 -> "ST010/ST011";
					case 0x02 -> "ST018";
					case 0x10 -> "CX4";
					default -> "custom";
				};
			}
			base += " (" + c + ")";
		}
		return String.format("0x%02X %s", t, base);
	}

	private void writeInfo(Program program, SnesHeader h, int loromBase) {
		info(program, "SNES Title", h.title());
		info(program, "SNES Mapping", h.mapping.label + (h.mapping == Mapping.LOROM
				? String.format(" (canonical ROM banks at $%02X)", loromBase)
				: ""));
		info(program, "SNES Map Mode", String.format("0x%02X (%s)", h.mapMode(),
			h.isFast() ? "FastROM" : "SlowROM"));
		info(program, "SNES Chipset", chipset(h));
		info(program, "SNES ROM Size", String.format("header 0x%02X (%d KB), file %d KB",
			h.romSizeByte(), (h.romSizeByte() < 16 ? (1 << h.romSizeByte()) : 0), h.romSize / 1024));
		info(program, "SNES SRAM Size", h.sramSize() / 1024 + " KB" +
			(h.expansionRamSize() > 0 ? ", expansion RAM " + h.expansionRamSize() / 1024 + " KB"
					: ""));
		int r = h.region();
		info(program, "SNES Region",
			String.format("0x%02X %s", r, r < REGIONS.length ? REGIONS[r] : "?"));
		info(program, "SNES Version", Integer.toString(h.version()));
		info(program, "SNES Checksum", String.format("stored 0x%04X, complement 0x%04X, " +
			"computed 0x%04X (%s)", h.checksum(), h.complement(), h.computedChecksum,
			h.computedChecksum == h.checksum() ? "match" : "MISMATCH"));
		info(program, "SNES Header", String.format("ROM offset 0x%X, copier header %d bytes, " +
			"detection score %d", h.mapping.headerOffset, h.copierHeader, h.score));
		int cp = h.coprocessor();
		if (cp >= 0) {
			info(program, "SNES Coprocessor", chipset(h) +
				" - mapped as plain " + h.mapping.label + "; coprocessor registers/RAM are not " +
				"modelled");
		}
	}
}
