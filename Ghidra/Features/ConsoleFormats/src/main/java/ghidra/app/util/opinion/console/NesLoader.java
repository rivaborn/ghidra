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
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for NES / Famicom cartridge images in the iNES and NES 2.0 formats (.nes).
 * <p>
 * PRG-ROM is mapped into the 2A03's 64 KB space per mapper: fixed banks as ordinary blocks at
 * their CPU addresses, switchable banks as overlay blocks {@code bank_NN} of the switchable
 * window. CHR-ROM is not visible to the CPU (it sits on the PPU bus), so each 8 KB CHR bank is
 * an overlay {@code chr_NN} of the non-loaded OTHER space at offset 0000-1FFF (its PPU pattern
 * table address). RAM (+mirrors), PPU and APU/IO registers, PRG-RAM and the trainer are
 * created; the NMI / RESET / IRQ vectors are labelled and RESET is the entry point.
 */
public class NesLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Nintendo NES ROM (iNES / NES 2.0)";
	public static final String LANGUAGE_ID = "6502:LE:16:default";
	public static final String COMPILER_ID = "default";

	public static final String OPT_LAYOUT = "NES PRG layout";
	public static final String OPT_MMC3_WINDOW = "NES 8 KB bank window";

	/** PRG layouts: how the PRG banks appear in 8000-FFFF. */
	public enum Layout {
		/** 16 or 32 KB, fixed (16 KB mirrored at C000). */
		NROM,
		/** 16 KB switchable at 8000 (overlays), last 16 KB fixed at C000. */
		FIXED16,
		/** 8 KB switchable (overlays at the 8 KB window), last two 8 KB fixed at C000/E000. */
		MMC3,
		/** 8 KB switchable at 8000, last three 8 KB fixed at A000-FFFF. */
		MMC2,
		/** 32 KB switchable at 8000-FFFF (overlays); last bank shown in the base space. */
		SWITCH32
	}

	/** Parsed iNES / NES 2.0 header. */
	public static final class NesHeader {
		public byte[] h;
		public long fileSize;
		public boolean nes2;
		public boolean archaic;
		public int mapper;
		public int submapper;
		public long prgSize;
		public long chrSize;
		public boolean trainer;
		public boolean battery;
		public boolean fourScreen;
		public boolean verticalMirroring;
		public long prgRamSize = -1;   // NES 2.0 only (volatile + NV)
		public long chrRamSize = -1;

		public long prgOffset() {
			return 16 + (trainer ? 512 : 0);
		}

		public long chrOffset() {
			return prgOffset() + prgSize;
		}
	}

	private static long nes2Size(int lsb, int msbNibble, long unit) {
		if (msbNibble == 0xF) {
			int e = lsb >> 2;
			int mm = lsb & 3;
			if (e > 40) {
				return -1;
			}
			return (1L << e) * (mm * 2 + 1);
		}
		return (((long) msbNibble << 8) | lsb) * unit;
	}

	/**
	 * Detection: "NES\x1A" magic at 0, PRG size &gt; 0, the file holds the header, trainer and
	 * the whole PRG-ROM.
	 */
	public static NesHeader detect(ByteProvider provider) throws IOException {
		long len = provider.length();
		if (len < 16 + 0x2000) {
			return null;
		}
		byte[] h = provider.readBytes(0, 16);
		if (h[0] != 'N' || h[1] != 'E' || h[2] != 'S' || h[3] != 0x1A) {
			return null;
		}
		NesHeader n = new NesHeader();
		n.h = h;
		n.fileSize = len;
		int f6 = h[6] & 0xFF;
		int f7 = h[7] & 0xFF;
		n.nes2 = (f7 & 0x0C) == 0x08;
		boolean tailZero = h[12] == 0 && h[13] == 0 && h[14] == 0 && h[15] == 0;
		n.archaic = !n.nes2 && !((f7 & 0x0C) == 0 && tailZero);
		n.verticalMirroring = (f6 & 1) != 0;
		n.battery = (f6 & 2) != 0;
		n.trainer = (f6 & 4) != 0;
		n.fourScreen = (f6 & 8) != 0;
		if (n.nes2) {
			n.mapper = (f6 >> 4) | (f7 & 0xF0) | ((h[8] & 0x0F) << 8);
			n.submapper = (h[8] & 0xFF) >> 4;
			n.prgSize = nes2Size(h[4] & 0xFF, h[9] & 0x0F, 0x4000);
			n.chrSize = nes2Size(h[5] & 0xFF, (h[9] & 0xFF) >> 4, 0x2000);
			int pr = h[10] & 0xFF;
			n.prgRamSize = ((pr & 0xF) == 0 ? 0 : 64L << (pr & 0xF)) +
				((pr >> 4) == 0 ? 0 : 64L << (pr >> 4));
			int cr = h[11] & 0xFF;
			n.chrRamSize = ((cr & 0xF) == 0 ? 0 : 64L << (cr & 0xF)) +
				((cr >> 4) == 0 ? 0 : 64L << (cr >> 4));
		}
		else {
			n.mapper = (f6 >> 4) | (n.archaic ? 0 : (f7 & 0xF0));
			n.prgSize = (h[4] & 0xFF) * 0x4000L;
			n.chrSize = (h[5] & 0xFF) * 0x2000L;
		}
		if (n.prgSize <= 0 || n.chrSize < 0) {
			return null;
		}
		if (n.prgOffset() + n.prgSize > len) {
			return null;
		}
		return n;
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
		if (detect(provider) != null && languageExists(getLanguageService(), LANGUAGE_ID)) {
			specs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(LANGUAGE_ID, COMPILER_ID), true));
		}
		return specs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(new Option(OPT_LAYOUT, "auto", String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-nesLayout"));
		list.add(new Option(OPT_MMC3_WINDOW, "8000", String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-nesBankWindow"));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String err = checkChoice(options, OPT_LAYOUT, "auto", "nrom", "fixed16", "mmc3", "mmc2",
			"switch32");
		if (err == null) {
			err = checkChoice(options, OPT_MMC3_WINDOW, "8000", "a000", "both");
		}
		if (err != null) {
			return err;
		}
		List<Option> rest = new ArrayList<>();
		for (Option o : options) {
			if (!o.getName().startsWith("NES ")) {
				rest.add(o);
			}
		}
		return super.validateOptions(provider, loadSpec, rest, program);
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, ImporterSettings settings) {
		// The loader creates the whole memory map itself (with the pspec block names).
	}

	/** Mapper number to (layout, board name). Unknown mappers return null. */
	public static Layout layoutOf(int mapper) {
		return switch (mapper) {
			case 0, 3 -> Layout.NROM;          // NROM, CNROM (CHR switching only)
			case 1, 2, 10 -> Layout.FIXED16;   // MMC1 (mode 3), UxROM, MMC4
			case 4 -> Layout.MMC3;
			case 9 -> Layout.MMC2;
			case 7, 66 -> Layout.SWITCH32;     // AxROM, GxROM
			default -> null;
		};
	}

	public static String mapperName(int mapper) {
		return switch (mapper) {
			case 0 -> "NROM";
			case 1 -> "MMC1 (SxROM)";
			case 2 -> "UxROM";
			case 3 -> "CNROM";
			case 4 -> "MMC3 (TxROM)";
			case 5 -> "MMC5 (ExROM)";
			case 7 -> "AxROM";
			case 9 -> "MMC2 (PxROM)";
			case 10 -> "MMC4 (FxROM)";
			case 11 -> "Color Dreams";
			case 66 -> "GxROM";
			case 69 -> "Sunsoft FME-7";
			default -> "mapper " + mapper;
		};
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		NesHeader n = detect(provider);
		if (n == null) {
			throw new IOException("Not an iNES / NES 2.0 image");
		}
		String layoutOpt = stringOption(settings.options(), OPT_LAYOUT, "auto").toLowerCase();
		String window = stringOption(settings.options(), OPT_MMC3_WINDOW, "8000").toLowerCase();
		Layout layout = layoutOpt.equals("auto") ? layoutOf(n.mapper)
				: Layout.valueOf(layoutOpt.toUpperCase());
		boolean generic = layout == null;
		if (generic) {
			layout = Layout.FIXED16;
		}
		// Layout constraints on the PRG size
		if (layout == Layout.NROM && n.prgSize > 0x8000) {
			log.appendMsg("NROM layout with more than 32 KB PRG: using 16 KB banks instead");
			layout = Layout.FIXED16;
		}
		if ((layout == Layout.MMC3 && n.prgSize < 0x4000) ||
			(layout == Layout.MMC2 && n.prgSize < 0x8000) ||
			(layout == Layout.SWITCH32 && n.prgSize < 0x8000)) {
			log.appendMsg("PRG too small for the " + layout + " layout: using NROM");
			layout = Layout.NROM;
		}

		FileBytes fb = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
		long prg = n.prgOffset();
		long P = n.prgSize;

		switch (layout) {
			case NROM -> {
				if (P <= 0x4000) {
					romBlock(program, fb, "PRG_ROM", ram.getAddress(0x8000), prg, P, false,
						"16 KB PRG-ROM", log);
					mirrorBlock(program, "PRG_ROM_MIRROR", ram.getAddress(0xC000),
						ram.getAddress(0x8000), P, false, true, false,
						"mirror of the 16 KB PRG-ROM", log);
				}
				else {
					romBlock(program, fb, "PRG_ROM", ram.getAddress(0x8000), prg, P, false,
						"32 KB PRG-ROM", log);
				}
			}
			case FIXED16 -> {
				int nb = (int) (P / 0x4000);
				romBlock(program, fb, "PRG_FIXED", ram.getAddress(0xC000),
					prg + (nb - 1) * 0x4000L, 0x4000, false,
					"last 16 KB PRG bank (" + (nb - 1) + ") fixed at C000", log);
				for (int i = 0; i < nb - 1; i++) {
					monitor.checkCancelled();
					romBlock(program, fb, "bank_" + hex(i, 2), ram.getAddress(0x8000),
						prg + i * 0x4000L, 0x4000, true,
						"switchable 16 KB PRG bank " + i + " at 8000-BFFF", log);
				}
			}
			case MMC3 -> {
				int nb = (int) (P / 0x2000);
				romBlock(program, fb, "PRG_FIXED_C000", ram.getAddress(0xC000),
					prg + (nb - 2) * 0x2000L, 0x2000, false,
					"second-last 8 KB PRG bank (" + (nb - 2) + ") at C000 (PRG mode 0)", log);
				romBlock(program, fb, "PRG_FIXED_E000", ram.getAddress(0xE000),
					prg + (nb - 1) * 0x2000L, 0x2000, false,
					"last 8 KB PRG bank (" + (nb - 1) + ") fixed at E000", log);
				for (int i = 0; i < nb - 2; i++) {
					monitor.checkCancelled();
					if (window.equals("8000") || window.equals("both")) {
						romBlock(program, fb,
							"bank_" + hex(i, 2) + (window.equals("both") ? "_8000" : ""),
							ram.getAddress(0x8000), prg + i * 0x2000L, 0x2000, true,
							"switchable 8 KB PRG bank " + i + " at 8000-9FFF", log);
					}
					if (window.equals("a000") || window.equals("both")) {
						romBlock(program, fb,
							"bank_" + hex(i, 2) + (window.equals("both") ? "_A000" : ""),
							ram.getAddress(0xA000), prg + i * 0x2000L, 0x2000, true,
							"switchable 8 KB PRG bank " + i + " at A000-BFFF", log);
					}
				}
			}
			case MMC2 -> {
				int nb = (int) (P / 0x2000);
				romBlock(program, fb, "PRG_FIXED", ram.getAddress(0xA000),
					prg + (nb - 3) * 0x2000L, 0x6000, false,
					"last three 8 KB PRG banks fixed at A000-FFFF", log);
				for (int i = 0; i < nb - 3; i++) {
					monitor.checkCancelled();
					romBlock(program, fb, "bank_" + hex(i, 2), ram.getAddress(0x8000),
						prg + i * 0x2000L, 0x2000, true,
						"switchable 8 KB PRG bank " + i + " at 8000-9FFF", log);
				}
			}
			case SWITCH32 -> {
				int nb = (int) (P / 0x8000);
				romBlock(program, fb, "PRG_BANK_LAST", ram.getAddress(0x8000),
					prg + (nb - 1) * 0x8000L, 0x8000, false,
					"32 KB PRG bank " + (nb - 1) + " (shown as the default view of 8000-FFFF)",
					log);
				for (int i = 0; i < nb - 1; i++) {
					monitor.checkCancelled();
					romBlock(program, fb, "bank_" + hex(i, 2), ram.getAddress(0x8000),
						prg + i * 0x8000L, 0x8000, true,
						"switchable 32 KB PRG bank " + i + " at 8000-FFFF", log);
				}
			}
		}

		// CHR-ROM: on the PPU bus, not CPU-visible -> OTHER-space overlays at PPU 0000-1FFF.
		if (n.chrSize > 0) {
			long chrAvail = Math.max(0, Math.min(n.chrSize, n.fileSize - n.chrOffset()));
			if (chrAvail < n.chrSize) {
				log.appendMsg("CHR-ROM truncated: " + chrAvail + " of " + n.chrSize + " bytes");
			}
			int cb = (int) ((chrAvail + 0x1FFF) / 0x2000);
			for (int i = 0; i < cb; i++) {
				long off = n.chrOffset() + i * 0x2000L;
				romBlock(program, fb, "chr_" + hex(i, 2), AddressSpace.OTHER_SPACE.getAddress(0),
					off, Math.min(0x2000, chrAvail - i * 0x2000L), true,
					"CHR-ROM 8 KB bank " + i + " (PPU pattern tables 0000-1FFF)", log);
				MemoryBlock b = program.getMemory().getBlock("chr_" + hex(i, 2));
				if (b != null) {
					b.setExecute(false);
				}
			}
		}

		mapRamAndIo(program, ram, n, log);
		labelVectors(program, ram, log);
		writeInfo(program, n, layout, generic);
	}

	private static final String[][] PPU_REGS = { { "2000", "PPUCTRL", "PPU control" },
		{ "2001", "PPUMASK", "PPU mask" }, { "2002", "PPUSTATUS", "PPU status" },
		{ "2003", "OAMADDR", "OAM address" }, { "2004", "OAMDATA", "OAM data" },
		{ "2005", "PPUSCROLL", "scroll (x2 writes)" },
		{ "2006", "PPUADDR", "VRAM address (x2 writes)" }, { "2007", "PPUDATA", "VRAM data" } };

	private static final String[][] APU_REGS = { { "4000", "SQ1_VOL", "pulse 1 duty/volume" },
		{ "4001", "SQ1_SWEEP", "pulse 1 sweep" }, { "4002", "SQ1_LO", "pulse 1 timer low" },
		{ "4003", "SQ1_HI", "pulse 1 length/timer high" },
		{ "4004", "SQ2_VOL", "pulse 2 duty/volume" }, { "4005", "SQ2_SWEEP", "pulse 2 sweep" },
		{ "4006", "SQ2_LO", "pulse 2 timer low" },
		{ "4007", "SQ2_HI", "pulse 2 length/timer high" },
		{ "4008", "TRI_LINEAR", "triangle linear counter" },
		{ "400A", "TRI_LO", "triangle timer low" },
		{ "400B", "TRI_HI", "triangle length/timer high" },
		{ "400C", "NOISE_VOL", "noise volume" }, { "400E", "NOISE_LO", "noise period" },
		{ "400F", "NOISE_HI", "noise length" }, { "4010", "DMC_FREQ", "DMC flags/rate" },
		{ "4011", "DMC_RAW", "DMC direct load" }, { "4012", "DMC_START", "DMC sample address" },
		{ "4013", "DMC_LEN", "DMC sample length" }, { "4014", "OAMDMA", "OAM DMA page" },
		{ "4015", "SND_CHN", "APU status / channel enable" },
		{ "4016", "JOY1", "joypad 1 / strobe" },
		{ "4017", "JOY2", "joypad 2 / APU frame counter" } };

	private void mapRamAndIo(Program program, AddressSpace ram, NesHeader n, MessageLog log) {
		// Block names ZERO_PAGE / STACK match the 6502 pspec.
		ramBlock(program, "ZERO_PAGE", ram.getAddress(0x0000), 0x100, false, true, false,
			"internal RAM: zero page", log);
		ramBlock(program, "STACK", ram.getAddress(0x0100), 0x100, false, true, false,
			"internal RAM: stack page", log);
		ramBlock(program, "RAM", ram.getAddress(0x0200), 0x600, false, true, false,
			"internal RAM 0200-07FF", log);
		for (int m = 1; m < 4; m++) {
			mirrorBlock(program, "RAM_MIRROR_" + m, ram.getAddress(0x800 * m), ram.getAddress(0),
				0x800, true, true, false, "mirror of internal RAM 0000-07FF", log);
		}
		ramBlock(program, "PPU_REGS", ram.getAddress(0x2000), 8, false, false, true,
			"PPU registers", log);
		ramBlock(program, "PPU_MIRRORS", ram.getAddress(0x2008), 0x2000 - 8, false, false, true,
			"PPU registers mirrored every 8 bytes", log);
		ramBlock(program, "APU_IO", ram.getAddress(0x4000), 0x18, false, false, true,
			"APU and I/O registers", log);
		for (String[] r : PPU_REGS) {
			label(program, ram.getAddress(Integer.parseInt(r[0], 16)), r[1], r[2], true);
		}
		for (String[] r : APU_REGS) {
			label(program, ram.getAddress(Integer.parseInt(r[0], 16)), r[1], r[2], true);
		}
		// PRG-RAM at 6000-7FFF (the trainer, if present, is loaded at 7000-71FF)
		String prgRamNote = n.battery ? "battery-backed PRG-RAM" : "PRG-RAM (if fitted)";
		if (n.trainer) {
			ramBlock(program, "PRG_RAM", ram.getAddress(0x6000), 0x1000, false, true, false,
				prgRamNote, log);
			try {
				FileBytes fb = program.getMemory().getAllFileBytes().get(0);
				romBlock(program, fb, "TRAINER", ram.getAddress(0x7000), 16, 512, false,
					"512-byte trainer loaded at 7000-71FF", log);
				MemoryBlock t = program.getMemory().getBlock("TRAINER");
				if (t != null) {
					t.setWrite(true);
				}
			}
			catch (Exception e) {
				log.appendMsg("Cannot map trainer: " + e.getMessage());
			}
			ramBlock(program, "PRG_RAM_7200", ram.getAddress(0x7200), 0xE00, false, true, false,
				prgRamNote, log);
		}
		else {
			ramBlock(program, "PRG_RAM", ram.getAddress(0x6000), 0x2000, false, true, false,
				prgRamNote, log);
		}
	}

	private void labelVectors(Program program, AddressSpace ram, MessageLog log) {
		String[][] vecs = { { "FFFA", "VEC_NMI", "NMI" }, { "FFFC", "VEC_RESET", "RESET" },
			{ "FFFE", "VEC_IRQ", "IRQ" } };
		for (String[] v : vecs) {
			Address va = ram.getAddress(Integer.parseInt(v[0], 16));
			if (!program.getMemory().contains(va)) {
				log.appendMsg("Vector " + v[1] + " not mapped");
				continue;
			}
			label(program, va, v[1], null, true);
			data(program, va, new PointerDataType(null, 2));
			int target;
			try {
				target = program.getMemory().getShort(va) & 0xFFFF;
			}
			catch (Exception e) {
				continue;
			}
			Address ta = ram.getAddress(target);
			MemoryBlock tb = program.getMemory().getBlock(ta);
			if (tb != null && tb.isExecute() && target >= 0x6000) {
				entry(program, ta, v[2], true);
			}
			else {
				label(program, ta, v[2], null, false);
			}
		}
	}

	private void writeInfo(Program program, NesHeader n, Layout layout, boolean generic) {
		info(program, "NES Format", n.nes2 ? "NES 2.0" : n.archaic ? "iNES (archaic)" : "iNES");
		info(program, "NES Mapper", n.mapper + " " + mapperName(n.mapper) +
			(n.nes2 ? " submapper " + n.submapper : ""));
		info(program, "NES PRG Layout", layout.name() + (generic
				? " (generic fallback: mapper " + n.mapper + " is not specifically supported)"
				: ""));
		info(program, "NES PRG-ROM", n.prgSize / 1024 + " KB");
		info(program, "NES CHR-ROM",
			n.chrSize == 0 ? "none (CHR-RAM)" : n.chrSize / 1024 + " KB");
		info(program, "NES Mirroring", n.fourScreen ? "four-screen"
				: n.verticalMirroring ? "vertical" : "horizontal");
		info(program, "NES Battery", Boolean.toString(n.battery));
		info(program, "NES Trainer", Boolean.toString(n.trainer));
		if (n.nes2) {
			info(program, "NES PRG-RAM", n.prgRamSize + " bytes (volatile + non-volatile)");
			info(program, "NES CHR-RAM", n.chrRamSize + " bytes");
		}
	}
}
