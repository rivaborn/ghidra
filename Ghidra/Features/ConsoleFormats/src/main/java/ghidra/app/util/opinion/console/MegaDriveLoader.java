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
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.HexLong;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.mem.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Sega Mega Drive / Genesis cartridge images (plain {@code .bin/.md/.gen} and interleaved
 * {@code .smd}), including the 68000 side of 32X cartridges.
 * <p>
 * Detection (plain): file length &ge; 0x200, ASCII "SEGA" at file offset 0x100 or 0x101, the
 * file does not start with "SEGADISCSYSTEM" (Mega-CD disc), and the reset vector (big-endian
 * u32 at 0x004) is even.
 * <p>
 * Detection (.smd): file length = 0x200 + n * 0x4000 (n &ge; 1); header byte 8 = 0xAA and byte
 * 9 = 0xBB, or header byte 1 = 0x03; and the first 16 KB block, de-interleaved (block offset
 * i &lt; 0x2000 holds ROM byte 2i+1, block offset 0x2000+i holds ROM byte 2i), has "SEGA" at
 * ROM offset 0x100 or 0x101.
 */
public class MegaDriveLoader extends SegaLoaderBase {

	public static final String NAME = "Sega Mega Drive / Genesis ROM";
	public static final String LANGUAGE = "68000:BE:32:default";

	static final String OPT_MAPPER = "Mapper (auto|none|ssf2)";
	static final String OPT_SSF_SLOT = "SSF2 overlay slot (1-7)";
	static final String OPT_SRAM = "Map cartridge SRAM";
	static final String OPT_32X = "32X windows (auto|yes|no)";

	private static final int MB4 = 0x400000;

	private static final String[] VECTORS = new String[64];
	static {
		String[] v = { "InitialSSP", "Reset", "BusError", "AddressError", "IllegalInstruction",
			"ZeroDivide", "CHK", "TRAPV", "PrivilegeViolation", "Trace", "Line1010Emulator",
			"Line1111Emulator" };
		System.arraycopy(v, 0, VECTORS, 0, v.length);
		VECTORS[24] = "SpuriousInterrupt";
		VECTORS[25] = "IRQ1";
		VECTORS[26] = "IRQ2_External";
		VECTORS[27] = "IRQ3";
		VECTORS[28] = "IRQ4_HBlank";
		VECTORS[29] = "IRQ5";
		VECTORS[30] = "IRQ6_VBlank";
		VECTORS[31] = "IRQ7";
		for (int i = 0; i < 16; i++) {
			VECTORS[32 + i] = "TRAP" + i;
		}
	}

	@Override
	public String getName() {
		return NAME;
	}

	// ------------------------------------------------------------------ detection

	/** 0 = not Mega Drive, 1 = plain, 2 = SMD interleaved. */
	static int detect(ByteProvider provider) throws IOException {
		long len = provider.length();
		byte[] h = read(provider, 0, 0x200);
		if (h.length < 0x200) {
			return 0;
		}
		if (isPlainHeader(h)) {
			return 1;
		}
		if (len >= 0x200 + 0x4000 && (len - 0x200) % 0x4000 == 0 &&
			((u8(h, 8) == 0xAA && u8(h, 9) == 0xBB) || u8(h, 1) == 0x03)) {
			byte[] blk = read(provider, 0x200, 0x4000);
			if (isPlainHeader(deinterleaveBlock(blk))) {
				return 2;
			}
		}
		return 0;
	}

	private static boolean isPlainHeader(byte[] h) {
		if (h.length < 0x200 || startsWith(h, 0, "SEGADISCSYSTEM")) {
			return false;
		}
		if (!startsWith(h, 0x100, "SEGA") && !startsWith(h, 0x101, "SEGA")) {
			return false;
		}
		return (u32be(h, 4) & 1) == 0;
	}

	static byte[] deinterleaveBlock(byte[] blk) {
		byte[] out = new byte[0x4000];
		for (int i = 0; i < 0x2000; i++) {
			out[2 * i + 1] = blk[i];
			out[2 * i] = blk[0x2000 + i];
		}
		return out;
	}

	static byte[] deinterleave(byte[] smd) {
		int blocks = (smd.length - 0x200) / 0x4000;
		byte[] out = new byte[blocks * 0x4000];
		byte[] blk = new byte[0x4000];
		for (int b = 0; b < blocks; b++) {
			System.arraycopy(smd, 0x200 + b * 0x4000, blk, 0, 0x4000);
			System.arraycopy(deinterleaveBlock(blk), 0, out, b * 0x4000, 0x4000);
		}
		return out;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (detect(provider) == 0) {
			return List.of();
		}
		return spec(this, LANGUAGE, true);
	}

	// ------------------------------------------------------------------ options

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(stringOpt(OPT_MAPPER, "auto", "mapper"));
		list.add(hexOpt(OPT_SSF_SLOT, 1, "ssfSlot"));
		list.add(boolOpt(OPT_SRAM, true, "mapSram"));
		list.add(stringOpt(OPT_32X, "auto", "map32x"));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String err = validateOwn(options, Map.of(OPT_MAPPER, String.class, OPT_SSF_SLOT,
			HexLong.class, OPT_SRAM, Boolean.class, OPT_32X, String.class));
		if (err != null) {
			return err;
		}
		String m = stringOption(options, OPT_MAPPER, "auto").toLowerCase();
		if (!m.equals("auto") && !m.equals("none") && !m.equals("ssf2")) {
			return OPT_MAPPER + ": expected auto, none or ssf2";
		}
		long slot = hexOption(options, OPT_SSF_SLOT, 1);
		if (slot < 1 || slot > 7) {
			return OPT_SSF_SLOT + ": expected 1..7";
		}
		String x = stringOption(options, OPT_32X, "auto").toLowerCase();
		if (!x.equals("auto") && !x.equals("yes") && !x.equals("no")) {
			return OPT_32X + ": expected auto, yes or no";
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	// ------------------------------------------------------------------ load

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		int kind = detect(provider);
		byte[] rom;
		FileBytes fb;
		if (kind == 2) {
			rom = deinterleave(provider.readBytes(0, provider.length()));
			fb = fileBytes(program, provider.getName() + " (de-interleaved SMD)", rom, monitor);
		}
		else {
			rom = provider.readBytes(0, provider.length());
			fb = program.getMemory()
					.createFileBytes(provider.getName(), 0, rom.length,
						provider.getInputStream(0), monitor);
		}
		int romLen = rom.length;

		String system = ascii(rom, 0x100, 16);
		String mapper = stringOption(options, OPT_MAPPER, "auto").toLowerCase();
		boolean ssf2 = mapper.equals("ssf2") ||
			(mapper.equals("auto") && (romLen > MB4 || system.trim().startsWith("SEGA SSF")));
		String opt32x = stringOption(options, OPT_32X, "auto").toLowerCase();
		boolean is32x = opt32x.equals("yes") || (opt32x.equals("auto") &&
			(system.contains("32X") || (romLen > 0x3C4 && startsWith(rom, 0x3C0, "MARS"))));

		// ---- ROM
		int baseLen = Math.min(romLen, MB4);
		romBlock(program, "ROM", 0, fb, 0, baseLen, false, false,
			"Cartridge ROM, mapped at 0x000000" + (kind == 2 ? " (de-interleaved from SMD)" : ""),
			log);
		if (ssf2 && romLen > MB4) {
			long slot = hexOption(options, OPT_SSF_SLOT, 1);
			long slotBase = slot * 0x80000;
			int banks = (romLen + 0x7FFFF) / 0x80000;
			for (int b = 8; b < banks; b++) {
				monitor.checkCancelled();
				long off = (long) b * 0x80000;
				long len = Math.min(0x80000, romLen - off);
				romBlock(program, String.format("ssf2_bank%02X", b), slotBase, fb, off, len,
					true, false,
					String.format("SSF2 mapper: ROM bank %d (file 0x%X) as seen in slot %d " +
						"(0x%06X) after writing %d to 0x%06X", b, off, slot, slotBase, b,
						0xA130F1 + 2 * slot),
					log);
			}
		}
		else if (romLen > MB4) {
			log.appendMsg("ROM larger than 4 MB without SSF2 mapper: only the first 4 MB mapped");
		}

		// ---- 32X (68000 side)
		if (is32x) {
			map32x(program, fb, rom, log);
		}

		// ---- hardware
		mapHardware(program, log);

		// ---- SRAM
		if (boolOption(options, OPT_SRAM, true) && startsWith(rom, 0x1B0, "RA")) {
			long s = u32be(rom, 0x1B4) & ~1L;
			long e = u32be(rom, 0x1B8) | 1L;
			long len = e - s + 1;
			if (s >= 0x200000 && s < 0x400000 && len > 0 && len <= 0x100000) {
				boolean overlay = s < baseLen;
				uninit(program, "SRAM", s, len, true, false, false, overlay,
					String.format("Cartridge SRAM %s-%s (type 0x%02X%02X%s)", hex(s), hex(e),
						u8(rom, 0x1B2), u8(rom, 0x1B3),
						overlay ? ", overlay: it shares addresses with ROM and is enabled by " +
							"writing 1 to 0xA130F1" : ""),
					log);
			}
			else {
				log.appendMsg("SRAM range in header looks invalid: " + hex(s) + "-" + hex(e));
			}
		}

		// ---- vectors, header, entry
		labelVectors(program, rom);
		labelHeader(program, rom, romLen, kind, ssf2, is32x);
	}

	private void mapHardware(Program program, MessageLog log) {
		io(program, "Z80_AREA", 0xA00000, 0x10000,
			"Z80 address space as seen from the 68000 (Z80 RAM, YM2612, bank register, PSG)",
			log);
		label(program, 0xA00000, "Z80_RAM");
		reg(program, 0xA04000, "YM2612_ADDR0", 1);
		label(program, 0xA04001, "YM2612_DATA0");
		label(program, 0xA04002, "YM2612_ADDR1");
		label(program, 0xA04003, "YM2612_DATA1");
		reg(program, 0xA06000, "Z80_BANK_REG", 1);
		label(program, 0xA07F11, "Z80_PSG");
		label(program, 0xA08000, "Z80_68K_WINDOW");

		io(program, "IO", 0xA10000, 0x20, "Version register and controller / serial ports",
			log);
		String[] ioNames = { "IO_VERSION", "IO_DATA1", "IO_DATA2", "IO_DATA3", "IO_CTRL1",
			"IO_CTRL2", "IO_CTRL3", "IO_TXDATA1", "IO_RXDATA1", "IO_SCTRL1", "IO_TXDATA2",
			"IO_RXDATA2", "IO_SCTRL2", "IO_TXDATA3", "IO_RXDATA3", "IO_SCTRL3" };
		for (int i = 0; i < ioNames.length; i++) {
			reg(program, 0xA10001 + 2 * i, ioNames[i], 1);
		}

		io(program, "SYS_CTRL", 0xA11000, 0x300, "Memory mode, Z80 bus request and reset", log);
		reg(program, 0xA11000, "MEMORY_MODE", 2);
		reg(program, 0xA11100, "Z80_BUSREQ", 2);
		reg(program, 0xA11200, "Z80_RESET", 2);

		io(program, "CART_CTRL", 0xA13000, 0x100,
			"/TIME area: cartridge registers (SRAM enable, SSF2 bank registers)", log);
		label(program, 0xA130F1, "SRAM_CTRL");
		for (int s = 1; s <= 7; s++) {
			label(program, 0xA130F1 + 2 * s, "SSF2_BANK_SLOT" + s);
		}

		io(program, "TMSS", 0xA14000, 0x200, "TMSS lock register and cartridge/BIOS switch",
			log);
		reg(program, 0xA14000, "TMSS_SEGA", 4);
		label(program, 0xA14101, "TMSS_CART_SWITCH");

		io(program, "VDP", 0xC00000, 0x20, "VDP ports (and PSG)", log);
		reg(program, 0xC00000, "VDP_DATA", 2);
		reg(program, 0xC00002, "VDP_DATA_MIRROR", 2);
		reg(program, 0xC00004, "VDP_CTRL", 2);
		reg(program, 0xC00006, "VDP_CTRL_MIRROR", 2);
		reg(program, 0xC00008, "VDP_HV_COUNTER", 2);
		label(program, 0xC00011, "PSG");
		reg(program, 0xC0001C, "VDP_DEBUG", 2);

		uninit(program, "RAM", 0xFF0000, 0x10000, true, true, false, false,
			"68000 work RAM (64 KB)", log);
		mirror(program, "RAM_SHORT", 0xFFFF0000L, 0xFF0000, 0x10000,
			"RAM again at 0xFFFF0000: absolute-short addressing ($xxxx.w) sign-extends to " +
				"these 32-bit addresses, the 24-bit bus folds them onto 0xFF0000",
			log);
	}

	private void map32x(Program program, FileBytes fb, byte[] rom, MessageLog log) {
		int romLen = rom.length;
		mirror(program, "MARS_ROM_FIXED", 0x880000, 0, Math.min(romLen, 0x80000), false, true,
			"32X mode: first 512 KB of ROM (fixed) at 0x880000", log);
		mirror(program, "MARS_ROM_BANK", 0x900000, 0, Math.min(romLen, 0x100000), false, true,
			"32X mode: 1 MB ROM window, bank 0 shown (bank register 0xA15104)", log);
		for (int b = 1; b < 4 && (long) b * 0x100000 < romLen; b++) {
			long off = (long) b * 0x100000;
			romBlock(program, "mars_bank" + b, 0x900000, fb, off,
				Math.min(0x100000, romLen - off), true, false,
				"32X mode: ROM bank " + b + " in the 0x900000 window (0xA15104 = " + b + ")",
				log);
		}
		io(program, "MARS_FRAMEBUFFER", 0x840000, 0x40000, "32X frame buffer and overwrite image",
			log);
		io(program, "MARS_SYS", 0xA15100, 0x200, "32X system, communication, PWM, VDP and " +
			"palette registers (68000 side)", log);
		String[][] regs = { { "A15100", "MARS_ADAPTER_CTRL" }, { "A15102", "MARS_INT_CTRL" },
			{ "A15104", "MARS_BANK_SET" }, { "A15106", "MARS_DREQ_CTRL" },
			{ "A15108", "MARS_DREQ_SRC_H" }, { "A1510A", "MARS_DREQ_SRC_L" },
			{ "A1510C", "MARS_DREQ_DST_H" }, { "A1510E", "MARS_DREQ_DST_L" },
			{ "A15110", "MARS_DREQ_LEN" }, { "A15112", "MARS_FIFO" },
			{ "A1511A", "MARS_SEGA_TV" }, { "A15120", "MARS_COMM0" },
			{ "A15130", "MARS_PWM_CTRL" }, { "A15180", "MARS_VDP_MODE" },
			{ "A1518A", "MARS_FB_CTRL" }, { "A15200", "MARS_PALETTE" } };
		for (String[] r : regs) {
			label(program, Long.parseLong(r[0], 16), r[1]);
		}
		if (romLen >= 0x3F0 && startsWith(rom, 0x3C0, "MARS")) {
			label(program, 0x3C0, "MARS_HEADER");
			data(program, addr(program, 0x3C0), new StringDataType(), 16);
			info(program, "32X module", ascii(rom, 0x3C0, 16));
			info(program, "32X SH-2 source (ROM offset)", hex(u32be(rom, 0x3D4)));
			info(program, "32X SH-2 destination (SDRAM offset)", hex(u32be(rom, 0x3D8)));
			info(program, "32X SH-2 size", hex(u32be(rom, 0x3DC)));
			info(program, "32X master SH-2 entry", hex(u32be(rom, 0x3E0)));
			info(program, "32X slave SH-2 entry", hex(u32be(rom, 0x3E4)));
			info(program, "32X master VBR", hex(u32be(rom, 0x3E8)));
			info(program, "32X slave VBR", hex(u32be(rom, 0x3EC)));
			for (int i = 0; i < 8; i++) {
				data(program, addr(program, 0x3D0 + 4 * i), new DWordDataType(), 4);
			}
		}
	}

	private void labelVectors(Program program, byte[] rom) {
		Memory mem = program.getMemory();
		Map<Long, String> firstName = new HashMap<>();
		for (int i = 0; i < 64; i++) {
			Address va = addr(program, 4 * i);
			data(program, va, PointerDataType.dataType, 4);
			String name = VECTORS[i];
			label(program, va, "VEC_" + (name == null ? String.format("Reserved%02d", i) : name));
			if (name == null || i == 0) {
				continue;
			}
			long target = u32be(rom, 4 * i) & 0xFFFFFFL;
			if ((target & 1) != 0) {
				continue;
			}
			Address ta = addr(program, target);
			MemoryBlock b = mem.getBlock(ta);
			if (b == null) {
				continue;
			}
			if (i == 1) {
				entry(program, ta, "Reset");
				firstName.put(target, "Reset");
				continue;
			}
			String handler = name + "_Handler";
			if (firstName.containsKey(target)) {
				alias(program, ta, handler); // the first vector's name stays primary
			}
			else {
				label(program, ta, handler);
				firstName.put(target, handler);
			}
			if (b.isInitialized() && b.isExecute()) {
				program.getSymbolTable().addExternalEntryPoint(ta);
				markAsFunction(program, null, ta);
			}
		}
	}

	private void labelHeader(Program program, byte[] rom, int romLen, int kind, boolean ssf2,
			boolean is32x) {
		stringField(program, 0, 0x100, "HDR_SYSTEM", 16);
		stringField(program, 0, 0x110, "HDR_COPYRIGHT", 16);
		stringField(program, 0, 0x120, "HDR_TITLE_DOMESTIC", 48);
		stringField(program, 0, 0x150, "HDR_TITLE_OVERSEAS", 48);
		stringField(program, 0, 0x180, "HDR_SERIAL", 14);
		field(program, 0, 0x18E, "HDR_CHECKSUM", WordDataType.dataType, 2);
		stringField(program, 0, 0x190, "HDR_IO_SUPPORT", 16);
		field(program, 0, 0x1A0, "HDR_ROM_START", DWordDataType.dataType, 4);
		field(program, 0, 0x1A4, "HDR_ROM_END", DWordDataType.dataType, 4);
		field(program, 0, 0x1A8, "HDR_RAM_START", DWordDataType.dataType, 4);
		field(program, 0, 0x1AC, "HDR_RAM_END", DWordDataType.dataType, 4);
		field(program, 0, 0x1B0, "HDR_SRAM_INFO", DWordDataType.dataType, 4);
		field(program, 0, 0x1B4, "HDR_SRAM_START", DWordDataType.dataType, 4);
		field(program, 0, 0x1B8, "HDR_SRAM_END", DWordDataType.dataType, 4);
		stringField(program, 0, 0x1BC, "HDR_MODEM", 12);
		stringField(program, 0, 0x1C8, "HDR_NOTES", 40);
		stringField(program, 0, 0x1F0, "HDR_REGION", 16);
		comment(program, addr(program, 0x100), "Mega Drive cartridge header (0x100-0x1FF)");

		int sum = 0;
		for (int i = 0x200; i + 1 < romLen; i += 2) {
			sum = (sum + u16be(rom, i)) & 0xffff;
		}
		int hdrSum = u16be(rom, 0x18E);
		info(program, "Format", kind == 2 ? "Mega Drive SMD (interleaved)" : "Mega Drive ROM");
		info(program, "System", ascii(rom, 0x100, 16));
		info(program, "Copyright", ascii(rom, 0x110, 16));
		info(program, "Title (domestic)", ascii(rom, 0x120, 48));
		info(program, "Title (overseas)", ascii(rom, 0x150, 48));
		info(program, "Serial", ascii(rom, 0x180, 14));
		info(program, "Checksum (header)", String.format("0x%04X", hdrSum));
		info(program, "Checksum (computed)",
			String.format("0x%04X (%s)", sum, sum == hdrSum ? "match" : "MISMATCH"));
		info(program, "I/O support", ascii(rom, 0x190, 16));
		info(program, "ROM range", hex(u32be(rom, 0x1A0)) + "-" + hex(u32be(rom, 0x1A4)));
		info(program, "RAM range", hex(u32be(rom, 0x1A8)) + "-" + hex(u32be(rom, 0x1AC)));
		info(program, "SRAM", startsWith(rom, 0x1B0, "RA")
				? String.format("type %02X%02X %s-%s", u8(rom, 0x1B2), u8(rom, 0x1B3),
					hex(u32be(rom, 0x1B4)), hex(u32be(rom, 0x1B8)))
				: "none");
		info(program, "Region", ascii(rom, 0x1F0, 16));
		info(program, "Mapper", ssf2 ? "SSF2" : "none");
		info(program, "32X", is32x ? "yes" : "no");
		info(program, "Initial SSP", hex(u32be(rom, 0)));
		info(program, "Reset vector", hex(u32be(rom, 4)));
	}
}
