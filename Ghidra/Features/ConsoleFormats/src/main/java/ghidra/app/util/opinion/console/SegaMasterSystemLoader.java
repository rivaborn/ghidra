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
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Sega Master System / Game Gear cartridge images ({@code .sms}, {@code .gg}).
 * <p>
 * Detection: ASCII "TMR SEGA" at file offset 0x7FF0, else 0x3FF0, else 0x1FF0 (the first one
 * found is the header). Without that header the file is claimed only when its name ends in
 * {@code .sms} or {@code .gg} and its length is a non-zero multiple of 0x2000 up to 4 MB.
 * Files the Mega Drive loader claims are never claimed. Game Gear = region nibble (high nibble
 * of header byte 0xF) 5, 6 or 7, or a {@code .gg} name.
 * <p>
 * Mapper (option, default auto): Codemasters when the u16 LE at 0x7FE6 plus the u16 LE at
 * 0x7FE8 equals 0x10000 (the Codemasters header checksum and its complement); Korean when the
 * ROM is larger than 48 KB, contains {@code LD (0xA000),A} (32 00 A0) and contains neither
 * {@code LD (0xFFFF),A} (32 FF FF) nor {@code LD (0xFFFE),A} (32 FE FF); otherwise Sega.
 * ROMs of 48 KB or less are mapped linearly without a mapper.
 */
public class SegaMasterSystemLoader extends SegaLoaderBase {

	public static final String NAME = "Sega Master System / Game Gear ROM";
	public static final String LANGUAGE = "z80:LE:16:default";

	/** Program-information value read by {@code SegaMapperBankAnalyzer}. */
	public static final String INFO_MAPPER = "Mapper";

	static final String OPT_MAPPER = "Mapper (auto|sega|codemasters|korean|none)";
	static final String OPT_SYSTEM = "System (auto|sms|gg)";
	static final String OPT_CART_RAM = "Cartridge RAM overlay in slot 2";

	private static final int[] HEADER_OFFSETS = { 0x7FF0, 0x3FF0, 0x1FF0 };
	private static final int BANK = 0x4000;

	@Override
	public String getName() {
		return NAME;
	}

	static int headerOffset(ByteProvider provider) throws IOException {
		for (int h : HEADER_OFFSETS) {
			byte[] b = read(provider, h, 8);
			if (startsWith(b, 0, "TMR SEGA")) {
				return h;
			}
		}
		return -1;
	}

	private static boolean nameHint(ByteProvider provider) {
		String n = provider.getName() == null ? "" : provider.getName().toLowerCase();
		return n.endsWith(".sms") || n.endsWith(".gg");
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		long len = provider.length();
		if (len < 0x2000 || MegaDriveLoader.detect(provider) != 0) {
			return List.of();
		}
		if (headerOffset(provider) >= 0) {
			return spec(this, LANGUAGE, true);
		}
		if (nameHint(provider) && len % 0x2000 == 0 && len <= 0x400000) {
			return spec(this, LANGUAGE, true);
		}
		return List.of();
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(stringOpt(OPT_MAPPER, "auto", "mapper"));
		list.add(stringOpt(OPT_SYSTEM, "auto", "system"));
		list.add(boolOpt(OPT_CART_RAM, true, "cartRam"));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String err = validateOwn(options, Map.of(OPT_MAPPER, String.class, OPT_SYSTEM,
			String.class, OPT_CART_RAM, Boolean.class));
		if (err != null) {
			return err;
		}
		String m = stringOption(options, OPT_MAPPER, "auto").toLowerCase();
		if (!List.of("auto", "sega", "codemasters", "korean", "none").contains(m)) {
			return OPT_MAPPER + ": expected auto, sega, codemasters, korean or none";
		}
		String s = stringOption(options, OPT_SYSTEM, "auto").toLowerCase();
		if (!List.of("auto", "sms", "gg").contains(s)) {
			return OPT_SYSTEM + ": expected auto, sms or gg";
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	/** Mapper heuristics as documented in the class comment. */
	static String detectMapper(byte[] rom) {
		if (rom.length <= 0xC000) {
			return "none";
		}
		if (rom.length >= 0x7FEA && u16le(rom, 0x7FE6) + u16le(rom, 0x7FE8) == 0x10000) {
			return "codemasters";
		}
		boolean a000 = false, fffx = false;
		for (int i = 0; i + 2 < rom.length; i++) {
			if ((rom[i] & 0xff) != 0x32) {
				continue;
			}
			int nn = u16le(rom, i + 1);
			a000 |= nn == 0xA000;
			fffx |= nn == 0xFFFF || nn == 0xFFFE;
		}
		return a000 && !fffx ? "korean" : "sega";
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		byte[] rom = provider.readBytes(0, provider.length());
		FileBytes fb = program.getMemory()
				.createFileBytes(provider.getName(), 0, rom.length, provider.getInputStream(0),
					monitor);
		int h = headerOffset(provider);

		String mapper = stringOption(options, OPT_MAPPER, "auto").toLowerCase();
		if (mapper.equals("auto")) {
			mapper = detectMapper(rom);
		}
		int regionNibble = h >= 0 ? u8(rom, h + 15) >> 4 : -1;
		String sys = stringOption(options, OPT_SYSTEM, "auto").toLowerCase();
		boolean gg = sys.equals("gg") || (sys.equals("auto") &&
			(regionNibble >= 5 && regionNibble <= 7 ||
				(provider.getName() != null && provider.getName().toLowerCase().endsWith(".gg"))));

		int banks = (rom.length + BANK - 1) / BANK;
		if (mapper.equals("none")) {
			romBlock(program, "ROM", 0, fb, 0, Math.min(rom.length, 0xC000), false, false,
				"Cartridge ROM, linear (no mapper)", log);
			if (rom.length > 0xC000) {
				log.appendMsg("No mapper selected: only the first 48 KB of ROM are mapped");
			}
		}
		else {
			romBlock(program, "ROM_SLOT0", 0, fb, 0, Math.min(rom.length, BANK), false, false,
				"Slot 0: bank 0" + (mapper.equals("sega")
						? " (0x0000-0x03FF always bank 0; 0x0400-0x3FFF paged by 0xFFFD)"
						: mapper.equals("codemasters") ? " (paged by writes to 0x0000)"
								: " (fixed)"),
				log);
			for (int slot = 1; slot <= 2; slot++) {
				if (slot < banks) {
					romBlock(program, "ROM_SLOT" + slot, slot * BANK, fb, (long) slot * BANK,
						Math.min(BANK, rom.length - slot * BANK), false, false,
						"Slot " + slot + ": bank " + slot + " (power-on default) - other banks " +
							"are overlays rom_bNN_s" + slot,
						log);
				}
			}
			for (int slot = 1; slot <= 2; slot++) {
				if (mapper.equals("korean") && slot == 1) {
					continue; // Korean mapper: slot 1 is fixed
				}
				for (int b = 0; b < banks; b++) {
					monitor.checkCancelled();
					if (b == slot) {
						continue;
					}
					romBlock(program, overlayName(b, slot), slot * BANK, fb, (long) b * BANK,
						Math.min(BANK, rom.length - (long) b * BANK), true, false,
						String.format("ROM bank %d (file 0x%X) seen in slot %d after writing %d " +
							"to %s", b, b * BANK, slot, b, registerName(mapper, slot)),
						log);
				}
			}
			if (mapper.equals("sega") && boolOption(options, OPT_CART_RAM, true)) {
				uninit(program, "cart_ram", 0x8000, BANK, true, true, false, true,
					"Cartridge RAM in slot 2 (enabled by bit 3 of 0xFFFC, bank by bit 2)", log);
			}
		}

		uninit(program, "RAM", 0xC000, 0x2000, true, true, false, false, "System RAM (8 KB)",
			log);
		mirror(program, "RAM_MIRROR", 0xE000, 0xC000, 0x2000,
			"System RAM mirror (the mapper registers at 0xFFFC-0xFFFF also write RAM)", log);
		if (mapper.equals("sega")) {
			label(program, 0xFFFC, "MAPPER_RAM_CTRL");
			label(program, 0xFFFD, "MAPPER_SLOT0");
			label(program, 0xFFFE, "MAPPER_SLOT1");
			label(program, 0xFFFF, "MAPPER_SLOT2");
		}

		mapPorts(program, gg, log);
		labelVectors(program, rom);
		if (h >= 0) {
			labelHeader(program, rom, h);
		}
		if (mapper.equals("codemasters")) {
			field(program, 0, 0x7FE0, "CM_HDR_BANKS", ByteDataType.dataType, 1);
			field(program, 0, 0x7FE6, "CM_HDR_CHECKSUM", WordDataType.dataType, 2);
			field(program, 0, 0x7FE8, "CM_HDR_CHECKSUM_INV", WordDataType.dataType, 2);
		}

		info(program, "Format", gg ? "Game Gear ROM" : "Master System ROM");
		info(program, INFO_MAPPER, mapper);
		info(program, "Banks (16 KB)", Integer.toString(banks));
		info(program, "Header offset", h >= 0 ? hex(h) : "none");
	}

	public static String overlayName(int bank, int slot) {
		return String.format("rom_b%02X_s%d", bank, slot);
	}

	/** Address written to page {@code slot} for the given mapper, or -1. */
	public static int registerAddress(String mapper, int slot) {
		switch (mapper) {
			case "sega":
				return slot == 0 ? 0xFFFD : slot == 1 ? 0xFFFE : 0xFFFF;
			case "codemasters":
				return slot * BANK;
			case "korean":
				return slot == 2 ? 0xA000 : -1;
			default:
				return -1;
		}
	}

	private static String registerName(String mapper, int slot) {
		return hex(registerAddress(mapper, slot));
	}

	private void mapPorts(Program program, boolean gg, MessageLog log) {
		AddressSpace io = program.getAddressFactory().getAddressSpace("io");
		if (io == null) {
			log.appendMsg("Language has no io space: ports not labelled");
			return;
		}
		try {
			MemoryBlock b = program.getMemory()
					.createUninitializedBlock("IO_PORTS", io.getAddress(0), 0x100, false);
			b.setVolatile(true);
			b.setWrite(true);
			b.setComment("Z80 I/O ports (IN/OUT), 8-bit decode");
		}
		catch (Exception e) {
			log.appendMsg("Failed to create IO_PORTS: " + e.getMessage());
			return;
		}
		String[][] ports = { { "3E", "PORT_MEMORY_CTRL" }, { "3F", "PORT_IO_CTRL" },
			{ "7E", "PORT_VCOUNTER_PSG" }, { "7F", "PORT_HCOUNTER_PSG" },
			{ "BE", "PORT_VDP_DATA" }, { "BF", "PORT_VDP_CTRL" }, { "DC", "PORT_IO_AB" },
			{ "DD", "PORT_IO_BMISC" }, { "C0", "PORT_IO_AB_MIRROR" },
			{ "C1", "PORT_IO_BMISC_MIRROR" }, { "F0", "PORT_FM_ADDR" },
			{ "F1", "PORT_FM_DATA" }, { "F2", "PORT_FM_DETECT" } };
		for (String[] p : ports) {
			label(program, io.getAddress(Long.parseLong(p[0], 16)), p[1]);
		}
		if (gg) {
			String[][] g = { { "00", "GG_START_REGION" }, { "01", "GG_EXT_DATA" },
				{ "02", "GG_EXT_DIR_NMI" }, { "03", "GG_SERIAL_TX" }, { "04", "GG_SERIAL_RX" },
				{ "05", "GG_SERIAL_CTRL" }, { "06", "GG_PSG_STEREO" } };
			for (String[] p : g) {
				label(program, io.getAddress(Long.parseLong(p[0], 16)), p[1]);
			}
		}
	}

	private void labelVectors(Program program, byte[] rom) {
		for (int r = 0; r <= 0x38; r += 8) {
			label(program, r, String.format("RST_%02X", r));
		}
		entry(program, addr(program, 0), "Reset");
		if (rom.length > 0x38) {
			alias(program, addr(program, 0x38), "RST_38");
			entry(program, addr(program, 0x38), "IRQ_Handler");
		}
		if (rom.length > 0x66) {
			entry(program, addr(program, 0x66), "NMI_Handler");
		}
	}

	private void labelHeader(Program program, byte[] rom, int h) {
		stringField(program, h, 0, "HDR_TMR_SEGA", 8);
		field(program, h, 8, "HDR_RESERVED", WordDataType.dataType, 2);
		field(program, h, 10, "HDR_CHECKSUM", WordDataType.dataType, 2);
		field(program, h, 12, "HDR_PRODUCT", new ArrayDataType(ByteDataType.dataType, 3, 1), 3);
		field(program, h, 15, "HDR_REGION_SIZE", ByteDataType.dataType, 1);
		comment(program, addr(program, h), "Sega ROM header (TMR SEGA)");

		int product = bcd(u8(rom, h + 12)) + bcd(u8(rom, h + 13)) * 100 +
			(u8(rom, h + 14) >> 4) * 10000;
		int region = u8(rom, h + 15) >> 4;
		int sizeCode = u8(rom, h + 15) & 0xf;
		String[] regions = { "", "", "", "SMS Japan", "SMS Export", "GG Japan", "GG Export",
			"GG International" };
		int[] sizes = { 0x40000, 0x80000, 0x100000, 0, 0, 0, 0, 0, 0, 0, 0x2000, 0x4000, 0x8000,
			0xC000, 0x10000, 0x20000 };
		int range = Math.min(sizes[sizeCode], rom.length);
		int sum = 0;
		for (int i = 0; i < range; i++) {
			if (i >= h && i < h + 16) {
				continue;
			}
			sum = (sum + u8(rom, i)) & 0xffff;
		}
		int hdr = u16le(rom, h + 10);
		info(program, "Product code", Integer.toString(product));
		info(program, "Version", Integer.toString(u8(rom, h + 14) & 0xf));
		info(program, "Region", region < regions.length && !regions[region].isEmpty()
				? regions[region] : "code " + region);
		info(program, "ROM size code", String.format("0x%X (%s bytes checksummed)", sizeCode,
			sizes[sizeCode] == 0 ? "?" : hex(sizes[sizeCode])));
		info(program, "Checksum (header)", String.format("0x%04X", hdr));
		info(program, "Checksum (computed)", String.format("0x%04X (%s)", sum,
			sum == hdr ? "match" : "MISMATCH"));
	}

	private static int bcd(int v) {
		return (v >> 4) * 10 + (v & 0xf);
	}
}
