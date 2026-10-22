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

import ghidra.app.util.*;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Game Boy Advance cartridge images (.gba) and multiboot images.
 * <p>
 * Header: ARM branch to the entry at 0x00 (condition AL, opcode byte 0xEA at offset 3), logo
 * 0x04-0x9F, title 0xA0 (12), game code 0xAC (4), maker 0xB0 (2), fixed 0x96 at 0xB2, unit
 * 0xB3, device 0xB4, version 0xBC, complement check 0xBD = -(sum of 0xA0..0xBC) - 0x19.
 * The ROM is mapped at 0x08000000 (wait-state mirrors 0x0A000000 / 0x0C000000 byte-mapped).
 */
public class GbaLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Nintendo Game Boy Advance ROM";

	static final String OPT_BASE = "Load address (0x08000000 cartridge, 0x02000000 multiboot)";
	static final String OPT_MIRRORS = "Map ROM wait-state mirrors";

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
		return 50;
	}

	public static int complement(byte[] h) {
		int sum = 0;
		for (int i = 0xA0; i <= 0xBC; i++) {
			sum += h[i] & 0xFF;
		}
		return (-(sum + 0x19)) & 0xFF;
	}

	/** Detection: fixed byte 0x96 at 0xB2, valid complement at 0xBD, ARM "B" at 0. */
	public static boolean isGba(byte[] h, long fileLength) {
		if (h.length < 0xC0 || fileLength < 0xC0 || fileLength > 0x02000000L) {
			return false;
		}
		return (h[0xB2] & 0xFF) == 0x96 && (h[0xBD] & 0xFF) == complement(h) &&
			(h[3] & 0xFF) == 0xEA;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() >= 0xC0 && isGba(provider.readBytes(0, 0xC0), provider.length())) {
			specs.add(new LoadSpec(this, 0, pair("ARM:LE:32:v4t", "default"), true));
		}
		return specs;
	}

	private static List<Option> myOptions() {
		return List.of(
			new Option(OPT_BASE, new HexLong(0x08000000L), HexLong.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr"),
			new Option(OPT_MIRRORS, true, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-mirrors"));
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
		if (r != null) {
			return r;
		}
		long b = optionLong(options, OPT_BASE, 0x08000000L);
		if (b != 0x08000000L && b != 0x02000000L) {
			return "Load address must be 0x08000000 or 0x02000000";
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		byte[] h = provider.readBytes(0, 0xC0);
		long len = provider.length();
		long base = optionLong(options, OPT_BASE, 0x08000000L);
		boolean multiboot = base == 0x02000000L;
		FileBytes fb = MemoryBlockUtils.createFileBytes(program, provider, monitor);

		if (multiboot) {
			fileBlock(program, fb, "multiboot", base, 0, Math.min(len, 0x40000), true, true,
				true, "Multiboot image in EWRAM", log);
		}
		else {
			fileBlock(program, fb, "rom", base, 0, len, true, false, true,
				"Cartridge ROM (wait state 0)", log);
			if (optionBool(options, OPT_MIRRORS, true)) {
				MemoryBlockUtils.createByteMappedBlock(program, "rom_ws1",
					addr(program, 0x0A000000L), addr(program, base), (int) len,
					"ROM mirror (wait state 1)", null, true, false, true, false, log);
				MemoryBlockUtils.createByteMappedBlock(program, "rom_ws2",
					addr(program, 0x0C000000L), addr(program, base), (int) len,
					"ROM mirror (wait state 2)", null, true, false, true, false, log);
			}
		}
		uninitBlock(program, "bios", 0x00000000L, 0x4000, true, false, true, false,
			"BIOS (16 KB, not in the ROM)", log);
		fillGaps(program, "ewram", 0x02000000L, 0x40000, true, true, true,
			"EWRAM (256 KB, on-board)", log);
		fillGaps(program, "iwram", 0x03000000L, 0x8000, true, true, true,
			"IWRAM (32 KB, on-chip)", log);
		ioBlock(program, "io", 0x04000000L, 0x400, "I/O registers", log);
		uninitBlock(program, "palette", 0x05000000L, 0x400, true, true, false, false,
			"Palette RAM", log);
		uninitBlock(program, "vram", 0x06000000L, 0x18000, true, true, false, false, "VRAM", log);
		uninitBlock(program, "oam", 0x07000000L, 0x400, true, true, false, false, "OAM", log);
		uninitBlock(program, "sram", 0x0E000000L, 0x10000, true, true, false, true,
			"Cartridge SRAM / flash", log);
		registers(program, lcdRegisters(), log);
		registers(program, GBA_REGISTERS, log);
		Object[][] bios = { { 0x03007FFCL, "BIOS_IRQ_HANDLER", 4 },
			{ 0x03007FF8L, "BIOS_IRQ_CHECK", 2 }, { 0x03007FF0L, "BIOS_SOUND_INFO", 4 } };
		registers(program, bios, log);

		// entry: the ARM branch at offset 0 (ARM state)
		int b = le32(h, 0);
		long target = base + 8 + ((long) ((b << 8) >> 8) << 2);
		setRegister(program, "TMode", base, base + 3, 0, log);
		setRegister(program, "TMode", target, target + 3, 0, log);
		label(program, base, "rom_header_branch");
		program.getSymbolTable().addExternalEntryPoint(addr(program, base));
		entry(program, target, "start");

		StructureDataType hs = struct("GBA_Header", "entry_branch", u32(), "logo", bytes(0x9C),
			"title", 12, "game_code", 4, "maker_code", 2, "fixed_96", u8(), "unit_code", u8(),
			"device_type", u8(), "reserved1", bytes(7), "version", u8(), "complement", u8(),
			"reserved2", bytes(2));
		createData(program, addr(program, base + 4), hs.getComponent(1).getDataType(), log);
		headerBlock(program, fb, 0, hs, "GBA_HEADER", log);
		createData(program, addr(program, base + 0xA0),
			struct("GBA_HeaderInfo", "title", 12, "game_code", 4, "maker_code", 2, "fixed_96",
				u8(), "unit_code", u8(), "device_type", u8(), "reserved1", bytes(7), "version",
				u8(), "complement", u8(), "reserved2", bytes(2)),
			log);

		info(program, "GBA title", ascii(h, 0xA0, 12));
		info(program, "GBA game code", ascii(h, 0xAC, 4) + " maker " + ascii(h, 0xB0, 2) +
			" version " + (h[0xBC] & 0xFF));
		info(program, "GBA entry", hex(target) + " (ARM)");
		info(program, "GBA load", multiboot ? "multiboot at 0x02000000" : "cartridge at 0x08000000");
		plate(program, target, "GBA entry (ARM state): " + ascii(h, 0xA0, 12) + " " +
			ascii(h, 0xAC, 4));
	}

	/** LCD, sound, DMA, timer, key and interrupt registers shared by the GBA and NDS. */
	static Object[][] lcdRegisters() {
		List<Object[]> t = new ArrayList<>(Arrays.asList(new Object[][] {
			{ 0x04000000L, "REG_DISPCNT", 4 }, { 0x04000004L, "REG_DISPSTAT", 2 },
			{ 0x04000006L, "REG_VCOUNT", 2 }, { 0x04000040L, "REG_WIN0H", 2 },
			{ 0x04000042L, "REG_WIN1H", 2 }, { 0x04000044L, "REG_WIN0V", 2 },
			{ 0x04000046L, "REG_WIN1V", 2 }, { 0x04000048L, "REG_WININ", 2 },
			{ 0x0400004AL, "REG_WINOUT", 2 }, { 0x0400004CL, "REG_MOSAIC", 2 },
			{ 0x04000050L, "REG_BLDCNT", 2 }, { 0x04000052L, "REG_BLDALPHA", 2 },
			{ 0x04000054L, "REG_BLDY", 2 }, { 0x04000130L, "REG_KEYINPUT", 2 },
			{ 0x04000132L, "REG_KEYCNT", 2 }, { 0x04000208L, "REG_IME", 2 } }));
		for (int i = 0; i < 4; i++) {
			t.add(new Object[] { 0x04000008L + 2 * i, "REG_BG" + i + "CNT", 2 });
			t.add(new Object[] { 0x04000010L + 4 * i, "REG_BG" + i + "HOFS", 2 });
			t.add(new Object[] { 0x04000012L + 4 * i, "REG_BG" + i + "VOFS", 2 });
			long d = 0x040000B0L + 12 * i;
			t.add(new Object[] { d, "REG_DMA" + i + "SAD", 4 });
			t.add(new Object[] { d + 4, "REG_DMA" + i + "DAD", 4 });
			t.add(new Object[] { d + 8, "REG_DMA" + i + "CNT_L", 2 });
			t.add(new Object[] { d + 10, "REG_DMA" + i + "CNT_H", 2 });
			t.add(new Object[] { 0x04000100L + 4 * i, "REG_TM" + i + "CNT_L", 2 });
			t.add(new Object[] { 0x04000102L + 4 * i, "REG_TM" + i + "CNT_H", 2 });
		}
		for (int bg = 2; bg <= 3; bg++) {
			long b = 0x04000020L + (bg - 2) * 0x10;
			t.add(new Object[] { b, "REG_BG" + bg + "PA", 2 });
			t.add(new Object[] { b + 2, "REG_BG" + bg + "PB", 2 });
			t.add(new Object[] { b + 4, "REG_BG" + bg + "PC", 2 });
			t.add(new Object[] { b + 6, "REG_BG" + bg + "PD", 2 });
			t.add(new Object[] { b + 8, "REG_BG" + bg + "X", 4 });
			t.add(new Object[] { b + 12, "REG_BG" + bg + "Y", 4 });
		}
		return t.toArray(new Object[0][]);
	}

	static final Object[][] GBA_REGISTERS = { { 0x04000060L, "REG_SOUND1CNT_L", 2 },
		{ 0x04000062L, "REG_SOUND1CNT_H", 2 }, { 0x04000064L, "REG_SOUND1CNT_X", 2 },
		{ 0x04000068L, "REG_SOUND2CNT_L", 2 }, { 0x0400006CL, "REG_SOUND2CNT_H", 2 },
		{ 0x04000070L, "REG_SOUND3CNT_L", 2 }, { 0x04000072L, "REG_SOUND3CNT_H", 2 },
		{ 0x04000074L, "REG_SOUND3CNT_X", 2 }, { 0x04000078L, "REG_SOUND4CNT_L", 2 },
		{ 0x0400007CL, "REG_SOUND4CNT_H", 2 }, { 0x04000080L, "REG_SOUNDCNT_L", 2 },
		{ 0x04000082L, "REG_SOUNDCNT_H", 2 }, { 0x04000084L, "REG_SOUNDCNT_X", 2 },
		{ 0x04000088L, "REG_SOUNDBIAS", 2 }, { 0x04000090L, "REG_WAVE_RAM", 4 },
		{ 0x040000A0L, "REG_FIFO_A", 4 }, { 0x040000A4L, "REG_FIFO_B", 4 },
		{ 0x04000120L, "REG_SIODATA32", 4 }, { 0x04000128L, "REG_SIOCNT", 2 },
		{ 0x0400012AL, "REG_SIODATA8", 2 }, { 0x04000134L, "REG_RCNT", 2 },
		{ 0x04000200L, "REG_IE", 2 }, { 0x04000202L, "REG_IF", 2 },
		{ 0x04000204L, "REG_WAITCNT", 2 }, { 0x04000300L, "REG_POSTFLG", 1 },
		{ 0x04000301L, "REG_HALTCNT", 1 } };
}
