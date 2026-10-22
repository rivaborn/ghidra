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
import java.util.zip.CRC32;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
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
 * Loader for Nintendo 64 cartridge images in all three byte orders:
 * <ul>
 * <li>.z64: big-endian, starts 80 37 12 40</li>
 * <li>.v64: 16-bit byte-swapped, starts 37 80 40 12</li>
 * <li>.n64: 32-bit little-endian words, starts 40 12 37 80</li>
 * </ul>
 * The image is converted to big-endian. Like the boot code (IPL3) does, the 1 MB following the
 * 4 KB boot area (ROM 0x1000) is copied to the header entry point (adjusted for CIC 6103/6106).
 * The whole cartridge is also mapped at 0xB0000000 (PI domain 1, KSEG1) and the boot area at
 * SP DMEM 0xA4000000 (where the PIF puts it and IPL3 runs).
 */
public class N64Loader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Nintendo 64 ROM";

	static final String OPT_CIC = "CIC (auto, 6101, 6102, 6103, 6105, 6106, 7102)";
	static final String OPT_EXPANSION = "Expansion Pak (8 MB RDRAM)";
	static final String OPT_CODE_SIZE = "Boot copy size";

	public static final int ORDER_Z64 = 0;
	public static final int ORDER_V64 = 1;
	public static final int ORDER_N64 = 2;

	/** CRC32 of the IPL3 bytes 0x040-0xFFF (big-endian image) per CIC chip. */
	private static final Map<Long, String> IPL3_CRC = Map.of(0x6170A4A1L, "6101", 0x90BB6CB5L,
		"6102", 0x0B050EE0L, "6103", 0x98BC2C86L, "6105", 0xACC8580AL, "6106", 0x009E9EA3L,
		"7102");

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

	/** Returns the byte order of the image or -1 if it is not an N64 ROM. */
	public static int byteOrder(byte[] b) {
		if (b.length < 4) {
			return -1;
		}
		int w = be32(b, 0);
		return switch (w) {
			case 0x80371240 -> ORDER_Z64;
			case 0x37804012 -> ORDER_V64;
			case 0x40123780 -> ORDER_N64;
			default -> -1;
		};
	}

	/** Converts an image in the given byte order to big-endian (in place). */
	public static void toBigEndian(byte[] b, int order) {
		if (order == ORDER_V64) {
			for (int i = 0; i + 1 < b.length; i += 2) {
				byte t = b[i];
				b[i] = b[i + 1];
				b[i + 1] = t;
			}
		}
		else if (order == ORDER_N64) {
			for (int i = 0; i + 3 < b.length; i += 4) {
				byte t0 = b[i], t1 = b[i + 1];
				b[i] = b[i + 3];
				b[i + 1] = b[i + 2];
				b[i + 2] = t1;
				b[i + 3] = t0;
			}
		}
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < 0x1000 || provider.length() > 0x10000000L) {
			return specs;
		}
		if (byteOrder(provider.readBytes(0, 4)) >= 0) {
			specs.add(new LoadSpec(this, 0, pair("MIPS:BE:64:64-32addr", "o32"), true));
			specs.add(new LoadSpec(this, 0, pair("MIPS:BE:64:64-32addr", "default"), false));
		}
		return specs;
	}

	private static List<Option> myOptions() {
		return List.of(
			new Option(OPT_CIC, "auto", String.class, Loader.COMMAND_LINE_ARG_PREFIX + "-cic"),
			new Option(OPT_EXPANSION, false, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-expansionPak"),
			new Option(OPT_CODE_SIZE, new ghidra.app.util.HexLong(0x100000),
				ghidra.app.util.HexLong.class, Loader.COMMAND_LINE_ARG_PREFIX + "-bootCopySize"));
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
		String cic = optionString(options, OPT_CIC, "auto").trim();
		if (!cic.equalsIgnoreCase("auto") && !IPL3_CRC.containsValue(cic)) {
			return "Unknown CIC '" + cic + "'";
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	/** Detects the CIC from the IPL3 CRC32, or null if unknown. */
	public static String detectCic(byte[] be) {
		CRC32 crc = new CRC32();
		crc.update(be, 0x40, 0x1000 - 0x40);
		return IPL3_CRC.get(crc.getValue());
	}

	public static long entryAdjust(String cic) {
		if ("6103".equals(cic)) {
			return -0x100000L;
		}
		if ("6106".equals(cic)) {
			return -0x200000L;
		}
		return 0;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		long len = provider.length();
		byte[] rom = provider.readBytes(0, len);
		int order = byteOrder(rom);
		if (order < 0) {
			throw new IOException("Not an N64 ROM");
		}
		toBigEndian(rom, order);
		String orderName = order == ORDER_Z64 ? "z64 (big-endian)"
				: order == ORDER_V64 ? "v64 (16-bit byte-swapped)" : "n64 (32-bit little-endian)";

		long headerEntry = u(be32(rom, 0x08));
		String detected = detectCic(rom);
		String cicOpt = optionString(options, OPT_CIC, "auto").trim();
		String cic = cicOpt.equalsIgnoreCase("auto") ? detected : cicOpt;
		long entry = headerEntry + entryAdjust(cic);
		long copySize = Math.min(optionLong(options, OPT_CODE_SIZE, 0x100000), len - 0x1000);
		long ramSize = optionBool(options, OPT_EXPANSION, false) ? 0x800000L : 0x400000L;
		long ramBase = 0x80000000L;
		if ((entry & 0xE0000000L) != 0x80000000L && (entry & 0xE0000000L) != 0xA0000000L) {
			log.appendMsg("Entry point " + hex(entry) + " is not in KSEG0/KSEG1");
		}

		// game code copied by IPL3
		bytesBlock(program, "code", entry, rom, 0x1000, (int) copySize, false, true, true, true,
			"ROM 0x1000-" + hex(0x1000 + copySize) + " copied by IPL3 to the entry point", log,
			monitor);
		fillGaps(program, "rdram", ramBase, ramSize, true, true, true,
			"RDRAM (" + (ramSize >> 20) + " MB)", log);

		// cartridge
		if (order == ORDER_Z64) {
			FileBytes fb = MemoryBlockUtils.createFileBytes(program, provider, monitor);
			fileBlock(program, fb, "cart_rom", 0xB0000000L, 0, len, true, false, false,
				"Cartridge ROM (PI domain 1, KSEG1 view)", log);
		}
		else {
			bytesBlock(program, "cart_rom", 0xB0000000L, rom, 0, (int) len, false, true, false,
				false, "Cartridge ROM (PI domain 1, KSEG1 view), converted from " + orderName,
				log, monitor);
		}

		// RSP memory: the PIF copies the first 4 KB of the cartridge to DMEM, IPL3 runs there
		bytesBlock(program, "sp_dmem", 0xA4000000L, rom, 0, 0x1000, false, true, true, true,
			"SP DMEM: ROM header + IPL3 boot code as placed by the PIF", log, monitor);
		uninitBlock(program, "sp_imem", 0xA4001000L, 0x1000, true, true, true, false,
			"SP IMEM", log);
		long[][] io = { { 0xA4040000L, 0x20 }, { 0xA4080000L, 0x8 }, { 0xA4100000L, 0x20 },
			{ 0xA4200000L, 0x10 }, { 0xA4300000L, 0x10 }, { 0xA4400000L, 0x38 },
			{ 0xA4500000L, 0x18 }, { 0xA4600000L, 0x34 }, { 0xA4700000L, 0x20 },
			{ 0xA4800000L, 0x1C }, { 0xA3F00000L, 0x28 } };
		String[] ioNames =
			{ "sp_regs", "sp_pc", "dpc_regs", "dps_regs", "mi_regs", "vi_regs", "ai_regs",
				"pi_regs", "ri_regs", "si_regs", "rdram_regs" };
		for (int i = 0; i < io.length; i++) {
			ioBlock(program, ioNames[i], io[i][0], io[i][1], "RCP registers", log);
		}
		uninitBlock(program, "pif_rom", 0xBFC00000L, 0x7C0, true, false, true, false,
			"PIF boot ROM (not in the cartridge)", log);
		ioBlock(program, "pif_ram", 0xBFC007C0L, 0x40, "PIF RAM (joybus)", log);
		registers(program, REGISTERS, log);

		// labels
		label(program, 0xA4000040L, "ipl3");
		function(program, 0xA4000040L, "ipl3");
		label(program, 0x80000000L, "tlb_refill_vector");
		label(program, 0x80000080L, "xtlb_refill_vector");
		label(program, 0x80000100L, "cache_error_vector");
		label(program, 0x80000180L, "general_exception_vector");
		Object[][] boot = { { 0x80000300L, "osTvType", 4 }, { 0x80000304L, "osRomType", 4 },
			{ 0x80000308L, "osRomBase", 4 }, { 0x8000030CL, "osResetType", 4 },
			{ 0x80000310L, "osCicId", 4 }, { 0x80000314L, "osVersion", 4 },
			{ 0x80000318L, "osMemSize", 4 }, { 0x8000031CL, "osAppNMIBuffer", 4 } };
		registers(program, boot, log);
		entry(program, entry, "entry");

		// header
		StructureDataType hs = struct("N64_ROM_Header", "pi_bsd_dom1_config", u32(),
			"clock_rate", u32(), "entry_point", u32(), "release", u32(), "crc1", u32(), "crc2",
			u32(), "reserved1", bytes(8), "title", 20, "reserved2", bytes(7), "media_format", 1,
			"cartridge_id", 2, "country_code", 1, "version", u8());
		createData(program, addr(program, 0xB0000000L), hs, log);
		createData(program, addr(program, 0xA4000000L), hs, log);

		String title = ascii(rom, 0x20, 20);
		String gameId = ascii(rom, 0x3B, 4);
		info(program, "N64 byte order", orderName);
		info(program, "N64 title", title);
		info(program, "N64 game id", gameId + " version " + (rom[0x3F] & 0xFF));
		info(program, "N64 header entry", hex(headerEntry));
		info(program, "N64 entry", hex(entry));
		info(program, "N64 CIC", (cic == null ? "unknown" : cic) +
			(cicOpt.equalsIgnoreCase("auto") ? " (detected from IPL3 CRC32)" : " (option)"));
		info(program, "N64 CRC1/CRC2", hex(u(be32(rom, 0x10))) + " " + hex(u(be32(rom, 0x14))));
		info(program, "N64 clock rate", hex(u(be32(rom, 0x04))));
		info(program, "N64 libultra release", hex(u(be32(rom, 0x0C))));
		plate(program, entry,
			"N64 entry: \"" + title + "\" " + gameId + "\nheader entry " + hex(headerEntry) +
				", CIC " + (cic == null ? "unknown" : cic) + ", boot copy ROM 0x1000+" +
				hex(copySize));
	}

	/** Major RCP / PI / SI / VI / AI registers (KSEG1 addresses). */
	static final Object[][] REGISTERS = { { 0xA4040000L, "SP_MEM_ADDR_REG", 4 },
		{ 0xA4040004L, "SP_DRAM_ADDR_REG", 4 }, { 0xA4040008L, "SP_RD_LEN_REG", 4 },
		{ 0xA404000CL, "SP_WR_LEN_REG", 4 }, { 0xA4040010L, "SP_STATUS_REG", 4 },
		{ 0xA4040014L, "SP_DMA_FULL_REG", 4 }, { 0xA4040018L, "SP_DMA_BUSY_REG", 4 },
		{ 0xA404001CL, "SP_SEMAPHORE_REG", 4 }, { 0xA4080000L, "SP_PC_REG", 4 },
		{ 0xA4080004L, "SP_IBIST_REG", 4 }, { 0xA4100000L, "DPC_START_REG", 4 },
		{ 0xA4100004L, "DPC_END_REG", 4 }, { 0xA4100008L, "DPC_CURRENT_REG", 4 },
		{ 0xA410000CL, "DPC_STATUS_REG", 4 }, { 0xA4100010L, "DPC_CLOCK_REG", 4 },
		{ 0xA4100014L, "DPC_BUFBUSY_REG", 4 }, { 0xA4100018L, "DPC_PIPEBUSY_REG", 4 },
		{ 0xA410001CL, "DPC_TMEM_REG", 4 }, { 0xA4300000L, "MI_MODE_REG", 4 },
		{ 0xA4300004L, "MI_VERSION_REG", 4 }, { 0xA4300008L, "MI_INTR_REG", 4 },
		{ 0xA430000CL, "MI_INTR_MASK_REG", 4 }, { 0xA4400000L, "VI_STATUS_REG", 4 },
		{ 0xA4400004L, "VI_ORIGIN_REG", 4 }, { 0xA4400008L, "VI_WIDTH_REG", 4 },
		{ 0xA440000CL, "VI_INTR_REG", 4 }, { 0xA4400010L, "VI_CURRENT_REG", 4 },
		{ 0xA4400014L, "VI_BURST_REG", 4 }, { 0xA4400018L, "VI_V_SYNC_REG", 4 },
		{ 0xA440001CL, "VI_H_SYNC_REG", 4 }, { 0xA4400020L, "VI_LEAP_REG", 4 },
		{ 0xA4400024L, "VI_H_START_REG", 4 }, { 0xA4400028L, "VI_V_START_REG", 4 },
		{ 0xA440002CL, "VI_V_BURST_REG", 4 }, { 0xA4400030L, "VI_X_SCALE_REG", 4 },
		{ 0xA4400034L, "VI_Y_SCALE_REG", 4 }, { 0xA4500000L, "AI_DRAM_ADDR_REG", 4 },
		{ 0xA4500004L, "AI_LEN_REG", 4 }, { 0xA4500008L, "AI_CONTROL_REG", 4 },
		{ 0xA450000CL, "AI_STATUS_REG", 4 }, { 0xA4500010L, "AI_DACRATE_REG", 4 },
		{ 0xA4500014L, "AI_BITRATE_REG", 4 }, { 0xA4600000L, "PI_DRAM_ADDR_REG", 4 },
		{ 0xA4600004L, "PI_CART_ADDR_REG", 4 }, { 0xA4600008L, "PI_RD_LEN_REG", 4 },
		{ 0xA460000CL, "PI_WR_LEN_REG", 4 }, { 0xA4600010L, "PI_STATUS_REG", 4 },
		{ 0xA4600014L, "PI_BSD_DOM1_LAT_REG", 4 }, { 0xA4600018L, "PI_BSD_DOM1_PWD_REG", 4 },
		{ 0xA460001CL, "PI_BSD_DOM1_PGS_REG", 4 }, { 0xA4600020L, "PI_BSD_DOM1_RLS_REG", 4 },
		{ 0xA4600024L, "PI_BSD_DOM2_LAT_REG", 4 }, { 0xA4600028L, "PI_BSD_DOM2_PWD_REG", 4 },
		{ 0xA460002CL, "PI_BSD_DOM2_PGS_REG", 4 }, { 0xA4600030L, "PI_BSD_DOM2_RLS_REG", 4 },
		{ 0xA4700000L, "RI_MODE_REG", 4 }, { 0xA4700004L, "RI_CONFIG_REG", 4 },
		{ 0xA4700008L, "RI_CURRENT_LOAD_REG", 4 }, { 0xA470000CL, "RI_SELECT_REG", 4 },
		{ 0xA4700010L, "RI_REFRESH_REG", 4 }, { 0xA4700014L, "RI_LATENCY_REG", 4 },
		{ 0xA4700018L, "RI_RERROR_REG", 4 }, { 0xA470001CL, "RI_WERROR_REG", 4 },
		{ 0xA4800000L, "SI_DRAM_ADDR_REG", 4 }, { 0xA4800004L, "SI_PIF_ADDR_RD64B_REG", 4 },
		{ 0xA4800010L, "SI_PIF_ADDR_WR64B_REG", 4 }, { 0xA4800018L, "SI_STATUS_REG", 4 },
		{ 0xBFC007C0L, "PIF_RAM", 4 }, { 0xBFC007FCL, "PIF_RAM_COMMAND", 4 } };
}
