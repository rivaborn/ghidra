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

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Sony PlayStation (PS1) "PS-X EXE" executables.
 * <p>
 * Header (little-endian, 0x800 bytes): "PS-X EXE" at 0, pc0 0x10, gp0 0x14, t_addr 0x18,
 * t_size 0x1C, d_addr 0x20, d_size 0x24, b_addr 0x28, b_size 0x2C, s_addr 0x30, s_size 0x34,
 * saved sp/fp/gp/ra/s0 0x38-0x4B, region marker text at 0x4C. The text image (file offset
 * 0x800, t_size bytes) is copied to t_addr; b_addr/b_size is zeroed by the loader (BSS).
 */
public class PsxExeLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Sony PlayStation PS-X EXE";

	static final String OPT_KUSEG = "Map KUSEG RAM mirror (0x00000000)";
	static final String OPT_KSEG1 = "Map KSEG1 RAM mirror (0xA0000000)";
	static final String OPT_RAM8 = "8 MB RAM (development unit)";

	private static final byte[] MAGIC = "PS-X EXE".getBytes();
	private static final int TEXT_OFFSET = 0x800;

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

	/** Header fields, or null if the bytes are not a PS-X EXE. */
	static long[] parse(byte[] h, long fileLength) {
		if (h.length < 0x50 || fileLength < TEXT_OFFSET) {
			return null;
		}
		for (int i = 0; i < MAGIC.length; i++) {
			if (h[i] != MAGIC[i]) {
				return null;
			}
		}
		long[] f = new long[14];
		for (int i = 0; i < 14; i++) {
			f[i] = u(le32(h, i * 4));
		}
		long tAddr = f[6], tSize = f[7];
		if (tSize == 0 || !isRam(tAddr) || !isRam(tAddr + tSize - 1)) {
			return null;
		}
		return f;
	}

	static boolean isRam(long a) {
		long seg = a & 0xE0000000L;
		long off = a & 0x1FFFFFFFL;
		return (seg == 0 || seg == 0x80000000L || seg == 0xA0000000L) && off < 0x00800000L;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < TEXT_OFFSET) {
			return specs;
		}
		if (parse(provider.readBytes(0, 0x50), provider.length()) != null) {
			specs.add(new LoadSpec(this, 0, pair("MIPS:LE:32:default", "default"), true));
		}
		return specs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		list.addAll(myOptions());
		return list;
	}

	private static List<Option> myOptions() {
		return List.of(
			new Option(OPT_KSEG1, true, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-kseg1"),
			new Option(OPT_KUSEG, false, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-kuseg"),
			new Option(OPT_RAM8, false, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-ram8"));
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String r = validateTypes(options, myOptions());
		return r != null ? r : super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		byte[] h = provider.readBytes(0, 0x800);
		long[] f = parse(h, provider.length());
		if (f == null) {
			throw new IOException("Not a PS-X EXE");
		}
		long pc0 = f[4], gp0 = f[5], tAddr = f[6], tSize = f[7];
		long dAddr = f[8], dSize = f[9], bAddr = f[10], bSize = f[11];
		long sAddr = f[12], sSize = f[13];
		String marker = ascii(h, 0x4C, 0x800 - 0x4C);

		long avail = provider.length() - TEXT_OFFSET;
		if (tSize > avail) {
			log.appendMsg("t_size " + hex(tSize) + " exceeds the file; loading " + hex(avail) +
				" bytes");
			tSize = avail;
		}

		FileBytes fb = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		long ramSize = optionBool(options, OPT_RAM8, false) ? 0x800000L : 0x200000L;
		long ramBase = tAddr & 0xE0000000L;

		// text image
		fileBlock(program, fb, "text", tAddr, TEXT_OFFSET, tSize, true, true, true,
			"PS-X EXE text image (file 0x800, t_size " + hex(tSize) + ")", log);

		// BSS
		if (bSize > 0 && isRam(bAddr)) {
			fillGaps(program, "bss", bAddr, bSize, true, true, false, "PS-X EXE BSS (b_addr/b_size)",
				log);
		}

		// kernel area (BIOS-owned RAM, first 64 KB) and rest of main RAM
		fillGaps(program, "kernel_ram", ramBase, 0x10000, true, true, true,
			"BIOS kernel RAM (exception vectors, A0/B0/C0 dispatch, kernel data)", log);
		fillGaps(program, "ram", ramBase, ramSize, true, true, true, "Main RAM", log);

		// mirrors
		MemoryBlock ramBlockAnchor = program.getMemory().getBlock(addr(program, ramBase));
		long[] mirrorBases = { 0x00000000L, 0x80000000L, 0xA0000000L };
		for (long mb : mirrorBases) {
			if (mb == ramBase) {
				continue;
			}
			boolean want = (mb == 0) ? optionBool(options, OPT_KUSEG, false)
					: (mb == 0xA0000000L) ? optionBool(options, OPT_KSEG1, true)
							: true;
			if (!want || ramBlockAnchor == null) {
				continue;
			}
			String n = mb == 0 ? "ram_kuseg" : mb == 0x80000000L ? "ram_kseg0" : "ram_kseg1";
			MemoryBlockUtils.createByteMappedBlock(program, n, addr(program, mb),
				addr(program, ramBase), (int) ramSize, "Mirror of main RAM at " + hex(ramBase),
				null, true, true, true, false, log);
		}

		// hardware
		uninitBlock(program, "scratchpad", 0x1F800000L, 0x400, true, true, false, false,
			"Scratchpad (D-cache as RAM, 1 KB)", log);
		ioBlock(program, "io", 0x1F801000L, 0x2000, "I/O ports and expansion region 2", log);
		uninitBlock(program, "expansion1", 0x1F000000L, 0x80000, true, true, false, true,
			"Expansion region 1 (parallel port)", log);
		uninitBlock(program, "bios", 0xBFC00000L, 0x80000, true, false, true, false,
			"BIOS ROM (512 KB, not in the file)", log);
		ioBlock(program, "cache_control", 0xFFFE0000L, 0x200, "Cache control (KSEG2)", log);
		registers(program, PsxRegisters.TABLE, log);
		label(program, 0x1F800000L, "SCRATCHPAD");
		label(program, 0xBFC00000L, "BIOS_RESET");
		label(program, ramBase + 0xA0, "BIOS_A0_dispatch");
		label(program, ramBase + 0xB0, "BIOS_B0_dispatch");
		label(program, ramBase + 0xC0, "BIOS_C0_dispatch");
		label(program, ramBase + 0x80, "exception_vector");

		// symbols
		if (sAddr != 0) {
			label(program, sAddr + sSize, "__stack_top");
		}
		if (bSize > 0) {
			label(program, bAddr, "__bss_start");
			label(program, bAddr + bSize, "__bss_end");
		}
		if (gp0 != 0) {
			label(program, gp0, "_gp");
			setRegister(program, "gp", ramBase, ramBase + ramSize - 1, gp0, log);
			setRegister(program, "gp", 0x1F800000L, 0x1F8003FFL, gp0, log);
		}
		entry(program, pc0, "entry");

		// header
		StructureDataType hs = struct("PSX_EXE_Header", "id", 8, "text_off", u32(), "data_off",
			u32(), "pc0", u32(), "gp0", u32(), "t_addr", u32(), "t_size", u32(), "d_addr", u32(),
			"d_size", u32(), "b_addr", u32(), "b_size", u32(), "s_addr", u32(), "s_size", u32(),
			"saved_sp", u32(), "saved_fp", u32(), "saved_gp", u32(), "saved_ra", u32(),
			"saved_s0", u32(), "marker", 0x800 - 0x4C);
		headerBlock(program, fb, 0, hs, "PSX_EXE_HEADER", log);

		info(program, "PS-X EXE pc0", hex(pc0));
		info(program, "PS-X EXE gp0", hex(gp0));
		info(program, "PS-X EXE text", hex(tAddr) + " size " + hex(tSize));
		info(program, "PS-X EXE data", hex(dAddr) + " size " + hex(dSize));
		info(program, "PS-X EXE bss", hex(bAddr) + " size " + hex(bSize));
		info(program, "PS-X EXE stack", hex(sAddr) + " size " + hex(sSize));
		info(program, "PS-X EXE marker", marker);
		plate(program, pc0, "PS-X EXE entry (pc0). gp0=" + hex(gp0) + "\nRegion marker: " +
			marker);
	}

	@Override
	protected boolean shouldApplyProcessorLabelsByDefault() {
		return true;
	}

	/** Major PS1 hardware registers (from the public PSX hardware documentation). */
	static final class PsxRegisters {
		static final Object[][] TABLE;
		static {
			List<Object[]> t = new ArrayList<>();
			Object[][] fixed = { { 0x1F801000L, "EXP1_BASE", 4 }, { 0x1F801004L, "EXP2_BASE", 4 },
				{ 0x1F801008L, "EXP1_DELAY", 4 }, { 0x1F80100CL, "EXP3_DELAY", 4 },
				{ 0x1F801010L, "BIOS_ROM_DELAY", 4 }, { 0x1F801014L, "SPU_DELAY", 4 },
				{ 0x1F801018L, "CDROM_DELAY", 4 }, { 0x1F80101CL, "EXP2_DELAY", 4 },
				{ 0x1F801020L, "COM_DELAY", 4 }, { 0x1F801040L, "JOY_DATA", 4 },
				{ 0x1F801044L, "JOY_STAT", 4 }, { 0x1F801048L, "JOY_MODE", 2 },
				{ 0x1F80104AL, "JOY_CTRL", 2 }, { 0x1F80104EL, "JOY_BAUD", 2 },
				{ 0x1F801050L, "SIO_DATA", 4 }, { 0x1F801054L, "SIO_STAT", 4 },
				{ 0x1F801058L, "SIO_MODE", 2 }, { 0x1F80105AL, "SIO_CTRL", 2 },
				{ 0x1F80105EL, "SIO_BAUD", 2 }, { 0x1F801060L, "RAM_SIZE", 4 },
				{ 0x1F801070L, "I_STAT", 4 }, { 0x1F801074L, "I_MASK", 4 },
				{ 0x1F8010F0L, "DMA_DPCR", 4 }, { 0x1F8010F4L, "DMA_DICR", 4 },
				{ 0x1F801800L, "CDROM_REG0", 1 }, { 0x1F801801L, "CDROM_REG1", 1 },
				{ 0x1F801802L, "CDROM_REG2", 1 }, { 0x1F801803L, "CDROM_REG3", 1 },
				{ 0x1F801810L, "GPU_GP0", 4 }, { 0x1F801814L, "GPU_GP1", 4 },
				{ 0x1F801820L, "MDEC_DATA", 4 }, { 0x1F801824L, "MDEC_STAT", 4 },
				{ 0x1F801D80L, "SPU_MAIN_VOL_L", 2 }, { 0x1F801D82L, "SPU_MAIN_VOL_R", 2 },
				{ 0x1F801D84L, "SPU_REVERB_VOL_L", 2 }, { 0x1F801D86L, "SPU_REVERB_VOL_R", 2 },
				{ 0x1F801D88L, "SPU_KEY_ON", 4 }, { 0x1F801D8CL, "SPU_KEY_OFF", 4 },
				{ 0x1F801D90L, "SPU_PMON", 4 }, { 0x1F801D94L, "SPU_NOISE_ON", 4 },
				{ 0x1F801D98L, "SPU_REVERB_ON", 4 }, { 0x1F801D9CL, "SPU_ENDX", 4 },
				{ 0x1F801DA2L, "SPU_REVERB_ADDR", 2 }, { 0x1F801DA4L, "SPU_IRQ_ADDR", 2 },
				{ 0x1F801DA6L, "SPU_TRANSFER_ADDR", 2 }, { 0x1F801DA8L, "SPU_TRANSFER_FIFO", 2 },
				{ 0x1F801DAAL, "SPU_CTRL", 2 }, { 0x1F801DACL, "SPU_TRANSFER_CTRL", 2 },
				{ 0x1F801DAEL, "SPU_STAT", 2 }, { 0x1F801DB0L, "SPU_CD_VOL", 4 },
				{ 0x1F801DB4L, "SPU_EXT_VOL", 4 }, { 0x1F801DB8L, "SPU_CUR_MAIN_VOL", 4 },
				{ 0x1F802041L, "EXP2_POST", 1 }, { 0xFFFE0130L, "CACHE_CONTROL", 4 } };
			t.addAll(Arrays.asList(fixed));
			String[] dma = { "MDECIN", "MDECOUT", "GPU", "CDROM", "SPU", "PIO", "OTC" };
			for (int i = 0; i < 7; i++) {
				long b = 0x1F801080L + i * 0x10;
				t.add(new Object[] { b, "DMA" + i + "_" + dma[i] + "_MADR", 4 });
				t.add(new Object[] { b + 4, "DMA" + i + "_" + dma[i] + "_BCR", 4 });
				t.add(new Object[] { b + 8, "DMA" + i + "_" + dma[i] + "_CHCR", 4 });
			}
			for (int i = 0; i < 3; i++) {
				long b = 0x1F801100L + i * 0x10;
				t.add(new Object[] { b, "TIMER" + i + "_COUNT", 4 });
				t.add(new Object[] { b + 4, "TIMER" + i + "_MODE", 4 });
				t.add(new Object[] { b + 8, "TIMER" + i + "_TARGET", 4 });
			}
			for (int v = 0; v < 24; v++) {
				long b = 0x1F801C00L + v * 0x10;
				t.add(new Object[] { b, "SPU_VOICE" + v + "_VOL_L", 2 });
				t.add(new Object[] { b + 2, "SPU_VOICE" + v + "_VOL_R", 2 });
				t.add(new Object[] { b + 4, "SPU_VOICE" + v + "_PITCH", 2 });
				t.add(new Object[] { b + 6, "SPU_VOICE" + v + "_START", 2 });
				t.add(new Object[] { b + 8, "SPU_VOICE" + v + "_ADSR", 4 });
				t.add(new Object[] { b + 0xC, "SPU_VOICE" + v + "_ADSR_VOL", 2 });
				t.add(new Object[] { b + 0xE, "SPU_VOICE" + v + "_REPEAT", 2 });
			}
			TABLE = t.toArray(new Object[0][]);
		}
	}
}
