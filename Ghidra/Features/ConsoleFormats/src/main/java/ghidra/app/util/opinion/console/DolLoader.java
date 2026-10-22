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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Nintendo GameCube / Wii DOL executables.
 * <p>
 * Header (big-endian, 0x100 bytes): 7 text + 11 data section file offsets at 0x00-0x47, load
 * addresses at 0x48-0x8F, sizes at 0x90-0xD7; BSS address 0xD8, BSS size 0xDC, entry 0xE0;
 * 0xE4-0xFF padding (zero). There is no magic: detection checks the header for consistency.
 */
public class DolLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Nintendo GameCube/Wii DOL";

	static final String OPT_PLATFORM = "Platform (auto, gc, wii)";
	static final String OPT_MIRROR = "Map uncached MEM1 mirror (0xC0000000)";

	public static final int HEADER_SIZE = 0x100;

	/** Parsed DOL header. */
	public record DolHeader(long[] offsets, long[] addresses, long[] sizes, long bssAddress,
			long bssSize, long entry) {
		public boolean isText(int i) {
			return i < 7;
		}

		public String sectionName(int i) {
			return i < 7 ? "text" + i : "data" + (i - 7);
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
		return 60;
	}

	static boolean inRam(long a) {
		return (a >= 0x80000000L && a < 0x81800000L) || (a >= 0x90000000L && a < 0x94000000L);
	}

	/** Parses and validates a DOL header; returns null if the bytes are not a DOL. */
	public static DolHeader parse(byte[] h, long fileLength) {
		if (h.length < HEADER_SIZE || fileLength < HEADER_SIZE) {
			return null;
		}
		for (int i = 0xE4; i < HEADER_SIZE; i++) {
			if (h[i] != 0) {
				return null;
			}
		}
		long[] off = new long[18], adr = new long[18], size = new long[18];
		for (int i = 0; i < 18; i++) {
			off[i] = u(be32(h, i * 4));
			adr[i] = u(be32(h, 0x48 + i * 4));
			size[i] = u(be32(h, 0x90 + i * 4));
		}
		long bssAddr = u(be32(h, 0xD8)), bssSize = u(be32(h, 0xDC)), entry = u(be32(h, 0xE0));
		boolean anyText = false, entryOk = false;
		for (int i = 0; i < 18; i++) {
			if (size[i] == 0) {
				continue;
			}
			if (off[i] < HEADER_SIZE || off[i] + size[i] > fileLength || (off[i] & 3) != 0 ||
				(adr[i] & 3) != 0 || !inRam(adr[i]) || !inRam(adr[i] + size[i] - 1)) {
				return null;
			}
			for (int j = 0; j < i; j++) {
				if (size[j] == 0) {
					continue;
				}
				if (adr[i] < adr[j] + size[j] && adr[j] < adr[i] + size[i]) {
					return null; // overlapping load addresses
				}
				if (off[i] < off[j] + size[j] && off[j] < off[i] + size[i]) {
					return null; // overlapping file ranges
				}
			}
			if (i < 7) {
				anyText = true;
				if (entry >= adr[i] && entry < adr[i] + size[i]) {
					entryOk = true;
				}
			}
		}
		if (!anyText || !entryOk || (entry & 3) != 0) {
			return null;
		}
		if (bssSize != 0 && (!inRam(bssAddr) || !inRam(bssAddr + bssSize - 1))) {
			return null;
		}
		return new DolHeader(off, adr, size, bssAddr, bssSize, entry);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < HEADER_SIZE) {
			return specs;
		}
		if (parse(provider.readBytes(0, HEADER_SIZE), provider.length()) != null) {
			specs.add(new LoadSpec(this, 0, gekkoOrDefault(getLanguageService()), true));
		}
		return specs;
	}

	private static List<Option> myOptions() {
		return List.of(
			new Option(OPT_PLATFORM, "auto", String.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-platform"),
			new Option(OPT_MIRROR, true, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-uncachedMirror"));
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
		String p = optionString(options, OPT_PLATFORM, "auto").trim().toLowerCase();
		if (!p.equals("auto") && !p.equals("gc") && !p.equals("wii")) {
			return "Platform must be auto, gc or wii";
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	/** Wii heuristic: an address in MEM2, or the Wii SDK's first text address 0x80004000. */
	static boolean looksLikeWii(DolHeader d) {
		for (int i = 0; i < 18; i++) {
			if (d.sizes()[i] != 0 && d.addresses()[i] >= 0x90000000L) {
				return true;
			}
		}
		return d.sizes()[0] != 0 && d.addresses()[0] == 0x80004000L;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		DolHeader d = parse(provider.readBytes(0, HEADER_SIZE), provider.length());
		if (d == null) {
			throw new IOException("Not a DOL file");
		}
		String p = optionString(options, OPT_PLATFORM, "auto").trim().toLowerCase();
		boolean wii = p.equals("wii") || (p.equals("auto") && looksLikeWii(d));

		FileBytes fb = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		StringBuilder map = new StringBuilder();
		for (int i = 0; i < 18; i++) {
			if (d.sizes()[i] == 0) {
				continue;
			}
			boolean text = d.isText(i);
			fileBlock(program, fb, d.sectionName(i), d.addresses()[i], d.offsets()[i],
				d.sizes()[i], true, !text, text,
				"DOL " + d.sectionName(i) + " (file " + hex(d.offsets()[i]) + ")", log);
			map.append(d.sectionName(i))
					.append(' ')
					.append(hex(d.addresses()[i]))
					.append('+')
					.append(hex(d.sizes()[i]))
					.append("; ");
		}
		if (d.bssSize() != 0) {
			fillGaps(program, "bss", d.bssAddress(), d.bssSize(), true, true, false,
				"DOL BSS (the header range also covers the small-data sections)", log);
			label(program, d.bssAddress(), "__bss_start");
			label(program, d.bssAddress() + d.bssSize(), "__bss_end");
		}
		mapPlatform(program, wii, optionBool(options, OPT_MIRROR, true), log);

		// small-data bases set by the start-up code
		long[] sda = findSdaBases(program, d, log);
		entry(program, d.entry(), "__start");

		StructureDataType hs = struct("DOL_Header", "text_offsets", dwords(7), "data_offsets",
			dwords(11), "text_addresses", dwords(7), "data_addresses", dwords(11), "text_sizes",
			dwords(7), "data_sizes", dwords(11), "bss_address", u32(), "bss_size", u32(),
			"entry_point", u32(), "padding", bytes(0x1C));
		headerBlock(program, fb, 0, hs, "DOL_HEADER", log);

		info(program, "DOL platform", (wii ? "Wii" : "GameCube") +
			(p.equals("auto") ? " (heuristic)" : " (option)"));
		info(program, "DOL entry", hex(d.entry()));
		info(program, "DOL bss", hex(d.bssAddress()) + " size " + hex(d.bssSize()));
		info(program, "DOL sections", map.toString().trim());
		if (sda[0] != 0 || sda[1] != 0) {
			info(program, "DOL r2/r13 (from start-up code)", hex(sda[0]) + " / " + hex(sda[1]));
		}
		plate(program, d.entry(), "DOL entry point\n" + map.toString().trim());
	}

	/**
	 * Finds the r2 / r13 small-data bases ("lis rN,hi ; ori|addi rN,rN,lo") in the text
	 * sections and sets them as register values over the whole image.
	 * @return {r2, r13} (0 when not found)
	 */
	static long[] findSdaBases(Program program, DolHeader d, MessageLog log) {
		long[] result = new long[2];
		int[] regs = { 2, 13 };
		for (int i = 0; i < 7; i++) {
			if (d.sizes()[i] == 0) {
				continue;
			}
			try {
				byte[] b = new byte[(int) Math.min(d.sizes()[i], 0x400000)];
				program.getMemory().getBytes(addr(program, d.addresses()[i]), b);
				for (int r = 0; r < 2; r++) {
					if (result[r] == 0) {
						result[r] = scanLisOri(b, regs[r]);
					}
				}
			}
			catch (Exception e) {
				// ignore
			}
		}
		if (result[0] != 0) {
			setRegister(program, "r2", 0x80000000L, 0x817FFFFFL, result[0], log);
		}
		if (result[1] != 0) {
			setRegister(program, "r13", 0x80000000L, 0x817FFFFFL, result[1], log);
		}
		return result;
	}

	/** Looks for lis rN,hi followed within 4 instructions by ori/addi rN,rN,lo. */
	static long scanLisOri(byte[] b, int reg) {
		for (int i = 0; i + 4 <= b.length; i += 4) {
			int insn = be32(b, i);
			// addis rD,0,imm : opcode 15, rA = 0
			if ((insn >>> 26) != 15 || ((insn >>> 21) & 31) != reg || ((insn >>> 16) & 31) != 0) {
				continue;
			}
			long hi = (insn & 0xFFFF) << 16;
			for (int k = 1; k <= 4 && i + 4 * k + 4 <= b.length; k++) {
				int n = be32(b, i + 4 * k);
				int op = n >>> 26;
				int rd = (n >>> 21) & 31, ra = (n >>> 16) & 31;
				if (op == 24 && rd == reg && ra == reg) { // ori rA,rS,UIMM (rS=21..25, rA=16..20)
					return (hi | (n & 0xFFFF)) & 0xFFFFFFFFL;
				}
				if (op == 14 && rd == reg && ra == reg) { // addi rD,rA,SIMM
					return (hi + (short) (n & 0xFFFF)) & 0xFFFFFFFFL;
				}
			}
		}
		return 0;
	}

	/** MEM1/MEM2, hardware registers and OS globals of the GameCube / Wii. */
	static void mapPlatform(Program program, boolean wii, boolean mirror, MessageLog log) {
		fillGaps(program, "mem1", 0x80000000L, 0x01800000L, true, true, true,
			"MEM1 (24 MB, cached KSEG0 view)", log);
		if (wii) {
			fillGaps(program, "mem2", 0x90000000L, 0x04000000L, true, true, true,
				"Wii MEM2 (64 MB, cached view)", log);
		}
		if (mirror && program.getMemory().getBlock(addr(program, 0xC0000000L)) == null) {
			MemoryBlockUtils.createByteMappedBlock(program, "mem1_uncached",
				addr(program, 0xC0000000L), addr(program, 0x80000000L), 0x01800000,
				"Uncached view of MEM1", null, true, true, false, false, log);
		}
		ioBlock(program, "hw_regs", 0xCC000000L, 0x10000,
			"Flipper/Hollywood legacy hardware registers (CP, PE, VI, PI, MI, DSP, DI, SI, EXI, AI, GX FIFO)",
			log);
		if (wii) {
			ioBlock(program, "hollywood_regs", 0xCD000000L, 0x10000,
				"Wii Hollywood registers (IPC, GPIO, timers)", log);
			ioBlock(program, "hollywood_regs_priv", 0xCD800000L, 0x10000,
				"Wii Hollywood registers (privileged alias)", log);
		}
		uninitBlock(program, "locked_cache", 0xE0000000L, 0x4000, true, true, false, false,
			"Gekko/Broadway locked L1 data cache (16 KB scratch)", log);
		registers(program, GC_REGISTERS, log);
		if (wii) {
			registers(program, WII_REGISTERS, log);
		}
		registers(program, OS_GLOBALS, log);
		String[][] vectors = { { "0100", "system_reset" }, { "0200", "machine_check" },
			{ "0300", "dsi" }, { "0400", "isi" }, { "0500", "external_interrupt" },
			{ "0600", "alignment" }, { "0700", "program" }, { "0800", "fp_unavailable" },
			{ "0900", "decrementer" }, { "0C00", "system_call" }, { "0D00", "trace" },
			{ "0F00", "performance_monitor" }, { "1300", "breakpoint" },
			{ "1700", "thermal" } };
		for (String[] v : vectors) {
			label(program, 0x80000000L + Long.parseLong(v[0], 16), "exception_" + v[1]);
		}
	}

	static final Object[][] OS_GLOBALS = { { 0x80000000L, "OS_BOOT_DISK_ID", 4 },
		{ 0x80000020L, "OS_BOOT_MAGIC", 4 }, { 0x80000024L, "OS_BOOT_VERSION", 4 },
		{ 0x80000028L, "OS_PHYSICAL_MEM_SIZE", 4 }, { 0x8000002CL, "OS_CONSOLE_TYPE", 4 },
		{ 0x80000030L, "OS_ARENA_LO", 4 }, { 0x80000034L, "OS_ARENA_HI", 4 },
		{ 0x80000038L, "OS_FST_ADDRESS", 4 }, { 0x8000003CL, "OS_FST_MAX_LENGTH", 4 },
		{ 0x800000F8L, "OS_BUS_CLOCK", 4 }, { 0x800000FCL, "OS_CPU_CLOCK", 4 } };

	static final Object[][] GC_REGISTERS;
	static final Object[][] WII_REGISTERS = { { 0xCD000000L, "HW_IPC_PPCMSG", 4 },
		{ 0xCD000004L, "HW_IPC_PPCCTRL", 4 }, { 0xCD000008L, "HW_IPC_ARMMSG", 4 },
		{ 0xCD00000CL, "HW_IPC_ARMCTRL", 4 }, { 0xCD000010L, "HW_TIMER", 4 },
		{ 0xCD000014L, "HW_ALARM", 4 }, { 0xCD000030L, "HW_PPCIRQFLAG", 4 },
		{ 0xCD000034L, "HW_PPCIRQMASK", 4 }, { 0xCD0000C0L, "HW_GPIOB_OUT", 4 },
		{ 0xCD0000C4L, "HW_GPIOB_DIR", 4 }, { 0xCD0000C8L, "HW_GPIOB_IN", 4 } };
	static {
		List<Object[]> t = new ArrayList<>(Arrays.asList(new Object[][] {
			{ 0xCC000000L, "CP_STATUS", 2 }, { 0xCC000002L, "CP_CONTROL", 2 },
			{ 0xCC000004L, "CP_CLEAR", 2 }, { 0xCC001000L, "PE_REGS", 2 },
			{ 0xCC002000L, "VI_VTR", 2 }, { 0xCC002002L, "VI_DCR", 2 },
			{ 0xCC002004L, "VI_HTR0", 4 }, { 0xCC002008L, "VI_HTR1", 4 },
			{ 0xCC00200CL, "VI_VTO", 4 }, { 0xCC002010L, "VI_VTE", 4 },
			{ 0xCC002014L, "VI_BBEI", 4 }, { 0xCC002018L, "VI_BBOI", 4 },
			{ 0xCC00201CL, "VI_TFBL", 4 }, { 0xCC002020L, "VI_TFBR", 4 },
			{ 0xCC002024L, "VI_BFBL", 4 }, { 0xCC002028L, "VI_BFBR", 4 },
			{ 0xCC00202CL, "VI_DPV", 2 }, { 0xCC00202EL, "VI_DPH", 2 },
			{ 0xCC002030L, "VI_DI0", 4 }, { 0xCC003000L, "PI_INTSR", 4 },
			{ 0xCC003004L, "PI_INTMR", 4 }, { 0xCC00300CL, "PI_FIFO_BASE", 4 },
			{ 0xCC003010L, "PI_FIFO_END", 4 }, { 0xCC003014L, "PI_FIFO_WPTR", 4 },
			{ 0xCC003024L, "PI_RESET", 4 }, { 0xCC00302CL, "PI_CONSOLE_TYPE", 4 },
			{ 0xCC004000L, "MI_REGS", 2 }, { 0xCC005000L, "DSP_MAILBOX_IN_H", 2 },
			{ 0xCC005002L, "DSP_MAILBOX_IN_L", 2 }, { 0xCC005004L, "DSP_MAILBOX_OUT_H", 2 },
			{ 0xCC005006L, "DSP_MAILBOX_OUT_L", 2 }, { 0xCC00500AL, "DSP_CSR", 2 },
			{ 0xCC005012L, "AR_SIZE", 2 }, { 0xCC005016L, "AR_MODE", 2 },
			{ 0xCC00501AL, "AR_REFRESH", 2 }, { 0xCC005020L, "AR_DMA_MMADDR", 4 },
			{ 0xCC005024L, "AR_DMA_ARADDR", 4 }, { 0xCC005028L, "AR_DMA_CNT", 4 },
			{ 0xCC005030L, "AUDIO_DMA_START_HI", 2 }, { 0xCC005032L, "AUDIO_DMA_START_LO", 2 },
			{ 0xCC005036L, "AUDIO_DMA_CONTROL_LEN", 2 },
			{ 0xCC00503AL, "AUDIO_DMA_BYTES_LEFT", 2 }, { 0xCC006000L, "DI_SR", 4 },
			{ 0xCC006004L, "DI_CVR", 4 }, { 0xCC006008L, "DI_CMDBUF0", 4 },
			{ 0xCC00600CL, "DI_CMDBUF1", 4 }, { 0xCC006010L, "DI_CMDBUF2", 4 },
			{ 0xCC006014L, "DI_MAR", 4 }, { 0xCC006018L, "DI_LENGTH", 4 },
			{ 0xCC00601CL, "DI_CR", 4 }, { 0xCC006020L, "DI_IMMBUF", 4 },
			{ 0xCC006024L, "DI_CFG", 4 }, { 0xCC006430L, "SI_POLL", 4 },
			{ 0xCC006434L, "SI_COMCSR", 4 }, { 0xCC006438L, "SI_SR", 4 },
			{ 0xCC00643CL, "SI_EXILK", 4 }, { 0xCC006480L, "SI_IO_BUFFER", 4 },
			{ 0xCC006C00L, "AI_CR", 4 }, { 0xCC006C04L, "AI_VR", 4 },
			{ 0xCC006C08L, "AI_SCNT", 4 }, { 0xCC006C0CL, "AI_IT", 4 },
			{ 0xCC008000L, "GX_WGPIPE", 4 } }));
		for (int c = 0; c < 4; c++) {
			long b = 0xCC006400L + c * 0xC;
			t.add(new Object[] { b, "SI_C" + c + "OUTBUF", 4 });
			t.add(new Object[] { b + 4, "SI_C" + c + "INBUFH", 4 });
			t.add(new Object[] { b + 8, "SI_C" + c + "INBUFL", 4 });
		}
		for (int c = 0; c < 3; c++) {
			long b = 0xCC006800L + c * 0x14;
			t.add(new Object[] { b, "EXI" + c + "_CSR", 4 });
			t.add(new Object[] { b + 4, "EXI" + c + "_MAR", 4 });
			t.add(new Object[] { b + 8, "EXI" + c + "_LENGTH", 4 });
			t.add(new Object[] { b + 0xC, "EXI" + c + "_CR", 4 });
			t.add(new Object[] { b + 0x10, "EXI" + c + "_DATA", 4 });
		}
		GC_REGISTERS = t.toArray(new Object[0][]);
	}
}
