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
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

/**
 * Commodore 64 program file (.prg): a little-endian load address followed by the bytes loaded
 * there. The format has no magic, so this loader only claims files named *.prg with a plausible
 * load address, and sits in the ambiguous tier (it beats only the raw binary loader).
 */
public class C64PrgLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Commodore 64 PRG";
	static final String KERNAL = "C64_KERNAL";
	static final LanguageCompilerSpecPair LANG = new LanguageCompilerSpecPair("6502:LE:16:default",
		"default");

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.AMBIGUOUS_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 100;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (!"prg".equals(extension(provider)) || provider.length() < 3 ||
			provider.length() > 0x10001) {
			return specs;
		}
		byte[] h = provider.readBytes(0, 2);
		int load = u16le(h, 0);
		if (load < 0x0400 || load > 0xCFFF) {
			return specs;
		}
		specs.add(new LoadSpec(this, 0, LANG, true));
		return specs;
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, ImporterSettings settings) {
		// the loader maps zero page and stack itself
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		MessageLog log = settings.log();
		ByteProvider p = settings.provider();
		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
		byte[] all = p.readBytes(0, p.length());
		int load = u16le(all, 0);
		int size = all.length - 2;
		if (load + size > 0x10000) {
			log.appendMsg("PRG data runs past 0xFFFF; truncated to " + hex(0x10000 - load, 4) +
				" bytes");
			size = 0x10000 - load;
		}
		FileBytes fb = MemoryBlockUtils.createFileBytes(program, p, settings.monitor());
		fileBlock(program, "PRG", ram.getAddress(load), fb, 2, size, false, true, true, true,
			"C64 program loaded at " + hex(load, 4), log);

		// RAM around the program, then I/O and KERNAL ROM (only the unmapped parts; when the
		// program itself lies there, the program wins and the register labels still apply).
		fillGaps(program, ram, "ZERO_PAGE", 0x0000, 0x00FF, true, true, false, false,
			"6510 zero page", log);
		fillGaps(program, ram, "STACK", 0x0100, 0x01FF, true, true, false, false, "6510 stack",
			log);
		fillGaps(program, ram, "RAM", 0x0200, 0x9FFF, true, true, true, false, "RAM", log);
		fillGaps(program, ram, "RAM_BASIC_ROM", 0xA000, 0xBFFF, true, true, true, false,
			"RAM / BASIC ROM (banked by $01)", log);
		fillGaps(program, ram, "RAM_HI", 0xC000, 0xCFFF, true, true, true, false, "RAM", log);
		fillGaps(program, ram, "IO", 0xD000, 0xDFFF, true, true, false, true,
			"VIC-II, SID, colour RAM, CIA1, CIA2 (or char ROM / RAM, banked by $01)", log);
		fillGaps(program, ram, "KERNAL_ROM", 0xE000, 0xFFFF, true, false, true, false,
			"KERNAL ROM (not loaded; jump table declared as externals)", log);

		labelHardware(program, ram, log);
		for (Object[] row : KERNAL_JUMPS) {
			externalRoutine(program, KERNAL, (String) row[1],
				ram.getAddress(((Number) row[0]).longValue()), log);
		}
		labelTable(program, ram, VECTORS, log);

		property(program, "C64 load address", hex(load, 4));
		Address entry = ram.getAddress(load);
		String how = "load address";
		if (load == 0x0801) {
			int sys = findSys(all, size);
			if (sys >= 0) {
				entry = ram.getAddress(sys);
				how = "BASIC SYS " + sys;
				label(program, ram.getAddress(0x0801), "basic_stub", true, log);
				program.getListing()
						.setComment(ram.getAddress(0x0801), CommentType.PLATE,
							"BASIC stub: SYS " + sys);
			}
			else {
				entry = null;
				how = "none (BASIC program without SYS)";
				log.appendMsg("PRG at $0801 has no BASIC SYS line; no entry point set");
			}
		}
		property(program, "C64 entry", entry == null ? "none" : entry + " (" + how + ")");
		if (entry != null) {
			entry(program, entry, "entry", log);
		}
	}

	/**
	 * Parses the BASIC lines at $0801 and returns the number after the first SYS token (0x9E),
	 * or -1. {@code all} is the file (2-byte load address first).
	 */
	static int findSys(byte[] all, int size) {
		int addr = 0x0801;
		for (int line = 0; line < 16; line++) {
			int off = addr - 0x0801 + 2;
			if (off + 4 > size + 2) {
				return -1;
			}
			int next = u16le(all, off);
			if (next == 0) {
				return -1;
			}
			int i = off + 4; // skip link and line number
			int end = Math.min(size + 2, next > addr ? next - 0x0801 + 2 : size + 2);
			while (i < end && all[i] != 0) {
				if ((all[i] & 0xff) == 0x9E) {
					i++;
					while (i < end && (all[i] == ' ' || all[i] == '(')) {
						i++;
					}
					int v = 0, digits = 0;
					while (i < end && all[i] >= '0' && all[i] <= '9' && digits < 6) {
						v = v * 10 + (all[i] - '0');
						i++;
						digits++;
					}
					return digits > 0 && v <= 0xFFFF ? v : -1;
				}
				i++;
			}
			if (next <= addr) {
				return -1;
			}
			addr = next;
		}
		return -1;
	}

	private static void labelHardware(Program program, AddressSpace ram, MessageLog log) {
		labelRegisters(program, ram, 0x0000, new String[] { "D6510", "R6510" }, log);
		String[] vic = new String[0x2F];
		for (int s = 0; s < 8; s++) {
			vic[2 * s] = "SP" + s + "X";
			vic[2 * s + 1] = "SP" + s + "Y";
			vic[0x27 + s] = "SP" + s + "COL";
		}
		String[] vicHi = { "MSIGX", "SCROLY", "RASTER", "LPENX", "LPENY", "SPENA", "SCROLX",
			"YXPAND", "VMCSB", "VICIRQ", "IRQMSK", "SPBGPR", "SPMC", "XXPAND", "SPSPCL", "SPBGCL",
			"EXTCOL", "BGCOL0", "BGCOL1", "BGCOL2", "BGCOL3", "SPMC0", "SPMC1" };
		System.arraycopy(vicHi, 0, vic, 0x10, vicHi.length);
		labelRegisters(program, ram, 0xD000, vic, log);
		labelRegisters(program, ram, 0xD400,
			new String[] { "FRELO1", "FREHI1", "PWLO1", "PWHI1", "VCREG1", "ATDCY1", "SUREL1",
				"FRELO2", "FREHI2", "PWLO2", "PWHI2", "VCREG2", "ATDCY2", "SUREL2", "FRELO3",
				"FREHI3", "PWLO3", "PWHI3", "VCREG3", "ATDCY3", "SUREL3", "CUTLO", "CUTHI",
				"RESON", "SIGVOL", "POTX", "POTY", "RANDOM", "ENV3" },
			log);
		label(program, ram.getAddress(0xD800), "COLOR_RAM", true, log);
		labelRegisters(program, ram, 0xDC00,
			new String[] { "CIAPRA", "CIAPRB", "CIDDRA", "CIDDRB", "TIMALO", "TIMAHI", "TIMBLO",
				"TIMBHI", "TODTEN", "TODSEC", "TODMIN", "TODHRS", "CIASDR", "CIAICR", "CIACRA",
				"CIACRB" },
			log);
		labelRegisters(program, ram, 0xDD00,
			new String[] { "CI2PRA", "CI2PRB", "C2DDRA", "C2DDRB", "TI2ALO", "TI2AHI", "TI2BLO",
				"TI2BHI", "TO2TEN", "TO2SEC", "TO2MIN", "TO2HRS", "CI2SDR", "CI2ICR", "CI2CRA",
				"CI2CRB" },
			log);
	}

	static final Object[][] VECTORS = { { 0x0314, "CINV" }, { 0x0316, "CBINV" },
		{ 0x0318, "NMINV" }, { 0xFFFA, "NMI_VECTOR" }, { 0xFFFC, "RESET_VECTOR" },
		{ 0xFFFE, "IRQ_VECTOR" } };

	/** The KERNAL jump table ($FF81-$FFF3), Commodore's names. */
	static final Object[][] KERNAL_JUMPS = { { 0xFF81, "CINT" }, { 0xFF84, "IOINIT" },
		{ 0xFF87, "RAMTAS" }, { 0xFF8A, "RESTOR" }, { 0xFF8D, "VECTOR" }, { 0xFF90, "SETMSG" },
		{ 0xFF93, "SECOND" }, { 0xFF96, "TKSA" }, { 0xFF99, "MEMTOP" }, { 0xFF9C, "MEMBOT" },
		{ 0xFF9F, "SCNKEY" }, { 0xFFA2, "SETTMO" }, { 0xFFA5, "ACPTR" }, { 0xFFA8, "CIOUT" },
		{ 0xFFAB, "UNTLK" }, { 0xFFAE, "UNLSN" }, { 0xFFB1, "LISTEN" }, { 0xFFB4, "TALK" },
		{ 0xFFB7, "READST" }, { 0xFFBA, "SETLFS" }, { 0xFFBD, "SETNAM" }, { 0xFFC0, "OPEN" },
		{ 0xFFC3, "CLOSE" }, { 0xFFC6, "CHKIN" }, { 0xFFC9, "CHKOUT" }, { 0xFFCC, "CLRCHN" },
		{ 0xFFCF, "CHRIN" }, { 0xFFD2, "CHROUT" }, { 0xFFD5, "LOAD" }, { 0xFFD8, "SAVE" },
		{ 0xFFDB, "SETTIM" }, { 0xFFDE, "RDTIM" }, { 0xFFE1, "STOP" }, { 0xFFE4, "GETIN" },
		{ 0xFFE7, "CLALL" }, { 0xFFEA, "UDTIM" }, { 0xFFED, "SCREEN" }, { 0xFFF0, "PLOT" },
		{ 0xFFF3, "IOBASE" } };
}
