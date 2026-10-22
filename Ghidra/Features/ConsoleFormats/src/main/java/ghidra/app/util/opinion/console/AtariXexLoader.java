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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;

/**
 * Atari 8-bit binary load file (XEX/COM/EXE): $FF $FF, then segments of
 * {start, end (inclusive), data}, each optionally preceded by another $FF $FF. Segments that
 * write INITAD ($02E2) give init routines run right after that segment loads; RUNAD ($02E0)
 * gives the run address.
 */
public class AtariXexLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Atari 8-bit Binary Load File (XEX)";
	static final LanguageCompilerSpecPair LANG = new LanguageCompilerSpecPair("6502:LE:16:default",
		"default");
	static final int RUNAD = 0x02E0;
	static final int INITAD = 0x02E2;

	/** One parsed segment. */
	record Segment(int index, int start, int end, long fileOffset) {
		int length() {
			return end - start + 1;
		}
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
		return 70; // after the cartridge loaders whose ROMs may start with 0xFF fill
	}

	/**
	 * Parses the whole file; returns null unless it is a well-formed binary load file: header
	 * $FFFF, then segments {start, end, data} with start <= end and all data present, each
	 * optionally preceded by ONE $FFFF marker (a run of markers, or a marker not followed by a
	 * segment, is rejected - 0xFF-filled ROM images would otherwise parse). Up to 3 trailing
	 * bytes, or trailing zero padding, are tolerated.
	 */
	static List<Segment> parse(byte[] b) {
		if (b.length < 7 || (b[0] & 0xff) != 0xFF || (b[1] & 0xff) != 0xFF) {
			return null;
		}
		List<Segment> segs = new ArrayList<>();
		int pos = 2;
		while (pos + 4 <= b.length) {
			int start = u16le(b, pos);
			if (start == 0xFFFF) {
				if (segs.isEmpty()) {
					return null; // $FFFF $FFFF at the start
				}
				pos += 2;
				if (pos + 4 > b.length) {
					return null; // marker without a segment
				}
				start = u16le(b, pos);
				if (start == 0xFFFF) {
					return null; // run of markers
				}
			}
			int end = u16le(b, pos + 2);
			if (end < start) {
				if (segs.isEmpty()) {
					return null;
				}
				break;
			}
			int len = end - start + 1;
			if (pos + 4 + len > b.length) {
				return null; // truncated segment
			}
			segs.add(new Segment(segs.size(), start, end, pos + 4));
			pos += 4 + len;
		}
		if (segs.isEmpty()) {
			return null;
		}
		if (b.length - pos > 3) {
			for (int i = pos; i < b.length; i++) {
				if (b[i] != 0) {
					return null; // trailing garbage
				}
			}
		}
		return segs;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < 7 || provider.length() > 0x100000) {
			return specs;
		}
		if (parse(provider.readBytes(0, provider.length())) != null) {
			specs.add(new LoadSpec(this, 0, LANG, true));
		}
		return specs;
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, ImporterSettings settings) {
		// zero page and stack are created by the loader
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		MessageLog log = settings.log();
		ByteProvider p = settings.provider();
		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
		byte[] b = p.readBytes(0, p.length());
		List<Segment> segs = parse(b);
		if (segs == null) {
			throw new IOException("Not an Atari binary load file");
		}
		FileBytes fb = MemoryBlockUtils.createFileBytes(program, p, settings.monitor());

		List<Integer> inits = new ArrayList<>();
		Integer run = null;
		StringBuilder layout = new StringBuilder();
		for (Segment s : segs) {
			settings.monitor().checkCancelled();
			layout.append(String.format("seg%d $%04X-$%04X%n", s.index(), s.start(), s.end()));
			boolean vectorOnly = s.start() >= RUNAD && s.end() <= INITAD + 1;
			if (vectorOnly) {
				// RUNAD/INITAD writes: decoded into entries, not mapped (each repeats $02E0-3)
				for (int a = s.start(); a <= s.end(); a++) {
					if (a == RUNAD && s.end() >= RUNAD + 1) {
						run = u16le(b, (int) s.fileOffset() + (RUNAD - s.start()));
					}
					if (a == INITAD && s.end() >= INITAD + 1) {
						inits.add(u16le(b, (int) s.fileOffset() + (INITAD - s.start())));
					}
				}
				continue;
			}
			String name = String.format("SEG%02d_%04X", s.index(), s.start());
			MemoryBlock blk = fileBlock(program, name, ram.getAddress(s.start()), fb,
				s.fileOffset(), s.length(), null, true, true, true,
				String.format("segment %d, file offset 0x%X", s.index(), s.fileOffset()), log);
			if (blk != null && blk.isOverlay()) {
				log.appendMsg(name + " overlaps an earlier segment; mapped as overlay " +
					blk.getName() + " (it replaces those bytes at load time)");
			}
			// INITAD/RUNAD inside a bigger segment
			if (s.start() <= INITAD && s.end() >= INITAD + 1) {
				inits.add(u16le(b, (int) s.fileOffset() + (INITAD - s.start())));
			}
			if (s.start() <= RUNAD && s.end() >= RUNAD + 1) {
				run = u16le(b, (int) s.fileOffset() + (RUNAD - s.start()));
			}
		}

		fillGaps(program, ram, "ZERO_PAGE", 0x0000, 0x00FF, true, true, false, false,
			"zero page", log);
		fillGaps(program, ram, "STACK", 0x0100, 0x01FF, true, true, false, false, "stack", log);
		fillGaps(program, ram, "RAM", 0x0200, 0x9FFF, true, true, true, false, "RAM", log);
		fillGaps(program, ram, "RAM_CART", 0xA000, 0xBFFF, true, true, true, false,
			"RAM / BASIC or cartridge ROM", log);
		fillGaps(program, ram, "OS_ROM_C000", 0xC000, 0xCFFF, true, false, true, false,
			"OS ROM (XL/XE: RAM under ROM)", log);
		fillGaps(program, ram, "GTIA", 0xD000, 0xD0FF, true, true, false, true, "GTIA", log);
		fillGaps(program, ram, "POKEY", 0xD200, 0xD2FF, true, true, false, true, "POKEY", log);
		fillGaps(program, ram, "PIA", 0xD300, 0xD3FF, true, true, false, true, "PIA", log);
		fillGaps(program, ram, "ANTIC", 0xD400, 0xD4FF, true, true, false, true, "ANTIC", log);
		fillGaps(program, ram, "OS_ROM", 0xD800, 0xFFFF, true, false, true, false,
			"floating point + OS ROM (not loaded)", log);

		labelHardware(program, ram, log);
		for (Object[] row : OS_VECTORS) {
			externalRoutine(program, "ATARI_OS", (String) row[1],
				ram.getAddress(((Number) row[0]).longValue()), log);
		}

		property(program, "Atari XEX segments", Integer.toString(segs.size()));
		property(program, "Atari XEX layout", layout.toString().trim());
		int n = 0;
		for (int init : inits) {
			Address a = ram.getAddress(init);
			entry(program, a, "init_" + (n++), log);
			program.getListing()
					.setComment(a, CommentType.PLATE,
						"INITAD routine (run by DOS right after its segment loads)");
		}
		property(program, "Atari XEX INITAD",
			inits.stream().map(v -> hex(v, 4)).reduce((x, y) -> x + "," + y).orElse("none"));
		property(program, "Atari XEX RUNAD", run == null ? "none" : hex(run, 4));
		if (run != null) {
			entry(program, ram.getAddress(run), "run", log);
		}
		else if (inits.isEmpty()) {
			// no vectors: DOS jumps to the first segment's start
			entry(program, ram.getAddress(segs.get(0).start()), "start", log);
		}
	}

	private static void labelHardware(Program program, AddressSpace ram, MessageLog log) {
		labelRegisters(program, ram, 0xD000,
			new String[] { "HPOSP0", "HPOSP1", "HPOSP2", "HPOSP3", "HPOSM0", "HPOSM1", "HPOSM2",
				"HPOSM3", "SIZEP0", "SIZEP1", "SIZEP2", "SIZEP3", "SIZEM", "GRAFP0", "GRAFP1",
				"GRAFP2", "GRAFP3", "GRAFM", "COLPM0", "COLPM1", "COLPM2", "COLPM3", "COLPF0",
				"COLPF1", "COLPF2", "COLPF3", "COLBK", "PRIOR", "VDELAY", "GRACTL", "HITCLR",
				"CONSOL" },
			log);
		labelRegisters(program, ram, 0xD200,
			new String[] { "AUDF1", "AUDC1", "AUDF2", "AUDC2", "AUDF3", "AUDC3", "AUDF4", "AUDC4",
				"AUDCTL", "STIMER", "SKREST", "POTGO", null, "SEROUT", "IRQEN", "SKCTL" },
			log);
		labelRegisters(program, ram, 0xD300, new String[] { "PORTA", "PORTB", "PACTL", "PBCTL" },
			log);
		labelRegisters(program, ram, 0xD400,
			new String[] { "DMACTL", "CHACTL", "DLISTL", "DLISTH", "HSCROL", "VSCROL", null,
				"PMBASE", null, "CHBASE", "WSYNC", "VCOUNT", "PENH", "PENV", "NMIEN", "NMIRES" },
			log);
		labelTable(program, ram, OS_VARS, log);
	}

	/** OS RAM variables / shadow registers (Atari OS names). */
	static final Object[][] OS_VARS = { { 0x000A, "DOSVEC" }, { 0x000C, "DOSINI" },
		{ 0x0012, "RTCLOK" }, { 0x0200, "VDSLST" }, { 0x0222, "VVBLKI" }, { 0x0224, "VVBLKD" },
		{ 0x022F, "SDMCTL" }, { 0x0230, "SDLSTL" }, { 0x0231, "SDLSTH" }, { 0x026F, "GPRIOR" },
		{ 0x0278, "STICK0" }, { 0x0284, "STRIG0" }, { 0x02C0, "PCOLR0" }, { 0x02C4, "COLOR0" },
		{ 0x02C5, "COLOR1" }, { 0x02C6, "COLOR2" }, { 0x02C7, "COLOR3" }, { 0x02C8, "COLOR4" },
		{ 0x02E0, "RUNAD" }, { 0x02E2, "INITAD" }, { 0x02E5, "MEMTOP" }, { 0x02E7, "MEMLO" },
		{ 0x02F4, "CHBAS" }, { 0x02FC, "CH" }, { 0x0300, "DDEVIC" }, { 0x0340, "IOCB0" },
		{ 0xFFFA, "NMI_VECTOR" }, { 0xFFFC, "RESET_VECTOR" }, { 0xFFFE, "IRQ_VECTOR" } };

	/** OS ROM jump vectors at $E450. */
	static final Object[][] OS_VECTORS = { { 0xE450, "DISKIV" }, { 0xE453, "DSKINV" },
		{ 0xE456, "CIOV" }, { 0xE459, "SIOV" }, { 0xE45C, "SETVBV" }, { 0xE45F, "SYSVBV" },
		{ 0xE462, "XITVBV" }, { 0xE465, "SIOINV" }, { 0xE468, "SENDEV" }, { 0xE46B, "INTINV" },
		{ 0xE46E, "CIOINV" }, { 0xE471, "BLKBDV" }, { 0xE474, "WARMSV" }, { 0xE477, "COLDSV" },
		{ 0xE47A, "RBLOKV" }, { 0xE47D, "CSOPIV" } };
}
