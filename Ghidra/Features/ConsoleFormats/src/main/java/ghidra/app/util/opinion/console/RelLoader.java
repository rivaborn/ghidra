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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for GameCube / Wii relocatable modules (REL, DolphinOS OSModule).
 * <p>
 * Header (big-endian): id 0x00, next 0x04, prev 0x08, numSections 0x0C, sectionInfoOffset
 * 0x10, nameOffset 0x14, nameSize 0x18, version 0x1C, bssSize 0x20, relOffset 0x24, impOffset
 * 0x28, impSize 0x2C, prolog/epilog/unresolved/bss section bytes 0x30-0x33, prolog 0x34,
 * epilog 0x38, unresolved 0x3C; version 2+: align 0x40, bssAlign 0x44; version 3: fixSize 0x48.
 * <p>
 * The module is placed like OSLink does: the file image at the chosen base, each section at
 * base + its file offset, BSS after the image. Relocations against the module itself and
 * against module 0 (the main DOL: absolute addresses) are applied; relocations against other
 * modules are left unpatched and commented.
 */
public class RelLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Nintendo GameCube/Wii REL";

	static final String OPT_BASE = "Module base address";
	static final String OPT_PLATFORM = "Map GameCube/Wii platform (MEM1, registers)";

	static final int R_DOLPHIN_NOP = 201;
	static final int R_DOLPHIN_SECTION = 202;
	static final int R_DOLPHIN_END = 203;

	public record RelHeader(long id, int numSections, long sectionInfoOffset, long nameOffset,
			long nameSize, int version, long bssSize, long relOffset, long impOffset,
			long impSize, int prologSection, int epilogSection, int unresolvedSection,
			long prolog, long epilog, long unresolved, long align, long bssAlign, long fixSize,
			long[] secOffset, long[] secSize, boolean[] secExec) {
		int headerSize() {
			return version == 1 ? 0x40 : version == 2 ? 0x48 : 0x4C;
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

	private static boolean pow2OrZero(long v) {
		return (v & (v - 1)) == 0 && v <= 0x10000;
	}

	/** Parses and validates a REL; returns null if the bytes are not a REL module. */
	public static RelHeader parse(byte[] b) {
		long len = b.length;
		if (len < 0x40) {
			return null;
		}
		long id = u(be32(b, 0));
		int version = be32(b, 0x1C);
		if (id == 0 || be32(b, 4) != 0 || be32(b, 8) != 0 || version < 1 || version > 3) {
			return null;
		}
		int hdr = version == 1 ? 0x40 : version == 2 ? 0x48 : 0x4C;
		if (len < hdr) {
			return null;
		}
		long num = u(be32(b, 0x0C));
		long sio = u(be32(b, 0x10));
		if (num < 2 || num > 255 || sio < hdr || (sio & 3) != 0 || sio + num * 8 > len) {
			return null;
		}
		long[] off = new long[(int) num], size = new long[(int) num];
		boolean[] exec = new boolean[(int) num];
		boolean anyExec = false;
		for (int i = 0; i < num; i++) {
			long raw = u(be32(b, (int) (sio + i * 8)));
			off[i] = raw & ~1L;
			exec[i] = (raw & 1) != 0;
			size[i] = u(be32(b, (int) (sio + i * 8 + 4)));
			if (i == 0 && (raw != 0 || size[i] != 0)) {
				return null;
			}
			if (off[i] != 0) {
				if (off[i] < hdr || off[i] + size[i] > len) {
					return null;
				}
				if (exec[i] && size[i] > 0) {
					anyExec = true;
				}
			}
		}
		if (!anyExec) {
			return null;
		}
		long relOff = u(be32(b, 0x24)), impOff = u(be32(b, 0x28)), impSize = u(be32(b, 0x2C));
		if ((impSize & 7) != 0 || impOff + impSize > len || relOff > len) {
			return null;
		}
		if (impSize > 0 && (impOff < hdr || relOff < hdr)) {
			return null;
		}
		for (long p = impOff; p < impOff + impSize; p += 8) {
			long o = u(be32(b, (int) p + 4));
			if (o < hdr || o + 8 > len) {
				return null;
			}
		}
		int[] secs = { b[0x30] & 0xFF, b[0x31] & 0xFF, b[0x32] & 0xFF };
		long[] fn = { u(be32(b, 0x34)), u(be32(b, 0x38)), u(be32(b, 0x3C)) };
		for (int k = 0; k < 3; k++) {
			if (secs[k] >= num) {
				return null;
			}
			if (secs[k] != 0 && (off[secs[k]] == 0 || fn[k] >= size[secs[k]])) {
				return null;
			}
		}
		long align = version >= 2 ? u(be32(b, 0x40)) : 0;
		long bssAlign = version >= 2 ? u(be32(b, 0x44)) : 0;
		long fixSize = version >= 3 ? u(be32(b, 0x48)) : 0;
		if (!pow2OrZero(align) || !pow2OrZero(bssAlign) || fixSize > len) {
			return null;
		}
		return new RelHeader(id, (int) num, sio, u(be32(b, 0x14)), u(be32(b, 0x18)), version,
			u(be32(b, 0x20)), relOff, impOff, impSize, secs[0], secs[1], secs[2], fn[0], fn[1],
			fn[2], align, bssAlign, fixSize, off, size, exec);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		long len = provider.length();
		if (len < 0x40 || len > 0x02000000L) {
			return specs;
		}
		// cheap pre-check before reading the whole file
		byte[] h = provider.readBytes(0, 0x40);
		int version = be32(h, 0x1C);
		if (be32(h, 0) == 0 || be32(h, 4) != 0 || be32(h, 8) != 0 || version < 1 ||
			version > 3) {
			return specs;
		}
		if (parse(provider.readBytes(0, len)) != null) {
			specs.add(new LoadSpec(this, 0, gekkoOrDefault(getLanguageService()), true));
		}
		return specs;
	}

	private static List<Option> myOptions() {
		return List.of(
			new Option(OPT_BASE, new HexLong(0x80800000L), HexLong.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr"),
			new Option(OPT_PLATFORM, true, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-platform"));
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
		return r != null ? r : super.validateOptions(provider, loadSpec, options, program);
	}

	private static long alignUp(long v, long a) {
		if (a <= 1) {
			return v;
		}
		return (v + a - 1) & ~(a - 1);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		byte[] b = provider.readBytes(0, provider.length());
		RelHeader h = parse(b);
		if (h == null) {
			throw new IOException("Not a REL module");
		}
		long align = Math.max(h.align(), 32);
		long base = optionLong(options, OPT_BASE, 0x80800000L);
		if ((base & (align - 1)) != 0) {
			long aligned = alignUp(base, align);
			log.appendMsg("Base " + hex(base) + " aligned to " + hex(aligned));
			base = aligned;
		}
		long bssAlign = Math.max(h.bssAlign(), 32);
		long bssBase = alignUp(base + b.length, bssAlign);

		FileBytes fb = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		long[] secAddr = new long[h.numSections()];
		StringBuilder map = new StringBuilder();
		for (int i = 1; i < h.numSections(); i++) {
			long size = h.secSize()[i];
			if (size == 0) {
				continue;
			}
			String name = "sec" + i;
			if (h.secOffset()[i] == 0) {
				secAddr[i] = bssBase;
				bssBase = alignUp(bssBase + size, bssAlign);
				uninitBlock(program, name + "_bss", secAddr[i], size, true, true, false, false,
					"REL section " + i + " (BSS)", log);
			}
			else {
				secAddr[i] = base + h.secOffset()[i];
				boolean x = h.secExec()[i];
				fileBlock(program, fb, name + (x ? "_text" : "_data"), secAddr[i],
					h.secOffset()[i], size, true, !x, x,
					"REL section " + i + " (file " + hex(h.secOffset()[i]) + ")", log);
			}
			map.append(i).append(':').append(hex(secAddr[i])).append('+').append(hex(size));
			map.append(h.secExec()[i] ? "x " : " ");
		}

		// relocations
		int applied = 0, external = 0, failed = 0;
		Set<Long> otherModules = new TreeSet<>();
		for (long p = h.impOffset(); p < h.impOffset() + h.impSize(); p += 8) {
			monitor.checkCancelled();
			long module = u(be32(b, (int) p));
			int pos = (int) u(be32(b, (int) p + 4));
			int sec = 0;
			long where = 0;
			for (; pos + 8 <= b.length; pos += 8) {
				int delta = be16(b, pos);
				int type = b[pos + 2] & 0xFF;
				int section = b[pos + 3] & 0xFF;
				long addend = u(be32(b, pos + 4));
				where += delta;
				if (type == R_DOLPHIN_END) {
					break;
				}
				if (type == R_DOLPHIN_SECTION) {
					sec = section;
					where = 0;
					continue;
				}
				if (type == R_DOLPHIN_NOP || sec >= secAddr.length) {
					continue;
				}
				Address at = addr(program, secAddr[sec] + where);
				long value;
				String symbol = null;
				if (module == h.id()) {
					if (section >= secAddr.length) {
						failed++;
						continue;
					}
					value = secAddr[section] + addend;
				}
				else if (module == 0) {
					value = addend;
					symbol = "dol_" + Long.toHexString(addend);
				}
				else {
					external++;
					otherModules.add(module);
					program.getListing()
							.setComment(at, CommentType.EOL, "REL import: module " + module +
								" section " + section + " + " + hex(addend) + " (type " + type +
								")");
					recordRelocation(program, at, type, addend, ppcRelocationLength(type), false,
						"module" + module + "_sec" + section);
					continue;
				}
				int len = ppcRelocationLength(type);
				int status = applyPpcRelocation(program, at, type, value);
				if (status == RELOC_OK) {
					applied++;
				}
				else {
					failed++;
					log.appendMsg("REL relocation type " + type + " at " + at + " failed (" +
						status + ")");
				}
				recordRelocation(program, at, type, value, len, status == RELOC_OK, symbol);
			}
		}

		if (optionBool(options, OPT_PLATFORM, true)) {
			DolLoader.mapPlatform(program, false, false, log);
		}

		// prolog / epilog / unresolved
		if (h.prologSection() != 0) {
			entry(program, secAddr[h.prologSection()] + h.prolog(), "_prolog");
		}
		if (h.epilogSection() != 0) {
			function(program, secAddr[h.epilogSection()] + h.epilog(), "_epilog");
			program.getSymbolTable()
					.addExternalEntryPoint(addr(program, secAddr[h.epilogSection()] + h.epilog()));
		}
		if (h.unresolvedSection() != 0) {
			function(program, secAddr[h.unresolvedSection()] + h.unresolved(), "_unresolved");
		}

		// header markup
		StructureDataType hs = struct("REL_Header", "id", u32(), "next", u32(), "prev", u32(),
			"num_sections", u32(), "section_info_offset", u32(), "name_offset", u32(),
			"name_size", u32(), "version", u32(), "bss_size", u32(), "rel_offset", u32(),
			"imp_offset", u32(), "imp_size", u32(), "prolog_section", u8(), "epilog_section",
			u8(), "unresolved_section", u8(), "bss_section", u8(), "prolog", u32(), "epilog",
			u32(), "unresolved", u32());
		if (h.version() >= 2) {
			hs.add(u32(), 4, "align", null);
			hs.add(u32(), 4, "bss_align", null);
		}
		if (h.version() >= 3) {
			hs.add(u32(), 4, "fix_size", null);
		}
		headerBlock(program, fb, 0, hs, "REL_HEADER", log);

		info(program, "REL module id", Long.toString(h.id()));
		info(program, "REL version", Integer.toString(h.version()));
		info(program, "REL base", hex(base));
		info(program, "REL sections", map.toString().trim());
		info(program, "REL name (offset/size in the .str file)",
			hex(h.nameOffset()) + " / " + hex(h.nameSize()));
		info(program, "REL relocations", applied + " applied, " + failed + " failed, " +
			external + " against other modules " + otherModules);
		if (h.version() >= 3) {
			info(program, "REL fixSize", hex(h.fixSize()));
		}
	}
}
