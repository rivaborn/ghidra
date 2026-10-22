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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.HexLong;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Shared plumbing for the Sega console loaders (Mega Drive, Master System / Game Gear, Saturn,
 * Dreamcast): block creation, labels, entry points, header data and program-information records.
 * <p>
 * Not a {@link Loader} itself (the class name does not end in "Loader", so the class searcher
 * ignores it).
 */
public abstract class SegaLoaderBase extends AbstractProgramWrapperLoader {

	/** Program-information key prefix used for every header field the Sega loaders record. */
	public static final String INFO_PREFIX = "Sega ";

	@Override
	public LoaderTier getTier() {
		return LoaderTier.GENERIC_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	// ------------------------------------------------------------------ byte helpers

	protected static byte[] read(ByteProvider provider, long offset, int length)
			throws IOException {
		long avail = provider.length() - offset;
		if (offset < 0 || avail <= 0) {
			return new byte[0];
		}
		return provider.readBytes(offset, (int) Math.min(length, avail));
	}

	protected static boolean startsWith(byte[] data, int offset, String ascii) {
		byte[] s = ascii.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
		if (offset < 0 || offset + s.length > data.length) {
			return false;
		}
		for (int i = 0; i < s.length; i++) {
			if (data[offset + i] != s[i]) {
				return false;
			}
		}
		return true;
	}

	protected static int u8(byte[] d, int o) {
		return d[o] & 0xff;
	}

	protected static int u16be(byte[] d, int o) {
		return ((d[o] & 0xff) << 8) | (d[o + 1] & 0xff);
	}

	protected static int u16le(byte[] d, int o) {
		return ((d[o + 1] & 0xff) << 8) | (d[o] & 0xff);
	}

	protected static long u32be(byte[] d, int o) {
		return ((long) u16be(d, o) << 16) | u16be(d, o + 2);
	}

	protected static long u32le(byte[] d, int o) {
		return ((long) u16le(d, o + 2) << 16) | u16le(d, o);
	}

	/** ASCII field, non-printables replaced, trailing blanks/NULs trimmed. */
	protected static String ascii(byte[] d, int o, int len) {
		StringBuilder sb = new StringBuilder();
		for (int i = o; i < o + len && i < d.length; i++) {
			int c = d[i] & 0xff;
			sb.append(c >= 0x20 && c < 0x7f ? (char) c : ' ');
		}
		return sb.toString().replaceAll("\\s+$", "");
	}

	protected static String hex(long v) {
		return String.format("0x%X", v);
	}

	// ------------------------------------------------------------------ options

	protected static long hexOption(List<Option> options, String name, long dflt) {
		Object v = optionValue(options, name);
		if (v instanceof Number n) {
			return n.longValue();
		}
		if (v instanceof String s && !s.isBlank()) {
			try {
				return Long.decode(s.trim());
			}
			catch (NumberFormatException e) {
				return dflt;
			}
		}
		return dflt;
	}

	protected static boolean boolOption(List<Option> options, String name, boolean dflt) {
		Object v = optionValue(options, name);
		return v instanceof Boolean b ? b : dflt;
	}

	protected static String stringOption(List<Option> options, String name, String dflt) {
		Object v = optionValue(options, name);
		return v instanceof String s ? s.trim() : dflt;
	}

	private static Object optionValue(List<Option> options, String name) {
		if (options == null) {
			return null;
		}
		for (Option o : options) {
			if (o.getName().equals(name)) {
				return o.getValue();
			}
		}
		return null;
	}

	protected static Option hexOpt(String name, long value, String arg) {
		return new Option(name, new HexLong(value), HexLong.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-" + arg);
	}

	protected static Option boolOpt(String name, boolean value, String arg) {
		return new Option(name, value, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-" + arg);
	}

	protected static Option stringOpt(String name, String value, String arg) {
		return new Option(name, value, String.class, Loader.COMMAND_LINE_ARG_PREFIX + "-" + arg);
	}

	/** Validates that every option of ours named in {@code ours} has the expected value class. */
	protected String validateOwn(List<Option> options, Map<String, Class<?>> ours) {
		if (options == null) {
			return null;
		}
		for (Option o : options) {
			Class<?> c = ours.get(o.getName());
			if (c != null && o.getValue() != null && !c.isInstance(o.getValue())) {
				return "Invalid type for option: " + o.getName();
			}
		}
		return null;
	}

	// ------------------------------------------------------------------ memory

	protected static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/** File bytes holding {@code data} (used for de-interleaved / de-sectored / descrambled images). */
	protected static FileBytes fileBytes(Program program, String name, byte[] data,
			TaskMonitor monitor) throws IOException, CancelledException {
		return program.getMemory()
				.createFileBytes(name, 0, data.length, new ByteArrayInputStream(data), monitor);
	}

	protected static MemoryBlock romBlock(Program program, String name, long start, FileBytes fb,
			long offset, long length, boolean overlay, boolean write, String comment,
			MessageLog log) {
		try {
			MemoryBlock b = program.getMemory()
					.createInitializedBlock(name, addr(program, start), fb, offset, length,
						overlay);
			b.setRead(true);
			b.setWrite(write);
			b.setExecute(true);
			b.setSourceName("Sega loader");
			if (comment != null) {
				b.setComment(comment);
			}
			return b;
		}
		catch (Exception e) {
			log.appendMsg("Failed to create block " + name + " at " + hex(start) + ": " +
				e.getMessage());
			return null;
		}
	}

	protected static MemoryBlock uninit(Program program, String name, long start, long length,
			boolean write, boolean execute, boolean isVolatile, boolean overlay, String comment,
			MessageLog log) {
		try {
			MemoryBlock b = program.getMemory()
					.createUninitializedBlock(name, addr(program, start), length, overlay);
			b.setRead(true);
			b.setWrite(write);
			b.setExecute(execute);
			b.setVolatile(isVolatile);
			b.setSourceName("Sega loader");
			if (comment != null) {
				b.setComment(comment);
			}
			return b;
		}
		catch (Exception e) {
			log.appendMsg("Failed to create block " + name + " at " + hex(start) + ": " +
				e.getMessage());
			return null;
		}
	}

	/** Hardware register region: uninitialized, volatile, read/write, not executable. */
	protected static MemoryBlock io(Program program, String name, long start, long length,
			String comment, MessageLog log) {
		return uninit(program, name, start, length, true, false, true, false, comment, log);
	}

	protected static MemoryBlock mirror(Program program, String name, long start, long target,
			long length, String comment, MessageLog log) {
		return mirror(program, name, start, target, length, true, true, comment, log);
	}

	/** Byte-mapped block: {@code start..} shows the bytes at {@code target..}. */
	protected static MemoryBlock mirror(Program program, String name, long start, long target,
			long length, boolean write, boolean execute, String comment, MessageLog log) {
		try {
			MemoryBlock b = program.getMemory()
					.createByteMappedBlock(name, addr(program, start), addr(program, target),
						length, false);
			b.setSourceName("Sega loader");
			b.setRead(true);
			b.setWrite(write);
			b.setExecute(execute);
			b.setComment(comment);
			return b;
		}
		catch (Exception e) {
			log.appendMsg("Failed to create mirror " + name + ": " + e.getMessage());
			return null;
		}
	}

	/**
	 * Creates uninitialized RAM blocks over [start, start+length) except where blocks already
	 * exist (e.g. a loaded executable placed inside RAM).
	 */
	protected static void ramAround(Program program, String name, long start, long length,
			String comment, MessageLog log) {
		Memory mem = program.getMemory();
		long end = start + length; // exclusive
		long cur = start;
		int part = 0;
		while (cur < end) {
			MemoryBlock b = mem.getBlock(addr(program, cur));
			if (b != null) {
				cur = b.getEnd().getOffset() + 1;
				continue;
			}
			long next = end;
			for (MemoryBlock other : mem.getBlocks()) {
				if (other.isOverlay()) {
					continue;
				}
				long s = other.getStart().getOffset();
				if (s > cur && s < next &&
					other.getStart().getAddressSpace() == addr(program, cur).getAddressSpace()) {
					next = s;
				}
			}
			uninit(program, part == 0 ? name : name + "_" + part, cur, next - cur, true, true,
				false, false, comment, log);
			part++;
			cur = next;
		}
	}

	// ------------------------------------------------------------------ symbols / data

	protected static Symbol label(Program program, Address a, String name) {
		try {
			SymbolTable st = program.getSymbolTable();
			Symbol s = st.createLabel(a, name, SourceType.IMPORTED);
			if (s != null && !s.isPrimary()) {
				s.setPrimary();
			}
			return s;
		}
		catch (Exception e) {
			return null;
		}
	}

	/** Secondary (non-primary) label. */
	protected static Symbol alias(Program program, Address a, String name) {
		try {
			return program.getSymbolTable().createLabel(a, name, SourceType.IMPORTED);
		}
		catch (Exception e) {
			return null;
		}
	}

	/** Labelled hardware register of {@code size} bytes (1, 2 or 4), typed so that the
	 * decompiler shows the register name for full-width accesses. */
	protected static void reg(Program program, long offset, String name, int size) {
		Address a = addr(program, offset);
		label(program, a, name);
		DataType dt = size == 4 ? DWordDataType.dataType
				: size == 2 ? WordDataType.dataType : ByteDataType.dataType;
		data(program, a, dt, size);
	}

	/**
	 * Labels a register table: each entry is "offset:NAME:size" (hex offset from {@code base},
	 * size in bytes). When {@code mirror} is non-zero the label is repeated at
	 * {@code mirror + offset} (e.g. a cache-through alias).
	 */
	protected static void regs(Program program, long base, long mirror, String... table) {
		for (String e : table) {
			String[] f = e.split(":");
			long off = Long.parseLong(f[0], 16);
			int size = f.length > 2 ? Integer.parseInt(f[2]) : 4;
			reg(program, base + off, f[1], size);
			if (mirror != 0) {
				label(program, mirror + off, f[1]);
			}
		}
	}

	protected static Symbol label(Program program, long offset, String name) {
		return label(program, addr(program, offset), name);
	}

	protected static void comment(Program program, Address a, String text) {
		try {
			program.getListing().setComment(a, CommentType.PLATE, text);
		}
		catch (Exception e) {
			// ignore: address without a code unit
		}
	}

	protected static void eol(Program program, Address a, String text) {
		try {
			program.getListing().setComment(a, CommentType.EOL, text);
		}
		catch (Exception e) {
			// ignore
		}
	}

	/** Labels {@code a}, makes it an external entry point and marks it as a function. */
	protected static void entry(Program program, Address a, String name) {
		label(program, a, name);
		program.getSymbolTable().addExternalEntryPoint(a);
		AbstractProgramLoader.markAsFunction(program, name, a);
	}

	protected static Data data(Program program, Address a, DataType dt, int length) {
		try {
			return DataUtilities.createData(program, a, dt, length,
				DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		}
		catch (Exception e) {
			return null;
		}
	}

	/** Labelled header field: string, byte, word or dword data. */
	protected static void field(Program program, long base, int offset, String name,
			DataType dt, int length) {
		Address a = addr(program, base + offset);
		label(program, a, name);
		data(program, a, dt, length);
	}

	protected static void stringField(Program program, long base, int offset, String name,
			int length) {
		field(program, base, offset, name, new StringDataType(), length);
	}

	protected static void info(Program program, String key, String value) {
		Options o = program.getOptions(Program.PROGRAM_INFO);
		o.setString(INFO_PREFIX + key, value == null ? "" : value);
	}

	/** Address in an overlay space named {@code space}, or null when no such space exists. */
	public static Address overlayAddress(Program program, String space, long offset) {
		AddressSpace s = program.getAddressFactory().getAddressSpace(space);
		return s == null ? null : s.getAddress(offset);
	}

	protected static List<LoadSpec> spec(Loader loader, String languageId, boolean preferred) {
		List<LoadSpec> l = new ArrayList<>();
		l.add(new LoadSpec(loader, 0,
			new ghidra.program.model.lang.LanguageCompilerSpecPair(languageId, "default"),
			preferred));
		return l;
	}
}
