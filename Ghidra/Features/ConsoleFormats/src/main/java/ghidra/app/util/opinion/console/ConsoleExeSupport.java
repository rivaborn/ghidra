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
import java.math.BigInteger;
import java.util.List;

import ghidra.app.util.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Shared helpers for the console executable loaders (PS-X EXE, N64, DOL, REL, NDS, GBA,
 * RPX/RPL): block creation, gap filling, register labels, entry points, header markup and
 * PowerPC relocation arithmetic.
 */
public final class ConsoleExeSupport {

	private ConsoleExeSupport() {
	}

	/** Returns true if the language exists in the given language service. */
	public static boolean hasLanguage(LanguageService service, String languageId) {
		try {
			service.getLanguageDescription(new LanguageID(languageId));
			return true;
		}
		catch (LanguageNotFoundException e) {
			return false;
		}
	}

	public static final String GEKKO_LANGUAGE = "PowerPC:BE:32:Gekko_Broadway";
	public static final String PPC_DEFAULT_LANGUAGE = "PowerPC:BE:32:default";

	/**
	 * The language for GameCube / Wii / Wii U PowerPC code: the Gekko/Broadway variant when it
	 * is installed (paired singles), otherwise the stock 32-bit big-endian PowerPC.
	 */
	public static LanguageCompilerSpecPair gekkoOrDefault(LanguageService service) {
		for (String id : new String[] { GEKKO_LANGUAGE, PPC_DEFAULT_LANGUAGE }) {
			try {
				LanguageDescription d = service.getLanguageDescription(new LanguageID(id));
				String cs = "default";
				List<CompilerSpecDescription> specs =
					new java.util.ArrayList<>(d.getCompatibleCompilerSpecDescriptions());
				boolean hasDefault = specs.stream()
						.anyMatch(s -> s.getCompilerSpecID().getIdAsString().equals("default"));
				if (!hasDefault && !specs.isEmpty()) {
					cs = specs.get(0).getCompilerSpecID().getIdAsString();
				}
				return new LanguageCompilerSpecPair(id, cs);
			}
			catch (LanguageNotFoundException e) {
				// try the next one
			}
		}
		return new LanguageCompilerSpecPair(PPC_DEFAULT_LANGUAGE, "default");
	}

	public static LanguageCompilerSpecPair pair(String languageId, String compilerId) {
		return new LanguageCompilerSpecPair(languageId, compilerId);
	}

	public static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset & 0xFFFFFFFFL);
	}

	// ---------------------------------------------------------------- options

	public static Object optionValue(List<Option> options, String name) {
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

	public static long optionLong(List<Option> options, String name, long def) {
		Object v = optionValue(options, name);
		if (v instanceof HexLong h) {
			return h.longValue();
		}
		if (v instanceof Number n) {
			return n.longValue();
		}
		if (v instanceof String s) {
			try {
				return Long.decode(s.trim());
			}
			catch (NumberFormatException e) {
				return def;
			}
		}
		return def;
	}

	public static boolean optionBool(List<Option> options, String name, boolean def) {
		Object v = optionValue(options, name);
		if (v instanceof Boolean b) {
			return b;
		}
		if (v instanceof String s) {
			return Boolean.parseBoolean(s.trim());
		}
		return def;
	}

	public static String optionString(List<Option> options, String name, String def) {
		Object v = optionValue(options, name);
		return v != null ? v.toString() : def;
	}

	/**
	 * Validates the value classes of loader-specific options.
	 * @return an error message or null
	 */
	public static String validateTypes(List<Option> options, List<Option> defaults) {
		if (options == null) {
			return null;
		}
		for (Option o : options) {
			for (Option d : defaults) {
				if (d.getName().equals(o.getName()) &&
					!d.getValueClass().isAssignableFrom(o.getValueClass())) {
					return "Invalid type for option: " + o.getName() + " - " + o.getValueClass();
				}
			}
		}
		return null;
	}

	// ---------------------------------------------------------------- memory

	/** Creates an initialized block backed by file bytes (overlay on conflict). */
	public static MemoryBlock fileBlock(Program program, FileBytes fileBytes, String name,
			long address, long fileOffset, long length, boolean r, boolean w, boolean x,
			String comment, MessageLog log) {
		if (length <= 0) {
			return null;
		}
		try {
			return MemoryBlockUtils.createInitializedBlock(program, false, name,
				addr(program, address), fileBytes, fileOffset, length, comment, null, r, w, x,
				log);
		}
		catch (AddressOverflowException e) {
			log.appendMsg("Block " + name + " does not fit in the address space: " +
				e.getMessage());
			return null;
		}
	}

	/** Creates an initialized block from a byte array (overlay on conflict). */
	public static MemoryBlock bytesBlock(Program program, String name, long address, byte[] data,
			boolean r, boolean w, boolean x, String comment, MessageLog log, TaskMonitor monitor) {
		return bytesBlock(program, name, address, data, 0, data.length, false, r, w, x, comment,
			log, monitor);
	}

	public static MemoryBlock bytesBlock(Program program, String name, long address, byte[] data,
			int off, int len, boolean overlay, boolean r, boolean w, boolean x, String comment,
			MessageLog log, TaskMonitor monitor) {
		if (len <= 0) {
			return null;
		}
		try {
			return MemoryBlockUtils.createInitializedBlock(program, overlay, name,
				addr(program, address), new ByteArrayInputStream(data, off, len), len, comment,
				null, r, w, x, log, monitor);
		}
		catch (AddressOverflowException e) {
			log.appendMsg("Block " + name + " does not fit in the address space: " +
				e.getMessage());
			return null;
		}
	}

	/** Creates an uninitialized block; skipped (with a log line) if it would conflict. */
	public static MemoryBlock uninitBlock(Program program, String name, long address,
			long length, boolean r, boolean w, boolean x, boolean isVolatile, String comment,
			MessageLog log) {
		if (length <= 0) {
			return null;
		}
		Address start = addr(program, address);
		Address end = start.add(length - 1);
		if (program.getMemory().intersects(start, end)) {
			fillGaps(program, name, address, length, r, w, x, comment, log);
			return null;
		}
		MemoryBlock b = MemoryBlockUtils.createUninitializedBlock(program, false, name, start,
			length, comment, null, r, w, x, log);
		if (b != null && isVolatile) {
			b.setVolatile(true);
		}
		return b;
	}

	/** Creates an uninitialized volatile I/O block. */
	public static MemoryBlock ioBlock(Program program, String name, long address, long length,
			String comment, MessageLog log) {
		return uninitBlock(program, name, address, length, true, true, false, true, comment, log);
	}

	/**
	 * Creates uninitialized blocks for every part of [address, address+length) that no block
	 * already covers.
	 */
	public static void fillGaps(Program program, String name, long address, long length,
			boolean r, boolean w, boolean x, String comment, MessageLog log) {
		if (length <= 0) {
			return;
		}
		Memory memory = program.getMemory();
		Address start = addr(program, address);
		Address end = start.add(length - 1);
		AddressSet gaps = new AddressSet(start, end).subtract(memory);
		int n = 0;
		for (AddressRange range : gaps) {
			String blockName = (n == 0) ? name : name + "_" + n;
			while (memory.getBlock(blockName) != null) {
				blockName = name + "_" + (++n);
			}
			n++;
			MemoryBlockUtils.createUninitializedBlock(program, false, blockName,
				range.getMinAddress(), range.getLength(), comment, null, r, w, x, log);
		}
	}

	/** Places a header copy in the OTHER space (non-loaded) and applies a structure there. */
	public static void headerBlock(Program program, FileBytes fileBytes, long fileOffset,
			DataType struct, String name, MessageLog log) {
		try {
			MemoryBlock block = program.getMemory()
					.createInitializedBlock(name, AddressSpace.OTHER_SPACE.getAddress(0),
						fileBytes, fileOffset, struct.getLength(), true);
			block.setComment(name + " (file offset 0x" + Long.toHexString(fileOffset) + ")");
			createData(program, block.getStart(), struct, log);
		}
		catch (Exception e) {
			log.appendMsg("Could not create " + name + ": " + e.getMessage());
		}
	}

	public static void headerBlock(Program program, byte[] bytes, DataType struct, String name,
			MessageLog log) {
		try {
			MemoryBlock block = program.getMemory()
					.createInitializedBlock(name, AddressSpace.OTHER_SPACE.getAddress(0),
						new ByteArrayInputStream(bytes, 0, struct.getLength()),
						struct.getLength(), TaskMonitor.DUMMY, true);
			block.setComment(name);
			createData(program, block.getStart(), struct, log);
		}
		catch (Exception e) {
			log.appendMsg("Could not create " + name + ": " + e.getMessage());
		}
	}

	public static Data createData(Program program, Address a, DataType dt, MessageLog log) {
		try {
			DataType resolved = program.getDataTypeManager().resolve(dt, null);
			return DataUtilities.createData(program, a, resolved, -1,
				DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		}
		catch (Exception e) {
			log.appendMsg("Could not create " + dt.getName() + " at " + a + ": " +
				e.getMessage());
			return null;
		}
	}

	// ---------------------------------------------------------------- symbols

	public static Symbol label(Program program, long address, String name) {
		return label(program, addr(program, address), name);
	}

	public static Symbol label(Program program, Address a, String name) {
		try {
			Symbol s = program.getSymbolTable().createLabel(a, name, SourceType.IMPORTED);
			s.setPrimary();
			return s;
		}
		catch (Exception e) {
			return null;
		}
	}

	/**
	 * Labels a register (and types it with the given size) if its address is in memory.
	 */
	public static void register(Program program, long address, String name, int size,
			MessageLog log) {
		Address a = addr(program, address);
		if (!program.getMemory().contains(a)) {
			return;
		}
		label(program, a, name);
		DataType dt = switch (size) {
			case 1 -> ByteDataType.dataType;
			case 2 -> WordDataType.dataType;
			case 8 -> QWordDataType.dataType;
			default -> DWordDataType.dataType;
		};
		try {
			DataUtilities.createData(program, a, dt, -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
		}
		catch (Exception e) {
			// overlapping register definitions are labelled only
		}
	}

	/** Labels a table of {address, name, size} entries. */
	public static void registers(Program program, Object[][] table, MessageLog log) {
		for (Object[] row : table) {
			register(program, ((Number) row[0]).longValue(), (String) row[1],
				((Number) row[2]).intValue(), log);
		}
	}

	/** Labels, marks as entry point and creates a function at the address. */
	public static void entry(Program program, long address, String name) {
		Address a = addr(program, address);
		if (!program.getMemory().contains(a)) {
			return;
		}
		label(program, a, name);
		program.getSymbolTable().addExternalEntryPoint(a);
		AbstractProgramLoader.markAsFunction(program, name, a);
	}

	public static void function(Program program, long address, String name) {
		Address a = addr(program, address);
		if (!program.getMemory().contains(a)) {
			return;
		}
		label(program, a, name);
		AbstractProgramLoader.markAsFunction(program, name, a);
	}

	/** Sets a register value (e.g. gp, r13, TMode) over [start, end]. */
	public static void setRegister(Program program, String registerName, long start, long end,
			long value, MessageLog log) {
		Register reg = program.getRegister(registerName);
		if (reg == null) {
			log.appendMsg("Register " + registerName + " not found in language");
			return;
		}
		try {
			program.getProgramContext()
					.setValue(reg, addr(program, start), addr(program, end),
						BigInteger.valueOf(value & 0xFFFFFFFFL));
		}
		catch (Exception e) {
			log.appendMsg("Could not set " + registerName + ": " + e.getMessage());
		}
	}

	public static void info(Program program, String key, String value) {
		Options props = program.getOptions(Program.PROGRAM_INFO);
		props.setString(key, value);
	}

	public static void plate(Program program, long address, String text) {
		Address a = addr(program, address);
		if (program.getMemory().contains(a)) {
			program.getListing().setComment(a, CommentType.PLATE, text);
		}
	}

	public static String hex(long v) {
		return "0x" + Long.toHexString(v & 0xFFFFFFFFL).toUpperCase();
	}

	// ---------------------------------------------------------------- structures

	/**
	 * Builds a structure from {name, type} pairs; a type given as an Integer N is a char[N].
	 */
	public static StructureDataType struct(String name, Object... fields) {
		StructureDataType s = new StructureDataType(name, 0);
		for (int i = 0; i < fields.length; i += 2) {
			String fieldName = (String) fields[i];
			Object t = fields[i + 1];
			DataType dt;
			if (t instanceof Integer n) {
				dt = new ArrayDataType(CharDataType.dataType, n, 1);
			}
			else {
				dt = (DataType) t;
			}
			s.add(dt, dt.getLength(), fieldName, null);
		}
		return s;
	}

	public static DataType u8() {
		return ByteDataType.dataType;
	}

	public static DataType u16() {
		return WordDataType.dataType;
	}

	public static DataType u32() {
		return DWordDataType.dataType;
	}

	public static DataType ptr32() {
		return Pointer32DataType.dataType;
	}

	public static DataType bytes(int n) {
		return new ArrayDataType(ByteDataType.dataType, n, 1);
	}

	public static DataType dwords(int n) {
		return new ArrayDataType(DWordDataType.dataType, n, 4);
	}

	// ---------------------------------------------------------------- byte helpers

	public static int be32(byte[] b, int off) {
		return ((b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16) |
			((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
	}

	public static int be16(byte[] b, int off) {
		return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
	}

	public static int le32(byte[] b, int off) {
		return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8) | ((b[off + 2] & 0xFF) << 16) |
			((b[off + 3] & 0xFF) << 24);
	}

	public static int le16(byte[] b, int off) {
		return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
	}

	public static long u(int v) {
		return v & 0xFFFFFFFFL;
	}

	public static String ascii(byte[] b, int off, int len) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < len && off + i < b.length; i++) {
			int c = b[off + i] & 0xFF;
			if (c == 0) {
				break;
			}
			sb.append(c >= 0x20 && c < 0x7F ? (char) c : '.');
		}
		return sb.toString().trim();
	}

	// ---------------------------------------------------------------- PowerPC relocations

	/** Result codes for {@link #applyPpcRelocation}. */
	public static final int RELOC_OK = 0;
	public static final int RELOC_UNSUPPORTED = 1;
	public static final int RELOC_OVERFLOW = 2;
	public static final int RELOC_NO_MEMORY = 3;

	public static final int R_PPC_NONE = 0;
	public static final int R_PPC_ADDR32 = 1;
	public static final int R_PPC_ADDR24 = 2;
	public static final int R_PPC_ADDR16 = 3;
	public static final int R_PPC_ADDR16_LO = 4;
	public static final int R_PPC_ADDR16_HI = 5;
	public static final int R_PPC_ADDR16_HA = 6;
	public static final int R_PPC_ADDR14 = 7;
	public static final int R_PPC_ADDR14_BRTAKEN = 8;
	public static final int R_PPC_ADDR14_BRNTAKEN = 9;
	public static final int R_PPC_REL24 = 10;
	public static final int R_PPC_REL14 = 11;
	public static final int R_PPC_REL14_BRTAKEN = 12;
	public static final int R_PPC_REL14_BRNTAKEN = 13;
	public static final int R_PPC_REL32 = 26;
	public static final int R_PPC_EMB_SDA21 = 109;
	public static final int R_PPC_GHS_REL16_HA = 251;
	public static final int R_PPC_GHS_REL16_HI = 252;
	public static final int R_PPC_GHS_REL16_LO = 253;

	/**
	 * Applies one PowerPC relocation at {@code where}. {@code value} is S + A (the target
	 * address). Big-endian. Returns one of the RELOC_* codes; nothing is written unless OK.
	 */
	public static int applyPpcRelocation(Program program, Address where, int type, long value) {
		Memory mem = program.getMemory();
		long p = where.getOffset();
		value &= 0xFFFFFFFFL;
		try {
			switch (type) {
				case R_PPC_NONE:
					return RELOC_OK;
				case R_PPC_ADDR32:
					mem.setInt(where, (int) value, true);
					return RELOC_OK;
				case R_PPC_REL32:
					mem.setInt(where, (int) (value - p), true);
					return RELOC_OK;
				case R_PPC_ADDR16:
				case R_PPC_ADDR16_LO:
					mem.setShort(where, (short) value, true);
					return RELOC_OK;
				case R_PPC_ADDR16_HI:
					mem.setShort(where, (short) (value >>> 16), true);
					return RELOC_OK;
				case R_PPC_ADDR16_HA:
					mem.setShort(where, (short) ((value + 0x8000) >>> 16), true);
					return RELOC_OK;
				case R_PPC_GHS_REL16_LO:
					mem.setShort(where, (short) (value - p), true);
					return RELOC_OK;
				case R_PPC_GHS_REL16_HI:
					mem.setShort(where, (short) (((value - p) & 0xFFFFFFFFL) >>> 16), true);
					return RELOC_OK;
				case R_PPC_GHS_REL16_HA:
					mem.setShort(where,
						(short) ((((value - p) & 0xFFFFFFFFL) + 0x8000) >>> 16), true);
					return RELOC_OK;
				case R_PPC_ADDR24: {
					long v = value;
					if (v > 0x01FFFFFFL && v < 0xFE000000L) {
						return RELOC_OVERFLOW;
					}
					int insn = mem.getInt(where, true);
					insn = (insn & 0xFC000003) | ((int) v & 0x03FFFFFC);
					mem.setInt(where, insn, true);
					return RELOC_OK;
				}
				case R_PPC_REL24: {
					long d = (int) (value - p);
					if (d < -0x02000000L || d > 0x01FFFFFFL) {
						return RELOC_OVERFLOW;
					}
					int insn = mem.getInt(where, true);
					insn = (insn & 0xFC000003) | ((int) d & 0x03FFFFFC);
					mem.setInt(where, insn, true);
					return RELOC_OK;
				}
				case R_PPC_ADDR14:
				case R_PPC_ADDR14_BRTAKEN:
				case R_PPC_ADDR14_BRNTAKEN: {
					int insn = mem.getInt(where, true);
					insn = (insn & 0xFFFF0003) | ((int) value & 0xFFFC);
					mem.setInt(where, insn, true);
					return RELOC_OK;
				}
				case R_PPC_REL14:
				case R_PPC_REL14_BRTAKEN:
				case R_PPC_REL14_BRNTAKEN: {
					long d = (int) (value - p);
					if (d < -0x8000L || d > 0x7FFFL) {
						return RELOC_OVERFLOW;
					}
					int insn = mem.getInt(where, true);
					insn = (insn & 0xFFFF0003) | ((int) d & 0xFFFC);
					mem.setInt(where, insn, true);
					return RELOC_OK;
				}
				default:
					return RELOC_UNSUPPORTED;
			}
		}
		catch (MemoryAccessException e) {
			return RELOC_NO_MEMORY;
		}
	}

	/** Records a relocation in the program's relocation table. */
	public static void recordRelocation(Program program, Address where, int type, long value,
			int length, boolean applied, String symbolName) {
		try {
			byte[] orig = new byte[length];
			program.getMemory().getBytes(where, orig);
			program.getRelocationTable()
					.add(where,
						applied ? ghidra.program.model.reloc.Relocation.Status.APPLIED
								: ghidra.program.model.reloc.Relocation.Status.FAILURE,
						type, new long[] { value }, orig, symbolName);
		}
		catch (Exception e) {
			// table entry is informational only
		}
	}

	public static int ppcRelocationLength(int type) {
		return switch (type) {
			case R_PPC_ADDR16, R_PPC_ADDR16_LO, R_PPC_ADDR16_HI, R_PPC_ADDR16_HA,
					R_PPC_GHS_REL16_HA, R_PPC_GHS_REL16_HI, R_PPC_GHS_REL16_LO ->
				2;
			default -> 4;
		};
	}

	// ---------------------------------------------------------------- CRC

	/** CRC-16/MODBUS (poly 0xA001 reflected, init 0xFFFF), as used by the NDS header. */
	public static int crc16(byte[] b, int off, int len) {
		int crc = 0xFFFF;
		for (int i = 0; i < len; i++) {
			crc ^= b[off + i] & 0xFF;
			for (int j = 0; j < 8; j++) {
				crc = (crc & 1) != 0 ? (crc >>> 1) ^ 0xA001 : crc >>> 1;
			}
		}
		return crc & 0xFFFF;
	}
}
