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

import java.math.BigInteger;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

/**
 * Small helpers shared by the Nintendo cartridge loaders ({@link SnesLoader},
 * {@link GameBoyLoader}, {@link NesLoader}): memory block creation, labels, entry points,
 * program-information properties and loader option lookup.
 */
public final class NintendoCartUtil {

	private NintendoCartUtil() {
		// utility class
	}

	/**
	 * Creates an initialized, file-backed ROM block (read + execute).
	 */
	public static MemoryBlock romBlock(Program program, FileBytes fileBytes, String name,
			Address start, long fileOffset, long length, boolean overlay, String comment,
			MessageLog log) {
		try {
			MemoryBlock block = program.getMemory()
					.createInitializedBlock(name, start, fileBytes, fileOffset, length, overlay);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
			block.setComment(comment);
			block.setSourceName("cartridge ROM");
			return block;
		}
		catch (Exception e) {
			log.appendMsg("Failed to create ROM block " + name + " at " + start + ": " +
				e.getMessage());
			return null;
		}
	}

	/**
	 * Creates an uninitialized RAM / register block.
	 */
	public static MemoryBlock ramBlock(Program program, String name, Address start, long length,
			boolean overlay, boolean execute, boolean volatil, String comment, MessageLog log) {
		try {
			MemoryBlock block =
				program.getMemory().createUninitializedBlock(name, start, length, overlay);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(execute);
			block.setVolatile(volatil);
			block.setComment(comment);
			block.setSourceName("hardware");
			return block;
		}
		catch (Exception e) {
			log.appendMsg("Failed to create block " + name + " at " + start + ": " +
				e.getMessage());
			return null;
		}
	}

	/**
	 * Creates a byte-mapped block: a second address range that views the same bytes as
	 * {@code source} (a hardware mirror).
	 */
	public static MemoryBlock mirrorBlock(Program program, String name, Address start,
			Address source, long length, boolean write, boolean execute, boolean volatil,
			String comment, MessageLog log) {
		try {
			MemoryBlock block =
				program.getMemory().createByteMappedBlock(name, start, source, length, false);
			block.setRead(true);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(volatil);
			block.setComment(comment);
			block.setSourceName("mirror of " + source);
			return block;
		}
		catch (Exception e) {
			log.appendMsg("Failed to create mirror block " + name + " at " + start + ": " +
				e.getMessage());
			return null;
		}
	}

	/**
	 * Creates a label (imported). Duplicate names at other addresses are allowed for labels.
	 */
	public static Symbol label(Program program, Address addr, String name, String comment,
			boolean primary) {
		if (addr == null || name == null) {
			return null;
		}
		try {
			SymbolTable st = program.getSymbolTable();
			Symbol s = st.createLabel(addr, name, SourceType.IMPORTED);
			if (primary && !s.isPrimary()) {
				s.setPrimary();
			}
			if (comment != null && program.getMemory().contains(addr)) {
				Listing listing = program.getListing();
				if (listing.getComment(CommentType.EOL, addr) == null) {
					listing.setComment(addr, CommentType.EOL, comment);
				}
			}
			return s;
		}
		catch (Exception e) {
			Msg.warn(NintendoCartUtil.class, "Cannot label " + addr + " " + name + ": " + e);
			return null;
		}
	}

	/**
	 * Labels {@code addr}, makes it an external entry point and (if {@code function}) marks it
	 * as a function start so that auto-analysis disassembles it.
	 */
	public static void entry(Program program, Address addr, String name, boolean function) {
		if (addr == null || !program.getMemory().contains(addr)) {
			return;
		}
		label(program, addr, name, null, true);
		program.getSymbolTable().addExternalEntryPoint(addr);
		if (function) {
			ghidra.app.util.opinion.AbstractProgramLoader.markAsFunction(program, name, addr);
		}
	}

	/** Lays down a data type at {@code addr}, ignoring conflicts. */
	public static Data data(Program program, Address addr, DataType dt) {
		try {
			return DataUtilities.createData(program, addr, dt, -1,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
		catch (Exception e) {
			return null;
		}
	}

	/** Adds a primary memory reference from {@code from} to {@code to}. */
	public static void reference(Program program, Address from, Address to, RefType type,
			int opIndex) {
		if (from == null || to == null) {
			return;
		}
		ReferenceManager rm = program.getReferenceManager();
		Reference r = rm.addMemoryReference(from, to, type, SourceType.IMPORTED, opIndex);
		rm.setPrimary(r, true);
	}

	/** Records a string property under Program Information. */
	public static void info(Program program, String key, String value) {
		Options props = program.getOptions(Program.PROGRAM_INFO);
		props.setString(key, value == null ? "" : value);
	}

	/** Sets a (context or ordinary) register value over [{@code start}, {@code end}]. */
	public static void setRegister(Program program, String regName, Address start, Address end,
			long value, MessageLog log) {
		Register reg = program.getRegister(regName);
		if (reg == null) {
			log.appendMsg("Register " + regName + " not found in " + program.getLanguageID());
			return;
		}
		try {
			program.getProgramContext()
					.setValue(reg, start, end, BigInteger.valueOf(value));
		}
		catch (Exception e) {
			log.appendMsg("Cannot set " + regName + " at " + start + ": " + e.getMessage());
		}
	}

	/** Returns the value of a String option, or {@code dflt}. */
	public static String stringOption(List<Option> options, String name, String dflt) {
		if (options != null) {
			for (Option o : options) {
				if (o.getName().equals(name) && o.getValue() != null) {
					return o.getValue().toString().trim();
				}
			}
		}
		return dflt;
	}

	/** Returns the value of a Boolean option, or {@code dflt}. */
	public static boolean boolOption(List<Option> options, String name, boolean dflt) {
		if (options != null) {
			for (Option o : options) {
				if (o.getName().equals(name) && o.getValue() instanceof Boolean b) {
					return b;
				}
			}
		}
		return dflt;
	}

	/** Checks that a String option is one of {@code allowed} (case-insensitive). */
	public static String checkChoice(List<Option> options, String name, String... allowed) {
		String v = stringOption(options, name, null);
		if (v == null) {
			return null;
		}
		for (String a : allowed) {
			if (a.equalsIgnoreCase(v)) {
				return null;
			}
		}
		return "Invalid value '" + v + "' for option '" + name + "' (allowed: " +
			String.join(", ", allowed) + ")";
	}

	/** True if the language can be found in the installation. */
	public static boolean languageExists(LanguageService service, String languageId) {
		try {
			service.getLanguageDescription(new LanguageID(languageId));
			return true;
		}
		catch (LanguageNotFoundException e) {
			return false;
		}
	}

	/** Returns the address space of an overlay block, or null. */
	public static AddressSpace blockSpace(Program program, String blockName) {
		MemoryBlock b = program.getMemory().getBlock(blockName);
		return b == null ? null : b.getStart().getAddressSpace();
	}

	/** Two-digit (or wider) uppercase hex. */
	public static String hex(long v, int digits) {
		return String.format("%0" + digits + "X", v);
	}

	/** Printable ASCII, trimmed (non-printables replaced by '.'). */
	public static String ascii(byte[] b, int off, int len) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < len && off + i < b.length; i++) {
			int c = b[off + i] & 0xFF;
			if (c == 0) {
				sb.append(' ');
			}
			else if (c >= 0x20 && c < 0x7F) {
				sb.append((char) c);
			}
			else {
				sb.append('.');
			}
		}
		return sb.toString().trim();
	}
}
