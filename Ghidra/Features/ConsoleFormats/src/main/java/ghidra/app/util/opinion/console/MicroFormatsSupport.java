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

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Shared helpers for the Xbox (XBE, XEX2) and home-computer (C64 PRG, Atari XEX, MSX ROM,
 * ColecoVision) loaders: block placement with automatic overlays, labels, external routines at
 * fixed ROM addresses, and program-information properties.
 */
public final class MicroFormatsSupport {

	private MicroFormatsSupport() {
		// utility class
	}

	/** {@return the lower-case extension of the provider's file name, or "" if none} */
	public static String extension(ByteProvider provider) {
		String name = provider.getName();
		if (name == null && provider.getFSRL() != null) {
			name = provider.getFSRL().getName();
		}
		if (name == null) {
			return "";
		}
		int dot = name.lastIndexOf('.');
		return dot < 0 ? "" : name.substring(dot + 1).toLowerCase(Locale.ROOT);
	}

	public static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	public static Address addr(AddressSpace space, long offset) {
		return space.getAddress(offset);
	}

	/** {@return true if any byte of [start, start+length) is already in memory} */
	public static boolean overlaps(Program program, Address start, long length) {
		Address end = start.add(length - 1);
		return program.getMemory().intersects(start, end);
	}

	/** Builds a unique block name (also unique as an overlay space name when it is one). */
	public static String uniqueBlockName(Program program, String name, boolean overlay) {
		String candidate = name;
		int n = 1;
		while (program.getMemory().getBlock(candidate) != null ||
			(overlay && program.getAddressFactory().getAddressSpace(candidate) != null)) {
			candidate = name + "_" + (n++);
		}
		return candidate;
	}

	/**
	 * Creates an initialized block from file bytes. If {@code overlay} is null, the block becomes
	 * an overlay only when its range is already (partly) mapped.
	 */
	public static MemoryBlock fileBlock(Program program, String name, Address start,
			FileBytes fileBytes, long offset, long length, Boolean overlay, boolean r, boolean w,
			boolean x, String comment, MessageLog log) {
		if (length <= 0) {
			return null;
		}
		boolean ov = overlay != null ? overlay : overlaps(program, start, length);
		try {
			return MemoryBlockUtils.createInitializedBlock(program, ov,
				uniqueBlockName(program, name, ov), start, fileBytes, offset, length, comment, null,
				r, w, x, log);
		}
		catch (AddressOverflowException e) {
			log.appendMsg("Block " + name + " does not fit at " + start + ": " + e.getMessage());
			return null;
		}
	}

	/** Creates an initialized block from a byte array slice (decrypted/decompressed data). */
	public static MemoryBlock bytesBlock(Program program, String name, Address start, byte[] data,
			int offset, int length, Boolean overlay, boolean r, boolean w, boolean x,
			String comment, MessageLog log, TaskMonitor monitor) {
		if (length <= 0) {
			return null;
		}
		boolean ov = overlay != null ? overlay : overlaps(program, start, length);
		try {
			return MemoryBlockUtils.createInitializedBlock(program, ov,
				uniqueBlockName(program, name, ov), start,
				new ByteArrayInputStream(data, offset, length), length, comment, null, r, w, x, log,
				monitor);
		}
		catch (AddressOverflowException e) {
			log.appendMsg("Block " + name + " does not fit at " + start + ": " + e.getMessage());
			return null;
		}
	}

	public static MemoryBlock uninitBlock(Program program, String name, Address start, long length,
			boolean overlay, boolean r, boolean w, boolean x, boolean isVolatile, String comment,
			MessageLog log) {
		if (length <= 0) {
			return null;
		}
		MemoryBlock b = MemoryBlockUtils.createUninitializedBlock(program, overlay,
			uniqueBlockName(program, name, overlay), start, length, comment, null, r, w, x, log);
		if (b != null && isVolatile) {
			b.setVolatile(true);
		}
		return b;
	}

	/**
	 * Creates uninitialized blocks covering only the parts of [start, end] (inclusive) of the
	 * given space that are not mapped yet. Several pieces get suffixes _1, _2 ...
	 */
	public static void fillGaps(Program program, AddressSpace space, String name, long start,
			long end, boolean r, boolean w, boolean x, boolean isVolatile, String comment,
			MessageLog log) {
		AddressSet want = new AddressSet(space.getAddress(start), space.getAddress(end));
		AddressSetView have = program.getMemory();
		AddressSet gaps = want.subtract(new AddressSet(have));
		for (AddressRange range : gaps) {
			uninitBlock(program, name, range.getMinAddress(), range.getLength(), false, r, w, x,
				isVolatile, comment, log);
		}
	}

	/** Creates a label (IMPORTED); memory need not exist at the address. */
	public static Symbol label(Program program, Address address, String name, boolean primary,
			MessageLog log) {
		try {
			SymbolTable st = program.getSymbolTable();
			Symbol s = st.createLabel(address, name, SourceType.IMPORTED);
			if (primary && s != null && !s.isPrimary()) {
				s.setPrimary();
			}
			return s;
		}
		catch (Exception e) {
			log.appendMsg("Cannot label " + address + " " + name + ": " + e.getMessage());
			return null;
		}
	}

	/** Labels consecutive byte registers: names[i] at base+i (null entries skipped). */
	public static void labelRegisters(Program program, AddressSpace space, long base,
			String[] names, MessageLog log) {
		for (int i = 0; i < names.length; i++) {
			if (names[i] != null) {
				label(program, space.getAddress(base + i), names[i], true, log);
			}
		}
	}

	/** Labels a {@code {address, name}} table. */
	public static void labelTable(Program program, AddressSpace space, Object[][] table,
			MessageLog log) {
		for (Object[] row : table) {
			label(program, space.getAddress(((Number) row[0]).longValue()), (String) row[1], true,
				log);
		}
	}

	/**
	 * Declares a ROM routine at a fixed address as an external: an external function
	 * {@code library::name} and a one-byte thunk function at the address, so calls to it read as
	 * {@code name()} in the decompiler even though the ROM itself is not loaded.
	 */
	public static Function externalRoutine(Program program, String library, String name,
			Address address, MessageLog log) {
		try {
			ExternalLocation loc = program.getExternalManager()
					.addExtFunction(library, name, null, SourceType.IMPORTED);
			Function ext = loc.getFunction();
			FunctionManager fm = program.getFunctionManager();
			Function f = fm.getFunctionAt(address);
			if (f == null) {
				f = fm.createThunkFunction(null, null, address, new AddressSet(address), ext,
					SourceType.IMPORTED);
			}
			label(program, address, name, true, log);
			return f;
		}
		catch (Exception e) {
			log.appendMsg("Cannot declare external " + library + "::" + name + " at " + address +
				": " + e.getMessage());
			return null;
		}
	}

	/** Adds an entry point and a one-byte function (the analyzers grow it) with a name. */
	public static void entry(Program program, Address address, String name, MessageLog log) {
		program.getSymbolTable().addExternalEntryPoint(address);
		FunctionManager fm = program.getFunctionManager();
		try {
			Function f = fm.getFunctionAt(address);
			if (f == null) {
				f = fm.createFunction(name, address, new AddressSet(address),
					SourceType.IMPORTED);
			}
			else if (name != null && f.getSymbol().getSource() == SourceType.DEFAULT) {
				f.setName(name, SourceType.IMPORTED);
			}
		}
		catch (Exception e) {
			if (name != null) {
				label(program, address, name, true, log);
			}
		}
	}

	/** Records a header field in Program Information (Help > About program / properties). */
	public static void property(Program program, String key, String value) {
		Options info = program.getOptions(Program.PROGRAM_INFO);
		info.setString(key, value);
	}

	public static String hex(long v, int digits) {
		return String.format("0x%0" + digits + "X", v);
	}

	public static int u16le(byte[] b, int off) {
		return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
	}

	public static long u32le(byte[] b, int off) {
		return (b[off] & 0xffL) | ((b[off + 1] & 0xffL) << 8) | ((b[off + 2] & 0xffL) << 16) |
			((b[off + 3] & 0xffL) << 24);
	}

	public static int u16be(byte[] b, int off) {
		return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
	}

	public static long u32be(byte[] b, int off) {
		return ((b[off] & 0xffL) << 24) | ((b[off + 1] & 0xffL) << 16) |
			((b[off + 2] & 0xffL) << 8) | (b[off + 3] & 0xffL);
	}

	/**
	 * Reads an export-names file: lines {@code <library> <ordinal> <name>} (ordinal decimal or
	 * 0x-hex, '#' starts a comment). Returns library (lower case) -> ordinal -> name.
	 */
	public static Map<String, Map<Integer, String>> readExportNames(String path, MessageLog log) {
		Map<String, Map<Integer, String>> result = new HashMap<>();
		if (path == null || path.isBlank()) {
			return result;
		}
		File f = new File(path.trim());
		if (!f.isFile()) {
			log.appendMsg("Export names file not found: " + f);
			return result;
		}
		try {
			for (String line : Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
				int hash = line.indexOf('#');
				if (hash >= 0) {
					line = line.substring(0, hash);
				}
				String[] parts = line.trim().split("[\\s,;]+");
				if (parts.length < 3) {
					continue;
				}
				try {
					int ord = parts[1].toLowerCase(Locale.ROOT).startsWith("0x")
							? Integer.parseInt(parts[1].substring(2), 16)
							: Integer.parseInt(parts[1]);
					result.computeIfAbsent(parts[0].toLowerCase(Locale.ROOT), k -> new HashMap<>())
							.put(ord, parts[2]);
				}
				catch (NumberFormatException e) {
					// skip the line
				}
			}
		}
		catch (IOException e) {
			log.appendMsg("Cannot read export names file " + f + ": " + e.getMessage());
		}
		return result;
	}
}
