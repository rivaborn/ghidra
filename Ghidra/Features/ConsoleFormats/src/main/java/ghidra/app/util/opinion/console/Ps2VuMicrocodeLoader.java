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

import ghidra.app.plugin.processors.generic.MemoryBlockDefinition;
import ghidra.app.util.HexLong;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Loads PlayStation 2 Vector Unit microcode (VU0/VU1 micro mode) with the PS2VU language.
 * <p>
 * The input is raw microcode (64-bit LIWs, as extracted by the Ps2VuExtractMicrocode script),
 * or any file with microcode at some offset (for example an EE ELF, using the offset and length
 * that the Ps2VuFindMicrocode script reports). When the bytes at the offset start with a VIF
 * {@code MPG} code, its load address and LIW count are used (option "Use VIF MPG Header").
 * <p>
 * The unit is chosen by the language: {@code PS2VU:LE:32:VU1} (16 KB micro / 16 KB data memory)
 * or {@code PS2VU:LE:32:VU0} (4 KB / 4 KB). The program gets the whole micro memory as block
 * "micro" (zero-filled outside the loaded range) and the data memory as the uninitialized
 * block "vumem" (from the processor spec). Entry points: the load address, the MSCAL targets
 * passed in by the script, and (option) every LIW following an E-bit LIW and its delay slot.
 * <p>
 * Load specs are offered for every file (not preferred) so that the loader can be chosen for
 * any input; they are preferred only for the extensions .vu, .vu0, .vu1 and .vubin.
 */
public class Ps2VuMicrocodeLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "PS2 VU Microcode";

	public static final String OPTION_FILE_OFFSET = "File Offset";
	public static final String OPTION_LENGTH = "Length";
	public static final String OPTION_MICRO_ADDRESS = "Micro Memory Address";
	public static final String OPTION_VIF_HEADER = "Use VIF MPG Header";
	public static final String OPTION_EBIT_ENTRIES = "Entry Points After E Bit";

	private static final String VU1 = "PS2VU:LE:32:VU1";
	private static final String VU0 = "PS2VU:LE:32:VU0";
	private static final int VIF_MPG = 0x4A;

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.UNTARGETED_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < 8) {
			return specs;
		}
		String name = provider.getName() == null ? "" : provider.getName().toLowerCase();
		boolean vu0Ext = name.endsWith(".vu0");
		boolean vuExt = vu0Ext || name.endsWith(".vu1") || name.endsWith(".vu") ||
			name.endsWith(".vubin");
		LanguageService ls = DefaultLanguageService.getLanguageService();
		for (String id : new String[] { VU1, VU0 }) {
			try {
				Language lang = ls.getLanguage(new LanguageID(id));
				boolean preferred = vuExt && (vu0Ext == id.equals(VU0));
				specs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(lang.getLanguageID(),
					lang.getDefaultCompilerSpec().getCompilerSpecID()), preferred));
			}
			catch (LanguageNotFoundException e) {
				// PS2VU processor module not installed
			}
		}
		return specs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(new Option(OPTION_FILE_OFFSET, new HexLong(0), HexLong.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-fileOffset"));
		list.add(new Option(OPTION_LENGTH, new HexLong(0), HexLong.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-length"));
		list.add(new Option(OPTION_MICRO_ADDRESS, new HexLong(0), HexLong.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-microAddress"));
		list.add(new Option(OPTION_VIF_HEADER, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-vifHeader"));
		list.add(new Option(OPTION_EBIT_ENTRIES, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-eBitEntries"));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		long fileLength = provider.length();
		long offset = longOption(options, OPTION_FILE_OFFSET, 0);
		long length = longOption(options, OPTION_LENGTH, 0);
		long micro = longOption(options, OPTION_MICRO_ADDRESS, 0);
		int size = microSize(loadSpec.getLanguageCompilerSpec().languageID.getIdAsString());
		if (offset < 0 || offset >= fileLength) {
			return OPTION_FILE_OFFSET + " must be within the file (0.." + (fileLength - 1) + ")";
		}
		if (length < 0 || offset + length > fileLength) {
			return OPTION_LENGTH + " goes past the end of the file";
		}
		if (micro < 0 || micro >= size || (micro & 7) != 0) {
			return OPTION_MICRO_ADDRESS +
				String.format(" must be a multiple of 8 below 0x%x", size);
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		List<Option> options = settings.options();
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		long offset = longOption(options, OPTION_FILE_OFFSET, 0);
		long length = longOption(options, OPTION_LENGTH, 0);
		int micro = (int) longOption(options, OPTION_MICRO_ADDRESS, 0);
		boolean vifHeader = boolOption(options, OPTION_VIF_HEADER, true);
		boolean eBitEntries = boolOption(options, OPTION_EBIT_ENTRIES, true);

		if (vifHeader && offset + 4 <= provider.length()) {
			byte[] w = provider.readBytes(offset, 4);
			int code = (w[0] & 0xFF) | (w[1] & 0xFF) << 8 | (w[2] & 0xFF) << 16 |
				(w[3] & 0xFF) << 24;
			if (((code >>> 24) & 0x7F) == VIF_MPG) {
				int num = (code >>> 16) & 0xFF;
				num = num == 0 ? 256 : num;
				micro = (code & 0xFFFF) * 8;
				offset += 4;
				length = Math.min((long) num * 8, provider.length() - offset);
				log.appendMsg(String.format(
					"VIF MPG header: %d LIWs loaded at micro address 0x%x", num, micro));
			}
		}
		if (length == 0) {
			length = provider.length() - offset;
		}
		int size = microSize(program.getLanguageID().getIdAsString());
		if (length > size) {
			log.appendMsg(String.format("Microcode clipped to the micro memory size 0x%x", size));
			length = size;
		}
		length &= ~7L;
		byte[] code = provider.readBytes(offset, length);
		populate(program, code, micro % size, List.of(), eBitEntries, log, settings.monitor());
	}

	/**
	 * Fills a PS2VU program: the micro memory block with the microcode at its load address,
	 * and the entry points. (The data memory block comes from the processor spec.)
	 *
	 * @param program a program with a PS2VU language (open transaction)
	 * @param code the microcode (LIWs)
	 * @param microAddress load address in micro memory (bytes, multiple of 8)
	 * @param callTargets additional entry points (micro addresses in bytes), e.g. MSCAL targets
	 * @param eBitEntries true to add an entry point after each E bit LIW and its delay slot
	 * @param log message log
	 * @param monitor task monitor
	 * @throws CancelledException if cancelled
	 * @throws IOException if a memory block cannot be created
	 */
	public static void populate(Program program, byte[] code, int microAddress,
			List<Integer> callTargets, boolean eBitEntries, MessageLog log, TaskMonitor monitor)
			throws CancelledException, IOException {
		int size = microSize(program.getLanguageID().getIdAsString());
		byte[] image = new byte[size];
		for (int i = 0; i < code.length && i < size; i++) {
			image[(microAddress + i) % size] = code[i]; // MPG loads wrap around micro memory
		}
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();
		try {
			MemoryBlock block = memory.createInitializedBlock("micro", space.getAddress(0),
				new ByteArrayInputStream(image), size, monitor, false);
			block.setPermissions(true, true, true);
			block.setComment(String.format("VU micro memory; 0x%x bytes loaded at 0x%x",
				code.length, microAddress));

			SymbolTable st = program.getSymbolTable();
			Set<Integer> entries = new TreeSet<>();
			entries.add(microAddress);
			entries.addAll(callTargets);
			if (eBitEntries) {
				for (int i = 0; i + 8 <= code.length; i += 8) {
					if ((code[i + 7] & 0x40) != 0 && i + 16 < code.length) { // upper bit 30 = E
						entries.add((microAddress + i + 16) % size);
					}
				}
			}
			for (int e : entries) {
				Address a = space.getAddress(e % size);
				String name = (e == microAddress) ? "vu_start" : String.format("vu_prog_%04x", e);
				st.createLabel(a, name, SourceType.IMPORTED);
				st.addExternalEntryPoint(a);
				AbstractProgramLoader.markAsFunction(program, name, a);
			}
		}
		catch (LockException | MemoryConflictException | AddressOverflowException
				| InvalidInputException e) {
			throw new IOException("Cannot create the VU memory: " + e.getMessage(), e);
		}
	}

	/**
	 * Creates a new PS2VU program with the given microcode (used by the extraction script to
	 * import microprograms found in an EE program). The caller saves and releases it.
	 *
	 * @param name program name
	 * @param vu0 true for VU0, false for VU1
	 * @param code microcode
	 * @param microAddress load address (bytes)
	 * @param callTargets extra entry points (micro addresses in bytes)
	 * @param consumer consumer of the new program
	 * @param log message log
	 * @param monitor task monitor
	 * @return the program
	 * @throws Exception if the language is missing or the program cannot be built
	 */
	public static Program createProgram(String name, boolean vu0, byte[] code, int microAddress,
			List<Integer> callTargets, Object consumer, MessageLog log, TaskMonitor monitor)
			throws Exception {
		Language lang =
			DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(vu0 ? VU0 : VU1));
		Program p = new ProgramDB(name, lang, lang.getDefaultCompilerSpec(), consumer);
		boolean ok = false;
		int tx = p.startTransaction("Load VU microcode");
		try {
			p.setExecutableFormat(NAME);
			createDataMemory(p, log);
			populate(p, code, microAddress, callTargets, true, log, monitor);
			ok = true;
		}
		finally {
			p.endTransaction(tx, ok);
			if (!ok) {
				p.release(consumer);
			}
		}
		return p;
	}

	private static void createDataMemory(Program program, MessageLog log)
			throws LockException, MemoryConflictException, AddressOverflowException {
		Language lang = program.getLanguage();
		for (MemoryBlockDefinition def : lang.getDefaultMemoryBlocks()) {
			if (program.getMemory().getBlock(def.getBlockName()) != null) {
				continue;
			}
			try {
				def.createBlock(program);
			}
			catch (InvalidAddressException e) {
				log.appendMsg("Cannot create " + def.getBlockName() + ": " + e.getMessage());
			}
		}
	}

	/** {@return the micro memory size of a PS2VU language} */
	public static int microSize(String languageId) {
		return VU0.equals(languageId) ? 0x1000 : 0x4000;
	}

	private static long longOption(List<Option> options, String name, long dflt) {
		if (options != null) {
			for (Option o : options) {
				if (o.getName().equals(name) && o.getValue() != null) {
					Object v = o.getValue();
					if (v instanceof Number n) {
						return n.longValue();
					}
					String s = v.toString().trim().toLowerCase();
					return s.startsWith("0x") ? Long.parseLong(s.substring(2), 16)
							: Long.parseLong(s, 16);
				}
			}
		}
		return dflt;
	}

	private static boolean boolOption(List<Option> options, String name, boolean dflt) {
		if (options != null) {
			for (Option o : options) {
				if (o.getName().equals(name) && o.getValue() instanceof Boolean b) {
					return b;
				}
			}
		}
		return dflt;
	}
}
