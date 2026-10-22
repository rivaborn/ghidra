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

import java.io.IOException;
import java.util.*;

import ghidra.app.util.HexLong;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A Dreamcast boot executable ({@code 1ST_READ.BIN}, plain or MIL-CD scrambled), loaded at a
 * user-given address (default 0x8C010000) with the Dreamcast memory map. Opt-in only: the file
 * has no signature, so the loader offers a <b>non-preferred</b> load spec for every file up to
 * 16 MB and sorts after the Raw Binary loader; it is never chosen automatically. Select it with
 * {@code -loader DreamcastExecutableLoader -processor SuperH4:LE:32:default} in headless mode
 * (the processor is required: the spec is not preferred), or from the Format list of the import dialog.
 * Options: {@code -loader-loadAddress 0x8C010000}, {@code -loader-descramble auto|yes|no}.
 */
public class DreamcastExecutableLoader extends SegaLoaderBase {

	public static final String NAME = "Sega Dreamcast 1ST_READ.BIN (opt-in, headerless)";
	static final String OPT_ADDRESS = "Load address";

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
		return 101; // after BinaryLoader
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		long len = provider.length();
		if (len == 0 || len > 0x1000000) {
			return List.of();
		}
		return spec(this, DreamcastLoader.LANGUAGE, false);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(hexOpt(OPT_ADDRESS, DreamcastLoader.FIRST_READ_ADDRESS, "loadAddress"));
		list.add(stringOpt(DreamcastLoader.OPT_DESCRAMBLE, "auto", "descramble"));
		list.add(boolOpt(DreamcastLoader.OPT_MIRRORS, false, "ramMirrors"));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String err = validateOwn(options, Map.of(OPT_ADDRESS, HexLong.class,
			DreamcastLoader.OPT_DESCRAMBLE, String.class, DreamcastLoader.OPT_MIRRORS,
			Boolean.class));
		if (err == null) {
			err = DreamcastLoader.checkDescramble(options);
		}
		long a = hexOption(options, OPT_ADDRESS, DreamcastLoader.FIRST_READ_ADDRESS);
		if (err == null && ((a & 1) != 0 || a < 0 || a + provider.length() > 0x100000000L)) {
			err = OPT_ADDRESS + ": must be even and leave room for the file";
		}
		return err != null ? err : super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();
		long at = hexOption(options, OPT_ADDRESS, DreamcastLoader.FIRST_READ_ADDRESS);

		byte[] stored = provider.readBytes(0, provider.length());
		byte[] image = DreamcastLoader.bootImage(program, stored, options);
		FileBytes fb = image == stored
				? program.getMemory()
						.createFileBytes(provider.getName(), 0, stored.length,
							provider.getInputStream(0), monitor)
				: fileBytes(program, provider.getName() + " (descrambled)", image, monitor);
		romBlock(program, "PROGRAM", at, fb, 0, image.length, false, true,
			"Dreamcast boot executable loaded at " + hex(at) +
				(image == stored ? "" : " (descrambled)"),
			log);
		entry(program, addr(program, at), "start");
		DreamcastLoader.mapHardware(program, boolOption(options, DreamcastLoader.OPT_MIRRORS,
			false), log);
		info(program, "Format", "Dreamcast boot executable (headerless)");
		info(program, "Load address", hex(at));
	}
}
