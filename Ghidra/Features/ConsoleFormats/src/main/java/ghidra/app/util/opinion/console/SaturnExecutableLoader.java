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
 * A headerless Saturn executable (the "1st read" file, or any program file) loaded at a
 * user-given address with the Saturn memory map. Opt-in only: the file has no signature, so the
 * loader offers a <b>non-preferred</b> load spec for every file up to 1 MB and sorts after the
 * Raw Binary loader; it is never chosen automatically. Select it with
 * {@code -loader SaturnExecutableLoader -processor SuperH:BE:32:SH-2}
 * in headless mode, or from the Format list of the import dialog. Option
 * {@code -loader-loadAddress 0x06004000}.
 */
public class SaturnExecutableLoader extends SegaLoaderBase {

	public static final String NAME = "Sega Saturn executable (opt-in, headerless)";
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
		if (len == 0 || len > 0x100000) {
			return List.of();
		}
		return spec(this, SaturnLoader.LANGUAGE, false);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(hexOpt(OPT_ADDRESS, 0x06004000L, "loadAddress"));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String err = validateOwn(options, Map.of(OPT_ADDRESS, HexLong.class));
		if (err != null) {
			return err;
		}
		long a = hexOption(options, OPT_ADDRESS, 0x06004000L);
		if ((a & 1) != 0 || a < 0 || a + provider.length() > 0x100000000L) {
			return OPT_ADDRESS + ": must be even and leave room for the file";
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		long at = hexOption(settings.options(), OPT_ADDRESS, 0x06004000L);
		FileBytes fb = program.getMemory()
				.createFileBytes(provider.getName(), 0, provider.length(),
					provider.getInputStream(0), monitor);
		romBlock(program, "PROGRAM", at, fb, 0, provider.length(), false, true,
			"Headerless Saturn executable loaded at " + hex(at), log);
		entry(program, addr(program, at), "start");
		SaturnLoader.mapHardware(program, log);
		info(program, "Format", "Saturn executable (headerless)");
		info(program, "Load address", hex(at));
	}
}
