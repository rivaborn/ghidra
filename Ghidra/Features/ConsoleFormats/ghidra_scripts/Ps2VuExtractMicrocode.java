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
// Extracts the PlayStation 2 VU microprograms (VIF MPG packets, back-to-back packets merged)
// found in the current EE program. Each microprogram is
//   - written to <dir>/<program>_<EE address>_m<micro address>.vu1 (raw LIWs; .vu0 for VU0),
//     loadable with the "PS2 VU Microcode" loader (Micro Memory Address = the m value);
//   - and/or imported into the current project, next to the EE program, as a PS2VU program
//     named "<program>_vu1_<EE address>", analyzed and saved.
// Arguments (headless: after the script name, as key=value or key value; GUI: asked for):
//   dir=<folder>   output folder for the files (default: none, no files)
//   import=true|false   import into the project (default true)
//   unit=vu1|vu0   language (default vu1; VU0 microcode is rarer and at most 4 KB)
//@category PS2
import java.io.File;
import java.nio.file.Files;
import java.util.List;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.console.Ps2VuMicrocodeFinder;
import ghidra.app.plugin.core.analysis.console.Ps2VuMicrocodeFinder.Group;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.console.Ps2VuMicrocodeLoader;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;

public class Ps2VuExtractMicrocode extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String dir = null;
		boolean doImport = true;
		boolean vu0 = false;
		String[] args = getScriptArgs();
		if (args.length == 0 && !isRunningHeadless()) {
			File d = askDirectory("Folder for the extracted microcode (cancel: none)", "Choose");
			dir = d == null ? null : d.getAbsolutePath();
			doImport = askYesNo("PS2 VU microcode", "Import the microprograms into the project?");
		}
		// key=value; also "key value", because analyzeHeadless.bat splits arguments at '='
		for (int i = 0; i < args.length; i++) {
			String key = args[i];
			String value;
			int eq = key.indexOf('=');
			if (eq > 0) {
				value = key.substring(eq + 1);
				key = key.substring(0, eq);
			}
			else if (i + 1 < args.length) {
				value = args[++i];
			}
			else {
				printerr("missing value for " + key);
				break;
			}
			switch (key.toLowerCase()) {
				case "dir" -> dir = value;
				case "import" -> doImport = Boolean.parseBoolean(value);
				case "unit" -> vu0 = value.equalsIgnoreCase("vu0");
				default -> printerr("unknown argument " + key);
			}
		}
		String unit = vu0 ? "vu0" : "vu1";
		Ps2VuMicrocodeFinder finder =
			new Ps2VuMicrocodeFinder(Ps2VuMicrocodeFinder.getVuLanguage(vu0));
		List<Group> groups = Ps2VuMicrocodeFinder.group(finder.find(currentProgram, null, monitor));
		println(groups.size() + " microprogram(s) in " + currentProgram.getName());
		// next to the EE program; during a headless import it is not saved yet: project root
		DomainFolder folder = currentProgram.getDomainFile().getParent();
		if (folder == null && state.getProject() != null) {
			folder = state.getProject().getProjectData().getRootFolder();
		}
		if (doImport && folder == null) {
			printerr("No project folder: the microprograms are not imported");
		}
		for (Group g : groups) {
			monitor.checkCancelled();
			byte[] code = Ps2VuMicrocodeFinder.readCode(currentProgram, g);
			String ee = String.format("%08x", g.first().vifAddress.getOffset());
			println("  " + g);
			if (dir != null) {
				File f = new File(dir, String.format("%s_%s_m%04x.%s",
					currentProgram.getName().replaceAll("[^A-Za-z0-9_.-]", "_"), ee,
					g.microAddress(), unit));
				f.getParentFile().mkdirs();
				Files.write(f.toPath(), code);
				println("    wrote " + f.getAbsolutePath());
			}
			if (doImport && folder != null) {
				String name = currentProgram.getName() + "_" + unit + "_" + ee;
				if (folder.getFile(name) != null) {
					println("    " + name + " already exists in the project, skipped");
					continue;
				}
				MessageLog log = new MessageLog();
				Program p = Ps2VuMicrocodeLoader.createProgram(name, vu0, code, g.microAddress(),
					g.callTargets(), this, log, monitor);
				try {
					AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(p);
					int tx = p.startTransaction("Analyze");
					try {
						mgr.initializeOptions();
						mgr.reAnalyzeAll(null);
						mgr.startAnalysis(monitor);
					}
					finally {
						p.endTransaction(tx, true);
					}
					folder.createFile(name, p, monitor);
					println(String.format("    imported %s (%d functions)",
						folder.getFile(name).getPathname(), p.getFunctionManager().getFunctionCount()));
				}
				finally {
					p.release(this);
				}
			}
		}
	}
}
