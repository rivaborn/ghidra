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
// Lists the PlayStation 2 VU microcode (VIF MPG packets) found in the current EE program:
// EE address of each MPG VIFcode, file offset, micro-memory address and length, decode ratio,
// surrounding VIFcodes and MSCAL targets, then the packets grouped into microprograms.
// Also lists memory blocks whose name suggests VU content (.vutext, .vudata, DVP sections).
// Optional script argument: "mark" to add the bookmarks/labels of the PS2 VU Microcode Finder
// analyzer.
//@category PS2
import java.util.List;

import ghidra.app.plugin.core.analysis.console.Ps2VuMicrocodeAnalyzer;
import ghidra.app.plugin.core.analysis.console.Ps2VuMicrocodeFinder;
import ghidra.app.plugin.core.analysis.console.Ps2VuMicrocodeFinder.Find;
import ghidra.app.plugin.core.analysis.console.Ps2VuMicrocodeFinder.Group;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;

public class Ps2VuFindMicrocode extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Ps2VuMicrocodeFinder finder =
			new Ps2VuMicrocodeFinder(Ps2VuMicrocodeFinder.getVuLanguage(false));
		List<Find> finds = finder.find(currentProgram, null, monitor);
		println(String.format("%d VIF MPG packet(s) in %s", finds.size(), currentProgram.getName()));
		println("  VIF code    file off   micro range      LIWs  decode  E  context");
		for (Find f : finds) {
			println(String.format("  %s  %8s   0x%04x-0x%04x  %4d  %3d%%   %d  %s | %s%s",
				f.vifAddress, fileOffset(f), f.microAddress, f.microAddress + f.lengthBytes() - 1,
				f.numInstructions, Math.round(f.score() * 100), f.endInstructions,
				String.join(" ", f.before), String.join(" ", f.after),
				f.callTargets.isEmpty() ? ""
						: "  MSCAL " + String.join(",",
							f.callTargets.stream().map(t -> String.format("0x%x", t)).toList())));
		}
		for (Group g : Ps2VuMicrocodeFinder.group(finds)) {
			println("  " + g);
		}
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			String n = b.getName().toLowerCase();
			if (n.contains("vu") || n.contains("dvp")) {
				println(String.format("  section %s %s-%s (%d bytes) may hold VU code/data",
					b.getName(), b.getStart(), b.getEnd(), b.getSize()));
			}
		}
		for (String a : getScriptArgs()) {
			if (a.equalsIgnoreCase("mark")) {
				Ps2VuMicrocodeAnalyzer.mark(currentProgram, finds);
				println("  marked " + finds.size() + " packet(s)");
			}
		}
	}

	private String fileOffset(Find f) {
		MemoryBlock b = currentProgram.getMemory().getBlock(f.vifAddress);
		if (b == null) {
			return "-";
		}
		for (MemoryBlockSourceInfo si : b.getSourceInfos()) {
			if (si.contains(f.vifAddress) && si.getFileBytes().isPresent()) {
				return String.format("0x%x", si.getFileBytesOffset(f.vifAddress) +
					si.getFileBytes().get().getFileOffset());
			}
		}
		return "-";
	}
}
