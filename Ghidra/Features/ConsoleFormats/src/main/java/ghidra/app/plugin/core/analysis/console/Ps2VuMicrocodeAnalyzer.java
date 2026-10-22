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
package ghidra.app.plugin.core.analysis.console;

import java.util.List;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Marks PlayStation 2 Vector Unit microcode (VIF MPG packets) in Emotion Engine (R5900)
 * programs: a bookmark and a plate comment at each MPG VIFcode and a label
 * {@code vu_mpg_<micro address>} at its first LIW. Use the Ps2VuExtractMicrocode script to
 * export or import the microprograms with the PS2VU language.
 */
public class Ps2VuMicrocodeAnalyzer extends AbstractAnalyzer {

	public static final String NAME = "PS2 VU Microcode Finder";
	public static final String BOOKMARK_CATEGORY = "PS2 VU Microcode";

	public Ps2VuMicrocodeAnalyzer() {
		super(NAME, "Finds VU0/VU1 microcode uploaded through VIF MPG packets in PlayStation 2 " +
			"EE programs and marks it (bookmark, comment, label).", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return Ps2VuMicrocodeFinder.isR5900(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Ps2VuMicrocodeFinder finder;
		try {
			finder = new Ps2VuMicrocodeFinder(Ps2VuMicrocodeFinder.getVuLanguage(false));
		}
		catch (LanguageNotFoundException e) {
			log.appendMsg(NAME + ": the PS2VU processor module is not installed");
			return false;
		}
		List<Ps2VuMicrocodeFinder.Find> finds = finder.find(program, set, monitor);
		mark(program, finds);
		if (!finds.isEmpty()) {
			log.appendMsg(NAME + ": " + finds.size() + " VIF MPG packet(s) found");
		}
		return true;
	}

	/**
	 * Adds a bookmark, a plate comment and a label for each packet.
	 *
	 * @param program the EE program (open transaction)
	 * @param finds the packets
	 */
	public static void mark(Program program, List<Ps2VuMicrocodeFinder.Find> finds) {
		BookmarkManager bm = program.getBookmarkManager();
		SymbolTable st = program.getSymbolTable();
		Listing listing = program.getListing();
		for (Ps2VuMicrocodeFinder.Find f : finds) {
			String text = String.format("VIF MPG: %d LIWs -> VU micro 0x%04x-0x%04x (%d decode)",
				f.numInstructions, f.microAddress, f.microAddress + f.lengthBytes() - 1,
				f.validInstructions);
			bm.setBookmark(f.vifAddress, BookmarkType.ANALYSIS, BOOKMARK_CATEGORY, text);
			if (listing.getComment(CommentType.PLATE, f.vifAddress) == null) {
				listing.setComment(f.vifAddress, CommentType.PLATE, text +
					(f.callTargets.isEmpty() ? ""
							: "\nMSCAL " + Ps2VuMicrocodeFinder.hexList(f.callTargets)));
			}
			Address code = f.codeAddress;
			String name = String.format("vu_mpg_%04x", f.microAddress);
			try {
				if (st.getSymbol(name, code, null) == null) {
					st.createLabel(code, name, SourceType.ANALYSIS);
				}
			}
			catch (InvalidInputException e) {
				// ignore
			}
		}
	}
}
