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

import java.math.BigInteger;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Propagates the 65816 M/X/E state (the {@code mflag}, {@code xflag} and {@code emode} context
 * bits of the 65816 language) from call sites into routines.
 * <p>
 * The disassembler carries the caller's context into a JSR/JSL/JMP/JML target only the first time
 * it reaches it: whichever flow arrives first decides how the routine is decoded. This analyzer
 * looks at every routine entry reached by a direct JSR, JSL, JMP or JML (and the interrupt and
 * reset vectors), collects the M/X/E state at each incoming transfer, and:
 * <ul>
 * <li>if all of them agree and the entry was decoded with a different state, sets the state at
 * the entry, clears the routine and disassembles it again;</li>
 * <li>if they disagree, leaves the routine and adds a warning bookmark "called with M=?,X=? from
 * ..." listing the callers;</li>
 * <li>bits that the routine sets itself with a leading REP/SEP before any instruction that depends
 * on them are ignored (the entry state cannot change the decoding).</li>
 * </ul>
 * Native-mode interrupt vectors (COP, BRK, ABORT, NMI, IRQ) enter with an unknown M/X state: they
 * add no constraint, and a routine reached only through one keeps its own REP/SEP (a note bookmark
 * is added when its decoding depends on the assumed entry state). RESET and the emulation-mode
 * vectors enter with M=1, X=1. Re-decoded routines change the state at their own call sites, so the
 * analysis repeats over the affected code until nothing changes (at most {@value #MAX_ROUNDS}
 * rounds).
 */
public class Snes65816StateAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "65816 M/X State Propagation";
	private static final String DESCRIPTION =
		"Sets the M/X/E context at 65816 routine entries from the state at their JSR/JSL/JMP/JML " +
			"call sites and re-disassembles routines decoded with the wrong operand sizes. " +
			"Routines called with conflicting states get a bookmark.";
	static final String BOOKMARK_CATEGORY = "65816 M/X state";
	static final int MAX_ROUNDS = 10;

	private static final int M = 1, X = 2, E = 4;

	/** Native-mode vectors: entered with M/X unknown. */
	private static final long[] NATIVE_VECTORS = { 0xFFE4, 0xFFE6, 0xFFE8, 0xFFEA, 0xFFEE };
	private static final String[] NATIVE_VECTOR_NAMES = { "COP", "BRK", "ABORT", "NMI", "IRQ" };
	/** Emulation-mode vectors and RESET: entered in emulation mode, M=1, X=1. */
	private static final long[] EMU_VECTORS = { 0xFFF4, 0xFFF8, 0xFFFA, 0xFFFC, 0xFFFE };
	private static final String[] EMU_VECTOR_NAMES =
		{ "COP (emulation)", "ABORT (emulation)", "NMI (emulation)", "RESET", "IRQ/BRK (emulation)" };

	private static final Set<String> TRANSFERS = Set.of("JSR", "JSL", "JMP", "JML");

	/** A state that flows into a routine entry; {@code known} says which of M, X, E it fixes. */
	private record State(int m, int x, int e, int known, String from) {
		String describe() {
			return ((known & M) != 0 ? "M=" + m : "M=?") + "," + ((known & X) != 0 ? "X=" + x : "X=?") +
				((known & E) != 0 && e == 1 ? ",E=1" : "");
		}
	}

	private Register mflagReg, xflagReg, emodeReg, contextReg;

	public Snes65816StateAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.DISASSEMBLY.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		Language lang = program.getLanguage();
		return "65816".equals(lang.getProcessor().toString()) &&
			lang.getRegister("mflag") != null && lang.getRegister("xflag") != null &&
			lang.getRegister("emode") != null;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return canAnalyze(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		mflagReg = program.getRegister("mflag");
		xflagReg = program.getRegister("xflag");
		emodeReg = program.getRegister("emode");
		contextReg = program.getProgramContext().getBaseContextRegister();

		Map<Address, List<State>> vectorStates = readVectors(program);
		AddressSet dirty = new AddressSet(set);
		for (Address v : vectorStates.keySet()) {
			if (set.contains(v)) {
				dirty.add(v);
			}
		}
		Set<Address> noted = new HashSet<>();
		for (int round = 0; round < MAX_ROUNDS && !dirty.isEmpty(); round++) {
			monitor.checkCancelled();
			Set<Address> entries = findEntries(program, dirty, vectorStates);
			AddressSet changed = new AddressSet();
			for (Address entry : entries) {
				monitor.checkCancelled();
				changed.add(processEntry(program, entry, vectorStates, noted, monitor));
			}
			dirty = changed;
			if (round == MAX_ROUNDS - 1 && !dirty.isEmpty()) {
				log.appendMsg(NAME + ": stopped after " + MAX_ROUNDS + " rounds; state may not be stable");
			}
		}
		return true;
	}

	// ---------------------------------------------------------------------------------------
	// Entries and incoming states
	// ---------------------------------------------------------------------------------------

	/** Routine entries touched by the given code: targets of transfers in it, or entries in it. */
	private Set<Address> findEntries(Program program, AddressSetView dirty,
			Map<Address, List<State>> vectorStates) {
		Set<Address> entries = new TreeSet<>();
		Listing listing = program.getListing();
		for (Instruction in : listing.getInstructions(dirty, true)) {
			if (isTransfer(in)) {
				for (Address t : in.getFlows()) {
					entries.add(t);
				}
			}
		}
		ReferenceManager rm = program.getReferenceManager();
		AddressIterator it = rm.getReferenceDestinationIterator(dirty, true);
		while (it.hasNext()) {
			Address to = it.next();
			for (Reference r : rm.getReferencesTo(to)) {
				Instruction from = listing.getInstructionAt(r.getFromAddress());
				if (r.getReferenceType().isFlow() && from != null && isTransfer(from)) {
					entries.add(to);
					break;
				}
			}
		}
		for (Address v : vectorStates.keySet()) {
			if (dirty.contains(v)) {
				entries.add(v);
			}
		}
		return entries;
	}

	private static boolean isTransfer(Instruction in) {
		FlowType ft = in.getFlowType();
		return TRANSFERS.contains(in.getMnemonicString().toUpperCase()) &&
			(ft.isCall() || ft.isJump()) && !ft.isComputed();
	}

	/**
	 * The states flowing into {@code entry}: transfers, branches, fall-through, vectors. Flows from
	 * the routine's own code (loops back to the entry, recursion) are left out: they carry the
	 * state the routine was decoded with, not a caller's.
	 */
	private List<State> incomingStates(Program program, Address entry,
			Map<Address, List<State>> vectorStates) {
		List<State> states = new ArrayList<>(vectorStates.getOrDefault(entry, List.of()));
		Listing listing = program.getListing();
		AddressSet own = null;
		for (Reference r : program.getReferenceManager().getReferencesTo(entry)) {
			if (!r.getReferenceType().isFlow()) {
				continue;
			}
			if (own == null) {
				own = routineBody(program, entry);
			}
			if (own.contains(r.getFromAddress())) {
				continue;
			}
			Instruction from = listing.getInstructionAt(r.getFromAddress());
			if (from == null || from.getFlowType().isComputed()) {
				continue;
			}
			states.add(stateAt(from, from.getMnemonicString() + " at " + from.getAddress()));
		}
		Instruction prev = listing.getInstructionBefore(entry);
		if (prev != null && entry.equals(prev.getFallThrough())) {
			State after = stateAfter(prev);
			if (after != null) {
				states.add(after);
			}
		}
		return states;
	}

	private State stateAt(Instruction in, String from) {
		return new State(ctx(in, mflagReg), ctx(in, xflagReg), ctx(in, emodeReg), M | X | E, from);
	}

	/** State after a fall-through instruction, or null when it cannot be told statically. */
	private State stateAfter(Instruction in) {
		String mn = in.getMnemonicString().toUpperCase();
		State s = stateAt(in, "fall-through from " + in.getAddress());
		int m = s.m(), x = s.x();
		switch (mn) {
			case "REP": {
				Long imm = immediate(in);
				if (imm == null) {
					return null;
				}
				if (s.e() == 0) {
					m = (imm & 0x20) != 0 ? 0 : m;
					x = (imm & 0x10) != 0 ? 0 : x;
				}
				break;
			}
			case "SEP": {
				Long imm = immediate(in);
				if (imm == null) {
					return null;
				}
				m = (imm & 0x20) != 0 ? 1 : m;
				x = (imm & 0x10) != 0 ? 1 : x;
				break;
			}
			case "PLP":
			case "XCE":
			case "RTI":
				return null;
			default:
				break;
		}
		return new State(m, x, s.e(), s.known(), s.from());
	}

	private static Long immediate(Instruction in) {
		Object[] ops = in.getOpObjects(0);
		for (Object o : ops) {
			if (o instanceof Scalar sc) {
				return sc.getUnsignedValue();
			}
		}
		return null;
	}

	private static int ctx(Instruction in, Register reg) {
		BigInteger v = in.getValue(reg, false);
		return v == null ? 0 : v.intValue();
	}

	/** M/X bits fixed by leading REP/SEP before the routine depends on them. */
	private int selfDeterminedBits(Program program, Address entry) {
		int covered = 0;
		Instruction in = program.getListing().getInstructionAt(entry);
		for (int i = 0; in != null && i < 8; i++) {
			String mn = in.getMnemonicString().toUpperCase();
			if (mn.equals("REP") || mn.equals("SEP")) {
				Long imm = immediate(in);
				if (imm == null) {
					break;
				}
				if ((imm & 0x20) != 0) {
					covered |= M;
				}
				if ((imm & 0x10) != 0) {
					covered |= X;
				}
			}
			else if (!Set.of("SEI", "CLI", "CLC", "SEC", "CLD", "SED", "CLV", "XCE", "PHP", "PHB",
				"PHD", "PHK", "NOP").contains(mn)) {
				break;
			}
			if ((covered & (M | X)) == (M | X)) {
				break;
			}
			Address next = in.getFallThrough();
			in = next == null ? null : program.getListing().getInstructionAt(next);
		}
		return covered;
	}

	// ---------------------------------------------------------------------------------------
	// Deciding and re-disassembling
	// ---------------------------------------------------------------------------------------

	/** Returns the address set of re-disassembled code (empty when nothing changed). */
	private AddressSetView processEntry(Program program, Address entry,
			Map<Address, List<State>> vectorStates, Set<Address> noted, TaskMonitor monitor) {
		Instruction first = program.getListing().getInstructionAt(entry);
		if (first == null) {
			return new AddressSet();
		}
		List<State> states = incomingStates(program, entry, vectorStates);
		if (states.isEmpty()) {
			return new AddressSet();
		}
		int relevant = (M | X | E) & ~selfDeterminedBits(program, entry);
		int[] agreed = { -1, -1, -1 };
		int disagree = 0;
		int[] bits = { M, X, E };
		for (int b = 0; b < 3; b++) {
			if ((relevant & bits[b]) == 0) {
				continue;
			}
			for (State s : states) {
				if ((s.known() & bits[b]) == 0) {
					continue;
				}
				int v = b == 0 ? s.m() : b == 1 ? s.x() : s.e();
				if (agreed[b] < 0) {
					agreed[b] = v;
				}
				else if (agreed[b] != v) {
					disagree |= bits[b];
				}
			}
		}
		BookmarkManager bm = program.getBookmarkManager();
		if ((disagree & (M | X | E)) != 0) {
			StringBuilder sb = new StringBuilder("called with ");
			sb.append((disagree & M) != 0 ? "M=?" : "M=" + val(agreed[0]));
			sb.append(",").append((disagree & X) != 0 ? "X=?" : "X=" + val(agreed[1]));
			if ((disagree & E) != 0) {
				sb.append(",E=?");
			}
			sb.append(" from ");
			StringJoiner sj = new StringJoiner(", ");
			for (State s : states) {
				sj.add(s.from() + " (" + s.describe() + ")");
			}
			sb.append(sj);
			setNote(bm, entry, BookmarkType.WARNING, sb.toString());
			return new AddressSet();
		}
		boolean anyKnownMX = agreed[0] >= 0 || agreed[1] >= 0;
		if (!anyKnownMX && (relevant & (M | X)) != 0 && vectorStates.containsKey(entry) &&
			noted.add(entry)) {
			setNote(bm, entry, BookmarkType.NOTE,
				"entered via " + vectorStates.get(entry).get(0).from() +
					" with M/X unknown; decoded with M=" + ctx(first, mflagReg) + ",X=" +
					ctx(first, xflagReg) + " (no REP/SEP sets them at the entry)");
		}
		int curM = ctx(first, mflagReg), curX = ctx(first, xflagReg), curE = ctx(first, emodeReg);
		int newM = agreed[0] >= 0 ? agreed[0] : curM;
		int newX = agreed[1] >= 0 ? agreed[1] : curX;
		int newE = agreed[2] >= 0 ? agreed[2] : curE;
		if (newM == curM && newX == curX && newE == curE) {
			clearNote(bm, entry, BookmarkType.WARNING);
			return new AddressSet();
		}
		clearNote(bm, entry, BookmarkType.WARNING);
		return redisassemble(program, entry, newM, newX, newE, monitor);
	}

	private static String val(int v) {
		return v < 0 ? "?" : Integer.toString(v);
	}

	private AddressSetView redisassemble(Program program, Address entry, int m, int x, int e,
			TaskMonitor monitor) {
		AddressSet body = routineBody(program, entry);
		Listing listing = program.getListing();
		ProgramContext pc = program.getProgramContext();
		try {
			for (AddressRange r : body) {
				listing.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
			}
			pc.setValue(mflagReg, entry, entry, BigInteger.valueOf(m));
			pc.setValue(xflagReg, entry, entry, BigInteger.valueOf(x));
			pc.setValue(emodeReg, entry, entry, BigInteger.valueOf(e));
		}
		catch (ContextChangeException ex) {
			Msg.warn(this, NAME + ": cannot set context at " + entry + ": " + ex.getMessage());
			return new AddressSet();
		}
		RegisterValue seed = pc.getDisassemblyContext(entry);
		seed = seed.assign(mflagReg, BigInteger.valueOf(m))
				.assign(xflagReg, BigInteger.valueOf(x))
				.assign(emodeReg, BigInteger.valueOf(e));
		DisassembleCommand cmd = new DisassembleCommand(entry, null, true);
		cmd.setInitialContext(seed);
		cmd.applyTo(program, monitor);
		AddressSet redone = new AddressSet(cmd.getDisassembledAddressSet());
		Function f = program.getFunctionManager().getFunctionAt(entry);
		if (f != null) {
			try {
				CreateFunctionCmd.fixupFunctionBody(program, f, monitor);
			}
			catch (CancelledException ex) {
				// the body is fixed again by later analysis
			}
		}
		program.getBookmarkManager()
				.setBookmark(entry, BookmarkType.ANALYSIS, BOOKMARK_CATEGORY,
					"re-disassembled with M=" + m + ",X=" + x + (e == 1 ? ",E=1" : "") +
						" (the state at all its call sites)");
		return redone;
	}

	/**
	 * The existing code of the routine at {@code entry}: instructions reached by fall-through and
	 * branches (not calls), stopping at other routines (function entries and transfer targets).
	 */
	private AddressSet routineBody(Program program, Address entry) {
		AddressSet body = new AddressSet();
		Listing listing = program.getListing();
		FunctionManager fm = program.getFunctionManager();
		Deque<Address> work = new ArrayDeque<>();
		work.push(entry);
		while (!work.isEmpty()) {
			Address a = work.pop();
			if (body.contains(a)) {
				continue;
			}
			if (!a.equals(entry) && (fm.getFunctionAt(a) != null || isTransferTarget(program, a))) {
				continue;
			}
			Instruction in = listing.getInstructionAt(a);
			if (in == null) {
				continue;
			}
			body.add(in.getMinAddress(), in.getMaxAddress());
			Address ft = in.getFallThrough();
			if (ft != null) {
				work.push(ft);
			}
			if (!in.getFlowType().isCall()) {
				for (Address t : in.getFlows()) {
					work.push(t);
				}
			}
		}
		return body;
	}

	private boolean isTransferTarget(Program program, Address a) {
		Listing listing = program.getListing();
		for (Reference r : program.getReferenceManager().getReferencesTo(a)) {
			Instruction from = listing.getInstructionAt(r.getFromAddress());
			if (from != null && r.getReferenceType().isFlow() && isTransfer(from)) {
				return true;
			}
		}
		return false;
	}

	private static void setNote(BookmarkManager bm, Address a, String type, String text) {
		Bookmark old = bm.getBookmark(a, type, BOOKMARK_CATEGORY);
		if (old != null && old.getComment().equals(text)) {
			return;
		}
		bm.setBookmark(a, type, BOOKMARK_CATEGORY, text);
	}

	private static void clearNote(BookmarkManager bm, Address a, String type) {
		Bookmark old = bm.getBookmark(a, type, BOOKMARK_CATEGORY);
		if (old != null) {
			bm.removeBookmark(old);
		}
	}

	// ---------------------------------------------------------------------------------------
	// Vectors
	// ---------------------------------------------------------------------------------------

	/** Vector targets in bank 0 and the state they are entered with. */
	private Map<Address, List<State>> readVectors(Program program) {
		Map<Address, List<State>> result = new HashMap<>();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Memory mem = program.getMemory();
		for (int pass = 0; pass < 2; pass++) {
			long[] vecs = pass == 0 ? NATIVE_VECTORS : EMU_VECTORS;
			String[] names = pass == 0 ? NATIVE_VECTOR_NAMES : EMU_VECTOR_NAMES;
			for (int i = 0; i < vecs.length; i++) {
				Address va = space.getAddress(vecs[i]);
				if (!mem.contains(va) || !mem.contains(va.add(1))) {
					continue;
				}
				int target;
				try {
					target = mem.getShort(va) & 0xFFFF;
				}
				catch (MemoryAccessException ex) {
					continue;
				}
				if (target == 0 || target == 0xFFFF) {
					continue;
				}
				Address t = space.getAddress(target);
				String from = names[i] + " vector";
				State s = pass == 0 ? new State(0, 0, 0, E, from)	// native: M/X unknown, E=0
						: new State(1, 1, 1, M | X, from);			// emulation: M=X=1 (E not forced)
				result.computeIfAbsent(t, k -> new ArrayList<>()).add(s);
			}
		}
		return result;
	}
}
