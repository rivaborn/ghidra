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

import java.util.*;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves Game Boy ROM bank switching for programs imported by the Game Boy loader.
 * <p>
 * The loader maps each switchable bank N as an overlay {@code bank_NN} of 4000-7FFF, so a
 * {@code CALL}/{@code JP} from bank 0 into 4000-7FFF has no target until the selected bank is
 * known. This analyzer tracks register constants through straight-line code (no incoming
 * branches) before each such instruction, finds the bank-select writes for the cartridge's
 * MBC ({@code LD (nn),A}, {@code LD (HL),A}, {@code LD (HL),n}, {@code LD (BC|DE),A}, and calls
 * to a recognised bank-switch helper with A known) and, when the bank is a known constant on
 * that path, points the instruction at the bank's overlay: a primary call reference for
 * {@code CALL} / {@code CALL cc} (also used by the decompiler); for {@code JP nn} /
 * {@code JP cc,nn} a {@code CALL_RETURN} flow override (the jump leaves the routine: a tail
 * call) plus a primary {@code CALL_OVERRIDE_UNCONDITIONAL} reference. The target is then
 * disassembled and made a function.
 * <p>
 * Helpers recognised (and labelled) when the pattern is obvious, by following the straight-line
 * code from each call target in bank 0:
 * <ul>
 * <li>{@code mbc_SetRomBank_A}: writes its incoming A to the MBC bank register and returns;</li>
 * <li>{@code mbc_FarCall_A_HL}: writes its incoming A to the bank register, then jumps to /
 * calls through its incoming HL ({@code JP (HL)} directly or via a {@code JP (HL)} stub).</li>
 * </ul>
 * Call sites of a far-call helper with A and HL known get a data reference to the far target
 * (on the {@code LD HL,nn}), which is disassembled. Anything not provably constant is left
 * alone.
 */
public class GameBoyBankAnalyzer extends AbstractAnalyzer {

	public static final String NAME = "Game Boy ROM Bank References";
	private static final String DESCRIPTION =
		"Follows MBC bank-select writes in straight-line code and points CALL/JP " +
			"instructions into 4000-7FFF at the selected bank overlay (bank_NN); labels " +
			"bank-switch / far-call helpers. Only for programs from the Game Boy loader.";

	private static final String INFO_MBC = "Game Boy MBC";
	private static final String INFO_BANKS = "Game Boy ROM Banks";
	private static final int MAX_WINDOW = 64;
	private static final int MAX_HELPER = 40;

	public GameBoyBankAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!"LR35902".equals(program.getLanguage().getProcessor().toString())) {
			return false;
		}
		String mbc = mbcName(program);
		return mbc != null && !mbc.equals("NONE");
	}

	private static String mbcName(Program program) {
		Options info = program.getOptions(Program.PROGRAM_INFO);
		if (!info.contains(INFO_MBC)) {
			return null;
		}
		String v = info.getString(INFO_MBC, null);
		if (v == null || v.isBlank()) {
			return null;
		}
		return v.split(" ")[0].trim();
	}

	// ------------------------------------------------------------------------------------
	// Abstract register values: -1 unknown, 0..255 constant, PARAM+r "value of r at entry"
	// ------------------------------------------------------------------------------------
	private static final int UNK = -1;
	private static final int PARAM = 0x1000;
	private static final int B = 0, C = 1, D = 2, E = 3, H = 4, L = 5, M = 6, A = 7;

	private static boolean isConst(int v) {
		return v >= 0 && v <= 0xFF;
	}

	/** Bank controller register model. */
	private final class MbcState {
		int low = UNK;     // ROM bank register (low bits)
		int high = UNK;    // MBC1 upper bits / MBC5 bit 8

		MbcState copy() {
			MbcState s = new MbcState();
			s.low = low;
			s.high = high;
			return s;
		}

		/** Applies a write of {@code v} (UNK allowed) to address {@code addr}. */
		boolean write(int addr, int v) {
			int value = isConst(v) ? v : UNK;
			switch (mbc) {
				case "MBC1", "MBC1M" -> {
					if (addr >= 0x2000 && addr < 0x4000) {
						low = value;
						return true;
					}
					if (addr >= 0x4000 && addr < 0x6000) {
						high = value == UNK ? UNK : (value & 3);
						return true;
					}
				}
				case "MBC2" -> {
					if (addr < 0x4000 && (addr & 0x100) != 0) {
						low = value;
						return true;
					}
				}
				case "MBC5" -> {
					if (addr >= 0x2000 && addr < 0x3000) {
						low = value;
						return true;
					}
					if (addr >= 0x3000 && addr < 0x4000) {
						high = value == UNK ? UNK : (value & 1);
						return true;
					}
				}
				case "MBC6", "MMM01", "TAMA5" -> {
					return false;
				}
				default -> { // MBC3, MBC7, HuC1, HuC3, camera, unknown
					if (addr >= 0x2000 && addr < 0x4000) {
						low = value;
						return true;
					}
				}
			}
			return false;
		}

		/** True if {@code addr} is a ROM-bank register of this MBC. */
		boolean isBankRegister(int addr) {
			return copy().write(addr, 1);
		}

		/** The ROM bank visible at 4000-7FFF, or -1 if not known. */
		int bank() {
			if (low == UNK) {
				return -1;
			}
			int bank;
			switch (mbc) {
				case "MBC1" -> {
					int l = low & 0x1F;
					if (l == 0) {
						l = 1;
					}
					if (banks > 32) {
						if (high == UNK) {
							return -1;
						}
						l |= high << 5;
					}
					bank = l;
				}
				case "MBC1M" -> {
					int l = low & 0x1F;
					if (l == 0) {
						l = 1;
					}
					l &= 0x0F;
					if (banks > 16) {
						if (high == UNK) {
							return -1;
						}
						l |= high << 4;
					}
					bank = l;
				}
				case "MBC2" -> bank = (low & 0x0F) == 0 ? 1 : (low & 0x0F);
				case "MBC3" -> bank = (low & 0x7F) == 0 ? 1 : (low & 0x7F);
				case "MBC5" -> {
					bank = low & 0xFF;
					if (banks > 256) {
						if (high == UNK) {
							return -1;
						}
						bank |= high << 8;
					}
				}
				default -> bank = low;
			}
			bank &= mask;
			if (bank == 0 || bank >= banks) {
				return -1; // bank 0 at 4000 (MBC5 etc.) is not modelled
			}
			return bank;
		}
	}

	/** Simulation state: registers, a small push/pop stack and the MBC. */
	private final class State {
		int[] r = new int[8];
		Address hlSource;            // LD HL,nn that produced a constant HL
		ArrayDeque<int[]> stack = new ArrayDeque<>();
		MbcState mbcState = new MbcState();
		boolean barrier;             // hit something we cannot model (call, etc.)

		State(boolean params) {
			for (int i = 0; i < 8; i++) {
				r[i] = params ? PARAM + i : UNK;
			}
		}

		int hl() {
			return isConst(r[H]) && isConst(r[L]) ? (r[H] << 8) | r[L] : -1;
		}

		void setAllUnknown() {
			Arrays.fill(r, UNK);
			hlSource = null;
			stack.clear();
		}

		void set(int reg, int v) {
			if (reg == M) {
				return;
			}
			r[reg] = v;
			if (reg == H || reg == L) {
				hlSource = null;
			}
		}
	}

	/** A helper routine recognised in bank 0. */
	private static final class Helper {
		boolean farCall;  // else SetRomBank
		int regAddr;      // bank register it writes
	}

	// per-run fields
	private String mbc;
	private int banks;
	private int mask;
	private Program program;
	private AddressSpace ram;
	private Map<Address, Helper> helpers;
	private int resolved;

	@Override
	public boolean added(Program prog, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		this.program = prog;
		this.mbc = mbcName(prog);
		Options info = prog.getOptions(Program.PROGRAM_INFO);
		try {
			banks = Integer.parseInt(info.getString(INFO_BANKS, "0").trim());
		}
		catch (NumberFormatException e) {
			banks = 0;
		}
		if (banks < 2 || mbc == null) {
			return false;
		}
		mask = Integer.highestOneBit(banks - 1) * 2 - 1;
		ram = prog.getAddressFactory().getDefaultAddressSpace();
		resolved = 0;

		findHelpers(monitor);

		// Bank 0 (0000-3FFF) is always rescanned (small); overlay code only where new.
		AddressSet scan = new AddressSet(ram.getAddress(0), ram.getAddress(0x3FFF));
		for (AddressRange r : set) {
			if (r.getAddressSpace().isOverlaySpace()) {
				scan.add(r);
			}
		}
		Listing listing = prog.getListing();
		InstructionIterator it = listing.getInstructions(scan, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction ins = it.next();
			processSite(ins, monitor);
		}
		if (resolved > 0) {
			log.appendMsg(NAME + ": resolved " + resolved + " bank-switched references");
		}
		return true;
	}

	// ------------------------------------------------------------------------------------
	// Instruction decoding (raw bytes; LR35902 opcode map)
	// ------------------------------------------------------------------------------------

	private static int u8(Instruction ins, int i) {
		try {
			return ins.getByte(i) & 0xFF;
		}
		catch (Exception e) {
			return -1;
		}
	}

	private static int imm16(Instruction ins) {
		return u8(ins, 1) | (u8(ins, 2) << 8);
	}

	private static int inc8(int v, int d) {
		return isConst(v) ? ((v + d) & 0xFF) : UNK;
	}

	/**
	 * Applies {@code ins} to {@code s}. Flow instructions (CALL / RST) are handled by the
	 * caller; this handles the data effects of every other opcode.
	 */
	private void step(State s, Instruction ins) {
		int op = u8(ins, 0);
		int[] r = s.r;
		if (op >= 0x40 && op <= 0x7F && op != 0x76) {          // LD r,r'
			int dst = (op >> 3) & 7, src = op & 7;
			if (dst == M) {
				store(s, s.hl(), r[src]);
			}
			else if (src == M) {
				s.set(dst, UNK);
			}
			else {
				s.set(dst, r[src]);
			}
			return;
		}
		if (op >= 0x80 && op <= 0xBF) {                          // ALU A,r
			int kind = (op >> 3) & 7, src = op & 7;
			if (kind == 7) {
				return;                                          // CP
			}
			if (kind == 5 && src == A) {
				r[A] = 0;                                        // XOR A
			}
			else if (kind == 2 && src == A) {
				r[A] = 0;                                        // SUB A
			}
			else if (kind == 4 && src == A || kind == 6 && src == A) {
				// AND A / OR A: A unchanged
			}
			else {
				r[A] = UNK;
			}
			return;
		}
		switch (op) {
			case 0x00, 0x37, 0x3F, 0xF3, 0xFB, 0x08, 0xE0, 0xE2, 0xE8, 0xF9, 0x76 -> {
				// no register effects
			}
			case 0x01 -> {
				s.set(B, u8(ins, 2));
				s.set(C, u8(ins, 1));
			}
			case 0x11 -> {
				s.set(D, u8(ins, 2));
				s.set(E, u8(ins, 1));
			}
			case 0x21 -> {
				s.set(H, u8(ins, 2));
				s.set(L, u8(ins, 1));
				s.hlSource = ins.getAddress();
			}
			case 0x31 -> { /* LD SP,nn */ }
			case 0x02 -> store(s, pair(r[B], r[C]), r[A]);
			case 0x12 -> store(s, pair(r[D], r[E]), r[A]);
			case 0x22, 0x32 -> {
				store(s, s.hl(), r[A]);
				s.set(H, UNK);
				s.set(L, UNK);
			}
			case 0x2A, 0x3A -> {
				r[A] = UNK;
				s.set(H, UNK);
				s.set(L, UNK);
			}
			case 0x0A, 0x1A, 0xF0, 0xF2, 0xFA, 0x07, 0x0F, 0x17, 0x1F, 0x27, 0x2F, 0xC6, 0xCE,
					0xD6, 0xDE, 0xE6, 0xEE, 0xF6 -> r[A] = UNK;
			case 0xFE -> { /* CP n */ }
			case 0xEA -> store(s, imm16(ins), r[A]);
			case 0x36 -> store(s, s.hl(), u8(ins, 1));
			case 0x03, 0x0B -> {
				s.set(B, UNK);
				s.set(C, UNK);
			}
			case 0x13, 0x1B -> {
				s.set(D, UNK);
				s.set(E, UNK);
			}
			case 0x23, 0x2B, 0x09, 0x19, 0x29, 0x39, 0xF8 -> {
				s.set(H, UNK);
				s.set(L, UNK);
			}
			case 0x33, 0x3B -> { /* INC/DEC SP */ }
			case 0xC5 -> s.stack.push(new int[] { r[B], r[C] });
			case 0xD5 -> s.stack.push(new int[] { r[D], r[E] });
			case 0xE5 -> s.stack.push(new int[] { r[H], r[L] });
			case 0xF5 -> s.stack.push(new int[] { r[A], UNK });
			case 0xC1, 0xD1, 0xE1, 0xF1 -> {
				int[] v = s.stack.isEmpty() ? new int[] { UNK, UNK } : s.stack.pop();
				switch (op) {
					case 0xC1 -> {
						s.set(B, v[0]);
						s.set(C, v[1]);
					}
					case 0xD1 -> {
						s.set(D, v[0]);
						s.set(E, v[1]);
					}
					case 0xE1 -> {
						s.set(H, v[0]);
						s.set(L, v[1]);
					}
					default -> r[A] = v[0];
				}
			}
			case 0xCB -> {
				int b = u8(ins, 1);
				if (b >= 0x40 && b <= 0x7F) {
					return;                                      // BIT
				}
				int reg = b & 7;
				if (reg != M) {
					s.set(reg, UNK);
				}
			}
			default -> {
				if ((op & 0xC7) == 0x04) {                       // INC r
					int reg = (op >> 3) & 7;
					if (reg != M) {
						s.set(reg, inc8(r[reg], 1));
					}
				}
				else if ((op & 0xC7) == 0x05) {                  // DEC r
					int reg = (op >> 3) & 7;
					if (reg != M) {
						s.set(reg, inc8(r[reg], -1));
					}
				}
				else if ((op & 0xC7) == 0x06) {                  // LD r,n
					int reg = (op >> 3) & 7;
					s.set(reg, u8(ins, 1));
				}
				else if (isFlowOpcode(op)) {
					// conditional branches / returns: data unaffected on the fall-through path
				}
				else {
					s.setAllUnknown();                           // unmodelled
					s.barrier = true;
				}
			}
		}
	}

	private static boolean isFlowOpcode(int op) {
		return op == 0x18 || op == 0x20 || op == 0x28 || op == 0x30 || op == 0x38 ||
			op == 0xC0 || op == 0xC8 || op == 0xD0 || op == 0xD8 || op == 0xC2 || op == 0xCA ||
			op == 0xD2 || op == 0xDA || op == 0xC3;
	}

	private static int pair(int hi, int lo) {
		return isConst(hi) && isConst(lo) ? (hi << 8) | lo : -1;
	}

	private void store(State s, int addr, int value) {
		if (addr < 0 || addr >= 0x8000) {
			return;
		}
		if (s.mbcState.isBankRegister(addr)) {
			s.mbcState.write(addr, value);
		}
	}

	private static boolean isCall(int op) {
		return op == 0xCD || op == 0xC4 || op == 0xCC || op == 0xD4 || op == 0xDC;
	}

	private static boolean isRst(int op) {
		return (op & 0xC7) == 0xC7;
	}

	/** Handles a CALL / RST inside a simulated window. */
	private void stepCall(State s, int target) {
		Helper h = helpers.get(ram.getAddress(target));
		if (h != null && !h.farCall) {
			s.mbcState.write(h.regAddr, s.r[A]);
			// the setter preserves nothing we rely on except the bank
			int bank = s.mbcState.low;
			s.setAllUnknown();
			s.mbcState.low = bank;
			return;
		}
		s.setAllUnknown();
		s.mbcState = new MbcState(); // the callee may switch banks
	}

	// ------------------------------------------------------------------------------------
	// Helpers
	// ------------------------------------------------------------------------------------

	private void findHelpers(TaskMonitor monitor) throws CancelledException {
		helpers = new HashMap<>();
		Listing listing = program.getListing();
		Set<Address> targets = new TreeSet<>();
		InstructionIterator it =
			listing.getInstructions(new AddressSet(ram.getAddress(0), ram.getAddress(0x3FFF)),
				true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction ins = it.next();
			int op = u8(ins, 0);
			if (isCall(op)) {
				targets.add(ram.getAddress(imm16(ins)));
			}
			else if (isRst(op)) {
				targets.add(ram.getAddress(op & 0x38));
			}
		}
		for (Address t : targets) {
			if (t.getOffset() >= 0x4000) {
				continue;
			}
			Helper h = classifyHelper(t);
			if (h != null) {
				helpers.put(t, h);
				String name = h.farCall ? "mbc_FarCall_A_HL" : "mbc_SetRomBank_A";
				nameHelper(t, name);
			}
		}
	}

	private void nameHelper(Address a, String name) {
		SymbolTable st = program.getSymbolTable();
		Symbol p = st.getPrimarySymbol(a);
		if (p != null && p.getSource() != SourceType.DEFAULT && p.getName().equals(name)) {
			return;
		}
		try {
			Function f = program.getFunctionManager().getFunctionAt(a);
			if (f != null && f.getSymbol().getSource() == SourceType.DEFAULT) {
				f.setName(name, SourceType.ANALYSIS);
			}
			else if (p == null || p.getSource() == SourceType.DEFAULT) {
				st.createLabel(a, name, SourceType.ANALYSIS).setPrimary();
			}
			else if (!p.getName().equals(name)) {
				st.createLabel(a, name, SourceType.ANALYSIS);
			}
		}
		catch (Exception e) {
			// ignore naming conflicts
		}
	}

	/** Straight-line walk from a call target with A/H/L as parameters. */
	private Helper classifyHelper(Address entry) {
		Listing listing = program.getListing();
		State s = new State(true);
		Instruction ins = listing.getInstructionAt(entry);
		int bankWrites = 0;
		int writeAddr = -1;
		boolean wroteParamA = false;
		for (int n = 0; n < MAX_HELPER && ins != null; n++) {
			int op = u8(ins, 0);
			// bank write of the incoming A?
			int storeAddr = storeTarget(s, ins);
			if (storeAddr >= 0 && s.mbcState.isBankRegister(storeAddr)) {
				int v = storeValue(s, ins);
				bankWrites++;
				if (bankWrites == 1) {
					if (v != PARAM + A) {
						return null;
					}
					wroteParamA = true;
					writeAddr = storeAddr;
				}
			}
			if (op == 0xC9 || op == 0xD9) {                       // RET / RETI
				if (wroteParamA && bankWrites == 1) {
					Helper h = new Helper();
					h.regAddr = writeAddr;
					return h;
				}
				return null;
			}
			if (op == 0xE9) {                                      // JP (HL)
				if (wroteParamA && s.r[H] == PARAM + H && s.r[L] == PARAM + L) {
					Helper h = new Helper();
					h.farCall = true;
					h.regAddr = writeAddr;
					return h;
				}
				return null;
			}
			if (isCall(op) || isRst(op)) {
				int t = isCall(op) ? imm16(ins) : (op & 0x38);
				Instruction callee = listing.getInstructionAt(ram.getAddress(t));
				if (wroteParamA && callee != null && u8(callee, 0) == 0xE9 &&
					s.r[H] == PARAM + H && s.r[L] == PARAM + L) {
					Helper h = new Helper();
					h.farCall = true;
					h.regAddr = writeAddr;
					return h;
				}
				return null;
			}
			if (op == 0xC0 || op == 0xC8 || op == 0xD0 || op == 0xD8 || op == 0xC2 ||
				op == 0xCA || op == 0xD2 || op == 0xDA || op == 0x20 || op == 0x28 ||
				op == 0x30 || op == 0x38 || op == 0xE9 || op == 0x10) {
				return null;                                       // not straight-line
			}
			step(s, ins);
			if (s.barrier) {
				return null;
			}
			Address next;
			if (op == 0xC3 || op == 0x18) {                        // JP nn / JR: follow
				Address[] fl = ins.getFlows();
				if (fl.length != 1) {
					return null;
				}
				next = fl[0];
			}
			else {
				next = ins.getFallThrough();
			}
			if (next == null) {
				return null;
			}
			ins = listing.getInstructionAt(next);
		}
		return null;
	}

	/** Address a store instruction writes to (or -1), given the current state. */
	private int storeTarget(State s, Instruction ins) {
		int op = u8(ins, 0);
		return switch (op) {
			case 0xEA -> imm16(ins);
			case 0x77, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x36, 0x22, 0x32 -> s.hl();
			case 0x02 -> pair(s.r[B], s.r[C]);
			case 0x12 -> pair(s.r[D], s.r[E]);
			default -> -1;
		};
	}

	private int storeValue(State s, Instruction ins) {
		int op = u8(ins, 0);
		if (op == 0x36) {
			return u8(ins, 1);
		}
		if (op >= 0x70 && op <= 0x77) {
			return s.r[op & 7];
		}
		return s.r[A];
	}

	// ------------------------------------------------------------------------------------
	// Call / jump sites
	// ------------------------------------------------------------------------------------

	private void processSite(Instruction ins, TaskMonitor monitor) {
		int op = u8(ins, 0);
		boolean inBank0 = ins.getAddress().getAddressSpace().equals(ram) &&
			ins.getAddress().getOffset() < 0x4000;
		boolean call = isCall(op);
		boolean jump = op == 0xC3 || op == 0xC2 || op == 0xCA || op == 0xD2 || op == 0xDA;
		if (!call && !jump) {
			return;
		}
		int target = imm16(ins);
		Helper h = helpers.get(ram.getAddress(target));
		if (call && h != null && h.farCall) {
			resolveFarCall(ins, h);
			return;
		}
		if (!inBank0 || target < 0x4000 || target >= 0x8000) {
			return;
		}
		if (alreadyResolved(ins)) {
			return;
		}
		State s = simulateTo(ins);
		if (s == null) {
			return;
		}
		int bank = s.mbcState.bank();
		if (bank < 1) {
			return;
		}
		Address to = bankAddress(bank, target);
		if (to == null) {
			return;
		}
		RefType type;
		if (call) {
			type = op == 0xCD ? RefType.UNCONDITIONAL_CALL : RefType.CONDITIONAL_CALL;
		}
		else {
			// A jump from bank 0 into a switchable bank leaves this routine: model it as a
			// (conditional) tail call so the decompiler can take the overlay target.
			if (ins.getFlowOverride() == FlowOverride.NONE) {
				ins.setFlowOverride(FlowOverride.CALL_RETURN);
			}
			type = RefType.CALL_OVERRIDE_UNCONDITIONAL;
		}
		redirect(ins, ram.getAddress(target), to, type);
		comment(ins, String.format("ROM bank %d (MBC bank write before this %s)", bank,
			call ? "call" : "jump"));
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		mgr.disassemble(to);
		// Calls start functions; a jump into another bank is a tail transfer to code that
		// is not part of this function's body, so it starts a function too.
		mgr.createFunction(to, false);
		resolved++;
	}

	private boolean alreadyResolved(Instruction ins) {
		for (Reference r : ins.getReferencesFrom()) {
			if (r.getToAddress().getAddressSpace().isOverlaySpace()) {
				return true;
			}
		}
		return false;
	}

	private Address bankAddress(int bank, int offset) {
		int digits = banks > 0x100 ? 3 : 2;
		MemoryBlock b = program.getMemory().getBlock(String.format("bank_%0" + digits + "X",
			bank));
		if (b == null || !b.isOverlay()) {
			return null;
		}
		Address a = b.getStart().getAddressSpace().getAddress(offset);
		return b.contains(a) ? a : null;
	}

	private void redirect(Instruction ins, Address oldTo, Address newTo, RefType type) {
		ReferenceManager rm = program.getReferenceManager();
		int opIndex = 0;
		for (Reference r : ins.getReferencesFrom()) {
			if (r.getToAddress().equals(oldTo)) {
				opIndex = r.getOperandIndex();
				rm.delete(r);
			}
		}
		Reference ref = rm.addMemoryReference(ins.getAddress(), newTo, type,
			SourceType.ANALYSIS, opIndex);
		rm.setPrimary(ref, true);
	}

	private void comment(Instruction ins, String text) {
		Listing listing = program.getListing();
		if (listing.getComment(CommentType.EOL, ins.getAddress()) == null) {
			listing.setComment(ins.getAddress(), CommentType.EOL, text);
		}
	}

	/**
	 * Walks back from {@code site} through fall-through predecessors that are not branch
	 * targets, then simulates forward. Returns the state before {@code site} executes, or
	 * null if {@code site} itself is a branch target.
	 */
	private State simulateTo(Instruction site) {
		Listing listing = program.getListing();
		ReferenceManager rm = program.getReferenceManager();
		Deque<Instruction> window = new ArrayDeque<>();
		Instruction cur = site;
		for (int n = 0; n < MAX_WINDOW; n++) {
			if (hasIncomingFlow(rm, cur.getAddress())) {
				break;
			}
			Instruction prev = listing.getInstructionBefore(cur.getAddress());
			if (prev == null || prev.getFallThrough() == null ||
				!prev.getFallThrough().equals(cur.getAddress())) {
				break;
			}
			int pop = u8(prev, 0);
			if (pop == 0xC9 || pop == 0xD9 || pop == 0xC3 || pop == 0x18 || pop == 0xE9) {
				break;
			}
			window.addFirst(prev);
			cur = prev;
		}
		if (window.isEmpty()) {
			return null;
		}
		State s = new State(false);
		for (Instruction ins : window) {
			int op = u8(ins, 0);
			if (isCall(op)) {
				stepCall(s, imm16(ins));
				if (op != 0xCD) {
					// conditional call: the callee may or may not have run
					s.setAllUnknown();
					s.mbcState = new MbcState();
				}
				continue;
			}
			if (isRst(op)) {
				stepCall(s, op & 0x38);
				continue;
			}
			step(s, ins);
			s.barrier = false;
		}
		return s;
	}

	private static boolean hasIncomingFlow(ReferenceManager rm, Address a) {
		ReferenceIterator it = rm.getReferencesTo(a);
		while (it.hasNext()) {
			Reference r = it.next();
			RefType t = r.getReferenceType();
			if (t.isFlow() && !t.isFallthrough()) {
				return true;
			}
		}
		return false;
	}

	private void resolveFarCall(Instruction call, Helper h) {
		if (alreadyResolvedFar(call)) {
			return;
		}
		State s = simulateTo(call);
		if (s == null) {
			return;
		}
		int a = s.r[A];
		int hl = s.hl();
		if (!isConst(a) || hl < 0) {
			return;
		}
		Address to;
		int bank = -1;
		if (hl < 0x4000) {
			to = ram.getAddress(hl);
		}
		else if (hl < 0x8000) {
			MbcState m = new MbcState();
			m.write(h.regAddr, a);
			bank = m.bank();
			if (bank < 1) {
				return;
			}
			to = bankAddress(bank, hl);
		}
		else {
			return;
		}
		if (to == null) {
			return;
		}
		ReferenceManager rm = program.getReferenceManager();
		Address from = s.hlSource != null ? s.hlSource : call.getAddress();
		int opIndex = s.hlSource != null ? 1 : Reference.MNEMONIC;
		for (Reference r : rm.getReferencesFrom(from)) {
			if (r.getOperandIndex() == opIndex && !r.getToAddress().equals(to)) {
				rm.delete(r);
			}
		}
		Reference ref =
			rm.addMemoryReference(from, to, RefType.DATA, SourceType.ANALYSIS, opIndex);
		rm.setPrimary(ref, true);
		comment(call, "far call to " + to + (bank > 0 ? " (ROM bank " + bank + ")" : ""));
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		mgr.disassemble(to);
		mgr.createFunction(to, false);
		resolved++;
	}

	private boolean alreadyResolvedFar(Instruction call) {
		String c = program.getListing().getComment(CommentType.EOL, call.getAddress());
		return c != null && c.startsWith("far call to ");
	}
}
