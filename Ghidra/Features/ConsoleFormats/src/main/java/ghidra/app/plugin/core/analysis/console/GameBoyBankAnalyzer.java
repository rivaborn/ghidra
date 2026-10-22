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
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.WordDataType;
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
 * Where the straight-line window does not settle the bank, a forward data flow over the bank-0
 * routine (registers, RAM bytes and the selected bank, met at branch joins) is used, starting
 * from the routine's entry bank: the bank every way in agrees on (a call from bank N's code
 * runs with bank N; a bank-0 caller or jump-table dispatcher with a known bank). Calls to
 * routines that never write a bank register (transitively), and to HRAM (the OAM DMA routine),
 * keep the selected bank.
 * <p>
 * Helpers recognised in bank 0 (and labelled), by following the straight-line code from each
 * call target and RST vector, with registers and RAM bytes as parameters:
 * <ul>
 * <li>{@code mbc_SetRomBank}: writes a parameter (A, or a RAM byte) to the MBC bank register
 * and returns;</li>
 * <li>{@code mbc_FarCall}: writes a parameter to the bank register, then jumps through an HL
 * built from parameters ({@code JP (HL)} directly or in a stub it calls). The parameters may
 * be registers (A, HL) or RAM bytes the caller stores first ({@code LD (nn),A},
 * {@code LD (HL+),A}, {@code LDH}: LADX's {@code Farcall});</li>
 * <li>{@code jumptable_Inline}: pops its return address into HL and jumps through HL: an
 * inline jump-table dispatcher ({@code RST $00} + {@code dw} table, as in LADX's
 * {@code JP_TABLE}). It is marked no-return; each call becomes a tail call, the bytes after it
 * are cleared and read as 16-bit handler addresses until the table runs into the first
 * handler, a known instruction or function, or an address that is not code in this bank;
 * each handler becomes a function.</li>
 * </ul>
 * Far-call sites with the parameters known get a data reference to the far target, which is
 * disassembled. Anything not provably constant is left alone.
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
	// Abstract register values: -1 unknown, 0..255 constant, PARAM+r "value of r at entry",
	// MEMP+addr "value of the RAM byte at addr at entry" (far-call parameters in RAM)
	// ------------------------------------------------------------------------------------
	private static final int UNK = -1;
	private static final int PARAM = 0x1000;
	private static final int MEMP = 0x100000;
	private static final int B = 0, C = 1, D = 2, E = 3, H = 4, L = 5, M = 6, A = 7;

	private static boolean isConst(int v) {
		return v >= 0 && v <= 0xFF;
	}

	/** Bank controller register model. */
	private final class MbcState {
		int low = UNK;     // ROM bank register (low bits)
		int high = UNK;    // MBC1 upper bits / MBC5 bit 8
		int assumed = -1;  // bank known from the callers while no write is seen

		MbcState copy() {
			MbcState s = new MbcState();
			s.low = low;
			s.high = high;
			s.assumed = assumed;
			return s;
		}

		/** Applies a write of {@code v} (UNK allowed) to address {@code addr}. */
		boolean write(int addr, int v) {
			assumed = -1;
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
				return assumed;
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

	/** Simulation state: registers, RAM bytes, a small push/pop stack and the MBC. */
	private final class State {
		int[] r = new int[8];
		Address hlSource;            // LD HL,nn that produced a constant HL
		ArrayDeque<int[]> stack = new ArrayDeque<>();
		Map<Integer, Integer> mem = new HashMap<>(); // RAM bytes (8000-FFFF) stored on this path
		MbcState mbcState = new MbcState();
		boolean barrier;             // hit something we cannot model (call, etc.)
		final boolean params;
		boolean poppedReturn;        // POP HL with an empty stack: took the return address

		State(boolean params) {
			this.params = params;
			for (int i = 0; i < 8; i++) {
				r[i] = params ? PARAM + i : UNK;
			}
		}

		int hl() {
			return isConst(r[H]) && isConst(r[L]) ? (r[H] << 8) | r[L] : -1;
		}

		/** Value of the RAM byte at {@code addr} as known on this path. */
		int load(int addr) {
			if (addr < 0x8000) {
				return UNK;
			}
			Integer v = mem.get(addr);
			if (v != null) {
				return v;
			}
			return params ? MEMP + addr : UNK;
		}

		/** HL += d where HL is a constant. */
		void stepHL(int d) {
			int hl = hl();
			if (hl < 0) {
				set(H, UNK);
				set(L, UNK);
				return;
			}
			hl = (hl + d) & 0xFFFF;
			set(H, hl >> 8);
			set(L, hl & 0xFF);
		}

		State copy() {
			State c = new State(params);
			c.r = r.clone();
			c.hlSource = hlSource;
			c.mem = new HashMap<>(mem);
			c.mbcState = mbcState.copy();
			c.poppedReturn = poppedReturn;
			return c; // the push/pop stack is not carried across branches
		}

		/** Meets {@code o} into this state; true if this state changed. */
		boolean merge(State o) {
			boolean changed = false;
			for (int i = 0; i < 8; i++) {
				if (r[i] != UNK && r[i] != o.r[i]) {
					r[i] = UNK;
					changed = true;
				}
			}
			if (hlSource != null && !hlSource.equals(o.hlSource)) {
				hlSource = null;
			}
			Iterator<Map.Entry<Integer, Integer>> it = mem.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<Integer, Integer> e = it.next();
				if (!e.getValue().equals(o.mem.get(e.getKey()))) {
					it.remove();
					changed = true;
				}
			}
			if (mbcState.low != UNK && mbcState.low != o.mbcState.low) {
				mbcState.low = UNK;
				changed = true;
			}
			if (mbcState.high != UNK && mbcState.high != o.mbcState.high) {
				mbcState.high = UNK;
				changed = true;
			}
			if (mbcState.assumed != -1 && mbcState.assumed != o.mbcState.assumed) {
				mbcState.assumed = -1;
				changed = true;
			}
			stack.clear();
			return changed;
		}

		void setAllUnknown() {
			Arrays.fill(r, UNK);
			hlSource = null;
			stack.clear();
			mem.clear();
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

	private static final int SET_BANK = 0, FAR_CALL = 1, JUMP_TABLE = 2;

	/** A helper routine recognised in bank 0. */
	private static final class Helper {
		int kind;
		int regAddr;      // bank register it writes (SET_BANK, FAR_CALL)
		int bankVal;      // what it writes there: PARAM+r or MEMP+addr
		int hVal, lVal;   // FAR_CALL: where its jump target's high / low bytes come from

		boolean farCall() {
			return kind == FAR_CALL;
		}
	}

	/** The value of a helper parameter ({@code PARAM+r} / {@code MEMP+addr}) in {@code s}. */
	private static int argument(State s, int sym) {
		if (sym >= MEMP) {
			Integer v = s.mem.get(sym - MEMP);
			return v == null ? UNK : v;
		}
		if (sym >= PARAM && sym < PARAM + 8) {
			return s.r[sym - PARAM];
		}
		return UNK;
	}

	private static boolean isParam(int v) {
		return v >= MEMP || (v >= PARAM && v < PARAM + 8);
	}

	// per-run fields
	private String mbc;
	private int banks;
	private int mask;
	private Program program;
	private AddressSpace ram;
	private Map<Address, Helper> helpers;
	private Map<Address, Boolean> preserves;
	private Map<Address, Integer> entryBanks;
	private Map<Address, Map<Address, State>> flows;
	private int resolved;
	private int tables;

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
		tables = 0;
		preserves = new HashMap<>();
		entryBanks = new HashMap<>();
		flows = new HashMap<>();

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
		if (tables > 0) {
			log.appendMsg(NAME + ": read " + tables + " inline jump tables");
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
				int hl = s.hl();
				s.set(dst, hl < 0 ? UNK : s.load(hl));
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
			case 0x00, 0x37, 0x3F, 0xF3, 0xFB, 0x08, 0xE8, 0xF9, 0x76 -> {
				// no register effects
			}
			case 0xE0 -> store(s, 0xFF00 | u8(ins, 1), r[A]);
			case 0xE2 -> store(s, isConst(r[C]) ? 0xFF00 | r[C] : -1, r[A]);
			case 0xF0 -> r[A] = s.load(0xFF00 | u8(ins, 1));
			case 0xF2 -> r[A] = isConst(r[C]) ? s.load(0xFF00 | r[C]) : UNK;
			case 0xFA -> r[A] = s.load(imm16(ins));
			case 0x0A -> r[A] = pair(r[B], r[C]) < 0 ? UNK : s.load(pair(r[B], r[C]));
			case 0x1A -> r[A] = pair(r[D], r[E]) < 0 ? UNK : s.load(pair(r[D], r[E]));
			case 0x23 -> s.stepHL(1);
			case 0x2B -> s.stepHL(-1);
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
				s.stepHL(op == 0x22 ? 1 : -1);
			}
			case 0x2A, 0x3A -> {
				int hl = s.hl();
				r[A] = hl < 0 ? UNK : s.load(hl);
				s.stepHL(op == 0x2A ? 1 : -1);
			}
			case 0x07, 0x0F, 0x17, 0x1F, 0x27, 0x2F, 0xC6, 0xCE, 0xD6, 0xDE, 0xE6, 0xEE,
					0xF6 -> r[A] = UNK;
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
			case 0x09, 0x19, 0x29, 0x39, 0xF8 -> {
				s.set(H, UNK);
				s.set(L, UNK);
			}
			case 0x33, 0x3B -> { /* INC/DEC SP */ }
			case 0xC5 -> s.stack.push(new int[] { r[B], r[C] });
			case 0xD5 -> s.stack.push(new int[] { r[D], r[E] });
			case 0xE5 -> s.stack.push(new int[] { r[H], r[L] });
			case 0xF5 -> s.stack.push(new int[] { r[A], UNK });
			case 0xC1, 0xD1, 0xE1, 0xF1 -> {
				if (s.stack.isEmpty() && op == 0xE1) {
					s.poppedReturn = true;
				}
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
		if (addr < 0) {
			return;
		}
		if (addr >= 0x8000) {
			s.mem.put(addr, value);
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

	/** Handles a CALL / RST at {@code site} inside a simulated window. */
	private void stepCall(State s, int target, Address site) {
		Helper h = target < 0x4000 ? helpers.get(ram.getAddress(target)) : null;
		if (h != null && h.kind == SET_BANK) {
			s.mbcState.write(h.regAddr, argument(s, h.bankVal));
			// the setter preserves nothing we rely on except the bank
			int bank = s.mbcState.low;
			s.setAllUnknown();
			s.mbcState.low = bank;
			return;
		}
		Address callee = h == null ? calleeAddress(target, site, s.mbcState) : null;
		// HRAM holds no ROM code but the OAM DMA routine games copy there: it keeps the bank
		boolean keep = callee != null ? preservesBank(callee, 0)
				: h == null && target >= 0xFF80 && target <= 0xFFFE;
		s.setAllUnknown();
		if (!keep) {
			s.mbcState = new MbcState(); // the callee may switch banks
		}
	}

	/** Where a CALL to {@code target} from {@code site} goes, or null if not known. */
	private Address calleeAddress(int target, Address site, MbcState m) {
		if (target < 0x4000) {
			return ram.getAddress(target);
		}
		if (target >= 0x8000) {
			return null;
		}
		AddressSpace sp = site.getAddressSpace();
		if (sp.isOverlaySpace()) {
			return sp.getAddress(target);
		}
		int bank = m.bank();
		return bank < 1 ? null : bankAddress(bank, target);
	}

	/**
	 * True if the function at {@code entry} never selects another ROM bank: it writes no MBC
	 * bank register at a constant address, makes no computed jump, and every routine it calls
	 * or jumps to does the same. Recursion counts as preserving; unknown code does not.
	 */
	private boolean preservesBank(Address entry, int depth) {
		Boolean known = preserves.get(entry);
		if (known != null) {
			return known;
		}
		if (depth > 16) {
			return false;
		}
		Function f = program.getFunctionManager().getFunctionAt(entry);
		if (f == null || helpers.containsKey(entry)) {
			preserves.put(entry, false);
			return false;
		}
		preserves.put(entry, true); // cycles
		boolean ok = true;
		MbcState probe = new MbcState();
		InstructionIterator it = program.getListing().getInstructions(f.getBody(), true);
		while (ok && it.hasNext()) {
			Instruction ins = it.next();
			int op = u8(ins, 0);
			if (op == 0xEA && probe.isBankRegister(imm16(ins))) {
				ok = false;
			}
			else if (op == 0xE9) {
				ok = false;
			}
			else if (isCall(op) || isRst(op) || op == 0xC3 || op == 0xC2 || op == 0xCA ||
				op == 0xD2 || op == 0xDA) {
				int t = isRst(op) ? (op & 0x38) : imm16(ins);
				Address to = calleeAddress(t, ins.getAddress(), new MbcState());
				boolean local = to != null && f.getBody().contains(to);
				if (!local) {
					ok = to != null && preservesBank(to, depth + 1);
				}
			}
		}
		preserves.put(entry, ok);
		return ok;
	}

	// ------------------------------------------------------------------------------------
	// Helpers
	// ------------------------------------------------------------------------------------

	private void findHelpers(TaskMonitor monitor) throws CancelledException {
		helpers = new HashMap<>();
		Listing listing = program.getListing();
		Set<Address> targets = new TreeSet<>();
		for (int v = 0; v < 0x40; v += 8) {
			targets.add(ram.getAddress(v));
		}
		// Call targets in bank 0, from any bank (a jump-table helper is used everywhere).
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction ins = it.next();
			int op = u8(ins, 0);
			if (isCall(op) || op == 0xC3) {
				int t = imm16(ins);
				if (t < 0x4000) {
					targets.add(ram.getAddress(t));
				}
			}
		}
		for (Address t : targets) {
			Helper h = classifyHelper(t);
			if (h != null) {
				helpers.put(t, h);
				String name = switch (h.kind) {
					case FAR_CALL -> "mbc_FarCall";
					case JUMP_TABLE -> "jumptable_Inline";
					default -> "mbc_SetRomBank";
				};
				nameHelper(t, name);
				if (h.kind == JUMP_TABLE) {
					markNoReturn(t);
				}
			}
		}
	}

	/** Calls to an inline jump-table helper never come back to the bytes after the call. */
	private void markNoReturn(Address a) {
		Function f = program.getFunctionManager().getFunctionAt(a);
		if (f == null) {
			AutoAnalysisManager.getAnalysisManager(program).createFunction(a, false);
			return; // marked on the next pass
		}
		if (!f.hasNoReturn()) {
			f.setNoReturn(true);
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

	/**
	 * Straight-line walk from a call target with the registers and RAM as parameters. A
	 * helper is: a bank setter (writes a parameter to the bank register, returns), a far call
	 * (writes a parameter to the bank register, then jumps through an HL built from
	 * parameters, directly or in a called stub), or an inline jump-table dispatcher (pops its
	 * return address into HL and jumps through HL: the table follows the call).
	 */
	private Helper classifyHelper(Address entry) {
		Listing listing = program.getListing();
		State s = new State(true);
		Instruction ins = listing.getInstructionAt(entry);
		int bankWrites = 0;
		Helper h = new Helper();
		boolean inStub = false;
		for (int n = 0; n < MAX_HELPER && ins != null; n++) {
			int op = u8(ins, 0);
			int storeAddr = storeTarget(s, ins);
			if (storeAddr >= 0 && storeAddr < 0x8000 && s.mbcState.isBankRegister(storeAddr)) {
				int v = storeValue(s, ins);
				bankWrites++;
				if (bankWrites == 1) {
					if (!isParam(v)) {
						return null;
					}
					h.regAddr = storeAddr;
					h.bankVal = v;
				}
			}
			if (op == 0xE9) {                                      // JP (HL)
				if (s.poppedReturn && bankWrites == 0) {
					h.kind = JUMP_TABLE;
					return h;
				}
				if (bankWrites >= 1 && isParam(s.r[H]) && isParam(s.r[L])) {
					h.kind = FAR_CALL;
					h.hVal = s.r[H];
					h.lVal = s.r[L];
					return h;
				}
				return null;
			}
			if (op == 0xC9 || op == 0xD9) {                       // RET / RETI
				if (inStub) {
					return null;
				}
				if (bankWrites == 1 && !s.poppedReturn) {
					h.kind = SET_BANK;
					return h;
				}
				return null;
			}
			if (isCall(op) || isRst(op)) {
				// a far call may jump through a stub it calls: walk into it once
				if (op != 0xCD || inStub || bankWrites == 0) {
					return null;
				}
				inStub = true;
				ins = listing.getInstructionAt(ram.getAddress(imm16(ins)));
				continue;
			}
			if (op == 0xC0 || op == 0xC8 || op == 0xD0 || op == 0xD8 || op == 0xC2 ||
				op == 0xCA || op == 0xD2 || op == 0xDA || op == 0x20 || op == 0x28 ||
				op == 0x30 || op == 0x38 || op == 0x10) {
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
			if (next == null || next.getOffset() >= 0x4000 ||
				!next.getAddressSpace().equals(ram)) {
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

	private void processSite(Instruction ins, TaskMonitor monitor) throws CancelledException {
		int op = u8(ins, 0);
		boolean inBank0 = ins.getAddress().getAddressSpace().equals(ram) &&
			ins.getAddress().getOffset() < 0x4000;
		boolean call = isCall(op);
		boolean jump = op == 0xC3 || op == 0xC2 || op == 0xCA || op == 0xD2 || op == 0xDA;
		if (op == 0xCD || isRst(op)) {
			int t = isRst(op) ? (op & 0x38) : imm16(ins);
			Helper jt = t < 0x4000 ? helpers.get(ram.getAddress(t)) : null;
			if (jt != null && jt.kind == JUMP_TABLE) {
				resolveJumpTable(ins, monitor);
				return;
			}
		}
		if (!call && !jump) {
			return;
		}
		int target = imm16(ins);
		Helper h = target < 0x4000 ? helpers.get(ram.getAddress(target)) : null;
		if ((call || op == 0xC3) && h != null && h.farCall()) {
			resolveFarCall(ins, h);
			return;
		}
		if (!inBank0 || target < 0x4000 || target >= 0x8000) {
			return;
		}
		if (alreadyResolved(ins)) {
			return;
		}
		int bank = bankBefore(ins, 0);
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
		return simulateTo(site, 0);
	}

	private State simulateTo(Instruction site, int depth) {
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
		Instruction first = window.isEmpty() ? site : window.peekFirst();
		int assumed = entryBank(first, depth);
		if (window.isEmpty() && assumed < 1) {
			return null;
		}
		State s = new State(false);
		s.mbcState.assumed = assumed;
		for (Instruction ins : window) {
			int op = u8(ins, 0);
			if (isCall(op)) {
				stepCall(s, imm16(ins), ins.getAddress());
				if (op != 0xCD) {
					// conditional call: the callee may or may not have run
					s.setAllUnknown();
					s.mbcState = new MbcState();
				}
				continue;
			}
			if (isRst(op)) {
				stepCall(s, op & 0x38, ins.getAddress());
				continue;
			}
			step(s, ins);
			s.barrier = false;
		}
		return s;
	}

	/**
	 * The bank selected whenever the bank-0 routine starting at {@code first} is entered, if
	 * every way in agrees: a call or jump from bank N's code (bank N is selected while it
	 * runs), from bank-0 code whose own selected bank is known, or an entry of an inline jump
	 * table dispatched with a known bank. -1 if not known or not a routine entry.
	 */
	private int entryBank(Instruction first, int depth) {
		Address a = first.getAddress();
		if (depth > 3 || !a.getAddressSpace().equals(ram) || a.getOffset() >= 0x4000 ||
			program.getFunctionManager().getFunctionAt(a) == null) {
			return -1;
		}
		Integer known = entryBanks.get(a);
		if (known != null) {
			return known;
		}
		entryBanks.put(a, -1); // cycles
		Listing listing = program.getListing();
		Instruction before = listing.getInstructionBefore(a);
		int agreed = -1;
		boolean conflict = before != null && a.equals(before.getFallThrough());
		ReferenceIterator it = program.getReferenceManager().getReferencesTo(a);
		while (!conflict && it.hasNext()) {
			Reference r = it.next();
			Instruction src = listing.getInstructionAt(r.getFromAddress());
			int b = -1;
			if (src != null && r.getReferenceType().isFlow() &&
				!r.getReferenceType().isFallthrough()) {
				b = bankAtSite(src, depth);
			}
			else if (src == null) {
				Instruction site = jumpTableSite(r.getFromAddress());
				b = site == null ? -1 : bankAtSite(site, depth);
			}
			if (b < 1 || (agreed >= 1 && b != agreed)) {
				conflict = true;
			}
			agreed = b;
		}
		int result = conflict ? -1 : agreed;
		entryBanks.put(a, result);
		return result;
	}

	/** The bank selected when {@code ins} executes, or -1. */
	private int bankAtSite(Instruction ins, int depth) {
		if (ins.getAddress().getAddressSpace().isOverlaySpace()) {
			MemoryBlock b = program.getMemory().getBlock(ins.getAddress());
			try {
				return Integer.parseInt(b.getName().substring(5), 16);
			}
			catch (Exception e) {
				return -1;
			}
		}
		return bankBefore(ins, depth + 1);
	}

	/** The bank selected before bank-0 instruction {@code ins}: straight-line, else data flow. */
	private int bankBefore(Instruction ins, int depth) {
		State s = simulateTo(ins, depth);
		int bank = s == null ? -1 : s.mbcState.bank();
		if (bank < 1) {
			State f = flowState(ins, depth);
			bank = f == null ? -1 : f.mbcState.bank();
		}
		return bank;
	}

	/**
	 * The state before {@code ins} from a forward data flow over its function's body (bank 0
	 * only): the selected bank, registers and RAM bytes, met at branch joins, starting from
	 * the routine's entry bank. Cached per function for this pass.
	 */
	private State flowState(Instruction ins, int depth) {
		Address a = ins.getAddress();
		if (!a.getAddressSpace().equals(ram) || a.getOffset() >= 0x4000) {
			return null;
		}
		Function f = program.getFunctionManager().getFunctionContaining(a);
		if (f == null) {
			return null;
		}
		Map<Address, State> in = flows.get(f.getEntryPoint());
		if (in == null) {
			in = new HashMap<>();
			flows.put(f.getEntryPoint(), in); // cycles through entryBank
			computeFlow(f, in, depth);
		}
		return in.get(a);
	}

	private void computeFlow(Function f, Map<Address, State> in, int depth) {
		Listing listing = program.getListing();
		AddressSetView body = f.getBody();
		Address entry = f.getEntryPoint();
		State init = new State(false);
		Instruction first = listing.getInstructionAt(entry);
		if (first == null) {
			return;
		}
		init.mbcState.assumed = entryBank(first, depth);
		in.put(entry, init);
		ArrayDeque<Address> work = new ArrayDeque<>();
		work.add(entry);
		int budget = 64 * (int) Math.min(body.getNumAddresses(), 0x4000);
		while (!work.isEmpty() && budget-- > 0) {
			Address at = work.poll();
			Instruction ins = listing.getInstructionAt(at);
			if (ins == null) {
				continue;
			}
			State s = in.get(at).copy();
			int op = u8(ins, 0);
			if (isCall(op)) {
				stepCall(s, imm16(ins), at);
				if (op != 0xCD) {
					s.setAllUnknown();
					s.mbcState = new MbcState();
				}
			}
			else if (isRst(op)) {
				stepCall(s, op & 0x38, at);
			}
			else {
				step(s, ins);
				s.barrier = false;
			}
			List<Address> next = new ArrayList<>();
			Address ft = ins.getFallThrough();
			if (ft != null) {
				next.add(ft);
			}
			if (!isCall(op) && !isRst(op)) {
				for (Address t : ins.getFlows()) {
					next.add(t);
				}
			}
			for (Address t : next) {
				if (!body.contains(t)) {
					continue;
				}
				State old = in.get(t);
				if (old == null) {
					in.put(t, s.copy());
					work.add(t);
				}
				else if (old.merge(s)) {
					work.add(t);
				}
			}
		}
	}

	/** The dispatch instruction of the inline jump table holding the word at {@code entry}. */
	private Instruction jumpTableSite(Address entry) {
		Instruction site = program.getListing().getInstructionBefore(entry);
		if (site == null) {
			return null;
		}
		String c = program.getListing().getComment(CommentType.EOL, site.getAddress());
		return c != null && c.startsWith("inline jump table") ? site : null;
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
		int a = argument(s, h.bankVal);
		int hi = argument(s, h.hVal), lo = argument(s, h.lVal);
		if (!isConst(a) || !isConst(hi) || !isConst(lo)) {
			return;
		}
		int hl = (hi << 8) | lo;
		boolean hlInRegisters = h.hVal == PARAM + H && h.lVal == PARAM + L;
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
		boolean onLoad = hlInRegisters && s.hlSource != null;
		Address from = onLoad ? s.hlSource : call.getAddress();
		int opIndex = onLoad ? 1 : Reference.MNEMONIC;
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

	/**
	 * A call of an inline jump-table dispatcher ({@code RST}/{@code CALL}, then a table of
	 * 16-bit handler addresses): the call never falls through, so it is made a tail call, the
	 * bytes after it (disassembled by fall-through) are cleared, and the entries are read
	 * until the table runs into the first handler that follows it, a known instruction or
	 * function, or an address that is not code in this bank. Each handler is disassembled
	 * and made a function.
	 */
	private void resolveJumpTable(Instruction site, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		ReferenceManager rm = program.getReferenceManager();
		Address start = site.getMaxAddress().next();
		if (start == null) {
			return;
		}
		if (site.getFlowOverride() == FlowOverride.CALL_RETURN &&
			listing.getDefinedDataAt(start) != null) {
			return; // done on an earlier pass
		}
		MemoryBlock block = program.getMemory().getBlock(start);
		if (block == null || !block.isInitialized()) {
			return;
		}
		site.setFlowOverride(FlowOverride.CALL_RETURN);
		Instruction after = listing.getInstructionAt(start);
		if (after != null && !hasIncomingFlow(rm, start)) {
			new ClearFlowAndRepairCmd(start, true, false, true).applyTo(program, monitor);
		}

		AddressSpace space = start.getAddressSpace();
		boolean overlay = space.isOverlaySpace();
		long end = block.getEnd().getOffset();
		long firstHandler = Long.MAX_VALUE;
		List<Address> targets = new ArrayList<>();
		long p = start.getOffset();
		for (int i = 0; i < 256; i++, p += 2) {
			if (p + 1 > end || p >= firstHandler) {
				break;
			}
			Address pa = space.getAddress(p);
			if (i > 0 && (listing.getInstructionAt(pa) != null ||
				program.getFunctionManager().getFunctionAt(pa) != null ||
				hasIncomingFlow(rm, pa))) {
				break;
			}
			int t;
			try {
				t = (program.getMemory().getByte(pa) & 0xFF) |
					((program.getMemory().getByte(pa.add(1)) & 0xFF) << 8);
			}
			catch (Exception e) {
				break;
			}
			Address ta;
			if (t >= 0x100 && t < 0x4000) {
				ta = ram.getAddress(t);
			}
			else if (t >= 0x4000 && t < 0x8000 && overlay) {
				ta = space.getAddress(t);
			}
			else {
				break;
			}
			boolean sameSpace = ta.getAddressSpace().equals(space);
			if (sameSpace && t >= start.getOffset() && t < p + 2) {
				break; // points into the table
			}
			Instruction containing = listing.getInstructionContaining(ta);
			if ((containing != null && !containing.getAddress().equals(ta)) ||
				listing.getDefinedDataContaining(ta) != null) {
				break;
			}
			if (sameSpace && t > p) {
				firstHandler = Math.min(firstHandler, t);
			}
			targets.add(ta);
		}
		if (targets.isEmpty()) {
			return;
		}
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		for (int i = 0; i < targets.size(); i++) {
			Address pa = start.add(2L * i);
			try {
				DataUtilities.createData(program, pa, WordDataType.dataType, 2,
					DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			}
			catch (Exception e) {
				break;
			}
			rm.addMemoryReference(pa, targets.get(i), RefType.DATA, SourceType.ANALYSIS, 0);
			mgr.disassemble(targets.get(i));
			mgr.createFunction(targets.get(i), false);
		}
		comment(site, "inline jump table, " + targets.size() + " entries");
		tables++;
	}

	private boolean alreadyResolvedFar(Instruction call) {
		String c = program.getListing().getComment(CommentType.EOL, call.getAddress());
		return c != null && c.startsWith("far call to ");
	}
}
