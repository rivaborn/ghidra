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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.console.SegaLoaderBase;
import ghidra.app.util.opinion.console.SegaMasterSystemLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves calls and jumps into the switchable slots of a Sega Master System / Game Gear ROM
 * (Sega, Codemasters or Korean mapper, as recorded by {@link SegaMasterSystemLoader}) to the
 * bank overlay that the preceding straight-line code selected.
 * <p>
 * For every {@code CALL nn}, {@code CALL cc,nn}, {@code JP nn} or {@code JP cc,nn} whose target
 * lies in slot 1 (0x4000-0x7FFF) or slot 2 (0x8000-0xBFFF), it walks backwards along the
 * fall-through chain looking for the write to that slot's paging register: {@code LD (nn),A}
 * with A set by {@code LD A,n} or {@code XOR A}; {@code LD (nn),HL} with HL from
 * {@code LD HL,nn} (slot register = low or high byte); {@code LD (HL),n} or {@code LD (HL),A}
 * with HL = the register address. The walk is conservative: it gives up at any join point
 * (an instruction that is the target of a jump, an entry point or a function start), at any
 * call, at a store through an address it cannot prove constant, and after 32 instructions.
 * <p>
 * When the selected bank is not the slot's power-on bank, an unconditional call or jump gets
 * a primary {@code CALL_OVERRIDE_UNCONDITIONAL} / {@code JUMP_OVERRIDE_UNCONDITIONAL}
 * reference to the overlay address (so the decompiler follows it), a conditional jump a plain
 * {@code CONDITIONAL_JUMP} reference; the target is disassembled and, for calls, a function is
 * created there. An EOL comment names the bank and the instruction that selected it.
 */
public class SegaMapperBankAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Sega Mapper Bank Resolver";
	private static final String DESCRIPTION =
		"Points calls/jumps into Sega Master System / Game Gear mapper slots 1 and 2 at the ROM " +
			"bank overlay selected by a constant write to the paging register (0xFFFE/0xFFFF, " +
			"Codemasters 0x4000/0x8000, Korean 0xA000) in the preceding straight-line code.";

	private static final int MAX_WALK = 32;

	public SegaMapperBankAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.DISASSEMBLY.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	private static String mapper(Program program) {
		Options o = program.getOptions(Program.PROGRAM_INFO);
		return o.getString(SegaLoaderBase.INFO_PREFIX + SegaMasterSystemLoader.INFO_MAPPER,
			null);
	}

	private static int banks(Program program) {
		Options o = program.getOptions(Program.PROGRAM_INFO);
		try {
			return Integer.parseInt(
				o.getString(SegaLoaderBase.INFO_PREFIX + "Banks (16 KB)", "0").trim());
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!"Z80".equalsIgnoreCase(program.getLanguage().getProcessor().toString())) {
			return false;
		}
		String m = mapper(program);
		return m != null && (m.equals("sega") || m.equals("codemasters") || m.equals("korean"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		String mapper = mapper(program);
		int banks = banks(program);
		if (mapper == null || banks <= 0) {
			return false;
		}
		Listing listing = program.getListing();
		InstructionIterator it = listing.getInstructions(set, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction in = it.next();
			byte[] b;
			try {
				b = in.getBytes();
			}
			catch (Exception e) {
				continue;
			}
			if (b.length != 3) {
				continue;
			}
			int op = b[0] & 0xff;
			boolean call = op == 0xCD || (op & 0xC7) == 0xC4;
			boolean jump = op == 0xC3 || (op & 0xC7) == 0xC2;
			if (!call && !jump) {
				continue;
			}
			boolean conditional = op != 0xCD && op != 0xC3;
			int target = (b[1] & 0xff) | ((b[2] & 0xff) << 8);
			int slot = target >= 0x4000 && target < 0x8000 ? 1
					: target >= 0x8000 && target < 0xC000 ? 2 : 0;
			if (slot == 0) {
				continue;
			}
			int reg = SegaMasterSystemLoader.registerAddress(mapper, slot);
			if (reg < 0) {
				continue;
			}
			Resolved r = resolveSlot(program, in, reg);
			if (r == null) {
				continue;
			}
			int bank = r.value % banks;
			String note = String.format("slot %d = bank %d (%s at %s)", slot, bank, r.how,
				r.where);
			if (bank == slot) {
				setEol(listing, in, note);
				continue; // power-on bank: the base block already shows it
			}
			Address dest = SegaLoaderBase.overlayAddress(program,
				SegaMasterSystemLoader.overlayName(bank, slot), target);
			if (dest == null) {
				continue;
			}
			apply(program, in, dest, call, conditional, monitor);
			setEol(listing, in, note + " -> " + dest);
		}
		return true;
	}

	private void setEol(Listing listing, Instruction in, String text) {
		String old = in.getComment(CommentType.EOL);
		if (old == null || !old.contains(text)) {
			listing.setComment(in.getAddress(), CommentType.EOL, text);
		}
	}

	private void apply(Program program, Instruction in, Address dest, boolean call,
			boolean conditional, TaskMonitor monitor) {
		ReferenceManager rm = program.getReferenceManager();
		int opIndex = in.getNumOperands() - 1;
		for (Reference ref : in.getReferencesFrom()) {
			if (ref.getReferenceType().isFlow() && ref.getOperandIndex() >= 0) {
				opIndex = ref.getOperandIndex();
			}
		}
		RefType type = call ? RefType.CALL_OVERRIDE_UNCONDITIONAL
				: conditional ? RefType.CONDITIONAL_JUMP : RefType.JUMP_OVERRIDE_UNCONDITIONAL;
		for (Reference ref : in.getReferencesFrom()) {
			if (ref.getToAddress().equals(dest) && ref.getReferenceType() == type) {
				return; // already done
			}
			if (ref.getReferenceType().isOverride()) {
				rm.delete(ref); // a previous (different) resolution
			}
		}
		Address base = dest.getAddressSpace().getPhysicalSpace().getAddress(dest.getOffset());
		for (Reference r : in.getReferencesFrom()) {
			if (r.getToAddress().equals(base) && r.getReferenceType().isFlow() &&
				!r.getReferenceType().isOverride()) {
				rm.delete(r); // the disassembler's flow into the power-on bank is not taken
			}
		}
		Reference ref = rm.addMemoryReference(in.getAddress(), dest, type, SourceType.ANALYSIS,
			opIndex);
		if (type.isOverride()) {
			rm.setPrimary(ref, true);
		}
		if (program.getListing().getInstructionAt(dest) == null) {
			new DisassembleCommand(dest, null, true).applyTo(program, monitor);
		}
		if ((call || !conditional) && program.getFunctionManager().getFunctionAt(dest) == null) {
			new CreateFunctionCmd(dest).applyTo(program, monitor);
		}
	}

	// ------------------------------------------------------------------ backward walk

	private record Resolved(int value, String how, Address where) {}

	private static Instruction prev(Program program, Instruction in) {
		Address ff = in.getFallFrom();
		return ff == null ? null : program.getListing().getInstructionAt(ff);
	}

	/** True when control can reach {@code in} other than by falling through. */
	private static boolean isJoin(Program program, Instruction in) {
		Address a = in.getAddress();
		if (program.getSymbolTable().isExternalEntryPoint(a) ||
			program.getFunctionManager().getFunctionAt(a) != null) {
			return true;
		}
		ReferenceIterator refs = program.getReferenceManager().getReferencesTo(a);
		while (refs.hasNext()) {
			Reference r = refs.next();
			if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough()) {
				return true;
			}
		}
		return false;
	}

	private static Resolved resolveSlot(Program program, Instruction in, int reg) {
		if (isJoin(program, in)) {
			return null;
		}
		Instruction cur = prev(program, in);
		for (int i = 0; i < MAX_WALK && cur != null; i++) {
			if (cur.getFlowType().isCall()) {
				return null;
			}
			byte[] b;
			try {
				b = cur.getBytes();
			}
			catch (Exception e) {
				return null;
			}
			int op = b[0] & 0xff;
			int nn = b.length >= 3 ? (b[1] & 0xff) | ((b[2] & 0xff) << 8) : -1;
			if (op == 0x32 && b.length == 3 && nn == reg) { // LD (nn),A
				Integer a = resolveReg(program, cur, "A");
				return a == null ? null
						: new Resolved(a, String.format("LD (0x%04X),A", reg), cur.getAddress());
			}
			if (op == 0x22 && b.length == 3 && (nn == reg || nn + 1 == reg)) { // LD (nn),HL
				Integer hl = resolveReg(program, cur, "HL");
				return hl == null ? null
						: new Resolved(nn == reg ? hl & 0xff : hl >> 8,
							String.format("LD (0x%04X),HL", nn), cur.getAddress());
			}
			if ((op == 0x36 && b.length == 2) || (op == 0x77 && b.length == 1)) { // LD (HL),n/A
				Integer hl = resolveReg(program, cur, "HL");
				if (hl == null) {
					return null; // store through an unknown pointer: could be the register
				}
				if (hl == reg) {
					Integer v = op == 0x36 ? Integer.valueOf(b[1] & 0xff)
							: resolveReg(program, cur, "A");
					return v == null ? null
							: new Resolved(v, String.format("LD (HL=0x%04X),%s", reg,
								op == 0x36 ? "n" : "A"), cur.getAddress());
				}
			}
			else if (storesUnknownOrTo(cur, reg)) {
				return null;
			}
			if (isJoin(program, cur)) {
				return null;
			}
			cur = prev(program, cur);
		}
		return null;
	}

	/** Value of register A (via LD A,n / XOR A) or HL (via LD HL,nn) before {@code from}. */
	private static Integer resolveReg(Program program, Instruction from, String name) {
		Register target = program.getRegister(name);
		if (target == null || isJoin(program, from)) {
			return null;
		}
		Instruction cur = prev(program, from);
		for (int i = 0; i < MAX_WALK && cur != null; i++) {
			if (cur.getFlowType().isCall()) {
				return null;
			}
			byte[] b;
			try {
				b = cur.getBytes();
			}
			catch (Exception e) {
				return null;
			}
			int op = b[0] & 0xff;
			if (name.equals("A") && op == 0x3E && b.length == 2) {
				return b[1] & 0xff;
			}
			if (name.equals("A") && op == 0xAF && b.length == 1) {
				return 0;
			}
			if (name.equals("HL") && op == 0x21 && b.length == 3) {
				return (b[1] & 0xff) | ((b[2] & 0xff) << 8);
			}
			for (Object o : cur.getResultObjects()) {
				if (o instanceof Register r && (r.contains(target) || target.contains(r))) {
					return null;
				}
			}
			if (isJoin(program, cur)) {
				return null;
			}
			cur = prev(program, cur);
		}
		return null;
	}

	private static Long constant(Varnode v, java.util.Map<Long, Long> uniq) {
		if (v.isConstant()) {
			return v.getOffset();
		}
		if (v.isUnique()) {
			return uniq.get(v.getOffset());
		}
		return null;
	}

	private static Long fold(PcodeOp p, java.util.Map<Long, Long> uniq) {
		switch (p.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
				return constant(p.getInput(0), uniq);
			case PcodeOp.INT_ADD: {
				Long a = constant(p.getInput(0), uniq);
				Long b = constant(p.getInput(1), uniq);
				return a == null || b == null ? null : (a + b) & 0xffff;
			}
			default:
				return null;
		}
	}

	/** True for a STORE whose address is not a constant, or is the paging register. */
	private static boolean storesUnknownOrTo(Instruction in, int reg) {
		String m = in.getMnemonicString();
		if (m.equalsIgnoreCase("PUSH")) {
			return false; // stack only
		}
		java.util.Map<Long, Long> uniq = new java.util.HashMap<>(); // constant-folded temps
		for (PcodeOp p : in.getPcode()) {
			Varnode out = p.getOutput();
			if (out != null && out.isUnique()) {
				Long v = fold(p, uniq);
				if (v != null) {
					uniq.put(out.getOffset(), v);
				}
				else {
					uniq.remove(out.getOffset());
				}
			}
			if (p.getOpcode() != PcodeOp.STORE) {
				continue;
			}
			Long off = constant(p.getInput(1), uniq);
			if (off == null) {
				return true;
			}
			if (off <= reg && reg < off + p.getInput(2).getSize()) {
				return true;
			}
		}
		return false;
	}
}
