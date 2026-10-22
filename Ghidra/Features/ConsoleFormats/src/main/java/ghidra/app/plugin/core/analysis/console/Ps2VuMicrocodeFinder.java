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

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds PlayStation 2 Vector Unit microcode carried by an Emotion Engine (R5900) program.
 * <p>
 * EE programs upload microprograms to VU0/VU1 micro memory through the VIF, with the
 * {@code MPG} VIFcode inside a DMA chain:
 * <pre>
 *   VIFcode = CMD(8) NUM(8) IMMEDIATE(16)      (little-endian 32-bit word)
 *   MPG     : CMD = 0x4A (bit 7 = interrupt bit, ignored)
 *             NUM = number of 64-bit LIWs that follow (0 means 256)
 *             IMMEDIATE = load address in micro memory, in 8-byte units
 * </pre>
 * The LIWs must start on a 64-bit boundary of the transfer, so the MPG code itself sits at an
 * address that is 4 modulo 8. Other VIFcodes (NOP, STCYCL, FLUSHE, FLUSHA, ...) and a DMAtag
 * usually precede it; MSCAL/MSCALF/MSCNT often follow it.
 * <p>
 * A candidate is accepted when its LIWs decode with the PS2VU language (most of them; zero
 * LIWs decode too, so they count as filler), when it is not mostly zero, and when it looks like
 * VU code (upper or lower NOPs, an E bit, or the LIWs after the packet are VIFcodes).
 * Each accepted packet is a {@link Find}; {@link #group(List)} merges back-to-back packets that
 * continue each other in micro memory (programs longer than 256 LIWs).
 */
public class Ps2VuMicrocodeFinder {

	public static final String VU1_LANGUAGE = "PS2VU:LE:32:VU1";
	public static final String VU0_LANGUAGE = "PS2VU:LE:32:VU0";

	public static final int VIF_MPG = 0x4A;
	public static final int VIF_MSCAL = 0x14;
	public static final int VIF_MSCALF = 0x15;
	public static final int VIF_MSCNT = 0x17;

	public static final int UPPER_NOP = 0x000002FF;
	public static final int LOWER_NOP = 0x8000033C;
	private static final int UPPER_EBIT = 0x40000000;

	/** One MPG packet. */
	public static class Find {
		/** Address of the MPG VIFcode. */
		public Address vifAddress;
		/** Address of the first LIW (vifAddress + 4). */
		public Address codeAddress;
		/** Load address in micro memory, in bytes. */
		public int microAddress;
		/** Number of LIWs. */
		public int numInstructions;
		/** LIWs that decode with the PS2VU language. */
		public int validInstructions;
		/** LIWs that are entirely zero. */
		public int zeroInstructions;
		/** LIWs with the E bit set. */
		public int endInstructions;
		/** Upper or lower NOPs seen. */
		public int nopCount;
		/** VIFcode names seen right before the packet (closest last). */
		public List<String> before = new ArrayList<>();
		/** VIFcode names seen right after the packet. */
		public List<String> after = new ArrayList<>();
		/** Micro-memory start addresses (bytes) given by MSCAL/MSCALF after the packet. */
		public List<Integer> callTargets = new ArrayList<>();

		public int lengthBytes() {
			return numInstructions * 8;
		}

		public double score() {
			return numInstructions == 0 ? 0 : (double) validInstructions / numInstructions;
		}

		@Override
		public String toString() {
			return String.format(
				"MPG at %s: code %s, %d LIWs -> micro 0x%04x-0x%04x, %d/%d decode, %d E-bit%s%s%s",
				vifAddress, codeAddress, numInstructions, microAddress,
				microAddress + lengthBytes() - 1, validInstructions, numInstructions,
				endInstructions, before.isEmpty() ? "" : ", before: " + String.join(" ", before),
				after.isEmpty() ? "" : ", after: " + String.join(" ", after),
				callTargets.isEmpty() ? "" : ", MSCAL " + hexList(callTargets));
		}
	}

	/** Back-to-back packets that load one contiguous range of micro memory. */
	public static class Group {
		public List<Find> packets = new ArrayList<>();

		public Find first() {
			return packets.get(0);
		}

		public int microAddress() {
			return first().microAddress;
		}

		public int lengthBytes() {
			int n = 0;
			for (Find f : packets) {
				n += f.lengthBytes();
			}
			return n;
		}

		public List<Integer> callTargets() {
			List<Integer> l = new ArrayList<>();
			for (Find f : packets) {
				for (Integer t : f.callTargets) {
					if (!l.contains(t)) {
						l.add(t);
					}
				}
			}
			return l;
		}

		@Override
		public String toString() {
			return String.format("VU microprogram at %s: %d packet(s), micro 0x%04x-0x%04x (%d LIWs)",
				first().vifAddress, packets.size(), microAddress(),
				microAddress() + lengthBytes() - 1, lengthBytes() / 8);
		}
	}

	private final Language vuLanguage;
	private final ProcessorContextImpl context;
	private final int microSize;
	private double minValidRatio = 0.9;
	private int minInstructions = 2;
	private boolean requireAlignment = true;

	/**
	 * @param vuLanguage a PS2VU language (VU1 or VU0), used to decide whether LIWs decode
	 */
	public Ps2VuMicrocodeFinder(Language vuLanguage) {
		this.vuLanguage = vuLanguage;
		this.context = new ProcessorContextImpl(vuLanguage);
		this.microSize = isVu0(vuLanguage) ? 0x1000 : 0x4000;
	}

	/**
	 * {@return the PS2VU language}
	 * @param vu0 true for VU0, false for VU1
	 * @throws LanguageNotFoundException if the PS2VU processor module is not installed
	 */
	public static Language getVuLanguage(boolean vu0) throws LanguageNotFoundException {
		return DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID(vu0 ? VU0_LANGUAGE : VU1_LANGUAGE));
	}

	public static boolean isVu0(Language language) {
		return language.getLanguageID().getIdAsString().equals(VU0_LANGUAGE);
	}

	/** {@return true if the program is an R5900 (Emotion Engine) program} */
	public static boolean isR5900(Program program) {
		return program.getLanguageID().getIdAsString().contains("R5900");
	}

	public void setMinValidRatio(double ratio) {
		this.minValidRatio = ratio;
	}

	public void setMinInstructions(int n) {
		this.minInstructions = n;
	}

	/** @param b true (default) to require the MPG code at an address that is 4 modulo 8 */
	public void setRequireAlignment(boolean b) {
		this.requireAlignment = b;
	}

	/**
	 * Scans the initialized memory of a program for MPG packets.
	 *
	 * @param program the EE program
	 * @param set the addresses to scan, or null for all initialized memory
	 * @param monitor task monitor
	 * @return the accepted packets, in address order
	 * @throws CancelledException if cancelled
	 */
	public List<Find> find(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		List<Find> finds = new ArrayList<>();
		Memory memory = program.getMemory();
		AddressSetView scan = memory.getLoadedAndInitializedAddressSet();
		if (set != null) {
			scan = scan.intersect(set);
		}
		monitor.setMessage("Scanning for VU microcode (VIF MPG)");
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized() || !scan.intersects(block.getStart(), block.getEnd())) {
				continue;
			}
			byte[] bytes = new byte[(int) Math.min(block.getSize(), Integer.MAX_VALUE - 16)];
			try {
				block.getBytes(block.getStart(), bytes);
			}
			catch (MemoryAccessException e) {
				continue;
			}
			long base = block.getStart().getOffset();
			int first = (int) ((4 - (base & 3)) & 3);
			for (int i = first; i + 4 <= bytes.length; i += 4) {
				if ((i & 0xFFFF) == 0) {
					monitor.checkCancelled();
				}
				if ((bytes[i + 3] & 0x7F) != VIF_MPG) {
					continue;
				}
				Address vifAddr = block.getStart().add(i);
				if (!scan.contains(vifAddr)) {
					continue;
				}
				if (requireAlignment && ((base + i) & 7) != 4) {
					continue;
				}
				Find f = check(bytes, i, block.getStart());
				if (f != null) {
					finds.add(f);
					i += f.lengthBytes(); // skip the packet body
				}
			}
		}
		return finds;
	}

	/**
	 * Checks one candidate MPG VIFcode at {@code bytes[i]}.
	 *
	 * @param bytes buffer
	 * @param i index of the VIFcode
	 * @param bufStart address of bytes[0]
	 * @return the find, or null if rejected
	 */
	public Find check(byte[] bytes, int i, Address bufStart) {
		int code = word(bytes, i);
		int num = (code >>> 16) & 0xFF;
		if (num == 0) {
			num = 256;
		}
		int microAddr = (code & 0xFFFF) * 8;
		if (num < minInstructions || microAddr + num * 8 > microSize) {
			return null;
		}
		int start = i + 4;
		if (start + num * 8 > bytes.length) {
			return null;
		}
		Find f = new Find();
		f.vifAddress = bufStart.add(i);
		f.codeAddress = bufStart.add(start);
		f.microAddress = microAddr;
		f.numInstructions = num;
		AddressSpace vuSpace = vuLanguage.getAddressFactory().getDefaultAddressSpace();
		for (int k = 0; k < num; k++) {
			int p = start + k * 8;
			int lo = word(bytes, p);
			int up = word(bytes, p + 4);
			if (lo == 0 && up == 0) {
				f.zeroInstructions++;
			}
			if ((up & UPPER_EBIT) != 0) {
				f.endInstructions++;
			}
			if ((up & 0x07FFFFFF) == UPPER_NOP || lo == LOWER_NOP) {
				f.nopCount++;
			}
			if (decodes(bytes, p, vuSpace.getAddress((microAddr + k * 8) % microSize))) {
				f.validInstructions++;
			}
		}
		if (f.score() < minValidRatio || f.zeroInstructions * 2 > num) {
			return null;
		}
		// context: VIFcodes before and after
		for (int k = 1; k <= 4 && i - 4 * k >= 0; k++) {
			String n = vifName(word(bytes, i - 4 * k));
			if (n == null) {
				break;
			}
			f.before.add(0, n);
		}
		int end = start + num * 8;
		for (int k = 0; k < 4 && end + 4 * k + 4 <= bytes.length; k++) {
			int w = word(bytes, end + 4 * k);
			String n = vifName(w);
			if (n == null) {
				break;
			}
			f.after.add(n);
			int cmd = (w >>> 24) & 0x7F;
			if (cmd == VIF_MSCAL || cmd == VIF_MSCALF) {
				f.callTargets.add((w & 0xFFFF) * 8);
			}
			if (cmd == VIF_MPG) {
				break;
			}
		}
		boolean looksLikeVu = f.nopCount > 0 || f.endInstructions > 0;
		boolean hasVifContext = !f.before.isEmpty() || !f.after.isEmpty();
		if (!looksLikeVu && !hasVifContext) {
			return null;
		}
		return f;
	}

	private boolean decodes(byte[] bytes, int p, Address addr) {
		byte[] liw = new byte[16];
		System.arraycopy(bytes, p, liw, 0, Math.min(16, bytes.length - p));
		try {
			MemBuffer buf = new ByteMemBufferImpl(addr, liw, false);
			vuLanguage.parse(buf, context, false);
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	/**
	 * Groups packets that follow each other in EE memory (only VIF NOPs in between) and
	 * continue each other in micro memory.
	 *
	 * @param finds the packets, in address order
	 * @return the groups
	 */
	public static List<Group> group(List<Find> finds) {
		List<Group> groups = new ArrayList<>();
		Group cur = null;
		for (Find f : finds) {
			if (cur != null) {
				Find last = cur.packets.get(cur.packets.size() - 1);
				Address lastEnd = last.codeAddress.add(last.lengthBytes());
				long gap = f.vifAddress.subtract(lastEnd);
				boolean adjacent = f.vifAddress.getAddressSpace()
						.equals(last.vifAddress.getAddressSpace()) && gap >= 0 && gap <= 12;
				if (adjacent && f.microAddress == last.microAddress + last.lengthBytes()) {
					cur.packets.add(f);
					continue;
				}
			}
			cur = new Group();
			cur.packets.add(f);
			groups.add(cur);
		}
		return groups;
	}

	/**
	 * Reads the LIWs of a group (the bytes after each VIFcode, without the VIFcodes).
	 *
	 * @param program the EE program
	 * @param g the group
	 * @return the microcode bytes
	 * @throws MemoryAccessException if the bytes cannot be read
	 */
	public static byte[] readCode(Program program, Group g) throws MemoryAccessException {
		byte[] out = new byte[g.lengthBytes()];
		int pos = 0;
		for (Find f : g.packets) {
			int n = program.getMemory().getBytes(f.codeAddress, out, pos, f.lengthBytes());
			if (n != f.lengthBytes()) {
				throw new MemoryAccessException("Short read at " + f.codeAddress);
			}
			pos += n;
		}
		return out;
	}

	/**
	 * {@return the name of a plausible VIFcode, or null}
	 * @param w the 32-bit word
	 */
	public static String vifName(int w) {
		int cmd = (w >>> 24) & 0x7F;
		int num = (w >>> 16) & 0xFF;
		int imm = w & 0xFFFF;
		switch (cmd) {
			case 0x00:
				return (num == 0 && imm == 0) ? "NOP" : null;
			case 0x01:
				return num == 0 ? "STCYCL" : null;
			case 0x02:
				return "OFFSET";
			case 0x03:
				return "BASE";
			case 0x04:
				return "ITOP";
			case 0x05:
				return "STMOD";
			case 0x06:
				return "MSKPATH3";
			case 0x07:
				return "MARK";
			case 0x10:
				return (num == 0 && imm == 0) ? "FLUSHE" : null;
			case 0x11:
				return (num == 0 && imm == 0) ? "FLUSH" : null;
			case 0x13:
				return (num == 0 && imm == 0) ? "FLUSHA" : null;
			case VIF_MSCAL:
				return String.format("MSCAL(0x%x)", imm * 8);
			case VIF_MSCALF:
				return String.format("MSCALF(0x%x)", imm * 8);
			case VIF_MSCNT:
				return "MSCNT";
			case 0x20:
				return "STMASK";
			case 0x30:
				return "STROW";
			case 0x31:
				return "STCOL";
			case VIF_MPG:
				return "MPG";
			case 0x50:
				return "DIRECT";
			case 0x51:
				return "DIRECTHL";
			default:
				return (cmd >= 0x60 && cmd <= 0x7F) ? "UNPACK" : null;
		}
	}

	static String hexList(List<Integer> l) {
		StringBuilder sb = new StringBuilder();
		for (Integer v : l) {
			if (sb.length() > 0) {
				sb.append(',');
			}
			sb.append(String.format("0x%x", v));
		}
		return sb.toString();
	}

	private static int word(byte[] b, int i) {
		return (b[i] & 0xFF) | (b[i + 1] & 0xFF) << 8 | (b[i + 2] & 0xFF) << 16 |
			(b[i + 3] & 0xFF) << 24;
	}
}
