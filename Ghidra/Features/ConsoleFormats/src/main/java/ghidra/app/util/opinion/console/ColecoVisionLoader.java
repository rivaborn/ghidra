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

import static ghidra.app.util.opinion.console.MicroFormatsSupport.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;

/**
 * ColecoVision cartridge (.col/.rom/.bin): ROM at 0x8000 starting with 0xAA55 (title screen) or
 * 0x55AA (skip title), start-game vector at 0x800A, RST 08..38 jumps at 0x800C..0x801E and the
 * NMI jump at 0x8021. Images above 32 KB are MegaCart: 16 KB banks, the last bank fixed at
 * 0x8000 and the others switched into 0xC000-0xFFFF (overlay blocks).
 */
public class ColecoVisionLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "ColecoVision Cartridge";
	static final LanguageCompilerSpecPair LANG = new LanguageCompilerSpecPair("z80:LE:16:default",
		"default");
	static final int BANK = 0x4000;

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.GENERIC_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 60;
	}

	static boolean magic(byte[] b, int off) {
		int a = b[off] & 0xff, c = b[off + 1] & 0xff;
		return (a == 0xAA && c == 0x55) || (a == 0x55 && c == 0xAA);
	}

	/** Header file offset (0, or the last 16 KB bank for MegaCart), or -1. */
	static int headerOffset(ByteProvider p) throws IOException {
		long len = p.length();
		if (len < 0x24 || len > 0x100000) {
			return -1;
		}
		if (len > 0x8000 && len % BANK == 0) {
			int off = (int) (len - BANK);
			if (plausible(p.readBytes(off, 0x24))) {
				return off;
			}
		}
		return plausible(p.readBytes(0, 0x24)) ? 0 : -1;
	}

	static boolean plausible(byte[] h) {
		if (!magic(h, 0)) {
			return false;
		}
		int start = u16le(h, 0x0A);
		return start >= 0x8000;
	}

	/** Counts vector slots that look like JP/RET/RETN/EI/zero. */
	static int vectorSlots(byte[] h) {
		int ok = 0;
		for (int off = 0x0C; off <= 0x21; off += 3) {
			int op = h[off] & 0xff;
			if (op == 0xC3 || op == 0xC9 || op == 0xED || op == 0xFB || op == 0x00) {
				ok++;
			}
		}
		return ok;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		int off = headerOffset(provider);
		if (off < 0) {
			return specs;
		}
		String ext = extension(provider);
		boolean extOk = ext.equals("col") || ext.equals("rom") || ext.equals("bin");
		if (extOk || vectorSlots(provider.readBytes(off, 0x24)) >= 4) {
			specs.add(new LoadSpec(this, 0, LANG, true));
		}
		return specs;
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, ImporterSettings settings) {
		// none for z80
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		MessageLog log = settings.log();
		ByteProvider p = settings.provider();
		AddressSpace mem = program.getAddressFactory().getDefaultAddressSpace();
		AddressSpace io = program.getAddressFactory().getAddressSpace("io");
		int hdr = headerOffset(p);
		if (hdr < 0) {
			throw new IOException("No ColecoVision header");
		}
		FileBytes fb = MemoryBlockUtils.createFileBytes(program, p, settings.monitor());
		long len = p.length();
		byte[] h = p.readBytes(hdr, 0x24);

		if (hdr == 0) {
			long size = Math.min(len, 0x8000);
			if (len > 0x8000) {
				log.appendMsg("Image above 32 KB without a MegaCart layout; only the first 32 KB" +
					" are mapped");
			}
			fileBlock(program, "ROM", mem.getAddress(0x8000), fb, 0, size, false, true, false,
				true, "cartridge ROM", log);
			property(program, "ColecoVision layout", "plain " + size / 1024 + " KB at 0x8000");
		}
		else {
			int banks = (int) (len / BANK);
			int last = banks - 1;
			fileBlock(program, String.format("BANK%02d_FIXED", last), mem.getAddress(0x8000), fb,
				(long) last * BANK, BANK, false, true, false, true,
				"MegaCart last bank, fixed at 0x8000", log);
			fileBlock(program, "BANK00", mem.getAddress(0xC000), fb, 0, BANK, false, true, false,
				true, "MegaCart bank 0 in the 0xC000 window", log);
			for (int b = 1; b < last; b++) {
				fileBlock(program, String.format("BANK%02d", b), mem.getAddress(0xC000), fb,
					(long) b * BANK, BANK, true, true, false, true,
					String.format("MegaCart bank %d (file 0x%X), overlay of 0xC000", b, b * BANK),
					log);
			}
			for (int b = 0; b < Math.min(banks, 64); b++) {
				label(program, mem.getAddress(0xFFC0 + b), String.format("MEGACART_SEL_BANK%02d", b),
					true, log);
			}
			program.getListing()
					.setComment(mem.getAddress(0xFFC0), CommentType.PRE,
						"reading 0xFFC0+n selects bank n (mod bank count) into 0xC000-0xFFFF");
			property(program, "ColecoVision layout",
				"MegaCart, " + banks + " banks of 16 KB, header in bank " + last);
		}

		fillGaps(program, mem, "BIOS", 0x0000, 0x1FFF, true, false, true, false,
			"ColecoVision BIOS (OS7) ROM, not loaded", log);
		fillGaps(program, mem, "EXPANSION", 0x2000, 0x5FFF, true, true, true, false,
			"expansion port", log);
		MemoryBlock ramBlock = uninitBlock(program, "RAM", mem.getAddress(0x7000), 0x400, false,
			true, true, true, false, "1 KB RAM", log);
		if (ramBlock != null) {
			for (long a = 0x6000; a < 0x8000; a += 0x400) {
				if (a == 0x7000) {
					continue;
				}
				MemoryBlockUtils.createByteMappedBlock(program,
					String.format("RAM_MIRROR_%04X", a), mem.getAddress(a),
					mem.getAddress(0x7000), 0x400, "mirror of RAM 0x7000-0x73FF", null, true,
					true, true, false, log);
			}
		}
		fillGaps(program, mem, "MEGACART_WINDOW", 0xC000, 0xFFFF, true, false, true, false,
			"unused (no MegaCart)", log);
		if (io != null) {
			uninitBlock(program, "IO_PORTS", io.getAddress(0), 0x100, false, true, true, false,
				true, "Z80 I/O ports", log);
			labelTable(program, io, IO_PORTS, log);
		}

		// header
		Address base = mem.getAddress(0x8000);
		boolean title = (h[0] & 0xff) == 0xAA;
		property(program, "ColecoVision header",
			(title ? "0xAA55 (title screen)" : "0x55AA (no title screen)") +
				String.format(" start %s", hex(u16le(h, 0x0A), 4)));
		String[] ptrs = { "LOCAL_SPR_TBL", "SPRITE_ORDER", "WORK_BUFFER", "CONTROLLER_MAP",
			"START_GAME_PTR" };
		try {
			program.getListing().createData(base, WordDataType.dataType);
			for (int i = 0; i < ptrs.length; i++) {
				Address a = base.add(2 + 2 * i);
				program.getListing().createData(a, PointerDataType.dataType);
				label(program, a, ptrs[i], true, log);
			}
			label(program, base, "CART_HEADER", true, log);
			program.getListing()
					.setComment(base, CommentType.PLATE,
						"ColecoVision cartridge header (0xAA55 = show title, 0x55AA = skip)");
			// game name "LINE2/LINE1/YEAR" at 0x8024 (only if it looks like text)
			byte[] name = p.readBytes(hdr + 0x24, Math.min(0x40, len - hdr - 0x24));
			int n = 0;
			while (n < name.length && name[n] >= 0x20 && name[n] < 0x7F) {
				n++;
			}
			if (n >= 4) {
				program.getListing().createData(base.add(0x24), new StringDataType(), n);
				label(program, base.add(0x24), "GAME_NAME", true, log);
				property(program, "ColecoVision name", new String(name, 0, n, "US-ASCII"));
			}
		}
		catch (Exception e) {
			log.appendMsg("Header markup: " + e.getMessage());
		}
		String[] vec = { "RST_08", "RST_10", "RST_18", "RST_20", "RST_28", "RST_30", "RST_38",
			"NMI" };
		for (int i = 0; i < vec.length; i++) {
			Address a = base.add(0x0C + 3 * i);
			int op = h[0x0C + 3 * i] & 0xff;
			if (op == 0xC3 || op == 0xC9 || op == 0xED || op == 0xFB) {
				entry(program, a, vec[i] + "_VECTOR", log);
			}
			else {
				label(program, a, vec[i] + "_VECTOR", true, log);
			}
		}
		entry(program, mem.getAddress(u16le(h, 0x0A)), "start_game", log);
	}

	static final Object[][] IO_PORTS = { { 0x80, "CTRL_SET_KEYPAD" }, { 0xBE, "VDP_DATA" },
		{ 0xBF, "VDP_CTRL" }, { 0xC0, "CTRL_SET_JOYSTICK" }, { 0xFC, "CTRL1_READ" },
		{ 0xFF, "SN76489_W_CTRL2_R" } };
}
