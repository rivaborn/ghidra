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

import static ghidra.app.util.opinion.console.NintendoCartUtil.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Nintendo Game Boy / Game Boy Color cartridge images (.gb / .gbc).
 * <p>
 * Detected by the Nintendo logo at 0x104-0x133. Bank 0 is mapped at 0000-3FFF; with a memory
 * bank controller each switchable 16 KB bank N (N &ge; 1) is an overlay block {@code bank_NN}
 * of 4000-7FFF (a 32 KB cartridge without MBC maps 4000-7FFF directly). VRAM, cartridge RAM
 * (banked as overlays {@code sram_NN}), WRAM (CGB banks 2-7 as overlays {@code wram_NN}),
 * echo RAM (a byte-mapped mirror of C000), OAM, I/O, HRAM and IE are created as in the
 * hardware; the RST / interrupt vectors, the entry point (0x100) and the header fields are
 * labelled. The hardware registers are named by the LR35902 processor specification (its
 * labels are applied because the I/O blocks carry the pspec block names {@code IO} and
 * {@code IE_REG}).
 */
public class GameBoyLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Nintendo Game Boy ROM";
	public static final String LANGUAGE_ID = "LR35902:LE:16:default";
	public static final String COMPILER_ID = "default";

	public static final String OPT_MBC = "Game Boy MBC";
	public static final String OPT_BANK1_VIEW = "Game Boy bank 1 view at 4000";

	/** Program-information keys read by GameBoyBankAnalyzer. */
	public static final String INFO_MBC = "Game Boy MBC";
	public static final String INFO_BANKS = "Game Boy ROM Banks";

	/** The 48-byte Nintendo logo bitmap at 0x104-0x133 checked by the boot ROM. */
	public static final byte[] LOGO = bytes(0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B,
		0x03, 0x73, 0x00, 0x83, 0x00, 0x0C, 0x00, 0x0D, 0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00,
		0x0E, 0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99, 0xBB, 0xBB, 0x67, 0x63, 0x6E, 0x0E,
		0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E);

	private static byte[] bytes(int... v) {
		byte[] b = new byte[v.length];
		for (int i = 0; i < v.length; i++) {
			b[i] = (byte) v[i];
		}
		return b;
	}

	/** Memory bank controller families. */
	public enum Mbc {
		NONE, MBC1, MBC1M, MBC2, MBC3, MBC5, MBC6, MBC7, MMM01, HUC1, HUC3, CAMERA, TAMA5, UNKNOWN
	}

	/** Cartridge type byte (0x147) to (MBC, description). */
	public static Mbc mbcOf(int type) {
		return switch (type) {
			case 0x00, 0x08, 0x09 -> Mbc.NONE;
			case 0x01, 0x02, 0x03 -> Mbc.MBC1;
			case 0x05, 0x06 -> Mbc.MBC2;
			case 0x0B, 0x0C, 0x0D -> Mbc.MMM01;
			case 0x0F, 0x10, 0x11, 0x12, 0x13 -> Mbc.MBC3;
			case 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E -> Mbc.MBC5;
			case 0x20 -> Mbc.MBC6;
			case 0x22 -> Mbc.MBC7;
			case 0xFC -> Mbc.CAMERA;
			case 0xFD -> Mbc.TAMA5;
			case 0xFE -> Mbc.HUC3;
			case 0xFF -> Mbc.HUC1;
			default -> Mbc.UNKNOWN;
		};
	}

	public static String cartTypeName(int type) {
		return switch (type) {
			case 0x00 -> "ROM ONLY";
			case 0x01 -> "MBC1";
			case 0x02 -> "MBC1+RAM";
			case 0x03 -> "MBC1+RAM+BATTERY";
			case 0x05 -> "MBC2";
			case 0x06 -> "MBC2+BATTERY";
			case 0x08 -> "ROM+RAM";
			case 0x09 -> "ROM+RAM+BATTERY";
			case 0x0B -> "MMM01";
			case 0x0C -> "MMM01+RAM";
			case 0x0D -> "MMM01+RAM+BATTERY";
			case 0x0F -> "MBC3+TIMER+BATTERY";
			case 0x10 -> "MBC3+TIMER+RAM+BATTERY";
			case 0x11 -> "MBC3";
			case 0x12 -> "MBC3+RAM";
			case 0x13 -> "MBC3+RAM+BATTERY";
			case 0x19 -> "MBC5";
			case 0x1A -> "MBC5+RAM";
			case 0x1B -> "MBC5+RAM+BATTERY";
			case 0x1C -> "MBC5+RUMBLE";
			case 0x1D -> "MBC5+RUMBLE+RAM";
			case 0x1E -> "MBC5+RUMBLE+RAM+BATTERY";
			case 0x20 -> "MBC6";
			case 0x22 -> "MBC7+SENSOR+RUMBLE+RAM+BATTERY";
			case 0xFC -> "POCKET CAMERA";
			case 0xFD -> "BANDAI TAMA5";
			case 0xFE -> "HuC3";
			case 0xFF -> "HuC1+RAM+BATTERY";
			default -> "unknown";
		};
	}

	/** Parsed cartridge header. */
	public static final class GbHeader {
		public byte[] h;           // file bytes 0x000-0x14F
		public long fileSize;
		public boolean multicart;  // MBC1M (logo repeated at 0x40104)

		public int cartType() {
			return h[0x147] & 0xFF;
		}

		public int romSizeCode() {
			return h[0x148] & 0xFF;
		}

		public int ramSizeCode() {
			return h[0x149] & 0xFF;
		}

		public int cgbFlag() {
			return h[0x143] & 0xFF;
		}

		public boolean isCgb() {
			return (cgbFlag() & 0x80) != 0;
		}

		public int headerChecksum() {
			return h[0x14D] & 0xFF;
		}

		public int computedHeaderChecksum() {
			int x = 0;
			for (int i = 0x134; i <= 0x14C; i++) {
				x = x - (h[i] & 0xFF) - 1;
			}
			return x & 0xFF;
		}

		public int globalChecksum() {
			return ((h[0x14E] & 0xFF) << 8) | (h[0x14F] & 0xFF);
		}

		public String title() {
			return ascii(h, 0x134, isCgb() ? 15 : 16);
		}

		/** ROM banks declared by the header (0 if unknown code). */
		public int declaredBanks() {
			int c = romSizeCode();
			if (c <= 0x08) {
				return 2 << c;
			}
			return switch (c) {
				case 0x52 -> 72;
				case 0x53 -> 80;
				case 0x54 -> 96;
				default -> 0;
			};
		}

		public long ramSize() {
			return switch (ramSizeCode()) {
				case 0x01 -> 0x800;
				case 0x02 -> 0x2000;
				case 0x03 -> 0x8000;
				case 0x04 -> 0x20000;
				case 0x05 -> 0x10000;
				default -> 0;
			};
		}
	}

	/**
	 * Detection: file at least 0x150 bytes and the 48-byte Nintendo logo at 0x104.
	 */
	public static GbHeader detect(ByteProvider provider) throws IOException {
		long len = provider.length();
		if (len < 0x150) {
			return null;
		}
		byte[] logo = provider.readBytes(0x104, LOGO.length);
		if (!Arrays.equals(logo, LOGO)) {
			return null;
		}
		GbHeader g = new GbHeader();
		g.h = provider.readBytes(0, 0x150);
		g.fileSize = len;
		if (mbcOf(g.cartType()) == Mbc.MBC1 && len == 0x100000) {
			byte[] l2 = provider.readBytes(0x40104, LOGO.length);
			g.multicart = Arrays.equals(l2, LOGO);
		}
		return g;
	}

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
		return 50;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (detect(provider) != null && languageExists(getLanguageService(), LANGUAGE_ID)) {
			specs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(LANGUAGE_ID, COMPILER_ID), true));
		}
		return specs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(new Option(OPT_MBC, "auto", String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-gbMbc"));
		list.add(new Option(OPT_BANK1_VIEW, Boolean.FALSE, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-gbBank1View"));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout));
		return list;
	}

	private static final String[] MBC_CHOICES =
		{ "auto", "none", "mbc1", "mbc1m", "mbc2", "mbc3", "mbc5", "mbc6", "mbc7", "mmm01",
			"huc1", "huc3", "camera", "tama5" };

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String err = checkChoice(options, OPT_MBC, MBC_CHOICES);
		if (err != null) {
			return err;
		}
		List<Option> rest = new ArrayList<>();
		for (Option o : options) {
			if (!o.getName().startsWith("Game Boy ")) {
				rest.add(o);
			}
		}
		return super.validateOptions(provider, loadSpec, rest, program);
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, ImporterSettings settings) {
		// The loader creates the whole memory map itself (with the pspec block names).
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		GbHeader g = detect(provider);
		if (g == null) {
			throw new IOException("Not a Game Boy ROM (Nintendo logo not found at 0x104)");
		}
		String mbcOpt = stringOption(settings.options(), OPT_MBC, "auto").toLowerCase();
		Mbc mbc = mbcOpt.equals("auto")
				? (g.multicart ? Mbc.MBC1M : mbcOf(g.cartType()))
				: Mbc.valueOf(mbcOpt.toUpperCase());
		boolean bank1View = boolOption(settings.options(), OPT_BANK1_VIEW, false);

		FileBytes fb = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
		long size = g.fileSize;
		int banks = (int) ((size + 0x3FFF) / 0x4000);
		if (g.declaredBanks() != 0 && g.declaredBanks() != banks) {
			log.appendMsg("ROM size in header (" + g.declaredBanks() + " banks) differs from " +
				"the file (" + banks + " banks); the file size is used");
		}
		int digits = banks > 0x100 ? 3 : 2;

		romBlock(program, fb, "ROM0", ram.getAddress(0), 0, Math.min(0x4000, size), false,
			"ROM bank 0 (fixed)", log);
		boolean banked = mbc != Mbc.NONE || banks > 2;
		if (!banked) {
			if (size > 0x4000) {
				romBlock(program, fb, "ROM1", ram.getAddress(0x4000), 0x4000,
					Math.min(0x4000, size - 0x4000), false, "ROM bank 1 (no MBC)", log);
			}
		}
		else {
			for (int i = 1; i < banks; i++) {
				monitor.checkCancelled();
				long off = (long) i * 0x4000;
				romBlock(program, fb, "bank_" + hex(i, digits), ram.getAddress(0x4000), off,
					Math.min(0x4000, size - off), true,
					String.format("switchable ROM bank %d (file 0x%X) at 4000-7FFF", i, off),
					log);
			}
			if (bank1View && banks > 1) {
				MemoryBlock b1 = program.getMemory().getBlock("bank_" + hex(1, digits));
				if (b1 != null) {
					mirrorBlock(program, "ROMX_bank1", ram.getAddress(0x4000), b1.getStart(),
						b1.getSize(), false, true, false,
						"view of bank 1 (the bank selected at power-on)", log);
				}
			}
		}

		ramBlock(program, "VRAM", ram.getAddress(0x8000), 0x2000, false, false, false,
			"video RAM" + (g.isCgb() ? " (CGB bank 0)" : ""), log);
		if (g.isCgb()) {
			ramBlock(program, "VRAM_1", ram.getAddress(0x8000), 0x2000, true, false, false,
				"CGB video RAM bank 1 (VBK=1)", log);
		}

		// Cartridge RAM
		long ramSize = g.ramSize();
		if (mbc == Mbc.MBC2) {
			ramBlock(program, "SRAM", ram.getAddress(0xA000), 0x200, false, false, false,
				"MBC2 built-in RAM: 512 x 4 bits (mirrored to BFFF)", log);
		}
		else if (ramSize > 0) {
			int rbanks = (int) Math.max(1, ramSize / 0x2000);
			ramBlock(program, "SRAM", ram.getAddress(0xA000), Math.min(0x2000, ramSize), false,
				false, false, "cartridge RAM bank 0 (" + ramSize / 1024 + " KB total)", log);
			for (int i = 1; i < rbanks; i++) {
				ramBlock(program, "sram_" + hex(i, 2), ram.getAddress(0xA000), 0x2000, true,
					false, false, "cartridge RAM bank " + i, log);
			}
		}
		if (mbc == Mbc.MBC3 && (g.cartType() == 0x0F || g.cartType() == 0x10)) {
			info(program, "Game Boy RTC",
				"MBC3 real-time clock: registers 08-0C selected through 4000-5FFF, " +
					"read/written at A000-BFFF, latched by writing 00 then 01 to 6000-7FFF");
		}

		ramBlock(program, "WRAM0", ram.getAddress(0xC000), 0x1000, false, true, false,
			"work RAM bank 0", log);
		ramBlock(program, "WRAMX", ram.getAddress(0xD000), 0x1000, false, true, false,
			"work RAM bank 1" + (g.isCgb() ? " (CGB: switchable 1-7 via SVBK)" : ""), log);
		if (g.isCgb()) {
			for (int i = 2; i < 8; i++) {
				ramBlock(program, "wram_" + hex(i, 2), ram.getAddress(0xD000), 0x1000, true,
					true, false, "CGB work RAM bank " + i, log);
			}
		}
		mirrorBlock(program, "ECHO", ram.getAddress(0xE000), ram.getAddress(0xC000), 0x1E00,
			true, true, false, "echo RAM (mirror of C000-DDFF)", log);
		ramBlock(program, "OAM", ram.getAddress(0xFE00), 0xA0, false, false, false,
			"object attribute memory", log);
		ramBlock(program, "IO", ram.getAddress(0xFF00), 0x80, false, false, true,
			"I/O registers", log);
		ramBlock(program, "HRAM", ram.getAddress(0xFF80), 0x7F, false, true, false,
			"high RAM", log);
		ramBlock(program, "IE_REG", ram.getAddress(0xFFFF), 1, false, false, true,
			"interrupt enable register", log);

		labelVectorsAndHeader(program, ram, g, log);
		writeInfo(program, g, mbc, banks);
	}

	private static final Object[][] VECTORS = { { 0x00, "RST_00" }, { 0x08, "RST_08" },
		{ 0x10, "RST_10" }, { 0x18, "RST_18" }, { 0x20, "RST_20" }, { 0x28, "RST_28" },
		{ 0x30, "RST_30" }, { 0x38, "RST_38" }, { 0x40, "INT_VBLANK" }, { 0x48, "INT_STAT" },
		{ 0x50, "INT_TIMER" }, { 0x58, "INT_SERIAL" }, { 0x60, "INT_JOYPAD" } };

	private void labelVectorsAndHeader(Program program, AddressSpace ram, GbHeader g,
			MessageLog log) {
		for (Object[] v : VECTORS) {
			int off = (Integer) v[0];
			int b = g.h[off] & 0xFF;
			Address a = ram.getAddress(off);
			if (b == 0xFF || b == 0x00) {
				label(program, a, (String) v[1], "unused vector (filler byte)", true);
			}
			else {
				entry(program, a, (String) v[1], true);
			}
		}
		entry(program, ram.getAddress(0x100), "ENTRY", true);

		Object[][] fields = { { 0x104, "hdr_nintendo_logo", new ArrayDataType(
			ByteDataType.dataType, 48, 1) },
			{ 0x134, "hdr_title", new StringDataType(), g.isCgb() ? 15 : 16 },
			{ 0x143, "hdr_cgb_flag", ByteDataType.dataType },
			{ 0x144, "hdr_new_licensee", new StringDataType(), 2 },
			{ 0x146, "hdr_sgb_flag", ByteDataType.dataType },
			{ 0x147, "hdr_cartridge_type", ByteDataType.dataType },
			{ 0x148, "hdr_rom_size", ByteDataType.dataType },
			{ 0x149, "hdr_ram_size", ByteDataType.dataType },
			{ 0x14A, "hdr_destination", ByteDataType.dataType },
			{ 0x14B, "hdr_old_licensee", ByteDataType.dataType },
			{ 0x14C, "hdr_version", ByteDataType.dataType },
			{ 0x14D, "hdr_header_checksum", ByteDataType.dataType },
			{ 0x14E, "hdr_global_checksum", new ArrayDataType(ByteDataType.dataType, 2, 1) } };
		for (Object[] f : fields) {
			Address a = ram.getAddress((Integer) f[0]);
			label(program, a, (String) f[1], null, true);
			DataType dt = (DataType) f[2];
			if (dt instanceof StringDataType && f.length > 3) {
				try {
					DataUtilities.createData(program, a, dt, (Integer) f[3],
						DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				}
				catch (Exception e) {
					// ignore
				}
			}
			else {
				data(program, a, dt);
			}
		}
		label(program, ram.getAddress(0x104), "CART_HEADER", null, false);
	}

	private void writeInfo(Program program, GbHeader g, Mbc mbc, int banks) {
		info(program, "Game Boy Title", g.title());
		info(program, "Game Boy Cartridge Type",
			String.format("0x%02X %s", g.cartType(), cartTypeName(g.cartType())));
		info(program, INFO_MBC, mbc.name() + (g.multicart ? " (multicart detected)" : ""));
		info(program, INFO_BANKS, Integer.toString(banks));
		info(program, "Game Boy ROM Size", String.format("code 0x%02X (%d banks declared), " +
			"file %d KB", g.romSizeCode(), g.declaredBanks(), g.fileSize / 1024));
		info(program, "Game Boy RAM Size",
			String.format("code 0x%02X (%d KB)", g.ramSizeCode(), g.ramSize() / 1024));
		info(program, "Game Boy CGB Flag", String.format("0x%02X %s", g.cgbFlag(),
			g.cgbFlag() == 0xC0 ? "(CGB only)"
					: g.cgbFlag() == 0x80 ? "(CGB enhanced, DMG compatible)" : "(DMG)"));
		info(program, "Game Boy SGB Flag", String.format("0x%02X", g.h[0x146] & 0xFF));
		info(program, "Game Boy Header Checksum", String.format("stored 0x%02X, computed " +
			"0x%02X (%s)", g.headerChecksum(), g.computedHeaderChecksum(),
			g.headerChecksum() == g.computedHeaderChecksum() ? "match" : "MISMATCH"));
		info(program, "Game Boy Global Checksum", String.format("0x%04X", g.globalChecksum()));
		info(program, "Game Boy Version", Integer.toString(g.h[0x14C] & 0xFF));
		if (mbc == Mbc.MBC6 || mbc == Mbc.MMM01 || mbc == Mbc.TAMA5 || mbc == Mbc.UNKNOWN) {
			info(program, "Game Boy Mapping Note", mbc.name() + ": banks mapped as generic " +
				"16 KB overlays of 4000-7FFF; the controller's exact windows are not modelled");
		}
	}
}
