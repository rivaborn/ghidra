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

import static ghidra.app.util.opinion.console.ConsoleExeSupport.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Nintendo DS cartridge images (.nds).
 * <p>
 * Header (little-endian): title 0x00, game code 0x0C, maker 0x10, unit 0x12, ROM version
 * 0x1E; ARM9 rom offset 0x20 / entry 0x24 / load address 0x28 / size 0x2C; ARM7 the same at
 * 0x30-0x3C; FNT 0x40/0x44; FAT 0x48/0x4C; ARM9 overlay table 0x50/0x54; ARM7 overlay table
 * 0x58/0x5C; autoload hooks 0x70/0x74; logo CRC16 0x15C (0xCF56); header CRC16 0x15E over
 * 0x000-0x15D.
 * <p>
 * One program holds one CPU: the ARM9 (ARMv5TE, language ARM:LE:32:v5t, preferred load spec) or
 * the ARM7 (ARMv4T, ARM:LE:32:v4t, the second load spec). The ARM9 main module is
 * decompressed if it is BLZ-compressed (module parameters), its autoload segments (ITCM/DTCM)
 * are placed at their destinations, and the overlays of the chosen CPU are loaded as overlay
 * blocks at their RAM addresses (decompressed when flagged).
 */
public class NdsLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Nintendo DS ROM";

	static final String LANG_ARM9 = "ARM:LE:32:v5t";
	static final String LANG_ARM7 = "ARM:LE:32:v4t";
	static final String OPT_OVERLAYS = "Load overlays";
	static final String OPT_DTCM = "DTCM address (when no autoload names it)";

	/** Little-endian bytes of the nitrocode pair 0xDEC00621, 0x2106C0DE. */
	private static final byte[] NITROCODE =
		{ 0x21, 0x06, (byte) 0xC0, (byte) 0xDE, (byte) 0xDE, (byte) 0xC0, 0x06, 0x21 };

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	static boolean inMainRam(long a) {
		return a >= 0x02000000L && a < 0x02400000L;
	}

	/** Detection: header CRC or logo CRC, plus sane ARM9 / ARM7 fields. */
	public static boolean isNds(byte[] h, long fileLength) {
		if (h.length < 0x160 || fileLength < 0x200) {
			return false;
		}
		boolean crcOk = crc16(h, 0, 0x15E) == le16(h, 0x15E);
		boolean logoOk = le16(h, 0x15C) == 0xCF56;
		if (!crcOk && !logoOk) {
			return false;
		}
		long off9 = u(le32(h, 0x20)), entry9 = u(le32(h, 0x24)), ram9 = u(le32(h, 0x28)),
				size9 = u(le32(h, 0x2C));
		if (size9 == 0 || off9 < 0x160 || off9 + size9 > fileLength || !inMainRam(ram9) ||
			ram9 + size9 > 0x02400000L || entry9 < ram9 || entry9 >= ram9 + size9) {
			return false;
		}
		long off7 = u(le32(h, 0x30)), ram7 = u(le32(h, 0x38)), size7 = u(le32(h, 0x3C));
		if (size7 != 0) {
			boolean ramOk = inMainRam(ram7) || (ram7 >= 0x037F8000L && ram7 < 0x03810000L);
			if (off7 < 0x160 || off7 + size7 > fileLength || !ramOk) {
				return false;
			}
		}
		return true;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < 0x200) {
			return specs;
		}
		byte[] h = provider.readBytes(0, 0x200);
		if (isNds(h, provider.length())) {
			specs.add(new LoadSpec(this, 0, pair(LANG_ARM9, "default"), true));
			if (u(le32(h, 0x3C)) != 0) {
				specs.add(new LoadSpec(this, 0, pair(LANG_ARM7, "default"), false));
			}
		}
		return specs;
	}

	private static List<Option> myOptions() {
		return List.of(
			new Option(OPT_OVERLAYS, true, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-overlays"),
			new Option(OPT_DTCM, new ghidra.app.util.HexLong(0x027E0000L),
				ghidra.app.util.HexLong.class, Loader.COMMAND_LINE_ARG_PREFIX + "-dtcm"));
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		list.addAll(myOptions());
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String r = validateTypes(options, myOptions());
		return r != null ? r : super.validateOptions(provider, loadSpec, options, program);
	}

	/**
	 * Decompresses a backward-LZ ("BLZ") region: {@code data[0..compEnd)} ends with an 8-byte
	 * footer (u32 compressed length | header length << 24, u32 size increase). Bytes before the
	 * compressed region are kept as they are. Returns the expanded buffer.
	 */
	public static byte[] blzDecompress(byte[] data, int compEnd) throws IOException {
		if (compEnd < 8 || compEnd > data.length) {
			throw new IOException("BLZ: bad compressed end");
		}
		int info = le32(data, compEnd - 8);
		int compLen = info & 0xFFFFFF;
		int hdrLen = (info >>> 24) & 0xFF;
		int inc = le32(data, compEnd - 4);
		if (hdrLen < 8 || compLen < hdrLen || compLen > compEnd || inc < 0 ||
			inc > 0x01000000) {
			throw new IOException("BLZ: bad footer");
		}
		// compressed bytes are read from 'data', so in-place overlap is not an issue here
		byte[] out = new byte[compEnd + inc];
		System.arraycopy(data, 0, out, 0, compEnd);
		int src = compEnd - hdrLen;
		int dst = compEnd + inc;
		int stop = compEnd - compLen;
		while (src > stop) {
			int flags = data[--src] & 0xFF;
			for (int bit = 0; bit < 8 && src > stop; bit++, flags <<= 1) {
				if ((flags & 0x80) != 0) {
					if (src - 2 < stop) {
						throw new IOException("BLZ: truncated back-reference");
					}
					int hi = data[--src] & 0xFF;
					int lo = data[--src] & 0xFF;
					int v = (hi << 8) | lo;
					int n = (v >>> 12) + 3;
					int disp = (v & 0xFFF) + 3;
					if (dst - n < 0 || dst - 1 + disp >= out.length) {
						throw new IOException("BLZ: bad back-reference");
					}
					for (int k = 0; k < n; k++) {
						dst--;
						out[dst] = out[dst + disp];
					}
				}
				else {
					if (dst <= 0) {
						throw new IOException("BLZ: overrun");
					}
					out[--dst] = data[--src];
				}
			}
		}
		return out;
	}

	static int indexOf(byte[] b, byte[] pat) {
		outer: for (int i = 0; i + pat.length <= b.length; i += 4) {
			for (int j = 0; j < pat.length; j++) {
				if (b[i + j] != pat[j]) {
					continue outer;
				}
			}
			return i;
		}
		return -1;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		byte[] h = provider.readBytes(0, 0x200);
		if (!isNds(h, provider.length())) {
			throw new IOException("Not an NDS ROM");
		}
		boolean arm7 = settings.loadSpec()
				.getLanguageCompilerSpec().languageID.getIdAsString()
				.equals(LANG_ARM7);
		int base = arm7 ? 0x30 : 0x20;
		long romOff = u(le32(h, base)), entry = u(le32(h, base + 4)),
				ram = u(le32(h, base + 8)), size = u(le32(h, base + 0xC));
		String cpu = arm7 ? "arm7" : "arm9";
		FileBytes fb = MemoryBlockUtils.createFileBytes(program, provider, monitor);

		byte[] image = provider.readBytes(romOff, size);
		String notes = "";
		long[] params = null;
		int paramsOff = -1;
		if (!arm7) {
			// secure area
			if (romOff == 0x4000 && size >= 8) {
				if (le32(image, 0) == 0xE7FFDEFF && le32(image, 4) == 0xE7FFDEFF) {
					notes += "secure area decrypted (E7FFDEFF marker); ";
				}
				else {
					notes += "secure area at 0x4000 lacks the decrypted marker (may be encrypted); ";
				}
			}
			// module parameters: nitrocode footer after the ARM9 in the ROM, else a search
			if (romOff + size + 12 <= provider.length()) {
				byte[] foot = provider.readBytes(romOff + size, 12);
				if (le32(foot, 0) == 0xDEC00621) {
					paramsOff = le32(foot, 4);
				}
			}
			if (paramsOff < 0 || paramsOff + 0x24 > image.length) {
				int at = indexOf(image, NITROCODE);
				paramsOff = at >= 0x1C ? at - 0x1C : -1;
			}
			if (paramsOff >= 0 && paramsOff + 0x24 <= image.length &&
				le32(image, paramsOff + 0x1C) == 0xDEC00621) {
				params = new long[7];
				for (int i = 0; i < 7; i++) {
					params[i] = u(le32(image, paramsOff + i * 4));
				}
				long compEnd = params[5];
				if (compEnd != 0) {
					int ce = (int) (compEnd - ram);
					try {
						image = blzDecompress(image, ce);
						// like the runtime decompressor, clear compressed_static_end
						image[paramsOff + 0x14] = image[paramsOff + 0x15] =
							image[paramsOff + 0x16] = image[paramsOff + 0x17] = 0;
						notes += "ARM9 BLZ-compressed, expanded " + hex(size) + " -> " +
							hex(image.length) + "; ";
					}
					catch (IOException e) {
						notes += "ARM9 compressed but decompression failed: " + e.getMessage() +
							"; ";
						log.appendMsg(e.getMessage());
					}
				}
			}
			else {
				notes += "no module parameters found; ";
			}
		}

		// main module
		if (image.length == size) {
			fileBlock(program, fb, cpu, ram, romOff, size, true, true, true,
				cpu.toUpperCase() + " binary (ROM " + hex(romOff) + ")", log);
		}
		else {
			bytesBlock(program, cpu, ram, image, true, true, true,
				cpu.toUpperCase() + " binary (ROM " + hex(romOff) + ", decompressed)", log,
				monitor);
		}

		// autoload segments (ITCM/DTCM...)
		boolean dtcmSeen = false;
		if (params != null) {
			long listStart = params[0], listEnd = params[1], dataPtr = params[2];
			int n = 0;
			for (long p = listStart; p + 12 <= listEnd && n < 32; p += 12, n++) {
				int o = (int) (p - ram);
				if (o < 0 || o + 12 > image.length) {
					break;
				}
				long dest = u(le32(image, o)), len = u(le32(image, o + 4)),
						bss = u(le32(image, o + 8));
				int src = (int) (dataPtr - ram);
				String name = dest < 0x02000000L ? "itcm"
						: (dest >= 0x02400000L && dest < 0x03000000L) ? "dtcm" : "autoload" + n;
				if (name.equals("dtcm")) {
					dtcmSeen = true;
				}
				if (src >= 0 && src + len <= image.length && len > 0) {
					MemoryBlock blk = bytesBlock(program, name, dest, image, src, (int) len, false,
						true, true, true, "Autoload segment " + n + " (from " + hex(dataPtr) + ")",
						log, monitor);
					if (blk != null) {
						label(program, blk.getStart(), name + "_start");
					}
				}
				if (bss > 0) {
					fillGaps(program, name + "_bss", dest + len, bss, true, true, false,
						"Autoload segment " + n + " BSS", log);
				}
				dataPtr += len;
			}
			if (params[4] > params[3]) {
				fillGaps(program, "arm9_bss", params[3], params[4] - params[3], true, true,
					false, "ARM9 static BSS", log);
				label(program, params[3], "__bss_start");
				label(program, params[4], "__bss_end");
			}
			label(program, ram + paramsOff, "_start_ModuleParams");
			StructureDataType mp = struct("NDS_ModuleParams", "autoload_list_start", u32(),
				"autoload_list_end", u32(), "autoload_start", u32(), "static_bss_start", u32(),
				"static_bss_end", u32(), "compressed_static_end", u32(), "sdk_version", u32(),
				"nitro_code_be", u32(), "nitro_code_le", u32());
			createData(program, addr(program, ram + paramsOff), mp, log);
		}

		// overlays of this CPU
		int ovCount = 0;
		if (optionBool(options, OPT_OVERLAYS, true)) {
			ovCount = loadOverlays(program, provider, h, arm7, log, monitor);
		}

		// memory map
		fillGaps(program, "main_ram", 0x02000000L, 0x400000L, true, true, true,
			"Main RAM (4 MB)", log);
		if (arm7) {
			fillGaps(program, "shared_wram", 0x037F8000L, 0x8000, true, true, true,
				"Shared WRAM (ARM7 view)", log);
			fillGaps(program, "arm7_wram", 0x03800000L, 0x10000, true, true, true,
				"ARM7 WRAM (64 KB)", log);
			ioBlock(program, "io", 0x04000000L, 0x600, "ARM7 I/O", log);
			ioBlock(program, "io_ipc", 0x04100000L, 0x20, "IPC FIFO / card data", log);
			ioBlock(program, "wifi", 0x04800000L, 0x10000, "Wi-Fi registers and RAM", log);
			uninitBlock(program, "bios7", 0x00000000L, 0x4000, true, false, true, false,
				"ARM7 BIOS (16 KB, not in the ROM)", log);
			registers(program, ARM7_REGISTERS, log);
		}
		else {
			fillGaps(program, "itcm", 0x01FF8000L, 0x8000, true, true, true,
				"ITCM (32 KB; mirrored below 0x02000000)", log);
			if (!dtcmSeen) {
				fillGaps(program, "dtcm", optionLong(options, OPT_DTCM, 0x027E0000L), 0x4000,
					true, true, false, "DTCM (16 KB; address set by CP15, option)", log);
			}
			fillGaps(program, "shared_wram", 0x03000000L, 0x8000, true, true, true,
				"Shared WRAM (ARM9 view)", log);
			ioBlock(program, "io", 0x04000000L, 0x1100, "ARM9 I/O (engine A, B at 0x04001000)",
				log);
			ioBlock(program, "io_ipc", 0x04100000L, 0x20, "IPC FIFO / card data", log);
			uninitBlock(program, "palette", 0x05000000L, 0x800, true, true, false, false,
				"Palettes", log);
			uninitBlock(program, "vram_bg_a", 0x06000000L, 0x80000, true, true, false, false,
				"VRAM engine A BG", log);
			uninitBlock(program, "vram_bg_b", 0x06200000L, 0x20000, true, true, false, false,
				"VRAM engine B BG", log);
			uninitBlock(program, "vram_obj_a", 0x06400000L, 0x40000, true, true, false, false,
				"VRAM engine A OBJ", log);
			uninitBlock(program, "vram_obj_b", 0x06600000L, 0x20000, true, true, false, false,
				"VRAM engine B OBJ", log);
			uninitBlock(program, "vram_lcdc", 0x06800000L, 0xA4000, true, true, false, false,
				"VRAM LCDC", log);
			uninitBlock(program, "oam", 0x07000000L, 0x800, true, true, false, false, "OAM",
				log);
			uninitBlock(program, "bios9", 0xFFFF0000L, 0x8000, true, false, true, false,
				"ARM9 BIOS (not in the ROM)", log);
			registers(program, GbaLoader.lcdRegisters(), log);
			registers(program, ARM9_REGISTERS, log);
		}

		// entry
		setRegister(program, "TMode", entry, entry, 0, log);
		entry(program, entry, "_start");
		long hook = u(le32(h, arm7 ? 0x74 : 0x70));
		if (hook != 0) {
			function(program, hook, cpu + "_autoload_done_hook");
		}

		StructureDataType hs = struct("NDS_Header", "title", 12, "game_code", 4, "maker_code",
			2, "unit_code", u8(), "seed_select", u8(), "device_capacity", u8(), "reserved1",
			bytes(7), "dsi_flags", u8(), "nds_region", u8(), "rom_version", u8(), "autostart",
			u8(), "arm9_rom_offset", u32(), "arm9_entry", u32(), "arm9_ram_address", u32(),
			"arm9_size", u32(), "arm7_rom_offset", u32(), "arm7_entry", u32(),
			"arm7_ram_address", u32(), "arm7_size", u32(), "fnt_offset", u32(), "fnt_size",
			u32(), "fat_offset", u32(), "fat_size", u32(), "arm9_overlay_offset", u32(),
			"arm9_overlay_size", u32(), "arm7_overlay_offset", u32(), "arm7_overlay_size",
			u32(), "card_control_normal", u32(), "card_control_key1", u32(), "icon_offset",
			u32(), "secure_area_crc", u16(), "secure_area_delay", u16(), "arm9_autoload_hook",
			u32(), "arm7_autoload_hook", u32(), "secure_area_disable", bytes(8),
			"total_rom_size", u32(), "header_size", u32(), "reserved2", bytes(0x38), "logo",
			bytes(0x9C), "logo_crc", u16(), "header_crc", u16());
		headerBlock(program, fb, 0, hs, "NDS_HEADER", log);

		info(program, "NDS title", ascii(h, 0, 12));
		info(program, "NDS game code", ascii(h, 0x0C, 4) + " maker " + ascii(h, 0x10, 2) +
			" version " + (h[0x1E] & 0xFF) + " unit " + (h[0x12] & 0xFF));
		info(program, "NDS CPU loaded", cpu.toUpperCase());
		info(program, "NDS " + cpu + " binary", "ROM " + hex(romOff) + " -> " + hex(ram) +
			" size " + hex(size) + " entry " + hex(entry));
		info(program, "NDS overlays loaded", Integer.toString(ovCount));
		info(program, "NDS header CRC", (crc16(h, 0, 0x15E) == le16(h, 0x15E) ? "valid" : "INVALID") +
			", logo CRC " + hex(le16(h, 0x15C)));
		if (!notes.isEmpty()) {
			info(program, "NDS notes", notes.trim());
		}
		plate(program, entry, "NDS " + cpu.toUpperCase() + " entry: " + ascii(h, 0, 12) + " (" +
			ascii(h, 0x0C, 4) + ")" + (notes.isEmpty() ? "" : "\n" + notes.trim()));
	}

	private int loadOverlays(Program program, ByteProvider provider, byte[] h, boolean arm7,
			MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {
		long ovtOff = u(le32(h, arm7 ? 0x58 : 0x50)), ovtSize = u(le32(h, arm7 ? 0x5C : 0x54));
		long fatOff = u(le32(h, 0x48)), fatSize = u(le32(h, 0x4C));
		long len = provider.length();
		if (ovtSize == 0 || ovtOff + ovtSize > len || fatOff + fatSize > len) {
			return 0;
		}
		byte[] ovt = provider.readBytes(ovtOff, ovtSize);
		int count = 0;
		for (int i = 0; i + 32 <= ovt.length; i += 32) {
			monitor.checkCancelled();
			long id = u(le32(ovt, i)), ram = u(le32(ovt, i + 4)), ramSize = u(le32(ovt, i + 8)),
					bss = u(le32(ovt, i + 12)), sinitStart = u(le32(ovt, i + 16)),
					sinitEnd = u(le32(ovt, i + 20)), fileId = u(le32(ovt, i + 24)),
					flags = u(le32(ovt, i + 28));
			if (fileId * 8 + 8 > fatSize) {
				log.appendMsg("Overlay " + id + ": file id " + fileId + " outside the FAT");
				continue;
			}
			byte[] fe = provider.readBytes(fatOff + fileId * 8, 8);
			long start = u(le32(fe, 0)), end = u(le32(fe, 4));
			if (end < start || end > len) {
				log.appendMsg("Overlay " + id + ": bad FAT entry");
				continue;
			}
			byte[] data = provider.readBytes(start, end - start);
			boolean compressed = (flags & 0x01000000L) != 0;
			String comment = "Overlay " + id + " (file " + fileId + ", ROM " + hex(start) + ")";
			if (compressed) {
				int compSize = (int) (flags & 0xFFFFFF);
				try {
					data = blzDecompress(data, compSize > 0 && compSize <= data.length
							? compSize : data.length);
					comment += ", BLZ-decompressed";
				}
				catch (IOException e) {
					log.appendMsg("Overlay " + id + ": " + e.getMessage());
					comment += ", COMPRESSED (decompression failed)";
				}
			}
			String name = String.format("%s_ov_%02d", arm7 ? "arm7" : "arm9", id);
			byte[] withBss = Arrays.copyOf(data, (int) (data.length + bss));
			if (bss > 0) {
				comment += ", BSS " + hex(ram + data.length) + "+" + hex(bss) + " zero-filled";
			}
			MemoryBlock blk = bytesBlock(program, name, ram, withBss, 0, withBss.length, true,
				true, true, true, comment, log, monitor);
			if (blk != null) {
				count++;
				if (sinitStart != 0 && sinitEnd > sinitStart) {
					try {
						program.getSymbolTable()
								.createLabel(blk.getStart().add(sinitStart - ram),
									name + "_sinit_start",
									ghidra.program.model.symbol.SourceType.IMPORTED);
					}
					catch (Exception e) {
						// outside the block
					}
				}
			}
		}
		return count;
	}

	static final Object[][] ARM9_REGISTERS = { { 0x04000180L, "REG_IPCSYNC", 2 },
		{ 0x04000184L, "REG_IPCFIFOCNT", 2 }, { 0x04000188L, "REG_IPCFIFOSEND", 4 },
		{ 0x040001A0L, "REG_AUXSPICNT", 2 }, { 0x040001A2L, "REG_AUXSPIDATA", 2 },
		{ 0x040001A4L, "REG_ROMCTRL", 4 }, { 0x040001A8L, "REG_CARD_COMMAND", 8 },
		{ 0x04000204L, "REG_EXMEMCNT", 2 }, { 0x04000208L, "REG_IME", 4 },
		{ 0x04000210L, "REG_IE", 4 }, { 0x04000214L, "REG_IF", 4 },
		{ 0x04000240L, "REG_VRAMCNT_A", 1 }, { 0x04000241L, "REG_VRAMCNT_B", 1 },
		{ 0x04000242L, "REG_VRAMCNT_C", 1 }, { 0x04000243L, "REG_VRAMCNT_D", 1 },
		{ 0x04000244L, "REG_VRAMCNT_E", 1 }, { 0x04000245L, "REG_VRAMCNT_F", 1 },
		{ 0x04000246L, "REG_VRAMCNT_G", 1 }, { 0x04000247L, "REG_WRAMCNT", 1 },
		{ 0x04000248L, "REG_VRAMCNT_H", 1 }, { 0x04000249L, "REG_VRAMCNT_I", 1 },
		{ 0x04000280L, "REG_DIVCNT", 2 }, { 0x04000290L, "REG_DIV_NUMER", 8 },
		{ 0x04000298L, "REG_DIV_DENOM", 8 }, { 0x040002A0L, "REG_DIV_RESULT", 8 },
		{ 0x040002A8L, "REG_DIVREM_RESULT", 8 }, { 0x040002B0L, "REG_SQRTCNT", 2 },
		{ 0x040002B4L, "REG_SQRT_RESULT", 4 }, { 0x040002B8L, "REG_SQRT_PARAM", 8 },
		{ 0x04000300L, "REG_POSTFLG", 1 }, { 0x04000304L, "REG_POWCNT1", 2 },
		{ 0x04001000L, "REG_DISPCNT_SUB", 4 }, { 0x04100000L, "REG_IPCFIFORECV", 4 },
		{ 0x04100010L, "REG_CARD_DATA_RD", 4 } };

	static final Object[][] ARM7_REGISTERS = { { 0x040000B0L, "REG_DMA0SAD", 4 },
		{ 0x04000100L, "REG_TM0CNT_L", 2 }, { 0x04000130L, "REG_KEYINPUT", 2 },
		{ 0x04000134L, "REG_RCNT", 2 }, { 0x04000136L, "REG_EXTKEYIN", 2 },
		{ 0x04000138L, "REG_RTC", 1 }, { 0x04000180L, "REG_IPCSYNC", 2 },
		{ 0x04000184L, "REG_IPCFIFOCNT", 2 }, { 0x04000188L, "REG_IPCFIFOSEND", 4 },
		{ 0x040001A0L, "REG_AUXSPICNT", 2 }, { 0x040001A4L, "REG_ROMCTRL", 4 },
		{ 0x040001C0L, "REG_SPICNT", 2 }, { 0x040001C2L, "REG_SPIDATA", 2 },
		{ 0x04000208L, "REG_IME", 4 }, { 0x04000210L, "REG_IE", 4 },
		{ 0x04000214L, "REG_IF", 4 }, { 0x04000241L, "REG_WRAMSTAT", 1 },
		{ 0x04000300L, "REG_POSTFLG", 1 }, { 0x04000301L, "REG_HALTCNT", 1 },
		{ 0x04000304L, "REG_POWCNT2", 2 }, { 0x04000400L, "REG_SOUND0CNT", 4 },
		{ 0x04000500L, "REG_SOUNDCNT", 2 }, { 0x04000504L, "REG_SOUNDBIAS", 2 },
		{ 0x04100000L, "REG_IPCFIFORECV", 4 } };
}
