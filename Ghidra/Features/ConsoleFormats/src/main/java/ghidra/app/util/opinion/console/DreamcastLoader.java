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

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Sega Dreamcast boot area: a bare IP.BIN, or a data track image starting with it (GD-ROM
 * {@code track03.iso/.bin}, a MIL-CD data session, 2048-byte or raw 2352-byte sectors).
 * <p>
 * Detection: ASCII "SEGA SEGAKATANA " (16 bytes) at the first byte of user data: file offset 0,
 * or 16 / 24 for a raw image (sync 00 FF x10 00 at offset 0, mode byte at 15 = 1 / 2).
 * <p>
 * IP.BIN (0x8000 bytes) is mapped at 0x8C008000; the boot ROM starts it at 0x8C008300. The boot
 * file name (16 bytes at 0x60, normally "1ST_READ.BIN") is recorded, and when the image has an
 * ISO 9660 root directory containing that file, it is loaded at 0x8C010000 (descrambled when it
 * looks scrambled, see {@link SegaDreamcastScramble}).
 */
public class DreamcastLoader extends SegaLoaderBase {

	public static final String NAME = "Sega Dreamcast IP.BIN / disc image";
	public static final String LANGUAGE = "SuperH4:LE:32:default";
	public static final String MAGIC = "SEGA SEGAKATANA ";
	public static final long IP_ADDRESS = 0x8C008000L;
	public static final long FIRST_READ_ADDRESS = 0x8C010000L;

	static final String OPT_LOAD_BOOT = "Load the boot file from the disc image";
	static final String OPT_DESCRAMBLE = "Descramble boot file (auto|yes|no)";
	static final String OPT_MIRRORS = "Map RAM mirrors at 0x0C000000 and 0xAC000000";

	@Override
	public String getName() {
		return NAME;
	}

	static boolean detect(ByteProvider provider) throws IOException {
		long off = SegaDiscImage.bootDataOffset(provider);
		return startsWith(read(provider, off, 16), 0, MAGIC);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		return detect(provider) ? spec(this, LANGUAGE, true) : List.of();
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(boolOpt(OPT_LOAD_BOOT, true, "loadBootFile"));
		list.add(stringOpt(OPT_DESCRAMBLE, "auto", "descramble"));
		list.add(boolOpt(OPT_MIRRORS, false, "ramMirrors"));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String err = validateOwn(options, Map.of(OPT_LOAD_BOOT, Boolean.class, OPT_DESCRAMBLE,
			String.class, OPT_MIRRORS, Boolean.class));
		if (err == null) {
			err = checkDescramble(options);
		}
		return err != null ? err : super.validateOptions(provider, loadSpec, options, program);
	}

	static String checkDescramble(List<Option> options) {
		String d = stringOption(options, OPT_DESCRAMBLE, "auto").toLowerCase();
		return List.of("auto", "yes", "no").contains(d) ? null
				: OPT_DESCRAMBLE + ": expected auto, yes or no";
	}

	/** Applies the descramble option; returns the image to load and records what was done. */
	static byte[] bootImage(Program program, byte[] stored, List<Option> options) {
		String d = stringOption(options, OPT_DESCRAMBLE, "auto").toLowerCase();
		boolean scrambled = d.equals("yes") ||
			(d.equals("auto") && SegaDreamcastScramble.looksScrambled(stored));
		info(program, "Boot file scrambled", (scrambled ? "yes" : "no") + " (option " + d +
			", code score stored " + SegaDreamcastScramble.score(stored) + " / descrambled " +
			SegaDreamcastScramble.score(SegaDreamcastScramble.descramble(stored)) + ")");
		return scrambled ? SegaDreamcastScramble.descramble(stored) : stored;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		SegaDiscImage disc = new SegaDiscImage(provider);
		byte[] ip = disc.read(0, 0x8000);
		FileBytes fb = !disc.isRaw() && provider.length() == ip.length
				? program.getMemory()
						.createFileBytes(provider.getName(), 0, ip.length,
							provider.getInputStream(0), monitor)
				: fileBytes(program, provider.getName() + " (IP.BIN)", ip, monitor);
		romBlock(program, "IP", IP_ADDRESS, fb, 0, ip.length, false, true,
			"IP.BIN (meta data, TOC, license screen and bootstrap code)", log);

		long b = IP_ADDRESS;
		stringField(program, b, 0x00, "IP_HARDWARE_ID", 16);
		stringField(program, b, 0x10, "IP_MAKER_ID", 16);
		stringField(program, b, 0x20, "IP_DEVICE_INFO", 16);
		stringField(program, b, 0x30, "IP_AREA_SYMBOLS", 8);
		stringField(program, b, 0x38, "IP_PERIPHERALS", 8);
		stringField(program, b, 0x40, "IP_PRODUCT_NUMBER", 10);
		stringField(program, b, 0x4A, "IP_VERSION", 6);
		stringField(program, b, 0x50, "IP_RELEASE_DATE", 16);
		stringField(program, b, 0x60, "IP_BOOT_FILENAME", 16);
		stringField(program, b, 0x70, "IP_SW_MAKER", 16);
		stringField(program, b, 0x80, "IP_GAME_TITLE", 128);
		comment(program, addr(program, b), "Dreamcast IP.BIN meta data (0x100 bytes)");
		if (ip.length > 0x300) {
			entry(program, addr(program, b + 0x300), "IP_BOOTSTRAP");
		}

		String bootName = ascii(ip, 0x60, 16).trim();
		info(program, "Format", "Dreamcast IP.BIN" + (disc.isRaw() ? " (raw 2352 image)" : ""));
		info(program, "Maker", ascii(ip, 0x10, 16));
		info(program, "Device", ascii(ip, 0x20, 16));
		info(program, "Areas", ascii(ip, 0x30, 8));
		info(program, "Peripherals", ascii(ip, 0x38, 8));
		info(program, "Product", ascii(ip, 0x40, 10));
		info(program, "Version", ascii(ip, 0x4A, 6));
		info(program, "Release date", ascii(ip, 0x50, 16));
		info(program, "Boot file", bootName);
		info(program, "Software maker", ascii(ip, 0x70, 16));
		info(program, "Title", ascii(ip, 0x80, 128));

		if (boolOption(options, OPT_LOAD_BOOT, true) && !bootName.isEmpty()) {
			SegaDiscImage.Entry e = disc.findRootFile(bootName);
			if (e != null && e.length() > 0 && e.length() <= 0xFF0000) {
				byte[] stored = disc.read(e.offset(), (int) e.length());
				byte[] image = bootImage(program, stored, options);
				FileBytes bfb = fileBytes(program, e.name(), image, monitor);
				romBlock(program, "BOOT_FILE", FIRST_READ_ADDRESS, bfb, 0, image.length, false,
					true, e.name() + " (LBA " + e.lba() + ", image base LBA " + e.baseLba() + ")",
					log);
				entry(program, addr(program, FIRST_READ_ADDRESS), "start");
				info(program, "Boot file loaded", e.name() + " (" + hex(image.length) +
					" bytes at " + hex(FIRST_READ_ADDRESS) + ")");
			}
			else {
				info(program, "Boot file loaded", "not in this image");
			}
		}

		mapHardware(program, boolOption(options, OPT_MIRRORS, false), log);
	}

	/** Dreamcast memory map, shared with {@link DreamcastExecutableLoader}. */
	static void mapHardware(Program program, boolean mirrors, MessageLog log) {
		uninit(program, "BOOT_ROM", 0xA0000000L, 0x200000, false, true, false, false,
			"Boot ROM (2 MB) - not part of the image", log);
		uninit(program, "FLASH", 0xA0200000L, 0x20000, false, false, false, false,
			"Flash ROM (128 KB: region, settings)", log);
		io(program, "HOLLY_SB", 0xA05F6800L, 0x800,
			"Holly system bus registers (Maple, DMA, interrupts)", log);
		regs(program, 0xA05F6800L, 0, "0:SB_C2DSTAT", "4:SB_C2DLEN", "8:SB_C2DST",
			"10:SB_SDSTAW", "14:SB_SDBAAW", "18:SB_SDWLT", "1C:SB_SDLAS", "20:SB_SDST",
			"40:SB_DBREQM", "44:SB_BAVLWC", "48:SB_C2DPRYC", "4C:SB_C2DMAXL", "80:SB_TFREM",
			"84:SB_LMMODE0", "88:SB_LMMODE1", "8C:SB_FFST", "90:SB_SFRES", "9C:SB_SBREV",
			"A0:SB_RBSPLT", "100:SB_ISTNRM", "104:SB_ISTEXT", "108:SB_ISTERR",
			"110:SB_IML2NRM", "114:SB_IML2EXT", "118:SB_IML2ERR", "120:SB_IML4NRM",
			"124:SB_IML4EXT", "128:SB_IML4ERR", "130:SB_IML6NRM", "134:SB_IML6EXT",
			"138:SB_IML6ERR", "140:SB_PDTNRM", "144:SB_PDTEXT", "150:SB_G2DTNRM",
			"154:SB_G2DTEXT", "404:SB_MDSTAR", "410:SB_MDTSEL", "414:SB_MDEN", "418:SB_MDST",
			"480:SB_MSYS", "484:SB_MST", "488:SB_MSHTCL", "48C:SB_MDAPRO", "4E8:SB_MMSEL");
		io(program, "GDROM", 0xA05F7000L, 0x100, "GD-ROM drive (G1 ATA) registers", log);
		regs(program, 0xA05F7000L, 0, "18:GD_ALTSTAT_DEVCTRL:1", "80:GD_DATA:2",
			"84:GD_ERROR_FEATURES:1", "88:GD_IREASON_SECCNT:1", "8C:GD_SECTNUM:1",
			"90:GD_BYCTLLO:1", "94:GD_BYCTLHI:1", "98:GD_DRVSEL:1", "9C:GD_STATUS_COMMAND:1");
		io(program, "G1_CTRL", 0xA05F7400L, 0x100, "G1 bus control / GD-ROM DMA", log);
		regs(program, 0xA05F7400L, 0, "4:SB_GDSTAR", "8:SB_GDLEN", "C:SB_GDDIR", "14:SB_GDEN",
			"18:SB_GDST", "80:SB_G1RRC", "84:SB_G1RWC", "88:SB_G1FRC", "8C:SB_G1FWC",
			"90:SB_G1CRC", "94:SB_G1CWC", "A0:SB_G1GDRC", "A4:SB_G1GDWC", "B4:SB_G1CRDYC",
			"B8:SB_GDAPRO");
		io(program, "G2_CTRL", 0xA05F7800L, 0x100, "G2 bus control / AICA DMA", log);
		regs(program, 0xA05F7800L, 0, "0:SB_ADSTAG", "4:SB_ADSTAR", "8:SB_ADLEN",
			"C:SB_ADDIR", "10:SB_ADTSEL", "14:SB_ADEN", "18:SB_ADST", "1C:SB_ADSUSP",
			"80:SB_G2ID", "BC:SB_G2APRO");
		io(program, "PVR_DMA_CTRL", 0xA05F7C00L, 0x100, "PowerVR DMA control", log);
		regs(program, 0xA05F7C00L, 0, "0:SB_PDSTAP", "4:SB_PDSTAR", "8:SB_PDLEN",
			"C:SB_PDDIR", "10:SB_PDTSEL", "14:SB_PDEN", "18:SB_PDST", "80:SB_PDAPRO");
		io(program, "PVR_REGS", 0xA05F8000L, 0x2000, "PowerVR2 CLX2 (TA / ISP / video) " +
			"registers, fog table, palette RAM", log);
		regs(program, 0xA05F8000L, 0, "0:PVR_ID", "4:PVR_REVISION", "8:PVR_SOFTRESET",
			"14:PVR_STARTRENDER", "20:PVR_PARAM_BASE", "2C:PVR_REGION_BASE",
			"30:PVR_SPAN_SORT", "40:PVR_VO_BORDER_COL", "44:PVR_FB_R_CTRL",
			"48:PVR_FB_W_CTRL", "4C:PVR_FB_W_LINESTRIDE", "50:PVR_FB_R_SOF1",
			"54:PVR_FB_R_SOF2", "5C:PVR_FB_R_SIZE", "60:PVR_FB_W_SOF1", "64:PVR_FB_W_SOF2",
			"68:PVR_FB_X_CLIP", "6C:PVR_FB_Y_CLIP", "C8:PVR_SPG_HBLANK_INT",
			"CC:PVR_SPG_VBLANK_INT", "D0:PVR_SPG_CONTROL", "D4:PVR_SPG_HBLANK",
			"D8:PVR_SPG_LOAD", "DC:PVR_SPG_VBLANK", "E0:PVR_SPG_WIDTH", "E4:PVR_TEXT_CONTROL",
			"E8:PVR_VO_CONTROL", "EC:PVR_VO_STARTX", "F0:PVR_VO_STARTY", "F4:PVR_SCALER_CTL",
			"108:PVR_PALETTE_TYPE", "10C:PVR_SPG_STATUS", "124:PVR_TA_OL_BASE",
			"128:PVR_TA_ISP_BASE", "12C:PVR_TA_OL_LIMIT", "130:PVR_TA_ISP_LIMIT",
			"134:PVR_TA_NEXT_OPB", "138:PVR_TA_ITP_CURRENT", "13C:PVR_TA_GLOB_TILE_CLIP",
			"140:PVR_TA_ALLOC_CTRL", "144:PVR_TA_LIST_INIT", "148:PVR_TA_YUV_TEX_BASE",
			"14C:PVR_TA_YUV_TEX_CTRL", "150:PVR_TA_YUV_TEX_CNT", "160:PVR_TA_LIST_CONT",
			"164:PVR_TA_NEXT_OPB_INIT", "200:PVR_FOG_TABLE", "1000:PVR_PALETTE_RAM");
		io(program, "MODEM", 0xA0600000L, 0x800, "Modem", log);
		io(program, "AICA_REGS", 0xA0700000L, 0x8000, "AICA sound registers", log);
		io(program, "AICA_RTC", 0xA0710000L, 0x10, "AICA real-time clock", log);
		regs(program, 0xA0710000L, 0, "0:AICA_RTC_HI", "4:AICA_RTC_LO", "8:AICA_RTC_WE");
		uninit(program, "AICA_RAM", 0xA0800000L, 0x200000, true, false, false, false,
			"AICA sound RAM (2 MB, ARM7 side)", log);
		uninit(program, "VRAM64", 0xA4000000L, 0x800000, true, false, false, false,
			"Video RAM, 64-bit (texture) access path", log);
		uninit(program, "VRAM32", 0xA5000000L, 0x800000, true, false, false, false,
			"Video RAM, 32-bit (frame buffer) access path", log);
		io(program, "TA_FIFO_POLY", 0x10000000L, 0x800000, "Tile accelerator polygon FIFO",
			log);
		io(program, "TA_FIFO_YUV", 0x10800000L, 0x800000, "Tile accelerator YUV converter", log);
		io(program, "TA_TEXTURE", 0x11000000L, 0x1000000, "Tile accelerator direct texture path",
			log);
		ramAround(program, "SYSTEM_RAM", 0x8C000000L, 0x1000000,
			"System RAM (16 MB, P1 cached). Also seen at 0x0C000000 (P0/U0) and 0xAC000000 (P2, " +
				"uncached)",
			log);
		if (mirrors) {
			mirror(program, "SYSTEM_RAM_P0", 0x0C000000L, 0x8C000000L, 0x1000000,
				"System RAM via P0/U0", log);
			mirror(program, "SYSTEM_RAM_P2", 0xAC000000L, 0x8C000000L, 0x1000000,
				"System RAM via P2 (uncached)", log);
		}
		io(program, "STORE_QUEUES", 0xE0000000L, 0x4000000,
			"SH-4 store queue area (writes go to SQ0/SQ1, flushed by PREF to QACR0/1 targets)",
			log);
		label(program, 0xE0000000L, "SQ0");
		label(program, 0xE0000020L, "SQ1");
		io(program, "SH4_CCN", 0xFF000000L, 0x100, "SH-4 cache / MMU control", log);
		regs(program, 0xFF000000L, 0, "0:CCN_PTEH", "4:CCN_PTEL", "8:CCN_TTB", "C:CCN_TEA",
			"10:CCN_MMUCR", "14:CCN_BASRA:1", "18:CCN_BASRB:1", "1C:CCN_CCR", "20:CCN_TRA",
			"24:CCN_EXPEVT", "28:CCN_INTEVT", "34:CCN_PTEA", "38:CCN_QACR0", "3C:CCN_QACR1");
		io(program, "SH4_UBC", 0xFF200000L, 0x24, "SH-4 user break controller", log);
		io(program, "SH4_BSC", 0xFF800000L, 0x50, "SH-4 bus state controller", log);
		regs(program, 0xFF800000L, 0, "0:BSC_BCR1", "4:BSC_BCR2:2", "8:BSC_WCR1", "C:BSC_WCR2",
			"10:BSC_WCR3", "14:BSC_MCR", "18:BSC_PCR:2", "1C:BSC_RTCSR:2", "20:BSC_RTCNT:2",
			"24:BSC_RTCOR:2", "28:BSC_RFCR:2", "2C:BSC_PCTRA", "30:BSC_PDTRA:2",
			"40:BSC_PCTRB", "44:BSC_PDTRB:2", "48:BSC_GPIOIC:2");
		io(program, "SH4_DMAC", 0xFFA00000L, 0x44, "SH-4 DMA controller", log);
		regs(program, 0xFFA00000L, 0, "0:DMAC_SAR0", "4:DMAC_DAR0", "8:DMAC_DMATCR0",
			"C:DMAC_CHCR0", "10:DMAC_SAR1", "14:DMAC_DAR1", "18:DMAC_DMATCR1", "1C:DMAC_CHCR1",
			"20:DMAC_SAR2", "24:DMAC_DAR2", "28:DMAC_DMATCR2", "2C:DMAC_CHCR2", "30:DMAC_SAR3",
			"34:DMAC_DAR3", "38:DMAC_DMATCR3", "3C:DMAC_CHCR3", "40:DMAC_DMAOR");
		io(program, "SH4_CPG", 0xFFC00000L, 0x14, "SH-4 clock pulse generator / watchdog", log);
		regs(program, 0xFFC00000L, 0, "0:CPG_FRQCR:2", "4:CPG_STBCR:1", "8:CPG_WTCNT:2",
			"C:CPG_WTCSR:2", "10:CPG_STBCR2:1");
		io(program, "SH4_RTC", 0xFFC80000L, 0x40, "SH-4 real-time clock", log);
		io(program, "SH4_INTC", 0xFFD00000L, 0x10, "SH-4 interrupt controller", log);
		regs(program, 0xFFD00000L, 0, "0:INTC_ICR:2", "4:INTC_IPRA:2", "8:INTC_IPRB:2",
			"C:INTC_IPRC:2");
		io(program, "SH4_TMU", 0xFFD80000L, 0x30, "SH-4 timer unit", log);
		regs(program, 0xFFD80000L, 0, "0:TMU_TOCR:1", "4:TMU_TSTR:1", "8:TMU_TCOR0",
			"C:TMU_TCNT0", "10:TMU_TCR0:2", "14:TMU_TCOR1", "18:TMU_TCNT1", "1C:TMU_TCR1:2",
			"20:TMU_TCOR2", "24:TMU_TCNT2", "28:TMU_TCR2:2", "2C:TMU_TCPR2");
		io(program, "SH4_SCI", 0xFFE00000L, 0x20, "SH-4 serial communication interface", log);
		io(program, "SH4_SCIF", 0xFFE80000L, 0x28, "SH-4 serial interface with FIFO", log);
		regs(program, 0xFFE80000L, 0, "0:SCIF_SCSMR2:2", "4:SCIF_SCBRR2:1", "8:SCIF_SCSCR2:2",
			"C:SCIF_SCFTDR2:1", "10:SCIF_SCFSR2:2", "14:SCIF_SCFRDR2:1", "18:SCIF_SCFCR2:2",
			"1C:SCIF_SCFDR2:2", "20:SCIF_SCSPTR2:2", "24:SCIF_SCLSR2:2");
	}
}
