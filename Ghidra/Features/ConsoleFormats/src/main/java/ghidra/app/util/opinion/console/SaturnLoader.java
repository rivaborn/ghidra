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
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Sega Saturn boot area: a bare IP.BIN, or a disc image whose data track starts with it
 * (2048-byte {@code .iso}, or raw 2352-byte Mode 1 / Mode 2 sectors).
 * <p>
 * Detection: ASCII "SEGA SEGASATURN " (16 bytes, note the trailing blank) at the first byte of
 * user data: file offset 0 for IP.BIN / ISO; for a raw image (sync pattern 00 FF x10 00 at 0)
 * offset 16 (Mode 1, byte 15 = 1) or 24 (Mode 2, byte 15 = 2).
 * <p>
 * The IP (its size is the u32 BE at 0xE0) is mapped at 0x06002000, which is where the boot ROM
 * reads it. When the image has an ISO 9660 file system, the first file of the root directory
 * (the one the boot ROM reads as the "1st read" file) is loaded at the 1st-read address from
 * the u32 BE at 0xF0 (option to name another file or turn it off).
 */
public class SaturnLoader extends SegaLoaderBase {

	public static final String NAME = "Sega Saturn IP.BIN / disc image";
	public static final String LANGUAGE = "SuperH:BE:32:SH-2";
	public static final String MAGIC = "SEGA SEGASATURN ";
	public static final long IP_ADDRESS = 0x06002000L;

	static final String OPT_LOAD_FIRST = "Load 1st read file from the disc image";
	static final String OPT_FIRST_NAME = "1st read file name (empty = first root file)";

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
		list.add(boolOpt(OPT_LOAD_FIRST, true, "loadFirstRead"));
		list.add(stringOpt(OPT_FIRST_NAME, "", "firstReadName"));
		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String err = validateOwn(options,
			Map.of(OPT_LOAD_FIRST, Boolean.class, OPT_FIRST_NAME, String.class));
		return err != null ? err : super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		List<Option> options = settings.options();

		SegaDiscImage disc = new SegaDiscImage(provider);
		byte[] hdr = disc.read(0, 0x100);
		long ipSize = u32be(hdr, 0xE0);
		byte[] avail = disc.read(0, 0x8000);
		int ipLen = (int) (ipSize >= 0x100 && ipSize <= 0x8000 ? Math.min(ipSize, avail.length)
				: Math.min(avail.length, 0x1000));
		byte[] ip = Arrays.copyOf(avail, ipLen);
		long firstRead = u32be(hdr, 0xF0);

		FileBytes fb = disc.isRaw() || provider.length() != ipLen
				? fileBytes(program, provider.getName() + " (IP)", ip, monitor)
				: program.getMemory()
						.createFileBytes(provider.getName(), 0, ipLen, provider.getInputStream(0),
							monitor);
		romBlock(program, "IP", IP_ADDRESS, fb, 0, ipLen, false, true,
			"IP.BIN (system ID, security code, area codes, AIP) as loaded by the boot ROM", log);

		// header fields
		long b = IP_ADDRESS;
		stringField(program, b, 0x00, "IP_HARDWARE_ID", 16);
		stringField(program, b, 0x10, "IP_MAKER_ID", 16);
		stringField(program, b, 0x20, "IP_PRODUCT_NUMBER", 10);
		stringField(program, b, 0x2A, "IP_VERSION", 6);
		stringField(program, b, 0x30, "IP_RELEASE_DATE", 8);
		stringField(program, b, 0x38, "IP_DEVICE_INFO", 8);
		stringField(program, b, 0x40, "IP_AREA_SYMBOLS", 10);
		stringField(program, b, 0x50, "IP_PERIPHERALS", 16);
		stringField(program, b, 0x60, "IP_GAME_TITLE", 112);
		field(program, b, 0xE0, "IP_SIZE", DWordDataType.dataType, 4);
		field(program, b, 0xE8, "IP_MASTER_STACK", DWordDataType.dataType, 4);
		field(program, b, 0xEC, "IP_SLAVE_STACK", DWordDataType.dataType, 4);
		field(program, b, 0xF0, "IP_FIRST_READ_ADDRESS", DWordDataType.dataType, 4);
		field(program, b, 0xF4, "IP_FIRST_READ_SIZE", DWordDataType.dataType, 4);
		comment(program, addr(program, b), "Saturn system ID (IP.BIN header, 0x100 bytes)");
		if (ipLen > 0x100) {
			entry(program, addr(program, b + 0x100), "IP_SECURITY_CODE");
			comment(program, addr(program, b + 0x100),
				"Security code (SYS_SEC, 0xD00 bytes), then the area code(s) (SYS_ARE) and " +
					"the application initial program (AIP)");
		}
		if (ipLen > 0xE00) {
			label(program, b + 0xE00, "IP_AREA_CODE");
		}

		info(program, "Format", "Saturn IP.BIN" + (disc.isRaw() ? " (raw 2352 image)" : ""));
		info(program, "Maker", ascii(hdr, 0x10, 16));
		info(program, "Product", ascii(hdr, 0x20, 10));
		info(program, "Version", ascii(hdr, 0x2A, 6));
		info(program, "Release date", ascii(hdr, 0x30, 8));
		info(program, "Device", ascii(hdr, 0x38, 8));
		info(program, "Areas", ascii(hdr, 0x40, 10));
		info(program, "Peripherals", ascii(hdr, 0x50, 16));
		info(program, "Title", ascii(hdr, 0x60, 112));
		info(program, "IP size", hex(ipSize));
		info(program, "Master stack", hex(u32be(hdr, 0xE8)));
		info(program, "Slave stack", hex(u32be(hdr, 0xEC)));
		info(program, "1st read address", hex(firstRead));
		info(program, "1st read size", hex(u32be(hdr, 0xF4)));

		// 1st read file from the image
		if (boolOption(options, OPT_LOAD_FIRST, true)) {
			String want = stringOption(options, OPT_FIRST_NAME, "");
			SegaDiscImage.Entry e = disc.findRootFile(want.isEmpty() ? null : want);
			if (e != null && e.length() > 0 && e.length() <= 0x100000) {
				byte[] data = disc.read(e.offset(), (int) e.length());
				FileBytes ffb = fileBytes(program, e.name(), data, monitor);
				romBlock(program, "FIRST_READ", firstRead, ffb, 0, data.length, false, true,
					"1st read file " + e.name() + " (LBA " + e.lba() + ", image base LBA " +
						e.baseLba() + ")",
					log);
				entry(program, addr(program, firstRead), "FIRST_READ_START");
				info(program, "1st read file", e.name() + " (" + hex(data.length) + " bytes)");
			}
			else {
				info(program, "1st read file", "not in this image");
			}
		}

		mapHardware(program, log);
	}

	/** Saturn memory map shared with {@link SaturnExecutableLoader}. */
	static void mapHardware(Program program, MessageLog log) {
		final long CT = 0x20000000L; // cache-through alias
		uninit(program, "BIOS_ROM", 0, 0x80000, false, true, false, false,
			"Boot ROM (512 KB) - not part of the image", log);
		io(program, "SMPC", 0x00100000L, 0x80, "SMPC registers (odd bytes)", log);
		mirror(program, "SMPC_ct", CT | 0x00100000L, 0x00100000L, 0x80, "SMPC, cache-through",
			log);
		regs(program, 0x00100000L, CT | 0x00100000L, "01:SMPC_IREG0:1", "03:SMPC_IREG1:1",
			"05:SMPC_IREG2:1", "07:SMPC_IREG3:1", "09:SMPC_IREG4:1", "0B:SMPC_IREG5:1",
			"0D:SMPC_IREG6:1", "1F:SMPC_COMREG:1", "21:SMPC_OREG0:1", "5F:SMPC_OREG31:1",
			"61:SMPC_SR:1", "63:SMPC_SF:1", "75:SMPC_PDR1:1", "77:SMPC_PDR2:1", "79:SMPC_DDR1:1",
			"7B:SMPC_DDR2:1", "7D:SMPC_IOSEL:1", "7F:SMPC_EXLE:1");
		uninit(program, "BACKUP_RAM", 0x00180000L, 0x10000, true, false, false, false,
			"Battery backup RAM (32 KB on odd bytes)", log);
		uninit(program, "WORK_RAM_LOW", 0x00200000L, 0x100000, true, true, false, false,
			"Work RAM low (1 MB)", log);
		mirror(program, "WORK_RAM_LOW_ct", CT | 0x00200000L, 0x00200000L, 0x100000,
			"Work RAM low, cache-through", log);
		io(program, "MINIT", 0x01000000L, 0x10, "Slave SH-2 FRT input capture (MINIT)", log);
		io(program, "SINIT", 0x01800000L, 0x10, "Master SH-2 FRT input capture (SINIT)", log);
		io(program, "A_BUS_CS0", 0x02000000L, 0x2000000, "A-bus CS0: cartridge", log);
		io(program, "A_BUS_CS1", 0x04000000L, 0x1000000, "A-bus CS1: cartridge", log);
		io(program, "CD_BLOCK", 0x05800000L, 0x100000, "A-bus CS2: CD block", log);
		mirror(program, "CD_BLOCK_ct", CT | 0x05800000L, 0x05800000L, 0x100000,
			"CD block, cache-through", log);
		regs(program, 0x05890000L, CT | 0x05890000L, "8:CDB_HIRQ:2", "C:CDB_HIRQ_MASK:2",
			"18:CDB_CR1:2", "1C:CDB_CR2:2", "20:CDB_CR3:2", "24:CDB_CR4:2");
		uninit(program, "SOUND_RAM", 0x05A00000L, 0x80000, true, false, false, false,
			"SCSP sound RAM (512 KB, 68EC000 side)", log);
		io(program, "SCSP_REGS", 0x05B00000L, 0x1000, "SCSP registers", log);
		uninit(program, "VDP1_VRAM", 0x05C00000L, 0x80000, true, false, false, false,
			"VDP1 VRAM (command tables, sprites)", log);
		uninit(program, "VDP1_FB", 0x05C80000L, 0x40000, true, false, false, false,
			"VDP1 frame buffer", log);
		io(program, "VDP1_REGS", 0x05D00000L, 0x18, "VDP1 registers", log);
		uninit(program, "VDP2_VRAM", 0x05E00000L, 0x80000, true, false, false, false,
			"VDP2 VRAM", log);
		uninit(program, "VDP2_CRAM", 0x05F00000L, 0x1000, true, false, false, false,
			"VDP2 color RAM", log);
		io(program, "VDP2_REGS", 0x05F80000L, 0x200, "VDP2 registers", log);
		io(program, "SCU_REGS", 0x05FE0000L, 0x100, "SCU registers (DMA, DSP, timers, " +
			"interrupt control)", log);
		mirror(program, "B_BUS_ct", CT | 0x05A00000L, 0x05A00000L, 0x5E0100,
			"SCSP / VDP1 / VDP2 / SCU, cache-through (0x25A00000-0x25FE00FF)", log);
		regs(program, 0x05D00000L, CT | 0x05D00000L, "0:VDP1_TVMR:2", "2:VDP1_FBCR:2",
			"4:VDP1_PTMR:2", "6:VDP1_EWDR:2", "8:VDP1_EWLR:2", "A:VDP1_EWRR:2", "C:VDP1_ENDR:2",
			"10:VDP1_EDSR:2", "12:VDP1_LOPR:2", "14:VDP1_COPR:2", "16:VDP1_MODR:2");
		regs(program, 0x05F80000L, CT | 0x05F80000L, "0:VDP2_TVMD:2", "2:VDP2_EXTEN:2",
			"4:VDP2_TVSTAT:2", "6:VDP2_VRSIZE:2", "8:VDP2_HCNT:2", "A:VDP2_VCNT:2",
			"E:VDP2_RAMCTL:2", "10:VDP2_CYCA0L:2", "20:VDP2_BGON:2", "22:VDP2_MZCTL:2",
			"28:VDP2_CHCTLA:2", "2A:VDP2_CHCTLB:2", "70:VDP2_SCXIN0:2", "E0:VDP2_SPCTL:2",
			"E4:VDP2_CRAOFA:2", "F0:VDP2_PRISA:2", "F8:VDP2_PRINA:2", "FC:VDP2_PRIR:2",
			"108:VDP2_CCRNA:2", "110:VDP2_CLOFEN:2");
		regs(program, 0x05FE0000L, CT | 0x05FE0000L, "0:SCU_D0R", "4:SCU_D0W", "8:SCU_D0C",
			"C:SCU_D0AD", "10:SCU_D0EN", "14:SCU_D0MD", "20:SCU_D1R", "24:SCU_D1W", "28:SCU_D1C",
			"2C:SCU_D1AD", "30:SCU_D1EN", "34:SCU_D1MD", "40:SCU_D2R", "44:SCU_D2W",
			"48:SCU_D2C", "4C:SCU_D2AD", "50:SCU_D2EN", "54:SCU_D2MD", "60:SCU_DSTP",
			"7C:SCU_DSTA", "80:SCU_PPAF", "84:SCU_PPD", "88:SCU_PDA", "8C:SCU_PDD", "90:SCU_T0C",
			"94:SCU_T1S", "98:SCU_T1MD", "A0:SCU_IMS", "A4:SCU_IST", "A8:SCU_AIACK",
			"B0:SCU_ASR0", "B4:SCU_ASR1", "B8:SCU_AREF", "C4:SCU_RSEL", "C8:SCU_VER");
		ramAround(program, "WORK_RAM_HIGH", 0x06000000L, 0x100000,
			"Work RAM high (1 MB); the boot ROM puts the vector table (VBR) at 0x06000000", log);
		mirror(program, "WORK_RAM_HIGH_ct", CT | 0x06000000L, 0x06000000L, 0x100000,
			"Work RAM high, cache-through", log);
		io(program, "SH2_ONCHIP", 0xFFFFFE00L, 0x200, "SH7604 on-chip modules (SCI, FRT, " +
			"WDT, INTC, DIVU, DMAC, BSC, cache control)", log);
		regs(program, 0xFFFFFE00L, 0, "0:SH2_SMR:1", "1:SH2_BRR:1", "2:SH2_SCR:1",
			"3:SH2_TDR:1", "4:SH2_SSR:1", "5:SH2_RDR:1", "10:SH2_TIER:1", "11:SH2_FTCSR:1",
			"12:SH2_FRC:2", "14:SH2_OCR:2", "16:SH2_TCR:1", "17:SH2_TOCR:1", "18:SH2_FICR:2",
			"60:SH2_IPRB:2", "62:SH2_VCRA:2", "64:SH2_VCRB:2", "66:SH2_VCRC:2",
			"68:SH2_VCRD:2", "71:SH2_DRCR0:1", "72:SH2_DRCR1:1", "80:SH2_WTCSR:1",
			"91:SH2_SBYCR:1", "92:SH2_CCR:1", "E0:SH2_ICR:2", "E2:SH2_IPRA:2",
			"E4:SH2_VCRWDT:2", "100:SH2_DVSR", "104:SH2_DVDNT", "108:SH2_DVCR",
			"10C:SH2_VCRDIV", "110:SH2_DVDNTH", "114:SH2_DVDNTL", "180:SH2_SAR0",
			"184:SH2_DAR0", "188:SH2_TCR0", "18C:SH2_CHCR0", "190:SH2_SAR1", "194:SH2_DAR1",
			"198:SH2_TCR1", "19C:SH2_CHCR1", "1A0:SH2_VCRDMA0", "1A8:SH2_VCRDMA1",
			"1B0:SH2_DMAOR", "1E0:SH2_BCR1", "1E4:SH2_BCR2", "1E8:SH2_WCR", "1EC:SH2_MCR",
			"1F0:SH2_RTCSR", "1F4:SH2_RTCNT", "1F8:SH2_RTCOR");
	}
}
