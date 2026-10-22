# ConsoleFormats

Loaders and analyzers for game-console cartridge and executable formats (rivaborn/ghidra, branch
nxdecomp-fixes). Each loader maps a file the way the console's hardware or OS does: banks as
overlay blocks, sections at their load addresses, headers parsed for entry points, hardware
registers labelled. They are picked automatically on import (no `-loader` needed), except the two
headerless opt-in loaders.

Loaders are in `ghidra.app.util.opinion.console`, analyzers in
`ghidra.app.plugin.core.analysis.console`, scripts in `ghidra_scripts`. In a release install,
Ghidra loads a module's jars only when their names start with the module name (case-sensitive):
`lib/ConsoleFormats*.jar`.

## Loaders

| Loader                                                | Platform / format                                                 | Language                             | Notes                                                                                                            |
| ----------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `SnesLoader`                                          | SNES `.sfc`/`.smc`: LoROM, HiROM, ExHiROM, 512-byte copier header | `65816:LE:24:default`                | header scored at 0x7FC0/0xFFC0/0x40FFC0; bank mirrors byte-mapped; vectors, PPU/CPU registers                    |
| `GameBoyLoader`                                       | Game Boy / Color `.gb`/`.gbc`                                     | `LR35902:LE:16:default`              | Nintendo logo at 0x104; every switchable bank an overlay `bank_NN`; MBC1/1M/2/3/5...                             |
| `NesLoader`                                           | NES iNES / NES 2.0 `.nes`                                         | `6502:LE:16:default`                 | mappers 0,1,2,3,4,7,9,10,66 and a generic fallback; CHR-ROM in the OTHER space                                   |
| `PsxExeLoader`                                        | PS1 PS-X EXE                                                      | `MIPS:LE:32:default`                 | text at t_addr, BSS, scratchpad, I/O registers, gp                                                               |
| `N64Loader`                                           | N64 `.z64`/`.v64`/`.n64`                                          | `MIPS:BE:64:64-32addr`               | all byte orders; boot copy at the header entry (CIC-adjusted); whole ROM at 0xB0000000                           |
| `DolLoader`                                           | GameCube / Wii DOL                                                | `PowerPC:BE:32:Gekko_Broadway`       | 7 text + 11 data sections, BSS, MEM1/MEM2, hardware registers, r2/r13                                            |
| `RelLoader`                                           | GameCube / Wii REL modules                                        | Gekko                                | relocations against itself and module 0 applied, base option                                                     |
| `NdsLoader`                                           | Nintendo DS `.nds`                                                | `ARM:LE:32:v5t` (ARM9), `v4t` (ARM7) | autoloads, overlays, BLZ decompression                                                                           |
| `GbaLoader`                                           | GBA `.gba`                                                        | `ARM:LE:32:v4t`                      | ROM at 0x08000000, EWRAM/IWRAM/I/O, multiboot option                                                             |
| `RpxLoader`                                           | Wii U RPX/RPL                                                     | Gekko                                | zlib sections inflated, imports/exports, RPL relocations, SDA bases                                              |
| `MegaDriveLoader`                                     | Mega Drive / Genesis, `.smd` interleaved, SSF2 mapper, 32X        | `68000:BE:32:default`                | vectors, VDP/IO/Z80/TMSS, SRAM, checksum                                                                         |
| `SegaMasterSystemLoader`                              | Master System / Game Gear                                         | `z80:LE:16:default`                  | Sega, Codemasters and Korean mappers, banks as overlays per slot, I/O ports                                      |
| `SaturnLoader`                                        | Saturn IP.BIN or disc image                                       | `SuperH:BE:32:SH-2`                  | IP at 0x06002000, first-read file from ISO 9660 at its load address                                              |
| `DreamcastLoader`                                     | Dreamcast IP.BIN or disc image                                    | `SuperH4:LE:32:default`              | IP at 0x8C008000, boot file at 0x8C010000, MIL-CD descrambling                                                   |
| `SaturnExecutableLoader`, `DreamcastExecutableLoader` | headerless 1st-read files                                         | SH-2 / SH-4                          | opt-in only: `-loader <name> -processor <lang>`                                                                  |
| `XbeLoader`                                           | Original Xbox XBE                                                 | `x86:LE:32:default` (windows)        | sections, kernel thunks named (ordinals 1-366), certificate                                                      |
| `Xex2Loader`                                          | Xbox 360 XEX2                                                     | `PowerPC:BE:64:64-32addr`            | AES with a user key file (`-loader-xexKeyFile` / `XEX_KEYS_FILE`), basic and LZX compression; VMX128 not decoded |
| `C64PrgLoader`                                        | Commodore 64 `.prg`                                               | `6502:LE:16:default`                 | load address, BASIC SYS stub, KERNAL externals                                                                   |
| `AtariXexLoader`                                      | Atari 8-bit XEX                                                   | `6502:LE:16:default`                 | segments, INIT/RUN entries                                                                                       |
| `MsxRomLoader`                                        | MSX ROM                                                           | `z80:LE:16:default`                  | plain, ASCII8/16, Konami, Konami SCC mappers                                                                     |
| `ColecoVisionLoader`                                  | ColecoVision `.col`                                               | `z80:LE:16:default`                  | header vectors, MegaCart banks                                                                                   |
| `Ps2VuMicrocodeLoader`                                | PS2 VU microcode `.vu`/`.vu0`/`.vu1` or a VIF MPG packet          | `PS2VU:LE:32:VU0/VU1`                | file offset, length, micro address options                                                                       |

## Analyzers

| Analyzer                 | What it does                                                                                                                     |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `Snes65816StateAnalyzer` | propagates the M/X/E state from callers to routines and re-disassembles them; bookmarks routines whose callers disagree          |
| `GameBoyBankAnalyzer`    | resolves calls and jumps into 4000-7FFF to the right bank overlay where the bank number is a known constant; labels bank helpers |
| `SegaMapperBankAnalyzer` | the same for Master System / Game Gear slots 1 and 2                                                                             |
| `Ps2VuMicrocodeAnalyzer` | finds VIF MPG packets in R5900 programs and bookmarks them (`Ps2VuMicrocodeFinder`)                                              |

Scripts: `Ps2VuFindMicrocode.java`, `Ps2VuExtractMicrocode.java` (extract and import each microprogram).

## Keys

Formats that need console keys (XEX2 encryption) read them from a file the user supplies; no key
or key-derived constant is in this module, and keys are never logged.

## Tests and limits

All loaders were tested on synthetic files only (no game data): each is picked automatically for
its format, maps the expected blocks, and decompiles its entry. The limits of each are listed in
`nxdecomp/README.md` and the coding_workflow knowledge base. Re-run `install_patched.ps1 -Fresh`
after changing `ghidra_scripts` (they are copied when the module is first installed).
