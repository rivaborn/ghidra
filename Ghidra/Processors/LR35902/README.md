# LR35902

Sharp LR35902 / SM83, the CPU of the Nintendo Game Boy and Game Boy Color.

Language: `LR35902:LE:16:default`.

- All 245 defined base opcodes and all 256 CB-prefixed opcodes. The 11 unused base
  opcodes (D3 DB DD E3 E4 EB EC ED F4 FC FD) are left undefined.
- Flags Z, N, H and C are kept in separate registers (`ZF`, `NF`, `HF`, `CF`) for a
  readable decompilation. `PUSH AF` builds `F` from them; `POP AF` splits `F` back.
- The processor spec names the hardware registers (FF00-FF7F, FFFF), the RST and
  interrupt vectors and the cartridge entry point (0100), and creates the VRAM, SRAM,
  WRAM, echo RAM, OAM, I/O (volatile), HRAM and IE blocks. The cartridge ROM is the
  imported file.

Not modelled: ROM and RAM bank switching (MBC registers), CGB VRAM/WRAM banks,
the HALT bug, the CGB double-speed switch performed by STOP, and instruction timing.
