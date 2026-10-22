# PS2VU

PlayStation 2 Vector Units (VU0 / VU1) in micro mode.

| Language id         | Micro memory | Data memory |
| ------------------- | ------------ | ----------- |
| `PS2VU:LE:32:VU1`   | 16 KB        | 16 KB       |
| `PS2VU:LE:32:VU0`   | 4 KB         | 4 KB        |

Both use `ps2vu.sla`; only the pspec (data memory size) differs. VU0 macro mode (COP2 of the
EE) is in the R5900 language (`MIPS:LE:64:R5900`); register names follow it.

## Model

- One 64-bit LIW is one instruction. The lower instruction is the word at the LIW address and
  the upper instruction the word at address + 4. It prints as
  `vmaddw.xyzw vf2,vf7,vf1w || sq.xyzw vf2, 0x0(vi3)`, with the flags after the upper
  mnemonic (`vnop[E]`, `[M]`, `[D]`, `[T]`). When the I bit is set, the lower half is `loi <imm>`.
- Spaces: `micro` (code, byte addressed) and `vumem` (data, byte addressed). Instructions
  address data in quadwords: the p-code scales `vi + imm` by 16.
- Registers: `vf0`-`vf31`, with 32-bit fields `vf<n>x`..`vf<n>w`. `ACC` (`ACCx`..`ACCw`),
  `vi0`-`vi15` (16 bits), `Q`, `P`, `I`, `R`, `status_flag`, `mac_flag` and `clip_flag`.
  `vf0` reads as (0, 0, 0, 1.0) and `vi0` as 0.
- The float operations are real p-code, field by field under the dest mask. This covers
  ADD/SUB/MUL/MADD/MSUB in their bc, q, i and ACC forms, OPMULA/OPMSUB, ABS, ITOF/FTOI, CLIP,
  DIV/SQRT/RSQRT and most of the EFU. MAX/MINI, RNEXT, EATAN*, ESIN, EEXP, XGKICK and
  XTOP/XITOP are pcodeops.
- Inside one LIW, the upper half reads its sources first. The lower half then runs, the upper
  results are written next, and the control flow comes last.
- Branches have one delay slot (the next LIW). BAL/JALR store the return LIW index (address / 8);
  `jr vi15` is a return. The E bit ends the program after the next LIW (`return`).

## Not modelled

- Pipeline latencies and stalls.
- MAC and status flag updates by the arithmetic.
- Wrap-around of data and micro memory addresses.
- VU0 access to VU1 registers through data memory 0x4000.

## Loading microcode

The ConsoleFormats feature provides:

- the `PS2 VU Microcode` loader;
- the `PS2 VU Microcode Finder` analyzer, for R5900 programs;
- the `Ps2VuFindMicrocode` and `Ps2VuExtractMicrocode` scripts.
