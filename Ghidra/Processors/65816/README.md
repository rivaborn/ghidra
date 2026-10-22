# 65816

WDC 65C816 processor module: the CPU core of the SNES (Ricoh 5A22), in
native and emulation mode.

| Language id           | Processor | Endian | Address size | Description                                        |
| --------------------- | --------- | ------ | ------------ | -------------------------------------------------- |
| `65816:LE:24:default` | 65816     | little | 24 bits      | WDC 65C816 (SNES 5A22), native and emulation mode  |

## Registers

| Register      | Size | Notes                                                              |
| ------------- | ---- | ------------------------------------------------------------------ |
| `C`           | 16   | Accumulator; `A` is the low byte, `B` the high byte                |
| `X`, `Y`      | 16   | Index registers; `XL`/`XH`, `YL`/`YH` are the byte halves          |
| `SP`          | 24   | Stack pointer, modelled as **S + 1** in bank 0 (see below)         |
| `D`           | 16   | Direct page register (`DL`/`DH`)                                   |
| `DBR`         | 8    | Data bank register: bank of absolute data addresses                |
| `PC`, `PBR`   | 24/8 | Program counter; `PBR` is its bank byte                            |
| `NF` .. `CF`  | 8    | Status bits N V M X D I Z C (`NF VF MF XF DF IF ZF CF`), and `EF`  |

## M, X and E: operand sizes

The size of immediates and of accumulator / index operations depends on the
M and X flags (and on E, emulation mode). They are context registers:

| Context  | Meaning                                                  | Default |
| -------- | -------------------------------------------------------- | ------- |
| `mflag`  | 1: 8-bit accumulator and memory, 0: 16-bit               | 1       |
| `xflag`  | 1: 8-bit index registers, 0: 16-bit                      | 1       |
| `emode`  | 1: emulation mode (M and X forced to 1)                  | 0       |
| `dflag`  | 1: decimal mode (D flag): `ADC`/`SBC` use BCD            | 0       |

The default is native mode with M=1, X=1, the state after the usual SNES
reset sequence `CLC; XCE`. The disassembler then follows the code:

- `REP #imm` / `SEP #imm` change `mflag` / `xflag` for the following
  instructions (REP cannot clear them in emulation mode);
- `CLC; XCE` selects native mode, `SEC; XCE` emulation mode (with M=X=1);
  an `XCE` not directly after `CLC`/`SEC` leaves the context unchanged;
- `PLP` restores the M/X context saved by the last `PHP` on the same flow.
- `SED` / `CLD`, and `REP` / `SEP` with bit 3, set `dflag`; `PLP` restores
  it from the last `PHP` too.

To change the state at a function entry or any other address, select the
range in the Listing and use **Set Register Values...** on `mflag`, `xflag`
or `emode` (or call `ProgramContext.setValue` from a script), then clear and
re-disassemble the code.

## Addresses

- Direct page: bank 0, `D + dp` (16-bit wrap).
- Absolute data (`LDA $1234`): `DBR:$1234`. When `DBR` is not set in the
  function, the decompiler shows `CONCAT12(DBR, 0x1234)`-style addresses.
  Set `DBR` (and `D`) with **Set Register Values...** over the function:
  the decompiler then folds them into constant addresses. A `PHA; PLB` or
  `PEA; PLD` / `TCD` inside the function is followed automatically.
- Long (`LDA $7E0010`): the 24-bit operand.
- `JMP`/`JSR` absolute and relative branches stay in the program bank;
  `JML`/`JSL`/`RTL` are long. `JMP (abs)` reads its pointer from bank 0,
  `JMP (abs,X)` / `JSR (abs,X)` from the program bank, `JML [abs]` a 24-bit
  pointer from bank 0.
- `MVN`/`MVP` are shown in WDC order, `MVN srcbank,dstbank` (the machine code
  stores the destination bank first). One byte is moved per execution and
  the instruction repeats until `C` wraps to `0xFFFF`.

## Stack pointer and calling convention

The 65816 `S` register points at the next free byte. Ghidra's decompiler
expects the stack pointer to point at the last pushed item, so the module
models `SP = S + 1` (a 24-bit address in bank 0). All memory effects are
exact; only the register value differs by one: `TSC`/`TSX` produce
`SP - 1`, `TCS`/`TXS` set `SP` to the value + 1, and stack-relative
`sr,S` addresses `SP - 1 + sr`. When you set the stack pointer for an
emulator, write `S + 1` to `SP`.

The single calling convention, `__asmcall`, takes arguments in `C` (`A`),
`X`, `Y`, returns in `C` (`A`) and treats `SP`, `D` and `DBR` as preserved.
It fits `JSR`/`RTS` and `JSL`/`RTL` functions alike: its stack purge matches
`RTS`, and the `JSL` p-code adds the extra byte an `RTL` pops after the call
returns. Ghidra's emulator branches at the call and never executes that
op, so emulation stays exact.

## Decimal mode

With `dflag` = 1, `ADC` and `SBC` work on 2 (8-bit) or 4 (16-bit) BCD digits:
each digit is added (subtracted) with the carry (borrow) of the digit below and
adjusted by 6 when it passes 9 (goes below 0). The carry out is the decimal
carry; N and Z come from the decimal result, as on the 65C02/65C816.

| Flag | ADC (decimal)                                                       | SBC (decimal)        |
| ---- | ------------------------------------------------------------------- | -------------------- |
| C    | decimal carry out of the top digit                                  | same as binary       |
| V    | signed overflow of the sum before the top digit is adjusted         | same as binary       |
| N, Z | from the result                                                     | from the result      |

V for ADC follows the 65C02 rule (Bruce Clark's decimal-mode tutorial,
sequence 2); for SBC the binary V. Operands that are not valid BCD (a digit
above 9) follow the same digit-by-digit rule, which may differ from the
silicon. The decompiler shows decimal arithmetic as the digit-by-digit
expressions.

## Not modelled

- Emulation-mode wrap quirks (direct page and stack confined to one page).
- `BRK`/`COP` are pseudo-ops (`softwareInterrupt`, `coprocessorInterrupt`)
  that fall through; `WAI` and `STP` are pseudo-ops too.
- M/X across calls: the disassembler carries the caller's M/X context into
  a `JSR`/`JSL` target the first time it reaches it (a `REP #$30; JSR sub`
  decodes `sub` with 16-bit operands). Whichever flow reaches a routine first
  wins. The **65816 M/X State Propagation** analyzer (ConsoleFormats module,
  `Snes65816StateAnalyzer`, on by default) corrects this after disassembly:
  when all the `JSR`/`JSL`/`JMP`/`JML` call sites of a routine agree on M/X/E
  and the routine was decoded with another state, it sets the state at the
  entry and disassembles the routine again; when they disagree it adds a
  warning bookmark (`called with M=?,X=? from ...`). Bits that a routine sets
  itself with a leading `REP`/`SEP` are ignored. Native-mode interrupt
  vectors give no state (a note bookmark marks routines that depend on it);
  RESET and the emulation vectors give M=1, X=1. After a call returns, the
  caller continues with its own context, although the callee may have
  changed M/X.
