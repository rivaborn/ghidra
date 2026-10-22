# nxdecomp-fixes

This branch is Ghidra 12.1.4 (tag `Ghidra_12.1.4_build`) with the changes the decompilation
pipelines in `rivaborn/coding_workflow` need. The fork's `master` follows upstream development
(12.3 DEV) and is not used: REA supports 12.1.x only.

| Change                | Files                                                                                                                                  | Why                                                                                                                                                 |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Varnode-hash fallback | `Features/Decompiler/src/decompile/cpp/funcdata_varnode.cc`                                                                            | "Unable to find unique hash for varnode" abandoned whole functions over one variable's name; the variable now keeps the shared name, with a warning |
| Cleared fall-through  | `PcodeOverride`, `InstructionPcodeOverride`, `PcodeEmit` (SoftwareModeling)                                                            | `Instruction.setFallThrough(null)` never reached the decompiler, so flow ran on past it; such an instruction now ends with a `RETURN`               |
| Telemetry             | `ghidra.util.telemetry.Telemetry` (Generic); hooks in `HeadlessAnalyzer`, `AutoAnalysisManager`, `DecompInterface`, `DecompileProcess` | `GHIDRA_TELEMETRY=log` or a file path: periodic reports of phase, memory, CPU, analyzers and decompiles in progress                                 |
| Builds without Gradle | `nxdecomp/build_decompile.ps1`, `nxdecomp/install_patched.ps1`                                                                         | build `decompile.exe` with MSVC; make a patched install from a stock 12.1.4 install                                                                 |

All three changes were found and checked on Breath of the Wild 1.6.0 (AArch64):

- 3 functions failed with the varnode-hash error.
- 1 function of 612 KB was decompiled in 19 pieces.
- With both fixes, all 83,254 functions decompile.

## Building

From a stock 12.1.4 install:

```powershell
powershell -NoProfile -File nxdecomp\install_patched.ps1 -Install <stock install> -OutDir <patched copy> -JavaHome <JDK 21+>
```

In `coding_workflow`, `Setup-Ghidra-Nxdecomp.ps1` does this for `tools\ghidra_12.1.4_nxdecomp` and
runs a smoke test. Its `INSTALL.md` (section 4) documents the whole setup.

Build outputs go to `build-nxdecomp\`, which `.git\info\exclude` keeps out of git.

## Rules

- New changes go on this branch, one commit per change.
- After each change, re-run `Setup-Ghidra-Nxdecomp.ps1`, and record the bug and the fix in
  `coding_workflow\knowledge\switch-decompile-and-port\07-troubleshooting.md` ("Ghidra fork fixes").
- Keep changes small and off by default where they change behaviour, so they could go upstream.
