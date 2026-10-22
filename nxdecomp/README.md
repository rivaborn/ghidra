# nxdecomp-fixes

This branch is Ghidra 12.1.4 (tag `Ghidra_12.1.4_build`) with the changes the decompilation
pipelines in `rivaborn/coding_workflow` need. The fork's `master` follows upstream development
(12.3 DEV) and is not used: REA supports 12.1.x only.

| Change                         | Files                                                                                                                                  | Why                                                                                                                                                                                                                                                                                                                             |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Varnode-hash fallback          | `Features/Decompiler/src/decompile/cpp/funcdata_varnode.cc`                                                                            | "Unable to find unique hash for varnode" abandoned whole functions over one variable's name; the variable now keeps the shared name, with a warning                                                                                                                                                                             |
| Cleared fall-through           | `PcodeOverride`, `InstructionPcodeOverride`, `PcodeEmit` (SoftwareModeling)                                                            | `Instruction.setFallThrough(null)` never reached the decompiler, so flow ran on past it; such an instruction now ends with a `RETURN`                                                                                                                                                                                           |
| Telemetry                      | `ghidra.util.telemetry.Telemetry` (Generic); hooks in `HeadlessAnalyzer`, `AutoAnalysisManager`, `DecompInterface`, `DecompileProcess` | `GHIDRA_TELEMETRY=log` or a file path: periodic reports of phase, memory, CPU, analyzers and decompiles in progress                                                                                                                                                                                                             |
| Builds without Gradle          | `nxdecomp/build_decompile.ps1`, `nxdecomp/install_patched.ps1`                                                                         | build `decompile.exe` with MSVC; make a patched install from a stock 12.1.4 install                                                                                                                                                                                                                                             |
| Decompiler memory cap          | `statusreport.cc` (new), `ghidra_process.cc`; `DecompileProcess.isReady()`                                                             | `GHIDRA_DECOMPILER_MAXMEM_MB`: a job object (Windows) or `RLIMIT_AS` caps each decompiler. Over it, that function fails with "Out of memory: N MB in use, peak P MB, limit L MB" and a fresh process takes the next. The stack is committed up front and an 8 MB reserve is freed for the reply, so the failure is always clean |
| Decompiler status              | `statusreport.cc`; hooks in `Action::perform`, `FlowInfo`; `DecompileProcess.getNativeStatus()`                                        | with telemetry on, each decompiler writes its function, Action stack, instruction count and memory to a status file every second; telemetry adds it to each decompile                                                                                                                                                           |
| Flow bounded by the body       | `Funcdata::setFlowRange`, `DecompileAt` (optional `<range>`); `DecompileOptions.setFlowBoundedByBody`                                  | off by default. Flow leaving the function's body ends in a return stub instead of being followed (pieces, tail calls into other functions)                                                                                                                                                                                      |
| Branch stubs findable          | `FlowInfo::fillinBranchStubs`                                                                                                          | an existing bug that bounded flow exposed: stubs for out-of-range targets were not in `visited`, so a branch or jump-table entry to one threw "Could not find op at target address"                                                                                                                                             |
| Exit code on script errors     | `AnalyzeHeadless`, `HeadlessAnalyzer`, `HeadlessOptions`                                                                               | `-failOnScriptError`: exit code 2 when a script threw or could not be found or compiled (0 before)                                                                                                                                                                                                                              |
| No C is a failure              | `DecompileResults.markNoCode()`, `DecompInterface`                                                                                     | a decompile that returns a function but none of the C asked for is no longer "completed"; the error says "Decompiler returned no C code"                                                                                                                                                                                        |
| Exit code of a dead decompiler | `DecompileProcess.exitDescription()`                                                                                                   | "Decompiler process died (exit code …, stack overflow)" instead of "died"                                                                                                                                                                                                                                                       |
| Analysis restriction           | `AutoAnalysisManager.setAnalysisRestriction`, `AnalysisScheduler`                                                                      | confines analysis, including work already queued, to a set of addresses: analysing 3 BotW functions went from about 25 minutes to under 1                                                                                                                                                                                       |

All changes were found and checked on Breath of the Wild 1.6.0 (AArch64), among them:

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
