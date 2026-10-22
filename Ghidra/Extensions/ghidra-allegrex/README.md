# ghidra-allegrex (vendored)

Source of the Ghidra processor extension for the **Sony Allegrex** CPU (PlayStation Portable),
vendored into this branch so `nxdecomp\install_patched.ps1` builds it for the patched Ghidra
12.1.4 install (the upstream release v21.4 is built for Ghidra 12.1.3 only, and Ghidra refuses
an extension whose `version` does not match the application).

| Item            | Value                                                                     |
| --------------- | ------------------------------------------------------------------------- |
| Upstream        | https://github.com/kotcrab/ghidra-allegrex (author: Kotcrab)              |
| Tag             | `v21.4`                                                                   |
| Commit          | `8d5ca58e609ad7e732d550036126b6b0f99bd663` ("Fix build", 2026-08-25)      |
| License         | Apache License 2.0 (`LICENSE`, copied unchanged)                          |
| Upstream README | `UPSTREAM_README.md` (copied unchanged), upstream history in `CHANGES.md` |

Copied unchanged: `Module.manifest`, `extension.properties` (a template: the installer writes
the real one with `version=` set to the install's `application.version`), `data\` (SLEIGH
sources, patterns), `ghidra_scripts\`, `src\main\java`, `src\main\kotlin`, `src\main\resources`.
Left out: the Gradle build (`build.gradle`, wrapper, CI workflow), so the fork's own Gradle build
does not pick this folder up as a project. Compiled `.sla` files and jars are never committed.

## Building

`nxdecomp\install_patched.ps1` (step 5) installs it into `<OutDir>\Ghidra\Extensions\ghidra-allegrex`:
SLEIGH compiled with `support\sleigh.bat -a`, the Kotlin sources compiled with `kotlinc`
(`-KotlinHome`, Kotlin 2.2.20 or newer: 2.0.x cannot parse JDK 25's version string), the Java
sources with `javac --release 21`, both into `lib\ghidra-allegrex.jar`, plus the Kotlin runtime
`lib\kotlin-stdlib.jar`. Upstream builds with Kotlin 2.0.21 through Gradle; the sources compile
unchanged with 2.2.20 against Ghidra 12.1.4 (warnings only).

