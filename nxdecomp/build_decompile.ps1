# Build the Windows decompiler (decompile.exe) from this checkout with MSVC, the way
# Ghidra/Features/Decompiler/buildNatives.gradle does (same sources, flags and defines),
# without Gradle. The source list is read from buildNatives.gradle so it stays in step.
#
#   powershell -NoProfile -File nxdecomp\build_decompile.ps1 [-OutDir <dir>]
#
# Output: <OutDir>\decompile.exe (default: build-nxdecomp\ under the repository root).
# Windows PowerShell 5.1 compatible.

param(
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$src = Join-Path $repo "Ghidra\Features\Decompiler\src\decompile\cpp"
$gradle = Join-Path $repo "Ghidra\Features\Decompiler\buildNatives.gradle"
if ($OutDir -eq "") { $OutDir = Join-Path $repo "build-nxdecomp" }
$obj = Join-Path $OutDir "obj"
New-Item -ItemType Directory -Force $obj | Out-Null

# sources: the `include "x.cc"` lines of the decompile(NativeExecutableSpec) block, minus commented ones
$text = Get-Content $gradle -Raw
$start = $text.IndexOf("decompile(NativeExecutableSpec)")
$end = $text.IndexOf("// end decompile", $start)
$block = $text.Substring($start, $end - $start)
$sources = @()
foreach ($line in ($block -split "`n")) {
    $t = $line.Trim()
    if ($t -match '^include "([^"]+\.cc)"') { $sources += (Join-Path $src $Matches[1]) }
}
if ($sources.Count -lt 50) { throw "only $($sources.Count) sources found in $gradle" }

# MSVC environment (vswhere -> vcvarsall x64)
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "Visual Studio with C++ tools not found" }
$bat = Join-Path $vs "VC\Auxiliary\Build\vcvarsall.bat"
cmd /c "`"$bat`" x64 >nul && set" | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2] }
}

$flags = @("/nologo", "/c", "/EHsc", "/W3", "/O2", "/Oy", "/GL", "/std:c++14",
    "/D_SECURE_SCL=0", "/D_HAS_ITERATOR_DEBUGGING=0",
    "/DWINDOWS", "/D_WINDOWS", "/DWIN32", "/D_WIN32", "/DWIN64", "/D_WIN64",
    "/I$src", "/Fo$obj\")
Write-Output "compiling $($sources.Count) sources"
& cl.exe @flags @sources 2>&1 | Where-Object { $_ -match "error|fatal" }
if ($LASTEXITCODE -ne 0) { throw "cl.exe failed ($LASTEXITCODE)" }
$objs = Get-ChildItem $obj -Filter *.obj | ForEach-Object { $_.FullName }
& link.exe /nologo /LTCG /OUT:"$OutDir\decompile.exe" @objs ws2_32.lib 2>&1 | Where-Object { $_ -match "error|fatal" }
if ($LASTEXITCODE -ne 0) { throw "link.exe failed ($LASTEXITCODE)" }
Write-Output "built $OutDir\decompile.exe"
