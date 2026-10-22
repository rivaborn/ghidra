# Make a patched Ghidra install from a stock release install plus this branch's changes,
# without a Gradle build:
#   1. copy the stock install to -OutDir (skipped if -OutDir exists, unless -Fresh);
#   2. build decompile.exe from this checkout (build_decompile.ps1) and put it in the copy;
#   3. compile every .java file this branch changed since -BaseTag against the copy's jars and
#      update the classes into their modules' jars (Ghidra/<Area>/<Module>/lib/<Module>.jar).
#
#   powershell -NoProfile -File nxdecomp\install_patched.ps1 -Install <stock install> -OutDir <patched copy>
#       [-BaseTag Ghidra_12.1.4_build] [-JavaHome <JDK 21+>] [-Fresh] [-SkipNative]
#
# The stock install is never modified. Re-run after every change on the branch.
# Windows PowerShell 5.1 compatible.

param(
    [Parameter(Mandatory = $true)][string]$Install,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string]$BaseTag = "Ghidra_12.1.4_build",
    [string]$JavaHome = "",
    [switch]$Fresh,
    [switch]$SkipNative
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path (Join-Path $Install "support\analyzeHeadless.bat"))) { throw "not a Ghidra install: $Install" }
$installFull = (Resolve-Path $Install).Path.TrimEnd("\")
if ([IO.Path]::GetFullPath($OutDir).TrimEnd("\") -eq $installFull) { throw "-OutDir must differ from -Install" }

# the installed version must be the one the branch starts from
$props = Get-Content (Join-Path $Install "Ghidra\application.properties")
$version = ($props | Where-Object { $_ -match "^application.version=" }) -replace "^application.version=", ""
if ($BaseTag -notmatch [regex]::Escape($version)) { throw "install is Ghidra $version but -BaseTag is $BaseTag" }

if ($JavaHome -eq "") { $JavaHome = $env:JAVA_HOME }
$javac = Join-Path $JavaHome "bin\javac.exe"
$jar = Join-Path $JavaHome "bin\jar.exe"
if (-not (Test-Path $javac)) { throw "javac not found; pass -JavaHome (JDK 21+)" }

# 1. the copy
if ($Fresh -and (Test-Path $OutDir)) { Remove-Item -Recurse -Force $OutDir }
if (-not (Test-Path $OutDir)) {
    Write-Output "copying $Install -> $OutDir"
    Copy-Item -Recurse $Install $OutDir
}
$OutDir = (Resolve-Path $OutDir).Path

# 2. the native decompiler
if (-not $SkipNative) {
    $build = Join-Path $repo "build-nxdecomp\install"
    & (Join-Path $PSScriptRoot "build_decompile.ps1") -OutDir $build
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null) { throw "build_decompile.ps1 failed" }
    Copy-Item -Force (Join-Path $build "decompile.exe") (Join-Path $OutDir "Ghidra\Features\Decompiler\os\win_x86_64\decompile.exe")
    Write-Output "installed decompile.exe"
}

# 3. the Java changes
$changed = @(git -C $repo diff --name-only $BaseTag -- "*.java")
$changed += @(git -C $repo ls-files --others --exclude-standard -- "*.java")
$changed = @($changed | Where-Object { $_ -match "^Ghidra/[^/]+/[^/]+/src/main/java/" } | Sort-Object -Unique)
if ($changed.Count -eq 0) { Write-Output "no Java changes since $BaseTag"; exit 0 }

$classes = Join-Path $repo "build-nxdecomp\classes"
if (Test-Path $classes) { Remove-Item -Recurse -Force $classes }
New-Item -ItemType Directory -Force $classes | Out-Null
$jars = Get-ChildItem -Recurse (Join-Path $OutDir "Ghidra") -Filter *.jar | ForEach-Object { $_.FullName }
$cpFile = Join-Path $repo "build-nxdecomp\classpath.txt"
Set-Content -Encoding ASCII $cpFile ("-cp `"" + (($jars | ForEach-Object { $_ -replace "\\", "/" }) -join ";") + "`"")
$sources = $changed | ForEach-Object { Join-Path $repo $_ }
Write-Output "compiling $($sources.Count) changed Java files"
& $javac --release 21 -nowarn -encoding UTF-8 -d $classes "@$cpFile" @sources
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

foreach ($src in $changed) {
    $m = [regex]::Match($src, "^Ghidra/([^/]+)/([^/]+)/src/main/java/(.+)\.java$")
    $area = $m.Groups[1].Value; $module = $m.Groups[2].Value; $rel = $m.Groups[3].Value
    $moduleJar = Join-Path $OutDir "Ghidra\$area\$module\lib\$module.jar"
    if (-not (Test-Path $moduleJar)) { throw "no jar for $src ($moduleJar)" }
    $dir = Split-Path $rel -Parent
    $base = Split-Path $rel -Leaf
    # the class and its nested classes
    $files = Get-ChildItem (Join-Path $classes $dir) -Filter "$base*.class" |
        Where-Object { $_.Name -eq "$base.class" -or $_.Name -like "$base`$*.class" } |
        ForEach-Object { ($dir -replace "\\", "/") + "/" + $_.Name }
    if (-not $files) { throw "no classes compiled for $src" }
    $jarArgs = @()
    foreach ($f in $files) { $jarArgs += @("-C", $classes, $f) }  # -C applies to the next file only
    & $jar uf $moduleJar @jarArgs
    if ($LASTEXITCODE -ne 0) { throw "jar update failed for $moduleJar" }
    Write-Output ("{0,-12} {1} ({2} classes)" -f $module, $rel, @($files).Count)
}

# record what the copy was built from
$head = git -C $repo rev-parse HEAD
$dirty = if (git -C $repo status --porcelain) { " (with uncommitted changes)" } else { "" }
Set-Content -Encoding UTF8 (Join-Path $OutDir "NXDECOMP_PATCHED.txt") @(
    "Patched from $repo",
    "branch $(git -C $repo rev-parse --abbrev-ref HEAD), commit $head$dirty, base $BaseTag",
    "built $(Get-Date -Format s)",
    "Java files:", ($changed | ForEach-Object { "  $_" }))
Write-Output "patched install ready: $OutDir"
