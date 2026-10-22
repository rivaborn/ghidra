# Make a patched Ghidra install from a stock release install plus this branch's changes,
# without a Gradle build:
#   1. copy the stock install to -OutDir (skipped if -OutDir exists, unless -Fresh);
#   2. build decompile.exe from this checkout (build_decompile.ps1) and put it in the copy;
#   3. compile every .java file this branch changed since -BaseTag against the copy's jars and
#      update the classes into their modules' jars (Ghidra/<Area>/<Module>/lib/<Module>.jar).
#   4. copy every processor module this branch changed or added (Ghidra/Processors/<Module>) and
#      compile its SLEIGH (.slaspec -> .sla) with the copy's support\sleigh.bat.
#   5. install every extension this branch changed or added (Ghidra/Extensions/<Name>, e.g. the
#      vendored ghidra-allegrex) into the copy as an installed extension, <OutDir>\Ghidra\Extensions\<Name>:
#      Module.manifest, data (SLEIGH compiled), ghidra_scripts, os, LICENSE*/NOTICE*/README*;
#      extension.properties with version= set to the install's application.version; its Java and
#      Kotlin sources and src\main\resources in lib\<Name>.jar (Kotlin needs -KotlinHome, and adds
#      the Kotlin runtime as lib\kotlin-stdlib.jar). The folder is rebuilt from scratch every run.
#
#   powershell -NoProfile -File nxdecomp\install_patched.ps1 -Install <stock install> -OutDir <patched copy>
#       [-BaseTag Ghidra_12.1.4_build] [-JavaHome <JDK 21+>] [-KotlinHome <kotlinc folder, 2.2.20+>]
#       [-Fresh] [-SkipNative]
#
# The stock install is never modified. Re-run after every change on the branch.
# Windows PowerShell 5.1 compatible.

param(
    [Parameter(Mandatory = $true)][string]$Install,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string]$BaseTag = "Ghidra_12.1.4_build",
    [string]$JavaHome = "",
    [string]$KotlinHome = "",
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
# extensions (Ghidra/Extensions/<Name>) are built on their own, in step 5
$changed = @($changed | Where-Object { $_ -match "^Ghidra/[^/]+/[^/]+/src/main/java/" -and $_ -notmatch "^Ghidra/Extensions/" } |
    Sort-Object -Unique)
if ($changed.Count -eq 0) { Write-Output "no Java changes since $BaseTag" } else {

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
    $jarMode = "uf"
    if (-not (Test-Path $moduleJar)) {
        # a module this branch adds (ConsoleFormats): its folder, manifest and data, and a new jar
        $srcModule = Join-Path $repo "Ghidra\$area\$module"
        if (-not (Test-Path (Join-Path $srcModule "Module.manifest"))) { throw "no jar for $src ($moduleJar)" }
        $dstModule = Join-Path $OutDir "Ghidra\$area\$module"
        New-Item -ItemType Directory -Force (Join-Path $dstModule "lib") | Out-Null
        foreach ($item in @("Module.manifest", "data", "ghidra_scripts")) {
            $from = Join-Path $srcModule $item
            if (Test-Path $from) { Copy-Item -Recurse -Force $from $dstModule }
        }
        $jarMode = "cf"
        Write-Output "new module $module"
    }
    $dir = Split-Path $rel -Parent
    $base = Split-Path $rel -Leaf
    # the class and its nested classes
    $files = Get-ChildItem (Join-Path $classes $dir) -Filter "$base*.class" |
        Where-Object { $_.Name -eq "$base.class" -or $_.Name -like "$base`$*.class" } |
        ForEach-Object { ($dir -replace "\\", "/") + "/" + $_.Name }
    if (-not $files) { throw "no classes compiled for $src" }
    $jarArgs = @()
    foreach ($f in $files) { $jarArgs += @("-C", $classes, $f) }  # -C applies to the next file only
    & $jar $jarMode $moduleJar @jarArgs
    if ($LASTEXITCODE -ne 0) { throw "jar update failed for $moduleJar" }
    Write-Output ("{0,-12} {1} ({2} classes)" -f $module, $rel, @($files).Count)
}
}  # Java changes

# 4. processor modules (SLEIGH): every Ghidra/Processors/<Module> with files changed or added since
#    the base tag. Its sources (Module.manifest, data/**) are copied over the copy's module folder,
#    then every .slaspec of the module is compiled (support\sleigh.bat -a) so no .sla is stale. A
#    new module folder (65816, LR35902) is picked up by Ghidra like the stock ones.
$procChanged = @(git -C $repo diff --name-only $BaseTag -- "Ghidra/Processors")
$procChanged += @(git -C $repo ls-files --others --exclude-standard -- "Ghidra/Processors")
$procModules = @($procChanged | Where-Object { $_ -match "^Ghidra/Processors/([^/]+)/" } |
    ForEach-Object { ([regex]::Match($_, "^Ghidra/Processors/([^/]+)/")).Groups[1].Value } | Sort-Object -Unique)
$sleigh = Join-Path $OutDir "support\sleigh.bat"
foreach ($procModule in $procModules) {
    $srcModule = Join-Path $repo "Ghidra\Processors\$procModule"
    $dstModule = Join-Path $OutDir "Ghidra\Processors\$procModule"
    New-Item -ItemType Directory -Force $dstModule | Out-Null
    foreach ($item in @("Module.manifest", "data")) {
        $from = Join-Path $srcModule $item
        if (Test-Path $from) { Copy-Item -Recurse -Force $from $dstModule }
    }
    $languages = Join-Path $dstModule "data\languages"
    $env:JAVA_HOME = $JavaHome
    # native stderr under 2>&1 would throw with ErrorActionPreference=Stop (Windows PowerShell 5.1)
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = @(& $sleigh -a $languages 2>&1 | ForEach-Object { "$_" })
    $sleighCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    $failed = @($out | Where-Object { $_ -match "error|Error|ERROR" -and $_ -notmatch "0 errors|errors? 0" })
    if ($sleighCode -ne 0 -or $failed.Count -gt 0) {
        throw ("SLEIGH compile failed for processor $procModule`n" + ($out -join "`n"))
    }
    $count = @(Get-ChildItem $languages -Filter *.sla).Count
    Write-Output ("{0,-12} processor installed, {1} .sla compiled" -f $procModule, $count)
}

# 5. extensions: every Ghidra/Extensions/<Name> with a Module.manifest and files changed or added
#    since the base tag (the vendored ghidra-allegrex), installed the way Ghidra installs an
#    extension zip, into <OutDir>\Ghidra\Extensions\<Name>, where Ghidra loads it for every user.
#    Ghidra skips an extension whose version is not the application's, so version= is written here.
$extChanged = @(git -C $repo diff --name-only $BaseTag -- "Ghidra/Extensions")
$extChanged += @(git -C $repo ls-files --others --exclude-standard -- "Ghidra/Extensions")
$extModules = @($extChanged | Where-Object { $_ -match "^Ghidra/Extensions/([^/]+)/" } |
    ForEach-Object { ([regex]::Match($_, "^Ghidra/Extensions/([^/]+)/")).Groups[1].Value } | Sort-Object -Unique |
    Where-Object { Test-Path (Join-Path $repo "Ghidra\Extensions\$_\Module.manifest") })

# run a native tool with its stderr captured: under 2>&1 it would throw with
# ErrorActionPreference=Stop (Windows PowerShell 5.1); returns the output, sets $script:nativeCode
function Invoke-Captured([string]$exe, [string[]]$arguments) {
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $captured = @(& $exe @arguments 2>&1 | ForEach-Object { "$_" })
    $script:nativeCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    return ,$captured
}

foreach ($extModule in $extModules) {
    $srcExt = Join-Path $repo "Ghidra\Extensions\$extModule"
    $dstExt = Join-Path $OutDir "Ghidra\Extensions\$extModule"
    if (Test-Path $dstExt) { Remove-Item -Recurse -Force $dstExt }
    New-Item -ItemType Directory -Force (Join-Path $dstExt "lib") | Out-Null
    foreach ($item in @("Module.manifest", "data", "ghidra_scripts", "os")) {
        $from = Join-Path $srcExt $item
        if (Test-Path $from) { Copy-Item -Recurse -Force $from $dstExt }
    }
    Get-ChildItem $srcExt -File | Where-Object { $_.Name -match "^(LICENSE|NOTICE|README)" } |
        ForEach-Object { Copy-Item -Force $_.FullName $dstExt }
    # never install a .sla from the source tree: the step below compiles every one. (-Filter *.sla
    # would also match .slaspec through its 8.3 short name, so the extension is compared exactly.)
    $dstData = Join-Path $dstExt "data"
    if (Test-Path $dstData) {
        Get-ChildItem -Recurse -File $dstData | Where-Object { $_.Extension -eq ".sla" } | Remove-Item -Force
    }

    # extension.properties: the source is a template (@extname@, @extversion@)
    $propsSrc = Join-Path $srcExt "extension.properties"
    if (-not (Test-Path $propsSrc)) { throw "extension $extModule has no extension.properties" }
    $extProps = @(Get-Content $propsSrc | ForEach-Object {
        if ($_ -match "^\s*version\s*=") { "version=$version" }
        elseif ($_ -match "^\s*createdOn\s*=\s*$") { "createdOn=" + (Get-Date -Format "M/d/yyyy") }
        else { $_ -replace "@extname@", $extModule -replace "@extversion@", $version }
    })
    if (-not ($extProps | Where-Object { $_ -match "^version=" })) { $extProps += "version=$version" }
    Set-Content -Encoding ASCII (Join-Path $dstExt "extension.properties") $extProps

    # SLEIGH
    $languages = Join-Path $dstExt "data\languages"
    $slaCount = 0
    if ((Test-Path $languages) -and @(Get-ChildItem $languages -Filter *.slaspec).Count -gt 0) {
        $env:JAVA_HOME = $JavaHome
        $out = Invoke-Captured $sleigh @("-a", $languages)
        $failed = @($out | Where-Object { $_ -match "error|Error|ERROR" -and $_ -notmatch "0 errors|errors? 0" })
        if ($script:nativeCode -ne 0 -or $failed.Count -gt 0) {
            throw ("SLEIGH compile failed for extension $extModule`n" + ($out -join "`n"))
        }
        $slaCount = @(Get-ChildItem -File $languages | Where-Object { $_.Extension -eq ".sla" }).Count
    }

    # Java and Kotlin: Kotlin first (kotlinc reads the Java sources it refers to), then javac
    # against the Kotlin classes; one jar, lib\<Name>.jar, with src\main\resources
    $javaRoot = Join-Path $srcExt "src\main\java"
    $kotlinRoot = Join-Path $srcExt "src\main\kotlin"
    $javaSources = @()
    $kotlinSources = @()
    if (Test-Path $javaRoot) { $javaSources = @(Get-ChildItem -Recurse $javaRoot -Filter *.java | ForEach-Object { $_.FullName }) }
    if (Test-Path $kotlinRoot) { $kotlinSources = @(Get-ChildItem -Recurse $kotlinRoot -Filter *.kt | ForEach-Object { $_.FullName }) }
    $classCount = 0
    if ($javaSources.Count + $kotlinSources.Count -gt 0) {
        $extClasses = Join-Path $repo "build-nxdecomp\ext-classes\$extModule"
        if (Test-Path $extClasses) { Remove-Item -Recurse -Force $extClasses }
        New-Item -ItemType Directory -Force $extClasses | Out-Null
        # the copy's jars (this extension's folder was just emptied) and any jars the extension ships
        $cp = @(Get-ChildItem -Recurse (Join-Path $OutDir "Ghidra") -Filter *.jar | ForEach-Object { $_.FullName })
        $srcLib = Join-Path $srcExt "lib"
        if (Test-Path $srcLib) {
            Get-ChildItem $srcLib -Filter *.jar | ForEach-Object {
                Copy-Item -Force $_.FullName (Join-Path $dstExt "lib")
                $cp += $_.FullName
            }
        }
        if ($kotlinSources.Count -gt 0) {
            if ($KotlinHome -eq "") { $KotlinHome = $env:KOTLIN_HOME }
            $kotlinc = Join-Path $KotlinHome "bin\kotlinc.bat"
            $stdlib = Join-Path $KotlinHome "lib\kotlin-stdlib.jar"
            if ($KotlinHome -eq "" -or -not (Test-Path $kotlinc) -or -not (Test-Path $stdlib)) {
                throw "extension $extModule has Kotlin sources: pass -KotlinHome <the kotlinc folder of Kotlin 2.2.20+> (github.com/JetBrains/kotlin/releases)"
            }
            $cp += $stdlib
            $kotlinArgs = Join-Path $repo "build-nxdecomp\kotlinc-$extModule.txt"
            $lines = @("-classpath", ("`"" + (($cp | ForEach-Object { $_ -replace "\\", "/" }) -join ";") + "`""),
                "-jvm-target", "21", "-no-stdlib", "-no-reflect", "-nowarn",
                "-d", ("`"" + ($extClasses -replace "\\", "/") + "`""))
            $lines += @(($kotlinSources + $javaSources) | ForEach-Object { "`"" + ($_ -replace "\\", "/") + "`"" })
            Set-Content -Encoding ASCII $kotlinArgs $lines
            $env:JAVA_HOME = $JavaHome
            Write-Output "compiling $($kotlinSources.Count) Kotlin files of $extModule"
            $out = Invoke-Captured $kotlinc @("@$kotlinArgs")
            if ($script:nativeCode -ne 0) { throw ("kotlinc failed for extension $extModule`n" + ($out -join "`n")) }
            Copy-Item -Force $stdlib (Join-Path $dstExt "lib\kotlin-stdlib.jar")
        }
        if ($javaSources.Count -gt 0) {
            $extCpFile = Join-Path $repo "build-nxdecomp\classpath-$extModule.txt"
            Set-Content -Encoding ASCII $extCpFile ("-cp `"" + ((@($cp + $extClasses) | ForEach-Object { $_ -replace "\\", "/" }) -join ";") + "`"")
            Write-Output "compiling $($javaSources.Count) Java files of $extModule"
            & $javac --release 21 -nowarn -encoding UTF-8 -d $extClasses "@$extCpFile" @javaSources
            if ($LASTEXITCODE -ne 0) { throw "javac failed for extension $extModule" }
        }
        $resources = Join-Path $srcExt "src\main\resources"
        if (Test-Path $resources) { Copy-Item -Recurse -Force (Join-Path $resources "*") $extClasses }
        $classCount = @(Get-ChildItem -Recurse $extClasses -Filter *.class).Count
        & $jar cf (Join-Path $dstExt "lib\$extModule.jar") -C $extClasses .
        if ($LASTEXITCODE -ne 0) { throw "jar failed for extension $extModule" }
    }
    Write-Output ("{0,-12} extension installed (version={1}, {2} .sla, {3} classes in lib\{0}.jar)" -f
        $extModule, $version, $slaCount, $classCount)
}

# record what the copy was built from
$head = git -C $repo rev-parse HEAD
$dirty = if (git -C $repo status --porcelain) { " (with uncommitted changes)" } else { "" }
Set-Content -Encoding UTF8 (Join-Path $OutDir "NXDECOMP_PATCHED.txt") @(
    "Patched from $repo",
    "branch $(git -C $repo rev-parse --abbrev-ref HEAD), commit $head$dirty, base $BaseTag",
    "built $(Get-Date -Format s)",
    "Java files:", ($changed | ForEach-Object { "  $_" }),
    "Processor modules:", ($procModules | ForEach-Object { "  $_" }),
    "Extensions:", ($extModules | ForEach-Object { "  $_" }))
Write-Output "patched install ready: $OutDir"
