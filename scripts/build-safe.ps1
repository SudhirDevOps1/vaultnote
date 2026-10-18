<#
.SYNOPSIS
    Throttled cargo wrapper for a thermally-limited laptop.

.DESCRIPTION
    Machine: i5-6300U, 2 physical / 4 logical cores, 15W TDP. A default
    `cargo build` saturates the package and the machine shuts down.

    Two lessons are baked in here, both learned the hard way on this box:

    1. `cargo -j 1` is NOT enough. `-j` limits how many *crates* build at once;
       a single rustc still drives LLVM across every core. Measured here:
       `-j 1` still pinned the CPU at 68-85%.

    2. Setting ProcessorAffinity on a `cmd /c cargo ...` wrapper is a race.
       cmd spawns cargo within the same second, so cargo inherits the old
       all-CPU affinity. Observed: cmd pinned to CPU 0 while its child cargo
       ran on all four. So cargo is started directly here, and the whole
       process tree is re-pinned on every watchdog tick, which also catches
       each newly spawned rustc.

.EXAMPLE
    .\scripts\build-safe.ps1 -CargoArgs "check --all-targets"

.EXAMPLE
    .\scripts\build-safe.ps1 -CargoArgs "test" -CpuCount 1 -LoadCeiling 75
#>
[CmdletBinding()]
param(
    [string] $CargoArgs   = "check --all-targets",
    [ValidateRange(1, 64)] [int] $CpuCount = 1,
    [int]    $LoadCeiling = 75,
    [int]    $BreachLimit = 6,
    [int]    $SampleSecs  = 3
)

$ErrorActionPreference = "Stop"

$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path $cargoBin) { $env:PATH = "$cargoBin;$env:PATH" }
$cargoExe = (Get-Command cargo -ErrorAction SilentlyContinue).Source
if (-not $cargoExe) { Write-Error "cargo not found on PATH"; exit 127 }

$projectDir = Split-Path -Parent $PSScriptRoot
$srcDir     = Join-Path $projectDir "src-tauri"
$outLog     = Join-Path $env:TEMP "vaultnote-cargo.out.log"
$errLog     = Join-Path $env:TEMP "vaultnote-cargo.err.log"

$logical = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$use     = [math]::Min($CpuCount, $logical)
$mask    = (1 -shl $use) - 1

# Every process the build spawns, directly or indirectly.
$treeNames = @("cargo", "rustc", "cl", "link", "lib", "cmake", "ninja")

function Set-TreeAffinity {
    $fixed = 0
    foreach ($n in $treeNames) {
        foreach ($p in (Get-Process -Name $n -ErrorAction SilentlyContinue)) {
            try {
                if ($p.ProcessorAffinity.ToInt64() -ne $mask) {
                    $p.ProcessorAffinity = [IntPtr]$mask
                    $fixed++
                }
                if ($p.PriorityClass -ne "BelowNormal") { $p.PriorityClass = "BelowNormal" }
            } catch { }
        }
    }
    return $fixed
}

Write-Host "Build directory : $srcDir"
Write-Host "Command         : cargo $CargoArgs"
Write-Host "CPU affinity    : $use of $logical logical processors (mask 0x$($mask.ToString('X')))"
Write-Host "Priority        : BelowNormal (whole tree)"
Write-Host "Load ceiling    : $LoadCeiling% sustained over $BreachLimit samples"
Write-Host ""
Write-Host "Note: this machine idles around 40% with a browser and an agent"
Write-Host "session open. Close them for a faster, cooler build."
Write-Host ""

foreach ($f in @($outLog, $errLog)) { if (Test-Path $f) { Remove-Item $f -Force } }

# Start cargo directly so it can be pinned before it spawns rustc.
$proc = Start-Process -FilePath $cargoExe `
    -ArgumentList $CargoArgs `
    -WorkingDirectory $srcDir `
    -NoNewWindow -PassThru `
    -RedirectStandardOutput $outLog `
    -RedirectStandardError  $errLog

$rePinned = Set-TreeAffinity
Write-Host "cargo started as pid $($proc.Id); re-pinned $rePinned process(es)."
Write-Host ""

$peak = 0.0; $sum = 0.0; $n = 0; $breaches = 0

Write-Host "Monitoring CPU load... (Ctrl+C to stop it yourself)"
Write-Host ""

while (-not $proc.HasExited) {
    Start-Sleep -Seconds $SampleSecs

    # Catch every newly spawned rustc before it can burn all four cores.
    $rePinned = Set-TreeAffinity

    $load = (Get-Counter "\Processor(_Total)\% Processor Time" `
             -SampleInterval 1 -MaxSamples 1).CounterSamples[0].CookedValue

    $peak = [math]::Max($peak, $load)
    $sum += $load; $n++

    $bar = "#" * [int]($load / 5)
    $note = if ($rePinned -gt 0) { "  (re-pinned $rePinned)" } else { "" }
    Write-Host ("  {0,6:N1}% |{1}{2}" -f $load, $bar.PadRight(20), $note)

    if ($load -ge $LoadCeiling) {
        $breaches++
        if ($breaches -ge $BreachLimit) {
            Write-Host ""
            Write-Host "!! Load stayed at or above $LoadCeiling% for $BreachLimit samples."
            Write-Host "!! Stopping the build to protect the machine."
            try { taskkill /PID $proc.Id /T /F | Out-Null } catch { }
            Start-Sleep -Seconds 2
            Set-TreeAffinity | Out-Null
            Write-Host ""
            Write-Host "--- last 25 log lines ---"
            if (Test-Path $errLog) { Get-Content $errLog -Tail 25 }
            Write-Host ""
            Write-Host "Partial results are cached in target\. Nothing is lost."
            Write-Host "Let the machine cool, then re-run."
            exit 2
        }
    }
    else { $breaches = 0 }
}

$proc.WaitForExit()
$code = $proc.ExitCode

Write-Host ""
Write-Host "=== build finished (exit $code) ==="
if ($n -gt 0) { Write-Host ("CPU  peak {0:N1}%   avg {1:N1}%   over {2} samples" -f $peak, ($sum / $n), $n) }
Write-Host ""
Write-Host "--- stdout ---"
if (Test-Path $outLog) { Get-Content $outLog }
Write-Host "--- stderr ---"
if (Test-Path $errLog) { Get-Content $errLog }

exit $code