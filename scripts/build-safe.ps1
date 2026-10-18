<#
.SYNOPSIS
    Throttled cargo wrapper for a thermally-limited laptop.

.DESCRIPTION
    Machine: i5-6300U, 2 physical / 4 logical cores, 15W TDP. A default
    `cargo build` saturates the package and the machine shuts down.

    `cargo -j 1` is NOT enough on its own. `-j` limits how many *crates* build
    concurrently; a single `rustc` still drives LLVM across every core. Measured
    on this machine: `-j 1` still pinned the CPU at 68-85%.

    So this wrapper uses three independent brakes:
      1. Processor affinity — the whole build tree is pinned to N logical CPUs.
         Child processes inherit affinity, so one setting covers cargo, every
         rustc it spawns, and every `cc`/link step.
      2. Process priority — BelowNormal, so the build yields to anything else.
      3. Sustained-load watchdog — samples total CPU and kills the build if it
         stays above the ceiling for several consecutive samples. Sustained
         load is what trips thermal protection; a short spike is harmless.

.EXAMPLE
    .\scripts\build-safe.ps1 -CargoArgs "check --all-targets"

.EXAMPLE
    .\scripts\build-safe.ps1 -CargoArgs "test" -CpuCount 1 -LoadCeiling 55
#>
[CmdletBinding()]
param(
    [string] $CargoArgs   = "check --all-targets",
    [ValidateRange(1, 64)] [int] $CpuCount = 2,
    [int]    $LoadCeiling = 70,
    [int]    $BreachLimit = 4,
    [int]    $SampleSecs  = 5
)

$ErrorActionPreference = "Stop"

$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path $cargoBin) { $env:PATH = "$cargoBin;$env:PATH" }

$projectDir = Split-Path -Parent $PSScriptRoot
$srcDir     = Join-Path $projectDir "src-tauri"
$log        = Join-Path $env:TEMP "vaultnote-cargo.log"

$logical = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$use     = [math]::Min($CpuCount, $logical)
$mask    = (1 -shl $use) - 1

Write-Host "Build directory : $srcDir"
Write-Host "Command         : cargo $CargoArgs"
Write-Host "CPU affinity    : $use of $logical logical processors (mask 0x$($mask.ToString('X')))"
Write-Host "Priority        : BelowNormal"
Write-Host "Load ceiling    : $LoadCeiling% sustained over $BreachLimit samples"
Write-Host "Log             : $log"
Write-Host ""

if (Test-Path $log) { Remove-Item $log -Force }

$proc = Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/c", "cargo $CargoArgs > `"$log`" 2>&1" `
    -WorkingDirectory $srcDir `
    -NoNewWindow -PassThru

Start-Sleep -Milliseconds 400
try {
    $proc.ProcessorAffinity = [IntPtr]$mask
    $proc.PriorityClass    = "BelowNormal"
    Write-Host "Affinity and priority applied to pid $($proc.Id); children inherit them."
}
catch {
    Write-Warning "Could not set affinity/priority: $($_.Exception.Message)"
}
Write-Host ""

$peak = 0.0; $sum = 0.0; $n = 0; $breaches = 0

Write-Host "Monitoring CPU load... (Ctrl+C to stop it yourself)"
Write-Host ""

while (-not $proc.HasExited) {
    Start-Sleep -Seconds $SampleSecs

    # Refresh affinity each sample: a long-lived cmd should still hold it, but
    # this is cheap insurance against a child resetting it.
    try { if (-not $proc.HasExited) { $proc.ProcessorAffinity = [IntPtr]$mask } } catch { }

    $load = (Get-Counter "\Processor(_Total)\% Processor Time" `
             -SampleInterval 1 -MaxSamples 1).CounterSamples[0].CookedValue

    $peak = [math]::Max($peak, $load)
    $sum += $load; $n++

    $pct   = [math]::Round($load)
    $bar   = "#" * [int]($load / 5)
    Write-Host ("  {0,6:N1}% |{1}" -f $load, $bar.PadRight(20))

    if ($load -ge $LoadCeiling) {
        $breaches++
        if ($breaches -ge $BreachLimit) {
            Write-Host ""
            Write-Host "!! Load stayed at or above $LoadCeiling% for $BreachLimit samples."
            Write-Host "!! Stopping the build to protect the machine."
            try { taskkill /PID $proc.Id /T /F | Out-Null } catch { }
            Start-Sleep -Seconds 2
            if (Test-Path $log) { Write-Host ""; Write-Host "--- last 25 log lines ---"; Get-Content $log -Tail 25 }
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
Write-Host "--- log ---"
if (Test-Path $log) { Get-Content $log }

exit $code