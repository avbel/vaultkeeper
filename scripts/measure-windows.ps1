# Measures Vaultkeeper's memory in the three states compared with the macOS step-0 spike.
#
# Windows reports private working set (what the process actually holds in RAM); the macOS numbers in
# docs/solutions/vaultkeeper-architecture.md are physical footprint from experiments/slint-ram. They are close enough
# for a shape comparison, not for byte-exact equality.
#
# Usage:
#   .\scripts\measure-windows.ps1
#   .\scripts\measure-windows.ps1 -ClosedSettleSeconds 15 -NoPrompt
#
# Start from a clean state: `vaultkeeper.exe --quit`, then `vaultkeeper.exe --tray` when the script asks.

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ProcessName = 'vaultkeeper',
    [int]$ClosedSettleSeconds = 10,
    [switch]$NoPrompt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$macTrayOnly = 13.9
$macWindowShown = 47.3
$macWindowClosed = 41.8

function Get-VaultkeeperProcesses {
    @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
}

function Get-PrivateWorkingSetMB {
    param([Parameter(Mandatory)][int]$ProcessId)

    $counter = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process `
        -Filter "IDProcess = $ProcessId" -ErrorAction SilentlyContinue
    $private = if ($counter) { $counter.PSObject.Properties['WorkingSetPrivate'] } else { $null }
    if ($private -and [uint64]$private.Value -gt 0) {
        return [math]::Round([double]$private.Value / 1MB, 1)
    }

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $process) {
        throw "process $ProcessId is gone"
    }
    Write-Warning 'Working Set - Private counter unavailable; falling back to private commit (an overestimate).'
    [math]::Round($process.PrivateMemorySize64 / 1MB, 1)
}

function Wait-ForUser {
    param([string]$Message)

    if ($NoPrompt) {
        return
    }
    Write-Host ''
    Write-Host $Message -ForegroundColor Cyan
    [void](Read-Host 'Press Enter when ready')
}

Write-Host 'Vaultkeeper memory on Windows (MB, private working set)' -ForegroundColor Cyan
Write-Host "macOS reference: $macTrayOnly tray only / $macWindowShown window shown / $macWindowClosed closed + 10 s" `
    -ForegroundColor DarkGray

Wait-ForUser "Step 1/3: run '$ProcessName.exe --quit', wait until it exits, then start '$ProcessName.exe --tray'."
$daemon = Get-VaultkeeperProcesses | Sort-Object StartTime | Select-Object -First 1
if (-not $daemon) {
    throw "no $ProcessName process found; start the tray-only daemon first"
}
$all = @(Get-VaultkeeperProcesses)
if ($all.Count -gt 1) {
    Write-Warning "found $($all.Count) $ProcessName processes; measuring the oldest as the daemon (quit extra windows first)"
}
Start-Sleep -Milliseconds 500
$trayOnlyMB = Get-PrivateWorkingSetMB -ProcessId $daemon.Id

Wait-ForUser 'Step 2/3: open the Quick Panel (Ctrl+Shift+Space) and leave the window visible.'
$windowed = @(Get-VaultkeeperProcesses | Where-Object { $_.MainWindowHandle -ne 0 })
if ($windowed.Count -gt 0) {
    $ui = $windowed | Sort-Object StartTime | Select-Object -Last 1
}
else {
    # Slint's panel may not qualify as Process.MainWindowHandle; the UI is spawned after the daemon.
    $ui = Get-VaultkeeperProcesses | Where-Object { $_.Id -ne $daemon.Id } |
        Sort-Object StartTime | Select-Object -Last 1
}
if (-not $ui) {
    throw 'no Vaultkeeper UI process found; is the Quick Panel open?'
}
Start-Sleep -Milliseconds 500
$windowShownMB = Get-PrivateWorkingSetMB -ProcessId $ui.Id

Wait-ForUser "Step 3/3: close the Quick Panel and leave the app idle for $ClosedSettleSeconds s."
Start-Sleep -Seconds $ClosedSettleSeconds
$windowClosedMB = $null
try {
    $windowClosedMB = Get-PrivateWorkingSetMB -ProcessId $ui.Id
}
catch {
    Write-Warning "UI process $($ui.Id) exited before the closed measurement; the 120 s linger may have expired"
}

$rows = @(
    [pscustomobject]@{
        State            = 'daemon, tray only'
        'Windows (MB)'   = $trayOnlyMB
        'macOS (MB)'     = $macTrayOnly
        'Windows/macOS'  = [math]::Round($trayOnlyMB / $macTrayOnly, 1)
    }
    [pscustomobject]@{
        State            = 'UI, window shown'
        'Windows (MB)'   = $windowShownMB
        'macOS (MB)'     = $macWindowShown
        'Windows/macOS'  = [math]::Round($windowShownMB / $macWindowShown, 1)
    }
    [pscustomobject]@{
        State            = "UI, window closed + $ClosedSettleSeconds s"
        'Windows (MB)'   = $windowClosedMB
        'macOS (MB)'     = $macWindowClosed
        'Windows/macOS'  = $(if ($null -eq $windowClosedMB) { '' } else { [math]::Round($windowClosedMB / $macWindowClosed, 1) })
    }
)

Write-Host ''
$rows | Format-Table -AutoSize
