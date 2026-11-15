<#
.SYNOPSIS
  Builds and packages the Windows release: -Build compiles and stages the exe, -Package makes the
  Inno Setup installer and the portable zip from the staged exe.
#>
[CmdletBinding()]
param(
  [switch]$Build,
  [switch]$Package,
  # Absolute path of ISCC.exe. Never looked up on PATH: the release job passes the runner image's copy.
  [string]$Iscc
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not ($Build -or $Package)) {
  throw 'Pass -Build, -Package or both.'
}

$Root = Split-Path -Parent $PSScriptRoot
$Out = Join-Path $Root 'out'
$Stage = Join-Path $Out 'stage'
$Target = 'x86_64-pc-windows-msvc'

# Same source as scripts/version.sh: [workspace.package] version in Cargo.toml.
function Get-WorkspaceVersion {
  $inside = $false
  foreach ($line in Get-Content -LiteralPath (Join-Path $Root 'Cargo.toml')) {
    if ($line -match '^\[workspace\.package\]') { $inside = $true; continue }
    if ($line -match '^\[') { $inside = $false; continue }
    if ($inside -and $line -match '^version\s*=\s*"([^"]*)"') { return $Matches[1] }
  }
  throw 'no version in [workspace.package] of Cargo.toml'
}

function Find-Iscc {
  $roots = @(${env:ProgramFiles(x86)}, $env:ProgramFiles, (Join-Path $env:LOCALAPPDATA 'Programs')) |
    Where-Object { $_ }
  foreach ($r in $roots) {
    $candidate = Join-Path $r 'Inno Setup 6\ISCC.exe'
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }
  throw 'ISCC.exe (Inno Setup 6) not found: install it (winget install JRSoftware.InnoSetup) or pass -Iscc.'
}

function Invoke-Checked {
  param([string]$Exe, [string[]]$Arguments)
  & $Exe @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
}

if ($Build) {
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw 'cargo not found: install Rust from https://rustup.rs and add the MSVC target.'
  }
  Push-Location $Root
  try {
    Invoke-Checked 'cargo' @('build', '--release', '--locked', '--target', $Target, '-p', 'vaultkeeper')
  } finally {
    Pop-Location
  }
  $exe = Join-Path $Root "target\$Target\release\vaultkeeper.exe"
  if (-not (Test-Path -LiteralPath $exe)) { throw "build did not produce $exe" }
  New-Item -ItemType Directory -Force -Path $Stage | Out-Null
  Copy-Item -LiteralPath $exe -Destination (Join-Path $Stage 'vaultkeeper.exe') -Force
  Write-Host "Staged $Stage\vaultkeeper.exe"
}

if ($Package) {
  $stagedExe = Join-Path $Stage 'vaultkeeper.exe'
  if (-not (Test-Path -LiteralPath $stagedExe)) {
    throw "$stagedExe not found: run with -Build first (or place the signed exe there)."
  }
  $version = Get-WorkspaceVersion
  if ($Iscc) {
    if (-not (Test-Path -LiteralPath $Iscc)) { throw "$Iscc not found" }
    $iscc = $Iscc
  } else {
    $iscc = Find-Iscc
  }
  New-Item -ItemType Directory -Force -Path $Out | Out-Null

  Invoke-Checked $iscc @(
    "/DAppVersion=$version",
    "/DStageDir=$Stage",
    (Join-Path $Root 'packaging\windows\vaultkeeper.iss')
  )
  $setup = Join-Path $Out "Vaultkeeper-v$version-x64-setup.exe"
  if (-not (Test-Path -LiteralPath $setup)) { throw "iscc did not produce $setup" }

  $portable = Join-Path $Out 'portable'
  if (Test-Path -LiteralPath $portable) { Remove-Item -LiteralPath $portable -Recurse -Force }
  New-Item -ItemType Directory -Force -Path $portable | Out-Null
  Copy-Item -LiteralPath $stagedExe -Destination $portable
  Copy-Item -LiteralPath (Join-Path $Root 'LICENSE') -Destination $portable
  Copy-Item -LiteralPath (Join-Path $Root 'README.md') -Destination $portable
  $zip = Join-Path $Out "Vaultkeeper-v$version-x64.zip"
  if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
  Compress-Archive -Path (Join-Path $portable '*') -DestinationPath $zip
  Remove-Item -LiteralPath $portable -Recurse -Force

  Write-Host "Created $setup"
  Write-Host "Created $zip"
}
