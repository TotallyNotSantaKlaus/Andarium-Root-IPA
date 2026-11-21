#!/usr/bin/env pwsh
# SPDX-License-Identifier: GPL-2.0-or-later
<#
.SYNOPSIS
    Build and verify a customizable Andarium Root IPA (v4) via WSL2.
.EXAMPLE
    .\build.ps1
    .\build.ps1 -Preset seceng -IconTheme crimson
    .\build.ps1 -Preset gamer -IconTheme cyber
    .\build.ps1 -Preset unrooted -NoRoot -IconTheme stealth
    .\build.ps1 -Config .\andarium-config.json
    .\build.ps1 -Profile lite
#>
param(
    [ValidateSet("", "mix", "seceng", "hacker", "gamer", "privacy", "unrooted")]
    [string]$Preset = "",
    [ValidateSet("ultimate", "lite", "stealth")]
    [string]$Profile = "ultimate",
    [ValidateSet("", "duskjade", "crimson", "cyber", "stealth", "stock")]
    [string]$IconTheme = "",
    [string]$Config = "",
    [switch]$NoRoot,
    [string]$Distro = "kali-linux",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$BuilderArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoWin = (Resolve-Path $PSScriptRoot).Path

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "WSL2 (wsl.exe) is required on Windows to run erofs-utils with security.selinux xattrs."
}

$null = & wsl.exe -d $Distro -- sh -lc 'command -v python3 >/dev/null && command -v mkfs.erofs >/dev/null && command -v fsck.erofs >/dev/null && command -v dump.erofs >/dev/null'
if ($LASTEXITCODE -ne 0) {
    throw "WSL distro '$Distro' is missing python3 or erofs-utils (mkfs.erofs/fsck.erofs/dump.erofs). Install with: wsl -d $Distro -- apt-get update && apt-get install -y python3 erofs-utils"
}

function Convert-ToWslPath([string]$WinPath) {
    $slash = $WinPath -replace '\\', '/'
    $wsl = ((& wsl.exe -d $Distro -- wslpath -a -u $slash) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($wsl)) {
        throw "Failed to convert path '$WinPath' to WSL path."
    }
    return $wsl
}

$RepoWsl = Convert-ToWslPath $RepoWin
$ScriptWsl = "$RepoWsl/scripts/build_rooted_ipa.py"

$AllArgs = @()
if ($Preset) {
    $AllArgs += @("--preset", $Preset)
} else {
    $AllArgs += @("--profile", $Profile)
}
if ($IconTheme) {
    $AllArgs += @("--icon-theme", $IconTheme)
}
if ($Config) {
    $cfgResolved = (Resolve-Path $Config).Path
    $AllArgs += @("--config", (Convert-ToWslPath $cfgResolved))
}
if ($NoRoot) {
    $AllArgs += "--no-root"
}
if ($BuilderArgs) {
    $AllArgs += $BuilderArgs
}

$label = if ($Preset) { "preset=$Preset" } else { "profile=$Profile" }
Write-Host "Running builder in WSL ($Distro) [$label]: $ScriptWsl $($AllArgs -join ' ')" -ForegroundColor Cyan

& wsl.exe -d $Distro -- python3 $ScriptWsl @AllArgs
exit $LASTEXITCODE
