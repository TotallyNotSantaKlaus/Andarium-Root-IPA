#!/usr/bin/env pwsh
# SPDX-License-Identifier: GPL-2.0-or-later
<#
.SYNOPSIS
    Build and verify the rooted Andarium IPA via WSL2.
.EXAMPLE
    .\build.ps1
    .\build.ps1 -Profile lite
    .\build.ps1 -Profile stealth
    .\build.ps1 -Profile ultimate --selinux enforcing --display-name "Andarium Root"
#>
param(
    [ValidateSet("ultimate", "lite", "stealth")]
    [string]$Profile = "ultimate",
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

$RepoWinSlash = $RepoWin -replace '\\', '/'
$RepoWsl = ((& wsl.exe -d $Distro -- wslpath -a -u $RepoWinSlash) | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($RepoWsl)) {
    throw "Failed to convert workspace path '$RepoWin' to WSL path."
}

$ScriptWsl = "$RepoWsl/scripts/build_rooted_ipa.py"
$AllArgs = @("--profile", $Profile)
if ($BuilderArgs) {
    $AllArgs += $BuilderArgs
}

Write-Host "Running builder in WSL ($Distro) [profile=$Profile]: $ScriptWsl $($AllArgs -join ' ')" -ForegroundColor Cyan

& wsl.exe -d $Distro -- python3 $ScriptWsl @AllArgs
exit $LASTEXITCODE
