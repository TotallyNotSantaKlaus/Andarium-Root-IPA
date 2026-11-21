#!/usr/bin/env pwsh
# SPDX-License-Identifier: GPL-2.0-or-later
<#
.SYNOPSIS
    Run the live ADB diagnostic audit against a booted Andarium Root guest on iOS.
.EXAMPLE
    .\audit.ps1 -Connect 192.168.1.42:5555
    .\audit.ps1
#>
param(
    [string]$Connect,
    [string]$Serial,
    [switch]$SkipAdbRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$pyArgs = @("$PSScriptRoot\scripts\live_audit.py")
if ($Connect) { $pyArgs += @("--connect", $Connect) }
if ($Serial) { $pyArgs += @("--serial", $Serial) }
if ($SkipAdbRoot) { $pyArgs += "--skip-adb-root" }

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $python) { throw "Python 3 is required on PATH to run live_audit.py." }

& $python.Source @pyArgs
exit $LASTEXITCODE
