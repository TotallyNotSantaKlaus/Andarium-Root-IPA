#!/usr/bin/env pwsh
# SPDX-License-Identifier: GPL-2.0-or-later
<#
.SYNOPSIS
    Launch the local browser-based Andarium Root Builder Studio UI (http://127.0.0.1:8765).
.DESCRIPTION
    Pick any of the 6 role presets (Mix/Ultimate, Security Engineer, Hacker/RE, Gamer,
    Privacy/Daily, Clean/Unrooted), toggle Root ON/OFF or True Unrooted, pick among
    the 4 custom iOS app icon themes with live previews, customize all 13 preinstalled
    apps with live IPA size estimation, and click "Build & Verify IPA" with live logs.
.EXAMPLE
    .\studio.ps1
    .\studio.ps1 -Port 8766 -Distro kali-linux
#>
param(
    [int]$Port = 8765,
    [string]$Distro = "kali-linux",
    [switch]$NoBrowser
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $py) {
    throw "Python 3 is required on Windows to run studio.ps1 (or run: wsl -d $Distro -- python3 scripts/studio_web.py --no-browser)."
}

$studioArgs = @("$PSScriptRoot\scripts\studio_web.py", "--port", "$Port", "--distro", $Distro)
if ($NoBrowser) { $studioArgs += "--no-browser" }

& $py.Source @studioArgs
exit $LASTEXITCODE
