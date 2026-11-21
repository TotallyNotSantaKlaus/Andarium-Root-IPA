# SPDX-License-Identifier: GPL-2.0-or-later
# Check & auto-update pinned upstream artifacts in manifests/artifacts.json via WSL2.
param(
    [switch]$Apply,
    [string[]]$Only = @(),
    [switch]$Json,
    [string]$Distro = "kali-linux"
)

$ErrorActionPreference = "Stop"
$RepoWin = (Resolve-Path $PSScriptRoot).Path
$RepoWsl = (& wsl -d $Distro -- wslpath -a -u ($RepoWin -replace '\\', '/')).Trim()

$PyArgs = @("$RepoWsl/scripts/update_artifacts.py")
if ($Apply) { $PyArgs += "--apply" }
if ($Only -and $Only.Count -gt 0) { $PyArgs += @("--only", ($Only -join ",")) }
if ($Json)  { $PyArgs += "--json" }

& wsl -d $Distro -- python3 @PyArgs
exit $LASTEXITCODE
