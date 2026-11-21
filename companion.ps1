#!/usr/bin/env pwsh
# SPDX-License-Identifier: GPL-2.0-or-later
<#
.SYNOPSIS
    Windows PC Companion CLI for a booted Andarium Root guest on iOS.
.DESCRIPTION
    One-command host workflows over ADB over network:
      - status           Show live Android guest status (`andarium-ctl status`)
      - shell            Open an interactive root shell with Andarium aliases loaded
      - webui            Forward localhost:8787 to your PC and open the Control Panel in your PC browser
      - frida            Start frida-server on Android and forward tcp:27042 to localhost:27042
      - frida-stop       Stop frida-server and remove port forward
      - ssh-setup        Push your PC's SSH public key, start Dropbear SSH (port 2222), and forward tcp:2222
      - ssh              Connect via OpenSSH to root@127.0.0.1:2222 (after ssh-setup)
      - mitm             Push a Burp/mitmproxy/HTTP Toolkit CA cert (.pem/.crt/.der) to Android 17 Conscrypt + optionally set HTTP proxy
      - proxy-clear      Clear global HTTP proxy on Android
      - mode             Switch live operating mode (`-Arg dev|pentest|gamer|stealth`)
      - root             Hide or restore Magisk root at runtime (`-Arg hide|restore|status`)
      - backup           Export Andarium Root config/DenyList/SSH keys JSON to PC (`-Arg backup.json`)
      - install-bundled  Install pre-staged APKs from /odm/andarium-root/apks over ADB (works even on --no-root IPAs!)
      - stealth          Toggle Stealth Mode (`-Arg on` or `-Arg off`)
      - selinux          Toggle SELinux (`-Arg permissive` or `-Arg enforcing`)
      - install          Install a local APK onto Android (`-Arg C:\path\app.apk`)
      - logcat           Tail Android logcat or boot log (`-Arg boot` for /data/adb/andarium-root.log)
      - audit            Run the full live ADB audit (`audit.ps1`)
.EXAMPLE
    .\companion.ps1 -Connect 192.168.1.42:5555 -Action webui
    .\companion.ps1 -Action mode -Arg pentest
    .\companion.ps1 -Action frida
    .\companion.ps1 -Action ssh-setup
    .\companion.ps1 -Action mitm -Arg C:\Users\you\burp.der -Proxy 192.168.1.10:8080
    .\companion.ps1 -Action backup -Arg .\andarium-backup.json
#>
param(
    [ValidateSet(
        "status", "shell", "webui", "frida", "frida-stop", "frida-inject",
        "pcap-start", "pcap-stop", "pcap-pull",
        "spoof", "firewall", "tproxy", "dns", "debloat", "macro",
        "ssh-setup", "ssh", "mitm", "proxy-clear", "mode", "root",
        "backup", "install-bundled", "stealth", "selinux", "install",
        "logcat", "audit", "update-check"
    )]
    [string]$Action = "status",
    [string]$Connect,
    [string]$Serial,
    [string]$Arg,
    [string]$Arg2,
    [string]$Proxy,
    [int]$SshPort = 2222
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw "adb is not on PATH. Install Android Platform-Tools first."
}

$Target = if ($Serial) { $Serial } elseif ($Connect) { $Connect } else { $null }

function Invoke-Adb {
    param([string[]]$AdbArgs)
    $full = @()
    if ($Target) { $full += @("-s", $Target) }
    $full += $AdbArgs
    & adb @full
    if ($LASTEXITCODE -ne 0) { throw "adb failed: $($full -join ' ')" }
}

function Invoke-AdbCapture {
    param([string[]]$AdbArgs)
    $full = @()
    if ($Target) { $full += @("-s", $Target) }
    $full += $AdbArgs
    $out = & adb @full
    if ($LASTEXITCODE -ne 0) { throw "adb failed: $($full -join ' ')" }
    return ($out | Out-String).Trim()
}

if ($Connect) {
    Write-Host "[companion] Connecting to $Connect..." -ForegroundColor Cyan
    & adb connect $Connect
}

switch ($Action) {
    "status" {
        Invoke-Adb @("shell", "su", "-c", "andarium-ctl status")
    }
    "shell" {
        Write-Host "[companion] Opening root shell (aliases from /data/adb/andarium/profile loaded)..." -ForegroundColor Cyan
        Invoke-Adb @("shell", "-t", "su -c 'ENV=/data/adb/andarium/profile /system/bin/sh'")
    }
    "webui" {
        Invoke-Adb @("shell", "su", "-c", "andarium-ctl webui start")
        $tok = Invoke-AdbCapture @("shell", "su", "-c", "cat /data/adb/andarium/run/webui.token")
        Invoke-Adb @("forward", "tcp:8787", "tcp:8787")
        $url = "http://127.0.0.1:8787/?token=$tok"
        Write-Host "[companion] Control Panel ready on PC: $url" -ForegroundColor Green
        Start-Process $url
    }
    "frida" {
        Invoke-Adb @("shell", "su", "-c", "andarium-ctl frida start 127.0.0.1:27042")
        Invoke-Adb @("forward", "tcp:27042", "tcp:27042")
        Write-Host "[companion] Frida Server running and forwarded to 127.0.0.1:27042" -ForegroundColor Green
        Write-Host "            Connect with: frida-ps -H 127.0.0.1:27042" -ForegroundColor Gray
    }
    "frida-stop" {
        Invoke-Adb @("shell", "su", "-c", "andarium-ctl frida stop")
        & adb forward --remove tcp:27042 2>$null
        Write-Host "[companion] Frida Server stopped." -ForegroundColor Yellow
    }
    "frida-inject" {
        if (-not $Arg) { throw "Usage: -Action frida-inject -Arg <package> -Arg2 <script.js> (default: ssl-pinning-bypass.js)" }
        $script = if ($Arg2) { $Arg2 } else { "ssl-pinning-bypass.js" }
        Invoke-Adb @("shell", "su", "-c", "andarium-workbench frida-run spawn '$Arg' '$script'")
    }
    "pcap-start" {
        $bpf = if ($Arg) { $Arg } else { "" }
        Invoke-Adb @("shell", "su", "-c", "andarium-workbench pcap-start '$bpf'")
    }
    "pcap-stop" {
        Invoke-Adb @("shell", "su", "-c", "andarium-workbench pcap-stop")
    }
    "pcap-pull" {
        $dest = if ($Arg) { $Arg } else { ".\pcaps" }
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        $list = Invoke-AdbCapture @("shell", "su", "-c", "ls -1 /data/adb/andarium/pcaps/*.pcap* 2>/dev/null || true")
        $files = @($list -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -like "*capture-*" })
        if ($files.Count -eq 0) { Write-Host "[companion] No PCAP files found." -ForegroundColor Yellow; break }
        foreach ($rf in $files) {
            $bn = Split-Path -Leaf $rf
            Invoke-Adb @("shell", "su", "-c", "cp -f '$rf' /data/local/tmp/$bn && chmod 0644 /data/local/tmp/$bn")
            Invoke-Adb @("pull", "/data/local/tmp/$bn", (Join-Path $dest $bn))
            Invoke-Adb @("shell", "rm -f /data/local/tmp/$bn")
        }
        Write-Host "[companion] Pulled $($files.Count) PCAP file(s) to $dest" -ForegroundColor Green
    }
    "spoof" {
        if (-not $Arg) { Invoke-Adb @("shell", "su", "-c", "andarium-spoof status") }
        else { Invoke-Adb @("shell", "su", "-c", "andarium-spoof set-profile '$Arg'") }
    }
    "firewall" {
        if (-not $Arg) { Invoke-Adb @("shell", "su", "-c", "andarium-net fw-list") }
        elseif ($Arg -eq "flush") { Invoke-Adb @("shell", "su", "-c", "andarium-net fw-flush") }
        elseif ($Arg2 -eq "unblock") { Invoke-Adb @("shell", "su", "-c", "andarium-net fw-unblock '$Arg'") }
        else { Invoke-Adb @("shell", "su", "-c", "andarium-net fw-block '$Arg'") }
    }
    "tproxy" {
        if (-not $Arg -or $Arg -eq "clear") { Invoke-Adb @("shell", "su", "-c", "andarium-net tproxy-clear") }
        else {
            $scope = if ($Arg2) { $Arg2 } else { "all" }
            Invoke-Adb @("shell", "su", "-c", "andarium-net tproxy-set '$Arg' '$scope' '80,443'")
        }
    }
    "dns" {
        $preset = if ($Arg) { $Arg } else { "cloudflare" }
        Invoke-Adb @("shell", "su", "-c", "andarium-net dns-set '$preset'")
    }
    "debloat" {
        if (-not $Arg) { Invoke-Adb @("shell", "su", "-c", "andarium-auto debloat-list") }
        elseif ($Arg -eq "restore-all") { Invoke-Adb @("shell", "su", "-c", "andarium-auto restore-all") }
        elseif ($Arg2 -eq "unfreeze") { Invoke-Adb @("shell", "su", "-c", "andarium-auto unfreeze '$Arg'") }
        else { Invoke-Adb @("shell", "su", "-c", "andarium-auto freeze '$Arg'") }
    }
    "macro" {
        $m = if ($Arg) { $Arg } else { "dump-env" }
        Invoke-Adb @("shell", "su", "-c", "andarium-auto macro '$m'")
    }
    "update-check" {
        & "$PSScriptRoot\update.ps1"
    }
    "ssh-setup" {
        $keyFile = $Arg
        if (-not $keyFile) {
            foreach ($cand in @("$HOME\.ssh\id_ed25519.pub", "$HOME\.ssh\id_rsa.pub")) {
                if (Test-Path $cand) { $keyFile = $cand; break }
            }
        }
        if (-not $keyFile -or -not (Test-Path $keyFile)) {
            throw "No SSH public key found. Generate one with `ssh-keygen -t ed25519` or pass `-Arg path\to\key.pub`."
        }
        $pubkey = (Get-Content -Raw $keyFile).Trim()
        $escaped = $pubkey -replace "'", "'\''"
        Invoke-Adb @("shell", "su", "-c", "andarium-ctl ssh addkey '$escaped'")
        Invoke-Adb @("shell", "su", "-c", "andarium-ctl ssh start $SshPort")
        Invoke-Adb @("forward", "tcp:$SshPort", "tcp:$SshPort")
        Write-Host "[companion] Dropbear SSH ready! Connect with:" -ForegroundColor Green
        Write-Host "            ssh -p $SshPort root@127.0.0.1" -ForegroundColor Cyan
        Write-Host "            (or run: .\companion.ps1 -Action ssh)" -ForegroundColor Gray
    }
    "ssh" {
        Invoke-Adb @("forward", "tcp:$SshPort", "tcp:$SshPort")
        & ssh -p $SshPort -o StrictHostKeyChecking=accept-new root@127.0.0.1
    }
    "mitm" {
        if (-not $Arg -or -not (Test-Path $Arg)) {
            throw "Pass path to a PEM/CRT/DER CA certificate via -Arg (e.g., -Arg C:\Users\you\burp.der)"
        }
        $certWin = (Resolve-Path $Arg).Path
        $certSlash = $certWin -replace '\\', '/'
        # Convert to Android <subject_hash_old>.0 PEM using WSL openssl
        $tmpOut = Join-Path ([System.IO.Path]::GetTempPath()) "andarium_mitm_cert"
        New-Item -ItemType Directory -Force -Path $tmpOut | Out-Null
        $tmpOutSlash = $tmpOut -replace '\\', '/'
        $hashName = ((& wsl.exe -d kali-linux -- python3 -c @"
import subprocess, pathlib, sys
src = pathlib.Path(subprocess.check_output(['wslpath', '-a', '-u', '$certSlash'], text=True).strip())
dst_dir = pathlib.Path(subprocess.check_output(['wslpath', '-a', '-u', '$tmpOutSlash'], text=True).strip())
raw = src.read_bytes()
inf = 'PEM' if b'-----BEGIN CERTIFICATE-----' in raw else 'DER'
h = subprocess.check_output(['openssl', 'x509', '-inform', inf, '-subject_hash_old', '-noout', '-in', str(src)], text=True).strip().splitlines()[0]
pem = subprocess.check_output(['openssl', 'x509', '-inform', inf, '-in', str(src), '-outform', 'PEM'], text=True)
txt = subprocess.check_output(['openssl', 'x509', '-inform', inf, '-text', '-fingerprint', '-noout', '-in', str(src)], text=True)
(dst_dir / f'{h}.0').write_text(pem + '\n' + txt, encoding='utf-8')
print(f'{h}.0')
"@) | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $hashName) { throw "Failed to convert certificate with WSL openssl." }
        $localHashFile = Join-Path $tmpOut $hashName
        Invoke-Adb @("push", $localHashFile, "/data/local/tmp/$hashName")
        Invoke-Adb @("shell", "su", "-c", "mkdir -p /data/misc/user/0/cacerts-added && cp -f /data/local/tmp/$hashName /data/misc/user/0/cacerts-added/$hashName && chmod 0644 /data/misc/user/0/cacerts-added/$hashName && rm -f /data/local/tmp/$hashName && andarium-ctl certs sync")
        if ($Proxy) {
            Invoke-Adb @("shell", "su", "-c", "andarium-ctl proxy set '$Proxy'")
        }
        Write-Host "[companion] CA certificate $hashName injected into Android 17 Conscrypt system store!" -ForegroundColor Green
    }
    "proxy-clear" {
        Invoke-Adb @("shell", "su", "-c", "andarium-ctl proxy clear")
    }
    "mode" {
        $m = if ($Arg) { $Arg } else { "dev" }
        Invoke-Adb @("shell", "su", "-c", "andarium-ctl mode $m")
    }
    "root" {
        $r = if ($Arg) { $Arg } else { "status" }
        Invoke-Adb @("shell", "su", "-c", "andarium-ctl root $r")
    }
    "backup" {
        $outPath = if ($Arg) { $Arg } else { "andarium-backup.json" }
        $json = Invoke-AdbCapture @("shell", "su", "-c", "andarium-ctl backup-export")
        Set-Content -Path $outPath -Value $json -Encoding utf8
        Write-Host "[companion] Exported config backup to $outPath" -ForegroundColor Green
    }
    "install-bundled" {
        $apkList = Invoke-AdbCapture @("shell", "ls -1 /odm/andarium-root/apks/*.apk 2>/dev/null")
        $files = @($apkList -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -like "*.apk" })
        if ($files.Count -eq 0) {
            throw "No bundled APKs found under /odm/andarium-root/apks/"
        }
        foreach ($remoteApk in $files) {
            $name = Split-Path -Leaf $remoteApk
            Write-Host "[companion] Installing $name..." -ForegroundColor Cyan
            Invoke-Adb @("shell", "cp '$remoteApk' /data/local/tmp/_ar_inst.apk && pm install -r -g /data/local/tmp/_ar_inst.apk && rm -f /data/local/tmp/_ar_inst.apk")
        }
        Write-Host "[companion] Installed $($files.Count) bundled APK(s)!" -ForegroundColor Green
    }
    "stealth" {
        $mode = if ($Arg) { $Arg } else { "status" }
        Invoke-Adb @("shell", "su", "-c", "andarium-ctl stealth $mode")
    }
    "selinux" {
        $mode = if ($Arg) { $Arg } else { "permissive" }
        Invoke-Adb @("shell", "su", "-c", "andarium-ctl selinux $mode")
    }
    "install" {
        if (-not $Arg -or -not (Test-Path $Arg)) { throw "Pass APK path via -Arg" }
        Invoke-Adb @("install", "-r", "-g", $Arg)
    }
    "logcat" {
        if ($Arg -eq "boot") {
            Invoke-Adb @("shell", "su", "-c", "andarium-ctl logs 150")
        } else {
            Invoke-Adb @("logcat", "-v", "time")
        }
    }
    "audit" {
        $auditParams = @{}
        if ($Connect) { $auditParams["Connect"] = $Connect }
        if ($Serial) { $auditParams["Serial"] = $Serial }
        & "$PSScriptRoot\audit.ps1" @auditParams
    }
}
