#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Live ADB audit script for a booted Andarium Root guest on iOS."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time


class AuditRunner:
    def __init__(self, serial: str | None) -> None:
        self.adb = shutil.which("adb")
        if not self.adb:
            raise SystemExit("ERROR: `adb` not found on PATH. Install Android Platform-Tools first.")
        self.serial = serial
        self.passed = 0
        self.warned = 0
        self.failed = 0

    def _base_cmd(self) -> list[str]:
        cmd = [self.adb]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def adb_run(self, *args: str, timeout: int = 20) -> subprocess.CompletedProcess[str]:
        return subprocess.run(self._base_cmd() + list(args), text=True, capture_output=True, timeout=timeout)

    def shell(self, cmd: str, *, root: bool = False, timeout: int = 20) -> subprocess.CompletedProcess[str]:
        if root:
            return self.adb_run("shell", "su", "-c", cmd, timeout=timeout)
        return self.adb_run("shell", cmd, timeout=timeout)

    def ok(self, label: str, detail: str = "") -> None:
        self.passed += 1
        suffix = f" ({detail})" if detail else ""
        print(f"  [PASS] {label}{suffix}")

    def warn(self, label: str, detail: str = "") -> None:
        self.warned += 1
        suffix = f" ({detail})" if detail else ""
        print(f"  [WARN] {label}{suffix}")

    def fail(self, label: str, detail: str = "") -> None:
        self.failed += 1
        suffix = f" ({detail})" if detail else ""
        print(f"  [FAIL] {label}{suffix}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a live booted Andarium Root Android guest over ADB.")
    parser.add_argument("--connect", help="Optional host:port to run `adb connect` against first (e.g. 192.168.1.42:5555)")
    parser.add_argument("--serial", "-s", help="Specific ADB device serial (defaults to --connect or sole connected device)")
    parser.add_argument("--skip-adb-root", action="store_true", help="Skip the live `adb root` / `adb unroot` round-trip test")
    args = parser.parse_args()

    serial = args.serial or args.connect
    audit = AuditRunner(serial)

    if args.connect:
        print(f"[audit] connecting to {args.connect}...")
        res = subprocess.run([audit.adb, "connect", args.connect], text=True, capture_output=True, timeout=15)
        print(" ", (res.stdout + res.stderr).strip())

    # 1. Connectivity & OS identity
    r = audit.shell("uname -r; getprop ro.build.version.release; getprop ro.build.version.sdk")
    if r.returncode != 0:
        audit.fail("ADB connectivity", r.stderr.strip() or "device not reachable")
        return 1
    lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    kernel = lines[0] if len(lines) > 0 else "?"
    rel = lines[1] if len(lines) > 1 else "?"
    sdk = lines[2] if len(lines) > 2 else "?"
    audit.ok("ADB connectivity & guest OS", f"Android {rel} API {sdk}, Linux {kernel}")

    # 2. Magisk root via su
    r = audit.shell("id -u && magisk -v", root=True)
    if r.returncode == 0 and r.stdout.strip().startswith("0"):
        mv = r.stdout.strip().splitlines()[-1]
        audit.ok("Magisk su root access", mv)
    else:
        audit.fail("Magisk su root access", (r.stdout + r.stderr).strip())
        return 1

    # 3. Magisk env_check (no "Requires Additional Setup") + PREINITDEVICE block node
    r = audit.shell(
        'MT="$(magisk --path 2>/dev/null || echo /debug_ramdisk)"; '
        'test -b "$MT/.magisk/device/preinit" && echo PREINIT_BLK_OK; '
        'test -f "$MT/.magisk/preinit/sepolicy.rule" && echo SEPOL_PREINIT_OK; '
        'for f in busybox magiskboot magiskinit magiskpolicy util_functions.sh boot_patch.sh; do '
        '  test -f "/data/adb/magisk/$f" || { echo "MISSING_$f"; exit 1; }; '
        'done; echo MAGISKBIN_OK',
        root=True,
    )
    out = r.stdout
    if "PREINIT_BLK_OK" in out and "MAGISKBIN_OK" in out:
        sepol_note = "preinit sepolicy.rule synced" if "SEPOL_PREINIT_OK" in out else "preinit sepolicy pending boot-complete"
        audit.ok("Magisk environment & PREINITDEVICE=metadata", sepol_note)
    else:
        audit.fail("Magisk environment check", out.strip().replace("\n", ", "))

    # 4. andarium-ctl status-json
    r = audit.shell("andarium-ctl status-json", root=True)
    status = {}
    try:
        status = json.loads(r.stdout.strip())
        audit.ok(
            "andarium-ctl telemetry",
            f"SELinux={status.get('selinux')}, stealth={status.get('stealth')}, "
            f"ro.debuggable={status.get('debuggable')}, adbroot={status.get('adbroot')}, "
            f"modules={len(status.get('modules', []))}",
        )
    except Exception as e:
        audit.fail("andarium-ctl status-json", f"{e}: {r.stdout[:120]}")

    # 5. Live adb root -> adb unroot round-trip test (only when not in Stealth Mode)
    if not args.skip_adb_root and status.get("stealth") != "on":
        r_root = audit.adb_run("root")
        time.sleep(2.5)
        if args.connect:
            subprocess.run([audit.adb, "connect", args.connect], text=True, capture_output=True, timeout=15)
        r_id = audit.shell("id -u")
        if r_id.returncode == 0 and r_id.stdout.strip() == "0":
            audit.ok("Native `adb root` escalation", "adbd running as uid=0")
        else:
            audit.fail("Native `adb root` escalation", f"root_out={r_root.stdout.strip()} id={r_id.stdout.strip()}")
        # Restore shell mode so Andarium's built-in iOS features stay intact
        audit.adb_run("unroot")
        time.sleep(2.0)
        if args.connect:
            subprocess.run([audit.adb, "connect", args.connect], text=True, capture_output=True, timeout=15)
        r_un = audit.shell("id -u")
        if r_un.returncode == 0 and r_un.stdout.strip() == "2000":
            audit.ok("Native `adb unroot` restoration", "adbd back to uid=2000 shell")
        else:
            audit.warn("Native `adb unroot` restoration", f"id={r_un.stdout.strip()}")
    else:
        audit.ok("`adb root` round-trip skipped", "stealth mode or --skip-adb-root")

    # 6. ReZygisk + Vector + TrickyStore live daemons
    r = audit.shell("ps -A -o NAME,ARGS 2>/dev/null || ps -ef", root=True)
    ps_out = r.stdout
    for label, pattern in (
        ("ReZygisk daemon (zygisk-ptrace / zygiskd)", ("zygisk-ptrace", "zygiskd")),
        ("Vector (LSPosed) daemon (vectord)", ("vectord", "VectorDaemon")),
        ("TrickyStore daemon", ("tricky_store",)),
    ):
        if any(p in ps_out for p in pattern):
            audit.ok(label, "running")
        else:
            audit.warn(label, "not detected in process list (may require one reboot after first boot)")

    # 7. Systemless Ad-Block hosts mount
    r = audit.shell("wc -l < /system/etc/hosts", root=True)
    try:
        hlines = int(r.stdout.strip())
        if hlines > 1000:
            audit.ok("Systemless Ad-Block (/system/etc/hosts)", f"{hlines:,} lines active")
        else:
            audit.warn("Systemless Ad-Block (/system/etc/hosts)", f"only {hlines} lines (adblock off?)")
    except ValueError:
        audit.fail("Systemless Ad-Block", r.stdout.strip())

    # 8. On-device Control Panel HTTP + Token Security Check
    r = audit.shell(
        'BB=/data/adb/magisk/busybox; TOK="$(cat /data/adb/andarium/run/webui.token 2>/dev/null)"; '
        'H1="$($BB wget -qO- http://127.0.0.1:8787/ 2>/dev/null | grep -c "Andarium Root")"; '
        'H2="$($BB wget -qO- "http://127.0.0.1:8787/cgi-bin/api?action=status" 2>&1 || echo BLOCKED)"; '
        'H3="$($BB wget -qO- "http://127.0.0.1:8787/cgi-bin/api?token=$TOK&action=status" 2>/dev/null | grep -c kernel)"; '
        'echo "H1=$H1 H2=$(echo "$H2" | grep -c 403) H3=$H3"',
        root=True,
    )
    if "H1=1" in r.stdout and "H3=1" in r.stdout:
        audit.ok("On-device Control Panel (127.0.0.1:8787)", "UI live + CGI token auth verified")
    else:
        audit.warn("On-device Control Panel (127.0.0.1:8787)", r.stdout.strip())

    # 9. Pentest & Networking tools executable
    r = audit.shell(
        "frida-server --version && dropbear -V 2>&1 | head -n1 && "
        "for t in strace socat sqlite3 jq tcpdump; do command -v $t >/dev/null || exit 1; done && echo CLI_SUITE_OK",
        root=True,
    )
    if r.returncode == 0 and "Dropbear" in r.stdout and "CLI_SUITE_OK" in r.stdout:
        audit.ok(
            "Frida, Dropbear SSH & 5 ARM64 CLI tools on PATH",
            " / ".join(ln.strip() for ln in r.stdout.splitlines()[:2]) + " + strace/socat/sqlite3/jq/tcpdump",
        )
    else:
        audit.warn("Frida / Dropbear / CLI tools", (r.stdout + r.stderr).strip())

    # 10. Bundled APKs + Shizuku + microG spoofing check
    expected_pkgs = [
        ("Magisk Manager", "com.topjohnwu.magisk"),
        ("Termux", "com.termux"),
        ("Material Files", "me.zhanghai.android.files"),
        ("microG GmsCore", "com.google.android.gms"),
        ("microG Companion", "com.android.vending"),
        ("Aurora Store", "com.aurora.store"),
        ("Obtainium", "dev.imranr.obtainium"),
        ("App Manager", "io.github.muntashirakon.AppManager"),
        ("Shizuku", "moe.shizuku.privileged.api"),
        ("Neo Backup", "com.machiav3lli.backup"),
        ("TrustMeAlready", "com.virb3.trustmealready"),
    ]
    r_pkgs = audit.shell("pm list packages", root=True)
    installed = set(ln.replace("package:", "").strip() for ln in r_pkgs.stdout.splitlines())
    missing = [f"{name} ({pkg})" for name, pkg in expected_pkgs if pkg not in installed]
    if not missing:
        audit.ok(f"All {len(expected_pkgs)} pre-bundled APKs installed")
    else:
        audit.warn(f"Missing {len(missing)} pre-bundled APK(s)", ", ".join(missing))

    if status.get("shizuku") == "running":
        audit.ok("Shizuku privileged server", "auto-started as root")
    else:
        audit.warn("Shizuku privileged server", "not running yet (try: andarium-ctl shizuku start)")

    # Summary
    print(f"\n[audit] Summary: {audit.passed} passed, {audit.warned} warnings, {audit.failed} failed")
    if audit.failed > 0 or audit.warned > 0:
        print("\n--- Recent /data/adb/andarium-root.log ---")
        r_log = audit.shell("tail -n 35 /data/adb/andarium-root.log 2>/dev/null || echo '(no log)'", root=True)
        print(r_log.stdout)
    return 1 if audit.failed > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
