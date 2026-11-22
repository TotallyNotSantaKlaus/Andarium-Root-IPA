#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Comprehensive independent verifier for a built Andarium Root IPA (v4)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = Path(__file__).resolve().parent
MANIFESTS_DIR = ROOT_DIR / "manifests"

sys.path.insert(0, str(SCRIPTS_DIR))
import android_image  # noqa: E402
import macho_inject  # noqa: E402

IPA_APP_PREFIX = "Payload/Andarium.app/"
IPA_MAIN_MACHO = IPA_APP_PREFIX + "Andarium"
IPA_SYSTEM_PREFIX = IPA_APP_PREFIX + "andarium-system/"
IPA_SYSTEM_IMG = IPA_SYSTEM_PREFIX + "guest/system.img"
IPA_LAYOUT_JSON = IPA_SYSTEM_PREFIX + "guest/partition-layout.json"
IPA_MANIFEST_JSON = IPA_SYSTEM_PREFIX + "release-manifest.json"
IPA_CMDLINE_TXT = IPA_SYSTEM_PREFIX + "boot/kernel-command-line.txt"
IPA_INFO_PLIST = IPA_APP_PREFIX + "Info.plist"
IPA_CODESIG_PREFIX = IPA_APP_PREFIX + "_CodeSignature/"
IPA_PREBOOT_BUNDLE = IPA_APP_PREFIX + "AndariumRootPreboot.bundle/"
IPA_PREBOOT_DYLIB = IPA_APP_PREFIX + "Frameworks/AndariumRootPreboot.dylib"
PREBOOT_DYLIB_LOAD_PATH = "@executable_path/Frameworks/AndariumRootPreboot.dylib"

EXPECTED_FRIDA_SCRIPTS = (
    "ssl-pinning-bypass.js",
    "root-detection-bypass.js",
    "flutter-ssl-bypass.js",
    "crypto-tracer.js",
    "intent-monitor.js",
)
FORBIDDEN_CMDLINE_PREFIXES = ("ubd", "initrd", "root=", "rootfstype=", "--aot-release=")

MACHO_EXECUTABLES = (
    IPA_APP_PREFIX + "Andarium",
    IPA_APP_PREFIX + "Frameworks/KosmicKrisp.framework/KosmicKrisp",
    IPA_APP_PREFIX + "Frameworks/MesaGallium.framework/MesaGallium",
    IPA_APP_PREFIX + "Frameworks/KRuntime_Android_6_18_4K.framework/KRuntime_Android_6_18_4K",
    IPA_APP_PREFIX + "Frameworks/MesaEGL.framework/MesaEGL",
)

CUSTOM_ICON_SPECS = (
    ("AndariumRoot60x60@2x.png", 120, 120),
    ("AndariumRoot60x60@3x.png", 180, 180),
    ("AndariumRoot76x76@2x~ipad.png", 152, 152),
    ("AndariumRoot83.5x83.5@2x~ipad.png", 167, 167),
    ("AndariumRoot1024x1024.png", 1024, 1024),
)

REQUIRED_ENTITLEMENTS = (
    b"com.apple.developer.kernel.increased-memory-limit",
    b"com.apple.developer.kernel.extended-virtual-addressing",
)

UNTOUCHED_PARTITIONS = ("recovery", "system", "product", "system_ext", "vendor")
VECTOR_PLACEHOLDER = b"5291374ceda0aef7c5d86cd2a4f6a3ac"
ODM_UUID = "4bd71fa4-60a6-5216-9ef1-00258e0f0150"
ODM_VENDOR_LABEL = b"u:object_r:vendor_file:s0"
XZ_MAGIC = b"\xfd7zXZ\x00"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
COPY_CHUNK = 4 * 1024 * 1024


class VerifyError(RuntimeError):
    pass


def ok(msg: str) -> None:
    print(f"[verify] PASS: {msg}", flush=True)


def fail(msg: str) -> None:
    raise VerifyError(msg)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(COPY_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def sha256_zip_member(zf: zipfile.ZipFile, name: str) -> str:
    h = hashlib.sha256()
    with zf.open(name, "r") as f:
        while chunk := f.read(COPY_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    res = subprocess.run(cmd, text=True, capture_output=True)
    if res.returncode != 0:
        fail(f"Command failed (rc={res.returncode}): {' '.join(cmd)}\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
    return res


def check_shell_script(data: bytes, label: str) -> None:
    if b"\r" in data:
        fail(f"{label} contains CR (\\r) line endings")
    if b"__DEFAULT_" in data:
        fail(f"{label} still contains unexpanded __DEFAULT_*__ placeholder")
    with tempfile.NamedTemporaryFile("wb", suffix=".sh", delete=False) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    try:
        res = subprocess.run(["sh", "-n", str(tmp_path)], text=True, capture_output=True)
        if res.returncode != 0:
            fail(f"sh -n failed for {label}:\n{res.stderr}")
    finally:
        tmp_path.unlink(missing_ok=True)


def check_elf_arch(data: bytes, expected_class: int, expected_machine: int, label: str) -> None:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        fail(f"{label} is not an ELF binary")
    e_class, e_data = data[4], data[5]
    e_machine = struct.unpack_from("<H", data, 18)[0]
    if e_class != expected_class or e_data != 1 or e_machine != expected_machine:
        fail(
            f"{label} ELF mismatch: class={e_class} data={e_data} machine={e_machine} "
            f"(expected class={expected_class} data=1 machine={expected_machine})"
        )


def extract_partition_slice(disk_path: Path, start: int, size: int, dst: Path) -> None:
    with disk_path.open("rb") as src, dst.open("wb") as out:
        src.seek(start)
        rem = size
        while rem > 0:
            chunk = src.read(min(rem, COPY_CHUNK))
            if not chunk:
                fail(f"Unexpected EOF extracting partition slice to {dst.name}")
            out.write(chunk)
            rem -= len(chunk)


def extract_stock_partition(base_ipa: Path, part_name: str, dst: Path) -> dict[str, object]:
    with zipfile.ZipFile(base_ipa, "r") as zf:
        layout = json.loads(zf.read(IPA_LAYOUT_JSON).decode("utf-8"))
        match = [p for p in layout["system_disk"]["partitions"] if p["name"] == part_name]
        if len(match) != 1:
            fail(f"Base IPA missing partition {part_name}")
        entry = match[0]
        start = int(entry["start_bytes"])
        size = int(entry["size_bytes"])
        with zf.open(IPA_SYSTEM_IMG, "r") as src:
            rem = start
            while rem > 0:
                buf = src.read(min(rem, COPY_CHUNK))
                if not buf:
                    fail(f"EOF skipping to {part_name} in base IPA")
                rem -= len(buf)
            with dst.open("wb") as out:
                rem = size
                while rem > 0:
                    buf = src.read(min(rem, COPY_CHUNK))
                    if not buf:
                        fail(f"EOF reading {part_name} in base IPA")
                    out.write(buf)
                    rem -= len(buf)
    return layout


def verify_cmdline(built_cmdline: bytes, stock_cmdline: bytes | None, *, expect_no_root: bool) -> None:
    if expect_no_root:
        if stock_cmdline is not None and built_cmdline != stock_cmdline:
            fail("Unrooted build altered kernel-command-line.txt unexpectedly")
        ok("unrooted kernel-command-line.txt is byte-for-byte identical to stock")
        return

    if b'"' in built_cmdline or b"'" in built_cmdline or b"\r" in built_cmdline:
        fail("kernel-command-line.txt contains forbidden quotes or CR bytes")
    if len(built_cmdline) > 2048:
        fail(f"kernel-command-line.txt too long ({len(built_cmdline)} B > 2048 B safety ceiling)")
    words = built_cmdline.decode("utf-8").split()
    boot_dev_count = 0
    ar_cfg = None
    for w in words:
        for pref in FORBIDDEN_CMDLINE_PREFIXES:
            if w.startswith(pref):
                fail(f"kernel-command-line.txt contains forbidden storage prefix: {w}")
        if w.startswith("androidboot.boot_devices="):
            if w != "androidboot.boot_devices=uml-blkdev.0,uml-blkdev.1":
                fail(f"Invalid androidboot.boot_devices token: {w}")
            boot_dev_count += 1
        elif w.startswith("androidboot.ar.cfg="):
            ar_cfg = w.split("=", 1)[1]
    if boot_dev_count != 1:
        fail(f"Expected androidboot.boot_devices exactly once, found {boot_dev_count}")
    if ar_cfg is None or not (ar_cfg.startswith("4,") or ar_cfg.startswith("5,")) or len(ar_cfg) >= 91:
        fail(f"Invalid or missing androidboot.ar.cfg token: {ar_cfg!r}")
    if stock_cmdline is not None:
        stock_words = [w for w in stock_cmdline.decode("utf-8").split() if not w.startswith("androidboot.ar.")]
        built_base = [w for w in words if not w.startswith("androidboot.ar.")]
        if built_base != stock_words:
            fail("Non-andarium stock kernel command line arguments were altered")
    ok(f"kernel-command-line.txt passes android_boot.cpp safety rules + androidboot.ar.cfg ({len(built_cmdline)} B)")


def verify_ipa_bundle(
    ipa_path: Path,
    base_ipa: Path | None,
    *,
    expected_bundle_id: str,
    expected_display_name: str,
    expect_custom_icon: bool,
    expect_no_root: bool,
    expect_preboot_dylib: bool,
    expect_raw_display_name: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    with zipfile.ZipFile(ipa_path, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            fail(f"IPA ZIP integrity check failed on entry: {bad}")
        ok(f"IPA ZIP integrity (testzip passed across {len(zf.infolist())} entries)")

        names = set(zf.namelist())
        stale_sig = [n for n in names if n == IPA_CODESIG_PREFIX or n.startswith(IPA_CODESIG_PREFIX)]
        if stale_sig:
            fail(f"Stale top-level _CodeSignature entries still present: {stale_sig}")
        ok("stale top-level _CodeSignature removed")

        for exe in MACHO_EXECUTABLES:
            if exe not in names:
                fail(f"Missing Mach-O executable in IPA: {exe}")
            zi = zf.getinfo(exe)
            mode = (zi.external_attr >> 16) & 0o777
            if (mode & 0o111) == 0:
                fail(f"Mach-O executable lost execute bits: {exe} (mode={oct(mode)})")
        ok(f"all {len(MACHO_EXECUTABLES)} Mach-O executables retain Unix execute permissions")

        main_bin = zf.read(IPA_MAIN_MACHO)
        for ent in REQUIRED_ENTITLEMENTS:
            if ent not in main_bin:
                fail(f"Missing required iOS entitlement in Andarium Mach-O: {ent.decode()}")
        ok("embedded iOS Mach-O entitlements preserved (increased-memory-limit + extended-virtual-addressing)")

        kruntime_path = IPA_APP_PREFIX + "Frameworks/KRuntime_Android_6_18_4K.framework/KRuntime_Android_6_18_4K"
        kruntime_bin = zf.read(kruntime_path)
        if b"\xa0\x01\x3e\xd4" not in kruntime_bin:
            fail("KRuntime_Android_6_18_4K missing ARM64 brk #0xf00d (0xd43e01a0) StikDebug JIT trap instruction")
        ok("KRuntime_Android_6_18_4K retains ARM64 brk #0xf00d StikDebug JIT breakpoint protocol")

        if expect_preboot_dylib:
            if IPA_PREBOOT_DYLIB not in names:
                fail(f"Missing pre-boot dylib in IPA: {IPA_PREBOOT_DYLIB}")
            dzi = zf.getinfo(IPA_PREBOOT_DYLIB)
            dmode = (dzi.external_attr >> 16) & 0o777
            if (dmode & 0o111) == 0:
                fail(f"Pre-boot dylib not executable: mode={oct(dmode)}")
            _ncmds, _sz, _min_off, dylibs = macho_inject.parse_macho64_dylibs(main_bin)
            if PREBOOT_DYLIB_LOAD_PATH not in dylibs:
                fail(f"Main Andarium Mach-O missing LC_LOAD_DYLIB for {PREBOOT_DYLIB_LOAD_PATH}")
            ok(f"native iOS Pre-Boot dylib bundled & LC_LOAD_DYLIB verified ({PREBOOT_DYLIB_LOAD_PATH})")

        if not expect_no_root:
            for req_res in ("preboot.html", "defaults.json"):
                zname = IPA_PREBOOT_BUNDLE + req_res
                if zname not in names:
                    fail(f"Missing pre-boot studio resource: {zname}")
            preboot_html = zf.read(IPA_PREBOOT_BUNDLE + "preboot.html").decode("utf-8")
            if "__andariumJitDiag" not in preboot_html or "launch_stikdebug" not in preboot_html:
                fail("AndariumRootPreboot.bundle/preboot.html missing JIT Doctor / StikDebug launcher")
            defs = json.loads(zf.read(IPA_PREBOOT_BUNDLE + "defaults.json").decode("utf-8"))
            if not defs.get("presets") or not defs.get("app_catalog") or not defs.get("default_config"):
                fail("AndariumRootPreboot.bundle/defaults.json missing required sections")
            ok(f"AndariumRootPreboot.bundle verified ({len(defs['presets'])} presets, {len(defs['app_catalog'])} catalog apps, JIT Doctor)")

        stock_cmdline: bytes | None = None
        if base_ipa is not None:
            with zipfile.ZipFile(base_ipa, "r") as base_zf:
                stock_cmdline = base_zf.read(IPA_CMDLINE_TXT)
                for exe in MACHO_EXECUTABLES:
                    if expect_preboot_dylib and exe == IPA_MAIN_MACHO:
                        continue
                    if sha256_zip_member(zf, exe) != sha256_zip_member(base_zf, exe):
                        fail(f"Mach-O binary altered unexpectedly: {exe}")
            if expect_preboot_dylib:
                ok("all 4 framework Mach-O binaries are byte-for-byte stock (main binary cleanly LC_LOAD_DYLIB-patched)")
            else:
                ok("all 5 Mach-O binaries are byte-for-byte identical to stock IPA")

        verify_cmdline(zf.read(IPA_CMDLINE_TXT), stock_cmdline, expect_no_root=expect_no_root)

        plist_raw = zf.read(IPA_INFO_PLIST)
        if not plist_raw.startswith(b"bplist00"):
            fail("Info.plist is not in binary plist format")
        pl = plistlib.loads(plist_raw)
        if pl.get("CFBundleIdentifier") != expected_bundle_id:
            fail(f"CFBundleIdentifier={pl.get('CFBundleIdentifier')!r}, expected {expected_bundle_id!r}")
        expected_root_name = expected_display_name if expect_raw_display_name else "Andarium"
        if pl.get("CFBundleDisplayName") != expected_root_name:
            fail(
                f"Root Info.plist CFBundleDisplayName={pl.get('CFBundleDisplayName')!r}, "
                f"expected {expected_root_name!r} (required for StikDebug universal.js auto-assignment)"
            )
        if pl.get("CFBundleExecutable") != "Andarium" or pl.get("CFBundleName") != "Andarium":
            fail("CFBundleExecutable / CFBundleName must remain 'Andarium'")
        schemes = pl.get("LSApplicationQueriesSchemes") or []
        if "stikdebug" not in schemes:
            fail(f"Info.plist LSApplicationQueriesSchemes missing 'stikdebug': {schemes!r}")

        lproj_files = sorted(
            n for n in names
            if n.startswith(IPA_APP_PREFIX) and n.endswith(".lproj/InfoPlist.strings") and n.count("/") == 3
        )
        if not lproj_files:
            fail("Missing localized *.lproj/InfoPlist.strings in IPA")
        for lf in lproj_files:
            lraw = zf.read(lf)
            if not lraw.startswith(b"bplist00"):
                fail(f"{lf} is not in binary plist format")
            lpl = plistlib.loads(lraw)
            if lpl.get("CFBundleDisplayName") != expected_display_name:
                fail(f"{lf} CFBundleDisplayName={lpl.get('CFBundleDisplayName')!r}, expected {expected_display_name!r}")
        ok(
            f"StikDebug JIT auto-script + localized display name verified "
            f"(root={expected_root_name!r}, {len(lproj_files)} locales={expected_display_name!r}, stikdebug:// scheme allowed)"
        )

        if expect_custom_icon:
            primary_iphone = pl.get("CFBundleIcons", {}).get("CFBundlePrimaryIcon", {})
            if "CFBundleIconName" in primary_iphone:
                fail("CFBundleIconName must be removed so iOS renders the custom PNG icon set")
            if primary_iphone.get("CFBundleIconFiles") != ["AndariumRoot60x60"]:
                fail(f"Unexpected iPhone CFBundleIconFiles: {primary_iphone.get('CFBundleIconFiles')!r}")
            for fname, exp_w, exp_h in CUSTOM_ICON_SPECS:
                zname = IPA_APP_PREFIX + fname
                if zname not in names:
                    fail(f"Missing custom iOS icon in IPA: {zname}")
                png = zf.read(zname)
                if not png.startswith(PNG_MAGIC) or png[12:16] != b"IHDR":
                    fail(f"Invalid PNG header for {fname}")
                w, h = struct.unpack_from(">II", png, 16)
                if (w, h) != (exp_w, exp_h):
                    fail(f"Icon {fname} dimensions {w}x{h} != {exp_w}x{exp_h}")
            if (IPA_APP_PREFIX + "Assets.car") not in names:
                fail("Assets.car must remain intact for internal SwiftUI assets")
            ok(f"custom 'Andarium Root' iOS app icon set verified ({len(CUSTOM_ICON_SPECS)} PNG sizes + Info.plist)")

        ok(f"Info.plist valid binary plist ({expected_bundle_id} / {expected_display_name!r})")

        manifest = json.loads(zf.read(IPA_MANIFEST_JSON).decode("utf-8"))
        layout = json.loads(zf.read(IPA_LAYOUT_JSON).decode("utf-8"))
        rel_id = manifest.get("release_id")
        if not isinstance(rel_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", rel_id):
            fail(f"Invalid release_id for ReleaseIdentity: {rel_id!r}")
        if manifest.get("acceptance") != "accepted":
            fail(f"Manifest acceptance={manifest.get('acceptance')!r}, expected 'accepted'")
        android_meta = manifest.get("android", {})
        if not android_meta.get("fingerprint") or int(android_meta.get("build_number", 0)) < 1:
            fail("Invalid android metadata in release-manifest.json")

        sys_disk_size = zf.getinfo(IPA_SYSTEM_IMG).file_size
        layout_size = zf.getinfo(IPA_LAYOUT_JSON).file_size
        cmdline_size = zf.getinfo(IPA_CMDLINE_TXT).file_size
        inv = {item["path"]: item["size"] for item in manifest.get("inventory", [])}
        if inv.get("guest/system.img") != sys_disk_size:
            fail(f"Manifest inventory guest/system.img={inv.get('guest/system.img')} != {sys_disk_size}")
        if inv.get("guest/partition-layout.json") != layout_size:
            fail(f"Manifest inventory guest/partition-layout.json={inv.get('guest/partition-layout.json')} != {layout_size}")
        if inv.get("boot/kernel-command-line.txt") != cmdline_size:
            fail(f"Manifest inventory boot/kernel-command-line.txt={inv.get('boot/kernel-command-line.txt')} != {cmdline_size}")
        ok(f"release-manifest.json passes ReleaseIdentity + inventory checks (release_id={rel_id})")

    return manifest, layout


def verify_init_boot(
    init_boot_path: Path,
    stock_init_boot_path: Path | None,
    *,
    expected_selinux: str,
) -> None:
    size = init_boot_path.stat().st_size
    with init_boot_path.open("rb") as f:
        info = android_image.parse_boot_image(f, 0, size, VerifyError)
        reader = android_image.RangeReader(f, info.ramdisk_offset, info.ramdisk_size, VerifyError)
        retain_names = {
            "init",
            ".backup/init.xz",
            ".backup/.magisk",
            "overlay.d/sbin/magisk.xz",
            "overlay.d/sbin/init-ld.xz",
            "overlay.d/init.andarium_root.rc",
            "overlay.d/sbin/andarium_early_init.sh",
            "first_stage_ramdisk/system/etc/fstab.uml",
        }
        entries = android_image.parse_newc(reader, lambda name, _mode: name in retain_names, VerifyError)
    ok(f"init_boot boot-image v4 + uncompressed newc valid ({len(entries)} entries, ramdisk={info.ramdisk_size:,} B)")

    for req in retain_names:
        if req not in entries:
            fail(f"init_boot ramdisk missing required entry: {req}")

    init_bytes = entries["init"].payload or b""
    check_elf_arch(init_bytes, android_image.ELFCLASS64, android_image.EM_AARCH64, "init_boot:/init")

    for xz_name in (".backup/init.xz", "overlay.d/sbin/magisk.xz", "overlay.d/sbin/init-ld.xz"):
        if not (entries[xz_name].payload or b"").startswith(XZ_MAGIC):
            fail(f"init_boot:{xz_name} does not start with XZ magic")

    cfg_text = (entries[".backup/.magisk"].payload or b"").decode("utf-8")
    cfg_lines = dict(line.split("=", 1) for line in cfg_text.splitlines() if "=" in line)
    if cfg_lines.get("PREINITDEVICE") != "metadata":
        fail(f"Unexpected PREINITDEVICE in .backup/.magisk: {cfg_lines.get('PREINITDEVICE')!r}")
    if cfg_lines.get("KEEPVERITY") != "true" or cfg_lines.get("RECOVERYMODE") != "false":
        fail(f"Unexpected Magisk config flags: {cfg_lines}")
    if not re.fullmatch(r"[0-9a-f]{40}", cfg_lines.get("SHA1", "")):
        fail(f"Invalid SHA1 in .backup/.magisk: {cfg_lines.get('SHA1')!r}")

    rc_bytes = entries["overlay.d/init.andarium_root.rc"].payload or b""
    if b"\r" in rc_bytes:
        fail("overlay.d/init.andarium_root.rc contains CR (\\r)")
    rc_text = rc_bytes.decode("utf-8")
    for snippet in (
        "on post-fs-data",
        "andarium_early_init.sh",
        "on property:service.adb.root=1",
        "on property:service.adb.root=0",
        "on property:sys.boot_completed=1",
        "andarium_boot_complete.sh",
    ):
        if snippet not in rc_text:
            fail(f"init.andarium_root.rc missing expected trigger: {snippet}")

    early_entry = entries["overlay.d/sbin/andarium_early_init.sh"]
    if (stat.S_IMODE(early_entry.mode) & 0o111) == 0:
        fail(f"andarium_early_init.sh is not executable: mode={oct(early_entry.mode)}")
    early_bytes = early_entry.payload or b""
    check_shell_script(early_bytes, "init_boot:overlay.d/sbin/andarium_early_init.sh")
    if f'DEFAULT_SELINUX="{expected_selinux}"'.encode() not in early_bytes:
        fail(f"andarium_early_init.sh missing DEFAULT_SELINUX={expected_selinux!r}")

    if stock_init_boot_path is not None:
        with stock_init_boot_path.open("rb") as sf:
            s_info = android_image.parse_boot_image(sf, 0, stock_init_boot_path.stat().st_size, VerifyError)
            s_reader = android_image.RangeReader(sf, s_info.ramdisk_offset, s_info.ramdisk_size, VerifyError)
            s_entries = android_image.parse_newc(
                s_reader,
                lambda n, _m: n in {"init", "first_stage_ramdisk/system/etc/fstab.uml"},
                VerifyError,
            )
        if entries["first_stage_ramdisk/system/etc/fstab.uml"].payload != s_entries["first_stage_ramdisk/system/etc/fstab.uml"].payload:
            fail("fstab.uml in patched init_boot differs from stock init_boot")
        if init_bytes == (s_entries["init"].payload or b""):
            fail("init_boot:/init was not replaced by magiskinit")

    ok("init_boot Magisk v31.1 payload, PREINITDEVICE=metadata, overlay.d scripts (sh -n), and stock fstab.uml verified")


def verify_odm(
    odm_path: Path,
    stock_odm_path: Path | None,
    work_dir: Path,
    *,
    expect_no_root: bool,
    expect_modules: bool,
    expect_stealth: bool,
    expect_pentest: bool,
    expect_network: bool,
    expect_apps: bool,
    expect_power_apps: bool,
    expect_microg: bool,
    expected_selinux: str,
    expected_apk_names: list[str] | None,
) -> None:
    with odm_path.open("rb") as f:
        prefix = f.read(2048)
    sb = android_image.erofs_superblock(prefix, "odm.img", VerifyError)
    if sb.block_size_bits != 12:
        fail(f"odm.img block_size_bits={sb.block_size_bits}, expected 12 (4 KiB)")
    if (sb.compression_algorithms & (1 << android_image.EROFS_ALGORITHM_ZSTD)) == 0:
        fail("odm.img does not declare zstd compression algorithm")
    if (sb.feature_incompat & android_image.EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER) == 0:
        fail("odm.img missing BIG_PCLUSTER incompat feature")

    dump = run_cmd(["dump.erofs", str(odm_path)]).stdout
    if ODM_UUID not in dump:
        fail(f"odm.img UUID does not match expected {ODM_UUID}")
    m_kver = re.search(r"Required upstream Linux kernel version:\s*(\d+)\.(\d+)", dump)
    if m_kver:
        maj, minor = int(m_kver.group(1)), int(m_kver.group(2))
        if (maj, minor) > (6, 18):
            fail(f"odm.img requires kernel {maj}.{minor} > shipped 6.18")
    ok(f"odm.img EROFS superblock valid (zstd, 4 KiB blocks, UUID={ODM_UUID})")

    odm_tree = work_dir / "verify_odm_tree"
    run_cmd(["fsck.erofs", f"--extract={odm_tree}", "--xattrs", "--preserve", str(odm_path)])

    if stock_odm_path is not None:
        stock_tree = work_dir / "verify_stock_odm_tree"
        run_cmd(["fsck.erofs", f"--extract={stock_tree}", "--xattrs", "--preserve", str(stock_odm_path)])
        if os.getxattr(odm_tree, "security.selinux") != os.getxattr(stock_tree, "security.selinux"):
            fail("odm root security.selinux xattr changed")
        stock_etc_count = 0
        for sp in sorted(stock_tree.rglob("*")):
            rel = sp.relative_to(stock_tree)
            dp = odm_tree / rel
            if not dp.exists():
                fail(f"Stock odm entry missing in patched odm: {rel}")
            s_st, d_st = sp.lstat(), dp.lstat()
            if stat.S_IMODE(s_st.st_mode) != stat.S_IMODE(d_st.st_mode):
                fail(f"Stock odm mode mismatch on {rel}")
            if (s_st.st_uid, s_st.st_gid) != (d_st.st_uid, d_st.st_gid):
                fail(f"Stock odm uid:gid mismatch on {rel}")
            if os.getxattr(sp, "security.selinux", follow_symlinks=False) != os.getxattr(dp, "security.selinux", follow_symlinks=False):
                fail(f"Stock odm security.selinux mismatch on {rel}")
            if sp.is_file() and sha256_file(sp) != sha256_file(dp):
                fail(f"Stock odm file content changed: {rel}")
            stock_etc_count += 1
        ok(f"all {stock_etc_count} stock /odm entries preserved byte-for-byte with identical modes and SELinux xattrs")

    payload_root = odm_tree / "andarium-root"
    if not payload_root.is_dir():
        fail("Missing /odm/andarium-root directory")
    payload_entries = 0
    for dirpath, _dirnames, filenames in os.walk(payload_root):
        for p in [Path(dirpath)] + [Path(dirpath) / fn for fn in filenames]:
            st = p.lstat()
            if (st.st_uid, st.st_gid) != (0, 0):
                fail(f"Unexpected uid:gid on {p.relative_to(odm_tree)}: {st.st_uid}:{st.st_gid}")
            if os.getxattr(p, "security.selinux", follow_symlinks=False) != ODM_VENDOR_LABEL:
                fail(f"Unexpected security.selinux on {p.relative_to(odm_tree)}")
            payload_entries += 1
    ok(f"all {payload_entries} entries under /odm/andarium-root owned 0:0 with u:object_r:vendor_file:s0")

    if not (payload_root / "config" / "preset.json").is_file():
        fail("Missing /odm/andarium-root/config/preset.json")

    if expect_no_root:
        for forbidden in ("magisk-bin", "modules", "tools"):
            if (payload_root / forbidden).exists():
                fail(f"Unrooted build must not contain /odm/andarium-root/{forbidden}")
        ok("unrooted build confirmed clean (no magisk-bin, modules, or pentest tools)")
    else:
        # Magisk runtime binaries
        mbin = payload_root / "magisk-bin"
        for name in ("busybox", "magiskboot", "magiskinit", "magiskpolicy", "bootctl", "magisk", "init-ld"):
            check_elf_arch((mbin / name).read_bytes(), android_image.ELFCLASS64, android_image.EM_AARCH64, f"magisk-bin/{name}")
        check_elf_arch((mbin / "magisk32").read_bytes(), android_image.ELFCLASS32, android_image.EM_ARM, "magisk-bin/magisk32")
        uf_text = (mbin / "util_functions.sh").read_text(encoding="utf-8")
        if "MAGISK_VER='31.1'" not in uf_text or "MAGISK_VER_CODE=31100" not in uf_text:
            fail("magisk-bin/util_functions.sh version mismatch")
        ok("magisk-bin full v31.1 runtime environment verified (ELF64/ARM32 + assets)")

        # Seeded magisk.db
        db_path = payload_root / "config" / "magisk.db"
        conn = sqlite3.connect(db_path)
        try:
            cur = conn.cursor()
            if cur.execute("PRAGMA user_version;").fetchone()[0] != 13:
                fail("magisk.db user_version != 13")
            settings = dict(cur.execute("SELECT key, value FROM settings;").fetchall())
            expected_zygisk = 0 if expect_modules else 1
            if settings.get("zygisk") != expected_zygisk:
                fail(f"magisk.db settings.zygisk={settings.get('zygisk')}, expected {expected_zygisk}")
            shell_pol = cur.execute("SELECT policy FROM policies WHERE uid = 2000;").fetchone()
            if shell_pol is None or shell_pol[0] != 2:
                fail("magisk.db missing UID 2000 allow policy")
        finally:
            conn.close()
        ok(f"magisk.db valid SQLite schema v13 (zygisk={expected_zygisk}, UID 2000 policy=2)")

        mods_dir = payload_root / "modules"

        # Andarium Root Control module (always present on rooted builds)
        ctrl = mods_dir / "andarium_control"
        for rel in ("module.prop", "service.sh", "action.sh", "webroot/index.html", "webroot/cgi-bin/api", "system/etc/hosts"):
            if not (ctrl / rel).is_file():
                fail(f"Missing andarium_control/{rel}")
        for sh_rel in ("service.sh", "action.sh", "webroot/cgi-bin/api"):
            sp = ctrl / sh_rel
            if (stat.S_IMODE(sp.stat().st_mode) & 0o111) == 0:
                fail(f"andarium_control/{sh_rel} is not executable")
            check_shell_script(sp.read_bytes(), f"andarium_control/{sh_rel}")
        ok("andarium_control v5 module verified (WebUI + token CGI + systemless hosts, sh -n passed)")

        dev_prof_path = payload_root / "config" / "device-profiles.json"
        if not dev_prof_path.is_file():
            fail("Missing /odm/andarium-root/config/device-profiles.json")
        dev_prof = json.loads(dev_prof_path.read_text(encoding="utf-8"))
        for req_p in ("stock", "pixel9pro", "s25ultra", "rog9", "redmagic10", "xiaomi15u"):
            if req_p not in dev_prof.get("profiles", {}):
                fail(f"device-profiles.json missing profile: {req_p}")
        if not dev_prof.get("debloat_catalog") or not dev_prof.get("protected_packages"):
            fail("device-profiles.json missing debloat_catalog or protected_packages")
        ok(f"device-profiles.json verified ({len(dev_prof['profiles'])} spoof profiles + {len(dev_prof['debloat_catalog'])} safe debloat items)")

        # Core modules (ReZygisk + Vector)
        if expect_modules:
            rz = mods_dir / "rezygisk"
            for rel in (
                "module.prop", "module.prop.bak", "post-fs-data.sh", "service.sh", "uninstall.sh",
                "sepolicy.rule", "bin/zygiskd64", "bin/zygiskd32", "bin/zygisk-ptrace64", "bin/zygisk-ptrace32",
                "lib64/libzygisk.so", "lib/libzygisk.so", "machikado.arm64", "machikado.arm", "webroot/index.html",
            ):
                if not (rz / rel).is_file():
                    fail(f"Missing ReZygisk file: {rel}")
            if not (mods_dir / "rezygisk.sh").is_file():
                fail("Missing modules/rezygisk.sh")

            vec = mods_dir / "zygisk_vector"
            for rel in (
                "module.prop", "action.sh", "service.sh", "uninstall.sh", "sepolicy.rule",
                "framework/vector.dex", "cli", "daemon", "daemon.apk", "manager.apk",
                "zygisk/arm64-v8a.so", "zygisk/armeabi-v7a.so",
                "bin/dex2oat64", "bin/dex2oat32", "bin/liboat_hook64.so", "bin/liboat_hook32.so",
            ):
                if not (vec / rel).is_file():
                    fail(f"Missing Vector file: {rel}")
            for p in (vec / "daemon.apk", vec / "bin/dex2oat64", vec / "bin/dex2oat32"):
                if VECTOR_PLACEHOLDER in p.read_bytes():
                    fail(f"Vector placeholder still present in {p.name}")
            with zipfile.ZipFile(vec / "daemon.apk", "r") as dzf:
                if dzf.testzip() is not None:
                    fail("Vector daemon.apk failed testzip()")
            ok("ReZygisk v1.0.0 + Vector v2.2-3119 staged cleanly (anti-detection patched & daemon.apk CRC valid)")

        # Stealth modules (PlayIntegrityFork + TrickyStore + Zygisk-Assistant)
        if expect_stealth:
            for rel in ("module.prop", "post-fs-data.sh", "service.sh", "action.sh", "classes.dex", "zygisk/arm64-v8a.so"):
                if not (mods_dir / "playintegrityfix" / rel).is_file():
                    fail(f"Missing PlayIntegrityFork file: {rel}")
            for rel in ("module.prop", "service.sh", "service.apk", "sepolicy.rule", "daemon", "libtricky_store.so", "machikado"):
                if not (mods_dir / "tricky_store" / rel).is_file():
                    fail(f"Missing TrickyStore file: {rel}")
            for cfg in ("keybox.xml", "target.txt"):
                if not (payload_root / "config" / "tricky_store" / cfg).is_file():
                    fail(f"Missing TrickyStore default config: {cfg}")
            for rel in ("module.prop", "post-fs-data.sh", "service.sh", "zygisk/arm64-v8a.so"):
                if not (mods_dir / "zygisk-assistant" / rel).is_file():
                    fail(f"Missing Zygisk-Assistant file: {rel}")
            ok("Stealth stack verified (PlayIntegrityFork v19 + TrickyStore v1.4.1 + Zygisk-Assistant v2.1.4)")

        # Pentest tools (Frida Server + Frida Inject + script pack + static/NDK ARM64 CLI suite)
        if expect_pentest:
            frida_bin = payload_root / "tools" / "frida-server"
            if not frida_bin.is_file() or (stat.S_IMODE(frida_bin.stat().st_mode) & 0o111) == 0:
                fail("frida-server missing or not executable")
            check_elf_arch(frida_bin.read_bytes(), android_image.ELFCLASS64, android_image.EM_AARCH64, "tools/frida-server")
            finj_bin = payload_root / "tools" / "frida-inject"
            if not finj_bin.is_file() or (stat.S_IMODE(finj_bin.stat().st_mode) & 0o111) == 0:
                fail("frida-inject missing or not executable")
            check_elf_arch(finj_bin.read_bytes(), android_image.ELFCLASS64, android_image.EM_AARCH64, "tools/frida-inject")
            for js_name in EXPECTED_FRIDA_SCRIPTS:
                jp = payload_root / "tools" / "frida-scripts" / js_name
                if not jp.is_file():
                    fail(f"Missing bundled Frida script: tools/frida-scripts/{js_name}")
                if b"\r" in jp.read_bytes():
                    fail(f"Frida script {js_name} contains CR bytes")
                if stat.S_IMODE(jp.stat().st_mode) != 0o644:
                    fail(f"Frida script {js_name} mode={oct(stat.S_IMODE(jp.stat().st_mode))}, expected 0o644")
            for cname in ("strace", "socat", "sqlite3", "jq", "tcpdump"):
                cp = payload_root / "tools" / "cli" / cname
                if not cp.is_file() or (stat.S_IMODE(cp.stat().st_mode) & 0o111) == 0:
                    fail(f"CLI pentest tool missing or not executable: {cname}")
                check_elf_arch(cp.read_bytes(), android_image.ELFCLASS64, android_image.EM_AARCH64, f"tools/cli/{cname}")
            ok(
                f"Pentest lab verified (frida-server {frida_bin.stat().st_size:,} B + frida-inject {finj_bin.stat().st_size:,} B + "
                f"{len(EXPECTED_FRIDA_SCRIPTS)} Frida scripts + 5 ARM64 CLI tools)"
            )

        # Networking tools (Dropbear SSH + StevenBlack hosts)
        if expect_network:
            for bname in ("dropbear", "dropbearkey", "dropbearconvert", "dbclient", "scp"):
                bp = payload_root / "tools" / "dropbear" / bname
                if not bp.is_file() or (stat.S_IMODE(bp.stat().st_mode) & 0o111) == 0:
                    fail(f"Dropbear binary missing or not executable: {bname}")
                check_elf_arch(bp.read_bytes(), android_image.ELFCLASS64, android_image.EM_AARCH64, f"tools/dropbear/{bname}")
            hosts_cfg = payload_root / "config" / "hosts.adblock"
            hosts_mod = ctrl / "system" / "etc" / "hosts"
            if not hosts_cfg.is_file() or hosts_cfg.stat().st_size < 500_000:
                fail("hosts.adblock missing or unexpectedly small")
            if hosts_mod.stat().st_size < 500_000:
                fail("andarium_control/system/etc/hosts not populated with adblock hosts")
            ok(f"Networking pack verified (Dropbear 2026.94 5x ARM64 ELFs + StevenBlack hosts {hosts_mod.stat().st_size:,} B)")

        # Guest scripts on /odm
        scripts_dir = payload_root / "scripts"
        odm_scripts = (
            "andarium_boot_complete.sh",
            "andarium-ctl",
            "andarium-workbench",
            "andarium-spoof",
            "andarium-net",
            "andarium-auto",
            "andarium-termux-setup",
            "andarium-shell-rc.sh",
        )
        for sname in odm_scripts:
            sp = scripts_dir / sname
            if not sp.is_file() or (stat.S_IMODE(sp.stat().st_mode) & 0o111) == 0:
                fail(f"Script {sname} missing or not executable")
            data = sp.read_bytes()
            check_shell_script(data, f"odm:/andarium-root/scripts/{sname}")
            if sname == "andarium_boot_complete.sh":
                if f'DEFAULT_SELINUX="{expected_selinux}"'.encode() not in data:
                    fail(f"andarium_boot_complete.sh missing DEFAULT_SELINUX={expected_selinux!r}")
        ok(f"all {len(odm_scripts)} /odm guest scripts LF-only, executable, and pass sh -n")

    # Bundled APKs (pinned SHA-256 + testzip)
    artifacts = json.loads((MANIFESTS_DIR / "artifacts.json").read_text(encoding="utf-8"))
    sha_by_install_name = {"01-magisk.apk": str(artifacts["magisk"]["sha256"])}
    for _k, entry in artifacts["apks"].items():
        sha_by_install_name[str(entry["install_name"])] = str(entry["sha256"])

    expected_apks: list[tuple[str, str]] = []
    if expected_apk_names is not None:
        for fname in expected_apk_names:
            if not fname:
                continue
            if fname not in sha_by_install_name:
                fail(f"Unknown APK name in --expected-apks: {fname}")
            expected_apks.append((fname, sha_by_install_name[fname]))
    else:
        if not expect_no_root:
            expected_apks.append(("01-magisk.apk", sha_by_install_name["01-magisk.apk"]))
        apk_groups = {
            "apps": expect_apps,
            "microg": expect_microg,
            "power_apps": expect_power_apps,
            "pentest": expect_pentest and not expect_no_root,
        }
        for _k, entry in artifacts["apks"].items():
            if apk_groups.get(str(entry["group"]), False):
                expected_apks.append((str(entry["install_name"]), str(entry["sha256"])))

    apks_dir = payload_root / "apks"
    for fname, exp_sha in expected_apks:
        ap = apks_dir / fname
        if not ap.is_file():
            fail(f"Missing staged APK: {fname}")
        if sha256_file(ap) != exp_sha.lower():
            fail(f"APK {fname} SHA-256 mismatch")
        with zipfile.ZipFile(ap, "r") as azf:
            if azf.testzip() is not None:
                fail(f"APK {fname} failed testzip()")
    ok(f"all {len(expected_apks)} bundled APKs match pinned SHA-256s and pass ZIP verification")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify an Andarium Root IPA (v4) thoroughly.")
    parser.add_argument("--ipa", type=Path, required=True, help="Path to built IPA to verify")
    parser.add_argument("--base-ipa", type=Path, help="Optional stock base IPA for byte-for-byte comparison")
    parser.add_argument("--expected-bundle-id", default="com.andarium.root")
    parser.add_argument("--expected-display-name", default="Andarium Root")
    parser.add_argument("--expected-selinux", choices=("permissive", "enforcing"), default="permissive")
    parser.add_argument("--expected-apks", default=None, help="Optional comma-separated install_name list of staged APKs")
    parser.add_argument("--no-root", action="store_true", help="Verify build-time unrooted IPA (stock init_boot untouched)")
    parser.add_argument("--expect-preboot-dylib", action="store_true", help="Verify native iOS Pre-Boot dylib & LC_LOAD_DYLIB")
    parser.add_argument("--raw-display-name", action="store_true", help="Expect raw root Info.plist CFBundleDisplayName override")
    parser.add_argument("--no-modules", action="store_true")
    parser.add_argument("--no-stealth", action="store_true")
    parser.add_argument("--no-pentest", action="store_true")
    parser.add_argument("--no-network", action="store_true")
    parser.add_argument("--no-apps", action="store_true")
    parser.add_argument("--no-power-apps", action="store_true")
    parser.add_argument("--no-microg", action="store_true")
    parser.add_argument("--no-custom-icon", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ipa_path = args.ipa.resolve()
    base_ipa = args.base_ipa.resolve() if args.base_ipa else None
    if not ipa_path.is_file():
        fail(f"IPA not found: {ipa_path}")

    _manifest, layout = verify_ipa_bundle(
        ipa_path,
        base_ipa,
        expected_bundle_id=args.expected_bundle_id,
        expected_display_name=args.expected_display_name,
        expect_custom_icon=not args.no_custom_icon,
        expect_no_root=args.no_root,
        expect_preboot_dylib=args.expect_preboot_dylib,
        expect_raw_display_name=args.raw_display_name,
    )

    work_dir = Path(tempfile.mkdtemp(prefix="andarium_root_verify_"))
    try:
        disk_path = work_dir / "system.img"
        layout_path = work_dir / "partition-layout.json"
        with zipfile.ZipFile(ipa_path, "r") as zf:
            layout_path.write_bytes(zf.read(IPA_LAYOUT_JSON))
            with zf.open(IPA_SYSTEM_IMG, "r") as src, disk_path.open("wb") as out:
                while chunk := src.read(COPY_CHUNK):
                    out.write(chunk)

        policy_path = MANIFESTS_DIR / "disk-policy.json"
        res = run_cmd(
            [
                sys.executable,
                str(SCRIPTS_DIR / "ubd_disk.py"),
                "verify",
                "--layout",
                str(layout_path),
                "--disk",
                str(disk_path),
                "--hash",
                "--policy",
                str(policy_path),
            ]
        )
        ok(res.stdout.strip())

        parts_by_name = {p["name"]: p for p in layout["system_disk"]["partitions"]}
        stock_init_boot: Path | None = None
        stock_odm: Path | None = None
        if base_ipa is not None:
            stock_init_boot = work_dir / "stock_init_boot.img"
            stock_layout = extract_stock_partition(base_ipa, "init_boot", stock_init_boot)
            stock_odm = work_dir / "stock_odm.img"
            extract_stock_partition(base_ipa, "odm", stock_odm)
            stock_by_name = {p["name"]: p for p in stock_layout["system_disk"]["partitions"]}
            for pname in UNTOUCHED_PARTITIONS:
                if parts_by_name[pname]["sha256"] != stock_by_name[pname]["sha256"]:
                    fail(f"Untouched partition {pname} SHA-256 changed unexpectedly")
            ok(f"all {len(UNTOUCHED_PARTITIONS)} untouched partitions ({', '.join(UNTOUCHED_PARTITIONS)}) match stock SHA-256")

        rec_start, rec_size = android_image.partition_range(layout_path, disk_path, "recovery", VerifyError)
        with disk_path.open("rb") as df:
            android_image.parse_boot_image(df, rec_start, rec_size, VerifyError)
        ok("recovery boot-image v4 header valid")

        ib_start, ib_size = android_image.partition_range(layout_path, disk_path, "init_boot", VerifyError)
        ib_path = work_dir / "init_boot.img"
        extract_partition_slice(disk_path, ib_start, ib_size, ib_path)
        if args.no_root:
            if stock_init_boot is not None and sha256_file(ib_path) != sha256_file(stock_init_boot):
                fail("Unrooted build modified init_boot.img unexpectedly")
            with ib_path.open("rb") as df:
                android_image.parse_boot_image(df, 0, ib_path.stat().st_size, VerifyError)
            ok("unrooted init_boot.img verified byte-for-byte stock untouched")
        else:
            verify_init_boot(ib_path, stock_init_boot, expected_selinux=args.expected_selinux)

        odm_start, odm_size = android_image.partition_range(layout_path, disk_path, "odm", VerifyError)
        odm_path = work_dir / "odm.img"
        extract_partition_slice(disk_path, odm_start, odm_size, odm_path)
        expected_apk_list = (
            [x.strip() for x in args.expected_apks.split(",") if x.strip()]
            if args.expected_apks is not None
            else None
        )
        verify_odm(
            odm_path,
            stock_odm,
            work_dir,
            expect_no_root=args.no_root,
            expect_modules=not args.no_modules,
            expect_stealth=not args.no_stealth,
            expect_pentest=not args.no_pentest,
            expect_network=not args.no_network,
            expect_apps=not args.no_apps,
            expect_power_apps=not args.no_power_apps,
            expect_microg=not args.no_microg,
            expected_selinux=args.expected_selinux,
            expected_apk_names=expected_apk_list,
        )

        print("[verify] ALL VERIFICATION CHECKS PASSED!", flush=True)
        return 0
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerifyError as exc:
        print(f"[verify] FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
