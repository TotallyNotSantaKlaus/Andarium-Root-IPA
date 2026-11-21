#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build a customizable Andarium Root IPA (v4 Pre-Boot & Config Studio Edition).

Supports 6 role presets (Mix/Ultimate, Security Engineer, Hacker/RE, Gamer,
Privacy/Daily, Clean/Unrooted), declarative `andarium-config.json`, build-time
unrooted mode (`--no-root`), runtime/pre-boot root hide/restore toggle, 4 custom
iOS icon themes (`duskjade`, `crimson`, `cyber`, `stealth`), native iOS Pre-Boot
Setup Studio (`AndariumRootPreboot.dylib` + Mach-O `LC_LOAD_DYLIB` injection),
Control Panel v4, Frida ready-to-run bypass script pack, 13 bundled APKs, and
custom/ drop-in overlay.

Must be run inside Linux / WSL2 with erofs-utils (`mkfs.erofs`, `fsck.erofs`,
`dump.erofs`) and `openssl` installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import plistlib
import secrets
import shutil
import sqlite3
import string
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
import zlib
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = Path(__file__).resolve().parent
MANIFESTS_DIR = ROOT_DIR / "manifests"
GUEST_SCRIPTS_DIR = SCRIPTS_DIR / "guest"
FRIDA_SCRIPTS_SRC = GUEST_SCRIPTS_DIR / "frida_scripts"
CONTROL_MODULE_SRC = GUEST_SCRIPTS_DIR / "control_module"
IOS_PREBOOT_SRC = ROOT_DIR / "ios" / "AndariumRootPreboot"
DEFAULT_PREBOOT_DYLIB = ROOT_DIR / "assets" / "ios" / "AndariumRootPreboot.dylib"
ICON_ASSETS_DIR = ROOT_DIR / "assets" / "icon"
DEFAULT_CUSTOM_DIR = ROOT_DIR / "custom"
CACHE_DIR = ROOT_DIR / ".cache"
DEFAULT_OUTPUT = ROOT_DIR / "dist" / "Andarium-Root-1.0-15.ipa"

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

ICON_THEMES = ("duskjade", "crimson", "cyber", "stealth", "stock")
PRESET_NAMES = ("mix", "seceng", "hacker", "gamer", "privacy", "unrooted")

CUSTOM_ICON_FILES = (
    "AndariumRoot60x60@2x.png",
    "AndariumRoot60x60@3x.png",
    "AndariumRoot76x76@2x~ipad.png",
    "AndariumRoot83.5x83.5@2x~ipad.png",
    "AndariumRoot1024x1024.png",
)

ODM_UUID = "4bd71fa4-60a6-5216-9ef1-00258e0f0150"
ODM_TIMESTAMP = "1230768000"
ODM_VENDOR_LABEL = b"u:object_r:vendor_file:s0"

VECTOR_PLACEHOLDER = b"5291374ceda0aef7c5d86cd2a4f6a3ac"
COPY_CHUNK = 4 * 1024 * 1024


class BuildError(RuntimeError):
    pass


def log(msg: str) -> None:
    print(f"[build] {msg}", flush=True)


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(COPY_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(cmd: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    res = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if check and res.returncode != 0:
        raise BuildError(
            f"Command failed (rc={res.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )
    return res


def check_host_tools() -> None:
    if sys.platform != "linux":
        raise BuildError("build_rooted_ipa.py must run in Linux / WSL2 (for erofs-utils and security.selinux xattrs).")
    for tool in ("fsck.erofs", "mkfs.erofs", "dump.erofs", "sh"):
        if shutil.which(tool) is None:
            raise BuildError(f"Required tool not found on PATH: {tool}")


def ensure_artifact(entry: dict[str, object], cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    name = str(entry["name"])
    expected_sha = str(entry["sha256"]).lower()
    expected_size = int(entry["size"])
    url = str(entry["url"])
    target = cache_dir / name

    if target.is_file():
        actual_size = target.stat().st_size
        if actual_size == expected_size:
            actual_sha = sha256_file(target)
            if actual_sha == expected_sha:
                log(f"cached OK: {name} ({actual_size:,} B)")
                return target
            log(f"hash mismatch for cached {name} ({actual_sha[:12]} != {expected_sha[:12]}), re-downloading...")
        else:
            log(f"size mismatch for cached {name} ({actual_size} != {expected_size}), re-downloading...")

    log(f"downloading {name} from {url} ...")
    tmp = cache_dir / (name + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "Andarium-Root-Builder/2.0"})
    with urllib.request.urlopen(req, timeout=180) as resp, tmp.open("wb") as out:
        while chunk := resp.read(COPY_CHUNK):
            out.write(chunk)
    actual_size = tmp.stat().st_size
    actual_sha = sha256_file(tmp)
    if actual_size != expected_size or actual_sha != expected_sha:
        tmp.unlink(missing_ok=True)
        raise BuildError(
            f"Downloaded {name} failed verification: size={actual_size} (expected {expected_size}), "
            f"sha256={actual_sha} (expected {expected_sha})"
        )
    tmp.replace(target)
    log(f"downloaded & verified: {name}")
    return target


def read_text_lf(path: Path, substitutions: dict[str, str] | None = None) -> bytes:
    if not path.is_file():
        raise BuildError(f"Missing text/script file: {path}")
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    if substitutions:
        for k, v in substitutions.items():
            text = text.replace(k, v)
    data = text.encode("utf-8")
    if b"\r" in data:
        raise BuildError(f"CRLF leaked into {path.name}")
    return data


def read_guest_script_lf(name: str, substitutions: dict[str, str] | None = None) -> bytes:
    return read_text_lf(GUEST_SCRIPTS_DIR / name, substitutions)


def check_shell_syntax(path: Path) -> None:
    res = subprocess.run(["sh", "-n", str(path)], text=True, capture_output=True)
    if res.returncode != 0:
        raise BuildError(f"Shell syntax error in {path}:\n{res.stderr}")


def extract_stock_partitions(ipa_path: Path, work_dir: Path) -> tuple[dict[str, object], dict[str, object], dict[str, Path]]:
    part_dir = work_dir / "partitions"
    part_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(ipa_path, "r") as zf:
        layout = json.loads(zf.read(IPA_LAYOUT_JSON).decode("utf-8"))
        manifest = json.loads(zf.read(IPA_MANIFEST_JSON).decode("utf-8"))
        partitions = layout["system_disk"]["partitions"]

        sorted_parts = sorted(partitions, key=lambda p: p["start_bytes"])
        out_paths: dict[str, Path] = {}

        log(f"streaming {IPA_SYSTEM_IMG} to unpack {len(sorted_parts)} GPT partitions...")
        with zf.open(IPA_SYSTEM_IMG, "r") as src:
            pos = 0
            for part in sorted_parts:
                name = part["name"]
                start = int(part["start_bytes"])
                size = int(part["size_bytes"])
                expected_sha = str(part["sha256"])

                if start < pos:
                    raise BuildError(f"Overlapping partition offset for {name}: {start} < {pos}")
                skip = start - pos
                while skip > 0:
                    buf = src.read(min(skip, COPY_CHUNK))
                    if not buf:
                        raise BuildError(f"Unexpected EOF skipping to partition {name}")
                    skip -= len(buf)
                    pos += len(buf)

                dst = part_dir / f"{name}.img"
                h = hashlib.sha256()
                rem = size
                with dst.open("wb") as out:
                    while rem > 0:
                        buf = src.read(min(rem, COPY_CHUNK))
                        if not buf:
                            raise BuildError(f"Unexpected EOF reading partition {name}")
                        out.write(buf)
                        h.update(buf)
                        rem -= len(buf)
                        pos += len(buf)

                got_sha = h.hexdigest()
                if got_sha != expected_sha:
                    raise BuildError(f"Stock partition {name} SHA-256 mismatch: {got_sha} != {expected_sha}")
                out_paths[name] = dst
                log(f"  unpacked {name}.img ({size:,} B, sha256 verified)")

    return layout, manifest, out_paths


def xz_compress_magisk(data: bytes) -> bytes:
    """Compress with XZ CRC32 check (matches Magisk boot_patch.sh `magiskboot compress=xz`)."""
    return lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32, preset=6)


def patch_init_boot(
    stock_init_boot: Path,
    magisk_apk: Path,
    out_init_boot: Path,
    work_dir: Path,
    *,
    selinux_mode: str,
    enable_debuggable: bool,
    enable_adbroot: bool,
    default_stealth: str,
) -> None:
    ib_work = work_dir / "init_boot_patch"
    ib_work.mkdir(parents=True, exist_ok=True)

    magiskboot = ib_work / "magiskboot"
    magiskinit = ib_work / "magiskinit"
    magisk_xz = ib_work / "magisk.xz"
    init_ld_xz = ib_work / "init-ld.xz"

    with zipfile.ZipFile(magisk_apk, "r") as zf:
        magiskboot.write_bytes(zf.read("lib/x86_64/libmagiskboot.so"))
        magiskboot.chmod(0o755)
        magiskinit.write_bytes(zf.read("lib/arm64-v8a/libmagiskinit.so"))
        magiskinit.chmod(0o755)
        magisk_xz.write_bytes(xz_compress_magisk(zf.read("lib/arm64-v8a/libmagisk.so")))
        init_ld_xz.write_bytes(xz_compress_magisk(zf.read("lib/arm64-v8a/libinit-ld.so")))

    res_sha1 = run_cmd([str(magiskboot), "sha1", str(stock_init_boot)], cwd=ib_work)
    stock_sha1 = res_sha1.stdout.strip().splitlines()[-1].strip()
    if len(stock_sha1) != 40:
        raise BuildError(f"Unexpected magiskboot sha1 output: {res_sha1.stdout!r}")

    working_ib = ib_work / "stock_init_boot.img"
    shutil.copy2(stock_init_boot, working_ib)
    run_cmd([str(magiskboot), "unpack", "-h", str(working_ib)], cwd=ib_work)

    ramdisk_cpio = ib_work / "ramdisk.cpio"
    if not ramdisk_cpio.is_file():
        raise BuildError("magiskboot unpack did not produce ramdisk.cpio")

    orig_ramdisk = ib_work / "ramdisk.cpio.orig"
    shutil.copy2(ramdisk_cpio, orig_ramdisk)

    magisk_cfg = ib_work / "config"
    magisk_cfg.write_bytes(
        (
            "KEEPVERITY=true\n"
            "KEEPFORCEENCRYPT=false\n"
            "RECOVERYMODE=false\n"
            "PREINITDEVICE=metadata\n"
            f"SHA1={stock_sha1}\n"
        ).encode("utf-8")
    )

    rc_file = ib_work / "init.andarium_root.rc"
    rc_file.write_bytes(read_guest_script_lf("init.andarium_root.rc"))

    early_sh = ib_work / "andarium_early_init.sh"
    early_sh.write_bytes(
        read_guest_script_lf(
            "andarium_early_init.sh",
            {
                "__DEFAULT_SELINUX__": selinux_mode,
                "__DEFAULT_DEBUGGABLE__": "1" if enable_debuggable else "0",
                "__DEFAULT_ADBROOT__": "1" if enable_adbroot else "0",
                "__DEFAULT_STEALTH__": default_stealth,
            },
        )
    )
    check_shell_syntax(early_sh)

    cpio_cmds = [
        "add 0750 init magiskinit",
        "mkdir 0750 overlay.d",
        "mkdir 0750 overlay.d/sbin",
        "add 0644 overlay.d/sbin/magisk.xz magisk.xz",
        "add 0644 overlay.d/sbin/init-ld.xz init-ld.xz",
        "add 0644 overlay.d/init.andarium_root.rc init.andarium_root.rc",
        "add 0755 overlay.d/sbin/andarium_early_init.sh andarium_early_init.sh",
        "patch",
        "backup ramdisk.cpio.orig",
        "mkdir 000 .backup",
        "add 000 .backup/.magisk config",
    ]
    run_cmd([str(magiskboot), "cpio", str(ramdisk_cpio), *cpio_cmds], cwd=ib_work)

    repacked_raw = ib_work / "new-boot.img"
    run_cmd([str(magiskboot), "repack", "-n", str(working_ib), str(repacked_raw)], cwd=ib_work)

    raw_bytes = repacked_raw.read_bytes()
    if raw_bytes[:8] != android_image.BOOT_MAGIC:
        raise BuildError("Repacked init_boot missing ANDROID! magic")
    kernel_size, ramdisk_size, _os_ver, header_size = struct.unpack_from("<IIII", raw_bytes, 8)
    if kernel_size != 0 or header_size != android_image.BOOT_HEADER_SIZE or ramdisk_size <= 0:
        raise BuildError(
            f"Unexpected repacked init_boot header: ksz={kernel_size} rsz={ramdisk_size} hsz={header_size}"
        )

    exact_size = align_up(android_image.BOOT_PAGE_SIZE + ramdisk_size, android_image.BOOT_PAGE_SIZE)
    if len(raw_bytes) < exact_size:
        trimmed = raw_bytes + bytes(exact_size - len(raw_bytes))
    else:
        tail = raw_bytes[android_image.BOOT_PAGE_SIZE + ramdisk_size :]
        if any(tail):
            raise BuildError("Repacked init_boot has unexpected non-zero bytes after ramdisk")
        trimmed = raw_bytes[: android_image.BOOT_PAGE_SIZE + ramdisk_size]
        trimmed += bytes(exact_size - len(trimmed))

    out_init_boot.write_bytes(trimmed)

    with out_init_boot.open("rb") as f:
        info = android_image.parse_boot_image(f, 0, len(trimmed), BuildError)
        reader = android_image.RangeReader(f, info.ramdisk_offset, info.ramdisk_size, BuildError)
        entries = android_image.parse_newc(reader, lambda _n, _m: False, BuildError)

    log(
        f"patched init_boot.img: {len(trimmed):,} B "
        f"(ramdisk={info.ramdisk_size:,} B, {len(entries)} CPIO entries, v4 header OK)"
    )


def create_magisk_db(db_path: Path, *, enable_rezygisk: bool) -> None:
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA user_version = 13;")
        cur.execute(
            "CREATE TABLE IF NOT EXISTS policies "
            "(uid INT, policy INT, until INT, logging INT, notification INT, PRIMARY KEY(uid));"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS settings "
            "(key TEXT, value INT, PRIMARY KEY(key));"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS denylist "
            "(package_name TEXT, process TEXT, PRIMARY KEY(package_name, process));"
        )
        settings_rows = [
            ("zygisk", 0 if enable_rezygisk else 1),
            ("denylist", 0),
            ("multiuser_mode", 0),
            ("mnt_ns", 1),
            ("bootloop", 0),
        ]
        cur.executemany("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?);", settings_rows)
        cur.execute(
            "INSERT OR REPLACE INTO policies (uid, policy, until, logging, notification) "
            "VALUES (2000, 2, 0, 1, 0);"
        )
        conn.commit()
    finally:
        conn.close()


def extract_verified_zip_member(zf: zipfile.ZipFile, member: str, dst: Path) -> None:
    data = zf.read(member)
    sha_member = member + ".sha256"
    if sha_member in zf.namelist():
        expected = zf.read(sha_member).decode("utf-8").strip().split()[0].lower()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise BuildError(f"Module file checksum mismatch for {member}: {actual} != {expected}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)


def stage_control_module(
    modules_root: Path,
    *,
    enable_debuggable: bool,
    default_stealth: str,
    hosts_adblock_path: Path | None,
    custom_hosts_path: Path | None,
) -> None:
    mod_dir = modules_root / "andarium_control"
    (mod_dir / "webroot" / "cgi-bin").mkdir(parents=True, exist_ok=True)
    (mod_dir / "system" / "etc").mkdir(parents=True, exist_ok=True)

    (mod_dir / "module.prop").write_bytes(read_text_lf(CONTROL_MODULE_SRC / "module.prop"))

    svc = mod_dir / "service.sh"
    svc.write_bytes(
        read_text_lf(
            CONTROL_MODULE_SRC / "service.sh",
            {
                "__DEFAULT_DEBUGGABLE__": "1" if enable_debuggable else "0",
                "__DEFAULT_STEALTH__": default_stealth,
            },
        )
    )
    check_shell_syntax(svc)

    act = mod_dir / "action.sh"
    act.write_bytes(read_text_lf(CONTROL_MODULE_SRC / "action.sh"))
    check_shell_syntax(act)

    api = mod_dir / "webroot" / "cgi-bin" / "api"
    api.write_bytes(read_text_lf(CONTROL_MODULE_SRC / "webroot" / "cgi-bin" / "api"))
    check_shell_syntax(api)

    (mod_dir / "webroot" / "index.html").write_bytes(read_text_lf(CONTROL_MODULE_SRC / "webroot" / "index.html"))

    # Active systemless /system/etc/hosts (Magic-Mounted by Magisk)
    hosts_buf = bytearray()
    if hosts_adblock_path is not None:
        hosts_buf.extend(hosts_adblock_path.read_bytes().replace(b"\r\n", b"\n"))
    else:
        hosts_buf.extend(b"127.0.0.1       localhost\n::1             ip6-localhost\n")
    if custom_hosts_path is not None and custom_hosts_path.is_file():
        hosts_buf.extend(b"\n# === Custom Hosts ===\n")
        hosts_buf.extend(custom_hosts_path.read_bytes().replace(b"\r\n", b"\n"))
    (mod_dir / "system" / "etc" / "hosts").write_bytes(bytes(hosts_buf))

    log("  staged module: andarium_control (WebUI + localhost:8787 CGI + systemless hosts)")


def stage_rezygisk_module(rezygisk_zip: Path, modules_root: Path) -> None:
    mod_dir = modules_root / "rezygisk"
    mod_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(rezygisk_zip, "r") as zf:
        for fn in ("module.prop", "post-fs-data.sh", "service.sh", "uninstall.sh", "sepolicy.rule"):
            extract_verified_zip_member(zf, fn, mod_dir / fn)
        shutil.copy2(mod_dir / "module.prop", mod_dir / "module.prop.bak")
        extract_verified_zip_member(zf, "rezygisk.sh", modules_root / "rezygisk.sh")

        for info in zf.infolist():
            name = info.filename
            if not name.startswith("webroot/") or name.endswith("/") or name.endswith(".sha256"):
                continue
            extract_verified_zip_member(zf, name, mod_dir / name)

        extract_verified_zip_member(zf, "bin/arm64-v8a/zygiskd", mod_dir / "bin/zygiskd64")
        extract_verified_zip_member(zf, "lib/arm64-v8a/libzygisk.so", mod_dir / "lib64/libzygisk.so")
        extract_verified_zip_member(zf, "lib/arm64-v8a/libzygisk_ptrace.so", mod_dir / "bin/zygisk-ptrace64")
        extract_verified_zip_member(zf, "machikado.arm64", mod_dir / "machikado.arm64")

        extract_verified_zip_member(zf, "bin/armeabi-v7a/zygiskd", mod_dir / "bin/zygiskd32")
        extract_verified_zip_member(zf, "lib/armeabi-v7a/libzygisk.so", mod_dir / "lib/libzygisk.so")
        extract_verified_zip_member(zf, "lib/armeabi-v7a/libzygisk_ptrace.so", mod_dir / "bin/zygisk-ptrace32")
        extract_verified_zip_member(zf, "machikado.arm", mod_dir / "machikado.arm")

    log("  staged module: rezygisk (arm64-v8a + armeabi-v7a, all .sha256 sidecars verified)")


def patch_vector_daemon_apk_inplace(apk_path: Path, dev_path: bytes) -> int:
    if len(dev_path) != len(VECTOR_PLACEHOLDER):
        raise BuildError("dev_path length must match VECTOR_PLACEHOLDER")

    buf = bytearray(apk_path.read_bytes())
    modified_crcs: dict[str, tuple[int, int]] = {}
    total_replacements = 0
    with zipfile.ZipFile(apk_path, "r") as zf:
        for zi in zf.infolist():
            if zi.compress_type != zipfile.ZIP_STORED:
                continue
            raw = zf.read(zi.filename)
            count = raw.count(VECTOR_PLACEHOLDER)
            if count == 0:
                continue
            if zi.flag_bits & 0x08:
                raise BuildError(f"Unsupported data descriptor on stored entry {zi.filename}")
            lh_off = zi.header_offset
            if buf[lh_off : lh_off + 4] != b"PK\x03\x04":
                raise BuildError(f"Invalid LFH magic for {zi.filename} at {lh_off}")
            fn_len, ex_len = struct.unpack_from("<HH", buf, lh_off + 26)
            data_off = lh_off + 30 + fn_len + ex_len
            data_end = data_off + zi.file_size
            if bytes(buf[data_off:data_end]) != raw:
                raise BuildError(f"Entry payload mismatch for {zi.filename}")

            patched_entry = raw.replace(VECTOR_PLACEHOLDER, dev_path)
            buf[data_off:data_end] = patched_entry
            new_crc = zlib.crc32(patched_entry) & 0xFFFFFFFF
            struct.pack_into("<I", buf, lh_off + 14, new_crc)
            modified_crcs[zi.filename] = (lh_off, new_crc)
            total_replacements += count

    if total_replacements == 0:
        raise BuildError("Expected placeholder not found in Vector daemon.apk")

    eocd_off = buf.rfind(b"PK\x05\x06")
    if eocd_off < 0:
        raise BuildError("EOCD not found in daemon.apk")
    cd_size, cd_off = struct.unpack_from("<II", buf, eocd_off + 12)
    cursor = cd_off
    cd_end = cd_off + cd_size
    updated_cd = 0
    while cursor < cd_end:
        if buf[cursor : cursor + 4] != b"PK\x01\x02":
            raise BuildError(f"Invalid CD header magic in daemon.apk at {cursor}")
        fn_len, ex_len, cm_len = struct.unpack_from("<HHH", buf, cursor + 28)
        lh_off = struct.unpack_from("<I", buf, cursor + 42)[0]
        fname = bytes(buf[cursor + 46 : cursor + 46 + fn_len]).decode("utf-8", "replace")
        if fname in modified_crcs and modified_crcs[fname][0] == lh_off:
            struct.pack_into("<I", buf, cursor + 16, modified_crcs[fname][1])
            updated_cd += 1
        cursor += 46 + fn_len + ex_len + cm_len

    if updated_cd != len(modified_crcs):
        raise BuildError(f"Updated {updated_cd} CD entries, expected {len(modified_crcs)}")

    apk_path.write_bytes(buf)

    with zipfile.ZipFile(apk_path, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise BuildError(f"Patched daemon.apk failed testzip() on entry: {bad}")
    if VECTOR_PLACEHOLDER in apk_path.read_bytes():
        raise BuildError("Placeholder still present in daemon.apk after patching")

    return total_replacements


def stage_vector_module(vector_zip: Path, modules_root: Path) -> str:
    mod_dir = modules_root / "zygisk_vector"
    mod_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(vector_zip, "r") as zf:
        for fn in (
            "module.prop",
            "action.sh",
            "service.sh",
            "uninstall.sh",
            "sepolicy.rule",
            "framework/vector.dex",
            "cli",
            "daemon.apk",
            "daemon",
            "manager.apk",
        ):
            extract_verified_zip_member(zf, fn, mod_dir / fn)

        extract_verified_zip_member(zf, "lib/arm64-v8a/libzygisk.so", mod_dir / "zygisk/arm64-v8a.so")
        extract_verified_zip_member(zf, "lib/armeabi-v7a/libzygisk.so", mod_dir / "zygisk/armeabi-v7a.so")

        extract_verified_zip_member(zf, "bin/arm64-v8a/dex2oat", mod_dir / "bin/dex2oat64")
        extract_verified_zip_member(zf, "bin/arm64-v8a/liboat_hook.so", mod_dir / "bin/liboat_hook64.so")
        extract_verified_zip_member(zf, "bin/armeabi-v7a/dex2oat", mod_dir / "bin/dex2oat32")
        extract_verified_zip_member(zf, "bin/armeabi-v7a/liboat_hook.so", mod_dir / "bin/liboat_hook32.so")

    alphabet = string.ascii_lowercase + string.digits
    dev_path_str = "".join(secrets.choice(alphabet) for _ in range(32))
    dev_path = dev_path_str.encode("ascii")

    apk_hits = patch_vector_daemon_apk_inplace(mod_dir / "daemon.apk", dev_path)
    for dex_bin in (mod_dir / "bin/dex2oat32", mod_dir / "bin/dex2oat64"):
        raw = dex_bin.read_bytes()
        hits = raw.count(VECTOR_PLACEHOLDER)
        if hits != 1:
            raise BuildError(f"Expected 1 placeholder in {dex_bin.name}, found {hits}")
        dex_bin.write_bytes(raw.replace(VECTOR_PLACEHOLDER, dev_path))

    log(
        f"  staged module: zygisk_vector (arm64-v8a + armeabi-v7a, "
        f"anti-detection DEV_PATH patched in {apk_hits} APK libs + dex2oat32/64)"
    )
    return dev_path_str


def stage_playintegrityfork_module(pif_zip: Path, modules_root: Path) -> None:
    mod_dir = modules_root / "playintegrityfix"
    mod_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(pif_zip, "r") as zf:
        for info in zf.infolist():
            name = info.filename
            if name.endswith("/") or name.startswith("META-INF/") or name == "customize.sh":
                continue
            dst = mod_dir / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(zf.read(name))
    log("  staged module: playintegrityfix (PlayIntegrityFork v19)")


def stage_trickystore_module(ts_zip: Path, modules_root: Path, config_root: Path) -> None:
    mod_dir = modules_root / "tricky_store"
    mod_dir.mkdir(parents=True, exist_ok=True)
    ts_cfg_dir = config_root / "tricky_store"
    ts_cfg_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(ts_zip, "r") as zf:
        for fn in ("module.prop", "post-fs-data.sh", "service.sh", "service.apk", "sepolicy.rule", "daemon", "mazoku"):
            extract_verified_zip_member(zf, fn, mod_dir / fn)
        extract_verified_zip_member(zf, "lib/arm64/libtricky_store.so", mod_dir / "libtricky_store.so")
        extract_verified_zip_member(zf, "machikado.arm64", mod_dir / "machikado")
        extract_verified_zip_member(zf, "keybox.xml", ts_cfg_dir / "keybox.xml")
        extract_verified_zip_member(zf, "target.txt", ts_cfg_dir / "target.txt")

    log("  staged module: tricky_store (TrickyStore v1.4.1 arm64 + default keybox/target, .sha256 verified)")


def stage_zygisk_assistant_module(za_zip: Path, modules_root: Path) -> None:
    mod_dir = modules_root / "zygisk-assistant"
    mod_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(za_zip, "r") as zf:
        for fn in ("module.prop", "common_func.sh", "post-fs-data.sh", "service.sh", "zygisk/arm64-v8a.so", "zygisk/armeabi-v7a.so"):
            dst = mod_dir / fn
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(zf.read(fn))
    log("  staged module: zygisk-assistant (Zygisk-Assistant v2.1.4)")


def stage_tools(
    tools_root: Path,
    config_root: Path,
    *,
    frida_xz: Path | None,
    dropbear_zip: Path | None,
    hosts_txt: Path | None,
    cli_tools: dict[str, Path] | None = None,
) -> Path | None:
    if frida_xz is not None:
        frida_dst = tools_root / "frida-server"
        with lzma.open(frida_xz, "rb") as xf:
            raw = xf.read()
        if len(raw) < 20 or raw[:4] != b"\x7fELF" or struct.unpack_from("<H", raw, 18)[0] != android_image.EM_AARCH64:
            raise BuildError("Decompressed frida-server is not an AArch64 ELF binary")
        frida_dst.write_bytes(raw)
        log(f"  staged tool: frida-server ({len(raw):,} B AArch64 ELF)")
        if FRIDA_SCRIPTS_SRC.is_dir():
            fs_dst = tools_root / "frida-scripts"
            fs_dst.mkdir(parents=True, exist_ok=True)
            staged_js: list[str] = []
            for js_file in sorted(FRIDA_SCRIPTS_SRC.glob("*.js")):
                (fs_dst / js_file.name).write_bytes(read_text_lf(js_file))
                staged_js.append(js_file.name)
            if staged_js:
                log(f"  staged Frida bypass script pack ({len(staged_js)}): {', '.join(staged_js)}")

    if dropbear_zip is not None:
        db_dir = tools_root / "dropbear"
        db_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(dropbear_zip, "r") as zf:
            for bin_name in ("dropbear", "dropbearkey", "dropbearconvert", "dbclient", "scp"):
                raw = zf.read(bin_name)
                if len(raw) < 20 or raw[:4] != b"\x7fELF" or struct.unpack_from("<H", raw, 18)[0] != android_image.EM_AARCH64:
                    raise BuildError(f"Dropbear {bin_name} is not an AArch64 ELF binary")
                (db_dir / bin_name).write_bytes(raw)
        log("  staged tool: dropbear SSH suite (dropbear, dropbearkey, dropbearconvert, dbclient, scp)")

    if cli_tools:
        cli_dir = tools_root / "cli"
        cli_dir.mkdir(parents=True, exist_ok=True)
        staged_names: list[str] = []
        for tool_name, src_path in cli_tools.items():
            if tool_name == "strace":
                with zipfile.ZipFile(src_path, "r") as zf:
                    raw = zf.read("strace-bin/arm64/strace")
            elif tool_name == "sqlite3":
                with zipfile.ZipFile(src_path, "r") as zf:
                    raw = zf.read("system/bin/sqlite3.arm64")
            else:
                raw = src_path.read_bytes()
            if len(raw) < 20 or raw[:4] != b"\x7fELF" or struct.unpack_from("<H", raw, 18)[0] != android_image.EM_AARCH64:
                raise BuildError(f"CLI tool {tool_name} is not an AArch64 ELF binary")
            (cli_dir / tool_name).write_bytes(raw)
            staged_names.append(tool_name)
        log(f"  staged ARM64 pentest/system CLI suite: {', '.join(staged_names)}")

    if hosts_txt is not None:
        hosts_dst = config_root / "hosts.adblock"
        hosts_dst.write_bytes(hosts_txt.read_bytes().replace(b"\r\n", b"\n"))
        log(f"  staged config: hosts.adblock ({hosts_dst.stat().st_size:,} B)")
        return hosts_dst
    return None


def convert_ca_cert_to_android_pem(src: Path, dst_dir: Path) -> Path:
    """Convert any PEM or DER X.509 certificate into Android's `<subject_hash_old>.0` PEM format."""
    if shutil.which("openssl") is None:
        raise BuildError("`openssl` is required to convert drop-in custom CA certificates")

    raw = src.read_bytes()
    inform = "PEM" if b"-----BEGIN CERTIFICATE-----" in raw else "DER"

    res_hash = run_cmd(["openssl", "x509", "-inform", inform, "-subject_hash_old", "-noout", "-in", str(src)])
    h = res_hash.stdout.strip().splitlines()[0].strip()
    if len(h) != 8:
        raise BuildError(f"Unexpected openssl subject_hash_old for {src.name}: {h!r}")

    res_pem = run_cmd(["openssl", "x509", "-inform", inform, "-in", str(src), "-outform", "PEM"])
    res_txt = run_cmd(["openssl", "x509", "-inform", inform, "-text", "-fingerprint", "-noout", "-in", str(src)])

    out = dst_dir / f"{h}.0"
    out.write_bytes((res_pem.stdout + "\n" + res_txt.stdout).encode("utf-8"))
    return out


def stage_custom_dropins(custom_dir: Path, payload_custom_dir: Path) -> Path | None:
    if not custom_dir.is_dir():
        return None

    custom_hosts_dst: Path | None = None
    counts = {"apks": 0, "modules": 0, "certs": 0, "scripts": 0}

    # custom/apks/*.apk
    apks_src = custom_dir / "apks"
    if apks_src.is_dir():
        for apk in sorted(apks_src.glob("*.apk")):
            with zipfile.ZipFile(apk, "r") as zf:
                bad = zf.testzip()
                if bad is not None:
                    raise BuildError(f"Custom APK failed ZIP check ({apk.name}): {bad}")
            dst = payload_custom_dir / "apks" / apk.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(apk, dst)
            counts["apks"] += 1

    # custom/modules/*.zip
    mods_src = custom_dir / "modules"
    if mods_src.is_dir():
        for mzip in sorted(mods_src.glob("*.zip")):
            with zipfile.ZipFile(mzip, "r") as zf:
                bad = zf.testzip()
                if bad is not None:
                    raise BuildError(f"Custom module ZIP failed check ({mzip.name}): {bad}")
            dst = payload_custom_dir / "modules" / mzip.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(mzip, dst)
            counts["modules"] += 1

    # custom/certs/*
    certs_src = custom_dir / "certs"
    if certs_src.is_dir():
        certs_dst = payload_custom_dir / "certs"
        for cfile in sorted(certs_src.iterdir()):
            if not cfile.is_file() or cfile.name.startswith("."):
                continue
            if cfile.suffix.lower() not in (".pem", ".crt", ".cer", ".der", ".0"):
                continue
            certs_dst.mkdir(parents=True, exist_ok=True)
            out_cert = convert_ca_cert_to_android_pem(cfile, certs_dst)
            log(f"  converted custom CA cert {cfile.name} -> {out_cert.name}")
            counts["certs"] += 1

    # custom/scripts/{post-fs-data.d,service.d}/*.sh
    for stage_sub in ("post-fs-data.d", "service.d"):
        sdir = custom_dir / "scripts" / stage_sub
        if not sdir.is_dir():
            continue
        for sh_file in sorted(sdir.glob("*.sh")):
            dst = payload_custom_dir / "scripts" / stage_sub / sh_file.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(read_text_lf(sh_file))
            check_shell_syntax(dst)
            counts["scripts"] += 1

    # custom/hosts
    hosts_src = custom_dir / "hosts"
    if hosts_src.is_file() and hosts_src.stat().st_size > 0:
        custom_hosts_dst = payload_custom_dir / "hosts"
        custom_hosts_dst.parent.mkdir(parents=True, exist_ok=True)
        custom_hosts_dst.write_bytes(read_text_lf(hosts_src))
        log(f"  staged custom/hosts ({custom_hosts_dst.stat().st_size:,} B)")

    # custom/authorized_keys
    ak_src = custom_dir / "authorized_keys"
    if ak_src.is_file() and ak_src.stat().st_size > 0:
        ak_dst = payload_custom_dir / "authorized_keys"
        ak_dst.parent.mkdir(parents=True, exist_ok=True)
        ak_dst.write_bytes(read_text_lf(ak_src))
        log("  staged custom/authorized_keys (Dropbear SSH will autostart)")

    # custom/root-packages.txt
    rp_src = custom_dir / "root-packages.txt"
    if rp_src.is_file():
        lines = [
            ln.strip()
            for ln in rp_src.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if lines:
            rp_dst = payload_custom_dir / "root-packages.txt"
            rp_dst.parent.mkdir(parents=True, exist_ok=True)
            rp_dst.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
            log(f"  staged custom/root-packages.txt ({len(lines)} package(s))")

    if any(counts.values()):
        log(
            f"  staged custom/ drop-ins: apks={counts['apks']}, modules={counts['modules']}, "
            f"certs={counts['certs']}, scripts={counts['scripts']}"
        )
    return custom_hosts_dst


def apply_odm_tree_attrs(tree_root: Path) -> None:
    """Recursively set clean UID/GID, modes, and security.selinux on /odm/andarium-root."""
    for dirpath, _dirnames, filenames in os.walk(tree_root):
        dpath = Path(dirpath)
        os.chown(dpath, 0, 0)
        os.chmod(dpath, 0o755)
        os.setxattr(dpath, "security.selinux", ODM_VENDOR_LABEL)
        for fn in filenames:
            fpath = dpath / fn
            os.chown(fpath, 0, 0)
            rel = fpath.relative_to(tree_root).as_posix()
            is_exec = (
                rel.startswith("scripts/")
                or (rel.startswith("tools/") and not fn.endswith(".js"))
                or (rel.startswith("magisk-bin/") and not fn.endswith(".jar"))
                or rel.endswith(".sh")
                or "/bin/" in ("/" + rel)
                or "/cgi-bin/" in ("/" + rel)
                or rel in (
                    "modules/zygisk_vector/daemon",
                    "modules/zygisk_vector/cli",
                    "modules/tricky_store/daemon",
                )
            )
            os.chmod(fpath, 0o755 if is_exec else 0o644)
            os.setxattr(fpath, "security.selinux", ODM_VENDOR_LABEL)


def build_odm_image(
    stock_odm: Path,
    out_odm: Path,
    work_dir: Path,
    *,
    magisk_apk: Path | None,
    rezygisk_zip: Path | None,
    vector_zip: Path | None,
    pif_zip: Path | None,
    trickystore_zip: Path | None,
    zygisk_assistant_zip: Path | None,
    frida_xz: Path | None,
    dropbear_zip: Path | None,
    hosts_txt: Path | None,
    cli_tools: dict[str, Path],
    extra_apks: list[tuple[str, Path]],
    custom_dir: Path,
    selinux_mode: str,
    enable_debuggable: bool,
    default_stealth: str,
    build_unrooted: bool = False,
    effective_config: dict[str, object] | None = None,
) -> None:
    odm_tree = work_dir / "odm_tree"
    if odm_tree.exists():
        shutil.rmtree(odm_tree)

    log("extracting stock odm.img with preserved xattrs and permissions...")
    run_cmd(["fsck.erofs", f"--extract={odm_tree}", "--xattrs", "--preserve", str(stock_odm)])

    root_label = os.getxattr(odm_tree, "security.selinux")
    if root_label != ODM_VENDOR_LABEL:
        raise BuildError(f"Unexpected stock odm root selinux label: {root_label!r}")

    payload_root = odm_tree / "andarium-root"
    config_dir = payload_root / "config"
    apks_dir = payload_root / "apks"
    custom_payload_dir = payload_root / "custom"
    for d in (config_dir, apks_dir):
        d.mkdir(parents=True, exist_ok=True)

    if effective_config is not None:
        (config_dir / "preset.json").write_bytes(
            (json.dumps(effective_config, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )

    if build_unrooted:
        log("  build-time UNROOTED mode: omitting Magisk runtime, root modules & pentest daemons")
        for install_name, apk_path in extra_apks:
            shutil.copy2(apk_path, apks_dir / install_name)
            log(f"  staged unrooted APK: {install_name} ({apk_path.stat().st_size:,} B)")
        stage_custom_dropins(custom_dir, custom_payload_dir)
    else:
        if magisk_apk is None:
            raise BuildError("magisk_apk is required for rooted builds")
        magisk_bin_dir = payload_root / "magisk-bin"
        modules_dir = payload_root / "modules"
        tools_dir = payload_root / "tools"
        scripts_dir = payload_root / "scripts"
        for d in (magisk_bin_dir, modules_dir, tools_dir, scripts_dir):
            d.mkdir(parents=True, exist_ok=True)

        # 1. Magisk runtime support binaries & assets for /data/adb/magisk/
        with zipfile.ZipFile(magisk_apk, "r") as zf:
            bin_map = {
                "lib/arm64-v8a/libbusybox.so": "busybox",
                "lib/arm64-v8a/libmagiskboot.so": "magiskboot",
                "lib/arm64-v8a/libmagiskinit.so": "magiskinit",
                "lib/arm64-v8a/libmagiskpolicy.so": "magiskpolicy",
                "lib/arm64-v8a/libbootctl.so": "bootctl",
                "lib/arm64-v8a/libmagisk.so": "magisk",
                "lib/arm64-v8a/libinit-ld.so": "init-ld",
                "lib/armeabi-v7a/libmagisk.so": "magisk32",
            }
            for src_name, dst_name in bin_map.items():
                (magisk_bin_dir / dst_name).write_bytes(zf.read(src_name))
            for asset in (
                "addon.d.sh",
                "app_functions.sh",
                "boot_patch.sh",
                "main.jar",
                "module_installer.sh",
                "uninstaller.sh",
                "util_functions.sh",
            ):
                (magisk_bin_dir / asset).write_bytes(zf.read(f"assets/{asset}"))
        log("  staged /odm/andarium-root/magisk-bin (Magisk v31.1 full environment)")

        # 2. Seeded magisk.db
        create_magisk_db(config_dir / "magisk.db", enable_rezygisk=(rezygisk_zip is not None))
        log(f"  staged /odm/andarium-root/config/magisk.db (zygisk={0 if rezygisk_zip else 1}, uid 2000 granted)")

        # 3. Stage tools (Frida Server + script pack, Dropbear SSH, CLI pentest suite, StevenBlack hosts) & custom/ drop-ins
        hosts_adblock_dst = stage_tools(
            tools_dir,
            config_dir,
            frida_xz=frida_xz,
            dropbear_zip=dropbear_zip,
            hosts_txt=hosts_txt,
            cli_tools=cli_tools,
        )
        custom_hosts_dst = stage_custom_dropins(custom_dir, custom_payload_dir)

        # 4. Pre-bundled Magisk modules
        stage_control_module(
            modules_dir,
            enable_debuggable=enable_debuggable,
            default_stealth=default_stealth,
            hosts_adblock_path=hosts_adblock_dst,
            custom_hosts_path=custom_hosts_dst,
        )
        if rezygisk_zip is not None:
            stage_rezygisk_module(rezygisk_zip, modules_dir)
        if vector_zip is not None:
            stage_vector_module(vector_zip, modules_dir)
        if pif_zip is not None:
            stage_playintegrityfork_module(pif_zip, modules_dir)
        if trickystore_zip is not None:
            stage_trickystore_module(trickystore_zip, modules_dir, config_dir)
        if zygisk_assistant_zip is not None:
            stage_zygisk_assistant_module(zygisk_assistant_zip, modules_dir)

        # 5. Pre-bundled APKs for first-boot installation & offline storefront
        shutil.copy2(magisk_apk, apks_dir / "01-magisk.apk")
        log(f"  staged APK: 01-magisk.apk ({magisk_apk.stat().st_size:,} B)")
        for install_name, apk_path in extra_apks:
            shutil.copy2(apk_path, apks_dir / install_name)
            log(f"  staged APK: {install_name} ({apk_path.stat().st_size:,} B)")

        # 6. Guest scripts (LF-normalized + syntax-checked)
        boot_sh = scripts_dir / "andarium_boot_complete.sh"
        boot_sh.write_bytes(
            read_guest_script_lf(
                "andarium_boot_complete.sh",
                {
                    "__DEFAULT_SELINUX__": selinux_mode,
                    "__DEFAULT_STEALTH__": default_stealth,
                },
            )
        )
        check_shell_syntax(boot_sh)

        ctl_sh = scripts_dir / "andarium-ctl"
        ctl_sh.write_bytes(read_guest_script_lf("andarium-ctl"))
        check_shell_syntax(ctl_sh)

        termux_setup = scripts_dir / "andarium-termux-setup"
        termux_setup.write_bytes(read_guest_script_lf("andarium-termux-setup"))
        check_shell_syntax(termux_setup)

        shell_rc = scripts_dir / "andarium-shell-rc.sh"
        shell_rc.write_bytes(read_guest_script_lf("andarium-shell-rc.sh"))
        check_shell_syntax(shell_rc)

    # 7. Apply exact ownership, permissions, and security.selinux labels to /odm/andarium-root
    apply_odm_tree_attrs(payload_root)

    # 8. Pack odm.img with Andarium's exact EROFS parameters
    if out_odm.exists():
        out_odm.unlink()
    log("packing odm.img with mkfs.erofs (-zzstd,15 -C16384)...")
    t0 = time.monotonic()
    run_cmd(
        [
            "mkfs.erofs",
            "-zzstd,15",
            "-C16384",
            f"-T{ODM_TIMESTAMP}",
            "-U",
            ODM_UUID,
            str(out_odm),
            str(odm_tree),
        ]
    )
    elapsed = time.monotonic() - t0
    log(f"packed odm.img: {out_odm.stat().st_size:,} B in {elapsed:.1f}s")


def assemble_system_disk(part_dir: Path, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    policy_path = MANIFESTS_DIR / "disk-policy.json"
    log("assembling GPT system.img + partition-layout.json via ubd_disk.py...")
    res = run_cmd(
        [
            sys.executable,
            str(SCRIPTS_DIR / "ubd_disk.py"),
            "assemble",
            "--policy",
            str(policy_path),
            "--images-dir",
            str(part_dir),
            "--output-dir",
            str(out_dir),
        ]
    )
    for line in res.stdout.strip().splitlines():
        log(f"  {line}")

    disk_path = out_dir / "system.img"
    layout_path = out_dir / "partition-layout.json"

    log("verifying assembled system.img via ubd_disk.py verify --hash --policy...")
    res_v = run_cmd(
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
    for line in res_v.stdout.strip().splitlines():
        log(f"  {line}")

    return disk_path, layout_path


def load_presets_manifest() -> dict[str, object]:
    return json.loads((MANIFESTS_DIR / "presets.json").read_text(encoding="utf-8"))


def encode_preboot_cmdline(
    stock_cmdline_bytes: bytes,
    cfg: dict[str, object],
    catalog: list[dict[str, object]],
) -> bytes:
    """Append compact sanitized `androidboot.ar.*` tokens onto stock kernel-command-line.txt."""
    import re

    stock_text = stock_cmdline_bytes.decode("utf-8")
    words = [w for w in stock_text.split() if not w.startswith("androidboot.ar.")]

    preset = str(cfg.get("preset", "mix"))
    if not re.fullmatch(r"[a-z0-9_-]{1,20}", preset):
        preset = "mix"
    root_bit = "1" if cfg.get("root_enabled", True) else "0"
    se_bit = "1" if str(cfg.get("selinux", "permissive")) == "enforcing" else "0"
    stealth_bit = "1" if cfg.get("stealth", False) else "0"
    adbroot_bit = "1" if cfg.get("adbroot", True) else "0"
    dbg_bit = "1" if cfg.get("debuggable", True) else "0"

    mods = cfg.get("modules") if isinstance(cfg.get("modules"), dict) else {}
    svcs = cfg.get("services") if isinstance(cfg.get("services"), dict) else {}
    twks = cfg.get("tweaks") if isinstance(cfg.get("tweaks"), dict) else {}

    mods_bits = (
        ("1" if mods.get("rezygisk", True) else "0")
        + ("1" if mods.get("vector", True) else "0")
        + ("1" if mods.get("stealth_stack", True) else "0")
        + ("1" if svcs.get("adblock", True) else "0")
    )
    svcs_bits = (
        ("1" if svcs.get("frida_autostart", False) else "0")
        + ("1" if svcs.get("ssh_autostart", False) else "0")
        + ("1" if svcs.get("shizuku_autostart", True) else "0")
    )

    enabled_apps = set(cfg.get("apps") or [item["id"] for item in catalog])
    apps_bits = "".join("1" if item["id"] in enabled_apps else "0" for item in catalog)

    anim = str(twks.get("anim_scale", "0.5"))
    if anim not in ("0", "0.5", "1"):
        anim = "0.5"
    try:
        swap_int = max(10, min(200, int(twks.get("swappiness", 100))))
    except (TypeError, ValueError):
        swap_int = 100
    awake_bit = "1" if twks.get("stay_awake", False) else "0"
    dpi_raw = str(twks.get("dpi", "default"))
    dpi = dpi_raw if re.fullmatch(r"[0-9]{3}", dpi_raw) else "0"

    cfg_token = (
        f"4,1,{preset},{root_bit},{se_bit},{stealth_bit},{adbroot_bit},{dbg_bit},"
        f"{mods_bits},{svcs_bits},{apps_bits},{anim},{swap_int},{awake_bit},{dpi}"
    )
    if len(cfg_token) >= 91:
        raise BuildError(f"androidboot.ar.cfg exceeds Android PROP_VALUE_MAX: {cfg_token}")

    words.append(f"androidboot.ar.preset={preset}")
    words.append(f"androidboot.ar.cfg={cfg_token}")

    proxy = str(cfg.get("proxy", "") or "").strip()
    if proxy and re.fullmatch(r"[a-zA-Z0-9.:_-]{3,64}", proxy) and ":" in proxy:
        words.append(f"androidboot.ar.proxy={proxy}")

    final = (" ".join(words) + "\n").encode("utf-8")
    if b'"' in final or b"'" in final:
        raise BuildError("Generated kernel command line contains forbidden quote characters")
    if len(final) > 2048:
        raise BuildError(f"Generated kernel command line unexpectedly long ({len(final)} B)")
    return final


def update_release_manifest(
    stock_manifest: dict[str, object],
    system_img_size: int,
    layout_json_size: int,
    *,
    release_suffix: str,
    cmdline_size: int | None = None,
) -> bytes:
    manifest = json.loads(json.dumps(stock_manifest))
    orig_id = str(manifest["release_id"])
    suffix = f"-{release_suffix}"
    new_id = orig_id if orig_id.endswith(suffix) else f"{orig_id}{suffix}"
    if len(new_id) > 64:
        raise BuildError(f"release_id exceeds 64 chars: {new_id}")
    manifest["release_id"] = new_id
    manifest["acceptance"] = "accepted"

    for item in manifest.get("inventory", []):
        if item.get("path") == "guest/system.img":
            item["size"] = system_img_size
        elif item.get("path") == "guest/partition-layout.json":
            item["size"] = layout_json_size
        elif cmdline_size is not None and item.get("path") == "boot/kernel-command-line.txt":
            item["size"] = cmdline_size

    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def resolve_icon_dir(icon_theme: str) -> Path | None:
    if icon_theme == "stock":
        return None
    themed = ICON_ASSETS_DIR / icon_theme
    if themed.is_dir():
        return themed
    if icon_theme == "duskjade" and (ICON_ASSETS_DIR / CUSTOM_ICON_FILES[0]).is_file():
        return ICON_ASSETS_DIR
    raise BuildError(f"Unknown or missing icon theme directory: {themed}")


def patch_info_plist(
    stock_plist_bytes: bytes,
    bundle_id: str,
    display_name: str,
    *,
    use_custom_icon: bool,
) -> bytes:
    pl = plistlib.loads(stock_plist_bytes)
    pl["CFBundleIdentifier"] = bundle_id
    pl["CFBundleDisplayName"] = display_name
    if use_custom_icon:
        # Remove CFBundleIconName so iOS SpringBoard loads our custom PNG set directly
        # instead of DuskJade inside Assets.car (leaving Assets.car untouched for SwiftUI).
        pl["CFBundleIcons"] = {
            "CFBundlePrimaryIcon": {
                "CFBundleIconFiles": ["AndariumRoot60x60"],
            }
        }
        pl["CFBundleIcons~ipad"] = {
            "CFBundlePrimaryIcon": {
                "CFBundleIconFiles": [
                    "AndariumRoot60x60",
                    "AndariumRoot76x76",
                    "AndariumRoot83.5x83.5",
                ],
            }
        }
    return plistlib.dumps(pl, fmt=plistlib.FMT_BINARY)


def package_ipa(
    base_ipa: Path,
    output_ipa: Path,
    *,
    system_img: Path,
    layout_json_bytes: bytes,
    manifest_json_bytes: bytes,
    cmdline_bytes: bytes | None,
    bundle_id: str,
    display_name: str,
    icon_theme: str,
    preboot_defaults_bytes: bytes | None = None,
    preboot_dylib: Path | None = None,
) -> None:
    output_ipa.parent.mkdir(parents=True, exist_ok=True)
    tmp_ipa = output_ipa.with_suffix(output_ipa.suffix + ".tmp")
    if tmp_ipa.exists():
        tmp_ipa.unlink()

    icon_dir = resolve_icon_dir(icon_theme)
    use_custom_icon = icon_dir is not None
    if icon_dir is not None:
        for fn in CUSTOM_ICON_FILES:
            if not (icon_dir / fn).is_file():
                raise BuildError(f"Missing custom iOS icon asset: {icon_dir / fn}")

    if preboot_dylib is not None and not preboot_dylib.is_file():
        raise BuildError(f"Pre-boot dylib not found: {preboot_dylib}")

    log(
        f"packaging {output_ipa} (bundle_id={bundle_id}, display_name={display_name!r}, "
        f"icon_theme={icon_theme}, preboot_dylib={'yes' if preboot_dylib else 'no'})..."
    )
    t0 = time.monotonic()

    with zipfile.ZipFile(base_ipa, "r") as src_zf, zipfile.ZipFile(
        tmp_ipa, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
    ) as dst_zf:
        stock_plist = src_zf.read(IPA_INFO_PLIST)
        patched_plist = patch_info_plist(
            stock_plist,
            bundle_id,
            display_name,
            use_custom_icon=use_custom_icon,
        )

        replacements: dict[str, bytes] = {
            IPA_INFO_PLIST: patched_plist,
            IPA_LAYOUT_JSON: layout_json_bytes,
            IPA_MANIFEST_JSON: manifest_json_bytes,
        }
        if cmdline_bytes is not None:
            replacements[IPA_CMDLINE_TXT] = cmdline_bytes

        if preboot_dylib is not None:
            raw_main = src_zf.read(IPA_MAIN_MACHO)
            injected_main = macho_inject.inject_lc_load_dylib(raw_main, PREBOOT_DYLIB_LOAD_PATH)
            replacements[IPA_MAIN_MACHO] = injected_main
            log(f"  injected LC_LOAD_DYLIB ({PREBOOT_DYLIB_LOAD_PATH}) into {IPA_MAIN_MACHO}")

        ref_dt = src_zf.getinfo(IPA_INFO_PLIST).date_time

        for src_info in src_zf.infolist():
            name = src_info.filename

            if name == IPA_CODESIG_PREFIX or name.startswith(IPA_CODESIG_PREFIX):
                continue

            # Drop replaced loose DuskJade PNG icons when using custom icon set
            if use_custom_icon and name.startswith(IPA_APP_PREFIX + "DuskJade") and name.endswith(".png"):
                continue

            new_info = zipfile.ZipInfo(filename=name, date_time=src_info.date_time)
            new_info.create_system = src_info.create_system
            new_info.external_attr = src_info.external_attr
            new_info.flag_bits = src_info.flag_bits & ~0x08

            if name == IPA_SYSTEM_IMG:
                new_info.compress_type = zipfile.ZIP_STORED
                new_info.file_size = system_img.stat().st_size
                with system_img.open("rb") as f_in, dst_zf.open(new_info, "w") as f_out:
                    while chunk := f_in.read(COPY_CHUNK):
                        f_out.write(chunk)
            elif name in replacements:
                new_info.compress_type = zipfile.ZIP_DEFLATED
                dst_zf.writestr(new_info, replacements[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
            elif name.endswith("/"):
                new_info.compress_type = zipfile.ZIP_STORED
                dst_zf.writestr(new_info, b"")
            else:
                new_info.compress_type = src_info.compress_type
                with src_zf.open(src_info, "r") as f_in, dst_zf.open(new_info, "w") as f_out:
                    while chunk := f_in.read(COPY_CHUNK):
                        f_out.write(chunk)

        if icon_dir is not None:
            for fn in CUSTOM_ICON_FILES:
                icon_path = icon_dir / fn
                zi = zipfile.ZipInfo(filename=IPA_APP_PREFIX + fn, date_time=ref_dt)
                zi.create_system = 3
                zi.external_attr = 0o100644 << 16
                zi.compress_type = zipfile.ZIP_STORED  # PNG is already compressed
                dst_zf.writestr(zi, icon_path.read_bytes(), compress_type=zipfile.ZIP_STORED)

        if preboot_defaults_bytes is not None and (IOS_PREBOOT_SRC / "preboot.html").is_file():
            bdir = zipfile.ZipInfo(filename=IPA_PREBOOT_BUNDLE, date_time=ref_dt)
            bdir.create_system = 3
            bdir.external_attr = 0o040755 << 16
            bdir.compress_type = zipfile.ZIP_STORED
            dst_zf.writestr(bdir, b"")

            for fname, payload in (
                ("preboot.html", read_text_lf(IOS_PREBOOT_SRC / "preboot.html")),
                ("defaults.json", preboot_defaults_bytes),
            ):
                zi = zipfile.ZipInfo(filename=IPA_PREBOOT_BUNDLE + fname, date_time=ref_dt)
                zi.create_system = 3
                zi.external_attr = 0o100644 << 16
                zi.compress_type = zipfile.ZIP_DEFLATED
                dst_zf.writestr(zi, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
            log("  bundled AndariumRootPreboot.bundle/{preboot.html,defaults.json}")

        if preboot_dylib is not None:
            zi = zipfile.ZipInfo(filename=IPA_PREBOOT_DYLIB, date_time=ref_dt)
            zi.create_system = 3
            zi.external_attr = 0o100755 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            dst_zf.writestr(zi, preboot_dylib.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
            log(f"  bundled {IPA_PREBOOT_DYLIB} ({preboot_dylib.stat().st_size:,} B)")

    tmp_ipa.replace(output_ipa)
    elapsed = time.monotonic() - t0
    log(f"packaged IPA: {output_ipa} ({output_ipa.stat().st_size:,} B in {elapsed:.1f}s)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a customizable Andarium Root IPA (v4 Pre-Boot & Config Studio Edition)."
    )
    parser.add_argument(
        "--preset",
        choices=PRESET_NAMES,
        default=None,
        help="Role preset: mix, seceng, hacker, gamer, privacy, or unrooted",
    )
    parser.add_argument(
        "--profile",
        choices=("ultimate", "lite", "stealth"),
        default="ultimate",
        help="Legacy v3 preset alias (ultimate=mix, lite=compact core+microG, stealth=enforcing+hidden)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Declarative JSON config exported from Studio / Pre-Boot UI (overrides preset defaults)",
    )
    parser.add_argument(
        "--apps",
        default=None,
        help="Comma-separated list of app IDs to preinstall on first boot (see manifests/presets.json)",
    )
    parser.add_argument(
        "--shrink-apks",
        action="store_true",
        help="Physically omit unchecked APKs from odm.img to shrink IPA size (disables offline install of omitted apps)",
    )
    parser.add_argument(
        "--icon-theme",
        choices=ICON_THEMES,
        default=None,
        help="Custom iOS app icon theme (duskjade, crimson, cyber, stealth, or stock)",
    )
    parser.add_argument(
        "--no-root",
        action="store_true",
        help="True build-time unrooted IPA: keep stock init_boot.img untouched (no Magisk/su) while applying icons & APKs",
    )
    parser.add_argument(
        "--preboot-dylib",
        type=Path,
        default=None,
        help="Compiled arm64 iOS AndariumRootPreboot.dylib to inject into Payload/Andarium.app/Andarium",
    )
    parser.add_argument(
        "--no-preboot-dylib",
        action="store_true",
        help="Do not auto-inject assets/ios/AndariumRootPreboot.dylib even if present",
    )
    parser.add_argument("--output", type=Path, default=None, help="Output IPA path (auto-named per preset/profile if omitted)")
    parser.add_argument("--base-ipa", type=Path, help="Optional local stock Andarium IPA override (for CI / newer releases)")
    parser.add_argument("--bundle-id", default=None, help="iOS CFBundleIdentifier")
    parser.add_argument("--display-name", default=None, help="iOS CFBundleDisplayName")
    parser.add_argument("--release-suffix", default=None, help="Suffix appended to release_id")
    parser.add_argument(
        "--selinux",
        choices=("permissive", "enforcing"),
        default=None,
        help="Default boot SELinux mode",
    )
    parser.add_argument(
        "--default-stealth",
        choices=("off", "on"),
        default=None,
        help="Boot directly into Stealth Mode",
    )
    parser.add_argument("--custom-dir", type=Path, default=DEFAULT_CUSTOM_DIR, help="Drop-in custom/ overlay directory")
    parser.add_argument("--no-adbroot", action="store_true", help="Do not pre-enable /data/adbroot/enabled=1")
    parser.add_argument("--no-debuggable", action="store_true", help="Do not set ro.debuggable=1 at boot")
    parser.add_argument("--no-modules", action="store_true", help="Skip ReZygisk + Vector modules")
    parser.add_argument("--no-stealth", action="store_true", help="Skip PlayIntegrityFork + TrickyStore + Zygisk-Assistant")
    parser.add_argument("--no-pentest", action="store_true", help="Skip Frida Server, CLI pentest tools & pentest APKs")
    parser.add_argument("--no-network", action="store_true", help="Skip Dropbear SSH + StevenBlack ad-block hosts")
    parser.add_argument("--no-apps", action="store_true", help="Skip Termux + Material Files")
    parser.add_argument("--no-power-apps", action="store_true", help="Skip Aurora Store, Obtainium, App Manager, Shizuku, Neo Backup")
    parser.add_argument("--no-microg", action="store_true", help="Skip microG GmsCore + Companion")
    parser.add_argument("--no-custom-icon", action="store_true", help="Keep stock DuskJade iOS app icon")
    parser.add_argument("--keep-work", action="store_true", help="Keep temporary Linux work directory after build")
    parser.add_argument("--skip-verify", action="store_true", help="Skip automatic post-build verification")
    return parser.parse_args()


def resolve_profile(args: argparse.Namespace) -> argparse.Namespace:
    presets_doc = load_presets_manifest()
    presets = presets_doc["presets"]
    catalog = presets_doc["app_catalog"]
    all_app_ids = [item["id"] for item in catalog]

    user_cfg: dict[str, object] = {}
    if getattr(args, "config", None) is not None:
        cfg_path = Path(args.config)
        if not cfg_path.is_file():
            raise BuildError(f"--config file not found: {cfg_path}")
        user_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))

    # Determine base preset
    if args.preset is not None:
        preset_id = args.preset
    elif isinstance(user_cfg.get("preset"), str) and user_cfg["preset"] in presets:
        preset_id = str(user_cfg["preset"])
    elif args.profile == "stealth":
        preset_id = "privacy"
    else:
        preset_id = "mix"

    base = json.loads(json.dumps(presets[preset_id]))
    base["preset"] = preset_id

    # Merge declarative --config on top of preset
    for key in ("root_enabled", "selinux", "stealth", "adbroot", "debuggable", "proxy", "icon_theme", "bundle_id", "display_name", "apps", "shrink_apks", "build_unrooted"):
        if key in user_cfg and user_cfg[key] is not None:
            base[key] = user_cfg[key]
    for sub in ("modules", "services", "tweaks"):
        if isinstance(user_cfg.get(sub), dict):
            base.setdefault(sub, {}).update(user_cfg[sub])

    # Legacy --profile behaviors (only when --preset and --config weren't explicitly provided)
    using_legacy_profile = args.preset is None and not user_cfg
    if using_legacy_profile and args.profile == "lite":
        args.no_stealth = True
        args.no_pentest = True
        args.no_network = True
        args.no_power_apps = True
        base["bundle_id"] = "com.andarium.root.lite"
        base["display_name"] = "Andarium Root Lite"
        base["modules"] = {"rezygisk": True, "vector": True, "stealth_stack": False}
        base["services"] = {"adblock": False, "frida_autostart": False, "ssh_autostart": False, "shizuku_autostart": False}
        base["apps"] = ["magisk", "termux", "material_files", "microg_gms", "microg_vending"]
        default_out = ROOT_DIR / "dist" / "Andarium-Root-Lite-1.0-15.ipa"
    elif using_legacy_profile and args.profile == "stealth":
        args.no_pentest = True
        args.no_adbroot = True
        args.no_debuggable = True
        base["bundle_id"] = "com.andarium.root.stealth"
        base["display_name"] = "Andarium Stealth"
        base["selinux"] = "enforcing"
        base["stealth"] = True
        base["adbroot"] = False
        base["debuggable"] = False
        default_out = ROOT_DIR / "dist" / "Andarium-Root-Stealth-1.0-15.ipa"
    elif preset_id == "mix":
        default_out = DEFAULT_OUTPUT
    else:
        slug = preset_id.capitalize()
        default_out = ROOT_DIR / "dist" / f"Andarium-{slug}-1.0-15.ipa"

    # Build-time unrooted flag
    if base.get("build_unrooted"):
        args.no_root = True
    if args.no_root:
        base["root_enabled"] = False
        args.no_modules = True
        args.no_stealth = True
        args.no_pentest = True
        args.no_network = True
        args.no_adbroot = True
        args.no_debuggable = True

    # Apply explicit CLI overrides
    if args.selinux is not None:
        base["selinux"] = args.selinux
    if args.default_stealth is not None:
        base["stealth"] = args.default_stealth == "on"
    if args.no_adbroot:
        base["adbroot"] = False
    if args.no_debuggable:
        base["debuggable"] = False
    if args.no_modules:
        base["modules"]["rezygisk"] = False
        base["modules"]["vector"] = False
    if args.no_stealth:
        base["modules"]["stealth_stack"] = False
    if args.no_network:
        base["services"]["adblock"] = False
        base["services"]["ssh_autostart"] = False
    if args.no_pentest:
        base["services"]["frida_autostart"] = False

    if args.apps is not None:
        chosen = [a.strip() for a in args.apps.split(",") if a.strip()]
        invalid = [a for a in chosen if a not in all_app_ids]
        if invalid:
            raise BuildError(f"Unknown app id(s) in --apps: {', '.join(invalid)}")
        base["apps"] = chosen

    if base.get("shrink_apks"):
        args.shrink_apks = True

    if args.no_custom_icon:
        icon_theme = "stock"
    elif args.icon_theme is not None:
        icon_theme = args.icon_theme
    else:
        icon_theme = str(base.get("icon_theme", "duskjade"))
        if icon_theme not in ICON_THEMES:
            icon_theme = "duskjade"

    args.icon_theme = icon_theme
    args.no_custom_icon = icon_theme == "stock"
    args.output = args.output or default_out
    args.bundle_id = args.bundle_id or str(base.get("bundle_id", "com.andarium.root"))
    args.display_name = args.display_name or str(base.get("display_name", "Andarium Root"))
    args.selinux = str(base.get("selinux", "permissive"))
    args.default_stealth = "on" if base.get("stealth", False) else "off"
    args.no_adbroot = not bool(base.get("adbroot", True))
    args.no_debuggable = not bool(base.get("debuggable", True))
    args.release_suffix = args.release_suffix or ("clean" if args.no_root else "root")
    args.effective_preset = preset_id
    args.effective_config = base
    args.presets_doc = presets_doc

    # Auto-detect compiled iOS pre-boot dylib if present and not disabled
    if not args.no_root and not args.no_preboot_dylib and args.preboot_dylib is None:
        if DEFAULT_PREBOOT_DYLIB.is_file():
            args.preboot_dylib = DEFAULT_PREBOOT_DYLIB
    if args.no_root or args.no_preboot_dylib:
        args.preboot_dylib = None

    return args


def main() -> int:
    args = resolve_profile(parse_args())
    check_host_tools()
    log(
        f"Preset={args.effective_preset} | Profile={args.profile} | BuildRoot={'NO (--no-root)' if args.no_root else 'YES'} | "
        f"DefaultRoot={'ON' if args.effective_config.get('root_enabled', True) else 'HIDDEN'} | "
        f"SELinux={args.selinux} | Stealth={args.default_stealth} | Icon={args.icon_theme} | BundleID={args.bundle_id}"
    )

    artifacts = json.loads((MANIFESTS_DIR / "artifacts.json").read_text(encoding="utf-8"))

    log("=== Step 1/7: Verifying upstream artifacts ===")
    if args.base_ipa is not None:
        base_ipa = args.base_ipa.resolve()
        if not base_ipa.is_file():
            raise BuildError(f"--base-ipa not found: {base_ipa}")
        log(f"using override base IPA: {base_ipa} ({base_ipa.stat().st_size:,} B)")
    else:
        base_ipa = ensure_artifact(artifacts["base_ipa"], CACHE_DIR)

    magisk_apk = None if args.no_root else ensure_artifact(artifacts["magisk"], CACHE_DIR)

    rezygisk_zip = None if (args.no_root or args.no_modules) else ensure_artifact(artifacts["modules"]["rezygisk"], CACHE_DIR)
    vector_zip = None if (args.no_root or args.no_modules) else ensure_artifact(artifacts["modules"]["vector"], CACHE_DIR)
    pif_zip = None if (args.no_root or args.no_stealth) else ensure_artifact(artifacts["modules"]["playintegrityfork"], CACHE_DIR)
    trickystore_zip = None if (args.no_root or args.no_stealth) else ensure_artifact(artifacts["modules"]["trickystore"], CACHE_DIR)
    zygisk_assistant_zip = None if (args.no_root or args.no_stealth) else ensure_artifact(artifacts["modules"]["zygisk_assistant"], CACHE_DIR)

    frida_xz = None if (args.no_root or args.no_pentest) else ensure_artifact(artifacts["tools"]["frida_server"], CACHE_DIR)
    dropbear_zip = None if (args.no_root or args.no_network) else ensure_artifact(artifacts["tools"]["dropbear"], CACHE_DIR)
    hosts_txt = None if (args.no_root or args.no_network) else ensure_artifact(artifacts["tools"]["stevenblack_hosts"], CACHE_DIR)

    cli_tools: dict[str, Path] = {}
    if not args.no_root and not args.no_pentest:
        for tname in ("strace", "socat", "sqlite3", "jq", "tcpdump"):
            cli_tools[tname] = ensure_artifact(artifacts["tools"][tname], CACHE_DIR)

    apk_groups_enabled = {
        "apps": not args.no_apps,
        "microg": not args.no_microg,
        "power_apps": not args.no_power_apps,
        "pentest": (not args.no_pentest) and (not args.no_root),
    }
    selected_app_ids = set(args.effective_config.get("apps") or [])
    extra_apks: list[tuple[str, Path]] = []
    staged_apk_names: list[str] = [] if args.no_root else ["01-magisk.apk"]
    for app_key, entry in artifacts["apks"].items():
        if args.no_root or args.shrink_apks:
            if app_key not in selected_app_ids:
                continue
        else:
            if not apk_groups_enabled.get(str(entry["group"]), False):
                continue
        extra_apks.append((str(entry["install_name"]), ensure_artifact(entry, CACHE_DIR)))
        staged_apk_names.append(str(entry["install_name"]))

    work_dir = Path(tempfile.mkdtemp(prefix="andarium_root_build_"))
    log(f"Linux staging directory: {work_dir}")
    try:
        log("=== Step 2/7: Unpacking stock GPT partitions ===")
        _stock_layout, stock_manifest, part_paths = extract_stock_partitions(base_ipa, work_dir)
        part_dir = work_dir / "partitions"

        stock_init_boot_copy = work_dir / "stock_init_boot.img"
        shutil.copy2(part_paths["init_boot"], stock_init_boot_copy)

        if args.no_root:
            log("=== Step 3/7: Skipping init_boot.img patch (--no-root: keeping stock init_boot untouched) ===")
        else:
            log("=== Step 3/7: Patching init_boot.img with Magisk v31.1 ===")
            patched_init_boot = work_dir / "patched_init_boot.img"
            assert magisk_apk is not None
            patch_init_boot(
                stock_init_boot_copy,
                magisk_apk,
                patched_init_boot,
                work_dir,
                selinux_mode=args.selinux,
                enable_debuggable=not args.no_debuggable,
                enable_adbroot=not args.no_adbroot,
                default_stealth=args.default_stealth,
            )
            shutil.copy2(patched_init_boot, part_paths["init_boot"])

        log("=== Step 4/7: Building augmented odm.img EROFS ===")
        stock_odm_copy = work_dir / "stock_odm.img"
        shutil.copy2(part_paths["odm"], stock_odm_copy)
        patched_odm = work_dir / "patched_odm.img"
        build_odm_image(
            stock_odm_copy,
            patched_odm,
            work_dir,
            magisk_apk=magisk_apk,
            rezygisk_zip=rezygisk_zip,
            vector_zip=vector_zip,
            pif_zip=pif_zip,
            trickystore_zip=trickystore_zip,
            zygisk_assistant_zip=zygisk_assistant_zip,
            frida_xz=frida_xz,
            dropbear_zip=dropbear_zip,
            hosts_txt=hosts_txt,
            cli_tools=cli_tools,
            extra_apks=extra_apks,
            custom_dir=args.custom_dir.resolve(),
            selinux_mode=args.selinux,
            enable_debuggable=not args.no_debuggable,
            default_stealth=args.default_stealth,
            build_unrooted=args.no_root,
            effective_config=args.effective_config,
        )
        shutil.copy2(patched_odm, part_paths["odm"])

        log("=== Step 5/7: Rebuilding exact-fit GPT system.img ===")
        disk_out_dir = work_dir / "assembled_disk"
        system_img, layout_json_path = assemble_system_disk(part_dir, disk_out_dir)

        log("=== Step 6/7: Packaging final IPA ===")
        with zipfile.ZipFile(base_ipa, "r") as zf:
            stock_cmdline = zf.read(IPA_CMDLINE_TXT)

        cmdline_bytes: bytes | None = None
        preboot_defaults_bytes: bytes | None = None
        if not args.no_root:
            cmdline_bytes = encode_preboot_cmdline(
                stock_cmdline,
                args.effective_config,
                args.presets_doc["app_catalog"],
            )
            defaults_payload = {
                "schema_version": 4,
                "app_catalog": args.presets_doc["app_catalog"],
                "presets": args.presets_doc["presets"],
                "default_config": args.effective_config,
            }
            preboot_defaults_bytes = (json.dumps(defaults_payload, indent=2) + "\n").encode("utf-8")

        layout_json_bytes = layout_json_path.read_bytes()
        manifest_json_bytes = update_release_manifest(
            stock_manifest,
            system_img.stat().st_size,
            len(layout_json_bytes),
            release_suffix=args.release_suffix,
            cmdline_size=len(cmdline_bytes) if cmdline_bytes is not None else None,
        )

        output_ipa = args.output.resolve()
        package_ipa(
            base_ipa,
            output_ipa,
            system_img=system_img,
            layout_json_bytes=layout_json_bytes,
            manifest_json_bytes=manifest_json_bytes,
            cmdline_bytes=cmdline_bytes,
            bundle_id=args.bundle_id,
            display_name=args.display_name,
            icon_theme=args.icon_theme,
            preboot_defaults_bytes=preboot_defaults_bytes,
            preboot_dylib=args.preboot_dylib,
        )

        if not args.skip_verify:
            log("=== Step 7/7: Running independent IPA verification ===")
            verify_cmd = [
                sys.executable,
                str(SCRIPTS_DIR / "verify_rooted_ipa.py"),
                "--ipa",
                str(output_ipa),
                "--base-ipa",
                str(base_ipa),
                "--expected-bundle-id",
                args.bundle_id,
                "--expected-display-name",
                args.display_name,
                "--expected-selinux",
                args.selinux,
                "--expected-apks",
                ",".join(staged_apk_names),
            ]
            for flag_name, flag_val in (
                ("--no-root", args.no_root),
                ("--expect-preboot-dylib", args.preboot_dylib is not None),
                ("--no-modules", args.no_modules),
                ("--no-stealth", args.no_stealth),
                ("--no-pentest", args.no_pentest),
                ("--no-network", args.no_network),
                ("--no-apps", args.no_apps),
                ("--no-power-apps", args.no_power_apps),
                ("--no-microg", args.no_microg),
                ("--no-custom-icon", args.no_custom_icon),
            ):
                if flag_val:
                    verify_cmd.append(flag_name)
            v_res = subprocess.run(verify_cmd)
            if v_res.returncode != 0:
                raise BuildError(f"Post-build verification failed (rc={v_res.returncode})")

        ipa_sha = sha256_file(output_ipa)
        log("============================================================")
        log(f"SUCCESS: {output_ipa}")
        log(f"Size:    {output_ipa.stat().st_size:,} bytes ({output_ipa.stat().st_size / (1024**3):.2f} GiB)")
        log(f"SHA-256: {ipa_sha}")
        log("============================================================")
        return 0
    finally:
        if args.keep_work:
            log(f"keeping temporary work directory: {work_dir}")
        else:
            shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as exc:
        print(f"[build] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
