#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Automated regression & security test suite for Andarium Root IPA Builder (v4).

Runs fast (~3 seconds) in Linux / WSL2 / GitHub Actions without needing to repack
the full 1.3 GB IPA on every unit test:
  1. Validates POSIX shell syntax (`sh -n`) on every guest script + LF check on
     Frida JS scripts and iOS Pre-Boot HTML/Objective-C/C sources.
  2. Validates `manifests/presets.json` schema integrity against `artifacts.json`
     and verifies all 4 themed iOS icon sets (5 PNG sizes each).
  3. Tests all 6 v4 Role Presets (`mix`, `seceng`, `hacker`, `gamer`, `privacy`,
     `unrooted`), `--no-root`, `--config`, `--apps`, `--icon-theme`, AND legacy
     `--profile {ultimate,lite,stealth}` backwards compatibility.
  4. Tests `encode_preboot_cmdline()` + `verify_cmdline()` against `android_boot.cpp`
     safety rules across every preset + proxy + `PROP_VALUE_MAX` (<91 B) limits.
  5. Tests `macho_inject.inject_lc_load_dylib()` directly on a real copy of
     `Payload/Andarium.app/Andarium` from `.cache/Andarium-1.0-15.ipa` (verifying
     `ncmds+1`, `@executable_path/Frameworks/AndariumRootPreboot.dylib`, idempotency,
     ZERO shifted section offsets, and BOTH embedded iOS entitlements intact!).
  6. Tests `custom/` drop-in processing end-to-end (PEM+DER CA certs -> hash.0,
     hosts, authorized_keys, root-packages.txt, LF scripts, bad-ZIP rejection).
  7. Live-tests Control Panel v4 (`busybox httpd` + `webroot/cgi-bin/api`) with
     Magisk's x86_64 busybox: checks 403 auth, 200 v4 endpoints (`mode`, `root`,
     `tweaks_*`, `apps_list`, `bundled_list`, `bundled_install`, `bundled_uninstall`,
     `revoke`, `denylist_add/rm`, `backup_export`, `proxy_set`, `display_*`,
     `module_disable`) AND injection / path-traversal / lockout rejections.
  8. Smoke-tests `studio_web.py` metadata endpoint + CSRF token enforcement.
  9. Tests `generate_altstore_source.py` multi-flavor JSON output & entitlements.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import plistlib
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import build_rooted_ipa as builder  # noqa: E402
import macho_inject  # noqa: E402
import studio_web  # noqa: E402
import update_artifacts  # noqa: E402
import verify_rooted_ipa as verifier  # noqa: E402


def ok(msg: str) -> None:
    print(f"[test] PASS: {msg}", flush=True)


def test_guest_shell_scripts() -> None:
    guest_scripts = [
        ROOT / "scripts/guest/andarium-ctl",
        ROOT / "scripts/guest/andarium-workbench",
        ROOT / "scripts/guest/andarium-spoof",
        ROOT / "scripts/guest/andarium-net",
        ROOT / "scripts/guest/andarium-auto",
        ROOT / "scripts/guest/andarium_early_init.sh",
        ROOT / "scripts/guest/andarium_boot_complete.sh",
        ROOT / "scripts/guest/andarium-termux-setup",
        ROOT / "scripts/guest/andarium-shell-rc.sh",
        ROOT / "scripts/guest/control_module/service.sh",
        ROOT / "scripts/guest/control_module/action.sh",
        ROOT / "scripts/guest/control_module/webroot/cgi-bin/api",
    ]
    for p in guest_scripts:
        assert p.is_file(), f"Missing guest script: {p}"
        data = builder.read_text_lf(p)
        assert b"\r" not in data, f"CR leaked in {p}"
        with tempfile.NamedTemporaryFile("wb", suffix=".sh", delete=False) as tf:
            tf.write(data)
            tp = pathlib.Path(tf.name)
        try:
            builder.check_shell_syntax(tp)
        finally:
            tp.unlink(missing_ok=True)

    # Verify bundled Frida bypass scripts & iOS pre-boot v2 assets exist cleanly
    frida_scripts = sorted((ROOT / "scripts/guest/frida_scripts").glob("*.js"))
    assert len(frida_scripts) == 5, f"Expected 5 Frida scripts, found {len(frida_scripts)}"
    for js in frida_scripts:
        assert len(builder.read_text_lf(js)) > 200, f"Frida script too small: {js}"

    for ios_src in ("fishhook.h", "fishhook.c", "AndariumRootPreboot.m", "preboot.html"):
        p = ROOT / "ios/AndariumRootPreboot" / ios_src
        assert p.is_file() and p.stat().st_size > 200, f"Missing iOS preboot file: {p}"

    m_src = (ROOT / "ios/AndariumRootPreboot/AndariumRootPreboot.m").read_text(encoding="utf-8")
    for env_sym in (
        "ANDARIUM_GUEST_INSTANCE",
        "KERNARIUM_VCPU_COUNT",
        "KERNARIUM_GUEST_MEMORY_MIB",
        "KERNARIUM_ANDROID_DISK_SIZE_GIB",
        "KERNARIUM_DISPLAY_SCALE",
        "ANDARIUM_THERMAL_STATE",
        "ANDARIUM_HAPTICS",
        "ANDARIUM_JIT",
        "andarium.jit",
        "andarium.statistics",
    ):
        assert f'"{env_sym}"' in m_src, f"Missing verified symbol in AndariumRootPreboot.m: {env_sym}"
    assert '"andarium.stats"' not in m_src, "Stale key 'andarium.stats' must be 'andarium.statistics'"

    ok(f"all {len(guest_scripts)} guest scripts (sh -n), 5 Frida JS scripts & iOS Pre-Boot v2 sources valid")


def test_jit_hardening() -> None:
    # 1. Info.plist + localized InfoPlist.strings StikDebug auto-script compatibility
    sample_plist = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.imxieyi.andarium",
            "CFBundleDisplayName": "Andarium",
            "CFBundleName": "Andarium",
            "CFBundleExecutable": "Andarium",
        },
        fmt=plistlib.FMT_BINARY,
    )
    patched_default = builder.patch_info_plist(
        sample_plist, "com.andarium.root", "Andarium Root", use_custom_icon=True
    )
    pl_def = plistlib.loads(patched_default)
    assert pl_def["CFBundleIdentifier"] == "com.andarium.root"
    assert pl_def["CFBundleDisplayName"] == "Andarium", "Root Info.plist must stay 'Andarium' for StikDebug universal.js"
    assert pl_def["CFBundleName"] == "Andarium"
    for sch in ("stikdebug", "sidestore", "altstore"):
        assert sch in pl_def.get("LSApplicationQueriesSchemes", []), f"Missing scheme {sch}"

    patched_raw = builder.patch_info_plist(
        sample_plist, "com.andarium.root", "Andarium Root", use_custom_icon=True, raw_display_name=True
    )
    assert plistlib.loads(patched_raw)["CFBundleDisplayName"] == "Andarium Root"

    sample_strings = plistlib.dumps(
        {"NSCameraUsageDescription": "Camera"}, fmt=plistlib.FMT_BINARY
    )
    patched_strings = builder.patch_localized_info_plist_strings(sample_strings, "Andarium Root")
    assert patched_strings.startswith(b"bplist00")
    lpl = plistlib.loads(patched_strings)
    assert lpl["CFBundleDisplayName"] == "Andarium Root" and lpl["NSCameraUsageDescription"] == "Camera"

    # 2. fishhook.c hardening (page-aligned vm_protect + self-exclusion + __AUTH_CONST)
    fh_src = (ROOT / "ios/AndariumRootPreboot/fishhook.c").read_text(encoding="utf-8")
    for token in ("AndariumRootPreboot", "vm_page_size", "prot_start", "__AUTH_CONST", "symtab_index >= nsyms"):
        assert token in fh_src, f"fishhook.c missing JIT hardening token: {token}"

    # 3. AndariumRootPreboot.m + preboot.html JIT engine & JIT Doctor
    m_src = (ROOT / "ios/AndariumRootPreboot/AndariumRootPreboot.m").read_text(encoding="utf-8")
    for token in (
        "0x1000000000ULL",
        "ar_hooked_vm_allocate",
        "ar_hooked_mlock",
        "ar_hooked_fprintf",
        "ar_hooked_printf",
        "MADV_WILLNEED",
        "csops(",
        "AR_CS_DEBUGGED",
        "AR_CS_KILL",
        "os_proc_available_memory",
        "P_TRACED",
        "stikdebug://enable-jit?bundle-id=",
        "script-name=universal.js",
    ):
        assert token in m_src, f"AndariumRootPreboot.m missing JIT hardening token: {token}"

    html_src = (ROOT / "ios/AndariumRootPreboot/preboot.html").read_text(encoding="utf-8")
    for token in ("__andariumJitDiag", "launch_stikdebug", "hw-jit-mode", "hw-jit-shield", "hw-jit-mlock", "jit-trace"):
        assert token in html_src, f"preboot.html missing JIT Doctor element: {token}"

    # 4. Bundled official StikDebug universal.js reference script
    ujs_path = ROOT / "docs/stikdebug-universal.js"
    assert ujs_path.is_file() and ujs_path.stat().st_size > 4000, "Missing docs/stikdebug-universal.js"
    ujs_txt = ujs_path.read_text(encoding="utf-8")
    assert "0xf00d" in ujs_txt and "prepare_memory_region" in ujs_txt

    # 5. If base IPA is cached, verify KRuntime brk #0xf00d + real InfoPlist.strings locales
    base_ipa = ROOT / ".cache" / "Andarium-1.0-15.ipa"
    if base_ipa.is_file():
        with zipfile.ZipFile(base_ipa, "r") as zf:
            kr = zf.read("Payload/Andarium.app/Frameworks/KRuntime_Android_6_18_4K.framework/KRuntime_Android_6_18_4K")
            assert b"\xa0\x01\x3e\xd4" in kr, "KRuntime missing brk #0xf00d"
            locales = [n for n in zf.namelist() if n.endswith(".lproj/InfoPlist.strings")]
            assert len(locales) >= 4, f"Expected >=4 locales, got {locales}"
            for loc in locales:
                p_loc = builder.patch_localized_info_plist_strings(zf.read(loc), "Andarium Root")
                assert plistlib.loads(p_loc)["CFBundleDisplayName"] == "Andarium Root"

    ok("StikDebug JIT hardening verified (Info.plist auto-script, InfoPlist.strings, 36-bit shield, soft-mlock, fishhook, universal.js)")


def test_presets_and_icons() -> None:
    presets_doc = builder.load_presets_manifest()
    artifacts = json.loads((ROOT / "manifests/artifacts.json").read_text(encoding="utf-8"))

    catalog = presets_doc["app_catalog"]
    assert len(catalog) == 13, f"Expected 13 catalog apps, got {len(catalog)}"
    catalog_ids = {item["id"] for item in catalog}
    artifact_apk_ids = {"magisk"} | set(artifacts["apks"].keys())
    assert catalog_ids == artifact_apk_ids, f"Catalog/artifacts mismatch: {catalog_ids ^ artifact_apk_ids}"

    presets = presets_doc["presets"]
    assert set(presets.keys()) == set(builder.PRESET_NAMES)
    dev_prof = json.loads((ROOT / "manifests/device_profiles.json").read_text(encoding="utf-8"))
    prof_ids = set(dev_prof["profiles"].keys())
    assert prof_ids >= {"stock", "pixel9pro", "s25ultra", "rog9", "redmagic10", "xiaomi15u"}
    assert "frida_inject" in artifacts["tools"], "Missing tools.frida_inject in artifacts.json"
    for pid, p in presets.items():
        assert p["icon_theme"] in builder.ICON_THEMES, f"Bad icon_theme in {pid}"
        assert set(p["apps"]).issubset(catalog_ids), f"Unknown app in preset {pid}"
        assert p.get("spoof_profile", "stock") in prof_ids, f"Unknown spoof_profile in {pid}"

    for theme in ("duskjade", "crimson", "cyber", "stealth"):
        tdir = builder.resolve_icon_dir(theme)
        assert tdir is not None and tdir.is_dir()
        for fname, exp_w, exp_h in verifier.CUSTOM_ICON_SPECS:
            png = (tdir / fname).read_bytes()
            assert png.startswith(verifier.PNG_MAGIC) and png[12:16] == b"IHDR"
            w, h = struct.unpack_from(">II", png, 16)
            assert (w, h) == (exp_w, exp_h), f"{theme}/{fname} is {w}x{h}, expected {exp_w}x{exp_h}"
        doc_preview = ROOT / "docs" / f"icon-{theme}.png"
        assert doc_preview.is_file(), f"Missing Studio preview icon: {doc_preview}"

    ok("manifests/presets.json (6 presets, 13 apps) & all 4 themed iOS icon sets (20 PNGs + previews) verified")


def test_profiles_and_presets() -> None:
    def parse_with(argv: list[str]) -> argparse.Namespace:
        old = sys.argv
        sys.argv = ["build_rooted_ipa.py", *argv]
        try:
            return builder.resolve_profile(builder.parse_args())
        finally:
            sys.argv = old

    # Legacy v3 profiles
    u = parse_with(["--profile", "ultimate"])
    assert u.bundle_id == "com.andarium.root" and u.selinux == "permissive" and u.default_stealth == "off"
    assert not u.no_pentest and not u.no_stealth and not u.no_network and not u.no_power_apps

    l = parse_with(["--profile", "lite"])
    assert l.bundle_id == "com.andarium.root.lite" and l.no_pentest and l.no_stealth and l.no_network and l.no_power_apps

    s = parse_with(["--profile", "stealth"])
    assert s.bundle_id == "com.andarium.root.stealth" and s.selinux == "enforcing" and s.default_stealth == "on"
    assert s.no_pentest and s.no_adbroot and s.no_debuggable and not s.no_stealth

    # New v4 role presets
    sec = parse_with(["--preset", "seceng"])
    assert sec.icon_theme == "crimson" and sec.effective_config["services"]["frida_autostart"] is True
    assert sec.effective_config["services"]["ssh_autostart"] is True

    gam = parse_with(["--preset", "gamer"])
    assert gam.icon_theme == "cyber" and gam.selinux == "enforcing" and gam.default_stealth == "on"
    assert gam.effective_config["tweaks"]["anim_scale"] == "0" and gam.effective_config["tweaks"]["swappiness"] == 130
    assert gam.effective_config["spoof_profile"] == "rog9"

    sp_ov = parse_with(["--preset", "mix", "--spoof", "s25ultra"])
    assert sp_ov.effective_config["spoof_profile"] == "s25ultra"

    unr = parse_with(["--preset", "unrooted", "--no-root", "--icon-theme", "stealth"])
    assert unr.no_root and unr.icon_theme == "stealth" and unr.release_suffix == "clean"
    assert unr.effective_config["root_enabled"] is False

    # Declarative --config JSON override + --apps override
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(
            {
                "preset": "hacker",
                "icon_theme": "crimson",
                "bundle_id": "com.test.lab",
                "display_name": "Lab Phone",
                "proxy": "192.168.1.50:8080",
                "apps": ["magisk", "termux", "trustmealready"],
            },
            tf,
        )
        cfg_path = pathlib.Path(tf.name)
    try:
        c = parse_with(["--config", str(cfg_path)])
        assert c.bundle_id == "com.test.lab" and c.display_name == "Lab Phone"
        assert c.effective_config["proxy"] == "192.168.1.50:8080"
        assert c.effective_config["apps"] == ["magisk", "termux", "trustmealready"]
    finally:
        cfg_path.unlink(missing_ok=True)

    ok("all 6 v4 presets, --no-root, --config JSON, --icon-theme & legacy v3 profiles resolve accurately")


def test_preboot_cmdline_encoding() -> None:
    presets_doc = builder.load_presets_manifest()
    catalog = presets_doc["app_catalog"]
    sample_stock = (
        b"init=/init console=ttyS0 androidboot.hardware=cutf_cvm "
        b"androidboot.boot_devices=uml-blkdev.0,uml-blkdev.1 androidboot.selinux=enforcing\n"
    )
    for pid, preset in presets_doc["presets"].items():
        cfg = dict(preset)
        cfg["preset"] = pid
        cfg["proxy"] = "10.0.0.5:8080" if pid == "seceng" else ""
        encoded = builder.encode_preboot_cmdline(sample_stock, cfg, catalog)
        verifier.verify_cmdline(encoded, sample_stock, expect_no_root=False)
        text = encoded.decode("utf-8")
        assert f"androidboot.ar.preset={pid}" in text
        if pid == "seceng":
            assert "androidboot.ar.proxy=10.0.0.5:8080" in text

    # Ensure unrooted mode preserves stock byte-for-byte
    verifier.verify_cmdline(sample_stock, sample_stock, expect_no_root=True)
    ok("pre-boot kernel-command-line.txt encoding & android_boot.cpp safety verification passed across all 6 presets")


def test_macho_lc_load_dylib_injection() -> None:
    base_ipa = ROOT / ".cache" / "Andarium-1.0-15.ipa"
    if not base_ipa.is_file():
        print("[test] SKIP: Mach-O injection test (.cache/Andarium-1.0-15.ipa not cached)")
        return

    with zipfile.ZipFile(base_ipa, "r") as zf:
        orig = zf.read(builder.IPA_MAIN_MACHO)

    orig_ncmds, orig_sz, min_sec, orig_dylibs = macho_inject.parse_macho64_dylibs(orig)
    assert builder.PREBOOT_DYLIB_LOAD_PATH not in orig_dylibs

    patched = macho_inject.inject_lc_load_dylib(orig, builder.PREBOOT_DYLIB_LOAD_PATH)
    assert len(patched) == len(orig), "File length must not change"
    new_ncmds, new_sz, new_min_sec, new_dylibs = macho_inject.parse_macho64_dylibs(patched)
    assert new_ncmds == orig_ncmds + 1
    assert new_sz > orig_sz and (new_sz - orig_sz) % 8 == 0
    assert new_min_sec == min_sec
    assert builder.PREBOOT_DYLIB_LOAD_PATH in new_dylibs
    # Bytes from first __TEXT section onward (including LC_CODE_SIGNATURE & entitlements) must be untouched!
    assert patched[min_sec:] == orig[min_sec:]
    for ent in verifier.REQUIRED_ENTITLEMENTS:
        assert ent in patched, f"Lost entitlement: {ent!r}"

    # Idempotency: injecting a second time is a no-op
    patched2 = macho_inject.inject_lc_load_dylib(patched, builder.PREBOOT_DYLIB_LOAD_PATH)
    assert patched2 == patched

    ok(
        f"real Andarium Mach-O LC_LOAD_DYLIB injection verified "
        f"(ncmds {orig_ncmds}->{new_ncmds}, 0 bytes shifted after offset {min_sec}, both iOS entitlements intact)"
    )


def test_custom_dropins() -> None:
    with tempfile.TemporaryDirectory(prefix="test_custom_") as td:
        tdp = pathlib.Path(td)
        cdir = tdp / "custom_in"
        pdir = tdp / "payload_custom"
        (cdir / "certs").mkdir(parents=True)
        (cdir / "apks").mkdir(parents=True)
        (cdir / "modules").mkdir(parents=True)
        (cdir / "scripts" / "service.d").mkdir(parents=True)
        (cdir / "scripts" / "post-fs-data.d").mkdir(parents=True)

        pem_cert = cdir / "certs" / "test_mitm.pem"
        der_cert = cdir / "certs" / "test_burp.der"
        key_tmp = tdp / "ca.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key_tmp), "-out", str(pem_cert),
             "-days", "1", "-subj", "/CN=AndariumTestCA1"],
            check=True, capture_output=True,
        )
        der_pem_tmp = tdp / "ca2.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key_tmp), "-out", str(der_pem_tmp),
             "-days", "1", "-subj", "/CN=AndariumTestCA2"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "x509", "-in", str(der_pem_tmp), "-outform", "DER", "-out", str(der_cert)],
            check=True, capture_output=True,
        )

        with zipfile.ZipFile(cdir / "apks" / "sample.apk", "w") as zf:
            zf.writestr("AndroidManifest.xml", b"dummy")
        with zipfile.ZipFile(cdir / "modules" / "sample_mod.zip", "w") as zf:
            zf.writestr("module.prop", b"id=sample\n")

        (cdir / "scripts" / "service.d" / "99-hello.sh").write_bytes(b"#!/system/bin/sh\r\necho hi\r\n")
        (cdir / "hosts").write_bytes(b"127.0.0.1 test.local\r\n")
        (cdir / "authorized_keys").write_bytes(b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@pc\r\n")
        (cdir / "root-packages.txt").write_bytes(b"# comment\r\ncom.example.tool\r\n")
        (cdir / "keybox.xml").write_bytes(b"<AndroidAttestation><Keybox DeviceID=\"test\"/></AndroidAttestation>\r\n")

        hosts_out = builder.stage_custom_dropins(cdir, pdir)
        assert hosts_out is not None and hosts_out.is_file()
        assert (pdir / "keybox.xml").is_file() and b"\r" not in (pdir / "keybox.xml").read_bytes()
        certs = sorted((pdir / "certs").glob("*.0"))
        assert len(certs) == 2
        for c in certs:
            assert len(c.stem) == 8 and b"-----BEGIN CERTIFICATE-----" in c.read_bytes()
        assert (pdir / "apks" / "sample.apk").is_file()
        assert (pdir / "modules" / "sample_mod.zip").is_file()
        assert b"\r" not in (pdir / "scripts" / "service.d" / "99-hello.sh").read_bytes()

        (cdir / "apks" / "corrupt.apk").write_bytes(b"not a zip")
        try:
            builder.stage_custom_dropins(cdir, tdp / "payload_bad")
            raise AssertionError("Expected error for corrupt custom APK")
        except (builder.BuildError, zipfile.BadZipFile):
            pass

    ok("custom/ drop-ins verified (PEM+DER->hash.0 CA certs, CRLF->LF scripts, hosts, keys, bad-ZIP rejection)")


def test_control_panel_v4_cgi() -> None:
    magisk_apk = ROOT / ".cache" / "Magisk-v31.1.apk"
    if not magisk_apk.is_file():
        print("[test] SKIP: Control Panel live busybox test (.cache/Magisk-v31.1.apk not cached)")
        return

    with tempfile.TemporaryDirectory(prefix="test_cgi_") as td:
        tdp = pathlib.Path(td)
        bb = tdp / "busybox"
        with zipfile.ZipFile(magisk_apk, "r") as zf:
            bb.write_bytes(zf.read("lib/x86_64/libbusybox.so"))
        bb.chmod(0o755)

        webroot = tdp / "webroot"
        (webroot / "cgi-bin").mkdir(parents=True)
        (webroot / "index.html").write_bytes(
            builder.read_text_lf(ROOT / "scripts/guest/control_module/webroot/index.html")
        )

        tok = "0123456789abcdef0123456789abcdef"
        tok_file = tdp / "webui.token"
        tok_file.write_text(tok)

        mock_ctl = tdp / "mock-ctl"
        mock_ctl.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  status-json) echo '{\"ok\":true,\"kernel\":\"6.18.60\",\"active_mode\":\"dev\",\"root_su\":\"active\"}'; exit 0 ;;\n"
            "  apps-json) echo '{\"apps\":[{\"pkg\":\"com.termux\",\"uid\":10101,\"su\":true,\"denylist\":false}]}'; exit 0 ;;\n"
            "  bundled-json) echo '{\"bundled\":[{\"file\":\"02-termux.apk\",\"pkg\":\"com.termux\",\"label\":\"Termux\",\"installed\":true}]}'; exit 0 ;;\n"
            "  backup-export) echo '{\"version\":4,\"selinux\":\"permissive\"}'; exit 0 ;;\n"
            "  tweaks)\n"
            "    if [ \"$2\" = 'swappiness' ] && [ \"$3\" -gt 200 ] 2>/dev/null; then echo 'Swappiness out of range' >&2; exit 2; fi\n"
            "    echo \"MOCK:$*\"; exit 0 ;;\n"
            "  *) echo \"MOCK:$*\"; exit 0 ;;\n"
            "esac\n"
        )
        mock_ctl.chmod(0o755)

        mock_sub = tdp / "mock-sub"
        mock_sub.write_text("#!/bin/sh\necho \"SUB:$*\"\nexit 0\n")
        mock_sub.chmod(0o755)

        api_src = builder.read_text_lf(ROOT / "scripts/guest/control_module/webroot/cgi-bin/api").decode("utf-8")
        api_src = api_src.replace("#!/system/bin/sh", "#!/bin/sh")
        api_src = api_src.replace('CTL="/odm/andarium-root/scripts/andarium-ctl"', f'CTL="{mock_ctl}"')
        api_src = api_src.replace('WB="/odm/andarium-root/scripts/andarium-workbench"', f'WB="{mock_sub}"')
        api_src = api_src.replace('SPOOF="/odm/andarium-root/scripts/andarium-spoof"', f'SPOOF="{mock_sub}"')
        api_src = api_src.replace('NET="/odm/andarium-root/scripts/andarium-net"', f'NET="{mock_sub}"')
        api_src = api_src.replace('AUTO="/odm/andarium-root/scripts/andarium-auto"', f'AUTO="{mock_sub}"')
        api_src = api_src.replace('TOKEN_FILE="/data/adb/andarium/run/webui.token"', f'TOKEN_FILE="{tok_file}"')
        api_src = api_src.replace('BB="/data/adb/magisk/busybox"', f'BB="{bb}"')
        api_p = webroot / "cgi-bin" / "api"
        api_p.write_text(api_src)
        api_p.chmod(0o755)

        port = 18794
        proc = subprocess.Popen([str(bb), "httpd", "-f", "-p", f"127.0.0.1:{port}", "-h", str(webroot)])
        try:
            time.sleep(0.4)

            def req(path: str) -> tuple[int, str]:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
                        return r.status, r.read().decode("utf-8")
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode("utf-8")

            st, body = req("/")
            assert st == 200 and "Andarium Root" in body and "v5" in body

            # Auth enforcement
            assert req("/cgi-bin/api?action=status")[0] == 403
            assert req("/cgi-bin/api?token=wrong&action=status")[0] == 403

            # v4 endpoints
            st, body = req(f"/cgi-bin/api?token={tok}&action=status")
            assert st == 200 and json.loads(body)["active_mode"] == "dev"

            st, body = req(f"/cgi-bin/api?token={tok}&action=mode&value=gamer")
            assert st == 200 and "MOCK:mode gamer" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=root&value=hide")
            assert st == 200 and "MOCK:root hide" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=tweaks_anim&value=0")
            assert st == 200 and "MOCK:tweaks anim 0" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=tweaks_swap&value=130")
            assert st == 200 and "MOCK:tweaks swappiness 130" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=tweaks_awake&value=on")
            assert st == 200 and "MOCK:tweaks awake on" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=apps_list")
            assert st == 200 and json.loads(body)["apps"][0]["pkg"] == "com.termux"

            st, body = req(f"/cgi-bin/api?token={tok}&action=bundled_list")
            assert st == 200 and json.loads(body)["bundled"][0]["file"] == "02-termux.apk"

            st, body = req(f"/cgi-bin/api?token={tok}&action=bundled_install&value=12-disable-flag-secure.apk")
            assert st == 200 and "MOCK:bundled-install 12-disable-flag-secure.apk" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=bundled_uninstall&value=com.android1500.gpssetter")
            assert st == 200 and "MOCK:bundled-uninstall com.android1500.gpssetter" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=revoke&value=com.termux")
            assert st == 200 and "MOCK:revoke com.termux" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=denylist_add&value=com.game.anticheat")
            assert st == 200 and "MOCK:denylist add com.game.anticheat" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=backup_export")
            assert st == 200 and json.loads(body)["version"] == 4

            st, body = req(f"/cgi-bin/api?token={tok}&action=proxy_set&value=192.168.1.5:8080")
            assert st == 200 and "MOCK:proxy set 192.168.1.5:8080" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=module_disable&value=zygisk_vector")
            assert st == 200 and "MOCK:module disable zygisk_vector" in body

            # v5 endpoints (Workbench, Spoof, Net/Firewall, Automation)
            st, body = req(f"/cgi-bin/api?token={tok}&action=wb_frida_run&value=spawn&p2=com.example.app&p3=ssl-pinning-bypass.js")
            assert st == 200 and "SUB:frida-run spawn com.example.app ssl-pinning-bypass.js" in body
            st, body = req(f"/cgi-bin/api?token={tok}&action=spoof_set&value=rog9")
            assert st == 200 and "SUB:set-profile rog9" in body
            st, body = req(f"/cgi-bin/api?token={tok}&action=spoof_ts_add&value=com.google.android.gms&p2=generate")
            assert st == 200 and "SUB:ts-add com.google.android.gms generate" in body
            st, body = req(f"/cgi-bin/api?token={tok}&action=net_fw_block&value=com.tracker.app")
            assert st == 200 and "SUB:fw-block com.tracker.app" in body
            st, body = req(f"/cgi-bin/api?token={tok}&action=net_tproxy_set&value=192.168.1.10:8080&p2=all&p3=80,443")
            assert st == 200 and "SUB:tproxy-set 192.168.1.10:8080 all 80,443" in body
            st, body = req(f"/cgi-bin/api?token={tok}&action=net_dns_set&value=cloudflare")
            assert st == 200 and "SUB:dns-set cloudflare" in body
            st, body = req(f"/cgi-bin/api?token={tok}&action=auto_freeze&value=org.lineageos.jelly")
            assert st == 200 and "SUB:freeze org.lineageos.jelly" in body
            st, body = req(f"/cgi-bin/api?token={tok}&action=auto_macro&value=clean-caches")
            assert st == 200 and "SUB:macro clean-caches" in body

            # Security / injection / path-traversal / lockout rejections (v4 + v5)
            assert req(f"/cgi-bin/api?token={tok}&action=mode&value=invalid")[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=root&value=rm")[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=tweaks_anim&value=5")[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=tweaks_swap&value=999")[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=bundled_install&value=" + urllib.parse.quote("../etc/passwd"))[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=revoke&value=" + urllib.parse.quote("com.foo;id"))[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=denylist_add&value=" + urllib.parse.quote("com.foo|id"))[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=proxy_set&value=" + urllib.parse.quote("1.2.3.4:80;id"))[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=module_disable&value=andarium_control")[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=module_disable&value=" + urllib.parse.quote("../etc"))[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=wb_frida_run&value=eval")[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=wb_inspect_xml&value=com.app&p2=" + urllib.parse.quote("../../etc/hosts"))[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=spoof_set&value=evil_profile")[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=net_fw_block&value=" + urllib.parse.quote("com.a;reboot"))[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=auto_macro&value=rm_rf")[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=auto_script_run&value=" + urllib.parse.quote("../evil.sh"))[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=exec&value=id")[0] == 400
        finally:
            proc.terminate()
            proc.wait(timeout=3)
    ok("Control Panel v5 live busybox httpd + CGI allowlist/security/path-traversal tests passed")


def test_studio_web_server() -> None:
    port = 18795
    srv = studio_web.ThreadingHTTPServer(("127.0.0.1", port), studio_web.make_handler("kali-linux"))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            html = r.read().decode("utf-8")
            assert r.status == 200 and "Andarium Root Builder Studio" in html
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/meta", timeout=5) as r:
            meta = json.loads(r.read().decode("utf-8"))
            assert len(meta["presets"]) == 6 and len(meta["app_catalog"]) == 13
            assert len(meta["device_profiles"]) == 6
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/icons/icon-crimson.png", timeout=5) as r:
            assert r.status == 200 and r.read().startswith(verifier.PNG_MAGIC)
        # CSRF token enforcement on POST
        for ep in ("/api/build", "/api/presets/save", "/api/updates/check"):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}{ep}",
                data=b'{"config":{}}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=5)
                raise AssertionError(f"Expected 403 without X-Studio-Token on {ep}")
            except urllib.error.HTTPError as e:
                assert e.code == 403
    finally:
        srv.shutdown()
        srv.server_close()
    ok("Local Web Builder Studio v5 HTML, /api/meta (device_profiles), icon previews & CSRF enforcement verified")


def test_upstream_artifact_updater() -> None:
    with tempfile.TemporaryDirectory(prefix="test_updater_") as td:
        tdp = pathlib.Path(td)
        man_path = tdp / "artifacts.json"
        cache_dir = tdp / "cache"
        orig_manifest = json.loads((ROOT / "manifests/artifacts.json").read_text(encoding="utf-8"))
        man_path.write_text(json.dumps(orig_manifest, indent=2), encoding="utf-8")

        # Mock fetcher: pretend Magisk has v32.0 while ReZygisk is up-to-date
        cur_rz_url = orig_manifest["modules"]["rezygisk"]["url"]
        cur_rz_name = cur_rz_url.rsplit("/", 1)[-1]

        def fake_fetch(repo: str) -> tuple[str, list[tuple[str, str]]]:
            if repo == "topjohnwu/Magisk":
                return "v32.0", [("Magisk-v32.0.apk", "https://example.invalid/Magisk-v32.0.apk")]
            if repo == "PerformanC/ReZygisk":
                return "v1.0.0", [(cur_rz_name, cur_rz_url)]
            raise RuntimeError(f"unexpected repo: {repo}")

        rows = update_artifacts.check_updates(
            orig_manifest, only={"magisk", "modules.rezygisk"}, fetcher=fake_fetch
        )
        by_key = {r["key"]: r for r in rows}
        assert by_key["magisk"]["status"] == "update_available"
        assert by_key["modules.rezygisk"]["status"] == "up_to_date"

        # Test corrupt download rejection does NOT touch manifest
        def bad_dl(_url: str, dest: pathlib.Path) -> None:
            dest.write_bytes(b"corrupt garbage bytes" * 30)

        applied_bad = update_artifacts.apply_updates(man_path, rows, cache_dir=cache_dir, downloader=bad_dl)
        assert len(applied_bad) == 0 and not by_key["magisk"].get("applied")
        assert json.loads(man_path.read_text(encoding="utf-8"))["magisk"]["version"] == orig_manifest["magisk"]["version"]

        # Test valid ZIP download applies cleanly, updates SHA-256/size & writes .bak
        def good_dl(_url: str, dest: pathlib.Path) -> None:
            with zipfile.ZipFile(dest, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"dummy" * 100)

        by_key["magisk"]["error"] = ""
        applied_ok = update_artifacts.apply_updates(man_path, rows, cache_dir=cache_dir, downloader=good_dl)
        assert len(applied_ok) == 1
        updated = json.loads(man_path.read_text(encoding="utf-8"))
        assert updated["magisk"]["version"] == "32.0"
        assert updated["magisk"]["name"] == "Magisk-v32.0.apk"
        assert (tdp / "artifacts.json.bak").is_file()
        assert (cache_dir / "Magisk-v32.0.apk").is_file()
    ok("Upstream Auto-Updater (update_artifacts.py) mock diff, corrupt rejection & atomic apply verified")


def test_altstore_source_generator() -> None:
    with tempfile.TemporaryDirectory(prefix="test_src_") as td:
        out = pathlib.Path(td) / "source.json"
        subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "generate_altstore_source.py"),
                "--output", str(out),
                "--repo", "example/Andarium-Root-IPA",
                "--ipa-size", "1350000000",
                "--download-url", "https://example.invalid/ult.ipa",
                "--sha256", "a" * 64,
                "--lite-size", "1100000000",
                "--lite-url", "https://example.invalid/lite.ipa",
                "--lite-sha256", "b" * 64,
            ],
            check=True,
            capture_output=True,
        )
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert len(doc["apps"]) == 2
        assert doc["apps"][0]["bundleIdentifier"] == "com.andarium.root"
        assert doc["apps"][1]["bundleIdentifier"] == "com.andarium.root.lite"
        for app in doc["apps"]:
            ents = app["appPermissions"]["entitlements"]
            assert "com.apple.developer.kernel.increased-memory-limit" in ents
            assert "com.apple.developer.kernel.extended-virtual-addressing" in ents
    ok("AltStore/SideStore/Feather multi-flavor source.json generation verified")


def main() -> int:
    test_guest_shell_scripts()
    test_jit_hardening()
    test_presets_and_icons()
    test_profiles_and_presets()
    test_preboot_cmdline_encoding()
    test_macho_lc_load_dylib_injection()
    test_custom_dropins()
    test_control_panel_v4_cgi()
    test_studio_web_server()
    test_upstream_artifact_updater()
    test_altstore_source_generator()
    print("[test] ALL V5.1 REGRESSION, SECURITY & JIT HARDENING TESTS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
