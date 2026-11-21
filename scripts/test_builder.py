#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Automated regression & security test suite for Andarium Root IPA Builder (v3).

Runs fast (~3 seconds) in Linux / WSL2 / GitHub Actions without needing to repack
the full 1.3 GB IPA on every unit test:
  1. Validates POSIX shell syntax (`sh -n`) on every guest script.
  2. Tests build profile presets (`ultimate`, `lite`, `stealth`) & CLI overrides.
  3. Tests `custom/` drop-in processing end-to-end: synthetic PEM & DER CA cert
     conversion via `openssl` -> `<subject_hash_old>.0`, custom hosts, authorized_keys,
     root-packages.txt, custom scripts LF normalization + `sh -n`, and corrupt ZIP rejection.
  4. Live-tests Control Panel v3 (`busybox httpd` + `webroot/cgi-bin/api`) with Magisk's
     real x86_64 busybox: checks 403 unauthorized, 200 authorized, allowlisted v3 endpoints
     (proxy, display, module enable/disable, ssh key manager), AND command-injection /
     path-traversal / `andarium_control` lockout protections!
  5. Tests `generate_altstore_source.py` multi-flavor JSON output & memory entitlements.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import build_rooted_ipa as builder  # noqa: E402


def ok(msg: str) -> None:
    print(f"[test] PASS: {msg}", flush=True)


def test_guest_shell_scripts() -> None:
    guest_scripts = [
        ROOT / "scripts/guest/andarium-ctl",
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
    ok(f"all {len(guest_scripts)} guest shell scripts normalize to LF and pass sh -n")


def test_profiles() -> None:
    def parse_with(argv: list[str]) -> argparse.Namespace:
        old = sys.argv
        sys.argv = ["build_rooted_ipa.py", *argv]
        try:
            return builder.resolve_profile(builder.parse_args())
        finally:
            sys.argv = old

    u = parse_with(["--profile", "ultimate"])
    assert u.bundle_id == "com.andarium.root" and u.selinux == "permissive" and u.default_stealth == "off"
    assert not u.no_pentest and not u.no_stealth and not u.no_network and not u.no_power_apps

    l = parse_with(["--profile", "lite"])
    assert l.bundle_id == "com.andarium.root.lite" and l.no_pentest and l.no_stealth and l.no_network and l.no_power_apps

    s = parse_with(["--profile", "stealth"])
    assert s.bundle_id == "com.andarium.root.stealth" and s.selinux == "enforcing" and s.default_stealth == "on"
    assert s.no_pentest and s.no_adbroot and s.no_debuggable and not s.no_stealth

    ov = parse_with(["--profile", "lite", "--bundle-id", "com.test.custom", "--selinux", "enforcing"])
    assert ov.bundle_id == "com.test.custom" and ov.selinux == "enforcing"
    ok("build profiles (ultimate / lite / stealth) and CLI overrides resolve accurately")


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

        # Generate a real self-signed test CA in both PEM and DER format
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

        # Create valid dummy APK & module ZIP
        with zipfile.ZipFile(cdir / "apks" / "sample.apk", "w") as zf:
            zf.writestr("AndroidManifest.xml", b"dummy")
        with zipfile.ZipFile(cdir / "modules" / "sample_mod.zip", "w") as zf:
            zf.writestr("module.prop", b"id=sample\n")

        # Create CRLF script, hosts, authorized_keys, root-packages.txt
        (cdir / "scripts" / "service.d" / "99-hello.sh").write_bytes(b"#!/system/bin/sh\r\necho hi\r\n")
        (cdir / "hosts").write_bytes(b"127.0.0.1 test.local\r\n")
        (cdir / "authorized_keys").write_bytes(b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@pc\r\n")
        (cdir / "root-packages.txt").write_bytes(b"# comment\r\ncom.example.tool\r\n")

        hosts_out = builder.stage_custom_dropins(cdir, pdir)
        assert hosts_out is not None and hosts_out.is_file()
        certs = sorted((pdir / "certs").glob("*.0"))
        assert len(certs) == 2, f"Expected 2 hashed .0 certs, got {certs}"
        for c in certs:
            assert len(c.stem) == 8 and b"-----BEGIN CERTIFICATE-----" in c.read_bytes()
        assert (pdir / "apks" / "sample.apk").is_file()
        assert (pdir / "modules" / "sample_mod.zip").is_file()
        svc_bytes = (pdir / "scripts" / "service.d" / "99-hello.sh").read_bytes()
        assert b"\r" not in svc_bytes
        assert (pdir / "authorized_keys").read_bytes() == b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@pc\n"
        assert (pdir / "root-packages.txt").read_bytes() == b"com.example.tool\n"

        # Negative test: corrupt ZIP must fail cleanly
        (cdir / "apks" / "corrupt.apk").write_bytes(b"not a zip")
        try:
            builder.stage_custom_dropins(cdir, tdp / "payload_bad")
            raise AssertionError("Expected error for corrupt custom APK")
        except (builder.BuildError, zipfile.BadZipFile):
            pass

    ok("custom/ drop-ins verified (PEM+DER->hash.0 CA certs, CRLF->LF scripts, hosts, keys, bad-ZIP rejection)")


def test_control_panel_cgi() -> None:
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

        # Mock CTL that echoes its args cleanly as JSON/text
        mock_ctl = tdp / "mock-ctl"
        mock_ctl.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = 'status-json' ]; then echo '{\"ok\":true,\"kernel\":\"6.18.60\"}'; exit 0; fi\n"
            "echo \"MOCK:$*\"\n"
        )
        mock_ctl.chmod(0o755)

        api_src = builder.read_text_lf(ROOT / "scripts/guest/control_module/webroot/cgi-bin/api").decode("utf-8")
        api_src = api_src.replace("#!/system/bin/sh", "#!/bin/sh")
        api_src = api_src.replace('CTL="/odm/andarium-root/scripts/andarium-ctl"', f'CTL="{mock_ctl}"')
        api_src = api_src.replace('TOKEN_FILE="/data/adb/andarium/run/webui.token"', f'TOKEN_FILE="{tok_file}"')
        api_src = api_src.replace('BB="/data/adb/magisk/busybox"', f'BB="{bb}"')
        api_p = webroot / "cgi-bin" / "api"
        api_p.write_text(api_src)
        api_p.chmod(0o755)

        port = 18793
        proc = subprocess.Popen([str(bb), "httpd", "-f", "-p", f"127.0.0.1:{port}", "-h", str(webroot)])
        try:
            time.sleep(0.4)

            def req(path: str) -> tuple[int, str]:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
                        return r.status, r.read().decode("utf-8")
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode("utf-8")

            # Index page
            st, body = req("/")
            assert st == 200 and "Andarium Root Control v3" in body

            # Auth enforcement
            assert req("/cgi-bin/api?action=status")[0] == 403
            assert req("/cgi-bin/api?token=wrong&action=status")[0] == 403

            # Valid v3 endpoints
            st, body = req(f"/cgi-bin/api?token={tok}&action=status")
            assert st == 200 and json.loads(body)["kernel"] == "6.18.60"

            st, body = req(f"/cgi-bin/api?token={tok}&action=proxy_set&value=192.168.1.5:8080")
            assert st == 200 and "MOCK:proxy set 192.168.1.5:8080" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=display_density&value=360")
            assert st == 200 and "MOCK:display density 360" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=display_size&value=1080x2340")
            assert st == 200 and "MOCK:display size 1080x2340" in body

            st, body = req(f"/cgi-bin/api?token={tok}&action=module_disable&value=zygisk_vector")
            assert st == 200 and "MOCK:module disable zygisk_vector" in body

            # Security / injection / lockout rejections
            assert req(f"/cgi-bin/api?token={tok}&action=proxy_set&value=" + urllib.parse.quote("1.2.3.4:80;id"))[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=module_disable&value=andarium_control")[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=module_disable&value=" + urllib.parse.quote("../etc"))[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=grant&value=" + urllib.parse.quote("com.foo;rm -rf /"))[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=display_size&value=badsize")[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=ssh_delkey&value=1;id")[0] == 400
            assert req(f"/cgi-bin/api?token={tok}&action=exec&value=id")[0] == 400
        finally:
            proc.terminate()
            proc.wait(timeout=3)
    ok("Control Panel v3 live busybox httpd + CGI security/allowlist/lockout tests passed")


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
    test_profiles()
    test_custom_dropins()
    test_control_panel_cgi()
    test_altstore_source_generator()
    print("[test] ALL REGRESSION & SECURITY TESTS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
