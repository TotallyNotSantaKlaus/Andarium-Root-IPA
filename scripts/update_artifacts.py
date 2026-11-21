#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Andarium Root Upstream Artifact Health Checker & Auto-Updater (v5).
Checks GitHub releases for newer versions of all pinned artifacts in
manifests/artifacts.json using rate-limit-free redirect + expanded_assets
discovery (or GitHub API when GITHUB_TOKEN is set), validates magic headers
and ZIP/XZ/ELF integrity, computes fresh SHA-256 digests, and optionally
writes an atomic update to manifests/artifacts.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import re
import shutil
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "manifests" / "artifacts.json"
CACHE_DIR = ROOT / ".cache"

# Map manifest paths -> upstream GitHub repo & asset matching rules
UPSTREAM_RULES: dict[str, dict[str, Any]] = {
    "base_ipa": {
        "repo": "imxieyi/Kernarium",
        "pattern": r"^Andarium-[0-9.]+\-[0-9]+\.ipa$",
        "kind": "zip",
        "version_from": "tag",
    },
    "magisk": {
        "repo": "topjohnwu/Magisk",
        "pattern": r"^Magisk-v[0-9.]+\.apk$",
        "kind": "zip",
    },
    "modules.rezygisk": {
        "repo": "PerformanC/ReZygisk",
        "pattern": r"^ReZygisk-.*-release\.zip$",
        "kind": "zip",
    },
    "modules.playintegrityfork": {
        "repo": "osm0sis/PlayIntegrityFork",
        "pattern": r"^PlayIntegrityFork-v.*\.zip$",
        "kind": "zip",
    },
    "modules.trickystore": {
        "repo": "5ec1cff/TrickyStore",
        "pattern": r"^Tricky-Store-.*-release\.zip$",
        "kind": "zip",
    },
    "modules.zygisk_assistant": {
        "repo": "snake-4/Zygisk-Assistant",
        "pattern": r"^Zygisk-Assistant-.*-release\.zip$",
        "kind": "zip",
    },
    "tools.frida_server": {
        "repo": "frida/frida",
        "pattern": r"^frida-server-[0-9.]+-android-arm64\.xz$",
        "kind": "xz_elf",
    },
    "tools.frida_inject": {
        "repo": "frida/frida",
        "pattern": r"^frida-inject-[0-9.]+-android-arm64\.xz$",
        "kind": "xz_elf",
    },
    "tools.dropbear": {
        "repo": "ribbons/android-dropbear",
        "pattern": r"^dropbear-aarch64-linux-android\.zip$",
        "kind": "zip",
    },
    "tools.stevenblack_hosts": {
        "repo": "StevenBlack/hosts",
        "raw_path": "hosts",
        "kind": "hosts",
    },
    "tools.jq": {
        "repo": "jqlang/jq",
        "pattern": r"^jq-linux-arm64$",
        "kind": "elf",
    },
    "apks.material_files": {
        "repo": "zhanghai/MaterialFiles",
        "pattern": r"^app-release-fdroid\.apk$",
        "kind": "zip",
    },
    "apks.microg_gms": {
        "repo": "microg/GmsCore",
        "pattern": r"^com\.google\.android\.gms-[0-9]+\.apk$",
        "kind": "zip",
    },
    "apks.microg_vending": {
        "repo": "microg/GmsCore",
        "pattern": r"^com\.android\.vending-[0-9]+\.apk$",
        "kind": "zip",
    },
    "apks.obtainium": {
        "repo": "ImranR98/Obtainium",
        "pattern": r"^app-arm64-v8a-release\.apk$",
        "kind": "zip",
    },
    "apks.app_manager": {
        "repo": "MuntashirAkon/AppManager",
        "pattern": r"^AppManager_v.*\.apk$",
        "kind": "zip",
    },
    "apks.shizuku": {
        "repo": "RikkaApps/Shizuku",
        "pattern": r"^shizuku-v.*-release\.apk$",
        "kind": "zip",
    },
    "apks.neo_backup": {
        "repo": "NeoApplications/Neo-Backup",
        "pattern": r"^Neo_Backup_.*_release\.apk$",
        "kind": "zip",
    },
    "apks.trustmealready": {
        "repo": "ViRb3/TrustMeAlready",
        "pattern": r"^TrustMeAlready-.*-release\.apk$",
        "kind": "zip",
    },
    "apks.disable_flag_secure": {
        "repo": "LSPosed/DisableFlagSecure",
        "pattern": r"^app-release\.apk$",
        "kind": "zip",
    },
    "apks.gps_setter": {
        "repo": "Android1500/GpsSetter",
        "pattern": r"^app-release\.apk$",
        "kind": "zip",
    },
}


def _http_headers() -> dict[str, str]:
    hdrs = {"User-Agent": "Andarium-Root-Updater/5.0"}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        hdrs["Authorization"] = f"Bearer {tok}"
    return hdrs


def fetch_latest_github_release(repo: str, timeout: int = 20) -> tuple[str, list[tuple[str, str]]]:
    """Return (latest_tag, [(asset_name, download_url), ...]) without hitting GitHub REST rate limits."""
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(api_url, headers={**_http_headers(), "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            obj = json.loads(r.read().decode("utf-8"))
        tag = str(obj.get("tag_name", "")).strip()
        assets = [(a["name"], a["browser_download_url"]) for a in obj.get("assets", [])]
        return tag, assets

    # Unauthenticated path: follow /releases/latest redirect -> /releases/tag/<tag>, then parse expanded_assets
    latest_url = f"https://github.com/{repo}/releases/latest"
    req = urllib.request.Request(latest_url, headers=_http_headers())
    with urllib.request.urlopen(req, timeout=timeout) as r:
        final_url = r.geturl()
    m = re.search(r"/releases/tag/([^/?#]+)", final_url)
    if not m:
        raise RuntimeError(f"Could not resolve latest release tag from {final_url}")
    tag = urllib.request.unquote(m.group(1))

    exp_url = f"https://github.com/{repo}/releases/expanded_assets/{tag}"
    req2 = urllib.request.Request(exp_url, headers=_http_headers())
    with urllib.request.urlopen(req2, timeout=timeout) as r:
        html = r.read().decode("utf-8", errors="replace")

    assets: list[tuple[str, str]] = []
    seen: set[str] = set()
    for href in re.findall(r'href="(/[^/]+/[^/]+/releases/download/[^"]+)"', html):
        full = "https://github.com" + href
        fname = urllib.request.unquote(href.rsplit("/", 1)[-1])
        if fname not in seen:
            seen.add(fname)
            assets.append((fname, full))
    return tag, assets


def validate_artifact_file(path: Path, kind: str) -> None:
    """Validate binary integrity of a newly downloaded artifact before trusting it."""
    data = path.read_bytes()
    if len(data) < 256:
        raise ValueError(f"Downloaded file too small ({len(data)} bytes)")

    if kind == "zip":
        if not data.startswith(b"PK\x03\x04"):
            raise ValueError("Not a valid ZIP/APK/IPA archive")
        with zipfile.ZipFile(path, "r") as zf:
            bad = zf.testzip()
            if bad is not None:
                raise ValueError(f"Corrupt ZIP entry: {bad}")
    elif kind == "xz_elf":
        if not data.startswith(b"\xfd7zXZ\x00"):
            raise ValueError("Not a valid XZ stream")
        hdr = lzma.decompress(data)[:20]
        if hdr[:4] != b"\x7fELF" or hdr[4] != 2 or int.from_bytes(hdr[18:20], "little") != 183:
            raise ValueError("XZ payload is not an ARM64 ELF binary")
    elif kind == "elf":
        if data[:4] != b"\x7fELF" or data[4] != 2 or int.from_bytes(data[18:20], "little") != 183:
            raise ValueError("Binary is not an ARM64 ELF executable")
    elif kind == "hosts":
        text = data.decode("utf-8", errors="replace")
        if len(data) < 50_000 or "0.0.0.0" not in text:
            raise ValueError("Downloaded hosts file looks invalid")


def get_entry(manifest: dict[str, Any], key: str) -> dict[str, Any]:
    cur: Any = manifest
    for part in key.split("."):
        cur = cur[part]
    return cur


def check_updates(
    manifest: dict[str, Any],
    only: set[str] | None = None,
    fetcher: Callable[[str], tuple[str, list[tuple[str, str]]]] = fetch_latest_github_release,
) -> list[dict[str, Any]]:
    """Inspect all tracked manifest entries and return structured status rows."""
    results: list[dict[str, Any]] = []
    repo_cache: dict[str, tuple[str, list[tuple[str, str]]]] = {}

    for key, rule in UPSTREAM_RULES.items():
        if only and key not in only:
            continue
        try:
            entry = get_entry(manifest, key)
        except KeyError:
            continue

        repo = rule["repo"]
        cur_url = str(entry.get("url", ""))
        cur_ver = str(entry.get("version") or entry.get("release_tag") or entry.get("name", ""))
        row: dict[str, Any] = {
            "key": key,
            "repo": repo,
            "current_version": cur_ver,
            "current_url": cur_url,
            "latest_tag": "",
            "latest_asset": "",
            "latest_url": "",
            "status": "unknown",
            "error": "",
        }
        try:
            if repo not in repo_cache:
                repo_cache[repo] = fetcher(repo)
            tag, assets = repo_cache[repo]
            row["latest_tag"] = tag

            if "raw_path" in rule:
                new_url = f"https://raw.githubusercontent.com/{repo}/{tag}/{rule['raw_path']}"
                row["latest_asset"] = f"{key.split('.')[-1]}-{tag}.txt"
                row["latest_url"] = new_url
            else:
                pat = re.compile(rule["pattern"])
                matched = next(((n, u) for n, u in assets if pat.match(n)), None)
                if not matched:
                    row["status"] = "asset_missing"
                    row["error"] = f"No asset matching {rule['pattern']} in {tag}"
                    results.append(row)
                    continue
                row["latest_asset"], row["latest_url"] = matched

            row["status"] = "up_to_date" if row["latest_url"] == cur_url else "update_available"
        except Exception as exc:
            row["status"] = "error"
            row["error"] = str(exc)
        results.append(row)
    return results


def apply_updates(
    manifest_path: Path,
    rows: list[dict[str, Any]],
    cache_dir: Path = CACHE_DIR,
    downloader: Callable[[str, Path], None] | None = None,
) -> list[dict[str, Any]]:
    """Download, verify, and atomically apply all 'update_available' rows to manifests/artifacts.json."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cache_dir.mkdir(parents=True, exist_ok=True)
    applied: list[dict[str, Any]] = []

    def _default_download(url: str, dest: Path) -> None:
        req = urllib.request.Request(url, headers=_http_headers())
        with urllib.request.urlopen(req, timeout=180) as r, open(dest, "wb") as out:
            shutil.copyfileobj(r, out)

    dl = downloader or _default_download

    for row in rows:
        if row["status"] != "update_available":
            continue
        key = row["key"]
        rule = UPSTREAM_RULES[key]
        entry = get_entry(manifest, key)
        new_url = row["latest_url"]
        new_tag = row["latest_tag"]
        asset_name = row["latest_asset"]
        if key in ("base_ipa", "magisk", "tools.frida_server", "tools.frida_inject"):
            fname = asset_name
        elif key == "tools.stevenblack_hosts":
            fname = f"stevenblack-hosts-{new_tag}.txt"
        else:
            ext = Path(asset_name).suffix or ""
            safe_tag = re.sub(r"[^A-Za-z0-9._-]+", "-", new_tag).strip("-") or "latest"
            safe_key = key.split(".")[-1].replace("_", "-")
            fname = f"{safe_key}-{safe_tag}{ext}"

        dest = cache_dir / fname
        tmp = dest.with_suffix(dest.suffix + ".part")
        try:
            dl(new_url, tmp)
            validate_artifact_file(tmp, rule["kind"])
            raw = tmp.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            tmp.replace(dest)

            entry["name"] = fname
            entry["url"] = new_url
            entry["sha256"] = digest
            entry["size"] = len(raw)
            if "release_tag" in entry:
                entry["release_tag"] = new_tag
            if "version" in entry:
                entry["version"] = new_tag.lstrip("v") if key == "magisk" else new_tag
            row["applied"] = True
            row["new_sha256"] = digest
            row["new_size"] = len(raw)
            applied.append(row)
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            row["applied"] = False
            row["error"] = f"apply failed: {exc}"

    if applied:
        bak = manifest_path.with_suffix(".json.bak")
        shutil.copy2(manifest_path, bak)
        tmp_manifest = manifest_path.with_suffix(".json.tmp")
        tmp_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        tmp_manifest.replace(manifest_path)

    return applied


def main() -> int:
    ap = argparse.ArgumentParser(description="Check and update pinned upstream artifacts in manifests/artifacts.json")
    ap.add_argument("--apply", action="store_true", help="Download, verify, and update manifests/artifacts.json")
    ap.add_argument("--only", default="", help="Comma-separated manifest keys to check (e.g. magisk,tools.frida_server)")
    ap.add_argument("--json", action="store_true", help="Output JSON report")
    ap.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    only = {k.strip() for k in re.split(r"[,\s]+", args.only) if k.strip()} or None
    rows = check_updates(manifest, only=only)

    applied: list[dict[str, Any]] = []
    if args.apply:
        applied = apply_updates(args.manifest, rows)

    if args.json:
        print(json.dumps({"rows": rows, "applied_count": len(applied)}, indent=2))
        return 0

    print(f"{'ARTIFACT':<28} {'CURRENT':<22} {'LATEST':<18} {'STATUS'}")
    print("-" * 88)
    up_cnt = 0
    for r in rows:
        st = r["status"]
        if r.get("applied"):
            st = f"UPDATED ({r['new_sha256'][:10]}...)"
        elif r["error"]:
            st = f"{st}: {r['error']}"
        if r["status"] == "update_available":
            up_cnt += 1
        print(f"{r['key']:<28} {r['current_version'][:21]:<22} {r['latest_tag'][:17]:<18} {st}")
    print("-" * 88)
    print(f"Checked {len(rows)} tracked artifacts · {up_cnt} update(s) available · {len(applied)} applied.")
    if up_cnt and not args.apply:
        print("Run with --apply (or .\\update.ps1 -Apply) to download, verify SHA-256, and update manifests/artifacts.json.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
