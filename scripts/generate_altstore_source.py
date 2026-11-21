#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate an AltStore / SideStore / Feather compatible source.json feed (Ultimate + optional Lite)."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path


def make_app_entry(
    *,
    name: str,
    bundle_id: str,
    subtitle: str,
    description: str,
    icon_url: str,
    version: str,
    build_version: str,
    date_iso: str,
    download_url: str,
    size: int,
    min_os: str,
) -> dict[str, object]:
    return {
        "name": name,
        "bundleIdentifier": bundle_id,
        "developerName": "Andarium Root (based on imxieyi/Kernarium)",
        "subtitle": subtitle,
        "localizedDescription": description,
        "iconURL": icon_url,
        "tintColor": "#34F5A1",
        "category": "utilities",
        "versions": [
            {
                "version": version,
                "buildVersion": build_version,
                "date": date_iso,
                "localizedDescription": description,
                "downloadURL": download_url,
                "size": size,
                "minOSVersion": min_os,
            }
        ],
        "appPermissions": {
            "entitlements": [
                "com.apple.developer.kernel.increased-memory-limit",
                "com.apple.developer.kernel.extended-virtual-addressing",
            ],
            "privacy": {
                "NSCameraUsageDescription": "Andarium uses the camera only when you turn on Camera inside the VM.",
                "NSLocalNetworkUsageDescription": "Used for guest networking, ADB over network, and Dropbear SSH.",
                "NSLocationWhenInUseUsageDescription": "Shares location only when Location is turned on inside the VM.",
                "NSMicrophoneUsageDescription": "Records audio only when Microphone is turned on inside the VM.",
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AltStore / SideStore / Feather source.json")
    parser.add_argument("--output", type=Path, default=Path("docs/altstore-source.json"))
    parser.add_argument("--repo", default="OWNER/Andarium-Root-IPA", help="GitHub owner/repo slug")
    parser.add_argument("--version", default="1.0.15", help="Marketing version string")
    parser.add_argument("--build-version", default="15", help="CFBundleVersion")
    parser.add_argument("--bundle-id", default="com.andarium.root")
    parser.add_argument("--display-name", default="Andarium Root")
    parser.add_argument("--ipa-size", type=int, required=True, help="Ultimate IPA size in bytes")
    parser.add_argument("--download-url", required=True, help="Direct HTTPS download URL to Ultimate .ipa")
    parser.add_argument("--sha256", default="", help="Optional SHA-256 hex digest for Ultimate IPA")
    parser.add_argument("--lite-size", type=int, default=0, help="Optional Lite IPA size in bytes")
    parser.add_argument("--lite-url", default="", help="Optional direct HTTPS download URL to Lite .ipa")
    parser.add_argument("--lite-sha256", default="", help="Optional SHA-256 hex digest for Lite IPA")
    parser.add_argument("--min-os", default="17.0", help="Minimum iOS version")
    args = parser.parse_args()

    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    icon_url = f"https://raw.githubusercontent.com/{args.repo}/main/docs/icon.png"

    ult_notes = (
        "Andarium Root v4 — Pre-Boot & Config Studio Edition (Android 17 / LineageOS 24 on Linux 6.18.60): "
        "Native iOS Pre-Boot Setup Studio (# Root Setup before Start Emulation), 6 Role Presets "
        "(Mix/Ultimate, Security Engineer, Hacker/RE, Gamer, Privacy/Daily, Clean/Unrooted), "
        "Magisk v31.1 with Root Hide/Restore toggle, ReZygisk, Vector (LSPosed), Control Panel v4 "
        "(Live Mode Switcher, Per-App SU & DenyList Manager, Bundled Offline App Storefront, Tweaks & JSON Backup), "
        "Stealth Stack (PlayIntegrityFork + TrickyStore + Zygisk-Assistant), Frida Server + 5 bypass scripts + "
        "strace/socat/sqlite3/jq/tcpdump, Android 17 Conscrypt CA cert injection, Dropbear SSH, Systemless Ad-Block, "
        "and 13 selectable apps (incl. Disable FLAG_SECURE & GPS Setter)."
    )
    if args.sha256:
        ult_notes += f"\n\nSHA-256: {args.sha256}"

    apps = [
        make_app_entry(
            name=args.display_name,
            bundle_id=args.bundle_id,
            subtitle="Full-Root Android 17 VM on iOS (Magisk + Vector + Pentest & Stealth Suite)",
            description=ult_notes,
            icon_url=icon_url,
            version=args.version,
            build_version=args.build_version,
            date_iso=today,
            download_url=args.download_url,
            size=args.ipa_size,
            min_os=args.min_os,
        )
    ]
    featured = [args.bundle_id]

    if args.lite_url and args.lite_size > 0:
        lite_bid = f"{args.bundle_id}.lite"
        lite_notes = (
            "Compact Andarium Root v4 Lite (Android 17 / LineageOS 24): Native iOS Pre-Boot Setup Studio, "
            "Magisk v31.1, ReZygisk, Vector (LSPosed), Control Panel v4, native adb root, switchable SELinux, "
            "Termux, Material Files, and microG."
        )
        if args.lite_sha256:
            lite_notes += f"\n\nSHA-256: {args.lite_sha256}"
        apps.append(
            make_app_entry(
                name=f"{args.display_name} Lite",
                bundle_id=lite_bid,
                subtitle="Compact Rooted Android 17 VM on iOS (Magisk + Vector + microG)",
                description=lite_notes,
                icon_url=icon_url,
                version=args.version,
                build_version=args.build_version,
                date_iso=today,
                download_url=args.lite_url,
                size=args.lite_size,
                min_os=args.min_os,
            )
        )
        featured.append(lite_bid)

    source = {
        "name": f"{args.display_name} Repository",
        "subtitle": "Rooted Android 17 VM for iOS (Pre-Boot Studio + Magisk + Vector + Control Panel v4)",
        "description": "Automated rooted builds of Andarium with Magisk v31.1, ReZygisk, Vector, and power-user tools.",
        "identifier": f"{args.bundle_id}.source",
        "iconURL": icon_url,
        "tintColor": "#34F5A1",
        "featuredApps": featured,
        "apps": apps,
        "news": [],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(source, indent=2) + "\n", encoding="utf-8")
    print(f"[source] wrote {args.output} ({len(apps)} app(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
