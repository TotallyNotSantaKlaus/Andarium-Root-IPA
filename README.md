# Andarium Root IPA Builder (v4 — Pre-Boot & Config Studio Edition)

Reproducible Windows + WSL2 & GitHub Actions patcher, interactive Builder Studio, **Native iOS Pre-Boot Setup Studio**, verifier, regression test suite, PC companion CLI, and live ADB auditor that transforms the official release **`Andarium-1.0-15.ipa`** (Android 17 / LineageOS 24 on Linux 6.18.60 Darwin UML from [imxieyi/Kernarium](https://github.com/imxieyi/Kernarium)) into a fully customizable **`Andarium Root`** IPA — preserving StikDebug JIT, GPU acceleration, audio, camera, and all built-in iOS features while giving total control over root access, role presets, preinstalled apps, pentest tools, performance tweaks, and custom iOS app icon themes.

---

## Role Presets (One-Tap Setup)

Choose any preset in the **Native iOS Pre-Boot Studio** (before clicking Start Emulation), in the **Local Browser Builder Studio** (`.\studio.ps1`), or on the command line (`.\build.ps1 -Preset <name>`):

| Preset | Default Icon Theme | Default Root / SELinux | Highlights |
| --- | --- | --- | --- |
| **`mix`** *(Mix / Ultimate)* | `duskjade` (Emerald) | Root ON · Permissive | Everything enabled: Magisk v31.1, ReZygisk, Vector (LSPosed), Control Panel v4, Stealth Stack, Frida + 5 bypass scripts + 5 ARM64 CLI tools, Dropbear SSH, Systemless Ad-Block, all **13 APKs** |
| **`seceng`** *(Security Engineer)* | `crimson` (Red/Gold) | Root ON · Permissive | Mobile AppSec & Pentest Lab: Frida + SSH autostart, Conscrypt MITM CA sync, TrustMeAlready, Disable FLAG_SECURE, GPS Setter, App Manager, Shizuku, Termux, Stay Awake ON |
| **`hacker`** *(Hacker / RE)* | `crimson` (Red/Gold) | Root ON · Permissive | Maximum instrumentation: ReZygisk, Vector, Frida + 5 ready-to-run JS bypass scripts, `strace`/`socat`/`tcpdump`/`sqlite3`/`jq`, SSH autostart, `0x` animations, `360 DPI`, all 13 APKs |
| **`gamer`** *(Gamer / Performance)* | `cyber` (Cyan/Gold) | Root ON · **Enforcing + Stealth** | Anti-Cheat Stealth ON, DenyList ON, `0x` instant animations, `vm.swappiness=130` zRAM boost, Stay Awake ON, zero background pentest daemons, clean gaming app set |
| **`privacy`** *(Privacy / Daily Driver)* | `stealth` (Titanium) | Root ON · **Enforcing + Stealth** | Clean daily Android 17 with microG, Aurora Store, Obtainium, Neo Backup, Material Files, Systemless Ad-Block, Stealth Mode ON |
| **`unrooted`** *(Clean / Unrooted)* | `stealth` (Titanium) | **Root OFF** · Enforcing | Runtime hidden root (`androidboot.ar.root=0`, reversible in Pre-Boot Studio) — or add `-NoRoot` for a **true build-time unrooted IPA** with stock `init_boot.img` byte-for-byte untouched! |

Legacy v3 profiles (`.\build.ps1 -Profile ultimate|lite|stealth`) remain 100% supported.

---

## Two Ways to Configure Before Booting

### 1. Native iOS Pre-Boot Setup Studio (Inside the Main IPA — BEFORE Clicking Start Emulation!)
- Source lives in [`ios/AndariumRootPreboot/`](ios/AndariumRootPreboot/): pure Objective-C (`UIKit` + `WKWebView` + 64-bit Darwin Mach-O `fishhook`), injected non-destructively into `Payload/Andarium.app/Andarium` via [`scripts/macho_inject.py`](scripts/macho_inject.py) (zero shifted section offsets; both iOS memory entitlements stay 100% intact).
- Adds a floating **`# Root Setup`** pill on Andarium's Home screen (automatically hidden whenever the Android VM Metal view is active) to pick presets, toggle Root ON/OFF, pick individual apps (1–13), modules, services, proxy, and performance tweaks **before** tapping Start Emulation.
- **How `AndariumRootPreboot.dylib` gets compiled**:
  - **Automatic via GitHub Actions (Recommended)**: Pushing this repo to GitHub runs the `build-ios-preboot-dylib` job on `macos-latest` (Apple Xcode `iPhoneOS.sdk`), compiles `AndariumRootPreboot.dylib`, and automatically injects it into every GitHub Release IPA!
  - **Local Mac with Xcode**: Compile with `xcrun -sdk iphoneos clang` (see `.github/workflows/build-rooted-ipa.yml`) and save to `assets/ios/AndariumRootPreboot.dylib` — `build_rooted_ipa.py` auto-detects and injects it!
  - **Local Windows + WSL2 build**: Even without Xcode on Windows, `AndariumRootPreboot.bundle` + your chosen preset/config's `androidboot.ar.cfg` are baked straight into `boot/kernel-command-line.txt` so every single preset, app selection, root toggle, and tweak applies cleanly on Boot 1!

### 2. Local Web Builder Studio (`.\studio.ps1`)
Run `.\studio.ps1` on Windows (or `python3 scripts/studio_web.py` on Linux/macOS) to open **`http://127.0.0.1:8765`** in your browser:
- Click any of the **6 Role Preset** cards
- Choose **Root ON**, **Root HIDDEN at boot**, or **True Unrooted (`--no-root`)**
- Pick any of the **4 Custom iOS App Icon Themes** (`Dusk Jade`, `Crimson Lab`, `Cyber Gold`, `Stealth Slate`, or `Stock`) with live previews
- Check/uncheck any of the **13 bundled APKs** with live IPA size estimation & optional **Shrink IPA** toggle
- Save/export `andarium-config.json` and click **Build & Verify IPA** with live streaming logs!

---

## What's Included (v4)

### Core Root, Control Panel v4 & Stealth Stack
- **Magisk `v31.1`** (`init_boot` patched with `magiskinit`, `PREINITDEVICE=metadata`, full `/data/adb/magisk/` pre-populated — zero "Requires Additional Setup" prompts).
- **On-Device Control Panel v4 (`andarium_control`)**: 5-tab **WebUI + localhost HTTP dashboard (`127.0.0.1:8787`)** secured with a per-boot random session token and strict allowlist CGI:
  1. **Modes & Root**: 1-tap Live Mode Switcher (**Dev**, **Pentest**, **Gamer**, **Stealth**), **Hide/Restore Root (`su`)**, SELinux, ADB Root, `ro.debuggable`.
  2. **Pentest & Net**: Global HTTP Proxy (Burp/mitmproxy), Android 17 Conscrypt CA Sync, Frida Server, Systemless Ad-Block, Dropbear SSH + Authorized Keys Manager, Shizuku, PlayIntegrityFork fetch.
  3. **Apps & SU**: Visual **Per-App Magisk Root (SU) Grant/Revoke** & **Magisk DenyList Manager** for every installed user app.
  4. **Offline Store**: **Bundled Offline App Storefront** — install or uninstall any of the 13 pre-staged APKs directly from `/odm/andarium-root/apks/` with zero internet required.
  5. **Tweaks & Logs**: Animation scale (`0x`/`0.5x`/`1x`), `vm.swappiness` zRAM tuning (`60`–`130`), Stay Awake, Display DPI/Resolution, Live Magisk Module Enable/Disable, **JSON Config Backup Export**, and Boot Log Viewer.
- **ReZygisk `v1.0.0`** + **Vector `v2.2 canary-3119`** (Android 8.1–17 LSPosed successor, anti-detection `DEV_PATH` patched).
- **Stealth & Play Integrity Stack**: **PlayIntegrityFork `v19`**, **TrickyStore `v1.4.1`**, and **Zygisk-Assistant `v2.1.4`**.

### Reverse Engineering, Pentest & Networking Lab
- **Frida Server `17.27.4` (`android-arm64`)** + **5 Ready-to-Run Bypass & Tracing Scripts** in `/odm/andarium-root/tools/frida-scripts/`:
  - `ssl-pinning-bypass.js`, `root-detection-bypass.js`, `flutter-ssl-bypass.js`, `crypto-tracer.js`, `intent-monitor.js`
- **Native ARM64 CLI Suite on root `PATH`**: `strace`, `socat 1.7.4.4`, `sqlite3 3.53.3`, `jq 1.8.2`, `tcpdump`, plus `andarium-termux-setup` & colored root shell aliases.
- **Android 17 Conscrypt System CA Injection (`andarium-ctl certs sync`)** via tmpfs + `nsenter` into Zygote & child namespaces.
- **Systemless Ad-Block** (StevenBlack Unified Hosts `3.16.131`) & **Dropbear SSH `2026.94`** (port `2222`).

### Pre-Bundled Apps (13 APKs — Individually Selectable!)
1. **Magisk Manager `v31.1`** · 2. **Termux `v0.119.0-beta.3`** · 3. **Material Files `v1.7.5`** · 4. **microG GmsCore `v0.3.18.252432`** · 5. **microG Companion** · 6. **Aurora Store `4.8.4`** · 7. **Obtainium `v1.7.4`** · 8. **App Manager `v4.1.1`** · 9. **Shizuku `v13.6.0`** · 10. **Neo Backup `8.3.18`** · 11. **TrustMeAlready `v1.11`** (SSL Unpinning) · 12. **Disable FLAG_SECURE `v5.0.1`** (Screenshots/Screen Recording in secure apps) · 13. **GPS Setter `v1.2.10`** (Mock Location / Xposed GPS Spoofing).

---

## Sideloading & First Boot

1. Sideload `dist/Andarium-Root-1.0-15.ipa` via **SideStore**, **AltStore**, **Sideloadly**, **Feather**, or a paid Apple Developer certificate (keep `increased-memory-limit` & `extended-virtual-addressing` entitlements enabled).
2. Attach **StikDebug** JIT before launching **Andarium Root**.
3. *(When built with `AndariumRootPreboot.dylib` via macOS CI / Xcode)* Tap **`# Root Setup`** on the Andarium Home screen **before** tapping Start Emulation to pick your preset, root toggle, apps, and tweaks!
4. On **first boot**, allow ~60–90 seconds on the home screen for selective APK installation (logged to `/data/adb/andarium-root.log`), then reboot Android **once** so persisted preinit SELinux rules, ReZygisk, Vector, and TrickyStore initialize from early boot.
5. Open **Control Panel v4** via **Magisk Manager → Modules → Andarium Root Control → Action** (or open on your PC browser with `.\companion.ps1 -Action webui`).

---

## Windows CLI Quick Reference

```powershell
# Launch the interactive browser Builder Studio (http://127.0.0.1:8765)
.\studio.ps1

# Build any Role Preset + Icon Theme + full independent verification
.\build.ps1 -Preset mix
.\build.ps1 -Preset seceng -IconTheme crimson
.\build.ps1 -Preset gamer -IconTheme cyber
.\build.ps1 -Preset unrooted -NoRoot -IconTheme stealth
.\build.ps1 -Config .\andarium-config.json

# PC Companion CLI over ADB (with ADB over network enabled)
.\companion.ps1 -Connect 192.168.1.42:5555 -Action webui
.\companion.ps1 -Action mode -Arg pentest      # dev | pentest | gamer | stealth
.\companion.ps1 -Action root -Arg hide         # hide | restore | status
.\companion.ps1 -Action frida                  # start frida-server + forward 27042
.\companion.ps1 -Action ssh-setup              # push ~/.ssh/id_ed25519.pub + forward 2222
.\companion.ps1 -Action mitm -Arg burp.der -Proxy 192.168.1.10:8080
.\companion.ps1 -Action backup -Arg .\andarium-backup.json
.\companion.ps1 -Action install-bundled        # install staged APKs (works on --no-root IPAs too!)
.\audit.ps1 -Connect 192.168.1.42:5555         # full live ADB audit

# Run fast automated v4 regression, Mach-O injection & CGI security tests (~3 seconds)
wsl -d kali-linux -- python3 scripts/test_builder.py
```

---

## Custom Drop-In Overlay (`custom/`)

See [custom/README.md](custom/README.md) — drop your own `.apk`s, Magisk module `.zip`s, Burp/mitmproxy CA certs (`.pem`/`.crt`/`.der`/`.0`), `hosts`, `authorized_keys`, `root-packages.txt`, or boot scripts into `custom/` and rebuild.

---

## Push to GitHub for Automatic macOS Pre-Boot Dylib Builds & SideStore Updates

```powershell
git remote add origin https://github.com/<your-user>/<your-repo>.git
git push -u origin main
```

GitHub Actions ([`.github/workflows/build-rooted-ipa.yml`](.github/workflows/build-rooted-ipa.yml)):
1. Runs `test_builder.py` on Ubuntu (`test` job) and compiles `AndariumRootPreboot.dylib` with real Apple Xcode `iPhoneOS.sdk` on `macos-latest` (`build-ios-preboot-dylib` job) on every push/PR!
2. On daily schedule or manual **Run workflow** dispatch, builds & verifies Ultimate + Lite IPAs **with `AndariumRootPreboot.dylib` injected**, publishes them to GitHub Releases, and updates `docs/altstore-source.json` for SideStore / AltStore / Feather one-tap installs!

## License

Tooling and guest scripts are licensed under **GPL-2.0-or-later** (matching reused Kernarium image tools `ubd_disk.py`, `android_image.py`, and `disk-policy.json`). Bundled upstream tools and apps remain under their respective open-source licenses.
