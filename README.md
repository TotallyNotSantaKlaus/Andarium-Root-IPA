# Andarium Root IPA Builder (v5 — Hypervisor, RE Workbench & Stealth Lab)

Reproducible Windows + WSL2 & GitHub Actions patcher, interactive Web Builder Studio, **Native iOS Pre-Boot Studio v2 (Multi-VM Slots & Hardware Tuning)**, standalone on-device RE Workbench (`frida-inject`, PCAP recorder, SQLite/SharedPrefs inspector), Device Identity & 120 FPS Gaming Spoofer, Root Per-App Firewall & Transparent MITM Proxy, LineageOS Debloater & Task Scheduler, Upstream Auto-Updater, verifier, regression test suite, PC companion CLI, and live ADB auditor that transforms **`Andarium-1.0-15.ipa`** (Android 17 / LineageOS 24 on Linux 6.18.60 Darwin UML from [imxieyi/Kernarium](https://github.com/imxieyi/Kernarium)) into a fully customizable **`Andarium Root`** IPA — preserving StikDebug JIT, GPU acceleration, audio, camera, and all native iOS features.

---

## Role Presets (One-Tap Setup)

Choose any built-in preset — or create, save, share & import **Custom Presets** — in **Native iOS Pre-Boot Studio v2**, **Local Browser Builder Studio** (`.\studio.ps1`), or CLI (`.\build.ps1 -Preset <name>`):

| Preset | Default Icon | Default Spoof | Default Root / SELinux | Highlights |
| --- | --- | --- | --- | --- |
| **`mix`** *(Mix / Ultimate)* | `duskjade` | Stock | Root ON · Permissive | Full suite: Magisk v31.1, ReZygisk, Vector (LSPosed), Control Panel v5, Stealth Stack, Frida Server + standalone `frida-inject` + 5 JS bypass scripts, 5 ARM64 CLI tools, Dropbear SSH, Ad-Block, all **13 APKs** |
| **`seceng`** *(Security Engineer)* | `crimson` | Stock | Root ON · Permissive | Mobile AppSec & Pentest Lab: Frida + SSH autostart, Conscrypt MITM CA sync, Transparent UID proxy redirect, TrustMeAlready, Disable FLAG_SECURE, GPS Setter, App Manager, Shizuku, Termux, Stay Awake ON |
| **`hacker`** *(Hacker / RE)* | `crimson` | Stock | Root ON · Permissive | Maximum instrumentation: ReZygisk, Vector, Frida Server + `frida-inject` + 5 bypass scripts, `strace`/`socat`/`tcpdump`/`sqlite3`/`jq`, SSH autostart, `0x` animations, `360 DPI`, all 13 APKs |
| **`gamer`** *(Gamer / Performance)* | `cyber` | **ROG Phone 9 Pro (120 FPS)** | Root ON · **Enforcing + Stealth** | Anti-Cheat Stealth ON, DenyList ON, 120 FPS gaming device spoof, `0x` instant animations, `vm.swappiness=130` zRAM boost, Stay Awake ON, zero pentest daemons |
| **`privacy`** *(Privacy / Daily Driver)* | `stealth` | **Google Pixel 9 Pro** | Root ON · **Enforcing + Stealth** | Clean daily Android 17 with Pixel 9 Pro identity, microG, Aurora Store, Obtainium, Neo Backup, Material Files, Systemless Ad-Block, Stealth Mode ON |
| **`unrooted`** *(Clean / Unrooted)* | `stealth` | Stock | **Root OFF** · Enforcing | Runtime hidden root (`androidboot.ar.root=0`, reversible in Pre-Boot Studio) — or add `-NoRoot` for a **true build-time unrooted IPA** with stock `init_boot.img` byte-for-byte untouched! |

---

## What's New in v5 (All 6 Major Capabilities)

### 1. On-Device Pentest & RE Workbench (`andarium-workbench`)
- **Standalone `frida-inject 17.27.4` (`android-arm64`)**: Run any of the 5 bundled bypass JS scripts — or write & save custom JS hooks — directly from Control Panel v5 (Spawn `-f` or Attach `-p`) with **zero PC or Python required**.
- **1-Tap `tcpdump` PCAP Ring Recorder**: Capture network traffic (`4 × 25 MB` safe ring cap) with optional BPF filters and download `.pcap` files straight to your browser or pull via `.\companion.ps1 -Action pcap-pull`.
- **In-Browser App Storage Inspector (Read-Only)**: Browse any app's `shared_prefs/*.xml` (with Android 17 ABX binary XML decoding via `abx2xml`) and query `databases/*.db` tables via bundled `sqlite3 -readonly`.
- **Live Filtered `logcat` Viewer**: Filter by package PID and priority (`V/D/I/W/E`) on-device.

### 2. Device Identity & 120 FPS Gaming Spoofer (`andarium-spoof`)
- **6 Built-In Device Profiles** persisted at `post-fs-data` via `resetprop` (before Zygote spawns apps): **Stock**, **Google Pixel 9 Pro** (`caiman`), **Samsung Galaxy S25 Ultra** (`pa3q`), **ASUS ROG Phone 9 Pro (120 FPS)** (`AI2501`), **RedMagic 10 Pro** (`NX789J`), and **Xiaomi 15 Ultra** (`xuanyuan`), plus **Custom Props**.
- **Per-App SSAID / Android ID Randomizer**: Safely reads & updates `/data/system/users/0/settings_ssaid.xml` (supports Android 17 ABX binary XML with automatic `.bak` backup).
- **Visual TrickyStore `target.txt` & `keybox.xml` Manager**: Toggle cert-generation (`!`), leaf-hack (`?`), or auto targets per app, 1-tap Sync GMS, and import/validate `keybox.xml` in Control Panel v5 (or drop `custom/keybox.xml` at build time).

### 3. Transparent Firewall & MITM Network Lab (`andarium-net`)
- **Per-App Root Firewall (`ANDARIUM_FW`)**: Blocks IPv4 + IPv6 internet per app UID using kernel-verified `xt_owner` (persisted across reboots; root/system UIDs protected).
- **Transparent UID MITM Proxy (`ANDARIUM_MITM` via `iptables -t nat`)**: Forces Flutter, Unity, Xamarin, and proxy-unaware apps' TCP `80,443` traffic straight to Burp/mitmproxy (`DNAT`) with safe loopback/root/proxy-IP exemptions.
- **Private DNS (DoT) 1-Tap Override**: Cloudflare, Quad9, AdGuard, Mullvad, Google, or custom DoT hostname.
- **WireGuard (`CONFIG_WIREGUARD=y`) & `socat` Tunnel Helpers**: Stage `wg0.conf` directly and launch local TCP port forwarders on demand.

### 4. Native iOS Pre-Boot Studio v2 (`ios/AndariumRootPreboot/`)
- **Pre-`main()` VM Hardware & Multi-VM Slot Bridge**: Configures verified native Andarium launch overrides before Swift `AppEntry` runs:
  - **Multi-VM Android Slots** (`ANDARIUM_GUEST_INSTANCE`: `default`, `pentest`, `gamer`, `privacy`, or custom named slots — each with its own isolated Android disk, apps, ADB keys & pre-boot config!)
  - **Hardware Tuning**: `KERNARIUM_VCPU_COUNT`, `KERNARIUM_GUEST_MEMORY_MIB` (64 MiB step), `KERNARIUM_ANDROID_DISK_SIZE_GIB` (4–64 GiB), `KERNARIUM_DISPLAY_SCALE`, `ANDARIUM_THERMAL_STATE=nominal` (anti-throttle), `ANDARIUM_HAPTICS=0`, and native `andarium.stats` FPS/CPU/RAM HUD!
- **Custom Presets**: Save, long-press delete, import JSON, and export via iOS Share Sheet directly inside `# Root Setup` before tapping Start Emulation.
- **Automatic Xcode Compilation via GitHub Actions**: Pushing to GitHub runs `build-ios-preboot-dylib` on `macos-latest` (`xcrun -sdk iphoneos clang -arch arm64`) and automatically injects `AndariumRootPreboot.dylib` into Release IPAs via [`scripts/macho_inject.py`](scripts/macho_inject.py).

### 5. System Debloater, App Freezer & Task Automation (`andarium-auto`)
- **Safe LineageOS 24 Debloater & App Freezer**: Non-destructive `pm disable-user` with a hardcoded critical-system protection list and **1-tap Restore All Frozen**.
- **6 Root Quick-Macros**: Trim & Drop Caches, Diagnostic Snapshot, Restart SystemUI, Reset All Network, Export User APKs, and Save Backup JSON to Downloads.
- **Custom Root Script Editor & Background Scheduler**: Save/run custom `.sh` scripts (15s bounded timeout) and schedule recurring root tasks (`pif-refresh`, `certs-sync`, `clean-caches`, `config-backup`, or custom scripts) across reboots.

### 6. Upstream Auto-Updater & Health Checker (`.\update.ps1`)
- [`scripts/update_artifacts.py`](scripts/update_artifacts.py) checks all tracked GitHub releases (Andarium base IPA, Magisk, ReZygisk, PlayIntegrityFork, TrickyStore, Zygisk-Assistant, Frida Server + Inject, Dropbear, StevenBlack Hosts, `jq`, and APKs) without hitting unauthenticated GitHub API rate limits.
- `--apply` downloads updates into `.cache/`, validates ZIP/APK/XZ/ARM64-ELF magic headers, updates SHA-256 + byte sizes atomically (saving `manifests/artifacts.json.bak`), and is also built right into **Web Builder Studio v5** (`.\studio.ps1`).

---

## On-Device Control Panel v5 (8 Tabs · `127.0.0.1:8787`)

Open via **Magisk Manager → Modules → Andarium Root Control → Action**, or on your PC browser with `.\companion.ps1 -Action webui`:
1. **Modes & Root** · 2. **RE Workbench** · 3. **Net & Firewall** · 4. **Spoof & Stealth** · 5. **SU & DenyList** · 6. **Apps & Debloat** · 7. **Automation** · 8. **Tweaks & Logs**

---

## Windows CLI Quick Reference

```powershell
# Launch interactive Browser Builder Studio v5 (http://127.0.0.1:8765)
.\studio.ps1

# Build any Role Preset + Spoof Profile + Icon Theme + full independent verification
.\build.ps1 -Preset mix
.\build.ps1 -Preset seceng -IconTheme crimson
.\build.ps1 -Preset gamer -IconTheme cyber -Spoof rog9
.\build.ps1 -Preset unrooted -NoRoot -IconTheme stealth
.\build.ps1 -Config .\andarium-config.json

# Check & auto-update upstream artifacts (GitHub releases + SHA-256 verification)
.\update.ps1
.\update.ps1 -Apply

# PC Companion CLI over ADB (with ADB over network enabled)
.\companion.ps1 -Connect 192.168.1.42:5555 -Action webui
.\companion.ps1 -Action mode -Arg pentest
.\companion.ps1 -Action spoof -Arg rog9                 # stock|pixel9pro|s25ultra|rog9|redmagic10|xiaomi15u
.\companion.ps1 -Action frida-inject -Arg com.example.app -Arg2 ssl-pinning-bypass.js
.\companion.ps1 -Action pcap-start -Arg "tcp port 443"
.\companion.ps1 -Action pcap-stop
.\companion.ps1 -Action pcap-pull -Arg .\pcaps
.\companion.ps1 -Action tproxy -Arg 192.168.1.10:8080 -Arg2 all
.\companion.ps1 -Action firewall -Arg com.tracker.app
.\companion.ps1 -Action dns -Arg cloudflare
.\companion.ps1 -Action debloat -Arg org.lineageos.jelly
.\companion.ps1 -Action macro -Arg dump-env
.\audit.ps1 -Connect 192.168.1.42:5555

# Run fast automated v5 regression, Mach-O injection, updater & CGI security tests (~4s)
wsl -d kali-linux -- python3 scripts/test_builder.py
```

---

## Custom Drop-In Overlay (`custom/`)

See [custom/README.md](custom/README.md) — drop your own `.apk`s, Magisk module `.zip`s, Burp/mitmproxy CA certs (`.pem`/`.crt`/`.der`/`.0`), `keybox.xml`, `hosts`, `authorized_keys`, `root-packages.txt`, or boot scripts into `custom/` and rebuild.

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
