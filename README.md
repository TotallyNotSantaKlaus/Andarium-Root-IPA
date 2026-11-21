# Andarium Root IPA Builder (v3 Ultimate Edition)

Reproducible Windows + WSL2 & GitHub Actions patcher, verifier, regression test suite, PC companion CLI, and live ADB auditor that transforms the official release **`Andarium-1.0-15.ipa`** (Android 17 / LineageOS 24 on Linux 6.18.60 Darwin UML from [imxieyi/Kernarium](https://github.com/imxieyi/Kernarium)) into a full-control rooted **`Andarium Root`** IPA — preserving StikDebug JIT, GPU acceleration, audio, camera, and all built-in iOS features while giving total root mastery inside Android.

## Build Profiles

Choose the exact flavor you want via `build.ps1 -Profile <name>` (or mix individual `--no-*` flags):

| Profile | Bundle ID | Default Mode | Included |
| --- | --- | --- | --- |
| **`ultimate`** *(default)* | `com.andarium.root` | SELinux Permissive / Dev Mode | Everything: Magisk v31.1, ReZygisk, Vector (LSPosed), Control Panel v3, Stealth Stack, Frida + 5 ARM64 CLI tools (`strace`, `socat`, `sqlite3`, `jq`, `tcpdump`), Conscrypt CA Injection, TrustMeAlready, Dropbear SSH, Systemless Ad-Block, all 11 APKs, custom iOS icon |
| **`lite`** | `com.andarium.root.lite` | SELinux Permissive / Dev Mode | Compact build (~1.1 GB): Magisk v31.1, ReZygisk, Vector, Control Panel v3, native `adb root`, Termux, Material Files, microG, custom iOS icon |
| **`stealth`** | `com.andarium.root.stealth` | **SELinux Enforcing / Stealth ON** | Hardened daily driver: Magisk v31.1, ReZygisk, Vector, Control Panel v3, PlayIntegrityFork + TrickyStore + Zygisk-Assistant, Systemless Ad-Block, microG + Aurora + Obtainium + App Manager + Shizuku + Neo Backup (no Frida/pentest tools, `ro.debuggable=0`, DenyList ON) |

## What's Included (Ultimate Edition)

### Core Root, Control Panel v3 & Stealth Stack
- **Magisk `v31.1`** (`init_boot` patched with `magiskinit`, `PREINITDEVICE=metadata`, full `/data/adb/magisk/` pre-populated — zero "Requires Additional Setup" prompts).
- **On-Device Control Panel v3 (`andarium_control`)**: Dual-mode **WebUI + localhost HTTP dashboard (`127.0.0.1:8787`)** secured with a per-boot random CSRF/session token and strict allowlist CGI. Includes one-tap toggles for **Stealth Mode**, **SELinux**, **ADB Root**, **ro.debuggable**, **HTTP Proxy Switcher (Burp/mitmproxy)**, **Android 17 Conscrypt CA Sync**, **Frida Server**, **Systemless Ad-Block**, **Dropbear SSH + Authorized Keys Manager**, **Display DPI & Resolution Switcher**, **Live Magisk Module Enable/Disable**, **Quick Root Grant**, **Boot Log Viewer**, and **One-Tap Reboot**.
- **ReZygisk `v1.0.0`** + **Vector `v2.2 canary-3119`** (JingMatrix Android 8.1–17 LSPosed successor, `arm64-v8a` + `armeabi-v7a`, anti-detection `DEV_PATH` patched into `daemon.apk` & `dex2oat32/64`).
- **Stealth & Play Integrity Stack**: **PlayIntegrityFork `v19`**, **TrickyStore `v1.4.1`** (default `keybox.xml` + `target.txt` seeded), and **Zygisk-Assistant `v2.1.4`**, coordinated with `andarium_control` so `adb root` keeps working in Dev Mode while one-tap Stealth Mode locks everything down.

### Reverse Engineering, Pentest & Networking Lab
- **Frida Server `17.27.4` (`android-arm64`)** on root `PATH` (`andarium-ctl frida start|stop|autostart`).
- **Native ARM64 CLI Suite on root `PATH`**: **`strace`** (static), **`socat 1.7.4.4`** (static-pie), **`sqlite3 3.53.3`** (Android NDK), **`jq 1.8.2`** (static), **`tcpdump`** (static), plus **`andarium-termux-setup`** and colored root shell aliases (`/data/adb/andarium/profile`).
- **Android 17 Conscrypt System CA Injection (`andarium-ctl certs sync`)**: Injects user-installed and `custom/certs/*` MITM CA certificates into `/apex/com.android.conscrypt/cacerts` and propagates into Zygote + running app mount namespaces via `nsenter`.
- **TrustMeAlready `v1.11`**: Xposed/Vector SSL-unpinning module.
- **Systemless Ad-Block**: StevenBlack Unified Hosts `3.16.131` Magic-Mounted over `/system/etc/hosts` (`andarium-ctl adblock on|off|update`).
- **Dropbear SSH `2026.94` (`aarch64-android`)**: `dropbear`, `dropbearkey`, `dropbearconvert`, `dbclient`, `scp` on root `PATH` with pubkey auth on port `2222`.

### Pre-Bundled Apps (11 APKs, Auto-Installed on First Boot)
**Magisk Manager `v31.1`**, **Termux `v0.119.0-beta.3`** (root granted), **Material Files `v1.7.5`** (root granted), **microG GmsCore + Companion `v0.3.18.252432`** (uses Andarium's built-in LineageOS user-build restricted signature spoofing), **Aurora Store `4.8.4`**, **Obtainium `v1.7.4`**, **App Manager `v4.1.1`** (root granted), **Shizuku `v13.6.0`** (root granted + **auto-started on every boot**), **Neo Backup `8.3.18`** (root granted), and **TrustMeAlready `v1.11`**.

---

## Sideloading & First Boot

1. Sideload `dist/Andarium-Root-1.0-15.ipa` via **SideStore**, **AltStore**, **Sideloadly**, **Feather**, or a paid Apple Developer certificate (keep the embedded `increased-memory-limit` & `extended-virtual-addressing` entitlements enabled).
2. Attach **StikDebug** JIT before launching **Andarium Root**.
3. On **first boot**, allow ~60–90 seconds on the home screen for silent APK installation (logged to `/data/adb/andarium-root.log`), then reboot Android **once** so persisted preinit SELinux rules, ReZygisk, Vector, and TrickyStore initialize from early boot.
4. Open **Control Panel v3** via **Magisk Manager → Modules → Andarium Root Control → Action** (or open it directly on your PC browser with `.\companion.ps1 -Action webui`!).

---

## Windows PC Companion CLI (`companion.ps1`) & Live Audit (`audit.ps1`)

With **ADB over network** enabled in Andarium Root:

```powershell
# Run the full live ADB diagnostic audit
.\audit.ps1 -Connect 192.168.1.42:5555

# Open Control Panel v3 directly in your PC browser (auto-forwards localhost:8787 + token)
.\companion.ps1 -Connect 192.168.1.42:5555 -Action webui

# Interactive root shell with Andarium aliases loaded
.\companion.ps1 -Action shell

# Start Frida Server + forward tcp:27042 -> 127.0.0.1:27042
.\companion.ps1 -Action frida

# Push your PC's ~/.ssh/id_ed25519.pub, start Dropbear SSH & forward port 2222
.\companion.ps1 -Action ssh-setup
.\companion.ps1 -Action ssh

# Convert & push a Burp/mitmproxy CA cert into Android 17 Conscrypt + set HTTP proxy in 1 command
.\companion.ps1 -Action mitm -Arg C:\Users\you\burp.der -Proxy 192.168.1.10:8080
.\companion.ps1 -Action proxy-clear

# Toggle Stealth Mode / SELinux / install local APK / tail boot log
.\companion.ps1 -Action stealth -Arg on
.\companion.ps1 -Action selinux -Arg permissive
.\companion.ps1 -Action install -Arg C:\path\to\app.apk
.\companion.ps1 -Action logcat -Arg boot
```

---

## Custom Drop-In Overlay (`custom/`)

See [custom/README.md](custom/README.md) — drop your own `.apk`s, Magisk module `.zip`s, Burp/mitmproxy CA certs (`.pem`/`.crt`/`.der`/`.0`), `hosts`, `authorized_keys`, `root-packages.txt`, or boot scripts into `custom/` and run `.\build.ps1`.

---

## Rebuilding, Testing & GitHub Actions CI

```powershell
# Build Ultimate (default), Lite, or Stealth profile + full 25-point independent verification
.\build.ps1
.\build.ps1 -Profile lite
.\build.ps1 -Profile stealth

# Run fast automated regression & CGI security tests (~3 seconds)
wsl -d kali-linux -- python3 scripts/test_builder.py
```

### Push to GitHub for Auto-Builds & One-Tap SideStore/AltStore Updates

This workspace is pre-initialized as a clean Git repository (`.cache/` and `dist/*.ipa` are gitignored):

```powershell
git remote add origin https://github.com/<your-user>/<your-repo>.git
git push -u origin main
```

Once pushed:
- GitHub Actions ([`.github/workflows/build-rooted-ipa.yml`](.github/workflows/build-rooted-ipa.yml)) runs `test_builder.py` on every push/PR, checks `imxieyi/Kernarium` daily for new Andarium releases, builds & verifies **both Ultimate and Lite** IPAs, publishes them to GitHub Releases, and updates `docs/altstore-source.json`.
- Add `https://raw.githubusercontent.com/<your-user>/<your-repo>/main/docs/altstore-source.json` in **SideStore**, **AltStore**, or **Feather** for one-tap updates!

## License

Tooling and guest scripts are licensed under **GPL-2.0-or-later** (matching reused Kernarium image tools `ubd_disk.py`, `android_image.py`, and `disk-policy.json`). Bundled upstream tools and apps remain under their respective open-source licenses.
