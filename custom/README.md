# Custom Drop-In Overlay (`custom/`)

Drop your own files into the subdirectories below and rebuild with `.\build.ps1`. They are automatically verified, converted where needed, baked into `/odm/andarium-root/custom/`, and deployed cleanly on boot.

## Supported Drop-In Slots

| Path | What It Does |
| --- | --- |
| `custom/apks/*.apk` | Verified with `testzip()` at build time and silently installed on first boot (`pm install -r -g`). |
| `custom/root-packages.txt` | Optional newline-separated list of package names (e.g. `com.example.tool`) to pre-grant permanent Magisk Superuser access on first boot (lines starting with `#` are ignored). |
| `custom/modules/*.zip` | Any standard Magisk / Zygisk / LSPosed module ZIP. Installed automatically via `magisk --install-module` on first boot (takes effect after the first guest reboot). |
| `custom/certs/*.pem`, `*.crt`, `*.cer`, `*.der`, `*.0` | Automatically converted to Android's `<subject_hash_old>.0` PEM format using `openssl` at build time and injected into Android 17's `/apex/com.android.conscrypt/cacerts` system CA store on every boot (great for Burp Suite, mitmproxy, HTTP Toolkit, or Charles Proxy). |
| `custom/hosts` | Appended verbatim to the systemless `/etc/hosts` file (rename `hosts.example` -> `hosts` to enable). |
| `custom/authorized_keys` | Installed into `/data/adb/andarium/ssh/authorized_keys` (`0600`) for passwordless Dropbear SSH root login (rename `authorized_keys.example` -> `authorized_keys`). |
| `custom/keybox.xml` | Validated for `<AndroidAttestation>` + `<Keybox>` XML tags and staged into `/data/adb/tricky_store/keybox.xml` (`0600`, gitignored). |
| `custom/scripts/post-fs-data.d/*.sh` | Normalized to LF, syntax-checked with `sh -n`, and deployed to `/data/adb/post-fs-data.d/` (`0755`). |
| `custom/scripts/service.d/*.sh` | Normalized to LF, syntax-checked with `sh -n`, and deployed to `/data/adb/service.d/` (`0755`). |
