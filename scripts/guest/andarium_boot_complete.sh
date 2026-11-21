#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Andarium Root boot-completed provisioner (v2, runs in background on sys.boot_completed=1).

MAGISKTMP="${1:-/debug_ramdisk}"
ODM_ROOT="/odm/andarium-root"
BB="/data/adb/magisk/busybox"
[ -x "$BB" ] || BB="$ODM_ROOT/magisk-bin/busybox"
MAGISK="$MAGISKTMP/magisk"
CTL="$ODM_ROOT/scripts/andarium-ctl"
ADB_DIR="/data/adb"
STATE_DIR="$ADB_DIR/andarium"
LOG_FILE="$ADB_DIR/andarium-root.log"

DEFAULT_SELINUX="__DEFAULT_SELINUX__"
DEFAULT_STEALTH="__DEFAULT_STEALTH__"

mkdir -p "$ADB_DIR" "$STATE_DIR" 2>/dev/null
exec >> "$LOG_FILE" 2>&1
echo "=== [andarium_boot_complete] started ==="

read_setting() {
    if [ -f "$STATE_DIR/$1" ]; then
        val="$(cat "$STATE_DIR/$1" 2>/dev/null | tr -d '\r\n ')"
        if [ -n "$val" ]; then
            printf '%s' "$val"
            return 0
        fi
    fi
    printf '%s' "$2"
}

# 1. Re-assert SELinux mode after boot completion (respecting Stealth Mode)
STEALTH="$(read_setting stealth_mode "$DEFAULT_STEALTH")"
if [ "$STEALTH" = "on" ]; then
    SELINUX_MODE="enforcing"
else
    SELINUX_MODE="$(read_setting selinux_mode "$DEFAULT_SELINUX")"
fi
if [ "$SELINUX_MODE" = "permissive" ]; then
    echo 0 > /sys/fs/selinux/enforce 2>/dev/null || setenforce 0 2>/dev/null || true
else
    echo 1 > /sys/fs/selinux/enforce 2>/dev/null || setenforce 1 2>/dev/null || true
fi

# 2. Persist merged module sepolicy.rule into Magisk's preinit dir so future
#    boots load module SELinux rules natively during magiskinit selinux_setup.
PREINIT_DIR="$MAGISKTMP/.magisk/preinit"
wait_preinit=0
while [ ! -d "$PREINIT_DIR" ] && [ "$wait_preinit" -lt 20 ]; do
    sleep 1
    wait_preinit=$((wait_preinit + 1))
done
if [ -d "$PREINIT_DIR" ]; then
    TMP_RULE="$STATE_DIR/.sepolicy.rule.tmp"
    : > "$TMP_RULE"
    for mod in "$ADB_DIR"/modules/*; do
        [ -d "$mod" ] || continue
        [ -f "$mod/disable" ] && continue
        [ -f "$mod/remove" ] && continue
        if [ -f "$mod/sepolicy.rule" ]; then
            cat "$mod/sepolicy.rule" >> "$TMP_RULE"
            printf '\n' >> "$TMP_RULE"
        fi
    done
    if [ -s "$TMP_RULE" ]; then
        cp -f "$TMP_RULE" "$PREINIT_DIR/sepolicy.rule" 2>/dev/null && \
            chmod 0644 "$PREINIT_DIR/sepolicy.rule" 2>/dev/null && \
            chown 0:0 "$PREINIT_DIR/sepolicy.rule" 2>/dev/null && \
            echo "[boot] synced merged sepolicy.rule to $PREINIT_DIR/sepolicy.rule"
    fi
    rm -f "$TMP_RULE"
fi

# 3. Sync Android 17 Conscrypt CA certs on every boot (if user/custom certs exist)
if [ -x "$CTL" ]; then
    "$CTL" certs sync 2>&1 || true
fi

# 4. Wait for PackageManager service to be ready
wait_pm=0
while [ "$wait_pm" -lt 120 ]; do
    if pm path android >/dev/null 2>&1; then
        break
    fi
    sleep 1
    wait_pm=$((wait_pm + 1))
done
if ! pm path android >/dev/null 2>&1; then
    echo "[boot] ERROR: PackageManager did not become ready within 120s; will retry next boot"
    exit 0
fi

# 5. Skip first-boot APK & custom module installation if already completed
if [ ! -f "$STATE_DIR/.apps_provisioned_v2" ]; then
    echo "[boot] PackageManager ready after ${wait_pm}s — starting first-boot provisioning"

    install_apk() {
        apk_path="$1"
        pkg="$2"
        [ -f "$apk_path" ] || return 0
        if [ -n "$pkg" ] && pm path "$pkg" >/dev/null 2>&1; then
            echo "[boot] already installed: $pkg"
            return 0
        fi
        stage="/data/local/tmp/_andarium_stage.apk"
        rm -f "$stage"
        cp -f "$apk_path" "$stage" 2>/dev/null || return 1
        chmod 0644 "$stage" 2>/dev/null
        chown 2000:2000 "$stage" 2>/dev/null || true

        echo "[boot] installing ${pkg:-$(basename "$apk_path")} from $apk_path"
        if pm install --user 0 -r -g "$stage" 2>&1; then
            rm -f "$stage"
            echo "[boot] installed: ${pkg:-$(basename "$apk_path")}"
            return 0
        fi
        if pm install -r -g "$stage" 2>&1; then
            rm -f "$stage"
            echo "[boot] installed (fallback): ${pkg:-$(basename "$apk_path")}"
            return 0
        fi
        rm -f "$stage"
        apk_size="$("$BB" stat -c %s "$apk_path" 2>/dev/null || echo 0)"
        if [ "$apk_size" -gt 0 ] 2>/dev/null && pm install -r -g -S "$apk_size" < "$apk_path" 2>&1; then
            echo "[boot] installed (stream): ${pkg:-$(basename "$apk_path")}"
            return 0
        fi
        echo "[boot] ERROR: failed to install ${pkg:-$(basename "$apk_path")}"
        return 1
    }

    get_pkg_uid() {
        pkg="$1"
        uid=""
        if [ -d "/data/data/$pkg" ] && [ -x "$BB" ]; then
            uid="$("$BB" stat -c %u "/data/data/$pkg" 2>/dev/null || true)"
        fi
        if [ -z "$uid" ] || [ "$uid" = "0" ]; then
            uid="$(dumpsys package "$pkg" 2>/dev/null | "$BB" grep -m1 -E 'appId=|userId=' | "$BB" sed -E 's/.*(appId|userId)=([0-9]+).*/\2/' || true)"
        fi
        case "$uid" in
            ''|*[!0-9]*) return 1 ;;
            *) printf '%s' "$uid"; return 0 ;;
        esac
    }

    grant_root_pkg() {
        pkg="$1"
        uid="$(get_pkg_uid "$pkg")" || { echo "[boot] warn: could not resolve UID for $pkg"; return 1; }
        if [ -x "$MAGISK" ]; then
            "$MAGISK" --sqlite "INSERT OR REPLACE INTO policies (uid,policy,until,logging,notification) VALUES ($uid,2,0,1,0);" && \
                echo "[boot] granted Magisk root to $pkg (uid=$uid)" || \
                echo "[boot] warn: sqlite root grant failed for $pkg (uid=$uid)"
        fi
    }

    ALL_OK=1

    # 01. Magisk Manager
    if [ -f "$ODM_ROOT/apks/01-magisk.apk" ]; then
        if install_apk "$ODM_ROOT/apks/01-magisk.apk" "com.topjohnwu.magisk"; then
            appops set --user 0 com.topjohnwu.magisk REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
        else
            ALL_OK=0
        fi
    fi

    # 02. Termux
    if [ -f "$ODM_ROOT/apks/02-termux.apk" ]; then
        if install_apk "$ODM_ROOT/apks/02-termux.apk" "com.termux"; then
            dumpsys deviceidle whitelist +com.termux >/dev/null 2>&1 || true
            appops set --user 0 com.termux MANAGE_EXTERNAL_STORAGE allow 2>/dev/null || true
            grant_root_pkg "com.termux" || true
        else
            ALL_OK=0
        fi
    fi

    # 03. Material Files
    if [ -f "$ODM_ROOT/apks/03-material-files.apk" ]; then
        if install_apk "$ODM_ROOT/apks/03-material-files.apk" "me.zhanghai.android.files"; then
            appops set --user 0 me.zhanghai.android.files MANAGE_EXTERNAL_STORAGE allow 2>/dev/null || true
            appops set --user 0 me.zhanghai.android.files REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
            grant_root_pkg "me.zhanghai.android.files" || true
        else
            ALL_OK=0
        fi
    fi

    # 04-05. microG GmsCore + Companion (uses built-in LineageOS user-build restricted signature spoofing)
    if [ -f "$ODM_ROOT/apks/04-microg-gms.apk" ]; then
        if install_apk "$ODM_ROOT/apks/04-microg-gms.apk" "com.google.android.gms"; then
            dumpsys deviceidle whitelist +com.google.android.gms >/dev/null 2>&1 || true
            appops set --user 0 com.google.android.gms REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
            pm grant --user 0 com.google.android.gms android.permission.FAKE_PACKAGE_SIGNATURE >/dev/null 2>&1 || true
            pm grant --user 0 com.google.android.gms android.permission.ACCESS_BACKGROUND_LOCATION >/dev/null 2>&1 || true
        else
            ALL_OK=0
        fi
    fi
    if [ -f "$ODM_ROOT/apks/05-microg-vending.apk" ]; then
        if install_apk "$ODM_ROOT/apks/05-microg-vending.apk" "com.android.vending"; then
            dumpsys deviceidle whitelist +com.android.vending >/dev/null 2>&1 || true
            appops set --user 0 com.android.vending REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
            pm grant --user 0 com.android.vending android.permission.FAKE_PACKAGE_SIGNATURE >/dev/null 2>&1 || true
        else
            ALL_OK=0
        fi
    fi

    # 06. Aurora Store
    if [ -f "$ODM_ROOT/apks/06-aurora-store.apk" ]; then
        if install_apk "$ODM_ROOT/apks/06-aurora-store.apk" "com.aurora.store"; then
            appops set --user 0 com.aurora.store MANAGE_EXTERNAL_STORAGE allow 2>/dev/null || true
            appops set --user 0 com.aurora.store REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
        else
            ALL_OK=0
        fi
    fi

    # 07. Obtainium
    if [ -f "$ODM_ROOT/apks/07-obtainium.apk" ]; then
        if install_apk "$ODM_ROOT/apks/07-obtainium.apk" "dev.imranr.obtainium"; then
            dumpsys deviceidle whitelist +dev.imranr.obtainium >/dev/null 2>&1 || true
            appops set --user 0 dev.imranr.obtainium REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
        else
            ALL_OK=0
        fi
    fi

    # 08. App Manager
    if [ -f "$ODM_ROOT/apks/08-app-manager.apk" ]; then
        if install_apk "$ODM_ROOT/apks/08-app-manager.apk" "io.github.muntashirakon.AppManager"; then
            appops set --user 0 io.github.muntashirakon.AppManager MANAGE_EXTERNAL_STORAGE allow 2>/dev/null || true
            appops set --user 0 io.github.muntashirakon.AppManager REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
            grant_root_pkg "io.github.muntashirakon.AppManager" || true
        else
            ALL_OK=0
        fi
    fi

    # 09. Shizuku (pre-granted root + auto-started below on every boot)
    if [ -f "$ODM_ROOT/apks/09-shizuku.apk" ]; then
        if install_apk "$ODM_ROOT/apks/09-shizuku.apk" "moe.shizuku.privileged.api"; then
            dumpsys deviceidle whitelist +moe.shizuku.privileged.api >/dev/null 2>&1 || true
            grant_root_pkg "moe.shizuku.privileged.api" || true
        else
            ALL_OK=0
        fi
    fi

    # 10. Neo Backup
    if [ -f "$ODM_ROOT/apks/10-neo-backup.apk" ]; then
        if install_apk "$ODM_ROOT/apks/10-neo-backup.apk" "com.machiav3lli.backup"; then
            dumpsys deviceidle whitelist +com.machiav3lli.backup >/dev/null 2>&1 || true
            appops set --user 0 com.machiav3lli.backup MANAGE_EXTERNAL_STORAGE allow 2>/dev/null || true
            appops set --user 0 com.machiav3lli.backup REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
            grant_root_pkg "com.machiav3lli.backup" || true
        else
            ALL_OK=0
        fi
    fi

    # 11. TrustMeAlready (SSL Unpinning LSPosed/Vector module)
    if [ -f "$ODM_ROOT/apks/11-trustmealready.apk" ]; then
        install_apk "$ODM_ROOT/apks/11-trustmealready.apk" "com.virb3.trustmealready" || ALL_OK=0
    fi

    # 12. Drop-in custom/apks/*.apk
    if [ -d "$ODM_ROOT/custom/apks" ]; then
        for capk in "$ODM_ROOT"/custom/apks/*.apk; do
            [ -f "$capk" ] || continue
            install_apk "$capk" "" || ALL_OK=0
        done
    fi

    # 13. Drop-in custom/root-packages.txt root grants
    if [ -f "$ODM_ROOT/custom/root-packages.txt" ]; then
        while IFS= read -r rpkg || [ -n "$rpkg" ]; do
            rpkg="$(printf '%s' "$rpkg" | tr -d '\r ')"
            case "$rpkg" in
                ''|'#'*) continue ;;
            esac
            grant_root_pkg "$rpkg" || true
        done < "$ODM_ROOT/custom/root-packages.txt"
    fi

    # 14. Drop-in custom/modules/*.zip via `magisk --install-module`
    if [ -d "$ODM_ROOT/custom/modules" ] && [ -x "$MAGISK" ]; then
        for mzip in "$ODM_ROOT"/custom/modules/*.zip; do
            [ -f "$mzip" ] || continue
            echo "[boot] installing custom Magisk module: $mzip"
            "$MAGISK" --install-module "$mzip" 2>&1 || echo "[boot] warn: custom module failed: $mzip"
        done
    fi

    # Ensure core Magisk DB settings (ReZygisk active -> built-in zygisk=0; shell UID 2000 granted)
    if [ -x "$MAGISK" ]; then
        if [ -d "$ODM_ROOT/modules/rezygisk" ]; then
            "$MAGISK" --sqlite "INSERT OR REPLACE INTO settings (key,value) VALUES('zygisk',0);" >/dev/null 2>&1 || true
        fi
        "$MAGISK" --sqlite "INSERT OR REPLACE INTO policies (uid,policy,until,logging,notification) VALUES (2000,2,0,1,0);" >/dev/null 2>&1 || true
    fi

    if [ "$ALL_OK" = "1" ]; then
        touch "$STATE_DIR/.apps_provisioned_v2"
        echo "[boot] ALL apps and custom overlays provisioned successfully"
    else
        echo "[boot] some installs failed; will retry on next boot"
    fi
fi

# 6. Auto-start Shizuku privileged server as root on EVERY boot
if [ -x "$CTL" ] && pm path moe.shizuku.privileged.api >/dev/null 2>&1; then
    "$CTL" shizuku start 2>&1 || true
fi

# 7. Ensure localhost Control Panel is running
if [ -x "$CTL" ]; then
    "$CTL" webui start >/dev/null 2>&1 || true
fi

echo "=== [andarium_boot_complete] done ==="
exit 0
