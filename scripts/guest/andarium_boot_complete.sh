#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Andarium Root boot-completed provisioner (v4, runs on sys.boot_completed=1).

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
echo "=== [andarium_boot_complete v4] started ==="

read_setting() {
    if [ -f "$STATE_DIR/$1" ]; then
        val="$(cat "$STATE_DIR/$1" 2>/dev/null | tr -d '\r\n ')"
        [ -n "$val" ] && { printf '%s' "$val"; return 0; }
    fi
    printf '%s' "$2"
}

ROOT_ENABLED="$(read_setting root_enabled 1)"
STEALTH="$(read_setting stealth_mode "$DEFAULT_STEALTH")"

# 1. Re-assert SELinux mode after boot completion
if [ "$ROOT_ENABLED" = "0" ] || [ "$STEALTH" = "on" ]; then
    SELINUX_MODE="enforcing"
else
    SELINUX_MODE="$(read_setting selinux_mode "$DEFAULT_SELINUX")"
fi
if [ "$SELINUX_MODE" = "permissive" ]; then
    echo 0 > /sys/fs/selinux/enforce 2>/dev/null || setenforce 0 2>/dev/null || true
else
    echo 1 > /sys/fs/selinux/enforce 2>/dev/null || setenforce 1 2>/dev/null || true
fi

# 2. Persist merged module sepolicy.rule into Magisk's preinit dir
PREINIT_DIR="$MAGISKTMP/.magisk/preinit"
wait_preinit=0
while [ ! -d "$PREINIT_DIR" ] && [ "$wait_preinit" -lt 20 ]; do
    sleep 1; wait_preinit=$((wait_preinit + 1))
done
if [ -d "$PREINIT_DIR" ]; then
    TMP_RULE="$STATE_DIR/.sepolicy.rule.tmp"
    : > "$TMP_RULE"
    for mod in "$ADB_DIR"/modules/*; do
        [ -d "$mod" ] || continue
        [ -f "$mod/disable" ] && continue
        [ -f "$mod/remove" ] && continue
        [ -f "$mod/sepolicy.rule" ] && { cat "$mod/sepolicy.rule" >> "$TMP_RULE"; printf '\n' >> "$TMP_RULE"; }
    done
    if [ -s "$TMP_RULE" ]; then
        cp -f "$TMP_RULE" "$PREINIT_DIR/sepolicy.rule" 2>/dev/null && \
            chmod 0644 "$PREINIT_DIR/sepolicy.rule" 2>/dev/null && \
            chown 0:0 "$PREINIT_DIR/sepolicy.rule" 2>/dev/null && \
            echo "[boot] synced merged sepolicy.rule"
    fi
    rm -f "$TMP_RULE"
fi

# 3. Sync Android 17 Conscrypt CA certs
[ -x "$CTL" ] && "$CTL" certs sync 2>&1 || true

# 4. Wait for PackageManager
wait_pm=0
while [ "$wait_pm" -lt 120 ]; do
    pm path android >/dev/null 2>&1 && break
    sleep 1; wait_pm=$((wait_pm + 1))
done
if ! pm path android >/dev/null 2>&1; then
    echo "[boot] ERROR: PackageManager did not become ready within 120s"
    exit 0
fi

# Helper: check 1-based bit in apps_mask (defaults to 1 = enabled if mask empty)
APPS_MASK="$(read_setting apps_mask '1111111111111')"
app_enabled() {
    idx="$1"
    bit="$(printf '%s' "$APPS_MASK" | cut -c"$idx")"
    [ "$bit" != "0" ]
}

# 5. First-boot selective APK & custom module installation
if [ ! -f "$STATE_DIR/.apps_provisioned_v4" ]; then
    echo "[boot] PackageManager ready (${wait_pm}s) — installing selected apps (mask=$APPS_MASK)"

    install_apk() {
        apk_path="$1"; pkg="$2"
        [ -f "$apk_path" ] || return 0
        [ -n "$pkg" ] && pm path "$pkg" >/dev/null 2>&1 && { echo "[boot] already installed: $pkg"; return 0; }
        stage="/data/local/tmp/_andarium_stage.apk"
        rm -f "$stage"
        cp -f "$apk_path" "$stage" 2>/dev/null || return 1
        chmod 0644 "$stage" 2>/dev/null; chown 2000:2000 "$stage" 2>/dev/null || true
        if pm install --user 0 -r -g "$stage" 2>&1 || pm install -r -g "$stage" 2>&1; then
            rm -f "$stage"; echo "[boot] installed: ${pkg:-$(basename "$apk_path")}"; return 0
        fi
        rm -f "$stage"
        apk_size="$("$BB" stat -c %s "$apk_path" 2>/dev/null || echo 0)"
        if [ "$apk_size" -gt 0 ] 2>/dev/null && pm install -r -g -S "$apk_size" < "$apk_path" 2>&1; then
            echo "[boot] installed (stream): ${pkg:-$(basename "$apk_path")}"; return 0
        fi
        echo "[boot] ERROR: failed to install ${pkg:-$(basename "$apk_path")}"
        return 1
    }

    grant_root_pkg() {
        [ "$ROOT_ENABLED" = "1" ] || return 0
        "$CTL" grant "$1" >/dev/null 2>&1 && echo "[boot] granted root to $1" || true
    }

    ALL_OK=1

    # 1: Magisk Manager (only when Root ON and bit 1 == 1)
    if [ "$ROOT_ENABLED" = "1" ] && app_enabled 1 && [ -f "$ODM_ROOT/apks/01-magisk.apk" ]; then
        install_apk "$ODM_ROOT/apks/01-magisk.apk" "com.topjohnwu.magisk" && \
            appops set --user 0 com.topjohnwu.magisk REQUEST_INSTALL_PACKAGES allow 2>/dev/null || ALL_OK=0
    fi
    # 2: Termux
    if app_enabled 2 && [ -f "$ODM_ROOT/apks/02-termux.apk" ]; then
        if install_apk "$ODM_ROOT/apks/02-termux.apk" "com.termux"; then
            dumpsys deviceidle whitelist +com.termux >/dev/null 2>&1 || true
            appops set --user 0 com.termux MANAGE_EXTERNAL_STORAGE allow 2>/dev/null || true
            grant_root_pkg "com.termux"
        else ALL_OK=0; fi
    fi
    # 3: Material Files
    if app_enabled 3 && [ -f "$ODM_ROOT/apks/03-material-files.apk" ]; then
        if install_apk "$ODM_ROOT/apks/03-material-files.apk" "me.zhanghai.android.files"; then
            appops set --user 0 me.zhanghai.android.files MANAGE_EXTERNAL_STORAGE allow 2>/dev/null || true
            appops set --user 0 me.zhanghai.android.files REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
            grant_root_pkg "me.zhanghai.android.files"
        else ALL_OK=0; fi
    fi
    # 4: microG GmsCore
    if app_enabled 4 && [ -f "$ODM_ROOT/apks/04-microg-gms.apk" ]; then
        if install_apk "$ODM_ROOT/apks/04-microg-gms.apk" "com.google.android.gms"; then
            dumpsys deviceidle whitelist +com.google.android.gms >/dev/null 2>&1 || true
            appops set --user 0 com.google.android.gms REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
            pm grant --user 0 com.google.android.gms android.permission.FAKE_PACKAGE_SIGNATURE >/dev/null 2>&1 || true
            pm grant --user 0 com.google.android.gms android.permission.ACCESS_BACKGROUND_LOCATION >/dev/null 2>&1 || true
        else ALL_OK=0; fi
    fi
    # 5: microG Companion
    if app_enabled 5 && [ -f "$ODM_ROOT/apks/05-microg-vending.apk" ]; then
        if install_apk "$ODM_ROOT/apks/05-microg-vending.apk" "com.android.vending"; then
            dumpsys deviceidle whitelist +com.android.vending >/dev/null 2>&1 || true
            appops set --user 0 com.android.vending REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
            pm grant --user 0 com.android.vending android.permission.FAKE_PACKAGE_SIGNATURE >/dev/null 2>&1 || true
        else ALL_OK=0; fi
    fi
    # 6: Aurora Store
    if app_enabled 6 && [ -f "$ODM_ROOT/apks/06-aurora-store.apk" ]; then
        if install_apk "$ODM_ROOT/apks/06-aurora-store.apk" "com.aurora.store"; then
            appops set --user 0 com.aurora.store MANAGE_EXTERNAL_STORAGE allow 2>/dev/null || true
            appops set --user 0 com.aurora.store REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
        else ALL_OK=0; fi
    fi
    # 7: Obtainium
    if app_enabled 7 && [ -f "$ODM_ROOT/apks/07-obtainium.apk" ]; then
        if install_apk "$ODM_ROOT/apks/07-obtainium.apk" "dev.imranr.obtainium"; then
            dumpsys deviceidle whitelist +dev.imranr.obtainium >/dev/null 2>&1 || true
            appops set --user 0 dev.imranr.obtainium REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
        else ALL_OK=0; fi
    fi
    # 8: App Manager
    if app_enabled 8 && [ -f "$ODM_ROOT/apks/08-app-manager.apk" ]; then
        if install_apk "$ODM_ROOT/apks/08-app-manager.apk" "io.github.muntashirakon.AppManager"; then
            appops set --user 0 io.github.muntashirakon.AppManager MANAGE_EXTERNAL_STORAGE allow 2>/dev/null || true
            appops set --user 0 io.github.muntashirakon.AppManager REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
            grant_root_pkg "io.github.muntashirakon.AppManager"
        else ALL_OK=0; fi
    fi
    # 9: Shizuku
    if app_enabled 9 && [ -f "$ODM_ROOT/apks/09-shizuku.apk" ]; then
        if install_apk "$ODM_ROOT/apks/09-shizuku.apk" "moe.shizuku.privileged.api"; then
            dumpsys deviceidle whitelist +moe.shizuku.privileged.api >/dev/null 2>&1 || true
            grant_root_pkg "moe.shizuku.privileged.api"
        else ALL_OK=0; fi
    fi
    # 10: Neo Backup
    if app_enabled 10 && [ -f "$ODM_ROOT/apks/10-neo-backup.apk" ]; then
        if install_apk "$ODM_ROOT/apks/10-neo-backup.apk" "com.machiav3lli.backup"; then
            dumpsys deviceidle whitelist +com.machiav3lli.backup >/dev/null 2>&1 || true
            appops set --user 0 com.machiav3lli.backup MANAGE_EXTERNAL_STORAGE allow 2>/dev/null || true
            appops set --user 0 com.machiav3lli.backup REQUEST_INSTALL_PACKAGES allow 2>/dev/null || true
            grant_root_pkg "com.machiav3lli.backup"
        else ALL_OK=0; fi
    fi
    # 11: TrustMeAlready
    if app_enabled 11 && [ -f "$ODM_ROOT/apks/11-trustmealready.apk" ]; then
        install_apk "$ODM_ROOT/apks/11-trustmealready.apk" "com.virb3.trustmealready" || ALL_OK=0
    fi
    # 12: Disable FLAG_SECURE
    if app_enabled 12 && [ -f "$ODM_ROOT/apks/12-disable-flag-secure.apk" ]; then
        install_apk "$ODM_ROOT/apks/12-disable-flag-secure.apk" "io.github.lsposed.disableflagsecure" || ALL_OK=0
    fi
    # 13: GPS Setter
    if app_enabled 13 && [ -f "$ODM_ROOT/apks/13-gps-setter.apk" ]; then
        install_apk "$ODM_ROOT/apks/13-gps-setter.apk" "com.android1500.gpssetter" || ALL_OK=0
    fi

    # Drop-in custom APKs, root grants & Magisk modules
    if [ -d "$ODM_ROOT/custom/apks" ]; then
        for capk in "$ODM_ROOT"/custom/apks/*.apk; do
            [ -f "$capk" ] && { install_apk "$capk" "" || ALL_OK=0; }
        done
    fi
    if [ -f "$ODM_ROOT/custom/root-packages.txt" ]; then
        while IFS= read -r rpkg || [ -n "$rpkg" ]; do
            rpkg="$(printf '%s' "$rpkg" | tr -d '\r ')"
            case "$rpkg" in ''|'#'*) continue ;; esac
            grant_root_pkg "$rpkg"
        done < "$ODM_ROOT/custom/root-packages.txt"
    fi
    if [ -d "$ODM_ROOT/custom/modules" ] && [ -x "$MAGISK" ]; then
        for mzip in "$ODM_ROOT"/custom/modules/*.zip; do
            [ -f "$mzip" ] && "$MAGISK" --install-module "$mzip" 2>&1 || true
        done
    fi

    if [ -x "$MAGISK" ]; then
        [ -d "$ODM_ROOT/modules/rezygisk" ] && "$MAGISK" --sqlite "INSERT OR REPLACE INTO settings (key,value) VALUES('zygisk',0);" >/dev/null 2>&1 || true
        "$MAGISK" --sqlite "INSERT OR REPLACE INTO policies (uid,policy,until,logging,notification) VALUES (2000,2,0,1,0);" >/dev/null 2>&1 || true
    fi

    [ "$ALL_OK" = "1" ] && { touch "$STATE_DIR/.apps_provisioned_v4"; echo "[boot] ALL selected apps provisioned"; } || echo "[boot] some installs failed; will retry"
fi

# 6. Enforce Root ON/OFF visibility on Magisk Manager on every boot
if [ "$ROOT_ENABLED" = "0" ]; then
    pm disable-user --user 0 com.topjohnwu.magisk >/dev/null 2>&1 || true
else
    pm enable com.topjohnwu.magisk >/dev/null 2>&1 || true
fi

# 7. Apply saved/pre-boot performance, display & proxy tweaks
if [ -x "$CTL" ]; then
    ANIM="$(read_setting anim_scale '')"
    [ -n "$ANIM" ] && "$CTL" tweaks anim "$ANIM" >/dev/null 2>&1 || true
    AWAKE="$(read_setting stay_awake '')"
    [ "$AWAKE" = "1" ] && "$CTL" tweaks awake on >/dev/null 2>&1 || true
    DPI="$(read_setting dpi '')"
    [ -n "$DPI" ] && [ "$DPI" != "0" ] && "$CTL" display density "$DPI" >/dev/null 2>&1 || true
    PROXY="$(read_setting http_proxy '')"
    [ -n "$PROXY" ] && "$CTL" proxy set "$PROXY" >/dev/null 2>&1 || true

    # Auto-start Shizuku if enabled & installed
    if [ "$ROOT_ENABLED" = "1" ] && [ "$(read_setting shizuku_autostart 1)" = "1" ] && pm path moe.shizuku.privileged.api >/dev/null 2>&1; then
        "$CTL" shizuku start 2>&1 || true
    fi

    # Start localhost Control Panel (unless Root OFF)
    [ "$ROOT_ENABLED" = "1" ] && "$CTL" webui start >/dev/null 2>&1 || true
fi

# 8. Re-apply persisted Per-App Firewall, Transparent MITM Proxy & Scheduler (v5)
if [ -x "$ODM_ROOT/scripts/andarium-net" ]; then
    [ -s "$STATE_DIR/firewall-blocked.list" ] && "$ODM_ROOT/scripts/andarium-net" fw-apply 2>&1 || true
    [ -s "$STATE_DIR/tproxy.conf" ] && "$ODM_ROOT/scripts/andarium-net" tproxy-apply 2>&1 || true
fi
if [ "$ROOT_ENABLED" = "1" ] && [ -x "$ODM_ROOT/scripts/andarium-auto" ]; then
    "$ODM_ROOT/scripts/andarium-auto" sched-start 2>&1 || true
fi

echo "=== [andarium_boot_complete v5] done ==="
exit 0
