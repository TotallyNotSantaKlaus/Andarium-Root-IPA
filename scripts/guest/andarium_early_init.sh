#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Andarium Root synchronous post-fs-data bootstrapper (v4).
# Reads live iOS Pre-Boot Studio parameters (`androidboot.ar.*` in /proc/cmdline)
# BEFORE `magisk --post-fs-data`, so toggling Root, Presets, Modules, SELinux,
# Stealth, and Preinstalled Apps BEFORE clicking Start Emulation works on Boot 1!

MAGISKTMP="${1:-/debug_ramdisk}"
ODM_ROOT="/odm/andarium-root"
MAGISK="$MAGISKTMP/magisk"
ADB_DIR="/data/adb"
MAGISKBIN="$ADB_DIR/magisk"
STATE_DIR="$ADB_DIR/andarium"
LOG_FILE="$ADB_DIR/andarium-root.log"

DEFAULT_SELINUX="__DEFAULT_SELINUX__"
DEFAULT_DEBUGGABLE="__DEFAULT_DEBUGGABLE__"
DEFAULT_ADBROOT="__DEFAULT_ADBROOT__"
DEFAULT_STEALTH="__DEFAULT_STEALTH__"

mkdir -p "$ADB_DIR" "$STATE_DIR" "$STATE_DIR/run" "$STATE_DIR/ssh" "$MAGISKBIN" \
    "$ADB_DIR/modules" "$ADB_DIR/post-fs-data.d" "$ADB_DIR/post-mount.d" "$ADB_DIR/service.d" 2>/dev/null
chmod 0700 "$ADB_DIR" "$STATE_DIR" "$STATE_DIR/run" "$STATE_DIR/ssh" 2>/dev/null
chmod 0755 "$MAGISKBIN" "$ADB_DIR/modules" "$ADB_DIR/post-fs-data.d" "$ADB_DIR/post-mount.d" "$ADB_DIR/service.d" 2>/dev/null
chown 0:0 "$ADB_DIR" "$STATE_DIR" "$STATE_DIR/run" "$STATE_DIR/ssh" "$MAGISKBIN" \
    "$ADB_DIR/modules" "$ADB_DIR/post-fs-data.d" "$ADB_DIR/post-mount.d" "$ADB_DIR/service.d" 2>/dev/null

if [ -f "$LOG_FILE" ]; then
    LOG_SIZE="$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)"
    if [ "$LOG_SIZE" -gt 262144 ] 2>/dev/null; then
        tail -c 65536 "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null && mv "${LOG_FILE}.tmp" "$LOG_FILE"
    fi
fi

exec >> "$LOG_FILE" 2>&1
echo "=== [andarium_early_init v4] boot start (MAGISKTMP=$MAGISKTMP) ==="

# Helper: extract an `androidboot.ar.<key>=<val>` token from /proc/cmdline
get_cmdline_arg() {
    key="androidboot.ar.$1="
    for tok in $(cat /proc/cmdline 2>/dev/null); do
        case "$tok" in
            "${key}"*)
                printf '%s' "${tok#"$key"}"
                return 0
                ;;
        esac
    done
    return 1
}

read_setting() {
    if [ -f "$STATE_DIR/$1" ]; then
        val="$(cat "$STATE_DIR/$1" 2>/dev/null | tr -d '\r\n ')"
        [ -n "$val" ] && { printf '%s' "$val"; return 0; }
    fi
    printf '%s' "$2"
}

write_setting() {
    printf '%s\n' "$2" > "$STATE_DIR/$1"
    chmod 0600 "$STATE_DIR/$1" 2>/dev/null
}

# 0. Ingest live iOS Pre-Boot Studio or build-time config (`androidboot.ar.cfg` in /proc/cmdline)
AR_CFG="$(get_cmdline_arg cfg || true)"
AR_REV=""
if [ -n "$AR_CFG" ]; then
    OLD_IFS="$IFS"
    IFS=","
    set -- $AR_CFG
    IFS="$OLD_IFS"
    AR_VER="$1"; AR_REV="$2"; AR_PRESET="$3"; AR_ROOT="$4"; AR_SE="$5"
    AR_STEALTH="$6"; AR_ADBROOT="$7"; AR_DBG="$8"; AR_MODS="$9"
    shift 9 2>/dev/null || true
    AR_SVCS="${1:-001}"; AR_APPS="${2:-1111111111111}"; AR_ANIM="${3:-0.5}"
    AR_SWAP="${4:-100}"; AR_AWAKE="${5:-0}"; AR_DPI="${6:-0}"
    AR_PROXY="$(get_cmdline_arg proxy || true)"
fi

LAST_REV="$(read_setting applied_preboot_rev 0)"
if [ -n "$AR_REV" ] && [ "$AR_REV" != "$LAST_REV" ]; then
    echo "[early] applying pre-boot config rev=$AR_REV (prev=$LAST_REV, preset=${AR_PRESET:-mix}, root=${AR_ROOT:-1})"
    PREV_APPS="$(read_setting apps_mask '')"

    write_setting active_mode "${AR_PRESET:-mix}"
    write_setting root_enabled "${AR_ROOT:-1}"
    [ "$AR_SE" = "1" ] && write_setting selinux_mode enforcing || write_setting selinux_mode permissive
    [ "$AR_STEALTH" = "1" ] && write_setting stealth_mode on || write_setting stealth_mode off
    write_setting adbroot "${AR_ADBROOT:-1}"
    write_setting debuggable "${AR_DBG:-1}"
    write_setting mods_mask "${AR_MODS:-1111}"
    write_setting svcs_mask "${AR_SVCS:-001}"
    write_setting apps_mask "${AR_APPS:-1111111111111}"
    write_setting anim_scale "${AR_ANIM:-0.5}"
    write_setting swappiness "${AR_SWAP:-100}"
    write_setting stay_awake "${AR_AWAKE:-0}"
    [ -n "$AR_DPI" ] && [ "$AR_DPI" != "0" ] && write_setting dpi "$AR_DPI" || rm -f "$STATE_DIR/dpi"
    [ -n "$AR_PROXY" ] && [ "$AR_PROXY" != "none" ] && write_setting http_proxy "$AR_PROXY" || rm -f "$STATE_DIR/http_proxy"

    # If the user enabled additional apps in Pre-Boot Studio, re-run selective APK pass
    if [ "$AR_APPS" != "$PREV_APPS" ]; then
        rm -f "$STATE_DIR/.apps_provisioned_v4"
    fi

    # Extract service autostart bits (FSZ: Frida, SSH, Shizuku)
    F_AUTO="$(printf '%s' "${AR_SVCS:-001}" | cut -c1)"
    S_AUTO="$(printf '%s' "${AR_SVCS:-001}" | cut -c2)"
    Z_AUTO="$(printf '%s' "${AR_SVCS:-001}" | cut -c3)"
    [ "$F_AUTO" = "1" ] && write_setting frida_autostart 1 || write_setting frida_autostart 0
    [ "$S_AUTO" = "1" ] && write_setting ssh_autostart 1 || write_setting ssh_autostart 0
    [ "$Z_AUTO" = "1" ] && write_setting shizuku_autostart 1 || write_setting shizuku_autostart 0

    write_setting applied_preboot_rev "$AR_REV"
fi

ROOT_ENABLED="$(read_setting root_enabled 1)"
STEALTH="$(read_setting stealth_mode "$DEFAULT_STEALTH")"

# Apply zRAM swappiness immediately if configured
SWAP_VAL="$(read_setting swappiness 100)"
case "$SWAP_VAL" in
    ''|*[!0-9]*) ;;
    *) echo "$SWAP_VAL" > /proc/sys/vm/swappiness 2>/dev/null || true ;;
esac

# 1. SELinux mode (Root OFF or Stealth ON forces enforcing)
if [ "$ROOT_ENABLED" = "0" ] || [ "$STEALTH" = "on" ]; then
    SELINUX_MODE="enforcing"
else
    SELINUX_MODE="$(read_setting selinux_mode "$DEFAULT_SELINUX")"
fi
if [ "$SELINUX_MODE" = "permissive" ]; then
    echo 0 > /sys/fs/selinux/enforce 2>/dev/null || setenforce 0 2>/dev/null || true
    echo "[early] SELinux set to permissive"
else
    echo 1 > /sys/fs/selinux/enforce 2>/dev/null || setenforce 1 2>/dev/null || true
    echo "[early] SELinux set to enforcing"
fi

# 2. Populate /data/adb/magisk
BB="$MAGISKBIN/busybox"
[ -x "$BB" ] || BB="$ODM_ROOT/magisk-bin/busybox"

NEED_MAGISKBIN=0
for f in busybox magiskboot magiskinit magiskpolicy bootctl util_functions.sh boot_patch.sh; do
    [ -f "$MAGISKBIN/$f" ] || { NEED_MAGISKBIN=1; break; }
done
if [ "$NEED_MAGISKBIN" = "1" ] && [ -d "$ODM_ROOT/magisk-bin" ]; then
    echo "[early] populating $MAGISKBIN from $ODM_ROOT/magisk-bin"
    if [ -x "$BB" ]; then "$BB" cp -af "$ODM_ROOT/magisk-bin/." "$MAGISKBIN/"; else cp -af "$ODM_ROOT/magisk-bin/." "$MAGISKBIN/"; fi
    chown -R 0:0 "$MAGISKBIN" 2>/dev/null
    chmod 0755 "$MAGISKBIN" 2>/dev/null
    for f in "$MAGISKBIN"/*; do
        [ -f "$f" ] || continue
        case "$f" in *.jar) chmod 0644 "$f" 2>/dev/null ;; *) chmod 0755 "$f" 2>/dev/null ;; esac
    done
    [ -x "$MAGISK" ] && [ ! -e "$MAGISKBIN/magisk" ] && cp -f "$MAGISK" "$MAGISKBIN/magisk" 2>/dev/null && chmod 0755 "$MAGISKBIN/magisk" 2>/dev/null
    restorecon -R "$MAGISKBIN" 2>/dev/null || true
    [ -x "$MAGISKBIN/busybox" ] && BB="$MAGISKBIN/busybox"
fi

MAGISKPOLICY="$MAGISKBIN/magiskpolicy"
[ -x "$MAGISKPOLICY" ] || MAGISKPOLICY="$ODM_ROOT/magisk-bin/magiskpolicy"

# If Root was toggled OFF before Start Emulation, remove su symlink from PATH!
if [ "$ROOT_ENABLED" = "0" ]; then
    rm -f "$MAGISKTMP/su" 2>/dev/null || true
    echo "[early] ROOT TOGGLED OFF: removed $MAGISKTMP/su and enforcing stealth mode"
fi

# Expose CLI tools directly on root PATH ($MAGISKTMP)
if [ -f "$ODM_ROOT/scripts/andarium-ctl" ]; then
    ln -sf "$ODM_ROOT/scripts/andarium-ctl" "$MAGISKTMP/andarium-ctl" 2>/dev/null || true
    ln -sf "$ODM_ROOT/scripts/andarium-ctl" "$ADB_DIR/andarium-ctl" 2>/dev/null || true
fi
[ -f "$ODM_ROOT/scripts/andarium-termux-setup" ] && ln -sf "$ODM_ROOT/scripts/andarium-termux-setup" "$MAGISKTMP/andarium-termux-setup" 2>/dev/null || true
[ -f "$ODM_ROOT/scripts/andarium-shell-rc.sh" ] && [ ! -f "$STATE_DIR/profile" ] && cp -f "$ODM_ROOT/scripts/andarium-shell-rc.sh" "$STATE_DIR/profile" 2>/dev/null && chmod 0644 "$STATE_DIR/profile" 2>/dev/null || true
[ -x "$ODM_ROOT/tools/frida-server" ] && ln -sf "$ODM_ROOT/tools/frida-server" "$MAGISKTMP/frida-server" 2>/dev/null || true
if [ -d "$ODM_ROOT/tools/dropbear" ]; then
    for bin in dropbear dropbearkey dropbearconvert dbclient scp; do
        [ -x "$ODM_ROOT/tools/dropbear/$bin" ] && ln -sf "$ODM_ROOT/tools/dropbear/$bin" "$MAGISKTMP/$bin" 2>/dev/null || true
    done
fi
if [ -d "$ODM_ROOT/tools/cli" ]; then
    for bin in strace socat sqlite3 jq tcpdump; do
        [ -x "$ODM_ROOT/tools/cli/$bin" ] && ln -sf "$ODM_ROOT/tools/cli/$bin" "$MAGISKTMP/$bin" 2>/dev/null || true
    done
fi

# 3. Apply live SELinux rules for bundled modules
if [ -x "$MAGISKPOLICY" ]; then
    for rule in "$ODM_ROOT"/modules/*/sepolicy.rule; do
        [ -f "$rule" ] && "$MAGISKPOLICY" --live --apply "$rule" && echo "[early] applied live sepolicy: $rule" || true
    done
fi

# 4. Unlock ro.debuggable=1 and LineageOS adbroot_service (unless Root OFF or Stealth ON)
if [ "$ROOT_ENABLED" = "0" ] || [ "$STEALTH" = "on" ]; then
    DEBUGGABLE="0"; ADBROOT="0"
else
    DEBUGGABLE="$(read_setting debuggable "$DEFAULT_DEBUGGABLE")"
    ADBROOT="$(read_setting adbroot "$DEFAULT_ADBROOT")"
fi
[ "$DEBUGGABLE" = "1" ] && [ -x "$MAGISK" ] && "$MAGISK" resetprop ro.debuggable 1 2>/dev/null || true
if [ "$ADBROOT" = "1" ]; then
    mkdir -p /data/adbroot 2>/dev/null && chmod 0700 /data/adbroot && chown 0:0 /data/adbroot
    [ -f /data/adbroot/enabled ] || { printf '1' > /data/adbroot/enabled && chmod 0600 /data/adbroot/enabled && chown 0:0 /data/adbroot/enabled; }
    restorecon -R /data/adbroot 2>/dev/null || true
else
    mkdir -p /data/adbroot 2>/dev/null && printf '0' > /data/adbroot/enabled 2>/dev/null || true
fi

# 5. Seed magisk.db before magiskd starts
if [ ! -f "$ADB_DIR/magisk.db" ] && [ -f "$ODM_ROOT/config/magisk.db" ]; then
    cp -f "$ODM_ROOT/config/magisk.db" "$ADB_DIR/magisk.db"
    chown 0:0 "$ADB_DIR/magisk.db" 2>/dev/null; chmod 0600 "$ADB_DIR/magisk.db" 2>/dev/null
    restorecon "$ADB_DIR/magisk.db" 2>/dev/null || true
fi

# 6. First-boot module & custom overlay installation BEFORE magisk --post-fs-data
if [ ! -f "$STATE_DIR/.early_provisioned_v4" ]; then
    echo "[early] installing pre-bundled Magisk modules (v4)"

    if [ -d "$ODM_ROOT/modules/andarium_control" ] && [ ! -d "$ADB_DIR/modules/andarium_control" ]; then
        mkdir -p "$ADB_DIR/modules/andarium_control"
        "$BB" cp -af "$ODM_ROOT/modules/andarium_control/." "$ADB_DIR/modules/andarium_control/"
        chown -R 0:0 "$ADB_DIR/modules/andarium_control" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/andarium_control" "$ADB_DIR/modules/andarium_control/service.sh" \
            "$ADB_DIR/modules/andarium_control/action.sh" "$ADB_DIR/modules/andarium_control/webroot/cgi-bin/api" 2>/dev/null
        [ -f "$ADB_DIR/modules/andarium_control/system/etc/hosts" ] && chmod 0644 "$ADB_DIR/modules/andarium_control/system/etc/hosts" && chcon u:object_r:system_file:s0 "$ADB_DIR/modules/andarium_control/system/etc/hosts" 2>/dev/null || true
    fi

    if [ -d "$ODM_ROOT/modules/rezygisk" ] && [ ! -d "$ADB_DIR/modules/rezygisk" ]; then
        mkdir -p "$ADB_DIR/modules/rezygisk"
        "$BB" cp -af "$ODM_ROOT/modules/rezygisk/." "$ADB_DIR/modules/rezygisk/"
        chown -R 0:0 "$ADB_DIR/modules/rezygisk" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/rezygisk" "$ADB_DIR/modules/rezygisk/bin" "$ADB_DIR/modules/rezygisk/bin"/* \
            "$ADB_DIR/modules/rezygisk/post-fs-data.sh" "$ADB_DIR/modules/rezygisk/service.sh" "$ADB_DIR/modules/rezygisk/uninstall.sh" 2>/dev/null
        [ -d "$ADB_DIR/modules/rezygisk/lib" ] && chmod 0755 "$ADB_DIR/modules/rezygisk/lib" && chmod 0644 "$ADB_DIR/modules/rezygisk/lib"/* && chcon -R u:object_r:system_lib_file:s0 "$ADB_DIR/modules/rezygisk/lib" 2>/dev/null || true
        [ -d "$ADB_DIR/modules/rezygisk/lib64" ] && chmod 0755 "$ADB_DIR/modules/rezygisk/lib64" && chmod 0644 "$ADB_DIR/modules/rezygisk/lib64"/* && chcon -R u:object_r:system_lib_file:s0 "$ADB_DIR/modules/rezygisk/lib64" 2>/dev/null || true
        if [ -f "$ODM_ROOT/modules/rezygisk.sh" ]; then
            cp -f "$ODM_ROOT/modules/rezygisk.sh" "$ADB_DIR/post-fs-data.d/rezygisk.sh"
            cp -f "$ODM_ROOT/modules/rezygisk.sh" "$ADB_DIR/post-mount.d/rezygisk.sh"
            chmod 0755 "$ADB_DIR/post-fs-data.d/rezygisk.sh" "$ADB_DIR/post-mount.d/rezygisk.sh" 2>/dev/null
        fi
    fi

    if [ -d "$ODM_ROOT/modules/zygisk_vector" ] && [ ! -d "$ADB_DIR/modules/zygisk_vector" ]; then
        mkdir -p "$ADB_DIR/modules/zygisk_vector"
        "$BB" cp -af "$ODM_ROOT/modules/zygisk_vector/." "$ADB_DIR/modules/zygisk_vector/"
        chown -R 0:0 "$ADB_DIR/modules/zygisk_vector" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/zygisk_vector" "$ADB_DIR/modules/zygisk_vector/service.sh" \
            "$ADB_DIR/modules/zygisk_vector/action.sh" "$ADB_DIR/modules/zygisk_vector/uninstall.sh" 2>/dev/null
        chmod 0744 "$ADB_DIR/modules/zygisk_vector/daemon" "$ADB_DIR/modules/zygisk_vector/cli" 2>/dev/null
        [ -d "$ADB_DIR/modules/zygisk_vector/bin" ] && chown -R 0:2000 "$ADB_DIR/modules/zygisk_vector/bin" && chmod 0755 "$ADB_DIR/modules/zygisk_vector/bin" "$ADB_DIR/modules/zygisk_vector/bin"/* && chcon -R u:object_r:xposed_file:s0 "$ADB_DIR/modules/zygisk_vector/bin" 2>/dev/null || true
    fi

    if [ -d "$ODM_ROOT/modules/playintegrityfix" ] && [ ! -d "$ADB_DIR/modules/playintegrityfix" ]; then
        mkdir -p "$ADB_DIR/modules/playintegrityfix"
        "$BB" cp -af "$ODM_ROOT/modules/playintegrityfix/." "$ADB_DIR/modules/playintegrityfix/"
        chown -R 0:0 "$ADB_DIR/modules/playintegrityfix" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/playintegrityfix" "$ADB_DIR/modules/playintegrityfix"/*.sh 2>/dev/null || true
    fi

    if [ -d "$ODM_ROOT/modules/tricky_store" ] && [ ! -d "$ADB_DIR/modules/tricky_store" ]; then
        mkdir -p "$ADB_DIR/modules/tricky_store" "$ADB_DIR/tricky_store"
        "$BB" cp -af "$ODM_ROOT/modules/tricky_store/." "$ADB_DIR/modules/tricky_store/"
        chown -R 0:0 "$ADB_DIR/modules/tricky_store" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/tricky_store" "$ADB_DIR/modules/tricky_store/daemon" \
            "$ADB_DIR/modules/tricky_store/post-fs-data.sh" "$ADB_DIR/modules/tricky_store/service.sh" 2>/dev/null
        [ -f "$ODM_ROOT/config/tricky_store/keybox.xml" ] && [ ! -f "$ADB_DIR/tricky_store/keybox.xml" ] && cp -f "$ODM_ROOT/config/tricky_store/keybox.xml" "$ADB_DIR/tricky_store/keybox.xml"
        [ -f "$ODM_ROOT/config/tricky_store/target.txt" ] && [ ! -f "$ADB_DIR/tricky_store/target.txt" ] && cp -f "$ODM_ROOT/config/tricky_store/target.txt" "$ADB_DIR/tricky_store/target.txt"
        chown -R 0:0 "$ADB_DIR/tricky_store" 2>/dev/null
    fi

    if [ -d "$ODM_ROOT/modules/zygisk-assistant" ] && [ ! -d "$ADB_DIR/modules/zygisk-assistant" ]; then
        mkdir -p "$ADB_DIR/modules/zygisk-assistant"
        "$BB" cp -af "$ODM_ROOT/modules/zygisk-assistant/." "$ADB_DIR/modules/zygisk-assistant/"
        chown -R 0:0 "$ADB_DIR/modules/zygisk-assistant" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/zygisk-assistant" "$ADB_DIR/modules/zygisk-assistant"/*.sh 2>/dev/null || true
    fi

    if [ -d "$ODM_ROOT/custom/scripts/post-fs-data.d" ]; then
        for s in "$ODM_ROOT"/custom/scripts/post-fs-data.d/*.sh; do
            [ -f "$s" ] || continue
            bn="$(basename "$s")"
            cp -f "$s" "$ADB_DIR/post-fs-data.d/$bn" && chmod 0755 "$ADB_DIR/post-fs-data.d/$bn" && chown 0:0 "$ADB_DIR/post-fs-data.d/$bn"
        done
    fi
    if [ -d "$ODM_ROOT/custom/scripts/service.d" ]; then
        for s in "$ODM_ROOT"/custom/scripts/service.d/*.sh; do
            [ -f "$s" ] || continue
            bn="$(basename "$s")"
            cp -f "$s" "$ADB_DIR/service.d/$bn" && chmod 0755 "$ADB_DIR/service.d/$bn" && chown 0:0 "$ADB_DIR/service.d/$bn"
        done
    fi
    if [ -s "$ODM_ROOT/custom/authorized_keys" ] && [ ! -s "$STATE_DIR/ssh/authorized_keys" ]; then
        cp -f "$ODM_ROOT/custom/authorized_keys" "$STATE_DIR/ssh/authorized_keys"
        chmod 0600 "$STATE_DIR/ssh/authorized_keys" && chown 0:0 "$STATE_DIR/ssh/authorized_keys"
        printf '1\n' > "$STATE_DIR/ssh_autostart"
    fi

    touch "$STATE_DIR/.early_provisioned_v4"
fi

# 7. Sync per-module enable/disable flags with iOS Pre-Boot `mods_mask` (RVSA) & Root toggle
MODS_MASK="$(read_setting mods_mask '')"
if [ -n "$MODS_MASK" ]; then
    M_RZ="$(printf '%s' "$MODS_MASK" | cut -c1)"
    M_VC="$(printf '%s' "$MODS_MASK" | cut -c2)"
    M_ST="$(printf '%s' "$MODS_MASK" | cut -c3)"
    M_AB="$(printf '%s' "$MODS_MASK" | cut -c4)"

    if [ "$ROOT_ENABLED" = "0" ]; then
        M_RZ="0"; M_VC="0"
    fi
    set_mod_flag() {
        mdir="$ADB_DIR/modules/$1"
        [ -d "$mdir" ] || return 0
        if [ "$2" = "0" ]; then touch "$mdir/disable"; else rm -f "$mdir/disable"; fi
    }
    set_mod_flag rezygisk "$M_RZ"
    set_mod_flag zygisk_vector "$M_VC"
    set_mod_flag playintegrityfix "$M_ST"
    set_mod_flag tricky_store "$M_ST"
    set_mod_flag zygisk-assistant "$M_ST"

    if [ -d "$ADB_DIR/modules/andarium_control/system/etc" ]; then
        if [ "$M_AB" = "0" ]; then
            printf '127.0.0.1       localhost\n::1             ip6-localhost\n' > "$ADB_DIR/modules/andarium_control/system/etc/hosts"
        elif [ -f "$ODM_ROOT/config/hosts.adblock" ]; then
            cp -f "$ODM_ROOT/config/hosts.adblock" "$ADB_DIR/modules/andarium_control/system/etc/hosts"
            [ -f "$ODM_ROOT/custom/hosts" ] && { printf '\n# === Custom Hosts ===\n' >> "$ADB_DIR/modules/andarium_control/system/etc/hosts"; cat "$ODM_ROOT/custom/hosts" >> "$ADB_DIR/modules/andarium_control/system/etc/hosts"; }
        fi
        chmod 0644 "$ADB_DIR/modules/andarium_control/system/etc/hosts" 2>/dev/null || true
    fi
fi

echo "=== [andarium_early_init v4] done ==="
exit 0
