#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Andarium Root synchronous post-fs-data bootstrapper (v2).
# Runs as u:r:magisk:s0 (UID 0) immediately before `magisk --post-fs-data`.

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

# Ensure /data/adb exists BEFORE magisk --post-fs-data checks SECURE_DIR
mkdir -p "$ADB_DIR" "$STATE_DIR" "$STATE_DIR/run" "$STATE_DIR/ssh" "$MAGISKBIN" \
    "$ADB_DIR/modules" "$ADB_DIR/post-fs-data.d" "$ADB_DIR/post-mount.d" "$ADB_DIR/service.d" 2>/dev/null
chmod 0700 "$ADB_DIR" "$STATE_DIR" "$STATE_DIR/run" "$STATE_DIR/ssh" 2>/dev/null
chmod 0755 "$MAGISKBIN" "$ADB_DIR/modules" "$ADB_DIR/post-fs-data.d" "$ADB_DIR/post-mount.d" "$ADB_DIR/service.d" 2>/dev/null
chown 0:0 "$ADB_DIR" "$STATE_DIR" "$STATE_DIR/run" "$STATE_DIR/ssh" "$MAGISKBIN" \
    "$ADB_DIR/modules" "$ADB_DIR/post-fs-data.d" "$ADB_DIR/post-mount.d" "$ADB_DIR/service.d" 2>/dev/null

# Keep log bounded (~256 KiB)
if [ -f "$LOG_FILE" ]; then
    LOG_SIZE="$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)"
    if [ "$LOG_SIZE" -gt 262144 ] 2>/dev/null; then
        tail -c 65536 "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null && mv "${LOG_FILE}.tmp" "$LOG_FILE"
    fi
fi

exec >> "$LOG_FILE" 2>&1
echo "=== [andarium_early_init] boot start (MAGISKTMP=$MAGISKTMP) ==="

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

STEALTH="$(read_setting stealth_mode "$DEFAULT_STEALTH")"

# 1. SELinux mode (Stealth Mode forces enforcing; otherwise saved/default)
if [ "$STEALTH" = "on" ]; then
    SELINUX_MODE="enforcing"
else
    SELINUX_MODE="$(read_setting selinux_mode "$DEFAULT_SELINUX")"
fi

if [ "$SELINUX_MODE" = "permissive" ]; then
    echo 0 > /sys/fs/selinux/enforce 2>/dev/null || setenforce 0 2>/dev/null || true
    echo "[early] SELinux set to permissive (enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null))"
else
    echo 1 > /sys/fs/selinux/enforce 2>/dev/null || setenforce 1 2>/dev/null || true
    echo "[early] SELinux kept enforcing (enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null))"
fi

# 2. Populate /data/adb/magisk (eliminates Magisk "Requires Additional Setup" prompt)
BB="$MAGISKBIN/busybox"
[ -x "$BB" ] || BB="$ODM_ROOT/magisk-bin/busybox"

NEED_MAGISKBIN=0
for f in busybox magiskboot magiskinit magiskpolicy bootctl util_functions.sh boot_patch.sh; do
    if [ ! -f "$MAGISKBIN/$f" ]; then
        NEED_MAGISKBIN=1
        break
    fi
done

if [ "$NEED_MAGISKBIN" = "1" ] && [ -d "$ODM_ROOT/magisk-bin" ]; then
    echo "[early] populating $MAGISKBIN from $ODM_ROOT/magisk-bin"
    if [ -x "$BB" ]; then
        "$BB" cp -af "$ODM_ROOT/magisk-bin/." "$MAGISKBIN/"
    else
        cp -af "$ODM_ROOT/magisk-bin/." "$MAGISKBIN/"
    fi
    chown -R 0:0 "$MAGISKBIN" 2>/dev/null
    chmod 0755 "$MAGISKBIN" 2>/dev/null
    for f in "$MAGISKBIN"/*; do
        [ -f "$f" ] || continue
        case "$f" in
            *.jar) chmod 0644 "$f" 2>/dev/null ;;
            *) chmod 0755 "$f" 2>/dev/null ;;
        esac
    done
    if [ -x "$MAGISK" ] && [ ! -e "$MAGISKBIN/magisk" ]; then
        cp -f "$MAGISK" "$MAGISKBIN/magisk" 2>/dev/null
        chmod 0755 "$MAGISKBIN/magisk" 2>/dev/null
    fi
    restorecon -R "$MAGISKBIN" 2>/dev/null || true
    [ -x "$MAGISKBIN/busybox" ] && BB="$MAGISKBIN/busybox"
fi

MAGISKPOLICY="$MAGISKBIN/magiskpolicy"
[ -x "$MAGISKPOLICY" ] || MAGISKPOLICY="$ODM_ROOT/magisk-bin/magiskpolicy"

# Expose CLI tools directly on root PATH ($MAGISKTMP) on every boot
if [ -f "$ODM_ROOT/scripts/andarium-ctl" ]; then
    ln -sf "$ODM_ROOT/scripts/andarium-ctl" "$MAGISKTMP/andarium-ctl" 2>/dev/null || true
    ln -sf "$ODM_ROOT/scripts/andarium-ctl" "$ADB_DIR/andarium-ctl" 2>/dev/null || true
fi
if [ -f "$ODM_ROOT/scripts/andarium-termux-setup" ]; then
    ln -sf "$ODM_ROOT/scripts/andarium-termux-setup" "$MAGISKTMP/andarium-termux-setup" 2>/dev/null || true
fi
if [ -f "$ODM_ROOT/scripts/andarium-shell-rc.sh" ] && [ ! -f "$STATE_DIR/profile" ]; then
    cp -f "$ODM_ROOT/scripts/andarium-shell-rc.sh" "$STATE_DIR/profile" 2>/dev/null || true
    chmod 0644 "$STATE_DIR/profile" 2>/dev/null || true
fi
if [ -x "$ODM_ROOT/tools/frida-server" ]; then
    ln -sf "$ODM_ROOT/tools/frida-server" "$MAGISKTMP/frida-server" 2>/dev/null || true
fi
if [ -d "$ODM_ROOT/tools/dropbear" ]; then
    for bin in dropbear dropbearkey dropbearconvert dbclient scp; do
        if [ -x "$ODM_ROOT/tools/dropbear/$bin" ]; then
            ln -sf "$ODM_ROOT/tools/dropbear/$bin" "$MAGISKTMP/$bin" 2>/dev/null || true
        fi
    done
fi
if [ -d "$ODM_ROOT/tools/cli" ]; then
    for bin in strace socat sqlite3 jq tcpdump; do
        if [ -x "$ODM_ROOT/tools/cli/$bin" ]; then
            ln -sf "$ODM_ROOT/tools/cli/$bin" "$MAGISKTMP/$bin" 2>/dev/null || true
        fi
    done
fi

# 3. Apply live SELinux rules for ALL bundled modules so custom types exist on Boot 1
if [ -x "$MAGISKPOLICY" ]; then
    for rule in "$ODM_ROOT"/modules/*/sepolicy.rule; do
        if [ -f "$rule" ]; then
            "$MAGISKPOLICY" --live --apply "$rule" && echo "[early] applied live sepolicy: $rule" || echo "[early] warn: sepolicy apply failed: $rule"
        fi
    done
fi

# 4. Unlock ro.debuggable=1 and LineageOS adbroot_service (unless Stealth Mode is on)
if [ "$STEALTH" = "on" ]; then
    DEBUGGABLE="0"
    ADBROOT="0"
else
    DEBUGGABLE="$(read_setting debuggable "$DEFAULT_DEBUGGABLE")"
    ADBROOT="$(read_setting adbroot "$DEFAULT_ADBROOT")"
fi

if [ "$DEBUGGABLE" = "1" ] && [ -x "$MAGISK" ]; then
    "$MAGISK" resetprop ro.debuggable 1 && echo "[early] resetprop ro.debuggable=1" || echo "[early] warn: resetprop ro.debuggable failed"
fi

if [ "$ADBROOT" = "1" ]; then
    mkdir -p /data/adbroot 2>/dev/null
    chmod 0700 /data/adbroot 2>/dev/null
    chown 0:0 /data/adbroot 2>/dev/null
    if [ ! -f /data/adbroot/enabled ]; then
        printf '1' > /data/adbroot/enabled
        chmod 0600 /data/adbroot/enabled 2>/dev/null
        chown 0:0 /data/adbroot/enabled 2>/dev/null
        echo "[early] initialized /data/adbroot/enabled=1"
    fi
    restorecon -R /data/adbroot 2>/dev/null || true
fi

# 5. Seed magisk.db before magiskd starts
if [ ! -f "$ADB_DIR/magisk.db" ] && [ -f "$ODM_ROOT/config/magisk.db" ]; then
    echo "[early] seeding $ADB_DIR/magisk.db"
    cp -f "$ODM_ROOT/config/magisk.db" "$ADB_DIR/magisk.db"
    chown 0:0 "$ADB_DIR/magisk.db" 2>/dev/null
    chmod 0600 "$ADB_DIR/magisk.db" 2>/dev/null
    restorecon "$ADB_DIR/magisk.db" 2>/dev/null || true
fi

# 6. First-boot module & custom overlay installation BEFORE magisk --post-fs-data
if [ ! -f "$STATE_DIR/.early_provisioned_v2" ]; then
    echo "[early] installing pre-bundled Magisk modules (v2)"

    # 6a. Andarium Root Control module (WebUI + localhost dashboard + systemless hosts)
    if [ -d "$ODM_ROOT/modules/andarium_control" ] && [ ! -d "$ADB_DIR/modules/andarium_control" ]; then
        mkdir -p "$ADB_DIR/modules/andarium_control"
        "$BB" cp -af "$ODM_ROOT/modules/andarium_control/." "$ADB_DIR/modules/andarium_control/"
        chown -R 0:0 "$ADB_DIR/modules/andarium_control" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/andarium_control" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/andarium_control/service.sh" "$ADB_DIR/modules/andarium_control/action.sh" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/andarium_control/webroot/cgi-bin/api" 2>/dev/null
        if [ -f "$ADB_DIR/modules/andarium_control/system/etc/hosts" ]; then
            chmod 0644 "$ADB_DIR/modules/andarium_control/system/etc/hosts" 2>/dev/null
            chcon u:object_r:system_file:s0 "$ADB_DIR/modules/andarium_control/system/etc/hosts" 2>/dev/null || true
        fi
        echo "[early] installed module: andarium_control"
    fi

    # 6b. ReZygisk
    if [ -d "$ODM_ROOT/modules/rezygisk" ] && [ ! -d "$ADB_DIR/modules/rezygisk" ]; then
        mkdir -p "$ADB_DIR/modules/rezygisk"
        "$BB" cp -af "$ODM_ROOT/modules/rezygisk/." "$ADB_DIR/modules/rezygisk/"
        chown -R 0:0 "$ADB_DIR/modules/rezygisk" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/rezygisk" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/rezygisk/bin" "$ADB_DIR/modules/rezygisk/bin"/* 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/rezygisk/post-fs-data.sh" "$ADB_DIR/modules/rezygisk/service.sh" "$ADB_DIR/modules/rezygisk/uninstall.sh" 2>/dev/null
        if [ -d "$ADB_DIR/modules/rezygisk/lib" ]; then
            chmod 0755 "$ADB_DIR/modules/rezygisk/lib" 2>/dev/null
            chmod 0644 "$ADB_DIR/modules/rezygisk/lib"/* 2>/dev/null
            chcon -R u:object_r:system_lib_file:s0 "$ADB_DIR/modules/rezygisk/lib" 2>/dev/null || true
        fi
        if [ -d "$ADB_DIR/modules/rezygisk/lib64" ]; then
            chmod 0755 "$ADB_DIR/modules/rezygisk/lib64" 2>/dev/null
            chmod 0644 "$ADB_DIR/modules/rezygisk/lib64"/* 2>/dev/null
            chcon -R u:object_r:system_lib_file:s0 "$ADB_DIR/modules/rezygisk/lib64" 2>/dev/null || true
        fi
        if [ -f "$ODM_ROOT/modules/rezygisk.sh" ]; then
            cp -f "$ODM_ROOT/modules/rezygisk.sh" "$ADB_DIR/post-fs-data.d/rezygisk.sh"
            cp -f "$ODM_ROOT/modules/rezygisk.sh" "$ADB_DIR/post-mount.d/rezygisk.sh"
            chmod 0755 "$ADB_DIR/post-fs-data.d/rezygisk.sh" "$ADB_DIR/post-mount.d/rezygisk.sh" 2>/dev/null
            chown 0:0 "$ADB_DIR/post-fs-data.d/rezygisk.sh" "$ADB_DIR/post-mount.d/rezygisk.sh" 2>/dev/null
        fi
        echo "[early] installed module: rezygisk"
    fi

    # 6c. Vector (JingMatrix LSPosed for Android 8.1-17)
    if [ -d "$ODM_ROOT/modules/zygisk_vector" ] && [ ! -d "$ADB_DIR/modules/zygisk_vector" ]; then
        mkdir -p "$ADB_DIR/modules/zygisk_vector"
        "$BB" cp -af "$ODM_ROOT/modules/zygisk_vector/." "$ADB_DIR/modules/zygisk_vector/"
        chown -R 0:0 "$ADB_DIR/modules/zygisk_vector" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/zygisk_vector" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/zygisk_vector/service.sh" "$ADB_DIR/modules/zygisk_vector/action.sh" "$ADB_DIR/modules/zygisk_vector/uninstall.sh" 2>/dev/null
        chmod 0744 "$ADB_DIR/modules/zygisk_vector/daemon" "$ADB_DIR/modules/zygisk_vector/cli" 2>/dev/null
        if [ -d "$ADB_DIR/modules/zygisk_vector/bin" ]; then
            chown -R 0:2000 "$ADB_DIR/modules/zygisk_vector/bin" 2>/dev/null
            chmod 0755 "$ADB_DIR/modules/zygisk_vector/bin" "$ADB_DIR/modules/zygisk_vector/bin"/* 2>/dev/null
            chcon -R u:object_r:xposed_file:s0 "$ADB_DIR/modules/zygisk_vector/bin" 2>/dev/null || true
        fi
        echo "[early] installed module: zygisk_vector"
    fi

    # 6d. PlayIntegrityFork (v19)
    if [ -d "$ODM_ROOT/modules/playintegrityfix" ] && [ ! -d "$ADB_DIR/modules/playintegrityfix" ]; then
        mkdir -p "$ADB_DIR/modules/playintegrityfix"
        "$BB" cp -af "$ODM_ROOT/modules/playintegrityfix/." "$ADB_DIR/modules/playintegrityfix/"
        chown -R 0:0 "$ADB_DIR/modules/playintegrityfix" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/playintegrityfix" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/playintegrityfix"/*.sh 2>/dev/null || true
        echo "[early] installed module: playintegrityfix"
    fi

    # 6e. TrickyStore (v1.4.1) + default /data/adb/tricky_store config
    if [ -d "$ODM_ROOT/modules/tricky_store" ] && [ ! -d "$ADB_DIR/modules/tricky_store" ]; then
        mkdir -p "$ADB_DIR/modules/tricky_store"
        "$BB" cp -af "$ODM_ROOT/modules/tricky_store/." "$ADB_DIR/modules/tricky_store/"
        chown -R 0:0 "$ADB_DIR/modules/tricky_store" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/tricky_store" "$ADB_DIR/modules/tricky_store/daemon" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/tricky_store/post-fs-data.sh" "$ADB_DIR/modules/tricky_store/service.sh" 2>/dev/null
        mkdir -p "$ADB_DIR/tricky_store"
        if [ -f "$ODM_ROOT/config/tricky_store/keybox.xml" ] && [ ! -f "$ADB_DIR/tricky_store/keybox.xml" ]; then
            cp -f "$ODM_ROOT/config/tricky_store/keybox.xml" "$ADB_DIR/tricky_store/keybox.xml"
        fi
        if [ -f "$ODM_ROOT/config/tricky_store/target.txt" ] && [ ! -f "$ADB_DIR/tricky_store/target.txt" ]; then
            cp -f "$ODM_ROOT/config/tricky_store/target.txt" "$ADB_DIR/tricky_store/target.txt"
        fi
        chown -R 0:0 "$ADB_DIR/tricky_store" 2>/dev/null
        echo "[early] installed module: tricky_store"
    fi

    # 6f. Zygisk Assistant (v2.1.4)
    if [ -d "$ODM_ROOT/modules/zygisk-assistant" ] && [ ! -d "$ADB_DIR/modules/zygisk-assistant" ]; then
        mkdir -p "$ADB_DIR/modules/zygisk-assistant"
        "$BB" cp -af "$ODM_ROOT/modules/zygisk-assistant/." "$ADB_DIR/modules/zygisk-assistant/"
        chown -R 0:0 "$ADB_DIR/modules/zygisk-assistant" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/zygisk-assistant" 2>/dev/null
        chmod 0755 "$ADB_DIR/modules/zygisk-assistant"/*.sh 2>/dev/null || true
        echo "[early] installed module: zygisk-assistant"
    fi

    # 6g. Drop-in custom scripts (post-fs-data.d & service.d) and SSH authorized_keys
    if [ -d "$ODM_ROOT/custom/scripts/post-fs-data.d" ]; then
        for s in "$ODM_ROOT"/custom/scripts/post-fs-data.d/*.sh; do
            [ -f "$s" ] || continue
            bn="$(basename "$s")"
            cp -f "$s" "$ADB_DIR/post-fs-data.d/$bn"
            chmod 0755 "$ADB_DIR/post-fs-data.d/$bn"
            chown 0:0 "$ADB_DIR/post-fs-data.d/$bn"
            echo "[early] deployed custom post-fs-data.d/$bn"
        done
    fi
    if [ -d "$ODM_ROOT/custom/scripts/service.d" ]; then
        for s in "$ODM_ROOT"/custom/scripts/service.d/*.sh; do
            [ -f "$s" ] || continue
            bn="$(basename "$s")"
            cp -f "$s" "$ADB_DIR/service.d/$bn"
            chmod 0755 "$ADB_DIR/service.d/$bn"
            chown 0:0 "$ADB_DIR/service.d/$bn"
            echo "[early] deployed custom service.d/$bn"
        done
    fi
    if [ -s "$ODM_ROOT/custom/authorized_keys" ] && [ ! -s "$STATE_DIR/ssh/authorized_keys" ]; then
        cp -f "$ODM_ROOT/custom/authorized_keys" "$STATE_DIR/ssh/authorized_keys"
        chmod 0600 "$STATE_DIR/ssh/authorized_keys"
        chown 0:0 "$STATE_DIR/ssh/authorized_keys"
        printf '1\n' > "$STATE_DIR/ssh_autostart"
        echo "[early] installed custom SSH authorized_keys and enabled ssh_autostart"
    fi

    touch "$STATE_DIR/.early_provisioned_v2"
    echo "[early] first-boot early provisioning complete"
fi

echo "=== [andarium_early_init] done ==="
exit 0
