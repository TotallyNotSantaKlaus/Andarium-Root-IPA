#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Andarium Root Control late_start service script (v3).

MODDIR="${0%/*}"
STATE_DIR="/data/adb/andarium"
CTL="/odm/andarium-root/scripts/andarium-ctl"
MAGISK="$(command -v magisk 2>/dev/null || echo /debug_ramdisk/magisk)"
[ -x "$MAGISK" ] || MAGISK="/sbin/magisk"

DEFAULT_STEALTH="__DEFAULT_STEALTH__"
DEFAULT_DEBUGGABLE="__DEFAULT_DEBUGGABLE__"

read_state() {
    if [ -f "$STATE_DIR/$1" ]; then
        val="$(cat "$STATE_DIR/$1" 2>/dev/null | tr -d '\r\n ')"
        [ -n "$val" ] && { printf '%s' "$val"; return 0; }
    fi
    printf '%s' "$2"
}

STEALTH="$(read_state stealth_mode "$DEFAULT_STEALTH")"
DEBUGGABLE="$(read_state debuggable "$DEFAULT_DEBUGGABLE")"

# Coordinate ro.debuggable with PlayIntegrityFork / Zygisk-Assistant:
if [ "$STEALTH" != "on" ] && [ "$DEBUGGABLE" = "1" ] && [ -x "$MAGISK" ]; then
    "$MAGISK" resetprop ro.debuggable 1 2>/dev/null || true
fi

if [ -x "$CTL" ]; then
    "$CTL" webui start >/dev/null 2>&1 || true
    "$CTL" certs sync >/dev/null 2>&1 || true

    if [ "$STEALTH" != "on" ]; then
        if [ "$(read_state ssh_autostart 0)" = "1" ]; then
            "$CTL" ssh start >/dev/null 2>&1 || true
        fi
        if [ "$(read_state frida_autostart 0)" = "1" ]; then
            "$CTL" frida start >/dev/null 2>&1 || true
        fi
    fi
fi

(
    i=0
    while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ] && [ "$i" -lt 90 ]; do
        sleep 1
        i=$((i + 1))
    done
    sleep 2
    if [ "$(read_state stealth_mode "$DEFAULT_STEALTH")" != "on" ] && [ "$(read_state debuggable "$DEFAULT_DEBUGGABLE")" = "1" ] && [ -x "$MAGISK" ]; then
        "$MAGISK" resetprop ro.debuggable 1 2>/dev/null || true
    fi
) &

exit 0
