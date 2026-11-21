// SPDX-License-Identifier: GPL-2.0-or-later
// Android Root Detection Bypass (Java + Native libc access/fopen/stat)
// Usage: frida -H 127.0.0.1:27042 -f <pkg> -l /odm/andarium-root/tools/frida-scripts/root-detection-bypass.js

var ROOT_PATHS = [
    "su", "magisk", "busybox", "Superuser", "superuser", "frida", "xposed",
    "lsposed", "vector", "rezygisk", "zygisk", "/data/adb", "/debug_ramdisk"
];

var ROOT_PKGS = [
    "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
    "io.github.vvb2060.magisk", "me.weishu.kernelsu", "org.matrix.vector.manager"
];

function isRootPath(p) {
    if (!p) return false;
    for (var i = 0; i < ROOT_PATHS.length; i++) {
        if (p.indexOf(ROOT_PATHS[i]) !== -1) return true;
    }
    return false;
}

// Native libc hooks
["access", "faccessat", "fopen", "open", "openat", "stat", "lstat", "__xstat"].forEach(function (fn) {
    var addr = Module.findExportByName("libc.so", fn);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            var idx = (fn === "faccessat" || fn === "openat") ? 1 : 0;
            try {
                var path = args[idx].readUtf8String();
                if (isRootPath(path)) {
                    this.hide = true;
                    this.path = path;
                }
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (this.hide) {
                retval.replace(fn === "fopen" ? ptr(0) : ptr(-1));
            }
        }
    });
});

Java.perform(function () {
    console.log("[andarium-rootbypass] Hooking Java root checks...");

    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
        var p = this.getAbsolutePath();
        if (isRootPath(p)) return false;
        return this.exists();
    };

    var Build = Java.use("android.os.Build");
    try { Build.TAGS.value = "release-keys"; } catch (e) {}

    var Runtime = Java.use("java.lang.Runtime");
    var IOException = Java.use("java.io.IOException");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
        if (cmd && (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1 || cmd.indexOf("magisk") !== -1)) {
            throw IOException.$new("Permission denied");
        }
        return this.exec(cmd);
    };

    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        var NameNotFound = Java.use("android.content.pm.PackageManager$NameNotFoundException");
        PM.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
            if (ROOT_PKGS.indexOf(pkg) !== -1) throw NameNotFound.$new(pkg);
            return this.getPackageInfo(pkg, flags);
        };
    } catch (e) {}

    console.log("[andarium-rootbypass] Hooks active.");
});
