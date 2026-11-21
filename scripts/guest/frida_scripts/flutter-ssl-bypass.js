// SPDX-License-Identifier: GPL-2.0-or-later
// Flutter ARM64 BoringSSL Certificate Verification Bypass
// Usage: frida -H 127.0.0.1:27042 -f <pkg> -l /odm/andarium-root/tools/frida-scripts/flutter-ssl-bypass.js

function hookFlutter(mod) {
    console.log("[andarium-flutter] Scanning " + mod.name + " (" + mod.size + " bytes)...");
    // Standard ARM64 BoringSSL ssl_crypto_x509_session_verify_cert_chain prologue patterns
    var patterns = [
        "FF 03 05 D1 FD 7B 0F A9",
        "FF 83 01 D1 FA 67 01 A9",
        "FF 43 01 D1 FE 67 01 A9",
        "F8 5F BC A9 F6 57 01 A9 F4 4F 02 A9 FD 7B 03 A9"
    ];
    var hooked = false;
    patterns.forEach(function (pat) {
        if (hooked) return;
        Memory.scan(mod.base, mod.size, pat, {
            onMatch: function (address) {
                console.log("[andarium-flutter] Candidate match at " + address);
                Interceptor.attach(address, {
                    onLeave: function (retval) {
                        retval.replace(ptr(1));
                    }
                });
                hooked = true;
            },
            onComplete: function () {}
        });
    });
    if (!hooked) {
        console.log("[andarium-flutter] No standard pattern matched; try ssl-pinning-bypass.js or reflutter.");
    }
}

var timer = setInterval(function () {
    var m = Process.findModuleByName("libflutter.so");
    if (m) {
        clearInterval(timer);
        hookFlutter(m);
    }
}, 250);
