// SPDX-License-Identifier: GPL-2.0-or-later
// Android Crypto Tracer (javax.crypto.Cipher, SecretKeySpec, MessageDigest)
// Usage: frida -H 127.0.0.1:27042 -f <pkg> -l /odm/andarium-root/tools/frida-scripts/crypto-tracer.js

function toHex(bytes) {
    if (!bytes) return "";
    var out = [];
    for (var i = 0; i < Math.min(bytes.length, 128); i++) {
        out.push(("0" + (bytes[i] & 0xff).toString(16)).slice(-2));
    }
    return out.join("") + (bytes.length > 128 ? "...(" + bytes.length + "B)" : "");
}

Java.perform(function () {
    console.log("[andarium-crypto] Tracing Cipher & SecretKeySpec...");
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
        console.log("[SecretKeySpec] algo=" + algo + " key=" + toHex(key));
        return this.$init(key, algo);
    };

    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
        var res = this.doFinal(input);
        console.log("[Cipher.doFinal] algo=" + this.getAlgorithm() + " in=" + toHex(input) + " out=" + toHex(res));
        return res;
    };
});
