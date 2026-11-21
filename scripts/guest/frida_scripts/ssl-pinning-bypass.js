// SPDX-License-Identifier: GPL-2.0-or-later
// Universal Android SSL Pinning Bypass (TrustManager, Conscrypt, OkHttp3, WebView)
// Usage: frida -H 127.0.0.1:27042 -f <pkg> -l /odm/andarium-root/tools/frida-scripts/ssl-pinning-bypass.js

Java.perform(function () {
    console.log("[andarium-ssl] Initializing universal Android SSL pinning bypass...");

    // 1. Android Conscrypt TrustManagerImpl (Android 7 - 17)
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[andarium-ssl] Conscrypt verifyChain bypassed for " + host);
            return untrustedChain;
        };
    } catch (e) {}

    try {
        var ArrayList = Java.use("java.util.ArrayList");
        var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TMI.checkTrustedRecursive.implementation = function () {
            console.log("[andarium-ssl] Conscrypt checkTrustedRecursive bypassed");
            return ArrayList.$new();
        };
    } catch (e) {}

    // 2. SSLContext.init custom TrustManager
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "dev.andarium.TrustAllManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom")
            .implementation = function (km, tm, sr) {
                console.log("[andarium-ssl] SSLContext.init hooked");
                this.init(km, TrustManagers, sr);
            };
    } catch (e) {}

    // 3. OkHttp3 CertificatePinner
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function (host, certs) {
            console.log("[andarium-ssl] OkHttp3 CertificatePinner bypassed for " + host);
        };
        CertPinner.check$okhttp.overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function (host, fn) {
            console.log("[andarium-ssl] OkHttp3 check$okhttp bypassed for " + host);
        };
    } catch (e) {}

    // 4. WebViewClient onReceivedSslError
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, err) {
            console.log("[andarium-ssl] WebViewClient SSL error proceeded");
            handler.proceed();
        };
    } catch (e) {}

    console.log("[andarium-ssl] Hooks active.");
});
