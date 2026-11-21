// SPDX-License-Identifier: GPL-2.0-or-later
// Android Intent & Activity Monitor
// Usage: frida -H 127.0.0.1:27042 -f <pkg> -l /odm/andarium-root/tools/frida-scripts/intent-monitor.js

Java.perform(function () {
    console.log("[andarium-intent] Monitoring Activity / Broadcast Intents...");
    var ContextWrapper = Java.use("android.content.ContextWrapper");
    ContextWrapper.startActivity.overload("android.content.Intent").implementation = function (intent) {
        console.log("[startActivity] " + intent.toUri(0));
        return this.startActivity(intent);
    };
    ContextWrapper.sendBroadcast.overload("android.content.Intent").implementation = function (intent) {
        console.log("[sendBroadcast] " + intent.toUri(0));
        return this.sendBroadcast(intent);
    };
});
