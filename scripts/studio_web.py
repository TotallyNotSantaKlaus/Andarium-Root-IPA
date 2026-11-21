#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Localhost-only Web Builder Studio for Andarium Root IPA (v4).

Zero external dependencies. Serves an interactive configuration & build studio
on http://127.0.0.1:8765 allowing users to pick Role Presets, toggle Root ON/OFF
or Build-Time Unrooted, select any of the 4 custom iOS icon themes with live
previews, pick individual preinstalled apps (13 APKs) with live IPA size
estimation, export/import `andarium-config.json`, and trigger a full verified
build (via WSL2 on Windows or directly on Linux) with streaming build logs.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import secrets
import shutil
import socketserver
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
MANIFESTS_DIR = ROOT_DIR / "manifests"
DOCS_DIR = ROOT_DIR / "docs"
DIST_DIR = ROOT_DIR / "dist"
DEFAULT_CONFIG_PATH = ROOT_DIR / "andarium-config.json"

SESSION_TOKEN = secrets.token_hex(16)
BUILD_LOCK = threading.Lock()
BUILD_STATE: dict[str, object] = {
    "running": False,
    "rc": None,
    "output_ipa": "",
    "logs": [],
}

STUDIO_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Andarium Root Builder Studio v4</title>
<style>
  :root {
    --bg: #070c0a;
    --panel: #0e1815;
    --panel2: #13221d;
    --border: #1e3830;
    --accent: #34f5a1;
    --accent-dim: rgba(52,245,161,0.13);
    --warn: #ffb84d;
    --danger: #ff5c77;
    --text: #eaf7f1;
    --muted: #84a699;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 20px; background: radial-gradient(circle at 50% -10%, #113025 0%, var(--bg) 48%);
    color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    font-size: 14px; line-height: 1.45;
  }
  .wrap { max-width: 1120px; margin: 0 auto; }
  header {
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
    gap: 14px; margin-bottom: 18px; padding-bottom: 14px; border-bottom: 1px solid var(--border);
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .badge {
    width: 46px; height: 46px; border-radius: 13px; border: 1.5px solid var(--accent);
    background: linear-gradient(135deg, #103226, #06120d); color: var(--accent);
    display: grid; place-items: center; font-weight: 800; font-size: 24px;
    box-shadow: 0 0 24px rgba(52,245,161,0.18);
  }
  h1 { margin: 0; font-size: 22px; letter-spacing: -0.3px; }
  .sub { color: var(--muted); font-size: 12.5px; }
  .pill-stat {
    background: var(--panel); border: 1px solid var(--border); border-radius: 999px;
    padding: 7px 14px; font-size: 12.5px; color: var(--accent); font-weight: 600;
  }
  .grid { display: grid; grid-template-columns: 1.35fr 1fr; gap: 16px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 15px; padding: 16px 18px; margin-bottom: 16px;
  }
  .card h2 {
    margin: 0 0 12px; font-size: 12.5px; color: var(--accent);
    text-transform: uppercase; letter-spacing: 0.8px;
  }
  .preset-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 9px; }
  @media (max-width: 640px) { .preset-grid { grid-template-columns: repeat(2, 1fr); } }
  .preset-btn {
    text-align: left; padding: 11px 12px; border-radius: 12px;
    border: 1px solid var(--border); background: #0a1310; color: var(--text);
    cursor: pointer; transition: 0.14s ease;
  }
  .preset-btn:hover { border-color: #2f5c4e; }
  .preset-btn.active { border-color: var(--accent); background: var(--accent-dim); box-shadow: 0 0 16px rgba(52,245,161,0.12); }
  .preset-btn .pt { font-weight: 700; font-size: 13.5px; margin-bottom: 4px; }
  .preset-btn .pd { font-size: 11.5px; color: var(--muted); line-height: 1.35; }
  .icon-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; }
  @media (max-width: 640px) { .icon-grid { grid-template-columns: repeat(3, 1fr); } }
  .icon-card {
    display: flex; flex-direction: column; align-items: center; gap: 6px;
    padding: 10px 6px; border-radius: 12px; border: 1px solid var(--border);
    background: #0a1310; cursor: pointer; text-align: center; transition: 0.14s;
  }
  .icon-card.active { border-color: var(--accent); background: var(--accent-dim); }
  .icon-card img, .icon-placeholder {
    width: 64px; height: 64px; border-radius: 15px; object-fit: cover;
    border: 1px solid rgba(255,255,255,0.1);
  }
  .icon-placeholder {
    display: grid; place-items: center; background: #162420; color: var(--muted); font-size: 11px; font-weight: 700;
  }
  .icon-card span { font-size: 12px; font-weight: 600; }
  .row {
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
    padding: 9px 0; border-top: 1px solid rgba(255,255,255,0.05);
  }
  .row:first-of-type { border-top: none; padding-top: 2px; }
  .rt { font-weight: 600; font-size: 13.5px; }
  .rd { font-size: 11.5px; color: var(--muted); }
  select, input[type="text"] {
    background: #09120f; border: 1px solid var(--border); border-radius: 9px;
    color: var(--text); padding: 7px 10px; font-size: 13px; outline: none; min-width: 170px;
  }
  select:focus, input[type="text"]:focus { border-color: var(--accent); }
  .switch { position: relative; width: 44px; height: 24px; flex-shrink: 0; }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider {
    position: absolute; inset: 0; border-radius: 999px;
    background: #1b2c26; border: 1px solid var(--border); transition: 0.16s; cursor: pointer;
  }
  .slider:before {
    content: ""; position: absolute; width: 18px; height: 18px; left: 2px; top: 2px;
    border-radius: 50%; background: #9db8ae; transition: 0.16s;
  }
  .switch input:checked + .slider { background: var(--accent-dim); border-color: var(--accent); }
  .switch input:checked + .slider:before { transform: translateX(20px); background: var(--accent); }
  .app-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
  .app-chip {
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
    padding: 8px 10px; border-radius: 10px; border: 1px solid var(--border);
    background: #0a1310; font-size: 12.5px; cursor: pointer;
  }
  .app-chip .al { display: flex; align-items: center; gap: 8px; }
  .app-chip input { accent-color: var(--accent); width: 15px; height: 15px; }
  .app-chip .sz { color: var(--muted); font-size: 11px; white-space: nowrap; }
  .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; }
  .btn {
    border: 1px solid var(--border); background: var(--panel2); color: var(--text);
    padding: 10px 15px; border-radius: 10px; font-size: 13.5px; font-weight: 700; cursor: pointer;
  }
  .btn:hover { border-color: var(--accent); }
  .btn.primary { background: var(--accent); color: #04130c; border-color: var(--accent); flex: 1; }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  pre.logbox {
    background: #050908; border: 1px solid var(--border); border-radius: 11px;
    padding: 12px; height: 290px; overflow: auto; font-family: ui-monospace, Consolas, monospace;
    font-size: 12px; color: #bfe8d5; white-space: pre-wrap; margin: 10px 0 0;
  }
  .cmd-box {
    background: #060d0a; border: 1px solid var(--border); border-radius: 9px;
    padding: 9px 11px; font-family: ui-monospace, Consolas, monospace; font-size: 11.5px;
    color: #9be8c5; word-break: break-all; margin-top: 8px;
  }
  .status-banner { font-size: 12.5px; margin-top: 8px; font-weight: 600; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <div class="badge">#</div>
      <div>
        <h1>Andarium Root Builder Studio <span style="color:var(--accent);font-size:14px;">v4</span></h1>
        <div class="sub">Pick a role preset, toggle Root ON/OFF, customize apps &amp; iOS icon themes, and build a verified IPA</div>
      </div>
    </div>
    <div class="pill-stat" id="est-size">Estimated IPA: ~1.30 GiB</div>
  </header>

  <div class="card">
    <h2>1. Choose a Role Preset</h2>
    <div class="preset-grid" id="preset-grid"></div>
  </div>

  <div class="grid">
    <div>
      <div class="card">
        <h2>2. Root Access &amp; Core Security</h2>
        <div class="row">
          <div>
            <div class="rt">Root Mode</div>
            <div class="rd">Toggle Root ON, Hidden at Boot (reversible in iOS Pre-Boot Studio), or True Unrooted (stock init_boot.img)</div>
          </div>
          <select id="f-root-mode" onchange="onChange()">
            <option value="on">Root ON (Magisk v31.1)</option>
            <option value="hidden">Root HIDDEN by default (toggleable)</option>
            <option value="unrooted">True Unrooted (--no-root, stock init_boot)</option>
          </select>
        </div>
        <div class="row">
          <div><div class="rt">Stealth Mode</div><div class="rd">Enforcing SELinux, DenyList ON, hides debuggable &amp; stops Frida/SSH</div></div>
          <label class="switch"><input type="checkbox" id="f-stealth" onchange="onChange()"><span class="slider"></span></label>
        </div>
        <div class="row">
          <div><div class="rt">SELinux Policy</div><div class="rd">Permissive for pentest/RE, Enforcing for gaming/banking</div></div>
          <select id="f-selinux" onchange="onChange()">
            <option value="permissive">Permissive</option>
            <option value="enforcing">Enforcing</option>
          </select>
        </div>
        <div class="row">
          <div><div class="rt">Native ADB Root</div><div class="rd">Unlock `adb root` while keeping default shell mode</div></div>
          <label class="switch"><input type="checkbox" id="f-adbroot" onchange="onChange()"><span class="slider"></span></label>
        </div>
        <div class="row">
          <div><div class="rt">ro.debuggable=1</div><div class="rd">Enable JDWP debugging &amp; root adb</div></div>
          <label class="switch"><input type="checkbox" id="f-dbg" onchange="onChange()"><span class="slider"></span></label>
        </div>
      </div>

      <div class="card">
        <h2>3. Preinstalled Apps (13 Bundled APKs)</h2>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:10px;flex-wrap:wrap;">
          <div style="display:flex;gap:6px;">
            <button class="btn" style="padding:5px 10px;font-size:12px;" onclick="toggleAllApps(true)">Select All</button>
            <button class="btn" style="padding:5px 10px;font-size:12px;" onclick="toggleAllApps(false)">Clear All</button>
          </div>
          <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);cursor:pointer;">
            <input type="checkbox" id="f-shrink" onchange="onChange()" style="accent-color:var(--accent);">
            Shrink IPA (physically omit unchecked APKs from odm.img)
          </label>
        </div>
        <div class="app-grid" id="app-grid"></div>
      </div>

      <div class="card">
        <h2>4. iOS App Icon Theme &amp; Identity</h2>
        <div class="icon-grid" id="icon-grid"></div>
        <div class="row" style="margin-top:10px;">
          <div><div class="rt">iOS App Display Name</div><div class="rd">Shown beneath the icon on iOS Home Screen</div></div>
          <input type="text" id="f-dname" oninput="onChange()">
        </div>
        <div class="row">
          <div><div class="rt">iOS Bundle Identifier</div><div class="rd">Unique ID so rooted &amp; stock IPAs install side-by-side</div></div>
          <input type="text" id="f-bid" oninput="onChange()">
        </div>
        <div class="row">
          <div><div class="rt">Output IPA Filename (inside dist/)</div><div class="rd">Must end in .ipa</div></div>
          <input type="text" id="f-outname" value="Andarium-Root-1.0-15.ipa" oninput="onChange()">
        </div>
      </div>
    </div>

    <div>
      <div class="card">
        <h2>5. Modules, Services &amp; Tweaks</h2>
        <div class="row">
          <div><div class="rt">ReZygisk</div><div class="rd">Standalone Zygisk runtime</div></div>
          <label class="switch"><input type="checkbox" id="m-rezygisk" onchange="onChange()"><span class="slider"></span></label>
        </div>
        <div class="row">
          <div><div class="rt">Vector (LSPosed Android 17)</div><div class="rd">Xposed hooking framework</div></div>
          <label class="switch"><input type="checkbox" id="m-vector" onchange="onChange()"><span class="slider"></span></label>
        </div>
        <div class="row">
          <div><div class="rt">Integrity &amp; Root-Hiding Stack</div><div class="rd">PlayIntegrityFork + TrickyStore + Zygisk-Assistant</div></div>
          <label class="switch"><input type="checkbox" id="m-stealth" onchange="onChange()"><span class="slider"></span></label>
        </div>
        <div class="row">
          <div><div class="rt">Systemless Ad-Block</div><div class="rd">StevenBlack unified hosts</div></div>
          <label class="switch"><input type="checkbox" id="s-adblock" onchange="onChange()"><span class="slider"></span></label>
        </div>
        <div class="row">
          <div><div class="rt">Frida Server Autostart</div><div class="rd">Auto-start frida-server on boot</div></div>
          <label class="switch"><input type="checkbox" id="s-frida" onchange="onChange()"><span class="slider"></span></label>
        </div>
        <div class="row">
          <div><div class="rt">Dropbear SSH Autostart</div><div class="rd">Auto-start SSH/SCP on boot (port 2222)</div></div>
          <label class="switch"><input type="checkbox" id="s-ssh" onchange="onChange()"><span class="slider"></span></label>
        </div>
        <div class="row">
          <div><div class="rt">Shizuku Auto-Start</div><div class="rd">Auto-start privileged Shizuku server</div></div>
          <label class="switch"><input type="checkbox" id="s-shizuku" onchange="onChange()"><span class="slider"></span></label>
        </div>
        <div class="row">
          <div><div class="rt">Global HTTP Proxy</div><div class="rd">Optional Burp/mitmproxy host:port</div></div>
          <input type="text" id="f-proxy" placeholder="off (host:port)" oninput="onChange()">
        </div>
        <div class="row">
          <div><div class="rt">Animation Scale</div><div class="rd">0x = instant (Gamer / Hacker)</div></div>
          <select id="t-anim" onchange="onChange()">
            <option value="0">0x (Instant)</option>
            <option value="0.5">0.5x (Snappy)</option>
            <option value="1">1x (Stock)</option>
          </select>
        </div>
        <div class="row">
          <div><div class="rt">zRAM Swappiness</div><div class="rd">Higher = more RAM compression</div></div>
          <select id="t-swap" onchange="onChange()">
            <option value="60">60 (Stock)</option>
            <option value="80">80 (Balanced)</option>
            <option value="100">100 (High)</option>
            <option value="130">130 (Gamer Max)</option>
          </select>
        </div>
        <div class="row">
          <div><div class="rt">Display DPI</div><div class="rd">Android density override</div></div>
          <select id="t-dpi" onchange="onChange()">
            <option value="default">Default</option>
            <option value="320">320 DPI</option>
            <option value="360">360 DPI</option>
            <option value="420">420 DPI</option>
          </select>
        </div>
        <div class="row">
          <div><div class="rt">Stay Awake</div><div class="rd">Keep screen awake while running</div></div>
          <label class="switch"><input type="checkbox" id="t-awake" onchange="onChange()"><span class="slider"></span></label>
        </div>
      </div>

      <div class="card">
        <h2>6. Build, Save &amp; Live Logs</h2>
        <div class="actions">
          <button class="btn primary" id="btn-build" onclick="startBuild()">Build &amp; Verify IPA</button>
          <button class="btn" onclick="saveConfigFile()">Save Config</button>
          <button class="btn" onclick="downloadJson()">Export JSON</button>
        </div>
        <div class="cmd-box" id="cmd-preview"></div>
        <div class="status-banner" id="build-status" style="color:var(--muted);">Ready to build.</div>
        <pre class="logbox" id="logbox">Waiting for build...</pre>
      </div>
    </div>
  </div>
</div>

<script>
const TOKEN = "__SESSION_TOKEN__";
let META = null;
let CFG = null;
let ICON_THEME = "duskjade";
let POLL_TIMER = null;

const THEMES = [
  { id: "duskjade", label: "Dusk Jade", img: "/icons/icon-duskjade.png" },
  { id: "crimson",  label: "Crimson Lab", img: "/icons/icon-crimson.png" },
  { id: "cyber",    label: "Cyber Gold", img: "/icons/icon-cyber.png" },
  { id: "stealth",  label: "Stealth Slate", img: "/icons/icon-stealth.png" },
  { id: "stock",    label: "Stock Icon", img: "" },
];

function fmtMB(bytes) {
  return (bytes / (1024 * 1024)).toFixed(bytes < 1048576 ? 2 : 1) + " MB";
}

async function init() {
  const res = await fetch("/api/meta");
  META = await res.json();
  applyPreset("mix");
  pollStatus();
}

function renderPresets() {
  const g = document.getElementById("preset-grid");
  g.innerHTML = "";
  Object.entries(META.presets).forEach(([id, p]) => {
    const b = document.createElement("button");
    b.className = "preset-btn" + (CFG.preset === id ? " active" : "");
    b.onclick = () => applyPreset(id);
    b.innerHTML = `<div class="pt"></div><div class="pd"></div>`;
    b.querySelector(".pt").textContent = p.name;
    b.querySelector(".pd").textContent = p.tagline;
    g.appendChild(b);
  });
}

function renderIcons() {
  const g = document.getElementById("icon-grid");
  g.innerHTML = "";
  THEMES.forEach(t => {
    const d = document.createElement("div");
    d.className = "icon-card" + (ICON_THEME === t.id ? " active" : "");
    d.onclick = () => { ICON_THEME = t.id; CFG.icon_theme = t.id; renderIcons(); updateEstimates(); };
    if (t.img) {
      const im = document.createElement("img"); im.src = t.img; im.alt = t.label;
      d.appendChild(im);
    } else {
      const ph = document.createElement("div"); ph.className = "icon-placeholder"; ph.textContent = "STOCK";
      d.appendChild(ph);
    }
    const sp = document.createElement("span"); sp.textContent = t.label;
    d.appendChild(sp);
    g.appendChild(d);
  });
}

function renderApps() {
  const g = document.getElementById("app-grid");
  g.innerHTML = "";
  const active = new Set(CFG.apps || []);
  META.app_catalog.forEach(app => {
    const sz = META.apk_sizes[app.id] || 0;
    const lbl = document.createElement("label");
    lbl.className = "app-chip";
    lbl.innerHTML = `<span class="al"><input type="checkbox"><span></span></span><span class="sz"></span>`;
    const cb = lbl.querySelector("input");
    cb.checked = active.has(app.id);
    cb.dataset.appId = app.id;
    cb.onchange = onChange;
    lbl.querySelector(".al span").textContent = app.label;
    lbl.querySelector(".sz").textContent = sz ? fmtMB(sz) : "";
    g.appendChild(lbl);
  });
}

function applyPreset(id) {
  const p = META.presets[id];
  if (!p) return;
  CFG = JSON.parse(JSON.stringify(p));
  CFG.preset = id;
  CFG.build_unrooted = false;
  CFG.shrink_apks = false;
  ICON_THEME = p.icon_theme || "duskjade";

  document.getElementById("f-root-mode").value = p.root_enabled === false ? "hidden" : "on";
  document.getElementById("f-stealth").checked = Boolean(p.stealth);
  document.getElementById("f-selinux").value = p.selinux || "permissive";
  document.getElementById("f-adbroot").checked = p.adbroot !== false;
  document.getElementById("f-dbg").checked = p.debuggable !== false;
  document.getElementById("f-dname").value = p.display_name || "Andarium Root";
  document.getElementById("f-bid").value = p.bundle_id || "com.andarium.root";
  document.getElementById("f-outname").value = id === "mix" ? "Andarium-Root-1.0-15.ipa" : `Andarium-${id[0].toUpperCase() + id.slice(1)}-1.0-15.ipa`;
  document.getElementById("f-proxy").value = "";
  document.getElementById("f-shrink").checked = false;

  document.getElementById("m-rezygisk").checked = p.modules.rezygisk !== false;
  document.getElementById("m-vector").checked = p.modules.vector !== false;
  document.getElementById("m-stealth").checked = p.modules.stealth_stack !== false;
  document.getElementById("s-adblock").checked = p.services.adblock !== false;
  document.getElementById("s-frida").checked = Boolean(p.services.frida_autostart);
  document.getElementById("s-ssh").checked = Boolean(p.services.ssh_autostart);
  document.getElementById("s-shizuku").checked = p.services.shizuku_autostart !== false;
  document.getElementById("t-anim").value = String(p.tweaks.anim_scale ?? "0.5");
  document.getElementById("t-swap").value = String(p.tweaks.swappiness ?? 100);
  document.getElementById("t-dpi").value = String(p.tweaks.dpi ?? "default");
  document.getElementById("t-awake").checked = Boolean(p.tweaks.stay_awake);

  renderPresets();
  renderIcons();
  renderApps();
  updateEstimates();
}

function toggleAllApps(state) {
  document.querySelectorAll("#app-grid input[type=checkbox]").forEach(cb => cb.checked = state);
  onChange();
}

function collectConfig() {
  const apps = [];
  document.querySelectorAll("#app-grid input[type=checkbox]").forEach(cb => {
    if (cb.checked) apps.push(cb.dataset.appId);
  });
  const rmode = document.getElementById("f-root-mode").value;
  return {
    preset: CFG.preset || "mix",
    root_enabled: rmode === "on",
    build_unrooted: rmode === "unrooted",
    stealth: document.getElementById("f-stealth").checked,
    selinux: document.getElementById("f-selinux").value,
    adbroot: document.getElementById("f-adbroot").checked,
    debuggable: document.getElementById("f-dbg").checked,
    icon_theme: ICON_THEME,
    display_name: document.getElementById("f-dname").value.trim() || "Andarium Root",
    bundle_id: document.getElementById("f-bid").value.trim() || "com.andarium.root",
    proxy: document.getElementById("f-proxy").value.trim(),
    shrink_apks: document.getElementById("f-shrink").checked,
    modules: {
      rezygisk: document.getElementById("m-rezygisk").checked,
      vector: document.getElementById("m-vector").checked,
      stealth_stack: document.getElementById("m-stealth").checked,
    },
    services: {
      adblock: document.getElementById("s-adblock").checked,
      frida_autostart: document.getElementById("s-frida").checked,
      ssh_autostart: document.getElementById("s-ssh").checked,
      shizuku_autostart: document.getElementById("s-shizuku").checked,
    },
    tweaks: {
      anim_scale: document.getElementById("t-anim").value,
      swappiness: Number(document.getElementById("t-swap").value),
      dpi: document.getElementById("t-dpi").value,
      stay_awake: document.getElementById("t-awake").checked,
    },
    apps: apps,
  };
}

function onChange() {
  CFG = collectConfig();
  updateEstimates();
}

function updateEstimates() {
  const c = collectConfig();
  let total = META.base_ipa_size;
  if (!c.build_unrooted) {
    total += 42 * 1024 * 1024; // Magisk + modules + Frida + CLI tools compressed in zstd EROFS
  }
  const active = new Set(c.apps);
  META.app_catalog.forEach(a => {
    const include = (c.build_unrooted || c.shrink_apks) ? active.has(a.id) : true;
    if (include) total += Math.round((META.apk_sizes[a.id] || 0) * 0.92);
  });
  document.getElementById("est-size").textContent =
    `Estimated IPA: ~${(total / (1024 ** 3)).toFixed(2)} GiB (${c.apps.length}/13 apps active)`;

  const outName = document.getElementById("f-outname").value.trim() || "Andarium-Root-1.0-15.ipa";
  const extra = c.build_unrooted ? " -NoRoot" : "";
  document.getElementById("cmd-preview").textContent =
    `.\\build.ps1 -Config andarium-config.json -IconTheme ${c.icon_theme}${extra} --output dist/${outName}`;
}

async function saveConfigFile() {
  const c = collectConfig();
  const res = await fetch("/api/save", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Studio-Token": TOKEN },
    body: JSON.stringify({ config: c }),
  });
  const data = await res.json();
  document.getElementById("build-status").textContent = data.ok ? `Saved ${data.path}` : `Error: ${data.error}`;
  document.getElementById("build-status").style.color = data.ok ? "var(--accent)" : "var(--danger)";
}

function downloadJson() {
  const blob = new Blob([JSON.stringify(collectConfig(), null, 2) + "\n"], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "andarium-config.json";
  a.click();
}

async function startBuild() {
  const c = collectConfig();
  const outName = document.getElementById("f-outname").value.trim() || "Andarium-Root-1.0-15.ipa";
  document.getElementById("btn-build").disabled = true;
  document.getElementById("logbox").textContent = "Starting build...\n";
  const res = await fetch("/api/build", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Studio-Token": TOKEN },
    body: JSON.stringify({ config: c, output_name: outName }),
  });
  const data = await res.json();
  if (!data.ok) {
    document.getElementById("build-status").textContent = "Error: " + data.error;
    document.getElementById("build-status").style.color = "var(--danger)";
    document.getElementById("btn-build").disabled = false;
    return;
  }
  if (!POLL_TIMER) POLL_TIMER = setInterval(pollStatus, 1000);
  pollStatus();
}

async function pollStatus() {
  const res = await fetch("/api/status");
  const st = await res.json();
  const box = document.getElementById("logbox");
  if (st.logs && st.logs.length > 0) {
    box.textContent = st.logs.join("\n");
    box.scrollTop = box.scrollHeight;
  }
  const sb = document.getElementById("build-status");
  const btn = document.getElementById("btn-build");
  if (st.running) {
    btn.disabled = true;
    sb.textContent = "Building & verifying IPA in progress...";
    sb.style.color = "var(--warn)";
    if (!POLL_TIMER) POLL_TIMER = setInterval(pollStatus, 1000);
  } else {
    btn.disabled = false;
    if (POLL_TIMER) { clearInterval(POLL_TIMER); POLL_TIMER = null; }
    if (st.rc === 0) {
      sb.textContent = `Build & verification SUCCEEDED: ${st.output_ipa}`;
      sb.style.color = "var(--accent)";
    } else if (st.rc !== null) {
      sb.textContent = `Build FAILED (exit code ${st.rc})`;
      sb.style.color = "var(--danger)";
    }
  }
}

init();
</script>
</body>
</html>
"""


def load_meta() -> dict[str, object]:
    presets_doc = json.loads((MANIFESTS_DIR / "presets.json").read_text(encoding="utf-8"))
    artifacts_doc = json.loads((MANIFESTS_DIR / "artifacts.json").read_text(encoding="utf-8"))
    apk_sizes: dict[str, int] = {"magisk": int(artifacts_doc["magisk"]["size"])}
    for k, v in artifacts_doc["apks"].items():
        apk_sizes[k] = int(v["size"])
    return {
        "presets": presets_doc["presets"],
        "app_catalog": presets_doc["app_catalog"],
        "apk_sizes": apk_sizes,
        "base_ipa_size": int(artifacts_doc["base_ipa"]["size"]),
    }


def run_build_thread(config_path: Path, output_name: str, distro: str) -> None:
    try:
        if sys.platform == "win32":
            repo_slash = str(ROOT_DIR).replace("\\", "/")
            repo_wsl = subprocess.check_output(
                ["wsl.exe", "-d", distro, "--", "wslpath", "-a", "-u", repo_slash],
                text=True,
            ).strip()
            cmd = [
                "wsl.exe",
                "-d",
                distro,
                "--",
                "python3",
                f"{repo_wsl}/scripts/build_rooted_ipa.py",
                "--config",
                f"{repo_wsl}/{config_path.name}",
                "--output",
                f"{repo_wsl}/dist/{output_name}",
            ]
        else:
            cmd = [
                sys.executable,
                str(ROOT_DIR / "scripts" / "build_rooted_ipa.py"),
                "--config",
                str(config_path),
                "--output",
                str(DIST_DIR / output_name),
            ]
        with BUILD_LOCK:
            BUILD_STATE["logs"].append(f"[studio] $ {' '.join(cmd)}")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            with BUILD_LOCK:
                BUILD_STATE["logs"].append(line.rstrip("\r\n"))
                if len(BUILD_STATE["logs"]) > 2000:
                    BUILD_STATE["logs"] = BUILD_STATE["logs"][-1500:]
        rc = proc.wait()
        with BUILD_LOCK:
            BUILD_STATE["rc"] = rc
            BUILD_STATE["running"] = False
    except Exception as exc:
        with BUILD_LOCK:
            BUILD_STATE["logs"].append(f"[studio] ERROR: {exc}")
            BUILD_STATE["rc"] = 1
            BUILD_STATE["running"] = False


def make_handler(distro: str) -> type[http.server.BaseHTTPRequestHandler]:
    class StudioHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass  # keep terminal clean

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status: int, obj: object) -> None:
            self._send(status, "application/json; charset=utf-8", json.dumps(obj).encode("utf-8"))

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                html = STUDIO_HTML.replace("__SESSION_TOKEN__", SESSION_TOKEN).encode("utf-8")
                self._send(200, "text/html; charset=utf-8", html)
                return
            if path == "/api/meta":
                self._send_json(200, load_meta())
                return
            if path == "/api/status":
                with BUILD_LOCK:
                    self._send_json(200, dict(BUILD_STATE))
                return
            if path.startswith("/icons/"):
                fname = path.removeprefix("/icons/")
                if re.fullmatch(r"icon-[a-z]+\.png", fname):
                    fp = DOCS_DIR / fname
                    if fp.is_file():
                        self._send(200, "image/png", fp.read_bytes())
                        return
            self._send(404, "text/plain", b"Not Found")

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            if self.headers.get("X-Studio-Token") != SESSION_TOKEN:
                self._send_json(403, {"ok": False, "error": "Invalid session token"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(min(length, 262144)).decode("utf-8"))
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": f"Invalid JSON: {exc}"})
                return

            if path == "/api/save":
                cfg = payload.get("config")
                if not isinstance(cfg, dict):
                    self._send_json(400, {"ok": False, "error": "Missing config object"})
                    return
                DEFAULT_CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
                self._send_json(200, {"ok": True, "path": str(DEFAULT_CONFIG_PATH)})
                return

            if path == "/api/build":
                cfg = payload.get("config")
                out_name = str(payload.get("output_name", "Andarium-Root-1.0-15.ipa")).strip()
                if not isinstance(cfg, dict):
                    self._send_json(400, {"ok": False, "error": "Missing config object"})
                    return
                if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}\.ipa", out_name):
                    self._send_json(400, {"ok": False, "error": "Invalid IPA filename (use letters, digits, ., _, - ending in .ipa)"})
                    return

                with BUILD_LOCK:
                    if BUILD_STATE["running"]:
                        self._send_json(409, {"ok": False, "error": "A build is already running"})
                        return
                    DEFAULT_CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
                    BUILD_STATE["running"] = True
                    BUILD_STATE["rc"] = None
                    BUILD_STATE["output_ipa"] = f"dist/{out_name}"
                    BUILD_STATE["logs"] = [f"[studio] Saved {DEFAULT_CONFIG_PATH.name}; starting build -> dist/{out_name}"]

                t = threading.Thread(
                    target=run_build_thread,
                    args=(DEFAULT_CONFIG_PATH, out_name, distro),
                    daemon=True,
                )
                t.start()
                self._send_json(200, {"ok": True})
                return

            self._send_json(404, {"ok": False, "error": "Unknown endpoint"})

    return StudioHandler


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser(description="Launch the local Andarium Root Builder Studio Web UI.")
    parser.add_argument("--port", type=int, default=8765, help="Localhost port (default 8765)")
    parser.add_argument("--distro", default="kali-linux", help="WSL2 Linux distro name on Windows")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser window")
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args.distro))
    url = f"http://127.0.0.1:{args.port}/"
    print(f"[studio] Andarium Root Builder Studio running at {url} (Ctrl+C to stop)", flush=True)
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[studio] Stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
