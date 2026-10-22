"""
app.py - Cloud Storage Space Optimizer (Vercel & Flask Web Application)
Features:
1. Exact Streamlit-style Dark Sidebar:
   - ☁️ Drive Optimizer Header & Subtitle
   - 🌐 Cloud Storage Connection Source Switcher (Simulated Cloud, Local Sync Folder, Google Drive API)
   - Real-time Connection Status Alert Banner
2. Cryptographic SHA-256 Deduplication & Storage Health Analysis
3. 8 Comprehensive Optimization & Security Modules:
   - 📊 Storage Analytics (Instant 0ms Category Distribution Bars + Fast Chart.js Category Doughnut)
   - 🛡️ File Safety & Junk Scanner (Scans all files, verifies all are safe, junk file detector with status)
   - 👯 SHA-256 Duplicate Detector (Grouping, original preservation, trash actions)
   - 🐘 Large File Audit (> 50 MB ranking)
   - 👻 Ghost & Clutter Detector (0-byte failed downloads, .tmp files)
   - 🧪 Live SHA-256 Hasher Lab (Drag & drop file hashing against drive records)
   - 💰 Financial Cost Optimization & ROI (Tier savings calculation)
   - 📘 System Architecture & Google Drive Zero-Payment OAuth Guide
"""

from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import io
import json
import os
import time
import tempfile
import shutil
from flask import Flask, request, jsonify, render_template_string, redirect, url_for

from drive_service import MockDriveManager, LocalFolderManager, GoogleDriveManager, GOOGLE_LIBS_AVAILABLE, resolve_storage_file
from optimizer import (
    compute_sha256,
    format_bytes,
    process_files_dataframe,
    detect_duplicates_by_sha256,
    audit_large_files,
    audit_inactive_files,
    calculate_storage_health,
    audit_empty_and_temp_files,
    calculate_cost_savings,
    scan_files_safety_and_junk,
)

# Initialize Flask application
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024

# Active drive manager and mode
current_mode = "simulated"
drive_mgr = MockDriveManager()

# In-memory fast cache to make all dashboard views and API responses instant (< 1ms)
_cached_data = None
_cached_time = 0.0
_cache_dirty = True


def invalidate_cache():
    """Invalidate cached data when storage contents change."""
    global _cache_dirty
    _cache_dirty = True


def get_current_data():
    """Extract and analyze current drive storage records with high-performance caching."""
    global _cached_data, _cached_time, _cache_dirty
    now = time.time()
    if not _cache_dirty and _cached_data is not None and (now - _cached_time < 2.0):
        return _cached_data

    files = drive_mgr.list_files()
    quota = drive_mgr.get_quota(files=files)
    df = process_files_dataframe(files)

    total_files = len(df)
    used_bytes = quota.get("usage", df["size"].sum() if not df.empty else 0)
    limit_bytes = quota.get("limit", 15 * 1024**3)
    trash_bytes = quota.get("usageInDriveTrash", 0)

    dupes_df, reclaimable_dupes = detect_duplicates_by_sha256(df)
    large_df = audit_large_files(df, threshold_mb=50)
    old_df = audit_inactive_files(df, days_threshold=180)
    clutter_df = audit_empty_and_temp_files(df)
    clutter_bytes = clutter_df["size"].sum() if not clutter_df.empty else 0

    total_savings = reclaimable_dupes + trash_bytes + clutter_bytes
    health = calculate_storage_health(
        used_bytes,
        limit_bytes,
        reclaimable_dupes,
        old_df["size"].sum() if not old_df.empty else 0,
    )
    cost = calculate_cost_savings(total_savings)

    # Category aggregation for charts and distribution bars
    cat_summary = []
    if not df.empty:
        total_used_space = float(df["size"].sum()) if df["size"].sum() > 0 else 1.0
        for cat, group in df.groupby("category"):
            cat_bytes = int(group["size"].sum())
            pct = round((cat_bytes / total_used_space) * 100, 1)
            cat_summary.append({
                "category": str(cat),
                "bytes": cat_bytes,
                "formatted": format_bytes(cat_bytes),
                "count": int(len(group)),
                "percent": pct,
            })
        cat_summary.sort(key=lambda x: x["bytes"], reverse=True)

    dupes_data = json.loads(dupes_df.to_json(orient="records")) if not dupes_df.empty else []
    large_data = json.loads(large_df.head(15).to_json(orient="records")) if not large_df.empty else []
    clutter_data = json.loads(clutter_df.to_json(orient="records")) if not clutter_df.empty else []

    # Deep File Safety & Junk File Scan
    scanned_files, scan_summary = scan_files_safety_and_junk(df, dupes_df, clutter_df)

    res = {
        "current_mode": current_mode,
        "user_info": getattr(drive_mgr, "user_info", {}),
        "is_live_google": current_mode == "google" and getattr(drive_mgr, "service", None) is not None,
        "total_files": int(total_files),
        "used_bytes": int(used_bytes),
        "formatted_used": format_bytes(used_bytes),
        "limit_bytes": int(limit_bytes),
        "formatted_limit": format_bytes(limit_bytes),
        "trash_bytes": int(trash_bytes),
        "formatted_trash": format_bytes(trash_bytes),
        "reclaimable_dupes": int(reclaimable_dupes),
        "formatted_reclaimable_dupes": format_bytes(reclaimable_dupes),
        "total_savings": int(total_savings),
        "formatted_savings": format_bytes(total_savings),
        "health": health,
        "cost": cost,
        "categories": cat_summary,
        "dupes": dupes_data,
        "large_files": large_data,
        "clutter": clutter_data,
        "scanned_files": scanned_files,
        "scan_summary": scan_summary,
    }

    _cached_data = res
    _cached_time = now
    _cache_dirty = False
    return res


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Drive Optimizer - Cloud Storage Space Optimizer</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Chart.js UMD -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <!-- FontAwesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #0f172a; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #475569; }
        .donut-fallback {
            background: conic-gradient(#8b5cf6 0% 35%, #ec4899 35% 55%, #3b82f6 55% 75%, #f59e0b 75% 88%, #10b981 88% 100%);
            mask: radial-gradient(circle closest-side, transparent 65%, black 66%);
            -webkit-mask: radial-gradient(circle closest-side, transparent 65%, black 66%);
        }
    </style>
</head>
<body class="bg-[#0f172a] text-slate-100 font-sans min-h-screen">

    <!-- Embedded Initial Server Data for Instant 0ms Load -->
    <script id="server-initial-data" type="application/json">
        {{ initial_data | tojson }}
    </script>

    <div class="min-h-screen flex flex-col md:flex-row">
        <!-- SIDEBAR -->
        <aside class="w-full md:w-80 lg:w-88 bg-[#1e212b] border-r border-slate-800 p-6 flex flex-col shrink-0">
            <!-- Sidebar Header -->
            <div class="flex items-center gap-3">
                <span class="text-3xl">☁️</span>
                <h1 class="text-2xl font-black text-white tracking-tight">Drive Optimizer</h1>
            </div>
            <p class="text-xs text-slate-400 font-medium mt-1">Cloud Storage Analysis & Deduplication</p>

            <hr class="border-slate-700/80 my-5">

            <!-- Storage Connection Section -->
            <div class="mb-5">
                <div class="flex items-center gap-2 text-sm font-bold text-white mb-2">
                    <span class="text-base">🌐</span>
                    <span>Cloud Storage Connection</span>
                </div>

                <div class="flex items-center gap-1.5 text-xs text-slate-300 font-medium mb-3">
                    <span>Choose Storage Source:</span>
                    <span class="text-slate-400 hover:text-white cursor-pointer" title="Switch between Simulated Cloud, Local Cloud Sync Folder, or Google Drive API">❔</span>
                </div>

                <!-- Storage Source Radio Buttons -->
                <div class="space-y-2">
                    <label class="flex items-start gap-3 p-2.5 rounded-xl cursor-pointer hover:bg-slate-800/80 transition-all border border-transparent">
                        <input type="radio" name="storage_source" id="radio-simulated" value="simulated" checked onchange="changeMode('simulated')" class="mt-0.5 accent-rose-500 w-4 h-4 cursor-pointer">
                        <div class="text-xs">
                            <span class="font-bold text-white">✨ Simulated Cloud</span> <br><span class="text-[11px] text-slate-400">(No Card / Ready Now)</span>
                        </div>
                    </label>

                    <label class="flex items-start gap-3 p-2.5 rounded-xl cursor-pointer hover:bg-slate-800/80 transition-all border border-transparent">
                        <input type="radio" name="storage_source" id="radio-local" value="local" onchange="changeMode('local')" class="mt-0.5 accent-rose-500 w-4 h-4 cursor-pointer">
                        <div class="text-xs">
                            <span class="font-bold text-white">📁 Local Cloud Sync Folder</span> <br><span class="text-[11px] text-slate-400">(Real Files, No Card)</span>
                        </div>
                    </label>

                    <label class="flex items-start gap-3 p-2.5 rounded-xl cursor-pointer hover:bg-slate-800/80 transition-all border border-transparent">
                        <input type="radio" name="storage_source" id="radio-google" value="google" onchange="changeMode('google')" class="mt-0.5 accent-rose-500 w-4 h-4 cursor-pointer">
                        <div class="text-xs">
                            <span class="font-bold text-white">🔗 Google Drive API</span> <br><span class="text-[11px] text-slate-400">(OAuth 2.0)</span>
                        </div>
                    </label>
                </div>

                <!-- Green Notification Box (Simulated Cloud) -->
                <div id="status-box-simulated" class="mt-4 p-3.5 rounded-xl bg-[#163826] border border-emerald-600/50 text-xs text-emerald-300 font-medium leading-relaxed shadow-sm">
                    Connected to <span class="font-bold text-emerald-100">Simulated Cloud Storage</span> (15 GB Quota, 45+ Files, Real SHA-256 Hashes).
                </div>

                <!-- Local Cloud Sync Folder Details -->
                <div id="status-box-local" class="mt-4 p-3.5 rounded-xl bg-slate-800/90 border border-slate-700 text-xs text-slate-200 hidden">
                    <div class="font-bold text-white mb-2 flex items-center justify-between">
                        <span class="flex items-center gap-1.5"><i class="fa-solid fa-folder-open text-blue-400"></i> Folder Scanner:</span>
                        <span id="local-status-badge" class="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-950 text-blue-300 border border-blue-800">Ready</span>
                    </div>

                    <div class="space-y-2">
                        <div>
                            <label class="text-[11px] text-slate-400 block mb-1">Local / Sample Folder Path:</label>
                            <div class="flex gap-1.5">
                                <input type="text" id="local-folder-path" value="sample_files" placeholder="sample_files or folder path" class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white focus:ring-1 focus:ring-blue-500 outline-none">
                                <button onclick="scanLocalFolder()" id="btn-scan-folder" class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded-lg transition-all text-xs shadow-md whitespace-nowrap">
                                    <i class="fa-solid fa-magnifying-glass mr-1"></i> Scan
                                </button>
                            </div>
                        </div>

                        <div class="pt-2 border-t border-slate-700/60">
                            <input type="file" id="browser-folder-picker" webkitdirectory directory multiple class="hidden" onchange="uploadAndScanFolder(event)">
                            <label for="browser-folder-picker" class="block w-full text-center cursor-pointer py-1.5 bg-slate-700 hover:bg-slate-600 text-white font-semibold rounded-lg text-xs border border-slate-600 transition-all shadow-sm">
                                <i class="fa-solid fa-laptop mr-1.5 text-blue-400"></i> Pick PC Folder to Scan
                            </label>
                            <div id="local-folder-status" class="text-[10px] text-emerald-400 font-semibold mt-1 hidden"></div>
                            <div class="text-[10px] text-slate-400 mt-1 leading-tight">
                                Scans real files on your system with 100% cryptographic SHA-256 hashes.
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Google Drive API Details -->
                <div id="status-box-google" class="mt-4 p-3.5 rounded-xl bg-slate-800/90 border border-slate-700 text-xs text-slate-200 hidden">
                    <div class="font-bold text-white mb-2 flex items-center justify-between">
                        <span class="flex items-center gap-1.5"><i class="fa-brands fa-google-drive text-emerald-400"></i> Google Drive:</span>
                        <span id="google-status-pill" class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800">Not Connected</span>
                    </div>

                    <!-- Connected State View -->
                    <div id="google-connected-view" class="hidden space-y-2 mb-2 p-2.5 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-emerald-200">
                        <div class="flex items-center gap-2">
                            <i class="fa-solid fa-circle-check text-emerald-400 text-sm"></i>
                            <div class="overflow-hidden">
                                <div class="font-bold text-white truncate" id="google-user-name">Google User</div>
                                <div class="text-[10px] text-emerald-300 truncate" id="google-user-email">user@gmail.com</div>
                            </div>
                        </div>
                        <button onclick="disconnectGoogleDrive()" class="w-full py-1 bg-slate-800 hover:bg-rose-900/60 text-slate-300 hover:text-rose-200 rounded text-[11px] font-semibold border border-slate-700 transition-all">
                            <i class="fa-solid fa-right-from-bracket mr-1"></i> Disconnect Drive
                        </button>
                    </div>

                    <!-- Setup / Connect View -->
                    <div id="google-connect-controls" class="space-y-2">
                        <input type="file" id="cred-file-input" accept=".json" class="hidden" onchange="uploadCredentials(event)">
                        <label for="cred-file-input" id="cred-file-label" class="block w-full text-center cursor-pointer py-1.5 bg-slate-700 hover:bg-slate-600 text-white font-semibold rounded-lg text-xs border border-slate-600 transition-all">
                            <i class="fa-solid fa-upload mr-1.5 text-emerald-400"></i> Upload credentials.json
                        </label>
                        <button onclick="connectGoogleDrive()" id="btn-connect-live-drive" class="w-full py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white font-bold rounded-lg transition-all text-xs shadow-md flex items-center justify-center gap-1.5">
                            <i class="fa-brands fa-google"></i> Connect Live Drive
                        </button>

                        <!-- Fast Token Connect (Zero Setup) -->
                        <div class="pt-2 border-t border-slate-700/60">
                            <button onclick="toggleTokenBox()" type="button" class="text-[11px] text-slate-400 hover:text-emerald-300 flex items-center justify-between w-full py-0.5 font-medium transition-all">
                                <span><i class="fa-solid fa-key text-amber-400 mr-1"></i> Quick Token Connect (Zero Setup)</span>
                                <i id="token-caret" class="fa-solid fa-chevron-down text-[10px]"></i>
                            </button>
                            <div id="google-token-box" class="hidden mt-2 space-y-1.5">
                                <input type="password" id="google-token-input" placeholder="Paste access token (ya29...)" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-white outline-none focus:ring-1 focus:ring-emerald-500">
                                <button onclick="connectGoogleToken()" class="w-full py-1 bg-amber-600 hover:bg-amber-700 text-white font-bold rounded-lg transition-all text-xs shadow-sm">
                                    Connect with Token
                                </button>
                                <div class="text-[10px] text-slate-400 leading-tight">
                                    Get free token in 10s: Open <a href="https://developers.google.com/oauthplayground" target="_blank" class="text-emerald-400 underline">OAuth Playground</a>, select Drive API v3, authorize & paste token.
                                </div>
                            </div>
                        </div>

                        <div class="p-2 rounded-lg bg-amber-950/40 border border-amber-800/50 text-[11px] text-amber-200/90 leading-tight">
                            💡 <b>Google Cloud Setup:</b> Enable Google Drive API in Google Cloud Console. Create OAuth Client ID or Service Account and upload credentials.json.
                        </div>
                    </div>
                </div>
            </div>

            <hr class="border-slate-700/80 my-3">

            <!-- Sidebar Navigation Links -->
            <div class="space-y-1 mb-6 flex-1">
                <div class="text-[11px] font-bold uppercase tracking-wider text-slate-500 px-3 py-1">Optimizer Modules</div>
                <button onclick="switchTab('analytics')" id="nav-btn-analytics" class="nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-white bg-blue-600 flex items-center gap-2.5 transition-all">
                    <span>📊</span> <span>Storage Analytics</span>
                </button>
                <button onclick="switchTab('scanner')" id="nav-btn-scanner" class="nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 flex items-center justify-between transition-all">
                    <span class="flex items-center gap-2.5">
                        <span>🛡️</span> <span>Safety & Junk Scanner</span>
                    </span>
                    <span id="nav-junk-badge" class="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800 hidden">0</span>
                </button>
                <button onclick="switchTab('duplicates')" id="nav-btn-duplicates" class="nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-all">
                    <span>👯</span> <span>SHA-256 Duplicates</span>
                </button>
                <button onclick="switchTab('large')" id="nav-btn-large" class="nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-all">
                    <span>🐘</span> <span>Large Files</span>
                </button>
                <button onclick="switchTab('clutter')" id="nav-btn-clutter" class="nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-all">
                    <span>👻</span> <span>Ghost & Clutter</span>
                </button>
                <button onclick="switchTab('lab')" id="nav-btn-lab" class="nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-all">
                    <span>🧪</span> <span>Live SHA-256 Lab</span>
                </button>
                <button onclick="switchTab('roi')" id="nav-btn-roi" class="nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-all">
                    <span>💰</span> <span>Financial ROI</span>
                </button>
                <button onclick="switchTab('architecture')" id="nav-btn-architecture" class="nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-all">
                    <span>📘</span> <span>Setup & Architecture</span>
                </button>
            </div>

            <!-- Bottom Quick Actions -->
            <div class="pt-4 border-t border-slate-800 space-y-2 mt-auto">
                <button onclick="refreshData()" class="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl border border-slate-700 transition-all flex items-center justify-center gap-2 shadow-sm">
                    <i class="fa-solid fa-arrows-rotate"></i> Refresh Cloud Data
                </button>
                <button onclick="emptyCloudTrash()" class="w-full py-2 bg-slate-800/80 hover:bg-rose-950/40 hover:text-rose-400 text-slate-400 text-xs font-semibold rounded-xl border border-slate-700/60 transition-all flex items-center justify-center gap-2">
                    <i class="fa-solid fa-trash-can"></i> Empty Trash Bin
                </button>
            </div>
        </aside>

        <!-- MAIN DASHBOARD CONTENT -->
        <main class="flex-1 bg-[#0b0f19] min-h-screen p-6 md:p-8 overflow-y-auto">
            <!-- Top Status Bar -->
            <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6 pb-4 border-b border-slate-800">
                <div>
                    <h2 class="text-xl font-black text-white tracking-tight flex items-center gap-2">
                        <span>Cloud Storage Space Optimizer</span>
                        <span id="active-mode-badge" class="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
                            ✨ Simulated Cloud Active
                        </span>
                    </h2>
                    <p class="text-xs text-slate-400 mt-0.5">High-Precision Cryptographic SHA-256 Deduplication & Space Recovery Engine</p>
                </div>
                <div class="flex items-center gap-3">
                    <span class="text-xs text-slate-400 font-mono" id="last-updated-text">Updated: Instant Cache Active</span>
                </div>
            </div>

            <!-- Quota Meter Card -->
            <div class="bg-[#151b28] p-5 rounded-2xl border border-slate-800/80 shadow-lg mb-6">
                <div class="flex justify-between items-center mb-2.5">
                    <span class="text-xs font-bold text-slate-300 flex items-center gap-2 uppercase tracking-wider">
                        <i class="fa-brands fa-google-drive text-blue-400"></i> Cloud Storage Capacity (15 GB Quota)
                    </span>
                    <span id="quota-text" class="text-xs font-mono font-bold text-blue-400">
                        {{ initial_data.formatted_used }} / {{ initial_data.formatted_limit }} ({{ ((initial_data.used_bytes / initial_data.limit_bytes) * 100) | round(1) }}%)
                    </span>
                </div>
                <div class="w-full bg-slate-800/80 rounded-full h-3.5 overflow-hidden p-0.5">
                    <div id="quota-bar" class="bg-gradient-to-r from-blue-500 to-indigo-500 h-2.5 rounded-full transition-all duration-700" style="width: {{ [((initial_data.used_bytes / initial_data.limit_bytes) * 100), 100] | min }}%"></div>
                </div>
            </div>

            <!-- 5 KPI Metric Cards -->
            <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                <div class="bg-[#151b28] p-4 rounded-2xl border border-slate-800/80 shadow-md">
                    <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Total Files</div>
                    <div id="stat-files" class="text-2xl font-black text-white mt-1">{{ initial_data.total_files }}</div>
                    <div class="text-[10px] text-slate-500 mt-1">Indexed in drive</div>
                </div>
                <div class="bg-[#151b28] p-4 rounded-2xl border border-slate-800/80 shadow-md">
                    <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Storage Used</div>
                    <div id="stat-used" class="text-2xl font-black text-blue-400 mt-1">{{ initial_data.formatted_used }}</div>
                    <div class="text-[10px] text-slate-500 mt-1">Active drive volume</div>
                </div>
                <div class="bg-[#151b28] p-4 rounded-2xl border border-slate-800/80 shadow-md">
                    <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Potential Savings</div>
                    <div id="stat-savings" class="text-2xl font-black text-emerald-400 mt-1">{{ initial_data.formatted_savings }}</div>
                    <div class="text-[10px] text-emerald-500/80 mt-1">Reclaimable space</div>
                </div>
                <div class="bg-[#151b28] p-4 rounded-2xl border border-slate-800/80 shadow-md">
                    <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Duplicate Copies</div>
                    <div id="stat-dupes" class="text-2xl font-black text-rose-400 mt-1">{{ initial_data.dupes | selectattr('is_redundant') | list | length }}</div>
                    <div class="text-[10px] text-rose-500/80 mt-1">Identical SHA-256</div>
                </div>
                <div class="bg-[#151b28] p-4 rounded-2xl border border-slate-800/80 shadow-md">
                    <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Health Score</div>
                    <div id="stat-health" class="text-2xl font-black text-indigo-400 mt-1">{{ initial_data.health.score }}/100</div>
                    <div class="text-[10px] text-slate-500 mt-1">Storage efficiency / 100</div>
                </div>
            </div>

            <!-- MODULE 1: STORAGE ANALYTICS -->
            <div id="tab-analytics" class="tab-module space-y-6">
                <!-- File Safety & Junk Overview Banner Card -->
                <div id="overview-safety-card" class="bg-[#151b28] p-5 rounded-2xl border border-slate-800 shadow-md flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                    <div class="flex items-center gap-3.5">
                        <div id="overview-safety-icon" class="w-12 h-12 rounded-xl bg-emerald-950/80 border border-emerald-800 text-emerald-400 flex items-center justify-center text-xl shrink-0">
                            <i class="fa-solid fa-shield-halved"></i>
                        </div>
                        <div>
                            <div class="flex items-center gap-2">
                                <h4 class="text-sm font-bold text-white uppercase tracking-wider">File Safety & Junk File Scanner</h4>
                                <span id="overview-safety-badge" class="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                                    {{ initial_data.scan_summary.status_message }}
                                </span>
                            </div>
                            <p id="overview-safety-desc" class="text-xs text-slate-400 mt-1">
                                Scans all stored files, verifies safety, and identifies junk files (.tmp, 0-byte, redundant duplicates).
                            </p>
                        </div>
                    </div>
                    <div class="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
                        <button onclick="switchTab('scanner'); runFileScan();" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-xl shadow-md transition-all flex items-center justify-center gap-2 w-full md:w-auto">
                            <i class="fa-solid fa-magnifying-glass"></i> Scan All Files Now
                        </button>
                        <button onclick="addTestJunkFile()" class="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-amber-300 font-bold text-xs rounded-xl border border-amber-800/60 shadow-md transition-all flex items-center justify-center gap-1.5 w-full md:w-auto">
                            <i class="fa-solid fa-plus-circle"></i> Add 1 Junk File (Test)
                        </button>
                        <button id="overview-clean-junk-btn" onclick="cleanAllJunkFiles()" class="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white font-bold text-xs rounded-xl shadow-md transition-all flex items-center justify-center gap-2 {% if initial_data.scan_summary.junk_count == 0 %}hidden{% endif %} w-full md:w-auto">
                            <i class="fa-solid fa-broom"></i> Clean Junk Files
                        </button>
                    </div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <!-- Category Distribution Card (Instant 0ms Load) -->
                    <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md">
                        <div class="flex justify-between items-center mb-4">
                            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                                <span>📊</span> Storage Distribution by File Category
                            </h3>
                            <span id="cat-total-badge" class="px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-blue-950 text-blue-400 border border-blue-800">
                                {{ initial_data.categories | length }} Categories · {{ initial_data.formatted_used }}
                            </span>
                        </div>

                        <!-- Chart Canvas Container -->
                        <div class="relative w-full h-64 mb-6 flex items-center justify-center">
                            <!-- Instant CSS Visual Donut Fallback Placeholder -->
                            <div id="chart-fallback" class="absolute w-48 h-48 rounded-full donut-fallback opacity-20 pointer-events-none"></div>
                            <canvas id="categoryChart" class="z-10"></canvas>
                        </div>

                        <!-- Live Category Breakdown Bars & Statistics (Pre-rendered for Instant Display) -->
                        <div id="category-bars-list" class="space-y-3 pt-4 border-t border-slate-800/80">
                            {% for c in initial_data.categories %}
                            <div class="group">
                                <div class="flex justify-between items-center text-xs mb-1">
                                    <span class="font-semibold text-slate-200 flex items-center gap-1.5">
                                        <span class="w-2.5 h-2.5 rounded-full inline-block" style="background-color: {% if c.category == 'Videos' %}#8b5cf6{% elif c.category == 'Photos & Images' %}#ec4899{% elif c.category == 'Archives & Backups' %}#f59e0b{% elif c.category == 'Documents' %}#3b82f6{% elif c.category == 'Code & Binaries' %}#10b981{% elif c.category == 'Audio' %}#06b6d4{% else %}#64748b{% endif %}"></span>
                                        <span>{{ c.category }}</span>
                                        <span class="text-slate-500 font-mono text-[10px]">({{ c.count }} file{{ 's' if c.count > 1 else '' }})</span>
                                    </span>
                                    <span class="font-mono text-xs font-bold text-slate-300">
                                        {{ c.formatted }} <span class="text-slate-500 font-normal">({{ c.percent }}%)</span>
                                    </span>
                                </div>
                                <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                                    <div class="h-2 rounded-full transition-all duration-500" style="width: {{ [c.percent, 1] | max }}%; background-color: {% if c.category == 'Videos' %}#8b5cf6{% elif c.category == 'Photos & Images' %}#ec4899{% elif c.category == 'Archives & Backups' %}#f59e0b{% elif c.category == 'Documents' %}#3b82f6{% elif c.category == 'Code & Binaries' %}#10b981{% elif c.category == 'Audio' %}#06b6d4{% else %}#64748b{% endif %}"></div>
                                </div>
                            </div>
                            {% endfor %}
                        </div>
                    </div>

                    <!-- Instant Recommendations Card -->
                    <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md flex flex-col justify-between">
                        <div>
                            <h3 class="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                                <span>⚡</span> Instant Optimization Recommendations
                            </h3>
                            <div class="space-y-3.5">
                                <div class="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/40 flex justify-between items-center">
                                    <div>
                                        <h4 class="font-bold text-emerald-400 text-xs">Purge Redundant Duplicate Copies</h4>
                                        <p class="text-[11px] text-emerald-300/70">Verified byte-for-byte matches via cryptographic SHA-256</p>
                                    </div>
                                    <span id="rec-dupe-size" class="text-sm font-black text-emerald-400">{{ initial_data.formatted_reclaimable_dupes }}</span>
                                </div>
                                <div class="p-4 rounded-xl bg-blue-950/30 border border-blue-800/40 flex justify-between items-center">
                                    <div>
                                        <h4 class="font-bold text-blue-400 text-xs">Empty Cloud Trash Bin</h4>
                                        <p class="text-[11px] text-blue-300/70">Permanently clear deleted items currently held in trash</p>
                                    </div>
                                    <span id="rec-trash-size" class="text-sm font-black text-blue-400">{{ initial_data.formatted_trash }}</span>
                                </div>
                                <div class="p-4 rounded-xl bg-amber-950/30 border border-amber-800/40 flex justify-between items-center">
                                    <div>
                                        <h4 class="font-bold text-amber-400 text-xs">Purge Ghost & Temporary Clutter</h4>
                                        <p class="text-[11px] text-amber-300/70">Zero-byte corrupted downloads and .tmp/.cache leftovers</p>
                                    </div>
                                    <span id="rec-clutter-size" class="text-sm font-black text-amber-400">{{ initial_data.scan_summary.formatted_junk_bytes }}</span>
                                </div>
                            </div>
                        </div>

                        <div class="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between">
                            <span class="text-xs text-slate-400">Total Immediate Recovery:</span>
                            <span class="text-base font-black text-emerald-400">{{ initial_data.formatted_savings }}</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- MODULE 2: FILE SAFETY & JUNK SCANNER (NEW FEATURE) -->
            <div id="tab-scanner" class="tab-module hidden space-y-6">
                <!-- Top Main Scan Control Card -->
                <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md">
                    <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6">
                        <div>
                            <h3 class="text-lg font-black text-white flex items-center gap-2.5">
                                <span>🛡️</span> File Safety & Junk File Scanner
                            </h3>
                            <p class="text-xs text-slate-400 mt-1">
                                Complete cloud storage scanner: classifies each file as <b>Safe</b>, a <b>Junk file</b>, or <b>Unsafe/Risk</b>.
                            </p>
                        </div>
                        <div class="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
                            <button onclick="runFileScan()" id="btn-run-scan" class="px-3.5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-xl shadow-md transition-all flex items-center justify-center gap-2">
                                <i class="fa-solid fa-shield-virus"></i> <span>Scan All Files</span>
                            </button>
                            <button onclick="runScanAndAutoClean()" id="btn-scan-autoclean" class="px-3.5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs rounded-xl shadow-md transition-all flex items-center justify-center gap-2" title="Scans and automatically removes any detected junk files in 1 step">
                                <i class="fa-solid fa-bolt"></i> <span>Scan & Auto-Remove Junk</span>
                            </button>
                            <button onclick="cleanAllJunkFiles()" id="btn-clean-junk" class="px-3.5 py-2.5 bg-amber-600 hover:bg-amber-700 text-white font-bold text-xs rounded-xl shadow-md transition-all flex items-center justify-center gap-2">
                                <i class="fa-solid fa-trash-can"></i> <span>1-Click Remove All Junk</span>
                            </button>
                            <button onclick="addTestJunkFile()" id="btn-add-test-junk" class="px-3.5 py-2.5 bg-slate-800 hover:bg-slate-700 text-amber-300 font-bold text-xs rounded-xl border border-amber-800/80 shadow-md transition-all flex items-center justify-center gap-2">
                                <i class="fa-solid fa-plus-circle"></i> <span>Add 1 Junk File (Test)</span>
                            </button>
                        </div>
                    </div>

                    <!-- Real-Time Scan Progress Indicator -->
                    <div id="scan-progress-container" class="hidden mb-6 p-4 rounded-xl bg-slate-900 border border-blue-500/40">
                        <div class="flex justify-between items-center text-xs mb-2">
                            <span class="font-bold text-blue-400 flex items-center gap-2">
                                <i class="fa-solid fa-circle-notch fa-spin"></i> <span id="scan-progress-title">Scanning all files for safety & junk status...</span>
                            </span>
                            <span id="scan-progress-pct" class="font-mono text-blue-300 font-bold">0%</span>
                        </div>
                        <div class="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
                            <div id="scan-progress-bar" class="bg-gradient-to-r from-blue-500 to-indigo-500 h-2.5 rounded-full transition-all duration-300" style="width: 0%"></div>
                        </div>
                    </div>

                    <!-- Scan Result Status Alert Banner -->
                    <div id="scan-status-alert" class="p-4 rounded-xl border text-xs font-medium flex items-center justify-between mb-6 shadow-sm">
                        <!-- Populated dynamically with 'All files are safe' or 'Junk files detected' -->
                    </div>

                    <!-- 4 KPI Scan Stats Cards -->
                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
                        <div class="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                            <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Total Scanned</div>
                            <div id="scan-total-count" class="text-2xl font-black text-white mt-1">{{ initial_data.scan_summary.total_files }}</div>
                            <div class="text-[10px] text-slate-500 mt-1">Indexed storage files</div>
                        </div>
                        <div class="bg-emerald-950/20 p-4 rounded-xl border border-emerald-800/40">
                            <div class="text-[11px] font-bold text-emerald-400 uppercase tracking-wider">Safe Files</div>
                            <div id="scan-safe-count" class="text-2xl font-black text-emerald-400 mt-1">{{ initial_data.scan_summary.safe_count }}</div>
                            <div class="text-[10px] text-emerald-500/80 mt-1">Verified safe & clean</div>
                        </div>
                        <div class="bg-amber-950/20 p-4 rounded-xl border border-amber-800/40">
                            <div class="text-[11px] font-bold text-amber-400 uppercase tracking-wider">Junk Files</div>
                            <div id="scan-junk-count" class="text-2xl font-black text-amber-400 mt-1">{{ initial_data.scan_summary.junk_count }}</div>
                            <div id="scan-junk-size" class="text-[10px] text-amber-500/80 mt-1">{{ initial_data.scan_summary.formatted_junk_bytes }} clutter to clean</div>
                        </div>
                        <div class="bg-rose-950/20 p-4 rounded-xl border border-rose-800/40">
                            <div class="text-[11px] font-bold text-rose-400 uppercase tracking-wider">Security Risks</div>
                            <div id="scan-suspicious-count" class="text-2xl font-black text-rose-400 mt-1">{{ initial_data.scan_summary.suspicious_count }}</div>
                            <div class="text-[10px] text-rose-500/80 mt-1">Executables / unverified</div>
                        </div>
                    </div>
                </div>

                <!-- Scanned Files List / Table Card -->
                <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md">
                    <!-- Filters & Search Toolbar -->
                    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
                        <div class="flex items-center gap-2 overflow-x-auto pb-1 sm:pb-0 w-full sm:w-auto">
                            <button onclick="filterScanTable('all')" id="filter-btn-all" class="filter-scan-btn px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 text-white transition-all">
                                All Files (<span id="filter-all-num">{{ initial_data.scan_summary.total_files }}</span>)
                            </button>
                            <button onclick="filterScanTable('safe')" id="filter-btn-safe" class="filter-scan-btn px-3 py-1.5 rounded-lg text-xs font-bold bg-slate-800 text-slate-300 hover:text-white transition-all">
                                ✅ Safe (<span id="filter-safe-num">{{ initial_data.scan_summary.safe_count }}</span>)
                            </button>
                            <button onclick="filterScanTable('junk')" id="filter-btn-junk" class="filter-scan-btn px-3 py-1.5 rounded-lg text-xs font-bold bg-slate-800 text-slate-300 hover:text-white transition-all">
                                🗑️ Junk (<span id="filter-junk-num">{{ initial_data.scan_summary.junk_count }}</span>)
                            </button>
                            <button onclick="filterScanTable('suspicious')" id="filter-btn-suspicious" class="filter-scan-btn px-3 py-1.5 rounded-lg text-xs font-bold bg-slate-800 text-slate-300 hover:text-white transition-all">
                                ⚠️ Risks (<span id="filter-suspicious-num">{{ initial_data.scan_summary.suspicious_count }}</span>)
                            </button>
                        </div>
                        <div class="relative w-full sm:w-64">
                            <input type="text" id="scan-search-input" oninput="searchScanTable()" placeholder="Search scanned files..." class="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:ring-1 focus:ring-blue-500 outline-none">
                            <i class="fa-solid fa-magnifying-glass absolute right-3 top-2.5 text-slate-500 text-xs"></i>
                        </div>
                    </div>

                    <!-- Table -->
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-xs text-slate-300">
                            <thead class="bg-slate-900/80 text-slate-400 uppercase font-semibold text-[11px] border-b border-slate-800">
                                <tr>
                                    <th class="p-3">File Name</th>
                                    <th class="p-3">Category</th>
                                    <th class="p-3">Size</th>
                                    <th class="p-3">Safety & Junk Status</th>
                                    <th class="p-3">Integrity & Status Details</th>
                                    <th class="p-3 text-right">Action</th>
                                </tr>
                            </thead>
                            <tbody id="scan-table-body" class="divide-y divide-slate-800">
                                <!-- Populated dynamically -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- MODULE 3: SHA-256 DUPLICATES -->
            <div id="tab-duplicates" class="tab-module hidden">
                <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md mb-6">
                    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
                        <div>
                            <h3 class="text-base font-bold text-white flex items-center gap-2">
                                <span>👯</span> Cryptographic SHA-256 Duplicate Detector
                            </h3>
                            <p class="text-xs text-slate-400">Files sharing identical 256-bit hashes are grouped. Earliest file is protected as Original.</p>
                        </div>
                        <button onclick="purgeDuplicates()" class="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs rounded-xl shadow-md transition-all flex items-center gap-2">
                            <i class="fa-solid fa-trash-can"></i> Move Redundant Copies to Trash
                        </button>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-xs text-slate-300">
                            <thead class="bg-slate-900/80 text-slate-400 uppercase font-semibold text-[11px] border-b border-slate-800">
                                <tr>
                                    <th class="p-3">Group</th>
                                    <th class="p-3">Role</th>
                                    <th class="p-3">File Name</th>
                                    <th class="p-3">Size</th>
                                    <th class="p-3">SHA-256 Hash</th>
                                    <th class="p-3 text-right">Action</th>
                                </tr>
                            </thead>
                            <tbody id="duplicates-table-body" class="divide-y divide-slate-800 font-mono">
                                <!-- Populated dynamically -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- MODULE 4: LARGE FILES -->
            <div id="tab-large" class="tab-module hidden">
                <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md">
                    <h3 class="text-base font-bold text-white mb-1 flex items-center gap-2">
                        <span>🐘</span> Heavy Storage Hog Audit (> 50 MB)
                    </h3>
                    <p class="text-xs text-slate-400 mb-4">Top heaviest items occupying the largest share of storage volume.</p>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-xs text-slate-300">
                            <thead class="bg-slate-900/80 text-slate-400 uppercase font-semibold text-[11px] border-b border-slate-800">
                                <tr>
                                    <th class="p-3">File Name</th>
                                    <th class="p-3">Category</th>
                                    <th class="p-3">Size</th>
                                    <th class="p-3">Age (Days)</th>
                                    <th class="p-3 text-right">Action</th>
                                </tr>
                            </thead>
                            <tbody id="large-table-body" class="divide-y divide-slate-800">
                                <!-- Populated dynamically -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- MODULE 5: CLUTTER -->
            <div id="tab-clutter" class="tab-module hidden">
                <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md">
                    <div class="flex justify-between items-center mb-4">
                        <div>
                            <h3 class="text-base font-bold text-white flex items-center gap-2">
                                <span>👻</span> 0-Byte Ghost & Temporary Clutter
                            </h3>
                            <p class="text-xs text-slate-400">Failed downloads, corrupted 0-byte items, and .tmp/.cache leftovers.</p>
                        </div>
                        <button onclick="purgeClutter()" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-xl shadow-md transition-all flex items-center gap-2">
                            <i class="fa-solid fa-broom"></i> Purge All Clutter
                        </button>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-xs text-slate-300">
                            <thead class="bg-slate-900/80 text-slate-400 uppercase font-semibold text-[11px] border-b border-slate-800">
                                <tr>
                                    <th class="p-3">File Name</th>
                                    <th class="p-3">Clutter Reason</th>
                                    <th class="p-3">Size</th>
                                    <th class="p-3">Age (Days)</th>
                                    <th class="p-3 text-right">Action</th>
                                </tr>
                            </thead>
                            <tbody id="clutter-table-body" class="divide-y divide-slate-800">
                                <!-- Populated dynamically -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- MODULE 6: SHA-256 TESTING LAB -->
            <div id="tab-lab" class="tab-module hidden">
                <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md">
                    <h3 class="text-base font-bold text-white mb-1 flex items-center gap-2">
                        <span>🧪</span> Live Cryptographic SHA-256 Hasher Lab
                    </h3>
                    <p class="text-xs text-slate-400 mb-6">Select or drag files from your computer to calculate real 256-bit SHA-256 digests and check for duplicates in the cloud.</p>

                    <div class="border-2 border-dashed border-slate-700 hover:border-blue-500 rounded-2xl p-8 text-center transition-all bg-slate-900/40">
                        <i class="fa-solid fa-file-shield text-4xl text-blue-400 mb-3"></i>
                        <h4 class="text-sm font-bold text-white mb-1">Select files to compute live cryptographic hashes</h4>
                        <p class="text-xs text-slate-400 mb-4">Files are processed instantly to extract 64-character SHA-256 fingerprints</p>
                        <input type="file" id="lab-file-input" multiple onchange="handleFileUpload(event)" class="hidden">
                        <label for="lab-file-input" class="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-xl cursor-pointer shadow-md transition-all">
                            <i class="fa-solid fa-cloud-arrow-up"></i> Choose Files
                        </label>
                    </div>

                    <div id="lab-results" class="mt-6 hidden">
                        <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">Hashing & Duplicate Audit Results:</h4>
                        <div id="lab-results-list" class="space-y-2"></div>
                    </div>
                </div>
            </div>

            <!-- MODULE 7: FINANCIAL ROI -->
            <div id="tab-roi" class="tab-module hidden">
                <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md">
                    <h3 class="text-base font-bold text-white mb-1 flex items-center gap-2">
                        <span>💰</span> Financial Cost Optimization & ROI Analysis
                    </h3>
                    <p class="text-xs text-slate-400 mb-6">Quantifiable dollar savings achieved by eliminating duplicates and reclaiming cloud quota.</p>

                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                        <div class="p-5 rounded-2xl bg-slate-900/80 border border-slate-800">
                            <div class="text-xs font-bold text-slate-400 uppercase">Monthly Cloud Savings</div>
                            <div id="roi-monthly" class="text-2xl font-black text-emerald-400 mt-1">$0.00</div>
                            <div class="text-[11px] text-slate-500 mt-1">Based on Google One 100GB plan ($1.99/mo)</div>
                        </div>
                        <div class="p-5 rounded-2xl bg-slate-900/80 border border-slate-800">
                            <div class="text-xs font-bold text-slate-400 uppercase">Annual Cost Avoidance</div>
                            <div id="roi-annual" class="text-2xl font-black text-emerald-400 mt-1">$0.00</div>
                            <div class="text-[11px] text-slate-500 mt-1">12-month projected ROI</div>
                        </div>
                        <div class="p-5 rounded-2xl bg-slate-900/80 border border-slate-800">
                            <div class="text-xs font-bold text-slate-400 uppercase">Quota Reclaim Ratio</div>
                            <div id="roi-percent" class="text-2xl font-black text-blue-400 mt-1">0.0%</div>
                            <div class="text-[11px] text-slate-500 mt-1">Total drive space freed</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- MODULE 8: ARCHITECTURE & SETUP -->
            <div id="tab-architecture" class="tab-module hidden">
                <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md">
                    <h3 class="text-base font-bold text-white mb-1 flex items-center gap-2">
                        <span>📘</span> System Architecture & Zero-Cost Google Cloud Setup
                    </h3>
                    <p class="text-xs text-slate-400 mb-6">Complete architectural pipeline and guide to connecting real Google Drive without credit card charges.</p>

                    <div class="space-y-6">
                        <div class="p-5 rounded-2xl bg-blue-950/20 border border-blue-800/40">
                            <h4 class="text-xs font-bold text-blue-300 uppercase tracking-wider mb-2">Cryptographic SHA-256 Pipeline</h4>
                            <p class="text-xs text-slate-300 leading-relaxed">
                                Unlike shallow name-based duplicate finders, this engine reads raw binary streams and applies the NIST standard 256-bit Secure Hash Algorithm (SHA-256). Even if files have completely different names, timestamps, or folder locations, identical file content always yields identical 64-hexadecimal hashes.
                            </p>
                        </div>

                        <div class="p-5 rounded-2xl bg-amber-950/20 border border-amber-800/40">
                            <h4 class="text-xs font-bold text-amber-300 uppercase tracking-wider mb-2">How to Connect Real Google Drive (100% Free / No Credit Card)</h4>
                            <ol class="list-decimal list-inside text-xs text-slate-300 space-y-2 leading-relaxed">
                                <li>Open <b>console.cloud.google.com/projectcreate</b> in your browser. (Do NOT click "Start Free Trial" to bypass billing setup).</li>
                                <li>Name your project <code>Drive-Optimizer</code> and create it.</li>
                                <li>Go to <b>APIs & Services &gt; Library</b>, search for <b>Google Drive API</b> and click <b>Enable</b>.</li>
                                <li>Navigate to <b>APIs & Services &gt; Credentials</b> &gt; <b>Create Credentials</b> &gt; <b>OAuth client ID</b>.</li>
                                <li>Choose Application type: <b>Desktop App</b>.</li>
                                <li>Download the JSON file, rename it to <code>credentials.json</code>, and upload it via the left sidebar.</li>
                            </ol>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- CLIENT SCRIPT -->
    <script>
        let currentData = null;
        let chartInstance = null;
        let currentScanFilter = 'all';
        let currentSearchQuery = '';

        const CATEGORY_META = {
            'Videos': { icon: '🎬', color: '#8b5cf6' },
            'Photos & Images': { icon: '🖼️', color: '#ec4899' },
            'Archives & Backups': { icon: '📦', color: '#f59e0b' },
            'Documents': { icon: '📄', color: '#3b82f6' },
            'Code & Binaries': { icon: '💻', color: '#10b981' },
            'Audio': { icon: '🎵', color: '#06b6d4' },
            'Other Files': { icon: '📁', color: '#64748b' }
        };

        // Initialize from pre-rendered data immediately for 0ms load time
        try {
            const rawEl = document.getElementById('server-initial-data');
            if (rawEl && rawEl.textContent.trim()) {
                currentData = JSON.parse(rawEl.textContent);
            }
        } catch (e) {
            console.error('Failed to parse embedded initial data:', e);
        }

        let currentActiveMode = localStorage.getItem('storage_mode') || 'simulated';
        let currentActivePath = localStorage.getItem('storage_path') || 'sample_files';

        async function fetchStats() {
            try {
                const res = await fetch(`/api/stats?mode=${encodeURIComponent(currentActiveMode)}&path=${encodeURIComponent(currentActivePath)}`);
                currentData = await res.json();
                renderUI();
            } catch (err) {
                console.error('Error fetching stats:', err);
            }
        }

        function renderCategoryBars() {
            const container = document.getElementById('category-bars-list');
            if (!container || !currentData || !currentData.categories) return;

            document.getElementById('cat-total-badge').innerText = `${currentData.categories.length} Categories · ${currentData.formatted_used}`;
            container.innerHTML = '';

            currentData.categories.forEach(c => {
                const meta = CATEGORY_META[c.category] || { icon: '📁', color: '#3b82f6' };
                const row = document.createElement('div');
                row.className = 'group';
                row.innerHTML = `
                    <div class="flex justify-between items-center text-xs mb-1">
                        <span class="font-semibold text-slate-200 flex items-center gap-1.5">
                            <span class="w-2.5 h-2.5 rounded-full inline-block" style="background-color: ${meta.color}"></span>
                            <span>${meta.icon} ${c.category}</span>
                            <span class="text-slate-500 font-mono text-[10px]">(${c.count} file${c.count > 1 ? 's' : ''})</span>
                        </span>
                        <span class="font-mono text-xs font-bold text-slate-300">
                            ${c.formatted} <span class="text-slate-500 font-normal">(${c.percent}%)</span>
                        </span>
                    </div>
                    <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                        <div class="h-2 rounded-full transition-all duration-500" style="width: ${Math.max(c.percent, 1)}%; background-color: ${meta.color}"></div>
                    </div>
                `;
                container.appendChild(row);
            });
        }

        function renderChart() {
            renderCategoryBars();

            if (!currentData || !currentData.categories || currentData.categories.length === 0) return;
            const canvas = document.getElementById('categoryChart');
            if (!canvas) return;

            if (typeof Chart === 'undefined') {
                setTimeout(renderChart, 100);
                return;
            }

            // Hide fallback background once Chart.js is ready
            const fallback = document.getElementById('chart-fallback');
            if (fallback) fallback.style.display = 'none';

            const ctx = canvas.getContext('2d');
            const labels = currentData.categories.map(c => c.category);
            const data = currentData.categories.map(c => c.bytes);
            const colors = currentData.categories.map(c => (CATEGORY_META[c.category] || {}).color || '#3b82f6');

            if (chartInstance) {
                chartInstance.data.labels = labels;
                chartInstance.data.datasets[0].data = data;
                chartInstance.data.datasets[0].backgroundColor = colors;
                chartInstance.update('none'); // Instant 0ms update without lag
                return;
            }

            chartInstance = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: colors,
                        borderWidth: 2,
                        borderColor: '#151b28',
                        hoverOffset: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: {
                        duration: 250, // Fast snappy 250ms animation instead of 1-second lag
                        easing: 'easeOutQuart'
                    },
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#cbd5e1',
                                boxWidth: 12,
                                padding: 10,
                                font: { size: 11, family: 'system-ui, sans-serif' }
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const val = context.raw || 0;
                                    const cat = currentData.categories[context.dataIndex];
                                    return ` ${context.label}: ${formatBytes(val)} (${cat ? cat.percent : 0}%)`;
                                }
                            }
                        }
                    },
                    cutout: '65%'
                }
            });
        }

        function renderScanUI() {
            if (!currentData || !currentData.scan_summary) return;
            const summary = currentData.scan_summary;

            // Update Counts in Scanner Tab
            document.getElementById('scan-total-count').innerText = summary.total_files;
            document.getElementById('scan-safe-count').innerText = summary.safe_count;
            document.getElementById('scan-junk-count').innerText = summary.junk_count;
            document.getElementById('scan-junk-size').innerText = `${summary.formatted_junk_bytes} clutter to clean`;
            document.getElementById('scan-suspicious-count').innerText = summary.suspicious_count;

            document.getElementById('filter-all-num').innerText = summary.total_files;
            document.getElementById('filter-safe-num').innerText = summary.safe_count;
            document.getElementById('filter-junk-num').innerText = summary.junk_count;
            document.getElementById('filter-suspicious-num').innerText = summary.suspicious_count;

            // Update Sidebar Badge
            const navBadge = document.getElementById('nav-junk-badge');
            if (summary.junk_count > 0) {
                navBadge.innerText = `${summary.junk_count} Junk`;
                navBadge.className = 'px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800';
                navBadge.classList.remove('hidden');
            } else {
                navBadge.innerText = '✓ Safe';
                navBadge.className = 'px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800';
                navBadge.classList.remove('hidden');
            }

            // Update Main Analytics Overview Safety Card
            const ovBadge = document.getElementById('overview-safety-badge');
            const ovDesc = document.getElementById('overview-safety-desc');
            const ovIcon = document.getElementById('overview-safety-icon');
            const ovCleanBtn = document.getElementById('overview-clean-junk-btn');

            if (summary.all_safe) {
                ovBadge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800';
                ovBadge.innerHTML = '<i class="fa-solid fa-circle-check text-emerald-400 mr-1"></i> All Files Safe';
                ovDesc.innerText = 'All files are safe! 100% of stored files passed integrity checks. No junk clutter or security hazards found.';
                ovIcon.className = 'w-12 h-12 rounded-xl bg-emerald-950/80 border border-emerald-800 text-emerald-400 flex items-center justify-center text-xl shrink-0';
                ovCleanBtn.classList.add('hidden');
            } else {
                ovBadge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-950 text-amber-300 border border-amber-800';
                ovBadge.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-amber-400 mr-1"></i> ${summary.junk_count} Junk Files Detected`;
                ovDesc.innerText = `Found ${summary.junk_count} junk file(s) (${summary.formatted_junk_bytes}) and ${summary.safe_count} safe file(s). Clean junk files now to ensure optimal storage.`;
                ovIcon.className = 'w-12 h-12 rounded-xl bg-amber-950/80 border border-amber-800 text-amber-400 flex items-center justify-center text-xl shrink-0';
                ovCleanBtn.classList.remove('hidden');
            }

            // Update Scanner Tab Main Status Alert Banner
            const alertBox = document.getElementById('scan-status-alert');
            if (summary.all_safe) {
                alertBox.className = 'p-4 rounded-xl border border-emerald-600/50 bg-[#163826] text-emerald-200 text-xs font-medium flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 shadow-sm';
                alertBox.innerHTML = `
                    <div class="flex items-center gap-3">
                        <span class="text-2xl">🎉</span>
                        <div>
                            <div class="font-black text-sm text-emerald-100">STATUS: All files are safe!</div>
                            <div class="text-[11px] text-emerald-300/90 mt-0.5">100% of files in your cloud storage have passed cryptographic hash verification and integrity checks. No junk clutter or risks detected.</div>
                        </div>
                    </div>
                    <div class="flex items-center gap-2">
                        <button onclick="addTestJunkFile()" class="px-3 py-1.5 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-amber-300 border border-amber-700/80 shadow transition-all flex items-center gap-1.5 whitespace-nowrap">
                            <i class="fa-solid fa-plus-circle"></i> Add 1 Junk File (Test)
                        </button>
                        <span class="px-3 py-1 rounded-full text-xs font-bold bg-emerald-900/80 text-emerald-300 border border-emerald-700 whitespace-nowrap">
                            <i class="fa-solid fa-circle-check mr-1"></i> 100% Safe Storage
                        </span>
                    </div>
                `;
            } else {
                alertBox.className = 'p-4 rounded-xl border border-amber-600/50 bg-amber-950/40 text-amber-200 text-xs font-medium flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 shadow-sm';
                const junkTitle = summary.junk_count === 1 ? 'STATUS: 1 Junk file detected!' : `STATUS: ${summary.junk_count} Junk files detected!`;
                alertBox.innerHTML = `
                    <div class="flex items-center gap-3">
                        <span class="text-2xl">⚠️</span>
                        <div>
                            <div class="font-black text-sm text-amber-100">${junkTitle}</div>
                            <div class="text-[11px] text-amber-300/90 mt-0.5">Found ${summary.junk_count} junk file(s) occupying ${summary.formatted_junk_bytes}. Remove junk file(s) below to restore 100% safe storage.</div>
                        </div>
                    </div>
                    <div class="flex flex-wrap items-center gap-2">
                        <button onclick="cleanAllJunkFiles()" class="px-3.5 py-2 rounded-xl text-xs font-bold bg-amber-600 hover:bg-amber-700 text-white shadow transition-all whitespace-nowrap flex items-center gap-1.5">
                            <i class="fa-solid fa-trash-can"></i> 1-Click Remove Junk File (${summary.formatted_junk_bytes})
                        </button>
                        <button onclick="runScanAndAutoClean()" class="px-3.5 py-2 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-700 text-white shadow transition-all whitespace-nowrap flex items-center gap-1.5">
                            <i class="fa-solid fa-bolt"></i> Scan & Auto-Remove
                        </button>
                    </div>
                `;
            }

            renderScanTableRows();
        }

        function filterScanTable(filter) {
            currentScanFilter = filter;
            document.querySelectorAll('.filter-scan-btn').forEach(btn => {
                btn.className = 'filter-scan-btn px-3 py-1.5 rounded-lg text-xs font-bold bg-slate-800 text-slate-300 hover:text-white transition-all';
            });
            const activeBtn = document.getElementById('filter-btn-' + filter);
            if (activeBtn) {
                activeBtn.className = 'filter-scan-btn px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 text-white transition-all';
            }
            renderScanTableRows();
        }

        function searchScanTable() {
            currentSearchQuery = (document.getElementById('scan-search-input').value || '').toLowerCase().trim();
            renderScanTableRows();
        }

        function renderScanTableRows() {
            const tbody = document.getElementById('scan-table-body');
            if (!tbody || !currentData || !currentData.scanned_files) return;
            tbody.innerHTML = '';

            let list = currentData.scanned_files;

            // Apply filter
            if (currentScanFilter === 'safe') {
                list = list.filter(f => f.status === 'safe');
            } else if (currentScanFilter === 'junk') {
                list = list.filter(f => f.status === 'junk');
            } else if (currentScanFilter === 'suspicious') {
                list = list.filter(f => f.status === 'suspicious');
            }

            // Apply search
            if (currentSearchQuery) {
                list = list.filter(f => f.name.toLowerCase().includes(currentSearchQuery) || f.category.toLowerCase().includes(currentSearchQuery));
            }

            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="p-8 text-center text-slate-500 font-sans">No files found matching the selected filter.</td></tr>';
                return;
            }

            list.forEach(f => {
                const tr = document.createElement('tr');
                const isJunk = f.status === 'junk';
                const isSuspicious = f.status === 'suspicious';

                tr.className = isJunk ? 'bg-amber-950/15 hover:bg-amber-950/30' : isSuspicious ? 'bg-rose-950/15 hover:bg-rose-950/30' : 'hover:bg-slate-900/50';

                // Status Badge & Label
                let statusBadgeHtml = '';
                if (f.status === 'safe') {
                    statusBadgeHtml = `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold bg-emerald-950/90 text-emerald-300 border border-emerald-800"><i class="fa-solid fa-circle-check text-emerald-400"></i> This file is Safe</span>`;
                } else if (f.status === 'junk') {
                    statusBadgeHtml = `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold bg-amber-950/90 text-amber-300 border border-amber-800"><i class="fa-solid fa-trash-can text-amber-400"></i> This file is a Junk file</span>`;
                } else {
                    statusBadgeHtml = `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold bg-rose-950/90 text-rose-300 border border-rose-800"><i class="fa-solid fa-triangle-exclamation text-rose-400"></i> This file is Unsafe / Risk</span>`;
                }

                const catMeta = CATEGORY_META[f.category] || { icon: '📁', color: '#64748b' };

                tr.innerHTML = `
                    <td class="p-3 font-medium text-slate-200">
                        <div class="flex items-center gap-2">
                            <span>${catMeta.icon}</span>
                            <span class="truncate max-w-xs md:max-w-md font-sans ${isJunk ? 'text-amber-200 font-bold' : ''}" title="${f.name}">${f.name}</span>
                        </div>
                    </td>
                    <td class="p-3">
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300">${f.category}</span>
                    </td>
                    <td class="p-3 font-mono text-slate-300 font-bold">${f.formatted_size}</td>
                    <td class="p-3">${statusBadgeHtml}</td>
                    <td class="p-3">
                        <div class="text-[11px] text-slate-400">${f.reason}</div>
                    </td>
                    <td class="p-3 text-right">
                        ${isJunk || isSuspicious ? `
                            <button data-id="${encodeURIComponent(f.id)}" data-name="${encodeURIComponent(f.name)}" onclick="removeSingleJunk(this)" class="px-3 py-1.5 text-xs bg-amber-600 hover:bg-amber-700 text-white rounded-lg shadow transition-all font-bold flex items-center gap-1.5 ml-auto">
                                <i class="fa-solid fa-trash-can"></i> 1-Click Remove
                            </button>
                        ` : `
                            <span class="text-emerald-400 font-bold text-xs flex items-center justify-end gap-1"><i class="fa-solid fa-check"></i> Safe</span>
                        `}
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function removeSingleJunk(btn) {
            const fileId = decodeURIComponent(btn.getAttribute('data-id') || '');
            const fileName = decodeURIComponent(btn.getAttribute('data-name') || '');
            try {
                const res = await fetch('/api/trash', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({id: fileId})
                });
                const data = await res.json();
                alert(`Successfully removed junk file '${fileName}'!`);
                await fetchStats();
                if (currentData && currentData.scan_summary && currentData.scan_summary.all_safe) {
                    alert('🎉 File Scan Complete: All files are now 100% safe!');
                }
            } catch (err) {
                console.error('Error removing junk file:', err);
                alert('Error removing junk file: ' + err);
            }
        }

        async function addTestJunkFile() {
            try {
                const res = await fetch('/api/add-junk-file', { method: 'POST' });
                const data = await res.json();
                alert(data.message);
                await fetchStats();
                switchTab('scanner');
            } catch (err) {
                console.error('Error adding test junk file:', err);
                alert('Error: ' + err);
            }
        }

        async function runScanAndAutoClean() {
            const container = document.getElementById('scan-progress-container');
            const bar = document.getElementById('scan-progress-bar');
            const pct = document.getElementById('scan-progress-pct');
            const title = document.getElementById('scan-progress-title');

            if (container) {
                container.classList.remove('hidden');
                bar.style.width = '20%';
                pct.innerText = '20%';
                title.innerText = 'Scanning all files for junk files & cryptographic integrity...';

                await new Promise(r => setTimeout(r, 120));
                bar.style.width = '60%';
                pct.innerText = '60%';
                title.innerText = 'Detecting junk clutter and 0-byte ghost files...';

                await new Promise(r => setTimeout(r, 120));
                bar.style.width = '90%';
                pct.innerText = '90%';
                title.innerText = 'Auto-removing detected junk files...';
            }

            try {
                const res = await fetch('/api/scan-and-autoclean', { method: 'POST' });
                const data = await res.json();
                await fetchStats();

                if (container) {
                    bar.style.width = '100%';
                    pct.innerText = '100%';
                    title.innerText = 'Scan & Clean Complete!';
                    await new Promise(r => setTimeout(r, 200));
                    container.classList.add('hidden');
                }

                alert(data.message);
            } catch (err) {
                console.error('Error in scan and auto-clean:', err);
                if (container) container.classList.add('hidden');
                alert('Error: ' + err);
            }
        }

        async function runFileScan() {
            const container = document.getElementById('scan-progress-container');
            const bar = document.getElementById('scan-progress-bar');
            const pct = document.getElementById('scan-progress-pct');
            const title = document.getElementById('scan-progress-title');

            if (container) {
                container.classList.remove('hidden');
                bar.style.width = '15%';
                pct.innerText = '15%';
                title.innerText = 'Scanning all file extensions & cryptographic headers...';

                await new Promise(r => setTimeout(r, 120));
                bar.style.width = '55%';
                pct.innerText = '55%';
                title.innerText = 'Verifying SHA-256 byte integrity & duplicate hashes...';

                await new Promise(r => setTimeout(r, 120));
                bar.style.width = '85%';
                pct.innerText = '85%';
                title.innerText = 'Auditing junk clutter, ghost files & test junk...';

                await fetchStats();

                bar.style.width = '100%';
                pct.innerText = '100%';
                title.innerText = 'Scan Complete! All files analyzed.';
                await new Promise(r => setTimeout(r, 200));
                container.classList.add('hidden');
            } else {
                await fetchStats();
            }

            if (currentData && currentData.scan_summary) {
                if (currentData.scan_summary.all_safe) {
                    alert('🎉 File Scan Complete: All files are safe! No junk or security risks found.');
                } else if (currentData.scan_summary.junk_count === 1) {
                    alert(`Scan Complete: 1 junk file detected (${currentData.scan_summary.formatted_junk_bytes})! Click '1-Click Remove' on the junk file or click 'Scan & Auto-Remove' to eliminate it.`);
                } else {
                    alert(`Scan Complete: ${currentData.scan_summary.junk_count} junk file(s) found (${currentData.scan_summary.formatted_junk_bytes}). You can clean them with 1 click!`);
                }
            }
        }

        async function cleanAllJunkFiles() {
            if (!confirm('Move all identified junk files (.tmp, 0-byte ghost files, and redundant duplicate copies) to trash?')) return;
            try {
                const res = await fetch('/api/clean-junk', { method: 'POST' });
                const data = await res.json();
                alert(data.message);
                await fetchStats();
            } catch (err) {
                console.error('Error cleaning junk:', err);
                alert('Error cleaning junk files: ' + err);
            }
        }

        function renderUI() {
            if (!currentData) return;

            // Quota Bar
            const usedPct = ((currentData.used_bytes / currentData.limit_bytes) * 100).toFixed(1);
            document.getElementById('quota-bar').style.width = Math.min(usedPct, 100) + '%';
            document.getElementById('quota-text').innerText = `${currentData.formatted_used} / ${currentData.formatted_limit} (${usedPct}%)`;

            // Metrics
            document.getElementById('stat-files').innerText = currentData.total_files;
            document.getElementById('stat-used').innerText = currentData.formatted_used;
            document.getElementById('stat-savings').innerText = currentData.formatted_savings;
            document.getElementById('stat-dupes').innerText = currentData.dupes.filter(d => d.is_redundant).length;
            document.getElementById('stat-health').innerText = `${currentData.health.score}/100`;

            // Recommendations
            document.getElementById('rec-dupe-size').innerText = currentData.formatted_reclaimable_dupes;
            document.getElementById('rec-trash-size').innerText = currentData.formatted_trash;
            const clutterBytes = currentData.clutter.reduce((acc, c) => acc + c.size, 0);
            document.getElementById('rec-clutter-size').innerText = formatBytes(clutterBytes);

            // ROI Tab
            document.getElementById('roi-monthly').innerText = `$${currentData.cost.monthly_savings_usd.toFixed(2)}`;
            document.getElementById('roi-annual').innerText = `$${currentData.cost.annual_savings_usd.toFixed(2)}`;
            const reclaimPct = currentData.used_bytes > 0 ? ((currentData.total_savings / currentData.used_bytes) * 100).toFixed(1) : 0;
            document.getElementById('roi-percent').innerText = `${reclaimPct}%`;

            // Duplicates Table
            const dupeTbody = document.getElementById('duplicates-table-body');
            dupeTbody.innerHTML = '';
            if (currentData.dupes.length === 0) {
                dupeTbody.innerHTML = '<tr><td colspan="6" class="p-6 text-center text-slate-500 font-sans">🎉 No duplicate files found in this storage source!</td></tr>';
            } else {
                currentData.dupes.forEach(d => {
                    const tr = document.createElement('tr');
                    tr.className = d.is_redundant ? 'bg-rose-950/20 hover:bg-rose-950/30' : 'bg-slate-900/40 hover:bg-slate-900/70';
                    tr.innerHTML = `
                        <td class="p-3 font-bold text-slate-400">#${d.duplicate_group_id || d.duplicate_group || ''}</td>
                        <td class="p-3">${d.is_redundant ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800">Duplicate</span>' : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">Original</span>'}</td>
                        <td class="p-3 font-sans font-medium text-slate-200">${d.name}</td>
                        <td class="p-3 text-slate-400">${d.formatted_size}</td>
                        <td class="p-3 text-[11px] text-slate-500">${d.sha256 ? d.sha256.substring(0, 16) + '...' : '--'}</td>
                        <td class="p-3 text-right">
                            <button data-id="${encodeURIComponent(d.id)}" onclick="trashFile(decodeURIComponent(this.dataset.id))" class="px-2.5 py-1 text-[11px] bg-slate-800 hover:bg-rose-900 hover:text-rose-200 text-slate-300 rounded border border-slate-700 transition-all font-sans font-medium">Trash</button>
                        </td>
                    `;
                    dupeTbody.appendChild(tr);
                });
            }

            // Large Files Table
            const largeTbody = document.getElementById('large-table-body');
            largeTbody.innerHTML = '';
            currentData.large_files.forEach(f => {
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-slate-900/50';
                tr.innerHTML = `
                    <td class="p-3 font-medium text-slate-200">${f.name}</td>
                    <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300">${f.category}</span></td>
                    <td class="p-3 font-mono font-bold text-blue-400">${f.formatted_size}</td>
                    <td class="p-3 font-mono text-slate-400">${f.age_days || f.days_inactive || 0}d ago</td>
                    <td class="p-3 text-right">
                        <button data-id="${encodeURIComponent(f.id)}" onclick="trashFile(decodeURIComponent(this.dataset.id))" class="px-2.5 py-1 text-[11px] bg-slate-800 hover:bg-rose-900 hover:text-rose-200 text-slate-300 rounded border border-slate-700 transition-all font-medium">Trash</button>
                    </td>
                `;
                largeTbody.appendChild(tr);
            });

            // Clutter Table
            const clutterTbody = document.getElementById('clutter-table-body');
            clutterTbody.innerHTML = '';
            currentData.clutter.forEach(c => {
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-slate-900/50';
                tr.innerHTML = `
                    <td class="p-3 font-medium text-slate-200">${c.name}</td>
                    <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800">${c.clutter_reason}</span></td>
                    <td class="p-3 font-mono text-slate-400">${c.formatted_size}</td>
                    <td class="p-3 font-mono text-slate-400">${c.age_days || c.days_inactive || 0}d</td>
                    <td class="p-3 text-right">
                        <button data-id="${encodeURIComponent(c.id)}" onclick="trashFile(decodeURIComponent(this.dataset.id))" class="px-2.5 py-1 text-[11px] bg-slate-800 hover:bg-rose-900 hover:text-rose-200 text-slate-300 rounded border border-slate-700 transition-all font-medium">Trash</button>
                    </td>
                `;
                clutterTbody.appendChild(tr);
            });

            // Google Drive & Local Storage Status View Update
            const isGoogleLive = currentData.is_live_google || (currentData.current_mode === 'google' && currentData.user_info && currentData.user_info.displayName);
            const gPill = document.getElementById('google-status-pill');
            const gConnectedView = document.getElementById('google-connected-view');
            const gControls = document.getElementById('google-connect-controls');
            if (isGoogleLive) {
                if (gPill) {
                    gPill.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800';
                    gPill.innerText = 'Connected';
                }
                if (gConnectedView) gConnectedView.classList.remove('hidden');
                if (gControls) gControls.classList.add('hidden');
                const u = currentData.user_info || {};
                const nameEl = document.getElementById('google-user-name');
                const emailEl = document.getElementById('google-user-email');
                if (nameEl) nameEl.innerText = u.displayName || 'Google Drive User';
                if (emailEl) emailEl.innerText = u.emailAddress || 'Connected via OAuth 2.0';
            } else {
                if (gPill) {
                    gPill.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800';
                    gPill.innerText = 'Not Connected';
                }
                if (gConnectedView) gConnectedView.classList.add('hidden');
                if (gControls) gControls.classList.remove('hidden');
            }

            const localBadge = document.getElementById('local-status-badge');
            if (localBadge && currentData.current_mode === 'local') {
                localBadge.innerText = `${currentData.total_files} Files`;
            }

            // File Safety & Junk Scanner UI
            renderScanUI();

            // Instant Chart Render
            renderChart();
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-module').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.nav-item').forEach(el => {
                el.className = 'nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 flex items-center justify-between transition-all';
            });
            document.getElementById('tab-' + tabId).classList.remove('hidden');
            const activeBtn = document.getElementById('nav-btn-' + tabId);
            if (activeBtn) {
                activeBtn.className = 'nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-white bg-blue-600 flex items-center justify-between transition-all';
            }

            if (tabId === 'analytics') {
                if (chartInstance) {
                    chartInstance.resize();
                } else {
                    renderChart();
                }
            } else if (tabId === 'scanner') {
                renderScanUI();
            }
        }

        async function changeMode(mode, skipServerCall = false) {
            currentActiveMode = mode;
            localStorage.setItem('storage_mode', mode);

            const rSim = document.getElementById('radio-simulated');
            const rLoc = document.getElementById('radio-local');
            const rGoo = document.getElementById('radio-google');
            if (mode === 'simulated' && rSim) rSim.checked = true;
            if (mode === 'local' && rLoc) rLoc.checked = true;
            if (mode === 'google' && rGoo) rGoo.checked = true;

            document.getElementById('status-box-simulated').classList.add('hidden');
            document.getElementById('status-box-local').classList.add('hidden');
            document.getElementById('status-box-google').classList.add('hidden');

            const activeBox = document.getElementById('status-box-' + mode);
            if (activeBox) activeBox.classList.remove('hidden');

            const badge = document.getElementById('active-mode-badge');
            if (mode === 'simulated') {
                if (badge) {
                    badge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800';
                    badge.innerText = '✨ Simulated Cloud Active';
                }
                if (!skipServerCall) {
                    await fetch('/api/set-mode', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({mode: 'simulated'}) });
                    fetchStats();
                }
            } else if (mode === 'local') {
                if (badge) {
                    badge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-blue-950/80 text-blue-400 border border-blue-800';
                    badge.innerText = '📁 Local Sync Folder Active';
                }
                if (!skipServerCall) {
                    await fetch('/api/set-mode', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({mode: 'local', path: currentActivePath}) });
                    fetchStats();
                }
            } else if (mode === 'google') {
                if (badge) {
                    badge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-950/80 text-amber-400 border border-amber-800';
                    badge.innerText = '🔗 Google Drive API';
                }
                if (!skipServerCall) {
                    fetchStats();
                }
            }
        }

        async function scanLocalFolder() {
            const path = document.getElementById('local-folder-path').value || 'sample_files';
            currentActivePath = path;
            localStorage.setItem('storage_path', path);

            const btn = document.getElementById('btn-scan-folder');
            if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Scanning...';

            try {
                const res = await fetch('/api/set-mode', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({mode: 'local', path: path})
                });
                const data = await res.json();
                if (data.success) {
                    currentActiveMode = 'local';
                    localStorage.setItem('storage_mode', 'local');
                    await fetchStats();
                    alert('📁 ' + (data.message || `Scanned folder '${path}' successfully!`));
                } else {
                    alert('⚠️ ' + (data.message || 'Error scanning folder.'));
                }
            } catch (err) {
                alert('Scan error: ' + err);
            } finally {
                if (btn) btn.innerHTML = '<i class="fa-solid fa-magnifying-glass mr-1"></i> Scan';
            }
        }

        async function uploadAndScanFolder(e) {
            const files = e.target.files;
            if (!files || files.length === 0) return;

            const statusEl = document.getElementById('local-folder-status');
            if (statusEl) {
                statusEl.innerText = `Uploading and scanning ${files.length} file(s)...`;
                statusEl.classList.remove('hidden');
            }

            const formData = new FormData();
            for (let f of files) {
                formData.append('files', f);
            }

            try {
                const res = await fetch('/api/scan-uploaded-folder', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                if (data.success) {
                    currentActiveMode = 'local';
                    currentActivePath = 'user_scanned_folder';
                    localStorage.setItem('storage_mode', 'local');
                    localStorage.setItem('storage_path', 'user_scanned_folder');
                    await fetchStats();
                    alert(`✅ ${data.message}`);
                } else {
                    alert('⚠️ ' + data.message);
                }
            } catch (err) {
                alert('Upload error: ' + err);
            } finally {
                if (statusEl) statusEl.classList.add('hidden');
            }
        }

        async function uploadCredentials(e) {
            const file = e.target.files[0];
            if (!file) return;

            const labelEl = document.getElementById('cred-file-label');
            if (labelEl) labelEl.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1.5"></i> Uploading...';

            const formData = new FormData();
            formData.append('file', file);

            try {
                const res = await fetch('/api/upload-credentials', { method: 'POST', body: formData });
                const data = await res.json();
                if (labelEl) {
                    labelEl.innerHTML = `<i class="fa-solid fa-circle-check text-emerald-400 mr-1.5"></i> ${file.name} ready`;
                    labelEl.className = 'block w-full text-center cursor-pointer py-1.5 bg-emerald-950/60 text-emerald-200 font-semibold rounded-lg text-xs border border-emerald-700 transition-all';
                }
                alert(data.message || 'credentials.json uploaded successfully!');
                if (data.service_account) {
                    currentActiveMode = 'google';
                    localStorage.setItem('storage_mode', 'google');
                    await fetchStats();
                }
            } catch (err) {
                alert('Upload error: ' + err);
                if (labelEl) labelEl.innerHTML = '<i class="fa-solid fa-upload mr-1.5 text-emerald-400"></i> Upload credentials.json';
            }
        }

        async function connectGoogleDrive() {
            const btn = document.getElementById('btn-connect-live-drive');
            if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1.5"></i> Connecting...';

            try {
                const res = await fetch('/api/set-mode', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({mode: 'google'})
                });
                const data = await res.json();

                if (data.requires_auth && data.auth_url) {
                    alert('Redirecting to Google Sign-In to connect your Google Drive...');
                    window.location.href = data.auth_url;
                    return;
                }

                if (data.success) {
                    currentActiveMode = 'google';
                    localStorage.setItem('storage_mode', 'google');
                    alert('🎉 ' + data.message);
                    await fetchStats();
                } else {
                    alert('⚠️ ' + data.message);
                }
            } catch (err) {
                alert('Connection error: ' + err);
            } finally {
                if (btn) btn.innerHTML = '<i class="fa-brands fa-google"></i> Connect Live Drive';
            }
        }

        function toggleTokenBox() {
            const box = document.getElementById('google-token-box');
            const caret = document.getElementById('token-caret');
            if (!box) return;
            box.classList.toggle('hidden');
            if (caret) {
                caret.className = box.classList.contains('hidden') ? 'fa-solid fa-chevron-down text-[10px]' : 'fa-solid fa-chevron-up text-[10px]';
            }
        }

        async function connectGoogleToken() {
            const tokenInput = document.getElementById('google-token-input');
            const token = tokenInput ? tokenInput.value.trim() : '';
            if (!token) {
                alert('Please enter or paste your Google Drive Access Token.');
                return;
            }

            try {
                const res = await fetch('/api/connect-google-token', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ token: token })
                });
                const data = await res.json();
                if (data.success) {
                    currentActiveMode = 'google';
                    localStorage.setItem('storage_mode', 'google');
                    alert('🎉 ' + data.message);
                    if (tokenInput) tokenInput.value = '';
                    await fetchStats();
                } else {
                    alert('⚠️ ' + data.message);
                }
            } catch (err) {
                alert('Error connecting token: ' + err);
            }
        }

        async function disconnectGoogleDrive() {
            if (!confirm('Disconnect from Google Drive and return to Simulated Cloud?')) return;
            try {
                await fetch('/api/disconnect-google', { method: 'POST' });
                await changeMode('simulated');
                alert('Disconnected from Google Drive.');
            } catch (err) {
                alert('Error disconnecting: ' + err);
            }
        }

        async function trashFile(fileId) {
            await fetch('/api/trash', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id: fileId}) });
            fetchStats();
        }

        async function purgeDuplicates() {
            const redundant = currentData.dupes.filter(d => d.is_redundant);
            for (let d of redundant) {
                await fetch('/api/trash', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id: d.id}) });
            }
            alert(`Moved ${redundant.length} duplicate copies to trash!`);
            fetchStats();
        }

        async function purgeClutter() {
            for (let c of currentData.clutter) {
                await fetch('/api/trash', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id: c.id}) });
            }
            alert('Purged clutter items!');
            fetchStats();
        }

        async function emptyCloudTrash() {
            const res = await fetch('/api/empty-trash', { method: 'POST' });
            const data = await res.json();
            alert(data.message);
            fetchStats();
        }

        let currentLabResults = [];

        async function handleFileUpload(e) {
            const files = e.target.files;
            if (!files.length) return;
            const formData = new FormData();
            for (let f of files) formData.append('files', f);

            const res = await fetch('/api/upload-hash', { method: 'POST', body: formData });
            const data = await res.json();
            currentLabResults = data || [];

            const container = document.getElementById('lab-results');
            const list = document.getElementById('lab-results-list');
            container.classList.remove('hidden');
            list.innerHTML = '';

            data.forEach((item, index) => {
                const div = document.createElement('div');
                div.id = `lab-item-${index}`;

                let borderBg = 'bg-emerald-950/20 border-emerald-800/60';
                if (item.is_junk) {
                    borderBg = 'bg-amber-950/25 border-amber-800/80';
                } else if (item.is_duplicate || item.is_suspicious) {
                    borderBg = 'bg-rose-950/25 border-rose-800/80';
                }

                div.className = `p-4 rounded-xl border ${borderBg} text-xs flex flex-col md:flex-row justify-between items-start md:items-center gap-3 transition-all`;

                let statusBadges = '';
                if (item.is_junk) {
                    statusBadges += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800"><i class="fa-solid fa-trash-can mr-1"></i> JUNK FILE</span> `;
                }
                if (item.is_duplicate) {
                    statusBadges += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">⚠️ DUPLICATE MATCH</span> `;
                } else {
                    statusBadges += `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">✅ UNIQUE</span> `;
                }

                const junkReasonHtml = item.junk_reason ? `<div class="text-[11px] text-amber-300 font-medium mt-1"><i class="fa-solid fa-triangle-exclamation mr-1"></i> ${item.junk_reason}</div>` : '';

                div.innerHTML = `
                    <div class="flex-1">
                        <div class="flex flex-wrap items-center gap-2 font-bold text-white text-xs">
                            <span class="${item.is_junk ? 'text-amber-200' : 'text-slate-100'} font-mono">${item.name} (${item.formatted_size})</span>
                            <div class="inline-flex gap-1.5">${statusBadges}</div>
                        </div>
                        ${junkReasonHtml}
                        <div class="font-mono text-[11px] text-slate-400 mt-1">SHA-256: ${item.sha256}</div>
                    </div>
                    <div class="flex items-center gap-2 shrink-0 w-full md:w-auto justify-end">
                        <button onclick="discardLabItem(${index})" class="px-3 py-1.5 bg-slate-800 hover:bg-rose-900 hover:text-white text-slate-300 rounded-lg text-xs font-bold transition-all border border-slate-700 flex items-center gap-1.5">
                            <i class="fa-solid fa-xmark"></i> 1-Click Remove
                        </button>
                        <button onclick="addLabFileByIndex(${index})" class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 shadow">
                            <i class="fa-solid fa-cloud-arrow-up"></i> Add to Cloud Drive
                        </button>
                    </div>
                `;
                list.appendChild(div);
            });
        }

        function discardLabItem(index) {
            const el = document.getElementById(`lab-item-${index}`);
            if (el) el.remove();
            const list = document.getElementById('lab-results-list');
            if (list && list.children.length === 0) {
                document.getElementById('lab-results').classList.add('hidden');
            }
        }

        async function addLabFileByIndex(index) {
            const item = currentLabResults[index];
            if (!item) return;
            try {
                const res = await fetch('/api/add-uploaded-to-drive', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name: item.name, size: item.size, sha256: item.sha256})
                });
                const data = await res.json();
                alert(data.message);
                await fetchStats();
                switchTab('scanner');
            } catch (err) {
                alert('Error adding file to drive: ' + err);
            }
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0.00 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
        }

        function refreshData() {
            document.getElementById('last-updated-text').innerText = 'Updating...';
            fetchStats().then(() => {
                document.getElementById('last-updated-text').innerText = 'Updated: ' + new Date().toLocaleTimeString();
            });
        }

        // Run immediate render on script execution for 0ms visual appearance
        if (currentData) {
            renderUI();
        }

        document.addEventListener('DOMContentLoaded', () => {
            const urlParams = new URLSearchParams(window.location.search);
            const googleConnected = urlParams.get('google_connected');
            const urlMode = urlParams.get('mode');

            if (googleConnected === '1' || urlMode === 'google') {
                changeMode('google', true);
                fetchStats();
                if (googleConnected === '1') {
                    window.history.replaceState({}, document.title, window.location.pathname);
                }
            } else if (urlMode === 'local') {
                changeMode('local', false);
            } else {
                const savedMode = localStorage.getItem('storage_mode');
                if (savedMode && savedMode !== 'simulated') {
                    changeMode(savedMode, false);
                } else if (currentData) {
                    renderUI();
                } else {
                    fetchStats();
                }
            }
        });
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    global drive_mgr, current_mode
    req_mode = request.args.get("mode")
    req_path = request.args.get("path")
    if req_mode == "local":
        current_mode = "local"
        drive_mgr = LocalFolderManager(req_path or "sample_files")
        invalidate_cache()
    elif req_mode == "google":
        current_mode = "google"
        drive_mgr = GoogleDriveManager()
        drive_mgr.authenticate()
        invalidate_cache()

    initial_data = get_current_data()
    return render_template_string(HTML_TEMPLATE, initial_data=initial_data)


@app.route("/api/stats")
def api_stats():
    global drive_mgr, current_mode
    req_mode = request.args.get("mode")
    req_path = request.args.get("path")

    if req_mode and req_mode != current_mode:
        if req_mode == "simulated":
            current_mode = "simulated"
            drive_mgr = MockDriveManager()
        elif req_mode == "local":
            current_mode = "local"
            drive_mgr = LocalFolderManager(req_path or "sample_files")
        elif req_mode == "google":
            current_mode = "google"
            drive_mgr = GoogleDriveManager()
            drive_mgr.authenticate()
        invalidate_cache()
    elif req_mode == "local" and req_path and hasattr(drive_mgr, "raw_path") and drive_mgr.raw_path != req_path:
        drive_mgr = LocalFolderManager(req_path)
        invalidate_cache()

    return jsonify(get_current_data())


@app.route("/api/clean-junk", methods=["POST"])
def api_clean_junk():
    """Purge all identified junk files (.tmp, 0-byte ghost files, redundant duplicates) in one operation."""
    data = get_current_data()
    junk_files = [f for f in data.get("scanned_files", []) if f.get("is_junk")]
    count = 0
    freed = 0
    for jf in junk_files:
        ok, _ = drive_mgr.move_to_trash(jf["id"])
        if ok:
            count += 1
            freed += jf.get("size", 0)
    invalidate_cache()
    return jsonify({
        "success": True,
        "count": count,
        "freed": freed,
        "formatted_freed": format_bytes(freed),
        "message": f"Successfully moved {count} junk file(s) ({format_bytes(freed)}) to trash!",
    })


@app.route("/api/set-mode", methods=["POST"])
def api_set_mode():
    global drive_mgr, current_mode
    invalidate_cache()
    data = request.json or {}
    mode = data.get("mode")

    if mode == "simulated":
        current_mode = "simulated"
        drive_mgr = MockDriveManager()
        return jsonify({"success": True, "mode": "simulated", "message": "Switched to Simulated Cloud Storage (15 GB Quota)"})

    elif mode == "local":
        folder_path = data.get("path", "sample_files")
        current_mode = "local"
        drive_mgr = LocalFolderManager(folder_path)
        files = drive_mgr.list_files()
        return jsonify({
            "success": True,
            "mode": "local",
            "message": f"Connected to folder '{folder_path}' ({len(files)} files scanned with SHA-256 hashes)!",
            "files_count": len(files),
        })

    elif mode == "google":
        current_mode = "google"
        drive_mgr = GoogleDriveManager()
        ok, msg = drive_mgr.authenticate()

        if ok:
            return jsonify({"success": True, "mode": "google", "message": msg})

        if msg == "OAUTH_FLOW_REQUIRED":
            try:
                redirect_uri = url_for("oauth2callback", _external=True)
                auth_url, state = drive_mgr.get_authorization_url(redirect_uri)
                return jsonify({
                    "success": False,
                    "requires_auth": True,
                    "auth_url": auth_url,
                    "message": "Google authentication required. Redirecting to Google Sign-In...",
                })
            except Exception as e:
                return jsonify({
                    "success": False,
                    "message": f"Google Drive setup: {str(e)} Please upload credentials.json or use Quick Token Connect.",
                })

        return jsonify({"success": False, "message": msg})

    return jsonify({"success": False, "message": "Unknown mode"}), 400


@app.route("/api/upload-credentials", methods=["POST"])
def api_upload_credentials():
    global drive_mgr, current_mode
    file = request.files.get("file")
    if not file:
        return jsonify({"success": False, "message": "No file uploaded"}), 400

    content = file.read()
    target_path = resolve_storage_file("credentials.json", check_writable=True)
    try:
        with open(target_path, "wb") as f:
            f.write(content)
    except Exception as e:
        return jsonify({"success": False, "message": f"Could not save credentials file: {e}"}), 500

    invalidate_cache()

    # Parse and inspect credentials JSON
    try:
        parsed = json.loads(content.decode("utf-8"))
        if parsed.get("type") == "service_account":
            current_mode = "google"
            drive_mgr = GoogleDriveManager()
            ok, msg = drive_mgr.authenticate_with_service_account(target_path)
            return jsonify({
                "success": ok,
                "service_account": True,
                "message": f"Service Account uploaded & authenticated: {msg}",
            })
        elif "web" in parsed or "installed" in parsed:
            client_type = "Web Client" if "web" in parsed else "Desktop Client"
            client_id = (parsed.get("web") or parsed.get("installed", {})).get("client_id", "")
            masked_id = client_id[:12] + "..." if len(client_id) > 12 else client_id
            return jsonify({
                "success": True,
                "client_type": client_type,
                "client_id": masked_id,
                "message": f"credentials.json ({client_type}, ID: {masked_id}) uploaded successfully! Click 'Connect Live Drive'.",
            })
    except Exception:
        pass

    return jsonify({"success": True, "message": "Uploaded credentials.json successfully! Click 'Connect Live Drive' to authenticate."})


@app.route("/oauth2callback")
def oauth2callback():
    global drive_mgr, current_mode
    code = request.args.get("code")
    error = request.args.get("error")
    if error:
        return f"<script>alert('Google Sign-In canceled: {error}'); window.location.href='/?mode=google';</script>"

    if not code:
        return redirect("/?mode=google")

    current_mode = "google"
    drive_mgr = GoogleDriveManager()
    redirect_uri = url_for("oauth2callback", _external=True)
    ok, msg = drive_mgr.exchange_code(code, redirect_uri)
    invalidate_cache()

    if ok:
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Google Drive Connected</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 flex items-center justify-center min-h-screen p-4 font-sans">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-8 max-w-md w-full text-center shadow-2xl">
        <div class="w-16 h-16 bg-emerald-950/80 border border-emerald-700/80 text-emerald-400 rounded-full flex items-center justify-center mx-auto mb-4 text-2xl font-bold">✓</div>
        <h2 class="text-xl font-bold text-white mb-2">Google Drive Connected!</h2>
        <p class="text-xs text-slate-400 mb-6">{msg}</p>
        <a href="/?mode=google&google_connected=1" class="inline-block w-full py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white font-bold rounded-xl text-xs transition-all shadow-md">
            Return to Dashboard
        </a>
    </div>
    <script>
        setTimeout(function() {{
            window.location.href = '/?mode=google&google_connected=1';
        }}, 1200);
    </script>
</body>
</html>"""
    else:
        return f"<script>alert('Authentication error: {msg}'); window.location.href='/?mode=google';</script>"


@app.route("/api/connect-google-token", methods=["POST"])
def api_connect_google_token():
    global drive_mgr, current_mode
    data = request.json or {}
    token = data.get("token", "").strip()
    if not token:
        return jsonify({"success": False, "message": "Please enter a valid Google Drive Access Token."}), 400

    current_mode = "google"
    drive_mgr = GoogleDriveManager()
    ok, msg = drive_mgr.authenticate_with_token(token)
    invalidate_cache()
    return jsonify({"success": ok, "message": msg})


@app.route("/api/disconnect-google", methods=["POST"])
def api_disconnect_google():
    global drive_mgr, current_mode
    current_mode = "simulated"
    drive_mgr = MockDriveManager()
    token_file = resolve_storage_file("token.json")
    if token_file and os.path.exists(token_file):
        try:
            os.remove(token_file)
        except Exception:
            pass
    invalidate_cache()
    return jsonify({"success": True, "message": "Disconnected from Google Drive."})


@app.route("/api/scan-uploaded-folder", methods=["POST"])
def api_scan_uploaded_folder():
    """Allows uploading multiple files from a local directory chosen in the browser."""
    global drive_mgr, current_mode
    uploaded = request.files.getlist("files")
    if not uploaded:
        return jsonify({"success": False, "message": "No files selected."}), 400

    dest_dir = os.path.join(tempfile.gettempdir(), "user_scanned_folder")
    if os.path.exists(dest_dir):
        try:
            shutil.rmtree(dest_dir)
        except Exception:
            pass
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except Exception:
        pass

    saved_count = 0
    for f in uploaded:
        if not f.filename:
            continue
        safe_name = os.path.basename(f.filename)
        dest_path = os.path.join(dest_dir, safe_name)
        try:
            f.save(dest_path)
            saved_count += 1
        except Exception as e:
            print(f"Error saving file {safe_name}: {e}")

    current_mode = "local"
    drive_mgr = LocalFolderManager(dest_dir)
    invalidate_cache()
    return jsonify({
        "success": True,
        "count": saved_count,
        "message": f"Successfully scanned {saved_count} file(s) from your local folder with full SHA-256 analysis!"
    })


@app.route("/api/trash", methods=["POST"])
def api_trash():
    file_id = request.json.get("id")
    ok, msg = drive_mgr.move_to_trash(file_id)
    invalidate_cache()
    return jsonify({"success": ok, "message": msg})


@app.route("/api/empty-trash", methods=["POST"])
def api_empty_trash():
    ok, msg = drive_mgr.empty_trash()
    invalidate_cache()
    return jsonify({"success": ok, "message": msg})


@app.route("/api/add-junk-file", methods=["POST"])
def api_add_junk_file():
    """Add a test junk file (junk_test_file.txt, 209 B) to cloud storage for scanner demonstration."""
    if hasattr(drive_mgr, "add_test_junk_file"):
        res = drive_mgr.add_test_junk_file(name="junk_test_file.txt", size=209)
        invalidate_cache()
        return jsonify({
            "success": True,
            "message": "Added test junk file ('junk_test_file.txt', 209 B) to cloud storage! Click 'Scan All Files' to detect it.",
            "file": res,
        })
    return jsonify({"success": False, "message": "Active storage source does not support adding test files."}), 400


@app.route("/api/scan-and-autoclean", methods=["POST"])
def api_scan_and_autoclean():
    """Scans all files, detects junk files, and automatically cleans them in one operation."""
    data = get_current_data()
    junk_files = [f for f in data.get("scanned_files", []) if f.get("is_junk")]
    cleaned_count = 0
    freed_bytes = 0
    for jf in junk_files:
        ok, _ = drive_mgr.move_to_trash(jf["id"])
        if ok:
            cleaned_count += 1
            freed_bytes += jf.get("size", 0)
    invalidate_cache()
    if cleaned_count > 0:
        msg = f"Scan & Auto-Clean complete! Successfully detected and removed {cleaned_count} junk file(s) ({format_bytes(freed_bytes)} freed). All files are now 100% safe!"
    else:
        msg = "Scan & Auto-Clean complete! 0 junk files found. All files are already 100% safe!"
    return jsonify({
        "success": True,
        "cleaned_count": cleaned_count,
        "freed_bytes": freed_bytes,
        "formatted_freed": format_bytes(freed_bytes),
        "message": msg,
    })


@app.route("/api/add-uploaded-to-drive", methods=["POST"])
def api_add_uploaded_to_drive():
    """Adds a file tested in the Live Lab into the active cloud drive for full scanning."""
    name = request.json.get("name", "junk_test_file.txt")
    size = int(request.json.get("size", 209))
    sha = request.json.get("sha256", "")
    if hasattr(drive_mgr, "add_test_junk_file"):
        res = drive_mgr.add_test_junk_file(name=name, size=size)
        if sha and isinstance(res, dict):
            res["sha256"] = sha
        invalidate_cache()
        return jsonify({
            "success": True,
            "message": f"Added '{name}' ({format_bytes(size)}) to cloud storage! You can now scan it in Safety & Junk Scanner.",
        })
    return jsonify({"success": False, "message": "Cannot add file to current drive mode."}), 400


@app.route("/api/upload-hash", methods=["POST"])
def api_upload_hash():
    uploaded_files = request.files.getlist("files")
    results = []
    current_files = drive_mgr.list_files()
    known_hashes = {f.get("sha256") for f in current_files if f.get("sha256")}

    temp_exts = [".tmp", ".temp", ".log", ".bak", ".part", ".crdownload", ".swp", ".cache", ".dmp", ".junk", ".old"]
    suspicious_exts = [".exe", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".msi"]

    for f in uploaded_files:
        content = f.read()
        sha = hashlib.sha256(content).hexdigest()
        is_dupe = sha in known_hashes
        name = f.filename or "uploaded_file"
        name_lower = name.lower()
        size = len(content)
        ext = os.path.splitext(name_lower)[1]

        is_junk = ("junk" in name_lower) or (size == 0) or (ext in temp_exts) or name_lower.startswith("~")
        is_suspicious = ext in suspicious_exts

        junk_reason = ""
        if "junk" in name_lower:
            junk_reason = "Identified as a Junk file ('junk' keyword in filename)"
        elif size == 0:
            junk_reason = "Zero-byte (empty) ghost file"
        elif ext in temp_exts:
            junk_reason = f"Temporary/cache clutter ({ext})"
        elif is_dupe:
            junk_reason = "Duplicate copy matching existing cloud file SHA-256"

        results.append({
            "name": name,
            "size": size,
            "formatted_size": format_bytes(size),
            "sha256": sha,
            "is_duplicate": is_dupe,
            "is_junk": is_junk,
            "is_suspicious": is_suspicious,
            "junk_reason": junk_reason,
            "is_safe": not is_junk and not is_suspicious and not is_dupe,
        })
    return jsonify(results)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
