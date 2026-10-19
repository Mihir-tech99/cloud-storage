"""
app.py - Cloud Storage Space Optimizer (Vercel & Flask Web Application)
Features:
1. Exact Streamlit-style Dark Sidebar:
   - ☁️ Drive Optimizer Header & Subtitle
   - 🌐 Cloud Storage Connection Source Switcher (Simulated Cloud, Local Sync Folder, Google Drive API)
   - Real-time Connection Status Alert Banner
2. Cryptographic SHA-256 Deduplication & Storage Health Analysis
3. 7 Comprehensive Optimization Modules:
   - 📊 Storage Analytics (Chart.js category doughnut + Live Category Distribution Bars)
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
from flask import Flask, request, jsonify, render_template_string

from drive_service import MockDriveManager, LocalFolderManager, GoogleDriveManager, GOOGLE_LIBS_AVAILABLE
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
)

# Initialize Flask application
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024

# Active drive manager and mode
current_mode = "simulated"
drive_mgr = MockDriveManager()


def get_current_data():
    """Extract and analyze current drive storage records."""
    files = drive_mgr.list_files()
    quota = drive_mgr.get_quota()
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

    return {
        "current_mode": current_mode,
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
    }


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
    </style>
</head>
<body class="bg-[#0f172a] text-slate-100 font-sans min-h-screen">

    <div class="min-h-screen flex flex-col md:flex-row">
        <!-- SIDEBAR (Matches Exact Streamlit Layout from Screenshot) -->
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
                    Connected to <span class="font-bold text-emerald-100">Simulated Cloud Storage</span> (15 GB Quota, 35+ Files, Real SHA-256 Hashes).
                </div>

                <!-- Local Cloud Sync Folder Details -->
                <div id="status-box-local" class="mt-4 p-3.5 rounded-xl bg-slate-800/90 border border-slate-700 text-xs text-slate-200 hidden">
                    <div class="font-bold text-white mb-2 flex items-center gap-1.5"><i class="fa-solid fa-folder-open text-blue-400"></i> Local Sync Folder:</div>
                    <input type="text" id="local-folder-path" value="sample_files" placeholder="e.g. C:\\GoogleDrive or sample_files" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white mb-2 focus:ring-1 focus:ring-blue-500 outline-none">
                    <button onclick="scanLocalFolder()" class="w-full py-1.5 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded-lg transition-all text-xs shadow-md">Scan Folder</button>
                    <div class="text-[10px] text-slate-400 mt-2">Scans actual files on your system with 100% cryptographic SHA-256 hashes.</div>
                </div>

                <!-- Google Drive API Details -->
                <div id="status-box-google" class="mt-4 p-3.5 rounded-xl bg-slate-800/90 border border-slate-700 text-xs text-slate-200 hidden">
                    <div class="font-bold text-white mb-2 flex items-center gap-1.5"><i class="fa-brands fa-google-drive text-emerald-400"></i> Google Drive OAuth 2.0:</div>
                    <input type="file" id="cred-file-input" accept=".json" class="hidden" onchange="uploadCredentials(event)">
                    <label for="cred-file-input" class="block w-full text-center cursor-pointer py-1.5 bg-slate-700 hover:bg-slate-600 text-white font-semibold rounded-lg text-xs mb-2 border border-slate-600 transition-all">
                        <i class="fa-solid fa-upload mr-1.5"></i> Upload credentials.json
                    </label>
                    <button onclick="connectGoogleDrive()" class="w-full py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white font-bold rounded-lg transition-all text-xs shadow-md">Connect Live Drive</button>
                    <div class="mt-2.5 p-2 rounded-lg bg-amber-950/40 border border-amber-800/50 text-[11px] text-amber-200/90 leading-tight">
                        💡 <b>Zero Payment Guide:</b> In Google Cloud Console, do NOT start the paid trial. Simply enable the Google Drive API and create a Desktop Client OAuth JSON for free!
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
                    <span class="text-xs text-slate-400 font-mono" id="last-updated-text">Updated: Just now</span>
                </div>
            </div>

            <!-- Quota Meter Card -->
            <div class="bg-[#151b28] p-5 rounded-2xl border border-slate-800/80 shadow-lg mb-6">
                <div class="flex justify-between items-center mb-2.5">
                    <span class="text-xs font-bold text-slate-300 flex items-center gap-2 uppercase tracking-wider">
                        <i class="fa-brands fa-google-drive text-blue-400"></i> Cloud Storage Capacity (15 GB Quota)
                    </span>
                    <span id="quota-text" class="text-xs font-mono font-bold text-blue-400">Calculating...</span>
                </div>
                <div class="w-full bg-slate-800/80 rounded-full h-3.5 overflow-hidden p-0.5">
                    <div id="quota-bar" class="bg-gradient-to-r from-blue-500 to-indigo-500 h-2.5 rounded-full transition-all duration-700" style="width: 0%"></div>
                </div>
            </div>

            <!-- 5 KPI Metric Cards -->
            <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
                <div class="bg-[#151b28] p-4 rounded-2xl border border-slate-800/80 shadow-md">
                    <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Total Files</div>
                    <div id="stat-files" class="text-2xl font-black text-white mt-1">--</div>
                    <div class="text-[10px] text-slate-500 mt-1">Indexed in drive</div>
                </div>
                <div class="bg-[#151b28] p-4 rounded-2xl border border-slate-800/80 shadow-md">
                    <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Storage Used</div>
                    <div id="stat-used" class="text-2xl font-black text-blue-400 mt-1">--</div>
                    <div class="text-[10px] text-slate-500 mt-1">Active drive volume</div>
                </div>
                <div class="bg-[#151b28] p-4 rounded-2xl border border-slate-800/80 shadow-md">
                    <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Potential Savings</div>
                    <div id="stat-savings" class="text-2xl font-black text-emerald-400 mt-1">--</div>
                    <div class="text-[10px] text-emerald-500/80 mt-1">Reclaimable space</div>
                </div>
                <div class="bg-[#151b28] p-4 rounded-2xl border border-slate-800/80 shadow-md">
                    <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Duplicate Copies</div>
                    <div id="stat-dupes" class="text-2xl font-black text-rose-400 mt-1">--</div>
                    <div class="text-[10px] text-rose-500/80 mt-1">Identical SHA-256</div>
                </div>
                <div class="bg-[#151b28] p-4 rounded-2xl border border-slate-800/80 shadow-md">
                    <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Health Score</div>
                    <div id="stat-health" class="text-2xl font-black text-indigo-400 mt-1">--</div>
                    <div class="text-[10px] text-slate-500 mt-1">Storage efficiency / 100</div>
                </div>
            </div>

            <!-- MODULE 1: STORAGE ANALYTICS -->
            <div id="tab-analytics" class="tab-module">
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                    <!-- Category Distribution Card -->
                    <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md">
                        <div class="flex justify-between items-center mb-4">
                            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                                <span>📊</span> Storage Distribution by File Category
                            </h3>
                            <span id="cat-total-badge" class="px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-blue-950 text-blue-400 border border-blue-800">
                                Loading categories...
                            </span>
                        </div>

                        <!-- Chart Canvas Container -->
                        <div class="relative w-full h-64 mb-6 flex items-center justify-center">
                            <canvas id="categoryChart"></canvas>
                        </div>

                        <!-- Live Category Breakdown Bars & Statistics -->
                        <div id="category-bars-list" class="space-y-3 pt-4 border-t border-slate-800/80">
                            <!-- Populated dynamically with exact sizes, percentages, and progress bars -->
                        </div>
                    </div>

                    <!-- Instant Recommendations Card -->
                    <div class="bg-[#151b28] p-6 rounded-2xl border border-slate-800 shadow-md">
                        <h3 class="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                            <span>⚡</span> Instant Optimization Recommendations
                        </h3>
                        <div class="space-y-3.5">
                            <div class="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/40 flex justify-between items-center">
                                <div>
                                    <h4 class="font-bold text-emerald-400 text-xs">Purge Redundant Duplicate Copies</h4>
                                    <p class="text-[11px] text-emerald-300/70">Verified byte-for-byte matches via cryptographic SHA-256</p>
                                </div>
                                <span id="rec-dupe-size" class="text-sm font-black text-emerald-400">--</span>
                            </div>
                            <div class="p-4 rounded-xl bg-blue-950/30 border border-blue-800/40 flex justify-between items-center">
                                <div>
                                    <h4 class="font-bold text-blue-400 text-xs">Empty Cloud Trash Bin</h4>
                                    <p class="text-[11px] text-blue-300/70">Permanently clear deleted items currently held in trash</p>
                                </div>
                                <span id="rec-trash-size" class="text-sm font-black text-blue-400">--</span>
                            </div>
                            <div class="p-4 rounded-xl bg-amber-950/30 border border-amber-800/40 flex justify-between items-center">
                                <div>
                                    <h4 class="font-bold text-amber-400 text-xs">Purge Ghost & Temporary Clutter</h4>
                                    <p class="text-[11px] text-amber-300/70">Zero-byte corrupted downloads and .tmp/.cache leftovers</p>
                                </div>
                                <span id="rec-clutter-size" class="text-sm font-black text-amber-400">--</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- MODULE 2: SHA-256 DUPLICATES -->
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

            <!-- MODULE 3: LARGE FILES -->
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

            <!-- MODULE 4: CLUTTER -->
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

            <!-- MODULE 5: SHA-256 TESTING LAB -->
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

            <!-- MODULE 6: FINANCIAL ROI -->
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

            <!-- MODULE 7: ARCHITECTURE & SETUP -->
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

        const CATEGORY_META = {
            'Videos': { icon: '🎬', color: '#8b5cf6' },
            'Photos & Images': { icon: '🖼️', color: '#ec4899' },
            'Archives & Backups': { icon: '📦', color: '#f59e0b' },
            'Documents': { icon: '📄', color: '#3b82f6' },
            'Code & Binaries': { icon: '💻', color: '#10b981' },
            'Audio': { icon: '🎵', color: '#06b6d4' },
            'Other Files': { icon: '📁', color: '#64748b' }
        };

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
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
                        <div class="h-2 rounded-full transition-all duration-700" style="width: ${Math.max(c.percent, 1)}%; background-color: ${meta.color}"></div>
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
                console.warn('Chart.js not yet loaded, retrying...');
                setTimeout(renderChart, 300);
                return;
            }

            const ctx = canvas.getContext('2d');
            if (chartInstance) {
                chartInstance.destroy();
            }

            const labels = currentData.categories.map(c => c.category);
            const data = currentData.categories.map(c => c.bytes);
            const colors = currentData.categories.map(c => (CATEGORY_META[c.category] || {}).color || '#3b82f6');

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
                        <td class="p-3 font-bold text-slate-400">#${d.duplicate_group}</td>
                        <td class="p-3">${d.is_redundant ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800">Duplicate</span>' : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">Original</span>'}</td>
                        <td class="p-3 font-sans font-medium text-slate-200">${d.name}</td>
                        <td class="p-3 text-slate-400">${d.formatted_size}</td>
                        <td class="p-3 text-[11px] text-slate-500">${d.sha256 ? d.sha256.substring(0, 16) + '...' : '--'}</td>
                        <td class="p-3 text-right">
                            <button onclick="trashFile('${d.id}')" class="px-2.5 py-1 text-[11px] bg-slate-800 hover:bg-rose-900 hover:text-rose-200 text-slate-300 rounded border border-slate-700 transition-all font-sans font-medium">Trash</button>
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
                    <td class="p-3 font-mono text-slate-400">${f.days_inactive}d ago</td>
                    <td class="p-3 text-right">
                        <button onclick="trashFile('${f.id}')" class="px-2.5 py-1 text-[11px] bg-slate-800 hover:bg-rose-900 hover:text-rose-200 text-slate-300 rounded border border-slate-700 transition-all font-medium">Trash</button>
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
                    <td class="p-3 font-mono text-slate-400">${c.days_inactive}d</td>
                    <td class="p-3 text-right">
                        <button onclick="trashFile('${c.id}')" class="px-2.5 py-1 text-[11px] bg-slate-800 hover:bg-rose-900 hover:text-rose-200 text-slate-300 rounded border border-slate-700 transition-all font-medium">Trash</button>
                    </td>
                `;
                clutterTbody.appendChild(tr);
            });

            renderChart();
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-module').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.nav-item').forEach(el => {
                el.className = 'nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-all';
            });
            document.getElementById('tab-' + tabId).classList.remove('hidden');
            const activeBtn = document.getElementById('nav-btn-' + tabId);
            if (activeBtn) {
                activeBtn.className = 'nav-item w-full text-left px-3 py-2 rounded-xl text-xs font-semibold text-white bg-blue-600 flex items-center gap-2.5 transition-all';
            }

            if (tabId === 'analytics') {
                setTimeout(renderChart, 50);
            }
        }

        async function changeMode(mode) {
            document.getElementById('status-box-simulated').classList.add('hidden');
            document.getElementById('status-box-local').classList.add('hidden');
            document.getElementById('status-box-google').classList.add('hidden');

            document.getElementById('status-box-' + mode).classList.remove('hidden');

            const badge = document.getElementById('active-mode-badge');
            if (mode === 'simulated') {
                badge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800';
                badge.innerText = '✨ Simulated Cloud Active';
                await fetch('/api/set-mode', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({mode: 'simulated'}) });
                fetchStats();
            } else if (mode === 'local') {
                badge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-blue-950/80 text-blue-400 border border-blue-800';
                badge.innerText = '📁 Local Sync Folder Active';
            } else if (mode === 'google') {
                badge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-950/80 text-amber-400 border border-amber-800';
                badge.innerText = '🔗 Google Drive API (OAuth 2.0)';
            }
        }

        async function scanLocalFolder() {
            const path = document.getElementById('local-folder-path').value || 'sample_files';
            const res = await fetch('/api/set-mode', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({mode: 'local', path: path}) });
            const data = await res.json();
            alert(data.message);
            fetchStats();
        }

        async function uploadCredentials(e) {
            const file = e.target.files[0];
            if (!file) return;
            const formData = new FormData();
            formData.append('file', file);
            const res = await fetch('/api/upload-credentials', { method: 'POST', body: formData });
            const data = await res.json();
            alert(data.message);
        }

        async function connectGoogleDrive() {
            const res = await fetch('/api/set-mode', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({mode: 'google'}) });
            const data = await res.json();
            alert(data.message);
            fetchStats();
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

        async function handleFileUpload(e) {
            const files = e.target.files;
            if (!files.length) return;
            const formData = new FormData();
            for (let f of files) formData.append('files', f);

            const res = await fetch('/api/upload-hash', { method: 'POST', body: formData });
            const data = await res.json();

            const container = document.getElementById('lab-results');
            const list = document.getElementById('lab-results-list');
            container.classList.remove('hidden');
            list.innerHTML = '';

            data.forEach(item => {
                const div = document.createElement('div');
                div.className = item.is_duplicate ? 'p-3 rounded-xl bg-rose-950/30 border border-rose-800 text-xs' : 'p-3 rounded-xl bg-emerald-950/30 border border-emerald-800 text-xs';
                div.innerHTML = `
                    <div class="flex justify-between font-bold ${item.is_duplicate ? 'text-rose-300' : 'text-emerald-300'}">
                        <span>${item.name} (${item.formatted_size})</span>
                        <span>${item.is_duplicate ? '⚠️ DUPLICATE MATCH' : '✅ UNIQUE'}</span>
                    </div>
                    <div class="font-mono text-[11px] text-slate-400 mt-1">SHA-256: ${item.sha256}</div>
                `;
                list.appendChild(div);
            });
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

        window.onload = fetchStats;
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/stats")
def api_stats():
    return jsonify(get_current_data())


@app.route("/api/set-mode", methods=["POST"])
def api_set_mode():
    global drive_mgr, current_mode
    mode = request.json.get("mode")
    if mode == "simulated":
        current_mode = "simulated"
        drive_mgr = MockDriveManager()
        return jsonify({"success": True, "message": "Switched to Simulated Cloud Storage (15 GB Quota)"})
    elif mode == "local":
        folder_path = request.json.get("path", "sample_files")
        if not os.path.exists(folder_path):
            os.makedirs(folder_path, exist_ok=True)
        current_mode = "local"
        drive_mgr = LocalFolderManager(folder_path)
        return jsonify({"success": True, "message": f"Connected to local folder: {folder_path}"})
    elif mode == "google":
        current_mode = "google"
        drive_mgr = GoogleDriveManager()
        ok, msg = drive_mgr.authenticate()
        return jsonify({"success": ok, "message": msg if not ok else "Connected to Google Drive API!"})
    return jsonify({"success": False, "message": "Unknown mode"}), 400


@app.route("/api/upload-credentials", methods=["POST"])
def api_upload_credentials():
    file = request.files.get("file")
    if file:
        file.save("credentials.json")
        return jsonify({"success": True, "message": "Uploaded credentials.json successfully!"})
    return jsonify({"success": False, "message": "No file uploaded"}), 400


@app.route("/api/trash", methods=["POST"])
def api_trash():
    file_id = request.json.get("id")
    ok, msg = drive_mgr.move_to_trash(file_id)
    return jsonify({"success": ok, "message": msg})


@app.route("/api/empty-trash", methods=["POST"])
def api_empty_trash():
    ok, msg = drive_mgr.empty_trash()
    return jsonify({"success": ok, "message": msg})


@app.route("/api/upload-hash", methods=["POST"])
def api_upload_hash():
    uploaded_files = request.files.getlist("files")
    results = []
    current_files = drive_mgr.list_files()
    known_hashes = {f.get("sha256") for f in current_files if f.get("sha256")}

    for f in uploaded_files:
        content = f.read()
        sha = hashlib.sha256(content).hexdigest()
        is_dupe = sha in known_hashes
        results.append({
            "name": f.filename,
            "size": len(content),
            "formatted_size": format_bytes(len(content)),
            "sha256": sha,
            "is_duplicate": is_dupe,
        })
    return jsonify(results)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
