"""
app.py - Cloud Storage Space Optimizer (Vercel & Flask Web Application)
Exports top-level `app` for native Vercel deployment without serverless errors.
Provides full SHA-256 duplicate detection, cloud analytics, clutter cleaning, and financial ROI.
"""

from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import io
import os
from flask import Flask, request, jsonify, render_template_string

from drive_service import MockDriveManager, LocalFolderManager
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

# Initialize Flask app (Required by Vercel)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB max upload

# Global simulated drive manager
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
    health = calculate_storage_health(used_bytes, limit_bytes, reclaimable_dupes, old_df["size"].sum() if not old_df.empty else 0)
    cost = calculate_cost_savings(total_savings)

    # Category aggregation for charts
    cat_summary = []
    if not df.empty:
        for cat, group in df.groupby("category"):
            cat_summary.append({
                "category": cat,
                "bytes": int(group["size"].sum()),
                "formatted": format_bytes(group["size"].sum()),
                "count": len(group)
            })

    import json

    dupes_data = json.loads(dupes_df.to_json(orient="records")) if not dupes_df.empty else []
    large_data = json.loads(large_df.head(15).to_json(orient="records")) if not large_df.empty else []
    clutter_data = json.loads(clutter_df.to_json(orient="records")) if not clutter_df.empty else []

    return {
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
    <title>Cloud Storage Space Optimizer</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- FontAwesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .active-tab { border-bottom: 3px solid #2563eb; color: #2563eb; font-weight: 600; }
    </style>
</head>
<body class="bg-slate-50 text-slate-800 font-sans min-h-screen">
    <!-- Navbar -->
    <nav class="bg-white border-b border-slate-200 px-6 py-4 shadow-sm sticky top-0 z-50">
        <div class="max-w-7xl mx-auto flex justify-between items-center">
            <div class="flex items-center space-x-3">
                <div class="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center text-white text-xl shadow-md shadow-blue-500/20">
                    <i class="fa-solid fa-cloud"></i>
                </div>
                <div>
                    <h1 class="text-xl font-bold text-slate-900 tracking-tight">Cloud Storage Space Optimizer</h1>
                    <p class="text-xs text-slate-500">Live Cryptographic SHA-256 Deduplication & Analytics</p>
                </div>
            </div>
            <div class="flex items-center space-x-3">
                <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-emerald-100 text-emerald-800 border border-emerald-200">
                    <span class="w-2 h-2 rounded-full bg-emerald-500 mr-2 animate-pulse"></span>
                    Live Cloud System Active
                </span>
                <button onclick="refreshData()" class="px-3 py-1.5 text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium rounded-lg transition-all flex items-center gap-1.5 border border-slate-300">
                    <i class="fa-solid fa-arrows-rotate"></i> Refresh
                </button>
            </div>
        </div>
    </nav>

    <!-- Main Container -->
    <div class="max-w-7xl mx-auto px-6 py-8">
        <!-- Storage Quota Bar -->
        <div class="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm mb-6">
            <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-semibold text-slate-700 flex items-center gap-2">
                    <i class="fa-brands fa-google-drive text-blue-500"></i> Google Drive Cloud Storage Quota
                </span>
                <span id="quota-text" class="text-sm font-bold text-slate-900">Calculating...</span>
            </div>
            <div class="w-full bg-slate-100 rounded-full h-3.5 overflow-hidden">
                <div id="quota-bar" class="bg-blue-600 h-3.5 rounded-full transition-all duration-700" style="width: 0%"></div>
            </div>
        </div>

        <!-- Metric Cards -->
        <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
            <div class="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm">
                <div class="text-xs font-semibold text-slate-500 uppercase tracking-wider">Total Files</div>
                <div id="stat-files" class="text-2xl font-black text-slate-900 mt-1">--</div>
            </div>
            <div class="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm">
                <div class="text-xs font-semibold text-slate-500 uppercase tracking-wider">Storage Used</div>
                <div id="stat-used" class="text-2xl font-black text-slate-900 mt-1">--</div>
            </div>
            <div class="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm">
                <div class="text-xs font-semibold text-slate-500 uppercase tracking-wider">Potential Savings</div>
                <div id="stat-savings" class="text-2xl font-black text-emerald-600 mt-1">--</div>
            </div>
            <div class="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm">
                <div class="text-xs font-semibold text-slate-500 uppercase tracking-wider">Duplicate Copies</div>
                <div id="stat-dupes" class="text-2xl font-black text-rose-600 mt-1">--</div>
            </div>
            <div class="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm">
                <div class="text-xs font-semibold text-slate-500 uppercase tracking-wider">Health Score</div>
                <div id="stat-health" class="text-2xl font-black text-blue-600 mt-1">--</div>
            </div>
        </div>

        <!-- Navigation Tabs -->
        <div class="flex border-b border-slate-200 mb-6 space-x-6 overflow-x-auto text-sm font-medium">
            <button onclick="switchTab('analytics')" id="tab-btn-analytics" class="tab-btn pb-3 px-1 active-tab">📊 Storage Analytics</button>
            <button onclick="switchTab('duplicates')" id="tab-btn-duplicates" class="tab-btn pb-3 px-1 text-slate-500 hover:text-slate-800">👯 SHA-256 Duplicates</button>
            <button onclick="switchTab('large')" id="tab-btn-large" class="tab-btn pb-3 px-1 text-slate-500 hover:text-slate-800">🐘 Large Files</button>
            <button onclick="switchTab('clutter')" id="tab-btn-clutter" class="tab-btn pb-3 px-1 text-slate-500 hover:text-slate-800">👻 Ghost & Clutter</button>
            <button onclick="switchTab('lab')" id="tab-btn-lab" class="tab-btn pb-3 px-1 text-slate-500 hover:text-slate-800">🧪 Live SHA-256 Lab</button>
            <button onclick="switchTab('roi')" id="tab-btn-roi" class="tab-btn pb-3 px-1 text-slate-500 hover:text-slate-800">💰 Financial ROI</button>
        </div>

        <!-- TAB 1: ANALYTICS -->
        <div id="tab-analytics" class="tab-content">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                    <h3 class="text-base font-bold text-slate-900 mb-4">Storage by File Category</h3>
                    <div class="h-64 flex justify-center">
                        <canvas id="categoryChart"></canvas>
                    </div>
                </div>
                <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                    <h3 class="text-base font-bold text-slate-900 mb-4">Optimization Recommendation Summary</h3>
                    <div class="space-y-4">
                        <div class="p-4 rounded-xl bg-emerald-50 border border-emerald-200 flex justify-between items-center">
                            <div>
                                <h4 class="font-bold text-emerald-900 text-sm">Purge Redundant Duplicate Files</h4>
                                <p class="text-xs text-emerald-700">Exact byte duplicates verified via SHA-256 cryptographic hashes</p>
                            </div>
                            <span id="rec-dupe-size" class="text-base font-extrabold text-emerald-800">--</span>
                        </div>
                        <div class="p-4 rounded-xl bg-blue-50 border border-blue-200 flex justify-between items-center">
                            <div>
                                <h4 class="font-bold text-blue-900 text-sm">Empty Cloud Trash Bin</h4>
                                <p class="text-xs text-blue-700">Permanently remove discarded files sitting in trash</p>
                            </div>
                            <span id="rec-trash-size" class="text-base font-extrabold text-blue-800">--</span>
                        </div>
                        <div class="p-4 rounded-xl bg-amber-50 border border-amber-200 flex justify-between items-center">
                            <div>
                                <h4 class="font-bold text-amber-900 text-sm">Remove Ghost & Temporary Clutter</h4>
                                <p class="text-xs text-amber-700">0-byte corrupted downloads and .tmp/.log cache residues</p>
                            </div>
                            <span id="rec-clutter-size" class="text-base font-extrabold text-amber-800">--</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 2: DUPLICATES -->
        <div id="tab-duplicates" class="tab-content hidden">
            <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm mb-6">
                <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
                    <div>
                        <h3 class="text-lg font-bold text-slate-900">Cryptographic SHA-256 Duplicate Detector</h3>
                        <p class="text-xs text-slate-500">Files matching identical 256-bit hashes are grouped below. The earliest file is kept as Original.</p>
                    </div>
                    <button onclick="purgeDuplicates()" class="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white font-medium text-xs rounded-xl shadow-sm transition-all flex items-center gap-2">
                        <i class="fa-solid fa-trash-can"></i> Move Redundant Copies to Trash
                    </button>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs text-slate-600">
                        <thead class="bg-slate-50 text-slate-800 uppercase font-semibold text-[11px] border-b border-slate-200">
                            <tr>
                                <th class="p-3">Group</th>
                                <th class="p-3">Action</th>
                                <th class="p-3">File Name</th>
                                <th class="p-3">Size</th>
                                <th class="p-3">SHA-256 Hash</th>
                            </tr>
                        </thead>
                        <tbody id="duplicates-table-body" class="divide-y divide-slate-100 font-mono">
                            <!-- Populated via JS -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 3: LARGE FILES -->
        <div id="tab-large" class="tab-content hidden">
            <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <h3 class="text-lg font-bold text-slate-900 mb-1">Space Hog Audit (> 50 MB)</h3>
                <p class="text-xs text-slate-500 mb-4">Top heaviest items occupying the largest share of storage quota.</p>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs text-slate-600">
                        <thead class="bg-slate-50 text-slate-800 uppercase font-semibold text-[11px] border-b border-slate-200">
                            <tr>
                                <th class="p-3">File Name</th>
                                <th class="p-3">Category</th>
                                <th class="p-3">Size</th>
                                <th class="p-3">Age (Days)</th>
                                <th class="p-3">Action</th>
                            </tr>
                        </thead>
                        <tbody id="large-table-body" class="divide-y divide-slate-100">
                            <!-- Populated via JS -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 4: CLUTTER -->
        <div id="tab-clutter" class="tab-content hidden">
            <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <div class="flex justify-between items-center mb-4">
                    <div>
                        <h3 class="text-lg font-bold text-slate-900">0-Byte Ghost & Temporary Clutter Files</h3>
                        <p class="text-xs text-slate-500">Failed downloads and lock files taking up sync metadata.</p>
                    </div>
                    <button onclick="purgeClutter()" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium text-xs rounded-xl shadow-sm transition-all flex items-center gap-2">
                        <i class="fa-solid fa-broom"></i> Purge All Clutter
                    </button>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs text-slate-600">
                        <thead class="bg-slate-50 text-slate-800 uppercase font-semibold text-[11px] border-b border-slate-200">
                            <tr>
                                <th class="p-3">File Name</th>
                                <th class="p-3">Clutter Reason</th>
                                <th class="p-3">Size</th>
                                <th class="p-3">Age (Days)</th>
                            </tr>
                        </thead>
                        <tbody id="clutter-table-body" class="divide-y divide-slate-100">
                            <!-- Populated via JS -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 5: TESTING LAB -->
        <div id="tab-lab" class="tab-content hidden">
            <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <h3 class="text-lg font-bold text-slate-900 mb-1">Live Cryptographic SHA-256 Hasher</h3>
                <p class="text-xs text-slate-500 mb-6">Select 2 or more files from your device to test live client-side byte-level duplicate detection.</p>
                <div class="border-2 border-dashed border-slate-300 rounded-2xl p-8 text-center bg-slate-50">
                    <input type="file" id="lab-file-input" multiple class="hidden" onchange="handleFileUpload(event)">
                    <label for="lab-file-input" class="cursor-pointer inline-flex flex-col items-center">
                        <div class="w-12 h-12 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-xl mb-3">
                            <i class="fa-solid fa-cloud-arrow-up"></i>
                        </div>
                        <span class="text-sm font-bold text-slate-800">Click to upload files for live SHA-256 analysis</span>
                        <span class="text-xs text-slate-500 mt-1">Try uploading identical photos or copies with different names</span>
                    </label>
                </div>
                <div id="lab-results" class="mt-6 hidden">
                    <h4 class="font-bold text-slate-900 text-sm mb-3">Live Hash Analysis Results:</h4>
                    <div id="lab-results-list" class="space-y-2"></div>
                </div>
            </div>
        </div>

        <!-- TAB 6: ROI -->
        <div id="tab-roi" class="tab-content hidden">
            <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <h3 class="text-lg font-bold text-slate-900 mb-1">Cloud Financial Cost-Savings ROI</h3>
                <p class="text-xs text-slate-500 mb-6">Quantifying financial savings by reclaiming storage and preventing cloud tier upgrades.</p>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="p-6 rounded-2xl bg-slate-50 border border-slate-200">
                        <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Tier Upgrade Avoided</div>
                        <div id="roi-tier" class="text-xl font-black text-blue-700">--</div>
                        <p class="text-xs text-slate-500 mt-2">By optimizing storage, you stay comfortably within free limits.</p>
                    </div>
                    <div class="p-6 rounded-2xl bg-emerald-50 border border-emerald-200">
                        <div class="text-xs font-bold text-emerald-700 uppercase tracking-wider mb-2">Estimated Annual Savings</div>
                        <div class="text-2xl font-black text-emerald-800" id="roi-annual">--</div>
                        <div class="text-xs text-emerald-600 mt-1" id="roi-monthly">--</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- JavaScript Application Logic -->
    <script>
        let currentData = null;
        let chartInstance = null;

        async function fetchStats() {
            const res = await fetch('/api/stats');
            currentData = await res.json();
            renderDashboard();
        }

        function renderDashboard() {
            if (!currentData) return;

            // Quota
            const pct = Math.min(100, (currentData.used_bytes / currentData.limit_bytes * 100)).toFixed(1);
            document.getElementById('quota-text').innerText = `${currentData.formatted_used} / ${currentData.formatted_limit} (${pct}%)`;
            document.getElementById('quota-bar').style.width = `${pct}%`;

            // Top Metrics
            document.getElementById('stat-files').innerText = currentData.total_files.toLocaleString();
            document.getElementById('stat-used').innerText = currentData.formatted_used;
            document.getElementById('stat-savings').innerText = currentData.formatted_savings;
            const redundantCount = currentData.dupes.filter(d => d.is_redundant).length;
            document.getElementById('stat-dupes').innerText = redundantCount;
            document.getElementById('stat-health').innerText = `${currentData.health.score}/100`;

            // Recommendations
            document.getElementById('rec-dupe-size').innerText = '+' + currentData.formatted_reclaimable_dupes;
            document.getElementById('rec-trash-size').innerText = '+' + currentData.formatted_trash;
            document.getElementById('rec-clutter-size').innerText = '+' + (currentData.clutter.reduce((acc, c) => acc + c.size, 0) / (1024*1024)).toFixed(1) + ' MB';

            // Chart
            renderChart();

            // Duplicates Table
            const dupeTbody = document.getElementById('duplicates-table-body');
            dupeTbody.innerHTML = '';
            currentData.dupes.forEach(d => {
                const tr = document.createElement('tr');
                tr.className = d.is_redundant ? 'bg-rose-50/50' : 'bg-emerald-50/50';
                tr.innerHTML = `
                    <td class="p-3 font-bold">${d.duplicate_group_id}</td>
                    <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${d.is_redundant ? 'bg-rose-200 text-rose-800' : 'bg-emerald-200 text-emerald-800'}">${d.status}</span></td>
                    <td class="p-3 font-sans font-medium text-slate-900">${d.name}</td>
                    <td class="p-3 font-sans">${d.formatted_size}</td>
                    <td class="p-3 text-[11px] text-slate-500">${d.sha256.substring(0, 16)}...</td>
                `;
                dupeTbody.appendChild(tr);
            });

            // Large Files Table
            const largeTbody = document.getElementById('large-table-body');
            largeTbody.innerHTML = '';
            currentData.large_files.forEach(f => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="p-3 font-medium text-slate-900">${f.name}</td>
                    <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-100 font-semibold">${f.category}</span></td>
                    <td class="p-3 font-bold text-slate-900">${f.formatted_size}</td>
                    <td class="p-3 text-slate-500">${f.age_days} days ago</td>
                    <td class="p-3"><button onclick="trashFile('${f.id}')" class="text-rose-600 hover:text-rose-800 font-semibold text-xs"><i class="fa-solid fa-trash"></i></button></td>
                `;
                largeTbody.appendChild(tr);
            });

            // Clutter Table
            const clutterTbody = document.getElementById('clutter-table-body');
            clutterTbody.innerHTML = '';
            currentData.clutter.forEach(c => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="p-3 font-medium text-slate-900">${c.name}</td>
                    <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-amber-100 text-amber-800 font-semibold">${c.clutter_reason}</span></td>
                    <td class="p-3">${c.formatted_size}</td>
                    <td class="p-3 text-slate-500">${c.age_days}d</td>
                `;
                clutterTbody.appendChild(tr);
            });

            // ROI
            document.getElementById('roi-tier').innerText = currentData.cost.tier_avoided;
            document.getElementById('roi-annual').innerText = `$${currentData.cost.annual_usd} / ₹${currentData.cost.annual_inr}`;
            document.getElementById('roi-monthly').innerText = `Estimated Monthly Savings: $${currentData.cost.monthly_usd} (₹${currentData.cost.monthly_inr})`;
        }

        function renderChart() {
            if (!currentData || !currentData.categories) return;
            const ctx = document.getElementById('categoryChart').getContext('2d');
            if (chartInstance) chartInstance.destroy();

            const labels = currentData.categories.map(c => c.category);
            const data = currentData.categories.map(c => c.bytes);

            chartInstance = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: ['#2563eb', '#10b981', '#f59e0b', '#ec4899', '#8b5cf6', '#64748b'],
                        borderWidth: 2,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'right' } }
                }
            });
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(el => {
                el.classList.remove('active-tab');
                el.classList.add('text-slate-500');
            });
            document.getElementById('tab-' + tabId).classList.remove('hidden');
            document.getElementById('tab-btn-' + tabId).classList.add('active-tab');
            document.getElementById('tab-btn-' + tabId).classList.remove('text-slate-500');
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
            alert(`Purged ${redundant.length} duplicate copies!`);
            fetchStats();
        }

        async function purgeClutter() {
            for (let c of currentData.clutter) {
                await fetch('/api/trash', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id: c.id}) });
            }
            alert('Purged all clutter files!');
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
                div.className = item.is_duplicate ? 'p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs' : 'p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-xs';
                div.innerHTML = `
                    <div class="flex justify-between font-bold ${item.is_duplicate ? 'text-rose-900' : 'text-emerald-900'}">
                        <span>${item.name} (${item.formatted_size})</span>
                        <span>${item.is_duplicate ? '⚠️ DUPLICATE MATCH' : '✅ UNIQUE'}</span>
                    </div>
                    <div class="font-mono text-[11px] text-slate-500 mt-1">SHA-256: ${item.sha256}</div>
                `;
                list.appendChild(div);
            });
        }

        function refreshData() { fetchStats(); }
        window.onload = fetchStats;
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    """Renders the main dashboard."""
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/stats")
def api_stats():
    """Returns real-time analytics and duplicate audit data."""
    return jsonify(get_current_data())


@app.route("/api/trash", methods=["POST"])
def api_trash():
    """Moves a file to trash."""
    file_id = request.json.get("id")
    ok, msg = drive_mgr.move_to_trash(file_id)
    return jsonify({"success": ok, "message": msg})


@app.route("/api/empty-trash", methods=["POST"])
def api_empty_trash():
    """Empties the trash bin."""
    ok, msg = drive_mgr.empty_trash()
    return jsonify({"success": ok, "message": msg})


@app.route("/api/upload-hash", methods=["POST"])
def api_upload_hash():
    """Computes live cryptographic SHA-256 checksums on uploaded files."""
    uploaded_files = request.files.getlist("files")
    records = []
    seen_hashes = {}

    for f in uploaded_files:
        content = f.read()
        h = compute_sha256(content)
        is_dupe = h in seen_hashes
        seen_hashes[h] = f.filename

        records.append({
            "name": f.filename,
            "size": len(content),
            "formatted_size": format_bytes(len(content)),
            "sha256": h,
            "is_duplicate": is_dupe,
        })

    return jsonify(records)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
