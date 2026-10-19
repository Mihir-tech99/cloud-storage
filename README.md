# ☁️ Cloud Storage Space Optimizer

A modern, fast, and beginner-friendly cloud storage analytics and optimization dashboard built with **Python**, **Streamlit**, and **Google Drive**.

Eliminates the complexity of separate HTML, CSS, or JavaScript files—everything is driven by Python with reactive web components, Plotly visualizations, cryptographic **SHA-256** duplicate detection, clutter purgers, and financial cost-savings ROI calculators.

---

## 🌟 Key Working Features

1. **📊 Cloud Storage Analytics & Explorer (Tab 1)**
   - Interactive category donut chart (*Videos, AI Models, Photos, Archives, Documents, Code & Audio*).
   - Storage volume distribution across file size brackets (`<1MB`, `1-10MB`, `10-50MB`, `50-200MB`, `200MB-1GB`, `>1GB`).
   - Real-time search by filename or SHA-256 hash substring with category filters.

2. **👯 SHA-256 Cryptographic Duplicate Finder (Tab 2)**
   - Calculates 256-bit cryptographic SHA-256 hashes for 100% byte-accurate duplicate detection.
   - **🔬 Side-by-Side Duplicate Inspector**: Compare original vs redundant copies side-by-side.
   - Automatically differentiates between the oldest **Original (Keep)** file and subsequent **Redundant Duplicates**.
   - 1-click batch action to move redundant copies to Google Drive Trash.
   - Export duplicate cleanup plan as CSV.

3. **🐘 Large File Scanner (Tab 3)**
   - Configurable size threshold (e.g. `>50 MB`) to identify space hogs like AI model weights, 4K footage, and VM images.
   - Direct 1-click file trashing.

4. **👻 Ghost & Clutter Cleaner (Tab 4)**
   - Detects **0-byte ghost files** from interrupted downloads or failed syncs.
   - Cleans up temporary residual clutter (`.tmp`, `.log`, `.bak`, `.crdownload`, lock files).
   - 1-click batch purge.

5. **🧪 Live SHA-256 Testing Lab (Tab 5)**
   - Upload any local files directly to calculate sizes and compute real-time SHA-256 hashes.
   - 1-click button to generate physical test files on disk in `./sample_files/` with deliberate duplicates for demonstration.

6. **💰 Reclaim & Financial Cost Savings ROI (Tab 6)**
   - Before vs. After storage comparison chart.
   - **Financial ROI Calculator**: Toggle between USD ($) and INR (₹) to see monthly and annual savings.
   - Recommends which paid cloud storage tier upgrade was avoided (e.g. Google One 100GB / 200GB plan).
   - 1-click Drive trash bin purge.

7. **🌐 3 Working Connection Modes**
   - **✨ Simulated Online Cloud Mode**: Instant trial with 35+ realistic cloud files and quotas without needing any API keys or credit cards.
   - **📁 Local Synced Cloud Folder**: Scans any local folder or your Google Drive for Desktop / OneDrive folder directly with real SHA-256 hashes.
   - **🔗 Live Google Drive API Mode**: OAuth 2.0 integration with Google Drive API v3.

---

## 🚀 Quickstart Guide

### 1. Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### 2. Launch the Streamlit Dashboard
```powershell
python -m streamlit run app.py
```
The dashboard will immediately open in your browser at `http://localhost:8501`.

### 3. Run Automated Tests
```powershell
python test_optimizer.py
```
*(All 8 tests pass).*

---

## 📁 Project Structure

```
cloud computing/
├── app.py                # Main Streamlit dashboard UI with 7 interactive tabs
├── drive_service.py      # Google Drive API connector, Mock Cloud simulator & Local folder scanner
├── optimizer.py          # Analytical engine (SHA-256 hashing, duplicate grouping, clutter audit, ROI)
├── test_optimizer.py     # Unit and integration test suite (8 tests)
├── requirements.txt      # Project Python dependencies
└── README.md             # Documentation and setup instructions
```
