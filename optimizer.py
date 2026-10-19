"""
optimizer.py - File Analysis & Space Optimization Engine.
Provides SHA-256 hash calculation, duplicate detection, file size categorization,
large file auditing, and storage savings calculations.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from typing import BinaryIO
import pandas as pd


def compute_sha256(data_or_path: str | bytes | BinaryIO) -> str:
    """
    Compute the SHA-256 hash of a file path, byte string, or file-like stream.
    Used for 100% accurate byte-level duplicate detection.
    """
    hasher = hashlib.sha256()

    if isinstance(data_or_path, str) and os.path.exists(data_or_path):
        with open(data_or_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    elif isinstance(data_or_path, bytes):
        hasher.update(data_or_path)
        return hasher.hexdigest()

    elif hasattr(data_or_path, "read"):
        current_pos = data_or_path.tell() if hasattr(data_or_path, "tell") else 0
        while chunk := data_or_path.read(65536):
            hasher.update(chunk)
        if hasattr(data_or_path, "seek"):
            data_or_path.seek(current_pos)
        return hasher.hexdigest()

    return ""


def format_bytes(bytes_num: float | int) -> str:
    """Format byte count into human-readable string (KB, MB, GB, TB)."""
    if not bytes_num or pd.isna(bytes_num) or bytes_num <= 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(bytes_num) < 1024.0:
            return f"{bytes_num:3.1f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.1f} PB"


def categorize_file(mime_type: str, file_name: str) -> str:
    """Categorize file based on MIME type and filename extension."""
    mime_type = (mime_type or "").lower()
    ext = os.path.splitext(file_name or "")[1].lower()

    if "video" in mime_type or ext in [".mp4", ".mkv", ".mov", ".avi", ".flv", ".wmv", ".webm", ".m4v"]:
        return "Videos"

    if "image" in mime_type or ext in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".raw", ".cr2", ".heic"]:
        return "Photos & Images"

    if "audio" in mime_type or ext in [".mp3", ".wav", ".flac", ".m4a", ".aac", ".ogg"]:
        return "Audio"

    if "zip" in mime_type or "tar" in mime_type or ext in [".zip", ".tar", ".gz", ".rar", ".7z", ".iso", ".tgz"]:
        return "Archives & Backups"

    if (
        "document" in mime_type
        or "pdf" in mime_type
        or "spreadsheet" in mime_type
        or "presentation" in mime_type
        or "text" in mime_type
        or ext in [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".txt", ".rtf", ".odt", ".csv"]
    ):
        return "Documents"

    if ext in [".py", ".js", ".ts", ".html", ".css", ".json", ".xml", ".sql", ".ipynb", ".exe", ".sh"]:
        return "Code & Binaries"

    return "Other Files"


def process_files_dataframe(files: list[dict]) -> pd.DataFrame:
    """
    Standardize raw file records into an enriched Pandas DataFrame.
    """
    if not files:
        return pd.DataFrame(columns=[
            "id", "name", "size", "mimeType", "category", "formatted_size",
            "sha256", "createdTime", "modifiedTime", "age_days", "webViewLink"
        ])

    df = pd.DataFrame(files)

    for col in ["size", "sha256", "createdTime", "modifiedTime", "webViewLink", "mimeType", "name", "id"]:
        if col not in df.columns:
            df[col] = None

    # Clean numeric size
    df["size"] = pd.to_numeric(df["size"], errors="coerce").fillna(0).astype(int)
    df["formatted_size"] = df["size"].apply(format_bytes)
    df["category"] = df.apply(lambda r: categorize_file(r["mimeType"], r["name"]), axis=1)

    # Calculate file age in days
    now = datetime.now(timezone.utc)

    def parse_age(dt_str):
        if not dt_str or pd.isna(dt_str):
            return 0
        try:
            clean_str = str(dt_str).replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return max(0, (now - dt).days)
        except Exception:
            return 0

    df["age_days"] = df["modifiedTime"].apply(parse_age)
    return df


def detect_duplicates_by_sha256(df: pd.DataFrame) -> tuple[pd.DataFrame, float]:
    """
    Identify duplicate files strictly using SHA-256 hashes (with fallback to size+name if hash missing).
    Groups duplicates together and designates the oldest copy as 'Original (Keep)' and later copies as 'Redundant'.

    Returns:
        (duplicate_df, total_reclaimable_bytes)
    """
    if df.empty or len(df) < 2:
        return pd.DataFrame(), 0

    valid_files = df[df["size"] > 0].copy()
    if valid_files.empty:
        return pd.DataFrame(), 0

    # Separate files having SHA-256 hash vs without
    has_hash = valid_files[valid_files["sha256"].notna() & (valid_files["sha256"] != "")].copy()
    no_hash = valid_files[valid_files["sha256"].isna() | (valid_files["sha256"] == "")].copy()

    duplicate_groups = []
    group_num = 1

    # 1. SHA-256 Duplicate Detection
    if not has_hash.empty:
        counts = has_hash["sha256"].value_counts()
        dupe_hashes = counts[counts > 1].index

        for h in dupe_hashes:
            grp = has_hash[has_hash["sha256"] == h].copy()
            # Sort by createdTime / age_days (oldest first is treated as original)
            grp = grp.sort_values(by=["createdTime", "age_days"], ascending=[True, False])
            grp["duplicate_group_id"] = f"SHA256-GRP-{group_num:03d}"
            grp["short_sha256"] = grp["sha256"].apply(lambda x: str(x)[:16] + "...")
            grp["status"] = ["Original (Keep)"] + ["Redundant Duplicate"] * (len(grp) - 1)
            grp["is_redundant"] = [False] + [True] * (len(grp) - 1)
            grp["reclaimable_bytes"] = [0] + [row["size"] for _, row in grp.iloc[1:].iterrows()]
            duplicate_groups.append(grp)
            group_num += 1

    # 2. Fallback matching (same name + exact same byte size)
    if not no_hash.empty:
        name_size_counts = no_hash.groupby(["name", "size"]).size()
        fallback_tuples = name_size_counts[name_size_counts > 1].index

        for name, size in fallback_tuples:
            grp = no_hash[(no_hash["name"] == name) & (no_hash["size"] == size)].copy()
            grp = grp.sort_values(by=["createdTime", "age_days"], ascending=[True, False])
            grp["duplicate_group_id"] = f"NAME-GRP-{group_num:03d}"
            grp["short_sha256"] = "Computed by (Name, Size)"
            grp["status"] = ["Original (Keep)"] + ["Redundant Duplicate"] * (len(grp) - 1)
            grp["is_redundant"] = [False] + [True] * (len(grp) - 1)
            grp["reclaimable_bytes"] = [0] + [row["size"] for _, row in grp.iloc[1:].iterrows()]
            duplicate_groups.append(grp)
            group_num += 1

    if not duplicate_groups:
        return pd.DataFrame(), 0

    all_dupes = pd.concat(duplicate_groups, ignore_index=True)
    total_reclaimable = all_dupes[all_dupes["is_redundant"]]["size"].sum()

    return all_dupes, total_reclaimable


def audit_large_files(df: pd.DataFrame, threshold_mb: float = 50.0) -> pd.DataFrame:
    """Filter and rank files exceeding threshold size in MB."""
    if df.empty:
        return pd.DataFrame()
    threshold_bytes = threshold_mb * 1024 * 1024
    large_df = df[df["size"] >= threshold_bytes].sort_values(by="size", ascending=False).copy()
    if not large_df.empty and df["size"].sum() > 0:
        large_df["storage_share_pct"] = (large_df["size"] / df["size"].sum() * 100).round(2)
    return large_df


def audit_inactive_files(df: pd.DataFrame, days_threshold: int = 180) -> pd.DataFrame:
    """Filter files untouched for more than days_threshold."""
    if df.empty:
        return pd.DataFrame()
    return df[df["age_days"] >= days_threshold].sort_values(by=["size", "age_days"], ascending=[False, False]).copy()


def calculate_storage_health(total_used_bytes: int, total_quota_bytes: int, duplicate_bytes: int, old_files_bytes: int) -> dict:
    """
    Compute overall cloud storage health score (0-100%).
    """
    score = 100

    if total_quota_bytes > 0:
        quota_pct = (total_used_bytes / total_quota_bytes) * 100
        if quota_pct > 90:
            score -= 35
        elif quota_pct > 75:
            score -= 20
        elif quota_pct > 50:
            score -= 10
    else:
        quota_pct = 0

    if total_used_bytes > 0:
        dupe_pct = (duplicate_bytes / total_used_bytes) * 100
        if dupe_pct > 25:
            score -= 30
        elif dupe_pct > 10:
            score -= 20
        elif dupe_pct > 5:
            score -= 10

        old_pct = (old_files_bytes / total_used_bytes) * 100
        if old_pct > 40:
            score -= 20
        elif old_pct > 20:
            score -= 10

    score = max(10, min(100, score))

    if score >= 85:
        rating = "Excellent"
        color = "#10B981"
        summary = "Storage is well-managed with minimal redundant data."
    elif score >= 70:
        rating = "Good"
        color = "#3B82F6"
        summary = "Storage is healthy, but space can be reclaimed from duplicate copies."
    elif score >= 50:
        rating = "Moderate"
        color = "#F59E0B"
        summary = "Substantial duplicate and stale data found. Cleanup recommended."
    else:
        rating = "Critical"
        color = "#EF4444"
        summary = "High storage consumption with excessive duplicates. Immediate action needed."

    return {
        "score": score,
        "rating": rating,
        "color": color,
        "summary": summary,
        "quota_pct": round(quota_pct, 1),
    }


def audit_empty_and_temp_files(df: pd.DataFrame) -> pd.DataFrame:
    """
    Identify 0-byte ghost files and temporary/cache clutter files (.tmp, .log, .bak, .part, etc.).
    """
    if df.empty:
        return pd.DataFrame()

    temp_extensions = [".tmp", ".temp", ".log", ".bak", ".part", ".crdownload", ".swp", ".cache", ".dmp"]

    def is_temp_or_empty(row):
        name = str(row.get("name", "")).lower()
        size = row.get("size", 0)
        ext = os.path.splitext(name)[1].lower()

        if size == 0:
            return True, "Zero-Byte (Empty) File"
        if ext in temp_extensions:
            return True, f"Temporary/Cache Clutter ({ext})"
        if name.startswith("~") or name.startswith("."):
            return True, "Hidden Temporary Lock File"
        return False, ""

    reasons = []
    matched_indices = []

    for idx, row in df.iterrows():
        match, reason = is_temp_or_empty(row)
        if match:
            matched_indices.append(idx)
            reasons.append(reason)

    if not matched_indices:
        return pd.DataFrame()

    temp_df = df.loc[matched_indices].copy()
    temp_df["clutter_reason"] = reasons
    return temp_df.sort_values(by="size", ascending=False)


def calculate_cost_savings(reclaimable_bytes: int) -> dict:
    """
    Calculate annual and monthly cloud storage cost savings based on standard
    cloud storage pricing (Google One, AWS S3, Microsoft OneDrive ~$0.02 / GB / month or ₹1.80 / GB / month).
    """
    gb_saved = reclaimable_bytes / (1024**3)
    monthly_usd = gb_saved * 0.02
    annual_usd = monthly_usd * 12

    monthly_inr = gb_saved * 1.80
    annual_inr = monthly_inr * 12

    # Tier recommendation
    tier_avoided = "Basic Storage"
    if gb_saved >= 50:
        tier_avoided = "200 GB Cloud Tier ($2.99 / mo | ₹210 / mo)"
    elif gb_saved >= 5:
        tier_avoided = "100 GB Cloud Tier ($1.99 / mo | ₹130 / mo)"
    else:
        tier_avoided = "Storage Top-up Pack"

    return {
        "gb_saved": round(gb_saved, 2),
        "monthly_usd": round(monthly_usd, 2),
        "annual_usd": round(annual_usd, 2),
        "monthly_inr": round(monthly_inr, 2),
        "annual_inr": round(annual_inr, 2),
        "tier_avoided": tier_avoided,
    }

