"""
test_optimizer.py - Unit and Integration Tests for Cloud Storage Space Optimizer.
Tests SHA-256 hashing, duplicate detection, mock drive service, and health calculations.
"""

import hashlib
import io
import os
import unittest
import pandas as pd

from optimizer import (
    compute_sha256,
    format_bytes,
    categorize_file,
    process_files_dataframe,
    detect_duplicates_by_sha256,
    audit_large_files,
    audit_inactive_files,
    calculate_storage_health,
)
from drive_service import MockDriveManager


class TestStorageOptimizer(unittest.TestCase):

    def test_sha256_computation(self):
        sample_bytes = b"Cloud Computing Storage Optimizer SHA-256 Test"
        expected_hash = hashlib.sha256(sample_bytes).hexdigest()

        # Test from bytes
        computed_from_bytes = compute_sha256(sample_bytes)
        self.assertEqual(computed_from_bytes, expected_hash)

        # Test from stream
        stream = io.BytesIO(sample_bytes)
        computed_from_stream = compute_sha256(stream)
        self.assertEqual(computed_from_stream, expected_hash)

    def test_format_bytes(self):
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(1024 * 1024), "1.0 MB")
        self.assertEqual(format_bytes(1024 * 1024 * 1024), "1.0 GB")

    def test_file_categorization(self):
        self.assertEqual(categorize_file("video/mp4", "movie.mp4"), "Videos")
        self.assertEqual(categorize_file("image/jpeg", "photo.jpg"), "Photos & Images")
        self.assertEqual(categorize_file("application/pdf", "paper.pdf"), "Documents")
        self.assertEqual(categorize_file("application/zip", "backup.zip"), "Archives & Backups")

    def test_duplicate_detection_by_sha256(self):
        hash1 = hashlib.sha256(b"duplicate_content_A").hexdigest()
        hash2 = hashlib.sha256(b"unique_content_B").hexdigest()

        records = [
            {"id": "1", "name": "doc_original.pdf", "size": 1000, "sha256": hash1, "createdTime": "2024-01-01T00:00:00Z", "modifiedTime": "2024-01-01T00:00:00Z"},
            {"id": "2", "name": "doc_copy1.pdf", "size": 1000, "sha256": hash1, "createdTime": "2024-02-01T00:00:00Z", "modifiedTime": "2024-02-01T00:00:00Z"},
            {"id": "3", "name": "doc_copy2.pdf", "size": 1000, "sha256": hash1, "createdTime": "2024-03-01T00:00:00Z", "modifiedTime": "2024-03-01T00:00:00Z"},
            {"id": "4", "name": "doc_unique.pdf", "size": 2000, "sha256": hash2, "createdTime": "2024-01-01T00:00:00Z", "modifiedTime": "2024-01-01T00:00:00Z"},
        ]

        df = process_files_dataframe(records)
        dupes_df, reclaimable = detect_duplicates_by_sha256(df)

        self.assertFalse(dupes_df.empty)
        # Should have 3 files in the duplicate group
        self.assertEqual(len(dupes_df), 3)
        # 1 original keep, 2 redundant copies
        redundant = dupes_df[dupes_df["is_redundant"]]
        self.assertEqual(len(redundant), 2)
        # Reclaimable size should be 2 * 1000 = 2000 bytes
        self.assertEqual(reclaimable, 2000)

    def test_mock_drive_manager(self):
        manager = MockDriveManager()
        files = manager.list_files()
        quota = manager.get_quota()

        self.assertGreater(len(files), 10)
        self.assertGreater(quota["usage"], 0)
        self.assertGreater(quota["limit"], quota["usage"])

        # Check duplicate detection on mock files
        df = process_files_dataframe(files)
        dupes_df, reclaimable = detect_duplicates_by_sha256(df)
        self.assertGreater(reclaimable, 100 * 1024 * 1024)  # Over 100 MB reclaimable

    def test_local_folder_manager(self):
        import tempfile
        from drive_service import LocalFolderManager
        with tempfile.TemporaryDirectory() as temp_dir:
            f1 = os.path.join(temp_dir, "test1.txt")
            f2 = os.path.join(temp_dir, "test2_dupe.txt")
            with open(f1, "wb") as f:
                f.write(b"Same Content for SHA-256")
            with open(f2, "wb") as f:
                f.write(b"Same Content for SHA-256")

            mgr = LocalFolderManager(temp_dir)
            files = mgr.list_files()
            self.assertEqual(len(files), 2)
            self.assertEqual(files[0]["sha256"], files[1]["sha256"])

            df = process_files_dataframe(files)
            dupes_df, reclaimable = detect_duplicates_by_sha256(df)
            self.assertEqual(len(dupes_df), 2)
            self.assertEqual(reclaimable, len(b"Same Content for SHA-256"))

    def test_audit_empty_and_temp_files(self):
        from optimizer import audit_empty_and_temp_files
        records = [
            {"id": "1", "name": "normal.pdf", "size": 1024, "mimeType": "application/pdf", "sha256": "abc"},
            {"id": "2", "name": "corrupt_zero.tmp", "size": 0, "mimeType": "application/octet-stream", "sha256": ""},
            {"id": "3", "name": "app_debug.log", "size": 2048, "mimeType": "text/plain", "sha256": "def"},
        ]
        df = process_files_dataframe(records)
        clutter_df = audit_empty_and_temp_files(df)
        self.assertEqual(len(clutter_df), 2)  # corrupt_zero.tmp and app_debug.log

    def test_calculate_cost_savings(self):
        from optimizer import calculate_cost_savings
        savings = calculate_cost_savings(10 * 1024**3)  # 10 GB
        self.assertEqual(savings["gb_saved"], 10.0)
        self.assertGreater(savings["monthly_usd"], 0)
        self.assertGreater(savings["monthly_inr"], 0)
        self.assertIn("100 GB", savings["tier_avoided"])

    def test_scan_files_safety_and_junk(self):
        from optimizer import scan_files_safety_and_junk, audit_empty_and_temp_files
        records = [
            {"id": "1", "name": "document.pdf", "size": 1024, "mimeType": "application/pdf", "sha256": "h1", "createdTime": "2024-01-01T00:00:00Z", "modifiedTime": "2024-01-01T00:00:00Z"},
            {"id": "2", "name": "cache.tmp", "size": 500, "mimeType": "application/octet-stream", "sha256": "h2", "createdTime": "2024-01-01T00:00:00Z", "modifiedTime": "2024-01-01T00:00:00Z"},
            {"id": "3", "name": "document_copy.pdf", "size": 1024, "sha256": "h1", "createdTime": "2024-02-01T00:00:00Z", "modifiedTime": "2024-02-01T00:00:00Z"},
            {"id": "4", "name": "malicious.exe", "size": 2048, "mimeType": "application/octet-stream", "sha256": "h3", "createdTime": "2024-01-01T00:00:00Z", "modifiedTime": "2024-01-01T00:00:00Z"},
        ]
        df = process_files_dataframe(records)
        dupes_df, _ = detect_duplicates_by_sha256(df)
        clutter_df = audit_empty_and_temp_files(df)

        scanned, summary = scan_files_safety_and_junk(df, dupes_df, clutter_df)
        self.assertEqual(summary["total_files"], 4)
        self.assertEqual(summary["safe_count"], 1)  # document.pdf
        self.assertEqual(summary["junk_count"], 2)  # cache.tmp (clutter) + document_copy.pdf (redundant dupe)
        self.assertEqual(summary["suspicious_count"], 1)  # malicious.exe
        self.assertFalse(summary["all_safe"])

        # Check status labels
        status_map = {f["id"]: f for f in scanned}
        self.assertEqual(status_map["1"]["status_label"], "This file is Safe")
        self.assertEqual(status_map["2"]["status_label"], "This file is a Junk file")
        self.assertEqual(status_map["3"]["status_label"], "This file is a Junk file")
        self.assertEqual(status_map["4"]["status_label"], "This file is Unsafe / Potential Risk")

    def test_junk_test_file_detection(self):
        from optimizer import scan_files_safety_and_junk, audit_empty_and_temp_files
        records = [
            {"id": "safe1", "name": "project_report.pdf", "size": 5000, "mimeType": "application/pdf", "sha256": "hsafe"},
            {"id": "junk1", "name": "junk_test_file.txt", "size": 209, "mimeType": "text/plain", "sha256": "7a2cc089e15f0360ac1204c37f488453df952b92b04f5f6b6fdd6e499bfe735a"},
        ]
        df = process_files_dataframe(records)
        dupes_df, _ = detect_duplicates_by_sha256(df)
        clutter_df = audit_empty_and_temp_files(df)

        scanned, summary = scan_files_safety_and_junk(df, dupes_df, clutter_df)
        self.assertEqual(summary["total_files"], 2)
        self.assertEqual(summary["safe_count"], 1)
        self.assertEqual(summary["junk_count"], 1)
        self.assertEqual(summary["suspicious_count"], 0)
        self.assertFalse(summary["all_safe"])
        self.assertIn("1 junk file detected", summary["status_message"])

        # Check that junk_test_file.txt is marked as junk
        status_map = {f["id"]: f for f in scanned}
        self.assertEqual(status_map["junk1"]["status"], "junk")
        self.assertEqual(status_map["junk1"]["status_label"], "This file is a Junk file")
        self.assertEqual(status_map["junk1"]["status_badge"], "Junk File")

    def test_mock_drive_add_and_remove_test_junk(self):
        mgr = MockDriveManager()
        # Add test junk file
        res = mgr.add_test_junk_file("junk_test_file.txt", 209)
        self.assertEqual(res["name"], "junk_test_file.txt")
        self.assertEqual(res["size"], 209)

        # File is present in list_files
        files = mgr.list_files()
        junk_in_list = [f for f in files if f["name"] == "junk_test_file.txt"]
        self.assertEqual(len(junk_in_list), 1)

        # Move to trash (1-click remove)
        ok, msg = mgr.move_to_trash(junk_in_list[0]["id"])
        self.assertTrue(ok)

        # File is no longer in active list
        files_after = mgr.list_files()
        junk_after = [f for f in files_after if f["name"] == "junk_test_file.txt"]
        self.assertEqual(len(junk_after), 0)

    def test_sample_files_scanning(self):
        from drive_service import LocalFolderManager
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            for i in range(6):
                with open(os.path.join(temp_dir, f"file_{i}.txt"), "wb") as f:
                    f.write(f"Sample content {i}".encode())
            mgr = LocalFolderManager(temp_dir)
            files = mgr.list_files()
            self.assertEqual(len(files), 6)
            for f in files:
                self.assertEqual(len(f.get("sha256", "")), 64)

    def test_flask_api_set_mode_and_credentials(self):
        from app import app
        import io, tempfile
        client = app.test_client()

        with tempfile.TemporaryDirectory() as temp_dir:
            for i in range(6):
                with open(os.path.join(temp_dir, f"test_file_{i}.txt"), "wb") as f:
                    f.write(f"Data payload {i}".encode())

            # Test set-mode local
            resp = client.post("/api/set-mode", json={"mode": "local", "path": temp_dir})
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["success"])
            self.assertEqual(data["files_count"], 6)

            # Test stats with mode
            resp_stats = client.get(f"/api/stats?mode=local&path={temp_dir}")
            self.assertEqual(resp_stats.status_code, 200)
            stats_data = resp_stats.get_json()
            self.assertEqual(stats_data["current_mode"], "local")
            self.assertEqual(stats_data["total_files"], 6)

        # Test upload credentials (safe saving on all environments)
        fake_creds = b'{"web": {"client_id": "test_id.apps.googleusercontent.com", "client_secret": "sec"}}'
        data_file = {"file": (io.BytesIO(fake_creds), "credentials.json")}
        resp_upload = client.post("/api/upload-credentials", data=data_file, content_type="multipart/form-data")
        self.assertEqual(resp_upload.status_code, 200)
        upload_data = resp_upload.get_json()
        self.assertTrue(upload_data["success"])
        self.assertEqual(upload_data["client_type"], "Web Client")

        # Test empty token connect
        resp_tok = client.post("/api/connect-google-token", json={"token": ""})
        self.assertEqual(resp_tok.status_code, 400)


if __name__ == "__main__":
    unittest.main()


