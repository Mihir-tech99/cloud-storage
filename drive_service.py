"""
drive_service.py - Cloud Storage Connector & Online Dataset Manager.
Supports:
1. Live Google Drive connection via OAuth 2.0 (Google Drive API v3)
2. Interactive Simulated Cloud Storage (Zero sign-up / No credit card required)
3. Local Synced Cloud Folder Scanner (Google Drive for Desktop, OneDrive, or any local folder)
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import hashlib
import io
import os
import random
import shutil
from typing import Any

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    GOOGLE_LIBS_AVAILABLE = True
except ImportError:
    GOOGLE_LIBS_AVAILABLE = False


SCOPES = [
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive",
]


class LocalFolderManager:
    """
    Scans a local synced cloud folder (e.g., Google Drive for Desktop, OneDrive, or any local directory).
    Computes real SHA-256 hashes without needing Google Cloud Console or credit cards.
    """

    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)
        self.trash_dir = os.path.join(self.root_dir, ".optimizer_trash")
        self.user_info = {
            "displayName": "Local Synced Cloud User",
            "emailAddress": "local.drive@pc.sync",
        }

    def get_quota(self) -> dict[str, Any]:
        """Calculates storage usage and drive capacity."""
        if not os.path.exists(self.root_dir):
            return {"limit": 15 * 1024**3, "usage": 0, "usageInDrive": 0, "usageInDriveTrash": 0}

        try:
            total, used, free = shutil.disk_usage(self.root_dir)
            files = self.list_files()
            folder_usage = sum(f["size"] for f in files)
            trash_usage = 0
            if os.path.exists(self.trash_dir):
                for root, _, filenames in os.walk(self.trash_dir):
                    for fn in filenames:
                        trash_usage += os.path.getsize(os.path.join(root, fn))

            # Virtual 15 GB quota cap for realistic display, or actual disk usage
            limit = 15 * 1024 * 1024 * 1024
            return {
                "limit": limit,
                "usage": folder_usage + trash_usage,
                "usageInDrive": folder_usage,
                "usageInDriveTrash": trash_usage,
            }
        except Exception as e:
            print(f"Error getting disk quota: {e}")
            return {"limit": 15 * 1024**3, "usage": 0, "usageInDrive": 0, "usageInDriveTrash": 0}

    def list_files(self, max_files: int = 1000) -> list[dict[str, Any]]:
        """Walks the folder and calculates SHA-256 hashes for all files."""
        if not os.path.exists(self.root_dir):
            return []

        results = []
        for root, dirs, filenames in os.walk(self.root_dir):
            # Skip hidden trash folder
            if ".optimizer_trash" in root:
                continue

            for fname in filenames:
                if len(results) >= max_files:
                    break
                fpath = os.path.join(root, fname)
                try:
                    stat = os.stat(fpath)
                    fsize = stat.st_size

                    # Compute SHA-256 hash
                    hasher = hashlib.sha256()
                    with open(fpath, "rb") as f:
                        while chunk := f.read(65536):
                            hasher.update(chunk)
                    sha = hasher.hexdigest()

                    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                    ctime = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()

                    ext = os.path.splitext(fname)[1].lower()
                    mime = "application/octet-stream"
                    if ext in [".mp4", ".mkv", ".mov"]:
                        mime = "video/mp4"
                    elif ext in [".jpg", ".jpeg", ".png"]:
                        mime = "image/jpeg"
                    elif ext in [".pdf"]:
                        mime = "application/pdf"
                    elif ext in [".csv"]:
                        mime = "text/csv"
                    elif ext in [".txt"]:
                        mime = "text/plain"
                    elif ext in [".zip", ".gz", ".tar"]:
                        mime = "application/zip"

                    results.append({
                        "id": fpath,
                        "name": fname,
                        "mimeType": mime,
                        "size": fsize,
                        "sha256": sha,
                        "createdTime": ctime,
                        "modifiedTime": mtime,
                        "webViewLink": f"file:///{fpath.replace(os.sep, '/')}",
                        "trashed": False,
                    })
                except Exception as e:
                    print(f"Error reading file {fpath}: {e}")

        return results

    def move_to_trash(self, file_id: str) -> tuple[bool, str]:
        """Safely moves file to .optimizer_trash folder."""
        fpath = file_id
        if not os.path.exists(fpath):
            return False, "File does not exist."

        try:
            os.makedirs(self.trash_dir, exist_ok=True)
            dest = os.path.join(self.trash_dir, os.path.basename(fpath))
            # Handle collision
            if os.path.exists(dest):
                base, ext = os.path.splitext(os.path.basename(fpath))
                dest = os.path.join(self.trash_dir, f"{base}_{int(datetime.now().timestamp())}{ext}")
            shutil.move(fpath, dest)
            return True, f"Moved {os.path.basename(fpath)} to trash."
        except Exception as e:
            return False, str(e)

    def empty_trash(self) -> tuple[bool, str]:
        """Empties .optimizer_trash folder."""
        if os.path.exists(self.trash_dir):
            try:
                shutil.rmtree(self.trash_dir)
                return True, "Emptied trash folder successfully."
            except Exception as e:
                return False, str(e)
        return True, "Trash is already empty."


class GoogleDriveManager:
    """Manages live Google Drive API connections, metadata extraction, and file management."""

    def __init__(self, credentials_path: str = "credentials.json", token_path: str = "token.json"):
        self.credentials_path = credentials_path
        self.token_path = token_path
        self.service = None
        self.user_info = {}

    def authenticate(self) -> tuple[bool, str]:
        """Authenticate with Google Drive via OAuth 2.0."""
        if not GOOGLE_LIBS_AVAILABLE:
            return False, "Google client libraries are missing. Please install requirements.txt."

        if not os.path.exists(self.credentials_path):
            return False, f"Credentials file '{self.credentials_path}' not found. Upload it in the sidebar."

        creds = None
        try:
            if os.path.exists(self.token_path):
                creds = Credentials.from_authorized_user_file(self.token_path, SCOPES)

            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file(self.credentials_path, SCOPES)
                    creds = flow.run_local_server(port=0)

                with open(self.token_path, "w", encoding="utf-8") as token_file:
                    token_file.write(creds.to_json())

            self.service = build("drive", "v3", credentials=creds)
            about = self.service.about().get(fields="user,storageQuota").execute()
            self.user_info = about.get("user", {})
            return True, f"Connected to Google Drive as {self.user_info.get('displayName', 'User')} ({self.user_info.get('emailAddress', '')})"
        except Exception as e:
            return False, f"Authentication error: {str(e)}"

    def get_quota(self) -> dict[str, Any]:
        """Fetch storage quota from Google Drive."""
        if not self.service:
            return {"limit": 0, "usage": 0, "usageInDrive": 0, "usageInDriveTrash": 0}
        try:
            about = self.service.about().get(fields="storageQuota").execute()
            quota = about.get("storageQuota", {})
            return {
                "limit": int(quota.get("limit", 0)),
                "usage": int(quota.get("usage", 0)),
                "usageInDrive": int(quota.get("usageInDrive", 0)),
                "usageInDriveTrash": int(quota.get("usageInDriveTrash", 0)),
            }
        except Exception as e:
            print(f"Error fetching quota: {e}")
            return {"limit": 0, "usage": 0, "usageInDrive": 0, "usageInDriveTrash": 0}

    def list_files(self, max_files: int = 1000) -> list[dict[str, Any]]:
        """List files stored online in Google Drive."""
        if not self.service:
            return []

        files = []
        page_token = None
        query = "trashed = false and mimeType != 'application/vnd.google-apps.folder'"

        try:
            while len(files) < max_files:
                response = self.service.files().list(
                    q=query,
                    spaces="drive",
                    fields="nextPageToken, files(id, name, mimeType, size, md5Checksum, sha256Checksum, createdTime, modifiedTime, webViewLink)",
                    pageSize=min(250, max_files - len(files)),
                    pageToken=page_token,
                ).execute()

                items = response.get("files", [])
                for item in items:
                    sha = item.get("sha256Checksum")
                    if not sha and item.get("md5Checksum"):
                        sig = f"{item.get('name')}_{item.get('size')}_{item.get('md5Checksum')}"
                        sha = hashlib.sha256(sig.encode()).hexdigest()
                    item["sha256"] = sha

                files.extend(items)
                page_token = response.get("nextPageToken")
                if not page_token:
                    break
        except Exception as e:
            print(f"Error fetching files: {e}")

        return files

    def move_to_trash(self, file_id: str) -> tuple[bool, str]:
        """Move a file to Google Drive Trash (safe operation)."""
        if not self.service:
            return False, "Google Drive is not connected."
        try:
            self.service.files().update(fileId=file_id, body={"trashed": True}).execute()
            return True, "File successfully moved to Google Drive Trash."
        except Exception as e:
            return False, str(e)

    def empty_trash(self) -> tuple[bool, str]:
        """Empty Google Drive trash."""
        if not self.service:
            return False, "Google Drive is not connected."
        try:
            self.service.files().emptyTrash().execute()
            return True, "Google Drive Trash has been permanently emptied."
        except Exception as e:
            return False, str(e)


class MockDriveManager:
    """
    Simulates Google Drive cloud storage with realistic online files,
    verified SHA-256 hashes, exact duplicate groups, and storage quotas.
    No Google Cloud Console sign up or payment required.
    """

    def __init__(self):
        self.user_info = {
            "displayName": "Demo Cloud Student",
            "emailAddress": "cloud.demo@university.edu",
        }
        self.trash_size_bytes = 750 * 1024 * 1024  # 750 MB in trash
        self.files = self._generate_mock_dataset()

    def get_quota(self) -> dict[str, Any]:
        """Simulated 15 GB Google Drive quota."""
        limit = 15 * 1024 * 1024 * 1024  # 15 GB
        files_size = sum(f["size"] for f in self.files)
        usage = files_size + self.trash_size_bytes
        return {
            "limit": limit,
            "usage": usage,
            "usageInDrive": files_size,
            "usageInDriveTrash": self.trash_size_bytes,
        }

    def list_files(self, max_files: int = 1000) -> list[dict[str, Any]]:
        return [f for f in self.files if not f.get("trashed", False)]

    def move_to_trash(self, file_id: str) -> tuple[bool, str]:
        """Simulate moving a file to trash."""
        for f in self.files:
            if f["id"] == file_id and not f.get("trashed", False):
                f["trashed"] = True
                self.trash_size_bytes += f["size"]
                return True, f"'{f['name']}' moved to trash."
        return False, "File ID not found."

    def empty_trash(self) -> tuple[bool, str]:
        """Simulate emptying the trash."""
        freed = self.trash_size_bytes
        self.trash_size_bytes = 0
        self.files = [f for f in self.files if not f.get("trashed", False)]
        return True, f"Emptied {freed / (1024**2):.1f} MB from trash."

    def _generate_mock_dataset(self) -> list[dict[str, Any]]:
        """Build realistic files with authentic SHA-256 hashes."""
        now = datetime.now(timezone.utc)
        files = []

        duplicate_groups_data = [
            {
                "group_name": "ML Weather Dataset",
                "original_name": "Global_Weather_Sensors_Dataset.csv",
                "mimeType": "text/csv",
                "size": 200 * 1024 * 1024,  # 200 MB
                "sha256": hashlib.sha256(b"Global_Weather_Sensors_Dataset_Binary_Content").hexdigest(),
                "copies": [
                    ("Global_Weather_Sensors_Dataset_COPY.csv", 90),
                    ("backup_weather_2024.csv", 35),
                ],
                "orig_age": 280,
            },
            {
                "group_name": "Drone 4K Footage",
                "original_name": "Campus_Drone_Footage_RAW_4K.mp4",
                "mimeType": "video/mp4",
                "size": 950 * 1024 * 1024,  # 950 MB
                "sha256": hashlib.sha256(b"Campus_Drone_Footage_RAW_4K_Stream_Bytes").hexdigest(),
                "copies": [
                    ("Campus_Drone_Footage_RAW_4K (Copy).mp4", 120),
                ],
                "orig_age": 210,
            },
            {
                "group_name": "OS Server Image",
                "original_name": "Ubuntu_24.04_LTS_Server.iso",
                "mimeType": "application/x-iso9660-image",
                "size": 1100 * 1024 * 1024,  # 1.1 GB
                "sha256": hashlib.sha256(b"Ubuntu_24.04_LTS_Server_ISO_Image_Header").hexdigest(),
                "copies": [
                    ("ubuntu-24.04-live-server-amd64.iso", 140),
                ],
                "orig_age": 320,
            },
            {
                "group_name": "LLM Model Weights",
                "original_name": "LLaMA3_8B_Instruct_Q4_K_M.gguf",
                "mimeType": "application/octet-stream",
                "size": 1400 * 1024 * 1024,  # 1.4 GB
                "sha256": hashlib.sha256(b"LLaMA3_8B_Instruct_Q4_K_M_Weights_Buffer").hexdigest(),
                "copies": [
                    ("llama-3-8b-instruct.Q4_K_M (1).gguf", 45),
                ],
                "orig_age": 120,
            },
            {
                "group_name": "AWS Cloud Sync Backup",
                "original_name": "AWS_S3_Bucket_Sync_Archive.zip",
                "mimeType": "application/zip",
                "size": 220 * 1024 * 1024,  # 220 MB
                "sha256": hashlib.sha256(b"AWS_S3_Bucket_Sync_Archive_Zip_Stream").hexdigest(),
                "copies": [
                    ("s3_backup_production_archive.zip", 30),
                ],
                "orig_age": 180,
            },
            {
                "group_name": "Seminar Presentation",
                "original_name": "Cloud_Computing_Final_Seminar.pptx",
                "mimeType": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                "size": 35 * 1024 * 1024,  # 35 MB
                "sha256": hashlib.sha256(b"Cloud_Computing_Final_Seminar_Slides_Content").hexdigest(),
                "copies": [
                    ("Cloud_Computing_Final_Seminar_v2.pptx", 60),
                    ("Copy of Cloud_Computing_Final_Seminar.pptx", 10),
                ],
                "orig_age": 160,
            },
            {
                "group_name": "High-Res RAW Photo",
                "original_name": "Mountain_Landscape_Panorama.cr2",
                "mimeType": "image/x-canon-cr2",
                "size": 45 * 1024 * 1024,  # 45 MB
                "sha256": hashlib.sha256(b"Mountain_Landscape_RAW_CR2_Sensor_Data").hexdigest(),
                "copies": [
                    ("IMG_5891_RAW_Mountain.cr2", 45),
                ],
                "orig_age": 190,
            },
            {
                "group_name": "Website Tarball Backup",
                "original_name": "Wordpress_Production_Backup_2023.tar.gz",
                "mimeType": "application/gzip",
                "size": 480 * 1024 * 1024,  # 480 MB
                "sha256": hashlib.sha256(b"Wordpress_Production_Backup_2023_Archive_Blob").hexdigest(),
                "copies": [
                    ("Wordpress_Production_Backup_2023_Archive.tar.gz", 300),
                ],
                "orig_age": 420,
            },
        ]

        file_id_counter = 100
        for grp in duplicate_groups_data:
            c_dt = now - timedelta(days=grp["orig_age"])
            files.append({
                "id": f"cloud_file_{file_id_counter}",
                "name": grp["original_name"],
                "mimeType": grp["mimeType"],
                "size": grp["size"],
                "sha256": grp["sha256"],
                "createdTime": c_dt.isoformat(),
                "modifiedTime": c_dt.isoformat(),
                "webViewLink": f"https://drive.google.com/file/d/cloud_file_{file_id_counter}/view",
                "trashed": False,
            })
            file_id_counter += 1

            for copy_name, days_ago in grp["copies"]:
                cp_dt = now - timedelta(days=days_ago)
                files.append({
                    "id": f"cloud_file_{file_id_counter}",
                    "name": copy_name,
                    "mimeType": grp["mimeType"],
                    "size": grp["size"],
                    "sha256": grp["sha256"],
                    "createdTime": cp_dt.isoformat(),
                    "modifiedTime": cp_dt.isoformat(),
                    "webViewLink": f"https://drive.google.com/file/d/cloud_file_{file_id_counter}/view",
                    "trashed": False,
                })
                file_id_counter += 1

        # Standalone large files
        large_files = [
            ("Kubernetes_Cluster_Snapshot.tar", "application/x-tar", 550 * 1024 * 1024, 90),
            ("Quarterly_Sprint_Demo_Recording.mp4", "video/mp4", 420 * 1024 * 1024, 45),
            ("Neural_Net_ResNet50_Weights.h5", "application/octet-stream", 310 * 1024 * 1024, 110),
            ("GoPro_Mountain_Biking_4K.mp4", "video/mp4", 480 * 1024 * 1024, 65),
            ("PyTorch_Model_Checkpoint_Epoch100.pth", "application/octet-stream", 220 * 1024 * 1024, 75),
            ("Postgres_Database_Dump_Jan2024.sql", "application/sql", 180 * 1024 * 1024, 250),
            ("Audio_Podcast_Full_Interview.flac", "audio/flac", 160 * 1024 * 1024, 180),
            ("Docker_Dev_Container_Export.tar", "application/x-tar", 390 * 1024 * 1024, 200),
        ]
        for name, mime, size, days in large_files:
            dt = now - timedelta(days=days)
            file_sha = hashlib.sha256(f"{name}_{size}_{days}".encode()).hexdigest()
            files.append({
                "id": f"cloud_file_{file_id_counter}",
                "name": name,
                "mimeType": mime,
                "size": size,
                "sha256": file_sha,
                "createdTime": dt.isoformat(),
                "modifiedTime": dt.isoformat(),
                "webViewLink": f"https://drive.google.com/file/d/cloud_file_{file_id_counter}/view",
                "trashed": False,
            })
            file_id_counter += 1

        # Clutter, temporary, and 0-byte ghost files
        clutter_files = [
            ("interrupted_download_dataset.crdownload", "application/octet-stream", 0, 12),
            ("~lock.Semester_Project_Presentation.pptx#", "application/octet-stream", 0, 4),
            ("cache_metadata_chunk_001.tmp", "application/octet-stream", 15 * 1024 * 1024, 8),
            ("npm_debug_error_output.log", "text/plain", 8 * 1024 * 1024, 30),
            ("system_temp_crash_dump.dmp", "application/octet-stream", 32 * 1024 * 1024, 15),
            ("empty_scratch_test.txt", "text/plain", 0, 2),
            ("temp_backup_staging.bak", "application/octet-stream", 18 * 1024 * 1024, 45),
        ]
        for name, mime, size, days in clutter_files:
            dt = now - timedelta(days=days)
            file_sha = hashlib.sha256(f"{name}_{size}".encode()).hexdigest() if size > 0 else ""
            files.append({
                "id": f"cloud_file_{file_id_counter}",
                "name": name,
                "mimeType": mime,
                "size": size,
                "sha256": file_sha,
                "createdTime": dt.isoformat(),
                "modifiedTime": dt.isoformat(),
                "webViewLink": f"https://drive.google.com/file/d/cloud_file_{file_id_counter}/view",
                "trashed": False,
            })
            file_id_counter += 1

        # Standard documents, images, code files
        standard_items = [
            ("Cloud_Storage_Optimization_Whitepaper.pdf", "application/pdf", 14 * 1024 * 1024, 15),
            ("Serverless_Architecture_Diagram.png", "image/png", 8 * 1024 * 1024, 28),
            ("Financial_Model_Projections.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 12 * 1024 * 1024, 85),
            ("Research_Summary_Distributed_Hash_Tables.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", 6 * 1024 * 1024, 400),
            ("Team_Offsite_Group_Photo.jpeg", "image/jpeg", 9 * 1024 * 1024, 150),
            ("Conference_Audio_Recording.mp3", "audio/mpeg", 45 * 1024 * 1024, 130),
            ("Terraform_Cloud_Infrastructure.tf", "text/plain", 1 * 1024 * 1024, 20),
            ("Machine_Learning_Pipelines.ipynb", "application/json", 5 * 1024 * 1024, 50),
            ("Dataset_Pandas_Feature_Store.parquet", "application/octet-stream", 25 * 1024 * 1024, 14),
            ("Spring_Boot_Microservice_Template.zip", "application/zip", 18 * 1024 * 1024, 40),
            ("Cloud_Security_Best_Practices.pdf", "application/pdf", 11 * 1024 * 1024, 60),
            ("Docker_Compose_FullStack.yaml", "text/yaml", 512 * 1024, 5),
            ("Customer_Feedback_Matrix.csv", "text/csv", 4 * 1024 * 1024, 25),
        ]
        for name, mime, size, days in standard_items:
            dt = now - timedelta(days=days)
            file_sha = hashlib.sha256(f"{name}_{size}_{days}".encode()).hexdigest()
            files.append({
                "id": f"cloud_file_{file_id_counter}",
                "name": name,
                "mimeType": mime,
                "size": size,
                "sha256": file_sha,
                "createdTime": dt.isoformat(),
                "modifiedTime": dt.isoformat(),
                "webViewLink": f"https://drive.google.com/file/d/cloud_file_{file_id_counter}/view",
                "trashed": False,
            })
            file_id_counter += 1

        return files
