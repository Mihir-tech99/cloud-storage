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
import json
import os
import random
import shutil
import tempfile
from typing import Any

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google.oauth2 import service_account
    from google_auth_oauthlib.flow import InstalledAppFlow, Flow
    from googleapiclient.discovery import build
    GOOGLE_LIBS_AVAILABLE = True
except ImportError:
    GOOGLE_LIBS_AVAILABLE = False


SCOPES = [
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive",
]


def resolve_storage_file(filename: str, check_writable: bool = False) -> str:
    """Find a readable file path, or return a safe writable path in /tmp on serverless environments."""
    if check_writable:
        # Check if local directory is writable
        try:
            test_path = os.path.join(".", f".chk_{int(datetime.now().timestamp())}")
            with open(test_path, "w") as f:
                f.write("1")
            os.remove(test_path)
            return os.path.abspath(filename)
        except Exception:
            return os.path.join(tempfile.gettempdir(), filename)

    # First check current directory
    if os.path.exists(filename):
        return os.path.abspath(filename)
    # Then check /tmp
    tmp_path = os.path.join(tempfile.gettempdir(), filename)
    if os.path.exists(tmp_path):
        return tmp_path
    # Default to current directory if exists, else tmp
    return tmp_path


class LocalFolderManager:
    """
    Scans a local synced cloud folder (e.g. sample_files, Google Drive for Desktop, or any local directory).
    Computes real SHA-256 hashes without needing Google Cloud Console or credit cards.
    """

    def __init__(self, root_dir: str = "sample_files"):
        self.raw_path = root_dir
        abs_path = os.path.abspath(root_dir)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        bundled_path = os.path.join(script_dir, root_dir)
        tmp_path = os.path.join(tempfile.gettempdir(), os.path.basename(root_dir))

        if os.path.exists(abs_path):
            self.root_dir = abs_path
        elif os.path.exists(bundled_path):
            self.root_dir = bundled_path
        elif os.path.exists(tmp_path):
            self.root_dir = tmp_path
        else:
            try:
                os.makedirs(tmp_path, exist_ok=True)
                self.root_dir = tmp_path
            except Exception:
                self.root_dir = abs_path

        # If sample_files is empty or missing, populate with rich demo files
        self._ensure_sample_files()

        # Check if root_dir is writable for trash
        is_writable = False
        try:
            if os.path.exists(self.root_dir) and os.access(self.root_dir, os.W_OK):
                test_file = os.path.join(self.root_dir, f".wr_test_{int(datetime.now().timestamp())}")
                with open(test_file, "w") as f:
                    f.write("1")
                os.remove(test_file)
                is_writable = True
        except Exception:
            is_writable = False

        if is_writable:
            self.trash_dir = os.path.join(self.root_dir, ".optimizer_trash")
        else:
            self.trash_dir = os.path.join(tempfile.gettempdir(), ".optimizer_trash")

        self.user_info = {
            "displayName": "Local Synced Cloud User",
            "emailAddress": "local.drive@pc.sync",
        }
        self._hash_cache: dict[str, tuple[float, int, str]] = {}

    def _ensure_sample_files(self):
        """Ensure sample_files contains files for scanning if target is sample_files."""
        # Only populate if this is specifically the sample_files folder
        if "sample_files" not in os.path.basename(self.root_dir).lower() and "sample_files" not in self.raw_path.lower():
            return

        if not os.path.exists(self.root_dir):
            try:
                os.makedirs(self.root_dir, exist_ok=True)
            except Exception:
                return

        try:
            existing = [f for f in os.listdir(self.root_dir) if not f.startswith(".")]
            if len(existing) > 0:
                return
        except Exception:
            pass

        try:
            doc_content = b"Cloud Computing Storage Optimizer Demonstration Notes.\nLecture 4: Cloud Resource Optimization and Storage Deduplication.\n"
            with open(os.path.join(self.root_dir, "Cloud_Notes_Lecture.txt"), "wb") as f:
                f.write(doc_content)
            with open(os.path.join(self.root_dir, "Cloud_Notes_Lecture_DUPLICATE.txt"), "wb") as f:
                f.write(doc_content)

            pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Title (Quarterly Cloud Financial Report) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n" + (b"DATA_PADDING_" * 500)
            with open(os.path.join(self.root_dir, "Quarterly_Financial_Report.pdf"), "wb") as f:
                f.write(pdf_content)
            with open(os.path.join(self.root_dir, "Quarterly_Financial_Report_COPY.pdf"), "wb") as f:
                f.write(pdf_content)

            img_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00" + (b"\xaa\xbb\xcc\xdd" * 400)
            with open(os.path.join(self.root_dir, "System_Architecture_Diagram.png"), "wb") as f:
                f.write(img_content)
            with open(os.path.join(self.root_dir, "System_Architecture_Backup.png"), "wb") as f:
                f.write(img_content)

            csv_content = b"id,customer_name,storage_gb,plan\n1,Alice,250,Enterprise\n2,Bob,50,Basic\n3,Charlie,500,Pro\n" + (b"row_data_entry_metric_stream\n" * 50)
            with open(os.path.join(self.root_dir, "Customer_Dataset_2026.csv"), "wb") as f:
                f.write(csv_content)
            with open(os.path.join(self.root_dir, "Customer_Dataset_2026_DUPLICATE.csv"), "wb") as f:
                f.write(csv_content)

            with open(os.path.join(self.root_dir, "interrupted_download.tmp"), "wb") as f:
                f.write(b"Temporary residual cache file")

            with open(os.path.join(self.root_dir, "application_debug.log"), "wb") as f:
                f.write(b"[DEBUG] 2026-10-22 Cache sync initialized\n[TRACE] Stale buffer dumped\n")

            with open(os.path.join(self.root_dir, "0_byte_ghost_file.txt"), "wb") as f:
                f.write(b"")

            with open(os.path.join(self.root_dir, "junk_test_file.txt"), "wb") as f:
                f.write(("Cloud Space Optimizer Test Junk File: Temporary data clutter.\n" * 5).encode("utf-8")[:209])
        except Exception as e:
            print(f"Notice: Could not write sample files into {self.root_dir}: {e}")

    def get_quota(self, files: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Calculates storage usage and drive capacity with fast 0ms computation."""
        limit = 15 * 1024 * 1024 * 1024  # 15 GB Virtual Quota
        folder_usage = 0
        trash_usage = 0

        if files is not None:
            folder_usage = sum(f.get("size", 0) for f in files)
        elif os.path.exists(self.root_dir):
            for root, _, filenames in os.walk(self.root_dir):
                if ".optimizer_trash" in root:
                    continue
                for fn in filenames:
                    try:
                        folder_usage += os.path.getsize(os.path.join(root, fn))
                    except Exception:
                        pass

        if os.path.exists(self.trash_dir):
            for root, _, filenames in os.walk(self.trash_dir):
                for fn in filenames:
                    try:
                        trash_usage += os.path.getsize(os.path.join(root, fn))
                    except Exception:
                        pass

        return {
            "limit": limit,
            "usage": folder_usage + trash_usage,
            "usageInDrive": folder_usage,
            "usageInDriveTrash": trash_usage,
        }

    def list_files(self, max_files: int = 1000) -> list[dict[str, Any]]:
        """Walks the folder and calculates SHA-256 hashes for all files with hash caching."""
        if not os.path.exists(self.root_dir):
            return []

        results = []
        for root, dirs, filenames in os.walk(self.root_dir):
            if ".optimizer_trash" in root:
                continue

            for fname in filenames:
                if len(results) >= max_files:
                    break
                fpath = os.path.join(root, fname)
                try:
                    stat = os.stat(fpath)
                    fsize = stat.st_size
                    mtime_ts = stat.st_mtime

                    cached_entry = self._hash_cache.get(fpath)
                    if cached_entry and cached_entry[0] == mtime_ts and cached_entry[1] == fsize:
                        sha = cached_entry[2]
                    else:
                        hasher = hashlib.sha256()
                        with open(fpath, "rb") as f:
                            while chunk := f.read(65536):
                                hasher.update(chunk)
                        sha = hasher.hexdigest()
                        self._hash_cache[fpath] = (mtime_ts, fsize, sha)

                    mtime = datetime.fromtimestamp(mtime_ts, tz=timezone.utc).isoformat()
                    ctime = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()

                    ext = os.path.splitext(fname)[1].lower()
                    mime = "application/octet-stream"
                    if ext in [".mp4", ".mkv", ".mov"]:
                        mime = "video/mp4"
                    elif ext in [".jpg", ".jpeg", ".png"]:
                        mime = "image/png"
                    elif ext in [".pdf"]:
                        mime = "application/pdf"
                    elif ext in [".csv"]:
                        mime = "text/csv"
                    elif ext in [".txt", ".log"]:
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
        """Safely moves file to trash folder."""
        fpath = file_id
        if not os.path.exists(fpath):
            return False, "File does not exist."

        try:
            os.makedirs(self.trash_dir, exist_ok=True)
            dest = os.path.join(self.trash_dir, os.path.basename(fpath))
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

    def add_test_junk_file(self, name: str = "junk_test_file.txt", size: int = 209) -> dict[str, Any]:
        """Creates a real test junk file in the local folder for scanner testing."""
        target_dir = self.root_dir
        if not os.access(target_dir, os.W_OK):
            target_dir = tempfile.gettempdir()
        try:
            os.makedirs(target_dir, exist_ok=True)
            fpath = os.path.join(target_dir, name)
            content = "Cloud Space Optimizer Test Junk File: Temporary data clutter.\n" * 5
            content_bytes = content.encode("utf-8")[:size]
            with open(fpath, "wb") as f:
                f.write(content_bytes)
            return {"id": fpath, "name": name, "size": len(content_bytes)}
        except Exception as e:
            return {"id": name, "name": name, "size": size}


def normalize_client_config(raw_dict: dict[str, Any]) -> dict[str, Any]:
    """Ensure client secrets dict contains all required fields for google_auth_oauthlib."""
    if not isinstance(raw_dict, dict):
        raise ValueError("Invalid client secrets format.")
    key = "web" if "web" in raw_dict else ("installed" if "installed" in raw_dict else None)
    if not key:
        raise ValueError("credentials.json must contain either 'web' or 'installed' configuration.")
    c = dict(raw_dict.get(key, {}))
    if not c.get("auth_uri"):
        c["auth_uri"] = "https://accounts.google.com/o/oauth2/auth"
    if not c.get("token_uri"):
        c["token_uri"] = "https://oauth2.googleapis.com/token"
    if not c.get("client_id") or not c.get("client_secret"):
        raise ValueError("The credentials file is missing 'client_id' or 'client_secret'.")
    return {key: c}


class GoogleDriveManager:
    """Manages live Google Drive API connections, metadata extraction, and file management."""

    def __init__(self, credentials_path: str | None = None, token_path: str | None = None):
        self.credentials_path = credentials_path or resolve_storage_file("credentials.json")
        self.token_path = token_path or resolve_storage_file("token.json", check_writable=True)
        self.service = None
        self.user_info = {}
        self._try_load_existing_token()

    def _try_load_existing_token(self):
        """Attempts to load credentials from token_path or environment/tmp."""
        if not GOOGLE_LIBS_AVAILABLE:
            return

        for token_file in [self.token_path, resolve_storage_file("token.json"), os.path.join(tempfile.gettempdir(), "token.json")]:
            if token_file and os.path.exists(token_file):
                try:
                    creds = Credentials.from_authorized_user_file(token_file, SCOPES)
                    if creds and creds.expired and creds.refresh_token:
                        creds.refresh(Request())
                        try:
                            with open(self.token_path, "w", encoding="utf-8") as f:
                                f.write(creds.to_json())
                        except Exception:
                            pass

                    if creds and creds.valid:
                        self.service = build("drive", "v3", credentials=creds)
                        about = self.service.about().get(fields="user,storageQuota").execute()
                        self.user_info = about.get("user", {})
                        return
                except Exception as e:
                    print(f"Notice: Could not load token from {token_file}: {e}")

    def authenticate_with_token(self, token_str: str) -> tuple[bool, str]:
        """Authenticate directly using an access token or bearer token."""
        if not GOOGLE_LIBS_AVAILABLE:
            return False, "Google client libraries are missing. Please install requirements.txt."
        token_str = token_str.strip()
        if not token_str:
            return False, "Access token is empty."
        try:
            creds = Credentials(token=token_str)
            self.service = build("drive", "v3", credentials=creds)
            about = self.service.about().get(fields="user,storageQuota").execute()
            self.user_info = about.get("user", {})
            try:
                with open(self.token_path, "w", encoding="utf-8") as f:
                    f.write(creds.to_json())
            except Exception:
                pass
            name = self.user_info.get("displayName", "User")
            email = self.user_info.get("emailAddress", "")
            return True, f"Connected to Google Drive as {name} ({email})!"
        except Exception as e:
            self.service = None
            err_msg = str(e)
            if "refresh" in err_msg.lower() or "401" in err_msg or "invalid_token" in err_msg.lower() or "invalid_grant" in err_msg.lower():
                return False, "Invalid or expired Access Token. Please generate a fresh token from Google OAuth Playground (Step 2) and try again."
            return False, f"Google Drive connection failed: {err_msg}"

    def authenticate_with_service_account(self, creds_path: str) -> tuple[bool, str]:
        """Authenticate using a Google Cloud Service Account JSON."""
        if not GOOGLE_LIBS_AVAILABLE:
            return False, "Google client libraries are missing."
        try:
            creds = service_account.Credentials.from_service_account_file(creds_path, scopes=SCOPES)
            self.service = build("drive", "v3", credentials=creds)
            about = self.service.about().get(fields="user,storageQuota").execute()
            self.user_info = about.get("user", {})
            return True, f"Connected to Google Drive via Service Account ({self.user_info.get('emailAddress', 'Service Account')})"
        except Exception as e:
            return False, f"Service account authentication error: {str(e)}"

    def get_authorization_url(self, redirect_uri: str, client_config: dict[str, Any] | None = None) -> tuple[str, str]:
        """Generates Google OAuth 2.0 authorization URL from config dict or credentials.json."""
        if not GOOGLE_LIBS_AVAILABLE:
            raise RuntimeError("Google client libraries not installed.")

        cfg = None
        if client_config:
            cfg = normalize_client_config(client_config)
        else:
            cred_file = resolve_storage_file("credentials.json")
            if cred_file and os.path.exists(cred_file):
                try:
                    with open(cred_file, "r", encoding="utf-8") as f:
                        raw = json.load(f)
                    cfg = normalize_client_config(raw)
                except Exception as e:
                    raise ValueError(f"Invalid credentials file: {e}")
            else:
                raise FileNotFoundError("Credentials not configured. Please upload credentials.json or use Quick Token Connect.")

        # Encode cid and cs into state to make flow 100% stateless across serverless containers
        custom_state = None
        c_info = cfg.get("web") or cfg.get("installed", {})
        if c_info.get("client_id") and c_info.get("client_secret"):
            try:
                import base64
                s_payload = json.dumps({"cid": c_info["client_id"], "cs": c_info["client_secret"]})
                custom_state = base64.urlsafe_b64encode(s_payload.encode()).decode()
            except Exception:
                pass

        flow = Flow.from_client_config(
            cfg,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        auth_kwargs = {
            "access_type": "offline",
            "include_granted_scopes": "true",
            "prompt": "consent",
        }
        if custom_state:
            auth_kwargs["state"] = custom_state

        auth_url, state = flow.authorization_url(**auth_kwargs)
        return auth_url, state

    def exchange_code(self, code: str, redirect_uri: str, client_config: dict[str, Any] | None = None, state: str | None = None) -> tuple[bool, str]:
        """Exchange authorization code for credentials/tokens."""
        if not GOOGLE_LIBS_AVAILABLE:
            return False, "Google client libraries missing."

        cfg = None
        if client_config:
            try:
                cfg = normalize_client_config(client_config)
            except Exception as e:
                return False, f"Invalid client config: {e}"

        if not cfg and state:
            try:
                import base64
                s_payload = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
                if s_payload.get("cid") and s_payload.get("cs"):
                    cfg = normalize_client_config({
                        "web": {
                            "client_id": s_payload["cid"],
                            "client_secret": s_payload["cs"],
                        }
                    })
            except Exception as e:
                print(f"Notice: Could not extract client credentials from OAuth state: {e}")

        if not cfg:
            cred_file = resolve_storage_file("credentials.json")
            if cred_file and os.path.exists(cred_file):
                try:
                    with open(cred_file, "r", encoding="utf-8") as f:
                        raw = json.load(f)
                    cfg = normalize_client_config(raw)
                except Exception as e:
                    return False, f"Invalid credentials file: {e}"
            else:
                return False, "Credentials configuration not found."

        try:
            flow = Flow.from_client_config(
                cfg,
                scopes=SCOPES,
                redirect_uri=redirect_uri
            )
            flow.fetch_token(code=code)
            creds = flow.credentials
            try:
                with open(self.token_path, "w", encoding="utf-8") as f:
                    f.write(creds.to_json())
            except Exception:
                pass
            self.service = build("drive", "v3", credentials=creds)
            about = self.service.about().get(fields="user,storageQuota").execute()
            self.user_info = about.get("user", {})
            name = self.user_info.get("displayName", "User")
            email = self.user_info.get("emailAddress", "")
            return True, f"Successfully connected to Google Drive as {name} ({email})!"
        except Exception as e:
            return False, f"OAuth Token Exchange Error: {str(e)}"

    def authenticate(self) -> tuple[bool, str]:
        """Authenticate with Google Drive via OAuth 2.0, service account, or existing token."""
        if not GOOGLE_LIBS_AVAILABLE:
            return False, "Google client libraries are missing. Please install requirements.txt."

        if self.service:
            name = self.user_info.get("displayName", "User")
            email = self.user_info.get("emailAddress", "")
            return True, f"Connected to Google Drive as {name} ({email})"

        cred_file = resolve_storage_file("credentials.json")
        if not cred_file or not os.path.exists(cred_file):
            return False, "Credentials file 'credentials.json' not found. Upload it or use the Instant Token Connect option."

        try:
            with open(cred_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if raw.get("type") == "service_account":
                return self.authenticate_with_service_account(cred_file)
        except Exception:
            pass

        token_file = resolve_storage_file("token.json")
        if token_file and os.path.exists(token_file):
            try:
                creds = Credentials.from_authorized_user_file(token_file, SCOPES)
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                    try:
                        with open(self.token_path, "w", encoding="utf-8") as f:
                            f.write(creds.to_json())
                    except Exception:
                        pass
                if creds and creds.valid:
                    self.service = build("drive", "v3", credentials=creds)
                    about = self.service.about().get(fields="user,storageQuota").execute()
                    self.user_info = about.get("user", {})
                    return True, f"Connected to Google Drive as {self.user_info.get('displayName', 'User')} ({self.user_info.get('emailAddress', '')})"
            except Exception as e:
                print(f"Token refresh error: {e}")

        # Check client type from credentials.json
        is_web_client = False
        try:
            with open(cred_file, "r", encoding="utf-8") as f:
                c_data = json.load(f)
            if "web" in c_data:
                is_web_client = True
        except Exception:
            pass

        # If it is a Web Client, or if on Vercel/cloud serverless, trigger web OAuth flow
        if is_web_client or os.environ.get("VERCEL") == "1" or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
            return False, "OAUTH_FLOW_REQUIRED"

        # On local desktop with installed/desktop credentials, attempt local server
        try:
            flow = InstalledAppFlow.from_client_secrets_file(cred_file, SCOPES)
            creds = flow.run_local_server(port=0)
            try:
                with open(self.token_path, "w", encoding="utf-8") as token_file_out:
                    token_file_out.write(creds.to_json())
            except Exception:
                pass
            self.service = build("drive", "v3", credentials=creds)
            about = self.service.about().get(fields="user,storageQuota").execute()
            self.user_info = about.get("user", {})
            return True, f"Connected to Google Drive as {self.user_info.get('displayName', 'User')} ({self.user_info.get('emailAddress', '')})"
        except Exception as e:
            # Fall back to web OAuth flow
            return False, "OAUTH_FLOW_REQUIRED"

    def get_quota(self, files: list[dict[str, Any]] | None = None) -> dict[str, Any]:
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

    def get_quota(self, files: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Simulated 15 GB Google Drive quota."""
        limit = 15 * 1024 * 1024 * 1024  # 15 GB
        files_size = sum(f["size"] for f in (files if files is not None else self.files))
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

    def add_test_junk_file(self, name: str = "junk_test_file.txt", size: int = 209) -> dict[str, Any]:
        """Add a specific test junk file so the user can test junk detection and 1-click removal."""
        now = datetime.now(timezone.utc)
        # Check if already present and not trashed
        for f in self.files:
            if f["name"] == name:
                f["trashed"] = False
                return f

        file_id = f"cloud_file_junk_{int(now.timestamp())}"
        sha = "7a2cc089e15f0360ac1204c37f488453df952b92b04f5f6b6fdd6e499bfe735a"
        new_file = {
            "id": file_id,
            "name": name,
            "mimeType": "text/plain",
            "size": size,
            "sha256": sha,
            "createdTime": now.isoformat(),
            "modifiedTime": now.isoformat(),
            "webViewLink": f"https://drive.google.com/file/d/{file_id}/view",
            "trashed": False,
        }
        self.files.insert(0, new_file)
        return new_file

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

        # Clutter, temporary, explicit junk, and 0-byte ghost files
        clutter_files = [
            ("junk_test_file.txt", "text/plain", 209, 1),
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
            if name == "junk_test_file.txt":
                file_sha = "7a2cc089e15f0360ac1204c37f488453df952b92b04f5f6b6fdd6e499bfe735a"
            elif size > 0:
                file_sha = hashlib.sha256(f"{name}_{size}".encode()).hexdigest()
            else:
                file_sha = ""
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
