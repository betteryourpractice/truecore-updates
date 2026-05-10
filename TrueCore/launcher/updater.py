import requests
import zipfile
import os
import io
import sys
import time
import hashlib
import shutil
import tempfile
import json
from datetime import datetime, timezone

from TrueCore.launcher.launcher_logging import log
from TrueCore.utils.release_signing import (
    SIGNATURE_ALGORITHM,
    load_public_key,
    verify_manifest_signature,
)


UPDATE_URL = "https://raw.githubusercontent.com/betteryourpractice/truecore-updates/main/version.json"

ENGINE_DIR = "engine"
VERSION_FILE = "version.txt"
ENGINE_EXE = "TrueCoreEngine.exe"
SIGNING_PUBLIC_KEY_FILE = "release_signing_public.pem"
ENGINE_INTEGRITY_FILE = "install_integrity.json"


# -------------------------------------------------
# GET BASE DIRECTORY
# -------------------------------------------------

def get_base_dir():

    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.abspath(".")


def get_launcher_resource_path(*parts):

    if getattr(sys, "frozen", False):
        base_path = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        return os.path.join(base_path, "launcher", "assets", *parts)

    return os.path.join(os.path.dirname(__file__), "assets", *parts)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# -------------------------------------------------
# GET LOCAL VERSION
# -------------------------------------------------

def get_local_version():

    try:

        base_dir = get_base_dir()
        version_path = os.path.join(base_dir, ENGINE_DIR, VERSION_FILE)

        if not os.path.exists(version_path):
            log("Local version file not found.")
            return None

        with open(version_path, "r") as f:
            version = f.read().strip()

        log(f"Local engine version: {version}")

        return version

    except Exception as e:

        log(f"Failed reading local version: {e}")
        return None


# -------------------------------------------------
# SAFE REQUEST WITH RETRY
# -------------------------------------------------

def safe_request(url, timeout=10, retries=3):

    for attempt in range(retries):

        try:

            log(f"Requesting: {url} (attempt {attempt+1})")

            r = requests.get(url, timeout=timeout)

            return r

        except Exception as e:

            log(f"Request attempt {attempt+1} failed: {e}")

            if attempt < retries - 1:
                time.sleep(2)

    return None


def _result(status, **kwargs):
    return {"status": status, **kwargs}


def _coerce_zip_bytes(zip_data):

    if isinstance(zip_data, io.BytesIO):
        return zip_data.getvalue()

    if isinstance(zip_data, bytes):
        return zip_data

    raise TypeError("Unsupported update payload type.")


def _compute_sha256(payload):
    return hashlib.sha256(payload).hexdigest().lower()


def _compute_file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().lower()


def _is_safe_archive_member(member_name):

    normalized = member_name.replace("\\", "/")

    if not normalized or normalized.endswith("/"):
        return True

    if normalized.startswith("/") or normalized.startswith("../"):
        return False

    return "/../" not in normalized


def _validate_archive(zipped_update):

    infos = zipped_update.infolist()

    if not infos:
        raise ValueError("Downloaded archive is empty.")

    has_engine = False

    for info in infos:

        if not _is_safe_archive_member(info.filename):
            raise ValueError(f"Unsafe archive entry detected: {info.filename}")

        if info.filename.replace("\\", "/").endswith(ENGINE_EXE):
            has_engine = True

    if not has_engine:
        raise ValueError("Downloaded archive does not contain the engine executable.")


def _extract_archive_safely(zipped_update, destination):

    _validate_archive(zipped_update)
    destination_root = os.path.abspath(destination)

    for info in zipped_update.infolist():

        target_path = os.path.abspath(os.path.join(destination, info.filename))

        if os.path.commonpath([destination_root, target_path]) != destination_root:
            raise ValueError(f"Unsafe extraction target detected: {info.filename}")

        zipped_update.extract(info, destination)


def _verify_download_integrity(zip_bytes, expected_sha256=None, expected_size=None):

    actual_size = len(zip_bytes)

    if expected_size is not None:
        try:
            expected_size = int(expected_size)
        except (TypeError, ValueError):
            raise ValueError("Manifest size field is invalid.")

        if actual_size != expected_size:
            raise ValueError(
                f"Downloaded update size mismatch. Expected {expected_size}, got {actual_size}."
            )

    actual_sha256 = _compute_sha256(zip_bytes)

    if expected_sha256:
        if actual_sha256 != str(expected_sha256).strip().lower():
            raise ValueError("Downloaded update checksum did not match the manifest.")
        log(f"Download checksum verified: {actual_sha256}")
    else:
        log("Manifest did not provide a checksum. Proceeding in compatibility mode.")

    return actual_sha256


def _verify_manifest_authenticity(data):
    manifest = dict(data or {})
    signature = manifest.get("signature")
    signature_algorithm = str(manifest.get("signature_algorithm") or "").strip().lower()
    public_key_path = get_launcher_resource_path(SIGNING_PUBLIC_KEY_FILE)

    if not os.path.exists(public_key_path):
        log("Release signing public key not found. Proceeding in compatibility mode.")
        return _result("unsigned_compatibility", reason="missing_public_key")

    if not signature:
        log("Manifest signature not provided. Proceeding in compatibility mode.")
        return _result("unsigned_compatibility", reason="missing_signature")

    if signature_algorithm and signature_algorithm != SIGNATURE_ALGORITHM:
        raise ValueError(f"Unsupported manifest signature algorithm: {signature_algorithm}")

    public_key = load_public_key(public_key_path)
    if not verify_manifest_signature(manifest, signature, public_key):
        raise ValueError("Update manifest signature verification failed.")

    key_id = manifest.get("signature_key_id")
    log(
        "Manifest signature verified."
        + (f" Key ID: {key_id}" if key_id else "")
    )
    return _result("verified", key_id=key_id)


def _write_engine_integrity_metadata(engine_dir_path, *, version=None, engine_sha256=None, manifest_authentication=None):
    metadata_path = os.path.join(engine_dir_path, ENGINE_INTEGRITY_FILE)
    manifest_authentication = dict(manifest_authentication or {})
    payload = {
        "schema_version": "1.0",
        "recorded_at": utc_now_iso(),
        "engine_executable": ENGINE_EXE,
        "version": version,
        "engine_sha256": engine_sha256,
        "manifest_authentication": {
            "status": manifest_authentication.get("status"),
            "key_id": manifest_authentication.get("key_id"),
        },
    }

    with open(metadata_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4, ensure_ascii=True, sort_keys=True)

    return metadata_path


def verify_installed_engine_integrity(base_dir=None):
    base_dir = base_dir or get_base_dir()
    engine_dir_path = os.path.join(base_dir, ENGINE_DIR)
    engine_path = os.path.join(engine_dir_path, ENGINE_EXE)
    metadata_path = os.path.join(engine_dir_path, ENGINE_INTEGRITY_FILE)

    if not os.path.exists(engine_path):
        return _result("missing_engine")

    if not os.path.exists(metadata_path):
        return _result("compatibility_mode", reason="missing_integrity_metadata")

    try:
        with open(metadata_path, "r", encoding="utf-8") as handle:
            metadata = json.load(handle)
    except Exception as exc:
        log(f"Engine integrity metadata could not be read: {exc}")
        return _result("compatibility_mode", reason="invalid_integrity_metadata")

    expected_sha256 = str(metadata.get("engine_sha256") or "").strip().lower()
    if not expected_sha256:
        return _result("compatibility_mode", reason="missing_engine_sha256")

    actual_sha256 = _compute_file_sha256(engine_path)

    if actual_sha256 != expected_sha256:
        log("Installed engine integrity verification failed.")
        return _result(
            "tampered",
            expected_sha256=expected_sha256,
            actual_sha256=actual_sha256,
            version=metadata.get("version"),
        )

    return _result(
        "verified",
        version=metadata.get("version"),
        engine_sha256=actual_sha256,
        manifest_authentication=metadata.get("manifest_authentication"),
    )


# -------------------------------------------------
# CHECK FOR UPDATES
# -------------------------------------------------

def check_updates():

    try:

        log("Checking update server...")

        r = safe_request(UPDATE_URL, timeout=10, retries=3)

        if r is None:
            log("Update server request failed after retries.")
            return _result("error", message="Update server request failed after retries.")

        if r.status_code != 200:
            log(f"Update server returned status {r.status_code}")
            return _result("error", message=f"Update server returned status {r.status_code}.")

        data = r.json()
        manifest_auth = _verify_manifest_authenticity(data)

        server_version = data.get("version")

        if not server_version:
            log("Invalid version.json: missing version field.")
            return _result("error", message="Invalid update manifest: missing version.")

        local_version = get_local_version()

        log(f"Server version: {server_version}")
        log(f"Local version: {local_version}")

        if local_version == server_version:
            log("Engine already up to date.")
            return _result(
                "up_to_date",
                version=server_version,
                local_version=local_version,
                manifest_authentication=manifest_auth,
            )

        if not data.get("download"):
            log("Invalid version.json: missing download field.")
            return _result("error", message="Invalid update manifest: missing download URL.")

        log("Update available.")

        return _result(
            "update_available",
            version=server_version,
            local_version=local_version,
            download=data.get("download"),
            sha256=data.get("sha256"),
            size=data.get("size"),
            manifest_authentication=manifest_auth,
        )

    except Exception as e:

        log(f"Update check failed: {e}")
        return _result("error", message=str(e))


# -------------------------------------------------
# DOWNLOAD UPDATE
# -------------------------------------------------

def download_update(download_url):

    try:

        log("Downloading update...")

        r = safe_request(download_url, timeout=30, retries=3)

        if r is None:
            log("Download request failed after retries.")
            return None

        if r.status_code != 200:
            log(f"Download returned status {r.status_code}")
            return None

        log("Download completed.")

        return io.BytesIO(r.content)

    except Exception as e:

        log(f"Download failed: {e}")
        return None


# -------------------------------------------------
# INSTALL UPDATE
# -------------------------------------------------

def install_update(zip_data, version=None, expected_sha256=None, expected_size=None, manifest_authentication=None):

    try:

        log("Installing update...")

        zip_bytes = _coerce_zip_bytes(zip_data)
        _verify_download_integrity(
            zip_bytes,
            expected_sha256=expected_sha256,
            expected_size=expected_size,
        )

        base_dir = get_base_dir()

        engine_path = os.path.join(base_dir, ENGINE_DIR)
        backup_path = os.path.join(base_dir, f"{ENGINE_DIR}_backup")
        temp_root = tempfile.mkdtemp(prefix="truecore_update_", dir=base_dir)
        staged_engine_path = os.path.join(temp_root, ENGINE_DIR)

        os.makedirs(staged_engine_path, exist_ok=True)

        # -------------------------------------------------
        # EXTRACT UPDATE
        # -------------------------------------------------

        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:

            _extract_archive_safely(z, staged_engine_path)

        staged_engine_exe = os.path.join(staged_engine_path, ENGINE_EXE)

        if not os.path.exists(staged_engine_exe):
            raise FileNotFoundError("Updated engine executable missing after extraction.")

        log("Engine extracted")
        engine_sha256 = _compute_file_sha256(staged_engine_exe)

        # -------------------------------------------------
        # SAVE INSTALLED VERSION
        # -------------------------------------------------

        if version:

            version_file = os.path.join(staged_engine_path, VERSION_FILE)

            try:

                with open(version_file, "w") as f:
                    f.write(version)

                log(f"Saved version file: {version}")

            except Exception as e:

                log(f"Failed writing version file: {e}")

        _write_engine_integrity_metadata(
            staged_engine_path,
            version=version,
            engine_sha256=engine_sha256,
            manifest_authentication=manifest_authentication,
        )

        if os.path.exists(backup_path):
            shutil.rmtree(backup_path, ignore_errors=True)

        if os.path.exists(engine_path):
            shutil.move(engine_path, backup_path)
            log("Moved previous engine install to backup")

        try:
            shutil.move(staged_engine_path, engine_path)
        except Exception:
            if os.path.exists(engine_path):
                shutil.rmtree(engine_path, ignore_errors=True)
            if os.path.exists(backup_path):
                shutil.move(backup_path, engine_path)
                log("Restored previous engine install after failed update")
            raise

        if os.path.exists(backup_path):
            shutil.rmtree(backup_path, ignore_errors=True)

        log("Update installed successfully")

        return True

    except Exception as e:

        log(f"Update install failed: {e}")

        return False

    finally:
        temp_root = locals().get("temp_root")
        if temp_root and os.path.exists(temp_root):
            shutil.rmtree(temp_root, ignore_errors=True)
