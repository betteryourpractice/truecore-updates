from __future__ import annotations

import json
import os
import sys
import subprocess
import tempfile
from datetime import datetime, timezone
from urllib.parse import quote

from TrueCore.core.office_rollout import load_office_profile
from TrueCore.launcher.launcher_logging import LOG_FILE
from TrueCore.launcher.updater import (
    PRODUCTION_UPDATE_URL,
    get_local_version,
    verify_installed_engine_integrity,
)
from TrueCore.utils.install_mode import (
    get_primary_update_channel,
    get_reference_update_channel,
    load_install_profile,
    normalize_install_profile,
)
from TrueCore.utils.private_dev_channel import (
    get_private_dev_repo_slug,
    is_private_dev_channel_enabled,
    load_private_dev_channel_config,
)
from TrueCore.utils.runtime_info import get_build_info, get_version, runtime_data_path


LAUNCHER_RELEASE_INFO_FILENAME = "launcher_release_info.json"
DEFAULT_IT_EMAIL = "aaron@betteryourpractice.com"
LAUNCHER_SUPPORT_CONFIG_PATH = runtime_data_path("dev_system", "launcher_support.json")


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def get_launcher_asset_path(*parts):
    if getattr(sys, "frozen", False):
        base_path = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        return os.path.join(base_path, "launcher", "assets", *parts)

    return os.path.join(os.path.dirname(__file__), "assets", *parts)


def load_launcher_release_info():
    path = get_launcher_asset_path(LAUNCHER_RELEASE_INFO_FILENAME)

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = dict(json.load(handle) or {})
                return {
                    "version": str(payload.get("version") or get_version() or "unknown"),
                    "build_id": payload.get("build_id"),
                    "build_timestamp": payload.get("build_timestamp"),
                    "release_channel": payload.get("release_channel") or PRODUCTION_UPDATE_URL,
                    "update_channel": str(payload.get("update_channel") or "production").strip().lower() or "production",
                }
        except Exception:
            pass

    build_id, build_timestamp = get_build_info()
    return {
        "version": get_version() or "unknown",
        "build_id": build_id,
        "build_timestamp": build_timestamp,
        "release_channel": PRODUCTION_UPDATE_URL,
        "update_channel": "production",
    }


def apply_launcher_release_profile(install_profile=None, release_info=None):
    payload = normalize_install_profile(install_profile or load_install_profile())
    release_payload = dict(release_info or load_launcher_release_info() or {})
    embedded_channel = str(release_payload.get("update_channel") or "").strip().lower()

    if embedded_channel == "dev":
        payload["machine_role"] = "dev"
        payload["update_channel"] = "dev"
        payload["show_production_reference"] = True
        payload["developer_tools_enabled"] = True
    else:
        payload["machine_role"] = "office"
        payload["update_channel"] = "production"
        payload["show_production_reference"] = False
        payload["developer_tools_enabled"] = False

    return payload


def ensure_launcher_support_config():
    os.makedirs(os.path.dirname(LAUNCHER_SUPPORT_CONFIG_PATH), exist_ok=True)
    if os.path.exists(LAUNCHER_SUPPORT_CONFIG_PATH):
        return LAUNCHER_SUPPORT_CONFIG_PATH

    with open(LAUNCHER_SUPPORT_CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump({"it_email": DEFAULT_IT_EMAIL}, handle, indent=4)

    return LAUNCHER_SUPPORT_CONFIG_PATH


def resolve_it_email():
    ensure_launcher_support_config()

    try:
        with open(LAUNCHER_SUPPORT_CONFIG_PATH, "r", encoding="utf-8") as handle:
            payload = dict(json.load(handle) or {})
    except Exception:
        payload = {}

    return str(payload.get("it_email") or DEFAULT_IT_EMAIL).strip() or DEFAULT_IT_EMAIL


def get_launcher_support_request_dir():
    return runtime_data_path("Outputs", "launcher_support_requests")


def _request_label(request_type):
    normalized = str(request_type or "support_request").strip().lower()
    return {
        "forgot_username": "Forgot Username",
        "forgot_password": "Forgot Password",
        "launcher_support": "Launcher Support",
    }.get(normalized, "Launcher Support")


def _safe_update_state(update_state):
    payload = dict(update_state or {})
    return {
        "phase": payload.get("phase"),
        "status": payload.get("status"),
        "server_version": payload.get("server_version"),
        "local_version": payload.get("local_version"),
        "local_version_before": payload.get("local_version_before"),
        "local_version_after": payload.get("local_version_after"),
        "message": payload.get("message"),
        "manifest_authentication": dict(payload.get("manifest_authentication") or {}),
        "integrity_status": dict(payload.get("integrity") or {}).get("status"),
    }


def build_launcher_support_snapshot(request_type, update_state=None):
    request_key = str(request_type or "launcher_support").strip().lower() or "launcher_support"
    release_info = dict(load_launcher_release_info() or {})
    office_profile = dict(load_office_profile() or {})
    install_profile = dict(apply_launcher_release_profile(release_info=release_info) or {})
    private_dev_channel = dict(load_private_dev_channel_config() or {})
    integrity = dict(verify_installed_engine_integrity() or {})
    generated_at = utc_now_iso()
    output_dir = get_launcher_support_request_dir()
    os.makedirs(output_dir, exist_ok=True)

    timestamp_key = generated_at.replace(":", "").replace("-", "")
    output_path = os.path.join(output_dir, f"truecore_{request_key}_{timestamp_key}.json")

    payload = {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "request_type": request_key,
        "request_label": _request_label(request_key),
        "office": {
            "organization_id": office_profile.get("organization_id"),
            "office_id": office_profile.get("office_id"),
            "office_name": office_profile.get("office_name"),
            "install_id": office_profile.get("install_id"),
        },
        "install_profile": {
            "machine_role": install_profile.get("machine_role"),
            "primary_update_channel": get_primary_update_channel(install_profile),
            "reference_update_channel": get_reference_update_channel(install_profile),
            "developer_tools_enabled": bool(install_profile.get("developer_tools_enabled")),
            "private_dev_repo_enabled": is_private_dev_channel_enabled(private_dev_channel),
            "private_dev_repo": get_private_dev_repo_slug(private_dev_channel),
        },
        "launcher": {
            "version": release_info.get("version"),
            "build_id": release_info.get("build_id"),
            "build_timestamp": release_info.get("build_timestamp"),
            "log_file": LOG_FILE,
            "release_channel": release_info.get("release_channel"),
        },
        "engine": {
            "installed_version": get_local_version(),
            "integrity_status": integrity.get("status"),
            "integrity_version": integrity.get("version"),
        },
        "update_state": _safe_update_state(update_state),
    }

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4, ensure_ascii=True, sort_keys=True)

    return output_path, payload


def build_support_mailto_url(request_type, snapshot_path, payload, recipient=None):
    recipient = str(recipient or resolve_it_email()).strip() or DEFAULT_IT_EMAIL
    request_label = _request_label(request_type)
    office = dict((payload or {}).get("office") or {})
    launcher = dict((payload or {}).get("launcher") or {})
    engine = dict((payload or {}).get("engine") or {})
    install_profile = dict((payload or {}).get("install_profile") or {})
    update_state = dict((payload or {}).get("update_state") or {})

    subject = f"TrueCore {request_label} Request - {office.get('office_name') or 'Unknown Office'}"
    body_lines = [
        f"Request Type: {request_label}",
        f"Office: {office.get('office_name') or 'Unknown'}",
        f"Office ID: {office.get('office_id') or 'Unknown'}",
        f"Install ID: {office.get('install_id') or 'Unknown'}",
        f"Machine Role: {install_profile.get('machine_role') or 'Unknown'}",
        f"Primary Update Channel: {install_profile.get('primary_update_channel') or 'Unknown'}",
        "",
        f"Launcher Version: {launcher.get('version') or 'Unknown'}",
        f"Launcher Build ID: {launcher.get('build_id') or 'Unknown'}",
        f"Program Version: {engine.get('installed_version') or 'Unknown'}",
        f"Program Integrity Status: {engine.get('integrity_status') or 'Unknown'}",
    ]

    if update_state.get("server_version"):
        body_lines.append(f"Server Program Version: {update_state.get('server_version')}")
    if update_state.get("status"):
        body_lines.append(f"Launcher Update Status: {update_state.get('status')}")

    body_lines.extend(
        [
            "",
            f"Support Snapshot: {snapshot_path}",
            "",
            "Please review this launcher/program access request and advise the office on next steps.",
        ]
    )

    return f"mailto:{quote(recipient)}?subject={quote(subject)}&body={quote(os.linesep.join(body_lines))}"


def probe_engine_runtime_identity(engine_command, *, timeout_seconds=20):
    output_fd, output_path = tempfile.mkstemp(
        prefix="truecore_runtime_probe_",
        suffix=".json",
        dir=runtime_data_path("Outputs"),
    )
    os.close(output_fd)

    try:
        env = dict(os.environ)
        env["TRUECORE_RUNTIME_DIAGNOSTIC"] = "1"
        env["TRUECORE_RUNTIME_DIAGNOSTIC_FILE"] = output_path

        popen_kwargs = {
            "env": env,
            "timeout": timeout_seconds,
            "check": False,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        command = engine_command if isinstance(engine_command, list) else [engine_command]
        result = subprocess.run(command, **popen_kwargs)

        if not os.path.exists(output_path):
            return {"status": "probe_failed", "returncode": result.returncode}

        with open(output_path, "r", encoding="utf-8") as handle:
            payload = dict(json.load(handle) or {})

        return {
            "status": "ok",
            "returncode": result.returncode,
            "payload": payload,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
    finally:
        try:
            if os.path.exists(output_path):
                os.remove(output_path)
        except Exception:
            pass


def validate_engine_lane(engine_command, *, release_info=None):
    release_payload = dict(release_info or load_launcher_release_info() or {})
    expected_channel = str(release_payload.get("update_channel") or "production").strip().lower() or "production"
    expected_role = "dev" if expected_channel == "dev" else "office"

    probe = probe_engine_runtime_identity(engine_command)
    if probe.get("status") != "ok":
        return {
            "status": "probe_failed",
            "expected_role": expected_role,
            "probe": probe,
        }

    payload = dict(probe.get("payload") or {})
    actual_role = str(payload.get("machine_role") or "").strip().lower()
    developer_tools_enabled = bool(payload.get("developer_tools_enabled"))
    version = str(payload.get("version") or "").strip()

    if actual_role != expected_role:
        return {
            "status": "lane_mismatch",
            "expected_role": expected_role,
            "actual_role": actual_role,
            "developer_tools_enabled": developer_tools_enabled,
            "version": version,
            "probe": probe,
        }

    if expected_role == "dev" and not developer_tools_enabled:
        return {
            "status": "lane_mismatch",
            "expected_role": expected_role,
            "actual_role": actual_role,
            "developer_tools_enabled": developer_tools_enabled,
            "version": version,
            "probe": probe,
        }

    if expected_role == "dev" and not version.lower().startswith("dv"):
        return {
            "status": "lane_mismatch",
            "expected_role": expected_role,
            "actual_role": actual_role,
            "developer_tools_enabled": developer_tools_enabled,
            "version": version,
            "probe": probe,
        }

    if expected_role == "office" and version.lower().startswith("dv"):
        return {
            "status": "lane_mismatch",
            "expected_role": expected_role,
            "actual_role": actual_role,
            "developer_tools_enabled": developer_tools_enabled,
            "version": version,
            "probe": probe,
        }

    return {
        "status": "verified",
        "expected_role": expected_role,
        "actual_role": actual_role,
        "developer_tools_enabled": developer_tools_enabled,
        "version": version,
        "probe": probe,
    }


def validate_engine_bundle_lane(*, release_info=None, integrity_result=None):
    release_payload = dict(release_info or load_launcher_release_info() or {})
    expected_channel = str(release_payload.get("update_channel") or "production").strip().lower() or "production"
    expected_role = "dev" if expected_channel == "dev" else "office"
    expected_engine_name = "TrueCoreEngine_DEV.exe" if expected_role == "dev" else "TrueCoreEngine_OFFICE.exe"
    local_version = str(get_local_version() or "").strip()

    integrity = dict(integrity_result or verify_installed_engine_integrity() or {})
    if integrity.get("status") == "tampered":
        return {
            "status": "tampered",
            "expected_role": expected_role,
            "version": local_version,
        }

    metadata = dict(integrity.get("manifest_authentication") or {})
    engine_version = str(integrity.get("version") or local_version or "").strip()

    if expected_role == "dev":
        version_ok = engine_version.lower().startswith("dv")
        executable_ok = expected_engine_name.lower().endswith("_dev.exe")
    else:
        version_ok = bool(engine_version) and not engine_version.lower().startswith("dv")
        executable_ok = expected_engine_name.lower().endswith("_office.exe")

    if not version_ok or not executable_ok:
        return {
            "status": "lane_mismatch",
            "expected_role": expected_role,
            "version": engine_version or local_version,
            "engine_executable": expected_engine_name,
            "manifest_authentication": metadata,
        }

    return {
        "status": "verified",
        "expected_role": expected_role,
        "version": engine_version or local_version,
        "engine_executable": expected_engine_name,
        "manifest_authentication": metadata,
    }
