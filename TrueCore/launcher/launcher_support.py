from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import quote

from TrueCore.core.office_rollout import load_office_profile
from TrueCore.launcher.launcher_logging import LOG_FILE
from TrueCore.launcher.updater import UPDATE_URL, get_local_version, verify_installed_engine_integrity
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
                    "release_channel": payload.get("release_channel") or UPDATE_URL,
                }
        except Exception:
            pass

    build_id, build_timestamp = get_build_info()
    return {
        "version": get_version() or "unknown",
        "build_id": build_id,
        "build_timestamp": build_timestamp,
        "release_channel": UPDATE_URL,
    }


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
    update_state = dict((payload or {}).get("update_state") or {})

    subject = f"TrueCore {request_label} Request - {office.get('office_name') or 'Unknown Office'}"
    body_lines = [
        f"Request Type: {request_label}",
        f"Office: {office.get('office_name') or 'Unknown'}",
        f"Office ID: {office.get('office_id') or 'Unknown'}",
        f"Install ID: {office.get('install_id') or 'Unknown'}",
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
