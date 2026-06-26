from __future__ import annotations

import json
import os
from copy import deepcopy

from TrueCore.utils.runtime_info import office_runtime_data_path


INSTALL_PROFILE_PATH = office_runtime_data_path("install_profile.json")

PRODUCTION_CHANNEL = "production"
DEV_CHANNEL = "dev"

DEFAULT_INSTALL_PROFILE = {
    "version": 1,
    "machine_role": "office",
    "update_channel": PRODUCTION_CHANNEL,
    "show_production_reference": False,
    "developer_tools_enabled": False,
}


def _deep_merge(base, updates):
    merged = deepcopy(base)
    for key, value in dict(updates or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged.get(key) or {}, value)
        else:
            merged[key] = value
    return merged


def _normalized_text(value, fallback=""):
    return str(value or fallback).strip() or fallback


def normalize_machine_role(value):
    normalized = _normalized_text(value, DEFAULT_INSTALL_PROFILE["machine_role"]).lower()
    return "dev" if normalized == "dev" else "office"


def normalize_update_channel(value, machine_role):
    normalized = _normalized_text(value).lower()
    if normalized not in {PRODUCTION_CHANNEL, DEV_CHANNEL}:
        return DEV_CHANNEL if machine_role == "dev" else PRODUCTION_CHANNEL
    return normalized


def normalize_install_profile(data):
    source = dict(data or {})
    payload = _deep_merge(DEFAULT_INSTALL_PROFILE, source)
    machine_role = normalize_machine_role(payload.get("machine_role"))
    update_channel_seed = source.get("update_channel") if "update_channel" in source else None
    update_channel = normalize_update_channel(update_channel_seed, machine_role)

    payload["version"] = int(payload.get("version") or DEFAULT_INSTALL_PROFILE["version"])
    payload["machine_role"] = machine_role
    payload["update_channel"] = update_channel
    show_reference_seed = source.get("show_production_reference") if "show_production_reference" in source else (machine_role == "dev")
    developer_tools_seed = source.get("developer_tools_enabled") if "developer_tools_enabled" in source else (machine_role == "dev")
    payload["show_production_reference"] = bool(show_reference_seed)
    payload["developer_tools_enabled"] = bool(developer_tools_seed)
    return payload


def ensure_install_profile():
    os.makedirs(os.path.dirname(INSTALL_PROFILE_PATH), exist_ok=True)
    if os.path.exists(INSTALL_PROFILE_PATH):
        return INSTALL_PROFILE_PATH

    save_install_profile({})
    return INSTALL_PROFILE_PATH


def load_install_profile():
    ensure_install_profile()
    try:
        with open(INSTALL_PROFILE_PATH, "r", encoding="utf-8") as handle:
            return normalize_install_profile(json.load(handle))
    except Exception:
        return normalize_install_profile({})


def save_install_profile(data):
    payload = normalize_install_profile(data)
    os.makedirs(os.path.dirname(INSTALL_PROFILE_PATH), exist_ok=True)
    with open(INSTALL_PROFILE_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4)
    return payload


def update_install_profile(changes):
    current = load_install_profile()
    payload = _deep_merge(current, dict(changes or {}))
    return save_install_profile(payload)


def is_dev_install(profile=None):
    return normalize_install_profile(profile or load_install_profile()).get("machine_role") == "dev"


def get_primary_update_channel(profile=None):
    return normalize_install_profile(profile or load_install_profile()).get("update_channel") or PRODUCTION_CHANNEL


def get_reference_update_channel(profile=None):
    payload = normalize_install_profile(profile or load_install_profile())
    if payload.get("machine_role") == "dev" and payload.get("show_production_reference"):
        primary = payload.get("update_channel") or DEV_CHANNEL
        return PRODUCTION_CHANNEL if primary != PRODUCTION_CHANNEL else None
    return None
