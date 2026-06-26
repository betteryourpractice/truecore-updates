from __future__ import annotations

import json
import os
import uuid
from copy import deepcopy
from datetime import datetime, timezone

from TrueCore.utils.admin_auth import admin_auth_uses_default_password, load_admin_auth_config
from TrueCore.utils.launcher_auth import (
    launcher_auth_uses_default_credentials,
    load_launcher_auth_config,
    normalize_launcher_username,
)
from TrueCore.utils.runtime_info import office_runtime_data_path


OFFICE_PROFILE_PATH = office_runtime_data_path("office_profile.json")

DEFAULT_OFFICE_PROFILE = {
    "version": 2,
    "organization_id": "organization-pending",
    "office_id": "office-pending",
    "office_name": "Office Setup Required",
    "install_id": None,
    "created_at": None,
    "deidentification_salt": None,
    "rollout_tier": "single_office",
    "support_contact_email": "",
    "support_contact_name": "",
    "onboarding": {
        "docs_kit_exported_at": None,
        "office_profile_confirmed_at": None,
        "first_packet_analyzed_at": None,
        "first_real_outcome_at": None,
        "notes": "",
    },
    "credential_policy": {
        "mode": "local_install_shared",
        "username_hint": None,
        "per_office_ready": True,
        "future_plan": "per_office_credentials",
    },
}


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _generate_hex_token(length=32):
    return uuid.uuid4().hex[:length]


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


def _normalize_onboarding(payload):
    base = dict(DEFAULT_OFFICE_PROFILE["onboarding"])
    base.update(dict(payload or {}))
    return {
        "docs_kit_exported_at": _normalized_text(base.get("docs_kit_exported_at")) or None,
        "office_profile_confirmed_at": _normalized_text(base.get("office_profile_confirmed_at")) or None,
        "first_packet_analyzed_at": _normalized_text(base.get("first_packet_analyzed_at")) or None,
        "first_real_outcome_at": _normalized_text(base.get("first_real_outcome_at")) or None,
        "notes": _normalized_text(base.get("notes")),
    }


def _normalize_credential_policy(payload):
    base = dict(DEFAULT_OFFICE_PROFILE["credential_policy"])
    base.update(dict(payload or {}))
    username_hint = normalize_launcher_username(base.get("username_hint"))
    if not username_hint:
        launcher_auth = load_launcher_auth_config()
        username_hint = normalize_launcher_username(launcher_auth.get("username"))
    return {
        "mode": _normalized_text(base.get("mode"), DEFAULT_OFFICE_PROFILE["credential_policy"]["mode"]).lower(),
        "username_hint": username_hint or None,
        "per_office_ready": bool(base.get("per_office_ready", True)),
        "future_plan": _normalized_text(
            base.get("future_plan"),
            DEFAULT_OFFICE_PROFILE["credential_policy"]["future_plan"],
        ),
    }


def normalize_office_profile(data):
    payload = _deep_merge(DEFAULT_OFFICE_PROFILE, dict(data or {}))
    if str(payload.get("organization_id") or "").strip().lower() == "truecore-local":
        payload["organization_id"] = DEFAULT_OFFICE_PROFILE["organization_id"]
    if str(payload.get("office_id") or "").strip().lower() == "office-default":
        payload["office_id"] = DEFAULT_OFFICE_PROFILE["office_id"]
    if str(payload.get("office_name") or "").strip().lower() == "default office":
        payload["office_name"] = DEFAULT_OFFICE_PROFILE["office_name"]
    payload["version"] = int(payload.get("version") or DEFAULT_OFFICE_PROFILE["version"])
    payload["organization_id"] = _normalized_text(
        payload.get("organization_id"),
        DEFAULT_OFFICE_PROFILE["organization_id"],
    )
    payload["office_id"] = _normalized_text(
        payload.get("office_id"),
        DEFAULT_OFFICE_PROFILE["office_id"],
    )
    payload["office_name"] = _normalized_text(
        payload.get("office_name"),
        DEFAULT_OFFICE_PROFILE["office_name"],
    )
    payload["install_id"] = _normalized_text(payload.get("install_id"), _generate_hex_token()).lower()
    payload["created_at"] = _normalized_text(payload.get("created_at"), utc_now_iso())
    payload["deidentification_salt"] = _normalized_text(
        payload.get("deidentification_salt"),
        _generate_hex_token(32),
    ).lower()
    payload["rollout_tier"] = _normalized_text(
        payload.get("rollout_tier"),
        DEFAULT_OFFICE_PROFILE["rollout_tier"],
    ).lower()
    payload["support_contact_email"] = _normalized_text(payload.get("support_contact_email"))
    payload["support_contact_name"] = _normalized_text(payload.get("support_contact_name"))
    payload["onboarding"] = _normalize_onboarding(payload.get("onboarding"))
    payload["credential_policy"] = _normalize_credential_policy(payload.get("credential_policy"))
    return payload


def office_identity_is_configured(profile=None):
    payload = normalize_office_profile(profile or load_office_profile())
    return any(
        payload.get(key) != DEFAULT_OFFICE_PROFILE.get(key)
        for key in ("organization_id", "office_id", "office_name")
    )


def office_setup_is_required(profile=None, launcher_auth=None, admin_auth=None):
    payload = normalize_office_profile(profile or load_office_profile())
    onboarding = dict(payload.get("onboarding") or {})

    identity_ready = office_identity_is_configured(payload) and bool(onboarding.get("office_profile_confirmed_at"))
    launcher_ready = not launcher_auth_uses_default_credentials(launcher_auth or load_launcher_auth_config())
    manager_ready = not admin_auth_uses_default_password(admin_auth or load_admin_auth_config())

    return not (identity_ready and launcher_ready and manager_ready)


def ensure_office_profile():
    os.makedirs(os.path.dirname(OFFICE_PROFILE_PATH), exist_ok=True)
    if os.path.exists(OFFICE_PROFILE_PATH):
        return OFFICE_PROFILE_PATH

    save_office_profile({})
    return OFFICE_PROFILE_PATH


def load_office_profile():
    ensure_office_profile()
    try:
        with open(OFFICE_PROFILE_PATH, "r", encoding="utf-8") as handle:
            return normalize_office_profile(json.load(handle))
    except Exception:
        return normalize_office_profile({})


def save_office_profile(data):
    payload = normalize_office_profile(data)
    os.makedirs(os.path.dirname(OFFICE_PROFILE_PATH), exist_ok=True)
    with open(OFFICE_PROFILE_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4)
    return payload


def update_office_profile(changes):
    current = load_office_profile()
    payload = _deep_merge(current, dict(changes or {}))
    return save_office_profile(payload)


def record_docs_kit_exported():
    profile = load_office_profile()
    onboarding = dict(profile.get("onboarding") or {})
    if not onboarding.get("docs_kit_exported_at"):
        onboarding["docs_kit_exported_at"] = utc_now_iso()
    return update_office_profile({"onboarding": onboarding})


def record_office_profile_confirmed():
    profile = load_office_profile()
    onboarding = dict(profile.get("onboarding") or {})
    onboarding["office_profile_confirmed_at"] = utc_now_iso()
    return update_office_profile({"onboarding": onboarding})


def record_packet_analyzed():
    profile = load_office_profile()
    onboarding = dict(profile.get("onboarding") or {})
    if not onboarding.get("first_packet_analyzed_at"):
        onboarding["first_packet_analyzed_at"] = utc_now_iso()
    return update_office_profile({"onboarding": onboarding})


def record_real_outcome():
    profile = load_office_profile()
    onboarding = dict(profile.get("onboarding") or {})
    if not onboarding.get("first_real_outcome_at"):
        onboarding["first_real_outcome_at"] = utc_now_iso()
    return update_office_profile({"onboarding": onboarding})


def build_rollout_summary(profile=None, *, packet_count=0, outcome_count=0, imported_snapshot_count=0):
    profile = normalize_office_profile(profile or load_office_profile())
    onboarding = dict(profile.get("onboarding") or {})
    credential_policy = dict(profile.get("credential_policy") or {})
    launcher_auth = load_launcher_auth_config()
    admin_auth = load_admin_auth_config()

    office_identity_configured = office_identity_is_configured(profile) and bool(onboarding.get("office_profile_confirmed_at"))
    docs_exported = bool(onboarding.get("docs_kit_exported_at"))
    first_packet = bool(onboarding.get("first_packet_analyzed_at")) or int(packet_count or 0) > 0
    first_outcome = bool(onboarding.get("first_real_outcome_at")) or int(outcome_count or 0) > 0
    credential_ready = not launcher_auth_uses_default_credentials(launcher_auth)
    manager_password_ready = not admin_auth_uses_default_password(admin_auth)

    checklist = [
        {
            "key": "docs_kit_exported",
            "label": "Onboarding kit exported",
            "complete": docs_exported,
            "detail": onboarding.get("docs_kit_exported_at"),
        },
        {
            "key": "office_identity_configured",
            "label": "Office identity customized",
            "complete": office_identity_configured,
            "detail": onboarding.get("office_profile_confirmed_at") or profile.get("office_name"),
        },
        {
            "key": "launcher_credentials_ready",
            "label": "Launcher credential profile defined",
            "complete": credential_ready,
            "detail": credential_policy.get("username_hint"),
        },
        {
            "key": "office_manager_password_ready",
            "label": "Office manager password defined",
            "complete": manager_password_ready,
            "detail": "Configured" if manager_password_ready else "Still using the packaged default",
        },
        {
            "key": "first_packet_analyzed",
            "label": "First packet analyzed",
            "complete": first_packet,
            "detail": onboarding.get("first_packet_analyzed_at") or packet_count,
        },
        {
            "key": "first_real_outcome_recorded",
            "label": "First real outcome recorded",
            "complete": first_outcome,
            "detail": onboarding.get("first_real_outcome_at") or outcome_count,
        },
    ]

    completed = sum(1 for item in checklist if item["complete"])
    total = len(checklist)
    score = round(completed / max(total, 1), 2)

    if completed <= 1:
        band = "starter"
    elif completed <= 3:
        band = "onboarding"
    elif completed == 4:
        band = "operational"
    else:
        band = "established"

    actions = []
    if not docs_exported:
        actions.append("Export the onboarding kit from the launcher so the office has the official packet-building documents.")
    if not office_identity_configured:
        actions.append("Replace the default office identity with the real organization and office names before broader rollout.")
    if not credential_ready:
        actions.append("Define the launcher username policy for this office so credentials are not just generic local defaults.")
    if not manager_password_ready:
        actions.append("Set a unique office manager password before staff start using the install operationally.")
    if not first_packet:
        actions.append("Analyze a real packet on this install to complete the first operational onboarding milestone.")
    if not first_outcome:
        actions.append("Record at least one real packet outcome so the local learning loop begins with actual feedback.")
    if imported_snapshot_count and band != "starter":
        actions.append("Cross-office data is available; use it to compare this office against the broader network.")

    return {
        "band": band,
        "score": score,
        "completed_steps": completed,
        "total_steps": total,
        "checklist": checklist,
        "credential_policy": credential_policy,
        "recommended_actions": actions,
        "office_identity_configured": office_identity_configured,
        "launcher_credentials_ready": credential_ready,
        "office_manager_password_ready": manager_password_ready,
        "docs_kit_exported": docs_exported,
        "first_packet_analyzed": first_packet,
        "first_real_outcome_recorded": first_outcome,
        "setup_required": office_setup_is_required(profile, launcher_auth=launcher_auth, admin_auth=admin_auth),
    }
