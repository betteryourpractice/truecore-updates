import json
import os
import platform
import sys
import hashlib
from datetime import datetime, timezone

from TrueCore.core.case_memory import get_recent_packet_events, get_recent_packet_runs, memory_totals
from TrueCore.core.cross_office_benchmarking import list_imported_snapshot_files, load_network_rollup
from TrueCore.core.cross_office_learning import SNAPSHOT_OUTPUT_PATH, load_office_profile
from TrueCore.core.hybrid_sync import (
    ACTIVE_NETWORK_INTELLIGENCE_PACKAGE_PATH,
    OFFICE_SYNC_PACKAGE_PATH,
    load_active_network_intelligence_package,
)
from TrueCore.core.office_rollout import build_rollout_summary
from TrueCore.core.outcome_learning_intelligence import build_predictive_learning_snapshot
from TrueCore.launcher.updater import UPDATE_URL
from TrueCore.utils.runtime_info import (
    get_build_info,
    get_release_manifest,
    get_runtime_project_dir,
    get_runtime_root,
    get_version,
    office_runtime_data_path,
    runtime_data_path,
)


DEPLOYMENT_MANIFEST_PATH = office_runtime_data_path("deployment_manifest.json")
SUPPORT_BUNDLE_OUTPUT_PATH = runtime_data_path("Outputs", "truecore_support_bundle.json")


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _json_dump(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4, ensure_ascii=True, sort_keys=True)
    return path


def _canonical_json_bytes(payload):
    return json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("utf-8")


def _safe_summary(value):
    if isinstance(value, dict):
        return dict(value)
    return {}


def _normalize_status(value, positive_labels):
    return "ready" if value in positive_labels else "pending"


def _hash_token(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _redact_file_reference(file_name):
    base_name = os.path.basename(str(file_name or "").strip())
    if not base_name:
        return None
    _, extension = os.path.splitext(base_name)
    extension = extension.lower() or ".file"
    digest = _hash_token(base_name)
    return f"{extension}:{digest}"


def _build_platform_readiness(office_profile, release_manifest, predictive_summary, imported_snapshot_count, network_rollup, active_network_package):
    score = 0.28

    if office_profile.get("install_id") and office_profile.get("office_id"):
        score += 0.18
    if release_manifest or (predictive_summary.get("model_summary") or {}).get("available") is not None:
        score += 0.16
    if imported_snapshot_count:
        score += 0.1
    if network_rollup:
        score += 0.12
    if active_network_package:
        score += 0.08

    maturity_band = "foundational"
    if score >= 0.82:
        maturity_band = "scale_ready"
    elif score >= 0.62:
        maturity_band = "operationally_ready"
    elif score >= 0.45:
        maturity_band = "growing"

    return {
        "score": round(min(score, 0.98), 2),
        "band": maturity_band,
    }


def build_deployment_manifest():
    office_profile = dict(load_office_profile() or {})
    totals = dict(memory_totals() or {})
    version = get_version()
    build_id, build_timestamp = get_build_info()
    release_manifest = dict(get_release_manifest() or {})
    recent_runs = get_recent_packet_runs(280)
    recent_events = get_recent_packet_events(280)
    predictive_summary = build_predictive_learning_snapshot(recent_runs, recent_events)
    model_summary = dict(predictive_summary.get("model_summary") or {})
    learning_health = dict(predictive_summary.get("outcome_learning_health") or {})
    imported_snapshot_files = list_imported_snapshot_files()
    network_rollup = _safe_summary(load_network_rollup())
    active_network_package = dict(load_active_network_intelligence_package() or {})
    runtime_root = get_runtime_root()
    runtime_project_dir = get_runtime_project_dir()
    readiness = _build_platform_readiness(
        office_profile,
        release_manifest,
        predictive_summary,
        len(imported_snapshot_files),
        network_rollup,
        active_network_package,
    )
    rollout_summary = build_rollout_summary(
        office_profile,
        packet_count=totals.get("packet_count", 0),
        outcome_count=learning_health.get("terminal_outcome_count", 0) or learning_health.get("manual_outcome_count", 0) or 0,
        imported_snapshot_count=len(imported_snapshot_files),
    )

    return {
        "schema_version": "1.0",
        "generated_at": utc_now_iso(),
        "platform": {
            "application": "TrueCore",
            "version": version,
            "build_id": build_id,
            "build_timestamp": build_timestamp,
            "runtime_root": runtime_root,
            "runtime_project_dir": runtime_project_dir,
            "frozen": bool(getattr(sys, "frozen", False)),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
        "deployment": {
            "organization_id": office_profile.get("organization_id"),
            "office_id": office_profile.get("office_id"),
            "office_name": office_profile.get("office_name"),
            "install_id": office_profile.get("install_id"),
            "rollout_tier": office_profile.get("rollout_tier") or "single_office",
            "update_channel": UPDATE_URL,
            "release_manifest_available": bool(release_manifest),
            "release_manifest": release_manifest or None,
            "snapshot_output_path": SNAPSHOT_OUTPUT_PATH,
            "office_sync_package_path": OFFICE_SYNC_PACKAGE_PATH,
            "active_network_package_path": ACTIVE_NETWORK_INTELLIGENCE_PACKAGE_PATH,
            "deployment_manifest_path": DEPLOYMENT_MANIFEST_PATH,
            "support_bundle_output_path": SUPPORT_BUNDLE_OUTPUT_PATH,
        },
        "data_state": {
            "packet_count": totals.get("packet_count", 0),
            "case_count": totals.get("case_count", 0),
            "provider_count": totals.get("provider_count", 0),
            "imported_snapshot_count": len(imported_snapshot_files),
            "network_rollup_status": _normalize_status(bool(network_rollup), {True}),
            "network_office_count": network_rollup.get("office_count"),
            "active_network_package_status": _normalize_status(bool(active_network_package), {True}),
        },
        "learning_state": {
            "predictive_model_available": bool(model_summary.get("available")),
            "predictive_model_type": model_summary.get("model_type") or model_summary.get("reason"),
            "labeled_sample_size": model_summary.get("sample_size", 0),
            "reliability_band": model_summary.get("reliability_band") or learning_health.get("reliability_band"),
            "reliability_score": model_summary.get("reliability_score") if model_summary.get("reliability_score") is not None else learning_health.get("reliability_score"),
            "maturity_band": learning_health.get("maturity_band"),
            "approval_count": learning_health.get("approval_count", 0),
            "denial_count": learning_health.get("denial_count", 0),
            "override_count": learning_health.get("override_count", 0),
        },
        "office_rollout": rollout_summary,
        "platform_readiness": readiness,
    }


def write_deployment_manifest():
    manifest = build_deployment_manifest()
    _json_dump(DEPLOYMENT_MANIFEST_PATH, manifest)
    return DEPLOYMENT_MANIFEST_PATH, manifest


def load_deployment_manifest(path=None):
    target_path = path or DEPLOYMENT_MANIFEST_PATH
    if not os.path.exists(target_path):
        return None
    try:
        with open(target_path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def build_support_bundle():
    manifest = build_deployment_manifest()
    office_profile = dict(load_office_profile() or {})
    network_rollup = _safe_summary(load_network_rollup())
    active_network_package = dict(load_active_network_intelligence_package() or {})
    imported_snapshot_names = [os.path.basename(path) for path in list_imported_snapshot_files()]
    recent_runs = get_recent_packet_runs(25)
    recent_events = get_recent_packet_events(25)

    return {
        "schema_version": "1.0",
        "generated_at": utc_now_iso(),
        "deployment_manifest": manifest,
        "privacy_guard": {
            "phi_safe_export": True,
            "raw_patient_file_names_included": False,
            "notes": [
                "Recent packet file names are exported as hashed references only.",
                "The support package is intended for operational troubleshooting, not for raw packet sharing.",
            ],
        },
        "office_profile": {
            "organization_id": office_profile.get("organization_id"),
            "office_id": office_profile.get("office_id"),
            "office_name": office_profile.get("office_name"),
            "install_id": office_profile.get("install_id"),
            "rollout_tier": office_profile.get("rollout_tier") or "single_office",
        },
        "office_rollout": dict(manifest.get("office_rollout") or {}),
        "network_state": {
            "imported_snapshot_names": imported_snapshot_names,
            "network_rollup_summary": {
                "office_count": network_rollup.get("office_count"),
                "organization_count": network_rollup.get("organization_count"),
                "total_packet_count": network_rollup.get("total_packet_count"),
                "average_packet_score": network_rollup.get("average_packet_score"),
            },
            "active_network_package": {
                "generated_at": active_network_package.get("generated_at"),
                "source": dict((active_network_package.get("source") or {})),
                "payload_summary": {
                    "office_count": dict((active_network_package.get("payload") or {})).get("network_rollup", {}).get("office_count")
                    if isinstance(dict((active_network_package.get("payload") or {})).get("network_rollup"), dict) else None,
                },
            } if active_network_package else None,
        },
        "recent_activity_summary": {
            "recent_run_count": len(recent_runs),
            "recent_event_count": len(recent_events),
            "recent_run_references": [
                _redact_file_reference(row.get("file_name"))
                for row in recent_runs[:10]
                if _redact_file_reference(row.get("file_name"))
            ],
            "recent_event_types": [row.get("event_type") for row in recent_events[:10] if row.get("event_type")],
        },
    }


def export_support_bundle():
    bundle = build_support_bundle()
    write_deployment_manifest()
    payload_bytes = _canonical_json_bytes(bundle)
    bundle["export_metadata"] = {
        "output_file": os.path.basename(SUPPORT_BUNDLE_OUTPUT_PATH),
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload_size_bytes": len(payload_bytes),
        "generated_with_manifest_refresh": True,
    }
    _json_dump(SUPPORT_BUNDLE_OUTPUT_PATH, bundle)
    return SUPPORT_BUNDLE_OUTPUT_PATH
