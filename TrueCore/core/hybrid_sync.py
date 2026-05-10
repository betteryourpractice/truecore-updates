import json
import os
import re

from TrueCore.core.cross_office_benchmarking import (
    build_network_rollup,
    load_cross_office_snapshots,
    load_imported_cross_office_snapshots,
)
from TrueCore.core.cross_office_intelligence import build_cross_office_intelligence
from TrueCore.core.cross_office_learning import build_cross_office_snapshot, load_office_profile, utc_now_iso
from TrueCore.utils.runtime_info import runtime_data_path


HYBRID_PACKAGE_SCHEMA_VERSION = "1.0"
OFFICE_SYNC_PACKAGE_PATH = runtime_data_path("Outputs", "truecore_office_sync_package.json")
NETWORK_INTELLIGENCE_PACKAGE_PATH = runtime_data_path("Outputs", "truecore_network_intelligence_package.json")
IMPORTED_NETWORK_PACKAGE_DIR = runtime_data_path("Outputs", "network_intelligence_packages")
ACTIVE_NETWORK_INTELLIGENCE_PACKAGE_PATH = runtime_data_path("Outputs", "active_network_intelligence_package.json")


def _safe_slug(value, fallback="package"):
    text = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(value or "").strip())
    text = re.sub(r"-{2,}", "-", text).strip("-_")
    return text or fallback


def _normalize_hybrid_package(package):
    payload = dict(package or {})
    payload["schema_version"] = str(payload.get("schema_version") or "").strip()
    payload["package_type"] = str(payload.get("package_type") or "").strip()
    payload["generated_at"] = str(payload.get("generated_at") or "").strip()
    payload["source"] = dict(payload.get("source") or {})
    payload["payload"] = dict(payload.get("payload") or {})
    return payload


def validate_hybrid_package(package):
    payload = _normalize_hybrid_package(package)
    errors = []

    if payload.get("schema_version") != HYBRID_PACKAGE_SCHEMA_VERSION:
        errors.append(
            f"Unsupported hybrid package schema version: {payload.get('schema_version') or 'missing'}"
        )

    package_type = payload.get("package_type")
    if package_type not in {"office_sync_package", "network_intelligence_package"}:
        errors.append(f"Unsupported hybrid package type: {package_type or 'missing'}")

    source = dict(payload.get("source") or {})
    for required_key in ["organization_id", "office_id", "office_name"]:
        if not source.get(required_key):
            errors.append(f"Missing source key: {required_key}")

    content = dict(payload.get("payload") or {})
    if package_type == "office_sync_package" and "snapshot" not in content:
        errors.append("Office sync package is missing snapshot payload.")

    if package_type == "network_intelligence_package":
        if "network_rollup" not in content:
            errors.append("Network intelligence package is missing network_rollup payload.")
        if "cross_office_intelligence" not in content:
            errors.append("Network intelligence package is missing cross_office_intelligence payload.")

    return {
        "valid": not errors,
        "errors": errors,
        "package": payload,
    }


def build_office_sync_package(limit_runs=250, limit_events=250):
    office_profile = load_office_profile()
    snapshot = build_cross_office_snapshot(limit_runs=limit_runs, limit_events=limit_events)

    return {
        "schema_version": HYBRID_PACKAGE_SCHEMA_VERSION,
        "package_type": "office_sync_package",
        "generated_at": utc_now_iso(),
        "source": {
            "organization_id": office_profile.get("organization_id"),
            "office_id": office_profile.get("office_id"),
            "office_name": office_profile.get("office_name"),
            "install_id": office_profile.get("install_id"),
        },
        "payload": {
            "snapshot": snapshot,
            "benchmark_summary": dict(snapshot.get("summary") or {}),
        },
    }


def export_office_sync_package(path=None, limit_runs=250, limit_events=250):
    package = build_office_sync_package(limit_runs=limit_runs, limit_events=limit_events)
    output_path = path or OFFICE_SYNC_PACKAGE_PATH

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(package, handle, indent=4)

    return output_path


def build_network_intelligence_package(snapshots, package_label="Organization Intelligence Package"):
    snapshots = [dict(item or {}) for item in list(snapshots or [])]
    if not snapshots:
        raise ValueError("No snapshots available to build a network intelligence package.")

    rollup = build_network_rollup(snapshots)
    intelligence = build_cross_office_intelligence(snapshots, rollup=rollup)
    source = {
        "organization_id": "multi-office-network",
        "office_id": "network-hub",
        "office_name": package_label,
    }

    if rollup.get("office_rankings"):
        lead = dict(rollup.get("office_rankings")[0] or {})
        source["organization_id"] = str(lead.get("organization_id") or source["organization_id"])

    return {
        "schema_version": HYBRID_PACKAGE_SCHEMA_VERSION,
        "package_type": "network_intelligence_package",
        "generated_at": utc_now_iso(),
        "source": source,
        "payload": {
            "network_rollup": rollup,
            "cross_office_intelligence": intelligence,
        },
    }


def export_network_intelligence_package(snapshots=None, paths=None, directory=None, path=None, package_label="Organization Intelligence Package"):
    if snapshots is None:
        snapshots = load_cross_office_snapshots(paths=paths, directory=directory)

    package = build_network_intelligence_package(snapshots, package_label=package_label)
    output_path = path or NETWORK_INTELLIGENCE_PACKAGE_PATH

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(package, handle, indent=4)

    return output_path


def build_local_network_intelligence_package(include_current_office=True, imported_directory=None, path=None, package_label="Organization Intelligence Package"):
    snapshots = load_imported_cross_office_snapshots(directory=imported_directory)

    if include_current_office:
        snapshots.insert(0, build_cross_office_snapshot())

    return export_network_intelligence_package(
        snapshots=snapshots,
        path=path,
        package_label=package_label,
    )


def load_hybrid_package(path):
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    validation = validate_hybrid_package(payload)
    if not validation["valid"]:
        raise ValueError(f"Invalid hybrid package at {path}: {'; '.join(validation['errors'])}")

    return validation["package"]


def import_network_intelligence_package(path, directory=None, activate=True):
    package = load_hybrid_package(path)
    if package.get("package_type") != "network_intelligence_package":
        raise ValueError("Only network intelligence packages can be imported into a local office.")

    storage_dir = directory or IMPORTED_NETWORK_PACKAGE_DIR
    os.makedirs(storage_dir, exist_ok=True)

    source = dict(package.get("source") or {})
    generated_at = str(package.get("generated_at") or "").replace(":", "-")
    filename = (
        f"{_safe_slug(source.get('organization_id'), 'org')}"
        f"__{_safe_slug(source.get('office_id'), 'network')}"
        f"__{_safe_slug(generated_at, 'package')}.json"
    )
    output_path = os.path.join(storage_dir, filename)

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(package, handle, indent=4)

    if activate:
        with open(ACTIVE_NETWORK_INTELLIGENCE_PACKAGE_PATH, "w", encoding="utf-8") as handle:
            json.dump(package, handle, indent=4)

    return output_path


def load_active_network_intelligence_package(path=None):
    package_path = path or ACTIVE_NETWORK_INTELLIGENCE_PACKAGE_PATH
    if not os.path.exists(package_path):
        return None

    return load_hybrid_package(package_path)
