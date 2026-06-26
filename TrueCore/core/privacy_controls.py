import os
import json
from datetime import datetime, timezone

from TrueCore.core.case_memory import MEMORY_DB_PATH, purge_memory_database
from TrueCore.core.cross_office_learning import build_cross_office_snapshot
from TrueCore.core.office_rollout import load_office_profile
from TrueCore.core.platform_scaling import build_support_bundle
from TrueCore.utils.runtime_info import runtime_data_path, runtime_dir_path


LEGACY_WORKBOOK_PATH = runtime_data_path("Outputs", "TrueCore Operations.xlsx")
PRIVACY_RESET_ARCHIVE_DIR = runtime_dir_path("Outputs", "privacy_reset_archives")


def utc_now_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _file_status(path):
    exists = os.path.exists(path)
    size_bytes = os.path.getsize(path) if exists else 0
    return {
        "path": path,
        "exists": exists,
        "size_bytes": size_bytes,
    }


def build_local_phi_storage_status():
    memory_db = _file_status(MEMORY_DB_PATH)
    workbook = _file_status(LEGACY_WORKBOOK_PATH)

    return {
        "memory_database": {
            **memory_db,
            "label": "Local packet memory database",
        },
        "legacy_workbook": {
            **workbook,
            "label": "Retired operations workbook",
        },
        "deidentified_exports": {
            "status": "available",
            "note": "Cross-office snapshots and support packages are de-identified exports, not raw packet storage.",
        },
        "privacy_reset_archive_dir": PRIVACY_RESET_ARCHIVE_DIR,
    }


def build_local_phi_reset_archive():
    office_profile = dict(load_office_profile() or {})
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "archive_type": "local_phi_reset_archive",
        "purpose": "De-identified support archive captured before local PHI-bearing storage reset.",
        "office": {
            "organization_id": office_profile.get("organization_id"),
            "office_id": office_profile.get("office_id"),
            "office_name": office_profile.get("office_name"),
            "install_id": office_profile.get("install_id"),
        },
        "status_before_reset": build_local_phi_storage_status(),
        "support_bundle": build_support_bundle(),
        "cross_office_snapshot": build_cross_office_snapshot(limit_runs=250, limit_events=250),
        "guidance": [
            "This archive is intended to preserve operational context before local PHI-linked storage is reset.",
            "It is de-identified and should not be treated as a replacement for the office's official medical record retention process.",
            "Use local PHI resets only under the office's retention policy and compliance direction.",
        ],
    }


def export_local_phi_reset_archive(path=None):
    output_dir = PRIVACY_RESET_ARCHIVE_DIR
    os.makedirs(output_dir, exist_ok=True)
    output_path = path or os.path.join(
        output_dir,
        f"truecore_phi_reset_archive_{utc_now_stamp()}.json",
    )
    payload = build_local_phi_reset_archive()
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4, ensure_ascii=True, sort_keys=True)
    return output_path


def purge_local_phi_storage(remove_memory_database=True, remove_legacy_workbook=True):
    removed_paths = []

    if remove_memory_database:
        removed_paths.extend(purge_memory_database())

    if remove_legacy_workbook and os.path.exists(LEGACY_WORKBOOK_PATH):
        os.remove(LEGACY_WORKBOOK_PATH)
        removed_paths.append(LEGACY_WORKBOOK_PATH)

    return {
        "removed_paths": removed_paths,
        "memory_database_removed": any(path.startswith(MEMORY_DB_PATH) for path in removed_paths),
        "legacy_workbook_removed": LEGACY_WORKBOOK_PATH in removed_paths,
        "status": build_local_phi_storage_status(),
    }
