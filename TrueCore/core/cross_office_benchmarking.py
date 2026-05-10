import json
import os
import re
import statistics
from collections import Counter
from datetime import datetime, timezone

from TrueCore.core.cross_office_learning import (
    SNAPSHOT_SCHEMA_VERSION,
    build_cross_office_snapshot,
    utc_now_iso,
)
from TrueCore.utils.runtime_info import runtime_data_path


NETWORK_ROLLUP_SCHEMA_VERSION = "1.0"
NETWORK_ROLLUP_OUTPUT_PATH = runtime_data_path("Outputs", "truecore_network_rollup.json")
IMPORTED_SNAPSHOT_DIR = runtime_data_path("Outputs", "cross_office_snapshots")
REQUIRED_OFFICE_KEYS = {"organization_id", "office_id", "office_name", "install_id"}
REQUIRED_RUN_KEYS = {
    "run_id",
    "packet_key",
    "analyzed_at",
    "packet_score",
    "status",
    "denial_risk",
    "workflow_queue",
    "forms",
    "issue_labels",
}
REQUIRED_EVENT_KEYS = {
    "event_id",
    "packet_key",
    "created_at",
    "event_type",
    "event_status",
}


def _coerce_list(value):
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _average(values):
    cleaned = [float(value) for value in values if value not in (None, "", [], {})]
    if not cleaned:
        return None
    return round(sum(cleaned) / len(cleaned), 2)


def _median(values):
    cleaned = [float(value) for value in values if value not in (None, "", [], {})]
    if not cleaned:
        return None
    return round(statistics.median(cleaned), 2)


def _safe_slug(value, fallback="snapshot"):
    text = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(value or "").strip())
    text = re.sub(r"-{2,}", "-", text).strip("-_")
    return text or fallback


def _parse_generated_at(value):
    text = str(value or "").strip()
    if not text:
        return datetime.min.replace(tzinfo=timezone.utc)

    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


def snapshot_office_key(snapshot):
    payload = _normalize_snapshot(snapshot)
    office = dict(payload.get("office") or {})
    return (
        str(office.get("organization_id") or "").strip().lower(),
        str(office.get("office_id") or "").strip().lower(),
    )


def group_snapshots_by_office(snapshots):
    groups = {}

    for snapshot in list(snapshots or []):
        payload = validate_cross_office_snapshot(snapshot)["snapshot"]
        office_key = snapshot_office_key(payload)
        groups.setdefault(office_key, []).append(payload)

    for office_key in list(groups):
        groups[office_key] = sorted(
            groups[office_key],
            key=lambda item: _parse_generated_at(item.get("generated_at")),
        )

    return groups


def collapse_snapshots_to_latest(snapshots):
    groups = group_snapshots_by_office(snapshots)
    return [history[-1] for history in groups.values() if history]


def _normalize_snapshot(snapshot):
    payload = dict(snapshot or {})
    payload["schema_version"] = str(payload.get("schema_version") or "").strip()
    payload["generated_at"] = str(payload.get("generated_at") or "").strip()
    payload["office"] = dict(payload.get("office") or {})
    payload["summary"] = dict(payload.get("summary") or {})
    payload["runs"] = [dict(item or {}) for item in list(payload.get("runs") or [])]
    payload["events"] = [dict(item or {}) for item in list(payload.get("events") or [])]
    return payload


def validate_cross_office_snapshot(snapshot):
    payload = _normalize_snapshot(snapshot)
    errors = []

    if payload.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        errors.append(
            f"Unsupported snapshot schema version: {payload.get('schema_version') or 'missing'}"
        )

    office = payload.get("office") or {}
    missing_office = sorted(REQUIRED_OFFICE_KEYS - set(office))
    if missing_office:
        errors.append(f"Missing office keys: {', '.join(missing_office)}")

    for index, run in enumerate(payload.get("runs", []), start=1):
        missing = sorted(REQUIRED_RUN_KEYS - set(run))
        if missing:
            errors.append(f"Run {index} missing keys: {', '.join(missing)}")

    for index, event in enumerate(payload.get("events", []), start=1):
        missing = sorted(REQUIRED_EVENT_KEYS - set(event))
        if missing:
            errors.append(f"Event {index} missing keys: {', '.join(missing)}")

    return {
        "valid": not errors,
        "errors": errors,
        "snapshot": payload,
    }


def load_cross_office_snapshot(path):
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    validation = validate_cross_office_snapshot(payload)
    if not validation["valid"]:
        raise ValueError(
            f"Invalid cross-office snapshot at {path}: {'; '.join(validation['errors'])}"
        )

    return validation["snapshot"]


def load_cross_office_snapshots(paths=None, directory=None):
    snapshot_paths = []

    if paths:
        snapshot_paths.extend(str(path) for path in paths if path)

    if directory:
        for name in sorted(os.listdir(directory)):
            if name.lower().endswith(".json"):
                snapshot_paths.append(os.path.join(directory, name))

    snapshots = []
    for path in snapshot_paths:
        snapshots.append(load_cross_office_snapshot(path))

    return snapshots


def list_imported_snapshot_files(directory=None):
    snapshot_dir = directory or IMPORTED_SNAPSHOT_DIR
    if not os.path.isdir(snapshot_dir):
        return []

    return [
        os.path.join(snapshot_dir, name)
        for name in sorted(os.listdir(snapshot_dir))
        if name.lower().endswith(".json")
    ]


def load_imported_cross_office_snapshots(directory=None):
    paths = list_imported_snapshot_files(directory=directory)
    return [load_cross_office_snapshot(path) for path in paths]


def import_cross_office_snapshot_files(paths, directory=None):
    snapshot_dir = directory or IMPORTED_SNAPSHOT_DIR
    os.makedirs(snapshot_dir, exist_ok=True)

    imported = []
    for source_path in list(paths or []):
        snapshot = load_cross_office_snapshot(source_path)
        office = dict(snapshot.get("office") or {})
        generated_at = str(snapshot.get("generated_at") or "").replace(":", "-")
        filename = (
            f"{_safe_slug(office.get('organization_id'), 'org')}"
            f"__{_safe_slug(office.get('office_id'), 'office')}"
            f"__{_safe_slug(office.get('install_id'), 'install')}"
            f"__{_safe_slug(generated_at, 'snapshot')}.json"
        )
        output_path = os.path.join(snapshot_dir, filename)

        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(snapshot, handle, indent=4)

        imported.append(output_path)

    return imported


def build_office_rollup(snapshot):
    snapshot = _normalize_snapshot(snapshot)
    office = dict(snapshot.get("office") or {})
    runs = [dict(item or {}) for item in snapshot.get("runs", [])]
    events = [dict(item or {}) for item in snapshot.get("events", [])]

    issue_counter = Counter()
    form_counter = Counter()
    workflow_counter = Counter()
    denial_counter = Counter()
    outcome_counter = Counter()

    for run in runs:
        issue_counter.update(_coerce_list(run.get("issue_labels")))
        form_counter.update(_coerce_list(run.get("forms")))
        workflow_counter.update([run.get("workflow_queue")] if run.get("workflow_queue") else [])
        denial_counter.update([run.get("denial_risk")] if run.get("denial_risk") else [])

    for event in events:
        if event.get("event_type") == "manual_outcome" and event.get("event_status"):
            outcome_counter.update([event.get("event_status")])

    packet_scores = [run.get("packet_score") for run in runs]
    packet_confidences = [run.get("packet_confidence") for run in runs]
    runtimes = [run.get("runtime_seconds") for run in runs]
    scan_scores = [run.get("scan_quality_score") for run in runs]

    average_score = _average(packet_scores)
    standing = "insufficient_history"
    if average_score is not None:
        if average_score >= 85:
            standing = "strong"
        elif average_score >= 70:
            standing = "competitive"
        else:
            standing = "needs_attention"

    return {
        "organization_id": office.get("organization_id"),
        "office_id": office.get("office_id"),
        "office_name": office.get("office_name"),
        "install_id": office.get("install_id"),
        "packet_count": len(runs),
        "event_count": len(events),
        "average_packet_score": average_score,
        "median_packet_score": _median(packet_scores),
        "average_packet_confidence": _average(packet_confidences),
        "average_runtime_seconds": _average(runtimes),
        "average_scan_quality_score": _average(scan_scores),
        "standing": standing,
        "workflow_distribution": dict(workflow_counter),
        "denial_risk_distribution": dict(denial_counter),
        "manual_outcome_distribution": dict(outcome_counter),
        "top_issues": issue_counter.most_common(8),
        "top_document_families": form_counter.most_common(8),
    }


def build_network_rollup(snapshots):
    normalized_snapshots = [validate_cross_office_snapshot(item)["snapshot"] for item in (snapshots or [])]
    latest_snapshots = collapse_snapshots_to_latest(normalized_snapshots)
    office_rollups = [build_office_rollup(snapshot) for snapshot in latest_snapshots]

    issue_counter = Counter()
    form_counter = Counter()
    workflow_counter = Counter()
    denial_counter = Counter()
    outcome_counter = Counter()
    office_counter = Counter()
    organization_counter = Counter()

    all_scores = []
    all_confidences = []
    all_runtimes = []
    all_scan_scores = []
    total_packets = 0
    total_events = 0

    for snapshot in latest_snapshots:
        office = dict(snapshot.get("office") or {})
        office_counter.update([office.get("office_id")] if office.get("office_id") else [])
        organization_counter.update([office.get("organization_id")] if office.get("organization_id") else [])

        for run in snapshot.get("runs", []):
            issue_counter.update(_coerce_list(run.get("issue_labels")))
            form_counter.update(_coerce_list(run.get("forms")))
            workflow_counter.update([run.get("workflow_queue")] if run.get("workflow_queue") else [])
            denial_counter.update([run.get("denial_risk")] if run.get("denial_risk") else [])
            all_scores.append(run.get("packet_score"))
            all_confidences.append(run.get("packet_confidence"))
            all_runtimes.append(run.get("runtime_seconds"))
            all_scan_scores.append(run.get("scan_quality_score"))
            total_packets += 1

        for event in snapshot.get("events", []):
            if event.get("event_type") == "manual_outcome" and event.get("event_status"):
                outcome_counter.update([event.get("event_status")])
            total_events += 1

    ranked_offices = sorted(
        office_rollups,
        key=lambda item: (
            item.get("average_packet_score") if item.get("average_packet_score") is not None else -1,
            item.get("packet_count") or 0,
        ),
        reverse=True,
    )

    return {
        "schema_version": NETWORK_ROLLUP_SCHEMA_VERSION,
        "source_snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION,
        "generated_at": utc_now_iso(),
        "source_snapshot_count": len(normalized_snapshots),
        "current_snapshot_count": len(latest_snapshots),
        "organization_count": len(organization_counter),
        "office_count": len(office_counter),
        "total_packet_count": total_packets,
        "total_event_count": total_events,
        "average_packet_score": _average(all_scores),
        "median_packet_score": _median(all_scores),
        "average_packet_confidence": _average(all_confidences),
        "average_runtime_seconds": _average(all_runtimes),
        "average_scan_quality_score": _average(all_scan_scores),
        "top_issues": issue_counter.most_common(12),
        "top_document_families": form_counter.most_common(12),
        "workflow_distribution": dict(workflow_counter),
        "denial_risk_distribution": dict(denial_counter),
        "manual_outcome_distribution": dict(outcome_counter),
        "office_rollups": office_rollups,
        "office_rankings": ranked_offices,
    }


def export_network_rollup(snapshots=None, paths=None, directory=None, path=None):
    if snapshots is None:
        snapshots = load_cross_office_snapshots(paths=paths, directory=directory)

    rollup = build_network_rollup(snapshots)
    output_path = path or NETWORK_ROLLUP_OUTPUT_PATH

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(rollup, handle, indent=4)

    return output_path


def load_network_rollup(path=None):
    rollup_path = path or NETWORK_ROLLUP_OUTPUT_PATH
    if not os.path.exists(rollup_path):
        return None

    with open(rollup_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_local_network_rollup(include_current_office=True, imported_directory=None, path=None):
    snapshots = load_imported_cross_office_snapshots(directory=imported_directory)

    if include_current_office:
        snapshots.insert(0, build_cross_office_snapshot())

    if not snapshots:
        raise ValueError("No snapshots available to build a network rollup.")

    return export_network_rollup(snapshots=snapshots, path=path)
