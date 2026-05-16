import hashlib
import hmac
import json
import os
import statistics
from collections import Counter
from datetime import datetime, timezone

from TrueCore.core.case_memory import (
    get_recent_packet_events,
    get_recent_packet_runs,
    json_loads,
    parse_issues,
)
from TrueCore.core.office_rollout import (
    OFFICE_PROFILE_PATH,
    ensure_office_profile,
    load_office_profile,
)
from TrueCore.utils.runtime_info import runtime_data_path


SNAPSHOT_SCHEMA_VERSION = "1.0"
SNAPSHOT_OUTPUT_PATH = runtime_data_path("Outputs", "truecore_cross_office_snapshot.json")


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _hash_value(value, salt):
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None
    digest = hmac.new(
        bytes.fromhex(str(salt or "")),
        normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest


def _coerce_list(value):
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _forms_from_row(row):
    return [
        item.strip()
        for item in str((row or {}).get("forms_text") or "").split("|")
        if item.strip()
    ]


def _intel_summary(row):
    return dict(json_loads((row or {}).get("intel_summary_json"), default={}) or {})


def build_deidentified_packet_run(row, office_profile=None):
    row = dict(row or {})
    office_profile = dict(office_profile or load_office_profile())
    salt = office_profile.get("deidentification_salt")
    intel_summary = _intel_summary(row)

    return {
        "run_id": _hash_value(
            f"{row.get('case_key')}|{row.get('analyzed_at')}|{row.get('file_name')}",
            salt,
        ),
        "packet_key": _hash_value(row.get("case_key"), salt),
        "provider_key_hash": _hash_value(row.get("provider_key"), salt),
        "analyzed_at": row.get("analyzed_at"),
        "packet_score": int(row.get("score") or 0),
        "status": row.get("status"),
        "denial_risk": row.get("denial_risk"),
        "workflow_queue": row.get("workflow_queue"),
        "review_priority": row.get("review_priority"),
        "packet_confidence": row.get("packet_confidence"),
        "runtime_seconds": row.get("runtime_seconds"),
        "intel_runtime_seconds": row.get("intel_runtime_seconds"),
        "host_runtime_seconds": row.get("host_runtime_seconds"),
        "analysis_mode": row.get("analysis_mode"),
        "scan_quality_band": row.get("scan_quality_band"),
        "scan_quality_score": row.get("scan_quality_score"),
        "ocr_confidence": row.get("ocr_confidence"),
        "triage_priority": row.get("triage_priority"),
        "triage_urgency": row.get("triage_urgency"),
        "review_depth": row.get("review_depth"),
        "forms": _forms_from_row(row),
        "issue_labels": parse_issues(row),
        "missing_items": _coerce_list(intel_summary.get("missing_items")),
        "review_flags": _coerce_list(intel_summary.get("review_flags")),
        "why_weak": _coerce_list(intel_summary.get("why_weak")),
        "engine_metrics": dict(intel_summary.get("engine_metrics", {}) or {}),
    }


def build_deidentified_event(event, office_profile=None):
    event = dict(event or {})
    office_profile = dict(office_profile or load_office_profile())
    salt = office_profile.get("deidentification_salt")
    details = dict(json_loads(event.get("details_json"), default={}) or {})

    return {
        "event_id": _hash_value(
            f"{event.get('case_key')}|{event.get('created_at')}|{event.get('event_type')}|{event.get('event_status')}",
            salt,
        ),
        "packet_key": _hash_value(event.get("case_key"), salt),
        "created_at": event.get("created_at"),
        "event_type": event.get("event_type"),
        "event_status": event.get("event_status"),
        "score": details.get("score"),
        "workflow_queue": details.get("workflow_queue"),
        "denial_risk": details.get("denial_risk"),
    }


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


def build_cross_office_benchmark_summary(runs, events):
    runs = [dict(item or {}) for item in (runs or [])]
    events = [dict(item or {}) for item in (events or [])]

    issue_counter = Counter()
    form_counter = Counter()
    status_counter = Counter()
    denial_counter = Counter()
    queue_counter = Counter()
    outcome_counter = Counter()

    for run in runs:
        issue_counter.update(_coerce_list(run.get("issue_labels")))
        form_counter.update(_coerce_list(run.get("forms")))
        status_counter.update([run.get("status")] if run.get("status") else [])
        denial_counter.update([run.get("denial_risk")] if run.get("denial_risk") else [])
        queue_counter.update([run.get("workflow_queue")] if run.get("workflow_queue") else [])

    for event in events:
        if event.get("event_type") == "manual_outcome" and event.get("event_status"):
            outcome_counter.update([event.get("event_status")])

    packet_scores = [run.get("packet_score") for run in runs]
    packet_confidences = [run.get("packet_confidence") for run in runs]
    runtimes = [run.get("runtime_seconds") for run in runs]
    scan_scores = [run.get("scan_quality_score") for run in runs]

    return {
        "packet_count": len(runs),
        "event_count": len(events),
        "average_packet_score": _average(packet_scores),
        "median_packet_score": _median(packet_scores),
        "average_packet_confidence": _average(packet_confidences),
        "average_runtime_seconds": _average(runtimes),
        "average_scan_quality_score": _average(scan_scores),
        "status_distribution": dict(status_counter),
        "denial_risk_distribution": dict(denial_counter),
        "workflow_distribution": dict(queue_counter),
        "manual_outcome_distribution": dict(outcome_counter),
        "top_issues": issue_counter.most_common(10),
        "top_document_families": form_counter.most_common(10),
    }


def build_cross_office_snapshot(limit_runs=250, limit_events=250):
    office_profile = load_office_profile()
    runs = get_recent_packet_runs(limit=limit_runs)
    events = get_recent_packet_events(limit=limit_events)

    deidentified_runs = [
        build_deidentified_packet_run(row, office_profile=office_profile)
        for row in runs
    ]
    deidentified_events = [
        build_deidentified_event(event, office_profile=office_profile)
        for event in events
    ]

    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "generated_at": utc_now_iso(),
        "office": {
            "organization_id": office_profile.get("organization_id"),
            "office_id": office_profile.get("office_id"),
            "office_name": office_profile.get("office_name"),
            "install_id": office_profile.get("install_id"),
        },
        "summary": build_cross_office_benchmark_summary(deidentified_runs, deidentified_events),
        "runs": deidentified_runs,
        "events": deidentified_events,
    }


def build_full_cross_office_snapshot():
    return build_cross_office_snapshot(limit_runs=None, limit_events=None)


def export_cross_office_snapshot(path=None, limit_runs=250, limit_events=250):
    snapshot = build_cross_office_snapshot(limit_runs=limit_runs, limit_events=limit_events)
    output_path = path or SNAPSHOT_OUTPUT_PATH

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=4)

    return output_path
