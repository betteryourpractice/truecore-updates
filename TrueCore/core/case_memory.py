import json
import os
import sqlite3
from collections import Counter
from datetime import datetime


MEMORY_DB_PATH = os.path.join(
    os.getcwd(),
    "TrueCore",
    "Outputs",
    "truecore_memory.db",
)


def utc_now_iso():
    return datetime.utcnow().isoformat(timespec="microseconds") + "Z"


def json_dumps(value):
    return json.dumps(value or {}, ensure_ascii=True, sort_keys=True)


def json_loads(value, default=None):
    if not value:
        return default

    try:
        return json.loads(value)
    except Exception:
        return default


def normalize_text(value):
    return " ".join(str(value or "").strip().lower().split())


def normalize_name(value):
    cleaned = normalize_text(value)
    for suffix in (
        " md",
        " do",
        " pa",
        " pa-c",
        " np",
        " fnp",
        " aprn",
        " rn",
        " dr",
        " dr.",
    ):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)].strip()
    return cleaned


def ensure_memory_db():
    os.makedirs(os.path.dirname(MEMORY_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.row_factory = sqlite3.Row

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS packet_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analyzed_at TEXT NOT NULL,
            file_name TEXT,
            file_path TEXT,
            case_key TEXT,
            patient_name TEXT,
            dob TEXT,
            authorization_number TEXT,
            va_icn TEXT,
            provider_key TEXT,
            provider_name TEXT,
            ordering_provider TEXT,
            referring_provider TEXT,
            diagnosis_text TEXT,
            forms_text TEXT,
            score INTEGER,
            status TEXT,
            denial_risk TEXT,
            workflow_queue TEXT,
            review_priority TEXT,
            packet_confidence REAL,
            runtime_seconds REAL,
            intel_runtime_seconds REAL,
            legacy_runtime_seconds REAL,
            host_runtime_seconds REAL,
            analysis_mode TEXT,
            scan_quality_band TEXT,
            scan_quality_score REAL,
            ocr_confidence REAL,
            triage_priority TEXT,
            triage_urgency TEXT,
            review_depth TEXT,
            issues_json TEXT,
            fixes_json TEXT,
            fields_json TEXT,
            intel_summary_json TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS packet_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            case_key TEXT,
            file_name TEXT,
            file_path TEXT,
            event_type TEXT,
            event_status TEXT,
            note TEXT,
            details_json TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packet_runs_case_key ON packet_runs(case_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packet_runs_provider_key ON packet_runs(provider_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packet_events_case_key ON packet_events(case_key)")
    _ensure_packet_run_columns(
        conn,
        {
            "runtime_seconds": "REAL",
            "intel_runtime_seconds": "REAL",
            "legacy_runtime_seconds": "REAL",
            "host_runtime_seconds": "REAL",
            "analysis_mode": "TEXT",
        },
    )
    conn.commit()
    return conn


def _ensure_packet_run_columns(conn, columns):
    existing = {
        str(row["name"]).strip().lower()
        for row in conn.execute("PRAGMA table_info(packet_runs)").fetchall()
    }

    for column_name, column_type in dict(columns or {}).items():
        normalized = str(column_name or "").strip().lower()
        if not normalized or normalized in existing:
            continue
        conn.execute(f"ALTER TABLE packet_runs ADD COLUMN {column_name} {column_type}")
        existing.add(normalized)


def determine_status(score):
    try:
        score = int(score or 0)
    except Exception:
        score = 0

    if score >= 90:
        return "approved"
    if score >= 70:
        return "needs_review"
    return "rejected"


def build_case_key(fields, file_path=None):
    fields = dict(fields or {})

    auth = normalize_text(fields.get("authorization_number"))
    if auth:
        return f"auth:{auth}"

    va_icn = normalize_text(fields.get("va_icn") or fields.get("icn"))
    if va_icn:
        return f"icn:{va_icn}"

    patient_name = normalize_name(fields.get("patient_name") or fields.get("name"))
    dob = normalize_text(fields.get("dob"))
    if patient_name and dob:
        return f"patient:{patient_name}|{dob}"

    if patient_name:
        return f"patient:{patient_name}"

    if file_path:
        return f"file:{normalize_text(os.path.basename(file_path))}"

    return "unknown_case"


def build_provider_key(fields):
    fields = dict(fields or {})
    candidates = [
        fields.get("ordering_doctor"),
        fields.get("ordering_provider"),
        fields.get("provider"),
        fields.get("referring_doctor"),
        fields.get("referring_provider"),
    ]

    for candidate in candidates:
        normalized = normalize_name(candidate)
        if normalized:
            return normalized

    return "unknown_provider"


def build_run_snapshot(file_path, result):
    result = dict(result or {})
    intel = dict(result.get("intel", {}) or {})
    display = dict(intel.get("display", {}) or {})
    fields = dict(result.get("fields", {}) or {})
    profiling = dict(result.get("profiling", {}) or {})
    metrics = dict(intel.get("metrics", {}) or {})
    scan = dict(intel.get("scan_diagnostics", {}) or {})
    scan_summary = dict(scan.get("summary", {}) or {})

    return {
        "analyzed_at": utc_now_iso(),
        "file_name": os.path.basename(file_path),
        "file_path": os.path.abspath(file_path),
        "case_key": build_case_key(fields, file_path=file_path),
        "patient_name": fields.get("patient_name") or fields.get("name"),
        "dob": fields.get("dob"),
        "authorization_number": fields.get("authorization_number"),
        "va_icn": fields.get("va_icn") or fields.get("icn"),
        "provider_key": build_provider_key(fields),
        "provider_name": fields.get("provider") or fields.get("ordering_doctor"),
        "ordering_provider": fields.get("ordering_doctor") or fields.get("ordering_provider"),
        "referring_provider": fields.get("referring_doctor") or fields.get("referring_provider"),
        "diagnosis_text": normalize_text(fields.get("diagnosis")),
        "forms_text": " | ".join(sorted(str(item) for item in result.get("forms", []) or [])),
        "score": int(result.get("score", 0) or 0),
        "status": determine_status(result.get("score", 0)),
        "denial_risk": display.get("denial_risk"),
        "workflow_queue": display.get("workflow_queue"),
        "review_priority": display.get("review_priority"),
        "packet_confidence": display.get("packet_confidence"),
        "runtime_seconds": profiling.get("total_seconds"),
        "intel_runtime_seconds": profiling.get("intel_seconds"),
        "legacy_runtime_seconds": profiling.get("legacy_seconds"),
        "host_runtime_seconds": profiling.get("host_seconds"),
        "analysis_mode": profiling.get("analysis_mode"),
        "scan_quality_band": scan_summary.get("scan_quality_band"),
        "scan_quality_score": scan_summary.get("scan_quality_score"),
        "ocr_confidence": scan_summary.get("average_ocr_confidence"),
        "issues": list(result.get("issues", []) or []),
        "fixes": list(result.get("fixes", []) or []),
        "fields": fields,
        "intel_summary": {
            "missing_items": list(display.get("missing_items", []) or []),
            "why_weak": list(display.get("why_weak", []) or []),
            "review_flags": list(display.get("review_flags", []) or []),
            "scan_summary": scan_summary,
            "runtime_profile": profiling,
            "pipeline_stage_timings": dict(metrics.get("pipeline_stage_timings", {}) or {}),
            "engine_metrics": {
                "intake_seconds": metrics.get("intake_seconds"),
                "primary_pipeline_seconds": metrics.get("primary_pipeline_seconds"),
                "retry_evaluation_seconds": metrics.get("retry_evaluation_seconds"),
                "fallback_reload_seconds": metrics.get("fallback_reload_seconds"),
                "fallback_pipeline_seconds": metrics.get("fallback_pipeline_seconds"),
                "pipeline_total_seconds": metrics.get("pipeline_total_seconds"),
                "process_path_total_seconds": metrics.get("process_path_total_seconds"),
                "used_ocr_fallback": metrics.get("used_ocr_fallback"),
            },
        },
    }


def rows_to_dicts(rows):
    return [dict(row) for row in rows or []]


def get_case_history(case_key, limit=25):
    if not case_key or case_key == "unknown_case":
        return []

    conn = ensure_memory_db()
    try:
        rows = conn.execute(
            """
            SELECT * FROM packet_runs
            WHERE case_key = ?
            ORDER BY analyzed_at DESC
            LIMIT ?
            """,
            (case_key, limit),
        ).fetchall()
        return rows_to_dicts(rows)
    finally:
        conn.close()


def get_recent_packet_runs(limit=250):
    conn = ensure_memory_db()
    try:
        rows = conn.execute(
            """
            SELECT * FROM packet_runs
            ORDER BY analyzed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return rows_to_dicts(rows)
    finally:
        conn.close()


def get_recent_packet_events(limit=250):
    conn = ensure_memory_db()
    try:
        rows = conn.execute(
            """
            SELECT * FROM packet_events
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return rows_to_dicts(rows)
    finally:
        conn.close()


def get_provider_history(provider_key, limit=40):
    if not provider_key or provider_key == "unknown_provider":
        return []

    conn = ensure_memory_db()
    try:
        rows = conn.execute(
            """
            SELECT * FROM packet_runs
            WHERE provider_key = ?
            ORDER BY analyzed_at DESC
            LIMIT ?
            """,
            (provider_key, limit),
        ).fetchall()
        return rows_to_dicts(rows)
    finally:
        conn.close()


def get_case_events(case_key, limit=40):
    if not case_key or case_key == "unknown_case":
        return []

    conn = ensure_memory_db()
    try:
        rows = conn.execute(
            """
            SELECT * FROM packet_events
            WHERE case_key = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (case_key, limit),
        ).fetchall()
        return rows_to_dicts(rows)
    finally:
        conn.close()


def parse_issues(row):
    return list(json_loads(row.get("issues_json"), default=[]) or [])


def parse_fixes(row):
    return list(json_loads(row.get("fixes_json"), default=[]) or [])


def parse_intel_summary(row):
    return dict(json_loads(row.get("intel_summary_json"), default={}) or {})


def parse_fields(row):
    return dict(json_loads(row.get("fields_json"), default={}) or {})


def compute_memory_confidence(case_key, prior_runs):
    prior_count = len(prior_runs)
    score = 0.35

    if case_key.startswith("auth:"):
        score += 0.35
    elif case_key.startswith("icn:"):
        score += 0.3
    elif case_key.startswith("patient:"):
        score += 0.22
    else:
        score += 0.1

    if prior_count >= 6:
        score += 0.25
    elif prior_count >= 3:
        score += 0.18
    elif prior_count >= 1:
        score += 0.1

    score = round(min(score, 0.98), 2)
    if score >= 0.82:
        band = "high"
    elif score >= 0.6:
        band = "medium"
    else:
        band = "low"

    return {"score": score, "band": band}


def build_timeline(prior_runs, case_events):
    entries = []

    for row in prior_runs[:10]:
        entries.append({
            "timestamp": row.get("analyzed_at"),
            "event_type": "analysis",
            "status": row.get("status"),
            "score": row.get("score"),
            "denial_risk": row.get("denial_risk"),
            "workflow_queue": row.get("workflow_queue"),
            "file_name": row.get("file_name"),
        })

    for event in case_events[:15]:
        entries.append({
            "timestamp": event.get("created_at"),
            "event_type": event.get("event_type"),
            "status": event.get("event_status"),
            "note": event.get("note"),
            "file_name": event.get("file_name"),
        })

    entries.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
    return entries[:15]


def build_provider_relationship_memory(provider_history):
    if not provider_history:
        return {
            "packet_count": 0,
            "average_score": None,
            "quality_trend": "unknown",
            "common_deficiencies": [],
        }

    scores = [int(row.get("score") or 0) for row in provider_history]
    average_score = round(sum(scores) / max(len(scores), 1), 1)
    common_issues = Counter()
    for row in provider_history:
        common_issues.update(parse_issues(row))

    if average_score >= 85:
        quality_trend = "strong"
    elif average_score >= 70:
        quality_trend = "mixed"
    else:
        quality_trend = "weak"

    return {
        "packet_count": len(provider_history),
        "average_score": average_score,
        "quality_trend": quality_trend,
        "common_deficiencies": [item for item, _ in common_issues.most_common(5)],
    }


def build_recurring_deficiency_detection(prior_runs, current_issues):
    issue_counter = Counter()
    for row in prior_runs:
        issue_counter.update(parse_issues(row))

    recurring = [item for item, count in issue_counter.most_common(6) if count >= 2]
    repeated_current = [issue for issue in current_issues if issue in issue_counter]

    return {
        "recurring_issues": recurring,
        "repeated_current_issues": repeated_current,
    }


def build_historical_correction_memory(prior_runs, current_issues):
    if not prior_runs:
        return {
            "resolved_issues": [],
            "new_issues": list(current_issues),
            "correction_reuse_candidates": [],
        }

    previous_issues = parse_issues(prior_runs[0])
    resolved = [issue for issue in previous_issues if issue not in current_issues]
    new_issues = [issue for issue in current_issues if issue not in previous_issues]
    return {
        "resolved_issues": resolved[:6],
        "new_issues": new_issues[:6],
        "correction_reuse_candidates": resolved[:4],
    }


def risk_rank(level):
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get(str(level or "").lower(), 0)


def build_longitudinal_risk_drift(prior_runs, current_score, current_denial_risk):
    if not prior_runs:
        return {
            "direction": "new_case",
            "previous_average_score": None,
            "current_score": current_score,
            "previous_denial_risk": None,
            "current_denial_risk": current_denial_risk,
        }

    recent = prior_runs[:3]
    previous_scores = [int(row.get("score") or 0) for row in recent]
    previous_average = round(sum(previous_scores) / max(len(previous_scores), 1), 1)
    previous_denial = recent[0].get("denial_risk")

    direction = "stable"
    if current_score >= previous_average + 8 and risk_rank(current_denial_risk) <= risk_rank(previous_denial):
        direction = "improving"
    elif current_score <= previous_average - 8 or risk_rank(current_denial_risk) > risk_rank(previous_denial):
        direction = "worsening"

    return {
        "direction": direction,
        "previous_average_score": previous_average,
        "current_score": current_score,
        "previous_denial_risk": previous_denial,
        "current_denial_risk": current_denial_risk,
    }


def build_outcome_linked_memory(case_events):
    counter = Counter(event.get("event_status") for event in case_events if event.get("event_status"))
    return {
        "status_counts": dict(counter),
        "recent_events": case_events[:8],
    }


def build_context_carryover(prior_runs):
    if not prior_runs:
        return {
            "carryover_context": [],
        }

    recent = prior_runs[0]
    carryover = []

    previous_queue = recent.get("workflow_queue")
    if previous_queue:
        carryover.append(f"Previous workflow queue: {previous_queue}")

    previous_priority = recent.get("review_priority")
    if previous_priority:
        carryover.append(f"Previous review priority: {previous_priority}")

    for issue in parse_issues(recent)[:4]:
        carryover.append(f"Recent prior issue: {issue}")

    return {
        "carryover_context": carryover[:6],
    }


def build_similar_case_recall(snapshot):
    conn = ensure_memory_db()
    try:
        rows = conn.execute(
            """
            SELECT * FROM packet_runs
            WHERE case_key != ?
            ORDER BY analyzed_at DESC
            LIMIT 80
            """,
            (snapshot["case_key"],),
        ).fetchall()
    finally:
        conn.close()

    forms = set(item.strip() for item in snapshot.get("forms_text", "").split("|") if item.strip())
    diagnosis = snapshot.get("diagnosis_text", "")
    provider_key = snapshot.get("provider_key")
    scored = []

    for row in rows_to_dicts(rows):
        score = 0.0
        row_forms = set(item.strip() for item in str(row.get("forms_text") or "").split("|") if item.strip())
        row_diag = normalize_text(row.get("diagnosis_text"))
        row_provider = row.get("provider_key")

        if provider_key and row_provider and provider_key == row_provider:
            score += 0.4
        if diagnosis and row_diag and (diagnosis in row_diag or row_diag in diagnosis):
            score += 0.35
        if forms and row_forms:
            overlap = len(forms.intersection(row_forms)) / max(len(forms.union(row_forms)), 1)
            score += overlap * 0.25

        if score <= 0:
            continue

        scored.append({
            "file_name": row.get("file_name"),
            "status": row.get("status"),
            "score": row.get("score"),
            "similarity_score": round(score, 2),
            "workflow_queue": row.get("workflow_queue"),
        })

    scored.sort(key=lambda item: (item["similarity_score"], item["score"] or 0), reverse=True)
    return scored[:5]


def build_case_memory(file_path, result):
    snapshot = build_run_snapshot(file_path, result)
    prior_runs = get_case_history(snapshot["case_key"], limit=25)
    case_events = get_case_events(snapshot["case_key"], limit=25)
    provider_history = get_provider_history(snapshot["provider_key"], limit=40)

    current_issues = list(result.get("issues", []) or [])
    memory_confidence = compute_memory_confidence(snapshot["case_key"], prior_runs)
    recurring = build_recurring_deficiency_detection(prior_runs, current_issues)
    corrections = build_historical_correction_memory(prior_runs, current_issues)
    risk_drift = build_longitudinal_risk_drift(
        prior_runs,
        snapshot["score"],
        snapshot["denial_risk"],
    )
    provider_memory = build_provider_relationship_memory(provider_history)
    timeline = build_timeline(prior_runs, case_events)
    similar_cases = build_similar_case_recall(snapshot)
    context_carryover = build_context_carryover(prior_runs)
    outcome_memory = build_outcome_linked_memory(case_events)

    return {
        "persistent_case_memory": {
            "case_key": snapshot["case_key"],
            "prior_case_count": len(prior_runs),
            "total_case_count": len(prior_runs) + 1,
            "last_status": prior_runs[0].get("status") if prior_runs else None,
            "last_score": prior_runs[0].get("score") if prior_runs else None,
        },
        "patient_timeline_reconstruction": {
            "timeline": timeline,
        },
        "provider_relationship_memory": provider_memory,
        "recurring_deficiency_detection": recurring,
        "historical_correction_memory": corrections,
        "longitudinal_risk_drift_tracking": risk_drift,
        "outcome_linked_memory_layer": outcome_memory,
        "context_carryover_engine": context_carryover,
        "similar_case_recall": similar_cases,
        "memory_confidence_scoring": memory_confidence,
    }


def record_packet_analysis(file_path, result, triage_intelligence=None):
    snapshot = build_run_snapshot(file_path, result)
    triage = dict(triage_intelligence or {})
    conn = ensure_memory_db()

    try:
        conn.execute(
            """
            INSERT INTO packet_runs (
                analyzed_at,
                file_name,
                file_path,
                case_key,
                patient_name,
                dob,
                authorization_number,
                va_icn,
                provider_key,
                provider_name,
                ordering_provider,
                referring_provider,
                diagnosis_text,
                forms_text,
                score,
                status,
                denial_risk,
                workflow_queue,
                review_priority,
                packet_confidence,
                runtime_seconds,
                intel_runtime_seconds,
                legacy_runtime_seconds,
                host_runtime_seconds,
                analysis_mode,
                scan_quality_band,
                scan_quality_score,
                ocr_confidence,
                triage_priority,
                triage_urgency,
                review_depth,
                issues_json,
                fixes_json,
                fields_json,
                intel_summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot["analyzed_at"],
                snapshot["file_name"],
                snapshot["file_path"],
                snapshot["case_key"],
                snapshot["patient_name"],
                snapshot["dob"],
                snapshot["authorization_number"],
                snapshot["va_icn"],
                snapshot["provider_key"],
                snapshot["provider_name"],
                snapshot["ordering_provider"],
                snapshot["referring_provider"],
                snapshot["diagnosis_text"],
                snapshot["forms_text"],
                snapshot["score"],
                snapshot["status"],
                snapshot["denial_risk"],
                snapshot["workflow_queue"],
                snapshot["review_priority"],
                snapshot["packet_confidence"],
                snapshot["runtime_seconds"],
                snapshot["intel_runtime_seconds"],
                snapshot["legacy_runtime_seconds"],
                snapshot["host_runtime_seconds"],
                snapshot["analysis_mode"],
                snapshot["scan_quality_band"],
                snapshot["scan_quality_score"],
                snapshot["ocr_confidence"],
                triage.get("priority_level"),
                triage.get("urgency_classification"),
                triage.get("review_depth_allocation"),
                json_dumps(snapshot["issues"]),
                json_dumps(snapshot["fixes"]),
                json_dumps(snapshot["fields"]),
                json_dumps(snapshot["intel_summary"]),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def record_packet_event(file_path, result, event_type, event_status, note="", details=None):
    snapshot = build_run_snapshot(file_path, result)
    conn = ensure_memory_db()

    try:
        conn.execute(
            """
            INSERT INTO packet_events (
                created_at,
                case_key,
                file_name,
                file_path,
                event_type,
                event_status,
                note,
                details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now_iso(),
                snapshot["case_key"],
                snapshot["file_name"],
                snapshot["file_path"],
                event_type,
                event_status,
                note,
                json_dumps(details or {}),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def memory_totals():
    conn = ensure_memory_db()
    try:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS packet_count,
                COUNT(DISTINCT case_key) AS case_count,
                COUNT(DISTINCT provider_key) AS provider_count
            FROM packet_runs
            """
        ).fetchone()
        return dict(row or {})
    finally:
        conn.close()
