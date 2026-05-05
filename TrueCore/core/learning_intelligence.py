from collections import Counter

from TrueCore.core.case_memory import (
    build_case_key,
    build_provider_key,
    get_case_events,
    get_case_history,
    get_provider_history,
    json_loads,
    parse_fixes,
    parse_issues,
)
from TrueCore.core.statistical_scoring import (
    beta_smoothed_rate,
    build_outcome_model,
    cusum_series,
    ewma_series,
    summarize_outcome_model,
    wilson_interval,
)


SUCCESS_OUTCOMES = {"approved"}
RECOVERY_OUTCOMES = {"corrected", "resubmitted"}
NEGATIVE_OUTCOMES = {"denied"}
OVERRIDE_OUTCOMES = {"reviewer_override"}


def _issues_from_result(result):
    return list(dict(result or {}).get("issues", []) or [])


def _fixes_from_result(result):
    return list(dict(result or {}).get("fixes", []) or [])


def _display(result):
    return dict(((result or {}).get("intel", {}) or {}).get("display", {}) or {})


def _manual_outcome_events(case_events):
    return [
        event
        for event in case_events
        if str(event.get("event_type") or "").lower() == "manual_outcome"
    ]


def _event_details(event):
    return dict(json_loads(event.get("details_json"), default={}) or {})


def _band_from_score(score):
    try:
        score = float(score or 0.0)
    except Exception:
        score = 0.0

    if score >= 0.82:
        return "strong"
    if score >= 0.6:
        return "moderate"
    return "weak"
def build_outcome_feedback(case_events):
    manual_outcomes = _manual_outcome_events(case_events)
    statuses = [str(event.get("event_status") or "").lower() for event in manual_outcomes if event.get("event_status")]
    counter = Counter(statuses)
    latest = manual_outcomes[0].get("event_status") if manual_outcomes else None

    return {
        "outcome_count": len(manual_outcomes),
        "latest_outcome": latest,
        "status_counts": dict(counter),
        "has_real_outcomes": bool(manual_outcomes),
    }


def build_override_learning(case_events, current_score):
    manual_outcomes = _manual_outcome_events(case_events)
    override_count = sum(
        1
        for event in manual_outcomes
        if str(event.get("event_status") or "").lower() in OVERRIDE_OUTCOMES
    )
    outcome_count = len(manual_outcomes)
    override_rate = round(override_count / max(outcome_count, 1), 2) if outcome_count else 0.0

    guidance = "stable"
    if override_rate >= 0.35:
        guidance = "high_override_pattern"
    elif current_score >= 90 and override_count:
        guidance = "approval_overrides_present"
    elif override_count:
        guidance = "some_override_learning"

    return {
        "override_count": override_count,
        "override_rate": override_rate,
        "status": guidance,
    }


def build_confidence_calibration(display, case_events, global_model_summary=None):
    manual_outcomes = _manual_outcome_events(case_events)
    approval_probability = display.get("approval_probability")
    packet_confidence = display.get("packet_confidence")
    global_model_summary = dict(global_model_summary or {})

    try:
        predicted = float(approval_probability if approval_probability is not None else packet_confidence if packet_confidence is not None else 0.0)
    except Exception:
        predicted = 0.0

    if predicted > 1.0:
        predicted /= 100.0

    actual_approval_rate = 0.0
    approvals = 0
    sample_size = len(manual_outcomes)
    if manual_outcomes:
        approvals = sum(
            1
            for event in manual_outcomes
            if str(event.get("event_status") or "").lower() in SUCCESS_OUTCOMES
        )
        actual_approval_rate = round(approvals / sample_size, 2)

    smoothed_actual = beta_smoothed_rate(approvals, sample_size, alpha=1.0, beta=1.0) if sample_size else None
    interval = wilson_interval(approvals, sample_size)
    delta = round(predicted - smoothed_actual, 2) if smoothed_actual is not None else None
    status = "insufficient_feedback"
    if manual_outcomes:
        lower = interval.get("lower") if interval else None
        upper = interval.get("upper") if interval else None
        if lower is not None and predicted < lower:
            status = "underconfident"
        elif upper is not None and predicted > upper:
            status = "overconfident"
        else:
            status = "calibrated"
    elif global_model_summary.get("available"):
        status = "model_only"

    return {
        "predicted_confidence": round(predicted, 2),
        "actual_approval_rate": actual_approval_rate,
        "smoothed_actual_approval_rate": smoothed_actual,
        "actual_approval_rate_interval": interval,
        "sample_size": sample_size,
        "delta": delta,
        "status": status,
        "global_model_sample_size": global_model_summary.get("sample_size"),
        "global_model_brier_score": global_model_summary.get("brier_score"),
        "global_model_roc_auc": global_model_summary.get("roc_auc"),
        "global_model_ece": global_model_summary.get("ece"),
        "global_model_reliability_band": global_model_summary.get("reliability_band"),
        "global_model_reliability_score": global_model_summary.get("reliability_score"),
    }


def build_rule_adjustment(memory_intelligence, case_events):
    recurring = list(((memory_intelligence or {}).get("recurring_deficiency_detection", {}) or {}).get("recurring_issues", []) or [])
    repeated_current = list(((memory_intelligence or {}).get("recurring_deficiency_detection", {}) or {}).get("repeated_current_issues", []) or [])
    manual_outcomes = _manual_outcome_events(case_events)
    denied_count = sum(
        1
        for event in manual_outcomes
        if str(event.get("event_status") or "").lower() in NEGATIVE_OUTCOMES
    )

    recommendations = []
    if denied_count >= 2:
        recommendations.append("Add stronger pre-submit denial checks for this case pattern.")
    if repeated_current:
        recommendations.append("Promote repeated packet defects into earlier validation prompts.")
    if any("authorization" in issue.lower() for issue in recurring):
        recommendations.append("Move authorization verification earlier in the workflow for similar packets.")
    if any("signature" in issue.lower() for issue in recurring):
        recommendations.append("Increase signature validation sensitivity for this case pattern.")

    return {
        "status": "actionable" if recommendations else "stable",
        "recommendations": recommendations[:5],
    }


def build_suggestion_acceptance(prior_runs, current_result, memory_intelligence):
    previous_fixes = parse_fixes(prior_runs[0]) if prior_runs else []
    resolved_issues = list(((memory_intelligence or {}).get("historical_correction_memory", {}) or {}).get("resolved_issues", []) or [])
    repeated_current = list(((memory_intelligence or {}).get("recurring_deficiency_detection", {}) or {}).get("repeated_current_issues", []) or [])

    accepted_count = min(len(previous_fixes), len(resolved_issues))
    outstanding_count = len(repeated_current)
    status = "insufficient_history"

    if prior_runs:
        if accepted_count >= 3 and outstanding_count <= 1:
            status = "strong"
        elif accepted_count >= 1:
            status = "partial"
        else:
            status = "low"

    return {
        "accepted_fix_count": accepted_count,
        "outstanding_repeat_count": outstanding_count,
        "status": status,
        "current_fix_count": len(_fixes_from_result(current_result)),
    }


def build_correction_patterns(memory_intelligence):
    history = dict((memory_intelligence or {}).get("historical_correction_memory", {}) or {})
    recurring = dict((memory_intelligence or {}).get("recurring_deficiency_detection", {}) or {})

    return {
        "resolved_patterns": list(history.get("resolved_issues", []) or [])[:5],
        "new_patterns": list(history.get("new_issues", []) or [])[:5],
        "repeat_patterns": list(recurring.get("repeated_current_issues", []) or [])[:5],
    }


def build_workflow_learning(prior_runs, triage_intelligence, case_events):
    workflow_counter = Counter(row.get("workflow_queue") for row in prior_runs if row.get("workflow_queue"))
    most_common_queue = workflow_counter.most_common(1)[0][0] if workflow_counter else None

    triage = dict(triage_intelligence or {})
    manual_outcomes = _manual_outcome_events(case_events)
    approvals = sum(
        1
        for event in manual_outcomes
        if str(event.get("event_status") or "").lower() in SUCCESS_OUTCOMES
    )
    recoveries = sum(
        1
        for event in manual_outcomes
        if str(event.get("event_status") or "").lower() in RECOVERY_OUTCOMES
    )

    learned_route = triage.get("staff_match_routing") or "general_packet_reviewer"
    if approvals >= 2 and most_common_queue:
        learned_route = f"{learned_route} via {most_common_queue}"

    return {
        "preferred_queue": most_common_queue,
        "learned_route": learned_route,
        "approval_count": approvals,
        "recovery_count": recoveries,
    }


def build_failure_learning(case_events, memory_intelligence):
    manual_outcomes = _manual_outcome_events(case_events)
    denied = sum(
        1
        for event in manual_outcomes
        if str(event.get("event_status") or "").lower() in NEGATIVE_OUTCOMES
    )
    corrected = sum(
        1
        for event in manual_outcomes
        if str(event.get("event_status") or "").lower() in RECOVERY_OUTCOMES
    )
    recurring = list(((memory_intelligence or {}).get("recurring_deficiency_detection", {}) or {}).get("recurring_issues", []) or [])

    safeguards = []
    if denied:
        safeguards.append("Route similar packets through enhanced pre-submit review.")
    if corrected:
        safeguards.append("Reuse historical correction patterns before resubmission.")
    if recurring:
        safeguards.append(f"Front-load repeated issue checks: {recurring[0]}")

    return {
        "denied_count": denied,
        "corrected_count": corrected,
        "recommended_safeguards": safeguards[:4],
    }


def build_drift_detection(prior_runs, case_events, memory_intelligence):
    risk_drift = dict(((memory_intelligence or {}).get("longitudinal_risk_drift_tracking", {}) or {}))
    manual_outcomes = _manual_outcome_events(case_events)
    recent_outcomes = [str(event.get("event_status") or "").lower() for event in manual_outcomes[:5]]
    prior_scores = [int(row.get("score") or 0) for row in prior_runs[:5]]
    score_series = list(reversed([int(row.get("score") or 0) for row in prior_runs[:12]]))
    score_ewma = ewma_series(score_series, alpha=0.3)
    score_cusum = cusum_series(score_series) if len(score_series) >= 5 else {"signal": "insufficient_data", "positive": [], "negative": [], "target": None}
    denial_series = list(
        reversed([
            1 if str(event.get("event_status") or "").lower() in NEGATIVE_OUTCOMES else 0
            for event in manual_outcomes[:12]
            if str(event.get("event_status") or "").lower() in (NEGATIVE_OUTCOMES | SUCCESS_OUTCOMES | RECOVERY_OUTCOMES | OVERRIDE_OUTCOMES)
        ])
    )
    denial_ewma = ewma_series(denial_series, alpha=0.35) if denial_series else []

    status = "stable"
    if risk_drift.get("direction") == "worsening":
        status = "drifting_negative"
    elif risk_drift.get("direction") == "improving":
        status = "improving"
    elif recent_outcomes.count("denied") >= 2:
        status = "outcome_drift_negative"
    elif score_cusum.get("signal") == "downward_shift":
        status = "score_drift_negative"
    elif score_cusum.get("signal") == "upward_shift":
        status = "score_drift_positive"

    return {
        "status": status,
        "recent_scores": prior_scores,
        "recent_outcomes": recent_outcomes,
        "score_ewma": score_ewma[-5:],
        "score_cusum_signal": score_cusum.get("signal"),
        "score_cusum_target": score_cusum.get("target"),
        "denial_ewma": denial_ewma[-5:],
    }


def build_continuous_refinement(provider_history, case_events, suggestion_acceptance, calibration):
    data_points = len(provider_history) + len(case_events)
    acceptance_status = suggestion_acceptance.get("status")
    calibration_status = calibration.get("status")

    readiness = 0.32
    if data_points >= 12:
        readiness += 0.28
    elif data_points >= 6:
        readiness += 0.18
    elif data_points >= 3:
        readiness += 0.1

    if acceptance_status == "strong":
        readiness += 0.2
    elif acceptance_status == "partial":
        readiness += 0.1

    if calibration_status == "calibrated":
        readiness += 0.12

    readiness = round(min(readiness, 0.98), 2)

    return {
        "readiness_score": readiness,
        "readiness_band": _band_from_score(readiness),
        "data_points": data_points,
    }


def build_learning_intelligence(file_path, result, memory_intelligence=None, triage_intelligence=None):
    result = dict(result or {})
    fields = dict(result.get("fields", {}) or {})
    memory = dict(memory_intelligence or {})

    case_key = build_case_key(fields, file_path=file_path)
    provider_key = build_provider_key(fields)
    prior_runs = get_case_history(case_key, limit=30)
    case_events = get_case_events(case_key, limit=50)
    provider_history = get_provider_history(provider_key, limit=50)
    display = _display(result)
    global_model_summary = summarize_outcome_model(build_outcome_model())

    outcome_feedback = build_outcome_feedback(case_events)
    override_learning = build_override_learning(case_events, result.get("score"))
    calibration = build_confidence_calibration(display, case_events, global_model_summary=global_model_summary)
    rule_adjustment = build_rule_adjustment(memory, case_events)
    suggestion_acceptance = build_suggestion_acceptance(prior_runs, result, memory)
    correction_patterns = build_correction_patterns(memory)
    workflow_learning = build_workflow_learning(prior_runs, triage_intelligence, case_events)
    failure_learning = build_failure_learning(case_events, memory)
    drift_detection = build_drift_detection(prior_runs, case_events, memory)
    continuous_refinement = build_continuous_refinement(
        provider_history,
        case_events,
        suggestion_acceptance,
        calibration,
    )

    return {
        "outcome_feedback_ingestion": outcome_feedback,
        "reviewer_override_learning": override_learning,
        "rule_adjustment_recommendation": rule_adjustment,
        "confidence_calibration_engine": calibration,
        "drift_detection_for_decision_logic": drift_detection,
        "suggestion_acceptance_tracking": suggestion_acceptance,
        "correction_pattern_mining": correction_patterns,
        "workflow_learning_loop": workflow_learning,
        "failure_to_learning_conversion": failure_learning,
        "continuous_intelligence_refinement": continuous_refinement,
        "global_probability_modeling": global_model_summary,
    }
