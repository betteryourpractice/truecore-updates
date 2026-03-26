def count_scan_issue_signals(scan_summary):
    scan_summary = dict(scan_summary or {})
    extraction_mode = str(scan_summary.get("extraction_mode") or "").lower()
    count = 0

    if str(scan_summary.get("scan_quality_band") or "").lower() == "poor":
        if extraction_mode not in {"native_text"}:
            count += 2
    if str(scan_summary.get("handwriting_risk_level") or "").lower() == "high":
        count += 2
    if int(scan_summary.get("pages_with_handwritten_regions") or 0) > 0:
        count += 1
    if scan_summary.get("ocr_attempted") and float(scan_summary.get("average_ocr_confidence") or 0.0) < 60:
        count += 1

    return count


def build_triage_intelligence(result, memory_intelligence=None):
    result = dict(result or {})
    intel = dict(result.get("intel", {}) or {})
    display = dict(intel.get("display", {}) or {})
    scan = dict(intel.get("scan_diagnostics", {}) or {})
    scan_summary = dict(scan.get("summary", {}) or {})
    memory = dict(memory_intelligence or {})

    score = int(result.get("score", 0) or 0)
    denial_risk = str(display.get("denial_risk") or "").lower()
    issues = list(result.get("issues", []) or [])
    fixes = list(result.get("fixes", []) or [])
    missing_items = list(display.get("missing_items", []) or [])
    risk_drift = dict(memory.get("longitudinal_risk_drift_tracking", {}) or {})
    prior_case_count = int(memory.get("persistent_case_memory", {}).get("prior_case_count") or 0)

    blockers = 0
    blockers += sum(1 for issue in issues if "missing authorization" in issue.lower())
    blockers += sum(1 for issue in issues if "missing" in issue.lower())
    blockers += sum(1 for issue in issues if "conflict" in issue.lower())
    blockers += count_scan_issue_signals(scan_summary)

    urgency = "routine"
    if denial_risk == "critical" or risk_drift.get("direction") == "worsening":
        urgency = "urgent"
    elif denial_risk == "high" or blockers >= 5:
        urgency = "high"
    elif score >= 90 and blockers <= 1:
        urgency = "fast_lane"

    if urgency == "urgent":
        priority = "P1"
    elif urgency == "high":
        priority = "P2"
    elif urgency == "fast_lane":
        priority = "P0"
    else:
        priority = "P3"

    if priority == "P0":
        review_depth = "minimal_review"
    elif denial_risk in {"critical", "high"} or blockers >= 5:
        review_depth = "senior_review"
    elif blockers >= 3:
        review_depth = "focused_review"
    else:
        review_depth = "standard_review"

    if priority == "P0":
        time_to_action = "same_run"
    elif priority == "P1":
        time_to_action = "within_4_hours"
    elif priority == "P2":
        time_to_action = "within_1_business_day"
    else:
        time_to_action = "within_2_business_days"

    fast_lane_candidate = (
        score >= 92
        and denial_risk in {"", "low"}
        and str(scan_summary.get("scan_quality_band") or "").lower() in {"good", "fair"}
        and len(missing_items) == 0
    )

    if any("clinical" in issue.lower() or "diagnosis" in issue.lower() for issue in issues):
        staff_route = "clinical_reviewer"
    elif count_scan_issue_signals(scan_summary) >= 3:
        staff_route = "document_quality_reviewer"
    elif any("authorization" in issue.lower() or "form" in issue.lower() or "missing" in issue.lower() for issue in issues):
        staff_route = "documentation_specialist"
    elif fast_lane_candidate:
        staff_route = "fast_lane_submission"
    else:
        staff_route = "general_packet_reviewer"

    queue_risk = "safe"
    if urgency == "urgent":
        queue_risk = "delay_sensitive"
    elif blockers >= 4 or count_scan_issue_signals(scan_summary) >= 3:
        queue_risk = "watch"

    triage_confidence = 0.58
    if display.get("packet_confidence") is not None:
        triage_confidence += min(float(display.get("packet_confidence") or 0.0) * 0.25, 0.2)
    if prior_case_count >= 2:
        triage_confidence += 0.08
    if str(scan_summary.get("scan_quality_band") or "").lower() == "poor":
        triage_confidence -= 0.08
    triage_confidence = round(max(0.2, min(triage_confidence, 0.98)), 2)

    deferral_safe = priority == "P3" and queue_risk == "safe" and denial_risk in {"", "low"}

    operational_feed = {
        "queue_bucket": "fast_lane" if priority == "P0" else "escalation" if priority == "P1" else "priority_review" if priority == "P2" else "standard_review",
        "priority_level": priority,
        "urgency": urgency,
        "staff_route": staff_route,
    }

    return {
        "urgency_classification": urgency,
        "priority_escalation_matrix": operational_feed["queue_bucket"],
        "priority_level": priority,
        "review_depth_allocation": review_depth,
        "time_to_action_scoring": time_to_action,
        "fast_lane_candidate_detection": fast_lane_candidate,
        "queue_risk_forecasting": queue_risk,
        "staff_match_routing": staff_route,
        "triage_confidence_scoring": triage_confidence,
        "deferral_safety_check": deferral_safe,
        "operational_urgency_dashboard_feed": operational_feed,
        "blocking_issue_count": blockers,
        "next_operator_focus": fixes[:3] or issues[:3],
    }
