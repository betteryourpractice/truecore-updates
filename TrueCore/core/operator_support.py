def build_checklist(result, triage_intelligence):
    issues = list(result.get("issues", []) or [])
    fixes = list(result.get("fixes", []) or [])
    triage = dict(triage_intelligence or {})

    checklist = []
    seen = set()

    for issue in issues:
        if issue not in seen:
            seen.add(issue)
            checklist.append(f"Verify: {issue}")

    for fix in fixes:
        if fix not in seen:
            seen.add(fix)
            checklist.append(f"Action: {fix}")

    if triage.get("review_depth_allocation") == "senior_review":
        checklist.append("Escalate to senior reviewer before submission.")

    return checklist[:10]


def build_exception_help(result):
    issues = list(result.get("issues", []) or [])
    help_items = []

    for issue in issues:
        lowered = issue.lower()
        if "authorization" in lowered:
            help_items.append("Authorization issues usually block submission first. Confirm the VA number before deeper review.")
        elif "clinical" in lowered or "diagnosis" in lowered:
            help_items.append("Clinical conflicts should be compared against ICD coding and the Letter of Medical Necessity.")
        elif "missing" in lowered and "form" in lowered:
            help_items.append("Missing form issues are usually faster to resolve than narrative conflicts. Group those requests together.")
        elif "signature" in lowered:
            help_items.append("Signature issues should be checked against signed note pages and document footer regions.")

    deduped = []
    seen = set()
    for item in help_items:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)

    return deduped[:5]


def build_productivity_hints(result, memory_intelligence, triage_intelligence):
    hints = []
    memory = dict(memory_intelligence or {})
    triage = dict(triage_intelligence or {})
    recurring = list(memory.get("recurring_deficiency_detection", {}).get("repeated_current_issues", []) or [])

    if recurring:
        hints.append("Start with repeated historical deficiencies first; they are the most likely to delay resubmission again.")

    if triage.get("staff_match_routing") == "document_quality_reviewer":
        hints.append("Use scan diagnostics before manual field review to avoid wasting time on unreadable pages.")

    if triage.get("fast_lane_candidate_detection"):
        hints.append("This packet is a fast-lane candidate. Focus on final verification instead of full deep review.")

    if triage.get("review_depth_allocation") == "senior_review":
        hints.append("Bundle clinical and documentation blockers into one escalation note to avoid multiple handoffs.")

    if not hints:
        hints.append("Address missing authorization, required forms, and major conflicts before secondary cleanup.")

    return hints[:5]


def build_compressed_actions(result):
    fixes = list(result.get("fixes", []) or [])
    missing_docs = []
    missing_fields = []
    conflict_actions = []

    for fix in fixes:
        lowered = fix.lower()
        if "add" in lowered or "attach" in lowered:
            if "form" in lowered or "letter" in lowered or "clinical notes" in lowered or "seoc" in lowered:
                missing_docs.append(fix)
            else:
                missing_fields.append(fix)
        elif "resolve" in lowered or "correct" in lowered:
            conflict_actions.append(fix)

    grouped = []
    if missing_fields:
        grouped.append("Resolve missing fields: " + ", ".join(missing_fields[:4]))
    if missing_docs:
        grouped.append("Collect missing support: " + ", ".join(missing_docs[:5]))
    if conflict_actions:
        grouped.append("Resolve conflicts together: " + ", ".join(conflict_actions[:4]))

    return grouped[:4]


def build_training_tips(result, triage_intelligence):
    issues = list(result.get("issues", []) or [])
    triage = dict(triage_intelligence or {})
    tips = []

    if any("authorization" in issue.lower() for issue in issues):
        tips.append("When authorization is missing, check request-for-service and SEOC pages before assuming the packet truly lacks it.")

    if triage.get("staff_match_routing") == "clinical_reviewer":
        tips.append("Clinical review should compare diagnosis language, ICD support, and requested procedure as one unit.")

    if any("signature" in issue.lower() for issue in issues):
        tips.append("Signature checks should include footer regions and electronically signed phrases, not just visible signature lines.")

    return tips[:4]


def build_escalation_note(result, memory_intelligence, triage_intelligence):
    fields = dict(result.get("fields", {}) or {})
    triage = dict(triage_intelligence or {})
    memory = dict(memory_intelligence or {})
    repeated = list(memory.get("recurring_deficiency_detection", {}).get("repeated_current_issues", []) or [])

    patient_name = fields.get("patient_name") or "Unknown patient"
    auth = fields.get("authorization_number") or "missing"
    diagnosis = fields.get("diagnosis") or "unspecified diagnosis"

    lines = [
        f"Packet for {patient_name} requires {triage.get('review_depth_allocation', 'review')} via {triage.get('staff_match_routing', 'general packet reviewer')}.",
        f"Current authorization status: {auth}. Diagnosis context: {diagnosis}.",
    ]

    if result.get("issues"):
        lines.append("Primary blockers: " + "; ".join(list(result.get("issues", []))[:4]) + ".")

    if repeated:
        lines.append("Repeated historical issues: " + "; ".join(repeated[:3]) + ".")

    if triage.get("time_to_action_scoring"):
        lines.append(f"Recommended turnaround: {triage.get('time_to_action_scoring')}.")

    return " ".join(lines)


def build_reviewer_efficiency(memory_intelligence, triage_intelligence, operator_checklist):
    memory = dict(memory_intelligence or {})
    triage = dict(triage_intelligence or {})
    recurring = list(memory.get("recurring_deficiency_detection", {}).get("repeated_current_issues", []) or [])
    checklist = list(operator_checklist or [])

    score = 0.52
    if triage.get("review_depth_allocation") == "minimal_review":
        score += 0.2
    elif triage.get("review_depth_allocation") == "focused_review":
        score += 0.08
    elif triage.get("review_depth_allocation") == "senior_review":
        score -= 0.12

    if len(checklist) <= 4:
        score += 0.12
    elif len(checklist) >= 8:
        score -= 0.08

    if recurring:
        score += 0.08

    score = round(max(0.2, min(score, 0.97)), 2)
    band = "strong" if score >= 0.78 else "moderate" if score >= 0.58 else "heavy"

    return {
        "score": score,
        "band": band,
        "checklist_length": len(checklist),
    }


def build_work_pattern_analysis(memory_intelligence, triage_intelligence):
    memory = dict(memory_intelligence or {})
    triage = dict(triage_intelligence or {})
    provider = dict(memory.get("provider_relationship_memory", {}) or {})
    outcome_memory = dict(memory.get("outcome_linked_memory_layer", {}) or {})
    recurring = dict(memory.get("recurring_deficiency_detection", {}) or {})

    status_counts = dict(outcome_memory.get("status_counts", {}) or {})
    friction_points = []

    if recurring.get("repeated_current_issues"):
        friction_points.append("Repeated packet defects are still consuming operator time.")
    if provider.get("quality_trend") == "weak":
        friction_points.append("This provider pattern trends weak and may require heavier review.")
    if triage.get("staff_match_routing") == "document_quality_reviewer":
        friction_points.append("Scan quality issues are likely driving review time.")
    if status_counts.get("reviewer_override", 0):
        friction_points.append("Override history suggests manual review pressure remains high.")

    return {
        "dominant_route": triage.get("staff_match_routing"),
        "provider_quality_trend": provider.get("quality_trend"),
        "recent_outcome_mix": status_counts,
        "friction_points": friction_points[:4],
    }


def build_feedback_loop(memory_intelligence, triage_intelligence):
    memory = dict(memory_intelligence or {})
    triage = dict(triage_intelligence or {})
    status_counts = dict(memory.get("outcome_linked_memory_layer", {}).get("status_counts", {}) or {})
    recurring = list(memory.get("recurring_deficiency_detection", {}).get("recurring_issues", []) or [])

    suggestions = []
    if status_counts.get("denied", 0):
        suggestions.append("Show denial-sensitive blockers earlier in the operator checklist.")
    if status_counts.get("reviewer_override", 0):
        suggestions.append("Highlight review-threshold reasoning before operator handoff.")
    if triage.get("staff_match_routing") == "clinical_reviewer":
        suggestions.append("Keep clinical mismatch guidance grouped near diagnosis and procedure conflicts.")
    if recurring:
        suggestions.append("Promote repeated recurring defects into one-click checklist groups.")

    return {
        "status": "adaptive" if suggestions else "stable",
        "suggestions": suggestions[:4],
    }


def build_operator_support(result, memory_intelligence=None, triage_intelligence=None):
    triage = dict(triage_intelligence or {})
    checklist = build_checklist(result, triage)

    return {
        "operator_workbench_layer": {
            "primary_route": triage.get("staff_match_routing"),
            "priority_level": triage.get("priority_level"),
            "review_depth": triage.get("review_depth_allocation"),
            "time_to_action": triage.get("time_to_action_scoring"),
            "next_operator_focus": list(triage.get("next_operator_focus", []) or []),
        },
        "smart_review_checklist_generation": {
            "checklist": checklist,
        },
        "exception_handling_assistant": {
            "items": build_exception_help(result),
        },
        "productivity_hint_engine": {
            "hints": build_productivity_hints(result, memory_intelligence, triage),
        },
        "repetitive_task_compression": {
            "grouped_actions": build_compressed_actions(result),
        },
        "training_by_case_assistance": {
            "tips": build_training_tips(result, triage),
        },
        "escalation_note_drafting": {
            "note": build_escalation_note(result, memory_intelligence, triage),
        },
        "reviewer_efficiency_scoring": build_reviewer_efficiency(
            memory_intelligence,
            triage,
            checklist,
        ),
        "work_pattern_analysis": build_work_pattern_analysis(
            memory_intelligence,
            triage,
        ),
        "operator_support_feedback_loop": build_feedback_loop(
            memory_intelligence,
            triage,
        ),
    }
