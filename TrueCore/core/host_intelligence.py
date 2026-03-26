import os

from TrueCore.core.case_memory import build_case_memory, record_packet_analysis, record_packet_event
from TrueCore.core.insight_intelligence import build_insight_intelligence
from TrueCore.core.learning_intelligence import build_learning_intelligence
from TrueCore.core.operator_support import build_operator_support
from TrueCore.core.benchmark_intelligence import build_benchmark_intelligence
from TrueCore.core.triage_intelligence import build_triage_intelligence
from TrueCore.utils.logging_system import log_event


def _safe_list(value, limit=None):
    items = list(value or [])
    if limit is not None:
        return items[:limit]
    return items


def build_host_display(
    memory_intelligence,
    triage_intelligence,
    operator_intelligence,
    learning_intelligence,
    insight_intelligence,
    benchmark_intelligence,
):
    memory = dict(memory_intelligence or {})
    triage = dict(triage_intelligence or {})
    operator = dict(operator_intelligence or {})
    learning = dict(learning_intelligence or {})
    insight = dict(insight_intelligence or {})
    benchmark = dict(benchmark_intelligence or {})

    persistent = dict(memory.get("persistent_case_memory", {}) or {})
    provider = dict(memory.get("provider_relationship_memory", {}) or {})
    drift = dict(memory.get("longitudinal_risk_drift_tracking", {}) or {})
    confidence = dict(memory.get("memory_confidence_scoring", {}) or {})
    recurring = dict(memory.get("recurring_deficiency_detection", {}) or {})
    carryover = dict(memory.get("context_carryover_engine", {}) or {})
    similar_cases = list(memory.get("similar_case_recall", []) or [])

    workbench = dict(operator.get("operator_workbench_layer", {}) or {})
    checklist = dict(operator.get("smart_review_checklist_generation", {}) or {})
    hints = dict(operator.get("productivity_hint_engine", {}) or {})
    escalation = dict(operator.get("escalation_note_drafting", {}) or {})
    outcomes = dict(learning.get("outcome_feedback_ingestion", {}) or {})
    calibration = dict(learning.get("confidence_calibration_engine", {}) or {})
    overrides = dict(learning.get("reviewer_override_learning", {}) or {})
    refinement = dict(learning.get("continuous_intelligence_refinement", {}) or {})
    workflow = dict(learning.get("workflow_learning_loop", {}) or {})
    adjustments = dict(learning.get("rule_adjustment_recommendation", {}) or {})
    hidden_trend = dict(insight.get("hidden_trend_detection", {}) or {})
    high_yield = dict(insight.get("high_yield_improvement_discovery", {}) or {})
    provider_network = dict(insight.get("provider_network_insight_engine", {}) or {})
    benchmark_internal = dict(benchmark.get("internal_benchmark_engine", {}) or {})
    benchmark_quality = dict(benchmark.get("quality_benchmark_calibration", {}) or {})
    benchmark_targets = dict(benchmark.get("improvement_target_modeling", {}) or {})
    benchmark_confidence = dict(benchmark.get("benchmark_confidence_scoring", {}) or {})

    return {
        "prior_case_count": persistent.get("prior_case_count"),
        "last_status": persistent.get("last_status"),
        "last_score": persistent.get("last_score"),
        "memory_confidence": confidence.get("score"),
        "memory_confidence_band": confidence.get("band"),
        "risk_drift": drift.get("direction"),
        "provider_quality_trend": provider.get("quality_trend"),
        "provider_packet_count": provider.get("packet_count"),
        "recurring_issues": _safe_list(recurring.get("recurring_issues"), limit=5),
        "carryover_context": _safe_list(carryover.get("carryover_context"), limit=5),
        "similar_cases": _safe_list(similar_cases, limit=3),
        "triage_priority": triage.get("priority_level"),
        "triage_urgency": triage.get("urgency_classification"),
        "review_depth": triage.get("review_depth_allocation"),
        "staff_route": triage.get("staff_match_routing"),
        "time_to_action": triage.get("time_to_action_scoring"),
        "queue_risk": triage.get("queue_risk_forecasting"),
        "triage_confidence": triage.get("triage_confidence_scoring"),
        "next_operator_focus": _safe_list(workbench.get("next_operator_focus"), limit=5),
        "operator_primary_route": workbench.get("primary_route"),
        "operator_checklist": _safe_list(checklist.get("checklist"), limit=6),
        "productivity_hints": _safe_list(hints.get("hints"), limit=4),
        "escalation_note": escalation.get("note"),
        "latest_outcome": outcomes.get("latest_outcome"),
        "outcome_count": outcomes.get("outcome_count"),
        "calibration_status": calibration.get("status"),
        "calibration_delta": calibration.get("delta"),
        "override_status": overrides.get("status"),
        "override_rate": overrides.get("override_rate"),
        "learning_readiness": refinement.get("readiness_band"),
        "learning_readiness_score": refinement.get("readiness_score"),
        "learned_route": workflow.get("learned_route"),
        "rule_adjustments": _safe_list(adjustments.get("recommendations"), limit=4),
        "reviewer_efficiency": dict(operator.get("reviewer_efficiency_scoring", {}) or {}).get("band"),
        "operator_feedback_loop": _safe_list(dict(operator.get("operator_support_feedback_loop", {}) or {}).get("suggestions"), limit=4),
        "insight_trend": hidden_trend.get("status"),
        "insight_top_opportunities": _safe_list(high_yield.get("opportunities"), limit=4),
        "provider_rank": provider_network.get("provider_rank"),
        "benchmark_standing": benchmark_internal.get("standing"),
        "benchmark_percentile": benchmark_quality.get("score_percentile"),
        "benchmark_target_score": benchmark_targets.get("target_score"),
        "benchmark_confidence": benchmark_confidence.get("band"),
    }


def enrich_result_with_host_intelligence(file_path, result, persist=True):
    if not isinstance(result, dict):
        return result

    try:
        intel = dict(result.get("intel", {}) or {})
        result["intel"] = intel

        memory_intelligence = build_case_memory(file_path, result)
        triage_intelligence = build_triage_intelligence(result, memory_intelligence)
        operator_intelligence = build_operator_support(result, memory_intelligence, triage_intelligence)
        learning_intelligence = build_learning_intelligence(
            file_path,
            result,
            memory_intelligence=memory_intelligence,
            triage_intelligence=triage_intelligence,
        )
        insight_intelligence = build_insight_intelligence(
            result,
            memory_intelligence=memory_intelligence,
        )
        benchmark_intelligence = build_benchmark_intelligence(result)

        intel["memory_intelligence"] = memory_intelligence
        intel["triage_intelligence"] = triage_intelligence
        intel["operator_intelligence"] = operator_intelligence
        intel["learning_intelligence"] = learning_intelligence
        intel["insight_intelligence"] = insight_intelligence
        intel["benchmark_intelligence"] = benchmark_intelligence
        intel["host_display"] = build_host_display(
            memory_intelligence,
            triage_intelligence,
            operator_intelligence,
            learning_intelligence,
            insight_intelligence,
            benchmark_intelligence,
        )

        if persist:
            record_packet_analysis(file_path, result, triage_intelligence=triage_intelligence)
            log_event("host_intelligence_active", os.path.basename(file_path))

        return result
    except Exception as exc:
        log_event("host_intelligence_error", f"{os.path.basename(file_path)} | {exc}")
        return result


def refresh_result_host_intelligence(file_path, result):
    return enrich_result_with_host_intelligence(file_path, result, persist=False)


def record_manual_outcome(file_path, result, outcome, note=""):
    normalized = str(outcome or "").strip().lower().replace(" ", "_")
    if not normalized:
        return result

    details = {
        "score": result.get("score"),
        "workflow_queue": ((result.get("intel", {}) or {}).get("display", {}) or {}).get("workflow_queue"),
        "denial_risk": ((result.get("intel", {}) or {}).get("display", {}) or {}).get("denial_risk"),
    }

    record_packet_event(
        file_path,
        result,
        event_type="manual_outcome",
        event_status=normalized,
        note=note,
        details=details,
    )

    log_event("manual_outcome_recorded", f"{os.path.basename(file_path)} | {normalized}")
    return refresh_result_host_intelligence(file_path, result)
