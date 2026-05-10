from collections import Counter

from TrueCore.core.statistical_scoring import (
    beta_smoothed_rate,
    build_result_feature_map,
    clamp,
    predict_outcome_probability,
    safe_float,
)


SUCCESS_OUTCOMES = {"approved"}
NEGATIVE_OUTCOMES = {"denied"}
TERMINAL_OUTCOMES = SUCCESS_OUTCOMES | NEGATIVE_OUTCOMES
RECOVERY_OUTCOMES = {"corrected", "resubmitted"}
OVERRIDE_OUTCOMES = {"reviewer_override"}


def _manual_outcomes(events):
    return [
        event
        for event in list(events or [])
        if str(event.get("event_type") or "").lower() == "manual_outcome"
    ]


def _normalize_probability(value):
    if value in (None, "", [], {}):
        return None
    numeric = safe_float(value, None)
    if numeric is None:
        return None
    if numeric > 1.0:
        numeric /= 100.0
    return clamp(numeric)


def _latest_terminal_outcome_by_case(events):
    latest = {}
    for event in _manual_outcomes(events):
        case_key = event.get("case_key")
        status = str(event.get("event_status") or "").lower()
        created_at = str(event.get("created_at") or "")
        if not case_key or status not in TERMINAL_OUTCOMES:
            continue
        current = latest.get(case_key)
        if current is None or created_at >= str(current.get("created_at") or ""):
            latest[case_key] = event
    return latest


def _maturity_band(score):
    score = safe_float(score, 0.0)
    if score >= 0.82:
        return "strong"
    if score >= 0.6:
        return "moderate"
    return "early"


def build_predictive_outcome_modeling(result, model, model_summary):
    result = dict(result or {})
    display = dict(((result.get("intel", {}) or {}).get("display", {}) or {}))
    engine_probability = _normalize_probability(
        display.get("approval_probability")
        if display.get("approval_probability") is not None
        else display.get("packet_confidence")
    )
    prediction = predict_outcome_probability(model, build_result_feature_map(result))
    model_summary = dict(model_summary or {})

    if not prediction.get("available"):
        return {
            "status": "insufficient_labeled_history",
            "engine_probability": round(engine_probability, 4) if engine_probability is not None else None,
            "learned_approval_probability": None,
            "blended_probability": round(engine_probability, 4) if engine_probability is not None else None,
            "agreement_status": "model_unavailable",
            "honesty_band": "early",
            "reliability_score": None,
            "reliability_band": None,
            "sample_size": model_summary.get("sample_size", 0),
            "delta": None,
            "blend_weight": 0.0,
        }

    learned_probability = _normalize_probability(prediction.get("calibrated_probability"))
    raw_probability = _normalize_probability(prediction.get("raw_probability"))
    reliability_score = safe_float(prediction.get("reliability_score"), 0.0)
    reliability_band = prediction.get("reliability_band")
    sample_size = int(model_summary.get("sample_size") or 0)
    sample_factor = min(sample_size / 80.0, 1.0)
    blend_weight = round(min((reliability_score * 0.7) + (sample_factor * 0.3), 0.85), 3)

    if engine_probability is None:
        blended_probability = learned_probability
        delta = None
        agreement_status = "model_only"
    else:
        blended_probability = clamp((engine_probability * (1.0 - blend_weight)) + (learned_probability * blend_weight))
        delta = round(learned_probability - engine_probability, 4)
        absolute_delta = abs(delta)
        if absolute_delta <= 0.06:
            agreement_status = "aligned"
        elif absolute_delta <= 0.15:
            agreement_status = "watch"
        else:
            agreement_status = "divergent"

    honesty_band = "early"
    if reliability_score >= 0.78 and sample_size >= 30:
        honesty_band = "credible"
    elif reliability_score >= 0.55 and sample_size >= 12:
        honesty_band = "developing"
    elif sample_size >= 6:
        honesty_band = "cautious"

    status = "stable"
    if agreement_status == "divergent":
        status = "prediction_divergence"
    elif honesty_band in {"early", "cautious"}:
        status = "learning_in_progress"

    return {
        "status": status,
        "engine_probability": round(engine_probability, 4) if engine_probability is not None else None,
        "raw_learned_probability": round(raw_probability, 4) if raw_probability is not None else None,
        "learned_approval_probability": round(learned_probability, 4) if learned_probability is not None else None,
        "blended_probability": round(blended_probability, 4) if blended_probability is not None else None,
        "agreement_status": agreement_status,
        "honesty_band": honesty_band,
        "reliability_score": round(reliability_score, 2) if reliability_score is not None else None,
        "reliability_band": reliability_band,
        "sample_size": sample_size,
        "delta": delta,
        "blend_weight": blend_weight,
    }


def build_outcome_learning_health(events, model_summary):
    manual_outcomes = _manual_outcomes(events)
    status_counts = Counter(
        str(event.get("event_status") or "").lower()
        for event in manual_outcomes
        if event.get("event_status")
    )
    terminal_events = [
        event
        for event in manual_outcomes
        if str(event.get("event_status") or "").lower() in TERMINAL_OUTCOMES
    ]
    terminal_count = len(terminal_events)
    approvals = sum(
        1
        for event in terminal_events
        if str(event.get("event_status") or "").lower() in SUCCESS_OUTCOMES
    )
    denials = sum(
        1
        for event in terminal_events
        if str(event.get("event_status") or "").lower() in NEGATIVE_OUTCOMES
    )

    smoothed_approval_rate = beta_smoothed_rate(approvals, terminal_count, alpha=1.0, beta=1.0) if terminal_count else None
    model_summary = dict(model_summary or {})
    reliability_score = safe_float(model_summary.get("reliability_score"), 0.0)
    ece_value = model_summary.get("ece")
    ece = safe_float(ece_value, 0.0) if ece_value not in (None, "", [], {}) else None
    sample_size = int(model_summary.get("sample_size") or 0)

    maturity_score = 0.24
    if sample_size >= 40:
        maturity_score += 0.32
    elif sample_size >= 20:
        maturity_score += 0.22
    elif sample_size >= 10:
        maturity_score += 0.14
    elif sample_size >= 5:
        maturity_score += 0.08

    maturity_score += min(reliability_score, 1.0) * 0.28
    if ece is not None:
        maturity_score += max(0.0, 0.16 * (1.0 - min(ece / 0.25, 1.0)))
    if terminal_count >= 6:
        maturity_score += 0.08
    maturity_score = round(min(maturity_score, 0.98), 2)

    return {
        "manual_outcome_count": len(manual_outcomes),
        "labeled_sample_size": sample_size,
        "terminal_outcome_count": terminal_count,
        "approval_count": approvals,
        "denial_count": denials,
        "correction_count": int(status_counts.get("corrected", 0)),
        "resubmission_count": int(status_counts.get("resubmitted", 0)),
        "override_count": int(status_counts.get("reviewer_override", 0)),
        "deferred_count": int(status_counts.get("deferred", 0)),
        "status_counts": dict(status_counts),
        "smoothed_approval_rate": smoothed_approval_rate,
        "reliability_score": round(reliability_score, 2) if reliability_score is not None else None,
        "reliability_band": model_summary.get("reliability_band"),
        "brier_score": model_summary.get("brier_score"),
        "log_loss": model_summary.get("log_loss"),
        "roc_auc": model_summary.get("roc_auc"),
        "ece": model_summary.get("ece"),
        "maturity_score": maturity_score,
        "maturity_band": _maturity_band(maturity_score),
    }


def build_provider_outcome_learning(provider_key, provider_history, events, model_summary):
    provider_key = str(provider_key or "").strip().lower()
    if not provider_key or provider_key == "unknown_provider":
        return {
            "status": "unknown_provider",
            "terminal_case_count": 0,
            "provider_smoothed_approval_rate": None,
            "global_approval_rate": model_summary.get("positive_rate"),
            "delta_vs_global": None,
            "recent_signal": "insufficient_feedback",
        }

    latest_terminal = _latest_terminal_outcome_by_case(events)
    provider_cases = [row.get("case_key") for row in list(provider_history or []) if row.get("case_key")]
    provider_terminal_events = [
        latest_terminal[case_key]
        for case_key in provider_cases
        if case_key in latest_terminal
    ]

    terminal_case_count = len(provider_terminal_events)
    approvals = sum(
        1
        for event in provider_terminal_events
        if str(event.get("event_status") or "").lower() in SUCCESS_OUTCOMES
    )
    smoothed_provider_rate = beta_smoothed_rate(approvals, terminal_case_count, alpha=1.0, beta=1.0) if terminal_case_count else None
    global_rate = _normalize_probability(model_summary.get("positive_rate"))
    delta_vs_global = None
    if smoothed_provider_rate is not None and global_rate is not None:
        delta_vs_global = round(smoothed_provider_rate - global_rate, 3)

    recent_statuses = [
        str(event.get("event_status") or "").lower()
        for event in provider_terminal_events[:5]
    ]
    if recent_statuses.count("denied") >= 2:
        recent_signal = "recent_denial_cluster"
    elif recent_statuses.count("approved") >= 3:
        recent_signal = "recent_approval_cluster"
    elif recent_statuses:
        recent_signal = "mixed_recent_feedback"
    else:
        recent_signal = "insufficient_feedback"

    if terminal_case_count < 4:
        status = "insufficient_feedback"
    elif delta_vs_global is not None and delta_vs_global >= 0.1:
        status = "outperforming"
    elif delta_vs_global is not None and delta_vs_global <= -0.1:
        status = "underperforming"
    else:
        status = "near_baseline"

    return {
        "status": status,
        "terminal_case_count": terminal_case_count,
        "provider_smoothed_approval_rate": smoothed_provider_rate,
        "global_approval_rate": global_rate,
        "delta_vs_global": delta_vs_global,
        "recent_signal": recent_signal,
    }


def build_prediction_watchpoints(predictive_modeling, calibration, provider_outcome_learning, outcome_learning_health=None):
    predictive_modeling = dict(predictive_modeling or {})
    calibration = dict(calibration or {})
    provider_outcome_learning = dict(provider_outcome_learning or {})
    outcome_learning_health = dict(outcome_learning_health or {})

    items = []
    if predictive_modeling.get("agreement_status") == "divergent":
        items.append("Learned outcome probability materially diverges from the packet engine approval signal.")
    if predictive_modeling.get("honesty_band") in {"early", "cautious"}:
        items.append("Outcome learning is still maturing; treat learned probability as directional support.")
    if calibration.get("status") == "overconfident":
        items.append("Recent real outcomes suggest the current confidence framing is too optimistic.")
    elif calibration.get("status") == "underconfident":
        items.append("Recent real outcomes suggest the current confidence framing is too conservative.")
    if provider_outcome_learning.get("status") == "underperforming":
        items.append("Current provider is trending below the broader learned approval baseline.")
    if provider_outcome_learning.get("recent_signal") == "recent_denial_cluster":
        items.append("Provider history shows a recent cluster of denials that should raise review attention.")
    if outcome_learning_health.get("maturity_band") == "early":
        items.append("The labeled outcome pool is still small, so prediction reliability should be communicated cautiously.")

    return {
        "status": "attention" if items else "stable",
        "items": items[:6],
    }


def build_predictive_learning_snapshot(all_runs, all_events):
    from TrueCore.core.statistical_scoring import build_outcome_model, summarize_outcome_model

    model = build_outcome_model(all_runs=all_runs, all_events=all_events)
    model_summary = summarize_outcome_model(model)
    return {
        "model": model,
        "model_summary": model_summary,
        "outcome_learning_health": build_outcome_learning_health(all_events, model_summary),
    }
