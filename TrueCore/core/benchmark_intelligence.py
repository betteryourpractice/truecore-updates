from collections import Counter, defaultdict
from datetime import datetime

from TrueCore.core.case_memory import build_provider_key, get_recent_packet_events, get_recent_packet_runs, parse_issues
from TrueCore.core.statistical_scoring import (
    beta_smoothed_rate,
    build_outcome_model,
    build_turnaround_observations,
    empirical_bayes_average,
    kaplan_meier_curve,
    midrank_percentile,
    summarize_outcome_model,
    wilson_interval,
)


def _parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _band_from_score(score):
    try:
        score = float(score or 0.0)
    except Exception:
        score = 0.0

    if score >= 0.82:
        return "best_in_class"
    if score >= 0.62:
        return "competitive"
    return "below_target"
def build_internal_benchmark(result, all_runs):
    current_score = int(result.get("score", 0) or 0)
    scores = [int(row.get("score") or 0) for row in all_runs]
    average_score = round(sum(scores) / max(len(scores), 1), 1) if scores else None
    best_score = max(scores) if scores else None
    standing = "insufficient_history"

    if average_score is not None:
        if current_score >= average_score + 10:
            standing = "above_average"
        elif current_score <= average_score - 10:
            standing = "below_average"
        else:
            standing = "near_average"

    return {
        "current_score": current_score,
        "average_score": average_score,
        "best_score": best_score,
        "standing": standing,
    }


def build_team_benchmark(result, all_runs):
    fields = dict(result.get("fields", {}) or {})
    current_provider = build_provider_key(fields)
    provider_scores = defaultdict(list)
    all_scores = []

    for row in all_runs:
        score = int(row.get("score") or 0)
        all_scores.append(score)
        provider_key = row.get("provider_key")
        if not provider_key or provider_key == "unknown_provider":
            continue
        provider_scores[provider_key].append(score)

    global_average = round(sum(all_scores) / max(len(all_scores), 1), 1) if all_scores else 0.0

    averages = [
        (
            provider_key,
            round(sum(scores) / max(len(scores), 1), 1),
            empirical_bayes_average(scores, global_average, prior_weight=6.0),
            len(scores),
        )
        for provider_key, scores in provider_scores.items()
    ]
    averages.sort(key=lambda item: (item[2], item[3], item[1]), reverse=True)

    rank = None
    current_average = None
    current_shrunk_average = None
    current_sample_size = 0
    for index, (provider_key, average_score, shrunk_average, sample_size) in enumerate(averages, start=1):
        if provider_key == current_provider:
            rank = index
            current_average = average_score
            current_shrunk_average = shrunk_average
            current_sample_size = sample_size
            break

    return {
        "provider_rank": rank,
        "provider_average_score": current_average,
        "provider_shrunk_average_score": current_shrunk_average,
        "provider_sample_size": current_sample_size,
        "provider_count": len(averages),
        "global_average_score": global_average,
    }


def build_workflow_benchmark(all_runs):
    queue_scores = defaultdict(list)
    for row in all_runs:
        queue = row.get("workflow_queue")
        if queue:
            queue_scores[queue].append(int(row.get("score") or 0))

    workflow_performance = {
        queue: round(sum(scores) / max(len(scores), 1), 1)
        for queue, scores in queue_scores.items()
    }

    best_workflow = None
    if workflow_performance:
        best_workflow = sorted(workflow_performance.items(), key=lambda item: item[1], reverse=True)[0][0]

    return {
        "best_workflow": best_workflow,
        "workflow_performance": workflow_performance,
    }


def build_quality_benchmark(result, all_runs):
    score = int(result.get("score", 0) or 0)
    scores = sorted(int(row.get("score") or 0) for row in all_runs)
    percentile = midrank_percentile(score, scores)

    return {
        "score_percentile": percentile,
        "quality_band": _band_from_score(percentile),
        "sample_size": len(scores),
    }


def build_denial_benchmark(result, all_events):
    manual_events = [
        event
        for event in all_events
        if str(event.get("event_type") or "").lower() == "manual_outcome"
    ]
    denied = sum(1 for event in manual_events if str(event.get("event_status") or "").lower() == "denied")
    sample_size = len(manual_events)
    denial_rate = round(denied / max(sample_size, 1), 2) if manual_events else 0.0
    smoothed_denial_rate = beta_smoothed_rate(denied, sample_size, alpha=1.0, beta=1.0)
    denial_interval = wilson_interval(denied, sample_size)

    return {
        "historical_denial_rate": denial_rate,
        "smoothed_denial_rate": smoothed_denial_rate,
        "historical_denial_rate_interval": denial_interval,
        "sample_size": sample_size,
        "current_denial_risk": ((result.get("intel", {}) or {}).get("display", {}) or {}).get("denial_risk"),
    }


def build_turnaround_benchmark(all_runs, all_events):
    outcomes_by_case = defaultdict(list)
    for event in all_events:
        if str(event.get("event_type") or "").lower() != "manual_outcome":
            continue
        outcomes_by_case[event.get("case_key")].append(event)

    durations = []
    for row in all_runs:
        case_key = row.get("case_key")
        analyzed_at = _parse_ts(row.get("analyzed_at"))
        if not analyzed_at or not outcomes_by_case.get(case_key):
            continue

        latest_event_time = _parse_ts(outcomes_by_case[case_key][0].get("created_at"))
        if latest_event_time and latest_event_time >= analyzed_at:
            durations.append((latest_event_time - analyzed_at).total_seconds() / 3600.0)

    median_hours = None
    if durations:
        ordered = sorted(durations)
        median_hours = round(ordered[len(ordered) // 2], 1)

    return {
        "median_hours_to_outcome": median_hours,
        "sample_count": len(durations),
    }


def build_turnaround_survival_benchmark(all_runs, all_events):
    observations = build_turnaround_observations(all_runs, all_events)
    survival = kaplan_meier_curve(observations)
    return {
        "median_hours_to_outcome": survival.get("median_survival_hours"),
        "sample_size": survival.get("sample_size"),
        "event_count": survival.get("event_count"),
        "censored_count": survival.get("censored_count"),
        "survival_curve": survival.get("curve"),
    }


def build_submission_readiness_benchmark(result, all_runs):
    ready_status = str(((result.get("intel", {}) or {}).get("display", {}) or {}).get("submission_readiness") or "").lower()
    approved_rows = [row for row in all_runs if str(row.get("status") or "").lower() == "approved"]
    approved_average = round(sum(int(row.get("score") or 0) for row in approved_rows) / max(len(approved_rows), 1), 1) if approved_rows else None

    return {
        "current_readiness": ready_status,
        "approved_average_score": approved_average,
    }


def build_complexity_normalized_benchmark(result, all_runs):
    current_complexity = len(result.get("issues", []) or []) + len(result.get("forms", []) or [])
    similar = []
    for row in all_runs:
        issue_count = len(parse_issues(row))
        form_count = len([item for item in str(row.get("forms_text") or "").split("|") if item.strip()])
        complexity = issue_count + form_count
        if abs(complexity - current_complexity) <= 2:
            similar.append(int(row.get("score") or 0))

    similar_average = round(sum(similar) / max(len(similar), 1), 1) if similar else None

    return {
        "current_complexity": current_complexity,
        "similar_case_average_score": similar_average,
    }


def build_improvement_targets(result, internal_benchmark, outcome_benchmark):
    current_score = int(result.get("score", 0) or 0)
    average_score = internal_benchmark.get("average_score") or current_score
    target_score = max(current_score, int(round(average_score + 8)))

    recommendations = []
    if internal_benchmark.get("standing") == "below_average":
        recommendations.append("Raise packet score above the recent system average before submission.")
    if str(outcome_benchmark.get("current_denial_risk") or "").lower() in {"high", "critical"}:
        recommendations.append("Reduce denial-sensitive blockers before final review.")

    return {
        "target_score": target_score,
        "recommendations": recommendations[:4],
    }


def build_benchmark_confidence(all_runs, all_events):
    sample_size = len(all_runs) + len(all_events)
    score = 0.28
    if sample_size >= 120:
        score += 0.5
    elif sample_size >= 60:
        score += 0.35
    elif sample_size >= 20:
        score += 0.18
    elif sample_size >= 8:
        score += 0.1

    score = round(min(score, 0.98), 2)

    return {
        "score": score,
        "band": _band_from_score(score),
        "sample_size": sample_size,
    }


def build_benchmark_intelligence(result):
    result = dict(result or {})
    all_runs = get_recent_packet_runs(limit=280)
    all_events = get_recent_packet_events(limit=280)

    internal = build_internal_benchmark(result, all_runs)
    team = build_team_benchmark(result, all_runs)
    workflow = build_workflow_benchmark(all_runs)
    quality = build_quality_benchmark(result, all_runs)
    denial = build_denial_benchmark(result, all_events)
    turnaround = build_turnaround_benchmark(all_runs, all_events)
    turnaround_survival = build_turnaround_survival_benchmark(all_runs, all_events)
    readiness = build_submission_readiness_benchmark(result, all_runs)
    complexity = build_complexity_normalized_benchmark(result, all_runs)
    targets = build_improvement_targets(result, internal, denial)
    confidence = build_benchmark_confidence(all_runs, all_events)
    outcome_model = summarize_outcome_model(build_outcome_model(all_runs, all_events))

    return {
        "internal_benchmark_engine": internal,
        "team_to_team_benchmarking": team,
        "workflow_benchmark_tracking": workflow,
        "quality_benchmark_calibration": quality,
        "denial_benchmark_comparison": denial,
        "turnaround_benchmark_analysis": turnaround,
        "turnaround_survival_analysis": turnaround_survival,
        "submission_readiness_benchmarking": readiness,
        "complexity_normalized_benchmarking": complexity,
        "improvement_target_modeling": targets,
        "benchmark_confidence_scoring": confidence,
        "approval_outcome_modeling": outcome_model,
    }
