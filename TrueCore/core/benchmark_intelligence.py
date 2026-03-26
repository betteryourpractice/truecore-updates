from collections import Counter, defaultdict
from datetime import datetime

from TrueCore.core.case_memory import build_provider_key, get_recent_packet_events, get_recent_packet_runs, parse_issues


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

    for row in all_runs:
        provider_key = row.get("provider_key")
        if not provider_key or provider_key == "unknown_provider":
            continue
        provider_scores[provider_key].append(int(row.get("score") or 0))

    averages = [
        (provider_key, round(sum(scores) / max(len(scores), 1), 1))
        for provider_key, scores in provider_scores.items()
    ]
    averages.sort(key=lambda item: item[1], reverse=True)

    rank = None
    current_average = None
    for index, (provider_key, average_score) in enumerate(averages, start=1):
        if provider_key == current_provider:
            rank = index
            current_average = average_score
            break

    return {
        "provider_rank": rank,
        "provider_average_score": current_average,
        "provider_count": len(averages),
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
    percentile = 0
    if scores:
        below = sum(1 for item in scores if item <= score)
        percentile = round(below / len(scores), 2)

    return {
        "score_percentile": percentile,
        "quality_band": _band_from_score(percentile),
    }


def build_denial_benchmark(result, all_events):
    manual_events = [
        event
        for event in all_events
        if str(event.get("event_type") or "").lower() == "manual_outcome"
    ]
    denied = sum(1 for event in manual_events if str(event.get("event_status") or "").lower() == "denied")
    denial_rate = round(denied / max(len(manual_events), 1), 2) if manual_events else 0.0

    return {
        "historical_denial_rate": denial_rate,
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
    readiness = build_submission_readiness_benchmark(result, all_runs)
    complexity = build_complexity_normalized_benchmark(result, all_runs)
    targets = build_improvement_targets(result, internal, denial)
    confidence = build_benchmark_confidence(all_runs, all_events)

    return {
        "internal_benchmark_engine": internal,
        "team_to_team_benchmarking": team,
        "workflow_benchmark_tracking": workflow,
        "quality_benchmark_calibration": quality,
        "denial_benchmark_comparison": denial,
        "turnaround_benchmark_analysis": turnaround,
        "submission_readiness_benchmarking": readiness,
        "complexity_normalized_benchmarking": complexity,
        "improvement_target_modeling": targets,
        "benchmark_confidence_scoring": confidence,
    }
