from collections import Counter, defaultdict

from TrueCore.core.case_memory import (
    build_provider_key,
    get_recent_packet_events,
    get_recent_packet_runs,
    parse_issues,
)
from TrueCore.core.statistical_scoring import empirical_bayes_average


def _manual_outcomes(events):
    return [
        event
        for event in events
        if str(event.get("event_type") or "").lower() == "manual_outcome"
    ]


def _current_provider(fields):
    return build_provider_key(fields)


def build_hidden_trend_detection(all_runs):
    recent = all_runs[:20]
    previous = all_runs[20:40]

    recent_avg = round(sum(int(row.get("score") or 0) for row in recent) / max(len(recent), 1), 1) if recent else None
    previous_avg = round(sum(int(row.get("score") or 0) for row in previous) / max(len(previous), 1), 1) if previous else None

    status = "stable"
    if recent_avg is not None and previous_avg is not None:
        if recent_avg <= previous_avg - 6:
            status = "downward"
        elif recent_avg >= previous_avg + 6:
            status = "upward"

    return {
        "status": status,
        "recent_average_score": recent_avg,
        "previous_average_score": previous_avg,
    }


def build_failure_concentration_analysis(all_runs):
    issue_counter = Counter()

    for row in all_runs:
        if str(row.get("status") or "").lower() not in {"rejected", "needs_review"}:
            continue
        issue_counter.update(parse_issues(row))

    return {
        "top_failure_sources": [item for item, _ in issue_counter.most_common(6)],
    }


def build_high_yield_improvement_discovery(failure_concentration, memory_intelligence):
    repeated_current = list(((memory_intelligence or {}).get("recurring_deficiency_detection", {}) or {}).get("repeated_current_issues", []) or [])
    top_failures = list((failure_concentration or {}).get("top_failure_sources", []) or [])

    opportunities = []
    for issue in repeated_current[:3]:
        opportunities.append(f"Fix recurring issue first: {issue}")
    for issue in top_failures[:3]:
        opportunities.append(f"System-wide improvement target: {issue}")

    deduped = []
    seen = set()
    for item in opportunities:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)

    return {
        "opportunities": deduped[:5],
    }


def build_provider_network_insight(fields, all_runs, provider_history):
    current_provider = _current_provider(fields)
    provider_rows = list(provider_history or [])

    provider_averages = defaultdict(list)
    all_scores = []
    for row in all_runs:
        provider_key = row.get("provider_key")
        if not provider_key or provider_key == "unknown_provider":
            continue
        score = int(row.get("score") or 0)
        all_scores.append(score)
        provider_averages[provider_key].append(score)

    global_average = round(sum(all_scores) / max(len(all_scores), 1), 1) if all_scores else 0.0

    provider_rankings = []
    for provider_key, scores in provider_averages.items():
        provider_rankings.append(
            (
                provider_key,
                round(sum(scores) / max(len(scores), 1), 1),
                empirical_bayes_average(scores, global_average, prior_weight=6.0),
                len(scores),
            )
        )

    provider_rankings.sort(key=lambda item: (item[2], item[3], item[1]), reverse=True)
    current_rank = None
    current_avg = None
    current_shrunk_average = None
    current_sample_size = 0
    for index, (provider_key, average_score, shrunk_average, sample_size) in enumerate(provider_rankings, start=1):
        if provider_key == current_provider:
            current_rank = index
            current_avg = average_score
            current_shrunk_average = shrunk_average
            current_sample_size = sample_size
            break

    if current_avg is None and provider_rows:
        current_avg = round(sum(int(row.get("score") or 0) for row in provider_rows) / max(len(provider_rows), 1), 1)
        current_shrunk_average = empirical_bayes_average(
            [int(row.get("score") or 0) for row in provider_rows],
            global_average,
            prior_weight=6.0,
        )
        current_sample_size = len(provider_rows)

    return {
        "current_provider": current_provider,
        "provider_average_score": current_avg,
        "provider_shrunk_average_score": current_shrunk_average,
        "provider_rank": current_rank,
        "provider_count": len(provider_rankings),
        "provider_sample_size": current_sample_size,
    }


def build_packet_composition_analytics(all_runs, current_forms):
    approved_rows = [
        row
        for row in all_runs
        if str(row.get("status") or "").lower() == "approved"
    ]
    approved_counter = Counter()

    for row in approved_rows:
        forms = tuple(sorted(item.strip() for item in str(row.get("forms_text") or "").split("|") if item.strip()))
        if forms:
            approved_counter[forms] += 1

    best_profile = []
    if approved_counter:
        best_profile = list(approved_counter.most_common(1)[0][0])

    current_form_set = set(current_forms or [])
    approved_overlap = len(current_form_set.intersection(best_profile)) if best_profile else 0

    return {
        "best_approved_profile": best_profile[:6],
        "approved_profile_overlap": approved_overlap,
    }


def build_review_behavior_insights(all_events):
    manual = _manual_outcomes(all_events)
    statuses = Counter(str(event.get("event_status") or "").lower() for event in manual if event.get("event_status"))

    return {
        "override_count": statuses.get("reviewer_override", 0),
        "corrected_count": statuses.get("corrected", 0),
        "resubmitted_count": statuses.get("resubmitted", 0),
        "denied_count": statuses.get("denied", 0),
    }


def build_process_variance_detection(all_runs):
    queue_counts = Counter(row.get("workflow_queue") for row in all_runs if row.get("workflow_queue"))
    priority_counts = Counter(row.get("triage_priority") for row in all_runs if row.get("triage_priority"))

    status = "stable"
    if len(queue_counts) >= 4 or len(priority_counts) >= 4:
        status = "high_variance"
    elif len(queue_counts) >= 2 or len(priority_counts) >= 2:
        status = "moderate_variance"

    return {
        "status": status,
        "queue_mix": dict(queue_counts),
        "priority_mix": dict(priority_counts),
    }


def build_outcome_driver_ranking(all_runs):
    driver_counter = Counter()

    for row in all_runs:
        status = str(row.get("status") or "").lower()
        issues = parse_issues(row)
        if status == "rejected":
            driver_counter.update(issues[:4])
        elif status == "needs_review":
            driver_counter.update(issue for issue in issues[:2])

        if str(row.get("scan_quality_band") or "").lower() == "poor":
            driver_counter.update(["Poor scan quality"])
        if str(row.get("denial_risk") or "").lower() in {"high", "critical"}:
            driver_counter.update(["High denial risk"])

    return {
        "ranked_drivers": [item for item, _ in driver_counter.most_common(6)],
    }


def build_strategic_summary(hidden_trend, failure_concentration, provider_network, process_variance):
    summary = []

    if hidden_trend.get("status") == "downward":
        summary.append("Recent packet quality is trending downward against prior runs.")
    elif hidden_trend.get("status") == "upward":
        summary.append("Recent packet quality is trending upward against prior runs.")

    top_failures = list(failure_concentration.get("top_failure_sources", []) or [])
    if top_failures:
        summary.append(f"Top failure source right now: {top_failures[0]}.")

    if provider_network.get("provider_rank") and provider_network.get("provider_count"):
        average_label = "smoothed provider score" if provider_network.get("provider_sample_size", 0) < 6 else "average packet score"
        summary.append(
            f"Current provider stands at rank {provider_network.get('provider_rank')} of {provider_network.get('provider_count')} by {average_label}."
        )

    if process_variance.get("status") != "stable":
        summary.append("Workflow routing variance is elevated across recent packets.")

    return summary[:4]


def build_insight_actions(high_yield, outcome_drivers, process_variance):
    actions = []

    for item in list(high_yield.get("opportunities", []) or [])[:3]:
        actions.append(item)

    drivers = list(outcome_drivers.get("ranked_drivers", []) or [])
    if drivers:
        actions.append(f"Target the leading outcome driver: {drivers[0]}")

    if process_variance.get("status") == "high_variance":
        actions.append("Standardize routing rules to reduce workflow variance.")

    deduped = []
    seen = set()
    for item in actions:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)

    return deduped[:5]


def build_insight_intelligence(result, memory_intelligence=None):
    result = dict(result or {})
    fields = dict(result.get("fields", {}) or {})
    all_runs = get_recent_packet_runs(limit=240)
    all_events = get_recent_packet_events(limit=240)
    provider_rows = [
        row
        for row in all_runs
        if row.get("provider_key") == _current_provider(fields)
    ]

    hidden_trend = build_hidden_trend_detection(all_runs)
    failure_concentration = build_failure_concentration_analysis(all_runs)
    high_yield = build_high_yield_improvement_discovery(failure_concentration, memory_intelligence)
    provider_network = build_provider_network_insight(fields, all_runs, provider_rows)
    packet_composition = build_packet_composition_analytics(all_runs, result.get("forms", []))
    review_behavior = build_review_behavior_insights(all_events)
    process_variance = build_process_variance_detection(all_runs)
    outcome_drivers = build_outcome_driver_ranking(all_runs)
    strategic_summary = build_strategic_summary(
        hidden_trend,
        failure_concentration,
        provider_network,
        process_variance,
    )
    insight_actions = build_insight_actions(high_yield, outcome_drivers, process_variance)

    return {
        "hidden_trend_detection": hidden_trend,
        "failure_concentration_analysis": failure_concentration,
        "high_yield_improvement_discovery": high_yield,
        "provider_network_insight_engine": provider_network,
        "packet_composition_analytics": packet_composition,
        "review_behavior_insights": review_behavior,
        "process_variance_detection": process_variance,
        "outcome_driver_ranking": outcome_drivers,
        "strategic_insight_summarization": strategic_summary,
        "insight_action_recommendation": insight_actions,
    }
