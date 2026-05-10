from TrueCore.core.cross_office_benchmarking import (
    build_network_rollup,
    build_office_rollup,
    collapse_snapshots_to_latest,
    group_snapshots_by_office,
    load_imported_cross_office_snapshots,
)
from TrueCore.core.cross_office_learning import build_cross_office_snapshot


def _distribution_share(distribution, keys):
    values = dict(distribution or {})
    total = sum(int(value or 0) for value in values.values())
    if total <= 0:
        return 0.0

    selected = 0
    normalized_keys = {str(key or "").strip().lower() for key in keys}
    for label, value in values.items():
        if str(label or "").strip().lower() in normalized_keys:
            selected += int(value or 0)

    return round(selected / total, 4)


def _delta(current_value, previous_value):
    if current_value in (None, "") or previous_value in (None, ""):
        return None

    try:
        return round(float(current_value) - float(previous_value), 2)
    except Exception:
        return None


def _severity_rank(value):
    return {"high": 3, "medium": 2, "low": 1}.get(str(value or "").strip().lower(), 0)


def build_office_trend_history(snapshots):
    histories = []

    for office_key, office_snapshots in group_snapshots_by_office(snapshots).items():
        del office_key
        records = []
        for snapshot in office_snapshots:
            rollup = build_office_rollup(snapshot)
            denial_distribution = dict(rollup.get("denial_risk_distribution") or {})
            workflow_distribution = dict(rollup.get("workflow_distribution") or {})
            records.append(
                {
                    "generated_at": snapshot.get("generated_at"),
                    "office_name": rollup.get("office_name"),
                    "office_id": rollup.get("office_id"),
                    "organization_id": rollup.get("organization_id"),
                    "packet_count": rollup.get("packet_count"),
                    "average_packet_score": rollup.get("average_packet_score"),
                    "average_runtime_seconds": rollup.get("average_runtime_seconds"),
                    "standing": rollup.get("standing"),
                    "high_risk_share": _distribution_share(denial_distribution, {"high", "critical"}),
                    "correction_share": _distribution_share(workflow_distribution, {"correction_queue", "senior_review_queue"}),
                    "top_issues": list(rollup.get("top_issues") or []),
                }
            )

        if not records:
            continue

        current = dict(records[-1])
        previous = dict(records[-2]) if len(records) > 1 else {}
        histories.append(
            {
                "office_name": current.get("office_name"),
                "office_id": current.get("office_id"),
                "organization_id": current.get("organization_id"),
                "history_count": len(records),
                "current": current,
                "previous": previous or None,
                "score_delta": _delta(current.get("average_packet_score"), previous.get("average_packet_score") if previous else None),
                "runtime_delta": _delta(current.get("average_runtime_seconds"), previous.get("average_runtime_seconds") if previous else None),
                "high_risk_share_delta": _delta(current.get("high_risk_share"), previous.get("high_risk_share") if previous else None),
                "correction_share_delta": _delta(current.get("correction_share"), previous.get("correction_share") if previous else None),
            }
        )

    return sorted(
        histories,
        key=lambda item: (
            item.get("current", {}).get("average_packet_score") if item.get("current", {}).get("average_packet_score") is not None else -1,
            item.get("current", {}).get("packet_count") or 0,
        ),
        reverse=True,
    )


def build_cross_office_intelligence(snapshots, rollup=None):
    latest_snapshots = collapse_snapshots_to_latest(snapshots)
    network_rollup = dict(rollup or build_network_rollup(latest_snapshots) or {})
    histories = build_office_trend_history(snapshots)

    network_average_runtime = network_rollup.get("average_runtime_seconds") or 0
    priority_alerts = []

    for office in histories:
        current = dict(office.get("current") or {})
        office_name = current.get("office_name") or current.get("office_id") or "Unknown Office"
        average_score = current.get("average_packet_score")
        high_risk_share = current.get("high_risk_share") or 0
        average_runtime = current.get("average_runtime_seconds") or 0
        score_delta = office.get("score_delta")
        runtime_delta = office.get("runtime_delta")
        top_issues = list(current.get("top_issues") or [])
        leading_issue = top_issues[0][0] if top_issues else "packet quality gaps"

        if average_score is not None and average_score < 70:
            priority_alerts.append(
                {
                    "severity": "high",
                    "office_name": office_name,
                    "title": "Low average packet quality",
                    "message": f"{office_name} is averaging {average_score:.0f}, which is below the current network health target.",
                }
            )

        if high_risk_share >= 0.35:
            priority_alerts.append(
                {
                    "severity": "high",
                    "office_name": office_name,
                    "title": "High denial-risk concentration",
                    "message": f"{office_name} has {int(round(high_risk_share * 100))}% of packets landing in high or critical denial risk.",
                }
            )

        if network_average_runtime and average_runtime >= network_average_runtime * 1.35:
            priority_alerts.append(
                {
                    "severity": "medium",
                    "office_name": office_name,
                    "title": "Slow packet throughput",
                    "message": f"{office_name} is averaging {average_runtime:.1f}s per packet versus the network average of {network_average_runtime:.1f}s.",
                }
            )

        if score_delta is not None and score_delta <= -8:
            priority_alerts.append(
                {
                    "severity": "medium",
                    "office_name": office_name,
                    "title": "Packet quality decline",
                    "message": f"{office_name} dropped {abs(score_delta):.0f} points since its prior snapshot, led by {leading_issue}.",
                }
            )

        if runtime_delta is not None and runtime_delta >= 4:
            priority_alerts.append(
                {
                    "severity": "low",
                    "office_name": office_name,
                    "title": "Runtime drift",
                    "message": f"{office_name} slowed by {runtime_delta:.1f}s versus its prior snapshot.",
                }
            )

    priority_alerts = sorted(
        priority_alerts,
        key=lambda item: (_severity_rank(item.get("severity")), item.get("office_name") or ""),
        reverse=True,
    )

    best_office = histories[0] if histories else None
    watchlist = sorted(
        histories,
        key=lambda item: (
            item.get("current", {}).get("average_packet_score") if item.get("current", {}).get("average_packet_score") is not None else 999,
            -(item.get("current", {}).get("high_risk_share") or 0),
        ),
    )[:5]

    most_improved = sorted(
        [item for item in histories if item.get("score_delta") not in (None, 0)],
        key=lambda item: item.get("score_delta") or 0,
        reverse=True,
    )[:3]

    most_declined = sorted(
        [item for item in histories if item.get("score_delta") not in (None, 0)],
        key=lambda item: item.get("score_delta") or 0,
    )[:3]

    return {
        "generated_at": network_rollup.get("generated_at"),
        "source_snapshot_count": len(list(snapshots or [])),
        "current_office_count": len(latest_snapshots),
        "office_histories": histories,
        "priority_alerts": priority_alerts[:8],
        "watchlist": watchlist,
        "most_improved": most_improved,
        "most_declined": most_declined,
        "network_summary": {
            "best_office": best_office.get("office_name") if best_office else None,
            "network_average_score": network_rollup.get("average_packet_score"),
            "network_average_runtime": network_rollup.get("average_runtime_seconds"),
            "network_average_confidence": network_rollup.get("average_packet_confidence"),
        },
    }


def build_local_cross_office_intelligence(include_current_office=True, imported_directory=None):
    snapshots = load_imported_cross_office_snapshots(directory=imported_directory)

    if include_current_office:
        snapshots.insert(0, build_cross_office_snapshot())

    if not snapshots:
        raise ValueError("No snapshots available to build cross-office intelligence.")

    rollup = build_network_rollup(snapshots)
    return build_cross_office_intelligence(snapshots, rollup=rollup)
