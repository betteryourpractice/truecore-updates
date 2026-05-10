class ReviewPredictiveMixin:
    def build_predictive_intelligence(self, packet, submission_decision, decision_intelligence):
        procedure_fit = decision_intelligence["procedure_to_documentation_fit"]
        success_pattern = decision_intelligence["packet_success_pattern_match"]
        denial_risk = decision_intelligence["denial_risk_prediction"]
        workflow_route = decision_intelligence["workflow_decision_routing"]
        missing_evidence = decision_intelligence["missing_evidence_recommendations"]
        escalation = decision_intelligence["escalation_trigger"]
        packet_type = decision_intelligence["packet_type"]

        case_complexity = self.build_case_complexity_scoring(
            packet,
            submission_decision,
            procedure_fit,
        )
        bottleneck_detection = self.build_bottleneck_detection(
            packet,
            submission_decision,
            workflow_route,
            procedure_fit,
            missing_evidence,
        )
        provider_performance = self.build_provider_performance_prediction(packet, case_complexity)
        approval_outcome = self.build_approval_outcome_prediction(
            packet,
            submission_decision,
            denial_risk,
            success_pattern,
            case_complexity,
        )
        denial_reason_forecasting = self.build_denial_reason_forecasting(
            packet,
            denial_risk,
            procedure_fit,
            missing_evidence,
        )
        volume_trend = self.build_volume_trend_prediction(
            packet,
            packet_type,
            workflow_route,
            case_complexity,
        )
        staffing_demand = self.build_staffing_demand_forecasting(
            packet,
            workflow_route,
            case_complexity,
            volume_trend,
        )
        turnaround_prediction = self.build_turnaround_time_prediction(
            packet,
            submission_decision,
            workflow_route,
            denial_risk,
            case_complexity,
            bottleneck_detection,
        )
        submission_timing = self.build_submission_timing_optimization(
            packet,
            submission_decision,
            workflow_route,
            turnaround_prediction,
            case_complexity,
        )
        predictive_escalation = self.build_predictive_escalation(
            packet,
            submission_decision,
            denial_risk,
            escalation,
            case_complexity,
            bottleneck_detection,
            provider_performance,
        )

        return {
            "approval_outcome_prediction": approval_outcome,
            "turnaround_time_prediction": turnaround_prediction,
            "bottleneck_detection": bottleneck_detection,
            "provider_performance_prediction": provider_performance,
            "denial_reason_forecasting": denial_reason_forecasting,
            "volume_trend_prediction": volume_trend,
            "staffing_demand_forecasting": staffing_demand,
            "submission_timing_optimization": submission_timing,
            "case_complexity_scoring": case_complexity,
            "predictive_escalation": predictive_escalation,
        }

    def build_case_complexity_scoring(self, packet, submission_decision, procedure_fit):
        score = 8
        drivers = []
        actionable_flags = [
            flag
            for flag in packet.review_flags
            if flag != "manual_review_required"
        ]
        high_conflicts = sum(1 for conflict in packet.conflicts if conflict.get("severity") == "high")
        medium_conflicts = sum(1 for conflict in packet.conflicts if conflict.get("severity") == "medium")
        low_conflicts = sum(1 for conflict in packet.conflicts if conflict.get("severity") == "low")

        if len(packet.detected_documents) >= 4:
            score += 10
            drivers.append("Multiple document types increase packet coordination complexity.")
        elif len(packet.detected_documents) >= 2:
            score += 5
            drivers.append("Packet spans more than one document type.")

        if len(packet.pages) >= 25:
            score += 10
            drivers.append("Large packet size increases review complexity.")
        elif len(packet.pages) >= 8:
            score += 5
            drivers.append("Packet has enough pages to require broader page-level review.")

        if packet.missing_documents:
            score += min(24, 10 * len(packet.missing_documents))
            drivers.append("Missing required documents create completion complexity.")

        if packet.missing_fields:
            score += min(18, 6 * len(packet.missing_fields))
            drivers.append("Missing fields increase correction and validation effort.")

        if high_conflicts:
            score += min(28, 18 * high_conflicts)
            drivers.append("High-severity conflicts materially increase case risk.")
        if medium_conflicts:
            score += min(20, 9 * medium_conflicts)
            drivers.append("Medium-severity conflicts increase review workload.")
        if low_conflicts:
            score += min(8, 4 * low_conflicts)
            drivers.append("Low-severity conflicts still add cleanup overhead.")

        if actionable_flags:
            score += min(16, 4 * len(actionable_flags))
            drivers.append("Clinical review flags add reasoning complexity.")

        if packet.duplicate_pages:
            score += 6
            drivers.append("Duplicate-page cleanup increases packet handling effort.")

        if "chronology_review_needed" in packet.review_flags:
            score += 8
            drivers.append("Chronology issues add timeline validation work.")

        if procedure_fit["status"] == "weak":
            score += 14
            drivers.append("Weak procedure support makes the packet clinically complex.")
        elif procedure_fit["status"] == "moderate":
            score += 6
            drivers.append("Moderate procedure support still requires more reviewer judgment.")

        if packet.packet_confidence is not None and packet.packet_confidence < 0.75:
            score += 8
            drivers.append("Lower packet confidence increases verification burden.")

        if submission_decision["readiness"] == "hold":
            score += 10
            drivers.append("Hold status indicates operationally complex correction work.")
        elif submission_decision["readiness"] == "requires_review":
            score += 4
            drivers.append("Reviewer routing adds operational complexity.")

        score = max(5, min(score, 100))
        if score >= 76:
            level = "critical"
        elif score >= 56:
            level = "high"
        elif score >= 31:
            level = "moderate"
        else:
            level = "low"

        return {
            "score": score,
            "level": level,
            "drivers": self.unique_preserve_order(drivers),
            "summary": {
                "critical": "Packet is operationally complex and likely to demand senior or multi-step handling.",
                "high": "Packet carries high coordination and review complexity.",
                "moderate": "Packet has moderate complexity with manageable but real review burden.",
                "low": "Packet complexity is low and should move predictably through routine handling.",
            }[level],
        }

    def build_approval_outcome_prediction(self, packet, submission_decision, denial_risk, success_pattern, case_complexity):
        modeling = dict((packet.metrics or {}).get("statistical_outcome_modeling", {}) or {})
        forecast_probability = packet.approval_probability if packet.approval_probability is not None else 0.5
        forecast_probability += (success_pattern.get("match_score", 0.5) - 0.5) * 0.14
        forecast_probability += ((packet.packet_confidence or 0.8) - 0.7) * 0.2
        forecast_probability -= max(0.0, denial_risk.get("risk_score", 0.5) - 0.35) * 0.22
        forecast_probability -= (case_complexity.get("score", 40) / 100.0) * 0.08

        if submission_decision["readiness"] == "hold":
            forecast_probability -= 0.15
        elif submission_decision["readiness"] == "requires_review":
            forecast_probability -= 0.06

        if packet.missing_documents:
            forecast_probability -= min(0.18, 0.08 * len(packet.missing_documents))
        if any(conflict.get("severity") == "high" for conflict in packet.conflicts):
            forecast_probability = min(forecast_probability, 0.38)

        forecast_probability = round(max(0.02, min(forecast_probability, 0.99)), 2)
        if forecast_probability >= 0.9:
            level = "very_likely"
        elif forecast_probability >= 0.75:
            level = "likely"
        elif forecast_probability >= 0.55:
            level = "possible"
        elif forecast_probability >= 0.35:
            level = "unlikely"
        else:
            level = "very_unlikely"

        confidence = 0.52 + (success_pattern.get("confidence", 0.6) * 0.28) + ((packet.packet_confidence or 0.8) * 0.14)
        confidence = round(max(0.25, min(confidence, 0.97)), 2)

        drivers = []
        if success_pattern.get("similarity") in {"strong", "moderate"}:
            drivers.append("Packet shape remains aligned with known successful submission patterns.")
        if packet.packet_confidence is not None and packet.packet_confidence >= 0.82:
            drivers.append("Packet confidence is strong enough to support a cleaner forecast.")
        if denial_risk.get("level") in {"high", "critical"}:
            drivers.append("Denial risk remains a strong negative approval driver.")
        if packet.missing_documents:
            drivers.append("Missing required documents still materially suppress approval likelihood.")
        if case_complexity.get("level") in {"high", "critical"}:
            drivers.append("Higher case complexity lowers forecast certainty.")
        if modeling.get("available") and modeling.get("reliability_band") in {"moderate", "high"}:
            calibrated_probability = modeling.get("calibrated_probability")
            if calibrated_probability is not None and calibrated_probability >= 0.7:
                drivers.append("Historical outcome modeling supports approval likelihood for similar packets.")
            elif calibrated_probability is not None and calibrated_probability <= 0.4:
                drivers.append("Historical outcome modeling still sees lower approval odds for similar packets.")

        return {
            "level": level,
            "forecast_probability": forecast_probability,
            "confidence": confidence,
            "drivers": self.unique_preserve_order(drivers),
            "summary": f"Forecasted approval likelihood is {level.replace('_', ' ')} based on readiness, denial risk, packet confidence, and successful-pattern similarity.",
            "statistical_modeling": {
                "available": bool(modeling.get("available")),
                "heuristic_probability": modeling.get("heuristic_probability"),
                "calibrated_probability": modeling.get("calibrated_probability"),
                "final_probability": modeling.get("final_probability"),
                "blend_weight": modeling.get("blend_weight"),
                "reliability_band": modeling.get("reliability_band"),
                "reliability_score": modeling.get("reliability_score"),
                "sample_size": modeling.get("sample_size"),
                "brier_score": modeling.get("brier_score"),
                "roc_auc": modeling.get("roc_auc"),
                "ece": modeling.get("ece"),
            },
        }

    def build_turnaround_time_prediction(self, packet, submission_decision, workflow_route, denial_risk, case_complexity, bottleneck_detection):
        queue = workflow_route.get("queue", "review_queue")
        prep_hours = self.TURNAROUND_QUEUE_HOURS.get(queue, 24)
        prep_hours += len(packet.missing_documents) * 14
        prep_hours += len(packet.missing_fields) * 5
        prep_hours += sum(18 for conflict in packet.conflicts if conflict.get("severity") == "high")
        prep_hours += sum(9 for conflict in packet.conflicts if conflict.get("severity") == "medium")
        prep_hours += 10 if any(stage.get("severity") == "high" for stage in bottleneck_detection.get("stages", [])) else 0
        prep_hours += 8 if denial_risk.get("level") in {"high", "critical"} else 0
        prep_hours += round(case_complexity.get("score", 40) * 0.32)

        if submission_decision["readiness"] == "ready":
            prep_hours = max(4, prep_hours - 10)

        final_hours = prep_hours + self.FINAL_DECISION_BUFFER_HOURS.get(queue, 48)
        final_hours = max(final_hours, prep_hours + 12)

        if final_hours <= 24:
            band = "same_day"
        elif final_hours <= 72:
            band = "one_to_three_days"
        elif final_hours <= 168:
            band = "three_to_seven_days"
        else:
            band = "over_one_week"

        return {
            "queue": queue,
            "estimated_submission_ready_hours": int(prep_hours),
            "estimated_final_decision_hours": int(final_hours),
            "band": band,
            "summary": {
                "same_day": "Packet should be operationally ready within the same business day.",
                "one_to_three_days": "Packet is likely to clear review and operational handling within one to three days.",
                "three_to_seven_days": "Packet will likely require a multi-day correction or review cycle.",
                "over_one_week": "Packet is likely to need extended handling before a final submission outcome.",
            }[band],
        }

    def build_bottleneck_detection(self, packet, submission_decision, workflow_route, procedure_fit, missing_evidence):
        stages = []

        if packet.missing_documents:
            stages.append({
                "stage": "document_collection",
                "severity": "high",
                "reason": f"Missing required documents: {', '.join(sorted(packet.missing_documents))}.",
            })

        if packet.missing_fields:
            stages.append({
                "stage": "field_completion",
                "severity": "medium" if not packet.missing_documents else "high",
                "reason": f"Missing required fields: {', '.join(packet.missing_fields)}.",
            })

        if packet.conflicts:
            highest = "low"
            if any(conflict.get("severity") == "high" for conflict in packet.conflicts):
                highest = "high"
            elif any(conflict.get("severity") == "medium" for conflict in packet.conflicts):
                highest = "medium"
            stages.append({
                "stage": "conflict_resolution",
                "severity": highest,
                "reason": "Cross-document conflicts are slowing packet clearance.",
            })

        if procedure_fit["status"] in {"moderate", "weak"}:
            stages.append({
                "stage": "clinical_support",
                "severity": "high" if procedure_fit["status"] == "weak" else "medium",
                "reason": procedure_fit["summary"],
            })

        if workflow_route.get("queue") == "senior_review_queue":
            stages.append({
                "stage": "senior_review",
                "severity": "high",
                "reason": "Senior review routing adds escalation latency.",
            })
        elif submission_decision["readiness"] == "requires_review":
            stages.append({
                "stage": "review_queue",
                "severity": "medium",
                "reason": "Reviewer confirmation is required before submission can proceed.",
            })

        if not stages and missing_evidence:
            stages.append({
                "stage": "submission_clearance",
                "severity": "low",
                "reason": missing_evidence[0].get("why", "Packet needs minor evidence cleanup before routine submission."),
            })

        severity_order = {"high": 0, "medium": 1, "low": 2}
        ordered = sorted(stages, key=lambda item: (severity_order.get(item["severity"], 3), item["stage"]))
        primary_stage = ordered[0]["stage"] if ordered else "clear"

        return {
            "primary_stage": primary_stage,
            "stages": ordered,
            "summary": ordered[0]["reason"] if ordered else "No material operational bottleneck is currently predicted.",
        }

    def build_provider_performance_prediction(self, packet, case_complexity):
        provider_values = []
        for key in ("provider", "ordering_provider", "referring_provider"):
            value = packet.fields.get(key)
            if value and value not in provider_values:
                provider_values.append(value)

        provider_conflicts = [
            conflict for conflict in packet.conflicts
            if conflict.get("field") in {"provider", "ordering_provider", "referring_provider"}
        ]

        provider_score = 0.25 if not provider_values else 0.58
        if provider_values:
            provider_score += min(0.14, 0.07 * len(provider_values))
        if packet.fields.get("signature_present") is True:
            provider_score += 0.14
        if packet.field_confidence.get("provider", 0) >= 0.9 or packet.field_confidence.get("ordering_provider", 0) >= 0.9:
            provider_score += 0.08
        if provider_conflicts:
            provider_score -= 0.28
        if any(doc in packet.detected_documents for doc in {"cover_sheet", "consult_request", "lomn"}) and not provider_values:
            provider_score -= 0.12
        if case_complexity.get("level") in {"high", "critical"} and provider_conflicts:
            provider_score -= 0.08

        provider_score = round(max(0.05, min(provider_score, 0.97)), 2)
        if provider_score >= 0.82:
            level = "reliable"
        elif provider_score >= 0.62:
            level = "generally_reliable"
        elif provider_score >= 0.4:
            level = "variable"
        else:
            level = "at_risk"

        drivers = []
        if provider_values:
            drivers.append("Provider identity is present in the packet.")
        if packet.fields.get("signature_present") is True:
            drivers.append("Signature evidence strengthens provider reliability.")
        if provider_conflicts:
            drivers.append("Provider-role conflicts reduce confidence in provider reliability.")
        if not provider_values:
            drivers.append("Provider identity is sparse or missing.")

        return {
            "provider": provider_values[0] if provider_values else None,
            "level": level,
            "score": provider_score,
            "drivers": self.unique_preserve_order(drivers),
            "summary": {
                "reliable": "Provider documentation looks consistently reliable in the current packet.",
                "generally_reliable": "Provider documentation is mostly reliable with minor review sensitivity.",
                "variable": "Provider documentation quality is variable and may need targeted cleanup.",
                "at_risk": "Provider documentation quality is at risk and could slow or weaken submission handling.",
            }[level],
        }

    def build_denial_reason_forecasting(self, packet, denial_risk, procedure_fit, missing_evidence):
        reasons = []

        def add_reason(code, likelihood, summary):
            reasons.append({
                "code": code,
                "likelihood": round(likelihood, 2),
                "summary": summary,
            })

        if packet.missing_documents:
            add_reason("missing_required_documents", 0.9, f"Missing required documents: {', '.join(sorted(packet.missing_documents))}.")
        if packet.missing_fields:
            add_reason("missing_required_fields", min(0.82, 0.52 + (0.08 * len(packet.missing_fields))), "Required fields are still missing or incomplete.")
        if any(conflict.get("severity") == "high" for conflict in packet.conflicts):
            add_reason("high_severity_conflicts", 0.88, "High-severity cross-document conflicts can trigger denial or hold decisions.")
        elif any(conflict.get("severity") == "medium" for conflict in packet.conflicts):
            add_reason("cross_document_conflicts", 0.64, "Medium-severity conflicts can trigger reviewer rejection or delay.")
        if procedure_fit["status"] == "weak":
            add_reason("weak_procedure_support", 0.78, "Requested procedure lacks strong clinical support.")
        elif procedure_fit["status"] == "moderate":
            add_reason("moderate_procedure_support", 0.46, "Procedure support is only moderate and may still draw scrutiny.")
        if "diagnosis_icd_mismatch" in packet.review_flags or "partial_diagnosis_icd_alignment" in packet.review_flags:
            add_reason("diagnosis_icd_alignment", 0.55, "Diagnosis and ICD alignment may be viewed as incomplete.")
        if "chronology_review_needed" in packet.review_flags:
            add_reason("chronology_issue", 0.58, "Timeline inconsistency can trigger operational rejection or hold.")
        if "packet_integrity_risk" in packet.review_flags:
            add_reason("identity_integrity_risk", 0.95, "Mixed identity or case signals represent a major denial risk.")
        if not reasons and denial_risk.get("level") in {"high", "critical"}:
            add_reason("general_packet_risk", denial_risk.get("risk_score", 0.65), "Overall packet risk remains elevated even without one dominant failure mode.")
        if not reasons and missing_evidence:
            add_reason("supporting_evidence_gap", 0.38, missing_evidence[0].get("why", "Supportive evidence remains incomplete."))

        reasons = sorted(reasons, key=lambda item: (-item["likelihood"], item["code"]))
        return {
            "primary_reason": reasons[0]["code"] if reasons else None,
            "reasons": reasons[:6],
            "summary": reasons[0]["summary"] if reasons else "No strong denial cause is currently forecasted beyond routine packet variance.",
        }

    def build_volume_trend_prediction(self, packet, packet_type, workflow_route, case_complexity):
        trend_score = self.VOLUME_PROXY_BASELINES.get(packet_type, 0.85)
        queue = workflow_route.get("queue")

        if queue == "review_queue":
            trend_score += 0.08
        elif queue == "correction_queue":
            trend_score += 0.12
        elif queue == "senior_review_queue":
            trend_score += 0.1
        else:
            trend_score -= 0.04

        trend_score += {
            "low": -0.05,
            "moderate": 0.03,
            "high": 0.09,
            "critical": 0.14,
        }.get(case_complexity.get("level"), 0.0)

        trend_score = round(max(0.45, min(trend_score, 1.35)), 2)
        if trend_score >= 1.15:
            band = "high"
            direction = "rising"
        elif trend_score >= 0.95:
            band = "elevated"
            direction = "rising"
        elif trend_score >= 0.72:
            band = "steady"
            direction = "stable"
        else:
            band = "light"
            direction = "stable"

        return {
            "band": band,
            "direction": direction,
            "trend_score": trend_score,
            "basis": "deterministic_packet_mix_proxy_v1",
            "summary": "Volume forecast uses the current packet mix, routing pressure, and case complexity as a local operational proxy.",
        }

    def build_staffing_demand_forecasting(self, packet, workflow_route, case_complexity, volume_trend):
        per_packet_minutes = 12 + round(case_complexity.get("score", 40) * 0.8)
        queue = workflow_route.get("queue")
        if queue == "review_queue":
            per_packet_minutes += 12
        elif queue == "correction_queue":
            per_packet_minutes += 22
        elif queue == "senior_review_queue":
            per_packet_minutes += 32

        demand_score = (per_packet_minutes / 60.0) + {
            "light": 0.2,
            "steady": 0.45,
            "elevated": 0.7,
            "high": 0.95,
        }.get(volume_trend.get("band"), 0.45)

        if demand_score >= 2.1:
            level = "high"
        elif demand_score >= 1.35:
            level = "elevated"
        elif demand_score >= 0.8:
            level = "standard"
        else:
            level = "light"

        return {
            "level": level,
            "estimated_staff_minutes_per_packet": per_packet_minutes,
            "recommended_staffing_signal": {
                "high": "Allocate senior review or correction bandwidth before intake volume stacks further.",
                "elevated": "Plan for elevated reviewer load and tighter queue monitoring.",
                "standard": "Current staffing demand looks normal for this packet profile.",
                "light": "This packet should not materially strain routine staffing.",
            }[level],
            "summary": f"Staffing demand is {level} based on queue routing, packet complexity, and the current volume proxy.",
        }

    def build_submission_timing_optimization(self, packet, submission_decision, workflow_route, turnaround_prediction, case_complexity):
        readiness = submission_decision["readiness"]
        queue = workflow_route.get("queue")

        if readiness == "ready" and queue == "submission_queue" and case_complexity.get("level") in {"low", "moderate"}:
            action = "submit_now"
            recommended_window = "same_business_day"
            reason = "Packet is ready and does not carry complexity high enough to justify holding for a later window."
        elif readiness == "ready":
            action = "submit_next_business_morning"
            recommended_window = "next_business_morning"
            reason = "Packet is ready, but a controlled next-morning submission gives staff time to absorb any last-minute issues."
        elif readiness == "requires_review":
            action = "submit_after_review_clearance"
            recommended_window = "after_review"
            reason = "Reviewer confirmation should happen before submission timing is committed."
        else:
            action = "wait_for_correction_completion"
            recommended_window = "after_corrections"
            reason = "Correction work should finish before submission is attempted."

        return {
            "action": action,
            "recommended_window": recommended_window,
            "estimated_wait_hours": turnaround_prediction.get("estimated_submission_ready_hours"),
            "reason": reason,
        }

    def build_predictive_escalation(self, packet, submission_decision, denial_risk, escalation, case_complexity, bottleneck_detection, provider_performance):
        reasons = []
        provider_sensitive_docs = {"consult_request", "cover_sheet", "lomn", "rfs", "approved_referral", "seoc"}
        provider_conflicts = any(
            conflict.get("field") in {"provider", "ordering_provider", "referring_provider"}
            and conflict.get("severity") in {"medium", "high"}
            for conflict in packet.conflicts
        )

        if escalation.get("escalate"):
            reasons.extend(escalation.get("reasons", []))
        else:
            if denial_risk.get("level") in {"high", "critical"}:
                reasons.append("Predicted denial risk is already high enough to justify earlier escalation.")
            if case_complexity.get("level") == "critical":
                reasons.append("Critical case complexity suggests routine routing may under-handle future problems.")
            if bottleneck_detection.get("primary_stage") in {"conflict_resolution", "senior_review"} and any(
                stage.get("severity") == "high" for stage in bottleneck_detection.get("stages", [])
            ):
                reasons.append("Current bottlenecks point toward likely escalation before submission is cleared.")
            if (
                provider_performance.get("level") == "at_risk"
                and (
                    provider_conflicts
                    or bool(provider_sensitive_docs.intersection(set(packet.detected_documents)))
                )
            ):
                reasons.append("Provider documentation reliability is poor enough to justify earlier intervention.")

        escalate = bool(reasons)
        return {
            "escalate": escalate,
            "predicted_queue": "senior_review_queue" if escalate else submission_decision.get("workflow_route"),
            "reasons": self.unique_preserve_order(reasons),
            "summary": (
                "Packet should be escalated before routine handling fully fails."
                if escalate else
                "No predictive escalation is currently needed beyond the active workflow route."
            ),
        }
