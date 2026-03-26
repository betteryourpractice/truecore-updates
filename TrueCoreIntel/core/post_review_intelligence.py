import os
import re
from importlib import util as importlib_util
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path


class PostReviewTools:
    DENIAL_TAXONOMY = {
        "missing_required_documents": ("documentation_gap", "Missing required documents remain the strongest denial trigger."),
        "missing_required_fields": ("critical_field_gap", "Critical or required packet fields are still missing."),
        "high_severity_conflicts": ("cross_document_conflict", "High-severity field conflicts weaken case integrity."),
        "cross_document_conflicts": ("cross_document_conflict", "Cross-document conflicts are still present."),
        "review_sensitive_conflicts": ("review_sensitive_conflict", "Medium-severity conflicts still drive reviewer hesitation."),
        "identity_integrity_risk": ("identity_integrity_risk", "Identity or case-integrity issues remain a major risk."),
        "weak_procedure_support": ("clinical_support_gap", "Requested procedure lacks strong medical support."),
        "moderate_procedure_support": ("clinical_support_gap", "Requested procedure only has moderate medical support."),
        "diagnosis_icd_alignment": ("coding_alignment_gap", "Diagnosis and coding alignment is incomplete."),
        "chronology_issue": ("timeline_issue", "Timeline and chronology issues can block approval or routing."),
        "general_packet_risk": ("general_packet_risk", "Overall packet risk is elevated."),
        "supporting_evidence_gap": ("evidence_gap", "Supporting evidence remains incomplete."),
    }

    def unique_preserve_order(self, items):
        seen = set()
        ordered = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            ordered.append(item)
        return ordered

    def humanize(self, value):
        text = str(value or "").replace("_", " ").strip()
        return text if text else None

    def serialize(self, value):
        if isinstance(value, tuple):
            return [self.serialize(item) for item in value]
        if isinstance(value, list):
            return [self.serialize(item) for item in value]
        if isinstance(value, dict):
            return {str(key): self.serialize(item) for key, item in value.items()}
        return value

    def top_tracebacks(self, packet, limit=8):
        tracebacks = list(
            getattr(packet, "validation_intelligence", {}).get("evidence_traceback_links", [])
            or packet.links.get("evidence_traceback_links", [])
            or []
        )
        return tracebacks[:limit]

    def low_confidence_fields(self, packet, threshold=0.84):
        fields = []
        for field, confidence in (packet.field_confidence or {}).items():
            numeric = float(confidence or 0.0)
            if numeric < threshold:
                fields.append({
                    "field": field,
                    "confidence": round(numeric, 2),
                })
        return sorted(fields, key=lambda item: (item["confidence"], item["field"]))

    def get_project_root(self):
        return Path(__file__).resolve().parents[2]

    def read_text_file(self, path):
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except Exception:
            return None

    def detect_package(self, module_name, package_name=None):
        found = importlib_util.find_spec(module_name) is not None
        package_name = package_name or module_name
        resolved_version = None
        if found:
            try:
                resolved_version = package_version(package_name)
            except PackageNotFoundError:
                resolved_version = None
        return {
            "module": module_name,
            "package": package_name,
            "available": found,
            "version": resolved_version,
        }

    def detect_body_regions(self, text):
        normalized = str(text or "").lower()
        normalized = re.sub(r"[^a-z0-9 ]", " ", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()

        regions = set()
        region_hints = {
            "lumbar": {"back", "lumbar", "lumbago", "low back", "radiculopathy", "sciatica"},
            "cervical": {"neck", "cervical"},
            "hip": {"hip"},
            "shoulder": {"shoulder"},
            "head": {"head", "migraine", "headache"},
        }

        for region, hints in region_hints.items():
            if any(hint in normalized for hint in hints):
                regions.add(region)
        return regions


class DenialIntelligenceAnalyzer(PostReviewTools):
    def analyze(self, packet):
        denial_risk = dict(packet.output.get("denial_risk", {}) or {})
        denial_forecast = dict(packet.output.get("denial_reason_forecasting", {}) or {})
        resubmission = dict(packet.output.get("resubmission_strategy", {}) or {})
        review_summary = dict(packet.output.get("review_summary", {}) or {})
        success_pattern = dict(packet.output.get("success_pattern_match", {}) or {})

        taxonomy = self.build_denial_taxonomy_engine(resubmission, denial_forecast)
        clustering = self.build_denial_pattern_clustering(taxonomy, denial_risk)
        countermeasures = self.build_countermeasure_recommendation_engine(resubmission, review_summary)
        appeal = self.build_appeal_opportunity_detection(packet, denial_risk, success_pattern)
        backtracking = self.build_denial_evidence_backtracking(packet, taxonomy)
        shielding = self.build_preventive_denial_shielding(packet, denial_risk, denial_forecast, countermeasures)
        vulnerability = self.build_documentation_vulnerability_mapping(packet)
        return_to_correct = self.build_return_to_correct_strategy_engine(packet, resubmission, countermeasures)
        trend = self.build_denial_trend_monitoring(denial_forecast, taxonomy, denial_risk)
        recovery = self.build_failure_recovery_scoring(packet, denial_risk, taxonomy)

        return {
            "denial_taxonomy_engine": taxonomy,
            "denial_pattern_clustering": clustering,
            "countermeasure_recommendation_engine": countermeasures,
            "appeal_opportunity_detection": appeal,
            "denial_evidence_backtracking": backtracking,
            "preventive_denial_shielding": shielding,
            "documentation_vulnerability_mapping": vulnerability,
            "return_to_correct_strategy_engine": return_to_correct,
            "denial_trend_monitoring": trend,
            "failure_recovery_scoring": recovery,
        }

    def build_denial_taxonomy_engine(self, resubmission, denial_forecast):
        taxonomy = []

        for mode in resubmission.get("failure_modes", []):
            category, summary = self.DENIAL_TAXONOMY.get(mode, ("general_packet_risk", self.humanize(mode)))
            taxonomy.append({
                "source": "failure_mode",
                "code": mode,
                "category": category,
                "summary": summary,
            })

        for reason in denial_forecast.get("reasons", []):
            code = reason.get("code")
            category, summary = self.DENIAL_TAXONOMY.get(code, ("general_packet_risk", reason.get("summary")))
            taxonomy.append({
                "source": "forecast",
                "code": code,
                "category": category,
                "likelihood": reason.get("likelihood"),
                "summary": reason.get("summary") or summary,
            })

        return {
            "items": taxonomy,
            "primary_category": taxonomy[0]["category"] if taxonomy else None,
            "summary": taxonomy[0]["summary"] if taxonomy else "No dominant denial category is currently active.",
        }

    def build_denial_pattern_clustering(self, taxonomy, denial_risk):
        categories = sorted({item["category"] for item in taxonomy.get("items", []) if item.get("category")})
        cluster_id = "current_packet:" + "|".join(categories or ["routine_variance"])
        return {
            "cluster_id": cluster_id,
            "cluster_type": "deterministic_current_packet",
            "categories": categories,
            "risk_level": denial_risk.get("level"),
        }

    def build_countermeasure_recommendation_engine(self, resubmission, review_summary):
        actions = []
        actions.extend(resubmission.get("corrective_actions", []))

        for item in review_summary.get("priority_fixes", []):
            if isinstance(item, dict):
                action = item.get("action")
                if action:
                    actions.append(action)
            elif item:
                actions.append(item)

        for item in review_summary.get("fix_recommendations", []):
            actions.append(item)

        actions = self.unique_preserve_order([str(item).strip() for item in actions if str(item).strip()])
        return {
            "recommended_actions": actions[:8],
            "action_count": len(actions),
            "summary": actions[0] if actions else "No corrective action is currently required beyond routine review.",
        }

    def build_appeal_opportunity_detection(self, packet, denial_risk, success_pattern):
        high_conflicts = any(conflict.get("severity") == "high" for conflict in packet.conflicts)
        strong_verification = float(getattr(packet, "deep_verification_score", 0) or 0) >= 72
        missing_core_items = bool(packet.missing_documents or packet.missing_fields)
        pattern_similarity = success_pattern.get("similarity")

        if not high_conflicts and not missing_core_items and strong_verification and denial_risk.get("level") in {"low", "moderate"}:
            disposition = "appeal_viable"
            summary = "Packet already carries enough verified support that appeal may be more efficient than a full rebuild."
        else:
            disposition = "rebuild_preferred"
            summary = "Packet still has structural gaps or conflicts, so rebuild/correction is safer than appeal."

        return {
            "disposition": disposition,
            "supporting_factors": {
                "high_conflicts": high_conflicts,
                "missing_core_items": missing_core_items,
                "deep_verification_score": getattr(packet, "deep_verification_score", None),
                "pattern_similarity": pattern_similarity,
            },
            "summary": summary,
        }

    def build_denial_evidence_backtracking(self, packet, taxonomy):
        tracebacks = self.top_tracebacks(packet)
        backtracking = []

        for item in taxonomy.get("items", [])[:6]:
            code = item.get("code")
            if code == "missing_required_documents":
                evidence = [{"missing_document": doc} for doc in packet.missing_documents[:4]]
            elif code == "missing_required_fields":
                evidence = [{"missing_field": field} for field in packet.missing_fields[:4]]
            elif "conflict" in str(code):
                evidence = [
                    {
                        "field": conflict.get("field"),
                        "message": conflict.get("message"),
                        "severity": conflict.get("severity"),
                    }
                    for conflict in packet.conflicts[:4]
                ]
            else:
                evidence = [
                    {
                        "field": link.get("field"),
                        "page_number": link.get("page_number"),
                        "document_type": link.get("document_type"),
                    }
                    for link in tracebacks[:3]
                ]

            backtracking.append({
                "cause": code,
                "category": item.get("category"),
                "evidence": evidence,
            })

        return backtracking

    def build_preventive_denial_shielding(self, packet, denial_risk, denial_forecast, countermeasures):
        triggers = list(denial_risk.get("drivers", []))
        for reason in denial_forecast.get("reasons", []):
            summary = reason.get("summary")
            if summary:
                triggers.append(summary)

        actions = list(countermeasures.get("recommended_actions", []))
        if packet.missing_documents:
            actions.append("Resolve missing required documents before submission.")
        if packet.missing_fields:
            actions.append("Resolve missing required fields before submission.")

        return {
            "risk_level": denial_risk.get("level"),
            "shielding_triggers": self.unique_preserve_order(triggers)[:8],
            "preventive_actions": self.unique_preserve_order(actions)[:8],
        }

    def build_documentation_vulnerability_mapping(self, packet):
        vulnerabilities = []

        for field in packet.missing_fields[:6]:
            vulnerabilities.append({
                "target": field,
                "risk": "missing_field",
                "severity": "high" if field in {"name", "dob", "authorization_number"} else "medium",
            })

        for conflict in packet.conflicts[:6]:
            vulnerabilities.append({
                "target": conflict.get("field"),
                "risk": conflict.get("type"),
                "severity": conflict.get("severity"),
            })

        for item in self.low_confidence_fields(packet)[:4]:
            vulnerabilities.append({
                "target": item.get("field"),
                "risk": "low_confidence_extraction",
                "severity": "medium",
                "confidence": item.get("confidence"),
            })

        return {
            "vulnerabilities": vulnerabilities,
            "summary": {
                "high_risk_targets": sum(1 for item in vulnerabilities if item.get("severity") == "high"),
                "total_targets": len(vulnerabilities),
            },
        }

    def build_return_to_correct_strategy_engine(self, packet, resubmission, countermeasures):
        next_action = dict(packet.output.get("recommended_next_action", {}) or {})
        workflow = dict(packet.output.get("workflow_route", {}) or {})
        return {
            "recommended": bool(resubmission.get("recommended")),
            "workflow_queue": workflow.get("queue"),
            "next_action": next_action.get("action"),
            "corrective_actions": list(countermeasures.get("recommended_actions", []))[:6],
            "summary": resubmission.get("summary") or workflow.get("reason"),
        }

    def build_denial_trend_monitoring(self, denial_forecast, taxonomy, denial_risk):
        primary_reason = denial_forecast.get("primary_reason") or taxonomy.get("primary_category")
        return {
            "mode": "current_packet_only",
            "dominant_pattern": primary_reason,
            "current_risk_level": denial_risk.get("level"),
            "summary": denial_forecast.get("summary") or taxonomy.get("summary"),
        }

    def build_failure_recovery_scoring(self, packet, denial_risk, taxonomy):
        score = 78
        score -= len(packet.missing_documents) * 8
        score -= len(packet.missing_fields) * 7
        score -= sum(10 for conflict in packet.conflicts if conflict.get("severity") == "high")
        score -= sum(5 for conflict in packet.conflicts if conflict.get("severity") == "medium")
        score -= 4 if denial_risk.get("level") in {"high", "critical"} else 0
        score -= len(taxonomy.get("items", [])) * 2
        score = max(0, min(score, 100))

        return {
            "score": score,
            "band": "high" if score >= 76 else "moderate" if score >= 52 else "low",
            "summary": "Probability of successful correction is estimated from missing items, conflict severity, and current denial risk.",
        }


class HumanInTheLoopIntelligenceAnalyzer(PostReviewTools):
    def analyze(self, packet):
        submission_decision = dict(packet.output.get("submission_decision", {}) or {})
        denial_risk = dict(packet.output.get("denial_risk", {}) or {})
        review_summary = dict(packet.output.get("review_summary", {}) or {})
        trust = self.build_trust_score_modeling(packet, submission_decision, denial_risk)
        thresholds = self.build_review_threshold_engine(packet, submission_decision, denial_risk, trust)
        gated = self.build_confidence_gated_automation(packet, submission_decision, denial_risk, trust, thresholds)
        explain = self.build_explain_before_action_layer(packet, submission_decision, denial_risk, trust)
        attention = self.build_reviewer_attention_guidance(packet, denial_risk, review_summary)
        options = self.build_assisted_decision_mode(packet, submission_decision, denial_risk, trust)
        checkpoints = self.build_approval_checkpoint_layer(packet, denial_risk, trust, submission_decision)
        correction_capture = self.build_human_correction_capture(packet)
        safety_override = self.build_automation_safety_override(packet, denial_risk, trust, thresholds)
        burden = self.build_review_burden_optimization(packet, review_summary, attention)

        return {
            "review_threshold_engine": thresholds,
            "confidence_gated_automation": gated,
            "explain_before_action_layer": explain,
            "reviewer_attention_guidance": attention,
            "assisted_decision_mode": options,
            "approval_checkpoint_layer": checkpoints,
            "human_correction_capture": correction_capture,
            "automation_safety_override": safety_override,
            "review_burden_optimization": burden,
            "trust_score_modeling": trust,
        }

    def build_trust_score_modeling(self, packet, submission_decision, denial_risk):
        packet_conf = float(packet.packet_confidence or 0.0)
        deep_score = float(getattr(packet, "deep_verification_score", 0) or 0) / 100.0
        approval = float(packet.approval_probability or 0.0)
        risk_inverse = 1.0 - float(denial_risk.get("risk_score", 0.5) or 0.5)
        trust = (packet_conf * 0.35) + (deep_score * 0.3) + (risk_inverse * 0.2) + (approval * 0.15)
        trust -= min(0.18, 0.04 * len(packet.conflicts))
        trust -= min(0.15, 0.03 * (len(packet.missing_fields) + len(packet.missing_documents)))
        trust = round(max(0.0, min(trust, 1.0)), 2)

        if trust >= 0.82 and submission_decision.get("readiness") == "ready":
            band = "high"
        elif trust >= 0.58:
            band = "moderate"
        else:
            band = "low"

        return {
            "trust_score": trust,
            "band": band,
            "drivers": self.unique_preserve_order([
                "packet_confidence",
                "deep_verification_score",
                "denial_risk",
                "approval_probability",
            ]),
        }

    def build_review_threshold_engine(self, packet, submission_decision, denial_risk, trust):
        reasons = []
        require_review = submission_decision.get("readiness") != "ready"

        if trust.get("trust_score", 0.0) < 0.82:
            reasons.append("Trust score is below the auto-action threshold.")
        if denial_risk.get("level") in {"high", "critical"}:
            reasons.append("Denial risk is too high for unattended action.")
        if packet.review_priority == "high":
            reasons.append("Review priority is already high.")
        if any(conflict.get("severity") == "high" for conflict in packet.conflicts):
            reasons.append("High-severity conflicts require human review.")

        if require_review or reasons:
            status = "human_review_required"
        else:
            status = "automation_safe"

        return {
            "status": status,
            "auto_action_allowed": status == "automation_safe",
            "reasons": reasons,
        }

    def build_confidence_gated_automation(self, packet, submission_decision, denial_risk, trust, thresholds):
        return {
            "gate_open": bool(thresholds.get("auto_action_allowed")),
            "packet_confidence": packet.packet_confidence,
            "deep_verification_score": getattr(packet, "deep_verification_score", None),
            "denial_risk_level": denial_risk.get("level"),
            "planned_action": submission_decision.get("next_action"),
        }

    def build_explain_before_action_layer(self, packet, submission_decision, denial_risk, trust):
        rationale = []
        if submission_decision.get("readiness"):
            rationale.append(f"Readiness is {submission_decision['readiness']}.")
        if denial_risk.get("drivers"):
            rationale.extend(list(denial_risk.get("drivers", []))[:3])
        if packet.output.get("approval_rationale"):
            rationale.extend(list(packet.output.get("approval_rationale", []))[:2])

        return {
            "action": submission_decision.get("next_action"),
            "trust_score": trust.get("trust_score"),
            "rationale": self.unique_preserve_order(rationale)[:6],
        }

    def build_reviewer_attention_guidance(self, packet, denial_risk, review_summary):
        attention_points = []

        for conflict in packet.conflicts[:5]:
            if conflict.get("severity") in {"high", "medium"}:
                attention_points.append(f"Review conflict: {conflict.get('message')}")

        for field in packet.missing_fields[:4]:
            attention_points.append(f"Review missing field: {field}.")

        for doc in packet.missing_documents[:4]:
            attention_points.append(f"Review missing document: {doc}.")

        for item in self.low_confidence_fields(packet)[:4]:
            attention_points.append(f"Review low-confidence extraction: {item['field']} ({item['confidence']}).")

        if not attention_points:
            attention_points.extend(list(review_summary.get("why_weak", []))[:4])

        return {
            "priority": packet.review_priority or "normal",
            "attention_points": self.unique_preserve_order(attention_points)[:8],
            "denial_risk_level": denial_risk.get("level"),
        }

    def build_assisted_decision_mode(self, packet, submission_decision, denial_risk, trust):
        readiness = submission_decision.get("readiness")
        options = []

        options.append({
            "action": "submit_packet",
            "rank": 1 if readiness == "ready" and trust.get("trust_score", 0) >= 0.8 else 3,
            "reason": "Packet is the closest state to immediate submission.",
        })
        options.append({
            "action": "route_to_review",
            "rank": 1 if readiness == "requires_review" else 2,
            "reason": "Human review is preferred when certainty or risk is mixed.",
        })
        options.append({
            "action": "correct_packet",
            "rank": 1 if readiness == "hold" or denial_risk.get("level") in {"high", "critical"} else 2,
            "reason": "Corrective work is preferred when packet gaps are still material.",
        })

        ranked = sorted(options, key=lambda item: (item["rank"], item["action"]))
        return {
            "options": ranked,
            "recommended_action": ranked[0]["action"] if ranked else None,
        }

    def build_approval_checkpoint_layer(self, packet, denial_risk, trust, submission_decision):
        required = (
            denial_risk.get("level") in {"high", "critical"}
            or trust.get("trust_score", 0.0) < 0.76
            or packet.review_priority == "high"
            or submission_decision.get("readiness") != "ready"
        )
        return {
            "checkpoint_required": required,
            "checkpoint_type": "human_signoff" if required else "standard_path",
            "reason": "Risk, trust, or review state requires checkpoint approval." if required else "Normal path does not require extra checkpointing.",
        }

    def build_human_correction_capture(self, packet):
        return {
            "capture_mode": "ready_for_manual_feedback",
            "accepted_inputs": ["field_override", "document_status_change", "review_comment", "fix_confirmation"],
            "persistence": "session_payload_only",
            "packet_label": packet.output.get("packet_label"),
        }

    def build_automation_safety_override(self, packet, denial_risk, trust, thresholds):
        engaged = (
            not thresholds.get("auto_action_allowed")
            and (
                denial_risk.get("level") in {"high", "critical"}
                or trust.get("trust_score", 0.0) < 0.58
                or "packet_integrity_risk" in packet.review_flags
            )
        )
        return {
            "engaged": engaged,
            "reason": "Safety override engaged because trust/risk conditions failed." if engaged else "Safety override not required.",
        }

    def build_review_burden_optimization(self, packet, review_summary, attention):
        focus = list(attention.get("attention_points", []))[:5]
        if not focus:
            focus.extend(list(review_summary.get("missing_items", []))[:5])

        return {
            "focus_first": focus,
            "estimated_review_burden": "high" if packet.review_priority == "high" or len(focus) >= 5 else "moderate" if focus else "low",
            "summary": "Reviewer effort is reduced by focusing only on the highest-uncertainty packet areas first.",
        }


class OrchestrationIntelligenceAnalyzer(PostReviewTools):
    def analyze(self, packet):
        stage_trace = list(packet.links.get("pipeline_stage_trace", []) or [])
        stage_confidence = self.build_stage_confidence_aggregation(packet)
        health_state = self.build_pipeline_health_state_machine(packet, stage_confidence)
        partial_success = self.build_partial_success_handling(packet)

        return {
            "multi_stage_orchestration_engine": self.build_multi_stage_orchestration_engine(stage_trace),
            "dependency_aware_processing": self.build_dependency_aware_processing(stage_trace),
            "conditional_branch_execution": self.build_conditional_branch_execution(packet),
            "recovery_path_routing": self.build_recovery_path_routing(packet),
            "partial_success_handling": partial_success,
            "stage_confidence_aggregation": stage_confidence,
            "pipeline_health_state_machine": health_state,
            "dynamic_module_invocation": self.build_dynamic_module_invocation(packet),
            "orchestration_trace_logging": stage_trace,
            "end_to_end_coordination_scoring": self.build_end_to_end_coordination_scoring(packet, stage_confidence, partial_success),
        }

    def build_multi_stage_orchestration_engine(self, stage_trace):
        return {
            "stages": stage_trace,
            "completed_stage_count": len(stage_trace),
        }

    def build_dependency_aware_processing(self, stage_trace):
        stage_names = [entry.get("stage") for entry in stage_trace]
        dependencies = [
            {"stage": "extraction", "depends_on": "detection", "satisfied": "detection" in stage_names},
            {"stage": "validation", "depends_on": "extraction", "satisfied": "extraction" in stage_names},
            {"stage": "intelligence", "depends_on": "validation", "satisfied": "validation" in stage_names},
            {"stage": "review", "depends_on": "intelligence", "satisfied": "intelligence" in stage_names},
        ]
        return {
            "dependencies": dependencies,
            "all_satisfied": all(item["satisfied"] for item in dependencies),
        }

    def build_conditional_branch_execution(self, packet):
        submission_decision = dict(packet.output.get("submission_decision", {}) or {})
        branches = []
        branches.append("review_path" if submission_decision.get("readiness") == "requires_review" else "submission_path" if submission_decision.get("readiness") == "ready" else "correction_path")
        if packet.missing_documents or packet.missing_fields:
            branches.append("missing_requirements_branch")
        if packet.detected_documents:
            branches.append("document_detection_branch")
        if getattr(packet, "document_intelligence", {}):
            branches.append("document_intelligence_branch")
        return {
            "branches": self.unique_preserve_order(branches),
        }

    def build_recovery_path_routing(self, packet):
        denial_risk = dict(packet.output.get("denial_risk", {}) or {})
        workflow = dict(packet.output.get("workflow_route", {}) or {})
        if denial_risk.get("level") in {"high", "critical"}:
            route = "senior_review_or_correction"
        elif packet.missing_fields or packet.missing_documents:
            route = "correction_then_recheck"
        elif packet.conflicts:
            route = "review_then_submit"
        else:
            route = "normal_submission"
        return {
            "route": route,
            "workflow_queue": workflow.get("queue"),
        }

    def build_partial_success_handling(self, packet):
        return {
            "documents_detected": len(packet.detected_documents),
            "fields_extracted": len(packet.fields),
            "usable_output_available": bool(packet.fields or packet.detected_documents or packet.output.get("review_summary")),
            "downstream_review_available": bool(packet.output.get("review_summary")),
        }

    def build_stage_confidence_aggregation(self, packet):
        page_confidences = list((packet.page_confidence or {}).values())
        field_confidences = list((packet.field_confidence or {}).values())
        approval_prediction = dict(packet.output.get("approval_outcome_prediction", {}) or {})

        detection = round(sum(page_confidences) / len(page_confidences), 2) if page_confidences else 0.0
        extraction = round(sum(field_confidences) / len(field_confidences), 2) if field_confidences else 0.0
        validation = round(float(getattr(packet, "deep_verification_score", 0) or 0) / 100.0, 2)
        intelligence = round(float(packet.packet_confidence or 0.0), 2)
        review = round(float(approval_prediction.get("confidence", packet.packet_confidence or 0.0) or 0.0), 2)

        return {
            "detection": detection,
            "extraction": extraction,
            "validation": validation,
            "intelligence": intelligence,
            "review": review,
            "overall": round((detection + extraction + validation + intelligence + review) / 5.0, 2),
        }

    def build_pipeline_health_state_machine(self, packet, stage_confidence):
        readiness = packet.output.get("submission_readiness")
        if readiness == "ready" and stage_confidence.get("overall", 0) >= 0.8:
            state = "ready"
        elif readiness == "not_ready":
            state = "correction_required"
        else:
            state = "review_required"
        return {
            "state": state,
            "submission_readiness": readiness,
            "workflow_queue": dict(packet.output.get("workflow_route", {}) or {}).get("queue"),
        }

    def build_dynamic_module_invocation(self, packet):
        modules = []
        module_names = {
            "document_intelligence_2": getattr(packet, "document_intelligence", {}),
            "validation_intelligence_2": getattr(packet, "validation_intelligence", {}),
            "evidence_intelligence_1": getattr(packet, "evidence_intelligence", {}),
            "clinical_intelligence_1": getattr(packet, "clinical_intelligence", {}),
        }
        for name, payload in module_names.items():
            modules.append({
                "module": name,
                "active": bool(payload),
            })
        return {
            "modules": modules,
            "active_count": sum(1 for item in modules if item["active"]),
        }

    def build_end_to_end_coordination_scoring(self, packet, stage_confidence, partial_success):
        score = int(round((stage_confidence.get("overall", 0.0) * 100)))
        score -= len(packet.missing_documents) * 4
        score -= len(packet.missing_fields) * 3
        score -= len(packet.conflicts) * 3
        if not partial_success.get("usable_output_available"):
            score -= 20
        score = max(0, min(score, 100))
        return {
            "score": score,
            "band": "high" if score >= 82 else "moderate" if score >= 60 else "low",
        }


class ArchitectureIntelligenceAnalyzer(PostReviewTools):
    CAPABILITY_REGISTRY = [
        ("evidence_intelligence_1", "evidence_intelligence"),
        ("clinical_intelligence_1", "clinical_intelligence"),
        ("document_intelligence_2", "document_intelligence"),
        ("validation_intelligence_2", "validation_intelligence"),
        ("denial_intelligence_1", "denial_intelligence"),
        ("human_in_the_loop_intelligence_1", "human_loop_intelligence"),
        ("orchestration_intelligence_1", "orchestration_intelligence"),
    ]

    def analyze(self, packet):
        dependencies = self.build_dependency_risk_detection()
        contracts = self.build_internal_contract_validation(packet)
        registry = self.build_versioned_capability_registry(packet)
        drift = self.build_architecture_drift_detection(contracts, dependencies, registry)

        return {
            "modular_service_boundary_layer": self.build_modular_service_boundary_layer(packet),
            "stable_integration_api": self.build_stable_integration_api(packet, contracts),
            "configuration_intelligence_layer": self.build_configuration_intelligence_layer(packet),
            "dependency_risk_detection": dependencies,
            "runtime_mode_switching": self.build_runtime_mode_switching(packet),
            "fallback_architecture_paths": self.build_fallback_architecture_paths(packet),
            "versioned_capability_registry": registry,
            "internal_contract_validation": contracts,
            "architecture_drift_detection": drift,
            "maintainability_scoring": self.build_maintainability_scoring(contracts, dependencies, drift),
        }

    def build_modular_service_boundary_layer(self, packet):
        services = [
            "detection",
            "extraction",
            "validation",
            "intelligence",
            "review",
            "post_review_intelligence",
            "learning",
        ]
        return {
            "services": services,
            "active_services": [service for service in services if packet.links.get("pipeline_stage_trace")],
        }

    def build_stable_integration_api(self, packet, contracts):
        required_output_keys = [
            "review_summary",
            "submission_decision",
            "denial_risk",
            "workflow_route",
            "approval_rationale",
        ]
        missing_keys = [key for key in required_output_keys if key not in packet.output]
        return {
            "required_output_keys": required_output_keys,
            "missing_output_keys": missing_keys,
            "status": "stable" if not missing_keys and contracts.get("status") == "valid" else "partial",
        }

    def build_configuration_intelligence_layer(self, packet):
        return {
            "env_flags": {
                "TRUECORE_DISABLE_INTEL": os.getenv("TRUECORE_DISABLE_INTEL", ""),
            },
            "source_type": packet.source_type,
        }

    def build_dependency_risk_detection(self):
        checks = [
            self.detect_package("PyPDF2"),
            self.detect_package("docx", "python-docx"),
            self.detect_package("PySide6"),
            self.detect_package("openpyxl"),
        ]
        return {
            "dependencies": checks,
            "missing_dependencies": [item["module"] for item in checks if not item["available"]],
            "status": "stable" if all(item["available"] for item in checks[:2]) else "attention_needed",
        }

    def build_runtime_mode_switching(self, packet):
        source_type = str(packet.source_type or "").lower()
        if source_type in {"pdf", "docx"}:
            mode = "desktop_processing"
        else:
            mode = "generic_processing"
        return {
            "mode": mode,
            "source_type": source_type,
        }

    def build_fallback_architecture_paths(self, packet):
        return {
            "paths": [
                "review_queue_routing",
                "correction_queue_routing",
                "manual_review_required",
                "partial_packet_output",
            ],
            "active_fallback": "review_queue_routing" if packet.needs_review else "partial_packet_output",
        }

    def build_versioned_capability_registry(self, packet):
        active = []
        for capability_name, attribute_name in self.CAPABILITY_REGISTRY:
            payload = getattr(packet, attribute_name, {})
            active.append({
                "capability": capability_name,
                "active": bool(payload),
            })
        return {
            "capabilities": active,
            "active_count": sum(1 for item in active if item["active"]),
        }

    def build_internal_contract_validation(self, packet):
        checks = {
            "fields_is_dict": isinstance(packet.fields, dict),
            "conflicts_is_list": isinstance(packet.conflicts, list),
            "review_summary_is_dict": isinstance(packet.output.get("review_summary", {}), dict),
            "submission_decision_is_dict": isinstance(packet.output.get("submission_decision", {}), dict),
            "workflow_route_is_dict": isinstance(packet.output.get("workflow_route", {}), dict),
        }
        return {
            "checks": checks,
            "status": "valid" if all(checks.values()) else "invalid",
        }

    def build_architecture_drift_detection(self, contracts, dependencies, registry):
        issues = []
        if contracts.get("status") != "valid":
            issues.append("Internal contract validation failed.")
        if dependencies.get("missing_dependencies"):
            issues.append("One or more runtime dependencies are missing.")
        inactive = [item["capability"] for item in registry.get("capabilities", []) if not item["active"]]
        if inactive:
            issues.append(f"Capabilities inactive: {', '.join(inactive)}.")
        return {
            "issues": issues,
            "status": "drift_detected" if issues else "aligned",
        }

    def build_maintainability_scoring(self, contracts, dependencies, drift):
        score = 92
        if contracts.get("status") != "valid":
            score -= 25
        score -= len(dependencies.get("missing_dependencies", [])) * 10
        score -= len(drift.get("issues", [])) * 6
        score = max(0, min(score, 100))
        return {
            "score": score,
            "band": "high" if score >= 82 else "moderate" if score >= 62 else "low",
        }


class RecoveryIntelligenceAnalyzer(PostReviewTools):
    def analyze(self, packet):
        failure_classification = self.build_failure_classification_layer(packet)
        retry = self.build_intelligent_retry_engine(packet, failure_classification)
        graceful = self.build_graceful_degradation_mode(packet)
        dependency_recovery = self.build_missing_dependency_recovery(packet)
        corrupt_input = self.build_corrupt_input_handling(packet)
        crash_context = self.build_crash_context_preservation(packet)
        recommendation = self.build_recovery_recommendation_engine(packet, failure_classification, retry, corrupt_input)
        replay = self.build_failure_replay_mode(packet, failure_classification, retry)
        testing_hooks = self.build_resilience_testing_hooks(packet, failure_classification)
        reliability = self.build_reliability_scoring(packet, failure_classification, corrupt_input)

        return {
            "intelligent_retry_engine": retry,
            "failure_classification_layer": failure_classification,
            "graceful_degradation_mode": graceful,
            "missing_dependency_recovery": dependency_recovery,
            "corrupt_input_handling": corrupt_input,
            "crash_context_preservation": crash_context,
            "recovery_recommendation_engine": recommendation,
            "failure_replay_mode": replay,
            "resilience_testing_hooks": testing_hooks,
            "reliability_scoring": reliability,
        }

    def build_intelligent_retry_engine(self, packet, failure_classification):
        page_confidences = list((packet.page_confidence or {}).values())
        low_page_count = sum(1 for confidence in page_confidences if float(confidence or 0.0) < 0.45)
        if low_page_count >= 2 and packet.source_type == "pdf":
            strategy = "ocr_retry"
        elif failure_classification.get("primary_failure_type") == "data_quality":
            strategy = "targeted_reextract"
        elif failure_classification.get("primary_failure_type") == "runtime_dependency":
            strategy = "dependency_recovery"
        else:
            strategy = "no_retry_needed"
        return {
            "strategy": strategy,
            "low_confidence_page_count": low_page_count,
        }

    def build_failure_classification_layer(self, packet):
        if getattr(packet, "architecture_intelligence", {}).get("dependency_risk_detection", {}).get("missing_dependencies"):
            primary = "runtime_dependency"
        elif len(packet.missing_documents) + len(packet.missing_fields) >= 3:
            primary = "data_quality"
        elif packet.conflicts:
            primary = "logic_validation"
        else:
            primary = "stable"
        return {
            "primary_failure_type": primary,
            "missing_documents": len(packet.missing_documents),
            "missing_fields": len(packet.missing_fields),
            "conflict_count": len(packet.conflicts),
        }

    def build_graceful_degradation_mode(self, packet):
        return {
            "available": True,
            "modes": [
                "partial_packet_output",
                "manual_review_queue",
                "correction_queue",
            ],
            "active_mode": "manual_review_queue" if packet.needs_review else "partial_packet_output",
        }

    def build_missing_dependency_recovery(self, packet):
        dependency_status = getattr(packet, "architecture_intelligence", {}).get("dependency_risk_detection", {})
        missing = list(dependency_status.get("missing_dependencies", []))
        suggestions = []
        if "PyPDF2" in missing:
            suggestions.append("Install PyPDF2 or route PDF packets through text/ocr fallback only.")
        if "docx" in missing:
            suggestions.append("Install python-docx or avoid DOCX extraction paths.")
        return {
            "missing_dependencies": missing,
            "suggestions": suggestions,
        }

    def build_corrupt_input_handling(self, packet):
        sparse_pages = 0
        for page in packet.pages or []:
            text = str(page or "")
            if len(re.sub(r"\s+", "", text)) < 45:
                sparse_pages += 1
        return {
            "sparse_page_count": sparse_pages,
            "page_count": len(packet.pages or []),
            "risk_level": "high" if sparse_pages >= 3 else "moderate" if sparse_pages >= 1 else "low",
        }

    def build_crash_context_preservation(self, packet):
        label = packet.output.get("packet_label")
        if not label:
            name = str(packet.fields.get("name") or "unknown_patient").replace(",", "")
            identifier = str(packet.fields.get("authorization_number") or packet.fields.get("va_icn") or "no_identifier")
            label = f"{name}_{identifier}".replace("/", "-")

        return {
            "packet_label": label,
            "stage_trace_length": len(packet.links.get("pipeline_stage_trace", []) or []),
            "field_count": len(packet.fields),
            "document_count": len(packet.detected_documents),
        }

    def build_recovery_recommendation_engine(self, packet, failure_classification, retry, corrupt_input):
        if retry.get("strategy") == "ocr_retry":
            recommendation = "Retry OCR-heavy extraction before final review."
        elif failure_classification.get("primary_failure_type") == "logic_validation":
            recommendation = "Re-run targeted validation after correcting conflicting fields."
        elif corrupt_input.get("risk_level") == "high":
            recommendation = "Inspect packet quality manually before retrying automated extraction."
        else:
            recommendation = "Current packet can stay on the standard review/correction path."
        return {
            "recommendation": recommendation,
        }

    def build_failure_replay_mode(self, packet, failure_classification, retry):
        stages = []
        if retry.get("strategy") == "ocr_retry":
            stages.extend(["detection", "extraction"])
        if failure_classification.get("primary_failure_type") == "logic_validation":
            stages.append("validation")
        if not stages:
            stages.append("full_review_only")
        return {
            "stages": self.unique_preserve_order(stages),
            "summary": "Replay only the affected stages instead of re-running the full pipeline." if stages != ["full_review_only"] else "No stage replay is currently needed.",
        }

    def build_resilience_testing_hooks(self, packet, failure_classification):
        hooks = ["low_confidence_page_test", "missing_required_document_test"]
        if failure_classification.get("primary_failure_type") == "logic_validation":
            hooks.append("conflict_resolution_test")
        return {
            "hooks": hooks,
        }

    def build_reliability_scoring(self, packet, failure_classification, corrupt_input):
        score = 90
        score -= len(packet.conflicts) * 5
        score -= len(packet.missing_fields) * 4
        score -= len(packet.missing_documents) * 4
        score -= int(corrupt_input.get("sparse_page_count", 0)) * 3
        if failure_classification.get("primary_failure_type") == "runtime_dependency":
            score -= 18
        score = max(0, min(score, 100))
        return {
            "score": score,
            "band": "high" if score >= 82 else "moderate" if score >= 62 else "low",
        }


class PolicyIntelligenceAnalyzer(PostReviewTools):
    def analyze(self, packet):
        regulatory = dict(packet.output.get("regulatory_rule_engine", {}) or {})
        enforcement = dict(packet.output.get("documentation_requirement_enforcement", {}) or {})
        policy_change = dict(packet.output.get("policy_change_detection", {}) or {})
        compliance_checks = dict(packet.output.get("compliance_validation_checks", {}) or {})
        compliance_risk = dict(packet.output.get("compliance_risk_scoring", {}) or {})

        matrix = self.build_requirement_matrix_engine(regulatory)
        rule_matching = self.build_rule_to_evidence_matching(packet, matrix)
        version_awareness = self.build_policy_version_awareness(regulatory, policy_change)
        differentiation = self.build_jurisdiction_program_differentiation(regulatory)
        conditional_logic = self.build_conditional_requirement_logic(regulatory)
        forecasting = self.build_missing_requirement_forecasting(enforcement, compliance_checks)
        ambiguity = self.build_rule_ambiguity_detection(packet, compliance_checks)
        impact = self.build_policy_change_impact_analysis(policy_change, compliance_risk)
        waivers = self.build_requirement_waiver_detection(regulatory, packet)
        confidence = self.build_policy_compliance_confidence(compliance_risk, enforcement, compliance_checks)

        return {
            "requirement_matrix_engine": matrix,
            "rule_to_evidence_matching": rule_matching,
            "policy_version_awareness": version_awareness,
            "jurisdiction_program_differentiation": differentiation,
            "conditional_requirement_logic": conditional_logic,
            "missing_requirement_forecasting": forecasting,
            "rule_ambiguity_detection": ambiguity,
            "policy_change_impact_analysis": impact,
            "requirement_waiver_detection": waivers,
            "policy_compliance_confidence": confidence,
        }

    def build_requirement_matrix_engine(self, regulatory):
        requirements = []
        for rule in regulatory.get("rules", []):
            requirements.append({
                "rule_id": rule.get("rule_id"),
                "description": rule.get("description"),
                "required_targets": list(rule.get("required_targets", [])),
            })
        return {
            "packet_type": regulatory.get("packet_type"),
            "requirements": requirements,
        }

    def build_rule_to_evidence_matching(self, packet, matrix):
        tracebacks = self.top_tracebacks(packet)
        mappings = []

        for rule in matrix.get("requirements", []):
            required_targets = list(rule.get("required_targets", []))
            satisfied_targets = []
            missing_targets = []
            evidence = []

            for target in required_targets:
                if target in packet.fields:
                    satisfied_targets.append(target)
                    mapping = packet.field_mappings.get(target, {})
                    if mapping:
                        evidence.append({
                            "target": target,
                            "page_number": mapping.get("page_number"),
                            "document_type": mapping.get("document_type"),
                        })
                elif target in packet.detected_documents:
                    satisfied_targets.append(target)
                else:
                    missing_targets.append(target)

            if not evidence and tracebacks:
                evidence = [
                    {
                        "target": link.get("field"),
                        "page_number": link.get("page_number"),
                        "document_type": link.get("document_type"),
                    }
                    for link in tracebacks[:3]
                ]

            mappings.append({
                "rule_id": rule.get("rule_id"),
                "satisfied_targets": satisfied_targets,
                "missing_targets": missing_targets,
                "evidence": evidence,
            })

        return mappings

    def build_policy_version_awareness(self, regulatory, policy_change):
        return {
            "policy_version": regulatory.get("policy_version"),
            "policy_effective_date": regulatory.get("policy_effective_date"),
            "change_detection": policy_change,
        }

    def build_jurisdiction_program_differentiation(self, regulatory):
        packet_type = regulatory.get("packet_type")
        return {
            "program": "va_community_care",
            "packet_type": packet_type,
            "jurisdiction_mode": "single_embedded_policy_manifest",
        }

    def build_conditional_requirement_logic(self, regulatory):
        authorization_required = False
        signature_targets = []

        for rule in regulatory.get("rules", []):
            if rule.get("rule_id") == "authorization_traceability":
                authorization_required = bool(rule.get("required_targets"))
            if rule.get("rule_id") == "signature_control":
                signature_targets = list(rule.get("required_targets", []))

        return {
            "authorization_required": authorization_required,
            "signature_targets": signature_targets,
        }

    def build_missing_requirement_forecasting(self, enforcement, compliance_checks):
        failed_checks = list(compliance_checks.get("failed_checks", [])) if isinstance(compliance_checks, dict) else []
        return {
            "missing_documents": list(enforcement.get("missing_documents", [])),
            "missing_fields": list(enforcement.get("missing_fields", [])),
            "failed_checks": failed_checks,
            "forecast_status": "gaps_remaining" if enforcement.get("missing_documents") or enforcement.get("missing_fields") or failed_checks else "requirements_met",
        }

    def build_rule_ambiguity_detection(self, packet, compliance_checks):
        ambiguous = []
        if any(conflict.get("severity") == "medium" for conflict in packet.conflicts):
            ambiguous.append("Moderate conflicts may require policy interpretation rather than purely deterministic routing.")
        if getattr(packet, "clinical_intelligence", {}).get("specialty_alignment_validation", {}).get("status") == "partial":
            ambiguous.append("Specialty alignment is partial and may require program-specific judgment.")
        for check in compliance_checks.get("checks", []):
            if check.get("status") == "warn":
                ambiguous.append(check.get("detail"))
        return {
            "ambiguous_rules": self.unique_preserve_order([item for item in ambiguous if item]),
        }

    def build_policy_change_impact_analysis(self, policy_change, compliance_risk):
        return {
            "active_policy_version": policy_change.get("active_policy_version"),
            "impact": "no_runtime_change_detected",
            "compliance_risk_level": compliance_risk.get("level"),
        }

    def build_requirement_waiver_detection(self, regulatory, packet):
        waivers = []
        packet_type = regulatory.get("packet_type")
        if packet_type == "clinical_minimal":
            waivers.append("Authorization traceability may not be required for minimal clinical packets.")
        if "consent" not in packet.detected_documents and packet_type != "full_submission":
            waivers.append("Consent may not be required for the currently inferred packet type.")
        return {
            "waivers": waivers,
            "waiver_detected": bool(waivers),
        }

    def build_policy_compliance_confidence(self, compliance_risk, enforcement, compliance_checks):
        score = 92
        score -= len(enforcement.get("missing_documents", [])) * 10
        score -= len(enforcement.get("missing_fields", [])) * 8
        score -= len(compliance_checks.get("failed_checks", [])) * 6 if isinstance(compliance_checks, dict) else 0
        score -= int(round(float(compliance_risk.get("risk_score", 0.0) or 0.0) * 18))
        score = max(0, min(score, 100))
        return {
            "score": score,
            "band": "high" if score >= 82 else "moderate" if score >= 62 else "low",
        }


class DeploymentIntelligenceAnalyzer(PostReviewTools):
    def analyze(self, packet):
        project_root = self.get_project_root()
        version_txt = self.read_text_file(project_root / "TrueCore" / "VERSION.txt")
        version_json = self.read_text_file(project_root / "version.json")
        dependency_status = getattr(packet, "architecture_intelligence", {}).get("dependency_risk_detection", {})
        packaging = self.build_packaging_integrity_checks(project_root)
        environment = self.build_environment_integrity_validation(project_root)
        drift = self.build_dependency_version_drift_checks(dependency_status)
        feature_flags = self.build_feature_flag_control_layer(packet)
        rollback = self.build_safe_rollback_detection(project_root, version_txt)
        release_health = self.build_release_health_monitoring(packet)
        config_routing = self.build_environment_specific_config_routing(packet)
        build_safety = self.build_build_safety_verification(project_root, packaging)
        compatibility = self.build_update_compatibility_analysis(version_txt, version_json, packet)
        confidence = self.build_deployment_confidence_scoring(environment, drift, build_safety, compatibility, packaging)

        return {
            "environment_integrity_validation": environment,
            "dependency_version_drift_checks": drift,
            "build_safety_verification": build_safety,
            "update_compatibility_analysis": compatibility,
            "feature_flag_control_layer": feature_flags,
            "safe_rollback_detection": rollback,
            "release_health_monitoring": release_health,
            "environment_specific_config_routing": config_routing,
            "packaging_integrity_checks": packaging,
            "deployment_confidence_scoring": confidence,
        }

    def build_environment_integrity_validation(self, project_root):
        checks = {
            "project_root_exists": project_root.exists(),
            "version_file_exists": (project_root / "TrueCore" / "VERSION.txt").exists(),
            "version_json_exists": (project_root / "version.json").exists(),
            "intel_package_exists": (project_root / "TrueCoreIntel").exists(),
        }
        return {
            "checks": checks,
            "status": "healthy" if all(checks.values()) else "attention_needed",
        }

    def build_dependency_version_drift_checks(self, dependency_status):
        dependencies = list(dependency_status.get("dependencies", []))
        drift = []
        for item in dependencies:
            if item.get("available") and not item.get("version"):
                drift.append(f"{item['module']} is importable but package version could not be resolved.")
        return {
            "dependencies": dependencies,
            "drift_notes": drift,
        }

    def build_build_safety_verification(self, project_root, packaging):
        build_script = (project_root / "TrueCore" / "dev" / "build.py").exists()
        return {
            "build_script_present": build_script,
            "packaging_integrity": packaging.get("status"),
            "status": "safe" if build_script and packaging.get("status") != "broken" else "attention_needed",
        }

    def build_update_compatibility_analysis(self, version_txt, version_json, packet):
        same_version = bool(version_txt and version_json and version_txt in version_json)
        return {
            "version_txt": version_txt,
            "version_json_contains_version": same_version,
            "submission_readiness": packet.output.get("submission_readiness"),
            "status": "compatible" if same_version else "review_needed",
        }

    def build_feature_flag_control_layer(self, packet):
        return {
            "flags": {
                "TRUECORE_DISABLE_INTEL": os.getenv("TRUECORE_DISABLE_INTEL", ""),
            },
            "intel_active": not bool(os.getenv("TRUECORE_DISABLE_INTEL", "")),
            "source_type": packet.source_type,
        }

    def build_safe_rollback_detection(self, project_root, version_txt):
        return {
            "rollback_artifacts_present": all(
                [
                    (project_root / "TrueCore" / "CHANGELOG.txt").exists(),
                    (project_root / "version.json").exists(),
                    bool(version_txt),
                ]
            ),
            "current_version": version_txt,
        }

    def build_release_health_monitoring(self, packet):
        return {
            "pipeline_completed": bool(packet.output.get("review_summary")),
            "packet_confidence": packet.packet_confidence,
            "review_priority": packet.review_priority,
        }

    def build_environment_specific_config_routing(self, packet):
        return {
            "platform": "windows_desktop",
            "source_type": packet.source_type,
            "routing_mode": "local_filesystem_processing",
        }

    def build_packaging_integrity_checks(self, project_root):
        checks = {
            "launcher_source_present": (project_root / "TrueCore" / "launcher" / "launcher_app.py").exists(),
            "engine_entry_present": (project_root / "TrueCore" / "ui" / "truecore_app.py").exists(),
            "intel_bridge_present": (project_root / "TrueCore" / "core" / "intel_bridge.py").exists(),
            "intel_package_present": (project_root / "TrueCoreIntel" / "intel_engine.py").exists(),
        }
        return {
            "checks": checks,
            "status": "healthy" if all(checks.values()) else "broken",
        }

    def build_deployment_confidence_scoring(self, environment, drift, build_safety, compatibility, packaging):
        score = 94
        if environment.get("status") != "healthy":
            score -= 18
        score -= len(drift.get("drift_notes", [])) * 6
        if build_safety.get("status") != "safe":
            score -= 14
        if compatibility.get("status") != "compatible":
            score -= 12
        if packaging.get("status") != "healthy":
            score -= 20
        score = max(0, min(score, 100))
        return {
            "score": score,
            "band": "high" if score >= 84 else "moderate" if score >= 66 else "low",
        }


class PostReviewIntelligenceEngine:
    def __init__(self):
        self.denial = DenialIntelligenceAnalyzer()
        self.human = HumanInTheLoopIntelligenceAnalyzer()
        self.orchestration = OrchestrationIntelligenceAnalyzer()
        self.architecture = ArchitectureIntelligenceAnalyzer()
        self.recovery = RecoveryIntelligenceAnalyzer()
        self.policy = PolicyIntelligenceAnalyzer()
        self.deployment = DeploymentIntelligenceAnalyzer()

    def enrich(self, packet):
        packet.denial_intelligence = {}
        packet.human_loop_intelligence = {}
        packet.orchestration_intelligence = {}
        packet.architecture_intelligence = {}
        packet.recovery_intelligence = {}
        packet.policy_intelligence = {}
        packet.deployment_intelligence = {}

        packet.denial_intelligence = self.denial.analyze(packet)
        packet.human_loop_intelligence = self.human.analyze(packet)
        packet.orchestration_intelligence = self.orchestration.analyze(packet)
        packet.architecture_intelligence = self.architecture.analyze(packet)
        packet.recovery_intelligence = self.recovery.analyze(packet)
        packet.policy_intelligence = self.policy.analyze(packet)
        packet.deployment_intelligence = self.deployment.analyze(packet)
        return packet
