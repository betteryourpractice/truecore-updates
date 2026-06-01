from TrueCoreIntel.review.autonomy_engine import AutonomousIntelligenceBuilder
from TrueCoreIntel.review.data_engine import DataIntelligenceBuilder
from TrueCoreIntel.review.integration_engine import IntegrationIntelligenceBuilder
from TrueCoreIntel.review.knowledge_engine import KnowledgeIntelligenceBuilder
from TrueCoreIntel.review.monitoring_engine import MonitoringIntelligenceBuilder
from TrueCoreIntel.review.review_compliance_mixin import ReviewComplianceMixin
from TrueCoreIntel.review.review_predictive_mixin import ReviewPredictiveMixin
from TrueCoreIntel.review.review_summary_builder import ReviewSummaryBuilder
from TrueCoreIntel.review.security_engine import SecurityIntelligenceBuilder
from TrueCoreIntel.review.simulation_engine import SimulationIntelligenceBuilder
from TrueCoreIntel.review.strategy_engine import StrategicIntelligenceBuilder
from TrueCoreIntel.review.ux_engine import UXIntelligenceBuilder
from TrueCoreIntel.core import packet_archetypes
from TrueCore.core.statistical_scoring import (
    build_outcome_model,
    build_packet_feature_map,
    predict_outcome_probability,
    summarize_outcome_model,
)


class ReviewEngine(ReviewComplianceMixin, ReviewPredictiveMixin):
    AUTHORIZATION_DOCUMENT_TYPES = packet_archetypes.AUTHORIZATION_DOCUMENT_TYPES

    HIGH_PRIORITY_FIELDS = {"name", "dob", "authorization_number"}
    MEDIUM_PRIORITY_FIELDS = {"icd_codes", "reason_for_request", "ordering_provider", "referring_provider"}
    SUMMARY_BUILDER = ReviewSummaryBuilder(HIGH_PRIORITY_FIELDS, MEDIUM_PRIORITY_FIELDS)
    NON_BLOCKING_REVIEW_FLAGS = {
        "partial_diagnosis_icd_alignment",
        "moderate_mri_justification",
    }
    HOLD_REVIEW_FLAGS = {
        "packet_integrity_risk",
        "procedure_without_medical_support",
        "weak_mri_justification",
    }
    SUCCESS_PACKET_PROFILES = {
        key: {
            "required_documents": set(config.get("required_documents", set()) or set()),
            "expected_fields": set(config.get("expected_fields", set()) or set()),
            "supportive_fields": set(config.get("supportive_fields", set()) or set()),
        }
        for key, config in packet_archetypes.SUBMISSION_PROFILES.items()
    }
    DOC_SEQUENCE_REASONS = {
        "cover_sheet": "Lead with the routing summary and veteran identifiers.",
        "rfs": "Place the authorization or Request for Service early so downstream reviewers can anchor the referral.",
        "approved_referral": "Place the VA referral early so downstream reviewers can anchor the authorization context.",
        "consult_request": "Keep the consult request near the front so ordering context is visible before clinical detail.",
        "seoc": "Place the episode-of-care document before the medical-necessity narrative.",
        "lomn": "Follow the request documents with the medical-necessity narrative.",
        "consent": "Keep the signed consent with the core submission packet before supporting clinical notes.",
        "clinical_notes": "Place supporting clinical evidence after routing, authorization, and medical-necessity documents.",
        "unknown": "Keep unmatched pages at the end until they are manually reviewed.",
    }
    VOLUME_PROXY_BASELINES = {
        "full_submission": 0.92,
        "authorization_request": 1.0,
        "clinical_minimal": 0.72,
    }
    TURNAROUND_QUEUE_HOURS = {
        "submission_queue": 8,
        "review_queue": 28,
        "correction_queue": 52,
        "senior_review_queue": 76,
    }
    FINAL_DECISION_BUFFER_HOURS = {
        "submission_queue": 24,
        "review_queue": 48,
        "correction_queue": 72,
        "senior_review_queue": 96,
    }
    OPTIMIZATION_ROLE_SKILLS = {
        "submission_specialist": ["final_submission", "packet_qc"],
        "review_specialist": ["clinical_review", "cross_document_validation"],
        "corrections_specialist": ["packet_completion", "document_collection"],
        "senior_reviewer": ["high_risk_review", "identity_resolution"],
    }
    COMPLIANCE_POLICY_VERSION = "va_cc_compliance_v1"
    COMPLIANCE_POLICY_EFFECTIVE_DATE = "2026-03-24"
    COMPLIANCE_SIGNATURE_REQUIRED_DOCS = {"consent"}
    COMPLIANCE_SECURE_FIELDS = {"name", "dob", "authorization_number", "va_icn", "claim_number"}

    def review(self, packet):
        packet_archetypes.annotate_packet_context(packet)
        self.build_review_summary(packet)

        if self.requires_review(packet):
            packet.needs_review = True
            packet.review_priority = self.assign_priority(packet)
            self.flag_packet(packet)

        return packet

    def requires_review(self, packet):
        decision = packet.output.get("submission_decision") or self.build_submission_decision(packet)
        return decision.get("readiness") != "ready"

    def assign_priority(self, packet):
        high_missing = any(field in self.HIGH_PRIORITY_FIELDS for field in packet.missing_fields)
        rubric = dict(getattr(packet, "packet_rubric", {}) or {})
        blockers = list(rubric.get("blockers", []) or [])
        blocking_conflict_fields = set(rubric.get("blocking_conflict_fields", []) or [])
        actionable_flags = set(self.get_actionable_review_flags(packet))

        if blockers:
            return "high"

        if blocking_conflict_fields:
            return "high"

        if "packet_integrity_risk" in actionable_flags:
            return "high"

        if high_missing or len(packet.missing_fields) >= 3 or len(packet.missing_documents) >= 3:
            return "high"

        if packet.packet_strength == "weak":
            return "normal"

        if packet.missing_fields or packet.missing_documents or packet.conflicts:
            return "normal"

        if actionable_flags:
            return "normal"

        return "low"

    def flag_packet(self, packet):
        if (
            "manual_review_required" not in packet.review_flags
            and (
                packet.missing_fields
                or packet.missing_documents
                or packet.conflicts
                or packet.packet_strength == "weak"
                or self.get_actionable_review_flags(packet)
            )
        ):
            packet.review_flags.append("manual_review_required")

    def get_actionable_review_flags(self, packet):
        return [
            flag
            for flag in packet.review_flags
            if flag != "manual_review_required" and flag not in self.NON_BLOCKING_REVIEW_FLAGS
        ]

    def apply_statistical_outcome_model(self, packet):
        heuristic_probability = packet.approval_probability if packet.approval_probability is not None else 0.5
        model = build_outcome_model()
        model_summary = summarize_outcome_model(model)
        feature_map = build_packet_feature_map(packet)
        prediction = predict_outcome_probability(model, feature_map)

        if not prediction.get("available"):
            modeling = {
                "available": False,
                "heuristic_probability": round(heuristic_probability, 2),
                "final_probability": round(heuristic_probability, 2),
                "blend_weight": 0.0,
                "reason": model_summary.get("reason") or "insufficient_labeled_history",
                "model_summary": model_summary,
                "feature_map": feature_map,
            }
            packet.metrics["statistical_outcome_modeling"] = modeling
            packet.output["statistical_probability_model"] = modeling
            return modeling

        model_probability = prediction.get("calibrated_probability")
        if model_probability is None:
            model_probability = prediction.get("raw_probability")
        if model_probability is None:
            model_probability = heuristic_probability

        reliability = float(prediction.get("reliability_score") or 0.0)
        sample_size = int(model_summary.get("sample_size") or 0)
        sample_factor = min(sample_size / 80.0, 1.0)
        blend_weight = round(min(0.72, reliability * sample_factor * 0.72), 2)
        if reliability >= 0.45 and sample_size >= 12:
            blend_weight = max(blend_weight, 0.18)

        blended_probability = ((1.0 - blend_weight) * heuristic_probability) + (blend_weight * float(model_probability))
        blended_probability = round(max(0.01, min(blended_probability, 0.99)), 2)
        packet.approval_probability = blended_probability

        modeling = {
            "available": True,
            "heuristic_probability": round(heuristic_probability, 2),
            "raw_probability": prediction.get("raw_probability"),
            "calibrated_probability": prediction.get("calibrated_probability"),
            "final_probability": blended_probability,
            "blend_weight": blend_weight,
            "reliability_score": prediction.get("reliability_score"),
            "reliability_band": prediction.get("reliability_band"),
            "sample_size": sample_size,
            "positive_count": model_summary.get("positive_count"),
            "negative_count": model_summary.get("negative_count"),
            "brier_score": model_summary.get("brier_score"),
            "roc_auc": model_summary.get("roc_auc"),
            "ece": model_summary.get("ece"),
            "model_type": model_summary.get("model_type"),
            "evaluation_basis": model_summary.get("evaluation_basis"),
            "feature_map": feature_map,
        }
        packet.metrics["statistical_outcome_modeling"] = modeling
        packet.output["statistical_probability_model"] = modeling
        packet.output["approval_probability"] = blended_probability
        return modeling

    def build_review_summary(self, packet):
        summary_artifacts = self.SUMMARY_BUILDER.build(packet)
        self.apply_statistical_outcome_model(packet)

        packet.output["review_summary"] = {
            "why_weak": summary_artifacts.why_weak,
            "missing_items": summary_artifacts.missing_items,
            "conflict_items": summary_artifacts.conflict_items,
            "fix_recommendations": summary_artifacts.fix_recommendations,
            "priority_fixes": summary_artifacts.prioritized_fixes,
        }

        submission_decision = self.build_submission_decision(packet)
        decision_intelligence = self.build_decision_intelligence(packet, submission_decision)
        submission_decision["next_action"] = decision_intelligence["recommended_next_action"]["action"]
        submission_decision["workflow_route"] = decision_intelligence["workflow_decision_routing"]["queue"]
        submission_decision["escalated"] = decision_intelligence["escalation_trigger"]["escalate"]
        packet.output["submission_decision"] = submission_decision
        packet.output["submission_readiness"] = self.map_legacy_submission_readiness(
            submission_decision["readiness"]
        )
        packet.output["decision_intelligence"] = decision_intelligence
        packet.output["recommended_next_action"] = decision_intelligence["recommended_next_action"]
        packet.output["denial_risk"] = decision_intelligence["denial_risk_prediction"]
        packet.output["missing_evidence_recommendations"] = decision_intelligence["missing_evidence_recommendations"]
        packet.output["procedure_fit_analysis"] = decision_intelligence["procedure_to_documentation_fit"]
        packet.output["submission_sequence"] = decision_intelligence["submission_sequence_optimization"]
        packet.output["workflow_route"] = decision_intelligence["workflow_decision_routing"]
        packet.output["resubmission_strategy"] = decision_intelligence["resubmission_strategy"]
        packet.output["success_pattern_match"] = decision_intelligence["packet_success_pattern_match"]
        predictive_intelligence = self.build_predictive_intelligence(
            packet,
            submission_decision,
            decision_intelligence,
        )
        packet.output["predictive_intelligence"] = predictive_intelligence
        packet.output["approval_outcome_prediction"] = predictive_intelligence["approval_outcome_prediction"]
        packet.output["turnaround_time_prediction"] = predictive_intelligence["turnaround_time_prediction"]
        packet.output["bottleneck_detection"] = predictive_intelligence["bottleneck_detection"]
        packet.output["provider_performance_prediction"] = predictive_intelligence["provider_performance_prediction"]
        packet.output["denial_reason_forecasting"] = predictive_intelligence["denial_reason_forecasting"]
        packet.output["volume_trend_prediction"] = predictive_intelligence["volume_trend_prediction"]
        packet.output["staffing_demand_forecasting"] = predictive_intelligence["staffing_demand_forecasting"]
        packet.output["submission_timing_optimization"] = predictive_intelligence["submission_timing_optimization"]
        packet.output["case_complexity"] = predictive_intelligence["case_complexity_scoring"]
        packet.output["predictive_escalation"] = predictive_intelligence["predictive_escalation"]
        optimization_intelligence = self.build_optimization_intelligence(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
        )
        packet.output["optimization_intelligence"] = optimization_intelligence
        packet.output["workflow_efficiency_optimization"] = optimization_intelligence["workflow_efficiency_optimization"]
        packet.output["resource_allocation_optimization"] = optimization_intelligence["resource_allocation_optimization"]
        packet.output["processing_speed_optimization"] = optimization_intelligence["processing_speed_optimization"]
        packet.output["cost_efficiency_analysis"] = optimization_intelligence["cost_efficiency_analysis"]
        packet.output["redundancy_elimination"] = optimization_intelligence["redundancy_elimination"]
        packet.output["throughput_optimization"] = optimization_intelligence["throughput_optimization"]
        packet.output["error_rate_minimization"] = optimization_intelligence["error_rate_minimization"]
        packet.output["smart_queue_prioritization"] = optimization_intelligence["smart_queue_prioritization"]
        packet.output["load_balancing_engine"] = optimization_intelligence["load_balancing_engine"]
        packet.output["continuous_performance_tuning"] = optimization_intelligence["continuous_performance_tuning"]
        compliance_intelligence = self.build_compliance_intelligence(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
            optimization_intelligence,
        )
        packet.output["compliance_intelligence"] = compliance_intelligence
        packet.output["regulatory_rule_engine"] = compliance_intelligence["regulatory_rule_engine"]
        packet.output["compliance_validation_checks"] = compliance_intelligence["compliance_validation_checks"]
        packet.output["audit_trail_automation"] = compliance_intelligence["audit_trail_automation"]
        packet.output["policy_change_detection"] = compliance_intelligence["policy_change_detection"]
        packet.output["compliance_risk_scoring"] = compliance_intelligence["compliance_risk_scoring"]
        packet.output["documentation_requirement_enforcement"] = compliance_intelligence["documentation_requirement_enforcement"]
        packet.output["secure_data_handling_validation"] = compliance_intelligence["secure_data_handling_validation"]
        packet.output["audit_report_generation"] = compliance_intelligence["audit_report_generation"]
        packet.output["violation_detection"] = compliance_intelligence["violation_detection"]
        packet.output["compliance_workflow_routing"] = compliance_intelligence["compliance_workflow_routing"]
        knowledge_intelligence = KnowledgeIntelligenceBuilder().build(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
            compliance_intelligence,
        )
        packet.output["knowledge_intelligence"] = knowledge_intelligence
        packet.output["central_knowledge_base"] = knowledge_intelligence["central_knowledge_base"]
        packet.output["case_based_reasoning_engine"] = knowledge_intelligence["case_based_reasoning_engine"]
        packet.output["rule_learning_system"] = knowledge_intelligence["rule_learning_system"]
        packet.output["contextual_recommendation_engine"] = knowledge_intelligence["contextual_recommendation_engine"]
        packet.output["knowledge_gap_detection"] = knowledge_intelligence["knowledge_gap_detection"]
        packet.output["expert_system_integration"] = knowledge_intelligence["expert_system_integration"]
        packet.output["clinical_guideline_mapping"] = knowledge_intelligence["clinical_guideline_mapping"]
        packet.output["knowledge_version_control"] = knowledge_intelligence["knowledge_version_control"]
        packet.output["reasoning_transparency_layer"] = knowledge_intelligence["reasoning_transparency_layer"]
        packet.output["knowledge_feedback_loop"] = knowledge_intelligence["knowledge_feedback_loop"]
        data_intelligence = DataIntelligenceBuilder().build(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
            compliance_intelligence,
            knowledge_intelligence,
        )
        packet.output["data_intelligence"] = data_intelligence
        packet.output["unified_data_model"] = data_intelligence["unified_data_model"]
        packet.output["data_normalization_engine"] = data_intelligence["data_normalization_engine"]
        packet.output["data_integrity_validation"] = data_intelligence["data_integrity_validation"]
        packet.output["cross_source_data_linking"] = data_intelligence["cross_source_data_linking"]
        packet.output["data_deduplication_engine"] = data_intelligence["data_deduplication_engine"]
        packet.output["data_enrichment_layer"] = data_intelligence["data_enrichment_layer"]
        packet.output["metadata_extraction"] = data_intelligence["metadata_extraction"]
        packet.output["data_lineage_tracking"] = data_intelligence["data_lineage_tracking"]
        packet.output["structured_data_export"] = data_intelligence["structured_data_export"]
        packet.output["data_quality_scoring"] = data_intelligence["data_quality_scoring"]
        integration_intelligence = IntegrationIntelligenceBuilder().build(
            packet,
            submission_decision,
            decision_intelligence,
            compliance_intelligence,
            data_intelligence,
        )
        packet.output["integration_intelligence"] = integration_intelligence
        packet.output["api_integration_layer"] = integration_intelligence["api_integration_layer"]
        packet.output["ehr_integration"] = integration_intelligence["ehr_integration"]
        packet.output["billing_system_integration"] = integration_intelligence["billing_system_integration"]
        packet.output["crm_integration"] = integration_intelligence["crm_integration"]
        packet.output["document_repository_sync"] = integration_intelligence["document_repository_sync"]
        packet.output["third_party_data_ingestion"] = integration_intelligence["third_party_data_ingestion"]
        packet.output["integration_health_monitoring"] = integration_intelligence["integration_health_monitoring"]
        packet.output["data_sync_conflict_resolution"] = integration_intelligence["data_sync_conflict_resolution"]
        packet.output["webhook_event_system"] = integration_intelligence["webhook_event_system"]
        packet.output["integration_security_controls"] = integration_intelligence["integration_security_controls"]
        security_intelligence = SecurityIntelligenceBuilder().build(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
            compliance_intelligence,
            integration_intelligence,
        )
        packet.output["security_intelligence"] = security_intelligence
        packet.output["access_control_enforcement"] = security_intelligence["access_control_enforcement"]
        packet.output["threat_detection_engine"] = security_intelligence["threat_detection_engine"]
        packet.output["data_encryption_management"] = security_intelligence["data_encryption_management"]
        packet.output["intrusion_detection_system"] = security_intelligence["intrusion_detection_system"]
        packet.output["risk_assessment_engine"] = security_intelligence["risk_assessment_engine"]
        packet.output["security_audit_logging"] = security_intelligence["security_audit_logging"]
        packet.output["compliance_security_validation"] = security_intelligence["compliance_security_validation"]
        packet.output["identity_verification_system"] = security_intelligence["identity_verification_system"]
        packet.output["secure_data_sharing"] = security_intelligence["secure_data_sharing"]
        packet.output["security_incident_response"] = security_intelligence["security_incident_response"]
        ux_intelligence = UXIntelligenceBuilder().build(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
            optimization_intelligence,
            compliance_intelligence,
            knowledge_intelligence,
            security_intelligence,
        )
        packet.output["ux_intelligence"] = ux_intelligence
        packet.output["adaptive_interface_engine"] = ux_intelligence["adaptive_interface_engine"]
        packet.output["smart_dashboard_generation"] = ux_intelligence["smart_dashboard_generation"]
        packet.output["workflow_visualization"] = ux_intelligence["workflow_visualization"]
        packet.output["user_behavior_tracking"] = ux_intelligence["user_behavior_tracking"]
        packet.output["interface_personalization"] = ux_intelligence["interface_personalization"]
        packet.output["guided_workflow_assistance"] = ux_intelligence["guided_workflow_assistance"]
        packet.output["error_prevention_ui"] = ux_intelligence["error_prevention_ui"]
        packet.output["feedback_capture_system"] = ux_intelligence["feedback_capture_system"]
        packet.output["ux_performance_metrics"] = ux_intelligence["ux_performance_metrics"]
        packet.output["continuous_ux_improvement"] = ux_intelligence["continuous_ux_improvement"]
        monitoring_intelligence = MonitoringIntelligenceBuilder().build(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
            optimization_intelligence,
            compliance_intelligence,
            integration_intelligence,
            security_intelligence,
        )
        packet.output["monitoring_intelligence"] = monitoring_intelligence
        packet.output["real_time_system_monitoring"] = monitoring_intelligence["real_time_system_monitoring"]
        packet.output["performance_metrics_dashboard"] = monitoring_intelligence["performance_metrics_dashboard"]
        packet.output["error_tracking_system"] = monitoring_intelligence["error_tracking_system"]
        packet.output["alerting_engine"] = monitoring_intelligence["alerting_engine"]
        packet.output["resource_usage_monitoring"] = monitoring_intelligence["resource_usage_monitoring"]
        packet.output["latency_tracking"] = monitoring_intelligence["latency_tracking"]
        packet.output["uptime_monitoring"] = monitoring_intelligence["uptime_monitoring"]
        packet.output["incident_detection"] = monitoring_intelligence["incident_detection"]
        packet.output["monitoring_analytics"] = monitoring_intelligence["monitoring_analytics"]
        packet.output["observability_integration"] = monitoring_intelligence["observability_integration"]
        simulation_intelligence = SimulationIntelligenceBuilder().build(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
            optimization_intelligence,
            compliance_intelligence,
            knowledge_intelligence,
            monitoring_intelligence,
        )
        packet.output["simulation_intelligence"] = simulation_intelligence
        packet.output["scenario_simulation_engine"] = simulation_intelligence["scenario_simulation_engine"]
        packet.output["what_if_analysis_system"] = simulation_intelligence["what_if_analysis_system"]
        packet.output["synthetic_data_generation"] = simulation_intelligence["synthetic_data_generation"]
        packet.output["stress_testing_engine"] = simulation_intelligence["stress_testing_engine"]
        packet.output["failure_simulation"] = simulation_intelligence["failure_simulation"]
        packet.output["training_simulation_mode"] = simulation_intelligence["training_simulation_mode"]
        packet.output["simulation_result_analysis"] = simulation_intelligence["simulation_result_analysis"]
        packet.output["optimization_testing"] = simulation_intelligence["optimization_testing"]
        packet.output["risk_simulation"] = simulation_intelligence["risk_simulation"]
        packet.output["continuous_simulation_loop"] = simulation_intelligence["continuous_simulation_loop"]
        autonomy_intelligence = AutonomousIntelligenceBuilder().build(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
            optimization_intelligence,
            compliance_intelligence,
            monitoring_intelligence,
            simulation_intelligence,
            security_intelligence,
        )
        packet.output["autonomy_intelligence"] = autonomy_intelligence
        packet.output["fully_autonomous_packet_processing"] = autonomy_intelligence["fully_autonomous_packet_processing"]
        packet.output["self_healing_system"] = autonomy_intelligence["self_healing_system"]
        packet.output["autonomous_decision_engine"] = autonomy_intelligence["autonomous_decision_engine"]
        packet.output["dynamic_workflow_adjustment"] = autonomy_intelligence["dynamic_workflow_adjustment"]
        packet.output["self_optimization_loop"] = autonomy_intelligence["self_optimization_loop"]
        packet.output["autonomous_learning_system"] = autonomy_intelligence["autonomous_learning_system"]
        packet.output["autonomous_resource_allocation"] = autonomy_intelligence["autonomous_resource_allocation"]
        packet.output["self_monitoring_intelligence"] = autonomy_intelligence["self_monitoring_intelligence"]
        packet.output["autonomous_compliance_enforcement"] = autonomy_intelligence["autonomous_compliance_enforcement"]
        packet.output["autonomous_reporting_system"] = autonomy_intelligence["autonomous_reporting_system"]
        strategic_intelligence = StrategicIntelligenceBuilder().build(
            packet,
            decision_intelligence,
            predictive_intelligence,
            optimization_intelligence,
            compliance_intelligence,
            monitoring_intelligence,
            autonomy_intelligence,
        )
        packet.output["strategic_intelligence"] = strategic_intelligence
        packet.output["executive_dashboard"] = strategic_intelligence["executive_dashboard"]
        packet.output["strategic_decision_support"] = strategic_intelligence["strategic_decision_support"]
        packet.output["roi_analysis_engine"] = strategic_intelligence["roi_analysis_engine"]
        packet.output["growth_opportunity_detection"] = strategic_intelligence["growth_opportunity_detection"]
        packet.output["competitive_benchmarking"] = strategic_intelligence["competitive_benchmarking"]
        packet.output["strategic_forecasting"] = strategic_intelligence["strategic_forecasting"]
        packet.output["operational_risk_analysis"] = strategic_intelligence["operational_risk_analysis"]
        packet.output["investment_optimization"] = strategic_intelligence["investment_optimization"]
        packet.output["performance_benchmarking"] = strategic_intelligence["performance_benchmarking"]
        packet.output["strategic_planning_support"] = strategic_intelligence["strategic_planning_support"]
        packet.output["approval_rationale"] = self.build_approval_rationale(packet)

    def compress_why_weak(self, reasons):
        return self.SUMMARY_BUILDER.compress_why_weak(reasons)


    def build_prioritized_fixes(self, packet):
        return self.SUMMARY_BUILDER.build_prioritized_fixes(packet)

    def get_field_priority(self, field):
        return self.SUMMARY_BUILDER.get_field_priority(field)

    def build_submission_decision(self, packet):
        rubric = dict(getattr(packet, "packet_rubric", {}) or {})
        semantic = dict(getattr(packet, "semantic_adjudication", {}) or {})
        semantic_score = float(semantic.get("overall_score") or 0.0)
        variant_tolerance = dict(semantic.get("variant_tolerance", {}) or {})
        rubric_blockers = list(rubric.get("blockers", []) or [])
        rubric_review_needs = list(rubric.get("review_needs", []) or [])
        actionable_flags = set(self.get_actionable_review_flags(packet))
        hold_reasons = []
        review_reasons = []
        assembly_score = getattr(packet, "packet_assembly_score", None)

        hold_reasons.extend(rubric_blockers)
        review_reasons.extend(rubric_review_needs)

        if packet.missing_fields:
            hold_reasons.append(
                f"Required fields are missing: {', '.join(sorted(packet.missing_fields))}."
            )

        if packet.missing_documents:
            hold_reasons.append(
                f"Required documents are missing: {', '.join(sorted(packet.missing_documents))}."
            )

        high_conflict_fields = sorted(set(rubric.get("blocking_conflict_fields", []) or []))
        if high_conflict_fields:
            hold_reasons.append(
                f"High-severity conflicts must be resolved first: {', '.join(high_conflict_fields)}."
            )

        if assembly_score is not None and assembly_score < 55:
            hold_reasons.append("Packet assembly quality is too weak for submission and should be corrected first.")

        if self.HOLD_REVIEW_FLAGS.intersection(actionable_flags):
            for flag in sorted(self.HOLD_REVIEW_FLAGS.intersection(actionable_flags)):
                hold_reasons.append(self.describe_decision_flag(flag, hold=True))

        medium_or_low_conflict_fields = sorted({
            conflict.get("field", "unknown_field")
            for conflict in packet.conflicts
            if conflict.get("severity") in {"medium", "low"}
        })
        if medium_or_low_conflict_fields:
            review_reasons.append(
                f"Reviewer confirmation is needed for: {', '.join(medium_or_low_conflict_fields)}."
            )

        review_flags = actionable_flags.difference(self.HOLD_REVIEW_FLAGS)
        for flag in sorted(review_flags):
            description = self.describe_decision_flag(flag, hold=False)
            if description:
                review_reasons.append(description)

        if packet.packet_strength == "weak" and not hold_reasons:
            review_reasons.append("Packet quality is still weak enough to need reviewer confirmation before submission.")

        if assembly_score is not None and 55 <= assembly_score < 72 and not hold_reasons:
            review_reasons.append("Packet assembly is incomplete enough to require reviewer confirmation.")

        if (
            packet.packet_confidence is not None
            and packet.packet_confidence < 0.78
            and not hold_reasons
            and not (semantic_score >= 84 and variant_tolerance.get("coherent_despite_variation"))
        ):
            review_reasons.append("Packet confidence is below the auto-submit threshold.")

        if semantic_score < 45 and not hold_reasons:
            review_reasons.append("Packet meaning is still semantically unstable across documents.")

        if hold_reasons:
            readiness = "hold"
        elif review_reasons:
            readiness = "requires_review"
        else:
            readiness = "ready"

        return {
            "readiness": readiness,
            "hold_reasons": self.unique_preserve_order(hold_reasons),
            "review_reasons": self.unique_preserve_order(review_reasons),
            "next_action": self.build_next_action_for_decision(packet, readiness),
        }

    def build_decision_intelligence(self, packet, submission_decision):
        packet_type = self.infer_review_packet_type(packet)
        procedure_fit = self.build_procedure_fit_analysis(packet)
        success_pattern = self.build_packet_success_pattern_match(packet, packet_type, procedure_fit)
        missing_evidence = self.build_missing_evidence_recommendations(packet, procedure_fit, success_pattern)
        submission_sequence = self.build_submission_sequence_optimization(packet, packet_type)
        recommended_next_action = self.build_recommended_next_action(
            packet,
            submission_decision,
            missing_evidence,
            procedure_fit,
        )
        escalation = self.build_escalation_trigger(packet, submission_decision, procedure_fit, success_pattern)
        denial_risk = self.build_denial_risk_prediction(
            packet,
            submission_decision,
            procedure_fit,
            success_pattern,
            escalation,
        )
        workflow_route = self.build_workflow_decision_routing(
            packet,
            submission_decision,
            denial_risk,
            escalation,
            recommended_next_action,
        )
        resubmission_strategy = self.build_resubmission_strategy(
            packet,
            submission_decision,
            denial_risk,
            missing_evidence,
            procedure_fit,
        )

        return {
            "packet_type": packet_type,
            "recommended_next_action": recommended_next_action,
            "denial_risk_prediction": denial_risk,
            "missing_evidence_recommendations": missing_evidence,
            "procedure_to_documentation_fit": procedure_fit,
            "submission_sequence_optimization": submission_sequence,
            "workflow_decision_routing": workflow_route,
            "escalation_trigger": escalation,
            "resubmission_strategy": resubmission_strategy,
            "packet_success_pattern_match": success_pattern,
        }

    def build_workflow_efficiency_optimization(self, packet, submission_decision, predictive_intelligence):
        efficiency_score = 0.92
        waste_drivers = []
        recommendations = []

        if packet.missing_documents:
            efficiency_score -= min(0.22, 0.08 * len(packet.missing_documents))
            waste_drivers.append("Missing documents are forcing avoidable correction cycles.")
            recommendations.append("Request missing documents before deeper reviewer handling.")

        if packet.missing_fields:
            efficiency_score -= min(0.18, 0.06 * len(packet.missing_fields))
            waste_drivers.append("Missing fields create rework during validation and review.")
            recommendations.append("Front-load field completion before packet review.")

        if packet.conflicts:
            efficiency_score -= min(0.22, 0.07 * len(packet.conflicts))
            waste_drivers.append("Cross-document conflicts are causing repetitive reviewer checks.")
            recommendations.append("Resolve field conflicts before packets enter longer review queues.")

        if packet.duplicate_pages:
            efficiency_score -= 0.06
            waste_drivers.append("Duplicate pages add avoidable packet handling overhead.")
            recommendations.append("Remove duplicate pages prior to final assembly.")

        if predictive_intelligence["bottleneck_detection"]["stages"]:
            primary_stage = predictive_intelligence["bottleneck_detection"]["stages"][0]
            recommendations.append(f"Address the primary bottleneck first: {primary_stage['stage']}.")

        if submission_decision["readiness"] == "ready":
            efficiency_score += 0.04
        elif submission_decision["readiness"] == "hold":
            efficiency_score -= 0.08

        efficiency_score = round(max(0.05, min(efficiency_score, 0.99)), 2)
        if efficiency_score >= 0.82:
            status = "optimized"
        elif efficiency_score >= 0.62:
            status = "stable"
        elif efficiency_score >= 0.42:
            status = "strained"
        else:
            status = "inefficient"

        if not recommendations:
            recommendations.append("Current packet flow is already reasonably efficient for its risk profile.")

        return {
            "status": status,
            "efficiency_score": efficiency_score,
            "waste_drivers": self.unique_preserve_order(waste_drivers),
            "recommendations": self.unique_preserve_order(recommendations),
        }

    def build_resource_allocation_optimization(self, packet, decision_intelligence, predictive_intelligence):
        queue = decision_intelligence["workflow_decision_routing"]["queue"]
        complexity = predictive_intelligence["case_complexity_scoring"]["level"]
        denial_level = decision_intelligence["denial_risk_prediction"]["level"]

        if queue == "senior_review_queue" or complexity == "critical":
            role = "senior_reviewer"
        elif queue == "correction_queue":
            role = "corrections_specialist"
        elif queue == "review_queue":
            role = "review_specialist"
        else:
            role = "submission_specialist"

        staff_band = "senior" if role == "senior_reviewer" else ("clinical" if role == "review_specialist" else "operations")
        if denial_level in {"high", "critical"} and role != "senior_reviewer":
            staff_band = "clinical"

        reason = {
            "submission_specialist": "Packet is close to submission-ready and should stay with submission operations.",
            "review_specialist": "Packet needs reviewer judgment more than administrative correction work.",
            "corrections_specialist": "Packet needs document or field completion before routine review will be efficient.",
            "senior_reviewer": "Packet risk profile is high enough to justify senior handling.",
        }[role]

        return {
            "recommended_role": role,
            "staff_band": staff_band,
            "skills": list(self.OPTIMIZATION_ROLE_SKILLS[role]),
            "assignment_reason": reason,
        }

    def build_processing_speed_optimization(self, packet, predictive_intelligence):
        complexity_score = predictive_intelligence["case_complexity_scoring"]["score"]
        queue = predictive_intelligence["turnaround_time_prediction"]["queue"]
        estimated_minutes = 6 + max(1, len(packet.pages)) * 1.8 + (complexity_score * 0.55)

        if queue == "submission_queue":
            lane = "fast_track"
        elif queue == "review_queue":
            lane = "standard_review"
        elif queue == "correction_queue":
            lane = "correction_heavy"
        else:
            lane = "senior_review"

        recommendations = []
        if len(packet.pages) > 20:
            recommendations.append("Process packet in page-aware review mode to avoid repeated full-packet rescans.")
        if packet.duplicate_pages:
            recommendations.append("Strip duplicate pages before final reviewer handling.")
        if predictive_intelligence["bottleneck_detection"]["primary_stage"] == "document_collection":
            recommendations.append("Pause deeper review until document collection finishes.")
        if not recommendations:
            recommendations.append("Current packet can move through its assigned lane without extra speed intervention.")

        estimated_minutes = int(round(estimated_minutes))
        estimated_savings = 0
        if lane == "fast_track":
            estimated_savings = 8
        elif packet.duplicate_pages:
            estimated_savings = 5

        return {
            "lane": lane,
            "estimated_processing_minutes": estimated_minutes,
            "estimated_minutes_saved": estimated_savings,
            "recommendations": self.unique_preserve_order(recommendations),
        }

    def build_cost_efficiency_analysis(self, packet, submission_decision, predictive_intelligence, processing_speed):
        cost_units = 1.0
        cost_units += len(packet.pages) * 0.05
        cost_units += len(packet.missing_documents) * 0.55
        cost_units += len(packet.missing_fields) * 0.22
        cost_units += sum(0.7 for conflict in packet.conflicts if conflict.get("severity") == "high")
        cost_units += sum(0.3 for conflict in packet.conflicts if conflict.get("severity") == "medium")
        cost_units += predictive_intelligence["case_complexity_scoring"]["score"] * 0.018
        cost_units += processing_speed["estimated_processing_minutes"] / 50.0

        if submission_decision["readiness"] == "ready":
            cost_units -= 0.35

        cost_units = round(max(0.5, cost_units), 2)
        if cost_units >= 5.5:
            band = "high"
        elif cost_units >= 3.0:
            band = "moderate"
        else:
            band = "low"

        savings = []
        if packet.missing_documents:
            savings.append("Collect missing documents earlier to avoid expensive repeat handling.")
        if not packet.conflicts and submission_decision["readiness"] == "ready":
            savings.append("Packet is a good candidate for lower-touch operational handling.")
        if packet.duplicate_pages:
            savings.append("Removing duplicate pages reduces reviewer time and packet assembly churn.")
        if not savings:
            savings.append("Current packet cost profile is already near the efficient baseline for its complexity.")

        return {
            "cost_band": band,
            "estimated_cost_units": cost_units,
            "cost_avoidance_actions": self.unique_preserve_order(savings),
        }

    def build_redundancy_elimination(self, packet, decision_intelligence, predictive_intelligence):
        redundant_signals = []
        eliminated_steps = []

        if packet.duplicate_pages:
            redundant_signals.append("Duplicate pages were detected.")
            eliminated_steps.append("Remove repeated page review and packet assembly steps.")

        if packet.fields.get("provider") and packet.fields.get("ordering_provider") == packet.fields.get("provider"):
            redundant_signals.append("Generic and ordering provider values are identical.")
            eliminated_steps.append("Reuse provider identity across provider-role handling when role evidence matches.")

        missing_targets = {
            item.get("target")
            for item in decision_intelligence["missing_evidence_recommendations"]
            if item.get("target")
        }
        fix_targets = {
            item.get("target")
            for item in packet.output.get("review_summary", {}).get("priority_fixes", [])
            if item.get("target")
        }
        repeated_targets = sorted(target for target in missing_targets.intersection(fix_targets) if target)
        for target in repeated_targets:
            redundant_signals.append(f"Multiple corrective paths are pointing to the same target: {target}.")
            eliminated_steps.append(f"Collapse duplicate correction work around {target} into one action.")

        if not redundant_signals:
            redundant_signals.append("No obvious duplicate work pattern is currently exposed in the packet path.")

        return {
            "redundant_signals": self.unique_preserve_order(redundant_signals),
            "eliminated_steps": self.unique_preserve_order(eliminated_steps),
            "summary": self.unique_preserve_order(eliminated_steps)[0] if eliminated_steps else redundant_signals[0],
        }

    def build_throughput_optimization(self, packet, decision_intelligence, predictive_intelligence, processing_speed):
        complexity = predictive_intelligence["case_complexity_scoring"]["level"]
        queue = decision_intelligence["workflow_decision_routing"]["queue"]

        if queue == "submission_queue" and complexity in {"low", "moderate"}:
            lane = "submission_fast_lane"
            packets_per_hour = 6
        elif queue == "review_queue":
            lane = "review_lane"
            packets_per_hour = 3 if complexity in {"low", "moderate"} else 2
        elif queue == "correction_queue":
            lane = "correction_lane"
            packets_per_hour = 2
        else:
            lane = "senior_lane"
            packets_per_hour = 1

        batching = "single_packet_focus" if complexity in {"high", "critical"} else "micro_batch"
        if len(packet.pages) > 20:
            batching = "page_segmented_batch"

        return {
            "processing_lane": lane,
            "estimated_packets_per_hour": packets_per_hour,
            "batch_strategy": batching,
            "reason": f"Current packet complexity and queue assignment fit the {lane} profile.",
        }

    def build_error_rate_minimization(self, packet, decision_intelligence, predictive_intelligence):
        hotspots = []
        for field, confidence in (packet.field_confidence or {}).items():
            try:
                numeric_confidence = float(confidence)
            except (TypeError, ValueError):
                continue
            if numeric_confidence < 0.85:
                hotspots.append(field)

        hotspots.extend(
            conflict.get("field", "unknown")
            for conflict in packet.conflicts
            if conflict.get("severity") in {"medium", "high"}
        )
        hotspots = self.unique_preserve_order(hotspots)

        targeted_checks = []
        for field in hotspots[:6]:
            targeted_checks.append(f"Re-verify {field} before queue handoff.")
        if packet.review_flags:
            targeted_checks.append("Re-check packet review flags before finalizing queue placement.")
        if not targeted_checks:
            targeted_checks.append("Current packet has no strong error hotspot beyond routine QC.")

        risk_count = len(hotspots) + len(packet.review_flags)
        if risk_count >= 6:
            level = "high"
        elif risk_count >= 3:
            level = "moderate"
        else:
            level = "low"

        return {
            "risk_level": level,
            "error_hotspots": hotspots,
            "targeted_checks": self.unique_preserve_order(targeted_checks),
        }

    def build_smart_queue_prioritization(self, packet, submission_decision, decision_intelligence, predictive_intelligence, throughput):
        score = 18
        queue = decision_intelligence["workflow_decision_routing"]["queue"]
        denial_level = decision_intelligence["denial_risk_prediction"]["level"]
        turnaround_hours = predictive_intelligence["turnaround_time_prediction"]["estimated_submission_ready_hours"]
        complexity_score = predictive_intelligence["case_complexity_scoring"]["score"]

        score += {
            "submission_queue": 18,
            "review_queue": 30,
            "correction_queue": 40,
            "senior_review_queue": 55,
        }.get(queue, 20)
        score += {
            "low": 0,
            "moderate": 10,
            "high": 22,
            "critical": 34,
        }.get(denial_level, 0)
        score += min(18, len(packet.missing_documents) * 8)
        score += min(14, len(packet.missing_fields) * 4)
        score += int(complexity_score * 0.22)
        if turnaround_hours >= 72:
            score += 10
        if throughput["processing_lane"] == "submission_fast_lane":
            score -= 8

        score = max(0, min(score, 100))
        if score >= 78:
            bucket = "urgent"
            queue_order_hint = "process_immediately"
        elif score >= 58:
            bucket = "high"
            queue_order_hint = "next_available_slot"
        elif score >= 34:
            bucket = "normal"
            queue_order_hint = "routine_sequence"
        else:
            bucket = "low"
            queue_order_hint = "background_sequence"

        return {
            "priority_score": score,
            "priority_bucket": bucket,
            "queue_order_hint": queue_order_hint,
            "reason": f"Queue priority is driven by {queue}, denial risk, and current packet complexity.",
        }

    def build_load_balancing_engine(self, packet, decision_intelligence, predictive_intelligence, resource_allocation, smart_queue):
        queue = decision_intelligence["workflow_decision_routing"]["queue"]
        bucket = {
            "submission_queue": "submission_team",
            "review_queue": "review_team",
            "correction_queue": "correction_team",
            "senior_review_queue": "senior_review_team",
        }.get(queue, "general_team")

        strategy = "keep_with_specialist"
        if smart_queue["priority_bucket"] in {"urgent", "high"}:
            strategy = "route_to_next_available_specialist"
        elif predictive_intelligence["case_complexity_scoring"]["level"] in {"low", "moderate"}:
            strategy = "spread_evenly_across_standard_staff"

        return {
            "workload_pool": bucket,
            "recommended_role": resource_allocation["recommended_role"],
            "balance_strategy": strategy,
            "summary": f"Distribute packet within {bucket} using {strategy}.",
        }

    def build_continuous_performance_tuning(self, packet, predictive_intelligence, processing_speed, smart_queue, throughput):
        poll_seconds = 15
        stable_polls = 2
        ocr_strategy = "conservative"

        if smart_queue["priority_bucket"] == "urgent":
            poll_seconds = 8
        elif smart_queue["priority_bucket"] == "high":
            poll_seconds = 12
        elif smart_queue["priority_bucket"] == "low":
            poll_seconds = 20

        if len(packet.pages) > 20 or predictive_intelligence["bottleneck_detection"]["primary_stage"] == "document_collection":
            stable_polls = 3
        if packet.source_type in {"png", "jpg", "jpeg", "tif", "tiff"}:
            ocr_strategy = "aggressive"
        elif processing_speed["lane"] in {"correction_heavy", "senior_review"}:
            ocr_strategy = "balanced"

        adjustments = [
            f"Set poll interval target to {poll_seconds} seconds for the current workload profile.",
            f"Use stable-poll target {stable_polls} for safer intake on this packet mix.",
            f"Use {ocr_strategy} OCR handling for packets in this lane.",
        ]

        return {
            "runtime_profile": {
                "poll_seconds": poll_seconds,
                "stable_polls": stable_polls,
                "ocr_strategy": ocr_strategy,
                "throughput_lane": throughput["processing_lane"],
            },
            "dynamic_adjustments": adjustments,
            "safe_to_apply": True,
        }

    def build_optimization_intelligence(self, packet, submission_decision, decision_intelligence, predictive_intelligence):
        workflow_efficiency = self.build_workflow_efficiency_optimization(
            packet,
            submission_decision,
            predictive_intelligence,
        )
        resource_allocation = self.build_resource_allocation_optimization(
            packet,
            decision_intelligence,
            predictive_intelligence,
        )
        processing_speed = self.build_processing_speed_optimization(packet, predictive_intelligence)
        cost_efficiency = self.build_cost_efficiency_analysis(
            packet,
            submission_decision,
            predictive_intelligence,
            processing_speed,
        )
        redundancy_elimination = self.build_redundancy_elimination(
            packet,
            decision_intelligence,
            predictive_intelligence,
        )
        throughput = self.build_throughput_optimization(
            packet,
            decision_intelligence,
            predictive_intelligence,
            processing_speed,
        )
        error_minimization = self.build_error_rate_minimization(
            packet,
            decision_intelligence,
            predictive_intelligence,
        )
        smart_queue = self.build_smart_queue_prioritization(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
            throughput,
        )
        load_balancing = self.build_load_balancing_engine(
            packet,
            decision_intelligence,
            predictive_intelligence,
            resource_allocation,
            smart_queue,
        )
        tuning = self.build_continuous_performance_tuning(
            packet,
            predictive_intelligence,
            processing_speed,
            smart_queue,
            throughput,
        )

        return {
            "workflow_efficiency_optimization": workflow_efficiency,
            "resource_allocation_optimization": resource_allocation,
            "processing_speed_optimization": processing_speed,
            "cost_efficiency_analysis": cost_efficiency,
            "redundancy_elimination": redundancy_elimination,
            "throughput_optimization": throughput,
            "error_rate_minimization": error_minimization,
            "smart_queue_prioritization": smart_queue,
            "load_balancing_engine": load_balancing,
            "continuous_performance_tuning": tuning,
        }

    def infer_review_packet_type(self, packet):
        profile = packet_archetypes.infer_submission_profile(packet)
        packet.packet_profile = profile
        packet.packet_profile_label = packet_archetypes.get_submission_profile_label(profile)
        return profile

    def has_equivalent_document(self, packet, document_type):
        return packet_archetypes.has_equivalent_document(packet, document_type)

    def get_missing_required_documents(self, packet, required_documents):
        missing = []
        for document_type in sorted(set(required_documents or [])):
            if not self.has_equivalent_document(packet, document_type):
                missing.append(document_type)
        return missing

    def map_legacy_submission_readiness(self, readiness):
        mapping = {
            "ready": "ready",
            "requires_review": "needs_review",
            "hold": "not_ready",
        }
        return mapping.get(readiness, "needs_review")

    def describe_decision_flag(self, flag, hold=False):
        descriptions = {
            "packet_integrity_risk": "Identity or case integrity signals require the packet to be held.",
            "procedure_without_medical_support": "Requested procedure lacks sufficient clinical support and should be held.",
            "weak_mri_justification": "MRI justification is too weak for submission and should be held.",
            "diagnosis_icd_mismatch": "Diagnosis and ICD alignment needs reviewer confirmation.",
            "diagnosis_without_icd_support": "Diagnosis appears without matching ICD support and needs review.",
            "icd_without_diagnosis_support": "ICD coding appears without matching diagnosis language and needs review.",
            "missing_reason_for_request": "Reason for request is missing or unclear and should be reviewed.",
            "chronology_review_needed": "Service date chronology needs reviewer confirmation.",
            "duplicate_pages_present": "Duplicate pages should be reviewed before submission.",
            "partial_diagnosis_icd_alignment": "Diagnosis and ICD support are only partially aligned.",
            "moderate_mri_justification": "MRI justification is moderate and should be reviewed.",
        }
        description = descriptions.get(flag)
        if description:
            return description
        if hold:
            return f"Review flag requires the packet to be held: {flag}."
        return f"Review flag requires reviewer confirmation: {flag}."

    def build_next_action_for_decision(self, packet, readiness):
        if readiness == "ready":
            return "submit_packet"

        if readiness == "requires_review":
            return "route_to_review"

        prioritized_fixes = packet.output.get("review_summary", {}).get("priority_fixes", [])
        if prioritized_fixes:
            top_fix = prioritized_fixes[0]
            target = top_fix.get("target", "packet")
            return f"correct_{target}"

        return "hold_for_correction"

    def build_packet_success_pattern_match(self, packet, packet_type, procedure_fit):
        profile = self.SUCCESS_PACKET_PROFILES.get(
            packet_type,
            self.SUCCESS_PACKET_PROFILES["authorization_request"],
        )
        required_documents = set(profile["required_documents"])
        expected_fields = set(profile["expected_fields"])
        supportive_fields = set(profile["supportive_fields"])

        detected_documents = set(packet.detected_documents)
        present_fields = set(packet.fields)

        missing_profile_documents = self.get_missing_required_documents(packet, required_documents)
        missing_profile_fields = sorted(expected_fields.difference(present_fields))
        missing_supportive_fields = sorted(
            field for field in supportive_fields
            if field not in present_fields
        )

        document_ratio = (
            (len(required_documents) - len(missing_profile_documents)) / len(required_documents)
            if required_documents else 1.0
        )
        field_ratio = (
            len(expected_fields.intersection(present_fields)) / len(expected_fields)
            if expected_fields else 1.0
        )
        supportive_ratio = (
            len(supportive_fields.intersection(present_fields)) / len(supportive_fields)
            if supportive_fields else 1.0
        )

        if any(conflict.get("severity") == "high" for conflict in packet.conflicts):
            consistency_ratio = 0.1
        elif any(conflict.get("severity") == "medium" for conflict in packet.conflicts):
            consistency_ratio = 0.45
        elif packet.conflicts:
            consistency_ratio = 0.7
        else:
            consistency_ratio = 1.0

        confidence_ratio = packet.packet_confidence if packet.packet_confidence is not None else 0.8
        procedure_ratio = {
            "strong": 1.0,
            "moderate": 0.72,
            "weak": 0.28,
            "not_applicable": 0.88,
        }.get(procedure_fit["status"], 0.8)
        profile_confidence = self.estimate_success_pattern_confidence(packet, packet_type)

        match_score = (
            (document_ratio * 0.34) +
            (field_ratio * 0.28) +
            (supportive_ratio * 0.12) +
            (consistency_ratio * 0.12) +
            (confidence_ratio * 0.08) +
            (procedure_ratio * 0.06)
        )
        match_score = round(max(0.0, min(match_score, 1.0)), 2)

        if profile_confidence < 0.45:
            similarity = "limited"
        elif match_score >= 0.9:
            similarity = "strong"
        elif match_score >= 0.65:
            similarity = "moderate"
        else:
            similarity = "weak"

        matched_signals = []
        if document_ratio >= 1.0:
            matched_signals.append("Required document mix matches a successful packet profile.")
        elif document_ratio >= 0.66:
            matched_signals.append("Most of the expected document mix is already present.")

        if field_ratio >= 1.0:
            matched_signals.append("Core required fields match the expected successful packet profile.")
        elif field_ratio >= 0.7:
            matched_signals.append("Most core packet fields are already present.")

        if supportive_ratio >= 0.5:
            matched_signals.append("Supportive packet context is present across multiple documents.")

        if consistency_ratio >= 1.0:
            matched_signals.append("No cross-document conflicts are pulling the packet away from successful patterns.")

        if procedure_ratio >= 0.72:
            matched_signals.append("Procedure support is aligned with successful packet expectations.")

        if profile_confidence < 0.45:
            matched_signals.append("Historical packet-shape matching is low-confidence because document detection is sparse.")

        gaps = []
        if profile_confidence >= 0.45:
            for doc in missing_profile_documents:
                gaps.append(f"Missing successful-pattern document: {doc}.")
        for field in missing_profile_fields:
            gaps.append(f"Missing successful-pattern field: {field}.")
        for field in missing_supportive_fields[:3]:
            gaps.append(f"Helpful supporting field is absent: {field}.")

        if consistency_ratio < 1.0:
            gaps.append("Cross-document conflicts reduce similarity to successful packets.")

        if procedure_fit["status"] == "weak":
            gaps.append("Procedure support is weaker than successful packet patterns typically show.")

        if profile_confidence < 0.45:
            gaps.append("Document-type evidence is too sparse to treat packet-shape mismatch as a strong historical risk signal.")

        return {
            "profile": packet_type,
            "historical_basis": "deterministic_success_profile_v1",
            "similarity": similarity,
            "match_score": match_score,
            "confidence": round(profile_confidence, 2),
            "matched_signals": self.unique_preserve_order(matched_signals),
            "gaps": self.unique_preserve_order(gaps),
        }

    def estimate_success_pattern_confidence(self, packet, packet_type):
        detected_documents = set(packet.detected_documents)
        avg_page_confidence = (
            sum(packet.page_confidence.values()) / len(packet.page_confidence)
            if packet.page_confidence else 0.0
        )

        if not detected_documents:
            return min(0.4, 0.2 + (avg_page_confidence * 0.25))

        if packet_type == "clinical_minimal" and len(detected_documents) <= 1:
            return min(0.7, 0.45 + (avg_page_confidence * 0.25))

        if len(detected_documents) <= 2:
            return min(0.8, 0.5 + (avg_page_confidence * 0.25))

        return min(1.0, 0.7 + (avg_page_confidence * 0.2))

    def build_procedure_fit_analysis(self, packet):
        procedure = packet.fields.get("procedure")
        diagnosis = packet.fields.get("diagnosis")
        symptom = packet.fields.get("symptom")
        reason_for_request = packet.fields.get("reason_for_request")
        icd_codes = packet.fields.get("icd_codes") or []

        if not procedure:
            return {
                "procedure": None,
                "status": "not_applicable",
                "fit_score": 0.85,
                "supporting_signals": [],
                "gaps": [],
                "summary": "No procedure was extracted, so fit analysis is not required.",
            }

        justification_link = None
        for link in packet.evidence_links:
            if link.get("type") == "procedure_justification" and link.get("procedure") == procedure:
                justification_link = link
                break

        status = justification_link.get("status") if justification_link else None
        if not status:
            if diagnosis or symptom:
                status = "moderate"
            else:
                status = "weak"

        fit_score = {
            "strong": 0.92,
            "moderate": 0.68,
            "weak": 0.28,
        }.get(status, 0.5)

        supporting_signals = []
        if diagnosis:
            supporting_signals.append(f"Diagnosis present: {diagnosis}.")
        if symptom:
            supporting_signals.append(f"Symptom present: {symptom}.")
        if reason_for_request:
            supporting_signals.append("Reason-for-request narrative is present.")
        if icd_codes:
            supporting_signals.append(f"ICD support present: {', '.join(icd_codes)}.")
        if justification_link and justification_link.get("status") == "strong":
            supporting_signals.append("Clinical justification already supports the requested procedure strongly.")

        gaps = []
        if not diagnosis:
            gaps.append("Add diagnosis language that supports the requested procedure.")
        if not symptom:
            gaps.append("Add symptom language showing why the procedure is needed.")
        if not reason_for_request:
            gaps.append("Add a reason-for-request statement that ties the procedure to the clinical problem.")
        if not icd_codes:
            gaps.append("Add ICD coding aligned to the procedure-related diagnosis.")

        if procedure == "MRI" and status in {"moderate", "weak"}:
            gaps.append("Add failed conservative treatment, functional impairment, or neurologic deficit detail for MRI support.")
            gaps.append("Add clinical narrative explaining why advanced imaging is needed now.")

        if "procedure_without_medical_support" in packet.review_flags:
            gaps.append("Requested procedure is missing enough clinical support to clear review.")

        if "diagnosis_icd_mismatch" in packet.review_flags:
            gaps.append("Diagnosis and ICD coding should align more tightly with the requested procedure.")

        summary_map = {
            "strong": "Requested procedure is well supported by the current packet documentation.",
            "moderate": "Requested procedure has some support, but stronger clinical detail would reduce review risk.",
            "weak": "Requested procedure is under-supported and is likely to draw reviewer scrutiny.",
        }

        return {
            "procedure": procedure,
            "status": status,
            "fit_score": fit_score,
            "supporting_signals": self.unique_preserve_order(supporting_signals),
            "gaps": self.unique_preserve_order(gaps),
            "summary": summary_map.get(status, "Procedure support is indeterminate."),
        }

    def build_missing_evidence_recommendations(self, packet, procedure_fit, success_pattern):
        recommendations = []

        for doc in sorted(packet.missing_documents):
            recommendations.append({
                "type": "document",
                "target": doc,
                "priority": "high" if doc in {"clinical_notes", "lomn", "rfs", "approved_referral", "consent"} else "medium",
                "recommendation": f"Attach the missing {doc} document.",
                "why": f"{doc} is missing from the current packet and weakens submission readiness.",
            })

        for field in packet.missing_fields:
            recommendations.append({
                "type": "field",
                "target": field,
                "priority": self.get_field_priority(field),
                "recommendation": f"Add or verify the {field} field.",
                "why": f"{field} is required for this packet profile.",
            })

        if procedure_fit["status"] in {"moderate", "weak"} and packet.fields.get("procedure") == "MRI":
            recommendations.append({
                "type": "clinical_support",
                "target": "mri_justification",
                "priority": "high" if procedure_fit["status"] == "weak" else "medium",
                "recommendation": "Add conservative-treatment failure, functional limitation, or neurologic deficit language supporting MRI.",
                "why": "MRI requests are stronger when the packet explains why advanced imaging is medically necessary now.",
            })

        if "diagnosis_icd_mismatch" in packet.review_flags:
            recommendations.append({
                "type": "clinical_alignment",
                "target": "diagnosis_icd_alignment",
                "priority": "medium",
                "recommendation": "Align diagnosis wording and ICD coding so they describe the same clinical condition.",
                "why": "Diagnosis and ICD inconsistency reduces reviewer confidence.",
            })

        if "diagnosis_without_icd_support" in packet.review_flags:
            recommendations.append({
                "type": "clinical_alignment",
                "target": "icd_codes",
                "priority": "medium",
                "recommendation": "Add ICD support for the stated diagnosis.",
                "why": "Diagnosis language without matching ICD support weakens the packet.",
            })

        if "icd_without_diagnosis_support" in packet.review_flags:
            recommendations.append({
                "type": "clinical_alignment",
                "target": "diagnosis",
                "priority": "medium",
                "recommendation": "Add diagnosis language that matches the coded condition.",
                "why": "ICD codes need matching diagnosis language to read as clinically coherent.",
            })

        if "chronology_review_needed" in packet.review_flags:
            recommendations.append({
                "type": "chronology",
                "target": "service_date_range",
                "priority": "medium",
                "recommendation": "Correct or clarify the service date range so the timeline is clinically consistent.",
                "why": "Chronology issues often lead to reviewer hold decisions.",
            })

        if "signature_present" in {conflict.get("field") for conflict in packet.conflicts if conflict.get("type") == "document_gap"}:
            recommendations.append({
                "type": "signature",
                "target": "signature_present",
                "priority": "high",
                "recommendation": "Add a signed provider or patient signature where the packet expects one.",
                "why": "Unsigned packet components block clean submission for signature-sensitive documents.",
            })

        if success_pattern["similarity"] == "weak":
            recommendations.append({
                "type": "packet_shape",
                "target": "successful_packet_profile",
                "priority": "medium",
                "recommendation": "Close the biggest document and field gaps before resubmission so the packet matches successful submission patterns more closely.",
                "why": "The current packet shape deviates materially from successful submission patterns.",
            })

        deduped = []
        seen = set()
        priority_order = {"high": 0, "medium": 1, "low": 2}
        for item in sorted(
            recommendations,
            key=lambda entry: (priority_order.get(entry["priority"], 3), entry["target"]),
        ):
            key = (item["type"], item["target"])
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        return deduped[:8]

    def build_submission_sequence_optimization(self, packet, packet_type):
        recommended_order = packet.links.get("recommended_page_order") or []

        if recommended_order:
            ordered_entries = sorted(
                recommended_order,
                key=lambda entry: (entry.get("recommended_position", 999), entry.get("current_position", 999)),
            )
            normalized_order = []
            for entry in ordered_entries:
                doc_type = entry.get("doc_type", "unknown")
                normalized_order.append({
                    "doc_type": doc_type,
                    "current_position": entry.get("current_position"),
                    "recommended_position": entry.get("recommended_position"),
                    "page_index": entry.get("page_index"),
                    "reason": self.DOC_SEQUENCE_REASONS.get(doc_type, self.DOC_SEQUENCE_REASONS["unknown"]),
                })
        else:
            ordered_doc_types = sorted(
                packet.detected_documents,
                key=lambda doc: (self.get_document_sequence_priority(doc), doc),
            )
            normalized_order = [
                {
                    "doc_type": doc_type,
                    "current_position": index + 1,
                    "recommended_position": index + 1,
                    "page_index": None,
                    "reason": self.DOC_SEQUENCE_REASONS.get(doc_type, self.DOC_SEQUENCE_REASONS["unknown"]),
                }
                for index, doc_type in enumerate(ordered_doc_types)
            ]

        needs_reorder = any(
            entry.get("current_position") != entry.get("recommended_position")
            for entry in normalized_order
            if entry.get("current_position") is not None
        )

        assembly_notes = [entry["reason"] for entry in normalized_order]
        if packet.missing_documents:
            assembly_notes.append(
                f"Packet is missing expected {packet_type.replace('_', ' ')} components: {', '.join(sorted(packet.missing_documents))}."
            )

        return {
            "packet_type": packet_type,
            "status": "needs_reorder" if needs_reorder else ("optimized" if normalized_order else "limited"),
            "recommended_order": normalized_order,
            "assembly_notes": self.unique_preserve_order(assembly_notes),
        }

    def get_document_sequence_priority(self, doc_type):
        priorities = {
            "cover_sheet": 10,
            "rfs": 20,
            "approved_referral": 25,
            "consult_request": 30,
            "seoc": 40,
            "lomn": 50,
            "consent": 60,
            "clinical_notes": 70,
            "unknown": 999,
        }
        return priorities.get(doc_type, priorities["unknown"])

    def build_recommended_next_action(self, packet, submission_decision, missing_evidence, procedure_fit):
        readiness = submission_decision["readiness"]

        if readiness == "ready":
            return {
                "action": "submit_packet",
                "target": "packet",
                "priority": "low",
                "owner": "submission_queue",
                "reason": "Packet is ready for submission without additional correction work.",
            }

        prioritized_fixes = packet.output.get("review_summary", {}).get("priority_fixes", [])
        if prioritized_fixes:
            action = self.build_action_from_fix(prioritized_fixes[0], readiness)
            if action:
                return action

        if missing_evidence:
            top_item = missing_evidence[0]
            return {
                "action": "collect_missing_evidence",
                "target": top_item.get("target", "packet"),
                "priority": top_item.get("priority", "medium"),
                "owner": "correction_queue" if readiness == "hold" else "review_queue",
                "reason": top_item.get("why", "Packet needs stronger supporting evidence."),
            }

        if procedure_fit["status"] == "weak":
            return {
                "action": "strengthen_procedure_support",
                "target": procedure_fit.get("procedure") or "procedure_support",
                "priority": "high",
                "owner": "correction_queue",
                "reason": procedure_fit["summary"],
            }

        if readiness == "requires_review":
            return {
                "action": "route_to_review",
                "target": "packet",
                "priority": "medium",
                "owner": "review_queue",
                "reason": submission_decision["review_reasons"][0] if submission_decision["review_reasons"] else "Packet needs reviewer confirmation.",
            }

        return {
            "action": "hold_for_correction",
            "target": "packet",
            "priority": "high",
            "owner": "correction_queue",
            "reason": submission_decision["hold_reasons"][0] if submission_decision["hold_reasons"] else "Packet requires corrective work before submission.",
        }

    def build_action_from_fix(self, fix, readiness):
        fix_type = fix.get("type")
        target = fix.get("target", "packet")
        priority = fix.get("priority", "medium")

        mappings = {
            "missing_document": ("attach_missing_document", "correction_queue"),
            "missing_document_bundle": ("attach_missing_documents", "correction_queue"),
            "missing_field": ("verify_missing_field", "correction_queue"),
            "conflict": ("resolve_conflict", "review_queue" if readiness == "requires_review" else "correction_queue"),
            "medical_support": ("strengthen_medical_support", "correction_queue"),
            "clinical_alignment": ("align_clinical_support", "correction_queue"),
            "packet_integrity": ("escalate_packet_integrity_review", "senior_review_queue"),
            "chronology": ("correct_service_dates", "correction_queue"),
            "packet_cleanup": ("remove_duplicate_pages", "correction_queue"),
        }
        action_name, owner = mappings.get(fix_type, ("hold_for_correction", "correction_queue"))

        return {
            "action": action_name,
            "target": target,
            "priority": priority,
            "owner": owner,
            "reason": fix.get("action", f"Address {target} before submission."),
        }

    def build_escalation_trigger(self, packet, submission_decision, procedure_fit, success_pattern):
        reasons = []

        high_conflict_fields = sorted({
            conflict.get("field", "unknown_field")
            for conflict in packet.conflicts
            if conflict.get("severity") == "high"
        })
        if high_conflict_fields:
            reasons.append(
                f"High-severity conflicts are present: {', '.join(high_conflict_fields)}."
            )

        if "packet_integrity_risk" in packet.review_flags:
            reasons.append("Packet may contain mixed patient or case identifiers.")

        medium_conflict_count = sum(1 for conflict in packet.conflicts if conflict.get("severity") == "medium")
        if (
            medium_conflict_count >= 2
            and submission_decision["readiness"] == "hold"
            and (packet.packet_confidence or 0) < 0.68
        ):
            reasons.append("Multiple medium-severity conflicts are combined with low packet confidence.")

        if procedure_fit["status"] == "weak" and submission_decision["readiness"] == "hold":
            reasons.append("Procedure support is too weak to rely on routine correction routing alone.")

        if (
            success_pattern["similarity"] == "weak"
            and submission_decision["readiness"] == "hold"
            and (packet.packet_confidence or 0) < 0.7
        ):
            reasons.append("Packet deviates materially from successful submission patterns.")

        if packet.approval_probability is not None and packet.approval_probability < 0.45 and reasons:
            reasons.append("Approval probability is already very low, so senior review is safer.")

        return {
            "escalate": bool(reasons),
            "level": "senior_review" if reasons else None,
            "reasons": self.unique_preserve_order(reasons),
        }

    def build_denial_risk_prediction(self, packet, submission_decision, procedure_fit, success_pattern, escalation):
        modeling = dict((packet.metrics or {}).get("statistical_outcome_modeling", {}) or {})
        semantic = dict(getattr(packet, "semantic_adjudication", {}) or {})
        semantic_score = float(semantic.get("overall_score") or 0.0) / 100.0
        variant_tolerance = dict(semantic.get("variant_tolerance", {}) or {})
        base_score = 1.0 - (packet.approval_probability if packet.approval_probability is not None else 0.5)
        risk_score = max(0.05, min(base_score, 0.95))
        drivers = []
        pattern_confidence = success_pattern.get("confidence", 1.0)

        if submission_decision["readiness"] == "hold":
            risk_score += 0.14
            drivers.append("Current packet state is not submission-ready.")
        elif submission_decision["readiness"] == "requires_review":
            risk_score += 0.07
            drivers.append("Packet still requires reviewer confirmation.")

        if packet.missing_documents:
            risk_score += min(0.18, 0.06 * len(packet.missing_documents))
            drivers.append("Missing required documents increase denial risk.")

        if packet.missing_fields:
            risk_score += min(0.2, 0.08 * len(packet.missing_fields))
            drivers.append("Missing required fields increase denial risk.")

        high_conflict_count = sum(1 for conflict in packet.conflicts if conflict.get("severity") == "high")
        medium_conflict_count = sum(1 for conflict in packet.conflicts if conflict.get("severity") == "medium")
        if high_conflict_count:
            risk_score += 0.2
            drivers.append("High-severity cross-document conflicts materially raise denial risk.")
        elif medium_conflict_count:
            risk_score += min(0.12, 0.05 * medium_conflict_count)
            drivers.append("Medium-severity conflicts still make the packet less reliable.")
        elif packet.conflicts:
            risk_score += 0.04
            drivers.append("Low-severity conflicts still require cleanup.")

        if procedure_fit["status"] == "weak":
            risk_score += 0.12
            drivers.append("Procedure support is weak for the requested service.")
        elif procedure_fit["status"] == "moderate":
            risk_score += 0.04
            drivers.append("Procedure support is only moderate.")

        if success_pattern["similarity"] == "weak" and pattern_confidence >= 0.6:
            risk_score += 0.12
            drivers.append("Packet shape diverges from successful submission patterns.")
        elif success_pattern["similarity"] == "moderate" and pattern_confidence >= 0.6:
            risk_score += 0.05
            drivers.append("Packet is only partially aligned with successful submission patterns.")
        elif pattern_confidence < 0.6:
            drivers.append("Historical packet-shape matching is low-confidence because document detection is sparse.")

        if packet.packet_confidence is not None and packet.packet_confidence < 0.75:
            risk_score += 0.08
            drivers.append("Packet confidence is below the normal auto-submit comfort range.")

        if semantic_score >= 0.88:
            risk_score -= 0.06
            drivers.append("Semantic packet review shows a coherent case story across documents.")
        elif semantic_score >= 0.74 and variant_tolerance.get("coherent_despite_variation"):
            risk_score -= 0.04
            drivers.append("Packet meaning stays coherent despite office-specific formatting variation.")
        elif semantic_score < 0.45:
            risk_score += 0.08
            drivers.append("Packet meaning is still semantically unstable across documents.")

        if escalation["escalate"]:
            risk_score += 0.08
            drivers.append("Escalation signals indicate elevated operational risk.")

        if modeling.get("available") and modeling.get("reliability_band") in {"moderate", "high"}:
            calibrated_probability = modeling.get("calibrated_probability")
            if calibrated_probability is not None and calibrated_probability <= 0.4:
                drivers.append("Historical outcome modeling suggests elevated denial likelihood for similar packets.")
            elif calibrated_probability is not None and calibrated_probability >= 0.7:
                drivers.append("Historical outcome modeling remains supportive for similar packets.")

        if (
            pattern_confidence < 0.6
            and submission_decision["readiness"] == "requires_review"
            and not any(conflict.get("severity") == "high" for conflict in packet.conflicts)
            and not packet.missing_documents
            and not packet.missing_fields
        ):
            risk_score = min(risk_score, 0.59)

        risk_score = round(max(0.05, min(risk_score, 0.99)), 2)
        if risk_score >= 0.82:
            level = "critical"
        elif risk_score >= 0.6:
            level = "high"
        elif risk_score >= 0.32:
            level = "moderate"
        else:
            level = "low"

        return {
            "level": level,
            "risk_score": risk_score,
            "drivers": self.unique_preserve_order(drivers),
            "historical_pattern_match": success_pattern["similarity"],
            "historical_model_signal": (
                "supportive"
                if modeling.get("available") and (modeling.get("calibrated_probability") or 0.0) >= 0.7
                else "elevated"
                if modeling.get("available") and (modeling.get("calibrated_probability") or 1.0) <= 0.4
                else "neutral"
                if modeling.get("available")
                else "unavailable"
            ),
            "model_reliability_band": modeling.get("reliability_band"),
            "model_sample_size": modeling.get("sample_size"),
        }

    def build_workflow_decision_routing(self, packet, submission_decision, denial_risk, escalation, recommended_next_action):
        if escalation["escalate"]:
            queue = "senior_review_queue"
            owner = "senior_review"
            reason = escalation["reasons"][0]
        elif submission_decision["readiness"] == "ready":
            queue = "submission_queue"
            owner = "submission"
            reason = "Packet is ready for submission."
        elif submission_decision["readiness"] == "requires_review":
            queue = "review_queue"
            owner = "review"
            reason = submission_decision["review_reasons"][0] if submission_decision["review_reasons"] else "Packet needs reviewer confirmation."
        else:
            queue = "correction_queue"
            owner = "corrections"
            reason = submission_decision["hold_reasons"][0] if submission_decision["hold_reasons"] else "Packet requires corrective work."

        priority = packet.review_priority or (
            "high" if denial_risk["level"] in {"high", "critical"} else "normal"
        )

        return {
            "queue": queue,
            "owner": owner,
            "priority": priority,
            "auto_route": True,
            "reason": reason,
            "next_action": recommended_next_action["action"],
        }

    def build_resubmission_strategy(self, packet, submission_decision, denial_risk, missing_evidence, procedure_fit):
        failure_modes = []
        corrective_actions = []

        if packet.missing_documents:
            failure_modes.append("missing_required_documents")
        if packet.missing_fields:
            failure_modes.append("missing_required_fields")
        if any(conflict.get("severity") == "high" for conflict in packet.conflicts):
            failure_modes.append("high_severity_conflicts")
        if any(conflict.get("severity") == "medium" for conflict in packet.conflicts):
            failure_modes.append("review_sensitive_conflicts")
        if "packet_integrity_risk" in packet.review_flags:
            failure_modes.append("identity_integrity_risk")
        if procedure_fit["status"] == "weak":
            failure_modes.append("weak_procedure_support")
        if "chronology_review_needed" in packet.review_flags:
            failure_modes.append("chronology_issue")

        for item in missing_evidence[:5]:
            corrective_actions.append(item["recommendation"])

        if not corrective_actions and submission_decision["hold_reasons"]:
            corrective_actions.extend(submission_decision["hold_reasons"][:3])

        recommended = (
            submission_decision["readiness"] == "hold"
            or denial_risk["level"] in {"high", "critical"}
            or bool(failure_modes)
        )

        if recommended:
            summary = "Packet should be corrected and rechecked before resubmission."
        else:
            summary = "No resubmission strategy is needed because the packet is already operationally acceptable."

        return {
            "recommended": recommended,
            "failure_modes": self.unique_preserve_order(failure_modes),
            "corrective_actions": self.unique_preserve_order(corrective_actions),
            "recheck_focus": [
                "validation",
                "medical_reasoning",
                "submission_decision",
            ] if recommended else [],
            "summary": summary,
        }

    def build_approval_rationale(self, packet):
        rationale = []

        if packet.packet_strength == "strong":
            rationale.append("Packet has strong overall field and document support.")
        elif packet.packet_strength == "moderate":
            rationale.append("Packet has moderate support but still contains review-sensitive gaps.")
        else:
            rationale.append("Packet is weak due to missing data, conflicts, or insufficient justification.")

        if packet.missing_fields:
            rationale.append(f"Missing required fields: {', '.join(packet.missing_fields)}.")

        if packet.missing_documents:
            rationale.append(f"Missing required documents: {', '.join(packet.missing_documents)}.")

        if any(conflict.get("severity") == "high" for conflict in packet.conflicts):
            rationale.append("High-severity field conflicts reduce approval confidence.")
        elif any(conflict.get("severity") == "medium" for conflict in packet.conflicts):
            rationale.append("Moderate field conflicts still require reviewer confirmation.")
        elif packet.conflicts:
            rationale.append("Low-severity field conflicts still need cleanup before submission.")

        if "weak_mri_justification" in packet.review_flags:
            rationale.append("MRI request lacks strong clinical justification.")
        elif "moderate_mri_justification" in packet.review_flags:
            rationale.append("MRI request has only moderate clinical justification.")

        if "procedure_without_medical_support" in packet.review_flags:
            rationale.append("Requested procedure is not supported by sufficient diagnosis or symptom evidence.")

        if "diagnosis_icd_mismatch" in packet.review_flags:
            rationale.append("Diagnosis and ICD coding do not appear clinically aligned.")
        elif "partial_diagnosis_icd_alignment" in packet.review_flags:
            rationale.append("Diagnosis and ICD support are present but only partially aligned.")

        if "diagnosis_without_icd_support" in packet.review_flags:
            rationale.append("Diagnosis appears without matching ICD support.")

        if "icd_without_diagnosis_support" in packet.review_flags:
            rationale.append("ICD codes appear without matching diagnosis language.")

        if "missing_reason_for_request" in packet.review_flags:
            rationale.append("Reason for request is missing or unclear.")

        if "packet_integrity_risk" in packet.review_flags:
            rationale.append("Multiple identity signals suggest the packet may contain mixed patient or case pages.")

        if "chronology_review_needed" in packet.review_flags:
            rationale.append("Service date chronology needs reviewer confirmation.")

        if "duplicate_pages_present" in packet.review_flags:
            rationale.append("Duplicate pages are present in the packet.")

        return self.unique_preserve_order(rationale)

    def unique_preserve_order(self, items):
        seen = set()
        ordered = []

        for item in items:
            if item not in seen:
                seen.add(item)
                ordered.append(item)

        return ordered
