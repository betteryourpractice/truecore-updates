import html
import os

from TrueCore.utils.logging_system import mask_phi


def render_build_advanced_intel_sections(self, result):

    intel = self.intel_payload(result)

    evidence = intel.get("evidence_intelligence", {}) or {}
    clinical = intel.get("clinical_intelligence", {}) or {}
    denial = intel.get("denial_intelligence", {}) or {}
    human_loop = intel.get("human_in_the_loop_intelligence", {}) or {}
    memory = intel.get("memory_intelligence", {}) or {}
    triage = intel.get("triage_intelligence", {}) or {}
    operator = intel.get("operator_intelligence", {}) or {}
    learning = intel.get("learning_intelligence", {}) or {}
    insight = intel.get("insight_intelligence", {}) or {}
    benchmark = intel.get("benchmark_intelligence", {}) or {}
    orchestration = intel.get("orchestration_intelligence", {}) or {}
    architecture = intel.get("architecture_intelligence", {}) or {}
    recovery = intel.get("recovery_intelligence", {}) or {}
    policy = intel.get("policy_intelligence", {}) or {}
    deployment = intel.get("deployment_intelligence", {}) or {}
    validation = intel.get("validation_intelligence", {}) or {}

    sections = []

    evidence_rows = [
        ("Sufficiency", self.get_nested_value(evidence, "evidence_sufficiency_modeling", "status")),
        ("Support Level", self.get_nested_value(evidence, "evidence_sufficiency_modeling", "support_level")),
        ("Freshness", self.get_nested_value(evidence, "evidence_freshness_validation", "status")),
        ("Escalation", self.get_nested_value(evidence, "evidence_escalation_recommendation", "level")),
        ("Evidence Score", self.get_nested_value(evidence, "evidence_sufficiency_modeling", "score")),
    ]

    if any(value not in (None, "", [], {}) for _, value in evidence_rows):
        sections.append(
            self.build_detail_card(
                "Evidence Intelligence",
                self.build_detail_table(evidence_rows, value_color="#57B6FF", show_missing=False),
                accent_color="#57B6FF",
            )
        )

    evidence_actions = self.get_nested_value(evidence, "evidence_escalation_recommendation", "recommendations", default=[])
    if evidence_actions:
        sections.append(
            self.build_bullet_section(
                "Evidence Actions",
                evidence_actions[:5],
                color="#57B6FF",
                accent_color="#57B6FF",
            )
        )

    clinical_rows = [
        ("Coherence Score", self.get_nested_value(clinical, "clinical_coherence_scoring", "score")),
        ("Coherence Band", self.get_nested_value(clinical, "clinical_coherence_scoring", "band")),
        ("Consistency", self.get_nested_value(clinical, "clinical_consistency_analysis", "status")),
        ("Severity", self.get_nested_value(clinical, "severity_inference_engine", "level")),
        ("Conservative Care", self.get_nested_value(clinical, "conservative_care_verification", "status")),
        ("Specialty Alignment", self.get_nested_value(clinical, "specialty_alignment_validation", "status")),
    ]

    if any(value not in (None, "", [], {}) for _, value in clinical_rows):
        sections.append(
            self.build_detail_card(
                "Clinical Intelligence",
                self.build_detail_table(clinical_rows, value_color="#57B6FF", show_missing=False),
                accent_color="#57B6FF",
            )
        )

    clinical_gaps = self.get_nested_value(clinical, "clinical_gap_detection", "gaps", default=[])
    if clinical_gaps:
        sections.append(
            self.build_bullet_section(
                "Clinical Gaps",
                clinical_gaps[:5],
                color="#EB5757",
                accent_color="#EB5757",
            )
        )

    denial_rows = [
        ("Primary Category", self.get_nested_value(denial, "denial_taxonomy_engine", "primary_category")),
        ("Appeal Disposition", self.get_nested_value(denial, "appeal_opportunity_detection", "disposition")),
        ("Recovery Score", self.get_nested_value(denial, "failure_recovery_scoring", "score")),
        ("Recovery Band", self.get_nested_value(denial, "failure_recovery_scoring", "band")),
    ]

    if any(value not in (None, "", [], {}) for _, value in denial_rows):
        sections.append(
            self.build_detail_card(
                "Denial Intelligence",
                self.build_detail_table(denial_rows, value_color="#F2994A", show_missing=False),
                accent_color="#F2994A",
            )
        )

    denial_actions = self.get_nested_value(denial, "countermeasure_recommendation_engine", "recommended_actions", default=[])
    if denial_actions:
        sections.append(
            self.build_bullet_section(
                "Denial Countermeasures",
                denial_actions[:5],
                color="#F2994A",
                accent_color="#F2994A",
            )
        )

    human_rows = [
        ("Trust Score", self.get_nested_value(human_loop, "trust_score_modeling", "trust_score")),
        ("Trust Band", self.get_nested_value(human_loop, "trust_score_modeling", "band")),
        ("Threshold", self.get_nested_value(human_loop, "review_threshold_engine", "status")),
        ("Gate Open", self.get_nested_value(human_loop, "confidence_gated_automation", "gate_open")),
        ("Checkpoint Required", self.get_nested_value(human_loop, "approval_checkpoint_layer", "checkpoint_required")),
    ]

    if any(value not in (None, "", [], {}) for _, value in human_rows):
        sections.append(
            self.build_detail_card(
                "Human-In-The-Loop",
                self.build_detail_table(human_rows, value_color="#F2C94C", show_missing=False),
                accent_color="#F2C94C",
            )
        )

    human_points = self.get_nested_value(human_loop, "reviewer_attention_guidance", "attention_points", default=[])
    if human_points:
        sections.append(
            self.build_bullet_section(
                "Reviewer Attention Guidance",
                human_points[:5],
                color="#F2C94C",
                accent_color="#F2C94C",
            )
        )

    memory_rows = [
        ("Prior Cases", self.get_nested_value(memory, "persistent_case_memory", "prior_case_count")),
        ("Last Status", self.get_nested_value(memory, "persistent_case_memory", "last_status")),
        ("Last Score", self.get_nested_value(memory, "persistent_case_memory", "last_score")),
        ("Memory Confidence", self.get_nested_value(memory, "memory_confidence_scoring", "score")),
        ("Memory Band", self.get_nested_value(memory, "memory_confidence_scoring", "band")),
        ("Risk Drift", self.get_nested_value(memory, "longitudinal_risk_drift_tracking", "direction")),
        ("Provider Quality", self.get_nested_value(memory, "provider_relationship_memory", "quality_trend")),
        ("Provider Packet Count", self.get_nested_value(memory, "provider_relationship_memory", "packet_count")),
    ]

    if any(value not in (None, "", [], {}) for _, value in memory_rows):
        sections.append(
            self.build_detail_card(
                "Case Memory",
                self.build_detail_table(memory_rows, value_color="#9B8CFF", show_missing=False),
                accent_color="#9B8CFF",
            )
        )

    recurring_issues = self.get_nested_value(memory, "recurring_deficiency_detection", "recurring_issues", default=[])
    if recurring_issues:
        sections.append(
            self.build_bullet_section(
                "Recurring Deficiencies",
                recurring_issues[:5],
                color="#EB5757",
                accent_color="#EB5757",
            )
        )

    carryover_context = self.get_nested_value(memory, "context_carryover_engine", "carryover_context", default=[])
    if carryover_context:
        sections.append(
            self.build_bullet_section(
                "Context Carryover",
                carryover_context[:5],
                color="#9B8CFF",
                accent_color="#9B8CFF",
            )
        )

    similar_cases = self.get_nested_value(memory, "similar_case_recall", default=[])
    if similar_cases:
        similar_case_items = [
            f"{item.get('file_name')} | similarity {item.get('similarity_score')} | "
            f"status {item.get('status')} | score {item.get('score')}"
            for item in similar_cases[:4]
        ]
        sections.append(
            self.build_bullet_section(
                "Similar Case Recall",
                similar_case_items,
                color="#9B8CFF",
                accent_color="#9B8CFF",
            )
        )

    triage_rows = [
        ("Priority", triage.get("priority_level")),
        ("Urgency", triage.get("urgency_classification")),
        ("Review Depth", triage.get("review_depth_allocation")),
        ("Time To Action", triage.get("time_to_action_scoring")),
        ("Staff Route", triage.get("staff_match_routing")),
        ("Queue Risk", triage.get("queue_risk_forecasting")),
        ("Triage Confidence", triage.get("triage_confidence_scoring")),
        ("Deferral Safe", triage.get("deferral_safety_check")),
    ]

    if any(value not in (None, "", [], {}) for _, value in triage_rows):
        sections.append(
            self.build_detail_card(
                "Triage Intelligence",
                self.build_detail_table(triage_rows, value_color="#56CCF2", show_missing=False),
                accent_color="#56CCF2",
            )
        )

    triage_focus = triage.get("next_operator_focus", []) or []
    if triage_focus:
        sections.append(
            self.build_bullet_section(
                "Triage Focus",
                triage_focus[:5],
                color="#56CCF2",
                accent_color="#56CCF2",
            )
        )

    operator_rows = [
        ("Primary Route", self.get_nested_value(operator, "operator_workbench_layer", "primary_route")),
        ("Priority", self.get_nested_value(operator, "operator_workbench_layer", "priority_level")),
        ("Review Depth", self.get_nested_value(operator, "operator_workbench_layer", "review_depth")),
        ("Time To Action", self.get_nested_value(operator, "operator_workbench_layer", "time_to_action")),
        ("Efficiency", self.get_nested_value(operator, "reviewer_efficiency_scoring", "band")),
        ("Efficiency Score", self.get_nested_value(operator, "reviewer_efficiency_scoring", "score")),
    ]

    if any(value not in (None, "", [], {}) for _, value in operator_rows):
        sections.append(
            self.build_detail_card(
                "Operator Workbench",
                self.build_detail_table(operator_rows, value_color="#6FCF97", show_missing=False),
                accent_color="#27AE60",
            )
        )

    operator_checklist = self.get_nested_value(operator, "smart_review_checklist_generation", "checklist", default=[])
    if operator_checklist:
        sections.append(
            self.build_bullet_section(
                "Operator Checklist",
                operator_checklist[:6],
                color="#6FCF97",
                accent_color="#27AE60",
            )
        )

    productivity_hints = self.get_nested_value(operator, "productivity_hint_engine", "hints", default=[])
    if productivity_hints:
        sections.append(
            self.build_bullet_section(
                "Productivity Hints",
                productivity_hints[:5],
                color="#6FCF97",
                accent_color="#27AE60",
            )
        )

    operator_feedback = self.get_nested_value(operator, "operator_support_feedback_loop", "suggestions", default=[])
    if operator_feedback:
        sections.append(
            self.build_bullet_section(
                "Operator Feedback Loop",
                operator_feedback[:5],
                color="#6FCF97",
                accent_color="#27AE60",
            )
        )

    operator_patterns = self.get_nested_value(operator, "work_pattern_analysis", "friction_points", default=[])
    if operator_patterns:
        sections.append(
            self.build_bullet_section(
                "Operator Friction Points",
                operator_patterns[:5],
                color="#6FCF97",
                accent_color="#27AE60",
            )
        )

    escalation_note = self.get_nested_value(operator, "escalation_note_drafting", "note")
    if escalation_note:
        sections.append(
            self.build_detail_card(
                "Escalation Note",
                f"<div style=\"color:#6FCF97;\">{html.escape(str(escalation_note))}</div>",
                accent_color="#27AE60",
            )
        )

    learning_rows = [
        ("Latest Outcome", self.get_nested_value(learning, "outcome_feedback_ingestion", "latest_outcome")),
        ("Outcome Count", self.get_nested_value(learning, "outcome_feedback_ingestion", "outcome_count")),
        ("Calibration", self.get_nested_value(learning, "confidence_calibration_engine", "status")),
        ("Calibration Delta", self.get_nested_value(learning, "confidence_calibration_engine", "delta")),
        ("Learned Approval Probability", self.get_nested_value(learning, "predictive_outcome_modeling", "learned_approval_probability")),
        ("Prediction Agreement", self.get_nested_value(learning, "predictive_outcome_modeling", "agreement_status")),
        ("Prediction Trust", self.get_nested_value(learning, "predictive_outcome_modeling", "honesty_band")),
        ("Model Reliability", self.get_nested_value(learning, "outcome_learning_health", "reliability_band")),
        ("Learning Maturity", self.get_nested_value(learning, "outcome_learning_health", "maturity_band")),
        ("Provider Outcome Status", self.get_nested_value(learning, "provider_outcome_learning", "status")),
        ("Override Status", self.get_nested_value(learning, "reviewer_override_learning", "status")),
        ("Override Rate", self.get_nested_value(learning, "reviewer_override_learning", "override_rate")),
        ("Readiness", self.get_nested_value(learning, "continuous_intelligence_refinement", "readiness_band")),
        ("Readiness Score", self.get_nested_value(learning, "continuous_intelligence_refinement", "readiness_score")),
    ]

    if any(value not in (None, "", [], {}) for _, value in learning_rows):
        sections.append(
            self.build_detail_card(
                "Learning Intelligence",
                self.build_detail_table(learning_rows, value_color="#F2994A", show_missing=False),
                accent_color="#F2994A",
            )
        )

    rule_adjustments = self.get_nested_value(learning, "rule_adjustment_recommendation", "recommendations", default=[])
    if rule_adjustments:
        sections.append(
            self.build_bullet_section(
                "Rule Adjustment Recommendations",
                rule_adjustments[:5],
                color="#F2994A",
                accent_color="#F2994A",
            )
        )

    learning_safeguards = self.get_nested_value(learning, "failure_to_learning_conversion", "recommended_safeguards", default=[])
    if learning_safeguards:
        sections.append(
            self.build_bullet_section(
                "Learning Safeguards",
                learning_safeguards[:5],
                color="#F2994A",
                accent_color="#F2994A",
            )
        )

    prediction_watchpoints = self.get_nested_value(learning, "prediction_watchpoints", "items", default=[])
    if prediction_watchpoints:
        sections.append(
            self.build_bullet_section(
                "Prediction Watchpoints",
                prediction_watchpoints[:5],
                color="#F2994A",
                accent_color="#F2994A",
            )
        )

    insight_rows = [
        ("Trend", self.get_nested_value(insight, "hidden_trend_detection", "status")),
        ("Recent Avg Score", self.get_nested_value(insight, "hidden_trend_detection", "recent_average_score")),
        ("Provider Rank", self.get_nested_value(insight, "provider_network_insight_engine", "provider_rank")),
        ("Provider Avg Score", self.get_nested_value(insight, "provider_network_insight_engine", "provider_average_score")),
        ("Variance", self.get_nested_value(insight, "process_variance_detection", "status")),
    ]

    if any(value not in (None, "", [], {}) for _, value in insight_rows):
        sections.append(
            self.build_detail_card(
                "Insight Intelligence",
                self.build_detail_table(insight_rows, value_color="#BB6BD9", show_missing=False),
                accent_color="#BB6BD9",
            )
        )

    strategic_insights = self.get_nested_value(insight, "strategic_insight_summarization", default=[])
    if strategic_insights:
        sections.append(
            self.build_bullet_section(
                "Insight Summary",
                strategic_insights[:5],
                color="#BB6BD9",
                accent_color="#BB6BD9",
            )
        )

    insight_actions = self.get_nested_value(insight, "insight_action_recommendation", default=[])
    if insight_actions:
        sections.append(
            self.build_bullet_section(
                "Insight Actions",
                insight_actions[:5],
                color="#BB6BD9",
                accent_color="#BB6BD9",
            )
        )

    benchmark_rows = [
        ("Standing", self.get_nested_value(benchmark, "internal_benchmark_engine", "standing")),
        ("Average Score", self.get_nested_value(benchmark, "internal_benchmark_engine", "average_score")),
        ("Quality Percentile", self.get_nested_value(benchmark, "quality_benchmark_calibration", "score_percentile")),
        ("Benchmark Confidence", self.get_nested_value(benchmark, "benchmark_confidence_scoring", "band")),
        ("Target Score", self.get_nested_value(benchmark, "improvement_target_modeling", "target_score")),
        ("Provider Rank", self.get_nested_value(benchmark, "team_to_team_benchmarking", "provider_rank")),
    ]

    if any(value not in (None, "", [], {}) for _, value in benchmark_rows):
        sections.append(
            self.build_detail_card(
                "Benchmark Intelligence",
                self.build_detail_table(benchmark_rows, value_color="#2DCE89", show_missing=False),
                accent_color="#2DCE89",
            )
        )

    benchmark_targets = self.get_nested_value(benchmark, "improvement_target_modeling", "recommendations", default=[])
    if benchmark_targets:
        sections.append(
            self.build_bullet_section(
                "Benchmark Targets",
                benchmark_targets[:5],
                color="#2DCE89",
                accent_color="#2DCE89",
            )
        )

    system_rows = [
        ("Pipeline State", self.get_nested_value(orchestration, "pipeline_health_state_machine", "state")),
        ("Coordination Score", self.get_nested_value(orchestration, "end_to_end_coordination_scoring", "score")),
        ("Coordination Band", self.get_nested_value(orchestration, "end_to_end_coordination_scoring", "band")),
        ("Maintainability", self.get_nested_value(architecture, "maintainability_scoring", "band")),
        ("Reliability", self.get_nested_value(recovery, "reliability_scoring", "band")),
        ("Recovery Strategy", self.get_nested_value(recovery, "intelligent_retry_engine", "strategy")),
    ]

    if any(value not in (None, "", [], {}) for _, value in system_rows):
        sections.append(
            self.build_detail_card(
                "System Intelligence",
                self.build_detail_table(system_rows, value_color="#6FCF97", show_missing=False),
                accent_color="#6FCF97",
            )
        )

    policy_rows = [
        ("Policy Confidence", self.get_nested_value(policy, "policy_compliance_confidence", "band")),
        ("Policy Score", self.get_nested_value(policy, "policy_compliance_confidence", "score")),
        ("Forecast Status", self.get_nested_value(policy, "missing_requirement_forecasting", "forecast_status")),
        ("Deployment Confidence", self.get_nested_value(deployment, "deployment_confidence_scoring", "band")),
        ("Deployment Score", self.get_nested_value(deployment, "deployment_confidence_scoring", "score")),
        ("Update Compatibility", self.get_nested_value(deployment, "update_compatibility_analysis", "status")),
    ]

    if any(value not in (None, "", [], {}) for _, value in policy_rows):
        sections.append(
            self.build_detail_card(
                "Policy & Deployment",
                self.build_detail_table(policy_rows, value_color="#57B6FF", show_missing=False),
                accent_color="#57B6FF",
            )
        )

    validation_rows = [
        ("Deep Verification Score", self.get_nested_value(validation, "deep_verification_score", "score")),
        ("Verification Band", self.get_nested_value(validation, "deep_verification_score", "band")),
        ("Verified Claims", self.get_nested_value(validation, "extraction_claim_verification", "verified_claims")),
        ("Weak Claims", self.get_nested_value(validation, "extraction_claim_verification", "weak_claims")),
        ("Date Logic", self.get_nested_value(validation, "date_logic_validation", "status")),
        ("Procedure-Code Check", self.get_nested_value(validation, "procedure_code_consistency_checks", "status")),
    ]

    if any(value not in (None, "", [], {}) for _, value in validation_rows):
        sections.append(
            self.build_detail_card(
                "Reviewer Verification",
                self.build_detail_table(validation_rows, value_color="#56CCF2", show_missing=False),
                accent_color="#56CCF2",
            )
        )

    traceback_items = []
    for item in (self.get_nested_value(validation, "evidence_traceback_links", default=[]) or [])[:8]:
        field_name = self.format_field(item.get("field"))
        support_status = self.format_field(item.get("support_status") or "unknown")
        document_type = self.format_field(item.get("document_type") or "unknown")
        page_number = item.get("page_number") or "?"
        provider = item.get("ocr_provider") or item.get("extraction_strategy") or "native_text"
        value = self.format_detail_value(item.get("value"))
        traceback_items.append(
            f"{field_name}: {value} | {support_status} | {document_type} | page {page_number} | {provider}"
        )

    if traceback_items:
        sections.append(
            self.build_bullet_section(
                "Source Traceback",
                traceback_items,
                color="#56CCF2",
                accent_color="#56CCF2",
            )
        )

    return sections

def render_build_condensed_advanced_intel_sections(self, result):

    intel = self.intel_payload(result)
    evidence = intel.get("evidence_intelligence", {}) or {}
    clinical = intel.get("clinical_intelligence", {}) or {}
    human_loop = intel.get("human_in_the_loop_intelligence", {}) or {}
    memory = intel.get("memory_intelligence", {}) or {}
    triage = intel.get("triage_intelligence", {}) or {}
    insight = intel.get("insight_intelligence", {}) or {}
    benchmark = intel.get("benchmark_intelligence", {}) or {}
    orchestration = intel.get("orchestration_intelligence", {}) or {}
    recovery = intel.get("recovery_intelligence", {}) or {}
    policy = intel.get("policy_intelligence", {}) or {}
    deployment = intel.get("deployment_intelligence", {}) or {}
    validation = intel.get("validation_intelligence", {}) or {}

    sections = []

    evidence_rows = [
        ("Support Level", self.format_packet_display_value("Support Level", self.get_nested_value(evidence, "evidence_sufficiency_modeling", "support_level"))),
        ("Evidence Rating", self.format_evidence_rating(self.get_nested_value(evidence, "evidence_sufficiency_modeling", "score"))),
        ("Freshness", self.format_packet_display_value("Freshness", self.get_nested_value(evidence, "evidence_freshness_validation", "status"))),
        ("Escalation", self.format_packet_display_value("Escalation", self.get_nested_value(evidence, "evidence_escalation_recommendation", "level"))),
    ]
    if any(value not in (None, "", [], {}) for _, value in evidence_rows):
        sections.append(
            self.build_detail_card(
                "Evidence Intelligence",
                self.build_detail_table(evidence_rows, value_color="#57B6FF", show_missing=False),
                accent_color="#57B6FF",
            )
        )

    clinical_rows = [
        ("Coherence", self.format_packet_display_value("Coherence", self.get_nested_value(clinical, "clinical_coherence_scoring", "band"))),
        ("Coherence Score", self.get_nested_value(clinical, "clinical_coherence_scoring", "score")),
        ("Severity", self.format_packet_display_value("Severity", self.get_nested_value(clinical, "severity_inference_engine", "level"))),
        ("Conservative Care", self.format_packet_display_value("Conservative Care", self.get_nested_value(clinical, "conservative_care_verification", "status"))),
        ("Specialty Alignment", self.format_packet_display_value("Specialty Alignment", self.get_nested_value(clinical, "specialty_alignment_validation", "status"))),
    ]
    if any(value not in (None, "", [], {}) for _, value in clinical_rows):
        sections.append(
            self.build_detail_card(
                "Clinical Intelligence",
                self.build_detail_table(clinical_rows, value_color="#57B6FF", show_missing=False),
                accent_color="#57B6FF",
            )
        )

    clinical_gaps = self.get_nested_value(clinical, "clinical_gap_detection", "gaps", default=[])
    if clinical_gaps:
        sections.append(
            self.build_bullet_section(
                "Clinical Gaps",
                clinical_gaps[:3],
                color="#F2C94C",
                accent_color="#F2994A",
            )
        )

    operations_rows = [
        ("Trust Score", self.format_packet_display_value("Trust Score", self.get_nested_value(human_loop, "trust_score_modeling", "trust_score"))),
        ("Provider History", self.format_packet_display_value("Provider History", self.get_nested_value(memory, "provider_relationship_memory", "quality_trend"))),
        ("Benchmark Standing", self.format_packet_display_value("Benchmark Standing", self.get_nested_value(benchmark, "internal_benchmark_engine", "standing"))),
    ]
    if any(value not in (None, "", [], {}) for _, value in operations_rows):
        sections.append(
            self.build_detail_card(
                "Operational Snapshot",
                self.build_detail_table(operations_rows, value_color="#9B8CFF", show_missing=False),
                accent_color="#9B8CFF",
            )
        )

    insight_actions = self.get_nested_value(insight, "insight_action_recommendation", "actions", default=[])
    if insight_actions:
        sections.append(
            self.build_bullet_section(
                "Insight Actions",
                insight_actions[:3],
                color="#9B8CFF",
                accent_color="#9B8CFF",
            )
        )

    system_rows = [
        ("Verification Score", self.get_nested_value(validation, "deep_verification_score", "score")),
        ("Verification Band", self.format_packet_display_value("Verification Band", self.get_nested_value(validation, "deep_verification_score", "band"))),
        ("Pipeline State", self.format_packet_display_value("Pipeline State", self.get_nested_value(orchestration, "pipeline_health_state_machine", "state"))),
        ("Reliability", self.format_packet_display_value("Reliability", self.get_nested_value(recovery, "reliability_scoring", "band"))),
        ("Policy Confidence", self.format_packet_display_value("Policy Confidence", self.get_nested_value(policy, "policy_compliance_confidence", "band"))),
    ]
    if any(value not in (None, "", [], {}) for _, value in system_rows):
        sections.append(
            self.build_detail_card(
                "Review Controls",
                self.build_detail_table(system_rows, value_color="#56CCF2", show_missing=False),
                accent_color="#56CCF2",
            )
        )

    concept_links = list(self.get_nested_value(validation, "concept_evidence_tracebacks", default=[]) or [])
    concept_items = []
    for item in concept_links[:4]:
        rendered = self.format_concept_evidence_item(item)
        if rendered:
            concept_items.append(rendered)

    if concept_items:
        sections.append(
            self.build_bullet_section(
                "Concept Evidence",
                concept_items,
                color="#57B6FF",
                accent_color="#57B6FF",
            )
        )

    traceback_links = list(self.get_nested_value(validation, "evidence_traceback_links", default=[]) or [])
    field_priority = {
        "diagnosis": 0,
        "icd_codes": 1,
        "reason_for_request": 2,
        "ordering_provider": 3,
        "ordering_doctor": 3,
        "provider": 4,
        "authorization_number": 5,
        "va_icn": 6,
        "patient_name": 7,
        "name": 7,
        "dob": 8,
    }
    sorted_traceback_links = sorted(
        traceback_links,
        key=lambda item: (
            field_priority.get(str(item.get("field") or "").strip().lower(), 99),
            item.get("page_number") or 999,
        ),
    )
    seen_fields = set()
    traceback_items = []
    for item in sorted_traceback_links:
        field_key = str(item.get("field") or "").strip().lower()
        if not field_key or field_key in seen_fields:
            continue
        seen_fields.add(field_key)
        field_name = self.format_field(item.get("field"))
        value = self.format_detail_value(item.get("value"))
        document_type = str(item.get("document_type") or "").strip()
        page_number = item.get("page_number") or "?"
        source_role = item.get("source_role")
        metadata_parts = []
        if document_type and document_type.lower() != "unknown":
            metadata_parts.append(self.format_field(document_type))
        if source_role:
            metadata_parts.append(self.format_field(source_role))
        metadata_text = f" | {' | '.join(metadata_parts)}" if metadata_parts else ""
        traceback_items.append(
            f"{field_name}: {value}{metadata_text} | page {page_number}"
        )
        if len(traceback_items) >= 4:
            break

    if traceback_items:
        sections.append(
            self.build_bullet_section(
                "Source Traceback Highlights",
                traceback_items,
                color="#56CCF2",
                accent_color="#56CCF2",
            )
        )

    return sections

def render_build_export_summary(self, result):

    intel = self.intel_payload(result)
    evidence = intel.get("evidence_intelligence", {}) or {}
    clinical = intel.get("clinical_intelligence", {}) or {}
    denial = intel.get("denial_intelligence", {}) or {}
    human_loop = intel.get("human_in_the_loop_intelligence", {}) or {}
    memory = intel.get("memory_intelligence", {}) or {}
    triage = intel.get("triage_intelligence", {}) or {}
    operator = intel.get("operator_intelligence", {}) or {}
    learning = intel.get("learning_intelligence", {}) or {}
    insight = intel.get("insight_intelligence", {}) or {}
    benchmark = intel.get("benchmark_intelligence", {}) or {}
    orchestration = intel.get("orchestration_intelligence", {}) or {}
    recovery = intel.get("recovery_intelligence", {}) or {}
    policy = intel.get("policy_intelligence", {}) or {}
    deployment = intel.get("deployment_intelligence", {}) or {}

    return {
        "evidence_sufficiency": self.get_nested_value(evidence, "evidence_sufficiency_modeling", "status"),
        "evidence_freshness": self.get_nested_value(evidence, "evidence_freshness_validation", "status"),
        "evidence_escalation": self.get_nested_value(evidence, "evidence_escalation_recommendation", "level"),
        "clinical_coherence": self.get_nested_value(clinical, "clinical_coherence_scoring", "band"),
        "clinical_severity": self.get_nested_value(clinical, "severity_inference_engine", "level"),
        "conservative_care": self.get_nested_value(clinical, "conservative_care_verification", "status"),
        "denial_category": self.get_nested_value(denial, "denial_taxonomy_engine", "primary_category"),
        "denial_recovery_score": self.get_nested_value(denial, "failure_recovery_scoring", "score"),
        "trust_score": self.get_nested_value(human_loop, "trust_score_modeling", "trust_score"),
        "checkpoint_required": self.get_nested_value(human_loop, "approval_checkpoint_layer", "checkpoint_required"),
        "prior_case_count": self.get_nested_value(memory, "persistent_case_memory", "prior_case_count"),
        "memory_confidence": self.get_nested_value(memory, "memory_confidence_scoring", "score"),
        "risk_drift": self.get_nested_value(memory, "longitudinal_risk_drift_tracking", "direction"),
        "provider_quality_trend": self.get_nested_value(memory, "provider_relationship_memory", "quality_trend"),
        "triage_priority": triage.get("priority_level"),
        "triage_urgency": triage.get("urgency_classification"),
        "triage_review_depth": triage.get("review_depth_allocation"),
        "triage_staff_route": triage.get("staff_match_routing"),
        "triage_time_to_action": triage.get("time_to_action_scoring"),
        "operator_primary_route": self.get_nested_value(operator, "operator_workbench_layer", "primary_route"),
        "operator_focus": self.get_nested_value(operator, "operator_workbench_layer", "next_operator_focus", default=[]),
        "operator_efficiency": self.get_nested_value(operator, "reviewer_efficiency_scoring", "band"),
        "latest_outcome": self.get_nested_value(learning, "outcome_feedback_ingestion", "latest_outcome"),
        "outcome_count": self.get_nested_value(learning, "outcome_feedback_ingestion", "outcome_count"),
        "calibration_status": self.get_nested_value(learning, "confidence_calibration_engine", "status"),
        "calibration_delta": self.get_nested_value(learning, "confidence_calibration_engine", "delta"),
        "learned_approval_probability": self.get_nested_value(learning, "predictive_outcome_modeling", "learned_approval_probability"),
        "prediction_alignment": self.get_nested_value(learning, "predictive_outcome_modeling", "agreement_status"),
        "prediction_trust": self.get_nested_value(learning, "predictive_outcome_modeling", "honesty_band"),
        "outcome_model_reliability": self.get_nested_value(learning, "outcome_learning_health", "reliability_band"),
        "outcome_learning_maturity": self.get_nested_value(learning, "outcome_learning_health", "maturity_band"),
        "provider_outcome_status": self.get_nested_value(learning, "provider_outcome_learning", "status"),
        "override_status": self.get_nested_value(learning, "reviewer_override_learning", "status"),
        "override_rate": self.get_nested_value(learning, "reviewer_override_learning", "override_rate"),
        "learning_readiness": self.get_nested_value(learning, "continuous_intelligence_refinement", "readiness_band"),
        "learning_readiness_score": self.get_nested_value(learning, "continuous_intelligence_refinement", "readiness_score"),
        "insight_trend": self.get_nested_value(insight, "hidden_trend_detection", "status"),
        "insight_provider_rank": self.get_nested_value(insight, "provider_network_insight_engine", "provider_rank"),
        "insight_top_action": self.get_nested_value(insight, "insight_action_recommendation", default=[]),
        "benchmark_standing": self.get_nested_value(benchmark, "internal_benchmark_engine", "standing"),
        "benchmark_percentile": self.get_nested_value(benchmark, "quality_benchmark_calibration", "score_percentile"),
        "benchmark_target_score": self.get_nested_value(benchmark, "improvement_target_modeling", "target_score"),
        "benchmark_confidence_band": self.get_nested_value(benchmark, "benchmark_confidence_scoring", "band"),
        "coordination_score": self.get_nested_value(orchestration, "end_to_end_coordination_scoring", "score"),
        "reliability_score": self.get_nested_value(recovery, "reliability_scoring", "score"),
        "policy_confidence": self.get_nested_value(policy, "policy_compliance_confidence", "band"),
        "deployment_confidence": self.get_nested_value(deployment, "deployment_confidence_scoring", "band"),
    }

def render_build_scan_diagnostics_html(self, file_path, result):

    intel = self.intel_payload(result)
    diagnostics = intel.get("scan_diagnostics", {}) or {}
    summary = diagnostics.get("summary", {}) or {}
    pages = diagnostics.get("pages", []) or []
    ranking = diagnostics.get("source_reliability_ranking", []) or []

    if not diagnostics:
        return (
            "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
            "font-family:'Segoe UI'; font-size:13px; line-height:1.45;\">"
            "<div style=\"color:#9CA3AF;\">No scan diagnostics available for this packet.</div>"
            "</body></html>"
        )

    sections = [
        self.build_detail_card(
            "Packet Scan Summary",
            self.build_detail_table(
                [
                    ("Packet", os.path.basename(file_path)),
                    ("Extraction Mode", self.format_scan_mode(summary.get("extraction_mode"))),
                    ("OCR Attempted", "Yes" if summary.get("ocr_attempted") else "No"),
                    ("OCR Provider", summary.get("ocr_provider") or "Not used"),
                    ("Provider Chain", ", ".join(summary.get("ocr_provider_chain", []) or []) or "Not used"),
                    ("Available OCR Providers", ", ".join(summary.get("available_ocr_providers", []) or []) or "None"),
                    ("Available PDF Tools", ", ".join(summary.get("available_pdf_tools", []) or []) or "None"),
                    ("Fallback Applied", "Yes" if summary.get("fallback_applied") else "No"),
                    ("Pages", summary.get("page_count")),
                    ("Pages With Native Text", summary.get("pages_with_native_text")),
                    ("Pages With OCR Text", summary.get("pages_with_ocr")),
                    ("Pages With OCR Field Zones", summary.get("pages_with_ocr_field_zones")),
                    ("Pages With Native Field Zones", summary.get("pages_with_native_field_zones")),
                    ("Pages With Field Zones", summary.get("pages_with_field_zones")),
                    ("Pages With Split Segments", summary.get("pages_with_split_segments")),
                    (
                        "Average OCR Confidence",
                        summary.get("average_ocr_confidence")
                        if summary.get("ocr_attempted")
                        else "Not used",
                    ),
                    ("Scan Quality", summary.get("scan_quality_band")),
                    ("Scan Quality Score", summary.get("scan_quality_score")),
                    ("Handwriting Risk", summary.get("handwriting_risk_level")),
                    ("Handwriting Risk Score", summary.get("handwriting_risk_score")),
                    ("Pages With Table Regions", summary.get("pages_with_table_regions")),
                    ("Pages With Signature Regions", summary.get("pages_with_signature_regions")),
                    ("Pages With Handwritten Regions", summary.get("pages_with_handwritten_regions")),
                ],
                value_color="#57B6FF",
                show_missing=False,
            ),
            accent_color="#57B6FF",
            margin_top=0,
        )
    ]

    if ranking:
        ranking_items = [
            f"{item.get('rank')}. {self.format_field(item.get('document_type', 'unknown'))} | "
            f"Reliability {item.get('reliability_score')} ({item.get('reliability_band')}) | "
            f"Confidence {item.get('average_confidence')}"
            for item in ranking
        ]
        sections.append(
            self.build_bullet_section(
                "Most Reliable Sources",
                ranking_items,
                color="#6FCF97",
                accent_color="#27AE60",
            )
        )

    if pages:
        page_rows = []
        for page in pages:
            page_rows.append(
                "<tr>"
                f"<td style=\"color:#FFFFFF; padding:4px 8px;\">{html.escape(str(page.get('page')))}</td>"
                f"<td style=\"color:#DCE6F2; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('document_type')))}</td>"
                f"<td style=\"color:#9B8CFF; padding:4px 8px;\">{html.escape(self.format_scan_mode(page.get('text_source')))}</td>"
                f"<td style=\"color:#57B6FF; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('ocr_provider') or 'Not used'))}</td>"
                f"<td style=\"color:#57B6FF; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('ocr_confidence') if page.get('ocr_confidence') is not None else 'Not used'))}</td>"
                f"<td style=\"color:#56CCF2; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('classification_confidence')))}</td>"
                f"<td style=\"color:#DCE6F2; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('scan_quality')))}</td>"
                f"<td style=\"color:#F2C94C; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('handwriting_risk')))}</td>"
                f"<td style=\"color:#6FCF97; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('field_zone_count')))}</td>"
                f"<td style=\"color:#57B6FF; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('ocr_field_zone_count')))}</td>"
                f"<td style=\"color:#6FCF97; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('native_field_zone_count')))}</td>"
                f"<td style=\"color:#DCE6F2; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('split_segment_count')))}</td>"
                "</tr>"
            )

        page_table = (
            "<table width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"border-collapse:collapse;\">"
            "<tr>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Page</td>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Document</td>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Read Mode</td>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Provider</td>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">OCR</td>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Classify</td>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Scan Quality</td>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Handwriting</td>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Field Zones</td>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">OCR Zones</td>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Native Zones</td>"
            "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Segments</td>"
            "</tr>"
            + "".join(page_rows) +
            "</table>"
        )

        sections.append(
            self.build_detail_card(
                "Page Diagnostics",
                page_table,
                accent_color="#57B6FF",
            )
        )

    rendered_sections = "".join(section for section in sections if section)

    return (
        "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
        "font-family:'Segoe UI'; font-size:13px; line-height:1.45;\">"
        f"{rendered_sections}</body></html>"
    )

def render_build_packet_details_html_condensed(self, file, result):

    score = result.get("score", 0)
    forms = result.get("forms", [])
    fields = result.get("fields", {})
    issues = result.get("issues", [])
    fixes = result.get("fixes", [])
    intel_display = result.get("intel", {}).get("display", {})
    issue_items = intel_display.get("issue_details") or issues
    issue_groups = intel_display.get("issue_breakdowns") or [{"title": item, "details": []} for item in issue_items]
    fix_items = intel_display.get("priority_fixes") or fixes
    review_rationale = (
        intel_display.get("review_rationale")
        or intel_display.get("why_weak")
        or intel_display.get("approval_rationale")
        or []
    )
    review_rationale = self.polish_review_rationale(review_rationale, max_items=5)
    issue_palette = self.get_issue_display_palette(intel_display)

    score_color = "#27AE60" if score >= 90 else "#F2C94C" if score >= 70 else "#EB5757"

    summary_rows = [
        ("Packet", os.path.basename(file)),
        ("Score", score),
    ]
    decision_rows = []

    if intel_display:
        summary_rows.extend(
            [
                ("Packet Strength", intel_display.get("packet_strength")),
                ("Submission Readiness", intel_display.get("submission_readiness")),
                ("Approval Probability", intel_display.get("approval_probability")),
                ("Next Action", intel_display.get("next_action")),
            ]
        )
        decision_rows = [
            ("Packet Confidence", intel_display.get("packet_confidence")),
            ("Denial Risk", intel_display.get("denial_risk")),
            ("Workflow Queue", intel_display.get("workflow_queue")),
            ("Review Priority", intel_display.get("review_priority")),
        ]

    sections = [
        self.build_operator_quick_read_card(
            intel_display,
            issue_groups,
            fix_items,
            review_rationale,
            margin_top=0,
        ),
        self.build_detail_card(
            "Packet Summary",
            self.build_detail_table(summary_rows, value_color="#57B6FF", show_missing=False),
            accent_color="#57B6FF",
            margin_top=0,
        ),
    ]

    if any(value not in (None, "", [], {}) for _, value in decision_rows):
        sections.append(
            self.build_detail_card(
                "Decision Snapshot",
                self.build_detail_table(decision_rows, value_color="#57B6FF", show_missing=False),
                accent_color="#57B6FF",
            )
        )
        sections.append(
            self.build_repeat_review_comparison_card(file, result)
        )

    sections.extend(
        [
            self.build_bullet_section(
                "Documents Found",
                forms,
                color="#6FCF97",
                accent_color="#27AE60",
                bullet="+",
            ),
            self.build_bullet_section(
                "Expected Documents",
                intel_display.get("expected_documents", []),
                color="#6FCF97",
                accent_color="#27AE60",
                bullet="+",
            ),
            self.build_detail_card(
                "Key Packet Fields",
                self.build_detail_table(
                    [
                        (
                            self.format_packet_field_label(key)
                            if hasattr(self, "format_packet_field_label")
                            else self.format_field(key),
                            value,
                        )
                        for key, value in fields.items()
                    ],
                    value_color="#DCE6F2",
                ),
                accent_color="#5B8DEF",
            ),
            self.build_bullet_section(
                "Issues",
                issue_items,
                color="#EB5757",
                accent_color="#EB5757",
                bullet="⚠",
            ),
            self.build_bullet_section(
                "Missing Items",
                intel_display.get("missing_items", []),
                color="#EB5757",
                accent_color="#EB5757",
            ),
            self.build_bullet_section(
                "Priority Fixes",
                fix_items,
                color="#F2C94C",
                accent_color="#F2C94C",
            ),
            self.build_bullet_section(
                "Review Flags",
                [self.format_review_flag(flag) for flag in intel_display.get("review_flags", [])],
                color="#F2994A",
                accent_color="#F2994A",
            ),
            self.build_bullet_section(
                "Review Rationale",
                review_rationale,
                color="#57B6FF",
                accent_color="#57B6FF",
            ),
        ]
    )

    if intel_display:
        sections.extend(self.build_condensed_advanced_intel_sections(result))

    rendered_sections = "".join(section for section in sections if section)

    return (
        "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
        "font-family:'Segoe UI'; font-size:13px; line-height:1.45;\">"
        f"{rendered_sections}</body></html>"
    )

