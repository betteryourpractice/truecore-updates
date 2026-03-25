class KnowledgeIntelligenceBuilder:
    KNOWLEDGE_BASE_VERSION = "truecore_knowledge_v1"
    KNOWLEDGE_BASE_EFFECTIVE_DATE = "2026-03-24"
    CLINICAL_GUIDELINES = {
        "MRI": {
            "guideline_id": "advanced_imaging_support",
            "required_evidence": [
                "diagnosis_or_icd",
                "symptom_or_reason",
                "clinical_notes",
            ],
            "summary": "Advanced imaging requests should be anchored by diagnosis or ICD support, symptom or request context, and clinical note evidence.",
        },
        "PHYSICAL_THERAPY": {
            "guideline_id": "rehabilitation_support",
            "required_evidence": [
                "diagnosis_or_icd",
                "clinical_notes",
            ],
            "summary": "Physical therapy requests should show a documented diagnosis and supporting clinical notes.",
        },
    }
    EXPERT_MODULES = {
        "clean_submission": ["packet_qc_expert", "submission_readiness_expert"],
        "missing_consent_submission": ["consent_control_expert", "packet_completion_expert"],
        "identity_integrity_escalation": ["identity_integrity_expert", "senior_review_expert"],
        "provider_conflict_review": ["provider_validation_expert", "review_workflow_expert"],
        "documentation_gap_correction": ["document_gap_expert", "packet_completion_expert"],
        "review_sensitive_packet": ["review_workflow_expert"],
    }

    def build(self, packet, submission_decision, decision_intelligence, predictive_intelligence, compliance_intelligence):
        packet_type = decision_intelligence.get("packet_type") or "authorization_request"
        central_knowledge_base = self.build_central_knowledge_base(packet_type)
        clinical_guideline_mapping = self.build_clinical_guideline_mapping(packet)
        case_based_reasoning = self.build_case_based_reasoning(
            packet,
            submission_decision,
            compliance_intelligence,
        )
        rule_learning = self.build_rule_learning_system(packet, case_based_reasoning, clinical_guideline_mapping)
        contextual_recommendation = self.build_contextual_recommendation_engine(
            packet,
            decision_intelligence,
            compliance_intelligence,
            clinical_guideline_mapping,
            case_based_reasoning,
        )
        knowledge_gaps = self.build_knowledge_gap_detection(
            packet,
            case_based_reasoning,
            clinical_guideline_mapping,
            compliance_intelligence,
        )
        expert_system = self.build_expert_system_integration(
            case_based_reasoning,
            clinical_guideline_mapping,
            compliance_intelligence,
        )
        version_control = self.build_knowledge_version_control()
        reasoning_transparency = self.build_reasoning_transparency_layer(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
            compliance_intelligence,
            clinical_guideline_mapping,
            case_based_reasoning,
            contextual_recommendation,
        )
        feedback_loop = self.build_knowledge_feedback_loop(
            packet,
            case_based_reasoning,
            rule_learning,
            knowledge_gaps,
        )

        return {
            "central_knowledge_base": central_knowledge_base,
            "case_based_reasoning_engine": case_based_reasoning,
            "rule_learning_system": rule_learning,
            "contextual_recommendation_engine": contextual_recommendation,
            "knowledge_gap_detection": knowledge_gaps,
            "expert_system_integration": expert_system,
            "clinical_guideline_mapping": clinical_guideline_mapping,
            "knowledge_version_control": version_control,
            "reasoning_transparency_layer": reasoning_transparency,
            "knowledge_feedback_loop": feedback_loop,
        }

    def build_central_knowledge_base(self, packet_type):
        return {
            "status": "active",
            "version": self.KNOWLEDGE_BASE_VERSION,
            "effective_date": self.KNOWLEDGE_BASE_EFFECTIVE_DATE,
            "packet_type": packet_type,
            "knowledge_domains": [
                "clinical_guidelines",
                "workflow_patterns",
                "packet_profiles",
                "compliance_controls",
            ],
            "guideline_count": len(self.CLINICAL_GUIDELINES),
            "expert_module_count": len({module for modules in self.EXPERT_MODULES.values() for module in modules}),
        }

    def build_clinical_guideline_mapping(self, packet):
        procedure = str(packet.fields.get("procedure") or "").strip().upper()
        diagnosis_present = bool(packet.fields.get("diagnosis")) or bool(packet.fields.get("icd_codes"))
        symptom_present = bool(packet.fields.get("symptom")) or bool(packet.fields.get("reason_for_request"))
        clinical_notes_present = "clinical_notes" in set(packet.detected_documents)

        guideline = self.CLINICAL_GUIDELINES.get(procedure)
        if not guideline:
            return {
                "status": "not_applicable" if not procedure else "unmapped",
                "procedure": packet.fields.get("procedure"),
                "guideline_id": None,
                "required_evidence": [],
                "evidence_status": {},
                "summary": "No procedure-specific clinical guideline mapping was applied.",
            }

        evidence_status = {
            "diagnosis_or_icd": diagnosis_present,
            "symptom_or_reason": symptom_present,
            "clinical_notes": clinical_notes_present,
        }
        met_count = sum(1 for requirement in guideline["required_evidence"] if evidence_status.get(requirement))
        required_count = len(guideline["required_evidence"])

        if met_count == required_count:
            status = "aligned"
        elif met_count >= max(1, required_count - 1):
            status = "partially_aligned"
        else:
            status = "gap"

        missing_evidence = [
            requirement
            for requirement in guideline["required_evidence"]
            if not evidence_status.get(requirement)
        ]
        summary = (
            guideline["summary"]
            if status == "aligned" else
            f"Guideline mapping is {status}; missing evidence: {', '.join(missing_evidence)}."
        )

        return {
            "status": status,
            "procedure": packet.fields.get("procedure"),
            "guideline_id": guideline["guideline_id"],
            "required_evidence": list(guideline["required_evidence"]),
            "evidence_status": evidence_status,
            "missing_evidence": missing_evidence,
            "summary": summary,
        }

    def build_case_based_reasoning(self, packet, submission_decision, compliance_intelligence):
        compliance_validation = compliance_intelligence.get("compliance_validation_checks", {})
        documentation = compliance_intelligence.get("documentation_requirement_enforcement", {})
        missing_documents = documentation.get("missing_documents", []) or list(packet.missing_documents)
        conflict_fields = {
            conflict.get("field")
            for conflict in packet.conflicts
            if conflict.get("field")
        }

        if "consent" in missing_documents:
            archetype = "missing_consent_submission"
            similarity = "strong"
            why = "Packet resembles previous correction-bound submissions missing consent support."
        elif "packet_integrity_risk" in packet.review_flags or "name" in conflict_fields or "dob" in conflict_fields:
            archetype = "identity_integrity_escalation"
            similarity = "strong"
            why = "Packet resembles high-risk identity or integrity escalation cases."
        elif {"provider", "ordering_provider", "referring_provider"}.intersection(conflict_fields):
            archetype = "provider_conflict_review"
            similarity = "moderate"
            why = "Packet resembles review-sensitive provider conflict cases."
        elif submission_decision.get("readiness") == "ready" and compliance_validation.get("overall_status") == "compliant":
            archetype = "clean_submission"
            similarity = "strong"
            why = "Packet resembles submission-ready packets with aligned evidence and no blocking gaps."
        elif packet.missing_fields or packet.missing_documents:
            archetype = "documentation_gap_correction"
            similarity = "moderate"
            why = "Packet resembles packets that need corrective document or field completion."
        else:
            archetype = "review_sensitive_packet"
            similarity = "limited"
            why = "Packet only partially matches a known reasoning archetype and still needs reviewer judgment."

        return {
            "archetype": archetype,
            "similarity": similarity,
            "confidence": 0.9 if similarity == "strong" else (0.72 if similarity == "moderate" else 0.55),
            "analog_case_outcome": submission_decision.get("readiness"),
            "why": why,
        }

    def build_rule_learning_system(self, packet, case_based_reasoning, clinical_guideline_mapping):
        candidate_rules = []

        if "consent" in packet.missing_documents:
            candidate_rules.append({
                "rule_id": "consent_required_for_full_submission",
                "status": "candidate",
                "evidence": "Missing consent repeatedly blocks otherwise viable submission packets.",
            })
        if packet.fields.get("procedure") == "MRI" and clinical_guideline_mapping.get("status") != "aligned":
            candidate_rules.append({
                "rule_id": "mri_requires_clinical_support_bundle",
                "status": "candidate",
                "evidence": "MRI requests degrade when diagnosis, symptom, or note support is incomplete.",
            })
        if case_based_reasoning.get("archetype") == "identity_integrity_escalation":
            candidate_rules.append({
                "rule_id": "identity_conflicts_force_senior_review",
                "status": "confirmed_pattern",
                "evidence": "Identity conflicts consistently escalate packet handling.",
            })

        return {
            "status": "candidate_rules_generated" if candidate_rules else "stable",
            "candidate_rule_count": len(candidate_rules),
            "candidate_rules": candidate_rules,
        }

    def build_contextual_recommendation_engine(self, packet, decision_intelligence, compliance_intelligence, clinical_guideline_mapping, case_based_reasoning):
        recommendations = []
        next_action = decision_intelligence.get("recommended_next_action", {})
        if next_action:
            recommendations.append({
                "type": "workflow_action",
                "priority": next_action.get("priority"),
                "action": next_action.get("action"),
                "target": next_action.get("target"),
                "why": next_action.get("reason"),
            })

        if packet.missing_documents:
            for doc in sorted(packet.missing_documents)[:3]:
                recommendations.append({
                    "type": "missing_document",
                    "priority": "high",
                    "action": "collect_document",
                    "target": doc,
                    "why": f"{doc} is missing and still weakens readiness.",
                })

        if clinical_guideline_mapping.get("status") in {"gap", "partially_aligned"}:
            recommendations.append({
                "type": "clinical_guideline_support",
                "priority": "medium",
                "action": "strengthen_guideline_alignment",
                "target": clinical_guideline_mapping.get("procedure") or "procedure_support",
                "why": clinical_guideline_mapping.get("summary"),
            })

        if compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status") != "compliant":
            recommendations.append({
                "type": "compliance",
                "priority": "high",
                "action": "resolve_compliance_gaps",
                "target": case_based_reasoning.get("archetype"),
                "why": "Packet remains compliance-sensitive and should be corrected before final submission.",
            })

        return {
            "status": "active" if recommendations else "limited",
            "recommendation_count": len(recommendations),
            "recommendations": self.unique_preserve_order(recommendations),
        }

    def build_knowledge_gap_detection(self, packet, case_based_reasoning, clinical_guideline_mapping, compliance_intelligence):
        gaps = []

        if clinical_guideline_mapping.get("status") == "unmapped":
            gaps.append("procedure_guidance_unmapped")
        if clinical_guideline_mapping.get("status") in {"gap", "partially_aligned"}:
            gaps.append("clinical_support_gap")
        if case_based_reasoning.get("similarity") == "limited":
            gaps.append("case_analogue_coverage")
        if packet.missing_documents:
            gaps.append("document_requirement_coverage")
        if compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status") != "compliant":
            gaps.append("compliance_resolution_knowledge")

        return {
            "status": "gaps_detected" if gaps else "sufficient",
            "gap_count": len(gaps),
            "gaps": self.unique_preserve_order(gaps),
        }

    def build_expert_system_integration(self, case_based_reasoning, clinical_guideline_mapping, compliance_intelligence):
        matched_modules = list(self.EXPERT_MODULES.get(case_based_reasoning.get("archetype"), []))
        if clinical_guideline_mapping.get("guideline_id"):
            matched_modules.append("clinical_guideline_mapper")
        if compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status") != "compliant":
            matched_modules.append("compliance_control_expert")

        matched_modules = self.unique_preserve_order(matched_modules)
        return {
            "status": "active" if matched_modules else "limited",
            "matched_modules": matched_modules,
            "summary": (
                "Expert heuristics were matched for the current packet."
                if matched_modules else
                "No specialized expert heuristic module was matched."
            ),
        }

    def build_knowledge_version_control(self):
        return {
            "status": "controlled",
            "active_version": self.KNOWLEDGE_BASE_VERSION,
            "effective_date": self.KNOWLEDGE_BASE_EFFECTIVE_DATE,
            "change_detected": False,
        }

    def build_reasoning_transparency_layer(
        self,
        packet,
        submission_decision,
        decision_intelligence,
        predictive_intelligence,
        compliance_intelligence,
        clinical_guideline_mapping,
        case_based_reasoning,
        contextual_recommendation,
    ):
        traces = [
            {
                "stage": "submission_decision",
                "evidence": submission_decision.get("readiness"),
                "outcome": decision_intelligence.get("workflow_decision_routing", {}).get("queue"),
            },
            {
                "stage": "predictive_forecast",
                "evidence": predictive_intelligence.get("approval_outcome_prediction", {}).get("level"),
                "outcome": predictive_intelligence.get("turnaround_time_prediction", {}).get("band"),
            },
            {
                "stage": "compliance",
                "evidence": compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status"),
                "outcome": compliance_intelligence.get("compliance_workflow_routing", {}).get("queue"),
            },
            {
                "stage": "clinical_guideline",
                "evidence": clinical_guideline_mapping.get("guideline_id"),
                "outcome": clinical_guideline_mapping.get("status"),
            },
            {
                "stage": "case_reasoning",
                "evidence": case_based_reasoning.get("archetype"),
                "outcome": case_based_reasoning.get("similarity"),
            },
        ]

        if contextual_recommendation.get("recommendations"):
            first_recommendation = contextual_recommendation["recommendations"][0]
            traces.append({
                "stage": "recommended_action",
                "evidence": first_recommendation.get("target"),
                "outcome": first_recommendation.get("action"),
            })

        return {
            "status": "transparent",
            "trace_count": len(traces),
            "traces": traces,
            "summary": (
                f"Reasoning remains transparent across {len(traces)} stages for packet {packet.output.get('packet_label') or 'unlabeled_packet'}."
            ),
        }

    def build_knowledge_feedback_loop(self, packet, case_based_reasoning, rule_learning, knowledge_gaps):
        feedback_targets = []
        if packet.missing_documents or packet.missing_fields:
            feedback_targets.append("packet_completion_outcomes")
        if packet.conflicts:
            feedback_targets.append("reviewer_conflict_resolutions")
        if knowledge_gaps.get("gap_count"):
            feedback_targets.append("knowledge_gap_backlog")
        if rule_learning.get("candidate_rule_count"):
            feedback_targets.append("candidate_rule_validation")

        return {
            "status": "active",
            "artifact_generated": False,
            "feedback_targets": self.unique_preserve_order(feedback_targets),
            "archetype": case_based_reasoning.get("archetype"),
        }

    def unique_preserve_order(self, items):
        seen = set()
        ordered = []

        for item in items:
            if isinstance(item, dict):
                key = tuple(sorted(item.items()))
            else:
                key = item
            if key not in seen:
                seen.add(key)
                ordered.append(item)

        return ordered
