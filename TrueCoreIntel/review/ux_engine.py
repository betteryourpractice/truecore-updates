class UXIntelligenceBuilder:
    UX_VERSION = "truecore_ux_v1"
    UX_EFFECTIVE_DATE = "2026-03-24"

    def build(
        self,
        packet,
        submission_decision,
        decision_intelligence,
        predictive_intelligence,
        optimization_intelligence,
        compliance_intelligence,
        knowledge_intelligence,
        security_intelligence,
    ):
        adaptive_interface = self.build_adaptive_interface_engine(
            packet,
            submission_decision,
            predictive_intelligence,
            security_intelligence,
        )
        smart_dashboard = self.build_smart_dashboard_generation(
            packet,
            decision_intelligence,
            predictive_intelligence,
            optimization_intelligence,
            security_intelligence,
        )
        workflow_visualization = self.build_workflow_visualization(
            packet,
            decision_intelligence,
            compliance_intelligence,
            optimization_intelligence,
        )
        behavior_tracking = self.build_user_behavior_tracking(
            packet,
            adaptive_interface,
            smart_dashboard,
            optimization_intelligence,
        )
        personalization = self.build_interface_personalization(
            submission_decision,
            decision_intelligence,
            optimization_intelligence,
            security_intelligence,
        )
        guided_workflow = self.build_guided_workflow_assistance(
            packet,
            decision_intelligence,
            knowledge_intelligence,
            compliance_intelligence,
            security_intelligence,
        )
        error_prevention = self.build_error_prevention_ui(
            packet,
            compliance_intelligence,
            security_intelligence,
        )
        feedback_capture = self.build_feedback_capture_system(
            packet,
            guided_workflow,
            personalization,
        )
        ux_metrics = self.build_ux_performance_metrics(
            packet,
            adaptive_interface,
            behavior_tracking,
            guided_workflow,
            error_prevention,
        )
        continuous_improvement = self.build_continuous_ux_improvement(
            ux_metrics,
            smart_dashboard,
            behavior_tracking,
            feedback_capture,
            optimization_intelligence,
        )

        return {
            "adaptive_interface_engine": adaptive_interface,
            "smart_dashboard_generation": smart_dashboard,
            "workflow_visualization": workflow_visualization,
            "user_behavior_tracking": behavior_tracking,
            "interface_personalization": personalization,
            "guided_workflow_assistance": guided_workflow,
            "error_prevention_ui": error_prevention,
            "feedback_capture_system": feedback_capture,
            "ux_performance_metrics": ux_metrics,
            "continuous_ux_improvement": continuous_improvement,
        }

    def build_adaptive_interface_engine(
        self,
        packet,
        submission_decision,
        predictive_intelligence,
        security_intelligence,
    ):
        readiness = submission_decision.get("readiness")
        complexity = predictive_intelligence.get("case_complexity_scoring", {}).get("level")
        security_risk = security_intelligence.get("risk_assessment_engine", {}).get("level")

        if security_risk in {"high", "critical"}:
            mode = "security_triage"
            density = "focused"
            focus_panels = ["security", "identity", "audit", "workflow"]
        elif readiness == "ready":
            mode = "submission_fast_view"
            density = "compact"
            focus_panels = ["readiness", "submission", "quality", "documents"]
        elif readiness == "requires_review":
            mode = "review_workbench"
            density = "standard"
            focus_panels = ["conflicts", "field_trace", "review_actions", "dashboard"]
        else:
            mode = "guided_correction"
            density = "detailed"
            focus_panels = ["missing_items", "guided_steps", "clinical_support", "security"]

        if complexity in {"high", "critical"} and density == "compact":
            density = "standard"

        return {
            "status": "active",
            "version": self.UX_VERSION,
            "effective_date": self.UX_EFFECTIVE_DATE,
            "mode": mode,
            "layout_density": density,
            "focus_panels": focus_panels,
            "summary": f"Use {mode} with {density} density to keep reviewers focused on the current packet state.",
        }

    def build_smart_dashboard_generation(
        self,
        packet,
        decision_intelligence,
        predictive_intelligence,
        optimization_intelligence,
        security_intelligence,
    ):
        cards = [
            {"card": "submission_readiness", "priority": "high"},
            {"card": "recommended_next_action", "priority": "high"},
            {"card": "workflow_route", "priority": "high"},
            {"card": "denial_risk", "priority": "medium"},
        ]

        if packet.missing_documents or packet.missing_fields:
            cards.append({"card": "missing_evidence", "priority": "high"})
        if packet.conflicts:
            cards.append({"card": "conflicts", "priority": "high"})
        if security_intelligence.get("risk_assessment_engine", {}).get("level") in {"high", "critical"}:
            cards.append({"card": "security_risk", "priority": "high"})
        if predictive_intelligence.get("case_complexity_scoring", {}).get("level") in {"high", "critical"}:
            cards.append({"card": "complexity", "priority": "medium"})
        if optimization_intelligence.get("smart_queue_prioritization", {}).get("priority_bucket") in {"high", "urgent"}:
            cards.append({"card": "queue_priority", "priority": "medium"})

        alerts = []
        next_action = decision_intelligence.get("recommended_next_action", {})
        if next_action:
            alerts.append(next_action.get("reason"))
        alerts.extend(security_intelligence.get("risk_assessment_engine", {}).get("drivers", [])[:2])

        return {
            "status": "generated",
            "primary_cards": cards[:6],
            "secondary_cards": cards[6:10],
            "alert_count": len([item for item in alerts if item]),
            "alerts": [item for item in alerts if item],
            "summary": "Dashboard cards are prioritized around readiness, next action, risk, and packet-specific blockers.",
        }

    def build_workflow_visualization(
        self,
        packet,
        decision_intelligence,
        compliance_intelligence,
        optimization_intelligence,
    ):
        workflow_queue = decision_intelligence.get("workflow_decision_routing", {}).get("queue")
        compliance_queue = compliance_intelligence.get("compliance_workflow_routing", {}).get("queue")
        throughput_lane = optimization_intelligence.get("throughput_optimization", {}).get("processing_lane")

        stages = [
            {"stage": "intake", "status": "complete"},
            {"stage": "detection", "status": "complete"},
            {"stage": "extraction", "status": "complete"},
            {"stage": "validation", "status": "complete"},
            {"stage": "intelligence", "status": "complete"},
            {"stage": "review", "status": "active" if workflow_queue != "submission_queue" else "complete"},
            {"stage": "submission", "status": "queued" if workflow_queue == "submission_queue" else "pending"},
        ]

        return {
            "status": "mapped",
            "current_stage": "review" if workflow_queue != "submission_queue" else "submission",
            "primary_queue": workflow_queue,
            "compliance_queue": compliance_queue,
            "throughput_lane": throughput_lane,
            "stages": stages,
            "summary": f"Workflow visualization centers on {workflow_queue or 'review_queue'} with {throughput_lane or 'standard'} handling.",
        }

    def build_user_behavior_tracking(
        self,
        packet,
        adaptive_interface,
        smart_dashboard,
        optimization_intelligence,
    ):
        friction_signals = []
        if packet.missing_documents:
            friction_signals.append("missing_documents")
        if packet.conflicts:
            friction_signals.append("field_conflicts")
        if adaptive_interface.get("mode") == "security_triage":
            friction_signals.append("security_triage")
        if optimization_intelligence.get("smart_queue_prioritization", {}).get("priority_bucket") == "urgent":
            friction_signals.append("urgent_queue")

        return {
            "status": "active",
            "tracked_events": [
                "dashboard_opened",
                "field_highlight_opened",
                "guided_step_completed",
                "correction_submitted",
                "review_completed",
            ],
            "predicted_friction_signals": friction_signals,
            "recommended_session_focus": (smart_dashboard.get("primary_cards") or [{}])[0].get("card"),
            "summary": "Behavior tracking is set up around dashboard usage, guided steps, and correction outcomes.",
        }

    def build_interface_personalization(
        self,
        submission_decision,
        decision_intelligence,
        optimization_intelligence,
        security_intelligence,
    ):
        role = optimization_intelligence.get("resource_allocation_optimization", {}).get("recommended_role") or "review_specialist"
        queue = decision_intelligence.get("workflow_decision_routing", {}).get("queue")
        security_level = security_intelligence.get("risk_assessment_engine", {}).get("level")
        show_sensitive_values = security_level not in {"high", "critical"}

        return {
            "status": "personalized",
            "recommended_role": role,
            "layout_preset": f"{role}_{queue or 'review'}",
            "show_sensitive_values": show_sensitive_values,
            "default_tabs": ["summary", "fields", "documents", "actions"],
            "summary": "Interface personalization aligns the dashboard with the assigned role and current packet queue.",
        }

    def build_guided_workflow_assistance(
        self,
        packet,
        decision_intelligence,
        knowledge_intelligence,
        compliance_intelligence,
        security_intelligence,
    ):
        steps = []
        next_action = decision_intelligence.get("recommended_next_action", {})
        if next_action.get("action"):
            steps.append({
                "step": next_action["action"],
                "target": next_action.get("target"),
                "priority": next_action.get("priority"),
            })

        for doc in packet.missing_documents[:3]:
            steps.append({"step": "attach_missing_document", "target": doc, "priority": "high"})
        for field in packet.missing_fields[:3]:
            steps.append({"step": "verify_missing_field", "target": field, "priority": "medium"})
        for item in (knowledge_intelligence.get("contextual_recommendation_engine", {}).get("recommendations") or [])[:2]:
            steps.append({
                "step": item.get("action"),
                "target": item.get("target"),
                "priority": item.get("priority") or "medium",
            })

        if security_intelligence.get("security_incident_response", {}).get("status") == "escalated":
            steps.insert(0, {"step": "security_hold", "target": "packet", "priority": "high"})
        if compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status") != "compliant":
            steps.append({"step": "resolve_compliance_issues", "target": "packet", "priority": "high"})

        deduped = []
        seen = set()
        for item in steps:
            key = (item.get("step"), item.get("target"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)

        return {
            "status": "guided",
            "step_count": len(deduped),
            "steps": deduped,
            "summary": "Guided workflow assistance converts packet state into a short actionable checklist.",
        }

    def build_error_prevention_ui(self, packet, compliance_intelligence, security_intelligence):
        warnings = []
        blocking = []
        confirmation_fields = []

        if packet.conflicts:
            warnings.append("Confirm reviewer-selected field values before completion.")
        if packet.missing_documents:
            blocking.append("Submission controls should stay disabled while required documents are missing.")
        if security_intelligence.get("risk_assessment_engine", {}).get("level") in {"high", "critical"}:
            blocking.append("Sensitive-field edits require elevated review because security risk is high.")
        if compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status") != "compliant":
            warnings.append("Show compliance remediation prompts before finalization.")

        for field in ("name", "dob", "authorization_number", "va_icn", "claim_number"):
            if packet.fields.get(field):
                confirmation_fields.append(field)

        return {
            "status": "active",
            "warning_count": len(warnings),
            "blocking_error_count": len(blocking),
            "warnings": warnings,
            "blocking_errors": blocking,
            "confirmation_required_fields": confirmation_fields,
            "summary": "UI guardrails focus on protected fields, blocking gaps, and compliance-sensitive edits.",
        }

    def build_feedback_capture_system(self, packet, guided_workflow, personalization):
        return {
            "status": "ready",
            "channels": [
                "review_annotations",
                "correction_records",
                "dashboard_feedback_form",
            ],
            "prompt_topics": [
                "extraction_accuracy",
                "false_positive_conflicts",
                "workflow_friction",
                "missing_document_guidance",
            ],
            "default_owner_role": personalization.get("recommended_role"),
            "related_step_count": guided_workflow.get("step_count"),
            "summary": "Feedback capture is built into annotations, corrections, and dashboard-level UX prompts.",
        }

    def build_ux_performance_metrics(
        self,
        packet,
        adaptive_interface,
        behavior_tracking,
        guided_workflow,
        error_prevention,
    ):
        score = 0.9
        score -= min(0.22, 0.05 * len(packet.missing_documents))
        score -= min(0.18, 0.04 * len(packet.conflicts))
        score -= min(0.15, 0.03 * guided_workflow.get("step_count", 0))
        score -= min(0.12, 0.03 * error_prevention.get("blocking_error_count", 0))
        if adaptive_interface.get("mode") == "security_triage":
            score -= 0.08
        if behavior_tracking.get("predicted_friction_signals"):
            score -= min(0.1, 0.03 * len(behavior_tracking["predicted_friction_signals"]))
        score = round(max(0.05, min(score, 0.99)), 2)

        if score >= 0.82:
            friction = "low"
        elif score >= 0.58:
            friction = "moderate"
        else:
            friction = "high"

        return {
            "status": "measured",
            "score": score,
            "friction_level": friction,
            "guided_step_count": guided_workflow.get("step_count", 0),
            "blocking_error_count": error_prevention.get("blocking_error_count", 0),
            "summary": f"UX friction is {friction} for the current packet workflow.",
        }

    def build_continuous_ux_improvement(
        self,
        ux_metrics,
        smart_dashboard,
        behavior_tracking,
        feedback_capture,
        optimization_intelligence,
    ):
        recommendations = []
        if ux_metrics.get("friction_level") == "high":
            recommendations.append("Elevate guided workflow steps above non-critical dashboard cards.")
        if len(smart_dashboard.get("alerts", [])) > 2:
            recommendations.append("Condense alert messaging so the highest-priority blocker stays first.")
        if behavior_tracking.get("predicted_friction_signals"):
            recommendations.append("Prioritize interaction tracking on the current friction signals.")
        if optimization_intelligence.get("smart_queue_prioritization", {}).get("priority_bucket") in {"high", "urgent"}:
            recommendations.append("Bias the interface toward quick resolution actions and conflict review.")

        status = "improve" if recommendations else "stable"
        return {
            "status": status,
            "feedback_channels": feedback_capture.get("channels", []),
            "recommendation_count": len(recommendations),
            "recommendations": recommendations,
            "summary": (
                "UX should be tuned around the current workflow friction signals."
                if recommendations else
                "Current UX profile is stable for the packet mix."
            ),
        }
