class LearningEngine:

    def learn(self, packet):
        self.capture_metrics(packet)
        self.capture_corrections(packet)
        return packet

    def capture_metrics(self, packet):
        packet.metrics["processed"] = True
        packet.metrics["source_type"] = packet.source_type

        # Track missing fields pattern
        packet.metrics["missing_fields"] = list(packet.missing_fields)

        # Track missing documents pattern
        packet.metrics["missing_documents"] = list(packet.missing_documents)

        # Track conflict types + severity
        packet.metrics["conflicts"] = [
            {
                "field": c.get("field"),
                "type": c.get("type"),
                "severity": c.get("severity"),
            }
            for c in packet.conflicts
        ]

        # Track review flags (reasoning failures)
        packet.metrics["review_flags"] = list(dict.fromkeys(packet.review_flags))

        # Track overall outcome
        packet.metrics["packet_score"] = packet.packet_score
        packet.metrics["packet_confidence"] = packet.packet_confidence
        packet.metrics["packet_strength"] = packet.packet_strength
        packet.metrics["detected_documents"] = sorted(packet.detected_documents)
        packet.metrics["duplicate_pages"] = list(packet.duplicate_pages)
        packet.metrics["page_confidence"] = dict(packet.page_confidence)
        packet.metrics["ocr_provider"] = getattr(packet, "ocr_provider", None)
        packet.metrics["intake_diagnostics"] = dict(getattr(packet, "intake_diagnostics", {}) or {})
        packet.metrics["benchmark_scores"] = dict(getattr(packet, "benchmark_scores", {}) or {})
        packet.metrics["page_metadata"] = [
            {
                "page_number": metadata.get("page_number"),
                "ocr_confidence": metadata.get("ocr_confidence"),
                "ocr_provider": metadata.get("ocr_provider"),
                "field_zone_count": len(metadata.get("field_zones", []) or []),
                "has_header_text": bool((metadata.get("layout", {}) or {}).get("header_text")),
                "table_region_count": len(((metadata.get("layout", {}) or {}).get("table_regions", []) or [])),
                "handwritten_region_count": len(((metadata.get("layout", {}) or {}).get("handwritten_regions", []) or [])),
            }
            for metadata in list(getattr(packet, "page_metadata", []) or [])
        ]
        packet.metrics["evidence_intelligence"] = dict(getattr(packet, "evidence_intelligence", {}) or {})
        packet.metrics["clinical_intelligence"] = dict(getattr(packet, "clinical_intelligence", {}) or {})
        packet.metrics["denial_intelligence"] = dict(getattr(packet, "denial_intelligence", {}) or {})
        packet.metrics["human_in_the_loop_intelligence"] = dict(getattr(packet, "human_loop_intelligence", {}) or {})
        packet.metrics["orchestration_intelligence"] = dict(getattr(packet, "orchestration_intelligence", {}) or {})
        packet.metrics["architecture_intelligence"] = dict(getattr(packet, "architecture_intelligence", {}) or {})
        packet.metrics["recovery_intelligence"] = dict(getattr(packet, "recovery_intelligence", {}) or {})
        packet.metrics["policy_intelligence"] = dict(getattr(packet, "policy_intelligence", {}) or {})
        packet.metrics["deployment_intelligence"] = dict(getattr(packet, "deployment_intelligence", {}) or {})
        packet.metrics["document_intelligence"] = dict(getattr(packet, "document_intelligence", {}) or {})
        packet.metrics["validation_intelligence"] = dict(getattr(packet, "validation_intelligence", {}) or {})
        packet.metrics["deep_verification_score"] = getattr(packet, "deep_verification_score", None)
        packet.metrics["links"] = {
            "document_chronology": list(packet.links.get("document_chronology", [])),
            "recommended_page_order": list(packet.links.get("recommended_page_order", [])),
            "page_order_review_needed": bool(packet.links.get("page_order_review_needed")),
            "evidence_traceback_links": list(packet.links.get("evidence_traceback_links", [])),
            "pipeline_stage_trace": list(packet.links.get("pipeline_stage_trace", [])),
        }
        packet.metrics["submission_decision"] = dict(packet.output.get("submission_decision", {}))
        packet.metrics["decision_intelligence"] = {
            "recommended_next_action": dict(packet.output.get("recommended_next_action", {})),
            "denial_risk": dict(packet.output.get("denial_risk", {})),
            "workflow_route": dict(packet.output.get("workflow_route", {})),
            "resubmission_strategy": dict(packet.output.get("resubmission_strategy", {})),
            "success_pattern_match": dict(packet.output.get("success_pattern_match", {})),
        }
        packet.metrics["predictive_intelligence"] = {
            "approval_outcome_prediction": dict(packet.output.get("approval_outcome_prediction", {})),
            "turnaround_time_prediction": dict(packet.output.get("turnaround_time_prediction", {})),
            "bottleneck_detection": dict(packet.output.get("bottleneck_detection", {})),
            "provider_performance_prediction": dict(packet.output.get("provider_performance_prediction", {})),
            "denial_reason_forecasting": dict(packet.output.get("denial_reason_forecasting", {})),
            "volume_trend_prediction": dict(packet.output.get("volume_trend_prediction", {})),
            "staffing_demand_forecasting": dict(packet.output.get("staffing_demand_forecasting", {})),
            "submission_timing_optimization": dict(packet.output.get("submission_timing_optimization", {})),
            "case_complexity": dict(packet.output.get("case_complexity", {})),
            "predictive_escalation": dict(packet.output.get("predictive_escalation", {})),
        }
        packet.metrics["optimization_intelligence"] = {
            "workflow_efficiency_optimization": dict(packet.output.get("workflow_efficiency_optimization", {})),
            "resource_allocation_optimization": dict(packet.output.get("resource_allocation_optimization", {})),
            "processing_speed_optimization": dict(packet.output.get("processing_speed_optimization", {})),
            "cost_efficiency_analysis": dict(packet.output.get("cost_efficiency_analysis", {})),
            "redundancy_elimination": dict(packet.output.get("redundancy_elimination", {})),
            "throughput_optimization": dict(packet.output.get("throughput_optimization", {})),
            "error_rate_minimization": dict(packet.output.get("error_rate_minimization", {})),
            "smart_queue_prioritization": dict(packet.output.get("smart_queue_prioritization", {})),
            "load_balancing_engine": dict(packet.output.get("load_balancing_engine", {})),
            "continuous_performance_tuning": dict(packet.output.get("continuous_performance_tuning", {})),
        }
        packet.metrics["compliance_intelligence"] = {
            "regulatory_rule_engine": dict(packet.output.get("regulatory_rule_engine", {})),
            "compliance_validation_checks": dict(packet.output.get("compliance_validation_checks", {})),
            "audit_trail_automation": dict(packet.output.get("audit_trail_automation", {})),
            "policy_change_detection": dict(packet.output.get("policy_change_detection", {})),
            "compliance_risk_scoring": dict(packet.output.get("compliance_risk_scoring", {})),
            "documentation_requirement_enforcement": dict(packet.output.get("documentation_requirement_enforcement", {})),
            "secure_data_handling_validation": dict(packet.output.get("secure_data_handling_validation", {})),
            "audit_report_generation": dict(packet.output.get("audit_report_generation", {})),
            "violation_detection": dict(packet.output.get("violation_detection", {})),
            "compliance_workflow_routing": dict(packet.output.get("compliance_workflow_routing", {})),
        }
        packet.metrics["knowledge_intelligence"] = {
            "central_knowledge_base": dict(packet.output.get("central_knowledge_base", {})),
            "case_based_reasoning_engine": dict(packet.output.get("case_based_reasoning_engine", {})),
            "rule_learning_system": dict(packet.output.get("rule_learning_system", {})),
            "contextual_recommendation_engine": dict(packet.output.get("contextual_recommendation_engine", {})),
            "knowledge_gap_detection": dict(packet.output.get("knowledge_gap_detection", {})),
            "expert_system_integration": dict(packet.output.get("expert_system_integration", {})),
            "clinical_guideline_mapping": dict(packet.output.get("clinical_guideline_mapping", {})),
            "knowledge_version_control": dict(packet.output.get("knowledge_version_control", {})),
            "reasoning_transparency_layer": dict(packet.output.get("reasoning_transparency_layer", {})),
            "knowledge_feedback_loop": dict(packet.output.get("knowledge_feedback_loop", {})),
        }
        packet.metrics["data_intelligence"] = {
            "unified_data_model": dict(packet.output.get("unified_data_model", {})),
            "data_normalization_engine": dict(packet.output.get("data_normalization_engine", {})),
            "data_integrity_validation": dict(packet.output.get("data_integrity_validation", {})),
            "cross_source_data_linking": dict(packet.output.get("cross_source_data_linking", {})),
            "data_deduplication_engine": dict(packet.output.get("data_deduplication_engine", {})),
            "data_enrichment_layer": dict(packet.output.get("data_enrichment_layer", {})),
            "metadata_extraction": dict(packet.output.get("metadata_extraction", {})),
            "data_lineage_tracking": dict(packet.output.get("data_lineage_tracking", {})),
            "structured_data_export": dict(packet.output.get("structured_data_export", {})),
            "data_quality_scoring": dict(packet.output.get("data_quality_scoring", {})),
        }
        packet.metrics["integration_intelligence"] = {
            "api_integration_layer": dict(packet.output.get("api_integration_layer", {})),
            "ehr_integration": dict(packet.output.get("ehr_integration", {})),
            "billing_system_integration": dict(packet.output.get("billing_system_integration", {})),
            "crm_integration": dict(packet.output.get("crm_integration", {})),
            "document_repository_sync": dict(packet.output.get("document_repository_sync", {})),
            "third_party_data_ingestion": dict(packet.output.get("third_party_data_ingestion", {})),
            "integration_health_monitoring": dict(packet.output.get("integration_health_monitoring", {})),
            "data_sync_conflict_resolution": dict(packet.output.get("data_sync_conflict_resolution", {})),
            "webhook_event_system": dict(packet.output.get("webhook_event_system", {})),
            "integration_security_controls": dict(packet.output.get("integration_security_controls", {})),
        }
        packet.metrics["security_intelligence"] = {
            "access_control_enforcement": dict(packet.output.get("access_control_enforcement", {})),
            "threat_detection_engine": dict(packet.output.get("threat_detection_engine", {})),
            "data_encryption_management": dict(packet.output.get("data_encryption_management", {})),
            "intrusion_detection_system": dict(packet.output.get("intrusion_detection_system", {})),
            "risk_assessment_engine": dict(packet.output.get("risk_assessment_engine", {})),
            "security_audit_logging": dict(packet.output.get("security_audit_logging", {})),
            "compliance_security_validation": dict(packet.output.get("compliance_security_validation", {})),
            "identity_verification_system": dict(packet.output.get("identity_verification_system", {})),
            "secure_data_sharing": dict(packet.output.get("secure_data_sharing", {})),
            "security_incident_response": dict(packet.output.get("security_incident_response", {})),
        }
        packet.metrics["ux_intelligence"] = {
            "adaptive_interface_engine": dict(packet.output.get("adaptive_interface_engine", {})),
            "smart_dashboard_generation": dict(packet.output.get("smart_dashboard_generation", {})),
            "workflow_visualization": dict(packet.output.get("workflow_visualization", {})),
            "user_behavior_tracking": dict(packet.output.get("user_behavior_tracking", {})),
            "interface_personalization": dict(packet.output.get("interface_personalization", {})),
            "guided_workflow_assistance": dict(packet.output.get("guided_workflow_assistance", {})),
            "error_prevention_ui": dict(packet.output.get("error_prevention_ui", {})),
            "feedback_capture_system": dict(packet.output.get("feedback_capture_system", {})),
            "ux_performance_metrics": dict(packet.output.get("ux_performance_metrics", {})),
            "continuous_ux_improvement": dict(packet.output.get("continuous_ux_improvement", {})),
        }
        packet.metrics["monitoring_intelligence"] = {
            "real_time_system_monitoring": dict(packet.output.get("real_time_system_monitoring", {})),
            "performance_metrics_dashboard": dict(packet.output.get("performance_metrics_dashboard", {})),
            "error_tracking_system": dict(packet.output.get("error_tracking_system", {})),
            "alerting_engine": dict(packet.output.get("alerting_engine", {})),
            "resource_usage_monitoring": dict(packet.output.get("resource_usage_monitoring", {})),
            "latency_tracking": dict(packet.output.get("latency_tracking", {})),
            "uptime_monitoring": dict(packet.output.get("uptime_monitoring", {})),
            "incident_detection": dict(packet.output.get("incident_detection", {})),
            "monitoring_analytics": dict(packet.output.get("monitoring_analytics", {})),
            "observability_integration": dict(packet.output.get("observability_integration", {})),
        }
        packet.metrics["simulation_intelligence"] = {
            "scenario_simulation_engine": dict(packet.output.get("scenario_simulation_engine", {})),
            "what_if_analysis_system": dict(packet.output.get("what_if_analysis_system", {})),
            "synthetic_data_generation": dict(packet.output.get("synthetic_data_generation", {})),
            "stress_testing_engine": dict(packet.output.get("stress_testing_engine", {})),
            "failure_simulation": dict(packet.output.get("failure_simulation", {})),
            "training_simulation_mode": dict(packet.output.get("training_simulation_mode", {})),
            "simulation_result_analysis": dict(packet.output.get("simulation_result_analysis", {})),
            "optimization_testing": dict(packet.output.get("optimization_testing", {})),
            "risk_simulation": dict(packet.output.get("risk_simulation", {})),
            "continuous_simulation_loop": dict(packet.output.get("continuous_simulation_loop", {})),
        }
        packet.metrics["autonomy_intelligence"] = {
            "fully_autonomous_packet_processing": dict(packet.output.get("fully_autonomous_packet_processing", {})),
            "self_healing_system": dict(packet.output.get("self_healing_system", {})),
            "autonomous_decision_engine": dict(packet.output.get("autonomous_decision_engine", {})),
            "dynamic_workflow_adjustment": dict(packet.output.get("dynamic_workflow_adjustment", {})),
            "self_optimization_loop": dict(packet.output.get("self_optimization_loop", {})),
            "autonomous_learning_system": dict(packet.output.get("autonomous_learning_system", {})),
            "autonomous_resource_allocation": dict(packet.output.get("autonomous_resource_allocation", {})),
            "self_monitoring_intelligence": dict(packet.output.get("self_monitoring_intelligence", {})),
            "autonomous_compliance_enforcement": dict(packet.output.get("autonomous_compliance_enforcement", {})),
            "autonomous_reporting_system": dict(packet.output.get("autonomous_reporting_system", {})),
        }
        packet.metrics["strategic_intelligence"] = {
            "executive_dashboard": dict(packet.output.get("executive_dashboard", {})),
            "strategic_decision_support": dict(packet.output.get("strategic_decision_support", {})),
            "roi_analysis_engine": dict(packet.output.get("roi_analysis_engine", {})),
            "growth_opportunity_detection": dict(packet.output.get("growth_opportunity_detection", {})),
            "competitive_benchmarking": dict(packet.output.get("competitive_benchmarking", {})),
            "strategic_forecasting": dict(packet.output.get("strategic_forecasting", {})),
            "operational_risk_analysis": dict(packet.output.get("operational_risk_analysis", {})),
            "investment_optimization": dict(packet.output.get("investment_optimization", {})),
            "performance_benchmarking": dict(packet.output.get("performance_benchmarking", {})),
            "strategic_planning_support": dict(packet.output.get("strategic_planning_support", {})),
        }

    def capture_corrections(self, packet):
        if packet.corrections:
            packet.metrics["has_corrections"] = True
