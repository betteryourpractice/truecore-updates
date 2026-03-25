class SimulationIntelligenceBuilder:
    SIMULATION_VERSION = "truecore_simulation_v1"
    SIMULATION_EFFECTIVE_DATE = "2026-03-24"

    def build(
        self,
        packet,
        submission_decision,
        decision_intelligence,
        predictive_intelligence,
        optimization_intelligence,
        compliance_intelligence,
        knowledge_intelligence,
        monitoring_intelligence,
    ):
        scenario_engine = self.build_scenario_simulation_engine(
            packet,
            submission_decision,
            decision_intelligence,
            predictive_intelligence,
            compliance_intelligence,
        )
        what_if = self.build_what_if_analysis_system(
            decision_intelligence,
            scenario_engine,
        )
        synthetic_data = self.build_synthetic_data_generation(
            packet,
            monitoring_intelligence,
        )
        stress_testing = self.build_stress_testing_engine(
            packet,
            predictive_intelligence,
            monitoring_intelligence,
        )
        failure_simulation = self.build_failure_simulation(
            packet,
            decision_intelligence,
            compliance_intelligence,
            monitoring_intelligence,
        )
        training_mode = self.build_training_simulation_mode(
            packet,
            submission_decision,
            what_if,
            failure_simulation,
        )
        optimization_testing = self.build_optimization_testing(
            decision_intelligence,
            optimization_intelligence,
            stress_testing,
        )
        risk_simulation = self.build_risk_simulation(
            packet,
            decision_intelligence,
            predictive_intelligence,
            monitoring_intelligence,
            failure_simulation,
        )
        result_analysis = self.build_simulation_result_analysis(
            scenario_engine,
            what_if,
            optimization_testing,
            risk_simulation,
        )
        continuous_loop = self.build_continuous_simulation_loop(
            packet,
            scenario_engine,
            stress_testing,
            risk_simulation,
            knowledge_intelligence,
        )

        return {
            "scenario_simulation_engine": scenario_engine,
            "what_if_analysis_system": what_if,
            "synthetic_data_generation": synthetic_data,
            "stress_testing_engine": stress_testing,
            "failure_simulation": failure_simulation,
            "training_simulation_mode": training_mode,
            "simulation_result_analysis": result_analysis,
            "optimization_testing": optimization_testing,
            "risk_simulation": risk_simulation,
            "continuous_simulation_loop": continuous_loop,
        }

    def build_scenario_simulation_engine(
        self,
        packet,
        submission_decision,
        decision_intelligence,
        predictive_intelligence,
        compliance_intelligence,
    ):
        baseline_readiness = submission_decision.get("readiness") or "requires_review"
        baseline_score = float(packet.packet_score or 0.0)
        baseline_risk = decision_intelligence.get("denial_risk_prediction", {}).get("level") or "moderate"
        scenarios = [
            {
                "name": "baseline_current_packet",
                "assumption": "Hold current packet conditions constant.",
                "projected_readiness": baseline_readiness,
                "projected_score": round(baseline_score, 2),
                "projected_risk": baseline_risk,
                "remediation_action": "maintain_current_state",
            }
        ]

        if packet.missing_documents or packet.missing_fields:
            projected_score = min(
                100.0,
                baseline_score + (8 * len(packet.missing_documents)) + (3 * len(packet.missing_fields)),
            )
            projected_readiness = "requires_review" if packet.conflicts else "ready"
            projected_risk = "low" if projected_readiness == "ready" else "moderate"
            scenarios.append({
                "name": "resolve_missing_evidence",
                "assumption": "Attach missing documents and verify missing fields.",
                "projected_readiness": projected_readiness,
                "projected_score": round(projected_score, 2),
                "projected_risk": projected_risk,
                "remediation_action": "attach_missing_document",
            })

        if packet.conflicts:
            highest_conflict = max(
                (conflict.get("severity") for conflict in packet.conflicts),
                default="medium",
                key=lambda value: {"low": 1, "medium": 2, "high": 3}.get(value, 0),
            )
            projected_score = min(100.0, baseline_score + (16 if highest_conflict == "high" else 9))
            scenarios.append({
                "name": "resolve_conflicts",
                "assumption": "Resolve identity, provider, or clinical conflicts across packet documents.",
                "projected_readiness": "requires_review" if packet.missing_documents else "ready",
                "projected_score": round(projected_score, 2),
                "projected_risk": "low" if highest_conflict != "high" else "moderate",
                "remediation_action": "resolve_conflict",
            })

        if (
            "weak_mri_justification" in packet.review_flags
            or "moderate_mri_justification" in packet.review_flags
            or "procedure_without_medical_support" in packet.review_flags
        ):
            projected_score = min(100.0, baseline_score + 7.0)
            scenarios.append({
                "name": "strengthen_clinical_support",
                "assumption": "Add stronger diagnosis, symptom, or procedure-support evidence.",
                "projected_readiness": "requires_review" if packet.missing_documents or packet.conflicts else "ready",
                "projected_score": round(projected_score, 2),
                "projected_risk": "low" if not packet.missing_documents else "moderate",
                "remediation_action": "strengthen_medical_support",
            })

        if compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status") == "non_compliant":
            projected_score = min(100.0, baseline_score + 10.0)
            scenarios.append({
                "name": "resolve_compliance_requirements",
                "assumption": "Resolve compliance blockers and missing requirement coverage.",
                "projected_readiness": "requires_review" if packet.conflicts else "ready",
                "projected_score": round(projected_score, 2),
                "projected_risk": "low" if not packet.conflicts else "moderate",
                "remediation_action": "resolve_compliance_issues",
            })

        return {
            "status": "simulated",
            "version": self.SIMULATION_VERSION,
            "effective_date": self.SIMULATION_EFFECTIVE_DATE,
            "baseline_readiness": baseline_readiness,
            "baseline_score": round(baseline_score, 2),
            "baseline_risk": baseline_risk,
            "scenario_count": len(scenarios),
            "scenarios": scenarios,
            "summary": "Simulation scenarios estimate how packet readiness changes when common blockers are resolved.",
        }

    def build_what_if_analysis_system(self, decision_intelligence, scenario_engine):
        scenarios = scenario_engine.get("scenarios", [])
        ranked = sorted(
            scenarios,
            key=lambda item: (
                {"ready": 2, "requires_review": 1, "hold": 0}.get(item.get("projected_readiness"), 0),
                float(item.get("projected_score") or 0.0),
            ),
            reverse=True,
        )
        best = ranked[0] if ranked else {}
        baseline = scenarios[0] if scenarios else {}
        next_action = decision_intelligence.get("recommended_next_action", {})

        return {
            "status": "analyzed",
            "best_scenario": best.get("name"),
            "best_action": best.get("remediation_action") or next_action.get("action"),
            "projected_readiness": best.get("projected_readiness"),
            "projected_score_gain": round(
                float(best.get("projected_score") or 0.0) - float(baseline.get("projected_score") or 0.0),
                2,
            ),
            "summary": (
                f"Best simulated next move is {best.get('remediation_action') or next_action.get('action') or 'hold_for_review'}."
            ),
        }

    def build_synthetic_data_generation(self, packet, monitoring_intelligence):
        docs = sorted(packet.detected_documents or [])
        fields = sorted((packet.fields or {}).keys())
        return {
            "status": "ready",
            "fixture_profile": "masked_packet_profile",
            "page_count": len(packet.pages or []),
            "document_count": len(docs),
            "field_count": len(fields),
            "masked_document_types": docs,
            "masked_field_names": fields[:20],
            "resource_level": monitoring_intelligence.get("resource_usage_monitoring", {}).get("level"),
            "summary": "Synthetic scenario generation uses masked packet structure rather than live protected values.",
        }

    def build_stress_testing_engine(self, packet, predictive_intelligence, monitoring_intelligence):
        complexity = predictive_intelligence.get("case_complexity_scoring", {}).get("level")
        resource_level = monitoring_intelligence.get("resource_usage_monitoring", {}).get("level")
        load_score = (
            len(packet.pages or [])
            + (len(packet.conflicts or []) * 3)
            + (len(packet.missing_documents or []) * 4)
            + (len(packet.duplicate_pages or []) * 2)
        )

        if load_score >= 90 or complexity == "critical" or resource_level == "heavy":
            level = "extreme"
        elif load_score >= 45 or complexity == "high":
            level = "high"
        elif load_score >= 18:
            level = "moderate"
        else:
            level = "low"

        return {
            "status": "tested",
            "level": level,
            "load_score": load_score,
            "test_profiles": [
                "baseline_packet_load",
                "duplicate_page_pressure",
                "low_confidence_page_mix",
                "high_conflict_resolution_pass",
            ],
            "summary": f"Stress testing rates this packet profile as {level} load.",
        }

    def build_failure_simulation(self, packet, decision_intelligence, compliance_intelligence, monitoring_intelligence):
        failure_modes = []
        if packet.missing_documents:
            failure_modes.append("missing_required_documents")
        if packet.missing_fields:
            failure_modes.append("missing_required_fields")
        if packet.conflicts:
            failure_modes.append("cross_document_conflicts")
        if "packet_integrity_risk" in packet.review_flags:
            failure_modes.append("identity_integrity_risk")
        if compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status") == "non_compliant":
            failure_modes.append("compliance_failure")
        if monitoring_intelligence.get("incident_detection", {}).get("status") == "incident":
            failure_modes.append("operational_incident")
        if decision_intelligence.get("denial_risk_prediction", {}).get("level") in {"high", "critical"}:
            failure_modes.append("high_denial_risk")

        highest = failure_modes[0] if failure_modes else None
        return {
            "status": "modeled",
            "failure_count": len(failure_modes),
            "failure_modes": failure_modes,
            "highest_risk_failure": highest,
            "summary": (
                "No major failure modes dominate this packet."
                if not failure_modes else
                "Failure simulation highlights the current dominant packet breakdown risks."
            ),
        }

    def build_training_simulation_mode(self, packet, submission_decision, what_if_analysis, failure_simulation):
        if submission_decision.get("readiness") == "ready" and not failure_simulation.get("failure_modes"):
            mode = "reference_review"
        elif submission_decision.get("readiness") == "hold":
            mode = "guided_recovery"
        else:
            mode = "correction_drill"

        return {
            "status": "available",
            "mode": mode,
            "recommended_exercise": what_if_analysis.get("best_action"),
            "training_modules": [
                "missing_evidence_resolution",
                "cross_document_conflict_review",
                "submission_readiness_decisioning",
            ],
            "summary": f"Training simulation mode is set to {mode} for this packet state.",
        }

    def build_optimization_testing(self, decision_intelligence, optimization_intelligence, stress_testing):
        runtime_profile = optimization_intelligence.get("continuous_performance_tuning", {}).get("runtime_profile", {})
        throughput_lane = optimization_intelligence.get("throughput_optimization", {}).get("processing_lane")
        best_action = decision_intelligence.get("recommended_next_action", {}).get("action")

        return {
            "status": "tested",
            "processing_lane": throughput_lane,
            "runtime_profile": runtime_profile,
            "best_action_under_load": best_action,
            "stress_level": stress_testing.get("level"),
            "expected_throughput_effect": (
                "maintain_fast_lane" if stress_testing.get("level") in {"low", "moderate"} else "shift_to_review_lane"
            ),
            "summary": "Optimization testing evaluates whether routing and runtime tuning remain stable under simulated load.",
        }

    def build_risk_simulation(
        self,
        packet,
        decision_intelligence,
        predictive_intelligence,
        monitoring_intelligence,
        failure_simulation,
    ):
        risk_level = decision_intelligence.get("denial_risk_prediction", {}).get("level") or "moderate"
        monitoring_status = monitoring_intelligence.get("real_time_system_monitoring", {}).get("status")
        complexity = predictive_intelligence.get("case_complexity_scoring", {}).get("level")

        simulation_score = 0
        simulation_score += {"low": 1, "moderate": 2, "high": 3, "critical": 4}.get(risk_level, 2)
        simulation_score += {"healthy": 0, "watch": 1, "degraded": 2, "incident": 3}.get(monitoring_status, 1)
        simulation_score += {"low": 0, "moderate": 1, "high": 2, "critical": 3}.get(complexity, 1)
        simulation_score += min(3, len(failure_simulation.get("failure_modes", [])))

        if simulation_score >= 9:
            level = "critical"
        elif simulation_score >= 6:
            level = "high"
        elif simulation_score >= 3:
            level = "moderate"
        else:
            level = "low"

        return {
            "status": "simulated",
            "level": level,
            "risk_score": simulation_score,
            "dominant_failure_mode": failure_simulation.get("highest_risk_failure"),
            "summary": f"Risk simulation projects a {level} future risk state if current issues persist.",
        }

    def build_simulation_result_analysis(self, scenario_engine, what_if_analysis, optimization_testing, risk_simulation):
        scenarios = scenario_engine.get("scenarios", [])
        ready_count = sum(1 for item in scenarios if item.get("projected_readiness") == "ready")

        return {
            "status": "summarized",
            "scenario_count": len(scenarios),
            "ready_outcome_count": ready_count,
            "best_action": what_if_analysis.get("best_action"),
            "optimization_effect": optimization_testing.get("expected_throughput_effect"),
            "risk_level": risk_simulation.get("level"),
            "summary": "Simulation analysis compares baseline conditions with improved scenarios and expected operating effects.",
        }

    def build_continuous_simulation_loop(
        self,
        packet,
        scenario_engine,
        stress_testing,
        risk_simulation,
        knowledge_intelligence,
    ):
        recommended_scenarios = ["baseline_current_packet"]
        for scenario in scenario_engine.get("scenarios", [])[1:]:
            recommended_scenarios.append(scenario.get("name"))

        if knowledge_intelligence.get("case_based_reasoning_engine", {}).get("archetype"):
            recommended_scenarios.append("knowledge_archetype_regression")
        if stress_testing.get("level") in {"high", "extreme"}:
            recommended_scenarios.append("high_load_regression")
        if risk_simulation.get("level") in {"high", "critical"}:
            cadence = "every_run"
        elif packet.needs_review:
            cadence = "daily"
        else:
            cadence = "weekly"

        deduped = []
        seen = set()
        for item in recommended_scenarios:
            if not item or item in seen:
                continue
            seen.add(item)
            deduped.append(item)

        return {
            "status": "active",
            "cadence": cadence,
            "recommended_scenarios": deduped,
            "scenario_count": len(deduped),
            "summary": "Continuous simulation keeps high-signal packet scenarios in the regression loop.",
        }
