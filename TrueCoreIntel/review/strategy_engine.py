class StrategicIntelligenceBuilder:
    STRATEGY_VERSION = "truecore_strategy_v1"
    STRATEGY_EFFECTIVE_DATE = "2026-03-24"

    def build(
        self,
        packet,
        decision_intelligence,
        predictive_intelligence,
        optimization_intelligence,
        compliance_intelligence,
        monitoring_intelligence,
        autonomy_intelligence,
    ):
        executive_dashboard = self.build_executive_dashboard(
            packet,
            decision_intelligence,
            predictive_intelligence,
            optimization_intelligence,
            compliance_intelligence,
            monitoring_intelligence,
            autonomy_intelligence,
        )
        decision_support = self.build_strategic_decision_support(
            decision_intelligence,
            predictive_intelligence,
            autonomy_intelligence,
        )
        roi_analysis = self.build_roi_analysis_engine(
            packet,
            predictive_intelligence,
            optimization_intelligence,
            autonomy_intelligence,
        )
        growth_detection = self.build_growth_opportunity_detection(
            packet,
            predictive_intelligence,
            optimization_intelligence,
            autonomy_intelligence,
        )
        competitive_benchmarking = self.build_competitive_benchmarking(
            packet,
            decision_intelligence,
            predictive_intelligence,
            compliance_intelligence,
        )
        strategic_forecasting = self.build_strategic_forecasting(
            predictive_intelligence,
            optimization_intelligence,
            monitoring_intelligence,
        )
        operational_risk = self.build_operational_risk_analysis(
            decision_intelligence,
            compliance_intelligence,
            monitoring_intelligence,
            autonomy_intelligence,
        )
        investment_optimization = self.build_investment_optimization(
            predictive_intelligence,
            optimization_intelligence,
            monitoring_intelligence,
            operational_risk,
        )
        performance_benchmarking = self.build_performance_benchmarking(
            packet,
            predictive_intelligence,
            compliance_intelligence,
            monitoring_intelligence,
        )
        planning_support = self.build_strategic_planning_support(
            decision_support,
            growth_detection,
            strategic_forecasting,
            investment_optimization,
            operational_risk,
        )

        return {
            "executive_dashboard": executive_dashboard,
            "strategic_decision_support": decision_support,
            "roi_analysis_engine": roi_analysis,
            "growth_opportunity_detection": growth_detection,
            "competitive_benchmarking": competitive_benchmarking,
            "strategic_forecasting": strategic_forecasting,
            "operational_risk_analysis": operational_risk,
            "investment_optimization": investment_optimization,
            "performance_benchmarking": performance_benchmarking,
            "strategic_planning_support": planning_support,
        }

    def build_executive_dashboard(
        self,
        packet,
        decision_intelligence,
        predictive_intelligence,
        optimization_intelligence,
        compliance_intelligence,
        monitoring_intelligence,
        autonomy_intelligence,
    ):
        return {
            "status": "available",
            "version": self.STRATEGY_VERSION,
            "effective_date": self.STRATEGY_EFFECTIVE_DATE,
            "headline_cards": [
                {"metric": "packet_score", "value": packet.packet_score},
                {"metric": "approval_probability", "value": packet.approval_probability},
                {"metric": "denial_risk", "value": decision_intelligence.get("denial_risk_prediction", {}).get("level")},
                {"metric": "turnaround_band", "value": predictive_intelligence.get("turnaround_time_prediction", {}).get("band")},
                {"metric": "throughput_lane", "value": optimization_intelligence.get("throughput_optimization", {}).get("processing_lane")},
                {"metric": "compliance_status", "value": compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status")},
                {"metric": "system_health", "value": monitoring_intelligence.get("real_time_system_monitoring", {}).get("status")},
                {"metric": "autonomy_status", "value": autonomy_intelligence.get("fully_autonomous_packet_processing", {}).get("status")},
            ],
            "summary": "Executive dashboard condenses packet quality, operational pressure, compliance, monitoring, and autonomy into one view.",
        }

    def build_strategic_decision_support(
        self,
        decision_intelligence,
        predictive_intelligence,
        autonomy_intelligence,
    ):
        denial_risk = decision_intelligence.get("denial_risk_prediction", {}).get("level")
        autonomy_status = autonomy_intelligence.get("fully_autonomous_packet_processing", {}).get("status")
        turnaround_band = predictive_intelligence.get("turnaround_time_prediction", {}).get("band")

        if autonomy_status == "autonomous_ready" and denial_risk == "low":
            action = "expand_autonomous_submission_lane"
        elif denial_risk in {"high", "critical"}:
            action = "tighten_pre_submission_controls"
        elif turnaround_band in {"three_to_seven_days", "over_one_week"}:
            action = "invest_in_correction_capacity"
        else:
            action = "maintain_current_operating_model"

        return {
            "status": "advisory",
            "recommended_action": action,
            "reason": decision_intelligence.get("recommended_next_action", {}).get("reason"),
            "summary": "Strategic decision support recommends the operating move that best fits packet risk, autonomy, and timing pressure.",
        }

    def build_roi_analysis_engine(
        self,
        packet,
        predictive_intelligence,
        optimization_intelligence,
        autonomy_intelligence,
    ):
        approval_probability = float(packet.approval_probability or 0.0)
        throughput_lane = optimization_intelligence.get("throughput_optimization", {}).get("processing_lane")
        autonomy_status = autonomy_intelligence.get("fully_autonomous_packet_processing", {}).get("status")
        turnaround_hours = float(
            predictive_intelligence.get("turnaround_time_prediction", {}).get("estimated_final_decision_hours") or 0.0
        )

        roi_score = approval_probability * 100
        if autonomy_status == "autonomous_ready":
            roi_score += 12
        if throughput_lane == "submission_fast_lane":
            roi_score += 8
        if turnaround_hours >= 96:
            roi_score -= 16
        elif turnaround_hours >= 48:
            roi_score -= 8

        roi_score = round(max(0.0, min(roi_score, 100.0)), 2)
        if roi_score >= 80:
            band = "strong"
        elif roi_score >= 60:
            band = "moderate"
        else:
            band = "weak"

        return {
            "status": "modeled",
            "roi_score": roi_score,
            "band": band,
            "value_driver": throughput_lane or "standard_lane",
            "summary": "ROI analysis weighs approval likelihood, lane efficiency, and turnaround drag to estimate packet operating value.",
        }

    def build_growth_opportunity_detection(
        self,
        packet,
        predictive_intelligence,
        optimization_intelligence,
        autonomy_intelligence,
    ):
        volume_band = predictive_intelligence.get("volume_trend_prediction", {}).get("band")
        autonomy_status = autonomy_intelligence.get("fully_autonomous_packet_processing", {}).get("status")
        quality_signal = "strong_quality" if packet.packet_strength == "strong" else "needs_quality_lift"

        if autonomy_status == "autonomous_ready" and packet.packet_strength == "strong":
            opportunity = "scale_high_quality_office_intake"
        elif volume_band in {"elevated", "high"}:
            opportunity = "expand_processing_capacity"
        else:
            opportunity = "target_quality_and_training_uplift"

        return {
            "status": "detected",
            "opportunity": opportunity,
            "quality_signal": quality_signal,
            "throughput_lane": optimization_intelligence.get("throughput_optimization", {}).get("processing_lane"),
            "summary": "Growth opportunities are derived from packet quality, autonomy readiness, and projected intake pressure.",
        }

    def build_competitive_benchmarking(
        self,
        packet,
        decision_intelligence,
        predictive_intelligence,
        compliance_intelligence,
    ):
        score = float(packet.packet_score or 0.0)
        denial_risk = decision_intelligence.get("denial_risk_prediction", {}).get("level")
        approval_forecast = predictive_intelligence.get("approval_outcome_prediction", {}).get("level")
        compliance_status = compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status")

        if score >= 92 and denial_risk == "low" and compliance_status == "compliant":
            position = "top_quartile"
        elif score >= 75 and approval_forecast not in {"unlikely", "very_unlikely"}:
            position = "competitive"
        else:
            position = "below_target"

        return {
            "status": "benchmarked",
            "position": position,
            "benchmark_basis": "deterministic_internal_target_proxy_v1",
            "summary": "Competitive benchmarking compares packet quality and risk against deterministic operational targets.",
        }

    def build_strategic_forecasting(
        self,
        predictive_intelligence,
        optimization_intelligence,
        monitoring_intelligence,
    ):
        volume_band = predictive_intelligence.get("volume_trend_prediction", {}).get("band")
        staffing_level = predictive_intelligence.get("staffing_demand_forecasting", {}).get("level")
        monitoring_trend = monitoring_intelligence.get("monitoring_analytics", {}).get("trend")
        throughput_lane = optimization_intelligence.get("throughput_optimization", {}).get("processing_lane")

        if volume_band == "high" or staffing_level == "high":
            horizon = "growth_pressure"
        elif monitoring_trend in {"stressed", "critical"}:
            horizon = "stability_pressure"
        else:
            horizon = "steady_state"

        return {
            "status": "forecasted",
            "horizon": horizon,
            "volume_band": volume_band,
            "staffing_level": staffing_level,
            "throughput_lane": throughput_lane,
            "summary": "Strategic forecasting projects medium-term operating posture from volume, staffing, throughput, and monitoring signals.",
        }

    def build_operational_risk_analysis(
        self,
        decision_intelligence,
        compliance_intelligence,
        monitoring_intelligence,
        autonomy_intelligence,
    ):
        denial_risk = decision_intelligence.get("denial_risk_prediction", {}).get("level")
        compliance_risk = compliance_intelligence.get("compliance_risk_scoring", {}).get("level")
        monitoring_status = monitoring_intelligence.get("incident_detection", {}).get("status")
        autonomy_status = autonomy_intelligence.get("fully_autonomous_packet_processing", {}).get("status")

        risk_score = 0
        risk_score += {"low": 1, "moderate": 2, "high": 3, "critical": 4}.get(denial_risk, 2)
        risk_score += {"low": 1, "moderate": 2, "high": 3, "critical": 4}.get(compliance_risk, 2)
        risk_score += {"standby": 0, "monitoring": 1, "degraded": 2, "incident": 3}.get(monitoring_status, 1)
        risk_score += {"autonomous_ready": 0, "supervised_autonomy": 1, "blocked": 2}.get(autonomy_status, 1)

        if risk_score >= 10:
            level = "critical"
        elif risk_score >= 7:
            level = "high"
        elif risk_score >= 4:
            level = "moderate"
        else:
            level = "low"

        return {
            "status": "assessed",
            "level": level,
            "risk_score": risk_score,
            "summary": "Operational risk combines denial, compliance, monitoring, and autonomy constraints into one enterprise risk signal.",
        }

    def build_investment_optimization(
        self,
        predictive_intelligence,
        optimization_intelligence,
        monitoring_intelligence,
        operational_risk,
    ):
        bottleneck = predictive_intelligence.get("bottleneck_detection", {}).get("primary_stage")
        monitoring_trend = monitoring_intelligence.get("monitoring_analytics", {}).get("trend")
        risk_level = operational_risk.get("level")

        if risk_level in {"high", "critical"}:
            priority = "risk_reduction"
        elif bottleneck in {"document_collection", "conflict_resolution"}:
            priority = "correction_capacity"
        elif monitoring_trend in {"stressed", "critical"}:
            priority = "observability_and_runtime"
        else:
            priority = "automation_scale"

        return {
            "status": "optimized",
            "priority": priority,
            "target_stage": bottleneck,
            "summary": "Investment optimization prioritizes spending where packet risk, bottlenecks, and monitoring strain are highest.",
        }

    def build_performance_benchmarking(
        self,
        packet,
        predictive_intelligence,
        compliance_intelligence,
        monitoring_intelligence,
    ):
        score = float(packet.packet_score or 0.0)
        turnaround_band = predictive_intelligence.get("turnaround_time_prediction", {}).get("band")
        compliance_status = compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status")
        health = monitoring_intelligence.get("real_time_system_monitoring", {}).get("status")

        if score >= 90 and compliance_status == "compliant" and health in {"healthy", "watch"}:
            benchmark = "above_target"
        elif score >= 75 and turnaround_band != "over_one_week":
            benchmark = "on_target"
        else:
            benchmark = "below_target"

        return {
            "status": "benchmarked",
            "benchmark": benchmark,
            "turnaround_band": turnaround_band,
            "summary": "Performance benchmarking compares quality, compliance, and timing against deterministic operating targets.",
        }

    def build_strategic_planning_support(
        self,
        decision_support,
        growth_detection,
        strategic_forecasting,
        investment_optimization,
        operational_risk,
    ):
        initiatives = [
            decision_support.get("recommended_action"),
            growth_detection.get("opportunity"),
            investment_optimization.get("priority"),
        ]
        initiatives = [item for item in initiatives if item]

        return {
            "status": "planned",
            "planning_horizon": strategic_forecasting.get("horizon"),
            "operational_risk_level": operational_risk.get("level"),
            "initiatives": initiatives,
            "summary": "Strategic planning support translates current operating signals into near-term planning priorities.",
        }
