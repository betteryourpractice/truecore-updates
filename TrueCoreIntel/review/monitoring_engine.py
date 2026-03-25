class MonitoringIntelligenceBuilder:
    MONITORING_VERSION = "truecore_monitoring_v1"
    MONITORING_EFFECTIVE_DATE = "2026-03-24"

    def build(
        self,
        packet,
        submission_decision,
        decision_intelligence,
        predictive_intelligence,
        optimization_intelligence,
        compliance_intelligence,
        integration_intelligence,
        security_intelligence,
    ):
        real_time_monitoring = self.build_real_time_system_monitoring(
            packet,
            submission_decision,
            predictive_intelligence,
            compliance_intelligence,
            integration_intelligence,
            security_intelligence,
        )
        performance_dashboard = self.build_performance_metrics_dashboard(
            packet,
            submission_decision,
            predictive_intelligence,
            optimization_intelligence,
            real_time_monitoring,
        )
        error_tracking = self.build_error_tracking_system(
            packet,
            compliance_intelligence,
            integration_intelligence,
            security_intelligence,
            real_time_monitoring,
        )
        alerting = self.build_alerting_engine(
            packet,
            decision_intelligence,
            predictive_intelligence,
            security_intelligence,
            real_time_monitoring,
            error_tracking,
        )
        resource_usage = self.build_resource_usage_monitoring(
            packet,
            optimization_intelligence,
            real_time_monitoring,
        )
        latency_tracking = self.build_latency_tracking(
            predictive_intelligence,
            optimization_intelligence,
            resource_usage,
            error_tracking,
        )
        uptime = self.build_uptime_monitoring(
            real_time_monitoring,
            security_intelligence,
            alerting,
        )
        incident_detection = self.build_incident_detection(
            real_time_monitoring,
            security_intelligence,
            alerting,
            error_tracking,
        )
        analytics = self.build_monitoring_analytics(
            real_time_monitoring,
            error_tracking,
            alerting,
            resource_usage,
            latency_tracking,
            incident_detection,
        )
        observability = self.build_observability_integration(
            alerting,
            incident_detection,
            analytics,
        )

        return {
            "real_time_system_monitoring": real_time_monitoring,
            "performance_metrics_dashboard": performance_dashboard,
            "error_tracking_system": error_tracking,
            "alerting_engine": alerting,
            "resource_usage_monitoring": resource_usage,
            "latency_tracking": latency_tracking,
            "uptime_monitoring": uptime,
            "incident_detection": incident_detection,
            "monitoring_analytics": analytics,
            "observability_integration": observability,
        }

    def build_real_time_system_monitoring(
        self,
        packet,
        submission_decision,
        predictive_intelligence,
        compliance_intelligence,
        integration_intelligence,
        security_intelligence,
    ):
        health_score = 0.94
        signals = []
        readiness = submission_decision.get("readiness") or "requires_review"
        compliance_status = compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status")
        integration_status = integration_intelligence.get("integration_health_monitoring", {}).get("status")
        threat_level = security_intelligence.get("threat_detection_engine", {}).get("level")
        complexity = predictive_intelligence.get("case_complexity_scoring", {}).get("level")
        low_confidence_pages = sum(
            1
            for confidence in (packet.page_confidence or {}).values()
            if isinstance(confidence, (int, float)) and confidence < 0.72
        )

        if readiness == "hold":
            health_score -= 0.18
            signals.append("submission_hold")
        elif readiness == "requires_review":
            health_score -= 0.08
            signals.append("review_queue")

        if compliance_status == "non_compliant":
            health_score -= 0.18
            signals.append("compliance_non_compliant")
        elif compliance_status and compliance_status != "compliant":
            health_score -= 0.08
            signals.append("compliance_watch")

        if integration_status == "degraded":
            health_score -= 0.18
            signals.append("integration_degraded")
        elif integration_status == "watch":
            health_score -= 0.08
            signals.append("integration_watch")

        if threat_level in {"critical", "elevated"}:
            health_score -= 0.22
            signals.append("security_alert")
        elif threat_level == "watch":
            health_score -= 0.10
            signals.append("security_watch")

        if complexity in {"high", "critical"}:
            health_score -= 0.06
            signals.append("complex_case")

        if low_confidence_pages:
            health_score -= min(0.12, low_confidence_pages * 0.03)
            signals.append("low_confidence_pages")

        if packet.conflicts:
            health_score -= min(0.12, len(packet.conflicts) * 0.03)
            signals.append("packet_conflicts")

        if packet.duplicate_pages:
            health_score -= min(0.08, len(packet.duplicate_pages) * 0.02)
            signals.append("duplicate_pages")

        health_score = round(max(0.05, min(health_score, 0.99)), 2)
        if health_score >= 0.82:
            status = "healthy"
        elif health_score >= 0.6:
            status = "watch"
        elif health_score >= 0.35:
            status = "degraded"
        else:
            status = "incident"

        return {
            "status": status,
            "version": self.MONITORING_VERSION,
            "effective_date": self.MONITORING_EFFECTIVE_DATE,
            "health_score": health_score,
            "health_band": status,
            "low_confidence_page_count": low_confidence_pages,
            "page_count": len(packet.pages or []),
            "signal_count": len(signals),
            "signals": signals,
            "summary": (
                "System health is stable for this packet."
                if status == "healthy" else
                "System health should be watched while this packet is processed."
                if status == "watch" else
                "System health is degraded enough to justify closer operational attention."
                if status == "degraded" else
                "System health is degraded into incident territory and needs intervention."
            ),
        }

    def build_performance_metrics_dashboard(
        self,
        packet,
        submission_decision,
        predictive_intelligence,
        optimization_intelligence,
        real_time_monitoring,
    ):
        cards = [
            {"metric": "packet_score", "value": packet.packet_score, "priority": "high"},
            {"metric": "packet_confidence", "value": packet.packet_confidence, "priority": "high"},
            {"metric": "submission_readiness", "value": submission_decision.get("readiness"), "priority": "high"},
            {
                "metric": "turnaround_hours",
                "value": predictive_intelligence.get("turnaround_time_prediction", {}).get("estimated_final_decision_hours"),
                "priority": "medium",
            },
            {
                "metric": "processing_minutes",
                "value": optimization_intelligence.get("processing_speed_optimization", {}).get("estimated_processing_minutes"),
                "priority": "medium",
            },
            {
                "metric": "system_health",
                "value": real_time_monitoring.get("status"),
                "priority": "high",
            },
        ]

        return {
            "status": "available",
            "card_count": len(cards),
            "cards": cards,
            "headline_metric": cards[0],
            "summary": "Performance metrics highlight readiness, confidence, timing, and live operational health.",
        }

    def build_error_tracking_system(
        self,
        packet,
        compliance_intelligence,
        integration_intelligence,
        security_intelligence,
        real_time_monitoring,
    ):
        errors = []

        for field in packet.missing_fields:
            errors.append({"type": "missing_field", "target": field, "severity": "medium"})
        for doc in packet.missing_documents:
            errors.append({"type": "missing_document", "target": doc, "severity": "high"})
        for conflict in packet.conflicts:
            errors.append({
                "type": conflict.get("type") or "conflict",
                "target": conflict.get("field") or "packet",
                "severity": conflict.get("severity") or "medium",
            })

        if compliance_intelligence.get("compliance_validation_checks", {}).get("overall_status") == "non_compliant":
            errors.append({"type": "compliance", "target": "packet", "severity": "high"})
        if integration_intelligence.get("integration_health_monitoring", {}).get("status") == "degraded":
            errors.append({"type": "integration", "target": "workflow_sync", "severity": "high"})
        if security_intelligence.get("security_incident_response", {}).get("status") == "escalated":
            errors.append({"type": "security", "target": "packet", "severity": "high"})
        if real_time_monitoring.get("status") == "incident":
            errors.append({"type": "monitoring", "target": "system_health", "severity": "high"})

        high_count = sum(1 for item in errors if item.get("severity") == "high")
        if high_count:
            status = "error"
        elif errors:
            status = "watch"
        else:
            status = "clear"

        return {
            "status": status,
            "error_count": len(errors),
            "high_severity_count": high_count,
            "errors": errors[:25],
            "summary": (
                "No material processing errors are active for this packet."
                if status == "clear" else
                "Processing errors are present and should be monitored."
                if status == "watch" else
                "Processing errors are material enough to require active intervention."
            ),
        }

    def build_alerting_engine(
        self,
        packet,
        decision_intelligence,
        predictive_intelligence,
        security_intelligence,
        real_time_monitoring,
        error_tracking,
    ):
        alerts = []

        if real_time_monitoring.get("status") in {"degraded", "incident"}:
            alerts.append({"code": "system_health", "severity": "high", "message": real_time_monitoring.get("summary")})
        if error_tracking.get("high_severity_count", 0):
            alerts.append({"code": "processing_errors", "severity": "high", "message": "High-severity packet processing issues were detected."})
        if security_intelligence.get("security_incident_response", {}).get("status") == "escalated":
            alerts.append({"code": "security_incident", "severity": "critical", "message": "Security controls escalated packet handling."})
        if predictive_intelligence.get("predictive_escalation", {}).get("escalate"):
            alerts.append({"code": "predictive_escalation", "severity": "high", "message": "Predictive escalation expects future downstream problems."})
        if decision_intelligence.get("workflow_decision_routing", {}).get("queue") == "senior_review_queue":
            alerts.append({"code": "senior_review", "severity": "high", "message": "Packet is routed to senior review."})
        if packet.review_priority == "high":
            alerts.append({"code": "priority_high", "severity": "watch", "message": "Packet review priority is high."})

        severity_order = {"none": 0, "watch": 1, "high": 2, "critical": 3}
        severity = "none"
        for alert in alerts:
            if severity_order[alert["severity"]] > severity_order[severity]:
                severity = alert["severity"]

        return {
            "status": "active" if alerts else "quiet",
            "severity": severity,
            "alert_count": len(alerts),
            "alerts": alerts,
            "destinations": ["local_event_log", "review_dashboard", "workflow_bridge"],
            "escalate": severity in {"high", "critical"},
            "summary": (
                "No operational alerts are active."
                if not alerts else
                "Operational alerts should be surfaced to staff handling this packet."
            ),
        }

    def build_resource_usage_monitoring(self, packet, optimization_intelligence, real_time_monitoring):
        page_count = len(packet.pages or [])
        duplicate_count = len(packet.duplicate_pages or [])
        low_confidence_pages = real_time_monitoring.get("low_confidence_page_count", 0)
        estimated_memory_mb = int(40 + (page_count * 6) + (low_confidence_pages * 4) + (duplicate_count * 2))

        load_score = page_count + (low_confidence_pages * 2) + duplicate_count
        if load_score >= 80:
            level = "heavy"
        elif load_score >= 35:
            level = "elevated"
        else:
            level = "standard"

        return {
            "status": "tracked",
            "level": level,
            "page_count": page_count,
            "duplicate_page_count": duplicate_count,
            "low_confidence_page_count": low_confidence_pages,
            "estimated_memory_mb": estimated_memory_mb,
            "processing_lane": optimization_intelligence.get("throughput_optimization", {}).get("processing_lane"),
            "summary": f"Resource usage is {level} for this packet profile.",
        }

    def build_latency_tracking(
        self,
        predictive_intelligence,
        optimization_intelligence,
        resource_usage,
        error_tracking,
    ):
        estimated_processing_minutes = float(
            optimization_intelligence.get("processing_speed_optimization", {}).get("estimated_processing_minutes") or 0.0
        )
        turnaround_hours = float(
            predictive_intelligence.get("turnaround_time_prediction", {}).get("estimated_final_decision_hours") or 0.0
        )

        if estimated_processing_minutes >= 20 or turnaround_hours >= 96 or error_tracking.get("high_severity_count", 0) >= 2:
            band = "high"
        elif estimated_processing_minutes >= 10 or turnaround_hours >= 48 or resource_usage.get("level") == "heavy":
            band = "elevated"
        elif estimated_processing_minutes >= 5 or turnaround_hours >= 24:
            band = "standard"
        else:
            band = "low"

        return {
            "status": "measured",
            "band": band,
            "estimated_processing_minutes": round(estimated_processing_minutes, 2),
            "estimated_final_decision_hours": round(turnaround_hours, 2),
            "summary": f"Latency tracking places this packet in the {band} latency band.",
        }

    def build_uptime_monitoring(self, real_time_monitoring, security_intelligence, alerting):
        if security_intelligence.get("security_incident_response", {}).get("status") == "escalated":
            status = "degraded"
            availability = 99.1
        elif real_time_monitoring.get("status") == "incident" or alerting.get("severity") == "critical":
            status = "degraded"
            availability = 99.2
        elif real_time_monitoring.get("status") == "degraded":
            status = "watch"
            availability = 99.6
        else:
            status = "available"
            availability = 99.95

        return {
            "status": status,
            "availability_percent": availability,
            "window": "rolling_local_runtime",
            "summary": (
                "System uptime is stable."
                if status == "available" else
                "System uptime should be watched because packet conditions are stressing handling."
                if status == "watch" else
                "System uptime is degraded for this packet context and needs attention."
            ),
        }

    def build_incident_detection(self, real_time_monitoring, security_intelligence, alerting, error_tracking):
        security_incident = security_intelligence.get("security_incident_response", {}).get("status")

        if security_incident == "escalated" or alerting.get("severity") == "critical":
            status = "incident"
        elif real_time_monitoring.get("status") == "degraded" or error_tracking.get("high_severity_count", 0):
            status = "degraded"
        elif alerting.get("alert_count", 0):
            status = "monitoring"
        else:
            status = "standby"

        return {
            "status": status,
            "security_status": security_incident,
            "alert_count": alerting.get("alert_count", 0),
            "error_count": error_tracking.get("error_count", 0),
            "summary": (
                "No monitoring incident is active."
                if status == "standby" else
                "Monitoring is active for emerging issues."
                if status == "monitoring" else
                "A material monitoring incident signal is present."
            ),
        }

    def build_monitoring_analytics(
        self,
        real_time_monitoring,
        error_tracking,
        alerting,
        resource_usage,
        latency_tracking,
        incident_detection,
    ):
        if incident_detection.get("status") == "incident":
            trend = "critical"
        elif real_time_monitoring.get("status") == "degraded" or latency_tracking.get("band") == "high":
            trend = "stressed"
        elif alerting.get("alert_count", 0) or error_tracking.get("error_count", 0):
            trend = "rising"
        else:
            trend = "stable"

        return {
            "status": "analyzed",
            "trend": trend,
            "signal_summary": {
                "alerts": alerting.get("alert_count", 0),
                "errors": error_tracking.get("error_count", 0),
                "resource_level": resource_usage.get("level"),
                "latency_band": latency_tracking.get("band"),
                "incident_status": incident_detection.get("status"),
            },
            "summary": f"Monitoring analytics currently show a {trend} operating pattern.",
        }

    def build_observability_integration(self, alerting, incident_detection, analytics):
        components = [
            "local_event_log",
            "workflow_bridge",
            "review_dashboard",
            "learning_feedback",
        ]
        if alerting.get("alert_count", 0):
            components.append("alert_artifacts")
        if incident_detection.get("status") in {"degraded", "incident"}:
            components.append("incident_tracking")

        return {
            "status": "integrated",
            "components": components,
            "component_count": len(components),
            "analytics_trend": analytics.get("trend"),
            "summary": "Observability signals are combined across local logs, dashboard views, workflow exports, and feedback snapshots.",
        }
