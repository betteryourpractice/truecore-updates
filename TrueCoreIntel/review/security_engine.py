from statistics import mean


class SecurityIntelligenceBuilder:
    SECURITY_VERSION = "truecore_security_v1"
    SECURITY_EFFECTIVE_DATE = "2026-03-24"
    SECURE_FIELDS = {
        "name",
        "dob",
        "authorization_number",
        "va_icn",
        "claim_number",
    }
    ROUTE_ACCESS = {
        "submission_queue": ["submission_specialist", "coordinator", "senior_reviewer"],
        "review_queue": ["review_specialist", "qa_reviewer", "coordinator", "senior_reviewer"],
        "correction_queue": ["corrections_specialist", "coordinator", "senior_reviewer"],
        "senior_review_queue": ["senior_reviewer", "coordinator"],
        "compliance_review_queue": ["qa_reviewer", "coordinator", "senior_reviewer"],
        "compliance_correction_queue": ["corrections_specialist", "coordinator", "senior_reviewer"],
        "compliance_escalation_queue": ["senior_reviewer", "coordinator"],
        "compliant_submission_queue": ["submission_specialist", "coordinator", "senior_reviewer"],
    }

    def build(
        self,
        packet,
        submission_decision,
        decision_intelligence,
        predictive_intelligence,
        compliance_intelligence,
        integration_intelligence,
    ):
        access_control = self.build_access_control_enforcement(
            packet,
            decision_intelligence,
            compliance_intelligence,
            integration_intelligence,
        )
        threat_detection = self.build_threat_detection_engine(
            packet,
            predictive_intelligence,
            compliance_intelligence,
            access_control,
        )
        encryption = self.build_data_encryption_management(
            packet,
            access_control,
            integration_intelligence,
        )
        intrusion_detection = self.build_intrusion_detection_system(
            packet,
            access_control,
            threat_detection,
            submission_decision,
        )
        compliance_security = self.build_compliance_security_validation(
            compliance_intelligence,
            integration_intelligence,
            access_control,
            encryption,
        )
        identity_verification = self.build_identity_verification_system(
            packet,
            compliance_intelligence,
            threat_detection,
        )
        secure_sharing = self.build_secure_data_sharing(
            packet,
            integration_intelligence,
            access_control,
            encryption,
            identity_verification,
        )
        risk_assessment = self.build_risk_assessment_engine(
            packet,
            threat_detection,
            intrusion_detection,
            compliance_security,
            secure_sharing,
        )
        audit_logging = self.build_security_audit_logging(
            packet,
            access_control,
            threat_detection,
            intrusion_detection,
            risk_assessment,
        )
        incident_response = self.build_security_incident_response(
            threat_detection,
            intrusion_detection,
            risk_assessment,
            secure_sharing,
            decision_intelligence,
        )

        return {
            "access_control_enforcement": access_control,
            "threat_detection_engine": threat_detection,
            "data_encryption_management": encryption,
            "intrusion_detection_system": intrusion_detection,
            "risk_assessment_engine": risk_assessment,
            "security_audit_logging": audit_logging,
            "compliance_security_validation": compliance_security,
            "identity_verification_system": identity_verification,
            "secure_data_sharing": secure_sharing,
            "security_incident_response": incident_response,
        }

    def build_access_control_enforcement(
        self,
        packet,
        decision_intelligence,
        compliance_intelligence,
        integration_intelligence,
    ):
        workflow_queue = (
            decision_intelligence.get("workflow_decision_routing", {}).get("queue")
            or "review_queue"
        )
        protected_fields = sorted(
            field
            for field in self.SECURE_FIELDS
            if packet.fields.get(field)
        )
        secure_validation = compliance_intelligence.get("secure_data_handling_validation", {})
        integration_security = integration_intelligence.get("integration_security_controls", {})
        missing_controls = []

        if secure_validation.get("status") == "violation":
            missing_controls.append("secure_data_handling_validation")
        if integration_security.get("status") == "violation":
            missing_controls.append("integration_security_controls")

        status = "enforced"
        if missing_controls:
            status = "restricted"
        elif not protected_fields:
            status = "minimal"

        return {
            "status": status,
            "version": self.SECURITY_VERSION,
            "effective_date": self.SECURITY_EFFECTIVE_DATE,
            "workflow_queue": workflow_queue,
            "allowed_roles": list(self.ROUTE_ACCESS.get(workflow_queue, ["coordinator", "senior_reviewer"])),
            "protected_fields": protected_fields,
            "protected_field_count": len(protected_fields),
            "least_privilege": True,
            "missing_controls": missing_controls,
            "summary": (
                "Role-restricted access is enforced for protected packet fields."
                if status == "enforced" else
                "Packet access is restricted until secure-handling controls are corrected."
                if status == "restricted" else
                "Packet carries minimal protected data, so standard local access controls are sufficient."
            ),
        }

    def build_threat_detection_engine(
        self,
        packet,
        predictive_intelligence,
        compliance_intelligence,
        access_control,
    ):
        indicators = []
        risk_score = 0.06

        identity_conflicts = [
            conflict.get("field")
            for conflict in packet.conflicts
            if conflict.get("field") in {"name", "dob", "authorization_number", "va_icn", "claim_number"}
        ]
        if identity_conflicts:
            indicators.append("identity_conflicts")
            risk_score += min(0.26, 0.08 * len(identity_conflicts))

        if "packet_integrity_risk" in packet.review_flags:
            indicators.append("packet_integrity_risk")
            risk_score += 0.22

        if len(packet.duplicate_pages) >= 2:
            indicators.append("duplicate_page_pattern")
            risk_score += 0.08

        identity_confidences = [
            confidence
            for field, confidence in (packet.field_confidence or {}).items()
            if field in {"name", "dob", "authorization_number", "va_icn", "claim_number"}
            and isinstance(confidence, (int, float))
        ]
        average_identity_confidence = mean(identity_confidences) if identity_confidences else 0.0
        if average_identity_confidence and average_identity_confidence < 0.72:
            indicators.append("low_identity_confidence")
            risk_score += 0.08

        secure_validation = compliance_intelligence.get("secure_data_handling_validation", {})
        if secure_validation.get("status") == "violation":
            indicators.append("secure_handling_violation")
            risk_score += 0.22

        if predictive_intelligence.get("predictive_escalation", {}).get("escalate"):
            indicators.append("predictive_escalation_signal")
            risk_score += 0.06

        if access_control.get("status") == "restricted":
            indicators.append("access_control_restriction")
            risk_score += 0.12

        risk_score = round(max(0.03, min(risk_score, 0.99)), 2)
        if risk_score >= 0.76:
            level = "critical"
        elif risk_score >= 0.54:
            level = "elevated"
        elif risk_score >= 0.24:
            level = "watch"
        else:
            level = "low"

        return {
            "status": "alert" if level in {"critical", "elevated"} else ("watch" if level == "watch" else "clear"),
            "level": level,
            "risk_score": risk_score,
            "indicators": indicators,
            "monitored_scopes": [
                "packet_identity",
                "secure_field_access",
                "duplicate_page_patterns",
                "workflow_escalation",
            ],
            "summary": (
                "Threat indicators are clear for this packet."
                if level == "low" else
                "Threat indicators should be monitored during handling."
                if level == "watch" else
                "Threat indicators are elevated enough to justify controlled handling."
            ),
        }

    def build_data_encryption_management(self, packet, access_control, integration_intelligence):
        protected_fields = access_control.get("protected_fields", [])
        integration_security = integration_intelligence.get("integration_security_controls", {})
        secure_mode = "masked_local_exports"
        if integration_security.get("status") == "violation":
            status = "restricted"
        elif protected_fields:
            status = "managed"
        else:
            status = "minimal"

        return {
            "status": status,
            "storage_profile": "local_controlled_artifacts",
            "transport_profile": integration_security.get("transport_profile") or "local_file_exports_only",
            "protection_mode": secure_mode,
            "protected_fields": protected_fields,
            "requires_redaction_for_sharing": bool(protected_fields),
            "summary": (
                "Protected packet values stay inside controlled local artifacts with masked sharing exports."
                if status in {"managed", "minimal"} else
                "Secure export handling is restricted until integration security issues are corrected."
            ),
        }

    def build_intrusion_detection_system(self, packet, access_control, threat_detection, submission_decision):
        alerts = []
        if threat_detection.get("level") in {"critical", "elevated"}:
            alerts.append("threat_detection_alert")
        if access_control.get("status") == "restricted":
            alerts.append("restricted_access_required")
        if submission_decision.get("readiness") == "hold" and "packet_integrity_risk" in packet.review_flags:
            alerts.append("integrity_hold_requires_review")

        if alerts:
            status = "alert"
        elif threat_detection.get("level") == "watch":
            status = "monitoring"
        else:
            status = "normal"

        return {
            "status": status,
            "alert_count": len(alerts),
            "alerts": alerts,
            "monitoring_mode": "local_audit_and_queue_controls",
            "summary": (
                "Intrusion monitoring is quiet for this packet."
                if status == "normal" else
                "Intrusion monitoring should remain active because security signals need attention."
            ),
        }

    def build_compliance_security_validation(
        self,
        compliance_intelligence,
        integration_intelligence,
        access_control,
        encryption,
    ):
        secure_validation = compliance_intelligence.get("secure_data_handling_validation", {})
        integration_security = integration_intelligence.get("integration_security_controls", {})
        failures = []

        if secure_validation.get("status") == "violation":
            failures.append("secure_data_handling_validation")
        if integration_security.get("status") == "violation":
            failures.append("integration_security_controls")
        if access_control.get("status") == "restricted":
            failures.append("access_control_restriction")
        if encryption.get("status") == "restricted":
            failures.append("masked_export_controls")

        if failures:
            status = "violation"
        elif secure_validation.get("status") not in {None, "compliant"} or integration_security.get("status") == "warning":
            status = "warning"
        else:
            status = "validated"

        return {
            "status": status,
            "failed_controls": failures,
            "secure_data_status": secure_validation.get("status"),
            "integration_security_status": integration_security.get("status"),
            "summary": (
                "Security controls are aligned with current compliance expectations."
                if status == "validated" else
                "Security controls need attention before the packet should leave controlled handling."
            ),
        }

    def build_identity_verification_system(self, packet, compliance_intelligence, threat_detection):
        conflict_fields = {
            conflict.get("field")
            for conflict in packet.conflicts
            if conflict.get("field")
        }
        patient_identity_present = bool(packet.fields.get("name")) and bool(packet.fields.get("dob"))
        case_identity_present = bool(packet.fields.get("authorization_number") or packet.fields.get("va_icn") or packet.fields.get("claim_number"))
        secure_status = compliance_intelligence.get("secure_data_handling_validation", {}).get("status")

        blockers = []
        if not patient_identity_present:
            blockers.append("patient_identity_missing")
        if not case_identity_present:
            blockers.append("case_identifier_missing")
        if {"name", "dob", "authorization_number", "va_icn", "claim_number"}.intersection(conflict_fields):
            blockers.append("identity_conflicts_present")
        if threat_detection.get("level") == "critical":
            blockers.append("critical_security_signal")

        if secure_status == "violation":
            status = "failed"
        elif blockers:
            status = "review"
        else:
            status = "verified"

        return {
            "status": status,
            "operator_identity_mode": "role_attested_local_review",
            "required_operator_attributes": ["reviewer_name", "reviewer_role"],
            "patient_identity_present": patient_identity_present,
            "case_identity_present": case_identity_present,
            "blockers": blockers,
            "summary": (
                "Packet and operator identity controls are sufficient for local handling."
                if status == "verified" else
                "Identity signals require reviewer confirmation before higher-trust actions are taken."
            ),
        }

    def build_secure_data_sharing(
        self,
        packet,
        integration_intelligence,
        access_control,
        encryption,
        identity_verification,
    ):
        protected_fields = access_control.get("protected_fields", [])
        integration_security = integration_intelligence.get("integration_security_controls", {})
        allowed_targets = [
            "workflow_bridge",
            "review_queue",
            "local_repository_sync",
        ]

        if integration_security.get("status") == "violation" or identity_verification.get("status") == "failed":
            status = "blocked"
        elif protected_fields:
            status = "masked_only"
        else:
            status = "ready"

        return {
            "status": status,
            "allowed_targets": allowed_targets,
            "masked_fields": protected_fields,
            "share_profile": encryption.get("protection_mode"),
            "requires_role_attestation": True,
            "summary": (
                "Data sharing is limited to local controlled targets with masked sensitive fields."
                if status in {"masked_only", "ready"} else
                "Data sharing is blocked until security and identity controls are corrected."
            ),
        }

    def build_risk_assessment_engine(
        self,
        packet,
        threat_detection,
        intrusion_detection,
        compliance_security,
        secure_sharing,
    ):
        score = 0.08
        drivers = []

        score += threat_detection.get("risk_score", 0.0) * 0.45
        if threat_detection.get("level") in {"critical", "elevated"}:
            drivers.append("Threat detection raised elevated security signals.")
        elif threat_detection.get("level") == "watch":
            drivers.append("Threat detection remains in watch mode.")

        if intrusion_detection.get("status") == "alert":
            score += 0.16
            drivers.append("Intrusion monitoring produced alert conditions.")
        elif intrusion_detection.get("status") == "monitoring":
            score += 0.07
            drivers.append("Intrusion monitoring is active for this packet.")

        if compliance_security.get("status") == "violation":
            score += 0.2
            drivers.append("Compliance security validation found a violation.")
        elif compliance_security.get("status") == "warning":
            score += 0.1
            drivers.append("Compliance security validation found a warning.")

        if secure_sharing.get("status") == "blocked":
            score += 0.14
            drivers.append("Secure sharing is blocked.")
        elif secure_sharing.get("status") == "masked_only":
            score += 0.05
            drivers.append("Sharing must stay masked because protected fields are present.")

        if packet.packet_confidence is not None and packet.packet_confidence < 0.7:
            score += 0.05
            drivers.append("Low packet confidence increases handling risk for protected data.")

        score = round(max(0.04, min(score, 0.99)), 2)
        if score >= 0.8:
            level = "critical"
        elif score >= 0.58:
            level = "high"
        elif score >= 0.3:
            level = "moderate"
        else:
            level = "low"

        return {
            "level": level,
            "risk_score": score,
            "drivers": drivers,
            "summary": f"Security risk is {level} based on threat, intrusion, compliance, and sharing controls.",
        }

    def build_security_audit_logging(
        self,
        packet,
        access_control,
        threat_detection,
        intrusion_detection,
        risk_assessment,
    ):
        event_categories = [
            "access_control_validation",
            "threat_screening",
            "intrusion_monitoring",
            "secure_sharing_gate",
            "packet_processing_audit",
        ]
        event_count = len(event_categories) + len(access_control.get("protected_fields", []))

        return {
            "status": "active",
            "version": self.SECURITY_VERSION,
            "event_categories": event_categories,
            "event_count": event_count,
            "protected_field_count": access_control.get("protected_field_count", 0),
            "threat_level": threat_detection.get("level"),
            "intrusion_status": intrusion_detection.get("status"),
            "risk_level": risk_assessment.get("level"),
            "summary": "Security events are recorded as local auditable artifacts for each processed packet.",
        }

    def build_security_incident_response(
        self,
        threat_detection,
        intrusion_detection,
        risk_assessment,
        secure_sharing,
        decision_intelligence,
    ):
        workflow_queue = decision_intelligence.get("workflow_decision_routing", {}).get("queue")
        if risk_assessment.get("level") == "critical" or intrusion_detection.get("status") == "alert":
            status = "escalated"
            queue = "security_review_queue"
            action = "security_hold"
            steps = [
                "Freeze non-essential sharing actions.",
                "Route packet to a senior security-aware reviewer.",
                "Confirm identity and protected-field integrity before release.",
            ]
        elif threat_detection.get("level") == "watch":
            status = "monitoring"
            queue = workflow_queue
            action = "continue_with_monitoring"
            steps = [
                "Keep packet in the assigned workflow queue.",
                "Require masked sharing for protected fields.",
                "Review any new identity or access anomalies before completion.",
            ]
        else:
            status = "standby"
            queue = workflow_queue
            action = "normal_secured_processing"
            steps = [
                "Continue normal controlled processing.",
                "Maintain local audit logging.",
            ]

        return {
            "status": status,
            "queue": queue,
            "action": action,
            "sharing_gate": secure_sharing.get("status"),
            "response_steps": steps,
            "summary": (
                "Security incident response is escalated."
                if status == "escalated" else
                "Security incident response remains in controlled monitoring."
                if status == "monitoring" else
                "No active security incident response is required."
            ),
        }
