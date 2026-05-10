class ReviewComplianceMixin:
    def build_regulatory_rule_engine(self, packet, decision_intelligence):
        packet_type = decision_intelligence["packet_type"]
        profile = self.SUCCESS_PACKET_PROFILES.get(
            packet_type,
            self.SUCCESS_PACKET_PROFILES["authorization_request"],
        )
        required_documents = sorted(profile["required_documents"])
        required_fields = sorted(profile["expected_fields"])
        signature_documents = sorted(
            self.COMPLIANCE_SIGNATURE_REQUIRED_DOCS.intersection(set(packet.detected_documents) | set(required_documents))
        )
        authorization_required = packet_type != "clinical_minimal" or bool((self.AUTHORIZATION_DOCUMENT_TYPES | {"consult_request"}).intersection(set(packet.detected_documents)))

        return {
            "policy_version": self.COMPLIANCE_POLICY_VERSION,
            "policy_effective_date": self.COMPLIANCE_POLICY_EFFECTIVE_DATE,
            "packet_type": packet_type,
            "rules": [
                {
                    "rule_id": "required_documents_present",
                    "description": "Packet must contain required document components for its packet profile.",
                    "required_targets": required_documents,
                },
                {
                    "rule_id": "required_fields_present",
                    "description": "Packet must contain required identity and clinical fields for its packet profile.",
                    "required_targets": required_fields,
                },
                {
                    "rule_id": "identity_consistency",
                    "description": "Identity fields must remain internally consistent across packet documents.",
                    "required_targets": ["name", "dob"],
                },
                {
                    "rule_id": "authorization_traceability",
                    "description": "Authorization or referral traceability must exist for authorization-driven packets.",
                    "required_targets": ["authorization_number"] if authorization_required else [],
                },
                {
                    "rule_id": "signature_control",
                    "description": "Signature-sensitive documents must show signed completion when present.",
                    "required_targets": signature_documents,
                },
                {
                    "rule_id": "secure_local_handling",
                    "description": "Packet handling should stay within local paths and avoid raw full-SSN exposure.",
                    "required_targets": sorted(self.COMPLIANCE_SECURE_FIELDS),
                },
            ],
        }

    def build_compliance_validation_checks(self, packet, regulatory_rules, decision_intelligence, secure_validation):
        required_documents = set()
        required_fields = set()
        for rule in regulatory_rules["rules"]:
            if rule["rule_id"] == "required_documents_present":
                required_documents.update(rule["required_targets"])
            elif rule["rule_id"] == "required_fields_present":
                required_fields.update(rule["required_targets"])

        failed_checks = []
        checks = []

        def add_check(check_id, status, detail, severity):
            checks.append({
                "check_id": check_id,
                "status": status,
                "severity": severity,
                "detail": detail,
            })
            if status != "pass":
                failed_checks.append(check_id)

        missing_docs = self.get_missing_required_documents(packet, required_documents)
        add_check(
            "required_documents_present",
            "pass" if not missing_docs else "fail",
            "All required documents are present." if not missing_docs else f"Missing required documents: {', '.join(missing_docs)}.",
            "high",
        )

        missing_fields = sorted(required_fields.difference(set(packet.fields)))
        add_check(
            "required_fields_present",
            "pass" if not missing_fields else "fail",
            "All required fields are present." if not missing_fields else f"Missing required fields: {', '.join(missing_fields)}.",
            "high" if {"name", "dob", "authorization_number"}.intersection(missing_fields) else "medium",
        )

        identity_issues = sorted({
            conflict.get("field")
            for conflict in packet.conflicts
            if conflict.get("type") == "identity_mismatch"
        })
        add_check(
            "identity_consistency",
            "pass" if not identity_issues else "fail",
            "Identity signals are internally consistent." if not identity_issues else f"Identity conflicts were detected in: {', '.join(identity_issues)}.",
            "high",
        )

        auth_required = any(
            rule["rule_id"] == "authorization_traceability" and rule["required_targets"]
            for rule in regulatory_rules["rules"]
        )
        auth_present = bool(packet.fields.get("authorization_number"))
        add_check(
            "authorization_traceability",
            "pass" if (not auth_required or auth_present) else "fail",
            "Authorization traceability is present." if (not auth_required or auth_present) else "Authorization traceability is missing for an authorization-driven packet.",
            "high" if auth_required else "low",
        )

        missing_signature_docs = []
        signature_docs = next(
            (rule["required_targets"] for rule in regulatory_rules["rules"] if rule["rule_id"] == "signature_control"),
            [],
        )
        if signature_docs and packet.fields.get("signature_present") is not True:
            missing_signature_docs = list(signature_docs)
        add_check(
            "signature_control",
            "pass" if not missing_signature_docs else "fail",
            "Signature-sensitive documents show signed completion." if not missing_signature_docs else f"Missing signature evidence for: {', '.join(missing_signature_docs)}.",
            "high" if "consent" in missing_signature_docs else "medium",
        )

        add_check(
            "secure_local_handling",
            "pass" if secure_validation["status"] == "compliant" else "fail",
            secure_validation["summary"],
            "high" if secure_validation["status"] == "violation" else "medium",
        )

        overall_status = "compliant" if not failed_checks else "non_compliant"
        return {
            "overall_status": overall_status,
            "checks": checks,
            "failed_checks": failed_checks,
        }

    def build_documentation_requirement_enforcement(self, packet, regulatory_rules, compliance_validation):
        required_documents = []
        required_fields = []
        for rule in regulatory_rules["rules"]:
            if rule["rule_id"] == "required_documents_present":
                required_documents.extend(rule["required_targets"])
            elif rule["rule_id"] == "required_fields_present":
                required_fields.extend(rule["required_targets"])

        missing_documents = self.get_missing_required_documents(packet, required_documents)
        missing_fields = sorted(set(required_fields).difference(set(packet.fields)))
        enforced = bool(required_documents or required_fields)

        return {
            "enforced": enforced,
            "missing_documents": missing_documents,
            "missing_fields": missing_fields,
            "summary": (
                "Documentation requirements are satisfied."
                if not missing_documents and not missing_fields else
                f"Documentation requirements are not satisfied: {', '.join(missing_documents + missing_fields)}."
            ),
        }

    def build_secure_data_handling_validation(self, packet):
        issues = []
        source_paths = list(packet.files or []) + list(packet.page_sources or [])
        local_only = True
        for path in source_paths:
            value = str(path or "")
            if value.lower().startswith(("http://", "https://", "ftp://")):
                local_only = False
                issues.append("Packet source path points to a non-local location.")
                break

        for field_name, value in packet.fields.items():
            if field_name.lower() in {"ssn", "social_security_number", "full_ssn"} and value:
                issues.append(f"Field {field_name} appears to contain raw SSN content.")
            digits = "".join(ch for ch in str(value) if ch.isdigit())
            if len(digits) == 9 and field_name.lower() not in {"claim_number"}:
                issues.append(f"Field {field_name} may expose a 9-digit sensitive identifier.")

        if not local_only:
            status = "violation"
        elif issues:
            status = "warning"
        else:
            status = "compliant"

        return {
            "status": status,
            "local_storage_only": local_only,
            "issues": self.unique_preserve_order(issues),
            "summary": (
                "Secure data handling checks passed."
                if not issues and local_only else
                "; ".join(self.unique_preserve_order(issues)) or "Secure data handling needs review."
            ),
        }

    def build_violation_detection(self, packet, compliance_validation, documentation_enforcement, secure_validation, decision_intelligence):
        violations = []

        if documentation_enforcement["missing_documents"]:
            violations.append({
                "code": "missing_required_documents",
                "severity": "high",
                "detail": f"Missing required documents: {', '.join(documentation_enforcement['missing_documents'])}.",
            })
        if documentation_enforcement["missing_fields"]:
            severity = "high" if {"name", "dob", "authorization_number"}.intersection(set(documentation_enforcement["missing_fields"])) else "medium"
            violations.append({
                "code": "missing_required_fields",
                "severity": severity,
                "detail": f"Missing required fields: {', '.join(documentation_enforcement['missing_fields'])}.",
            })

        for check in compliance_validation["checks"]:
            if check["status"] == "fail" and check["check_id"] not in {"required_documents_present", "required_fields_present"}:
                violations.append({
                    "code": check["check_id"],
                    "severity": check["severity"],
                    "detail": check["detail"],
                })

        if secure_validation["status"] in {"warning", "violation"}:
            violations.append({
                "code": "secure_data_handling",
                "severity": "high" if secure_validation["status"] == "violation" else "medium",
                "detail": secure_validation["summary"],
            })

        for conflict in packet.conflicts:
            if conflict.get("severity") == "high":
                violations.append({
                    "code": "high_severity_conflict",
                    "severity": "high",
                    "detail": conflict.get("message", "High-severity conflict detected."),
                })

        if decision_intelligence["denial_risk_prediction"]["level"] in {"high", "critical"} and packet.missing_documents:
            violations.append({
                "code": "submission_risk_control",
                "severity": "medium",
                "detail": "Compliance-sensitive packet is still carrying high denial risk with unresolved document gaps.",
            })

        severity_order = {"high": 0, "medium": 1, "low": 2}
        violations = sorted(
            self.unique_preserve_order(tuple(sorted(item.items())) for item in violations),
            key=lambda item: (severity_order.get(dict(item)["severity"], 3), dict(item)["code"]),
        )
        normalized = [dict(item) for item in violations]
        return {
            "count": len(normalized),
            "violations": normalized,
            "highest_severity": normalized[0]["severity"] if normalized else None,
        }

    def build_compliance_risk_scoring(self, packet, compliance_validation, secure_validation, violation_detection, predictive_intelligence):
        risk_score = 0.08
        drivers = []

        if compliance_validation["overall_status"] != "compliant":
            risk_score += 0.24
            drivers.append("Compliance validation checks failed.")

        risk_score += min(0.26, 0.09 * len(packet.missing_documents))
        if packet.missing_documents:
            drivers.append("Missing required documents raise regulatory handling risk.")

        risk_score += min(0.18, 0.06 * len(packet.missing_fields))
        if packet.missing_fields:
            drivers.append("Missing required fields raise regulatory handling risk.")

        if secure_validation["status"] == "violation":
            risk_score += 0.3
            drivers.append("Secure data handling check produced a violation.")
        elif secure_validation["status"] == "warning":
            risk_score += 0.12
            drivers.append("Secure data handling requires review.")

        high_violations = sum(1 for item in violation_detection["violations"] if item["severity"] == "high")
        medium_violations = sum(1 for item in violation_detection["violations"] if item["severity"] == "medium")
        risk_score += min(0.22, 0.08 * high_violations)
        risk_score += min(0.14, 0.04 * medium_violations)

        denial_risk = predictive_intelligence["approval_outcome_prediction"]["forecast_probability"]
        if denial_risk < 0.55:
            risk_score += 0.08
            drivers.append("Low approval outlook also increases compliance sensitivity.")

        risk_score = round(max(0.03, min(risk_score, 0.99)), 2)
        if risk_score >= 0.78:
            level = "critical"
        elif risk_score >= 0.56:
            level = "high"
        elif risk_score >= 0.3:
            level = "moderate"
        else:
            level = "low"

        return {
            "level": level,
            "risk_score": risk_score,
            "drivers": self.unique_preserve_order(drivers),
            "summary": f"Compliance risk is {level} based on missing requirements, validation failures, and secure-handling checks.",
        }

    def build_audit_trail_automation(self, packet, decision_intelligence, predictive_intelligence, optimization_intelligence, compliance_risk):
        tracked_actions = [
            "document_detection",
            "field_extraction",
            "validation",
            "medical_reasoning",
            "review_decision",
            "predictive_forecasting",
            "optimization_analysis",
            "compliance_evaluation",
        ]
        return {
            "tracked_actions": tracked_actions,
            "artifact_generated": False,
            "audit_scope": {
                "packet_label": packet.output.get("packet_label"),
                "workflow_route": decision_intelligence["workflow_decision_routing"]["queue"],
                "predicted_turnaround_band": predictive_intelligence["turnaround_time_prediction"]["band"],
                "queue_priority": optimization_intelligence["smart_queue_prioritization"]["priority_bucket"],
                "compliance_risk": compliance_risk["level"],
            },
        }

    def build_policy_change_detection(self):
        return {
            "active_policy_version": self.COMPLIANCE_POLICY_VERSION,
            "policy_effective_date": self.COMPLIANCE_POLICY_EFFECTIVE_DATE,
            "change_detected": False,
            "detection_mode": "embedded_policy_manifest",
            "summary": "Embedded compliance policy is active; no runtime policy change has been detected locally.",
        }

    def build_audit_report_generation(self, packet, violation_detection, compliance_risk):
        return {
            "report_type": "packet_compliance_report",
            "artifact_generated": False,
            "violation_count": violation_detection["count"],
            "compliance_risk": compliance_risk["level"],
            "summary": (
                "Compliance report is ready to generate."
                if violation_detection["count"] else
                "Packet is compliant enough for a minimal audit report."
            ),
        }

    def build_compliance_workflow_routing(self, packet, compliance_risk, violation_detection, secure_validation):
        if secure_validation["status"] == "violation":
            queue = "compliance_escalation_queue"
            reason = secure_validation["summary"]
        elif violation_detection["highest_severity"] == "high":
            queue = "compliance_correction_queue"
            reason = violation_detection["violations"][0]["detail"] if violation_detection["violations"] else "High-severity compliance issue detected."
        elif compliance_risk["level"] in {"high", "critical"}:
            queue = "compliance_review_queue"
            reason = compliance_risk["summary"]
        elif violation_detection["count"]:
            queue = "compliance_correction_queue"
            reason = violation_detection["violations"][0]["detail"]
        else:
            queue = "submission_queue"
            reason = "No material compliance issues were detected."

        return {
            "queue": queue,
            "requires_compliance_review": queue != "submission_queue",
            "reason": reason,
        }

    def build_compliance_intelligence(self, packet, submission_decision, decision_intelligence, predictive_intelligence, optimization_intelligence):
        regulatory_rules = self.build_regulatory_rule_engine(packet, decision_intelligence)
        secure_validation = self.build_secure_data_handling_validation(packet)
        compliance_validation = self.build_compliance_validation_checks(
            packet,
            regulatory_rules,
            decision_intelligence,
            secure_validation,
        )
        documentation_enforcement = self.build_documentation_requirement_enforcement(
            packet,
            regulatory_rules,
            compliance_validation,
        )
        violation_detection = self.build_violation_detection(
            packet,
            compliance_validation,
            documentation_enforcement,
            secure_validation,
            decision_intelligence,
        )
        compliance_risk = self.build_compliance_risk_scoring(
            packet,
            compliance_validation,
            secure_validation,
            violation_detection,
            predictive_intelligence,
        )
        audit_trail = self.build_audit_trail_automation(
            packet,
            decision_intelligence,
            predictive_intelligence,
            optimization_intelligence,
            compliance_risk,
        )
        policy_change = self.build_policy_change_detection()
        audit_report = self.build_audit_report_generation(packet, violation_detection, compliance_risk)
        compliance_route = self.build_compliance_workflow_routing(
            packet,
            compliance_risk,
            violation_detection,
            secure_validation,
        )

        return {
            "regulatory_rule_engine": regulatory_rules,
            "compliance_validation_checks": compliance_validation,
            "audit_trail_automation": audit_trail,
            "policy_change_detection": policy_change,
            "compliance_risk_scoring": compliance_risk,
            "documentation_requirement_enforcement": documentation_enforcement,
            "secure_data_handling_validation": secure_validation,
            "audit_report_generation": audit_report,
            "violation_detection": violation_detection,
            "compliance_workflow_routing": compliance_route,
        }
