class IntegrationIntelligenceBuilder:
    INTEGRATION_VERSION = "truecore_integration_v1"

    def build(self, packet, submission_decision, decision_intelligence, compliance_intelligence, data_intelligence):
        api = self.build_api_integration_layer(packet, submission_decision, data_intelligence)
        ehr = self.build_ehr_integration(packet, data_intelligence)
        billing = self.build_billing_system_integration(packet, data_intelligence)
        crm = self.build_crm_integration(packet, submission_decision, decision_intelligence)
        repository = self.build_document_repository_sync(packet, data_intelligence)
        third_party = self.build_third_party_data_ingestion(packet, data_intelligence)
        conflict_resolution = self.build_data_sync_conflict_resolution(packet)
        security = self.build_integration_security_controls(packet, compliance_intelligence)
        health = self.build_integration_health_monitoring(
            api,
            ehr,
            billing,
            crm,
            repository,
            third_party,
            conflict_resolution,
            security,
        )
        webhook = self.build_webhook_event_system(
            packet,
            submission_decision,
            decision_intelligence,
            health,
            conflict_resolution,
        )

        return {
            "api_integration_layer": api,
            "ehr_integration": ehr,
            "billing_system_integration": billing,
            "crm_integration": crm,
            "document_repository_sync": repository,
            "third_party_data_ingestion": third_party,
            "integration_health_monitoring": health,
            "data_sync_conflict_resolution": conflict_resolution,
            "webhook_event_system": webhook,
            "integration_security_controls": security,
        }

    def build_api_integration_layer(self, packet, submission_decision, data_intelligence):
        integrity = data_intelligence.get("data_integrity_validation", {})
        quality = data_intelligence.get("data_quality_scoring", {})
        export_payload = data_intelligence.get("structured_data_export", {})

        if integrity.get("status") == "failed":
            status = "blocked"
        elif submission_decision.get("readiness") == "ready":
            status = "ready"
        else:
            status = "staged"

        return {
            "status": status,
            "version": self.INTEGRATION_VERSION,
            "export_payload_version": export_payload.get("export_version"),
            "supported_targets": [
                "workflow_bridge",
                "review_queue",
                "repository_sync",
                "local_connector_exports",
            ],
            "quality_gate": quality.get("band"),
            "summary": (
                "API-layer exports are ready for downstream local integration."
                if status == "ready" else
                "API-layer exports are staged pending review or correction."
                if status == "staged" else
                "API-layer exports are blocked until integrity issues are corrected."
            ),
        }

    def build_ehr_integration(self, packet, data_intelligence):
        missing = []
        if not packet.fields.get("name"):
            missing.append("name")
        if not packet.fields.get("dob"):
            missing.append("dob")
        if not (packet.fields.get("diagnosis") or packet.fields.get("icd_codes")):
            missing.append("diagnosis_or_icd")
        if "clinical_notes" not in set(packet.detected_documents):
            missing.append("clinical_notes")

        if missing:
            status = "pending_data"
        else:
            status = "ready"

        return {
            "status": status,
            "patient_key": data_intelligence.get("unified_data_model", {}).get("keys", {}).get("patient_key"),
            "missing_requirements": missing,
            "sync_scope": ["patient_identity", "clinical_summary", "authorization_context"],
            "summary": (
                "EHR sync payload has the minimum patient and clinical context needed for export."
                if status == "ready" else
                f"EHR sync remains pending because required fields are missing: {', '.join(missing)}."
            ),
        }

    def build_billing_system_integration(self, packet, data_intelligence):
        missing = []
        if not packet.fields.get("procedure"):
            missing.append("procedure")
        if not (packet.fields.get("diagnosis") or packet.fields.get("icd_codes")):
            missing.append("diagnosis_or_icd")
        if not packet.fields.get("provider"):
            missing.append("provider")
        if not packet.fields.get("service_date_range"):
            missing.append("service_date_range")

        return {
            "status": "ready" if not missing else "pending_data",
            "missing_requirements": missing,
            "billing_profile": {
                "procedure": packet.fields.get("procedure"),
                "icd_code_count": len(packet.fields.get("icd_codes") or []),
                "provider": packet.fields.get("provider"),
            },
            "summary": (
                "Billing payload is complete enough for downstream claim preparation."
                if not missing else
                f"Billing sync is pending because these elements are missing: {', '.join(missing)}."
            ),
        }

    def build_crm_integration(self, packet, submission_decision, decision_intelligence):
        next_action = decision_intelligence.get("recommended_next_action", {})
        workflow_route = decision_intelligence.get("workflow_decision_routing", {})

        return {
            "status": "ready" if packet.fields.get("name") and packet.fields.get("dob") else "pending_data",
            "case_status": submission_decision.get("readiness"),
            "workflow_queue": workflow_route.get("queue"),
            "next_action": next_action.get("action"),
            "contact_subject": packet.fields.get("provider") or packet.fields.get("ordering_provider") or packet.fields.get("clinic_name"),
            "summary": "CRM sync tracks packet status, next action, and the accountable office/provider contact.",
        }

    def build_document_repository_sync(self, packet, data_intelligence):
        metadata = data_intelligence.get("metadata_extraction", {})
        return {
            "status": "ready" if metadata.get("page_count", 0) > 0 else "blocked",
            "document_count": len(packet.detected_documents),
            "page_count": metadata.get("page_count"),
            "source_type": metadata.get("source_type"),
            "summary": "Document repository sync can persist packet artifacts and metadata."
            if metadata.get("page_count", 0) > 0 else
            "Document repository sync is blocked because the packet has no page payload.",
        }

    def build_third_party_data_ingestion(self, packet, data_intelligence):
        identifiers = [
            name
            for name in ("authorization_number", "va_icn", "claim_number")
            if packet.fields.get(name)
        ]
        return {
            "status": "ready" if identifiers else "limited",
            "available_identifiers": identifiers,
            "candidate_sources": [
                "local_external_data_store",
                "workflow_snapshot",
                "office_reference_exports",
            ],
            "enrichment_ready": bool(data_intelligence.get("data_enrichment_layer", {}).get("external_context_ready")),
            "summary": (
                "Third-party ingestion has identifiers that can anchor downstream lookups."
                if identifiers else
                "Third-party ingestion is limited because no stable packet identifier is present."
            ),
        }

    def build_data_sync_conflict_resolution(self, packet):
        sync_sensitive_fields = {
            "name",
            "dob",
            "authorization_number",
            "provider",
            "ordering_provider",
            "referring_provider",
            "va_icn",
            "claim_number",
        }
        sync_conflicts = [
            conflict
            for conflict in packet.conflicts
            if conflict.get("field") in sync_sensitive_fields
        ]

        return {
            "status": "conflicts_present" if sync_conflicts else "clear",
            "conflict_count": len(sync_conflicts),
            "conflict_fields": sorted({
                conflict.get("field")
                for conflict in sync_conflicts
                if conflict.get("field")
            }),
            "resolution_strategy": (
                "Hold external sync until reviewer-approved values resolve the mismatches."
                if sync_conflicts else
                "No sync conflicts detected; downstream exports can use the normalized packet values."
            ),
        }

    def build_integration_security_controls(self, packet, compliance_intelligence):
        secure_validation = compliance_intelligence.get("secure_data_handling_validation", {})
        masked_fields = [
            field
            for field in ("name", "dob", "authorization_number", "va_icn", "claim_number")
            if packet.fields.get(field)
        ]

        status = "secured"
        if secure_validation.get("status") == "violation":
            status = "violation"
        elif secure_validation.get("status") not in {None, "compliant"}:
            status = "warning"

        return {
            "status": status,
            "transport_profile": "local_file_exports_only",
            "masked_field_candidates": masked_fields,
            "secure_validation_status": secure_validation.get("status"),
            "summary": (
                "Integration outputs stay inside the local controlled export model."
                if status == "secured" else
                "Integration security needs attention before external sync is allowed."
            ),
        }

    def build_integration_health_monitoring(self, api, ehr, billing, crm, repository, third_party, conflict_resolution, security):
        statuses = [
            api.get("status"),
            ehr.get("status"),
            billing.get("status"),
            crm.get("status"),
            repository.get("status"),
            third_party.get("status"),
            conflict_resolution.get("status"),
            security.get("status"),
        ]

        degraded = any(status in {"pending_data", "limited", "staged", "warning"} for status in statuses)
        blocked = any(status in {"blocked", "violation", "conflicts_present"} for status in statuses)

        if blocked:
            overall_status = "degraded"
        elif degraded:
            overall_status = "watch"
        else:
            overall_status = "healthy"

        return {
            "status": overall_status,
            "component_statuses": {
                "api": api.get("status"),
                "ehr": ehr.get("status"),
                "billing": billing.get("status"),
                "crm": crm.get("status"),
                "repository": repository.get("status"),
                "third_party": third_party.get("status"),
                "sync_conflicts": conflict_resolution.get("status"),
                "security": security.get("status"),
            },
            "summary": (
                "Integration components are healthy and ready for local sync."
                if overall_status == "healthy" else
                "Integration components need monitoring because one or more dependencies remain staged or blocked."
            ),
        }

    def build_webhook_event_system(self, packet, submission_decision, decision_intelligence, health, conflict_resolution):
        events = []
        queue = decision_intelligence.get("workflow_decision_routing", {}).get("queue")
        readiness = submission_decision.get("readiness")

        if readiness == "ready":
            events.append("packet_ready_for_submission")
        elif readiness == "requires_review":
            events.append("packet_review_required")
        else:
            events.append("packet_correction_required")

        if queue:
            events.append(f"queue::{queue}")
        if conflict_resolution.get("status") == "conflicts_present":
            events.append("sync_conflicts_detected")
        if health.get("status") != "healthy":
            events.append("integration_health_watch")

        return {
            "status": "events_ready",
            "event_count": len(events),
            "events": events,
            "summary": "Webhook event payloads are prepared as deterministic local event records.",
        }
