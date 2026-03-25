import re
from statistics import mean


class DataIntelligenceBuilder:
    DATA_MODEL_VERSION = "truecore_data_v1"
    STRUCTURED_EXPORT_VERSION = "truecore_structured_export_v1"

    def build(self, packet, submission_decision, decision_intelligence, predictive_intelligence, compliance_intelligence, knowledge_intelligence):
        unified_data_model = self.build_unified_data_model(packet, submission_decision, decision_intelligence)
        normalization = self.build_data_normalization_engine(packet, unified_data_model)
        integrity = self.build_data_integrity_validation(
            packet,
            submission_decision,
            compliance_intelligence,
            normalization,
        )
        linking = self.build_cross_source_data_linking(packet)
        deduplication = self.build_data_deduplication_engine(packet)
        enrichment = self.build_data_enrichment_layer(
            packet,
            decision_intelligence,
            predictive_intelligence,
            knowledge_intelligence,
        )
        metadata = self.build_metadata_extraction(packet)
        lineage = self.build_data_lineage_tracking(packet)
        quality = self.build_data_quality_scoring(
            packet,
            integrity,
            metadata,
            lineage,
            deduplication,
        )
        structured_export = self.build_structured_data_export(
            packet,
            unified_data_model,
            metadata,
            lineage,
            quality,
            enrichment,
            submission_decision,
        )

        return {
            "unified_data_model": unified_data_model,
            "data_normalization_engine": normalization,
            "data_integrity_validation": integrity,
            "cross_source_data_linking": linking,
            "data_deduplication_engine": deduplication,
            "data_enrichment_layer": enrichment,
            "metadata_extraction": metadata,
            "data_lineage_tracking": lineage,
            "structured_data_export": structured_export,
            "data_quality_scoring": quality,
        }

    def build_unified_data_model(self, packet, submission_decision, decision_intelligence):
        patient_key = self.build_patient_key(packet.fields)
        case_key = self.build_case_key(packet.fields)
        packet_type = decision_intelligence.get("packet_type") or "authorization_request"

        return {
            "version": self.DATA_MODEL_VERSION,
            "packet_type": packet_type,
            "keys": {
                "patient_key": patient_key,
                "case_key": case_key,
            },
            "patient": {
                "name": packet.fields.get("name"),
                "dob": packet.fields.get("dob"),
                "va_icn": packet.fields.get("va_icn"),
                "claim_number": packet.fields.get("claim_number"),
            },
            "providers": {
                "provider": packet.fields.get("provider"),
                "ordering_provider": packet.fields.get("ordering_provider"),
                "referring_provider": packet.fields.get("referring_provider"),
                "npi": packet.fields.get("npi"),
                "clinic_name": packet.fields.get("clinic_name"),
                "facility": packet.fields.get("facility"),
                "location": packet.fields.get("location"),
            },
            "authorization": {
                "authorization_number": packet.fields.get("authorization_number"),
                "authorization_detected": bool(packet.fields.get("authorization_detected")),
            },
            "clinical": {
                "procedure": packet.fields.get("procedure"),
                "diagnosis": packet.fields.get("diagnosis"),
                "icd_codes": list(packet.fields.get("icd_codes") or []),
                "symptom": packet.fields.get("symptom"),
                "reason_for_request": packet.fields.get("reason_for_request"),
                "medications": list(packet.fields.get("medications") or []),
                "service_date_range": packet.fields.get("service_date_range"),
            },
            "documents": sorted(packet.detected_documents),
            "review": {
                "readiness": submission_decision.get("readiness"),
                "workflow_route": submission_decision.get("workflow_route"),
                "needs_review": bool(packet.needs_review),
                "packet_strength": packet.packet_strength,
            },
        }

    def build_data_normalization_engine(self, packet, unified_data_model):
        normalized_fields = {}
        transformed_fields = []

        for field, value in sorted(packet.fields.items()):
            normalized = self.normalize_value(field, value)
            normalized_fields[field] = normalized
            if normalized != value:
                transformed_fields.append(field)

        return {
            "status": "normalized",
            "normalized_field_count": len(normalized_fields),
            "transformed_field_count": len(transformed_fields),
            "transformed_fields": transformed_fields,
            "normalized_fields": normalized_fields,
            "patient_key": unified_data_model["keys"]["patient_key"],
            "case_key": unified_data_model["keys"]["case_key"],
        }

    def build_data_integrity_validation(self, packet, submission_decision, compliance_intelligence, normalization):
        issues = []
        checks = []
        secure_validation = compliance_intelligence.get("secure_data_handling_validation", {})

        def add_check(name, passed, detail):
            checks.append({
                "check": name,
                "status": "pass" if passed else "fail",
                "detail": detail,
            })
            if not passed:
                issues.append(name)

        add_check(
            "patient_identity_present",
            bool(packet.fields.get("name")) and bool(packet.fields.get("dob")),
            "Packet should include normalized patient identity fields.",
        )
        add_check(
            "case_identifier_present",
            bool(packet.fields.get("authorization_number") or packet.fields.get("va_icn") or packet.fields.get("claim_number")),
            "Packet should include at least one case identifier.",
        )
        add_check(
            "no_high_conflicts",
            not any(conflict.get("severity") == "high" for conflict in packet.conflicts),
            "High-severity conflicts reduce data integrity.",
        )
        add_check(
            "field_mappings_present",
            bool(packet.field_mappings),
            "Extracted data should retain field mappings for lineage.",
        )
        add_check(
            "secure_data_ok",
            secure_validation.get("status") != "violation",
            "Secure-data validation should not report a violation.",
        )
        add_check(
            "submission_key_consistency",
            bool(normalization.get("patient_key")) and bool(normalization.get("case_key")),
            "Patient and case keys should both be derivable from normalized fields.",
        )

        average_confidence = (
            mean(packet.field_confidence.values())
            if packet.field_confidence else 0.0
        )

        score = 1.0
        score -= min(0.45, len(issues) * 0.12)
        score -= min(0.2, len(packet.missing_fields) * 0.04)
        score -= min(0.2, len(packet.conflicts) * 0.05)
        score += min(0.12, average_confidence * 0.12)
        score = max(0.0, min(1.0, round(score, 2)))

        if score >= 0.82 and not issues:
            status = "validated"
        elif score >= 0.55:
            status = "warning"
        else:
            status = "failed"

        return {
            "status": status,
            "integrity_score": score,
            "issue_count": len(issues),
            "issues": issues,
            "checks": checks,
            "submission_readiness": submission_decision.get("readiness"),
            "summary": (
                "Data integrity is strong and internally consistent."
                if status == "validated" else
                "Data integrity has review-sensitive gaps but remains usable."
                if status == "warning" else
                "Data integrity is materially degraded and needs correction."
            ),
        }

    def build_cross_source_data_linking(self, packet):
        field_links = []
        document_links = {}

        for field, mapping in sorted((packet.field_mappings or {}).items()):
            if not isinstance(mapping, dict):
                continue
            document_type = mapping.get("document_type")
            document_links.setdefault(document_type or "unknown", []).append(field)
            field_links.append({
                "field": field,
                "value": mapping.get("value"),
                "document_type": document_type,
                "page_number": mapping.get("page_number"),
                "source_file": mapping.get("source_file"),
                "confidence": mapping.get("confidence"),
            })

        linked_documents = [
            {
                "document_type": document_type,
                "linked_fields": sorted(fields),
                "linked_field_count": len(set(fields)),
            }
            for document_type, fields in sorted(document_links.items())
        ]

        identity_link_count = sum(
            1
            for item in field_links
            if item["field"] in {"name", "dob", "authorization_number", "va_icn", "claim_number"}
        )

        return {
            "status": "linked" if field_links else "limited",
            "field_link_count": len(field_links),
            "linked_document_count": len(linked_documents),
            "identity_link_count": identity_link_count,
            "field_links": field_links,
            "linked_documents": linked_documents,
        }

    def build_data_deduplication_engine(self, packet):
        redundant_field_groups = []

        for field, values in sorted((packet.field_values or {}).items()):
            normalized_values = [
                self.normalize_for_compare(value)
                for value in values
                if value is not None and value != ""
            ]
            distinct_values = list(dict.fromkeys(normalized_values))
            if len(normalized_values) > len(distinct_values):
                redundant_field_groups.append({
                    "field": field,
                    "captured_count": len(normalized_values),
                    "distinct_count": len(distinct_values),
                    "canonical_values": distinct_values,
                })

        return {
            "status": "deduplicated",
            "duplicate_page_count": len(packet.duplicate_pages),
            "redundant_field_group_count": len(redundant_field_groups),
            "redundant_field_groups": redundant_field_groups,
            "duplicate_pages": list(packet.duplicate_pages),
        }

    def build_data_enrichment_layer(self, packet, decision_intelligence, predictive_intelligence, knowledge_intelligence):
        procedure = str(packet.fields.get("procedure") or "").strip().upper()
        diagnosis = str(packet.fields.get("diagnosis") or "")
        reason = str(packet.fields.get("reason_for_request") or "")
        body_region_hints = []

        region_map = {
            "lumbar": {"lumbar", "low back", "back"},
            "cervical": {"cervical", "neck"},
            "hip": {"hip"},
            "shoulder": {"shoulder"},
        }
        combined_text = f"{diagnosis} {reason}".lower()
        for region, hints in region_map.items():
            if any(hint in combined_text for hint in hints):
                body_region_hints.append(region)

        procedure_family = {
            "MRI": "advanced_imaging",
            "CT": "advanced_imaging",
            "XRAY": "basic_imaging",
            "PHYSICAL THERAPY": "rehabilitation",
        }.get(procedure, "general_medical")

        return {
            "status": "enriched",
            "procedure_family": procedure_family,
            "body_region_hints": body_region_hints,
            "packet_type": decision_intelligence.get("packet_type"),
            "predicted_complexity": predictive_intelligence.get("case_complexity_scoring", {}).get("level"),
            "knowledge_case": knowledge_intelligence.get("case_based_reasoning_engine", {}).get("archetype"),
            "external_context_ready": bool(
                packet.fields.get("va_icn")
                or packet.fields.get("claim_number")
                or packet.fields.get("facility")
                or packet.fields.get("clinic_name")
            ),
        }

    def build_metadata_extraction(self, packet):
        field_confidence_avg = round(
            mean(packet.field_confidence.values()),
            2,
        ) if packet.field_confidence else 0.0
        page_confidence_avg = round(
            mean(packet.page_confidence.values()),
            2,
        ) if packet.page_confidence else 0.0

        return {
            "status": "extracted",
            "source_type": packet.source_type,
            "page_count": len(packet.pages),
            "field_count": len(packet.fields),
            "document_type_count": len(packet.detected_documents),
            "source_file_count": len({
                str(source.get("path"))
                for source in packet.page_sources
                if isinstance(source, dict) and source.get("path")
            }),
            "field_confidence_average": field_confidence_avg,
            "page_confidence_average": page_confidence_avg,
            "duplicate_page_count": len(packet.duplicate_pages),
            "document_types": sorted(packet.detected_documents),
        }

    def build_data_lineage_tracking(self, packet):
        field_lineage = []
        for field, mapping in sorted((packet.field_mappings or {}).items()):
            if not isinstance(mapping, dict):
                continue
            field_lineage.append({
                "field": field,
                "document_type": mapping.get("document_type"),
                "page_number": mapping.get("page_number"),
                "source_file": mapping.get("source_file"),
                "confidence": mapping.get("confidence"),
                "snippet": mapping.get("snippet"),
            })

        lineage_coverage = round(
            len(field_lineage) / max(1, len(packet.fields)),
            2,
        )

        return {
            "status": "tracked" if field_lineage else "limited",
            "lineage_coverage": lineage_coverage,
            "lineage_field_count": len(field_lineage),
            "field_lineage": field_lineage,
        }

    def build_structured_data_export(self, packet, unified_data_model, metadata, lineage, quality, enrichment, submission_decision):
        return {
            "export_version": self.STRUCTURED_EXPORT_VERSION,
            "packet_key": unified_data_model["keys"]["case_key"],
            "patient": unified_data_model["patient"],
            "providers": unified_data_model["providers"],
            "authorization": unified_data_model["authorization"],
            "clinical": unified_data_model["clinical"],
            "documents": unified_data_model["documents"],
            "metadata": metadata,
            "lineage": {
                "coverage": lineage.get("lineage_coverage"),
                "fields": lineage.get("field_lineage", []),
            },
            "quality": {
                "score": quality.get("score"),
                "band": quality.get("band"),
            },
            "enrichment": enrichment,
            "review": {
                "submission_readiness": submission_decision.get("readiness"),
                "workflow_route": submission_decision.get("workflow_route"),
                "needs_review": bool(packet.needs_review),
                "review_priority": packet.review_priority,
            },
        }

    def build_data_quality_scoring(self, packet, integrity, metadata, lineage, deduplication):
        avg_field_confidence = metadata.get("field_confidence_average", 0.0)
        conflict_pressure = sum(
            {
                "high": 0.22,
                "medium": 0.1,
                "low": 0.05,
            }.get(conflict.get("severity"), 0.08)
            for conflict in packet.conflicts
        )
        score = 0.38
        score += min(0.25, avg_field_confidence * 0.25)
        score += integrity.get("integrity_score", 0.0) * 0.3
        score += min(0.12, lineage.get("lineage_coverage", 0.0) * 0.12)
        score -= min(0.18, len(packet.missing_fields) * 0.04 + len(packet.missing_documents) * 0.05)
        score -= min(0.45, conflict_pressure)
        score -= min(0.08, deduplication.get("duplicate_page_count", 0) * 0.03)

        if integrity.get("status") == "failed":
            score = min(score, 0.58)
        elif integrity.get("status") == "warning":
            score = min(score, 0.76)

        score = max(0.0, min(1.0, round(score, 2)))

        if score >= 0.82:
            band = "high"
        elif score >= 0.62:
            band = "moderate"
        else:
            band = "low"

        drivers = []
        if avg_field_confidence >= 0.9:
            drivers.append("high_field_confidence")
        if integrity.get("status") == "validated":
            drivers.append("validated_integrity")
        if lineage.get("lineage_coverage", 0.0) >= 0.8:
            drivers.append("strong_lineage")
        if packet.missing_documents:
            drivers.append("missing_documents")
        if packet.conflicts:
            drivers.append("field_conflicts")

        return {
            "score": score,
            "band": band,
            "drivers": drivers,
            "summary": (
                f"Data quality is {band} with score {score} based on normalization, integrity, lineage, and conflict pressure."
            ),
        }

    def build_patient_key(self, fields):
        name = re.sub(r"[^A-Z0-9]+", "", str(fields.get("name") or "").upper())
        dob = re.sub(r"[^0-9]+", "", str(fields.get("dob") or ""))
        if not name and not dob:
            return None
        return "::".join(part for part in (name, dob) if part)

    def build_case_key(self, fields):
        case_identifier = (
            fields.get("authorization_number")
            or fields.get("va_icn")
            or fields.get("claim_number")
        )
        case_identifier = re.sub(r"[^A-Z0-9]+", "", str(case_identifier or "").upper())
        patient_key = self.build_patient_key(fields)
        if not patient_key and not case_identifier:
            return None
        return "::".join(part for part in (patient_key, case_identifier) if part)

    def normalize_value(self, field, value):
        if value is None:
            return None
        if isinstance(value, list):
            return [self.normalize_value(field, item) for item in value]
        text = str(value).strip()
        if not text:
            return None
        if field in {"name", "provider", "ordering_provider", "referring_provider", "clinic_name", "facility", "location"}:
            return re.sub(r"\s+", " ", text)
        if field in {"authorization_number", "va_icn", "claim_number", "npi"}:
            return re.sub(r"\s+", "", text).upper()
        if field == "dob":
            return re.sub(r"\s+", "", text)
        return re.sub(r"\s+", " ", text)

    def normalize_for_compare(self, value):
        if isinstance(value, list):
            return tuple(self.normalize_for_compare(item) for item in value)
        return re.sub(r"\s+", " ", str(value).strip().lower())
