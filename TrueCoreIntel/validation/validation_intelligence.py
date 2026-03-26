import re

from TrueCoreIntel.detection.form_templates import FORM_TEMPLATES


class ValidationIntelligenceAnalyzer:
    FACT_FIELDS = (
        "name",
        "dob",
        "authorization_number",
        "va_icn",
        "claim_number",
        "provider",
        "ordering_provider",
        "referring_provider",
        "diagnosis",
        "procedure",
        "icd_codes",
        "service_date_range",
    )

    TRACEBACK_FIELD_ORDER = (
        "name",
        "dob",
        "authorization_number",
        "va_icn",
        "claim_number",
        "ordering_provider",
        "referring_provider",
        "provider",
        "diagnosis",
        "procedure",
        "icd_codes",
        "reason_for_request",
        "service_date_range",
        "signature_present",
    )

    REGION_HINTS = {
        "lumbar": {"back", "lumbar", "lumbago", "radiculopathy", "sciatica", "low back"},
        "cervical": {"neck", "cervical"},
        "hip": {"hip"},
        "shoulder": {"shoulder"},
        "knee": {"knee"},
        "head": {"head", "migraine", "headache"},
    }

    def analyze(self, packet, validator):
        cross_document = self.build_cross_document_fact_verification(packet, validator)
        extraction = self.build_extraction_claim_verification(packet)
        form_consistency = self.build_field_to_form_consistency_checks(packet)
        signature_completeness = self.build_signature_and_completeness_validation(packet)
        date_logic = self.build_date_logic_validation(packet, validator)
        procedure_code = self.build_procedure_code_consistency_checks(packet)
        conflict_ranking = self.build_validation_conflict_severity_ranking(packet)
        traceback_links = self.build_evidence_traceback_links(packet, extraction)
        deep_score = self.build_deep_verification_score(
            packet,
            extraction,
            form_consistency,
            signature_completeness,
            date_logic,
            procedure_code,
            conflict_ranking,
        )

        packet.links["evidence_traceback_links"] = traceback_links
        packet.deep_verification_score = deep_score.get("score")
        packet.validation_intelligence = {
            "cross_document_fact_verification": cross_document,
            "extraction_claim_verification": extraction["summary"],
            "field_to_form_consistency_checks": form_consistency,
            "signature_and_completeness_validation": signature_completeness,
            "date_logic_validation": date_logic,
            "procedure_code_consistency_checks": procedure_code,
            "validation_conflict_severity_ranking": conflict_ranking,
            "evidence_traceback_links": traceback_links,
            "deep_verification_score": deep_score,
        }
        return packet

    def build_cross_document_fact_verification(self, packet, validator):
        facts = []
        consistent = 0
        conflicted = 0
        missing = 0

        for field in self.FACT_FIELDS:
            selected_value = packet.fields.get(field)
            observed_values = list(packet.field_values.get(field, []) or [])
            if not observed_values and selected_value not in (None, "", []):
                observed_values = [selected_value]

            normalized_values = validator.get_normalized_unique_values(field, observed_values)
            mapping = packet.field_mappings.get(field, {})

            if not observed_values and selected_value in (None, "", []):
                status = "missing"
                missing += 1
            elif len(normalized_values) > 1:
                status = "conflict"
                conflicted += 1
            else:
                status = "consistent"
                consistent += 1

            facts.append({
                "field": field,
                "status": status,
                "selected_value": self.serialize_value(selected_value),
                "observed_value_count": len(observed_values),
                "unique_value_count": len(normalized_values),
                "normalized_values": [self.serialize_value(value) for value in normalized_values[:4]],
                "source_document_type": mapping.get("document_type"),
                "source_page_number": mapping.get("page_number"),
                "confidence": mapping.get("confidence"),
                "page_zone": mapping.get("page_zone"),
                "ocr_confidence": mapping.get("ocr_confidence"),
            })

        return {
            "facts": facts,
            "summary": {
                "consistent_fields": consistent,
                "conflicted_fields": conflicted,
                "missing_fields": missing,
            },
        }

    def build_extraction_claim_verification(self, packet):
        claims = []
        status_counts = {
            "verified_text_match": 0,
            "verified_context_match": 0,
            "label_supported": 0,
            "weak_context": 0,
            "unsupported": 0,
        }
        by_field = {}

        for field, mapping in sorted(
            (packet.field_mappings or {}).items(),
            key=lambda item: float((item[1] or {}).get("confidence") or 0.0),
            reverse=True,
        ):
            status = self.classify_mapping_support(mapping)
            status_counts[status] = status_counts.get(status, 0) + 1

            claim = {
                "field": field,
                "status": status,
                "value": self.serialize_value(mapping.get("value")),
                "confidence": mapping.get("confidence"),
                "document_type": mapping.get("document_type"),
                "page_number": mapping.get("page_number"),
                "page_zone": mapping.get("page_zone"),
                "anchor_label": mapping.get("anchor_label"),
                "ocr_confidence": mapping.get("ocr_confidence"),
                "ocr_provider": mapping.get("ocr_provider"),
                "extraction_strategy": mapping.get("extraction_strategy"),
                "matched_text": self.clean_excerpt(mapping.get("matched_text")),
                "snippet": self.clean_excerpt(mapping.get("snippet")),
            }
            claims.append(claim)
            by_field[field] = claim

        return {
            "summary": {
                "claims": claims,
                "status_counts": status_counts,
                "verified_claims": status_counts["verified_text_match"] + status_counts["verified_context_match"],
                "weak_claims": status_counts["weak_context"] + status_counts["unsupported"],
            },
            "by_field": by_field,
        }

    def build_field_to_form_consistency_checks(self, packet):
        document_checks = []
        complete = 0
        partial = 0
        weak = 0

        for doc_type in sorted(packet.detected_documents):
            template = FORM_TEMPLATES.get(doc_type, {})
            expected_fields = list(template.get("expected_fields", []))

            if not expected_fields:
                continue

            local_fields = []
            shared_fields = []
            missing_fields = []

            for field in expected_fields:
                support_type = self.classify_document_field_support(packet, field, doc_type)
                if support_type == "local":
                    local_fields.append(field)
                elif support_type == "shared":
                    shared_fields.append(field)
                else:
                    missing_fields.append(field)

            satisfied_count = len(local_fields) + len(shared_fields)
            completeness_ratio = round(satisfied_count / max(len(expected_fields), 1), 2)

            if not missing_fields:
                status = "complete"
                complete += 1
            elif satisfied_count > 0:
                status = "partial"
                partial += 1
            else:
                status = "weak"
                weak += 1

            document_checks.append({
                "document_type": doc_type,
                "status": status,
                "expected_field_count": len(expected_fields),
                "local_fields": local_fields,
                "shared_fields": shared_fields,
                "missing_expected_fields": missing_fields,
                "completeness_ratio": completeness_ratio,
            })

        return {
            "documents": document_checks,
            "summary": {
                "complete_documents": complete,
                "partial_documents": partial,
                "weak_documents": weak,
            },
        }

    def build_signature_and_completeness_validation(self, packet):
        detected_documents = sorted(packet.detected_documents)
        unfilled_documents = sorted(packet.unfilled_documents)
        document_gap_conflicts = [
            conflict.get("message")
            for conflict in packet.conflicts
            if conflict.get("type") == "document_gap" and conflict.get("message")
        ]
        signature_expected_documents = [
            doc_type
            for doc_type in detected_documents
            if "signature_present" in FORM_TEMPLATES.get(doc_type, {}).get("expected_fields", [])
        ]

        missing_signature_documents = []
        if signature_expected_documents and not packet.fields.get("signature_present"):
            missing_signature_documents = list(signature_expected_documents)

        status = "stable"
        if unfilled_documents or document_gap_conflicts or missing_signature_documents:
            status = "attention_needed"

        return {
            "status": status,
            "signature_present": bool(packet.fields.get("signature_present")),
            "documents_expect_signature": signature_expected_documents,
            "missing_signature_documents": missing_signature_documents,
            "unfilled_documents": unfilled_documents,
            "missing_documents": list(packet.missing_documents),
            "document_gap_messages": document_gap_conflicts,
        }

    def build_date_logic_validation(self, packet, validator):
        chronology_entries = list(packet.links.get("document_chronology", []))
        recommended_order = list(packet.links.get("recommended_page_order", []))
        chronology_conflicts = [
            conflict
            for conflict in packet.conflicts
            if conflict.get("type") == "chronology_error"
        ]
        moved_pages = [
            entry
            for entry in recommended_order
            if entry.get("recommended_position") != entry.get("current_position")
            and entry.get("doc_type") != "unknown"
        ]

        parsed_dates = []
        for entry in chronology_entries:
            for key in ("start_date", "end_date"):
                parsed = validator.parse_date(entry.get(key))
                if parsed:
                    parsed_dates.append(parsed)

        parsed_dates = sorted(parsed_dates)
        chronology_span = None
        if parsed_dates:
            chronology_span = {
                "earliest_date": parsed_dates[0].strftime("%m/%d/%Y"),
                "latest_date": parsed_dates[-1].strftime("%m/%d/%Y"),
            }

        status = "stable"
        if chronology_conflicts or packet.links.get("page_order_review_needed"):
            status = "attention_needed"

        return {
            "status": status,
            "service_date_range": packet.fields.get("service_date_range"),
            "chronology_entry_count": len(chronology_entries),
            "chronology_conflicts": [
                {
                    "field": conflict.get("field"),
                    "message": conflict.get("message"),
                    "severity": conflict.get("severity"),
                }
                for conflict in chronology_conflicts
            ],
            "chronology_span": chronology_span,
            "page_order_review_needed": bool(packet.links.get("page_order_review_needed")),
            "pages_recommended_to_move": [entry.get("page_index", 0) + 1 for entry in moved_pages],
        }

    def build_procedure_code_consistency_checks(self, packet):
        diagnosis = packet.fields.get("diagnosis")
        procedure = packet.fields.get("procedure")
        icd_codes = list(packet.fields.get("icd_codes", []) or [])
        reason_for_request = packet.fields.get("reason_for_request")
        review_flags = set(packet.review_flags or [])

        if "diagnosis_icd_mismatch" in review_flags:
            diagnosis_icd_alignment = "misaligned"
        elif "partial_diagnosis_icd_alignment" in review_flags:
            diagnosis_icd_alignment = "partial"
        elif diagnosis and icd_codes:
            diagnosis_icd_alignment = "aligned"
        else:
            diagnosis_icd_alignment = "unknown"

        diagnosis_regions = self.extract_regions(diagnosis)
        reason_regions = self.extract_regions(reason_for_request)

        if diagnosis_regions and reason_regions:
            region_alignment = "aligned" if diagnosis_regions.intersection(reason_regions) else "mixed"
        elif diagnosis_regions or reason_regions:
            region_alignment = "partial"
        else:
            region_alignment = "unknown"

        if diagnosis_icd_alignment == "misaligned" or region_alignment == "mixed":
            status = "attention_needed"
        elif diagnosis_icd_alignment == "partial" or region_alignment == "partial":
            status = "review"
        else:
            status = "aligned"

        return {
            "status": status,
            "procedure": procedure,
            "diagnosis": diagnosis,
            "icd_codes": icd_codes,
            "reason_for_request": reason_for_request,
            "diagnosis_icd_alignment": diagnosis_icd_alignment,
            "body_region_alignment": region_alignment,
            "review_flags": [
                flag
                for flag in packet.review_flags
                if "diagnosis" in str(flag) or "procedure" in str(flag) or "icd" in str(flag)
            ],
        }

    def build_validation_conflict_severity_ranking(self, packet):
        severity_weights = {"high": 3, "medium": 2, "low": 1}
        ranked = []

        for index, conflict in enumerate(packet.conflicts or []):
            severity = str(conflict.get("severity") or "low").lower()
            base_score = severity_weights.get(severity, 1) * 10
            if conflict.get("type") == "document_gap":
                base_score -= 1

            ranked.append({
                "rank": 0,
                "impact_score": base_score,
                "field": conflict.get("field"),
                "type": conflict.get("type"),
                "severity": severity,
                "message": conflict.get("message"),
                "values": self.serialize_value(conflict.get("values")),
                "original_index": index,
            })

        ranked.sort(
            key=lambda item: (
                -int(item.get("impact_score") or 0),
                str(item.get("field") or ""),
                int(item.get("original_index") or 0),
            )
        )

        for rank, conflict in enumerate(ranked, start=1):
            conflict["rank"] = rank
            conflict.pop("original_index", None)

        return {
            "conflicts": ranked,
            "summary": {
                "high_severity": sum(1 for item in ranked if item.get("severity") == "high"),
                "medium_severity": sum(1 for item in ranked if item.get("severity") == "medium"),
                "low_severity": sum(1 for item in ranked if item.get("severity") == "low"),
            },
        }

    def build_evidence_traceback_links(self, packet, extraction):
        traceback_links = []
        by_field = extraction.get("by_field", {})

        for field in self.TRACEBACK_FIELD_ORDER:
            mapping = packet.field_mappings.get(field)
            if not mapping:
                continue

            claim = by_field.get(field, {})
            traceback_links.append({
                "field": field,
                "value": self.serialize_value(mapping.get("value")),
                "support_status": claim.get("status"),
                "confidence": mapping.get("confidence"),
                "document_type": mapping.get("document_type"),
                "page_number": mapping.get("page_number"),
                "page_zone": mapping.get("page_zone"),
                "anchor_label": mapping.get("anchor_label"),
                "ocr_confidence": mapping.get("ocr_confidence"),
                "ocr_provider": mapping.get("ocr_provider"),
                "extraction_strategy": mapping.get("extraction_strategy"),
                "matched_text": self.clean_excerpt(mapping.get("matched_text")),
                "snippet": self.clean_excerpt(mapping.get("snippet")),
                "source_file": mapping.get("source_file"),
            })

        return traceback_links

    def build_deep_verification_score(
        self,
        packet,
        extraction,
        form_consistency,
        signature_completeness,
        date_logic,
        procedure_code,
        conflict_ranking,
    ):
        score = 100
        penalties = []

        for conflict in packet.conflicts or []:
            severity = str(conflict.get("severity") or "low").lower()
            penalty = {"high": 15, "medium": 9, "low": 4}.get(severity, 4)
            if conflict.get("type") == "document_gap":
                penalty = min(penalty, 6)
            score -= penalty
            penalties.append({
                "reason": conflict.get("message") or f"{conflict.get('field')} conflict",
                "penalty": penalty,
            })

        for field in packet.missing_fields or []:
            penalty = 8
            score -= penalty
            penalties.append({
                "reason": f"Missing required field: {field}",
                "penalty": penalty,
            })

        for document_type in packet.missing_documents or []:
            penalty = 6
            score -= penalty
            penalties.append({
                "reason": f"Missing required document: {document_type}",
                "penalty": penalty,
            })

        for document_type in packet.unfilled_documents or []:
            penalty = 5
            score -= penalty
            penalties.append({
                "reason": f"Document present but unfilled: {document_type}",
                "penalty": penalty,
            })

        for claim in extraction.get("summary", {}).get("claims", []):
            status = claim.get("status")
            if status == "weak_context":
                penalties.append({
                    "reason": f"Weak source support for extracted field: {claim.get('field')}",
                    "penalty": 2,
                })
                score -= 2
            elif status == "unsupported":
                penalties.append({
                    "reason": f"No strong source support for extracted field: {claim.get('field')}",
                    "penalty": 6,
                })
                score -= 6

        if signature_completeness.get("missing_signature_documents"):
            score -= 8
            penalties.append({
                "reason": "Expected signature-bearing documents are missing signatures.",
                "penalty": 8,
            })

        if date_logic.get("status") == "attention_needed":
            score -= 6
            penalties.append({
                "reason": "Chronology or page ordering needs review.",
                "penalty": 6,
            })

        if procedure_code.get("status") == "attention_needed":
            score -= 8
            penalties.append({
                "reason": "Procedure, diagnosis, and coding are not fully aligned.",
                "penalty": 8,
            })
        elif procedure_code.get("status") == "review":
            score -= 4
            penalties.append({
                "reason": "Procedure and diagnosis alignment is only partial.",
                "penalty": 4,
            })

        weak_documents = int(form_consistency.get("summary", {}).get("weak_documents") or 0)
        if weak_documents:
            form_penalty = min(weak_documents * 3, 12)
            score -= form_penalty
            penalties.append({
                "reason": "Some detected documents are weakly supported by expected fields.",
                "penalty": form_penalty,
            })

        if not packet.conflicts and not packet.missing_fields and extraction.get("summary", {}).get("verified_claims", 0) >= 4:
            score += 4

        score = max(0, min(int(round(score)), 100))
        sorted_penalties = sorted(penalties, key=lambda item: item.get("penalty", 0), reverse=True)

        return {
            "score": score,
            "band": "high" if score >= 85 else "moderate" if score >= 65 else "low",
            "top_penalties": sorted_penalties[:6],
            "conflict_count": len(conflict_ranking.get("conflicts", [])),
            "missing_field_count": len(packet.missing_fields or []),
            "missing_document_count": len(packet.missing_documents or []),
        }

    def classify_document_field_support(self, packet, field, doc_type):
        mapping = packet.field_mappings.get(field, {})
        if mapping.get("document_type") == doc_type:
            return "local"

        if field in packet.fields and packet.fields.get(field) not in (None, "", []):
            return "shared"

        if packet.field_values.get(field):
            return "shared"

        return None

    def classify_mapping_support(self, mapping):
        matched_text = str(mapping.get("matched_text") or "").strip()
        snippet = str(mapping.get("snippet") or "")
        confidence = float(mapping.get("confidence") or 0.0)
        value_terms = self.get_value_terms(mapping.get("value"))

        if matched_text:
            return "verified_text_match"

        if snippet and any(term.lower() in snippet.lower() for term in value_terms):
            return "verified_context_match"

        if snippet and confidence >= 0.9:
            return "label_supported"

        if snippet:
            return "weak_context"

        return "unsupported"

    def get_value_terms(self, value):
        if value is True:
            return ["signed", "signature"]

        if isinstance(value, (list, tuple, set)):
            return [str(item).strip() for item in value if str(item).strip()]

        text = str(value or "").strip()
        if not text:
            return []

        text = re.sub(r"\s+", " ", text)
        return [text]

    def extract_regions(self, text):
        normalized = str(text or "").lower()
        normalized = re.sub(r"[^a-z0-9 ]", " ", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()

        if not normalized:
            return set()

        found = set()
        for region, hints in self.REGION_HINTS.items():
            if any(hint in normalized for hint in hints):
                found.add(region)
        return found

    def serialize_value(self, value):
        if isinstance(value, tuple):
            return [self.serialize_value(item) for item in value]
        if isinstance(value, list):
            return [self.serialize_value(item) for item in value]
        if isinstance(value, dict):
            return {str(key): self.serialize_value(item) for key, item in value.items()}
        return value

    def clean_excerpt(self, text):
        cleaned = str(text or "").strip()
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned[:240] if cleaned else None
