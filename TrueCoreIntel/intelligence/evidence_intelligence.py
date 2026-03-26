from datetime import datetime, timezone
import re

from TrueCoreIntel.detection.form_templates import FORM_TEMPLATES


class EvidenceIntelligenceAnalyzer:
    DOCUMENT_RELEVANCE_WEIGHTS = {
        "lomn": 1.0,
        "clinical_notes": 0.96,
        "rfs": 0.9,
        "consult_request": 0.88,
        "seoc": 0.72,
        "cover_sheet": 0.58,
        "consent": 0.45,
        "unknown": 0.25,
    }

    DOCUMENT_SUPPORT_FIELDS = {
        "lomn": ("diagnosis", "reason_for_request", "service_date_range", "signature_present"),
        "clinical_notes": ("diagnosis", "symptom", "procedure", "icd_codes", "service_date_range", "signature_present"),
        "rfs": ("authorization_number", "va_icn", "ordering_provider", "referring_provider", "service_date_range"),
        "consult_request": ("ordering_provider", "referring_provider", "authorization_number", "reason_for_request"),
        "seoc": ("authorization_number", "referring_provider", "service_date_range"),
        "cover_sheet": ("name", "dob", "ordering_provider", "clinic_name", "facility"),
        "consent": ("name", "dob", "signature_present"),
    }

    REQUIREMENTS = {
        "patient_identity": {
            "fields": ("name", "dob"),
            "documents": ("cover_sheet", "rfs", "consult_request", "clinical_notes"),
        },
        "authorization_support": {
            "fields": ("authorization_number",),
            "documents": ("rfs", "consult_request", "seoc"),
        },
        "clinical_justification": {
            "fields": ("diagnosis", "symptom", "reason_for_request"),
            "documents": ("clinical_notes", "lomn"),
        },
        "coding_support": {
            "fields": ("diagnosis", "icd_codes"),
            "documents": ("clinical_notes", "lomn"),
        },
        "requested_service_support": {
            "fields": ("procedure", "reason_for_request"),
            "documents": ("consult_request", "clinical_notes", "lomn"),
        },
        "provider_routing": {
            "fields": ("ordering_provider", "referring_provider"),
            "documents": ("consult_request", "rfs", "seoc"),
        },
        "signature_attestation": {
            "fields": ("signature_present",),
            "documents": ("lomn", "consent", "clinical_notes"),
        },
        "date_recency": {
            "fields": ("service_date_range",),
            "documents": ("clinical_notes", "rfs", "seoc", "lomn"),
        },
    }

    JUSTIFICATION_SIGNALS = (
        "procedure",
        "diagnosis",
        "symptom",
        "reason_for_request",
        "icd_codes",
        "service_date_range",
        "signature_present",
    )

    def analyze(self, packet):
        document_strength = self.build_document_strength_scoring(packet)
        relevance_ranking = self.build_evidence_relevance_ranking(document_strength)
        contradictions = self.build_contradictory_evidence_detection(packet)
        coverage_mapping = self.build_evidence_coverage_mapping(packet)
        density_analysis = self.build_clinical_justification_density_analysis(packet)
        freshness_validation = self.build_evidence_freshness_validation(packet)
        weak_support = self.build_weak_support_identification(packet, document_strength, coverage_mapping)
        sufficiency = self.build_evidence_sufficiency_modeling(
            packet,
            coverage_mapping,
            density_analysis,
            contradictions,
            freshness_validation,
            weak_support,
        )
        escalation = self.build_evidence_escalation_recommendation(
            packet,
            coverage_mapping,
            contradictions,
            freshness_validation,
            weak_support,
            sufficiency,
        )
        narrative = self.build_evidence_narrative_assembly(
            packet,
            relevance_ranking,
            sufficiency,
            contradictions,
            freshness_validation,
            weak_support,
        )

        packet.evidence_intelligence = {
            "evidence_strength_scoring": document_strength,
            "evidence_relevance_ranking": relevance_ranking,
            "evidence_sufficiency_modeling": sufficiency,
            "contradictory_evidence_detection": contradictions,
            "weak_support_identification": weak_support,
            "clinical_justification_density_analysis": density_analysis,
            "evidence_coverage_mapping": coverage_mapping,
            "evidence_freshness_validation": freshness_validation,
            "evidence_escalation_recommendation": escalation,
            "evidence_narrative_assembly": narrative,
        }

        packet.evidence_links.append({
            "type": "evidence_sufficiency",
            "status": sufficiency.get("status"),
            "score": sufficiency.get("score"),
        })
        packet.evidence_links.append({
            "type": "evidence_freshness",
            "status": freshness_validation.get("status"),
            "latest_evidence_date": freshness_validation.get("latest_evidence_date"),
        })
        packet.evidence_links.append({
            "type": "evidence_coverage",
            "supported_requirements": coverage_mapping.get("summary", {}).get("strong_requirements"),
            "partial_requirements": coverage_mapping.get("summary", {}).get("partial_requirements"),
            "missing_requirements": coverage_mapping.get("summary", {}).get("missing_requirements"),
        })
        return packet

    def build_document_strength_scoring(self, packet):
        spans = list(getattr(packet, "document_spans", []) or [])
        if not spans:
            spans = self.build_fallback_spans(packet)

        form_checks = {
            item.get("document_type"): item
            for item in (
                packet.validation_intelligence
                .get("field_to_form_consistency_checks", {})
                .get("documents", [])
            )
            if item.get("document_type")
        }

        scored = []
        for span in spans:
            doc_type = span.get("document_type", "unknown")
            support_fields = self.get_document_support_fields(packet, doc_type)
            expected_fields = list(self.DOCUMENT_SUPPORT_FIELDS.get(doc_type, FORM_TEMPLATES.get(doc_type, {}).get("expected_fields", [])))
            local_ratio = len(support_fields) / max(len(expected_fields), 1) if expected_fields else 0.0
            average_confidence = float(span.get("average_confidence") or 0.0)
            relevance_weight = float(self.DOCUMENT_RELEVANCE_WEIGHTS.get(doc_type, self.DOCUMENT_RELEVANCE_WEIGHTS["unknown"]))

            score = (relevance_weight * 0.45) + (average_confidence * 0.35) + (local_ratio * 0.20)
            score = round(min(max(score, 0.0), 0.99), 2)

            form_status = (form_checks.get(doc_type) or {}).get("status")
            missing_expected_fields = list((form_checks.get(doc_type) or {}).get("missing_expected_fields", []))

            scored.append({
                "document_type": doc_type,
                "start_page": span.get("start_page"),
                "end_page": span.get("end_page"),
                "page_count": span.get("page_count"),
                "average_confidence": round(average_confidence, 2),
                "strength_score": score,
                "strength_band": self.band_from_score(score),
                "relevance_score": round(min(0.99, (relevance_weight * 0.6) + (local_ratio * 0.25) + (average_confidence * 0.15)), 2),
                "support_fields": support_fields,
                "missing_expected_fields": missing_expected_fields,
                "form_consistency_status": form_status,
            })

        return {
            "documents": sorted(scored, key=lambda item: (-item["strength_score"], item["document_type"])),
            "summary": {
                "strong_documents": sum(1 for item in scored if item["strength_band"] == "strong"),
                "moderate_documents": sum(1 for item in scored if item["strength_band"] == "moderate"),
                "weak_documents": sum(1 for item in scored if item["strength_band"] == "weak"),
            },
        }

    def build_evidence_relevance_ranking(self, document_strength):
        ranked = sorted(
            list(document_strength.get("documents", [])),
            key=lambda item: (-float(item.get("relevance_score") or 0.0), -float(item.get("strength_score") or 0.0), item.get("document_type", "")),
        )

        ranking = []
        for position, item in enumerate(ranked, start=1):
            ranking.append({
                "rank": position,
                "document_type": item.get("document_type"),
                "relevance_score": item.get("relevance_score"),
                "strength_score": item.get("strength_score"),
                "support_fields": list(item.get("support_fields", []))[:6],
                "page_range": self.page_range_label(item.get("start_page"), item.get("end_page")),
            })
        return ranking

    def build_evidence_sufficiency_modeling(self, packet, coverage_mapping, density_analysis, contradictions, freshness_validation, weak_support):
        score = 52
        strong_requirements = int(coverage_mapping.get("summary", {}).get("strong_requirements") or 0)
        partial_requirements = int(coverage_mapping.get("summary", {}).get("partial_requirements") or 0)
        contradiction_count = int(contradictions.get("summary", {}).get("contradiction_count") or 0)
        critical_contradictions = int(contradictions.get("summary", {}).get("critical_contradictions") or 0)
        deep_score = float(getattr(packet, "deep_verification_score", 0) or 0)

        score += strong_requirements * 6
        score += partial_requirements * 2
        score += int(round(float(density_analysis.get("density_score") or 0.0) * 12))
        score += int(round((deep_score / 100.0) * 8))
        score -= contradiction_count * 5
        score -= critical_contradictions * 4
        score -= int(weak_support.get("summary", {}).get("high_priority_gaps") or 0) * 4

        freshness_status = freshness_validation.get("status")
        if freshness_status == "fresh":
            score += 4
        elif freshness_status == "aging":
            score -= 4
        elif freshness_status == "stale":
            score -= 10
        elif freshness_status == "unknown":
            score -= 3

        score = max(0, min(int(round(score)), 100))

        if score >= 78 and critical_contradictions == 0:
            status = "likely_sufficient"
        elif score >= 58:
            status = "borderline"
        else:
            status = "insufficient"

        reasons = []
        if strong_requirements >= 5:
            reasons.append("Most core evidence requirements are covered strongly.")
        if density_analysis.get("density_band") == "strong":
            reasons.append("Clinical justification density is strong.")
        if critical_contradictions:
            reasons.append("Critical contradictions reduce evidence sufficiency.")
        if weak_support.get("summary", {}).get("high_priority_gaps"):
            reasons.append("High-priority evidence gaps remain unresolved.")
        if freshness_status in {"aging", "stale"}:
            reasons.append("Evidence recency weakens submission support.")
        if not reasons:
            reasons.append("Evidence sufficiency is driven by overall coverage, verification quality, and contradiction load.")

        return {
            "score": score,
            "status": status,
            "support_level": "high" if score >= 78 else "moderate" if score >= 58 else "low",
            "reasons": reasons[:5],
            "supporting_requirement_count": strong_requirements,
            "partial_requirement_count": partial_requirements,
            "contradiction_count": contradiction_count,
        }

    def build_contradictory_evidence_detection(self, packet):
        contradictions = []
        for conflict in packet.conflicts or []:
            if conflict.get("type") == "document_gap":
                continue

            contradictions.append({
                "field": conflict.get("field"),
                "type": conflict.get("type"),
                "severity": conflict.get("severity"),
                "message": conflict.get("message"),
                "values": self.serialize_value(conflict.get("values")),
            })

        return {
            "contradictions": contradictions,
            "summary": {
                "contradiction_count": len(contradictions),
                "critical_contradictions": sum(1 for item in contradictions if item.get("severity") == "high"),
                "moderate_contradictions": sum(1 for item in contradictions if item.get("severity") == "medium"),
            },
        }

    def build_weak_support_identification(self, packet, document_strength, coverage_mapping):
        weak_documents = [
            {
                "document_type": item.get("document_type"),
                "strength_score": item.get("strength_score"),
                "reason": "Document has weak evidence strength or missing expected support fields.",
            }
            for item in document_strength.get("documents", [])
            if item.get("strength_band") == "weak"
        ]

        requirement_gaps = []
        for item in coverage_mapping.get("requirements", []):
            if item.get("status") == "strong":
                continue
            requirement_gaps.append({
                "requirement": item.get("requirement"),
                "status": item.get("status"),
                "missing_fields": list(item.get("missing_fields", [])),
                "missing_documents": list(item.get("missing_documents", [])),
            })

        return {
            "weak_documents": weak_documents,
            "requirement_gaps": requirement_gaps,
            "summary": {
                "weak_document_count": len(weak_documents),
                "high_priority_gaps": sum(1 for item in requirement_gaps if item.get("status") == "missing"),
                "partial_support_gaps": sum(1 for item in requirement_gaps if item.get("status") == "partial"),
            },
        }

    def build_clinical_justification_density_analysis(self, packet):
        present_signals = []
        missing_signals = []

        for field in self.JUSTIFICATION_SIGNALS:
            value = packet.fields.get(field)
            if value in (None, "", []):
                missing_signals.append(field)
            else:
                present_signals.append(field)

        if "clinical_notes" in packet.detected_documents:
            present_signals.append("clinical_notes_document")
        else:
            missing_signals.append("clinical_notes_document")

        if "lomn" in packet.detected_documents:
            present_signals.append("lomn_document")
        else:
            missing_signals.append("lomn_document")

        density_score = round(len(present_signals) / max(len(present_signals) + len(missing_signals), 1), 2)

        return {
            "density_score": density_score,
            "density_band": "strong" if density_score >= 0.75 else "moderate" if density_score >= 0.5 else "weak",
            "present_signals": present_signals,
            "missing_signals": missing_signals,
        }

    def build_evidence_coverage_mapping(self, packet):
        requirements = []

        for requirement, definition in self.REQUIREMENTS.items():
            expected_fields = list(definition.get("fields", ()))
            expected_documents = list(definition.get("documents", ()))
            supporting_fields = [field for field in expected_fields if packet.fields.get(field) not in (None, "", [])]
            missing_fields = [field for field in expected_fields if field not in supporting_fields]
            supporting_documents = [doc for doc in expected_documents if doc in packet.detected_documents]
            missing_documents = [doc for doc in expected_documents if doc not in packet.detected_documents]

            if supporting_fields and supporting_documents:
                status = "strong"
            elif supporting_fields or supporting_documents:
                status = "partial"
            else:
                status = "missing"

            supporting_pages = sorted({
                mapping.get("page_number")
                for field, mapping in (packet.field_mappings or {}).items()
                if field in supporting_fields and mapping.get("page_number")
            })

            requirements.append({
                "requirement": requirement,
                "status": status,
                "supporting_fields": supporting_fields,
                "missing_fields": missing_fields,
                "supporting_documents": supporting_documents,
                "missing_documents": missing_documents,
                "supporting_pages": supporting_pages,
            })

        return {
            "requirements": requirements,
            "summary": {
                "strong_requirements": sum(1 for item in requirements if item["status"] == "strong"),
                "partial_requirements": sum(1 for item in requirements if item["status"] == "partial"),
                "missing_requirements": sum(1 for item in requirements if item["status"] == "missing"),
            },
        }

    def build_evidence_freshness_validation(self, packet):
        now = datetime.now(timezone.utc)
        candidate_dates = []

        for entry in packet.links.get("document_chronology", []):
            for key in ("start_date", "end_date"):
                parsed = self.parse_date(entry.get(key))
                if parsed:
                    candidate_dates.append(parsed)

        service_date_range = packet.fields.get("service_date_range")
        if isinstance(service_date_range, str) and " to " in service_date_range:
            _start_text, end_text = [part.strip() for part in service_date_range.split(" to ", 1)]
            parsed = self.parse_date(end_text)
            if parsed:
                candidate_dates.append(parsed)

        if not candidate_dates:
            return {
                "status": "unknown",
                "latest_evidence_date": None,
                "age_days": None,
                "summary": "No reliable evidence dates were available for freshness validation.",
            }

        latest = max(candidate_dates)
        age_days = (now - latest).days

        if age_days <= 180:
            status = "fresh"
            summary = "Supporting evidence appears recent enough for normal submission use."
        elif age_days <= 365:
            status = "aging"
            summary = "Supporting evidence is aging and may need refreshed documentation."
        else:
            status = "stale"
            summary = "Supporting evidence appears stale and may weaken approval support."

        return {
            "status": status,
            "latest_evidence_date": latest.strftime("%m/%d/%Y"),
            "age_days": age_days,
            "summary": summary,
        }

    def build_evidence_escalation_recommendation(self, packet, coverage_mapping, contradictions, freshness_validation, weak_support, sufficiency):
        recommendations = []

        if sufficiency.get("status") == "insufficient":
            recommendations.append("Escalate for stronger clinical support before submission.")

        if contradictions.get("summary", {}).get("critical_contradictions"):
            recommendations.append("Resolve contradictory evidence before relying on the current packet narrative.")

        if freshness_validation.get("status") == "stale":
            recommendations.append("Request updated clinical notes or refreshed supporting documentation.")

        for gap in weak_support.get("requirement_gaps", []):
            if gap.get("status") != "missing":
                continue
            requirement = str(gap.get("requirement")).replace("_", " ")
            recommendations.append(f"Add stronger evidence for {requirement}.")

        if "lomn" not in packet.detected_documents and packet.fields.get("procedure"):
            recommendations.append("Add a Letter of Medical Necessity to strengthen the medical necessity story.")

        if "clinical_notes" not in packet.detected_documents:
            recommendations.append("Add current clinical notes to support diagnosis, symptoms, and treatment need.")

        return {
            "level": "high" if recommendations else "low",
            "recommendations": recommendations[:6],
        }

    def build_evidence_narrative_assembly(self, packet, relevance_ranking, sufficiency, contradictions, freshness_validation, weak_support):
        strongest_documents = [item.get("document_type") for item in relevance_ranking[:3] if item.get("document_type")]
        phrases = []

        if strongest_documents:
            phrases.append(f"Primary supporting evidence comes from {', '.join(strongest_documents)}.")

        if packet.fields.get("diagnosis") and packet.fields.get("icd_codes"):
            phrases.append("Diagnosis and coding evidence are present in the packet.")

        if packet.fields.get("reason_for_request"):
            phrases.append("A reason-for-request narrative is available to support the requested care.")

        if contradictions.get("summary", {}).get("contradiction_count"):
            phrases.append("Conflicting evidence remains and weakens the overall submission story.")

        if freshness_validation.get("status") in {"aging", "stale"}:
            phrases.append("Evidence recency may need attention before submission.")

        if weak_support.get("summary", {}).get("high_priority_gaps"):
            phrases.append("High-priority support gaps still need stronger documentation.")

        if not phrases:
            phrases.append("Current evidence is limited, so the submission story remains thin.")

        focus = []
        if sufficiency.get("status") != "likely_sufficient":
            focus.append("Tighten the clinical support around the requested service and its medical necessity.")
        if "authorization_number" not in packet.fields:
            focus.append("Add or verify authorization support.")
        if "referring_provider" not in packet.fields:
            focus.append("Capture the referring provider to improve routing support.")

        return {
            "summary": " ".join(phrases[:4]),
            "support_story": phrases[:6],
            "recommended_focus": focus[:4],
        }

    def build_fallback_spans(self, packet):
        spans = []
        for index, document_type in enumerate(sorted(packet.detected_documents), start=1):
            spans.append({
                "span_id": index,
                "document_type": document_type,
                "start_page": None,
                "end_page": None,
                "page_count": None,
                "average_confidence": 0.6,
            })
        return spans

    def get_document_support_fields(self, packet, document_type):
        support_fields = []
        for field, mapping in (packet.field_mappings or {}).items():
            if mapping.get("document_type") != document_type:
                continue
            if packet.fields.get(field) in (None, "", []):
                continue
            support_fields.append(field)
        return sorted(set(support_fields))

    def band_from_score(self, score):
        if score >= 0.78:
            return "strong"
        if score >= 0.52:
            return "moderate"
        return "weak"

    def page_range_label(self, start_page, end_page):
        if start_page and end_page:
            if start_page == end_page:
                return f"page {start_page}"
            return f"pages {start_page}-{end_page}"
        return None

    def parse_date(self, value):
        cleaned = str(value or "").strip()
        if not cleaned:
            return None

        cleaned = re.sub(r"(\d{1,2})(st|nd|rd|th)\b", r"\1", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s+", " ", cleaned.replace("-", "/")).strip()

        for fmt in (
            "%m/%d/%Y",
            "%m/%d/%y",
            "%Y/%m/%d",
            "%B %d, %Y",
            "%b %d, %Y",
            "%B %d %Y",
            "%b %d %Y",
        ):
            try:
                return datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

        return None

    def serialize_value(self, value):
        if isinstance(value, tuple):
            return [self.serialize_value(item) for item in value]
        if isinstance(value, list):
            return [self.serialize_value(item) for item in value]
        if isinstance(value, dict):
            return {str(key): self.serialize_value(item) for key, item in value.items()}
        return value
