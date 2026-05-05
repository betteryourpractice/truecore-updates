import hashlib
import re
from difflib import SequenceMatcher

from TrueCoreIntel.detection.document_intelligence import DocumentIntelligenceAnalyzer
from TrueCoreIntel.detection.form_templates import FORM_TEMPLATES


class DocumentDetector:
    """
    Hybrid VA packet detector:
    - works on messy PDF text
    - uses strong phrase matches first
    - falls back to weighted keyword scoring
    - avoids generic false positives
    """

    STRONG_PATTERNS = {
        doc_type: template.get("strong_patterns", [])
        for doc_type, template in FORM_TEMPLATES.items()
    }

    TITLE_PATTERNS = {
        doc_type: template.get("title_patterns", [])
        for doc_type, template in FORM_TEMPLATES.items()
    }

    ANCHOR_GROUP_THRESHOLDS = {
        doc_type: int(template.get("anchor_group_threshold", 2) or 2)
        for doc_type, template in FORM_TEMPLATES.items()
    }

    KEYWORD_WEIGHTS = {
        "cover_sheet": {
            "submission cover sheet": 8,
            "documents included": 5,
            "date of submission": 4,
            "primary diagnosis code": 4,
        },
        "consent": {
            "virtual consent form": 6,
            "telehealth consent": 6,
            "consent for medical care and treatment": 6,
            "patient signature": 3,
        },
        "consult_request": {
            "consultation and treatment request": 7,
            "reason for consultation": 5,
            "requested services": 5,
            "medical rationale": 4,
            "referring va provider": 4,
            "duration and scope of care": 4,
        },
        "seoc": {
            "single episode of care": 7,
            "seoc": 6,
            "scope of requested episode": 5,
            "estimated duration of episode": 5,
            "continuity of care": 4,
        },
        "lomn": {
            "letter of medical necessity": 8,
            "necessity": 5,
            "medical necessity": 5,
            "medically reasonable and necessary": 5,
            "clinical summary": 4,
            "to whom it may concern": 3,
        },
        "rfs": {
            "10-10172": 7,
            "10172": 6,
            "va form": 3,
            "request for service": 6,
            "va authorization number": 5,
            "diagnosis codes (icd-10)": 5,
            "community care provider": 4,
            "ordering provider signature": 4,
        },
        "clinical_notes": {
            "clinical documentation template": 6,
            "history of present illness": 4,
            "chief complaint": 3,
            "assessment": 3,
            "treatment plan": 3,
            "physical exam": 3,
            "encounter performed and documented": 4,
        },
        "imaging_report": {
            "mri report": 7,
            "lumbar spine mri report": 7,
            "radiology report": 6,
            "imaging report": 5,
            "findings": 3,
            "impression": 3,
            "study date": 2,
        },
        "conservative_care_summary": {
            "conservative care summary": 7,
            "conservative treatment summary": 7,
            "prior conservative therapy documentation": 3,
        },
    }

    PACKET_LEVEL_HINT_PATTERNS = {
        doc_type: template.get("packet_level_patterns", [])
        for doc_type, template in FORM_TEMPLATES.items()
    }

    STRUCTURE_SIGNATURES = {
        doc_type: template.get("structure_signatures", [])
        for doc_type, template in FORM_TEMPLATES.items()
    }

    NEGATIVE_PATTERNS = {
        doc_type: template.get("negative_patterns", [])
        for doc_type, template in FORM_TEMPLATES.items()
    }

    ANCHOR_GROUPS = {
        doc_type: template.get("anchor_groups", [])
        for doc_type, template in FORM_TEMPLATES.items()
    }

    HEADER_HINT_PRIORITY = {
        "unknown": 0,
        "clinical_notes": 1,
        "consult_request": 2,
        "lomn": 2,
        "rfs": 2,
        "seoc": 2,
        "cover_sheet": 2,
        "consent": 2,
    }

    FIELD_HINTS = {
        "name": ["veteran name", "patient name", "full name", "member name"],
        "dob": ["date of birth", "birth date", "dob", "d.o.b."],
        "provider": ["provider name", "provider", "rendering provider", "treating provider"],
        "ordering_provider": ["ordering provider", "ordering physician", "ordered by", "requested by"],
        "referring_provider": ["referring provider", "referring va provider", "referred by", "ref provider", "pcp"],
        "authorization_number": ["authorization number", "auth number", "auth #", "referral number", "member id", "reference number", "tracking number"],
        "va_icn": ["va icn", "integrated control number", "icn"],
        "claim_number": ["claim number", "claim #", "va claim number", "last four ssn", "ssn ending"],
        "service_date_range": ["date of service", "dates of service", "service date", "visit date", "dos"],
        "reason_for_request": ["reason for request", "reason for referral", "chief complaint", "requested service", "requested procedure"],
        "facility": ["facility", "servicing facility", "treating facility", "requested facility", "facility name"],
        "clinic_name": ["submitting office", "office name", "practice name", "clinic name"],
        "location": ["office location", "clinic location", "facility location", "city/state", "city, state"],
        "npi": ["npi"],
        "diagnosis": ["diagnosis", "assessment", "impression", "clinical impression"],
        "icd_codes": ["icd", "icd-10", "diagnosis code"],
        "medications": ["medications", "current meds", "current medications"],
        "signature_present": ["signature", "signed by", "electronically signed"],
        "symptom": ["chief complaint", "history of present illness"],
        "procedure": ["requested procedure", "procedure", "cpt"],
    }

    FIELD_ZONE_DOCUMENT_HINTS = {
        "cover_sheet": [
            "submission cover sheet",
            "date of submission",
            "submission date",
            "primary diagnosis code",
            "documents included",
            "submitting office",
        ],
        "consent": [
            "virtual consent",
            "telehealth consent",
            "consent for medical care and treatment",
            "appointment confirmation method",
            "patient signature",
        ],
        "consult_request": [
            "consultation and treatment request",
            "referring va provider",
            "requested services",
            "reason for consultation",
            "medical rationale",
        ],
        "seoc": [
            "single episode of care",
            "scope of requested episode",
            "estimated duration of episode",
            "continuity of care",
        ],
        "lomn": [
            "letter of medical necessity",
            "medical necessity",
            "clinical summary",
            "medically reasonable and necessary",
        ],
        "rfs": [
            "10-10172",
            "request for service",
            "va authorization number",
            "diagnosis codes",
            "ordering provider signature",
            "community care",
        ],
        "clinical_notes": [
            "clinical documentation template",
            "chief complaint",
            "history of present illness",
            "physical exam",
            "assessment",
            "treatment plan",
        ],
        "imaging_report": [
            "mri report",
            "radiology report",
            "study date",
            "findings",
            "impression",
        ],
        "conservative_care_summary": [
            "conservative care summary",
            "conservative treatment summary",
            "home exercise program",
            "activity modification",
            "structured physical therapy",
        ],
    }

    def __init__(self):
        self.document_intelligence_analyzer = DocumentIntelligenceAnalyzer()

    def get_page_metadata(self, packet, page_index):
        page_metadata = list(getattr(packet, "page_metadata", []) or [])
        if page_index < len(page_metadata):
            return page_metadata[page_index]
        return {}

    def count_filled_consent_signals(self, text):
        filled_patterns = [
            r"full name[^\n\r:]{0,40}:\s*(?!date of birth\b|state\b|street address\b|home phone\b|email address\b|email\b|city\b|mobile phone\b|ssn\b|phone\b|zip\b|work phone\b)([A-Za-z][A-Za-z'\-]+(?:\s+[A-Za-z][A-Za-z'\-]+){1,3})",
            r"date of birth[^\n\r:]{0,40}:\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}",
            r"street address[^\n\r:]{0,40}:\s*\d{1,6}\s+[A-Za-z0-9.\- ]{3,}",
            r"(?:home phone|mobile phone|work phone|phone)[^\n\r:]{0,40}:\s*(?:\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}|\d{7,})",
            r"email(?: address)?[^\n\r:]{0,40}:\s*[\w.\-]+@[\w.\-]+\.\w+",
            r"\b(?:signature|signed)\b",
        ]

        return sum(
            1 for pattern in filled_patterns
            if re.search(pattern, text, re.IGNORECASE)
        )

    def detect(self, packet):
        packet.document_types = {}
        packet.detected_documents = set()
        packet.page_confidence = {}
        packet.duplicate_pages = []
        packet.unfilled_documents = set()
        packet.document_intelligence = {}
        packet.document_confidence_map = {}
        packet.source_reliability_ranking = []
        packet.document_spans = []

        for idx, page in enumerate(packet.pages):
            page_metadata = self.get_page_metadata(packet, idx)
            doc_type, confidence = self.classify_page_with_confidence(page, page_metadata=page_metadata)
            packet.document_types[idx] = doc_type
            packet.page_confidence[idx] = confidence

            if doc_type != "unknown":
                if self.is_unfilled_document(doc_type, str(page)):
                    packet.unfilled_documents.add(doc_type)
                packet.detected_documents.add(doc_type)

        self.supplement_detected_documents(packet)
        self.propagate_document_context(packet)
        self.detect_duplicate_pages(packet)
        packet = self.document_intelligence_analyzer.analyze(packet)

        return packet

    def classify_page(self, page):
        return self.classify_page_with_confidence(page)[0]

    def classify_page_with_confidence(self, page, page_metadata=None):
        raw_text = str(page) if page is not None else ""
        text = self.normalize_page_text(page, page_metadata=page_metadata)

        if not text or len(text) < 40:
            return "unknown", self.estimate_unknown_confidence(text, page_metadata=page_metadata)

        if self.looks_like_cover_sheet(page, page_metadata=page_metadata):
            confidence = 0.96
            confidence = self.adjust_confidence_for_field_hints("cover_sheet", text, confidence)
            confidence = self.adjust_confidence_for_layout("cover_sheet", confidence, page_metadata)
            return "cover_sheet", min(0.99, confidence)

        title_hint = self.infer_document_type_from_title(page, page_metadata=page_metadata)
        if title_hint:
            doc_type, confidence = title_hint
            return doc_type, confidence

        # 1) Exact / strong match first
        strong_hits = {}
        for doc_type, patterns in self.STRONG_PATTERNS.items():
            hits = sum(
                1 for pattern in patterns
                if re.search(pattern, text, re.IGNORECASE)
            )
            if hits:
                strong_hits[doc_type] = {
                    "hits": hits,
                    "anchor_group_hits": self.count_anchor_group_hits(doc_type, text),
                    "field_hint_hits": self.count_template_field_hints(doc_type, text),
                }

        if strong_hits:
            # Prefer strongest hit count first, but still reject blank/template docs.
            ranked_hits = sorted(
                strong_hits.items(),
                key=lambda item: (
                    item[1]["hits"],
                    item[1]["anchor_group_hits"],
                    item[1]["field_hint_hits"],
                ),
                reverse=True,
            )
            max_hits = max(details["hits"] for details in strong_hits.values())
            for doc_type, _details in ranked_hits:
                if not self.should_skip_document(doc_type, raw_text):
                    confidence = min(0.99, 0.84 + (0.04 * max_hits))
                    confidence = self.adjust_confidence_for_anchor_groups(doc_type, text, confidence)
                    confidence = self.adjust_confidence_for_field_hints(doc_type, text, confidence)
                    confidence = self.adjust_confidence_for_layout(doc_type, confidence, page_metadata)
                    return doc_type, confidence

        structure_hint = self.infer_document_type_from_structure(text, page_metadata=page_metadata)
        if structure_hint:
            doc_type, confidence = structure_hint
            return doc_type, confidence

        zone_hint = self.infer_document_type_from_field_zones(page_metadata, text)
        if zone_hint:
            doc_type, confidence = zone_hint
            return doc_type, confidence

        anchor_hint = self.infer_document_type_from_anchor_groups(text, page_metadata=page_metadata)
        if anchor_hint:
            doc_type, confidence = anchor_hint
            return doc_type, confidence

        # 2) Fallback weighted keyword scoring
        scores = {}
        for doc_type, keywords in self.KEYWORD_WEIGHTS.items():
            score = 0
            for phrase, weight in keywords.items():
                if phrase in text:
                    score += weight

            if score > 0:
                scores[doc_type] = score

        if not scores:
            return "unknown", self.estimate_unknown_confidence(text, page_metadata=page_metadata)

        # Guardrails against fake positives
        scores = self.apply_guardrails(raw_text, text, scores)
        scores = self.apply_layout_signal_boosts(scores, page_metadata, text)

        if not scores:
            return "unknown", self.estimate_unknown_confidence(text, page_metadata=page_metadata)

        best_doc_type, best_score = max(scores.items(), key=lambda item: item[1])

        # Minimum thresholds by doc type
        thresholds = {
            "cover_sheet": 8,
            "consent": 7,
            "consult_request": 7,
            "seoc": 7,
            "lomn": 7,
            "rfs": 7,
            "clinical_notes": 6,
        }

        if best_score < thresholds.get(best_doc_type, 7):
            return "unknown", self.estimate_unknown_confidence(text, page_metadata=page_metadata)

        threshold = thresholds.get(best_doc_type, 7)
        margin = max(best_score - threshold, 0)
        confidence = min(0.95, 0.58 + (0.04 * margin))
        confidence = self.adjust_confidence_for_anchor_groups(best_doc_type, text, confidence)
        confidence = self.adjust_confidence_for_field_hints(best_doc_type, text, confidence)
        confidence = self.adjust_confidence_for_layout(best_doc_type, confidence, page_metadata)
        return best_doc_type, confidence

    def count_structure_signature_hits(self, doc_type, text):
        normalized_text = str(text or "")
        hits = 0
        for pattern in self.STRUCTURE_SIGNATURES.get(doc_type, []):
            if not pattern:
                continue
            if re.search(pattern, normalized_text, re.IGNORECASE):
                hits += 1
        return hits

    def infer_document_type_from_structure(self, text, page_metadata=None):
        normalized_text = str(text or "")
        if not normalized_text:
            return None

        scores = {}
        for doc_type, patterns in self.STRUCTURE_SIGNATURES.items():
            if not patterns:
                continue
            signature_hits = self.count_structure_signature_hits(doc_type, normalized_text)
            if not signature_hits:
                continue
            field_hint_hits = self.count_template_field_hints(doc_type, normalized_text)
            anchor_group_hits = self.count_anchor_group_hits(doc_type, normalized_text)
            scores[doc_type] = {
                "signature_hits": signature_hits,
                "field_hint_hits": field_hint_hits,
                "anchor_group_hits": anchor_group_hits,
            }

        if not scores:
            return None

        ranked = sorted(
            scores.items(),
            key=lambda item: (
                item[1]["signature_hits"],
                item[1]["anchor_group_hits"],
                item[1]["field_hint_hits"],
            ),
            reverse=True,
        )
        best_doc_type, best_details = ranked[0]
        signature_hits = best_details["signature_hits"]
        field_hint_hits = best_details["field_hint_hits"]
        anchor_group_hits = best_details["anchor_group_hits"]

        if not self.matches_family_fingerprint(best_doc_type, normalized_text):
            return None

        threshold = 3
        if best_doc_type in {"cover_sheet", "clinical_notes"}:
            threshold = 2

        if signature_hits < threshold and not (
            signature_hits >= 2 and (field_hint_hits >= 3 or anchor_group_hits >= 2)
        ):
            return None

        if len(ranked) > 1:
            next_details = ranked[1][1]
            if (
                signature_hits == next_details["signature_hits"]
                and anchor_group_hits == next_details["anchor_group_hits"]
                and field_hint_hits == next_details["field_hint_hits"]
            ):
                return None

        confidence = (
            0.62
            + (0.06 * min(signature_hits, 4))
            + (0.03 * min(anchor_group_hits, 3))
            + (0.02 * min(field_hint_hits, 3))
        )
        confidence = self.adjust_confidence_for_layout(best_doc_type, confidence, page_metadata)
        return best_doc_type, min(0.95, round(confidence, 2))

    def infer_document_type_from_field_zones(self, page_metadata, text):
        page_metadata = dict(page_metadata or {})
        normalized_text = str(text or "")
        field_zones = list(page_metadata.get("field_zones", []) or [])
        if not field_zones:
            return None

        labels = []
        for zone in field_zones:
            label = str(zone.get("normalized_label") or zone.get("label") or "").strip().lower()
            if label:
                labels.append(label)

        if not labels:
            return None

        scores = {}
        for doc_type, hints in self.FIELD_ZONE_DOCUMENT_HINTS.items():
            score = 0
            for hint in hints:
                if any(hint in label for label in labels):
                    score += 1
            if score:
                scores[doc_type] = score

        if not scores:
            return None

        best_doc_type, best_score = max(scores.items(), key=lambda item: item[1])
        if best_score < 2:
            return None

        if not self.matches_family_fingerprint(best_doc_type, normalized_text):
            return None

        confidence = 0.68 + (0.05 * min(best_score - 2, 3))
        confidence = self.adjust_confidence_for_layout(best_doc_type, confidence, page_metadata)
        if normalized_text and self.count_template_field_hints(best_doc_type, normalized_text) >= 2:
            confidence = min(0.94, confidence + 0.04)
        return best_doc_type, min(0.94, round(confidence, 2))

    def get_template_field_hints(self, doc_type):
        template = FORM_TEMPLATES.get(doc_type, {})
        hints = []
        for field_name in template.get("expected_fields", []):
            hints.extend(self.FIELD_HINTS.get(field_name, []))
        return hints

    def count_template_field_hints(self, doc_type, text):
        normalized_text = str(text or "")
        hits = 0
        for hint in dict.fromkeys(self.get_template_field_hints(doc_type)):
            if hint and hint in normalized_text:
                hits += 1
        return hits

    def count_title_pattern_hits(self, doc_type, title_text):
        normalized_title = str(title_text or "")
        hits = 0
        for pattern in self.TITLE_PATTERNS.get(doc_type, []):
            if pattern and re.search(pattern, normalized_title, re.IGNORECASE):
                hits += 1
        return hits

    def count_anchor_group_hits(self, doc_type, text):
        normalized_text = str(text or "")
        hits = 0
        for group in self.ANCHOR_GROUPS.get(doc_type, []):
            if any(term and term in normalized_text for term in group):
                hits += 1
        return hits

    def get_anchor_group_threshold(self, doc_type):
        return max(1, int(self.ANCHOR_GROUP_THRESHOLDS.get(doc_type, 2) or 2))

    def matches_family_fingerprint(self, doc_type, text, *, title_hits=0):
        normalized_text = str(text or "")
        if not normalized_text:
            return False

        anchor_group_hits = self.count_anchor_group_hits(doc_type, normalized_text)
        field_hint_hits = self.count_template_field_hints(doc_type, normalized_text)
        signature_hits = self.count_structure_signature_hits(doc_type, normalized_text)
        threshold = self.get_anchor_group_threshold(doc_type)

        # A solid title can lower the burden slightly, but only if the page also
        # contains document-family support beyond generic demographics.
        if title_hits and anchor_group_hits >= max(1, threshold - 1):
            return True

        if anchor_group_hits >= threshold and (signature_hits >= 1 or field_hint_hits >= 2):
            return True

        if anchor_group_hits >= threshold + 1:
            return True

        if doc_type == "clinical_notes" and signature_hits >= 3 and field_hint_hits >= 2:
            return True

        return False

    def extract_title_region_text(self, page, page_metadata=None):
        page_metadata = dict(page_metadata or {})
        layout = dict(page_metadata.get("layout", {}) or {})
        header_text = str(layout.get("header_text") or "").strip().lower()
        normalized_text = self.normalize_page_text(page, page_metadata=page_metadata)
        return " ".join(part for part in [header_text[:300], normalized_text[:500]] if part).strip()

    def infer_document_type_from_title(self, page, page_metadata=None):
        title_text = self.extract_title_region_text(page, page_metadata=page_metadata)
        if not title_text:
            return None

        normalized_text = self.normalize_page_text(page, page_metadata=page_metadata)
        if not normalized_text:
            return None

        candidates = {}
        for doc_type in FORM_TEMPLATES:
            title_hits = self.count_title_pattern_hits(doc_type, title_text)
            if not title_hits:
                continue
            anchor_group_hits = self.count_anchor_group_hits(doc_type, title_text)
            field_hint_hits = self.count_template_field_hints(doc_type, title_text)
            candidates[doc_type] = {
                "title_hits": title_hits,
                "anchor_group_hits": anchor_group_hits,
                "field_hint_hits": field_hint_hits,
            }

        if not candidates:
            return None

        ranked = sorted(
            candidates.items(),
            key=lambda item: (
                item[1]["title_hits"],
                item[1]["anchor_group_hits"],
                item[1]["field_hint_hits"],
            ),
            reverse=True,
        )
        best_doc_type, best_details = ranked[0]
        anchor_group_hits = best_details["anchor_group_hits"]
        field_hint_hits = best_details["field_hint_hits"]

        if not self.matches_family_fingerprint(
            best_doc_type,
            normalized_text,
            title_hits=best_details["title_hits"],
        ):
            return None

        confidence = 0.88 + (0.02 * min(best_details["title_hits"], 2))
        confidence += 0.02 * min(anchor_group_hits, 3)
        confidence += 0.01 * min(field_hint_hits, 3)
        confidence = self.adjust_confidence_for_layout(best_doc_type, confidence, page_metadata)
        return best_doc_type, min(0.99, round(confidence, 2))

    def infer_document_type_from_anchor_groups(self, text, page_metadata=None):
        normalized_text = str(text or "")
        if not normalized_text:
            return None

        scores = {}
        for doc_type in FORM_TEMPLATES:
            anchor_group_hits = self.count_anchor_group_hits(doc_type, normalized_text)
            if not anchor_group_hits:
                continue
            field_hint_hits = self.count_template_field_hints(doc_type, normalized_text)
            scores[doc_type] = {
                "anchor_group_hits": anchor_group_hits,
                "field_hint_hits": field_hint_hits,
            }

        if not scores:
            return None

        ranked = sorted(
            scores.items(),
            key=lambda item: (
                item[1]["anchor_group_hits"],
                item[1]["field_hint_hits"],
            ),
            reverse=True,
        )
        best_doc_type, best_details = ranked[0]
        anchor_group_hits = best_details["anchor_group_hits"]
        field_hint_hits = best_details["field_hint_hits"]

        if not self.matches_family_fingerprint(best_doc_type, normalized_text):
            return None

        if len(ranked) > 1:
            next_details = ranked[1][1]
            if (
                anchor_group_hits == next_details["anchor_group_hits"]
                and field_hint_hits == next_details["field_hint_hits"]
            ):
                return None

        confidence = 0.64 + (0.05 * min(anchor_group_hits, 4)) + (0.02 * min(field_hint_hits, 3))
        confidence = self.adjust_confidence_for_layout(best_doc_type, confidence, page_metadata)
        return best_doc_type, min(0.93, round(confidence, 2))

    def adjust_confidence_for_field_hints(self, doc_type, text, base_confidence):
        field_hint_hits = self.count_template_field_hints(doc_type, text)
        if field_hint_hits >= 4:
            return min(0.99, base_confidence + 0.08)
        if field_hint_hits >= 2:
            return min(0.98, base_confidence + 0.04)
        if field_hint_hits == 1:
            return min(0.97, base_confidence + 0.02)
        return max(0.4, base_confidence - 0.03)

    def adjust_confidence_for_anchor_groups(self, doc_type, text, base_confidence):
        anchor_group_hits = self.count_anchor_group_hits(doc_type, text)
        if anchor_group_hits >= 4:
            return min(0.99, base_confidence + 0.08)
        if anchor_group_hits >= 2:
            return min(0.98, base_confidence + 0.05)
        if anchor_group_hits == 1:
            return min(0.97, base_confidence + 0.02)
        return base_confidence

    def estimate_unknown_confidence(self, text, page_metadata=None):
        if not text:
            return 0.1

        page_metadata = dict(page_metadata or {})
        layout = dict(page_metadata.get("layout", {}) or {})
        field_zone_count = len(page_metadata.get("field_zones", []) or [])

        if len(text) < 120:
            confidence = 0.2
        else:
            confidence = 0.35

        if field_zone_count >= 4:
            confidence += 0.08
        if layout.get("header_text"):
            confidence += 0.04
        if layout.get("table_regions"):
            confidence += 0.04

        return min(0.55, round(confidence, 2))

    def adjust_confidence_for_layout(self, doc_type, confidence, page_metadata):
        page_metadata = dict(page_metadata or {})
        layout = dict(page_metadata.get("layout", {}) or {})
        field_zones = list(page_metadata.get("field_zones", []) or [])
        zone_labels = {str(zone.get("normalized_label") or "").lower() for zone in field_zones}

        if layout.get("header_text"):
            confidence += 0.02

        if doc_type in {"rfs", "consult_request", "seoc", "cover_sheet"} and len(field_zones) >= 4:
            confidence += 0.05

        if doc_type == "clinical_notes" and layout.get("signature_regions"):
            confidence += 0.03

        if doc_type == "rfs" and any("authorization" in label or "box 4" in label for label in zone_labels):
            confidence += 0.06

        if doc_type == "consent" and page_metadata.get("ocr_confidence", 0.0) < 55:
            confidence -= 0.03

        return min(0.99, max(0.15, round(confidence, 2)))

    def apply_layout_signal_boosts(self, scores, page_metadata, normalized_text):
        if not scores:
            return scores

        page_metadata = dict(page_metadata or {})
        layout = dict(page_metadata.get("layout", {}) or {})
        field_zones = list(page_metadata.get("field_zones", []) or [])
        zone_labels = [str(zone.get("normalized_label") or "").lower() for zone in field_zones]
        header_text = str(layout.get("header_text") or "").lower()

        boosted = dict(scores)

        if any("authorization" in label or "box 4" in label for label in zone_labels):
            boosted["rfs"] = boosted.get("rfs", 0) + 3

        if any("reason for request" in label or "requested service" in label for label in zone_labels):
            boosted["consult_request"] = boosted.get("consult_request", 0) + 2

        if layout.get("table_regions") and len(field_zones) >= 5:
            boosted["rfs"] = boosted.get("rfs", 0) + 2
            boosted["cover_sheet"] = boosted.get("cover_sheet", 0) + 1

        if layout.get("signature_regions") and any(term in normalized_text for term in ["assessment", "plan", "history of present illness"]):
            boosted["clinical_notes"] = boosted.get("clinical_notes", 0) + 1
            boosted["lomn"] = boosted.get("lomn", 0) + 1

        if "10-10172" in header_text or "request for service" in header_text:
            boosted["rfs"] = boosted.get("rfs", 0) + 3

        return boosted

    def apply_guardrails(self, raw_text, text, scores):
        filtered = dict(scores)

        if self.looks_like_cover_sheet(raw_text):
            filtered["cover_sheet"] = max(filtered.get("cover_sheet", 0), 12)
            for doc_type in ("rfs", "consult_request", "consent", "seoc", "lomn"):
                filtered.pop(doc_type, None)

        for doc_type, patterns in self.NEGATIVE_PATTERNS.items():
            if doc_type not in filtered:
                continue
            if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns if pattern):
                filtered.pop(doc_type, None)

        if "consent" in filtered and self.should_skip_document("consent", raw_text):
            filtered.pop("consent", None)

        for doc_type in list(filtered):
            if not self.matches_family_fingerprint(doc_type, text):
                filtered.pop(doc_type, None)

        # cover sheet must not be generic admin garbage
        if "cover_sheet" in filtered:
            if "submission" not in text or "cover" not in text or "sheet" not in text:
                filtered.pop("cover_sheet", None)

        # seoc must really look like SEOC
        if "seoc" in filtered:
            if "seoc" not in text and not (
                "single" in text and "episode" in text and "care" in text
            ):
                filtered.pop("seoc", None)

        # consult_request should have request/provider language
        if "consult_request" in filtered:
            provider_or_request = any(
                term in text for term in [
                    "consultation",
                    "consult",
                    "treatment request",
                    "referring va provider",
                    "ordering provider",
                    "requested service",
                ]
            )
            if not provider_or_request:
                filtered.pop("consult_request", None)

        # lomn should really have necessity/request language
        if "lomn" in filtered:
            necessity_language = any(
                term in text for term in [
                    "medical necessity",
                    "letter of medical necessity",
                    "reason for request",
                    "chief complaint",
                    "requested service",
                ]
            )
            if not necessity_language and filtered.get("lomn", 0) < 8:
                filtered.pop("lomn", None)

        # rfs should have actual form or request/service language
        if "rfs" in filtered:
            rfs_language = any(
                term in text for term in [
                    "10-10172",
                    "10172",
                    "va form",
                    "request for service",
                    "authorization",
                    "referral",
                    "member id",
                ]
            )
            if not rfs_language and filtered.get("rfs", 0) < 8:
                filtered.pop("rfs", None)

        # clinical notes should have actual clinical content
        if "clinical_notes" in filtered:
            clinical_support = sum(
                1 for term in [
                    "diagnosis",
                    "icd",
                    "assessment",
                    "impression",
                    "plan",
                    "physical exam",
                    "history of present illness",
                ]
                if term in text
            )
            if clinical_support < 2 and "clinical" not in text and "notes" not in text:
                filtered.pop("clinical_notes", None)

        if "consent" in filtered:
            consent_language = any(
                term in text for term in [
                    "telehealth consent",
                    "consent for medical care and treatment",
                    "consent to participate in telehealth sessions",
                    "interactive video connection",
                ]
            )
            if not consent_language:
                filtered.pop("consent", None)

        return filtered

    def normalize_page_text(self, page, page_metadata=None):
        text = str(page) if page is not None else ""
        page_metadata = dict(page_metadata or {})

        layout = dict(page_metadata.get("layout", {}) or {})
        discovery_text = page_metadata.get("document_discovery_text")
        field_zone_lines = []
        for zone in page_metadata.get("field_zones", []) or []:
            label = str(zone.get("label") or zone.get("normalized_label") or "").strip()
            value = str(zone.get("value") or "").strip()
            if label and value:
                field_zone_lines.append(f"{label}: {value}")

        extra_parts = [
            layout.get("header_text"),
            layout.get("left_column_text"),
            layout.get("right_column_text"),
            discovery_text,
            "\n".join(field_zone_lines),
            page_metadata.get("ocr_text"),
        ]
        extra_text = "\n".join(part for part in extra_parts if part)
        if extra_text:
            text = f"{text}\n{extra_text}" if text else extra_text

        if not text:
            return ""

        text = text.replace("\r", "\n")
        text = re.sub(r"(?<=\w)-\n(?=\w)", "", text)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{2,}", "\n", text)
        text = " ".join(text.split())

        return text.lower().strip()

    def supplement_detected_documents(self, packet):
        for idx, page in enumerate(packet.pages):
            current_doc_type = packet.document_types.get(idx, "unknown")
            page_metadata = self.get_page_metadata(packet, idx)
            normalized_text = self.normalize_page_text(page, page_metadata=page_metadata)

            header = self.extract_page_header(page, page_metadata=page_metadata)
            if header:
                hinted_doc = self.find_packet_level_document_hint(header)
                if hinted_doc:
                    if self.should_skip_document(hinted_doc, str(page)):
                        packet.unfilled_documents.add(hinted_doc)
                    else:
                        if self.is_unfilled_document(hinted_doc, str(page)):
                            packet.unfilled_documents.add(hinted_doc)
                        packet.detected_documents.add(hinted_doc)

                        if self.should_apply_header_hint(current_doc_type, hinted_doc):
                            packet.document_types[idx] = hinted_doc
                            packet.page_confidence[idx] = max(packet.page_confidence.get(idx, 0.0), 0.88)
                            current_doc_type = hinted_doc

            if current_doc_type == "unknown":
                structure_hint = self.infer_document_type_from_structure(normalized_text, page_metadata=page_metadata)
                if structure_hint:
                    hinted_doc, confidence = structure_hint
                    packet.document_types[idx] = hinted_doc
                    packet.page_confidence[idx] = max(packet.page_confidence.get(idx, 0.0), confidence)
                    packet.detected_documents.add(hinted_doc)
                    current_doc_type = hinted_doc

            if current_doc_type == "unknown":
                anchor_hint = self.infer_document_type_from_anchor_groups(normalized_text, page_metadata=page_metadata)
                if anchor_hint:
                    hinted_doc, confidence = anchor_hint
                    packet.document_types[idx] = hinted_doc
                    packet.page_confidence[idx] = max(packet.page_confidence.get(idx, 0.0), confidence)
                    packet.detected_documents.add(hinted_doc)
                    current_doc_type = hinted_doc

            if self.looks_like_clinical_notes(page, page_metadata=page_metadata):
                packet.detected_documents.add("clinical_notes")

                if current_doc_type == "unknown":
                    packet.document_types[idx] = "clinical_notes"
                    packet.page_confidence[idx] = max(packet.page_confidence.get(idx, 0.0), 0.78)

            if self.looks_like_rfs_form(page, page_metadata=page_metadata):
                packet.detected_documents.add("rfs")

                if current_doc_type == "unknown":
                    packet.document_types[idx] = "rfs"
                    packet.page_confidence[idx] = max(packet.page_confidence.get(idx, 0.0), 0.8)

    def propagate_document_context(self, packet):
        page_count = len(packet.pages)
        if page_count < 3:
            return

        index = 0
        while index < page_count:
            if packet.document_types.get(index, "unknown") != "unknown":
                index += 1
                continue

            run_start = index
            while index < page_count and packet.document_types.get(index, "unknown") == "unknown":
                index += 1
            run_end = index - 1

            previous_doc = packet.document_types.get(run_start - 1, "unknown") if run_start > 0 else "unknown"
            next_doc = packet.document_types.get(run_end + 1, "unknown") if run_end + 1 < page_count else "unknown"

            if previous_doc == "unknown" or previous_doc != next_doc:
                continue

            if not self.run_is_low_information(packet, run_start, run_end):
                continue

            for page_index in range(run_start, run_end + 1):
                packet.document_types[page_index] = previous_doc
                packet.page_confidence[page_index] = max(packet.page_confidence.get(page_index, 0.0), 0.64)
                packet.detected_documents.add(previous_doc)

    def run_is_low_information(self, packet, run_start, run_end):
        for page_index in range(run_start, run_end + 1):
            page = packet.pages[page_index]
            page_metadata = self.get_page_metadata(packet, page_index)
            text = self.normalize_page_text(page, page_metadata=page_metadata)
            field_zone_count = len(page_metadata.get("field_zones", []) or [])
            layout = dict(page_metadata.get("layout", {}) or {})

            if len(text) > 320:
                return False

            if field_zone_count > 4:
                return False

            if layout.get("header_text") and len(str(layout.get("header_text") or "")) > 40:
                return False

        return True

    def extract_page_header(self, page, page_metadata=None):
        page_metadata = dict(page_metadata or {})
        header_text = str((page_metadata.get("layout", {}) or {}).get("header_text") or "").strip()
        if header_text:
            return header_text[:500].lower().strip()

        text = str(page) if page is not None else ""
        if not text:
            return ""

        text = text.replace("\r", "\n")
        text = re.sub(r"(?<=\w)-\n(?=\w)", "", text)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{2,}", "\n", text)
        text = " ".join(text.split())

        return text[:500].lower().strip()

    def find_packet_level_document_hint(self, header_text):
        best_match = None
        for doc_type, patterns in self.PACKET_LEVEL_HINT_PATTERNS.items():
            doc_match = None
            for pattern in patterns:
                match = re.search(pattern, header_text, re.IGNORECASE)
                if match and (doc_match is None or match.start() < doc_match.start()):
                    doc_match = match

            if not doc_match:
                continue

            candidate = (
                doc_match.start(),
                -self.HEADER_HINT_PRIORITY.get(doc_type, 0),
                doc_type,
            )
            if best_match is None or candidate < best_match:
                best_match = candidate

        return best_match[2] if best_match else None

    def should_apply_header_hint(self, current_doc_type, hinted_doc_type):
        return self.HEADER_HINT_PRIORITY.get(hinted_doc_type, 0) > self.HEADER_HINT_PRIORITY.get(current_doc_type, 0)

    def looks_like_clinical_notes(self, page, page_metadata=None):
        text = self.normalize_page_text(page, page_metadata=page_metadata)

        if not text or len(text) < 120:
            return False
        return self.matches_family_fingerprint("clinical_notes", text)

    def looks_like_rfs_form(self, page, page_metadata=None):
        text = self.normalize_page_text(page, page_metadata=page_metadata)

        if not text or len(text) < 120:
            return False

        if self.looks_like_cover_sheet(page, page_metadata=page_metadata):
            return False
        return self.matches_family_fingerprint("rfs", text)

    def looks_like_cover_sheet(self, page, page_metadata=None):
        text = self.normalize_page_text(page, page_metadata=page_metadata)
        if not text:
            return False

        strong_title = "submission cover sheet" in text
        if not strong_title:
            return False

        return self.matches_family_fingerprint("cover_sheet", text, title_hits=1)

    def should_skip_document(self, doc_type, page_text):
        return False

    def is_unfilled_document(self, doc_type, page_text):
        if doc_type == "consent":
            return self.looks_like_unfilled_consent(page_text)

        if doc_type == "consult_request":
            return self.looks_like_unfilled_consult_request(page_text)

        if doc_type == "clinical_notes":
            return self.looks_like_unfilled_clinical_notes(page_text)

        return False

    def looks_like_unfilled_consent(self, page_text):
        text = " ".join(str(page_text or "").replace("\r", "\n").split())
        lower_text = text.lower()

        consent_markers = [
            "virtual consent",
            "telehealth consent",
            "consent for treatment",
            "consent form",
        ]

        if not any(marker in lower_text for marker in consent_markers):
            return False

        return self.count_filled_consent_signals(text) < 2

    def looks_like_unfilled_consult_request(self, page_text):
        text = " ".join(str(page_text or "").replace("\r", "\n").split())
        lower_text = text.lower()

        if "consultation and treatment request" not in lower_text:
            return False

        blank_sequence_patterns = [
            r"veteran name:\s*dob:\s*last four ssn:\s*va claim number:\s*referring va provider:",
            r"veteran name:\s*dob:\s*last four ssn:",
            r"va claim number:\s*referring va provider:",
        ]
        has_blank_shell = any(re.search(pattern, lower_text) for pattern in blank_sequence_patterns)

        has_patient_fill = bool(
            re.search(
                r"veteran name:\s*(?!dob:|last four ssn:|va claim number:|referring va provider:)([A-Za-z][A-Za-z'\-]+(?:\s+[A-Za-z][A-Za-z'\-]+){1,3})",
                text,
                re.IGNORECASE,
            )
        )
        has_dob_fill = bool(re.search(r"\bdob:\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", text, re.IGNORECASE))
        has_ref_provider_fill = bool(
            re.search(
                r"referring va provider:\s*(?!evaluation\b|diagnoses\b|authorization\b)([A-Za-z][^\n\r]{3,})",
                text,
                re.IGNORECASE,
            )
        )

        return has_blank_shell and not (has_patient_fill and has_dob_fill and has_ref_provider_fill)

    def looks_like_unfilled_clinical_notes(self, page_text):
        text = " ".join(str(page_text or "").replace("\r", "\n").split())
        lower_text = text.lower()

        if "clinical documentation template" not in lower_text:
            return False

        blank_markers = [
            r"pain severity\s*\(0.?10\)\s*:\s*iii\.",
            r"describe specific functional impact:\s*m conservative therapy history",
            r"mri date:\s*findings:\s*affected levels:",
            r"diagnosis:\s*primary:\s*secondary",
        ]
        blank_hits = sum(1 for pattern in blank_markers if re.search(pattern, lower_text))

        return blank_hits >= 1

    def detect_duplicate_pages(self, packet):
        fingerprints = {}
        candidate_pages = {}

        for idx, page in enumerate(packet.pages):
            normalized = self.normalize_page_text(page)
            doc_type = packet.document_types.get(idx, "unknown")
            if len(normalized) < 80:
                continue
            if doc_type == "unknown" and len(normalized) < 250:
                continue

            fingerprint = hashlib.sha1(normalized.encode("utf-8")).hexdigest()
            fingerprints.setdefault(fingerprint, []).append(idx)
            candidate_pages[idx] = {
                "doc_type": doc_type,
                "normalized": normalized,
                "comparison_text": self.build_duplicate_comparison_text(normalized),
            }

        duplicates = []
        grouped_pages = set()
        for indices in fingerprints.values():
            if len(indices) < 2:
                continue

            doc_types = [packet.document_types.get(index, "unknown") for index in indices]
            if all(doc_type == "unknown" for doc_type in doc_types):
                continue
            concrete_doc_types = {doc_type for doc_type in doc_types if doc_type != "unknown"}
            if len(concrete_doc_types) > 1:
                continue

            # Ignore exact-duplicate clusters that are only short header stubs.
            normalized_lengths = [
                len(candidate_pages.get(index, {}).get("normalized", ""))
                for index in indices
            ]
            if normalized_lengths and max(normalized_lengths) < 220:
                continue
            if not all(
                self.has_substantive_duplicate_content(
                    candidate_pages.get(index, {}).get("doc_type", "unknown"),
                    candidate_pages.get(index, {}).get("normalized", ""),
                    candidate_pages.get(index, {}).get("comparison_text", ""),
                )
                for index in indices
            ):
                continue

            duplicates.append({
                "page_indices": indices,
                "document_types": doc_types,
                "match_type": "exact",
            })
            grouped_pages.update(indices)

        duplicates.extend(self.find_fuzzy_duplicate_groups(packet, candidate_pages, grouped_pages))

        packet.duplicate_pages = duplicates
        if duplicates:
            packet.links["duplicate_pages"] = duplicates

    def build_duplicate_comparison_text(self, normalized_text):
        text = str(normalized_text or "")
        text = re.sub(
            r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2}|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*|\s+)\d{4})\b",
            " DATE ",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(r"\b[a-z]*\d[a-z0-9\-]{4,}\b", " ID ", text, flags=re.IGNORECASE)
        text = re.sub(r"\b\d{3,}\b", " NUM ", text)
        text = re.sub(r"\bdate of birth\b", " dob ", text, flags=re.IGNORECASE)
        text = re.sub(r"\bfollow[\s\-]+up\b", " followup ", text, flags=re.IGNORECASE)
        text = re.sub(r"[^a-z0-9 ]", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def has_substantive_duplicate_content(self, doc_type, normalized_text, comparison_text):
        normalized_text = str(normalized_text or "").lower()
        comparison_text = str(comparison_text or "").lower()
        token_count = len(set(comparison_text.split()))

        if len(normalized_text) >= 450 and token_count >= 28:
            return True

        template = FORM_TEMPLATES.get(doc_type, {}) or {}
        anchor_candidates = []
        for group in template.get("anchor_groups", []):
            if isinstance(group, dict):
                anchor_candidates.extend(group.get("patterns", []))
            elif isinstance(group, (list, tuple, set)):
                anchor_candidates.extend(group)
        anchor_candidates.extend(template.get("structure_signatures", []))

        body_hits = 0
        seen = set()
        for candidate in anchor_candidates:
            candidate_text = str(candidate or "").strip().lower()
            if len(candidate_text) < 6 or candidate_text in seen:
                continue
            seen.add(candidate_text)
            if candidate_text in normalized_text:
                body_hits += 1
                if body_hits >= 2:
                    return True

        fallback_markers = {
            "consent": ["telehealth", "consent", "treatment", "appointment", "signature", "emergency contact", "insurance"],
            "clinical_notes": ["history of present illness", "assessment", "treatment plan", "imaging", "conservative therapy"],
            "lomn": ["medical necessity", "medically reasonable", "conservative treatment", "intervention"],
            "consult_request": ["consultation", "requested services", "medical rationale", "reason for consultation"],
            "seoc": ["single episode of care", "scope of requested episode", "continuity of care", "estimated duration"],
            "cover_sheet": ["documents included", "date of submission", "primary diagnosis code", "submitting office"],
            "rfs": ["request for service", "type of care request", "diagnosis codes", "reason for request"],
        }
        markers = fallback_markers.get(doc_type, [])
        if sum(1 for marker in markers if marker in normalized_text) >= 2:
            return True

        return False

    def find_fuzzy_duplicate_groups(self, packet, candidate_pages, grouped_pages):
        page_indices = [index for index in sorted(candidate_pages) if index not in grouped_pages]
        if len(page_indices) < 2:
            return []

        parent = {index: index for index in page_indices}

        def find(index):
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        def union(left, right):
            left_root = find(left)
            right_root = find(right)
            if left_root != right_root:
                parent[right_root] = left_root

        for position, left_index in enumerate(page_indices):
            left = candidate_pages[left_index]
            left_doc = left["doc_type"]
            left_text = left["comparison_text"]
            left_length = len(left_text)
            left_tokens = set(left_text.split())
            left_substantive = self.has_substantive_duplicate_content(
                left_doc,
                left.get("normalized", ""),
                left_text,
            )
            if len(left_tokens) < 12:
                continue

            for right_index in page_indices[position + 1:]:
                right = candidate_pages[right_index]
                right_doc = right["doc_type"]
                if left_doc != right_doc:
                    continue
                if left_doc == "unknown":
                    continue
                if max(
                    len(left.get("normalized", "")),
                    len(right.get("normalized", "")),
                ) < 220:
                    continue
                right_substantive = self.has_substantive_duplicate_content(
                    right_doc,
                    right.get("normalized", ""),
                    right.get("comparison_text", ""),
                )
                if not (left_substantive and right_substantive):
                    continue

                right_text = right["comparison_text"]
                length_ratio = min(left_length, len(right_text)) / max(left_length, len(right_text))
                if length_ratio < 0.88:
                    continue

                right_tokens = set(right_text.split())
                intersection_size = len(left_tokens.intersection(right_tokens))
                token_overlap = intersection_size / max(len(left_tokens), len(right_tokens))
                if token_overlap < 0.72 or intersection_size < 12:
                    continue

                similarity = SequenceMatcher(None, left_text, right_text).ratio()
                if similarity >= 0.94:
                    union(left_index, right_index)

        grouped = {}
        for index in page_indices:
            root = find(index)
            grouped.setdefault(root, []).append(index)

        fuzzy_duplicates = []
        for indices in grouped.values():
            if len(indices) < 2:
                continue

            fuzzy_duplicates.append({
                "page_indices": sorted(indices),
                "document_types": [packet.document_types.get(index, "unknown") for index in sorted(indices)],
                "match_type": "fuzzy",
            })

        return fuzzy_duplicates
