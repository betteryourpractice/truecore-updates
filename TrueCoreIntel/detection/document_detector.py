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

    KEYWORD_WEIGHTS = {
        "cover_sheet": {
            "submission": 3,
            "cover": 3,
            "sheet": 3,
        },
        "consent": {
            "consent": 4,
            "telehealth": 3,
            "virtual": 2,
        },
        "consult_request": {
            "consultation": 3,
            "consult": 2,
            "treatment": 2,
            "request": 2,
            "referring va provider": 4,
            "ordering provider": 3,
            "requested service": 3,
        },
        "seoc": {
            "single": 2,
            "episode": 3,
            "care": 2,
            "seoc": 5,
        },
        "lomn": {
            "letter": 1,
            "medical": 2,
            "necessity": 5,
            "reason for request": 4,
            "chief complaint": 3,
            "requested service": 3,
            "low back pain": 1,
        },
        "rfs": {
            "10-10172": 7,
            "10172": 6,
            "va form": 3,
            "request for service": 6,
            "authorization": 3,
            "referral": 3,
            "member id": 3,
            "community care": 2,
        },
        "clinical_notes": {
            "clinical": 2,
            "notes": 2,
            "diagnosis": 2,
            "icd": 2,
            "assessment": 2,
            "impression": 2,
            "plan": 1,
            "physical exam": 2,
            "history of present illness": 3,
        },
    }

    PACKET_LEVEL_HINT_PATTERNS = {
        doc_type: template.get("packet_level_patterns", [])
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
                packet.detected_documents.add(doc_type)

        self.supplement_detected_documents(packet)
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

        # 1) Exact / strong match first
        strong_hits = {}
        for doc_type, patterns in self.STRONG_PATTERNS.items():
            hits = sum(
                1 for pattern in patterns
                if re.search(pattern, text, re.IGNORECASE)
            )
            if hits:
                strong_hits[doc_type] = hits

        if strong_hits:
            # Prefer strongest hit count first, but still reject blank/template docs.
            ranked_hits = sorted(strong_hits.items(), key=lambda item: item[1], reverse=True)
            for doc_type, _ in ranked_hits:
                if not self.should_skip_document(doc_type, raw_text):
                    max_hits = max(strong_hits.values())
                    confidence = min(0.99, 0.84 + (0.04 * max_hits))
                    confidence = self.adjust_confidence_for_field_hints(doc_type, text, confidence)
                    confidence = self.adjust_confidence_for_layout(doc_type, confidence, page_metadata)
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
        confidence = self.adjust_confidence_for_field_hints(best_doc_type, text, confidence)
        confidence = self.adjust_confidence_for_layout(best_doc_type, confidence, page_metadata)
        return best_doc_type, confidence

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

    def adjust_confidence_for_field_hints(self, doc_type, text, base_confidence):
        field_hint_hits = self.count_template_field_hints(doc_type, text)
        if field_hint_hits >= 4:
            return min(0.99, base_confidence + 0.08)
        if field_hint_hits >= 2:
            return min(0.98, base_confidence + 0.04)
        if field_hint_hits == 1:
            return min(0.97, base_confidence + 0.02)
        return max(0.4, base_confidence - 0.03)

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

        if "consent" in filtered and self.should_skip_document("consent", raw_text):
            filtered.pop("consent", None)

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

        return filtered

    def normalize_page_text(self, page, page_metadata=None):
        text = str(page) if page is not None else ""
        page_metadata = dict(page_metadata or {})

        layout = dict(page_metadata.get("layout", {}) or {})
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

            header = self.extract_page_header(page, page_metadata=page_metadata)
            if header:
                hinted_doc = self.find_packet_level_document_hint(header)
                if hinted_doc:
                    if self.should_skip_document(hinted_doc, str(page)):
                        packet.unfilled_documents.add(hinted_doc)
                    else:
                        packet.detected_documents.add(hinted_doc)

                        if self.should_apply_header_hint(current_doc_type, hinted_doc):
                            packet.document_types[idx] = hinted_doc
                            packet.page_confidence[idx] = max(packet.page_confidence.get(idx, 0.0), 0.88)
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

        anchor_terms = [
            "diagnosis",
            "icd",
            "assessment",
            "impression",
            "history of present illness",
            "clinical notes",
            "clinical note",
            "progress note",
        ]

        support_terms = [
            "provider",
            "electronically signed",
            "signed",
            "pain",
            "radiculopathy",
            "lumbar",
            "medications",
            "physical exam",
            "plan",
            "symptom",
        ]

        anchor_hits = sum(1 for term in anchor_terms if term in text)
        support_hits = sum(1 for term in support_terms if term in text)

        return anchor_hits >= 2 or (anchor_hits >= 1 and support_hits >= 3)

    def looks_like_rfs_form(self, page, page_metadata=None):
        text = self.normalize_page_text(page, page_metadata=page_metadata)

        if not text or len(text) < 120:
            return False

        anchor_terms = [
            "10-10172",
            "10172",
            "request for service",
            "request for services",
            "authorization number",
            "referral number",
            "member id",
            "community care",
        ]

        field_terms = [
            "patient name",
            "veteran name",
            "date of birth",
            "dob",
            "ordering provider",
            "referring provider",
            "requested service",
            "reason for request",
            "date of service",
            "service date",
            "va icn",
            "claim number",
        ]

        anchor_hits = sum(1 for term in anchor_terms if term in text)
        field_hits = sum(1 for term in field_terms if term in text)

        if anchor_hits >= 2 and field_hits >= 2:
            return True

        return anchor_hits >= 1 and field_hits >= 4

    def should_skip_document(self, doc_type, page_text):
        text = str(page_text or "")

        if doc_type == "consent":
            return self.count_filled_consent_signals(text) < 2

        return False

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
            if len(left_tokens) < 12:
                continue

            for right_index in page_indices[position + 1:]:
                right = candidate_pages[right_index]
                right_doc = right["doc_type"]
                if left_doc != right_doc:
                    continue
                if left_doc == "unknown":
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
