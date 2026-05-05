import re
from datetime import datetime

from TrueCoreIntel.detection.form_templates import FORM_TEMPLATES


class ExtractorEngine:

    STOP_LABELS = (
        "dob",
        "date of birth",
        "birth date",
        "provider",
        "provider name",
        "ordering provider",
        "ordering physician",
        "ordered by",
        "requested by",
        "referring provider",
        "referring va provider",
        "referred by",
        "ref provider",
        "pcp",
        "facility",
        "servicing facility",
        "treating facility",
        "requested facility",
        "location",
        "diagnosis",
        "assessment",
        "impression",
        "clinical impression",
        "icd",
        "icd-10",
        "authorization",
        "authorization number",
        "auth",
        "auth #",
        "member id",
        "pob",
        "ssn",
        "last four ssn",
        "va claim number",
        "reason for request",
        "reason for consultation",
        "reason for consult",
        "request rationale",
        "medical rationale",
        "clinical objective",
        "reason for referral",
        "chief complaint",
        "date of submission",
        "primary diagnosis code",
        "episode diagnosis",
        "diagnoses",
        "clinical summary",
        "requested service",
        "requested procedure",
        "procedure",
        "cpt",
        "npi",
        "claim",
        "claim number",
        "va icn",
        "icn",
        "integrated control number",
        "clinic",
        "clinic name",
        "practice name",
        "location",
        "city",
        "state",
        "date of service",
        "dates of service",
        "service dates",
        "visit date",
        "dos",
        "medications",
        "current meds",
        "current medications",
        "signature",
        "signed by",
        "phone",
        "fax",
        "address",
        "office staff",
        "submitting office",
        "reviewed",
        "scope of requested episode",
        "duration and scope of care",
        "continuity of care",
    )

    TEMPLATE_TEXT_MARKERS = (
        "do not submit",
        "training example",
        "example training packet",
        "template",
    )

    TEMPLATE_VALUE_PATTERNS = (
        r"\b(?:specific lumbar level\(s\)|duration|doctors name|doctor'?s name|parent/guardian initial)\b",
    )

    TEMPLATE_PLACEHOLDER_HINTS = (
        "specific",
        "duration",
        "doctor",
        "provider",
        "physician",
        "guardian",
        "initial",
        "signature",
        "service",
        "facility",
        "clinic",
        "address",
        "patient",
        "member",
        "veteran",
        "referring",
        "ordering",
    )

    IDENTITY_PATTERNS = {
        "name": [
            r"(?:veteran name|patient name|full name|name of veteran|member name)\s*[:\-]\s*([^\n\r]+)",
            r"\b(?:last,\s*first\s*m(?:iddle)?|patient)\s*name\s*[:\-]\s*([^\n\r]+)",
            r"\bname\s*[:\-]\s*([A-Z][A-Za-z,\-\' ]{4,})",
        ],
        "dob": [
            r"(?:dob|d\.o\.b\.|date of birth|birth date)\s*[:\-]\s*([^\n\r]+)",
        ],
        "provider": [
            r"(?:provider name|provider|treating provider|rendering provider|attending provider)\s*[:\-]\s*([^\n\r]+)",
        ],
        "ordering_provider": [
            r"(?:ordering provider|ordering physician|ordered by|requested by|requesting provider)\s*[:\-]\s*([^\n\r]+)",
        ],
        "referring_provider": [
            r"(?:referring va provider|referring provider|referring physician|referred by|ref provider|pcp)\s*[:\-]\s*([^\n\r]+)",
        ],
    }

    FIELD_PATTERNS = {
        "authorization_number": [
            r"\bref(?:\.|erral)?\b\s*(?:#|no\.?|number|id)?\s*[:\-]?\s*(VA(?:[\- ]?\d){8,18})\b",
            r"(?:authorization(?:\s+number|\s+no\.?)?|auth(?:orization)?(?:\s+number|\s+no\.?)?|ref(?:\.|erral)?(?:\s+number|\s+no\.?)?|member\s*id|tracking(?:\s+number|\s+no\.?|\s+id)?|reference(?:\s+number|\s+no\.?|\s+id)?|case(?:\s+number|\s+no\.?|\s+id)?|consult(?:\s+number|\s+no\.?|\s+id)?|episode(?:\s+of\s+care)?(?:\s+number|\s+no\.?|\s+id)?|seoc(?:\s+number|\s+no\.?|\s+id)?)\s*(?:#|no\.?|number|id)?\s*[:\-]?\s*([A-Z0-9][A-Z0-9\- ]{5,32})",
            r"(?:\b(?:auth|authorization|ref(?:\.|erral)?|member\s*id|tracking|reference|case|consult|episode(?:\s+of\s+care)?|seoc)\b\s*[#:;\-]?\s*)([A-Z0-9][A-Z0-9\- ]{5,32})",
            r"\b(?:auth|authorization|ref(?:\.|erral)?|member\s*id|tracking|reference|case|consult|episode(?:\s+of\s+care)?|seoc)\b[\s\r\n]{0,12}(?:number|no\.?|#|id)?[\s\r\n:;\-]{0,8}([A-Z0-9][A-Z0-9\- ]{5,32})",
        ],
        "facility": [
            r"(?:facility(?: name)?|servicing facility|treating facility|requested facility|referring facility|rendering facility|medical facility)\s*[:\-]\s*([^\n\r]+)",
            r"(?:medical center|hospital|health system|vamc)\s*[:\-]\s*([^\n\r]+)",
        ],
        "location": [
            r"(?:office location|clinic location|facility location|city,\s*state|city/state|location)\s*[:\-]\s*([^\n\r]+)",
            r"\bcity\s*[:\-]\s*([A-Za-z .'\-]+,\s*[A-Z]{2})\b",
            r"\bcity/state\s*[:\-]\s*([A-Za-z .'\-]+,\s*[A-Z]{2})\b",
        ],
        "clinic_name": [
            r"(?:clinic(?: name)?|practice(?: name)?|submitting office|office name|provider group|group name)\s*[:\-]\s*([^\n\r]+)",
        ],
        "npi": [
            r"\b(?:provider\s+)?npi\b\s*[:#\-]?\s*(\d{10})\b",
            r"\bnpi\s*(?:number|#)?\s*[:#\-]?\s*(\d{10})\b",
        ],
        "va_icn": [
            r"(?:\bicn\b|va icn|integrated control number|icn/ssn)\s*[:#\-]?\s*([A-Z0-9]{8,24})\b",
        ],
        "claim_number": [
            r"(?:claim(?: number| no\.?)?|va claim number|claim #)\s*[:#\-]?\s*([A-Z0-9\-]{4,24})\b",
            r"(?:last four ssn|last four)\s*[:#\-]?\s*(\d{4})\b",
            r"(?:ssn ending(?: in)?|ending in)\s*[:#\-]?\s*(\d{4})\b",
        ],
        "reason_for_request": [
            r"(?:reason for request|reason for consultation|reason for consult|reason for referral|chief complaint|requested service|requested procedure|reason)\s*[:\-]\s*([^\n\r]+)",
            r"\bchief complaint\s*[:\-]?\s*([^\n\r]+)",
            r"\bhistory of present illness\s*[:\-]?\s*([^\n\r]+)",
        ],
        "service_date_range": [
            r"(?:date(?:s)? of service|service date(?:s| range)?|visit date(?:s| range)?|clinical visit(?: date)?s?|dos)\s*[:\-]\s*([^\n\r]+)",
            r"(?:from|service dates?)\s+([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4}\s+(?:to|through|-)\s+[A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})",
            r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\s*(?:to|through|-)\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4})",
        ],
        "medications": [
            r"(?:medications?|current meds?|current medications?)\s*[:\-]\s*([^\n\r]+)",
        ],
        "diagnosis": [
            r"(?:episode diagnosis|primary diagnosis code|diagnosis|assessment|impression|clinical impression)\s*[:\-]\s*([^\n\r]+)",
            r"\bdiagnoses\s*[:\-]?\s*([^\n\r]+)",
        ],
    }

    DIAGNOSIS_KEYWORDS = {
        "degenerative disc disease": ["degenerative disc disease", "ddd"],
        "low back pain": ["low back pain", "lumbar pain", "back pain"],
        "migraine": ["migraine", "migraines", "headache disorder"],
        "osteoarthritis": ["osteoarthritis", "degenerative joint disease", "djd"],
        "radiculopathy": ["radiculopathy", "radicular pain", "sciatica"],
        "neck pain": ["neck pain", "cervicalgia"],
    }

    SYMPTOM_KEYWORDS = {
        "pain": ["pain", "painful", "ache", "aching"],
        "headache": ["headache", "head pain"],
        "numbness": ["numbness", "numb"],
        "weakness": ["weakness", "weak"],
        "tingling": ["tingling", "paresthesia"],
        "limited_range_of_motion": ["limited range of motion", "reduced range of motion", "restricted motion"],
    }

    PROCEDURE_KEYWORDS = {
        "MRI": ["mri", "magnetic resonance imaging"],
        "CT": ["ct", "cat scan", "computed tomography"],
        "XRAY": ["xray", "x-ray", "radiograph"],
        "PHYSICAL_THERAPY": ["physical therapy", "pt evaluation", "pt"],
    }

    MEDICATION_KEYWORDS = {
        "gabapentin": ["gabapentin"],
        "ibuprofen": ["ibuprofen", "motrin"],
        "naproxen": ["naproxen", "aleve"],
        "meloxicam": ["meloxicam"],
        "tramadol": ["tramadol"],
        "acetaminophen": ["acetaminophen", "tylenol"],
        "cyclobenzaprine": ["cyclobenzaprine", "flexeril"],
        "lidocaine": ["lidocaine"],
    }

    def extract(self, packet):
        for idx, page in enumerate(packet.pages):
            doc_type = packet.document_types.get(idx, "unknown")
            page_metadata = packet.page_metadata[idx] if idx < len(getattr(packet, "page_metadata", []) or []) else {}
            text = str(page)
            section_role_details = self.detect_section_roles(text, doc_type)
            section_roles = [entry.get("role") for entry in section_role_details if entry.get("role")]
            primary_section_role = self.get_primary_section_role(section_roles)
            if isinstance(page_metadata, dict):
                page_metadata["section_roles"] = list(section_role_details)
            packet.section_roles[idx] = list(section_role_details)
            packet.document_intelligence.setdefault("page_section_roles", {})[idx + 1] = list(section_role_details)
            template_markers = self.detect_template_markers(text)
            if template_markers:
                marker_entry = {
                    "page_number": idx + 1,
                    "document_type": doc_type,
                    "markers": list(template_markers),
                }
                packet.template_markers.append(marker_entry)
                packet.document_intelligence.setdefault("template_markers", []).append(marker_entry)
            field_context = {
                "_page_section_roles": list(section_roles),
                "_page_section_headings": [entry.get("heading") for entry in section_role_details if entry.get("heading")],
                "_primary_section_role": primary_section_role,
                "_template_markers": list(template_markers),
            }

            data = self.extract_template_fields(page, doc_type, page_metadata=page_metadata, field_context=field_context)
            data.update(self.route_extraction(page, doc_type, page_metadata=page_metadata, field_context=field_context))
            data = self.apply_document_context_boost(data, doc_type, text, field_context=field_context)

            identity_data = self.extract_identity_fields(page, page_metadata=page_metadata, field_context=field_context)
            data.update(identity_data)

            labeled_data = self.extract_labeled_fields(page, page_metadata=page_metadata, field_context=field_context)
            data.update(labeled_data)

            inferred_data = self.extract_inferred_medical_fields(page)
            data = self.merge_extraction_data(data, inferred_data)

            self.store_results(packet, data, page, idx, doc_type, page_metadata=page_metadata, field_context=field_context)

        return packet

    def extract_template_fields(self, page, doc_type, page_metadata=None, field_context=None):
        text = str(page)
        data = {}
        template = FORM_TEMPLATES.get(doc_type, {})

        for field_name in template.get("expected_fields", []):
            if field_name == "signature_present":
                if self.detect_signature_presence(text) or ((page_metadata or {}).get("layout", {}) or {}).get("signature_regions"):
                    data["signature_present"] = True
                    self.capture_field_context(field_context, "signature_present", value=True, page_metadata=page_metadata, strategy="layout_signature")
                continue

            zone_match = self.extract_from_field_zones(page_metadata, field_name)
            if zone_match:
                data[field_name] = zone_match["value"]
                self.capture_field_context(field_context, field_name, value=zone_match["value"], page_metadata=page_metadata, zone=zone_match, strategy="field_zone")
                continue

            patterns = self.IDENTITY_PATTERNS.get(field_name) or self.FIELD_PATTERNS.get(field_name)
            if not patterns:
                continue

            value = self.extract_first_labeled_match(text, patterns, field_name)
            if value:
                data[field_name] = value

        return data

    def route_extraction(self, page, doc_type, page_metadata=None, field_context=None):
        data = {}

        if doc_type in {"authorization", "rfs", "seoc"}:
            data.update(self.extract_authorization(page, page_metadata=page_metadata, field_context=field_context))

        if doc_type == "consult_request":
            data.update(self.extract_authorization(page, page_metadata=page_metadata, field_context=field_context))
            data.update(self.extract_referral(page, page_metadata=page_metadata, field_context=field_context))

        elif doc_type in {"clinical_notes", "lomn"}:
            data.update(self.extract_clinical(page, doc_type=doc_type, page_metadata=page_metadata, field_context=field_context))

        elif doc_type in {"referral", "seoc"}:
            data.update(self.extract_referral(page, page_metadata=page_metadata, field_context=field_context))

        return data
    
    def apply_document_context_boost(self, data, doc_type, text, field_context=None):
        """
        Reinforce high-priority fields based on document type.
        This does NOT override existing values — only fills gaps.
        """

        if doc_type == "lomn":
            if "diagnosis" not in data:
                diagnosis = self.extract_diagnosis_concept(text)
                if diagnosis:
                    data["diagnosis"] = diagnosis
                    self.capture_field_context(field_context, "diagnosis", value=diagnosis, strategy="concept_diagnosis_basis")

        elif doc_type == "rfs":
            if "authorization_number" not in data:
                auth = self.extract_first_labeled_match(
                    text,
                    self.FIELD_PATTERNS["authorization_number"],
                    "authorization_number",
                )
                if auth:
                    data["authorization_number"] = auth

        elif doc_type == "clinical_notes":
            if "icd_codes" not in data:
                contextual_icds = self.extract_contextual_icd_codes(text)
                regex_icds = self.extract_regex_icd_codes(text)
                inferred_icds = self.infer_icd_codes_from_diagnosis_text(text)

                merged = self.merge_icd_codes(
                    contextual_icds=contextual_icds,
                    regex_icds=regex_icds,
                    inferred_icds=inferred_icds,
                )
                if merged:
                    data["icd_codes"] = merged

            if "diagnosis" not in data:
                diagnosis = self.extract_diagnosis_concept(text)
                if diagnosis:
                    data["diagnosis"] = diagnosis
                    self.capture_field_context(field_context, "diagnosis", value=diagnosis, strategy="concept_diagnosis_basis")

        elif doc_type in {"consult_request", "seoc"}:
            if "reason_for_request" not in data:
                reason = self.extract_request_intent_concept(text)
                if reason:
                    data["reason_for_request"] = reason
                    self.capture_field_context(field_context, "reason_for_request", value=reason, strategy="concept_request_intent")
            if "diagnosis" not in data:
                diagnosis = self.extract_diagnosis_concept(text)
                if diagnosis:
                    data["diagnosis"] = diagnosis
                    self.capture_field_context(field_context, "diagnosis", value=diagnosis, strategy="concept_diagnosis_basis")

        return data

    def extract_authorization(self, page, page_metadata=None, field_context=None):
        text = str(page)
        lower_text = text.lower()
        data = {}

        zone_match = self.extract_from_field_zones(page_metadata, "authorization_number")
        if zone_match:
            data["authorization_number"] = zone_match["value"]
            self.capture_field_context(field_context, "authorization_number", value=zone_match["value"], page_metadata=page_metadata, zone=zone_match, strategy="field_zone")

        if any(term in lower_text for term in [
            "auth",
            "authorization",
            "referral",
            "10-10172",
            "request for service",
            "community care",
            "member id",
            "tracking number",
            "reference number",
            "case number",
            "consult number",
            "consultation and treatment request",
            "episode of care",
            "seoc",
        ]) or re.search(r"\bref(?:\.|erral)?\b\s*[:#\-]?\s*va[a-z0-9\-]{6,}", lower_text):
            data["authorization_detected"] = True

        def normalize_auth_candidate(candidate):
            candidate = re.sub(
                r"^(?:community care|authorization(?:\s+number|\s+no\.?)?|auth(?:orization)?(?:\s+number|\s+no\.?)?|ref(?:\.|erral)?(?:\s+number|\s+no\.?)?|member\s*id|tracking(?:\s+number|\s+no\.?|\s+id)?|reference(?:\s+number|\s+no\.?|\s+id)?|case(?:\s+number|\s+no\.?|\s+id)?|consult(?:\s+number|\s+no\.?|\s+id)?|episode(?:\s+of\s+care)?(?:\s+number|\s+no\.?|\s+id)?|seoc(?:\s+number|\s+no\.?|\s+id)?)\b",
                "",
                candidate,
                flags=re.IGNORECASE,
            )
            candidate = re.sub(
                r"^(?:\s*(?:#|no\.?|number|id|is|:|-))+",
                "",
                candidate,
                flags=re.IGNORECASE,
            )
            candidate = re.sub(r"\s+", " ", candidate).strip()
            return self.normalize_authorization_number(candidate)

        auth_number = self.extract_first_labeled_match(
            text,
            self.FIELD_PATTERNS["authorization_number"],
            "authorization_number",
        )

        if not auth_number:
            ref_candidates = re.findall(
                r"\bref(?:\.|erral)?\b\s*(?:#|no\.?|number|id)?\s*[:\-]?\s*(VA(?:[\- ]?\d){8,18})\b",
                text,
                re.IGNORECASE,
            )
            for candidate in ref_candidates:
                normalized = normalize_auth_candidate(candidate)
                if normalized:
                    auth_number = normalized
                    break

        if not auth_number:
            anchor_pattern = re.compile(
                r"(authorization(?:\s+number|\s+no\.?)?|auth(?:orization)?(?:\s+number|\s+no\.?)?|ref(?:\.|erral)?(?:\s+number|\s+no\.?)?|community care|member\s*id|tracking(?:\s+number|\s+no\.?|\s+id)?|reference(?:\s+number|\s+no\.?|\s+id)?|case(?:\s+number|\s+no\.?|\s+id)?|consult(?:\s+number|\s+no\.?|\s+id)?|episode(?:\s+of\s+care)?(?:\s+number|\s+no\.?|\s+id)?|seoc(?:\s+number|\s+no\.?|\s+id)?)",
                re.IGNORECASE,
            )
            numeric_label_terms = [
                "authorization number",
                "auth number",
                "referral number",
                "member id",
                "tracking number",
                "reference number",
                "case number",
                "consult number",
                "episode of care",
                "seoc",
            ]

            for match in anchor_pattern.finditer(text):
                start = max(0, match.start() - 20)
                end = min(len(text), match.end() + 140)
                window = text[start:end]
                window = re.sub(r"[\r\n\t]+", " ", window)
                window = re.sub(r"\s+", " ", window).strip()
                window_lower = window.lower()

                candidates = re.findall(r"\b[A-Z0-9][A-Z0-9\- ]{5,32}\b", window, re.IGNORECASE)
                ranked_candidates = []
                for candidate in candidates:
                    normalized = normalize_auth_candidate(candidate)
                    if normalized:
                        compact_candidate = normalized.replace("-", "")
                        if compact_candidate.isdigit() and not any(term in window_lower for term in numeric_label_terms):
                            continue

                        score = 0
                        if normalized.startswith("VA") and re.search(r"\d", normalized):
                            score += 5
                        elif re.search(r"[A-Z]", normalized) and re.search(r"\d", normalized):
                            score += 3
                        elif normalized.isdigit():
                            score += 2
                        if "-" in normalized:
                            score += 1
                        if len(normalized.replace("-", "")) >= 9:
                            score += 1
                        if candidate.strip().isdigit():
                            score += 1
                        ranked_candidates.append((score, normalized))

                if ranked_candidates:
                    ranked_candidates.sort(key=lambda item: (-item[0], -len(item[1]), item[1]))
                    auth_number = ranked_candidates[0][1]
                    break

        if not auth_number:
            numeric_anchor_pattern = re.compile(
                r"(?:member\s*id|tracking(?:\s+number|\s+no\.?|\s+id)?|reference(?:\s+number|\s+no\.?|\s+id)?|case(?:\s+number|\s+no\.?|\s+id)?|consult(?:\s+number|\s+no\.?|\s+id)?|episode(?:\s+of\s+care)?(?:\s+number|\s+no\.?|\s+id)?|seoc(?:\s+number|\s+no\.?|\s+id)?)\s*(?:#|no\.?|number|id)?\s*[:\-]?\s*(\d[\d \-]{7,22}\d)",
                re.IGNORECASE,
            )
            for match in numeric_anchor_pattern.finditer(text):
                normalized = normalize_auth_candidate(match.group(1))
                if normalized:
                    auth_number = normalized
                    break

        if not auth_number:
            va_prefixed_candidates = re.findall(r"\bVA(?:[\s\-]?\d){8,18}\b", text, re.IGNORECASE)
            for candidate in va_prefixed_candidates:
                normalized = normalize_auth_candidate(candidate)
                if normalized:
                    auth_number = normalized
                    break

        if not auth_number:
            broad_candidates = re.findall(r"\b[A-Z]{1,4}-?[A-Z0-9]{5,24}\b", text, re.IGNORECASE)
            for candidate in broad_candidates:
                normalized = normalize_auth_candidate(candidate)
                if normalized and re.search(r"[A-Z]", normalized) and re.search(r"\d", normalized):
                    auth_number = normalized
                    break

        if auth_number:
            data["authorization_number"] = auth_number

        facility = self.infer_facility(text)
        if facility:
            data.setdefault("facility", facility)

        return data

    def extract_clinical(self, page, doc_type=None, page_metadata=None, field_context=None):
        text = str(page)
        data = {}

        contextual_icds = self.extract_contextual_icd_codes(text)
        regex_icds = self.extract_regex_icd_codes(text)
        inferred_icds = self.infer_icd_codes_from_diagnosis_text(text)

        merged_icds = self.merge_icd_codes(
            contextual_icds=contextual_icds,
            regex_icds=regex_icds,
            inferred_icds=inferred_icds,
        )
        if merged_icds:
            data["icd_codes"] = merged_icds

        diagnosis_zone = self.extract_from_field_zones(page_metadata, "diagnosis")
        if diagnosis_zone:
            diagnosis = diagnosis_zone["value"]
            self.capture_field_context(field_context, "diagnosis", value=diagnosis, page_metadata=page_metadata, zone=diagnosis_zone, strategy="field_zone")
        else:
            diagnosis = self.extract_first_labeled_match(
                text,
                self.FIELD_PATTERNS["diagnosis"],
                "diagnosis",
            )
        if diagnosis:
            data["diagnosis"] = diagnosis
        else:
            inferred_diagnosis = self.infer_diagnosis(text)
            if inferred_diagnosis:
                data["diagnosis"] = inferred_diagnosis

        concept_diagnosis = self.extract_diagnosis_concept(text)
        if concept_diagnosis and self.should_prefer_concept_diagnosis(data.get("diagnosis"), concept_diagnosis):
            data["diagnosis"] = concept_diagnosis
            self.capture_field_context(field_context, "diagnosis", value=concept_diagnosis, page_metadata=page_metadata, strategy="concept_diagnosis_basis")

        symptom = self.infer_symptom(text)
        if symptom:
            data["symptom"] = symptom

        procedure = self.infer_procedure(text)
        if procedure:
            data["procedure"] = procedure

        reason_zone = self.extract_from_field_zones(page_metadata, "reason_for_request")
        if reason_zone:
            reason_for_request = reason_zone["value"]
            self.capture_field_context(field_context, "reason_for_request", value=reason_for_request, page_metadata=page_metadata, zone=reason_zone, strategy="field_zone")
        else:
            reason_for_request = self.extract_first_labeled_match(
                text,
                self.FIELD_PATTERNS["reason_for_request"],
                "reason_for_request",
            )
        if reason_for_request:
            data["reason_for_request"] = reason_for_request

        concept_reason = None if doc_type == "lomn" else self.extract_request_intent_concept(text)
        if concept_reason and self.should_prefer_concept_reason(data.get("reason_for_request"), concept_reason):
            data["reason_for_request"] = concept_reason
            self.capture_field_context(field_context, "reason_for_request", value=concept_reason, page_metadata=page_metadata, strategy="concept_request_intent")

        facility_zone = self.extract_from_field_zones(page_metadata, "facility")
        if facility_zone:
            facility = facility_zone["value"]
            self.capture_field_context(field_context, "facility", value=facility, page_metadata=page_metadata, zone=facility_zone, strategy="field_zone")
        else:
            facility = self.extract_first_labeled_match(
                text,
                self.FIELD_PATTERNS["facility"],
                "facility",
            )
        if not facility:
            facility = self.infer_facility(text)
        if facility:
            data["facility"] = facility

        return data

    def extract_referral(self, page, page_metadata=None, field_context=None):
        text = str(page)
        lower_text = text.lower()
        data = {}

        if "referral" in lower_text:
            data["referral_detected"] = True

        reason_zone = self.extract_from_field_zones(page_metadata, "reason_for_request")
        if reason_zone:
            reason_for_request = reason_zone["value"]
            self.capture_field_context(field_context, "reason_for_request", value=reason_for_request, page_metadata=page_metadata, zone=reason_zone, strategy="field_zone")
        else:
            reason_for_request = self.extract_first_labeled_match(
                text,
                self.FIELD_PATTERNS["reason_for_request"],
                "reason_for_request",
            )
        if reason_for_request:
            data["reason_for_request"] = reason_for_request

        concept_reason = self.extract_request_intent_concept(text)
        if concept_reason and self.should_prefer_concept_reason(data.get("reason_for_request"), concept_reason):
            data["reason_for_request"] = concept_reason
            self.capture_field_context(field_context, "reason_for_request", value=concept_reason, page_metadata=page_metadata, strategy="concept_request_intent")

        facility_zone = self.extract_from_field_zones(page_metadata, "facility")
        if facility_zone:
            facility = facility_zone["value"]
            self.capture_field_context(field_context, "facility", value=facility, page_metadata=page_metadata, zone=facility_zone, strategy="field_zone")
        else:
            facility = self.extract_first_labeled_match(
                text,
                self.FIELD_PATTERNS["facility"],
                "facility",
            )
        if not facility:
            facility = self.infer_facility(text)
        if facility:
            data["facility"] = facility

        diagnosis_zone = self.extract_from_field_zones(page_metadata, "diagnosis")
        if diagnosis_zone:
            diagnosis = diagnosis_zone["value"]
            self.capture_field_context(field_context, "diagnosis", value=diagnosis, page_metadata=page_metadata, zone=diagnosis_zone, strategy="field_zone")
        else:
            diagnosis = self.extract_first_labeled_match(
                text,
                self.FIELD_PATTERNS["diagnosis"],
                "diagnosis",
            )
        if diagnosis:
            data["diagnosis"] = diagnosis

        concept_diagnosis = self.extract_diagnosis_concept(text)
        if concept_diagnosis and self.should_prefer_concept_diagnosis(data.get("diagnosis"), concept_diagnosis):
            data["diagnosis"] = concept_diagnosis
            self.capture_field_context(field_context, "diagnosis", value=concept_diagnosis, page_metadata=page_metadata, strategy="concept_diagnosis_basis")

        return data

    def get_text_lines(self, text):
        return [
            re.sub(r"\s+", " ", line).strip()
            for line in re.split(r"[\r\n]+", str(text or ""))
            if re.sub(r"\s+", " ", line).strip()
        ]

    def detect_template_markers(self, text):
        lowered = str(text or "").lower()
        markers = []
        for marker in self.TEMPLATE_TEXT_MARKERS:
            if marker in lowered:
                markers.append(marker)
        for content in self.extract_bracket_contents(text):
            if self.is_template_placeholder_content(content):
                markers.append("bracket_placeholder")
                break
        return list(dict.fromkeys(markers))

    def contains_template_value_marker(self, value):
        if isinstance(value, dict):
            return any(self.contains_template_value_marker(item) for item in value.values())
        if isinstance(value, (list, tuple, set)):
            return any(self.contains_template_value_marker(item) for item in value)

        raw = str(value or "").strip()
        if not raw:
            return False
        lowered = raw.lower()
        if any(marker in lowered for marker in self.TEMPLATE_TEXT_MARKERS):
            return True
        for content in self.extract_bracket_contents(raw):
            if self.is_template_placeholder_content(content):
                return True
        return any(re.search(pattern, raw, re.IGNORECASE) for pattern in self.TEMPLATE_VALUE_PATTERNS)

    def extract_bracket_contents(self, text):
        return [
            re.sub(r"\s+", " ", match.group(1)).strip()
            for match in re.finditer(r"\[([^\]]+)\]", str(text or ""))
            if match.group(1) is not None
        ]

    def is_template_placeholder_content(self, content):
        normalized = re.sub(r"\s+", " ", str(content or "")).strip().lower()
        if not normalized:
            return False

        if any(re.search(pattern, normalized, re.IGNORECASE) for pattern in self.TEMPLATE_VALUE_PATTERNS):
            return True

        if any(hint in normalized for hint in self.TEMPLATE_PLACEHOLDER_HINTS) and re.search(r"[a-z]", normalized):
            return True

        if re.fullmatch(r"[x✓✔ ]{0,4}", normalized):
            return False

        if re.fullmatch(r"id\s*:\s*[a-z0-9\-]+", normalized):
            return False

        if re.fullmatch(r"[a-z0-9._:/#\-]{1,24}", normalized):
            return False

        return False

    def is_structural_heading_line(self, line):
        normalized = re.sub(r"\s+", " ", str(line or "")).strip()
        if not normalized:
            return False

        lowered = normalized.lower().strip(":")
        known_headings = {
            "clinical summary",
            "requested services",
            "medical rationale",
            "clinical goals include",
            "duration and scope of care",
            "continuity of care",
            "medical necessity",
            "diagnosis",
            "diagnoses",
            "episode diagnosis",
            "clinical objective",
            "reason for consultation",
            "reason for request",
            "reason for referral",
        }
        if lowered in known_headings:
            return True

        if normalized.endswith(":") and len(normalized.split()) <= 8:
            return True

        alpha_chars = re.sub(r"[^A-Za-z]", "", normalized)
        if alpha_chars and normalized == normalized.upper() and len(normalized.split()) <= 8:
            return True

        return False

    def get_section_role_patterns(self):
        return {
            "identity_admin": [
                r"\bdemographic information\b",
                r"\bpatient name\b",
                r"\bveteran name\b",
                r"\bdate of submission\b",
                r"\bsubmitting office\b",
                r"\boffice staff name\b",
                r"\bdocuments included\b",
            ],
            "request_intent": [
                r"\breason for consultation\b",
                r"\breason for request\b",
                r"\breason for referral\b",
                r"\bchief complaint\b",
                r"\bconsultation and treatment request\b",
            ],
            "diagnostic_basis": [
                r"\bepisode diagnosis\b",
                r"\bprimary diagnosis code\b",
                r"\bdiagnoses\b",
                r"\bdiagnosis\b",
                r"\bpre-?operative diagnosis\b",
                r"\bpost-?operative diagnosis\b",
            ],
            "clinical_support": [
                r"\bclinical summary\b",
                r"\bhistory of present illness\b",
                r"\bclinical notes\b",
                r"\bassessment\b",
                r"\bimpression\b",
                r"\boffice visit notes\b",
                r"\bprior conservative therapy documentation\b",
            ],
            "justification": [
                r"\bletter of medical necessity\b",
                r"\bmedical necessity\b",
                r"\bmedical rationale\b",
            ],
            "request_scope": [
                r"\brequested services\b",
                r"\bscope of requested episode\b",
                r"\bduration and scope of care\b",
                r"\bauthorization is requested for\b",
            ],
            "routing_followup": [
                r"\bcontinuity of care\b",
                r"\breferring va provider\b",
                r"\bfollow-?up\b",
                r"\bwill be forwarded to the referring va provider\b",
            ],
            "consent_admin": [
                r"\btelehealth virtual consent\b",
                r"\btelehealth consent\b",
                r"\bconsent for medical care and treatment\b",
                r"\bappointment confirmation method\b",
            ],
            "imaging_support": [
                r"\bmri report\b",
                r"\blumbar spine mri report\b",
                r"\bstudy date\b",
                r"\bimaging findings\b",
            ],
        }

    def get_section_role_defaults(self):
        return {
            "cover_sheet": ["identity_admin"],
            "consent": ["consent_admin"],
            "consult_request": ["request_intent", "request_scope"],
            "seoc": ["diagnostic_basis", "request_scope", "routing_followup"],
            "lomn": ["justification", "diagnostic_basis"],
            "clinical_notes": ["clinical_support", "diagnostic_basis"],
            "imaging": ["imaging_support"],
            "mri_report": ["imaging_support"],
            "imaging_report": ["imaging_support"],
            "conservative_care_summary": ["clinical_support"],
        }

    def detect_section_roles(self, text, doc_type=None):
        lines = self.get_text_lines(text)
        patterns = self.get_section_role_patterns()
        roles = []
        seen = set()

        for line in lines:
            normalized = re.sub(r"\s+", " ", line).strip()
            lowered = normalized.lower()
            if re.match(r"^[\u2022\u25cf\u25cb\u2610\u2611\u2612\-\*]", normalized):
                continue
            for role, anchors in patterns.items():
                if not any(re.search(anchor, normalized, re.IGNORECASE) for anchor in anchors):
                    continue
                key = (role, lowered)
                if key in seen:
                    continue
                seen.add(key)
                roles.append({
                    "role": role,
                    "heading": normalized,
                })

        for default_role in self.get_section_role_defaults().get(doc_type, []):
            key = (default_role, f"inferred:{doc_type}")
            if key in seen:
                continue
            if any(entry.get("role") == default_role for entry in roles):
                continue
            seen.add(key)
            roles.append({
                "role": default_role,
                "heading": f"Inferred from {doc_type}",
                "inferred": True,
            })

        return roles

    def get_primary_section_role(self, section_roles):
        priority = [
            "request_intent",
            "diagnostic_basis",
            "justification",
            "clinical_support",
            "request_scope",
            "routing_followup",
            "consent_admin",
            "imaging_support",
            "identity_admin",
        ]
        roles = list(section_roles or [])
        for role in priority:
            if role in roles:
                return role
        return roles[0] if roles else None

    def extract_concept_window(self, text, anchors, max_follow_lines=4, inline_only=False):
        lines = self.get_text_lines(text)
        if not lines:
            return None

        anchor_patterns = [re.compile(anchor, re.IGNORECASE) for anchor in anchors]
        for index, line in enumerate(lines):
            for pattern in anchor_patterns:
                match = pattern.search(line)
                if not match:
                    continue

                inline_value = line[match.end():].strip(" :-")
                if inline_value:
                    return inline_value

                if inline_only:
                    continue

                collected = []
                for next_line in lines[index + 1:index + 1 + max_follow_lines]:
                    if self.is_structural_heading_line(next_line):
                        break
                    collected.append(next_line)
                if collected:
                    return " ".join(collected).strip()

        return None

    def extract_request_intent_concept(self, text):
        strong_concept = self.extract_concept_window(
            text,
            anchors=[
                r"\breason for consultation\b",
                r"\breason for request\b",
                r"\breason for referral\b",
                r"\bchief complaint\b",
            ],
            max_follow_lines=3,
        )
        if strong_concept:
            return self.normalize_reason_for_request(strong_concept)

        request_sentence = self.extract_concept_window(
            text,
            anchors=[
                r"\bthis request is for authorization of\b",
            ],
            max_follow_lines=3,
        )
        if request_sentence:
            return self.normalize_reason_for_request(request_sentence)

        return None

    def extract_diagnosis_concept(self, text):
        primary_match = re.search(r"\bprimary\s*:\s*([^\n\r]+)", text, re.IGNORECASE)
        if primary_match:
            candidate = self.normalize_diagnosis(primary_match.group(1))
            if candidate:
                return candidate

        episode_diagnosis = self.extract_concept_window(
            text,
            anchors=[
                r"\bepisode diagnosis\b",
                r"\bdiagnosis\b",
                r"\bdiagnoses\b",
                r"\bprimary diagnosis code\b",
            ],
            max_follow_lines=3,
        )
        if episode_diagnosis:
            candidate = self.normalize_diagnosis(episode_diagnosis)
            if candidate:
                return candidate

        return None

    def should_prefer_concept_reason(self, existing_value, concept_value):
        if not concept_value:
            return False
        if not existing_value:
            return True

        existing = str(existing_value).strip()
        concept = str(concept_value).strip()
        if not existing:
            return True

        existing_lower = existing.lower()
        concept_lower = concept.lower()

        weak_existing_markers = [
            "the veteran demonstrates",
            "despite conservative therapy",
            "is indicated to",
            "remains at risk",
            "failure of conservative",
        ]
        if any(marker in existing_lower for marker in weak_existing_markers) and not any(marker in concept_lower for marker in weak_existing_markers):
            return True

        if len(existing) > 140 and len(concept) < len(existing):
            return True

        return False

    def should_prefer_concept_diagnosis(self, existing_value, concept_value):
        if not concept_value:
            return False
        if not existing_value:
            return True

        existing = str(existing_value).strip().lower()
        concept = str(concept_value).strip().lower()

        weak_existing_markers = ["pain", "low back pain", "neck pain", "headache"]
        if existing in weak_existing_markers and concept not in weak_existing_markers:
            return True

        if existing in {"primary", "secondary"}:
            return True

        return False

    def extract_provider_role_fallback(self, text, field_name):
        anchor_map = {
            "ordering_provider": [
                r"ordering provider",
                r"ordering physician",
                r"ordered by",
                r"requested by",
                r"requesting provider",
            ],
            "referring_provider": [
                r"referring va provider",
                r"referring provider",
                r"referring physician",
                r"referred by",
                r"ref provider",
                r"pcp",
            ],
            "provider": [
                r"provider name",
                r"treating provider",
                r"rendering provider",
                r"attending provider",
                r"treating physician",
                r"rendering physician",
                r"attending physician",
            ],
        }
        anchors = anchor_map.get(field_name, [])
        if not anchors:
            return None

        name_pattern = (
            r"("
            r"(?:Dr\.?\s+)?"
            r"[A-Z][A-Za-z'\-]+"
            r"(?:\s+[A-Z](?:\.)?(?=\s|$))?"
            r"(?:\s+[A-Z][A-Za-z'\-]+){0,3}"
            r"(?:\s*,?\s*(?:M\.?D\.?|D\.?O\.?|PA(?:-C)?|NP|FNP|APRN|RN|DC|DDS))?"
            r")"
        )
        anchor_regex = "|".join(anchors)
        windows = self.build_provider_fallback_windows(text)
        patterns = [
            rf"(?:{anchor_regex})\s*(?:name\s*)?(?:[:\-]|is\b)?\s*{name_pattern}",
            rf"{name_pattern}\s*(?:[-|,:]|is\b|as\b)?\s*(?:{anchor_regex})\b",
        ]

        if field_name == "provider":
            patterns.extend([
                rf"(?:electronically signed by|signed by|signature on file(?: for)?|provider signature(?: of record)?)\s*[:\-]?\s*{name_pattern}",
                rf"{name_pattern}\s*(?:electronically signed by|signed by)\b",
            ])

        for window in windows:
            for pattern in patterns:
                match = re.search(pattern, window, re.IGNORECASE)
                if not match:
                    continue

                candidate = self.normalize_provider(match.group(1))
                if candidate:
                    return candidate

        return None

    def build_provider_fallback_windows(self, text):
        raw_lines = [
            re.sub(r"\s+", " ", line).strip()
            for line in re.split(r"[\r\n]+", str(text))
            if str(line).strip()
        ]
        windows = []

        for index, line in enumerate(raw_lines):
            windows.append(line)
            if index + 1 < len(raw_lines):
                combined = f"{line} {raw_lines[index + 1]}".strip()
                if len(combined) <= 220:
                    windows.append(combined)

        compact = re.sub(r"[\r\n\t]+", " ", str(text))
        compact = re.sub(r"\s+", " ", compact).strip()
        if compact:
            windows.append(compact)

        deduped = []
        seen = set()
        for window in windows:
            normalized = window.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(window)

        return deduped

    def get_page_metadata(self, packet, page_index):
        page_metadata = list(getattr(packet, "page_metadata", []) or [])
        if page_index < len(page_metadata):
            return page_metadata[page_index]
        return {}

    def get_field_zone_hints(self, field_name):
        hints = list(self.get_field_label_hints().get(field_name, []))
        if field_name == "authorization_number":
            hints.extend(["authorization", "referral", "member id", "box 4", "4 authorization"])
        return list(dict.fromkeys(hints))

    def extract_from_field_zones(self, page_metadata, field_name):
        page_metadata = dict(page_metadata or {})
        field_zones = list(page_metadata.get("field_zones", []) or [])
        if not field_zones:
            return None

        hints = [hint.lower() for hint in self.get_field_zone_hints(field_name)]
        if not hints:
            return None

        candidates = []
        for zone in field_zones:
            label = str(zone.get("normalized_label") or zone.get("label") or "").lower()
            raw_label = str(zone.get("label") or "").lower()
            if not label and not raw_label:
                continue

            if hints and not any(hint in label or hint in raw_label for hint in hints):
                continue

            value = self.clean_labeled_value(zone.get("value"), field_name)
            if not value:
                continue

            candidate = dict(zone)
            candidate["value"] = value
            candidates.append(candidate)

        if not candidates:
            return None

        candidates.sort(
            key=lambda zone: (
                float(zone.get("confidence") or 0.0),
                1 if zone.get("zone_name") == "native_text" else 0,
                len(str(zone.get("value") or "")),
            ),
            reverse=True,
        )
        return candidates[0]

    def capture_field_context(self, field_context, field_name, value, page_metadata=None, zone=None, strategy=None):
        if field_context is None:
            return

        page_metadata = dict(page_metadata or {})
        section_roles = list(
            field_context.get("_page_section_roles")
            or [entry.get("role") for entry in list(page_metadata.get("section_roles", []) or []) if entry.get("role")]
        )
        section_headings = list(
            field_context.get("_page_section_headings")
            or [entry.get("heading") for entry in list(page_metadata.get("section_roles", []) or []) if entry.get("heading")]
        )
        primary_section_role = field_context.get("_primary_section_role") or self.get_primary_section_role(section_roles)
        context = {
            "value": value,
            "strategy": strategy,
            "ocr_confidence": page_metadata.get("ocr_confidence"),
            "ocr_provider": page_metadata.get("ocr_provider"),
            "section_roles": section_roles,
            "section_headings": section_headings[:4],
            "primary_section_role": primary_section_role,
            "template_markers": list(field_context.get("_template_markers") or []),
        }
        if zone:
            context.update({
                "zone_name": zone.get("zone_name"),
                "zone_bbox": zone.get("bbox"),
                "anchor_label": zone.get("anchor_label") or zone.get("label"),
                "zone_confidence": zone.get("confidence"),
            })
        field_context[field_name] = context

    def extract_identity_fields(self, page, page_metadata=None, field_context=None):
        text = str(page)
        data = {}

        for field_name, patterns in self.IDENTITY_PATTERNS.items():
            zone_match = self.extract_from_field_zones(page_metadata, field_name)
            if zone_match:
                data[field_name] = zone_match["value"]
                self.capture_field_context(field_context, field_name, value=zone_match["value"], page_metadata=page_metadata, zone=zone_match, strategy="field_zone")
                continue
            value = self.extract_first_labeled_match(text, patterns, field_name)
            if value:
                data[field_name] = value

        for field_name in ("ordering_provider", "referring_provider", "provider"):
            if field_name in data:
                continue
            fallback_value = self.extract_provider_role_fallback(text, field_name)
            if fallback_value:
                data[field_name] = fallback_value

        if "provider" not in data:
            if "ordering_provider" in data:
                data["provider"] = data["ordering_provider"]
            elif "referring_provider" in data:
                data["provider"] = data["referring_provider"]

        if "va_icn" not in data:
            inferred_va_icn = self.infer_va_icn(text)
            if inferred_va_icn:
                data["va_icn"] = inferred_va_icn

        if "clinic_name" not in data:
            inferred_clinic_name = self.infer_clinic_name(text)
            if inferred_clinic_name:
                data["clinic_name"] = inferred_clinic_name

        return data

    def extract_labeled_fields(self, page, page_metadata=None, field_context=None):
        text = str(page)
        data = {}

        for field_name, patterns in self.FIELD_PATTERNS.items():
            zone_match = self.extract_from_field_zones(page_metadata, field_name)
            if zone_match:
                data[field_name] = zone_match["value"]
                self.capture_field_context(field_context, field_name, value=zone_match["value"], page_metadata=page_metadata, zone=zone_match, strategy="field_zone")
                continue
            value = self.extract_first_labeled_match(text, patterns, field_name)
            if value:
                data[field_name] = value

        if "facility" not in data:
            inferred_facility = self.infer_facility(text)
            if inferred_facility:
                data["facility"] = inferred_facility

        return data

    def extract_inferred_medical_fields(self, page):
        text = str(page)
        data = {}

        if "diagnosis" not in data:
            diagnosis = self.infer_diagnosis(text)
            if diagnosis:
                data["diagnosis"] = diagnosis

        symptom = self.infer_symptom(text)
        if symptom:
            data["symptom"] = symptom

        procedure = self.infer_procedure(text)
        if procedure:
            data["procedure"] = procedure

        contextual_icds = self.extract_contextual_icd_codes(text)
        regex_icds = self.extract_regex_icd_codes(text)
        inferred_icds = self.infer_icd_codes_from_diagnosis_text(text)

        merged_icds = self.merge_icd_codes(
            contextual_icds=contextual_icds,
            regex_icds=regex_icds,
            inferred_icds=inferred_icds,
        )
        if merged_icds:
            data["icd_codes"] = merged_icds

        medications = self.infer_medications(text)
        if medications:
            data["medications"] = medications

        if self.detect_signature_presence(text):
            data["signature_present"] = True

        return data

    def detect_signature_presence(self, text):
        normalized = str(text)
        strong_patterns = [
            r"\belectronically signed(?: by)?\b[^\n\r]{0,80}\b(?:dr\.?|md|do|pa|np|rn|[A-Z][a-z]+)\b",
            r"\bsigned by\b[^\n\r]{0,80}\b(?:dr\.?|md|do|pa|np|rn|[A-Z][a-z]+)\b",
            r"\b/s/\s*[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){0,3}\b",
            r"\bsignature on file\b",
        ]
        if any(re.search(pattern, normalized, re.IGNORECASE) for pattern in strong_patterns):
            return True

        labeled_signature = re.search(
            r"\b(?:provider|physician|clinician|patient|member)?\s*signature\b\s*[:\-]?\s*([^\n\r]{0,80})",
            normalized,
            re.IGNORECASE,
        )
        if not labeled_signature:
            return False

        trailing = labeled_signature.group(1).strip()
        if not trailing:
            return False

        trailing = re.split(
            r"\b(?:date|dob|phone|fax|address|facility|location|npi|provider|patient name|veteran name)\b",
            trailing,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0].strip(" :.-")
        if not trailing:
            return False

        if re.fullmatch(r"[_\-. ]{3,}", trailing):
            return False

        if re.search(r"[A-Za-z]", trailing):
            return True

        return False

    def merge_extraction_data(self, primary_data, secondary_data):
        merged = dict(primary_data)

        for key, value in secondary_data.items():
            if key not in merged:
                merged[key] = value
                continue

            if key == "icd_codes":
                existing = merged.get(key, [])
                merged[key] = sorted(set(existing + value))

        return merged

    def extract_first_labeled_match(self, text, patterns, field_name):
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if not match:
                continue

            raw_value = match.group(1).strip()
            cleaned_value = self.clean_labeled_value(raw_value, field_name)

            if cleaned_value:
                return cleaned_value

        return None

    def clean_labeled_value(self, raw_value, field_name):
        value = raw_value.strip()
        value = re.sub(r"\s+", " ", value)
        value = re.split(r"\s{2,}|\t|\||;", value)[0].strip()
        value = re.sub(r"^[\s:.\-#]+", "", value).strip()

        if field_name == "dob":
            return self.normalize_dob(value)

        if field_name in {"provider", "ordering_provider", "referring_provider"}:
            return self.normalize_provider(value)

        if field_name == "name":
            return self.normalize_name(value)

        if field_name == "authorization_number":
            return self.normalize_authorization_number(value)

        if field_name == "facility":
            return self.normalize_facility(value)

        if field_name == "location":
            return self.normalize_location(value)

        if field_name == "clinic_name":
            return self.normalize_clinic_name(value)

        if field_name == "reason_for_request":
            return self.normalize_reason_for_request(value)

        if field_name == "diagnosis":
            return self.normalize_diagnosis(value)

        if field_name == "npi":
            return self.normalize_npi(value)

        if field_name == "va_icn":
            return self.normalize_identifier(value, min_length=8)

        if field_name == "claim_number":
            return self.normalize_identifier(value, min_length=4)

        if field_name == "service_date_range":
            return self.normalize_service_date_range(value)

        if field_name == "medications":
            return self.normalize_medications(value)

        if field_name == "procedure":
            return self.normalize_procedure(value)

        return value or None

    def format_title_text(self, value):
        value = str(value).strip()
        if not value:
            return value

        if value.isupper():
            value = value.title()

        replacements = {
            "Va": "VA",
            "Vamc": "VAMC",
            "Usa": "USA",
            "Npi": "NPI",
            "Icn": "ICN",
            "Ssn": "SSN",
        }
        for old, new in replacements.items():
            value = re.sub(rf"\b{old}\b", new, value)

        return value

    def canonicalize_known_clinic_name(self, value):
        raw = str(value or "").strip()
        if not raw:
            return None

        lowered = raw.lower()
        known_patterns = [
            (
                r"\baiken neurosciences(?:\s+and)?\s+pain management,?\s*l\.?l\.?c\.?\b",
                "Aiken Neurosciences And Pain Management, Llc",
            ),
        ]
        for pattern, canonical in known_patterns:
            if re.search(pattern, lowered, re.IGNORECASE):
                return canonical

        entity_match = re.search(
            r"((?:[A-Z][A-Za-z&'\-]*\.?,?\s+){1,6}(?:LLC|L\.L\.C\.|INC|P\.?C\.?|PLLC|CLINIC|CENTER|ASSOCIATES|GROUP|MANAGEMENT))",
            raw,
            re.IGNORECASE,
        )
        if entity_match:
            return self.format_title_text(entity_match.group(1).strip(" ,.-"))

        return None

    def detect_suspect_field_reason(self, field_name, value, mapping=None):
        raw = str(value or "").strip()
        if not raw:
            return None

        mapping = dict(mapping or {})
        snippet = str(mapping.get("snippet") or "").strip()
        anchor = str(mapping.get("anchor_label") or "").strip()
        combined = " ".join(part for part in [raw, snippet, anchor] if part).lower()
        template_markers = list(mapping.get("template_markers") or [])

        if self.contains_template_value_marker(raw):
            return "template placeholder text captured as live field value"

        if field_name in {"provider", "ordering_provider", "referring_provider"}:
            if re.search(r"\byear[- ]old\b|\bmale\b|\bfemale\b", combined):
                return "demographic narrative misread as provider"
            if "care team" in combined:
                return "care-team text misread as provider"
            raw_tokens = re.findall(r"[A-Za-z']+", raw)
            if raw_tokens and not raw.isupper() and any(token.isupper() and len(token) >= 3 for token in raw_tokens):
                return "mixed-case OCR fragment in provider name"
            if len(raw_tokens) > 4:
                return "provider value spilled into narrative text"

        if field_name == "clinic_name":
            if self.canonicalize_known_clinic_name(raw):
                return None
            narrative_markers = [
                "injected",
                "fluoroscopic",
                "revealed",
                "spinal nerve",
                "neural foramen",
                "proximal spread",
                "needle",
                "contrast",
                "epidural",
            ]
            if any(marker in combined for marker in narrative_markers):
                return "procedure narrative leaked into clinic name"
            if len(raw.split()) > 8:
                return "clinic value is too long to be a real organization name"

        if field_name == "facility":
            if any(marker in combined for marker in ["fluoroscopic", "injected", "neural foramen", "spinal nerve"]):
                return "procedure narrative leaked into facility"

        if field_name == "reason_for_request":
            if combined.strip() in {"patient's care team", "patients care team", "care team"}:
                return "non-request care-team text captured as reason for request"
            if template_markers and "bracket_placeholder" in template_markers and self.contains_template_value_marker(raw):
                return "template placeholder text captured as live request intent"

        return None

    def parse_date_text(self, value):
        cleaned = str(value).strip()
        if not cleaned:
            return None

        cleaned = re.sub(r"(\d{1,2})(st|nd|rd|th)\b", r"\1", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s+", " ", cleaned.replace("-", "/")).strip()

        formats = (
            "%m/%d/%Y",
            "%m/%d/%y",
            "%Y/%m/%d",
            "%B %d, %Y",
            "%b %d, %Y",
            "%B %d %Y",
            "%b %d %Y",
        )

        for fmt in formats:
            try:
                parsed = datetime.strptime(cleaned, fmt)
                return parsed.strftime("%m/%d/%Y")
            except ValueError:
                continue

        return None

    def normalize_dob(self, value):
        match = re.search(
            r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2}|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*|\s+)\d{4})\b",
            str(value),
            re.IGNORECASE,
        )
        candidate = match.group(1) if match else str(value).strip()
        return self.parse_date_text(candidate)

    def normalize_name(self, value):
        value = self.cut_at_stop_label(value)
        value = re.sub(
            r"\b(?:jr|sr|md|m\.d\.|do|d\.o\.|pa|np|rn)\b\.?$",
            "",
            value,
            flags=re.IGNORECASE,
        ).strip()

        value = re.sub(r"[^A-Za-z,\-\' ]", " ", value)
        value = re.sub(r"\s+", " ", value).strip(" ,.-")

        if not value:
            return None

        invalid_name_phrases = {
            "admin documents",
            "clinical documentation",
            "submission cover sheet",
            "letter of medical necessity",
            "consultation and treatment request",
            "single episode of care",
            "virtual consent form",
            "medical necessity",
            "request for service",
            "community care",
            "last four ss",
            "last four ssn",
            "last four",
            "va claim number",
        }

        lowered = value.lower()
        if lowered in invalid_name_phrases:
            return None

        if lowered.startswith("last four"):
            return None

        collapsed = lowered.replace(" ", "")
        label_fragments = (
            "dateofbirth",
            "birthdate",
            "patientname",
            "veteranname",
            "fullname",
            "membername",
            "telehealthconsent",
        )
        if any(fragment in collapsed for fragment in label_fragments):
            return None
        if "birth" in collapsed and any(fragment in collapsed for fragment in ("phone", "phos", "dob")):
            return None

        # Reject obvious non-person junk
        junk_tokens = {
            "document", "documents", "form", "request", "service",
            "care", "clinical", "consultation", "necessity", "authorization",
            "pob", "dob", "ssn", "claim", "submission", "provider",
            "diagnosis", "code", "office", "reviewed", "ss",
        }
        pieces = lowered.replace(",", " ").split()
        if any(token in junk_tokens for token in pieces):
            return None

        if value.isupper():
            value = value.title()

        if len(value.split()) < 2:
            return None

        # Require at least mostly alphabetic name-like content
        alpha_count = sum(ch.isalpha() for ch in value)
        if alpha_count < 6:
            return None

        return value

    def normalize_provider(self, value):
        raw_value = str(value or "")
        had_provider_title = bool(
            re.search(r"\b(?:dr|doctor|md|m\.d\.|do|d\.o\.|pa|np|rn|fnp|aprn|dc|dds)\b\.?", raw_value, re.IGNORECASE)
        )
        value = self.cut_at_stop_label(raw_value)
        value = re.split(
            r"\b(?:today'?s(?:\s+date)?|date\s*\(mm/dd(?:/yyyy)?\)|mm/dd(?:/yyyy)?)\b",
            value,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0]
        value = re.split(
            r"\b(?:(?:p|d)ate\s+of\s+submission|primary diagnosis code|office staff|submitting office|reviewed|patient name|veteran name|phone|fax|npi|address|facility|date|dob|reason(?:\s+for\s+(?:request|referral))?|chief complaint|requested service|requested procedure|diagnosis|assessment|impression)\b",
            value,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0]
        value = re.sub(
            r"\b(?:dr|doctor|md|m\.d\.|do|d\.o\.|pa|np|rn|fnp|aprn|dc|dds)\b\.?",
            " ",
            value,
            flags=re.IGNORECASE,
        )
        value = re.sub(r"[^A-Za-z,\-\'\. ]", " ", value)
        value = re.sub(r"\s+", " ", value).strip(" ,.-")

        if not value:
            return None

        lowered = value.lower()
        if re.match(r"^(?:is|was|are|new|the|for|patient|evaluation|treatment)\b", lowered):
            return None
        invalid_phrases = (
            "secure email",
            "email address",
            "provider signa",
            "provider signature",
            "signature",
            "office staff",
            "fax number",
            "phone number",
            "today's",
            "todays",
            "year-old",
            "patient's care team",
            "patients care team",
            "care team",
        )
        if any(phrase in lowered for phrase in invalid_phrases):
            return None
        if re.match(r"^(?:another|secure|email|signature)\b", lowered):
            return None
        if re.search(r"\byear[- ]old\b|\bmale\b|\bfemale\b", lowered):
            return None
        narrative_keywords = {
            "evaluation",
            "treatment",
            "diagnosis",
            "diagnoses",
            "patient",
            "veteran",
            "pain",
            "lumbar",
            "cervical",
            "mri",
            "therapy",
            "injection",
            "intervention",
            "management",
            "activities",
            "clinical",
            "findings",
            "physical",
            "exercise",
            "epidural",
            "support",
            "request",
            "service",
            "procedure",
        }
        connector_tokens = {
            "the",
            "for",
            "of",
            "and",
            "to",
            "from",
            "at",
            "by",
            "on",
            "in",
            "with",
        }
        organizational_tokens = {
            "va",
            "vamc",
            "veterans",
            "affairs",
            "community",
            "care",
            "office",
            "clinic",
            "medical",
            "center",
            "hospital",
        }
        tokens = [token for token in re.split(r"[\s,]+", lowered) if token]

        if len(tokens) > 6:
            return None

        if len(tokens) == 1:
            if not had_provider_title or len(tokens[0]) < 4:
                return None
        elif len(tokens) < 2:
            return None

        if any(token in connector_tokens for token in tokens):
            return None

        if sum(1 for token in tokens if token in narrative_keywords) >= 2:
            return None

        if sum(1 for token in tokens if token in organizational_tokens) >= 1:
            return None

        alpha_tokens = [token for token in tokens if re.fullmatch(r"[a-z][a-z'\-]*", token)]
        clean_name_tokens = [
            token
            for token in alpha_tokens
            if token not in narrative_keywords and token not in organizational_tokens and token not in connector_tokens
        ]
        long_name_tokens = [token for token in clean_name_tokens if len(token) >= 2]
        if len(tokens) == 1:
            if len(clean_name_tokens) != 1:
                return None
        elif len(clean_name_tokens) < 2:
            return None
        if len(long_name_tokens) < 2:
            return None
        if len(tokens) <= 2 and any(len(token) == 1 for token in clean_name_tokens):
            return None

        if len(value) > 60:
            return None

        raw_tokens = re.findall(r"[A-Za-z']+", raw_value)
        if raw_tokens and not raw_value.isupper() and any(token.isupper() and len(token) >= 3 for token in raw_tokens):
            return None

        if value.isupper():
            value = value.title()

        provider_corrections = {
            "wile durrett": "William Durrett",
            "wiliam durrett": "William Durrett",
            "willam durrett": "William Durrett",
        }
        corrected = provider_corrections.get(value.lower())
        if corrected:
            value = corrected

        value = re.sub(r"\b([A-Z])\.\s+(?=[A-Z][a-z]+$)", "", value).strip()
        value = re.sub(r"\s+", " ", value).strip()

        if len(tokens) == 1:
            return value

        if len(value.split()) < 2:
            return None

        return value

    def normalize_authorization_number(self, value):
        original_value = str(value or "")
        value = self.cut_at_stop_label(value)
        value = re.sub(
            r"^(?:community care|authorization(?:\s+number|\s+no\.?)?|auth(?:orization)?(?:\s+number|\s+no\.?)?|ref(?:\.|erral)?(?:\s+number|\s+no\.?)?|member\s*id|tracking(?:\s+number|\s+no\.?|\s+id)?|reference(?:\s+number|\s+no\.?|\s+id)?|case(?:\s+number|\s+no\.?|\s+id)?|consult(?:\s+number|\s+no\.?|\s+id)?|episode(?:\s+of\s+care)?(?:\s+number|\s+no\.?|\s+id)?|seoc(?:\s+number|\s+no\.?|\s+id)?)\b",
            "",
            value,
            flags=re.IGNORECASE,
        )
        value = re.split(
            r"\b(?:effective|expiration|expires|issued|date|dates|dob|member|patient|provider|facility|form|fax|phone|ref|icn)\b",
            value,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0]
        value = value.strip(" \t\r\n:;#.-")
        value = value.upper()
        value = re.sub(r"[\s/]+", "-", value)
        value = re.sub(r"[^A-Z0-9\-]", "", value)
        value = self.strip_trailing_label_suffixes(value)
        value = re.sub(r"-{2,}", "-", value).strip("-")

        if len(value) < 6 or len(value) > 24:
            return None

        compact = value.replace("-", "")

        if value.startswith("VA") and compact.startswith("VA") and compact[2:].isdigit():
            digit_tail = compact[2:]
            if 8 <= len(digit_tail) <= 18:
                return f"VA{digit_tail}"

        if re.fullmatch(r"\d{6}", compact):
            return None
        if re.fullmatch(r"\d{8}", compact):
            return None
        if re.fullmatch(r"\d{1,2}-\d{1,2}-\d{2,4}", value):
            return None
        if re.fullmatch(r"\d{4}-\d{1,2}-\d{1,2}", value):
            return None

        if compact == "10172":
            return None

        digit_count = sum(ch.isdigit() for ch in compact)
        alpha_count = sum(ch.isalpha() for ch in value)

        if not value.startswith("VA") and re.fullmatch(r"[A-Z]{2}-\d{5}(?:-\d{4})?(?:-[A-Z]{1,12}){0,4}", value):
            return None

        if not value.startswith("VA") and re.search(r"\d+(?:ST|ND|RD|TH)\b", compact):
            return None

        if not value.startswith("VA") and re.search(
            r"\b(?:ST|STREET|AVE|AVENUE|RD|ROAD|BLVD|BOULEVARD|DR|DRIVE|LN|LANE|CT|COURT|WAY|HWY|HIGHWAY)\b",
            original_value,
            re.IGNORECASE,
        ):
            return None

        if not value.startswith("VA") and re.fullmatch(r"\d{3}-\d{3}-\d{4,7}[A-Z]{0,2}", value):
            return None

        if not value.startswith("VA") and digit_count >= 10 and value.count("-") >= 2 and alpha_count <= 1:
            return None

        if compact.isdigit():
            if len(compact) < 9 or len(compact) > 18:
                return None
            return compact

        if not (re.search(r"[A-Z]", value) and re.search(r"\d", value)):
            return None

        if digit_count < 4:
            return None

        if not value.startswith("VA") and alpha_count > 4:
            return None

        if not value.startswith("VA") and digit_count < 6:
            return None

        if re.fullmatch(r"[A-Z]{1,3}-?\d{1,4}", value):
            return None

        return value

    def strip_trailing_label_suffixes(self, value):
        cleaned = str(value or "").strip(" \t\r\n-")

        suffix_pattern = re.compile(
            r"(?:DATE|DATES|DOB|REF|ICN|PATIENT|MEMBER|PROVIDER|FACILITY|FORM|PHONE|FAX|SERVICE)+$"
        )

        while cleaned:
            updated = suffix_pattern.sub("", cleaned).strip(" \t\r\n-")

            if updated == cleaned:
                break

            cleaned = updated

        return cleaned

    def normalize_facility(self, value):
        value = self.cut_at_stop_label(value)
        value = re.sub(
            r"^(?:facility(?: name)?|va facility|servicing facility|treating facility|requested facility|referring facility|rendering facility|medical facility|community care office|va community care office)\s*[:\-]?\s*",
            "",
            value,
            flags=re.IGNORECASE,
        )
        value = re.split(
            r"\b(?:phone|fax|npi|address|dob|provider|diagnosis|reason|city|state|zip|location)\b",
            value,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0]
        value = re.sub(r"[^A-Za-z0-9,\-&\'\.()/ ]", " ", value)
        value = re.sub(r"\s+", " ", value).strip(" ,.-")

        if not value:
            return None

        value = re.split(r",\s*\d{1,5}\b", value, maxsplit=1)[0]
        value = re.split(r"\bph\s*\(", value, maxsplit=1, flags=re.IGNORECASE)[0]
        value = value.strip(" ,.-")

        invalid_facility_values = {"lbp", "pain", "mri", "ct", "xray", "clinic", "office"}

        if value.lower() in invalid_facility_values:
            return None

        lowered = value.lower()
        if re.match(r"^\d{1,5}\s+", value):
            return None
        if re.search(r"charlie\s+n[0o]r[wv][o0]{2}d", lowered):
            return "Charlie Norwood VA Medical Center"
        facility_keywords = [
            "medical center",
            "hospital",
            "health system",
            "healthcare",
            "clinic",
            "center",
            "vamc",
            "va ",
            "department of veterans affairs",
        ]
        if not any(keyword in lowered for keyword in facility_keywords):
            if len(value.split()) < 3:
                return None

        if "pharmacy" in lowered:
            return None

        if re.fullmatch(r"[A-Za-z]+(?:\s+[A-Za-z]+){0,2}", value) and "va" not in lowered and "clinic" not in lowered:
            return None

        if len(value) < 3:
            return None

        return self.format_title_text(value)

    def infer_facility(self, text):
        compact = re.sub(r"[\r\n\t]+", " ", str(text or ""))
        compact = re.sub(r"\s+", " ", compact).strip()
        if not compact:
            return None

        patterns = [
            r"\b([A-Z][A-Za-z&,\-\. ]{6,}VA Medical Center)\b",
            r"\b([A-Z][A-Za-z&,\-\. ]{6,}VAMC)\b",
            r"\b([A-Z][A-Za-z&,\-\. ]{6,}(?:Medical Center|Hospital|Health System))\b",
        ]

        for pattern in patterns:
            match = re.search(pattern, compact, re.IGNORECASE)
            if not match:
                continue
            candidate = self.normalize_facility(match.group(1))
            if candidate:
                return candidate

        return None

    def infer_clinic_name(self, text):
        compact = re.sub(r"[\r\n\t]+", " ", str(text or ""))
        compact = re.sub(r"\s+", " ", compact).strip()
        if not compact:
            return None

        patterns = [
            r"\b([A-Z][A-Z&,\-\. ]{8,}(?:LLC|L\.L\.C\.|PC|P\.C\.|INC|CORP|CLINIC|MANAGEMENT))\b",
            r"\b([A-Z][A-Z&,\-\. ]{8,}(?:NEUROSCIENCES|PAIN MANAGEMENT|MEDICAL GROUP|MEDICAL CENTER|CLINIC))\b",
        ]

        for pattern in patterns:
            match = re.search(pattern, compact)
            if not match:
                continue
            candidate = self.normalize_clinic_name(match.group(1))
            if candidate:
                return candidate

        return None

    def infer_va_icn(self, text):
        compact = re.sub(r"[\r\n\t]+", " ", str(text or ""))
        compact = re.sub(r"\s+", " ", compact).strip()
        lower_text = compact.lower()

        if not lower_text:
            return None

        if "va community care" not in lower_text and "optum - va community care" not in lower_text:
            return None

        insurance_match = re.search(
            r"insurance\s*(?:number|no\.?|#)\s*[:\-]?\s*([A-Z0-9]{8,24})\b",
            compact,
            re.IGNORECASE,
        )
        if not insurance_match:
            return None

        return self.normalize_identifier(insurance_match.group(1), min_length=8)

    def normalize_location(self, value):
        value = self.cut_at_stop_label(value)
        value = re.sub(
            r"^(?:office location|clinic location|facility location|city/state|city,\s*state|city|location)\s*[:\-]?\s*",
            "",
            value,
            flags=re.IGNORECASE,
        )
        value = re.split(
            r"\b(?:phone|fax|npi|address|provider|facility|diagnosis|reason|zip)\b",
            value,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0]
        value = re.sub(r"[^A-Za-z0-9,\-&\'\.()/ ]", " ", value)
        value = re.sub(r"\s+", " ", value).strip(" ,.-")

        if not value or len(value) < 3:
            return None

        invalid_values = {
            "lbp",
            "low back pain",
            "lumbar",
            "cervical",
            "hip pain",
            "shoulder pain",
            "neck pain",
            "pain",
        }
        if value.lower() in invalid_values:
            return None

        if re.search(r"\d", value):
            return None

        symptom_like_markers = [
            "radiating",
            "bilateral",
            "posterior",
            "anterior",
            "shoulder pain",
            "neck pain",
            "back pain",
            "left shoulder",
            "right shoulder",
            "ue",
            "le",
        ]
        if any(marker in value.lower() for marker in symptom_like_markers):
            return None

        city_state = re.search(r"^([A-Za-z .'\-]+?)(?:,\s*|\s+)([A-Za-z]{2})$", value)
        if city_state:
            city = self.format_title_text(city_state.group(1).strip())
            state = city_state.group(2).upper()
            return f"{city}, {state}"

        if len(value) > 40:
            return None

        return self.format_title_text(value)

    def normalize_clinic_name(self, value):
        value = self.cut_at_stop_label(value)
        value = re.sub(
            r"^(?:clinic(?: name)?|practice(?: name)?|submitting office|office name|provider group|group name)\s*[:\-]?\s*",
            "",
            value,
            flags=re.IGNORECASE,
        )
        value = re.split(
            r"\b(?:phone|fax|npi|address|city|state|zip|location|facility|dob|provider)\b",
            value,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0]
        value = re.sub(r"^(?:pm|p\.m\.)\s+", "", value, flags=re.IGNORECASE)
        canonical = self.canonicalize_known_clinic_name(value)
        if canonical:
            return canonical
        value = re.sub(r"[^A-Za-z0-9,\-&\'\.()/ ]", " ", value)
        value = re.sub(r"\s+", " ", value).strip(" ,.-")

        if not value or len(value) < 3:
            return None

        invalid_values = {"office", "clinic", "practice"}
        if value.lower() in invalid_values:
            return None

        connector_fragments = {"and", "&", "of", "for"}
        first_token = value.lower().split()[0] if value.split() else ""
        if first_token in connector_fragments:
            return None

        lowered = value.lower()
        if any(keyword in lowered for keyword in ["medical center", "hospital", "vamc"]) and "clinic" not in lowered:
            return None

        narrative_markers = [
            "injected",
            "fluoroscopic",
            "revealed",
            "spinal nerve",
            "neural foramen",
            "proximal spread",
            "contrast",
            "epidural",
        ]
        if any(marker in lowered for marker in narrative_markers):
            return None

        if len(value.split()) > 8:
            return None

        return self.format_title_text(value)

    def normalize_reason_for_request(self, value):
        value = self.cut_at_stop_label(value)
        value = re.sub(
            r"^(?:reason for request|reason for consultation|reason for consult|reason for referral|request rationale|chief complaint|history of present illness|requested service|requested procedure|reason)\s*[:\-]?\s*",
            "",
            value,
            flags=re.IGNORECASE,
        )
        value = re.split(
            r"\b(?:icd|diagnosis|provider|facility|dob|authorization|auth)\b",
            value,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0]
        value = re.sub(r"\s+", " ", value).strip(" ,.-")

        if not value or len(value) < 4:
            return None

        if value.lower() in {"patient's care team", "patients care team", "care team"}:
            return None

        return value

    def normalize_npi(self, value):
        digits = re.sub(r"\D", "", value)
        if len(digits) != 10:
            return None
        return digits

    def normalize_identifier(self, value, min_length=4):
        original = str(value).strip()
        cleaned = re.sub(
            r"\b(?:claim(?: number| no\.?)?|va claim number|claim #|icn|va icn|integrated control number|icn/ssn|last four ssn|last four|ssn ending(?: in)?|ending in)\b",
            "",
            original,
            flags=re.IGNORECASE,
        )
        cleaned = re.sub(r"[^A-Za-z0-9\-]", "", cleaned.upper())
        cleaned = self.strip_trailing_label_suffixes(cleaned)
        if len(cleaned) < min_length:
            return None

        invalid_cleaned_values = {
            "NUMBER",
            "CLAIMNUMBER",
            "VACLAIMNUMBER",
            "LASTFOUR",
            "LASTFOURSS",
            "LASTFOURSSN",
            "REFERRING",
            "PROVIDER",
            "UNKNOWN",
            "NONE",
            "NA",
            "NAN",
        }
        if cleaned in invalid_cleaned_values:
            return None

        if not re.search(r"\d", cleaned):
            return None

        date_like_patterns = [
            r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
            r"\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b",
            r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*|\s+)\d{4}\b",
        ]
        if any(re.search(pattern, original, re.IGNORECASE) for pattern in date_like_patterns):
            return None

        if re.fullmatch(r"(?:19|20)\d{6}", cleaned):
            return None
        return cleaned

    def normalize_service_date_range(self, value):
        date_matches = re.finditer(
            r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2}|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*|\s+)\d{4})\b",
            str(value),
            re.IGNORECASE,
        )
        dates = [match.group(1) for match in date_matches]
        if not dates:
            return None

        normalized_dates = [self.parse_date_text(date) for date in dates if self.parse_date_text(date)]
        if not normalized_dates:
            return None

        if len(normalized_dates) == 1:
            return normalized_dates[0]

        return f"{normalized_dates[0]} to {normalized_dates[-1]}"

    def normalize_medications(self, value):
        chunks = []
        for part in re.split(r"[,;/]|\band\b", str(value), flags=re.IGNORECASE):
            part = re.sub(r"\s+", " ", part).strip(" ,.-")
            if part:
                chunks.append(part.title())

        unique = []
        seen = set()
        for item in chunks:
            lowered = item.lower()
            if lowered not in seen:
                seen.add(lowered)
                unique.append(item)

        return unique or None

    def normalize_procedure(self, value):
        cleaned = str(value or "").strip()
        if not cleaned:
            return None

        lowered = re.sub(r"\s+", " ", cleaned).lower()

        if re.fullmatch(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\)?", lowered):
            return None

        if any(marker in lowered for marker in [
            "extremities",
            "capillary",
            "opioid use",
            "pain management",
            "provider signa",
            "signature",
        ]):
            return None

        if re.search(r"\bmri\b|\bmagnetic resonance imaging\b", lowered):
            return "MRI"
        if re.search(r"\bcat scan\b|\bcomputed tomography\b", lowered):
            return "CT"
        if re.search(r"\bx[- ]?ray\b|\bradiograph\b", lowered):
            return "XRAY"
        if re.search(r"\bphysical therapy\b|\bpt evaluation\b", lowered):
            return "PHYSICAL_THERAPY"

        return None

    def normalize_diagnosis(self, value):
        value = self.cut_at_stop_label(value)
        value = re.sub(
            r"^(?:episode diagnosis|primary diagnosis code|diagnosis|diagnoses|assessment|impression|clinical impression|primary|secondary)\s*[:\-]?\s*",
            "",
            value,
            flags=re.IGNORECASE,
        )
        value = re.sub(r"\s+", " ", value).strip(" ,.-")

        if not value:
            return None

        lowered = value.lower()

        invalid_diagnosis_values = {
            "pre",
            "post",
            "n/a",
            "na",
            "none",
            "unknown",
            "primary",
            "secondary",
        }
        if lowered in invalid_diagnosis_values:
            return None

        if len(lowered) < 4:
            return None

        if len(lowered) > 90:
            return None

        if "primary:" in lowered and "secondary" in lowered:
            return None

        if any(marker in lowered for marker in ["optum", "community care netw", "med primary", "insurance"]):
            return None

        procedural_noise_markers = [
            "annul",
            "annulargram",
            "fibrin injection",
            "injection",
            "pain management",
            "requested service",
            "scope of requested episode",
            "continuity of care",
            "postoperative",
        ]

        if len(lowered.split()) > 8 and any(marker in lowered for marker in procedural_noise_markers):
            return None

        problem_match = re.search(
            r"(?:^|\bassessment\s*/\s*plan\b|\bdiagnosis\b)\s*(?:\d+\.\s*)?([A-Za-z][A-Za-z '\-]{3,80}?)(?:\s+M\d{2}(?:\.\d{1,4})?:|\s+G\d{2}(?:\.\d{1,4})?:|:|$)",
            value,
            re.IGNORECASE,
        )
        if problem_match:
            candidate = re.sub(r"\s+", " ", problem_match.group(1)).strip(" ,.-")
            candidate_lower = candidate.lower()
            if candidate_lower and "radiculopathy" not in candidate_lower:
                value = candidate
                lowered = candidate_lower

        for canonical, aliases in self.DIAGNOSIS_KEYWORDS.items():
            if canonical in lowered or any(alias in lowered for alias in aliases):
                return canonical

        return lowered

    def cut_at_stop_label(self, value):
        lower_value = value.lower()
        earliest_index = None

        for label in self.STOP_LABELS:
            idx = lower_value.find(label)
            if idx > 0:
                if earliest_index is None or idx < earliest_index:
                    earliest_index = idx

        if earliest_index is not None:
            value = value[:earliest_index].strip()

        return value

    def extract_contextual_icd_codes(self, text):
        contextual_patterns = [
            r"(?:icd(?:-10)?(?: code)?s?|diagnosis code(?:s)?)\s*[:\-]\s*([^\n\r]+)",
        ]

        codes = []
        for pattern in contextual_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                block = match.group(1)
                codes.extend(self.extract_regex_icd_codes(block))

        return sorted(set(codes))

    def extract_regex_icd_codes(self, text):
        matches = re.findall(r"\b[A-Z][0-9]{2}(?:\.[0-9A-Z]{1,4})?\b", text)
        return sorted(set(matches))

    def infer_icd_codes_from_diagnosis_text(self, text):
        lower_text = text.lower()
        inferred = []

        if any(term in lower_text for term in ["migraine", "migraines"]):
            inferred.append("G43.909")

        if any(term in lower_text for term in ["osteoarthritis", "degenerative joint disease", "djd"]):
            inferred.append("M19.90")

        if any(term in lower_text for term in ["low back pain", "lumbar pain", "back pain"]):
            inferred.append("M54.50")

        if any(term in lower_text for term in ["neck pain", "cervicalgia"]):
            inferred.append("M54.2")

        return sorted(set(inferred))

    def merge_icd_codes(self, contextual_icds, regex_icds, inferred_icds):
        if contextual_icds:
            combined = contextual_icds + inferred_icds
        else:
            combined = regex_icds + inferred_icds

        normalized = [self.normalize_icd(code) for code in combined if code]
        normalized = [code for code in normalized if code]

        specific_prefixes = {
            code.split(".")[0]
            for code in normalized
            if "." in code
        }
        normalized = [
            code for code in normalized
            if ("." in code) or (code.split(".")[0] not in specific_prefixes)
        ]

        return sorted(set(normalized))
    
    def normalize_icd(self, code):
        code = code.upper().strip()

        # Common normalization cases
        ICD_NORMALIZATION_MAP = {
            "M54.5": "M54.50",
            "M54.50": "M54.50",
            "M54.2": "M54.2",
            "G43.9": "G43.909",
            "G43.909": "G43.909",
            "M19.9": "M19.90",
            "M19.90": "M19.90",
        }

        if code in ICD_NORMALIZATION_MAP:
            return ICD_NORMALIZATION_MAP[code]

        if re.fullmatch(r"[A-Z][0-9]{2}", code):
            return None

        return code

    def infer_diagnosis(self, text):
        lower_text = text.lower()

        for canonical, aliases in self.DIAGNOSIS_KEYWORDS.items():
            if canonical in lower_text:
                return canonical
            for alias in aliases:
                if alias in lower_text:
                    return canonical

        return None

    def infer_facility(self, text):
        compact = re.sub(r"[\r\n\t]+", " ", str(text or ""))
        compact = re.sub(r"\s+", " ", compact).strip()
        lower_text = compact.lower()

        if not lower_text:
            return None

        if re.search(r"charlie\s+n[0o]r[vw][o0]{2}d", lower_text):
            return "Charlie Norwood VA Medical Center"

        if "va medical center" in lower_text and "augusta" in lower_text:
            return "Charlie Norwood VA Medical Center"

        match = re.search(r"(va medical center[^\n\r]{0,80})", compact, re.IGNORECASE)
        if match:
            candidate = self.normalize_facility(match.group(1))
            if candidate:
                return candidate

        return None

    def infer_symptom(self, text):
        lower_text = text.lower()

        for canonical, aliases in self.SYMPTOM_KEYWORDS.items():
            if canonical in lower_text:
                return canonical
            for alias in aliases:
                if alias in lower_text:
                    return canonical

        return None

    def infer_procedure(self, text):
        request_windows = [
            r"(?:requested procedure|requested service|authorization is requested for|authorization requested for|plan includes|candidate for|procedure(?:s)? performed)\s*[:\-]?\s*([^\n\r]{0,120})",
            r"([^\n\r]{0,120})\s*(?:requested procedure|requested service|authorization is requested for)",
        ]

        candidates = []
        for pattern in request_windows:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                candidates.append(match.group(1))

        if not candidates:
            return None

        combined = " ".join(candidates).lower()

        if re.search(r"\bmri\b|\bmagnetic resonance imaging\b", combined):
            return "MRI"

        if re.search(r"\bcat scan\b|\bcomputed tomography\b", combined):
            return "CT"

        if re.search(r"\bx[- ]?ray\b|\bradiograph\b", combined):
            return "XRAY"

        if re.search(r"\bphysical therapy\b|\bpt evaluation\b", combined):
            return "PHYSICAL_THERAPY"

        return None

    def infer_medications(self, text):
        lower_text = text.lower()
        medication_context_terms = [
            "medication",
            "medications",
            "current meds",
            "current medications",
            "taking",
            "prescribed",
            "rx",
        ]
        if not any(term in lower_text for term in medication_context_terms):
            return []

        found = []

        for canonical, aliases in self.MEDICATION_KEYWORDS.items():
            if canonical in lower_text or any(alias in lower_text for alias in aliases):
                found.append(canonical.title())

        return sorted(set(found))

    def get_field_label_hints(self):
        return {
            "name": ["veteran name", "patient name", "full name", "member name"],
            "dob": ["dob", "date of birth", "birth date", "d.o.b."],
            "provider": ["provider", "provider name", "treating provider", "rendering provider", "attending provider"],
            "ordering_provider": ["ordering provider", "ordering physician", "ordered by", "requested by", "requesting provider"],
            "referring_provider": ["referring provider", "referring va provider", "referred by", "ref provider", "pcp", "referring physician"],
            "authorization_number": ["authorization number", "auth number", "auth no", "auth #", "authorization #", "referral number", "referral #", "member id", "tracking number", "reference number", "ref"],
            "facility": ["facility", "facility name", "va facility", "servicing facility", "treating facility", "requested facility", "medical facility", "medical center", "va medical center", "community care office", "va community care office", "vamc"],
            "location": ["location", "office location", "clinic location", "facility location", "city", "city/state"],
            "clinic_name": ["clinic", "clinic name", "practice name", "office", "submitting office", "office name", "provider group"],
            "npi": ["npi"],
            "va_icn": ["icn", "va icn", "integrated control number", "icn/ssn"],
            "claim_number": ["claim number", "claim #", "va claim number", "last four ssn", "ssn ending"],
            "reason_for_request": ["reason for request", "reason for consultation", "reason for consult", "reason for referral", "request rationale", "chief complaint", "requested service", "requested procedure", "clinical goals"],
            "diagnosis": ["episode diagnosis", "primary diagnosis code", "diagnosis", "diagnoses", "assessment", "impression", "clinical impression"],
            "icd_codes": ["icd", "icd-10", "diagnosis code"],
            "service_date_range": ["date of service", "dates of service", "service date", "visit date", "dos", "through"],
            "medications": ["medications", "current meds", "current medications"],
            "signature_present": ["signature", "signed by", "electronically signed"],
        }

    def get_field_source_terms(self, value):
        if isinstance(value, (list, tuple, set)):
            return [str(item).strip() for item in value if str(item).strip()]

        if value is True:
            return []

        term = str(value).strip()
        return [term] if term else []

    def build_excerpt(self, text, start, end, radius=80):
        text = str(text or "")
        start = max(0, start - radius)
        end = min(len(text), end + radius)
        excerpt = re.sub(r"\s+", " ", text[start:end]).strip()
        return excerpt[:240]

    def infer_source_role(self, doc_type, text, page_metadata=None):
        lowered = str(text or "").lower()
        page_metadata = dict(page_metadata or {})
        layout = dict(page_metadata.get("layout", {}) or {})
        header_text = str(layout.get("header_text") or "").lower()
        combined = f"{lowered}\n{header_text}"

        if doc_type in {"clinical_notes", "lomn"}:
            return "community_provider"

        if doc_type in {"consult_request", "seoc"}:
            return "va_clinic"

        if doc_type == "consent":
            return "patient"

        if doc_type in {"cover_sheet", "rfs"}:
            return "shared"

        va_markers = [
            "referring va provider",
            "va facility",
            "va medical center",
            "va community care",
            "department of veterans affairs",
            "veterans affairs",
            "optum",
            "community care network",
            "charlie norwood",
            "10-10172",
            "request for service",
        ]
        provider_markers = [
            "clinical notes",
            "letter of medical necessity",
            "ordering provider",
            "rendering provider",
            "provider npi",
            "clinic name",
            "practice name",
            "aiken neurosciences",
            "pain management",
        ]

        if any(marker in combined for marker in va_markers):
            return "va_clinic"

        if any(marker in combined for marker in provider_markers):
            return "community_provider"

        return "unknown"

    def build_field_mapping(self, packet, key, value, page, page_index, doc_type, confidence, page_metadata=None, field_context=None):
        text = str(page)
        page_metadata = dict(page_metadata or {})
        raw_field_context = dict(field_context or {})
        mapping_context = dict(raw_field_context.get(key, {}) or {})
        if "section_roles" not in mapping_context and raw_field_context.get("_page_section_roles"):
            mapping_context["section_roles"] = list(raw_field_context.get("_page_section_roles") or [])
        if "section_headings" not in mapping_context and raw_field_context.get("_page_section_headings"):
            mapping_context["section_headings"] = list(raw_field_context.get("_page_section_headings") or [])
        if "primary_section_role" not in mapping_context and raw_field_context.get("_primary_section_role"):
            mapping_context["primary_section_role"] = raw_field_context.get("_primary_section_role")
        if mapping_context.get("value") not in (None, value):
            mapping_context = {}
        matched_text = None
        snippet = None
        match_start = None
        match_end = None
        snippet_start = None
        snippet_end = None

        for candidate in self.get_field_source_terms(value):
            if len(candidate) < 2:
                continue
            match = re.search(re.escape(candidate), text, re.IGNORECASE)
            if match:
                matched_text = text[match.start():match.end()]
                snippet = self.build_excerpt(text, match.start(), match.end())
                match_start = match.start()
                match_end = match.end()
                snippet_start = max(0, match.start() - 80)
                snippet_end = min(len(text), match.end() + 80)
                break

        if not snippet:
            for label in self.get_field_label_hints().get(key, []):
                match = re.search(re.escape(label), text, re.IGNORECASE)
                if match:
                    matched_text = text[match.start():match.end()]
                    snippet = self.build_excerpt(text, match.start(), match.end() + 60)
                    match_start = match.start()
                    match_end = match.end()
                    snippet_start = max(0, match.start() - 80)
                    snippet_end = min(len(text), match.end() + 140)
                    break

        if not snippet:
            snippet = self.build_excerpt(text, 0, min(len(text), 60), radius=0)
            snippet_start = 0
            snippet_end = min(len(text), 60)

        layout = dict(page_metadata.get("layout", {}) or {})
        source_role = self.infer_source_role(doc_type, text, page_metadata=page_metadata)
        section_roles = list(mapping_context.get("section_roles") or [])
        section_headings = list(mapping_context.get("section_headings") or [])
        primary_section_role = mapping_context.get("primary_section_role") or self.get_primary_section_role(section_roles)
        return {
            "field": key,
            "value": value,
            "confidence": round(confidence, 2),
            "page_index": page_index,
            "page_number": page_index + 1,
            "document_type": doc_type,
            "source_role": source_role,
            "section_roles": section_roles,
            "section_headings": section_headings[:4],
            "primary_section_role": primary_section_role,
            "matched_text": matched_text,
            "match_start": match_start,
            "match_end": match_end,
            "snippet": snippet,
            "snippet_start": snippet_start,
            "snippet_end": snippet_end,
            "page_zone": mapping_context.get("zone_name"),
            "zone_bbox": mapping_context.get("zone_bbox"),
            "anchor_label": mapping_context.get("anchor_label"),
            "ocr_confidence": mapping_context.get("zone_confidence") or mapping_context.get("ocr_confidence") or page_metadata.get("ocr_confidence"),
            "ocr_provider": mapping_context.get("ocr_provider") or page_metadata.get("ocr_provider"),
            "extraction_strategy": mapping_context.get("strategy") or "text_match",
            "layout_header": layout.get("header_text"),
            "source_file": (
                packet.page_sources[page_index]
                if page_index < len(packet.page_sources)
                else (packet.files[0] if packet.files else None)
            ),
            "traceback": {
                "page_number": page_index + 1,
                "document_type": doc_type,
                "source_role": source_role,
                "section_roles": section_roles,
                "primary_section_role": primary_section_role,
                "page_zone": mapping_context.get("zone_name"),
                "anchor_label": mapping_context.get("anchor_label"),
                "ocr_confidence": mapping_context.get("zone_confidence") or mapping_context.get("ocr_confidence") or page_metadata.get("ocr_confidence"),
                "extraction_strategy": mapping_context.get("strategy") or "text_match",
            },
        }

    def store_results(self, packet, data, page, page_index, doc_type, page_metadata=None, field_context=None):
        for key, value in data.items():
            page_level_context = {
                "section_roles": list((field_context or {}).get("_page_section_roles") or []),
                "section_headings": list((field_context or {}).get("_page_section_headings") or []),
                "primary_section_role": (field_context or {}).get("_primary_section_role"),
            }
            field_specific_context = dict((field_context or {}).get(key, {}) or {})
            merged_field_context = {**page_level_context, **field_specific_context}
            new_conf = self.estimate_confidence(key, value, page, page_metadata=page_metadata, field_context=merged_field_context)
            existing_conf = packet.field_confidence.get(key, 0)
            existing_value = packet.fields.get(key)
            mapping_field_context = dict(field_context or {})
            mapping_field_context[key] = merged_field_context
            built_mapping = self.build_field_mapping(
                packet,
                key,
                value,
                page,
                page_index,
                doc_type,
                new_conf,
                page_metadata=page_metadata,
                field_context=mapping_field_context,
            )
            suspect_reason = self.detect_suspect_field_reason(key, value, mapping=built_mapping)
            if suspect_reason:
                built_mapping["suspect_reason"] = suspect_reason
                built_mapping["confidence"] = round(max(0.2, min(new_conf, 0.55)), 2)
                packet.suspect_fields.setdefault(key, []).append(dict(built_mapping))
                continue

            if key == "icd_codes" and existing_value and self.should_prefer_icd_value(existing_value, value):
                new_conf = max(new_conf, existing_conf + 0.01)
                built_mapping["confidence"] = round(new_conf, 2)

            if key not in packet.fields or new_conf >= existing_conf:
                packet.fields[key] = value
                packet.field_sources[key] = page
                packet.field_mappings[key] = dict(built_mapping)
                packet.field_confidence[key] = new_conf

            if key not in packet.field_values:
                packet.field_values[key] = []

            packet.field_values[key].append(value)

            if key not in packet.field_observations:
                packet.field_observations[key] = []

            packet.field_observations[key].append(dict(built_mapping))

            if key in packet.identity_fields:
                packet.identity_fields[key].append(value)

    def should_prefer_icd_value(self, existing_value, candidate_value):
        if not isinstance(existing_value, list) or not isinstance(candidate_value, list):
            return False

        def score(values):
            normalized = []
            seen = set()

            for code in values:
                normalized_code = self.normalize_icd(code)
                if not normalized_code or normalized_code in seen:
                    continue
                seen.add(normalized_code)
                normalized.append(normalized_code)

            if not normalized:
                return (0, 0)

            return (
                sum(1 for code in normalized if "." in code),
                len(normalized),
            )

        return score(candidate_value) > score(existing_value)

    def estimate_confidence(self, key, value, page, page_metadata=None, field_context=None):
        text = str(page).lower()
        label_map = self.get_field_label_hints()
        page_metadata = dict(page_metadata or {})
        field_context = dict(field_context or {})
        primary_section_role = field_context.get("primary_section_role") or self.get_primary_section_role(field_context.get("section_roles") or [])

        if field_context.get("strategy") == "field_zone":
            base = 0.93
            if key == "authorization_number":
                base = 0.99
            elif key in {"ordering_provider", "referring_provider", "provider"}:
                base = 0.97
            elif key in {"name", "dob", "va_icn"}:
                base = 0.98

            ocr_confidence = float(field_context.get("zone_confidence") or page_metadata.get("ocr_confidence") or 0.0)
            if ocr_confidence >= 80:
                base += 0.02
            elif 0 < ocr_confidence < 55:
                base -= 0.05
            if key == "reason_for_request" and primary_section_role == "request_intent":
                base += 0.01
            elif key == "diagnosis" and primary_section_role in {"diagnostic_basis", "clinical_support", "justification"}:
                base += 0.01
            return round(max(0.75, min(base, 0.99)), 2)

        if key == "authorization_number":
            normalized_value = str(value).upper().strip()
            if normalized_value.startswith("VA") and re.search(r"\bref(?:\.|erral)?\b", text):
                return 0.99
            if normalized_value.startswith("VA") and any(term in text for term in ["community care", "10-10172", "request for service"]):
                return 0.97

        for label in label_map.get(key, []):
            if label in text:
                base = 0.95
                if key == "reason_for_request" and primary_section_role == "request_intent":
                    base += 0.02
                elif key == "diagnosis" and primary_section_role in {"diagnostic_basis", "clinical_support", "justification"}:
                    base += 0.02
                elif key == "procedure" and primary_section_role == "request_scope":
                    base += 0.02
                elif key == "facility" and primary_section_role in {"identity_admin", "routing_followup"}:
                    base += 0.01
                return round(min(base, 0.99), 2)

        if key in {"symptom", "procedure"}:
            base = 0.8
            if key == "procedure" and primary_section_role == "request_scope":
                base += 0.05
            return round(min(base, 0.9), 2)

        if page_metadata.get("ocr_confidence", 0.0):
            base = max(0.7, min(0.95, 0.72 + (float(page_metadata.get("ocr_confidence") or 0.0) / 500)))
            if key == "reason_for_request" and primary_section_role == "request_intent":
                base += 0.03
            elif key == "diagnosis" and primary_section_role in {"diagnostic_basis", "clinical_support", "justification"}:
                base += 0.03
            elif key == "facility" and primary_section_role in {"identity_admin", "routing_followup"}:
                base += 0.02
            return round(min(base, 0.97), 2)

        base = 0.75
        if key == "reason_for_request" and primary_section_role == "request_intent":
            base += 0.05
        elif key == "diagnosis" and primary_section_role in {"diagnostic_basis", "clinical_support", "justification"}:
            base += 0.05
        elif key == "facility" and primary_section_role in {"identity_admin", "routing_followup"}:
            base += 0.03
        return round(min(base, 0.9), 2)
