import re


class ExtractorNormalizationMixin:
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

        invalid_values = {"office", "clinic", "practice", "office visit note", "office clinic note"}
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

    def normalize_provider_role_candidate(self, value):
        raw = re.sub(r"\s+", " ", str(value or "").replace("\xa0", " ")).strip(" :-,")
        if not raw:
            return None

        raw = re.sub(
            r"^(?:physician|performed by|verified by|rendering provider|treating provider|attending provider|provider name|provider)\s*:\s*",
            "",
            raw,
            flags=re.IGNORECASE,
        )
        raw = re.split(
            r"\b(?:on|encounter info|result title|auth\s*\(verified\)|registration date)\b",
            raw,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0].strip(" :-,")
        if not raw:
            return None

        parts = [part.strip() for part in raw.split(",", 1)] if "," in raw else [raw]
        part_tokens = [re.findall(r"[A-Za-z][A-Za-z.'\-]*", part) for part in parts]
        credential_pattern = re.compile(r"^(?:MD|DO|PA|PAC|NP|FNP|APRN|RN|DC|DDS)$", re.IGNORECASE)

        credentials = []
        cleaned_parts = []
        for tokens in part_tokens:
            name_tokens = []
            for token in tokens:
                normalized = token.replace(".", "")
                if credential_pattern.fullmatch(normalized):
                    normalized = "PA-C" if normalized.upper() == "PAC" else normalized.upper()
                    if normalized not in credentials:
                        credentials.append(normalized)
                    continue
                name_tokens.append(token)
            cleaned_parts.append(name_tokens)

        ordered_tokens = []
        if len(cleaned_parts) == 2 and len(cleaned_parts[0]) == 1:
            ordered_tokens.extend(cleaned_parts[1])
            ordered_tokens.extend(cleaned_parts[0])
        else:
            for tokens in cleaned_parts:
                ordered_tokens.extend(tokens)

        if len(ordered_tokens) < 2:
            return None

        rendered_tokens = []
        for token in ordered_tokens:
            if len(token) == 1:
                rendered_tokens.append(token.upper())
            else:
                rendered_tokens.append(token.title())

        name = " ".join(rendered_tokens)
        if credentials:
            name += ", " + ", ".join(credentials)
        return name

    def drop_middle_initial_provider_candidate(self, value):
        normalized = self.normalize_provider_role_candidate(value)
        if not normalized:
            return None

        match = re.match(r"^([A-Za-z]+)\s+([A-Z])\s+([A-Za-z]+)(,\s*[A-Z\-]+(?:,\s*[A-Z\-]+)*)?$", normalized)
        if not match:
            return normalized

        first_name, _middle_initial, last_name, credential_suffix = match.groups()
        simplified = f"{first_name} {last_name}"
        if credential_suffix:
            simplified += credential_suffix
        return simplified

    def clean_referral_community_facility(self, value):
        raw = re.sub(r"\s+", " ", str(value or "").replace("\xa0", " ")).strip()
        if not raw:
            return None

        if "-" in raw:
            left, right = raw.split("-", 1)
            if re.match(r"^\d", right.strip()):
                raw = left.strip()

        raw = re.sub(r"\b\d{5}(?:-\d{4})?\b.*$", "", raw).strip(" ,-")
        canonical = self.canonicalize_known_clinic_name(raw)
        if canonical:
            return canonical
        return self.format_title_text(raw) if raw else None

    def clean_referral_location(self, value):
        raw = re.sub(r"\s+", " ", str(value or "").replace("\xa0", " ")).strip()
        if not raw:
            return None

        if "-" in raw:
            left, right = raw.split("-", 1)
            if re.match(r"^\d", right.strip()):
                raw = right.strip()

        match = re.search(
            r"(\d{1,6}[^,\n\r]+,\s*[A-Za-z .'\-]+,\s*[A-Z]{2})\s*,\s*(\d{5})(?:-\d+[A-Z]?)?",
            raw,
        )
        if match:
            formatted = self.format_title_text(match.group(1))
            formatted = re.sub(r",\s*([A-Za-z]{2})$", lambda item: f", {item.group(1).upper()}", formatted)
            return f"{formatted} {match.group(2)}"

        raw = re.sub(r"-\d{6,}[A-Z]?$", "", raw)
        raw = re.sub(r",\s*(\d{5})(?:-\d{4})?$", r" \1", raw)
        cleaned = raw.strip(" ,-")
        return self.format_title_text(cleaned) if cleaned else None

    def looks_truncated_packet_value(self, value):
        normalized = re.sub(r"\s+", " ", str(value or "").replace("\xa0", " ")).strip()
        if not normalized:
            return True
        if normalized.lower() in {"office visit note", "office clinic note", "och center", "och center for pain man"}:
            return True
        return len(normalized) < 18

    def normalize_reason_for_request(self, value):
        value = self.cut_at_stop_label(value)
        value = re.split(r"\bdisclaimer\b", value, maxsplit=1, flags=re.IGNORECASE)[0]
        if "*" in value:
            value = value.split("*", 1)[0]
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

        icd_normalization_map = {
            "M54.5": "M54.50",
            "M54.50": "M54.50",
            "M54.2": "M54.2",
            "G43.9": "G43.909",
            "G43.909": "G43.909",
            "M19.9": "M19.90",
            "M19.90": "M19.90",
        }

        if code in icd_normalization_map:
            return icd_normalization_map[code]

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
