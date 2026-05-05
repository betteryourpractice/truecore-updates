from datetime import datetime
import re

from TrueCoreIntel.validation.validation_intelligence import ValidationIntelligenceAnalyzer


class ValidatorEngine:

    HIGH_SEVERITY_FIELDS = {"name", "dob", "authorization_number", "va_icn", "claim_number"}
    MEDIUM_SEVERITY_FIELDS = {
        "ordering_provider",
        "referring_provider",
        "provider",
        "icd_codes",
        "reason_for_request",
        "npi",
        "service_date_range",
    }

    ROLE_TOLERANT_FIELDS = {
        "provider",
        "clinic_name",
        "facility",
        "location",
    }

    DOCUMENT_ORDER_PRIORITY = {
        "cover_sheet": 10,
        "rfs": 20,
        "consult_request": 30,
        "seoc": 40,
        "lomn": 50,
        "consent": 60,
        "clinical_notes": 70,
        "unknown": 999,
    }

    DOCUMENT_FIELD_EXPECTATIONS = {
        "lomn": ["reason_for_request", "signature_present"],
        "rfs": ["authorization_number"],
        "clinical_notes": ["icd_codes"],
        "consult_request": ["ordering_provider"],
        "seoc": ["referring_provider"],
        "consent": ["signature_present"],
    }

    REQUIRED_DOCS_BY_PACKET_TYPE = {
        "full_submission": {
            "lomn",
            "seoc",
            "rfs",
            "consult_request",
            "clinical_notes",
            "consent",
            "cover_sheet",
        },
        "authorization_request": {
            "consult_request",
            "clinical_notes",
        },
        "clinical_minimal": {
            "clinical_notes",
        },
    }

    REQUIRED_FIELDS_BY_PACKET_TYPE = {
        "full_submission": [
            "name",
            "dob",
            "icd_codes",
            "authorization_number",
            "reason_for_request",
        ],
        "authorization_request": [
            "name",
            "dob",
            "icd_codes",
            "authorization_number",
            "reason_for_request",
        ],
        "clinical_minimal": [
            "name",
            "dob",
            "icd_codes",
        ],
    }

    def __init__(self):
        self.validation_intelligence_analyzer = ValidationIntelligenceAnalyzer()

    def validate(self, packet):
        packet.validation_intelligence = {}
        packet.deep_verification_score = None
        self.check_missing_fields(packet)
        self.check_required_documents(packet)
        self.check_document_field_gaps(packet)
        self.check_identity_consistency(packet)
        self.check_identifier_consistency(packet)
        self.check_provider_consistency(packet)
        self.check_authorization_consistency(packet)
        self.check_npi_validity(packet)
        self.check_service_date_chronology(packet)
        self.build_document_chronology(packet)
        self.check_duplicate_pages(packet)
        self.check_icd_consistency(packet)
        self.check_general_field_conflicts(packet)
        packet = self.validation_intelligence_analyzer.analyze(packet, validator=self)
        return packet

    def infer_packet_type(self, packet):
        detected = set(packet.detected_documents)
        full_submission_docs = {
            "lomn",
            "seoc",
            "rfs",
            "consult_request",
            "clinical_notes",
            "consent",
            "cover_sheet",
        }
        full_submission_hits = detected.intersection(full_submission_docs)

        if "clinical_notes" in detected and len(detected) <= 2 and not ({"rfs", "consult_request"} & detected):
            return "clinical_minimal"

        if len(full_submission_hits) >= 4:
            return "full_submission"

        if {"cover_sheet", "lomn", "seoc"} & detected and len(full_submission_hits) >= 3:
            return "full_submission"

        if "rfs" in detected or "consult_request" in detected:
            return "authorization_request"

        return "full_submission"

    def check_required_documents(self, packet):
        # Only enforce required docs if ANY docs were detected
        if not packet.detected_documents:
            return

        packet_type = self.infer_packet_type(packet)
        required_docs = self.REQUIRED_DOCS_BY_PACKET_TYPE.get(packet_type, set())

        for doc in required_docs:
            if doc not in packet.detected_documents and doc not in packet.missing_documents:
                packet.missing_documents.append(doc)

    def check_document_field_gaps(self, packet):
        """
        Detect when a document exists but fails to provide expected fields.
        Example: consult_request present but ordering_provider missing.
        """

        for doc, expected_fields in self.DOCUMENT_FIELD_EXPECTATIONS.items():
            if doc not in packet.detected_documents:
                continue

            for field in expected_fields:
                has_field = field in packet.fields or bool(packet.field_values.get(field))

                if not has_field:
                    # Hard suppress provider-role doc gaps for consult pages if any
                    # provider-like signal was captured anywhere in the packet.
                    if field in {"ordering_provider", "referring_provider"}:
                        provider_seen = any(
                            provider_field in packet.fields or bool(packet.field_values.get(provider_field))
                            for provider_field in {"provider", "ordering_provider", "referring_provider"}
                        )
                        if provider_seen:
                            continue

                        # Also suppress if a consult_request exists and patient/provider
                        # routing text is present elsewhere but role label was messy.
                        if doc == "consult_request":
                            continue

                    self.add_conflict(
                        packet=packet,
                        field=field,
                        conflict_type="document_gap",
                        severity=self.get_field_severity(field),
                        values=[],
                        message=f"{doc} document is present but missing expected field: {field}.",
                    )

    def check_missing_fields(self, packet):
        if packet.detected_documents:
            packet_type = self.infer_packet_type(packet)
            required_fields = self.REQUIRED_FIELDS_BY_PACKET_TYPE.get(
                packet_type,
                self.REQUIRED_FIELDS_BY_PACKET_TYPE["full_submission"],
            )
        else:
            required_fields = ["name", "dob"]

        for field in required_fields:
            if field not in packet.fields and field not in packet.missing_fields:
                packet.missing_fields.append(field)

    def check_identity_consistency(self, packet):
        self.check_specific_field_consistency(
            packet=packet,
            field="name",
            conflict_type="identity_mismatch",
            severity="high",
            message="Patient name is inconsistent across packet documents.",
        )
        self.check_specific_field_consistency(
            packet=packet,
            field="dob",
            conflict_type="identity_mismatch",
            severity="high",
            message="DOB is inconsistent across packet documents.",
        )

    def check_identifier_consistency(self, packet):
        self.check_specific_field_consistency(
            packet=packet,
            field="va_icn",
            conflict_type="identity_mismatch",
            severity="high",
            message="VA ICN is inconsistent across packet documents.",
        )
        self.check_specific_field_consistency(
            packet=packet,
            field="claim_number",
            conflict_type="identity_mismatch",
            severity="high",
            message="Claim number is inconsistent across packet documents.",
        )

    def check_provider_consistency(self, packet):
        self.check_specific_field_consistency(
            packet=packet,
            field="provider",
            conflict_type="provider_mismatch",
            severity="medium",
            message="Provider is inconsistent across packet documents.",
        )
        self.check_specific_field_consistency(
            packet=packet,
            field="ordering_provider",
            conflict_type="provider_mismatch",
            severity="medium",
            message="Ordering provider is inconsistent across packet documents.",
        )
        self.check_specific_field_consistency(
            packet=packet,
            field="referring_provider",
            conflict_type="provider_mismatch",
            severity="medium",
            message="Referring provider is inconsistent across packet documents.",
        )

    def check_authorization_consistency(self, packet):
        values = packet.field_values.get("authorization_number", [])
        normalized_values = self.get_normalized_unique_values("authorization_number", values)

        distinct_values = []
        for value in normalized_values:
            if not any(self.authorization_values_equivalent(value, existing) for existing in distinct_values):
                distinct_values.append(value)

        if len(distinct_values) > 1:
            self.add_conflict(
                packet=packet,
                field="authorization_number",
                conflict_type="authorization_mismatch",
                severity="high",
                values=distinct_values,
                message="Authorization or referral number is inconsistent across packet documents.",
            )

    def check_npi_validity(self, packet):
        npi = packet.fields.get("npi")
        if not npi:
            return

        if not self.is_valid_npi(npi):
            self.add_conflict(
                packet=packet,
                field="npi",
                conflict_type="format_error",
                severity="medium",
                values=[npi],
                message="Detected NPI does not appear valid.",
            )

    def check_service_date_chronology(self, packet):
        date_range = packet.fields.get("service_date_range")
        if not date_range or not isinstance(date_range, str) or " to " not in date_range:
            return

        start_text, end_text = [part.strip() for part in date_range.split(" to ", 1)]
        start_date = self.parse_date(start_text)
        end_date = self.parse_date(end_text)

        if start_date and end_date and start_date > end_date:
            self.add_conflict(
                packet=packet,
                field="service_date_range",
                conflict_type="chronology_error",
                severity="medium",
                values=[date_range],
                message="Service date range appears reversed or clinically out of order.",
            )

    def build_document_chronology(self, packet):
        chronology_entries = []
        chronology_by_page = {}

        for page_index, page in enumerate(packet.pages):
            doc_type = packet.document_types.get(page_index, "unknown")
            page_entries = self.extract_page_chronology_entries(str(page), page_index, doc_type)
            if page_entries:
                chronology_entries.extend(page_entries)
                chronology_by_page[page_index] = page_entries

        packet.links["document_chronology"] = chronology_entries
        packet.links["recommended_page_order"] = self.build_recommended_page_order(packet, chronology_by_page)

        moved_pages = [
            entry for entry in packet.links["recommended_page_order"]
            if entry.get("recommended_position") != entry.get("current_position")
            and entry.get("doc_type") != "unknown"
        ]
        packet.links["page_order_review_needed"] = len(moved_pages) >= 2 and len(packet.detected_documents) >= 3

    def extract_page_chronology_entries(self, text, page_index, doc_type):
        labeled_patterns = {
            "service": [
                r"(?:date(?:s)? of service|service date(?:s| range)?|visit date(?:s| range)?|clinical visit(?: date)?s?|dos)\s*[:\-]\s*([^\n\r]+)",
                r"(?:from|service dates?)\s+([A-Za-z0-9, /\-]+(?:to|through|-)[A-Za-z0-9, /\-]+)",
            ],
            "submission": [
                r"(?:date of submission|submission date|submitted(?: on| date)?)\s*[:\-]?\s*([^\n\r]+)",
            ],
            "signature": [
                r"(?:signed(?: on| date)?|electronically signed(?: on)?|signature date)\s*[:\-]?\s*([^\n\r]+)",
            ],
        }

        entries = []
        seen = set()
        for date_type, patterns in labeled_patterns.items():
            for pattern in patterns:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    date_values = self.extract_dates_from_text(match.group(1))
                    if not date_values:
                        continue

                    entry = {
                        "page_index": page_index,
                        "doc_type": doc_type,
                        "date_type": date_type,
                        "start_date": date_values[0],
                        "end_date": date_values[-1],
                        "date_count": len(date_values),
                    }
                    dedupe_key = (
                        entry["page_index"],
                        entry["doc_type"],
                        entry["date_type"],
                        entry["start_date"],
                        entry["end_date"],
                    )
                    if dedupe_key not in seen:
                        seen.add(dedupe_key)
                        entries.append(entry)

        return entries

    def extract_dates_from_text(self, text):
        matches = re.finditer(
            r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2}|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*|\s+)\d{4})\b",
            str(text),
            re.IGNORECASE,
        )

        normalized_dates = []
        seen = set()
        for match in matches:
            parsed = self.parse_date(match.group(1))
            if not parsed:
                continue

            normalized = parsed.strftime("%m/%d/%Y")
            if normalized not in seen:
                seen.add(normalized)
                normalized_dates.append(normalized)

        return normalized_dates

    def build_recommended_page_order(self, packet, chronology_by_page):
        recommendations = []
        date_type_priority = {"submission": 0, "service": 1, "signature": 2}

        for page_index, _page in enumerate(packet.pages):
            doc_type = packet.document_types.get(page_index, "unknown")
            page_entries = chronology_by_page.get(page_index, [])
            best_entry = None
            if page_entries:
                best_entry = sorted(
                    page_entries,
                    key=lambda entry: (
                        date_type_priority.get(entry.get("date_type"), 9),
                        self.parse_date(entry.get("start_date")) or datetime.max,
                    ),
                )[0]

            recommendations.append({
                "page_index": page_index,
                "current_position": page_index + 1,
                "doc_type": doc_type,
                "doc_priority": self.DOCUMENT_ORDER_PRIORITY.get(doc_type, 999),
                "anchor_date": best_entry.get("start_date") if best_entry else None,
                "date_type": best_entry.get("date_type") if best_entry else None,
            })

        recommendations.sort(
            key=lambda entry: (
                entry["doc_priority"],
                self.parse_date(entry["anchor_date"]) or datetime.max,
                entry["page_index"],
            )
        )

        for position, entry in enumerate(recommendations, start=1):
            entry["recommended_position"] = position

        return recommendations

    def check_duplicate_pages(self, packet):
        duplicate_pages = getattr(packet, "duplicate_pages", []) or packet.links.get("duplicate_pages", [])
        if not duplicate_pages:
            return

        self.add_conflict(
            packet=packet,
            field="packet_pages",
            conflict_type="duplicate_pages",
            severity="low",
            values=[entry.get("page_indices", []) for entry in duplicate_pages],
            message="Packet contains duplicate or repeated pages.",
        )

    def check_icd_consistency(self, packet):
        values = packet.field_values.get("icd_codes", [])
        normalized_values = self.get_normalized_unique_values("icd_codes", values)

        if len(normalized_values) > 1:
            if self.has_mixed_episode_history(packet, "icd_codes"):
                return

            code_sets = [set(value) for value in normalized_values if isinstance(value, tuple) and value]
            if len(code_sets) >= 2:
                shared_codes = set.intersection(*code_sets)
                if shared_codes:
                    return

                code_families = [{code.split(".")[0] for code in value} for value in code_sets]
                shared_families = set.intersection(*code_families)
                if shared_families:
                    return

            self.add_conflict(
                packet=packet,
                field="icd_codes",
                conflict_type="clinical_mismatch",
                severity="medium",
                values=normalized_values,
                message="ICD codes are inconsistent across packet documents.",
            )

    def check_general_field_conflicts(self, packet):
        protected_fields = {
            "name",
            "dob",
            "authorization_number",
            "provider",
            "ordering_provider",
            "referring_provider",
            "icd_codes",
            "symptom",
            "medications",
        }

        for field, values in packet.field_values.items():
            if field in protected_fields:
                continue

            normalized_values = self.get_normalized_unique_values(field, values)

            if len(normalized_values) > 1:
                if field == "authorization_number":
                    distinct_auth_values = []
                    for value in normalized_values:
                        if not any(
                            self.authorization_values_equivalent(value, existing)
                            for existing in distinct_auth_values
                        ):
                            distinct_auth_values.append(value)

                    if len(distinct_auth_values) <= 1:
                        continue

                    normalized_values = distinct_auth_values

                # reduce false-positive conflict noise for reason_for_request
                if field == "reason_for_request" and self.reason_values_substantially_overlap(normalized_values):
                    continue

                if field in self.ROLE_TOLERANT_FIELDS and self.has_only_cross_role_variation(packet, field):
                    continue

                if field == "npi" and self.has_contextually_acceptable_npi_variation(packet):
                    continue

                if field in {"reason_for_request", "diagnosis"} and self.has_mixed_episode_history(packet, field):
                    continue

                self.add_conflict(
                    packet=packet,
                    field=field,
                    conflict_type="mismatch",
                    severity=self.get_field_severity(field),
                    values=normalized_values,
                    message=f"{field} is inconsistent across packet documents.",
                )

    def check_specific_field_consistency(self, packet, field, conflict_type, severity, message):
        values = (
            packet.identity_fields.get(field, [])
            if field in packet.identity_fields
            else packet.field_values.get(field, [])
        )
        normalized_values = self.get_normalized_unique_values(field, values)

        if len(normalized_values) > 1:
            if field in self.ROLE_TOLERANT_FIELDS and self.has_only_cross_role_variation(packet, field):
                return

            if field == "npi" and self.has_contextually_acceptable_npi_variation(packet):
                return

            if field in {"diagnosis"} and self.has_mixed_episode_history(packet, field):
                return

            self.add_conflict(
                packet=packet,
                field=field,
                conflict_type=conflict_type,
                severity=severity,
                values=normalized_values,
                message=message,
            )

    def has_only_cross_role_variation(self, packet, field):
        observations = list((getattr(packet, "field_observations", {}) or {}).get(field, []) or [])
        if len(observations) < 2:
            return False

        role_values = {}
        for observation in observations:
            normalized_value = self.normalize_conflict_value(field, observation.get("value"))
            if normalized_value is None:
                continue

            role = str(observation.get("source_role") or "unknown").strip().lower()
            role_values.setdefault(role, set()).add(normalized_value)

        concrete_roles = {
            role: values
            for role, values in role_values.items()
            if role not in {"unknown", "shared", "patient"} and values
        }

        if len(concrete_roles) < 2:
            return False

        if any(len(values) > 1 for values in concrete_roles.values()):
            return False

        distinct_values = {
            next(iter(values))
            for values in concrete_roles.values()
            if values
        }
        return len(distinct_values) > 1

    def get_normalized_unique_values(self, field, values):
        normalized = []

        for value in values:
            normalized_value = self.normalize_conflict_value(field, value)
            if normalized_value is not None:
                normalized.append(normalized_value)

        unique = []
        seen = set()

        for item in normalized:
            if item not in seen:
                seen.add(item)
                unique.append(item)

        return unique

    def normalize_conflict_value(self, field, value):
        if value is None:
            return None

        if field == "name":
            return self.normalize_name(value)

        if field == "dob":
            return self.normalize_dob(value)

        if field in {"provider", "ordering_provider", "referring_provider"}:
            return self.normalize_provider(value)

        if field in {"va_icn", "claim_number", "authorization_number", "npi"}:
            cleaned = str(value).strip().upper()
            return cleaned if cleaned else None

        if field == "icd_codes":
            if not isinstance(value, list):
                return None
            cleaned = [str(code).strip().upper() for code in value if code]
            return tuple(sorted(set(cleaned)))

        if field == "clinic_name":
            if isinstance(value, str):
                cleaned = value.strip().lower()
                cleaned = re.sub(r"[^a-z0-9&,'\- ]", " ", cleaned)
                cleaned = re.sub(r"\s+", " ", cleaned).strip()
                if not cleaned:
                    return None

                connector_fragments = {"and", "&", "of", "for"}
                first_token = cleaned.split()[0] if cleaned.split() else ""
                if first_token in connector_fragments:
                    return None

                if "aiken neurosciences" in cleaned and (
                    "pain management" in cleaned or "painmanagement" in cleaned
                ):
                    return "aiken neurosciences and pain management llc"

                if len(cleaned.split()) > 8:
                    return None

                generic_noise = [
                    "year old",
                    "presents to",
                    "hours then heat",
                    "chronic opioid use",
                ]
                if any(marker in cleaned for marker in generic_noise):
                    return None

                return cleaned

        if field == "reason_for_request":
            if isinstance(value, str):
                cleaned = value.strip().lower()
                cleaned = cleaned.replace("bilateral", " ")
                cleaned = re.sub(r"[^a-z0-9,;/ ]", " ", cleaned)
                cleaned = re.sub(r"\s+", " ", cleaned).strip()

                if cleaned in {
                    "is medically reasonable and necessary",
                    "medically reasonable and necessary",
                    "reasonable and necessary",
                    "necessary",
                }:
                    return None

                chunks = []
                for part in re.split(r"[,;/]|\band\b", cleaned):
                    part = part.strip()
                    if not part:
                        continue

                    part = re.sub(r"\b(chief complaint|reason for request|reason for referral|history of present illness)\b", "", part)
                    part = re.sub(r"\s+", " ", part).strip()

                    if part:
                        chunks.append(part)

                normalized_chunks = sorted(set(chunks))
                return tuple(normalized_chunks) if normalized_chunks else None

        if field == "diagnosis":
            if isinstance(value, str):
                cleaned = value.strip().lower()
                cleaned = re.sub(r"\s+", " ", cleaned)

                cervical_markers = [
                    "cervical",
                    "cervicalgia",
                    "neck pain",
                    "c spine",
                    "c-spine",
                    "cervical spondylosis",
                ]
                if any(marker in cleaned for marker in cervical_markers):
                    return "cervical_spine_condition"

                lumbar_markers = [
                    "low back pain",
                    "back pain",
                    "lumbar",
                    "lumbago",
                    "radiculopathy",
                    "sciatica",
                    "lumbosacral",
                    "degenerative disc",
                    "disc degeneration",
                    "discogenic",
                ]
                if any(marker in cleaned for marker in lumbar_markers):
                    return "lumbar_spine_condition"

                if "radiculopathy" in cleaned:
                    return "spine_radiculopathy_condition"

                return cleaned if cleaned else None

        if field == "service_date_range":
            cleaned = str(value).strip()
            return cleaned if cleaned else None

        if isinstance(value, list):
            return tuple(sorted(set(str(v).strip().lower() for v in value if v)))

        if isinstance(value, str):
            cleaned = value.strip().lower()
            return cleaned if cleaned else None

        return value

    def normalize_name(self, value):
        raw = str(value).strip().lower()
        raw = re.sub(r"\b(?:jr|sr|ii|iii|iv|md|m\.d\.|do|d\.o\.|pa|np|rn)\b\.?", " ", raw)
        raw = re.sub(r"[^a-z,\-\' ]", " ", raw)
        raw = " ".join(raw.split())

        if not raw:
            return None

        collapsed = raw.replace(" ", "")
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

        junk_tokens = {
            "pob",
            "dob",
            "ssn",
            "claim",
            "submission",
            "provider",
            "diagnosis",
            "office",
            "reviewed",
            "code",
        }
        if any(token in junk_tokens for token in raw.replace(",", " ").split()):
            return None

        if "," in raw:
            last_part, first_part = raw.split(",", 1)
            last_tokens = [token for token in last_part.split() if token]
            first_tokens = [token for token in first_part.split() if token]
            if last_tokens and first_tokens:
                return f"{first_tokens[0]} {last_tokens[0]}"

        tokens = [token for token in raw.split() if token]
        if len(tokens) < 2:
            return None

        return f"{tokens[0]} {tokens[-1]}"

    def normalize_dob(self, value):
        parsed = self.parse_date(value)
        if parsed:
            return parsed.strftime("%m/%d/%Y")

        cleaned = str(value).strip().replace("-", "/")
        return cleaned if cleaned else None

    def normalize_provider(self, value):
        cleaned = str(value).strip().lower()
        cleaned = cleaned.replace("dr.", "dr").replace(",", " ")
        cleaned = re.sub(
            r"\b(?:dr|doctor|md|m\.d\.|do|d\.o\.|pa(?:-c)?|np|fnp|aprn|rn|dc|dds)\b\.?",
            " ",
            cleaned,
            flags=re.IGNORECASE,
        )
        cleaned = re.sub(r"[^a-z'\- ]", " ", cleaned)
        tokens = [token for token in cleaned.split() if token]

        if len(tokens) > 2:
            tokens = [token for token in tokens if len(token) > 1]

        cleaned = " ".join(tokens)
        return cleaned if cleaned else None

    def reason_values_substantially_overlap(self, normalized_values):
        """
        Avoid treating reason_for_request as conflicting when one value is
        contained within a broader complaint list.
        """

        if len(normalized_values) < 2:
            return False

        normalized_sets = []
        for value in normalized_values:
            if isinstance(value, tuple):
                parts = {
                    part.strip()
                    for part in value
                    if isinstance(part, str) and part.strip()
                }
            elif isinstance(value, str):
                parts = {value.strip()} if value.strip() else set()
            else:
                parts = set()

            if parts:
                normalized_sets.append(parts)

        if len(normalized_sets) < 2:
            return False

        for i, left in enumerate(normalized_sets):
            for j, right in enumerate(normalized_sets):
                if i == j:
                    continue

                if left.issubset(right) or right.issubset(left):
                    return True

                intersection = left.intersection(right)
                if not intersection:
                    continue

                overlap_ratio = len(intersection) / min(len(left), len(right))

                if overlap_ratio >= 0.5:
                    return True

        return False

    def has_contextually_acceptable_npi_variation(self, packet):
        observations = list((getattr(packet, "field_observations", {}) or {}).get("npi", []) or [])
        if len(observations) < 2:
            return False

        normalized = [
            self.normalize_conflict_value("npi", observation.get("value"))
            for observation in observations
        ]
        distinct_values = sorted({value for value in normalized if value})
        if len(distinct_values) <= 1:
            return False

        counts = {}
        for value in normalized:
            if not value:
                continue
            counts[value] = counts.get(value, 0) + 1

        if counts:
            max_count = max(counts.values())
            if max_count >= max(2, len(observations) - 1):
                return True

        context_markers = {
            "pcp",
            "primary care provider",
            "patient's care team",
            "care team",
        }

        contextual_hits = 0
        for observation in observations:
            snippet = str(observation.get("snippet") or "").lower()
            matched_text = str(observation.get("matched_text") or "").lower()
            anchor = str(observation.get("anchor_label") or "").lower()
            combined = f"{snippet} {matched_text} {anchor}"
            if any(marker in combined for marker in context_markers):
                contextual_hits += 1

        return contextual_hits >= max(1, len(observations) - 1)

    def has_mixed_episode_history(self, packet, field):
        observations = list((getattr(packet, "field_observations", {}) or {}).get(field, []) or [])
        if len(observations) < 2:
            return False

        regions = set()
        historical_like = 0
        considered = 0

        for observation in observations:
            value = observation.get("value")
            regions.update(self.infer_regions_for_field_value(field, value))

            snippet = str(observation.get("snippet") or "").lower()
            matched_text = str(observation.get("matched_text") or "").lower()
            combined = f"{snippet} {matched_text}"
            doc_type = str(observation.get("document_type") or "unknown").lower()

            considered += 1
            if (
                doc_type == "unknown"
                or any(marker in combined for marker in [
                    "problems reviewed",
                    "problems not reviewed",
                    "past medical history",
                    "chief complaint",
                    "patient's care team",
                    "encounter date",
                ])
            ):
                historical_like += 1

        if len(regions) < 2:
            return False

        return historical_like >= max(1, considered // 2)

    def infer_regions_for_field_value(self, field, value):
        regions = set()

        if field in {"reason_for_request", "diagnosis"} and isinstance(value, str):
            cleaned = value.lower()
            if any(marker in cleaned for marker in ["cervical", "cervicalgia", "neck pain", "c-spine", "c spine"]):
                regions.add("cervical")
            if any(marker in cleaned for marker in ["lumbar", "lumbago", "low back", "back pain", "sciatica"]):
                regions.add("lumbar")
            if "migraine" in cleaned or "headache" in cleaned:
                regions.add("head")
            if "radiculopathy" in cleaned and not regions:
                regions.add("spine")

        if field == "icd_codes" and isinstance(value, list):
            for code in value:
                normalized = str(code).strip().upper()
                if normalized.startswith("M54.2") or normalized.startswith("M47.812"):
                    regions.add("cervical")
                elif normalized.startswith("M54.5") or normalized.startswith("M54.4") or normalized.startswith("M51"):
                    regions.add("lumbar")
                elif normalized.startswith("G43"):
                    regions.add("head")

        return regions

    def get_field_severity(self, field):
        if field in self.HIGH_SEVERITY_FIELDS:
            return "high"
        if field in self.MEDIUM_SEVERITY_FIELDS:
            return "medium"
        return "low"

    def parse_date(self, value):
        cleaned = str(value).strip()
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
                return datetime.strptime(cleaned, fmt)
            except ValueError:
                continue
        return None

    def authorization_values_equivalent(self, left, right):
        left_clean = re.sub(r"[^A-Z0-9]", "", str(left).upper())
        right_clean = re.sub(r"[^A-Z0-9]", "", str(right).upper())

        if not left_clean or not right_clean:
            return False

        if left_clean == right_clean:
            return True

        shorter, longer = sorted((left_clean, right_clean), key=len)
        if len(shorter) >= 8 and shorter in longer:
            return True

        left_digits = re.sub(r"\D", "", left_clean)
        right_digits = re.sub(r"\D", "", right_clean)
        if len(left_digits) >= 8 and len(right_digits) >= 8:
            if left_digits[-8:] == right_digits[-8:]:
                return True

        left_tail = left_clean[-10:] if len(left_clean) >= 10 else left_clean
        right_tail = right_clean[-10:] if len(right_clean) >= 10 else right_clean
        if len(left_tail) >= 8 and left_tail == right_tail:
            return True

        return False

    def is_valid_npi(self, value):
        digits = re.sub(r"\D", "", str(value))
        if len(digits) != 10:
            return False

        transformed = "80840" + digits[:-1]
        total = 0
        reverse_digits = transformed[::-1]
        for index, char in enumerate(reverse_digits):
            digit = int(char)
            if index % 2 == 0:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit

        check_digit = (10 - (total % 10)) % 10
        return check_digit == int(digits[-1])

    def add_conflict(self, packet, field, conflict_type, severity, values, message):
        for existing in packet.conflicts:
            if existing.get("field") == field and existing.get("type") == conflict_type:
                return

        packet.conflicts.append({
            "field": field,
            "type": conflict_type,
            "severity": severity,
            "values": [list(v) if isinstance(v, tuple) else v for v in values],
            "message": message,
        })
