"""
TrueCore Intel Bridge

Adapts the TrueCoreIntel packet model into the legacy
TrueCore Packet Assistant result format expected by the GUI.
"""

import os
import re
from collections import Counter

from TrueCore.utils.logging_system import log_event


INTEL_IMPORT_ERROR = None

try:
    from TrueCoreIntel.intel_engine import process_path as process_intel_path
except Exception as exc:
    process_intel_path = None
    INTEL_IMPORT_ERROR = exc

try:
    from TrueCoreIntel.core import packet_archetypes as intel_packet_archetypes
except Exception:
    intel_packet_archetypes = None


FIELD_NAME_MAP = {
    "name": "patient_name",
    "dob": "dob",
    "authorization_number": "authorization_number",
    "icd_codes": "icd_codes",
    "ordering_provider": "ordering_doctor",
    "referring_provider": "referring_doctor",
    "provider": "provider",
    "treating_provider": "treating_provider",
    "followup_provider": "followup_provider",
    "diagnosis": "diagnosis",
    "symptom": "symptom",
    "procedure": "procedure",
    "reason_for_request": "reason_for_request",
    "va_icn": "va_icn",
    "claim_number": "claim_number",
    "facility": "facility",
    "clinic_name": "clinic_name",
    "location": "location",
    "service_date_range": "service_date_range",
    "npi": "npi",
    "signature_present": "signature_present",
}

FIELD_LABEL_MAP = {
    "name": "patient name",
    "patient_name": "patient name",
    "dob": "patient DOB",
    "authorization_number": "authorization number",
    "icd_codes": "ICD codes",
    "ordering_provider": "ordering doctor",
    "ordering_doctor": "ordering doctor",
    "referring_provider": "referring doctor",
    "referring_doctor": "referring doctor",
    "provider": "provider",
    "treating_provider": "treating provider",
    "followup_provider": "follow-up provider",
    "reason_for_request": "reason for request",
    "facility": "facility",
    "clinic_name": "clinic name",
    "location": "treating location",
    "service_date_range": "service date range",
    "signature_present": "signature",
    "va_icn": "VA ICN",
    "claim_number": "claim number",
}

FORM_NAME_MAP = {
    "cover_sheet": "Submission Cover Sheet",
    "consent": "Virtual Consent Form",
    "consult_request": "Consultation & Treatment Request",
    "seoc": "SEOC",
    "lomn": "Letter of Medical Necessity",
    "rfs": "VA Form 10-10172",
    "approved_referral": "VA Form 10-7080",
    "clinical_notes": "Clinical Notes",
    "imaging_report": "MRI / Imaging Report",
    "conservative_care_summary": "Conservative Care Summary",
}

FORM_ORDER = {
    "Submission Cover Sheet": 10,
    "VA Form 10-10172": 20,
    "VA Form 10-7080": 25,
    "Consultation & Treatment Request": 30,
    "SEOC": 40,
    "Letter of Medical Necessity": 50,
    "Virtual Consent Form": 60,
    "Clinical Notes": 70,
    "Conservative Care Summary": 80,
    "MRI / Imaging Report": 90,
}

if intel_packet_archetypes is not None:
    PACKET_PROFILE_LABELS = {
        key: config.get("label") or str(key).replace("_", " ").title()
        for key, config in intel_packet_archetypes.SUBMISSION_PROFILES.items()
    }
    PACKET_PROFILE_EXPECTED_DOCUMENTS = {
        key: list(config.get("expected_document_labels", []) or [])
        for key, config in intel_packet_archetypes.SUBMISSION_PROFILES.items()
    }
    PACKET_ARCHETYPE_LABELS = {
        key: config.get("label") or str(key).replace("_", " ").title()
        for key, config in intel_packet_archetypes.PACKET_ARCHETYPES.items()
    }
else:
    PACKET_PROFILE_LABELS = {
        "full_submission": "Full Submission",
        "authorization_request": "Authorization Request",
        "clinical_minimal": "Clinical Minimal",
    }

    PACKET_PROFILE_EXPECTED_DOCUMENTS = {
        "full_submission": [
            "Submission Cover Sheet",
            "VA Form 10-10172",
            "Consultation & Treatment Request",
            "SEOC",
            "Letter of Medical Necessity",
            "Virtual Consent Form",
            "Clinical Notes",
        ],
        "authorization_request": [
            "Consultation & Treatment Request",
            "Clinical Notes",
            "VA Authorization / Referral (10-10172 or 10-7080)",
        ],
        "clinical_minimal": [
            "Clinical Notes",
        ],
    }
    PACKET_ARCHETYPE_LABELS = {}

CONCEPT_LABEL_MAP = {
    "request_intent": "request intent",
    "diagnostic_basis": "diagnostic basis",
    "clinical_justification": "clinical justification",
    "routing_admin": "routing and admin support",
}

FIELD_CONCEPT_FAMILY = {
    "reason_for_request": "request_intent",
    "procedure": "request_intent",
    "service_date_range": "request_intent",
    "diagnosis": "diagnostic_basis",
    "icd_codes": "diagnostic_basis",
    "symptom": "diagnostic_basis",
    "ordering_provider": "routing_admin",
    "ordering_doctor": "routing_admin",
    "referring_provider": "routing_admin",
    "referring_doctor": "routing_admin",
    "provider": "routing_admin",
    "treating_provider": "routing_admin",
    "followup_provider": "routing_admin",
    "authorization_number": "routing_admin",
    "va_icn": "routing_admin",
    "claim_number": "routing_admin",
    "facility": "routing_admin",
    "clinic_name": "routing_admin",
}

TEXT_REPLACEMENTS = {
    "authorization_number": "authorization number",
    "ordering_provider": "ordering doctor",
    "referring_provider": "referring doctor",
    "treating_provider": "treating provider",
    "followup_provider": "follow-up provider",
    "patient_name": "patient name",
    "clinic_name": "clinic name",
    "location": "treating location",
    "service_date_range": "service date range",
    "signature_present": "signature",
    "icd_codes": "ICD codes",
    "va_icn": "VA ICN",
    "claim_number": "claim number",
    "consult_request": "Consultation & Treatment Request",
    "clinical_notes": "Clinical Notes",
    "cover_sheet": "Submission Cover Sheet",
    "consent": "Virtual Consent Form",
    "lomn": "Letter of Medical Necessity",
    "rfs": "VA Form 10-10172",
    "approved_referral": "VA Form 10-7080",
    "seoc": "SEOC",
    "classification_uncertainty": "document family uncertainty",
}

UNFILLED_DOCUMENT_MESSAGES = {
    "consent": (
        "Virtual Consent Form is present but unfilled",
        "Complete Virtual Consent Form",
    ),
    "consult_request": (
        "Consultation & Treatment Request is present but unfilled",
        "Complete Consultation & Treatment Request",
    ),
    "clinical_notes": (
        "Clinical Notes are present but unfilled",
        "Complete Clinical Notes",
    ),
}

HOST_REQUIRED_FIELDS = [
    ("patient_name", 20, "Missing patient name", "Add patient name to packet"),
    ("dob", 15, "Missing patient DOB", "Add patient date of birth"),
    ("authorization_number", 20, "Missing authorization number", "Add VA authorization number"),
    ("icd_codes", 15, "Missing ICD codes", "Add diagnosis ICD codes"),
    ("ordering_doctor", 10, "Missing ordering doctor", "Add ordering provider"),
    ("referring_doctor", 10, "Missing referring doctor", "Add referring provider"),
]

HOST_REQUIRED_FORMS = [
    (
        "Letter of Medical Necessity",
        5,
        "Missing Letter of Medical Necessity (LOMN)",
        "Add Letter of Medical Necessity",
    ),
    ("Clinical Notes", 5, "Missing Clinical Notes", "Attach clinical notes"),
    ("VA Form 10-10172", 0, "Missing VA Form 10-10172", "Add VA Form 10-10172"),
    ("Virtual Consent Form", 0, "Missing Virtual Consent Form", "Add Virtual Consent Form"),
    ("SEOC", 5, "Missing SEOC", "Add SEOC"),
    (
        "Consultation & Treatment Request",
        5,
        "Missing Consultation & Treatment Request",
        "Add Consultation & Treatment Request",
    ),
]


def intel_bridge_available():
    return process_intel_path is not None


def intel_bridge_enabled():
    value = os.getenv("TRUECORE_DISABLE_INTEL", "").strip().lower()
    return value not in {"1", "true", "yes", "on"}


def _unique(items):
    seen = set()
    deduped = []

    for item in items:
        key = item

        if isinstance(item, dict):
            key = tuple(sorted(item.items()))

        if key in seen:
            continue

        seen.add(key)
        deduped.append(item)

    return deduped


def _rewrite_terms(text):
    rewritten = str(text)

    for source, target in sorted(TEXT_REPLACEMENTS.items(), key=lambda item: len(item[0]), reverse=True):
        rewritten = rewritten.replace(source, target)

    return rewritten


def _sentence_case_text(text):
    cleaned = " ".join(str(text or "").strip().split())
    if not cleaned:
        return ""

    acronym_map = {
        "va": "VA",
        "icd": "ICD",
        "mri": "MRI",
        "ocr": "OCR",
        "npi": "NPI",
        "icn": "ICN",
        "dob": "DOB",
        "seoc": "SEOC",
        "lomn": "LOMN",
    }

    for raw, rendered in acronym_map.items():
        cleaned = re.sub(rf"\b{raw}\b", rendered, cleaned, flags=re.IGNORECASE)

    if cleaned and cleaned[0].islower():
        cleaned = cleaned[0].upper() + cleaned[1:]

    return cleaned


def _clean_issue(text):
    cleaned = _rewrite_terms(text).strip().rstrip(".")
    return _sentence_case_text(cleaned)


def _clean_fix(text):
    cleaned = _rewrite_terms(text).strip().rstrip(".")
    cleaned = re.sub(
        r"^\s*resolve conflicting values for name\b",
        "Resolve conflicting values for patient name",
        cleaned,
        flags=re.IGNORECASE,
    )
    return _sentence_case_text(cleaned)


def _issue_key(text):
    cleaned = _clean_issue(text).lower()
    cleaned = re.sub(r"\([^)]*\)", "", cleaned)
    cleaned = re.sub(r"[^a-z0-9]+", " ", cleaned)
    return cleaned.strip()


def _fix_key(text):
    cleaned = _clean_fix(text).lower()
    cleaned = re.sub(r"^\s*attach required document:\s*", "", cleaned)
    cleaned = re.sub(r"^\s*attach missing required documents\s*\(\d+\):\s*", "", cleaned)
    cleaned = re.sub(r"^\s*add or verify\s*", "", cleaned)
    cleaned = re.sub(r"^\s*add\s*", "", cleaned)
    cleaned = re.sub(r"^\s*attach\s*", "", cleaned)
    cleaned = re.sub(r"\([^)]*\)", "", cleaned)
    cleaned = re.sub(r"[^a-z0-9]+", " ", cleaned)
    return cleaned.strip()


def _merge_unique_strings(items, key_fn):
    deduped = []
    seen = set()

    for item in items:
        if not item:
            continue

        key = key_fn(item)

        if not key or key in seen:
            continue

        seen.add(key)
        deduped.append(item)

    return deduped


def _true_conflict_fields(packet):
    return {
        str(conflict.get("field", "")).strip()
        for conflict in getattr(packet, "conflicts", []) or []
        if conflict.get("type") != "document_gap"
    }


def _has_unfilled_document(packet, document_type):
    return document_type in set(getattr(packet, "unfilled_documents", set()) or set())


def _unfilled_document_entries(packet):
    entries = []

    for document_type, messages in UNFILLED_DOCUMENT_MESSAGES.items():
        if not _has_unfilled_document(packet, document_type):
            continue
        issue_text, fix_text = messages
        entries.append((issue_text, fix_text))

    return entries


def _rewrite_unfilled_document_language(text, packet):
    rewritten = str(text or "")

    for document_type, (issue_text, fix_text) in UNFILLED_DOCUMENT_MESSAGES.items():
        if not _has_unfilled_document(packet, document_type):
            continue

        form_name = FORM_NAME_MAP.get(document_type, document_type.replace("_", " "))
        rewritten = re.sub(
            rf"Missing required document:\s*{re.escape(document_type)}\b\.?",
            issue_text,
            rewritten,
            flags=re.IGNORECASE,
        )
        rewritten = re.sub(
            rf"Attach required document:\s*{re.escape(document_type)}\b\.?",
            fix_text,
            rewritten,
            flags=re.IGNORECASE,
        )
        rewritten = re.sub(
            rf"Missing {re.escape(document_type)}\b\.?",
            issue_text,
            rewritten,
            flags=re.IGNORECASE,
        )
        rewritten = rewritten.replace(
            f"Missing {form_name}",
            issue_text,
        )
        rewritten = rewritten.replace(
            f"Missing required document: {form_name}",
            issue_text,
        )
        rewritten = rewritten.replace(
            f"Attach required document: {form_name}",
            fix_text,
        )
        rewritten = rewritten.replace(
            f"Add {form_name}",
            fix_text,
        )

    if _unfilled_document_entries(packet):
        rewritten = rewritten.replace(
            "Missing required documents:",
            "Missing or incomplete required documents:",
        )
        rewritten = rewritten.replace(
            "Required supporting documents are missing",
            "Required supporting documents are missing or incomplete",
        )

    rewritten = _rewrite_document_gap_language(rewritten, packet)
    return rewritten


def _get_concept_tracebacks(packet):
    validation = dict(getattr(packet, "validation_intelligence", {}) or {})
    return list(
        validation.get("concept_evidence_tracebacks", [])
        or getattr(packet, "links", {}).get("concept_evidence_tracebacks", [])
        or []
    )


def _get_concept_entry(packet, concept_name):
    concept_name = str(concept_name or "").strip().lower()
    for entry in _get_concept_tracebacks(packet):
        if str(entry.get("concept") or "").strip().lower() == concept_name:
            return dict(entry)
    return {}


def _format_human_label(value):
    return str(value or "").replace("_", " ").strip().title()


def _format_scored_band(score, band):
    if score in (None, "") and not band:
        return None

    band_label = _format_human_label(band) if band else None
    try:
        numeric_score = int(round(float(score)))
    except Exception:
        numeric_score = None

    if band_label and numeric_score is not None:
        return f"{band_label} ({numeric_score})"
    if band_label:
        return band_label
    if numeric_score is not None:
        return numeric_score
    return score


def _describe_concept_source(entry):
    if not entry:
        return None

    document_type = str(entry.get("document_type") or "").strip()
    page_number = entry.get("page_number")
    primary_section_role = str(entry.get("primary_section_role") or "").strip()

    if document_type and document_type.lower() != "unknown":
        label = _format_document_type_name(document_type)
        return f"{label} on page {page_number}" if page_number else label

    if primary_section_role:
        label = f"{str(primary_section_role).replace('_', ' ')} section"
        return f"{label} on page {page_number}" if page_number else label

    if page_number:
        return f"page {page_number}"

    return None


def _rewrite_document_gap_language(text, packet):
    rewritten = str(text or "")
    match = re.fullmatch(
        r"\s*(?P<doc>[A-Za-z0-9_& ]+?)\s+document\s+is\s+present\s+but\s+missing\s+expected\s+field:\s*(?P<field>[A-Za-z0-9_]+)\.?\s*",
        rewritten,
        flags=re.IGNORECASE,
    )
    if not match:
        return rewritten

    doc = str(match.group("doc") or "").strip()
    field = str(match.group("field") or "").strip().lower()
    concept_name = FIELD_CONCEPT_FAMILY.get(field)
    field_label = FIELD_LABEL_MAP.get(field, field.replace("_", " "))
    pretty_doc = FORM_NAME_MAP.get(doc.lower(), _format_human_label(doc))

    if not concept_name:
        return f"{pretty_doc} does not show an explicit {field_label}."

    concept_entry = _get_concept_entry(packet, concept_name)
    concept_label = CONCEPT_LABEL_MAP.get(concept_name, concept_name.replace("_", " "))
    source_text = _describe_concept_source(concept_entry)

    if source_text:
        return f"{pretty_doc} does not show an explicit {field_label}; related {concept_label} appears in {source_text}."

    return f"{pretty_doc} does not show an explicit {field_label}."


def _filter_icd_codes(icd_codes, approved_icd_codes=None):
    if not icd_codes:
        return []

    if approved_icd_codes is None:
        return list(icd_codes)

    approved = {str(code).upper() for code in approved_icd_codes}

    return [
        str(code)
        for code in icd_codes
        if str(code).upper() in approved
    ]


def _map_forms(packet_output, packet):
    detected_documents = packet_output.get("detected_documents")

    if not detected_documents:
        detected_documents = sorted(getattr(packet, "detected_documents", []))

    forms = []

    for document_type in detected_documents or []:
        form_name = FORM_NAME_MAP.get(
            document_type,
            str(document_type).replace("_", " ").title(),
        )
        forms.append(form_name)

    forms = _unique(forms)

    return sorted(forms, key=lambda name: (FORM_ORDER.get(name, 999), name))


US_STATE_CODES = {
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
    "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
    "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
    "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
    "DC",
}

LOWERCASE_TITLE_WORDS = {"and", "or", "of", "for", "the", "at", "in", "on", "to"}
ALWAYS_UPPER_WORDS = {"OCH", "VA", "VAMC", "MRI", "ICD", "DOB", "NPI", "ICN", "SEOC", "RFA"}


def _normalize_space(value):
    return re.sub(r"\s+", " ", str(value or "").replace("\xa0", " ")).strip()


def _smart_title_case(value):
    raw = _normalize_space(value)
    if not raw:
        return None

    parts = re.split(r"(\s+)", raw)
    rendered = []
    word_index = 0

    for part in parts:
        if not part or part.isspace():
            rendered.append(part)
            continue

        if not re.search(r"[A-Za-z]", part):
            rendered.append(part)
            continue

        leading = re.match(r"^[^A-Za-z0-9]*", part).group(0)
        trailing = re.search(r"[^A-Za-z0-9]*$", part).group(0)
        core = part[len(leading): len(part) - len(trailing) if trailing else len(part)]
        upper_core = core.upper()
        lower_core = core.lower()

        if upper_core in US_STATE_CODES or upper_core in ALWAYS_UPPER_WORDS:
            word = upper_core
        elif word_index > 0 and lower_core in LOWERCASE_TITLE_WORDS:
            word = lower_core
        else:
            word = core.title()

        rendered.append(f"{leading}{word}{trailing}")
        word_index += 1

    text = "".join(rendered)
    text = re.sub(r"\bOch\b", "OCH", text)
    text = re.sub(r"\bVa\b", "VA", text)
    return text


def _normalize_provider_name(value):
    raw = _normalize_space(value)
    if not raw:
        return None

    raw = re.sub(r"^(?:physician|performed by|verified by|primary care physician|pcp)\s*:\s*", "", raw, flags=re.IGNORECASE)
    raw = re.split(r"\b(?:on|encounter info|result title|auth\s*\(verified\)|registration date)\b", raw, maxsplit=1, flags=re.IGNORECASE)[0]
    raw = raw.strip(" :-,")
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


def _drop_middle_initial_if_possible(value):
    normalized = _normalize_provider_name(value)
    if not normalized:
        return None

    match = re.match(r"^([A-Za-z]+)\s+([A-Z])\s+([A-Za-z]+)(,\s*[A-Z\-]+)?$", normalized)
    if not match:
        return normalized

    first_name, _middle_initial, last_name, credential_suffix = match.groups()
    simplified = f"{first_name} {last_name}"
    if credential_suffix:
        simplified += credential_suffix
    return simplified


def _clean_community_facility_name(value):
    raw = _normalize_space(value)
    if not raw:
        return None

    if "-" in raw:
        left, right = raw.split("-", 1)
        if re.match(r"^\d", right.strip()):
            raw = left.strip()

    raw = re.sub(r"\b\d{5}(?:-\d{4})?\b.*$", "", raw).strip(" ,-")
    return _smart_title_case(raw)


def _clean_location_value(value):
    raw = _normalize_space(value)
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
        return f"{_smart_title_case(match.group(1))} {match.group(2)}"

    raw = re.sub(r"-\d{6,}[A-Z]?$", "", raw)
    raw = re.sub(r",\s*(\d{5})(?:-\d{4})?$", r" \1", raw)
    return _smart_title_case(raw.strip(" ,-"))


def _looks_truncated(value):
    normalized = _normalize_space(value)
    if not normalized:
        return True
    if normalized.lower() in {"office visit note", "och center", "och center for pain man"}:
        return True
    return len(normalized) < 18


def _extract_referral_community_fields(packet):
    facility_candidates = []
    location_candidates = []

    for page_index, page in enumerate(list(getattr(packet, "pages", []) or [])):
        doc_type = getattr(packet, "document_types", {}).get(page_index, "unknown")
        if doc_type != "approved_referral":
            continue

        text = str(page or "")

        for match in re.finditer(r"Provider Name \(If known\)\s*:\s*([^\n\r]+)", text, re.IGNORECASE):
            facility = _clean_community_facility_name(match.group(1))
            if facility:
                facility_candidates.append(facility)

        for match in re.finditer(
            r"Initial Provider Location\s*:\s*([^\n\r]+(?:[\r\n]+\s*\d{5}(?:-\d+[A-Z]?)?)?)",
            text,
            re.IGNORECASE,
        ):
            raw_value = match.group(1)
            facility = _clean_community_facility_name(raw_value)
            location = _clean_location_value(raw_value)
            if facility:
                facility_candidates.append(facility)
            if location:
                location_candidates.append(location)

    facility = Counter(facility_candidates).most_common(1)[0][0] if facility_candidates else None
    location = Counter(location_candidates).most_common(1)[0][0] if location_candidates else None
    return facility, location


def _extract_treating_provider(packet):
    primary_candidates = []
    fallback_candidates = []

    for _page_index, page in enumerate(list(getattr(packet, "pages", []) or [])):
        text = str(page or "")
        lowered = text.lower()
        if "procedure note" not in lowered:
            continue

        for match in re.finditer(r"Physician\s*:\s*([^\n\r]+)", text, re.IGNORECASE):
            candidate = _drop_middle_initial_if_possible(match.group(1))
            if candidate:
                primary_candidates.append(candidate)

        for pattern in [
            r"Performed by\s*:\s*([^\n\r]+)",
            r"Verified by\s*:\s*([^\n\r]+)",
        ]:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                candidate = _drop_middle_initial_if_possible(match.group(1))
                if candidate:
                    fallback_candidates.append(candidate)

    if primary_candidates:
        return Counter(primary_candidates).most_common(1)[0][0]
    if fallback_candidates:
        return Counter(fallback_candidates).most_common(1)[0][0]
    return None


def _extract_followup_provider(packet):
    candidates = []

    for _page_index, page in enumerate(list(getattr(packet, "pages", []) or [])):
        text = str(page or "")
        lowered = text.lower()
        if "office visit note" not in lowered and "office clinic note" not in lowered:
            continue

        for pattern in [
            r"Performed by\s*:\s*([^\n\r]+)",
            r"Verified by\s*:\s*([^\n\r]+)",
        ]:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                candidate = _normalize_provider_name(match.group(1))
                if candidate:
                    candidates.append(candidate)

    return Counter(candidates).most_common(1)[0][0] if candidates else None


def _derive_provider_role_fields(packet, host_fields):
    derived = {}

    treating_provider = _extract_treating_provider(packet)
    followup_provider = _extract_followup_provider(packet)
    community_facility, treating_location = _extract_referral_community_fields(packet)

    if treating_provider:
        derived["treating_provider"] = treating_provider
        derived["provider"] = treating_provider

    if followup_provider and followup_provider != treating_provider:
        derived["followup_provider"] = followup_provider

    if community_facility:
        current_clinic = host_fields.get("clinic_name")
        if _looks_truncated(current_clinic) or len(_normalize_space(current_clinic)) < len(community_facility):
            derived["clinic_name"] = community_facility

    if treating_location:
        current_location = host_fields.get("location")
        if _looks_truncated(current_location) or len(_normalize_space(current_location)) < len(treating_location):
            derived["location"] = treating_location

    return derived


def _build_host_fields(packet, packet_output, approved_icd_codes=None, legacy_result=None):
    legacy_fields = {}

    if isinstance(legacy_result, dict):
        for key, value in dict(legacy_result.get("fields", {})).items():
            if value not in (None, "", []):
                legacy_fields[key] = value

    host_fields = dict(legacy_fields)
    intel_fields = dict(getattr(packet, "fields", {}) or {})

    for intel_name, host_name in FIELD_NAME_MAP.items():
        if intel_name not in intel_fields:
            continue

        value = intel_fields[intel_name]

        if intel_name == "icd_codes":
            value = _filter_icd_codes(value, approved_icd_codes)

        if value in (None, "", []):
            continue

        host_fields[host_name] = value

    if (
        not host_fields.get("ordering_doctor")
        and host_fields.get("provider")
        and not host_fields.get("treating_provider")
        and not host_fields.get("followup_provider")
        and (
            not host_fields.get("referring_doctor")
            or str(host_fields.get("provider")).strip().lower()
            != str(host_fields.get("referring_doctor")).strip().lower()
        )
    ):
        host_fields["ordering_doctor"] = host_fields["provider"]

    host_fields.update(_derive_provider_role_fields(packet, host_fields))

    return host_fields


def _build_issues(packet, packet_output):
    issues = []
    rubric = dict(packet_output.get("packet_rubric", {}) or {})

    for field_name in getattr(packet, "missing_fields", []) or []:
        label = FIELD_LABEL_MAP.get(field_name, field_name.replace("_", " "))
        issues.append(f"Missing {label}")

    for document_type in getattr(packet, "missing_documents", []) or []:
        issues.append(_rewrite_unfilled_document_language(
            f"Missing {_rewrite_terms(document_type)}",
            packet,
        ))

    for issue_text, _fix_text in _unfilled_document_entries(packet):
        issues.append(_clean_issue(issue_text))

    for conflict in getattr(packet, "conflicts", []) or []:
        message = conflict.get("message")

        if message:
            issues.append(_clean_issue(_rewrite_unfilled_document_language(message, packet)))
            continue

        field_name = conflict.get("field", "packet")
        label = FIELD_LABEL_MAP.get(field_name, field_name.replace("_", " "))
        issues.append(f"Conflict in {label}")

    for item in rubric.get("blockers", []):
        issues.append(_clean_issue(item))

    for item in rubric.get("review_needs", []):
        issues.append(_clean_issue(item))

    if not issues:
        review_summary = packet_output.get("review_summary", {})

        for item in review_summary.get("why_weak", []):
            issues.append(_clean_issue(item))

    return _unique([issue for issue in issues if issue])


def _build_fixes(packet, packet_output, legacy_result=None):
    fixes = []
    review_summary = packet_output.get("review_summary", {})
    rubric = dict(packet_output.get("packet_rubric", {}) or {})
    true_conflict_fields = _true_conflict_fields(packet)

    for fix in review_summary.get("priority_fixes", []):
        if fix.get("type") in {"missing_field", "missing_document", "missing_document_bundle"}:
            continue

        action = fix.get("action")
        target = str(fix.get("target", "")).strip()

        if action and not (
            fix.get("type") == "conflict" and target not in true_conflict_fields
        ):
            fixes.append(_clean_fix(_rewrite_unfilled_document_language(action, packet)))

    for recommendation in review_summary.get("fix_recommendations", []):
        if recommendation.lower().startswith("resolve conflicting values for "):
            field_name = recommendation.rsplit(" ", 1)[-1].rstrip(".")
            if field_name not in true_conflict_fields:
                continue
        fixes.append(_clean_fix(_rewrite_unfilled_document_language(recommendation, packet)))

    for _issue_text, fix_text in _unfilled_document_entries(packet):
        fixes.append(_clean_fix(fix_text))

    for fix_text in rubric.get("fixes", []):
        fixes.append(_clean_fix(fix_text))

    fixes = _merge_unique_strings(fixes, _fix_key)

    return fixes


def _format_page_ranges(pages):
    cleaned = sorted({int(page) for page in pages if str(page).isdigit()})
    if not cleaned:
        return ""

    ranges = []
    start = cleaned[0]
    end = cleaned[0]

    for page in cleaned[1:]:
        if page == end + 1:
            end = page
            continue

        ranges.append(f"{start}-{end}" if start != end else str(start))
        start = end = page

    ranges.append(f"{start}-{end}" if start != end else str(start))
    return ", ".join(ranges)


def _infer_region_from_text(text):
    cleaned = str(text or "").lower()
    if not cleaned:
        return None

    if any(marker in cleaned for marker in ["cervical", "cervicalgia", "neck pain", "c-spine", "c spine"]):
        return "cervical"

    if any(marker in cleaned for marker in ["lumbar", "lumbago", "low back", "back pain", "sciatica"]):
        return "lumbar"

    if "migraine" in cleaned or "headache" in cleaned:
        return "head"

    if "radiculopathy" in cleaned:
        return "spine"

    return None


def _infer_region_from_icds(value):
    regions = set()
    for code in value if isinstance(value, list) else []:
        normalized = str(code).strip().upper()
        if normalized.startswith(("M54.2", "M47.812")):
            regions.add("cervical")
        elif normalized.startswith(("M54.5", "M54.50", "M54.4", "M51")):
            regions.add("lumbar")
        elif normalized.startswith("G43"):
            regions.add("head")
    return regions


def _get_field_observations(packet, field_name):
    return list((getattr(packet, "field_observations", {}) or {}).get(field_name, []) or [])


def _describe_region_split(packet, field_name):
    observations = _get_field_observations(packet, field_name)
    region_pages = {}

    for observation in observations:
        if field_name == "icd_codes":
            regions = _infer_region_from_icds(observation.get("value"))
        else:
            regions = set()
            region = _infer_region_from_text(observation.get("value"))
            if region:
                regions.add(region)

        page_number = observation.get("page_number")
        for region in regions:
            region_pages.setdefault(region, set()).add(page_number)

    return _render_region_history(region_pages)


def _collect_region_history(packet, field_name):
    observations = _get_field_observations(packet, field_name)
    region_pages = {}

    for observation in observations:
        if field_name == "icd_codes":
            regions = _infer_region_from_icds(observation.get("value"))
        else:
            regions = set()
            region = _infer_region_from_text(observation.get("value"))
            if region:
                regions.add(region)

        page_number = observation.get("page_number")
        for region in regions:
            region_pages.setdefault(region, set()).add(page_number)

    return region_pages


def _render_region_history(region_pages):
    if len(region_pages) < 2:
        return None

    preferred_order = ["lumbar", "cervical", "head", "spine"]
    parts = []
    for region in preferred_order:
        pages = region_pages.get(region)
        if not pages:
            continue
        parts.append(f"{region} pages {_format_page_ranges(pages)}")

    if len(parts) < 2:
        return None

    if "lumbar" in region_pages and "cervical" in region_pages:
        prefix = "Mixed lumbar and cervical history"
    else:
        prefix = "Mixed episode history"

    return prefix + ": " + "; ".join(parts[:3])


def _build_issue_breakdowns(packet):
    breakdowns = []
    review_flags = set(getattr(packet, "review_flags", []) or [])

    if "diagnosis_icd_mismatch" in review_flags:
        region_pages = (
            _collect_region_history(packet, "diagnosis")
            or _collect_region_history(packet, "reason_for_request")
            or _collect_region_history(packet, "icd_codes")
        )
        details = []
        for region in ["lumbar", "cervical", "head", "spine"]:
            pages = (region_pages or {}).get(region)
            if pages:
                details.append(f"{region.title()} history on pages {_format_page_ranges(pages)}")
        breakdowns.append({
            "title": "Diagnosis / ICD mismatch",
            "details": details,
        })

    return breakdowns


def _build_concept_review_notes(packet):
    notes = []
    concept_tracebacks = _get_concept_tracebacks(packet)
    lead_text = {
        "request_intent": "Request intent appears in",
        "diagnostic_basis": "Diagnostic basis appears in",
        "clinical_justification": "Clinical justification appears in",
        "routing_admin": "Routing and admin details appear in",
    }

    for concept_name in ("request_intent", "diagnostic_basis", "clinical_justification", "routing_admin"):
        entry = next(
            (
                item
                for item in concept_tracebacks
                if str(item.get("concept") or "").strip().lower() == concept_name
            ),
            None,
        )
        if not entry:
            continue
        source_text = _describe_concept_source(entry)
        if not source_text:
            continue
        notes.append(f"{lead_text.get(concept_name, 'Relevant support appears in')} {source_text}.")

    return _merge_unique_strings(notes, _issue_key)


def _describe_npi_context(packet):
    observations = _get_field_observations(packet, "npi")
    if not observations:
        return None

    page_buckets = {}
    for observation in observations:
        page = observation.get("page_number")
        snippet = str(observation.get("snippet") or "").lower()
        if any(marker in snippet for marker in ["pcp", "primary care provider", "care team", "patient's care team"]):
            label = "PCP/care-team context"
        else:
            label = "other provider context"
        page_buckets.setdefault(label, set()).add(page)

    if len(page_buckets) < 2:
        return None

    parts = [
        f"{label} on pages {_format_page_ranges(pages)}"
        for label, pages in page_buckets.items()
    ]
    return "Multiple provider contexts: " + " vs ".join(parts[:2])


def _describe_clinic_name_context(packet):
    observations = _get_field_observations(packet, "clinic_name")
    if not observations:
        return None

    cover_sheet_pages = sorted({
        observation.get("page_number")
        for observation in observations
        if observation.get("document_type") == "cover_sheet"
    })
    if cover_sheet_pages:
        return f"Mostly the same clinic; cover-sheet formatting variant on page {_format_page_ranges(cover_sheet_pages)}"

    return None


def _describe_conflict_context(packet, field_name):
    if field_name in {"diagnosis", "reason_for_request", "icd_codes"}:
        return _describe_region_split(packet, field_name)

    if field_name == "npi":
        return _describe_npi_context(packet)

    if field_name == "clinic_name":
        return _describe_clinic_name_context(packet)

    observations = _get_field_observations(packet, field_name)
    pages = [observation.get("page_number") for observation in observations if observation.get("page_number")]
    if not pages:
        return None

    return f"Seen on pages {_format_page_ranges(pages)}"


def _format_conflict_value(value):
    if isinstance(value, list):
        value = ", ".join(str(item).strip() for item in value if str(item).strip())
    elif isinstance(value, tuple):
        value = ", ".join(str(item).strip() for item in value if str(item).strip())
    else:
        value = str(value or "").strip()

    value = re.sub(r"\s+", " ", value).strip(" ,.-")
    if len(value) > 80:
        value = value[:77].rstrip() + "..."
    return value or None


def _summarize_conflict_values(conflict):
    values = list((conflict or {}).get("values", []) or [])
    rendered = []
    seen = set()
    for value in values:
        formatted = _format_conflict_value(value)
        if not formatted:
            continue
        key = formatted.lower()
        if key in seen:
            continue
        seen.add(key)
        rendered.append(formatted)
    if len(rendered) < 2:
        return None
    return " vs ".join(rendered[:2])


def _build_issue_details(packet, packet_output):
    details = []
    template_markers = list(getattr(packet, "template_markers", []) or [])

    if template_markers:
        pages = sorted({int(entry.get("page_number")) for entry in template_markers if entry.get("page_number")})
        if pages:
            page_text = ", ".join(str(page) for page in pages[:6])
            if len(pages) > 6:
                page_text += ", ..."
            details.append(f"Template or training-example text detected on pages {page_text}")

    for field_name in getattr(packet, "missing_fields", []) or []:
        label = FIELD_LABEL_MAP.get(field_name, field_name.replace("_", " "))
        details.append(f"Missing {label}")

    for document_type in getattr(packet, "missing_documents", []) or []:
        details.append(_clean_issue(_rewrite_unfilled_document_language(
            f"Missing {_rewrite_terms(document_type)}",
            packet,
        )))

    for issue_text, _fix_text in _unfilled_document_entries(packet):
        details.append(_clean_issue(issue_text))

    for conflict in getattr(packet, "conflicts", []) or []:
        message = _clean_issue(_rewrite_unfilled_document_language(conflict.get("message") or "", packet))
        context = _describe_conflict_context(packet, conflict.get("field"))
        value_summary = _summarize_conflict_values(conflict)
        context_parts = [part for part in [value_summary, context] if part]
        details.append(f"{message} ({'; '.join(context_parts)})" if context_parts else message)

    if "diagnosis_icd_mismatch" in set(getattr(packet, "review_flags", []) or []):
        context = (
            _describe_region_split(packet, "diagnosis")
            or _describe_region_split(packet, "reason_for_request")
            or _describe_region_split(packet, "icd_codes")
        )
        text = "Diagnosis / ICD mismatch"
        details.append(f"{text}: {context}" if context else text)

    if not details:
        review_summary = packet_output.get("review_summary", {})
        details.extend([_clean_issue(item) for item in review_summary.get("why_weak", [])])

    return _merge_unique_strings(details, _issue_key)


def _build_intel_display(packet, packet_output):
    review_summary = packet_output.get("review_summary", {})
    rubric = dict(packet_output.get("packet_rubric", {}) or {})
    workflow_route = packet_output.get("workflow_route", {})
    next_action = packet_output.get("recommended_next_action", {})
    denial_risk = packet_output.get("denial_risk", {})
    decision_intelligence = dict(packet_output.get("decision_intelligence", {}) or {})
    success_pattern = dict(packet_output.get("success_pattern_match", {}) or {})
    true_conflict_fields = _true_conflict_fields(packet)
    packet_profile = (
        packet_output.get("packet_profile")
        or getattr(packet, "packet_profile", None)
        or decision_intelligence.get("packet_type")
        or success_pattern.get("profile")
    )
    expected_documents = list(PACKET_PROFILE_EXPECTED_DOCUMENTS.get(packet_profile, []) or [])
    packet_archetype = packet_output.get("packet_archetype") or getattr(packet, "packet_archetype", None)
    packet_archetype_label = (
        packet_output.get("packet_archetype_label")
        or getattr(packet, "packet_archetype_label", None)
        or PACKET_ARCHETYPE_LABELS.get(packet_archetype)
        or (_format_human_label(packet_archetype) if packet_archetype else None)
    )
    packet_archetype_signals = list(
        packet_output.get("packet_archetype_signals", [])
        or getattr(packet, "packet_archetype_signals", [])
        or []
    )
    invariant_score = packet_output.get("packet_invariant_coverage_score", getattr(packet, "packet_invariant_coverage_score", None))
    invariant_band = packet_output.get("packet_invariant_coverage_band", getattr(packet, "packet_invariant_coverage_band", None))
    format_variability = packet_output.get("packet_format_variability", getattr(packet, "packet_format_variability", None))
    variability_reasons = list(
        packet_output.get("packet_variability_reasons", [])
        or getattr(packet, "packet_variability_reasons", [])
        or []
    )
    failure_mode_summaries = list(
        packet_output.get("packet_failure_mode_summaries", [])
        or getattr(packet, "packet_failure_mode_summaries", [])
        or []
    )
    classification_caution = bool(
        packet_output.get("packet_classification_caution", getattr(packet, "packet_classification_caution", False))
    )
    template_markers = list(getattr(packet, "template_markers", []) or [])
    evidence_strength_score = packet_output.get("packet_evidence_score", getattr(packet, "packet_evidence_score", None))
    evidence_strength_band = packet_output.get("packet_evidence_band", getattr(packet, "packet_evidence_band", None))
    assembly_score = packet_output.get("packet_assembly_score", getattr(packet, "packet_assembly_score", None))
    assembly_band = packet_output.get("packet_assembly_band", getattr(packet, "packet_assembly_band", None))

    priority_fixes = []

    for item in review_summary.get("priority_fixes", []):
        if isinstance(item, dict):
            action = item.get("action")
            target = str(item.get("target", "")).strip()
            if action and not (
                item.get("type") == "conflict" and target not in true_conflict_fields
            ):
                priority_fixes.append(_clean_fix(_rewrite_unfilled_document_language(action, packet)))
        elif item:
            priority_fixes.append(_clean_fix(_rewrite_unfilled_document_language(item, packet)))

    why_weak = [_clean_issue(item) for item in review_summary.get("why_weak", [])]
    why_weak = [_clean_issue(_rewrite_unfilled_document_language(item, packet)) for item in review_summary.get("why_weak", [])]
    conflict_items = [_clean_issue(_rewrite_unfilled_document_language(item, packet)) for item in review_summary.get("conflict_items", [])]
    approval_rationale = [_clean_issue(_rewrite_unfilled_document_language(item, packet)) for item in packet_output.get("approval_rationale", [])]

    if not true_conflict_fields:
        why_weak = [item for item in why_weak if "conflict" not in item.lower()]
        conflict_items = []
        approval_rationale = [item for item in approval_rationale if "conflict" not in item.lower()]

    missing_items = [_clean_issue(_rewrite_unfilled_document_language(item, packet)) for item in review_summary.get("missing_items", [])]
    for issue_text, _fix_text in _unfilled_document_entries(packet):
        missing_items.append(_clean_issue(issue_text))

    for _issue_text, fix_text in _unfilled_document_entries(packet):
        priority_fixes.append(_clean_fix(fix_text))

    issue_details = _build_issue_details(packet, packet_output)
    issue_breakdowns = _build_issue_breakdowns(packet)
    concept_review_notes = _build_concept_review_notes(packet)
    review_rationale = _merge_unique_strings(
        why_weak + approval_rationale,
        _issue_key,
    )
    review_flags = set(getattr(packet, "review_flags", []) or [])
    if "diagnosis_icd_mismatch" in review_flags:
        alignment_summary = "Mixed clinical history still needs reviewer alignment"
        if packet_output.get("packet_strength", getattr(packet, "packet_strength", None)) == "strong":
            alignment_summary = "Strong packet overall, but mixed clinical history still needs reviewer alignment"
        review_rationale = [alignment_summary] + [
            item for item in review_rationale
            if "diagnosis and icd coding do not appear clinically aligned" not in str(item).lower()
        ]
        review_rationale = _merge_unique_strings(review_rationale, _issue_key)

    if packet_profile and expected_documents:
        profile_label = PACKET_PROFILE_LABELS.get(packet_profile, str(packet_profile).replace("_", " ").title())
        profile_summary = f"Inferred packet profile: {profile_label}. Expected document family: {', '.join(expected_documents)}."
        review_rationale = _merge_unique_strings([profile_summary] + review_rationale, _issue_key)

    if packet_archetype_label:
        archetype_summary = f"Observed packet archetype: {packet_archetype_label}."
        review_rationale = _merge_unique_strings([archetype_summary] + review_rationale, _issue_key)

    try:
        invariant_numeric = float(invariant_score)
    except Exception:
        invariant_numeric = None

    normalized_variability = str(format_variability or "").strip().lower()
    if invariant_numeric is not None and normalized_variability:
        if invariant_numeric >= 80 and normalized_variability == "high":
            review_rationale = _merge_unique_strings(
                ["Core packet invariants are present despite high format variation." ] + review_rationale,
                _issue_key,
            )
        elif invariant_numeric < 60 and normalized_variability == "high":
            review_rationale = _merge_unique_strings(
                ["High format variation is limiting confidence because core packet anchors are only partially present."] + review_rationale,
                _issue_key,
            )

    if failure_mode_summaries:
        review_rationale = _merge_unique_strings(failure_mode_summaries + review_rationale, _issue_key)

    if classification_caution and getattr(packet, "missing_documents", []):
        caution_note = "Some missing-document calls may reflect packet-format ambiguity; confirm them against packet content before treating them as final."
        review_rationale = _merge_unique_strings([caution_note] + review_rationale, _issue_key)

    if concept_review_notes:
        review_rationale = _merge_unique_strings(concept_review_notes + review_rationale, _issue_key)

    if template_markers:
        pages = sorted({int(entry.get("page_number")) for entry in template_markers if entry.get("page_number")})
        if pages:
            page_text = ", ".join(str(page) for page in pages[:6])
            if len(pages) > 6:
                page_text += ", ..."
            template_summary = f"Training or template scaffolding detected on pages {page_text}; reviewer should treat placeholder content cautiously."
            review_rationale = _merge_unique_strings([template_summary] + review_rationale, _issue_key)

    try:
        evidence_numeric = float(evidence_strength_score)
    except Exception:
        evidence_numeric = None

    try:
        assembly_numeric = float(assembly_score)
    except Exception:
        assembly_numeric = None

    if (
        evidence_numeric is not None
        and assembly_numeric is not None
        and evidence_numeric >= assembly_numeric + 12
    ):
        assembly_gap_summary = "Substantive support is stronger than packet assembly; paperwork completion is the main blocker."
        review_rationale = _merge_unique_strings([assembly_gap_summary] + review_rationale, _issue_key)

    score_breakdown = []
    for component in list(rubric.get("components", []) or []):
        label = str(component.get("label") or "").strip()
        if not label:
            continue
        try:
            earned_points = float(component.get("earned_points") or 0.0)
            max_points = float(component.get("max_points") or 0.0)
            points_text = f"{earned_points:.2f} / {max_points:.2f}"
        except Exception:
            points_text = str(component.get("earned_points") or "")
        summary_text = str(component.get("summary") or "").strip()
        status_text = _format_human_label(component.get("status")) if component.get("status") else None
        parts = [part for part in [points_text, status_text, summary_text] if part]
        score_breakdown.append({
            "label": label,
            "value": " | ".join(parts),
        })

    consistency = dict(rubric.get("consistency", {}) or {})
    if consistency:
        score_breakdown.append({
            "label": str(consistency.get("label") or "Cross-document consistency"),
            "value": f"{float(consistency.get('earned_points') or 0.0):.2f} / {float(consistency.get('max_points') or 0.0):.2f} | {_format_human_label(consistency.get('status')) if consistency.get('status') else ''} | {str(consistency.get('summary') or '').strip()}".strip(" |"),
        })

    main_blocker = (
        rubric.get("main_blocker")
        or packet_output.get("packet_main_blocker")
        or (packet_output.get("submission_decision", {}) or {}).get("hold_reasons", [None])[0]
    )

    return {
        "packet_confidence": packet_output.get("packet_confidence", getattr(packet, "packet_confidence", None)),
        "approval_probability": packet_output.get("approval_probability", getattr(packet, "approval_probability", None)),
        "approval_outlook": packet_output.get("approval_probability", getattr(packet, "approval_probability", None)),
        "packet_strength": packet_output.get("packet_strength", getattr(packet, "packet_strength", None)),
        "score_basis": rubric.get("score_basis"),
        "score_story": rubric.get("summary"),
        "main_blocker": main_blocker,
        "score_breakdown": score_breakdown,
        "legacy_score": packet_output.get("packet_legacy_score", getattr(packet, "packet_legacy_score", None)),
        "evidence_strength": _format_scored_band(evidence_strength_score, evidence_strength_band),
        "evidence_strength_score": evidence_strength_score,
        "evidence_strength_band": evidence_strength_band,
        "packet_assembly": _format_scored_band(assembly_score, assembly_band),
        "packet_assembly_score": assembly_score,
        "packet_assembly_band": assembly_band,
        "invariant_coverage": _format_scored_band(invariant_score, invariant_band),
        "invariant_coverage_score": invariant_score,
        "invariant_coverage_band": invariant_band,
        "format_variability": _format_human_label(format_variability) if format_variability else None,
        "format_variability_reasons": variability_reasons,
        "classification_caution": classification_caution,
        "failure_mode_summaries": failure_mode_summaries,
        "submission_readiness": packet_output.get("submission_readiness"),
        "packet_profile": PACKET_PROFILE_LABELS.get(packet_profile, str(packet_profile).replace("_", " ").title()) if packet_profile else None,
        "packet_archetype": packet_archetype_label,
        "packet_archetype_signals": packet_archetype_signals,
        "profile_confidence": success_pattern.get("confidence"),
        "expected_documents": expected_documents,
        "template_markers": template_markers,
        "workflow_queue": workflow_route.get("queue") if isinstance(workflow_route, dict) else None,
        "next_action": next_action.get("action") if isinstance(next_action, dict) else None,
        "denial_risk": denial_risk.get("level") if isinstance(denial_risk, dict) else None,
        "review_priority": getattr(packet, "review_priority", None),
        "review_flags": _unique(list(review_flags or [])),
        "issue_details": issue_details,
        "issue_breakdowns": issue_breakdowns,
        "concept_review_notes": concept_review_notes,
        "why_weak": _merge_unique_strings(
            why_weak,
            _issue_key,
        ),
        "missing_items": _merge_unique_strings(
            missing_items,
            _issue_key,
        ),
        "conflict_items": _merge_unique_strings(
            conflict_items,
            _issue_key,
        ),
        "priority_fixes": _merge_unique_strings(priority_fixes, _fix_key),
        "review_rationale": review_rationale,
        "approval_rationale": _merge_unique_strings(
            approval_rationale,
            _issue_key,
        ),
    }


def _format_document_type_name(document_type):
    if not document_type or document_type == "unknown":
        return "Unknown"

    return FORM_NAME_MAP.get(
        document_type,
        str(document_type).replace("_", " ").title(),
    )


def _build_scan_diagnostics(packet, packet_output):
    intake_summary = dict(
        packet_output.get("ocr_intake_summary", {})
        or getattr(packet, "intake_diagnostics", {})
        or {}
    )
    document_intelligence = dict(
        packet_output.get("document_intelligence_2", {})
        or getattr(packet, "document_intelligence", {})
        or {}
    )
    confidence_map = dict(
        document_intelligence.get("document_intelligence_confidence_map", {})
        or packet_output.get("document_confidence_map", {})
        or {}
    )
    scan_quality = dict(document_intelligence.get("scan_quality_assessment", {}) or {})
    handwriting = dict(document_intelligence.get("handwriting_risk_detection", {}) or {})
    layout_summary = dict(document_intelligence.get("layout_zone_detection", {}).get("summary", {}) or {})
    source_ranking = list(document_intelligence.get("source_reliability_ranking", []) or [])
    page_metadata = list(getattr(packet, "page_metadata", []) or [])

    pages = []
    for index, metadata in enumerate(page_metadata, start=1):
        metadata = dict(metadata or {})
        layout = dict(metadata.get("layout", {}) or {})
        field_zones = list(metadata.get("field_zones", []) or [])
        ocr_zone_count = sum(
            1
            for zone in field_zones
            if str(zone.get("zone_name") or "").lower() != "native_text"
        )
        native_zone_count = sum(
            1
            for zone in field_zones
            if str(zone.get("zone_name") or "").lower() == "native_text"
        )
        has_ocr_text = bool(str(metadata.get("ocr_text") or "").strip())
        has_native_text = bool(str(metadata.get("native_text") or "").strip())
        text_source = "native_text"
        if has_ocr_text:
            text_source = "ocr_text"
        elif ocr_zone_count:
            text_source = "layout_ocr"
        elif has_native_text and native_zone_count:
            text_source = "native_text_structured"
        confidence_entry = dict(confidence_map.get(f"page_{index}", {}) or {})
        pages.append({
            "page": index,
            "document_type": _format_document_type_name(
                confidence_entry.get("document_type")
                or getattr(packet, "document_types", {}).get(index - 1, "unknown")
            ),
            "classification_confidence": confidence_entry.get("confidence"),
            "classification_band": confidence_entry.get("confidence_band"),
            "ocr_provider": metadata.get("ocr_provider"),
            "ocr_provider_chain": list(metadata.get("ocr_provider_chain", []) or []),
            "ocr_confidence": metadata.get("ocr_confidence") if has_ocr_text or ocr_zone_count else None,
            "scan_quality": confidence_entry.get("scan_quality_band"),
            "handwriting_risk": confidence_entry.get("handwriting_risk_level"),
            "field_zone_count": len(field_zones),
            "ocr_field_zone_count": ocr_zone_count,
            "native_field_zone_count": native_zone_count,
            "split_segment_count": len(metadata.get("ocr_segments", []) or []),
            "table_region_count": len(layout.get("table_regions", []) or []),
            "signature_region_count": len(layout.get("signature_regions", []) or []),
            "handwritten_region_count": len(layout.get("handwritten_regions", []) or []),
            "text_source": text_source,
        })

    return {
        "summary": {
            "ocr_provider": intake_summary.get("ocr_provider") or getattr(packet, "ocr_provider", None),
            "page_count": intake_summary.get("page_count", len(page_metadata)),
            "pages_with_native_text": intake_summary.get("pages_with_native_text"),
            "pages_with_ocr": intake_summary.get("pages_with_ocr"),
            "pages_with_ocr_field_zones": intake_summary.get("pages_with_ocr_field_zones"),
            "pages_with_native_field_zones": intake_summary.get("pages_with_native_field_zones"),
            "pages_with_field_zones": intake_summary.get("pages_with_field_zones"),
            "pages_with_split_segments": intake_summary.get("pages_with_split_segments"),
            "average_ocr_confidence": intake_summary.get("average_ocr_confidence"),
            "ocr_attempted": intake_summary.get("ocr_attempted"),
            "extraction_mode": intake_summary.get("extraction_mode"),
            "fallback_applied": intake_summary.get("fallback_applied"),
            "available_ocr_providers": list(intake_summary.get("available_ocr_providers", []) or []),
            "available_pdf_tools": list(intake_summary.get("available_pdf_tools", []) or []),
            "ocr_provider_chain": list(intake_summary.get("ocr_provider_chain", []) or []),
            "scan_quality_band": scan_quality.get("overall_band"),
            "scan_quality_score": scan_quality.get("average_score"),
            "handwriting_risk_level": handwriting.get("overall_level"),
            "handwriting_risk_score": handwriting.get("average_score"),
            "pages_with_table_regions": layout_summary.get("pages_with_table_regions"),
            "pages_with_signature_regions": layout_summary.get("pages_with_signature_regions"),
            "pages_with_handwritten_regions": layout_summary.get("pages_with_handwritten_regions"),
        },
        "pages": pages,
        "source_reliability_ranking": source_ranking[:5],
    }


def _apply_host_packet_rules(result, packet=None):
    score = int(result.get("score", 0))
    fields = dict(result.get("fields", {}))
    forms = set(result.get("forms", []))
    issues = list(result.get("issues", []))
    fixes = list(result.get("fixes", []))

    compatibility = {
        "missing_fields": [],
        "missing_forms": [],
    }

    intel_backed = packet is not None and bool(getattr(packet, "output", {}) or {})

    if intel_backed:
        compatibility["missing_fields"] = list(getattr(packet, "missing_fields", []) or [])
        compatibility["missing_forms"] = [
            FORM_NAME_MAP.get(document_type, _rewrite_terms(document_type))
            for document_type in (getattr(packet, "missing_documents", []) or [])
        ]

        result["score"] = max(score, 0)
        result["issues"] = _merge_unique_strings(issues, _issue_key)
        result["fixes"] = _merge_unique_strings(fixes, _fix_key)
        result.setdefault("intel", {})
        result["intel"]["host_compatibility"] = compatibility
        return result

    for field_name, penalty, issue_text, fix_text in HOST_REQUIRED_FIELDS:
        value = fields.get(field_name)

        if value in (None, "", []):
            compatibility["missing_fields"].append(field_name)

            if _issue_key(issue_text) not in {_issue_key(item) for item in issues}:
                issues.append(issue_text)

            if _fix_key(fix_text) not in {_fix_key(item) for item in fixes}:
                fixes.append(fix_text)

            score -= penalty

    for form_name, penalty, issue_text, fix_text in HOST_REQUIRED_FORMS:
        if form_name in forms:
            continue

        compatibility["missing_forms"].append(form_name)
        issue_text = _rewrite_unfilled_document_language(issue_text, packet)
        fix_text = _rewrite_unfilled_document_language(fix_text, packet)

        if _issue_key(issue_text) not in {_issue_key(item) for item in issues}:
            issues.append(issue_text)

        if _fix_key(fix_text) not in {_fix_key(item) for item in fixes}:
            fixes.append(fix_text)

        score -= penalty

    score = max(score, 0)

    result["score"] = score
    result["issues"] = _merge_unique_strings(issues, _issue_key)
    result["fixes"] = _merge_unique_strings(fixes, _fix_key)
    result.setdefault("intel", {})
    result["intel"]["host_compatibility"] = compatibility

    return result


def build_intel_result(file_path, approved_icd_codes=None, legacy_result=None):
    if not intel_bridge_enabled():
        return None

    if not intel_bridge_available():
        if INTEL_IMPORT_ERROR is not None:
            log_event("intel_bridge_unavailable", str(INTEL_IMPORT_ERROR))
        return None

    filename = os.path.basename(file_path)

    try:
        bundle = process_intel_path(file_path)
    except Exception as exc:
        log_event("intel_processing_error", f"{filename} | {exc}")
        return None

    packet = bundle.get("packet")

    if packet is None:
        return None

    packet_output = dict(getattr(packet, "output", {}) or {})
    score = packet_output.get("packet_score", getattr(packet, "packet_score", None))

    if score is None:
        return None

    result = {
        "file": filename,
        "score": score,
        "fields": _build_host_fields(
            packet,
            packet_output,
            approved_icd_codes=approved_icd_codes,
            legacy_result=legacy_result,
        ),
        "forms": _map_forms(packet_output, packet),
        "issues": _build_issues(packet, packet_output),
        "fixes": _build_fixes(packet, packet_output, legacy_result=legacy_result),
        "intel": {
            "enabled": True,
            "packet_output": packet_output,
            "evidence_intelligence": dict(packet_output.get("evidence_intelligence_1", {}) or {}),
            "clinical_intelligence": dict(packet_output.get("clinical_intelligence_1", {}) or {}),
            "denial_intelligence": dict(packet_output.get("denial_intelligence_1", {}) or {}),
            "human_in_the_loop_intelligence": dict(packet_output.get("human_in_the_loop_intelligence_1", {}) or {}),
            "orchestration_intelligence": dict(packet_output.get("orchestration_intelligence_1", {}) or {}),
            "architecture_intelligence": dict(packet_output.get("architecture_intelligence_1", {}) or {}),
            "recovery_intelligence": dict(packet_output.get("recovery_intelligence_1", {}) or {}),
            "policy_intelligence": dict(packet_output.get("policy_intelligence_2", {}) or {}),
            "deployment_intelligence": dict(packet_output.get("deployment_intelligence_1", {}) or {}),
            "document_intelligence": dict(packet_output.get("document_intelligence_2", {}) or {}),
            "validation_intelligence": dict(packet_output.get("validation_intelligence_2", {}) or {}),
            "review_flags": list(getattr(packet, "review_flags", []) or []),
            "metrics": dict(getattr(packet, "metrics", {}) or {}),
            "scan_diagnostics": _build_scan_diagnostics(packet, packet_output),
            "display": _build_intel_display(packet, packet_output),
        },
    }

    try:
        authoritative_score = int(float(score))
    except Exception:
        authoritative_score = int(score or 0)

    result["score"] = authoritative_score
    result["intel"]["core_packet_score"] = authoritative_score
    result["intel"]["display"]["core_packet_score"] = authoritative_score

    result = _apply_host_packet_rules(result, packet=packet)

    log_event("intel_analysis_active", filename)

    return result
