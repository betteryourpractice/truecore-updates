"""
TrueCore Intel Bridge

Adapts the TrueCoreIntel packet model into the legacy
TrueCore Packet Assistant result format expected by the GUI.
"""

import os
import re

from TrueCore.utils.logging_system import log_event


INTEL_IMPORT_ERROR = None

try:
    from TrueCoreIntel.intel_engine import process_path as process_intel_path
except Exception as exc:
    process_intel_path = None
    INTEL_IMPORT_ERROR = exc


FIELD_NAME_MAP = {
    "name": "patient_name",
    "dob": "dob",
    "authorization_number": "authorization_number",
    "icd_codes": "icd_codes",
    "ordering_provider": "ordering_doctor",
    "referring_provider": "referring_doctor",
    "provider": "provider",
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
    "reason_for_request": "reason for request",
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
    "clinical_notes": "Clinical Notes",
    "imaging_report": "MRI / Imaging Report",
    "conservative_care_summary": "Conservative Care Summary",
}

FORM_ORDER = {
    "Submission Cover Sheet": 10,
    "VA Form 10-10172": 20,
    "Consultation & Treatment Request": 30,
    "SEOC": 40,
    "Letter of Medical Necessity": 50,
    "Virtual Consent Form": 60,
    "Clinical Notes": 70,
    "Conservative Care Summary": 80,
    "MRI / Imaging Report": 90,
}

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
        "VA Form 10-10172",
    ],
    "clinical_minimal": [
        "Clinical Notes",
    ],
}

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
    "seoc": "SEOC",
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


def _clean_issue(text):
    cleaned = _rewrite_terms(text).strip()
    return cleaned.rstrip(".")


def _clean_fix(text):
    cleaned = _rewrite_terms(text).strip()
    return cleaned.rstrip(".")


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

    if not host_fields.get("ordering_doctor") and host_fields.get("provider"):
        host_fields["ordering_doctor"] = host_fields["provider"]

    return host_fields


def _build_issues(packet, packet_output):
    issues = []

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

    if not issues:
        review_summary = packet_output.get("review_summary", {})

        for item in review_summary.get("why_weak", []):
            issues.append(_clean_issue(item))

    return _unique([issue for issue in issues if issue])


def _build_fixes(packet, packet_output, legacy_result=None):
    fixes = []
    review_summary = packet_output.get("review_summary", {})
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
    workflow_route = packet_output.get("workflow_route", {})
    next_action = packet_output.get("recommended_next_action", {})
    denial_risk = packet_output.get("denial_risk", {})
    decision_intelligence = dict(packet_output.get("decision_intelligence", {}) or {})
    success_pattern = dict(packet_output.get("success_pattern_match", {}) or {})
    true_conflict_fields = _true_conflict_fields(packet)
    packet_profile = decision_intelligence.get("packet_type") or success_pattern.get("profile")
    expected_documents = list(PACKET_PROFILE_EXPECTED_DOCUMENTS.get(packet_profile, []) or [])
    template_markers = list(getattr(packet, "template_markers", []) or [])

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

    return {
        "packet_confidence": packet_output.get("packet_confidence", getattr(packet, "packet_confidence", None)),
        "approval_probability": packet_output.get("approval_probability", getattr(packet, "approval_probability", None)),
        "packet_strength": packet_output.get("packet_strength", getattr(packet, "packet_strength", None)),
        "submission_readiness": packet_output.get("submission_readiness"),
        "packet_profile": PACKET_PROFILE_LABELS.get(packet_profile, str(packet_profile).replace("_", " ").title()) if packet_profile else None,
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

    result = _apply_host_packet_rules(result, packet=packet)

    log_event("intel_analysis_active", filename)

    return result
