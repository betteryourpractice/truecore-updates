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
}

FORM_ORDER = {
    "Submission Cover Sheet": 10,
    "VA Form 10-10172": 20,
    "Consultation & Treatment Request": 30,
    "SEOC": 40,
    "Letter of Medical Necessity": 50,
    "Virtual Consent Form": 60,
    "Clinical Notes": 70,
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


def _rewrite_unfilled_document_language(text, packet):
    rewritten = str(text or "")

    if _has_unfilled_document(packet, "consent"):
        rewritten = re.sub(
            r"Missing required document:\s*consent\b\.?",
            "Virtual Consent Form is present but unfilled",
            rewritten,
            flags=re.IGNORECASE,
        )
        rewritten = re.sub(
            r"Attach required document:\s*consent\b\.?",
            "Complete Virtual Consent Form",
            rewritten,
            flags=re.IGNORECASE,
        )
        rewritten = re.sub(
            r"Missing consent\b\.?",
            "Virtual Consent Form is present but unfilled",
            rewritten,
            flags=re.IGNORECASE,
        )
        rewritten = rewritten.replace(
            "Missing Virtual Consent Form",
            "Virtual Consent Form is present but unfilled",
        )
        rewritten = rewritten.replace(
            "Missing required document: Virtual Consent Form",
            "Virtual Consent Form is present but unfilled",
        )
        rewritten = rewritten.replace(
            "Attach required document: Virtual Consent Form",
            "Complete Virtual Consent Form",
        )
        rewritten = rewritten.replace(
            "Add Virtual Consent Form",
            "Complete Virtual Consent Form",
        )
        rewritten = rewritten.replace(
            "Missing required documents:",
            "Missing or incomplete required documents:",
        )
        rewritten = rewritten.replace(
            "Required supporting documents are missing",
            "Required supporting documents are missing or incomplete",
        )

    return rewritten


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

    fixes = _merge_unique_strings(fixes, _fix_key)

    return fixes


def _build_intel_display(packet, packet_output):
    review_summary = packet_output.get("review_summary", {})
    workflow_route = packet_output.get("workflow_route", {})
    next_action = packet_output.get("recommended_next_action", {})
    denial_risk = packet_output.get("denial_risk", {})
    true_conflict_fields = _true_conflict_fields(packet)

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

    return {
        "packet_confidence": packet_output.get("packet_confidence", getattr(packet, "packet_confidence", None)),
        "approval_probability": packet_output.get("approval_probability", getattr(packet, "approval_probability", None)),
        "packet_strength": packet_output.get("packet_strength", getattr(packet, "packet_strength", None)),
        "submission_readiness": packet_output.get("submission_readiness"),
        "workflow_queue": workflow_route.get("queue") if isinstance(workflow_route, dict) else None,
        "next_action": next_action.get("action") if isinstance(next_action, dict) else None,
        "denial_risk": denial_risk.get("level") if isinstance(denial_risk, dict) else None,
        "review_priority": getattr(packet, "review_priority", None),
        "review_flags": _unique(list(getattr(packet, "review_flags", []) or [])),
        "why_weak": _merge_unique_strings(
            why_weak,
            _issue_key,
        ),
        "missing_items": _merge_unique_strings(
            [_clean_issue(_rewrite_unfilled_document_language(item, packet)) for item in review_summary.get("missing_items", [])],
            _issue_key,
        ),
        "conflict_items": _merge_unique_strings(
            conflict_items,
            _issue_key,
        ),
        "priority_fixes": _merge_unique_strings(priority_fixes, _fix_key),
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
        confidence_entry = dict(confidence_map.get(f"page_{index}", {}) or {})
        pages.append({
            "page": index,
            "document_type": _format_document_type_name(
                confidence_entry.get("document_type")
                or getattr(packet, "document_types", {}).get(index - 1, "unknown")
            ),
            "classification_confidence": confidence_entry.get("confidence"),
            "classification_band": confidence_entry.get("confidence_band"),
            "ocr_confidence": metadata.get("ocr_confidence"),
            "scan_quality": confidence_entry.get("scan_quality_band"),
            "handwriting_risk": confidence_entry.get("handwriting_risk_level"),
            "field_zone_count": len(metadata.get("field_zones", []) or []),
            "split_segment_count": len(metadata.get("ocr_segments", []) or []),
            "table_region_count": len(layout.get("table_regions", []) or []),
            "signature_region_count": len(layout.get("signature_regions", []) or []),
            "handwritten_region_count": len(layout.get("handwritten_regions", []) or []),
        })

    return {
        "summary": {
            "ocr_provider": getattr(packet, "ocr_provider", None),
            "page_count": intake_summary.get("page_count", len(page_metadata)),
            "pages_with_ocr": intake_summary.get("pages_with_ocr"),
            "pages_with_field_zones": intake_summary.get("pages_with_field_zones"),
            "pages_with_split_segments": intake_summary.get("pages_with_split_segments"),
            "average_ocr_confidence": intake_summary.get("average_ocr_confidence"),
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
