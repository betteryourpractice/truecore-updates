from __future__ import annotations

from copy import deepcopy


AUTHORIZATION_DOCUMENT_TYPES = {"rfs", "approved_referral"}

DOCUMENT_TYPE_DISPLAY_NAMES = {
    "cover_sheet": "Submission Cover Sheet",
    "rfs": "VA Form 10-10172",
    "approved_referral": "VA Form 10-7080",
    "consult_request": "Consultation & Treatment Request",
    "seoc": "SEOC",
    "lomn": "Letter of Medical Necessity",
    "consent": "Virtual Consent Form",
    "clinical_notes": "Clinical Notes",
}

SUBMISSION_PROFILES = {
    "full_submission": {
        "label": "Full Submission",
        "required_documents": {
            "cover_sheet",
            "rfs",
            "consult_request",
            "seoc",
            "lomn",
            "consent",
            "clinical_notes",
        },
        "expected_fields": {
            "name",
            "dob",
            "authorization_number",
            "reason_for_request",
            "diagnosis",
            "icd_codes",
        },
        "supportive_fields": {
            "ordering_provider",
            "referring_provider",
            "service_date_range",
            "signature_present",
            "va_icn",
            "facility",
        },
        "expected_document_labels": [
            "Submission Cover Sheet",
            "VA Form 10-10172",
            "Consultation & Treatment Request",
            "SEOC",
            "Letter of Medical Necessity",
            "Virtual Consent Form",
            "Clinical Notes",
        ],
    },
    "authorization_request": {
        "label": "Authorization Request",
        "required_documents": {
            "consult_request",
            "clinical_notes",
            "rfs",
        },
        "expected_fields": {
            "name",
            "dob",
            "authorization_number",
            "reason_for_request",
            "icd_codes",
        },
        "supportive_fields": {
            "diagnosis",
            "procedure",
            "ordering_provider",
            "va_icn",
        },
        "expected_document_labels": [
            "Consultation & Treatment Request",
            "Clinical Notes",
            "VA Authorization / Referral (10-10172 or 10-7080)",
        ],
    },
    "clinical_minimal": {
        "label": "Clinical Minimal",
        "required_documents": {
            "clinical_notes",
        },
        "expected_fields": {
            "name",
            "dob",
            "icd_codes",
        },
        "supportive_fields": {
            "diagnosis",
            "procedure",
            "service_date_range",
        },
        "expected_document_labels": [
            "Clinical Notes",
        ],
    },
}

PACKET_ARCHETYPES = {
    "formal_full_submission": {
        "label": "Formal Full Submission",
        "description": "A purpose-built submission packet with the expected routing, authorization, and support stack.",
    },
    "authorization_submission_packet": {
        "label": "Authorization Submission Packet",
        "description": "An authorization-oriented packet with formal request paperwork but not the full submission stack.",
    },
    "referral_backed_treatment_history": {
        "label": "Referral-Backed Treatment History",
        "description": "A treatment-history packet anchored by VA referral or authorization material rather than a polished submission stack.",
    },
    "procedure_history_packet": {
        "label": "Procedure History Packet",
        "description": "A packet driven mainly by procedure notes, follow-up care, and longitudinal treatment evidence.",
    },
    "clinical_note_packet": {
        "label": "Clinical Note Packet",
        "description": "A minimal packet centered on clinical notes with limited formal submission paperwork.",
    },
    "mixed_history_packet": {
        "label": "Mixed History Packet",
        "description": "A mixed administrative and clinical packet that does not cleanly fit one formal submission family.",
    },
}


def _detected_documents(packet_or_documents):
    if isinstance(packet_or_documents, (set, list, tuple)):
        return set(packet_or_documents)
    return set(getattr(packet_or_documents, "detected_documents", set()) or set())


def _packet_links(packet):
    return dict(getattr(packet, "links", {}) or {})


def _packet_fields(packet):
    return dict(getattr(packet, "fields", {}) or {})


def _field_observations(packet, field_name):
    return list((getattr(packet, "field_observations", {}) or {}).get(field_name, []) or [])


def _section_role_counts(packet):
    counts = {}
    for roles in (getattr(packet, "section_roles", {}) or {}).values():
        for role in roles or []:
            if isinstance(role, dict):
                role = role.get("role") or role.get("name") or role.get("label")
            role = str(role or "").strip()
            if not role:
                continue
            counts[role] = counts.get(role, 0) + 1
    return counts


def _format_label(value):
    return str(value or "").replace("_", " ").strip().title()


def _document_hint_counts(packet):
    counts = {}
    for hints in (_packet_links(packet).get("document_family_hints", {}) or {}).values():
        for hint in hints or []:
            hint = str(hint or "").strip()
            if not hint:
                continue
            counts[hint] = counts.get(hint, 0) + 1
    return counts


def _semantic_recovery_scores(packet):
    scores = {}
    for recoveries in (_packet_links(packet).get("semantic_document_recoveries", {}) or {}).values():
        for recovery in recoveries or []:
            doc_type = str((recovery or {}).get("doc_type") or "").strip()
            if not doc_type:
                continue
            mode = str((recovery or {}).get("mode") or "").strip().lower()
            weight = 1.0 if mode == "primary" else 0.75
            scores[doc_type] = max(scores.get(doc_type, 0.0), weight)
    return scores


def _contextual_document_support(packet):
    detected = _detected_documents(packet)
    fields = _packet_fields(packet)
    role_counts = _section_role_counts(packet)
    hint_counts = _document_hint_counts(packet)
    recovery_scores = _semantic_recovery_scores(packet)

    support = {doc_type: 1.5 for doc_type in detected}

    for doc_type, count in hint_counts.items():
        support[doc_type] = support.get(doc_type, 0.0) + (0.45 * count)
        if count >= 2:
            support[doc_type] += 0.15

    for doc_type, score in recovery_scores.items():
        support[doc_type] = max(support.get(doc_type, 0.0), score)

    if hint_counts.get("consult_request") and (
        fields.get("ordering_provider")
        or fields.get("provider")
    ) and (
        fields.get("reason_for_request")
        or fields.get("procedure")
        or fields.get("icd_codes")
    ):
        support["consult_request"] = support.get("consult_request", 0.0) + 0.45

    if hint_counts.get("clinical_notes") and (
        role_counts.get("clinical_support", 0) >= 1
        or role_counts.get("diagnostic_basis", 0) >= 1
    ) and (
        fields.get("diagnosis")
        or fields.get("icd_codes")
        or fields.get("symptom")
    ):
        support["clinical_notes"] = support.get("clinical_notes", 0.0) + 0.45

    if hint_counts.get("lomn") and role_counts.get("justification", 0) >= 1 and (
        fields.get("diagnosis")
        or fields.get("reason_for_request")
        or fields.get("procedure")
    ):
        support["lomn"] = support.get("lomn", 0.0) + 0.4

    if hint_counts.get("cover_sheet") and fields.get("authorization_number") and fields.get("facility"):
        support["cover_sheet"] = support.get("cover_sheet", 0.0) + 0.35

    if hint_counts.get("approved_referral") and (
        fields.get("authorization_number")
        or fields.get("va_icn")
        or fields.get("referring_provider")
        or fields.get("provider")
    ):
        support["approved_referral"] = support.get("approved_referral", 0.0) + 0.45

    if hint_counts.get("rfs") and (
        fields.get("authorization_number")
        or fields.get("va_icn")
        or fields.get("ordering_provider")
    ):
        support["rfs"] = support.get("rfs", 0.0) + 0.4

    return support


def _contextual_documents(packet):
    return {
        doc_type
        for doc_type, score in _contextual_document_support(packet).items()
        if float(score or 0.0) >= 0.9
    }


def _has_multi_date_history(packet):
    observed_values = {
        str(item.get("value") or "").strip()
        for item in _field_observations(packet, "service_date_range")
        if str(item.get("value") or "").strip()
    }

    if len(observed_values) >= 2:
        return True

    field_values = list((getattr(packet, "field_values", {}) or {}).get("service_date_range", []) or [])
    normalized_values = {str(value).strip() for value in field_values if str(value).strip()}
    return len(normalized_values) >= 2


def has_equivalent_document(packet_or_documents, document_type):
    detected = _detected_documents(packet_or_documents)
    if document_type == "rfs":
        return bool(detected.intersection(AUTHORIZATION_DOCUMENT_TYPES))
    return document_type in detected


def infer_submission_profile(packet):
    detected = _contextual_documents(packet)
    full_submission_docs = set(SUBMISSION_PROFILES["full_submission"]["required_documents"])
    full_submission_hits = {
        document_type
        for document_type in full_submission_docs
        if has_equivalent_document(detected, document_type)
    }

    if not detected:
        return "clinical_minimal"

    if "clinical_notes" in detected and len(detected) <= 2 and not ((AUTHORIZATION_DOCUMENT_TYPES | {"consult_request"}) & detected):
        return "clinical_minimal"

    if len(full_submission_hits) >= 4:
        return "full_submission"

    formal_stack_markers = {"cover_sheet", "seoc", "consent", "lomn"}
    if len(full_submission_hits) >= 3 and len(formal_stack_markers & detected) >= 2:
        return "full_submission"

    if detected.intersection(AUTHORIZATION_DOCUMENT_TYPES) or "consult_request" in detected:
        return "authorization_request"

    return "full_submission"


def get_submission_profile_requirements(profile_key):
    profile = SUBMISSION_PROFILES.get(profile_key, SUBMISSION_PROFILES["full_submission"])
    return deepcopy(profile)


def get_submission_profile_label(profile_key):
    profile = SUBMISSION_PROFILES.get(profile_key, SUBMISSION_PROFILES["full_submission"])
    return profile.get("label") or _format_label(profile_key)


def get_submission_profile_expected_documents(profile_key):
    profile = SUBMISSION_PROFILES.get(profile_key, SUBMISSION_PROFILES["full_submission"])
    return list(profile.get("expected_document_labels", []) or [])


def infer_packet_archetype(packet, submission_profile=None):
    detected = _contextual_documents(packet)
    fields = _packet_fields(packet)
    role_counts = _section_role_counts(packet)
    submission_profile = submission_profile or infer_submission_profile(packet)

    full_stack_documents = {"cover_sheet", "consult_request", "seoc", "lomn", "consent"}
    full_stack_hits = len(detected.intersection(full_stack_documents))
    has_authorization = bool(detected.intersection(AUTHORIZATION_DOCUMENT_TYPES))
    has_consult_request = "consult_request" in detected
    has_clinical_notes = "clinical_notes" in detected
    has_formal_stack = full_stack_hits >= 3
    has_procedure_signal = role_counts.get("request_scope", 0) >= 2 or (
        "procedure" in fields and _has_multi_date_history(packet)
    )
    has_request_signal = (
        "reason_for_request" in fields
        or has_consult_request
        or role_counts.get("request_intent", 0) >= 1
    )
    has_history_signal = (
        _has_multi_date_history(packet)
        or role_counts.get("clinical_support", 0) >= 3
        or (role_counts.get("clinical_support", 0) >= 2 and has_authorization and not has_consult_request)
        or has_procedure_signal
    )

    signals = []
    if has_authorization:
        signals.append("VA authorization or referral material is present.")
    if has_formal_stack:
        signals.append("A formal submission document stack is present.")
    if has_consult_request:
        signals.append("A formal consult/request document is present.")
    elif "consult_request" in _document_hint_counts(packet):
        signals.append("Recovered semantic hints support a consult/request document family.")
    if has_clinical_notes and "clinical_notes" not in _detected_documents(packet):
        signals.append("Recovered semantic hints support clinical-note context.")
    if has_history_signal:
        signals.append("The packet carries longitudinal treatment-history evidence.")
    if has_procedure_signal:
        signals.append("Procedure-driven clinical content is present.")
    if submission_profile == "clinical_minimal":
        signals.append("The detected packet is clinically light on formal submission paperwork.")

    if submission_profile == "full_submission" and has_formal_stack:
        key = "formal_full_submission"
    elif submission_profile == "authorization_request" and has_authorization and has_clinical_notes and not has_consult_request:
        key = "referral_backed_treatment_history"
    elif submission_profile == "authorization_request" and (has_authorization or has_consult_request) and not has_history_signal:
        key = "authorization_submission_packet"
    elif has_procedure_signal and has_clinical_notes and not has_formal_stack:
        key = "procedure_history_packet"
    elif submission_profile == "clinical_minimal" or detected.issubset({"clinical_notes"}):
        key = "clinical_note_packet"
    elif has_history_signal:
        key = "mixed_history_packet"
    else:
        key = "authorization_submission_packet" if submission_profile == "authorization_request" else "mixed_history_packet"

    metadata = PACKET_ARCHETYPES.get(key, PACKET_ARCHETYPES["mixed_history_packet"])
    return {
        "key": key,
        "label": metadata.get("label") or _format_label(key),
        "description": metadata.get("description"),
        "signals": signals,
    }


def annotate_packet_context(packet):
    submission_profile = infer_submission_profile(packet)
    packet.packet_profile = submission_profile
    packet.packet_profile_label = get_submission_profile_label(submission_profile)

    archetype = infer_packet_archetype(packet, submission_profile=submission_profile)
    packet.packet_archetype = archetype.get("key")
    packet.packet_archetype_label = archetype.get("label")
    packet.packet_archetype_description = archetype.get("description")
    packet.packet_archetype_signals = list(archetype.get("signals", []) or [])
    return packet
