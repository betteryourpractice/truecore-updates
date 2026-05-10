from __future__ import annotations

import re


DOCUMENT_ORDER_PRIORITY = {
    "cover_sheet": 10,
    "rfs": 20,
    "approved_referral": 25,
    "consult_request": 30,
    "seoc": 40,
    "lomn": 50,
    "consent": 60,
    "clinical_notes": 70,
    "imaging_report": 80,
    "conservative_care_summary": 85,
    "unknown": 999,
}


def _field_value(packet, field_name):
    value = dict(getattr(packet, "fields", {}) or {}).get(field_name)
    return value not in (None, "", [])


def _has_document(packet, document_type):
    return document_type in set(getattr(packet, "detected_documents", set()) or set())


def _field_observations(packet, field_name):
    return list((getattr(packet, "field_observations", {}) or {}).get(field_name, []) or [])


def _section_role_names(packet):
    names = []
    for roles in (getattr(packet, "section_roles", {}) or {}).values():
        for role in roles or []:
            if isinstance(role, dict):
                role = role.get("role") or role.get("name") or role.get("label")
            role = str(role or "").strip()
            if role:
                names.append(role)
    return names


def _unique_date_mentions(packet):
    observed = {
        str(item.get("value") or "").strip()
        for item in _field_observations(packet, "service_date_range")
        if str(item.get("value") or "").strip()
    }
    if observed:
        return observed

    date_pattern = re.compile(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b")
    dates = set()
    for page_text in list(getattr(packet, "pages", []) or [])[:24]:
        dates.update(match.group(0) for match in date_pattern.finditer(str(page_text or "")))
        if len(dates) >= 6:
            break
    return dates


def _page_document_sequence(packet):
    first_seen = {}
    for page_index, document_type in sorted((getattr(packet, "document_types", {}) or {}).items()):
        normalized = str(document_type or "unknown").strip() or "unknown"
        if normalized not in first_seen:
            first_seen[normalized] = int(page_index)
    return [
        document_type
        for document_type, _page_index in sorted(first_seen.items(), key=lambda item: item[1])
        if document_type != "unknown"
    ]


def _status_score(status):
    return {
        "present": 1.0,
        "partial": 0.55,
        "missing": 0.0,
    }.get(status, 0.0)


def _score_band(score):
    score = float(score or 0.0)
    if score >= 85:
        return "strong"
    if score >= 60:
        return "moderate"
    return "weak"


def _classify_level(score):
    if score >= 2.6:
        return "high"
    if score >= 1.6:
        return "moderate"
    return "low"


def build_packet_invariants(packet):
    role_names = set(_section_role_names(packet))
    invariants = {}

    has_identity = _field_value(packet, "name") and (
        _field_value(packet, "dob") or _field_value(packet, "va_icn") or _field_value(packet, "claim_number")
    )
    partial_identity = _field_value(packet, "name") or _field_value(packet, "dob") or _field_value(packet, "va_icn")
    invariants["patient_identity"] = {
        "label": "Patient Identity",
        "status": "present" if has_identity else "partial" if partial_identity else "missing",
        "summary": (
            "Patient identity is anchored by core identifiers."
            if has_identity else
            "Some identity signals are present, but the anchor is incomplete."
            if partial_identity else
            "Patient identity anchor is missing."
        ),
    }

    has_admin = (
        _field_value(packet, "authorization_number")
        or _has_document(packet, "rfs")
        or _has_document(packet, "approved_referral")
    ) and (
        _field_value(packet, "facility") or _field_value(packet, "va_icn") or _field_value(packet, "referring_provider")
    )
    partial_admin = (
        _field_value(packet, "authorization_number")
        or _has_document(packet, "approved_referral")
        or _has_document(packet, "rfs")
        or _field_value(packet, "facility")
        or _field_value(packet, "va_icn")
    )
    invariants["routing_admin"] = {
        "label": "Routing / Admin Context",
        "status": "present" if has_admin else "partial" if partial_admin else "missing",
        "summary": (
            "VA routing and authorization context is clearly present."
            if has_admin else
            "Some routing or authorization context is present, but it is incomplete."
            if partial_admin else
            "Routing and authorization context is not clearly anchored."
        ),
    }

    has_request = (
        _field_value(packet, "reason_for_request")
        or _has_document(packet, "consult_request")
        or _has_document(packet, "seoc")
        or "request_intent" in role_names
    )
    partial_request = has_request or _field_value(packet, "procedure") or _has_document(packet, "lomn")
    invariants["request_intent"] = {
        "label": "Request Intent",
        "status": "present" if has_request else "partial" if partial_request else "missing",
        "summary": (
            "The packet communicates what is being requested."
            if has_request else
            "There are hints of request intent, but not a clean request anchor."
            if partial_request else
            "Request intent is not clearly stated."
        ),
    }

    has_clinical = (
        _has_document(packet, "clinical_notes")
        or _has_document(packet, "lomn")
        or _has_document(packet, "imaging_report")
        or (_field_value(packet, "diagnosis") and _field_value(packet, "icd_codes"))
    )
    partial_clinical = has_clinical or _field_value(packet, "diagnosis") or _field_value(packet, "icd_codes")
    invariants["clinical_support"] = {
        "label": "Clinical Support",
        "status": "present" if has_clinical else "partial" if partial_clinical else "missing",
        "summary": (
            "Clinical support is present in the packet."
            if has_clinical else
            "Some clinical support is present, but it is thin or fragmented."
            if partial_clinical else
            "Clinical support is not clearly anchored."
        ),
    }

    provider_field_count = sum(
        1
        for field_name in ("ordering_provider", "referring_provider", "provider", "treating_provider", "followup_provider")
        if _field_value(packet, field_name)
    )
    provider_obs = set()
    for field_name in ("ordering_provider", "referring_provider", "provider", "treating_provider", "followup_provider"):
        for item in _field_observations(packet, field_name):
            provider_obs.add(str(item.get("document_type") or "").strip() or "unknown")
    has_provider_context = provider_field_count >= 2 or len(provider_obs) >= 2
    partial_provider_context = provider_field_count >= 1 or len(provider_obs) >= 1
    invariants["provider_context"] = {
        "label": "Provider Context",
        "status": "present" if has_provider_context else "partial" if partial_provider_context else "missing",
        "summary": (
            "Provider roles are meaningfully represented."
            if has_provider_context else
            "Some provider context is present, but role separation is limited."
            if partial_provider_context else
            "Provider context is not clearly represented."
        ),
    }

    date_mentions = _unique_date_mentions(packet)
    has_timeline = _field_value(packet, "service_date_range") or len(date_mentions) >= 2
    partial_timeline = has_timeline or len(date_mentions) >= 1 or len(getattr(packet, "document_spans", []) or []) >= 2
    invariants["timeline_context"] = {
        "label": "Timeline Context",
        "status": "present" if has_timeline else "partial" if partial_timeline else "missing",
        "summary": (
            "The packet contains usable treatment or service chronology."
            if has_timeline else
            "Some chronology is present, but the timeline anchor is incomplete."
            if partial_timeline else
            "Timeline context is not clearly anchored."
        ),
    }

    coverage_score = round(
        100.0 * (
            sum(_status_score(item["status"]) for item in invariants.values()) / max(len(invariants), 1)
        ),
        2,
    )

    return {
        "coverage_score": coverage_score,
        "coverage_band": _score_band(coverage_score),
        "items": invariants,
    }


def build_packet_variability(packet):
    sequence = _page_document_sequence(packet)
    priorities = [DOCUMENT_ORDER_PRIORITY.get(document_type, 999) for document_type in sequence]
    inversions = 0
    comparisons = 0
    for index, left in enumerate(priorities):
        for right in priorities[index + 1:]:
            comparisons += 1
            if left > right:
                inversions += 1
    order_ratio = (inversions / comparisons) if comparisons else 0.0
    order_level = "high" if order_ratio >= 0.34 else "moderate" if order_ratio >= 0.12 else "low"

    provider_surface = sum(
        1
        for field_name in ("ordering_provider", "referring_provider", "provider")
        if _field_value(packet, field_name)
    )
    provider_observation_count = sum(
        len(_field_observations(packet, field_name))
        for field_name in ("ordering_provider", "referring_provider", "provider")
    )
    provider_complexity_score = 1.0
    if provider_surface >= 3:
        provider_complexity_score += 1.2
    elif provider_surface >= 2:
        provider_complexity_score += 0.7
    if provider_observation_count >= 5:
        provider_complexity_score += 1.0
    elif provider_observation_count >= 2:
        provider_complexity_score += 0.5
    provider_level = _classify_level(provider_complexity_score)

    date_mentions = _unique_date_mentions(packet)
    timeline_complexity_score = 1.0
    if len(date_mentions) >= 5:
        timeline_complexity_score += 1.8
    elif len(date_mentions) >= 3:
        timeline_complexity_score += 1.0
    elif len(date_mentions) >= 1:
        timeline_complexity_score += 0.4
    if _field_value(packet, "procedure"):
        timeline_complexity_score += 0.5
    if str(getattr(packet, "packet_archetype", "")).strip() in {"referral_backed_treatment_history", "procedure_history_packet", "mixed_history_packet"}:
        timeline_complexity_score += 0.5
    timeline_level = _classify_level(timeline_complexity_score)

    diagnostics = dict(getattr(packet, "intake_diagnostics", {}) or {})
    scan_complexity_score = 1.0
    if diagnostics.get("used_ocr_fallback") or diagnostics.get("fallback_used") or diagnostics.get("ocr_retry_reasons"):
        scan_complexity_score += 1.2
    discovery_pages = diagnostics.get("discovery_ocr_pages") or diagnostics.get("ocr_pages") or 0
    try:
        discovery_pages = int(discovery_pages)
    except Exception:
        discovery_pages = 0
    if discovery_pages >= 8:
        scan_complexity_score += 0.8
    elif discovery_pages >= 3:
        scan_complexity_score += 0.4
    scan_level = _classify_level(scan_complexity_score)

    archetype = str(getattr(packet, "packet_archetype", "")).strip()
    base_variability_score = 1.0
    if archetype in {"formal_full_submission", "authorization_submission_packet"}:
        base_variability_score = 1.2
    elif archetype in {"clinical_note_packet"}:
        base_variability_score = 1.6
    elif archetype in {"referral_backed_treatment_history", "procedure_history_packet"}:
        base_variability_score = 2.4
    elif archetype in {"mixed_history_packet"}:
        base_variability_score = 2.8

    levels = {
        "document_order": order_level,
        "provider_roles": provider_level,
        "timeline_depth": timeline_level,
        "scan_path": scan_level,
    }
    level_values = {"low": 1.0, "moderate": 2.0, "high": 3.0}
    overall_score = base_variability_score + (
        sum(level_values[level] for level in levels.values()) / max(len(levels), 1) - 1.0
    )
    overall_level = _classify_level(overall_score)

    reasons = []
    if archetype in {"referral_backed_treatment_history", "procedure_history_packet", "mixed_history_packet"}:
        reasons.append("Packet style is driven by treatment history rather than a clean front-stacked submission set.")
    if timeline_level == "high":
        reasons.append("The packet spans multiple dated encounters or treatment events.")
    if provider_level == "high":
        reasons.append("Multiple provider roles or provider contexts are present.")
    if order_level == "high":
        reasons.append("Document order departs noticeably from a canonical submission flow.")
    if scan_level == "high":
        reasons.append("The packet required heavier OCR or fallback intake handling.")

    return {
        "overall_level": overall_level,
        "dimensions": levels,
        "reasons": reasons,
    }


def annotate_packet_robustness(packet):
    invariants = build_packet_invariants(packet)
    variability = build_packet_variability(packet)

    packet.packet_invariants = invariants
    packet.packet_invariant_coverage_score = invariants.get("coverage_score")
    packet.packet_invariant_coverage_band = invariants.get("coverage_band")
    packet.packet_variability = variability
    packet.packet_format_variability = variability.get("overall_level")
    packet.packet_variability_reasons = list(variability.get("reasons", []) or [])
    return packet
