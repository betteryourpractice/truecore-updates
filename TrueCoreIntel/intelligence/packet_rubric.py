from __future__ import annotations

import re
from difflib import SequenceMatcher


DOCUMENT_LABELS = {
    "rfs": "VA Authorization / Referral",
    "approved_referral": "VA Authorization / Referral",
    "seoc": "SEOC",
    "consult_request": "Consultation & Treatment Request",
    "lomn": "Letter of Medical Necessity",
    "consent": "Virtual Consent Form",
    "clinical_notes": "Clinical Notes",
    "imaging_report": "MRI / Imaging Report",
}


PROFILE_COMPONENTS = {
    "full_submission": [
        ("rfs", 4.0),
        ("seoc", 1.0),
        ("consult_request", 2.0),
        ("lomn", 2.0),
        ("consent", 2.0),
        ("clinical_notes", 1.0),
    ],
    "authorization_request": [
        ("rfs", 4.0),
        ("consult_request", 4.0),
        ("clinical_notes", 3.0),
    ],
    "clinical_minimal": [
        ("clinical_notes", 6.0),
    ],
}


DOCUMENT_RULES = {
    "rfs": {
        "label": "VA Authorization / Referral",
        "aliases": ("rfs", "approved_referral"),
        "presence_weight": 0.35,
        "data_weight": 0.65,
        "signature_weight": 0.0,
        "data_fields": ("name", "dob", "authorization_number", "diagnosis", "icd_codes"),
        "signature_required": False,
        "blocking_if_missing": True,
        "blocking_if_unsigned": False,
    },
    "seoc": {
        "label": "SEOC",
        "aliases": ("seoc",),
        "presence_weight": 0.40,
        "data_weight": 0.60,
        "signature_weight": 0.0,
        "data_fields": ("name", "dob", "reason_for_request", "diagnosis", "icd_codes"),
        "signature_required": False,
        "blocking_if_missing": False,
        "blocking_if_unsigned": False,
    },
    "consult_request": {
        "label": "Consultation & Treatment Request",
        "aliases": ("consult_request",),
        "presence_weight": 0.35,
        "data_weight": 0.65,
        "signature_weight": 0.0,
        "data_fields": ("ordering_provider", "reason_for_request", "diagnosis", "icd_codes"),
        "signature_required": False,
        "blocking_if_missing": True,
        "blocking_if_unsigned": False,
    },
    "lomn": {
        "label": "Letter of Medical Necessity",
        "aliases": ("lomn",),
        "presence_weight": 0.30,
        "data_weight": 0.70,
        "signature_weight": 0.0,
        "data_fields": ("reason_for_request", "diagnosis", "icd_codes"),
        "signature_required": False,
        "blocking_if_missing": True,
        "blocking_if_unsigned": False,
    },
    "consent": {
        "label": "Virtual Consent Form",
        "aliases": ("consent",),
        "presence_weight": 0.35,
        "data_weight": 0.35,
        "signature_weight": 0.30,
        "data_fields": ("name", "dob"),
        "signature_required": True,
        "blocking_if_missing": True,
        "blocking_if_unsigned": True,
        "fill_sensitive": True,
    },
    "clinical_notes": {
        "label": "Clinical Notes",
        "aliases": ("clinical_notes",),
        "presence_weight": 0.45,
        "data_weight": 0.55,
        "signature_weight": 0.0,
        "data_fields": ("diagnosis", "icd_codes"),
        "signature_required": False,
        "blocking_if_missing": True,
        "blocking_if_unsigned": False,
    },
    "imaging_report": {
        "label": "MRI / Imaging Report",
        "aliases": ("imaging_report",),
        "presence_weight": 0.60,
        "data_weight": 0.40,
        "signature_weight": 0.0,
        "data_fields": (),
        "signature_required": False,
        "blocking_if_missing": False,
        "blocking_if_unsigned": False,
    },
}


CONSISTENCY_MAX_POINTS = 2.0
IDENTITY_MAX_POINTS = 0.8
ADMIN_MAX_POINTS = 0.6
CLINICAL_MAX_POINTS = 0.6

IDENTITY_FIELDS = {"name", "dob", "authorization_number", "va_icn", "claim_number"}
ADMIN_FIELDS = {"ordering_provider", "referring_provider", "provider", "facility", "clinic_name", "location"}
CLINICAL_FIELDS = {"diagnosis", "icd_codes", "reason_for_request", "procedure", "symptom"}


def build_packet_rubric(packet):
    profile = str(getattr(packet, "packet_profile", "") or "full_submission").strip().lower() or "full_submission"
    component_specs = list(PROFILE_COMPONENTS.get(profile, PROFILE_COMPONENTS["full_submission"]))
    if _should_score_imaging(packet):
        component_specs.append(("imaging_report", 2.0))

    components = []
    document_points = 0.0
    document_max = 0.0
    blockers = []
    review_needs = []
    fixes = []

    for component_key, max_points in component_specs:
        component = _score_document_component(packet, component_key, max_points)
        components.append(component)
        document_points += float(component.get("earned_points") or 0.0)
        document_max += float(component.get("max_points") or 0.0)
        blockers.extend(component.get("blockers", []))
        review_needs.extend(component.get("review_needs", []))
        fixes.extend(component.get("fixes", []))

    conflict_summary = _classify_conflicts(packet)
    consistency = _score_consistency(packet, conflict_summary)
    blockers.extend(conflict_summary.get("blocking_messages", []))
    review_needs.extend(conflict_summary.get("review_messages", []))
    fixes.extend(conflict_summary.get("fixes", []))

    total_points = document_points + float(consistency.get("earned_points") or 0.0)
    total_max = document_max + float(consistency.get("max_points") or 0.0)
    score = round((100.0 * total_points / total_max), 2) if total_max else 0.0

    blockers = _dedupe_strings(blockers)
    review_needs = _dedupe_strings(review_needs)
    fixes = _dedupe_strings(fixes)

    score_band = "strong" if score >= 85 else "moderate" if score >= 70 else "weak"
    main_blocker = blockers[0] if blockers else review_needs[0] if review_needs else None
    score_basis = "Packet score reflects document quality and cross-document consistency. Readiness is decided separately."

    if blockers:
        summary = "Packet quality is measured separately from readiness, and one or more blockers still need to be corrected."
    elif review_needs:
        summary = "The packet is substantively assembled, but reviewer follow-up is still needed before treating it as ready."
    else:
        summary = "The packet is structurally strong and does not currently show a blocking paperwork issue."

    return {
        "profile": profile,
        "document_points": round(document_points, 2),
        "document_max": round(document_max, 2),
        "consistency_points": round(float(consistency.get("earned_points") or 0.0), 2),
        "consistency_max": round(float(consistency.get("max_points") or 0.0), 2),
        "score": score,
        "score_band": score_band,
        "components": components,
        "consistency": consistency,
        "blockers": blockers,
        "review_needs": review_needs,
        "fixes": fixes,
        "main_blocker": main_blocker,
        "summary": summary,
        "score_basis": score_basis,
        "blocking_conflict_fields": list(conflict_summary.get("blocking_fields", [])),
        "review_conflict_fields": list(conflict_summary.get("review_fields", [])),
    }


def _score_document_component(packet, component_key, max_points):
    rule = dict(DOCUMENT_RULES.get(component_key, {}))
    aliases = tuple(rule.get("aliases", (component_key,)))
    label = str(rule.get("label") or DOCUMENT_LABELS.get(component_key) or component_key.replace("_", " ").title())
    present = _has_document(packet, aliases)
    unfilled = _is_unfilled(packet, aliases)
    signature_required = bool(rule.get("signature_required"))
    signature_present = _has_signature(packet, aliases)
    blockers = []
    review_needs = []
    fixes = []

    if not present:
        if rule.get("blocking_if_missing"):
            blockers.append(f"Missing required document: {label}")
            fixes.append(f"Attach required document: {label}")
        else:
            review_needs.append(f"Supporting document could not be confirmed: {label}")
            fixes.append(f"Confirm or attach supporting document: {label}")

        return {
            "key": component_key,
            "label": label,
            "earned_points": 0.0,
            "max_points": float(max_points),
            "status": "missing",
            "summary": f"{label} was not confirmed in the packet.",
            "blockers": blockers,
            "review_needs": review_needs,
            "fixes": fixes,
        }

    presence_ratio = float(rule.get("presence_weight") or 0.0)

    if component_key == "imaging_report":
        confirmed = _confirmed_imaging_report(packet, aliases)
        data_ratio = 1.0 if confirmed else 0.0
        if not confirmed:
            review_needs.append("MRI or imaging support was referenced, but a formal report was not clearly confirmed.")
            fixes.append("Attach the formal MRI or imaging report")
        summary = (
            f"{label} is present and reads like a formal report."
            if confirmed else
            f"{label} was hinted at, but the packet does not clearly show a formal imaging report."
        )
        earned_ratio = 1.0 if confirmed else 0.0
    else:
        data_ratio = 0.0 if unfilled else _field_coverage_ratio(packet, aliases, tuple(rule.get("data_fields", ())))
        earned_ratio = presence_ratio + (float(rule.get("data_weight") or 0.0) * data_ratio)
        summary_parts = [f"{label} is present."]

        if rule.get("fill_sensitive") and unfilled:
            blockers.append(f"{label} appears present but unfilled.")
            fixes.append(f"Complete {label}")
            summary_parts.append("It appears unfilled.")
        elif data_ratio >= 0.9:
            summary_parts.append("The key packet data looks complete.")
        elif data_ratio >= 0.45:
            review_needs.append(f"{label} is present but only partially complete.")
            fixes.append(f"Review and complete {label}")
            summary_parts.append("It looks only partially complete.")
        else:
            review_needs.append(f"{label} is present but weakly populated.")
            fixes.append(f"Strengthen the packet data on {label}")
            summary_parts.append("Its packet data is thin.")

        if signature_required:
            if signature_present:
                earned_ratio += float(rule.get("signature_weight") or 0.0)
                summary_parts.append("A document-level signature was detected.")
            else:
                missing_signature_text = f"{label} does not show a confirmed document-level signature."
                if rule.get("blocking_if_unsigned"):
                    blockers.append(missing_signature_text)
                else:
                    review_needs.append(missing_signature_text)
                fixes.append(f"Add a confirmed signature to {label}")
                summary_parts.append("A document-level signature was not clearly detected.")

        summary = " ".join(summary_parts)

    earned_points = round(float(max_points) * max(0.0, min(earned_ratio, 1.0)), 2)
    status = "strong" if earned_points >= (float(max_points) * 0.8) else "moderate" if earned_points >= (float(max_points) * 0.45) else "weak"

    return {
        "key": component_key,
        "label": label,
        "earned_points": earned_points,
        "max_points": float(max_points),
        "status": status,
        "summary": summary,
        "blockers": blockers,
        "review_needs": review_needs,
        "fixes": fixes,
    }


def _score_consistency(packet, conflict_summary):
    review_flags = {str(flag or "").strip().lower() for flag in (getattr(packet, "review_flags", []) or [])}

    identity_points = IDENTITY_MAX_POINTS
    if conflict_summary.get("blocking_identity_conflict"):
        identity_points = 0.0
    elif conflict_summary.get("benign_identity_conflict"):
        identity_points = 0.55

    admin_points = ADMIN_MAX_POINTS
    admin_points -= min(0.25, 0.10 * int(conflict_summary.get("admin_low_conflicts", 0)))
    admin_points -= min(0.25, 0.20 * int(conflict_summary.get("admin_medium_conflicts", 0)))
    if conflict_summary.get("admin_high_conflict"):
        admin_points = min(admin_points, 0.20)
    admin_points = max(0.20 if conflict_summary.get("admin_low_conflicts") else 0.0, admin_points) if conflict_summary.get("admin_any_conflict") else admin_points

    clinical_points = CLINICAL_MAX_POINTS
    if "diagnosis_icd_mismatch" in review_flags:
        clinical_points -= 0.30
    elif "partial_diagnosis_icd_alignment" in review_flags:
        clinical_points -= 0.15

    clinical_points -= min(0.15, 0.08 * int(conflict_summary.get("clinical_low_conflicts", 0)))
    clinical_points -= min(0.20, 0.12 * int(conflict_summary.get("clinical_medium_conflicts", 0)))
    if conflict_summary.get("clinical_high_conflict"):
        clinical_points = min(clinical_points, 0.15)

    identity_points = max(0.0, round(identity_points, 2))
    admin_points = max(0.0, round(admin_points, 2))
    clinical_points = max(0.0, round(clinical_points, 2))
    earned_points = round(identity_points + admin_points + clinical_points, 2)

    summary = "Cross-document consistency is holding up well."
    if earned_points < 1.1:
        summary = "Cross-document consistency needs careful review before treating the packet as ready."
    elif earned_points < 1.6:
        summary = "Most packet data lines up, but a few cross-document mismatches still need review."

    return {
        "label": "Cross-document consistency",
        "earned_points": earned_points,
        "max_points": CONSISTENCY_MAX_POINTS,
        "status": "strong" if earned_points >= 1.6 else "moderate" if earned_points >= 1.0 else "weak",
        "summary": summary,
        "families": {
            "identity": identity_points,
            "admin": admin_points,
            "clinical": clinical_points,
        },
    }


def _classify_conflicts(packet):
    conflicts = list(getattr(packet, "conflicts", []) or [])
    tolerated_conflicts = list((getattr(packet, "semantic_adjudication", {}) or {}).get("tolerated_conflicts", []) or [])
    tolerated_fields = {
        str(item.get("field") or "").strip().lower()
        for item in tolerated_conflicts
        if item.get("field")
    }
    summary = {
        "blocking_fields": [],
        "review_fields": [],
        "blocking_messages": [],
        "review_messages": [],
        "fixes": [],
        "blocking_identity_conflict": False,
        "benign_identity_conflict": False,
        "admin_low_conflicts": 0,
        "admin_medium_conflicts": 0,
        "admin_high_conflict": False,
        "admin_any_conflict": False,
        "clinical_low_conflicts": 0,
        "clinical_medium_conflicts": 0,
        "clinical_high_conflict": False,
    }

    for conflict in conflicts:
        field_name = str(conflict.get("field") or "").strip().lower()
        severity = str(conflict.get("severity") or "low").strip().lower()
        values = list(conflict.get("values") or [])

        if field_name in tolerated_fields and severity in {"low", "medium"}:
            continue

        if field_name == "name" and _is_benign_name_conflict(values, packet):
            summary["benign_identity_conflict"] = True
            summary["review_fields"].append("name")
            summary["review_messages"].append(
                "Patient name has a small OCR-style variation that should be confirmed before submission."
            )
            summary["fixes"].append("Confirm the patient name against the clearest packet page")
            continue

        if field_name in IDENTITY_FIELDS and severity == "high":
            summary["blocking_fields"].append(field_name)
            summary["blocking_messages"].append(
                f"Resolve conflicting {field_name.replace('_', ' ')} values before submission."
            )
            summary["fixes"].append(
                f"Resolve conflicting values for {field_name.replace('_', ' ')}"
            )
            if field_name == "name":
                summary["blocking_identity_conflict"] = True
            continue

        if field_name in ADMIN_FIELDS:
            summary["admin_any_conflict"] = True
            summary["review_fields"].append(field_name)
            summary["review_messages"].append(
                f"Reviewer should confirm the packet's {field_name.replace('_', ' ')} details."
            )
            summary["fixes"].append(
                f"Confirm the packet's {field_name.replace('_', ' ')} details"
            )
            if severity == "high":
                summary["admin_high_conflict"] = True
            elif severity == "medium":
                summary["admin_medium_conflicts"] += 1
            else:
                summary["admin_low_conflicts"] += 1
            continue

        if field_name in CLINICAL_FIELDS:
            summary["review_fields"].append(field_name)
            summary["review_messages"].append(
                f"Reviewer should confirm the packet's {field_name.replace('_', ' ')} alignment."
            )
            summary["fixes"].append(
                f"Confirm the packet's {field_name.replace('_', ' ')} alignment"
            )
            if severity == "high":
                summary["clinical_high_conflict"] = True
            elif severity == "medium":
                summary["clinical_medium_conflicts"] += 1
            else:
                summary["clinical_low_conflicts"] += 1

    summary["blocking_fields"] = sorted(set(summary["blocking_fields"]))
    summary["review_fields"] = sorted(set(summary["review_fields"]))
    summary["blocking_messages"] = _dedupe_strings(summary["blocking_messages"])
    summary["review_messages"] = _dedupe_strings(summary["review_messages"])
    summary["fixes"] = _dedupe_strings(summary["fixes"])
    return summary


def _field_coverage_ratio(packet, aliases, field_names):
    if not field_names:
        return 1.0

    document_ratio = _document_completeness_ratio(packet, aliases)
    if document_ratio is not None:
        return document_ratio

    score = 0.0
    for field_name in field_names:
        if _has_field_observation(packet, field_name, aliases):
            score += 1.0
        elif getattr(packet, "fields", {}).get(field_name) not in (None, "", []):
            score += 0.55
    return round(score / max(len(field_names), 1), 2)


def _document_completeness_ratio(packet, aliases):
    documents = (
        getattr(packet, "validation_intelligence", {}) or {}
    ).get("field_to_form_consistency_checks", {}).get("documents", [])
    alias_set = {str(alias or "").strip().lower() for alias in aliases}

    for document in documents:
        document_type = str(document.get("document_type") or "").strip().lower()
        if document_type not in alias_set:
            continue
        try:
            return float(document.get("completeness_ratio"))
        except Exception:
            return None
    return None


def _has_field_observation(packet, field_name, aliases):
    observations = list((getattr(packet, "field_observations", {}) or {}).get(field_name, []) or [])
    alias_set = set(aliases)
    for observation in observations:
        if str(observation.get("document_type") or "").strip().lower() in alias_set:
            return True
    return False


def _has_signature(packet, aliases):
    observations = list((getattr(packet, "field_observations", {}) or {}).get("signature_present", []) or [])
    alias_set = set(aliases)
    for observation in observations:
        if not observation.get("value"):
            continue
        if str(observation.get("document_type") or "").strip().lower() in alias_set:
            return True
    return False


def _has_document(packet, aliases):
    detected = {str(item or "").strip().lower() for item in (getattr(packet, "detected_documents", set()) or set())}
    alias_set = set(aliases)
    return bool(detected.intersection(alias_set))


def _is_unfilled(packet, aliases):
    unfilled = {str(item or "").strip().lower() for item in (getattr(packet, "unfilled_documents", set()) or set())}
    return bool(unfilled.intersection(set(aliases)))


def _component_page_texts(packet, aliases):
    texts = []
    alias_set = set(aliases)
    page_types = dict(getattr(packet, "document_types", {}) or {})
    pages = list(getattr(packet, "pages", []) or [])
    for page_index, document_type in page_types.items():
        if str(document_type or "").strip().lower() not in alias_set:
            continue
        try:
            texts.append(str(pages[int(page_index)] or ""))
        except Exception:
            continue
    return texts


def _confirmed_imaging_report(packet, aliases):
    page_texts = _component_page_texts(packet, aliases)
    if not page_texts:
        return False

    modality_terms = ("mri", "imaging", "radiology", "ct", "x-ray", "xr")
    report_terms = ("impression", "findings", "technique", "exam", "study", "comparison", "radiologist")

    for page_text in page_texts:
        lower_text = str(page_text or "").lower()
        modality_hit = any(term in lower_text for term in modality_terms)
        report_hit = any(term in lower_text for term in report_terms)
        if modality_hit and report_hit:
            return True

    return False


def _should_score_imaging(packet):
    if _has_document(packet, ("imaging_report",)):
        return True

    page_texts = _component_page_texts(packet, ("cover_sheet",))
    for page_text in page_texts:
        lower_text = str(page_text or "").lower()
        if "documents included" in lower_text and (
            "mri report" in lower_text or "imaging report" in lower_text or ("mri" in lower_text and "included" in lower_text)
        ):
            return True

    request_text = " ".join(
        str(value or "")
        for value in (
            getattr(packet, "fields", {}).get("reason_for_request"),
            getattr(packet, "fields", {}).get("procedure"),
        )
    ).lower()
    return "mri" in request_text or "imaging" in request_text


def _normalize_name(value):
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9 ]", "", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def _is_benign_name_conflict(values, packet):
    normalized = [_normalize_name(item) for item in values if _normalize_name(item)]
    unique_values = sorted(set(normalized))
    if len(unique_values) != 2:
        return False

    similarity = SequenceMatcher(None, unique_values[0], unique_values[1]).ratio()
    has_identity_anchors = bool(
        getattr(packet, "fields", {}).get("dob")
        and (
            getattr(packet, "fields", {}).get("authorization_number")
            or getattr(packet, "fields", {}).get("va_icn")
            or getattr(packet, "fields", {}).get("claim_number")
        )
    )
    return similarity >= 0.82 and has_identity_anchors


def _dedupe_strings(items):
    seen = set()
    deduped = []
    for item in items:
        text = str(item or "").strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped
