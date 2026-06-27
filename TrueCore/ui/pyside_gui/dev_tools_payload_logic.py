from __future__ import annotations

import re
import unicodedata

from TrueCore.ui.pyside_gui.dev_tools_profiles import (
    PACKET_BUILDER_PROFILES,
    default_title_for_profile,
    is_clinical_documentation_profile,
    is_consult_request_profile,
    is_lomn_profile,
    is_referral_request_profile,
    is_seoc_request_profile,
    is_submission_cover_profile,
    is_va_10172_profile,
    is_virtual_consent_profile,
)


SHARED_PACKET_HEADER_FIELDS = [
    ("patient_name", "Veteran Name"),
    ("date_of_birth", "Date of Birth"),
    ("authorization_number", "VA Authorization"),
    ("va_icn", "VA ICN"),
    ("ordering_doctor", "VA Referring / Ordering Provider"),
    ("facility", "VA Referring Facility"),
    ("diagnosis", "Primary Diagnosis"),
    ("icd_codes", "ICD-10 Codes"),
    ("master_provider_npi", "Community Care Treating Provider NPI"),
    ("master_practice_name", "Community Care Practice Name"),
]


LEGACY_PACKET_TEXT_REPLACEMENTS = {
    "clinical_doc_treatment_plan_intro": {
        "The patient is an appropriate candidate for TrueDisc intradiscal biologic repair under a Single Episode of Care (SEOC) model.": (
            "The patient is an appropriate candidate for focused spine evaluation and consideration of the requested intervention if confirmed clinically appropriate."
        ),
    },
}


TEXT_ARTIFACT_REPLACEMENTS = {
    "Ã¢â‚¬â„¢": "'",
    "Ã¢â‚¬Å“": '"',
    "Ã¢â‚¬\x9d": '"',
    "Ã¢â‚¬â€œ": "-",
    "Ã¢â‚¬â€": "-",
    "Ã¢â‚¬Â¦": "...",
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2013": "-",
    "\u2014": "-",
    "\u2022": "-",
    "\u2611": "[X]",
    "\u2610": "[ ]",
    "\ufb00": "ff",
    "\ufb01": "fi",
    "\ufb02": "fl",
    "\ufb03": "ffi",
    "\ufb04": "ffl",
}


def build_profile_export_payload(base_payload, profile_name, *, normalize_packet_builder_payload_fn, apply_packet_builder_shared_field_sync_fn):
    payload = normalize_packet_builder_payload_fn(base_payload)
    normalized_profile = str(profile_name or "").strip()
    payload["packet_profile"] = normalized_profile
    payload["packet_title"] = default_title_for_profile(normalized_profile) or normalized_profile or payload.get("packet_title") or ""
    if is_virtual_consent_profile(normalized_profile):
        payload["consent_form_title"] = payload.get("consent_form_title") or default_title_for_profile(normalized_profile)
    elif is_submission_cover_profile(normalized_profile):
        payload["submission_cover_title"] = payload.get("submission_cover_title") or default_title_for_profile(normalized_profile)
    elif is_clinical_documentation_profile(normalized_profile):
        payload["clinical_doc_title"] = payload.get("clinical_doc_title") or default_title_for_profile(normalized_profile)
    return apply_packet_builder_shared_field_sync_fn(payload)


def _has_meaningful_value(value):
    if isinstance(value, bool):
        return bool(value)
    return bool(str(value or "").strip())


def _any_present(packet, field_names):
    return any(_has_meaningful_value(packet.get(field_name)) for field_name in field_names or [])


def _any_checked(packet, field_names):
    return any(bool(packet.get(field_name)) for field_name in field_names or [])


def _first_icd_code(value):
    raw = str(value or "").strip()
    if not raw:
        return ""
    return raw.split(",")[0].strip()


def _normalized_compare_value(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def _last_four_digits(value):
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    return digits[-4:] if len(digits) >= 4 else digits


def _values_conflict(left_value, right_value, mode="text", allow_contains=False):
    left_raw = str(left_value or "").strip()
    right_raw = str(right_value or "").strip()
    if not left_raw or not right_raw:
        return False
    if mode == "icd_first":
        left_raw = _first_icd_code(left_raw)
        right_raw = _first_icd_code(right_raw)
    elif mode == "last_four":
        left_raw = _last_four_digits(left_raw)
        right_raw = _last_four_digits(right_raw)
    left_norm = _normalized_compare_value(left_raw)
    right_norm = _normalized_compare_value(right_raw)
    if not left_norm or not right_norm:
        return False
    if allow_contains and (left_norm in right_norm or right_norm in left_norm):
        return False
    return left_norm != right_norm


def build_profile_current_form_checks(profile_name, packet):
    if is_referral_request_profile(profile_name):
        return [
            ("Packet Title", _has_meaningful_value(packet.get("packet_title"))),
            ("Subtitle", _has_meaningful_value(packet.get("referral_subtitle"))),
            ("PCP Request Wording", _has_meaningful_value(packet.get("pcp_request_text"))),
            ("Referral Entry Wording", _has_meaningful_value(packet.get("referral_entry_text"))),
            ("Areas of Concern", _has_meaningful_value(packet.get("areas_of_concern"))),
            ("Group NPI", _has_meaningful_value(packet.get("group_npi"))),
            ("Fax Number", _has_meaningful_value(packet.get("fax_number"))),
            ("Liaison Contact", _has_meaningful_value(packet.get("liaison_contact_info"))),
        ]
    if is_submission_cover_profile(profile_name):
        return [
            ("Packet Title", _has_meaningful_value(packet.get("packet_title"))),
            ("Submission Date", _has_meaningful_value(packet.get("submission_date"))),
            ("Primary Diagnosis Code", _has_meaningful_value(packet.get("primary_diagnosis_code"))),
            ("Submitting Office", _has_meaningful_value(packet.get("submitting_office"))),
            ("Office Staff Name", _has_meaningful_value(packet.get("office_staff_name"))),
            (
                "Program User / Office Staff Signature",
                _has_meaningful_value(packet.get("office_staff_signature"))
                or _has_meaningful_value(packet.get("office_staff_signature_image")),
            ),
            ("Date Reviewed", _has_meaningful_value(packet.get("date_reviewed"))),
            (
                "Document Checklist",
                _any_checked(
                    packet,
                    [
                        "included_virtual_consent_form",
                        "included_va_form_10_10172",
                        "included_seoc_request",
                        "included_consult_request",
                        "included_lomn",
                        "included_clinical_notes",
                        "included_mri_report",
                    ],
                ),
            ),
        ]
    if is_virtual_consent_profile(profile_name):
        return [
            ("Packet Title", _has_meaningful_value(packet.get("packet_title"))),
            ("Street Address", _has_meaningful_value(packet.get("street_address"))),
            ("City", _has_meaningful_value(packet.get("city"))),
            ("State", _has_meaningful_value(packet.get("state"))),
            ("ZIP Code", _has_meaningful_value(packet.get("zip_code"))),
            ("Phone", _any_present(packet, ["mobile_phone", "home_phone", "work_phone"])),
            ("Email Address", _has_meaningful_value(packet.get("email_address"))),
            ("SSN", _has_meaningful_value(packet.get("ssn"))),
            ("Driver License", _has_meaningful_value(packet.get("drivers_license"))),
            ("Driver License State", _has_meaningful_value(packet.get("drivers_license_state"))),
            ("Emergency Contact Name", _has_meaningful_value(packet.get("emergency_contact_name"))),
            ("Emergency Contact Relationship", _has_meaningful_value(packet.get("emergency_contact_relationship"))),
            ("Emergency Contact Phone", _has_meaningful_value(packet.get("emergency_contact_phone"))),
            ("PCP / PCM Name", _has_meaningful_value(packet.get("pcp_pcm_name"))),
            ("PCP / PCM Phone", _has_meaningful_value(packet.get("pcp_pcm_phone"))),
            ("PCP / PCM Fax", _has_meaningful_value(packet.get("pcp_pcm_fax"))),
            ("Consent Provider Name", _has_meaningful_value(packet.get("consent_provider_name"))),
            ("Consent Initials", _has_meaningful_value(packet.get("consent_initials"))),
            ("Service Authorization Name", _has_meaningful_value(packet.get("service_authorization_name"))),
            (
                "Veteran / Patient Signature",
                _has_meaningful_value(packet.get("patient_signature_name"))
                or _has_meaningful_value(packet.get("patient_signature_image")),
            ),
            ("Patient Signature Date", _has_meaningful_value(packet.get("patient_signature_date"))),
        ]
    if is_va_10172_profile(profile_name):
        return [
            ("VA Facility Address", _has_meaningful_value(packet.get("va10172_va_facility_address"))),
            ("Provider Office Address", _has_meaningful_value(packet.get("va10172_ordering_provider_office_address"))),
            ("Provider Phone", _has_meaningful_value(packet.get("va10172_ordering_provider_phone"))),
            ("Provider Fax", _has_meaningful_value(packet.get("va10172_ordering_provider_fax"))),
            ("Provider Secure Email", _has_meaningful_value(packet.get("va10172_ordering_provider_secure_email"))),
            ("Specialty Text", _has_meaningful_value(packet.get("va10172_referral_specialty_text"))),
            ("Diagnosis Description", _has_meaningful_value(packet.get("va10172_diagnosis_description"))),
            ("Requested CPT / HCPCS", _has_meaningful_value(packet.get("va10172_requested_cpt_hcpcs_code"))),
            ("Requested Service Description", _has_meaningful_value(packet.get("va10172_description_cpt_hcpcs_code"))),
            ("Reason For Request", _has_meaningful_value(packet.get("va10172_reason_for_request"))),
            ("Printed CCN Ordering Provider Name", _has_meaningful_value(packet.get("va10172_ordering_provider_name_printed"))),
            ("CCN Ordering Provider NPI", _has_meaningful_value(packet.get("va10172_ordering_provider_npi"))),
            (
                "CCN Ordering Provider Signature",
                _has_meaningful_value(packet.get("va10172_signature_text"))
                or _has_meaningful_value(packet.get("va10172_signature_image")),
            ),
            ("Today's Date", _has_meaningful_value(packet.get("va10172_today_date"))),
        ]
    if is_seoc_request_profile(profile_name):
        return [
            ("Request Date", _has_meaningful_value(packet.get("seoc_request_date"))),
            ("VA Medical Center", _has_meaningful_value(packet.get("va_medical_center_name"))),
            ("Last Four SSN", _has_meaningful_value(packet.get("last_four_ssn"))),
            ("Episode Diagnosis", _has_meaningful_value(packet.get("episode_diagnosis"))),
            ("Episode ICD Code", _has_meaningful_value(packet.get("episode_icd_code"))),
            ("Scope Language", _has_meaningful_value(packet.get("seoc_scope_text"))),
            ("Estimated Duration", _has_meaningful_value(packet.get("estimated_duration_text"))),
            ("Clinical Objectives", _has_meaningful_value(packet.get("clinical_objectives"))),
            ("Continuity of Care", _has_meaningful_value(packet.get("seoc_continuity_text"))),
            ("Community Care Provider Credentials", _has_meaningful_value(packet.get("provider_credentials"))),
            ("Community Care Provider Specialty", _has_meaningful_value(packet.get("provider_specialty"))),
            ("Community Care Provider NPI", _has_meaningful_value(packet.get("provider_npi"))),
            ("Community Care Practice Name", _has_meaningful_value(packet.get("practice_name"))),
            ("Community Care Practice Phone", _has_meaningful_value(packet.get("provider_phone"))),
            ("Community Care Practice Fax", _has_meaningful_value(packet.get("provider_fax"))),
            (
                "Scope Items",
                _any_checked(
                    packet,
                    [
                        "seoc_include_preprocedure_eval",
                        "seoc_include_annulargram",
                        "seoc_include_fibrin_injection",
                        "seoc_include_follow_up",
                    ],
                ),
            ),
        ]
    if is_consult_request_profile(profile_name):
        return [
            ("Request Date", _has_meaningful_value(packet.get("consult_request_date"))),
            ("VA Claim Number", _has_meaningful_value(packet.get("consult_va_claim_number"))),
            ("Referring VA Provider", _has_meaningful_value(packet.get("consult_referring_va_provider"))),
            ("Reason For Consultation", _has_meaningful_value(packet.get("consult_reason_text"))),
            ("Primary Diagnosis", _has_meaningful_value(packet.get("consult_primary_diagnosis"))),
            ("Secondary Diagnosis", _has_meaningful_value(packet.get("consult_secondary_diagnosis"))),
            ("MRI Date", _has_meaningful_value(packet.get("consult_mri_date"))),
            ("MRI Findings", _has_meaningful_value(packet.get("consult_mri_findings"))),
            ("Conservative Duration", _has_meaningful_value(packet.get("consult_conservative_duration"))),
            ("Scope Statement", _has_meaningful_value(packet.get("consult_scope_exclusion_text"))),
            ("Medical Rationale", _has_meaningful_value(packet.get("consult_medical_rationale_text"))),
            ("Risk Without Treatment", _has_meaningful_value(packet.get("consult_risk_without_treatment"))),
            ("Duration / Scope", _has_meaningful_value(packet.get("consult_duration_scope_text"))),
            ("Community Care Provider Contact Statement", _has_meaningful_value(packet.get("consult_contact_statement"))),
            ("Community Care Provider Credentials", _has_meaningful_value(packet.get("provider_credentials"))),
            ("Community Care Provider Specialty", _has_meaningful_value(packet.get("provider_specialty"))),
            ("Community Care Provider NPI", _has_meaningful_value(packet.get("provider_npi"))),
            ("Community Care Practice Name", _has_meaningful_value(packet.get("practice_name"))),
            ("Community Care Practice Address", _has_meaningful_value(packet.get("provider_address"))),
            ("Community Care Practice Phone", _has_meaningful_value(packet.get("provider_phone"))),
            ("Community Care Practice Fax", _has_meaningful_value(packet.get("provider_fax"))),
            ("Community Care Secure Email", _has_meaningful_value(packet.get("provider_email"))),
            (
                "Symptom Set",
                _any_checked(
                    packet,
                    [
                        "consult_symptom_axial_pain",
                        "consult_symptom_activity_exacerbation",
                        "consult_symptom_reduced_tolerance",
                        "consult_symptom_functional_impairment",
                    ],
                ),
            ),
            (
                "Conservative History",
                _any_checked(
                    packet,
                    [
                        "consult_include_physical_therapy",
                        "consult_include_nsaids",
                        "consult_include_activity_modification",
                        "consult_include_home_exercise",
                        "consult_include_interventional_history",
                    ],
                ),
            ),
            (
                "Requested Services",
                _any_checked(
                    packet,
                    [
                        "consult_include_pain_management_consultation",
                        "consult_include_procedural_planning",
                        "consult_include_annulargram",
                        "consult_include_fibrin_injection",
                        "consult_include_follow_up",
                    ],
                ),
            ),
            (
                "Clinical Goals",
                _any_checked(
                    packet,
                    [
                        "consult_goal_pain_reduction",
                        "consult_goal_functional_improvement",
                        "consult_goal_reduce_analgesics",
                        "consult_goal_prevent_surgery",
                    ],
                ),
            ),
        ]
    if is_lomn_profile(profile_name):
        return [
            ("Request Date", _has_meaningful_value(packet.get("lmn_request_date"))),
            ("VA Claim Number", _has_meaningful_value(packet.get("lmn_va_claim_number"))),
            ("Primary Diagnosis", _has_meaningful_value(packet.get("lmn_primary_diagnosis"))),
            ("Secondary Diagnosis", _has_meaningful_value(packet.get("lmn_secondary_diagnosis"))),
            ("Clinical Summary", _has_meaningful_value(packet.get("lmn_clinical_summary"))),
            ("MRI Date", _has_meaningful_value(packet.get("lmn_mri_date"))),
            ("MRI Findings", _has_meaningful_value(packet.get("lmn_mri_findings"))),
            ("Conservative Duration", _has_meaningful_value(packet.get("lmn_conservative_duration"))),
            ("Medical Necessity Statement", _has_meaningful_value(packet.get("lmn_medical_necessity_statement"))),
            ("Risk Statement", _has_meaningful_value(packet.get("lmn_risk_statement"))),
            ("Reasonable / Necessary Statement", _has_meaningful_value(packet.get("lmn_reasonable_necessary_statement"))),
            ("Contact Statement", _has_meaningful_value(packet.get("lmn_contact_statement"))),
            ("Community Care Provider Credentials", _has_meaningful_value(packet.get("provider_credentials"))),
            ("Community Care Provider Specialty", _has_meaningful_value(packet.get("provider_specialty"))),
            ("Community Care Provider NPI", _has_meaningful_value(packet.get("provider_npi"))),
            ("Community Care Practice Name", _has_meaningful_value(packet.get("practice_name"))),
            ("Community Care Practice Phone", _has_meaningful_value(packet.get("provider_phone"))),
            ("Community Care Practice Fax", _has_meaningful_value(packet.get("provider_fax"))),
            (
                "Conservative History",
                _any_checked(
                    packet,
                    [
                        "lmn_include_physical_therapy",
                        "lmn_include_nsaids",
                        "lmn_include_activity_modification",
                        "lmn_include_home_exercise",
                        "lmn_include_epidural_steroid_injections",
                    ],
                ),
            ),
            (
                "Treatment Objectives",
                _any_checked(
                    packet,
                    [
                        "lmn_indication_reduce_pain",
                        "lmn_indication_improve_function",
                        "lmn_indication_prevent_degeneration",
                        "lmn_indication_reduce_opioid_reliance",
                        "lmn_indication_prevent_surgery",
                    ],
                ),
            ),
        ]
    if is_clinical_documentation_profile(profile_name):
        return [
            ("Chief Complaint", _has_meaningful_value(packet.get("clinical_doc_chief_complaint"))),
            ("Duration Detail", _has_meaningful_value(packet.get("clinical_doc_exact_duration"))),
            ("Pain Severity", _has_meaningful_value(packet.get("clinical_doc_pain_severity"))),
            ("Functional Impact", _has_meaningful_value(packet.get("clinical_doc_functional_impact"))),
            ("Conservative Duration", _has_meaningful_value(packet.get("clinical_doc_conservative_duration"))),
            ("MRI Date", _has_meaningful_value(packet.get("clinical_doc_mri_date"))),
            ("Affected Levels", _has_meaningful_value(packet.get("clinical_doc_affected_levels"))),
            ("Primary Diagnosis", _has_meaningful_value(packet.get("clinical_doc_primary_diagnosis"))),
            ("Secondary Diagnosis", _has_meaningful_value(packet.get("clinical_doc_secondary_diagnosis"))),
            ("Assessment Summary", _has_meaningful_value(packet.get("clinical_doc_assessment_summary"))),
            ("Treatment Plan Intro", _has_meaningful_value(packet.get("clinical_doc_treatment_plan_intro"))),
            ("Plan Exclusion", _has_meaningful_value(packet.get("clinical_doc_plan_exclusion"))),
            ("Physician Narrative", _has_meaningful_value(packet.get("clinical_doc_physician_narrative"))),
            (
                "Pain Pattern",
                _any_checked(
                    packet,
                    [
                        "clinical_doc_pain_axial",
                        "clinical_doc_pain_discogenic",
                        "clinical_doc_pain_activity_exacerbation",
                        "clinical_doc_pain_sitting_intolerance",
                        "clinical_doc_pain_standing_intolerance",
                        "clinical_doc_pain_bending_lifting",
                    ],
                ),
            ),
            (
                "Functional Limitation Set",
                _any_checked(
                    packet,
                    [
                        "clinical_doc_limit_occupational",
                        "clinical_doc_limit_prolonged_sitting",
                        "clinical_doc_limit_prolonged_standing",
                        "clinical_doc_limit_ambulation",
                        "clinical_doc_limit_household",
                        "clinical_doc_limit_sleep",
                    ],
                ),
            ),
            (
                "Conservative Care Set",
                _any_checked(
                    packet,
                    [
                        "clinical_doc_conservative_pt",
                        "clinical_doc_conservative_home_exercise",
                        "clinical_doc_conservative_nsaids",
                        "clinical_doc_conservative_non_opioid",
                        "clinical_doc_conservative_activity_modification",
                        "clinical_doc_conservative_esi",
                        "clinical_doc_conservative_other_interventional",
                    ],
                ),
            ),
            (
                "Imaging Findings Set",
                _any_checked(
                    packet,
                    [
                        "clinical_doc_imaging_annular_tear",
                        "clinical_doc_imaging_disc_degeneration",
                        "clinical_doc_imaging_disc_protrusion",
                        "clinical_doc_imaging_disc_displacement",
                    ],
                ),
            ),
            (
                "Treatment Plan Set",
                _any_checked(
                    packet,
                    [
                        "clinical_doc_plan_diagnostic_confirmation",
                        "clinical_doc_plan_intradiscal_intervention",
                        "clinical_doc_plan_follow_up",
                    ],
                ),
            ),
        ]
    return []


def build_packet_inconsistency_messages(packet):
    profile_name = str(packet.get("packet_profile") or "").strip()
    messages = []

    def add_conflict(label, left_value, right_value, mode="text", allow_contains=False):
        if _values_conflict(left_value, right_value, mode=mode, allow_contains=allow_contains):
            messages.append(
                f"{label} is inconsistent. Shared value '{str(left_value).strip()}' does not match this form's value '{str(right_value).strip()}'."
            )

    if is_submission_cover_profile(profile_name):
        add_conflict("Primary diagnosis code", packet.get("icd_codes"), packet.get("primary_diagnosis_code"), mode="icd_first")

    if is_seoc_request_profile(profile_name):
        add_conflict("VA Medical Center", packet.get("facility"), packet.get("va_medical_center_name"))
        add_conflict("Episode diagnosis", packet.get("diagnosis"), packet.get("episode_diagnosis"), allow_contains=True)
        add_conflict("Episode ICD-10", packet.get("icd_codes"), packet.get("episode_icd_code"), mode="icd_first")
        add_conflict("Last four SSN", packet.get("ssn"), packet.get("last_four_ssn"), mode="last_four")
        add_conflict("Community Care treating provider NPI", packet.get("master_provider_npi"), packet.get("provider_npi"))
        add_conflict("Community Care practice name", packet.get("master_practice_name"), packet.get("practice_name"), allow_contains=True)
        add_conflict("Community Care practice phone", packet.get("master_provider_phone"), packet.get("provider_phone"))
        add_conflict("Community Care practice fax", packet.get("master_provider_fax"), packet.get("provider_fax"))

    if is_consult_request_profile(profile_name):
        add_conflict("VA claim number", packet.get("authorization_number"), packet.get("consult_va_claim_number"))
        add_conflict("VA referring / ordering provider", packet.get("ordering_doctor"), packet.get("consult_referring_va_provider"), allow_contains=True)
        add_conflict("Primary diagnosis", packet.get("diagnosis"), packet.get("consult_primary_diagnosis"), allow_contains=True)
        add_conflict("Secondary diagnosis", packet.get("secondary_diagnosis"), packet.get("consult_secondary_diagnosis"), allow_contains=True)
        add_conflict("VA Medical Center", packet.get("facility"), packet.get("va_medical_center_name"))
        add_conflict("MRI date", packet.get("master_mri_date"), packet.get("consult_mri_date"))
        add_conflict("MRI findings", packet.get("master_mri_findings"), packet.get("consult_mri_findings"), allow_contains=True)
        add_conflict("Community Care treating provider NPI", packet.get("master_provider_npi"), packet.get("provider_npi"))
        add_conflict("Community Care practice name", packet.get("master_practice_name"), packet.get("practice_name"), allow_contains=True)
        add_conflict("Community Care practice address", packet.get("master_provider_address"), packet.get("provider_address"), allow_contains=True)
        add_conflict("Community Care practice phone", packet.get("master_provider_phone"), packet.get("provider_phone"))
        add_conflict("Community Care practice fax", packet.get("master_provider_fax"), packet.get("provider_fax"))
        add_conflict("Community Care secure email", packet.get("master_provider_email"), packet.get("provider_email"))

    if is_lomn_profile(profile_name):
        add_conflict("VA claim number", packet.get("authorization_number"), packet.get("lmn_va_claim_number"))
        add_conflict("Primary diagnosis", packet.get("diagnosis"), packet.get("lmn_primary_diagnosis"), allow_contains=True)
        add_conflict("Secondary diagnosis", packet.get("secondary_diagnosis"), packet.get("lmn_secondary_diagnosis"), allow_contains=True)
        add_conflict("MRI date", packet.get("master_mri_date"), packet.get("lmn_mri_date"))
        add_conflict("MRI findings", packet.get("master_mri_findings"), packet.get("lmn_mri_findings"), allow_contains=True)
        add_conflict("Community Care treating provider NPI", packet.get("master_provider_npi"), packet.get("provider_npi"))
        add_conflict("Community Care practice name", packet.get("master_practice_name"), packet.get("practice_name"), allow_contains=True)
        add_conflict("Community Care practice phone", packet.get("master_provider_phone"), packet.get("provider_phone"))
        add_conflict("Community Care practice fax", packet.get("master_provider_fax"), packet.get("provider_fax"))

    if is_clinical_documentation_profile(profile_name):
        add_conflict("Primary diagnosis", packet.get("diagnosis"), packet.get("clinical_doc_primary_diagnosis"), allow_contains=True)
        add_conflict("Secondary diagnosis", packet.get("secondary_diagnosis"), packet.get("clinical_doc_secondary_diagnosis"), allow_contains=True)
        add_conflict("MRI date", packet.get("master_mri_date"), packet.get("clinical_doc_mri_date"))
        add_conflict("Affected spinal levels", packet.get("master_affected_levels"), packet.get("clinical_doc_affected_levels"), allow_contains=True)

    if is_va_10172_profile(profile_name):
        add_conflict(
            "10-10172 CCN ordering provider name",
            packet.get("provider") or packet.get("ordering_doctor"),
            packet.get("va10172_ordering_provider_name_printed"),
            allow_contains=True,
        )
        add_conflict("10-10172 ordering provider NPI", packet.get("master_provider_npi"), packet.get("va10172_ordering_provider_npi"))
        add_conflict("10-10172 ordering provider phone", packet.get("master_provider_phone"), packet.get("va10172_ordering_provider_phone"))
        add_conflict("10-10172 ordering provider fax", packet.get("master_provider_fax"), packet.get("va10172_ordering_provider_fax"))
        add_conflict("10-10172 ordering provider secure email", packet.get("master_provider_email"), packet.get("va10172_ordering_provider_secure_email"))
        add_conflict("10-10172 ordering provider office address", packet.get("master_provider_address"), packet.get("va10172_ordering_provider_office_address"), allow_contains=True)
        add_conflict("Diagnosis description", packet.get("diagnosis"), packet.get("va10172_diagnosis_description"), allow_contains=True)
        add_conflict("Requested CPT / HCPCS", packet.get("master_requested_cpt_code"), packet.get("va10172_requested_cpt_hcpcs_code"))

    return messages


def _can_replace_with_shared_value(current_value, fallback_values=None):
    current = str(current_value or "").strip()
    if not current:
        return True
    for fallback in fallback_values or []:
        if current == str(fallback or "").strip():
            return True
    return False


def apply_packet_builder_shared_field_sync(payload, *, default_packet_builder_payload_fn):
    packet = dict(payload or {})
    defaults = default_packet_builder_payload_fn()

    auth_number = str(packet.get("authorization_number") or "").strip()
    icd_codes = str(packet.get("icd_codes") or "").strip()
    ordering_doctor = str(packet.get("ordering_doctor") or "").strip()
    provider_name = str(packet.get("provider") or "").strip()
    facility = str(packet.get("facility") or "").strip()
    diagnosis = str(packet.get("diagnosis") or "").strip()
    ssn = str(packet.get("ssn") or "").strip()
    secondary_diagnosis = str(packet.get("secondary_diagnosis") or "").strip()
    provider_credentials = str(packet.get("master_provider_credentials") or "").strip()
    provider_specialty = str(packet.get("master_provider_specialty") or "").strip()
    provider_npi = str(packet.get("master_provider_npi") or "").strip()
    practice_name = str(packet.get("master_practice_name") or "").strip()
    provider_phone = str(packet.get("master_provider_phone") or "").strip()
    provider_fax = str(packet.get("master_provider_fax") or "").strip()
    provider_email = str(packet.get("master_provider_email") or "").strip()
    provider_address = str(packet.get("master_provider_address") or "").strip()
    requested_cpt_code = str(packet.get("master_requested_cpt_code") or "").strip()
    mri_date = str(packet.get("master_mri_date") or "").strip()
    mri_findings = str(packet.get("master_mri_findings") or "").strip()
    affected_levels = str(packet.get("master_affected_levels") or "").strip()
    requested_service = str(packet.get("requested_service") or "").strip()

    if auth_number:
        if _can_replace_with_shared_value(packet.get("lmn_va_claim_number"), [defaults.get("lmn_va_claim_number")]):
            packet["lmn_va_claim_number"] = auth_number
        if _can_replace_with_shared_value(packet.get("consult_va_claim_number"), [defaults.get("consult_va_claim_number")]):
            packet["consult_va_claim_number"] = auth_number

    if icd_codes:
        first_icd_code = _first_icd_code(icd_codes)
        if _can_replace_with_shared_value(packet.get("episode_icd_code"), [defaults.get("episode_icd_code")]):
            packet["episode_icd_code"] = first_icd_code or icd_codes
        if _can_replace_with_shared_value(packet.get("primary_diagnosis_code"), [defaults.get("primary_diagnosis_code")]):
            packet["primary_diagnosis_code"] = first_icd_code

    if ordering_doctor:
        if _can_replace_with_shared_value(packet.get("consult_referring_va_provider"), [defaults.get("consult_referring_va_provider")]):
            packet["consult_referring_va_provider"] = ordering_doctor

    if provider_name or ordering_doctor:
        va10172_provider_name = provider_name or ordering_doctor
        if _can_replace_with_shared_value(
            packet.get("va10172_ordering_provider_name_printed"),
            [defaults.get("va10172_ordering_provider_name_printed")],
        ):
            packet["va10172_ordering_provider_name_printed"] = va10172_provider_name

    if facility:
        if _can_replace_with_shared_value(packet.get("va_medical_center_name"), [defaults.get("va_medical_center_name")]):
            packet["va_medical_center_name"] = facility

    if diagnosis:
        if _can_replace_with_shared_value(packet.get("episode_diagnosis"), [defaults.get("episode_diagnosis")]):
            packet["episode_diagnosis"] = diagnosis
        if _can_replace_with_shared_value(packet.get("lmn_primary_diagnosis"), [defaults.get("lmn_primary_diagnosis")]):
            packet["lmn_primary_diagnosis"] = diagnosis
        if _can_replace_with_shared_value(packet.get("consult_primary_diagnosis"), [defaults.get("consult_primary_diagnosis")]):
            packet["consult_primary_diagnosis"] = diagnosis
        if _can_replace_with_shared_value(
            packet.get("clinical_doc_primary_diagnosis"),
            [defaults.get("clinical_doc_primary_diagnosis")],
        ):
            packet["clinical_doc_primary_diagnosis"] = diagnosis
        if _can_replace_with_shared_value(packet.get("va10172_diagnosis_description"), [defaults.get("va10172_diagnosis_description")]):
            packet["va10172_diagnosis_description"] = diagnosis

    if secondary_diagnosis:
        if _can_replace_with_shared_value(packet.get("lmn_secondary_diagnosis"), [defaults.get("lmn_secondary_diagnosis")]):
            packet["lmn_secondary_diagnosis"] = secondary_diagnosis
        if _can_replace_with_shared_value(packet.get("consult_secondary_diagnosis"), [defaults.get("consult_secondary_diagnosis")]):
            packet["consult_secondary_diagnosis"] = secondary_diagnosis
        if _can_replace_with_shared_value(
            packet.get("clinical_doc_secondary_diagnosis"),
            [defaults.get("clinical_doc_secondary_diagnosis")],
        ):
            packet["clinical_doc_secondary_diagnosis"] = secondary_diagnosis

    if provider_credentials:
        if _can_replace_with_shared_value(packet.get("provider_credentials"), [defaults.get("provider_credentials")]):
            packet["provider_credentials"] = provider_credentials

    if provider_specialty:
        if _can_replace_with_shared_value(packet.get("provider_specialty"), [defaults.get("provider_specialty")]):
            packet["provider_specialty"] = provider_specialty

    if provider_npi:
        if _can_replace_with_shared_value(packet.get("provider_npi"), [defaults.get("provider_npi")]):
            packet["provider_npi"] = provider_npi
        if _can_replace_with_shared_value(packet.get("va10172_ordering_provider_npi"), [defaults.get("va10172_ordering_provider_npi")]):
            packet["va10172_ordering_provider_npi"] = provider_npi

    if practice_name:
        if _can_replace_with_shared_value(packet.get("practice_name"), [defaults.get("practice_name")]):
            packet["practice_name"] = practice_name

    if provider_phone:
        if _can_replace_with_shared_value(packet.get("provider_phone"), [defaults.get("provider_phone")]):
            packet["provider_phone"] = provider_phone
        if _can_replace_with_shared_value(packet.get("va10172_ordering_provider_phone"), [defaults.get("va10172_ordering_provider_phone")]):
            packet["va10172_ordering_provider_phone"] = provider_phone

    if provider_fax:
        if _can_replace_with_shared_value(packet.get("provider_fax"), [defaults.get("provider_fax")]):
            packet["provider_fax"] = provider_fax
        if _can_replace_with_shared_value(packet.get("va10172_ordering_provider_fax"), [defaults.get("va10172_ordering_provider_fax")]):
            packet["va10172_ordering_provider_fax"] = provider_fax

    if provider_email:
        if _can_replace_with_shared_value(packet.get("provider_email"), [defaults.get("provider_email")]):
            packet["provider_email"] = provider_email
        if _can_replace_with_shared_value(
            packet.get("va10172_ordering_provider_secure_email"),
            [defaults.get("va10172_ordering_provider_secure_email")],
        ):
            packet["va10172_ordering_provider_secure_email"] = provider_email

    if provider_address:
        if _can_replace_with_shared_value(packet.get("provider_address"), [defaults.get("provider_address")]):
            packet["provider_address"] = provider_address
        if _can_replace_with_shared_value(
            packet.get("va10172_ordering_provider_office_address"),
            [defaults.get("va10172_ordering_provider_office_address")],
        ):
            packet["va10172_ordering_provider_office_address"] = provider_address

    if requested_cpt_code:
        if _can_replace_with_shared_value(
            packet.get("va10172_requested_cpt_hcpcs_code"),
            [defaults.get("va10172_requested_cpt_hcpcs_code")],
        ):
            packet["va10172_requested_cpt_hcpcs_code"] = requested_cpt_code

    if requested_service:
        if _can_replace_with_shared_value(
            packet.get("va10172_description_cpt_hcpcs_code"),
            [defaults.get("va10172_description_cpt_hcpcs_code")],
        ):
            packet["va10172_description_cpt_hcpcs_code"] = requested_service

    if mri_date:
        if _can_replace_with_shared_value(packet.get("lmn_mri_date"), [defaults.get("lmn_mri_date")]):
            packet["lmn_mri_date"] = mri_date
        if _can_replace_with_shared_value(packet.get("consult_mri_date"), [defaults.get("consult_mri_date")]):
            packet["consult_mri_date"] = mri_date
        if _can_replace_with_shared_value(packet.get("clinical_doc_mri_date"), [defaults.get("clinical_doc_mri_date")]):
            packet["clinical_doc_mri_date"] = mri_date

    if mri_findings:
        if _can_replace_with_shared_value(packet.get("lmn_mri_findings"), [defaults.get("lmn_mri_findings")]):
            packet["lmn_mri_findings"] = mri_findings
        if _can_replace_with_shared_value(packet.get("consult_mri_findings"), [defaults.get("consult_mri_findings")]):
            packet["consult_mri_findings"] = mri_findings

    if affected_levels:
        if _can_replace_with_shared_value(
            packet.get("clinical_doc_affected_levels"),
            [defaults.get("clinical_doc_affected_levels")],
        ):
            packet["clinical_doc_affected_levels"] = affected_levels

    if ssn and not str(packet.get("last_four_ssn") or "").strip():
        digits = "".join(ch for ch in ssn if ch.isdigit())
        if len(digits) >= 4:
            packet["last_four_ssn"] = digits[-4:]

    return packet


def default_packet_builder_payload():
    return {
        "packet_title": "",
        "packet_profile": PACKET_BUILDER_PROFILES[0],
        "patient_name": "",
        "date_of_birth": "",
        "authorization_number": "",
        "va_icn": "",
        "ordering_doctor": "",
        "provider": "",
        "facility": "",
        "community_facility": "",
        "requested_service": "",
        "diagnosis": "",
        "secondary_diagnosis": "",
        "icd_codes": "",
        "clinical_summary": "",
        "packet_notes": "",
        "scenario_pathology_pattern": "Auto",
        "scenario_conservative_duration": "Auto",
        "scenario_prior_esi_response": "Auto",
        "scenario_functional_emphasis": "Auto",
        "scenario_request_framing": "Auto",
        "scenario_symptom_pattern": "Auto",
        "scenario_conservative_modalities": "Auto",
        "scenario_review_concern": "Auto",
        "scenario_treatment_goals": "Auto",
        "referral_subtitle": "Spine and Pain Evaluation",
        "pcp_request_text": "I am requesting a Community Care referral for pain management and spine evaluation to determine the most appropriate treatment plan.",
        "referral_entry_text": "Specialty spine and pain evaluation and consultation",
        "areas_of_concern": "Cervical, Thoracic, Lumbar, Joints (if applicable)",
        "group_npi": "",
        "fax_number": "",
        "liaison_contact_info": "",
        "consent_form_title": "TELEHEALTH VIRTUAL CONSENT FORM",
        "consent_provider_name": "",
        "consent_initials": "",
        "minor_doctor_name": "",
        "minor_consent_initials": "",
        "service_authorization_name": "",
        "street_address": "",
        "city": "",
        "state": "",
        "zip_code": "",
        "home_phone": "",
        "mobile_phone": "",
        "work_phone": "",
        "email_address": "",
        "ssn": "",
        "drivers_license": "",
        "drivers_license_state": "",
        "appointment_confirmation_method": "Phone",
        "filed_for_disability": "No",
        "condition_work_related": "No",
        "condition_due_to_accident": "No",
        "yes_response_explanation": "",
        "has_attorney": "No",
        "attorney_name": "",
        "attorney_phone": "",
        "emergency_contact_name": "",
        "emergency_contact_relationship": "",
        "emergency_contact_phone": "",
        "primary_insurance_carrier": "",
        "primary_insurance_id": "",
        "primary_insurance_phone": "",
        "secondary_insurance_carrier": "",
        "secondary_insurance_id": "",
        "secondary_insurance_phone": "",
        "pcp_pcm_name": "",
        "pcp_pcm_phone": "",
        "pcp_pcm_fax": "",
        "patient_signature_name": "",
        "patient_signature_image": "",
        "patient_signature_date": "",
        "submission_cover_title": "VA Submission Cover Sheet",
        "submission_date": "",
        "primary_diagnosis_code": "",
        "included_virtual_consent_form": True,
        "included_va_form_10_10172": True,
        "included_seoc_request": True,
        "included_consult_request": True,
        "included_lomn": True,
        "included_clinical_notes": True,
        "included_mri_report": True,
        "submitting_office": "",
        "office_staff_name": "",
        "office_staff_signature": "",
        "office_staff_signature_image": "",
        "date_reviewed": "",
        "seoc_request_date": "",
        "va_medical_center_name": "",
        "last_four_ssn": "",
        "episode_diagnosis": "",
        "episode_icd_code": "",
        "seoc_scope_text": "",
        "estimated_duration_text": "Thirty to ninety days, including routine post-procedure follow-up related only to the authorized episode of care.",
        "clinical_objectives": "Reduce pain severity\nImprove functional capacity\nSupport activity tolerance related to the documented condition",
        "seoc_continuity_text": (
            "Upon completion of the authorized episode, a treatment summary and clinical outcome update will be provided "
            "to the referring VA provider. Any additional or unrelated care will require separate evaluation and authorization."
        ),
        "provider_credentials": "",
        "provider_specialty": "",
        "provider_npi": "",
        "practice_name": "",
        "provider_phone": "",
        "provider_fax": "",
        "seoc_include_preprocedure_eval": True,
        "seoc_include_annulargram": True,
        "seoc_include_fibrin_injection": True,
        "seoc_include_follow_up": True,
        "lmn_request_date": "",
        "lmn_va_claim_number": "",
        "lmn_primary_diagnosis": "",
        "lmn_secondary_diagnosis": "",
        "lmn_clinical_summary": "",
        "lmn_mri_date": "",
        "lmn_mri_findings": "",
        "lmn_conservative_duration": "",
        "lmn_include_physical_therapy": True,
        "lmn_include_nsaids": True,
        "lmn_include_activity_modification": True,
        "lmn_include_home_exercise": True,
        "lmn_include_epidural_steroid_injections": True,
        "lmn_medical_necessity_statement": "Based on chronic symptoms, failed conservative management, functional limitation, and imaging findings that correlate with the clinical presentation, the requested intervention is medically reasonable and necessary.",
        "lmn_indication_reduce_pain": True,
        "lmn_indication_improve_function": True,
        "lmn_indication_prevent_degeneration": True,
        "lmn_indication_reduce_opioid_reliance": True,
        "lmn_indication_prevent_surgery": True,
        "lmn_risk_statement": "Without appropriate treatment, the patient remains at risk for persistent pain, worsening functional limitation, and continued impairment of daily activities.",
        "lmn_reasonable_necessary_statement": "The requested care is consistent with the documented diagnosis, the failure of conservative treatment, and the current clinical findings.",
        "lmn_contact_statement": "Additional supporting documentation can be provided upon request.",
        "consult_request_date": "",
        "consult_va_claim_number": "",
        "consult_referring_va_provider": "",
        "consult_reason_text": "Authorization is requested for specialty consultation and treatment planning related to documented lumbar disc pathology and persistent pain despite conservative management.",
        "consult_primary_diagnosis": "",
        "consult_secondary_diagnosis": "",
        "consult_symptom_axial_pain": True,
        "consult_symptom_activity_exacerbation": True,
        "consult_symptom_reduced_tolerance": True,
        "consult_symptom_functional_impairment": True,
        "consult_mri_date": "",
        "consult_mri_findings": "",
        "consult_conservative_duration": "",
        "consult_include_physical_therapy": True,
        "consult_include_nsaids": True,
        "consult_include_activity_modification": True,
        "consult_include_home_exercise": True,
        "consult_include_interventional_history": True,
        "consult_include_pain_management_consultation": True,
        "consult_include_procedural_planning": True,
        "consult_include_annulargram": True,
        "consult_include_fibrin_injection": True,
        "consult_include_follow_up": True,
        "consult_fibrin_levels": "",
        "consult_scope_exclusion_text": "This request is limited to evaluation, procedural planning, the indicated intervention if clinically appropriate, and standard post-procedure follow-up related only to the documented lumbar condition.",
        "consult_medical_rationale_text": "The requested evaluation and treatment pathway is supported by the patient's ongoing symptoms, functional impairment, failure of conservative care, and imaging findings that correlate with the clinical presentation.",
        "consult_goal_pain_reduction": True,
        "consult_goal_functional_improvement": True,
        "consult_goal_reduce_analgesics": True,
        "consult_goal_prevent_surgery": True,
        "consult_risk_without_treatment": "Without appropriate specialty evaluation and treatment, the patient may continue to experience persistent pain, reduced function, and progression of disability.",
        "consult_duration_scope_text": "This consultation and treatment request is limited to a defined evaluation and treatment pathway rather than open-ended pain management.",
        "consult_contact_statement": "Please contact the treating office if additional records or clarification are needed for review.",
        "provider_address": "",
        "provider_email": "",
        "clinical_doc_title": "Clinical Documentation Template",
        "clinical_doc_chief_complaint": "",
        "clinical_doc_duration_gt_3m": True,
        "clinical_doc_duration_gt_6m": False,
        "clinical_doc_duration_gt_12m": False,
        "clinical_doc_exact_duration": "",
        "clinical_doc_pain_axial": True,
        "clinical_doc_pain_discogenic": True,
        "clinical_doc_pain_activity_exacerbation": True,
        "clinical_doc_pain_sitting_intolerance": True,
        "clinical_doc_pain_standing_intolerance": True,
        "clinical_doc_pain_bending_lifting": True,
        "clinical_doc_pain_severity": "",
        "clinical_doc_limit_occupational": True,
        "clinical_doc_limit_prolonged_sitting": True,
        "clinical_doc_limit_prolonged_standing": True,
        "clinical_doc_limit_ambulation": False,
        "clinical_doc_limit_household": True,
        "clinical_doc_limit_sleep": True,
        "clinical_doc_functional_impact": "",
        "clinical_doc_conservative_pt": True,
        "clinical_doc_conservative_home_exercise": True,
        "clinical_doc_conservative_nsaids": True,
        "clinical_doc_conservative_non_opioid": True,
        "clinical_doc_conservative_activity_modification": True,
        "clinical_doc_conservative_esi": True,
        "clinical_doc_conservative_other_interventional": False,
        "clinical_doc_conservative_duration": "",
        "clinical_doc_esi_response": "",
        "clinical_doc_mri_date": "",
        "clinical_doc_imaging_annular_tear": True,
        "clinical_doc_imaging_disc_degeneration": True,
        "clinical_doc_imaging_disc_protrusion": False,
        "clinical_doc_imaging_disc_displacement": False,
        "clinical_doc_affected_levels": "",
        "clinical_doc_primary_diagnosis": "",
        "clinical_doc_secondary_diagnosis": "",
        "clinical_doc_assessment_summary": "",
        "clinical_doc_treatment_plan_intro": "",
        "clinical_doc_plan_diagnostic_confirmation": True,
        "clinical_doc_plan_intradiscal_intervention": True,
        "clinical_doc_plan_follow_up": True,
        "clinical_doc_plan_exclusion": "This plan does not request open-ended medication management or unrelated pain treatment outside the documented lumbar condition.",
        "clinical_doc_physician_narrative": "",
        "va10172_va_facility_address": "",
        "va10172_ordering_provider_office_address": "",
        "va10172_is_ihs_provider": "No",
        "va10172_ordering_provider_phone": "",
        "va10172_ordering_provider_fax": "",
        "va10172_ordering_provider_secure_email": "",
        "va10172_care_needed_within_48_hours": "No",
        "va10172_is_continuation_of_care": "No",
        "va10172_referral_to_specialty": "No",
        "va10172_referral_specialty_text": "",
        "va10172_diagnosis_description": "",
        "va10172_requested_cpt_hcpcs_code": "",
        "va10172_description_cpt_hcpcs_code": "",
        "va10172_geriatric_care_option": "None",
        "va10172_reason_for_request": "",
        "va10172_ordering_provider_name_printed": "",
        "va10172_ordering_provider_npi": "",
        "va10172_signature_text": "",
        "va10172_signature_image": "",
        "va10172_today_date": "",
        "master_requested_cpt_code": "",
        "master_provider_credentials": "",
        "master_provider_specialty": "",
        "master_provider_npi": "",
        "master_practice_name": "",
        "master_provider_phone": "",
        "master_provider_fax": "",
        "master_provider_email": "",
        "master_provider_address": "",
        "master_mri_date": "",
        "master_mri_findings": "",
        "master_affected_levels": "",
        "wording_assist_state": {},
    }


def sanitize_packet_builder_text(value):
    text = str(value or "")
    if not text:
        return ""
    for source, target in TEXT_ARTIFACT_REPLACEMENTS.items():
        text = text.replace(source, target)
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    return text.strip()


def normalize_packet_builder_payload(payload, *, default_packet_builder_payload_fn, apply_packet_builder_shared_field_sync_fn):
    packet = dict(default_packet_builder_payload_fn())
    packet.update(dict(payload or {}))
    for field_name, value in list(packet.items()):
        if isinstance(value, str):
            packet[field_name] = sanitize_packet_builder_text(value)
    for field_name, replacements in LEGACY_PACKET_TEXT_REPLACEMENTS.items():
        current_value = str(packet.get(field_name) or "").strip()
        if current_value in replacements:
            packet[field_name] = replacements[current_value]
    return apply_packet_builder_shared_field_sync_fn(packet)
