from __future__ import annotations


REFERRAL_REQUEST_PROFILE = "Community Care Referral Request"
PATIENT_PACKET_PROFILE_ORDER = [
    "Submission Cover Sheet",
    "Virtual Consent Form",
    "VA Form 10-10172",
    "Single Episode of Care Request Template",
    "Consultation & Treatment Request Template",
    "Letter of Medical Necessity Template",
    "Clinical Notes Template",
]

PACKET_BUILDER_PROFILES = [
    REFERRAL_REQUEST_PROFILE,
    *PATIENT_PACKET_PROFILE_ORDER,
]

BUNDLE_EXPORT_EXTENSIONS = {
    "word": ["docx"],
    "pdf": ["pdf"],
    "both": ["docx", "pdf"],
}


def sanitize_builder_filename(value):
    text = str(value or "").strip()
    if not text:
        return "truecore_packet"
    safe = []
    for char in text:
        if char.isalnum() or char in {"-", "_", " "}:
            safe.append(char)
    compact = "".join(safe).strip().replace(" ", "_")
    return compact or "truecore_packet"


def is_referral_request_profile(profile_name):
    return str(profile_name or "").strip().lower() == "community care referral request"


def is_virtual_consent_profile(profile_name):
    return str(profile_name or "").strip().lower() == "virtual consent form"


def is_submission_cover_profile(profile_name):
    return str(profile_name or "").strip().lower() == "submission cover sheet"


def is_seoc_request_profile(profile_name):
    normalized = str(profile_name or "").strip().lower()
    return normalized in {
        "seoc request template",
        "single episode of care request template",
    }


def is_lomn_profile(profile_name):
    normalized = str(profile_name or "").strip().lower()
    return normalized in {
        "letter of medical necessity template",
        "letter of medical necessity",
    }


def is_consult_request_profile(profile_name):
    normalized = str(profile_name or "").strip().lower()
    return normalized in {
        "consultation request template",
        "consultation & treatment request template",
        "consultation and treatment request",
    }


def is_clinical_documentation_profile(profile_name):
    normalized = str(profile_name or "").strip().lower()
    return normalized in {
        "clinical documentation template",
        "clinical notes template",
        "clinical documentation",
        "clinical notes",
    }


def is_va_10172_profile(profile_name):
    normalized = str(profile_name or "").strip().lower()
    return normalized in {
        "va form 10-10172",
        "va form 10172",
        "10-10172",
    }


def default_title_for_profile(profile_name):
    if is_referral_request_profile(profile_name):
        return "Community Care Referral Request"
    if is_virtual_consent_profile(profile_name):
        return "TELEHEALTH VIRTUAL CONSENT FORM"
    if is_submission_cover_profile(profile_name):
        return "VA Submission Cover Sheet"
    if is_seoc_request_profile(profile_name):
        return "Single Episode of Care (SEOC) Request"
    if is_lomn_profile(profile_name):
        return "LETTER OF MEDICAL NECESSITY"
    if is_consult_request_profile(profile_name):
        return "CONSULTATION AND TREATMENT REQUEST"
    if is_clinical_documentation_profile(profile_name):
        return "Clinical Documentation Template"
    if is_va_10172_profile(profile_name):
        return "VA Form 10-10172"
    return ""


def get_packet_export_group(profile_name):
    normalized = str(profile_name or "").strip()
    if normalized == REFERRAL_REQUEST_PROFILE:
        return "referral_request"
    if normalized in PATIENT_PACKET_PROFILE_ORDER:
        return "patient_packet"
    return "standalone"


def get_patient_packet_position(profile_name):
    normalized = str(profile_name or "").strip()
    if normalized not in PATIENT_PACKET_PROFILE_ORDER:
        return None
    return PATIENT_PACKET_PROFILE_ORDER.index(normalized) + 1


def describe_packet_export_context(profile_name):
    group = get_packet_export_group(profile_name)
    if group == "referral_request":
        return "Standalone export: Community Care Referral Request (pre-packet document)."
    if group == "patient_packet":
        position = get_patient_packet_position(profile_name)
        total = len(PATIENT_PACKET_PROFILE_ORDER)
        return f"Patient packet component: item {position} of {total}. Exports as part of the ordered patient packet bundle."
    return "Standalone builder profile."


def bundle_profiles_for_group(group_name):
    normalized = str(group_name or "").strip().lower()
    if normalized == "referral_request":
        return [REFERRAL_REQUEST_PROFILE]
    if normalized == "patient_packet":
        return list(PATIENT_PACKET_PROFILE_ORDER)
    return []


def bundle_folder_name(base_filename, group_name):
    safe_base = sanitize_builder_filename(base_filename)
    normalized = str(group_name or "").strip().lower()
    suffix = "packet_bundle"
    if normalized == "referral_request":
        suffix = "referral_request"
    elif normalized == "patient_packet":
        suffix = "patient_packet"
    return f"{safe_base}_{suffix}"


def compiled_packet_filename(base_filename, group_name):
    safe_base = sanitize_builder_filename(base_filename)
    normalized = str(group_name or "").strip().lower()
    if normalized == "patient_packet":
        return f"{safe_base}_patient_packet.pdf"
    if normalized == "referral_request":
        return f"{safe_base}_referral_request.pdf"
    return f"{safe_base}_packet.pdf"


def bundle_member_filename(profile_name, group_name):
    normalized_group = str(group_name or "").strip().lower()
    title = default_title_for_profile(profile_name) or str(profile_name or "packet_document").strip() or "packet_document"
    safe_title = sanitize_builder_filename(title)
    if normalized_group == "patient_packet":
        position = get_patient_packet_position(profile_name)
        if position is not None:
            return f"{position:02d}_{safe_title}"
    return safe_title


def normalize_bundle_export_format(format_name):
    normalized = str(format_name or "").strip().lower()
    if normalized in BUNDLE_EXPORT_EXTENSIONS:
        return normalized
    return "both"


def bundle_extensions_for_format(format_name, include_real_va_pdf=False):
    normalized = normalize_bundle_export_format(format_name)
    extensions = list(BUNDLE_EXPORT_EXTENSIONS.get(normalized) or BUNDLE_EXPORT_EXTENSIONS["both"])
    if include_real_va_pdf and "pdf" not in extensions:
        extensions.append("pdf")
    return extensions


def build_bundle_export_plan(base_filename, group_name, format_name):
    normalized_group = str(group_name or "").strip().lower()
    extensions = bundle_extensions_for_format(format_name)
    documents = []
    for profile_name in bundle_profiles_for_group(normalized_group):
        member_stem = bundle_member_filename(profile_name, normalized_group)
        member_extensions = list(extensions)
        if is_va_10172_profile(profile_name) and "pdf" not in member_extensions:
            member_extensions.append("pdf")
        for extension in member_extensions:
            documents.append(
                {
                    "profile_name": profile_name,
                    "filename": f"{member_stem}.{extension}",
                    "extension": extension,
                }
            )
    return {
        "group_name": normalized_group,
        "folder_name": bundle_folder_name(base_filename, normalized_group),
        "documents": documents,
    }
