from __future__ import annotations

import html
import hashlib
import json
import os
import re
import tempfile
from PySide6.QtCore import Qt, QThread, QTimer, QSignalBlocker
from PySide6.QtPdf import QPdfDocument
from PySide6.QtPdfWidgets import QPdfView
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from TrueCore.ui.pyside_gui.dev_tools_controls import (
    MultiSelectPromptField,
    SignatureCaptureDialog,
)
from TrueCore.ui.pyside_gui.dev_tools_config import (
    DEFAULT_DEV_TOOLS_CONFIG_PATH,
    default_dev_tools_config,
    default_export_dir as default_export_dir_impl,
    default_va_form_10172_template_path as default_va_form_10172_template_path_impl,
    deep_merge as deep_merge_impl,
    load_dev_tools_config as load_dev_tools_config_impl,
    normalize_dev_tools_config as normalize_dev_tools_config_impl,
    save_dev_tools_config as save_dev_tools_config_impl,
    update_dev_tools_config as update_dev_tools_config_impl,
)
from TrueCore.ui.pyside_gui.dev_tools_export_mixin import PacketBuilderExportMixin
from TrueCore.ui.pyside_gui.dev_tools_export_utils import (
    convert_docx_to_pdf_via_word as convert_docx_to_pdf_via_word_impl,
    find_word_executable as find_word_executable_impl,
)
from TrueCore.ui.pyside_gui.dev_tools_lab_logic import (
    build_packet_lab_html as build_packet_lab_html_impl,
    build_packet_lab_report as build_packet_lab_report_impl,
    classify_packet_lab_completion as classify_packet_lab_completion_impl,
    packet_profile_status_palette as packet_profile_status_palette_impl,
)
from TrueCore.ui.pyside_gui.dev_tools_packet_logic import (
    WORDING_FACT_LABELS,
    WORDING_REVIEW_DECISIONS,
    WORDING_STATUS_COLORS,
    build_export_warning_context as build_export_warning_context_impl,
    build_packet_library_completion as build_packet_library_completion_impl,
    build_packet_library_production_metrics as build_packet_library_production_metrics_impl,
    build_wording_assist_banner as build_wording_assist_banner_impl,
    build_wording_assist_entries as build_wording_assist_entries_impl,
    build_wording_export_blockers as build_wording_export_blockers_impl,
    build_wording_risk_messages as build_wording_risk_messages_impl,
    delete_packet_library_record as delete_packet_library_record_impl,
    ensure_packet_library_dir as ensure_packet_library_dir_impl,
    generate_packet_library_draft_id as generate_packet_library_draft_id_impl,
    list_packet_library_records as list_packet_library_records_impl,
    packet_library_display_name as packet_library_display_name_impl,
    packet_library_record_path as packet_library_record_path_impl,
    save_packet_library_record as save_packet_library_record_impl,
    should_enforce_wording_assist as should_enforce_wording_assist_impl,
)
from TrueCore.ui.pyside_gui.dev_tools_payload_logic import (
    SHARED_PACKET_HEADER_FIELDS,
    _can_replace_with_shared_value as can_replace_with_shared_value_impl,
    _first_icd_code as first_icd_code_impl,
    _has_meaningful_value as has_meaningful_value_impl,
    apply_packet_builder_shared_field_sync as apply_packet_builder_shared_field_sync_impl,
    build_packet_inconsistency_messages as build_packet_inconsistency_messages_impl,
    build_profile_current_form_checks as build_profile_current_form_checks_impl,
    build_profile_export_payload as build_profile_export_payload_impl,
    default_packet_builder_payload as default_packet_builder_payload_impl,
    normalize_packet_builder_payload as normalize_packet_builder_payload_impl,
    sanitize_packet_builder_text as sanitize_packet_builder_text_impl,
)
from TrueCore.ui.pyside_gui.dev_tools_wording_library import PacketBuilderWordingLibraryMixin
from TrueCore.ui.pyside_gui.dev_tools_profiles import (
    PACKET_BUILDER_PROFILES,
    PATIENT_PACKET_PROFILE_ORDER,
    build_bundle_export_plan,
    bundle_folder_name,
    bundle_member_filename,
    compiled_packet_filename,
    default_title_for_profile,
    describe_packet_export_context,
    is_clinical_documentation_profile,
    is_consult_request_profile,
    is_lomn_profile,
    is_referral_request_profile,
    is_seoc_request_profile,
    is_submission_cover_profile,
    is_va_10172_profile,
    is_virtual_consent_profile,
    normalize_bundle_export_format,
    sanitize_builder_filename,
)
from TrueCore.ui.pyside_gui.dev_tools_preview_markup import (
    build_packet_builder_document_markup,
    build_packet_builder_sections,
    render_packet_builder_document_export,
    render_packet_builder_document_preview,
)
from TrueCore.ui.pyside_gui.dev_tools_signature_logic import (
    SIGNATURE_IMAGE_FIELDS,
    SIGNATURE_ROLE_LABELS,
    signature_image_bytes as signature_image_bytes_impl,
    signature_image_html as signature_image_html_impl,
    typed_signature_image_bytes as typed_signature_image_bytes_impl,
)
from TrueCore.ui.pyside_gui.dev_tools_workers import ExactPreviewRenderWorker, PacketExportWorker
from TrueCore.utils.runtime_info import runtime_data_path


DEV_TOOLS_CONFIG_PATH = DEFAULT_DEV_TOOLS_CONFIG_PATH
def _first_nonempty_text(*values):
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _ensure_sentence(text):
    normalized = sanitize_packet_builder_text(text)
    if not normalized:
        return ""
    if normalized[-1] not in ".!?":
        normalized += "."
    return normalized


def _human_join(items):
    cleaned = []
    seen = set()
    for item in items:
        text = str(item or "").strip()
        if not text:
            continue
        normalized = re.sub(r"\s+", " ", text).strip().lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        cleaned.append(text)
    if not cleaned:
        return ""
    if len(cleaned) == 1:
        return cleaned[0]
    if len(cleaned) == 2:
        return f"{cleaned[0]} and {cleaned[1]}"
    return ", ".join(cleaned[:-1]) + f", and {cleaned[-1]}"


def _selected_labels(packet, option_pairs):
    labels = []
    for field_name, label in option_pairs:
        if packet.get(field_name):
            labels.append(label)
    return labels


def _consult_requested_service_labels(packet):
    labels = _selected_labels(packet, [
        ("consult_include_pain_management_consultation", "specialty pain management consultation"),
        ("consult_include_procedural_planning", "diagnostic confirmation and procedural planning"),
        ("consult_include_annulargram", "diagnostic annulargram if clinically indicated"),
        ("consult_include_fibrin_injection", "inter annular fibrin injection if clinically indicated"),
        ("consult_include_follow_up", "standard post-procedure follow-up"),
    ])
    if not labels:
        requested_service = str(packet.get("requested_service") or "").strip()
        if requested_service:
            labels.append(requested_service)
    return labels


def _seoc_scope_labels(packet):
    labels = _selected_labels(packet, [
        ("seoc_include_preprocedure_eval", "pre-procedure evaluation and procedural planning"),
        ("seoc_include_annulargram", "diagnostic annulargram"),
        ("seoc_include_fibrin_injection", "inter annular fibrin injection if clinically indicated"),
        ("seoc_include_follow_up", "standard post-procedure follow-up"),
    ])
    if not labels:
        requested_service = str(packet.get("requested_service") or "").strip()
        if requested_service:
            labels.append(requested_service)
    return labels


def _clinical_plan_labels(packet):
    labels = _selected_labels(packet, [
        ("clinical_doc_plan_diagnostic_confirmation", "diagnostic confirmation if clinically indicated"),
        ("clinical_doc_plan_intradiscal_intervention", "the requested interventional treatment if clinically indicated"),
        ("clinical_doc_plan_follow_up", "standard post-procedure follow-up"),
    ])
    if not labels:
        requested_service = str(packet.get("requested_service") or "").strip()
        if requested_service:
            labels.append(requested_service)
    return labels


def _clinical_limitation_labels(packet):
    labels = _selected_labels(packet, [
        ("clinical_doc_limit_occupational", "occupational duties"),
        ("clinical_doc_limit_prolonged_sitting", "prolonged sitting"),
        ("clinical_doc_limit_prolonged_standing", "prolonged standing"),
        ("clinical_doc_limit_ambulation", "ambulation tolerance"),
        ("clinical_doc_limit_household", "household activities"),
        ("clinical_doc_limit_sleep", "sleep quality"),
    ])
    direct_text = _clean_functional_impact_text(packet.get("clinical_doc_functional_impact"))
    if direct_text:
        labels.insert(0, direct_text)
    return labels


def _conservative_history_labels(packet):
    labels = []
    labels.extend(_selected_labels(packet, [
        ("consult_include_physical_therapy", "physical therapy"),
        ("consult_include_nsaids", "NSAIDs"),
        ("consult_include_activity_modification", "activity modification"),
        ("consult_include_home_exercise", "home exercise program"),
        ("consult_include_interventional_history", "prior interventional treatment"),
        ("lmn_include_physical_therapy", "physical therapy"),
        ("lmn_include_nsaids", "NSAIDs"),
        ("lmn_include_activity_modification", "activity modification"),
        ("lmn_include_home_exercise", "home exercise program"),
        ("lmn_include_epidural_steroid_injections", "epidural steroid injection history"),
        ("clinical_doc_conservative_pt", "physical therapy"),
        ("clinical_doc_conservative_home_exercise", "home exercise program"),
        ("clinical_doc_conservative_nsaids", "NSAIDs"),
        ("clinical_doc_conservative_non_opioid", "non-opioid analgesics"),
        ("clinical_doc_conservative_activity_modification", "activity modification"),
        ("clinical_doc_conservative_esi", "epidural steroid injections"),
        ("clinical_doc_conservative_other_interventional", "other interventional procedures"),
    ]))
    duration = _first_nonempty_text(
        packet.get("consult_conservative_duration"),
        packet.get("lmn_conservative_duration"),
        packet.get("clinical_doc_conservative_duration"),
    )
    if duration:
        labels.append(f"documented conservative management over {duration}")
    deduped = []
    for label in labels:
        if label not in deduped:
            deduped.append(label)
    return deduped


def _clean_functional_impact_text(value):
    text = sanitize_packet_builder_text(value)
    if not text:
        return ""
    patterns = [
        r"^(the condition continues to interfere with)\s+",
        r"^(current symptoms continue to limit)\s+",
        r"^(the veteran'?s symptoms interfere with)\s+",
        r"^(the veteran'?s ability to)\s+",
        r"^(symptoms continue to impair)\s+",
        r"^(functional impact is evident in)\s+",
    ]
    for pattern in patterns:
        text = re.sub(pattern, "", text, flags=re.IGNORECASE).strip(" :;-")
    return text


def _wording_fact_text(packet, fact_key):
    packet = normalize_packet_builder_payload(packet)
    if fact_key == "diagnosis":
        return _first_nonempty_text(
            packet.get("diagnosis"),
            packet.get("consult_primary_diagnosis"),
            packet.get("lmn_primary_diagnosis"),
            packet.get("clinical_doc_primary_diagnosis"),
            packet.get("episode_diagnosis"),
            packet.get("va10172_diagnosis_description"),
        )
    if fact_key == "secondary_diagnosis":
        return _first_nonempty_text(
            packet.get("secondary_diagnosis"),
            packet.get("consult_secondary_diagnosis"),
            packet.get("lmn_secondary_diagnosis"),
            packet.get("clinical_doc_secondary_diagnosis"),
        )
    if fact_key == "icd_codes":
        return _first_nonempty_text(
            packet.get("icd_codes"),
            packet.get("episode_icd_code"),
            packet.get("primary_diagnosis_code"),
        )
    if fact_key == "requested_service":
        return _first_nonempty_text(
            packet.get("requested_service"),
            packet.get("va10172_description_cpt_hcpcs_code"),
        )
    if fact_key == "mri_date":
        return _first_nonempty_text(
            packet.get("master_mri_date"),
            packet.get("consult_mri_date"),
            packet.get("lmn_mri_date"),
            packet.get("clinical_doc_mri_date"),
        )
    if fact_key == "mri_findings":
        return _first_nonempty_text(
            packet.get("master_mri_findings"),
            packet.get("consult_mri_findings"),
            packet.get("lmn_mri_findings"),
        )
    if fact_key == "affected_levels":
        return _first_nonempty_text(
            packet.get("master_affected_levels"),
            packet.get("clinical_doc_affected_levels"),
        )
    if fact_key == "symptom_summary":
        return _first_nonempty_text(
            packet.get("clinical_summary"),
            packet.get("clinical_doc_chief_complaint"),
            packet.get("lmn_clinical_summary"),
            packet.get("consult_reason_text"),
        )
    if fact_key == "functional_impact":
        return _first_nonempty_text(
            packet.get("clinical_doc_functional_impact"),
            _human_join(_clinical_limitation_labels(packet)),
        )
    if fact_key == "conservative_history":
        return _human_join(_conservative_history_labels(packet))
    if fact_key == "consult_requested_services":
        return _human_join(_consult_requested_service_labels(packet))
    if fact_key == "seoc_scope_items":
        return _human_join(_seoc_scope_labels(packet))
    if fact_key == "clinical_plan_items":
        return _human_join(_clinical_plan_labels(packet))
    if fact_key == "clinical_limitations":
        return _human_join(_clinical_limitation_labels(packet))
    if fact_key == "estimated_duration_text":
        return str(packet.get("estimated_duration_text") or "").strip()
    if fact_key in {"ordering_doctor", "facility"}:
        return str(packet.get(fact_key) or "").strip()
    return str(packet.get(fact_key) or "").strip()


def _diagnosis_phrase(packet):
    diagnosis = _wording_fact_text(packet, "diagnosis")
    icd_code = _first_icd_code(_wording_fact_text(packet, "icd_codes"))
    if not diagnosis:
        return ""
    if icd_code and icd_code not in diagnosis:
        return f"{diagnosis} ({icd_code})"
    return diagnosis


def _diagnosis_with_levels_phrase(packet):
    diagnosis_phrase = _diagnosis_phrase(packet)
    levels = _wording_fact_text(packet, "affected_levels")
    if diagnosis_phrase and levels and levels.lower() not in diagnosis_phrase.lower():
        return f"{diagnosis_phrase} involving {levels}"
    return diagnosis_phrase


def _wording_cycle_index(packet, context=""):
    current_key = str(packet.get("__wording_cycle_key") or "").strip().lower()
    if current_key:
        try:
            return max(0, int(packet.get("__wording_cycle_index") or 0))
        except Exception:
            return 0
    return 0


def _wording_variation_seed(packet, context=""):
    seed_parts = [
        context,
        _wording_fact_text(packet, "diagnosis"),
        _wording_fact_text(packet, "requested_service"),
        _wording_fact_text(packet, "mri_findings"),
        _wording_fact_text(packet, "functional_impact"),
        _wording_fact_text(packet, "conservative_history"),
    ]
    return "|".join(part for part in seed_parts if part)


def _pick_wording_variant(packet, context, *options):
    choices = [option for option in options if option]
    if not choices:
        return ""
    seed = _wording_variation_seed(packet, context)
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()
    index = (int(digest, 16) + _wording_cycle_index(packet, context)) % len(choices)
    return choices[index]


def _pick_wording_index(packet, context, count):
    if count <= 0:
        return 0
    seed = _wording_variation_seed(packet, context)
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()
    return (int(digest, 16) + _wording_cycle_index(packet, context)) % count


def _select_wording_blueprint(packet, context, scenarios):
    valid = [scenario for scenario in scenarios if scenario.get("text")]
    if not valid:
        return {
            "suggestion_text": "",
            "scenario_label": "",
            "scenario_use_when": "",
        }
    selected = valid[_pick_wording_index(packet, context, len(valid))]
    return {
        "suggestion_text": sanitize_packet_builder_text(selected.get("text") or ""),
        "scenario_label": str(selected.get("label") or "").strip(),
        "scenario_use_when": str(selected.get("use_when") or "").strip(),
    }


def _make_wording_scenario(label, use_when, text, enabled=True):
    return {
        "label": label,
        "use_when": use_when,
        "text": sanitize_packet_builder_text(text) if enabled and text else "",
    }


def _clean_lower_text(value):
    return sanitize_packet_builder_text(value).lower()


def _text_contains_any(value, *needles):
    haystack = _clean_lower_text(value)
    return any(str(needle or "").strip().lower() in haystack for needle in needles if str(needle or "").strip())


def _combined_wording_source_text(packet):
    parts = [
        _wording_fact_text(packet, "diagnosis"),
        _wording_fact_text(packet, "mri_findings"),
        _wording_fact_text(packet, "symptom_summary"),
        _wording_fact_text(packet, "requested_service"),
        _wording_fact_text(packet, "functional_impact"),
        _wording_fact_text(packet, "conservative_history"),
        _wording_fact_text(packet, "affected_levels"),
    ]
    return " | ".join(part for part in parts if part)


def _duration_source_text(packet):
    return _first_nonempty_text(
        packet.get("consult_conservative_duration"),
        packet.get("lmn_conservative_duration"),
        packet.get("clinical_doc_conservative_duration"),
        packet.get("clinical_doc_exact_duration"),
        packet.get("estimated_duration_text"),
    )


def _scenario_choices(packet, field_name):
    value = str(packet.get(field_name) or "").strip()
    if not value or value.lower() == "auto":
        return set()
    parts = [part.strip() for part in value.replace("\n", "|").split("|") if part.strip()]
    return {
        re.sub(r"[^a-z0-9]+", "_", part.lower()).strip("_")
        for part in parts
        if part.lower() != "auto"
    }


def _scenario_has(packet, field_name, *values):
    selected = _scenario_choices(packet, field_name)
    if not selected:
        return False
    wanted = {
        re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")
        for value in values
        if str(value or "").strip()
    }
    return any(item in selected for item in wanted)


def _duration_bucket(packet):
    explicit = _scenario_choices(packet, "scenario_conservative_duration")
    for choice in ("over_12_months", "over_6_months", "over_90_days"):
        if choice in explicit:
            return choice
    source = _clean_lower_text(_duration_source_text(packet))
    if packet.get("clinical_doc_duration_gt_12m"):
        return "over_12_months"
    if packet.get("clinical_doc_duration_gt_6m"):
        return "over_6_months"
    if packet.get("clinical_doc_duration_gt_3m"):
        return "over_90_days"
    if not source:
        return ""
    if re.search(r"\b(12|twelve)\s*(months?|mos?)\b", source) or re.search(r"\b(1|one)\s*(years?|yrs?)\b", source):
        return "over_12_months"
    if re.search(r"\b(6|six)\s*(months?|mos?)\b", source):
        return "over_6_months"
    if re.search(r"\b(90|ninety)\b", source) and re.search(r"\b(days?)\b", source):
        return "over_90_days"
    if re.search(r"\b(3|three)\s*(months?|mos?)\b", source):
        return "over_90_days"
    return ""


def _has_annular_pattern(packet):
    if _scenario_has(packet, "scenario_pathology_pattern", "discogenic_annular"):
        return True
    if _scenario_has(packet, "scenario_symptom_pattern", "discogenic_pattern"):
        return True
    return (
        bool(packet.get("clinical_doc_imaging_annular_tear"))
        or _text_contains_any(_combined_wording_source_text(packet), "annular", "discogenic")
    )


def _has_radicular_pattern(packet):
    if _scenario_has(packet, "scenario_pathology_pattern", "radicular"):
        return True
    if _scenario_has(packet, "scenario_symptom_pattern", "radicular_symptoms"):
        return True
    return _text_contains_any(
        _combined_wording_source_text(packet),
        "radicular",
        "radiculopathy",
        "radiating pain",
        "numbness",
        "tingling",
        "sciatica",
    )


def _has_disc_displacement_pattern(packet):
    if _scenario_has(packet, "scenario_pathology_pattern", "disc_displacement_herniation"):
        return True
    return _text_contains_any(
        _combined_wording_source_text(packet),
        "herniat",
        "displacement",
        "protrusion",
        "extrusion",
    )


def _has_multilevel_pattern(packet):
    if _scenario_has(packet, "scenario_pathology_pattern", "multilevel"):
        return True
    levels = _clean_lower_text(_wording_fact_text(packet, "affected_levels"))
    if not levels:
        return False
    if "," in levels or "/" in levels or " and " in levels:
        return True
    level_matches = re.findall(r"[clt]\d+\s*-\s*[clt]\d+", levels)
    return len(level_matches) > 1


def _has_failed_esi_history(packet):
    if _scenario_has(packet, "scenario_prior_esi_response", "temporary_relief", "partial_relief", "no_relief"):
        return True
    if _scenario_has(packet, "scenario_prior_esi_response", "none_not_documented"):
        return False
    if _scenario_has(packet, "scenario_conservative_modalities", "prior_esi_interventional"):
        return True
    return any(
        bool(packet.get(flag))
        for flag in [
            "clinical_doc_conservative_esi",
            "lmn_include_epidural_steroid_injections",
            "consult_include_interventional_history",
        ]
    ) or _text_contains_any(_combined_wording_source_text(packet), "epidural steroid", "esi")


def _has_failed_pt_history(packet):
    if _scenario_has(packet, "scenario_conservative_modalities", "physical_therapy"):
        return True
    return any(
        bool(packet.get(flag))
        for flag in [
            "clinical_doc_conservative_pt",
            "lmn_include_physical_therapy",
            "consult_include_physical_therapy",
        ]
    )


def _has_medication_history(packet):
    if _scenario_has(packet, "scenario_conservative_modalities", "nsaids_analgesics"):
        return True
    return any(
        bool(packet.get(flag))
        for flag in [
            "clinical_doc_conservative_nsaids",
            "clinical_doc_conservative_non_opioid",
            "lmn_include_nsaids",
            "consult_include_nsaids",
        ]
    ) or _text_contains_any(_combined_wording_source_text(packet), "nsaid", "analgesic")


def _has_sleep_limitation(packet):
    if _scenario_has(packet, "scenario_functional_emphasis", "sleep_disruption"):
        return True
    return bool(packet.get("clinical_doc_limit_sleep")) or _text_contains_any(
        _wording_fact_text(packet, "functional_impact"),
        "sleep",
    )


def _has_occupational_limitation(packet):
    if _scenario_has(packet, "scenario_functional_emphasis", "work_capacity"):
        return True
    return bool(packet.get("clinical_doc_limit_occupational")) or _text_contains_any(
        _wording_fact_text(packet, "functional_impact"),
        "work",
        "occupational",
        "job",
    )


def _has_position_tolerance_limitation(packet):
    if _scenario_has(packet, "scenario_functional_emphasis", "sitting_standing_tolerance"):
        return True
    if _scenario_has(packet, "scenario_symptom_pattern", "position_intolerance", "activity_related_exacerbation"):
        return True
    return any(
        bool(packet.get(flag))
        for flag in [
            "clinical_doc_limit_prolonged_sitting",
            "clinical_doc_limit_prolonged_standing",
            "clinical_doc_limit_ambulation",
            "clinical_doc_limit_household",
        ]
    ) or _text_contains_any(
        _wording_fact_text(packet, "functional_impact"),
        "sitting",
        "standing",
        "walking",
        "bending",
        "lifting",
        "household",
    )


def _has_specific_requested_procedure(packet):
    if _scenario_has(packet, "scenario_request_framing", "specific_requested_procedure", "defined_interventional_pathway"):
        return True
    explicit = _scenario_choices(packet, "scenario_request_framing")
    if explicit == {"procedure_neutral_evaluation"}:
        return False
    return _text_contains_any(
        _wording_fact_text(packet, "requested_service"),
        "annulargram",
        "fibrin",
        "injection",
        "procedure",
        "intervention",
    )


def _has_imaging_correlation(packet):
    if _scenario_has(packet, "scenario_review_concern", "imaging_correlation_emphasis"):
        return True
    return bool(_wording_fact_text(packet, "mri_findings"))


def _symptom_summary_sentence(packet):
    symptom_summary = _wording_fact_text(packet, "symptom_summary")
    if not symptom_summary:
        return ""
    cleaned = sanitize_packet_builder_text(symptom_summary)
    weak_patterns = [
        r"\bhaving pain\b",
        r"\binability to function normally\b",
        r"\blower lumbar injuries\b",
        r"\bback pain\b",
    ]
    if any(re.search(pattern, cleaned, flags=re.IGNORECASE) for pattern in weak_patterns):
        diagnosis_phrase = _diagnosis_with_levels_phrase(packet) or "the documented lumbar condition"
        return _pick_wording_variant(
            packet,
            "symptom_summary_rewrite",
            _ensure_sentence(f"The Veteran has chronic, function-limiting pain related to {diagnosis_phrase}"),
            _ensure_sentence(f"Symptoms remain consistent with chronic, function-limiting pain associated with {diagnosis_phrase}"),
            _ensure_sentence(f"The current presentation reflects persistent pain and functional limitation related to {diagnosis_phrase}"),
            _ensure_sentence(f"The Veteran continues to report persistent pain and activity-related limitation related to {diagnosis_phrase}"),
        )
    return _ensure_sentence(cleaned)


def _imaging_correlation_sentence(packet):
    mri_date = _wording_fact_text(packet, "mri_date")
    mri_findings = _wording_fact_text(packet, "mri_findings")
    if mri_date and mri_findings:
        return _pick_wording_variant(
            packet,
            "imaging_correlation_with_date",
            _ensure_sentence(
                f"MRI dated {mri_date} demonstrates {mri_findings}, and the imaging findings correlate with the clinical presentation"
            ),
            _ensure_sentence(
                f"MRI dated {mri_date} shows {mri_findings}, and those findings correlate with the reported symptom pattern and examination context"
            ),
            _ensure_sentence(
                f"Imaging obtained on {mri_date} demonstrates {mri_findings}, with radiographic findings that support the clinical presentation"
            ),
        )
    if mri_findings:
        return _pick_wording_variant(
            packet,
            "imaging_correlation_no_date",
            _ensure_sentence(
                f"Imaging findings demonstrate {mri_findings}, and the imaging findings correlate with the clinical presentation"
            ),
            _ensure_sentence(
                f"Available imaging shows {mri_findings}, and those findings are consistent with the clinical presentation"
            ),
            _ensure_sentence(
                f"Imaging review demonstrates {mri_findings}, with findings that correlate with the Veteran's reported symptoms"
            ),
        )
    return ""


def _conservative_history_sentence(packet):
    conservative_history = _wording_fact_text(packet, "conservative_history")
    if not conservative_history:
        return ""
    return _pick_wording_variant(
        packet,
        "conservative_history",
        _ensure_sentence(f"Symptoms have persisted despite {conservative_history}"),
        _ensure_sentence(f"Persistent symptoms remain despite conservative management that has included {conservative_history}"),
        _ensure_sentence(f"The Veteran has not achieved sustained relief despite conservative treatment, including {conservative_history}"),
    )


def _functional_impact_sentence(packet):
    functional_impact = _clean_functional_impact_text(_wording_fact_text(packet, "functional_impact"))
    if not functional_impact:
        return ""
    return _pick_wording_variant(
        packet,
        "functional_impact",
        _ensure_sentence(f"The condition continues to interfere with {functional_impact}"),
        _ensure_sentence(f"Functional limitation remains evident in {functional_impact}"),
        _ensure_sentence(f"Symptoms continue to impair {functional_impact}"),
    )


def _requested_service_sentence(packet):
    requested_service = _wording_fact_text(packet, "requested_service")
    requested_cpt = _wording_fact_text(packet, "requested_cpt_code")
    if requested_service:
        if requested_cpt and requested_cpt not in requested_service:
            return _pick_wording_variant(
                packet,
                "requested_service_with_cpt",
                _ensure_sentence(f"Authorization is requested for {requested_service} associated with CPT/HCPCS code {requested_cpt}"),
                _ensure_sentence(f"The requested service is {requested_service}, submitted in association with CPT/HCPCS code {requested_cpt}"),
                _ensure_sentence(f"Review is requested for {requested_service} under CPT/HCPCS code {requested_cpt} if clinically indicated"),
            )
        return _pick_wording_variant(
            packet,
            "requested_service_no_cpt",
            _ensure_sentence(f"Authorization is requested for {requested_service}"),
            _ensure_sentence(f"The requested care includes {requested_service}"),
            _ensure_sentence(f"Review is requested for {requested_service} if clinically indicated"),
        )
    return _pick_wording_variant(
        packet,
        "requested_service_fallback",
        "Authorization is requested for specialty evaluation, diagnostic confirmation, and indicated interventional treatment planning.",
        "Authorization is requested for specialty evaluation, diagnostic confirmation, and clinically indicated interventional treatment planning.",
        "Review is requested for specialty evaluation, diagnostic confirmation, and an indicated interventional treatment pathway.",
    )


def _build_consult_reason_suggestion(packet, raw_text):
    requested_service = _wording_fact_text(packet, "requested_service") or "specialty interventional spine consultation and treatment planning"
    diagnosis_phrase = _diagnosis_phrase(packet) or "the documented lumbar condition"
    diagnosis_with_levels = _diagnosis_with_levels_phrase(packet) or diagnosis_phrase
    mri_findings = _wording_fact_text(packet, "mri_findings") or "documented imaging findings"
    levels = _wording_fact_text(packet, "affected_levels") or "the affected lumbar level(s)"
    conservative = _wording_fact_text(packet, "conservative_history") or "appropriate conservative management"
    duration = _duration_source_text(packet) or "the documented treatment period"
    impact = _clean_functional_impact_text(_wording_fact_text(packet, "functional_impact")) or "daily function and activity tolerance"
    scenarios = [
        _make_wording_scenario(
            "Discogenic / Annular pathology consult",
            "Use when annular or discogenic pathology is documented and specialty correlation is needed.",
            (
                f"Consultation is requested for symptoms consistent with discogenic lumbar pain, with imaging findings demonstrating {mri_findings} at {levels}. "
                f"Specialty review is needed to correlate symptoms, imaging, and treatment history and to determine whether {requested_service} is clinically indicated."
            ),
            enabled=_has_annular_pattern(packet),
        ),
        _make_wording_scenario(
            "Radicular / herniation consult",
            "Use when disc displacement, herniation, or radicular symptoms are part of the presentation.",
            (
                f"Authorization is requested for consultation related to documented lumbar disc pathology involving {levels}, with persistent symptoms concerning for radicular involvement. "
                f"Diagnostic confirmation and treatment planning are needed for {diagnosis_phrase} after inadequate response to {conservative}."
            ),
            enabled=_has_radicular_pattern(packet) or _has_disc_displacement_pattern(packet),
        ),
        _make_wording_scenario(
            "Imaging correlation consult",
            "Use when MRI correlation should be stated clearly.",
            (
                f"MRI dated {_wording_fact_text(packet, 'mri_date') or 'the documented study date'} demonstrates {mri_findings}, which correlates with the Veteran's reported pain pattern and functional limitations. "
                f"Consultation and treatment planning are requested for {diagnosis_with_levels}."
            ),
            enabled=_has_imaging_correlation(packet),
        ),
        _make_wording_scenario(
            "Failed epidural / interventional history consult",
            "Use when prior epidural steroid injection or other interventional care did not produce sustained relief.",
            (
                f"Consultation is requested because the Veteran continues to report persistent, function-limiting symptoms despite prior epidural steroid injection history and other conservative measures, including {conservative}. "
                f"Specialty review is needed to reevaluate {diagnosis_with_levels} and determine the clinically appropriate next step within a defined scope of care."
            ),
            enabled=_has_failed_esi_history(packet),
        ),
        _make_wording_scenario(
            "Extended conservative care consult",
            "Use when symptoms persisted despite prolonged conservative care.",
            (
                f"Authorization is requested because symptoms have persisted despite {duration} of conservative treatment, including {conservative}. "
                f"Specialty consultation is needed to evaluate {diagnosis_with_levels} and determine indicated treatment options within the requested pathway."
            ),
            enabled=_duration_bucket(packet) in {"over_90_days", "over_6_months", "over_12_months"},
        ),
        _make_wording_scenario(
            "Functional impairment consult",
            "Use when functional limitation is the clearest reason for escalation.",
            (
                f"Consultation is requested because the Veteran reports ongoing functional limitation affecting {impact} in association with {diagnosis_with_levels}. "
                f"Symptoms remain persistent despite {conservative}, and further specialty review is needed before proceeding with {requested_service}."
            ),
            enabled=bool(_wording_fact_text(packet, "functional_impact")),
        ),
        _make_wording_scenario(
            "High-quality default consult",
            "Use when a broad but denial-resistant default is needed.",
            (
                f"Authorization is requested for {requested_service} related to documented {diagnosis_with_levels}. "
                f"The Veteran remains function-limited despite {conservative}, and the available imaging findings support the current clinical presentation."
            ),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "consult_reason", scenarios)


def _build_consult_rationale_suggestion(packet, raw_text):
    diagnosis_with_levels = _diagnosis_with_levels_phrase(packet) or "the documented lumbar condition"
    conservative = _wording_fact_text(packet, "conservative_history") or "appropriate conservative management"
    impact = _clean_functional_impact_text(_wording_fact_text(packet, "functional_impact")) or "daily function"
    mri_findings = _wording_fact_text(packet, "mri_findings") or "documented imaging findings"
    scenarios = [
        _make_wording_scenario(
            "Imaging-supported rationale",
            "Use when MRI correlation is central to medical justification.",
            (
                f"The requested consultation and treatment pathway is supported by documented {diagnosis_with_levels}, with imaging demonstrating {mri_findings} that correlate with the clinical presentation. "
                f"Persistent symptoms and reduced function despite {conservative} support specialist review and procedural planning."
            ),
            enabled=_has_imaging_correlation(packet),
        ),
        _make_wording_scenario(
            "Failed conservative care rationale",
            "Use when conservative-care failure is the primary support.",
            (
                f"The requested care pathway is supported by documented {diagnosis_with_levels}, persistent symptoms, and lack of sustained relief despite conservative treatment that has included {conservative}. "
                f"Further specialty evaluation is appropriate to determine whether the requested intervention remains clinically indicated."
            ),
            enabled=bool(_wording_fact_text(packet, "conservative_history")),
        ),
        _make_wording_scenario(
            "Occupational / daily function rationale",
            "Use when occupational or activity tolerance impairment is prominent.",
            (
                f"The requested specialty evaluation is supported by ongoing functional impairment affecting {impact}, together with documented {diagnosis_with_levels}. "
                f"Because symptoms persist despite {conservative}, additional specialty review and treatment planning are medically appropriate."
            ),
            enabled=bool(_wording_fact_text(packet, "functional_impact")),
        ),
        _make_wording_scenario(
            "Records-supported rationale",
            "Use when the packet clearly includes the diagnosis, imaging, and treatment history.",
            (
                f"This request is supported by the attached diagnosis, imaging findings, treatment history, and functional limitation details related to {diagnosis_with_levels}. "
                f"Those records support specialty consultation to confirm the pain generator and define the appropriate treatment pathway."
            ),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "consult_rationale", scenarios)


def _build_consult_scope_suggestion(packet, raw_text):
    services = _wording_fact_text(packet, "consult_requested_services") or _wording_fact_text(packet, "requested_service") or "specialty evaluation, diagnostic confirmation, indicated intervention if clinically appropriate, and standard follow-up"
    diagnosis_phrase = _diagnosis_phrase(packet) or "the documented lumbar condition"
    scenarios = [
        _make_wording_scenario(
            "Diagnostic-first consult scope",
            "Use when evaluation and confirmation should occur before any intervention is assumed.",
            (
                f"This consultation request is limited to specialty evaluation, diagnostic confirmation, and procedural planning related to {diagnosis_phrase}. "
                f"Any intervention should occur only if clinically indicated after review of the documented condition."
            ),
            enabled=not _has_specific_requested_procedure(packet),
        ),
        _make_wording_scenario(
            "Procedure-cautious consult scope",
            "Use when a procedure is named but should not sound preapproved.",
            (
                f"This request is limited to {services} related only to {diagnosis_phrase}. "
                f"The requested intervention should proceed only if clinically appropriate after specialist evaluation and diagnostic confirmation."
            ),
            enabled=_has_specific_requested_procedure(packet),
        ),
        _make_wording_scenario(
            "Non-open-ended consult scope",
            "Use when the reviewer needs reassurance that care is contained.",
            (
                f"This request is limited to {services} for {diagnosis_phrase}. "
                "It is not a request for open-ended pain management, unrelated spine care, or long-term medication management; additional or unrelated services require separate authorization."
            ),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "consult_scope", scenarios)


def _build_lomn_clinical_basis_suggestion(packet, raw_text):
    diagnosis_with_levels = _diagnosis_with_levels_phrase(packet) or "the documented lumbar condition"
    conservative = _wording_fact_text(packet, "conservative_history") or "appropriate conservative management"
    mri_date = _wording_fact_text(packet, "mri_date") or "the documented study date"
    mri_findings = _wording_fact_text(packet, "mri_findings") or "documented lumbar pathology"
    impact = _clean_functional_impact_text(_wording_fact_text(packet, "functional_impact")) or "daily function"
    scenarios = [
        _make_wording_scenario(
            "Annular / discogenic clinical basis",
            "Use when annular pathology or discogenic pain should anchor the clinical basis.",
            (
                f"The Veteran presents with symptoms consistent with discogenic lumbar pain associated with {diagnosis_with_levels}. "
                f"MRI dated {mri_date} demonstrates {mri_findings}, which correlate with the Veteran's functional limitations and persistent symptoms despite {conservative}."
            ),
            enabled=_has_annular_pattern(packet),
        ),
        _make_wording_scenario(
            "Radicular / displacement clinical basis",
            "Use when disc displacement or radicular features are part of the record.",
            (
                f"The Veteran has documented lumbar disc pathology involving {diagnosis_with_levels}, with persistent symptoms concerning for radicular involvement and reduced function in {impact}. "
                f"Those symptoms continue despite {conservative}, and imaging findings support the current clinical presentation."
            ),
            enabled=_has_radicular_pattern(packet) or _has_disc_displacement_pattern(packet),
        ),
        _make_wording_scenario(
            "Extended conservative care clinical basis",
            "Use when long-standing symptoms and conservative-care failure are the clearest support.",
            (
                f"The Veteran continues to report chronic, function-limiting symptoms related to {diagnosis_with_levels} despite {conservative} over {_duration_source_text(packet) or 'the documented treatment period'}. "
                f"MRI findings showing {mri_findings} support the need for the requested specialty evaluation and treatment pathway."
            ),
            enabled=_duration_bucket(packet) in {"over_90_days", "over_6_months", "over_12_months"},
        ),
        _make_wording_scenario(
            "Default clinical basis",
            "Use when a broad medical-necessity foundation is needed without overstating the case.",
            (
                f"The Veteran has documented {diagnosis_with_levels} with persistent, function-limiting symptoms affecting {impact}. "
                f"Imaging demonstrates {mri_findings}, and symptoms remain refractory to {conservative}."
            ),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "lomn_clinical_basis", scenarios)


def _build_lomn_medical_necessity_suggestion(packet, raw_text):
    diagnosis_phrase = _diagnosis_with_levels_phrase(packet) or "the documented lumbar condition"
    requested_service = _wording_fact_text(packet, "requested_service") or "the requested interventional pathway"
    conservative = _wording_fact_text(packet, "conservative_history") or "appropriate conservative management"
    mri_findings = _wording_fact_text(packet, "mri_findings") or "documented imaging findings"
    scenarios = [
        _make_wording_scenario(
            "Imaging-correlation necessity",
            "Use when imaging correlation is central to necessity.",
            (
                f"Based on documented {diagnosis_phrase}, imaging findings demonstrating {mri_findings}, persistent symptoms despite {conservative}, and associated functional limitation, {requested_service} is medically reasonable and necessary if clinically indicated."
            ),
            enabled=_has_imaging_correlation(packet),
        ),
        _make_wording_scenario(
            "Failed conservative care necessity",
            "Use when conservative-care failure is the strongest support.",
            (
                f"Given persistent symptoms related to {diagnosis_phrase}, inadequate sustained response to {conservative}, and ongoing functional impairment, {requested_service} is medically reasonable and necessary if clinically indicated."
            ),
            enabled=bool(_wording_fact_text(packet, "conservative_history")),
        ),
        _make_wording_scenario(
            "Procedure-specific but restrained necessity",
            "Use when the requested procedure should be named without sounding guaranteed or promotional.",
            (
                f"The requested {requested_service} is medically reasonable and necessary if clinically indicated after specialty evaluation and diagnostic confirmation. "
                f"This request is supported by documented {diagnosis_phrase}, persistent symptoms, and lack of sustained relief with conservative care."
            ),
            enabled=_has_specific_requested_procedure(packet),
        ),
        _make_wording_scenario(
            "Default medical necessity",
            "Use when a broad, denial-resistant necessity statement is needed.",
            (
                f"Based on documented {diagnosis_phrase}, persistent symptoms despite appropriate conservative management, functional limitation, and imaging findings that correlate with the clinical presentation, {requested_service} is medically reasonable and necessary if clinically indicated."
            ),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "lomn_medical_necessity", scenarios)


def _build_lomn_risk_suggestion(packet, raw_text):
    diagnosis_phrase = _diagnosis_phrase(packet) or "the documented condition"
    impact = _clean_functional_impact_text(_wording_fact_text(packet, "functional_impact")) or "daily activities"
    scenarios = [
        _make_wording_scenario(
            "Sleep / daily function risk",
            "Use when pain is disrupting sleep and routine daily function.",
            (
                f"Without timely specialty evaluation and indicated treatment for {diagnosis_phrase}, the Veteran may continue to experience persistent pain, sleep disruption, and worsening limitation in {impact}."
            ),
            enabled=_has_sleep_limitation(packet),
        ),
        _make_wording_scenario(
            "Occupational risk",
            "Use when the condition is interfering with work or role function.",
            (
                f"If specialty evaluation and indicated treatment are delayed or denied for {diagnosis_phrase}, the Veteran may continue to experience persistent pain, reduced occupational capacity, and ongoing limitation in {impact}."
            ),
            enabled=_has_occupational_limitation(packet),
        ),
        _make_wording_scenario(
            "Default risk if delayed",
            "Use when a restrained risk statement is needed.",
            (
                f"Without timely specialty evaluation and indicated treatment for {diagnosis_phrase}, the Veteran remains at risk for persistent pain, worsening functional limitation, and continued impairment of daily activities."
            ),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "lomn_risk", scenarios)


def _build_seoc_diagnosis_suggestion(packet, raw_text):
    diagnosis_with_levels = _diagnosis_with_levels_phrase(packet)
    if not diagnosis_with_levels:
        return {
            "suggestion_text": "",
            "scenario_label": "",
            "scenario_use_when": "",
        }
    scenarios = [
        _make_wording_scenario(
            "Multi-level SEOC diagnosis",
            "Use when more than one lumbar level is involved.",
            f"{diagnosis_with_levels}.",
            enabled=_has_multilevel_pattern(packet),
        ),
        _make_wording_scenario(
            "Focused SEOC diagnosis",
            "Use when the diagnosis should remain tightly aligned to the documented episode.",
            f"{diagnosis_with_levels}.",
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "seoc_diagnosis", scenarios)


def _build_seoc_scope_suggestion(packet, raw_text):
    services = _wording_fact_text(packet, "seoc_scope_items") or _wording_fact_text(packet, "requested_service") or "specialty evaluation, diagnostic confirmation, indicated intervention if clinically appropriate, and standard follow-up"
    diagnosis_phrase = _diagnosis_phrase(packet) or "the documented lumbar condition"
    scenarios = [
        _make_wording_scenario(
            "Diagnostic-first SEOC",
            "Use when evaluation and procedural planning must come before intervention.",
            (
                f"This SEOC is limited to specialty evaluation, diagnostic confirmation, and procedural planning related only to {diagnosis_phrase}. "
                "Any intervention should occur only if clinically indicated after the authorized evaluation."
            ),
            enabled=not _has_specific_requested_procedure(packet),
        ),
        _make_wording_scenario(
            "Procedure-included SEOC",
            "Use when the episode should expressly include the indicated intervention and follow-up.",
            (
                f"This SEOC is limited to {services} related only to {diagnosis_phrase}. "
                "No open-ended pain management, unrelated spine care, or long-term medication management is requested under this episode."
            ),
            enabled=_has_specific_requested_procedure(packet),
        ),
        _make_wording_scenario(
            "Contained-scope SEOC",
            "Use when the reviewer needs a tight scope statement.",
            (
                f"This SEOC is limited to {services} for {diagnosis_phrase}. "
                "Any additional or unrelated services will require separate evaluation and authorization."
            ),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "seoc_scope", scenarios)


def _build_seoc_duration_suggestion(packet, raw_text):
    duration = _wording_fact_text(packet, "estimated_duration_text")
    if not duration:
        return {
            "suggestion_text": "",
            "scenario_label": "",
            "scenario_use_when": "",
        }
    scenarios = [
        _make_wording_scenario(
            "Thirty-to-ninety-day duration",
            "Use when the episode is a common 30- to 90-day authorization window.",
            _ensure_sentence(f"The authorized episode is expected to conclude within {duration}"),
            enabled=_text_contains_any(duration, "30", "ninety", "90"),
        ),
        _make_wording_scenario(
            "Brief procedure-focused duration",
            "Use when the episode should read as short and procedure-focused.",
            _ensure_sentence(f"This defined episode of care is expected to be completed within {duration}"),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "seoc_duration", scenarios)


def _build_seoc_continuity_suggestion(packet, raw_text):
    scenarios = [
        _make_wording_scenario(
            "VA handoff continuity",
            "Use when continuity language should emphasize communication back to the VA referrer.",
            "Upon completion of the authorized episode, a treatment summary and clinical outcome update will be provided to the referring VA provider. Any additional or unrelated care will require separate evaluation and authorization.",
            enabled=True,
        ),
        _make_wording_scenario(
            "Contained continuity",
            "Use when the emphasis is that any further care needs new authorization.",
            "Following completion of the authorized episode, the referring VA provider will receive a treatment summary and outcome update. Additional or unrelated services will require separate review and authorization.",
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "seoc_continuity", scenarios)


def _build_clinical_functional_impact_suggestion(packet, raw_text):
    impact = _wording_fact_text(packet, "functional_impact")
    if not impact:
        return {
            "suggestion_text": "",
            "scenario_label": "",
            "scenario_use_when": "",
        }
    impact = _clean_functional_impact_text(impact)
    scenarios = [
        _make_wording_scenario(
            "Sleep-focused functional impact",
            "Use when sleep disruption is prominent.",
            _ensure_sentence(f"The Veteran reports sleep disruption and reduced daily function related to limitation in {impact}"),
            enabled=_has_sleep_limitation(packet),
        ),
        _make_wording_scenario(
            "Occupational functional impact",
            "Use when work capacity is being affected.",
            _ensure_sentence(f"The Veteran reports functional limitation affecting {impact}, including reduced occupational tolerance and day-to-day activity capacity"),
            enabled=_has_occupational_limitation(packet),
        ),
        _make_wording_scenario(
            "Default functional impact",
            "Use when a general provider-style function statement is needed.",
            _ensure_sentence(f"The Veteran's symptoms interfere with {impact}"),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "clinical_functional_impact", scenarios)


def _build_clinical_assessment_suggestion(packet, raw_text):
    diagnosis_with_levels = _diagnosis_with_levels_phrase(packet) or "the documented lumbar condition"
    mri_findings = _wording_fact_text(packet, "mri_findings") or "documented imaging findings"
    conservative = _wording_fact_text(packet, "conservative_history") or "appropriate conservative management"
    scenarios = [
        _make_wording_scenario(
            "Discogenic assessment",
            "Use when the presentation is discogenic or annular in pattern.",
            (
                f"The clinical presentation is consistent with discogenic lumbar pain associated with {diagnosis_with_levels}. "
                f"Imaging demonstrates {mri_findings}, and symptoms remain persistent despite {conservative}."
            ),
            enabled=_has_annular_pattern(packet),
        ),
        _make_wording_scenario(
            "Radicular / disc displacement assessment",
            "Use when radicular features or displacement findings are present.",
            (
                f"Current findings support {diagnosis_with_levels} with persistent symptoms concerning for radicular involvement. "
                f"Imaging demonstrates {mri_findings}, and symptoms remain refractory to {conservative}."
            ),
            enabled=_has_radicular_pattern(packet) or _has_disc_displacement_pattern(packet),
        ),
        _make_wording_scenario(
            "Imaging-correlation assessment",
            "Use when tying the clinical picture directly to the MRI is most important.",
            (
                f"The overall assessment is consistent with {diagnosis_with_levels}. "
                f"Imaging findings demonstrating {mri_findings} correlate with the Veteran's pain pattern and persistent symptoms despite {conservative}."
            ),
            enabled=_has_imaging_correlation(packet),
        ),
        _make_wording_scenario(
            "Default assessment",
            "Use when a concise provider-style assessment is needed.",
            (
                f"The overall assessment is consistent with documented {diagnosis_with_levels}. "
                f"Symptoms remain persistent despite {conservative} and continue to warrant specialty evaluation."
            ),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "clinical_assessment", scenarios)


def _build_clinical_treatment_plan_suggestion(packet, raw_text):
    plan_items = _wording_fact_text(packet, "clinical_plan_items") or _wording_fact_text(packet, "requested_service")
    if not plan_items:
        return {
            "suggestion_text": "",
            "scenario_label": "",
            "scenario_use_when": "",
        }
    scenarios = [
        _make_wording_scenario(
            "Diagnostic-first treatment plan",
            "Use when the provider should confirm indication before intervention.",
            (
                f"The treatment plan is limited to diagnostic confirmation and procedural planning, followed by {plan_items} only if clinically indicated. "
                "No open-ended pain management or unrelated care is requested."
            ),
            enabled=not _has_specific_requested_procedure(packet),
        ),
        _make_wording_scenario(
            "Contained intervention plan",
            "Use when the plan should remain tightly limited to the documented condition.",
            (
                f"The requested plan of care is limited to {plan_items} related only to the documented lumbar condition. "
                "This plan does not request unrelated care, long-term medication management, or broad ongoing pain management."
            ),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "clinical_treatment_plan", scenarios)


def _build_clinical_narrative_suggestion(packet, raw_text):
    diagnosis_with_levels = _diagnosis_with_levels_phrase(packet) or "the documented lumbar condition"
    requested_service = _wording_fact_text(packet, "requested_service") or "specialty evaluation and indicated treatment planning"
    conservative = _wording_fact_text(packet, "conservative_history") or "appropriate conservative management"
    mri_date = _wording_fact_text(packet, "mri_date") or "the documented study date"
    mri_findings = _wording_fact_text(packet, "mri_findings") or "documented imaging findings"
    symptom_summary = _wording_fact_text(packet, "symptom_summary") or "persistent function-limiting lumbar symptoms"
    impact = _clean_functional_impact_text(_wording_fact_text(packet, "functional_impact")) or "daily function"
    scenarios = [
        _make_wording_scenario(
            "Discogenic narrative",
            "Use when the packet points to discogenic or annular pathology.",
            (
                f"The Veteran presents with chronic, function-limiting lumbar symptoms associated with {diagnosis_with_levels}. "
                f"Symptoms include {symptom_summary.lower()} and interfere with {impact}. MRI dated {mri_date} demonstrates {mri_findings}, which correlate with the clinical presentation. "
                f"Symptoms have persisted despite {conservative}. Based on the documented condition, imaging correlation, and failed conservative management, {requested_service} is medically appropriate if clinically indicated."
            ),
            enabled=_has_annular_pattern(packet),
        ),
        _make_wording_scenario(
            "Radicular / displacement narrative",
            "Use when displacement findings or radicular features are present.",
            (
                f"The Veteran presents with {diagnosis_with_levels} and persistent symptoms concerning for radicular involvement. "
                f"These symptoms continue to impair {impact} despite {conservative}. MRI dated {mri_date} demonstrates {mri_findings}, and the imaging findings correlate with the current clinical picture. "
                f"Specialty evaluation and {requested_service} are medically appropriate for consideration if clinically indicated."
            ),
            enabled=_has_radicular_pattern(packet) or _has_disc_displacement_pattern(packet),
        ),
        _make_wording_scenario(
            "Long-duration narrative",
            "Use when chronicity and failed conservative care are the strongest support.",
            (
                f"The Veteran has chronic, function-limiting symptoms related to {diagnosis_with_levels} that have persisted despite {conservative} over {_duration_source_text(packet) or 'the documented treatment period'}. "
                f"MRI dated {mri_date} demonstrates {mri_findings}, and those findings correlate with the clinical presentation. "
                f"Given the persistent symptoms, documented functional limitation, and failure of conservative management, {requested_service} is medically reasonable for consideration if clinically indicated."
            ),
            enabled=_duration_bucket(packet) in {"over_90_days", "over_6_months", "over_12_months"},
        ),
        _make_wording_scenario(
            "Default physician narrative",
            "Use when a broad provider-authored narrative is needed.",
            (
                f"The Veteran presents with chronic, function-limiting lumbar pain associated with {diagnosis_with_levels}. "
                f"Symptoms interfere with {impact}. MRI dated {mri_date} demonstrates {mri_findings}, which correlate with the clinical presentation. "
                f"Symptoms have persisted despite {conservative}. Based on the documented condition, imaging correlation, and failed conservative management, {requested_service} is medically appropriate if clinically indicated."
            ),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "clinical_narrative", scenarios)


def _build_va_reason_for_request_suggestion(packet, raw_text):
    diagnosis_with_levels = _diagnosis_with_levels_phrase(packet) or "the documented lumbar condition"
    requested_service = _wording_fact_text(packet, "requested_service") or "specialty interventional spine evaluation and treatment planning"
    conservative = _wording_fact_text(packet, "conservative_history") or "appropriate conservative management"
    mri_date = _wording_fact_text(packet, "mri_date") or "the documented study date"
    mri_findings = _wording_fact_text(packet, "mri_findings") or "documented imaging findings"
    duration = _duration_source_text(packet) or "the documented treatment period"
    impact = _clean_functional_impact_text(_wording_fact_text(packet, "functional_impact")) or "daily function and activity tolerance"
    scenarios = [
        _make_wording_scenario(
            "Annular / discogenic 10-10172 request",
            "Use when MRI documents annular pathology or the case reads as discogenic pain.",
            (
                f"Authorization is requested for evaluation and treatment planning for discogenic lumbar pain associated with {mri_findings} at {_wording_fact_text(packet, 'affected_levels') or 'the documented lumbar level(s)'}. "
                f"Symptoms persist despite conservative management including {conservative}. Requested services are limited to specialty consultation, diagnostic confirmation, indicated intervention if clinically appropriate, and routine follow-up."
            ),
            enabled=_has_annular_pattern(packet),
        ),
        _make_wording_scenario(
            "Radicular / herniation 10-10172 request",
            "Use when disc displacement or radicular symptoms are documented.",
            (
                f"The Veteran has documented lumbar disc pathology involving {diagnosis_with_levels}, with persistent symptoms concerning for radicular involvement despite conservative care. "
                f"Authorization is requested for specialty evaluation, diagnostic confirmation, and indicated interventional treatment planning related to the documented condition."
            ),
            enabled=_has_radicular_pattern(packet) or _has_disc_displacement_pattern(packet),
        ),
        _make_wording_scenario(
            "Imaging correlation 10-10172 request",
            "Use when MRI correlation should anchor the reason-for-request field.",
            (
                f"Authorization is requested because MRI dated {mri_date} demonstrates {mri_findings}, which correlates with the Veteran's clinical presentation and functional limitations. "
                f"Symptoms have persisted despite {conservative}. Requested care is limited to specialty evaluation, procedural planning, indicated intervention if clinically appropriate, and standard follow-up."
            ),
            enabled=_has_imaging_correlation(packet),
        ),
        _make_wording_scenario(
            "Extended conservative care 10-10172 request",
            "Use when conservative care has been prolonged without sustained relief.",
            (
                f"Authorization is requested for a defined specialty interventional spine evaluation and treatment pathway for {diagnosis_with_levels}. "
                f"The Veteran has chronic, function-limiting symptoms that persist despite {conservative} over {duration}. Requested services are limited to diagnostic confirmation, indicated intervention if clinically appropriate, and routine post-procedure follow-up."
            ),
            enabled=_duration_bucket(packet) in {"over_90_days", "over_6_months", "over_12_months"},
        ),
        _make_wording_scenario(
            "SEOC-limited 10-10172 request",
            "Use when the reason-for-request field should clearly reject open-ended care.",
            (
                f"This request is for a defined specialty evaluation and treatment pathway related only to {diagnosis_with_levels}. "
                f"It is not a request for open-ended pain management, unrelated spine care, or long-term medication management. The Veteran remains function-limited in {impact} despite {conservative}."
            ),
            enabled=True,
        ),
        _make_wording_scenario(
            "High-quality default 10-10172 request",
            "Use when a general best-default reason-for-request is needed.",
            (
                f"Authorization is requested for {requested_service} related to documented {diagnosis_with_levels}. "
                f"The Veteran has chronic, function-limiting symptoms that correlate with imaging findings and persist despite {conservative}. Requested care is limited to diagnostic confirmation, indicated intervention if clinically appropriate, and routine follow-up."
            ),
            enabled=True,
        ),
    ]
    return _select_wording_blueprint(packet, "va_reason_for_request", scenarios)


WORDING_ASSIST_SPECS = {
    "va_form_10_10172": [
        {
            "key": "va_reason_for_request",
            "label": "Reason for Request",
            "field_name": "va10172_reason_for_request",
            "required_facts": ["diagnosis", "icd_codes", "requested_service", "mri_findings", "symptom_summary", "conservative_history"],
            "builder": _build_va_reason_for_request_suggestion,
        },
    ],
    "lomn": [
        {
            "key": "lomn_clinical_basis",
            "label": "Clinical Basis",
            "field_name": "lmn_clinical_summary",
            "required_facts": ["diagnosis", "icd_codes", "mri_date", "mri_findings", "symptom_summary", "conservative_history"],
            "builder": _build_lomn_clinical_basis_suggestion,
        },
        {
            "key": "lomn_medical_necessity",
            "label": "Medical Necessity",
            "field_name": "lmn_medical_necessity_statement",
            "required_facts": ["diagnosis", "requested_service", "functional_impact", "conservative_history", "mri_findings"],
            "builder": _build_lomn_medical_necessity_suggestion,
        },
        {
            "key": "lomn_risk_if_delayed",
            "label": "Risk if Delayed / Denied",
            "field_name": "lmn_risk_statement",
            "required_facts": ["diagnosis", "functional_impact"],
            "builder": _build_lomn_risk_suggestion,
        },
    ],
    "consult": [
        {
            "key": "consult_reason",
            "label": "Reason for Consultation",
            "field_name": "consult_reason_text",
            "required_facts": ["diagnosis", "requested_service", "symptom_summary"],
            "builder": _build_consult_reason_suggestion,
        },
        {
            "key": "consult_rationale",
            "label": "Medical Rationale",
            "field_name": "consult_medical_rationale_text",
            "required_facts": ["diagnosis", "functional_impact", "conservative_history", "mri_findings"],
            "builder": _build_consult_rationale_suggestion,
        },
        {
            "key": "consult_scope",
            "label": "Scope of Request",
            "field_name": "consult_scope_exclusion_text",
            "required_facts": ["diagnosis", "consult_requested_services"],
            "builder": _build_consult_scope_suggestion,
        },
    ],
    "seoc": [
        {
            "key": "seoc_diagnosis_language",
            "label": "Diagnosis Language",
            "field_name": "episode_diagnosis",
            "required_facts": ["diagnosis", "icd_codes"],
            "builder": _build_seoc_diagnosis_suggestion,
        },
        {
            "key": "seoc_scope_language",
            "label": "Scope of Request",
            "field_name": "seoc_scope_text",
            "required_facts": ["diagnosis", "seoc_scope_items"],
            "builder": _build_seoc_scope_suggestion,
        },
        {
            "key": "seoc_duration_language",
            "label": "Duration Language",
            "field_name": "estimated_duration_text",
            "required_facts": ["estimated_duration_text"],
            "builder": _build_seoc_duration_suggestion,
        },
        {
            "key": "seoc_continuity_language",
            "label": "Continuity of Care Language",
            "field_name": "seoc_continuity_text",
            "required_facts": ["ordering_doctor", "facility"],
            "builder": _build_seoc_continuity_suggestion,
        },
    ],
    "clinical": [
        {
            "key": "clinical_functional_impact",
            "label": "Functional Impact",
            "field_name": "clinical_doc_functional_impact",
            "required_facts": ["clinical_limitations"],
            "builder": _build_clinical_functional_impact_suggestion,
        },
        {
            "key": "clinical_assessment",
            "label": "Assessment",
            "field_name": "clinical_doc_assessment_summary",
            "required_facts": ["symptom_summary", "diagnosis", "mri_findings", "conservative_history"],
            "builder": _build_clinical_assessment_suggestion,
        },
        {
            "key": "clinical_treatment_plan",
            "label": "Treatment Plan",
            "field_name": "clinical_doc_treatment_plan_intro",
            "required_facts": ["requested_service", "clinical_plan_items"],
            "builder": _build_clinical_treatment_plan_suggestion,
        },
        {
            "key": "clinical_physician_narrative",
            "label": "Physician Narrative Paragraph",
            "field_name": "clinical_doc_physician_narrative",
            "required_facts": ["symptom_summary", "diagnosis", "functional_impact", "conservative_history", "mri_findings"],
            "builder": _build_clinical_narrative_suggestion,
        },
    ],
}


def wording_assist_specs_for_profile(profile_name):
    if is_va_10172_profile(profile_name):
        return WORDING_ASSIST_SPECS["va_form_10_10172"]
    if is_lomn_profile(profile_name):
        return WORDING_ASSIST_SPECS["lomn"]
    if is_consult_request_profile(profile_name):
        return WORDING_ASSIST_SPECS["consult"]
    if is_seoc_request_profile(profile_name):
        return WORDING_ASSIST_SPECS["seoc"]
    if is_clinical_documentation_profile(profile_name):
        return WORDING_ASSIST_SPECS["clinical"]
    return []


def build_wording_risk_messages(text):
    return build_wording_risk_messages_impl(
        text,
        sanitize_packet_builder_text_fn=sanitize_packet_builder_text,
    )


def build_wording_assist_entries(payload):
    return build_wording_assist_entries_impl(
        payload,
        normalize_packet_builder_payload_fn=normalize_packet_builder_payload,
        wording_assist_specs_for_profile_fn=wording_assist_specs_for_profile,
        sanitize_packet_builder_text_fn=sanitize_packet_builder_text,
        wording_fact_text_fn=_wording_fact_text,
        wording_review_decisions=WORDING_REVIEW_DECISIONS,
        wording_fact_labels=WORDING_FACT_LABELS,
    )


def build_wording_assist_banner(payload):
    return build_wording_assist_banner_impl(
        payload,
        build_wording_assist_entries_fn=build_wording_assist_entries,
    )


def should_enforce_wording_assist(payload, group_name=""):
    return should_enforce_wording_assist_impl(
        payload,
        normalize_packet_builder_payload_fn=normalize_packet_builder_payload,
    )


def build_wording_export_blockers(payload, group_name=""):
    return build_wording_export_blockers_impl(
        payload,
        group_name=group_name,
        normalize_packet_builder_payload_fn=normalize_packet_builder_payload,
        should_enforce_wording_assist_fn=should_enforce_wording_assist,
        build_profile_export_payload_fn=build_profile_export_payload,
        build_wording_assist_entries_fn=build_wording_assist_entries,
    )


def _default_export_dir():
    return default_export_dir_impl()


def _default_va_form_10172_template_path():
    return default_va_form_10172_template_path_impl()


DEFAULT_DEV_TOOLS_CONFIG = default_dev_tools_config()

PACKET_WIDGET_BINDINGS = {
    "packet_title": ("packet_title_input", "text"),
    "packet_profile": ("profile_combo", "currentText"),
    "patient_name": ("patient_name_input", "text"),
    "date_of_birth": ("dob_input", "text"),
    "authorization_number": ("auth_input", "text"),
    "va_icn": ("icn_input", "text"),
    "ordering_doctor": ("ordering_doctor_input", "text"),
    "provider": ("provider_input", "text"),
    "facility": ("facility_input", "text"),
    "community_facility": ("community_facility_input", "text"),
    "requested_service": ("requested_service_input", "text"),
    "diagnosis": ("diagnosis_input", "text"),
    "secondary_diagnosis": ("secondary_diagnosis_input", "text"),
    "icd_codes": ("icd_codes_input", "text"),
    "master_requested_cpt_code": ("master_requested_cpt_code_input", "text"),
    "master_provider_credentials": ("master_provider_credentials_input", "text"),
    "master_provider_specialty": ("master_provider_specialty_input", "text"),
    "master_provider_npi": ("master_provider_npi_input", "text"),
    "master_practice_name": ("master_practice_name_input", "text"),
    "master_provider_phone": ("master_provider_phone_input", "text"),
    "master_provider_fax": ("master_provider_fax_input", "text"),
    "master_provider_email": ("master_provider_email_input", "text"),
    "master_provider_address": ("master_provider_address_input", "toPlainText"),
    "master_mri_date": ("master_mri_date_input", "text"),
    "master_mri_findings": ("master_mri_findings_input", "text"),
    "master_affected_levels": ("master_affected_levels_input", "text"),
    "clinical_summary": ("clinical_summary_input", "toPlainText"),
    "packet_notes": ("packet_notes_input", "toPlainText"),
    "scenario_pathology_pattern": ("scenario_pathology_pattern_input", "text"),
    "scenario_conservative_duration": ("scenario_conservative_duration_input", "text"),
    "scenario_prior_esi_response": ("scenario_prior_esi_response_input", "text"),
    "scenario_functional_emphasis": ("scenario_functional_emphasis_input", "text"),
    "scenario_request_framing": ("scenario_request_framing_input", "text"),
    "scenario_symptom_pattern": ("scenario_symptom_pattern_input", "text"),
    "scenario_conservative_modalities": ("scenario_conservative_modalities_input", "text"),
    "scenario_review_concern": ("scenario_review_concern_input", "text"),
    "scenario_treatment_goals": ("scenario_treatment_goals_input", "text"),
    "referral_subtitle": ("referral_subtitle_input", "text"),
    "pcp_request_text": ("pcp_request_input", "text"),
    "referral_entry_text": ("referral_entry_input", "text"),
    "areas_of_concern": ("areas_of_concern_input", "text"),
    "group_npi": ("group_npi_input", "text"),
    "fax_number": ("fax_number_input", "text"),
    "liaison_contact_info": ("liaison_contact_input", "toPlainText"),
    "consent_form_title": ("consent_form_title_input", "text"),
    "street_address": ("street_address_input", "text"),
    "city": ("city_input", "text"),
    "state": ("state_input", "text"),
    "zip_code": ("zip_code_input", "text"),
    "home_phone": ("home_phone_input", "text"),
    "mobile_phone": ("mobile_phone_input", "text"),
    "work_phone": ("work_phone_input", "text"),
    "email_address": ("email_address_input", "text"),
    "ssn": ("ssn_input", "text"),
    "drivers_license": ("drivers_license_input", "text"),
    "drivers_license_state": ("drivers_license_state_input", "text"),
    "appointment_confirmation_method": ("appointment_confirmation_combo", "currentText"),
    "filed_for_disability": ("filed_for_disability_combo", "currentText"),
    "condition_work_related": ("condition_work_related_combo", "currentText"),
    "condition_due_to_accident": ("condition_due_to_accident_combo", "currentText"),
    "yes_response_explanation": ("yes_response_explanation_input", "toPlainText"),
    "has_attorney": ("has_attorney_combo", "currentText"),
    "attorney_name": ("attorney_name_input", "text"),
    "attorney_phone": ("attorney_phone_input", "text"),
    "emergency_contact_name": ("emergency_contact_name_input", "text"),
    "emergency_contact_relationship": ("emergency_contact_relationship_input", "text"),
    "emergency_contact_phone": ("emergency_contact_phone_input", "text"),
    "primary_insurance_carrier": ("primary_insurance_carrier_input", "text"),
    "primary_insurance_id": ("primary_insurance_id_input", "text"),
    "primary_insurance_phone": ("primary_insurance_phone_input", "text"),
    "secondary_insurance_carrier": ("secondary_insurance_carrier_input", "text"),
    "secondary_insurance_id": ("secondary_insurance_id_input", "text"),
    "secondary_insurance_phone": ("secondary_insurance_phone_input", "text"),
    "pcp_pcm_name": ("pcp_pcm_name_input", "text"),
    "pcp_pcm_phone": ("pcp_pcm_phone_input", "text"),
    "pcp_pcm_fax": ("pcp_pcm_fax_input", "text"),
    "consent_provider_name": ("consent_provider_name_input", "text"),
    "consent_initials": ("consent_initials_input", "text"),
    "minor_doctor_name": ("minor_doctor_name_input", "text"),
    "minor_consent_initials": ("minor_consent_initials_input", "text"),
    "service_authorization_name": ("service_authorization_name_input", "text"),
    "patient_signature_name": ("patient_signature_name_input", "text"),
    "patient_signature_date": ("patient_signature_date_input", "text"),
    "submission_cover_title": ("submission_cover_title_input", "text"),
    "submission_date": ("submission_date_input", "text"),
    "primary_diagnosis_code": ("primary_diagnosis_code_input", "text"),
    "included_virtual_consent_form": ("included_virtual_consent_checkbox", "isChecked"),
    "included_va_form_10_10172": ("included_va_form_checkbox", "isChecked"),
    "included_seoc_request": ("included_seoc_checkbox", "isChecked"),
    "included_consult_request": ("included_consult_checkbox", "isChecked"),
    "included_lomn": ("included_lomn_checkbox", "isChecked"),
    "included_clinical_notes": ("included_clinical_notes_checkbox", "isChecked"),
    "included_mri_report": ("included_mri_checkbox", "isChecked"),
    "submitting_office": ("submitting_office_input", "text"),
    "office_staff_name": ("office_staff_name_input", "text"),
    "office_staff_signature": ("office_staff_signature_input", "text"),
    "date_reviewed": ("date_reviewed_input", "text"),
    "seoc_request_date": ("seoc_request_date_input", "text"),
    "va_medical_center_name": ("va_medical_center_input", "text"),
    "last_four_ssn": ("last_four_ssn_input", "text"),
    "episode_diagnosis": ("episode_diagnosis_input", "text"),
    "episode_icd_code": ("episode_icd_code_input", "text"),
    "seoc_scope_text": ("seoc_scope_text_input", "toPlainText"),
    "estimated_duration_text": ("estimated_duration_input", "text"),
    "clinical_objectives": ("clinical_objectives_input", "toPlainText"),
    "seoc_continuity_text": ("seoc_continuity_text_input", "toPlainText"),
    "provider_credentials": ("provider_credentials_input", "text"),
    "provider_specialty": ("provider_specialty_input", "text"),
    "provider_npi": ("provider_npi_input", "text"),
    "practice_name": ("practice_name_input", "text"),
    "provider_phone": ("provider_phone_input", "text"),
    "provider_fax": ("provider_fax_input", "text"),
    "seoc_include_preprocedure_eval": ("seoc_preprocedure_checkbox", "isChecked"),
    "seoc_include_annulargram": ("seoc_annulargram_checkbox", "isChecked"),
    "seoc_include_fibrin_injection": ("seoc_fibrin_checkbox", "isChecked"),
    "seoc_include_follow_up": ("seoc_follow_up_checkbox", "isChecked"),
    "lmn_request_date": ("lomn_request_date_input", "text"),
    "lmn_va_claim_number": ("lomn_va_claim_number_input", "text"),
    "lmn_primary_diagnosis": ("lomn_primary_diagnosis_input", "text"),
    "lmn_secondary_diagnosis": ("lomn_secondary_diagnosis_input", "text"),
    "lmn_clinical_summary": ("lomn_clinical_summary_input", "toPlainText"),
    "lmn_mri_date": ("lomn_mri_date_input", "text"),
    "lmn_mri_findings": ("lomn_mri_findings_input", "text"),
    "lmn_conservative_duration": ("lomn_conservative_duration_input", "text"),
    "lmn_include_physical_therapy": ("lomn_physical_therapy_checkbox", "isChecked"),
    "lmn_include_nsaids": ("lomn_nsaids_checkbox", "isChecked"),
    "lmn_include_activity_modification": ("lomn_activity_modification_checkbox", "isChecked"),
    "lmn_include_home_exercise": ("lomn_home_exercise_checkbox", "isChecked"),
    "lmn_include_epidural_steroid_injections": ("lomn_esi_checkbox", "isChecked"),
    "lmn_medical_necessity_statement": ("lomn_medical_necessity_input", "toPlainText"),
    "lmn_indication_reduce_pain": ("lomn_reduce_pain_checkbox", "isChecked"),
    "lmn_indication_improve_function": ("lomn_improve_function_checkbox", "isChecked"),
    "lmn_indication_prevent_degeneration": ("lomn_prevent_degeneration_checkbox", "isChecked"),
    "lmn_indication_reduce_opioid_reliance": ("lomn_reduce_opioids_checkbox", "isChecked"),
    "lmn_indication_prevent_surgery": ("lomn_prevent_surgery_checkbox", "isChecked"),
    "lmn_risk_statement": ("lomn_risk_statement_input", "toPlainText"),
    "lmn_reasonable_necessary_statement": ("lomn_reasonable_statement_input", "toPlainText"),
    "lmn_contact_statement": ("lomn_contact_statement_input", "toPlainText"),
    "consult_request_date": ("consult_request_date_input", "text"),
    "consult_va_claim_number": ("consult_va_claim_number_input", "text"),
    "consult_referring_va_provider": ("consult_referring_va_provider_input", "text"),
    "consult_reason_text": ("consult_reason_input", "toPlainText"),
    "consult_primary_diagnosis": ("consult_primary_diagnosis_input", "text"),
    "consult_secondary_diagnosis": ("consult_secondary_diagnosis_input", "text"),
    "consult_symptom_axial_pain": ("consult_symptom_axial_pain_checkbox", "isChecked"),
    "consult_symptom_activity_exacerbation": ("consult_symptom_activity_checkbox", "isChecked"),
    "consult_symptom_reduced_tolerance": ("consult_symptom_tolerance_checkbox", "isChecked"),
    "consult_symptom_functional_impairment": ("consult_symptom_function_checkbox", "isChecked"),
    "consult_mri_date": ("consult_mri_date_input", "text"),
    "consult_mri_findings": ("consult_mri_findings_input", "text"),
    "consult_conservative_duration": ("consult_conservative_duration_input", "text"),
    "consult_include_physical_therapy": ("consult_physical_therapy_checkbox", "isChecked"),
    "consult_include_nsaids": ("consult_nsaids_checkbox", "isChecked"),
    "consult_include_activity_modification": ("consult_activity_mod_checkbox", "isChecked"),
    "consult_include_home_exercise": ("consult_home_exercise_checkbox", "isChecked"),
    "consult_include_interventional_history": ("consult_interventional_history_checkbox", "isChecked"),
    "consult_include_pain_management_consultation": ("consult_include_pm_consult_checkbox", "isChecked"),
    "consult_include_procedural_planning": ("consult_include_planning_checkbox", "isChecked"),
    "consult_include_annulargram": ("consult_include_annulargram_checkbox", "isChecked"),
    "consult_include_fibrin_injection": ("consult_include_fibrin_checkbox", "isChecked"),
    "consult_include_follow_up": ("consult_include_follow_up_checkbox", "isChecked"),
    "consult_fibrin_levels": ("consult_fibrin_levels_input", "text"),
    "consult_scope_exclusion_text": ("consult_scope_exclusion_input", "toPlainText"),
    "consult_medical_rationale_text": ("consult_medical_rationale_input", "toPlainText"),
    "consult_goal_pain_reduction": ("consult_goal_pain_checkbox", "isChecked"),
    "consult_goal_functional_improvement": ("consult_goal_function_checkbox", "isChecked"),
    "consult_goal_reduce_analgesics": ("consult_goal_analgesics_checkbox", "isChecked"),
    "consult_goal_prevent_surgery": ("consult_goal_surgery_checkbox", "isChecked"),
    "consult_risk_without_treatment": ("consult_risk_without_treatment_input", "toPlainText"),
    "consult_duration_scope_text": ("consult_duration_scope_input", "toPlainText"),
    "consult_contact_statement": ("consult_contact_statement_input", "toPlainText"),
    "provider_address": ("provider_address_input", "text"),
    "provider_email": ("provider_email_input", "text"),
    "clinical_doc_title": ("clinical_doc_title_input", "text"),
    "clinical_doc_chief_complaint": ("clinical_doc_chief_complaint_input", "text"),
    "clinical_doc_duration_gt_3m": ("clinical_doc_duration_3m_checkbox", "isChecked"),
    "clinical_doc_duration_gt_6m": ("clinical_doc_duration_6m_checkbox", "isChecked"),
    "clinical_doc_duration_gt_12m": ("clinical_doc_duration_12m_checkbox", "isChecked"),
    "clinical_doc_exact_duration": ("clinical_doc_exact_duration_input", "text"),
    "clinical_doc_pain_axial": ("clinical_doc_pain_axial_checkbox", "isChecked"),
    "clinical_doc_pain_discogenic": ("clinical_doc_pain_discogenic_checkbox", "isChecked"),
    "clinical_doc_pain_activity_exacerbation": ("clinical_doc_pain_activity_checkbox", "isChecked"),
    "clinical_doc_pain_sitting_intolerance": ("clinical_doc_pain_sitting_checkbox", "isChecked"),
    "clinical_doc_pain_standing_intolerance": ("clinical_doc_pain_standing_checkbox", "isChecked"),
    "clinical_doc_pain_bending_lifting": ("clinical_doc_pain_bending_checkbox", "isChecked"),
    "clinical_doc_pain_severity": ("clinical_doc_pain_severity_input", "text"),
    "clinical_doc_limit_occupational": ("clinical_doc_limit_occupational_checkbox", "isChecked"),
    "clinical_doc_limit_prolonged_sitting": ("clinical_doc_limit_sitting_checkbox", "isChecked"),
    "clinical_doc_limit_prolonged_standing": ("clinical_doc_limit_standing_checkbox", "isChecked"),
    "clinical_doc_limit_ambulation": ("clinical_doc_limit_ambulation_checkbox", "isChecked"),
    "clinical_doc_limit_household": ("clinical_doc_limit_household_checkbox", "isChecked"),
    "clinical_doc_limit_sleep": ("clinical_doc_limit_sleep_checkbox", "isChecked"),
    "clinical_doc_functional_impact": ("clinical_doc_functional_impact_input", "toPlainText"),
    "clinical_doc_conservative_pt": ("clinical_doc_conservative_pt_checkbox", "isChecked"),
    "clinical_doc_conservative_home_exercise": ("clinical_doc_conservative_home_exercise_checkbox", "isChecked"),
    "clinical_doc_conservative_nsaids": ("clinical_doc_conservative_nsaids_checkbox", "isChecked"),
    "clinical_doc_conservative_non_opioid": ("clinical_doc_conservative_non_opioid_checkbox", "isChecked"),
    "clinical_doc_conservative_activity_modification": ("clinical_doc_conservative_activity_checkbox", "isChecked"),
    "clinical_doc_conservative_esi": ("clinical_doc_conservative_esi_checkbox", "isChecked"),
    "clinical_doc_conservative_other_interventional": ("clinical_doc_conservative_other_checkbox", "isChecked"),
    "clinical_doc_conservative_duration": ("clinical_doc_conservative_duration_input", "text"),
    "clinical_doc_esi_response": ("clinical_doc_esi_response_combo", "currentText"),
    "clinical_doc_mri_date": ("clinical_doc_mri_date_input", "text"),
    "clinical_doc_imaging_annular_tear": ("clinical_doc_imaging_annular_checkbox", "isChecked"),
    "clinical_doc_imaging_disc_degeneration": ("clinical_doc_imaging_degeneration_checkbox", "isChecked"),
    "clinical_doc_imaging_disc_protrusion": ("clinical_doc_imaging_protrusion_checkbox", "isChecked"),
    "clinical_doc_imaging_disc_displacement": ("clinical_doc_imaging_displacement_checkbox", "isChecked"),
    "clinical_doc_affected_levels": ("clinical_doc_affected_levels_input", "text"),
    "clinical_doc_primary_diagnosis": ("clinical_doc_primary_diagnosis_input", "text"),
    "clinical_doc_secondary_diagnosis": ("clinical_doc_secondary_diagnosis_input", "text"),
    "clinical_doc_assessment_summary": ("clinical_doc_assessment_summary_input", "toPlainText"),
    "clinical_doc_treatment_plan_intro": ("clinical_doc_treatment_plan_intro_input", "toPlainText"),
    "clinical_doc_plan_diagnostic_confirmation": ("clinical_doc_plan_diagnostic_checkbox", "isChecked"),
    "clinical_doc_plan_intradiscal_intervention": ("clinical_doc_plan_intervention_checkbox", "isChecked"),
    "clinical_doc_plan_follow_up": ("clinical_doc_plan_follow_up_checkbox", "isChecked"),
    "clinical_doc_plan_exclusion": ("clinical_doc_plan_exclusion_input", "toPlainText"),
    "clinical_doc_physician_narrative": ("clinical_doc_physician_narrative_input", "toPlainText"),
    "va10172_va_facility_address": ("va10172_facility_address_input", "toPlainText"),
    "va10172_ordering_provider_office_address": ("va10172_provider_office_address_input", "toPlainText"),
    "va10172_is_ihs_provider": ("va10172_is_ihs_combo", "currentText"),
    "va10172_ordering_provider_phone": ("va10172_provider_phone_input", "text"),
    "va10172_ordering_provider_fax": ("va10172_provider_fax_input", "text"),
    "va10172_ordering_provider_secure_email": ("va10172_provider_email_input", "text"),
    "va10172_care_needed_within_48_hours": ("va10172_48h_combo", "currentText"),
    "va10172_is_continuation_of_care": ("va10172_continuation_combo", "currentText"),
    "va10172_referral_to_specialty": ("va10172_referral_specialty_combo", "currentText"),
    "va10172_referral_specialty_text": ("va10172_referral_specialty_text_input", "text"),
    "va10172_diagnosis_description": ("va10172_diagnosis_description_input", "toPlainText"),
    "va10172_requested_cpt_hcpcs_code": ("va10172_requested_cpt_input", "text"),
    "va10172_description_cpt_hcpcs_code": ("va10172_requested_cpt_description_input", "text"),
    "va10172_geriatric_care_option": ("va10172_geriatric_option_combo", "currentText"),
    "va10172_reason_for_request": ("va10172_reason_for_request_input", "toPlainText"),
    "va10172_ordering_provider_name_printed": ("va10172_provider_name_printed_input", "text"),
    "va10172_ordering_provider_npi": ("va10172_provider_npi_input", "text"),
    "va10172_signature_text": ("va10172_signature_text_input", "text"),
    "va10172_today_date": ("va10172_today_date_input", "text"),
}


def _deep_merge(base, updates):
    return deep_merge_impl(base, updates)


def normalize_dev_tools_config(
    data=None,
    *,
    default_config=None,
    default_export_dir_fn=None,
    default_va_form_10172_template_path_fn=None,
):
    return normalize_dev_tools_config_impl(
        data,
        default_config=default_config or DEFAULT_DEV_TOOLS_CONFIG,
        default_export_dir_fn=default_export_dir_fn or _default_export_dir,
        default_va_form_10172_template_path_fn=default_va_form_10172_template_path_fn or _default_va_form_10172_template_path,
    )


def load_dev_tools_config():
    return load_dev_tools_config_impl(
        config_path=DEV_TOOLS_CONFIG_PATH,
        default_config=DEFAULT_DEV_TOOLS_CONFIG,
        normalize_dev_tools_config_fn=normalize_dev_tools_config,
    )


def save_dev_tools_config(data):
    return save_dev_tools_config_impl(
        data,
        config_path=DEV_TOOLS_CONFIG_PATH,
        default_config=DEFAULT_DEV_TOOLS_CONFIG,
        normalize_dev_tools_config_fn=normalize_dev_tools_config,
    )


def update_dev_tools_config(changes):
    return update_dev_tools_config_impl(
        changes,
        config_path=DEV_TOOLS_CONFIG_PATH,
        default_config=DEFAULT_DEV_TOOLS_CONFIG,
        load_dev_tools_config_fn=load_dev_tools_config_impl,
        save_dev_tools_config_fn=save_dev_tools_config_impl,
    )


def build_profile_export_payload(base_payload, profile_name):
    return build_profile_export_payload_impl(
        base_payload,
        profile_name,
        normalize_packet_builder_payload_fn=normalize_packet_builder_payload,
        apply_packet_builder_shared_field_sync_fn=apply_packet_builder_shared_field_sync,
    )


def build_profile_current_form_checks(profile_name, packet):
    return build_profile_current_form_checks_impl(profile_name, packet)


def build_packet_inconsistency_messages(packet):
    return build_packet_inconsistency_messages_impl(packet)


def _has_meaningful_value(value):
    return has_meaningful_value_impl(value)


def _first_icd_code(value):
    return first_icd_code_impl(value)


def _can_replace_with_shared_value(current_value, fallback_values=None):
    return can_replace_with_shared_value_impl(current_value, fallback_values)


def apply_packet_builder_shared_field_sync(payload):
    return apply_packet_builder_shared_field_sync_impl(
        payload,
        default_packet_builder_payload_fn=default_packet_builder_payload,
    )


def build_packet_lab_report(payload):
    return build_packet_lab_report_impl(
        payload,
        apply_packet_builder_shared_field_sync_fn=apply_packet_builder_shared_field_sync,
        default_packet_builder_payload_fn=default_packet_builder_payload,
        has_meaningful_value_fn=_has_meaningful_value,
        shared_packet_header_fields=SHARED_PACKET_HEADER_FIELDS,
        build_profile_current_form_checks_fn=build_profile_current_form_checks,
        build_packet_inconsistency_messages_fn=build_packet_inconsistency_messages,
        build_wording_assist_entries_fn=build_wording_assist_entries,
    )


def classify_packet_lab_completion(report):
    return classify_packet_lab_completion_impl(report)


def packet_profile_status_palette(status_key):
    return packet_profile_status_palette_impl(status_key)


def build_packet_lab_html(payload):
    return build_packet_lab_html_impl(
        payload,
        build_packet_lab_report_fn=build_packet_lab_report,
        render_packet_builder_document_preview_fn=render_packet_builder_document_preview,
    )


def ensure_packet_library_dir():
    return ensure_packet_library_dir_impl()


def packet_library_record_path(draft_id):
    return packet_library_record_path_impl(draft_id)


def generate_packet_library_draft_id():
    return generate_packet_library_draft_id_impl()


def packet_library_display_name(payload, base_filename=""):
    return packet_library_display_name_impl(
        payload,
        base_filename,
        normalize_packet_builder_payload_fn=normalize_packet_builder_payload,
    )


def build_packet_library_completion(payload):
    return build_packet_library_completion_impl(
        payload,
        normalize_packet_builder_payload_fn=normalize_packet_builder_payload,
        build_profile_export_payload_fn=build_profile_export_payload,
        build_packet_lab_report_fn=build_packet_lab_report,
    )


def build_export_warning_context(payload, group_name=""):
    return build_export_warning_context_impl(
        payload,
        group_name=group_name,
        normalize_packet_builder_payload_fn=normalize_packet_builder_payload,
        build_packet_library_completion_fn=build_packet_library_completion,
        build_packet_lab_report_fn=build_packet_lab_report,
        classify_packet_lab_completion_fn=classify_packet_lab_completion,
    )


def build_packet_library_production_metrics(payload):
    return build_packet_library_production_metrics_impl(
        payload,
        normalize_packet_builder_payload_fn=normalize_packet_builder_payload,
        build_packet_library_completion_fn=build_packet_library_completion,
        first_icd_code_fn=_first_icd_code,
    )


def list_packet_library_records():
    return list_packet_library_records_impl(
        normalize_packet_builder_payload_fn=normalize_packet_builder_payload,
    )


def save_packet_library_record(record):
    return save_packet_library_record_impl(record)


def delete_packet_library_record(draft_id):
    delete_packet_library_record_impl(draft_id)


def find_word_executable():
    return find_word_executable_impl()


def convert_docx_to_pdf_via_word(docx_path, pdf_path):
    return convert_docx_to_pdf_via_word_impl(docx_path, pdf_path)


def _signature_image_bytes(payload, field_name):
    return signature_image_bytes_impl(payload, field_name)


def _signature_image_html(payload, field_name, width_px=220, height_px=54):
    return signature_image_html_impl(payload, field_name, width_px=width_px, height_px=height_px)


def _typed_signature_image_bytes(text):
    return typed_signature_image_bytes_impl(text)


def default_packet_builder_payload():
    return default_packet_builder_payload_impl()


def sanitize_packet_builder_text(value):
    return sanitize_packet_builder_text_impl(value)


def export_checkbox_marker(enabled):
    return "[X]" if enabled else "[ ]"


def normalize_packet_builder_payload(payload):
    return normalize_packet_builder_payload_impl(
        payload,
        default_packet_builder_payload_fn=default_packet_builder_payload,
        apply_packet_builder_shared_field_sync_fn=apply_packet_builder_shared_field_sync,
    )


def build_packet_builder_inconsistency_banner(payload):
    packet = apply_packet_builder_shared_field_sync(default_packet_builder_payload() | dict(payload or {}))
    messages = build_packet_inconsistency_messages(packet)
    if not messages:
        return ""
    items = "".join(f"<li style='margin-bottom:6px;'>{html.escape(message)}</li>" for message in messages)
    return (
        "<div style='margin-bottom:14px; padding:10px 12px; background:#FFF7ED; border:1px solid #F1C996; color:#7C3400; font-size:11pt; line-height:1.35;'>"
        "<div style='font-weight:700;'>Consistency Warning</div>"
        "<div style='margin-top:4px;'>Some repeated values on this form do not match the shared packet header.</div>"
        f"<ul style='margin:6px 0 0 18px; padding:0;'>{items}</ul>"
        "</div>"
    )


def build_packet_builder_preview_html(payload):
    banner = build_packet_builder_inconsistency_banner(payload)
    wording_banner = build_wording_assist_banner(payload)
    return render_packet_builder_document_preview(banner + wording_banner + build_packet_builder_document_markup(payload))


def build_packet_builder_export_html(payload):
    return render_packet_builder_document_export(build_packet_builder_document_markup(payload))


class PacketBuilderTab(PacketBuilderExportMixin, PacketBuilderWordingLibraryMixin, QWidget):
    def __init__(self, config, save_config_callback, parent=None):
        super().__init__(parent)
        self.config = dict(config or {})
        self.save_config_callback = save_config_callback
        self.packet_payload = default_packet_builder_payload()
        self._builder_ready = False
        self._shared_sync_state = {}
        self._wording_assist_state = {}
        self._wording_entries = {}
        self._current_wording_entry_key = ""
        self.current_draft_id = None
        self.current_draft_record = {}
        self.word_executable_path = find_word_executable()
        self._preview_cache_dir = runtime_data_path("dev_system", "preview_cache")
        self._preview_render_thread = None
        self._preview_render_worker = None
        self._preview_latest_requested_key = ""
        self._preview_loaded_key = ""
        self._preview_current_key = ""
        self._export_thread = None
        self._export_worker = None
        self._export_controls = []
        self._signature_images = {}
        self._wording_status_colors = WORDING_STATUS_COLORS
        self._build_wording_assist_entries_fn = build_wording_assist_entries
        self._sanitize_packet_builder_text_fn = sanitize_packet_builder_text
        self._packet_widget_bindings = PACKET_WIDGET_BINDINGS
        self._packet_library_display_name_fn = packet_library_display_name
        self._generate_packet_library_draft_id_fn = generate_packet_library_draft_id
        self._save_packet_library_record_fn = save_packet_library_record
        self._build_packet_library_completion_fn = build_packet_library_completion
        self._build_packet_library_production_metrics_fn = build_packet_library_production_metrics
        self._list_packet_library_records_fn = list_packet_library_records
        self._delete_packet_library_record_fn = delete_packet_library_record
        self._packet_profile_status_palette_fn = packet_profile_status_palette
        self._preview_refresh_timer = QTimer(self)
        self._preview_refresh_timer.setSingleShot(True)
        self._preview_refresh_timer.setInterval(120)
        self._preview_refresh_timer.timeout.connect(self._refresh_preview_now)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        intro = QLabel(
            "Packet Builder Studio is the dev-side drafting shell. It lets you stage packet data once, carry shared header details across forms, preview the document, and use Lab to catch gaps before export."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#BFD0E3;")
        layout.addWidget(intro)

        self.current_packet_status_label = QLabel()
        self.current_packet_status_label.setWordWrap(True)
        self.current_packet_status_label.setStyleSheet("color:#8FA6C1; font-weight:600;")
        layout.addWidget(self.current_packet_status_label)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(6)
        self.builder_splitter = splitter
        layout.addWidget(splitter, stretch=1)

        form_scroll = QScrollArea()
        form_scroll.setWidgetResizable(True)
        form_scroll.setFrameShape(QFrame.NoFrame)
        form_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        form_scroll.viewport().setStyleSheet("background:#0F1823;")
        form_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.form_scroll = form_scroll
        splitter.addWidget(form_scroll)

        form_panel = QWidget()
        form_panel.setStyleSheet("background:#0F1823;")
        form_panel.setMinimumWidth(0)
        form_panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        form_layout = QVBoxLayout(form_panel)
        form_layout.setContentsMargins(0, 0, 6, 0)
        form_layout.setSpacing(12)
        self.form_panel = form_panel
        form_scroll.setWidget(form_panel)

        export_group = QGroupBox("Export")
        export_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        export_layout = QVBoxLayout(export_group)
        export_layout.setSpacing(10)

        self.export_dir_value = QLabel(self.config.get("packet_builder_export_dir") or _default_export_dir())
        self.export_dir_value.setWordWrap(True)
        self.export_dir_value.setStyleSheet("color:#8FA6C1;")
        choose_folder_button = QPushButton("Choose Folder")
        self._style_builder_button(choose_folder_button)
        choose_folder_button.setMaximumWidth(150)
        choose_folder_button.clicked.connect(self.choose_export_dir)
        export_layout.addWidget(QLabel("Export Folder"))
        export_path_row = QHBoxLayout()
        export_path_row.setContentsMargins(0, 0, 0, 0)
        export_path_row.setSpacing(10)
        export_path_row.addWidget(self.export_dir_value, stretch=1)
        export_path_row.addWidget(choose_folder_button, 0, Qt.AlignRight)
        export_layout.addLayout(export_path_row)

        self.base_filename_input = QLineEdit("truecore_packet")
        self.base_filename_input.textChanged.connect(self.refresh_preview)
        export_layout.addWidget(QLabel("Base Filename"))
        export_layout.addWidget(self.base_filename_input)
        form_layout.addWidget(export_group)

        editor_tabs = QTabWidget()
        editor_tabs.setDocumentMode(True)
        editor_tabs.setStyleSheet(
            "QTabWidget::pane { border:1px solid #243446; border-radius:12px; background:#0F1823; top:-1px; }"
            "QTabBar::tab { background:#13202E; color:#DDE8F5; padding:9px 16px; border-top-left-radius:10px; border-top-right-radius:10px; margin-right:4px; }"
            "QTabBar::tab:selected { background:#1D2B3A; color:#FFFFFF; font-weight:700; }"
            "QTabBar::tab:hover:!selected { background:#182433; }"
        )
        self.packet_builder_left_tabs = editor_tabs
        form_layout.addWidget(editor_tabs, stretch=1)

        intake_page = QWidget()
        intake_page.setStyleSheet("background:#0F1823;")
        intake_layout = QVBoxLayout(intake_page)
        intake_layout.setContentsMargins(12, 12, 12, 12)
        intake_layout.setSpacing(12)
        self.packet_intake_page = intake_page

        workspace_page = QWidget()
        workspace_page.setStyleSheet("background:#0F1823;")
        workspace_layout = QVBoxLayout(workspace_page)
        workspace_layout.setContentsMargins(12, 12, 12, 12)
        workspace_layout.setSpacing(12)
        self.packet_workspace_page = workspace_page

        editor_tabs.addTab(intake_page, "Packet Intake")
        editor_tabs.addTab(workspace_page, "Form Workspace")
        editor_tabs.setCurrentWidget(workspace_page)

        current_form_group = QGroupBox("Current Form")
        current_form_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        current_form_layout = QFormLayout(current_form_group)
        self._configure_form_layout(current_form_layout)

        current_form_help = QLabel(
            "Use Packet Intake for shared packet facts and scenario prompts. Only the active form below is export-facing."
        )
        current_form_help.setWordWrap(True)
        current_form_help.setStyleSheet("color:#8FA6C1;")
        current_form_layout.addRow(current_form_help)

        self.profile_combo = QComboBox()
        self.profile_combo.addItems(PACKET_BUILDER_PROFILES)
        self.profile_combo.currentTextChanged.connect(self.on_profile_changed)
        self.profile_combo.setMaximumWidth(360)
        self.profile_combo.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        current_form_layout.addRow("Packet Profile", self.profile_combo)

        self.export_context_label = QLabel("")
        self.export_context_label.setWordWrap(True)
        self.export_context_label.setStyleSheet("color:#8FA6C1;")
        current_form_layout.addRow("Export Context", self.export_context_label)

        self.packet_title_input = self._make_line_edit("Packet title")
        current_form_layout.addRow("Packet Title", self.packet_title_input)
        workspace_layout.addWidget(current_form_group)

        details_group = QGroupBox("Packet Intake")
        details_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        details_form = QFormLayout(details_group)
        self._configure_form_layout(details_form)

        shared_header_help = QLabel(
            "Enter repeated packet facts here once. This intake area is never exported. Packet Studio carries these values into matching form fields where expected, while page-specific reasoning stays manual.<br/><br/>"
            "<strong>VA Referring Source</strong> = VA facility and VA referring / ordering provider.<br/>"
            "<strong>Community Care Destination</strong> = the outside specialist / practice the Veteran is being referred to.<br/>"
            "<strong>PCP / PCM</strong> = the Veteran's primary care office, used only where the form specifically asks for it."
        )
        shared_header_help.setWordWrap(True)
        shared_header_help.setStyleSheet("color:#8FA6C1;")
        details_form.addRow(shared_header_help)

        def add_section_label(text):
            label = QLabel(text)
            label.setStyleSheet("color:#C8D8E8; font-weight:700; padding-top:6px;")
            details_form.addRow(label)

        add_section_label("Veteran / VA Identifiers")
        self.patient_name_input = self._make_line_edit("Patient name")
        details_form.addRow("Veteran Full Legal Name", self.patient_name_input)
        self.dob_input = self._make_line_edit("MM/DD/YYYY")
        details_form.addRow("Date of Birth", self.dob_input)
        self.auth_input = self._make_line_edit("VA authorization number")
        details_form.addRow("VA Authorization Number", self.auth_input)
        self.icn_input = self._make_line_edit("VA ICN")
        details_form.addRow("VA ICN", self.icn_input)
        add_section_label("VA Referring Source")
        self.ordering_doctor_input = self._make_line_edit("VA referring / ordering provider name")
        details_form.addRow("VA Referring / Ordering Provider", self.ordering_doctor_input)
        self.facility_input = self._make_line_edit("VA facility / VA medical center")
        details_form.addRow("VA Referring Facility / Medical Center", self.facility_input)
        add_section_label("Community Care Destination")
        self.provider_input = self._make_line_edit("Community Care treating provider name")
        details_form.addRow("Community Care Treating Provider", self.provider_input)
        self.community_facility_input = self._make_line_edit("Community Care referred-to practice / facility")
        details_form.addRow("Community Care Practice / Facility", self.community_facility_input)
        self.master_provider_credentials_input = self._make_line_edit("Community Care provider credentials")
        details_form.addRow("Community Care Provider Credentials", self.master_provider_credentials_input)
        self.master_provider_specialty_input = self._make_line_edit("Community Care provider specialty")
        details_form.addRow("Community Care Provider Specialty", self.master_provider_specialty_input)
        self.master_provider_npi_input = self._make_line_edit("Community Care provider NPI")
        details_form.addRow("Community Care Provider NPI", self.master_provider_npi_input)
        self.master_practice_name_input = self._make_line_edit("Community Care practice name")
        details_form.addRow("Community Care Practice Name", self.master_practice_name_input)
        self.master_provider_phone_input = self._make_line_edit("Community Care practice phone")
        details_form.addRow("Community Care Practice Phone", self.master_provider_phone_input)
        self.master_provider_fax_input = self._make_line_edit("Community Care practice fax")
        details_form.addRow("Community Care Practice Fax", self.master_provider_fax_input)
        self.master_provider_email_input = self._make_line_edit("Community Care secure email")
        details_form.addRow("Community Care Secure Email", self.master_provider_email_input)

        self.master_provider_address_input = QTextEdit()
        self.master_provider_address_input.setMinimumHeight(70)
        self.master_provider_address_input.textChanged.connect(self.refresh_preview)
        details_form.addRow("Community Care Practice Address", self.master_provider_address_input)

        add_section_label("Clinical Baseline Shared Across Forms")
        self.requested_service_input = self._make_line_edit("Requested service")
        details_form.addRow("Requested Service", self.requested_service_input)
        self.diagnosis_input = self._make_line_edit("Diagnosis")
        details_form.addRow("Primary Diagnosis", self.diagnosis_input)
        self.secondary_diagnosis_input = self._make_line_edit("Secondary diagnosis")
        details_form.addRow("Secondary Diagnosis", self.secondary_diagnosis_input)
        self.icd_codes_input = self._make_line_edit("ICD codes")
        details_form.addRow("ICD Codes", self.icd_codes_input)
        self.master_requested_cpt_code_input = self._make_line_edit("Requested CPT / HCPCS code")
        details_form.addRow("Requested CPT / HCPCS", self.master_requested_cpt_code_input)

        self.master_mri_date_input = self._make_line_edit("MM/DD/YYYY")
        details_form.addRow("MRI Date", self.master_mri_date_input)
        self.master_mri_findings_input = self._make_line_edit("MRI findings")
        details_form.addRow("MRI Findings", self.master_mri_findings_input)
        self.master_affected_levels_input = self._make_line_edit("Affected spinal levels")
        details_form.addRow("Affected Spinal Levels", self.master_affected_levels_input)

        self.clinical_summary_input = QTextEdit()
        self.clinical_summary_input.setMinimumHeight(90)
        self.clinical_summary_input.textChanged.connect(self.refresh_preview)
        details_form.addRow("Clinical Summary / Symptoms", self.clinical_summary_input)

        self.packet_notes_input = QTextEdit()
        self.packet_notes_input.setMinimumHeight(90)
        self.packet_notes_input.textChanged.connect(self.refresh_preview)
        details_form.addRow("Packet Notes", self.packet_notes_input)

        intake_layout.addWidget(details_group)

        scenario_group = QGroupBox("Scenario Prompts")
        scenario_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        scenario_form = QFormLayout(scenario_group)
        self._configure_form_layout(scenario_form)

        scenario_help = QLabel(
            "These prompts are not exported. Choose one or more where needed. They help Wording Assist choose cleaner blueprint families without forcing you to over-explain the same packet facts on every form."
        )
        scenario_help.setWordWrap(True)
        scenario_help.setStyleSheet("color:#8FA6C1;")
        scenario_form.addRow(scenario_help)

        self.scenario_pathology_pattern_input = MultiSelectPromptField(
            "Primary Pathology Pattern",
            [
                "Discogenic / Annular",
                "Radicular",
                "Disc Displacement / Herniation",
                "Multilevel",
            ],
        )
        self.scenario_pathology_pattern_input.textChanged.connect(self.refresh_preview)
        scenario_form.addRow("Primary Pathology Pattern", self.scenario_pathology_pattern_input)

        self.scenario_conservative_duration_input = MultiSelectPromptField(
            "Conservative Care Duration",
            [
                "Over 90 Days",
                "Over 6 Months",
                "Over 12 Months",
            ],
        )
        self.scenario_conservative_duration_input.textChanged.connect(self.refresh_preview)
        scenario_form.addRow("Conservative Care Duration", self.scenario_conservative_duration_input)

        self.scenario_prior_esi_response_input = MultiSelectPromptField(
            "Prior ESI Response",
            [
                "None / Not Documented",
                "Temporary Relief",
                "Partial Relief",
                "No Relief",
            ],
        )
        self.scenario_prior_esi_response_input.textChanged.connect(self.refresh_preview)
        scenario_form.addRow("Prior ESI Response", self.scenario_prior_esi_response_input)

        self.scenario_functional_emphasis_input = MultiSelectPromptField(
            "Functional Emphasis",
            [
                "Sleep Disruption",
                "Work Capacity",
                "Sitting / Standing Tolerance",
                "Daily Activities",
            ],
        )
        self.scenario_functional_emphasis_input.textChanged.connect(self.refresh_preview)
        scenario_form.addRow("Functional Emphasis", self.scenario_functional_emphasis_input)

        self.scenario_request_framing_input = MultiSelectPromptField(
            "Request Framing",
            [
                "Procedure-Neutral Evaluation",
                "Defined Interventional Pathway",
                "Specific Requested Procedure",
            ],
        )
        self.scenario_request_framing_input.textChanged.connect(self.refresh_preview)
        scenario_form.addRow("Request Framing", self.scenario_request_framing_input)

        self.scenario_symptom_pattern_input = MultiSelectPromptField(
            "Symptom Pattern",
            [
                "Axial Lumbar Pain",
                "Discogenic Pattern",
                "Radicular Symptoms",
                "Activity-Related Exacerbation",
                "Position Intolerance",
            ],
        )
        self.scenario_symptom_pattern_input.textChanged.connect(self.refresh_preview)
        scenario_form.addRow("Symptom Pattern", self.scenario_symptom_pattern_input)

        self.scenario_conservative_modalities_input = MultiSelectPromptField(
            "Conservative Modalities Already Tried",
            [
                "Physical Therapy",
                "Home Exercise Program",
                "NSAIDs / Analgesics",
                "Activity Modification",
                "Prior ESI / Interventional",
            ],
        )
        self.scenario_conservative_modalities_input.textChanged.connect(self.refresh_preview)
        scenario_form.addRow("Conservative Modalities Tried", self.scenario_conservative_modalities_input)

        self.scenario_review_concern_input = MultiSelectPromptField(
            "Primary Review Concern",
            [
                "Scope Must Stay Limited",
                "Medical Necessity Emphasis",
                "Imaging Correlation Emphasis",
                "Failed Conservative Care Emphasis",
            ],
        )
        self.scenario_review_concern_input.textChanged.connect(self.refresh_preview)
        scenario_form.addRow("Primary Review Concern", self.scenario_review_concern_input)

        self.scenario_treatment_goals_input = MultiSelectPromptField(
            "Treatment Goals to Emphasize",
            [
                "Pain Reduction",
                "Functional Improvement",
                "Reduce Analgesics",
                "Avoid Surgery",
                "Prevent Progression",
            ],
        )
        self.scenario_treatment_goals_input.textChanged.connect(self.refresh_preview)
        scenario_form.addRow("Treatment Goals", self.scenario_treatment_goals_input)
        intake_layout.addWidget(scenario_group)
        intake_layout.addStretch(1)

        self.referral_group = QGroupBox("Community Care Referral Request")
        self.referral_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        referral_form = QFormLayout(self.referral_group)
        self._configure_form_layout(referral_form)

        self.referral_subtitle_input = self._make_line_edit("Spine & Pain Evaluation")
        self.referral_subtitle_input.setText("Spine and Pain Evaluation")
        referral_form.addRow("Subtitle", self.referral_subtitle_input)

        self.pcp_request_input = self._make_line_edit("PCP request wording")
        self.pcp_request_input.setText(
            "I am requesting a Community Care referral for pain management and spine evaluation to determine the most appropriate treatment plan."
        )
        referral_form.addRow("PCP Request Wording", self.pcp_request_input)

        self.referral_entry_input = self._make_line_edit("Referral entry wording")
        self.referral_entry_input.setText("Specialty spine and pain evaluation and consultation")
        referral_form.addRow("Referral Entry Wording", self.referral_entry_input)

        self.areas_of_concern_input = self._make_line_edit("Cervical, Thoracic, Lumbar, Joints (if applicable)")
        self.areas_of_concern_input.setText("Cervical, Thoracic, Lumbar, Joints (if applicable)")
        referral_form.addRow("Areas of Concern", self.areas_of_concern_input)

        self.group_npi_input = self._make_line_edit("Group NPI")
        referral_form.addRow("Group NPI", self.group_npi_input)

        self.fax_number_input = self._make_line_edit("Fax number")
        referral_form.addRow("Fax Number", self.fax_number_input)

        self.liaison_contact_input = QTextEdit()
        self.liaison_contact_input.setMinimumHeight(80)
        self.liaison_contact_input.textChanged.connect(self.refresh_preview)
        self.liaison_contact_input.setPlaceholderText("Veteran liaison contact information")
        referral_form.addRow("Liaison Contact", self.liaison_contact_input)

        workspace_layout.addWidget(self.referral_group)

        self.virtual_consent_group = QGroupBox("Virtual Consent Form")
        self.virtual_consent_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        consent_form = QFormLayout(self.virtual_consent_group)
        self._configure_form_layout(consent_form)

        self.consent_form_title_input = self._make_line_edit("TELEHEALTH VIRTUAL CONSENT FORM")
        self.consent_form_title_input.setText("TELEHEALTH VIRTUAL CONSENT FORM")
        consent_form.addRow("Form Title", self.consent_form_title_input)

        self.street_address_input = self._make_line_edit("Street address")
        consent_form.addRow("Street Address", self.street_address_input)
        self.city_input = self._make_line_edit("City")
        consent_form.addRow("City", self.city_input)
        self.state_input = self._make_line_edit("State")
        consent_form.addRow("State", self.state_input)
        self.zip_code_input = self._make_line_edit("Zip code")
        consent_form.addRow("Zip Code", self.zip_code_input)

        self.home_phone_input = self._make_line_edit("Home phone")
        consent_form.addRow("Home Phone", self.home_phone_input)
        self.mobile_phone_input = self._make_line_edit("Mobile phone")
        consent_form.addRow("Mobile Phone", self.mobile_phone_input)
        self.work_phone_input = self._make_line_edit("Work phone")
        consent_form.addRow("Work Phone", self.work_phone_input)

        self.email_address_input = self._make_line_edit("Email address")
        consent_form.addRow("Email Address", self.email_address_input)
        self.ssn_input = self._make_line_edit("SSN")
        consent_form.addRow("SSN", self.ssn_input)
        self.drivers_license_input = self._make_line_edit("Driver license")
        consent_form.addRow("Driver License", self.drivers_license_input)
        self.drivers_license_state_input = self._make_line_edit("DL state")
        consent_form.addRow("DL State", self.drivers_license_state_input)

        self.appointment_confirmation_combo = self._make_choice_combo(["Phone", "Text", "Email"])
        consent_form.addRow("Appointment Confirmation", self.appointment_confirmation_combo)
        self.filed_for_disability_combo = self._make_choice_combo(["No", "Yes"])
        consent_form.addRow("Filed for Disability", self.filed_for_disability_combo)
        self.condition_work_related_combo = self._make_choice_combo(["No", "Yes"])
        consent_form.addRow("Condition Work Related", self.condition_work_related_combo)
        self.condition_due_to_accident_combo = self._make_choice_combo(["No", "Yes"])
        consent_form.addRow("Condition Due to Accident", self.condition_due_to_accident_combo)

        self.yes_response_explanation_input = QTextEdit()
        self.yes_response_explanation_input.setMinimumHeight(70)
        self.yes_response_explanation_input.textChanged.connect(self.refresh_preview)
        self.yes_response_explanation_input.setPlaceholderText("Explain any Yes responses")
        consent_form.addRow("Yes Response Explanation", self.yes_response_explanation_input)

        self.has_attorney_combo = self._make_choice_combo(["No", "Yes"])
        consent_form.addRow("Has Attorney", self.has_attorney_combo)
        self.attorney_name_input = self._make_line_edit("Attorney full name")
        consent_form.addRow("Attorney Name", self.attorney_name_input)
        self.attorney_phone_input = self._make_line_edit("Attorney phone")
        consent_form.addRow("Attorney Phone", self.attorney_phone_input)

        self.emergency_contact_name_input = self._make_line_edit("Emergency contact")
        consent_form.addRow("Emergency Contact", self.emergency_contact_name_input)
        self.emergency_contact_relationship_input = self._make_line_edit("Relationship")
        consent_form.addRow("Relationship", self.emergency_contact_relationship_input)
        self.emergency_contact_phone_input = self._make_line_edit("Emergency contact phone")
        consent_form.addRow("Emergency Contact Phone", self.emergency_contact_phone_input)

        self.primary_insurance_carrier_input = self._make_line_edit("Primary insurance carrier")
        consent_form.addRow("Primary Insurance Carrier", self.primary_insurance_carrier_input)
        self.primary_insurance_id_input = self._make_line_edit("Primary insurance ID")
        consent_form.addRow("Primary Insurance ID", self.primary_insurance_id_input)
        self.primary_insurance_phone_input = self._make_line_edit("Primary insurance phone")
        consent_form.addRow("Primary Insurance Phone", self.primary_insurance_phone_input)

        self.secondary_insurance_carrier_input = self._make_line_edit("Secondary insurance carrier")
        consent_form.addRow("Secondary Insurance Carrier", self.secondary_insurance_carrier_input)
        self.secondary_insurance_id_input = self._make_line_edit("Secondary insurance ID")
        consent_form.addRow("Secondary Insurance ID", self.secondary_insurance_id_input)
        self.secondary_insurance_phone_input = self._make_line_edit("Secondary insurance phone")
        consent_form.addRow("Secondary Insurance Phone", self.secondary_insurance_phone_input)

        self.pcp_pcm_name_input = self._make_line_edit("PCP/PCM")
        consent_form.addRow("PCP / PCM", self.pcp_pcm_name_input)
        self.pcp_pcm_phone_input = self._make_line_edit("PCP/PCM phone")
        consent_form.addRow("PCP / PCM Phone", self.pcp_pcm_phone_input)
        self.pcp_pcm_fax_input = self._make_line_edit("PCP/PCM fax")
        consent_form.addRow("PCP / PCM Fax", self.pcp_pcm_fax_input)

        self.consent_provider_name_input = self._make_line_edit("Care provider name")
        consent_form.addRow("Consent Provider Name", self.consent_provider_name_input)
        self.consent_initials_input = self._make_line_edit("Patient initials")
        consent_form.addRow("Consent Initials", self.consent_initials_input)
        self.minor_doctor_name_input = self._make_line_edit("Doctor name for minor consent")
        consent_form.addRow("Minor Doctor Name", self.minor_doctor_name_input)
        self.minor_consent_initials_input = self._make_line_edit("Parent / guardian initials")
        consent_form.addRow("Minor Consent Initials", self.minor_consent_initials_input)
        self.service_authorization_name_input = self._make_line_edit("Authorized service name")
        consent_form.addRow("Service Authorization Name", self.service_authorization_name_input)
        patient_signature_widget, self.patient_signature_name_input = self._make_signature_field("patient_signature_name", "Veteran / patient signature")
        consent_form.addRow("Veteran / Patient Signature", patient_signature_widget)
        self.patient_signature_date_input = self._make_line_edit("MM/DD/YYYY")
        consent_form.addRow("Veteran / Patient Signature Date", self.patient_signature_date_input)

        workspace_layout.addWidget(self.virtual_consent_group)

        self.submission_cover_group = QGroupBox("Submission Cover Sheet")
        self.submission_cover_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        cover_form = QFormLayout(self.submission_cover_group)
        self._configure_form_layout(cover_form)

        self.submission_cover_title_input = self._make_line_edit("VA Submission Cover Sheet")
        self.submission_cover_title_input.setText("VA Submission Cover Sheet")
        cover_form.addRow("Cover Title", self.submission_cover_title_input)

        self.submission_date_input = self._make_line_edit("MM/DD/YYYY")
        cover_form.addRow("Date of Submission", self.submission_date_input)
        self.primary_diagnosis_code_input = self._make_line_edit("Primary diagnosis code")
        cover_form.addRow("Primary Diagnosis Code", self.primary_diagnosis_code_input)

        self.included_virtual_consent_checkbox = self._make_checkbox("Virtual Consent Form completed and signed", True)
        cover_form.addRow("Included", self.included_virtual_consent_checkbox)
        self.included_va_form_checkbox = self._make_checkbox("VA Form 10-10172 completed and signed", True)
        cover_form.addRow("", self.included_va_form_checkbox)
        self.included_seoc_checkbox = self._make_checkbox("SEOC request signed by CCN ordering provider", True)
        cover_form.addRow("", self.included_seoc_checkbox)
        self.included_consult_checkbox = self._make_checkbox("Consultation & Treatment Request completed", True)
        cover_form.addRow("", self.included_consult_checkbox)
        self.included_lomn_checkbox = self._make_checkbox("Letter of Medical Necessity completed", True)
        cover_form.addRow("", self.included_lomn_checkbox)
        self.included_clinical_notes_checkbox = self._make_checkbox("Clinical Notes included", True)
        cover_form.addRow("", self.included_clinical_notes_checkbox)
        self.included_mri_checkbox = self._make_checkbox("MRI Report included", True)
        cover_form.addRow("", self.included_mri_checkbox)

        self.submitting_office_input = self._make_line_edit("Submitting office")
        cover_form.addRow("Submitting Office", self.submitting_office_input)
        self.office_staff_name_input = self._make_line_edit("Office staff name")
        cover_form.addRow("Office Staff Name", self.office_staff_name_input)
        office_signature_widget, self.office_staff_signature_input = self._make_signature_field("office_staff_signature", "Program user / office staff signature")
        cover_form.addRow("Program User / Office Staff Signature", office_signature_widget)
        self.date_reviewed_input = self._make_line_edit("MM/DD/YYYY")
        cover_form.addRow("Date Reviewed", self.date_reviewed_input)

        workspace_layout.addWidget(self.submission_cover_group)

        self.seoc_request_group = QGroupBox("Single Episode of Care Request Template")
        self.seoc_request_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        seoc_form = QFormLayout(self.seoc_request_group)
        self._configure_form_layout(seoc_form)

        self.seoc_request_date_input = self._make_line_edit("MM/DD/YYYY")
        seoc_form.addRow("Request Date", self.seoc_request_date_input)
        self.va_medical_center_input = self._make_line_edit("VA Medical Center Name")
        seoc_form.addRow("VA Medical Center", self.va_medical_center_input)
        self.last_four_ssn_input = self._make_line_edit("Last four SSN")
        seoc_form.addRow("Last Four SSN", self.last_four_ssn_input)
        self.episode_diagnosis_input = self._make_line_edit("Episode diagnosis / condition")
        seoc_form.addRow("Episode Diagnosis", self.episode_diagnosis_input)
        self.episode_icd_code_input = self._make_line_edit("ICD-10 code")
        seoc_form.addRow("Episode ICD Code", self.episode_icd_code_input)
        self.estimated_duration_input = self._make_line_edit("Thirty to ninety days, including routine post-procedure follow-up related only to the authorized episode of care.")
        self.estimated_duration_input.setText("Thirty to ninety days, including routine post-procedure follow-up related only to the authorized episode of care.")
        seoc_form.addRow("Estimated Duration", self.estimated_duration_input)

        self.seoc_preprocedure_checkbox = self._make_checkbox("Pre-procedure evaluation and procedural planning", True)
        seoc_form.addRow("Scope", self.seoc_preprocedure_checkbox)
        self.seoc_annulargram_checkbox = self._make_checkbox("Diagnostic Annulargram", True)
        seoc_form.addRow("", self.seoc_annulargram_checkbox)
        self.seoc_fibrin_checkbox = self._make_checkbox("Inter Annular Fibrin Injections if indicated", True)
        seoc_form.addRow("", self.seoc_fibrin_checkbox)
        self.seoc_follow_up_checkbox = self._make_checkbox("Standard post-procedure follow-up visit(s) within the global postoperative period", True)
        seoc_form.addRow("", self.seoc_follow_up_checkbox)
        self.seoc_scope_text_input = QTextEdit()
        self.seoc_scope_text_input.setMinimumHeight(78)
        self.seoc_scope_text_input.setPlaceholderText("Summarize the requested scope of this episode of care")
        self.seoc_scope_text_input.setPlainText(
            "This SEOC is limited to evaluation, procedural planning, the indicated intervention if clinically appropriate, and standard post-procedure follow-up related only to the documented condition. No unrelated care or open-ended pain management is requested under this episode."
        )
        self.seoc_scope_text_input.textChanged.connect(self.refresh_preview)
        seoc_form.addRow("Scope Language", self.seoc_scope_text_input)

        self.clinical_objectives_input = QTextEdit()
        self.clinical_objectives_input.setMinimumHeight(90)
        self.clinical_objectives_input.setPlaceholderText("One clinical objective per line")
        self.clinical_objectives_input.setPlainText(
            "Reduce pain severity\nImprove functional capacity\nSupport activity tolerance related to the documented condition"
        )
        self.clinical_objectives_input.textChanged.connect(self.refresh_preview)
        seoc_form.addRow("Clinical Objectives", self.clinical_objectives_input)
        self.seoc_continuity_text_input = QTextEdit()
        self.seoc_continuity_text_input.setMinimumHeight(78)
        self.seoc_continuity_text_input.setPlaceholderText("Describe continuity-of-care handling after the episode is complete")
        self.seoc_continuity_text_input.setPlainText(
            "Upon completion of the authorized episode, a treatment summary and clinical outcome update will be provided to the referring VA provider. Any additional or unrelated care will require separate evaluation and authorization."
        )
        self.seoc_continuity_text_input.textChanged.connect(self.refresh_preview)
        seoc_form.addRow("Continuity of Care", self.seoc_continuity_text_input)

        self.provider_credentials_input = self._make_line_edit("Community Care provider credentials")
        seoc_form.addRow("Community Care Provider Credentials", self.provider_credentials_input)
        self.provider_specialty_input = self._make_line_edit("Community Care provider specialty")
        seoc_form.addRow("Community Care Provider Specialty", self.provider_specialty_input)
        self.provider_npi_input = self._make_line_edit("Community Care provider NPI")
        seoc_form.addRow("Community Care Provider NPI", self.provider_npi_input)
        self.practice_name_input = self._make_line_edit("Community Care practice name")
        seoc_form.addRow("Community Care Practice Name", self.practice_name_input)
        self.provider_phone_input = self._make_line_edit("Community Care practice phone")
        seoc_form.addRow("Community Care Practice Phone", self.provider_phone_input)
        self.provider_fax_input = self._make_line_edit("Community Care practice fax")
        seoc_form.addRow("Community Care Practice Fax", self.provider_fax_input)

        workspace_layout.addWidget(self.seoc_request_group)

        self.lomn_group = QGroupBox("Letter of Medical Necessity Template")
        self.lomn_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        lomn_form = QFormLayout(self.lomn_group)
        self._configure_form_layout(lomn_form)

        self.lomn_request_date_input = self._make_line_edit("MM/DD/YYYY")
        lomn_form.addRow("Letter Date", self.lomn_request_date_input)
        self.lomn_va_claim_number_input = self._make_line_edit("VA claim number if applicable")
        lomn_form.addRow("VA Claim Number", self.lomn_va_claim_number_input)

        self.lomn_primary_diagnosis_input = self._make_line_edit("Primary diagnosis")
        lomn_form.addRow("Primary Diagnosis", self.lomn_primary_diagnosis_input)
        self.lomn_secondary_diagnosis_input = self._make_line_edit("Secondary diagnosis")
        lomn_form.addRow("Secondary Diagnosis", self.lomn_secondary_diagnosis_input)

        self.lomn_clinical_summary_input = QTextEdit()
        self.lomn_clinical_summary_input.setMinimumHeight(100)
        self.lomn_clinical_summary_input.setPlaceholderText("Summarize the clinical picture and functional impact")
        self.lomn_clinical_summary_input.setPlainText("")
        self.lomn_clinical_summary_input.textChanged.connect(self.refresh_preview)
        lomn_form.addRow("Clinical Basis", self.lomn_clinical_summary_input)

        self.lomn_mri_date_input = self._make_line_edit("MM/DD/YYYY")
        lomn_form.addRow("MRI Date", self.lomn_mri_date_input)
        self.lomn_mri_findings_input = self._make_line_edit("MRI findings")
        lomn_form.addRow("MRI Findings", self.lomn_mri_findings_input)
        self.lomn_conservative_duration_input = self._make_line_edit("Duration of conservative care")
        lomn_form.addRow("Conservative Care Duration", self.lomn_conservative_duration_input)

        self.lomn_physical_therapy_checkbox = self._make_checkbox("Structured physical therapy", True)
        lomn_form.addRow("Conservative Care", self.lomn_physical_therapy_checkbox)
        self.lomn_nsaids_checkbox = self._make_checkbox("NSAIDs and non-opioid analgesics", True)
        lomn_form.addRow("", self.lomn_nsaids_checkbox)
        self.lomn_activity_modification_checkbox = self._make_checkbox("Activity modification", True)
        lomn_form.addRow("", self.lomn_activity_modification_checkbox)
        self.lomn_home_exercise_checkbox = self._make_checkbox("Home exercise program", True)
        lomn_form.addRow("", self.lomn_home_exercise_checkbox)
        self.lomn_esi_checkbox = self._make_checkbox("Epidural Steroid injections (if applicable)", True)
        lomn_form.addRow("", self.lomn_esi_checkbox)

        self.lomn_medical_necessity_input = QTextEdit()
        self.lomn_medical_necessity_input.setMinimumHeight(80)
        self.lomn_medical_necessity_input.setPlaceholderText("Explain why the requested treatment is medically necessary")
        self.lomn_medical_necessity_input.setPlainText(
            "Based on chronic symptoms, failed conservative management, functional limitation, and imaging findings that correlate with the clinical presentation, the requested intervention is medically reasonable and necessary."
        )
        self.lomn_medical_necessity_input.textChanged.connect(self.refresh_preview)
        lomn_form.addRow("Medical Necessity", self.lomn_medical_necessity_input)

        self.lomn_reduce_pain_checkbox = self._make_checkbox("Reduce pain severity", True)
        lomn_form.addRow("Indications", self.lomn_reduce_pain_checkbox)
        self.lomn_improve_function_checkbox = self._make_checkbox("Improve functional capacity", True)
        lomn_form.addRow("", self.lomn_improve_function_checkbox)
        self.lomn_prevent_degeneration_checkbox = self._make_checkbox("Prevent further disc degeneration", True)
        lomn_form.addRow("", self.lomn_prevent_degeneration_checkbox)
        self.lomn_reduce_opioids_checkbox = self._make_checkbox("Decrease reliance on long-term opioid therapy", True)
        lomn_form.addRow("", self.lomn_reduce_opioids_checkbox)
        self.lomn_prevent_surgery_checkbox = self._make_checkbox("Potentially prevent need for more invasive surgical intervention", True)
        lomn_form.addRow("", self.lomn_prevent_surgery_checkbox)

        self.lomn_risk_statement_input = QTextEdit()
        self.lomn_risk_statement_input.setMinimumHeight(70)
        self.lomn_risk_statement_input.setPlaceholderText("Describe the risks of non-treatment")
        self.lomn_risk_statement_input.setPlainText(
            "Without appropriate treatment, the patient remains at risk for persistent pain, worsening functional limitation, and continued impairment of daily activities."
        )
        self.lomn_risk_statement_input.textChanged.connect(self.refresh_preview)
        lomn_form.addRow("Risk Statement", self.lomn_risk_statement_input)

        self.lomn_reasonable_statement_input = QTextEdit()
        self.lomn_reasonable_statement_input.setMinimumHeight(70)
        self.lomn_reasonable_statement_input.setPlaceholderText("State why the requested care is reasonable and necessary")
        self.lomn_reasonable_statement_input.setPlainText(
            "The requested care is consistent with the documented diagnosis, the failure of conservative treatment, and the current clinical findings."
        )
        self.lomn_reasonable_statement_input.textChanged.connect(self.refresh_preview)
        lomn_form.addRow("Reasonable / Necessary", self.lomn_reasonable_statement_input)

        self.lomn_contact_statement_input = QTextEdit()
        self.lomn_contact_statement_input.setMinimumHeight(60)
        self.lomn_contact_statement_input.setPlaceholderText("Optional contact statement")
        self.lomn_contact_statement_input.setPlainText(
            "Additional supporting documentation can be provided upon request."
        )
        self.lomn_contact_statement_input.textChanged.connect(self.refresh_preview)
        lomn_form.addRow("Contact Statement", self.lomn_contact_statement_input)

        workspace_layout.addWidget(self.lomn_group)

        self.consult_request_group = QGroupBox("Consultation & Treatment Request Template")
        self.consult_request_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        consult_form = QFormLayout(self.consult_request_group)
        self._configure_form_layout(consult_form)

        self.consult_request_date_input = self._make_line_edit("MM/DD/YYYY")
        consult_form.addRow("Request Date", self.consult_request_date_input)
        self.consult_va_claim_number_input = self._make_line_edit("VA claim number if applicable")
        consult_form.addRow("VA Claim Number", self.consult_va_claim_number_input)
        self.consult_referring_va_provider_input = self._make_line_edit("Referring VA provider")
        consult_form.addRow("Referring VA Provider", self.consult_referring_va_provider_input)

        self.consult_reason_input = QTextEdit()
        self.consult_reason_input.setMinimumHeight(70)
        self.consult_reason_input.setPlaceholderText("Summarize the reason for consultation and requested treatment")
        self.consult_reason_input.setPlainText(
            "Authorization is requested for specialty consultation and treatment planning related to documented lumbar disc pathology and persistent pain despite conservative management."
        )
        self.consult_reason_input.textChanged.connect(self.refresh_preview)
        consult_form.addRow("Reason for Consultation", self.consult_reason_input)

        self.consult_primary_diagnosis_input = self._make_line_edit("Primary diagnosis")
        consult_form.addRow("Primary Diagnosis", self.consult_primary_diagnosis_input)
        self.consult_secondary_diagnosis_input = self._make_line_edit("Secondary diagnosis")
        consult_form.addRow("Secondary Diagnosis", self.consult_secondary_diagnosis_input)

        self.consult_symptom_axial_pain_checkbox = self._make_checkbox("Chronic axial lumbar pain", True)
        consult_form.addRow("Symptoms", self.consult_symptom_axial_pain_checkbox)
        self.consult_symptom_activity_checkbox = self._make_checkbox("Activity-related exacerbation (sitting, standing, bending)", True)
        consult_form.addRow("", self.consult_symptom_activity_checkbox)
        self.consult_symptom_tolerance_checkbox = self._make_checkbox("Reduced tolerance for prolonged positioning", True)
        consult_form.addRow("", self.consult_symptom_tolerance_checkbox)
        self.consult_symptom_function_checkbox = self._make_checkbox("Functional impairment affecting occupational and daily activities", True)
        consult_form.addRow("", self.consult_symptom_function_checkbox)

        self.consult_mri_date_input = self._make_line_edit("MM/DD/YYYY")
        consult_form.addRow("MRI Date", self.consult_mri_date_input)
        self.consult_mri_findings_input = self._make_line_edit("MRI findings")
        consult_form.addRow("MRI Findings", self.consult_mri_findings_input)
        self.consult_conservative_duration_input = self._make_line_edit("Duration of prior treatment")
        consult_form.addRow("Conservative Care Duration", self.consult_conservative_duration_input)

        self.consult_physical_therapy_checkbox = self._make_checkbox("Physical therapy", True)
        consult_form.addRow("Conservative Care", self.consult_physical_therapy_checkbox)
        self.consult_nsaids_checkbox = self._make_checkbox("NSAIDs and non-opioid analgesics", True)
        consult_form.addRow("", self.consult_nsaids_checkbox)
        self.consult_activity_mod_checkbox = self._make_checkbox("Activity modification", True)
        consult_form.addRow("", self.consult_activity_mod_checkbox)
        self.consult_home_exercise_checkbox = self._make_checkbox("Home exercise program", True)
        consult_form.addRow("", self.consult_home_exercise_checkbox)
        self.consult_interventional_history_checkbox = self._make_checkbox("Epidural steroid injections and/or other interventional procedures (if applicable)", True)
        consult_form.addRow("", self.consult_interventional_history_checkbox)

        self.consult_include_pm_consult_checkbox = self._make_checkbox("Comprehensive pain management consultation", True)
        consult_form.addRow("Requested Services", self.consult_include_pm_consult_checkbox)
        self.consult_include_planning_checkbox = self._make_checkbox("Diagnostic confirmation and procedural planning", True)
        consult_form.addRow("", self.consult_include_planning_checkbox)
        self.consult_include_annulargram_checkbox = self._make_checkbox("Diagnostic Annulargram", True)
        consult_form.addRow("", self.consult_include_annulargram_checkbox)
        self.consult_include_fibrin_checkbox = self._make_checkbox("Intraannular Fibrin injection if indicated", True)
        consult_form.addRow("", self.consult_include_fibrin_checkbox)
        self.consult_fibrin_levels_input = self._make_line_edit("Specific lumbar level(s)")
        consult_form.addRow("Fibrin Levels", self.consult_fibrin_levels_input)
        self.consult_include_follow_up_checkbox = self._make_checkbox("Routine post-procedure follow-up visit(s)", True)
        consult_form.addRow("", self.consult_include_follow_up_checkbox)

        self.consult_scope_exclusion_input = QTextEdit()
        self.consult_scope_exclusion_input.setMinimumHeight(70)
        self.consult_scope_exclusion_input.setPlaceholderText("Optional scope or exclusion note")
        self.consult_scope_exclusion_input.setPlainText(
            "This request is limited to evaluation, procedural planning, the indicated intervention if clinically appropriate, and standard post-procedure follow-up related only to the documented lumbar condition."
        )
        self.consult_scope_exclusion_input.textChanged.connect(self.refresh_preview)
        consult_form.addRow("Scope of Request", self.consult_scope_exclusion_input)

        self.consult_medical_rationale_input = QTextEdit()
        self.consult_medical_rationale_input.setMinimumHeight(80)
        self.consult_medical_rationale_input.setPlaceholderText("Document the medical rationale")
        self.consult_medical_rationale_input.setPlainText(
            "The requested evaluation and treatment pathway is supported by the patient’s ongoing symptoms, functional impairment, failure of conservative care, and imaging findings that correlate with the clinical presentation."
        )
        self.consult_medical_rationale_input.textChanged.connect(self.refresh_preview)
        consult_form.addRow("Medical Rationale", self.consult_medical_rationale_input)

        self.consult_goal_pain_checkbox = self._make_checkbox("Pain reduction", True)
        consult_form.addRow("Clinical Goals", self.consult_goal_pain_checkbox)
        self.consult_goal_function_checkbox = self._make_checkbox("Functional improvement", True)
        consult_form.addRow("", self.consult_goal_function_checkbox)
        self.consult_goal_analgesics_checkbox = self._make_checkbox("Decreased reliance on chronic analgesic therapy", True)
        consult_form.addRow("", self.consult_goal_analgesics_checkbox)
        self.consult_goal_surgery_checkbox = self._make_checkbox("Prevention of progression requiring more invasive surgical intervention", True)
        consult_form.addRow("", self.consult_goal_surgery_checkbox)

        self.consult_risk_without_treatment_input = QTextEdit()
        self.consult_risk_without_treatment_input.setMinimumHeight(70)
        self.consult_risk_without_treatment_input.setPlaceholderText("Optional risk of non-treatment statement")
        self.consult_risk_without_treatment_input.setPlainText(
            "Without appropriate specialty evaluation and treatment, the patient may continue to experience persistent pain, reduced function, and progression of disability."
        )
        self.consult_risk_without_treatment_input.textChanged.connect(self.refresh_preview)
        consult_form.addRow("Risk Without Treatment", self.consult_risk_without_treatment_input)

        self.consult_duration_scope_input = QTextEdit()
        self.consult_duration_scope_input.setMinimumHeight(80)
        self.consult_duration_scope_input.setPlaceholderText("Describe the scope and expected duration of care")
        self.consult_duration_scope_input.setPlainText(
            "This consultation and treatment request is limited to a defined evaluation and treatment pathway rather than open-ended pain management."
        )
        self.consult_duration_scope_input.textChanged.connect(self.refresh_preview)
        consult_form.addRow("Duration and Scope", self.consult_duration_scope_input)

        self.consult_contact_statement_input = QTextEdit()
        self.consult_contact_statement_input.setMinimumHeight(60)
        self.consult_contact_statement_input.setPlaceholderText("Optional contact statement")
        self.consult_contact_statement_input.setPlainText(
            "Please contact the treating office if additional records or clarification are needed for review."
        )
        self.consult_contact_statement_input.textChanged.connect(self.refresh_preview)
        consult_form.addRow("Contact Statement", self.consult_contact_statement_input)

        self.provider_address_input = self._make_line_edit("Community Care practice address")
        consult_form.addRow("Community Care Practice Address", self.provider_address_input)
        self.provider_email_input = self._make_line_edit("Community Care secure email")
        consult_form.addRow("Community Care Secure Email", self.provider_email_input)

        workspace_layout.addWidget(self.consult_request_group)

        self.clinical_doc_group = QGroupBox("Clinical Notes Template")
        self.clinical_doc_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        clinical_doc_form = QFormLayout(self.clinical_doc_group)
        self._configure_form_layout(clinical_doc_form)

        self.clinical_doc_title_input = self._make_line_edit("Clinical Documentation Template")
        self.clinical_doc_title_input.setText("Clinical Documentation Template")
        clinical_doc_form.addRow("Template Title", self.clinical_doc_title_input)

        self.clinical_doc_chief_complaint_input = self._make_line_edit("Chief complaint")
        clinical_doc_form.addRow("Chief Complaint", self.clinical_doc_chief_complaint_input)

        self.clinical_doc_duration_3m_checkbox = self._make_checkbox("> 3 months", True)
        clinical_doc_form.addRow("Duration of Symptoms", self.clinical_doc_duration_3m_checkbox)
        self.clinical_doc_duration_6m_checkbox = self._make_checkbox("> 6 months", False)
        clinical_doc_form.addRow("", self.clinical_doc_duration_6m_checkbox)
        self.clinical_doc_duration_12m_checkbox = self._make_checkbox("> 12 months", False)
        clinical_doc_form.addRow("", self.clinical_doc_duration_12m_checkbox)
        self.clinical_doc_exact_duration_input = self._make_line_edit("Exact duration")
        clinical_doc_form.addRow("Exact Duration", self.clinical_doc_exact_duration_input)

        self.clinical_doc_pain_axial_checkbox = self._make_checkbox("Axial lumbar pain", True)
        clinical_doc_form.addRow("Pain Characteristics", self.clinical_doc_pain_axial_checkbox)
        self.clinical_doc_pain_discogenic_checkbox = self._make_checkbox("Discogenic pattern", True)
        clinical_doc_form.addRow("", self.clinical_doc_pain_discogenic_checkbox)
        self.clinical_doc_pain_activity_checkbox = self._make_checkbox("Activity-related exacerbation", True)
        clinical_doc_form.addRow("", self.clinical_doc_pain_activity_checkbox)
        self.clinical_doc_pain_sitting_checkbox = self._make_checkbox("Sitting intolerance", True)
        clinical_doc_form.addRow("", self.clinical_doc_pain_sitting_checkbox)
        self.clinical_doc_pain_standing_checkbox = self._make_checkbox("Standing intolerance", True)
        clinical_doc_form.addRow("", self.clinical_doc_pain_standing_checkbox)
        self.clinical_doc_pain_bending_checkbox = self._make_checkbox("Bending/lifting provocation", True)
        clinical_doc_form.addRow("", self.clinical_doc_pain_bending_checkbox)
        self.clinical_doc_pain_severity_input = self._make_line_edit("0-10")
        clinical_doc_form.addRow("Pain Severity", self.clinical_doc_pain_severity_input)

        self.clinical_doc_limit_occupational_checkbox = self._make_checkbox("Occupational duties", True)
        clinical_doc_form.addRow("Functional Limitation", self.clinical_doc_limit_occupational_checkbox)
        self.clinical_doc_limit_sitting_checkbox = self._make_checkbox("Prolonged sitting", True)
        clinical_doc_form.addRow("", self.clinical_doc_limit_sitting_checkbox)
        self.clinical_doc_limit_standing_checkbox = self._make_checkbox("Prolonged standing", True)
        clinical_doc_form.addRow("", self.clinical_doc_limit_standing_checkbox)
        self.clinical_doc_limit_ambulation_checkbox = self._make_checkbox("Ambulation tolerance", False)
        clinical_doc_form.addRow("", self.clinical_doc_limit_ambulation_checkbox)
        self.clinical_doc_limit_household_checkbox = self._make_checkbox("Household activities", True)
        clinical_doc_form.addRow("", self.clinical_doc_limit_household_checkbox)
        self.clinical_doc_limit_sleep_checkbox = self._make_checkbox("Sleep disturbance", True)
        clinical_doc_form.addRow("", self.clinical_doc_limit_sleep_checkbox)
        self.clinical_doc_functional_impact_input = QTextEdit()
        self.clinical_doc_functional_impact_input.setMinimumHeight(80)
        self.clinical_doc_functional_impact_input.textChanged.connect(self.refresh_preview)
        clinical_doc_form.addRow("Specific Functional Impact", self.clinical_doc_functional_impact_input)

        self.clinical_doc_conservative_pt_checkbox = self._make_checkbox("Physical therapy", True)
        clinical_doc_form.addRow("Conservative Therapy", self.clinical_doc_conservative_pt_checkbox)
        self.clinical_doc_conservative_home_exercise_checkbox = self._make_checkbox("Home exercise program", True)
        clinical_doc_form.addRow("", self.clinical_doc_conservative_home_exercise_checkbox)
        self.clinical_doc_conservative_nsaids_checkbox = self._make_checkbox("NSAIDs", True)
        clinical_doc_form.addRow("", self.clinical_doc_conservative_nsaids_checkbox)
        self.clinical_doc_conservative_non_opioid_checkbox = self._make_checkbox("Non-opioid analgesics", True)
        clinical_doc_form.addRow("", self.clinical_doc_conservative_non_opioid_checkbox)
        self.clinical_doc_conservative_activity_checkbox = self._make_checkbox("Activity modification", True)
        clinical_doc_form.addRow("", self.clinical_doc_conservative_activity_checkbox)
        self.clinical_doc_conservative_esi_checkbox = self._make_checkbox("Epidural steroid injections", True)
        clinical_doc_form.addRow("", self.clinical_doc_conservative_esi_checkbox)
        self.clinical_doc_conservative_other_checkbox = self._make_checkbox("Other interventional procedures", False)
        clinical_doc_form.addRow("", self.clinical_doc_conservative_other_checkbox)
        self.clinical_doc_conservative_duration_input = self._make_line_edit("Duration of conservative treatment")
        clinical_doc_form.addRow("Conservative Care Duration", self.clinical_doc_conservative_duration_input)
        self.clinical_doc_esi_response_combo = self._make_choice_combo(["Temporary relief", "Partial relief", "No relief"])
        clinical_doc_form.addRow("Response to Prior ESI", self.clinical_doc_esi_response_combo)

        self.clinical_doc_mri_date_input = self._make_line_edit("MM/DD/YYYY")
        clinical_doc_form.addRow("MRI Date", self.clinical_doc_mri_date_input)
        self.clinical_doc_imaging_annular_checkbox = self._make_checkbox("Annular tear", True)
        clinical_doc_form.addRow("Imaging Findings", self.clinical_doc_imaging_annular_checkbox)
        self.clinical_doc_imaging_degeneration_checkbox = self._make_checkbox("Disc degeneration", True)
        clinical_doc_form.addRow("", self.clinical_doc_imaging_degeneration_checkbox)
        self.clinical_doc_imaging_protrusion_checkbox = self._make_checkbox("Disc protrusion", False)
        clinical_doc_form.addRow("", self.clinical_doc_imaging_protrusion_checkbox)
        self.clinical_doc_imaging_displacement_checkbox = self._make_checkbox("Disc displacement", False)
        clinical_doc_form.addRow("", self.clinical_doc_imaging_displacement_checkbox)
        self.clinical_doc_affected_levels_input = self._make_line_edit("Affected levels")
        clinical_doc_form.addRow("Affected Levels", self.clinical_doc_affected_levels_input)

        self.clinical_doc_primary_diagnosis_input = self._make_line_edit("Primary diagnosis (ICD-10)")
        clinical_doc_form.addRow("Primary Diagnosis", self.clinical_doc_primary_diagnosis_input)
        self.clinical_doc_secondary_diagnosis_input = self._make_line_edit("Secondary diagnosis")
        clinical_doc_form.addRow("Secondary Diagnosis", self.clinical_doc_secondary_diagnosis_input)
        self.clinical_doc_assessment_summary_input = QTextEdit()
        self.clinical_doc_assessment_summary_input.setMinimumHeight(70)
        self.clinical_doc_assessment_summary_input.setPlaceholderText("Summarize the assessment")
        self.clinical_doc_assessment_summary_input.setPlainText("")
        self.clinical_doc_assessment_summary_input.textChanged.connect(self.refresh_preview)
        clinical_doc_form.addRow("Assessment", self.clinical_doc_assessment_summary_input)

        self.clinical_doc_treatment_plan_intro_input = QTextEdit()
        self.clinical_doc_treatment_plan_intro_input.setMinimumHeight(70)
        self.clinical_doc_treatment_plan_intro_input.setPlaceholderText("Summarize the treatment plan")
        self.clinical_doc_treatment_plan_intro_input.setPlainText("")
        self.clinical_doc_treatment_plan_intro_input.textChanged.connect(self.refresh_preview)
        clinical_doc_form.addRow("Treatment Plan", self.clinical_doc_treatment_plan_intro_input)
        self.clinical_doc_plan_diagnostic_checkbox = self._make_checkbox("Diagnostic confirmation if necessary", True)
        clinical_doc_form.addRow("Plan Includes", self.clinical_doc_plan_diagnostic_checkbox)
        self.clinical_doc_plan_intervention_checkbox = self._make_checkbox("Intradiscal annular intervention if indicated", True)
        clinical_doc_form.addRow("", self.clinical_doc_plan_intervention_checkbox)
        self.clinical_doc_plan_follow_up_checkbox = self._make_checkbox("Standard post-procedure follow-up", True)
        clinical_doc_form.addRow("", self.clinical_doc_plan_follow_up_checkbox)
        self.clinical_doc_plan_exclusion_input = QTextEdit()
        self.clinical_doc_plan_exclusion_input.setMinimumHeight(70)
        self.clinical_doc_plan_exclusion_input.setPlaceholderText("Optional plan limitation or exclusion note")
        self.clinical_doc_plan_exclusion_input.setPlainText(
            "This plan does not request open-ended medication management or unrelated pain treatment outside the documented lumbar condition."
        )
        self.clinical_doc_plan_exclusion_input.textChanged.connect(self.refresh_preview)
        clinical_doc_form.addRow("Plan Exclusion", self.clinical_doc_plan_exclusion_input)

        self.clinical_doc_physician_narrative_input = QTextEdit()
        self.clinical_doc_physician_narrative_input.setMinimumHeight(110)
        self.clinical_doc_physician_narrative_input.setPlaceholderText("Document the physician narrative for this patient")
        self.clinical_doc_physician_narrative_input.setPlainText("")
        self.clinical_doc_physician_narrative_input.textChanged.connect(self.refresh_preview)
        clinical_doc_form.addRow("Physician Narrative", self.clinical_doc_physician_narrative_input)

        workspace_layout.addWidget(self.clinical_doc_group)

        self.va10172_group = QGroupBox("VA Form 10-10172")
        self.va10172_group.setStyleSheet("QGroupBox { font-weight:700; color:#E5E7EB; }")
        va10172_form = QFormLayout(self.va10172_group)
        self._configure_form_layout(va10172_form)

        template_row = QWidget()
        template_layout = QHBoxLayout(template_row)
        template_layout.setContentsMargins(0, 0, 0, 0)
        template_layout.setSpacing(8)
        self.va10172_template_value = QLabel(self.config.get("va_form_10172_template_path") or "No template selected")
        self.va10172_template_value.setWordWrap(True)
        self.va10172_template_value.setStyleSheet("color:#8FA6C1;")
        choose_va10172_template_button = QPushButton("Choose PDF Template")
        choose_va10172_template_button.clicked.connect(self.choose_va10172_template)
        template_layout.addWidget(self.va10172_template_value, stretch=1)
        template_layout.addWidget(choose_va10172_template_button)
        va10172_form.addRow("Template PDF", template_row)

        self.va10172_facility_address_input = QTextEdit()
        self.va10172_facility_address_input.setMinimumHeight(70)
        self.va10172_facility_address_input.textChanged.connect(self.refresh_preview)
        va10172_form.addRow("VA Facility & Address", self.va10172_facility_address_input)

        self.va10172_provider_office_address_input = QTextEdit()
        self.va10172_provider_office_address_input.setMinimumHeight(80)
        self.va10172_provider_office_address_input.textChanged.connect(self.refresh_preview)
        va10172_form.addRow("Ordering Provider Office Name & Address", self.va10172_provider_office_address_input)

        self.va10172_is_ihs_combo = self._make_choice_combo(["No", "Yes"])
        va10172_form.addRow("Indian Health Services / THP Provider", self.va10172_is_ihs_combo)
        self.va10172_provider_phone_input = self._make_line_edit("Provider phone")
        va10172_form.addRow("Ordering Provider Phone", self.va10172_provider_phone_input)
        self.va10172_provider_fax_input = self._make_line_edit("Provider fax")
        va10172_form.addRow("Ordering Provider Fax", self.va10172_provider_fax_input)
        self.va10172_provider_email_input = self._make_line_edit("Secure email")
        va10172_form.addRow("Ordering Provider Secure Email", self.va10172_provider_email_input)

        self.va10172_48h_combo = self._make_choice_combo(["No", "Yes"])
        va10172_form.addRow("Care Needed Within 48 Hours", self.va10172_48h_combo)
        self.va10172_continuation_combo = self._make_choice_combo(["No", "Yes"])
        va10172_form.addRow("Continuation of Care", self.va10172_continuation_combo)
        self.va10172_referral_specialty_combo = self._make_choice_combo(["No", "Yes"])
        va10172_form.addRow("Referral to Another Specialty", self.va10172_referral_specialty_combo)
        self.va10172_referral_specialty_text_input = self._make_line_edit("Specialty name")
        va10172_form.addRow("Specialty", self.va10172_referral_specialty_text_input)

        self.va10172_diagnosis_description_input = QTextEdit()
        self.va10172_diagnosis_description_input.setMinimumHeight(70)
        self.va10172_diagnosis_description_input.textChanged.connect(self.refresh_preview)
        va10172_form.addRow("Diagnosis Description", self.va10172_diagnosis_description_input)
        self.va10172_requested_cpt_input = self._make_line_edit("Requested CPT/HCPCS code")
        va10172_form.addRow("Requested CPT/HCPCS Code", self.va10172_requested_cpt_input)
        self.va10172_requested_cpt_description_input = self._make_line_edit("CPT/HCPCS description")
        va10172_form.addRow("Description CPT/HCPCS Code", self.va10172_requested_cpt_description_input)

        self.va10172_geriatric_option_combo = self._make_choice_combo(
            [
                "None",
                "Community Nursing Home",
                "Home Infusion",
                "Hospice/Palliative Care",
                "Skilled Home Health Care",
                "Community Adult Day Health Care",
                "Home Homemaker/Home Health Aide",
                "Respite",
            ]
        )
        va10172_form.addRow("Geriatric / Extended Care", self.va10172_geriatric_option_combo)

        self.va10172_reason_for_request_input = QTextEdit()
        self.va10172_reason_for_request_input.setMinimumHeight(130)
        self.va10172_reason_for_request_input.textChanged.connect(self.refresh_preview)
        va10172_form.addRow("Reason for Request", self.va10172_reason_for_request_input)

        self.va10172_provider_name_printed_input = self._make_line_edit("CCN ordering provider printed name")
        va10172_form.addRow("CCN Ordering Provider Name (Printed)", self.va10172_provider_name_printed_input)
        self.va10172_provider_npi_input = self._make_line_edit("CCN ordering provider NPI")
        va10172_form.addRow("CCN Ordering Provider NPI", self.va10172_provider_npi_input)
        va_signature_widget, self.va10172_signature_text_input = self._make_signature_field("va10172_signature_text", "CCN ordering provider signature")
        va10172_form.addRow("CCN Ordering Provider Signature", va_signature_widget)
        self.va10172_today_date_input = self._make_line_edit("MM/DD/YYYY")
        va10172_form.addRow("Today's Date", self.va10172_today_date_input)

        workspace_layout.addWidget(self.va10172_group)

        action_row = QGridLayout()
        action_row.setHorizontalSpacing(10)
        action_row.setVerticalSpacing(10)
        self.new_packet_button = QPushButton("New Packet")
        self._style_builder_button(self.new_packet_button)
        self.new_packet_button.clicked.connect(self.start_new_packet)
        self.save_to_library_button = QPushButton("Save To Library")
        self._style_builder_button(self.save_to_library_button)
        self.save_to_library_button.clicked.connect(self.save_draft_json)
        self.export_word_button = QPushButton("Word")
        self._style_builder_button(self.export_word_button)
        self.export_word_button.clicked.connect(self.export_word)
        self.export_pdf_button = QPushButton("PDF")
        self._style_builder_button(self.export_pdf_button)
        self.export_pdf_button.clicked.connect(self.export_pdf)
        self.export_both_button = QPushButton("Word + PDF")
        self._style_builder_button(self.export_both_button)
        self.export_both_button.clicked.connect(self.export_both)
        self.open_folder_button = QPushButton("Open Folder")
        self._style_builder_button(self.open_folder_button)
        self.open_folder_button.clicked.connect(self.open_export_folder)
        action_row.addWidget(self.new_packet_button, 0, 0)
        action_row.addWidget(self.save_to_library_button, 0, 1)
        action_row.addWidget(self.export_word_button, 0, 2)
        action_row.addWidget(self.export_pdf_button, 1, 0)
        action_row.addWidget(self.export_both_button, 1, 1)
        action_row.addWidget(self.open_folder_button, 1, 2)
        workspace_layout.addLayout(action_row)

        bundle_row = QGridLayout()
        bundle_row.setHorizontalSpacing(10)
        bundle_row.setVerticalSpacing(10)
        bundle_label = QLabel("Bundle Export")
        bundle_label.setStyleSheet("font-weight:700; color:#C8D8E8;")
        self.bundle_format_combo = QComboBox()
        self.bundle_format_combo.addItems(["Word", "PDF", "Both"])
        self.bundle_format_combo.setCurrentText("Both")
        self.export_referral_button = QPushButton("Referral Request")
        self._style_builder_button(self.export_referral_button)
        self.export_referral_button.clicked.connect(self.export_referral_request_bundle)
        self.export_packet_button = QPushButton("Patient Packet")
        self._style_builder_button(self.export_packet_button)
        self.export_packet_button.clicked.connect(self.export_patient_packet_bundle)
        bundle_row.addWidget(bundle_label, 0, 0)
        bundle_row.addWidget(self.bundle_format_combo, 0, 1)
        bundle_row.addWidget(self.export_referral_button, 0, 2)
        bundle_row.addWidget(self.export_packet_button, 0, 3)
        bundle_row.setColumnStretch(4, 1)
        workspace_layout.addLayout(bundle_row)
        workspace_layout.addStretch(1)
        self._export_controls = [
            self.export_word_button,
            self.export_pdf_button,
            self.export_both_button,
            self.export_referral_button,
            self.export_packet_button,
            self.bundle_format_combo,
            choose_folder_button,
            self.open_folder_button,
        ]

        preview_panel = QWidget()
        preview_layout = QVBoxLayout(preview_panel)
        preview_layout.setContentsMargins(8, 0, 0, 0)
        preview_layout.setSpacing(6)

        self.preview_tabs = QTabWidget()
        self.preview_tabs.setDocumentMode(True)

        preview_tab = QWidget()
        preview_tab_layout = QVBoxLayout(preview_tab)
        preview_tab_layout.setContentsMargins(0, 0, 0, 0)
        preview_tab_layout.setSpacing(8)
        self.preview_status_label = QLabel()
        self.preview_status_label.setWordWrap(True)
        self.preview_status_label.setStyleSheet("color:#8FA6C1; font-size:12px;")
        preview_tab_layout.addWidget(self.preview_status_label)
        preview_action_row = QHBoxLayout()
        preview_action_row.setContentsMargins(0, 0, 0, 0)
        preview_action_row.setSpacing(8)
        preview_action_row.addStretch(1)
        self.exact_preview_button = QPushButton("Refresh Exact Preview")
        self._style_builder_button(self.exact_preview_button)
        self.exact_preview_button.setMaximumWidth(180)
        self.exact_preview_button.clicked.connect(self.refresh_exact_preview)
        preview_action_row.addWidget(self.exact_preview_button, 0, Qt.AlignRight)
        preview_tab_layout.addLayout(preview_action_row)
        self.preview_stack = QStackedWidget()
        self.preview_view = QTextEdit()
        self.preview_view.setReadOnly(True)
        self.preview_view.setMinimumWidth(300)
        self.preview_view.document().setDocumentMargin(0)
        self.preview_view.setStyleSheet(
            "background:#FFFFFF; border:1px solid #D6DCE5; border-radius:10px; color:#111827; padding:0px;"
        )
        self.preview_pdf_document = QPdfDocument(self)
        self.preview_pdf_view = QPdfView()
        self.preview_pdf_view.setDocument(self.preview_pdf_document)
        self.preview_pdf_view.setPageMode(QPdfView.PageMode.MultiPage)
        self.preview_pdf_view.setZoomMode(QPdfView.ZoomMode.FitToWidth)
        self.preview_pdf_view.setStyleSheet(
            "background:#09121B; border:1px solid #243446; border-radius:10px;"
        )
        self.preview_stack.addWidget(self.preview_view)
        self.preview_stack.addWidget(self.preview_pdf_view)
        preview_tab_layout.addWidget(self.preview_stack, stretch=1)

        lab_tab = QWidget()
        lab_tab_layout = QVBoxLayout(lab_tab)
        lab_tab_layout.setContentsMargins(0, 0, 0, 0)
        lab_tab_layout.setSpacing(8)
        self.lab_view = QTextEdit()
        self.lab_view.setReadOnly(True)
        self.lab_view.setMinimumWidth(300)
        self.lab_view.setStyleSheet(
            "background:#09121B; border:1px solid #243446; border-radius:10px; color:#E8F1FC; padding:0px;"
        )
        lab_tab_layout.addWidget(self.lab_view, stretch=1)

        wording_tab = self._build_wording_tab()
        library_tab = self._build_library_tab()

        self.preview_tabs.addTab(preview_tab, "Export Preview")
        self.preview_tabs.addTab(wording_tab, "Wording Assist")
        self.preview_tabs.addTab(lab_tab, "Lab")
        self.preview_tabs.addTab(library_tab, "Library")
        self.preview_tabs.tabBar().setUsesScrollButtons(True)
        preview_layout.addWidget(self.preview_tabs, stretch=1)
        splitter.addWidget(preview_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([760, 760])

        self.packet_title_input.setText("Community Care Referral Request")
        self._builder_ready = True
        self.on_profile_changed(self.profile_combo.currentText())
        self.refresh_library()
        self._update_current_packet_status()
        self.refresh_preview()
        QTimer.singleShot(0, self._rebalance_builder_splitter)

    def _make_line_edit(self, placeholder):
        widget = QLineEdit()
        widget.setPlaceholderText(placeholder)
        widget.textChanged.connect(self.refresh_preview)
        return widget

    def _make_signature_field(self, field_name, placeholder):
        line_edit = self._make_line_edit(placeholder)
        line_edit.setPlaceholderText(f"{placeholder} (double-click to draw)")
        line_edit.mouseDoubleClickEvent = lambda event, key=field_name: self._open_signature_capture(key)
        button = QPushButton("Draw")
        button.setFixedHeight(32)
        button.setMaximumWidth(84)
        button.setStyleSheet(
            "QPushButton {"
            "background-color:#1D2A3A; color:#FFFFFF; border:1px solid #34506B; border-radius:8px; "
            "padding:4px 10px; font-size:12px; font-weight:600; }"
            "QPushButton:hover { background-color:#223246; }"
        )
        button.clicked.connect(lambda _=False, key=field_name: self._open_signature_capture(key))
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(line_edit, stretch=1)
        layout.addWidget(button, 0)
        return container, line_edit

    def _apply_signature_field_state(self, field_name):
        binding = PACKET_WIDGET_BINDINGS.get(field_name)
        if not binding:
            return
        widget = getattr(self, binding[0], None)
        if widget is None:
            return
        has_signature = bool(self._signature_images.get(SIGNATURE_IMAGE_FIELDS.get(field_name, field_name)))
        tooltip = "Double-click to draw a signature." if not has_signature else "Drawn signature captured. Double-click or use Draw to replace it."
        widget.setToolTip(tooltip)
        if has_signature:
            widget.setStyleSheet("QLineEdit { border:1px solid #2C8B57; border-radius:8px; padding:6px; }")
        else:
            widget.setStyleSheet("")

    def _open_signature_capture(self, field_name):
        binding = PACKET_WIDGET_BINDINGS.get(field_name)
        if not binding:
            return
        widget = getattr(self, binding[0], None)
        if widget is None:
            return
        image_field = SIGNATURE_IMAGE_FIELDS.get(field_name, field_name)
        role_label = SIGNATURE_ROLE_LABELS.get(field_name, "signature")
        dialog = SignatureCaptureDialog(
            label_text=f"Draw the {role_label} below. Use Reset to clear it, then Accept to apply it to the current packet.",
            existing_base64=self._signature_images.get(image_field, ""),
            parent=self,
        )
        if dialog.exec() != QDialog.Accepted:
            return
        encoded = dialog.signature_base64()
        self._signature_images[image_field] = encoded
        if encoded and not widget.text().strip():
            fallback_name = ""
            if field_name == "patient_signature_name":
                fallback_name = self.patient_name_input.text().strip()
            elif field_name == "office_staff_signature":
                fallback_name = self.office_staff_name_input.text().strip()
            elif field_name == "va10172_signature_text":
                fallback_name = self.va10172_provider_name_printed_input.text().strip() or self.provider_input.text().strip()
            if fallback_name:
                widget.setText(fallback_name)
        self._apply_signature_field_state(field_name)
        self.refresh_preview()

    def _configure_form_layout(self, form_layout):
        form_layout.setLabelAlignment(Qt.AlignLeft)
        form_layout.setFormAlignment(Qt.AlignLeft | Qt.AlignTop)
        form_layout.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        form_layout.setRowWrapPolicy(QFormLayout.WrapAllRows)
        form_layout.setHorizontalSpacing(14)
        form_layout.setVerticalSpacing(8)

    def _style_builder_button(self, button):
        button.setFixedHeight(38)
        button.setMaximumWidth(190)
        button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        button.setStyleSheet(
            "QPushButton {"
            "background-color:#1D2A3A; color:#FFFFFF; border:1px solid #34506B; border-radius:8px; "
            "padding:4px 12px; font-size:13px; font-weight:600; }"
            "QPushButton:hover { background-color:#223246; }"
        )

    def _set_bound_widget_value(self, widget, value, kind):
        with QSignalBlocker(widget):
            if kind == "text":
                widget.setText(str(value or ""))
            elif kind == "toPlainText":
                widget.setPlainText(str(value or ""))
            elif kind == "currentText":
                text = str(value or "")
                index = widget.findText(text)
                if index >= 0:
                    widget.setCurrentIndex(index)
                elif text:
                    widget.setCurrentText(text)
            elif kind == "isChecked":
                widget.setChecked(bool(value))

    def _apply_payload_to_widgets(self, payload, base_filename=None):
        packet = normalize_packet_builder_payload(payload)
        self._builder_ready = False
        try:
            self._wording_assist_state = dict(packet.get("wording_assist_state") or {})
            self._signature_images = {
                image_field: str(packet.get(image_field) or "").strip()
                for image_field in SIGNATURE_IMAGE_FIELDS.values()
            }
            for field_name, (attr_name, kind) in PACKET_WIDGET_BINDINGS.items():
                widget = getattr(self, attr_name, None)
                if widget is None:
                    continue
                self._set_bound_widget_value(widget, packet.get(field_name), kind)
            for field_name in SIGNATURE_IMAGE_FIELDS:
                self._apply_signature_field_state(field_name)
            if hasattr(self, "base_filename_input"):
                with QSignalBlocker(self.base_filename_input):
                    self.base_filename_input.setText(sanitize_builder_filename(base_filename or "truecore_packet"))
            template_path = str(packet.get("va10172_template_path") or self.config.get("va_form_10172_template_path") or "").strip()
            if template_path:
                self.config = dict(self.save_config_callback({"va_form_10172_template_path": template_path}) or {})
            if hasattr(self, "va10172_template_value"):
                self.va10172_template_value.setText(
                    str(self.config.get("va_form_10172_template_path") or _default_va_form_10172_template_path() or "")
                )
            self._shared_sync_state.clear()
        finally:
            self._builder_ready = True
        self.on_profile_changed(packet.get("packet_profile") or self.profile_combo.currentText())
        self.refresh_preview()

    def start_new_packet(self):
        reply = QMessageBox.question(
            self,
            "Start New Packet",
            "Clear the current working packet and start a new one?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self.current_draft_id = None
        self.current_draft_record = {}
        self._signature_images = {}
        self._apply_payload_to_widgets(default_packet_builder_payload(), "truecore_packet")
        self.preview_tabs.setCurrentIndex(0)
        if hasattr(self, "packet_builder_left_tabs"):
            self.packet_builder_left_tabs.setCurrentWidget(self.packet_intake_page)
        self.refresh_library()
        self._update_current_packet_status()

    def _rebalance_builder_splitter(self):
        if not hasattr(self, "builder_splitter"):
            return
        total = max(0, self.builder_splitter.width())
        if total <= 0:
            return
        half = total // 2
        self.builder_splitter.setSizes([half, max(half, total - half)])

    def _make_choice_combo(self, options):
        widget = QComboBox()
        widget.addItems(list(options or []))
        widget.currentTextChanged.connect(self.refresh_preview)
        return widget

    def _make_checkbox(self, label, checked=False):
        widget = QCheckBox(label)
        widget.setChecked(bool(checked))
        widget.stateChanged.connect(self.refresh_preview)
        return widget

    def _apply_profile_combo_status_style(self, status_key):
        palette = packet_profile_status_palette(status_key)
        self.profile_combo.setStyleSheet(
            "QComboBox {"
            f"background-color:{palette['combo_background']}; color:{palette['combo_text']}; "
            f"border:1px solid {palette['combo_border']}; border-radius:8px; padding:5px 10px; min-height:28px;"
            "}"
            "QComboBox::drop-down { border:0px; width:28px; }"
            "QComboBox QAbstractItemView {"
            "background:#0F1823; color:#E8F1FC; border:1px solid #243446; selection-background-color:#223246;"
            "}"
        )

    def _update_profile_statuses(self, base_payload):
        model = self.profile_combo.model()
        status_map = {}
        for index, profile_name in enumerate(PACKET_BUILDER_PROFILES):
            profile_payload = build_profile_export_payload(base_payload, profile_name)
            profile_report = build_packet_lab_report(profile_payload)
            status_key, status_label = classify_packet_lab_completion(profile_report)
            status_map[profile_name] = status_key
            palette = packet_profile_status_palette(status_key)
            model.setData(model.index(index, 0), palette["item_background"], Qt.BackgroundRole)
            model.setData(model.index(index, 0), palette["item_foreground"], Qt.ForegroundRole)
            model.setData(
                model.index(index, 0),
                f"{status_label} | Shared: {profile_report['shared_complete']}/{len(profile_report['shared_checks'])} | "
                f"Form: {profile_report['current_complete']}/{len(profile_report['current_form_checks'])} | "
                f"Inconsistencies: {len(profile_report.get('inconsistency_messages') or [])}",
                Qt.ToolTipRole,
            )
        self._profile_status_map = status_map
        current_status = status_map.get(self.profile_combo.currentText().strip(), "not_started")
        self._apply_profile_combo_status_style(current_status)

    def _sync_line_edit_from_shared(self, state_key, target_widget, value, fallback_values=None):
        normalized = str(value or "").strip()
        previous = str(self._shared_sync_state.get(state_key) or "").strip()
        current = target_widget.text().strip()
        if not normalized:
            if previous and current == previous:
                with QSignalBlocker(target_widget):
                    target_widget.clear()
            self._shared_sync_state[state_key] = ""
            return
        if _can_replace_with_shared_value(current, [previous, *(fallback_values or [])]):
            if current != normalized:
                with QSignalBlocker(target_widget):
                    target_widget.setText(normalized)
            self._shared_sync_state[state_key] = normalized
            return
        self._shared_sync_state[state_key] = previous

    def _sync_text_edit_from_shared(self, state_key, target_widget, value, fallback_values=None):
        normalized = str(value or "").strip()
        previous = str(self._shared_sync_state.get(state_key) or "").strip()
        current = target_widget.toPlainText().strip()
        if not normalized:
            if previous and current == previous:
                with QSignalBlocker(target_widget):
                    target_widget.clear()
            self._shared_sync_state[state_key] = ""
            return
        if _can_replace_with_shared_value(current, [previous, *(fallback_values or [])]):
            if current != normalized:
                with QSignalBlocker(target_widget):
                    target_widget.setPlainText(normalized)
            self._shared_sync_state[state_key] = normalized
            return
        self._shared_sync_state[state_key] = previous

    def _propagate_shared_fields(self):
        defaults = default_packet_builder_payload()
        auth_number = self.auth_input.text().strip()
        ordering_doctor = self.ordering_doctor_input.text().strip()
        provider_name = self.provider_input.text().strip()
        facility = self.facility_input.text().strip()
        diagnosis = self.diagnosis_input.text().strip()
        secondary_diagnosis = self.secondary_diagnosis_input.text().strip()
        icd_codes = self.icd_codes_input.text().strip()
        first_icd_code = _first_icd_code(icd_codes)
        ssn = self.ssn_input.text().strip()
        last_four = re.sub(r"\D", "", ssn)[-4:] if ssn else ""
        provider_credentials = self.master_provider_credentials_input.text().strip()
        provider_specialty = self.master_provider_specialty_input.text().strip()
        provider_npi = self.master_provider_npi_input.text().strip()
        practice_name = self.master_practice_name_input.text().strip()
        provider_phone = self.master_provider_phone_input.text().strip()
        provider_fax = self.master_provider_fax_input.text().strip()
        provider_email = self.master_provider_email_input.text().strip()
        provider_address = self.master_provider_address_input.toPlainText().strip()
        provider_address_one_line = ", ".join(part.strip() for part in provider_address.splitlines() if part.strip())
        requested_cpt = self.master_requested_cpt_code_input.text().strip()
        requested_service = self.requested_service_input.text().strip()
        mri_date = self.master_mri_date_input.text().strip()
        mri_findings = self.master_mri_findings_input.text().strip()
        affected_levels = self.master_affected_levels_input.text().strip()

        self._sync_line_edit_from_shared("auth:lmn", self.lomn_va_claim_number_input, auth_number, [defaults.get("lmn_va_claim_number")])
        self._sync_line_edit_from_shared("auth:consult", self.consult_va_claim_number_input, auth_number, [defaults.get("consult_va_claim_number")])
        self._sync_line_edit_from_shared("icd:cover", self.primary_diagnosis_code_input, first_icd_code, [defaults.get("primary_diagnosis_code")])
        self._sync_line_edit_from_shared("icd:seoc", self.episode_icd_code_input, first_icd_code, [defaults.get("episode_icd_code")])
        self._sync_line_edit_from_shared("facility:seoc", self.va_medical_center_input, facility, [defaults.get("va_medical_center_name")])
        self._sync_line_edit_from_shared("doctor:consult", self.consult_referring_va_provider_input, ordering_doctor, [defaults.get("consult_referring_va_provider")])
        self._sync_line_edit_from_shared(
            "provider:va10172",
            self.va10172_provider_name_printed_input,
            provider_name or ordering_doctor,
            [defaults.get("va10172_ordering_provider_name_printed")],
        )
        self._sync_line_edit_from_shared("diagnosis:seoc", self.episode_diagnosis_input, diagnosis, [defaults.get("episode_diagnosis")])
        self._sync_line_edit_from_shared("diagnosis:lomn", self.lomn_primary_diagnosis_input, diagnosis, [defaults.get("lmn_primary_diagnosis")])
        self._sync_line_edit_from_shared("diagnosis:consult", self.consult_primary_diagnosis_input, diagnosis, [defaults.get("consult_primary_diagnosis")])
        self._sync_line_edit_from_shared("diagnosis:clinical", self.clinical_doc_primary_diagnosis_input, diagnosis, [defaults.get("clinical_doc_primary_diagnosis")])
        self._sync_line_edit_from_shared("diagnosis:secondary_lomn", self.lomn_secondary_diagnosis_input, secondary_diagnosis, [defaults.get("lmn_secondary_diagnosis")])
        self._sync_line_edit_from_shared("diagnosis:secondary_consult", self.consult_secondary_diagnosis_input, secondary_diagnosis, [defaults.get("consult_secondary_diagnosis")])
        self._sync_line_edit_from_shared("diagnosis:secondary_clinical", self.clinical_doc_secondary_diagnosis_input, secondary_diagnosis, [defaults.get("clinical_doc_secondary_diagnosis")])
        self._sync_text_edit_from_shared("diagnosis:va10172", self.va10172_diagnosis_description_input, diagnosis, [defaults.get("va10172_diagnosis_description")])
        self._sync_line_edit_from_shared("ssn:last4", self.last_four_ssn_input, last_four)
        self._sync_line_edit_from_shared("provider:credentials", self.provider_credentials_input, provider_credentials, [defaults.get("provider_credentials")])
        self._sync_line_edit_from_shared("provider:specialty", self.provider_specialty_input, provider_specialty, [defaults.get("provider_specialty")])
        self._sync_line_edit_from_shared("provider:npi", self.provider_npi_input, provider_npi, [defaults.get("provider_npi")])
        self._sync_line_edit_from_shared("provider:npi_va10172", self.va10172_provider_npi_input, provider_npi, [defaults.get("va10172_ordering_provider_npi")])
        self._sync_line_edit_from_shared("provider:practice", self.practice_name_input, practice_name, [defaults.get("practice_name")])
        self._sync_line_edit_from_shared("provider:phone", self.provider_phone_input, provider_phone, [defaults.get("provider_phone")])
        self._sync_line_edit_from_shared("provider:phone_va10172", self.va10172_provider_phone_input, provider_phone, [defaults.get("va10172_ordering_provider_phone")])
        self._sync_line_edit_from_shared("provider:fax", self.provider_fax_input, provider_fax, [defaults.get("provider_fax")])
        self._sync_line_edit_from_shared("provider:fax_va10172", self.va10172_provider_fax_input, provider_fax, [defaults.get("va10172_ordering_provider_fax")])
        self._sync_line_edit_from_shared("provider:email", self.provider_email_input, provider_email, [defaults.get("provider_email")])
        self._sync_line_edit_from_shared("provider:email_va10172", self.va10172_provider_email_input, provider_email, [defaults.get("va10172_ordering_provider_secure_email")])
        self._sync_text_edit_from_shared("provider:address", self.va10172_provider_office_address_input, provider_address, [defaults.get("va10172_ordering_provider_office_address")])
        self._sync_line_edit_from_shared("provider:address_consult", self.provider_address_input, provider_address_one_line)
        self._sync_line_edit_from_shared("request:cpt", self.va10172_requested_cpt_input, requested_cpt, [defaults.get("va10172_requested_cpt_hcpcs_code")])
        self._sync_line_edit_from_shared("request:description", self.va10172_requested_cpt_description_input, requested_service, [defaults.get("va10172_description_cpt_hcpcs_code")])
        self._sync_line_edit_from_shared("mri:date_lomn", self.lomn_mri_date_input, mri_date, [defaults.get("lmn_mri_date")])
        self._sync_line_edit_from_shared("mri:date_consult", self.consult_mri_date_input, mri_date, [defaults.get("consult_mri_date")])
        self._sync_line_edit_from_shared("mri:date_clinical", self.clinical_doc_mri_date_input, mri_date, [defaults.get("clinical_doc_mri_date")])
        self._sync_line_edit_from_shared("mri:findings_lomn", self.lomn_mri_findings_input, mri_findings, [defaults.get("lmn_mri_findings")])
        self._sync_line_edit_from_shared("mri:findings_consult", self.consult_mri_findings_input, mri_findings, [defaults.get("consult_mri_findings")])
        self._sync_line_edit_from_shared("levels:clinical", self.clinical_doc_affected_levels_input, affected_levels, [defaults.get("clinical_doc_affected_levels")])

    def collect_payload(self):
        return normalize_packet_builder_payload({
            "packet_title": self.packet_title_input.text().strip(),
            "packet_profile": self.profile_combo.currentText().strip(),
            "patient_name": self.patient_name_input.text().strip(),
            "date_of_birth": self.dob_input.text().strip(),
            "authorization_number": self.auth_input.text().strip(),
            "va_icn": self.icn_input.text().strip(),
            "ordering_doctor": self.ordering_doctor_input.text().strip(),
            "provider": self.provider_input.text().strip(),
            "facility": self.facility_input.text().strip(),
            "community_facility": self.community_facility_input.text().strip(),
            "requested_service": self.requested_service_input.text().strip(),
            "diagnosis": self.diagnosis_input.text().strip(),
            "secondary_diagnosis": self.secondary_diagnosis_input.text().strip(),
            "icd_codes": self.icd_codes_input.text().strip(),
            "master_requested_cpt_code": self.master_requested_cpt_code_input.text().strip(),
            "master_provider_credentials": self.master_provider_credentials_input.text().strip(),
            "master_provider_specialty": self.master_provider_specialty_input.text().strip(),
            "master_provider_npi": self.master_provider_npi_input.text().strip(),
            "master_practice_name": self.master_practice_name_input.text().strip(),
            "master_provider_phone": self.master_provider_phone_input.text().strip(),
            "master_provider_fax": self.master_provider_fax_input.text().strip(),
            "master_provider_email": self.master_provider_email_input.text().strip(),
            "master_provider_address": self.master_provider_address_input.toPlainText().strip(),
            "master_mri_date": self.master_mri_date_input.text().strip(),
            "master_mri_findings": self.master_mri_findings_input.text().strip(),
            "master_affected_levels": self.master_affected_levels_input.text().strip(),
            "clinical_summary": self.clinical_summary_input.toPlainText().strip(),
            "packet_notes": self.packet_notes_input.toPlainText().strip(),
            "scenario_pathology_pattern": self.scenario_pathology_pattern_input.text().strip(),
            "scenario_conservative_duration": self.scenario_conservative_duration_input.text().strip(),
            "scenario_prior_esi_response": self.scenario_prior_esi_response_input.text().strip(),
            "scenario_functional_emphasis": self.scenario_functional_emphasis_input.text().strip(),
            "scenario_request_framing": self.scenario_request_framing_input.text().strip(),
            "scenario_symptom_pattern": self.scenario_symptom_pattern_input.text().strip(),
            "scenario_conservative_modalities": self.scenario_conservative_modalities_input.text().strip(),
            "scenario_review_concern": self.scenario_review_concern_input.text().strip(),
            "scenario_treatment_goals": self.scenario_treatment_goals_input.text().strip(),
            "referral_subtitle": self.referral_subtitle_input.text().strip(),
            "pcp_request_text": self.pcp_request_input.text().strip(),
            "referral_entry_text": self.referral_entry_input.text().strip(),
            "areas_of_concern": self.areas_of_concern_input.text().strip(),
            "group_npi": self.group_npi_input.text().strip(),
            "fax_number": self.fax_number_input.text().strip(),
            "liaison_contact_info": self.liaison_contact_input.toPlainText().strip(),
            "consent_form_title": self.consent_form_title_input.text().strip(),
            "street_address": self.street_address_input.text().strip(),
            "city": self.city_input.text().strip(),
            "state": self.state_input.text().strip(),
            "zip_code": self.zip_code_input.text().strip(),
            "home_phone": self.home_phone_input.text().strip(),
            "mobile_phone": self.mobile_phone_input.text().strip(),
            "work_phone": self.work_phone_input.text().strip(),
            "email_address": self.email_address_input.text().strip(),
            "ssn": self.ssn_input.text().strip(),
            "drivers_license": self.drivers_license_input.text().strip(),
            "drivers_license_state": self.drivers_license_state_input.text().strip(),
            "appointment_confirmation_method": self.appointment_confirmation_combo.currentText().strip(),
            "filed_for_disability": self.filed_for_disability_combo.currentText().strip(),
            "condition_work_related": self.condition_work_related_combo.currentText().strip(),
            "condition_due_to_accident": self.condition_due_to_accident_combo.currentText().strip(),
            "yes_response_explanation": self.yes_response_explanation_input.toPlainText().strip(),
            "has_attorney": self.has_attorney_combo.currentText().strip(),
            "attorney_name": self.attorney_name_input.text().strip(),
            "attorney_phone": self.attorney_phone_input.text().strip(),
            "emergency_contact_name": self.emergency_contact_name_input.text().strip(),
            "emergency_contact_relationship": self.emergency_contact_relationship_input.text().strip(),
            "emergency_contact_phone": self.emergency_contact_phone_input.text().strip(),
            "primary_insurance_carrier": self.primary_insurance_carrier_input.text().strip(),
            "primary_insurance_id": self.primary_insurance_id_input.text().strip(),
            "primary_insurance_phone": self.primary_insurance_phone_input.text().strip(),
            "secondary_insurance_carrier": self.secondary_insurance_carrier_input.text().strip(),
            "secondary_insurance_id": self.secondary_insurance_id_input.text().strip(),
            "secondary_insurance_phone": self.secondary_insurance_phone_input.text().strip(),
            "pcp_pcm_name": self.pcp_pcm_name_input.text().strip(),
            "pcp_pcm_phone": self.pcp_pcm_phone_input.text().strip(),
            "pcp_pcm_fax": self.pcp_pcm_fax_input.text().strip(),
            "consent_provider_name": self.consent_provider_name_input.text().strip(),
            "consent_initials": self.consent_initials_input.text().strip(),
            "minor_doctor_name": self.minor_doctor_name_input.text().strip(),
            "minor_consent_initials": self.minor_consent_initials_input.text().strip(),
            "service_authorization_name": self.service_authorization_name_input.text().strip(),
            "patient_signature_name": self.patient_signature_name_input.text().strip(),
            "patient_signature_image": str(self._signature_images.get("patient_signature_image") or "").strip(),
            "patient_signature_date": self.patient_signature_date_input.text().strip(),
            "submission_cover_title": self.submission_cover_title_input.text().strip(),
            "submission_date": self.submission_date_input.text().strip(),
            "primary_diagnosis_code": self.primary_diagnosis_code_input.text().strip(),
            "included_virtual_consent_form": self.included_virtual_consent_checkbox.isChecked(),
            "included_va_form_10_10172": self.included_va_form_checkbox.isChecked(),
            "included_seoc_request": self.included_seoc_checkbox.isChecked(),
            "included_consult_request": self.included_consult_checkbox.isChecked(),
            "included_lomn": self.included_lomn_checkbox.isChecked(),
            "included_clinical_notes": self.included_clinical_notes_checkbox.isChecked(),
            "included_mri_report": self.included_mri_checkbox.isChecked(),
            "submitting_office": self.submitting_office_input.text().strip(),
            "office_staff_name": self.office_staff_name_input.text().strip(),
            "office_staff_signature": self.office_staff_signature_input.text().strip(),
            "office_staff_signature_image": str(self._signature_images.get("office_staff_signature_image") or "").strip(),
            "date_reviewed": self.date_reviewed_input.text().strip(),
            "seoc_request_date": self.seoc_request_date_input.text().strip(),
            "va_medical_center_name": self.va_medical_center_input.text().strip(),
            "last_four_ssn": self.last_four_ssn_input.text().strip(),
            "episode_diagnosis": self.episode_diagnosis_input.text().strip(),
            "episode_icd_code": self.episode_icd_code_input.text().strip(),
            "seoc_scope_text": self.seoc_scope_text_input.toPlainText().strip(),
            "estimated_duration_text": self.estimated_duration_input.text().strip(),
            "clinical_objectives": self.clinical_objectives_input.toPlainText().strip(),
            "seoc_continuity_text": self.seoc_continuity_text_input.toPlainText().strip(),
            "provider_credentials": self.provider_credentials_input.text().strip(),
            "provider_specialty": self.provider_specialty_input.text().strip(),
            "provider_npi": self.provider_npi_input.text().strip(),
            "practice_name": self.practice_name_input.text().strip(),
            "provider_phone": self.provider_phone_input.text().strip(),
            "provider_fax": self.provider_fax_input.text().strip(),
            "seoc_include_preprocedure_eval": self.seoc_preprocedure_checkbox.isChecked(),
            "seoc_include_annulargram": self.seoc_annulargram_checkbox.isChecked(),
            "seoc_include_fibrin_injection": self.seoc_fibrin_checkbox.isChecked(),
            "seoc_include_follow_up": self.seoc_follow_up_checkbox.isChecked(),
            "lmn_request_date": self.lomn_request_date_input.text().strip(),
            "lmn_va_claim_number": self.lomn_va_claim_number_input.text().strip(),
            "lmn_primary_diagnosis": self.lomn_primary_diagnosis_input.text().strip(),
            "lmn_secondary_diagnosis": self.lomn_secondary_diagnosis_input.text().strip(),
            "lmn_clinical_summary": self.lomn_clinical_summary_input.toPlainText().strip(),
            "lmn_mri_date": self.lomn_mri_date_input.text().strip(),
            "lmn_mri_findings": self.lomn_mri_findings_input.text().strip(),
            "lmn_conservative_duration": self.lomn_conservative_duration_input.text().strip(),
            "lmn_include_physical_therapy": self.lomn_physical_therapy_checkbox.isChecked(),
            "lmn_include_nsaids": self.lomn_nsaids_checkbox.isChecked(),
            "lmn_include_activity_modification": self.lomn_activity_modification_checkbox.isChecked(),
            "lmn_include_home_exercise": self.lomn_home_exercise_checkbox.isChecked(),
            "lmn_include_epidural_steroid_injections": self.lomn_esi_checkbox.isChecked(),
            "lmn_medical_necessity_statement": self.lomn_medical_necessity_input.toPlainText().strip(),
            "lmn_indication_reduce_pain": self.lomn_reduce_pain_checkbox.isChecked(),
            "lmn_indication_improve_function": self.lomn_improve_function_checkbox.isChecked(),
            "lmn_indication_prevent_degeneration": self.lomn_prevent_degeneration_checkbox.isChecked(),
            "lmn_indication_reduce_opioid_reliance": self.lomn_reduce_opioids_checkbox.isChecked(),
            "lmn_indication_prevent_surgery": self.lomn_prevent_surgery_checkbox.isChecked(),
            "lmn_risk_statement": self.lomn_risk_statement_input.toPlainText().strip(),
            "lmn_reasonable_necessary_statement": self.lomn_reasonable_statement_input.toPlainText().strip(),
            "lmn_contact_statement": self.lomn_contact_statement_input.toPlainText().strip(),
            "consult_request_date": self.consult_request_date_input.text().strip(),
            "consult_va_claim_number": self.consult_va_claim_number_input.text().strip(),
            "consult_referring_va_provider": self.consult_referring_va_provider_input.text().strip(),
            "consult_reason_text": self.consult_reason_input.toPlainText().strip(),
            "consult_primary_diagnosis": self.consult_primary_diagnosis_input.text().strip(),
            "consult_secondary_diagnosis": self.consult_secondary_diagnosis_input.text().strip(),
            "consult_symptom_axial_pain": self.consult_symptom_axial_pain_checkbox.isChecked(),
            "consult_symptom_activity_exacerbation": self.consult_symptom_activity_checkbox.isChecked(),
            "consult_symptom_reduced_tolerance": self.consult_symptom_tolerance_checkbox.isChecked(),
            "consult_symptom_functional_impairment": self.consult_symptom_function_checkbox.isChecked(),
            "consult_mri_date": self.consult_mri_date_input.text().strip(),
            "consult_mri_findings": self.consult_mri_findings_input.text().strip(),
            "consult_conservative_duration": self.consult_conservative_duration_input.text().strip(),
            "consult_include_physical_therapy": self.consult_physical_therapy_checkbox.isChecked(),
            "consult_include_nsaids": self.consult_nsaids_checkbox.isChecked(),
            "consult_include_activity_modification": self.consult_activity_mod_checkbox.isChecked(),
            "consult_include_home_exercise": self.consult_home_exercise_checkbox.isChecked(),
            "consult_include_interventional_history": self.consult_interventional_history_checkbox.isChecked(),
            "consult_include_pain_management_consultation": self.consult_include_pm_consult_checkbox.isChecked(),
            "consult_include_procedural_planning": self.consult_include_planning_checkbox.isChecked(),
            "consult_include_annulargram": self.consult_include_annulargram_checkbox.isChecked(),
            "consult_include_fibrin_injection": self.consult_include_fibrin_checkbox.isChecked(),
            "consult_include_follow_up": self.consult_include_follow_up_checkbox.isChecked(),
            "consult_fibrin_levels": self.consult_fibrin_levels_input.text().strip(),
            "consult_scope_exclusion_text": self.consult_scope_exclusion_input.toPlainText().strip(),
            "consult_medical_rationale_text": self.consult_medical_rationale_input.toPlainText().strip(),
            "consult_goal_pain_reduction": self.consult_goal_pain_checkbox.isChecked(),
            "consult_goal_functional_improvement": self.consult_goal_function_checkbox.isChecked(),
            "consult_goal_reduce_analgesics": self.consult_goal_analgesics_checkbox.isChecked(),
            "consult_goal_prevent_surgery": self.consult_goal_surgery_checkbox.isChecked(),
            "consult_risk_without_treatment": self.consult_risk_without_treatment_input.toPlainText().strip(),
            "consult_duration_scope_text": self.consult_duration_scope_input.toPlainText().strip(),
            "consult_contact_statement": self.consult_contact_statement_input.toPlainText().strip(),
            "provider_address": self.provider_address_input.text().strip(),
            "provider_email": self.provider_email_input.text().strip(),
            "clinical_doc_title": self.clinical_doc_title_input.text().strip(),
            "clinical_doc_chief_complaint": self.clinical_doc_chief_complaint_input.text().strip(),
            "clinical_doc_duration_gt_3m": self.clinical_doc_duration_3m_checkbox.isChecked(),
            "clinical_doc_duration_gt_6m": self.clinical_doc_duration_6m_checkbox.isChecked(),
            "clinical_doc_duration_gt_12m": self.clinical_doc_duration_12m_checkbox.isChecked(),
            "clinical_doc_exact_duration": self.clinical_doc_exact_duration_input.text().strip(),
            "clinical_doc_pain_axial": self.clinical_doc_pain_axial_checkbox.isChecked(),
            "clinical_doc_pain_discogenic": self.clinical_doc_pain_discogenic_checkbox.isChecked(),
            "clinical_doc_pain_activity_exacerbation": self.clinical_doc_pain_activity_checkbox.isChecked(),
            "clinical_doc_pain_sitting_intolerance": self.clinical_doc_pain_sitting_checkbox.isChecked(),
            "clinical_doc_pain_standing_intolerance": self.clinical_doc_pain_standing_checkbox.isChecked(),
            "clinical_doc_pain_bending_lifting": self.clinical_doc_pain_bending_checkbox.isChecked(),
            "clinical_doc_pain_severity": self.clinical_doc_pain_severity_input.text().strip(),
            "clinical_doc_limit_occupational": self.clinical_doc_limit_occupational_checkbox.isChecked(),
            "clinical_doc_limit_prolonged_sitting": self.clinical_doc_limit_sitting_checkbox.isChecked(),
            "clinical_doc_limit_prolonged_standing": self.clinical_doc_limit_standing_checkbox.isChecked(),
            "clinical_doc_limit_ambulation": self.clinical_doc_limit_ambulation_checkbox.isChecked(),
            "clinical_doc_limit_household": self.clinical_doc_limit_household_checkbox.isChecked(),
            "clinical_doc_limit_sleep": self.clinical_doc_limit_sleep_checkbox.isChecked(),
            "clinical_doc_functional_impact": self.clinical_doc_functional_impact_input.toPlainText().strip(),
            "clinical_doc_conservative_pt": self.clinical_doc_conservative_pt_checkbox.isChecked(),
            "clinical_doc_conservative_home_exercise": self.clinical_doc_conservative_home_exercise_checkbox.isChecked(),
            "clinical_doc_conservative_nsaids": self.clinical_doc_conservative_nsaids_checkbox.isChecked(),
            "clinical_doc_conservative_non_opioid": self.clinical_doc_conservative_non_opioid_checkbox.isChecked(),
            "clinical_doc_conservative_activity_modification": self.clinical_doc_conservative_activity_checkbox.isChecked(),
            "clinical_doc_conservative_esi": self.clinical_doc_conservative_esi_checkbox.isChecked(),
            "clinical_doc_conservative_other_interventional": self.clinical_doc_conservative_other_checkbox.isChecked(),
            "clinical_doc_conservative_duration": self.clinical_doc_conservative_duration_input.text().strip(),
            "clinical_doc_esi_response": self.clinical_doc_esi_response_combo.currentText().strip(),
            "clinical_doc_mri_date": self.clinical_doc_mri_date_input.text().strip(),
            "clinical_doc_imaging_annular_tear": self.clinical_doc_imaging_annular_checkbox.isChecked(),
            "clinical_doc_imaging_disc_degeneration": self.clinical_doc_imaging_degeneration_checkbox.isChecked(),
            "clinical_doc_imaging_disc_protrusion": self.clinical_doc_imaging_protrusion_checkbox.isChecked(),
            "clinical_doc_imaging_disc_displacement": self.clinical_doc_imaging_displacement_checkbox.isChecked(),
            "clinical_doc_affected_levels": self.clinical_doc_affected_levels_input.text().strip(),
            "clinical_doc_primary_diagnosis": self.clinical_doc_primary_diagnosis_input.text().strip(),
            "clinical_doc_secondary_diagnosis": self.clinical_doc_secondary_diagnosis_input.text().strip(),
            "clinical_doc_assessment_summary": self.clinical_doc_assessment_summary_input.toPlainText().strip(),
            "clinical_doc_treatment_plan_intro": self.clinical_doc_treatment_plan_intro_input.toPlainText().strip(),
            "clinical_doc_plan_diagnostic_confirmation": self.clinical_doc_plan_diagnostic_checkbox.isChecked(),
            "clinical_doc_plan_intradiscal_intervention": self.clinical_doc_plan_intervention_checkbox.isChecked(),
            "clinical_doc_plan_follow_up": self.clinical_doc_plan_follow_up_checkbox.isChecked(),
            "clinical_doc_plan_exclusion": self.clinical_doc_plan_exclusion_input.toPlainText().strip(),
            "clinical_doc_physician_narrative": self.clinical_doc_physician_narrative_input.toPlainText().strip(),
            "va10172_template_path": self.config.get("va_form_10172_template_path") or "",
            "va10172_va_facility_address": self.va10172_facility_address_input.toPlainText().strip(),
            "va10172_ordering_provider_office_address": self.va10172_provider_office_address_input.toPlainText().strip(),
            "va10172_is_ihs_provider": self.va10172_is_ihs_combo.currentText().strip(),
            "va10172_ordering_provider_phone": self.va10172_provider_phone_input.text().strip(),
            "va10172_ordering_provider_fax": self.va10172_provider_fax_input.text().strip(),
            "va10172_ordering_provider_secure_email": self.va10172_provider_email_input.text().strip(),
            "va10172_care_needed_within_48_hours": self.va10172_48h_combo.currentText().strip(),
            "va10172_is_continuation_of_care": self.va10172_continuation_combo.currentText().strip(),
            "va10172_referral_to_specialty": self.va10172_referral_specialty_combo.currentText().strip(),
            "va10172_referral_specialty_text": self.va10172_referral_specialty_text_input.text().strip(),
            "va10172_diagnosis_description": self.va10172_diagnosis_description_input.toPlainText().strip(),
            "va10172_requested_cpt_hcpcs_code": self.va10172_requested_cpt_input.text().strip(),
            "va10172_description_cpt_hcpcs_code": self.va10172_requested_cpt_description_input.text().strip(),
            "va10172_geriatric_care_option": self.va10172_geriatric_option_combo.currentText().strip(),
            "va10172_reason_for_request": self.va10172_reason_for_request_input.toPlainText().strip(),
            "va10172_ordering_provider_name_printed": self.va10172_provider_name_printed_input.text().strip(),
            "va10172_ordering_provider_npi": self.va10172_provider_npi_input.text().strip(),
            "va10172_signature_text": self.va10172_signature_text_input.text().strip(),
            "va10172_signature_image": str(self._signature_images.get("va10172_signature_image") or "").strip(),
            "va10172_today_date": self.va10172_today_date_input.text().strip(),
            "wording_assist_state": dict(self._wording_assist_state or {}),
        })

    def _set_preview_status(self, text):
        if hasattr(self, "preview_status_label"):
            self.preview_status_label.setText(str(text or "").strip())

    def _preview_render_key_for_payload(self, payload):
        packet = apply_packet_builder_shared_field_sync(default_packet_builder_payload() | dict(payload or {}))
        serialized = json.dumps(packet, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha1(serialized.encode("utf-8")).hexdigest()

    def _set_exact_preview_button_state(self, busy=False):
        if not hasattr(self, "exact_preview_button"):
            return
        preview_available = bool(self.word_executable_path) or is_va_10172_profile((self.packet_payload or {}).get("packet_profile"))
        if busy:
            self.exact_preview_button.setEnabled(False)
            self.exact_preview_button.setText("Rendering Exact Preview...")
            return
        self.exact_preview_button.setEnabled(preview_available)
        self.exact_preview_button.setText("Refresh Exact Preview" if preview_available else "Exact Preview Unavailable")

    def _show_export_html_preview(self, payload, status_text=""):
        self.preview_view.setHtml(build_packet_builder_preview_html(payload))
        if hasattr(self, "preview_stack"):
            self.preview_stack.setCurrentWidget(self.preview_view)
        self._set_preview_status(status_text)

    def _load_exact_preview_pdf(self, render_key, pdf_path):
        normalized = str(pdf_path or "").strip()
        if not normalized or not os.path.exists(normalized):
            return False
        try:
            self.preview_pdf_document.close()
        except Exception:
            pass
        self.preview_pdf_document.load(normalized)
        if hasattr(self, "preview_stack"):
            self.preview_stack.setCurrentWidget(self.preview_pdf_view)
        self._preview_loaded_key = render_key
        self._set_preview_status("Exact preview matches the current exported document layout and pagination.")
        return True

    def refresh_exact_preview(self):
        payload = dict(self.packet_payload or {})
        if not payload:
            payload = self.collect_payload()
        if not self.word_executable_path and not is_va_10172_profile(payload.get("packet_profile")):
            self._show_export_html_preview(
                payload,
                "Fast preview shown. Exact Word-faithful preview is unavailable because Microsoft Word was not detected.",
            )
            self._set_exact_preview_button_state(False)
            return
        if self._preview_render_thread:
            self._set_preview_status("Exact preview is already rendering. Please let it finish.")
            return
        render_key = self._preview_render_key_for_payload(payload)
        self._preview_latest_requested_key = render_key
        os.makedirs(self._preview_cache_dir, exist_ok=True)
        cached_pdf = os.path.join(self._preview_cache_dir, f"{render_key}.pdf")
        if render_key == self._preview_loaded_key and os.path.exists(cached_pdf):
            self._set_preview_status("Exact preview matches the current exported document layout and pagination.")
            self._set_exact_preview_button_state(False)
            return
        if os.path.exists(cached_pdf):
            self._load_exact_preview_pdf(render_key, cached_pdf)
            self._set_exact_preview_button_state(False)
            return
        self._set_exact_preview_button_state(True)
        self._set_preview_status("Rendering exact preview from the exported document. You can keep editing while this finishes.")
        self._start_exact_preview_worker(render_key, payload)

    def _start_exact_preview_worker(self, render_key, payload):
        thread = QThread(self)
        worker = ExactPreviewRenderWorker(
            render_key=render_key,
            payload=payload,
            output_dir=self._preview_cache_dir,
            is_va_10172_fn=is_va_10172_profile,
            write_pdf_fn=self._write_pdf_doc_for_payload,
            write_word_fn=self._write_word_doc_for_payload,
            convert_docx_to_pdf_fn=convert_docx_to_pdf_via_word,
        )
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_exact_preview_render_finished)
        worker.failed.connect(self._on_exact_preview_render_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(lambda: self._on_exact_preview_thread_finished(thread))
        self._preview_render_thread = thread
        self._preview_render_worker = worker
        thread.start()

    def _on_exact_preview_render_finished(self, render_key, pdf_path):
        self._set_exact_preview_button_state(False)
        if render_key == self._preview_current_key:
            if not self._load_exact_preview_pdf(render_key, pdf_path):
                self._show_export_html_preview(
                    self.packet_payload,
                    "The exact preview finished rendering, but the PDF could not be loaded. Showing the fast export preview instead.",
                )

    def _on_exact_preview_render_failed(self, render_key, error_text):
        self._set_exact_preview_button_state(False)
        if render_key == self._preview_current_key:
            self._show_export_html_preview(
                self.packet_payload,
                "Exact preview render failed, so Packet Studio is showing the fast export preview. "
                f"Details: {error_text}",
            )

    def _on_exact_preview_thread_finished(self, thread):
        if self._preview_render_thread is thread:
            self._preview_render_thread = None
            self._preview_render_worker = None
        self._set_exact_preview_button_state(False)

    def refresh_preview(self):
        if not self._builder_ready:
            return
        self._preview_refresh_timer.start()

    def _refresh_preview_now(self):
        if not self._builder_ready:
            return
        self._propagate_shared_fields()
        self.packet_payload = self.collect_payload()
        self._preview_current_key = self._preview_render_key_for_payload(self.packet_payload)
        self._update_profile_statuses(self.packet_payload)
        self._refresh_wording_assist()
        if self._preview_render_thread:
            status_text = "Fast preview shown while exact preview finishes in the background."
        elif self.word_executable_path or is_va_10172_profile(self.packet_payload.get("packet_profile")):
            status_text = "Fast preview shown. Use Refresh Exact Preview for the Word-faithful view."
        else:
            status_text = "Fast preview shown. Exact preview is unavailable because Microsoft Word was not detected."
        self._show_export_html_preview(
            self.packet_payload,
            status_text,
        )
        self.lab_view.setHtml(build_packet_lab_html(self.packet_payload))
        self._update_current_packet_status()
        self._set_exact_preview_button_state(False)

    def on_profile_changed(self, profile_name):
        is_referral = is_referral_request_profile(profile_name)
        is_consent = is_virtual_consent_profile(profile_name)
        is_cover_sheet = is_submission_cover_profile(profile_name)
        is_seoc = is_seoc_request_profile(profile_name)
        is_lomn = is_lomn_profile(profile_name)
        is_consult = is_consult_request_profile(profile_name)
        is_clinical_doc = is_clinical_documentation_profile(profile_name)
        is_va_10172 = is_va_10172_profile(profile_name)
        self.referral_group.setVisible(is_referral)
        self.virtual_consent_group.setVisible(is_consent)
        self.submission_cover_group.setVisible(is_cover_sheet)
        self.seoc_request_group.setVisible(is_seoc)
        self.lomn_group.setVisible(is_lomn)
        self.consult_request_group.setVisible(is_consult)
        self.clinical_doc_group.setVisible(is_clinical_doc)
        self.va10172_group.setVisible(is_va_10172)
        self.export_context_label.setText(describe_packet_export_context(profile_name))
        current_title = self.packet_title_input.text().strip()
        known_defaults = {
            default_title_for_profile(name)
            for name in PACKET_BUILDER_PROFILES
            if default_title_for_profile(name)
        }
        default_title = default_title_for_profile(profile_name)
        if default_title and (not current_title or current_title in known_defaults):
            self.packet_title_input.setText(default_title)
        current_status = getattr(self, "_profile_status_map", {}).get(profile_name, "not_started")
        self._apply_profile_combo_status_style(current_status)
        self.refresh_preview()

    def choose_export_dir(self):
        current_dir = self.config.get("packet_builder_export_dir") or _default_export_dir()
        selected = QFileDialog.getExistingDirectory(self, "Choose Packet Builder Export Folder", current_dir)
        if not selected:
            return
        self.config = dict(self.save_config_callback({"packet_builder_export_dir": selected}) or {})
        self.export_dir_value.setText(selected)
        self.refresh_preview()

    def choose_va10172_template(self):
        current_path = self.config.get("va_form_10172_template_path") or _default_va_form_10172_template_path() or _default_export_dir()
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "Choose VA Form 10-10172 PDF Template",
            current_path,
            "PDF Files (*.pdf)",
        )
        if not selected:
            return
        self.config = dict(self.save_config_callback({"va_form_10172_template_path": selected}) or {})
        self.va10172_template_value.setText(selected)
        self.refresh_preview()

    def _resolve_export_dir(self):
        export_dir = str(self.config.get("packet_builder_export_dir") or "").strip()
        if export_dir and os.path.isdir(export_dir):
            return export_dir
        self.choose_export_dir()
        return str(self.config.get("packet_builder_export_dir") or "").strip()

    def _resolve_va10172_template_path(self):
        template_path = str(self.config.get("va_form_10172_template_path") or "").strip()
        if template_path and os.path.exists(template_path):
            return template_path
        template_path = _default_va_form_10172_template_path()
        if template_path and os.path.exists(template_path):
            self.config = dict(self.save_config_callback({"va_form_10172_template_path": template_path}) or {})
            if hasattr(self, "va10172_template_value"):
                self.va10172_template_value.setText(template_path)
            return template_path
        return ""

    def _resolve_base_filename(self):
        raw_text = self.base_filename_input.text()
        typed = sanitize_builder_filename(raw_text)
        if typed != raw_text:
            self.base_filename_input.setText(typed)
        return typed or "truecore_packet"

    def _ensure_export_targets(self, extensions):
        export_dir = self._resolve_export_dir()
        if not export_dir:
            QMessageBox.warning(
                self,
                "Export Folder Required",
                "Choose an export folder before saving packet drafts.",
            )
            return None

        base_name = self._resolve_base_filename()
        if not base_name:
            base_name = "truecore_packet"
        return {
            ext: os.path.join(export_dir, f"{base_name}.{ext}")
            for ext in extensions
        }

    def _ensure_bundle_export_dir(self, group_name):
        export_dir = self._resolve_export_dir()
        if not export_dir:
            QMessageBox.warning(
                self,
                "Export Folder Required",
                "Choose an export folder before exporting referral requests or patient packets.",
            )
            return None
        bundle_dir = os.path.join(export_dir, bundle_folder_name(self._resolve_base_filename(), group_name))
        os.makedirs(bundle_dir, exist_ok=True)
        return bundle_dir

    def _selected_bundle_format(self):
        return self.bundle_format_combo.currentText().strip() or "Both"

    def _section_rows(self):
        return build_packet_builder_sections(self.collect_payload())

    def save_draft_json(self):
        self._save_current_draft_record()
        self.preview_tabs.setCurrentIndex(3)

    def _set_export_busy_state(self, busy=False, status_text=""):
        for control in self._export_controls or []:
            if control is not None:
                control.setEnabled(not busy)
        if busy:
            self._set_preview_status(status_text or "Exporting packet files in the background.")
        elif status_text:
            self._set_preview_status(status_text)

    def _start_export_request(self, request):
        if self._export_thread:
            QMessageBox.information(
                self,
                "Export In Progress",
                "A packet export is already running. Let it finish before starting another one.",
            )
            return False

        action_label = str(request.get("action_label") or "packet").strip().lower()
        self._set_export_busy_state(True, f"Exporting {action_label} in the background. You can keep reviewing the packet while it runs.")
        thread = QThread(self)
        worker = PacketExportWorker(
            request=request,
            run_export_fn=self._run_export_request,
        )
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_export_worker_finished)
        worker.failed.connect(self._on_export_worker_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(lambda: self._on_export_thread_finished(thread))
        self._export_thread = thread
        self._export_worker = worker
        thread.start()
        return True

    def _on_export_worker_finished(self, result):
        result = dict(result or {})
        artifact_updates = dict(result.get("artifact_updates") or {})
        if artifact_updates:
            self._update_current_draft_artifacts(artifact_updates)
        title = str(result.get("title") or "Export Complete").strip()
        message = str(result.get("message") or "Packet export completed.").strip()
        self._set_export_busy_state(False, "Export complete. Packet Studio is ready for the next action.")
        QMessageBox.information(self, title, message)

    def _on_export_worker_failed(self, error_text):
        self._set_export_busy_state(False, "Packet export failed. Review the error details and try again.")
        QMessageBox.warning(self, "Export Failed", str(error_text or "Packet export failed."))

    def _on_export_thread_finished(self, thread):
        if self._export_thread is thread:
            self._export_thread = None
            self._export_worker = None
        self._set_export_busy_state(False)

    def _run_export_request(self, request):
        request = dict(request or {})
        mode = str(request.get("mode") or "").strip().lower()

        if mode == "single":
            output_map = dict(request.get("output_map") or {})
            for extension, target_path in output_map.items():
                normalized_extension = str(extension or "").strip().lower()
                if normalized_extension == "docx":
                    self._write_word_doc_for_payload(target_path, request.get("payload"))
                elif normalized_extension == "pdf":
                    self._write_pdf_doc_for_payload(target_path, request.get("payload"))
            artifact_updates = dict(request.get("artifact_updates") or {})
            return {
                "title": request.get("success_title") or "Export Complete",
                "message": request.get("success_message") or "Packet export completed.",
                "artifact_updates": artifact_updates,
            }

        if mode == "bundle":
            written_files = []
            bundle_dir = str(request.get("bundle_dir") or "").strip()
            for item in request.get("documents") or []:
                payload = dict(item.get("payload") or {})
                target_path = str(item.get("target_path") or "").strip()
                extension = str(item.get("extension") or "").strip().lower()
                if extension == "docx":
                    self._write_word_doc_for_payload(target_path, payload)
                elif extension == "pdf":
                    self._write_pdf_doc_for_payload(target_path, payload)
                else:
                    continue
                written_files.append(target_path)
            notice = [
                f"Bundle folder:\n{bundle_dir}",
                "",
                f"Exported {len(written_files)} file(s).",
            ]
            if request.get("group_name") == "patient_packet":
                notice.extend(
                    [
                        "",
                        "Note: VA Form 10-10172 always includes the real filled PDF in the patient packet export.",
                    ]
                )
            return {
                "title": request.get("success_title") or "Bundle Export Complete",
                "message": "\n".join(notice),
                "artifact_updates": dict(request.get("artifact_updates") or {}),
            }

        if mode == "compiled_pdf":
            temp_paths = []
            target_path = str(request.get("target_path") or "").strip()
            with tempfile.TemporaryDirectory() as temp_dir:
                for item in request.get("documents") or []:
                    payload = dict(item.get("payload") or {})
                    temp_path = os.path.join(
                        temp_dir,
                        f"{bundle_member_filename(payload.get('packet_profile'), 'patient_packet')}.pdf",
                    )
                    self._write_pdf_doc_for_payload(temp_path, payload)
                    temp_paths.append(temp_path)
                # Keep compiled packet generation lossless. The prior continuous-page-number
                # overlay path corrupted merged PDFs, so for now we preserve the original
                # rendered pages exactly and revisit packet-wide numbering separately.
                self._merge_pdf_files(temp_paths, target_path, add_continuous_page_numbers=False)
            return {
                "title": request.get("success_title") or "Patient Packet Export Complete",
                "message": request.get("success_message") or f"Compiled patient packet PDF saved to:\n{target_path}",
                "artifact_updates": dict(request.get("artifact_updates") or {}),
            }

        raise RuntimeError("Unknown export request.")

    def _confirm_export_warning_if_needed(self, payload, group_name=""):
        warning = build_export_warning_context(payload, group_name=group_name)
        if not warning:
            return True
        choice = QMessageBox.question(
            self,
            str(warning.get("title") or "Export Warning"),
            str(warning.get("message") or "This export looks incomplete. Continue?"),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        return choice == QMessageBox.Yes

    def _confirm_wording_review_if_needed(self, payload, group_name=""):
        blockers = build_wording_export_blockers(payload, group_name=group_name)
        if not blockers:
            return True
        self.preview_tabs.setCurrentIndex(1)
        blocker_lines = "\n".join(f"- {item}" for item in blockers[:12])
        if len(blockers) > 12:
            blocker_lines += f"\n- ...and {len(blockers) - 12} more"
        QMessageBox.information(
            self,
            "Wording Review Required",
            "Before final export, Packet Studio needs wording approval on the denial-sensitive fields below.\n\n"
            + blocker_lines
            + "\n\nOpen the Wording Assist tab, review the original wording, and either accept the suggestion, edit it, or intentionally keep the original once the supporting facts are complete.",
        )
        return False

    def export_word(self):
        targets = self._ensure_export_targets(["docx"])
        if not targets:
            return
        payload = self.collect_payload()
        if not self._confirm_export_warning_if_needed(payload):
            return
        if not self._confirm_wording_review_if_needed(payload):
            return
        self._start_export_request(
            {
                "mode": "single",
                "action_label": "word export",
                "payload": payload,
                "output_map": {"docx": targets["docx"]},
                "artifact_updates": {"single_doc_docx": targets["docx"]},
                "success_title": "Word Export Complete",
                "success_message": f"Word packet draft saved to:\n{targets['docx']}",
            }
        )

    def export_pdf(self):
        targets = self._ensure_export_targets(["pdf"])
        if not targets:
            return
        payload = self.collect_payload()
        if not self._confirm_export_warning_if_needed(payload):
            return
        if not self._confirm_wording_review_if_needed(payload):
            return
        self._start_export_request(
            {
                "mode": "single",
                "action_label": "pdf export",
                "payload": payload,
                "output_map": {"pdf": targets["pdf"]},
                "artifact_updates": {"single_doc_pdf": targets["pdf"]},
                "success_title": "PDF Export Complete",
                "success_message": f"PDF packet draft saved to:\n{targets['pdf']}",
            }
        )

    def export_both(self):
        targets = self._ensure_export_targets(["docx", "pdf"])
        if not targets:
            return
        payload = self.collect_payload()
        if not self._confirm_export_warning_if_needed(payload):
            return
        if not self._confirm_wording_review_if_needed(payload):
            return
        self._start_export_request(
            {
                "mode": "single",
                "action_label": "word and pdf export",
                "payload": payload,
                "output_map": {"docx": targets["docx"], "pdf": targets["pdf"]},
                "artifact_updates": {"single_doc_docx": targets["docx"], "single_doc_pdf": targets["pdf"]},
                "success_title": "Packet Exports Complete",
                "success_message": f"Word draft:\n{targets['docx']}\n\nPDF draft:\n{targets['pdf']}",
            }
        )

    def export_referral_request_bundle(self):
        self._export_bundle_group("referral_request", "Referral Request Export Complete")

    def export_patient_packet_bundle(self):
        if normalize_bundle_export_format(self._selected_bundle_format()) == "pdf":
            self._export_compiled_patient_packet_pdf()
            return
        self._export_bundle_group("patient_packet", "Patient Packet Export Complete")

    def open_export_folder(self):
        export_dir = self._resolve_export_dir()
        if export_dir and os.path.isdir(export_dir):
            os.startfile(export_dir)
        else:
            QMessageBox.information(self, "No Export Folder Yet", "Choose an export folder first.")

    def _export_bundle_group(self, group_name, success_title):
        bundle_dir = self._ensure_bundle_export_dir(group_name)
        if not bundle_dir:
            return
        base_payload = self.collect_payload()
        if not self._confirm_export_warning_if_needed(base_payload, group_name=group_name):
            return
        if not self._confirm_wording_review_if_needed(base_payload, group_name=group_name):
            return
        plan = build_bundle_export_plan(self._resolve_base_filename(), group_name, self._selected_bundle_format())
        documents = []
        for item in plan.get("documents") or []:
            payload = build_profile_export_payload(base_payload, item.get("profile_name"))
            target_path = os.path.join(bundle_dir, item.get("filename") or "packet_document")
            documents.append(
                {
                    "payload": payload,
                    "target_path": target_path,
                    "extension": str(item.get("extension") or "").strip().lower(),
                }
            )
        if group_name == "patient_packet":
            artifact_key = "patient_packet_bundle_dir"
        else:
            artifact_key = "referral_request_bundle_dir"
        artifact_updates = {artifact_key: bundle_dir}
        if group_name == "referral_request":
            referral_pdf = os.path.join(bundle_dir, "Community_Care_Referral_Request.pdf")
            artifact_updates["referral_request_pdf"] = referral_pdf
        self._start_export_request(
            {
                "mode": "bundle",
                "action_label": f"{group_name.replace('_', ' ')} bundle",
                "group_name": group_name,
                "bundle_dir": bundle_dir,
                "documents": documents,
                "artifact_updates": artifact_updates,
                "success_title": success_title,
            }
        )

    def _export_compiled_patient_packet_pdf(self):
        export_dir = self._resolve_export_dir()
        if not export_dir:
            QMessageBox.warning(
                self,
                "Export Folder Required",
                "Choose an export folder before exporting the compiled patient packet PDF.",
            )
            return

        base_payload = self.collect_payload()
        if not self._confirm_export_warning_if_needed(base_payload, group_name="patient_packet"):
            return
        if not self._confirm_wording_review_if_needed(base_payload, group_name="patient_packet"):
            return
        target_path = os.path.join(export_dir, compiled_packet_filename(self._resolve_base_filename(), "patient_packet"))
        documents = [
            {"payload": build_profile_export_payload(base_payload, profile_name)}
            for profile_name in PATIENT_PACKET_PROFILE_ORDER
        ]
        self._start_export_request(
            {
                "mode": "compiled_pdf",
                "action_label": "compiled patient packet pdf",
                "documents": documents,
                "target_path": target_path,
                "artifact_updates": {"compiled_patient_packet_pdf": target_path},
                "success_title": "Patient Packet Export Complete",
                "success_message": f"Compiled patient packet PDF saved to:\n{target_path}",
            }
        )
