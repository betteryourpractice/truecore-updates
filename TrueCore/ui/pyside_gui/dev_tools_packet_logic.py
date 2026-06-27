from __future__ import annotations

import hashlib
import html
import json
import os
import re
from datetime import datetime

from TrueCoreIntel.data.packet_model import Packet
from TrueCoreIntel.intelligence.packet_rubric import build_packet_rubric
from TrueCoreIntel.review.review_engine import ReviewEngine
from TrueCore.ui.pyside_gui.dev_tools_profiles import (
    bundle_profiles_for_group,
    default_title_for_profile,
    get_packet_export_group,
    sanitize_builder_filename,
)
from TrueCore.utils.runtime_info import runtime_data_path


PACKET_LIBRARY_DIR = runtime_data_path("dev_system", "packet_library")
WORDING_REVIEW_DECISIONS = {"accepted", "edited", "keep_original"}
WORDING_STATUS_COLORS = {
    "approved": ("#173B29", "#2C8B57", "#EAFBF1"),
    "needs_review": ("#4A3410", "#C7922E", "#FFF6DB"),
    "needs_facts": ("#441A1A", "#B55050", "#FFECEC"),
}
WORDING_FACT_LABELS = {
    "diagnosis": "Primary diagnosis",
    "secondary_diagnosis": "Secondary diagnosis",
    "icd_codes": "ICD-10 code",
    "requested_service": "Requested service",
    "mri_date": "MRI date",
    "mri_findings": "MRI findings",
    "affected_levels": "Affected spinal level(s)",
    "symptom_summary": "Clinical summary / symptoms",
    "functional_impact": "Functional impairment",
    "conservative_history": "Conservative treatment history",
    "consult_requested_services": "Requested consult services",
    "seoc_scope_items": "SEOC scope items",
    "clinical_plan_items": "Treatment plan items",
    "clinical_limitations": "Functional limitation detail",
    "estimated_duration_text": "Estimated duration",
    "ordering_doctor": "VA referring / ordering provider",
    "facility": "VA facility / medical center",
}


def build_wording_risk_messages(text, *, sanitize_packet_builder_text_fn):
    value = sanitize_packet_builder_text_fn(text)
    if not value:
        return ["No wording entered yet for this field."]
    risks = []
    lowered = value.lower()
    if re.search(r"\b(heal|heals|cure|cures|guarantee|guarantees|fix|fixes|eliminate|eliminates)\b", lowered):
        risks.append("Avoid overpromising words such as heal, cure, fix, eliminate, or guarantee.")
    if "will prevent" in lowered or "will reduce" in lowered:
        risks.append(
            "Avoid absolute outcome claims such as will prevent or will reduce. Prefer intended to or if clinically indicated."
        )
    if re.search(r"\b(best|superior|revolutionary|cutting-edge|innovative)\b", lowered):
        risks.append("Avoid marketing or promotional language. Keep the tone clinical and documentation-based.")
    if re.search(r"\b(stuff|thing|things|really|just|bad back|fix pain)\b", lowered):
        risks.append("Tighten casual or vague wording so the request reads like provider documentation.")
    if "pain management" in lowered and "not open-ended pain management" not in lowered:
        risks.append("Clarify scope so the request does not sound like open-ended pain management.")
    return risks


def _wording_entry_fingerprint(
    spec,
    packet,
    raw_text,
    suggestion_text,
    *,
    sanitize_packet_builder_text_fn,
    wording_fact_text_fn,
):
    payload = {
        "field_name": spec.get("field_name"),
        "raw_text": sanitize_packet_builder_text_fn(raw_text),
        "suggestion_text": sanitize_packet_builder_text_fn(suggestion_text),
        "facts": {
            fact_key: wording_fact_text_fn(packet, fact_key)
            for fact_key in spec.get("required_facts") or []
        },
    }
    return hashlib.sha1(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def build_wording_assist_entries(
    payload,
    *,
    normalize_packet_builder_payload_fn,
    wording_assist_specs_for_profile_fn,
    sanitize_packet_builder_text_fn,
    wording_fact_text_fn,
    wording_review_decisions=WORDING_REVIEW_DECISIONS,
    wording_fact_labels=WORDING_FACT_LABELS,
):
    packet = normalize_packet_builder_payload_fn(payload)
    profile_name = packet.get("packet_profile") or ""
    review_state = dict(packet.get("wording_assist_state") or {})
    entries = []
    for spec in wording_assist_specs_for_profile_fn(profile_name):
        raw_text = str(packet.get(spec.get("field_name")) or "").strip()
        missing_facts = [
            wording_fact_labels.get(fact_key, fact_key.replace("_", " ").title())
            for fact_key in spec.get("required_facts") or []
            if not wording_fact_text_fn(packet, fact_key)
        ]
        suggestion_text = ""
        state = dict(review_state.get(spec["key"]) or {})
        cycle_index = 0
        try:
            cycle_index = max(0, int(state.get("cycle_index") or 0))
        except Exception:
            cycle_index = 0
        if not missing_facts:
            packet_for_builder = dict(packet)
            packet_for_builder["__wording_cycle_key"] = spec["key"]
            packet_for_builder["__wording_cycle_index"] = cycle_index
            builder_result = spec["builder"](packet_for_builder, raw_text)
            if isinstance(builder_result, dict):
                suggestion_text = sanitize_packet_builder_text_fn(builder_result.get("suggestion_text") or "")
                scenario_label = sanitize_packet_builder_text_fn(builder_result.get("scenario_label") or "")
                scenario_use_when = sanitize_packet_builder_text_fn(builder_result.get("scenario_use_when") or "")
            else:
                suggestion_text = sanitize_packet_builder_text_fn(builder_result)
                scenario_label = ""
                scenario_use_when = ""
        else:
            scenario_label = ""
            scenario_use_when = ""
        source_fingerprint = _wording_entry_fingerprint(
            spec,
            packet,
            raw_text,
            suggestion_text + "|" + scenario_label,
            sanitize_packet_builder_text_fn=sanitize_packet_builder_text_fn,
            wording_fact_text_fn=wording_fact_text_fn,
        )
        decision = str(state.get("decision") or "").strip().lower()
        approved_text = sanitize_packet_builder_text_fn(state.get("approved_text") or "")
        stale = bool(state) and str(state.get("source_fingerprint") or "") != source_fingerprint
        if missing_facts:
            status_key = "needs_facts"
            status_label = "Needs Facts"
        elif decision in wording_review_decisions and approved_text and not stale:
            status_key = "approved"
            status_label = {
                "accepted": "Accepted Suggestion",
                "edited": "Edited Suggestion",
                "keep_original": "Kept Original",
            }.get(decision, "Approved")
        else:
            status_key = "needs_review"
            status_label = "Needs Review"
        entries.append(
            {
                "key": spec["key"],
                "label": spec["label"],
                "field_name": spec["field_name"],
                "raw_text": raw_text,
                "suggestion_text": suggestion_text,
                "missing_facts": missing_facts,
                "risk_messages": build_wording_risk_messages(
                    raw_text,
                    sanitize_packet_builder_text_fn=sanitize_packet_builder_text_fn,
                ),
                "status_key": status_key,
                "status_label": status_label,
                "decision": decision,
                "approved_text": approved_text,
                "source_fingerprint": source_fingerprint,
                "stale": stale,
                "cycle_index": cycle_index,
                "scenario_label": scenario_label,
                "scenario_use_when": scenario_use_when,
            }
        )
    return entries


def build_wording_assist_banner(payload, *, build_wording_assist_entries_fn):
    entries = build_wording_assist_entries_fn(payload)
    if not entries:
        return ""
    pending = [entry for entry in entries if entry["status_key"] != "approved"]
    if not pending:
        return (
            "<div style='margin-bottom:14px; padding:10px 12px; background:#ECFDF3; border:1px solid #B8E3C9; color:#1F6F43; font-size:11pt; line-height:1.35;'>"
            "<div style='font-weight:700;'>Wording Assist Ready</div>"
            "<div style='margin-top:4px;'>High-risk wording fields on this form have been reviewed and approved.</div>"
            "</div>"
        )
    fact_blockers = [entry for entry in pending if entry["status_key"] == "needs_facts"]
    review_blockers = [entry for entry in pending if entry["status_key"] == "needs_review"]
    detail_lines = []
    if fact_blockers:
        detail_lines.append(
            f"{len(fact_blockers)} field(s) still need supporting facts before professional wording can be approved."
        )
    if review_blockers:
        detail_lines.append(
            f"{len(review_blockers)} field(s) still need wording review or approval."
        )
    return (
        "<div style='margin-bottom:14px; padding:10px 12px; background:#FFF7ED; border:1px solid #F1C996; color:#7C3400; font-size:11pt; line-height:1.35;'>"
        "<div style='font-weight:700;'>Wording Assist Pending</div>"
        "<div style='margin-top:4px;'>"
        + html.escape(" ".join(detail_lines) or "Review the Wording Assist tab before final export.")
        + "</div>"
        "</div>"
    )


def _critical_shared_field_count(packet):
    critical_shared_values = [
        str(packet.get("patient_name") or "").strip(),
        str(packet.get("date_of_birth") or "").strip(),
        str(packet.get("facility") or "").strip(),
        str(packet.get("ordering_doctor") or "").strip(),
        str(packet.get("diagnosis") or "").strip(),
        str(packet.get("authorization_number") or "").strip(),
    ]
    return sum(1 for value in critical_shared_values if value)


def should_enforce_wording_assist(payload, *, normalize_packet_builder_payload_fn):
    packet = normalize_packet_builder_payload_fn(payload)
    return _critical_shared_field_count(packet) >= 3


def build_wording_export_blockers(
    payload,
    group_name="",
    *,
    normalize_packet_builder_payload_fn,
    should_enforce_wording_assist_fn,
    build_profile_export_payload_fn,
    build_wording_assist_entries_fn,
):
    packet = normalize_packet_builder_payload_fn(payload)
    if not should_enforce_wording_assist_fn(packet, group_name=group_name):
        return []
    normalized_group = str(group_name or "").strip().lower()
    profiles = bundle_profiles_for_group(normalized_group) if normalized_group else [packet.get("packet_profile")]
    blockers = []
    for profile_name in profiles:
        if not profile_name:
            continue
        profile_payload = (
            build_profile_export_payload_fn(packet, profile_name)
            if normalized_group
            else normalize_packet_builder_payload_fn(packet)
        )
        for entry in build_wording_assist_entries_fn(profile_payload):
            if entry["missing_facts"]:
                blockers.append(
                    f"{default_title_for_profile(profile_name) or profile_name} - {entry['label']}: missing "
                    + ", ".join(entry["missing_facts"])
                )
            elif entry["status_key"] != "approved":
                blockers.append(
                    f"{default_title_for_profile(profile_name) or profile_name} - {entry['label']}: wording review still needs approval"
                )
    return blockers


def ensure_packet_library_dir(*, packet_library_dir=PACKET_LIBRARY_DIR):
    os.makedirs(packet_library_dir, exist_ok=True)
    return packet_library_dir


def packet_library_record_path(draft_id, *, packet_library_dir=PACKET_LIBRARY_DIR):
    safe_id = sanitize_builder_filename(draft_id or "packet_draft")
    return os.path.join(ensure_packet_library_dir(packet_library_dir=packet_library_dir), f"{safe_id}.json")


def generate_packet_library_draft_id():
    return datetime.now().strftime("draft_%Y%m%d_%H%M%S_%f")


def packet_library_display_name(payload, base_filename="", *, normalize_packet_builder_payload_fn):
    packet = normalize_packet_builder_payload_fn(payload)
    patient_name = str(packet.get("patient_name") or "").strip()
    profile_name = str(packet.get("packet_profile") or "").strip()
    packet_title = str(packet.get("packet_title") or "").strip()
    normalized_base = sanitize_builder_filename(base_filename)

    if patient_name:
        return patient_name
    if normalized_base and normalized_base != "truecore_packet":
        return normalized_base.replace("_", " ")
    if packet_title and packet_title != default_title_for_profile(profile_name):
        return packet_title
    fallback_title = default_title_for_profile(profile_name) or "TrueCore Packet"
    return f"{fallback_title} Draft"


def build_packet_library_completion(
    payload,
    *,
    normalize_packet_builder_payload_fn,
    build_profile_export_payload_fn,
    build_packet_lab_report_fn,
):
    packet = normalize_packet_builder_payload_fn(payload)
    group_name = get_packet_export_group(packet.get("packet_profile"))
    profile_names = bundle_profiles_for_group(group_name) or [packet.get("packet_profile")]
    profile_reports = [
        build_packet_lab_report_fn(build_profile_export_payload_fn(packet, profile_name))
        for profile_name in profile_names
        if profile_name
    ]
    if not profile_reports:
        profile_reports = [build_packet_lab_report_fn(packet)]

    shared_checks = list(profile_reports[0].get("shared_checks") or [])
    packet_checks = list(profile_reports[0].get("patient_packet_checks") or [])
    current_total = sum(len(report.get("current_form_checks") or []) for report in profile_reports)
    current_complete = sum(int(report.get("current_complete") or 0) for report in profile_reports)
    packet_total = len(packet_checks)
    packet_complete = int(profile_reports[0].get("packet_complete") or 0)
    shared_total = len(shared_checks)
    shared_complete = int(profile_reports[0].get("shared_complete") or 0)

    shared_missing = list(dict.fromkeys(profile_reports[0].get("shared_missing") or []))
    packet_missing = list(dict.fromkeys(profile_reports[0].get("packet_missing") or []))
    current_missing = []
    for report in profile_reports:
        for label in report.get("current_missing") or []:
            if label not in current_missing:
                current_missing.append(label)

    total_checks = shared_total + current_total + packet_total
    total_complete = shared_complete + current_complete + packet_complete
    completion_score = round((100.0 * total_complete / total_checks), 2) if total_checks else 0.0

    if total_complete <= 0:
        status_key, status_label = "not_started", "Not Started"
    elif not shared_missing and not current_missing and not packet_missing:
        status_key, status_label = "complete", "Complete"
    else:
        status_key, status_label = "in_progress", "In Progress"

    return {
        "group_name": group_name,
        "profile_names": profile_names,
        "shared_checks": shared_checks,
        "packet_checks": packet_checks,
        "shared_total": shared_total,
        "shared_complete": shared_complete,
        "current_total": current_total,
        "current_complete": current_complete,
        "packet_total": packet_total,
        "packet_complete": packet_complete,
        "shared_missing": shared_missing,
        "current_missing": current_missing,
        "packet_missing": packet_missing,
        "status_key": status_key,
        "status_label": status_label,
        "completion_score": completion_score,
    }


def build_export_warning_context(
    payload,
    group_name="",
    *,
    normalize_packet_builder_payload_fn,
    build_packet_library_completion_fn,
    build_packet_lab_report_fn,
    classify_packet_lab_completion_fn,
):
    packet = normalize_packet_builder_payload_fn(payload)
    normalized_group = str(group_name or get_packet_export_group(packet.get("packet_profile")) or "").strip().lower()
    critical_shared_values = [
        str(packet.get("patient_name") or "").strip(),
        str(packet.get("date_of_birth") or "").strip(),
        str(packet.get("facility") or "").strip(),
        str(packet.get("ordering_doctor") or "").strip(),
        str(packet.get("diagnosis") or "").strip(),
        str(packet.get("authorization_number") or "").strip(),
    ]
    critical_shared_complete = sum(1 for value in critical_shared_values if value)

    if normalized_group == "patient_packet":
        completion = build_packet_library_completion_fn(packet)
        completion_score = float(completion.get("completion_score") or 0.0)
        if completion.get("status_key") == "not_started" or completion_score <= 10.0 or critical_shared_complete <= 1:
            return {
                "title": "Packet Mostly Empty",
                "message": (
                    "This patient packet is still mostly empty.\n\n"
                    f"Completion score: {completion_score:.0f}%\n"
                    f"Core packet facts: {critical_shared_complete} of 6\n"
                    f"Shared header: {completion.get('shared_complete', 0)} of {completion.get('shared_total', 0)}\n"
                    f"Forms complete: {completion.get('current_complete', 0)} of {completion.get('current_total', 0)}\n\n"
                    "Export anyway?"
                ),
            }
        return None

    report = build_packet_lab_report_fn(packet)
    status_key, _ = classify_packet_lab_completion_fn(report)
    if status_key == "not_started" or critical_shared_complete <= 1:
        return {
            "title": "Form Not Started",
            "message": (
                "This form has not really been started yet.\n\n"
                f"Core packet facts: {critical_shared_complete} of 6\n"
                f"Shared header: {report.get('shared_complete', 0)} of {len(report.get('shared_checks') or [])}\n"
                f"Current form: {report.get('current_complete', 0)} of {len(report.get('current_form_checks') or [])}\n\n"
                "Export anyway?"
            ),
        }
    return None


def _add_packet_field_observation(packet, field_name, document_type, value):
    normalized_value = value if isinstance(value, bool) else str(value or "").strip()
    if normalized_value in ("", None, []):
        return
    packet.fields[field_name] = normalized_value
    packet.field_observations.setdefault(field_name, []).append(
        {
            "document_type": str(document_type or "").strip().lower(),
            "value": normalized_value,
        }
    )


def build_packet_library_production_metrics(
    payload,
    *,
    normalize_packet_builder_payload_fn,
    build_packet_library_completion_fn,
    first_icd_code_fn,
):
    packet_payload = normalize_packet_builder_payload_fn(payload)
    completion = build_packet_library_completion_fn(packet_payload)
    packet = Packet()
    group_name = completion.get("group_name")
    packet.packet_profile = "authorization_request" if group_name == "referral_request" else "full_submission"
    packet.packet_profile_label = "Authorization Request" if group_name == "referral_request" else "Full Submission"
    packet.packet_assembly_score = float(completion.get("completion_score") or 0.0)
    packet.packet_confidence = round(max(0.32, min(0.96, packet.packet_assembly_score / 100.0)), 2)

    patient_name = str(packet_payload.get("patient_name") or "").strip()
    dob = str(packet_payload.get("date_of_birth") or "").strip()
    auth_number = str(packet_payload.get("authorization_number") or "").strip()
    diagnosis = str(packet_payload.get("diagnosis") or packet_payload.get("consult_primary_diagnosis") or "").strip()
    icd_codes = str(packet_payload.get("icd_codes") or "").strip()
    ordering_provider = str(packet_payload.get("ordering_doctor") or "").strip()
    facility = str(packet_payload.get("facility") or "").strip()
    requested_service = str(packet_payload.get("requested_service") or "").strip()
    clinical_summary = str(
        packet_payload.get("clinical_summary")
        or packet_payload.get("clinical_doc_chief_complaint")
        or packet_payload.get("consult_reason_text")
        or ""
    ).strip()

    packet.fields.update(
        {
            "name": patient_name,
            "dob": dob,
            "authorization_number": auth_number,
            "claim_number": auth_number,
            "va_icn": str(packet_payload.get("va_icn") or "").strip(),
            "ordering_provider": ordering_provider,
            "provider": str(packet_payload.get("provider") or packet_payload.get("master_practice_name") or "").strip(),
            "facility": facility,
            "diagnosis": diagnosis,
            "icd_codes": icd_codes,
            "reason_for_request": requested_service or str(packet_payload.get("consult_reason_text") or "").strip(),
            "procedure": requested_service,
            "symptom": clinical_summary,
        }
    )

    detected_documents = set()
    if group_name == "referral_request":
        detected_documents.update({"rfs", "approved_referral"})
    else:
        if packet_payload.get("included_va_form_10_10172"):
            detected_documents.update({"rfs", "approved_referral"})
        if packet_payload.get("included_virtual_consent_form"):
            detected_documents.add("consent")
        if packet_payload.get("included_seoc_request"):
            detected_documents.add("seoc")
        if packet_payload.get("included_consult_request"):
            detected_documents.add("consult_request")
        if packet_payload.get("included_lomn"):
            detected_documents.add("lomn")
        if packet_payload.get("included_clinical_notes"):
            detected_documents.add("clinical_notes")
        if packet_payload.get("included_mri_report"):
            detected_documents.add("imaging_report")
    packet.detected_documents = detected_documents

    if "rfs" in detected_documents:
        for field_name, value in {
            "name": patient_name,
            "dob": dob,
            "authorization_number": auth_number,
            "diagnosis": diagnosis or str(packet_payload.get("va10172_diagnosis_description") or "").strip(),
            "icd_codes": icd_codes or str(packet_payload.get("primary_diagnosis_code") or "").strip(),
        }.items():
            _add_packet_field_observation(packet, field_name, "rfs", value)

    if "seoc" in detected_documents:
        for field_name, value in {
            "name": patient_name,
            "dob": dob,
            "reason_for_request": str(packet_payload.get("clinical_objectives") or requested_service).strip(),
            "diagnosis": str(packet_payload.get("episode_diagnosis") or diagnosis).strip(),
            "icd_codes": str(packet_payload.get("episode_icd_code") or first_icd_code_fn(icd_codes)).strip(),
        }.items():
            _add_packet_field_observation(packet, field_name, "seoc", value)

    if "consult_request" in detected_documents:
        for field_name, value in {
            "ordering_provider": str(packet_payload.get("consult_referring_va_provider") or ordering_provider).strip(),
            "reason_for_request": str(packet_payload.get("consult_reason_text") or requested_service).strip(),
            "diagnosis": str(packet_payload.get("consult_primary_diagnosis") or diagnosis).strip(),
            "icd_codes": icd_codes,
        }.items():
            _add_packet_field_observation(packet, field_name, "consult_request", value)

    if "lomn" in detected_documents:
        for field_name, value in {
            "reason_for_request": str(packet_payload.get("lmn_medical_necessity_statement") or requested_service).strip(),
            "diagnosis": str(packet_payload.get("lmn_primary_diagnosis") or diagnosis).strip(),
            "icd_codes": icd_codes,
        }.items():
            _add_packet_field_observation(packet, field_name, "lomn", value)

    if "consent" in detected_documents:
        _add_packet_field_observation(packet, "name", "consent", patient_name)
        _add_packet_field_observation(packet, "dob", "consent", dob)
        if str(packet_payload.get("patient_signature_name") or "").strip() and str(packet_payload.get("patient_signature_date") or "").strip():
            _add_packet_field_observation(packet, "signature_present", "consent", True)
        else:
            packet.unfilled_documents.add("consent")

    if "clinical_notes" in detected_documents:
        for field_name, value in {
            "diagnosis": str(packet_payload.get("clinical_doc_primary_diagnosis") or diagnosis).strip(),
            "icd_codes": icd_codes,
            "symptom": str(packet_payload.get("clinical_doc_chief_complaint") or clinical_summary).strip(),
        }.items():
            _add_packet_field_observation(packet, field_name, "clinical_notes", value)

    packet.packet_rubric = build_packet_rubric(packet)
    packet.packet_score = packet.packet_rubric.get("score")
    packet.packet_strength = packet.packet_rubric.get("score_band")
    packet.packet_main_blocker = packet.packet_rubric.get("main_blocker")

    decision = ReviewEngine().build_submission_decision(packet)
    return {
        "score": float(packet.packet_rubric.get("score") or 0.0),
        "strength": str(packet.packet_rubric.get("score_band") or "weak"),
        "main_blocker": packet.packet_rubric.get("main_blocker"),
        "readiness": str(decision.get("readiness") or "hold"),
        "next_action": str(decision.get("next_action") or "").strip(),
        "decision": decision,
        "completion": completion,
    }


def list_packet_library_records(*, normalize_packet_builder_payload_fn, packet_library_dir=PACKET_LIBRARY_DIR):
    ensure_packet_library_dir(packet_library_dir=packet_library_dir)
    records = []
    for name in os.listdir(packet_library_dir):
        if not str(name).lower().endswith(".json"):
            continue
        path = os.path.join(packet_library_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                record = dict(json.load(handle) or {})
        except Exception:
            continue
        payload = normalize_packet_builder_payload_fn(record.get("payload") or {})
        record["draft_id"] = str(record.get("draft_id") or os.path.splitext(name)[0]).strip()
        record["base_filename"] = sanitize_builder_filename(record.get("base_filename") or "truecore_packet")
        record["display_name"] = str(
            record.get("display_name")
            or packet_library_display_name(
                payload,
                record.get("base_filename"),
                normalize_packet_builder_payload_fn=normalize_packet_builder_payload_fn,
            )
        ).strip()
        record["path"] = path
        record["payload"] = payload
        record["artifacts"] = dict(record.get("artifacts") or {})
        record["updated_at"] = str(record.get("updated_at") or record.get("saved_at") or "").strip()
        records.append(record)
    records.sort(key=lambda item: item.get("updated_at") or "", reverse=True)
    return records


def save_packet_library_record(record, *, packet_library_dir=PACKET_LIBRARY_DIR):
    draft_id = str(record.get("draft_id") or generate_packet_library_draft_id()).strip()
    record = dict(record or {})
    record["draft_id"] = draft_id
    path = packet_library_record_path(draft_id, packet_library_dir=packet_library_dir)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=4)
    record["path"] = path
    return record


def delete_packet_library_record(draft_id, *, packet_library_dir=PACKET_LIBRARY_DIR):
    path = packet_library_record_path(draft_id, packet_library_dir=packet_library_dir)
    if os.path.exists(path):
        os.remove(path)
