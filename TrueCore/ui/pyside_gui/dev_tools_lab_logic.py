from __future__ import annotations

import html

from PySide6.QtGui import QColor

from TrueCore.ui.pyside_gui.dev_tools_profiles import get_packet_export_group


def build_packet_lab_report(
    payload,
    *,
    apply_packet_builder_shared_field_sync_fn,
    default_packet_builder_payload_fn,
    has_meaningful_value_fn,
    shared_packet_header_fields,
    build_profile_current_form_checks_fn,
    build_packet_inconsistency_messages_fn,
    build_wording_assist_entries_fn,
):
    packet = apply_packet_builder_shared_field_sync_fn(default_packet_builder_payload_fn() | dict(payload or {}))
    profile_name = packet.get("packet_profile") or ""

    shared_checks = [
        (label, has_meaningful_value_fn(packet.get(field_name)))
        for field_name, label in shared_packet_header_fields
    ]
    current_form_checks = list(build_profile_current_form_checks_fn(profile_name, packet))
    inconsistency_messages = build_packet_inconsistency_messages_fn(packet)
    wording_entries = build_wording_assist_entries_fn(packet)
    wording_checks = []
    for entry in wording_entries:
        wording_checks.append(
            (
                f"Wording Review: {entry['label']}",
                entry["status_key"] == "approved",
            )
        )
    current_form_checks.extend(wording_checks)

    patient_packet_checks = []
    if get_packet_export_group(profile_name) == "patient_packet":
        patient_packet_checks = [
            ("Virtual Consent Included", bool(packet.get("included_virtual_consent_form"))),
            ("VA Form 10-10172 Included", bool(packet.get("included_va_form_10_10172"))),
            ("SEOC Request Included", bool(packet.get("included_seoc_request"))),
            ("Consult Request Included", bool(packet.get("included_consult_request"))),
            ("Letter Of Medical Necessity Included", bool(packet.get("included_lomn"))),
            ("Clinical Notes Included", bool(packet.get("included_clinical_notes"))),
            ("MRI Report Included", bool(packet.get("included_mri_report"))),
        ]

    shared_missing = [label for label, present in shared_checks if not present]
    current_missing = [label for label, present in current_form_checks if not present]
    packet_missing = [label for label, present in patient_packet_checks if not present]

    shared_complete = sum(1 for _, present in shared_checks if present)
    current_complete = sum(1 for _, present in current_form_checks if present)
    packet_complete = sum(1 for _, present in patient_packet_checks if present)

    score = 100
    score -= len(shared_missing) * 8
    score -= len(current_missing) * 7
    score -= len(packet_missing) * 3
    score -= len(inconsistency_messages) * 10
    score = max(0, min(100, score))

    if inconsistency_messages:
        status = "Needs Consistency Fixes"
    elif shared_missing:
        status = "Needs Shared Packet Header Details"
    elif current_missing or packet_missing:
        status = "Needs Current Form Work"
    else:
        status = "Ready To Export"

    return {
        "status": status,
        "score": score,
        "profile_name": profile_name,
        "shared_checks": shared_checks,
        "current_form_checks": current_form_checks,
        "patient_packet_checks": patient_packet_checks,
        "shared_missing": shared_missing,
        "current_missing": current_missing,
        "packet_missing": packet_missing,
        "shared_complete": shared_complete,
        "current_complete": current_complete,
        "packet_complete": packet_complete,
        "inconsistency_messages": inconsistency_messages,
        "wording_entries": wording_entries,
        "wording_checks": wording_checks,
    }


def classify_packet_lab_completion(report):
    current_checks = list(report.get("current_form_checks") or [])
    current_complete = int(report.get("current_complete") or 0)
    current_missing = list(report.get("current_missing") or [])
    shared_missing = list(report.get("shared_missing") or [])
    inconsistency_messages = list(report.get("inconsistency_messages") or [])

    if current_checks and current_complete <= 0:
        return "not_started", "Not Started"
    if shared_missing or current_missing or inconsistency_messages:
        return "in_progress", "In Progress"
    return "complete", "Complete"


def packet_profile_status_palette(status_key):
    palettes = {
        "complete": {
            "item_background": QColor("#103522"),
            "item_foreground": QColor("#CFF8DE"),
            "combo_background": "#173B29",
            "combo_border": "#2C8B57",
            "combo_text": "#EAFBF1",
        },
        "in_progress": {
            "item_background": QColor("#4A3410"),
            "item_foreground": QColor("#FFF2C4"),
            "combo_background": "#4A3410",
            "combo_border": "#C7922E",
            "combo_text": "#FFF6DB",
        },
        "not_started": {
            "item_background": QColor("#441A1A"),
            "item_foreground": QColor("#FFD8D8"),
            "combo_background": "#441A1A",
            "combo_border": "#B55050",
            "combo_text": "#FFECEC",
        },
    }
    return palettes.get(status_key, palettes["not_started"])


def build_packet_lab_html(
    payload,
    *,
    build_packet_lab_report_fn,
    render_packet_builder_document_preview_fn,
):
    report = build_packet_lab_report_fn(payload)

    def checklist_html(rows):
        if not rows:
            return "<div style='color:#64748B; font-style:italic;'>No checks for this scope.</div>"
        parts = []
        for label, present in rows:
            color = "#1F6F43" if present else "#A63A3A"
            marker = "&#10003;" if present else "&#10007;"
            parts.append(
                f"<div style='margin-top:6px; color:{color};'><span style='font-weight:700;'>{marker}</span> {html.escape(label)}</div>"
            )
        return "".join(parts)

    missing_lines = []
    if report["shared_missing"]:
        missing_lines.append(
            "<div style='margin-top:8px;'><strong>Shared header still missing:</strong> "
            + ", ".join(html.escape(item) for item in report["shared_missing"])
            + "</div>"
        )
    if report["current_missing"]:
        missing_lines.append(
            "<div style='margin-top:8px;'><strong>Current form still missing:</strong> "
            + ", ".join(html.escape(item) for item in report["current_missing"])
            + "</div>"
        )
    if report["packet_missing"]:
        missing_lines.append(
            "<div style='margin-top:8px;'><strong>Patient packet items not marked included:</strong> "
            + ", ".join(html.escape(item) for item in report["packet_missing"])
            + "</div>"
        )
    if report["inconsistency_messages"]:
        missing_lines.append(
            "<div style='margin-top:8px;'><strong>Consistency issues:</strong></div>"
            + "".join(
                f"<div style='margin-top:6px;'>{html.escape(item)}</div>"
                for item in report["inconsistency_messages"]
            )
        )
    pending_wording = [
        entry for entry in report.get("wording_entries") or []
        if entry.get("status_key") != "approved"
    ]
    if pending_wording:
        missing_lines.append(
            "<div style='margin-top:8px;'><strong>Wording assist still needs attention:</strong></div>"
            + "".join(
                (
                    f"<div style='margin-top:6px;'>{html.escape(entry['label'])}: "
                    + (
                        "missing " + ", ".join(html.escape(item) for item in entry.get("missing_facts") or [])
                        if entry.get("missing_facts")
                        else "review or approval still pending"
                    )
                    + "</div>"
                )
                for entry in pending_wording
            )
        )

    markup = (
        "<div style='font-family:Calibri, Arial, sans-serif; color:#111827; line-height:1.55;'>"
        "<div style='font-size:18pt; font-weight:700;'>Packet Studio Lab</div>"
        f"<div style='margin-top:8px; font-size:11pt;'><strong>Current form:</strong> {html.escape(report['profile_name'] or 'Unknown')}</div>"
        f"<div style='margin-top:6px; font-size:11pt;'><strong>Draft status:</strong> {html.escape(report['status'])}</div>"
        f"<div style='margin-top:6px; font-size:11pt;'><strong>Lab score:</strong> {report['score']}%</div>"
        "<div style='margin-top:18px; font-size:12pt; font-weight:700; color:#1F3A5F;'>Shared Packet Header</div>"
        f"<div style='margin-top:6px; color:#4B5563;'>{report['shared_complete']} of {len(report['shared_checks'])} complete. These values carry across forms where expected.</div>"
        + checklist_html(report["shared_checks"])
        + "<div style='margin-top:18px; font-size:12pt; font-weight:700; color:#1F3A5F;'>Current Form Essentials</div>"
        f"<div style='margin-top:6px; color:#4B5563;'>{report['current_complete']} of {len(report['current_form_checks'])} complete.</div>"
        + checklist_html(report["current_form_checks"])
    )
    if report["patient_packet_checks"]:
        markup += (
            "<div style='margin-top:18px; font-size:12pt; font-weight:700; color:#1F3A5F;'>Patient Packet Bundle Marks</div>"
            f"<div style='margin-top:6px; color:#4B5563;'>{report['packet_complete']} of {len(report['patient_packet_checks'])} marked included.</div>"
            + checklist_html(report["patient_packet_checks"])
        )
    if report["inconsistency_messages"]:
        markup += (
            "<div style='margin-top:18px; padding:12px 14px; background:#FEF3C7; border:1px solid #EAB308;'>"
            "<div style='font-weight:700; color:#92400E;'>Consistency Flags</div>"
            + "".join(
                f"<div style='margin-top:6px; color:#92400E;'>{html.escape(item)}</div>"
                for item in report["inconsistency_messages"]
            )
            + "</div>"
        )
    if missing_lines:
        markup += (
            "<div style='margin-top:18px; padding:12px 14px; background:#FFF7ED; border:1px solid #F3D6A4;'>"
            "<div style='font-weight:700; color:#9A4D00;'>What To Fix Before Export</div>"
            + "".join(missing_lines)
            + "</div>"
        )
    else:
        markup += (
            "<div style='margin-top:18px; padding:12px 14px; background:#ECFDF3; border:1px solid #B8E3C9;'>"
            "<div style='font-weight:700; color:#1F6F43;'>This draft is in a strong place for export.</div>"
            "<div style='margin-top:6px;'>Shared packet facts are complete, and the current form has its key page-specific details filled in.</div>"
            "</div>"
        )

    markup += "</div>"
    return render_packet_builder_document_preview_fn(markup)
