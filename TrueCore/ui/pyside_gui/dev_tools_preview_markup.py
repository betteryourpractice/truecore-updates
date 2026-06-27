from __future__ import annotations

import html
import re

from TrueCore.ui.pyside_gui.dev_tools_payload_logic import default_packet_builder_payload
from TrueCore.ui.pyside_gui.dev_tools_profiles import (
    is_clinical_documentation_profile,
    is_consult_request_profile,
    is_lomn_profile,
    is_referral_request_profile,
    is_seoc_request_profile,
    is_submission_cover_profile,
    is_va_10172_profile,
    is_virtual_consent_profile,
)
from TrueCore.ui.pyside_gui.dev_tools_signature_logic import signature_image_html as _signature_image_html


def _normalize_packet_builder_document_markup(markup):
    replacements = {
        "font-family:Segoe UI; color:#E8F1FC; line-height:1.55;": "font-family:Calibri, Arial, sans-serif; color:#111827; line-height:1.6; font-size:11pt;",
        "font-family:Segoe UI; color:#E8F1FC; line-height:1.5;": "font-family:Calibri, Arial, sans-serif; color:#111827; line-height:1.6; font-size:11pt;",
        "#F2F5F9": "#111827",
        "#E8F1FC": "#111827",
        "#C8D8E8": "#374151",
        "#9BB3CC": "#6B7280",
        "#8FA6C1": "#4B5563",
        "#69BCFF": "#1B4F72",
        "#0F1823": "#FFFFFF",
        "#13202E": "#FBF7E8",
        "#243446": "#D6DCE5",
        "#28415A": "#D6DCE5",
        "#F7E3AA": "#8A6A0A",
    }
    rendered = str(markup or "")
    for source, target in replacements.items():
        rendered = rendered.replace(source, target)
    return re.sub(
        r"(?<![A-Za-z])Pending(?![A-Za-z])",
        "<span style='color:#64748B; font-style:italic; font-weight:600;'>Pending</span>",
        rendered,
    )


def render_packet_builder_document_preview(markup):
    rendered = _normalize_packet_builder_document_markup(markup)
    return (
        "<div style='background:#0D1520; padding:18px 16px;'>"
        "<div style='width:100%; max-width:920px; margin:0 auto; box-sizing:border-box; background:#FFFFFF; border:1px solid #D6DCE5; "
        "box-shadow:0 18px 42px rgba(0,0,0,0.18); padding:32px 34px 38px 34px; overflow-wrap:anywhere; word-break:normal;'>"
        + rendered
        + "</div></div>"
    )


def render_packet_builder_document_export(markup):
    rendered = _normalize_packet_builder_document_markup(markup)
    return (
        "<html><body style='margin:0; background:#FFFFFF;'>"
        "<div style='background:#FFFFFF; padding:18px 22px 24px 22px; color:#111827; overflow-wrap:anywhere; word-break:normal;'>"
        + rendered
        + "</div></body></html>"
    )


def build_packet_builder_sections(payload):
    packet = dict(default_packet_builder_payload())
    packet.update(payload or {})
    return [
        (
            "Packet Identity",
            [
                ("Packet Title", packet.get("packet_title")),
                ("Packet Profile", packet.get("packet_profile")),
            ],
        ),
        (
            "Patient And VA Information",
            [
                ("Patient Name", packet.get("patient_name")),
                ("Date of Birth", packet.get("date_of_birth")),
                ("Authorization Number", packet.get("authorization_number")),
                ("VA ICN", packet.get("va_icn")),
            ],
        ),
        (
            "Clinical Routing",
            [
                ("Ordering Doctor", packet.get("ordering_doctor")),
                ("Provider", packet.get("provider")),
                ("Facility", packet.get("facility")),
                ("Community Facility", packet.get("community_facility")),
                ("Requested Service", packet.get("requested_service")),
            ],
        ),
        (
            "Clinical Support",
            [
                ("Diagnosis", packet.get("diagnosis")),
                ("ICD Codes", packet.get("icd_codes")),
                ("Clinical Summary", packet.get("clinical_summary")),
                ("Packet Notes", packet.get("packet_notes")),
            ],
        ),
    ]


def build_packet_builder_document_markup(payload):
    packet = dict(default_packet_builder_payload())
    packet.update(payload or {})

    if is_referral_request_profile(packet.get("packet_profile")):
        return build_referral_request_preview_html(packet)
    if is_virtual_consent_profile(packet.get("packet_profile")):
        return build_virtual_consent_preview_html(packet)
    if is_submission_cover_profile(packet.get("packet_profile")):
        return build_submission_cover_preview_html(packet)
    if is_seoc_request_profile(packet.get("packet_profile")):
        return build_seoc_request_preview_markup(packet)
    if is_lomn_profile(packet.get("packet_profile")):
        return build_lomn_preview_html(packet)
    if is_consult_request_profile(packet.get("packet_profile")):
        return build_consult_request_preview_html(packet)
    if is_clinical_documentation_profile(packet.get("packet_profile")):
        return build_clinical_documentation_preview_html(packet)
    if is_va_10172_profile(packet.get("packet_profile")):
        return build_va_10172_preview_html(packet)

    title = html.escape(packet.get("packet_title") or "Untitled Packet Draft")
    summary_rows = []
    for section_title, rows in build_packet_builder_sections(packet):
        row_html = []
        for label, value in rows:
            rendered = html.escape(str(value or "Pending").strip() or "Pending")
            row_html.append(
                f"<tr><td style='padding:8px 10px; color:#8FA6C1; width:32%; vertical-align:top;'>{html.escape(label)}</td>"
                f"<td style='padding:8px 10px; color:#E8F1FC;'>{rendered}</td></tr>"
            )
        summary_rows.append(
            f"<div style='margin-top:16px;'>"
            f"<div style='font-size:15px; font-weight:700; color:#69BCFF; margin-bottom:6px;'>{html.escape(section_title)}</div>"
            f"<table style='width:100%; border-collapse:collapse; background:#0F1823; border:1px solid #243446; border-radius:10px; table-layout:fixed;'>"
            + "".join(row_html)
            + "</table></div>"
        )

    return (
        "<div style='font-family:Segoe UI; color:#E8F1FC; line-height:1.5;'>"
        f"<div style='font-size:24px; font-weight:800; color:#F2F5F9;'>{title}</div>"
        f"<div style='font-size:13px; color:#9BB3CC; margin-top:4px;'>Profile: {packet.get('packet_profile') or 'Pending'}</div>"
        "<div style='margin-top:12px; font-size:13px; color:#C8D8E8;'>"
        "This is the developer-side packet-builder preview. It is a clean drafting shell for packet creation and export."
        "</div>"
        + "".join(summary_rows)
        + "</div>"
    )


def build_referral_request_preview_html(packet):
    title = html.escape(packet.get("packet_title") or "Community Care Referral Request")
    subtitle = html.escape(packet.get("referral_subtitle") or "Spine & Pain Evaluation")
    pcp_request = html.escape(packet.get("pcp_request_text") or "Pending")
    referral_entry = html.escape(packet.get("referral_entry_text") or "Pending")
    areas_of_concern = html.escape(packet.get("areas_of_concern") or "Pending")
    group_npi = html.escape(packet.get("group_npi") or "Pending")
    fax_number = html.escape(packet.get("fax_number") or "Pending")
    contact_info = html.escape(packet.get("liaison_contact_info") or "Pending").replace("\n", "<br/>")

    return (
        "<div style='font-family:Calibri, Arial, sans-serif; color:#111827; line-height:1.55;'>"
        f"<div style='text-align:center; font-size:19pt; font-weight:700; letter-spacing:0.2px;'>{title}</div>"
        f"<div style='text-align:center; font-size:12.5pt; font-weight:700; color:#1F3A5F; margin-top:6px;'>{subtitle}</div>"
        "<p style='margin-top:18px;'>"
        "Please provide this request to your VA Primary Care Provider to begin the Community Care referral process. "
        "This document supports specialty spine and pain evaluation."
        "</p>"
        "<div style='margin-top:16px; padding:12px 14px; background:#F7F9FC; border:1px solid #D5DCE5;'>"
        "<div style='font-weight:700;'>Important:</div>"
        "<div style='margin-top:6px;'>This request is for specialty evaluation and consultation. It is not a request for a specific procedure.</div>"
        "</div>"
        "<div style='margin-top:18px; font-size:11pt; font-weight:700; text-transform:uppercase; letter-spacing:0.4px; color:#1F3A5F;'>Instructions for PCP Referral Entry</div>"
        "<ol style='margin-top:10px; padding-left:22px;'>"
        "<li style='margin-bottom:8px;'>Schedule a visit with your VA Primary Care Provider.</li>"
        f"<li style='margin-bottom:8px;'>Ask the provider to enter the referral as: <strong>{referral_entry}</strong>.</li>"
        f"<li style='margin-bottom:8px;'>Use the following request language: &ldquo;{pcp_request}&rdquo;</li>"
        f"<li style='margin-bottom:8px;'>Include all relevant diagnoses and areas of concern: <strong>{areas_of_concern}</strong>.</li>"
        "<li style='margin-bottom:8px;'>Send any relevant imaging and clinical records with the referral.</li>"
        "</ol>"
        "<div style='margin-top:18px; font-size:11pt; font-weight:700; text-transform:uppercase; letter-spacing:0.4px; color:#1F3A5F;'>Routing Information</div>"
        "<table style='width:100%; border-collapse:collapse; table-layout:fixed; margin-top:10px;'>"
        f"<tr><td style='width:28%; padding:8px 10px; border:1px solid #D5DCE5; font-weight:700; vertical-align:top;'>Group NPI</td><td style='padding:8px 10px; border:1px solid #D5DCE5; vertical-align:top;'>{group_npi}</td></tr>"
        f"<tr><td style='padding:8px 10px; border:1px solid #D5DCE5; font-weight:700; vertical-align:top;'>Fax Number</td><td style='padding:8px 10px; border:1px solid #D5DCE5; vertical-align:top;'>{fax_number}</td></tr>"
        "</table>"
        "<div style='margin-top:18px; font-size:11pt; font-weight:700; text-transform:uppercase; letter-spacing:0.4px; color:#1F3A5F;'>Veteran Liaison Contact</div>"
        f"<div style='margin-top:8px;'>{contact_info}</div>"
        "</div>"
    )


def build_seoc_request_preview_markup(packet):
    def filled(value, blank_length):
        raw = str(value or "").strip()
        return html.escape(raw) if raw else "_" * blank_length

    def bullet_lines(items):
        return "".join(f"<div style='margin-top:6px;'>- {html.escape(item)}</div>" for item in items)

    request_date = filled(packet.get("seoc_request_date"), 12)
    va_medical_center_name = filled(packet.get("va_medical_center_name"), 22)
    patient_name = filled(packet.get("patient_name"), 18)
    dob = filled(packet.get("date_of_birth"), 12)
    last_four_ssn = filled(packet.get("last_four_ssn"), 8)
    episode_diagnosis = filled(packet.get("episode_diagnosis"), 44)
    episode_icd_code = str(packet.get("episode_icd_code") or "").strip()
    estimated_duration = filled(packet.get("estimated_duration_text"), 18)
    provider_name = filled(packet.get("provider") or packet.get("ordering_doctor"), 18)
    provider_credentials = filled(packet.get("provider_credentials"), 8)
    provider_specialty = filled(packet.get("provider_specialty"), 18)
    provider_npi = filled(packet.get("provider_npi"), 14)
    practice_name = filled(packet.get("practice_name") or packet.get("community_facility"), 20)
    provider_phone = filled(packet.get("provider_phone"), 14)
    provider_fax = filled(packet.get("provider_fax"), 14)
    provider_header = provider_name
    raw_credentials = str(packet.get("provider_credentials") or "").strip()
    if raw_credentials:
        provider_header += f", {html.escape(raw_credentials)}"
    provider_header = provider_name
    raw_credentials = str(packet.get("provider_credentials") or "").strip()
    if raw_credentials:
        provider_header += f", {html.escape(raw_credentials)}"
    provider_header = provider_name
    raw_credentials = str(packet.get("provider_credentials") or "").strip()
    if raw_credentials:
        provider_header += f", {html.escape(raw_credentials)}"

    scope_items = []
    if packet.get("seoc_include_preprocedure_eval"):
        scope_items.append("Pre-procedure evaluation and procedural planning")
    if packet.get("seoc_include_annulargram"):
        scope_items.append("Diagnostic Annulargram")
    if packet.get("seoc_include_fibrin_injection"):
        scope_items.append("Inter Annular Fibrin Injections if indicated")
    if packet.get("seoc_include_follow_up"):
        scope_items.append("Standard post-procedure follow-up visit(s) within the global postoperative period")
    if not scope_items:
        scope_items.append("________________________________________")

    objective_lines = [line.strip() for line in str(packet.get("clinical_objectives") or "").splitlines() if line.strip()]
    if not objective_lines:
        objective_lines = ["________________________________________"]
    scope_summary = str(packet.get("seoc_scope_text") or "").strip()
    continuity_text = str(packet.get("seoc_continuity_text") or "").strip()

    diagnosis_line = episode_diagnosis
    provider_header = provider_name
    raw_credentials = str(packet.get("provider_credentials") or "").strip()
    if raw_credentials:
        provider_header += f", {html.escape(raw_credentials)}"

    return (
        "<div style='font-family:Calibri, Arial, sans-serif; color:#111827; line-height:1.5;'>"
        f"<div>{request_date}</div>"
        "<div style='margin-top:10px;'>Department of Veterans Affairs<br/>Community Care Office<br/>"
        f"{va_medical_center_name}</div>"
        "<div style='margin-top:16px; font-weight:700;'>RE: Single Episode of Care (SEOC) Request</div>"
        f"<div style='margin-top:4px;'>Veteran Name: {patient_name}</div>"
        f"<div>DOB: {dob}</div>"
        f"<div>Last Four SSN: {last_four_ssn}</div>"
        "<div style='margin-top:12px;'>This request is for authorization of a defined, time-limited Single Episode of Care (SEOC) for the condition identified below.</div>"
        "<div style='margin-top:12px; font-weight:700;'>Episode Diagnosis / Condition</div>"
        f"<div style='margin-top:4px;'>Diagnosis: {diagnosis_line}</div>"
        f"<div>ICD-10 Code: {html.escape(episode_icd_code) if episode_icd_code else '____________'}</div>"
        "<div style='margin-top:12px; font-weight:700;'>Scope of Requested Episode:</div>"
        "<div style='margin-top:4px;'>This SEOC includes only the following services directly related to treatment of the above diagnosis:</div>"
        + bullet_lines(scope_items)
        + f"<div style='margin-top:8px;'>{html.escape(scope_summary) if scope_summary else 'No additional pain management services, long-term medication management, or unrelated spine care are requested under this episode.'}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Estimated Duration of Episode:</div>"
        + f"<div style='margin-top:4px;'>Expected episode duration: {estimated_duration}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Clinical Objective:</div>"
        + bullet_lines(objective_lines)
        + "<div style='margin-top:12px; font-weight:700;'>Continuity of Care:</div>"
        + f"<div style='margin-top:4px;'>{html.escape(continuity_text) if continuity_text else 'Upon completion of the episode, a summary of treatment rendered and clinical outcome will be forwarded to the referring VA provider. Any need for further care beyond this defined episode will require separate evaluation and authorization.'}</div>"
        + "<div style='margin-top:16px;'>Sincerely,</div>"
        + f"<div style='margin-top:10px;'>{provider_header}<br/>{provider_specialty}<br/>NPI Number: {provider_npi}<br/>{practice_name}<br/>{provider_phone}<br/>{provider_fax}</div>"
        + "</div>"
    )


def build_virtual_consent_preview_html(packet):
    title = html.escape(packet.get("packet_title") or packet.get("consent_form_title") or "TELEHEALTH VIRTUAL CONSENT FORM")
    def filled(value, blank_length):
        raw = str(value or "").strip()
        return html.escape(raw) if raw else "_" * blank_length

    def checkbox_row(label, value):
        selected = str(value or "").strip().lower()
        yes_box = "[X]" if selected == "yes" else "[ ]"
        no_box = "[X]" if selected == "no" else "[ ]"
        return (
            f"<div style='margin-top:8px;'><strong>{html.escape(label)}</strong> "
            f"{yes_box} Yes&nbsp;&nbsp;&nbsp;{no_box} No</div>"
        )

    def options_row(label, selected_value, options):
        selected = str(selected_value or "").strip().lower()
        rendered = []
        for option in options:
            marker = "[X]" if selected == option.lower() else "[ ]"
            rendered.append(f"{marker} {html.escape(option)}")
        return (
            f"<div style='margin-top:8px;'><strong>{html.escape(label)}</strong> "
            + "&nbsp;&nbsp;&nbsp;".join(rendered)
            + "</div>"
        )

    def two_line_table(rows, widths):
        colgroup = "".join(f"<col style='width:{width}%'>" for width in widths)
        blocks = []
        for labels, values in rows:
            label_cells = "".join(
                f"<td style='padding:0 16px 3px 0; font-weight:700; vertical-align:bottom;'>{html.escape(label)}</td>"
                for label in labels
            )
            value_cells = "".join(
                f"<td style='padding:0 16px 10px 0; vertical-align:top;'>{value}</td>"
                for value in values
            )
            blocks.append(
                "<table style='width:100%; border-collapse:collapse; table-layout:fixed; margin-top:8px;'>"
                f"<colgroup>{colgroup}</colgroup>"
                f"<tr>{label_cells}</tr><tr>{value_cells}</tr></table>"
            )
        return "".join(blocks)

    telehealth_lines = [
        "I understand that through an interactive video connection, telehealth might be used to perform my consultation and that we may use telehealth to connect while working together.",
        "I understand the benefits and risks involved with telehealth technology:",
        "I do not need to travel to the consultation location.",
        "I have access to a specialist through this consultation.",
        "There may be interruptions, unauthorized access and technical difficulties and my health care provider(s) or myself can discontinue the telemedicine consult/visit if it is felt that the videoconferencing connections are not adequate for the situation.",
        "My healthcare information may be shared with other individuals for scheduling and billing purposes.",
        "I also understand that other individuals may need to use the telehealth platform and that reasonable steps will be taken to maintain confidentiality of the information obtained.",
        "I understand the initial virtual meet and greet discussion is primarily intended to determine any and all treatment I might pursue, in addition to the best approach for scheduling these treatments. The virtual discussion will be followed by individual cost estimates (if applicable).",
        "I have read this document in its entirety and understand the risks and benefits of telehealth consultation/post op visits and have had my questions explained. I hereby consent to participate in telehealth sessions under the conditions described in this document.",
    ]

    patient_name = filled(packet.get("patient_name"), 28)
    dob = filled(packet.get("date_of_birth"), 14)
    mobile_phone = filled(packet.get("mobile_phone") or packet.get("phone"), 14)
    street_address = filled(packet.get("street_address"), 24)
    city = filled(packet.get("city"), 12)
    state = filled(packet.get("state"), 6)
    zip_code = filled(packet.get("zip_code"), 10)
    home_phone = filled(packet.get("home_phone"), 14)
    work_phone = filled(packet.get("work_phone"), 14)
    email_address = filled(packet.get("email_address"), 22)
    ssn = filled(packet.get("ssn"), 14)
    drivers_license = filled(packet.get("drivers_license"), 14)
    drivers_license_state = filled(packet.get("drivers_license_state"), 10)
    yes_explanation = filled(packet.get("yes_response_explanation"), 54)
    attorney_name = filled(packet.get("attorney_name"), 22)
    attorney_phone = filled(packet.get("attorney_phone"), 20)
    emergency_contact_name = filled(packet.get("emergency_contact_name"), 18)
    emergency_contact_relationship = filled(packet.get("emergency_contact_relationship"), 14)
    emergency_contact_phone = filled(packet.get("emergency_contact_phone"), 16)
    primary_insurance_carrier = filled(packet.get("primary_insurance_carrier"), 22)
    primary_insurance_id = filled(packet.get("primary_insurance_id"), 14)
    primary_insurance_phone = filled(packet.get("primary_insurance_phone"), 16)
    secondary_insurance_carrier = filled(packet.get("secondary_insurance_carrier"), 22)
    secondary_insurance_id = filled(packet.get("secondary_insurance_id"), 14)
    secondary_insurance_phone = filled(packet.get("secondary_insurance_phone"), 16)
    pcp_pcm_name = filled(packet.get("pcp_pcm_name"), 22)
    pcp_pcm_phone = filled(packet.get("pcp_pcm_phone"), 14)
    pcp_pcm_fax = filled(packet.get("pcp_pcm_fax"), 14)
    consent_provider_name = filled(packet.get("consent_provider_name"), 18)
    consent_initials = filled(packet.get("consent_initials"), 6)
    minor_doctor_name = filled(packet.get("minor_doctor_name"), 18)
    minor_consent_initials = filled(packet.get("minor_consent_initials"), 6)
    service_authorization_name = filled(packet.get("service_authorization_name"), 18)
    patient_signature_name = filled(packet.get("patient_signature_name") or packet.get("patient_name"), 30)
    patient_signature_image_html = _signature_image_html(packet, "patient_signature_name", width_px=240, height_px=56)
    patient_signature_date = filled(packet.get("patient_signature_date"), 12)

    return (
        "<div style='font-family:Calibri, Arial, sans-serif; color:#111827; line-height:1.45;'>"
        f"<div style='text-align:center; font-size:18pt; font-weight:700;'>{title}</div>"
        "<div style='margin-top:16px; font-weight:700;'>Demographic Information:</div>"
        + two_line_table(
            [
                (
                    ["Full Name (Shown on your Ins Card):", "Date of Birth:", "Phone:"],
                    [patient_name, dob, mobile_phone],
                ),
                (
                    ["Street Address:", "City:", "State:", "Zip:"],
                    [street_address, city, state, zip_code],
                ),
                (
                    ["Home Phone:", "Mobile Phone:", "Work Phone:"],
                    [home_phone, mobile_phone, work_phone],
                ),
                (
                    ["Email Address:", "SSN:", "DL:", "State:"],
                    [email_address, ssn, drivers_license, drivers_license_state],
                ),
            ],
            [42, 18, 20, 20],
        )
        + options_row("Appointment Confirmation Method:", packet.get("appointment_confirmation_method"), ["Phone", "Text", "Email"])
        + checkbox_row("Have you filed for Disability?", packet.get("filed_for_disability"))
        + checkbox_row("Is your condition work related?", packet.get("condition_work_related"))
        + checkbox_row("Is your condition due to an accident?", packet.get("condition_due_to_accident"))
        + "<div style='margin-top:10px; font-weight:700;'>Please explain any responses you answered 'Yes' to:</div>"
        + f"<div style='margin-top:4px;'>{yes_explanation}</div>"
        + checkbox_row("Do you have an Attorney?", packet.get("has_attorney"))
        + two_line_table(
            [
                (
                    ["Attorney Full Name:", "Attorney Phone Number:"],
                    [attorney_name, attorney_phone],
                ),
                (
                    ["Emergency Contact:", "Relationship:", "Phone:"],
                    [emergency_contact_name, emergency_contact_relationship, emergency_contact_phone],
                ),
            ],
            [42, 28, 30],
        )
        + "<div style='margin-top:10px; font-weight:700;'>Insurance Information - If your condition is due to a work injury or other Personal Injury/Accident, there is a separate form you will need to complete. See accident information form.</div>"
        + two_line_table(
            [
                (
                    ["Primary Insurance Carrier:", "ID Number:", "Insurance Phone:"],
                    [primary_insurance_carrier, primary_insurance_id, primary_insurance_phone],
                ),
                (
                    ["Secondary Insurance Carrier:", "ID Number:", "Insurance Phone:"],
                    [secondary_insurance_carrier, secondary_insurance_id, secondary_insurance_phone],
                ),
                (
                    ["PCP/PCM:", "Phone:", "Fax:"],
                    [pcp_pcm_name, pcp_pcm_phone, pcp_pcm_fax],
                ),
            ],
            [44, 22, 34],
        )
        + "<div style='page-break-before:always;'></div>"
        + "<div style='margin-top:8px; font-weight:700;'>CONSENT FOR MEDICAL CARE AND TREATMENT</div>"
        + (
            "<p style='margin-top:10px;'>"
            f"I, {patient_name} hereby agree and give my consent for {consent_provider_name} to furnish medical care and treatment considered necessary and proper in evaluating or treating my physical condition. {consent_initials} (initial)"
            "</p>"
        )
        + "<div style='margin-top:10px; font-weight:700;'>FOR MINORS ONLY CONSENT FOR CARE:</div>"
        + (
            "<p style='margin-top:6px;'>"
            f"As parent and/or legal guardian, I authorize {minor_doctor_name} (Doctors Name) to treat the minor patient named in the attached form while I am not present. {minor_consent_initials} (Parent/Guardian initial)"
            "</p>"
        )
        + "<div style='margin-top:14px; font-weight:700;'>TELEHEALTH CONSENT</div>"
        + "".join(f"<p style='margin-top:8px;'>{html.escape(line)}</p>" for line in telehealth_lines)
        + (
            "<p style='margin-top:12px;'>"
            f"By signing below, I agree that all the above information is correct, and that I authorize {service_authorization_name} to provide me with medical services and to furnish my physician, insurance company or attorney information concerning my injury and/or treatment."
            "</p>"
        )
        + two_line_table(
            [
                (
                    ["Veteran / Patient Signature (Parent/Guardian if applicable):", "Date:"],
                    [patient_signature_image_html or patient_signature_name, patient_signature_date],
                ),
            ],
            [72, 28],
        )
        + "</div>"
    )


def build_submission_cover_preview_html(packet):
    title = html.escape(packet.get("packet_title") or packet.get("submission_cover_title") or "VA Submission Cover Sheet")
    patient_name = html.escape(packet.get("patient_name") or "")
    dob = html.escape(packet.get("date_of_birth") or "")
    facility = html.escape(packet.get("facility") or "")
    ordering_provider = html.escape(packet.get("ordering_doctor") or packet.get("provider") or "")
    submission_date = html.escape(packet.get("submission_date") or "")
    diagnosis_code = html.escape(packet.get("primary_diagnosis_code") or packet.get("icd_codes") or "")
    submitting_office = html.escape(packet.get("submitting_office") or "")
    office_staff_name = html.escape(packet.get("office_staff_name") or "")
    office_staff_signature = html.escape(packet.get("office_staff_signature") or "")
    office_staff_signature_image_html = _signature_image_html(packet, "office_staff_signature", width_px=220, height_px=48)
    date_reviewed = html.escape(packet.get("date_reviewed") or "")

    included_docs = [
        ("Virtual Consent Form completed and signed", bool(packet.get("included_virtual_consent_form"))),
        ("VA Form 10-10172 completed and signed", bool(packet.get("included_va_form_10_10172"))),
        ("SEOC request signed by CCN ordering provider", bool(packet.get("included_seoc_request"))),
        ("Consultation & Treatment Request completed", bool(packet.get("included_consult_request"))),
        ("Letter of Medical Necessity completed", bool(packet.get("included_lomn"))),
        ("Clinical Notes included", bool(packet.get("included_clinical_notes"))),
        ("MRI Report included", bool(packet.get("included_mri_report"))),
    ]

    checklist_html = "".join(
        f"<div style='margin-bottom:6px;'>{'[X]' if checked else '[ ]'} {html.escape(label)}</div>"
        for label, checked in included_docs
    )

    def field_line(label, value, blank_length, raw_html=False):
        display = value if value else "_" * blank_length
        rendered = display if raw_html else html.escape(str(display))
        return (
            "<div style='margin-bottom:10px;'>"
            f"<span style='font-weight:700;'>{html.escape(label)}:</span> "
            f"<span>{rendered}</span>"
            "</div>"
        )

    return (
        "<div style='font-family:Calibri, Arial, sans-serif; color:#111827; line-height:1.5;'>"
        f"<div style='text-align:center; font-size:18pt; font-weight:700;'>{title}</div>"
        + "<div style='margin-top:20px;'>"
        + field_line("Patient Name", patient_name, 24)
        + field_line("DOB", dob, 14)
        + field_line("VA Facility", facility, 28)
        + field_line("Ordering Provider", ordering_provider, 24)
        + field_line("Date of Submission", submission_date, 18)
        + field_line("Primary Diagnosis Code", diagnosis_code, 18)
        + "</div>"
        + "<div style='margin-top:18px; font-weight:700;'>Documents Included (check all):</div>"
        + "<div style='margin-top:10px; padding-left:4px;'>"
        + checklist_html
        + "</div>"
        + "<div style='margin-top:22px;'>"
        + field_line("Submitting Office", submitting_office, 24)
        + field_line("Office Staff Name", office_staff_name, 20)
        + field_line("Program User / Office Staff Signature", office_staff_signature_image_html or office_staff_signature, 20, raw_html=bool(office_staff_signature_image_html))
        + field_line("Date Reviewed", date_reviewed, 18)
        + "</div>"
        + "</div>"
    )


def build_seoc_request_preview_html(packet):
    title = "Single Episode of Care (SEOC) Request"
    request_date = html.escape(packet.get("seoc_request_date") or "Pending")
    va_medical_center_name = html.escape(packet.get("va_medical_center_name") or "Pending")
    patient_name = html.escape(packet.get("patient_name") or "Pending")
    dob = html.escape(packet.get("date_of_birth") or "Pending")
    last_four_ssn = html.escape(packet.get("last_four_ssn") or "Pending")
    episode_diagnosis = html.escape(packet.get("episode_diagnosis") or "Pending")
    episode_icd_code = html.escape(packet.get("episode_icd_code") or "Pending")
    estimated_duration = html.escape(packet.get("estimated_duration_text") or "Pending")
    provider_name = html.escape(packet.get("provider") or packet.get("ordering_doctor") or "Pending")
    provider_credentials = html.escape(packet.get("provider_credentials") or "Pending")
    provider_specialty = html.escape(packet.get("provider_specialty") or "Pending")
    provider_npi = html.escape(packet.get("provider_npi") or "Pending")
    practice_name = html.escape(packet.get("practice_name") or packet.get("community_facility") or "Pending")
    provider_phone = html.escape(packet.get("provider_phone") or "Pending")
    provider_fax = html.escape(packet.get("provider_fax") or "Pending")

    scope_items = []
    if packet.get("seoc_include_preprocedure_eval"):
        scope_items.append("Pre-procedure evaluation and procedural planning")
    if packet.get("seoc_include_annulargram"):
        scope_items.append("Diagnostic Annulargram")
    if packet.get("seoc_include_fibrin_injection"):
        scope_items.append("Inter Annular Fibrin Injections if indicated")
    if packet.get("seoc_include_follow_up"):
        scope_items.append("Standard post-procedure follow-up visit(s) within the global postoperative period")
    if not scope_items:
        scope_items.append("Pending scope items")

    objective_lines = [line.strip() for line in str(packet.get("clinical_objectives") or "").splitlines() if line.strip()]
    if not objective_lines:
        objective_lines = ["Pending clinical objective"]
    scope_summary = str(packet.get("seoc_scope_text") or "").strip()
    continuity_text = str(packet.get("seoc_continuity_text") or "").strip()

    def bullets(items):
        return "".join(
            f"<div style='margin-top:6px; color:#E8F1FC;'>- {html.escape(item)}</div>" for item in items
        )

    return (
        "<div style='font-family:Segoe UI; color:#E8F1FC; line-height:1.55;'>"
        f"<div style='color:#8FA6C1;'>{request_date}</div>"
        "<div style='margin-top:12px; color:#E8F1FC;'>Department of Veterans Affairs<br/>Community Care Office<br/>"
        f"{va_medical_center_name}</div>"
        f"<div style='margin-top:16px; font-size:24px; font-weight:800; color:#F2F5F9;'>{title}</div>"
        "<div style='margin-top:10px; padding:12px 14px; background:#0F1823; border:1px solid #243446; border-radius:10px;'>"
        f"<div><span style='color:#8FA6C1;'>Veteran Name:</span> <span style='color:#E8F1FC;'>{patient_name}</span></div>"
        f"<div style='margin-top:6px;'><span style='color:#8FA6C1;'>DOB:</span> <span style='color:#E8F1FC;'>{dob}</span></div>"
        f"<div style='margin-top:6px;'><span style='color:#8FA6C1;'>Last Four SSN:</span> <span style='color:#E8F1FC;'>{last_four_ssn}</span></div>"
        "</div>"
        "<div style='margin-top:14px; color:#E8F1FC;'>"
        "This request is for authorization of a defined, time-limited Single Episode of Care (SEOC) for treatment of lumbar disc pathology."
        "</div>"
        "<div style='margin-top:14px; font-size:16px; font-weight:800; color:#69BCFF;'>Episode Diagnosis</div>"
        f"<div style='margin-top:6px; color:#E8F1FC;'>{episode_diagnosis}"
        + (f" - {episode_icd_code}" if episode_icd_code else "")
        + "</div>"
        "<div style='margin-top:14px; font-size:16px; font-weight:800; color:#69BCFF;'>Scope of Requested Episode</div>"
        "<div style='margin-top:6px; color:#C8D8E8;'>This SEOC includes only the following services directly related to treatment of the above diagnosis:</div>"
        + bullets(scope_items)
        + f"<div style='color:#C8D8E8;'>{html.escape(scope_summary) if scope_summary else 'No additional pain management services, long-term medication management, or unrelated spine care are requested under this episode.'}</div>"
        + "<div style='margin-top:14px; font-size:16px; font-weight:800; color:#69BCFF;'>Estimated Duration of Episode</div>"
        + f"<div style='margin-top:6px; color:#E8F1FC;'>The episode is expected to begin upon authorization and conclude within approximately {estimated_duration}</div>"
        + "<div style='margin-top:14px; font-size:16px; font-weight:800; color:#69BCFF;'>Clinical Objective</div>"
        + bullets(objective_lines)
        + "<div style='margin-top:14px; font-size:16px; font-weight:800; color:#69BCFF;'>Continuity of Care</div>"
        + f"<div style='margin-top:6px; color:#E8F1FC;'>{html.escape(continuity_text) if continuity_text else 'Upon completion of the episode, a summary of treatment rendered and clinical outcome will be forwarded to the referring VA provider. Any need for further care beyond this defined episode will require separate evaluation and authorization.'}</div>"
        + "<div style='margin-top:10px; color:#E8F1FC;'>This request represents a discrete, procedure-based intervention and meets criteria for authorization under the Single Episode of Care (SEOC) framework.</div>"
        + "<div style='margin-top:18px; color:#E8F1FC;'>Sincerely,</div>"
        + f"<div style='margin-top:12px; color:#E8F1FC;'><strong>{provider_name}</strong>{', ' + provider_credentials if provider_credentials and provider_credentials != 'Pending' else ''}<br/>"
        + f"{provider_specialty}<br/>NPI: {provider_npi}<br/>{practice_name}<br/>{provider_phone}<br/>{provider_fax}</div>"
        + "</div>"
    )


def build_lomn_preview_html(packet):
    def filled(value, blank_length):
        raw = str(value or "").strip()
        return html.escape(raw) if raw else "_" * blank_length

    def block_text(value, blank_length=48):
        raw = str(value or "").strip()
        return html.escape(raw).replace("\n", "<br/>") if raw else "_" * blank_length

    def bullet_lines(items):
        return "".join(f"<div style='margin-top:6px;'>- {html.escape(item)}</div>" for item in items)

    title = html.escape(packet.get("packet_title") or "LETTER OF MEDICAL NECESSITY")
    request_date = filled(packet.get("lmn_request_date"), 12)
    va_medical_center_name = filled(packet.get("va_medical_center_name"), 22)
    facility = filled(packet.get("facility"), 20)
    patient_name = filled(packet.get("patient_name"), 18)
    dob = filled(packet.get("date_of_birth"), 12)
    last_four_ssn = filled(packet.get("last_four_ssn"), 8)
    claim_number = filled(packet.get("lmn_va_claim_number"), 14)
    primary_diagnosis = filled(packet.get("lmn_primary_diagnosis"), 30)
    secondary_diagnosis = filled(packet.get("lmn_secondary_diagnosis"), 30)
    clinical_summary = block_text(packet.get("lmn_clinical_summary"))
    mri_date = filled(packet.get("lmn_mri_date"), 12)
    mri_findings = filled(packet.get("lmn_mri_findings"), 28)
    conservative_duration = filled(packet.get("lmn_conservative_duration"), 14)
    medical_necessity_statement = block_text(packet.get("lmn_medical_necessity_statement"))
    risk_statement = block_text(packet.get("lmn_risk_statement"))
    reasonable_statement = block_text(packet.get("lmn_reasonable_necessary_statement"))
    contact_statement = block_text(packet.get("lmn_contact_statement"))
    provider_name = filled(packet.get("provider") or packet.get("ordering_doctor"), 18)
    provider_credentials = filled(packet.get("provider_credentials"), 8)
    provider_specialty = filled(packet.get("provider_specialty"), 18)
    provider_npi = filled(packet.get("provider_npi"), 14)
    practice_name = filled(packet.get("practice_name") or packet.get("community_facility"), 20)
    provider_phone = filled(packet.get("provider_phone"), 14)
    provider_fax = filled(packet.get("provider_fax"), 14)
    provider_header = provider_name
    raw_credentials = str(packet.get("provider_credentials") or "").strip()
    if raw_credentials:
        provider_header += f", {html.escape(raw_credentials)}"

    conservative_items = []
    if packet.get("lmn_include_physical_therapy"):
        conservative_items.append("Structured physical therapy")
    if packet.get("lmn_include_nsaids"):
        conservative_items.append("NSAIDs and non-opioid analgesics")
    if packet.get("lmn_include_activity_modification"):
        conservative_items.append("Activity modification")
    if packet.get("lmn_include_home_exercise"):
        conservative_items.append("Home exercise program")
    if packet.get("lmn_include_epidural_steroid_injections"):
        conservative_items.append("Epidural Steroid injections (if applicable)")
    if not conservative_items:
        conservative_items.append("________________________________________")

    indication_items = []
    if packet.get("lmn_indication_reduce_pain"):
        indication_items.append("Reduce pain severity")
    if packet.get("lmn_indication_improve_function"):
        indication_items.append("Improve functional capacity")
    if packet.get("lmn_indication_prevent_degeneration"):
        indication_items.append("Prevent further disc degeneration")
    if packet.get("lmn_indication_reduce_opioid_reliance"):
        indication_items.append("Decrease reliance on long-term opioid therapy")
    if packet.get("lmn_indication_prevent_surgery"):
        indication_items.append("Potentially prevent need for more invasive surgical intervention")
    if not indication_items:
        indication_items.append("________________________________________")

    return (
        "<div style='font-family:Calibri, Arial, sans-serif; color:#111827; line-height:1.5;'>"
        f"<div style='text-align:center; font-size:18pt; font-weight:700;'>{title}</div>"
        "<div style='text-align:center; margin-top:2px;'>(Pain Management - Interventional Spine)</div>"
        f"<div style='margin-top:12px;'>{request_date}</div>"
        "<div style='margin-top:8px;'>Department of Veterans Affairs<br/>Community Care Office<br/>"
        f"{va_medical_center_name}<br/>{facility}</div>"
        "<div style='margin-top:12px; font-weight:700;'>RE: Letter of Medical Necessity</div>"
        f"<div>Veteran Name: {patient_name}</div>"
        f"<div>DOB: {dob}</div>"
        f"<div>Last Four SSN: {last_four_ssn}</div>"
        f"<div>VA Claim Number: {claim_number}</div>"
        + "<div style='margin-top:10px;'>To Whom It May Concern:</div>"
        + "<div style='margin-top:6px;'>I am writing to formally document the medical necessity of interventional spine treatment for the above-named Veteran.</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Clinical Diagnoses</div>"
        + f"<div style='margin-top:4px;'>Primary: {primary_diagnosis}</div>"
        + f"<div>Secondary: {secondary_diagnosis}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Clinical Basis</div>"
        + f"<div style='margin-top:4px;'>{clinical_summary}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Imaging Support</div>"
        + f"<div style='margin-top:4px;'>MRI Date: {mri_date}</div>"
        + f"<div>MRI Findings: {mri_findings}</div>"
        + "<div style='margin-top:8px;'>The Veteran has completed extensive conservative management, including:</div>"
        + bullet_lines(conservative_items)
        + f"<div style='margin-top:8px;'>Despite appropriate and guideline-based conservative treatment for greater than {conservative_duration}, the Veteran continues to experience persistent pain and functional limitation.</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Basis for Medical Necessity</div>"
        + f"<div style='margin-top:4px;'>{medical_necessity_statement}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Requested Treatment Objectives</div>"
        + "<div style='margin-top:4px;'>This intervention is indicated to:</div>"
        + bullet_lines(indication_items)
        + "<div style='margin-top:12px; font-weight:700;'>Risk if Treatment Is Delayed or Denied</div>"
        + f"<div style='margin-top:4px;'>{risk_statement}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Reasonable and Necessary Determination</div>"
        + f"<div style='margin-top:4px;'>{reasonable_statement}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Provider Contact Statement</div>"
        + f"<div style='margin-top:4px;'>{contact_statement}</div>"
        + "<div style='margin-top:16px;'>Sincerely,</div>"
        + f"<div style='margin-top:10px;'>{provider_header}<br/>{provider_specialty}<br/>NPI Number: {provider_npi}<br/>{practice_name}<br/>{provider_phone}<br/>{provider_fax}</div>"
        + "</div>"
    )


def build_consult_request_preview_html(packet):
    def filled(value, blank_length):
        raw = str(value or "").strip()
        return html.escape(raw) if raw else "_" * blank_length

    def block_text(value, blank_length=48):
        raw = str(value or "").strip()
        return html.escape(raw).replace("\n", "<br/>") if raw else "_" * blank_length

    def bullet_lines(items):
        return "".join(f"<div style='margin-top:6px;'>- {html.escape(item)}</div>" for item in items)

    title = html.escape(packet.get("packet_title") or "CONSULTATION AND TREATMENT REQUEST")
    request_date = filled(packet.get("consult_request_date"), 12)
    va_medical_center_name = filled(packet.get("va_medical_center_name"), 22)
    facility = filled(packet.get("facility"), 20)
    patient_name = filled(packet.get("patient_name"), 18)
    dob = filled(packet.get("date_of_birth"), 12)
    last_four_ssn = filled(packet.get("last_four_ssn"), 8)
    claim_number = filled(packet.get("consult_va_claim_number"), 14)
    referring_provider = filled(packet.get("consult_referring_va_provider"), 18)
    reason_text = block_text(packet.get("consult_reason_text"))
    primary_diagnosis = filled(packet.get("consult_primary_diagnosis"), 30)
    secondary_diagnosis = filled(packet.get("consult_secondary_diagnosis"), 30)
    mri_date = filled(packet.get("consult_mri_date"), 12)
    mri_findings = filled(packet.get("consult_mri_findings"), 28)
    conservative_duration = filled(packet.get("consult_conservative_duration"), 14)
    scope_exclusion_text = block_text(packet.get("consult_scope_exclusion_text"))
    medical_rationale_text = block_text(packet.get("consult_medical_rationale_text"))
    risk_without_treatment = block_text(packet.get("consult_risk_without_treatment"))
    duration_scope_text = block_text(packet.get("consult_duration_scope_text"))
    consult_contact_statement = block_text(packet.get("consult_contact_statement"))
    provider_name = filled(packet.get("provider") or packet.get("ordering_doctor"), 18)
    provider_credentials = filled(packet.get("provider_credentials"), 8)
    provider_specialty = filled(packet.get("provider_specialty"), 18)
    provider_npi = filled(packet.get("provider_npi"), 14)
    practice_name = filled(packet.get("practice_name") or packet.get("community_facility"), 20)
    provider_address = filled(packet.get("provider_address"), 22)
    provider_phone = filled(packet.get("provider_phone"), 14)
    provider_fax = filled(packet.get("provider_fax"), 14)
    provider_email = filled(packet.get("provider_email"), 20)
    provider_header = provider_name
    raw_credentials = str(packet.get("provider_credentials") or "").strip()
    if raw_credentials:
        provider_header += f", {html.escape(raw_credentials)}"

    symptom_items = []
    if packet.get("consult_symptom_axial_pain"):
        symptom_items.append("Chronic axial lumbar pain")
    if packet.get("consult_symptom_activity_exacerbation"):
        symptom_items.append("Activity-related exacerbation (sitting, standing, bending)")
    if packet.get("consult_symptom_reduced_tolerance"):
        symptom_items.append("Reduced tolerance for prolonged positioning")
    if packet.get("consult_symptom_functional_impairment"):
        symptom_items.append("Functional impairment affecting occupational and daily activities")
    if not symptom_items:
        symptom_items.append("________________________________________")

    conservative_items = []
    if packet.get("consult_include_physical_therapy"):
        conservative_items.append("Physical therapy")
    if packet.get("consult_include_nsaids"):
        conservative_items.append("NSAIDs and non-opioid analgesics")
    if packet.get("consult_include_activity_modification"):
        conservative_items.append("Activity modification")
    if packet.get("consult_include_home_exercise"):
        conservative_items.append("Home exercise program")
    if packet.get("consult_include_interventional_history"):
        conservative_items.append("Epidural steroid injections and/or other interventional procedures (if applicable)")
    if not conservative_items:
        conservative_items.append("________________________________________")

    service_items = []
    if packet.get("consult_include_pain_management_consultation"):
        service_items.append("Comprehensive pain management consultation")
    if packet.get("consult_include_procedural_planning"):
        service_items.append("Diagnostic confirmation and procedural planning")
    if packet.get("consult_include_annulargram"):
        service_items.append("Diagnostic Annulargram")
    if packet.get("consult_include_fibrin_injection"):
        fibrin_line = "Intraannular Fibrin injection"
        if str(packet.get("consult_fibrin_levels") or "").strip():
            fibrin_line += f" at {packet.get('consult_fibrin_levels').strip()}"
        fibrin_line += " if indicated"
        service_items.append(fibrin_line)
    if packet.get("consult_include_follow_up"):
        service_items.append("Routine post-procedure follow-up visit(s)")
    if not service_items:
        service_items.append("________________________________________")

    goal_items = []
    if packet.get("consult_goal_pain_reduction"):
        goal_items.append("Pain reduction")
    if packet.get("consult_goal_functional_improvement"):
        goal_items.append("Functional improvement")
    if packet.get("consult_goal_reduce_analgesics"):
        goal_items.append("Decreased reliance on chronic analgesic therapy")
    if packet.get("consult_goal_prevent_surgery"):
        goal_items.append("Prevention of progression requiring more invasive surgical intervention")
    if not goal_items:
        goal_items.append("________________________________________")

    return (
        "<div style='font-family:Calibri, Arial, sans-serif; color:#111827; line-height:1.5;'>"
        f"<div style='text-align:center; font-size:18pt; font-weight:700;'>{title}</div>"
        "<div style='text-align:center; margin-top:2px;'>(Pain Management - Interventional Spine)</div>"
        f"<div style='margin-top:12px;'>{request_date}</div>"
        "<div style='margin-top:8px;'>Department of Veterans Affairs<br/>Community Care Office<br/>"
        f"{va_medical_center_name}<br/>{facility}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>RE: Consultation and Treatment Request</div>"
        + f"<div>Veteran Name: {patient_name}</div>"
        + f"<div>DOB: {dob}</div>"
        + f"<div>Last Four SSN: {last_four_ssn}</div>"
        + f"<div>VA Claim Number: {claim_number}</div>"
        + f"<div>Referring VA Provider: {referring_provider}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Reason for Consultation</div>"
        + f"<div style='margin-top:4px;'>{reason_text}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Diagnoses</div>"
        + f"<div style='margin-top:4px;'>Primary: {primary_diagnosis}</div>"
        + f"<div>Secondary: {secondary_diagnosis}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Clinical Summary</div>"
        + "<div style='margin-top:4px;'>Symptoms and functional concerns documented for this consultation include:</div>"
        + bullet_lines(symptom_items)
        + "<div style='margin-top:12px; font-weight:700;'>Imaging Review</div>"
        + f"<div style='margin-top:4px;'>MRI Date: {mri_date}</div>"
        + f"<div>MRI Findings: {mri_findings}</div>"
        + "<div style='margin-top:4px;'>These findings are reviewed alongside the reported symptoms and prior treatment history.</div>"
        + "<div style='margin-top:8px;'>Conservative management has included:</div>"
        + bullet_lines(conservative_items)
        + f"<div style='margin-top:8px;'>Despite appropriate treatment for greater than {conservative_duration}, the Veteran continues to experience persistent pain and impaired function.</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Requested Services</div>"
        + "<div style='margin-top:4px;'>Authorization is requested for:</div>"
        + bullet_lines(service_items)
        + "<div style='margin-top:12px; font-weight:700;'>Scope of Request</div>"
        + f"<div style='margin-top:4px;'>{scope_exclusion_text}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Medical Rationale</div>"
        + f"<div style='margin-top:4px;'>{medical_rationale_text}</div>"
        + "<div style='margin-top:8px;'>Clinical goals include:</div>"
        + bullet_lines(goal_items)
        + "<div style='margin-top:12px; font-weight:700;'>Risk Without Requested Treatment</div>"
        + f"<div style='margin-top:4px;'>{risk_without_treatment}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Duration and Scope of Care</div>"
        + f"<div style='margin-top:4px;'>{duration_scope_text}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Provider Contact Statement</div>"
        + f"<div style='margin-top:4px;'>{consult_contact_statement}</div>"
        + "<div style='margin-top:16px;'>Sincerely,</div>"
        + f"<div style='margin-top:10px;'>{provider_header}<br/>{provider_specialty}<br/>NPI Number: {provider_npi}<br/>{practice_name}<br/>{provider_address}<br/>{provider_phone}<br/>{provider_fax}<br/>{provider_email}</div>"
        + "</div>"
    )


def build_clinical_documentation_preview_html(packet):
    def filled(value, blank_length):
        raw = str(value or "").strip()
        return html.escape(raw) if raw else "_" * blank_length

    def block_text(value, blank_length=40):
        raw = str(value or "").strip()
        return html.escape(raw).replace("\n", "<br/>") if raw else "_" * blank_length

    def checkbox_items(items):
        rendered = []
        for enabled, label in items:
            marker = "[X]" if enabled else "[ ]"
            rendered.append(f"<div style='margin-top:4px; padding-left:12px;'>{marker} {html.escape(label)}</div>")
        return "".join(rendered)

    title = html.escape(packet.get("packet_title") or packet.get("clinical_doc_title") or "Clinical Documentation Template")
    chief_complaint = filled(packet.get("clinical_doc_chief_complaint"), 24)
    exact_duration = filled(packet.get("clinical_doc_exact_duration"), 20)
    pain_severity = filled(packet.get("clinical_doc_pain_severity"), 6)
    functional_impact = block_text(packet.get("clinical_doc_functional_impact"), 28)
    conservative_duration = filled(packet.get("clinical_doc_conservative_duration"), 18)
    imaging_date = filled(packet.get("clinical_doc_mri_date"), 18)
    affected_levels = filled(packet.get("clinical_doc_affected_levels"), 20)
    primary_diagnosis = filled(packet.get("clinical_doc_primary_diagnosis"), 26)
    secondary_diagnosis = filled(packet.get("clinical_doc_secondary_diagnosis"), 26)
    assessment_summary = block_text(packet.get("clinical_doc_assessment_summary"))
    treatment_plan_intro = block_text(packet.get("clinical_doc_treatment_plan_intro"))
    plan_exclusion = block_text(packet.get("clinical_doc_plan_exclusion"))
    physician_narrative = block_text(packet.get("clinical_doc_physician_narrative"))

    duration_items = [
        (packet.get("clinical_doc_duration_gt_3m"), "> 3 months"),
        (packet.get("clinical_doc_duration_gt_6m"), "> 6 months"),
        (packet.get("clinical_doc_duration_gt_12m"), "> 12 months"),
    ]
    pain_items = [
        (packet.get("clinical_doc_pain_axial"), "Axial lumbar pain"),
        (packet.get("clinical_doc_pain_discogenic"), "Discogenic pattern"),
        (packet.get("clinical_doc_pain_activity_exacerbation"), "Activity-related exacerbation"),
        (packet.get("clinical_doc_pain_sitting_intolerance"), "Sitting intolerance"),
        (packet.get("clinical_doc_pain_standing_intolerance"), "Standing intolerance"),
        (packet.get("clinical_doc_pain_bending_lifting"), "Bending/lifting provocation"),
    ]
    limitation_items = [
        (packet.get("clinical_doc_limit_occupational"), "Occupational duties"),
        (packet.get("clinical_doc_limit_prolonged_sitting"), "Prolonged sitting"),
        (packet.get("clinical_doc_limit_prolonged_standing"), "Prolonged standing"),
        (packet.get("clinical_doc_limit_ambulation"), "Ambulation tolerance"),
        (packet.get("clinical_doc_limit_household"), "Household activities"),
        (packet.get("clinical_doc_limit_sleep"), "Sleep disturbance"),
    ]
    conservative_items = [
        (packet.get("clinical_doc_conservative_pt"), "Physical therapy"),
        (packet.get("clinical_doc_conservative_home_exercise"), "Home exercise program"),
        (packet.get("clinical_doc_conservative_nsaids"), "NSAIDs"),
        (packet.get("clinical_doc_conservative_non_opioid"), "Non-opioid analgesics"),
        (packet.get("clinical_doc_conservative_activity_modification"), "Activity modification"),
        (packet.get("clinical_doc_conservative_esi"), "Epidural steroid injections"),
        (packet.get("clinical_doc_conservative_other_interventional"), "Other interventional procedures"),
    ]
    imaging_items = [
        (packet.get("clinical_doc_imaging_annular_tear"), "Annular tear"),
        (packet.get("clinical_doc_imaging_disc_degeneration"), "Disc degeneration"),
        (packet.get("clinical_doc_imaging_disc_protrusion"), "Disc protrusion"),
        (packet.get("clinical_doc_imaging_disc_displacement"), "Disc displacement"),
    ]
    plan_items = [
        (packet.get("clinical_doc_plan_diagnostic_confirmation"), "Diagnostic confirmation if necessary"),
        (packet.get("clinical_doc_plan_intradiscal_intervention"), "Intradiscal annular intervention if indicated"),
        (packet.get("clinical_doc_plan_follow_up"), "Standard post-procedure follow-up"),
    ]

    return (
        "<div style='font-family:Calibri, Arial, sans-serif; color:#111827; line-height:1.45;'>"
        f"<div style='text-align:center; font-size:18pt; font-weight:700;'>{title}</div>"
        + "<div style='margin-top:14px; font-weight:700;'>I. Chief Complaint</div>"
        + f"<div style='margin-top:4px;'>{chief_complaint}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>II. History of Present Illness</div>"
        + "<div style='margin-top:4px;'>Duration of Symptoms:</div>"
        + checkbox_items(duration_items)
        + f"<div style='margin-top:6px;'>Exact duration: {exact_duration}</div>"
        + "<div style='margin-top:8px;'>Pain Characteristics:</div>"
        + checkbox_items(pain_items)
        + f"<div style='margin-top:8px;'>Pain severity (0-10): {pain_severity}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>III. Functional Impairment</div>"
        + "<div style='margin-top:4px;'>Patient reports limitation in:</div>"
        + checkbox_items(limitation_items)
        + f"<div style='margin-top:8px;'>Describe specific functional impact: {functional_impact}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>IV. Conservative Therapy History</div>"
        + "<div style='margin-top:4px;'>The patient has completed and/or attempted:</div>"
        + checkbox_items(conservative_items)
        + f"<div style='margin-top:8px;'>Duration of conservative treatment: {conservative_duration}</div>"
        + f"<div style='margin-top:8px;'>Response to prior ESI (if applicable): {filled(packet.get('clinical_doc_esi_response'), 18)}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>V. Imaging Findings</div>"
        + f"<div style='margin-top:4px;'>MRI Date: {imaging_date}</div>"
        + "<div style='margin-top:4px;'>Findings:</div>"
        + checkbox_items(imaging_items)
        + f"<div style='margin-top:8px;'>Affected Levels: {affected_levels}</div>"
        + "<div style='margin-top:4px;'>Imaging correlates with clinical presentation.</div>"
        + "<div style='margin-top:12px; font-weight:700;'>VI. Assessment</div>"
        + f"<div style='margin-top:4px;'>Primary Diagnosis / ICD-10: {primary_diagnosis}</div>"
        + f"<div>Secondary Diagnosis / ICD-10: {secondary_diagnosis}</div>"
        + f"<div style='margin-top:6px;'>{assessment_summary}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>VII. Treatment Plan</div>"
        + f"<div style='margin-top:4px;'>{treatment_plan_intro}</div>"
        + "<div style='margin-top:6px;'>Plan includes:</div>"
        + checkbox_items([(enabled, label) for enabled, label in plan_items if enabled] or [(False, "________________________________________")])
        + f"<div style='margin-top:6px;'>{plan_exclusion}</div>"
        + "<div style='margin-top:12px; font-weight:700;'>Physician Narrative Paragraph</div>"
        + f"<div style='margin-top:6px;'>{physician_narrative}</div>"
        + "</div>"
    )


def build_va_10172_preview_html(packet, template_path=""):
    if not template_path:
        template_path = packet.get("va10172_template_path") or ""
    title = html.escape(packet.get("packet_title") or "VA Form 10-10172")
    patient_name = html.escape(packet.get("patient_name") or "Pending")
    dob = html.escape(packet.get("date_of_birth") or "Pending")
    auth = html.escape(packet.get("authorization_number") or "Pending")
    va_facility_address = html.escape(packet.get("va10172_va_facility_address") or "Pending").replace("\n", "<br/>")
    provider_office_address = html.escape(packet.get("va10172_ordering_provider_office_address") or "Pending").replace("\n", "<br/>")
    provider_phone = html.escape(packet.get("va10172_ordering_provider_phone") or "Pending")
    provider_fax = html.escape(packet.get("va10172_ordering_provider_fax") or "Pending")
    provider_email = html.escape(packet.get("va10172_ordering_provider_secure_email") or "Pending")
    specialty = html.escape(packet.get("va10172_referral_specialty_text") or "Pending")
    icd_codes = html.escape(packet.get("icd_codes") or "Pending")
    diagnosis_description = html.escape(packet.get("va10172_diagnosis_description") or packet.get("diagnosis") or "Pending")
    requested_cpt = html.escape(packet.get("va10172_requested_cpt_hcpcs_code") or "Pending")
    cpt_description = html.escape(packet.get("va10172_description_cpt_hcpcs_code") or "Pending")
    reason_for_request = html.escape(packet.get("va10172_reason_for_request") or "Pending").replace("\n", "<br/>")
    provider_name_printed = html.escape(packet.get("va10172_ordering_provider_name_printed") or packet.get("provider") or packet.get("ordering_doctor") or "Pending")
    provider_npi = html.escape(packet.get("va10172_ordering_provider_npi") or packet.get("provider_npi") or "Pending")
    today_date = html.escape(packet.get("va10172_today_date") or "Pending")
    template_label = html.escape(template_path or "No template selected")

    def kv(label, value):
        return f"<div style='margin-top:6px;'><span style='color:#8FA6C1;'>{html.escape(label)}:</span> <span style='color:#E8F1FC;'>{value}</span></div>"

    return (
        "<div style='font-family:Segoe UI; color:#E8F1FC; line-height:1.55;'>"
        f"<div style='font-size:24px; font-weight:800; color:#F2F5F9;'>{title}</div>"
        "<div style='margin-top:6px; color:#69BCFF; font-weight:700;'>Actual VA PDF Export Profile</div>"
        "<div style='margin-top:10px; color:#C8D8E8;'>"
        "This profile exports onto the real VA Form 10-10172 template. PDF export fills the actual form page rather than producing a visual clone."
        "</div>"
        + f"<div style='margin-top:10px; color:#8FA6C1;'>Template PDF: {template_label}</div>"
        + "<div style='margin-top:16px; padding:12px 14px; background:#0F1823; border:1px solid #243446; border-radius:10px;'>"
        + kv("Veteran Legal Full Name", patient_name)
        + kv("Date of Birth", dob)
        + kv("VA Authorization Number", auth)
        + kv("VA Facility & Address", va_facility_address)
        + kv("Ordering Provider Office Name & Address", provider_office_address)
        + kv("Ordering Provider Phone", provider_phone)
        + kv("Ordering Provider Fax", provider_fax)
        + kv("Ordering Provider Secure Email", provider_email)
        + kv("Care Needed Within 48 Hours", html.escape(packet.get("va10172_care_needed_within_48_hours") or "Pending"))
        + kv("Continuation of Care", html.escape(packet.get("va10172_is_continuation_of_care") or "Pending"))
        + kv("Referral to Another Specialty", html.escape(packet.get("va10172_referral_to_specialty") or "Pending"))
        + kv("Specialty", specialty)
        + kv("Diagnosis Codes", icd_codes)
        + kv("Diagnosis Description", diagnosis_description)
        + kv("Requested CPT/HCPCS Code", requested_cpt)
        + kv("Description CPT/HCPCS Code", cpt_description)
        + kv("Reason for Request", reason_for_request)
        + kv("CCN Ordering Provider Name (Printed)", provider_name_printed)
        + kv("CCN Ordering Provider NPI", provider_npi)
        + kv("Today's Date", today_date)
        + "</div>"
        + "<div style='margin-top:12px; color:#C8D8E8;'>"
        "Note: the CCN ordering provider signature field can be staged with a typed placeholder or drawn signature for drafting, but formal signing requirements may still need office review."
        "</div>"
        + "</div>"
    )
