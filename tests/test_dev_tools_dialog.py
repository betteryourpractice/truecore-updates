import os
import tempfile
import unittest
from unittest import mock

from docx import Document

from TrueCore.ui.pyside_gui import dev_tools_dialog


class DevToolsDialogTests(unittest.TestCase):
    def _export_doc_text(self, writer_name, payload):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "sample.docx")
            getattr(dev_tools_dialog.PacketBuilderTab, writer_name)(object(), output_path, payload)
            document = Document(output_path)
            return "\n".join(paragraph.text for paragraph in document.paragraphs)

    def test_packet_export_context_matches_referral_and_patient_packet_groups(self):
        self.assertEqual(
            dev_tools_dialog.get_packet_export_group("Community Care Referral Request"),
            "referral_request",
        )
        self.assertEqual(
            dev_tools_dialog.get_packet_export_group("Submission Cover Sheet"),
            "patient_packet",
        )
        self.assertEqual(
            dev_tools_dialog.get_patient_packet_position("VA Form 10-10172"),
            3,
        )
        self.assertIn(
            "item 3 of 7",
            dev_tools_dialog.describe_packet_export_context("VA Form 10-10172"),
        )

    def test_bundle_export_plan_keeps_referral_request_separate(self):
        plan = dev_tools_dialog.build_bundle_export_plan("Jacob Talbott Packet", "referral_request", "Both")

        self.assertEqual(plan["folder_name"], "Jacob_Talbott_Packet_referral_request")
        self.assertEqual(
            [item["filename"] for item in plan["documents"]],
            [
                "Community_Care_Referral_Request.docx",
                "Community_Care_Referral_Request.pdf",
            ],
        )

    def test_compiled_packet_filename_uses_clean_patient_packet_name(self):
        self.assertEqual(
            dev_tools_dialog.compiled_packet_filename("Jacob Talbott Packet", "patient_packet"),
            "Jacob_Talbott_Packet_patient_packet.pdf",
        )

    def test_discover_legacy_reference_entries_from_folder_finds_launcher_and_gui_previews(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            launcher_dir = os.path.join(temp_dir, "launcher")
            gui_dir = os.path.join(temp_dir, "ui", "pyside_gui")
            assets_dir = os.path.join(gui_dir, "assets")
            os.makedirs(launcher_dir, exist_ok=True)
            os.makedirs(assets_dir, exist_ok=True)
            for path in [
                os.path.join(launcher_dir, "launcher_window.py"),
                os.path.join(gui_dir, "main_window.py"),
                os.path.join(assets_dir, "launcher_background.png"),
                os.path.join(assets_dir, "truecore_logo.png"),
            ]:
                with open(path, "wb") as handle:
                    handle.write(b"legacy")

            entries = dev_tools_dialog.discover_legacy_reference_entries(temp_dir)

        kinds = [entry["kind"] for entry in entries]
        self.assertIn("launcher_preview", kinds)
        self.assertIn("gui_preview", kinds)

    def test_discover_legacy_reference_entries_for_image_file_returns_image_entry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            image_path = os.path.join(temp_dir, "legacy_gui.png")
            with open(image_path, "wb") as handle:
                handle.write(b"image")
            entries = dev_tools_dialog.discover_legacy_reference_entries(image_path)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["kind"], "image")

    def test_bundle_export_plan_keeps_patient_packet_in_order(self):
        plan = dev_tools_dialog.build_bundle_export_plan("Jacob Talbott Packet", "patient_packet", "PDF")

        self.assertEqual(plan["folder_name"], "Jacob_Talbott_Packet_patient_packet")
        self.assertEqual(
            [item["filename"] for item in plan["documents"]],
            [
                "01_VA_Submission_Cover_Sheet.pdf",
                "02_TELEHEALTH_VIRTUAL_CONSENT_FORM.pdf",
                "03_VA_Form_10-10172.pdf",
                "04_Single_Episode_of_Care_SEOC_Request.pdf",
                "05_CONSULTATION_AND_TREATMENT_REQUEST.pdf",
                "06_LETTER_OF_MEDICAL_NECESSITY.pdf",
                "07_Clinical_Documentation_Template.pdf",
            ],
        )

    def test_patient_packet_word_bundle_still_includes_real_va_form_pdf(self):
        plan = dev_tools_dialog.build_bundle_export_plan("Jacob Talbott Packet", "patient_packet", "Word")
        filenames = [item["filename"] for item in plan["documents"]]

        self.assertIn("01_VA_Submission_Cover_Sheet.docx", filenames)
        self.assertNotIn("01_VA_Submission_Cover_Sheet.pdf", filenames)
        self.assertIn("03_VA_Form_10-10172.docx", filenames)
        self.assertIn("03_VA_Form_10-10172.pdf", filenames)

    def test_build_profile_export_payload_resets_packet_title_for_target_profile(self):
        payload = dev_tools_dialog.build_profile_export_payload(
            {
                "packet_profile": "Community Care Referral Request",
                "packet_title": "Community Care Referral Request",
                "patient_name": "Jacob Talbott",
            },
            "Submission Cover Sheet",
        )

        self.assertEqual(payload["packet_profile"], "Submission Cover Sheet")
        self.assertEqual(payload["packet_title"], "VA Submission Cover Sheet")
        self.assertEqual(payload["patient_name"], "Jacob Talbott")

    def test_build_profile_export_payload_applies_shared_header_sync(self):
        payload = dev_tools_dialog.build_profile_export_payload(
            {
                "packet_profile": "Submission Cover Sheet",
                "patient_name": "Jacob Talbott",
                "date_of_birth": "04/03/1992",
                "authorization_number": "VA0051513368",
                "icd_codes": "M51.36, M51.26, M54.50",
                "ordering_doctor": "William Durrett",
                "facility": "Charlie Norwood VA Medical Center",
                "diagnosis": "Lumbar Disc Degeneration",
                "secondary_diagnosis": "Lumbar Radiculopathy",
                "master_provider_npi": "1234567890",
                "master_practice_name": "Aiken Neurosciences and Pain Management",
                "master_provider_phone": "555-123-4567",
                "master_provider_fax": "555-987-6543",
                "master_provider_email": "secure@example.com",
                "master_provider_address": "123 Main St\nAiken, SC 29801",
                "master_mri_date": "05/01/2026",
                "master_mri_findings": "Annular tear at L4-L5",
                "master_affected_levels": "L4-L5, L5-S1",
                "master_requested_cpt_code": "62287",
                "ssn": "***-**-6789",
            },
            "Letter of Medical Necessity Template",
        )

        self.assertEqual(payload["lmn_va_claim_number"], "VA0051513368")
        self.assertEqual(payload["consult_va_claim_number"], "VA0051513368")
        self.assertEqual(payload["episode_icd_code"], "M51.36")
        self.assertEqual(payload["primary_diagnosis_code"], "M51.36")
        self.assertEqual(payload["va_medical_center_name"], "Charlie Norwood VA Medical Center")
        self.assertEqual(payload["va10172_ordering_provider_name_printed"], "William Durrett")
        self.assertEqual(payload["va10172_diagnosis_description"], "Lumbar Disc Degeneration")
        self.assertEqual(payload["lmn_secondary_diagnosis"], "Lumbar Radiculopathy")
        self.assertEqual(payload["consult_secondary_diagnosis"], "Lumbar Radiculopathy")
        self.assertEqual(payload["provider_npi"], "1234567890")
        self.assertEqual(payload["va10172_ordering_provider_npi"], "1234567890")
        self.assertEqual(payload["practice_name"], "Aiken Neurosciences and Pain Management")
        self.assertEqual(payload["provider_phone"], "555-123-4567")
        self.assertEqual(payload["provider_fax"], "555-987-6543")
        self.assertEqual(payload["provider_email"], "secure@example.com")
        self.assertEqual(payload["provider_address"], "123 Main St\nAiken, SC 29801")
        self.assertEqual(payload["lmn_mri_date"], "05/01/2026")
        self.assertEqual(payload["consult_mri_findings"], "Annular tear at L4-L5")
        self.assertEqual(payload["clinical_doc_affected_levels"], "L4-L5, L5-S1")
        self.assertEqual(payload["va10172_requested_cpt_hcpcs_code"], "62287")
        self.assertEqual(payload["last_four_ssn"], "6789")

    def test_normalize_packet_builder_payload_replaces_legacy_true_disc_text(self):
        payload = dev_tools_dialog.normalize_packet_builder_payload(
            {
                "clinical_doc_treatment_plan_intro": "The patient is an appropriate candidate for TrueDisc intradiscal biologic repair under a Single Episode of Care (SEOC) model.",
            }
        )

        self.assertNotIn("TrueDisc", payload["clinical_doc_treatment_plan_intro"])
        self.assertIn("focused spine evaluation", payload["clinical_doc_treatment_plan_intro"])

    def test_normalize_packet_builder_payload_sanitizes_common_text_artifacts(self):
        payload = dev_tools_dialog.normalize_packet_builder_payload(
            {
                "consult_medical_rationale_text": "The patient's care pathway â€™ should be clean \ufb03 text.",
            }
        )

        self.assertIn("patient's", payload["consult_medical_rationale_text"])
        self.assertIn("ffi", payload["consult_medical_rationale_text"])

    def test_packet_library_completion_summarizes_patient_packet_progress(self):
        completion = dev_tools_dialog.build_packet_library_completion(
            {
                "packet_profile": "Submission Cover Sheet",
                "patient_name": "Jacob Talbott",
                "date_of_birth": "04/03/1992",
                "authorization_number": "VA0051513368",
                "va_icn": "1041529679V678591",
                "ordering_doctor": "William Durrett",
                "facility": "Charlie Norwood VA Medical Center",
                "diagnosis": "Lumbar Disc Degeneration",
                "icd_codes": "M51.36, M54.50",
                "included_virtual_consent_form": True,
                "included_va_form_10_10172": True,
                "included_seoc_request": True,
                "included_consult_request": True,
                "included_lomn": True,
                "included_clinical_notes": True,
                "included_mri_report": True,
            }
        )

        self.assertEqual(completion["group_name"], "patient_packet")
        self.assertGreater(completion["completion_score"], 0)
        self.assertIn(completion["status_key"], {"in_progress", "complete"})

    def test_packet_library_production_metrics_uses_prod_style_score_and_readiness(self):
        metrics = dev_tools_dialog.build_packet_library_production_metrics(
            {
                "packet_profile": "Submission Cover Sheet",
                "patient_name": "Jacob Talbott",
                "date_of_birth": "04/03/1992",
                "authorization_number": "VA0051513368",
                "va_icn": "1041529679V678591",
                "ordering_doctor": "William Durrett",
                "facility": "Charlie Norwood VA Medical Center",
                "diagnosis": "Lumbar Disc Degeneration",
                "icd_codes": "M51.36, M54.50",
                "requested_service": "Specialty spine evaluation",
                "clinical_summary": "Persistent lumbar pain despite conservative treatment.",
                "included_virtual_consent_form": True,
                "included_va_form_10_10172": True,
                "included_seoc_request": True,
                "included_consult_request": True,
                "included_lomn": True,
                "included_clinical_notes": True,
                "included_mri_report": True,
            }
        )

        self.assertIsInstance(metrics["score"], float)
        self.assertIn(metrics["readiness"], {"ready", "requires_review", "hold"})
        self.assertIn(metrics["strength"], {"strong", "moderate", "weak"})
        self.assertIn("completion", metrics)

    def test_packet_library_record_roundtrip_uses_library_storage(self):
        record = {
            "draft_id": "talbott_packet",
            "display_name": "Jacob Talbott",
            "base_filename": "Jacob_Talbott_Packet",
            "packet_profile": "Submission Cover Sheet",
            "saved_at": "2026-05-30T10:15:00",
            "updated_at": "2026-05-30T10:15:00",
            "artifacts": {"single_doc_pdf": r"C:\\Exports\\Jacob_Talbott_Packet.pdf"},
            "payload": {"patient_name": "Jacob Talbott", "packet_profile": "Submission Cover Sheet"},
        }
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(dev_tools_dialog, "PACKET_LIBRARY_DIR", temp_dir):
            dev_tools_dialog.save_packet_library_record(record)
            records = dev_tools_dialog.list_packet_library_records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["display_name"], "Jacob Talbott")
            self.assertTrue(records[0]["path"].endswith("talbott_packet.json"))
            dev_tools_dialog.delete_packet_library_record("talbott_packet")
            self.assertEqual(dev_tools_dialog.list_packet_library_records(), [])

    def test_packet_lab_html_flags_missing_shared_header_fields(self):
        html = dev_tools_dialog.build_packet_lab_html(
            {
                "packet_profile": "Virtual Consent Form",
                "packet_title": "TELEHEALTH VIRTUAL CONSENT FORM",
                "patient_name": "",
                "date_of_birth": "",
                "authorization_number": "",
                "va_icn": "",
                "diagnosis": "",
                "icd_codes": "",
            }
        )

        self.assertIn("Needs Shared Packet Header Details", html)
        self.assertIn("Shared Packet Header", html)
        self.assertIn("Veteran Name", html)
        self.assertIn("VA Authorization", html)

    def test_classify_packet_lab_completion_marks_not_started(self):
        status_key, status_label = dev_tools_dialog.classify_packet_lab_completion(
            {
                "current_form_checks": [("Request Date", False), ("Diagnosis", False)],
                "current_complete": 0,
                "current_missing": ["Request Date", "Diagnosis"],
                "shared_missing": [],
            }
        )

        self.assertEqual(status_key, "not_started")
        self.assertEqual(status_label, "Not Started")

    def test_classify_packet_lab_completion_marks_in_progress(self):
        status_key, status_label = dev_tools_dialog.classify_packet_lab_completion(
            {
                "current_form_checks": [("Request Date", True), ("Diagnosis", False)],
                "current_complete": 1,
                "current_missing": ["Diagnosis"],
                "shared_missing": [],
            }
        )

        self.assertEqual(status_key, "in_progress")
        self.assertEqual(status_label, "In Progress")

    def test_classify_packet_lab_completion_marks_complete(self):
        status_key, status_label = dev_tools_dialog.classify_packet_lab_completion(
            {
                "current_form_checks": [("Request Date", True), ("Diagnosis", True)],
                "current_complete": 2,
                "current_missing": [],
                "shared_missing": [],
                "inconsistency_messages": [],
            }
        )

        self.assertEqual(status_key, "complete")
        self.assertEqual(status_label, "Complete")

    def test_classify_packet_lab_completion_keeps_inconsistent_form_in_progress(self):
        status_key, status_label = dev_tools_dialog.classify_packet_lab_completion(
            {
                "current_form_checks": [("Request Date", True), ("Diagnosis", True)],
                "current_complete": 2,
                "current_missing": [],
                "shared_missing": [],
                "inconsistency_messages": ["Primary diagnosis is inconsistent."],
            }
        )

        self.assertEqual(status_key, "in_progress")
        self.assertEqual(status_label, "In Progress")

    def test_sanitize_builder_filename_keeps_safe_shape(self):
        self.assertEqual(
            dev_tools_dialog.sanitize_builder_filename(" Jacob Talbott Packet #1 "),
            "Jacob_Talbott_Packet_1",
        )

    def test_preview_html_contains_key_packet_fields(self):
        html = dev_tools_dialog.build_packet_builder_preview_html(
            {
                "packet_title": "Talbott Packet Draft",
                "patient_name": "Jacob Talbott",
                "authorization_number": "VA0051513368",
                "packet_profile": "VA Full Submission",
            }
        )

        self.assertIn("Talbott Packet Draft", html)
        self.assertIn("Jacob Talbott", html)
        self.assertIn("VA0051513368", html)
        self.assertIn("VA Full Submission", html)

    def test_export_html_uses_document_surface_not_preview_shell(self):
        html = dev_tools_dialog.build_packet_builder_export_html(
            {
                "packet_profile": "Submission Cover Sheet",
                "packet_title": "VA Submission Cover Sheet",
                "patient_name": "Jacob Talbott",
            }
        )

        self.assertNotIn("background:#0D1520", html)
        self.assertIn("background:#FFFFFF", html)
        self.assertIn("VA Submission Cover Sheet", html)

    def test_referral_request_preview_contains_referral_specific_fields(self):
        html = dev_tools_dialog.build_packet_builder_preview_html(
            {
                "packet_profile": "Community Care Referral Request",
                "packet_title": "Community Care Referral Request",
                "referral_subtitle": "Spine & Pain Evaluation",
                "group_npi": "1234567890",
                "fax_number": "555-123-4567",
                "liaison_contact_info": "Veteran Liaison Team | 555-111-2222",
            }
        )

        self.assertIn("Community Care Referral Request", html)
        self.assertIn("Spine &amp; Pain Evaluation", html)
        self.assertIn("1234567890", html)
        self.assertIn("555-123-4567", html)
        self.assertIn("Veteran Liaison Team", html)

    def test_preview_html_flags_inconsistent_repeated_values(self):
        html = dev_tools_dialog.build_packet_builder_preview_html(
            {
                "packet_profile": "Letter of Medical Necessity Template",
                "packet_title": "LETTER OF MEDICAL NECESSITY",
                "diagnosis": "Lumbar Disc Degeneration",
                "lmn_primary_diagnosis": "Cervical Radiculopathy",
                "authorization_number": "VA12345",
                "lmn_va_claim_number": "VA12345",
            }
        )

        self.assertIn("Consistency Warning", html)
        self.assertIn("Primary diagnosis is inconsistent", html)

    def test_wording_assist_entry_requires_supporting_facts_before_suggestion(self):
        entries = dev_tools_dialog.build_wording_assist_entries(
            {
                "packet_profile": "Consultation & Treatment Request Template",
                "consult_reason_text": "Need consult for back pain.",
            }
        )

        reason_entry = next(entry for entry in entries if entry["key"] == "consult_reason")
        self.assertEqual(reason_entry["status_key"], "needs_facts")
        self.assertIn("Primary diagnosis", reason_entry["missing_facts"])
        self.assertIn("Requested service", reason_entry["missing_facts"])

    def test_wording_export_blockers_require_review_for_started_packet(self):
        payload = {
            "packet_profile": "VA Form 10-10172",
            "patient_name": "Jacob Talbott",
            "date_of_birth": "04/03/1992",
            "authorization_number": "VA0051513368",
            "ordering_doctor": "William Durrett",
            "facility": "Charlie Norwood VA Medical Center",
            "diagnosis": "Lumbar disc degeneration",
            "icd_codes": "M51.36",
            "requested_service": "specialty spine evaluation and indicated interventional treatment planning",
            "master_mri_findings": "annular tear at L4-L5",
            "clinical_summary": "Persistent function-limiting lumbar pain despite conservative management.",
        }

        blockers = dev_tools_dialog.build_wording_export_blockers(payload)
        self.assertTrue(blockers)
        self.assertIn("Reason for Request", blockers[0])

    def test_wording_export_blockers_clear_after_review_state_matches_current_text(self):
        base_payload = {
            "packet_profile": "VA Form 10-10172",
            "patient_name": "Jacob Talbott",
            "date_of_birth": "04/03/1992",
            "authorization_number": "VA0051513368",
            "ordering_doctor": "William Durrett",
            "facility": "Charlie Norwood VA Medical Center",
            "diagnosis": "Lumbar disc degeneration",
            "icd_codes": "M51.36",
            "requested_service": "specialty spine evaluation and indicated interventional treatment planning",
            "master_mri_findings": "annular tear at L4-L5",
            "clinical_summary": "Persistent function-limiting lumbar pain despite conservative management.",
        }
        suggested = dev_tools_dialog.build_wording_assist_entries(base_payload)[0]["suggestion_text"]
        payload = dict(base_payload)
        payload["va10172_reason_for_request"] = suggested
        current_entry = dev_tools_dialog.build_wording_assist_entries(payload)[0]
        payload["wording_assist_state"] = {
            "va_reason_for_request": {
                "decision": "accepted",
                "approved_text": suggested,
                "source_fingerprint": current_entry["source_fingerprint"],
            }
        }

        self.assertEqual(dev_tools_dialog.build_wording_export_blockers(payload), [])

    def test_wording_assist_suggestions_are_profile_specific_and_deterministic(self):
        consult_payload = {
            "packet_profile": "Consultation & Treatment Request Template",
            "diagnosis": "Lumbar degenerative disc disease",
            "icd_codes": "M51.36",
            "requested_service": "specialty pain management/interventional spine evaluation, diagnostic confirmation, and procedural planning",
            "master_mri_date": "05/30/2026",
            "master_mri_findings": "disc degeneration with annular/disc pathology at L4-L5",
            "clinical_summary": "The Veteran has chronic, function-limiting lumbar pain with a discogenic pattern.",
            "clinical_doc_functional_impact": "sleep, household activity, and occupational duties",
            "clinical_doc_physical_therapy": True,
            "clinical_doc_home_exercise": True,
            "clinical_doc_activity_modification": True,
        }
        consult_entries_a = dev_tools_dialog.build_wording_assist_entries(dict(consult_payload))
        consult_entries_b = dev_tools_dialog.build_wording_assist_entries(dict(consult_payload))
        consult_reason_a = next(entry for entry in consult_entries_a if entry["key"] == "consult_reason")["suggestion_text"]
        consult_reason_b = next(entry for entry in consult_entries_b if entry["key"] == "consult_reason")["suggestion_text"]

        self.assertEqual(consult_reason_a, consult_reason_b)
        self.assertTrue("requested" in consult_reason_a.lower())

        va_payload = dict(consult_payload)
        va_payload["packet_profile"] = "VA Form 10-10172"
        va_entries = dev_tools_dialog.build_wording_assist_entries(va_payload)
        va_reason = next(entry for entry in va_entries if entry["key"] == "va_reason_for_request")["suggestion_text"]

        self.assertNotEqual(consult_reason_a, va_reason)

    def test_clinical_narrative_suggestion_includes_fact_bound_closeout_language(self):
        payload = {
            "packet_profile": "Clinical Documentation Template",
            "diagnosis": "Lumbar degenerative disc disease",
            "icd_codes": "M51.36",
            "requested_service": "interventional spine evaluation with diagnostic confirmation",
            "master_mri_date": "05/30/2026",
            "master_mri_findings": "disc degeneration with annular/disc pathology at L4-L5",
            "clinical_summary": "The Veteran has chronic, function-limiting lumbar pain with a discogenic pattern.",
            "clinical_doc_functional_impact": "sleep, household activity, and occupational duties",
            "clinical_doc_physical_therapy": True,
            "clinical_doc_home_exercise": True,
            "clinical_doc_activity_modification": True,
        }

        entry = next(
            item
            for item in dev_tools_dialog.build_wording_assist_entries(payload)
            if item["key"] == "clinical_physician_narrative"
        )

        self.assertIn("medically", entry["suggestion_text"].lower())
        self.assertIn("interventional spine evaluation with diagnostic confirmation", entry["suggestion_text"])

    def test_wording_assist_cycle_index_changes_suggestion_variant(self):
        payload = {
            "packet_profile": "Consultation & Treatment Request Template",
            "diagnosis": "Lumbar degenerative disc disease",
            "icd_codes": "M51.36",
            "requested_service": "specialty pain management/interventional spine evaluation, diagnostic confirmation, and procedural planning",
            "master_mri_date": "05/30/2026",
            "master_mri_findings": "disc degeneration with annular/disc pathology at L4-L5",
            "clinical_summary": "Persistent lumbar pain with a discogenic pattern.",
            "clinical_doc_functional_impact": "sleep, household activity, and occupational duties",
            "clinical_doc_physical_therapy": True,
            "clinical_doc_home_exercise": True,
            "clinical_doc_activity_modification": True,
        }

        suggestion_a = next(
            entry for entry in dev_tools_dialog.build_wording_assist_entries(payload)
            if entry["key"] == "consult_reason"
        )["suggestion_text"]
        payload["wording_assist_state"] = {"consult_reason": {"cycle_index": 1}}
        suggestion_b = next(
            entry for entry in dev_tools_dialog.build_wording_assist_entries(payload)
            if entry["key"] == "consult_reason"
        )["suggestion_text"]

        self.assertNotEqual(suggestion_a, suggestion_b)

    def test_wording_assist_exposes_matched_scenario_blueprint(self):
        payload = {
            "packet_profile": "Consultation & Treatment Request Template",
            "diagnosis": "Lumbar disc degeneration",
            "icd_codes": "M51.36",
            "requested_service": "diagnostic annulargram and interventional spine treatment planning",
            "master_mri_date": "05/30/2026",
            "master_mri_findings": "annular tear with discogenic pathology at L4-L5",
            "clinical_summary": "Persistent discogenic lumbar pain despite conservative care.",
            "clinical_doc_functional_impact": "sleep and daily activity tolerance",
            "clinical_doc_conservative_pt": True,
            "clinical_doc_conservative_home_exercise": True,
            "clinical_doc_conservative_activity_modification": True,
        }

        entry = next(
            entry for entry in dev_tools_dialog.build_wording_assist_entries(payload)
            if entry["key"] == "consult_reason"
        )

        self.assertTrue(entry["scenario_label"])
        self.assertTrue(entry["scenario_use_when"])
        self.assertIn("discogenic", entry["suggestion_text"].lower())

    def test_wording_assist_cycle_can_change_matched_blueprint_family(self):
        payload = {
            "packet_profile": "VA Form 10-10172",
            "diagnosis": "Lumbar degenerative disc disease",
            "icd_codes": "M51.36",
            "requested_service": "specialty interventional spine evaluation and treatment planning",
            "master_mri_date": "05/30/2026",
            "master_mri_findings": "annular tear with disc protrusion at L4-L5 and L5-S1",
            "clinical_summary": "Persistent lumbar pain with functional limitation despite conservative management.",
            "clinical_doc_functional_impact": "sleep, walking, and occupational duties",
            "clinical_doc_conservative_pt": True,
            "clinical_doc_conservative_home_exercise": True,
            "clinical_doc_conservative_nsaids": True,
            "clinical_doc_conservative_esi": True,
            "clinical_doc_duration_gt_6m": True,
            "clinical_doc_affected_levels": "L4-L5, L5-S1",
        }

        entry_a = next(
            entry for entry in dev_tools_dialog.build_wording_assist_entries(payload)
            if entry["key"] == "va_reason_for_request"
        )
        payload["wording_assist_state"] = {"va_reason_for_request": {"cycle_index": 1}}
        entry_b = next(
            entry for entry in dev_tools_dialog.build_wording_assist_entries(payload)
            if entry["key"] == "va_reason_for_request"
        )

        self.assertNotEqual(entry_a["suggestion_text"], entry_b["suggestion_text"])
        self.assertNotEqual(entry_a["scenario_label"], entry_b["scenario_label"])

    def test_functional_impact_sentence_strips_duplicate_lead_in(self):
        payload = {
            "clinical_doc_functional_impact": "Current symptoms continue to limit The Veteran's ability to sleep, move, and sit for prolonged intervals."
        }
        sentence = dev_tools_dialog._functional_impact_sentence(payload)

        self.assertIn("sleep, move, and sit", sentence)
        self.assertNotIn("Current symptoms continue to limit The Veteran's ability to", sentence)

    def test_seoc_preview_uses_custom_scope_and_continuity_language(self):
        html = dev_tools_dialog.build_packet_builder_preview_html(
            {
                "packet_profile": "Single Episode of Care Request Template",
                "packet_title": "Single Episode of Care (SEOC) Request",
                "seoc_scope_text": "This SEOC is limited to the requested intervention and routine follow-up for the documented condition.",
                "seoc_continuity_text": "A treatment summary will be sent back to the referring VA provider once the authorized episode is complete.",
            }
        )

        self.assertIn("This SEOC is limited to the requested intervention", html)
        self.assertIn("A treatment summary will be sent back to the referring VA provider", html)

    def test_packet_lab_report_includes_wording_review_checks(self):
        report = dev_tools_dialog.build_packet_lab_report(
            {
                "packet_profile": "VA Form 10-10172",
                "patient_name": "Jacob Talbott",
                "date_of_birth": "04/03/1992",
                "authorization_number": "VA0051513368",
                "ordering_doctor": "William Durrett",
                "facility": "Charlie Norwood VA Medical Center",
                "diagnosis": "Lumbar disc degeneration",
                "icd_codes": "M51.36",
                "requested_service": "specialty spine evaluation and indicated interventional treatment planning",
                "master_mri_findings": "annular tear at L4-L5",
                "clinical_summary": "Persistent function-limiting lumbar pain despite conservative management.",
            }
        )

        self.assertTrue(any(label.startswith("Wording Review:") for label, _ in report["current_form_checks"]))

    def test_seoc_profile_report_can_reach_complete(self):
        payload = {
            "packet_profile": "Single Episode of Care Request Template",
            "packet_title": "Single Episode of Care (SEOC) Request",
            "patient_name": "Jacob Talbott",
            "date_of_birth": "04/03/1992",
            "authorization_number": "VA0051513368",
            "va_icn": "1041529679V678591",
            "ordering_doctor": "William Durrett",
            "facility": "Charlie Norwood VA Medical Center",
            "diagnosis": "Lumbar Disc Degeneration",
            "icd_codes": "M51.36, M54.50",
            "master_provider_npi": "1234567890",
            "master_practice_name": "Aiken Neurosciences and Pain Management",
            "seoc_request_date": "05/31/2026",
            "va_medical_center_name": "Charlie Norwood VA Medical Center",
            "ssn": "***-**-6789",
            "last_four_ssn": "6789",
            "episode_diagnosis": "Lumbar Disc Degeneration",
            "episode_icd_code": "M51.36",
            "seoc_scope_text": "This SEOC is limited to evaluation, procedural planning, the indicated intervention if clinically appropriate, and standard post-procedure follow-up related only to the documented condition.",
            "estimated_duration_text": "30 to 90 days",
            "clinical_objectives": "Reduce pain\nImprove function",
            "seoc_continuity_text": "Upon completion of the authorized episode, a treatment summary and clinical outcome update will be provided to the referring VA provider. Any additional or unrelated care will require separate evaluation and authorization.",
            "provider_credentials": "MD",
            "provider_specialty": "Interventional Spine",
            "provider_npi": "1234567890",
            "practice_name": "Aiken Neurosciences and Pain Management",
            "provider_phone": "555-123-4567",
            "provider_fax": "555-987-6543",
            "seoc_include_preprocedure_eval": True,
        }
        wording_state = {}
        for entry in dev_tools_dialog.build_wording_assist_entries(payload):
            approved_text = entry["suggestion_text"] or entry["raw_text"]
            payload[entry["field_name"]] = approved_text
        for entry in dev_tools_dialog.build_wording_assist_entries(payload):
            wording_state[entry["key"]] = {
                "decision": "accepted",
                "approved_text": entry["suggestion_text"] or entry["raw_text"],
                "source_fingerprint": entry["source_fingerprint"],
            }
        payload["wording_assist_state"] = wording_state
        report = dev_tools_dialog.build_packet_lab_report(payload)

        status_key, status_label = dev_tools_dialog.classify_packet_lab_completion(report)
        self.assertEqual(status_key, "complete")
        self.assertEqual(status_label, "Complete")

    def test_virtual_consent_preview_contains_consent_specific_fields(self):
        html = dev_tools_dialog.build_packet_builder_preview_html(
            {
                "packet_profile": "Virtual Consent Form",
                "packet_title": "TELEHEALTH VIRTUAL CONSENT FORM",
                "patient_name": "Jacob Talbott",
                "appointment_confirmation_method": "Text",
                "consent_provider_name": "Aiken Neurosciences and Pain Management",
                "service_authorization_name": "TrueDisc",
                "patient_signature_date": "05/29/2026",
            }
        )

        self.assertIn("TELEHEALTH VIRTUAL CONSENT FORM", html)
        self.assertIn("Jacob Talbott", html)
        self.assertIn("Text", html)
        self.assertIn("Aiken Neurosciences and Pain Management", html)
        self.assertIn("TrueDisc", html)
        self.assertIn("05/29/2026", html)

    def test_submission_cover_preview_contains_document_checklist(self):
        html = dev_tools_dialog.build_packet_builder_preview_html(
            {
                "packet_profile": "Submission Cover Sheet",
                "packet_title": "VA Submission Cover Sheet",
                "patient_name": "Jacob Talbott",
                "included_virtual_consent_form": True,
                "included_mri_report": False,
                "office_staff_name": "A. Smith",
            }
        )

        self.assertIn("VA Submission Cover Sheet", html)
        self.assertIn("Jacob Talbott", html)
        self.assertIn("[X] Virtual Consent Form completed and signed", html)
        self.assertIn("[ ] MRI Report included", html)
        self.assertIn("A. Smith", html)

    def test_seoc_request_preview_contains_request_specific_fields(self):
        html = dev_tools_dialog.build_packet_builder_preview_html(
            {
                "packet_profile": "Single Episode of Care Request Template",
                "packet_title": "Single Episode of Care (SEOC) Request",
                "seoc_request_date": "05/29/2026",
                "va_medical_center_name": "Charlie Norwood VA Medical Center",
                "patient_name": "Jacob Talbott",
                "last_four_ssn": "6789",
                "episode_diagnosis": "Lumbar Disc Degeneration / Annular Tear / Discogenic Pain",
                "episode_icd_code": "M51.36",
                "provider": "William Durrett",
                "provider_credentials": "MD",
                "practice_name": "Aiken Neurosciences and Pain Management",
            }
        )

        self.assertIn("Single Episode of Care (SEOC) Request", html)
        self.assertIn("Charlie Norwood VA Medical Center", html)
        self.assertIn("Jacob Talbott", html)
        self.assertIn("6789", html)
        self.assertIn("M51.36", html)
        self.assertIn("William Durrett", html)
        self.assertIn("Aiken Neurosciences and Pain Management", html)

    def test_lomn_preview_contains_medical_necessity_fields(self):
        html = dev_tools_dialog.build_packet_builder_preview_html(
            {
                "packet_profile": "Letter of Medical Necessity Template",
                "packet_title": "LETTER OF MEDICAL NECESSITY",
                "lmn_request_date": "05/29/2026",
                "va_medical_center_name": "Charlie Norwood VA Medical Center",
                "patient_name": "Jacob Talbott",
                "last_four_ssn": "6789",
                "lmn_primary_diagnosis": "Lumbar Disc Degeneration (M51.36)",
                "lmn_mri_findings": "annular tear at L4-L5",
                "lmn_conservative_duration": "6 months",
                "provider": "William Durrett",
                "provider_credentials": "MD",
            }
        )

        self.assertIn("LETTER OF MEDICAL NECESSITY", html)
        self.assertIn("Charlie Norwood VA Medical Center", html)
        self.assertIn("Jacob Talbott", html)
        self.assertIn("Lumbar Disc Degeneration (M51.36)", html)
        self.assertIn("annular tear at L4-L5", html)
        self.assertIn("6 months", html)
        self.assertIn("William Durrett", html)

    def test_consult_request_preview_contains_request_and_service_fields(self):
        html = dev_tools_dialog.build_packet_builder_preview_html(
            {
                "packet_profile": "Consultation & Treatment Request Template",
                "packet_title": "CONSULTATION AND TREATMENT REQUEST",
                "consult_request_date": "05/29/2026",
                "va_medical_center_name": "Charlie Norwood VA Medical Center",
                "patient_name": "Jacob Talbott",
                "consult_referring_va_provider": "Dr. Smith",
                "consult_primary_diagnosis": "Lumbar Disc Degeneration (M51.36)",
                "consult_mri_findings": "disc protrusion at L5-S1",
                "consult_fibrin_levels": "L4-L5",
                "provider": "William Durrett",
            }
        )

        self.assertIn("CONSULTATION AND TREATMENT REQUEST", html)
        self.assertIn("Charlie Norwood VA Medical Center", html)
        self.assertIn("Jacob Talbott", html)
        self.assertIn("Dr. Smith", html)
        self.assertIn("Lumbar Disc Degeneration (M51.36)", html)
        self.assertIn("disc protrusion at L5-S1", html)
        self.assertIn("L4-L5", html)
        self.assertIn("William Durrett", html)

    def test_clinical_documentation_preview_contains_emr_sections(self):
        html = dev_tools_dialog.build_packet_builder_preview_html(
            {
                "packet_profile": "Clinical Notes Template",
                "packet_title": "Clinical Documentation Template",
                "clinical_doc_chief_complaint": "Chronic low back pain.",
                "clinical_doc_exact_duration": "14 months",
                "clinical_doc_pain_severity": "8",
                "clinical_doc_functional_impact": "Cannot tolerate prolonged sitting at work.",
                "clinical_doc_mri_date": "05/01/2026",
                "clinical_doc_affected_levels": "L4-L5, L5-S1",
                "clinical_doc_primary_diagnosis": "Lumbar Disc Degeneration (M51.36)",
            }
        )

        self.assertIn("Clinical Documentation Template", html)
        self.assertIn("Chronic low back pain.", html)
        self.assertIn("14 months", html)
        self.assertIn("Cannot tolerate prolonged sitting at work.", html)
        self.assertIn("05/01/2026", html)
        self.assertIn("L4-L5, L5-S1", html)
        self.assertIn("Lumbar Disc Degeneration (M51.36)", html)
        self.assertIn("Physician Narrative Paragraph", html)

    def test_seoc_request_doc_v2_contains_template_sections(self):
        text = self._export_doc_text(
            "_write_seoc_request_doc_v2",
            {
                "seoc_request_date": "05/29/2026",
                "va_medical_center_name": "Charlie Norwood VA Medical Center",
                "patient_name": "Jacob Talbott",
                "date_of_birth": "04/03/1992",
                "last_four_ssn": "6789",
                "episode_diagnosis": "Lumbar Disc Degeneration / Annular Tear / Discogenic Pain",
                "episode_icd_code": "M51.36",
                "seoc_include_preprocedure_eval": True,
                "seoc_include_annulargram": True,
                "estimated_duration_text": "30-90 days",
                "clinical_objectives": "Reduction in discogenic pain\nImproved spinal function",
                "provider": "William Durrett",
                "provider_credentials": "MD",
                "provider_specialty": "Interventional Spine",
                "provider_npi": "1234567890",
                "practice_name": "Aiken Neurosciences and Pain Management",
            },
        )

        self.assertIn("RE: Single Episode of Care (SEOC) Request", text)
        self.assertIn("Charlie Norwood VA Medical Center", text)
        self.assertIn("M51.36", text)
        self.assertIn("Episode Diagnosis / Condition:", text)
        self.assertIn("Scope of Requested Episode:", text)
        self.assertIn("Estimated Duration of Episode:", text)
        self.assertIn("William Durrett, MD", text)
        self.assertNotIn("treatment of lumbar disc pathology", text)

    def test_lomn_doc_v2_contains_template_sections(self):
        text = self._export_doc_text(
            "_write_lomn_doc_v2",
            {
                "packet_title": "LETTER OF MEDICAL NECESSITY",
                "lmn_request_date": "05/29/2026",
                "va_medical_center_name": "Charlie Norwood VA Medical Center",
                "patient_name": "Jacob Talbott",
                "date_of_birth": "04/03/1992",
                "last_four_ssn": "6789",
                "lmn_va_claim_number": "VA123456",
                "lmn_primary_diagnosis": "Lumbar Disc Degeneration (M51.36)",
                "lmn_mri_findings": "annular tear at L4-L5",
                "lmn_include_physical_therapy": True,
                "lmn_indication_reduce_pain": True,
                "provider": "William Durrett",
                "provider_credentials": "MD",
                "practice_name": "Aiken Neurosciences and Pain Management",
            },
        )

        self.assertIn("LETTER OF MEDICAL NECESSITY", text)
        self.assertIn("VA Claim Number: VA123456", text)
        self.assertIn("Clinical Basis:", text)
        self.assertIn("Basis for Medical Necessity:", text)
        self.assertIn("William Durrett, MD", text)
        self.assertNotIn("MRI dated", text)

    def test_consult_request_doc_v2_contains_template_sections(self):
        text = self._export_doc_text(
            "_write_consult_request_doc_v2",
            {
                "packet_title": "CONSULTATION AND TREATMENT REQUEST",
                "consult_request_date": "05/29/2026",
                "va_medical_center_name": "Charlie Norwood VA Medical Center",
                "patient_name": "Jacob Talbott",
                "date_of_birth": "04/03/1992",
                "last_four_ssn": "6789",
                "consult_va_claim_number": "VA123456",
                "consult_referring_va_provider": "Dr. Smith",
                "consult_primary_diagnosis": "Lumbar Disc Degeneration (M51.36)",
                "consult_reason_text": "Evaluation and treatment of chronic lumbar spine pain.",
                "consult_include_fibrin_injection": True,
                "consult_fibrin_levels": "L4-L5",
                "consult_goal_pain_reduction": True,
                "provider": "William Durrett",
                "provider_credentials": "MD",
                "practice_name": "Aiken Neurosciences and Pain Management",
                "provider_address": "123 Main St",
                "provider_email": "office@example.com",
            },
        )

        self.assertIn("CONSULTATION AND TREATMENT REQUEST", text)
        self.assertIn("Referring VA Provider: Dr. Smith", text)
        self.assertIn("Requested Services", text)
        self.assertIn("Intraannular Fibrin injection at L4-L5 if indicated", text)
        self.assertIn("office@example.com", text)
        self.assertIn("Scope of Request", text)
        self.assertNotIn("MRI dated", text)

    def test_clinical_documentation_doc_v2_contains_template_sections(self):
        text = self._export_doc_text(
            "_write_clinical_documentation_doc_v2",
            {
                "packet_title": "Clinical Documentation Template",
                "clinical_doc_chief_complaint": "Chronic low back pain.",
                "clinical_doc_duration_gt_3m": True,
                "clinical_doc_duration_gt_6m": False,
                "clinical_doc_duration_gt_12m": False,
                "clinical_doc_exact_duration": "14 months",
                "clinical_doc_pain_axial": True,
                "clinical_doc_limit_occupational": True,
                "clinical_doc_conservative_pt": True,
                "clinical_doc_esi_response": "Temporary relief",
                "clinical_doc_imaging_annular_tear": True,
                "clinical_doc_primary_diagnosis": "Lumbar Disc Degeneration (M51.36)",
                "clinical_doc_plan_diagnostic_confirmation": True,
                "clinical_doc_physician_narrative": "Narrative test paragraph.",
            },
        )

        self.assertIn("Clinical Documentation Template", text)
        self.assertIn("Duration of Symptoms:", text)
        self.assertIn("[X] > 3 months", text)
        self.assertIn("Response to prior ESI (if applicable):", text)
        self.assertIn("Physician Narrative Paragraph", text)
        self.assertIn("Narrative test paragraph.", text)
        self.assertNotIn("EMR Note Guide", text)

    def test_va_10172_preview_mentions_actual_pdf_export(self):
        html = dev_tools_dialog.build_packet_builder_preview_html(
            {
                "packet_profile": "VA Form 10-10172",
                "packet_title": "VA Form 10-10172",
                "patient_name": "Jacob Talbott",
                "date_of_birth": "04/03/1992",
                "authorization_number": "VA0051513368",
                "va10172_va_facility_address": "Charlie Norwood VA Medical Center",
                "va10172_reason_for_request": "Evaluation and treatment of chronic lumbar spine pain.",
                "va10172_template_path": "C:/templates/VA_Form_10-10172.pdf",
            }
        )

        self.assertIn("VA Form 10-10172", html)
        self.assertIn("Jacob Talbott", html)
        self.assertIn("VA0051513368", html)
        self.assertIn("real va form 10-10172", html.lower())
        self.assertIn("C:/templates/VA_Form_10-10172.pdf", html)

    def test_dev_tools_config_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "dev_tools_config.json")

            with mock.patch.object(dev_tools_dialog, "DEV_TOOLS_CONFIG_PATH", config_path):
                payload = dev_tools_dialog.save_dev_tools_config(
                    {
                        "legacy_gallery_paths": ["C:\\demo.png", "C:\\demo.png"],
                        "packet_builder_export_dir": temp_dir,
                    }
                )
                loaded = dev_tools_dialog.load_dev_tools_config()

        self.assertEqual(payload["legacy_gallery_paths"], ["C:\\demo.png"])
        self.assertEqual(loaded["packet_builder_export_dir"], temp_dir)

    def test_run_export_request_single_writes_requested_formats(self):
        class WriterStub:
            def __init__(self):
                self.calls = []

            def _write_word_doc_for_payload(self, path, payload):
                self.calls.append(("docx", path, payload["packet_profile"]))

            def _write_pdf_doc_for_payload(self, path, payload):
                self.calls.append(("pdf", path, payload["packet_profile"]))

        stub = WriterStub()
        result = dev_tools_dialog.PacketBuilderTab._run_export_request(
            stub,
            {
                "mode": "single",
                "payload": {"packet_profile": "Submission Cover Sheet"},
                "output_map": {
                    "docx": r"C:\Exports\sample.docx",
                    "pdf": r"C:\Exports\sample.pdf",
                },
                "artifact_updates": {"single_doc_pdf": r"C:\Exports\sample.pdf"},
                "success_title": "Packet Exports Complete",
                "success_message": "done",
            },
        )

        self.assertEqual(
            stub.calls,
            [
                ("docx", r"C:\Exports\sample.docx", "Submission Cover Sheet"),
                ("pdf", r"C:\Exports\sample.pdf", "Submission Cover Sheet"),
            ],
        )
        self.assertEqual(result["title"], "Packet Exports Complete")
        self.assertEqual(result["artifact_updates"]["single_doc_pdf"], r"C:\Exports\sample.pdf")

    def test_build_export_warning_context_flags_unstarted_form_export(self):
        warning = dev_tools_dialog.build_export_warning_context(
            {
                "packet_profile": "Submission Cover Sheet",
                "packet_title": "VA Submission Cover Sheet",
            }
        )

        self.assertIsNotNone(warning)
        self.assertIn("Export anyway?", warning["message"])

    def test_build_export_warning_context_skips_warning_for_started_form(self):
        warning = dev_tools_dialog.build_export_warning_context(
            {
                "packet_profile": "Submission Cover Sheet",
                "packet_title": "VA Submission Cover Sheet",
                "patient_name": "Jacob Talbott",
                "date_of_birth": "04/03/1992",
                "facility": "Charlie Norwood VA Medical Center",
                "ordering_doctor": "William Durrett",
                "submission_date": "05/31/2026",
                "primary_diagnosis_code": "M51.36",
            }
        )

        self.assertIsNone(warning)

    def test_inconsistency_messages_use_role_specific_provider_wording(self):
        messages = dev_tools_dialog.build_packet_inconsistency_messages(
            {
                "packet_profile": "Consultation & Treatment Request Template",
                "ordering_doctor": "Dr. VA Referrer",
                "consult_referring_va_provider": "Dr. Other",
                "master_provider_phone": "555-111-2222",
                "provider_phone": "555-999-0000",
            }
        )

        joined = "\n".join(messages)
        self.assertIn("VA referring / ordering provider", joined)
        self.assertIn("Community Care practice phone", joined)


if __name__ == "__main__":
    unittest.main()
