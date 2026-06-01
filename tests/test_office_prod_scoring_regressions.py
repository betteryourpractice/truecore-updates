import unittest
from unittest.mock import patch

from TrueCoreIntel.detection.document_detector import DocumentDetector
from TrueCoreIntel.core.packet_failure_modes import annotate_packet_failure_modes
from TrueCoreIntel.data.packet_model import Packet
from TrueCoreIntel.extraction.extractor_engine import ExtractorEngine
from TrueCoreIntel.intel_engine import process_pages
from TrueCoreIntel.intelligence.semantic_adjudication import SemanticAdjudicationAnalyzer
from TrueCoreIntel.validation.validation_intelligence import ValidationIntelligenceAnalyzer
from TrueCoreIntel.validation.validator_engine import ValidatorEngine


class OfficeProdScoringRegressionTests(unittest.TestCase):
    def setUp(self):
        self.extractor = ExtractorEngine()
        self.detector = DocumentDetector()
        self.validator = ValidatorEngine()
        self.validation_intelligence = ValidationIntelligenceAnalyzer()
        self.semantic = SemanticAdjudicationAnalyzer()

    def test_last_four_ssn_does_not_extract_claim_number(self):
        text = (
            "RE: Single Episode of Care (SEOC) Request\n"
            "Veteran Name: Aaron Wharton\n"
            "DOB: 03/05/1993\n"
            "Last Four SSN: 3601\n"
        )
        data = self.extractor.extract_labeled_fields(text, doc_type="seoc")
        self.assertNotIn("claim_number", data)

    def test_chief_complaint_does_not_drive_reason_for_request(self):
        text = "Clinical Documentation Template\nChief Complaint: Pain\n"
        self.assertIsNone(self.extractor.extract_request_intent_concept(text))

    def test_phone_like_fallback_is_not_used_as_authorization_number(self):
        text = (
            "RE: Single Episode of Care (SEOC) Request\n"
            "This SEOC is limited to pre-procedure evaluation.\n"
            "Phone: C11-222-3333    Fax: C11-2222-4444\n"
        )
        data = self.extractor.extract_authorization(text)
        self.assertNotIn("authorization_number", data)

    def test_ihs_checkbox_text_is_rejected_as_clinic_name(self):
        self.assertIsNone(self.extractor.normalize_clinic_name("6. INDIAN HEALTH SERVICES (IHS)"))

    def test_ihs_checkbox_text_is_rejected_as_provider_name(self):
        self.assertIsNone(self.extractor.normalize_provider("6. INDIAN HEALTH SERVICES (IHS) PROVIDER/"))

    def test_clinical_documentation_title_is_not_a_template_marker(self):
        markers = self.extractor.detect_template_markers("Clinical Documentation Template\nI. Chief Complaint\nPain")
        self.assertNotIn("template", markers)

    def test_filled_consent_page_is_not_marked_unfilled(self):
        text = (
            "TELEHEALTH VIRTUAL CONSENT FORM\n"
            "Aaron Wharton  03/05/1993\n"
            "Email Address: test@gmail.com\n"
            "PCP/PCM: Dr. Pillay\n"
            "CONSENT FOR MEDICAL CARE AND TREATMENT\n"
            "I, Aaron Wharton hereby agree and give my consent\n"
            "Date: 05/31/2026\n"
        )
        self.assertFalse(self.detector.looks_like_unfilled_consent(text))

    def test_lumbar_icd_code_normalizes_to_same_diagnosis_family(self):
        code_value = self.validator.normalize_conflict_value("diagnosis", "M51.36")
        text_value = self.validator.normalize_conflict_value("diagnosis", "Degenerative Disc Disease")
        self.assertEqual(code_value, text_value)

    def test_seoc_and_consult_reason_values_substantially_overlap(self):
        seoc_reason = self.validator.normalize_conflict_value(
            "reason_for_request",
            "This request is for authorization of a defined, time-limited Single Episode of Care (SEOC) related to Degenerative Disc Disease (M51.36) involving L4-L5.",
        )
        consult_reason = self.validator.normalize_conflict_value(
            "reason_for_request",
            "MRI dated 05/30/2026 demonstrates Degenerative Disc Disease, which correlates with the Veteran's reported pain pattern and functional limitations. Consultation and treatment planning are requested for Degenerative Disc Disease (M51.36) involving L4-L5.",
        )
        self.assertTrue(self.validator.reason_values_substantially_overlap([seoc_reason, consult_reason]))

    def test_rfs_claim_identifier_can_promote_into_authorization_number(self):
        packet = Packet()
        packet.detected_documents = {"rfs", "consult_request", "lomn"}
        packet.fields["claim_number"] = "VAU123"
        packet.field_values["claim_number"] = ["VAU123", "VAU123"]
        packet.field_observations["claim_number"] = [
            {
                "value": "VAU123",
                "document_type": "consult_request",
                "page_index": 6,
                "confidence": 0.9,
            }
        ]
        self.extractor.consolidate_identifier_fields(packet)
        self.assertEqual(packet.fields.get("authorization_number"), "VAU123")

    def test_rfs_context_can_recover_printed_provider_name(self):
        text = (
            "VA FORM 10-10172, MAR 2025 Page 2\n"
            "Aaron Wharton\n"
            "03/05/1993\n"
            "000 VA Way, Oviedo, FL 32765\n"
            "VAU123\n"
            "000 SC Way, Aiken, SC 77411\n"
            "C11-222-3333\n"
            "C11-2222-4444\n"
            "CCN@gmail.com\n"
            "Dr. William E. Durrett\n"
            "CN123\n"
            "05/31/2026\n"
        )

        data = self.extractor.extract_contextual_provider_role_fields(text, doc_type="rfs")

        self.assertEqual(data.get("ordering_provider"), "William Durrett")
        self.assertEqual(data.get("provider"), "William Durrett")

    def test_clinical_note_only_packet_promotes_diagnosis_into_request_intent(self):
        packet = Packet()
        packet.detected_documents = {"clinical_notes"}
        packet.fields["diagnosis"] = "neck pain"
        packet.field_values["diagnosis"] = ["neck pain"]
        packet.field_observations["diagnosis"] = [
            {
                "value": "neck pain",
                "document_type": "clinical_notes",
                "page_index": 0,
                "confidence": 0.88,
            }
        ]
        self.extractor.consolidate_clinical_minimal_request_intent(packet)
        self.assertEqual(packet.fields.get("reason_for_request"), "neck pain")

    def test_consult_request_completeness_ignores_optional_va_icn_and_location(self):
        packet = Packet()
        packet.detected_documents = {"consult_request"}
        packet.fields = {
            "name": "Aaron Wharton",
            "dob": "03/05/1993",
            "ordering_provider": "Dr. Pillay",
            "referring_provider": "Pillay Primary",
            "authorization_number": "VAU123",
            "reason_for_request": "Consultation and treatment planning are requested.",
            "diagnosis": "degenerative disc disease",
        }

        result = self.validation_intelligence.build_field_to_form_consistency_checks(packet)
        consult_check = next(item for item in result["documents"] if item["document_type"] == "consult_request")

        self.assertEqual(consult_check["status"], "complete")
        self.assertEqual(consult_check["missing_expected_fields"], [])

    def test_only_consent_is_treated_as_signature_expected(self):
        packet = Packet()
        packet.detected_documents = {"consent", "lomn", "consult_request"}
        packet.fields = {}
        packet.missing_documents = []
        packet.unfilled_documents = set()
        packet.conflicts = []

        signature_state = self.validation_intelligence.build_signature_and_completeness_validation(packet)

        self.assertEqual(signature_state["documents_expect_signature"], ["consent"])
        self.assertEqual(signature_state["missing_signature_documents"], ["consent"])

    def test_select_best_observation_prefers_consult_provider_over_rfs_shell_text(self):
        packet = Packet()
        packet.field_observations["ordering_provider"] = [
            {
                "value": "Indian Health Services Ihs",
                "document_type": "rfs",
                "confidence": 0.99,
                "primary_section_role": "request_intent",
            },
            {
                "value": "William Durrett",
                "document_type": "consult_request",
                "confidence": 0.95,
                "primary_section_role": "identity_admin",
            },
        ]

        selected = self.extractor.select_best_observation(packet, "ordering_provider")

        self.assertEqual(selected["value"], "William Durrett")
        self.assertEqual(selected["document_type"], "consult_request")

    def test_select_best_observation_prefers_diagnostic_basis_over_unknown_tail(self):
        packet = Packet()
        packet.field_observations["diagnosis"] = [
            {
                "value": "degenerative disc disease",
                "document_type": "unknown",
                "confidence": 0.97,
                "primary_section_role": "request_intent",
            },
            {
                "value": "degenerative disc disease",
                "document_type": "lomn",
                "confidence": 0.95,
                "primary_section_role": "diagnostic_basis",
            },
        ]

        selected = self.extractor.select_best_observation(packet, "diagnosis")

        self.assertEqual(selected["document_type"], "lomn")
        self.assertEqual(selected["primary_section_role"], "diagnostic_basis")

    def test_lomn_continuation_page_classifies_as_lomn(self):
        text = (
            "The requested Intraannular Fibrin Injection is medically reasonable and necessary if clinically indicated after specialty evaluation and diagnostic confirmation.\n"
            "Requested Treatment Objectives:\n"
            "Reduce pain severity\n"
            "Risk if Treatment Is Delayed or Denied:\n"
            "Without timely specialty evaluation and indicated treatment, the Veteran remains at risk for persistent pain.\n"
            "Reasonable and Necessary Determination:\n"
            "The requested care is consistent with the documented diagnosis.\n"
            "Provider Contact Statement:\n"
            "Additional supporting documentation can be provided upon request.\n"
            "Sincerely,\n"
            "Dr. William E. Durrett, Doctor, MD\n"
        )

        doc_type, confidence = self.detector.classify_page_with_confidence(text)

        self.assertEqual(doc_type, "lomn")
        self.assertGreaterEqual(confidence, 0.75)

    def test_merged_page_content_does_not_raise_classification_uncertainty_by_itself(self):
        packet = Packet()
        packet.review_flags = []
        with (
            patch("TrueCoreIntel.core.packet_failure_modes._page_hint_map", return_value={}),
            patch(
                "TrueCoreIntel.core.packet_failure_modes._detect_semantic_title_drift",
                return_value=None,
            ),
            patch(
                "TrueCoreIntel.core.packet_failure_modes._detect_merged_page_content",
                return_value={
                    "code": "merged_page_content",
                    "label": "Merged Page Content",
                    "severity": "medium",
                    "summary": "synthetic merged content",
                    "confidence_penalty": 0.04,
                },
            ),
            patch(
                "TrueCoreIntel.core.packet_failure_modes._detect_ocr_admin_degradation",
                return_value=None,
            ),
            patch(
                "TrueCoreIntel.core.packet_failure_modes._detect_classification_uncertainty",
                return_value=None,
            ),
        ):
            annotate_packet_failure_modes(packet)

        failure_codes = {item.get("code") for item in packet.packet_failure_modes}
        self.assertIn("merged_page_content", failure_codes)
        self.assertNotIn("classification_uncertainty", packet.review_flags)

    def test_semantic_adjudication_recognizes_coherent_variant_packet(self):
        packet = Packet()
        packet.packet_format_variability = "high"
        packet.fields = {
            "name": "Aaron Wharton",
            "dob": "03/05/1993",
            "authorization_number": "VAU123",
            "diagnosis": "Degenerative Disc Disease",
            "icd_codes": ["M51.36", "M54.50"],
            "reason_for_request": (
                "MRI dated 05/30/2026 demonstrates degenerative disc disease, which correlates with the Veteran's "
                "reported low back pain and functional limitations. Consultation and treatment planning are requested "
                "for degenerative disc disease involving L4-L5."
            ),
            "ordering_provider": "William Durrett",
            "referring_provider": "Pillay Primary",
            "provider": "William Durrett",
            "facility": "Lake Baldwin VA",
            "clinic_name": "Aiken Neuroscience",
        }

        packet = self.semantic.analyze(packet)

        self.assertGreaterEqual(packet.packet_semantic_coherence_score, 80)
        self.assertIn(packet.semantic_adjudication["overall_status"], {"coherent", "coherent_variant"})
        self.assertTrue(packet.semantic_adjudication["variant_tolerance"]["coherent_despite_variation"])

    def test_semantic_deduction_ledger_marks_real_gap_vs_review_caution(self):
        packet = Packet()
        packet.fields = {
            "name": "Aaron Wharton",
            "dob": "03/05/1993",
            "authorization_number": "VAU123",
            "diagnosis": "Degenerative Disc Disease",
            "icd_codes": ["M51.36", "M54.50"],
            "reason_for_request": "Consultation and treatment planning are requested for lumbar degenerative disc disease.",
        }
        packet.missing_documents = ["imaging_report"]
        packet.review_flags = ["partial_diagnosis_icd_alignment"]

        packet = self.semantic.analyze(packet)
        ledger = list(packet.semantic_adjudication.get("deduction_ledger", []))

        self.assertTrue(any(item.get("category") == "missing_document" and item.get("trust_level") == "real_gap" for item in ledger))
        self.assertTrue(any(item.get("category") == "review_flag" and item.get("trust_level") == "review_caution" for item in ledger))

    def test_pipeline_exposes_semantic_adjudication_output(self):
        packet = process_pages(
            [
                "Submission Cover Sheet\nPatient Name: Aaron Wharton\nDOB: 03/05/1993\nAuthorization Number: VAU123\nVA Facility: Lake Baldwin VA",
                "Consultation and Treatment Request\nOrdering Provider: William Durrett\nReason for Request: consultation and treatment planning for degenerative disc disease involving L4-L5\nDiagnosis: degenerative disc disease\nICD-10: M51.36, M54.50",
                "Letter of Medical Necessity\nDiagnosis: degenerative disc disease\nMedical Necessity: conservative care has failed and specialty evaluation remains medically necessary.",
                "Clinical Notes\nPatient Name: Aaron Wharton\nDOB: 03/05/1993\nAssessment: degenerative disc disease\nChief Complaint: low back pain",
            ],
            source_type="pdf",
        )

        self.assertIn("semantic_adjudication", packet.links)
        self.assertIsNotNone(packet.packet_semantic_coherence_score)
        self.assertIn("review_notes", packet.semantic_adjudication)


if __name__ == "__main__":
    unittest.main()
