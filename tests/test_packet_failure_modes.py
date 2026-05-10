from types import SimpleNamespace
import unittest

from TrueCoreIntel.core.packet_failure_modes import annotate_packet_failure_modes


class PacketFailureModeTests(unittest.TestCase):

    def test_semantic_title_drift_and_classification_uncertainty_are_flagged(self):
        packet = SimpleNamespace(
            pages=[
                "Cover Sheet\nDocuments Included: Consult Request, LOMN, Consent\nPatient Name: Jane Doe\nAuthorization Number: VA123\nVA Facility: Test VAMC",
                "Medical necessity letter\nDiagnosis: lumbar radiculopathy\nRequested service: MRI lumbar spine",
                "Telehealth Consent\nPatient signature: Jane Doe\nDate: 03/01/2026",
            ],
            detected_documents={"clinical_notes"},
            missing_documents=["cover_sheet", "consult_request", "lomn", "consent"],
            document_types={0: "unknown", 1: "unknown", 2: "unknown"},
            field_values={},
            fields={"authorization_number": "VA123", "facility": "Test VAMC"},
            section_roles={},
            links={},
            intake_diagnostics={},
            review_flags=[],
            packet_invariant_coverage_score=82.0,
            packet_format_variability="high",
            packet_archetype="mixed_history_packet",
            packet_profile="full_submission",
        )

        annotate_packet_failure_modes(packet)

        self.assertTrue(packet.packet_classification_caution)
        self.assertIn("Semantic Title Drift", packet.packet_failure_mode_labels)
        self.assertIn("classification_uncertainty", packet.review_flags)


if __name__ == "__main__":
    unittest.main()
