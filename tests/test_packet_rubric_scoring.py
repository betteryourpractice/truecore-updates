import unittest

from TrueCoreIntel.data.packet_model import Packet
from TrueCoreIntel.intelligence.intelligence_engine import IntelligenceEngine
from TrueCoreIntel.intelligence.packet_rubric import build_packet_rubric
from TrueCoreIntel.intelligence.semantic_adjudication import SemanticAdjudicationAnalyzer
from TrueCoreIntel.review.review_engine import ReviewEngine


def make_full_submission_packet():
    packet = Packet()
    packet.packet_profile = "full_submission"
    packet.detected_documents = {
        "rfs",
        "seoc",
        "consult_request",
        "lomn",
        "consent",
        "clinical_notes",
    }
    packet.fields = {
        "name": "Jacob Ray Talbott",
        "dob": "04/03/1992",
        "authorization_number": "VA0053074284",
        "va_icn": "1041529679V678591",
        "ordering_provider": "William E. Durrett, MD",
        "provider": "William E. Durrett, MD",
        "reason_for_request": "Evaluation and treatment planning for discogenic lumbar pain",
        "diagnosis": "low back pain",
        "icd_codes": ["M54.50"],
    }
    packet.field_observations = {
        "name": [
            {"value": "Jacob Ray Talbott", "document_type": "rfs"},
            {"value": "Jacob Ray Talbott", "document_type": "consent"},
        ],
        "dob": [{"value": "04/03/1992", "document_type": "rfs"}],
        "authorization_number": [{"value": "VA0053074284", "document_type": "rfs"}],
        "reason_for_request": [
            {"value": "Evaluation and treatment planning for discogenic lumbar pain", "document_type": "seoc"},
            {"value": "Evaluation and treatment planning for discogenic lumbar pain", "document_type": "consult_request"},
            {"value": "Evaluation and treatment planning for discogenic lumbar pain", "document_type": "lomn"},
        ],
        "diagnosis": [
            {"value": "low back pain", "document_type": "rfs"},
            {"value": "low back pain", "document_type": "consult_request"},
            {"value": "low back pain", "document_type": "lomn"},
            {"value": "low back pain", "document_type": "clinical_notes"},
        ],
        "icd_codes": [
            {"value": ["M54.50"], "document_type": "rfs"},
            {"value": ["M54.50"], "document_type": "consult_request"},
            {"value": ["M54.50"], "document_type": "lomn"},
            {"value": ["M54.50"], "document_type": "clinical_notes"},
        ],
        "ordering_provider": [{"value": "William E. Durrett, MD", "document_type": "consult_request"}],
        "provider": [{"value": "William E. Durrett, MD", "document_type": "clinical_notes"}],
        "signature_present": [
            {"value": True, "document_type": "rfs"},
            {"value": True, "document_type": "consult_request"},
            {"value": True, "document_type": "lomn"},
            {"value": True, "document_type": "consent"},
        ],
    }
    packet.review_flags = []
    packet.conflicts = []
    packet.page_confidence = {}
    packet.field_confidence = {}
    return packet


class PacketRubricScoringTests(unittest.TestCase):
    def setUp(self):
        self.semantic = SemanticAdjudicationAnalyzer()

    def test_consult_and_lomn_do_not_require_signature(self):
        packet = make_full_submission_packet()
        packet.field_observations["signature_present"] = [
            {"value": True, "document_type": "rfs"},
            {"value": True, "document_type": "consent"},
        ]

        rubric = build_packet_rubric(packet)
        consult_component = next(component for component in rubric["components"] if component["key"] == "consult_request")
        lomn_component = next(component for component in rubric["components"] if component["key"] == "lomn")

        self.assertEqual(consult_component["status"], "strong")
        self.assertEqual(lomn_component["status"], "strong")
        self.assertFalse(
            any("signature" in item.lower() for item in consult_component["review_needs"]),
            consult_component["review_needs"],
        )
        self.assertFalse(
            any("signature" in item.lower() for item in lomn_component["review_needs"]),
            lomn_component["review_needs"],
        )

    def test_small_name_ocr_conflict_becomes_review_not_blocker(self):
        packet = make_full_submission_packet()
        packet.conflicts = [
            {"field": "name", "severity": "high", "values": ["Jacob Talbott", "Acob Talbott"]},
        ]

        rubric = build_packet_rubric(packet)

        self.assertFalse(rubric["blocking_conflict_fields"], rubric)
        self.assertIn("name", rubric["review_conflict_fields"])
        self.assertTrue(
            any("ocr-style variation" in item.lower() for item in rubric["review_needs"]),
            rubric["review_needs"],
        )

    def test_imaging_report_requires_formal_report_not_simple_reference(self):
        packet = make_full_submission_packet()
        packet.detected_documents.add("imaging_report")
        packet.document_types = {
            0: "cover_sheet",
            1: "imaging_report",
        }
        packet.pages = [
            "Documents Included: Virtual Consent Form completed and signed. MRI Report included.",
            (
                "Follow-up clinic note. Prior MRI history reviewed with patient. "
                "Pain remains active. Conservative care discussed."
            ),
        ]

        rubric = build_packet_rubric(packet)
        imaging_component = next(
            component for component in rubric["components"] if component["key"] == "imaging_report"
        )

        self.assertEqual(imaging_component["earned_points"], 0.0)
        self.assertTrue(
            any("formal report was not clearly confirmed" in item.lower() for item in rubric["review_needs"]),
            rubric["review_needs"],
        )

    def test_visible_score_follows_rubric_not_old_conflict_cap(self):
        packet = Packet()
        packet.packet_rubric = {"score": 70.31}
        packet.field_confidence = {}
        packet.conflicts = [
            {"field": "name", "severity": "high", "values": ["Jacob Talbott", "Acob Talbott"]},
        ]

        score = IntelligenceEngine().calculate_score(packet)

        self.assertEqual(score, 70.31)

    def test_readiness_can_hold_packet_even_when_score_is_moderate(self):
        packet = make_full_submission_packet()
        packet.unfilled_documents = {"consent"}
        packet.field_observations["signature_present"] = [
            {"value": True, "document_type": "rfs"},
            {"value": True, "document_type": "consult_request"},
            {"value": True, "document_type": "lomn"},
        ]
        packet.packet_rubric = build_packet_rubric(packet)
        packet.packet_strength = "moderate"
        packet.packet_assembly_score = 88
        packet.packet_confidence = 0.9
        packet.missing_fields = []
        packet.missing_documents = []
        packet.review_flags = []

        decision = ReviewEngine().build_submission_decision(packet)

        self.assertEqual(decision["readiness"], "hold")
        self.assertTrue(
            any("virtual consent form" in reason.lower() for reason in decision["hold_reasons"]),
            decision["hold_reasons"],
        )

    def test_semantically_tolerated_reason_conflict_does_not_count_as_review_conflict(self):
        packet = make_full_submission_packet()
        packet.packet_format_variability = "high"
        packet.conflicts = [
            {
                "field": "reason_for_request",
                "severity": "medium",
                "message": "Reason for request is inconsistent across packet documents.",
            }
        ]
        packet = self.semantic.analyze(packet)

        rubric = build_packet_rubric(packet)

        self.assertNotIn("reason_for_request", rubric["review_conflict_fields"])


if __name__ == "__main__":
    unittest.main()
