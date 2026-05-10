import unittest
from types import SimpleNamespace

from TrueCoreIntel.review.review_summary_builder import ReviewSummaryBuilder


class ReviewSummaryBuilderTests(unittest.TestCase):

    def setUp(self):
        self.builder = ReviewSummaryBuilder(
            {"name", "dob", "authorization_number"},
            {"icd_codes", "reason_for_request", "ordering_provider", "referring_provider"},
        )

    def test_build_collects_review_summary_artifacts(self):
        packet = SimpleNamespace(
            missing_fields=["authorization_number", "reason_for_request"],
            missing_documents=["Consultation & Treatment Request"],
            conflicts=[{"field": "provider", "severity": "medium", "message": "Provider differs across documents."}],
            review_flags=["diagnosis_icd_mismatch", "chronology_review_needed"],
            packet_strength="weak",
        )

        summary = self.builder.build(packet)

        self.assertIn("Critical required fields are missing: authorization_number.", summary.why_weak)
        self.assertIn("Important clinical/review fields are missing: reason_for_request.", summary.why_weak)
        self.assertIn("Missing required document: Consultation & Treatment Request.", summary.missing_items)
        self.assertIn("Provider differs across documents.", summary.conflict_items)
        self.assertIn("Correct the diagnosis language or update ICD coding so they match.", summary.fix_recommendations)
        self.assertTrue(any(item["target"] == "authorization_number" for item in summary.prioritized_fixes))

    def test_build_prioritized_fixes_deduplicates_reason_for_request_gap(self):
        packet = SimpleNamespace(
            missing_fields=["reason_for_request"],
            missing_documents=[],
            conflicts=[],
            review_flags=["missing_reason_for_request"],
            packet_strength="moderate",
        )

        fixes = self.builder.build_prioritized_fixes(packet)
        reason_fixes = [item for item in fixes if item["target"] == "reason_for_request"]

        self.assertEqual(len(reason_fixes), 1)
        self.assertEqual(reason_fixes[0]["priority"], "medium")


if __name__ == "__main__":
    unittest.main()
