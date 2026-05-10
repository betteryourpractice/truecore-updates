import tempfile
import unittest
from unittest import mock

from TrueCore.core import cross_office_learning


class CrossOfficeLearningTests(unittest.TestCase):

    def test_snapshot_deidentifies_case_and_provider_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = f"{temp_dir}/office_profile.json"
            with mock.patch.object(cross_office_learning, "OFFICE_PROFILE_PATH", profile_path):
                office_profile = cross_office_learning.load_office_profile()
                packet = cross_office_learning.build_deidentified_packet_run(
                    {
                        "case_key": "auth:va0053074284",
                        "provider_key": "ernestine ivy",
                        "analyzed_at": "2026-05-08T10:00:00Z",
                        "file_name": "Nickoles_B.pdf",
                        "score": 67,
                        "status": "needs_review",
                        "forms_text": "approved_referral | clinical_notes",
                        "issues_json": '["Missing Consultation & Treatment Request"]',
                    },
                    office_profile=office_profile,
                )

                self.assertNotEqual(packet["packet_key"], "auth:va0053074284")
                self.assertNotEqual(packet["provider_key_hash"], "ernestine ivy")
                self.assertEqual(packet["forms"], ["approved_referral", "clinical_notes"])
                self.assertIn("Missing Consultation & Treatment Request", packet["issue_labels"])

    def test_cross_office_summary_aggregates_packet_health(self):
        summary = cross_office_learning.build_cross_office_benchmark_summary(
            [
                {
                    "packet_score": 80,
                    "packet_confidence": 0.8,
                    "runtime_seconds": 10.0,
                    "scan_quality_score": 0.9,
                    "status": "approved",
                    "denial_risk": "low",
                    "workflow_queue": "review_queue",
                    "issue_labels": ["A", "B"],
                    "forms": ["clinical_notes"],
                },
                {
                    "packet_score": 60,
                    "packet_confidence": 0.6,
                    "runtime_seconds": 20.0,
                    "scan_quality_score": 0.7,
                    "status": "needs_review",
                    "denial_risk": "high",
                    "workflow_queue": "correction_queue",
                    "issue_labels": ["A"],
                    "forms": ["approved_referral"],
                },
            ],
            [
                {
                    "event_type": "manual_outcome",
                    "event_status": "approved",
                }
            ],
        )

        self.assertEqual(summary["packet_count"], 2)
        self.assertEqual(summary["average_packet_score"], 70.0)
        self.assertEqual(summary["manual_outcome_distribution"], {"approved": 1})
        self.assertEqual(summary["top_issues"][0][0], "A")


if __name__ == "__main__":
    unittest.main()
