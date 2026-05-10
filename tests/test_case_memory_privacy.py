import os
import tempfile
import unittest
from unittest.mock import patch

from TrueCore.core import case_memory


class CaseMemoryPrivacyTests(unittest.TestCase):

    def test_recorded_runs_store_redacted_identifiers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "truecore_memory.db")
            result = {
                "score": 78,
                "forms": ["approved_referral", "clinical_notes"],
                "issues": ["Missing Consultation & Treatment Request"],
                "fixes": ["Attach required document: Consultation & Treatment Request"],
                "fields": {
                    "patient_name": "Billy Joe Nickoles",
                    "dob": "07/12/1960",
                    "authorization_number": "VA0053074284",
                    "va_icn": "1016439260V811008",
                    "provider": "Ernestine Ivy",
                    "diagnosis": "low back pain",
                },
                "intel": {
                    "display": {
                        "denial_risk": "critical",
                        "workflow_queue": "senior_review_queue",
                        "review_priority": "high",
                        "packet_confidence": 0.71,
                    }
                },
                "profiling": {
                    "total_seconds": 12.4,
                    "intel_seconds": 12.1,
                    "host_seconds": 0.3,
                    "analysis_mode": "intel",
                },
            }

            with patch.object(case_memory, "MEMORY_DB_PATH", db_path), \
                 patch("TrueCore.core.case_memory.load_office_profile", return_value={"deidentification_salt": "a" * 32}):
                case_memory.record_packet_analysis(
                    r"C:\Packets\Billy Nickoles Packet.pdf",
                    result,
                )
                rows = case_memory.get_recent_packet_runs(limit=5)

            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertTrue(str(row["case_key"]).startswith("auth_hash:"))
            self.assertTrue(str(row["patient_name"]).startswith("patient:"))
            self.assertTrue(str(row["authorization_number"]).startswith("auth:"))
            self.assertTrue(str(row["va_icn"]).startswith("icn:"))
            self.assertTrue(str(row["file_name"]).startswith(".pdf:"))
            self.assertIsNone(row["file_path"])
            self.assertNotIn("Billy", str(row["fields_json"]))
            self.assertNotIn("VA0053074284", str(row["fields_json"]))

    def test_recorded_events_redact_free_text_notes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "truecore_memory.db")
            result = {
                "score": 67,
                "forms": [],
                "issues": [],
                "fixes": [],
                "fields": {
                    "patient_name": "Billy Joe Nickoles",
                    "authorization_number": "VA0053074284",
                },
                "intel": {"display": {}},
            }

            with patch.object(case_memory, "MEMORY_DB_PATH", db_path), \
                 patch("TrueCore.core.case_memory.load_office_profile", return_value={"deidentification_salt": "b" * 32}):
                case_memory.record_packet_event(
                    r"C:\Packets\Billy Nickoles Packet.pdf",
                    result,
                    event_type="manual_outcome",
                    event_status="approved",
                    note="Approved after confirming Billy Nickoles packet with VA auth VA0053074284.",
                    details={"score": 67},
                )
                events = case_memory.get_recent_packet_events(limit=5)

            self.assertEqual(len(events), 1)
            event = events[0]
            self.assertTrue(str(event["note"]).startswith("Note captured ("))
            self.assertTrue(str(event["case_key"]).startswith("auth_hash:"))
            self.assertTrue(str(event["file_name"]).startswith(".pdf:"))
            self.assertIsNone(event["file_path"])


if __name__ == "__main__":
    unittest.main()
