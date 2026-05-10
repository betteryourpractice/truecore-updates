import unittest

from TrueCoreIntel.data.packet_model import Packet
from TrueCoreIntel.extraction.extractor_engine import ExtractorEngine
from TrueCoreIntel.validation.validator_engine import ValidatorEngine


class CorePacketEngineRoleTests(unittest.TestCase):

    def test_extractor_promotes_treating_and_followup_provider_roles_on_mixed_packet(self):
        packet = Packet()
        packet.pages = [
            (
                "VA Form 10-7080 Approved Referral for Medical Care\n"
                "Provider Name (If known): OCH CENTER FOR PAIN MANAGEMENT\n"
                "Initial Provider Location: OCH CENTER FOR PAIN MANAGEMENT-107 DOCTORS PARK, STARKVILLE, MS, 39759-193200000X\n"
                "Referring Provider: ERNESTINE IVY\n"
            ),
            (
                "Procedure Note\n"
                "Physician: Douglas Tucker, MD\n"
                "Performed by: Tucker, Douglas A MD on March 18, 2026 8:31 CDT\n"
                "Verified by: Tucker, Douglas A MD on March 18, 2026 8:31 CDT\n"
            ),
            (
                "Office Clinic Note\n"
                "Performed by: Lyle, Lana J FNP on February 18, 2026 9:21 CST\n"
                "Verified by: Lyle, Lana J FNP on February 18, 2026 9:21 CST\n"
            ),
        ]
        packet.page_metadata = [{}, {}, {}]
        packet.page_sources = ["page1", "page2", "page3"]
        packet.document_types = {
            0: "approved_referral",
            1: "unknown",
            2: "unknown",
        }
        packet.detected_documents = {"approved_referral"}

        ExtractorEngine().extract(packet)

        self.assertEqual(packet.document_types[1], "clinical_notes")
        self.assertEqual(packet.document_types[2], "clinical_notes")
        self.assertEqual(packet.fields.get("referring_provider"), "Ernestine Ivy")
        self.assertEqual(packet.fields.get("provider"), "Douglas Tucker, MD")
        self.assertEqual(packet.fields.get("treating_provider"), "Douglas Tucker, MD")
        self.assertEqual(packet.fields.get("followup_provider"), "Lana J Lyle, FNP")
        self.assertEqual(packet.fields.get("clinic_name"), "OCH Center for Pain Management")
        self.assertEqual(packet.fields.get("location"), "107 Doctors Park, Starkville, MS 39759")

    def test_validator_allows_lumbar_history_icd_variation(self):
        packet = Packet()
        packet.field_values["icd_codes"] = [
            ["M54.50"],
            ["M43.06", "M54.50"],
            ["M47.817"],
            ["M51.36"],
        ]
        packet.field_observations["icd_codes"] = [
            {"value": ["M54.50"], "document_type": "clinical_notes", "snippet": "Office clinic note low back pain", "matched_text": "M54.50"},
            {"value": ["M43.06", "M54.50"], "document_type": "clinical_notes", "snippet": "Procedure note lumbar history", "matched_text": "M43.06 M54.50"},
            {"value": ["M47.817"], "document_type": "unknown", "snippet": "Office clinic note lumbar spondylosis", "matched_text": "M47.817"},
            {"value": ["M51.36"], "document_type": "unknown", "snippet": "Office visit note lumbar degeneration", "matched_text": "M51.36"},
        ]

        ValidatorEngine().check_icd_consistency(packet)

        self.assertFalse(
            any(conflict.get("field") == "icd_codes" for conflict in packet.conflicts),
            packet.conflicts,
        )


if __name__ == "__main__":
    unittest.main()
