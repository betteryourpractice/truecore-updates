import unittest
from types import SimpleNamespace

from TrueCore.core import intel_bridge


class IntelBridgeProviderRoleTests(unittest.TestCase):

    def test_derives_treating_provider_and_location_from_mixed_packet_context(self):
        packet = SimpleNamespace(
            pages=[
                (
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
            ],
            document_types={
                0: "approved_referral",
                1: "clinical_notes",
                2: "unknown",
            },
        )

        host_fields = {
            "provider": "Ernestine Ivy",
            "referring_doctor": "Ernestine Ivy",
            "clinic_name": "Och Center",
            "location": "Och Center For Pain Man",
        }

        derived = intel_bridge._derive_provider_role_fields(packet, host_fields)

        self.assertEqual(derived["provider"], "Douglas Tucker, MD")
        self.assertEqual(derived["treating_provider"], "Douglas Tucker, MD")
        self.assertEqual(derived["clinic_name"], "OCH Center for Pain Management")
        self.assertEqual(derived["location"], "107 Doctors Park, Starkville, MS 39759")
        self.assertIn("Lyle", derived["followup_provider"])


if __name__ == "__main__":
    unittest.main()
