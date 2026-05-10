from types import SimpleNamespace
import unittest

from TrueCoreIntel.core import packet_archetypes


def make_packet(
    *,
    detected_documents=None,
    fields=None,
    section_roles=None,
    document_family_hints=None,
    semantic_document_recoveries=None,
    field_observations=None,
    field_values=None,
):
    return SimpleNamespace(
        detected_documents=set(detected_documents or set()),
        fields=dict(fields or {}),
        section_roles=dict(section_roles or {}),
        links={
            "document_family_hints": dict(document_family_hints or {}),
            "semantic_document_recoveries": dict(semantic_document_recoveries or {}),
        },
        field_observations=dict(field_observations or {}),
        field_values=dict(field_values or {}),
    )


class PacketContextTests(unittest.TestCase):

    def test_infer_submission_profile_for_referral_backed_packet(self):
        packet = make_packet(
            detected_documents={"approved_referral", "clinical_notes"},
            fields={
                "authorization_number": "VA0053074284",
                "va_icn": "1016439260V811008",
                "diagnosis": "low back pain",
            },
            section_roles={1: ["routing_followup"], 2: ["clinical_support", "diagnostic_basis"]},
            document_family_hints={1: ["approved_referral"], 2: ["clinical_notes"]},
        )
        self.assertEqual(packet_archetypes.infer_submission_profile(packet), "authorization_request")

    def test_infer_packet_archetype_for_referral_backed_history(self):
        packet = make_packet(
            detected_documents={"approved_referral", "clinical_notes"},
            fields={
                "authorization_number": "VA0053074284",
                "va_icn": "1016439260V811008",
                "diagnosis": "low back pain",
                "procedure": "lumbar radiofrequency ablation",
            },
            section_roles={
                1: ["routing_followup"],
                2: ["clinical_support", "diagnostic_basis"],
                3: ["request_scope", "clinical_support"],
            },
            document_family_hints={1: ["approved_referral"], 2: ["clinical_notes"]},
            field_observations={
                "service_date_range": [
                    {"value": "09/17/2025 to 09/17/2025"},
                    {"value": "03/18/2026 to 03/18/2026"},
                ]
            },
            field_values={
                "service_date_range": [
                    "09/17/2025 to 09/17/2025",
                    "03/18/2026 to 03/18/2026",
                ]
            },
        )
        archetype = packet_archetypes.infer_packet_archetype(packet, submission_profile="authorization_request")
        self.assertEqual(archetype["key"], "referral_backed_treatment_history")


if __name__ == "__main__":
    unittest.main()
