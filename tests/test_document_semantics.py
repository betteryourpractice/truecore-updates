import unittest

from TrueCoreIntel.core.document_semantics import normalize_semantic_text, page_hints


class DocumentSemanticsTests(unittest.TestCase):

    def test_normalize_semantic_text_recovers_light_ocr_drift(self):
        text = "C0nsultat1on and Treatment Request\n0rdering Provider: William Durrett\nReas0n f0r Request: low back pain"
        normalized = normalize_semantic_text(text)
        self.assertIn("consultation", normalized)
        self.assertIn("ordering provider", normalized)
        self.assertIn("reason for request", normalized)

    def test_page_hints_recovers_consult_request_from_semantic_clues(self):
        text = (
            "Consult for treatment\n"
            "Ordering Provider: William Durrett\n"
            "Reason for Request: low back pain\n"
            "ICD-10: M54.16, M54.50"
        )
        hints = page_hints(text)
        self.assertIn("consult_request", hints)


if __name__ == "__main__":
    unittest.main()
