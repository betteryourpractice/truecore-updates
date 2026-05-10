import unittest
from unittest.mock import patch

from TrueCore.dev import real_packet_regression_library as regression_library


def make_result():
    return {
        "score": 67,
        "forms": ["VA Form 10-7080", "Clinical Notes"],
        "fields": {
            "patient_name": "Nickoles, Billy",
            "authorization_number": "VA0053074284",
            "va_icn": "1016439260V811008",
            "diagnosis": "low back pain",
            "reason_for_request": "Evaluation for all pain treatment options in VA (excluding opioid therapy)",
        },
        "issues": [
            "Missing Consultation & Treatment Request",
            "ICD codes are inconsistent across packet documents",
        ],
        "intel": {
            "display": {
                "packet_profile": "Authorization Request",
                "packet_archetype": "Referral-Backed Treatment History",
                "missing_items": ["Missing required document: Consultation & Treatment Request"],
            }
        },
    }


class RealPacketRegressionLibraryTests(unittest.TestCase):

    @patch("TrueCore.dev.real_packet_regression_library.os.path.exists")
    @patch("TrueCore.dev.real_packet_regression_library.process_packet")
    def test_evaluate_case_passes_when_expected_values_match(self, mock_process_packet, mock_exists):
        mock_exists.return_value = True
        mock_process_packet.return_value = make_result()
        case = regression_library.RealPacketCase(
            case_id="nickoles",
            mode="strict",
            description="Nickoles regression",
            file_path="C:\\temp\\nickoles.pdf",
            expected_profile="Authorization Request",
            expected_archetype="Referral-Backed Treatment History",
            min_score=60,
            max_score=75,
            required_forms={"VA Form 10-7080", "Clinical Notes"},
            required_issue_fragments={"Missing Consultation & Treatment Request"},
            required_missing_fragments={"Missing required document: Consultation & Treatment Request"},
            expected_fields={"patient_name": "Nickoles, Billy"},
            contains_fields={"reason_for_request": "pain treatment options"},
        )

        result = regression_library._evaluate_case(case)

        self.assertTrue(result["available"])
        self.assertTrue(result["passed"])

    @patch("TrueCore.dev.real_packet_regression_library.os.path.exists")
    def test_evaluate_case_skips_when_file_missing(self, mock_exists):
        mock_exists.return_value = False
        case = regression_library.RealPacketCase(
            case_id="missing",
            mode="tracking",
            description="Missing file case",
            file_path="C:\\temp\\missing.pdf",
        )

        result = regression_library._evaluate_case(case)

        self.assertFalse(result["available"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["reason"], "file_missing")

    @patch("TrueCore.dev.real_packet_regression_library.load_real_packet_cases")
    def test_run_real_packet_regression_library_summarizes_results(self, mock_cases):
        mock_cases.return_value = [
            regression_library.RealPacketCase(
                case_id="strict_case",
                mode="strict",
                description="Strict case",
                file_path="C:\\temp\\strict.pdf",
            ),
            regression_library.RealPacketCase(
                case_id="tracking_case",
                mode="tracking",
                description="Tracking case",
                file_path="C:\\temp\\tracking.pdf",
            ),
        ]

        with patch("TrueCore.dev.real_packet_regression_library._evaluate_case") as mock_eval:
            mock_eval.side_effect = [
                {
                    "case": mock_cases.return_value[0],
                    "available": True,
                    "passed": True,
                    "checks": [],
                    "observed": {},
                    "reason": None,
                },
                {
                    "case": mock_cases.return_value[1],
                    "available": True,
                    "passed": False,
                    "checks": [],
                    "observed": {},
                    "reason": None,
                },
            ]

            summary = regression_library.run_real_packet_regression_library(verbose=False)

        self.assertTrue(summary["strict_pass"])
        self.assertEqual(len(summary["available_results"]), 2)
        self.assertEqual(len(summary["tracking_results"]), 1)


if __name__ == "__main__":
    unittest.main()
