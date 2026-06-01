import unittest

from TrueCore.ui.pyside_gui.main_window_packet_ui_mixin import MainWindowPacketUiMixin
from TrueCore.ui.pyside_gui.packet_details_renderer import render_build_export_summary


class _SemanticReportingPresenter(MainWindowPacketUiMixin):
    def intel_payload(self, result):
        return dict((result or {}).get("intel", {}) or {})

    def get_nested_value(self, mapping, *keys, default=None):
        current = mapping
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                return default
            current = current.get(key)
        return current

    def format_detail_value(self, value):
        if value in (None, "", [], {}):
            return "Missing"
        if isinstance(value, (list, tuple)):
            return ", ".join(str(item) for item in value)
        return str(value)

    def format_packet_display_value(self, label, value):
        return self.format_detail_value(value)

    def format_field(self, value):
        return str(value or "").replace("_", " ").title()

    def format_review_flag(self, flag):
        return str(flag or "").replace("_", " ")

    def build_detail_card(self, *args, **kwargs):
        return ""

    def build_bullet_section(self, *args, **kwargs):
        return ""

    def build_detail_table(self, *args, **kwargs):
        return ""


class Phase3SemanticReportingTests(unittest.TestCase):
    def setUp(self):
        self.presenter = _SemanticReportingPresenter()

    def test_deduction_ledger_groups_real_gap_and_review_caution(self):
        intel_display = {
            "deduction_ledger": [
                {
                    "trust_level": "real_gap",
                    "reason": "Supporting document could not be confirmed: imaging_report",
                },
                {
                    "trust_level": "review_caution",
                    "reason": "partial_diagnosis_icd_alignment",
                },
            ]
        }

        grouped = self.presenter.group_deduction_ledger(intel_display)
        summary = self.presenter.summarize_deduction_ledger(intel_display)

        self.assertEqual(
            grouped["real_gap"],
            ["Supporting document could not be confirmed: Imaging Report"],
        )
        self.assertEqual(
            grouped["review_caution"],
            ["Diagnosis and ICD support are present but only partially aligned."],
        )
        self.assertEqual(summary, "1 real gap | 1 review caution")

    def test_export_summary_includes_semantic_reporting_fields(self):
        result = {
            "intel": {
                "display": {
                    "semantic_coherence": "Strong (93)",
                    "semantic_review_notes": [
                        "Packet meaning remains coherent even though the office formatting varies."
                    ],
                    "deduction_ledger": [
                        {
                            "trust_level": "real_gap",
                            "reason": "Supporting document could not be confirmed: imaging_report",
                        },
                        {
                            "trust_level": "variant_tolerated",
                            "reason": "High format variation was detected, but the packet story still reconciles coherently.",
                        },
                    ],
                }
            }
        }

        export_summary = render_build_export_summary(self.presenter, result)

        self.assertEqual(export_summary.get("semantic_coherence"), "Strong (93)")
        self.assertEqual(
            export_summary.get("semantic_review_notes"),
            ["Packet meaning remains coherent even though the office formatting varies."],
        )
        self.assertEqual(export_summary.get("deduction_ledger_summary"), "1 real gap | 1 variant tolerated")
        self.assertEqual(
            export_summary.get("deduction_real_gaps"),
            ["Supporting document could not be confirmed: Imaging Report"],
        )
        self.assertEqual(
            export_summary.get("deduction_variant_tolerated"),
            ["High format variation was detected, but the packet story still reconciles coherently."],
        )


if __name__ == "__main__":
    unittest.main()
