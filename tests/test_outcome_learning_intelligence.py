import unittest
from unittest.mock import patch

from TrueCore.core import learning_intelligence
from TrueCore.core import outcome_learning_intelligence


def make_result(score=74, approval_probability=0.62, packet_confidence=0.78):
    return {
        "score": score,
        "forms": ["clinical_notes", "consult_request"],
        "issues": ["Missing Consultation & Treatment Request"],
        "fixes": ["Attach required document: Consultation & Treatment Request"],
        "fields": {
            "patient_name": "Example Patient",
            "dob": "01/01/1980",
            "authorization_number": "VA1234567890",
            "ordering_doctor": "Dana Example",
        },
        "intel": {
            "display": {
                "approval_probability": approval_probability,
                "packet_confidence": packet_confidence,
                "missing_items": ["Missing required document: Consultation & Treatment Request"],
                "review_flags": ["Manual Review Required"],
            },
            "scan_diagnostics": {
                "summary": {
                    "scan_quality_score": 0.81,
                    "average_ocr_confidence": 0.77,
                }
            },
        },
    }


class OutcomeLearningIntelligenceTests(unittest.TestCase):

    def test_predictive_outcome_modeling_detects_divergence(self):
        model = {
            "available": True,
            "base_probability": 0.28,
            "weights": {},
            "metrics": {
                "reliability_score": 0.73,
                "reliability_band": "moderate",
            },
        }
        model_summary = {
            "available": True,
            "sample_size": 22,
            "reliability_score": 0.73,
            "reliability_band": "moderate",
            "positive_rate": 0.28,
        }

        predictive = outcome_learning_intelligence.build_predictive_outcome_modeling(
            make_result(),
            model,
            model_summary,
        )

        self.assertEqual(predictive["agreement_status"], "divergent")
        self.assertEqual(predictive["honesty_band"], "developing")
        self.assertAlmostEqual(predictive["learned_approval_probability"], 0.28, places=2)

    def test_outcome_learning_health_tracks_maturity_and_counts(self):
        events = [
            {"event_type": "manual_outcome", "event_status": "approved"},
            {"event_type": "manual_outcome", "event_status": "approved"},
            {"event_type": "manual_outcome", "event_status": "denied"},
            {"event_type": "manual_outcome", "event_status": "corrected"},
            {"event_type": "manual_outcome", "event_status": "reviewer_override"},
        ]
        model_summary = {
            "available": True,
            "sample_size": 18,
            "positive_rate": 0.61,
            "reliability_score": 0.69,
            "reliability_band": "moderate",
            "brier_score": 0.18,
            "log_loss": 0.52,
            "roc_auc": 0.74,
            "ece": 0.08,
        }

        health = outcome_learning_intelligence.build_outcome_learning_health(events, model_summary)

        self.assertEqual(health["approval_count"], 2)
        self.assertEqual(health["denial_count"], 1)
        self.assertEqual(health["correction_count"], 1)
        self.assertEqual(health["override_count"], 1)
        self.assertEqual(health["maturity_band"], "moderate")

    def test_provider_outcome_learning_compares_to_global_rate(self):
        provider_history = [
            {"case_key": "case-1"},
            {"case_key": "case-2"},
            {"case_key": "case-3"},
            {"case_key": "case-4"},
        ]
        events = [
            {"case_key": "case-1", "created_at": "2026-05-08T10:00:00Z", "event_type": "manual_outcome", "event_status": "denied"},
            {"case_key": "case-2", "created_at": "2026-05-08T10:05:00Z", "event_type": "manual_outcome", "event_status": "denied"},
            {"case_key": "case-3", "created_at": "2026-05-08T10:06:00Z", "event_type": "manual_outcome", "event_status": "approved"},
            {"case_key": "case-4", "created_at": "2026-05-08T10:07:00Z", "event_type": "manual_outcome", "event_status": "denied"},
        ]
        model_summary = {"positive_rate": 0.65}

        provider_learning = outcome_learning_intelligence.build_provider_outcome_learning(
            "dana example",
            provider_history,
            events,
            model_summary,
        )

        self.assertEqual(provider_learning["status"], "underperforming")
        self.assertEqual(provider_learning["recent_signal"], "recent_denial_cluster")

    @patch("TrueCore.core.learning_intelligence.get_recent_packet_events")
    @patch("TrueCore.core.learning_intelligence.get_recent_packet_runs")
    @patch("TrueCore.core.learning_intelligence.get_provider_history")
    @patch("TrueCore.core.learning_intelligence.get_case_events")
    @patch("TrueCore.core.learning_intelligence.get_case_history")
    def test_learning_intelligence_exposes_predictive_layers(
        self,
        mock_case_history,
        mock_case_events,
        mock_provider_history,
        mock_recent_runs,
        mock_recent_events,
    ):
        mock_case_history.return_value = []
        mock_case_events.return_value = []
        mock_provider_history.return_value = [{"case_key": "case-1"}]
        mock_recent_runs.return_value = []
        mock_recent_events.return_value = []

        learning = learning_intelligence.build_learning_intelligence(
            "C:\\temp\\packet.pdf",
            make_result(),
            memory_intelligence={},
            triage_intelligence={},
        )

        self.assertIn("predictive_outcome_modeling", learning)
        self.assertIn("outcome_learning_health", learning)
        self.assertIn("provider_outcome_learning", learning)
        self.assertIn("prediction_watchpoints", learning)


if __name__ == "__main__":
    unittest.main()
