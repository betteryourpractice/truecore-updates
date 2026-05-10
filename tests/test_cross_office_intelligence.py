import unittest

from TrueCore.core import cross_office_intelligence


def make_snapshot(office_id, office_name, score_values, generated_at, runtime_base=12.0):
    runs = []
    for index, score in enumerate(score_values, start=1):
        runs.append(
            {
                "run_id": f"{office_id}-run-{index}",
                "packet_key": f"{office_id}-packet-{index}",
                "analyzed_at": generated_at,
                "packet_score": score,
                "status": "approved" if score >= 80 else "needs_review",
                "denial_risk": "low" if score >= 80 else "high",
                "workflow_queue": "review_queue" if score >= 80 else "correction_queue",
                "forms": ["clinical_notes", "consult_request"],
                "issue_labels": ["Missing Consultation & Treatment Request"] if score < 80 else [],
                "packet_confidence": 0.82 if score >= 80 else 0.58,
                "runtime_seconds": runtime_base + index,
                "scan_quality_score": 0.88 if score >= 80 else 0.72,
            }
        )

    return {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "office": {
            "organization_id": "org-1",
            "office_id": office_id,
            "office_name": office_name,
            "install_id": f"{office_id}-install",
        },
        "summary": {},
        "runs": runs,
        "events": [
            {
                "event_id": f"{office_id}-event-1",
                "packet_key": f"{office_id}-packet-1",
                "created_at": generated_at,
                "event_type": "manual_outcome",
                "event_status": "approved" if score_values and score_values[0] >= 80 else "corrected",
            }
        ],
    }


class CrossOfficeIntelligenceTests(unittest.TestCase):

    def test_build_office_trend_history_computes_deltas(self):
        alpha_old = make_snapshot("alpha", "Alpha Office", [90, 86], "2026-05-07T10:00:00Z")
        alpha_new = make_snapshot("alpha", "Alpha Office", [70, 68], "2026-05-08T10:00:00Z", runtime_base=18.0)

        histories = cross_office_intelligence.build_office_trend_history([alpha_old, alpha_new])

        self.assertEqual(len(histories), 1)
        self.assertEqual(histories[0]["office_id"], "alpha")
        self.assertLess(histories[0]["score_delta"], 0)
        self.assertGreater(histories[0]["runtime_delta"], 0)

    def test_build_cross_office_intelligence_creates_priority_alerts(self):
        alpha_old = make_snapshot("alpha", "Alpha Office", [90, 86], "2026-05-07T10:00:00Z")
        alpha_new = make_snapshot("alpha", "Alpha Office", [70, 68], "2026-05-08T10:00:00Z", runtime_base=18.0)
        beta_new = make_snapshot("beta", "Beta Office", [92, 89], "2026-05-08T10:00:00Z", runtime_base=10.0)

        intelligence = cross_office_intelligence.build_cross_office_intelligence([alpha_old, alpha_new, beta_new])

        self.assertEqual(intelligence["current_office_count"], 2)
        self.assertTrue(intelligence["priority_alerts"])
        self.assertEqual(intelligence["network_summary"]["best_office"], "Beta Office")
        self.assertEqual(intelligence["watchlist"][0]["office_name"], "Alpha Office")


if __name__ == "__main__":
    unittest.main()
