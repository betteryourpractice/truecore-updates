import json
import tempfile
import unittest
from unittest import mock

from TrueCore.core import hybrid_sync


def make_snapshot(office_id, office_name, score_values, generated_at):
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
                "packet_confidence": 0.8 if score >= 80 else 0.6,
                "runtime_seconds": 12.0 + index,
                "scan_quality_score": 0.9 if score >= 80 else 0.7,
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
                "event_status": "approved",
            }
        ],
    }


class HybridSyncTests(unittest.TestCase):

    def test_build_office_sync_package_contains_snapshot_payload(self):
        snapshot = make_snapshot("local", "Local Office", [82], "2026-05-08T10:00:00Z")

        with mock.patch.object(hybrid_sync, "build_cross_office_snapshot", return_value=snapshot):
            package = hybrid_sync.build_office_sync_package()

        self.assertEqual(package["package_type"], "office_sync_package")
        self.assertEqual(package["payload"]["snapshot"]["office"]["office_id"], "local")

    def test_build_network_intelligence_package_contains_rollup_and_intelligence(self):
        alpha = make_snapshot("alpha", "Alpha Office", [92], "2026-05-08T10:00:00Z")
        beta = make_snapshot("beta", "Beta Office", [68], "2026-05-08T10:00:00Z")

        package = hybrid_sync.build_network_intelligence_package([alpha, beta])

        self.assertEqual(package["package_type"], "network_intelligence_package")
        self.assertIn("network_rollup", package["payload"])
        self.assertIn("cross_office_intelligence", package["payload"])

    def test_import_network_intelligence_package_activates_local_copy(self):
        alpha = make_snapshot("alpha", "Alpha Office", [92], "2026-05-08T10:00:00Z")
        package = hybrid_sync.build_network_intelligence_package([alpha])

        with tempfile.TemporaryDirectory() as temp_dir:
            package_path = f"{temp_dir}/network_package.json"
            active_path = f"{temp_dir}/active_network_package.json"

            with open(package_path, "w", encoding="utf-8") as handle:
                json.dump(package, handle, indent=4)

            with mock.patch.object(hybrid_sync, "ACTIVE_NETWORK_INTELLIGENCE_PACKAGE_PATH", active_path):
                imported_path = hybrid_sync.import_network_intelligence_package(package_path, directory=temp_dir)
                loaded = hybrid_sync.load_active_network_intelligence_package(path=active_path)

            self.assertTrue(imported_path.endswith(".json"))
            self.assertEqual(loaded["package_type"], "network_intelligence_package")


if __name__ == "__main__":
    unittest.main()
