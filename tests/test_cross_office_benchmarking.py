import tempfile
import unittest
from unittest import mock

from TrueCore.core import cross_office_benchmarking


def make_snapshot(office_id, office_name, score_values):
    runs = []
    for index, score in enumerate(score_values, start=1):
        runs.append(
            {
                "run_id": f"{office_id}-run-{index}",
                "packet_key": f"{office_id}-packet-{index}",
                "analyzed_at": "2026-05-08T10:00:00Z",
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
        "generated_at": "2026-05-08T10:00:00Z",
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
                "created_at": "2026-05-08T12:00:00Z",
                "event_type": "manual_outcome",
                "event_status": "approved",
            }
        ],
    }


class CrossOfficeBenchmarkingTests(unittest.TestCase):

    def test_validate_snapshot_rejects_missing_office_keys(self):
        result = cross_office_benchmarking.validate_cross_office_snapshot(
            {
                "schema_version": "1.0",
                "generated_at": "2026-05-08T10:00:00Z",
                "office": {"office_id": "only-one-key"},
                "runs": [],
                "events": [],
            }
        )

        self.assertFalse(result["valid"])
        self.assertTrue(any("Missing office keys" in error for error in result["errors"]))

    def test_build_network_rollup_ranks_offices_and_aggregates_summary(self):
        alpha = make_snapshot("alpha", "Alpha Office", [92, 88])
        beta = make_snapshot("beta", "Beta Office", [65, 60])

        rollup = cross_office_benchmarking.build_network_rollup([alpha, beta])

        self.assertEqual(rollup["office_count"], 2)
        self.assertEqual(rollup["organization_count"], 1)
        self.assertEqual(rollup["total_packet_count"], 4)
        self.assertEqual(rollup["office_rankings"][0]["office_id"], "alpha")
        self.assertEqual(rollup["office_rankings"][0]["standing"], "strong")
        self.assertEqual(rollup["office_rankings"][1]["office_id"], "beta")
        self.assertEqual(rollup["manual_outcome_distribution"], {"approved": 2})

    def test_export_network_rollup_writes_json(self):
        snapshot = make_snapshot("alpha", "Alpha Office", [92])

        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/network_rollup.json"
            output_path = cross_office_benchmarking.export_network_rollup(
                snapshots=[snapshot],
                path=path,
            )

            self.assertEqual(output_path, path)

    def test_import_snapshot_files_and_build_local_rollup(self):
        snapshot = make_snapshot("alpha", "Alpha Office", [92])

        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = f"{temp_dir}/alpha_snapshot.json"
            imported_dir = f"{temp_dir}/imports"
            rollup_path = f"{temp_dir}/network_rollup.json"

            with open(source_path, "w", encoding="utf-8") as handle:
                import json
                json.dump(snapshot, handle, indent=4)

            imported = cross_office_benchmarking.import_cross_office_snapshot_files(
                [source_path],
                directory=imported_dir,
            )
            self.assertEqual(len(imported), 1)
            self.assertEqual(len(cross_office_benchmarking.list_imported_snapshot_files(directory=imported_dir)), 1)

            local_snapshot = make_snapshot("local", "Local Office", [88])
            with mock.patch.object(cross_office_benchmarking, "build_cross_office_snapshot", return_value=local_snapshot):
                output = cross_office_benchmarking.build_local_network_rollup(
                    include_current_office=True,
                    imported_directory=imported_dir,
                    path=rollup_path,
                )

            self.assertEqual(output, rollup_path)
            rollup = cross_office_benchmarking.load_network_rollup(path=rollup_path)
            self.assertEqual(rollup["office_count"], 2)
            self.assertEqual(rollup["total_packet_count"], 2)

    def test_build_network_rollup_uses_latest_snapshot_per_office(self):
        older = make_snapshot("alpha", "Alpha Office", [90, 88])
        older["generated_at"] = "2026-05-07T10:00:00Z"
        newer = make_snapshot("alpha", "Alpha Office", [72])
        newer["generated_at"] = "2026-05-08T10:00:00Z"

        rollup = cross_office_benchmarking.build_network_rollup([older, newer])

        self.assertEqual(rollup["office_count"], 1)
        self.assertEqual(rollup["source_snapshot_count"], 2)
        self.assertEqual(rollup["current_snapshot_count"], 1)
        self.assertEqual(rollup["total_packet_count"], 1)
        self.assertEqual(rollup["office_rankings"][0]["average_packet_score"], 72.0)


if __name__ == "__main__":
    unittest.main()
