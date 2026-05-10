import json
import os
import tempfile
import unittest
from unittest.mock import patch

from TrueCore.core import platform_scaling


class PlatformScalingTests(unittest.TestCase):

    @patch("TrueCore.core.platform_scaling.get_runtime_project_dir", return_value="C:\\TrueCore\\Project")
    @patch("TrueCore.core.platform_scaling.get_runtime_root", return_value="C:\\TrueCore")
    @patch("TrueCore.core.platform_scaling.load_active_network_intelligence_package", return_value={"generated_at": "2026-05-08T12:00:00Z"})
    @patch("TrueCore.core.platform_scaling.load_network_rollup", return_value={"office_count": 3})
    @patch("TrueCore.core.platform_scaling.list_imported_snapshot_files", return_value=["alpha.json", "beta.json"])
    @patch("TrueCore.core.platform_scaling.build_predictive_learning_snapshot")
    @patch("TrueCore.core.platform_scaling.get_recent_packet_events", return_value=[])
    @patch("TrueCore.core.platform_scaling.get_recent_packet_runs", return_value=[])
    @patch("TrueCore.core.platform_scaling.get_release_manifest", return_value={"version": "4.1"})
    @patch("TrueCore.core.platform_scaling.get_build_info", return_value=("TC41-20260505-1127", "2026-05-05 11:27:24"))
    @patch("TrueCore.core.platform_scaling.get_version", return_value="4.1")
    @patch("TrueCore.core.platform_scaling.memory_totals", return_value={"packet_count": 42, "case_count": 19, "provider_count": 7})
    @patch("TrueCore.core.platform_scaling.load_office_profile", return_value={
        "organization_id": "org-1",
        "office_id": "office-a",
        "office_name": "Office A",
        "install_id": "install-a",
    })
    def test_build_deployment_manifest_reports_platform_state(
        self,
        mock_office,
        mock_totals,
        mock_version,
        mock_build_info,
        mock_release_manifest,
        mock_recent_runs,
        mock_recent_events,
        mock_predictive_snapshot,
        mock_imported,
        mock_rollup,
        mock_network_package,
        mock_runtime_root,
        mock_runtime_project,
    ):
        mock_predictive_snapshot.return_value = {
            "model_summary": {
                "available": True,
                "model_type": "logistic_regression_platt_v1",
                "sample_size": 18,
                "reliability_band": "moderate",
                "reliability_score": 0.68,
            },
            "outcome_learning_health": {
                "maturity_band": "moderate",
                "approval_count": 8,
                "denial_count": 3,
                "override_count": 1,
            },
        }

        manifest = platform_scaling.build_deployment_manifest()

        self.assertEqual(manifest["platform"]["version"], "4.1")
        self.assertEqual(manifest["deployment"]["office_name"], "Office A")
        self.assertEqual(manifest["deployment"]["rollout_tier"], "single_office")
        self.assertEqual(manifest["data_state"]["imported_snapshot_count"], 2)
        self.assertEqual(manifest["learning_state"]["maturity_band"], "moderate")
        self.assertIn("office_rollout", manifest)
        self.assertEqual(manifest["platform_readiness"]["band"], "scale_ready")

    def test_export_support_bundle_writes_bundle_and_manifest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            support_path = os.path.join(temp_dir, "support_bundle.json")
            manifest_path = os.path.join(temp_dir, "deployment_manifest.json")

            with patch.object(platform_scaling, "SUPPORT_BUNDLE_OUTPUT_PATH", support_path), \
                 patch.object(platform_scaling, "DEPLOYMENT_MANIFEST_PATH", manifest_path), \
                 patch("TrueCore.core.platform_scaling.build_deployment_manifest", return_value={
                     "platform": {"version": "4.1"},
                     "deployment": {"office_name": "Office A"},
                     "platform_readiness": {"band": "operationally_ready"},
                 }), \
                 patch("TrueCore.core.platform_scaling.load_office_profile", return_value={"office_name": "Office A"}), \
                 patch("TrueCore.core.platform_scaling.load_network_rollup", return_value={"office_count": 2}), \
                 patch("TrueCore.core.platform_scaling.load_active_network_intelligence_package", return_value=None), \
                 patch("TrueCore.core.platform_scaling.list_imported_snapshot_files", return_value=["alpha.json"]), \
                 patch("TrueCore.core.platform_scaling.get_recent_packet_runs", return_value=[{"file_name": "Billy Nickoles Packet.pdf"}]), \
                 patch("TrueCore.core.platform_scaling.get_recent_packet_events", return_value=[{"event_type": "manual_outcome"}]):
                output_path = platform_scaling.export_support_bundle()

            self.assertEqual(output_path, support_path)
            self.assertTrue(os.path.exists(support_path))
            self.assertTrue(os.path.exists(manifest_path))

            with open(support_path, "r", encoding="utf-8") as handle:
                bundle = json.load(handle)

            self.assertEqual(bundle["office_profile"]["office_name"], "Office A")
            self.assertEqual(bundle["network_state"]["imported_snapshot_names"], ["alpha.json"])
            self.assertTrue(bundle["privacy_guard"]["phi_safe_export"])
            self.assertFalse(bundle["privacy_guard"]["raw_patient_file_names_included"])
            self.assertNotIn("recent_run_files", bundle["recent_activity_summary"])
            self.assertEqual(len(bundle["recent_activity_summary"]["recent_run_references"]), 1)
            self.assertNotIn("Billy Nickoles Packet.pdf", json.dumps(bundle))
            self.assertIn("payload_sha256", bundle["export_metadata"])


if __name__ == "__main__":
    unittest.main()
