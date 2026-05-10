import os
import tempfile
import unittest
from unittest import mock

from TrueCore.launcher import launcher_support


class LauncherSupportTests(unittest.TestCase):
    def test_build_launcher_support_snapshot_writes_expected_payload(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.object(
                launcher_support,
                "get_launcher_support_request_dir",
                return_value=temp_dir,
            ), mock.patch.object(
                launcher_support,
                "load_office_profile",
                return_value={
                    "organization_id": "org-1",
                    "office_id": "office-1",
                    "office_name": "Demo Office",
                    "install_id": "install-abc",
                },
            ), mock.patch.object(
                launcher_support,
                "load_launcher_release_info",
                return_value={
                    "version": "4.4",
                    "build_id": "L-123",
                    "build_timestamp": "2026-05-09 22:00:00",
                    "release_channel": "https://example.com/version.json",
                },
            ), mock.patch.object(
                launcher_support,
                "get_local_version",
                return_value="4.3",
            ), mock.patch.object(
                launcher_support,
                "verify_installed_engine_integrity",
                return_value={"status": "verified", "version": "4.3"},
            ):
                output_path, payload = launcher_support.build_launcher_support_snapshot(
                    "forgot_password",
                    update_state={"status": "installed", "server_version": "4.4"},
                )

                self.assertTrue(os.path.exists(output_path))
                self.assertEqual(payload["request_type"], "forgot_password")
                self.assertEqual(payload["office"]["office_name"], "Demo Office")
                self.assertEqual(payload["launcher"]["version"], "4.4")
                self.assertEqual(payload["engine"]["installed_version"], "4.3")

    def test_build_support_mailto_url_contains_snapshot_and_versions(self):
        payload = {
            "office": {"office_name": "Demo Office", "office_id": "office-1", "install_id": "install-abc"},
            "launcher": {"version": "4.4", "build_id": "L-123"},
            "engine": {"installed_version": "4.3", "integrity_status": "verified"},
            "update_state": {"status": "installed", "server_version": "4.4"},
        }

        url = launcher_support.build_support_mailto_url(
            "forgot_username",
            "C:\\snapshot.json",
            payload,
            recipient="it@example.com",
        )

        self.assertIn("mailto:it%40example.com", url)
        self.assertIn("TrueCore%20Forgot%20Username%20Request", url)
        self.assertIn("C%3A%5Csnapshot.json", url)


if __name__ == "__main__":
    unittest.main()
