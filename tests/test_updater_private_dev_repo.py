import base64
import json
import unittest
from unittest.mock import patch

from TrueCore.launcher import updater


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class UpdaterPrivateDevRepoTests(unittest.TestCase):

    def test_check_updates_uses_private_dev_repo_when_enabled(self):
        manifest_payload = {
            "version": "dv1.0",
            "release_tag": "dv1.0",
            "sha256": "abc123",
            "size": 123,
            "channel": "dev",
        }
        encoded_manifest = base64.b64encode(
            json.dumps(manifest_payload).encode("utf-8")
        ).decode("ascii")

        config = {
            "enabled": True,
            "owner": "betteryourpractice",
            "repo": "truecore-dev-updates",
            "ref": "main",
            "manifest_path": "version-dev.json",
            "token": "dev-token",
            "asset_name_template": "TrueCore_{release_tag}.zip",
        }

        def fake_safe_request(url, timeout=10, retries=3, headers=None):
            if "/contents/" in url:
                return _FakeResponse(
                    200,
                    {
                        "content": encoded_manifest,
                        "encoding": "base64",
                    },
                )
            if "/releases/tags/" in url:
                return _FakeResponse(
                    200,
                    {
                        "assets": [
                            {
                                "name": "TrueCore_dv1.0.zip",
                                "url": "https://api.github.com/repos/betteryourpractice/truecore-dev-updates/releases/assets/99",
                            }
                        ]
                    },
                )
            raise AssertionError(f"Unexpected URL requested: {url}")

        with patch.object(updater, "is_private_dev_channel_enabled", return_value=True), patch.object(
            updater, "load_private_dev_channel_config", return_value=config
        ), patch.object(updater, "_verify_manifest_authenticity", return_value={"status": "verified"}), patch.object(
            updater, "get_local_version", return_value="dv0.9"
        ), patch.object(updater, "safe_request", side_effect=fake_safe_request):
            result = updater.check_updates("dev")

        self.assertEqual(result["status"], "update_available")
        self.assertEqual(result["version"], "dv1.0")
        self.assertEqual(
            result["download"],
            "https://api.github.com/repos/betteryourpractice/truecore-dev-updates/releases/assets/99",
        )
        self.assertEqual(result["asset_name"], "TrueCore_dv1.0.zip")
        self.assertEqual(result["repo"], "betteryourpractice/truecore-dev-updates")
        self.assertEqual(result["download_headers"]["Authorization"], "Bearer dev-token")
        self.assertEqual(result["download_headers"]["Accept"], "application/octet-stream")


if __name__ == "__main__":
    unittest.main()
