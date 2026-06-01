import os
import tempfile
import unittest
from unittest.mock import patch

from TrueCore.utils import private_dev_channel


class PrivateDevChannelTests(unittest.TestCase):

    def test_private_dev_channel_requires_repo_and_token(self):
        disabled = private_dev_channel.normalize_private_dev_channel_config({})
        self.assertFalse(private_dev_channel.is_private_dev_channel_enabled(disabled))

        enabled = private_dev_channel.normalize_private_dev_channel_config(
            {
                "enabled": True,
                "owner": "betteryourpractice",
                "repo": "truecore-dev-updates",
                "token": "abc123",
            }
        )
        self.assertTrue(private_dev_channel.is_private_dev_channel_enabled(enabled))
        self.assertEqual(
            private_dev_channel.get_private_dev_repo_slug(enabled),
            "betteryourpractice/truecore-dev-updates",
        )

    def test_private_dev_channel_config_persists(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "private_dev_channel.json")

            with patch.object(private_dev_channel, "PRIVATE_DEV_CHANNEL_CONFIG_PATH", config_path):
                private_dev_channel.save_private_dev_channel_config(
                    {
                        "enabled": True,
                        "owner": "betteryourpractice",
                        "repo": "truecore-dev-updates",
                        "token": "abc123",
                    }
                )
                payload = private_dev_channel.load_private_dev_channel_config()

            self.assertTrue(payload["enabled"])
            self.assertEqual(payload["owner"], "betteryourpractice")
            self.assertEqual(payload["repo"], "truecore-dev-updates")


if __name__ == "__main__":
    unittest.main()
