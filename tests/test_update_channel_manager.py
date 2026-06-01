import json
import os
import tempfile
import unittest
from unittest.mock import patch

from TrueCore.dev import update_channel_manager
from TrueCore.utils.release_signing import load_public_key, verify_manifest_signature


class UpdateChannelManagerTests(unittest.TestCase):

    def test_seed_dev_manifest_from_production_writes_signed_dev_manifest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            production_manifest_path = os.path.join(temp_dir, "version.json")
            dev_manifest_path = os.path.join(temp_dir, "version-dev.json")
            private_key_path = os.path.join(temp_dir, "release_signing_private.pem")
            public_key_path = os.path.join(temp_dir, "release_signing_public.pem")

            with open(production_manifest_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "version": "5",
                        "download": "https://example.com/TrueCore_v5.zip",
                        "sha256": "abc123",
                        "size": 123,
                        "build_id": "TC5-20260529-0001",
                        "published_at": "2026-05-29 08:00:00",
                        "signature_algorithm": "ed25519",
                        "signature_key_id": "old-key",
                        "signature": "old-signature",
                    },
                    handle,
                    indent=4,
                )

            with patch.object(update_channel_manager, "VERSION_JSON_PATH", production_manifest_path), patch.object(
                update_channel_manager, "VERSION_DEV_JSON_PATH", dev_manifest_path
            ), patch.object(update_channel_manager, "SIGNING_PRIVATE_KEY_PATH", private_key_path), patch.object(
                update_channel_manager, "SIGNING_PUBLIC_KEY_PATH", public_key_path
            ):
                output_path, payload = update_channel_manager.seed_dev_manifest_from_production(
                    version="5-dev1",
                    download="https://example.com/TrueCore_v5-dev1.zip",
                )

            self.assertEqual(output_path, dev_manifest_path)
            self.assertTrue(os.path.exists(dev_manifest_path))
            self.assertEqual(payload["channel"], "dev")
            self.assertEqual(payload["promoted_from_channel"], "production")
            self.assertEqual(payload["version"], "5-dev1")
            self.assertEqual(payload["download"], "https://example.com/TrueCore_v5-dev1.zip")

            public_key = load_public_key(public_key_path)
            self.assertTrue(verify_manifest_signature(payload, payload["signature"], public_key))


if __name__ == "__main__":
    unittest.main()
