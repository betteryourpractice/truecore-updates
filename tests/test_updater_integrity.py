import io
import os
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from TrueCore.launcher import updater
from TrueCore.utils import release_signing


class UpdaterIntegrityTests(unittest.TestCase):

    def test_verify_download_integrity_accepts_matching_size_and_checksum(self):
        payload = b"truecore update payload"
        digest = updater._compute_sha256(payload)
        verified = updater._verify_download_integrity(payload, expected_sha256=digest, expected_size=len(payload))
        self.assertEqual(verified, digest)

    def test_verify_download_integrity_rejects_checksum_mismatch(self):
        payload = b"truecore update payload"
        with self.assertRaises(ValueError):
            updater._verify_download_integrity(payload, expected_sha256="0" * 64, expected_size=len(payload))

    def test_validate_archive_requires_engine_executable(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("notes.txt", "missing engine")

        buffer.seek(0)
        with zipfile.ZipFile(buffer) as archive:
            with self.assertRaises(ValueError):
                updater._validate_archive(archive)

    def test_verify_manifest_authenticity_accepts_valid_signature(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            private_path = os.path.join(temp_dir, "release_signing_private.pem")
            public_path = os.path.join(temp_dir, "release_signing_public.pem")
            private_key, public_key = release_signing.generate_signing_keypair(private_path, public_path)

            manifest = {
                "version": "4.2",
                "download": "https://example.com/TrueCore_v4.2.zip",
                "sha256": "a" * 64,
                "size": 1234,
                "signature_algorithm": release_signing.SIGNATURE_ALGORITHM,
                "signature_key_id": release_signing.public_key_id(public_key),
            }
            manifest["signature"] = release_signing.sign_manifest(manifest, private_key)

            with patch.object(updater, "get_launcher_resource_path", return_value=public_path):
                result = updater._verify_manifest_authenticity(manifest)

            self.assertEqual(result["status"], "verified")

    def test_verify_manifest_authenticity_rejects_invalid_signature(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            private_path = os.path.join(temp_dir, "release_signing_private.pem")
            public_path = os.path.join(temp_dir, "release_signing_public.pem")
            private_key, public_key = release_signing.generate_signing_keypair(private_path, public_path)

            manifest = {
                "version": "4.2",
                "download": "https://example.com/TrueCore_v4.2.zip",
                "sha256": "a" * 64,
                "size": 1234,
                "signature_algorithm": release_signing.SIGNATURE_ALGORITHM,
                "signature_key_id": release_signing.public_key_id(public_key),
                "signature": "not-a-real-signature",
            }

            with patch.object(updater, "get_launcher_resource_path", return_value=public_path):
                with self.assertRaises(ValueError):
                    updater._verify_manifest_authenticity(manifest)

    def test_verify_installed_engine_integrity_accepts_matching_engine_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            engine_dir = os.path.join(temp_dir, updater.ENGINE_DIR)
            os.makedirs(engine_dir, exist_ok=True)
            engine_path = os.path.join(engine_dir, updater.ENGINE_EXE)

            with open(engine_path, "wb") as handle:
                handle.write(b"engine-binary")

            engine_sha256 = updater._compute_file_sha256(engine_path)
            updater._write_engine_integrity_metadata(
                engine_dir,
                version="4.2",
                engine_sha256=engine_sha256,
                manifest_authentication={"status": "verified", "key_id": "abc123"},
            )

            result = updater.verify_installed_engine_integrity(base_dir=temp_dir)

            self.assertEqual(result["status"], "verified")
            self.assertEqual(result["version"], "4.2")

    def test_verify_installed_engine_integrity_detects_tampered_engine(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            engine_dir = os.path.join(temp_dir, updater.ENGINE_DIR)
            os.makedirs(engine_dir, exist_ok=True)
            engine_path = os.path.join(engine_dir, updater.ENGINE_EXE)

            with open(engine_path, "wb") as handle:
                handle.write(b"engine-binary")

            engine_sha256 = updater._compute_file_sha256(engine_path)
            updater._write_engine_integrity_metadata(
                engine_dir,
                version="4.2",
                engine_sha256=engine_sha256,
                manifest_authentication={"status": "verified", "key_id": "abc123"},
            )

            with open(engine_path, "wb") as handle:
                handle.write(b"modified-engine-binary")

            result = updater.verify_installed_engine_integrity(base_dir=temp_dir)

            self.assertEqual(result["status"], "tampered")


if __name__ == "__main__":
    unittest.main()
