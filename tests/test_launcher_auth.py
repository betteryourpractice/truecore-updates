import tempfile
import unittest
from unittest import mock

from TrueCore.utils import launcher_auth


class LauncherAuthTests(unittest.TestCase):

    def test_verify_launcher_credentials_accepts_expected_pair(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            auth_path = f"{temp_dir}/launcher_auth.json"
            with mock.patch.object(launcher_auth, "LAUNCHER_AUTH_PATH", auth_path):
                launcher_auth.ensure_launcher_auth_config()
                self.assertTrue(launcher_auth.verify_launcher_credentials("truevalour", "athena"))

    def test_verify_launcher_credentials_rejects_wrong_username_or_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            auth_path = f"{temp_dir}/launcher_auth.json"
            with mock.patch.object(launcher_auth, "LAUNCHER_AUTH_PATH", auth_path):
                launcher_auth.ensure_launcher_auth_config()
                self.assertFalse(launcher_auth.verify_launcher_credentials("wrong", "athena"))
                self.assertFalse(launcher_auth.verify_launcher_credentials("truevalour", "wrong"))


if __name__ == "__main__":
    unittest.main()
