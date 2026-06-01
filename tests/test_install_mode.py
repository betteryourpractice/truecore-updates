import os
import tempfile
import unittest
from unittest.mock import patch

from TrueCore.utils import install_mode


class InstallModeTests(unittest.TestCase):

    def test_normalize_install_profile_defaults_dev_features_for_dev_role(self):
        profile = install_mode.normalize_install_profile({
            "machine_role": "dev",
        })

        self.assertEqual(profile["machine_role"], "dev")
        self.assertEqual(profile["update_channel"], "dev")
        self.assertTrue(profile["show_production_reference"])
        self.assertTrue(profile["developer_tools_enabled"])

    def test_normalize_install_profile_defaults_office_role_to_production(self):
        profile = install_mode.normalize_install_profile({})

        self.assertEqual(profile["machine_role"], "office")
        self.assertEqual(profile["update_channel"], "production")
        self.assertFalse(profile["show_production_reference"])
        self.assertFalse(profile["developer_tools_enabled"])

    def test_install_profile_persists_to_disk(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = os.path.join(temp_dir, "install_profile.json")

            with patch.object(install_mode, "INSTALL_PROFILE_PATH", profile_path):
                install_mode.ensure_install_profile()
                install_mode.update_install_profile({
                    "machine_role": "dev",
                    "update_channel": "production",
                })
                profile = install_mode.load_install_profile()

            self.assertEqual(profile["machine_role"], "dev")
            self.assertEqual(profile["update_channel"], "production")


if __name__ == "__main__":
    unittest.main()
