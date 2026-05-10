import os
import tempfile
import unittest
from unittest import mock

from TrueCore.utils import runtime_info


class RuntimeInfoTests(unittest.TestCase):

    def test_runtime_data_path_uses_shared_appdata_root_in_development(self):
        expected_root = r"C:\Work\TrueCore Packet Assistant"
        expected_truecore = expected_root + r"\TrueCore"
        expected_data_root = r"C:\Users\Test\AppData\Local\TrueCore"

        with mock.patch.object(runtime_info.sys, "frozen", False, create=True):
            with mock.patch("TrueCore.utils.runtime_info.os.path.abspath", return_value=expected_root):
                with mock.patch.dict("TrueCore.utils.runtime_info.os.environ", {"LOCALAPPDATA": r"C:\Users\Test\AppData\Local"}, clear=False):
                    with mock.patch("TrueCore.utils.runtime_info.ensure_runtime_data_root", return_value=expected_data_root):
                        self.assertEqual(runtime_info.get_runtime_root(), expected_root)
                        self.assertEqual(runtime_info.get_runtime_project_dir(), expected_truecore)
                        self.assertEqual(runtime_info.get_runtime_data_root(), expected_data_root)
                        self.assertEqual(
                            runtime_info.runtime_data_path("Outputs", "truecore_memory.db"),
                            expected_data_root + r"\Outputs\truecore_memory.db",
                        )

    def test_runtime_root_uses_parent_of_engine_folder_when_frozen(self):
        with mock.patch.object(runtime_info.sys, "frozen", True, create=True):
            with mock.patch.object(runtime_info.sys, "executable", r"C:\Deploy\engine\TrueCoreEngine.exe"):
                self.assertEqual(runtime_info.get_runtime_root(), r"C:\Deploy")
                self.assertEqual(runtime_info.get_runtime_project_dir(), r"C:\Deploy\TrueCore")

    def test_runtime_data_root_migrates_richer_legacy_memory_db(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target_root = os.path.join(temp_dir, "appdata_truecore")
            legacy_root = os.path.join(temp_dir, "legacy_truecore")

            os.makedirs(os.path.join(target_root, "Outputs"), exist_ok=True)
            os.makedirs(os.path.join(legacy_root, "Outputs"), exist_ok=True)

            target_db = os.path.join(target_root, "Outputs", "truecore_memory.db")
            legacy_db = os.path.join(legacy_root, "Outputs", "truecore_memory.db")

            with open(target_db, "wb") as handle:
                handle.write(b"tiny")
            with open(legacy_db, "wb") as handle:
                handle.write(b"legacy-history-data")

            original_ready = runtime_info._RUNTIME_DATA_READY
            try:
                runtime_info._RUNTIME_DATA_READY = False
                with mock.patch("TrueCore.utils.runtime_info.get_runtime_data_root", return_value=target_root):
                    with mock.patch("TrueCore.utils.runtime_info._legacy_runtime_project_dirs", return_value=[legacy_root]):
                        resolved = runtime_info.ensure_runtime_data_root()
                        self.assertEqual(resolved, target_root)
                        with open(target_db, "rb") as handle:
                            self.assertEqual(handle.read(), b"legacy-history-data")
            finally:
                runtime_info._RUNTIME_DATA_READY = original_ready


if __name__ == "__main__":
    unittest.main()
