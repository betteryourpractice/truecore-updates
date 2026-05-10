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


if __name__ == "__main__":
    unittest.main()
