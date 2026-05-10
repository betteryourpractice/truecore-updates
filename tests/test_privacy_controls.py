import os
import json
import tempfile
import unittest
from unittest.mock import patch

from TrueCore.core import privacy_controls


class PrivacyControlsTests(unittest.TestCase):

    def test_export_local_phi_reset_archive_writes_deidentified_archive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_dir = os.path.join(temp_dir, "archives")
            archive_path = os.path.join(archive_dir, "archive.json")

            with patch.object(privacy_controls, "PRIVACY_RESET_ARCHIVE_DIR", archive_dir), \
                 patch("TrueCore.core.privacy_controls.load_office_profile", return_value={
                     "organization_id": "org-1",
                     "office_id": "office-a",
                     "office_name": "Office A",
                     "install_id": "install-a",
                 }), \
                 patch("TrueCore.core.privacy_controls.build_local_phi_storage_status", return_value={
                     "memory_database": {"exists": True},
                     "legacy_workbook": {"exists": False},
                 }), \
                 patch("TrueCore.core.privacy_controls.build_support_bundle", return_value={"privacy_guard": {"phi_safe_export": True}}), \
                 patch("TrueCore.core.privacy_controls.build_cross_office_snapshot", return_value={"summary": {"packet_count": 5}}):
                output_path = privacy_controls.export_local_phi_reset_archive(path=archive_path)

            self.assertEqual(output_path, archive_path)
            self.assertTrue(os.path.exists(archive_path))

            with open(archive_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)

            self.assertEqual(payload["archive_type"], "local_phi_reset_archive")
            self.assertEqual(payload["office"]["office_name"], "Office A")
            self.assertTrue(payload["support_bundle"]["privacy_guard"]["phi_safe_export"])
            self.assertEqual(payload["cross_office_snapshot"]["summary"]["packet_count"], 5)

    def test_status_and_purge_cover_local_storage_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            memory_db_path = os.path.join(temp_dir, "truecore_memory.db")
            workbook_path = os.path.join(temp_dir, "TrueValour Operations.xlsx")

            with open(memory_db_path, "w", encoding="utf-8") as handle:
                handle.write("db")
            with open(workbook_path, "w", encoding="utf-8") as handle:
                handle.write("workbook")

            def fake_purge_memory_database():
                removed = []
                for path in [memory_db_path, f"{memory_db_path}-wal", f"{memory_db_path}-shm"]:
                    if os.path.exists(path):
                        os.remove(path)
                        removed.append(path)
                return removed

            with patch.object(privacy_controls, "MEMORY_DB_PATH", memory_db_path), \
                 patch.object(privacy_controls, "LEGACY_WORKBOOK_PATH", workbook_path), \
                 patch.object(privacy_controls, "purge_memory_database", side_effect=fake_purge_memory_database):
                before = privacy_controls.build_local_phi_storage_status()
                outcome = privacy_controls.purge_local_phi_storage()
                after = privacy_controls.build_local_phi_storage_status()

            self.assertTrue(before["memory_database"]["exists"])
            self.assertTrue(before["legacy_workbook"]["exists"])
            self.assertTrue(outcome["memory_database_removed"])
            self.assertTrue(outcome["legacy_workbook_removed"])
            self.assertFalse(after["memory_database"]["exists"])
            self.assertFalse(after["legacy_workbook"]["exists"])


if __name__ == "__main__":
    unittest.main()
