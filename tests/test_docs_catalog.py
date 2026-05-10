import io
import os
import tempfile
import unittest
import zipfile

from TrueCore.launcher.docs_catalog import build_docs_catalog, export_docs_bundle


def make_nested_docs_zip(path):
    inner_bytes = io.BytesIO()
    with zipfile.ZipFile(inner_bytes, "w") as inner_zip:
        inner_zip.writestr("01_Read_First/Guide.pdf", b"guide")
        inner_zip.writestr("02_Office_Onboarding/Registration.pdf", b"registration")
        inner_zip.writestr("03_Patient_Submission_Templates/VA_Form_10-10172.pdf", b"template")
        inner_zip.writestr("04_Sample_Completed_Packet/Sample Packet.pdf", b"sample")

    with zipfile.ZipFile(path, "w") as outer_zip:
        outer_zip.writestr("TrueDisc_VA_Complete_Submission_Program_v1.0.zip", inner_bytes.getvalue())


class DocsCatalogTests(unittest.TestCase):

    def test_build_docs_catalog_groups_nested_sections(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, "TrueCoreDocs.zip")
            make_nested_docs_zip(zip_path)

            catalog = build_docs_catalog(zip_path)

            self.assertEqual(catalog["document_count"], 4)
            self.assertIn("Read First", catalog["sections"])
            self.assertIn("Guide.pdf", catalog["sections"]["Read First"])
            self.assertIn("Patient Submission Templates", catalog["sections"])

    def test_export_docs_bundle_extracts_folder_and_index(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, "TrueCoreDocs.zip")
            make_nested_docs_zip(zip_path)

            exported = export_docs_bundle(zip_path, temp_dir)

            bundle_dir = exported["bundle_dir"]
            index_path = exported["index_path"]
            self.assertTrue(os.path.isdir(bundle_dir))
            self.assertTrue(os.path.exists(index_path))
            self.assertTrue(os.path.exists(os.path.join(bundle_dir, "01_Read_First", "Guide.pdf")))

            with open(index_path, "r", encoding="utf-8") as handle:
                index_text = handle.read()

            self.assertIn("TrueCore Documentation Kit", index_text)
            self.assertIn("Recommended reading order:", index_text)


if __name__ == "__main__":
    unittest.main()
