from __future__ import annotations

import io
import os
import shutil
import zipfile
from pathlib import Path


SECTION_LABELS = {
    "01_Read_First": "Read First",
    "02_Office_Onboarding": "Office Onboarding",
    "03_Patient_Submission_Templates": "Patient Submission Templates",
    "04_Sample_Completed_Packet": "Sample Completed Packets",
}


def _safe_name(value):
    return str(value or "").replace("\\", "/").strip("/")


def _read_nested_entries(outer_zip_path):
    with zipfile.ZipFile(outer_zip_path) as outer_zip:
        nested_archives = [name for name in outer_zip.namelist() if name.lower().endswith(".zip")]
        if not nested_archives:
            return []

        nested_name = nested_archives[0]
        with outer_zip.open(nested_name) as nested_file:
            nested_bytes = nested_file.read()

    with zipfile.ZipFile(io.BytesIO(nested_bytes)) as nested_zip:
        return [_safe_name(name) for name in nested_zip.namelist() if _safe_name(name) and not name.endswith("/")]


def build_docs_catalog(outer_zip_path):
    entries = _read_nested_entries(outer_zip_path)
    sections = {}

    for entry in entries:
        parts = entry.split("/", 1)
        section_key = parts[0] if parts else "Other"
        display_name = SECTION_LABELS.get(section_key, section_key or "Other")
        relative_name = parts[1] if len(parts) > 1 else parts[0]
        sections.setdefault(display_name, []).append(relative_name)

    return {
        "source_zip": str(outer_zip_path),
        "document_count": len(entries),
        "sections": {
            label: sorted(items)
            for label, items in sorted(sections.items())
        },
    }


def build_docs_index_text(catalog):
    lines = [
        "TrueCore Documentation Kit",
        "==========================",
        "",
        "This folder contains the onboarding and packet-building documents bundled with the launcher.",
        "",
        f"Total documents: {catalog.get('document_count', 0)}",
        "",
    ]

    for section, items in dict(catalog.get("sections") or {}).items():
        lines.append(section)
        lines.append("-" * len(section))
        for item in items:
            lines.append(f"- {item}")
        lines.append("")

    lines.append("Recommended reading order:")
    lines.append("1. Read First")
    lines.append("2. Office Onboarding")
    lines.append("3. Patient Submission Templates")
    lines.append("4. Sample Completed Packets")
    lines.append("")
    return "\n".join(lines)


def export_docs_bundle(outer_zip_path, destination_root):
    outer_zip_path = Path(outer_zip_path)
    destination_root = Path(destination_root)
    bundle_dir = destination_root / "TrueCore Onboarding Kit"

    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    catalog = build_docs_catalog(outer_zip_path)

    copied_zip_path = bundle_dir / outer_zip_path.name
    shutil.copyfile(outer_zip_path, copied_zip_path)

    with zipfile.ZipFile(outer_zip_path) as outer_zip:
        nested_name = next(name for name in outer_zip.namelist() if name.lower().endswith(".zip"))
        with outer_zip.open(nested_name) as nested_file:
            nested_bytes = nested_file.read()

    with zipfile.ZipFile(io.BytesIO(nested_bytes)) as nested_zip:
        nested_zip.extractall(bundle_dir)

    index_path = bundle_dir / "TrueCoreDocs_Index.txt"
    index_path.write_text(build_docs_index_text(catalog), encoding="utf-8")

    return {
        "bundle_dir": str(bundle_dir),
        "index_path": str(index_path),
        "zip_copy_path": str(copied_zip_path),
        "catalog": catalog,
    }
