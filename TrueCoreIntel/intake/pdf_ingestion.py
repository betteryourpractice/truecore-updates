import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import PyPDF2
try:
    import pdfplumber
except Exception:  # pragma: no cover - optional dependency fallback
    pdfplumber = None

try:
    from PIL import Image, ImageFilter, ImageOps, ImageStat
except Exception:  # pragma: no cover - optional dependency fallback
    Image = None
    ImageFilter = None
    ImageOps = None
    ImageStat = None

from TrueCoreIntel.intake.ocr_layout import (
    build_hybrid_page_metadata,
    layout_ocr_available,
    normalize_label,
    ocr_image_header_only,
    ocr_image_with_layout,
    preprocess_image_object_for_ocr,
    render_pdf_pages_as_images,
)
from TrueCoreIntel.intake.ocr_runtime import (
    available_ocr_providers,
    available_pdf_tools,
    build_execution_env,
    ocrmypdf_available,
    resolve_executable,
)


SUPPORTED_PACKET_EXTENSIONS = {
    ".pdf",
    ".docx",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
    ".tif",
    ".tiff",
    ".bmp",
}

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}
TEXT_EXTENSIONS = {".txt"}


AUTH_OCR_SIGNAL = re.compile(
    r"\b(?:ref(?:\.|erral)?\b\s*[:#\-]?\s*va(?:[\- ]?\d){6,}|va(?:[\- ]?\d){8,}|authorization|member id|10[\s\-]*10172|community care)\b",
    re.IGNORECASE,
)

AUTH_OCR_SNIPPET_PATTERNS = [
    re.compile(r"\bicn\b[^\n\r]{0,60}\bref(?:\.|erral)?\b[^\n\r]{0,30}\bva(?:[\- ]?\d){8,18}\b", re.IGNORECASE),
    re.compile(r"\bref(?:\.|erral)?\b[^\n\r]{0,20}\bva(?:[\- ]?\d){8,18}\b", re.IGNORECASE),
    re.compile(
        r"\b(?:authorization|auth|referral|member id|tracking number|reference number|case number|consult number|episode of care|seoc|10[\s\-]*10172|community care)\b[^\n\r]{0,120}\bva(?:[\- ]?\d){8,18}\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bva(?:[\- ]?\d){8,18}\b", re.IGNORECASE),
]

DOC_TITLE_OCR_PATTERNS = [
    ("cover_sheet", re.compile(r"\b(?:va\s+)?submission\s+cover\s+sheet\b", re.IGNORECASE)),
    ("rfs", re.compile(r"\b(?:medical\s+)?request\s+for\s+service(?:s)?\b|\b(?:va\s+form\s+)?10[\s\-]*10172\b", re.IGNORECASE)),
    ("seoc", re.compile(r"\bsingle\s+episode\s+of\s+care\b|\bseoc\b", re.IGNORECASE)),
    ("lomn", re.compile(r"\bletter\s+of\s+medical\s+necessity\b|\bmedical\s+necessity\s+letter\b", re.IGNORECASE)),
    ("consult_request", re.compile(r"\bconsultation\s+and\s+treatment\s+request\b|\bconsult\s+and\s+treatment\s+request\b", re.IGNORECASE)),
    ("clinical_notes", re.compile(r"\bclinical\s+documentation\s+template\b|\bclinical\s+notes?\b", re.IGNORECASE)),
    ("consent", re.compile(r"\btelehealth\s+virtual\s+consent\s+form\b|\bvirtual\s+consent\s+form\b|\bconsent\s+for\s+telehealth\b", re.IGNORECASE)),
]

OCR_STRUCTURED_LINE_PATTERNS = [
    re.compile(r"\b(?:veteran name|patient name|member name|name of veteran)\b", re.IGNORECASE),
    re.compile(r"\b(?:date of birth|dob|d\.o\.b\.)\b", re.IGNORECASE),
    re.compile(r"\b(?:authorization(?: number)?|auth(?: number)?|ref(?:\.|erral)?(?: number)?|member id|tracking number|reference number|case number|consult number|episode of care|seoc|10[\s\-]*10172)\b", re.IGNORECASE),
    re.compile(r"\b(?:ordering provider|ordering physician|requesting provider|requested by|referring provider|referring va provider|referring physician|referred by|ref provider|pcp|provider name|rendering provider|attending provider)\b", re.IGNORECASE),
    re.compile(r"\b(?:facility|medical facility|servicing facility|treating facility|requested facility|clinic|submitting office|practice name|city/state|location)\b", re.IGNORECASE),
    re.compile(r"\b(?:reason for request|reason for referral|chief complaint|requested service|requested procedure|diagnosis|assessment|impression|history of present illness)\b", re.IGNORECASE),
    re.compile(r"\b(?:icn|va icn|integrated control number|claim number|last four ssn|ssn ending|npi)\b", re.IGNORECASE),
    re.compile(r"\b(?:date of service|dates of service|service date|visit date|dos|date of submission|submission date|signed by|signature date|electronically signed)\b", re.IGNORECASE),
]

OCR_PAGE_EXCERPT_SIGNAL_PATTERNS = [
    AUTH_OCR_SIGNAL,
    re.compile(r"\b(?:veteran name|patient name|date of birth|dob)\b", re.IGNORECASE),
    re.compile(r"\b(?:ordering provider|referring provider|provider name|referring va provider)\b", re.IGNORECASE),
    re.compile(r"\b(?:reason for request|reason for referral|diagnosis|assessment|impression|history of present illness)\b", re.IGNORECASE),
    re.compile(r"\b(?:facility|clinic|medical center|hospital|vamc)\b", re.IGNORECASE),
    re.compile(r"\b(?:date of service|dates of service|service date|visit date|date of submission|submission date)\b", re.IGNORECASE),
]

OCR_PAGE_DOC_HINT_PATTERNS = [
    re.compile(r"\b(?:va\s+)?submission\s+cover\s+sheet\b", re.IGNORECASE),
    re.compile(r"\b(?:telehealth\s+)?virtual\s+consent(?:\s+form)?\b|\bconsent\s+for\s+telehealth\b", re.IGNORECASE),
    re.compile(r"\bconsult(?:ation)?\s+and\s+treatment\s+request\b", re.IGNORECASE),
    re.compile(r"\bsingle\s+episode\s+of\s+care\b|\bseoc\b", re.IGNORECASE),
    re.compile(r"\bmedical\s+necessity\b|\bletter\s+of\s+medical\s+necessity\b", re.IGNORECASE),
    re.compile(r"\b(?:request|reo?uest)\s+for\s+service(?:s)?\b|\b10[\s'\-]*10172\b", re.IGNORECASE),
]


def emit(log_fn, message):
    if log_fn:
        log_fn(message)


def resolve_pdf_object(value):
    try:
        return value.get_object()
    except Exception:
        return value


def normalize_pdf_form_value(value):
    value = resolve_pdf_object(value)

    if value is None:
        return None

    if isinstance(value, (list, tuple)):
        parts = [normalize_pdf_form_value(item) for item in value]
        parts = [part for part in parts if part]
        return ", ".join(parts) if parts else None

    text = normalize_pdf_text(str(value))

    if not text:
        return None

    text = text.strip("/")

    if text.lower() in {"off", "none", "null"}:
        return None

    if text.lower() in {"yes", "on", "checked"}:
        return "checked"

    return text


def extract_pdf_page_form_lines(page):
    lines = []
    seen = set()

    annotations = resolve_pdf_object(page.get("/Annots")) or []

    for annotation_ref in annotations:
        annotation = resolve_pdf_object(annotation_ref)

        if not isinstance(annotation, dict):
            continue

        if str(annotation.get("/Subtype")) != "/Widget":
            continue

        parent = resolve_pdf_object(annotation.get("/Parent")) or {}

        field_name = (
            normalize_pdf_form_value(annotation.get("/TU"))
            or normalize_pdf_form_value(annotation.get("/T"))
            or normalize_pdf_form_value(parent.get("/TU"))
            or normalize_pdf_form_value(parent.get("/T"))
        )

        field_value = normalize_pdf_form_value(annotation.get("/V"))
        if field_value is None:
            field_value = normalize_pdf_form_value(parent.get("/V"))

        if not field_name or not field_value:
            continue

        candidate = f"{field_name}: {field_value}"
        candidate_key = candidate.lower()

        if candidate_key in seen:
            continue

        seen.add(candidate_key)
        lines.append(candidate)

    return lines


def has_filled_consent_signals(text):
    filled_patterns = [
        r"full name[^\n\r:]{0,40}:\s*(?!date of birth\b|state\b|street address\b|home phone\b|email address\b|email\b|city\b|mobile phone\b|ssn\b|phone\b|zip\b|work phone\b)([A-Za-z][A-Za-z'\-]+(?:\s+[A-Za-z][A-Za-z'\-]+){1,3})",
        r"date of birth[^\n\r:]{0,40}:\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}",
        r"street address[^\n\r:]{0,40}:\s*\d{1,6}\s+[A-Za-z0-9.\- ]{3,}",
        r"(?:home phone|mobile phone|work phone|phone)[^\n\r:]{0,40}:\s*(?:\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}|\d{7,})",
        r"email(?: address)?[^\n\r:]{0,40}:\s*[\w.\-]+@[\w.\-]+\.\w+",
        r"\b(?:signature|signed)\b",
    ]
    return sum(
        1 for pattern in filled_patterns
        if re.search(pattern, text, re.IGNORECASE)
    )


def normalize_pdf_text(text):
    if not text:
        return ""

    text = text.replace("\r", "\n")
    text = re.sub(r"(?<=\w)-\n(?=\w)", "", text)
    text = re.sub(r"\n(?=[a-z])", " ", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{2,}", "\n", text)

    return text.strip()


def is_sparse_page_text(text):
    normalized = normalize_pdf_text(text)
    if not normalized:
        return True

    lines = [line.strip() for line in normalized.split("\n") if line.strip()]
    alpha_numeric = sum(ch.isalnum() for ch in normalized)
    return len(normalized) < 220 or (len(lines) <= 4 and alpha_numeric < 180)


def get_powershell_command():
    for command in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        if shutil.which(command):
            return command
    return None


def run_text_capture_command(arguments, log_fn=None, timeout=240):
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=False,
            timeout=timeout,
            env=build_execution_env(),
            check=False,
        )
    except Exception as exc:
        emit(log_fn, f"[DEBUG] Text capture command failed to start: {exc}")
        return None

    if completed.returncode != 0:
        stderr = normalize_pdf_text((completed.stderr or b"").decode("utf-8", errors="replace"))
        if stderr:
            emit(log_fn, f"[DEBUG] Text capture command failed: {stderr}")
        return None

    return (completed.stdout or b"").decode("utf-8", errors="replace")


def split_pages_from_formfeed(text):
    pages = [normalize_pdf_text(page) for page in str(text or "").split("\f")]
    while pages and not pages[-1]:
        pages.pop()
    return pages


def extract_pdf_pages_with_pdftotext(pdf_path, log_fn=None):
    pdftotext_path = resolve_executable("pdftotext")
    if not pdftotext_path:
        return []

    output = run_text_capture_command(
        [pdftotext_path, "-layout", str(pdf_path), "-"],
        log_fn=log_fn,
        timeout=240,
    )
    if not output:
        return []

    pages = split_pages_from_formfeed(output)
    if pages:
        emit(log_fn, f"[DEBUG] pdftotext extracted {len(pages)} page(s)")
    return pages


def build_searchable_pdf_with_ocrmypdf(pdf_path, log_fn=None):
    if not ocrmypdf_available():
        return None

    ocrmypdf_path = resolve_executable("ocrmypdf")
    if not ocrmypdf_path:
        return None

    temp_dir = Path(tempfile.mkdtemp(prefix="truecoreintel_ocrmypdf_"))
    output_pdf = temp_dir / f"{Path(pdf_path).stem}_searchable.pdf"
    command = [
        ocrmypdf_path,
        "--force-ocr",
        "--deskew",
        "--rotate-pages",
        "--clean-final",
        "--skip-big",
        "80",
        "--output-type",
        "pdf",
        str(pdf_path),
        str(output_pdf),
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=False,
            timeout=900,
            env=build_execution_env(),
            check=False,
        )
    except Exception as exc:
        emit(log_fn, f"[DEBUG] OCRmyPDF failed to start: {exc}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None

    if completed.returncode != 0 or not output_pdf.exists():
        stderr = normalize_pdf_text((completed.stderr or b"").decode("utf-8", errors="replace"))
        if stderr:
            emit(log_fn, f"[DEBUG] OCRmyPDF failed: {stderr}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None

    emit(log_fn, f"[DEBUG] OCRmyPDF generated searchable copy: {output_pdf}")
    return output_pdf


def cleanup_temporary_pdf(pdf_path, log_fn=None):
    if not pdf_path:
        return

    try:
        pdf_path = Path(pdf_path)
        parent = pdf_path.parent
        if pdf_path.exists():
            pdf_path.unlink()
        if parent.exists():
            parent.rmdir()
    except Exception as exc:
        emit(log_fn, f"[DEBUG] Unable to clean OCRmyPDF temp file: {exc}")


def run_windows_ocr_script(script, env, log_fn=None, timeout=240):
    shell = get_powershell_command()
    if not shell:
        return None

    try:
        completed = subprocess.run(
            [shell, "-NoProfile", "-Command", script],
            capture_output=True,
            text=False,
            timeout=timeout,
            env=env,
            check=False,
        )
    except Exception as exc:
        emit(log_fn, f"[DEBUG] OCR fallback failed to start: {exc}")
        return None

    if completed.returncode != 0:
        stderr = (completed.stderr or b"").decode("utf-8", errors="replace").strip()
        if stderr:
            emit(log_fn, f"[DEBUG] OCR fallback unavailable: {stderr}")
        return None

    stdout = (completed.stdout or b"").decode("ascii", errors="ignore").strip()
    if not stdout:
        return None

    try:
        payload = base64.b64decode(stdout)
        return json.loads(payload.decode("utf-8"))
    except Exception as exc:
        emit(log_fn, f"[DEBUG] OCR fallback produced invalid payload: {exc}")
        return None


def normalize_ocr_pages_payload(payload):
    if payload is None:
        return None
    if isinstance(payload, str):
        return [payload]
    if isinstance(payload, list):
        normalized = []
        for item in payload:
            if isinstance(item, str):
                normalized.append(item)
            elif item is not None:
                normalized.append(str(item))
        return normalized
    return [str(payload)]


def page_metadata_has_real_ocr_content(metadata):
    metadata = dict(metadata or {})
    if normalize_pdf_text(metadata.get("ocr_text")):
        return True
    if metadata.get("ocr_provider"):
        return True

    field_zones = list(metadata.get("field_zones", []) or [])
    if any(str(zone.get("zone_name") or "").lower() != "native_text" for zone in field_zones):
        return True

    layout = dict(metadata.get("layout", {}) or {})
    if layout.get("header_text") or layout.get("structured_line_count") or layout.get("field_zone_count"):
        return True

    return False


def merge_field_zones(primary_zones, secondary_zones):
    merged = []
    seen = set()

    for zone in list(primary_zones or []) + list(secondary_zones or []):
        label = normalize_label(zone.get("normalized_label") or zone.get("label") or "")
        value = normalize_pdf_text(zone.get("value"))
        zone_name = zone.get("zone_name")
        key = (label, value.lower(), zone_name)
        if not label or not value or key in seen:
            continue
        seen.add(key)
        candidate = dict(zone)
        candidate["normalized_label"] = label
        candidate["value"] = value
        merged.append(candidate)

    return merged


def merge_layout_maps(primary_layout, secondary_layout):
    merged = dict(primary_layout or {})
    secondary_layout = dict(secondary_layout or {})

    for key in ("header_text", "footer_text", "left_column_text", "right_column_text"):
        primary_value = normalize_pdf_text(merged.get(key))
        secondary_value = normalize_pdf_text(secondary_layout.get(key))
        if not secondary_value:
            continue
        if not primary_value:
            merged[key] = secondary_value
            continue
        if secondary_value.lower() not in primary_value.lower():
            merged[key] = normalize_pdf_text(f"{primary_value}\n{secondary_value}")

    for key in ("table_regions", "signature_regions", "handwritten_regions"):
        existing = list(merged.get(key, []) or [])
        existing.extend(list(secondary_layout.get(key, []) or []))
        merged[key] = existing

    for key in ("field_zone_count", "structured_line_count"):
        merged[key] = max(int(merged.get(key, 0) or 0), int(secondary_layout.get(key, 0) or 0))

    return merged


def build_zone_text(field_zones):
    lines = []
    seen = set()
    for zone in field_zones or []:
        label = normalize_pdf_text(zone.get("label") or zone.get("normalized_label"))
        value = normalize_pdf_text(zone.get("value"))
        if not label or not value:
            continue
        candidate = f"{label}: {value}"
        key = candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        lines.append(candidate)
    return normalize_pdf_text("\n".join(lines))


def finalize_page_text_from_metadata(metadata):
    metadata = dict(metadata or {})
    native_text = normalize_pdf_text(metadata.get("native_text"))
    ocr_text = normalize_pdf_text(metadata.get("ocr_text"))
    form_text = normalize_pdf_text("\n".join(metadata.get("form_lines", []) or []))
    zone_text = build_zone_text(metadata.get("field_zones"))
    header_text = normalize_pdf_text((metadata.get("layout", {}) or {}).get("header_text"))

    merged = native_text
    if form_text:
        merged = normalize_pdf_text(f"{merged}\n{form_text}") if merged else form_text
    if ocr_text:
        merged = merge_page_texts(merged, ocr_text) if merged else ocr_text
    if zone_text:
        merged = merge_page_texts(merged, zone_text) if merged else zone_text
    if header_text and header_text.lower() not in str(merged).lower():
        merged = normalize_pdf_text(f"{header_text}\n{merged}") if merged else header_text

    metadata["merged_text"] = merged
    return merged, metadata


def merge_page_metadata(primary_metadata, secondary_metadata):
    merged = dict(primary_metadata or {})
    secondary_metadata = dict(secondary_metadata or {})

    if secondary_metadata.get("ocr_mode") == "discovery":
        discovery_text = normalize_pdf_text(secondary_metadata.get("ocr_text"))
        if discovery_text:
            existing_discovery = normalize_pdf_text(merged.get("document_discovery_text"))
            if discovery_text.lower() not in existing_discovery.lower():
                merged["document_discovery_text"] = normalize_pdf_text(
                    f"{existing_discovery}\n{discovery_text}" if existing_discovery else discovery_text
                )
        merged["document_discovery_confidence"] = max(
            float(merged.get("document_discovery_confidence") or 0.0),
            float(secondary_metadata.get("ocr_confidence") or 0.0),
        )
        merged["document_discovery_provider"] = secondary_metadata.get("ocr_provider") or merged.get("document_discovery_provider")
        merged["layout"] = merge_layout_maps(merged.get("layout"), secondary_metadata.get("layout"))
        merged["ocr_segments"] = list(merged.get("ocr_segments", []) or []) + list(secondary_metadata.get("ocr_segments", []) or [])
        return merged

    if secondary_metadata.get("native_text") and not merged.get("native_text"):
        merged["native_text"] = secondary_metadata.get("native_text")

    secondary_ocr_text = normalize_pdf_text(secondary_metadata.get("ocr_text"))
    if secondary_ocr_text:
        merged["ocr_text"] = secondary_ocr_text

    merged["ocr_confidence"] = max(
        float(merged.get("ocr_confidence") or 0.0),
        float(secondary_metadata.get("ocr_confidence") or 0.0),
    )
    merged["ocr_provider"] = secondary_metadata.get("ocr_provider") or merged.get("ocr_provider")
    merged["field_zones"] = merge_field_zones(merged.get("field_zones"), secondary_metadata.get("field_zones"))
    merged["layout"] = merge_layout_maps(merged.get("layout"), secondary_metadata.get("layout"))
    merged["ocr_segments"] = list(merged.get("ocr_segments", []) or []) + list(secondary_metadata.get("ocr_segments", []) or [])

    return merged


def build_basic_page_metadata(page_number, source_type, text, source_file):
    metadata = build_hybrid_page_metadata(
        page_number=page_number,
        source_type=source_type,
        native_text=text,
        source_file=source_file,
    )
    _, metadata = finalize_page_text_from_metadata(metadata)
    return metadata


def extract_pdf_native_text(page, plumber_page=None):
    candidates = []

    try:
        candidates.append(normalize_pdf_text(page.extract_text() or ""))
    except Exception:
        candidates.append("")

    if plumber_page is not None:
        try:
            candidates.append(
                normalize_pdf_text(
                    plumber_page.extract_text(
                        x_tolerance=2,
                        y_tolerance=3,
                    ) or ""
                )
            )
        except Exception:
            candidates.append("")

        try:
            tables = plumber_page.extract_tables() or []
        except Exception:
            tables = []

        table_lines = []
        for table in tables:
            for row in table or []:
                if not row:
                    continue
                cleaned = [normalize_pdf_text(cell) for cell in row if normalize_pdf_text(cell)]
                if cleaned:
                    table_lines.append(" | ".join(cleaned))

        if table_lines:
            candidates.append(normalize_pdf_text("\n".join(table_lines)))

    best = ""
    for candidate in candidates:
        if candidate and len(candidate) > len(best):
            best = candidate

    return best


def select_pdf_ocr_candidate_pages(pages, metadata, max_candidates=6):
    candidates = []

    for index, page_text in enumerate(pages or [], start=1):
        page_metadata = dict((metadata or [])[index - 1] or {}) if index - 1 < len(metadata or []) else {}
        field_zones = list(page_metadata.get("field_zones", []) or [])
        layout = dict(page_metadata.get("layout", {}) or {})
        native_zone_count = sum(
            1
            for zone in field_zones
            if str(zone.get("zone_name") or "").lower() == "native_text"
        )
        field_zone_count = len(field_zones)
        structured_line_count = int(layout.get("structured_line_count", 0) or 0)
        has_header = bool(normalize_pdf_text(layout.get("header_text")))
        signal_count = count_pattern_matches(page_text, OCR_PAGE_EXCERPT_SIGNAL_PATTERNS)
        sparse = is_sparse_page_text(page_text)
        priority = 0

        if sparse:
            priority += 5
        if signal_count <= 1:
            priority += 3
        if native_zone_count <= 1:
            priority += 2
        if field_zone_count <= 1 and structured_line_count <= 1:
            priority += 1
        if not has_header and field_zone_count <= 2:
            priority += 1
        if has_header and field_zone_count >= 4 and signal_count >= 2:
            priority -= 2
        elif field_zone_count >= 4 and structured_line_count >= 6:
            priority -= 1

        if priority > 0:
            fingerprint = normalize_pdf_text(page_text)[:240].lower()
            candidates.append((priority, index, fingerprint))

    candidates.sort(key=lambda item: (-item[0], item[1]))

    grouped = {}
    for priority, index, fingerprint in candidates:
        grouped.setdefault(fingerprint or f"page_{index}", []).append((priority, index))

    selected = []
    seen = set()
    ordered_groups = sorted(
        grouped.values(),
        key=lambda items: (-max(priority for priority, _index in items), min(index for _priority, index in items)),
    )

    for items in ordered_groups:
        indices = sorted(index for _priority, index in items)
        representatives = []
        if indices:
            representatives.append(indices[0])
        if len(indices) >= 3:
            representatives.append(indices[len(indices) // 2])
        if len(indices) >= 2:
            representatives.append(indices[-1])

        for index in representatives:
            if index in seen:
                continue
            seen.add(index)
            selected.append(index)
            if len(selected) >= max_candidates:
                return selected

    return selected


def select_pdf_title_ocr_candidate_pages(pages, metadata, max_candidates=14):
    runs = []
    run_start = None

    for index, page_text in enumerate(pages or [], start=1):
        page_metadata = dict((metadata or [])[index - 1] or {}) if index - 1 < len(metadata or []) else {}
        field_zones = list(page_metadata.get("field_zones", []) or [])
        layout = dict(page_metadata.get("layout", {}) or {})
        field_zone_count = len(field_zones)
        structured_line_count = int(layout.get("structured_line_count", 0) or 0)
        has_doc_hint = count_pattern_matches(page_text, OCR_PAGE_DOC_HINT_PATTERNS) > 0
        sparse = is_sparse_page_text(page_text)
        header_text = normalize_pdf_text(layout.get("header_text"))

        looks_like_low_info_form_page = (
            sparse
            and field_zone_count <= 1
            and structured_line_count <= 1
            and not has_doc_hint
            and len(header_text) <= 180
        )

        if looks_like_low_info_form_page:
            if run_start is None:
                run_start = index
            continue

        if run_start is not None:
            runs.append((run_start, index - 1))
            run_start = None

    if run_start is not None:
        runs.append((run_start, len(pages or [])))

    selected = []
    for run_start, run_end in runs:
        run_length = (run_end - run_start) + 1
        if run_length < 2:
            continue

        for page_number in range(run_start, run_end + 1):
            selected.append(page_number)
            if len(selected) >= max_candidates:
                return selected

    return selected


def select_pdf_promoted_full_ocr_pages(metadata, candidate_pages, max_candidates=10):
    promoted = []
    seen = set()

    for page_number in candidate_pages or []:
        if page_number in seen:
            continue

        page_metadata = dict((metadata or [])[page_number - 1] or {}) if page_number - 1 < len(metadata or []) else {}
        layout = dict(page_metadata.get("layout", {}) or {})
        header_text = normalize_pdf_text(layout.get("header_text"))
        ocr_confidence = float(page_metadata.get("ocr_confidence") or 0.0)

        if len(header_text) < 180:
            continue

        exact_hint_hits = count_pattern_matches(header_text, OCR_PAGE_DOC_HINT_PATTERNS)
        structured_hint_hits = count_pattern_matches(header_text, OCR_STRUCTURED_LINE_PATTERNS)
        lexical_header_signals = [
            "medical necessity",
            "treatment request",
            "requested services",
            "reason for consultation",
            "single episode of care",
            "seoc",
            "virtual consent",
            "consent form",
            "clinical documentation",
            "imaging findings",
            "chief complaint",
            "history of present illness",
            "despite appropriate",
            "to whom it may concern",
            "attorney full name",
        ]
        has_dense_header_signal = (
            exact_hint_hits >= 1
            or structured_hint_hits >= 2
            or any(term in header_text.lower() for term in lexical_header_signals)
        )

        if not has_dense_header_signal:
            continue

        if ocr_confidence > 89.0 and exact_hint_hits == 0 and structured_hint_hits < 3:
            continue

        seen.add(page_number)
        promoted.append(page_number)
        if len(promoted) >= max_candidates:
            break

    return promoted


def extract_pdf_page_ocr_metadata(pdf_path, log_fn=None, page_numbers=None, mode="full", page_images=None):
    if not layout_ocr_available():
        emit(log_fn, "[DEBUG] Layout OCR backend unavailable; skipping pdfium/tesseract OCR stage")
        return {}

    if page_images is None:
        page_images = render_pdf_pages_as_images(pdf_path, page_numbers=page_numbers, log_fn=log_fn)
    else:
        selected_pages = {int(number) for number in (page_numbers or []) if int(number) >= 1}
        filtered_images = []
        for page_number, image in page_images or []:
            try:
                normalized_page_number = int(page_number)
            except Exception:
                continue
            if selected_pages and normalized_page_number not in selected_pages:
                continue
            filtered_images.append((normalized_page_number, image))
        page_images = sorted(filtered_images, key=lambda item: item[0])
    metadata = {}
    if not page_images:
        return metadata

    for index, image in page_images:
        if mode == "header_only":
            header_result = ocr_image_header_only(image, log_fn=log_fn)
            page_results = [header_result] if header_result else []
        else:
            page_results = ocr_image_with_layout(image, log_fn=log_fn) or []
        page_metadata = build_hybrid_page_metadata(
            page_number=index,
            source_type="pdf",
            ocr_results=page_results,
            source_file=str(pdf_path),
        )
        if mode == "header_only":
            page_metadata["ocr_mode"] = "discovery"
        metadata[index] = page_metadata

    return metadata


def extract_docx_pages(docx_path, log_fn=None, return_metadata=False):
    docx_path = Path(docx_path).expanduser().resolve()
    emit(log_fn, f"[DEBUG] Opening DOCX: {docx_path}")

    try:
        with zipfile.ZipFile(docx_path, "r") as archive:
            xml_parts = []
            for member in ("word/header1.xml", "word/document.xml", "word/footer1.xml"):
                if member not in archive.namelist():
                    continue
                xml_parts.append(archive.read(member))
    except Exception as exc:
        raise RuntimeError(f"Unable to read DOCX file: {docx_path}") from exc

    paragraphs = []
    namespace = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}

    for xml_blob in xml_parts:
        try:
            root = ET.fromstring(xml_blob)
        except ET.ParseError:
            continue

        for paragraph in root.findall(".//w:p", namespace):
            text_runs = [node.text for node in paragraph.findall(".//w:t", namespace) if node.text]
            paragraph_text = normalize_pdf_text("".join(text_runs))
            if paragraph_text:
                paragraphs.append(paragraph_text)

    text = normalize_pdf_text("\n".join(paragraphs))
    emit(log_fn, f"[DEBUG] Extracted DOCX pseudo-page: {len(text)} chars")
    pages = [text] if text else []
    if not return_metadata:
        return pages

    metadata = [
        build_basic_page_metadata(1, "docx", text, str(docx_path))
    ] if text else []
    return pages, metadata


def extract_text_pages(text_path, log_fn=None, return_metadata=False):
    text_path = Path(text_path).expanduser().resolve()
    emit(log_fn, f"[DEBUG] Opening text file: {text_path}")
    text = normalize_pdf_text(text_path.read_text(encoding="utf-8", errors="replace"))
    emit(log_fn, f"[DEBUG] Extracted text pseudo-page: {len(text)} chars")
    pages = [text] if text else []
    if not return_metadata:
        return pages

    metadata = [
        build_basic_page_metadata(1, "txt", text, str(text_path))
    ] if text else []
    return pages, metadata


def extract_image_pages_with_windows_ocr(image_path, log_fn=None, return_metadata=False):
    def run_image_ocr(candidate_path):
        env = os.environ.copy()
        env["TRUECORE_IMAGE_PATH"] = str(candidate_path)
        pages = run_windows_ocr_script(ocr_script, env, log_fn=log_fn, timeout=180)
        if pages is None:
            return None
        pages = normalize_ocr_pages_payload(pages)
        return [normalize_pdf_text(page) for page in pages]

    image_path = Path(image_path).expanduser().resolve()

    ocr_script = r"""
Add-Type -AssemblyName System.Runtime.WindowsRuntime

function Await-WinRT($operation, [Type]$resultType = $null) {
    if ($null -eq $resultType) {
        $method = [System.WindowsRuntimeSystemExtensions].GetMethods() |
            Where-Object { $_.Name -eq 'AsTask' -and -not $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 } |
            Select-Object -First 1
        if (-not $method) { throw 'No WinRT AsTask method found.' }
        $task = $method.Invoke($null, @($operation))
        $task.Wait()
        return $null
    }

    $method = [System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 } |
        Select-Object -First 1
    if (-not $method) { throw 'No generic WinRT AsTask method found.' }

    $generic = $method.MakeGenericMethod($resultType)
    $task = $generic.Invoke($null, @($operation))
    $task.Wait()
    return $task.Result
}

$storageFileType = [type]'Windows.Storage.StorageFile, Windows, ContentType=WindowsRuntime'
$streamType = [type]'Windows.Storage.Streams.IRandomAccessStreamWithContentType, Windows, ContentType=WindowsRuntime'
$bitmapDecoderType = [type]'Windows.Graphics.Imaging.BitmapDecoder, Windows, ContentType=WindowsRuntime'
$softwareBitmapType = [type]'Windows.Graphics.Imaging.SoftwareBitmap, Windows, ContentType=WindowsRuntime'
$ocrEngineType = [type]'Windows.Media.Ocr.OcrEngine, Windows, ContentType=WindowsRuntime'
$ocrResultType = [type]'Windows.Media.Ocr.OcrResult, Windows, ContentType=WindowsRuntime'

$imagePath = $env:TRUECORE_IMAGE_PATH
if (-not $imagePath) { throw 'TRUECORE_IMAGE_PATH is not set.' }

$file = Await-WinRT ($storageFileType::GetFileFromPathAsync($imagePath)) $storageFileType
$stream = Await-WinRT ($file.OpenReadAsync()) $streamType
$decoder = Await-WinRT ($bitmapDecoderType::CreateAsync($stream)) $bitmapDecoderType
$bitmap = Await-WinRT ($decoder.GetSoftwareBitmapAsync()) $softwareBitmapType
$ocrEngine = $ocrEngineType::TryCreateFromUserProfileLanguages()
if ($null -eq $ocrEngine) { throw 'Windows OCR engine unavailable.' }
$result = Await-WinRT ($ocrEngine.RecognizeAsync($bitmap)) $ocrResultType

$texts = @([string]$result.Text)
$json = $texts | ConvertTo-Json -Compress
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
"""

    rich_pages = []
    if Image is not None:
        try:
            with Image.open(image_path) as source_image:
                rich_pages = ocr_image_with_layout(source_image, log_fn=log_fn) or []
        except Exception as exc:
            emit(log_fn, f"[DEBUG] Rich image OCR failed: {exc}")

    if rich_pages:
        metadata = []
        pages = []
        for index, page_result in enumerate(rich_pages, start=1):
            page_metadata = build_hybrid_page_metadata(
                page_number=index,
                source_type=image_path.suffix.lower().lstrip("."),
                ocr_results=[page_result],
                source_file=str(image_path),
            )
            page_text, page_metadata = finalize_page_text_from_metadata(page_metadata)
            pages.append(page_text)
            metadata.append(page_metadata)

        return (pages, metadata) if return_metadata else pages

    raw_pages = run_image_ocr(image_path)
    temp_paths = []
    merged_pages = raw_pages

    preprocessed_path = preprocess_image_for_ocr(image_path, log_fn=log_fn)
    if preprocessed_path:
        temp_paths.append(preprocessed_path)

    try:
        if preprocessed_path:
            merged_pages = merge_ocr_page_sets(merged_pages, run_image_ocr(preprocessed_path))

        if should_try_rotated_image_ocr(merged_pages):
            for rotated_path in build_rotated_image_variants(preprocessed_path or image_path, log_fn=log_fn):
                temp_paths.append(rotated_path)
                merged_pages = merge_ocr_page_sets(merged_pages, run_image_ocr(rotated_path))
    finally:
        cleanup_temporary_image_paths(temp_paths, log_fn=log_fn)

    if merged_pages is None:
        return ([], []) if return_metadata else None

    pages = [normalize_pdf_text(page) for page in merged_pages]
    if not return_metadata:
        return pages

    metadata = [
        build_basic_page_metadata(index, image_path.suffix.lower().lstrip("."), text, str(image_path))
        for index, text in enumerate(pages, start=1)
    ]
    return pages, metadata


def preprocess_image_for_ocr(image_path, log_fn=None):
    if Image is None or ImageOps is None or ImageFilter is None:
        emit(log_fn, "[DEBUG] PIL is unavailable; skipping image preprocessing")
        return None

    image_path = Path(image_path).expanduser().resolve()

    try:
        with Image.open(image_path) as source_image:
            image, preprocessing = preprocess_image_object_for_ocr(source_image, log_fn=log_fn)

            temp_dir = Path(tempfile.mkdtemp(prefix="truecoreintel_img_ocr_"))
            output_path = temp_dir / f"{image_path.stem}_ocr_preprocessed.png"
            image.save(output_path, format="PNG", optimize=True)
            emit(log_fn, f"[DEBUG] Preprocessed image for OCR: {output_path} ({', '.join(preprocessing.get('steps', []))})")
            return output_path
    except Exception as exc:
        emit(log_fn, f"[DEBUG] Image preprocessing failed: {exc}")
        return None


def cleanup_temporary_image_path(image_path, log_fn=None):
    if not image_path:
        return

    image_path = Path(image_path)
    try:
        parent = image_path.parent
        if image_path.exists():
            image_path.unlink()
        if parent.exists():
            parent.rmdir()
    except Exception as exc:
        emit(log_fn, f"[DEBUG] Unable to clean OCR temp image: {exc}")


def cleanup_temporary_image_paths(image_paths, log_fn=None):
    parent_dirs = set()
    for image_path in image_paths or []:
        if not image_path:
            continue
        image_path = Path(image_path)
        parent_dirs.add(image_path.parent)
        try:
            if image_path.exists():
                image_path.unlink()
        except Exception as exc:
            emit(log_fn, f"[DEBUG] Unable to clean OCR temp image: {exc}")

    for parent in sorted(parent_dirs, key=lambda path: len(str(path)), reverse=True):
        try:
            if parent.exists():
                parent.rmdir()
        except Exception:
            continue


def build_rotated_image_variants(image_path, log_fn=None):
    if Image is None or ImageOps is None:
        return []

    image_path = Path(image_path).expanduser().resolve()
    variants = []
    resampling = getattr(Image, "Resampling", Image)

    try:
        with Image.open(image_path) as source_image:
            image = ImageOps.exif_transpose(source_image)
            fill_color = 255 if image.mode in {"1", "L"} else (255, 255, 255)
            temp_dir = Path(tempfile.mkdtemp(prefix="truecoreintel_img_rot_ocr_"))

            for index, angle in enumerate((-2.0, 2.0), start=1):
                rotated = image.rotate(
                    angle,
                    resample=resampling.BICUBIC,
                    expand=True,
                    fillcolor=fill_color,
                )
                output_path = temp_dir / f"{image_path.stem}_ocr_rotated_{index}.png"
                rotated.save(output_path, format="PNG", optimize=True)
                variants.append(output_path)

        if variants:
            emit(log_fn, f"[DEBUG] Built rotated OCR image variants: {len(variants)}")
    except Exception as exc:
        emit(log_fn, f"[DEBUG] Rotated OCR variant generation failed: {exc}")
        cleanup_temporary_image_paths(variants, log_fn=log_fn)
        return []

    return variants


def should_try_rotated_image_ocr(pages):
    merged_text = normalize_pdf_text("\n".join(pages or []))
    if not merged_text:
        return True

    signal_count = sum(
        1 for pattern in OCR_PAGE_EXCERPT_SIGNAL_PATTERNS
        if pattern.search(merged_text)
    )
    return len(merged_text) < 120 or signal_count < 2


def merge_ocr_page_sets(primary_pages, secondary_pages):
    if primary_pages and secondary_pages:
        merged = []
        total_pages = max(len(primary_pages), len(secondary_pages))
        for index in range(total_pages):
            primary_text = primary_pages[index] if index < len(primary_pages) else ""
            secondary_text = secondary_pages[index] if index < len(secondary_pages) else ""
            merged_text = merge_page_texts(primary_text, secondary_text)
            if not merged_text:
                merged_text = secondary_text or primary_text
            merged.append(merged_text)
        return merged

    return secondary_pages or primary_pages


def extract_pdf_pages_with_windows_ocr(pdf_path, log_fn=None):
    ocr_script = r"""
Add-Type -AssemblyName System.Runtime.WindowsRuntime

function Await-WinRT($operation, [Type]$resultType = $null) {
    if ($null -eq $resultType) {
        $method = [System.WindowsRuntimeSystemExtensions].GetMethods() |
            Where-Object { $_.Name -eq 'AsTask' -and -not $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 } |
            Select-Object -First 1
        if (-not $method) { throw 'No WinRT AsTask method found.' }
        $task = $method.Invoke($null, @($operation))
        $task.Wait()
        return $null
    }

    $method = [System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 } |
        Select-Object -First 1
    if (-not $method) { throw 'No generic WinRT AsTask method found.' }

    $generic = $method.MakeGenericMethod($resultType)
    $task = $generic.Invoke($null, @($operation))
    $task.Wait()
    return $task.Result
}

$storageFileType = [type]'Windows.Storage.StorageFile, Windows, ContentType=WindowsRuntime'
$pdfType = [type]'Windows.Data.Pdf.PdfDocument, Windows, ContentType=WindowsRuntime'
$streamType = [type]'Windows.Storage.Streams.InMemoryRandomAccessStream, Windows, ContentType=WindowsRuntime'
$bitmapDecoderType = [type]'Windows.Graphics.Imaging.BitmapDecoder, Windows, ContentType=WindowsRuntime'
$softwareBitmapType = [type]'Windows.Graphics.Imaging.SoftwareBitmap, Windows, ContentType=WindowsRuntime'
$ocrEngineType = [type]'Windows.Media.Ocr.OcrEngine, Windows, ContentType=WindowsRuntime'
$ocrResultType = [type]'Windows.Media.Ocr.OcrResult, Windows, ContentType=WindowsRuntime'

$pdfPath = $env:TRUECORE_PDF_PATH
if (-not $pdfPath) { throw 'TRUECORE_PDF_PATH is not set.' }

$file = Await-WinRT ($storageFileType::GetFileFromPathAsync($pdfPath)) $storageFileType
$pdf = Await-WinRT ($pdfType::LoadFromFileAsync($file)) $pdfType
$ocrEngine = $ocrEngineType::TryCreateFromUserProfileLanguages()
if ($null -eq $ocrEngine) { throw 'Windows OCR engine unavailable.' }

$texts = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $pdf.PageCount; $i++) {
    $page = $pdf.GetPage($i)
    $stream = [Activator]::CreateInstance($streamType)
    Await-WinRT ($page.RenderToStreamAsync($stream))
    $stream.Seek(0)

    $decoder = Await-WinRT ($bitmapDecoderType::CreateAsync($stream)) $bitmapDecoderType
    $bitmap = Await-WinRT ($decoder.GetSoftwareBitmapAsync()) $softwareBitmapType
    $result = Await-WinRT ($ocrEngine.RecognizeAsync($bitmap)) $ocrResultType
    $texts.Add([string]$result.Text)
}

$json = $texts | ConvertTo-Json -Compress
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
"""

    env = os.environ.copy()
    env["TRUECORE_PDF_PATH"] = str(pdf_path)
    pages = run_windows_ocr_script(ocr_script, env, log_fn=log_fn, timeout=240)
    if pages is None:
        return None
    pages = normalize_ocr_pages_payload(pages)
    return [normalize_pdf_text(page) for page in pages]


def merge_page_texts(primary_text, ocr_text):
    primary_text = normalize_pdf_text(primary_text)
    ocr_text = normalize_pdf_text(ocr_text)

    if not ocr_text:
        return primary_text

    if not primary_text:
        return ocr_text

    def extract_doc_title_snippet(text):
        header_text = text[:450]
        snippet_tail_by_doc = {
            "cover_sheet": 220,
            "rfs": 180,
            "seoc": 180,
            "lomn": 180,
            "consult_request": 200,
            "clinical_notes": 180,
            "consent": 160,
        }

        for doc_type, pattern in DOC_TITLE_OCR_PATTERNS:
            match = pattern.search(header_text)
            if not match:
                continue

            if doc_type == "consent":
                if has_filled_consent_signals(text) < 2:
                    return None

            start = max(0, match.start() - 40)
            end = min(len(header_text), match.end() + snippet_tail_by_doc.get(doc_type, 120))
            snippet = normalize_pdf_text(header_text[start:end])
            return snippet

        return None

    primary_lower = primary_text.lower()
    ocr_lower = ocr_text.lower()
    merged_parts = [primary_text]
    merged_seen = {primary_lower}

    doc_title_snippet = extract_doc_title_snippet(ocr_text)
    if doc_title_snippet:
        doc_lower = doc_title_snippet.lower()
        if doc_lower not in merged_seen:
            merged_parts.append(doc_title_snippet)
            merged_seen.add(doc_lower)

    doc_title_present = doc_title_snippet is not None
    primary_text_is_minimal = len(primary_text) < 80
    allow_structured_line_merge = primary_text_is_minimal and (doc_title_present or AUTH_OCR_SIGNAL.search(ocr_lower))
    structured_lines = extract_structured_ocr_lines(ocr_text) if allow_structured_line_merge else []
    for line in structured_lines:
        line_lower = line.lower()
        if line_lower not in merged_seen:
            merged_parts.append(line)
            merged_seen.add(line_lower)
    snippets = []
    seen = set()

    for pattern in AUTH_OCR_SNIPPET_PATTERNS:
        for match in pattern.finditer(ocr_text):
            snippet = normalize_pdf_text(match.group(0))
            snippet_lower = snippet.lower()
            if snippet and snippet_lower not in seen:
                seen.add(snippet_lower)
                snippets.append(snippet)

    if not snippets:
        return finalize_merged_page_text(primary_text, ocr_text, structured_lines, merged_parts, merged_seen, doc_title_present)

    additions = [snippet for snippet in snippets if snippet.lower() not in primary_lower]
    if not additions:
        return finalize_merged_page_text(primary_text, ocr_text, structured_lines, merged_parts, merged_seen, doc_title_present)

    for addition in additions:
        addition_lower = addition.lower()
        if addition_lower not in merged_seen:
            merged_parts.append(addition)
            merged_seen.add(addition_lower)

    return finalize_merged_page_text(primary_text, ocr_text, structured_lines, merged_parts, merged_seen, doc_title_present)


def extract_structured_ocr_lines(text):
    lines = [
        normalize_pdf_text(line)
        for line in re.split(r"[\r\n]+", text)
        if normalize_pdf_text(line)
    ]
    selected = []
    seen = set()

    for index, line in enumerate(lines):
        if not any(pattern.search(line) for pattern in OCR_STRUCTURED_LINE_PATTERNS):
            continue

        candidate = line
        if re.search(r"[:\-]\s*$", line) and index + 1 < len(lines):
            candidate = normalize_pdf_text(f"{line} {lines[index + 1]}")

        candidate_lower = candidate.lower()
        if candidate_lower in seen:
            continue

        seen.add(candidate_lower)
        selected.append(candidate)
        if len(selected) >= 12:
            break

    return selected


def build_ocr_page_excerpt(text, max_lines=10, max_chars=900):
    lines = [
        normalize_pdf_text(line)
        for line in re.split(r"[\r\n]+", text)
        if normalize_pdf_text(line)
    ]
    if not lines:
        return None

    excerpt_lines = []
    current_chars = 0
    for line in lines[:max_lines]:
        if current_chars + len(line) > max_chars and excerpt_lines:
            break
        excerpt_lines.append(line)
        current_chars += len(line)

    excerpt = normalize_pdf_text("\n".join(excerpt_lines))
    return excerpt or None


def count_pattern_matches(text, patterns):
    normalized = normalize_pdf_text(text)
    if not normalized:
        return 0

    return sum(1 for pattern in patterns if pattern.search(normalized))


def has_new_doc_hints(primary_text, ocr_text):
    normalized_primary = normalize_pdf_text(primary_text)
    normalized_ocr = normalize_pdf_text(ocr_text)

    if not normalized_ocr:
        return False

    for pattern in OCR_PAGE_DOC_HINT_PATTERNS:
        primary_has = bool(pattern.search(normalized_primary))
        ocr_has = bool(pattern.search(normalized_ocr))

        if ocr_has and not primary_has:
            return True

    return False


def should_append_ocr_page_excerpt(primary_text, ocr_text, structured_lines, doc_title_present):
    primary_text = normalize_pdf_text(primary_text)
    ocr_text = normalize_pdf_text(ocr_text)

    if not ocr_text:
        return False

    primary_signal_count = count_pattern_matches(primary_text, OCR_PAGE_EXCERPT_SIGNAL_PATTERNS)
    ocr_signal_count = count_pattern_matches(ocr_text, OCR_PAGE_EXCERPT_SIGNAL_PATTERNS)
    new_doc_hints = has_new_doc_hints(primary_text, ocr_text)

    if len(ocr_text) < max(260, len(primary_text) + 80):
        return False

    if not doc_title_present and not AUTH_OCR_SIGNAL.search(ocr_text) and not new_doc_hints:
        return False

    if is_sparse_page_text(primary_text):
        return len(structured_lines) >= 2 or ocr_signal_count >= max(1, primary_signal_count + 1) or new_doc_hints

    if new_doc_hints and len(ocr_text) >= len(primary_text) + 40:
        return True

    if doc_title_present and len(ocr_text) >= len(primary_text) + 80:
        return True

    return len(structured_lines) >= 4 and ocr_signal_count >= primary_signal_count + 1


def finalize_merged_page_text(primary_text, ocr_text, structured_lines, merged_parts, merged_seen, doc_title_present):
    if should_append_ocr_page_excerpt(primary_text, ocr_text, structured_lines, doc_title_present):
        excerpt = build_ocr_page_excerpt(ocr_text)
        if excerpt:
            excerpt_lower = excerpt.lower()
            if excerpt_lower not in merged_seen:
                merged_parts.append(excerpt)
                merged_seen.add(excerpt_lower)

    return normalize_pdf_text("\n".join(merged_parts))


def extract_pdf_pages(pdf_path, log_fn=None, return_metadata=False):
    emit(log_fn, f"[DEBUG] Opening PDF: {pdf_path}")

    pages = []
    metadata = []
    plumber_document = None
    poppler_pages = extract_pdf_pages_with_pdftotext(pdf_path, log_fn=log_fn)

    try:
        if pdfplumber is not None:
            plumber_document = pdfplumber.open(str(pdf_path))

        with open(pdf_path, "rb") as handle:
            reader = PyPDF2.PdfReader(handle)
            emit(log_fn, f"[DEBUG] PDF loaded. Pages found: {len(reader.pages)}")

            for index, page in enumerate(reader.pages, start=1):
                plumber_page = plumber_document.pages[index - 1] if plumber_document and index - 1 < len(plumber_document.pages) else None
                text = extract_pdf_native_text(page, plumber_page=plumber_page)
                form_lines = extract_pdf_page_form_lines(page)

                page_metadata = build_hybrid_page_metadata(
                    page_number=index,
                    source_type="pdf",
                    native_text=text,
                    form_lines=form_lines,
                    source_file=str(pdf_path),
                )
                merged_text, page_metadata = finalize_page_text_from_metadata(page_metadata)

                if form_lines:
                    emit(log_fn, f"[DEBUG] Extracted page {index} form fields: {len(form_lines)}")

                pages.append(merged_text)
                metadata.append(page_metadata)
                emit(log_fn, f"[DEBUG] Extracted page {index}: {len(merged_text)} chars")
    finally:
        if plumber_document is not None:
            try:
                plumber_document.close()
            except Exception:
                pass

    if poppler_pages:
        merged_pages = []
        merged_metadata = []
        total_pages = max(len(pages), len(poppler_pages))
        improved_pages = 0

        for index in range(total_pages):
            base_metadata = metadata[index] if index < len(metadata) else build_hybrid_page_metadata(
                page_number=index + 1,
                source_type="pdf",
                source_file=str(pdf_path),
            )
            poppler_text = poppler_pages[index] if index < len(poppler_pages) else ""
            native_text = normalize_pdf_text(base_metadata.get("native_text"))
            chosen_native = merge_page_texts(native_text, poppler_text) if poppler_text else native_text
            if chosen_native and chosen_native != native_text:
                improved_pages += 1
            base_metadata["native_text"] = chosen_native
            merged_text, base_metadata = finalize_page_text_from_metadata(base_metadata)
            merged_pages.append(merged_text)
            merged_metadata.append(base_metadata)

        if improved_pages:
            emit(log_fn, f"[DEBUG] Poppler text strengthened {improved_pages} PDF page(s)")
        pages = merged_pages
        metadata = merged_metadata

    return (pages, metadata) if return_metadata else pages


def extract_pdf_pages_with_fallback(pdf_path, log_fn=None, return_metadata=False, base_pages=None, base_metadata=None):
    if base_pages is not None and base_metadata is not None:
        pages = list(base_pages or [])
        metadata = list(base_metadata or [])
    else:
        pages, metadata = extract_pdf_pages(pdf_path, log_fn=log_fn, return_metadata=True)

    title_page_images = []
    title_candidate_pages = select_pdf_title_ocr_candidate_pages(pages, metadata)
    if title_candidate_pages:
        emit(log_fn, f"[DEBUG] Title-zone OCR candidate pages: {', '.join(str(page) for page in title_candidate_pages[:20])}")
        title_page_images = render_pdf_pages_as_images(
            pdf_path,
            dpi=220,
            page_numbers=title_candidate_pages,
            log_fn=log_fn,
        )
        title_ocr_metadata = extract_pdf_page_ocr_metadata(
            pdf_path,
            log_fn=log_fn,
            page_numbers=title_candidate_pages,
            mode="header_only",
            page_images=title_page_images,
        )
        if title_ocr_metadata:
            refreshed_pages = []
            refreshed_metadata = []
            for index in range(max(len(pages), len(metadata))):
                primary_metadata = metadata[index] if index < len(metadata) else build_hybrid_page_metadata(
                    page_number=index + 1,
                    source_type="pdf",
                    source_file=str(pdf_path),
                )
                secondary_metadata = title_ocr_metadata.get(index + 1, {})
                merged_page_metadata = merge_page_metadata(primary_metadata, secondary_metadata)
                merged_text, merged_page_metadata = finalize_page_text_from_metadata(merged_page_metadata)
                refreshed_pages.append(merged_text)
                refreshed_metadata.append(merged_page_metadata)
            pages = refreshed_pages
            metadata = refreshed_metadata

    candidate_pages = select_pdf_ocr_candidate_pages(pages, metadata)
    promoted_pages = select_pdf_promoted_full_ocr_pages(metadata, title_candidate_pages)
    if promoted_pages:
        for page_number in promoted_pages:
            if page_number not in candidate_pages:
                candidate_pages.append(page_number)
    if candidate_pages:
        emit(log_fn, f"[DEBUG] Selective OCR candidate pages: {', '.join(str(page) for page in candidate_pages[:20])}")

    cached_full_images = []
    missing_full_pages = []
    candidate_page_set = {int(page_number) for page_number in (candidate_pages or []) if int(page_number) >= 1}

    if candidate_page_set:
        title_page_image_index = {
            int(page_number): image
            for page_number, image in title_page_images or []
            if int(page_number) in candidate_page_set
        }
        cached_full_images = sorted(title_page_image_index.items(), key=lambda item: item[0])
        missing_full_pages = sorted(candidate_page_set.difference(title_page_image_index.keys()))

    if cached_full_images and missing_full_pages:
        emit(
            log_fn,
            f"[DEBUG] Reusing {len(cached_full_images)} rendered title page(s) for full OCR; rendering {len(missing_full_pages)} additional page(s)",
        )
    elif cached_full_images:
        emit(log_fn, f"[DEBUG] Reusing {len(cached_full_images)} rendered title page(s) for full OCR")

    additional_full_images = (
        render_pdf_pages_as_images(pdf_path, page_numbers=missing_full_pages, log_fn=log_fn)
        if missing_full_pages else []
    )
    full_ocr_page_images = sorted(
        list(cached_full_images) + list(additional_full_images),
        key=lambda item: item[0],
    )

    ocr_metadata = extract_pdf_page_ocr_metadata(
        pdf_path,
        log_fn=log_fn,
        page_numbers=candidate_pages,
        page_images=full_ocr_page_images,
    )
    searchable_copy = None

    if not any(page_metadata_has_real_ocr_content(item) for item in (ocr_metadata or {}).values()):
        ocr_pages = extract_pdf_pages_with_windows_ocr(pdf_path, log_fn=log_fn)
        if ocr_pages:
            ocr_metadata = {
                index: build_hybrid_page_metadata(
                    page_number=index,
                    source_type="pdf",
                    ocr_results=[{
                        "provider": "windows_ocr",
                        "providers": ["windows_ocr"],
                        "text": normalize_pdf_text(text),
                        "confidence": 62.0,
                        "field_zones": [],
                        "layout": {},
                        "segment_index": 0,
                        "segment_reason": "full_page",
                        "segment_bbox": None,
                        "preprocessing": {},
                        "region_runs": [],
                    }],
                    source_file=str(pdf_path),
                )
                for index, text in enumerate(ocr_pages, start=1)
            }

    sparse_pages = sum(1 for page in pages if is_sparse_page_text(page))
    should_try_searchable_copy = (
        sparse_pages >= max(2, int(len(pages) * 0.25))
        and not any(page_metadata_has_real_ocr_content(item) for item in (ocr_metadata or {}).values())
        and ocrmypdf_available()
    )

    if should_try_searchable_copy:
        searchable_copy = build_searchable_pdf_with_ocrmypdf(pdf_path, log_fn=log_fn)
        if searchable_copy:
            try:
                searchable_pages, searchable_metadata = extract_pdf_pages(searchable_copy, log_fn=log_fn, return_metadata=True)
                if searchable_pages:
                    emit(log_fn, "[DEBUG] Searchable PDF copy extracted for fallback merge")
                    pages = searchable_pages
                    metadata = searchable_metadata
            finally:
                cleanup_temporary_pdf(searchable_copy, log_fn=log_fn)

    if not ocr_metadata:
        return (pages, metadata) if return_metadata else pages

    merged_pages = []
    merged_metadata = []
    changed_pages = 0
    total_pages = len(metadata)

    for index in range(total_pages):
        primary_metadata = metadata[index] if index < len(metadata) else build_hybrid_page_metadata(
            page_number=index + 1,
            source_type="pdf",
            source_file=str(pdf_path),
        )
        secondary_metadata = ocr_metadata.get(index + 1, {})
        merged_page_metadata = merge_page_metadata(primary_metadata, secondary_metadata)
        merged_text, merged_page_metadata = finalize_page_text_from_metadata(merged_page_metadata)
        if index < len(pages) and merged_text != pages[index]:
            changed_pages += 1
        merged_pages.append(merged_text)
        merged_metadata.append(merged_page_metadata)

    emit(log_fn, f"[DEBUG] OCR fallback merged into {changed_pages} page(s)")
    return (merged_pages, merged_metadata) if return_metadata else merged_pages


def extract_document_pages(file_path, log_fn=None, return_metadata=False):
    file_path = Path(file_path).expanduser().resolve()
    suffix = file_path.suffix.lower()

    if suffix == ".pdf":
        return extract_pdf_pages(file_path, log_fn=log_fn, return_metadata=return_metadata)
    if suffix == ".docx":
        return extract_docx_pages(file_path, log_fn=log_fn, return_metadata=return_metadata)
    if suffix in TEXT_EXTENSIONS:
        return extract_text_pages(file_path, log_fn=log_fn, return_metadata=return_metadata)
    if suffix in IMAGE_EXTENSIONS:
        pages = extract_image_pages_with_windows_ocr(file_path, log_fn=log_fn, return_metadata=return_metadata)
        if return_metadata:
            return pages or ([], [])
        return pages or []

    raise RuntimeError(f"Unsupported packet file type: {file_path.suffix or '<none>'}")


def extract_document_pages_with_fallback(file_path, log_fn=None, return_metadata=False, base_pages=None, base_metadata=None):
    file_path = Path(file_path).expanduser().resolve()
    suffix = file_path.suffix.lower()

    if suffix == ".pdf":
        return extract_pdf_pages_with_fallback(
            file_path,
            log_fn=log_fn,
            return_metadata=return_metadata,
            base_pages=base_pages,
            base_metadata=base_metadata,
        )

    return extract_document_pages(file_path, log_fn=log_fn, return_metadata=return_metadata)


__all__ = [
    "SUPPORTED_PACKET_EXTENSIONS",
    "extract_document_pages",
    "extract_document_pages_with_fallback",
    "extract_docx_pages",
    "extract_image_pages_with_windows_ocr",
    "extract_pdf_pages",
    "extract_pdf_pages_with_fallback",
    "extract_pdf_pages_with_windows_ocr",
    "extract_text_pages",
    "get_powershell_command",
    "has_filled_consent_signals",
    "merge_page_texts",
    "merge_ocr_page_sets",
    "normalize_pdf_text",
    "is_sparse_page_text",
    "preprocess_image_for_ocr",
]
