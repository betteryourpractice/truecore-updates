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
    from PIL import Image, ImageFilter, ImageOps, ImageStat
except Exception:  # pragma: no cover - optional dependency fallback
    Image = None
    ImageFilter = None
    ImageOps = None
    ImageStat = None


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


def extract_docx_pages(docx_path, log_fn=None):
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
    return [text] if text else []


def extract_text_pages(text_path, log_fn=None):
    text_path = Path(text_path).expanduser().resolve()
    emit(log_fn, f"[DEBUG] Opening text file: {text_path}")
    text = normalize_pdf_text(text_path.read_text(encoding="utf-8", errors="replace"))
    emit(log_fn, f"[DEBUG] Extracted text pseudo-page: {len(text)} chars")
    return [text] if text else []


def extract_image_pages_with_windows_ocr(image_path, log_fn=None):
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
        return None

    return [normalize_pdf_text(page) for page in merged_pages]


def preprocess_image_for_ocr(image_path, log_fn=None):
    if Image is None or ImageOps is None or ImageFilter is None:
        emit(log_fn, "[DEBUG] PIL is unavailable; skipping image preprocessing")
        return None

    image_path = Path(image_path).expanduser().resolve()

    try:
        with Image.open(image_path) as source_image:
            image = ImageOps.exif_transpose(source_image)
            image = image.convert("L")

            min_dimension = min(image.size)
            if min_dimension and min_dimension < 1600:
                scale = 1600 / float(min_dimension)
                resampling = getattr(Image, "Resampling", Image).LANCZOS
                image = image.resize(
                    (int(image.width * scale), int(image.height * scale)),
                    resampling,
                )

            image = ImageOps.autocontrast(image)
            image = image.filter(ImageFilter.MedianFilter(size=3))

            threshold = 170
            if ImageStat is not None:
                stats = ImageStat.Stat(image)
                mean_value = stats.mean[0] if stats.mean else threshold
                threshold = max(130, min(190, int(mean_value)))

            image = image.point(lambda value: 255 if value >= threshold else 0)
            image = ImageOps.expand(image, border=12, fill=255)

            temp_dir = Path(tempfile.mkdtemp(prefix="truecoreintel_img_ocr_"))
            output_path = temp_dir / f"{image_path.stem}_ocr_preprocessed.png"
            image.save(output_path, format="PNG", optimize=True)
            emit(log_fn, f"[DEBUG] Preprocessed image for OCR: {output_path}")
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


def extract_pdf_pages(pdf_path, log_fn=None):
    emit(log_fn, f"[DEBUG] Opening PDF: {pdf_path}")

    pages = []

    with open(pdf_path, "rb") as handle:
        reader = PyPDF2.PdfReader(handle)
        emit(log_fn, f"[DEBUG] PDF loaded. Pages found: {len(reader.pages)}")

        for index, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""
            text = normalize_pdf_text(text)
            form_lines = extract_pdf_page_form_lines(page)

            if form_lines:
                form_text = normalize_pdf_text("\n".join(form_lines))
                if form_text:
                    text = normalize_pdf_text(f"{text}\n{form_text}") if text else form_text
                emit(log_fn, f"[DEBUG] Extracted page {index} form fields: {len(form_lines)}")

            pages.append(text)
            emit(log_fn, f"[DEBUG] Extracted page {index}: {len(text)} chars")

    return pages


def extract_pdf_pages_with_fallback(pdf_path, log_fn=None):
    pages = extract_pdf_pages(pdf_path, log_fn=log_fn)
    ocr_pages = extract_pdf_pages_with_windows_ocr(pdf_path, log_fn=log_fn)

    if not ocr_pages:
        return pages

    merged_pages = []
    changed_pages = 0

    for index, primary_text in enumerate(pages):
        ocr_text = ocr_pages[index] if index < len(ocr_pages) else ""
        merged_text = merge_page_texts(primary_text, ocr_text)
        if merged_text != primary_text:
            changed_pages += 1
        merged_pages.append(merged_text)

    emit(log_fn, f"[DEBUG] OCR fallback merged into {changed_pages} page(s)")
    return merged_pages


def extract_document_pages(file_path, log_fn=None):
    file_path = Path(file_path).expanduser().resolve()
    suffix = file_path.suffix.lower()

    if suffix == ".pdf":
        return extract_pdf_pages(file_path, log_fn=log_fn)
    if suffix == ".docx":
        return extract_docx_pages(file_path, log_fn=log_fn)
    if suffix in TEXT_EXTENSIONS:
        return extract_text_pages(file_path, log_fn=log_fn)
    if suffix in IMAGE_EXTENSIONS:
        pages = extract_image_pages_with_windows_ocr(file_path, log_fn=log_fn)
        return pages or []

    raise RuntimeError(f"Unsupported packet file type: {file_path.suffix or '<none>'}")


def extract_document_pages_with_fallback(file_path, log_fn=None):
    file_path = Path(file_path).expanduser().resolve()
    suffix = file_path.suffix.lower()

    if suffix == ".pdf":
        return extract_pdf_pages_with_fallback(file_path, log_fn=log_fn)

    return extract_document_pages(file_path, log_fn=log_fn)


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
