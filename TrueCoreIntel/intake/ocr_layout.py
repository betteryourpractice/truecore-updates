from __future__ import annotations

import math
import re
from pathlib import Path

try:
    import pypdfium2 as pdfium
except Exception:  # pragma: no cover - optional dependency fallback
    pdfium = None

try:
    import pytesseract
    from pytesseract import Output
except Exception:  # pragma: no cover - optional dependency fallback
    pytesseract = None
    Output = None

try:
    from PIL import Image, ImageEnhance, ImageFilter, ImageOps, ImageStat
except Exception:  # pragma: no cover - optional dependency fallback
    Image = None
    ImageEnhance = None
    ImageFilter = None
    ImageOps = None
    ImageStat = None


FIELD_LABEL_PATTERNS = [
    re.compile(r"\b(?:patient name|veteran name|member name|full name)\b", re.IGNORECASE),
    re.compile(r"\b(?:date of birth|dob|d\.o\.b\.)\b", re.IGNORECASE),
    re.compile(r"\b(?:authorization(?: number)?|referral(?: number)?|member id|tracking number|reference number)\b", re.IGNORECASE),
    re.compile(r"\b(?:ordering provider|requesting provider|referring provider|provider name|rendering provider)\b", re.IGNORECASE),
    re.compile(r"\b(?:reason for request|requested service|requested procedure|diagnosis|assessment|impression)\b", re.IGNORECASE),
    re.compile(r"\b(?:icd(?:-10)?|claim number|va icn|icn|date of service|signature)\b", re.IGNORECASE),
]

FIELD_ZONE_LABELS = {
    "name": [
        "patient name",
        "veteran name",
        "member name",
        "full name",
    ],
    "dob": [
        "date of birth",
        "dob",
        "d.o.b.",
    ],
    "authorization_number": [
        "authorization number",
        "authorization",
        "referral number",
        "referral",
        "member id",
        "tracking number",
        "reference number",
        "box 4",
    ],
    "ordering_provider": [
        "ordering provider",
        "ordering physician",
        "requesting provider",
        "ordered by",
        "requested by",
    ],
    "referring_provider": [
        "referring provider",
        "referring va provider",
        "referring physician",
        "referred by",
    ],
    "provider": [
        "provider name",
        "provider",
        "rendering provider",
        "attending provider",
    ],
    "va_icn": [
        "va icn",
        "icn",
        "integrated control number",
    ],
    "claim_number": [
        "claim number",
        "claim #",
        "last four ssn",
    ],
    "service_date_range": [
        "date of service",
        "dates of service",
        "service date",
        "dos",
    ],
    "reason_for_request": [
        "reason for request",
        "reason for referral",
        "requested service",
        "requested procedure",
        "chief complaint",
    ],
    "diagnosis": [
        "diagnosis",
        "assessment",
        "impression",
    ],
    "icd_codes": [
        "icd",
        "icd-10",
        "diagnosis code",
    ],
    "signature_present": [
        "signature",
        "signed by",
        "electronically signed",
    ],
}


def normalize_text(text):
    if not text:
        return ""

    text = str(text).replace("\r", "\n")
    text = re.sub(r"(?<=\w)-\n(?=\w)", "", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def normalize_label(label):
    label = normalize_text(label).lower()
    label = re.sub(r"^[0-9]+[\).\-\s]+", "", label)
    return label.strip(" :-")


def emit(log_fn, message):
    if log_fn:
        log_fn(message)


def render_pdf_pages_as_images(pdf_path, dpi=300, log_fn=None):
    if pdfium is None or Image is None:
        return []

    images = []
    try:
        document = pdfium.PdfDocument(str(Path(pdf_path).expanduser().resolve()))
        scale = max(1.0, float(dpi) / 72.0)

        for index in range(len(document)):
            page = document[index]
            bitmap = page.render(scale=scale, rotation=0)
            pil_image = bitmap.to_pil()
            images.append(pil_image)
        emit(log_fn, f"[DEBUG] Rendered {len(images)} PDF page image(s) with pdfium")
    except Exception as exc:
        emit(log_fn, f"[DEBUG] PDF rendering failed: {exc}")
        return []

    return images


def build_region_crops(image):
    width, height = image.size
    if width <= 0 or height <= 0:
        return []

    def crop(box_name, left, top, right, bottom):
        return {
            "zone_name": box_name,
            "image": image.crop((max(0, int(left)), max(0, int(top)), min(width, int(right)), min(height, int(bottom)))),
            "bbox": [max(0, int(left)), max(0, int(top)), min(width, int(right)), min(height, int(bottom))],
        }

    return [
        crop("page_header", 0, 0, width, height * 0.18),
        crop("left_column", 0, 0, width * 0.45, height),
        crop("center_form", width * 0.15, height * 0.1, width * 0.85, height * 0.9),
        crop("right_column", width * 0.55, 0, width, height),
        crop("page_footer", 0, height * 0.82, width, height),
    ]


def choose_deskew_angle(image):
    if Image is None or ImageStat is None:
        return 0.0

    preview = image.copy()
    preview.thumbnail((1400, 1400))
    preview = preview.convert("L")

    best_angle = 0.0
    best_score = -1.0
    for angle in [step / 10.0 for step in range(-30, 31, 5)]:
        rotated = preview.rotate(angle, resample=getattr(Image, "Resampling", Image).BICUBIC, expand=True, fillcolor=255)
        histogram = ImageStat.Stat(rotated).var
        row_variance = float(histogram[0] if histogram else 0.0)
        if row_variance > best_score:
            best_score = row_variance
            best_angle = angle

    return best_angle


def preprocess_image_object_for_ocr(image, log_fn=None):
    if Image is None or ImageOps is None or ImageFilter is None:
        return image, {"steps": [], "deskew_angle": 0.0}

    steps = []
    image = ImageOps.exif_transpose(image)
    steps.append("exif_transpose")
    image = image.convert("L")
    steps.append("grayscale")

    angle = choose_deskew_angle(image)
    if abs(angle) >= 0.2:
        image = image.rotate(
            angle,
            resample=getattr(Image, "Resampling", Image).BICUBIC,
            expand=True,
            fillcolor=255,
        )
        steps.append(f"deskew_{angle}")

    min_dimension = min(image.size) if image.size else 0
    if min_dimension and min_dimension < 1800:
        scale = 1800 / float(min_dimension)
        image = image.resize(
            (max(1, int(image.width * scale)), max(1, int(image.height * scale))),
            getattr(Image, "Resampling", Image).LANCZOS,
        )
        steps.append("upscale")

    image = ImageOps.autocontrast(image, cutoff=2)
    steps.append("autocontrast")

    if ImageEnhance is not None:
        image = ImageEnhance.Contrast(image).enhance(1.45)
        steps.append("contrast_boost")
        image = ImageEnhance.Sharpness(image).enhance(1.8)
        steps.append("sharpen")

    image = image.filter(ImageFilter.MedianFilter(size=3))
    steps.append("denoise")

    threshold = 170
    if ImageStat is not None:
        stats = ImageStat.Stat(image)
        mean_value = stats.mean[0] if stats.mean else threshold
        threshold = max(128, min(190, int(mean_value)))

    image = image.point(lambda value: 255 if value >= threshold else 0)
    steps.append("binarize")
    image = ImageOps.expand(image, border=12, fill=255)
    steps.append("border")

    emit(log_fn, f"[DEBUG] OCR preprocessing steps: {', '.join(steps)}")
    return image, {
        "steps": steps,
        "deskew_angle": round(angle, 2),
        "size": [image.width, image.height],
        "threshold": threshold,
    }


def split_scanned_image_segments(image, log_fn=None):
    width, height = image.size
    if width <= 0 or height <= 0:
        return [{"segment_index": 0, "segment_reason": "full_page", "bbox": [0, 0, width, height], "image": image}]

    grayscale = image.convert("L")
    segments = []

    if width >= height * 1.45:
        center = width // 2
        seam_window = max(width // 10, 40)
        candidate_start = max(1, center - seam_window)
        candidate_end = min(width - 1, center + seam_window)
        best_x = center
        best_score = None

        for x in range(candidate_start, candidate_end):
            column = grayscale.crop((x, 0, x + 1, height))
            darkness = ImageStat.Stat(column).mean[0]
            if best_score is None or darkness > best_score:
                best_score = darkness
                best_x = x

        if best_x > width * 0.22 and best_x < width * 0.78:
            left_box = [0, 0, best_x, height]
            right_box = [best_x, 0, width, height]
            segments.append({"segment_index": 0, "segment_reason": "split_left", "bbox": left_box, "image": image.crop(tuple(left_box))})
            segments.append({"segment_index": 1, "segment_reason": "split_right", "bbox": right_box, "image": image.crop(tuple(right_box))})
            emit(log_fn, "[DEBUG] Split wide scan into two logical page segments")

    if not segments:
        segments.append({"segment_index": 0, "segment_reason": "full_page", "bbox": [0, 0, width, height], "image": image})

    return segments


def run_tesseract_ocr(image, zone_name="full_page"):
    if pytesseract is None or Output is None or Image is None:
        return None

    try:
        data = pytesseract.image_to_data(
            image,
            output_type=Output.DICT,
            config="--oem 3 --psm 6",
        )
    except Exception:
        return None

    words = []
    line_groups = {}
    count = len(data.get("text", []))

    for index in range(count):
        raw_text = normalize_text(data["text"][index])
        if not raw_text:
            continue

        try:
            confidence = float(data["conf"][index])
        except Exception:
            confidence = -1.0

        bbox = [
            int(data["left"][index]),
            int(data["top"][index]),
            int(data["left"][index] + data["width"][index]),
            int(data["top"][index] + data["height"][index]),
        ]
        word = {
            "text": raw_text,
            "confidence": max(0.0, confidence),
            "bbox": bbox,
            "line_key": (
                data.get("block_num", [0])[index],
                data.get("par_num", [0])[index],
                data.get("line_num", [0])[index],
            ),
        }
        words.append(word)
        line_groups.setdefault(word["line_key"], []).append(word)

    lines = []
    for key, line_words in sorted(line_groups.items(), key=lambda item: item[0]):
        text = " ".join(word["text"] for word in line_words if word["text"]).strip()
        if not text:
            continue

        confidences = [word["confidence"] for word in line_words if word["confidence"] >= 0]
        bbox = [
            min(word["bbox"][0] for word in line_words),
            min(word["bbox"][1] for word in line_words),
            max(word["bbox"][2] for word in line_words),
            max(word["bbox"][3] for word in line_words),
        ]
        lines.append({
            "text": text,
            "confidence": round(sum(confidences) / max(len(confidences), 1), 2) if confidences else 0.0,
            "bbox": bbox,
            "zone_name": zone_name,
        })

    line_text = normalize_text("\n".join(line["text"] for line in lines))
    confidences = [word["confidence"] for word in words if word["confidence"] >= 0]
    overall_confidence = round(sum(confidences) / max(len(confidences), 1), 2) if confidences else 0.0

    return {
        "provider": "tesseract_layout",
        "zone_name": zone_name,
        "text": line_text,
        "confidence": overall_confidence,
        "words": words,
        "lines": lines,
    }


def classify_zone_name(bbox, image_size):
    width, height = image_size
    left, top, right, bottom = bbox
    center_x = (left + right) / 2.0
    center_y = (top + bottom) / 2.0

    if center_y <= height * 0.18:
        return "page_header"
    if center_y >= height * 0.82:
        return "page_footer"
    if center_x <= width * 0.38:
        return "left_column"
    if center_x >= width * 0.62:
        return "right_column"
    return "center_form"


def build_field_zones(lines, image_size):
    zones = []
    seen = set()
    for line in lines:
        text = normalize_text(line.get("text"))
        if not text:
            continue

        label = None
        value = None

        if ":" in text:
            left, right = text.split(":", 1)
            if len(left.strip()) <= 60 and right.strip():
                label = left.strip()
                value = right.strip()
        else:
            inline_match = re.match(
                r"^\s*((?:\d+\s*[\).\-]\s*)?(?:patient name|veteran name|member name|date of birth|dob|authorization(?: number)?|referral(?: number)?|member id|ordering provider|referring provider|provider name|reason for request|requested service|requested procedure|diagnosis|assessment|impression|icd(?:-10)?|va icn|icn|claim number|date of service|signature(?: date)?|signed by))\b\s+(.+)$",
                text,
                flags=re.IGNORECASE,
            )
            if inline_match:
                label = inline_match.group(1).strip()
                value = inline_match.group(2).strip()

        if not label or not value:
            continue

        normalized = normalize_label(label)
        zone_name = line.get("zone_name") or classify_zone_name(line.get("bbox", [0, 0, 0, 0]), image_size)
        zone_key = (normalized, value.lower(), zone_name)
        if zone_key in seen:
            continue
        seen.add(zone_key)

        zones.append({
            "label": label,
            "normalized_label": normalized,
            "value": value,
            "zone_name": zone_name,
            "bbox": list(line.get("bbox") or [0, 0, 0, 0]),
            "confidence": round(float(line.get("confidence") or 0.0), 2),
            "anchor_label": label,
        })

    return zones


def build_layout_summary(words, lines, image_size):
    width, height = image_size
    if width <= 0 or height <= 0:
        width = height = 1

    header_lines = [line for line in lines if line["bbox"][1] <= height * 0.18]
    footer_lines = [line for line in lines if line["bbox"][3] >= height * 0.82]
    left_lines = [line for line in lines if ((line["bbox"][0] + line["bbox"][2]) / 2.0) <= width * 0.42]
    right_lines = [line for line in lines if ((line["bbox"][0] + line["bbox"][2]) / 2.0) >= width * 0.58]

    low_conf_lines = [line for line in lines if float(line.get("confidence") or 0.0) < 55.0]
    signature_lines = [
        line for line in lines
        if re.search(r"\b(?:signature|signed by|electronically signed)\b", line["text"], re.IGNORECASE)
    ]
    table_like = sum(1 for line in lines if len(line["text"].split()) >= 6 and len(re.findall(r"\d", line["text"])) >= 2) >= 3

    return {
        "header_text": normalize_text("\n".join(line["text"] for line in header_lines[:4])),
        "footer_text": normalize_text("\n".join(line["text"] for line in footer_lines[-3:])),
        "left_column_text": normalize_text("\n".join(line["text"] for line in left_lines[:12])),
        "right_column_text": normalize_text("\n".join(line["text"] for line in right_lines[:12])),
        "table_regions": [
            {
                "zone_name": "body_table",
                "confidence": round(sum(float(line.get("confidence") or 0.0) for line in lines) / max(len(lines), 1), 2),
            }
        ] if table_like else [],
        "signature_regions": [
            {
                "text": line["text"],
                "bbox": list(line["bbox"]),
                "confidence": round(float(line.get("confidence") or 0.0), 2),
            }
            for line in signature_lines[:4]
        ],
        "handwritten_regions": [
            {
                "text": line["text"],
                "bbox": list(line["bbox"]),
                "confidence": round(float(line.get("confidence") or 0.0), 2),
            }
            for line in low_conf_lines[:6]
        ],
        "field_zone_count": len(build_field_zones(lines, image_size)),
        "structured_line_count": sum(
            1 for line in lines
            if any(pattern.search(line["text"]) for pattern in FIELD_LABEL_PATTERNS)
        ),
    }


def merge_ocr_runs(primary_run, secondary_run):
    if not primary_run:
        return secondary_run
    if not secondary_run:
        return primary_run

    merged_text_parts = []
    seen_text = set()
    for candidate in (primary_run.get("text"), secondary_run.get("text")):
        normalized = normalize_text(candidate)
        if normalized and normalized.lower() not in seen_text:
            merged_text_parts.append(normalized)
            seen_text.add(normalized.lower())

    merged_lines = []
    seen_lines = set()
    for source in (primary_run, secondary_run):
        for line in source.get("lines", []):
            key = (normalize_text(line.get("text")).lower(), tuple(line.get("bbox") or []), line.get("zone_name"))
            if not key[0] or key in seen_lines:
                continue
            seen_lines.add(key)
            merged_lines.append(line)

    merged_words = list(primary_run.get("words", [])) + list(secondary_run.get("words", []))
    confidences = [
        float(run.get("confidence") or 0.0)
        for run in (primary_run, secondary_run)
        if run
    ]
    image_size = primary_run.get("image_size") or secondary_run.get("image_size") or (1, 1)

    return {
        "provider": primary_run.get("provider") or secondary_run.get("provider"),
        "zone_name": "merged",
        "text": normalize_text("\n".join(merged_text_parts)),
        "confidence": round(max(confidences) if confidences else 0.0, 2),
        "words": merged_words,
        "lines": merged_lines,
        "image_size": image_size,
    }


def ocr_image_with_layout(image, log_fn=None):
    if Image is None:
        return None

    segments = split_scanned_image_segments(image, log_fn=log_fn)
    page_results = []

    for segment in segments:
        processed, preprocessing = preprocess_image_object_for_ocr(segment["image"], log_fn=log_fn)
        full_run = run_tesseract_ocr(processed, zone_name="full_page")

        if not full_run:
            page_results.append({
                "provider": None,
                "text": "",
                "confidence": 0.0,
                "field_zones": [],
                "layout": {},
                "segment_index": segment["segment_index"],
                "segment_reason": segment["segment_reason"],
                "segment_bbox": segment["bbox"],
                "preprocessing": preprocessing,
            })
            continue

        full_run["image_size"] = processed.size
        merged_run = full_run
        region_runs = []

        if full_run.get("confidence", 0.0) < 70.0 or len(full_run.get("text", "")) < 220:
            for region in build_region_crops(processed):
                region_run = run_tesseract_ocr(region["image"], zone_name=region["zone_name"])
                if not region_run or not region_run.get("text"):
                    continue

                adjusted_lines = []
                for line in region_run.get("lines", []):
                    bbox = list(line.get("bbox") or [0, 0, 0, 0])
                    bbox[0] += region["bbox"][0]
                    bbox[1] += region["bbox"][1]
                    bbox[2] += region["bbox"][0]
                    bbox[3] += region["bbox"][1]
                    adjusted_line = dict(line)
                    adjusted_line["bbox"] = bbox
                    adjusted_line["zone_name"] = region["zone_name"]
                    adjusted_lines.append(adjusted_line)

                region_run["lines"] = adjusted_lines
                region_run["image_size"] = processed.size
                region_runs.append({
                    "zone_name": region["zone_name"],
                    "confidence": region_run.get("confidence"),
                    "text_length": len(region_run.get("text", "")),
                })
                merged_run = merge_ocr_runs(merged_run, region_run)

        lines = list(merged_run.get("lines", []))
        field_zones = build_field_zones(lines, processed.size)
        layout = build_layout_summary(merged_run.get("words", []), lines, processed.size)
        page_results.append({
            "provider": merged_run.get("provider"),
            "text": normalize_text(merged_run.get("text")),
            "confidence": round(float(merged_run.get("confidence") or 0.0), 2),
            "field_zones": field_zones,
            "layout": layout,
            "segment_index": segment["segment_index"],
            "segment_reason": segment["segment_reason"],
            "segment_bbox": segment["bbox"],
            "preprocessing": preprocessing,
            "region_runs": region_runs,
        })

    return page_results


def collect_text_field_zones(text):
    zones = []
    seen = set()
    for raw_line in re.split(r"[\r\n]+", str(text or "")):
        line = normalize_text(raw_line)
        if not line or ":" not in line:
            continue
        label, value = line.split(":", 1)
        label = label.strip()
        value = value.strip()
        if not label or not value or len(label) > 60:
            continue
        normalized = normalize_label(label)
        key = (normalized, value.lower())
        if key in seen:
            continue
        seen.add(key)
        zones.append({
            "label": label,
            "normalized_label": normalized,
            "value": value,
            "zone_name": "native_text",
            "bbox": None,
            "confidence": 95.0,
            "anchor_label": label,
        })
    return zones


def build_hybrid_page_metadata(page_number, source_type, native_text="", ocr_results=None, form_lines=None, source_file=None):
    ocr_results = list(ocr_results or [])
    merged_ocr_text = normalize_text("\n".join(result.get("text", "") for result in ocr_results if result.get("text")))
    field_zones = []
    seen = set()
    for zone in collect_text_field_zones(native_text):
        key = (zone.get("normalized_label"), zone.get("value"), zone.get("zone_name"))
        seen.add(key)
        field_zones.append(zone)
    for result in ocr_results:
        for zone in result.get("field_zones", []):
            key = (zone.get("normalized_label"), zone.get("value"), zone.get("zone_name"))
            if key in seen:
                continue
            seen.add(key)
            field_zones.append(zone)

    confidences = [float(result.get("confidence") or 0.0) for result in ocr_results if result.get("confidence") is not None]
    providers = [result.get("provider") for result in ocr_results if result.get("provider")]
    layout = {}
    if ocr_results:
        layout = dict(ocr_results[0].get("layout", {}) or {})
        for extra in ocr_results[1:]:
            extra_layout = dict(extra.get("layout", {}) or {})
            for key in ("header_text", "footer_text", "left_column_text", "right_column_text"):
                if extra_layout.get(key) and extra_layout.get(key) not in normalize_text(layout.get(key, "")).lower():
                    merged = "\n".join(part for part in [layout.get(key), extra_layout.get(key)] if part)
                    layout[key] = normalize_text(merged)
            for list_key in ("table_regions", "signature_regions", "handwritten_regions"):
                layout.setdefault(list_key, [])
                layout[list_key].extend(extra_layout.get(list_key, []))
            layout["field_zone_count"] = max(int(layout.get("field_zone_count", 0)), int(extra_layout.get("field_zone_count", 0)))
            layout["structured_line_count"] = max(int(layout.get("structured_line_count", 0)), int(extra_layout.get("structured_line_count", 0)))

    return {
        "page_number": page_number,
        "source_type": source_type,
        "source_file": source_file,
        "native_text": normalize_text(native_text),
        "ocr_text": merged_ocr_text,
        "ocr_confidence": round(sum(confidences) / max(len(confidences), 1), 2) if confidences else 0.0,
        "ocr_provider": providers[0] if providers else None,
        "form_lines": list(form_lines or []),
        "field_zones": field_zones,
        "layout": layout,
        "ocr_segments": [
            {
                "segment_index": result.get("segment_index"),
                "segment_reason": result.get("segment_reason"),
                "segment_bbox": result.get("segment_bbox"),
                "confidence": result.get("confidence"),
                "provider": result.get("provider"),
                "text_length": len(result.get("text", "")),
                "preprocessing": dict(result.get("preprocessing", {}) or {}),
                "region_runs": list(result.get("region_runs", []) or []),
            }
            for result in ocr_results
        ],
    }


__all__ = [
    "build_hybrid_page_metadata",
    "collect_text_field_zones",
    "normalize_label",
    "normalize_text",
    "ocr_image_with_layout",
    "preprocess_image_object_for_ocr",
    "render_pdf_pages_as_images",
    "split_scanned_image_segments",
]
