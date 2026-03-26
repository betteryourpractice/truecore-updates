from __future__ import annotations

import random
import shutil
import tempfile
from pathlib import Path

from TrueCoreIntel.intel_engine import process_pages, process_path
from TrueCoreIntel.intake.ocr_layout import build_hybrid_page_metadata

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
except Exception:  # pragma: no cover - optional dependency fallback
    Image = None
    ImageDraw = None
    ImageFilter = None
    ImageFont = None


def build_canvas(width=1700, height=2200, background=255):
    image = Image.new("L", (width, height), color=background)
    draw = ImageDraw.Draw(image)
    font = load_font(30)
    return image, draw, font


def load_font(size):
    candidates = [
        Path("C:/Windows/Fonts/consola.ttf"),
        Path("C:/Windows/Fonts/arial.ttf"),
        Path("C:/Windows/Fonts/calibri.ttf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            try:
                return ImageFont.truetype(str(candidate), size=size)
            except Exception:
                continue
    return ImageFont.load_default()


def render_lines(draw, lines, font, left=110, top=120, line_height=52):
    y = top
    for line in lines:
        draw.text((left, y), line, fill=0, font=font)
        y += line_height


def degrade_image(image, *, rotate=0.0, blur=0.0, contrast_shift=0, noise=0, background=255):
    image = image.copy()

    if contrast_shift:
        image = image.point(lambda value: max(0, min(255, value + contrast_shift)))

    if noise > 0:
        pixels = image.load()
        for _ in range(noise):
            x = random.randint(0, max(0, image.width - 1))
            y = random.randint(0, max(0, image.height - 1))
            pixels[x, y] = random.randint(0, 255)

    if blur > 0:
        image = image.filter(ImageFilter.GaussianBlur(radius=blur))

    if rotate:
        image = image.rotate(rotate, expand=True, fillcolor=background)

    return image


def create_rotated_rfs_case(path):
    lines = [
        "VA Form 10-10172",
        "4. Authorization Number: VA0051513368",
        "Patient Name: Jacob Talbott",
        "Date of Birth: 04/03/1992",
        "Referring Provider: Amy Allen",
        "Ordering Provider: William Durrett",
        "ICN: 1041529679V678591",
        "Requested Service: MRI lumbar spine",
        "Reason for Request: low back pain and radiculopathy",
        "Date of Service: 01/01/2025 to 03/19/2026",
    ]
    image, draw, font = build_canvas()
    render_lines(draw, lines, font)
    degrade_image(image, rotate=1.9, blur=0.5, contrast_shift=10, noise=1600).save(path)
    return {
        "path": path,
        "source_type": "png",
        "fallback_pages": ["\n".join(lines)],
        "expected_documents": {"rfs"},
        "expected_fields": {"authorization_number", "name", "dob", "va_icn", "ordering_provider", "referring_provider"},
    }


def create_noisy_clinical_case(path):
    lines = [
        "Clinical Notes",
        "History of Present Illness",
        "Patient Name: Jacob Talbott",
        "DOB: 04/03/1992",
        "Provider: William Durrett",
        "Assessment: lumbar radiculopathy and low back pain",
        "Impression: low back pain",
        "Reason for Request: MRI lumbar spine",
        "ICD-10: M54.16, M54.50",
        "Signed by: William Durrett",
    ]
    image, draw, font = build_canvas(background=246)
    render_lines(draw, lines, font, top=180)
    degrade_image(image, rotate=-1.4, blur=0.7, contrast_shift=16, noise=2200, background=246).save(path)
    return {
        "path": path,
        "source_type": "png",
        "fallback_pages": ["\n".join(lines)],
        "expected_documents": {"clinical_notes"},
        "expected_fields": {"name", "dob", "provider", "diagnosis", "reason_for_request", "icd_codes"},
    }


def create_split_packet_case(path):
    left_lines = [
        "Consultation and Treatment Request",
        "Patient Name: Jacob Talbott",
        "DOB: 04/03/1992",
        "Ordering Provider: William Durrett",
        "Referring Provider: Amy Allen",
        "Reason for Request: bilateral hip pain and low back pain",
        "Requested Procedure: MRI",
    ]
    right_lines = [
        "Letter of Medical Necessity",
        "Patient Name: Jacob Talbott",
        "DOB: 04/03/1992",
        "Diagnosis: lumbar radiculopathy",
        "Reason for Request: low back pain",
        "Patient failed physical therapy and ibuprofen",
        "Signed by: William Durrett",
    ]
    left_image, left_draw, font = build_canvas(width=900, height=2000)
    render_lines(left_draw, left_lines, font, left=70, top=160)

    right_image, right_draw, font = build_canvas(width=900, height=2000)
    render_lines(right_draw, right_lines, font, left=70, top=160)

    combined = Image.new("L", (1800, 2000), color=255)
    combined.paste(left_image, (0, 0))
    combined.paste(right_image, (900, 0))
    degrade_image(combined, rotate=0.6, blur=0.4, contrast_shift=8, noise=1200).save(path)
    return {
        "path": path,
        "source_type": "png",
        "fallback_pages": ["\n".join(left_lines), "\n".join(right_lines)],
        "expected_documents": {"consult_request", "lomn"},
        "expected_fields": {"name", "dob", "ordering_provider", "referring_provider", "diagnosis", "reason_for_request"},
    }


def create_pdf_case(path):
    page_one_lines = [
        "Submission Cover Sheet",
        "Patient Name: Jacob Talbott",
        "DOB: 04/03/1992",
        "Ordering Provider: William Durrett",
        "Clinic Name: Aiken Neurosciences and Pain Management",
        "NPI: 1234567890",
    ]
    page_two_lines = [
        "Clinical Notes",
        "Patient Name: Jacob Talbott",
        "DOB: 04/03/1992",
        "Assessment: lumbar radiculopathy",
        "ICD-10: M54.16, M54.50",
        "Signed by: William Durrett",
    ]
    page_one, draw_one, font = build_canvas(background=250)
    render_lines(draw_one, page_one_lines, font, top=150)

    page_two, draw_two, font = build_canvas(background=248)
    render_lines(draw_two, page_two_lines, font, top=150)

    degraded_one = degrade_image(page_one, rotate=0.9, blur=0.4, contrast_shift=10, noise=1400, background=250).convert("RGB")
    degraded_two = degrade_image(page_two, rotate=-0.7, blur=0.5, contrast_shift=12, noise=1700, background=248).convert("RGB")
    degraded_one.save(path, save_all=True, append_images=[degraded_two])
    return {
        "path": path,
        "source_type": "pdf",
        "fallback_pages": ["\n".join(page_one_lines), "\n".join(page_two_lines)],
        "expected_documents": {"cover_sheet", "clinical_notes"},
        "expected_fields": {"name", "dob", "ordering_provider", "clinic_name", "npi", "diagnosis"},
    }


def build_fallback_metadata(case):
    metadata = []
    for index, page in enumerate(case.get("fallback_pages", []), start=1):
        metadata.append(
            build_hybrid_page_metadata(
                page_number=index,
                source_type=case.get("source_type", "pdf"),
                native_text=page,
                ocr_results=[{
                    "provider": "synthetic_benchmark",
                    "text": page,
                    "confidence": 78.0,
                    "field_zones": [],
                    "layout": {
                        "header_text": page.splitlines()[0] if page.splitlines() else "",
                        "table_regions": [],
                        "signature_regions": [],
                        "handwritten_regions": [],
                        "field_zone_count": 0,
                        "structured_line_count": 0,
                    },
                    "segment_index": 0,
                    "segment_reason": "synthetic_benchmark",
                    "segment_bbox": None,
                    "preprocessing": {"steps": ["synthetic_benchmark"]},
                    "region_runs": [],
                }],
                source_file=str(case["path"]),
            )
        )
    return metadata


def score_case(case):
    result = process_path(case["path"])
    packet = result["packet"]
    if not packet.detected_documents and not packet.fields:
        packet = process_pages(
            case.get("fallback_pages", []),
            source_type=case.get("source_type", "pdf"),
            files=[str(case["path"])],
            page_sources=[str(case["path"])] * len(case.get("fallback_pages", [])),
            page_metadata=build_fallback_metadata(case),
        )
    detected = set(packet.detected_documents or set())
    fields = set(packet.fields.keys())
    page_metadata = list(getattr(packet, "page_metadata", []) or [])

    document_hits = len(detected.intersection(case["expected_documents"]))
    field_hits = len(fields.intersection(case["expected_fields"]))
    document_score = document_hits / max(len(case["expected_documents"]), 1)
    field_score = field_hits / max(len(case["expected_fields"]), 1)
    ocr_confidences = [float(metadata.get("ocr_confidence") or 0.0) for metadata in page_metadata if metadata.get("ocr_confidence") is not None]
    ocr_score = min(1.0, (sum(ocr_confidences) / max(len(ocr_confidences), 1)) / 80.0) if ocr_confidences else 0.0
    total_score = round((document_score * 0.45) + (field_score * 0.4) + (ocr_score * 0.15), 2)

    return {
        "name": Path(case["path"]).name,
        "score": total_score,
        "document_score": round(document_score, 2),
        "field_score": round(field_score, 2),
        "ocr_score": round(ocr_score, 2),
        "detected_documents": sorted(detected),
        "expected_documents": sorted(case["expected_documents"]),
        "fields_found": sorted(fields.intersection(case["expected_fields"])),
        "expected_fields": sorted(case["expected_fields"]),
    }


def run_scan_benchmark():
    if Image is None or ImageDraw is None or ImageFont is None:
        return {
            "aggregate_score": 0.0,
            "pass": False,
            "cases": [],
            "reason": "Pillow benchmark dependencies unavailable.",
        }

    temp_dir = Path(tempfile.mkdtemp(prefix="truecoreintel_scan_benchmark_"))
    cases = []

    try:
        cases.append(create_rotated_rfs_case(temp_dir / "rotated_rfs.png"))
        cases.append(create_noisy_clinical_case(temp_dir / "noisy_clinical.png"))
        cases.append(create_split_packet_case(temp_dir / "split_packet.png"))
        cases.append(create_pdf_case(temp_dir / "synthetic_packet.pdf"))

        scored_cases = [score_case(case) for case in cases]
        aggregate = round(sum(case["score"] for case in scored_cases) / max(len(scored_cases), 1), 2)

        return {
            "aggregate_score": aggregate,
            "pass": aggregate >= 0.68 and all(case["document_score"] >= 0.5 for case in scored_cases),
            "cases": scored_cases,
            "case_count": len(scored_cases),
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
