"""
TrueCore Packet Processor

Handles packet analysis for both single files and folders.
Extracts text, detects forms, validates packets, and returns
structured analysis results.
"""

import os

from TrueCore.extraction.parser import parse_document
from TrueCore.extraction.extractor import extract_fields
from TrueCore.detection.form_detector import detect_document_features
from TrueCore.validation.validator import validate_packet
from TrueCore.validation.suggestions import generate_suggestions
from TrueCore.medical.icd_lookup import detect_icd_codes
from TrueCore.core.intel_bridge import build_intel_result
from TrueCore.utils.logging_system import log_event


SUPPORTED_EXTENSIONS = [
    ".pdf",
    ".docx",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
]


# -------------------------------------------------
# SINGLE FILE PROCESSING
# -------------------------------------------------

def process_file(file_path, approved_icd_codes=None):

    filename = os.path.basename(file_path)

    if not os.path.exists(file_path):

        log_event("file_missing", filename)

        return {
            "file": filename,
            "score": 0,
            "fields": {},
            "forms": [],
            "issues": ["File not found"],
            "fixes": [],
        }

    text = parse_document(file_path)

    if not text:

        log_event("no_text_detected", filename)

        return {
            "file": filename,
            "score": 0,
            "fields": {},
            "forms": [],
            "issues": ["No readable text detected"],
            "fixes": [],
        }

    # Extract fields
    fields = extract_fields(text)

    # Detect ICD codes
    icd_codes = detect_icd_codes(text, approved_icd_codes)

    if icd_codes:
        fields["icd_codes"] = icd_codes

    # Detect document features
    features = detect_document_features(text)
    detected_forms = features.get("forms_detected", [])

    # Validate packet
    validation = validate_packet(fields, detected_forms)

    issues = validation.get("issues", [])
    score = validation.get("score", 100)

    # Generate suggestions
    suggestions = generate_suggestions(
            issues,
            fields,
            detected_forms,
            text
    )
    
    log_event("packet_processed", filename)

    result = {
        "file": filename,
        "score": score,
        "fields": fields,
        "forms": detected_forms,
        "issues": issues,
        "fixes": suggestions,
    }

    intel_result = build_intel_result(
        file_path,
        approved_icd_codes=approved_icd_codes,
        legacy_result=result,
    )

    if intel_result:
        return intel_result

    return result


# -------------------------------------------------
# FOLDER PROCESSING
# -------------------------------------------------

def process_folder(folder_path, approved_icd_codes=None):

    results = []

    if not os.path.exists(folder_path):
        return results

    for root, _, files in os.walk(folder_path):

        for file in files:

            ext = os.path.splitext(file)[1].lower()

            if ext not in SUPPORTED_EXTENSIONS:
                continue

            full_path = os.path.join(root, file)

            try:

                result = process_file(full_path, approved_icd_codes)
                results.append(result)

            except Exception as e:

                log_event("processing_error", f"{file} | {str(e)}")

                results.append({
                    "file": file,
                    "score": 0,
                    "fields": {},
                    "forms": [],
                    "issues": ["Processing error occurred"],
                    "fixes": [],
                })

    log_event("folder_processed", folder_path)

    return results


# -------------------------------------------------
# ENTRY POINT
# -------------------------------------------------

def process_packet(path, approved_icd_codes=None):

    if os.path.isdir(path):
        return process_folder(path, approved_icd_codes)

    return process_file(path, approved_icd_codes)
