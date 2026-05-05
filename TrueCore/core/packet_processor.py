"""
TrueCore Packet Processor

Handles packet analysis for both single files and folders.
Extracts text, detects forms, validates packets, and returns
structured analysis results.
"""

import os
from time import perf_counter

from TrueCore.extraction.parser import parse_document
from TrueCore.extraction.extractor import extract_fields
from TrueCore.detection.form_detector import detect_document_features
from TrueCore.validation.validator import validate_packet
from TrueCore.validation.suggestions import generate_suggestions
from TrueCore.medical.icd_lookup import detect_icd_codes
from TrueCore.core.case_memory import record_packet_analysis
from TrueCore.core.intel_bridge import build_intel_result
from TrueCore.core.host_intelligence import enrich_result_with_host_intelligence
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

def _missing_file_result(filename):

    return {
        "file": filename,
        "score": 0,
        "fields": {},
        "forms": [],
        "issues": ["File not found"],
        "fixes": [],
    }


def _no_text_result(filename):

    return {
        "file": filename,
        "score": 0,
        "fields": {},
        "forms": [],
        "issues": ["No readable text detected"],
        "fixes": [],
    }


def _build_legacy_result(file_path, approved_icd_codes=None):

    filename = os.path.basename(file_path)
    text = parse_document(file_path)

    if not text:
        log_event("no_text_detected", filename)
        return _no_text_result(filename)

    fields = extract_fields(text)
    icd_codes = detect_icd_codes(text, approved_icd_codes)

    if icd_codes:
        fields["icd_codes"] = icd_codes

    features = detect_document_features(text)
    detected_forms = features.get("forms_detected", [])
    validation = validate_packet(fields, detected_forms)
    issues = validation.get("issues", [])
    score = validation.get("score", 100)
    suggestions = generate_suggestions(
        issues,
        fields,
        detected_forms,
        text,
    )

    return {
        "file": filename,
        "score": score,
        "fields": fields,
        "forms": detected_forms,
        "issues": issues,
        "fixes": suggestions,
    }


def _attach_profiling(result, profiling):

    payload = dict(result or {})
    profile = dict(profiling or {})
    payload["profiling"] = profile

    intel = dict(payload.get("intel", {}) or {})
    if intel:
        intel["profiling"] = profile
        payload["intel"] = intel

    return payload


def process_file(file_path, approved_icd_codes=None):

    filename = os.path.basename(file_path)

    if not os.path.exists(file_path):

        log_event("file_missing", filename)

        return _missing_file_result(filename)

    overall_start = perf_counter()

    intel_start = perf_counter()
    intel_result = build_intel_result(
        file_path,
        approved_icd_codes=approved_icd_codes,
    )
    intel_elapsed = perf_counter() - intel_start

    if intel_result:
        profiled_result = _attach_profiling(
            intel_result,
            {
                "analysis_mode": "intel",
                "intel_seconds": round(intel_elapsed, 3),
                "legacy_seconds": 0.0,
                "host_seconds": 0.0,
                "total_seconds": 0.0,
            },
        )
        host_start = perf_counter()
        final_result = enrich_result_with_host_intelligence(file_path, profiled_result, persist=False)
        host_elapsed = perf_counter() - host_start
        total_elapsed = perf_counter() - overall_start
        final_result = _attach_profiling(
            final_result,
            {
                "analysis_mode": "intel",
                "intel_seconds": round(intel_elapsed, 3),
                "legacy_seconds": 0.0,
                "host_seconds": round(host_elapsed, 3),
                "total_seconds": round(total_elapsed, 3),
            },
        )
        record_packet_analysis(
            file_path,
            final_result,
            triage_intelligence=final_result.get("intel", {}).get("triage_intelligence"),
        )
        log_event("host_intelligence_active", filename)
        log_event("packet_processed", filename)
        return final_result

    legacy_start = perf_counter()
    legacy_result = _build_legacy_result(
        file_path,
        approved_icd_codes=approved_icd_codes,
    )
    legacy_elapsed = perf_counter() - legacy_start

    profiled_legacy_result = _attach_profiling(
        legacy_result,
        {
            "analysis_mode": "legacy_fallback",
            "intel_seconds": round(intel_elapsed, 3),
            "legacy_seconds": round(legacy_elapsed, 3),
            "host_seconds": 0.0,
            "total_seconds": 0.0,
        },
    )
    host_start = perf_counter()
    final_result = enrich_result_with_host_intelligence(file_path, profiled_legacy_result, persist=False)
    host_elapsed = perf_counter() - host_start
    total_elapsed = perf_counter() - overall_start
    final_result = _attach_profiling(
        final_result,
        {
            "analysis_mode": "legacy_fallback",
            "intel_seconds": round(intel_elapsed, 3),
            "legacy_seconds": round(legacy_elapsed, 3),
            "host_seconds": round(host_elapsed, 3),
            "total_seconds": round(total_elapsed, 3),
        },
    )
    record_packet_analysis(
        file_path,
        final_result,
        triage_intelligence=final_result.get("intel", {}).get("triage_intelligence"),
    )
    log_event("host_intelligence_active", filename)
    log_event("packet_processed", filename)
    return final_result


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
