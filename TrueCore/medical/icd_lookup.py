"""
TrueCore ICD Lookup System

Handles loading approved ICD codes and detecting ICD
diagnosis codes inside packet text.
"""

import re
import csv
import os

from TrueCore.utils.runtime_info import resource_path


# -------------------------------------------------
# GLOBAL ICD DATABASE
# -------------------------------------------------

ICD_DATABASE = set()


# -------------------------------------------------
# LOAD ICD DATABASE
# -------------------------------------------------

def load_icd_database(csv_path="assets/Approved-VA-ICD-10-Codes-List.csv"):

    icd_set = set()

    # Resolve path safely for both development and PyInstaller builds
    try:
        resolved_path = resource_path(csv_path)
    except Exception:
        resolved_path = csv_path

    if not os.path.exists(resolved_path):
        return icd_set

    try:

        with open(resolved_path, newline="", encoding="utf-8") as file:

            reader = csv.reader(file)

            for row in reader:

                if not row:
                    continue

                code = row[0].strip().upper()

                if code:
                    icd_set.add(code)

    except Exception:
        return icd_set

    return icd_set


# -------------------------------------------------
# GUI COMPATIBILITY FUNCTION
# -------------------------------------------------

def load_icd_codes(csv_path="assets/Approved-VA-ICD-10-Codes-List.csv"):

    global ICD_DATABASE

    ICD_DATABASE = load_icd_database(csv_path)

    return ICD_DATABASE


# -------------------------------------------------
# ICD REGEX
# -------------------------------------------------

ICD_PATTERN = re.compile(r"\b[A-TV-Z][0-9][0-9AB]\.?[0-9A-TV-Z]{0,4}\b")


# -------------------------------------------------
# CLINICAL CONTEXT KEYWORDS
# -------------------------------------------------

CLINICAL_CONTEXT = [

    "diagnosis",
    "assessment",
    "impression",
    "plan",
    "history",
    "clinical indication",
    "reason for visit",
]


# -------------------------------------------------
# NORMALIZE ICD
# -------------------------------------------------

def normalize_icd(code):

    code = code.upper().replace(" ", "")

    if "." not in code and len(code) > 3:
        code = code[:3] + "." + code[3:]

    return code


# -------------------------------------------------
# BASIC ICD EXTRACTION
# -------------------------------------------------

def extract_icd_codes(text, approved_codes=None):

    if not text:
        return []

    text_upper = text.upper()

    found_codes = set()

    matches = ICD_PATTERN.findall(text_upper)

    for match in matches:

        code = normalize_icd(match)

        if approved_codes:

            if code not in approved_codes:
                continue

        found_codes.add(code)

    return sorted(found_codes)


# -------------------------------------------------
# CONTEXT-AWARE ICD DETECTION
# -------------------------------------------------

def extract_contextual_icd(text, approved_codes=None):

    if not text:
        return []

    results = set()

    lines = text.split("\n")

    for line in lines:

        line_upper = line.upper()

        for keyword in CLINICAL_CONTEXT:

            if keyword.upper() in line_upper:

                matches = ICD_PATTERN.findall(line_upper)

                for match in matches:

                    code = normalize_icd(match)

                    if approved_codes:

                        if code not in approved_codes:
                            continue

                    results.add(code)

    return sorted(results)


# -------------------------------------------------
# PRIMARY ICD DETECTOR
# -------------------------------------------------

def detect_icd_codes(text, approved_codes=None):

    if approved_codes is None:
        approved_codes = ICD_DATABASE

    regex_codes = extract_icd_codes(text, approved_codes)

    contextual_codes = extract_contextual_icd(text, approved_codes)

    inferred_codes = infer_icd_from_clinical_text(text, approved_codes)

    # Prefer contextual detection when available
    if contextual_codes:
        combined = set(contextual_codes) | set(inferred_codes)
    else:
        combined = set(regex_codes) | set(inferred_codes)

    return sorted(combined)


# -------------------------------------------------
# CLINICAL TERM → ICD INFERENCE
# -------------------------------------------------

CLINICAL_TO_ICD = {

    "back pain": "M54.50",
    "low back pain": "M54.50",
    "lumbar pain": "M54.50",

    "ptsd": "F43.12",
    "post traumatic stress disorder": "F43.12",

    "concussion": "S06.0X0A",

    "disc herniation": "M51.26",
    "herniated disc": "M51.26",

    "arthritis": "M19.90",

    "migraine": "G43.909",

}


def infer_icd_from_clinical_text(text, approved_codes=None):

    if not text:
        return []

    text_lower = text.lower()

    inferred = set()

    for phrase, code in CLINICAL_TO_ICD.items():

        if phrase in text_lower:

            normalized = normalize_icd(code)

            if approved_codes:

                if normalized not in approved_codes:
                    continue

            inferred.add(normalized)

    return sorted(inferred)