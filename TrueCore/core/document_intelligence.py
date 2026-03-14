"""
TrueCore Document Intelligence

Provides additional structural and semantic analysis
for parsed document text.
"""

import re


# ------------------------------------------------
# SAFE TEXT EXTRACTION
# ------------------------------------------------

def _extract_text(text):
    """
    Safely extract usable text from various input structures.
    """

    if isinstance(text, dict):

        if "text" in text and isinstance(text["text"], str):
            return text["text"]

        if "content" in text and isinstance(text["content"], str):
            return text["content"]

        if "raw_text" in text and isinstance(text["raw_text"], str):
            return text["raw_text"]

        return str(text)

    if text is None:
        return ""

    return str(text)


# ------------------------------------------------
# TABLE DETECTION
# ------------------------------------------------

def detect_tables(text):

    text = _extract_text(text)

    tables = []

    lines = text.split("\n")

    for line in lines:

        line_strip = line.strip()

        # Detect typical table formatting patterns
        if (
            "|" in line_strip
            or "\t" in line_strip
            or re.search(r"\s{3,}", line_strip)
        ):
            tables.append(line_strip)

    return tables


# ------------------------------------------------
# CHECKBOX DETECTION
# ------------------------------------------------

def detect_checkboxes(text):

    text = _extract_text(text)

    checkboxes = []

    patterns = [
        "☐",
        "☑",
        "[ ]",
        "[x]",
        "( )",
        "(x)",
        "□",
        "■"
    ]

    for pattern in patterns:

        if pattern in text:
            checkboxes.append(pattern)

    return checkboxes


# ------------------------------------------------
# SIGNATURE DETECTION
# ------------------------------------------------

def detect_signature(text):

    text = _extract_text(text)

    signature_keywords = [

        "signature",
        "signed",
        "physician signature",
        "provider signature",
        "electronically signed",
        "digitally signed"

    ]

    text_lower = text.lower()

    for keyword in signature_keywords:

        if keyword in text_lower:
            return True

    return False


# ------------------------------------------------
# SEMANTIC FIELD DETECTION
# ------------------------------------------------

def semantic_field_detection(text):

    text = _extract_text(text)

    results = {}

    # Possible name detection
    name_match = re.search(
        r"\b([A-Z][a-z]+ [A-Z][a-z]+(?: [A-Z][a-z]+)?)\b",
        text
    )

    if name_match:
        results["Possible Name"] = name_match.group(1)

    # Possible DOB detection
    dob_match = re.search(
        r"\b\d{1,2}/\d{1,2}/\d{2,4}\b",
        text
    )

    if dob_match:
        results["Possible DOB"] = dob_match.group()

    # Possible ICD detection
    icd_match = re.findall(
        r"\b[A-Z]\d{2}\.?\d{0,3}\b",
        text
    )

    if icd_match:
        results["Possible Diagnosis"] = icd_match[0]

    return results

# ------------------------------------------------
# CLINICAL NARRATIVE EXTRACTION
# ------------------------------------------------

def extract_clinical_narratives(text):

    text = _extract_text(text)
    text_lower = text.lower()

    results = {
        "symptoms": [],
        "procedures": [],
        "diagnosis_terms": [],
        "treatments": []
    }

    symptom_keywords = [
        "pain",
        "numbness",
        "weakness",
        "fatigue",
        "headache",
        "dizziness"
    ]

    procedure_keywords = [
        "mri",
        "ct scan",
        "x-ray",
        "ultrasound",
        "surgery"
    ]

    diagnosis_keywords = [
        "hernia",
        "herniation",
        "fracture",
        "degeneration",
        "arthritis",
        "lesion"
    ]

    treatment_keywords = [
        "therapy",
        "medication",
        "injection",
        "rehabilitation",
        "surgery"
    ]

    for word in symptom_keywords:
        if word in text_lower:
            results["symptoms"].append(word)

    for word in procedure_keywords:
        if word in text_lower:
            results["procedures"].append(word)

    for word in diagnosis_keywords:
        if word in text_lower:
            results["diagnosis_terms"].append(word)

    for word in treatment_keywords:
        if word in text_lower:
            results["treatments"].append(word)

    return results
# ------------------------------------------------
# STRUCTURED SECTION DETECTION
# ------------------------------------------------

def detect_structured_sections(text):

    text = _extract_text(text)

    sections = {}

    lines = text.split("\n")

    section_patterns = [

        "DIAGNOSIS",
        "ASSESSMENT",
        "PLAN",
        "IMPRESSION",
        "FINDINGS",
        "PROCEDURE",
        "HISTORY OF PRESENT ILLNESS",
        "CLINICAL INDICATION",
        "REASON FOR VISIT"

    ]

    for i, line in enumerate(lines):

        line_clean = line.strip().upper()

        if line_clean in section_patterns:

            start = i + 1
            end = min(start + 20, len(lines))

            section_text = "\n".join(lines[start:end])

            sections[line_clean] = section_text

    return sections