"""
TrueCore Field Extractor

Extracts structured medical packet data such as:
- Authorization number
- Patient name
- Date of birth
- ICD codes
- Ordering doctor
- Referring doctor
"""

import re


# -------------------------------------------------
# UTILITY
# -------------------------------------------------

def unique(items):

    seen = set()
    out = []

    for item in items:

        if item not in seen:
            seen.add(item)
            out.append(item)

    return out


# -------------------------------------------------
# AUTHORIZATION NUMBER
# -------------------------------------------------

def find_authorization_number(text):

    patterns = [

        r'authorization\s*(number|#)?\s*[:\-]?\s*(\d{2,12})',
        r'va\s*authorization\s*(number|#)?\s*[:\-]?\s*(\d{2,12})',
        r'va\s*claim\s*number\s*[:\-]?\s*(\d{2,12})',
        r'claim\s*number\s*[:\-]?\s*(\d{2,12})',
        r'auth\s*(number|#)?\s*[:\-]?\s*(\d{2,12})'
    ]

    for pattern in patterns:

        match = re.search(pattern, text, re.I)

        if match:
            return match.group(match.lastindex)

    return None


# -------------------------------------------------
# DATE OF BIRTH
# -------------------------------------------------

def find_dob(text):

    patterns = [

        r'\b\d{2}/\d{2}/\d{4}\b',
        r'\b\d{2}-\d{2}-\d{4}\b',
        r'\b\d{4}-\d{2}-\d{2}\b',
        r'\b\d{2}/\d{2}/\d{2}\b'
    ]

    for pattern in patterns:

        match = re.search(pattern, text)

        if match:
            return match.group(0)

    return None


# -------------------------------------------------
# ICD CODES
# -------------------------------------------------

def find_icd_codes(text):

    # Normalize OCR spacing around ICD decimals
    normalized = re.sub(r'([A-Z]\d{2})\s*\.\s*', r'\1.', text)

    codes = re.findall(r'\b[A-Z][0-9]{2}\.[0-9A-Z]{1,4}\b', normalized)

    return unique(codes)


# -------------------------------------------------
# PATIENT NAME
# -------------------------------------------------

def find_patient_name(text):

    patterns = [

        r'patient\s*name\s*[:\-]?\s*([A-Z][a-z]+\s[A-Z][a-z]+)',
        r'patient\s*name\s*[:\-]?\s*([A-Z][a-z]+\s[A-Z][a-z]+\s[A-Z][a-z]+)',
        r'veteran\s*name\s*[:\-]?\s*([A-Z][a-z]+\s[A-Z][a-z]+)',
        r'veteran\s*name\s*[:\-]?\s*([A-Z][a-z]+\s[A-Z][a-z]+\s[A-Z][a-z]+)'
    ]

    for pattern in patterns:

        match = re.search(pattern, text, re.I)

        if match:
            return match.group(1)

    return None


# -------------------------------------------------
# DOCTOR NAME CLEANUP
# -------------------------------------------------

def clean_doctor(name):

    name = name.strip()

    # Remove trailing labels (common OCR noise)
    name = re.sub(r'\s*(date|phone|fax|email).*', '', name, flags=re.I)

    return name


# -------------------------------------------------
# ORDERING DOCTOR
# -------------------------------------------------

def find_ordering_doctor(text):

    patterns = [

        r'ordering\s*provider\s*[:\-]?\s*(Dr\.?\s*[A-Za-z]+\s*[A-Za-z]*)',
        r'ordering\s*physician\s*[:\-]?\s*(Dr\.?\s*[A-Za-z]+\s*[A-Za-z]*)',
        r'ordering\s*doctor\s*[:\-]?\s*(Dr\.?\s*[A-Za-z]+\s*[A-Za-z]*)'
    ]

    for pattern in patterns:

        match = re.search(pattern, text, re.I)

        if match:
            return clean_doctor(match.group(1))

    return None


# -------------------------------------------------
# REFERRING DOCTOR
# -------------------------------------------------

def find_referring_doctor(text):

    patterns = [

        r'referring\s*va\s*provider\s*[:\-]?\s*(Dr\.?\s*[A-Za-z]+\s*[A-Za-z]*)',
        r'referring\s*provider\s*[:\-]?\s*(Dr\.?\s*[A-Za-z]+\s*[A-Za-z]*)',
        r'referring\s*physician\s*[:\-]?\s*(Dr\.?\s*[A-Za-z]+\s*[A-Za-z]*)'
    ]

    for pattern in patterns:

        match = re.search(pattern, text, re.I)

        if match:
            return clean_doctor(match.group(1))

    return None


# -------------------------------------------------
# MASTER FIELD EXTRACTION
# -------------------------------------------------

def extract_fields(text):

    return {

        "authorization_number": find_authorization_number(text),
        "patient_name": find_patient_name(text),
        "dob": find_dob(text),
        "icd_codes": find_icd_codes(text),
        "ordering_doctor": find_ordering_doctor(text),
        "referring_doctor": find_referring_doctor(text)

    }