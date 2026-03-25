FORM_TEMPLATES = {
    "cover_sheet": {
        "strong_patterns": [
            r"\bsubmission\s+cover\s+sheet\b",
        ],
        "packet_level_patterns": [
            r"\b(?:va\s+)?submission\s+cover\s+sheet\b",
        ],
        "expected_fields": [
            "name",
            "dob",
            "ordering_provider",
            "npi",
            "clinic_name",
            "facility",
            "location",
            "claim_number",
        ],
    },
    "consent": {
        "strong_patterns": [
            r"\bvirtual\s+consent\s+form\b",
            r"\btelehealth\s+virtual\s+consent\s+form\b",
            r"\bconsent\s+for\s+telehealth\b",
        ],
        "packet_level_patterns": [
            r"\btelehealth\s+virtual\s+consent\s+form\b",
            r"\bvirtual\s+consent\s+form\b",
            r"\bconsent\s+for\s+telehealth\b",
        ],
        "expected_fields": [
            "name",
            "dob",
            "signature_present",
        ],
    },
    "consult_request": {
        "strong_patterns": [
            r"\bconsultation\s+and\s+treatment\s+request\b",
            r"\bconsult\s+and\s+treatment\s+request\b",
        ],
        "packet_level_patterns": [
            r"\bconsultation\s+and\s+treatment\s+request\b",
            r"\bconsult\s+and\s+treatment\s+request\b",
        ],
        "expected_fields": [
            "name",
            "dob",
            "ordering_provider",
            "referring_provider",
            "authorization_number",
            "va_icn",
            "claim_number",
            "reason_for_request",
            "facility",
            "clinic_name",
            "location",
        ],
    },
    "seoc": {
        "strong_patterns": [
            r"\bsingle\s+episode\s+of\s+care\b",
            r"\bseoc\b",
        ],
        "packet_level_patterns": [
            r"\bsingle\s+episode\s+of\s+care\b",
            r"\bseoc\b",
        ],
        "expected_fields": [
            "name",
            "dob",
            "referring_provider",
            "facility",
            "clinic_name",
            "location",
            "authorization_number",
            "service_date_range",
        ],
    },
    "lomn": {
        "strong_patterns": [
            r"\bletter\s+of\s+medical\s+necessity\b",
            r"\bmedical\s+necessity\s+letter\b",
        ],
        "packet_level_patterns": [
            r"\bletter\s+of\s+medical\s+necessity\b",
            r"\bmedical\s+necessity\s+letter\b",
        ],
        "expected_fields": [
            "name",
            "dob",
            "ordering_provider",
            "referring_provider",
            "diagnosis",
            "reason_for_request",
            "service_date_range",
            "facility",
            "signature_present",
        ],
    },
    "rfs": {
        "strong_patterns": [
            r"\bva\s+form\s+10[\s\-]*10172\b",
            r"\b10[\s\-]*10172\b",
            r"\brequest\s+for\s+service(?:s)?\b",
        ],
        "packet_level_patterns": [
            r"\b(?:medical\s+)?request\s+for\s+service(?:s)?\b",
            r"\b(?:va\s+form\s+)?10[\s\-]*10172\b",
        ],
        "expected_fields": [
            "name",
            "dob",
            "ordering_provider",
            "referring_provider",
            "authorization_number",
            "va_icn",
            "claim_number",
            "service_date_range",
            "facility",
            "clinic_name",
            "location",
        ],
    },
    "clinical_notes": {
        "strong_patterns": [
            r"\bclinical\s+notes?\b",
            r"\bclinical\s+documentation\b",
            r"\bprogress\s+notes?\b",
            r"\bhistory\s+of\s+present\s+illness\b",
            r"\bassessment\s+and\s+plan\b",
        ],
        "packet_level_patterns": [
            r"\bclinical\s+documentation\s+template\b",
            r"\bclinical\s+notes?\b",
        ],
        "expected_fields": [
            "name",
            "dob",
            "provider",
            "ordering_provider",
            "referring_provider",
            "va_icn",
            "diagnosis",
            "symptom",
            "procedure",
            "icd_codes",
            "medications",
            "service_date_range",
            "facility",
            "clinic_name",
            "location",
            "signature_present",
        ],
    },
}


SUPPORTED_DOCUMENT_TYPES = tuple(FORM_TEMPLATES.keys())
