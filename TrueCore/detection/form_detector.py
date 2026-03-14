"""
TrueCore Form Detector

Identifies document types inside a packet using
keyword fingerprint detection.
"""

import re


# -------------------------------------------------
# FORM KEYWORD FINGERPRINTS
# -------------------------------------------------

FORM_KEYWORDS = {

    "Virtual Consent Form": [
        "virtual consent",
        "telehealth consent",
        "consent for telehealth",
    ],

    "VA Form 10-10172": [
        "10-10172",
        "va form 10-10172",
        "request for services",
        "community care",
    ],

    "SEOC": [
        "episode of care",
        "seoc",
        "service episode",
    ],

    "Consultation & Treatment Request": [
        "consultation request",
        "treatment request",
        "consultation & treatment",
    ],

    "Letter of Medical Necessity": [
        "letter of medical necessity",
        "medical necessity",
        "lomn",
    ],

    "MRI Report": [
        "mri",
        "findings",
        "impression",
        "radiology report",
    ],

    "Clinical Notes": [
        "history of present illness",
        "assessment and plan",
        "clinical note",
        "provider notes",
    ],
}


# -------------------------------------------------
# TEXT NORMALIZATION
# -------------------------------------------------

def normalize_text(text):

    if not text:
        return ""

    text = text.lower()
    text = re.sub(r"\s+", " ", text)

    return text


# -------------------------------------------------
# FORM DETECTION
# -------------------------------------------------

def detect_forms(text):

    normalized = normalize_text(text)

    detected_forms = []
    seen = set()

    for form_name, keywords in FORM_KEYWORDS.items():

        for keyword in keywords:

            if keyword in normalized:

                if form_name not in seen:
                    detected_forms.append(form_name)
                    seen.add(form_name)

                break

    return detected_forms


# -------------------------------------------------
# PRIMARY FEATURE API
# -------------------------------------------------

def detect_document_features(text):

    forms = list(set(detect_forms(text) + detect_forms_with_scoring(text)))

    features = {
        "forms_detected": forms,
        "form_count": len(forms),
    }

    return features

# -------------------------------------------------
# PROBABILITY SCORING DETECTION
# -------------------------------------------------

FORM_CONTEXT_SIGNALS = {

    "Virtual Consent Form": [
        "telehealth",
        "video visit",
        "remote consultation"
    ],

    "VA Form 10-10172": [
        "community care",
        "referral authorization",
        "request for services"
    ],

    "Letter of Medical Necessity": [
        "medically necessary",
        "required treatment",
        "supporting documentation"
    ],

}


def score_form_probability(text, form_name):

    text_lower = normalize_text(text)

    score = 0

    # Keyword score
    keywords = FORM_KEYWORDS.get(form_name, [])

    for keyword in keywords:
        if keyword in text_lower:
            score += 50

    # Context score
    signals = FORM_CONTEXT_SIGNALS.get(form_name, [])

    for signal in signals:
        if signal in text_lower:
            score += 15

    return score


def detect_forms_with_scoring(text):

    detected = []

    for form_name in FORM_KEYWORDS:

        score = score_form_probability(text, form_name)

        if score >= 40:
            detected.append(form_name)

    return detected