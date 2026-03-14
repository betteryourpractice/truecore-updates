"""
TrueCore Packet Classifier

Classifies packets based on detected textual patterns.
"""

import re


# ------------------------------------------------
# SAFE TEXT EXTRACTION
# ------------------------------------------------

def _extract_text(text):
    """
    Safely extract string content from possible inputs.
    Handles dict-based structures returned by other modules.
    """

    if isinstance(text, dict):

        if "text" in text and isinstance(text["text"], str):
            return text["text"]

        if "content" in text and isinstance(text["content"], str):
            return text["content"]

        return str(text)

    if text is None:
        return ""

    return str(text)


# ------------------------------------------------
# PACKET CLASSIFICATION
# ------------------------------------------------

def classify_packet(text):

    text = _extract_text(text)

    if not text:
        return "Unknown Packet"

    text_lower = text.lower()

    # -----------------------------------------
    # DETECTION RULES
    # -----------------------------------------

    if re.search(r"community\s*care\s*authorization", text_lower):
        return "VA Community Care Packet"

    if re.search(r"consultation\s*(and|&)?\s*treatment\s*request", text_lower):
        return "Consultation Packet"

    if re.search(r"request\s*for\s*services", text_lower):
        return "Request for Services Packet"

    if re.search(r"cms[-\s]?1500", text_lower):
        return "CMS1500 Billing Packet"

    if re.search(r"letter\s*of\s*medical\s*necessity|lomn", text_lower):
        return "LOMN Packet"

    if re.search(r"\bseoc\b|episode\s*of\s*care", text_lower):
        return "SEOC Packet"

    return "Unknown Packet"