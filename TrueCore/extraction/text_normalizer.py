"""
TrueCore Text Normalizer

Prepares parsed document text for downstream extraction by
normalizing spacing, fixing OCR line breaks, and merging
common split headers.
"""

import re


def normalize_text(text):

    if not text:
        return ""

    # -------------------------------------------------
    # NORMALIZE LINE ENDINGS
    # -------------------------------------------------

    text = text.replace("\r", "\n")

    lines = text.split("\n")

    merged_lines = []

    i = 0

    # -------------------------------------------------
    # HEADERS THAT MAY SPLIT ACROSS LINES
    # -------------------------------------------------

    merge_headers = [

        "authorization number",
        "patient name",
        "veteran name",
        "date of birth",
        "va claim number",
        "referral number",

        # Provider fields
        "ordering physician",
        "ordering doctor",
        "ordering provider",
        "referring physician",
        "referring doctor",
        "referring provider",
        "primary care provider",
        "consult requested by",
        "ordered by",
        "referred by"
    ]

    # -------------------------------------------------
    # MERGE SPLIT HEADERS
    # -------------------------------------------------

    while i < len(lines):

        line = lines[i].strip()

        if i + 1 < len(lines):

            next_line = lines[i + 1].strip()

            pair = (line + " " + next_line).lower()

            if pair in merge_headers:

                merged_lines.append(line + " " + next_line)

                i += 2
                continue

        merged_lines.append(line)

        i += 1

    text = "\n".join(merged_lines)

    # -------------------------------------------------
    # WHITESPACE CLEANUP
    # -------------------------------------------------

    # Collapse multiple spaces/tabs
    text = re.sub(r"[ \t]+", " ", text)

    # Remove excessive line breaks
    text = re.sub(r"\n+", "\n", text)

    return text.strip()