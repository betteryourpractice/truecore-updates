from __future__ import annotations

import re


SEMANTIC_HINTS = {
    "cover_sheet": [
        ("documents included", "authorization number"),
        ("documents included", "va facility"),
        ("documents included", "patient name"),
        ("date of submission", "authorization number"),
    ],
    "consult_request": [
        ("ordering provider", "reason for request"),
        ("ordering provider", "procedure"),
        ("ordering provider", "icd-10"),
        ("reason for request", "icd-10"),
        ("requested service", "diagnosis"),
        ("request for", "ordering provider"),
    ],
    "seoc": [
        ("episode diagnosis", "continuity of care"),
        ("episode diagnosis", "clinical objective"),
    ],
    "lomn": [
        ("medical necessity", "diagnosis"),
        ("medically necessary", "requested service"),
        ("medical necessity", "requested service"),
    ],
    "consent": [
        ("patient signature", "date"),
        ("telehealth", "consent"),
        ("consent", "patient signature"),
    ],
    "approved_referral": [
        ("approved referral", "authorization number"),
        ("medical care", "authorization number"),
        ("referring provider", "va icn"),
        ("authorization number", "va icn"),
        ("va order reason for request", "va icn"),
    ],
    "rfs": [
        ("10-10172", "authorization number"),
        ("request for service", "authorization number"),
    ],
    "clinical_notes": [
        ("assessment", "impression"),
        ("history of present illness", "assessment"),
        ("clinical summary", "assessment"),
        ("assessment", "provider"),
        ("assessment", "icd-10"),
        ("progress note", "assessment"),
    ],
}

OCR_SEMANTIC_CHAR_MAP = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "@": "a",
    "5": "s",
})


def normalize_semantic_text(text: str) -> str:
    cleaned = str(text or "").lower()
    cleaned = cleaned.replace("\r", "\n")
    cleaned = re.sub(r"(?<=\w)-\n(?=\w)", "", cleaned)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n{2,}", "\n", cleaned)
    cleaned = " ".join(cleaned.split())
    return cleaned.translate(OCR_SEMANTIC_CHAR_MAP).strip()


def semantic_hint_matches(text: str) -> dict[str, list[tuple[str, str]]]:
    normalized = normalize_semantic_text(text)
    matches: dict[str, list[tuple[str, str]]] = {}
    for document_type, clue_pairs in SEMANTIC_HINTS.items():
        matched_pairs = []
        for pair in clue_pairs:
            if all(fragment in normalized for fragment in pair):
                matched_pairs.append(pair)
        if matched_pairs:
            matches[document_type] = matched_pairs
    return matches


def page_hints(text: str) -> set[str]:
    return set(semantic_hint_matches(text))
