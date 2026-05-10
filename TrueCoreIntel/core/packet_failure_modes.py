from __future__ import annotations

import re

from TrueCoreIntel.core import packet_archetypes
from TrueCoreIntel.core.document_semantics import page_hints

OCR_NOISE_TOKEN_RE = re.compile(r"(?i)(?=.*[a-z])(?=.*[0-9@])[a-z0-9@]{4,}")

FAILURE_MODE_LABELS = {
    "semantic_title_drift": "Semantic Title Drift",
    "merged_page_content": "Merged Page Content",
    "ocr_admin_degradation": "OCR / Admin Degradation",
    "classification_uncertainty": "Document Family Uncertainty",
}


def _page_hints(page_text: str) -> set[str]:
    return page_hints(page_text)


def _page_hint_map(packet):
    hint_map = {}
    for page_index, page_text in enumerate(list(getattr(packet, "pages", []) or []), start=1):
        hints = _page_hints(page_text)
        if hints:
            hint_map[page_index] = hints
    return hint_map


def _detect_semantic_title_drift(packet, hint_map):
    detected = set(getattr(packet, "detected_documents", set()) or set())
    missing = set(getattr(packet, "missing_documents", []) or [])
    invariant_score = float(getattr(packet, "packet_invariant_coverage_score", 0.0) or 0.0)

    hinted_missing = []
    for page_index, hints in hint_map.items():
        current_doc = str((getattr(packet, "document_types", {}) or {}).get(page_index - 1, "unknown") or "unknown")
        for hint in sorted(hints):
            if hint in detected:
                continue
            if hint not in missing and hint not in {"rfs", "approved_referral", "cover_sheet", "consult_request", "seoc", "lomn", "consent"}:
                continue
            hinted_missing.append((page_index, hint, current_doc))

    distinct_missing = sorted({document for _page, document, _current in hinted_missing})
    if invariant_score < 75:
        return None

    if len(hinted_missing) < 2 and not (len(distinct_missing) >= 1 and len(missing) >= 3):
        return None

    hinted_docs = distinct_missing
    pages = sorted({page for page, _document, _current in hinted_missing})
    return {
        "code": "semantic_title_drift",
        "label": FAILURE_MODE_LABELS["semantic_title_drift"],
        "severity": "medium",
        "summary": "Some expected document families appear to be present by meaning, but their titles or headings are too soft for confident classification.",
        "details": f"Semantic hints suggest unresolved document families on pages {', '.join(str(page) for page in pages[:6])}: {', '.join(hinted_docs[:4])}.",
        "confidence_penalty": 0.05,
        "pages": pages,
        "documents": hinted_docs,
    }


def _detect_merged_page_content(packet, hint_map):
    merged_pages = []
    for page_index, hints in hint_map.items():
        if len(hints) >= 2:
            merged_pages.append((page_index, sorted(hints)))

    if not merged_pages:
        return None

    pages = [page for page, _hints in merged_pages]
    return {
        "code": "merged_page_content",
        "label": FAILURE_MODE_LABELS["merged_page_content"],
        "severity": "medium",
        "summary": "Some pages appear to carry multiple document-family signals at once, which can blur document classification boundaries.",
        "details": f"Multiple document-family hints were detected on pages {', '.join(str(page) for page in pages[:6])}.",
        "confidence_penalty": 0.04,
        "pages": pages,
    }


def _detect_ocr_admin_degradation(packet):
    diagnostics = dict(getattr(packet, "intake_diagnostics", {}) or {})
    pages = list(getattr(packet, "pages", []) or [])
    if not pages:
        return None

    noisy_tokens = 0
    total_tokens = 0
    for page_text in pages[:12]:
        tokens = re.findall(r"[A-Za-z0-9@]+", str(page_text or ""))
        total_tokens += len(tokens)
        noisy_tokens += sum(1 for token in tokens if OCR_NOISE_TOKEN_RE.fullmatch(token))

    noisy_ratio = (noisy_tokens / total_tokens) if total_tokens else 0.0
    used_ocr = bool(
        diagnostics.get("used_ocr_fallback")
        or diagnostics.get("fallback_used")
        or diagnostics.get("ocr_retry_reasons")
        or diagnostics.get("discovery_ocr_pages")
    )

    missing_admin_anchor = not (
        getattr(packet, "fields", {}).get("authorization_number")
        or getattr(packet, "fields", {}).get("va_icn")
        or getattr(packet, "fields", {}).get("referring_provider")
    )

    if noisy_ratio < 0.02 and not (used_ocr and missing_admin_anchor):
        return None

    severity = "high" if noisy_ratio >= 0.04 or missing_admin_anchor else "medium"
    penalty = 0.08 if severity == "high" else 0.05
    return {
        "code": "ocr_admin_degradation",
        "label": FAILURE_MODE_LABELS["ocr_admin_degradation"],
        "severity": severity,
        "summary": "OCR-like distortion appears to be degrading some administrative or document-family anchors.",
        "details": f"OCR-noise ratio observed at {round(noisy_ratio, 3)} with admin-anchor sensitivity.",
        "confidence_penalty": penalty,
    }


def _detect_classification_uncertainty(packet, failure_modes):
    invariant_score = float(getattr(packet, "packet_invariant_coverage_score", 0.0) or 0.0)
    variability = str(getattr(packet, "packet_format_variability", "")).strip().lower()
    missing_documents = list(getattr(packet, "missing_documents", []) or [])
    archetype = str(getattr(packet, "packet_archetype", "")).strip()
    profile = str(getattr(packet, "packet_profile", "")).strip()

    if not failure_modes:
        return None

    if variability != "high" and len(missing_documents) < 2:
        return None

    if invariant_score < 68 and len(missing_documents) < 3:
        return None

    if profile == "full_submission" and archetype in {"formal_full_submission", "authorization_submission_packet"} and len(missing_documents) <= 1:
        return None

    return {
        "code": "classification_uncertainty",
        "label": FAILURE_MODE_LABELS["classification_uncertainty"],
        "severity": "high" if invariant_score < 68 else "medium",
        "summary": "Document-family classification is partially uncertain, so missing-item calls should be confirmed against packet content before acting on them.",
        "details": f"Profile={profile or 'unknown'}, archetype={archetype or 'unknown'}, missing_docs={len(missing_documents)}, variability={variability or 'unknown'}.",
        "confidence_penalty": 0.06 if invariant_score < 68 else 0.04,
    }


def annotate_packet_failure_modes(packet):
    hint_map = _page_hint_map(packet)
    failure_modes = []

    for detector in (
        lambda: _detect_semantic_title_drift(packet, hint_map),
        lambda: _detect_merged_page_content(packet, hint_map),
        lambda: _detect_ocr_admin_degradation(packet),
    ):
        result = detector()
        if result:
            failure_modes.append(result)

    classification_uncertainty = _detect_classification_uncertainty(packet, failure_modes)
    if classification_uncertainty:
        failure_modes.append(classification_uncertainty)

    penalty = round(min(0.18, sum(float(item.get("confidence_penalty", 0.0) or 0.0) for item in failure_modes)), 3)

    packet.packet_failure_modes = failure_modes
    packet.packet_failure_mode_labels = [item.get("label") for item in failure_modes if item.get("label")]
    packet.packet_failure_mode_summaries = [item.get("summary") for item in failure_modes if item.get("summary")]
    packet.packet_classification_caution = bool(failure_modes)
    packet.packet_confidence_penalty = penalty
    packet.links["document_family_hints"] = {
        page: sorted(list(hints))
        for page, hints in hint_map.items()
    }

    if failure_modes and "classification_uncertainty" not in set(getattr(packet, "review_flags", []) or []):
        packet.review_flags.append("classification_uncertainty")

    return packet
