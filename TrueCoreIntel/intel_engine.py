from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from TrueCoreIntel.core.pipeline import TrueCorePipeline
from TrueCoreIntel.data.packet_model import Packet
from TrueCoreIntel.intake.pdf_ingestion import (
    extract_document_pages,
    extract_document_pages_with_fallback,
    is_sparse_page_text,
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_packet_label(packet: Packet) -> str:
    name = str(packet.fields.get("name") or "unknown_patient").strip()
    name = name.replace(",", "").replace("/", "-")
    identifier = str(
        packet.fields.get("authorization_number")
        or packet.fields.get("va_icn")
        or packet.fields.get("claim_number")
        or "no_identifier"
    ).strip()
    identifier = identifier.replace("/", "-")
    return f"{name}_{identifier}"


def should_retry_with_ocr(packet: Packet, result: Packet) -> list[str]:
    reasons: list[str] = []

    if "authorization_number" not in result.fields:
        reasons.append("authorization_number missing after primary extraction")

    if len(packet.pages) >= 8 and len(result.detected_documents) <= 2:
        reasons.append("document detection is sparse for packet size")

    sparse_pages = sum(1 for page in packet.pages if is_sparse_page_text(page))
    if len(packet.pages) >= 3 and sparse_pages >= max(2, int(len(packet.pages) * 0.35)):
        reasons.append("packet contains many sparse text pages")

    return reasons


def build_structured_result(
    packet: Packet,
    source_path: str | Path,
    used_ocr_fallback: bool,
    ocr_retry_reasons: Iterable[str],
) -> dict:
    source_path = Path(source_path).resolve()
    stat = source_path.stat()
    packet_label = packet.output.get("packet_label") or build_packet_label(packet)

    return {
        "status": "processed",
        "processed_at": utc_now_iso(),
        "source_pdf": {
            "path": str(source_path),
            "name": source_path.name,
            "type": source_path.suffix.lower().lstrip("."),
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        },
        "automation": {
            "used_ocr_fallback": used_ocr_fallback,
            "ocr_retry_reasons": list(ocr_retry_reasons),
        },
        "core": {
            "packet_score": packet.packet_score,
            "packet_confidence": packet.packet_confidence,
            "packet_strength": packet.packet_strength,
            "approval_probability": packet.approval_probability,
            "needs_review": packet.needs_review,
            "review_priority": packet.review_priority,
            "submission_readiness": packet.output.get("submission_readiness"),
        },
        "packet_label": packet_label,
        "packet_output": packet.output,
        "metrics": packet.metrics,
    }


class TrueCoreIntelEngine:
    def __init__(self, pipeline: TrueCorePipeline | None = None):
        self.pipeline = pipeline or TrueCorePipeline()

    def process_packet(self, packet: Packet) -> Packet:
        return self.pipeline.run(packet)

    def process_pages(
        self,
        pages: Iterable[str],
        *,
        source_type: str | None = None,
        files: Iterable[str] | None = None,
        page_sources: Iterable[str] | None = None,
    ) -> Packet:
        packet = Packet()
        packet.pages = list(pages)
        packet.source_type = source_type
        if files is not None:
            packet.files = list(files)
        if page_sources is not None:
            packet.page_sources = list(page_sources)
        return self.process_packet(packet)

    def process_path(self, path: str | Path, log_fn=None) -> dict:
        source_path = Path(path).expanduser().resolve()

        if log_fn:
            log_fn("[DEBUG] Starting run()")

        packet = Packet()
        packet.source_type = source_path.suffix.lower().lstrip(".") or None
        packet.files = [str(source_path)]
        packet.pages = extract_document_pages(source_path, log_fn=log_fn)
        packet.page_sources = [str(source_path)] * len(packet.pages)

        if log_fn:
            log_fn(f"[DEBUG] Packet pages loaded: {len(packet.pages)}")

        result = self.process_packet(packet)
        retry_reasons = should_retry_with_ocr(packet, result)
        used_ocr_fallback = False

        if retry_reasons:
            if log_fn:
                log_fn(f"[DEBUG] Retrying with OCR fallback: {', '.join(retry_reasons)}")
            fallback_pages = extract_document_pages_with_fallback(source_path, log_fn=log_fn)

            if fallback_pages != packet.pages:
                used_ocr_fallback = True
                packet = Packet()
                packet.source_type = source_path.suffix.lower().lstrip(".") or None
                packet.files = [str(source_path)]
                packet.pages = fallback_pages
                packet.page_sources = [str(source_path)] * len(packet.pages)
                if log_fn:
                    log_fn(f"[DEBUG] Packet pages reloaded with OCR fallback: {len(packet.pages)}")
                result = self.process_packet(packet)

        return {
            "packet": result,
            "structured_result": build_structured_result(
                packet=result,
                source_path=source_path,
                used_ocr_fallback=used_ocr_fallback,
                ocr_retry_reasons=retry_reasons,
            ),
        }


def process_packet(packet: Packet, pipeline: TrueCorePipeline | None = None) -> Packet:
    return TrueCoreIntelEngine(pipeline=pipeline).process_packet(packet)


def process_pages(
    pages: Iterable[str],
    *,
    source_type: str | None = None,
    files: Iterable[str] | None = None,
    page_sources: Iterable[str] | None = None,
    pipeline: TrueCorePipeline | None = None,
) -> Packet:
    return TrueCoreIntelEngine(pipeline=pipeline).process_pages(
        pages,
        source_type=source_type,
        files=files,
        page_sources=page_sources,
    )


def process_path(path: str | Path, *, log_fn=None, pipeline: TrueCorePipeline | None = None) -> dict:
    return TrueCoreIntelEngine(pipeline=pipeline).process_path(path, log_fn=log_fn)
