from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from TrueCoreIntel.core.pipeline import TrueCorePipeline
from TrueCoreIntel.data.packet_model import Packet
from TrueCoreIntel.intake.ocr_runtime import available_ocr_providers, available_pdf_tools
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
    page_metadata = list(getattr(packet, "page_metadata", []) or [])
    page_count = len(packet.pages)
    native_text_pages = sum(1 for metadata in page_metadata if str(metadata.get("native_text") or "").strip())
    field_zone_pages = sum(1 for metadata in page_metadata if metadata.get("field_zones"))
    native_text_ratio = (native_text_pages / max(page_count, 1)) if page_count else 0.0
    field_zone_ratio = (field_zone_pages / max(page_count, 1)) if page_count else 0.0
    strong_native_coverage = native_text_ratio >= 0.85 and field_zone_ratio >= 0.5
    sparse_pages = sum(1 for page in packet.pages if is_sparse_page_text(page))
    front_window = packet.pages[: min(page_count, 16)]
    front_sparse_pages = sum(1 for page in front_window if is_sparse_page_text(page))
    sparse_ratio = (sparse_pages / max(page_count, 1)) if page_count else 0.0

    if "authorization_number" not in result.fields and (
        not strong_native_coverage
        or front_sparse_pages >= 4
        or sparse_ratio >= 0.25
    ):
        reasons.append("authorization_number missing after primary extraction")

    if len(packet.pages) >= 8 and len(result.detected_documents) <= 2 and (
        not strong_native_coverage
        or front_sparse_pages >= 4
        or sparse_ratio >= 0.25
    ):
        reasons.append("document detection is sparse for packet size")

    if len(packet.pages) >= 3 and (
        sparse_pages >= max(2, int(len(packet.pages) * 0.35)) and native_text_ratio < 0.7
        or front_sparse_pages >= 4 and sparse_ratio >= 0.2
    ):
        reasons.append("packet contains many sparse text pages")

    return reasons


def build_intake_diagnostics(packet: Packet, fallback_applied: bool = False) -> dict:
    page_metadata = list(getattr(packet, "page_metadata", []) or [])
    providers = [
        metadata.get("ocr_provider")
        for metadata in page_metadata
        if isinstance(metadata, dict) and metadata.get("ocr_provider")
    ]
    ocr_confidences = [
        float(metadata.get("ocr_confidence") or 0.0)
        for metadata in page_metadata
        if isinstance(metadata, dict)
        and metadata.get("ocr_provider")
        and metadata.get("ocr_confidence") is not None
    ]
    pages_with_native_text = sum(1 for metadata in page_metadata if str(metadata.get("native_text") or "").strip())
    pages_with_ocr_text = sum(1 for metadata in page_metadata if str(metadata.get("ocr_text") or "").strip())
    pages_with_ocr_field_zones = sum(
        1
        for metadata in page_metadata
        if any(str(zone.get("zone_name") or "").lower() != "native_text" for zone in (metadata.get("field_zones") or []))
    )
    pages_with_native_field_zones = sum(
        1
        for metadata in page_metadata
        if any(str(zone.get("zone_name") or "").lower() == "native_text" for zone in (metadata.get("field_zones") or []))
    )
    pages_with_split_segments = sum(1 for metadata in page_metadata if len(metadata.get("ocr_segments", []) or []) > 1)
    ocr_attempted = bool(pages_with_ocr_text or pages_with_ocr_field_zones or providers)

    extraction_mode = "native_text"
    if pages_with_ocr_text:
        extraction_mode = "ocr_text"
    elif pages_with_ocr_field_zones:
        extraction_mode = "layout_ocr"

    if fallback_applied and ocr_attempted:
        extraction_mode = "fallback_ocr"

    return {
        "page_count": len(getattr(packet, "pages", []) or []),
        "pages_with_native_text": pages_with_native_text,
        "pages_with_ocr": pages_with_ocr_text,
        "pages_with_ocr_field_zones": pages_with_ocr_field_zones,
        "pages_with_native_field_zones": pages_with_native_field_zones,
        "pages_with_field_zones": sum(1 for metadata in page_metadata if metadata.get("field_zones")),
        "pages_with_split_segments": pages_with_split_segments,
        "average_ocr_confidence": round(sum(ocr_confidences) / max(len(ocr_confidences), 1), 2) if ocr_confidences else None,
        "ocr_attempted": ocr_attempted,
        "ocr_provider": providers[0] if providers else None,
        "ocr_provider_chain": providers,
        "available_ocr_providers": available_ocr_providers(),
        "available_pdf_tools": available_pdf_tools(),
        "extraction_mode": extraction_mode,
        "fallback_applied": fallback_applied,
    }


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
            "ocr_provider": getattr(packet, "ocr_provider", None),
            "intake_diagnostics": dict(getattr(packet, "intake_diagnostics", {}) or {}),
            "benchmark_scores": dict(getattr(packet, "benchmark_scores", {}) or {}),
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
        page_metadata: Iterable[dict] | None = None,
    ) -> Packet:
        packet = Packet()
        packet.pages = list(pages)
        packet.source_type = source_type
        if files is not None:
            packet.files = list(files)
        if page_sources is not None:
            packet.page_sources = list(page_sources)
        if page_metadata is not None:
            packet.page_metadata = list(page_metadata)
            packet.intake_diagnostics = build_intake_diagnostics(packet)
            packet.ocr_provider = packet.intake_diagnostics.get("ocr_provider")
        return self.process_packet(packet)

    def process_path(self, path: str | Path, log_fn=None) -> dict:
        source_path = Path(path).expanduser().resolve()

        if log_fn:
            log_fn("[DEBUG] Starting run()")

        packet = Packet()
        packet.source_type = source_path.suffix.lower().lstrip(".") or None
        packet.files = [str(source_path)]
        packet.pages, packet.page_metadata = extract_document_pages(source_path, log_fn=log_fn, return_metadata=True)
        packet.page_sources = [str(source_path)] * len(packet.pages)
        packet.intake_diagnostics = build_intake_diagnostics(packet)
        packet.ocr_provider = packet.intake_diagnostics.get("ocr_provider")

        if log_fn:
            log_fn(f"[DEBUG] Packet pages loaded: {len(packet.pages)}")

        result = self.process_packet(packet)
        retry_reasons = should_retry_with_ocr(packet, result)
        used_ocr_fallback = False

        if retry_reasons:
            if log_fn:
                log_fn(f"[DEBUG] Retrying with OCR fallback: {', '.join(retry_reasons)}")
            fallback_pages, fallback_metadata = extract_document_pages_with_fallback(
                source_path,
                log_fn=log_fn,
                return_metadata=True,
                base_pages=packet.pages,
                base_metadata=packet.page_metadata,
            )

            if fallback_pages != packet.pages:
                used_ocr_fallback = True
                packet = Packet()
                packet.source_type = source_path.suffix.lower().lstrip(".") or None
                packet.files = [str(source_path)]
                packet.pages = fallback_pages
                packet.page_metadata = list(fallback_metadata or [])
                packet.page_sources = [str(source_path)] * len(packet.pages)
                packet.intake_diagnostics = build_intake_diagnostics(packet, fallback_applied=True)
                packet.ocr_provider = packet.intake_diagnostics.get("ocr_provider")
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
    page_metadata: Iterable[dict] | None = None,
    pipeline: TrueCorePipeline | None = None,
) -> Packet:
    return TrueCoreIntelEngine(pipeline=pipeline).process_pages(
        pages,
        source_type=source_type,
        files=files,
        page_sources=page_sources,
        page_metadata=page_metadata,
    )


def process_path(path: str | Path, *, log_fn=None, pipeline: TrueCorePipeline | None = None) -> dict:
    return TrueCoreIntelEngine(pipeline=pipeline).process_path(path, log_fn=log_fn)
