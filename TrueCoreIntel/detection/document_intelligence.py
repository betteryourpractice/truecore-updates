import re

from TrueCoreIntel.intake.pdf_ingestion import is_sparse_page_text, normalize_pdf_text


class DocumentIntelligenceAnalyzer:
    STRUCTURED_LABEL_PATTERNS = [
        re.compile(r"\b(?:patient name|veteran name|member name|name of veteran)\b", re.IGNORECASE),
        re.compile(r"\b(?:date of birth|dob|d\.o\.b\.)\b", re.IGNORECASE),
        re.compile(r"\b(?:authorization(?: number)?|auth(?: number)?|ref(?:\.|erral)?(?: number)?|member id)\b", re.IGNORECASE),
        re.compile(r"\b(?:ordering provider|referring provider|provider name|rendering provider|referring va provider)\b", re.IGNORECASE),
        re.compile(r"\b(?:reason for request|requested service|diagnosis|assessment|impression|history of present illness)\b", re.IGNORECASE),
        re.compile(r"\b(?:date of service|service date|submission date|signed by|signature date)\b", re.IGNORECASE),
    ]

    SECTION_HINT_PATTERNS = {
        "history_of_present_illness": re.compile(r"\b(?:history of present illness|hpi)\b", re.IGNORECASE),
        "chief_complaint": re.compile(r"\bchief complaint\b", re.IGNORECASE),
        "assessment": re.compile(r"\bassessment\b", re.IGNORECASE),
        "impression": re.compile(r"\bimpression\b", re.IGNORECASE),
        "plan": re.compile(r"\bplan\b", re.IGNORECASE),
        "diagnosis": re.compile(r"\bdiagnosis\b", re.IGNORECASE),
        "requested_service": re.compile(r"\b(?:requested service|requested procedure|procedure)\b", re.IGNORECASE),
        "authorization": re.compile(r"\b(?:authorization(?: number)?|referral number|member id)\b", re.IGNORECASE),
    }

    HANDWRITING_HINT_PATTERNS = [
        re.compile(r"\b(?:handwritten|illegible|scribbled|initialed by hand)\b", re.IGNORECASE),
    ]

    def analyze(self, packet):
        page_entries = []
        page_metadata_list = list(getattr(packet, "page_metadata", []) or [])

        for idx, page in enumerate(packet.pages or []):
            text = normalize_pdf_text(page)
            doc_type = packet.document_types.get(idx, "unknown")
            confidence = round(float(packet.page_confidence.get(idx, 0.0) or 0.0), 2)
            page_metadata = page_metadata_list[idx] if idx < len(page_metadata_list) else {}
            layout = dict(page_metadata.get("layout", {}) or {})
            structured_hits = self.count_pattern_hits(text, self.STRUCTURED_LABEL_PATTERNS)
            quality = self.assess_scan_quality(
                text,
                source_type=packet.source_type,
                confidence=confidence,
                structured_hits=structured_hits,
                ocr_confidence=float(page_metadata.get("ocr_confidence") or 0.0),
                layout=layout,
            )
            handwriting = self.assess_handwriting_risk(
                text,
                source_type=packet.source_type,
                confidence=confidence,
                quality_score=quality["score"],
                structured_hits=structured_hits,
                page_metadata=page_metadata,
            )
            sections = self.detect_sections(text)

            page_entries.append({
                "page": idx + 1,
                "document_type": doc_type,
                "confidence": confidence,
                "confidence_band": self.band_from_score(confidence, high=0.85, medium=0.6),
                "scan_quality": quality,
                "handwriting_risk": handwriting,
                "section_hints": sections,
                "text_length": len(text),
                "structured_hint_count": structured_hits,
                "ocr_confidence": round(float(page_metadata.get("ocr_confidence") or 0.0), 2),
                "field_zone_count": len(page_metadata.get("field_zones", []) or []),
                "layout": layout,
            })

        spans = self.build_document_spans(page_entries)
        attachments = self.build_attachment_links(page_entries, spans)
        duplicate_summary = self.build_duplicate_summary(packet)
        confidence_model = self.build_document_type_confidence_model(page_entries, spans, duplicate_summary)
        source_ranking = self.build_source_reliability_ranking(confidence_model)
        confidence_map = self.build_confidence_map(page_entries, spans, attachments)

        packet.document_spans = spans
        packet.document_confidence_map = confidence_map
        packet.source_reliability_ranking = source_ranking
        packet.document_intelligence = {
            "section_boundary_detection": {
                "pages_with_sections": [entry["page"] for entry in page_entries if entry["section_hints"]],
                "page_sections": {
                    f"page_{entry['page']}": list(entry["section_hints"])
                    for entry in page_entries
                    if entry["section_hints"]
                },
            },
            "document_type_confidence_model": confidence_model,
            "multi_page_cohesion_analysis": self.build_multi_page_cohesion_analysis(spans),
            "attachment_to_parent_linking": {
                "linked_attachments": attachments,
                "attachment_count": len(attachments),
            },
            "duplicate_page_detection": duplicate_summary,
            "scan_quality_assessment": self.build_scan_quality_summary(page_entries),
            "handwriting_risk_detection": self.build_handwriting_summary(page_entries),
            "layout_zone_detection": self.build_layout_zone_summary(page_entries),
            "mixed_document_separation": self.build_mixed_document_separation(spans),
            "source_reliability_ranking": source_ranking,
            "document_intelligence_confidence_map": confidence_map,
        }

        return packet

    def count_pattern_hits(self, text, patterns):
        normalized = str(text or "")
        return sum(1 for pattern in patterns if pattern.search(normalized))

    def band_from_score(self, score, high=0.78, medium=0.52):
        if score >= high:
            return "high"
        if score >= medium:
            return "medium"
        return "low"

    def assess_scan_quality(self, text, source_type=None, confidence=0.0, structured_hits=0, ocr_confidence=0.0, layout=None):
        normalized = str(text or "")
        layout = dict(layout or {})

        if not normalized:
            return {
                "score": 0.05,
                "band": "poor",
                "signals": ["No readable text was recovered from the page."],
            }

        score = 0.32
        signals = []
        alpha_numeric = sum(1 for ch in normalized if ch.isalnum())
        density = alpha_numeric / max(len(normalized), 1)

        if len(normalized) >= 350:
            score += 0.2
            signals.append("Recovered text length is strong.")
        elif len(normalized) >= 180:
            score += 0.1
            signals.append("Recovered text length is usable.")
        else:
            signals.append("Recovered text is thin.")

        if density >= 0.58:
            score += 0.12
            signals.append("Character density suggests a clean text layer.")
        elif density < 0.38:
            score -= 0.08
            signals.append("Character density suggests OCR or scan noise.")

        if structured_hits >= 3:
            score += 0.12
            signals.append("Structured field labels were detected.")
        elif structured_hits == 0:
            score -= 0.05
            signals.append("Few structured document signals were detected.")

        if is_sparse_page_text(normalized):
            score -= 0.18
            signals.append("Page text is sparse.")

        if confidence >= 0.85:
            score += 0.08
        elif confidence < 0.45:
            score -= 0.06

        if ocr_confidence >= 75:
            score += 0.08
            signals.append("OCR confidence is strong.")
        elif 0 < ocr_confidence < 50:
            score -= 0.08
            signals.append("OCR confidence is weak.")

        if int(layout.get("field_zone_count", 0) or 0) >= 4:
            score += 0.08
            signals.append("Layout zoning found structured field regions.")

        if source_type in {"docx", "txt"}:
            score += 0.06

        score = round(max(0.05, min(score, 0.99)), 2)

        return {
            "score": score,
            "band": "good" if score >= 0.78 else "fair" if score >= 0.52 else "poor",
            "signals": signals[:4],
        }

    def assess_handwriting_risk(self, text, source_type=None, confidence=0.0, quality_score=0.0, structured_hits=0, page_metadata=None):
        normalized = str(text or "")
        page_metadata = dict(page_metadata or {})
        layout = dict(page_metadata.get("layout", {}) or {})

        if source_type in {"docx", "txt"}:
            score = 0.08
        elif source_type in {"png", "jpg", "jpeg", "tif", "tiff", "bmp"}:
            score = 0.28
        else:
            score = 0.18

        signals = []

        if is_sparse_page_text(normalized):
            score += 0.18
            signals.append("Sparse text increases handwriting/OCR risk.")

        if quality_score < 0.5:
            score += 0.16
            signals.append("Low scan quality increases handwriting risk.")

        if confidence < 0.55:
            score += 0.12
            signals.append("Low classification confidence increases handwriting risk.")

        if structured_hits == 0:
            score += 0.08
            signals.append("Missing structured labels suggest weak recognition.")

        if any(pattern.search(normalized) for pattern in self.HANDWRITING_HINT_PATTERNS):
            score += 0.2
            signals.append("Handwriting cues were explicitly detected.")

        if layout.get("handwritten_regions"):
            score += 0.18
            signals.append("Low-confidence handwritten regions were detected in layout analysis.")

        score = round(max(0.05, min(score, 0.95)), 2)

        return {
            "score": score,
            "level": "high" if score >= 0.66 else "medium" if score >= 0.38 else "low",
            "signals": signals[:4],
        }

    def detect_sections(self, text):
        normalized = str(text or "")
        if not normalized:
            return []

        matches = []
        for section_name, pattern in self.SECTION_HINT_PATTERNS.items():
            match = pattern.search(normalized)
            if match:
                matches.append((match.start(), section_name))

        matches.sort()
        return [section_name for _, section_name in matches]

    def build_document_spans(self, page_entries):
        spans = []
        current = None
        entry_by_page = {entry["page"]: entry for entry in page_entries}

        for entry in page_entries:
            if current and current["document_type"] == entry["document_type"] and current["end_page"] == entry["page"] - 1:
                current["end_page"] = entry["page"]
                current["page_indices"].append(entry["page"])
                current["confidences"].append(entry["confidence"])
                continue

            current = {
                "document_type": entry["document_type"],
                "start_page": entry["page"],
                "end_page": entry["page"],
                "page_indices": [entry["page"]],
                "confidences": [entry["confidence"]],
                "bridged_pages": [],
            }
            spans.append(current)

        merged_spans = []
        index = 0
        while index < len(spans):
            current = dict(spans[index])
            current.setdefault("bridged_pages", [])
            lookahead = index + 1

            while lookahead < len(spans):
                candidate = spans[lookahead]
                if candidate["document_type"] != current["document_type"]:
                    break

                gap_pages = list(range(current["end_page"] + 1, candidate["start_page"]))
                gap_entries = [entry_by_page.get(page) for page in gap_pages if entry_by_page.get(page)]

                if not self.should_bridge_document_gap(current, candidate, gap_entries):
                    break

                current["end_page"] = candidate["end_page"]
                current["page_indices"].extend(candidate["page_indices"])
                current["confidences"].extend(candidate["confidences"])
                current["bridged_pages"].extend(gap_pages)
                lookahead += 1

            merged_spans.append(current)
            index = lookahead

        built = []
        for index, span in enumerate(merged_spans, start=1):
            avg_confidence = round(sum(span["confidences"]) / max(len(span["confidences"]), 1), 2)
            bridged_pages = sorted(set(span.get("bridged_pages", [])))
            full_page_indices = sorted(set(span["page_indices"] + bridged_pages))
            built.append({
                "span_id": index,
                "document_type": span["document_type"],
                "start_page": span["start_page"],
                "end_page": span["end_page"],
                "page_count": len(full_page_indices),
                "classified_page_count": len(span["page_indices"]),
                "average_confidence": avg_confidence,
                "cohesion": "strong" if len(span["page_indices"]) > 1 and avg_confidence >= 0.72 else "stable" if avg_confidence >= 0.55 else "fragile",
                "page_indices": full_page_indices,
                "bridged_pages": bridged_pages,
            })

        return built

    def should_bridge_document_gap(self, current_span, candidate_span, gap_entries):
        if not gap_entries:
            return False

        if current_span.get("document_type") != candidate_span.get("document_type"):
            return False

        if len(gap_entries) > 2:
            return False

        if any(entry.get("document_type") != "unknown" for entry in gap_entries):
            return False

        if float(current_span.get("confidences", [0])[-1] or 0.0) < 0.55:
            return False

        if float(candidate_span.get("confidences", [0])[0] or 0.0) < 0.55:
            return False

        for entry in gap_entries:
            if entry.get("text_length", 0) > 420 and entry.get("structured_hint_count", 0) >= 2:
                return False

            if entry.get("scan_quality", {}).get("band") == "good" and entry.get("field_zone_count", 0) >= 4:
                return False

        return True

    def build_attachment_links(self, page_entries, spans):
        span_by_page = {}
        for span in spans:
            for page in span["page_indices"]:
                span_by_page[page] = span

        links = []
        for entry in page_entries:
            if entry["document_type"] != "unknown":
                continue
            if entry["text_length"] > 260:
                continue

            candidate_parent = None
            for neighbor_page in (entry["page"] - 1, entry["page"] + 1):
                neighbor_span = span_by_page.get(neighbor_page)
                if neighbor_span and neighbor_span["document_type"] != "unknown":
                    candidate_parent = neighbor_span
                    break

            if candidate_parent is None:
                continue

            links.append({
                "attachment_page": entry["page"],
                "parent_document_type": candidate_parent["document_type"],
                "parent_span_id": candidate_parent["span_id"],
                "reason": "Short low-confidence page is adjacent to a classified document span.",
            })

        return links

    def build_duplicate_summary(self, packet):
        duplicates = list(getattr(packet, "duplicate_pages", []) or [])
        exact = sum(1 for item in duplicates if item.get("match_type") == "exact")
        fuzzy = sum(1 for item in duplicates if item.get("match_type") == "fuzzy")
        duplicate_pages = sorted({
            page + 1
            for item in duplicates
            for page in item.get("page_indices", [])
        })

        return {
            "duplicate_group_count": len(duplicates),
            "exact_match_groups": exact,
            "fuzzy_match_groups": fuzzy,
            "duplicate_pages": duplicate_pages,
        }

    def build_layout_zone_summary(self, page_entries):
        pages = []
        for entry in page_entries:
            layout = dict(entry.get("layout", {}) or {})
            pages.append({
                "page": entry["page"],
                "field_zone_count": entry.get("field_zone_count", 0),
                "table_region_count": len(layout.get("table_regions", []) or []),
                "signature_region_count": len(layout.get("signature_regions", []) or []),
                "handwritten_region_count": len(layout.get("handwritten_regions", []) or []),
                "ocr_confidence": entry.get("ocr_confidence"),
            })

        return {
            "pages": pages,
            "summary": {
                "pages_with_field_zones": sum(1 for page in pages if page["field_zone_count"] > 0),
                "pages_with_table_regions": sum(1 for page in pages if page["table_region_count"] > 0),
                "pages_with_signature_regions": sum(1 for page in pages if page["signature_region_count"] > 0),
                "pages_with_handwritten_regions": sum(1 for page in pages if page["handwritten_region_count"] > 0),
            },
        }

    def build_document_type_confidence_model(self, page_entries, spans, duplicate_summary):
        grouped = {}
        duplicate_pages = set(duplicate_summary.get("duplicate_pages", []))

        for entry in page_entries:
            doc_type = entry["document_type"]
            model = grouped.setdefault(doc_type, {
                "page_count": 0,
                "confidence_sum": 0.0,
                "high_confidence_pages": 0,
                "medium_confidence_pages": 0,
                "low_confidence_pages": 0,
                "good_quality_pages": 0,
                "fair_quality_pages": 0,
                "poor_quality_pages": 0,
                "high_handwriting_pages": 0,
                "section_hints": set(),
                "page_indices": [],
                "duplicate_pages": 0,
            })

            model["page_count"] += 1
            model["confidence_sum"] += entry["confidence"]
            model[f"{entry['confidence_band']}_confidence_pages"] += 1
            model[f"{entry['scan_quality']['band']}_quality_pages"] += 1
            if entry["handwriting_risk"]["level"] == "high":
                model["high_handwriting_pages"] += 1
            model["section_hints"].update(entry["section_hints"])
            model["page_indices"].append(entry["page"])
            if entry["page"] in duplicate_pages:
                model["duplicate_pages"] += 1

        span_counts = {}
        for span in spans:
            span_counts[span["document_type"]] = span_counts.get(span["document_type"], 0) + 1

        built = {}
        for doc_type, model in grouped.items():
            avg_confidence = round(model["confidence_sum"] / max(model["page_count"], 1), 2)
            reliability_score = avg_confidence
            reliability_score += 0.04 * model["good_quality_pages"]
            reliability_score -= 0.05 * model["poor_quality_pages"]
            reliability_score -= 0.06 * model["high_handwriting_pages"]
            reliability_score -= 0.04 * model["duplicate_pages"]
            reliability_score = round(max(0.05, min(reliability_score, 0.99)), 2)

            built[doc_type] = {
                "page_count": model["page_count"],
                "span_count": span_counts.get(doc_type, 0),
                "average_confidence": avg_confidence,
                "confidence_band": self.band_from_score(avg_confidence, high=0.85, medium=0.6),
                "reliability_score": reliability_score,
                "reliability_band": "high" if reliability_score >= 0.8 else "medium" if reliability_score >= 0.55 else "low",
                "page_indices": list(model["page_indices"]),
                "duplicate_page_count": model["duplicate_pages"],
                "section_hints": sorted(model["section_hints"]),
                "quality_profile": {
                    "good": model["good_quality_pages"],
                    "fair": model["fair_quality_pages"],
                    "poor": model["poor_quality_pages"],
                },
                "high_handwriting_pages": model["high_handwriting_pages"],
            }

        return built

    def build_multi_page_cohesion_analysis(self, spans):
        fragmented_types = sorted({
            span["document_type"]
            for span in spans
            if span["document_type"] != "unknown"
        })
        repeated = {
            doc_type
            for doc_type in fragmented_types
            if sum(1 for span in spans if span["document_type"] == doc_type) > 1
        }

        return {
            "span_count": len(spans),
            "multi_page_spans": [span for span in spans if span["page_count"] > 1],
            "fragmented_document_types": sorted(repeated),
            "overall_cohesion": "fragmented" if repeated else "stable",
        }

    def build_scan_quality_summary(self, page_entries):
        poor_pages = [entry["page"] for entry in page_entries if entry["scan_quality"]["band"] == "poor"]
        good_pages = [entry["page"] for entry in page_entries if entry["scan_quality"]["band"] == "good"]
        average = round(
            sum(entry["scan_quality"]["score"] for entry in page_entries) / max(len(page_entries), 1),
            2,
        ) if page_entries else 0.0

        return {
            "average_score": average,
            "overall_band": "good" if average >= 0.78 else "fair" if average >= 0.52 else "poor",
            "good_pages": good_pages,
            "poor_pages": poor_pages,
        }

    def build_handwriting_summary(self, page_entries):
        high_pages = [entry["page"] for entry in page_entries if entry["handwriting_risk"]["level"] == "high"]
        average = round(
            sum(entry["handwriting_risk"]["score"] for entry in page_entries) / max(len(page_entries), 1),
            2,
        ) if page_entries else 0.0

        return {
            "average_score": average,
            "overall_level": "high" if average >= 0.66 else "medium" if average >= 0.38 else "low",
            "high_risk_pages": high_pages,
        }

    def build_mixed_document_separation(self, spans):
        classified_spans = [span for span in spans if span["document_type"] != "unknown"]
        repeated_types = sorted({
            span["document_type"]
            for span in classified_spans
            if sum(1 for item in classified_spans if item["document_type"] == span["document_type"]) > 1
        })

        return {
            "classified_span_count": len(classified_spans),
            "document_types_in_order": [span["document_type"] for span in classified_spans],
            "repeated_document_types": repeated_types,
            "mixed_bundle_detected": len({span["document_type"] for span in classified_spans}) > 1,
        }

    def build_source_reliability_ranking(self, confidence_model):
        ranked = []

        for doc_type, details in confidence_model.items():
            ranked.append({
                "document_type": doc_type,
                "reliability_score": details["reliability_score"],
                "reliability_band": details["reliability_band"],
                "average_confidence": details["average_confidence"],
                "page_count": details["page_count"],
            })

        ranked.sort(
            key=lambda item: (
                item["reliability_score"],
                item["average_confidence"],
                item["page_count"],
            ),
            reverse=True,
        )

        for position, item in enumerate(ranked, start=1):
            item["rank"] = position

        return ranked

    def build_confidence_map(self, page_entries, spans, attachments):
        span_lookup = {}
        for span in spans:
            for page in span["page_indices"]:
                span_lookup[page] = span["span_id"]

        attachment_lookup = {item["attachment_page"]: item for item in attachments}

        return {
            f"page_{entry['page']}": {
                "document_type": entry["document_type"],
                "confidence": entry["confidence"],
                "confidence_band": entry["confidence_band"],
                "scan_quality_band": entry["scan_quality"]["band"],
                "handwriting_risk_level": entry["handwriting_risk"]["level"],
                "span_id": span_lookup.get(entry["page"]),
                "attachment_parent": attachment_lookup.get(entry["page"], {}).get("parent_document_type"),
                "section_hints": list(entry["section_hints"]),
            }
            for entry in page_entries
        }
