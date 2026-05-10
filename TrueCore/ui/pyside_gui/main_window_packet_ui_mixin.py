import html
import re
from datetime import datetime

from TrueCore.core.case_memory import (
    build_run_snapshot,
    get_recent_packet_runs,
    parse_intel_summary,
    parse_issues,
)


class MainWindowPacketUiMixin:

    def format_operator_display_value(self, label, value):

        formatter = getattr(self, "format_packet_display_value", None)
        if callable(formatter):
            try:
                return formatter(label, value)
            except TypeError:
                pass
        return self.format_detail_value(value)

    def extract_operator_issue_title(self, issue):

        if isinstance(issue, dict):
            return self.format_detail_value(issue.get("title"))
        return self.format_detail_value(issue)

    def build_operator_quick_read_card(self, intel_display, issue_groups, fix_items, review_rationale, margin_top=0):

        intel_display = dict(intel_display or {})
        issue_groups = list(issue_groups or [])
        fix_items = list(fix_items or [])
        review_rationale = list(review_rationale or [])

        readiness = self.format_operator_display_value("Submission Readiness", intel_display.get("submission_readiness"))
        next_action = self.format_operator_display_value("Next Action", intel_display.get("next_action"))
        packet_strength = self.format_operator_display_value("Packet Strength", intel_display.get("packet_strength"))
        confidence = self.format_operator_display_value("Packet Confidence", intel_display.get("packet_confidence"))
        workflow_queue = self.format_operator_display_value("Workflow Queue", intel_display.get("workflow_queue"))
        review_priority = self.format_operator_display_value("Review Priority", intel_display.get("review_priority"))

        missing_items = list(intel_display.get("missing_items") or [])
        main_blocker = None
        if missing_items:
            main_blocker = self.format_detail_value(missing_items[0])
        elif issue_groups:
            main_blocker = self.extract_operator_issue_title(issue_groups[0])

        first_fix = self.format_detail_value(fix_items[0]) if fix_items else None
        first_rationale = self.format_detail_value(review_rationale[0]) if review_rationale else None

        overall_parts = []
        if readiness not in (None, "", "Missing"):
            overall_parts.append(f"This packet is {readiness.lower()}.")
        elif packet_strength not in (None, "", "Missing"):
            overall_parts.append(f"This is currently a {packet_strength.lower()} packet.")
        if next_action not in (None, "", "Missing"):
            overall_parts.append(f"The next move is {next_action.lower()}.")
        overall_summary = " ".join(overall_parts).strip() or "Review the packet summary and issues below."

        review_posture_parts = []
        if confidence not in (None, "", "Missing"):
            review_posture_parts.append(f"Confidence {confidence}")
        if workflow_queue not in (None, "", "Missing"):
            review_posture_parts.append(f"Queue {workflow_queue}")
        if review_priority not in (None, "", "Missing"):
            review_posture_parts.append(f"Priority {review_priority}")
        review_posture = " | ".join(review_posture_parts)

        quick_rows = [("Overall", overall_summary)]
        if main_blocker not in (None, "", "Missing"):
            quick_rows.append(("Main blocker", main_blocker))
        if first_fix not in (None, "", "Missing"):
            quick_rows.append(("Do first", first_fix))
        if review_posture:
            quick_rows.append(("Review posture", review_posture))
        if first_rationale not in (None, "", "Missing"):
            quick_rows.append(("Why this was flagged", first_rationale))

        return self.build_detail_card(
            "Operator Quick Read",
            self.build_detail_table(quick_rows, value_color="#DCE6F2", show_missing=False),
            accent_color="#2DCE89",
            margin_top=margin_top,
        )

    def normalize_comparison_value(self, value):

        normalized = self.format_detail_value(value)
        if normalized in (None, "", "Missing"):
            return ""
        return " ".join(str(normalized).strip().lower().split())

    def normalize_issue_family_text(self, value):

        normalized = self.normalize_comparison_value(value)
        if not normalized:
            return ""

        normalized = re.sub(r"\s*\([^)]*\)", "", normalized)
        normalized = re.sub(r"\s*;\s*seen on pages?.*$", "", normalized)
        normalized = re.sub(r"\s*seen on pages?.*$", "", normalized)
        normalized = " ".join(normalized.strip().split())
        return normalized

    def normalize_comparison_items(self, items):

        normalized_items = []

        for item in list(items or []):
            candidate = item
            if isinstance(item, dict):
                candidate = item.get("title") or item.get("label") or item.get("value")

            normalized = self.normalize_issue_family_text(candidate)
            if normalized:
                normalized_items.append(normalized)

        return sorted(set(normalized_items))

    def build_current_review_signature(self, file_path, result):

        intel_display = dict((result or {}).get("intel", {}).get("display", {}) or {})
        current_issues = intel_display.get("issue_details") or (result or {}).get("issues", [])

        return (
            int((result or {}).get("score", 0) or 0),
            self.normalize_comparison_value(intel_display.get("denial_risk")),
            self.normalize_comparison_value(intel_display.get("workflow_queue")),
            tuple(self.normalize_comparison_items(intel_display.get("missing_items", []))),
            tuple(self.normalize_comparison_items(current_issues)),
            build_run_snapshot(file_path, result).get("case_key"),
        )

    def build_previous_review_signature(self, row):

        summary = parse_intel_summary(row)
        return (
            int((row or {}).get("score", 0) or 0),
            self.normalize_comparison_value((row or {}).get("denial_risk")),
            self.normalize_comparison_value((row or {}).get("workflow_queue")),
            tuple(self.normalize_comparison_items(summary.get("missing_items", []))),
            tuple(self.normalize_comparison_items(parse_issues(row))),
            str((row or {}).get("case_key") or ""),
        )

    def find_previous_packet_run(self, file_path, result, limit=250):

        current_snapshot = build_run_snapshot(file_path, result)
        case_key = str(current_snapshot.get("case_key") or "")
        file_reference = str(current_snapshot.get("file_name") or "")
        current_signature = self.build_current_review_signature(file_path, result)

        for row in get_recent_packet_runs(limit=limit):
            row_case_key = str((row or {}).get("case_key") or "")
            row_file_reference = str((row or {}).get("file_name") or "")

            if case_key and case_key != "unknown_case":
                if row_case_key != case_key:
                    continue
            elif file_reference:
                if row_file_reference != file_reference:
                    continue
            else:
                continue

            if self.build_previous_review_signature(row) == current_signature:
                continue

            return row

        return None

    def format_repeat_review_timestamp(self, value):

        raw_value = str(value or "").strip()
        if not raw_value:
            return "Unknown"

        try:
            parsed = datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
            return parsed.strftime("%b %d, %Y %I:%M %p UTC")
        except Exception:
            return raw_value

    def format_shift_value(self, previous_value, current_value, label=None, empty_label="Unknown"):

        previous_display = self.format_operator_display_value(label, previous_value)
        current_display = self.format_operator_display_value(label, current_value)

        if previous_display in ("", "Missing"):
            previous_display = empty_label
        if current_display in ("", "Missing"):
            current_display = empty_label

        if previous_display == current_display:
            return f"No change ({current_display})"

        return f"{previous_display} -> {current_display}"

    def build_repeat_review_delta_block(self, title, items, color, empty_text):

        if not items:
            body = f"<div style=\"color:#9CA3AF;\">{html.escape(empty_text)}</div>"
        else:
            entries = "".join(
                f"<li style=\"margin-bottom:6px;\">{html.escape(str(item))}</li>"
                for item in items
            )
            body = f"<ul style=\"margin:8px 0 0 18px; padding:0; color:{color};\">{entries}</ul>"

        return (
            "<div style=\"margin-top:14px;\">"
            f"<div style=\"color:#FFFFFF; font-weight:600; margin-bottom:4px;\">{html.escape(title)}</div>"
            f"{body}"
            "</div>"
        )

    def build_repeat_review_comparison_card(self, file_path, result, margin_top=12):

        previous_run = self.find_previous_packet_run(file_path, result)
        if not previous_run:
            return ""

        current_intel_display = dict((result or {}).get("intel", {}).get("display", {}) or {})
        previous_summary = parse_intel_summary(previous_run)
        previous_issues = self.normalize_comparison_items(parse_issues(previous_run))
        current_issues = self.normalize_comparison_items(
            current_intel_display.get("issue_details") or (result or {}).get("issues", [])
        )
        previous_missing = self.normalize_comparison_items(previous_summary.get("missing_items", []))
        current_missing = self.normalize_comparison_items(current_intel_display.get("missing_items", []))

        previous_score = int((previous_run or {}).get("score", 0) or 0)
        current_score = int((result or {}).get("score", 0) or 0)
        score_delta = current_score - previous_score

        comparison_rows = [
            ("Previous review", self.format_repeat_review_timestamp((previous_run or {}).get("analyzed_at"))),
            ("Score change", f"{previous_score} -> {current_score} ({score_delta:+d})"),
            (
                "Risk shift",
                self.format_shift_value(
                    (previous_run or {}).get("denial_risk"),
                    current_intel_display.get("denial_risk"),
                    label="Denial Risk",
                ),
            ),
            (
                "Queue shift",
                self.format_shift_value(
                    (previous_run or {}).get("workflow_queue"),
                    current_intel_display.get("workflow_queue"),
                    label="Workflow Queue",
                ),
            ),
        ]

        resolved_items = []
        new_items = []

        resolved_missing = sorted(set(previous_missing) - set(current_missing))
        new_missing = sorted(set(current_missing) - set(previous_missing))
        resolved_issues = sorted(set(previous_issues) - set(current_issues))
        new_issues = sorted(set(current_issues) - set(previous_issues))

        resolved_items.extend(f"Missing item resolved: {self.format_field(item)}" for item in resolved_missing)
        resolved_items.extend(f"Issue resolved: {self.format_field(item)}" for item in resolved_issues)
        new_items.extend(f"New missing item: {self.format_field(item)}" for item in new_missing)
        new_items.extend(f"New issue: {self.format_field(item)}" for item in new_issues)

        if not resolved_items and not new_items and score_delta == 0:
            new_items.append("This packet matches the previous reviewed state closely.")

        card_body = self.build_detail_table(
            comparison_rows,
            value_color="#DCE6F2",
            show_missing=False,
        )
        card_body += self.build_repeat_review_delta_block(
            "Resolved since last review",
            resolved_items,
            "#6FCF97",
            "No previously flagged items were resolved in this comparison.",
        )
        card_body += self.build_repeat_review_delta_block(
            "New since last review",
            new_items,
            "#F2C94C",
            "No new flags appeared compared with the last review.",
        )

        return self.build_detail_card(
            "What Changed Since Last Review",
            card_body,
            accent_color="#9B51E0",
            margin_top=margin_top,
        )

    def format_source_role_label(self, role):

        mapping = {
            "va_clinic": "VA",
            "community_provider": "community provider",
            "shared": "shared",
            "patient": "patient",
        }

        normalized = str(role or "").strip().lower()
        if not normalized:
            return ""

        return mapping.get(normalized, self.format_field(normalized))

    def format_concept_source_phrase(self, item):

        concept_key = str((item or {}).get("concept") or "").strip().lower()
        document_type = str((item or {}).get("document_type") or "").strip()
        primary_section_role = str((item or {}).get("primary_section_role") or "").strip().lower()
        role_label = self.format_source_role_label((item or {}).get("source_role"))
        page_number = (item or {}).get("page_number")
        page_text = f" on page {page_number}" if page_number not in (None, "", [], {}) else ""

        if document_type and document_type.lower() != "unknown":
            return f"{self.format_document_type_label(document_type)}{page_text}"

        if concept_key == "request_intent":
            lead = f"{role_label} request content".strip() if role_label else "request content"
            return f"{lead}{page_text}"

        if concept_key == "diagnostic_basis":
            lead = f"{role_label} diagnostic content".strip() if role_label else "diagnostic content"
            return f"{lead}{page_text}"

        if concept_key == "clinical_justification":
            if primary_section_role == "imaging_support":
                lead = f"{role_label} imaging support".strip() if role_label else "imaging support"
            elif primary_section_role == "justification":
                lead = f"{role_label} clinical justification".strip() if role_label else "clinical justification"
            else:
                lead = f"{role_label} clinical support".strip() if role_label else "clinical support"
            return f"{lead}{page_text}"

        if concept_key == "routing_admin":
            lead = f"{role_label} facility and admin content".strip() if role_label else "facility and admin content"
            return f"{lead}{page_text}"

        if primary_section_role:
            return f"{self.format_field(primary_section_role)}{page_text}"

        if role_label:
            return f"{role_label} packet content{page_text}"

        return f"page {page_number}" if page_text else ""

    def format_concept_evidence_item(self, item):

        concept_label = self.format_field((item or {}).get("concept_label") or (item or {}).get("concept"))
        source_phrase = self.format_concept_source_phrase(item)

        if not concept_label:
            return ""

        if source_phrase:
            return f"{concept_label}: Supported by {source_phrase}"

        return concept_label

    def polish_review_rationale_item(self, item):

        text = self.format_detail_value(item)

        concept_patterns = [
            (r"^Request intent appears in (.+)\.$", "Request intent is supported by {source}."),
            (r"^Diagnostic basis appears in (.+)\.$", "Diagnostic basis is supported by {source}."),
            (r"^Clinical justification appears in (.+)\.$", "Clinical justification is supported by {source}."),
            (r"^Routing and admin details appear in (.+)\.$", "Routing and admin details are supported by {source}."),
        ]

        for pattern, template in concept_patterns:
            match = re.match(pattern, text, flags=re.IGNORECASE)
            if not match:
                continue
            source = str(match.group(1) or "").strip()
            source = re.sub(r"\brequest intent section\b", "request content", source, flags=re.IGNORECASE)
            source = re.sub(r"\bdiagnostic basis section\b", "diagnostic content", source, flags=re.IGNORECASE)
            source = re.sub(r"\bclinical justification section\b", "clinical support", source, flags=re.IGNORECASE)
            source = re.sub(r"\bidentity admin section\b", "admin content", source, flags=re.IGNORECASE)
            source = re.sub(r"\brouting followup section\b", "routing follow-up content", source, flags=re.IGNORECASE)
            return template.format(source=source)

        text = re.sub(r"^Inferred packet profile:\s*", "Packet profile: ", text, flags=re.IGNORECASE)
        text = re.sub(r"\bExpected document family:\s*", "Expected documents: ", text, flags=re.IGNORECASE)
        return text

    def classify_review_rationale_item(self, item):

        text = self.polish_review_rationale_item(item)
        normalized = str(text or "").strip().lower()

        if not normalized:
            return ""

        if normalized.startswith("training or template scaffolding detected"):
            return "template"
        if "packet may contain mixed patient or case identifiers" in normalized or "multiple identity signals suggest" in normalized:
            return "integrity"
        if "mixed clinical history still needs reviewer alignment" in normalized:
            return "clinical_alignment"
        if "diagnosis and icd" in normalized and "aligned" in normalized:
            return "clinical_alignment"
        if normalized.startswith("packet profile:"):
            return "packet_profile"
        if "critical required fields are missing" in normalized or normalized.startswith("missing required fields"):
            return "missing_fields"
        if "required supporting documents are missing" in normalized or normalized.startswith("missing required documents"):
            return "missing_documents"
        if normalized.startswith("request intent "):
            return "concept_request"
        if normalized.startswith("diagnostic basis "):
            return "concept_diagnostic"
        if normalized.startswith("clinical justification "):
            return "concept_justification"
        if normalized.startswith("routing and admin details "):
            return "concept_routing"
        if "packet has " in normalized or "overall packet strength is weak" in normalized or "packet is weak due" in normalized:
            return "overall_support"
        if "field conflicts still require reviewer confirmation" in normalized or "conflicts were found" in normalized:
            return "conflicts"

        return f"other:{normalized}"

    def polish_review_rationale(self, items, max_items=5):

        if not items:
            return []

        ordered_categories = [
            "template",
            "integrity",
            "clinical_alignment",
            "missing_fields",
            "missing_documents",
            "overall_support",
            "packet_profile",
            "concept_diagnostic",
            "concept_justification",
            "concept_request",
            "concept_routing",
            "conflicts",
        ]

        buckets = {}
        category_order = []

        for raw_item in items:
            polished = self.polish_review_rationale_item(raw_item)
            if not polished or polished == "Missing":
                continue

            category = self.classify_review_rationale_item(polished)
            if category in buckets:
                continue

            buckets[category] = polished
            category_order.append(category)

        sorted_categories = [
            category
            for category in ordered_categories
            if category in buckets
        ]
        sorted_categories.extend(
            category for category in category_order
            if category not in sorted_categories
        )

        return [buckets[category] for category in sorted_categories[:max_items]]

    def format_evidence_rating(self, score):

        if score in (None, "", [], {}):
            return score

        try:
            numeric_score = float(score)
        except (TypeError, ValueError):
            return score

        if numeric_score >= 95:
            band = "Very strong"
        elif numeric_score >= 85:
            band = "Strong"
        elif numeric_score >= 70:
            band = "Moderate"
        else:
            band = "Limited"

        return f"{band} ({int(round(numeric_score))})"

    def get_issue_display_palette(self, intel_display):

        missing_items = list((intel_display or {}).get("missing_items", []) or [])
        denial_risk = str((intel_display or {}).get("denial_risk") or "").strip().lower()
        readiness = str((intel_display or {}).get("submission_readiness") or "").strip().lower()

        if missing_items or denial_risk in {"high", "critical"} or readiness == "not_ready":
            return {
                "color": "#EB5757",
                "accent": "#EB5757",
            }

        return {
            "color": "#F2C94C",
            "accent": "#F2994A",
        }

    def format_scan_mode(self, mode):

        normalized = str(mode or "").strip().lower()

        mapping = {
            "native_text": "Native Text",
            "native_text_structured": "Native Text + Field Zones",
            "ocr_text": "OCR Text",
            "layout_ocr": "Layout OCR",
            "fallback_ocr": "OCR Fallback",
        }

        if not normalized:
            return "Unknown"

        return mapping.get(normalized, self.format_field(normalized))

    def build_metric_tiles(self, tiles):

        rendered_tiles = []

        for tile in tiles:
            if not isinstance(tile, dict):
                continue

            title = str(tile.get("title") or "").strip()
            value = self.format_detail_value(tile.get("value"))
            accent = str(tile.get("accent") or "#57B6FF")
            subtitle = str(tile.get("subtitle") or "").strip()

            if not title:
                continue

            subtitle_html = (
                f"<div style=\"color:#9CA3AF; font-size:11px; margin-top:4px;\">{html.escape(subtitle)}</div>"
                if subtitle else ""
            )

            rendered_tiles.append(
                "<div style=\"display:inline-block; width:31%; min-width:180px; vertical-align:top; "
                "margin:0 1.5% 12px 0; padding:12px 14px; background-color:#10161E; "
                f"border:1px solid #253243; border-top:3px solid {accent}; border-radius:8px; box-sizing:border-box;\">"
                f"<div style=\"color:#FFFFFF; font-size:12px; font-weight:600;\">{html.escape(title)}</div>"
                f"<div style=\"color:{accent}; font-size:24px; font-weight:700; margin-top:6px;\">{html.escape(value)}</div>"
                f"{subtitle_html}</div>"
            )

        if not rendered_tiles:
            return "<div style=\"color:#9CA3AF;\">No summary metrics</div>"

        return "<div style=\"margin-right:-1.5%;\">" + "".join(rendered_tiles) + "</div>"

    def build_detail_card(self, title, body_html, accent_color="#2F80ED", margin_top=12):

        return (
            f"<div style=\"margin-top:{margin_top}px; padding:12px 14px; "
            f"background-color:#10161E; border:1px solid #253243; "
            f"border-left:3px solid {accent_color}; border-radius:8px; "
            f"box-sizing:border-box; overflow-wrap:anywhere; word-break:break-word;\">"
            f"<div style=\"color:#FFFFFF; font-weight:700; margin-bottom:8px;\">"
            f"{html.escape(title)}</div>{body_html}</div>"
        )

    def build_detail_table(self, rows, value_color="#DCE6F2", show_missing=True):

        rendered_rows = []

        for label, value in rows:
            if not show_missing and value in (None, "", [], {}):
                continue

            display_value = self.format_detail_value(value)
            row_color = "#EB5757" if display_value == "Missing" else value_color

            rendered_rows.append(
                "<tr>"
                f"<td valign=\"top\" style=\"color:#FFFFFF; font-weight:600; padding:3px 12px 3px 0; width:38%; "
                f"white-space:normal; overflow-wrap:anywhere; word-break:break-word;\">"
                f"{html.escape(str(label))}</td>"
                f"<td valign=\"top\" style=\"color:{row_color}; padding:3px 0; "
                f"white-space:normal; overflow-wrap:anywhere; word-break:break-word;\">"
                f"{html.escape(display_value)}</td>"
                "</tr>"
            )

        if not rendered_rows:
            return "<div style=\"color:#9CA3AF;\">No data</div>"

        return (
            "<table width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" "
            "style=\"border-collapse:collapse; table-layout:fixed; width:100%;\">"
            + "".join(rendered_rows) +
            "</table>"
        )

    def build_bullet_section(self, title, items, color, accent_color=None, bullet="•"):

        if not items:
            return ""

        accent = accent_color or color
        lines = []

        for item in items:
            lines.append(
                f"<div style=\"color:{color}; margin:0 0 6px 0; white-space:normal; "
                f"overflow-wrap:anywhere; word-break:break-word; line-height:1.45;\">"
                f"{html.escape(bullet)} {html.escape(self.format_detail_value(item))}</div>"
            )

        return self.build_detail_card(title, "".join(lines), accent_color=accent)

    def build_issue_breakdown_section(self, title, issue_groups, color, accent_color=None, bullet="⚠"):

        if not issue_groups:
            return ""

        accent = accent_color or color
        detail_color = "#F7C2C2" if color == "#EB5757" else "#F8E7A1"
        groups_html = []

        for group in issue_groups:
            if isinstance(group, dict):
                group_title = self.format_detail_value(group.get("title"))
                details = list(group.get("details") or [])
            else:
                group_title = self.format_detail_value(group)
                details = []

            detail_lines = []
            for detail in details:
                detail_lines.append(
                    f"<div style=\"color:{detail_color}; margin:4px 0 0 22px; white-space:normal; "
                    f"overflow-wrap:anywhere; word-break:break-word; line-height:1.4;\">"
                    f"• {html.escape(self.format_detail_value(detail))}</div>"
                )

            groups_html.append(
                f"<div style=\"margin:0 0 8px 0;\">"
                f"<div style=\"color:{color}; white-space:normal; overflow-wrap:anywhere; "
                f"word-break:break-word; line-height:1.45;\">{html.escape(bullet)} {html.escape(group_title)}</div>"
                f"{''.join(detail_lines)}</div>"
            )

        return self.build_detail_card(title, "".join(groups_html), accent_color=accent)

    def build_html_grid_table(self, headers, rows, column_colors=None):

        if not rows:
            return "<div style=\"color:#9CA3AF;\">No data</div>"

        header_html = "".join(
            f"<td style=\"color:#FFFFFF; font-weight:700; padding:6px 8px;\">{html.escape(str(header))}</td>"
            for header in headers
        )

        rendered_rows = []
        column_colors = list(column_colors or [])

        for row in rows:
            cells = []
            for index, value in enumerate(row):
                color = column_colors[index] if index < len(column_colors) else "#DCE6F2"
                cells.append(
                    f"<td style=\"color:{color}; padding:6px 8px; vertical-align:top;\">"
                    f"{html.escape(self.format_detail_value(value))}</td>"
                )
            rendered_rows.append("<tr>" + "".join(cells) + "</tr>")

        return (
            "<table width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"border-collapse:collapse;\">"
            f"<tr>{header_html}</tr>"
            + "".join(rendered_rows) +
            "</table>"
        )

    def build_distribution_bar_card(self, title, distribution, accent_color="#57B6FF", bar_color=None, empty_message="No distribution data"):

        normalized_distribution = {}

        for label, value in dict(distribution or {}).items():
            if value in (None, "", [], {}):
                continue

            try:
                numeric_value = int(value)
            except (TypeError, ValueError):
                continue

            if numeric_value <= 0:
                continue

            normalized_distribution[self.format_field(str(label))] = numeric_value

        if not normalized_distribution:
            return self.build_detail_card(
                title,
                f"<div style=\"color:#9CA3AF;\">{html.escape(empty_message)}</div>",
                accent_color=accent_color,
            )

        total = sum(normalized_distribution.values())
        peak = max(normalized_distribution.values()) or 1
        fill_color = bar_color or accent_color
        rows = []

        for label, count in sorted(normalized_distribution.items(), key=lambda item: (-item[1], item[0])):
            share = (count / total) * 100 if total else 0
            width = max((count / peak) * 100, 8)
            rows.append(
                "<div style=\"margin:0 0 10px 0;\">"
                "<div style=\"display:flex; justify-content:space-between; gap:10px; margin-bottom:4px;\">"
                f"<span style=\"color:#FFFFFF; font-weight:600;\">{html.escape(label)}</span>"
                f"<span style=\"color:#9CA3AF;\">{count} | {share:.0f}%</span>"
                "</div>"
                "<div style=\"height:10px; background-color:#17212D; border-radius:999px; overflow:hidden;\">"
                f"<div style=\"width:{width:.1f}%; height:10px; background-color:{fill_color}; border-radius:999px;\"></div>"
                "</div></div>"
            )

        return self.build_detail_card(title, "".join(rows), accent_color=accent_color)

    def get_nested_value(self, data, *keys, default=None):

        current = data

        for key in keys:
            if not isinstance(current, dict):
                return default

            current = current.get(key)

            if current is None:
                return default

        return current
