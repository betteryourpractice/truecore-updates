import html
import os
import re
from datetime import datetime

from TrueCore.core.case_memory import (
    build_run_snapshot,
    get_recent_packet_runs,
    parse_intel_summary,
    parse_issues,
)


class MainWindowPacketUiMixin:

    def build_packet_math_html(self, file_path, result):

        result = dict(result or {})
        intel = dict(result.get("intel", {}) or {})
        intel_display = dict(intel.get("display", {}) or {})
        packet_output = dict(intel.get("packet_output", {}) or {})
        rubric = dict(packet_output.get("packet_rubric", {}) or {})

        if not intel or not packet_output or not rubric:
            return (
                "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
                "font-family:'Segoe UI'; font-size:13px; line-height:1.45; margin:0; text-align:left;\">"
                "<div style=\"margin:8px 0 0 0; padding:20px 22px; background:#151C26; "
                "border:1px solid #243244; border-radius:14px; text-align:left;\">"
                "<div style=\"font-size:20px; font-weight:700; color:#FFFFFF; margin-bottom:8px;\">Math view is not available for this packet</div>"
                "<div style=\"color:#A9B6C7;\">This row does not currently carry a full scoring worksheet payload.</div>"
                "</div></body></html>"
            )

        score = result.get("score", 0)
        rubric_score = rubric.get("score")
        legacy_score = packet_output.get("packet_legacy_score", intel_display.get("legacy_score"))
        approval_outlook = intel_display.get("approval_outlook", intel_display.get("approval_probability"))
        assembly_score = packet_output.get("packet_assembly_score", intel_display.get("packet_assembly_score"))
        evidence_score = packet_output.get("packet_evidence_score", intel_display.get("evidence_strength_score"))
        confidence = packet_output.get("packet_confidence", intel_display.get("packet_confidence"))

        try:
            score_value = float(score or 0.0)
        except Exception:
            score_value = 0.0

        try:
            rubric_score_value = float(rubric_score or 0.0)
        except Exception:
            rubric_score_value = 0.0

        confidence_factor = None
        if rubric_score_value > 0:
            confidence_factor = round(score_value / rubric_score_value, 4)

        summary_rows = [
            ("Packet", os.path.basename(file_path)),
            ("Displayed Score", f"{score_value:.2f}" if score_value else self.format_detail_value(score)),
            ("Base Rubric Score", f"{rubric_score_value:.2f}" if rubric_score_value else self.format_detail_value(rubric_score)),
            ("Baseline Score", f"{float(legacy_score):.2f}" if legacy_score not in (None, "", [], {}) else "Missing"),
            ("Approval Outlook", self.format_operator_display_value("Approval Outlook", approval_outlook)),
            ("Readiness", self.format_operator_display_value("Submission Readiness", intel_display.get("submission_readiness"))),
        ]

        sections = [
            self.build_detail_card(
                "Math Summary",
                self.build_detail_table(summary_rows, value_color="#DCE6F2", show_missing=False),
                accent_color="#57B6FF",
                margin_top=0,
            )
        ]

        document_points = float(rubric.get("document_points") or 0.0)
        document_max = float(rubric.get("document_max") or 0.0)
        consistency_points = float(rubric.get("consistency_points") or 0.0)
        consistency_max = float(rubric.get("consistency_max") or 0.0)

        formula_lines = [
            "Rubric backbone:",
            f"(({document_points:.2f} + {consistency_points:.2f}) / ({document_max:.2f} + {consistency_max:.2f})) × 100 = {rubric_score_value:.2f}",
        ]
        if confidence_factor is not None:
            formula_lines.extend(
                [
                    "",
                    "Displayed score adjustment:",
                    f"{rubric_score_value:.2f} × {confidence_factor:.4f} = {score_value:.2f}",
                ]
            )
        if evidence_score not in (None, "", [], {}) and assembly_score not in (None, "", [], {}) and legacy_score not in (None, "", [], {}):
            try:
                evidence_numeric = float(evidence_score)
                assembly_numeric = float(assembly_score)
                legacy_numeric = float(legacy_score)
                formula_lines.extend(
                    [
                        "",
                        "Baseline score comparison:",
                        f"({evidence_numeric:.2f} × 0.35) + ({assembly_numeric:.2f} × 0.65) = {legacy_numeric:.2f}",
                    ]
                )
            except Exception:
                pass

        blocker_count = len(list(rubric.get("blockers", []) or []))
        review_count = len(list(rubric.get("review_needs", []) or []))
        if approval_outlook not in (None, "", [], {}) and assembly_score not in (None, "", [], {}):
            try:
                approval_numeric = float(approval_outlook)
                assembly_numeric = float(assembly_score) / 100.0
                score_numeric = score_value / 100.0
                base_outlook = (score_numeric * 0.72) + (assembly_numeric * 0.28)
                formula_lines.extend(
                    [
                        "",
                        "Approval outlook starting blend:",
                        f"(({score_numeric:.4f} × 0.72) + ({assembly_numeric:.4f} × 0.28)) = {base_outlook:.4f}",
                        f"Then reduced for blockers ({blocker_count}) and review needs ({review_count}) to {approval_numeric:.4f}.",
                    ]
                )
            except Exception:
                pass

        formula_html = "".join(
            f"<div style=\"margin-bottom:6px; color:#DCE6F2; white-space:pre-wrap; text-align:left;\">{html.escape(line)}</div>"
            for line in formula_lines
        )
        sections.append(
            self.build_detail_card(
                "Equations Used",
                formula_html,
                accent_color="#F2C94C",
            )
        )

        component_rows = []
        for component in list(rubric.get("components", []) or []):
            component_rows.append(
                (
                    str(component.get("label") or "Component"),
                    f"{float(component.get('earned_points') or 0.0):.2f} / {float(component.get('max_points') or 0.0):.2f} | "
                    f"{self.format_detail_value(component.get('status'))} | "
                    f"{self.format_detail_value(component.get('summary'))}"
                )
            )

        if component_rows:
            sections.append(
                self.build_detail_card(
                    "Document Component Math",
                    self.build_detail_table(component_rows, value_color="#DCE6F2", show_missing=False),
                    accent_color="#2DCE89",
                )
            )

        consistency = dict(rubric.get("consistency", {}) or {})
        family_rows = []
        for family_name, points in dict(consistency.get("families") or {}).items():
            try:
                family_rows.append((self.format_field(family_name), f"{float(points):.2f}"))
            except Exception:
                family_rows.append((self.format_field(family_name), self.format_detail_value(points)))

        if consistency:
            consistency_rows = [
                ("Overall Consistency", f"{float(consistency.get('earned_points') or 0.0):.2f} / {float(consistency.get('max_points') or 0.0):.2f}"),
                ("Consistency Band", self.format_detail_value(consistency.get("status"))),
                ("Consistency Summary", self.format_detail_value(consistency.get("summary"))),
            ]
            sections.append(
                self.build_detail_card(
                    "Consistency Math",
                    self.build_detail_table(consistency_rows + family_rows, value_color="#DCE6F2", show_missing=False),
                    accent_color="#9B8CFF",
                )
            )

        sections.extend(self.build_semantic_reasoning_sections(intel_display))

        blocker_items = list(rubric.get("blockers", []) or [])
        review_items = list(rubric.get("review_needs", []) or [])
        if blocker_items:
            sections.append(
                self.build_bullet_section(
                    "Blocking Math Notes",
                    blocker_items,
                    color="#EB5757",
                    accent_color="#EB5757",
                )
            )
        if review_items:
            sections.append(
                self.build_bullet_section(
                    "Review-Level Math Notes",
                    review_items,
                    color="#F2C94C",
                    accent_color="#F2C94C",
                )
            )

        sections.append(
            self.build_detail_card(
                "What This Means",
                (
                    "<div style=\"color:#DCE6F2; line-height:1.5; text-align:left;\">"
                    "The packet score measures document quality and cross-document consistency. "
                    "Readiness is a separate decision layer, so a packet can score moderately and still be held if a real blocker remains."
                    "</div>"
                ),
                accent_color="#57B6FF",
            )
        )

        rendered_sections = "".join(section for section in sections if section)
        return (
            "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
            "font-family:'Segoe UI'; font-size:13px; line-height:1.45; margin:0; text-align:left;\">"
            f"{rendered_sections}</body></html>"
        )

    def format_operator_display_value(self, label, value):

        formatter = getattr(self, "format_packet_display_value", None)
        if callable(formatter):
            try:
                return formatter(label, value)
            except TypeError:
                pass
        return self.format_detail_value(value)

    def sentence_case_phrase(self, value):

        text = " ".join(str(value or "").strip().split())
        if not text:
            return ""

        acronym_map = {
            "va": "VA",
            "icd": "ICD",
            "mri": "MRI",
            "ocr": "OCR",
            "npi": "NPI",
            "icn": "ICN",
            "dob": "DOB",
            "seoc": "SEOC",
            "lomn": "LOMN",
        }

        for raw, rendered in acronym_map.items():
            text = re.sub(rf"\b{raw}\b", rendered, text, flags=re.IGNORECASE)

        if text and text[0].islower():
            text = text[0].upper() + text[1:]

        return text

    def title_case_field_candidate(self, value):

        raw = " ".join(str(value or "").strip().split())
        if not raw:
            return ""

        raw = re.sub(r"\bPain Man\b", "Pain Management", raw, flags=re.IGNORECASE)
        raw = re.sub(r"\bVa\b", "VA", raw)

        uppercase_tokens = {"VA", "MRI", "ICD", "NPI", "ICN", "DOB", "SEOC", "GA", "SC", "NC"}
        parts = re.split(r"(\s+)", raw)
        rendered = []

        for part in parts:
            if not part:
                continue
            if part.isspace():
                rendered.append(part)
                continue

            if re.search(r"[A-Za-z]", part):
                stripped = re.sub(r"^[^A-Za-z0-9]+|[^A-Za-z0-9]+$", "", part)
                if stripped.upper() in uppercase_tokens:
                    rendered.append(part.replace(stripped, stripped.upper()))
                else:
                    rendered.append(part.title())
            else:
                rendered.append(part)

        return "".join(rendered).strip()

    def extract_operator_issue_title(self, issue):

        if isinstance(issue, dict):
            return self.format_detail_value(issue.get("title"))
        return self.format_detail_value(issue)

    def significant_text_tokens(self, value):

        stop_words = {
            "a", "an", "and", "the", "for", "of", "to", "is", "are", "but", "or",
            "with", "across", "packet", "documents", "values", "value", "conflicting",
            "resolve", "reviewer", "review", "required", "missing", "present", "appears",
            "detected", "confirmed", "document", "level",
        }
        return {
            token
            for token in re.findall(r"[a-z]+", str(value or "").lower())
            if token and token not in stop_words
        }

    def choose_primary_fix(self, main_blocker, fix_items):

        rendered_fixes = [
            self.format_detail_value(item)
            for item in list(fix_items or [])
            if item not in (None, "", [], {})
        ]
        if not rendered_fixes:
            return None

        blocker_tokens = self.significant_text_tokens(main_blocker)
        if not blocker_tokens:
            return rendered_fixes[0]

        best_fix = rendered_fixes[0]
        best_score = -1

        for fix_text in rendered_fixes:
            overlap = blocker_tokens.intersection(self.significant_text_tokens(fix_text))
            score = len(overlap)
            if score > best_score:
                best_score = score
                best_fix = fix_text

        return best_fix

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
        semantic_coherence = self.format_operator_display_value("Semantic Coherence", intel_display.get("semantic_coherence"))
        ledger_summary = self.summarize_deduction_ledger(intel_display)
        deduction_groups = self.group_deduction_ledger(intel_display)

        missing_items = list(intel_display.get("missing_items") or [])
        main_blocker = self.format_detail_value(intel_display.get("main_blocker")) if intel_display.get("main_blocker") not in (None, "", [], {}) else None
        if not main_blocker and missing_items:
            main_blocker = self.format_detail_value(missing_items[0])
        elif not main_blocker and issue_groups:
            main_blocker = self.extract_operator_issue_title(issue_groups[0])

        first_fix = self.choose_primary_fix(main_blocker, fix_items)
        first_rationale = self.format_detail_value(review_rationale[0]) if review_rationale else None

        overall_parts = []
        if readiness not in (None, "", "Missing"):
            overall_parts.append(f"This packet is {readiness.lower()}.")
        elif packet_strength not in (None, "", "Missing"):
            overall_parts.append(f"This is currently a {packet_strength.lower()} packet.")
        primary_move = first_fix or next_action
        if primary_move not in (None, "", "Missing"):
            action_text = str(primary_move).strip()
            if action_text and action_text[-1] not in ".!?":
                action_text += "."
            overall_parts.append(f"Next move: {action_text}")
        overall_summary = " ".join(overall_parts).strip() or "Review the packet summary and issues below."

        review_posture_parts = []
        if confidence not in (None, "", "Missing"):
            review_posture_parts.append(f"{confidence} confidence")
        if workflow_queue not in (None, "", "Missing"):
            review_posture_parts.append(str(workflow_queue).strip())
        if review_priority not in (None, "", "Missing"):
            priority_text = str(review_priority).strip()
            if priority_text and not priority_text.lower().endswith("priority"):
                priority_text = f"{priority_text} priority"
            review_posture_parts.append(priority_text)
        review_posture = " | ".join(review_posture_parts)

        quick_rows = [("Overall", overall_summary)]
        if main_blocker not in (None, "", "Missing"):
            quick_rows.append(("Main blocker", main_blocker))
        if first_fix not in (None, "", "Missing"):
            quick_rows.append(("Do first", first_fix))
        if ledger_summary not in (None, "", "Missing"):
            quick_rows.append(("Decision basis", ledger_summary))
        if semantic_coherence not in (None, "", "Missing"):
            quick_rows.append(("Semantic read", semantic_coherence))
        if review_posture:
            quick_rows.append(("Review posture", review_posture))
        if deduction_groups["variant_tolerated"]:
            quick_rows.append(("Variant handling", "Formatting differences were tolerated where packet meaning still reconciled cleanly."))
        if first_rationale not in (None, "", "Missing"):
            quick_rows.append(("Why this was flagged", first_rationale))

        return self.build_detail_card(
            "Operator Quick Read",
            self.build_detail_table(quick_rows, value_color="#DCE6F2", show_missing=False),
            accent_color="#2DCE89",
            margin_top=margin_top,
        )

    def build_score_breakdown_card(self, intel_display, margin_top=12):

        intel_display = dict(intel_display or {})
        rows = []
        for item in list(intel_display.get("score_breakdown") or []):
            label = str(item.get("label") or "").strip()
            value = str(item.get("value") or "").strip()
            if not label or not value:
                continue
            rows.append((label, value))

        if not rows:
            return ""

        return self.build_detail_card(
            "Score Breakdown",
            self.build_detail_table(rows, value_color="#DCE6F2", show_missing=False),
            accent_color="#F2C94C",
            margin_top=margin_top,
        )

    def format_deduction_trust_label(self, trust_level):

        mapping = {
            "real_gap": "Real gap",
            "review_caution": "Review caution",
            "variant_tolerated": "Variant tolerated",
        }

        normalized = str(trust_level or "").strip().lower()
        if not normalized:
            return ""

        return mapping.get(normalized, self.sentence_case_phrase(normalized.replace("_", " ")))

    def format_deduction_reason(self, item):

        entry = dict(item or {})
        reason = " ".join(str(entry.get("reason") or "").strip().split())
        if not reason:
            return ""

        lowered = reason.lower()
        normalized_key = lowered.replace("_", " ")
        friendly_reason_map = {
            "partial diagnosis icd alignment": "Diagnosis and ICD support are present but only partially aligned.",
            "classification uncertainty": "Document classification still needs reviewer confirmation.",
            "manual review required": "Manual reviewer confirmation is still required.",
        }

        if normalized_key in friendly_reason_map:
            return friendly_reason_map[normalized_key]

        prefix = "Supporting document could not be confirmed:"
        if lowered.startswith(prefix.lower()):
            document_name = reason.split(":", 1)[1].strip() if ":" in reason else ""
            if document_name:
                return f"Supporting document could not be confirmed: {self.format_field(document_name)}"

        if hasattr(self, "format_review_flag") and "_" in lowered and ":" not in reason:
            formatted = self.format_review_flag(lowered)
            if formatted:
                return formatted

        if (
            hasattr(self, "format_review_flag")
            and lowered == reason
            and all(ch.islower() or ch.isspace() for ch in lowered)
        ):
            formatted = self.format_review_flag(lowered.replace(" ", "_"))
            if formatted:
                return formatted

        cleaned = self.sentence_case_phrase(reason)
        if cleaned and cleaned[-1] not in ".!?":
            cleaned += "."
        return cleaned

    def group_deduction_ledger(self, intel_display):

        display = dict(intel_display or {})
        grouped = {
            "real_gap": [],
            "review_caution": [],
            "variant_tolerated": [],
        }

        for item in list(display.get("deduction_ledger") or []):
            entry = dict(item or {})
            trust_level = str(entry.get("trust_level") or "review_caution").strip().lower()
            if trust_level not in grouped:
                trust_level = "review_caution"

            formatted = self.format_deduction_reason(entry)
            if formatted and formatted not in grouped[trust_level]:
                grouped[trust_level].append(formatted)

        return grouped

    def summarize_deduction_ledger(self, intel_display):

        grouped = self.group_deduction_ledger(intel_display)
        counts = [
            ("real_gap", len(grouped["real_gap"])),
            ("review_caution", len(grouped["review_caution"])),
            ("variant_tolerated", len(grouped["variant_tolerated"])),
        ]

        parts = []
        for trust_level, count in counts:
            if count <= 0:
                continue
            label = self.format_deduction_trust_label(trust_level).lower()
            suffix = "" if count == 1 else "s"
            parts.append(f"{count} {label}{suffix}")

        if not parts:
            return ""

        return " | ".join(parts)

    def build_semantic_reasoning_sections(self, intel_display, margin_top=12):

        display = dict(intel_display or {})
        grouped = self.group_deduction_ledger(display)
        summary_rows = []
        semantic_coherence = self.format_packet_display_value("Semantic Coherence", display.get("semantic_coherence"))
        ledger_summary = self.summarize_deduction_ledger(display)
        semantic_notes = [
            self.sentence_case_phrase(item)
            for item in list(display.get("semantic_review_notes") or [])
            if item not in (None, "", [], {})
        ]

        if semantic_coherence not in (None, "", "Missing"):
            summary_rows.append(("Semantic Coherence", semantic_coherence))
        if ledger_summary:
            summary_rows.append(("Deduction Ledger", ledger_summary))
        if grouped["variant_tolerated"]:
            summary_rows.append(("Variant Handling", "Formatting differences were tolerated where packet meaning still reconciled coherently."))

        sections = []
        if summary_rows:
            sections.append(
                self.build_detail_card(
                    "Semantic Adjudication",
                    self.build_detail_table(summary_rows, value_color="#DCE6F2", show_missing=False),
                    accent_color="#2DCE89",
                    margin_top=margin_top,
                )
            )

        if grouped["real_gap"]:
            sections.append(
                self.build_bullet_section(
                    "Real Gaps",
                    grouped["real_gap"],
                    color="#EB5757",
                    accent_color="#EB5757",
                )
            )

        if grouped["review_caution"]:
            sections.append(
                self.build_bullet_section(
                    "Review Cautions",
                    grouped["review_caution"],
                    color="#F2C94C",
                    accent_color="#F2994A",
                )
            )

        if grouped["variant_tolerated"]:
            sections.append(
                self.build_bullet_section(
                    "Variant-Tolerated Differences",
                    grouped["variant_tolerated"],
                    color="#6FCF97",
                    accent_color="#27AE60",
                )
            )

        if semantic_notes:
            sections.append(
                self.build_bullet_section(
                    "Semantic Review Notes",
                    semantic_notes,
                    color="#57B6FF",
                    accent_color="#57B6FF",
                )
            )

        return sections

    def packet_conflict_field_aliases(self, field_name):

        normalized = str(field_name or "").strip().lower()
        alias_map = {
            "patient_name": {"patient_name", "name"},
            "ordering_doctor": {"ordering_doctor", "ordering_provider"},
            "referring_doctor": {"referring_doctor", "referring_provider"},
        }
        return alias_map.get(normalized, {normalized})

    def find_packet_field_conflict(self, field_name, result):

        packet_output = dict(((result or {}).get("intel", {}) or {}).get("packet_output", {}) or {})
        aliases = self.packet_conflict_field_aliases(field_name)

        for conflict in list(packet_output.get("conflicts", []) or []):
            conflict_field = str(conflict.get("field") or "").strip().lower()
            if conflict_field in aliases:
                return dict(conflict)

        return {}

    def score_field_candidate(self, field_name, value):

        text = " ".join(str(value or "").strip().split())
        if not text:
            return -999

        field_key = str(field_name or "").strip().lower()
        lowered = text.lower()
        score = float(len(text))

        if re.search(r"[A-Za-z]\d|\d[A-Za-z]", text):
            score -= 20
        if lowered.startswith("hpi "):
            score -= 8

        if field_key in {"patient_name", "name"}:
            alpha_tokens = re.findall(r"[A-Za-z][A-Za-z'\\-]*", text)
            if len(alpha_tokens) >= 2:
                score += 15
            if any(len(token) == 1 for token in alpha_tokens):
                score -= 4
        elif field_key in {"facility", "clinic_name", "location"}:
            if any(term in lowered for term in ["medical center", "neurosciences", "pain", "center"]):
                score += 8
            if lowered.endswith(" pain man"):
                score -= 4
            if len(text) < 12:
                score -= 6

        return score

    def preferred_conflict_candidate(self, field_name, current_value, result):

        conflict = self.find_packet_field_conflict(field_name, result)
        candidates = [current_value]
        candidates.extend(list(conflict.get("values", []) or []))

        unique_candidates = []
        seen = set()
        for candidate in candidates:
            normalized = " ".join(str(candidate or "").strip().lower().split())
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            unique_candidates.append(str(candidate).strip())

        if not unique_candidates:
            return None

        ranked = sorted(
            unique_candidates,
            key=lambda item: self.score_field_candidate(field_name, item),
            reverse=True,
        )
        return self.title_case_field_candidate(ranked[0])

    def is_suspicious_field_value(self, field_name, value):

        text = " ".join(str(value or "").strip().split())
        if not text:
            return False

        field_key = str(field_name or "").strip().lower()
        lowered = text.lower()

        if re.search(r"[A-Za-z]\d|\d[A-Za-z]", text):
            return True
        if lowered.startswith("hpi "):
            return True
        if field_key in {"clinic_name", "facility", "location"} and lowered.endswith(" pain man"):
            return True
        if field_key in {"patient_name", "name"} and len(re.findall(r"[A-Za-z][A-Za-z'\\-]*", text)) < 2:
            return True

        return False

    def format_packet_field_value_for_details(self, field_name, value, result):

        display_value = self.format_packet_display_value(field_name, value)
        conflict = self.find_packet_field_conflict(field_name, result)
        if not conflict:
            return display_value

        preferred = self.preferred_conflict_candidate(field_name, display_value, result)
        if not preferred:
            return display_value

        current_normalized = " ".join(str(display_value or "").strip().lower().split())
        preferred_normalized = " ".join(str(preferred or "").strip().lower().split())

        if preferred_normalized != current_normalized and (
            self.is_suspicious_field_value(field_name, display_value)
            or str(field_name or "").strip().lower() == "patient_name"
        ):
            return f"Likely: {preferred}"

        return display_value

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
        normalized = normalized.replace("appears present but unfilled", "is present but unfilled")
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

    def build_active_review_flags(self, missing_items, issue_items):

        return sorted(
            set(self.normalize_comparison_items(missing_items))
            | set(self.normalize_comparison_items(issue_items))
        )

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

    def extract_redacted_file_extension(self, file_reference):

        match = re.match(r"^(\.[a-z0-9]+):", str(file_reference or "").strip().lower())
        if match:
            return match.group(1)
        return None

    def find_previous_packet_run(self, file_path, result, limit=250):

        current_snapshot = build_run_snapshot(file_path, result)
        case_key = str(current_snapshot.get("case_key") or "")
        file_reference = str(current_snapshot.get("file_name") or "")
        current_signature = self.build_current_review_signature(file_path, result)
        current_extension = self.extract_redacted_file_extension(file_reference)

        exact_matches = []
        extension_matches = []

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

            if file_reference and row_file_reference == file_reference:
                exact_matches.append(row)
                continue

            row_extension = self.extract_redacted_file_extension(row_file_reference)

            if current_extension and row_extension == current_extension:
                extension_matches.append(row)
                continue

            if not current_extension:
                extension_matches.append(row)

        if exact_matches:
            return exact_matches[0]
        if extension_matches:
            return extension_matches[0]

        return None

    def format_repeat_review_item(self, value):

        return self.sentence_case_phrase(value)

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
        previous_flags = self.build_active_review_flags(previous_missing, previous_issues)
        current_flags = self.build_active_review_flags(current_missing, current_issues)

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

        resolved_flags = sorted(set(previous_flags) - set(current_flags))
        new_flags = sorted(set(current_flags) - set(previous_flags))

        resolved_items.extend(
            f"Issue resolved: {self.format_repeat_review_item(item)}"
            for item in resolved_flags
        )
        new_items.extend(
            f"New issue: {self.format_repeat_review_item(item)}"
            for item in new_flags
        )

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
                f"<div style=\"color:#9CA3AF; font-size:11px; margin-top:4px; text-align:left;\">{html.escape(subtitle)}</div>"
                if subtitle else ""
            )

            rendered_tiles.append(
                "<div style=\"display:inline-block; width:31%; min-width:180px; vertical-align:top; "
                "margin:0 1.5% 12px 0; padding:12px 14px; background-color:#10161E; "
                f"border:1px solid #253243; border-top:3px solid {accent}; border-radius:8px; box-sizing:border-box; text-align:left;\">"
                f"<div style=\"color:#FFFFFF; font-size:12px; font-weight:600; text-align:left;\">{html.escape(title)}</div>"
                f"<div style=\"color:{accent}; font-size:24px; font-weight:700; margin-top:6px; text-align:left;\">{html.escape(value)}</div>"
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
            f"box-sizing:border-box; overflow-wrap:anywhere; word-break:break-word; text-align:left;\">"
            f"<div style=\"color:#FFFFFF; font-weight:700; margin-bottom:8px; text-align:left;\">"
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
                f"white-space:normal; overflow-wrap:anywhere; word-break:break-word; text-align:left;\">"
                f"{html.escape(str(label))}</td>"
                f"<td valign=\"top\" style=\"color:{row_color}; padding:3px 0; "
                f"white-space:normal; overflow-wrap:anywhere; word-break:break-word; text-align:left;\">"
                f"{html.escape(display_value)}</td>"
                "</tr>"
            )

        if not rendered_rows:
            return "<div style=\"color:#9CA3AF;\">No data</div>"

        return (
            "<table width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" "
            "style=\"border-collapse:collapse; table-layout:fixed; width:100%; text-align:left;\">"
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
                f"overflow-wrap:anywhere; word-break:break-word; line-height:1.45; text-align:left;\">"
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
                    f"overflow-wrap:anywhere; word-break:break-word; line-height:1.4; text-align:left;\">"
                    f"• {html.escape(self.format_detail_value(detail))}</div>"
                )

            groups_html.append(
                f"<div style=\"margin:0 0 8px 0;\">"
                f"<div style=\"color:{color}; white-space:normal; overflow-wrap:anywhere; "
                f"word-break:break-word; line-height:1.45; text-align:left;\">{html.escape(bullet)} {html.escape(group_title)}</div>"
                f"{''.join(detail_lines)}</div>"
            )

        return self.build_detail_card(title, "".join(groups_html), accent_color=accent)

    def build_html_grid_table(self, headers, rows, column_colors=None):

        if not rows:
            return "<div style=\"color:#9CA3AF;\">No data</div>"

        header_html = "".join(
            f"<td style=\"color:#FFFFFF; font-weight:700; padding:6px 8px; text-align:left;\">{html.escape(str(header))}</td>"
            for header in headers
        )

        rendered_rows = []
        column_colors = list(column_colors or [])

        for row in rows:
            cells = []
            for index, value in enumerate(row):
                color = column_colors[index] if index < len(column_colors) else "#DCE6F2"
                cells.append(
                    f"<td style=\"color:{color}; padding:6px 8px; vertical-align:top; text-align:left;\">"
                    f"{html.escape(self.format_detail_value(value))}</td>"
                )
            rendered_rows.append("<tr>" + "".join(cells) + "</tr>")

        return (
            "<table width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"border-collapse:collapse; text-align:left;\">"
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
