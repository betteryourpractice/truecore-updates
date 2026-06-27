from __future__ import annotations

import html
import os
from datetime import datetime

from PySide6.QtCore import QSignalBlocker, Qt
from PySide6.QtGui import QColor, QFontMetrics, QTextOption
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from TrueCore.ui.pyside_gui.dev_tools_controls import AutoSizingPlainTextEdit


class PacketBuilderWordingLibraryMixin:
    def _build_wording_tab(self):
        wording_tab = QWidget()
        wording_tab_layout = QVBoxLayout(wording_tab)
        wording_tab_layout.setContentsMargins(0, 0, 0, 0)
        wording_tab_layout.setSpacing(8)
        wording_help = QLabel(
            "Wording Assist turns rough facts into provider-style language for denial-sensitive fields. Review the original wording, cycle the phrasing when you want a different version, then accept, edit, or intentionally keep the original before final export."
        )
        wording_help.setWordWrap(True)
        wording_help.setStyleSheet("color:#8FA6C1;")
        wording_tab_layout.addWidget(wording_help)
        wording_splitter = QSplitter(Qt.Horizontal)
        wording_splitter.setChildrenCollapsible(False)
        wording_splitter.setHandleWidth(10)
        self.wording_splitter = wording_splitter
        self.wording_assist_list = QListWidget()
        self.wording_assist_list.setMinimumWidth(0)
        self.wording_assist_list.setMaximumWidth(230)
        self.wording_assist_list.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.wording_assist_list.setStyleSheet(
            "QListWidget { background:#09121B; border:1px solid #243446; border-radius:10px; padding:8px; }"
            "QListWidget::item { color:#E8F1FC; padding:8px 10px; margin:2px 0; border-radius:8px; }"
            "QListWidget::item:selected { background:#1D2A3A; }"
        )
        self.wording_assist_list.currentItemChanged.connect(self._on_wording_entry_changed)
        wording_splitter.addWidget(self.wording_assist_list)

        wording_detail = QWidget()
        wording_detail.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        wording_detail.setMinimumWidth(0)
        wording_detail_layout = QVBoxLayout(wording_detail)
        wording_detail_layout.setContentsMargins(0, 0, 18, 0)
        wording_detail_layout.setSpacing(8)
        self.wording_field_title_label = QLabel("No wording-assist fields on this form.")
        self.wording_field_title_label.setWordWrap(True)
        self.wording_field_title_label.setStyleSheet("color:#EAF2FF; font-size:15px; font-weight:700;")
        wording_detail_layout.addWidget(self.wording_field_title_label)
        self.wording_status_label = QLabel("")
        self.wording_status_label.setWordWrap(True)
        wording_detail_layout.addWidget(self.wording_status_label)
        self.wording_followup_label = QLabel("")
        self.wording_followup_label.setWordWrap(True)
        self.wording_followup_label.setStyleSheet("color:#FCD7A4;")
        wording_detail_layout.addWidget(self.wording_followup_label)
        self.wording_risk_label = QLabel("")
        self.wording_risk_label.setWordWrap(True)
        self.wording_risk_label.setStyleSheet("color:#F4C7C3;")
        wording_detail_layout.addWidget(self.wording_risk_label)
        original_label = QLabel("Original Wording")
        original_label.setStyleSheet("color:#C8D8E8; font-weight:700;")
        wording_detail_layout.addWidget(original_label)
        self.wording_original_view = AutoSizingPlainTextEdit(150)
        self.wording_original_view.setReadOnly(True)
        self.wording_original_view.document().setDocumentMargin(10)
        self.wording_original_view.setLineWrapMode(AutoSizingPlainTextEdit.WidgetWidth)
        self.wording_original_view.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        self.wording_original_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.wording_original_view.setCenterOnScroll(False)
        self.wording_original_view.setStyleSheet(
            "background:#09121B; border:1px solid #243446; border-radius:10px; color:#E8F1FC; padding:12px 10px 18px 10px; font-size:13px;"
        )
        wording_detail_layout.addWidget(self.wording_original_view)
        suggestion_label = QLabel("Suggested Professional Wording")
        suggestion_label.setStyleSheet("color:#C8D8E8; font-weight:700;")
        wording_detail_layout.addWidget(suggestion_label)
        self.wording_suggestion_input = AutoSizingPlainTextEdit(220)
        self.wording_suggestion_input.document().setDocumentMargin(10)
        self.wording_suggestion_input.setLineWrapMode(AutoSizingPlainTextEdit.WidgetWidth)
        self.wording_suggestion_input.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        self.wording_suggestion_input.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.wording_suggestion_input.setCenterOnScroll(False)
        self.wording_suggestion_input.setStyleSheet(
            "background:#0F1823; border:1px solid #243446; border-radius:10px; color:#EAF2FF; padding:12px 10px 18px 10px; font-size:13px;"
        )
        wording_detail_layout.addWidget(self.wording_suggestion_input, stretch=1)
        wording_button_row = QGridLayout()
        wording_button_row.setContentsMargins(0, 0, 0, 0)
        wording_button_row.setHorizontalSpacing(8)
        wording_button_row.setVerticalSpacing(8)
        self.wording_accept_button = QPushButton("Accept Suggestion")
        self._style_builder_button(self.wording_accept_button)
        self.wording_accept_button.clicked.connect(self.accept_wording_suggestion)
        self.wording_accept_button.setMaximumWidth(180)
        wording_button_row.addWidget(self.wording_accept_button, 0, 0)
        self.wording_edit_button = QPushButton("Apply Edited Suggestion")
        self._style_builder_button(self.wording_edit_button)
        self.wording_edit_button.clicked.connect(self.apply_edited_wording_suggestion)
        self.wording_edit_button.setMaximumWidth(180)
        wording_button_row.addWidget(self.wording_edit_button, 0, 1)
        self.wording_keep_button = QPushButton("Keep Original")
        self._style_builder_button(self.wording_keep_button)
        self.wording_keep_button.clicked.connect(self.keep_original_wording)
        self.wording_keep_button.setMaximumWidth(160)
        wording_button_row.addWidget(self.wording_keep_button, 0, 2)
        self.wording_cycle_button = QPushButton("Cycle Phrasing")
        self._style_builder_button(self.wording_cycle_button)
        self.wording_cycle_button.clicked.connect(self.cycle_wording_suggestion)
        self.wording_cycle_button.setMaximumWidth(160)
        wording_button_row.addWidget(self.wording_cycle_button, 1, 0)
        self.wording_reset_button = QPushButton("Reset Review")
        self._style_builder_button(self.wording_reset_button)
        self.wording_reset_button.clicked.connect(self.reset_wording_review)
        self.wording_reset_button.setMaximumWidth(150)
        wording_button_row.addWidget(self.wording_reset_button, 1, 1)
        wording_button_row.setColumnStretch(0, 1)
        wording_button_row.setColumnStretch(1, 1)
        wording_button_row.setColumnStretch(2, 1)
        wording_detail_layout.addLayout(wording_button_row)
        wording_detail_scroll = QScrollArea()
        wording_detail_scroll.setWidgetResizable(True)
        wording_detail_scroll.setFrameShape(QFrame.NoFrame)
        wording_detail_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        wording_detail_scroll.setWidget(wording_detail)
        wording_splitter.addWidget(wording_detail_scroll)
        wording_splitter.setStretchFactor(0, 0)
        wording_splitter.setStretchFactor(1, 1)
        wording_splitter.setSizes([180, 720])
        wording_tab_layout.addWidget(wording_splitter, stretch=1)
        return wording_tab

    def _build_library_tab(self):
        library_tab = QWidget()
        library_tab_layout = QVBoxLayout(library_tab)
        library_tab_layout.setContentsMargins(0, 0, 0, 0)
        library_tab_layout.setSpacing(8)
        library_help = QLabel(
            "Saved packet drafts live here. Click the packet name to reopen it, open its latest PDF, or remove the draft from the library."
        )
        library_help.setWordWrap(True)
        library_help.setStyleSheet("color:#8FA6C1;")
        library_tab_layout.addWidget(library_help)
        self.library_list = QListWidget()
        self.library_list.setStyleSheet(
            "QListWidget { background:#09121B; border:1px solid #243446; border-radius:10px; padding:8px; }"
            "QListWidget::item { border:0px; margin:0px; padding:0px; }"
        )
        library_tab_layout.addWidget(self.library_list, stretch=1)
        return library_tab

    def _style_library_button(self, button, destructive=False):
        background = "#1D2A3A"
        border = "#34506B"
        hover = "#223246"
        if destructive:
            background = "#4A1F1F"
            border = "#934141"
            hover = "#5A2626"
        button.setFixedHeight(30)
        button.setMaximumWidth(110)
        button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        button.setStyleSheet(
            "QPushButton {"
            f"background-color:{background}; color:#FFFFFF; border:1px solid {border}; border-radius:8px; "
            "padding:4px 10px; font-size:12px; font-weight:600; }"
            f"QPushButton:hover {{ background-color:{hover}; }}"
        )

    def _update_wording_assist_list_width(self):
        if not hasattr(self, "wording_assist_list"):
            return
        metrics = QFontMetrics(self.wording_assist_list.font())
        longest = 0
        for index in range(self.wording_assist_list.count()):
            item = self.wording_assist_list.item(index)
            if item:
                longest = max(longest, metrics.horizontalAdvance(item.text()))
        content_width = longest + 54
        target_width = max(156, min(220, content_width))
        self.wording_assist_list.setFixedWidth(target_width)
        splitter = getattr(self, "wording_splitter", None)
        if splitter is not None:
            total_width = max(splitter.size().width(), 820)
            right_width = max(500, total_width - target_width - splitter.handleWidth() - 18)
            splitter.setSizes([target_width, right_width])

    def _set_payload_field_value(self, field_name, value):
        binding = self._packet_widget_bindings.get(field_name)
        if not binding:
            return False
        attr_name, kind = binding
        widget = getattr(self, attr_name, None)
        if widget is None:
            return False
        self._set_bound_widget_value(widget, value, kind)
        return True

    def _wording_status_markup(self, entry):
        status_colors = self._wording_status_colors
        bg, border, text = status_colors.get(entry.get("status_key"), status_colors["needs_review"])
        return (
            f"<span style='display:inline-block; padding:4px 10px; border-radius:10px; "
            f"background:{bg}; color:{text}; border:1px solid {border}; font-weight:700;'>"
            f"{html.escape(entry.get('status_label') or 'Needs Review')}</span>"
        )

    def _refresh_wording_assist(self):
        payload = self.collect_payload() if self._builder_ready else dict(self.packet_payload or {})
        entries = self._build_wording_assist_entries_fn(payload)
        self._wording_entries = {entry["key"]: entry for entry in entries}
        selected_key = self._current_wording_entry_key if self._current_wording_entry_key in self._wording_entries else ""
        with QSignalBlocker(self.wording_assist_list):
            self.wording_assist_list.clear()
            for entry in entries:
                item = QListWidgetItem(entry["label"])
                item.setData(Qt.UserRole, entry["key"])
                bg, _, fg = self._wording_status_colors.get(
                    entry["status_key"], self._wording_status_colors["needs_review"]
                )
                item.setBackground(QColor(bg))
                item.setForeground(QColor(fg))
                item.setToolTip(entry["status_label"])
                self.wording_assist_list.addItem(item)
                if entry["key"] == selected_key:
                    self.wording_assist_list.setCurrentItem(item)
            if not selected_key and self.wording_assist_list.count() > 0:
                self.wording_assist_list.setCurrentRow(0)
        self._update_wording_assist_list_width()
        current_item = self.wording_assist_list.currentItem()
        if current_item:
            self._on_wording_entry_changed(current_item, None)
        else:
            self._current_wording_entry_key = ""
            self.wording_field_title_label.setText("No wording-assist fields on this form.")
            self.wording_status_label.setText("")
            self.wording_followup_label.setText("")
            self.wording_risk_label.setText("")
            self.wording_original_view.setPlainText("")
            self.wording_suggestion_input.setPlainText("")
            self.wording_accept_button.setEnabled(False)
            self.wording_edit_button.setEnabled(False)
            self.wording_keep_button.setEnabled(False)
            self.wording_reset_button.setEnabled(False)

    def _on_wording_entry_changed(self, current, previous):
        key = current.data(Qt.UserRole) if current else ""
        entry = dict(self._wording_entries.get(key) or {})
        self._current_wording_entry_key = key or ""
        if not entry:
            self.wording_field_title_label.setText("No wording-assist fields on this form.")
            self.wording_status_label.setText("")
            self.wording_followup_label.setText("")
            self.wording_risk_label.setText("")
            self.wording_original_view.setPlainText("")
            self.wording_suggestion_input.setPlainText("")
            self.wording_accept_button.setEnabled(False)
            self.wording_edit_button.setEnabled(False)
            self.wording_keep_button.setEnabled(False)
            self.wording_cycle_button.setEnabled(False)
            self.wording_reset_button.setEnabled(False)
            return
        self.wording_field_title_label.setText(entry["label"])
        self.wording_status_label.setText(self._wording_status_markup(entry))
        if entry["missing_facts"]:
            self.wording_followup_label.setText(
                "Follow-up needed before professional wording can be approved:\n- "
                + "\n- ".join(entry["missing_facts"])
            )
        else:
            scenario_lines = ["All supporting facts needed for wording assist are present."]
            if entry.get("scenario_label"):
                scenario_lines.append(f"Matched blueprint: {entry['scenario_label']}")
            if entry.get("scenario_use_when"):
                scenario_lines.append(f"Use when: {entry['scenario_use_when']}")
            self.wording_followup_label.setText("\n".join(scenario_lines))
        if entry["risk_messages"]:
            self.wording_risk_label.setText("Wording checks:\n- " + "\n- ".join(entry["risk_messages"]))
        else:
            self.wording_risk_label.setText("No wording-risk flags detected in the current text.")
        self.wording_original_view.setPlainText(entry["raw_text"])
        self.wording_suggestion_input.setPlainText(entry["suggestion_text"])
        allow_suggestion = bool(entry["suggestion_text"]) and not entry["missing_facts"]
        self.wording_accept_button.setEnabled(allow_suggestion)
        self.wording_edit_button.setEnabled(True)
        self.wording_keep_button.setEnabled(bool(entry["raw_text"]))
        self.wording_cycle_button.setEnabled(allow_suggestion)
        self.wording_reset_button.setEnabled(bool((self._wording_assist_state or {}).get(entry["key"])))

    def _store_wording_review(self, entry_key, decision, approved_text):
        payload = self.collect_payload()
        entries = {entry["key"]: entry for entry in self._build_wording_assist_entries_fn(payload)}
        entry = entries.get(entry_key)
        if not entry:
            return
        state = dict(self._wording_assist_state or {})
        prior_state = dict(state.get(entry_key) or {})
        state[entry_key] = {
            "decision": decision,
            "approved_text": self._sanitize_packet_builder_text_fn(approved_text),
            "source_fingerprint": entry["source_fingerprint"],
            "reviewed_at": datetime.now().isoformat(timespec="seconds"),
            "cycle_index": prior_state.get("cycle_index", entry.get("cycle_index", 0)),
        }
        self._wording_assist_state = state

    def cycle_wording_suggestion(self):
        entry = dict(self._wording_entries.get(self._current_wording_entry_key) or {})
        if not entry or entry["missing_facts"]:
            return
        state = dict(self._wording_assist_state or {})
        current_state = dict(state.get(entry["key"]) or {})
        try:
            cycle_index = max(0, int(current_state.get("cycle_index") or 0)) + 1
        except Exception:
            cycle_index = 1
        current_state["cycle_index"] = cycle_index
        current_state["reviewed_at"] = datetime.now().isoformat(timespec="seconds")
        state[entry["key"]] = current_state
        self._wording_assist_state = state
        self.refresh_preview()
        self._select_wording_entry(entry["key"])

    def accept_wording_suggestion(self):
        entry = dict(self._wording_entries.get(self._current_wording_entry_key) or {})
        suggestion = self._sanitize_packet_builder_text_fn(self.wording_suggestion_input.toPlainText())
        if not entry or not suggestion:
            return
        self._set_payload_field_value(entry["field_name"], suggestion)
        self._store_wording_review(entry["key"], "accepted", suggestion)
        self.refresh_preview()
        self._select_wording_entry(entry["key"])

    def apply_edited_wording_suggestion(self):
        entry = dict(self._wording_entries.get(self._current_wording_entry_key) or {})
        edited_text = self._sanitize_packet_builder_text_fn(self.wording_suggestion_input.toPlainText())
        if not entry:
            return
        if not edited_text:
            QMessageBox.information(self, "Edited Suggestion Required", "Enter the edited wording you want to approve for this field.")
            return
        self._set_payload_field_value(entry["field_name"], edited_text)
        self._store_wording_review(entry["key"], "edited", edited_text)
        self.refresh_preview()
        self._select_wording_entry(entry["key"])

    def keep_original_wording(self):
        entry = dict(self._wording_entries.get(self._current_wording_entry_key) or {})
        if not entry or not entry["raw_text"]:
            return
        self._store_wording_review(entry["key"], "keep_original", entry["raw_text"])
        self.refresh_preview()
        self._select_wording_entry(entry["key"])

    def reset_wording_review(self):
        entry_key = self._current_wording_entry_key
        if not entry_key:
            return
        state = dict(self._wording_assist_state or {})
        if entry_key in state:
            state.pop(entry_key, None)
            self._wording_assist_state = state
        self.refresh_preview()
        self._select_wording_entry(entry_key)

    def _select_wording_entry(self, entry_key):
        if not entry_key:
            return
        for index in range(self.wording_assist_list.count()):
            item = self.wording_assist_list.item(index)
            if item.data(Qt.UserRole) == entry_key:
                self.wording_assist_list.setCurrentItem(item)
                break

    def _current_display_name(self, payload=None, base_filename=None):
        working_payload = dict(payload or self.collect_payload())
        return self._packet_library_display_name_fn(working_payload, base_filename or self._resolve_base_filename())

    def _build_current_draft_record(self):
        payload = self.collect_payload()
        now = datetime.now().isoformat(timespec="seconds")
        existing = dict(self.current_draft_record or {})
        artifacts = dict(existing.get("artifacts") or {})
        return {
            "draft_id": self.current_draft_id or existing.get("draft_id") or self._generate_packet_library_draft_id_fn(),
            "display_name": self._current_display_name(payload),
            "base_filename": self._resolve_base_filename(),
            "packet_profile": str(payload.get("packet_profile") or "").strip(),
            "saved_at": existing.get("saved_at") or now,
            "updated_at": now,
            "artifacts": artifacts,
            "payload": payload,
        }

    def _save_current_draft_record(self, silent=False):
        record = self._save_packet_library_record_fn(self._build_current_draft_record())
        self.current_draft_id = record.get("draft_id")
        self.current_draft_record = dict(record)
        self.refresh_library()
        self._update_current_packet_status()
        if not silent:
            QMessageBox.information(
                self,
                "Saved To Packet Library",
                f"{record.get('display_name') or 'Packet draft'} was saved to the Packet Library.",
            )
        return record

    def _update_current_draft_artifacts(self, updates):
        if not updates:
            return
        record = self.current_draft_record if self.current_draft_id else self._save_current_draft_record(silent=True)
        artifacts = dict((record or {}).get("artifacts") or {})
        artifacts.update({key: value for key, value in dict(updates or {}).items() if value})
        record = dict(record or {})
        record["artifacts"] = artifacts
        record = self._save_packet_library_record_fn(record)
        self.current_draft_record = dict(record)
        self.refresh_library()
        self._update_current_packet_status()

    def _preferred_pdf_path_for_record(self, record):
        artifacts = dict((record or {}).get("artifacts") or {})
        candidates = [
            artifacts.get("compiled_patient_packet_pdf"),
            artifacts.get("single_doc_pdf"),
            artifacts.get("referral_request_pdf"),
        ]
        for bundle_key in ("patient_packet_bundle_dir", "referral_request_bundle_dir"):
            bundle_dir = str(artifacts.get(bundle_key) or "").strip()
            if bundle_dir and os.path.isdir(bundle_dir):
                for name in sorted(os.listdir(bundle_dir)):
                    if str(name).lower().endswith(".pdf"):
                        candidates.append(os.path.join(bundle_dir, name))
        for candidate in candidates:
            normalized = str(candidate or "").strip()
            if normalized and os.path.exists(normalized):
                return normalized
        return ""

    def _artifact_folder_for_record(self, record):
        artifacts = dict((record or {}).get("artifacts") or {})
        for key in ("patient_packet_bundle_dir", "referral_request_bundle_dir"):
            bundle_dir = str(artifacts.get(key) or "").strip()
            if bundle_dir and os.path.isdir(bundle_dir):
                return bundle_dir
        preferred_pdf = self._preferred_pdf_path_for_record(record)
        if preferred_pdf:
            return os.path.dirname(preferred_pdf)
        single_doc = str(artifacts.get("single_doc_docx") or artifacts.get("single_doc_pdf") or "").strip()
        if single_doc and os.path.exists(single_doc):
            return os.path.dirname(single_doc)
        return str(self.config.get("packet_builder_export_dir") or "").strip()

    def _format_library_timestamp(self, value):
        try:
            return datetime.fromisoformat(str(value)).strftime("%b %d, %Y %I:%M %p")
        except Exception:
            return "Unknown"

    def _update_current_packet_status(self):
        payload = self.collect_payload() if self._builder_ready else dict(self.packet_payload or {})
        display_name = self._current_display_name(payload)
        completion = self._build_packet_library_completion_fn(payload)
        metrics = self._build_packet_library_production_metrics_fn(payload)
        saved_state = "Saved Draft" if self.current_draft_id else "Unsaved Draft"
        readiness_label = {
            "ready": "Ready",
            "requires_review": "Review Required",
            "hold": "Hold",
        }.get(metrics.get("readiness"), "Hold")
        self.current_packet_status_label.setText(
            f"{saved_state}: {display_name} | {completion.get('status_label')} | "
            f"Prod Score {int(round(metrics.get('score') or 0))} | {readiness_label}"
        )

    def _build_library_row(self, record):
        payload = dict(record.get("payload") or {})
        completion = self._build_packet_library_completion_fn(payload)
        metrics = self._build_packet_library_production_metrics_fn(payload)
        status_palette = self._packet_profile_status_palette_fn(completion.get("status_key"))
        readiness = str(metrics.get("readiness") or "hold")
        readiness_colors = {
            "ready": ("#173B29", "#2C8B57", "#EAFBF1"),
            "requires_review": ("#4A3410", "#C7922E", "#FFF6DB"),
            "hold": ("#441A1A", "#B55050", "#FFECEC"),
        }
        ready_bg, ready_border, ready_text = readiness_colors.get(readiness, readiness_colors["hold"])
        is_current = record.get("draft_id") == self.current_draft_id

        frame = QFrame()
        frame.setStyleSheet(
            "QFrame {"
            f"background:#0F1823; border:1px solid {'#4A89C7' if is_current else '#243446'}; border-radius:12px; "
            "padding:10px; }"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        title_button = QPushButton(str(record.get("display_name") or "Untitled Packet"))
        title_button.setCursor(Qt.PointingHandCursor)
        title_button.setFlat(True)
        title_button.setStyleSheet(
            "QPushButton { color:#EAF2FF; font-size:15px; font-weight:700; text-align:left; border:0px; padding:0px; }"
            "QPushButton:hover { color:#8BC8FF; }"
        )
        title_button.clicked.connect(lambda _=False, draft_id=record.get("draft_id"): self.load_library_draft(draft_id))
        top_row.addWidget(title_button, stretch=1)

        status_badge = QLabel(completion.get("status_label") or "In Progress")
        status_badge.setStyleSheet(
            "padding:4px 10px; border-radius:10px; font-weight:700; "
            f"background:{status_palette['combo_background']}; color:{status_palette['combo_text']}; "
            f"border:1px solid {status_palette['combo_border']};"
        )
        top_row.addWidget(status_badge, 0, Qt.AlignRight)

        readiness_badge = QLabel(
            {
                "ready": "Ready",
                "requires_review": "Review Required",
                "hold": "Hold",
            }.get(readiness, "Hold")
        )
        readiness_badge.setStyleSheet(
            "padding:4px 10px; border-radius:10px; font-weight:700; "
            f"background:{ready_bg}; color:{ready_text}; border:1px solid {ready_border};"
        )
        top_row.addWidget(readiness_badge, 0, Qt.AlignRight)
        layout.addLayout(top_row)

        meta_text = (
            f"Updated {self._format_library_timestamp(record.get('updated_at'))} | "
            f"{'Patient Packet' if completion.get('group_name') == 'patient_packet' else 'Referral Request'} | "
            f"Prod Score {int(round(metrics.get('score') or 0))}"
        )
        if is_current:
            meta_text += " | Current Draft"
        meta_label = QLabel(meta_text)
        meta_label.setWordWrap(True)
        meta_label.setStyleSheet("color:#8FA6C1;")
        layout.addWidget(meta_label)

        blocker = str(metrics.get("main_blocker") or "").strip()
        summary_label = QLabel(
            blocker
            or "This draft does not currently show a blocking paperwork issue."
        )
        summary_label.setWordWrap(True)
        summary_label.setStyleSheet("color:#DDE8F5;")
        layout.addWidget(summary_label)

        action_row = QHBoxLayout()
        action_row.setContentsMargins(0, 0, 0, 0)
        action_row.setSpacing(8)
        resume_button = QPushButton("Resume")
        self._style_library_button(resume_button)
        resume_button.clicked.connect(lambda _=False, draft_id=record.get("draft_id"): self.load_library_draft(draft_id))
        pdf_button = QPushButton("Open PDF")
        self._style_library_button(pdf_button)
        pdf_button.clicked.connect(lambda _=False, draft_id=record.get("draft_id"): self.open_library_pdf(draft_id))
        folder_button = QPushButton("Open Folder")
        self._style_library_button(folder_button)
        folder_button.clicked.connect(lambda _=False, draft_id=record.get("draft_id"): self.open_library_folder(draft_id))
        delete_button = QPushButton("Delete")
        self._style_library_button(delete_button, destructive=True)
        delete_button.clicked.connect(lambda _=False, draft_id=record.get("draft_id"): self.delete_library_draft(draft_id))
        for button in (resume_button, pdf_button, folder_button, delete_button):
            action_row.addWidget(button)
        action_row.addStretch(1)
        layout.addLayout(action_row)
        return frame

    def refresh_library(self):
        if not hasattr(self, "library_list"):
            return
        self.library_list.clear()
        records = self._list_packet_library_records_fn()
        if not records:
            empty_item = QListWidgetItem()
            empty_widget = QLabel(
                "No saved packet drafts yet. Use Save To Library after you start a packet, and it will appear here."
            )
            empty_widget.setWordWrap(True)
            empty_widget.setStyleSheet("color:#8FA6C1; padding:14px;")
            empty_item.setSizeHint(empty_widget.sizeHint())
            self.library_list.addItem(empty_item)
            self.library_list.setItemWidget(empty_item, empty_widget)
            return
        for record in records:
            item = QListWidgetItem()
            widget = self._build_library_row(record)
            item.setSizeHint(widget.sizeHint())
            self.library_list.addItem(item)
            self.library_list.setItemWidget(item, widget)

    def load_library_draft(self, draft_id):
        record = next((item for item in self._list_packet_library_records_fn() if item.get("draft_id") == draft_id), None)
        if not record:
            QMessageBox.information(self, "Draft Not Found", "That packet draft could not be found in the library.")
            self.refresh_library()
            return
        self.current_draft_id = record.get("draft_id")
        self.current_draft_record = dict(record)
        self._apply_payload_to_widgets(record.get("payload") or {}, record.get("base_filename"))
        self.preview_tabs.setCurrentIndex(0)
        if hasattr(self, "packet_builder_left_tabs"):
            self.packet_builder_left_tabs.setCurrentWidget(self.packet_workspace_page)
        self.refresh_library()
        self._update_current_packet_status()

    def open_library_pdf(self, draft_id):
        record = next((item for item in self._list_packet_library_records_fn() if item.get("draft_id") == draft_id), None)
        pdf_path = self._preferred_pdf_path_for_record(record or {})
        if pdf_path:
            os.startfile(pdf_path)
            return
        QMessageBox.information(
            self,
            "No PDF Yet",
            "This draft does not have a saved PDF yet. Export a PDF first, then reopen it from the library.",
        )

    def open_library_folder(self, draft_id):
        record = next((item for item in self._list_packet_library_records_fn() if item.get("draft_id") == draft_id), None)
        folder_path = self._artifact_folder_for_record(record or {})
        if folder_path and os.path.isdir(folder_path):
            os.startfile(folder_path)
            return
        QMessageBox.information(self, "No Export Folder Yet", "This draft does not have an export folder yet.")

    def delete_library_draft(self, draft_id):
        reply = QMessageBox.question(
            self,
            "Delete Saved Draft",
            "Remove this saved draft from the Packet Library? Exported files on disk will be left alone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self._delete_packet_library_record_fn(draft_id)
        if draft_id == self.current_draft_id:
            self.current_draft_id = None
            self.current_draft_record = {}
        self.refresh_library()
        self._update_current_packet_status()
