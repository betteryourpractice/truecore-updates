from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTextEdit,
    QFrame,
    QFileDialog,
    QInputDialog,
    QDialog,
    QMessageBox,
    QLineEdit,
    QTableWidgetItem,
    QHeaderView,
    QGraphicsOpacityEffect
)

from PySide6.QtGui import QIcon, QColor, QPixmap, QFont
from PySide6.QtCore import Qt, QSize, QTimer, QObject, QThread, Signal

import os
import csv
import html
import json
import re
from datetime import datetime

from TrueCore.utils.logging_system import LOG_FILE, LEGACY_LOG_FILE, log_event, mask_phi
from TrueCore.utils.admin_auth import ensure_admin_auth_config, verify_admin_password
from TrueCore.utils.runtime_info import (
    ensure_runtime_environment,
    get_version,
    get_build_info,
    resource_path
    
)

from TrueCore.core.packet_processor import process_packet
from TrueCore.core.packet_triage import triage_packet
from TrueCore.core.host_intelligence import record_manual_outcome
from TrueCore.core.case_memory import (
    get_recent_packet_events,
    get_recent_packet_runs,
    memory_totals,
    parse_intel_summary,
)
from TrueCore.export.workbook_export import export_patient
from TrueCore.medical.icd_lookup import load_icd_codes


def build_processing_error_result(file_path, error_text):

    return {
        "_processing_error": True,
        "file": file_path,
        "score": 0,
        "fields": {},
        "forms": [],
        "issues": [f"Packet processing failed: {error_text}"],
        "fixes": ["Retry packet analysis after reviewing the packet and logs."],
        "intel": {
            "display": {
                "packet_strength": "error",
                "submission_readiness": "needs_review",
                "review_priority": "high",
                "denial_risk": "high",
                "workflow_queue": "review_queue",
                "next_action": "retry_analysis",
                "issue_details": [f"Packet processing failed: {error_text}"],
                "priority_fixes": ["Retry packet analysis after reviewing the packet and logs."],
                "review_rationale": ["The packet could not be fully analyzed."],
                "review_flags": ["manual_review_required"],
            }
        },
    }


class PacketAnalysisWorker(QObject):

    packet_started = Signal(int, int, str)
    packet_finished = Signal(int, str, object)
    finished = Signal()

    def __init__(self, files):
        super().__init__()
        self.files = list(files or [])

    def run(self):

        total = len(self.files)

        for index, file_path in enumerate(self.files, start=1):
            basename = os.path.basename(file_path)
            self.packet_started.emit(index, total, basename)

            try:
                result = process_packet(file_path)
            except Exception as exc:
                error_text = str(exc)
                log_event("packet_processing_error", f"{basename} | {error_text}")
                result = build_processing_error_result(file_path, error_text)

            self.packet_finished.emit(index, file_path, result)

        self.finished.emit()


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        ensure_runtime_environment()
        ensure_admin_auth_config()

        self.version = get_version()
        _, self.build_timestamp = get_build_info()

        self.setWindowTitle(f"TrueValour Packet Auditor v{self.version}")
        self.resize(1400, 900)
        self.showFullScreen()

        icon_base = resource_path("ui/pyside_gui/assets/icons/")

        self.files = []
        self.results = {}
        self.scan_diagnostics_dialog = None
        self.scan_diagnostics_view = None
        self.analysis_thread = None
        self.analysis_worker = None

        load_icd_codes()

        # -------------------------------------------------
        # ROOT
        # -------------------------------------------------

        root = QWidget()
        self.setCentralWidget(root)

        root_layout = QVBoxLayout()
        root_layout.setContentsMargins(20,20,20,20)
        root_layout.setSpacing(16)

        root.setLayout(root_layout)

        # ---------------------------------
        # BACKGROUND WATERMARK
        # ---------------------------------

        self.bg_logo = QLabel(root)
        self.bg_logo.setAlignment(Qt.AlignCenter)
        self.bg_logo.setGeometry(self.rect())

        logo_path = resource_path("ui/pyside_gui/assets/launcher_background.png")

        self.bg_pix = QPixmap(logo_path)
        self.bg_logo.setPixmap(self.bg_pix)

        if self.bg_pix.isNull():
            print("Watermark logo failed to load:", logo_path)

        opacity = QGraphicsOpacityEffect()
        opacity.setOpacity(0.08)
        self.bg_logo.setGraphicsEffect(opacity)

        self.bg_logo.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.bg_logo.lower()

        # DeLay background scaling until window finishes rendering
        QTimer.singleShot(0, self.update_background)


        # -------------------------------------------------
        # HEADER
        # -------------------------------------------------

        header = QFrame()
        header.setObjectName("headerPanel")

        header_layout = QHBoxLayout()

        title_block = QVBoxLayout()

        title = QLabel("TRUEVALOUR PACKET AUDITOR")
        title.setObjectName("appTitle")

        subtitle = QLabel(f"Powered by TrueCore Engine v{self.version}")
        subtitle.setObjectName("appSubtitle")

        title_block.addWidget(title)
        title_block.addWidget(subtitle)

        header_layout.addLayout(title_block)
        header_layout.addStretch()

        self.btn_admin = QPushButton(
            QIcon(icon_base + "settings.svg"),
            "Admin"
        )
        self.btn_scan_diagnostics = QPushButton(
            QIcon(icon_base + "search.svg"),
            "Scan Diagnostics"
        )
        self.btn_scan_diagnostics.setEnabled(False)
        self.btn_record_outcome = QPushButton(
            QIcon(icon_base + "file-text.svg"),
            "Record Outcome"
        )
        self.btn_record_outcome.setEnabled(False)

        self.btn_close = QPushButton("Exit")
        self.btn_close.setObjectName("closeButton")

        header_layout.addWidget(self.btn_scan_diagnostics)
        header_layout.addWidget(self.btn_record_outcome)
        header_layout.addWidget(self.btn_admin)
        header_layout.addWidget(self.btn_close)

        header.setLayout(header_layout)

        root_layout.addWidget(header)

        # -------------------------------------------------
        # TOOLBAR
        # -------------------------------------------------

        toolbar = QHBoxLayout()
        toolbar.setSpacing(12)

        self.btn_select = QPushButton(
            QIcon(icon_base + "folder.svg"),
            "Select Files"
        )

        self.btn_analyze = QPushButton(
            QIcon(icon_base + "search.svg"),
            "Analyze Packets"
        )

        self.btn_folder = QPushButton(
            QIcon(icon_base + "folder-open.svg"),
            "Analyze Folder"
        )

        self.btn_export = QPushButton(
            QIcon(icon_base + "file-text.svg"),
            "Export Report"
        )

        self.btn_clear = QPushButton(
            QIcon(icon_base + "trash.svg"),
            "Clear Results"
        )

        for btn in [
            self.btn_select,
            self.btn_analyze,
            self.btn_folder,
            self.btn_export,
            self.btn_clear,
            self.btn_scan_diagnostics,
            self.btn_record_outcome,
            self.btn_admin
        ]:
            btn.setIconSize(QSize(18,18))

        toolbar.addWidget(self.btn_select,1)
        toolbar.addWidget(self.btn_analyze,1)
        toolbar.addWidget(self.btn_folder,1)
        toolbar.addWidget(self.btn_export,1)
        toolbar.addWidget(self.btn_clear,1)

        self.btn_admin.setFixedWidth(self.btn_clear.sizeHint().width())

        root_layout.addLayout(toolbar)

        # -------------------------------------------------
        # BODY
        # -------------------------------------------------

        body = QHBoxLayout()
        body.setSpacing(16)
        root_layout.addLayout(body)

        left = QVBoxLayout()
        left.setSpacing(16)
        body.addLayout(left,2)

        right = QVBoxLayout()
        body.addLayout(right,3)

        # -------------------------------------------------
        # RESULTS PANEL
        # -------------------------------------------------

        results_panel = QFrame()
        results_panel.setObjectName("panel")

        results_layout = QVBoxLayout()

        title = QLabel("Packet Results")
        title.setObjectName("sectionTitle")

        results_layout.addWidget(title)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["File","Score","Status"])

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)

        self.table.itemSelectionChanged.connect(self.load_packet_details)

        results_layout.addWidget(self.table)

        results_panel.setLayout(results_layout)
        left.addWidget(results_panel)

        # -------------------------------------------------
        # CONSOLE
        # -------------------------------------------------

        console_panel = QFrame()
        console_panel.setObjectName("panel")

        console_layout = QVBoxLayout()

        console_title = QLabel("Audit Console")
        console_title.setObjectName("sectionTitle")

        console_layout.addWidget(console_title)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 10))

        console_layout.addWidget(self.console)

        console_panel.setLayout(console_layout)
        left.addWidget(console_panel)

        # -------------------------------------------------
        # DETAILS PANEL
        # -------------------------------------------------

        details_panel = QFrame()
        details_panel.setObjectName("panel")

        details_layout = QVBoxLayout()

        details_title = QLabel("Packet Details")
        details_title.setObjectName("sectionTitle")

        details_layout.addWidget(details_title)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setFont(QFont("Segoe UI", 10))

        details_layout.addWidget(self.details)

        details_panel.setLayout(details_layout)
        right.addWidget(details_panel)

        # -------------------------------------------------
        # BUTTON CONNECTIONS
        # -------------------------------------------------

        self.btn_select.clicked.connect(self.select_files)
        self.btn_analyze.clicked.connect(self.analyze_packets)
        self.btn_folder.clicked.connect(self.analyze_folder)
        self.btn_export.clicked.connect(self.export_report)
        self.btn_clear.clicked.connect(self.clear_results)
        self.btn_scan_diagnostics.clicked.connect(self.open_scan_diagnostics)
        self.btn_record_outcome.clicked.connect(self.open_record_outcome)
        self.btn_admin.clicked.connect(self.open_admin_panel)
        self.btn_close.clicked.connect(self.close)


    # ----------------------------------------------
    # RESIZE EVENT
    # ----------------------------------------------

    def resizeEvent(self, event):

        super().resizeEvent(event)

        if hasattr(self, "bg_logo"):

            self.bg_logo.setGeometry(self.centralWidget().rect())

        if hasattr(self, "update_background"):

            self.update_background()

    def closeEvent(self, event):

        if self.analysis_thread and self.analysis_thread.isRunning():
            QMessageBox.information(
                self,
                "Analysis Running",
                "Please wait for packet analysis to finish before exiting.",
            )
            event.ignore()
            return

        super().closeEvent(event)
    
    # ----------------------------------------------
    # BACKGROUND UPDATE
    # ----------------------------------------------

    def update_background(self):

        if hasattr(self, "bg_logo") and hasattr(self, "bg_pix"):

            if not self.bg_pix.isNull():

                scaled = self.bg_pix.scaled(
                    self.bg_logo.size(),
                    Qt.KeepAspectRatioByExpanding,
                    Qt.SmoothTransformation
                )

                self.bg_logo.setPixmap(scaled)

    def set_analysis_controls_enabled(self, enabled):

        for button in [
            self.btn_select,
            self.btn_analyze,
            self.btn_folder,
            self.btn_export,
            self.btn_clear,
            self.btn_admin,
        ]:
            button.setEnabled(enabled)

    def append_analysis_result_row(self, file, result):

        icon_base = resource_path("ui/pyside_gui/assets/icons/")
        basename = os.path.basename(file)
        score = result.get("score", 0)
        intel_display = result.get("intel", {}).get("display", {})
        workbook_summary = self.build_export_summary(result)
        workbook_summary.update({
            "packet_confidence": intel_display.get("packet_confidence"),
            "approval_probability": intel_display.get("approval_probability"),
            "submission_readiness": intel_display.get("submission_readiness"),
            "workflow_queue": intel_display.get("workflow_queue"),
            "next_action": intel_display.get("next_action"),
            "denial_risk": intel_display.get("denial_risk"),
        })

        self.results[file] = result

        row = self.table.rowCount()
        self.table.insertRow(row)

        file_item = QTableWidgetItem(basename)
        file_item.setIcon(QIcon(icon_base + "folder.svg"))
        self.table.setItem(row, 0, file_item)

        score_item = QTableWidgetItem(str(score))
        score_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 1, score_item)

        status = QTableWidgetItem()

        if result.get("_processing_error"):
            status.setText("Error")
            status.setIcon(QIcon(icon_base + "error.svg"))
            status.setForeground(QColor("#EB5757"))
            issue_text = (result.get("issues") or ["Packet processing failed."])[0]
            self.log(f"Packet processing failed for {basename}: {issue_text}")
        elif score >= 90:
            status.setText("Approved")
            status.setIcon(QIcon(icon_base + "check.svg"))
            status.setForeground(QColor("#27AE60"))
            export_patient(result.get("fields", {}), file, workbook_summary)
            self.log(
                f"Approved packet exported → {basename}",
                action="packet_processed"
            )
        elif score >= 70:
            status.setText("Needs Review")
            status.setIcon(QIcon(icon_base + "warning.svg"))
            status.setForeground(QColor("#F2C94C"))
        else:
            status.setText("Rejected")
            status.setIcon(QIcon(icon_base + "error.svg"))
            status.setForeground(QColor("#EB5757"))

        self.table.setItem(row, 2, status)

        if not result.get("_processing_error"):
            triage_packet(file, score, result=result)

        if row == 0:
            self.table.selectRow(0)
            self.load_packet_details()

    def on_analysis_packet_started(self, index, total, basename):

        self.log(f"Analyzing {index}/{total}: {basename}")

    def on_analysis_packet_finished(self, index, file_path, result):

        self.append_analysis_result_row(file_path, result)

    def on_analysis_finished(self):

        self.set_analysis_controls_enabled(True)

        if self.table.rowCount() > 0 and self.table.currentRow() < 0:
            self.table.selectRow(0)
            self.load_packet_details()

        self.update_scan_diagnostics_button()
        self.log("Packet analysis complete.")

    def cleanup_analysis_thread(self):

        self.analysis_worker = None
        self.analysis_thread = None

    # -------------------------------------------------
    # UTILITIES
    # -------------------------------------------------

    def log(self,msg, action=None):

        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"

        # GUI console always shows everything
        self.console.append(entry)

        # Only write specific events to activity.log
        if action:
            try:
                log_event(action, msg)
            except Exception:
                pass

    def format_field(self,name):

        return name.replace("_"," ").title()

    def format_detail_value(self, value):

        if value in (None, "", [], {}):
            return "Missing"

        if isinstance(value, bool):
            return "True" if value else "False"

        if isinstance(value, (list, tuple, set)):
            return ", ".join(str(item) for item in value)

        return str(value)

    def format_packet_field_label(self, name):

        mapping = {
            "dob": "DOB",
            "icd_codes": "ICD Codes",
            "va_icn": "VA ICN",
            "npi": "NPI",
        }

        return mapping.get(str(name or "").strip().lower(), self.format_field(str(name or "")))

    def format_packet_display_value(self, label, value):

        if value in (None, "", [], {}):
            return value

        label_text = str(label or "").strip().lower()

        if isinstance(value, bool):
            return "Yes" if value else "No"

        if isinstance(value, (int, float)) and 0 <= float(value) <= 1:
            if "probability" in label_text or "confidence" in label_text or "trust score" in label_text:
                return f"{round(float(value) * 100):.0f}%"

        if isinstance(value, str):
            if label_text in {
                "submission readiness",
                "next action",
                "workflow queue",
                "review priority",
                "packet strength",
                "denial risk",
                "support level",
                "freshness",
                "escalation",
                "coherence",
                "severity",
                "conservative care",
                "specialty alignment",
                "provider history",
                "benchmark standing",
                "pipeline state",
                "reliability",
                "policy confidence",
                "verification band",
            }:
                return self.format_field(value)

        return value

    def format_review_flag(self, flag):

        normalized = str(flag or "").strip().lower()
        mapping = {
            "diagnosis_icd_mismatch": "Diagnosis / ICD mismatch",
        }

        return mapping.get(normalized, self.format_field(normalized))

    def format_document_type_label(self, document_type):

        mapping = {
            "cover_sheet": "Submission Cover Sheet",
            "consent": "Virtual Consent Form",
            "consult_request": "Consultation & Treatment Request",
            "seoc": "SEOC",
            "lomn": "Letter of Medical Necessity",
            "rfs": "VA Form 10-10172",
            "clinical_notes": "Clinical Notes",
            "imaging_report": "MRI / Imaging Report",
            "conservative_care_summary": "Conservative Care Summary",
        }

        normalized = str(document_type or "").strip().lower()
        if not normalized:
            return ""

        return mapping.get(normalized, self.format_field(normalized))

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

    def format_admin_value(self, value, missing="Missing"):

        display_value = self.format_detail_value(value)

        if display_value == "Missing":
            return missing

        return mask_phi(display_value)

    def format_runtime_value(self, value):

        if value in (None, "", [], {}):
            return "—"

        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            return str(value)

        if numeric_value < 1:
            return f"{numeric_value:.2f}s"

        return f"{numeric_value:.1f}s"

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

    def intel_payload(self, result):

        return result.get("intel", {}) if isinstance(result, dict) else {}

    def get_nested_value(self, data, *keys, default=None):

        current = data

        for key in keys:
            if not isinstance(current, dict):
                return default

            current = current.get(key)

            if current is None:
                return default

        return current

    def build_advanced_intel_sections(self, result):

        intel = self.intel_payload(result)

        evidence = intel.get("evidence_intelligence", {}) or {}
        clinical = intel.get("clinical_intelligence", {}) or {}
        denial = intel.get("denial_intelligence", {}) or {}
        human_loop = intel.get("human_in_the_loop_intelligence", {}) or {}
        memory = intel.get("memory_intelligence", {}) or {}
        triage = intel.get("triage_intelligence", {}) or {}
        operator = intel.get("operator_intelligence", {}) or {}
        learning = intel.get("learning_intelligence", {}) or {}
        insight = intel.get("insight_intelligence", {}) or {}
        benchmark = intel.get("benchmark_intelligence", {}) or {}
        orchestration = intel.get("orchestration_intelligence", {}) or {}
        architecture = intel.get("architecture_intelligence", {}) or {}
        recovery = intel.get("recovery_intelligence", {}) or {}
        policy = intel.get("policy_intelligence", {}) or {}
        deployment = intel.get("deployment_intelligence", {}) or {}
        validation = intel.get("validation_intelligence", {}) or {}

        sections = []

        evidence_rows = [
            ("Sufficiency", self.get_nested_value(evidence, "evidence_sufficiency_modeling", "status")),
            ("Support Level", self.get_nested_value(evidence, "evidence_sufficiency_modeling", "support_level")),
            ("Freshness", self.get_nested_value(evidence, "evidence_freshness_validation", "status")),
            ("Escalation", self.get_nested_value(evidence, "evidence_escalation_recommendation", "level")),
            ("Evidence Score", self.get_nested_value(evidence, "evidence_sufficiency_modeling", "score")),
        ]

        if any(value not in (None, "", [], {}) for _, value in evidence_rows):
            sections.append(
                self.build_detail_card(
                    "Evidence Intelligence",
                    self.build_detail_table(evidence_rows, value_color="#57B6FF", show_missing=False),
                    accent_color="#57B6FF",
                )
            )

        evidence_actions = self.get_nested_value(evidence, "evidence_escalation_recommendation", "recommendations", default=[])
        if evidence_actions:
            sections.append(
                self.build_bullet_section(
                    "Evidence Actions",
                    evidence_actions[:5],
                    color="#57B6FF",
                    accent_color="#57B6FF",
                )
            )

        clinical_rows = [
            ("Coherence Score", self.get_nested_value(clinical, "clinical_coherence_scoring", "score")),
            ("Coherence Band", self.get_nested_value(clinical, "clinical_coherence_scoring", "band")),
            ("Consistency", self.get_nested_value(clinical, "clinical_consistency_analysis", "status")),
            ("Severity", self.get_nested_value(clinical, "severity_inference_engine", "level")),
            ("Conservative Care", self.get_nested_value(clinical, "conservative_care_verification", "status")),
            ("Specialty Alignment", self.get_nested_value(clinical, "specialty_alignment_validation", "status")),
        ]

        if any(value not in (None, "", [], {}) for _, value in clinical_rows):
            sections.append(
                self.build_detail_card(
                    "Clinical Intelligence",
                    self.build_detail_table(clinical_rows, value_color="#57B6FF", show_missing=False),
                    accent_color="#57B6FF",
                )
            )

        clinical_gaps = self.get_nested_value(clinical, "clinical_gap_detection", "gaps", default=[])
        if clinical_gaps:
            sections.append(
                self.build_bullet_section(
                    "Clinical Gaps",
                    clinical_gaps[:5],
                    color="#EB5757",
                    accent_color="#EB5757",
                )
            )

        denial_rows = [
            ("Primary Category", self.get_nested_value(denial, "denial_taxonomy_engine", "primary_category")),
            ("Appeal Disposition", self.get_nested_value(denial, "appeal_opportunity_detection", "disposition")),
            ("Recovery Score", self.get_nested_value(denial, "failure_recovery_scoring", "score")),
            ("Recovery Band", self.get_nested_value(denial, "failure_recovery_scoring", "band")),
        ]

        if any(value not in (None, "", [], {}) for _, value in denial_rows):
            sections.append(
                self.build_detail_card(
                    "Denial Intelligence",
                    self.build_detail_table(denial_rows, value_color="#F2994A", show_missing=False),
                    accent_color="#F2994A",
                )
            )

        denial_actions = self.get_nested_value(denial, "countermeasure_recommendation_engine", "recommended_actions", default=[])
        if denial_actions:
            sections.append(
                self.build_bullet_section(
                    "Denial Countermeasures",
                    denial_actions[:5],
                    color="#F2994A",
                    accent_color="#F2994A",
                )
            )

        human_rows = [
            ("Trust Score", self.get_nested_value(human_loop, "trust_score_modeling", "trust_score")),
            ("Trust Band", self.get_nested_value(human_loop, "trust_score_modeling", "band")),
            ("Threshold", self.get_nested_value(human_loop, "review_threshold_engine", "status")),
            ("Gate Open", self.get_nested_value(human_loop, "confidence_gated_automation", "gate_open")),
            ("Checkpoint Required", self.get_nested_value(human_loop, "approval_checkpoint_layer", "checkpoint_required")),
        ]

        if any(value not in (None, "", [], {}) for _, value in human_rows):
            sections.append(
                self.build_detail_card(
                    "Human-In-The-Loop",
                    self.build_detail_table(human_rows, value_color="#F2C94C", show_missing=False),
                    accent_color="#F2C94C",
                )
            )

        human_points = self.get_nested_value(human_loop, "reviewer_attention_guidance", "attention_points", default=[])
        if human_points:
            sections.append(
                self.build_bullet_section(
                    "Reviewer Attention Guidance",
                    human_points[:5],
                    color="#F2C94C",
                    accent_color="#F2C94C",
                )
            )

        memory_rows = [
            ("Prior Cases", self.get_nested_value(memory, "persistent_case_memory", "prior_case_count")),
            ("Last Status", self.get_nested_value(memory, "persistent_case_memory", "last_status")),
            ("Last Score", self.get_nested_value(memory, "persistent_case_memory", "last_score")),
            ("Memory Confidence", self.get_nested_value(memory, "memory_confidence_scoring", "score")),
            ("Memory Band", self.get_nested_value(memory, "memory_confidence_scoring", "band")),
            ("Risk Drift", self.get_nested_value(memory, "longitudinal_risk_drift_tracking", "direction")),
            ("Provider Quality", self.get_nested_value(memory, "provider_relationship_memory", "quality_trend")),
            ("Provider Packet Count", self.get_nested_value(memory, "provider_relationship_memory", "packet_count")),
        ]

        if any(value not in (None, "", [], {}) for _, value in memory_rows):
            sections.append(
                self.build_detail_card(
                    "Case Memory",
                    self.build_detail_table(memory_rows, value_color="#9B8CFF", show_missing=False),
                    accent_color="#9B8CFF",
                )
            )

        recurring_issues = self.get_nested_value(memory, "recurring_deficiency_detection", "recurring_issues", default=[])
        if recurring_issues:
            sections.append(
                self.build_bullet_section(
                    "Recurring Deficiencies",
                    recurring_issues[:5],
                    color="#EB5757",
                    accent_color="#EB5757",
                )
            )

        carryover_context = self.get_nested_value(memory, "context_carryover_engine", "carryover_context", default=[])
        if carryover_context:
            sections.append(
                self.build_bullet_section(
                    "Context Carryover",
                    carryover_context[:5],
                    color="#9B8CFF",
                    accent_color="#9B8CFF",
                )
            )

        similar_cases = self.get_nested_value(memory, "similar_case_recall", default=[])
        if similar_cases:
            similar_case_items = [
                f"{item.get('file_name')} | similarity {item.get('similarity_score')} | "
                f"status {item.get('status')} | score {item.get('score')}"
                for item in similar_cases[:4]
            ]
            sections.append(
                self.build_bullet_section(
                    "Similar Case Recall",
                    similar_case_items,
                    color="#9B8CFF",
                    accent_color="#9B8CFF",
                )
            )

        triage_rows = [
            ("Priority", triage.get("priority_level")),
            ("Urgency", triage.get("urgency_classification")),
            ("Review Depth", triage.get("review_depth_allocation")),
            ("Time To Action", triage.get("time_to_action_scoring")),
            ("Staff Route", triage.get("staff_match_routing")),
            ("Queue Risk", triage.get("queue_risk_forecasting")),
            ("Triage Confidence", triage.get("triage_confidence_scoring")),
            ("Deferral Safe", triage.get("deferral_safety_check")),
        ]

        if any(value not in (None, "", [], {}) for _, value in triage_rows):
            sections.append(
                self.build_detail_card(
                    "Triage Intelligence",
                    self.build_detail_table(triage_rows, value_color="#56CCF2", show_missing=False),
                    accent_color="#56CCF2",
                )
            )

        triage_focus = triage.get("next_operator_focus", []) or []
        if triage_focus:
            sections.append(
                self.build_bullet_section(
                    "Triage Focus",
                    triage_focus[:5],
                    color="#56CCF2",
                    accent_color="#56CCF2",
                )
            )

        operator_rows = [
            ("Primary Route", self.get_nested_value(operator, "operator_workbench_layer", "primary_route")),
            ("Priority", self.get_nested_value(operator, "operator_workbench_layer", "priority_level")),
            ("Review Depth", self.get_nested_value(operator, "operator_workbench_layer", "review_depth")),
            ("Time To Action", self.get_nested_value(operator, "operator_workbench_layer", "time_to_action")),
            ("Efficiency", self.get_nested_value(operator, "reviewer_efficiency_scoring", "band")),
            ("Efficiency Score", self.get_nested_value(operator, "reviewer_efficiency_scoring", "score")),
        ]

        if any(value not in (None, "", [], {}) for _, value in operator_rows):
            sections.append(
                self.build_detail_card(
                    "Operator Workbench",
                    self.build_detail_table(operator_rows, value_color="#6FCF97", show_missing=False),
                    accent_color="#27AE60",
                )
            )

        operator_checklist = self.get_nested_value(operator, "smart_review_checklist_generation", "checklist", default=[])
        if operator_checklist:
            sections.append(
                self.build_bullet_section(
                    "Operator Checklist",
                    operator_checklist[:6],
                    color="#6FCF97",
                    accent_color="#27AE60",
                )
            )

        productivity_hints = self.get_nested_value(operator, "productivity_hint_engine", "hints", default=[])
        if productivity_hints:
            sections.append(
                self.build_bullet_section(
                    "Productivity Hints",
                    productivity_hints[:5],
                    color="#6FCF97",
                    accent_color="#27AE60",
                )
            )

        operator_feedback = self.get_nested_value(operator, "operator_support_feedback_loop", "suggestions", default=[])
        if operator_feedback:
            sections.append(
                self.build_bullet_section(
                    "Operator Feedback Loop",
                    operator_feedback[:5],
                    color="#6FCF97",
                    accent_color="#27AE60",
                )
            )

        operator_patterns = self.get_nested_value(operator, "work_pattern_analysis", "friction_points", default=[])
        if operator_patterns:
            sections.append(
                self.build_bullet_section(
                    "Operator Friction Points",
                    operator_patterns[:5],
                    color="#6FCF97",
                    accent_color="#27AE60",
                )
            )

        escalation_note = self.get_nested_value(operator, "escalation_note_drafting", "note")
        if escalation_note:
            sections.append(
                self.build_detail_card(
                    "Escalation Note",
                    f"<div style=\"color:#6FCF97;\">{html.escape(str(escalation_note))}</div>",
                    accent_color="#27AE60",
                )
            )

        learning_rows = [
            ("Latest Outcome", self.get_nested_value(learning, "outcome_feedback_ingestion", "latest_outcome")),
            ("Outcome Count", self.get_nested_value(learning, "outcome_feedback_ingestion", "outcome_count")),
            ("Calibration", self.get_nested_value(learning, "confidence_calibration_engine", "status")),
            ("Calibration Delta", self.get_nested_value(learning, "confidence_calibration_engine", "delta")),
            ("Override Status", self.get_nested_value(learning, "reviewer_override_learning", "status")),
            ("Override Rate", self.get_nested_value(learning, "reviewer_override_learning", "override_rate")),
            ("Readiness", self.get_nested_value(learning, "continuous_intelligence_refinement", "readiness_band")),
            ("Readiness Score", self.get_nested_value(learning, "continuous_intelligence_refinement", "readiness_score")),
        ]

        if any(value not in (None, "", [], {}) for _, value in learning_rows):
            sections.append(
                self.build_detail_card(
                    "Learning Intelligence",
                    self.build_detail_table(learning_rows, value_color="#F2994A", show_missing=False),
                    accent_color="#F2994A",
                )
            )

        rule_adjustments = self.get_nested_value(learning, "rule_adjustment_recommendation", "recommendations", default=[])
        if rule_adjustments:
            sections.append(
                self.build_bullet_section(
                    "Rule Adjustment Recommendations",
                    rule_adjustments[:5],
                    color="#F2994A",
                    accent_color="#F2994A",
                )
            )

        learning_safeguards = self.get_nested_value(learning, "failure_to_learning_conversion", "recommended_safeguards", default=[])
        if learning_safeguards:
            sections.append(
                self.build_bullet_section(
                    "Learning Safeguards",
                    learning_safeguards[:5],
                    color="#F2994A",
                    accent_color="#F2994A",
                )
            )

        insight_rows = [
            ("Trend", self.get_nested_value(insight, "hidden_trend_detection", "status")),
            ("Recent Avg Score", self.get_nested_value(insight, "hidden_trend_detection", "recent_average_score")),
            ("Provider Rank", self.get_nested_value(insight, "provider_network_insight_engine", "provider_rank")),
            ("Provider Avg Score", self.get_nested_value(insight, "provider_network_insight_engine", "provider_average_score")),
            ("Variance", self.get_nested_value(insight, "process_variance_detection", "status")),
        ]

        if any(value not in (None, "", [], {}) for _, value in insight_rows):
            sections.append(
                self.build_detail_card(
                    "Insight Intelligence",
                    self.build_detail_table(insight_rows, value_color="#BB6BD9", show_missing=False),
                    accent_color="#BB6BD9",
                )
            )

        strategic_insights = self.get_nested_value(insight, "strategic_insight_summarization", default=[])
        if strategic_insights:
            sections.append(
                self.build_bullet_section(
                    "Insight Summary",
                    strategic_insights[:5],
                    color="#BB6BD9",
                    accent_color="#BB6BD9",
                )
            )

        insight_actions = self.get_nested_value(insight, "insight_action_recommendation", default=[])
        if insight_actions:
            sections.append(
                self.build_bullet_section(
                    "Insight Actions",
                    insight_actions[:5],
                    color="#BB6BD9",
                    accent_color="#BB6BD9",
                )
            )

        benchmark_rows = [
            ("Standing", self.get_nested_value(benchmark, "internal_benchmark_engine", "standing")),
            ("Average Score", self.get_nested_value(benchmark, "internal_benchmark_engine", "average_score")),
            ("Quality Percentile", self.get_nested_value(benchmark, "quality_benchmark_calibration", "score_percentile")),
            ("Benchmark Confidence", self.get_nested_value(benchmark, "benchmark_confidence_scoring", "band")),
            ("Target Score", self.get_nested_value(benchmark, "improvement_target_modeling", "target_score")),
            ("Provider Rank", self.get_nested_value(benchmark, "team_to_team_benchmarking", "provider_rank")),
        ]

        if any(value not in (None, "", [], {}) for _, value in benchmark_rows):
            sections.append(
                self.build_detail_card(
                    "Benchmark Intelligence",
                    self.build_detail_table(benchmark_rows, value_color="#2DCE89", show_missing=False),
                    accent_color="#2DCE89",
                )
            )

        benchmark_targets = self.get_nested_value(benchmark, "improvement_target_modeling", "recommendations", default=[])
        if benchmark_targets:
            sections.append(
                self.build_bullet_section(
                    "Benchmark Targets",
                    benchmark_targets[:5],
                    color="#2DCE89",
                    accent_color="#2DCE89",
                )
            )

        system_rows = [
            ("Pipeline State", self.get_nested_value(orchestration, "pipeline_health_state_machine", "state")),
            ("Coordination Score", self.get_nested_value(orchestration, "end_to_end_coordination_scoring", "score")),
            ("Coordination Band", self.get_nested_value(orchestration, "end_to_end_coordination_scoring", "band")),
            ("Maintainability", self.get_nested_value(architecture, "maintainability_scoring", "band")),
            ("Reliability", self.get_nested_value(recovery, "reliability_scoring", "band")),
            ("Recovery Strategy", self.get_nested_value(recovery, "intelligent_retry_engine", "strategy")),
        ]

        if any(value not in (None, "", [], {}) for _, value in system_rows):
            sections.append(
                self.build_detail_card(
                    "System Intelligence",
                    self.build_detail_table(system_rows, value_color="#6FCF97", show_missing=False),
                    accent_color="#6FCF97",
                )
            )

        policy_rows = [
            ("Policy Confidence", self.get_nested_value(policy, "policy_compliance_confidence", "band")),
            ("Policy Score", self.get_nested_value(policy, "policy_compliance_confidence", "score")),
            ("Forecast Status", self.get_nested_value(policy, "missing_requirement_forecasting", "forecast_status")),
            ("Deployment Confidence", self.get_nested_value(deployment, "deployment_confidence_scoring", "band")),
            ("Deployment Score", self.get_nested_value(deployment, "deployment_confidence_scoring", "score")),
            ("Update Compatibility", self.get_nested_value(deployment, "update_compatibility_analysis", "status")),
        ]

        if any(value not in (None, "", [], {}) for _, value in policy_rows):
            sections.append(
                self.build_detail_card(
                    "Policy & Deployment",
                    self.build_detail_table(policy_rows, value_color="#57B6FF", show_missing=False),
                    accent_color="#57B6FF",
                )
            )

        validation_rows = [
            ("Deep Verification Score", self.get_nested_value(validation, "deep_verification_score", "score")),
            ("Verification Band", self.get_nested_value(validation, "deep_verification_score", "band")),
            ("Verified Claims", self.get_nested_value(validation, "extraction_claim_verification", "verified_claims")),
            ("Weak Claims", self.get_nested_value(validation, "extraction_claim_verification", "weak_claims")),
            ("Date Logic", self.get_nested_value(validation, "date_logic_validation", "status")),
            ("Procedure-Code Check", self.get_nested_value(validation, "procedure_code_consistency_checks", "status")),
        ]

        if any(value not in (None, "", [], {}) for _, value in validation_rows):
            sections.append(
                self.build_detail_card(
                    "Reviewer Verification",
                    self.build_detail_table(validation_rows, value_color="#56CCF2", show_missing=False),
                    accent_color="#56CCF2",
                )
            )

        traceback_items = []
        for item in (self.get_nested_value(validation, "evidence_traceback_links", default=[]) or [])[:8]:
            field_name = self.format_field(item.get("field"))
            support_status = self.format_field(item.get("support_status") or "unknown")
            document_type = self.format_field(item.get("document_type") or "unknown")
            page_number = item.get("page_number") or "?"
            provider = item.get("ocr_provider") or item.get("extraction_strategy") or "native_text"
            value = self.format_detail_value(item.get("value"))
            traceback_items.append(
                f"{field_name}: {value} | {support_status} | {document_type} | page {page_number} | {provider}"
            )

        if traceback_items:
            sections.append(
                self.build_bullet_section(
                    "Source Traceback",
                    traceback_items,
                    color="#56CCF2",
                    accent_color="#56CCF2",
                )
            )

        return sections

    def build_condensed_advanced_intel_sections(self, result):

        intel = self.intel_payload(result)
        evidence = intel.get("evidence_intelligence", {}) or {}
        clinical = intel.get("clinical_intelligence", {}) or {}
        human_loop = intel.get("human_in_the_loop_intelligence", {}) or {}
        memory = intel.get("memory_intelligence", {}) or {}
        triage = intel.get("triage_intelligence", {}) or {}
        insight = intel.get("insight_intelligence", {}) or {}
        benchmark = intel.get("benchmark_intelligence", {}) or {}
        orchestration = intel.get("orchestration_intelligence", {}) or {}
        recovery = intel.get("recovery_intelligence", {}) or {}
        policy = intel.get("policy_intelligence", {}) or {}
        deployment = intel.get("deployment_intelligence", {}) or {}
        validation = intel.get("validation_intelligence", {}) or {}

        sections = []

        evidence_rows = [
            ("Support Level", self.format_packet_display_value("Support Level", self.get_nested_value(evidence, "evidence_sufficiency_modeling", "support_level"))),
            ("Evidence Rating", self.format_evidence_rating(self.get_nested_value(evidence, "evidence_sufficiency_modeling", "score"))),
            ("Freshness", self.format_packet_display_value("Freshness", self.get_nested_value(evidence, "evidence_freshness_validation", "status"))),
            ("Escalation", self.format_packet_display_value("Escalation", self.get_nested_value(evidence, "evidence_escalation_recommendation", "level"))),
        ]
        if any(value not in (None, "", [], {}) for _, value in evidence_rows):
            sections.append(
                self.build_detail_card(
                    "Evidence Intelligence",
                    self.build_detail_table(evidence_rows, value_color="#57B6FF", show_missing=False),
                    accent_color="#57B6FF",
                )
            )

        clinical_rows = [
            ("Coherence", self.format_packet_display_value("Coherence", self.get_nested_value(clinical, "clinical_coherence_scoring", "band"))),
            ("Coherence Score", self.get_nested_value(clinical, "clinical_coherence_scoring", "score")),
            ("Severity", self.format_packet_display_value("Severity", self.get_nested_value(clinical, "severity_inference_engine", "level"))),
            ("Conservative Care", self.format_packet_display_value("Conservative Care", self.get_nested_value(clinical, "conservative_care_verification", "status"))),
            ("Specialty Alignment", self.format_packet_display_value("Specialty Alignment", self.get_nested_value(clinical, "specialty_alignment_validation", "status"))),
        ]
        if any(value not in (None, "", [], {}) for _, value in clinical_rows):
            sections.append(
                self.build_detail_card(
                    "Clinical Intelligence",
                    self.build_detail_table(clinical_rows, value_color="#57B6FF", show_missing=False),
                    accent_color="#57B6FF",
                )
            )

        clinical_gaps = self.get_nested_value(clinical, "clinical_gap_detection", "gaps", default=[])
        if clinical_gaps:
            sections.append(
                self.build_bullet_section(
                    "Clinical Gaps",
                    clinical_gaps[:3],
                    color="#F2C94C",
                    accent_color="#F2994A",
                )
            )

        operations_rows = [
            ("Trust Score", self.format_packet_display_value("Trust Score", self.get_nested_value(human_loop, "trust_score_modeling", "trust_score"))),
            ("Provider History", self.format_packet_display_value("Provider History", self.get_nested_value(memory, "provider_relationship_memory", "quality_trend"))),
            ("Benchmark Standing", self.format_packet_display_value("Benchmark Standing", self.get_nested_value(benchmark, "internal_benchmark_engine", "standing"))),
        ]
        if any(value not in (None, "", [], {}) for _, value in operations_rows):
            sections.append(
                self.build_detail_card(
                    "Operational Snapshot",
                    self.build_detail_table(operations_rows, value_color="#9B8CFF", show_missing=False),
                    accent_color="#9B8CFF",
                )
            )

        insight_actions = self.get_nested_value(insight, "insight_action_recommendation", "actions", default=[])
        if insight_actions:
            sections.append(
                self.build_bullet_section(
                    "Insight Actions",
                    insight_actions[:3],
                    color="#9B8CFF",
                    accent_color="#9B8CFF",
                )
            )

        system_rows = [
            ("Verification Score", self.get_nested_value(validation, "deep_verification_score", "score")),
            ("Verification Band", self.format_packet_display_value("Verification Band", self.get_nested_value(validation, "deep_verification_score", "band"))),
            ("Pipeline State", self.format_packet_display_value("Pipeline State", self.get_nested_value(orchestration, "pipeline_health_state_machine", "state"))),
            ("Reliability", self.format_packet_display_value("Reliability", self.get_nested_value(recovery, "reliability_scoring", "band"))),
            ("Policy Confidence", self.format_packet_display_value("Policy Confidence", self.get_nested_value(policy, "policy_compliance_confidence", "band"))),
        ]
        if any(value not in (None, "", [], {}) for _, value in system_rows):
            sections.append(
                self.build_detail_card(
                    "Review Controls",
                    self.build_detail_table(system_rows, value_color="#56CCF2", show_missing=False),
                    accent_color="#56CCF2",
                )
            )

        concept_links = list(self.get_nested_value(validation, "concept_evidence_tracebacks", default=[]) or [])
        concept_items = []
        for item in concept_links[:4]:
            rendered = self.format_concept_evidence_item(item)
            if rendered:
                concept_items.append(rendered)

        if concept_items:
            sections.append(
                self.build_bullet_section(
                    "Concept Evidence",
                    concept_items,
                    color="#57B6FF",
                    accent_color="#57B6FF",
                )
            )

        traceback_links = list(self.get_nested_value(validation, "evidence_traceback_links", default=[]) or [])
        field_priority = {
            "diagnosis": 0,
            "icd_codes": 1,
            "reason_for_request": 2,
            "ordering_provider": 3,
            "ordering_doctor": 3,
            "provider": 4,
            "authorization_number": 5,
            "va_icn": 6,
            "patient_name": 7,
            "name": 7,
            "dob": 8,
        }
        sorted_traceback_links = sorted(
            traceback_links,
            key=lambda item: (
                field_priority.get(str(item.get("field") or "").strip().lower(), 99),
                item.get("page_number") or 999,
            ),
        )
        seen_fields = set()
        traceback_items = []
        for item in sorted_traceback_links:
            field_key = str(item.get("field") or "").strip().lower()
            if not field_key or field_key in seen_fields:
                continue
            seen_fields.add(field_key)
            field_name = self.format_field(item.get("field"))
            value = self.format_detail_value(item.get("value"))
            document_type = str(item.get("document_type") or "").strip()
            page_number = item.get("page_number") or "?"
            source_role = item.get("source_role")
            metadata_parts = []
            if document_type and document_type.lower() != "unknown":
                metadata_parts.append(self.format_field(document_type))
            if source_role:
                metadata_parts.append(self.format_field(source_role))
            metadata_text = f" | {' | '.join(metadata_parts)}" if metadata_parts else ""
            traceback_items.append(
                f"{field_name}: {value}{metadata_text} | page {page_number}"
            )
            if len(traceback_items) >= 4:
                break

        if traceback_items:
            sections.append(
                self.build_bullet_section(
                    "Source Traceback Highlights",
                    traceback_items,
                    color="#56CCF2",
                    accent_color="#56CCF2",
                )
            )

        return sections

    def build_export_summary(self, result):

        intel = self.intel_payload(result)
        evidence = intel.get("evidence_intelligence", {}) or {}
        clinical = intel.get("clinical_intelligence", {}) or {}
        denial = intel.get("denial_intelligence", {}) or {}
        human_loop = intel.get("human_in_the_loop_intelligence", {}) or {}
        memory = intel.get("memory_intelligence", {}) or {}
        triage = intel.get("triage_intelligence", {}) or {}
        operator = intel.get("operator_intelligence", {}) or {}
        learning = intel.get("learning_intelligence", {}) or {}
        insight = intel.get("insight_intelligence", {}) or {}
        benchmark = intel.get("benchmark_intelligence", {}) or {}
        orchestration = intel.get("orchestration_intelligence", {}) or {}
        recovery = intel.get("recovery_intelligence", {}) or {}
        policy = intel.get("policy_intelligence", {}) or {}
        deployment = intel.get("deployment_intelligence", {}) or {}

        return {
            "evidence_sufficiency": self.get_nested_value(evidence, "evidence_sufficiency_modeling", "status"),
            "evidence_freshness": self.get_nested_value(evidence, "evidence_freshness_validation", "status"),
            "evidence_escalation": self.get_nested_value(evidence, "evidence_escalation_recommendation", "level"),
            "clinical_coherence": self.get_nested_value(clinical, "clinical_coherence_scoring", "band"),
            "clinical_severity": self.get_nested_value(clinical, "severity_inference_engine", "level"),
            "conservative_care": self.get_nested_value(clinical, "conservative_care_verification", "status"),
            "denial_category": self.get_nested_value(denial, "denial_taxonomy_engine", "primary_category"),
            "denial_recovery_score": self.get_nested_value(denial, "failure_recovery_scoring", "score"),
            "trust_score": self.get_nested_value(human_loop, "trust_score_modeling", "trust_score"),
            "checkpoint_required": self.get_nested_value(human_loop, "approval_checkpoint_layer", "checkpoint_required"),
            "prior_case_count": self.get_nested_value(memory, "persistent_case_memory", "prior_case_count"),
            "memory_confidence": self.get_nested_value(memory, "memory_confidence_scoring", "score"),
            "risk_drift": self.get_nested_value(memory, "longitudinal_risk_drift_tracking", "direction"),
            "provider_quality_trend": self.get_nested_value(memory, "provider_relationship_memory", "quality_trend"),
            "triage_priority": triage.get("priority_level"),
            "triage_urgency": triage.get("urgency_classification"),
            "triage_review_depth": triage.get("review_depth_allocation"),
            "triage_staff_route": triage.get("staff_match_routing"),
            "triage_time_to_action": triage.get("time_to_action_scoring"),
            "operator_primary_route": self.get_nested_value(operator, "operator_workbench_layer", "primary_route"),
            "operator_focus": self.get_nested_value(operator, "operator_workbench_layer", "next_operator_focus", default=[]),
            "operator_efficiency": self.get_nested_value(operator, "reviewer_efficiency_scoring", "band"),
            "latest_outcome": self.get_nested_value(learning, "outcome_feedback_ingestion", "latest_outcome"),
            "outcome_count": self.get_nested_value(learning, "outcome_feedback_ingestion", "outcome_count"),
            "calibration_status": self.get_nested_value(learning, "confidence_calibration_engine", "status"),
            "calibration_delta": self.get_nested_value(learning, "confidence_calibration_engine", "delta"),
            "override_status": self.get_nested_value(learning, "reviewer_override_learning", "status"),
            "override_rate": self.get_nested_value(learning, "reviewer_override_learning", "override_rate"),
            "learning_readiness": self.get_nested_value(learning, "continuous_intelligence_refinement", "readiness_band"),
            "learning_readiness_score": self.get_nested_value(learning, "continuous_intelligence_refinement", "readiness_score"),
            "insight_trend": self.get_nested_value(insight, "hidden_trend_detection", "status"),
            "insight_provider_rank": self.get_nested_value(insight, "provider_network_insight_engine", "provider_rank"),
            "insight_top_action": self.get_nested_value(insight, "insight_action_recommendation", default=[]),
            "benchmark_standing": self.get_nested_value(benchmark, "internal_benchmark_engine", "standing"),
            "benchmark_percentile": self.get_nested_value(benchmark, "quality_benchmark_calibration", "score_percentile"),
            "benchmark_target_score": self.get_nested_value(benchmark, "improvement_target_modeling", "target_score"),
            "benchmark_confidence_band": self.get_nested_value(benchmark, "benchmark_confidence_scoring", "band"),
            "coordination_score": self.get_nested_value(orchestration, "end_to_end_coordination_scoring", "score"),
            "reliability_score": self.get_nested_value(recovery, "reliability_scoring", "score"),
            "policy_confidence": self.get_nested_value(policy, "policy_compliance_confidence", "band"),
            "deployment_confidence": self.get_nested_value(deployment, "deployment_confidence_scoring", "band"),
        }

    def current_selected_file(self):

        selected = self.table.currentRow()

        if selected < 0 or selected >= len(self.files):
            return None

        return self.files[selected]

    def current_selected_result(self):

        file_path = self.current_selected_file()

        if not file_path:
            return None, None

        return file_path, self.results.get(file_path)

    def update_scan_diagnostics_button(self):

        _, result = self.current_selected_result()
        diagnostics = ((result or {}).get("intel", {}) or {}).get("scan_diagnostics", {})
        self.btn_scan_diagnostics.setEnabled(bool(diagnostics))
        self.btn_record_outcome.setEnabled(bool(result))

    def build_scan_diagnostics_html(self, file_path, result):

        intel = self.intel_payload(result)
        diagnostics = intel.get("scan_diagnostics", {}) or {}
        summary = diagnostics.get("summary", {}) or {}
        pages = diagnostics.get("pages", []) or []
        ranking = diagnostics.get("source_reliability_ranking", []) or []

        if not diagnostics:
            return (
                "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
                "font-family:'Segoe UI'; font-size:13px; line-height:1.45;\">"
                "<div style=\"color:#9CA3AF;\">No scan diagnostics available for this packet.</div>"
                "</body></html>"
            )

        sections = [
            self.build_detail_card(
                "Packet Scan Summary",
                self.build_detail_table(
                    [
                        ("Packet", os.path.basename(file_path)),
                        ("Extraction Mode", self.format_scan_mode(summary.get("extraction_mode"))),
                        ("OCR Attempted", "Yes" if summary.get("ocr_attempted") else "No"),
                        ("OCR Provider", summary.get("ocr_provider") or "Not used"),
                        ("Provider Chain", ", ".join(summary.get("ocr_provider_chain", []) or []) or "Not used"),
                        ("Available OCR Providers", ", ".join(summary.get("available_ocr_providers", []) or []) or "None"),
                        ("Available PDF Tools", ", ".join(summary.get("available_pdf_tools", []) or []) or "None"),
                        ("Fallback Applied", "Yes" if summary.get("fallback_applied") else "No"),
                        ("Pages", summary.get("page_count")),
                        ("Pages With Native Text", summary.get("pages_with_native_text")),
                        ("Pages With OCR Text", summary.get("pages_with_ocr")),
                        ("Pages With OCR Field Zones", summary.get("pages_with_ocr_field_zones")),
                        ("Pages With Native Field Zones", summary.get("pages_with_native_field_zones")),
                        ("Pages With Field Zones", summary.get("pages_with_field_zones")),
                        ("Pages With Split Segments", summary.get("pages_with_split_segments")),
                        (
                            "Average OCR Confidence",
                            summary.get("average_ocr_confidence")
                            if summary.get("ocr_attempted")
                            else "Not used",
                        ),
                        ("Scan Quality", summary.get("scan_quality_band")),
                        ("Scan Quality Score", summary.get("scan_quality_score")),
                        ("Handwriting Risk", summary.get("handwriting_risk_level")),
                        ("Handwriting Risk Score", summary.get("handwriting_risk_score")),
                        ("Pages With Table Regions", summary.get("pages_with_table_regions")),
                        ("Pages With Signature Regions", summary.get("pages_with_signature_regions")),
                        ("Pages With Handwritten Regions", summary.get("pages_with_handwritten_regions")),
                    ],
                    value_color="#57B6FF",
                    show_missing=False,
                ),
                accent_color="#57B6FF",
                margin_top=0,
            )
        ]

        if ranking:
            ranking_items = [
                f"{item.get('rank')}. {self.format_field(item.get('document_type', 'unknown'))} | "
                f"Reliability {item.get('reliability_score')} ({item.get('reliability_band')}) | "
                f"Confidence {item.get('average_confidence')}"
                for item in ranking
            ]
            sections.append(
                self.build_bullet_section(
                    "Most Reliable Sources",
                    ranking_items,
                    color="#6FCF97",
                    accent_color="#27AE60",
                )
            )

        if pages:
            page_rows = []
            for page in pages:
                page_rows.append(
                    "<tr>"
                    f"<td style=\"color:#FFFFFF; padding:4px 8px;\">{html.escape(str(page.get('page')))}</td>"
                    f"<td style=\"color:#DCE6F2; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('document_type')))}</td>"
                    f"<td style=\"color:#9B8CFF; padding:4px 8px;\">{html.escape(self.format_scan_mode(page.get('text_source')))}</td>"
                    f"<td style=\"color:#57B6FF; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('ocr_provider') or 'Not used'))}</td>"
                    f"<td style=\"color:#57B6FF; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('ocr_confidence') if page.get('ocr_confidence') is not None else 'Not used'))}</td>"
                    f"<td style=\"color:#56CCF2; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('classification_confidence')))}</td>"
                    f"<td style=\"color:#DCE6F2; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('scan_quality')))}</td>"
                    f"<td style=\"color:#F2C94C; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('handwriting_risk')))}</td>"
                    f"<td style=\"color:#6FCF97; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('field_zone_count')))}</td>"
                    f"<td style=\"color:#57B6FF; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('ocr_field_zone_count')))}</td>"
                    f"<td style=\"color:#6FCF97; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('native_field_zone_count')))}</td>"
                    f"<td style=\"color:#DCE6F2; padding:4px 8px;\">{html.escape(self.format_detail_value(page.get('split_segment_count')))}</td>"
                    "</tr>"
                )

            page_table = (
                "<table width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"border-collapse:collapse;\">"
                "<tr>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Page</td>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Document</td>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Read Mode</td>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Provider</td>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">OCR</td>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Classify</td>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Scan Quality</td>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Handwriting</td>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Field Zones</td>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">OCR Zones</td>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Native Zones</td>"
                "<td style=\"color:#FFFFFF; font-weight:700; padding:4px 8px;\">Segments</td>"
                "</tr>"
                + "".join(page_rows) +
                "</table>"
            )

            sections.append(
                self.build_detail_card(
                    "Page Diagnostics",
                    page_table,
                    accent_color="#57B6FF",
                )
            )

        rendered_sections = "".join(section for section in sections if section)

        return (
            "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
            "font-family:'Segoe UI'; font-size:13px; line-height:1.45;\">"
            f"{rendered_sections}</body></html>"
        )

    def refresh_scan_diagnostics_dialog(self):

        if not self.scan_diagnostics_dialog or not self.scan_diagnostics_view:
            return

        file_path, result = self.current_selected_result()

        if not file_path or not result:
            self.scan_diagnostics_view.setHtml(
                "<html><body style=\"background-color:#11161E; color:#E5E7EB; font-family:'Segoe UI'; "
                "font-size:13px; line-height:1.45;\"><div style=\"color:#9CA3AF;\">Select a packet result to view scan diagnostics.</div></body></html>"
            )
            return

        self.scan_diagnostics_dialog.setWindowTitle(
            f"Scan Diagnostics - {os.path.basename(file_path)}"
        )
        self.scan_diagnostics_view.setHtml(
            self.build_scan_diagnostics_html(file_path, result)
        )

    def open_scan_diagnostics(self):

        file_path, result = self.current_selected_result()

        if not file_path or not result:
            QMessageBox.information(self, "Scan Diagnostics", "Select a packet result first.")
            return

        if self.scan_diagnostics_dialog is None:
            dialog = QDialog(self)
            dialog.setWindowTitle("Scan Diagnostics")
            dialog.resize(980, 720)

            layout = QVBoxLayout()

            view = QTextEdit()
            view.setReadOnly(True)
            view.setFont(QFont("Segoe UI", 10))

            layout.addWidget(view)
            dialog.setLayout(layout)

            self.scan_diagnostics_dialog = dialog
            self.scan_diagnostics_view = view

        self.refresh_scan_diagnostics_dialog()
        self.scan_diagnostics_dialog.show()
        self.scan_diagnostics_dialog.raise_()
        self.scan_diagnostics_dialog.activateWindow()

    def open_record_outcome(self):

        file_path, result = self.current_selected_result()

        if not file_path or not result:
            QMessageBox.information(self, "Record Outcome", "Select a packet result first.")
            return

        options = [
            "Approved",
            "Denied",
            "Corrected",
            "Resubmitted",
            "Reviewer Override",
            "Deferred",
        ]

        outcome, ok = QInputDialog.getItem(
            self,
            "Record Outcome",
            "Select packet outcome:",
            options,
            0,
            False,
        )

        if not ok or not outcome:
            return

        note, _ = QInputDialog.getMultiLineText(
            self,
            "Record Outcome",
            "Optional note:",
        )

        updated_result = record_manual_outcome(file_path, result, outcome, note=note)
        self.results[file_path] = updated_result
        self.details.setHtml(self.build_packet_details_html(file_path, updated_result))
        self.update_scan_diagnostics_button()

        if self.scan_diagnostics_dialog and self.scan_diagnostics_dialog.isVisible():
            self.refresh_scan_diagnostics_dialog()

        self.log(f"Recorded outcome for {os.path.basename(file_path)}: {outcome}")
        QMessageBox.information(self, "Record Outcome", f"Saved outcome: {outcome}")

    def build_packet_details_html_condensed(self, file, result):

        score = result.get("score", 0)
        forms = result.get("forms", [])
        fields = result.get("fields", {})
        issues = result.get("issues", [])
        fixes = result.get("fixes", [])
        intel_display = result.get("intel", {}).get("display", {})
        issue_items = intel_display.get("issue_details") or issues
        issue_groups = intel_display.get("issue_breakdowns") or [{"title": item, "details": []} for item in issue_items]
        fix_items = intel_display.get("priority_fixes") or fixes
        review_rationale = (
            intel_display.get("review_rationale")
            or intel_display.get("why_weak")
            or intel_display.get("approval_rationale")
            or []
        )
        review_rationale = self.polish_review_rationale(review_rationale, max_items=5)
        issue_palette = self.get_issue_display_palette(intel_display)

        score_color = "#27AE60" if score >= 90 else "#F2C94C" if score >= 70 else "#EB5757"

        summary_rows = [
            ("Packet", os.path.basename(file)),
            ("Score", score),
        ]
        decision_rows = []

        if intel_display:
            summary_rows.extend(
                [
                    ("Packet Strength", intel_display.get("packet_strength")),
                    ("Submission Readiness", intel_display.get("submission_readiness")),
                    ("Approval Probability", intel_display.get("approval_probability")),
                    ("Next Action", intel_display.get("next_action")),
                ]
            )
            decision_rows = [
                ("Packet Confidence", intel_display.get("packet_confidence")),
                ("Denial Risk", intel_display.get("denial_risk")),
                ("Workflow Queue", intel_display.get("workflow_queue")),
                ("Review Priority", intel_display.get("review_priority")),
            ]

        sections = [
            self.build_detail_card(
                "Packet Summary",
                self.build_detail_table(summary_rows, value_color="#57B6FF", show_missing=False),
                accent_color="#57B6FF",
                margin_top=0,
            ),
        ]

        if any(value not in (None, "", [], {}) for _, value in decision_rows):
            sections.append(
                self.build_detail_card(
                    "Decision Snapshot",
                    self.build_detail_table(decision_rows, value_color="#57B6FF", show_missing=False),
                    accent_color="#57B6FF",
                )
            )

        sections.extend(
            [
                self.build_bullet_section(
                    "Forms Detected",
                    forms,
                    color="#6FCF97",
                    accent_color="#27AE60",
                    bullet="✓",
                ),
                self.build_detail_card(
                    "Fields",
                    self.build_detail_table(
                        [(self.format_field(key), value) for key, value in fields.items()],
                        value_color="#DCE6F2",
                    ),
                    accent_color="#5B8DEF",
                ),
                self.build_bullet_section(
                    "Issues",
                    issue_items,
                    color="#EB5757",
                    accent_color="#EB5757",
                    bullet="⚠",
                ),
                self.build_bullet_section(
                    "Missing Items",
                    intel_display.get("missing_items", []),
                    color="#EB5757",
                    accent_color="#EB5757",
                ),
                self.build_bullet_section(
                    "Priority Fixes",
                    fix_items,
                    color="#F2C94C",
                    accent_color="#F2C94C",
                ),
                self.build_bullet_section(
                    "Review Flags",
                    [self.format_review_flag(flag) for flag in intel_display.get("review_flags", [])],
                    color="#F2994A",
                    accent_color="#F2994A",
                ),
                self.build_bullet_section(
                    "Review Rationale",
                    review_rationale,
                    color="#57B6FF",
                    accent_color="#57B6FF",
                ),
            ]
        )

        if intel_display:
            sections.extend(self.build_condensed_advanced_intel_sections(result))

        rendered_sections = "".join(section for section in sections if section)

        return (
            "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
            "font-family:'Segoe UI'; font-size:13px; line-height:1.45;\">"
            f"{rendered_sections}</body></html>"
        )

    def build_packet_details_html_v2(self, file, result):

        score = result.get("score", 0)
        forms = result.get("forms", [])
        fields = result.get("fields", {})
        issues = result.get("issues", [])
        fixes = result.get("fixes", [])
        intel_display = result.get("intel", {}).get("display", {})
        issue_items = intel_display.get("issue_details") or issues
        issue_groups = intel_display.get("issue_breakdowns") or [{"title": item, "details": []} for item in issue_items]
        fix_items = intel_display.get("priority_fixes") or fixes
        review_rationale = (
            intel_display.get("review_rationale")
            or intel_display.get("why_weak")
            or intel_display.get("approval_rationale")
            or []
        )
        review_rationale = self.polish_review_rationale(review_rationale, max_items=5)
        issue_palette = self.get_issue_display_palette(intel_display)

        key_field_order = [
            "patient_name",
            "dob",
            "authorization_number",
            "va_icn",
            "ordering_doctor",
            "referring_doctor",
            "provider",
            "facility",
            "clinic_name",
            "service_date_range",
            "npi",
            "signature_present",
        ]
        clinical_field_order = [
            "reason_for_request",
            "diagnosis",
            "icd_codes",
            "symptom",
            "location",
            "procedure",
        ]

        score_color = "#27AE60" if score >= 90 else "#F2C94C" if score >= 70 else "#EB5757"

        summary_rows = [
            ("Packet", os.path.basename(file)),
            ("Score", score),
        ]
        decision_rows = []

        if intel_display:
            summary_rows.extend(
                [
                    ("Packet Strength", self.format_packet_display_value("Packet Strength", intel_display.get("packet_strength"))),
                    ("Submission Readiness", self.format_packet_display_value("Submission Readiness", intel_display.get("submission_readiness"))),
                    ("Approval Probability", self.format_packet_display_value("Approval Probability", intel_display.get("approval_probability"))),
                    ("Next Action", self.format_packet_display_value("Next Action", intel_display.get("next_action"))),
                ]
            )
            decision_rows = [
                ("Packet Confidence", self.format_packet_display_value("Packet Confidence", intel_display.get("packet_confidence"))),
                ("Packet Profile", self.format_packet_display_value("Packet Profile", intel_display.get("packet_profile"))),
                ("Denial Risk", self.format_packet_display_value("Denial Risk", intel_display.get("denial_risk"))),
                ("Workflow Queue", self.format_packet_display_value("Workflow Queue", intel_display.get("workflow_queue"))),
                ("Review Priority", self.format_packet_display_value("Review Priority", intel_display.get("review_priority"))),
            ]

        key_rows = []
        clinical_rows = []
        remaining_fields = dict(fields or {})

        for field_name in key_field_order:
            if field_name in remaining_fields:
                key_rows.append(
                    (
                        self.format_packet_field_label(field_name),
                        self.format_packet_display_value(field_name, remaining_fields.pop(field_name)),
                    )
                )

        for field_name in clinical_field_order:
            if field_name in remaining_fields:
                clinical_rows.append(
                    (
                        self.format_packet_field_label(field_name),
                        self.format_packet_display_value(field_name, remaining_fields.pop(field_name)),
                    )
                )

        for field_name, value in remaining_fields.items():
            key_rows.append(
                (
                    self.format_packet_field_label(field_name),
                    self.format_packet_display_value(field_name, value),
                )
            )

        sections = [
            self.build_detail_card(
                "Packet Summary",
                self.build_detail_table(summary_rows, value_color=score_color, show_missing=False),
                accent_color=score_color,
                margin_top=0,
            ),
        ]

        if any(value not in (None, "", [], {}) for _, value in decision_rows):
            sections.append(
                self.build_detail_card(
                    "Decision Snapshot",
                    self.build_detail_table(decision_rows, value_color="#57B6FF", show_missing=False),
                    accent_color="#57B6FF",
                )
            )

        sections.extend(
            [
                self.build_bullet_section(
                    "Documents Found",
                    forms,
                    color="#6FCF97",
                    accent_color="#27AE60",
                    bullet="✓",
                ),
                self.build_bullet_section(
                    "Expected Documents",
                    intel_display.get("expected_documents", []),
                    color="#6FCF97",
                    accent_color="#27AE60",
                    bullet="•",
                ),
                self.build_detail_card(
                    "Key Packet Fields",
                    self.build_detail_table(
                        key_rows,
                        value_color="#DCE6F2",
                        show_missing=False,
                    ),
                    accent_color="#5B8DEF",
                ),
                self.build_detail_card(
                    "Clinical Fields",
                    self.build_detail_table(
                        clinical_rows,
                        value_color="#DCE6F2",
                        show_missing=False,
                    ),
                    accent_color="#5B8DEF",
                ),
                self.build_issue_breakdown_section(
                    "Issues",
                    issue_groups,
                    color=issue_palette["color"],
                    accent_color=issue_palette["accent"],
                ),
                self.build_bullet_section(
                    "Missing Items",
                    intel_display.get("missing_items", []),
                    color="#EB5757",
                    accent_color="#EB5757",
                ),
                self.build_bullet_section(
                    "Priority Fixes",
                    fix_items,
                    color="#F2C94C",
                    accent_color="#F2C94C",
                ),
                self.build_bullet_section(
                    "Review Flags",
                    [self.format_review_flag(flag) for flag in intel_display.get("review_flags", [])],
                    color=issue_palette["color"],
                    accent_color=issue_palette["accent"],
                ),
                self.build_bullet_section(
                    "Review Rationale",
                    review_rationale,
                    color="#57B6FF",
                    accent_color="#57B6FF",
                ),
            ]
        )

        if intel_display:
            sections.extend(self.build_condensed_advanced_intel_sections(result))

        rendered_sections = "".join(section for section in sections if section)

        return (
            "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
            "font-family:'Segoe UI'; font-size:13px; line-height:1.45;\">"
            f"{rendered_sections}</body></html>"
        )

    def build_packet_details_html(self, file, result):

        return self.build_packet_details_html_v2(file, result)

        score = result.get("score", 0)
        forms = result.get("forms", [])
        fields = result.get("fields", {})
        issues = result.get("issues", [])
        fixes = result.get("fixes", [])
        intel_display = result.get("intel", {}).get("display", {})

        score_color = "#27AE60" if score >= 90 else "#F2C94C" if score >= 70 else "#EB5757"

        sections = [
            self.build_detail_card(
                "Packet Summary",
                self.build_detail_table(
                    [
                        ("Packet", os.path.basename(file)),
                        ("Score", score),
                    ],
                    value_color=score_color,
                ),
                accent_color=score_color,
                margin_top=0,
            ),
            self.build_bullet_section(
                "Forms Detected",
                forms,
                color="#6FCF97",
                accent_color="#27AE60",
                bullet="✓",
            ),
            self.build_detail_card(
                "Fields",
                self.build_detail_table(
                    [(self.format_field(key), value) for key, value in fields.items()],
                    value_color="#DCE6F2",
                ),
                accent_color="#5B8DEF",
            ),
            self.build_bullet_section(
                "Issues",
                issues,
                color="#EB5757",
                accent_color="#EB5757",
                bullet="⚠",
            ),
            self.build_bullet_section(
                "Suggested Fixes",
                fixes,
                color="#F2C94C",
                accent_color="#F2C94C",
            ),
        ]

        if intel_display:
            intel_summary_rows = [
                ("Packet Confidence", intel_display.get("packet_confidence")),
                ("Approval Probability", intel_display.get("approval_probability")),
                ("Packet Strength", intel_display.get("packet_strength")),
                ("Submission Readiness", intel_display.get("submission_readiness")),
                ("Workflow Queue", intel_display.get("workflow_queue")),
                ("Next Action", intel_display.get("next_action")),
                ("Denial Risk", intel_display.get("denial_risk")),
                ("Review Priority", intel_display.get("review_priority")),
            ]

            sections.append(
                self.build_detail_card(
                    "Intel Analysis",
                    self.build_detail_table(intel_summary_rows, value_color="#57B6FF", show_missing=False),
                    accent_color="#57B6FF",
                )
            )

            intel_sections = [
                ("Review Flags", [self.format_field(flag) for flag in intel_display.get("review_flags", [])], "#F2C94C", "#F2C94C"),
                ("Missing Items", intel_display.get("missing_items", []), "#EB5757", "#EB5757"),
                ("Why Weak", intel_display.get("why_weak", []), "#57B6FF", "#57B6FF"),
                ("Conflict Summary", intel_display.get("conflict_items", []), "#F2994A", "#F2994A"),
                ("Priority Fixes", intel_display.get("priority_fixes", []), "#6FCF97", "#27AE60"),
                ("Approval Rationale", intel_display.get("approval_rationale", []), "#57B6FF", "#57B6FF"),
            ]

            for title, items, color, accent in intel_sections:
                section_html = self.build_bullet_section(title, items, color=color, accent_color=accent)
                if section_html:
                    sections.append(section_html)

            sections.extend(self.build_advanced_intel_sections(result))

        rendered_sections = "".join(section for section in sections if section)

        return (
            "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
            "font-family:'Segoe UI'; font-size:13px; line-height:1.45;\">"
            f"{rendered_sections}</body></html>"
        )

    def stringify_export_value(self, value):

        if value in (None, "", [], {}):
            return ""

        if isinstance(value, bool):
            return "True" if value else "False"

        if isinstance(value, (list, tuple, set)):
            return " | ".join(str(item) for item in value)

        return str(value)

    # -------------------------------------------------
    # SELECT FILES
    # -------------------------------------------------

    def select_files(self):

        files,_=QFileDialog.getOpenFileNames(self)

        if not files:
            return

        self.files=files
        self.update_scan_diagnostics_button()
        self.log(f"Loaded {len(files)} files.")
        log_event("files_loaded", f"{len(files)} files")

    # -------------------------------------------------
    # ANALYZE (LEGACY BLOCKING PATH)
    # -------------------------------------------------

    def analyze_packets_legacy_blocking(self):

        icon_base=resource_path("ui/pyside_gui/assets/icons/")
        self.table.setRowCount(0)
        self.results = {}

        if not self.files:
            self.log("No packets loaded for analysis.")
            return

        total = len(self.files)
        self.btn_analyze.setEnabled(False)
        self.btn_folder.setEnabled(False)

        try:
            for index, file in enumerate(self.files, start=1):
                basename = os.path.basename(file)
                self.log(f"Analyzing {index}/{total}: {basename}")
                QApplication.processEvents()

                try:
                    result = process_packet(file)
                except Exception as exc:
                    error_text = str(exc)
                    log_event("packet_processing_error", f"{basename} | {error_text}")
                    self.log(f"Packet processing failed for {basename}: {error_text}")
                    result = {
                        "_processing_error": True,
                        "file": file,
                        "score": 0,
                        "fields": {},
                        "forms": [],
                        "issues": [f"Packet processing failed: {error_text}"],
                        "fixes": ["Retry packet analysis after reviewing the packet and logs."],
                        "intel": {
                            "display": {
                                "packet_strength": "error",
                                "submission_readiness": "needs_review",
                                "review_priority": "high",
                                "denial_risk": "high",
                                "workflow_queue": "review_queue",
                                "next_action": "retry_analysis",
                                "issue_details": [f"Packet processing failed: {error_text}"],
                                "priority_fixes": ["Retry packet analysis after reviewing the packet and logs."],
                                "review_rationale": ["The packet could not be fully analyzed."],
                                "review_flags": ["manual_review_required"],
                            }
                        },
                    }

                score=result.get("score",0)
                intel_display=result.get("intel",{}).get("display",{})
                workbook_summary=self.build_export_summary(result)
                workbook_summary.update({
                    "packet_confidence": intel_display.get("packet_confidence"),
                    "approval_probability": intel_display.get("approval_probability"),
                    "submission_readiness": intel_display.get("submission_readiness"),
                    "workflow_queue": intel_display.get("workflow_queue"),
                    "next_action": intel_display.get("next_action"),
                    "denial_risk": intel_display.get("denial_risk"),
                })

                self.results[file]=result

                row=self.table.rowCount()
                self.table.insertRow(row)

                file_item=QTableWidgetItem(basename)
                file_item.setIcon(QIcon(icon_base+"folder.svg"))
                self.table.setItem(row,0,file_item)

                score_item=QTableWidgetItem(str(score))
                score_item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row,1,score_item)

                status=QTableWidgetItem()

                if result.get("_processing_error"):
                    status.setText("Error")
                    status.setIcon(QIcon(icon_base+"error.svg"))
                    status.setForeground(QColor("#EB5757"))
                elif score>=90:
                    status.setText("Approved")
                    status.setIcon(QIcon(icon_base+"check.svg"))
                    status.setForeground(QColor("#27AE60"))
                    export_patient(result.get("fields",{}), file, workbook_summary)
                    self.log(
                        f"Approved packet exported → {basename}",
                        action="packet_processed"
                    )
                elif score>=70:
                    status.setText("Needs Review")
                    status.setIcon(QIcon(icon_base+"warning.svg"))
                    status.setForeground(QColor("#F2C94C"))
                else:
                    status.setText("Rejected")
                    status.setIcon(QIcon(icon_base+"error.svg"))
                    status.setForeground(QColor("#EB5757"))

                self.table.setItem(row,2,status)

                if not result.get("_processing_error"):
                    triage_packet(file, score, result=result)

                if row == 0:
                    self.table.selectRow(0)
                    self.load_packet_details()

                QApplication.processEvents()
        finally:
            self.btn_analyze.setEnabled(True)
            self.btn_folder.setEnabled(True)

        if self.table.rowCount() > 0 and self.table.currentRow() < 0:
            self.table.selectRow(0)
            self.load_packet_details()

        self.update_scan_diagnostics_button()
        self.log("Packet analysis complete.")

    def analyze_packets(self):

        if self.analysis_thread and self.analysis_thread.isRunning():
            self.log("Packet analysis is already running.")
            return

        self.table.setRowCount(0)
        self.results = {}
        self.details.clear()

        if not self.files:
            self.log("No packets loaded for analysis.")
            return

        self.update_scan_diagnostics_button()
        self.set_analysis_controls_enabled(False)

        self.analysis_thread = QThread(self)
        self.analysis_worker = PacketAnalysisWorker(list(self.files))
        self.analysis_worker.moveToThread(self.analysis_thread)

        self.analysis_thread.started.connect(self.analysis_worker.run)
        self.analysis_worker.packet_started.connect(self.on_analysis_packet_started)
        self.analysis_worker.packet_finished.connect(self.on_analysis_packet_finished)
        self.analysis_worker.finished.connect(self.on_analysis_finished)
        self.analysis_worker.finished.connect(self.analysis_thread.quit)
        self.analysis_worker.finished.connect(self.analysis_worker.deleteLater)
        self.analysis_thread.finished.connect(self.analysis_thread.deleteLater)
        self.analysis_thread.finished.connect(self.cleanup_analysis_thread)

        self.analysis_thread.start()

    # -------------------------------------------------
    # PACKET DETAILS
    # -------------------------------------------------

    def load_packet_details(self):

        selected=self.table.currentRow()

        if selected<0:
            return

        file=self.files[selected]
        result=self.results.get(file)

        if not result:
            self.update_scan_diagnostics_button()
            return

        try:
            self.details.setHtml(self.build_packet_details_html(file, result))
        except Exception as exc:
            self.details.setHtml(
                "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
                "font-family:'Segoe UI'; font-size:13px; line-height:1.45;\">"
                "<div style=\"color:#EB5757; font-weight:700; margin-bottom:8px;\">"
                "Packet Details failed to render</div>"
                f"<div style=\"color:#F7C2C2;\">{html.escape(str(exc))}</div>"
                "</body></html>"
            )
            self.log(f"Packet Details render failed for {os.path.basename(file)}: {exc}")
        self.update_scan_diagnostics_button()

        if self.scan_diagnostics_dialog and self.scan_diagnostics_dialog.isVisible():
            self.refresh_scan_diagnostics_dialog()

    # -------------------------------------------------
    # ANALYZE FOLDER
    # -------------------------------------------------

    def analyze_folder(self):

        folder=QFileDialog.getExistingDirectory(self)

        if not folder:
            return

        files=[]

        for root,dirs,fs in os.walk(folder):
            for f in fs:
                files.append(os.path.join(root,f))

        self.files=files
        self.update_scan_diagnostics_button()
        self.log(f"Loaded {len(files)} files.")
        log_event("files_loaded", f"{len(files)} files")

    # -------------------------------------------------
    # EXPORT
    # -------------------------------------------------

    def export_report(self):

        if not self.results:
            return

        path,_=QFileDialog.getSaveFileName(self,"Export",".","CSV (*.csv)")

        if not path:
            return

        with open(path,"w",newline="",encoding="utf-8") as f:

            writer=csv.writer(f)
            writer.writerow([
                "File",
                "Score",
                "Issues",
                "Forms Detected",
                "Issue Details",
                "Suggested Fixes",
                "Packet Confidence",
                "Approval Probability",
                "Packet Strength",
                "Submission Readiness",
                "Workflow Queue",
                "Next Action",
                "Denial Risk",
                "Review Priority",
                "Review Flags",
                "Missing Items",
                "Why Weak",
                "Conflict Summary",
                "Priority Fixes",
                "Approval Rationale",
                "Evidence Sufficiency",
                "Evidence Freshness",
                "Evidence Escalation",
                "Clinical Coherence",
                "Clinical Severity",
                "Conservative Care",
                "Denial Category",
                "Denial Recovery Score",
                "Trust Score",
                "Checkpoint Required",
                "Coordination Score",
                "Reliability Score",
                "Policy Confidence",
                "Deployment Confidence",
                "Prior Case Count",
                "Memory Confidence",
                "Risk Drift",
                "Provider Quality Trend",
                "Triage Priority",
                "Triage Urgency",
                "Triage Review Depth",
                "Triage Staff Route",
                "Triage Time To Action",
                "Operator Primary Route",
                "Operator Focus",
                "Operator Efficiency",
                "Latest Outcome",
                "Outcome Count",
                "Calibration Status",
                "Calibration Delta",
                "Override Status",
                "Override Rate",
                "Learning Readiness",
                "Learning Readiness Score",
                "Insight Trend",
                "Insight Provider Rank",
                "Insight Top Action",
                "Benchmark Standing",
                "Benchmark Percentile",
                "Benchmark Target Score",
                "Benchmark Confidence",
            ])

            for file,result in self.results.items():
                intel_display=result.get("intel",{}).get("display",{})
                intel_export=self.build_export_summary(result)

                writer.writerow([
                    os.path.basename(file),
                    result.get("score",0),
                    len(result.get("issues",[])),
                    self.stringify_export_value(result.get("forms",[])),
                    self.stringify_export_value(result.get("issues",[])),
                    self.stringify_export_value(result.get("fixes",[])),
                    self.stringify_export_value(intel_display.get("packet_confidence")),
                    self.stringify_export_value(intel_display.get("approval_probability")),
                    self.stringify_export_value(intel_display.get("packet_strength")),
                    self.stringify_export_value(intel_display.get("submission_readiness")),
                    self.stringify_export_value(intel_display.get("workflow_queue")),
                    self.stringify_export_value(intel_display.get("next_action")),
                    self.stringify_export_value(intel_display.get("denial_risk")),
                    self.stringify_export_value(intel_display.get("review_priority")),
                    self.stringify_export_value(intel_display.get("review_flags",[])),
                    self.stringify_export_value(intel_display.get("missing_items",[])),
                    self.stringify_export_value(intel_display.get("why_weak",[])),
                    self.stringify_export_value(intel_display.get("conflict_items",[])),
                    self.stringify_export_value(intel_display.get("priority_fixes",[])),
                    self.stringify_export_value(intel_display.get("approval_rationale",[])),
                    self.stringify_export_value(intel_export.get("evidence_sufficiency")),
                    self.stringify_export_value(intel_export.get("evidence_freshness")),
                    self.stringify_export_value(intel_export.get("evidence_escalation")),
                    self.stringify_export_value(intel_export.get("clinical_coherence")),
                    self.stringify_export_value(intel_export.get("clinical_severity")),
                    self.stringify_export_value(intel_export.get("conservative_care")),
                    self.stringify_export_value(intel_export.get("denial_category")),
                    self.stringify_export_value(intel_export.get("denial_recovery_score")),
                    self.stringify_export_value(intel_export.get("trust_score")),
                    self.stringify_export_value(intel_export.get("checkpoint_required")),
                    self.stringify_export_value(intel_export.get("coordination_score")),
                    self.stringify_export_value(intel_export.get("reliability_score")),
                    self.stringify_export_value(intel_export.get("policy_confidence")),
                    self.stringify_export_value(intel_export.get("deployment_confidence")),
                    self.stringify_export_value(intel_export.get("prior_case_count")),
                    self.stringify_export_value(intel_export.get("memory_confidence")),
                    self.stringify_export_value(intel_export.get("risk_drift")),
                    self.stringify_export_value(intel_export.get("provider_quality_trend")),
                    self.stringify_export_value(intel_export.get("triage_priority")),
                    self.stringify_export_value(intel_export.get("triage_urgency")),
                    self.stringify_export_value(intel_export.get("triage_review_depth")),
                    self.stringify_export_value(intel_export.get("triage_staff_route")),
                    self.stringify_export_value(intel_export.get("triage_time_to_action")),
                    self.stringify_export_value(intel_export.get("operator_primary_route")),
                    self.stringify_export_value(intel_export.get("operator_focus")),
                    self.stringify_export_value(intel_export.get("operator_efficiency")),
                    self.stringify_export_value(intel_export.get("latest_outcome")),
                    self.stringify_export_value(intel_export.get("outcome_count")),
                    self.stringify_export_value(intel_export.get("calibration_status")),
                    self.stringify_export_value(intel_export.get("calibration_delta")),
                    self.stringify_export_value(intel_export.get("override_status")),
                    self.stringify_export_value(intel_export.get("override_rate")),
                    self.stringify_export_value(intel_export.get("learning_readiness")),
                    self.stringify_export_value(intel_export.get("learning_readiness_score")),
                    self.stringify_export_value(intel_export.get("insight_trend")),
                    self.stringify_export_value(intel_export.get("insight_provider_rank")),
                    self.stringify_export_value(intel_export.get("insight_top_action")),
                    self.stringify_export_value(intel_export.get("benchmark_standing")),
                    self.stringify_export_value(intel_export.get("benchmark_percentile")),
                    self.stringify_export_value(intel_export.get("benchmark_target_score")),
                    self.stringify_export_value(intel_export.get("benchmark_confidence_band")),
                ])

        self.log("Report exported.")

    # -------------------------------------------------
    # CLEAR
    # -------------------------------------------------

    def clear_results(self):

        self.table.setRowCount(0)
        self.console.clear()
        self.details.clear()

        self.files=[]
        self.results={}
        self.update_scan_diagnostics_button()

        if self.scan_diagnostics_dialog:
            self.scan_diagnostics_dialog.close()

        self.log("Results cleared.")

    # -------------------------------------------------
    # ADMIN AUTH
    # -------------------------------------------------

    def prompt_admin_password(self):

        dialog = QDialog(self)
        dialog.setWindowTitle("Admin Access")
        dialog.setModal(True)
        dialog.resize(420, 190)
        dialog.setStyleSheet(
            """
            QDialog {
                background-color: #11161E;
                color: #E5E7EB;
            }
            QLabel#adminTitle {
                color: #FFFFFF;
                font-size: 16px;
                font-weight: 700;
            }
            QLabel#adminSubtitle {
                color: #9CA3AF;
                font-size: 12px;
            }
            QLineEdit {
                background-color: #0B1017;
                color: #E5E7EB;
                border: 1px solid #2B3A4D;
                border-radius: 6px;
                padding: 10px 12px;
                selection-background-color: #2F80ED;
            }
            QPushButton {
                background-color: #1A2430;
                color: #E5E7EB;
                border: 1px solid #2B3A4D;
                border-radius: 6px;
                padding: 9px 16px;
                min-width: 92px;
            }
            QPushButton:hover {
                background-color: #223247;
            }
            QPushButton#primaryButton {
                background-color: #2F80ED;
                border: 1px solid #2F80ED;
                color: #FFFFFF;
                font-weight: 600;
            }
            QPushButton#primaryButton:hover {
                background-color: #3B8FFF;
            }
            """
        )

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        title = QLabel("Admin Panel Access")
        title.setObjectName("adminTitle")
        layout.addWidget(title)

        subtitle = QLabel("Enter the admin password to open system controls and diagnostics.")
        subtitle.setWordWrap(True)
        subtitle.setObjectName("adminSubtitle")
        layout.addWidget(subtitle)

        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.Password)
        password_input.setPlaceholderText("Admin password")
        layout.addWidget(password_input)

        button_row = QHBoxLayout()
        button_row.addStretch()

        cancel_button = QPushButton("Cancel")
        unlock_button = QPushButton("Unlock")
        unlock_button.setObjectName("primaryButton")
        unlock_button.setDefault(True)

        cancel_button.clicked.connect(dialog.reject)
        unlock_button.clicked.connect(dialog.accept)
        password_input.returnPressed.connect(dialog.accept)

        button_row.addWidget(cancel_button)
        button_row.addWidget(unlock_button)
        layout.addLayout(button_row)

        password_input.setFocus()

        accepted = dialog.exec() == QDialog.Accepted
        return password_input.text(), accepted

    # -------------------------------------------------
    # ADMIN PANEL
    # -------------------------------------------------

    def open_admin_panel(self):

        password,ok = self.prompt_admin_password()

        if not ok or not verify_admin_password(password):
            QMessageBox.warning(self,"Access Denied","Incorrect password.")
            return

        # Create Admin Window
        dialog = QDialog(self)
        dialog.setWindowTitle("TrueCore Admin Panel")
        dialog.resize(1180, 760)

        layout = QVBoxLayout()

        text = QTextEdit()
        text.setReadOnly(True)
        text.setFont(QFont("Segoe UI", 10))

        layout.addWidget(text)

        dialog.setLayout(layout)
        
        # ----------------------------------------------
        # LOAD ADMIN DATA
        # ----------------------------------------------

        try:

            changelog_path = resource_path("CHANGELOG.txt")
            activity_path = LOG_FILE if os.path.exists(LOG_FILE) else LEGACY_LOG_FILE

            changelog = ""
            activity_lines = []

            if os.path.exists(changelog_path):
                with open(changelog_path,"r",encoding="utf-8") as f:
                    changelog = f.read()

            if os.path.exists(activity_path):
                with open(activity_path,"r",encoding="utf-8") as f:
                    activity_lines = [line.rstrip() for line in f.readlines() if line.strip()]

            totals = memory_totals()
            recent_runs = get_recent_packet_runs(20)
            recent_events = get_recent_packet_events(12)
            recent_activity = [mask_phi(line) for line in activity_lines[-80:]]

            unmasked_dob_count = len(re.findall(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", "\n".join(recent_activity)))
            unmasked_va_count = len(re.findall(r"\bVA\d{6,}\b", "\n".join(recent_activity), flags=re.IGNORECASE))
            unmasked_email_count = len(re.findall(r"\b[\w.\-]+@[\w.\-]+\.\w+\b", "\n".join(recent_activity)))
            unmasked_phone_count = len(re.findall(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b", "\n".join(recent_activity)))
            phi_audit_clean = not any([unmasked_dob_count, unmasked_va_count, unmasked_email_count, unmasked_phone_count])

            blocks = changelog.split("VERSION:")
            blocks = [b.strip() for b in blocks if b.strip()]
            blocks.reverse()
            blocks = blocks[:5]

            updates_html = "".join(
                f"<div style=\"color:#DCE6F2; margin:0 0 10px 0; white-space:pre-wrap;\">{html.escape(mask_phi('VERSION: ' + block[:800]))}</div>"
                for block in blocks
            ) or "<div style=\"color:#9CA3AF;\">No changelog entries found.</div>"

            def average(values):
                cleaned = [float(value) for value in values if value not in (None, "", [], {})]
                if not cleaned:
                    return None
                return round(sum(cleaned) / len(cleaned), 2)

            def safe_issue_list(run):
                try:
                    return list(json.loads(run.get("issues_json") or "[]") or [])
                except Exception:
                    return []

            scores = [run.get("score") for run in recent_runs if run.get("score") not in (None, "")]
            packet_confidences = [run.get("packet_confidence") for run in recent_runs if run.get("packet_confidence") not in (None, "")]
            runtimes = [run.get("runtime_seconds") for run in recent_runs if run.get("runtime_seconds") not in (None, "")]
            intel_runtimes = [run.get("intel_runtime_seconds") for run in recent_runs if run.get("intel_runtime_seconds") not in (None, "")]
            host_runtimes = [run.get("host_runtime_seconds") for run in recent_runs if run.get("host_runtime_seconds") not in (None, "")]
            ocr_confidences = [run.get("ocr_confidence") for run in recent_runs if run.get("ocr_confidence") not in (None, "")]
            intel_summaries = [parse_intel_summary(run) for run in recent_runs]

            avg_score = average(scores)
            avg_confidence = average(packet_confidences)
            avg_runtime = average(runtimes)
            avg_intel_runtime = average(intel_runtimes)
            avg_host_runtime = average(host_runtimes)
            avg_ocr_confidence = average(ocr_confidences)

            engine_metric_averages = {}
            for key in [
                "intake_seconds",
                "primary_pipeline_seconds",
                "retry_evaluation_seconds",
                "fallback_reload_seconds",
                "fallback_pipeline_seconds",
                "pipeline_total_seconds",
                "process_path_total_seconds",
            ]:
                engine_metric_averages[key] = average(
                    [
                        (summary.get("engine_metrics", {}) or {}).get(key)
                        for summary in intel_summaries
                    ]
                )

            pipeline_stage_averages = {}
            for stage_name in [
                "detection",
                "extraction",
                "validation",
                "intelligence",
                "review",
                "post_review_intelligence",
                "learning",
            ]:
                pipeline_stage_averages[stage_name] = average(
                    [
                        (summary.get("pipeline_stage_timings", {}) or {}).get(stage_name)
                        for summary in intel_summaries
                    ]
                )

            status_counts = {"approved": 0, "needs_review": 0, "rejected": 0}
            high_risk_count = 0
            slow_packet_count = 0
            analysis_mode_counts = {}
            recurring_issue_counter = {}

            for run in recent_runs:
                status = str(run.get("status") or "").strip().lower()
                if status in status_counts:
                    status_counts[status] += 1

                risk = str(run.get("denial_risk") or "").strip().lower()
                if risk in {"high", "critical"}:
                    high_risk_count += 1

                runtime_value = run.get("runtime_seconds")
                try:
                    if runtime_value is not None and float(runtime_value) >= 30:
                        slow_packet_count += 1
                except Exception:
                    pass

                analysis_mode = str(run.get("analysis_mode") or "unknown").strip().lower()
                analysis_mode_counts[analysis_mode] = analysis_mode_counts.get(analysis_mode, 0) + 1

                for issue in safe_issue_list(run):
                    recurring_issue_counter[issue] = recurring_issue_counter.get(issue, 0) + 1

            recurring_issues = [
                f"{issue} ({count})"
                for issue, count in sorted(
                    recurring_issue_counter.items(),
                    key=lambda item: item[1],
                    reverse=True,
                )[:6]
            ]

            dominant_mode = "-"
            if analysis_mode_counts:
                dominant_mode = max(analysis_mode_counts.items(), key=lambda item: item[1])[0]
                dominant_mode = self.format_field(dominant_mode)

            overview_tiles = [
                {
                    "title": "Packets Remembered",
                    "value": totals.get("packet_count", 0),
                    "subtitle": f"{totals.get('case_count', 0)} cases | {totals.get('provider_count', 0)} providers",
                    "accent": "#57B6FF",
                },
                {
                    "title": "Recent Avg Score",
                    "value": "—" if avg_score is None else int(round(avg_score)),
                    "subtitle": "Last 20 packet runs",
                    "accent": "#F2C94C",
                },
                {
                    "title": "Avg Runtime",
                    "value": self.format_runtime_value(avg_runtime),
                    "subtitle": f"Mode: {dominant_mode}",
                    "accent": "#9B8CFF",
                },
                {
                    "title": "Slow Packets",
                    "value": slow_packet_count,
                    "subtitle": "Recent runs over 30s",
                    "accent": "#F2994A" if slow_packet_count else "#27AE60",
                },
                {
                    "title": "High Risk Packets",
                    "value": high_risk_count,
                    "subtitle": "Recent high / critical denial risk",
                    "accent": "#EB5757" if high_risk_count else "#27AE60",
                },
                {
                    "title": "PHI Audit",
                    "value": "Clean" if phi_audit_clean else "Review",
                    "subtitle": "Recent activity log masking",
                    "accent": "#27AE60" if phi_audit_clean else "#EB5757",
                },
            ]

            run_rows = [
                [
                    self.format_admin_value(run.get("file_name"), missing="Unknown"),
                    run.get("score"),
                    self.format_runtime_value(run.get("runtime_seconds")),
                    self.format_field(run.get("status") or "unknown"),
                    self.format_field(run.get("denial_risk") or "unknown"),
                    self.format_field(run.get("analysis_mode") or "unknown"),
                    self.format_field(run.get("scan_quality_band") or "unknown"),
                    self.format_admin_value(run.get("provider_name"), missing="Unknown"),
                ]
                for run in recent_runs
            ]

            slowest_runs = sorted(
                recent_runs,
                key=lambda run: float(run.get("runtime_seconds") or 0.0),
                reverse=True,
            )[:6]

            slow_run_rows = [
                [
                    self.format_admin_value(run.get("file_name"), missing="Unknown"),
                    self.format_runtime_value(run.get("runtime_seconds")),
                    run.get("score"),
                    self.format_field(run.get("analysis_mode") or "unknown"),
                    self.format_field(run.get("denial_risk") or "unknown"),
                    self.format_field(run.get("scan_quality_band") or "unknown"),
                ]
                for run in slowest_runs
            ]

            event_rows = [
                [
                    event.get("created_at"),
                    self.format_field(event.get("event_type") or "unknown"),
                    self.format_field(event.get("event_status") or "unknown"),
                    self.format_admin_value(event.get("file_name"), missing="Unknown"),
                    self.format_admin_value(event.get("note"), missing="-"),
                ]
                for event in recent_events
            ]

            activity_html = (
                "<div style=\"color:#9CA3AF; white-space:pre-wrap;\">"
                + "<br>".join(html.escape(line) for line in recent_activity)
                + "</div>"
            ) if recent_activity else "<div style=\"color:#9CA3AF;\">No activity log entries found.</div>"

            performance_rows = [
                ("Average Total Runtime", self.format_runtime_value(avg_runtime)),
                ("Average Intel Runtime", self.format_runtime_value(avg_intel_runtime)),
                ("Average Host Runtime", self.format_runtime_value(avg_host_runtime)),
                ("Average Intake Runtime", self.format_runtime_value(engine_metric_averages.get("intake_seconds"))),
                ("Average Pipeline Runtime", self.format_runtime_value(engine_metric_averages.get("pipeline_total_seconds"))),
                ("Average OCR Confidence", "—" if avg_ocr_confidence is None else f"{avg_ocr_confidence:.2f}"),
                ("Slow Packets (>30s)", slow_packet_count),
                ("Dominant Analysis Mode", dominant_mode),
            ]

            pipeline_stage_rows = [
                ("Detection", self.format_runtime_value(pipeline_stage_averages.get("detection"))),
                ("Extraction", self.format_runtime_value(pipeline_stage_averages.get("extraction"))),
                ("Validation", self.format_runtime_value(pipeline_stage_averages.get("validation"))),
                ("Intelligence", self.format_runtime_value(pipeline_stage_averages.get("intelligence"))),
                ("Review", self.format_runtime_value(pipeline_stage_averages.get("review"))),
                ("Post Review", self.format_runtime_value(pipeline_stage_averages.get("post_review_intelligence"))),
                ("Learning", self.format_runtime_value(pipeline_stage_averages.get("learning"))),
            ]

            quality_rows = [
                ("Recent Average Score", "—" if avg_score is None else int(round(avg_score))),
                ("Average Packet Confidence", "—" if avg_confidence is None else f"{int(round(avg_confidence * 100))}%"),
                ("Approved", status_counts["approved"]),
                ("Needs Review", status_counts["needs_review"]),
                ("Rejected", status_counts["rejected"]),
                ("High / Critical Risk", high_risk_count),
            ]

            sections = [
                self.build_detail_card(
                    "Operations Overview",
                    self.build_metric_tiles(overview_tiles),
                    accent_color="#57B6FF",
                    margin_top=0,
                ),
                self.build_detail_card(
                    "System Summary",
                    self.build_detail_table(
                        [
                            ("Engine Version", self.version),
                            ("Build Time", self.build_timestamp or "Unknown"),
                            ("PHI Masking", "Active"),
                            ("Threaded Analysis", "Enabled"),
                            ("Activity Log Path", activity_path if os.path.exists(activity_path) else "Missing"),
                            ("Legacy Log Mirror", LEGACY_LOG_FILE if os.path.exists(LEGACY_LOG_FILE) else "Missing"),
                            ("Packets Remembered", totals.get("packet_count", 0)),
                            ("Cases Remembered", totals.get("case_count", 0)),
                            ("Providers Remembered", totals.get("provider_count", 0)),
                            ("Recent Activity Entries", len(recent_activity)),
                        ],
                        value_color="#57B6FF",
                    ),
                    accent_color="#57B6FF",
                ),
                self.build_detail_card(
                    "Performance Snapshot",
                    self.build_detail_table(
                        performance_rows,
                        value_color="#9B8CFF",
                        show_missing=False,
                    ),
                    accent_color="#9B8CFF",
                ),
                self.build_detail_card(
                    "Intel Stage Timings",
                    self.build_detail_table(
                        pipeline_stage_rows,
                        value_color="#9B8CFF",
                        show_missing=False,
                    ),
                    accent_color="#9B8CFF",
                ),
                self.build_detail_card(
                    "Quality Snapshot",
                    self.build_detail_table(
                        quality_rows,
                        value_color="#57B6FF",
                        show_missing=False,
                    ),
                    accent_color="#57B6FF",
                ),
                self.build_bullet_section(
                    "Top Recurring Issues",
                    recurring_issues,
                    color="#F2C94C",
                    accent_color="#F2994A",
                ),
                self.build_detail_card(
                    "Slowest Recent Packets",
                    self.build_html_grid_table(
                        ["File", "Runtime", "Score", "Mode", "Risk", "Scan"],
                        slow_run_rows,
                        column_colors=["#DCE6F2", "#9B8CFF", "#F2C94C", "#57B6FF", "#EB5757", "#DCE6F2"],
                    ),
                    accent_color="#9B8CFF",
                ),
                self.build_detail_card(
                    "Recent Packet Runs",
                    self.build_html_grid_table(
                        ["File", "Score", "Runtime", "Status", "Risk", "Mode", "Scan", "Provider"],
                        run_rows,
                        column_colors=["#DCE6F2", "#F2C94C", "#9B8CFF", "#DCE6F2", "#EB5757", "#57B6FF", "#DCE6F2", "#57B6FF"],
                    ),
                    accent_color="#57B6FF",
                ),
                self.build_detail_card(
                    "PHI Masking Audit",
                    self.build_detail_table(
                        [
                            ("Raw DOB Tokens In Recent Log", unmasked_dob_count),
                            ("Raw VA Tokens In Recent Log", unmasked_va_count),
                            ("Raw Email Tokens In Recent Log", unmasked_email_count),
                            ("Raw Phone Tokens In Recent Log", unmasked_phone_count),
                        ],
                        value_color="#6FCF97" if phi_audit_clean else "#EB5757",
                    ),
                    accent_color="#27AE60" if phi_audit_clean else "#EB5757",
                ),
                self.build_detail_card(
                    "Recent Events",
                    self.build_html_grid_table(
                        ["Timestamp", "Event", "Status", "File", "Note"],
                        event_rows,
                        column_colors=["#9CA3AF", "#57B6FF", "#F2C94C", "#DCE6F2", "#DCE6F2"],
                    ),
                    accent_color="#F2C94C",
                ),
                self.build_detail_card(
                    "Recent Updates",
                    updates_html,
                    accent_color="#57B6FF",
                ),
                self.build_detail_card(
                    "Masked Activity Log",
                    activity_html,
                    accent_color="#9B8CFF",
                ),
            ]

            text.setHtml(
                "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
                "font-family:'Segoe UI'; font-size:13px; line-height:1.45;\">"
                + "".join(section for section in sections if section)
                + "</body></html>"
            )

        except Exception as e:

            text.setHtml(
                "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
                "font-family:'Segoe UI'; font-size:13px; line-height:1.45;\">"
                f"{self.build_detail_card('Admin Panel Error', '<div style=\"color:#EB5757;\">' + html.escape(str(e)) + '</div>', accent_color='#EB5757', margin_top=0)}"
                "</body></html>"
            )

        dialog.exec()

    # ----------------------------------------------
    # ESCAPE KEY HANDLER
    # ----------------------------------------------

    def keyPressEvent(self, event):

        if event.key() == Qt.Key_Escape:
            self.showMaximized()
            event.accept()
