from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTextEdit,
    QFrame,
    QFileDialog,
    QDialog,
    QMessageBox,
    QLineEdit,
    QComboBox,
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

from TrueCore.utils.logging_system import LOG_FILE, log_event, mask_phi
from TrueCore.utils.admin_auth import ensure_admin_auth_config, verify_admin_password
from TrueCore.utils.runtime_info import (
    ensure_runtime_environment,
    format_version_display,
    get_version,
    get_build_info,
    resource_path
    
)
from TrueCore.utils.runtime_identity import resolve_runtime_identity
from TrueCore.utils.install_mode import (
    load_install_profile,
    update_install_profile,
)
from TrueCore.utils.private_dev_channel import (
    load_private_dev_channel_config,
)

from TrueCore.core.packet_processor import process_packet
from TrueCore.core.packet_triage import triage_packet
from TrueCore.core.host_intelligence import record_manual_outcome
from TrueCore.core.office_rollout import (
    build_rollout_summary,
    load_office_profile,
)
from TrueCore.core.case_memory import (
    get_recent_packet_events,
    get_recent_packet_runs,
    memory_totals,
    parse_issues,
    parse_intel_summary,
)
from TrueCore.core.cross_office_learning import (
    OFFICE_PROFILE_PATH,
    SNAPSHOT_OUTPUT_PATH,
    build_full_cross_office_snapshot,
    export_cross_office_snapshot,
)
from TrueCore.core.cross_office_benchmarking import (
    IMPORTED_SNAPSHOT_DIR,
    NETWORK_ROLLUP_OUTPUT_PATH,
    build_local_network_rollup,
    import_cross_office_snapshot_files,
    list_imported_snapshot_files,
    load_cross_office_snapshot,
    load_network_rollup,
)
from TrueCore.core.cross_office_intelligence import build_local_cross_office_intelligence
from TrueCore.core.hybrid_sync import (
    ACTIVE_NETWORK_INTELLIGENCE_PACKAGE_PATH,
    OFFICE_SYNC_PACKAGE_PATH,
    build_local_network_intelligence_package,
    export_office_sync_package,
    import_network_intelligence_package,
    load_active_network_intelligence_package,
)
from TrueCore.core.outcome_learning_intelligence import build_predictive_learning_snapshot
from TrueCore.core.platform_scaling import (
    DEPLOYMENT_MANIFEST_PATH,
    SUPPORT_BUNDLE_OUTPUT_PATH,
    build_deployment_manifest,
    export_support_bundle,
    write_deployment_manifest,
)
from TrueCore.core.privacy_controls import (
    build_local_phi_storage_status,
    export_local_phi_reset_archive,
    purge_local_phi_storage,
)
from TrueCore.medical.icd_lookup import load_icd_codes
from TrueCore.ui.pyside_gui.packet_details_renderer import (
    render_build_advanced_intel_sections,
    render_build_condensed_advanced_intel_sections,
    render_build_export_summary,
    render_build_packet_details_html_condensed,
    render_build_scan_diagnostics_html,
)
from TrueCore.ui.pyside_gui.main_window_admin_mixin import MainWindowAdminMixin
from TrueCore.ui.pyside_gui.main_window_packet_ui_mixin import MainWindowPacketUiMixin


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


class MainWindow(MainWindowAdminMixin, MainWindowPacketUiMixin, QMainWindow):
    OUTCOME_OPTION_DETAILS = {
        "Approved": "Use when the packet was accepted in the real world without needing more correction.",
        "Denied": "Use when the packet was formally denied or rejected downstream.",
        "Corrected": "Use when the packet needed corrections and was sent back for fixes, but not yet resubmitted.",
        "Resubmitted": "Use when the corrected packet was sent back into the workflow.",
        "Reviewer Override": "Use when a human reviewer intentionally disagreed with the system's recommendation.",
        "Deferred": "Use when the packet is still waiting on outside action and the final disposition is not known yet.",
    }
    OUTCOME_NOTE_REQUIRED = {"Reviewer Override", "Deferred"}

    def __init__(self):
        super().__init__()

        ensure_runtime_environment()
        ensure_admin_auth_config()

        self.version = get_version()
        self.build_id, self.build_timestamp = get_build_info()
        self.private_dev_channel = dict(load_private_dev_channel_config() or {})
        self.install_profile = dict(load_install_profile() or {})
        self._dev_tools_dialog = None
        runtime_identity = resolve_runtime_identity(
            version=self.version,
            install_profile=self.install_profile,
            private_dev_channel=self.private_dev_channel,
        )
        if runtime_identity.get("should_promote_install_profile"):
            self.install_profile = dict(
                update_install_profile(runtime_identity.get("promoted_install_profile"))
                or self.install_profile
            )
            runtime_identity = resolve_runtime_identity(
                version=self.version,
                install_profile=self.install_profile,
                private_dev_channel=self.private_dev_channel,
            )

        self.machine_role = runtime_identity.get("machine_role") or "office"
        self.primary_update_channel = runtime_identity.get("primary_update_channel") or "production"
        self.reference_update_channel = runtime_identity.get("reference_update_channel")
        self.developer_tools_enabled = bool(runtime_identity.get("developer_tools_enabled"))

        window_version = format_version_display(self.version)
        if self.developer_tools_enabled or self.machine_role == "dev":
            self.setWindowTitle(f"TrueValour Packet Auditor DEV {window_version}")
        else:
            self.setWindowTitle(f"TrueValour Packet Auditor {window_version}")
        self.resize(1400, 900)
        self.showFullScreen()

        icon_base = resource_path("ui/pyside_gui/assets/icons/")

        self.files = []
        self.results = {}
        self.scan_diagnostics_dialog = None
        self.scan_diagnostics_view = None
        self.admin_dialog = None
        self.admin_dashboard_host = None
        self.admin_dashboard_focus = None
        self.admin_panel_text = None
        self.admin_cross_office_text = None
        self.admin_operations_text = None
        self.admin_audit_text = None
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

        subtitle = QLabel(f"Powered by TrueCore Engine {format_version_display(self.version)}")
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
            "Record Real Outcome"
        )
        self.btn_record_outcome.setEnabled(False)
        self.btn_record_outcome.setToolTip(
            "Save what actually happened to the selected packet after human review."
        )
        self.btn_dev_tools = None
        if self.developer_tools_enabled:
            self.btn_dev_tools = QPushButton(
                QIcon(icon_base + "settings.svg"),
                "Dev Tools"
            )
            self.btn_dev_tools.setToolTip(
                "Developer-only tools and channel context. This does not appear on office installs."
            )

        self.btn_close = QPushButton("Exit")
        self.btn_close.setObjectName("closeButton")

        header_layout.addWidget(self.btn_scan_diagnostics)
        header_layout.addWidget(self.btn_record_outcome)
        if self.btn_dev_tools:
            header_layout.addWidget(self.btn_dev_tools)
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

        button_list = [
            self.btn_select,
            self.btn_analyze,
            self.btn_folder,
            self.btn_export,
            self.btn_clear,
            self.btn_scan_diagnostics,
            self.btn_record_outcome,
            self.btn_admin
        ]
        if self.btn_dev_tools:
            button_list.append(self.btn_dev_tools)

        for btn in button_list:
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

        self.results_title_label = QLabel("Packet Results")
        self.results_title_label.setObjectName("sectionTitle")

        results_layout.addWidget(self.results_title_label)

        self.results_hint_label = QLabel("Load packets, analyze them, then select a row to review details.")
        self.results_hint_label.setWordWrap(True)
        self.results_hint_label.setStyleSheet("color:#9CA3AF; font-size:12px; margin-top:-4px; margin-bottom:4px;")
        results_layout.addWidget(self.results_hint_label)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["File","Score","Status"])

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(False)

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

        self.details_tabs = QTabWidget()
        self.details_tabs.setObjectName("packetDetailsTabs")
        self.details_tabs.setStyleSheet(
            """
            QTabWidget#packetDetailsTabs::pane {
                border-top: 1px solid #41536D;
                margin-top: 8px;
            }
            QTabWidget#packetDetailsTabs QTabBar::tab {
                background-color: #172331;
                color: #93C9FF;
                border: 1px solid #34465C;
                border-bottom: none;
                padding: 8px 18px;
                min-width: 124px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 4px;
                font-weight: 600;
            }
            QTabWidget#packetDetailsTabs QTabBar::tab:selected {
                background-color: #DDE7F3;
                color: #122033;
                border-color: #8FB6E3;
                font-weight: 700;
            }
            QTabWidget#packetDetailsTabs QTabBar::tab:hover {
                background-color: #BFD2E8;
                color: #112030;
            }
            """
        )

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setFont(QFont("Segoe UI", 10))
        self.details_tabs.addTab(self.details, "Packet Details")

        self.details_math = QTextEdit()
        self.details_math.setReadOnly(True)
        self.details_math.setFont(QFont("Segoe UI", 10))
        self.details_tabs.addTab(self.details_math, "Math")

        details_layout.addWidget(self.details_tabs)

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
        if self.btn_dev_tools:
            self.btn_dev_tools.clicked.connect(self.open_dev_tools_hub)
        self.btn_admin.clicked.connect(self.open_admin_panel)
        self.btn_close.clicked.connect(self.close)
        self.show_reviewer_empty_state("startup")


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
        if self.btn_dev_tools:
            self.btn_dev_tools.setEnabled(enabled)

    def open_dev_tools_hub(self):

        if not self.developer_tools_enabled:
            return

        from TrueCore.ui.pyside_gui.dev_tools_dialog import DevToolsDialog

        if self._dev_tools_dialog and self._dev_tools_dialog.isVisible():
            if self._dev_tools_dialog.isMinimized():
                self._dev_tools_dialog.showNormal()
            self._dev_tools_dialog.showMaximized()
            self._dev_tools_dialog.raise_()
            self._dev_tools_dialog.activateWindow()
            return

        dialog = DevToolsDialog(
            machine_role=self.machine_role,
            primary_update_channel=self.primary_update_channel,
            reference_update_channel=self.reference_update_channel,
            developer_tools_enabled=self.developer_tools_enabled,
            private_dev_channel=self.private_dev_channel,
            parent=self,
        )
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        dialog.destroyed.connect(lambda *_: setattr(self, "_dev_tools_dialog", None))
        self._dev_tools_dialog = dialog
        dialog.showMaximized()
        dialog.raise_()
        dialog.activateWindow()

    def append_analysis_result_row(self, file, result):

        icon_base = resource_path("ui/pyside_gui/assets/icons/")
        basename = os.path.basename(file)
        score = self.get_result_score(result)
        intel_display = result.get("intel", {}).get("display", {})

        self.results[file] = result

        row = self.table.rowCount()
        self.table.insertRow(row)

        file_item = QTableWidgetItem(basename)
        file_item.setIcon(QIcon(icon_base + "folder.svg"))
        file_item.setData(Qt.UserRole, file)
        self.table.setItem(row, 0, file_item)

        score_item = QTableWidgetItem()
        score_item.setData(Qt.DisplayRole, int(score or 0))
        score_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 1, score_item)

        status = QTableWidgetItem()
        status.setData(Qt.UserRole, file)

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
            self.log(
                f"Approved packet ready → {basename}",
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

        if self.table.rowCount() > 0:
            self.table.setSortingEnabled(True)
            self.table.sortByColumn(1, Qt.DescendingOrder)
            self.table.selectRow(0)
            self.load_packet_details()
            self.update_results_hint(
                f"{self.table.rowCount()} packet result{'s' if self.table.rowCount() != 1 else ''} ready. "
                "Sorted by score. Select any row to review details."
            )
        else:
            self.show_reviewer_empty_state("post_analysis")
            self.update_results_hint("Analysis finished, but no packet rows were returned.")

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

    def update_results_hint(self, message=None):

        if not hasattr(self, "results_hint_label") or not self.results_hint_label:
            return

        default_message = "Load packets, analyze them, then select a row to review details."
        self.results_hint_label.setText(str(message or default_message))

    def build_reviewer_empty_state_html(self, state="startup"):

        file_count = len(self.files or [])
        result_count = self.table.rowCount() if hasattr(self, "table") else 0

        states = {
            "startup": {
                "title": "Start a packet review",
                "subtitle": "Use Select Packets or Analyze Folder to load work into the reviewer.",
                "steps": [
                    "Load one or more packet files.",
                    "Click Analyze Packets to run TrueCore intelligence.",
                    "Select a result row to review the packet story and fixes.",
                    "Record a real outcome later when you know what happened operationally.",
                ],
            },
            "files_loaded": {
                "title": f"{file_count} packet{'s' if file_count != 1 else ''} loaded",
                "subtitle": "The files are ready. The next step is to analyze them so the reviewer can score and explain each packet.",
                "steps": [
                    "Click Analyze Packets to start processing.",
                    "The results table will fill in as each packet finishes.",
                    "When analysis is done, click any row to open the full packet review.",
                ],
            },
            "no_files": {
                "title": "No packets are loaded yet",
                "subtitle": "There is nothing to analyze right now.",
                "steps": [
                    "Click Select Packets to choose individual files.",
                    "Or click Analyze Folder to load a whole folder of packets.",
                ],
            },
            "analyzing": {
                "title": "Analysis is running",
                "subtitle": f"TrueCore is processing {file_count} packet{'s' if file_count != 1 else ''}.",
                "steps": [
                    "Scores will populate in the results table as packets finish.",
                    "When the first row appears, you can select it to review the packet details.",
                ],
            },
            "no_selection": {
                "title": "Select a packet result",
                "subtitle": "The reviewer detail view opens from the results table on the left.",
                "steps": [
                    "Click a packet row to open its quick read, packet summary, and issues.",
                    "Use Record Real Outcome after review when you know the real disposition.",
                ],
            },
            "cleared": {
                "title": "Results cleared",
                "subtitle": "The last review session has been removed from the screen.",
                "steps": [
                    "Load new packets to start another review cycle.",
                    "Analyze them to repopulate the results table and detail view.",
                ],
            },
            "no_result": {
                "title": "No packet details are ready for this row",
                "subtitle": "The selected result does not currently have a renderable packet payload.",
                "steps": [
                    "Try selecting a different row.",
                    "If the issue persists, review the Audit Console for processing errors.",
                ],
            },
            "post_analysis": {
                "title": "Review complete results",
                "subtitle": f"{result_count} packet result{'s' if result_count != 1 else ''} are ready.",
                "steps": [
                    "Rows are sorted by score so the highest packet scores sit at the top.",
                    "Select any row to see the quick read, decision snapshot, and review guidance.",
                ],
            },
        }

        payload = states.get(state, states["startup"])
        steps_html = "".join(
            f"<li style=\"margin-bottom:8px;\">{html.escape(str(step))}</li>"
            for step in payload["steps"]
        )

        return (
            "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
            "font-family:'Segoe UI'; font-size:13px; line-height:1.5; margin:0;\">"
            "<div style=\"margin:8px 0 0 0; padding:20px 22px; background:#151C26; "
            "border:1px solid #243244; border-radius:14px;\">"
            f"<div style=\"font-size:20px; font-weight:700; color:#FFFFFF; margin-bottom:8px;\">{html.escape(payload['title'])}</div>"
            f"<div style=\"color:#A9B6C7; margin-bottom:14px;\">{html.escape(payload['subtitle'])}</div>"
            "<div style=\"display:inline-block; padding:6px 10px; border-radius:999px; "
            "background:#0F1824; border:1px solid #2F80ED; color:#7EC8FF; font-size:11px; "
            "font-weight:600; margin-bottom:14px;\">Reviewer Workflow</div>"
            "<ol style=\"margin:0 0 0 18px; padding:0; color:#DCE6F2;\">"
            f"{steps_html}"
            "</ol>"
            "</div></body></html>"
        )

    def build_packet_math_empty_state_html(self, state="startup"):

        state_titles = {
            "startup": "Score Math will appear here",
            "files_loaded": "Analyze the loaded packets first",
            "analyzing": "TrueCore is still scoring the packet",
            "no_selection": "Select a packet to open its score math",
            "no_result": "No packet math is available for this row",
            "cleared": "Packet math was cleared with the last results",
            "post_analysis": "Select a packet row to inspect the scoring math",
        }

        title = state_titles.get(state, state_titles["startup"])
        steps = [
            "Open a packet result from the table on the left.",
            "Use the Math tab to see the rubric points, consistency points, and approval-outlook math.",
            "This tab explains how the visible score was built for the selected packet.",
        ]
        steps_html = "".join(
            f"<li style=\"margin-bottom:8px;\">{html.escape(str(step))}</li>"
            for step in steps
        )

        return (
            "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
            "font-family:'Segoe UI'; font-size:13px; line-height:1.5; margin:0; text-align:left;\">"
            "<div style=\"margin:8px 0 0 0; padding:20px 22px; background:#151C26; "
            "border:1px solid #243244; border-radius:14px; text-align:left;\">"
            f"<div style=\"font-size:20px; font-weight:700; color:#FFFFFF; margin-bottom:8px; text-align:left;\">{html.escape(title)}</div>"
            "<div style=\"color:#A9B6C7; margin-bottom:14px; text-align:left;\">"
            "The Math tab is the packet-by-packet scoring worksheet for the current result."
            "</div>"
            "<div style=\"display:inline-block; padding:6px 10px; border-radius:999px; "
            "background:#0F1824; border:1px solid #F2C94C; color:#F7D774; font-size:11px; "
            "font-weight:600; margin-bottom:14px;\">Score Explanation</div>"
            "<ol style=\"margin:0 0 0 18px; padding:0; color:#DCE6F2; text-align:left;\">"
            f"{steps_html}"
            "</ol>"
            "</div></body></html>"
        )

    def show_reviewer_empty_state(self, state="startup"):

        if hasattr(self, "details") and self.details:
            self.details.setHtml(self.build_reviewer_empty_state_html(state))
        if hasattr(self, "details_math") and self.details_math:
            self.details_math.setHtml(self.build_packet_math_empty_state_html(state))

    def get_selected_table_file(self):

        if not hasattr(self, "table") or not self.table:
            return None

        selected = self.table.currentRow()
        if selected < 0:
            return None

        file_item = self.table.item(selected, 0)
        if not file_item:
            return None

        return file_item.data(Qt.UserRole)

    def get_result_score(self, result):

        intel = dict((result or {}).get("intel", {}) or {})
        display = dict(intel.get("display", {}) or {})

        for candidate in (
            display.get("core_packet_score"),
            intel.get("core_packet_score"),
            (result or {}).get("score"),
        ):
            try:
                return int(float(candidate))
            except Exception:
                continue

        return 0

    def format_field(self,name):
        text = str(name or "").strip()
        if not text:
            return ""

        token_map = {
            "api": "API",
            "csv": "CSV",
            "db": "DB",
            "dob": "DOB",
            "gui": "GUI",
            "hipaa": "HIPAA",
            "icd": "ICD",
            "icn": "ICN",
            "id": "ID",
            "it": "IT",
            "json": "JSON",
            "lomn": "LOMN",
            "mri": "MRI",
            "npi": "NPI",
            "ocr": "OCR",
            "pdf": "PDF",
            "phi": "PHI",
            "ppv": "PPV",
            "npv": "NPV",
            "rfs": "RFS",
            "seoc": "SEOC",
            "ui": "UI",
            "va": "VA",
        }

        cleaned = text.replace("_", " ").replace("-", " - ").replace("/", " / ")
        parts = re.split(r"(\s+|/|-)", cleaned)
        rendered = []

        for part in parts:
            if not part:
                continue
            if part.isspace() or part in {"/", "-"}:
                rendered.append(part)
                continue

            normalized = part.lower()
            if normalized in token_map:
                rendered.append(token_map[normalized])
            elif re.fullmatch(r"p\d+", normalized):
                rendered.append(normalized.upper())
            else:
                rendered.append(part.title())

        return re.sub(r"\s+", " ", "".join(rendered)).replace(" / ", "/").replace(" - ", "-").strip()

    def format_machine_text(self, value):

        text = str(value or "").strip()
        if not text:
            return ""

        normalized = re.sub(r"\s+", " ", text).strip()
        lowered = normalized.lower()
        exact_map = {
            "n/a": "N/A",
            "ready": "Ready",
            "hold": "Hold",
            "requires_review": "Review Required",
            "not_ready": "Not Ready",
            "needs_review": "Needs Review",
            "submission_queue": "Submission Queue",
            "review_queue": "Review Queue",
            "correction_queue": "Correction Queue",
            "senior_review_queue": "Senior Review Queue",
            "submit_packet": "Submit Packet",
            "route_to_review": "Route to Review",
            "attach_missing_document": "Attach Missing Document",
            "attach_missing_documents": "Attach Missing Documents",
            "verify_missing_field": "Verify Missing Field",
            "resolve_conflict": "Resolve Conflict",
            "strengthen_medical_support": "Strengthen Medical Support",
            "align_clinical_support": "Align Clinical Support",
            "escalate_packet_integrity_review": "Escalate Packet Integrity Review",
            "correct_service_dates": "Correct Service Dates",
            "remove_duplicate_pages": "Remove Duplicate Pages",
            "collect_missing_evidence": "Collect Missing Evidence",
            "strengthen_procedure_support": "Strengthen Procedure Support",
            "hold_for_correction": "Hold for Correction",
            "manual_review_required": "Manual Review Required",
            "packet_integrity_risk": "Packet Integrity Risk",
            "duplicate_pages_present": "Duplicate Pages Present",
            "chronology_review_needed": "Chronology Review Needed",
            "partial_diagnosis_icd_alignment": "Partial Diagnosis / ICD Alignment",
            "diagnosis_icd_mismatch": "Diagnosis / ICD Mismatch",
            "moderate_mri_justification": "Moderate MRI Justification",
            "weak_mri_justification": "Weak MRI Justification",
            "procedure_without_medical_support": "Procedure Without Medical Support",
        }

        if lowered in exact_map:
            return exact_map[lowered]

        if "_" in normalized:
            return self.format_field(normalized)

        if normalized == lowered and len(normalized.split()) <= 4 and normalized.replace(" ", "").isalnum():
            return self.format_field(normalized)

        return normalized

    def format_detail_value(self, value):

        if value in (None, "", [], {}):
            return "Missing"

        if isinstance(value, bool):
            return "Yes" if value else "No"

        if isinstance(value, (list, tuple, set)):
            return ", ".join(self.format_detail_value(item) for item in value)

        if isinstance(value, str):
            return self.format_machine_text(value)

        return str(value)

    def format_packet_field_label(self, name):

        mapping = {
            "dob": "DOB",
            "icd_codes": "ICD Codes",
            "va_icn": "VA ICN",
            "npi": "NPI",
            "treating_provider": "Treating Provider",
            "followup_provider": "Follow-Up Provider",
            "clinic_name": "Community Facility",
            "location": "Treating Location",
        }

        return mapping.get(str(name or "").strip().lower(), self.format_field(str(name or "")))

    def format_packet_display_value(self, label, value):

        if value in (None, "", [], {}):
            return value

        label_text = str(label or "").strip().lower()

        if isinstance(value, bool):
            return "Yes" if value else "No"

        if isinstance(value, (int, float)) and 0 <= float(value) <= 1:
            if (
                "probability" in label_text
                or "outlook" in label_text
                or "confidence" in label_text
                or "trust score" in label_text
            ):
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
                "main blocker",
            }:
                return self.format_machine_text(value)

        return value

    def format_review_flag(self, flag):

        normalized = str(flag or "").strip().lower()
        mapping = {
            "diagnosis_icd_mismatch": "Diagnosis / ICD Mismatch",
            "partial_diagnosis_icd_alignment": "Partial Diagnosis / ICD Alignment",
            "manual_review_required": "Manual Review Required",
            "packet_integrity_risk": "Packet Integrity Risk",
            "duplicate_pages_present": "Duplicate Pages Present",
            "chronology_review_needed": "Chronology Review Needed",
            "moderate_mri_justification": "Moderate MRI Justification",
            "weak_mri_justification": "Weak MRI Justification",
            "procedure_without_medical_support": "Procedure Without Medical Support",
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
            "approved_referral": "VA Form 10-7080",
            "clinical_notes": "Clinical Notes",
            "imaging_report": "MRI / Imaging Report",
            "conservative_care_summary": "Conservative Care Summary",
        }

        normalized = str(document_type or "").strip().lower()
        if not normalized:
            return ""

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

    def intel_payload(self, result):

        return result.get("intel", {}) if isinstance(result, dict) else {}

    def build_advanced_intel_sections(self, result):
        return render_build_advanced_intel_sections(self, result)

    def build_condensed_advanced_intel_sections(self, result):
        return render_build_condensed_advanced_intel_sections(self, result)

    def build_export_summary(self, result):
        return render_build_export_summary(self, result)

    def current_selected_file(self):

        return self.get_selected_table_file()

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
        return render_build_scan_diagnostics_html(self, file_path, result)

    def refresh_scan_diagnostics_dialog(self):

        if not self.scan_diagnostics_dialog or not self.scan_diagnostics_view:
            return

        file_path, result = self.current_selected_result()

        if not file_path or not result:
            self.scan_diagnostics_view.setHtml(
                "<html><body style=\"background-color:#11161E; color:#E5E7EB; font-family:'Segoe UI'; "
                "font-size:13px; line-height:1.45; margin:0; text-align:left;\"><div style=\"color:#9CA3AF; text-align:left;\">Select a packet result to view scan diagnostics.</div></body></html>"
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

    def prompt_record_outcome(self, file_path, result):

        intel_display = dict(((result.get("intel", {}) or {}).get("display", {}) or {}))
        score = self.get_result_score(result)
        queue = self.format_packet_display_value("Workflow Queue", intel_display.get("workflow_queue") or "n/a")
        denial_risk = self.format_packet_display_value("Denial Risk", intel_display.get("denial_risk") or "n/a")

        dialog = QDialog(self)
        dialog.setWindowTitle("Record Real Outcome")
        dialog.setMinimumWidth(560)
        dialog.setStyleSheet(self.admin_modal_stylesheet())

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title = QLabel("Save what actually happened to this packet")
        title.setStyleSheet("font-size:18px; font-weight:700; color:#FFFFFF;")
        title.setWordWrap(True)
        layout.addWidget(title)

        guidance = QLabel(
            "Use this after human review or real downstream disposition. "
            "This should reflect what truly happened, not what the system predicted."
        )
        guidance.setWordWrap(True)
        guidance.setStyleSheet("color:#B8C4D6;")
        layout.addWidget(guidance)

        packet_summary = QLabel(
            f"Packet: {os.path.basename(file_path)}\n"
            f"Score: {score}   |   Queue: {queue}   |   Denial Risk: {denial_risk}"
        )
        packet_summary.setWordWrap(True)
        packet_summary.setStyleSheet(
            "background-color:#0F1722; border:1px solid #253243; border-radius:8px; "
            "padding:10px; color:#E5E7EB;"
        )
        layout.addWidget(packet_summary)

        outcome_label = QLabel("Outcome")
        outcome_label.setStyleSheet("font-weight:600; color:#FFFFFF;")
        layout.addWidget(outcome_label)

        outcome_combo = QComboBox(dialog)
        outcome_combo.addItems(list(self.OUTCOME_OPTION_DETAILS.keys()))
        layout.addWidget(outcome_combo)

        detail_label = QLabel("")
        detail_label.setWordWrap(True)
        detail_label.setStyleSheet(
            "background-color:#111A25; border:1px solid #253243; border-radius:8px; "
            "padding:10px; color:#C9D5E6;"
        )
        layout.addWidget(detail_label)

        note_label = QLabel("Note")
        note_label.setStyleSheet("font-weight:600; color:#FFFFFF;")
        layout.addWidget(note_label)

        note_edit = QTextEdit(dialog)
        note_edit.setPlaceholderText(
            "Optional context, such as why it was denied, what was corrected, or why the reviewer overrode the system."
        )
        note_edit.setFixedHeight(110)
        layout.addWidget(note_edit)

        requirement_label = QLabel("")
        requirement_label.setWordWrap(True)
        requirement_label.setStyleSheet("color:#F2C94C;")
        layout.addWidget(requirement_label)

        button_row = QHBoxLayout()
        button_row.addStretch()

        cancel_button = QPushButton("Cancel")
        save_button = QPushButton("Save Outcome")
        save_button.setStyleSheet(
            "background-color:#1E6FDB; color:#FFFFFF; border:1px solid #2F80ED; "
            "border-radius:6px; padding:8px 14px;"
        )
        button_row.addWidget(cancel_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)

        def update_outcome_guidance():
            selected = outcome_combo.currentText()
            detail_label.setText(self.OUTCOME_OPTION_DETAILS.get(selected, ""))
            if selected in self.OUTCOME_NOTE_REQUIRED:
                requirement_label.setText(
                    "A short note is required for this outcome so the learning record has useful context."
                )
            else:
                requirement_label.setText(
                    "A note is optional, but adding context makes the learning layer more useful later."
                )

        def submit():
            selected = outcome_combo.currentText().strip()
            note = note_edit.toPlainText().strip()
            if selected in self.OUTCOME_NOTE_REQUIRED and not note:
                self.show_admin_message(
                    "Note Required",
                    "Please add a short note for this outcome so future learning has enough context.",
                    icon=QMessageBox.Warning,
                )
                return
            dialog.accept()

        outcome_combo.currentTextChanged.connect(lambda _: update_outcome_guidance())
        cancel_button.clicked.connect(dialog.reject)
        save_button.clicked.connect(submit)

        update_outcome_guidance()

        if dialog.exec() != QDialog.Accepted:
            return None, None

        return outcome_combo.currentText().strip(), note_edit.toPlainText().strip()

    def open_record_outcome(self):

        file_path, result = self.current_selected_result()

        if not file_path or not result:
            self.show_admin_message("Record Real Outcome", "Select a packet result first.")
            return

        outcome, note = self.prompt_record_outcome(file_path, result)
        if not outcome:
            return

        updated_result = record_manual_outcome(file_path, result, outcome, note=note)
        self.results[file_path] = updated_result
        self.details.setHtml(self.build_packet_details_html(file_path, updated_result))
        self.update_scan_diagnostics_button()

        if self.scan_diagnostics_dialog and self.scan_diagnostics_dialog.isVisible():
            self.refresh_scan_diagnostics_dialog()

        self.log(f"Recorded outcome for {os.path.basename(file_path)}: {outcome}")
        self.show_admin_message(
            "Record Real Outcome",
            f"Saved outcome: {outcome}\n\nThis packet's learning and benchmark context have been refreshed.",
        )

    def build_packet_details_html_condensed(self, file, result):
        return render_build_packet_details_html_condensed(self, file, result)

    def build_packet_details_html_v2(self, file, result):

        score = self.get_result_score(result)
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
            "treating_provider",
            "followup_provider",
            "facility",
            "clinic_name",
            "location",
            "service_date_range",
            "npi",
            "signature_present",
        ]
        clinical_field_order = [
            "reason_for_request",
            "diagnosis",
            "icd_codes",
            "symptom",
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
                    ("Approval Outlook", self.format_packet_display_value("Approval Outlook", intel_display.get("approval_outlook", intel_display.get("approval_probability")))),
                    ("Next Action", self.format_packet_display_value("Next Action", intel_display.get("next_action"))),
                    ("Main Blocker", self.format_packet_display_value("Main Blocker", intel_display.get("main_blocker"))),
                ]
            )
            decision_rows = [
                ("Evidence Strength", self.format_packet_display_value("Evidence Strength", intel_display.get("evidence_strength"))),
                ("Packet Assembly", self.format_packet_display_value("Packet Assembly", intel_display.get("packet_assembly"))),
                ("Invariant Coverage", self.format_packet_display_value("Invariant Coverage", intel_display.get("invariant_coverage"))),
                ("Packet Profile", self.format_packet_display_value("Packet Profile", intel_display.get("packet_profile"))),
                ("Packet Archetype", self.format_packet_display_value("Packet Archetype", intel_display.get("packet_archetype"))),
                ("Format Variability", self.format_packet_display_value("Format Variability", intel_display.get("format_variability"))),
                ("Denial Risk", self.format_packet_display_value("Denial Risk", intel_display.get("denial_risk"))),
                ("Workflow Queue", self.format_packet_display_value("Workflow Queue", intel_display.get("workflow_queue"))),
                ("Review Priority", self.format_packet_display_value("Review Priority", intel_display.get("review_priority"))),
            ]

        key_rows = []
        clinical_rows = []
        remaining_fields = dict(fields or {})

        for field_name in key_field_order:
            if field_name in remaining_fields:
                if (
                    field_name == "provider"
                    and "treating_provider" in remaining_fields
                    and self.format_detail_value(remaining_fields.get("provider")).strip().lower()
                    == self.format_detail_value(remaining_fields.get("treating_provider")).strip().lower()
                ):
                    remaining_fields.pop(field_name, None)
                    continue
                key_rows.append(
                    (
                        self.format_packet_field_label(field_name),
                        self.format_packet_field_value_for_details(field_name, remaining_fields.pop(field_name), result),
                    )
                )

        for field_name in clinical_field_order:
            if field_name in remaining_fields:
                clinical_rows.append(
                    (
                        self.format_packet_field_label(field_name),
                        self.format_packet_field_value_for_details(field_name, remaining_fields.pop(field_name), result),
                    )
                )

        for field_name, value in remaining_fields.items():
            key_rows.append(
                (
                    self.format_packet_field_label(field_name),
                    self.format_packet_field_value_for_details(field_name, value, result),
                )
            )

        sections = [
            self.build_operator_quick_read_card(
                intel_display,
                issue_groups,
                fix_items,
                review_rationale,
                margin_top=0,
            ),
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
            sections.append(
                self.build_repeat_review_comparison_card(file, result)
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
                *self.build_semantic_reasoning_sections(intel_display),
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
            "font-family:'Segoe UI'; font-size:13px; line-height:1.45; margin:0; text-align:left;\">"
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
                ("Packet Confidence", self.format_packet_display_value("Packet Confidence", intel_display.get("packet_confidence"))),
                ("Approval Outlook", self.format_packet_display_value("Approval Outlook", intel_display.get("approval_outlook", intel_display.get("approval_probability")))),
                ("Packet Strength", self.format_packet_display_value("Packet Strength", intel_display.get("packet_strength"))),
                ("Submission Readiness", self.format_packet_display_value("Submission Readiness", intel_display.get("submission_readiness"))),
                ("Workflow Queue", self.format_packet_display_value("Workflow Queue", intel_display.get("workflow_queue"))),
                ("Next Action", self.format_packet_display_value("Next Action", intel_display.get("next_action"))),
                ("Denial Risk", self.format_packet_display_value("Denial Risk", intel_display.get("denial_risk"))),
                ("Review Priority", self.format_packet_display_value("Review Priority", intel_display.get("review_priority"))),
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
            "font-family:'Segoe UI'; font-size:13px; line-height:1.45; margin:0; text-align:left;\">"
            f"{rendered_sections}</body></html>"
        )

    def stringify_export_value(self, value, label=None):

        if value in (None, "", [], {}):
            return ""

        if isinstance(value, bool):
            return "Yes" if value else "No"

        if isinstance(value, (list, tuple, set)):
            return " | ".join(
                self.stringify_export_value(item, label=label)
                for item in value
                if item not in (None, "", [], {})
            )

        if label:
            label_text = str(label or "").strip()
            if label_text.lower() == "review flags":
                return self.format_review_flag(value)
            return self.format_detail_value(self.format_packet_display_value(label_text, value))

        return self.format_detail_value(value)

    # -------------------------------------------------
    # SELECT FILES
    # -------------------------------------------------

    def select_files(self):

        files,_=QFileDialog.getOpenFileNames(self)

        if not files:
            return

        self.files=files
        self.update_scan_diagnostics_button()
        self.show_reviewer_empty_state("files_loaded")
        self.update_results_hint(
            f"{len(files)} packet{'s' if len(files) != 1 else ''} loaded. Click Analyze Packets to score and review them."
        )
        self.log(f"Loaded {len(files)} files.")
        log_event("files_loaded", f"{len(files)} files")

    # -------------------------------------------------
    def analyze_packets(self):

        if self.analysis_thread and self.analysis_thread.isRunning():
            self.log("Packet analysis is already running.")
            return

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.results = {}
        self.show_reviewer_empty_state("analyzing")

        if not self.files:
            self.show_reviewer_empty_state("no_files")
            self.update_results_hint("No packets loaded yet. Use Select Packets or Analyze Folder first.")
            self.log("No packets loaded for analysis.")
            return

        self.update_scan_diagnostics_button()
        self.set_analysis_controls_enabled(False)
        self.update_results_hint(
            f"Analyzing {len(self.files)} packet{'s' if len(self.files) != 1 else ''}. Results will populate below."
        )

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
            self.show_reviewer_empty_state("no_selection")
            self.update_scan_diagnostics_button()
            return

        file = self.get_selected_table_file()
        result=self.results.get(file)

        if not result:
            self.show_reviewer_empty_state("no_result")
            self.update_scan_diagnostics_button()
            return

        try:
            self.details.setHtml(self.build_packet_details_html(file, result))
            if hasattr(self, "details_math") and self.details_math:
                self.details_math.setHtml(self.build_packet_math_html(file, result))
        except Exception as exc:
            self.details.setHtml(
                "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
                "font-family:'Segoe UI'; font-size:13px; line-height:1.45; margin:0; text-align:left;\">"
                "<div style=\"color:#EB5757; font-weight:700; margin-bottom:8px;\">"
                "Packet Details failed to render</div>"
                f"<div style=\"color:#F7C2C2;\">{html.escape(str(exc))}</div>"
                "</body></html>"
            )
            if hasattr(self, "details_math") and self.details_math:
                self.details_math.setHtml(
                    "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
                    "font-family:'Segoe UI'; font-size:13px; line-height:1.45; margin:0; text-align:left;\">"
                    "<div style=\"color:#EB5757; font-weight:700; margin-bottom:8px;\">"
                    "Math view failed to render</div>"
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
        self.show_reviewer_empty_state("files_loaded")
        self.update_results_hint(
            f"{len(files)} packet{'s' if len(files) != 1 else ''} loaded from the folder. Click Analyze Packets to review them."
        )
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
                "Approval Outlook",
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
                "Semantic Coherence",
                "Semantic Review Notes",
                "Deduction Ledger Summary",
                "Real Gaps",
                "Review Cautions",
                "Variant-Tolerated Differences",
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
                    self.stringify_export_value(intel_display.get("packet_confidence"), "Packet Confidence"),
                    self.stringify_export_value(intel_display.get("approval_outlook", intel_display.get("approval_probability")), "Approval Outlook"),
                    self.stringify_export_value(intel_display.get("packet_strength"), "Packet Strength"),
                    self.stringify_export_value(intel_display.get("submission_readiness"), "Submission Readiness"),
                    self.stringify_export_value(intel_display.get("workflow_queue"), "Workflow Queue"),
                    self.stringify_export_value(intel_display.get("next_action"), "Next Action"),
                    self.stringify_export_value(intel_display.get("denial_risk"), "Denial Risk"),
                    self.stringify_export_value(intel_display.get("review_priority"), "Review Priority"),
                    self.stringify_export_value(intel_display.get("review_flags",[]), "Review Flags"),
                    self.stringify_export_value(intel_display.get("missing_items",[])),
                    self.stringify_export_value(intel_display.get("why_weak",[])),
                    self.stringify_export_value(intel_display.get("conflict_items",[])),
                    self.stringify_export_value(intel_display.get("priority_fixes",[])),
                    self.stringify_export_value(intel_display.get("approval_rationale",[])),
                    self.stringify_export_value(intel_export.get("semantic_coherence"), "Semantic Coherence"),
                    self.stringify_export_value(intel_export.get("semantic_review_notes",[])),
                    self.stringify_export_value(intel_export.get("deduction_ledger_summary")),
                    self.stringify_export_value(intel_export.get("deduction_real_gaps",[])),
                    self.stringify_export_value(intel_export.get("deduction_review_cautions",[])),
                    self.stringify_export_value(intel_export.get("deduction_variant_tolerated",[])),
                    self.stringify_export_value(intel_export.get("evidence_sufficiency"), "Support Level"),
                    self.stringify_export_value(intel_export.get("evidence_freshness"), "Freshness"),
                    self.stringify_export_value(intel_export.get("evidence_escalation"), "Escalation"),
                    self.stringify_export_value(intel_export.get("clinical_coherence"), "Coherence"),
                    self.stringify_export_value(intel_export.get("clinical_severity"), "Severity"),
                    self.stringify_export_value(intel_export.get("conservative_care"), "Conservative Care"),
                    self.stringify_export_value(intel_export.get("denial_category")),
                    self.stringify_export_value(intel_export.get("denial_recovery_score")),
                    self.stringify_export_value(intel_export.get("trust_score")),
                    self.stringify_export_value(intel_export.get("checkpoint_required")),
                    self.stringify_export_value(intel_export.get("coordination_score")),
                    self.stringify_export_value(intel_export.get("reliability_score")),
                    self.stringify_export_value(intel_export.get("policy_confidence"), "Policy Confidence"),
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

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.console.clear()
        self.show_reviewer_empty_state("cleared")

        self.files=[]
        self.results={}
        self.update_scan_diagnostics_button()
        self.update_results_hint("Results cleared. Load packets to start another review.")

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
                selection-color: #FFFFFF;
            }
            QLineEdit:focus {
                background-color: #111A25;
                border: 1px solid #57B6FF;
            }
            QLineEdit::placeholder {
                color: #7F8FA5;
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

    def build_admin_panel_views(self):

        changelog_path = resource_path("CHANGELOG.txt")
        activity_path = LOG_FILE

        changelog = ""
        activity_lines = []

        if os.path.exists(changelog_path):
            with open(changelog_path, "r", encoding="utf-8") as handle:
                changelog = handle.read()

        if os.path.exists(activity_path):
            with open(activity_path, "r", encoding="utf-8") as handle:
                activity_lines = [line.rstrip() for line in handle.readlines() if line.strip()]

        totals = memory_totals()
        all_runs = get_recent_packet_runs(280)
        all_events = get_recent_packet_events(280)
        recent_runs = all_runs[:20]
        recent_events = all_events[:12]
        predictive_snapshot = build_predictive_learning_snapshot(all_runs, all_events)
        predictive_model_summary = dict(predictive_snapshot.get("model_summary") or {})
        predictive_validation_summary = dict(predictive_snapshot.get("validation_summary") or {})
        predictive_threshold_guidance = dict(predictive_snapshot.get("threshold_guidance") or {})
        outcome_learning_health = dict(predictive_snapshot.get("outcome_learning_health") or {})
        deployment_manifest = build_deployment_manifest()
        deployment_platform = dict(deployment_manifest.get("platform") or {})
        deployment_details = dict(deployment_manifest.get("deployment") or {})
        deployment_data_state = dict(deployment_manifest.get("data_state") or {})
        rollout_summary = dict(deployment_manifest.get("office_rollout") or {})
        platform_readiness = dict(deployment_manifest.get("platform_readiness") or {})
        recent_activity = [mask_phi(line) for line in activity_lines[-80:]]

        unmasked_dob_count = len(re.findall(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", "\n".join(recent_activity)))
        unmasked_va_count = len(re.findall(r"\bVA\d{6,}\b", "\n".join(recent_activity), flags=re.IGNORECASE))
        unmasked_email_count = len(re.findall(r"\b[\w.\-]+@[\w.\-]+\.\w+\b", "\n".join(recent_activity)))
        unmasked_phone_count = len(re.findall(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b", "\n".join(recent_activity)))
        phi_audit_clean = not any([unmasked_dob_count, unmasked_va_count, unmasked_email_count, unmasked_phone_count])

        blocks = changelog.split("VERSION:")
        blocks = [block.strip() for block in blocks if block.strip()]
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

        def format_score_value(value):
            if value in (None, "", [], {}):
                return "—"
            try:
                return int(round(float(value)))
            except (TypeError, ValueError):
                return value

        def format_confidence_percent(value):
            if value in (None, "", [], {}):
                return "—"
            try:
                return f"{int(round(float(value) * 100))}%"
            except (TypeError, ValueError):
                return str(value)

        def format_probability_percent(value):
            if value in (None, "", [], {}):
                return "â€”"
            try:
                numeric = float(value)
                if numeric <= 1.0:
                    numeric *= 100.0
                return f"{int(round(numeric))}%"
            except (TypeError, ValueError):
                return str(value)

        def format_count_pairs(items, normalize_label=False):
            formatted = []
            for item in list(items or []):
                if not isinstance(item, (list, tuple)) or len(item) < 2:
                    continue
                label = str(item[0] or "Unknown").strip() or "Unknown"
                if normalize_label:
                    label = self.format_field(label)
                formatted.append(f"{label} ({item[1]})")
            return formatted

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

        self.ensure_admin_history_cache()

        office_profile = load_office_profile()
        current_snapshot = build_full_cross_office_snapshot()
        current_snapshot_summary = dict(current_snapshot.get("summary") or {})
        snapshot_file_exists = os.path.exists(SNAPSHOT_OUTPUT_PATH)
        imported_snapshot_paths = list_imported_snapshot_files()
        imported_snapshot_rows = []
        imported_office_count = 0

        for snapshot_path in imported_snapshot_paths:
            try:
                snapshot = load_cross_office_snapshot(snapshot_path)
            except Exception:
                continue

            office = dict(snapshot.get("office") or {})
            summary = dict(snapshot.get("summary") or {})
            imported_snapshot_rows.append(
                [
                    office.get("office_name") or "Unknown Office",
                    office.get("organization_id") or "Unknown Org",
                    snapshot.get("generated_at") or "Unknown",
                    summary.get("packet_count") or 0,
                    format_score_value(summary.get("average_packet_score")),
                ]
            )
            imported_office_count += 1

        network_rollup = load_network_rollup()
        network_office_rankings = list((network_rollup or {}).get("office_rankings") or [])
        network_office_count = int((network_rollup or {}).get("office_count") or 0) if isinstance(network_rollup, dict) else 0
        network_live = imported_office_count > 0 or network_office_count > 1
        network_status = "Ready" if network_live else ("Local Preview" if network_rollup else "Waiting For Imports")
        network_total_packets = (network_rollup or {}).get("total_packet_count")
        network_average_score = (network_rollup or {}).get("average_packet_score")
        network_average_runtime = (network_rollup or {}).get("average_runtime_seconds")
        network_generated_at = (network_rollup or {}).get("generated_at")
        network_office_count = (network_rollup or {}).get("office_count")
        network_org_count = (network_rollup or {}).get("organization_count")

        last_snapshot_exported = "Not exported yet"
        if snapshot_file_exists:
            try:
                last_snapshot_exported = datetime.fromtimestamp(
                    os.path.getmtime(SNAPSHOT_OUTPUT_PATH)
                ).strftime("%b %d, %Y %I:%M %p")
            except OSError:
                last_snapshot_exported = "Exported"
        try:
            cross_office_intelligence = build_local_cross_office_intelligence(include_current_office=True)
        except Exception:
            cross_office_intelligence = {}
        active_network_package = load_active_network_intelligence_package()
        active_network_package_payload = dict((active_network_package or {}).get("payload") or {})
        imported_network_intelligence = dict(active_network_package_payload.get("cross_office_intelligence") or {})
        imported_network_rollup = dict(active_network_package_payload.get("network_rollup") or {})

        network_tiles = [
            {
                "title": "Office Snapshot",
                "value": "Ready",
                "subtitle": office_profile.get("office_name") or "Current office profile loaded",
                "accent": "#57B6FF",
            },
            {
                "title": "Imported Snapshots",
                "value": imported_office_count,
                "subtitle": "De-identified office feeds stored locally",
                "accent": "#2DCE89" if imported_office_count else "#9CA3AF",
            },
            {
                "title": "Network Rollup",
                "value": network_status,
                "subtitle": network_generated_at or ("Local office cache is ready" if network_rollup else "Build after imports to unlock comparison"),
                "accent": "#F2C94C" if network_live else ("#57B6FF" if network_rollup else "#F2994A"),
            },
            {
                "title": "Network Offices",
                "value": network_office_count if network_live else imported_office_count + 1,
                "subtitle": f"{network_org_count or 1} organizations in view",
                "accent": "#9B8CFF",
            },
            {
                "title": "Network Packets",
                "value": network_total_packets if network_live else current_snapshot_summary.get("packet_count", 0),
                "subtitle": "Combined learning volume",
                "accent": "#57B6FF",
            },
            {
                "title": "Avg Network Score",
                "value": format_score_value(network_average_score if network_live else current_snapshot_summary.get("average_packet_score")),
                "subtitle": self.format_runtime_value(network_average_runtime) + " average runtime" if network_live else "Current office preview",
                "accent": "#F2C94C",
            },
        ]

        snapshot_status_rows = [
            ("Office Profile", office_profile.get("office_name")),
            ("Organization ID", office_profile.get("organization_id")),
            ("Office ID", office_profile.get("office_id")),
            ("Install ID", office_profile.get("install_id")),
            ("Office Profile Path", OFFICE_PROFILE_PATH),
            ("Snapshot File Status", "Exported" if snapshot_file_exists else "Not exported yet"),
            ("Snapshot Output Path", SNAPSHOT_OUTPUT_PATH),
            ("Imported Snapshot Folder", IMPORTED_SNAPSHOT_DIR),
            ("Imported Snapshot Count", imported_office_count),
            ("Network Rollup Status", network_status),
            ("Network Rollup Path", NETWORK_ROLLUP_OUTPUT_PATH),
        ]

        network_status_html = ""
        if not network_rollup:
            network_status_html = self.build_detail_card(
                "Cross-Office Rollup Status",
                "<div style=\"color:#9CA3AF; line-height:1.5;\">"
                "Import other office snapshots and build a network rollup to unlock cross-office rankings, "
                "workflow graphs, and organization-level quality benchmarking."
                "</div>",
                accent_color="#F2994A",
            )

        imported_library_html = self.build_html_grid_table(
            ["Office", "Organization", "Imported", "Packets", "Avg Score"],
            imported_snapshot_rows,
            column_colors=["#FFFFFF", "#57B6FF", "#9CA3AF", "#DCE6F2", "#F2C94C"],
        ) if imported_snapshot_rows else "<div style=\"color:#9CA3AF;\">No imported office snapshots yet.</div>"

        office_ranking_rows = []
        for index, office_rollup in enumerate(network_office_rankings, start=1):
            top_issue = "—"
            top_issues = list(office_rollup.get("top_issues") or [])
            if top_issues:
                lead_issue = top_issues[0]
                if isinstance(lead_issue, (list, tuple)) and len(lead_issue) >= 2:
                    top_issue = f"{lead_issue[0]} ({lead_issue[1]})"

            office_ranking_rows.append(
                [
                    index,
                    office_rollup.get("office_name") or office_rollup.get("office_id") or "Unknown Office",
                    self.format_field(office_rollup.get("standing") or "unknown"),
                    office_rollup.get("packet_count") or 0,
                    format_score_value(office_rollup.get("average_packet_score")),
                    format_confidence_percent(office_rollup.get("average_packet_confidence")),
                    self.format_runtime_value(office_rollup.get("average_runtime_seconds")),
                    top_issue,
                ]
            )

        intelligence_summary = dict((cross_office_intelligence or {}).get("network_summary") or {})
        priority_alert_groups = []
        for alert in list((cross_office_intelligence or {}).get("priority_alerts") or []):
            severity = self.format_field(alert.get("severity") or "notice")
            office_name = alert.get("office_name") or "Unknown Office"
            priority_alert_groups.append(
                {
                    "title": f"{severity}: {alert.get('title') or 'Network attention item'} | {office_name}",
                    "details": [alert.get("message") or ""],
                }
            )

        momentum_rows = []
        for office_history in list((cross_office_intelligence or {}).get("office_histories") or [])[:6]:
            current_state = dict(office_history.get("current") or {})

            def format_delta(value, suffix=""):
                if value in (None, ""):
                    return "—"
                try:
                    numeric = float(value)
                except Exception:
                    return str(value)
                prefix = "+" if numeric > 0 else ""
                return f"{prefix}{numeric:.1f}{suffix}"

            momentum_rows.append(
                [
                    current_state.get("office_name") or current_state.get("office_id") or "Unknown Office",
                    current_state.get("average_packet_score"),
                    format_delta(office_history.get("score_delta")),
                    self.format_runtime_value(current_state.get("average_runtime_seconds")),
                    format_delta(office_history.get("runtime_delta"), "s"),
                    f"{int(round((current_state.get('high_risk_share') or 0) * 100))}%",
                ]
            )

        network_signal_rows = [
            ("Source Snapshots", (cross_office_intelligence or {}).get("source_snapshot_count")),
            ("Current Offices In View", (cross_office_intelligence or {}).get("current_office_count")),
            ("Best Current Office", intelligence_summary.get("best_office") or "—"),
            ("Network Average Score", format_score_value(intelligence_summary.get("network_average_score"))),
            ("Network Average Runtime", self.format_runtime_value(intelligence_summary.get("network_average_runtime"))),
            ("Network Average Confidence", format_confidence_percent(intelligence_summary.get("network_average_confidence"))),
        ]

        hybrid_package_status_rows = [
            ("Office Sync Package", "Ready" if os.path.exists(OFFICE_SYNC_PACKAGE_PATH) else "Not exported yet"),
            ("Office Sync Path", OFFICE_SYNC_PACKAGE_PATH),
            ("Network Intelligence Package", "Active" if active_network_package else "Not imported"),
            ("Active Network Package Path", ACTIVE_NETWORK_INTELLIGENCE_PACKAGE_PATH),
            ("Imported Package Generated", (active_network_package or {}).get("generated_at") or "—"),
            ("Imported Package Source", (active_network_package or {}).get("source", {}).get("office_name") or "—"),
            ("Imported Package Offices", imported_network_rollup.get("office_count") or "—"),
            ("Imported Package Alerts", len(list(imported_network_intelligence.get("priority_alerts") or []))),
        ]

        improving_items = [
            f"{item.get('office_name')}: {('+' if (item.get('score_delta') or 0) > 0 else '')}{item.get('score_delta')} score delta"
            for item in list((cross_office_intelligence or {}).get("most_improved") or [])
            if item.get("score_delta") not in (None, "")
        ]
        declining_items = [
            f"{item.get('office_name')}: {item.get('score_delta')} score delta"
            for item in list((cross_office_intelligence or {}).get("most_declined") or [])
            if item.get("score_delta") not in (None, "")
        ]

        imported_package_alert_groups = []
        for alert in list(imported_network_intelligence.get("priority_alerts") or []):
            imported_package_alert_groups.append(
                {
                    "title": f"{self.format_field(alert.get('severity') or 'notice')}: {alert.get('title') or 'Imported network insight'}",
                    "details": [alert.get("message") or ""],
                }
            )

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

        predictive_learning_rows = [
            ("Model Availability", "Active" if predictive_model_summary.get("available") else "Learning"),
            ("Learning Approach", self.format_field(predictive_model_summary.get("model_type") or predictive_model_summary.get("reason") or "insufficient_history")),
            ("Labeled Outcomes", predictive_model_summary.get("sample_size") or 0),
            ("Approval Base Rate", format_probability_percent(predictive_model_summary.get("positive_rate"))),
            ("Reliability", self.format_field(predictive_model_summary.get("reliability_band") or outcome_learning_health.get("reliability_band") or "early")),
            ("Reliability Score", predictive_model_summary.get("reliability_score") if predictive_model_summary.get("reliability_score") not in (None, "") else outcome_learning_health.get("reliability_score")),
            ("Probability Accuracy", predictive_model_summary.get("brier_score")),
            ("Confidence Honesty Gap", predictive_model_summary.get("ece")),
            ("Sorting Strength", predictive_model_summary.get("roc_auc")),
            ("Learning Maturity", self.format_field(outcome_learning_health.get("maturity_band") or "early")),
        ]

        validation_quality_rows = [
            ("Ready Calls That Were Right", format_probability_percent(predictive_validation_summary.get("ready_call_accuracy"))),
            ("Review Calls That Were Right", format_probability_percent(predictive_validation_summary.get("review_call_accuracy"))),
            ("Ready Packets The Model Caught", format_probability_percent(predictive_validation_summary.get("ready_capture_rate"))),
            ("Problem Packets The Model Caught", format_probability_percent(predictive_validation_summary.get("problem_catch_rate"))),
            ("False-Ready Risk", format_probability_percent(predictive_validation_summary.get("false_ready_rate"))),
            ("Validation Sample", predictive_validation_summary.get("sample_size") or 0),
            ("Decision Threshold", format_probability_percent(predictive_validation_summary.get("decision_threshold"))),
            ("Validation Strength", self.format_field(predictive_validation_summary.get("status") or "early")),
        ]

        threshold_guidance_rows = [
            ("Current Trust Threshold", format_probability_percent(predictive_threshold_guidance.get("current_threshold"))),
            ("Suggested Trust Threshold", format_probability_percent(predictive_threshold_guidance.get("suggested_threshold"))),
            ("Suggested Posture", self.format_field(predictive_threshold_guidance.get("posture") or "too_early")),
            ("Current False-Ready Risk", format_probability_percent(predictive_threshold_guidance.get("current_false_ready_rate"))),
            ("Suggested False-Ready Risk", format_probability_percent(predictive_threshold_guidance.get("suggested_false_ready_rate"))),
            ("Current Ready Capture", format_probability_percent(predictive_threshold_guidance.get("current_ready_capture_rate"))),
            ("Suggested Ready Capture", format_probability_percent(predictive_threshold_guidance.get("suggested_ready_capture_rate"))),
        ]

        outcome_activity_rows = [
            ("Approved Outcomes", outcome_learning_health.get("approval_count") or 0),
            ("Denied Outcomes", outcome_learning_health.get("denial_count") or 0),
            ("Corrected Outcomes", outcome_learning_health.get("correction_count") or 0),
            ("Resubmitted Outcomes", outcome_learning_health.get("resubmission_count") or 0),
            ("Reviewer Overrides", outcome_learning_health.get("override_count") or 0),
            ("Deferred Outcomes", outcome_learning_health.get("deferred_count") or 0),
        ]

        predictive_guidance = []
        if not predictive_model_summary.get("available"):
            predictive_guidance.append("Add more real approved and denied outcomes to activate learned probability modeling.")
        if str(predictive_model_summary.get("reliability_band") or outcome_learning_health.get("reliability_band") or "").lower() == "low":
            predictive_guidance.append("Prediction reliability is still low, so approval signals should be treated as directional support.")
        if predictive_threshold_guidance.get("guidance"):
            predictive_guidance.append(str(predictive_threshold_guidance.get("guidance")))
        if predictive_validation_summary.get("false_ready_rate") is not None and float(predictive_validation_summary.get("false_ready_rate") or 0.0) > 0.2:
            predictive_guidance.append("False-ready risk is still high, so auto-ready style trust should stay conservative.")
        if predictive_validation_summary.get("sample_size", 0) < 12:
            predictive_guidance.append("Validation history is still small, so quality metrics should be treated as early signals rather than settled truth.")
        if outcome_learning_health.get("correction_count", 0) + outcome_learning_health.get("resubmission_count", 0) >= 3:
            predictive_guidance.append("Correction and resubmission volume is high enough to justify stronger pre-submit safeguards.")
        if outcome_learning_health.get("override_count", 0) >= 2:
            predictive_guidance.append("Reviewer overrides are recurring, which suggests policy or routing rules should be revisited.")

        operations_guide_items = [
            "Office Profile Editor: lets you set the real office identity, rollout tier, support contact, and launcher username hint for this install.",
            "Install Profile: refreshes the local record of this office's version, build, install, and learning state.",
            "Support Package: exports a troubleshooting snapshot you can share internally without digging through folders by hand.",
            "Archive + Reset Local PHI: creates a de-identified archive first, then resets local PHI-bearing history for this install.",
            "Rollout Readiness: shows whether this install is in good shape for broader deployment and support.",
            "Office Rollout Status: shows how far this office has moved through onboarding and real-world usage milestones.",
            "Learning Model Status: shows how much real outcome history exists and how trustworthy the learned prediction layer is.",
            "Prediction Quality Checks: show, in plain English, how often the model's ready and review calls have been right so far.",
            "Recent Packet Runs and Slowest Recent Packets: help you understand live workload and bottlenecks.",
        ]

        local_phi_status = build_local_phi_storage_status()
        memory_storage = dict(local_phi_status.get("memory_database") or {})
        workbook_storage = dict(local_phi_status.get("legacy_workbook") or {})

        def format_size_bytes(value):
            try:
                size = int(value or 0)
            except Exception:
                size = 0

            if size >= 1024 * 1024:
                return f"{round(size / (1024 * 1024), 2)} MB"
            if size >= 1024:
                return f"{round(size / 1024, 2)} KB"
            return f"{size} bytes"

        privacy_storage_rows = [
            ("Memory Storage Mode", "De-identified local history"),
            ("Local Memory Database", "Present" if memory_storage.get("exists") else "Missing"),
            ("Memory Database Size", format_size_bytes(memory_storage.get("size_bytes"))),
            ("Retired Workbook", "Present" if workbook_storage.get("exists") else "Removed"),
            ("Workbook Size", format_size_bytes(workbook_storage.get("size_bytes"))),
            ("Memory Database Path", memory_storage.get("path") or "Unknown"),
            ("Reset Archive Folder", local_phi_status.get("privacy_reset_archive_dir") or "Unknown"),
            ("De-Identified Export Policy", "Active"),
        ]

        privacy_warning_items = [
            "Archive + Reset Local PHI is a controlled privacy reset, not a routine cleanup button.",
            "It creates a de-identified archive first, then removes the local memory database and the retired workbook from this install.",
            "That reset reduces local learning history for this office until new packets and real outcomes are recorded again.",
            "Use it only under the office's retention policy and compliance direction. It should not replace the office's official medical-record or audit-retention process.",
        ]

        deployment_readiness_rows = [
            ("Scale Readiness", self.format_field(platform_readiness.get("band") or "foundational")),
            ("Readiness Score", platform_readiness.get("score")),
            ("Office Rollout Status", self.format_field(rollout_summary.get("band") or "starter")),
            ("Onboarding Progress", f"{rollout_summary.get('completed_steps', 0)}/{rollout_summary.get('total_steps', 0)}"),
            ("Version", deployment_platform.get("version") or self.version),
            ("Build ID", deployment_platform.get("build_id") or self.build_id or "Unknown"),
            ("Office", deployment_details.get("office_name") or office_profile.get("office_name") or "Default Office"),
            ("Install ID", deployment_details.get("install_id") or office_profile.get("install_id") or "Unknown"),
            ("Runtime Mode", "Packaged" if deployment_platform.get("frozen") else "Source"),
            ("Release Manifest", "Available" if deployment_details.get("release_manifest_available") else "Pending"),
        ]

        rollout_status_rows = [
            ("Rollout Tier", self.format_field(deployment_details.get("rollout_tier") or office_profile.get("rollout_tier") or "single_office")),
            ("Office Identity Configured", "Yes" if rollout_summary.get("office_identity_configured") else "No"),
            ("Docs Kit Exported", "Yes" if rollout_summary.get("docs_kit_exported") else "No"),
            ("Launcher Credential Mode", self.format_field((rollout_summary.get("credential_policy") or {}).get("mode") or "local_install_shared")),
            ("Launcher Username", (rollout_summary.get("credential_policy") or {}).get("username_hint") or "Not set"),
            ("First Packet Analyzed", "Yes" if rollout_summary.get("first_packet_analyzed") else "No"),
            ("First Real Outcome Recorded", "Yes" if rollout_summary.get("first_real_outcome_recorded") else "No"),
        ]

        rollout_checklist_groups = [
            (
                item.get("label"),
                [
                    (
                        "Completed" if item.get("complete") else "Pending"
                    )
                    + (f" | {item.get('detail')}" if item.get("detail") not in (None, "", False) else "")
                ],
            )
            for item in list(rollout_summary.get("checklist") or [])
        ]

        deployment_asset_rows = [
            ("Deployment Manifest Path", DEPLOYMENT_MANIFEST_PATH),
            ("Support Bundle Path", SUPPORT_BUNDLE_OUTPUT_PATH),
            ("Snapshot Export Path", deployment_details.get("snapshot_output_path") or SNAPSHOT_OUTPUT_PATH),
            ("Imported Snapshot Count", deployment_data_state.get("imported_snapshot_count") or 0),
            ("Network Rollup Status", self.format_field(deployment_data_state.get("network_rollup_status") or "pending")),
            ("Active Network Package", self.format_field(deployment_data_state.get("active_network_package_status") or "pending")),
            ("Update Channel", deployment_details.get("update_channel")),
            ("Runtime Root", deployment_platform.get("runtime_root")),
        ]

        platform_actions = []
        if not deployment_details.get("release_manifest_available"):
            platform_actions.append("Next release build should publish release manifest metadata for cleaner deployment traceability.")
        if not predictive_model_summary.get("available"):
            platform_actions.append("Support teams should keep recording real outcomes so predictive learning matures at each office.")
        if (deployment_data_state.get("imported_snapshot_count") or 0) == 0:
            platform_actions.append("Cross-office benchmarking is ready, but no external office snapshots have been imported yet.")
        platform_actions.extend(list(rollout_summary.get("recommended_actions") or []))

        cross_office_sections = [
            self.build_detail_card(
                "Cross-Office Intelligence Overview",
                self.build_metric_tiles(network_tiles),
                accent_color="#2DCE89",
                margin_top=0,
            ),
            self.build_detail_card(
                "Network Data Profile",
                self.build_detail_table(snapshot_status_rows, value_color="#57B6FF"),
                accent_color="#57B6FF",
            ),
            self.build_detail_card(
                "Hybrid Package Status",
                self.build_detail_table(hybrid_package_status_rows, value_color="#57B6FF"),
                accent_color="#9B8CFF",
            ),
            network_status_html,
            self.build_detail_card(
                "Imported Office Snapshot Library",
                imported_library_html,
                accent_color="#2DCE89",
            ),
            self.build_detail_card(
                "Central Network Signals",
                self.build_detail_table(network_signal_rows, value_color="#57B6FF"),
                accent_color="#57B6FF",
            ),
            self.build_issue_breakdown_section(
                "Priority Attention Items",
                priority_alert_groups,
                color="#F2C94C",
                accent_color="#F2994A",
                bullet="•",
            ),
            self.build_issue_breakdown_section(
                "Imported Network Package Alerts",
                imported_package_alert_groups,
                color="#57B6FF",
                accent_color="#57B6FF",
                bullet="•",
            ),
            self.build_detail_card(
                "Office Momentum",
                self.build_html_grid_table(
                    ["Office", "Current Score", "Score Delta", "Avg Runtime", "Runtime Delta", "High-Risk Share"],
                    momentum_rows,
                    column_colors=["#FFFFFF", "#F2C94C", "#57B6FF", "#9B8CFF", "#2DCE89", "#EB5757"],
                ),
                accent_color="#2DCE89",
            ),
            self.build_bullet_section(
                "Most Improved Offices",
                improving_items,
                color="#2DCE89",
                accent_color="#2DCE89",
                bullet="•",
            ),
            self.build_bullet_section(
                "Most At-Risk Declines",
                declining_items,
                color="#EB5757",
                accent_color="#EB5757",
                bullet="•",
            ),
        ]

        if network_live:
            cross_office_sections.extend(
                [
                    self.build_detail_card(
                        "Office Rankings",
                        self.build_html_grid_table(
                            ["Rank", "Office", "Standing", "Packets", "Avg Score", "Avg Confidence", "Avg Runtime", "Top Issue"],
                            office_ranking_rows,
                            column_colors=["#9CA3AF", "#FFFFFF", "#57B6FF", "#DCE6F2", "#F2C94C", "#2DCE89", "#9B8CFF", "#DCE6F2"],
                        ),
                        accent_color="#F2C94C",
                    ),
                    self.build_distribution_bar_card(
                        "Workflow Distribution",
                        (network_rollup or {}).get("workflow_distribution"),
                        accent_color="#57B6FF",
                    ),
                    self.build_distribution_bar_card(
                        "Denial Risk Distribution",
                        (network_rollup or {}).get("denial_risk_distribution"),
                        accent_color="#EB5757",
                    ),
                    self.build_distribution_bar_card(
                        "Manual Outcome Distribution",
                        (network_rollup or {}).get("manual_outcome_distribution"),
                        accent_color="#2DCE89",
                    ),
                    self.build_bullet_section(
                        "Cross-Office Top Issues",
                        format_count_pairs((network_rollup or {}).get("top_issues")),
                        color="#F2C94C",
                        accent_color="#F2994A",
                    ),
                    self.build_bullet_section(
                        "Cross-Office Document Mix",
                        format_count_pairs((network_rollup or {}).get("top_document_families"), normalize_label=True),
                        color="#57B6FF",
                        accent_color="#57B6FF",
                    ),
                ]
            )
        else:
            cross_office_sections.extend(
                [
                    self.build_distribution_bar_card(
                        "Current Office Workflow Distribution",
                        current_snapshot_summary.get("workflow_distribution"),
                        accent_color="#57B6FF",
                    ),
                    self.build_distribution_bar_card(
                        "Current Office Denial Risk Distribution",
                        current_snapshot_summary.get("denial_risk_distribution"),
                        accent_color="#EB5757",
                    ),
                    self.build_bullet_section(
                        "Current Office Top Issues",
                        format_count_pairs(current_snapshot_summary.get("top_issues")),
                        color="#F2C94C",
                        accent_color="#F2994A",
                    ),
                ]
            )

        snapshot_help_items = [
            "Export Office Snapshot creates a de-identified summary of this office's packet history.",
            "Import Office Snapshots pulls in de-identified summaries from other offices.",
            "TrueCore refreshes the office comparison automatically after every import.",
        ]

        current_office_rows = [
            ("Office", office_profile.get("office_name") or "Default Office"),
            ("Organization", office_profile.get("organization_id") or "Unknown"),
            ("Office ID", office_profile.get("office_id") or "Unknown"),
            ("Packets In Snapshot", current_snapshot_summary.get("packet_count") or 0),
            ("Average Score", format_score_value(current_snapshot_summary.get("average_packet_score"))),
            ("Average Runtime", self.format_runtime_value(current_snapshot_summary.get("average_runtime_seconds"))),
            ("Last Snapshot Export", last_snapshot_exported),
        ]

        comparison_summary_rows = [
            ("Comparison Status", network_status),
            ("Imported Offices", imported_office_count),
            ("Offices In View", network_office_count if network_live else 1),
            ("Packets In View", network_total_packets if network_live else current_snapshot_summary.get("packet_count", 0)),
            ("Average Score", format_score_value(network_average_score if network_live else current_snapshot_summary.get("average_packet_score"))),
            ("Average Runtime", self.format_runtime_value(network_average_runtime if network_live else current_snapshot_summary.get("average_runtime_seconds"))),
            ("Last Comparison Refresh", network_generated_at or ("Updates automatically after import" if imported_office_count else "Waiting for imported snapshots")),
        ]

        comparison_table_html = self.build_html_grid_table(
            ["Rank", "Office", "Standing", "Packets", "Avg Score", "Avg Runtime"],
            [[row[0], row[1], row[2], row[3], row[4], row[6]] for row in office_ranking_rows],
            column_colors=["#9CA3AF", "#FFFFFF", "#57B6FF", "#DCE6F2", "#F2C94C", "#9B8CFF"],
        ) if network_live else (
            "<div style=\"color:#9CA3AF; line-height:1.5;\">"
            "Import another office snapshot to unlock the office comparison table here."
            "</div>"
        )

        comparison_issue_title = "Recurring Issues Across Offices" if network_live else "Current Office Top Issues"
        comparison_issue_items = format_count_pairs(
            (network_rollup or {}).get("top_issues") if network_live else current_snapshot_summary.get("top_issues")
        )

        cross_office_sections = [
            self.build_bullet_section(
                "How Snapshot Sharing Works",
                snapshot_help_items,
                color="#57B6FF",
                accent_color="#57B6FF",
                bullet="•",
            ),
            self.build_detail_card(
                "Current Office Snapshot",
                self.build_detail_table(current_office_rows, value_color="#57B6FF"),
                accent_color="#2DCE89",
            ),
            self.build_detail_card(
                "Imported Offices",
                imported_library_html,
                accent_color="#2DCE89",
            ),
            self.build_detail_card(
                "Comparison Summary",
                self.build_detail_table(comparison_summary_rows, value_color="#57B6FF"),
                accent_color="#F2C94C",
            ),
            self.build_detail_card(
                "Office Comparison",
                comparison_table_html,
                accent_color="#F2C94C",
            ),
            self.build_bullet_section(
                comparison_issue_title,
                comparison_issue_items,
                color="#F2C94C",
                accent_color="#F2994A",
                bullet="•",
            ),
        ]

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

        operations_sections = [
            self.build_bullet_section(
                "How To Use Operations",
                operations_guide_items,
                color="#57B6FF",
                accent_color="#57B6FF",
            ),
            self.build_detail_card(
                "Local Operations Overview",
                self.build_metric_tiles(overview_tiles),
                accent_color="#57B6FF",
                margin_top=0,
            ),
            self.build_detail_card(
                "System Snapshot",
                self.build_detail_table(
                    [
                        ("Engine Version", self.version),
                        ("Build Time", self.build_timestamp or "Unknown"),
                        ("PHI Masking", "Active"),
                        ("Threaded Analysis", "Enabled"),
                        ("Activity Log Path", activity_path if os.path.exists(activity_path) else "Missing"),
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
                "Rollout Readiness",
                self.build_detail_table(
                    deployment_readiness_rows,
                    value_color="#2DCE89",
                    show_missing=False,
                ),
                accent_color="#2DCE89",
            ),
            self.build_detail_card(
                "Office Rollout Status",
                self.build_detail_table(
                    rollout_status_rows,
                    value_color="#57B6FF",
                    show_missing=False,
                ),
                accent_color="#9B8CFF",
            ),
            self.build_issue_breakdown_section(
                "Onboarding Checklist",
                rollout_checklist_groups or [("Onboarding Checklist", ["No rollout checklist data available yet."])],
                color="#57B6FF",
                accent_color="#57B6FF",
                bullet="•",
            ),
            self.build_detail_card(
                "Support Files & Paths",
                self.build_detail_table(
                    deployment_asset_rows,
                    value_color="#57B6FF",
                    show_missing=False,
                ),
                accent_color="#57B6FF",
            ),
            self.build_detail_card(
                "Local PHI Storage",
                self.build_detail_table(
                    privacy_storage_rows,
                    value_color="#EB5757" if memory_storage.get("exists") or workbook_storage.get("exists") else "#2DCE89",
                    show_missing=False,
                ),
                accent_color="#EB5757" if memory_storage.get("exists") or workbook_storage.get("exists") else "#2DCE89",
            ),
            self.build_bullet_section(
                "Privacy Reset Warning",
                privacy_warning_items,
                color="#F2C94C",
                accent_color="#F2994A",
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
            self.build_detail_card(
                "Learning Model Status",
                self.build_detail_table(
                    predictive_learning_rows,
                    value_color="#F2994A",
                    show_missing=False,
                ),
                accent_color="#F2994A",
            ),
            self.build_detail_card(
                "Prediction Quality Checks",
                self.build_detail_table(
                    validation_quality_rows,
                    value_color="#F2C94C",
                    show_missing=False,
                ),
                accent_color="#F2C94C",
            ),
            self.build_detail_card(
                "Ready-Call Guardrails",
                self.build_detail_table(
                    threshold_guidance_rows,
                    value_color="#57B6FF",
                    show_missing=False,
                ),
                accent_color="#57B6FF",
            ),
            self.build_detail_card(
                "Recorded Real Outcomes",
                self.build_detail_table(
                    outcome_activity_rows,
                    value_color="#F2994A",
                    show_missing=False,
                ),
                accent_color="#F2994A",
            ),
            self.build_bullet_section(
                "Learning Guidance",
                predictive_guidance or ["Prediction learning is stable with no immediate watchpoints."],
                color="#F2994A",
                accent_color="#F2994A",
            ),
            self.build_bullet_section(
                "Recommended Next Steps",
                platform_actions or ["Deployment manifest and support bundle flow are ready for use."],
                color="#2DCE89",
                accent_color="#2DCE89",
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
        ]

        audit_sections = [
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
                margin_top=0,
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

        def wrap_sections(section_list):
            return (
                "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
                "font-family:'Segoe UI'; font-size:13px; line-height:1.45; margin:0; text-align:left;\">"
                + "".join(section for section in section_list if section)
                + "</body></html>"
            )

        return {
            "cross_office": wrap_sections(cross_office_sections),
            "operations": wrap_sections(operations_sections),
            "audit": wrap_sections(audit_sections),
        }

    def refresh_admin_panel(self):
        dashboard_error = None

        try:
            self.ensure_admin_history_cache()
        except Exception:
            pass

        try:
            self.populate_admin_dashboard()
        except Exception as exc:
            dashboard_error = exc

        if not any([self.admin_cross_office_text, self.admin_operations_text, self.admin_audit_text]):
            return

        try:
            views = self.build_admin_panel_views()

            if self.admin_cross_office_text:
                self.admin_cross_office_text.setHtml(views.get("cross_office", ""))

            if self.admin_operations_text:
                self.admin_operations_text.setHtml(views.get("operations", ""))

            if self.admin_audit_text:
                self.admin_audit_text.setHtml(views.get("audit", ""))

        except Exception as exc:
            if dashboard_error is not None:
                exc = dashboard_error
            error_html = (
                "<html><body style=\"background-color:#11161E; color:#E5E7EB; "
                "font-family:'Segoe UI'; font-size:13px; line-height:1.45; margin:0; text-align:left;\">"
                f"{self.build_detail_card('Admin Panel Error', '<div style=\"color:#EB5757;\">' + html.escape(str(exc)) + '</div>', accent_color='#EB5757', margin_top=0)}"
                "</body></html>"
            )

            if self.admin_cross_office_text:
                self.admin_cross_office_text.setHtml(error_html)
            if self.admin_operations_text:
                self.admin_operations_text.setHtml(error_html)
            if self.admin_audit_text:
                self.admin_audit_text.setHtml(error_html)

    def export_office_snapshot_action(self):

        try:
            output_path = export_cross_office_snapshot()
            log_event("cross_office_snapshot_exported", output_path)
            self.refresh_admin_panel()
            self.show_admin_message(
                "Office Snapshot Exported",
                f"De-identified office snapshot exported successfully.\n\n{output_path}",
            )
        except Exception as exc:
            self.show_admin_message("Snapshot Export Failed", str(exc), icon=QMessageBox.Warning)

    def import_cross_office_snapshots_action(self):

        start_dir = os.path.dirname(SNAPSHOT_OUTPUT_PATH)
        paths = self.get_admin_open_file_names(
            "Import Office Snapshots",
            start_dir,
            "JSON Files (*.json)",
        )

        if not paths:
            return

        try:
            imported_paths = import_cross_office_snapshot_files(paths)
            output_path = build_local_network_rollup(include_current_office=True)
            rollup = load_network_rollup(output_path) or {}
            log_event(
                "cross_office_snapshots_imported",
                f"{len(imported_paths)} snapshots | comparison refreshed for {rollup.get('office_count', 0)} offices",
            )
            self.refresh_admin_panel()
            self.show_admin_message(
                "Snapshots Imported",
                f"Imported {len(imported_paths)} de-identified office snapshot(s).\n\n"
                f"TrueCore refreshed the comparison view automatically for {rollup.get('office_count', 0)} office(s).",
            )
        except Exception as exc:
            self.show_admin_message("Snapshot Import Failed", str(exc), icon=QMessageBox.Warning)

    def build_network_rollup_action(self):

        try:
            output_path = build_local_network_rollup(include_current_office=True)
            rollup = load_network_rollup(output_path) or {}
            log_event(
                "cross_office_network_rollup_built",
                f"{rollup.get('office_count', 0)} offices | {rollup.get('total_packet_count', 0)} packets",
            )
            self.refresh_admin_panel()
            self.show_admin_message(
                "Network Rollup Built",
                f"Built a network rollup for {rollup.get('office_count', 0)} office(s) across "
                f"{rollup.get('organization_count', 0)} organization(s).\n\n{output_path}",
            )
        except Exception as exc:
            self.show_admin_message("Network Rollup Failed", str(exc), icon=QMessageBox.Warning)

    def export_office_sync_package_action(self):

        try:
            output_path = export_office_sync_package()
            log_event("hybrid_office_sync_package_exported", output_path)
            self.refresh_admin_panel()
            self.show_admin_message(
                "Office Sync Package Exported",
                f"Hybrid office sync package exported successfully.\n\n{output_path}",
            )
        except Exception as exc:
            self.show_admin_message("Office Sync Export Failed", str(exc), icon=QMessageBox.Warning)

    def import_network_intelligence_package_action(self):

        start_dir = os.path.dirname(NETWORK_INTELLIGENCE_PACKAGE_PATH)
        paths = self.get_admin_open_file_names(
            "Import Network Intelligence Package",
            start_dir,
            "JSON Files (*.json)",
        )

        if not paths:
            return

        try:
            imported_path = import_network_intelligence_package(paths[0])
            log_event("hybrid_network_package_imported", imported_path)
            self.refresh_admin_panel()
            self.show_admin_message(
                "Network Intelligence Imported",
                f"Imported and activated network intelligence package.\n\n{imported_path}",
            )
        except Exception as exc:
            self.show_admin_message("Network Package Import Failed", str(exc), icon=QMessageBox.Warning)

    def export_network_intelligence_package_action(self):

        try:
            output_path = build_local_network_intelligence_package(include_current_office=True)
            log_event("hybrid_network_package_exported", output_path)
            self.refresh_admin_panel()
            self.show_admin_message(
                "Network Intelligence Package Exported",
                f"Built and exported a hybrid network intelligence package.\n\n{output_path}",
            )
        except Exception as exc:
            self.show_admin_message("Network Package Export Failed", str(exc), icon=QMessageBox.Warning)

    def open_cross_office_data_folder_action(self):

        try:
            output_folder = os.path.dirname(NETWORK_ROLLUP_OUTPUT_PATH)
            os.makedirs(output_folder, exist_ok=True)
            if hasattr(os, "startfile"):
                os.startfile(output_folder)
            else:
                self.show_admin_message("Cross-Office Data Folder", output_folder)
        except Exception as exc:
            self.show_admin_message("Unable To Open Folder", str(exc), icon=QMessageBox.Warning)

    def refresh_deployment_manifest_action(self):

        try:
            output_path, manifest = write_deployment_manifest()
            self.build_id, self.build_timestamp = get_build_info()
            log_event(
                "deployment_manifest_refreshed",
                f"{manifest.get('platform', {}).get('version', 'unknown')} | {manifest.get('platform_readiness', {}).get('band', 'foundational')}",
            )
            self.refresh_admin_panel()
            self.show_admin_message(
                "Install Profile Refreshed",
                "The local install profile was refreshed successfully.\n\n"
                "This file records the version, build, office identity, and current learning state for this install.\n\n"
                f"{output_path}",
            )
        except Exception as exc:
            self.show_admin_message("Install Profile Refresh Failed", str(exc), icon=QMessageBox.Warning)

    def export_support_bundle_action(self):

        try:
            output_path = export_support_bundle()
            log_event("support_bundle_exported", output_path)
            self.refresh_admin_panel()
            self.show_admin_message(
                "Support Package Exported",
                "A support package was exported successfully.\n\n"
                "It contains de-identified deployment, office, network, and recent activity summaries so support can understand this install quickly without exposing raw patient file names.\n\n"
                f"{output_path}",
            )
        except Exception as exc:
            self.show_admin_message("Support Package Export Failed", str(exc), icon=QMessageBox.Warning)

    def open_support_data_folder_action(self):

        try:
            output_folder = os.path.dirname(SUPPORT_BUNDLE_OUTPUT_PATH)
            os.makedirs(output_folder, exist_ok=True)
            if hasattr(os, "startfile"):
                os.startfile(output_folder)
            else:
                self.show_admin_message("Support Files Folder", output_folder)
        except Exception as exc:
            self.show_admin_message("Unable To Open Support Folder", str(exc), icon=QMessageBox.Warning)

    def archive_and_reset_local_phi_action(self):

        should_purge = self.confirm_admin_action(
            "Archive And Reset Local PHI",
            "This will first create a de-identified archive, then delete the local packet memory database and the retired Excel workbook from this install.",
            "Use this only under the office's retention policy and compliance direction. This tool resets local learning history and should not be treated as a substitute for the office's official record-retention process.",
            confirm_label="Archive And Reset",
        )

        if not should_purge:
            return

        try:
            archive_path = export_local_phi_reset_archive()
            outcome = purge_local_phi_storage()
            removed_paths = list(outcome.get("removed_paths") or [])
            log_event(
                "local_phi_storage_purged",
                f"Archived and removed {len(removed_paths)} local storage file(s).",
            )
            self.refresh_admin_panel()
            message_lines = [
                "A de-identified archive was created and local PHI-bearing storage was reset successfully.",
                "",
                "Archive file:",
                archive_path,
                "",
                "Removed files:",
            ]
            if removed_paths:
                message_lines.extend(removed_paths)
            else:
                message_lines.append("Nothing needed removal.")
            self.show_admin_message("Archive And Reset Complete", "\n".join(message_lines))
        except Exception as exc:
            self.show_admin_message("Archive And Reset Failed", str(exc), icon=QMessageBox.Warning)

    def open_admin_panel(self):

        password,ok = self.prompt_admin_password()

        if not ok or not verify_admin_password(password):
            QMessageBox.warning(self,"Access Denied","Incorrect password.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("TrueCore Admin Panel")
        dialog.resize(1260, 820)
        dialog.setMinimumSize(1080, 760)
        dialog.setStyleSheet(self.admin_modal_stylesheet())

        layout = QVBoxLayout()
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        tab_widget = QTabWidget()
        tab_widget.setDocumentMode(True)
        layout.addWidget(tab_widget)

        def create_admin_text_view():
            text_view = QTextEdit()
            text_view.setReadOnly(True)
            text_view.setFont(QFont("Segoe UI", 10))
            text_view.setStyleSheet(
                "QTextEdit { background-color:#11161E; border:1px solid #253243; "
                "border-radius:8px; padding:6px; }"
            )
            return text_view

        overview_tab = QWidget()
        overview_tab.setStyleSheet("background-color:#11161E;")
        overview_layout = QVBoxLayout(overview_tab)
        overview_layout.setContentsMargins(10, 10, 10, 10)
        overview_layout.setSpacing(10)

        dashboard_host = QWidget()
        dashboard_host.setObjectName("adminDashboardHost")
        dashboard_host.setStyleSheet("QWidget#adminDashboardHost { background-color:#11161E; }")
        dashboard_layout = QVBoxLayout(dashboard_host)
        dashboard_layout.setContentsMargins(0, 0, 0, 0)
        dashboard_layout.setSpacing(10)

        dashboard_scroll = QScrollArea()
        dashboard_scroll.setWidgetResizable(True)
        dashboard_scroll.setFrameShape(QFrame.NoFrame)
        dashboard_scroll.setStyleSheet(
            "QScrollArea { background-color:#11161E; border:0; } "
            "QScrollArea > QWidget > QWidget { background-color:#11161E; }"
        )
        dashboard_scroll.setWidget(dashboard_host)
        overview_layout.addWidget(dashboard_scroll, 1)

        cross_office_tab = QWidget()
        cross_office_layout = QVBoxLayout(cross_office_tab)
        cross_office_layout.setContentsMargins(10, 10, 10, 10)
        cross_office_layout.setSpacing(10)

        snapshot_actions = [
            ("Export Office Snapshot", self.export_office_snapshot_action, "Create a de-identified snapshot of this office's packet history."),
            ("Import Office Snapshots", self.import_cross_office_snapshots_action, "Bring in de-identified snapshot files from other offices and refresh comparison automatically."),
            ("Refresh Comparison", self.refresh_admin_panel, "Refresh the snapshot and comparison view."),
        ]
        cross_office_layout.addWidget(self.build_admin_action_grid(snapshot_actions, columns=3))

        cross_office_text = create_admin_text_view()
        cross_office_layout.addWidget(cross_office_text, 1)

        operations_tab = QWidget()
        operations_layout = QVBoxLayout(operations_tab)
        operations_layout.setContentsMargins(10, 10, 10, 10)
        operations_layout.setSpacing(10)

        operations_actions = [
            ("Edit Office Profile", self.open_office_profile_editor, "Set the real office identity, rollout tier, and support contact for this install."),
            ("Refresh Install Profile", self.refresh_deployment_manifest_action, "Update the local record of version, build, office, and learning state."),
            ("Export Support Package", self.export_support_bundle_action, "Export a troubleshooting snapshot for this install."),
            ("Open Support Files", self.open_support_data_folder_action, "Open the folder that contains support and rollout files."),
            ("Archive + Reset Local PHI", self.archive_and_reset_local_phi_action, "Create a de-identified archive, then reset local PHI-bearing storage for this install."),
            ("Refresh", self.refresh_admin_panel, "Refresh the Operations tab data."),
        ]
        operations_layout.addWidget(self.build_admin_action_grid(operations_actions, columns=2))

        operations_text = create_admin_text_view()
        operations_layout.addWidget(operations_text, 1)

        audit_tab = QWidget()
        audit_layout = QVBoxLayout(audit_tab)
        audit_layout.setContentsMargins(10, 10, 10, 10)
        audit_layout.setSpacing(10)

        audit_text = create_admin_text_view()
        audit_layout.addWidget(audit_text, 1)

        tab_widget.addTab(overview_tab, "Overview")
        tab_widget.addTab(cross_office_tab, "Office Comparison")
        tab_widget.addTab(operations_tab, "Operations")
        tab_widget.addTab(audit_tab, "Audit & Logs")

        dialog.setLayout(layout)

        self.admin_dialog = dialog
        self.admin_dashboard_focus = None
        self.admin_dashboard_host = dashboard_host
        self.admin_panel_text = None
        self.admin_cross_office_text = cross_office_text
        self.admin_operations_text = operations_text
        self.admin_audit_text = audit_text
        self.refresh_admin_panel()

        dialog.exec()

        self.admin_dialog = None
        self.admin_dashboard_focus = None
        self.admin_dashboard_host = None
        self.admin_panel_text = None
        self.admin_cross_office_text = None
        self.admin_operations_text = None
        self.admin_audit_text = None
        return

    # ----------------------------------------------
    # ESCAPE KEY HANDLER
    # ----------------------------------------------

    def keyPressEvent(self, event):

        if event.key() == Qt.Key_Escape:
            self.showMaximized()
            event.accept()
