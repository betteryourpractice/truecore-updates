from PySide6.QtWidgets import (
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

from PySide6.QtGui import QIcon, QColor, QPixmap
from PySide6.QtCore import Qt, QSize, QTimer

import os
import csv
import html
from datetime import datetime

from TrueCore.utils.logging_system import log_event
from TrueCore.utils.runtime_info import (
    ensure_runtime_environment,
    get_version,
    get_build_info,
    resource_path
    
)

from TrueCore.core.packet_processor import process_packet
from TrueCore.core.packet_triage import triage_packet
from TrueCore.export.workbook_export import export_patient
from TrueCore.medical.icd_lookup import load_icd_codes


ADMIN_PASSWORD = "athena"


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        ensure_runtime_environment()

        self.version = get_version()
        _, self.build_timestamp = get_build_info()

        self.setWindowTitle(f"TrueValour Packet Auditor v{self.version}")
        self.resize(1400, 900)
        self.showFullScreen()

        icon_base = resource_path("ui/pyside_gui/assets/icons/")

        self.files = []
        self.results = {}

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

        self.btn_close = QPushButton("Exit")
        self.btn_close.setObjectName("closeButton")

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

    def build_detail_card(self, title, body_html, accent_color="#2F80ED", margin_top=12):

        return (
            f"<div style=\"margin-top:{margin_top}px; padding:12px 14px; "
            f"background-color:#10161E; border:1px solid #253243; "
            f"border-left:3px solid {accent_color}; border-radius:8px;\">"
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
                f"<td valign=\"top\" style=\"color:#FFFFFF; font-weight:600; padding:3px 12px 3px 0; width:38%;\">"
                f"{html.escape(str(label))}</td>"
                f"<td valign=\"top\" style=\"color:{row_color}; padding:3px 0;\">"
                f"{html.escape(display_value)}</td>"
                "</tr>"
            )

        if not rendered_rows:
            return "<div style=\"color:#9CA3AF;\">No data</div>"

        return (
            "<table width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"border-collapse:collapse;\">"
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
                f"<div style=\"color:{color}; margin:0 0 4px 0;\">"
                f"{html.escape(bullet)} {html.escape(self.format_detail_value(item))}</div>"
            )

        return self.build_detail_card(title, "".join(lines), accent_color=accent)

    def build_packet_details_html(self, file, result):

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
        self.log(f"Loaded {len(files)} files.")
        log_event("files_loaded", f"{len(files)} files")

    # -------------------------------------------------
    # ANALYZE
    # -------------------------------------------------

    def analyze_packets(self):

        icon_base=resource_path("ui/pyside_gui/assets/icons/")
        self.table.setRowCount(0)

        for file in self.files:

            result=process_packet(file)

            score=result.get("score",0)

            self.results[file]=result

            row=self.table.rowCount()
            self.table.insertRow(row)

            file_item=QTableWidgetItem(os.path.basename(file))
            file_item.setIcon(QIcon(icon_base+"folder.svg"))
            self.table.setItem(row,0,file_item)

            score_item=QTableWidgetItem(str(score))
            score_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row,1,score_item)

            status=QTableWidgetItem()

            if score>=90:
                status.setText("Approved")
                status.setIcon(QIcon(icon_base+"check.svg"))
                status.setForeground(QColor("#27AE60"))
                export_patient(result.get("fields",{}),file)
                self.log(
                    f"Approved packet exported → {os.path.basename(file)}",
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

            triage_packet(file,score)

        self.log("Packet analysis complete.")

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
            return

        self.details.setHtml(self.build_packet_details_html(file, result))

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
            ])

            for file,result in self.results.items():
                intel_display=result.get("intel",{}).get("display",{})

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

        self.log("Results cleared.")

    # -------------------------------------------------
    # ADMIN PANEL
    # -------------------------------------------------

    def open_admin_panel(self):

        password,ok=QInputDialog.getText(
            self,
            "Admin Access",
            "Enter Admin Password:",
            QLineEdit.Password
        )

        if not ok or password != ADMIN_PASSWORD:
            QMessageBox.warning(self,"Access Denied","Incorrect password.")
            return

        # Create Admin Window
        dialog = QDialog(self)
        dialog.setWindowTitle("TrueCore Admin Panel")
        dialog.resize(900,600)

        layout = QVBoxLayout()

        text = QTextEdit()
        text.setReadOnly(True)

        layout.addWidget(text)

        dialog.setLayout(layout)
        
        # ----------------------------------------------
        # LOAD ADMIN DATA
        # ----------------------------------------------

        try:

            changelog_path = resource_path("CHANGELOG.txt")
            activity_path = resource_path("logs/activity.log")

            changelog = ""
            activity = ""

            if os.path.exists(changelog_path):
                with open(changelog_path,"r",encoding="utf-8") as f:
                    changelog = f.read()

            if os.path.exists(activity_path):
                with open(activity_path,"r",encoding="utf-8") as f:
                    activity_lines = f.readlines()
                    activity = "".join(reversed(activity_lines[:200]))

            text.append("TRUECORE SYSTEM OVERVIEW\n")
            text.append("====================================\n")

            text.append(f"Engine Version: {self.version}\n")

            if self.build_timestamp:
                text.append(f"Build Time: {self.build_timestamp}\n")

            text.append("\nRecent Updates\n")
            text.append("------------------------------------\n")

            blocks = changelog.split("VERSION:")
            blocks = [b.strip() for b in blocks if b.strip()]
            blocks.reverse()
            blocks = blocks[:10]

            for block in blocks:
                text.append("VERSION: " + block + "\n")

            text.append("\nActivity Log\n")
            text.append("------------------------------------\n")
            text.append(activity)

        except Exception as e:

            text.append(f"Admin panel error:\n{str(e)}")

        dialog.exec()

    # ----------------------------------------------
    # ESCAPE KEY HANDLER
    # ----------------------------------------------

    def keyPressEvent(self, event):

        if event.key() == Qt.Key_Escape:
            self.showMaximized()
            event.accept()
