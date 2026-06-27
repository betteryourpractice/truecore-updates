from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QDialog, QLabel, QPushButton, QTabWidget, QTextEdit, QVBoxLayout, QWidget

from TrueCore.ui.pyside_gui.dev_tools_config import load_dev_tools_config, update_dev_tools_config
from TrueCore.ui.pyside_gui.dev_tools_dialog import PacketBuilderTab


class DevToolsDialog(QDialog):
    def __init__(self, machine_role, primary_update_channel, reference_update_channel, developer_tools_enabled, private_dev_channel, parent=None):
        super().__init__(parent)
        self.machine_role = machine_role
        self.primary_update_channel = primary_update_channel
        self.reference_update_channel = reference_update_channel
        self.developer_tools_enabled = developer_tools_enabled
        self.private_dev_channel = dict(private_dev_channel or {})
        self.config = load_dev_tools_config()

        self.setWindowTitle("Developer Tools")
        self.setMinimumSize(980, 720)
        self.setWindowFlags(
            Qt.Window
            | Qt.WindowCloseButtonHint
            | Qt.WindowMinimizeButtonHint
            | Qt.WindowMaximizeButtonHint
            | Qt.WindowSystemMenuHint
        )
        self.setStyleSheet(
            """
            QDialog { background-color: #0D1520; color: #E5E7EB; }
            QLabel { color: #E5E7EB; }
            QScrollArea, QScrollArea > QWidget > QWidget {
                background-color: #0F1823;
                border: none;
            }
            QTextEdit, QListWidget, QLineEdit, QComboBox {
                background-color: #111A25;
                border: 1px solid #253243;
                border-radius: 8px;
                color: #DCE6F2;
                padding: 8px;
            }
            QComboBox QAbstractItemView {
                background-color: #111A25;
                color: #DCE6F2;
                border: 1px solid #34506B;
                selection-background-color: #223246;
                selection-color: #FFFFFF;
                outline: 0;
            }
            QTextEdit:focus, QListWidget:focus, QLineEdit:focus, QComboBox:focus {
                border: 1px solid #69BCFF;
            }
            QPushButton {
                background-color: #1D2A3A;
                color: #FFFFFF;
                border: 1px solid #34506B;
                border-radius: 6px;
                padding: 8px 14px;
            }
            QPushButton:hover { background-color: #223246; }
            QTabWidget::pane {
                border: 1px solid #243446;
                background: #0F1823;
                border-radius: 10px;
            }
            QTabBar::tab {
                background: #111A25;
                color: #C9D7E5;
                padding: 10px 16px;
                margin-right: 4px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background: #1D2A3A;
                color: #FFFFFF;
                font-weight: 700;
            }
            QGroupBox {
                background-color: #0F1823;
                border: 1px solid #243446;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 14px;
            }
            QGroupBox:title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 4px;
            }
            QSplitter::handle {
                background: #243446;
            }
            QSplitter::handle:horizontal {
                width: 6px;
            }
            QSplitter::handle:vertical {
                height: 6px;
            }
            """
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title = QLabel("Developer Tools")
        title.setStyleSheet("font-size:22px; font-weight:700; color:#69BCFF;")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.addTab(self._build_overview_tab(), "Overview")
        tabs.addTab(PacketBuilderTab(self.config, self.save_config, self), "Packet Builder Studio")
        layout.addWidget(tabs, stretch=1)

        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button, alignment=Qt.AlignRight)
        self._apply_initial_geometry(parent)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.showMinimized()
            event.accept()
            return
        super().keyPressEvent(event)

    def save_config(self, changes):
        self.config = dict(update_dev_tools_config(changes or {}) or {})
        return self.config

    def _apply_initial_geometry(self, parent):
        screen = None
        if parent and parent.windowHandle():
            screen = parent.windowHandle().screen()
        if not screen:
            screen = QGuiApplication.primaryScreen()
        if not screen:
            self.resize(1360, 900)
            return
        available = screen.availableGeometry()
        width = min(max(1180, int(available.width() * 0.88)), 1700)
        height = min(max(820, int(available.height() * 0.88)), 1100)
        x = available.x() + max(0, (available.width() - width) // 2)
        y = available.y() + max(0, (available.height() - height) // 2)
        self.setGeometry(x, y, width, height)

    def _build_overview_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        intro = QLabel(
            "This install is marked as a developer machine. Offices will never see this area. Use it to build packets, test phrasing, and validate exports without exposing in-progress tools to production users."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#BFD0E3;")
        layout.addWidget(intro)

        summary = QTextEdit()
        summary.setReadOnly(True)
        summary.setStyleSheet(
            "background:#0F1823; border:1px solid #243446; border-radius:12px; color:#DCE6F2; padding:12px;"
        )
        summary.setHtml(
            f"""
            <div style="font-family:'Segoe UI'; font-size:14px; color:#DCE6F2; line-height:1.55;">
              <div style="font-size:18px; font-weight:700; color:#69BCFF; margin-bottom:10px;">Developer Install Status</div>
              <table style="width:100%; border-collapse:collapse; margin-bottom:18px;">
                <tr><td style="padding:6px 0; color:#8FA6C1; width:38%;">Machine role</td><td style="padding:6px 0; color:#F2F5F9; font-weight:600;">{html.escape(str(self.machine_role or 'unknown').title())}</td></tr>
                <tr><td style="padding:6px 0; color:#8FA6C1;">Primary update channel</td><td style="padding:6px 0; color:#F2F5F9; font-weight:600;">{html.escape(str(self.primary_update_channel or 'unknown').title())}</td></tr>
                <tr><td style="padding:6px 0; color:#8FA6C1;">Production reference visible</td><td style="padding:6px 0; color:#F2F5F9; font-weight:600;">{'Yes' if self.reference_update_channel else 'No'}</td></tr>
                <tr><td style="padding:6px 0; color:#8FA6C1;">Developer tools enabled</td><td style="padding:6px 0; color:#F2F5F9; font-weight:600;">{'Yes' if self.developer_tools_enabled else 'No'}</td></tr>
                <tr><td style="padding:6px 0; color:#8FA6C1;">Private dev repo</td><td style="padding:6px 0; color:#F2F5F9; font-weight:600;">{html.escape((f"{self.private_dev_channel.get('owner', '')}/{self.private_dev_channel.get('repo', '')}".strip("/") or "Not configured"))}</td></tr>
                <tr><td style="padding:6px 0; color:#8FA6C1;">Private dev updates enabled</td><td style="padding:6px 0; color:#F2F5F9; font-weight:600;">{'Yes' if self.private_dev_channel.get('enabled') else 'No'}</td></tr>
              </table>

              <div style="font-size:17px; font-weight:700; color:#69BCFF; margin:0 0 8px 0;">What This Version Gives You</div>
              <ul style="margin:0 0 18px 18px; padding:0;">
                <li style="margin-bottom:6px;">Packet Builder Studio with live preview</li>
                <li style="margin-bottom:6px;">Wording Assist with blueprint-aware phrasing review</li>
                <li style="margin-bottom:6px;">Single-form export to Word, PDF, or both</li>
                <li style="margin-bottom:6px;">Referral-request and patient-packet export flows</li>
                <li style="margin-bottom:6px;">Packet library, signatures, and reusable export-folder selection</li>
              </ul>

              <div style="font-size:17px; font-weight:700; color:#69BCFF; margin:0 0 8px 0;">Next Dev-Only Ideas</div>
              <ul style="margin:0 0 0 18px; padding:0;">
                <li style="margin-bottom:6px;">Packet Lab</li>
                <li style="margin-bottom:6px;">Extraction Trace</li>
                <li style="margin-bottom:6px;">Threshold tuning</li>
                <li style="margin-bottom:6px;">Regression helpers</li>
              </ul>
            </div>
            """
        )
        layout.addWidget(summary, stretch=1)
        return tab
