from PySide6.QtCore import QObject, QPoint, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QIcon, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import os
import subprocess
import sys

from TrueCore.core.office_rollout import load_office_profile, record_docs_kit_exported
from TrueCore.launcher.docs_catalog import export_docs_bundle
from TrueCore.launcher.launcher_logging import log
from TrueCore.launcher.launcher_support import (
    build_launcher_support_snapshot,
    build_support_mailto_url,
    get_launcher_support_request_dir,
    load_launcher_release_info,
    resolve_it_email,
)
from TrueCore.launcher.updater import (
    check_updates,
    download_update,
    get_local_version,
    install_update,
    verify_installed_engine_integrity,
)
from TrueCore.utils.launcher_auth import ensure_launcher_auth_config, verify_launcher_credentials


ENGINE_DIR = "engine"


def resource_path(relative_path):
    if hasattr(sys, "_MEIPASS"):
        base_path = os.path.join(sys._MEIPASS, "launcher")
    else:
        base_path = os.path.abspath(os.path.dirname(__file__))

    return os.path.join(base_path, relative_path)


def find_engine():
    if not getattr(sys, "frozen", False):
        executable = sys.executable
        if os.name == "nt":
            pythonw_path = os.path.join(os.path.dirname(executable), "pythonw.exe")
            if os.path.exists(pythonw_path):
                executable = pythonw_path
        return [executable, "-m", "TrueCore.ui.truecore_app"]

    base_dir = os.path.dirname(sys.executable)
    engine_path = os.path.join(base_dir, ENGINE_DIR, "TrueCoreEngine.exe")
    if os.path.exists(engine_path):
        return engine_path
    return None


def hidden_process_kwargs():
    kwargs = {}

    if os.name != "nt":
        return kwargs

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if creationflags:
        kwargs["creationflags"] = creationflags

    startupinfo_factory = getattr(subprocess, "STARTUPINFO", None)
    startf_use_show_window = getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
    sw_hide = getattr(subprocess, "SW_HIDE", 0)

    if startupinfo_factory and startf_use_show_window:
        startupinfo = startupinfo_factory()
        startupinfo.dwFlags |= startf_use_show_window
        startupinfo.wShowWindow = sw_hide
        kwargs["startupinfo"] = startupinfo

    return kwargs


class LauncherUpdateWorker(QObject):
    activity = Signal(str)
    finished = Signal(object)

    def run(self):
        state = {
            "phase": "checking",
            "status": "checking",
            "message": "Checking for the latest program build...",
            "server_version": None,
            "local_version_before": get_local_version(),
            "local_version_after": None,
            "local_version": None,
            "manifest_authentication": {},
            "integrity": {},
        }

        try:
            self.activity.emit("Checking for the latest program build...")
            update_data = check_updates()

            if not update_data:
                state.update(
                    {
                        "phase": "error",
                        "status": "error",
                        "message": "The update check returned no data.",
                    }
                )
                self.finished.emit(state)
                return

            state["manifest_authentication"] = dict(update_data.get("manifest_authentication") or {})
            state["server_version"] = update_data.get("version")
            state["local_version"] = update_data.get("local_version") or state["local_version_before"]
            status = str(update_data.get("status") or "error").strip().lower()

            if status == "error":
                state.update(
                    {
                        "phase": "error",
                        "status": "error",
                        "message": update_data.get("message") or "The update server could not be reached.",
                        "integrity": dict(verify_installed_engine_integrity() or {}),
                    }
                )
                self.activity.emit(state["message"])
                self.finished.emit(state)
                return

            if status == "up_to_date":
                state.update(
                    {
                        "phase": "ready",
                        "status": "up_to_date",
                        "message": "Program engine is already up to date.",
                        "integrity": dict(verify_installed_engine_integrity() or {}),
                    }
                )
                self.activity.emit("Program engine is already up to date.")
                self.finished.emit(state)
                return

            download_url = update_data.get("download")
            if not download_url:
                state.update(
                    {
                        "phase": "error",
                        "status": "error",
                        "message": "Update metadata was incomplete. No download URL was provided.",
                        "integrity": dict(verify_installed_engine_integrity() or {}),
                    }
                )
                self.activity.emit(state["message"])
                self.finished.emit(state)
                return

            self.activity.emit(f"New program build found: v{state['server_version']}. Downloading now...")
            zip_data = download_update(download_url)

            if zip_data is None:
                state.update(
                    {
                        "phase": "download_failed",
                        "status": "download_failed",
                        "message": "Program update download failed.",
                        "integrity": dict(verify_installed_engine_integrity() or {}),
                    }
                )
                self.activity.emit(state["message"])
                self.finished.emit(state)
                return

            self.activity.emit("Installing the latest program build...")
            success = install_update(
                zip_data,
                version=state["server_version"],
                expected_sha256=update_data.get("sha256"),
                expected_size=update_data.get("size"),
                manifest_authentication=update_data.get("manifest_authentication"),
            )

            state["local_version_after"] = get_local_version()
            state["local_version"] = state["local_version_after"] or state["local_version_before"]
            state["integrity"] = dict(verify_installed_engine_integrity() or {})

            if success:
                state.update(
                    {
                        "phase": "ready",
                        "status": "installed",
                        "message": f"Program engine updated successfully to v{state['server_version']}.",
                    }
                )
                self.activity.emit(state["message"])
            else:
                state.update(
                    {
                        "phase": "install_failed",
                        "status": "install_failed",
                        "message": "Program update install failed. Existing local files were kept where possible.",
                    }
                )
                self.activity.emit(state["message"])

        except Exception as exc:
            state.update(
                {
                    "phase": "error",
                    "status": "error",
                    "message": str(exc),
                    "integrity": dict(verify_installed_engine_integrity() or {}),
                }
            )
            self.activity.emit(f"Launcher sync failed: {exc}")

        self.finished.emit(state)


class LauncherWindow(QWidget):
    def __init__(self):
        super().__init__()

        ensure_launcher_auth_config()

        self.release_info = dict(load_launcher_release_info() or {})
        self.office_profile = {}
        self.last_update_state = {}
        self.update_in_progress = False
        self.update_thread = None
        self.update_worker = None
        self._drag_active = False
        self._drag_offset = QPoint()

        self.setWindowTitle("TrueCore Launcher")
        self.setWindowIcon(QIcon(resource_path("assets/truecore_icon.ico")))
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.resize(1040, 700)
        self.setMinimumSize(1040, 700)
        self.setMaximumSize(1040, 700)

        self._build_ui()
        self.refresh_static_context()
        self.refresh_engine_snapshot()
        self.update_launch_button_state()

        QTimer.singleShot(100, self.start_background_sync)

    def _build_ui(self):
        self.setStyleSheet(
            """
            QWidget {
                color: #E6EDF7;
                font-family: "Segoe UI";
                font-size: 13px;
                background: transparent;
            }
            QFrame#shell {
                background-color: rgba(10, 15, 24, 0.97);
                border: 1px solid #21354A;
                border-radius: 20px;
            }
            QFrame#titleBar {
                background-color: rgba(12, 18, 28, 0.96);
                border: 1px solid #1B2C3E;
                border-radius: 14px;
            }
            QFrame#brandPanel {
                background-color: rgba(15, 24, 36, 0.96);
                border: 1px solid #21354A;
                border-radius: 16px;
            }
            QFrame#card {
                background-color: rgba(15, 24, 36, 0.96);
                border: 1px solid #21354A;
                border-radius: 16px;
            }
            QLabel#windowTitle {
                color: #FFFFFF;
                font-size: 15px;
                font-weight: 700;
            }
            QLabel#heroTitle {
                color: #FFFFFF;
                font-size: 26px;
                font-weight: 700;
            }
            QLabel#heroSubtitle {
                color: #9BB3CC;
                font-size: 12px;
            }
            QLabel#sectionTitle {
                color: #FFFFFF;
                font-size: 15px;
                font-weight: 700;
            }
            QLabel#metricTitle {
                color: #92A8C2;
                font-size: 11px;
                font-weight: 600;
            }
            QLabel#metricValue {
                color: #FFFFFF;
                font-size: 22px;
                font-weight: 700;
            }
            QLabel#metricSubtle {
                color: #8AA1BA;
                font-size: 11px;
            }
            QLabel#pill {
                background-color: rgba(27, 41, 57, 0.95);
                border: 1px solid #2A4560;
                border-radius: 10px;
                padding: 7px 12px;
                color: #D5E3F4;
                font-size: 11px;
                font-weight: 600;
            }
            QPushButton {
                background-color: #1A2837;
                color: #EAF2FB;
                border: 1px solid #2E4B67;
                border-radius: 8px;
                padding: 9px 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #21354A;
            }
            QPushButton:disabled {
                color: #7188A1;
                background-color: #121B25;
                border-color: #223547;
            }
            QPushButton#primaryButton {
                background-color: #2C73D2;
                border-color: #4A90F0;
                color: #FFFFFF;
            }
            QPushButton#primaryButton:hover {
                background-color: #3681E8;
            }
            QPushButton#linkButton {
                background: transparent;
                border: 0;
                color: #66BBFF;
                text-align: left;
                padding: 0;
                font-weight: 600;
            }
            QPushButton#linkButton:hover {
                color: #93D2FF;
                text-decoration: underline;
            }
            QPushButton#windowControl {
                background: transparent;
                border: 0;
                color: #9EC7F4;
                font-size: 18px;
                font-weight: 700;
                padding: 2px 8px;
            }
            QPushButton#windowControl:hover {
                color: #FFFFFF;
                background-color: rgba(34, 53, 74, 0.9);
                border-radius: 8px;
            }
            QLineEdit {
                background-color: rgba(11, 18, 27, 0.96);
                color: #F3F7FB;
                border: 1px solid #2B445C;
                border-radius: 10px;
                padding: 11px 12px;
            }
            QTextEdit {
                background-color: rgba(11, 18, 27, 0.96);
                color: #E6EDF7;
                border: 1px solid #21354A;
                border-radius: 12px;
                padding: 10px;
            }
            """
        )

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(12, 12, 12, 12)
        outer_layout.setSpacing(0)

        shell = QFrame()
        shell.setObjectName("shell")
        shell_layout = QVBoxLayout(shell)
        shell_layout.setContentsMargins(14, 14, 14, 14)
        shell_layout.setSpacing(14)
        outer_layout.addWidget(shell)

        title_bar = QFrame()
        title_bar.setObjectName("titleBar")
        title_bar.setFixedHeight(48)
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(12, 6, 12, 6)
        title_layout.setSpacing(10)

        icon_label = QLabel()
        icon_pixmap = QPixmap(resource_path("assets/truecore_icon.ico"))
        icon_label.setPixmap(icon_pixmap.scaled(24, 24, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        title_layout.addWidget(icon_label)

        title_text = QLabel("TrueCore Launcher")
        title_text.setObjectName("windowTitle")
        title_layout.addWidget(title_text)

        title_layout.addStretch()

        self.launcher_version_pill = QLabel("Launcher v-")
        self.launcher_version_pill.setObjectName("pill")
        title_layout.addWidget(self.launcher_version_pill)

        minimize_button = QPushButton("−")
        minimize_button.setObjectName("windowControl")
        minimize_button.setFixedSize(34, 28)
        minimize_button.clicked.connect(self.showMinimized)
        title_layout.addWidget(minimize_button)

        close_button = QPushButton("×")
        close_button.setObjectName("windowControl")
        close_button.setFixedSize(34, 28)
        close_button.clicked.connect(self.close)
        title_layout.addWidget(close_button)

        shell_layout.addWidget(title_bar)
        self.title_bar = title_bar

        hero_layout = QHBoxLayout()
        hero_layout.setSpacing(14)

        brand_panel = QFrame()
        brand_panel.setObjectName("brandPanel")
        brand_panel.setFixedWidth(278)
        brand_layout = QVBoxLayout(brand_panel)
        brand_layout.setContentsMargins(18, 18, 18, 18)
        brand_layout.setSpacing(10)

        logo = QLabel()
        logo_pixmap = QPixmap(resource_path("assets/truecore_logo.png"))
        logo.setPixmap(logo_pixmap.scaled(205, 94, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setAlignment(Qt.AlignCenter)
        brand_layout.addWidget(logo)

        brand_tagline = QLabel("Secure local-first packet review, launch control, and office support.")
        brand_tagline.setObjectName("heroSubtitle")
        brand_tagline.setWordWrap(True)
        brand_layout.addWidget(brand_tagline)
        brand_layout.addStretch()

        hero_layout.addWidget(brand_panel, 0)

        summary_panel = QFrame()
        summary_panel.setObjectName("card")
        summary_layout = QVBoxLayout(summary_panel)
        summary_layout.setContentsMargins(20, 18, 20, 18)
        summary_layout.setSpacing(8)

        hero_title = QLabel("TrueCore Secure Launch Console")
        hero_title.setObjectName("heroTitle")
        summary_layout.addWidget(hero_title)

        hero_subtitle = QLabel(
            "The new launcher keeps the update check, office identity, launch credentials, "
            "and support snapshot tools in one compact shell."
        )
        hero_subtitle.setObjectName("heroSubtitle")
        hero_subtitle.setWordWrap(True)
        summary_layout.addWidget(hero_subtitle)

        summary_pills = QHBoxLayout()
        summary_pills.setSpacing(10)

        self.hero_office_label = QLabel("Office: Loading...")
        self.hero_office_label.setObjectName("pill")
        summary_pills.addWidget(self.hero_office_label)

        self.hero_build_label = QLabel("Build: Loading...")
        self.hero_build_label.setObjectName("pill")
        summary_pills.addWidget(self.hero_build_label)

        summary_pills.addStretch()
        summary_layout.addLayout(summary_pills)
        summary_layout.addStretch()

        hero_layout.addWidget(summary_panel, 1)
        shell_layout.addLayout(hero_layout)

        metrics_layout = QGridLayout()
        metrics_layout.setHorizontalSpacing(12)
        metrics_layout.setVerticalSpacing(12)

        launcher_card, self.launcher_metric_value, self.launcher_metric_subtitle = self.build_metric_card("Launcher Build", "#56B7FF")
        engine_card, self.engine_metric_value, self.engine_metric_subtitle = self.build_metric_card("Installed Program", "#34D399")
        sync_card, self.sync_metric_value, self.sync_metric_subtitle = self.build_metric_card("Sync Status", "#F6C945")
        office_card, self.office_metric_value, self.office_metric_subtitle = self.build_metric_card("Office Identity", "#B28DFF")

        metrics_layout.addWidget(launcher_card, 0, 0)
        metrics_layout.addWidget(engine_card, 0, 1)
        metrics_layout.addWidget(sync_card, 0, 2)
        metrics_layout.addWidget(office_card, 0, 3)

        for column in range(4):
            metrics_layout.setColumnStretch(column, 1)

        shell_layout.addLayout(metrics_layout)

        content_layout = QHBoxLayout()
        content_layout.setSpacing(14)

        activity_card = QFrame()
        activity_card.setObjectName("card")
        activity_layout = QVBoxLayout(activity_card)
        activity_layout.setContentsMargins(18, 18, 18, 18)
        activity_layout.setSpacing(12)

        activity_title = QLabel("Activity And Update Status")
        activity_title.setObjectName("sectionTitle")
        activity_layout.addWidget(activity_title)

        activity_intro = QLabel(
            "The launcher loads immediately and checks the latest program build in the background. "
            "If a new build exists, it installs here before launch."
        )
        activity_intro.setObjectName("heroSubtitle")
        activity_intro.setWordWrap(True)
        activity_layout.addWidget(activity_intro)

        self.activity_box = QTextEdit()
        self.activity_box.setReadOnly(True)
        self.activity_box.setMinimumHeight(290)
        activity_layout.addWidget(self.activity_box, 1)

        activity_button_row = QHBoxLayout()
        activity_button_row.setSpacing(10)

        self.refresh_status_button = QPushButton("Refresh Status")
        self.refresh_status_button.clicked.connect(self.refresh_launcher_status)
        activity_button_row.addWidget(self.refresh_status_button)

        docs_button = QPushButton("Export Docs Kit")
        docs_button.clicked.connect(self.open_docs)
        activity_button_row.addWidget(docs_button)

        open_support_folder_button = QPushButton("Open Support Folder")
        open_support_folder_button.clicked.connect(self.open_support_folder)
        activity_button_row.addWidget(open_support_folder_button)

        activity_button_row.addStretch()
        activity_layout.addLayout(activity_button_row)
        content_layout.addWidget(activity_card, 3)

        launch_card = QFrame()
        launch_card.setObjectName("card")
        launch_layout = QVBoxLayout(launch_card)
        launch_layout.setContentsMargins(18, 18, 18, 18)
        launch_layout.setSpacing(12)

        launch_title = QLabel("Secure Program Launch")
        launch_title.setObjectName("sectionTitle")
        launch_layout.addWidget(launch_title)

        launch_intro = QLabel(
            "Enter the office launch credentials to open TrueCore. "
            "If the office forgets them, use the quick support links below."
        )
        launch_intro.setObjectName("heroSubtitle")
        launch_intro.setWordWrap(True)
        launch_layout.addWidget(launch_intro)

        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.Password)
        self.username.returnPressed.connect(self.launch_engine)
        self.password.returnPressed.connect(self.launch_engine)
        self.username.textChanged.connect(self.update_launch_button_state)
        self.password.textChanged.connect(self.update_launch_button_state)

        launch_layout.addWidget(self.username)
        launch_layout.addWidget(self.password)

        link_row = QHBoxLayout()
        link_row.setSpacing(14)

        forgot_username_button = QPushButton("Forgot Username")
        forgot_username_button.setObjectName("linkButton")
        forgot_username_button.clicked.connect(lambda: self.request_credential_help("forgot_username"))
        link_row.addWidget(forgot_username_button)

        forgot_password_button = QPushButton("Forgot Password")
        forgot_password_button.setObjectName("linkButton")
        forgot_password_button.clicked.connect(lambda: self.request_credential_help("forgot_password"))
        link_row.addWidget(forgot_password_button)

        link_row.addStretch()
        launch_layout.addLayout(link_row)

        self.launch_button = QPushButton("Launch TrueCore")
        self.launch_button.setObjectName("primaryButton")
        self.launch_button.setIcon(QIcon(resource_path("assets/icons/launch.svg")))
        self.launch_button.clicked.connect(self.launch_engine)
        self.launch_button.setMinimumHeight(42)
        launch_layout.addWidget(self.launch_button)

        self.launch_status_label = QLabel("Waiting for credentials.")
        self.launch_status_label.setWordWrap(True)
        self.launch_status_label.setStyleSheet("color:#8AA1BA;")
        launch_layout.addWidget(self.launch_status_label)

        support_card = QFrame()
        support_card.setObjectName("brandPanel")
        support_layout = QVBoxLayout(support_card)
        support_layout.setContentsMargins(14, 14, 14, 14)
        support_layout.setSpacing(10)

        support_title = QLabel("Office And Support Snapshot")
        support_title.setStyleSheet("color:#FFFFFF; font-size:14px; font-weight:700;")
        support_layout.addWidget(support_title)

        self.support_summary_label = QLabel("Loading office support profile...")
        self.support_summary_label.setObjectName("heroSubtitle")
        self.support_summary_label.setWordWrap(True)
        support_layout.addWidget(self.support_summary_label)

        self.username_hint_label = QLabel("")
        self.username_hint_label.setWordWrap(True)
        self.username_hint_label.setStyleSheet("color:#69BCFF; font-size:12px; font-weight:600;")
        support_layout.addWidget(self.username_hint_label)

        support_actions = QGridLayout()
        support_actions.setHorizontalSpacing(8)
        support_actions.setVerticalSpacing(8)

        report_button = QPushButton("Report Issue")
        report_button.clicked.connect(self.open_report)
        report_button.setMinimumHeight(34)
        support_actions.addWidget(report_button, 0, 0)

        support_folder_button = QPushButton("Support Folder")
        support_folder_button.clicked.connect(self.open_support_folder)
        support_folder_button.setMinimumHeight(34)
        support_actions.addWidget(support_folder_button, 0, 1)

        website_button = QPushButton("Website")
        website_button.clicked.connect(self.open_website)
        website_button.setMinimumHeight(34)
        support_actions.addWidget(website_button, 1, 0)

        support_email_button = QPushButton("Email Support")
        support_email_button.clicked.connect(self.open_support)
        support_email_button.setMinimumHeight(34)
        support_actions.addWidget(support_email_button, 1, 1)

        support_layout.addLayout(support_actions)
        launch_layout.addWidget(support_card)
        launch_layout.addStretch()
        content_layout.addWidget(launch_card, 2)

        shell_layout.addLayout(content_layout, 1)

    def build_metric_card(self, title, accent):
        frame = QFrame()
        frame.setObjectName("card")
        frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        frame.setMinimumHeight(112)
        frame.setStyleSheet(
            f"QFrame#card {{ background-color: rgba(15, 24, 36, 0.96); border:1px solid #21354A; "
            f"border-top:3px solid {accent}; border-radius:16px; }}"
        )

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setObjectName("metricTitle")

        value_label = QLabel("—")
        value_label.setObjectName("metricValue")

        subtitle_label = QLabel("")
        subtitle_label.setObjectName("metricSubtle")
        subtitle_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addWidget(subtitle_label)
        layout.addStretch()
        return frame, value_label, subtitle_label

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.title_bar.geometry().contains(event.position().toPoint()):
            self._drag_active = True
            self._drag_offset = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._drag_active and event.buttons() & Qt.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_offset)
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self._drag_active = False
        super().mouseReleaseEvent(event)

    def append_activity(self, message):
        text = str(message or "").strip()
        if not text:
            return
        self.activity_box.append(text)

    def refresh_static_context(self):
        self.release_info = dict(load_launcher_release_info() or {})
        self.office_profile = dict(load_office_profile() or {})
        office_name = self.office_profile.get("office_name") or "Unknown Office"
        office_id = self.office_profile.get("office_id") or "unknown"
        launcher_version = self.release_info.get("version") or "unknown"
        launcher_build_id = self.release_info.get("build_id") or "Unknown"
        username_hint = (
            dict(self.office_profile.get("credential_policy") or {}).get("username_hint")
            or "No office username hint configured yet."
        )

        self.launcher_version_pill.setText(f"Launcher v{launcher_version}")
        self.hero_office_label.setText(f"Office: {office_name}")
        self.hero_build_label.setText(f"Build: {launcher_build_id}")

        self.launcher_metric_value.setText(f"v{launcher_version}")
        self.launcher_metric_subtitle.setText(f"Build ID: {launcher_build_id}")

        self.office_metric_value.setText(office_name)
        self.office_metric_subtitle.setText(
            f"Office ID: {office_id} | Install: {self.office_profile.get('install_id') or 'Unknown'}"
        )

        self.support_summary_label.setText(
            f"This launcher is tied to {office_name}. "
            "Support requests include launcher/program build details and office identity automatically."
        )
        self.username_hint_label.setText(f"Office username hint: {username_hint}")

    def refresh_engine_snapshot(self, state=None):
        state = dict(state or {})
        local_version = state.get("local_version") or get_local_version() or "Not installed"
        integrity = dict(state.get("integrity") or verify_installed_engine_integrity() or {})
        integrity_status = integrity.get("status") or "unknown"
        server_version = state.get("server_version") or dict(self.last_update_state or {}).get("server_version")

        self.engine_metric_value.setText(str(local_version))
        self.engine_metric_subtitle.setText(
            f"Integrity: {integrity_status.replace('_', ' ').title()}"
            + (f" | Target: v{server_version}" if server_version else "")
        )

    def apply_update_state(self, state):
        state = dict(state or {})
        status = str(state.get("status") or "idle").strip().lower()
        message = str(state.get("message") or "Launcher standing by.").strip()

        label_map = {
            "checking": "Checking",
            "up_to_date": "Ready",
            "installed": "Updated",
            "download_failed": "Download Failed",
            "install_failed": "Install Failed",
            "error": "Attention",
        }

        sync_value = label_map.get(status, status.replace("_", " ").title() if status else "Idle")
        self.sync_metric_value.setText(sync_value)
        self.sync_metric_subtitle.setText(message)
        self.launch_status_label.setText(message)
        self.refresh_engine_snapshot(state)

    def update_launch_button_state(self):
        has_username = bool((self.username.text() or "").strip())
        has_password = bool((self.password.text() or "").strip())
        engine_available = bool(find_engine())

        if self.update_in_progress:
            self.launch_button.setEnabled(False)
            self.launch_button.setText("Syncing Latest Program...")
            self.launch_status_label.setText("The launcher is finishing the latest program sync before launch.")
            return

        if not engine_available:
            self.launch_button.setEnabled(False)
            self.launch_button.setText("Program Not Installed Yet")
            self.launch_status_label.setText("No local program build is ready yet. Wait for sync or refresh status.")
            return

        self.launch_button.setText("Launch TrueCore")
        self.launch_button.setEnabled(has_username and has_password)

        if has_username and has_password:
            self.launch_status_label.setText("Credentials entered. Ready to verify and launch.")
        else:
            self.launch_status_label.setText("Enter both username and password to unlock the program.")

    def start_background_sync(self):
        if self.update_thread is not None:
            return

        self.update_in_progress = True
        self.update_launch_button_state()

        self.update_thread = QThread(self)
        self.update_worker = LauncherUpdateWorker()
        self.update_worker.moveToThread(self.update_thread)
        self.update_thread.started.connect(self.update_worker.run)
        self.update_worker.activity.connect(self.append_activity)
        self.update_worker.finished.connect(self.handle_background_sync_finished)
        self.update_worker.finished.connect(self.update_thread.quit)
        self.update_thread.finished.connect(self.update_thread.deleteLater)
        self.update_thread.finished.connect(self.cleanup_update_worker)
        self.update_thread.start()

    def cleanup_update_worker(self):
        self.update_thread = None
        self.update_worker = None

    def handle_background_sync_finished(self, state):
        self.last_update_state = dict(state or {})
        self.update_in_progress = False
        self.apply_update_state(self.last_update_state)
        launcher_version = str(self.release_info.get("version") or "").strip()
        server_version = str(self.last_update_state.get("server_version") or "").strip()
        if launcher_version and server_version and launcher_version != server_version:
            self.append_activity(
                f"Launcher refresh recommended. This launcher is v{launcher_version}, while the current program release is v{server_version}."
            )
        self.update_launch_button_state()

    def refresh_launcher_status(self):
        if self.update_in_progress:
            self.append_activity("Launcher sync is already running.")
            return

        self.append_activity("Refreshing launcher status on demand...")
        self.refresh_static_context()
        self.refresh_engine_snapshot()
        self.start_background_sync()

    def request_credential_help(self, request_type):
        request_key = str(request_type or "launcher_support").strip().lower() or "launcher_support"
        snapshot_path, payload = build_launcher_support_snapshot(request_key, update_state=self.last_update_state)
        recipient = resolve_it_email()
        mailto_url = build_support_mailto_url(request_key, snapshot_path, payload, recipient=recipient)

        if request_key == "forgot_username":
            username_hint = (
                dict(self.office_profile.get("credential_policy") or {}).get("username_hint")
                or "No office username hint is configured yet."
            )
            self.append_activity(f"Username help requested. Office username hint: {username_hint}")
        else:
            self.append_activity("Password help requested. IT support draft prepared.")

        self.append_activity(f"Support snapshot exported: {snapshot_path}")
        QDesktopServices.openUrl(QUrl(mailto_url))

    def launch_engine(self):
        username = (self.username.text() or "").strip()
        password = self.password.text() or ""

        if self.update_in_progress:
            log("Blocked engine launch because launcher sync is still in progress.")
            self.append_activity("Please wait for the launcher to finish syncing the latest program build.")
            return

        if not username or not password.strip():
            log("Launcher sign-in blocked because required credentials were blank.")
            self.append_activity("Sign-in required. Enter both username and password before launching.")
            if not username:
                self.username.setFocus()
            else:
                self.password.setFocus()
            self.update_launch_button_state()
            return

        if not verify_launcher_credentials(username, password):
            log("Launcher sign-in failed.")
            self.append_activity("Access denied. The username or password did not match the office launch profile.")
            self.password.clear()
            self.password.setFocus()
            self.update_launch_button_state()
            return

        engine = find_engine()

        if engine is None:
            log("No engine found.")
            self.append_activity("Program engine not found locally. Refreshing launcher status may reinstall it.")
            self.update_launch_button_state()
            return

        try:
            log(f"Launching TrueCore engine: {engine}")
            integrity_result = {"status": "source_mode"} if isinstance(engine, list) else verify_installed_engine_integrity()
            integrity_status = integrity_result.get("status")

            if integrity_status == "tampered":
                log("Blocked engine launch because local engine integrity verification failed.")
                self.append_activity("Engine integrity check failed. The local program files appear to have changed unexpectedly.")
                self.append_activity("Use Refresh Status to reinstall the latest trusted program build before launching.")
                return

            if integrity_status == "compatibility_mode":
                self.append_activity("Engine integrity metadata was not found. Launching in compatibility mode.")

            if isinstance(engine, list):
                subprocess.Popen(engine, **hidden_process_kwargs())
            else:
                subprocess.Popen([engine], **hidden_process_kwargs())

            self.close()

        except Exception as exc:
            log(f"Engine launch failed: {exc}")
            self.append_activity(f"Engine launch failed: {exc}")

    def open_website(self):
        QDesktopServices.openUrl(QUrl("https://thetrubrain.com/"))

    def open_blog(self):
        QDesktopServices.openUrl(QUrl("https://thetrubrain.com/blog/"))

    def open_support(self):
        recipient = resolve_it_email()
        QDesktopServices.openUrl(QUrl(f"mailto:{recipient}"))

    def open_report(self):
        snapshot_path, payload = build_launcher_support_snapshot("launcher_support", update_state=self.last_update_state)
        recipient = resolve_it_email()
        mailto_url = build_support_mailto_url("launcher_support", snapshot_path, payload, recipient=recipient)
        self.append_activity(f"Launcher support request prepared: {snapshot_path}")
        QDesktopServices.openUrl(QUrl(mailto_url))

    def open_support_folder(self):
        support_dir = get_launcher_support_request_dir()
        os.makedirs(support_dir, exist_ok=True)

        if hasattr(os, "startfile"):
            os.startfile(support_dir)
            return

        QDesktopServices.openUrl(QUrl.fromLocalFile(support_dir))

    def open_docs(self):
        docs_source = resource_path("assets/docs/TrueCoreDocs.zip")
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")

        if not os.path.exists(docs_source):
            self.append_activity(f"Documentation kit not found: {docs_source}")
            return

        try:
            exported = export_docs_bundle(docs_source, desktop)
            bundle_dir = exported["bundle_dir"]
            index_path = exported["index_path"]
            record_docs_kit_exported()
            self.append_activity("Documentation kit exported to the desktop successfully.")
            self.append_activity(f"Open this index first: {os.path.basename(index_path)}")
            QDesktopServices.openUrl(QUrl.fromLocalFile(bundle_dir))
        except Exception as exc:
            self.append_activity(f"Documentation export failed: {exc}")
