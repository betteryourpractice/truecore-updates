from PySide6.QtCore import QObject, Qt, QThread, QTimer, QUrl, Signal
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
from TrueCore.utils.launcher_auth import (
    ensure_launcher_auth_config,
    verify_launcher_credentials,
)


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

        self.setWindowTitle("TrueCore Launcher")
        self.resize(1180, 760)
        self.setMinimumSize(1080, 700)
        self.setWindowIcon(QIcon(resource_path("assets/truecore_icon.ico")))

        self.release_info = dict(load_launcher_release_info() or {})
        self.office_profile = {}
        self.last_update_state = {}
        self.update_in_progress = False
        self.update_thread = None
        self.update_worker = None

        self._build_ui()
        self.refresh_static_context()
        self.refresh_engine_snapshot()
        self.update_launch_button_state()

        QTimer.singleShot(100, self.start_background_sync)

    def _build_ui(self):
        self.setStyleSheet(
            """
            QWidget {
                background-color: #0B1118;
                color: #E5E7EB;
                font-family: "Segoe UI";
                font-size: 13px;
            }
            QFrame#card {
                background-color: #111A24;
                border: 1px solid #223246;
                border-radius: 14px;
            }
            QLabel#heroTitle {
                color: #FFFFFF;
                font-size: 28px;
                font-weight: 700;
            }
            QLabel#heroSubtitle {
                color: #9FB3C8;
                font-size: 13px;
            }
            QLabel#sectionTitle {
                color: #FFFFFF;
                font-size: 16px;
                font-weight: 700;
            }
            QLabel#metricTitle {
                color: #9FB3C8;
                font-size: 12px;
                font-weight: 600;
            }
            QLabel#metricValue {
                color: #FFFFFF;
                font-size: 24px;
                font-weight: 700;
            }
            QLabel#metricSubtle {
                color: #8EA4BB;
                font-size: 11px;
            }
            QPushButton {
                background-color: #1A2532;
                color: #E5E7EB;
                border: 1px solid #2D435B;
                border-radius: 8px;
                padding: 10px 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #213246;
            }
            QPushButton:disabled {
                color: #738499;
                border-color: #233242;
                background-color: #101823;
            }
            QPushButton#primaryButton {
                background-color: #1E6FDB;
                border-color: #2F80ED;
                color: #FFFFFF;
            }
            QPushButton#primaryButton:hover {
                background-color: #2A7AEB;
            }
            QPushButton#linkButton {
                background: transparent;
                border: 0;
                color: #66B8FF;
                text-align: left;
                padding: 0;
                font-weight: 600;
            }
            QPushButton#linkButton:hover {
                color: #91CCFF;
                text-decoration: underline;
            }
            QLineEdit {
                background-color: #0E151E;
                color: #F3F5F7;
                border: 1px solid #2A3B4E;
                border-radius: 8px;
                padding: 10px 12px;
            }
            QTextEdit {
                background-color: #0E151E;
                color: #E5E7EB;
                border: 1px solid #223246;
                border-radius: 10px;
                padding: 10px;
            }
            """
        )

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(22, 22, 22, 22)
        root_layout.setSpacing(16)

        hero = QFrame()
        hero.setObjectName("card")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(20, 18, 20, 18)
        hero_layout.setSpacing(18)

        logo = QLabel()
        logo_pixmap = QPixmap(resource_path("assets/truecore_logo.png"))
        logo.setPixmap(logo_pixmap.scaled(220, 84, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        hero_layout.addWidget(logo, 0)

        hero_text_layout = QVBoxLayout()
        hero_title = QLabel("TrueCore Secure Launch Console")
        hero_title.setObjectName("heroTitle")
        hero_subtitle = QLabel(
            "The launcher now opens first, checks the latest program build in the background, "
            "and keeps credential access, update status, and office support in one place."
        )
        hero_subtitle.setObjectName("heroSubtitle")
        hero_subtitle.setWordWrap(True)
        hero_text_layout.addWidget(hero_title)
        hero_text_layout.addWidget(hero_subtitle)
        hero_layout.addLayout(hero_text_layout, 1)

        hero_side_layout = QVBoxLayout()
        hero_side_layout.setSpacing(4)
        self.hero_office_label = QLabel("Office: Loading...")
        self.hero_office_label.setStyleSheet("color:#FFFFFF; font-size:14px; font-weight:700;")
        self.hero_build_label = QLabel("Launcher build: Loading...")
        self.hero_build_label.setStyleSheet("color:#8EA4BB; font-size:12px;")
        self.hero_it_label = QLabel("IT Contact: Loading...")
        self.hero_it_label.setStyleSheet("color:#8EA4BB; font-size:12px;")
        hero_side_layout.addWidget(self.hero_office_label)
        hero_side_layout.addWidget(self.hero_build_label)
        hero_side_layout.addWidget(self.hero_it_label)
        hero_side_layout.addStretch()
        hero_layout.addLayout(hero_side_layout, 0)

        root_layout.addWidget(hero)

        metrics_frame = QFrame()
        metrics_layout = QGridLayout(metrics_frame)
        metrics_layout.setContentsMargins(0, 0, 0, 0)
        metrics_layout.setHorizontalSpacing(12)
        metrics_layout.setVerticalSpacing(12)

        launcher_card, self.launcher_metric_value, self.launcher_metric_subtitle = self.build_metric_card("Launcher Build", "#57B6FF")
        engine_card, self.engine_metric_value, self.engine_metric_subtitle = self.build_metric_card("Installed Program", "#34D399")
        sync_card, self.sync_metric_value, self.sync_metric_subtitle = self.build_metric_card("Sync Status", "#F6C945")
        office_card, self.office_metric_value, self.office_metric_subtitle = self.build_metric_card("Office Identity", "#A78BFA")

        metrics_layout.addWidget(launcher_card, 0, 0)
        metrics_layout.addWidget(engine_card, 0, 1)
        metrics_layout.addWidget(sync_card, 0, 2)
        metrics_layout.addWidget(office_card, 0, 3)

        for column in range(4):
            metrics_layout.setColumnStretch(column, 1)

        root_layout.addWidget(metrics_frame)

        content_layout = QHBoxLayout()
        content_layout.setSpacing(16)

        activity_card = QFrame()
        activity_card.setObjectName("card")
        activity_layout = QVBoxLayout(activity_card)
        activity_layout.setContentsMargins(18, 18, 18, 18)
        activity_layout.setSpacing(12)

        activity_title = QLabel("Activity And Update Status")
        activity_title.setObjectName("sectionTitle")
        activity_layout.addWidget(activity_title)

        activity_intro = QLabel(
            "The launcher now loads immediately and handles update checks in the background. "
            "If a new program build exists, it will download and install it here before launch."
        )
        activity_intro.setWordWrap(True)
        activity_intro.setStyleSheet("color:#9FB3C8;")
        activity_layout.addWidget(activity_intro)

        self.activity_box = QTextEdit()
        self.activity_box.setReadOnly(True)
        self.activity_box.setMinimumHeight(320)
        activity_layout.addWidget(self.activity_box, 1)

        activity_button_row = QHBoxLayout()
        activity_button_row.setSpacing(10)

        self.refresh_status_button = QPushButton("Refresh Status")
        self.refresh_status_button.clicked.connect(self.refresh_launcher_status)
        activity_button_row.addWidget(self.refresh_status_button)

        open_support_folder_button = QPushButton("Open Support Folder")
        open_support_folder_button.clicked.connect(self.open_support_folder)
        activity_button_row.addWidget(open_support_folder_button)

        export_docs_button = QPushButton("Export Docs Kit")
        export_docs_button.clicked.connect(self.open_docs)
        activity_button_row.addWidget(export_docs_button)

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
            "Enter the office launch credentials to open TrueCore. If the office forgets them, "
            "use the support links below to prepare an IT help request with the right build and office details."
        )
        launch_intro.setWordWrap(True)
        launch_intro.setStyleSheet("color:#9FB3C8;")
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
        link_row.setSpacing(10)

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
        self.launch_status_label.setStyleSheet("color:#8EA4BB;")
        launch_layout.addWidget(self.launch_status_label)

        help_card = QFrame()
        help_card.setObjectName("card")
        help_card.setStyleSheet(
            "QFrame#card { background-color:#0E151E; border:1px solid #25394F; border-radius:12px; }"
        )
        help_layout = QVBoxLayout(help_card)
        help_layout.setContentsMargins(14, 14, 14, 14)
        help_layout.setSpacing(8)

        help_title = QLabel("Office And Support Snapshot")
        help_title.setStyleSheet("color:#FFFFFF; font-size:14px; font-weight:700;")
        help_layout.addWidget(help_title)

        self.support_summary_label = QLabel("Loading office support profile...")
        self.support_summary_label.setWordWrap(True)
        self.support_summary_label.setStyleSheet("color:#9FB3C8;")
        help_layout.addWidget(self.support_summary_label)

        self.username_hint_label = QLabel("")
        self.username_hint_label.setWordWrap(True)
        self.username_hint_label.setStyleSheet("color:#66B8FF; font-size:12px;")
        help_layout.addWidget(self.username_hint_label)

        support_button_row = QHBoxLayout()
        support_button_row.setSpacing(10)

        support_button = QPushButton("Support")
        support_button.clicked.connect(self.open_support)
        support_button_row.addWidget(support_button)

        report_button = QPushButton("Report Issue")
        report_button.clicked.connect(self.open_report)
        support_button_row.addWidget(report_button)

        website_button = QPushButton("Website")
        website_button.clicked.connect(self.open_website)
        support_button_row.addWidget(website_button)

        support_button_row.addStretch()
        help_layout.addLayout(support_button_row)
        launch_layout.addWidget(help_card)

        launch_layout.addStretch()
        content_layout.addWidget(launch_card, 2)

        root_layout.addLayout(content_layout, 1)

    def build_metric_card(self, title, accent):
        frame = QFrame()
        frame.setObjectName("card")
        frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        frame.setMinimumHeight(122)
        frame.setStyleSheet(
            f"QFrame#card {{ background-color:#111A24; border:1px solid #223246; "
            f"border-top:3px solid {accent}; border-radius:14px; }}"
        )

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 14, 16, 14)
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
        it_email = resolve_it_email()
        username_hint = (
            dict(self.office_profile.get("credential_policy") or {}).get("username_hint")
            or "No office username hint configured yet."
        )

        self.hero_office_label.setText(f"Office: {office_name}")
        self.hero_build_label.setText(f"Launcher build: v{launcher_version} | {launcher_build_id}")
        self.hero_it_label.setText(f"IT Contact: {it_email}")

        self.launcher_metric_value.setText(f"v{launcher_version}")
        self.launcher_metric_subtitle.setText(
            f"Build ID: {launcher_build_id} | Release channel: {self.release_info.get('release_channel') or 'Unknown'}"
        )

        self.office_metric_value.setText(office_name)
        self.office_metric_subtitle.setText(f"Office ID: {office_id} | Install: {self.office_profile.get('install_id') or 'Unknown'}")

        self.support_summary_label.setText(
            f"This launcher is tied to {office_name}. "
            f"Support requests will be prepared for {it_email} with office identity and build details included."
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
            + (f" | Server target: v{server_version}" if server_version else "")
        )

    def apply_update_state(self, state):
        state = dict(state or {})
        status = str(state.get("status") or "idle").strip().lower()
        message = str(state.get("message") or "Launcher standing by.").strip()
        manifest_status = dict(state.get("manifest_authentication") or {}).get("status") or "unknown"

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
        self.sync_metric_subtitle.setText(
            f"{message}"
            + (f" | Manifest: {manifest_status.replace('_', ' ')}" if manifest_status else "")
        )
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
            self.launch_status_label.setText("No local program build is ready yet. Use Refresh Status if this does not resolve shortly.")
            return

        self.launch_button.setText("Launch TrueCore")
        self.launch_button.setEnabled(has_username and has_password)

        if has_username and has_password:
            self.launch_status_label.setText("Credentials entered. Ready to launch once access is verified.")
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
