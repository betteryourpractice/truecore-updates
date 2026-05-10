from PySide6.QtWidgets import (
    QWidget, QLabel, QPushButton, QTextEdit,
    QLineEdit, QVBoxLayout, QHBoxLayout, QFrame
)
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QPixmap, QIcon, QPainter, QDesktopServices, QGuiApplication

import subprocess
import os
import sys
import re

from TrueCore.launcher.docs_catalog import export_docs_bundle
from TrueCore.launcher.launcher_logging import log
from TrueCore.launcher.launcher_support import (
    build_launcher_support_snapshot,
    build_support_mailto_url,
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
from TrueCore.core.office_rollout import load_office_profile, record_docs_kit_exported
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
    engine_path = os.path.join(base_dir, "engine", "TrueCoreEngine.exe")

    if os.path.exists(engine_path):
        return engine_path

    return None


def changelog_path():
    candidates = []

    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        candidates.extend(
            [
                os.path.join(exe_dir, "TrueCore", "CHANGELOG.txt"),
                os.path.join(exe_dir, "_internal", "TrueCore", "CHANGELOG.txt"),
                os.path.join(exe_dir, "CHANGELOG.txt"),
            ]
        )
    else:
        launcher_dir = os.path.abspath(os.path.dirname(__file__))
        candidates.extend(
            [
                os.path.join(os.path.dirname(launcher_dir), "CHANGELOG.txt"),
                os.path.join(os.path.dirname(os.path.dirname(launcher_dir)), "TrueCore", "CHANGELOG.txt"),
            ]
        )

    for path in candidates:
        if os.path.exists(path):
            return path

    return None


def load_recent_update_summary(target_version=None):
    path = changelog_path()
    if not path:
        return None

    try:
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except Exception:
        return None

    blocks = re.split(r"\n\s*\n(?=VERSION:)", content)
    entries = []

    for block in blocks:
        version_match = re.search(r"VERSION:\s*([^\r\n]+)", block)
        if not version_match:
            continue

        date_match = re.search(r"DATE:\s*([^\r\n]+)", block)
        version = version_match.group(1).strip()
        date_value = date_match.group(1).strip() if date_match else ""

        changes = []
        in_changes = False
        for raw_line in block.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line == "CHANGES":
                in_changes = True
                continue
            if in_changes and (line.startswith("-") or line.startswith("*")):
                changes.append(line[1:].strip())

        if changes:
            entries.append({"version": version, "date": date_value, "changes": changes})

    if not entries:
        return None

    if target_version:
        normalized_target = str(target_version).strip().lower().lstrip("v")
        for entry in reversed(entries):
            if entry["version"].strip().lower().lstrip("v") == normalized_target:
                return entry

    return entries[-1]


class LauncherWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.old_pos = None
        self.release_info = dict(load_launcher_release_info() or {})
        self.last_update_state = {}

        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowTitle("TrueCore Launcher")
        self.setFixedSize(742, 469)
        self.setWindowIcon(QIcon(resource_path("assets/truecore_icon.ico")))

        self.bg = QPixmap(resource_path("assets/launcher_background.png"))

        self.setStyleSheet("""
        QWidget {
            background: transparent;
        }

        QFrame {
            background-color: rgba(10,15,25,0.90);
            border: 1px solid #2F3A4D;
            border-radius: 10px;
        }

        QTextEdit {
            background-color: #090D13;
        }

        QLineEdit {
            background-color: #090D13;
        }

        QPushButton {
            color: #F2D58B;
            border: 1px solid #8C7342;
        }

        QPushButton:hover {
            border: 1px solid #D4B36A;
        }

        QLabel#helpLinks {
            color: #69BCFF;
            font-size: 10px;
        }
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        header_layout = QHBoxLayout()

        close_button = QPushButton("✕")
        close_button.setFixedSize(30, 30)
        close_button.clicked.connect(self.close)
        close_button.setObjectName("closeButton")
        close_button.setStyleSheet("""
        QPushButton {
            background: transparent;
            color: #57B6FF;
            font-size: 20px;
            font-weight: bold;
            border: none;
            padding: 0px;
        }

        QPushButton:hover {
            color: #8ED0FF;
        }
        """)
        header_layout.addWidget(close_button)
        header_layout.addStretch()

        logo = QLabel()
        pix = QPixmap(resource_path("assets/truecore_logo.png"))
        logo.setPixmap(pix.scaled(200, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setAlignment(Qt.AlignCenter)
        logo.setFixedHeight(70)
        header_layout.addWidget(logo)
        header_layout.addStretch()

        version_layout = QVBoxLayout()
        version_layout.setAlignment(Qt.AlignRight)

        self.server_version = QLabel("Server v-")
        launcher_version = self.release_info.get("version") or "1.0"
        self.launcher_version = QLabel(f"Launcher v{launcher_version}")

        version_layout.addWidget(self.server_version)
        version_layout.addWidget(self.launcher_version)
        header_layout.addLayout(version_layout)

        main_layout.addLayout(header_layout)

        content_layout = QHBoxLayout()
        content_layout.setSpacing(20)

        news_panel = QFrame()
        news_layout = QVBoxLayout()

        news_title = QLabel("News / Updates")
        news_title.setStyleSheet("font-size:18px;color:#57B6FF;font-weight:600")

        self.news_box = QTextEdit()
        self.news_box.setReadOnly(True)
        self.news_box.setText(
            "TrueCore Update\n\n"
            "- Improved packet extraction\n"
            "- Faster ICD detection\n"
            "- Launcher reverted to the classic shell\n"
        )

        news_layout.addWidget(news_title)
        news_layout.addWidget(self.news_box)
        news_panel.setLayout(news_layout)

        login_panel = QFrame()
        login_layout = QVBoxLayout()

        login_title = QLabel("Sign In")
        login_title.setStyleSheet("font-size:18px;color:#57B6FF;font-weight:600")

        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")

        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.Password)

        self.help_links = QLabel(
            '<a href="forgot_username" style="color:#69BCFF; text-decoration:none;">Forgot Username</a>'
            '  |  '
            '<a href="forgot_password" style="color:#69BCFF; text-decoration:none;">Forgot Password</a>'
        )
        self.help_links.setObjectName("helpLinks")
        self.help_links.setTextFormat(Qt.RichText)
        self.help_links.setTextInteractionFlags(Qt.TextBrowserInteraction)
        self.help_links.setOpenExternalLinks(False)
        self.help_links.linkActivated.connect(self.handle_help_link)
        self.help_links.setWordWrap(True)

        self.support_snapshot_title = QLabel("Office And Support Snapshot")
        self.support_snapshot_title.setStyleSheet("font-size:10px;color:#8DBBEA;font-weight:600;")

        self.support_summary_label = QLabel("Loading office support profile...")
        self.support_summary_label.setStyleSheet("font-size:10px;color:#9DB8D3;")
        self.support_summary_label.setWordWrap(True)

        self.username_hint_label = QLabel("")
        self.username_hint_label.setStyleSheet("font-size:10px;color:#69BCFF;")
        self.username_hint_label.setWordWrap(True)

        self.play_button = QPushButton("Launch TrueCore")
        self.play_button.setIcon(QIcon(resource_path("assets/icons/launch.svg")))
        self.play_button.clicked.connect(self.launch_engine)
        self.username.returnPressed.connect(self.launch_engine)
        self.password.returnPressed.connect(self.launch_engine)
        self.username.textChanged.connect(self.update_launch_button_state)
        self.password.textChanged.connect(self.update_launch_button_state)

        login_layout.addWidget(login_title)
        login_layout.addWidget(self.username)
        login_layout.addWidget(self.password)
        login_layout.addWidget(self.help_links)
        login_layout.addWidget(self.support_snapshot_title)
        login_layout.addWidget(self.support_summary_label)
        login_layout.addWidget(self.username_hint_label)
        login_layout.addStretch()
        login_layout.addWidget(self.play_button)
        login_panel.setLayout(login_layout)

        content_layout.addWidget(news_panel, 2)
        content_layout.addWidget(login_panel, 1)

        main_layout.addLayout(content_layout)

        footer_layout = QHBoxLayout()
        footer_layout.setSpacing(20)
        footer_layout.addStretch()

        website_btn = QPushButton("Website")
        website_btn.setIcon(QIcon(resource_path("assets/icons/website.svg")))

        blog_btn = QPushButton("Blog")

        docs_btn = QPushButton("Docs")
        docs_btn.setIcon(QIcon(resource_path("assets/icons/docs.svg")))

        support_btn = QPushButton("Support")
        support_btn.setIcon(QIcon(resource_path("assets/icons/support.svg")))

        report_btn = QPushButton("Report Issue")
        report_btn.setIcon(QIcon(resource_path("assets/icons/report.svg")))

        footer_layout.addWidget(website_btn)
        footer_layout.addWidget(blog_btn)
        footer_layout.addWidget(docs_btn)
        footer_layout.addWidget(support_btn)
        footer_layout.addWidget(report_btn)

        website_btn.clicked.connect(self.open_website)
        blog_btn.clicked.connect(self.open_blog)
        support_btn.clicked.connect(self.open_support)
        report_btn.clicked.connect(self.open_report)
        docs_btn.clicked.connect(self.open_docs)

        footer_layout.addStretch()
        main_layout.addLayout(footer_layout)

        ensure_launcher_auth_config()
        self.refresh_static_context()
        self.update_launch_button_state()
        self.center_on_screen()
        self.auto_update()

    def center_on_screen(self):
        screen = QGuiApplication.primaryScreen()
        if not screen:
            return

        available = screen.availableGeometry()
        frame = self.frameGeometry()
        frame.moveCenter(available.center())
        self.move(frame.topLeft())

    def paintEvent(self, event):
        painter = QPainter(self)

        if not self.bg.isNull():
            painter.drawPixmap(self.rect(), self.bg)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.old_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if self.old_pos:
            delta = event.globalPosition().toPoint() - self.old_pos
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.old_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event):
        self.old_pos = None

    def auto_update(self):
        self.news_box.clear()
        self.write_update_summary()
        self.news_box.append("\nChecking for updates...")

        update_data = check_updates()
        status = update_data.get("status") if update_data else "error"
        self.last_update_state = dict(update_data or {})

        if status == "error":
            message = (update_data or {}).get("message", "Update server unreachable.")
            self.news_box.append(message)
            return

        server_version = str((update_data or {}).get("version") or "").strip()
        manifest_auth = dict((update_data or {}).get("manifest_authentication") or {})

        if server_version:
            self.server_version.setText(f"Server v{server_version}")
            self.write_update_summary(server_version)

        local_version = str((update_data or {}).get("local_version") or get_local_version() or "-").strip()

        self.news_box.append(f"Latest engine version: {server_version}")
        self.news_box.append(f"Installed engine version: {local_version}")
        if manifest_auth.get("status") == "verified":
            self.news_box.append("Update manifest signature verified.")
        elif manifest_auth.get("status") == "unsigned_compatibility":
            self.news_box.append("Update manifest is running in compatibility mode.")

        if status == "up_to_date":
            self.news_box.append("Engine is already up to date.")
            return

        download_url = (update_data or {}).get("download")

        if not download_url:
            self.news_box.append("Invalid update configuration.")
            return

        self.news_box.append("Update available. Downloading...")

        zip_data = download_update(download_url)

        if zip_data is None:
            self.news_box.append("Download failed.")
            return

        success = install_update(
            zip_data,
            version=server_version,
            expected_sha256=(update_data or {}).get("sha256"),
            expected_size=(update_data or {}).get("size"),
            manifest_authentication=(update_data or {}).get("manifest_authentication"),
        )

        if success:
            self.news_box.append("Update installed successfully.")
        else:
            self.news_box.append("Update install failed.")

    def write_update_summary(self, target_version=None):
        release_entry = load_recent_update_summary(target_version)
        launcher_version = self.release_info.get("version") or "unknown"

        if not release_entry:
            self.news_box.setPlainText(
                "\n".join(
                    [
                        "TrueCore Update",
                        "",
                        f"- Launcher version: v{launcher_version}",
                        "- Current release notes unavailable.",
                    ]
                )
            )
            return

        lines = [
            f"TrueCore Update v{release_entry['version']}",
        ]
        if release_entry.get("date"):
            lines.append(f"Released: {release_entry['date']}")
        lines.append("")
        for change in release_entry.get("changes", [])[:5]:
            lines.append(f"- {change}")
        self.news_box.setPlainText("\n".join(lines))

    def refresh_static_context(self):
        office_profile = dict(load_office_profile() or {})
        office_name = office_profile.get("office_name") or "Unknown Office"
        username_hint = (
            dict(office_profile.get("credential_policy") or {}).get("username_hint")
            or "No office username hint configured yet."
        )
        self.support_summary_label.setText(
            f"This launcher is tied to {office_name}. Support requests include launcher, program, and office details automatically."
        )
        self.username_hint_label.setText(f"Office username hint: {username_hint}")

    def update_launch_button_state(self):
        has_username = bool((self.username.text() or "").strip())
        has_password = bool((self.password.text() or "").strip())
        self.play_button.setEnabled(has_username and has_password)

    def handle_help_link(self, target):
        request_type = str(target or "").strip().lower()
        if request_type not in {"forgot_username", "forgot_password"}:
            return

        snapshot_path, payload = build_launcher_support_snapshot(request_type, update_state=self.last_update_state)
        recipient = resolve_it_email()
        mailto_url = build_support_mailto_url(request_type, snapshot_path, payload, recipient=recipient)

        if request_type == "forgot_username":
            office_profile = dict(load_office_profile() or {})
            username_hint = (
                dict(office_profile.get("credential_policy") or {}).get("username_hint")
                or "No office username hint configured yet."
            )
            self.news_box.append(f"\nUsername help requested. Hint: {username_hint}")
        else:
            self.news_box.append("\nPassword help requested. IT support draft prepared.")

        self.news_box.append(f"Support snapshot exported: {snapshot_path}")
        QDesktopServices.openUrl(QUrl(mailto_url))

    def launch_engine(self):
        username = (self.username.text() or "").strip()
        password = self.password.text() or ""

        if not username or not password.strip():
            log("Launcher sign-in blocked because required credentials were blank.")
            self.news_box.append("\nSign-in required. Enter both username and password before launching.")
            if not username:
                self.username.setFocus()
            else:
                self.password.setFocus()
            self.update_launch_button_state()
            return

        if not verify_launcher_credentials(username, password):
            log("Launcher sign-in failed.")
            self.news_box.append("\nAccess denied. Invalid username or password.")
            self.password.clear()
            self.password.setFocus()
            self.update_launch_button_state()
            return

        engine = find_engine()

        if engine is None:
            log("No engine found.")
            self.news_box.append("\nEngine not found. Please update.")
            return

        try:
            log(f"Launching TrueCore engine: {engine}")
            integrity_result = {"status": "source_mode"} if isinstance(engine, list) else verify_installed_engine_integrity()
            integrity_status = integrity_result.get("status")

            if integrity_status == "tampered":
                log("Blocked engine launch because local engine integrity verification failed.")
                self.news_box.append("\nEngine integrity check failed. Local engine files appear to have changed unexpectedly.")
                self.news_box.append("Please reinstall or update the engine before launching.")
                return

            if integrity_status == "compatibility_mode":
                self.news_box.append("\nEngine integrity metadata not found. Launching in compatibility mode.")

            popen_kwargs = {}
            if os.name == "nt":
                popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

            if isinstance(engine, list):
                subprocess.Popen(engine, **popen_kwargs)
            else:
                subprocess.Popen([engine], **popen_kwargs)

            self.close()

        except Exception as exc:
            log(f"Engine launch failed: {exc}")
            self.news_box.append(f"\nEngine launch failed: {exc}")

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
        self.news_box.append(f"\nSupport snapshot exported: {snapshot_path}")
        QDesktopServices.openUrl(QUrl(mailto_url))

    def open_docs(self):
        docs_source = resource_path("assets/docs/TrueCoreDocs.zip")
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")

        if not os.path.exists(docs_source):
            self.news_box.append(f"Docs not found: {docs_source}")
            return

        try:
            exported = export_docs_bundle(docs_source, desktop)
            bundle_dir = exported["bundle_dir"]
            index_path = exported["index_path"]
            record_docs_kit_exported()
            self.news_box.append("\nDocumentation kit exported to desktop.")
            self.news_box.append(f"Open the index first: {os.path.basename(index_path)}")
            QDesktopServices.openUrl(QUrl.fromLocalFile(bundle_dir))

        except Exception as exc:
            self.news_box.append(f"Docs error: {exc}")
