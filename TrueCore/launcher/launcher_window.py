from PySide6.QtWidgets import (
    QWidget, QLabel, QPushButton, QTextEdit,
    QLineEdit, QVBoxLayout, QHBoxLayout, QFrame,
    QScrollArea,
    QDialog, QCheckBox, QMessageBox
)
from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QPixmap, QIcon, QPainter, QDesktopServices, QGuiApplication

import subprocess
import os
import sys
import re

from TrueCore.launcher.docs_catalog import export_docs_bundle
from TrueCore.launcher.launcher_logging import log
from TrueCore.launcher.launcher_support import (
    apply_launcher_release_profile,
    build_launcher_support_snapshot,
    build_support_mailto_url,
    load_launcher_release_info,
    resolve_it_email,
    validate_engine_bundle_lane,
)
from TrueCore.launcher.updater import (
    check_updates,
    download_update,
    get_local_version,
    install_update,
    resolve_engine_executable_path,
    verify_installed_engine_integrity,
)
from TrueCore.core.office_rollout import (
    load_office_profile,
    office_setup_is_required,
    record_docs_kit_exported,
    record_office_profile_confirmed,
    update_office_profile,
)
from TrueCore.utils.admin_auth import ensure_admin_auth_config, update_admin_password
from TrueCore.utils.launcher_auth import (
    ensure_launcher_auth_config,
    launcher_auth_uses_default_credentials,
    load_launcher_auth_config,
    update_launcher_credentials,
    verify_launcher_credentials,
)
from TrueCore.utils.install_mode import (
    get_primary_update_channel,
    get_reference_update_channel,
    is_dev_install,
)
from TrueCore.utils.runtime_info import format_version_display


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
    engine_path = resolve_engine_executable_path(base_dir)

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
        self.install_profile = dict(apply_launcher_release_profile(release_info=self.release_info) or {})
        self.is_dev_launcher = str(self.release_info.get("update_channel") or "").strip().lower() == "dev"
        self.setup_required = False
        self.setup_prompted = False

        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowTitle("TrueCore Dev Launcher" if self.is_dev_launcher else "TrueCore Office Launcher")
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

        self.server_version = QLabel("Server -")
        launcher_version = self.release_info.get("version") or "1.0"
        self.launcher_version = QLabel(f"Launcher {format_version_display(launcher_version)}")

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

        self.setup_button = QPushButton("Complete First-Time Setup")
        self.setup_button.clicked.connect(self.open_first_time_setup_dialog)
        self.setup_button.setVisible(False)

        login_layout.addWidget(login_title)
        login_layout.addWidget(self.username)
        login_layout.addWidget(self.password)
        login_layout.addWidget(self.help_links)
        login_layout.addWidget(self.support_snapshot_title)
        login_layout.addWidget(self.support_summary_label)
        login_layout.addWidget(self.username_hint_label)
        login_layout.addStretch()
        login_layout.addWidget(self.setup_button)
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
        ensure_admin_auth_config()
        self.refresh_static_context()
        self.update_launch_button_state()
        self.center_on_screen()
        self.auto_update()
        QTimer.singleShot(0, self.maybe_run_first_time_setup)

    def channel_display_name(self, channel_name):
        normalized = str(channel_name or "").strip().lower()
        if normalized == "dev":
            return "Dev"
        if normalized == "production":
            return "Production"
        return "Custom"

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
        self.install_profile = dict(apply_launcher_release_profile(release_info=self.release_info) or {})
        primary_channel = get_primary_update_channel(self.install_profile)
        reference_channel = get_reference_update_channel(self.install_profile)

        self.news_box.clear()
        self.write_update_summary()
        self.news_box.append("\nChecking for updates...")
        if is_dev_install(self.install_profile):
            self.news_box.append(
                f"Machine role: Dev | Primary channel: {self.channel_display_name(primary_channel)}"
            )

        update_data = check_updates(primary_channel)
        status = update_data.get("status") if update_data else "error"
        self.last_update_state = dict(update_data or {})

        reference_update = None
        if reference_channel:
            reference_update = check_updates(reference_channel)
            self.last_update_state["reference_channel"] = dict(reference_update or {})

        if status == "error":
            message = (update_data or {}).get("message", "Update server unreachable.")
            self.news_box.append(message)
            if reference_update and reference_update.get("version"):
                self.news_box.append(
                    f"{self.channel_display_name(reference_channel)} reference: {format_version_display(reference_update.get('version'))}"
                )
            return

        server_version = str((update_data or {}).get("version") or "").strip()
        manifest_auth = dict((update_data or {}).get("manifest_authentication") or {})
        primary_channel_name = self.channel_display_name((update_data or {}).get("channel") or primary_channel)

        if server_version:
            self.server_version.setText(f"{primary_channel_name} {format_version_display(server_version)}")
            self.write_update_summary(server_version)

        local_version = str((update_data or {}).get("local_version") or get_local_version() or "-").strip()

        self.news_box.append(f"Latest {primary_channel_name.lower()} engine version: {server_version}")
        self.news_box.append(f"Installed engine version: {local_version}")
        if reference_update and reference_update.get("version"):
            self.news_box.append(
                f"{self.channel_display_name(reference_channel)} reference version: {reference_update.get('version')}"
            )
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

        download_headers = (update_data or {}).get("download_headers")
        zip_data = download_update(download_url, request_headers=download_headers)

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
                        f"- Launcher version: {format_version_display(launcher_version)}",
                        "- Release notes were not bundled with this launcher build.",
                    ]
                )
            )
            return

        lines = [
            f"TrueCore Update {format_version_display(release_entry['version'])}",
        ]
        if release_entry.get("date"):
            lines.append(f"Released: {release_entry['date']}")
        lines.append("")
        for change in release_entry.get("changes", [])[:5]:
            lines.append(f"- {change}")
        self.news_box.setPlainText("\n".join(lines))

    def refresh_static_context(self):
        self.install_profile = dict(apply_launcher_release_profile(release_info=self.release_info) or {})
        office_profile = dict(load_office_profile() or {})
        office_name = office_profile.get("office_name") or "Unknown Office"
        username_hint = (
            dict(office_profile.get("credential_policy") or {}).get("username_hint")
            or "No office username hint configured yet."
        )
        self.setup_required = (
            not is_dev_install(self.install_profile)
            and not self.is_dev_launcher
            and office_setup_is_required(profile=office_profile)
        )
        if self.setup_required:
            self.support_summary_label.setText(
                "First-time office setup is required before staff can sign in. Claim this install, set office credentials, and define the office manager password."
            )
            self.username_hint_label.setText("Sign-in unlocks after first-time setup is completed.")
        elif is_dev_install(self.install_profile):
            self.support_summary_label.setText(
                f"Developer workspace is active for {office_name}. Support requests include channel, launcher, program, and office details automatically."
            )
            self.username_hint_label.setText(f"Office login hint: {username_hint}")
        else:
            self.support_summary_label.setText(
                f"Office workspace: {office_name}. Support requests include launcher, program, and office details automatically."
            )
            self.username_hint_label.setText(f"Office login hint: {username_hint}")
        self.setup_button.setVisible(self.setup_required)

    def update_launch_button_state(self):
        has_username = bool((self.username.text() or "").strip())
        has_password = bool((self.password.text() or "").strip())
        sign_in_enabled = has_username and has_password and not self.setup_required
        self.username.setEnabled(not self.setup_required)
        self.password.setEnabled(not self.setup_required)
        self.help_links.setEnabled(not self.setup_required)
        self.play_button.setText("Setup Required" if self.setup_required else "Launch TrueCore")
        self.play_button.setEnabled(sign_in_enabled)

    def maybe_run_first_time_setup(self):
        self.refresh_static_context()
        self.update_launch_button_state()
        if self.setup_required and not self.setup_prompted:
            self.setup_prompted = True
            self.open_first_time_setup_dialog()

    def handle_help_link(self, target):
        request_type = str(target or "").strip().lower()
        if request_type not in {"forgot_username", "forgot_password"}:
            return

        if self.setup_required:
            self.news_box.append("\nComplete first-time office setup before requesting sign-in help.")
            self.open_first_time_setup_dialog()
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

    def open_first_time_setup_dialog(self):
        if self.is_dev_launcher or is_dev_install(self.install_profile):
            return

        profile = dict(load_office_profile() or {})
        current_launcher_auth = dict(load_launcher_auth_config() or {})
        current_username_hint = (
            dict(profile.get("credential_policy") or {}).get("username_hint")
            or current_launcher_auth.get("username")
            or ""
        )
        if launcher_auth_uses_default_credentials(current_launcher_auth):
            current_username_hint = ""

        dialog = QDialog(self)
        dialog.setWindowTitle("First-Time Office Setup")
        dialog.setModal(True)
        dialog.setMinimumSize(540, 520)
        available = QGuiApplication.primaryScreen().availableGeometry() if QGuiApplication.primaryScreen() else None
        if available is not None:
            dialog.resize(min(680, max(540, available.width() - 160)), min(820, max(560, available.height() - 120)))
        else:
            dialog.resize(620, 720)
        dialog.setSizeGripEnabled(True)
        dialog.setStyleSheet(
            """
            QDialog {
                background-color: #11161E;
                color: #E5E7EB;
            }
            QLabel#setupTitle {
                color: #FFFFFF;
                font-size: 18px;
                font-weight: 700;
            }
            QLabel#setupSubtitle {
                color: #9CA3AF;
                font-size: 12px;
            }
            QLabel#setupFieldLabel {
                color: #DCE6F2;
                font-size: 12px;
                font-weight: 600;
                margin-bottom: 4px;
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
            QCheckBox {
                color: #DCE6F2;
                spacing: 8px;
            }
            QPushButton {
                background-color: #1A2430;
                color: #E5E7EB;
                border: 1px solid #2B3A4D;
                border-radius: 6px;
                padding: 9px 16px;
                min-width: 110px;
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
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        scroll = QScrollArea(dialog)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(
            "QScrollArea { background-color: transparent; border: 0; } "
            "QScrollArea > QWidget > QWidget { background-color: transparent; }"
        )
        layout.addWidget(scroll, 1)

        content = QWidget()
        scroll.setWidget(content)

        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(6, 6, 10, 6)
        content_layout.setSpacing(12)

        title = QLabel("Claim This Office Install")
        title.setObjectName("setupTitle")
        content_layout.addWidget(title)

        subtitle = QLabel(
            "Complete this one-time setup before staff sign in. This defines the office identity, launcher credentials, and office manager password for this install."
        )
        subtitle.setWordWrap(True)
        subtitle.setObjectName("setupSubtitle")
        content_layout.addWidget(subtitle)

        def add_field(label_text, placeholder="", text="", password=False):
            label = QLabel(label_text)
            label.setObjectName("setupFieldLabel")
            label.setWordWrap(True)
            content_layout.addWidget(label)
            field = QLineEdit()
            field.setPlaceholderText(placeholder)
            field.setText(str(text or ""))
            if password:
                field.setEchoMode(QLineEdit.Password)
            content_layout.addWidget(field)
            return field

        organization_id_edit = add_field(
            "Organization ID / Parent Group",
            "Example: betteryourpractice",
            profile.get("organization_id") if profile.get("organization_id") != "organization-pending" else "",
        )
        office_id_edit = add_field(
            "Office ID",
            "Example: aiken-sc",
            profile.get("office_id") if profile.get("office_id") != "office-pending" else "",
        )
        office_name_edit = add_field(
            "Office Name",
            "Example: Aiken Neuroscience",
            profile.get("office_name") if profile.get("office_name") != "Office Setup Required" else "",
        )
        support_name_edit = add_field(
            "Support Contact Name",
            "Optional",
            profile.get("support_contact_name") or "",
        )
        support_email_edit = add_field(
            "Support Contact Email",
            "Optional",
            profile.get("support_contact_email") or "",
        )
        launcher_username_edit = add_field(
            "Launcher Username",
            "Office login username",
            current_username_hint,
        )
        launcher_password_edit = add_field(
            "Launcher Password",
            "At least 8 characters",
            password=True,
        )
        launcher_password_confirm_edit = add_field(
            "Confirm Launcher Password",
            "Repeat launcher password",
            password=True,
        )
        manager_password_edit = add_field(
            "Office Manager Password",
            "At least 8 characters",
            password=True,
        )
        manager_password_confirm_edit = add_field(
            "Confirm Office Manager Password",
            "Repeat office manager password",
            password=True,
        )

        export_docs_checkbox = QCheckBox("Export onboarding kit to the desktop after setup")
        export_docs_checkbox.setChecked(not profile.get("onboarding", {}).get("docs_kit_exported_at"))
        content_layout.addWidget(export_docs_checkbox)
        content_layout.addStretch()

        button_row = QHBoxLayout()
        button_row.addStretch()
        cancel_button = QPushButton("Cancel")
        save_button = QPushButton("Complete Setup")
        save_button.setObjectName("primaryButton")
        button_row.addWidget(cancel_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)

        cancel_button.clicked.connect(dialog.reject)

        def complete_setup():
            organization_id = organization_id_edit.text().strip()
            office_id = office_id_edit.text().strip()
            office_name = office_name_edit.text().strip()
            launcher_username = launcher_username_edit.text().strip()
            launcher_password = launcher_password_edit.text()
            launcher_password_confirm = launcher_password_confirm_edit.text()
            manager_password = manager_password_edit.text()
            manager_password_confirm = manager_password_confirm_edit.text()
            support_email = support_email_edit.text().strip()

            if not organization_id or not office_id or not office_name:
                QMessageBox.warning(dialog, "Setup Incomplete", "Organization ID, Office ID, and Office Name are required.")
                return
            if not launcher_username:
                QMessageBox.warning(dialog, "Setup Incomplete", "Launcher username is required.")
                return
            if len(launcher_password.strip()) < 8:
                QMessageBox.warning(dialog, "Launcher Password", "Launcher password must be at least 8 characters.")
                return
            if launcher_password != launcher_password_confirm:
                QMessageBox.warning(dialog, "Launcher Password", "Launcher password confirmation does not match.")
                return
            if len(manager_password.strip()) < 8:
                QMessageBox.warning(dialog, "Office Manager Password", "Office manager password must be at least 8 characters.")
                return
            if manager_password != manager_password_confirm:
                QMessageBox.warning(dialog, "Office Manager Password", "Office manager password confirmation does not match.")
                return
            if support_email and "@" not in support_email:
                QMessageBox.warning(dialog, "Support Contact Email", "Enter a valid support email address or leave it blank.")
                return

            try:
                update_launcher_credentials(launcher_username, launcher_password)
                update_admin_password(manager_password)
                update_office_profile(
                    {
                        "organization_id": organization_id,
                        "office_id": office_id,
                        "office_name": office_name,
                        "support_contact_name": support_name_edit.text().strip(),
                        "support_contact_email": support_email,
                        "credential_policy": {
                            "mode": "local_install_shared",
                            "username_hint": launcher_username,
                            "per_office_ready": True,
                            "future_plan": "per_office_credentials",
                        },
                    }
                )
                record_office_profile_confirmed()
            except Exception as exc:
                QMessageBox.warning(dialog, "Setup Failed", str(exc))
                return

            dialog.accept()

        save_button.clicked.connect(complete_setup)

        if dialog.exec() != QDialog.Accepted:
            if self.setup_required:
                self.news_box.append("\nFirst-time office setup is still required before staff can sign in.")
                self.update_launch_button_state()
            return

        self.refresh_static_context()
        self.username.setText(
            dict(load_office_profile().get("credential_policy") or {}).get("username_hint")
            or launcher_username_edit.text().strip()
        )
        self.password.clear()
        self.update_launch_button_state()
        self.news_box.append("\nFirst-time office setup completed. Sign in using the new office launcher credentials.")

        if export_docs_checkbox.isChecked():
            self.open_docs()

    def launch_engine(self):
        if self.setup_required:
            self.news_box.append("\nFirst-time office setup must be completed before launch.")
            self.open_first_time_setup_dialog()
            return

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

            lane_result = validate_engine_bundle_lane(
                release_info=self.release_info,
                integrity_result=integrity_result,
            )
            if lane_result.get("status") != "verified":
                log(
                    "Blocked engine launch because launcher/engine lane verification failed: "
                    f"{lane_result}"
                )
                self.news_box.append("\nLaunch blocked. The packaged engine does not match this launcher.")
                self.news_box.append(
                    f"Expected {lane_result.get('expected_role') or 'unknown'} runtime, "
                    f"but detected {lane_result.get('actual_role') or 'unknown'} "
                    f"({lane_result.get('version') or 'unknown'})."
                )
                self.news_box.append(
                    "Reinstall this lane from the matching OFFICE or DEVELOPMENT folder before continuing."
                )
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
