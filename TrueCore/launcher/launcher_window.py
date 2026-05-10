from PySide6.QtWidgets import (
    QWidget, QLabel, QPushButton, QTextEdit,
    QLineEdit, QVBoxLayout, QHBoxLayout, QFrame
)
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QPixmap, QIcon, QPainter, QDesktopServices

import subprocess
import os
import sys

from TrueCore.launcher.docs_catalog import export_docs_bundle
from TrueCore.launcher.launcher_logging import log
from TrueCore.launcher.updater import check_updates, download_update, install_update, verify_installed_engine_integrity
from TrueCore.core.office_rollout import record_docs_kit_exported
from TrueCore.utils.launcher_auth import ensure_launcher_auth_config, verify_launcher_credentials


ENGINE_DIR = "engine"


# -------------------------------------------------
# RESOURCE PATH (FOR PYINSTALLER)
# -------------------------------------------------

def resource_path(relative_path):

    if hasattr(sys, "_MEIPASS"):
        base_path = os.path.join(sys._MEIPASS, "launcher")
    else:
        base_path = os.path.abspath(os.path.dirname(__file__))

    return os.path.join(base_path, relative_path)


# -------------------------------------------------
# FIND ENGINE EXECUTABLE
# -------------------------------------------------

def find_engine():

    # DEV MODE
    if not getattr(sys, "frozen", False):
        return [sys.executable, "-m", "TrueCore.ui.pyside_gui.pyside_app"]

    # BUILT MODE
    base_dir = os.path.dirname(sys.executable)

    engine_path = os.path.join(base_dir, "engine", "TrueCoreEngine.exe")

    if os.path.exists(engine_path):
        return engine_path

    return None

# -------------------------------------------------
# LAUNCHER WINDOW
# -------------------------------------------------

class LauncherWindow(QWidget):

    def __init__(self):
        super().__init__()

        self.setWindowFlags(Qt.FramelessWindowHint)
        self.old_pos = None

        self.setWindowTitle("TrueCore Launcher")
        self.resize(300,375)
        self.move(500, 220)

        self.setWindowIcon(QIcon(resource_path("assets/truecore_icon.ico")))

        # -------------------------------------------------
        # LOAD BACKGROUND IMAGE
        # -------------------------------------------------

        self.bg = QPixmap(resource_path("assets/launcher_background.png"))

        # -------------------------------------------------
        # STYLE
        # -------------------------------------------------

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
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20,20,20,20)
        main_layout.setSpacing(15)

        # -------------------------------------------------
        # HEADER
        # -------------------------------------------------

        header_layout = QHBoxLayout()

        close_button = QPushButton("✕")
        close_button.setFixedSize(30, 30)
        close_button.clicked.connect(self.close)

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
        self.launcher_version = QLabel("Launcher v1.0")

        version_layout.addWidget(self.server_version)
        version_layout.addWidget(self.launcher_version)

        header_layout.addLayout(version_layout)

        main_layout.addLayout(header_layout)

        # -------------------------------------------------
        # CONTENT AREA
        # -------------------------------------------------

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
            "- New launcher system\n"
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

        self.play_button = QPushButton("Launch TrueCore")
        self.play_button.setIcon(QIcon(resource_path("assets/icons/launch.svg")))
        self.play_button.clicked.connect(self.launch_engine)
        self.username.returnPressed.connect(self.launch_engine)
        self.password.returnPressed.connect(self.launch_engine)

        login_layout.addWidget(login_title)
        login_layout.addWidget(self.username)
        login_layout.addWidget(self.password)
        login_layout.addStretch()
        login_layout.addWidget(self.play_button)

        login_panel.setLayout(login_layout)

        content_layout.addWidget(news_panel, 3)
        content_layout.addWidget(login_panel, 1)

        main_layout.addLayout(content_layout)

        # -------------------------------------------------
        # FOOTER
        # -------------------------------------------------

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
        self.auto_update()

    # -------------------------------------------------
    # DRAW BACKGROUND
    # -------------------------------------------------

    def paintEvent(self, event):

        painter = QPainter(self)

        if not self.bg.isNull():
            painter.drawPixmap(self.rect(), self.bg)

    # -------------------------------------------------
    # WINDOW DRAGGING
    # -------------------------------------------------

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

    # -------------------------------------------------
    # AUTO UPDATE CHECK
    # -------------------------------------------------

    def auto_update(self):

        self.news_box.append("\nChecking for updates...")

        update_data = check_updates()

        status = update_data.get("status") if update_data else "error"

        if status == "error":
            self.news_box.append(update_data.get("message", "Update server unreachable."))
            return

        server_version = (update_data.get("version") or "").strip()
        manifest_auth = dict(update_data.get("manifest_authentication") or {})

        if server_version:
            self.server_version.setText(f"Server v{server_version}")

        local_version = (update_data.get("local_version") or "-").strip()

        self.news_box.append(f"Latest engine version: {server_version}")
        self.news_box.append(f"Installed engine version: {local_version}")
        if manifest_auth.get("status") == "verified":
            self.news_box.append("Update manifest signature verified.")
        elif manifest_auth.get("status") == "unsigned_compatibility":
            self.news_box.append("Update manifest is running in compatibility mode.")

        if status == "up_to_date":
            self.news_box.append("Engine is already up to date.")
            return
        
        download_url = update_data.get("download")

        if not download_url:
            self.news_box.append("Invalid update configuration.")
            return

        self.news_box.append("Update available. Downloading...")

        zip_data = download_update(download_url)

        if zip_data is None:
            self.news_box.append("Download failed.")
            return

        # ----------------------------------------------
        # INSTALL UPDATE (PASS SERVER VERSION)
        # ----------------------------------------------

        success = install_update(
            zip_data,
            version=server_version,
            expected_sha256=update_data.get("sha256"),
            expected_size=update_data.get("size"),
            manifest_authentication=update_data.get("manifest_authentication"),
        )

        if success:
            self.news_box.append("Update installed successfully.")
        else:
            self.news_box.append("Update install failed.")


    # -------------------------------------------------
    # ENGINE LAUNCH
    # -------------------------------------------------

    def launch_engine(self):

        username = self.username.text()
        password = self.password.text()

        if not verify_launcher_credentials(username, password):
            log("Launcher sign-in failed.")
            self.news_box.append("\nAccess denied. Invalid username or password.")
            self.password.clear()
            self.password.setFocus()
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

        except Exception as e:
            log(f"Engine launch failed: {e}")
            self.news_box.append(f"\nEngine launch failed: {e}")

    # -------------------------------------------------
    # LINKS
    # -------------------------------------------------

    def open_website(self):
        QDesktopServices.openUrl(QUrl("https://thetrubrain.com/"))

    def open_blog(self):
        QDesktopServices.openUrl(QUrl("https://thetrubrain.com/blog/"))

    def open_support(self):
        QDesktopServices.openUrl(QUrl("mailto:info@thetrubrain.com"))

    def open_report(self):
        QDesktopServices.openUrl(QUrl("mailto:aaron@betteryourpractice.com"))

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

        except Exception as e:
            self.news_box.append(f"Docs error: {e}")
