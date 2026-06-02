import sys
import warnings
import os
import json
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont

from TrueCore.utils.runtime_info import resource_path
from TrueCore.utils.runtime_identity import resolve_runtime_identity
from TrueCore.utils.install_mode import load_install_profile
from TrueCore.utils.private_dev_channel import load_private_dev_channel_config


def configure_runtime_warnings():

    try:
        from requests.exceptions import RequestsDependencyWarning
    except Exception:
        RequestsDependencyWarning = None

    if RequestsDependencyWarning is not None:
        warnings.filterwarnings("ignore", category=RequestsDependencyWarning)


def emit_runtime_diagnostic():

    runtime_identity = resolve_runtime_identity(
        install_profile=load_install_profile(),
        private_dev_channel=load_private_dev_channel_config(),
    )
    payload = {
        "version": runtime_identity.get("version"),
        "embedded_dev_build": bool(runtime_identity.get("embedded_dev_build")),
        "machine_role": runtime_identity.get("machine_role"),
        "primary_update_channel": runtime_identity.get("primary_update_channel"),
        "reference_update_channel": runtime_identity.get("reference_update_channel"),
        "developer_tools_enabled": bool(runtime_identity.get("developer_tools_enabled")),
    }

    output_path = str(os.environ.get("TRUECORE_RUNTIME_DIAGNOSTIC_FILE") or "").strip()
    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=4, ensure_ascii=True, sort_keys=True)
    else:
        print(json.dumps(payload, indent=4, ensure_ascii=True, sort_keys=True))


def launch_gui():

    configure_runtime_warnings()

    if str(os.environ.get("TRUECORE_RUNTIME_DIAGNOSTIC") or "").strip() == "1":
        emit_runtime_diagnostic()
        return

    from TrueCore.ui.pyside_gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))

    # -------------------------------------------------
    # LOAD TRUESUITE THEME
    # -------------------------------------------------

    theme_path = resource_path("ui/pyside_gui/truesuite_theme.qss")

    with open(theme_path, "r") as f:
        app.setStyleSheet(f.read())

    # -------------------------------------------------

    window = MainWindow()
    window.show()

    sys.exit(app.exec())

# -------------------------------------------------
# ENTRY POINT
# -------------------------------------------------

if __name__ == "__main__":
    launch_gui()   
