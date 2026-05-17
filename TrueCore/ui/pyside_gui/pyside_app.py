import sys
import warnings
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont

from TrueCore.utils.runtime_info import resource_path


def configure_runtime_warnings():

    try:
        from requests.exceptions import RequestsDependencyWarning
    except Exception:
        RequestsDependencyWarning = None

    if RequestsDependencyWarning is not None:
        warnings.filterwarnings("ignore", category=RequestsDependencyWarning)


def launch_gui():

    configure_runtime_warnings()

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
