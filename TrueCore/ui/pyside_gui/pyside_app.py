import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont

from TrueCore.utils.runtime_info import resource_path
from TrueCore.ui.pyside_gui.main_window import MainWindow


def launch_gui():

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
