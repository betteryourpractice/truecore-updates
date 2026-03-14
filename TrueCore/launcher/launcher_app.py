from PySide6.QtWidgets import QApplication
import sys
import os

from TrueCore.launcher.launcher_window import LauncherWindow


# -------------------------------------------------
# RESOURCE PATH (FOR PYINSTALLER)
# -------------------------------------------------

def resource_path(relative_path):

    if hasattr(sys, "_MEIPASS"):
        base_path = os.path.join(sys._MEIPASS, "launcher")
    else:
        base_path = os.path.abspath(os.path.dirname(__file__))

    return os.path.join(base_path, relative_path)
    """
    Get absolute path to resource for development or PyInstaller.
    """

    if hasattr(sys, "_MEIPASS"):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(os.path.dirname(__file__))

    return os.path.join(base_path, relative_path)


def start_launcher():

    app = QApplication(sys.argv)

    app.setApplicationName("TrueCore Launcher")

    # --------------------------------
    # LOAD STYLESHEET
    # --------------------------------

    try:

        style_path = resource_path(
            "assets/launcher_style.qss"
        )

        with open(style_path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())

    except Exception as e:

        print(f"Launcher style failed to load: {e}")

    # --------------------------------
    # START WINDOW
    # --------------------------------

    window = LauncherWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":

    start_launcher()