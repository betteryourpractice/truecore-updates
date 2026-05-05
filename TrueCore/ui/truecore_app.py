"""
TrueCore Application Entrypoint

Provides runtime helpers and launches the active GUI
implementation for the TrueCore engine.
"""

import os
import json

from TrueCore.utils.runtime_info import resource_path


SUPPORTED_EXTENSIONS = (
    ".pdf", ".docx", ".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".txt"
)

LOGO_WIDTH = 220
LOGO_HEIGHT = 120
MAX_WORKERS = 6





def load_dev_tracker():

    path = resource_path("dev_system/dev_tracker.json")

    if not os.path.exists(path):
        return None

    try:

        with open(path, "r") as f:
            return json.load(f)

    except Exception:
        return None


def load_rotation():

    path = resource_path("dev_system/rotation_state.json")

    if not os.path.exists(path):
        return None

    try:

        with open(path, "r") as f:
            return json.load(f)

    except Exception:
        return None


def load_changelog():

    path = resource_path("CHANGELOG.txt")

    if not os.path.exists(path):
        return ""

    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_activity_log():

    path = resource_path("logs/activity.log")

    if not os.path.exists(path):
        return "No activity log yet."

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Reverse order so newest events appear first
    lines = list(reversed(lines))

    return "".join(lines[:200])
    
def detect_development_cycle(changelog):

    text = changelog.lower()

    if "intelligence" in text:
        return "Intelligence Upgrade"

    if "validation" in text or "validator" in text:
        return "Validation Development"

    if "gui" in text or "interface" in text:
        return "Interface Development"

    if "architecture" in text or "build" in text:
        return "Infrastructure Development"

    if "security" in text or "logging" in text:
        return "Security Hardening"

    return "System Stable"


# -------------------------------------------------
# PROGRAM ENTRY
# -------------------------------------------------

from TrueCore.ui.pyside_gui.pyside_app import launch_gui

if __name__ == "__main__":
    launch_gui()
