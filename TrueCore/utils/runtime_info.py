import os
import sys
import json

# -------------------------------------------------
# RESOURCE PATH
# -------------------------------------------------

def resource_path(relative_path):

    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    return os.path.join(base_path, relative_path)


# -------------------------------------------------
# RUNTIME ENVIRONMENT
# -------------------------------------------------

def ensure_runtime_environment():

    logs_path = resource_path("logs")
    dev_path = resource_path("dev_system")

    os.makedirs(logs_path, exist_ok=True)
    os.makedirs(dev_path, exist_ok=True)

    log_file = resource_path("logs/activity.log")

    if not os.path.exists(log_file):
        open(log_file, "w").close()

    tracker_file = resource_path("dev_system/dev_tracker.json")

    if not os.path.exists(tracker_file):

        with open(tracker_file, "w") as f:

            json.dump(
                {"tasks": [{"description": "Initial system setup"}]},
                f,
                indent=4
            )

    rotation_file = resource_path("dev_system/rotation_state.json")

    if not os.path.exists(rotation_file):

        with open(rotation_file, "w") as f:

            json.dump(
                {"current_cycle": "System Stable"},
                f,
                indent=4
            )

# -------------------------------------------------
# LOAD SUPPORT FILES
# -------------------------------------------------

def get_version():

    path = resource_path("VERSION.txt")

    if not os.path.exists(path):
        return "unknown"

    with open(path, "r") as f:
        return f.read().strip()


def get_build_info():

    path = resource_path("build_info.txt")

    if not os.path.exists(path):
        return None, None

    build_id = None
    timestamp = None

    try:

        with open(path, "r") as f:

            for line in f:

                if line.startswith("BUILD_ID="):
                    build_id = line.split("=",1)[1].strip()

                if line.startswith("TIMESTAMP="):
                    timestamp = line.split("=",1)[1].strip()

    except Exception:
        pass

    return build_id, timestamp
def get_latest_update_title():

    path = resource_path("CHANGELOG.txt")

    if not os.path.exists(path):
        return None

    try:

        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # scan from bottom of file upward
        for line in reversed(lines):

            if line.startswith("-"):
                return line.lstrip("-").strip()

    except Exception:
        pass

    return None
