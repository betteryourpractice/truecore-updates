import os
import sys
import json
import shutil
import re

OFFICE_SYSTEM_DIR_NAME = "office_system"
DEV_SYSTEM_DIR_NAME = "dev_system"
RUNTIME_STATE_DIR_NAME = "runtime_state"

OFFICE_SYSTEM_FILE_NAMES = {
    "admin_auth.json",
    "deployment_manifest.json",
    "install_profile.json",
    "launcher_auth.json",
    "launcher_support.json",
    "office_profile.json",
}
RUNTIME_STATE_FILE_NAMES = {
    "dev_tracker.json",
    "rotation_state.json",
}

# -------------------------------------------------
# RESOURCE PATH
# -------------------------------------------------

def resource_path(relative_path):

    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    return os.path.join(base_path, relative_path)


def get_runtime_root():

    if getattr(sys, "frozen", False):
        base_dir = os.path.dirname(os.path.abspath(sys.executable))

        if os.path.basename(base_dir).strip().lower() == "engine":
            return os.path.dirname(base_dir)

        return base_dir

    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def get_runtime_project_dir():
    return os.path.join(get_runtime_root(), "TrueCore")


_RUNTIME_DATA_READY = False


def get_runtime_data_root():

    override = str(os.environ.get("TRUECORE_DATA_DIR") or "").strip()
    if override:
        return override

    if os.name == "nt":
        base_dir = (
            str(os.environ.get("LOCALAPPDATA") or "").strip()
            or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        )
        return os.path.join(base_dir, "TrueCore")

    return os.path.join(os.path.expanduser("~"), ".truecore")


def _copy_tree_contents(source_dir, target_dir):

    if not os.path.isdir(source_dir):
        return

    os.makedirs(target_dir, exist_ok=True)

    for name in os.listdir(source_dir):
        source_path = os.path.join(source_dir, name)
        target_path = os.path.join(target_dir, name)

        if os.path.isdir(source_path):
            shutil.copytree(source_path, target_path, dirs_exist_ok=True)
        elif not os.path.exists(target_path):
            shutil.copy2(source_path, target_path)


def _copy_file_if_missing(source_path, target_path):

    if not os.path.isfile(source_path) or os.path.exists(target_path):
        return False

    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    shutil.copy2(source_path, target_path)
    return True


def _copy_file_if_richer(source_path, target_path):

    if not os.path.isfile(source_path):
        return False

    source_size = os.path.getsize(source_path)
    target_size = os.path.getsize(target_path) if os.path.isfile(target_path) else -1

    if source_size <= target_size:
        return False

    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    shutil.copy2(source_path, target_path)
    return True


def _copy_named_files_if_missing(source_dir, target_dir, file_names):

    if not os.path.isdir(source_dir):
        return False

    copied_any = False
    os.makedirs(target_dir, exist_ok=True)

    for file_name in sorted(set(file_names or [])):
        source_path = os.path.join(source_dir, file_name)
        target_path = os.path.join(target_dir, file_name)
        if _copy_file_if_missing(source_path, target_path):
            copied_any = True

    return copied_any


def _read_text_file(path):

    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            value = str(handle.read() or "").strip()
            return value or None
    except Exception:
        return None


def _read_version_from_build_info(path):

    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            for line in handle:
                if line.startswith("VERSION="):
                    version = line.split("=", 1)[1].strip()
                    if version:
                        return version
    except Exception:
        return None

    return None


def _legacy_runtime_project_dirs():

    candidates = []
    install_project_dir = get_runtime_project_dir()
    candidates.append(install_project_dir)

    exe_dir = os.path.dirname(os.path.abspath(getattr(sys, "executable", "")))
    if getattr(sys, "frozen", False) and os.path.basename(exe_dir).strip().lower() == "engine":
        candidates.append(os.path.join(os.path.dirname(exe_dir), "TrueCore"))

    unique = []
    seen = set()
    for path in candidates:
        normalized = os.path.normcase(os.path.abspath(path))
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(path)
    return unique


def _path_has_runtime_state(project_dir):

    checks = [
        os.path.join(project_dir, "Outputs", "truecore_memory.db"),
        os.path.join(project_dir, OFFICE_SYSTEM_DIR_NAME, "office_profile.json"),
        os.path.join(project_dir, OFFICE_SYSTEM_DIR_NAME, "launcher_auth.json"),
        os.path.join(project_dir, DEV_SYSTEM_DIR_NAME, "office_profile.json"),
        os.path.join(project_dir, DEV_SYSTEM_DIR_NAME, "launcher_auth.json"),
        os.path.join(project_dir, "logs", "activity.log"),
    ]
    return any(os.path.exists(path) for path in checks)


def _migrate_runtime_aliases(target_root):

    legacy_dev_dir = os.path.join(target_root, DEV_SYSTEM_DIR_NAME)
    office_dir = os.path.join(target_root, OFFICE_SYSTEM_DIR_NAME)
    state_dir = os.path.join(target_root, RUNTIME_STATE_DIR_NAME)

    _copy_named_files_if_missing(legacy_dev_dir, office_dir, OFFICE_SYSTEM_FILE_NAMES)
    _copy_named_files_if_missing(legacy_dev_dir, state_dir, RUNTIME_STATE_FILE_NAMES)


def ensure_runtime_data_root():

    global _RUNTIME_DATA_READY

    target_root = get_runtime_data_root()
    os.makedirs(target_root, exist_ok=True)

    if _RUNTIME_DATA_READY:
        return target_root

    _RUNTIME_DATA_READY = True

    target_norm = os.path.normcase(os.path.abspath(target_root))

    for legacy_dir in _legacy_runtime_project_dirs():
        legacy_norm = os.path.normcase(os.path.abspath(legacy_dir))
        if legacy_norm == target_norm:
            continue
        if not _path_has_runtime_state(legacy_dir):
            continue

        source_db = os.path.join(legacy_dir, "Outputs", "truecore_memory.db")
        target_db = os.path.join(target_root, "Outputs", "truecore_memory.db")
        _copy_file_if_richer(source_db, target_db)

        for folder_name in ("logs",):
            source_dir = os.path.join(legacy_dir, folder_name)
            target_dir = os.path.join(target_root, folder_name)
            _copy_tree_contents(source_dir, target_dir)

        for folder_name in ("Outputs", DEV_SYSTEM_DIR_NAME, OFFICE_SYSTEM_DIR_NAME, RUNTIME_STATE_DIR_NAME):
            source_dir = os.path.join(legacy_dir, folder_name)
            target_dir = os.path.join(target_root, folder_name)
            if not os.path.isdir(source_dir):
                continue
            os.makedirs(target_dir, exist_ok=True)
            for name in os.listdir(source_dir):
                source_path = os.path.join(source_dir, name)
                target_path = os.path.join(target_dir, name)
                if os.path.isdir(source_path):
                    if not os.path.exists(target_path):
                        shutil.copytree(source_path, target_path, dirs_exist_ok=True)
                    continue
                if os.path.normcase(os.path.abspath(source_path)) == os.path.normcase(os.path.abspath(source_db)):
                    continue
                _copy_file_if_missing(source_path, target_path)
        break

    _migrate_runtime_aliases(target_root)

    return target_root


def runtime_data_path(*parts, ensure_parent=False):

    path = os.path.join(ensure_runtime_data_root(), *parts)

    if ensure_parent:
        os.makedirs(os.path.dirname(path), exist_ok=True)

    return path


def runtime_dir_path(*parts):

    path = runtime_data_path(*parts)
    os.makedirs(path, exist_ok=True)
    return path


def office_runtime_data_path(*parts, ensure_parent=False):
    return runtime_data_path(OFFICE_SYSTEM_DIR_NAME, *parts, ensure_parent=ensure_parent)


def dev_runtime_data_path(*parts, ensure_parent=False):
    return runtime_data_path(DEV_SYSTEM_DIR_NAME, *parts, ensure_parent=ensure_parent)


def runtime_state_path(*parts, ensure_parent=False):
    return runtime_data_path(RUNTIME_STATE_DIR_NAME, *parts, ensure_parent=ensure_parent)


# -------------------------------------------------
# RUNTIME ENVIRONMENT
# -------------------------------------------------

def ensure_runtime_environment():

    runtime_dir_path("logs")
    runtime_dir_path(OFFICE_SYSTEM_DIR_NAME)
    runtime_dir_path(RUNTIME_STATE_DIR_NAME)

    log_file = runtime_data_path("logs", "activity.log", ensure_parent=True)

    if not os.path.exists(log_file):
        open(log_file, "w").close()

    tracker_file = runtime_state_path("dev_tracker.json", ensure_parent=True)

    if not os.path.exists(tracker_file):

        with open(tracker_file, "w") as f:

            json.dump(
                {"tasks": [{"description": "Initial system setup"}]},
                f,
                indent=4
            )

    rotation_file = runtime_state_path("rotation_state.json", ensure_parent=True)

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

    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(getattr(sys, "executable", "")))
        frozen_candidates = []

        if exe_dir:
            frozen_candidates.append(os.path.join(exe_dir, "version.txt"))
            frozen_candidates.append(os.path.join(exe_dir, "VERSION.txt"))

        for path in frozen_candidates:
            version = _read_text_file(path)
            if version:
                return version

        for path in (
            os.path.join(exe_dir, "build_info.txt") if exe_dir else "",
            resource_path("build_info.txt"),
        ):
            if not path:
                continue
            version = _read_version_from_build_info(path)
            if version:
                return version

    for path in (resource_path("VERSION.txt"),):
        version = _read_text_file(path)
        if version:
            return version

    return "unknown"


def format_version_display(version):

    raw = str(version or "").strip()

    if not raw:
        return "unknown"

    if re.match(r"^(?:v|dv)\d", raw, re.IGNORECASE):
        return raw

    return f"v{raw}"


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


def get_release_manifest():

    path = resource_path("release_manifest.json")

    if not os.path.exists(path):
        return None

    try:

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    except Exception:
        return None


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
