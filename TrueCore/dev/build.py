"""
TrueCore Build System

Handles version bumping, changelog updates,
syntax validation, system validation, and
PyInstaller packaging.
"""

import os
import subprocess
import datetime
import re
import sys
import shutil
import compileall
import time

print("=====================================")
print("        TRUECORE BUILD SYSTEM")
print("=====================================\n")

# -------------------------------------------------
# RUN PRE-BUILD VALIDATION
# -------------------------------------------------

print("Running pre-build validation...\n")

result = subprocess.call(
    [sys.executable, "-m", "TrueCore.dev.validate_system"]
)

if result != 0:
    print("\nBuild aborted due to validation failures.\n")
    sys.exit(1)

print("Validation successful.\n")

# -------------------------------------------------
# PROJECT PATHS
# -------------------------------------------------

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORE_DIR = os.path.join(ROOT_DIR, "TrueCore")

VERSION_PATH = os.path.join(CORE_DIR, "VERSION.txt")
CHANGELOG_PATH = os.path.join(CORE_DIR, "CHANGELOG.txt")

ASSETS_DIR = os.path.join(CORE_DIR, "launcher","assets")
DEV_SYSTEM_DIR = os.path.join(CORE_DIR, "dev_system")
LOGS_DIR = os.path.join(CORE_DIR, "logs")

GUI_DIR = os.path.join(CORE_DIR, "ui", "pyside_gui")

ENGINE_APP = os.path.join(GUI_DIR, "pyside_app.py")
LAUNCHER_APP = os.path.join(CORE_DIR, "launcher", "launcher_app.py")

# -------------------------------------------------
# UTILITY FUNCTIONS
# -------------------------------------------------

def ensure_folder(path):
    if not os.path.exists(path):
        os.makedirs(path)


def read_version():
    if not os.path.exists(VERSION_PATH):
        print("ERROR: VERSION.txt missing.")
        sys.exit()

    with open(VERSION_PATH, "r") as f:
        return f.read().strip()


def write_version(version):
    with open(VERSION_PATH, "w") as f:
        f.write(version)


def append_changelog(version, notes):
    date = datetime.date.today()

    entry = f"""

VERSION: {version}
DATE: {date}

CHANGES

* {notes}

"""

    with open(CHANGELOG_PATH, "a", encoding="utf-8") as f:
        f.write(entry)


# -------------------------------------------------
# CLEAN BUILD FOLDERS
# -------------------------------------------------

def clean_build():

    print("\nCleaning previous builds...")

    for folder in ["build", "dist"]:
        path = os.path.join(ROOT_DIR, folder)

        if os.path.exists(path):
            shutil.rmtree(path)

    for file in os.listdir(ROOT_DIR):
        if file.endswith(".spec"):
            os.remove(os.path.join(ROOT_DIR, file))


# -------------------------------------------------
# POST BUILD CLEAN
# -------------------------------------------------

def post_build_clean():

    print("\nRunning post-build cleanup...")

    for root, dirs, files in os.walk(ROOT_DIR):

        for d in dirs:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d))

        for file in files:
            if file.endswith(".pyc"):
                try:
                    os.remove(os.path.join(root, file))
                except:
                    pass


# -------------------------------------------------
# COMPILE ENTIRE PROJECT
# -------------------------------------------------

def syntax_check():

    print("\nCompiling entire project...\n")

    success = compileall.compile_dir(CORE_DIR, quiet=1)

    if not success:
        print("ERROR: Syntax errors detected.")
        sys.exit()

    print("Project compilation successful.")


# -------------------------------------------------
# GUI STARTUP TEST
# -------------------------------------------------

def runtime_startup_test():

    print("\nRunning GUI startup test...\n")

    try:

        proc = subprocess.Popen(
            [sys.executable, "-m", "TrueCore.ui.pyside_gui.pyside_app"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(3)

        proc.terminate()

        print("GUI startup test passed.")

    except Exception as e:

        print("\nERROR: GUI failed to launch.")
        print(e)

        sys.exit()


# -------------------------------------------------
# VERSION BUMP LOGIC
# -------------------------------------------------

version = read_version()

print(f"Current Version: v{version}\n")

print("Select update type:")
print("1 - BIG update")
print("2 - SMALL fix\n")

choice = input("Choose 1 or 2: ").strip()

match = re.match(r"(\d+)(?:\.(\d+))?",version)

if not match:
    print("\nERROR: VERSION.txt format invalid.")
    sys.exit()

major = int(match.group(1))
minor = match.group(2)

if minor is None:
    minor = 0
else:
    minor = int(minor)

if choice == "1":
    # BIG update
    major += 1
    new_version = f"{major}"

else:
    # SMALL update
    minor += 1
    new_version = f"{major}.{minor}"

print(f"\nNew Version: v{new_version}")

write_version(new_version)

notes = input("\nEnter short description of changes:\n> ")

append_changelog(new_version, notes)

# -------------------------------------------------
# BUILD METADATA
# -------------------------------------------------

build_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
build_id = f"TC{new_version.replace('.', '')}-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}"

BUILD_INFO_PATH = os.path.join(CORE_DIR, "build_info.txt")

with open(BUILD_INFO_PATH, "w") as f:
    f.write(f"VERSION={new_version}\n")
    f.write(f"BUILD_ID={build_id}\n")
    f.write(f"TIMESTAMP={build_timestamp}\n")

# -------------------------------------------------
# PREPARE RUNTIME FOLDERS
# -------------------------------------------------

ensure_folder(LOGS_DIR)
ensure_folder(DEV_SYSTEM_DIR)
ensure_folder(ASSETS_DIR)

# -------------------------------------------------
# VALIDATION CHECKS
# -------------------------------------------------

syntax_check()
runtime_startup_test()

# -------------------------------------------------
# CLEAN BUILD
# -------------------------------------------------

clean_build()

# -------------------------------------------------
# BUILD ENGINE
# -------------------------------------------------

print("\nBuilding TrueCore Engine...\n")

engine_cmd = (
    f'{sys.executable} -m PyInstaller '
    f'--clean '
    f'--noconfirm '
    f'--onefile '
    f'--windowed '
    f'--name TrueCoreEngine '
    f'--add-data "{GUI_DIR};ui/pyside_gui" '
    f'--hidden-import=PySide6.QtCore '
    f'--hidden-import=PySide6.QtGui '
    f'--hidden-import=PySide6.QtWidgets '
    f'"{ENGINE_APP}"'
)

result = subprocess.call(engine_cmd, shell=True)

if result != 0:
    print("\nEngine build failed.")
    sys.exit(1)

# -------------------------------------------------
# BUILD LAUNCHER
# -------------------------------------------------

print("\nBuilding TrueCore Launcher...\n")

launcher_cmd = (
    f'{sys.executable} -m PyInstaller '
    f'--clean '
    f'--noconfirm '
    f'--onefile '
    f'--windowed '
    f'--name TrueCoreLauncher '
    f'--icon "{os.path.join(ASSETS_DIR, "truecore_icon.ico")}" '
    f'--add-data "{ASSETS_DIR};launcher/assets" '
    f'--add-data "{CORE_DIR}/launcher/assets;launcher/assets"  '
    f'"{LAUNCHER_APP}"'
)

result = subprocess.call(launcher_cmd, shell=True)

if result != 0:
    print("\nLauncher build failed.")
    sys.exit(1)

# -------------------------------------------------
# MOVE ENGINE INTO LAUNCHER DIST STRUCTURE
# -------------------------------------------------

print("\nArranging build output...\n")

engine_src = os.path.join(ROOT_DIR, "dist", "TrueCoreEngine.exe")
engine_dest_dir = os.path.join(ROOT_DIR, "dist", "dist")

os.makedirs(engine_dest_dir, exist_ok=True)

shutil.move(engine_src, os.path.join(engine_dest_dir, "TrueCoreEngine.exe"))

post_build_clean()

# -------------------------------------------------
# CREATE RELEASE ZIP (ENGINE ONLY)
# -------------------------------------------------

print("\nCreating release package...\n")

release_dir = os.path.join(ROOT_DIR, "release")
os.makedirs(release_dir, exist_ok=True)

engine_src = os.path.join(ROOT_DIR, "dist", "dist", "TrueCoreEngine.exe")

zip_path = os.path.join(release_dir, f"TrueCore_v{new_version}.zip")

import zipfile

with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.write(engine_src, "TrueCoreEngine.exe")

print("\nRelease ZIP created:")
print(zip_path)


# -------------------------------------------------
# FINAL ENGINE STARTUP VERIFICATION
# -------------------------------------------------

print("\nRunning final engine verification...\n")

try:

    proc = subprocess.Popen(
        [sys.executable, "-m", "TrueCore.ui.pyside_gui.pyside_app"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(3)

    proc.terminate()

    print("Engine startup verification passed.\n")

except Exception as e:

    print("\nERROR: Engine failed to start.")
    print(e)
    sys.exit(1)


# -------------------------------------------------
# UPDATE VERSION.JSON FOR UPDATE SERVER
# -------------------------------------------------

print("\nUpdating version.json...\n")

import json

version_json_path = os.path.join(ROOT_DIR, "version.json")

download_url = f"https://github.com/betteryourpractice/truecore-updates/releases/download/v{new_version}/TrueCore_v{new_version}.zip"

version_data = {
    "version": new_version,
    "download": download_url
}

with open(version_json_path, "w") as f:
    json.dump(version_data, f, indent=4)

print("version.json updated.")

# commit + push update server changes
subprocess.call("git add version.json", shell=True)
subprocess.call(f'git commit -m "Update version.json for v{new_version}"', shell=True)
subprocess.call("git push", shell=True)

print("version.json pushed to GitHub.\n")

# -------------------------------------------------
# BUILD COMPLETE
# -------------------------------------------------

print("\n=====================================")
print("BUILD COMPLETE")
print("=====================================\n")

print("Executables created:\n")
print("dist\\TrueCoreLauncher.exe")
print("dist\\dist\\TrueCoreEngine.exe\n")