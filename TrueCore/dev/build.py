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
import hashlib
import json
from TrueCore.utils.release_signing import (
    SIGNATURE_ALGORITHM,
    ensure_signing_keypair,
    public_key_id,
    sign_manifest,
)

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
INTEL_DIR = os.path.join(ROOT_DIR, "TrueCoreIntel")

VERSION_PATH = os.path.join(CORE_DIR, "VERSION.txt")
CHANGELOG_PATH = os.path.join(CORE_DIR, "CHANGELOG.txt")

ASSETS_DIR = os.path.join(CORE_DIR, "launcher","assets")
DEV_SYSTEM_DIR = os.path.join(CORE_DIR, "dev_system")
LOGS_DIR = os.path.join(CORE_DIR, "logs")
LAUNCHER_RELEASE_INFO_PATH = os.path.join(ASSETS_DIR, "launcher_release_info.json")

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


def compute_file_sha256(path):

    digest = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def run_git_command(args):
    return subprocess.call(args, cwd=ROOT_DIR)


def has_git_changes():
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    return bool((result.stdout or "").strip())


def publish_release_changes(version, notes):
    commit_message = f"Release v{version}"
    cleaned_notes = str(notes or "").strip()
    if cleaned_notes:
        commit_message += f": {cleaned_notes[:72]}"

    print("\nPreparing Git publish...\n")

    add_result = run_git_command(["git", "add", "-A"])
    if add_result != 0:
        print("ERROR: git add failed.")
        return False

    if not has_git_changes():
        print("No git changes detected after build. Nothing to commit.\n")
        return True

    commit_result = run_git_command(["git", "commit", "-m", commit_message])
    if commit_result != 0:
        print("ERROR: git commit failed.")
        return False

    push_result = run_git_command(["git", "push"])
    if push_result != 0:
        print("ERROR: git push failed.")
        return False

    print("\nGit publish completed successfully.\n")
    return True


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

    build_dir = os.path.join(ROOT_DIR, "build")
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)

    for spec_name in ("TrueCoreEngine.spec", "TrueCoreLauncher.spec"):
        spec_path = os.path.join(ROOT_DIR, spec_name)
        if os.path.exists(spec_path):
            os.remove(spec_path)

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

    if success and os.path.isdir(INTEL_DIR):
        success = compileall.compile_dir(INTEL_DIR, quiet=1)

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
    new_version = f"{major}.0"

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
RELEASE_MANIFEST_PATH = os.path.join(CORE_DIR, "release_manifest.json")
SIGNING_PRIVATE_KEY_PATH = os.path.join(DEV_SYSTEM_DIR, "release_signing_private.pem")
SIGNING_PUBLIC_KEY_PATH = os.path.join(ASSETS_DIR, "release_signing_public.pem")

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

with open(LAUNCHER_RELEASE_INFO_PATH, "w", encoding="utf-8") as f:
    json.dump(
        {
            "version": new_version,
            "build_id": build_id,
            "build_timestamp": build_timestamp,
            "release_channel": "https://raw.githubusercontent.com/betteryourpractice/truecore-updates/main/version.json",
        },
        f,
        indent=4,
    )

private_signing_key, public_signing_key, generated_signing_keys = ensure_signing_keypair(
    SIGNING_PRIVATE_KEY_PATH,
    SIGNING_PUBLIC_KEY_PATH,
)
signing_key_id = public_key_id(public_signing_key)

if generated_signing_keys:
    print("\nRelease signing keypair generated.")
    print(f"Private key (keep local): {SIGNING_PRIVATE_KEY_PATH}")
    print(f"Public key (bundled with launcher): {SIGNING_PUBLIC_KEY_PATH}\n")

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

ENGINE_EXCLUDES = [
    "paddleocr",
    "paddle",
    "baidubce",
    "modelscope",
]

engine_exclude_args = " ".join(
    f"--exclude-module={module_name}"
    for module_name in ENGINE_EXCLUDES
)

engine_cmd = (
    f'{sys.executable} -m PyInstaller '
    f'--clean '
    f'--noconfirm '
    f'--onefile '
    f'--windowed '
    f'--name TrueCoreEngine '
    f'--paths "{ROOT_DIR}" '
    f'--add-data "{GUI_DIR};ui/pyside_gui" '
    f'--hidden-import=PySide6.QtCore '
    f'--hidden-import=PySide6.QtGui '
    f'--hidden-import=PySide6.QtWidgets '
    f'{engine_exclude_args} '
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
    f'--paths "{ROOT_DIR}" '
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
launcher_src = os.path.join(ROOT_DIR, "dist", "TrueCoreLauncher.exe")

zip_path = os.path.join(release_dir, f"TrueCore_v{new_version}.zip")
launcher_zip_path = os.path.join(release_dir, f"TrueCoreLauncher_v{new_version}.zip")
suite_zip_path = os.path.join(release_dir, f"TrueCoreSuite_v{new_version}.zip")

import zipfile

with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.write(engine_src, "TrueCoreEngine.exe")

with zipfile.ZipFile(launcher_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.write(launcher_src, "TrueCoreLauncher.exe")

with zipfile.ZipFile(suite_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.write(launcher_src, "TrueCoreLauncher.exe")
    z.write(engine_src, "TrueCoreEngine.exe")

print("\nRelease ZIP created:")
print(zip_path)
print(launcher_zip_path)
print(suite_zip_path)


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

version_json_path = os.path.join(ROOT_DIR, "version.json")

download_url = f"https://github.com/betteryourpractice/truecore-updates/releases/download/v{new_version}/TrueCore_v{new_version}.zip"
release_size = os.path.getsize(zip_path)
release_sha256 = compute_file_sha256(zip_path)
launcher_release_size = os.path.getsize(launcher_zip_path)
launcher_release_sha256 = compute_file_sha256(launcher_zip_path)
suite_release_size = os.path.getsize(suite_zip_path)
suite_release_sha256 = compute_file_sha256(suite_zip_path)

version_data = {
    "version": new_version,
    "download": download_url,
    "sha256": release_sha256,
    "size": release_size,
    "build_id": build_id,
    "published_at": build_timestamp,
    "signature_algorithm": SIGNATURE_ALGORITHM,
    "signature_key_id": signing_key_id,
}
version_data["signature"] = sign_manifest(version_data, private_signing_key)

with open(version_json_path, "w") as f:
    json.dump(version_data, f, indent=4)

release_manifest = {
    "version": new_version,
    "build_id": build_id,
    "published_at": build_timestamp,
    "download": download_url,
    "sha256": release_sha256,
    "size": release_size,
    "release_zip": os.path.basename(zip_path),
    "launcher_release_zip": os.path.basename(launcher_zip_path),
    "launcher_release_sha256": launcher_release_sha256,
    "launcher_release_size": launcher_release_size,
    "suite_release_zip": os.path.basename(suite_zip_path),
    "suite_release_sha256": suite_release_sha256,
    "suite_release_size": suite_release_size,
    "signature_algorithm": SIGNATURE_ALGORITHM,
    "signature_key_id": signing_key_id,
}
release_manifest["signature"] = sign_manifest(release_manifest, private_signing_key)

with open(RELEASE_MANIFEST_PATH, "w", encoding="utf-8") as f:
    json.dump(release_manifest, f, indent=4)

print("version.json updated.")
print("release_manifest.json updated.")
print(f"SHA256: {release_sha256}")
print(f"Size: {release_size} bytes")
print(f"Launcher SHA256: {launcher_release_sha256}")
print(f"Launcher Size: {launcher_release_size} bytes")
print(f"Suite SHA256: {suite_release_sha256}")
print(f"Suite Size: {suite_release_size} bytes")

publish_choice = input(
    "\nCommit and push the current release changes to GitHub now? (y/N): "
).strip().lower()

git_publish_succeeded = False

if publish_choice in {"y", "yes"}:
    git_publish_succeeded = publish_release_changes(new_version, notes)
else:
    print("\nGit publish skipped. Your build files remain local until you commit and push them.\n")

print("Manual release follow-up:")
if git_publish_succeeded:
    print("1. Create/publish the GitHub release tag when ready.")
    print(f"2. Tag/release name: v{new_version}")
    print(f"3. Upload engine: {zip_path}")
    print(f"4. Launcher package: {launcher_zip_path}")
    print(f"5. Full suite package: {suite_zip_path}\n")
else:
    print("1. Commit and push source/release metadata when you are ready.")
    print(f"2. Create/publish GitHub release tag: v{new_version}")
    print(f"3. Upload engine: {zip_path}")
    print(f"4. Launcher package: {launcher_zip_path}")
    print(f"5. Full suite package: {suite_zip_path}\n")

# -------------------------------------------------
# BUILD COMPLETE
# -------------------------------------------------

print("\n=====================================")
print("BUILD COMPLETE")
print("=====================================\n")

print("Executables created:\n")
print("dist\\TrueCoreLauncher.exe")
print("dist\\dist\\TrueCoreEngine.exe\n")
