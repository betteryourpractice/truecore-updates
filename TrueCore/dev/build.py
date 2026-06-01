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
from TrueCore.dev.update_channel_manager import (
    build_signed_channel_manifest,
    seed_dev_manifest_from_production,
    write_manifest,
)
from TrueCore.utils.private_dev_channel import load_private_dev_channel_config, is_private_dev_channel_enabled

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
DEV_VERSION_PATH = os.path.join(CORE_DIR, "DEV_VERSION.txt")
CHANGELOG_PATH = os.path.join(CORE_DIR, "CHANGELOG.txt")

ASSETS_DIR = os.path.join(CORE_DIR, "launcher","assets")
DEV_SYSTEM_DIR = os.path.join(CORE_DIR, "dev_system")
LOGS_DIR = os.path.join(CORE_DIR, "logs")
LAUNCHER_RELEASE_INFO_PATH = os.path.join(ASSETS_DIR, "launcher_release_info.json")
PRODUCTION_RELEASE_CHANNEL_URL = "https://raw.githubusercontent.com/betteryourpractice/truecore-updates/main/version.json"
DEV_RELEASE_CHANNEL_URL = "https://raw.githubusercontent.com/betteryourpractice/truecore-updates/main/version-dev.json"
PUBLIC_DEV_CHANNEL_ENABLED = False

GUI_DIR = os.path.join(CORE_DIR, "ui", "pyside_gui")

ENGINE_APP = os.path.join(GUI_DIR, "pyside_app.py")
LAUNCHER_APP = os.path.join(CORE_DIR, "launcher", "launcher_app.py")

# -------------------------------------------------
# UTILITY FUNCTIONS
# -------------------------------------------------

def ensure_folder(path):
    if not os.path.exists(path):
        os.makedirs(path)


def normalize_numeric_version(version_text, *, default_minor=0):
    version_text = str(version_text or "").strip()
    match = re.match(r"^(\d+)(?:\.(\d+))?$", version_text)
    if not match:
        return None

    major = int(match.group(1))
    minor = int(match.group(2) or default_minor)
    return f"{major}.{minor}"


def read_version(version_path=VERSION_PATH, *, default_version=None):
    if not os.path.exists(version_path):
        if default_version is not None:
            return normalize_numeric_version(default_version)
        print(f"ERROR: {os.path.basename(version_path)} missing.")
        sys.exit()

    with open(version_path, "r") as f:
        version_text = f.read().strip()

    normalized = normalize_numeric_version(version_text)
    if normalized is None:
        print(f"ERROR: {os.path.basename(version_path)} format invalid: {version_text}")
        sys.exit()

    return normalized


def write_version(version, version_path=VERSION_PATH):
    with open(version_path, "w") as f:
        f.write(version)


def format_release_tag(build_channel, numeric_version):
    normalized = normalize_numeric_version(numeric_version)
    if normalized is None:
        print(f"ERROR: Invalid numeric version: {numeric_version}")
        sys.exit(1)
    return f"dv{normalized}" if build_channel == "dev" else f"v{normalized}"


def bump_numeric_version(current_version, is_big_update):
    normalized = normalize_numeric_version(current_version)
    if normalized is None:
        print(f"ERROR: Invalid current version: {current_version}")
        sys.exit(1)

    match = re.match(r"^(\d+)\.(\d+)$", normalized)
    major = int(match.group(1))
    minor = int(match.group(2))

    if is_big_update:
        major += 1
        minor = 0
    else:
        minor += 1

    return f"{major}.{minor}"


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


def build_release_download_url(build_channel, release_tag, asset_name, *, private_dev_config=None):
    private_dev_config = dict(private_dev_config or {})
    if build_channel == "dev" and not PUBLIC_DEV_CHANNEL_ENABLED and is_private_dev_channel_enabled(private_dev_config):
        owner = str(private_dev_config.get("owner") or "").strip()
        repo = str(private_dev_config.get("repo") or "").strip()
        if owner and repo:
            return f"https://github.com/{owner}/{repo}/releases/download/{release_tag}/{asset_name}"
    return f"https://github.com/betteryourpractice/truecore-updates/releases/download/{release_tag}/{asset_name}"


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


def publish_release_changes(version_label, notes):
    commit_message = f"Release {version_label}"
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

print("\nSelect build channel:")
print("1 - Production")
print("2 - Dev\n")

channel_choice = input("Choose 1 or 2: ").strip()
build_channel = "dev" if channel_choice == "2" else "production"
release_channel_url = DEV_RELEASE_CHANNEL_URL if build_channel == "dev" and PUBLIC_DEV_CHANNEL_ENABLED else PRODUCTION_RELEASE_CHANNEL_URL
version_track_path = DEV_VERSION_PATH if build_channel == "dev" else VERSION_PATH
default_track_version = "0.0" if build_channel == "dev" else "5.0"
current_version = read_version(version_track_path, default_version=default_track_version)
current_version_label = format_release_tag(build_channel, current_version)

print(f"Current {build_channel.title()} Version: {current_version_label}\n")

print("Select update type:")
print("1 - BIG update")
print("2 - SMALL fix\n")

choice = input("Choose 1 or 2: ").strip()
is_big_update = choice == "1"
new_version = bump_numeric_version(current_version, is_big_update)
new_version_label = format_release_tag(build_channel, new_version)

print(f"\nNew Version: {new_version_label}")
print(f"Build Channel: {build_channel.title()}")

write_version(new_version, version_track_path)

notes = input("\nEnter short description of changes:\n> ")

append_changelog(new_version_label, notes)

# -------------------------------------------------
# BUILD METADATA
# -------------------------------------------------

build_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
build_prefix = "DTC" if build_channel == "dev" else "TC"
build_id = f"{build_prefix}{new_version.replace('.', '')}-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}"

BUILD_INFO_PATH = os.path.join(CORE_DIR, "build_info.txt")
RELEASE_MANIFEST_PATH = os.path.join(CORE_DIR, "release_manifest.json")
VERSION_DEV_JSON_PATH = os.path.join(ROOT_DIR, "version-dev.json")
SIGNING_PRIVATE_KEY_PATH = os.path.join(DEV_SYSTEM_DIR, "release_signing_private.pem")
SIGNING_PUBLIC_KEY_PATH = os.path.join(ASSETS_DIR, "release_signing_public.pem")

with open(BUILD_INFO_PATH, "w") as f:
    f.write(f"VERSION={new_version_label}\n")
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
            "version": new_version_label,
            "build_id": build_id,
            "build_timestamp": build_timestamp,
            "release_channel": release_channel_url,
            "update_channel": build_channel,
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

release_tag = new_version_label
zip_path = os.path.join(release_dir, f"TrueCore_{release_tag}.zip")
launcher_zip_path = os.path.join(release_dir, f"TrueCoreLauncher_{release_tag}.zip")
suite_zip_path = os.path.join(release_dir, f"TrueCoreSuite_{release_tag}.zip")

import zipfile

with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.write(engine_src, "TrueCoreEngine.exe")

with zipfile.ZipFile(launcher_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.write(launcher_src, "TrueCoreLauncher.exe")

with zipfile.ZipFile(suite_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.write(launcher_src, "TrueCoreLauncher.exe")
    z.write(engine_src, "engine/TrueCoreEngine.exe")
    z.writestr("engine/version.txt", release_tag)

dev_launcher_alias = None
dev_engine_alias = None

if build_channel == "dev":
    dev_launcher_alias = os.path.join(ROOT_DIR, "dist", "TrueCoreLauncher_DEV.exe")
    dev_engine_alias = os.path.join(ROOT_DIR, "dist", "dist", "TrueCoreEngine_DEV.exe")
    shutil.copy2(launcher_src, dev_launcher_alias)
    shutil.copy2(engine_src, dev_engine_alias)

print("\nRelease ZIP created:")
print(zip_path)
print(launcher_zip_path)
print(suite_zip_path)
if build_channel == "dev":
    print("\nDev executable aliases created:")
    print(dev_launcher_alias)
    print(dev_engine_alias)


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
# UPDATE CHANNEL MANIFEST FOR UPDATE SERVER
# -------------------------------------------------

print("\nUpdating release manifest...\n")

version_json_path = os.path.join(ROOT_DIR, "version.json")
private_dev_config = load_private_dev_channel_config()
download_url = build_release_download_url(
    build_channel,
    release_tag,
    f"TrueCore_{release_tag}.zip",
    private_dev_config=private_dev_config,
)
release_size = os.path.getsize(zip_path)
release_sha256 = compute_file_sha256(zip_path)
launcher_release_size = os.path.getsize(launcher_zip_path)
launcher_release_sha256 = compute_file_sha256(launcher_zip_path)
suite_release_size = os.path.getsize(suite_zip_path)
suite_release_sha256 = compute_file_sha256(suite_zip_path)

version_data = {
    "version": release_tag,
    "channel": build_channel,
    "release_tag": release_tag,
    "download": download_url,
    "sha256": release_sha256,
    "size": release_size,
    "build_id": build_id,
    "published_at": build_timestamp,
    "signature_algorithm": SIGNATURE_ALGORITHM,
    "signature_key_id": signing_key_id,
}
target_manifest_path = version_json_path if build_channel == "production" else VERSION_DEV_JSON_PATH

if build_channel == "production":
    version_data["signature"] = sign_manifest(version_data, private_signing_key)

    with open(version_json_path, "w") as f:
        json.dump(version_data, f, indent=4)

    if not PUBLIC_DEV_CHANNEL_ENABLED:
        seed_dev_manifest_from_production(output_manifest_path=VERSION_DEV_JSON_PATH)
        print("version-dev.json mirrored to the current production release.")
    elif not os.path.exists(VERSION_DEV_JSON_PATH):
        seed_dev_manifest_from_production(output_manifest_path=VERSION_DEV_JSON_PATH)
        print("version-dev.json bootstrapped from production.")
else:
    dev_version_data = build_signed_channel_manifest(version_data, channel="dev")
    write_manifest(VERSION_DEV_JSON_PATH, dev_version_data)
    if PUBLIC_DEV_CHANNEL_ENABLED:
        print("version-dev.json updated for the public dev channel.")
    else:
        if is_private_dev_channel_enabled(private_dev_config):
            print("version-dev.json updated for the private dev channel.")
        else:
            print("version-dev.json updated for local dev tracking.")
    if not os.path.exists(version_json_path):
        production_fallback = dict(version_data)
        production_fallback["version"] = format_release_tag("production", new_version)
        production_fallback["channel"] = "production"
        production_fallback["release_tag"] = format_release_tag("production", new_version)
        production_fallback["signature"] = sign_manifest(production_fallback, private_signing_key)
        with open(version_json_path, "w") as f:
            json.dump(production_fallback, f, indent=4)
        print("version.json bootstrapped from the dev build context.")

release_manifest = {
    "version": release_tag,
    "release_tag": release_tag,
    "build_channel": build_channel,
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

if target_manifest_path:
    print(f"{os.path.basename(target_manifest_path)} updated.")
else:
    print("Public update manifests unchanged for this local-only dev build.")
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
    git_publish_succeeded = publish_release_changes(release_tag, notes)
else:
    print("\nGit publish skipped. Your build files remain local until you commit and push them.\n")

print("Manual release follow-up:")
if git_publish_succeeded:
    if build_channel == "dev" and not PUBLIC_DEV_CHANNEL_ENABLED:
        print("1. Local-only dev build complete.")
        print("2. Source changes were pushed, but no public dev update channel was touched.")
        print(f"3. Local dev tag reference: {release_tag}")
        print(f"4. Engine package: {zip_path}")
        print(f"5. Launcher package: {launcher_zip_path}")
        print(f"6. Full suite package: {suite_zip_path}\n")
    else:
        print("1. Create/publish the GitHub release tag when ready.")
        print(f"2. Build channel: {build_channel.title()}")
        print(f"3. Tag/release name: {release_tag}")
        print(f"4. Upload engine: {zip_path}")
        print(f"5. Launcher package: {launcher_zip_path}")
        print(f"6. Full suite package: {suite_zip_path}\n")
else:
    if build_channel == "dev" and not PUBLIC_DEV_CHANNEL_ENABLED:
        print("1. Commit and push source changes when you are ready.")
        print("2. This dev build is local-only. No public dev release step is required.")
        print(f"3. Local dev tag reference: {release_tag}")
        print(f"4. Engine package: {zip_path}")
        print(f"5. Launcher package: {launcher_zip_path}")
        print(f"6. Full suite package: {suite_zip_path}\n")
    else:
        print("1. Commit and push source/release metadata when you are ready.")
        print(f"2. Create/publish GitHub release tag: {release_tag}")
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
if build_channel == "dev":
    print("dist\\TrueCoreLauncher_DEV.exe")
    print("dist\\dist\\TrueCoreEngine_DEV.exe\n")
