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
import tempfile
import atexit
import zipfile
from TrueCore.utils.release_signing import (
    SIGNATURE_ALGORITHM,
    ensure_signing_keypair,
    public_key_id,
    sign_manifest,
)
from TrueCore.dev.update_channel_manager import (
    build_signed_channel_manifest,
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
DIST_ROOT = os.path.join(ROOT_DIR, "dist")

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


def write_engine_version_file(engine_dir, version_label):
    version_path = os.path.join(engine_dir, "version.txt")
    with open(version_path, "w", encoding="utf-8") as handle:
        handle.write(str(version_label or "").strip())
    return version_path


def build_engine_integrity_payload(*, version_label, engine_executable_path, signing_key_id):
    return {
        "schema_version": "1.0",
        "recorded_at": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "engine_executable": os.path.basename(engine_executable_path),
        "version": str(version_label or "").strip(),
        "engine_sha256": compute_file_sha256(engine_executable_path),
        "manifest_authentication": {
            "status": "verified",
            "key_id": signing_key_id,
        },
    }


def write_engine_integrity_metadata(engine_dir, *, version_label, engine_executable_path, signing_key_id):
    metadata_path = os.path.join(engine_dir, "install_integrity.json")
    payload = build_engine_integrity_payload(
        version_label=version_label,
        engine_executable_path=engine_executable_path,
        signing_key_id=signing_key_id,
    )

    with open(metadata_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4, ensure_ascii=True, sort_keys=True)

    return metadata_path


def stage_portable_runtime(runtime_root, *, launcher_source_path, launcher_output_name, engine_source_path, version_label, signing_key_id):
    if os.path.isdir(runtime_root):
        shutil.rmtree(runtime_root)

    os.makedirs(runtime_root, exist_ok=True)
    engine_dir = os.path.join(runtime_root, "engine")
    os.makedirs(engine_dir, exist_ok=True)

    launcher_target = os.path.join(runtime_root, launcher_output_name)
    launcher_output_name_lower = str(launcher_output_name or "").strip().lower()
    if launcher_output_name_lower.endswith("_office.exe"):
        engine_output_name = "TrueCoreEngine_OFFICE.exe"
    elif launcher_output_name_lower.endswith("_dev.exe"):
        engine_output_name = "TrueCoreEngine_DEV.exe"
    else:
        engine_output_name = "TrueCoreEngine.exe"
    engine_target = os.path.join(engine_dir, engine_output_name)

    shutil.copy2(launcher_source_path, launcher_target)
    shutil.copy2(engine_source_path, engine_target)

    write_engine_version_file(engine_dir, version_label)
    write_engine_integrity_metadata(
        engine_dir,
        version_label=version_label,
        engine_executable_path=engine_target,
        signing_key_id=signing_key_id,
    )

    readme_path = os.path.join(runtime_root, "README.txt")
    with open(readme_path, "w", encoding="utf-8") as handle:
        handle.write(
            "Drag this entire folder to the desktop or another location.\n"
            "Do not mix files between OFFICE and DEVELOPMENT folders.\n"
            "Launcher must stay beside the engine folder.\n"
        )

    return {
        "launcher": launcher_target,
        "engine": engine_target,
        "version_file": os.path.join(engine_dir, "version.txt"),
        "integrity_file": os.path.join(engine_dir, "install_integrity.json"),
        "readme": readme_path,
    }


def runtime_has_payload(runtime_root):
    engine_dir = os.path.join(runtime_root, "engine")
    if not os.path.isdir(runtime_root) or not os.path.isdir(engine_dir):
        return False

    launchers = [entry for entry in os.listdir(runtime_root) if entry.lower().endswith(".exe")]
    engines = [entry for entry in os.listdir(engine_dir) if entry.lower().endswith(".exe")]
    return bool(launchers and engines)


def find_latest_suite_zip(channel_name):
    release_dir = os.path.join(ROOT_DIR, "release")
    if not os.path.isdir(release_dir):
        return None

    prefix = "dv" if channel_name == "dev" else "v"
    candidates = []
    for name in os.listdir(release_dir):
        if not (name.startswith(f"TrueCoreSuite_{prefix}") and name.endswith(".zip")):
            continue
        path = os.path.join(release_dir, name)
        candidates.append((os.path.getmtime(path), path))

    if not candidates:
        return None

    candidates.sort(reverse=True)
    return candidates[0][1]


def hydrate_runtime_from_suite_zip(runtime_root, *, suite_zip_path, launcher_output_name, signing_key_id):
    temp_dir = tempfile.mkdtemp(prefix="truecore_runtime_hydrate_", dir=ROOT_DIR)
    try:
        with zipfile.ZipFile(suite_zip_path, "r") as archive:
            archive.extract("TrueCoreLauncher.exe", temp_dir)
            archive.extract("engine/TrueCoreEngine.exe", temp_dir)
            version_label = ""
            if "engine/version.txt" in archive.namelist():
                archive.extract("engine/version.txt", temp_dir)
                version_path = os.path.join(temp_dir, "engine", "version.txt")
                with open(version_path, "r", encoding="utf-8") as handle:
                    version_label = str(handle.read() or "").strip()

        launcher_source = os.path.join(temp_dir, "TrueCoreLauncher.exe")
        engine_source = os.path.join(temp_dir, "engine", "TrueCoreEngine.exe")
        return stage_portable_runtime(
            runtime_root,
            launcher_source_path=launcher_source,
            launcher_output_name=launcher_output_name,
            engine_source_path=engine_source,
            version_label=version_label,
            signing_key_id=signing_key_id,
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def ensure_opposite_runtime_available(channel_name, *, runtime_root, launcher_output_name, signing_key_id):
    if runtime_has_payload(runtime_root):
        return None

    suite_zip_path = find_latest_suite_zip(channel_name)
    if not suite_zip_path:
        ensure_folder(runtime_root)
        return None

    return hydrate_runtime_from_suite_zip(
        runtime_root,
        suite_zip_path=suite_zip_path,
        launcher_output_name=launcher_output_name,
        signing_key_id=signing_key_id,
    )


def packaged_engine_contains_build_metadata(engine_executable_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller.utils.cliutils.archive_viewer",
            engine_executable_path,
            "-l",
        ],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        return False
    output = str(result.stdout or "")
    return "build_info.txt" in output


def verify_portable_runtime_lane(runtime_info, *, expected_role, expected_version_prefix):
    engine_path = str(dict(runtime_info or {}).get("engine") or "").strip()
    if not engine_path or not os.path.exists(engine_path):
        print(f"ERROR: portable runtime engine missing for expected {expected_role} lane.")
        sys.exit(1)

    runtime_root = os.path.dirname(os.path.dirname(engine_path))
    version_path = os.path.join(os.path.dirname(engine_path), "version.txt")
    integrity_path = os.path.join(os.path.dirname(engine_path), "install_integrity.json")

    if not os.path.exists(version_path) or not os.path.exists(integrity_path):
        print(f"ERROR: portable runtime metadata missing for {runtime_root}.")
        sys.exit(1)

    with open(version_path, "r", encoding="utf-8-sig") as handle:
        version = str(handle.read() or "").strip()

    with open(integrity_path, "r", encoding="utf-8-sig") as handle:
        integrity_payload = dict(json.load(handle) or {})

    expected_engine_name = "TrueCoreEngine_DEV.exe" if expected_role == "dev" else "TrueCoreEngine_OFFICE.exe"
    actual_engine_name = str(integrity_payload.get("engine_executable") or "").strip()
    integrity_version = str(integrity_payload.get("version") or "").strip()

    if actual_engine_name != expected_engine_name:
        print(
            f"ERROR: packaged runtime executable mismatch. Expected {expected_engine_name}, "
            f"got {actual_engine_name or 'unknown'}."
        )
        sys.exit(1)

    if expected_version_prefix and not version.lower().startswith(expected_version_prefix.lower()):
        print(
            f"ERROR: packaged runtime version mismatch. Expected prefix {expected_version_prefix}, "
            f"got {version or 'unknown'}."
        )
        sys.exit(1)

    if integrity_version != version:
        print(
            f"ERROR: runtime version metadata mismatch. version.txt={version or 'unknown'} "
            f"install_integrity.json={integrity_version or 'unknown'}."
        )
        sys.exit(1)

    if not packaged_engine_contains_build_metadata(engine_path):
        print("ERROR: packaged engine is missing embedded build metadata.")
        sys.exit(1)


def build_release_download_url(build_channel, release_tag, asset_name, *, private_dev_config=None):
    private_dev_config = dict(private_dev_config or {})
    if build_channel == "dev" and not PUBLIC_DEV_CHANNEL_ENABLED and is_private_dev_channel_enabled(private_dev_config):
        owner = str(private_dev_config.get("owner") or "").strip()
        repo = str(private_dev_config.get("repo") or "").strip()
        if owner and repo:
            return f"https://github.com/{owner}/{repo}/releases/download/{release_tag}/{asset_name}"
    return f"https://github.com/betteryourpractice/truecore-updates/releases/download/{release_tag}/{asset_name}"


def run_git_command(args, *, cwd=None):
    return subprocess.call(args, cwd=cwd or ROOT_DIR)


def has_git_changes(*, cwd=None):
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=cwd or ROOT_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    return bool((result.stdout or "").strip())


def read_git_head(*, cwd=None):
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=cwd or ROOT_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return (result.stdout or "").strip() or None


def sync_git_release_tag(version_label, *, commit_ref="HEAD", remote_name="origin", cwd=None):
    working_dir = cwd or ROOT_DIR
    tag_result = run_git_command(["git", "tag", "-f", version_label, commit_ref], cwd=working_dir)
    if tag_result != 0:
        print(f"ERROR: failed to update git tag {version_label}.")
        return False

    push_result = run_git_command(
        ["git", "push", remote_name, f"refs/tags/{version_label}", "--force"],
        cwd=working_dir,
    )
    if push_result != 0:
        print(f"ERROR: failed to push git tag {version_label}.")
        return False
    return True


def sync_private_dev_manifest_repo(version_label, *, notes, private_dev_config, manifest_source_path):
    if not is_private_dev_channel_enabled(private_dev_config):
        print("Private dev repo sync skipped: private dev channel is not enabled.")
        return True

    owner = str(private_dev_config.get("owner") or "").strip()
    repo = str(private_dev_config.get("repo") or "").strip()
    branch_name = str(private_dev_config.get("ref") or "main").strip() or "main"
    manifest_path = str(private_dev_config.get("manifest_path") or "version-dev.json").strip() or "version-dev.json"
    if not owner or not repo:
        print("ERROR: private dev repo owner/repo missing.")
        return False

    repo_url = f"https://github.com/{owner}/{repo}.git"
    clone_root = tempfile.mkdtemp(prefix="truecore_private_dev_repo_", dir=ROOT_DIR)
    clone_dir = os.path.join(clone_root, repo)
    try:
        clone_result = run_git_command(["git", "clone", repo_url, clone_dir], cwd=ROOT_DIR)
        if clone_result != 0:
            print("ERROR: failed to clone private dev repo.")
            return False

        target_manifest_path = os.path.join(clone_dir, *manifest_path.split("/"))
        os.makedirs(os.path.dirname(target_manifest_path), exist_ok=True)
        shutil.copy2(manifest_source_path, target_manifest_path)

        add_result = run_git_command(["git", "add", manifest_path], cwd=clone_dir)
        if add_result != 0:
            print("ERROR: failed to stage private dev manifest update.")
            return False

        if has_git_changes(cwd=clone_dir):
            commit_message = f"Update {os.path.basename(manifest_path)} for {version_label}"
            if str(notes or "").strip():
                commit_message += f": {str(notes).strip()[:48]}"
            commit_result = run_git_command(["git", "commit", "-m", commit_message], cwd=clone_dir)
            if commit_result != 0:
                print("ERROR: failed to commit private dev manifest update.")
                return False
        else:
            print("Private dev manifest already matches current build.")

        push_result = run_git_command(["git", "push", "origin", branch_name], cwd=clone_dir)
        if push_result != 0:
            print("ERROR: failed to push private dev branch update.")
            return False

        branch_head = read_git_head(cwd=clone_dir)
        if not branch_head:
            print("ERROR: failed to resolve private dev repo HEAD.")
            return False

        if not sync_git_release_tag(version_label, commit_ref=branch_head, remote_name="origin", cwd=clone_dir):
            return False

        print("Private dev repo manifest and tag synced successfully.")
        return True
    finally:
        shutil.rmtree(clone_root, ignore_errors=True)


def publish_release_changes(version_label, notes, *, build_channel, private_dev_config=None, dev_manifest_path=None):
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
    else:
        commit_result = run_git_command(["git", "commit", "-m", commit_message])
        if commit_result != 0:
            print("ERROR: git commit failed.")
            return False

        push_result = run_git_command(["git", "push"])
        if push_result != 0:
            print("ERROR: git push failed.")
            return False

    release_commit = read_git_head()
    if not release_commit:
        print("ERROR: failed to resolve release commit after publish.")
        return False

    if build_channel == "production":
        if not sync_git_release_tag(version_label, commit_ref=release_commit):
            return False
    elif build_channel == "dev":
        manifest_path = dev_manifest_path or VERSION_DEV_JSON_PATH
        if not sync_private_dev_manifest_repo(
            version_label,
            notes=notes,
            private_dev_config=private_dev_config,
            manifest_source_path=manifest_path,
        ):
            return False

    print("\nGit publish completed successfully.\n")
    return True


PORTABLE_VARIANT_FOLDERS = ("OFFICE", "DEVELOPMENT")


def preserve_dist_variants(active_variant=None):
    dist_dir = os.path.join(ROOT_DIR, "dist")
    preserved_root = tempfile.mkdtemp(prefix="truecore_dist_variants_", dir=ROOT_DIR)
    preserved = {}

    if not os.path.isdir(dist_dir):
        return preserved_root, preserved

    for variant_name in PORTABLE_VARIANT_FOLDERS:
        if variant_name == active_variant:
            continue
        source_dir = os.path.join(dist_dir, variant_name)
        if not os.path.isdir(source_dir):
            continue
        target_dir = os.path.join(preserved_root, variant_name)
        shutil.copytree(source_dir, target_dir)
        preserved[variant_name] = target_dir

    return preserved_root, preserved


def restore_dist_variants(preserved_root, preserved_variants):
    dist_dir = os.path.join(ROOT_DIR, "dist")
    os.makedirs(dist_dir, exist_ok=True)

    for variant_name, source_dir in dict(preserved_variants or {}).items():
        target_dir = os.path.join(dist_dir, variant_name)
        if os.path.isdir(target_dir):
            shutil.rmtree(target_dir)
        shutil.copytree(source_dir, target_dir)

    if preserved_root and os.path.isdir(preserved_root):
        shutil.rmtree(preserved_root, ignore_errors=True)


def restore_public_facing_metadata(*, version_json_path, release_dir, build_info_path, launcher_release_info_path, release_manifest_path, private_signing_key, signing_key_id):
    if not os.path.exists(version_json_path):
        return False

    with open(version_json_path, "r", encoding="utf-8") as handle:
        version_payload = dict(json.load(handle) or {})

    release_tag = str(version_payload.get("release_tag") or version_payload.get("version") or "").strip()
    if not release_tag:
        return False

    build_id = str(version_payload.get("build_id") or "").strip()
    published_at = str(version_payload.get("published_at") or "").strip()

    with open(build_info_path, "w", encoding="utf-8") as handle:
        handle.write(f"VERSION={release_tag}\n")
        handle.write(f"BUILD_ID={build_id}\n")
        handle.write(f"TIMESTAMP={published_at}\n")

    with open(launcher_release_info_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "version": release_tag,
                "build_id": build_id,
                "build_timestamp": published_at,
                "release_channel": PRODUCTION_RELEASE_CHANNEL_URL,
                "update_channel": "production",
            },
            handle,
            indent=4,
        )

    engine_zip = os.path.join(release_dir, f"TrueCore_{release_tag}.zip")
    launcher_zip = os.path.join(release_dir, f"TrueCoreLauncher_{release_tag}.zip")
    suite_zip = os.path.join(release_dir, f"TrueCoreSuite_{release_tag}.zip")
    if not all(os.path.exists(path) for path in (engine_zip, launcher_zip, suite_zip)):
        return True

    payload = {
        "version": release_tag,
        "release_tag": release_tag,
        "build_channel": "production",
        "build_id": build_id,
        "published_at": published_at,
        "download": version_payload.get("download"),
        "sha256": version_payload.get("sha256"),
        "size": version_payload.get("size"),
        "release_zip": os.path.basename(engine_zip),
        "launcher_release_zip": os.path.basename(launcher_zip),
        "launcher_release_sha256": compute_file_sha256(launcher_zip),
        "launcher_release_size": os.path.getsize(launcher_zip),
        "suite_release_zip": os.path.basename(suite_zip),
        "suite_release_sha256": compute_file_sha256(suite_zip),
        "suite_release_size": os.path.getsize(suite_zip),
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "signature_key_id": signing_key_id,
    }
    payload["signature"] = sign_manifest(payload, private_signing_key)

    with open(release_manifest_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4)

    return True


# -------------------------------------------------
# CLEAN BUILD FOLDERS
# -------------------------------------------------

def clean_build(active_variant=None):

    print("\nCleaning previous builds...")

    preserved_root, preserved_variants = preserve_dist_variants(active_variant)

    for folder in ["build", "dist"]:
        path = os.path.join(ROOT_DIR, folder)

        if os.path.exists(path):
            shutil.rmtree(path)

    for file in os.listdir(ROOT_DIR):
        if file.endswith(".spec"):
            os.remove(os.path.join(ROOT_DIR, file))

    os.makedirs(DIST_ROOT, exist_ok=True)
    restore_dist_variants(preserved_root, preserved_variants)


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

active_portable_variant = "DEVELOPMENT" if build_channel == "dev" else "OFFICE"
clean_build(active_portable_variant)

build_output_root = tempfile.mkdtemp(prefix="truecore_pyinstaller_", dir=tempfile.gettempdir())
atexit.register(lambda: shutil.rmtree(build_output_root, ignore_errors=True))
engine_dist_dir = os.path.join(build_output_root, "engine_dist")
engine_work_dir = os.path.join(build_output_root, "engine_work")
engine_spec_dir = os.path.join(build_output_root, "engine_spec")
launcher_dist_dir = os.path.join(build_output_root, "launcher_dist")
launcher_work_dir = os.path.join(build_output_root, "launcher_work")
launcher_spec_dir = os.path.join(build_output_root, "launcher_spec")

for path in (
    engine_dist_dir,
    engine_work_dir,
    engine_spec_dir,
    launcher_dist_dir,
    launcher_work_dir,
    launcher_spec_dir,
):
    os.makedirs(path, exist_ok=True)

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
    f'--distpath "{engine_dist_dir}" '
    f'--workpath "{engine_work_dir}" '
    f'--specpath "{engine_spec_dir}" '
    f'--paths "{ROOT_DIR}" '
    f'--add-data "{GUI_DIR};ui/pyside_gui" '
    f'--add-data "{BUILD_INFO_PATH};." '
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
    f'--distpath "{launcher_dist_dir}" '
    f'--workpath "{launcher_work_dir}" '
    f'--specpath "{launcher_spec_dir}" '
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

post_build_clean()

# -------------------------------------------------
# CREATE RELEASE ZIP (ENGINE ONLY)
# -------------------------------------------------

print("\nCreating release package...\n")

release_dir = os.path.join(ROOT_DIR, "release")
os.makedirs(release_dir, exist_ok=True)

engine_src = os.path.join(engine_dist_dir, "TrueCoreEngine.exe")
launcher_src = os.path.join(launcher_dist_dir, "TrueCoreLauncher.exe")

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
    z.writestr(
        "engine/install_integrity.json",
        json.dumps(
            build_engine_integrity_payload(
                version_label=release_tag,
                engine_executable_path=engine_src,
                signing_key_id=signing_key_id,
            ),
            indent=4,
            ensure_ascii=True,
            sort_keys=True,
        ),
    )

portable_office_runtime = None
portable_dev_runtime = None
preserved_opposite_runtime = None

if build_channel == "dev":
    portable_dev_runtime = stage_portable_runtime(
        os.path.join(DIST_ROOT, "DEVELOPMENT"),
        launcher_source_path=launcher_src,
        launcher_output_name="TrueCoreLauncher_DEV.exe",
        engine_source_path=engine_src,
        version_label=release_tag,
        signing_key_id=signing_key_id,
    )
    preserved_opposite_runtime = ensure_opposite_runtime_available(
        "production",
        runtime_root=os.path.join(DIST_ROOT, "OFFICE"),
        launcher_output_name="TrueCoreLauncher_OFFICE.exe",
        signing_key_id=signing_key_id,
    )
else:
    portable_office_runtime = stage_portable_runtime(
        os.path.join(DIST_ROOT, "OFFICE"),
        launcher_source_path=launcher_src,
        launcher_output_name="TrueCoreLauncher_OFFICE.exe",
        engine_source_path=engine_src,
        version_label=release_tag,
        signing_key_id=signing_key_id,
    )
    preserved_opposite_runtime = ensure_opposite_runtime_available(
        "dev",
        runtime_root=os.path.join(DIST_ROOT, "DEVELOPMENT"),
        launcher_output_name="TrueCoreLauncher_DEV.exe",
        signing_key_id=signing_key_id,
        )

if build_channel == "dev":
    verify_portable_runtime_lane(
        portable_dev_runtime,
        expected_role="dev",
        expected_version_prefix="dv",
    )
else:
    verify_portable_runtime_lane(
        portable_office_runtime,
        expected_role="office",
        expected_version_prefix="v",
    )

print("\nRelease ZIP created:")
print(zip_path)
print(launcher_zip_path)
print(suite_zip_path)
if build_channel == "dev":
    print("\nDevelopment runtime folder created:")
    print(portable_dev_runtime["launcher"])
    print(portable_dev_runtime["engine"])
    if preserved_opposite_runtime:
        print("\nOffice runtime hydrated from latest release package:")
        print(preserved_opposite_runtime["launcher"])
        print(preserved_opposite_runtime["engine"])
else:
    print("\nOffice runtime folder created:")
    print(portable_office_runtime["launcher"])
    print(portable_office_runtime["engine"])
    if preserved_opposite_runtime:
        print("\nDevelopment runtime hydrated from latest release package:")
        print(preserved_opposite_runtime["launcher"])
        print(preserved_opposite_runtime["engine"])


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
    print("version-dev.json left unchanged for this production build.")
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

if build_channel == "dev":
    restored_public_metadata = restore_public_facing_metadata(
        version_json_path=version_json_path,
        release_dir=release_dir,
        build_info_path=BUILD_INFO_PATH,
        launcher_release_info_path=LAUNCHER_RELEASE_INFO_PATH,
        release_manifest_path=RELEASE_MANIFEST_PATH,
        private_signing_key=private_signing_key,
        signing_key_id=signing_key_id,
    )
    if restored_public_metadata:
        print("Public-facing metadata restored after dev build.")

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
    git_publish_succeeded = publish_release_changes(
        release_tag,
        notes,
        build_channel=build_channel,
        private_dev_config=private_dev_config,
        dev_manifest_path=VERSION_DEV_JSON_PATH,
    )
else:
    print("\nGit publish skipped. Your build files remain local until you commit and push them.\n")

print("Manual release follow-up:")
if git_publish_succeeded:
    if build_channel == "dev" and not PUBLIC_DEV_CHANNEL_ENABLED:
        print("1. Source changes were pushed.")
        print("2. Private dev manifest repo and release tag were synced automatically.")
        print(f"3. Dev tag/release name: {release_tag}")
        print(f"4. Engine package: {zip_path}")
        print(f"5. Launcher package: {launcher_zip_path}")
        print(f"6. Full suite package: {suite_zip_path}\n")
    else:
        print("1. Source changes were pushed.")
        print("2. Public release tag was synced automatically.")
        print(f"3. Build channel: {build_channel.title()}")
        print(f"4. Tag/release name: {release_tag}")
        print(f"5. Upload engine: {zip_path}")
        print(f"6. Launcher package: {launcher_zip_path}")
        print(f"7. Full suite package: {suite_zip_path}\n")
else:
    if build_channel == "dev" and not PUBLIC_DEV_CHANNEL_ENABLED:
        print("1. Commit and push source changes when you are ready.")
        print("2. Private dev manifest repo/tag sync will happen automatically the next time you choose publish.")
        print(f"3. Local dev tag reference: {release_tag}")
        print(f"4. Engine package: {zip_path}")
        print(f"5. Launcher package: {launcher_zip_path}")
        print(f"6. Full suite package: {suite_zip_path}\n")
    else:
        print("1. Commit and push source/release metadata when you are ready.")
        print("2. Public release tag sync will happen automatically the next time you choose publish.")
        print(f"3. Create/publish GitHub release tag/release object if needed: {release_tag}")
        print(f"4. Upload engine: {zip_path}")
        print(f"5. Launcher package: {launcher_zip_path}")
        print(f"6. Full suite package: {suite_zip_path}\n")

if os.path.isdir(build_output_root):
    shutil.rmtree(build_output_root, ignore_errors=True)

# -------------------------------------------------
# BUILD COMPLETE
# -------------------------------------------------

print("\n=====================================")
print("BUILD COMPLETE")
print("=====================================\n")

if build_channel == "dev":
    print("Portable runtime created:\n")
    print("dist\\DEVELOPMENT\\TrueCoreLauncher_DEV.exe")
    print("dist\\DEVELOPMENT\\engine\\TrueCoreEngine_DEV.exe\n")
    print("dist\\OFFICE\\ (preserved if already present)\n")
else:
    print("Portable runtime created:\n")
    print("dist\\OFFICE\\TrueCoreLauncher_OFFICE.exe")
    print("dist\\OFFICE\\engine\\TrueCoreEngine_OFFICE.exe\n")
    print("dist\\DEVELOPMENT\\ (preserved if already present)\n")

print("Release packages:\n")
print(zip_path)
print(launcher_zip_path)
print(suite_zip_path)
