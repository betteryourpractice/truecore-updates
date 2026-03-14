import requests
import zipfile
import os
import io
import sys

from TrueCore.launcher.launcher_logging import log


UPDATE_URL = "https://raw.githubusercontent.com/betteryourpractice/truecore-updates/main/version.json"

ENGINE_DIR = "engine"
VERSION_FILE = "version.txt"


# -------------------------------------------------
# GET BASE DIRECTORY
# -------------------------------------------------

def get_base_dir():

    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.abspath(".")


# -------------------------------------------------
# GET LOCAL VERSION
# -------------------------------------------------

def get_local_version():

    try:

        base_dir = get_base_dir()
        version_path = os.path.join(base_dir, ENGINE_DIR, VERSION_FILE)

        if not os.path.exists(version_path):
            return None

        with open(version_path, "r") as f:
            return f.read().strip()

    except Exception as e:

        log(f"Failed reading local version: {e}")
        return None


# -------------------------------------------------
# CHECK FOR UPDATES
# -------------------------------------------------

def check_updates():

    try:

        log("Checking update server...")

        r = requests.get(UPDATE_URL, timeout=10)

        if r.status_code != 200:
            log(f"Update server returned status {r.status_code}")
            return None

        data = r.json()

        server_version = data.get("version")

        local_version = get_local_version()

        log(f"Local version: {local_version}")
        log(f"Server version: {server_version}")

        if local_version == server_version:
            log("Launcher already up to date.")
            return None

        return data

    except Exception as e:

        log(f"Update check failed: {e}")
        return None


# -------------------------------------------------
# DOWNLOAD UPDATE
# -------------------------------------------------

def download_update(download_url):

    try:

        log("Downloading update...")

        r = requests.get(download_url, timeout=30)

        if r.status_code != 200:
            log(f"Download returned status {r.status_code}")
            return None

        log("Download completed")

        return io.BytesIO(r.content)

    except Exception as e:

        log(f"Download failed: {e}")
        return None


# -------------------------------------------------
# INSTALL UPDATE
# -------------------------------------------------

def install_update(zip_data, version=None):

    try:

        log("Installing update...")

        base_dir = get_base_dir()

        engine_path = os.path.join(base_dir, ENGINE_DIR)

        os.makedirs(engine_path, exist_ok=True)

        # -------------------------------------------------
        # REMOVE OLD ENGINE INSTALL
        # -------------------------------------------------

        import shutil

        if os.path.exists(engine_path):
            try:
                shutil.rmtree(engine_path)
                log("Removed old engine install")
            except Exception as e:
                log(f"Failed removing old engine: {e}")
                
        os.makedirs(engine_path, exist_ok=True)

        # -------------------------------------------------
        # EXTRACT UPDATE
        # -------------------------------------------------

        with zipfile.ZipFile(zip_data) as z:

            z.extractall(engine_path)

        log("Engine extracted")

        # -------------------------------------------------
        # SAVE INSTALLED VERSION
        # -------------------------------------------------

        if version:

            version_file = os.path.join(engine_path, VERSION_FILE)

            try:

                with open(version_file, "w") as f:
                    f.write(version)

                log(f"Saved version file: {version}")

            except Exception as e:

                log(f"Failed writing version file: {e}")

        log("Update installed successfully")

        return True

    except Exception as e:

        log(f"Update install failed: {e}")

        return False