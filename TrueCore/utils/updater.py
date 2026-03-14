"""
TrueCore Updater

Handles downloading and applying application updates
from the remote update server.
"""

import requests
import zipfile
import io
import os


UPDATE_URL = "https://yourserver.com/truecore/latest.zip"


# -------------------------------------------------
# UPDATE CHECK + INSTALL
# -------------------------------------------------

def check_for_updates():

    try:

        # Download update archive
        response = requests.get(UPDATE_URL, timeout=10)

        if response.status_code != 200:
            return False

        zip_data = zipfile.ZipFile(io.BytesIO(response.content))

        # -------------------------------------------------
        # SAFE EXTRACTION
        # -------------------------------------------------

        for member in zip_data.namelist():

            # Prevent path traversal attacks
            if ".." in member or member.startswith("/") or member.startswith("\\"):
                continue

            target_path = os.path.join(".", member)

            # Ensure directory exists
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            with zip_data.open(member) as source, open(target_path, "wb") as target:
                target.write(source.read())

        return True

    except Exception as e:

        print("Update failed:", e)

        return False