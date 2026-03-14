import os
import re
from datetime import datetime
from TrueCore.utils.runtime_info import resource_path


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FOLDER = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_FOLDER, "activity.log")


def ensure_log_folder():

    if not os.path.exists(LOG_FOLDER):
        os.makedirs(LOG_FOLDER)


# -------------------------------------------------
# PHI MASKING
# -------------------------------------------------

def mask_phi(text):

    if not text:
        return text

    # Mask SSN patterns
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "***-**-****", text)

    # Mask DOB patterns
    text = re.sub(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", "[DOB_REDACTED]", text)

    # Mask authorization numbers (keep last 2 characters)
    text = re.sub(r"(auth[:\s]*[A-Za-z0-9\-]+)", lambda m: m.group(0)[:-2] + "**", text, flags=re.IGNORECASE)

    # Convert full names to initials (John Smith -> JS)
    def initials(match):
        first = match.group(1)[0]
        last = match.group(2)[0]
        return f"{first}{last}"

    text = re.sub(r"\b([A-Z][a-z]+)\s([A-Z][a-z]+)\b", initials, text)

    return text


def log_event(action, details=""):

    ensure_log_folder()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Apply PHI masking
    details = mask_phi(details)

    entry = f"{timestamp} | ACTION: {action} | DETAILS: {details}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)