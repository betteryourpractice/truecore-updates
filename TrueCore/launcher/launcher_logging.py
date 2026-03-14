import logging
import os
import sys


# -------------------------------------------------
# DETERMINE BASE DIRECTORY
# -------------------------------------------------

if getattr(sys, "frozen", False):
    # Running as packaged EXE
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Running from source
    BASE_DIR = os.path.abspath(".")


# -------------------------------------------------
# LOG DIRECTORY
# -------------------------------------------------

LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)


# -------------------------------------------------
# LOG FILE
# -------------------------------------------------

LOG_FILE = os.path.join(LOG_DIR, "launcher.log")


# -------------------------------------------------
# LOGGING CONFIGURATION
# -------------------------------------------------

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# -------------------------------------------------
# SIMPLE LOG FUNCTION
# -------------------------------------------------

def log(msg):
    logging.info(msg)