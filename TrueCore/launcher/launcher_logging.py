import logging
import os
from TrueCore.utils.runtime_info import runtime_dir_path, runtime_data_path


# -------------------------------------------------
# LOG DIRECTORY
# -------------------------------------------------

LOG_DIR = runtime_dir_path("logs")


# -------------------------------------------------
# LOG FILE
# -------------------------------------------------

LOG_FILE = runtime_data_path("logs", "launcher.log", ensure_parent=True)


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
