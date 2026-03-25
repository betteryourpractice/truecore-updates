"""
TrueCore Pre-Build Validation System
Checks system integrity before building the executable.
"""

import os
import re
import subprocess
import compileall
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPO_ROOT = os.path.abspath(os.path.join(PROJECT_ROOT, ".."))
INTEL_ROOT = os.path.join(REPO_ROOT, "TrueCoreIntel")

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# -------------------------------------------------
# REQUIRED FILES
# -------------------------------------------------

REQUIRED_FILES = [
    "ui/truecore_app.py",
    "core/packet_processor.py",
    "dev/build.py",
    "VERSION.txt",
    "CHANGELOG.txt",
    "AI_CONTENT.txt",
    "AI_GUARD.txt"
]

# -------------------------------------------------
# FORBIDDEN ENTRYPOINTS
# -------------------------------------------------

FORBIDDEN_ENTRYPOINTS = [
    "launcher.py",
    "start.py",
    "app_main.py"
]

# -------------------------------------------------
# PROTECTED FUNCTIONS
# -------------------------------------------------

PROTECTED_FUNCTIONS = {
    "core/packet_processor.py": [
        "process_packet",
        "process_file",
        "process_folder"
    ],
    "extraction/parser.py": [
        "parse_document"
    ],
    "extraction/extractor.py": [
        "extract_fields"
    ],
    "detection/form_detector.py": [
        "detect_document_features"
    ],
    "validation/validator.py": [
        "validate_packet"
    ],
    "validation/suggestions.py": [
        "generate_suggestions"
    ],
    "medical/icd_lookup.py": [
        "detect_icd_codes"
    ],
    "utils/logging_system.py": [
        "log_event"
    ]
}

# -------------------------------------------------
# EXPECTED PIPELINE ORDER
# -------------------------------------------------

PIPELINE_SEQUENCE = [
    "parse_document",
    "extract_fields",
    "detect_icd_codes",
    "detect_document_features",
    "validate_packet",
    "generate_suggestions"
]


# -------------------------------------------------
# REQUIRED FILE CHECK
# -------------------------------------------------

def check_required_files():

    print("Checking required files...")

    missing = []

    for file in REQUIRED_FILES:

        path = os.path.join(PROJECT_ROOT, file)

        if not os.path.exists(path):
            missing.append(file)

    if missing:
        print("ERROR: Missing required files:")
        for m in missing:
            print(" -", m)
        return False

    return True


# -------------------------------------------------
# VERSION FORMAT CHECK
# -------------------------------------------------

def check_version_format():

    print("Checking VERSION.txt format...")

    version_path = os.path.join(PROJECT_ROOT, "VERSION.txt")

    with open(version_path, "r") as f:
        version = f.read().strip()

    if not re.match(r"^\d+(\.\d+)?$", version):
        print("ERROR: VERSION.txt format invalid:", version)
        return False

    return True


# -------------------------------------------------
# FORBIDDEN ENTRYPOINT CHECK
# -------------------------------------------------

def check_forbidden_entrypoints():

    print("Checking for unauthorized entrypoints...")

    for root, dirs, files in os.walk(PROJECT_ROOT):

        for file in files:

            if file in FORBIDDEN_ENTRYPOINTS:
                print("ERROR: Unauthorized entrypoint detected:", file)
                return False

    return True


# -------------------------------------------------
# PROTECTED FUNCTION CHECK
# -------------------------------------------------

def check_protected_functions():

    print("Checking protected functions...")

    for file_path, functions in PROTECTED_FUNCTIONS.items():

        full_path = os.path.join(PROJECT_ROOT, file_path)

        if not os.path.exists(full_path):

            print("ERROR: Protected file missing:", file_path)
            return False

        try:

            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()

        except Exception as e:

            print("ERROR reading file:", file_path)
            print(e)
            return False

        for func in functions:

            if f"def {func}" not in content:

                print(f"ERROR: Protected function missing: {func} in {file_path}")
                return False

    return True


# -------------------------------------------------
# PIPELINE ORDER CHECK
# -------------------------------------------------

def check_pipeline_order():

    print("Checking packet processing pipeline order...")

    processor_path = os.path.join(PROJECT_ROOT, "core", "packet_processor.py")

    if not os.path.exists(processor_path):

        print("ERROR: packet_processor.py missing")
        return False

    try:

        with open(processor_path, "r", encoding="utf-8") as f:
            content = f.read()

    except Exception as e:

        print("ERROR reading packet_processor.py:", e)
        return False

    last_index = -1

    for step in PIPELINE_SEQUENCE:

        index = content.find(step + "(")

        if index == -1:

            print(f"WARNING: Pipeline step not detected: {step}")
            continue

        if index < last_index:

            print(f"ERROR: Pipeline step out of order: {step}")
            return False

        last_index = index

    return True


# -------------------------------------------------
# PROJECT COMPILATION
# -------------------------------------------------

def compile_project():

    print("Compiling project...")

    success = compileall.compile_dir(PROJECT_ROOT, quiet=1)

    if success and os.path.isdir(INTEL_ROOT):
        success = compileall.compile_dir(INTEL_ROOT, quiet=1)

    if not success:
        print("ERROR: Syntax errors detected.")
        return False

    return True


# -------------------------------------------------
# INTEL IMPORT TEST
# -------------------------------------------------

def test_intel_import():

    if not os.path.isdir(INTEL_ROOT):
        return True

    print("Testing TrueCoreIntel import...")

    try:

        __import__("TrueCoreIntel.intel_engine")
        return True

    except Exception as e:

        print("ERROR: TrueCoreIntel import failed:", e)
        return False


# -------------------------------------------------
# GUI STARTUP TEST
# -------------------------------------------------

def test_gui_startup():

    print("Testing GUI startup...")

    try:

        proc = subprocess.Popen(
            [sys.executable, "-m", "TrueCore.ui.truecore_app"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(3)

        proc.terminate()

        return True

    except Exception as e:

        print("ERROR: GUI failed to launch:", e)

        return False


# -------------------------------------------------
# VALIDATION PIPELINE
# -------------------------------------------------

def run_validation():

    print("\nTrueCore System Validation\n")

    checks = [
        check_required_files,
        check_version_format,
        check_forbidden_entrypoints,
        check_protected_functions,
        check_pipeline_order,
        compile_project,
        test_intel_import,
        test_gui_startup
    ]

    for check in checks:

        if not check():
            print("\nVALIDATION FAILED\n")
            return False

    print("\nVALIDATION PASSED\n")

    return True


# -------------------------------------------------
# ENTRY POINT
# -------------------------------------------------

if __name__ == "__main__":

    success = run_validation()

    sys.exit(0 if success else 1)
