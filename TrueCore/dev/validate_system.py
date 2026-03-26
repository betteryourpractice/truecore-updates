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
import tempfile

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
# INTEL CAPABILITY SMOKE TEST
# -------------------------------------------------

def test_intel_capabilities():

    if not os.path.isdir(INTEL_ROOT):
        return True

    print("Testing TrueCoreIntel capabilities...")

    try:

        from TrueCoreIntel.intel_engine import process_pages

        pages = [
            "VA Form 10-10172\nPatient Name: Jacob Talbott\nDOB: 04/03/1992\nAuthorization Number: VA0051513368\nReferring Provider: Amy Allen\nICN: 1041529679V678591\nDate of Service: 01/01/2025 to 03/19/2026",
            "Consultation and Treatment Request\nOrdering Provider: William Durrett\nReason for Request: low back pain, bilateral hip pain\nProcedure: MRI\nDiagnosis: lumbar radiculopathy\nICD-10: M54.16, M54.50",
            "Letter of Medical Necessity\nDiagnosis: lumbar radiculopathy\nReason for Request: low back pain\nPatient failed physical therapy and ibuprofen.\nSignature Date: 03/12/2026\nSigned by: William Durrett",
            "Clinical Notes\nHistory of Present Illness\nPatient Name: Jacob Talbott\nDOB: 04/03/1992\nProvider: William Durrett\nAssessment: low back pain\nImpression: lumbar radiculopathy\nPatient reports pain, numbness, and tingling.\nSigned by: William Durrett",
        ]

        packet = process_pages(pages, source_type="pdf")
        output = dict(getattr(packet, "output", {}) or {})

        required_payloads = [
            "evidence_intelligence_1",
            "clinical_intelligence_1",
            "denial_intelligence_1",
            "human_in_the_loop_intelligence_1",
            "orchestration_intelligence_1",
            "architecture_intelligence_1",
            "recovery_intelligence_1",
            "validation_intelligence_2",
            "document_intelligence_2",
            "policy_intelligence_2",
            "deployment_intelligence_1",
        ]

        missing = [
            key
            for key in required_payloads
            if not output.get(key)
        ]

        if missing:
            print("ERROR: TrueCoreIntel capability payloads missing:", ", ".join(missing))
            return False

        if not packet.links.get("pipeline_stage_trace"):
            print("ERROR: Pipeline stage trace missing from Intel output.")
            return False

        return True

    except Exception as e:

        print("ERROR: TrueCoreIntel capability smoke test failed:", e)
        return False


# -------------------------------------------------
# INTEL SCAN BENCHMARK
# -------------------------------------------------

def test_intel_scan_benchmark():

    if not os.path.isdir(INTEL_ROOT):
        return True

    print("Testing TrueCoreIntel scan benchmark...")

    try:

        from TrueCoreIntel.benchmarks.scan_benchmark import run_scan_benchmark

        benchmark = run_scan_benchmark()

        if not benchmark.get("pass"):
            print("ERROR: Scan benchmark failed:", benchmark)
            return False

        aggregate = benchmark.get("aggregate_score", 0.0)
        if aggregate < 0.68:
            print("ERROR: Scan benchmark score below threshold:", aggregate)
            return False

        return True

    except Exception as e:

        print("ERROR: TrueCoreIntel scan benchmark failed:", e)
        return False


# -------------------------------------------------
# HOST INTELLIGENCE SMOKE TEST
# -------------------------------------------------

def test_host_intelligence():

    print("Testing host intelligence wiring...")

    try:

        from TrueCore.core.packet_processor import process_packet

        sample_text = "\n".join([
            "Clinical Notes",
            "Patient Name: Jacob Talbott",
            "DOB: 04/03/1992",
            "Authorization Number: VA0051513368",
            "Ordering Provider: William Durrett",
            "Referring Provider: Amy Allen",
            "Diagnosis: low back pain",
            "Reason for Request: MRI lumbar spine",
            "ICD-10: M54.16, M54.50",
            "Signed by: William Durrett",
        ])

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
            handle.write(sample_text)
            temp_path = handle.name

        try:
            result = process_packet(temp_path)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        intel = dict(result.get("intel", {}) or {})

        if not intel.get("memory_intelligence"):
            print("ERROR: memory_intelligence missing from host result.")
            return False

        if not intel.get("triage_intelligence"):
            print("ERROR: triage_intelligence missing from host result.")
            return False

        if not intel.get("operator_intelligence"):
            print("ERROR: operator_intelligence missing from host result.")
            return False

        if not intel.get("learning_intelligence"):
            print("ERROR: learning_intelligence missing from host result.")
            return False

        if not intel.get("insight_intelligence"):
            print("ERROR: insight_intelligence missing from host result.")
            return False

        if not intel.get("benchmark_intelligence"):
            print("ERROR: benchmark_intelligence missing from host result.")
            return False

        if not intel.get("host_display"):
            print("ERROR: host_display missing from host result.")
            return False

        return True

    except Exception as e:

        print("ERROR: Host intelligence smoke test failed:", e)
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
        test_intel_capabilities,
        test_intel_scan_benchmark,
        test_host_intelligence,
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
