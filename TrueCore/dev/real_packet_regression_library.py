from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from TrueCore.core.packet_processor import process_packet
from TrueCore.utils.runtime_info import runtime_data_path


CUSTOM_CASES_PATH = runtime_data_path("dev_system", "real_packet_regressions.json")


@dataclass
class RealPacketCase:
    case_id: str
    mode: str
    description: str
    file_path: str
    expected_profile: str | None = None
    expected_archetype: str | None = None
    min_score: float | None = None
    max_score: float | None = None
    required_forms: set[str] = field(default_factory=set)
    required_issue_fragments: set[str] = field(default_factory=set)
    required_missing_fragments: set[str] = field(default_factory=set)
    expected_fields: dict[str, str] = field(default_factory=dict)
    contains_fields: dict[str, str] = field(default_factory=dict)
    notes: str = ""


def _desktop_root():
    one_drive_desktop = os.path.join(os.path.expanduser("~"), "OneDrive", "Desktop")
    if os.path.isdir(one_drive_desktop):
        return one_drive_desktop
    return os.path.join(os.path.expanduser("~"), "Desktop")


def _normalize_set(values):
    return {str(value).strip() for value in (values or []) if str(value).strip()}


def _default_cases() -> list[RealPacketCase]:
    desktop = _desktop_root()
    return [
        RealPacketCase(
            case_id="nickoles_real_packet",
            mode="strict",
            description="Real-world referral-backed treatment-history packet used to guard against provider/auth/referral regressions.",
            file_path=os.path.join(desktop, "Nickoles_B.pdf"),
            expected_profile="Authorization Request",
            expected_archetype="Referral-Backed Treatment History",
            min_score=60.0,
            max_score=75.0,
            required_forms={"VA Form 10-7080", "Clinical Notes"},
            required_issue_fragments={"Missing Consultation & Treatment Request"},
            required_missing_fragments={"Missing required document: Consultation & Treatment Request"},
            expected_fields={
                "patient_name": "Nickoles, Billy",
                "authorization_number": "VA0053074284",
                "va_icn": "1016439260V811008",
                "diagnosis": "low back pain",
            },
            contains_fields={
                "reason_for_request": "pain treatment options",
                "treating_provider": "Douglas Tucker",
                "clinic_name": "OCH Center",
            },
            notes="This case protects the Nickoles normalization fixes and treatment-history packet reasoning.",
        ),
        RealPacketCase(
            case_id="doe_sample_patient_packet",
            mode="tracking",
            description="Sample full-submission packet from the launcher docs kit, used to track semantic full-stack packet behavior.",
            file_path=os.path.join(
                desktop,
                "TrueDisc_VA_Complete_Submission_Program_v1.0",
                "04_Sample_Completed_Packet",
                "TrueDisc_Doe_J_Sample_Completed_Patient_Packet.pdf",
            ),
            expected_profile="Full Submission",
            expected_archetype="Formal Full Submission",
            min_score=50.0,
            max_score=75.0,
            required_forms={
                "Submission Cover Sheet",
                "Consultation & Treatment Request",
                "SEOC",
                "Letter of Medical Necessity",
                "Virtual Consent Form",
                "Clinical Notes",
            },
            required_issue_fragments={"Missing authorization number", "Missing VA Form 10-10172"},
            expected_fields={
                "patient_name": "John Daniel Doe",
            },
            contains_fields={
                "reason_for_request": "chronic lumbar spine pain",
                "diagnosis": "intervertebral disc degeneration",
            },
            notes="This case tracks semantic full-submission reading without forcing exact issue counts while the sample packet still carries training scaffolding.",
        ),
    ]


def _load_custom_cases():
    if not os.path.exists(CUSTOM_CASES_PATH):
        return []

    try:
        with open(CUSTOM_CASES_PATH, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return []

    custom_cases = []
    for item in list(payload or []):
        try:
            custom_cases.append(
                RealPacketCase(
                    case_id=str(item.get("case_id") or "").strip(),
                    mode=str(item.get("mode") or "tracking").strip().lower() or "tracking",
                    description=str(item.get("description") or "").strip(),
                    file_path=str(item.get("file_path") or "").strip(),
                    expected_profile=item.get("expected_profile"),
                    expected_archetype=item.get("expected_archetype"),
                    min_score=item.get("min_score"),
                    max_score=item.get("max_score"),
                    required_forms=_normalize_set(item.get("required_forms")),
                    required_issue_fragments=_normalize_set(item.get("required_issue_fragments")),
                    required_missing_fragments=_normalize_set(item.get("required_missing_fragments")),
                    expected_fields=dict(item.get("expected_fields") or {}),
                    contains_fields=dict(item.get("contains_fields") or {}),
                    notes=str(item.get("notes") or "").strip(),
                )
            )
        except Exception:
            continue
    return [case for case in custom_cases if case.case_id and case.file_path]


def load_real_packet_cases():
    return _default_cases() + _load_custom_cases()


def _contains_fragment(items, fragment):
    fragment = str(fragment or "").strip().lower()
    if not fragment:
        return True
    return any(fragment in str(item or "").lower() for item in list(items or []))


def _evaluate_case(case: RealPacketCase) -> dict:
    if not os.path.exists(case.file_path):
        return {
            "case": case,
            "available": False,
            "passed": case.mode != "strict",
            "checks": [],
            "observed": {},
            "reason": "file_missing",
        }

    result = dict(process_packet(case.file_path) or {})
    fields = dict(result.get("fields", {}) or {})
    intel = dict(result.get("intel", {}) or {})
    display = dict(intel.get("display", {}) or {})
    issues = list(result.get("issues", []) or [])
    missing_items = list(display.get("missing_items", []) or [])
    forms = _normalize_set(result.get("forms", []))

    observed = {
        "score": float(result.get("score") or 0.0),
        "forms": sorted(forms),
        "issues": issues,
        "missing_items": missing_items,
        "patient_name": fields.get("patient_name"),
        "authorization_number": fields.get("authorization_number"),
        "va_icn": fields.get("va_icn"),
        "diagnosis": fields.get("diagnosis"),
        "reason_for_request": fields.get("reason_for_request"),
        "profile": display.get("packet_profile"),
        "archetype": display.get("packet_archetype"),
    }

    checks = []

    if case.expected_profile:
        checks.append((
            "profile",
            observed["profile"] == case.expected_profile,
            f"expected {case.expected_profile}, observed {observed['profile']}",
        ))

    if case.expected_archetype:
        checks.append((
            "archetype",
            observed["archetype"] == case.expected_archetype,
            f"expected {case.expected_archetype}, observed {observed['archetype']}",
        ))

    if case.min_score is not None:
        checks.append((
            "min_score",
            observed["score"] >= float(case.min_score),
            f"expected >= {case.min_score}, observed {observed['score']}",
        ))

    if case.max_score is not None:
        checks.append((
            "max_score",
            observed["score"] <= float(case.max_score),
            f"expected <= {case.max_score}, observed {observed['score']}",
        ))

    if case.required_forms:
        checks.append((
            "required_forms",
            case.required_forms.issubset(forms),
            f"expected forms {sorted(case.required_forms)}, observed {sorted(forms)}",
        ))

    for field_name, expected_value in dict(case.expected_fields or {}).items():
        checks.append((
            f"field:{field_name}",
            str(fields.get(field_name) or "").strip() == str(expected_value).strip(),
            f"expected {expected_value}, observed {fields.get(field_name)}",
        ))

    for field_name, fragment in dict(case.contains_fields or {}).items():
        checks.append((
            f"contains:{field_name}",
            str(fragment).strip().lower() in str(fields.get(field_name) or "").lower(),
            f"expected fragment {fragment}, observed {fields.get(field_name)}",
        ))

    for fragment in sorted(case.required_issue_fragments):
        checks.append((
            f"issue:{fragment}",
            _contains_fragment(issues, fragment),
            f"expected issue containing {fragment}",
        ))

    for fragment in sorted(case.required_missing_fragments):
        checks.append((
            f"missing:{fragment}",
            _contains_fragment(missing_items, fragment),
            f"expected missing-item containing {fragment}",
        ))

    return {
        "case": case,
        "available": True,
        "passed": all(item[1] for item in checks),
        "checks": checks,
        "observed": observed,
        "reason": None,
    }


def run_real_packet_regression_library(*, verbose=True):
    cases = load_real_packet_cases()
    results = [_evaluate_case(case) for case in cases]
    strict_results = [result for result in results if result["case"].mode == "strict"]
    tracking_results = [result for result in results if result["case"].mode == "tracking"]
    available_results = [result for result in results if result.get("available")]
    skipped_results = [result for result in results if not result.get("available")]

    strict_available = [result for result in strict_results if result.get("available")]
    strict_pass = all(result.get("passed") for result in strict_available) if strict_available else True

    if verbose:
        print("Real Packet Regression Library")
        print()
        for result in results:
            case = result["case"]
            if not result.get("available"):
                print(f"[SKIP] {case.case_id} ({case.mode})")
                print(f"  {case.description}")
                print(f"  File missing: {case.file_path}")
                print()
                continue

            status = "PASS" if result.get("passed") else "FAIL" if case.mode == "strict" else "TRACK"
            print(f"[{status}] {case.case_id} ({case.mode})")
            print(f"  {case.description}")
            print(
                "  Observed:"
                f" score={result['observed'].get('score')},"
                f" profile={result['observed'].get('profile')},"
                f" archetype={result['observed'].get('archetype')}"
            )
            for check_name, ok, detail in result.get("checks", []):
                mark = "ok" if ok else "miss"
                print(f"    - {check_name}: {mark} ({detail})")
            if case.notes:
                print(f"  Notes: {case.notes}")
            print()

        print(
            f"Available cases: {len(available_results)} | Skipped: {len(skipped_results)} | "
            f"Strict available passed: {sum(1 for item in strict_available if item.get('passed'))}/{len(strict_available)}"
        )

    return {
        "strict_pass": strict_pass,
        "results": results,
        "strict_results": strict_results,
        "tracking_results": tracking_results,
        "available_results": available_results,
        "skipped_results": skipped_results,
    }


if __name__ == "__main__":
    summary = run_real_packet_regression_library(verbose=True)
    raise SystemExit(0 if summary.get("strict_pass") else 1)
