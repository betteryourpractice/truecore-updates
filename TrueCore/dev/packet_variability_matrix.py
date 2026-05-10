from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from TrueCoreIntel.intel_engine import process_pages


@dataclass
class VariationCase:
    case_id: str
    mode: str
    description: str
    pages: list[str]
    expected_profile: str | None = None
    expected_archetype: str | None = None
    min_invariant_coverage: float | None = None
    allowed_variability: set[str] = field(default_factory=set)
    required_documents: set[str] = field(default_factory=set)
    expected_missing_documents: set[str] = field(default_factory=set)
    notes: str = ""


STRICT_CASES: list[VariationCase] = [
    VariationCase(
        case_id="full_submission_front_stacked",
        mode="strict",
        description="Canonical full submission packet with the core stack in expected order.",
        pages=[
            "Submission Cover Sheet\nPatient Name: Jane Doe\nDOB: 01/02/1970\nAuthorization Number: VA123\nVA Facility: Test VAMC\nDocuments Included: Consult Request, SEOC, LOMN, Consent, Clinical Notes",
            "Virtual Consent Form\nPatient Name: Jane Doe\nDOB: 01/02/1970\nPatient Signature: Jane Doe\nDate: 03/01/2026",
            "Letter of Medical Necessity\nDiagnosis: lumbar radiculopathy\nReason for Request: low back pain\nSigned by: William Durrett",
            "Consultation and Treatment Request\nOrdering Provider: William Durrett\nReason for Request: low back pain\nProcedure: MRI\nDiagnosis: lumbar radiculopathy\nICD-10: M54.16, M54.50",
            "SEOC Request\nEpisode Diagnosis: lumbar radiculopathy\nClinical Objective: restore function\nContinuity of care requested",
            "Clinical Notes\nPatient Name: Jane Doe\nDOB: 01/02/1970\nProvider: William Durrett\nAssessment: lumbar radiculopathy\nICD-10: M54.16, M54.50",
        ],
        expected_profile="full_submission",
        expected_archetype="formal_full_submission",
        min_invariant_coverage=85.0,
        allowed_variability={"low", "moderate"},
        required_documents={"cover_sheet", "consent", "consult_request", "lomn", "seoc", "clinical_notes"},
    ),
    VariationCase(
        case_id="full_submission_reordered",
        mode="strict",
        description="Formal submission packet with the same content but non-canonical order.",
        pages=[
            "Clinical Notes\nPatient Name: Jane Doe\nDOB: 01/02/1970\nProvider: William Durrett\nAssessment: lumbar radiculopathy\nICD-10: M54.16, M54.50",
            "Letter of Medical Necessity\nDiagnosis: lumbar radiculopathy\nReason for Request: low back pain\nSigned by: William Durrett",
            "Virtual Consent Form\nPatient Name: Jane Doe\nDOB: 01/02/1970\nPatient Signature: Jane Doe\nDate: 03/01/2026",
            "Submission Cover Sheet\nPatient Name: Jane Doe\nDOB: 01/02/1970\nAuthorization Number: VA123\nVA Facility: Test VAMC\nDocuments Included: Consult Request, SEOC, LOMN, Consent, Clinical Notes",
            "SEOC Request\nEpisode Diagnosis: lumbar radiculopathy\nClinical Objective: restore function\nContinuity of care requested",
            "Consultation and Treatment Request\nOrdering Provider: William Durrett\nReason for Request: low back pain\nProcedure: MRI\nDiagnosis: lumbar radiculopathy\nICD-10: M54.16, M54.50",
        ],
        expected_profile="full_submission",
        expected_archetype="formal_full_submission",
        min_invariant_coverage=85.0,
        allowed_variability={"moderate", "high"},
        required_documents={"cover_sheet", "consent", "consult_request", "lomn", "seoc", "clinical_notes"},
    ),
    VariationCase(
        case_id="authorization_referral_history",
        mode="strict",
        description="Referral-backed treatment-history packet without a clean consult request.",
        pages=[
            "Approved Referral for Medical Care\nVA Form 10-7080\nPatient Name: Billy Nickoles\nDOB: 07/12/1960\nAuthorization Number: VA0053074284\nReferring Provider: Ernestine Ivy\nVA ICN: 1016439260V811008\nEvaluation for all pain treatment options in VA excluding opioid therapy",
            "Clinical Notes\nPatient Name: Billy Nickoles\nDOB: 07/12/1960\nProvider: Lana Lyle\nAssessment: low back pain\nImpression: lumbar spondylosis\nICD-10: M43.06, M54.50\n3 month follow up",
            "Procedure Note\nProvider: Douglas Tucker\nProcedure: lumbar radiofrequency ablation\nDate of Service: 03/18/2026\nDiagnosis: low back pain",
            "Procedure Note\nProvider: Douglas Tucker\nProcedure: ViaDisc L5/S1\nDate of Service: 09/17/2025\nDiagnosis: low back pain",
        ],
        expected_profile="authorization_request",
        expected_archetype="referral_backed_treatment_history",
        min_invariant_coverage=80.0,
        allowed_variability={"high"},
        required_documents={"approved_referral", "clinical_notes"},
        expected_missing_documents={"consult_request"},
    ),
    VariationCase(
        case_id="clinical_note_minimal",
        mode="strict",
        description="Single clinical-note packet with minimal paperwork but intact patient and diagnosis anchors.",
        pages=[
            "Clinical Notes\nPatient Name: Mark Rivers\nDOB: 02/14/1975\nProvider: William Durrett\nAssessment: neck pain\nICD-10: M54.2\nHistory of present illness: persistent neck pain after conservative care",
        ],
        expected_profile="clinical_minimal",
        expected_archetype="clinical_note_packet",
        min_invariant_coverage=60.0,
        allowed_variability={"low", "moderate"},
        required_documents={"clinical_notes"},
    ),
]


TRACKING_CASES: list[VariationCase] = [
    VariationCase(
        case_id="title_light_semantic_packet",
        mode="tracking",
        description="Request packet where meaning is present but explicit document titles are weak or missing.",
        pages=[
            "Patient Name: Sarah Kent\nDOB: 06/06/1972\nAuthorization Number: VA999\nVA Facility: Test VAMC\nOrdering Provider: William Durrett\nRequest for evaluation of chronic low back pain and bilateral leg pain\nICD-10: M54.16, M54.50",
            "Clinical summary\nPatient reports chronic low back pain despite PT and ibuprofen\nAssessment: lumbar radiculopathy\nSigned by William Durrett",
            "Medical necessity\nThis treatment is medically necessary because conservative care failed\nDiagnosis: lumbar radiculopathy\nRequested service: MRI lumbar spine",
        ],
        expected_profile="authorization_request",
        expected_archetype="authorization_submission_packet",
        min_invariant_coverage=75.0,
        allowed_variability={"high"},
        notes="Current engine still leans toward mixed_history_packet here; this case tracks semantic-title tolerance progress.",
    ),
    VariationCase(
        case_id="ocr_noisy_request_packet",
        mode="tracking",
        description="Authorization packet with OCR-style character substitutions in titles and field labels.",
        pages=[
            "VA F0rm 10-10172\nPatlent Name: Jacob Talbott\nD0B: 04/03/1992\nAuth0rizat1on Number: VA0051513368\nReferrlng Provlder: Amy Allen\nICN: 1041529679V678591",
            "C0nsultat1on and Treatment Request\n0rdering Provider: William Durrett\nReas0n f0r Request: low back pain\nDiagn0sis: lumbar radiculopathy\nICD-10: M54.16, M54.50",
            "ClinicaI N0tes\nPatlent Name: Jacob Talbott\nD0B: 04/03/1992\nAssessment: low back pain\nImpression: lumbar radiculopathy",
        ],
        expected_profile="authorization_request",
        expected_archetype="authorization_submission_packet",
        min_invariant_coverage=65.0,
        allowed_variability={"high"},
        notes="Tracks OCR-tolerance progress for degraded admin/request packets.",
    ),
]


def _copy_case(case: VariationCase, **updates) -> VariationCase:
    payload = {
        "case_id": case.case_id,
        "mode": case.mode,
        "description": case.description,
        "pages": list(case.pages),
        "expected_profile": case.expected_profile,
        "expected_archetype": case.expected_archetype,
        "min_invariant_coverage": case.min_invariant_coverage,
        "allowed_variability": set(case.allowed_variability),
        "required_documents": set(case.required_documents),
        "expected_missing_documents": set(case.expected_missing_documents),
        "notes": case.notes,
    }
    payload.update(updates)
    return VariationCase(**payload)


def _replace_all(text: str, replacements: dict[str, str]) -> str:
    updated = str(text)
    for source, target in replacements.items():
        updated = updated.replace(source, target)
    return updated


def transform_reverse_pages(pages: list[str]) -> list[str]:
    return list(reversed(pages))


def transform_flip_provider_name_order(pages: list[str]) -> list[str]:
    replacements = {
        "Ernestine Ivy": "Ivy Ernestine",
        "Douglas Tucker": "Tucker Douglas",
        "William Durrett": "Durrett William",
        "Lana Lyle": "Lyle Lana",
    }
    return [_replace_all(page, replacements) for page in pages]


def transform_soften_titles(pages: list[str]) -> list[str]:
    replacements = {
        "Submission Cover Sheet": "Cover Sheet",
        "Virtual Consent Form": "Telehealth Consent",
        "Letter of Medical Necessity": "Medical necessity letter",
        "Consultation and Treatment Request": "Consult for treatment",
        "SEOC Request": "Episode of care request",
        "Clinical Notes": "Progress note",
        "Approved Referral for Medical Care\nVA Form 10-7080": "Referral approval\nMedical care authorization",
    }
    return [_replace_all(page, replacements) for page in pages]


def transform_merge_adjacent_pairs(pages: list[str]) -> list[str]:
    merged = []
    index = 0
    while index < len(pages):
        left = pages[index]
        if index + 1 < len(pages):
            merged.append(f"{left}\n{pages[index + 1]}")
            index += 2
        else:
            merged.append(left)
            index += 1
    return merged


def transform_light_ocr_noise(pages: list[str]) -> list[str]:
    replacements = {
        "o": "0",
        "O": "0",
        "i": "1",
        "I": "1",
        "a": "@",
        "e": "3",
    }

    def mutate_token(token: str) -> str:
        if len(token) < 5:
            return token
        mutated = []
        substitutions = 0
        for char in token:
            if substitutions >= 2:
                mutated.append(char)
                continue
            repl = replacements.get(char)
            if repl:
                mutated.append(repl)
                substitutions += 1
            else:
                mutated.append(char)
        return "".join(mutated)

    mutated_pages = []
    for page in pages:
        tokens = str(page).split()
        mutated_pages.append(" ".join(mutate_token(token) for token in tokens))
    return mutated_pages


CASE_INDEX = {case.case_id: case for case in STRICT_CASES + TRACKING_CASES}

STRICT_PERTURBATION_CASES: list[VariationCase] = [
    _copy_case(
        CASE_INDEX["authorization_referral_history"],
        case_id="authorization_referral_history__provider_name_flip",
        description="Referral-backed treatment-history packet with provider names flipped into alternate orderings.",
        pages=transform_flip_provider_name_order(CASE_INDEX["authorization_referral_history"].pages),
        notes="This perturbation checks that role/order name variation does not collapse the packet context.",
    ),
]

TRACKING_PERTURBATION_CASES: list[VariationCase] = [
    _copy_case(
        CASE_INDEX["full_submission_front_stacked"],
        case_id="full_submission_front_stacked__merged_pairs",
        mode="tracking",
        description="Full submission packet with admin and clinical content merged across adjacent pages.",
        pages=transform_merge_adjacent_pairs(CASE_INDEX["full_submission_front_stacked"].pages),
        allowed_variability={"moderate", "high"},
        notes="Tracks whether document-family detection can survive mixed-content pages without losing packet profile fidelity.",
    ),
    _copy_case(
        CASE_INDEX["full_submission_front_stacked"],
        case_id="full_submission_front_stacked__soft_titles",
        mode="tracking",
        description="Full submission packet with softer, less canonical document titles.",
        pages=transform_soften_titles(CASE_INDEX["full_submission_front_stacked"].pages),
        allowed_variability={"moderate", "high"},
        notes="Tracks semantic title tolerance for offices that rename familiar documents.",
    ),
    _copy_case(
        CASE_INDEX["authorization_referral_history"],
        case_id="authorization_referral_history__ocr_noise",
        mode="tracking",
        description="Referral-backed treatment-history packet with light OCR-style character substitutions.",
        pages=transform_light_ocr_noise(CASE_INDEX["authorization_referral_history"].pages),
        min_invariant_coverage=70.0,
        allowed_variability={"high"},
        notes="Tracks OCR robustness when referral/admin titles degrade but the packet story is still present.",
    ),
]


def _normalize_set(values: Iterable[str] | None) -> set[str]:
    return {str(value).strip() for value in (values or []) if str(value).strip()}


def _evaluate_case(case: VariationCase) -> dict:
    packet = process_pages(case.pages, source_type="pdf")
    output = dict(getattr(packet, "output", {}) or {})
    detected_documents = _normalize_set(output.get("detected_documents", []))
    missing_documents = _normalize_set(output.get("missing_documents", []))

    observed = {
        "profile": output.get("packet_profile"),
        "archetype": output.get("packet_archetype"),
        "invariant_coverage_score": float(output.get("packet_invariant_coverage_score") or 0.0),
        "format_variability": str(output.get("packet_format_variability") or "").strip(),
        "detected_documents": sorted(detected_documents),
        "missing_documents": sorted(missing_documents),
        "score": output.get("packet_score"),
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

    if case.min_invariant_coverage is not None:
        checks.append((
            "invariant_coverage",
            observed["invariant_coverage_score"] >= float(case.min_invariant_coverage),
            f"expected >= {case.min_invariant_coverage}, observed {observed['invariant_coverage_score']}",
        ))

    if case.allowed_variability:
        checks.append((
            "format_variability",
            observed["format_variability"] in case.allowed_variability,
            f"expected one of {sorted(case.allowed_variability)}, observed {observed['format_variability']}",
        ))

    if case.required_documents:
        checks.append((
            "required_documents",
            case.required_documents.issubset(detected_documents),
            f"expected docs {sorted(case.required_documents)}, observed {sorted(detected_documents)}",
        ))

    if case.expected_missing_documents:
        checks.append((
            "missing_documents",
            case.expected_missing_documents.issubset(missing_documents),
            f"expected missing docs {sorted(case.expected_missing_documents)}, observed {sorted(missing_documents)}",
        ))

    passed = all(item[1] for item in checks) if checks else True
    return {
        "case": case,
        "observed": observed,
        "checks": checks,
        "passed": passed,
    }


def run_packet_variability_matrix(*, include_tracking: bool = True, verbose: bool = True) -> dict:
    cases = list(STRICT_CASES) + list(STRICT_PERTURBATION_CASES)
    if include_tracking:
        cases.extend(TRACKING_CASES)
        cases.extend(TRACKING_PERTURBATION_CASES)

    results = [_evaluate_case(case) for case in cases]
    strict_results = [result for result in results if result["case"].mode == "strict"]
    tracking_results = [result for result in results if result["case"].mode == "tracking"]

    strict_pass = all(result["passed"] for result in strict_results)

    if verbose:
        print("Packet Variability Matrix")
        print()
        for result in results:
            case = result["case"]
            status = "PASS" if result["passed"] else "FAIL" if case.mode == "strict" else "TRACK"
            print(f"[{status}] {case.case_id} ({case.mode})")
            print(f"  {case.description}")
            print(
                "  Observed:"
                f" profile={result['observed']['profile']},"
                f" archetype={result['observed']['archetype']},"
                f" invariants={result['observed']['invariant_coverage_score']},"
                f" variability={result['observed']['format_variability']}"
            )
            for check_name, ok, detail in result["checks"]:
                mark = "ok" if ok else "miss"
                print(f"    - {check_name}: {mark} ({detail})")
            if case.notes:
                print(f"  Notes: {case.notes}")
            print()

        strict_total = len(strict_results)
        strict_passed = sum(1 for result in strict_results if result["passed"])
        tracking_total = len(tracking_results)
        tracking_green = sum(1 for result in tracking_results if result["passed"])
        print(
            f"Strict cases: {strict_passed}/{strict_total} passed. "
            f"Tracking cases meeting target: {tracking_green}/{tracking_total}."
        )

    return {
        "strict_pass": strict_pass,
        "results": results,
        "strict_results": strict_results,
        "tracking_results": tracking_results,
    }


if __name__ == "__main__":
    summary = run_packet_variability_matrix(include_tracking=True, verbose=True)
    raise SystemExit(0 if summary["strict_pass"] else 1)
