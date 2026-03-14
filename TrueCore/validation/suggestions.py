"""
TrueCore Suggestion Engine

Generates remediation suggestions for packet issues
detected during validation.
"""


def generate_suggestions(issues, fields, detected_forms, text=None):

    suggestions = []

    patient_name = fields.get("patient_name")
    dob = fields.get("dob")
    authorization = fields.get("authorization_number")
    icd_codes = fields.get("icd_codes")

    # -----------------------------
    # FIELD REPAIRS
    # -----------------------------

    if "Missing patient name" in issues:
        suggestions.append("Add patient name to packet")

    if "Missing patient DOB" in issues:
        suggestions.append("Add patient date of birth")

    if "Missing authorization number" in issues:
        suggestions.append("Add VA authorization number")

    if "Missing ordering doctor" in issues:
        suggestions.append("Add ordering provider")

    if "Missing referring doctor" in issues:
        suggestions.append("Add referring provider")

    if "Missing ICD codes" in issues:
        suggestions.append("Add diagnosis ICD codes")

    # -----------------------------
    # FORM REPAIRS
    # -----------------------------

    if "Missing Virtual Consent Form" in issues:
        suggestions.append("Add Virtual Consent Form")

    if "Missing VA Form 10-10172" in issues:
        suggestions.append("Add VA Form 10-10172")

    if "Missing Letter of Medical Necessity (LOMN)" in issues:
        suggestions.append("Add Letter of Medical Necessity")

    if "Missing Clinical Notes" in issues:
        suggestions.append("Attach clinical notes")

    if "Missing required packet component: SEOC" in issues:
        suggestions.append("Add SEOC")

    if "Missing required packet component: Consultation & Treatment Request" in issues:
        suggestions.append("Add Consultation & Treatment Request")


    # -------------------------------------------------
    # TRUEBRAIN DIAGNOSTIC SUMMARY
    # -------------------------------------------------

    if issues:

        explanation = "Packet requires correction because:\n"

        for issue in issues:
            explanation += f"- {issue}\n"

        suggestions.insert(0, explanation)

    else:

        suggestions.append(
            "Packet appears complete."
        )

    suggestions = list(dict.fromkeys(suggestions))

    return suggestions