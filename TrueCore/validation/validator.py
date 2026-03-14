"""
TrueCore Packet Validator

Validates extracted packet fields and detected forms,
assigning a packet completeness score and generating
issues + suggestions.
"""
# -------------------------------------------------
# REQUIRED PACKET COMPONENTS
# -------------------------------------------------

REQUIRED_PACKET_FORMS = [

    "Virtual Consent Form",
    "VA Form 10-10172",
    "SEOC",
    "Consultation & Treatment Request",
    "Letter of Medical Necessity",

]

def validate_packet(fields, detected_forms):

    issues = []

    score = 100

    # -------------------------------------------------
    # FIELD EXTRACTION
    # -------------------------------------------------

    patient_name = fields.get("patient_name")
    dob = fields.get("dob")
    authorization = fields.get("authorization_number")
    icd_codes = fields.get("icd_codes")
    ordering_doctor = fields.get("ordering_doctor")
    referring_doctor = fields.get("referring_doctor")

    # -------------------------------------------------
    # FIELD VALIDATION
    # -------------------------------------------------

    if not patient_name:
        issues.append("Missing patient name")
        score -= 20

    if not dob:
        issues.append("Missing patient DOB")
        score -= 15

    if not authorization:
        issues.append("Missing authorization number")
        score -= 20

    if not icd_codes:
        issues.append("Missing ICD codes")
        score -= 15

    if not ordering_doctor:
        issues.append("Missing ordering doctor")
        score -= 10

    if not referring_doctor:
        issues.append("Missing referring doctor")
        score -= 10

    # -------------------------------------------------
    # FORM VALIDATION
    # -------------------------------------------------

    # Required packet forms check
            
    if "Letter of Medical Necessity" not in detected_forms:
        issues.append("Missing Letter of Medical Necessity (LOMN)")
        score -= 5

    if "Clinical Notes" not in detected_forms:
        issues.append("Missing Clinical Notes")
        score -= 5

    if "VA Form 10-10172" not in detected_forms:
        issues.append("Missing VA Form 10-10172")

    if "Virtual Consent Form" not in detected_forms:
        issues.append("Missing Virtual Consent Form")

    if "SEOC" not in detected_forms:
        issues.append("Missing SEOC")
        score -= 5
   
    if "Consultation & Treatment Request" not in detected_forms:
        issues.append("Missing Consultation & Treatment Request")
        score -= 5

    # -------------------------------------------------
    # SCORE FLOOR
    # -------------------------------------------------

    if score < 0:
        score = 0

    # -------------------------------------------------
    # CONFIDENCE LEVEL
    # -------------------------------------------------

    if score >= 90:
        confidence = "HIGH"
    elif score >= 70:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"
    
    # -------------------------------------------------
    # RESULT
    # -------------------------------------------------

    result = {
        "score": score,
        "confidence": confidence,
        "issues": issues,
    }

    return result