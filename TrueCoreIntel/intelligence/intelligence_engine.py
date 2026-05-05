import re

from TrueCoreIntel.intelligence.clinical_intelligence import ClinicalIntelligenceAnalyzer
from TrueCoreIntel.intelligence.evidence_intelligence import EvidenceIntelligenceAnalyzer


class IntelligenceEngine:

    HIGH_IMPACT_FIELDS = {"name", "dob", "authorization_number"}
    MEDIUM_IMPACT_FIELDS = {"icd_codes", "reason_for_request", "ordering_provider", "referring_provider"}

    MRI_SUPPORT_TERMS = {
        "symptoms_strong": {"numbness", "weakness", "tingling"},
        "symptoms_moderate": {"pain", "limited_range_of_motion"},
        "diagnoses_strong": {"radiculopathy", "degenerative disc disease"},
        "diagnoses_moderate": {"low back pain", "neck pain", "osteoarthritis"},
    }

    DIAGNOSIS_ICD_EXPECTATIONS = {
        "degenerative disc disease": {"M51", "M50"},
        "low back pain": {"M54.5", "M54.50"},
        "migraine": {"G43"},
        "osteoarthritis": {"M19"},
        "radiculopathy": {"M54.1", "M54.10", "M54.12", "M54.16"},
        "neck pain": {"M54.2"},
    }

    def __init__(self):
        self.clinical_intelligence_analyzer = ClinicalIntelligenceAnalyzer()
        self.evidence_intelligence_analyzer = EvidenceIntelligenceAnalyzer()

    def evaluate(self, packet):
        packet.evidence_intelligence = {}
        packet.clinical_intelligence = {}
        self.link_medical_evidence(packet)
        self.evaluate_medical_necessity(packet)
        self.evaluate_packet_integrity(packet)
        packet = self.evidence_intelligence_analyzer.analyze(packet)
        packet = self.clinical_intelligence_analyzer.analyze(packet)

        packet.packet_score = self.calculate_score(packet)
        packet.packet_confidence = self.calculate_packet_confidence(packet)
        packet.packet_strength = self.classify_strength(packet)
        packet.approval_probability = self.estimate_approval(packet)
        return packet

    def link_medical_evidence(self, packet):
        if "procedure" in packet.fields and "symptom" in packet.fields:
            packet.evidence_links.append({
                "type": "symptom_support",
                "procedure": packet.fields["procedure"],
                "supported_by": packet.fields["symptom"],
            })

        if "diagnosis" in packet.fields and "icd_codes" in packet.fields:
            packet.evidence_links.append({
                "type": "diagnosis_mapping",
                "diagnosis": packet.fields["diagnosis"],
                "icd_codes": packet.fields["icd_codes"],
            })

        if "reason_for_request" in packet.fields and "procedure" in packet.fields:
            packet.evidence_links.append({
                "type": "request_alignment",
                "procedure": packet.fields["procedure"],
                "reason_for_request": packet.fields["reason_for_request"],
            })

        if packet.duplicate_pages:
            packet.evidence_links.append({
                "type": "duplicate_page_groups",
                "groups": packet.duplicate_pages,
            })

        if "service_date_range" in packet.fields:
            packet.evidence_links.append({
                "type": "service_date_range",
                "service_date_range": packet.fields["service_date_range"],
            })

    def evaluate_medical_necessity(self, packet):
        procedure = packet.fields.get("procedure")
        diagnosis = packet.fields.get("diagnosis")
        symptom = packet.fields.get("symptom")
        reason_for_request = packet.fields.get("reason_for_request")
        icd_codes = packet.fields.get("icd_codes", [])

        self.evaluate_diagnosis_icd_alignment(packet, diagnosis, icd_codes)
        self.evaluate_procedure_support(packet, procedure, diagnosis, symptom, reason_for_request)

        if "reason_for_request" not in packet.fields:
            packet.review_flags.append("missing_reason_for_request")

    def evaluate_packet_integrity(self, packet):
        high_identity_conflicts = [
            conflict for conflict in packet.conflicts
            if conflict.get("field") in {"name", "dob", "va_icn", "claim_number"}
            and conflict.get("severity") == "high"
        ]

        if len(high_identity_conflicts) >= 2:
            packet.review_flags.append("packet_integrity_risk")

        if packet.duplicate_pages:
            packet.review_flags.append("duplicate_pages_present")

        if any(conflict.get("type") == "chronology_error" for conflict in packet.conflicts):
            packet.review_flags.append("chronology_review_needed")

    def evaluate_diagnosis_icd_alignment(self, packet, diagnosis, icd_codes):
        if diagnosis and icd_codes:
            expected_prefixes = self.DIAGNOSIS_ICD_EXPECTATIONS.get(diagnosis, set())

            if not expected_prefixes:
                packet.evidence_links.append({
                    "type": "diagnosis_icd_support",
                    "diagnosis": diagnosis,
                    "icd_codes": icd_codes,
                    "status": "present_unmapped",
                })
                return

            match_quality = self.evaluate_icd_match_quality(icd_codes, expected_prefixes)

            packet.evidence_links.append({
                "type": "diagnosis_icd_support",
                "diagnosis": diagnosis,
                "icd_codes": icd_codes,
                "status": match_quality,
                "expected_prefixes": sorted(expected_prefixes),
            })

            if match_quality == "weak":
                packet.review_flags.append("diagnosis_icd_mismatch")

            elif match_quality == "moderate":
                packet.review_flags.append("partial_diagnosis_icd_alignment")

        elif diagnosis and not icd_codes:
            packet.review_flags.append("diagnosis_without_icd_support")

        elif icd_codes and not diagnosis:
            packet.review_flags.append("icd_without_diagnosis_support")

    def evaluate_procedure_support(self, packet, procedure, diagnosis, symptom, reason_for_request=None):
        if not procedure:
            return

        if procedure == "MRI":
            support_level = self.get_mri_support_level(diagnosis, symptom, reason_for_request)

            packet.evidence_links.append({
                "type": "procedure_justification",
                "procedure": procedure,
                "diagnosis": diagnosis,
                "symptom": symptom,
                "reason_for_request": reason_for_request,
                "status": support_level,
            })

            if support_level == "strong":
                return

            if support_level == "moderate":
                packet.review_flags.append("moderate_mri_justification")
                return

            packet.review_flags.append("weak_mri_justification")

        if procedure and not diagnosis and not symptom:
            packet.review_flags.append("procedure_without_medical_support")

    def get_mri_support_level(self, diagnosis, symptom, reason_for_request=None):
        strong_points = 0
        moderate_points = 0

        if diagnosis in self.MRI_SUPPORT_TERMS["diagnoses_strong"]:
            strong_points += 1
        elif diagnosis in self.MRI_SUPPORT_TERMS["diagnoses_moderate"]:
            moderate_points += 1

        if symptom in self.MRI_SUPPORT_TERMS["symptoms_strong"]:
            strong_points += 1
        elif symptom in self.MRI_SUPPORT_TERMS["symptoms_moderate"]:
            moderate_points += 1

        if reason_for_request:
            cleaned_reason = str(reason_for_request).strip().lower()
            cleaned_reason = re.sub(r"[^a-z0-9,;/ ]", " ", cleaned_reason)
            cleaned_reason = re.sub(r"\s+", " ", cleaned_reason).strip()

            complaint_chunks = [
                part.strip()
                for part in re.split(r"[,;/]|\band\b", cleaned_reason)
                if part.strip()
            ]

            body_regions = {
                "back": {"back", "lumbar", "lumbago"},
                "neck": {"neck", "cervical"},
                "hip": {"hip"},
                "shoulder": {"shoulder"},
                "leg": {"leg", "sciatica"},
                "arm": {"arm"},
            }
            mentioned_regions = {
                region
                for region, aliases in body_regions.items()
                if any(alias in cleaned_reason for alias in aliases)
            }

            if "pain" in cleaned_reason and (len(complaint_chunks) >= 2 or len(mentioned_regions) >= 2):
                strong_points += 1
            elif len(complaint_chunks) >= 2 or len(mentioned_regions) >= 2:
                moderate_points += 1

        if strong_points >= 1 and (strong_points + moderate_points) >= 2:
            return "strong"

        if moderate_points >= 3:
            return "strong"

        if strong_points >= 1:
            return "moderate"

        if moderate_points >= 2:
            return "moderate"

        if moderate_points == 1:
            return "moderate"

        return "weak"

    def evaluate_icd_match_quality(self, icd_codes, expected_prefixes):
        """
        Returns match quality: strong / moderate / weak
        based on how many ICDs align with expected diagnosis families.
        """

        if not icd_codes:
            return "none"

        total = len(icd_codes)
        matches = 0

        for code in icd_codes:
            normalized_code = str(code).upper().strip()
            if any(normalized_code.startswith(prefix) for prefix in expected_prefixes):
                matches += 1

        if matches == total and total > 0:
            return "strong"

        if matches >= 1:
            return "moderate"

        return "weak"

    def calculate_score(self, packet):
        score = 100

        for field in packet.missing_fields:
            if field in self.HIGH_IMPACT_FIELDS:
                score -= 20
            elif field in self.MEDIUM_IMPACT_FIELDS:
                score -= 12
            else:
                score -= 8

        missing_doc_count = len(packet.missing_documents)
        if missing_doc_count > 0:
            # Diminishing penalty - first docs matter most, not linear destruction
            score -= min(18, missing_doc_count * 4)

        if "icd_codes" in packet.fields:
            score += 6
        if "diagnosis" in packet.fields:
            score += 8
        if "reason_for_request" in packet.fields:
            score += 5
        if "npi" in packet.fields:
            score += 2
        if "service_date_range" in packet.fields:
            score += 2

        for conflict in packet.conflicts:
            severity = conflict.get("severity", "low")

            if severity == "high":
                score -= 22
            elif severity == "medium":
                score -= 12
            else:
                score -= 6

        for flag in set(packet.review_flags):
            if flag == "procedure_without_medical_support":
                score -= 15
            elif flag == "weak_mri_justification":
                score -= 12
            elif flag == "moderate_mri_justification":
                score -= 5
            elif flag in {
                "diagnosis_without_icd_support",
                "icd_without_diagnosis_support",
                "missing_reason_for_request",
                "diagnosis_icd_mismatch",
            }:
                score -= 10
            elif flag == "packet_integrity_risk":
                score -= 15
            elif flag == "chronology_review_needed":
                score -= 6
            elif flag == "duplicate_pages_present":
                score -= 3

        if packet.field_confidence:
            avg_conf = sum(packet.field_confidence.values()) / len(packet.field_confidence)
            score *= avg_conf

        score = self.apply_score_caps(packet, score)
        return max(min(round(score, 2), 100), 0)

    def calculate_packet_confidence(self, packet):
        field_confidence = (
            sum(packet.field_confidence.values()) / len(packet.field_confidence)
            if packet.field_confidence else 0.0
        )
        meaningful_page_confidences = [
            confidence
            for index, confidence in packet.page_confidence.items()
            if packet.document_types.get(index, "unknown") != "unknown" or confidence >= 0.5
        ]
        if not meaningful_page_confidences:
            meaningful_page_confidences = list(packet.page_confidence.values())

        page_confidence = (
            sum(meaningful_page_confidences) / len(meaningful_page_confidences)
            if meaningful_page_confidences else 0.0
        )

        if field_confidence and page_confidence:
            confidence = (field_confidence * 0.65) + (page_confidence * 0.35)
        else:
            confidence = max(field_confidence, page_confidence)

        if packet.conflicts:
            confidence -= min(0.18, 0.04 * len(packet.conflicts))

        if packet.missing_fields or packet.missing_documents:
            confidence -= 0.05

        return round(max(min(confidence, 1.0), 0.0), 2)

    def apply_score_caps(self, packet, score):
        if packet.missing_fields:
            if any(field in self.HIGH_IMPACT_FIELDS for field in packet.missing_fields):
                score = min(score, 62)
            elif any(field in self.MEDIUM_IMPACT_FIELDS for field in packet.missing_fields):
                score = min(score, 74)
            else:
                score = min(score, 82)

        missing_doc_count = len(packet.missing_documents)
        if missing_doc_count == 1:
            score = min(score, 78)
        elif missing_doc_count == 2:
            score = min(score, 72)
        elif missing_doc_count >= 3:
            score = min(score, 66)

        if any(conflict.get("severity") == "high" for conflict in packet.conflicts):
            score = min(score, 64)
        elif any(conflict.get("severity") == "medium" for conflict in packet.conflicts):
            score = min(score, 82)

        if "procedure_without_medical_support" in packet.review_flags:
            score = min(score, 72)
        elif "weak_mri_justification" in packet.review_flags:
            score = min(score, 78)
        elif "diagnosis_icd_mismatch" in packet.review_flags:
            score = min(score, 84)

        return score

    def classify_strength(self, packet):
        score = packet.packet_score
        has_high_conflict = any(conflict.get("severity") == "high" for conflict in packet.conflicts)

        if has_high_conflict and score < 80:
            return "weak"

        if score >= 80:
            return "strong"
        if score >= 55:
            return "moderate"
        return "weak"

    def estimate_approval(self, packet):
        probability = packet.packet_score / 100

        if packet.missing_fields:
            if any(field in self.HIGH_IMPACT_FIELDS for field in packet.missing_fields):
                probability -= 0.22
            elif any(field in self.MEDIUM_IMPACT_FIELDS for field in packet.missing_fields):
                probability -= 0.12
            else:
                probability -= 0.07

        if packet.missing_documents:
            probability -= min(0.24, 0.10 * len(packet.missing_documents))

        if any(conflict.get("severity") == "high" for conflict in packet.conflicts):
            probability -= 0.15
        elif any(conflict.get("severity") == "medium" for conflict in packet.conflicts):
            probability -= 0.08

        if "diagnosis_icd_mismatch" in packet.review_flags:
            probability -= 0.10

        if "weak_mri_justification" in packet.review_flags:
            probability -= 0.08
        elif "moderate_mri_justification" in packet.review_flags:
            probability -= 0.03

        return round(max(min(probability, 1.0), 0.0), 2)
