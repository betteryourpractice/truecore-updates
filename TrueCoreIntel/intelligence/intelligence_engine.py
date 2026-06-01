import re

from TrueCoreIntel.core import packet_archetypes
from TrueCoreIntel.core import packet_failure_modes
from TrueCoreIntel.core import packet_robustness
from TrueCoreIntel.intelligence.clinical_intelligence import ClinicalIntelligenceAnalyzer
from TrueCoreIntel.intelligence.evidence_intelligence import EvidenceIntelligenceAnalyzer
from TrueCoreIntel.intelligence.packet_rubric import build_packet_rubric
from TrueCoreIntel.intelligence.semantic_adjudication import SemanticAdjudicationAnalyzer


class IntelligenceEngine:

    AUTHORIZATION_DOCUMENT_TYPES = packet_archetypes.AUTHORIZATION_DOCUMENT_TYPES
    HIGH_IMPACT_FIELDS = {"name", "dob", "authorization_number"}
    MEDIUM_IMPACT_FIELDS = {"icd_codes", "reason_for_request", "ordering_provider", "referring_provider"}
    ASSEMBLY_ADMIN_FIELDS = {
        "name",
        "dob",
        "authorization_number",
        "va_icn",
        "claim_number",
        "ordering_provider",
        "referring_provider",
        "provider",
        "facility",
        "clinic_name",
        "location",
        "service_date_range",
    }
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
        self.semantic_adjudication_analyzer = SemanticAdjudicationAnalyzer()

    def evaluate(self, packet):
        packet.evidence_intelligence = {}
        packet.clinical_intelligence = {}
        packet_archetypes.annotate_packet_context(packet)
        packet_robustness.annotate_packet_robustness(packet)
        packet_failure_modes.annotate_packet_failure_modes(packet)
        self.link_medical_evidence(packet)
        self.evaluate_medical_necessity(packet)
        self.evaluate_packet_integrity(packet)
        packet = self.evidence_intelligence_analyzer.analyze(packet)
        packet = self.clinical_intelligence_analyzer.analyze(packet)

        packet.packet_evidence_score = self.calculate_evidence_strength_score(packet)
        packet.packet_evidence_band = self.classify_support_band(packet.packet_evidence_score)
        packet.packet_assembly_score = self.calculate_packet_assembly_score(packet)
        packet.packet_assembly_band = self.classify_assembly_band(packet.packet_assembly_score)
        packet.packet_legacy_score = self.calculate_legacy_score(packet)
        packet.packet_rubric = build_packet_rubric(packet)
        packet = self.semantic_adjudication_analyzer.analyze(packet)
        packet.packet_main_blocker = packet.packet_rubric.get("main_blocker")
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

    def infer_packet_profile(self, packet):
        profile = packet_archetypes.infer_submission_profile(packet)
        packet.packet_profile = profile
        packet.packet_profile_label = packet_archetypes.get_submission_profile_label(profile)
        return profile

    def has_equivalent_document(self, packet, document_type):
        return packet_archetypes.has_equivalent_document(packet, document_type)

    def get_profile_requirements(self, packet):
        profile = self.infer_packet_profile(packet)
        requirements = packet_archetypes.get_submission_profile_requirements(profile)
        return (
            profile,
            set(requirements.get("required_documents", set()) or set()),
            set(requirements.get("expected_fields", set()) or set()),
        )

    def calculate_evidence_strength_score(self, packet):
        evidence_model = dict(getattr(packet, "evidence_intelligence", {}) or {}).get("evidence_sufficiency_modeling", {}) or {}
        score = evidence_model.get("score")
        try:
            evidence_score = float(score)
        except Exception:
            evidence_score = None

        if evidence_score is None:
            evidence_score = 28.0
            if "clinical_notes" in packet.detected_documents:
                evidence_score += 18
            if "diagnosis" in packet.fields:
                evidence_score += 16
            if "icd_codes" in packet.fields:
                evidence_score += 14
            if "reason_for_request" in packet.fields:
                evidence_score += 10
            if "procedure" in packet.fields:
                evidence_score += 7
            if "authorization_number" in packet.fields or "va_icn" in packet.fields:
                evidence_score += 6

        for flag in set(packet.review_flags or []):
            if flag == "weak_mri_justification":
                evidence_score -= 10
            elif flag == "moderate_mri_justification":
                evidence_score -= 4
            elif flag in {
                "diagnosis_without_icd_support",
                "icd_without_diagnosis_support",
                "missing_reason_for_request",
                "diagnosis_icd_mismatch",
                "partial_diagnosis_icd_alignment",
            }:
                evidence_score -= 6
            elif flag == "procedure_without_medical_support":
                evidence_score -= 12

        clinical_conflicts = sum(
            1 for conflict in packet.conflicts
            if conflict.get("field") in {"diagnosis", "icd_codes", "reason_for_request", "procedure", "symptom"}
        )
        if clinical_conflicts:
            evidence_score -= min(14, clinical_conflicts * 3)

        return round(max(0.0, min(evidence_score, 100.0)), 2)

    def calculate_packet_assembly_score(self, packet):
        _profile, required_documents, expected_fields = self.get_profile_requirements(packet)

        required_document_count = len(required_documents)
        present_required_documents = sum(
            1 for document_type in required_documents
            if self.has_equivalent_document(packet, document_type)
        )
        document_ratio = (
            present_required_documents / required_document_count
            if required_document_count else 1.0
        )
        document_score = 100.0 * (document_ratio ** 1.85)

        expected_field_count = len(expected_fields)
        present_expected_fields = sum(1 for field_name in expected_fields if packet.fields.get(field_name) not in (None, "", []))
        field_ratio = (
            present_expected_fields / expected_field_count
            if expected_field_count else 1.0
        )
        field_score = 100.0 * (field_ratio ** 1.25)

        cleanliness_score = 100.0
        admin_conflicts = 0
        for conflict in packet.conflicts:
            field_name = conflict.get("field")
            if field_name not in self.ASSEMBLY_ADMIN_FIELDS:
                continue
            admin_conflicts += 1
            severity = conflict.get("severity", "low")
            if severity == "high":
                cleanliness_score -= 16
            elif severity == "medium":
                cleanliness_score -= 8
            else:
                cleanliness_score -= 4

        if packet.missing_fields:
            for field in packet.missing_fields:
                if field in self.HIGH_IMPACT_FIELDS:
                    cleanliness_score -= 10
                elif field in self.MEDIUM_IMPACT_FIELDS:
                    cleanliness_score -= 6
                else:
                    cleanliness_score -= 4

        if getattr(packet, "unfilled_documents", set()):
            cleanliness_score -= min(18, len(packet.unfilled_documents) * 9)

        if "packet_integrity_risk" in set(packet.review_flags or []):
            cleanliness_score -= 16

        if "duplicate_pages_present" in set(packet.review_flags or []):
            cleanliness_score -= 6

        if "chronology_review_needed" in set(packet.review_flags or []):
            cleanliness_score -= 4

        cleanliness_score = max(0.0, min(cleanliness_score, 100.0))

        assembly_score = (document_score * 0.72) + (field_score * 0.18) + (cleanliness_score * 0.10)
        missing_doc_count = len(packet.missing_documents or [])
        if missing_doc_count:
            assembly_score -= min(18, 6 + max(0, missing_doc_count - 1) * 4)

        return round(max(0.0, min(assembly_score, 100.0)), 2)

    def calculate_legacy_score(self, packet):
        evidence_score = float(getattr(packet, "packet_evidence_score", 0.0) or 0.0)
        assembly_score = float(getattr(packet, "packet_assembly_score", 0.0) or 0.0)

        score = (evidence_score * 0.35) + (assembly_score * 0.65)

        if packet.field_confidence:
            avg_conf = sum(packet.field_confidence.values()) / len(packet.field_confidence)
            score *= 0.9 + (0.1 * avg_conf)

        score = self.apply_score_caps(packet, score)
        return max(min(round(score, 2), 100), 0)

    def calculate_score(self, packet):
        rubric = dict(getattr(packet, "packet_rubric", {}) or {})
        score = float(rubric.get("score") or 0.0)

        if packet.field_confidence:
            avg_conf = sum(packet.field_confidence.values()) / len(packet.field_confidence)
            score *= 0.95 + (0.05 * avg_conf)

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

        invariant_score = float(getattr(packet, "packet_invariant_coverage_score", 0.0) or 0.0) / 100.0
        semantic_score = float(getattr(packet, "packet_semantic_coherence_score", 0.0) or 0.0) / 100.0
        variability_level = str(getattr(packet, "packet_format_variability", "")).strip().lower()
        if invariant_score >= 0.85:
            confidence += 0.03
        elif invariant_score < 0.55:
            confidence -= 0.07

        if semantic_score >= 0.88:
            confidence += 0.04
        elif semantic_score >= 0.74 and variability_level == "high":
            confidence += 0.03
        elif semantic_score < 0.45:
            confidence -= 0.06

        if variability_level == "high" and invariant_score < 0.75:
            confidence -= 0.04
        elif variability_level == "low" and invariant_score >= 0.8:
            confidence += 0.02

        confidence -= float(getattr(packet, "packet_confidence_penalty", 0.0) or 0.0)

        return round(max(min(confidence, 1.0), 0.0), 2)

    def apply_score_caps(self, packet, score):
        assembly_score = float(getattr(packet, "packet_assembly_score", 0.0) or 0.0)

        if assembly_score < 45:
            score = min(score, 58)
        elif assembly_score < 60:
            score = min(score, 68)
        elif assembly_score < 75:
            score = min(score, 79)

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

    def classify_support_band(self, score):
        score = float(score or 0.0)
        if score >= 90:
            return "very_strong"
        if score >= 75:
            return "strong"
        if score >= 55:
            return "moderate"
        return "weak"

    def classify_assembly_band(self, score):
        score = float(score or 0.0)
        if score >= 85:
            return "strong"
        if score >= 65:
            return "moderate"
        return "weak"

    def classify_strength(self, packet):
        score = float(packet.packet_score or 0.0)
        if score >= 85:
            return "strong"
        if score >= 70:
            return "moderate"
        return "weak"

    def estimate_approval(self, packet):
        overall_score = float(packet.packet_score or 0.0) / 100.0
        assembly_score = float(getattr(packet, "packet_assembly_score", 0.0) or 0.0) / 100.0
        rubric = dict(getattr(packet, "packet_rubric", {}) or {})
        blockers = list(rubric.get("blockers", []) or [])
        review_needs = list(rubric.get("review_needs", []) or [])
        probability = (overall_score * 0.72) + (assembly_score * 0.28)

        if packet.missing_fields:
            if any(field in self.HIGH_IMPACT_FIELDS for field in packet.missing_fields):
                probability -= 0.22
            elif any(field in self.MEDIUM_IMPACT_FIELDS for field in packet.missing_fields):
                probability -= 0.12
            else:
                probability -= 0.07

        if packet.missing_documents:
            missing_document_count = len(packet.missing_documents)
            probability -= min(0.30, 0.12 * missing_document_count)
            if missing_document_count == 1:
                probability = min(probability, 0.48)
            elif missing_document_count == 2:
                probability = min(probability, 0.38)
            else:
                probability = min(probability, 0.28)

        if blockers:
            probability -= min(0.34, 0.10 + (0.08 * len(blockers)))
            probability = min(probability, 0.44)
        elif review_needs:
            probability -= min(0.18, 0.05 + (0.03 * len(review_needs)))
            probability = min(probability, 0.68)

        semantic_score = float(getattr(packet, "packet_semantic_coherence_score", 0.0) or 0.0) / 100.0
        semantic_summary = dict(getattr(packet, "semantic_adjudication", {}) or {})
        variant_tolerance = dict(semantic_summary.get("variant_tolerance", {}) or {})
        if semantic_score >= 0.88:
            probability += 0.04
        elif semantic_score >= 0.74 and variant_tolerance.get("coherent_despite_variation"):
            probability += 0.03
        elif semantic_score < 0.45:
            probability -= 0.08

        if "diagnosis_icd_mismatch" in packet.review_flags:
            probability -= 0.10

        if "weak_mri_justification" in packet.review_flags:
            probability -= 0.08
        elif "moderate_mri_justification" in packet.review_flags:
            probability -= 0.03

        if assembly_score < 0.60:
            probability = min(probability, 0.50)
        elif assembly_score < 0.75 and not blockers:
            probability = min(probability, 0.68)

        return round(max(min(probability, 1.0), 0.0), 2)
