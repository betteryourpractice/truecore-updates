from __future__ import annotations

import re

from TrueCoreIntel.core.document_semantics import normalize_semantic_text


class SemanticAdjudicationAnalyzer:
    REGION_HINTS = {
        "lumbar": {"lumbar", "low back", "back pain", "l4", "l5", "s1", "l5-s1", "l4-l5"},
        "cervical": {"cervical", "neck", "c spine", "c-spine"},
        "thoracic": {"thoracic", "mid back", "t spine", "t-spine"},
        "hip": {"hip"},
        "knee": {"knee"},
        "shoulder": {"shoulder"},
    }

    DIAGNOSIS_FAMILIES = {
        "degenerative_disc": {"degenerative disc disease", "disc degeneration", "degenerative disc", "ddd"},
        "discogenic_annular": {"discogenic", "annular", "annular tear", "intradiscal", "intraannular", "fibrin"},
        "disc_displacement": {"disc displacement", "disc protrusion", "disc herniation", "herniation", "bulge"},
        "radicular": {"radiculopathy", "radicular", "sciatica", "nerve root"},
        "axial_pain": {"low back pain", "back pain", "neck pain", "lumbar pain", "cervical pain", "pain"},
    }

    REQUEST_FAMILIES = {
        "specialty_evaluation": {"specialty evaluation", "consultation", "consult", "treatment planning", "diagnostic confirmation", "evaluation"},
        "episode_limited": {"single episode of care", "seoc", "time limited", "limited to", "standard follow-up"},
        "procedure_specific": {"procedure", "injection", "ablation", "mri", "imaging", "fibrin", "interventional"},
        "conservative_failure": {"failed conservative", "despite conservative", "physical therapy", "home exercise", "activity modification", "nsaids"},
        "functional_impact": {"functional limitation", "daily activities", "sleep", "sit", "stand", "walk", "run"},
    }

    ICD_PREFIX_FAMILIES = {
        "M50": "degenerative_disc",
        "M51": "degenerative_disc",
        "M54.1": "radicular",
        "M54.16": "radicular",
        "M54.10": "radicular",
        "M54.12": "radicular",
        "M54.2": "axial_pain",
        "M54.5": "axial_pain",
        "M54.50": "axial_pain",
    }

    SUPPORTIVE_FAMILY_PAIRS = {
        ("degenerative_disc", "axial_pain"),
        ("degenerative_disc", "radicular"),
        ("discogenic_annular", "degenerative_disc"),
        ("disc_displacement", "radicular"),
        ("disc_displacement", "degenerative_disc"),
    }

    NON_BLOCKING_FLAGS = {
        "partial_diagnosis_icd_alignment",
        "moderate_mri_justification",
    }
    TOLERABLE_CONFLICT_FIELDS = {
        "diagnosis",
        "reason_for_request",
        "procedure",
        "icd_codes",
        "provider",
        "ordering_provider",
        "referring_provider",
        "facility",
        "clinic_name",
        "location",
    }

    def analyze(self, packet):
        diagnosis_alignment = self.build_diagnosis_alignment(packet)
        request_alignment = self.build_request_alignment(packet, diagnosis_alignment)
        provider_alignment = self.build_provider_alignment(packet)
        episode_alignment = self.build_episode_alignment(packet, diagnosis_alignment, request_alignment)

        concepts = [
            diagnosis_alignment,
            request_alignment,
            provider_alignment,
            episode_alignment,
        ]
        overall_score = self.compute_overall_score(concepts)
        overall_status = self.score_to_status(overall_score)
        variant_tolerance = self.build_variant_tolerance(packet, overall_score, concepts)
        tolerated_conflicts = self.build_tolerated_conflicts(packet, concepts, overall_score, variant_tolerance)
        deduction_ledger = self.build_deduction_ledger(packet, concepts, variant_tolerance, tolerated_conflicts)

        packet.semantic_adjudication = {
            "overall_score": overall_score,
            "overall_status": overall_status,
            "concepts": concepts,
            "variant_tolerance": variant_tolerance,
            "tolerated_conflicts": tolerated_conflicts,
            "deduction_ledger": deduction_ledger,
            "review_notes": self.build_review_notes(concepts, variant_tolerance, tolerated_conflicts),
        }
        packet.packet_semantic_coherence_score = overall_score
        packet.packet_semantic_coherence_band = self.score_to_band(overall_score)
        packet.links["semantic_adjudication"] = dict(packet.semantic_adjudication)
        packet.metrics["semantic_coherence_score"] = overall_score
        return packet

    def build_diagnosis_alignment(self, packet):
        diagnosis_text = str(packet.fields.get("diagnosis") or "")
        reason_text = str(packet.fields.get("reason_for_request") or "")
        symptom_text = str(packet.fields.get("symptom") or "")
        icd_codes = list(packet.fields.get("icd_codes", []) or [])

        diagnosis_families = self.extract_families(diagnosis_text, self.DIAGNOSIS_FAMILIES)
        reason_families = self.extract_families(reason_text, self.DIAGNOSIS_FAMILIES)
        symptom_families = self.extract_families(symptom_text, self.DIAGNOSIS_FAMILIES)
        icd_families = self.extract_icd_families(icd_codes)

        region_signals = {
            "diagnosis": sorted(self.extract_regions(diagnosis_text)),
            "reason": sorted(self.extract_regions(reason_text)),
            "symptom": sorted(self.extract_regions(symptom_text)),
        }
        combined_families = diagnosis_families | reason_families | symptom_families | icd_families

        notes = []
        if diagnosis_families and icd_families:
            if diagnosis_families & icd_families:
                notes.append("Primary diagnosis language and ICD coding point to the same clinical family.")
                score = 94
                status = "coherent"
            elif self.families_are_supportive(diagnosis_families, icd_families):
                notes.append("Diagnosis language and ICD coding are not identical, but they still describe the same spine episode.")
                score = 84
                status = "coherent_variant"
            else:
                notes.append("Diagnosis language and ICD coding appear to describe different clinical families.")
                score = 46
                status = "conflict"
        elif combined_families:
            notes.append("Diagnosis support is clinically recognizable, but not all anchors are explicit.")
            score = 72
            status = "partial"
        else:
            notes.append("Diagnosis support is too sparse for confident semantic reconciliation.")
            score = 38
            status = "insufficient"

        aligned_regions = self.aligned_regions(region_signals)
        if aligned_regions:
            notes.append(f"Body-region alignment is centered on {', '.join(aligned_regions)}.")
            score += 4
        elif any(region_signals.values()):
            notes.append("Body-region wording is mixed or only partially explicit.")
            score -= 4

        return {
            "concept": "diagnostic_basis",
            "status": self.normalize_status(status),
            "score": max(0, min(score, 100)),
            "families": sorted(combined_families),
            "regions": region_signals,
            "notes": notes,
        }

    def build_request_alignment(self, packet, diagnosis_alignment):
        reason_text = str(packet.fields.get("reason_for_request") or "")
        procedure_text = str(packet.fields.get("procedure") or "")
        diagnosis_text = str(packet.fields.get("diagnosis") or "")
        concept_tracebacks = list(packet.links.get("concept_evidence_tracebacks", []) or [])

        request_families = self.extract_families(reason_text, self.REQUEST_FAMILIES)
        procedure_families = self.extract_families(procedure_text, self.REQUEST_FAMILIES)
        combined_families = request_families | procedure_families
        diagnosis_regions = set(diagnosis_alignment.get("regions", {}).get("diagnosis", []))
        request_regions = self.extract_regions(reason_text) | self.extract_regions(procedure_text) | self.extract_regions(diagnosis_text)

        notes = []
        if combined_families:
            if {"specialty_evaluation", "episode_limited"} & combined_families or "procedure_specific" in combined_families:
                notes.append("The request intent reads like a defined evaluation/treatment pathway rather than open-ended care.")
                score = 90
                status = "coherent"
            else:
                notes.append("The request intent is present, but its scope is less explicit than ideal.")
                score = 72
                status = "partial"
        elif reason_text.strip():
            notes.append("The request intent is written in narrative form, but semantic cues are thin.")
            score = 62
            status = "partial"
        else:
            notes.append("Reason-for-request support is too thin for semantic interpretation.")
            score = 34
            status = "insufficient"

        if diagnosis_regions and request_regions and diagnosis_regions.intersection(request_regions):
            notes.append("The request stays tied to the same body region as the diagnosis.")
            score += 4
        elif request_regions:
            notes.append("Request wording does not fully anchor back to the diagnosis region.")
            score -= 5

        if any(str(item.get("concept") or "").strip().lower() == "request_intent" for item in concept_tracebacks):
            score += 2

        return {
            "concept": "request_intent",
            "status": self.normalize_status(status),
            "score": max(0, min(score, 100)),
            "families": sorted(combined_families),
            "regions": sorted(request_regions),
            "notes": notes,
        }

    def build_provider_alignment(self, packet):
        ordering_provider = str(packet.fields.get("ordering_provider") or "")
        referring_provider = str(packet.fields.get("referring_provider") or "")
        provider = str(packet.fields.get("provider") or "")
        facility = str(packet.fields.get("facility") or "")
        clinic_name = str(packet.fields.get("clinic_name") or "")
        conflicts = list(packet.conflicts or [])

        provider_conflicts = [
            conflict for conflict in conflicts
            if str(conflict.get("field") or "") in {"ordering_provider", "referring_provider", "provider", "facility", "clinic_name", "location"}
        ]

        present_roles = [
            label
            for label, value in (
                ("ordering provider", ordering_provider),
                ("referring provider", referring_provider),
                ("community provider", provider),
                ("VA facility", facility),
                ("community clinic", clinic_name),
            )
            if value.strip()
        ]
        notes = []

        if provider_conflicts:
            score = 52
            status = "conflict"
            notes.append("Provider or routing roles are still colliding across documents.")
        elif len(present_roles) >= 3:
            score = 92
            status = "coherent"
            notes.append("VA routing and community-treatment roles are separately recognizable.")
        elif present_roles:
            score = 74
            status = "partial"
            notes.append("Some provider-role anchors are present, but the full referral chain is only partially explicit.")
        else:
            score = 36
            status = "insufficient"
            notes.append("Provider-role anchors are too thin for reliable semantic routing.")

        if ordering_provider and provider and self.normalized_value(ordering_provider) == self.normalized_value(provider):
            notes.append("Ordering and community provider currently collapse to the same named provider.")

        return {
            "concept": "provider_routing",
            "status": self.normalize_status(status),
            "score": max(0, min(score, 100)),
            "roles_present": present_roles,
            "notes": notes,
        }

    def build_episode_alignment(self, packet, diagnosis_alignment, request_alignment):
        name = str(packet.fields.get("name") or "")
        dob = str(packet.fields.get("dob") or "")
        authorization = str(packet.fields.get("authorization_number") or packet.fields.get("claim_number") or "")
        high_identity_conflicts = [
            conflict for conflict in (packet.conflicts or [])
            if str(conflict.get("field") or "") in {"name", "dob", "authorization_number", "va_icn", "claim_number"}
            and str(conflict.get("severity") or "").lower() == "high"
        ]

        notes = []
        score = 50
        status = "partial"
        anchors = sum(1 for value in (name, dob, authorization) if value.strip())

        if high_identity_conflicts:
            score = 22
            status = "conflict"
            notes.append("High-severity identity or case-anchor conflicts remain unresolved.")
        elif anchors >= 3 and diagnosis_alignment.get("score", 0) >= 70 and request_alignment.get("score", 0) >= 70:
            score = 94
            status = "coherent"
            notes.append("Identity, routing, diagnosis, and request intent read like one coherent case episode.")
        elif anchors >= 2:
            score = 76
            status = "coherent_variant"
            notes.append("Core case anchors are present even though some packet details vary by office format.")
        else:
            notes.append("Too few packet-wide case anchors are present for strong semantic adjudication.")

        return {
            "concept": "packet_episode",
            "status": self.normalize_status(status),
            "score": max(0, min(score, 100)),
            "notes": notes,
        }

    def compute_overall_score(self, concepts):
        concept_weights = {
            "diagnostic_basis": 0.35,
            "request_intent": 0.30,
            "provider_routing": 0.15,
            "packet_episode": 0.20,
        }
        weighted = 0.0
        for concept in concepts:
            weighted += float(concept.get("score") or 0.0) * float(concept_weights.get(concept.get("concept"), 0.0))
        return round(max(0.0, min(weighted, 100.0)), 2)

    def build_variant_tolerance(self, packet, overall_score, concepts):
        variability = str(getattr(packet, "packet_format_variability", "") or "").strip().lower()
        conflict_count = len(getattr(packet, "conflicts", []) or [])
        coherent_concepts = sum(1 for concept in concepts if concept.get("status") in {"coherent", "coherent_variant"})
        despite_variation = variability == "high" and overall_score >= 80 and conflict_count <= 1 and coherent_concepts >= 3
        return {
            "format_variability": variability or None,
            "coherent_despite_variation": despite_variation,
            "interpretation_mode": "human_like_reconciliation" if despite_variation else "structured_reconciliation",
            "notes": [
                "Packet remains semantically coherent despite office-specific wording variation."
                if despite_variation else
                "Packet meaning is still being judged through structured reconciliation rather than literal field matching."
            ],
        }

    def build_tolerated_conflicts(self, packet, concepts, overall_score, variant_tolerance):
        if overall_score < 78:
            return []

        concept_scores = {
            str(item.get("concept") or "").strip().lower(): float(item.get("score") or 0.0)
            for item in list(concepts or [])
        }
        tolerated = []

        for conflict in list(packet.conflicts or []):
            field_name = str(conflict.get("field") or "").strip().lower()
            severity = str(conflict.get("severity") or "low").strip().lower()
            if field_name not in self.TOLERABLE_CONFLICT_FIELDS or severity == "high":
                continue

            supportive = False
            if field_name in {"diagnosis", "icd_codes"} and concept_scores.get("diagnostic_basis", 0.0) >= 82:
                supportive = True
            elif field_name in {"reason_for_request", "procedure"} and concept_scores.get("request_intent", 0.0) >= 82:
                supportive = True
            elif field_name in {"provider", "ordering_provider", "referring_provider", "facility", "clinic_name", "location"} and concept_scores.get("provider_routing", 0.0) >= 82:
                supportive = True

            if not supportive and not variant_tolerance.get("coherent_despite_variation"):
                continue

            tolerated.append({
                "field": field_name,
                "severity": severity,
                "message": str(conflict.get("message") or "").strip(),
                "reason": "semantic_variant_tolerated",
            })

        return tolerated

    def build_deduction_ledger(self, packet, concepts, variant_tolerance, tolerated_conflicts):
        rubric = dict(getattr(packet, "packet_rubric", {}) or {})
        tolerated_conflict_fields = {
            str(item.get("field") or "").strip().lower()
            for item in list(tolerated_conflicts or [])
            if item.get("field")
        }
        deductions = []

        for document_type in list(packet.missing_documents or []):
            deductions.append({
                "category": "missing_document",
                "severity": "high" if document_type in {"rfs", "consult_request", "lomn", "consent", "clinical_notes"} else "medium",
                "reason": f"Supporting document could not be confirmed: {document_type}",
                "trust_level": "real_gap",
            })

        for field in list(packet.missing_fields or []):
            deductions.append({
                "category": "missing_field",
                "severity": "high" if field in {"name", "dob", "authorization_number"} else "medium",
                "reason": f"Required field is still missing: {field}",
                "trust_level": "real_gap",
            })

        for conflict in list(packet.conflicts or []):
            field_name = str(conflict.get("field") or "").strip().lower()
            deductions.append({
                "category": "conflict",
                "severity": str(conflict.get("severity") or "low").lower(),
                "reason": str(conflict.get("message") or f"Conflict detected for {conflict.get('field')}.").strip(),
                "trust_level": (
                    "variant_tolerated"
                    if field_name in tolerated_conflict_fields
                    else "real_gap" if str(conflict.get("severity") or "").lower() == "high" else "review_caution"
                ),
            })

        for flag in list(packet.review_flags or []):
            normalized_flag = str(flag or "").strip().lower()
            if normalized_flag == "manual_review_required":
                continue
            deductions.append({
                "category": "review_flag",
                "severity": "low" if normalized_flag in self.NON_BLOCKING_FLAGS else "medium",
                "reason": normalized_flag.replace("_", " "),
                "trust_level": "review_caution" if normalized_flag in self.NON_BLOCKING_FLAGS else "real_gap",
            })

        if variant_tolerance.get("coherent_despite_variation"):
            deductions.append({
                "category": "variant_tolerance",
                "severity": "info",
                "reason": "High format variation was detected, but the packet story still reconciles coherently.",
                "trust_level": "variant_tolerated",
            })

        for concept in concepts:
            if concept.get("status") == "conflict":
                deductions.append({
                    "category": "semantic_conflict",
                    "severity": "medium",
                    "reason": f"Semantic reconciliation still sees tension in {concept.get('concept')}.",
                    "trust_level": "review_caution",
                })

        if rubric.get("main_blocker"):
            deductions.append({
                "category": "main_blocker",
                "severity": "high",
                "reason": str(rubric.get("main_blocker")).strip(),
                "trust_level": "real_gap",
            })

        return self.dedupe_deductions(deductions)

    def build_review_notes(self, concepts, variant_tolerance, tolerated_conflicts):
        notes = []
        if variant_tolerance.get("coherent_despite_variation"):
            notes.append("Packet meaning remains coherent even though the office formatting varies.")
        if tolerated_conflicts:
            notes.append("Some medium/low field conflicts are being treated as office-format or wording variants rather than hard defects.")

        for concept in concepts:
            status = concept.get("status")
            if status in {"coherent_variant", "partial", "conflict"}:
                notes.extend(list(concept.get("notes") or [])[:2])

        return self.unique_preserve_order(notes)[:8]

    def extract_regions(self, text):
        normalized = normalize_semantic_text(text)
        found = set()
        for region, hints in self.REGION_HINTS.items():
            if any(hint in normalized for hint in hints):
                found.add(region)
        return found

    def extract_families(self, text, family_map):
        normalized = normalize_semantic_text(text)
        found = set()
        for family, hints in family_map.items():
            if any(hint in normalized for hint in hints):
                found.add(family)
        return found

    def extract_icd_families(self, icd_codes):
        families = set()
        for code in list(icd_codes or []):
            normalized = str(code or "").upper().strip()
            for prefix, family in self.ICD_PREFIX_FAMILIES.items():
                if normalized.startswith(prefix):
                    families.add(family)
        return families

    def families_are_supportive(self, left, right):
        for left_family in left:
            for right_family in right:
                if left_family == right_family:
                    return True
                if (left_family, right_family) in self.SUPPORTIVE_FAMILY_PAIRS:
                    return True
                if (right_family, left_family) in self.SUPPORTIVE_FAMILY_PAIRS:
                    return True
        return False

    def aligned_regions(self, region_signals):
        non_empty = [set(regions) for regions in region_signals.values() if regions]
        if not non_empty:
            return []
        intersection = set.intersection(*non_empty) if len(non_empty) > 1 else non_empty[0]
        return sorted(intersection)

    def score_to_status(self, score):
        if score >= 88:
            return "coherent"
        if score >= 74:
            return "coherent_variant"
        if score >= 58:
            return "partial"
        if score >= 40:
            return "review"
        return "conflict"

    def score_to_band(self, score):
        if score >= 88:
            return "strong"
        if score >= 74:
            return "moderate"
        return "low"

    def normalize_status(self, status):
        status = str(status or "").strip().lower()
        if status in {"coherent", "coherent_variant", "partial", "conflict", "insufficient"}:
            return status
        return "partial"

    def normalized_value(self, value):
        normalized = normalize_semantic_text(value)
        normalized = re.sub(r"[^a-z0-9 ]", " ", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    def dedupe_deductions(self, deductions):
        seen = set()
        deduped = []
        for item in list(deductions or []):
            key = (
                str(item.get("category") or "").strip().lower(),
                str(item.get("reason") or "").strip().lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    def unique_preserve_order(self, items):
        seen = set()
        output = []
        for item in list(items or []):
            if item in seen:
                continue
            seen.add(item)
            output.append(item)
        return output
