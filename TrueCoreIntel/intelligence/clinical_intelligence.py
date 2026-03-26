import re


class ClinicalIntelligenceAnalyzer:
    SEVERE_TERMS = {
        "weakness",
        "numbness",
        "tingling",
        "radiculopathy",
        "neurologic",
        "neurological",
        "progressive",
        "severe",
    }

    MODERATE_TERMS = {
        "pain",
        "limited range of motion",
        "restricted motion",
        "spasm",
        "degenerative",
        "disc",
        "osteoarthritis",
        "migraine",
    }

    CONSERVATIVE_CARE_PATTERNS = {
        "physical_therapy": r"\b(?:physical therapy|pt evaluation|pt\b|home exercise program|home exercises)\b",
        "nsaids": r"\b(?:ibuprofen|naproxen|meloxicam|motrin|aleve|anti-inflammatory|nsaid)\b",
        "neuropathic_medication": r"\b(?:gabapentin|pregabalin|lyrica)\b",
        "muscle_relaxant": r"\b(?:cyclobenzaprine|flexeril|muscle relaxant)\b",
        "pain_medication": r"\b(?:tramadol|acetaminophen|tylenol|lidocaine)\b",
        "injections": r"\b(?:injection|epidural|facet injection|trigger point)\b",
        "chiropractic": r"\b(?:chiropractic|chiropractor)\b",
        "activity_modification": r"\b(?:activity modification|rest|modified duty)\b",
    }

    SPECIALTY_HINTS = {
        "pain_management": {"pain management", "interventional pain", "disc seal"},
        "neurology": {"neurology", "neuro", "neurosciences"},
        "orthopedics": {"orthopedic", "ortho", "spine institute"},
        "physical_medicine": {"physical medicine", "pm&r", "physiatry", "rehabilitation"},
        "primary_care": {"primary care", "family medicine", "internal medicine"},
    }

    REGION_HINTS = {
        "lumbar": {"back", "lumbar", "lumbago", "radiculopathy", "sciatica", "low back"},
        "cervical": {"neck", "cervical"},
        "hip": {"hip"},
        "shoulder": {"shoulder"},
        "head": {"head", "migraine", "headache"},
    }

    def analyze(self, packet):
        packet_text = self.build_packet_text(packet)
        clinical_consistency = self.build_clinical_consistency_analysis(packet)
        severity = self.build_severity_inference_engine(packet, packet_text)
        treatment_progression = self.build_treatment_progression_modeling(packet, packet_text)
        conservative_care = self.build_conservative_care_verification(packet, packet_text)
        diagnostic_support = self.build_diagnostic_support_matching(packet)
        comorbidity_impact = self.build_comorbidity_impact_analysis(packet)
        medical_necessity = self.build_medical_necessity_framing_engine(
            packet,
            severity,
            conservative_care,
            diagnostic_support,
        )
        clinical_gaps = self.build_clinical_gap_detection(
            packet,
            severity,
            conservative_care,
            diagnostic_support,
        )
        specialty_alignment = self.build_specialty_alignment_validation(packet, packet_text)
        coherence = self.build_clinical_coherence_scoring(
            packet,
            clinical_consistency,
            severity,
            treatment_progression,
            conservative_care,
            diagnostic_support,
            clinical_gaps,
            specialty_alignment,
        )

        packet.clinical_intelligence = {
            "clinical_consistency_analysis": clinical_consistency,
            "severity_inference_engine": severity,
            "treatment_progression_modeling": treatment_progression,
            "conservative_care_verification": conservative_care,
            "diagnostic_support_matching": diagnostic_support,
            "comorbidity_impact_analysis": comorbidity_impact,
            "medical_necessity_framing_engine": medical_necessity,
            "clinical_gap_detection": clinical_gaps,
            "specialty_alignment_validation": specialty_alignment,
            "clinical_coherence_scoring": coherence,
        }
        return packet

    def build_clinical_consistency_analysis(self, packet):
        diagnosis = packet.fields.get("diagnosis")
        symptom = packet.fields.get("symptom")
        reason_for_request = packet.fields.get("reason_for_request")
        procedure = packet.fields.get("procedure")
        icd_codes = list(packet.fields.get("icd_codes", []) or [])

        diagnosis_regions = self.extract_regions(diagnosis)
        symptom_regions = self.extract_regions(symptom)
        reason_regions = self.extract_regions(reason_for_request)
        shared_regions = diagnosis_regions.intersection(reason_regions or diagnosis_regions).intersection(
            symptom_regions or diagnosis_regions
        )

        procedure_status = self.find_evidence_link_status(packet, "procedure_justification")
        diagnosis_icd_status = self.find_evidence_link_status(packet, "diagnosis_icd_support")

        concerns = []
        if diagnosis and not icd_codes:
            concerns.append("Diagnosis is present without ICD support.")
        if icd_codes and not diagnosis:
            concerns.append("ICD support is present without an extracted diagnosis.")
        if procedure and not reason_for_request:
            concerns.append("Procedure is present without a reason-for-request narrative.")
        if procedure_status == "weak":
            concerns.append("Requested procedure is only weakly supported by the current clinical picture.")
        if diagnosis_icd_status == "weak":
            concerns.append("Diagnosis and ICD support are clinically misaligned.")
        if packet.fields.get("diagnosis") and packet.fields.get("reason_for_request") and not shared_regions:
            concerns.append("Diagnosis and reason-for-request point to different body regions or conditions.")

        if concerns:
            status = "inconsistent" if len(concerns) >= 2 else "mixed"
        else:
            status = "consistent"

        return {
            "status": status,
            "diagnosis": diagnosis,
            "symptom": symptom,
            "procedure": procedure,
            "reason_for_request": reason_for_request,
            "diagnosis_icd_status": diagnosis_icd_status,
            "procedure_support_status": procedure_status,
            "shared_regions": sorted(shared_regions),
            "concerns": concerns,
        }

    def build_severity_inference_engine(self, packet, packet_text):
        indicators = []
        score = 0

        for term in sorted(self.SEVERE_TERMS):
            if term in packet_text:
                indicators.append(term)
                score += 2

        for term in sorted(self.MODERATE_TERMS):
            if term in packet_text:
                indicators.append(term)
                score += 1

        if packet.fields.get("procedure") == "MRI":
            score += 1
            indicators.append("mri_requested")

        if score >= 7:
            level = "high"
        elif score >= 4:
            level = "moderate"
        else:
            level = "mild"

        return {
            "level": level,
            "score": score,
            "indicators": sorted(set(indicators))[:10],
            "summary": {
                "high": "Clinical findings suggest a higher-severity case with stronger escalation signals.",
                "moderate": "Clinical findings suggest a moderate-severity case with meaningful documented symptoms.",
                "mild": "Clinical findings appear limited or lightly documented.",
            }.get(level),
        }

    def build_treatment_progression_modeling(self, packet, packet_text):
        conservative_hits = self.find_pattern_hits(packet_text, self.CONSERVATIVE_CARE_PATTERNS)
        has_advanced_imaging = bool(packet.fields.get("procedure") == "MRI" or re.search(r"\b(?:mri|ct|x-ray|xray)\b", packet_text))
        clinical_notes_present = "clinical_notes" in packet.detected_documents
        lomn_present = "lomn" in packet.detected_documents

        if has_advanced_imaging and conservative_hits:
            status = "logical_progression"
        elif has_advanced_imaging:
            status = "advanced_care_without_documented_progression"
        elif conservative_hits:
            status = "conservative_path_documented"
        else:
            status = "thin_progression"

        return {
            "status": status,
            "conservative_steps": sorted(conservative_hits),
            "advanced_diagnostics_present": has_advanced_imaging,
            "clinical_notes_present": clinical_notes_present,
            "lomn_present": lomn_present,
        }

    def build_conservative_care_verification(self, packet, packet_text):
        hits = self.find_pattern_hits(packet_text, self.CONSERVATIVE_CARE_PATTERNS)
        procedure = packet.fields.get("procedure")

        if hits and len(hits) >= 2:
            status = "verified"
        elif hits:
            status = "partial"
        elif procedure == "MRI":
            status = "not_documented"
        else:
            status = "not_applicable"

        return {
            "status": status,
            "documented_modalities": sorted(hits),
            "procedure_context": procedure,
            "summary": {
                "verified": "Conservative care appears documented before or alongside the current request.",
                "partial": "Some conservative care is documented, but the treatment history is not comprehensive.",
                "not_documented": "Advanced care is requested without clear conservative-care support.",
                "not_applicable": "Conservative care verification is not strongly indicated from the current packet.",
            }.get(status),
        }

    def build_diagnostic_support_matching(self, packet):
        diagnosis = packet.fields.get("diagnosis")
        symptom = packet.fields.get("symptom")
        procedure = packet.fields.get("procedure")
        reason_for_request = packet.fields.get("reason_for_request")
        icd_codes = list(packet.fields.get("icd_codes", []) or [])

        diagnosis_icd_status = self.find_evidence_link_status(packet, "diagnosis_icd_support")
        procedure_status = self.find_evidence_link_status(packet, "procedure_justification")

        support_signals = []
        gaps = []

        if diagnosis:
            support_signals.append(f"Diagnosis present: {diagnosis}.")
        else:
            gaps.append("Add diagnosis language that explains the clinical problem.")

        if symptom:
            support_signals.append(f"Symptom present: {symptom}.")
        else:
            gaps.append("Add symptom detail showing how the condition presents clinically.")

        if icd_codes:
            support_signals.append(f"ICD support present: {', '.join(icd_codes)}.")
        else:
            gaps.append("Add ICD support aligned to the diagnosis.")

        if reason_for_request:
            support_signals.append("Reason-for-request narrative is present.")
        else:
            gaps.append("Add a reason-for-request statement tied to the diagnosis and procedure.")

        if procedure and procedure_status == "weak":
            gaps.append("Requested procedure needs stronger clinical justification.")

        if diagnosis_icd_status == "weak":
            gaps.append("Diagnosis and ICD coding should align more tightly.")

        if not gaps:
            status = "aligned"
        elif len(gaps) <= 2:
            status = "partial"
        else:
            status = "weak"

        return {
            "status": status,
            "procedure": procedure,
            "diagnosis_icd_status": diagnosis_icd_status,
            "procedure_support_status": procedure_status,
            "support_signals": support_signals,
            "gaps": gaps,
        }

    def build_comorbidity_impact_analysis(self, packet):
        diagnosis = str(packet.fields.get("diagnosis") or "").strip()
        reason_for_request = str(packet.fields.get("reason_for_request") or "").strip()
        icd_codes = list(packet.fields.get("icd_codes", []) or [])

        reason_chunks = [
            part.strip()
            for part in re.split(r"[,;/]|\band\b", reason_for_request.lower())
            if part.strip()
        ]
        code_families = sorted({str(code).split(".")[0] for code in icd_codes if code})

        related_conditions = []
        for chunk in reason_chunks:
            if diagnosis and chunk in diagnosis.lower():
                continue
            related_conditions.append(chunk)

        if len(code_families) >= 3 or len(related_conditions) >= 3:
            status = "complex"
        elif len(code_families) >= 2 or len(related_conditions) >= 2:
            status = "multi_factor"
        else:
            status = "focused"

        return {
            "status": status,
            "diagnosis": diagnosis or None,
            "icd_families": code_families,
            "related_conditions": related_conditions[:6],
            "impact_summary": {
                "complex": "Multiple conditions or coding families may complicate the clinical case.",
                "multi_factor": "Related conditions add context and may strengthen or complicate the request.",
                "focused": "The case appears clinically focused around a narrow problem set.",
            }.get(status),
        }

    def build_medical_necessity_framing_engine(self, packet, severity, conservative_care, diagnostic_support):
        framing_points = []

        if packet.fields.get("diagnosis"):
            framing_points.append(f"Documented diagnosis supports the request: {packet.fields['diagnosis']}.")
        if packet.fields.get("symptom"):
            framing_points.append(f"Symptoms are documented: {packet.fields['symptom']}.")
        if packet.fields.get("reason_for_request"):
            framing_points.append("A reason-for-request narrative connects the clinical problem to the requested care.")
        if conservative_care.get("status") in {"verified", "partial"}:
            framing_points.append("Conservative care appears documented in the packet.")
        if severity.get("level") in {"high", "moderate"}:
            framing_points.append(f"Severity indicators suggest a {severity['level']}-severity presentation.")
        if packet.fields.get("procedure") == "MRI":
            framing_points.append("Advanced imaging is being requested, which benefits from strong documented findings and treatment history.")

        necessity_strength = "strong" if len(framing_points) >= 5 else "moderate" if len(framing_points) >= 3 else "weak"

        return {
            "necessity_strength": necessity_strength,
            "framing_points": framing_points[:6],
            "recommended_language": diagnostic_support.get("support_signals", [])[:4],
        }

    def build_clinical_gap_detection(self, packet, severity, conservative_care, diagnostic_support):
        gaps = []

        if not packet.fields.get("diagnosis"):
            gaps.append("Missing diagnosis detail.")
        if not packet.fields.get("symptom"):
            gaps.append("Missing symptom detail.")
        if not packet.fields.get("reason_for_request"):
            gaps.append("Missing reason-for-request narrative.")
        if not packet.fields.get("icd_codes"):
            gaps.append("Missing ICD support.")
        if "clinical_notes" not in packet.detected_documents:
            gaps.append("Missing clinical notes.")
        if "lomn" not in packet.detected_documents and packet.fields.get("procedure"):
            gaps.append("Missing Letter of Medical Necessity.")
        if conservative_care.get("status") == "not_documented":
            gaps.append("No documented conservative care supporting the advanced request.")
        if severity.get("level") == "high" and not any(
            keyword in str(packet.fields.get("symptom") or "").lower()
            for keyword in ("weakness", "numbness", "tingling")
        ):
            gaps.append("Neurologic deficit detail may be missing despite higher-severity indicators.")

        return {
            "gap_count": len(gaps),
            "gaps": gaps,
            "status": "minimal" if len(gaps) <= 1 else "moderate" if len(gaps) <= 3 else "significant",
            "diagnostic_support_status": diagnostic_support.get("status"),
        }

    def build_specialty_alignment_validation(self, packet, packet_text):
        clinic_name = str(packet.fields.get("clinic_name") or "").lower()
        specialty_source = f"{clinic_name} {packet_text}"
        inferred_specialties = []

        for specialty, hints in self.SPECIALTY_HINTS.items():
            if any(hint in specialty_source for hint in hints):
                inferred_specialties.append(specialty)

        diagnosis_regions = self.extract_regions(packet.fields.get("diagnosis"))
        procedure = packet.fields.get("procedure")

        expected_specialties = set()
        if diagnosis_regions.intersection({"lumbar", "cervical", "hip", "shoulder"}):
            expected_specialties.update({"pain_management", "orthopedics", "physical_medicine"})
        if diagnosis_regions.intersection({"head"}):
            expected_specialties.add("neurology")
        if procedure == "MRI":
            expected_specialties.update({"pain_management", "orthopedics", "neurology"})

        inferred_set = set(inferred_specialties)

        if inferred_set and expected_specialties and inferred_set.intersection(expected_specialties):
            status = "aligned"
        elif inferred_set and expected_specialties:
            status = "partial"
        elif inferred_set:
            status = "inferred_only"
        else:
            status = "unknown"

        return {
            "status": status,
            "inferred_specialties": sorted(inferred_set),
            "expected_specialties": sorted(expected_specialties),
            "clinic_name": packet.fields.get("clinic_name"),
        }

    def build_clinical_coherence_scoring(
        self,
        packet,
        clinical_consistency,
        severity,
        treatment_progression,
        conservative_care,
        diagnostic_support,
        clinical_gaps,
        specialty_alignment,
    ):
        score = 68
        drivers = []

        consistency_status = clinical_consistency.get("status")
        if consistency_status == "consistent":
            score += 10
            drivers.append("Diagnosis, symptoms, and request are clinically consistent.")
        elif consistency_status == "mixed":
            score -= 6
            drivers.append("Clinical consistency is only partial.")
        else:
            score -= 12
            drivers.append("Clinical evidence is inconsistent.")

        if diagnostic_support.get("status") == "aligned":
            score += 10
            drivers.append("Diagnostic support is aligned with the request.")
        elif diagnostic_support.get("status") == "partial":
            score += 2
        else:
            score -= 10
            drivers.append("Diagnostic support remains weak.")

        if conservative_care.get("status") == "verified":
            score += 8
        elif conservative_care.get("status") == "partial":
            score += 2
        elif conservative_care.get("status") == "not_documented":
            score -= 12
            drivers.append("Conservative care is not documented for the requested escalation.")

        if treatment_progression.get("status") == "logical_progression":
            score += 6
        elif treatment_progression.get("status") == "advanced_care_without_documented_progression":
            score -= 8
            drivers.append("Treatment progression looks incomplete for the requested care.")

        if specialty_alignment.get("status") == "aligned":
            score += 3
        elif specialty_alignment.get("status") == "partial":
            score -= 2

        gap_penalty = min(clinical_gaps.get("gap_count", 0) * 4, 20)
        if gap_penalty:
            score -= gap_penalty
            drivers.append("Clinical gaps reduce the overall coherence of the packet.")

        if severity.get("level") == "high" and packet.fields.get("procedure") == "MRI":
            score += 3

        score = max(0, min(int(round(score)), 100))
        return {
            "score": score,
            "band": "high" if score >= 82 else "moderate" if score >= 62 else "low",
            "drivers": drivers[:6],
        }

    def build_packet_text(self, packet):
        text = "\n".join(str(page or "") for page in (packet.pages or []))
        text = text.lower()
        text = re.sub(r"\s+", " ", text)
        return text

    def find_pattern_hits(self, packet_text, patterns):
        hits = set()
        for label, pattern in patterns.items():
            if re.search(pattern, packet_text, re.IGNORECASE):
                hits.add(label)
        return hits

    def find_evidence_link_status(self, packet, link_type):
        for link in packet.evidence_links:
            if link.get("type") == link_type:
                return link.get("status")
        return None

    def extract_regions(self, text):
        normalized = str(text or "").lower()
        normalized = re.sub(r"[^a-z0-9 ]", " ", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()

        if not normalized:
            return set()

        regions = set()
        for region, hints in self.REGION_HINTS.items():
            if any(hint in normalized for hint in hints):
                regions.add(region)
        return regions
