from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ReviewSummaryArtifacts:
    why_weak: list[str]
    missing_items: list[str]
    conflict_items: list[str]
    fix_recommendations: list[str]
    prioritized_fixes: list[dict]


class ReviewSummaryBuilder:
    def __init__(self, high_priority_fields, medium_priority_fields):
        self.high_priority_fields = set(high_priority_fields or set())
        self.medium_priority_fields = set(medium_priority_fields or set())

    def build(self, packet) -> ReviewSummaryArtifacts:
        why_weak = []
        missing_items = []
        conflict_items = []
        fix_recommendations = []
        semantic = dict(getattr(packet, "semantic_adjudication", {}) or {})
        tolerated_conflict_fields = {
            str(item.get("field") or "").strip().lower()
            for item in list(semantic.get("tolerated_conflicts", []) or [])
            if item.get("field")
        }

        prioritized_fixes = self.build_prioritized_fixes(packet)

        if packet.missing_fields:
            high_missing = [field for field in packet.missing_fields if field in self.high_priority_fields]
            medium_missing = [field for field in packet.missing_fields if field in self.medium_priority_fields]
            low_missing = [
                field
                for field in packet.missing_fields
                if field not in self.high_priority_fields and field not in self.medium_priority_fields
            ]

            if high_missing:
                why_weak.append(
                    f"Critical required fields are missing: {', '.join(sorted(high_missing))}."
                )

            if medium_missing:
                why_weak.append(
                    f"Important clinical/review fields are missing: {', '.join(sorted(medium_missing))}."
                )

            if low_missing:
                why_weak.append(
                    f"Additional required fields are missing: {', '.join(sorted(low_missing))}."
                )

            for field in packet.missing_fields:
                missing_items.append(f"Missing required field: {field}.")
                fix_recommendations.append(f"Add or verify {field} in the packet.")

        if packet.missing_documents:
            sorted_docs = sorted(packet.missing_documents)
            why_weak.append(
                f"Required supporting documents are missing ({len(sorted_docs)}): {', '.join(sorted_docs)}."
            )

            for doc in sorted_docs:
                missing_items.append(f"Missing required document: {doc}.")
                fix_recommendations.append(f"Attach required document: {doc}.")

        if packet.conflicts:
            effective_conflicts = [
                conflict
                for conflict in packet.conflicts
                if str(conflict.get("field", "")).strip().lower() not in tolerated_conflict_fields
                or str(conflict.get("severity") or "").strip().lower() == "high"
            ]
            high_conflicts = [c.get("field", "unknown_field") for c in effective_conflicts if c.get("severity") == "high"]
            medium_conflicts = [c.get("field", "unknown_field") for c in effective_conflicts if c.get("severity") == "medium"]
            low_conflicts = [c.get("field", "unknown_field") for c in effective_conflicts if c.get("severity") == "low"]

            if high_conflicts:
                why_weak.append(
                    f"High-severity conflicts were found: {', '.join(sorted(set(high_conflicts)))}."
                )

            if medium_conflicts:
                why_weak.append(
                    f"Moderate conflicts were found: {', '.join(sorted(set(medium_conflicts)))}."
                )

            if low_conflicts:
                why_weak.append(
                    f"Low-severity conflicts were found: {', '.join(sorted(set(low_conflicts)))}."
                )

            for conflict in effective_conflicts:
                message = conflict.get("message", f"Conflict detected for {conflict.get('field', 'unknown_field')}.")
                conflict_items.append(message)
                fix_recommendations.append(
                    f"Resolve conflicting values for {conflict.get('field', 'unknown_field')}."
                )

        review_flags = set(packet.review_flags)

        if "weak_mri_justification" in review_flags:
            why_weak.append("MRI request has weak clinical justification.")
            fix_recommendations.append("Add clearer diagnosis or symptom support for MRI necessity.")

        if "moderate_mri_justification" in review_flags:
            why_weak.append("MRI request has only moderate clinical justification.")
            fix_recommendations.append("Strengthen the clinical rationale supporting MRI necessity.")

        if "procedure_without_medical_support" in review_flags:
            why_weak.append("Requested procedure is not supported by diagnosis or symptom evidence.")
            fix_recommendations.append("Add clinical documentation supporting the requested procedure.")

        if "diagnosis_without_icd_support" in review_flags:
            why_weak.append("Diagnosis is present without corresponding ICD support.")
            fix_recommendations.append("Add supporting ICD codes for the stated diagnosis.")

        if "icd_without_diagnosis_support" in review_flags:
            why_weak.append("ICD codes are present without clear diagnosis language.")
            fix_recommendations.append("Add diagnosis language matching the ICD codes.")

        if "diagnosis_icd_mismatch" in review_flags:
            why_weak.append("Diagnosis and ICD coding do not appear clinically aligned.")
            fix_recommendations.append("Correct the diagnosis language or update ICD coding so they match.")

        if "missing_reason_for_request" in review_flags and "reason_for_request" not in packet.missing_fields:
            why_weak.append("Reason for request is missing or unclear.")
            fix_recommendations.append("Add a clear reason for request or referral statement.")

        if "packet_integrity_risk" in review_flags:
            why_weak.append("Packet may contain mixed patient or case identifiers.")
            fix_recommendations.append("Confirm that all pages belong to the same veteran and case.")

        if "chronology_review_needed" in review_flags:
            why_weak.append("Service dates appear out of sequence or need chronology review.")
            fix_recommendations.append("Verify the service date range and correct reversed dates.")

        if "duplicate_pages_present" in review_flags:
            why_weak.append("Packet contains duplicate or repeated pages.")
            fix_recommendations.append("Remove repeated pages to keep the submission clean.")

        if packet.packet_strength == "weak":
            why_weak.append("Overall packet strength is weak based on missing support, conflicts, and justification gaps.")

        for note in list(semantic.get("review_notes", []) or []):
            if "hard defects" in str(note).lower():
                why_weak.append(str(note).strip())

        return ReviewSummaryArtifacts(
            why_weak=self.compress_why_weak(why_weak),
            missing_items=self.unique_preserve_order(missing_items),
            conflict_items=self.unique_preserve_order(conflict_items),
            fix_recommendations=self.unique_preserve_order(fix_recommendations),
            prioritized_fixes=prioritized_fixes,
        )

    def compress_why_weak(self, reasons):
        if not reasons:
            return []

        grouped = {
            "critical": [],
            "clinical": [],
            "documents": [],
            "conflicts": [],
            "other": [],
        }

        for reason in reasons:
            reason_lower = reason.lower()
            if "critical" in reason_lower or "missing required field" in reason_lower:
                grouped["critical"].append(reason)
            elif "clinical" in reason_lower or "diagnosis" in reason_lower or "mri" in reason_lower:
                grouped["clinical"].append(reason)
            elif "document" in reason_lower:
                grouped["documents"].append(reason)
            elif "conflict" in reason_lower:
                grouped["conflicts"].append(reason)
            else:
                grouped["other"].append(reason)

        ordered = (
            grouped["critical"]
            + grouped["clinical"]
            + grouped["documents"]
            + grouped["conflicts"]
            + grouped["other"]
        )

        seen = set()
        deduped = []
        for item in ordered:
            if item not in seen:
                seen.add(item)
                deduped.append(item)

        return deduped[:5]

    def build_prioritized_fixes(self, packet):
        fixes = []
        semantic = dict(getattr(packet, "semantic_adjudication", {}) or {})
        tolerated_conflict_fields = {
            str(item.get("field") or "").strip().lower()
            for item in list(semantic.get("tolerated_conflicts", []) or [])
            if item.get("field")
        }

        for field in packet.missing_fields:
            fixes.append({
                "priority": self.get_field_priority(field),
                "type": "missing_field",
                "target": field,
                "action": f"Add or verify {field}.",
            })

        missing_docs = sorted(packet.missing_documents)
        if missing_docs:
            if len(missing_docs) <= 2:
                for doc in missing_docs:
                    fixes.append({
                        "priority": "medium",
                        "type": "missing_document",
                        "target": doc,
                        "action": f"Attach required document: {doc}.",
                    })
            else:
                fixes.append({
                    "priority": "medium",
                    "type": "missing_document_bundle",
                    "target": "required_documents",
                    "action": f"Attach missing required documents ({len(missing_docs)}): {', '.join(missing_docs)}.",
                })

        for conflict in packet.conflicts:
            field_name = str(conflict.get("field", "unknown_field")).strip().lower()
            severity = str(conflict.get("severity") or "").strip().lower()
            if field_name in tolerated_conflict_fields and severity in {"low", "medium"}:
                continue
            fixes.append({
                "priority": conflict.get("severity", "low"),
                "type": "conflict",
                "target": conflict.get("field", "unknown_field"),
                "action": f"Resolve conflicting values for {conflict.get('field', 'unknown_field')}.",
            })

        review_flags = set(packet.review_flags)

        if "procedure_without_medical_support" in review_flags:
            fixes.append({
                "priority": "high",
                "type": "medical_support",
                "target": "procedure_support",
                "action": "Add clinical documentation supporting the requested procedure.",
            })
        elif "weak_mri_justification" in review_flags:
            fixes.append({
                "priority": "medium",
                "type": "medical_support",
                "target": "mri_justification",
                "action": "Add clearer diagnosis or symptom support for MRI necessity.",
            })
        elif "moderate_mri_justification" in review_flags:
            fixes.append({
                "priority": "low",
                "type": "medical_support",
                "target": "mri_justification",
                "action": "Strengthen the clinical rationale supporting MRI necessity.",
            })

        if "diagnosis_icd_mismatch" in review_flags:
            fixes.append({
                "priority": "medium",
                "type": "clinical_alignment",
                "target": "diagnosis_icd_alignment",
                "action": "Correct the diagnosis language or update ICD coding so they match.",
            })

        if "diagnosis_without_icd_support" in review_flags:
            fixes.append({
                "priority": "medium",
                "type": "clinical_alignment",
                "target": "diagnosis_icd_alignment",
                "action": "Add supporting ICD codes for the stated diagnosis.",
            })

        if "icd_without_diagnosis_support" in review_flags:
            fixes.append({
                "priority": "medium",
                "type": "clinical_alignment",
                "target": "diagnosis_icd_alignment",
                "action": "Add diagnosis language matching the ICD codes.",
            })

        if "reason_for_request" in packet.missing_fields or "missing_reason_for_request" in review_flags:
            fixes.append({
                "priority": "medium",
                "type": "missing_field",
                "target": "reason_for_request",
                "action": "Add a clear reason for request or referral statement.",
            })

        if "packet_integrity_risk" in review_flags:
            fixes.append({
                "priority": "high",
                "type": "packet_integrity",
                "target": "packet_identity",
                "action": "Confirm all packet pages belong to the same veteran and case.",
            })

        if "chronology_review_needed" in review_flags:
            fixes.append({
                "priority": "medium",
                "type": "chronology",
                "target": "service_date_range",
                "action": "Correct or verify the service date range chronology.",
            })

        if "duplicate_pages_present" in review_flags:
            fixes.append({
                "priority": "low",
                "type": "packet_cleanup",
                "target": "duplicate_pages",
                "action": "Remove duplicate or repeated packet pages.",
            })

        priority_order = {"high": 0, "medium": 1, "low": 2}
        fixes.sort(key=lambda item: (priority_order.get(item["priority"], 3), item["target"]))

        deduped = []
        seen = set()
        for item in fixes:
            key = (item["type"], item["target"])
            if key not in seen:
                seen.add(key)
                deduped.append(item)

        return deduped[:6]

    def get_field_priority(self, field):
        if field in self.high_priority_fields:
            return "high"
        if field in self.medium_priority_fields:
            return "medium"
        return "low"

    @staticmethod
    def unique_preserve_order(items):
        seen = set()
        output = []
        for item in list(items or []):
            if item in seen:
                continue
            seen.add(item)
            output.append(item)
        return output
