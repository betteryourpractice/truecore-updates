from TrueCoreIntel.detection.document_detector import DocumentDetector
from TrueCoreIntel.core.post_review_intelligence import PostReviewIntelligenceEngine
from TrueCoreIntel.extraction.extractor_engine import ExtractorEngine
from TrueCoreIntel.validation.validator_engine import ValidatorEngine
from TrueCoreIntel.intelligence.intelligence_engine import IntelligenceEngine
from TrueCoreIntel.review.review_engine import ReviewEngine
from TrueCoreIntel.learning.learning_engine import LearningEngine


class TrueCorePipeline:

    def __init__(self):
        self.detector = DocumentDetector()
        self.extractor = ExtractorEngine()
        self.validator = ValidatorEngine()
        self.intelligence = IntelligenceEngine()
        self.reviewer = ReviewEngine()
        self.post_reviewer = PostReviewIntelligenceEngine()
        self.learning = LearningEngine()

    def run(self, packet):
        packet.links["pipeline_stage_trace"] = []
        packet = self.detector.detect(packet)
        self.record_stage(packet, "detection")
        packet = self.extractor.extract(packet)
        self.record_stage(packet, "extraction")
        packet = self.validator.validate(packet)
        self.record_stage(packet, "validation")
        packet = self.intelligence.evaluate(packet)
        self.record_stage(packet, "intelligence")
        packet = self.reviewer.review(packet)
        self.record_stage(packet, "review")
        packet = self.post_reviewer.enrich(packet)
        self.record_stage(packet, "post_review_intelligence")
        packet = self.learning.learn(packet)
        self.record_stage(packet, "learning")

        packet.output["packet_label"] = self.build_packet_label(packet)
        packet.output["packet_score"] = packet.packet_score
        packet.output["packet_confidence"] = packet.packet_confidence
        packet.output["packet_strength"] = packet.packet_strength
        packet.output["approval_probability"] = packet.approval_probability
        packet.output["source_type"] = packet.source_type
        packet.output["detected_documents"] = sorted(packet.detected_documents)
        packet.output["fields"] = packet.fields
        packet.output["field_confidence"] = packet.field_confidence
        packet.output["field_mappings"] = packet.field_mappings
        packet.output["missing_fields"] = packet.missing_fields
        packet.output["missing_documents"] = packet.missing_documents
        packet.output["conflicts"] = packet.conflicts
        packet.output["review_flags"] = packet.review_flags
        packet.output["evidence_links"] = packet.evidence_links
        packet.output["links"] = packet.links
        packet.output["page_confidence"] = packet.page_confidence
        packet.output["duplicate_pages"] = packet.duplicate_pages
        packet.output["needs_review"] = packet.needs_review
        packet.output["review_priority"] = packet.review_priority
        packet.output["ocr_intake_summary"] = dict(getattr(packet, "intake_diagnostics", {}) or {})
        packet.output["scan_benchmark_scores"] = dict(getattr(packet, "benchmark_scores", {}) or {})
        packet.output["evidence_intelligence_1"] = dict(getattr(packet, "evidence_intelligence", {}) or {})
        packet.output["clinical_intelligence_1"] = dict(getattr(packet, "clinical_intelligence", {}) or {})
        packet.output["denial_intelligence_1"] = dict(getattr(packet, "denial_intelligence", {}) or {})
        packet.output["human_in_the_loop_intelligence_1"] = dict(getattr(packet, "human_loop_intelligence", {}) or {})
        packet.output["orchestration_intelligence_1"] = dict(getattr(packet, "orchestration_intelligence", {}) or {})
        packet.output["architecture_intelligence_1"] = dict(getattr(packet, "architecture_intelligence", {}) or {})
        packet.output["recovery_intelligence_1"] = dict(getattr(packet, "recovery_intelligence", {}) or {})
        packet.output["policy_intelligence_2"] = dict(getattr(packet, "policy_intelligence", {}) or {})
        packet.output["deployment_intelligence_1"] = dict(getattr(packet, "deployment_intelligence", {}) or {})
        packet.output["document_intelligence_2"] = dict(getattr(packet, "document_intelligence", {}) or {})
        packet.output["document_confidence_map"] = dict(getattr(packet, "document_confidence_map", {}) or {})
        packet.output["source_reliability_ranking"] = list(getattr(packet, "source_reliability_ranking", []) or [])
        packet.output["document_spans"] = list(getattr(packet, "document_spans", []) or [])
        packet.output["validation_intelligence_2"] = dict(getattr(packet, "validation_intelligence", {}) or {})
        packet.output["deep_verification_score"] = getattr(packet, "deep_verification_score", None)

        if "review_summary" not in packet.output:
            packet.output["review_summary"] = {
                "why_weak": [],
                "missing_items": [],
                "conflict_items": [],
                "fix_recommendations": [],
            }

        if "submission_readiness" not in packet.output:
            packet.output["submission_readiness"] = "needs_review"

        if "approval_rationale" not in packet.output:
            packet.output["approval_rationale"] = []

        return packet

    def record_stage(self, packet, stage_name):
        packet.links.setdefault("pipeline_stage_trace", [])
        packet.links["pipeline_stage_trace"].append({
            "stage": stage_name,
            "status": "completed",
            "detected_document_count": len(getattr(packet, "detected_documents", set()) or []),
            "field_count": len(getattr(packet, "fields", {}) or {}),
            "missing_field_count": len(getattr(packet, "missing_fields", []) or []),
            "missing_document_count": len(getattr(packet, "missing_documents", []) or []),
            "conflict_count": len(getattr(packet, "conflicts", []) or []),
            "review_flag_count": len(getattr(packet, "review_flags", []) or []),
            "output_key_count": len(getattr(packet, "output", {}) or {}),
            "packet_confidence": getattr(packet, "packet_confidence", None),
        })

    def build_packet_label(self, packet):
        name = str(packet.fields.get("name") or "unknown_patient").strip().replace(",", "")
        identifier = (
            packet.fields.get("authorization_number")
            or packet.fields.get("va_icn")
            or packet.fields.get("claim_number")
            or "no_identifier"
        )
        identifier = str(identifier).strip()
        return f"{name}_{identifier}".replace("/", "-")
