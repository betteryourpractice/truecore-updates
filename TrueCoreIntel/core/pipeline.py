from TrueCoreIntel.detection.document_detector import DocumentDetector
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
        self.learning = LearningEngine()

    def run(self, packet):
        packet = self.detector.detect(packet)
        packet = self.extractor.extract(packet)
        packet = self.validator.validate(packet)
        packet = self.intelligence.evaluate(packet)
        packet = self.reviewer.review(packet)
        packet = self.learning.learn(packet)

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
