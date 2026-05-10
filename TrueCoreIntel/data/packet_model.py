class Packet:

    def __init__(self):
        # Raw input
        self.files = []
        self.pages = []
        self.page_sources = []
        self.page_metadata = []
        self.source_type = None
        self.ocr_provider = None
        self.intake_diagnostics = {}
        self.benchmark_scores = {}

        # Detection
        self.document_types = {}
        self.detected_documents = set()
        self.missing_documents = []
        self.unfilled_documents = set()

        # Extraction
        self.fields = {}
        self.field_sources = {}
        self.field_mappings = {}
        self.field_confidence = {}
        self.field_values = {}
        self.field_observations = {}
        self.suspect_fields = {}
        self.template_markers = []
        self.identity_fields = {
            "name": [],
            "dob": [],
            "provider": [],
            "treating_provider": [],
            "followup_provider": [],
            "ordering_provider": [],
            "referring_provider": [],
            "va_icn": [],
            "claim_number": [],
        }

        # Metadata
        self.page_confidence = {}
        self.document_intelligence = {}
        self.document_confidence_map = {}
        self.source_reliability_ranking = []
        self.document_spans = []
        self.section_roles = {}

        # Relationships
        self.links = {}
        self.evidence_links = []
        self.duplicate_pages = []

        # Validation
        self.missing_fields = []
        self.conflicts = []
        self.validation_intelligence = {}
        self.deep_verification_score = None

        # Intelligence
        self.evidence_intelligence = {}
        self.clinical_intelligence = {}
        self.denial_intelligence = {}
        self.human_loop_intelligence = {}
        self.orchestration_intelligence = {}
        self.architecture_intelligence = {}
        self.recovery_intelligence = {}
        self.policy_intelligence = {}
        self.deployment_intelligence = {}
        self.packet_score = None
        self.packet_evidence_score = None
        self.packet_evidence_band = None
        self.packet_assembly_score = None
        self.packet_assembly_band = None
        self.packet_profile = None
        self.packet_profile_label = None
        self.packet_archetype = None
        self.packet_archetype_label = None
        self.packet_archetype_description = None
        self.packet_archetype_signals = []
        self.packet_invariants = {}
        self.packet_invariant_coverage_score = None
        self.packet_invariant_coverage_band = None
        self.packet_variability = {}
        self.packet_format_variability = None
        self.packet_variability_reasons = []
        self.packet_failure_modes = []
        self.packet_failure_mode_labels = []
        self.packet_failure_mode_summaries = []
        self.packet_classification_caution = False
        self.packet_confidence_penalty = 0.0
        self.packet_strength = None
        self.approval_probability = None
        self.packet_confidence = None

        # Review
        self.needs_review = False
        self.review_flags = []
        self.review_priority = None

        # Learning
        self.corrections = []
        self.metrics = {}

        # Output
        self.output = {}
