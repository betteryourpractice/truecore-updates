class Packet:

    def __init__(self):
        # Raw input
        self.files = []
        self.pages = []
        self.page_sources = []
        self.source_type = None

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
        self.identity_fields = {
            "name": [],
            "dob": [],
            "provider": [],
            "ordering_provider": [],
            "referring_provider": [],
            "va_icn": [],
            "claim_number": [],
        }

        # Metadata
        self.page_confidence = {}

        # Relationships
        self.links = {}
        self.evidence_links = []
        self.duplicate_pages = []

        # Validation
        self.missing_fields = []
        self.conflicts = []

        # Intelligence
        self.packet_score = None
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
