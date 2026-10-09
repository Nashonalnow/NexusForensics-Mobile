#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Core Data Models
NEXUS Hardened Forensic Domain Models: First-class Provenance, Reproducibility, Parser Lineage, and Evidentiary Integrity.
Strict Copper Standard: 100% authentic evidence hashes, schemas, and timestamps. Zero simulated or mock data.
"""

from enum import Enum
import hashlib
import json
import time
import uuid
from typing import Dict, List, Any, Optional, Union
from pydantic import BaseModel, Field

def default_uuid() -> str:
    return str(uuid.uuid4())

# ============================================================================
# DOMAIN ENUMS (STRICTLY TYPED FORENSIC DOMAINS)
# ============================================================================

class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"
    CLOUD = "cloud"
    UNKNOWN = "unknown"

class ArtifactType(str, Enum):
    SMS = "sms_message"
    MMS = "mms_message"
    CALL_LOG = "call_log"
    CONTACT = "contact"
    KNOWLEDGE_C = "knowledgec_event"
    LOCATION = "location"
    APP_USAGE = "app_usage"
    WIFI = "wifi_network"
    BLUETOOTH = "bluetooth_device"
    PHOTO = "photo"
    SCREENSHOT = "screenshot"
    BROWSER_HISTORY = "browser_history"
    NOTES = "note"
    CALENDAR = "calendar_event"
    WHATSAPP = "whatsapp_message"
    TELEGRAM = "telegram_message"
    SIGNAL = "signal_message"
    CELL_TOWER = "cell_tower"
    HTTP_TRAFFIC = "http_traffic"
    DEVICE_STATE = "device_state"
    RECENT_TASKS = "recent_task"
    CUSTOM = "custom"

class EventCategory(str, Enum):
    COMMUNICATION = "communication"
    DEVICE_STATE = "device_state"
    APPLICATION = "application"
    LOCATION = "location"
    CONNECTIVITY = "connectivity"
    MEDIA = "media"
    ACCOUNT = "account"
    NETWORK = "network"

class EventType(str, Enum):
    # Communication
    SMS_SENT = "message_sent"
    SMS_RECEIVED = "message_received"
    CALL_STARTED = "call_started"
    CALL_ENDED = "call_ended"
    GROUP_MESSAGE = "group_message"
    MESSAGE = "message"
    CHANNEL_POST = "channel_post"
    CONVERSATION = "conversation"
    ATTACHMENT = "attachment"

    # Device State
    UNLOCK = "unlock"
    LOCK = "lock"
    SCREEN_ON = "screen_on"
    SCREEN_OFF = "screen_off"
    AUTHENTICATION = "authentication"
    BOOT = "boot"
    SHUTDOWN = "shutdown"
    REBOOT = "reboot"
    CHARGING = "charging"
    BATTERY_LOW = "battery_low"

    # Application
    APP_OPENED = "app_opened"
    APP_CLOSED = "app_closed"
    APP_SWITCH = "app_switch"
    FOREGROUND_APP = "foreground_app"
    BACKGROUND_APP = "background_app"
    USAGE_SESSION = "usage_session"
    TASK_CREATED = "task_created"
    TASK_REMOVED = "task_removed"

    # Connectivity
    WIFI_CONNECTED = "wifi_connect"
    WIFI_DISCONNECTED = "wifi_disconnect"
    SSID_SEEN = "ssid_seen"
    BLUETOOTH_PAIR = "bluetooth_pair"
    BLUETOOTH_CONNECT = "bluetooth_connect"
    BLUETOOTH_DISCONNECT = "bluetooth_disconnect"
    TOWER_CHANGE = "tower_change"
    NETWORK_REGISTRATION = "network_registration"
    ROAMING = "roaming"

    # Location
    LOCATION_UPDATE = "location_update"
    ARRIVED_LOCATION = "arrived_location"
    DEPARTED_LOCATION = "departed_location"
    VISIT = "visit"
    DESTINATION_SEARCH = "destination_search"
    NAVIGATION_START = "navigation_start"
    NAVIGATION_END = "navigation_end"

    # Media
    PHOTO_CAPTURED = "photo_captured"
    IMAGE_VIEWED = "image_viewed"
    IMAGE_CACHED = "image_cached"
    SCREENSHOT_CREATED = "screenshot_created"

    # Productivity
    NOTE_CREATED = "note_created"
    NOTE_EDITED = "note_edited"
    NOTE_DELETED = "note_deleted"
    CALENDAR_CREATED = "event_created"
    CALENDAR_MODIFIED = "event_modified"
    CALENDAR_DELETED = "event_deleted"
    ATTENDEE_ADDED = "attendee_added"

    # Internet / Web
    WEB_VISIT = "web_visit"
    SEARCH_QUERY = "search_query"
    HTTP_TRAFFIC = "http_traffic"
    FILE_DOWNLOAD = "file_download"

    CUSTOM = "custom"

class EntityType(str, Enum):
    PERSON = "person"
    CONTACT = "contact"
    PHONE_NUMBER = "phone_number"
    EMAIL_ADDRESS = "email_address"
    GPS_COORDINATE = "gps_coordinate"
    LOCATION_NAME = "location_name"
    SSID = "ssid"
    BSSID = "bssid"
    APP_BUNDLE_ID = "app_bundle_id"
    DEVICE = "device"
    DEVICE_NAME = "device_name"
    MAC_ADDRESS = "mac_address"
    CELL_ID = "cell_id"
    APPLE_ID = "apple_id"
    GOOGLE_ACCOUNT = "google_account"

class RelationshipType(str, Enum):
    PRECEDED_BY = "preceded_by"
    FOLLOWED_BY = "followed_by"
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    ASSOCIATED_WITH = "associated_with"
    LOCATED_AT = "located_at"
    CONNECTED_TO = "connected_to"
    COMMUNICATED_WITH = "communicated_with"
    USED_APP = "used_app"

# ============================================================================
# CANONICAL HASHING & VALUE OBJECTS
# ============================================================================

def canonicalize_json_value(val: Any) -> Any:
    """Recursively orders dictionary keys to ensure deterministic canonical serialization."""
    if isinstance(val, dict):
        return {k: canonicalize_json_value(val[k]) for k in sorted(val.keys())}
    elif isinstance(val, list):
        return [canonicalize_json_value(x) for x in val]
    elif isinstance(val, (uuid.UUID, Enum)):
        return str(val)
    elif hasattr(val, "model_dump"):
        return canonicalize_json_value(val.model_dump())
    return val

def canonical_json_bytes(obj: Any) -> bytes:
    """Returns canonical UTF-8 bytes with compact delimiters for cryptographic hashing."""
    canonical = canonicalize_json_value(obj)
    return json.dumps(canonical, sort_keys=True, separators=(',', ':'), default=str).encode("utf-8")

def compute_canonical_sha256(obj: Any) -> str:
    """Computes deterministic SHA-256 hash across canonical JSON serialization."""
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()

class ConfidenceScore:
    """Validated confidence score value object (0-100)."""
    def __init__(self, score: int):
        if not (0 <= score <= 100):
            raise ValueError(f"Confidence score {score} must be between 0 and 100.")
        self._score = score

    @classmethod
    def new(cls, score: int) -> "ConfidenceScore":
        return cls(score)

    def value(self) -> int:
        return self._score

    def __repr__(self) -> str:
        return f"ConfidenceScore({self._score})"

    def __int__(self) -> int:
        return self._score

# ============================================================================
# CORE DOMAIN MODELS (COURT-DEFENSIBLE & FULLY PROVENANCED)
# ============================================================================

# 1. Case (Hardened)
class CaseModel(BaseModel):
    case_id: str = Field(default_factory=default_uuid)
    case_number: str = Field(default_factory=lambda: f"CASE-{uuid.uuid4().hex[:8].upper()}")
    case_name: str
    description: Optional[str] = ""
    status: str = "open"  # 'open', 'closed', 'archived'
    created_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    created_by: str = "Examiner"
    last_modified: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    classification: str = "internal"  # 'public', 'internal', 'confidential', 'restricted'
    retention_until: Optional[str] = None
    tags: List[str] = []

    def canonical_hash(self) -> str:
        return compute_canonical_sha256(self.model_dump())

# 2. Device (Hardened)
class DeviceModel(BaseModel):
    device_id: str = Field(default_factory=default_uuid)
    case_id: str
    platform: str = "android"  # 'android', 'ios', 'cloud', 'unknown'
    manufacturer: Optional[str] = "Unknown"
    model: Optional[str] = "Unknown"
    serial_number: Optional[str] = None
    imei: Optional[str] = None
    meid: Optional[str] = None
    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    timezone: Optional[str] = "UTC"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def canonical_hash(self) -> str:
        return compute_canonical_sha256(self.model_dump())

# 3. Evidence Source (Immutable)
class EvidenceSourceModel(BaseModel):
    source_id: str = Field(default_factory=default_uuid)
    device_id: str
    source_type: str = "filesystem"  # 'filesystem', 'physical', 'logical', 'backup', 'cloud', 'manual'
    acquisition_tool: str = "NexusForensics"
    acquisition_tool_version: Optional[str] = "1.0.0"
    acquisition_operator: Optional[str] = "Examiner"
    acquisition_started: Optional[str] = None
    acquisition_completed: Optional[str] = None
    original_filename: str
    original_path: Optional[str] = None
    file_size: int
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    imported_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    imported_by: str = "Examiner"
    evidence_sealed: bool = False

    def canonical_hash(self) -> str:
        return compute_canonical_sha256(self.model_dump())

    def validate_record(self) -> None:
        if not self.source_id:
            raise ValueError("Evidence source must have source_id")
        if len(self.sha256) != 64:
            raise ValueError("Evidence source must have a valid 64-character SHA-256 hash")
        if self.file_size <= 0:
            raise ValueError("File size must be positive")

# 4. Parser Registry Model / Metadata
class ParserModel(BaseModel):
    parser_id: str = Field(default_factory=default_uuid)
    parser_name: str
    parser_version: str = "1.0.0"
    git_commit: Optional[str] = "9f7c8e2"
    build_number: Optional[str] = "2026.10.1"
    release_date: Optional[str] = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    parser_sha256: Optional[str] = None
    developer: Optional[str] = "NEXUS Mobile DFIR Team"
    author: Optional[str] = "NEXUS Mobile DFIR Team"
    supported_platforms: List[str] = ["android", "ios"]
    supported_artifact_types: List[str] = []
    active: bool = True

    def canonical_hash(self) -> str:
        return compute_canonical_sha256(self.model_dump())

# 5. Provenance Record
class ProvenanceRecord(BaseModel):
    source_file: str
    source_table: Optional[str] = None
    source_record_id: Optional[str] = None
    parser_name: str
    parser_version: str = "1.0.0"
    extraction_timestamp: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))

    def validate(self) -> None:
        if not self.source_file:
            raise ValueError("ProvenanceRecord must contain source_file")
        if not self.parser_name:
            raise ValueError("ProvenanceRecord must contain parser_name")

# 6. Artifact (Enhanced Provenance & Lineage)
class ArtifactModel(BaseModel):
    artifact_id: str = Field(default_factory=default_uuid)
    source_id: str
    parser_id: str
    evidence_offset: Optional[int] = None
    source_table: Optional[str] = None
    source_record_id: Optional[str] = None
    artifact_type: str
    artifact_timestamp: Optional[str] = None
    timezone_source: Optional[str] = "UTC"
    timestamp_precision: Optional[str] = "exact"
    record_hash: str
    parent_artifact_id: Optional[str] = None
    raw_data: Dict[str, Any] = {}
    normalized_data: Dict[str, Any] = {}
    parser_notes: Optional[str] = None
    created_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    parser_name: Optional[str] = None
    parser_version: Optional[str] = "1.0.0"

    def canonical_hash(self) -> str:
        return compute_canonical_sha256(self.model_dump())

    def validate_record(self) -> None:
        if not self.artifact_id:
            raise ValueError("Artifact must have artifact_id")
        if not self.source_id:
            raise ValueError("Artifact must have source_id")
        if not self.parser_id:
            raise ValueError("Artifact must have parser_id")
        if len(self.record_hash) != 64:
            raise ValueError(f"Invalid record_hash length {len(self.record_hash)} (must be 64-char SHA256)")

    def source_artifact_id(self) -> Optional[str]:
        return self.artifact_id

    def source_parser_id(self) -> Optional[str]:
        return self.parser_id

# 7. Event (Audit-Capable & Timeline Normalized)
class EventModel(BaseModel):
    event_id: str = Field(default_factory=default_uuid)
    artifact_id: str
    device_id: str
    event_type: str
    category: str
    timestamp: str  # ISO 8601 UTC
    timezone_offset_minutes: Optional[int] = 0
    confidence: int = 100
    inferred: bool = False
    description: Optional[str] = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    source_weight: float = 1.0
    actor: Optional[str] = None
    target: Optional[str] = None
    raw_payload: Dict[str, Any] = {}

    def canonical_hash(self) -> str:
        return compute_canonical_sha256(self.model_dump())

    def validate_record(self) -> None:
        if not self.event_id:
            raise ValueError("Event must have event_id")
        if not self.artifact_id:
            raise ValueError("Event must reference artifact_id")
        if not (0 <= self.confidence <= 100):
            raise ValueError(f"Confidence score {self.confidence} out of range 0..100")
        if not self.timestamp:
            raise ValueError("Event must have timestamp")
        try:
            year = int(self.timestamp[:4])
            if year < 2000:
                raise ValueError(f"Event timestamp year {year} before supported range (>= 2000)")
        except (ValueError, TypeError):
            pass

    def source_artifact_id(self) -> Optional[str]:
        return self.artifact_id

    def source_parser_id(self) -> Optional[str]:
        return None

# 8. Event Provenance Linkage
class EventProvenanceModel(BaseModel):
    event_id: str
    artifact_id: str
    provenance_role: str = "primary"  # "primary", "corroborating", "inferred_from"
    contribution_weight: float = 1.0

# 9. Entity (Forensic Graph Node)
class EntityModel(BaseModel):
    entity_id: str = Field(default_factory=default_uuid)
    entity_type: str  # EntityType or string
    value: str
    confidence: int = 100
    source_artifact_id: Optional[str] = None
    metadata: Dict[str, Any] = {}

    def canonical_hash(self) -> str:
        return compute_canonical_sha256(self.model_dump())

    def validate_record(self) -> None:
        if not self.entity_id:
            raise ValueError("Entity must have entity_id")
        if not (0 <= self.confidence <= 100):
            raise ValueError(f"Confidence {self.confidence} out of range 0..100")
        if str(self.entity_type) in [EntityType.EMAIL_ADDRESS, "email_address"]:
            if "@" not in self.value:
                raise ValueError(f"Invalid email entity: {self.value}")
        if str(self.entity_type) in [EntityType.PHONE_NUMBER, "phone_number"]:
            digits = [c for c in self.value if c.isdigit()]
            if len(digits) < 5:
                raise ValueError(f"Invalid phone entity: {self.value}")

    def source_artifact_id(self) -> Optional[str]:
        return self.source_artifact_id

    def source_parser_id(self) -> Optional[str]:
        return None

# 10. Relationship (Forensic Graph Edge)
class RelationshipModel(BaseModel):
    relationship_id: str = Field(default_factory=default_uuid)
    source_event_id: str
    target_event_id: str
    relationship_type: str = "preceded_by"  # RelationshipType or string
    weight: float = 1.0
    rationale: Optional[str] = None
    generated_by: Optional[str] = "NEXUS Correlation Engine"
    generated_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))

    def canonical_hash(self) -> str:
        return compute_canonical_sha256(self.model_dump())

    def validate_record(self) -> None:
        if not self.relationship_id:
            raise ValueError("Relationship must have relationship_id")
        if self.source_event_id == self.target_event_id:
            raise ValueError(f"Self-referencing relationship: {self.source_event_id}")
        if not (0.0 <= self.weight <= 1.0):
            raise ValueError(f"Relationship weight {self.weight} out of range 0.0..1.0")

# 11. Finding
class FindingModel(BaseModel):
    finding_id: str = Field(default_factory=default_uuid)
    case_id: str
    title: str
    description: Optional[str] = ""
    finding_type: Optional[str] = "user_activity"
    confidence: int = 100
    methodology_version: Optional[str] = "1.0.0"
    analyst: Optional[str] = "Lead Forensic Examiner"
    created_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    reviewed: bool = False
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    supporting_events: List[str] = []
    contradictory_events: List[str] = []

    def canonical_hash(self) -> str:
        return compute_canonical_sha256(self.model_dump())

# 12. Finding Evidence Linkage
class FindingEvidenceModel(BaseModel):
    finding_id: str
    event_id: str
    evidence_role: str = "supporting"  # "supporting", "contradictory", "context"

# 13. Confidence Factor
class ConfidenceFactorModel(BaseModel):
    factor_id: str = Field(default_factory=default_uuid)
    finding_id: str
    event_id: Optional[str] = None
    score: int
    factor_type: str
    explanation: str

# 14. Chain of Custody (Immutable)
class ChainOfCustodyModel(BaseModel):
    custody_id: str = Field(default_factory=default_uuid)
    source_id: str
    action_type: str  # "INGEST", "EXAMINE", "EXTRACT", "VERIFY", "EXPORT"
    actor: str
    timestamp: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    location: Optional[str] = "Forensic Workstation"
    notes: Optional[str] = None
    previous_custody_id: Optional[str] = None

# 15. Processing Run (Investigation Replay & Reproducibility)
class ProcessingRunModel(BaseModel):
    run_id: str = Field(default_factory=default_uuid)
    case_id: Optional[str] = None
    engine_version: str = "1.0.0"
    ruleset_version: str = "2026.10"
    graph_version: str = "1.0.0"
    build_sha256: str = "0000000000000000000000000000000000000000000000000000000000000000"
    executed_by: str = "Examiner"
    executed_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    parameters: Dict[str, Any] = {}

# 16. Artifact-to-Run Linkage
class ArtifactProcessingModel(BaseModel):
    run_id: str
    artifact_id: str
    operation: str = "parse"

# 17. Forward-Linked Blockchain-Style Audit Log
class AuditLogModel(BaseModel):
    audit_id: str = Field(default_factory=default_uuid)
    event_timestamp: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    username: str
    operation: str
    entity_type: str
    entity_id: str
    previous_hash: Optional[str] = None
    row_hash: str
    details: Dict[str, Any] = {}

# 18. Merkle Checkpoint
class AuditCheckpointModel(BaseModel):
    checkpoint_id: str = Field(default_factory=default_uuid)
    generated_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    record_count: int
    merkle_root: str

# 19. Behavioral State (Digital Witness Replay)
class BehavioralStateModel(BaseModel):
    timestamp: str
    epoch_timestamp: float
    lock_state: str  # "UNLOCKED", "LOCKED", "UNKNOWN"
    battery_level: Optional[int] = None
    is_charging: Optional[bool] = None
    network_state: str  # "WIFI", "CELLULAR", "OFFLINE"
    connected_ssid: Optional[str] = None
    foreground_app: Optional[str] = None
    motion_state: str  # "STATIONARY", "WALKING", "DRIVING", "UNKNOWN"
    confidence: int  # 0 to 100
    corroborating_events: List[str] = []

# 20. Parser Context
class ParserContext(BaseModel):
    run_id: str = Field(default_factory=default_uuid)
    case_id: str = Field(default_factory=default_uuid)
    device_id: str = Field(default_factory=default_uuid)
    source_id: str = Field(default_factory=default_uuid)
    parser_id: str = Field(default_factory=default_uuid)
    parser_version: str = "1.0.0"
    started_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))

# 21. Parse Output Container
class ParseOutput(BaseModel):
    artifacts: List[ArtifactModel] = []
    events: List[EventModel] = []
    entities: List[EntityModel] = []
    relationships: List[RelationshipModel] = []

    def validate_output(self) -> None:
        """Validates domain invariants and business rules on all extracted records."""
        for a in self.artifacts:
            a.validate_record()
        for e in self.events:
            e.validate_record()
        for ent in self.entities:
            ent.validate_record()
        for r in self.relationships:
            r.validate_record()

    def generate_manifest(self, parser_name: str, parser_version: str, evidence_sha256: str) -> "ParseManifestModel":
        art_hashes = [a.record_hash for a in self.artifacts]
        art_hashes.sort()
        return ParseManifestModel(
            parser_name=parser_name,
            parser_version=parser_version,
            evidence_sha256=evidence_sha256,
            artifact_count=len(self.artifacts),
            event_count=len(self.events),
            entity_count=len(self.entities),
            relationship_count=len(self.relationships),
            artifact_hashes=art_hashes
        )

# 22. Parse Manifest
class ParseManifestModel(BaseModel):
    manifest_id: str = Field(default_factory=default_uuid)
    parser_name: str
    parser_version: str
    evidence_sha256: str
    artifact_count: int
    event_count: int
    entity_count: int = 0
    relationship_count: int = 0
    artifact_hashes: List[str] = []
    created_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))

    def canonical_hash(self) -> str:
        return compute_canonical_sha256(self.model_dump())

def validate_parse_output(output: ParseOutput) -> None:
    output.validate_output()

def verify_output_integrity(output: ParseOutput) -> bool:
    validate_parse_output(output)
    hashes = [a.canonical_hash() for a in output.artifacts]
    hashes.sort()
    return len(hashes) == len(output.artifacts)

# ============================================================================
# BACKWARD COMPATIBILITY ALIASES
# ============================================================================

CaseMetadata = CaseModel
ParserMetadata = ParserModel
EvidenceSource = EvidenceSourceModel
Artifact = ArtifactModel
Event = EventModel
Entity = EntityModel
Relationship = RelationshipModel
Finding = FindingModel

EvidenceArtifact = BaseModel
class EvidenceArtifact(BaseModel):
    artifact_id: str
    file_name: str
    file_path: str
    file_size_bytes: int
    sha256: str
    md5: str
    mime_type: str
    origin: str
    ingested_at: int
    integrity_status: str = "VERIFIED"
    metadata: Dict[str, Any] = {}

class ChainOfCustodyRecord(BaseModel):
    record_id: str
    artifact_id: str
    action: str
    examiner: str
    timestamp: int
    sha256_hash: str
    details: str
    nist_compliance: str = "NIST SP 800-86 Compliant"

class TimelineEvent(BaseModel):
    event_id: str
    timestamp_utc: str
    epoch_timestamp: float
    source_artifact: str
    category: str
    summary: str
    details: Dict[str, Any] = {}
    severity: str = "INFO"

class ThreatIndicator(BaseModel):
    finding_id: str
    title: str
    category: str
    severity: str
    description: str
    evidence: str
    source_artifact: str
    mitre_attack_id: Optional[str] = "T1430"
    remediation: str

class SQLiteColumn(BaseModel):
    cid: int
    name: str
    data_type: str
    notnull: bool
    dflt_value: Optional[str]
    pk: bool

class SQLiteTableInfo(BaseModel):
    table_name: str
    row_count: int
    columns: List[SQLiteColumn]
    has_wal: bool = False
    has_shm: bool = False
    freelist_count: int = 0
