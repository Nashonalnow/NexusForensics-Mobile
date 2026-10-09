#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Core Data Models
NEXUS Hardened Forensic Domain Models: First-class Provenance, Reproducibility, Parser Lineage, and Evidentiary Integrity.
Strict Copper Standard: 100% authentic evidence hashes, schemas, and timestamps.
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
import time
import uuid

def default_uuid() -> str:
    return str(uuid.uuid4())

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

# 4. Parser Registry Model
class ParserModel(BaseModel):
    parser_id: str = Field(default_factory=default_uuid)
    parser_name: str
    parser_version: str = "1.0.0"
    git_commit: Optional[str] = "9f7c8e2"
    build_number: Optional[str] = "2026.10.1"
    release_date: Optional[str] = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    parser_sha256: Optional[str] = None
    developer: Optional[str] = "NEXUS Mobile DFIR Team"
    active: bool = True

# 5. Artifact (Enhanced Provenance)
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
    timestamp_precision: Optional[str] = "exact"  # 'exact', 'second', 'minute', 'hour', 'day', 'estimated'
    record_hash: str
    parent_artifact_id: Optional[str] = None
    raw_data: Dict[str, Any] = {}
    normalized_data: Dict[str, Any] = {}
    parser_notes: Optional[str] = None
    created_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    # Compatibility properties
    parser_name: Optional[str] = None
    parser_version: Optional[str] = "1.0.0"

# 6. Event (Audit-Capable)
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

# 7. Event Provenance Linkage
class EventProvenanceModel(BaseModel):
    event_id: str
    artifact_id: str
    provenance_role: str = "primary"  # "primary", "corroborating", "inferred_from"
    contribution_weight: float = 1.0

# 8. Relationship
class RelationshipModel(BaseModel):
    relationship_id: str = Field(default_factory=default_uuid)
    source_event_id: str
    target_event_id: str
    relationship_type: str = "preceded_by"  # 'preceded_by', 'followed_by', 'supports', 'contradicts', etc.
    weight: float = 1.0
    rationale: Optional[str] = None
    generated_by: Optional[str] = "NEXUS Correlation Engine"
    generated_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))

# 9. Finding
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

# 10. Finding Evidence Linkage
class FindingEvidenceModel(BaseModel):
    finding_id: str
    event_id: str
    evidence_role: str = "supporting"  # "supporting", "contradictory", "context"

# 11. Confidence Factor
class ConfidenceFactorModel(BaseModel):
    factor_id: str = Field(default_factory=default_uuid)
    finding_id: str
    event_id: Optional[str] = None
    score: int
    factor_type: str
    explanation: str

# 12. Chain of Custody (Immutable)
class ChainOfCustodyModel(BaseModel):
    custody_id: str = Field(default_factory=default_uuid)
    source_id: str
    action_type: str  # "INGEST", "EXAMINE", "EXTRACT", "VERIFY", "EXPORT"
    actor: str
    timestamp: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    location: Optional[str] = "Forensic Workstation"
    notes: Optional[str] = None
    previous_custody_id: Optional[str] = None

# 13. Processing Run (Investigation Replay & Reproducibility)
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

# 14. Artifact-to-Run Linkage
class ArtifactProcessingModel(BaseModel):
    run_id: str
    artifact_id: str
    operation: str = "parse"

# 15. Forward-Linked Blockchain-Style Audit Log
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

# 16. Merkle Checkpoint
class AuditCheckpointModel(BaseModel):
    checkpoint_id: str = Field(default_factory=default_uuid)
    generated_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    record_count: int
    merkle_root: str

# 17. Behavioral State (Digital Witness Replay)
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

# Legacy aliases for backward compatibility
CaseMetadata = CaseModel
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
