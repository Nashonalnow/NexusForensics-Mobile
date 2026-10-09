#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Core Data Models
NEXUS MVP Domain Model: The 5 Canonical Entities (Artifact -> Event -> Relationship -> Finding -> Report)
Strict Copper Standard: 100% authentic evidence hashes, schemas, and timestamps.
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
import time
import uuid

# 1. Case
class CaseModel(BaseModel):
    case_id: str = Field(default_factory=lambda: f"CASE-{uuid.uuid4().hex[:8].upper()}")
    case_name: str
    description: Optional[str] = ""
    status: str = "active"  # "active", "archived", "closed"
    created_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    created_by: str = "Examiner"
    tags: List[str] = []

# 2. Device
class DeviceModel(BaseModel):
    device_id: str = Field(default_factory=lambda: f"DEV-{uuid.uuid4().hex[:8].upper()}")
    case_id: str
    platform: str  # "Android", "iOS", "Generic"
    manufacturer: Optional[str] = "Unknown"
    model: Optional[str] = "Unknown"
    serial_number: Optional[str] = None
    imei: Optional[str] = None
    phone_number: Optional[str] = None
    os_version: Optional[str] = None
    acquisition_date: Optional[str] = None

# 3. Evidence Source
class EvidenceSourceModel(BaseModel):
    source_id: str = Field(default_factory=lambda: f"SRC-{uuid.uuid4().hex[:8].upper()}")
    device_id: str
    source_type: str  # "filesystem", "logical", "physical", "nexusproxy", "backup"
    acquisition_tool: Optional[str] = "NexusForensics"
    acquisition_tool_version: Optional[str] = "1.0"
    original_filename: str
    file_size: int
    sha256: str
    imported_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))
    examiner: str = "Examiner"

# 4. Artifact
class ArtifactModel(BaseModel):
    artifact_id: str = Field(default_factory=lambda: f"ART-{uuid.uuid4().hex[:8].upper()}")
    source_id: str
    artifact_type: str  # "sms", "call_log", "knowledgec", "chrome_history", "safari_history", "photos", "network_flow"
    parser_name: str
    parser_version: str = "1.0"
    artifact_timestamp: Optional[str] = None
    record_hash: str
    raw_data: Dict[str, Any] = {}
    normalized_data: Dict[str, Any] = {}

# 5. Event
class EventModel(BaseModel):
    event_id: str = Field(default_factory=lambda: f"EV-{uuid.uuid4().hex[:8].upper()}")
    artifact_id: str
    device_id: str
    timestamp: str  # ISO 8601 UTC
    event_type: str  # "unlock", "screen_on", "message_sent", "call_started", "photo_taken", "app_opened", "wifi_connected", "gps_update"
    category: str  # "communication", "device_state", "location", "app_activity", "network"
    description: str
    confidence: int = 100
    location_lat: Optional[float] = None
    location_lon: Optional[float] = None
    actor: Optional[str] = None
    target: Optional[str] = None
    raw_payload: Dict[str, Any] = {}

# 6. Relationship
class RelationshipModel(BaseModel):
    relationship_id: str = Field(default_factory=lambda: f"REL-{uuid.uuid4().hex[:8].upper()}")
    source_event_id: str
    target_event_id: str
    relationship_type: str  # "preceded_by", "followed_by", "originated_from", "supports", "contradicts", "located_at", "used_app", "connected_to"
    weight: float = 1.0
    rationale: Optional[str] = None
    created_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))

# 7. Finding
class FindingModel(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"F-{uuid.uuid4().hex[:8].upper()}")
    case_id: str
    device_id: str
    title: str
    description: str
    confidence: int  # 0 to 100
    finding_type: str  # "user_activity", "threat", "location_presence", "communication"
    supporting_events: List[str] = []
    contradictory_events: List[str] = []
    created_at: str = Field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()))

# 8. Confidence Factor
class ConfidenceFactorModel(BaseModel):
    factor_id: str = Field(default_factory=lambda: f"CONF-{uuid.uuid4().hex[:8].upper()}")
    finding_id: str
    event_id: Optional[str] = None
    score: int  # e.g. +35, +20, -40
    factor_type: str  # "direct_evidence", "supporting_corroboration", "temporal_proximity", "contradiction"
    explanation: str

# 9. Behavioral State (Digital Witness Replay)
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

# NIST SP 800-86 Evidence & Forensic Models
class CaseMetadata(BaseModel):
    case_id: str = Field(..., description="Unique case identifier (e.g. CASE-2026-001)")
    title: str = Field(..., description="Case title or operation name")
    examiner: str = Field(..., description="Lead forensic investigator name or callsign")
    organization: str = Field(default="Security Operations Center / DFIR Unit")
    created_at: int = Field(default_factory=lambda: int(time.time()))
    notes: Optional[str] = ""

class EvidenceArtifact(BaseModel):
    artifact_id: str
    file_name: str
    file_path: str
    file_size_bytes: int
    sha256: str
    md5: str
    mime_type: str
    origin: str  # "Android", "iOS", "NexusProxy", "Manual"
    ingested_at: int
    integrity_status: str = "VERIFIED"  # "VERIFIED", "TAMPERED", "UNCHECKED"
    metadata: Dict[str, Any] = {}

class ChainOfCustodyRecord(BaseModel):
    record_id: str
    artifact_id: str
    action: str  # "INGEST", "EXAMINE", "EXTRACT", "VERIFY", "EXPORT"
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
    category: str  # "NETWORK", "FILESYSTEM", "DATABASE", "SYSTEM", "THREAT"
    summary: str
    details: Dict[str, Any] = {}
    severity: str = "INFO"  # "HIGH", "MEDIUM", "LOW", "INFO"

class ThreatIndicator(BaseModel):
    finding_id: str
    title: str
    category: str  # "STALKERWARE", "MALWARE", "SUSPICIOUS_PERMISSION", "C2_DOMAIN", "PERSISTENCE"
    severity: str  # "HIGH", "MEDIUM", "LOW", "INFO"
    description: str
    evidence: str
    source_artifact: str
    mitre_attack_id: Optional[str] = "T1430"  # Mobile ATT&CK
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

