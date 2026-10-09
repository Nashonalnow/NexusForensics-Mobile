#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Core Data Models
Digital Forensics & Incident Response (DFIR) entities adhering to NIST SP 800-86 standards.
Strict Copper Standard: 100% authentic evidence hashes, schemas, and timestamps.
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
import time

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
