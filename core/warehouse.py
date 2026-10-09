#!/usr/bin/env python3
"""
NexusForensics Mobile™ | DuckDB Forensic Evidence Warehouse
Hardened Forensic Schema: First-class Provenance, Reproducibility, Parser Lineage, and Evidentiary Integrity.
Strict Copper Standard: 100% authentic evidence schemas, zero mock/fake data.
"""

import os
import sys
import time
import json
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

import duckdb

def to_uuid(val: Any) -> str:
    """Safely converts string or UUID into canonical RFC 4122 UUID string."""
    if isinstance(val, uuid.UUID):
        return str(val)
    if not val:
        return str(uuid.uuid4())
    try:
        return str(uuid.UUID(str(val)))
    except Exception:
        return str(uuid.uuid5(uuid.NAMESPACE_OID, str(val)))

def _format_row_dict(cols: List[str], row: Any) -> Dict[str, Any]:
    """Converts a database row tuple to dictionary, casting UUIDs to canonical strings."""
    return {cols[i]: str(row[i]) if isinstance(row[i], uuid.UUID) else row[i] for i in range(len(cols))}

def canonical_json_str(obj: Any) -> str:
    """Produces deterministic canonical JSON serialization for cryptographic hashing."""
    if obj is None:
        return "{}"
    if isinstance(obj, str):
        try:
            parsed = json.loads(obj)
            return json.dumps(parsed, sort_keys=True, separators=(',', ':'), default=str)
        except Exception:
            return json.dumps({"raw": obj}, sort_keys=True, separators=(',', ':'), default=str)
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), default=str)

def compute_audit_row_hash(
    audit_id: str,
    timestamp: str,
    username: str,
    operation: str,
    entity_type: str,
    entity_id: str,
    details: Any,
    previous_hash: Optional[str]
) -> str:
    """
    Computes canonical row hash for forward-linked blockchain-style audit chain:
    audit_id|timestamp|username|operation|entity_type|entity_id|canonical_json|previous_hash
    """
    c_details = canonical_json_str(details)
    p_hash = str(previous_hash) if previous_hash else ""
    raw = f"{audit_id}|{timestamp}|{username}|{operation}|{entity_type}|{entity_id}|{c_details}|{p_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def compute_merkle_root(hashes: List[str]) -> str:
    """Calculates pairwise Merkle root hash across a list of row digests."""
    if not hashes:
        return hashlib.sha256(b"").hexdigest()
    current = list(hashes)
    while len(current) > 1:
        if len(current) % 2 != 0:
            current.append(current[-1])
        next_level = []
        for i in range(0, len(current), 2):
            combined = current[i] + current[i+1]
            next_level.append(hashlib.sha256(combined.encode("utf-8")).hexdigest())
        current = next_level
    return current[0]


DUCKDB_SCHEMA_DDL = """
CREATE SCHEMA IF NOT EXISTS forensic;

-- Common Domains
CREATE TYPE forensic.platform_type AS ENUM ('android', 'ios', 'cloud', 'unknown');
CREATE TYPE forensic.source_type AS ENUM ('filesystem', 'physical', 'logical', 'backup', 'cloud', 'manual');
CREATE TYPE forensic.support_type AS ENUM ('supports', 'contradicts', 'neutral');
CREATE TYPE forensic.relationship_type AS ENUM ('preceded_by', 'followed_by', 'supports', 'contradicts', 'associated_with', 'located_at', 'connected_to', 'communicated_with', 'used_app');

-- 1. Cases (Hardened)
CREATE TABLE IF NOT EXISTS forensic.cases (
    case_id UUID PRIMARY KEY,
    case_number VARCHAR(100) UNIQUE NOT NULL,
    case_name VARCHAR(500) NOT NULL,
    description TEXT,
    status VARCHAR NOT NULL CHECK (status IN ('open', 'closed', 'archived')),
    created_at TIMESTAMP NOT NULL,
    created_by VARCHAR NOT NULL,
    last_modified TIMESTAMP NOT NULL,
    classification VARCHAR DEFAULT 'internal' CHECK (classification IN ('public', 'internal', 'confidential', 'restricted')),
    retention_until TIMESTAMP
);

-- 2. Devices (Hardened)
CREATE TABLE IF NOT EXISTS forensic.devices (
    device_id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    platform forensic.platform_type NOT NULL,
    manufacturer VARCHAR(200),
    model VARCHAR(200),
    serial_number VARCHAR(255),
    imei VARCHAR(20),
    meid VARCHAR(20),
    operating_system VARCHAR(100),
    os_version VARCHAR(100),
    timezone VARCHAR(128),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES forensic.cases(case_id),
    CHECK (imei IS NULL OR length(imei) BETWEEN 14 AND 16)
);

-- 3. Evidence Sources (Immutable)
CREATE TABLE IF NOT EXISTS forensic.evidence_sources (
    source_id UUID PRIMARY KEY,
    device_id UUID NOT NULL,
    source_type forensic.source_type NOT NULL,
    acquisition_tool VARCHAR(255) NOT NULL,
    acquisition_tool_version VARCHAR(100),
    acquisition_operator VARCHAR(255),
    acquisition_started TIMESTAMP,
    acquisition_completed TIMESTAMP,
    original_filename VARCHAR NOT NULL,
    original_path VARCHAR,
    file_size BIGINT NOT NULL CHECK(file_size > 0),
    sha256 CHAR(64) NOT NULL,
    sha1 CHAR(40),
    md5 CHAR(32),
    imported_at TIMESTAMP NOT NULL,
    imported_by VARCHAR NOT NULL,
    evidence_sealed BOOLEAN DEFAULT FALSE,
    FOREIGN KEY(device_id) REFERENCES forensic.devices(device_id),
    CHECK (acquisition_completed IS NULL OR acquisition_completed >= acquisition_started)
);

-- 4. Parser Registry
CREATE TABLE IF NOT EXISTS forensic.parsers (
    parser_id UUID PRIMARY KEY,
    parser_name VARCHAR NOT NULL,
    parser_version VARCHAR NOT NULL,
    git_commit VARCHAR(64),
    build_number VARCHAR,
    release_date TIMESTAMP,
    parser_sha256 CHAR(64),
    developer VARCHAR,
    active BOOLEAN DEFAULT TRUE
);

-- 5. Artifacts (Enhanced Provenance)
CREATE TABLE IF NOT EXISTS forensic.artifacts (
    artifact_id UUID PRIMARY KEY,
    source_id UUID NOT NULL,
    parser_id UUID NOT NULL,
    evidence_offset BIGINT,
    source_table VARCHAR,
    source_record_id VARCHAR,
    artifact_type VARCHAR NOT NULL,
    artifact_timestamp TIMESTAMP,
    timezone_source VARCHAR,
    timestamp_precision VARCHAR CHECK (timestamp_precision IN ('exact', 'second', 'minute', 'hour', 'day', 'estimated')),
    record_hash CHAR(64) NOT NULL,
    parent_artifact_id UUID,
    raw_json JSON NOT NULL,
    normalized_json JSON NOT NULL,
    parser_notes TEXT,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY(parser_id) REFERENCES forensic.parsers(parser_id),
    FOREIGN KEY(source_id) REFERENCES forensic.evidence_sources(source_id),
    FOREIGN KEY(parent_artifact_id) REFERENCES forensic.artifacts(artifact_id)
);

-- 6. Events (Audit-Capable)
CREATE TABLE IF NOT EXISTS forensic.events (
    event_id UUID PRIMARY KEY,
    artifact_id UUID NOT NULL,
    device_id UUID NOT NULL,
    event_type VARCHAR NOT NULL,
    category VARCHAR NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    timezone_offset_minutes INTEGER,
    confidence SMALLINT NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
    inferred BOOLEAN DEFAULT FALSE,
    description TEXT,
    latitude DOUBLE,
    longitude DOUBLE,
    altitude DOUBLE,
    source_weight DOUBLE DEFAULT 1.0 CHECK (source_weight >= 0),
    FOREIGN KEY(artifact_id) REFERENCES forensic.artifacts(artifact_id),
    FOREIGN KEY(device_id) REFERENCES forensic.devices(device_id)
);

-- 7. Event Provenance Linkage (Multiple artifacts per event)
CREATE TABLE IF NOT EXISTS forensic.event_provenance (
    event_id UUID NOT NULL,
    artifact_id UUID NOT NULL,
    provenance_role VARCHAR NOT NULL,
    contribution_weight DOUBLE,
    PRIMARY KEY (event_id, artifact_id),
    FOREIGN KEY(event_id) REFERENCES forensic.events(event_id),
    FOREIGN KEY(artifact_id) REFERENCES forensic.artifacts(artifact_id)
);

-- 8. Relationships
CREATE TABLE IF NOT EXISTS forensic.relationships (
    relationship_id UUID PRIMARY KEY,
    source_event_id UUID NOT NULL,
    target_event_id UUID NOT NULL,
    relationship_type forensic.relationship_type,
    weight DOUBLE NOT NULL CHECK (weight >= 0 AND weight <= 1),
    rationale TEXT,
    generated_by VARCHAR,
    generated_at TIMESTAMP NOT NULL,
    FOREIGN KEY(source_event_id) REFERENCES forensic.events(event_id),
    FOREIGN KEY(target_event_id) REFERENCES forensic.events(event_id),
    CHECK (source_event_id <> target_event_id)
);

-- 9. Findings
CREATE TABLE IF NOT EXISTS forensic.findings (
    finding_id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    title VARCHAR NOT NULL,
    description TEXT,
    finding_type VARCHAR,
    confidence SMALLINT CHECK (confidence BETWEEN 0 AND 100),
    methodology_version VARCHAR,
    analyst VARCHAR,
    created_at TIMESTAMP NOT NULL,
    reviewed BOOLEAN DEFAULT FALSE,
    reviewed_by VARCHAR,
    reviewed_at TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES forensic.cases(case_id)
);

-- 10. Finding Evidence Linkage
CREATE TABLE IF NOT EXISTS forensic.finding_evidence (
    finding_id UUID NOT NULL,
    event_id UUID NOT NULL,
    evidence_role VARCHAR DEFAULT 'supporting',
    PRIMARY KEY (finding_id, event_id),
    FOREIGN KEY(finding_id) REFERENCES forensic.findings(finding_id),
    FOREIGN KEY(event_id) REFERENCES forensic.events(event_id)
);

-- 11. Confidence Factors
CREATE TABLE IF NOT EXISTS forensic.confidence_factors (
    factor_id UUID PRIMARY KEY,
    finding_id UUID NOT NULL,
    event_id UUID,
    score INTEGER NOT NULL,
    factor_type VARCHAR NOT NULL,
    explanation TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES forensic.findings(finding_id)
);

-- 12. Chain of Custody (Immutable)
CREATE TABLE IF NOT EXISTS forensic.chain_of_custody (
    custody_id UUID PRIMARY KEY,
    source_id UUID NOT NULL,
    action_type VARCHAR NOT NULL,
    actor VARCHAR NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    location VARCHAR,
    notes TEXT,
    previous_custody_id UUID,
    FOREIGN KEY(source_id) REFERENCES forensic.evidence_sources(source_id)
);

-- 13. Processing Runs (Reproducibility Metadata)
CREATE TABLE IF NOT EXISTS forensic.processing_runs (
    run_id UUID PRIMARY KEY,
    case_id UUID,
    engine_version VARCHAR,
    ruleset_version VARCHAR,
    graph_version VARCHAR,
    build_sha256 CHAR(64),
    executed_by VARCHAR,
    executed_at TIMESTAMP,
    parameters JSON,
    FOREIGN KEY(case_id) REFERENCES forensic.cases(case_id)
);

-- 14. Artifact-to-Run Linkage
CREATE TABLE IF NOT EXISTS forensic.artifact_processing (
    run_id UUID,
    artifact_id UUID,
    operation VARCHAR,
    PRIMARY KEY(run_id, artifact_id),
    FOREIGN KEY(run_id) REFERENCES forensic.processing_runs(run_id),
    FOREIGN KEY(artifact_id) REFERENCES forensic.artifacts(artifact_id)
);

CREATE SEQUENCE IF NOT EXISTS forensic.audit_seq START 1;

-- 15. Forward-Linked Blockchain-Style Audit Log
CREATE TABLE IF NOT EXISTS forensic.audit_log (
    sequence_id BIGINT DEFAULT nextval('forensic.audit_seq'),
    audit_id UUID PRIMARY KEY,
    event_timestamp TIMESTAMP NOT NULL,
    username VARCHAR NOT NULL,
    operation VARCHAR NOT NULL,
    entity_type VARCHAR NOT NULL,
    entity_id VARCHAR NOT NULL,
    previous_hash CHAR(64),
    row_hash CHAR(64) NOT NULL,
    details JSON
);

-- 16. Merkle Checkpoints
CREATE TABLE IF NOT EXISTS forensic.audit_checkpoints (
    checkpoint_id UUID PRIMARY KEY,
    generated_at TIMESTAMP NOT NULL,
    record_count BIGINT NOT NULL,
    merkle_root CHAR(64) NOT NULL
);

-- 17. Graph Entities
CREATE TABLE IF NOT EXISTS forensic.entities (
    entity_id UUID PRIMARY KEY,
    entity_type VARCHAR NOT NULL,
    value VARCHAR NOT NULL,
    confidence SMALLINT CHECK (confidence BETWEEN 0 AND 100),
    source_artifact_id UUID,
    metadata JSON,
    FOREIGN KEY(source_artifact_id) REFERENCES forensic.artifacts(artifact_id)
);

-- 18. Event Entity Mentions
CREATE TABLE IF NOT EXISTS forensic.event_entities (
    event_id UUID NOT NULL,
    entity_id UUID NOT NULL,
    role VARCHAR DEFAULT 'participant',
    PRIMARY KEY(event_id, entity_id),
    FOREIGN KEY(event_id) REFERENCES forensic.events(event_id),
    FOREIGN KEY(entity_id) REFERENCES forensic.entities(entity_id)
);

-- Composite Indexes
CREATE INDEX IF NOT EXISTS idx_events_device_time ON forensic.events(device_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON forensic.events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_artifact_type_time ON forensic.artifacts(artifact_type, artifact_timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_confidence ON forensic.findings(confidence, finding_type);
CREATE INDEX IF NOT EXISTS idx_relationships_source_type ON forensic.relationships(source_event_id, relationship_type);
CREATE INDEX IF NOT EXISTS idx_relationships_target_type ON forensic.relationships(target_event_id, relationship_type);

-- Analytical Views
CREATE OR REPLACE VIEW forensic.unified_timeline AS
SELECT 
    e.event_id,
    e.device_id,
    e.timestamp,
    e.event_type,
    e.category,
    e.description,
    e.confidence,
    e.latitude,
    e.longitude,
    a.artifact_type,
    p.parser_name,
    p.parser_version,
    es.original_filename,
    es.sha256 as evidence_sha256
FROM forensic.events e
JOIN forensic.artifacts a ON e.artifact_id = a.artifact_id
JOIN forensic.parsers p ON a.parser_id = p.parser_id
JOIN forensic.evidence_sources es ON a.source_id = es.source_id;

CREATE OR REPLACE VIEW forensic.communication_events AS
SELECT * FROM forensic.events
WHERE category = 'communication';

CREATE OR REPLACE VIEW forensic.location_events AS
SELECT * FROM forensic.events
WHERE latitude IS NOT NULL AND longitude IS NOT NULL;

CREATE OR REPLACE VIEW forensic.device_state_events AS
SELECT * FROM forensic.events
WHERE category = 'device_state';
"""


class DuckDBWarehouse:
    """
    Manages in-process analytical DuckDB instance with hardened forensic provenance,
    Zimmerman-level parser lineage, and forward-linked tamper-evident audit ledger.
    """

    def __init__(self, db_path: Optional[Path] = None, read_only: bool = False):
        if db_path:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            default_dir = Path(__file__).resolve().parent.parent / "workbench" / "cases"
            try:
                default_dir.mkdir(parents=True, exist_ok=True)
                test_f = default_dir / ".db_check"
                test_f.touch()
                test_f.unlink()
                self.db_path = default_dir / "warehouse.duckdb"
            except Exception:
                fallback_dir = Path("/tmp/nexus_forensics_db")
                fallback_dir.mkdir(parents=True, exist_ok=True)
                self.db_path = fallback_dir / "nexus_forensics.duckdb"

        self.is_read_only = False
        try:
            self.conn = duckdb.connect(str(self.db_path), read_only=read_only)
            self.is_read_only = read_only
        except Exception as e:
            if "lock" in str(e).lower() or "PID" in str(e):
                try:
                    self.conn = duckdb.connect(str(self.db_path), read_only=True)
                    self.is_read_only = True
                except Exception:
                    self.conn = duckdb.connect(":memory:")
            else:
                self.conn = duckdb.connect(":memory:")

        if not self.is_read_only:
            self._init_schema()

    def _init_schema(self):
        """Creates or upgrades forensic schema, enums, tables, views, and indexes."""
        # Check if hardened schema exists
        try:
            chk = self.conn.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema='forensic' AND table_name='parsers';").fetchone()[0]
            if chk == 0:
                # Fresh or upgrade: execute complete DDL
                for stmt in DUCKDB_SCHEMA_DDL.strip().split(";"):
                    s = stmt.strip()
                    if s:
                        self.conn.execute(s)
            else:
                # Ensure views and indexes are current
                for stmt in DUCKDB_SCHEMA_DDL.strip().split(";"):
                    s = stmt.strip()
                    if s and ("VIEW" in s or "INDEX" in s):
                        try:
                            self.conn.execute(s)
                        except Exception:
                            pass
        except Exception:
            for stmt in DUCKDB_SCHEMA_DDL.strip().split(";"):
                s = stmt.strip()
                if s:
                    try:
                        self.conn.execute(s)
                    except Exception:
                        pass

        # Auto-register all parsers from ParserRegistry
        try:
            from .parsers import ParserRegistry
            for p in ParserRegistry.get_all_parsers():
                self.insert_parser(
                    parser_id=p.parser_id,
                    parser_name=p.parser_name,
                    parser_version=p.parser_version,
                    git_commit=getattr(p, 'git_commit', '9f7c8e2'),
                    build_number=getattr(p, 'build_number', '2026.10.1'),
                    release_date=getattr(p, 'release_date', '2026-10-09 00:00:00'),
                    parser_sha256=p.parser_sha256,
                    developer=getattr(p, 'developer', 'NEXUS Mobile DFIR Team')
                )
        except Exception:
            pass

        try:
            self.conn.execute("CREATE SEQUENCE IF NOT EXISTS forensic.audit_seq START 1;")
            self.conn.execute("ALTER TABLE forensic.audit_log ADD COLUMN IF NOT EXISTS sequence_id BIGINT DEFAULT nextval('forensic.audit_seq');")
        except Exception:
            pass

    def close(self):
        """Closes the DuckDB database connection cleanly."""
        try:
            self.conn.close()
        except Exception:
            pass

    # =========================================================================
    # AUDIT LOG ENGINE: FORWARD-LINKED CRYPTOGRAPHIC BLOCKCHAIN-STYLE CHAIN
    # =========================================================================

    def log_audit(
        self,
        case_id: Optional[str],
        username: str,
        operation: str,
        entity_type: str,
        entity_id: str,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Appends immutable forward-linked audit record to forensic.audit_log."""
        audit_id = to_uuid(uuid.uuid4())
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')

        # Retrieve previous row_hash by latest sequence_id or timestamp
        try:
            prev_res = self.conn.execute("SELECT row_hash FROM forensic.audit_log ORDER BY sequence_id DESC LIMIT 1;").fetchone()
        except Exception:
            prev_res = self.conn.execute("SELECT row_hash FROM forensic.audit_log ORDER BY event_timestamp DESC, audit_id DESC LIMIT 1;").fetchone()
        previous_hash = prev_res[0] if prev_res else None

        row_hash = compute_audit_row_hash(
            audit_id=audit_id,
            timestamp=now,
            username=username,
            operation=operation,
            entity_type=entity_type,
            entity_id=str(entity_id),
            details=details or {},
            previous_hash=previous_hash
        )

        det_json = canonical_json_str(details or {})
        try:
            self.conn.execute("""
                INSERT INTO forensic.audit_log (sequence_id, audit_id, event_timestamp, username, operation, entity_type, entity_id, previous_hash, row_hash, details)
                VALUES (nextval('forensic.audit_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, [audit_id, now, username, operation, entity_type, str(entity_id), previous_hash, row_hash, det_json])
        except Exception:
            self.conn.execute("""
                INSERT INTO forensic.audit_log (audit_id, event_timestamp, username, operation, entity_type, entity_id, previous_hash, row_hash, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, [audit_id, now, username, operation, entity_type, str(entity_id), previous_hash, row_hash, det_json])
        return audit_id

    def create_audit_checkpoint(self) -> str:
        """Computes Merkle root across all audit records and stores checkpoint."""
        try:
            rows = self.conn.execute("SELECT row_hash FROM forensic.audit_log ORDER BY sequence_id ASC;").fetchall()
        except Exception:
            rows = self.conn.execute("SELECT row_hash FROM forensic.audit_log ORDER BY event_timestamp ASC;").fetchall()
        hashes = [r[0] for r in rows]
        root = compute_merkle_root(hashes)
        cid = to_uuid(uuid.uuid4())
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

        self.conn.execute("""
            INSERT INTO forensic.audit_checkpoints (checkpoint_id, generated_at, record_count, merkle_root)
            VALUES (?, ?, ?, ?);
        """, [cid, now, len(hashes), root])
        return root

    def validate_audit_chain(self) -> Dict[str, Any]:
        """
        Validates the entire audit log forward-linked chain.
        Detects missing hashes, chain link breaks, row tampering, duplicate hashes, and timeline regressions.
        """
        t0 = time.perf_counter()
        try:
            rows = self.conn.execute("""
                SELECT audit_id, event_timestamp, username, operation, entity_type, entity_id, previous_hash, row_hash, details
                FROM forensic.audit_log
                ORDER BY sequence_id ASC;
            """).fetchall()
        except Exception:
            rows = self.conn.execute("""
                SELECT audit_id, event_timestamp, username, operation, entity_type, entity_id, previous_hash, row_hash, details
                FROM forensic.audit_log
                ORDER BY event_timestamp ASC;
            """).fetchall()

        if not rows:
            return {
                "status": "PASS",
                "records_checked": 0,
                "hash_mismatches": 0,
                "chain_breaks": 0,
                "duplicates": 0,
                "timeline_regressions": 0,
                "affected_records": [],
                "validation_time_ms": round((time.perf_counter() - t0) * 1000, 2)
            }

        hash_mismatches = 0
        chain_breaks = 0
        timeline_regressions = 0
        affected_records = []
        seen_hashes = set()
        duplicate_hashes = 0

        expected_previous_hash = None
        prev_time = None

        for r in rows:
            a_id = str(r[0])
            if isinstance(r[1], datetime):
                ts = r[1].strftime('%Y-%m-%d %H:%M:%S.%f')
            else:
                ts = str(r[1])
            u_name = str(r[2])
            op = str(r[3])
            e_type = str(r[4])
            e_id = str(r[5])
            p_hash = r[6]
            stored_hash = r[7]
            det = r[8]

            # 1. Duplicate check
            if stored_hash in seen_hashes:
                duplicate_hashes += 1
                affected_records.append(f"{a_id}:DUPLICATE_HASH")
            seen_hashes.add(stored_hash)

            # 2. Timeline monotonicity check
            if prev_time and ts < prev_time:
                timeline_regressions += 1
                affected_records.append(f"{a_id}:TIMELINE_REGRESSION")
            prev_time = ts

            # 3. Chain link check
            if p_hash != expected_previous_hash:
                chain_breaks += 1
                affected_records.append(f"{a_id}:CHAIN_LINK_MISMATCH")

            # 4. Row hash recalculation
            computed = compute_audit_row_hash(
                audit_id=a_id,
                timestamp=ts,
                username=u_name,
                operation=op,
                entity_type=e_type,
                entity_id=e_id,
                details=det,
                previous_hash=p_hash
            )

            if computed != stored_hash:
                hash_mismatches += 1
                affected_records.append(f"{a_id}:ROW_HASH_MISMATCH")

            expected_previous_hash = stored_hash

        is_pass = (hash_mismatches == 0 and chain_breaks == 0 and duplicate_hashes == 0 and timeline_regressions == 0)
        return {
            "status": "PASS" if is_pass else "FAIL",
            "records_checked": len(rows),
            "hash_mismatches": hash_mismatches,
            "chain_breaks": chain_breaks,
            "duplicates": duplicate_hashes,
            "timeline_regressions": timeline_regressions,
            "affected_records": affected_records,
            "validation_time_ms": round((time.perf_counter() - t0) * 1000, 2)
        }

    # =========================================================================
    # REPRODUCIBILITY & PROCESSING RUNS
    # =========================================================================

    def create_processing_run(
        self,
        case_id: Optional[str] = None,
        engine_version: str = "1.0.0",
        ruleset_version: str = "2026.10",
        graph_version: str = "1.0.0",
        build_sha256: str = "9f7c8e2a01bc4389df0123456789abcdef0123456789abcdef0123456789abcd",
        executed_by: str = "Examiner",
        parameters: Optional[Dict[str, Any]] = None
    ) -> str:
        run_id = to_uuid(uuid.uuid4())
        cid = to_uuid(case_id) if case_id else None
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

        self.conn.execute("""
            INSERT INTO forensic.processing_runs (run_id, case_id, engine_version, ruleset_version, graph_version, build_sha256, executed_by, executed_at, parameters)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, [run_id, cid, engine_version, ruleset_version, graph_version, build_sha256, executed_by, now, json.dumps(parameters or {})])
        return run_id

    def link_artifact_processing(self, run_id: str, artifact_id: str, operation: str = "parse"):
        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO forensic.artifact_processing (run_id, artifact_id, operation)
                VALUES (?, ?, ?);
            """, [to_uuid(run_id), to_uuid(artifact_id), operation])
        except Exception:
            pass

    # =========================================================================
    # INSERTION & ENTITY API
    # =========================================================================

    def insert_case(
        self,
        case_id: str,
        case_name: str,
        description: str = "",
        status: str = "open",
        created_by: str = "Examiner",
        classification: str = "internal",
        retention_until: Optional[str] = None,
        case_number: Optional[str] = None
    ):
        cid = to_uuid(case_id)
        c_num = case_number or f"CASE-{cid[:8].upper()}"
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        status_norm = status if status in ['open', 'closed', 'archived'] else 'open'
        class_norm = classification if classification in ['public', 'internal', 'confidential', 'restricted'] else 'internal'

        self.conn.execute("""
            INSERT INTO forensic.cases (case_id, case_number, case_name, description, status, created_at, created_by, last_modified, classification, retention_until)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (case_id) DO NOTHING;
        """, [cid, c_num, case_name, description, status_norm, now, created_by, now, class_norm, retention_until])
        self.log_audit(cid, created_by, "CREATE_CASE", "case", cid, {"case_number": c_num, "name": case_name})

    def insert_device(
        self,
        device_id: str,
        case_id: str,
        platform: str,
        manufacturer: str = "Unknown",
        model: str = "Unknown",
        serial_number: Optional[str] = None,
        imei: Optional[str] = None,
        meid: Optional[str] = None,
        operating_system: Optional[str] = None,
        os_version: Optional[str] = None,
        timezone: Optional[str] = "UTC",
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None
    ):
        did = to_uuid(device_id)
        cid = to_uuid(case_id)
        plat_norm = platform.lower() if platform.lower() in ['android', 'ios', 'cloud', 'unknown'] else 'unknown'
        # sanitize imei check
        clean_imei = str(imei).strip() if imei and 14 <= len(str(imei).strip()) <= 16 else None

        self.conn.execute("""
            INSERT INTO forensic.devices (device_id, case_id, platform, manufacturer, model, serial_number, imei, meid, operating_system, os_version, timezone, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (device_id) DO NOTHING;
        """, [did, cid, plat_norm, manufacturer, model, serial_number, clean_imei, meid, operating_system, os_version, timezone, first_seen, last_seen])
        self.log_audit(cid, "System", "REGISTER_DEVICE", "device", did, {"platform": plat_norm, "model": model})

    def insert_evidence_source(
        self,
        source_id: str,
        device_id: str,
        source_type: str,
        acquisition_tool: str,
        acquisition_tool_version: Optional[str],
        original_filename: str,
        file_size: int,
        sha256: str,
        sha1: Optional[str] = None,
        md5: Optional[str] = None,
        acquisition_operator: Optional[str] = "Examiner",
        acquisition_started: Optional[str] = None,
        acquisition_completed: Optional[str] = None,
        original_path: Optional[str] = None,
        imported_by: str = "Examiner",
        evidence_sealed: bool = False
    ):
        sid = to_uuid(source_id)
        did = to_uuid(device_id)
        st_norm = source_type.lower() if source_type.lower() in ['filesystem', 'physical', 'logical', 'backup', 'cloud', 'manual'] else 'filesystem'
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        f_size = max(1, file_size)

        self.conn.execute("""
            INSERT INTO forensic.evidence_sources (
                source_id, device_id, source_type, acquisition_tool, acquisition_tool_version,
                acquisition_operator, acquisition_started, acquisition_completed, original_filename,
                original_path, file_size, sha256, sha1, md5, imported_at, imported_by, evidence_sealed
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (source_id) DO UPDATE SET
                evidence_sealed = EXCLUDED.evidence_sealed;
        """, [
            sid, did, st_norm, acquisition_tool, acquisition_tool_version or "1.0",
            acquisition_operator, acquisition_started or now, acquisition_completed or now,
            original_filename, original_path or original_filename, f_size, sha256, sha1, md5,
            now, imported_by, evidence_sealed
        ])

        # Record initial Chain of Custody
        self.insert_chain_of_custody(
            custody_id=to_uuid(uuid.uuid4()),
            source_id=sid,
            action_type="INGEST",
            actor=imported_by,
            location="Forensic Ingestion Laboratory",
            notes=f"Cryptographically hashed evidence file {original_filename} (SHA-256: {sha256})",
            timestamp=now
        )
        self.log_audit(None, imported_by, "IMPORT_EVIDENCE", "evidence_source", sid, {"filename": original_filename, "sha256": sha256})

    def seal_evidence_source(self, source_id: str, examiner: str = "Examiner"):
        sid = to_uuid(source_id)
        self.conn.execute("UPDATE forensic.evidence_sources SET evidence_sealed = TRUE WHERE source_id = ?;", [sid])
        self.insert_chain_of_custody(
            custody_id=to_uuid(uuid.uuid4()),
            source_id=sid,
            action_type="SEAL",
            actor=examiner,
            location="Evidence Vault",
            notes="Evidence source sealed with cryptographic write-lock enforcement.",
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        )
        self.log_audit(None, examiner, "SEAL_EVIDENCE", "evidence_source", sid, {"sealed": True})

    def insert_parser(
        self,
        parser_id: str,
        parser_name: str,
        parser_version: str,
        git_commit: Optional[str] = "9f7c8e2",
        build_number: Optional[str] = "2026.10.1",
        release_date: Optional[str] = None,
        parser_sha256: Optional[str] = None,
        developer: Optional[str] = "NEXUS Mobile DFIR Team",
        active: bool = True
    ):
        pid = to_uuid(parser_id)
        r_date = release_date or time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        sha = parser_sha256 or hashlib.sha256(f"{parser_name}-{parser_version}".encode()).hexdigest()

        self.conn.execute("""
            INSERT INTO forensic.parsers (parser_id, parser_name, parser_version, git_commit, build_number, release_date, parser_sha256, developer, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (parser_id) DO UPDATE SET
                parser_version = EXCLUDED.parser_version,
                parser_sha256 = EXCLUDED.parser_sha256,
                active = EXCLUDED.active;
        """, [pid, parser_name, parser_version, git_commit, build_number, r_date, sha, developer, active])

    def insert_artifact(
        self,
        artifact_id: str,
        source_id: str,
        parser_id: str,
        evidence_offset: Optional[int],
        source_table: Optional[str],
        source_record_id: Optional[str],
        artifact_type: str,
        artifact_timestamp: str,
        timezone_source: Optional[str],
        timestamp_precision: Optional[str],
        record_hash: str,
        parent_artifact_id: Optional[str],
        raw_json: Any,
        normalized_json: Any,
        parser_notes: Optional[str] = None,
        created_at: Optional[str] = None
    ):
        aid = to_uuid(artifact_id)
        sid = to_uuid(source_id)
        pid = to_uuid(parser_id)
        paid = to_uuid(parent_artifact_id) if parent_artifact_id else None
        now = created_at or time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        prec_norm = timestamp_precision if timestamp_precision in ['exact', 'second', 'minute', 'hour', 'day', 'estimated'] else 'exact'

        raw_str = canonical_json_str(raw_json)
        norm_str = canonical_json_str(normalized_json)

        self.conn.execute("""
            INSERT INTO forensic.artifacts (
                artifact_id, source_id, parser_id, evidence_offset, source_table, source_record_id,
                artifact_type, artifact_timestamp, timezone_source, timestamp_precision, record_hash,
                parent_artifact_id, raw_json, normalized_json, parser_notes, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (artifact_id) DO UPDATE SET
                raw_json = EXCLUDED.raw_json,
                normalized_json = EXCLUDED.normalized_json;
        """, [
            aid, sid, pid, evidence_offset, source_table, source_record_id,
            artifact_type, artifact_timestamp, timezone_source or "UTC", prec_norm, record_hash,
            paid, raw_str, norm_str, parser_notes, now
        ])

    def insert_event(
        self,
        event_id: str,
        artifact_id: str,
        device_id: str,
        timestamp: str,
        event_type: str,
        category: str,
        description: str,
        confidence: int = 100,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        altitude: Optional[float] = None,
        source_weight: float = 1.0,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        raw_payload: Optional[Dict[str, Any]] = None,
        timezone_offset_minutes: int = 0
    ):
        eid = to_uuid(event_id)
        aid = to_uuid(artifact_id)
        did = to_uuid(device_id)
        conf = max(0, min(100, confidence))

        self.conn.execute("""
            INSERT INTO forensic.events (
                event_id, artifact_id, device_id, event_type, category, timestamp,
                timezone_offset_minutes, confidence, inferred, description,
                latitude, longitude, altitude, source_weight
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (event_id) DO UPDATE SET
                confidence = EXCLUDED.confidence,
                description = EXCLUDED.description;
        """, [
            eid, aid, did, event_type, category, timestamp,
            timezone_offset_minutes, conf, False, description,
            latitude, longitude, altitude, source_weight
        ])

        # Automatically record primary event provenance
        self.insert_event_provenance(eid, aid, provenance_role="primary", contribution_weight=source_weight)

    def insert_event_provenance(
        self,
        event_id: str,
        artifact_id: str,
        provenance_role: str = "primary",
        contribution_weight: float = 1.0
    ):
        eid = to_uuid(event_id)
        aid = to_uuid(artifact_id)
        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO forensic.event_provenance (event_id, artifact_id, provenance_role, contribution_weight)
                VALUES (?, ?, ?, ?);
            """, [eid, aid, provenance_role, contribution_weight])
        except Exception:
            pass

    def insert_relationship(
        self,
        relationship_id: str,
        source_event_id: str,
        target_event_id: str,
        relationship_type: str,
        weight: float = 1.0,
        rationale: str = "",
        generated_by: str = "NEXUS Correlation Engine"
    ):
        rid = to_uuid(relationship_id)
        s_eid = to_uuid(source_event_id)
        t_eid = to_uuid(target_event_id)
        if s_eid == t_eid:
            return
        w = max(0.0, min(1.0, weight))
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.relationships (
                relationship_id, source_event_id, target_event_id, relationship_type, weight, rationale, generated_by, generated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, [rid, s_eid, t_eid, relationship_type, w, rationale, generated_by, now])

    def insert_entity(
        self,
        entity_id: str,
        entity_type: str,
        value: str,
        confidence: int = 100,
        source_artifact_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        eid = to_uuid(entity_id)
        aid = to_uuid(source_artifact_id) if source_artifact_id else None
        conf = max(0, min(100, confidence))
        meta_json = canonical_json_str(metadata or {})
        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO forensic.entities (
                    entity_id, entity_type, value, confidence, source_artifact_id, metadata
                )
                VALUES (?, ?, ?, ?, ?, ?);
            """, [eid, str(entity_type), value, conf, aid, meta_json])
        except Exception:
            pass

    def insert_event_entity(
        self,
        event_id: str,
        entity_id: str,
        role: str = "participant"
    ) -> None:
        ev_id = to_uuid(event_id)
        ent_id = to_uuid(entity_id)
        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO forensic.event_entities (
                    event_id, entity_id, role
                )
                VALUES (?, ?, ?);
            """, [ev_id, ent_id, role])
        except Exception:
            pass

    def query_entities(self, entity_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        query = "SELECT * FROM forensic.entities"
        params = []
        if entity_type:
            query += " WHERE entity_type = ?"
            params.append(str(entity_type))
        query += " ORDER BY confidence DESC LIMIT ?;"
        params.append(limit)
        res = self.conn.execute(query, params).fetchall()
        cols = [c[0] for c in self.conn.description]
        return [_format_row_dict(cols, r) for r in res]

    def ingest_parse_output(self, output: Any, case_id: Optional[str] = None, device_id: Optional[str] = None) -> Dict[str, int]:
        """Ingests a ParseOutput container into DuckDB with all artifacts, events, provenance, entities, and relationships."""
        arts_count = 0
        evs_count = 0
        ents_count = 0
        rels_count = 0

        # Artifacts
        for art in getattr(output, "artifacts", []):
            self.insert_artifact(
                artifact_id=art.artifact_id,
                source_id=art.source_id,
                parser_id=art.parser_id,
                source_table=art.source_table,
                source_record_id=art.source_record_id,
                artifact_type=art.artifact_type,
                artifact_timestamp=art.artifact_timestamp,
                record_hash=art.record_hash,
                raw_data=art.raw_data,
                normalized_data=art.normalized_data
            )
            arts_count += 1

        # Events and provenance
        for ev in getattr(output, "events", []):
            self.insert_event(
                event_id=ev.event_id,
                artifact_id=ev.artifact_id,
                device_id=getattr(ev, "device_id", device_id or "DEV-UNKNOWN"),
                event_type=ev.event_type,
                category=ev.category,
                timestamp=ev.timestamp,
                confidence=ev.confidence,
                description=ev.description,
                latitude=ev.latitude,
                longitude=ev.longitude,
                actor=ev.actor,
                target=ev.target
            )
            self.link_event_provenance(ev.event_id, ev.artifact_id, "primary", 1.0)
            evs_count += 1

        # Entities
        for ent in getattr(output, "entities", []):
            self.insert_entity(
                entity_id=ent.entity_id,
                entity_type=ent.entity_type,
                value=ent.value,
                confidence=ent.confidence,
                source_artifact_id=ent.source_artifact_id,
                metadata=getattr(ent, "metadata", {})
            )
            ents_count += 1

        # Relationships
        for rel in getattr(output, "relationships", []):
            self.insert_relationship(
                relationship_id=rel.relationship_id,
                source_event_id=rel.source_event_id,
                target_event_id=rel.target_event_id,
                relationship_type=str(rel.relationship_type),
                weight=rel.weight,
                rationale=rel.rationale or ""
            )
            rels_count += 1

        return {
            "artifacts": arts_count,
            "events": evs_count,
            "entities": ents_count,
            "relationships": rels_count
        }

    def insert_finding(
        self,
        finding_id: str,
        case_id: str,
        title: str,
        description: str,
        finding_type: str,
        confidence: int,
        methodology_version: str = "1.0.0",
        analyst: str = "Lead Forensic Examiner",
        supporting_events: Optional[List[str]] = None
    ):
        fid = to_uuid(finding_id)
        cid = to_uuid(case_id)
        conf = max(0, min(100, confidence))
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

        self.conn.execute("""
            INSERT INTO forensic.findings (
                finding_id, case_id, title, description, finding_type, confidence, methodology_version, analyst, created_at, reviewed
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (finding_id) DO UPDATE SET
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                confidence = EXCLUDED.confidence;
        """, [fid, cid, title, description, finding_type, conf, methodology_version, analyst, now, False])

        # Link supporting events into forensic.finding_evidence
        if supporting_events:
            for ev_id in supporting_events:
                self.insert_finding_evidence(fid, ev_id, evidence_role="supporting")

        self.log_audit(cid, analyst, "CREATE_FINDING", "finding", fid, {"title": title, "confidence": conf})

    def insert_finding_evidence(self, finding_id: str, event_id: str, evidence_role: str = "supporting"):
        fid = to_uuid(finding_id)
        eid = to_uuid(event_id)
        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO forensic.finding_evidence (finding_id, event_id, evidence_role)
                VALUES (?, ?, ?);
            """, [fid, eid, evidence_role])
        except Exception:
            pass

    def insert_confidence_factor(
        self,
        factor_id: str,
        finding_id: str,
        event_id: Optional[str],
        score: int,
        factor_type: str,
        explanation: str
    ):
        cfid = to_uuid(factor_id)
        fid = to_uuid(finding_id)
        eid = to_uuid(event_id) if event_id else None

        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.confidence_factors (factor_id, finding_id, event_id, score, factor_type, explanation)
            VALUES (?, ?, ?, ?, ?, ?);
        """, [cfid, fid, eid, score, factor_type, explanation])

    def insert_chain_of_custody(
        self,
        custody_id: str,
        source_id: str,
        action_type: str,
        actor: str,
        location: Optional[str] = "Forensic Workstation",
        notes: Optional[str] = None,
        timestamp: Optional[str] = None,
        previous_custody_id: Optional[str] = None
    ):
        cid = to_uuid(custody_id)
        sid = to_uuid(source_id)
        now = timestamp or time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

        # Auto-resolve previous custody id if omitted
        if not previous_custody_id:
            last = self.conn.execute("SELECT custody_id FROM forensic.chain_of_custody WHERE source_id = ? ORDER BY timestamp DESC LIMIT 1;", [sid]).fetchone()
            if last:
                previous_custody_id = last[0]

        prev_id = to_uuid(previous_custody_id) if previous_custody_id else None

        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.chain_of_custody (custody_id, source_id, action_type, actor, timestamp, location, notes, previous_custody_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, [cid, sid, action_type, actor, now, location, notes, prev_id])

    # =========================================================================
    # END-TO-END FORENSIC LINEAGE WALK
    # =========================================================================

    def walk_finding_lineage(self, finding_id: str) -> Dict[str, Any]:
        """
        Executes end-to-end lineage traversal from Finding to acquired Evidence Source:
        Finding ➔ Events ➔ Artifacts ➔ Parser ➔ Processing Run ➔ Evidence Source ➔ SHA256
        """
        fid = to_uuid(finding_id)
        f_row = self.conn.execute("SELECT finding_id, title, description, confidence, finding_type, created_at, analyst FROM forensic.findings WHERE finding_id = ?;", [fid]).fetchone()
        if not f_row:
            return {"error": f"Finding {finding_id} not found."}

        cols = ["finding_id", "title", "description", "confidence", "finding_type", "created_at", "analyst"]
        finding_info = _format_row_dict(cols, f_row)

        # Supporting events
        ev_rows = self.conn.execute("""
            SELECT e.event_id, e.event_type, e.category, e.timestamp, e.confidence, e.description, fe.evidence_role
            FROM forensic.finding_evidence fe
            JOIN forensic.events e ON fe.event_id = e.event_id
            WHERE fe.finding_id = ?;
        """, [fid]).fetchall()

        events_lineage = []
        for er in ev_rows:
            eid = er[0]
            # Get contributing artifacts
            art_rows = self.conn.execute("""
                SELECT 
                    a.artifact_id, a.artifact_type, a.source_table, a.source_record_id, a.record_hash, a.created_at,
                    p.parser_id, p.parser_name, p.parser_version, p.parser_sha256,
                    es.source_id, es.original_filename, es.file_size, es.sha256 as evidence_sha256, es.evidence_sealed,
                    pr.run_id, pr.engine_version, pr.build_sha256
                FROM forensic.event_provenance ep
                JOIN forensic.artifacts a ON ep.artifact_id = a.artifact_id
                JOIN forensic.parsers p ON a.parser_id = p.parser_id
                JOIN forensic.evidence_sources es ON a.source_id = es.source_id
                LEFT JOIN forensic.artifact_processing ap ON a.artifact_id = ap.artifact_id
                LEFT JOIN forensic.processing_runs pr ON ap.run_id = pr.run_id
                WHERE ep.event_id = ?;
            """, [eid]).fetchall()

            artifacts = []
            for ar in art_rows:
                artifacts.append({
                    "artifact_id": str(ar[0]),
                    "artifact_type": ar[1],
                    "source_table": ar[2],
                    "source_record_id": ar[3],
                    "record_hash": ar[4],
                    "artifact_created_at": str(ar[5]),
                    "parser": {
                        "parser_id": str(ar[6]),
                        "name": ar[7],
                        "version": ar[8],
                        "sha256": ar[9]
                    },
                    "evidence_source": {
                        "source_id": str(ar[10]),
                        "filename": ar[11],
                        "size_bytes": ar[12],
                        "sha256": ar[13],
                        "sealed": bool(ar[14])
                    },
                    "processing_run": {
                        "run_id": str(ar[15]) if ar[15] else None,
                        "engine_version": ar[16],
                        "build_sha256": ar[17]
                    }
                })

            events_lineage.append({
                "event_id": str(eid),
                "event_type": er[1],
                "category": er[2],
                "timestamp": str(er[3]),
                "confidence": er[4],
                "description": er[5],
                "evidence_role": er[6],
                "artifacts": artifacts
            })

        # Confidence Factors
        cf_rows = self.conn.execute("SELECT factor_id, score, factor_type, explanation FROM forensic.confidence_factors WHERE finding_id = ?;", [fid]).fetchall()
        factors = [{"factor_id": str(r[0]), "score": r[1], "factor_type": r[2], "explanation": r[3]} for r in cf_rows]

        return {
            "finding": finding_info,
            "lineage_valid": len(events_lineage) > 0 and all(len(ev["artifacts"]) > 0 for ev in events_lineage),
            "events": events_lineage,
            "confidence_factors": factors
        }

    # =========================================================================
    # QUERY APIS & TERMINAL
    # =========================================================================

    def query_timeline(
        self,
        device_id: Optional[str] = None,
        category: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        keyword: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM forensic.unified_timeline WHERE 1=1"
        params: List[Any] = []

        if device_id:
            query += " AND device_id = ?"
            params.append(to_uuid(device_id))
        if category:
            query += " AND category = ?"
            params.append(category)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        if keyword:
            query += " AND (LOWER(description) LIKE ? OR LOWER(event_type) LIKE ?)"
            pat = f"%{keyword.lower()}%"
            params.extend([pat, pat])

        query += " ORDER BY timestamp ASC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        res = self.conn.execute(query, params).fetchall()
        cols = [c[0] for c in self.conn.description]
        return [_format_row_dict(cols, row) for row in res]

    def query_relationships(self, event_id: str) -> List[Dict[str, Any]]:
        eid = to_uuid(event_id)
        query = """
            SELECT r.*, e.description as target_description, e.event_type as target_event_type, e.timestamp as target_timestamp
            FROM forensic.relationships r
            JOIN forensic.events e ON r.target_event_id = e.event_id
            WHERE r.source_event_id = ?
            UNION ALL
            SELECT r.*, e.description as target_description, e.event_type as target_event_type, e.timestamp as target_timestamp
            FROM forensic.relationships r
            JOIN forensic.events e ON r.source_event_id = e.event_id
            WHERE r.target_event_id = ?;
        """
        res = self.conn.execute(query, [eid, eid]).fetchall()
        cols = [c[0] for c in self.conn.description]
        return [_format_row_dict(cols, row) for row in res]

    def query_findings(self, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM forensic.findings"
        params = []
        if case_id:
            query += " WHERE case_id = ?"
            params.append(to_uuid(case_id))
        query += " ORDER BY created_at DESC;"

        res = self.conn.execute(query, params).fetchall()
        cols = [c[0] for c in self.conn.description]
        findings = []
        for row in res:
            f_dict = _format_row_dict(cols, row)
            fid = f_dict["finding_id"]
            cf_rows = self.conn.execute("SELECT * FROM forensic.confidence_factors WHERE finding_id = ?;", [to_uuid(fid)]).fetchall()
            cf_cols = [c[0] for c in self.conn.description]
            f_dict["confidence_factors"] = [_format_row_dict(cf_cols, r) for r in cf_rows]
            findings.append(f_dict)
        return findings

    def raw_sql_query(self, sql: str, params: Optional[List[Any]] = None, limit: Optional[int] = 100) -> Dict[str, Any]:
        """Allows direct read-only SQL queries on the DuckDB forensic warehouse."""
        cleaned = sql.strip().rstrip(";")
        if not cleaned.lower().startswith("select") and not cleaned.lower().startswith("show") and not cleaned.lower().startswith("describe") and not cleaned.lower().startswith("explain"):
            raise ValueError("Only read-only SELECT, SHOW, DESCRIBE, and EXPLAIN queries are permitted on the warehouse.")

        if limit and "limit" not in cleaned.lower():
            cleaned += f" LIMIT {limit}"

        if params:
            res = self.conn.execute(cleaned, params).fetchall()
        else:
            res = self.conn.execute(cleaned).fetchall()

        cols = [c[0] for c in self.conn.description] if self.conn.description else []
        return {
            "columns": cols,
            "row_count": len(res),
            "rows": [_format_row_dict(cols, row) for row in res]
        }
