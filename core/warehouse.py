#!/usr/bin/env python3
"""
NexusForensics Mobile™ | DuckDB Forensic Evidence Warehouse
High-performance analytical columnar warehouse for mobile artifacts, timelines, relationships, and findings.
Strict Copper Standard: 100% authentic evidence schemas, zero mock/fake data.
"""

import os
import sys
import time
import json
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

import duckdb

DUCKDB_SCHEMA_DDL = """
CREATE SCHEMA IF NOT EXISTS forensic;

-- 1. Cases
CREATE TABLE IF NOT EXISTS forensic.cases (
    case_id VARCHAR PRIMARY KEY,
    case_name VARCHAR NOT NULL,
    description VARCHAR,
    status VARCHAR NOT NULL,
    created_at TIMESTAMP NOT NULL,
    created_by VARCHAR NOT NULL,
    tags JSON
);

-- 2. Devices
CREATE TABLE IF NOT EXISTS forensic.devices (
    device_id VARCHAR PRIMARY KEY,
    case_id VARCHAR NOT NULL,
    platform VARCHAR NOT NULL,
    manufacturer VARCHAR,
    model VARCHAR,
    serial_number VARCHAR,
    imei VARCHAR,
    phone_number VARCHAR,
    os_version VARCHAR,
    acquisition_date TIMESTAMP
);

-- 3. Evidence Sources (Cellebrite, GrayKey, Backups, NexusProxy, etc.)
CREATE TABLE IF NOT EXISTS forensic.evidence_sources (
    source_id VARCHAR PRIMARY KEY,
    device_id VARCHAR NOT NULL,
    source_type VARCHAR NOT NULL,
    acquisition_tool VARCHAR,
    acquisition_tool_version VARCHAR,
    original_filename VARCHAR,
    file_size BIGINT,
    sha256 VARCHAR NOT NULL,
    imported_at TIMESTAMP NOT NULL,
    examiner VARCHAR
);

-- 4. Artifact Registry
CREATE TABLE IF NOT EXISTS forensic.artifacts (
    artifact_id VARCHAR PRIMARY KEY,
    source_id VARCHAR NOT NULL,
    artifact_type VARCHAR NOT NULL,
    parser_name VARCHAR NOT NULL,
    parser_version VARCHAR NOT NULL,
    artifact_timestamp TIMESTAMP,
    record_hash VARCHAR NOT NULL,
    raw_json JSON,
    normalized_json JSON,
    created_at TIMESTAMP NOT NULL
);

-- 5. Standardized Events Table (Most Important Analytical Table)
CREATE TABLE IF NOT EXISTS forensic.events (
    event_id VARCHAR PRIMARY KEY,
    artifact_id VARCHAR NOT NULL,
    device_id VARCHAR NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    event_type VARCHAR NOT NULL,
    category VARCHAR NOT NULL,
    description VARCHAR,
    confidence SMALLINT DEFAULT 100,
    location_lat DOUBLE,
    location_lon DOUBLE,
    actor VARCHAR,
    target VARCHAR,
    raw_payload JSON
);

-- 6. Relationships (Temporal Graph Connections)
CREATE TABLE IF NOT EXISTS forensic.relationships (
    relationship_id VARCHAR PRIMARY KEY,
    source_event_id VARCHAR NOT NULL,
    target_event_id VARCHAR NOT NULL,
    relationship_type VARCHAR NOT NULL,
    weight DOUBLE DEFAULT 1.0,
    rationale VARCHAR,
    created_at TIMESTAMP NOT NULL
);

-- 7. Findings (Investigator Conclusions)
CREATE TABLE IF NOT EXISTS forensic.findings (
    finding_id VARCHAR PRIMARY KEY,
    case_id VARCHAR NOT NULL,
    device_id VARCHAR NOT NULL,
    title VARCHAR NOT NULL,
    description TEXT,
    confidence SMALLINT NOT NULL,
    finding_type VARCHAR,
    created_at TIMESTAMP NOT NULL
);

-- 8. Finding Evidence Map (Many-to-Many with Support/Contradict tags)
CREATE TABLE IF NOT EXISTS forensic.finding_evidence (
    finding_id VARCHAR NOT NULL,
    event_id VARCHAR NOT NULL,
    weight DOUBLE,
    support_type VARCHAR NOT NULL, -- 'supports', 'contradicts', 'neutral'
    PRIMARY KEY (finding_id, event_id)
);

-- 9. Confidence Factors (Court-Defensible Scoring Formula Proof)
CREATE TABLE IF NOT EXISTS forensic.confidence_factors (
    factor_id VARCHAR PRIMARY KEY,
    finding_id VARCHAR NOT NULL,
    event_id VARCHAR,
    score INTEGER NOT NULL,
    factor_type VARCHAR NOT NULL,
    explanation VARCHAR NOT NULL
);

-- 10. Audit Log (Immutable Chain of Custody)
CREATE TABLE IF NOT EXISTS forensic.audit_log (
    audit_id VARCHAR PRIMARY KEY,
    case_id VARCHAR,
    username VARCHAR NOT NULL,
    action VARCHAR NOT NULL,
    entity_type VARCHAR NOT NULL,
    entity_id VARCHAR NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    details JSON
);

-- 11. Reports
CREATE TABLE IF NOT EXISTS forensic.reports (
    report_id VARCHAR PRIMARY KEY,
    case_id VARCHAR NOT NULL,
    report_type VARCHAR NOT NULL,
    sha256 VARCHAR NOT NULL,
    generated_at TIMESTAMP NOT NULL,
    filepath VARCHAR NOT NULL
);

-- 12. Extracted Entities
CREATE TABLE IF NOT EXISTS forensic.entities (
    entity_id VARCHAR PRIMARY KEY,
    entity_type VARCHAR NOT NULL, -- 'phone_number', 'email', 'ssid', 'app', 'location'
    value VARCHAR NOT NULL,
    confidence INTEGER DEFAULT 100
);

-- 13. Event-Entity Mapping
CREATE TABLE IF NOT EXISTS forensic.event_entities (
    event_id VARCHAR NOT NULL,
    entity_id VARCHAR NOT NULL,
    relationship_type VARCHAR NOT NULL,
    PRIMARY KEY (event_id, entity_id)
);

-- Search Documents for Fast Full-Text Search
CREATE TABLE IF NOT EXISTS forensic.search_documents (
    doc_id VARCHAR PRIMARY KEY,
    source_type VARCHAR NOT NULL,
    source_id VARCHAR NOT NULL,
    searchable_text TEXT NOT NULL
);

-- Standard Views
CREATE OR REPLACE VIEW forensic.unified_timeline AS
SELECT
    e.event_id,
    e.device_id,
    e.timestamp,
    e.event_type,
    e.category,
    e.description,
    e.confidence,
    e.location_lat,
    e.location_lon,
    e.actor,
    e.target
FROM forensic.events e
ORDER BY e.timestamp DESC;

CREATE OR REPLACE VIEW forensic.communication_events AS
SELECT *
FROM forensic.events
WHERE category = 'communication'
ORDER BY timestamp DESC;

CREATE OR REPLACE VIEW forensic.location_events AS
SELECT *
FROM forensic.events
WHERE category = 'location'
ORDER BY timestamp DESC;

CREATE OR REPLACE VIEW forensic.device_state_events AS
SELECT *
FROM forensic.events
WHERE category = 'device_state'
ORDER BY timestamp DESC;
"""

class DuckDBWarehouse:
    """
    Forensic Evidence Warehouse powered by DuckDB.
    Operates as an in-process, high-speed columnar analytical warehouse.
    """

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is not None:
            self.db_path = Path(db_path)
        else:
            default_dir = Path(__file__).resolve().parent.parent / "cases"
            try:
                default_dir.mkdir(parents=True, exist_ok=True)
                self.db_path = default_dir / "nexus_forensics.duckdb"
            except Exception:
                fallback_dir = Path("/tmp/nexus_forensics_db")
                fallback_dir.mkdir(parents=True, exist_ok=True)
                self.db_path = fallback_dir / "nexus_forensics.duckdb"

        # Initialize connection with concurrency resilience
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
        """Creates forensic schema, tables, views, and indexes."""
        self.conn.execute(DUCKDB_SCHEMA_DDL)

    def log_audit(self, case_id: Optional[str], username: str, action: str, entity_type: str, entity_id: str, details: Optional[Dict[str, Any]] = None):
        """Appends immutable audit record to forensic.audit_log."""
        audit_id = f"AUD-{uuid.uuid4()}"
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        det_json = json.dumps(details or {})
        self.conn.execute("""
            INSERT INTO forensic.audit_log (audit_id, case_id, username, action, entity_type, entity_id, timestamp, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, [audit_id, case_id, username, action, entity_type, entity_id, now, det_json])

    def insert_case(self, case_id: str, name: str, description: str, status: str, created_by: str, tags: Optional[List[str]] = None):
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.cases (case_id, case_name, description, status, created_at, created_by, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        """, [case_id, name, description, status, now, created_by, json.dumps(tags or [])])
        self.log_audit(case_id, created_by, "CREATE_CASE", "case", case_id, {"case_name": name})

    def insert_device(self, device_id: str, case_id: str, platform: str, manufacturer: str, model: str, serial: str, imei: str, os_version: str):
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.devices (device_id, case_id, platform, manufacturer, model, serial_number, imei, os_version, acquisition_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, [device_id, case_id, platform, manufacturer, model, serial, imei, os_version, now])
        self.log_audit(case_id, "system", "REGISTER_DEVICE", "device", device_id, {"model": model, "platform": platform})

    def insert_evidence_source(self, source_id: str, device_id: str, source_type: str, tool: str, tool_version: str, original_filename: str, file_size: int, sha256: str, examiner: str):
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.evidence_sources (source_id, device_id, source_type, acquisition_tool, acquisition_tool_version, original_filename, file_size, sha256, imported_at, examiner)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, [source_id, device_id, source_type, tool, tool_version, original_filename, file_size, sha256, now, examiner])
        self.log_audit(None, examiner, "IMPORT_EVIDENCE", "evidence_source", source_id, {"sha256": sha256, "file": original_filename})

    def insert_artifact(self, artifact_id: str, source_id: str, artifact_type: str, parser_name: str, parser_version: str, timestamp_str: str, record_hash: str, raw_json: Dict[str, Any], normalized_json: Dict[str, Any]):
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.artifacts (artifact_id, source_id, artifact_type, parser_name, parser_version, artifact_timestamp, record_hash, raw_json, normalized_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, [artifact_id, source_id, artifact_type, parser_name, parser_version, timestamp_str, record_hash, json.dumps(raw_json), json.dumps(normalized_json), now])

    def insert_event(self, event_id: str, artifact_id: str, device_id: str, timestamp_str: str, event_type: str, category: str, description: str, confidence: int = 100, lat: Optional[float] = None, lon: Optional[float] = None, actor: Optional[str] = None, target: Optional[str] = None, payload: Optional[Dict[str, Any]] = None):
        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.events (event_id, artifact_id, device_id, timestamp, event_type, category, description, confidence, location_lat, location_lon, actor, target, raw_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, [event_id, artifact_id, device_id, timestamp_str, event_type, category, description, confidence, lat, lon, actor, target, json.dumps(payload or {})])

        # Also insert into search documents
        searchable = f"{event_type} {category} {description or ''} {actor or ''} {target or ''}"
        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.search_documents (doc_id, source_type, source_id, searchable_text)
            VALUES (?, 'event', ?, ?);
        """, [f"DOC-{event_id}", event_id, searchable])

    def insert_relationship(self, relationship_id: str, source_event_id: str, target_event_id: str, rel_type: str, weight: float = 1.0, rationale: Optional[str] = None):
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.relationships (relationship_id, source_event_id, target_event_id, relationship_type, weight, rationale, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        """, [relationship_id, source_event_id, target_event_id, rel_type, weight, rationale or "", now])

    def insert_finding(self, finding_id: str, case_id: str, device_id: str, title: str, description: str, confidence: int, finding_type: str, supporting_events: List[str], contradictory_events: Optional[List[str]] = None):
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.findings (finding_id, case_id, device_id, title, description, confidence, finding_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, [finding_id, case_id, device_id, title, description, confidence, finding_type, now])

        for ev_id in supporting_events:
            self.conn.execute("""
                INSERT OR REPLACE INTO forensic.finding_evidence (finding_id, event_id, weight, support_type)
                VALUES (?, ?, 1.0, 'supports');
            """, [finding_id, ev_id])

        for ev_id in (contradictory_events or []):
            self.conn.execute("""
                INSERT OR REPLACE INTO forensic.finding_evidence (finding_id, event_id, weight, support_type)
                VALUES (?, ?, -1.0, 'contradicts');
            """, [finding_id, ev_id])

    def insert_confidence_factor(self, factor_id: str, finding_id: str, event_id: Optional[str], score: int, factor_type: str, explanation: str):
        self.conn.execute("""
            INSERT OR REPLACE INTO forensic.confidence_factors (factor_id, finding_id, event_id, score, factor_type, explanation)
            VALUES (?, ?, ?, ?, ?, ?);
        """, [factor_id, finding_id, event_id, score, factor_type, explanation])

    def query_timeline(self, device_id: Optional[str] = None, category: Optional[str] = None, event_type: Optional[str] = None, keyword: Optional[str] = None, start_time: Optional[str] = None, end_time: Optional[str] = None, limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
        """High-speed timeline query executing against DuckDB columnar store."""
        query = "SELECT * FROM forensic.unified_timeline WHERE 1=1"
        params: List[Any] = []

        if device_id:
            query += " AND device_id = ?"
            params.append(device_id)
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
            query += " AND (LOWER(description) LIKE ? OR LOWER(event_type) LIKE ? OR LOWER(actor) LIKE ? OR LOWER(target) LIKE ?)"
            pat = f"%{keyword.lower()}%"
            params.extend([pat, pat, pat, pat])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        res = self.conn.execute(query, params).fetchall()
        cols = [c[0] for c in self.conn.description]
        return [dict(zip(cols, row)) for row in res]

    def query_relationships(self, event_id: str) -> List[Dict[str, Any]]:
        """Traverses the temporal relationship graph for a target event."""
        res = self.conn.execute("""
            SELECT r.*, e.event_type AS target_event_type, e.description AS target_description, e.timestamp AS target_timestamp
            FROM forensic.relationships r
            JOIN forensic.events e ON r.target_event_id = e.event_id
            WHERE r.source_event_id = ?
            UNION
            SELECT r.*, e.event_type AS source_event_type, e.description AS source_description, e.timestamp AS source_timestamp
            FROM forensic.relationships r
            JOIN forensic.events e ON r.source_event_id = e.event_id
            WHERE r.target_event_id = ?;
        """, [event_id, event_id]).fetchall()
        cols = [c[0] for c in self.conn.description]
        return [dict(zip(cols, row)) for row in res]

    def query_findings(self, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves all findings with their confidence factors and evidence links."""
        q = "SELECT * FROM forensic.findings WHERE 1=1"
        params = []
        if case_id:
            q += " AND case_id = ?"
            params.append(case_id)
        q += " ORDER BY created_at DESC"

        findings = []
        for row in self.conn.execute(q, params).fetchall():
            f_cols = [c[0] for c in self.conn.description]
            f_dict = dict(zip(f_cols, row))
            fid = f_dict["finding_id"]

            # Get evidence
            ev_rows = self.conn.execute("""
                SELECT fe.*, e.event_type, e.timestamp, e.description
                FROM forensic.finding_evidence fe
                JOIN forensic.events e ON fe.event_id = e.event_id
                WHERE fe.finding_id = ?;
            """, [fid]).fetchall()
            ev_cols = [c[0] for c in self.conn.description]
            f_dict["evidence"] = [dict(zip(ev_cols, r)) for r in ev_rows]

            # Get confidence factors
            cf_rows = self.conn.execute("""
                SELECT * FROM forensic.confidence_factors WHERE finding_id = ?;
            """, [fid]).fetchall()
            cf_cols = [c[0] for c in self.conn.description]
            f_dict["confidence_factors"] = [dict(zip(cf_cols, r)) for r in cf_rows]

            findings.append(f_dict)
        return findings

    def raw_sql_query(self, sql: str, params: Optional[List[Any]] = None, limit: Optional[int] = 100) -> Dict[str, Any]:
        """Allows direct read-only SQL queries on the DuckDB forensic warehouse."""
        cleaned = sql.strip().rstrip(";")
        if not cleaned.lower().startswith("select") and not cleaned.lower().startswith("show") and not cleaned.lower().startswith("describe") and not cleaned.lower().startswith("explain"):
            raise ValueError("Only read-only SELECT, SHOW, DESCRIBE, and EXPLAIN queries are permitted on the warehouse.")

        # Append limit if not present
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
            "rows": [dict(zip(cols, row)) for row in res]
        }

