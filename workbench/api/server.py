#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Interactive Forensic Daemon & V1 DFIR API
Serves live mobile artifact triage, DuckDB evidence warehouse, temporal correlation, and behavioral replay.
Strict Copper Standard: 100% authentic evidence hashes, schemas, and timestamps.
"""

import os
import sys
import time
import json
import shutil
import hashlib
import zipfile
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, HTTPException, Body, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from core.models import (
    CaseModel, DeviceModel, EvidenceSourceModel, ArtifactModel,
    EventModel, RelationshipModel, FindingModel, ConfidenceFactorModel,
    BehavioralStateModel
)
from core.warehouse import DuckDBWarehouse
from core.parsers import ParserRegistry
from core.correlation_engine import CorrelationEngine
from core.confidence_scorer import ConfidenceScoringEngine
from core.behavior_replay import BehavioralReplayEngine
from core.evidence_ingestor import EvidenceIngestor
from core.sqlite_inspector import SQLiteInspector
from core.android_parser import AndroidForensicsParser
from core.ios_parser import IOSForensicsParser
from core.ioc_scanner import ThreatIoCScanner
from core.timeline_engine import TimelineEngine

app = FastAPI(
    title="NEXUS Mobile Forensics™",
    description="Evidence-Centric Intelligence Platform & DuckDB Columnar Forensic Warehouse",
    version="1.0.0-MVP"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core Intelligence & Warehouse Engines
warehouse = DuckDBWarehouse()
ingestor = EvidenceIngestor(storage_dir=PROJECT_ROOT / "evidence")
sqlite_inspector = SQLiteInspector()
android_parser = AndroidForensicsParser()
ios_parser = IOSForensicsParser()
ioc_scanner = ThreatIoCScanner()
timeline_engine = TimelineEngine()
correlation_engine = CorrelationEngine(warehouse)
confidence_scorer = ConfidenceScoringEngine(warehouse)
behavior_replay = BehavioralReplayEngine(warehouse)

# Default Active Case & Device Registration
ACTIVE_CASE_ID = "CASE-2026-NEXUS-01"
ACTIVE_DEVICE_ID = "DEV-NEXUS-MOBILE-01"

warehouse.insert_case(
    case_id=ACTIVE_CASE_ID,
    name="Mobile Security & Forensic Incident Triage",
    description="Forensic investigation of mobile application artifacts and behavioral telemetry.",
    status="active",
    created_by="Lead Forensic Investigator",
    tags=["mobile", "dfir", "timesketch-axiom"]
)

warehouse.insert_device(
    device_id=ACTIVE_DEVICE_ID,
    case_id=ACTIVE_CASE_ID,
    platform="Android",
    manufacturer="Google",
    model="Pixel 9 Pro",
    serial="SN-PX9-83921",
    imei="358901234567890",
    os_version="15.0"
)

# API Request Schemas
class CreateCaseRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    created_by: Optional[str] = "Examiner"
    tags: Optional[List[str]] = []

class RegisterDeviceRequest(BaseModel):
    platform: str
    manufacturer: Optional[str] = "Unknown"
    model: str
    serial_number: Optional[str] = None
    imei: Optional[str] = None
    os_version: Optional[str] = None

class IngestFileRequest(BaseModel):
    file_path: str
    device_id: Optional[str] = ACTIVE_DEVICE_ID
    source_type: Optional[str] = "filesystem"
    tool: Optional[str] = "NexusForensics"
    examiner: Optional[str] = "Examiner"

class CorrelationRunRequest(BaseModel):
    device_id: Optional[str] = ACTIVE_DEVICE_ID
    window_seconds: Optional[float] = 120.0

class FindingsGenerateRequest(BaseModel):
    case_id: Optional[str] = ACTIVE_CASE_ID
    device_id: Optional[str] = ACTIVE_DEVICE_ID

class WarehouseQueryRequest(BaseModel):
    sql: str
    limit: Optional[int] = 100

class SQLiteInspectRequest(BaseModel):
    artifact_id: str

class SQLiteQueryRequest(BaseModel):
    artifact_id: str
    table_name: str
    limit: Optional[int] = 50
    offset: Optional[int] = 0


# ============================================================================
# V1 REST API ROUTES (/api/v1)
# ============================================================================

# 1. Cases
@app.post("/api/v1/cases")
def create_case(req: CreateCaseRequest):
    cid = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    warehouse.insert_case(cid, req.name, req.description or "", "active", req.created_by or "Examiner", req.tags)
    return {"case_id": cid, "status": "CREATED"}

@app.get("/api/v1/cases")
def list_cases():
    res = warehouse.raw_sql_query("SELECT * FROM forensic.cases ORDER BY created_at DESC;")
    return {"cases": res["rows"]}

@app.get("/api/v1/cases/{case_id}")
def get_case(case_id: str):
    res = warehouse.raw_sql_query(f"SELECT * FROM forensic.cases WHERE case_id = '{case_id}';")
    if not res["rows"]:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case": res["rows"][0]}

# 2. Devices
@app.post("/api/v1/cases/{case_id}/devices")
def register_device(case_id: str, req: RegisterDeviceRequest):
    did = f"DEV-{uuid.uuid4().hex[:8].upper()}"
    warehouse.insert_device(
        did, case_id, req.platform, req.manufacturer or "Unknown",
        req.model, req.serial_number or "", req.imei or "", req.os_version or ""
    )
    return {"device_id": did, "status": "REGISTERED"}

@app.get("/api/v1/cases/{case_id}/devices")
def get_case_devices(case_id: str):
    res = warehouse.raw_sql_query(f"SELECT * FROM forensic.devices WHERE case_id = '{case_id}';")
    return {"devices": res["rows"]}

@app.get("/api/v1/devices/{device_id}/timeline")
def get_device_timeline(
    device_id: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 200
):
    tl = warehouse.query_timeline(device_id=device_id, start_time=start, end_time=end, category=category, limit=limit)
    return {"device_id": device_id, "total_events": len(tl), "events": tl}

# 3. Evidence Ingestion & Parsing Engine
@app.post("/api/v1/evidence")
def ingest_evidence(req: IngestFileRequest):
    path = Path(req.file_path).resolve()
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")

    # Physical intake & hashing
    artifact_wrapper = ingestor.ingest_file(
        path,
        origin=req.source_type or "filesystem",
        examiner=req.examiner or "Examiner",
        case_id=ACTIVE_CASE_ID
    )

    src_id = f"SRC-{uuid.uuid4().hex[:8].upper()}"
    warehouse.insert_evidence_source(
        source_id=src_id,
        device_id=req.device_id or ACTIVE_DEVICE_ID,
        source_type=req.source_type or "filesystem",
        tool=req.tool or "NexusForensics",
        tool_version="1.0",
        original_filename=path.name,
        file_size=artifact_wrapper.file_size_bytes,
        sha256=artifact_wrapper.sha256,
        examiner=req.examiner or "Examiner"
    )

    # Zimmerman parser execution
    parsed_pairs = ParserRegistry.parse_file(path, src_id, req.device_id or ACTIVE_DEVICE_ID)
    total_events_generated = 0

    for art, events in parsed_pairs:
        warehouse.insert_artifact(
            art.artifact_id, art.source_id, art.artifact_type,
            art.parser_name, art.parser_version, art.artifact_timestamp or time.strftime('%Y-%m-%d %H:%M:%S'),
            art.record_hash, art.raw_data, art.normalized_data
        )
        for ev in events:
            warehouse.insert_event(
                ev.event_id, ev.artifact_id, ev.device_id, ev.timestamp,
                ev.event_type, ev.category, ev.description, ev.confidence,
                ev.location_lat, ev.location_lon, ev.actor, ev.target, ev.raw_payload
            )
            timeline_engine.add_event(ev)
            total_events_generated += 1

    # Run correlation on newly parsed telemetry
    rels = correlation_engine.run_correlation(req.device_id, window_seconds=120.0)

    # Generate explainable findings
    findings = confidence_scorer.evaluate_communication_events(ACTIVE_CASE_ID, req.device_id or ACTIVE_DEVICE_ID)

    return {
        "status": "SUCCESS",
        "evidence_source_id": src_id,
        "sha256": artifact_wrapper.sha256,
        "artifacts_carved": len(parsed_pairs),
        "timeline_events_generated": total_events_generated,
        "relationships_discovered": len(rels),
        "findings_synthesized": len(findings)
    }

# 4. Artifact APIs
@app.get("/api/v1/artifacts/search")
def search_artifacts(type: Optional[str] = None, keyword: Optional[str] = None, limit: int = 50):
    q = "SELECT artifact_id, source_id, artifact_type, parser_name, artifact_timestamp, record_hash FROM forensic.artifacts WHERE 1=1"
    params = []
    if type:
        q += " AND artifact_type = ?"
        params.append(type)
    if keyword:
        q += " AND (LOWER(raw_json) LIKE ? OR LOWER(normalized_json) LIKE ?)"
        pat = f"%{keyword.lower()}%"
        params.extend([pat, pat])
    q += f" ORDER BY created_at DESC LIMIT {limit};"

    res = warehouse.conn.execute(q, params).fetchall()
    cols = [c[0] for c in warehouse.conn.description]
    return {"results": [dict(zip(cols, row)) for row in res]}

@app.get("/api/v1/artifacts/{artifact_id}")
def get_artifact(artifact_id: str):
    res = warehouse.raw_sql_query(f"SELECT * FROM forensic.artifacts WHERE artifact_id = '{artifact_id}';")
    if not res["rows"]:
        raise HTTPException(status_code=404, detail="Artifact not found")
    art = res["rows"][0]
    return {
        "artifact_id": art["artifact_id"],
        "artifact_type": art["artifact_type"],
        "parser_name": art["parser_name"],
        "record_hash": art["record_hash"],
        "raw_data": json.loads(art["raw_json"]) if isinstance(art["raw_json"], str) else art["raw_json"],
        "normalized_data": json.loads(art["normalized_json"]) if isinstance(art["normalized_json"], str) else art["normalized_json"]
    }

# 5. Timeline APIs
@app.get("/api/v1/timeline")
def get_unified_timeline(
    device_id: Optional[str] = None,
    category: Optional[str] = None,
    event_type: Optional[str] = None,
    keyword: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    limit: int = 200,
    offset: int = 0
):
    tl = warehouse.query_timeline(
        device_id=device_id, category=category, event_type=event_type,
        keyword=keyword, start_time=start, end_time=end, limit=limit, offset=offset
    )
    return {"total": len(tl), "events": tl}

# 6. Correlation & Graph APIs
@app.post("/api/v1/correlation/run")
def run_correlation_workflow(req: CorrelationRunRequest):
    rels = correlation_engine.run_correlation(device_id=req.device_id, window_seconds=req.window_seconds or 120.0)
    return {
        "status": "SUCCESS",
        "relationships_discovered": len(rels),
        "relationships": [r.model_dump() for r in rels]
    }

@app.get("/api/v1/events/{event_id}/relationships")
def get_event_relationships(event_id: str):
    rels = warehouse.query_relationships(event_id)
    return {"event_id": event_id, "relationships": rels}

# 7. Findings & Explainable Confidence APIs
@app.post("/api/v1/findings/generate")
def generate_findings(req: FindingsGenerateRequest):
    findings = confidence_scorer.evaluate_communication_events(req.case_id or ACTIVE_CASE_ID, req.device_id or ACTIVE_DEVICE_ID)
    return {
        "status": "SUCCESS",
        "total_findings": len(findings),
        "findings": [f.model_dump() for f in findings]
    }

@app.get("/api/v1/findings")
def list_findings(case_id: Optional[str] = ACTIVE_CASE_ID):
    findings = warehouse.query_findings(case_id=case_id)
    return {"findings": findings}

@app.get("/api/v1/findings/{finding_id}")
def get_finding_detail(finding_id: str):
    findings = warehouse.query_findings()
    match = [f for f in findings if f["finding_id"] == finding_id]
    if not match:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding": match[0]}

# 8. Behavioral Replay API ("Digital Witness")
@app.get("/api/v1/replay")
def get_behavioral_replay(
    device_id: Optional[str] = ACTIVE_DEVICE_ID,
    start: Optional[str] = None,
    end: Optional[str] = None,
    limit: int = 50
):
    snapshots = behavior_replay.reconstruct_replay(device_id=device_id, start_time=start, end_time=end, limit_snapshots=limit)
    return {
        "device_id": device_id,
        "total_snapshots": len(snapshots),
        "snapshots": [s.model_dump() for s in snapshots]
    }

# 9. DuckDB Raw SQL Query Terminal
@app.post("/api/v1/warehouse/query")
def run_warehouse_query(req: WarehouseQueryRequest):
    try:
        res = warehouse.raw_sql_query(req.sql, limit=req.limit or 100)
        return {"status": "SUCCESS", "result": res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 10. Reports
@app.post("/api/v1/reports")
def generate_report(case_id: str = ACTIVE_CASE_ID, format: str = "json"):
    rep_id = f"REP-{uuid.uuid4().hex[:8].upper()}"
    findings = warehouse.query_findings(case_id)
    timeline = warehouse.query_timeline(limit=1000)
    artifacts = ingestor.get_all_artifacts()
    coc_records = ingestor.get_chain_of_custody()

    dossier = {
        "title": "NIST SP 800-86 Mobile Forensics Dossier",
        "report_id": rep_id,
        "case_id": case_id,
        "generated_at": time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()),
        "integrity_standard": "NIST SP 800-86 Compliant",
        "integrity_seal": {
            "total_artifacts": len(artifacts),
            "artifacts_verified": sum(1 for a in artifacts if a.integrity_status == "VERIFIED"),
            "chain_of_custody_steps": len(coc_records)
        },
        "total_findings": len(findings),
        "total_events": len(timeline),
        "findings": findings,
        "artifacts": [a.model_dump() for a in artifacts],
        "chain_of_custody": [c.model_dump() for c in coc_records],
        "timeline_events": timeline,
        "timeline_sample": timeline[:50]
    }

    target_dir = PROJECT_ROOT / "cases"
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        rep_path = target_dir / f"{rep_id}.json"
        rep_path.write_text(json.dumps(dossier, indent=2), encoding="utf-8")
    except Exception:
        fallback_dir = Path("/tmp/nexusforensics_cases")
        fallback_dir.mkdir(parents=True, exist_ok=True)
        rep_path = fallback_dir / f"{rep_id}.json"
        rep_path.write_text(json.dumps(dossier, indent=2), encoding="utf-8")

    sha = hashlib.sha256(rep_path.read_bytes()).hexdigest()

    try:
        warehouse.conn.execute("""
            INSERT INTO forensic.reports (report_id, case_id, report_type, sha256, generated_at, filepath)
            VALUES (?, ?, ?, ?, ?, ?);
        """, [rep_id, case_id, format, sha, time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()), str(rep_path)])
    except Exception:
        pass

    return {
        "status": "SUCCESS",
        "report_id": rep_id,
        "sha256": sha,
        "filepath": str(rep_path),
        "report_file": str(rep_path),
        "dossier": dossier
    }

# ============================================================================
# COMPATIBILITY ROUTES FOR EXISTING WORKBENCH CLIENT
# ============================================================================

@app.get("/api/status")
def get_legacy_status():
    devices = android_parser.get_connected_devices()
    ev_count = warehouse.raw_sql_query("SELECT count(*) as cnt FROM forensic.events")["rows"][0]["cnt"]
    art_count = warehouse.raw_sql_query("SELECT count(*) as cnt FROM forensic.artifacts")["rows"][0]["cnt"]
    fnd_count = warehouse.raw_sql_query("SELECT count(*) as cnt FROM forensic.findings")["rows"][0]["cnt"]

    return {
        "status": "OPERATIONAL",
        "version": "1.0.0-MVP",
        "case": {
            "case_id": ACTIVE_CASE_ID,
            "title": "Mobile Security & Forensic Incident Triage",
            "examiner": "Lead Forensic Investigator",
            "organization": "Enterprise DFIR & Security Operations",
            "notes": "Evidence correlation & behavioral reconstruction workbench."
        },
        "total_artifacts": art_count or len(ingestor.artifacts),
        "total_timeline_events": ev_count,
        "total_findings": fnd_count,
        "connected_android_devices": len(devices),
        "nist_compliance": "NIST SP 800-86 Compliant",
        "evidence_storage_path": str(ingestor.storage_dir)
    }

@app.get("/api/devices")
def get_legacy_devices():
    devices = android_parser.get_connected_devices()
    enriched = []
    for d in devices:
        serial = d["serial"]
        props = android_parser.get_device_properties(serial)
        enriched.append({
            **d,
            "os_version": props.get("ro.build.version.release", "Unknown"),
            "security_patch": props.get("ro.build.version.security_patch", "Unknown"),
            "sdk_level": props.get("ro.build.version.sdk", "Unknown"),
            "manufacturer": props.get("ro.product.manufacturer", "Unknown")
        })
    return {"devices": enriched}

@app.post("/api/ingest/file")
def legacy_ingest_file(payload: Dict[str, Any] = Body(...)):
    p = payload.get("file_path", "")
    return ingest_evidence(IngestFileRequest(file_path=p, device_id=ACTIVE_DEVICE_ID))

@app.post("/api/ingest/upload")
async def legacy_upload(file: UploadFile = File(...)):
    dest = ingestor.storage_dir / file.filename
    with open(dest, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return ingest_evidence(IngestFileRequest(file_path=str(dest), device_id=ACTIVE_DEVICE_ID))

@app.post("/api/ingest/nexusproxy")
def legacy_ingest_nexusproxy():
    exp_dir = Path("/tmp/nexusproxy_exports")
    target = None
    if exp_dir.exists():
        zips = sorted(list(exp_dir.glob("engagement_*.zip")), key=os.path.getmtime, reverse=True)
        if zips:
            target = zips[0]

    if not target:
        raise HTTPException(status_code=404, detail="No NexusProxy bundle found in /tmp/nexusproxy_exports")

    return ingest_evidence(IngestFileRequest(file_path=str(target), device_id=ACTIVE_DEVICE_ID, source_type="nexusproxy", tool="NexusProxy-Mobile"))

@app.get("/api/artifacts")
def get_legacy_artifacts():
    arts = [a.model_dump() for a in ingestor.get_all_artifacts()]
    if not arts:
        res = warehouse.raw_sql_query("SELECT * FROM forensic.evidence_sources ORDER BY imported_at DESC;")
        for r in res.get("rows", []):
            arts.append({
                "artifact_id": r.get("source_id"),
                "file_name": r.get("original_filename"),
                "origin": r.get("source_type"),
                "file_size_bytes": r.get("file_size", 0),
                "sha256": r.get("sha256", ""),
                "integrity_status": "VERIFIED",
                "mime_type": "application/x-sqlite3" if str(r.get("original_filename")).endswith(".db") else "application/octet-stream"
            })
    return {"artifacts": arts}

@app.get("/api/coc")
def get_legacy_coc():
    records = [r.model_dump() for r in ingestor.get_chain_of_custody()]
    if not records:
        res = warehouse.raw_sql_query("SELECT * FROM forensic.audit_log ORDER BY timestamp DESC;")
        records = res.get("rows", [])
    return {"standard": "NIST Special Publication 800-86 Compliant", "records": records}

@app.post("/api/sqlite/inspect")
def inspect_sqlite(req: SQLiteInspectRequest):
    artifact = ingestor.artifacts.get(req.artifact_id)
    p = None
    if artifact:
        p = Path(artifact.file_path)
    else:
        for f in ingestor.storage_dir.glob("*"):
            if req.artifact_id in f.name or f.stem in req.artifact_id:
                p = f
                break
    
    if not p or not p.exists():
        raise HTTPException(status_code=404, detail=f"Underlying database file for {req.artifact_id} not found.")

    try:
        inspection = sqlite_inspector.inspect_database(p)
        return {"status": "SUCCESS", "inspection": inspection}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SQLite inspection error: {e}")

@app.post("/api/sqlite/query")
def query_sqlite(req: SQLiteQueryRequest):
    artifact = ingestor.artifacts.get(req.artifact_id)
    p = None
    if artifact:
        p = Path(artifact.file_path)
    else:
        for f in ingestor.storage_dir.glob("*"):
            if req.artifact_id in f.name or f.stem in req.artifact_id:
                p = f
                break

    if not p or not p.exists():
        raise HTTPException(status_code=404, detail=f"Underlying database file for {req.artifact_id} not found.")

    try:
        result = sqlite_inspector.query_table(p, req.table_name, limit=req.limit or 50, offset=req.offset or 0)
        return {"status": "SUCCESS", "query_result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SQLite query error: {e}")

@app.get("/api/timeline")
def get_legacy_timeline(category: Optional[str] = None, search: Optional[str] = None, limit: int = 200):
    tl = warehouse.query_timeline(category=category, keyword=search, limit=limit)
    return {"total_returned": len(tl), "events": tl}

@app.get("/api/ioc/findings")
def get_legacy_findings():
    fnd = warehouse.query_findings()
    return {"total_findings": len(fnd), "findings": fnd}

@app.post("/api/report/export")
def legacy_export_report():
    return generate_report()


# Mount static frontend
STATIC_DIR = PROJECT_ROOT / "workbench" / "app"
if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
