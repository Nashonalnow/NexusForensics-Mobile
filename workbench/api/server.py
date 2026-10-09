#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Interactive Forensic Daemon & DFIR API
Serves live mobile artifact triage, SQLite examination, IoC detection, and NIST SP 800-86 chain of custody.
Strict Copper Standard: 100% authentic evidence hashes, schemas, and timestamps.
"""

import os
import sys
import time
import json
import shutil
import hashlib
import zipfile
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

from core.models import CaseMetadata, EvidenceArtifact, ChainOfCustodyRecord, TimelineEvent, ThreatIndicator
from core.evidence_ingestor import EvidenceIngestor
from core.sqlite_inspector import SQLiteInspector
from core.android_parser import AndroidForensicsParser
from core.ios_parser import IOSForensicsParser
from core.ioc_scanner import ThreatIoCScanner
from core.timeline_engine import TimelineEngine

app = FastAPI(
    title="NexusForensics Mobile™",
    description="Mobile Digital Forensics, Artifact Carving & NIST SP 800-86 Incident Response Core",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Forensic Subsystems
ingestor = EvidenceIngestor(storage_dir=PROJECT_ROOT / "evidence")
sqlite_inspector = SQLiteInspector()
android_parser = AndroidForensicsParser()
ios_parser = IOSForensicsParser()
ioc_scanner = ThreatIoCScanner()
timeline_engine = TimelineEngine()

# Active Investigation Case State
active_case = CaseMetadata(
    case_id="CASE-2026-NEXUS-01",
    title="Mobile Security & Forensic Incident Triage",
    examiner="Lead Forensic Investigator",
    organization="Enterprise DFIR & Security Operations",
    notes="Authorized forensic examination of mobile testbeds and network telemetry."
)

# Threat findings collection
all_findings: List[ThreatIndicator] = []

# Models for API requests
class CaseUpdateRequest(BaseModel):
    title: Optional[str] = None
    examiner: Optional[str] = None
    organization: Optional[str] = None
    notes: Optional[str] = None

class IngestPathRequest(BaseModel):
    file_path: str
    origin: Optional[str] = "Manual"
    notes: Optional[str] = None

class SQLiteInspectRequest(BaseModel):
    artifact_id: str

class SQLiteQueryRequest(BaseModel):
    artifact_id: str
    table_name: str
    limit: Optional[int] = 50
    offset: Optional[int] = 0

# 1. Status & Overview
@app.get("/api/status")
def get_status():
    devices = android_parser.get_connected_devices()
    tl_stats = timeline_engine.get_summary_stats()
    artifacts = ingestor.get_all_artifacts()

    return {
        "status": "OPERATIONAL",
        "version": "0.1.0",
        "case": active_case.model_dump(),
        "total_artifacts": len(artifacts),
        "total_timeline_events": tl_stats["total_events"],
        "total_findings": len(all_findings),
        "connected_android_devices": len(devices),
        "nist_compliance": "NIST SP 800-86 Compliant",
        "evidence_storage_path": str(ingestor.storage_dir)
    }

# 2. Case Management
@app.post("/api/case/update")
def update_case(req: CaseUpdateRequest):
    global active_case
    if req.title: active_case.title = req.title
    if req.examiner: active_case.examiner = req.examiner
    if req.organization: active_case.organization = req.organization
    if req.notes is not None: active_case.notes = req.notes
    return {"status": "SUCCESS", "case": active_case.model_dump()}

# 3. Live Device Discovery (ADB)
@app.get("/api/devices")
def get_devices():
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

# 4. Evidence Ingestion: Local File Path
@app.post("/api/ingest/file")
def ingest_file_by_path(req: IngestPathRequest):
    p = Path(req.file_path).resolve()
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {p}")

    artifact = ingestor.ingest_file(
        p,
        origin=req.origin or "Manual",
        examiner=active_case.examiner,
        case_id=active_case.case_id,
        metadata={"notes": req.notes}
    )

    # Post-ingestion automated artifact triage
    _auto_triage_artifact(artifact)

    return {"status": "SUCCESS", "artifact": artifact.model_dump()}

# 5. Evidence Ingestion: Multipart File Upload
@app.post("/api/ingest/upload")
async def upload_evidence(file: UploadFile = File(...), origin: str = "Upload"):
    dest = ingestor.storage_dir / file.filename
    with open(dest, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    artifact = ingestor.ingest_file(
        dest,
        origin=origin,
        examiner=active_case.examiner,
        case_id=active_case.case_id
    )

    # Post-ingestion automated artifact triage
    _auto_triage_artifact(artifact)

    return {"status": "SUCCESS", "artifact": artifact.model_dump()}

# 6. Evidence Ingestion: NexusProxy-Mobile Package
@app.post("/api/ingest/nexusproxy")
def ingest_nexusproxy_bundle(bundle_path: Optional[str] = None):
    target_path = None
    if bundle_path:
        target_path = Path(bundle_path)
    else:
        # Check standard /tmp/nexusproxy_exports directory
        exp_dir = Path("/tmp/nexusproxy_exports")
        if exp_dir.exists():
            zips = sorted(list(exp_dir.glob("engagement_*.zip")), key=os.path.getmtime, reverse=True)
            if zips:
                target_path = zips[0]

    if not target_path or not target_path.exists():
        raise HTTPException(
            status_code=404,
            detail="No NexusProxy-Mobile engagement bundle found. Please export from NexusProxy-Mobile first or supply path."
        )

    artifact, verification, tl_events = ingestor.ingest_nexusproxy_bundle(
        target_path,
        examiner=active_case.examiner,
        case_id=active_case.case_id
    )

    # Add timeline events
    timeline_engine.add_events(tl_events)

    # Scan for IoCs
    manifest = artifact.metadata.get("manifest", {})
    # If requests were recorded, scan them
    raw_txs = []
    with zipfile.ZipFile(target_path, "r") as z:
        for name in z.namelist():
            if name.startswith("requests/"):
                req_text = z.read(name).decode("utf-8", errors="replace")
                lines = req_text.split("\n")
                first = lines[0] if lines else ""
                parts = first.split(" ")
                m = parts[0] if parts else "GET"
                p = parts[1] if len(parts) > 1 else "/"
                h = "unknown"
                for line in lines:
                    if line.lower().startswith("host:"):
                        h = line.split(":", 1)[1].strip()
                        break
                raw_txs.append({"id": name, "method": m, "path": p, "host": h, "request_raw": req_text})

    ioc_findings = ioc_scanner.scan_network_telemetry(raw_txs)
    all_findings.extend(ioc_findings)

    return {
        "status": "SUCCESS",
        "artifact": artifact.model_dump(),
        "verification": verification,
        "timeline_events_ingested": len(tl_events),
        "ioc_findings": [f.model_dump() for f in ioc_findings]
    }

def _auto_triage_artifact(artifact: EvidenceArtifact):
    """Automatically parses and indexes ingested SQLite, APK, or Plist files."""
    path = Path(artifact.file_path)
    ext = path.suffix.lower()

    # 1. SQLite Triage
    if ext in [".db", ".sqlite", ".sqlite3"]:
        try:
            tl = sqlite_inspector.extract_timeline_events(path, artifact.artifact_id)
            timeline_engine.add_events(tl)
        except Exception:
            pass

    # 2. APK Triage
    elif ext in [".apk"]:
        try:
            apk_data = android_parser.parse_apk(path)
            artifact.metadata["apk_details"] = apk_data
            for f in apk_data.get("findings", []):
                all_findings.append(ThreatIndicator(**f))
        except Exception:
            pass

    # 3. Plist Triage
    elif ext in [".plist"]:
        try:
            plist_data = ios_parser.parse_plist(path)
            artifact.metadata["plist_details"] = plist_data
        except Exception:
            pass

# 7. Artifacts Listing
@app.get("/api/artifacts")
def get_artifacts():
    return {"artifacts": [a.model_dump() for a in ingestor.get_all_artifacts()]}

# 8. Chain of Custody (NIST SP 800-86)
@app.get("/api/coc")
def get_chain_of_custody(artifact_id: Optional[str] = None):
    records = ingestor.get_chain_of_custody(artifact_id)
    return {
        "standard": "NIST Special Publication 800-86 Compliant",
        "records": [r.model_dump() for r in records]
    }

# 9. SQLite Inspector Endpoints
@app.post("/api/sqlite/inspect")
def inspect_sqlite(req: SQLiteInspectRequest):
    artifact = ingestor.artifacts.get(req.artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail=f"Artifact {req.artifact_id} not found.")

    p = Path(artifact.file_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Underlying database file not found on disk.")

    try:
        inspection = sqlite_inspector.inspect_database(p)
        return {"status": "SUCCESS", "inspection": inspection}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SQLite inspection error: {e}")

@app.post("/api/sqlite/query")
def query_sqlite(req: SQLiteQueryRequest):
    artifact = ingestor.artifacts.get(req.artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail=f"Artifact {req.artifact_id} not found.")

    p = Path(artifact.file_path)
    try:
        result = sqlite_inspector.query_table(p, req.table_name, limit=req.limit or 50, offset=req.offset or 0)
        return {"status": "SUCCESS", "query_result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SQLite query error: {e}")

# 10. Unified Chronological Timeline
@app.get("/api/timeline")
def get_timeline(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 150
):
    events = timeline_engine.get_timeline(category=category, severity=severity, search_query=search, limit=limit)
    return {
        "total_returned": len(events),
        "events": [e.model_dump() for e in events]
    }

# 11. IoC Threat Findings
@app.get("/api/ioc/findings")
def get_findings():
    return {
        "total_findings": len(all_findings),
        "findings": [f.model_dump() for f in all_findings]
    }

# 12. Forensic Report & Evidence Package Export
@app.post("/api/report/export")
def export_forensic_report():
    """Generates comprehensive court-ready forensic report dossier."""
    target_exp = PROJECT_ROOT / "cases" / active_case.case_id / "exports"
    try:
        target_exp.mkdir(parents=True, exist_ok=True)
        exp_dir = target_exp
    except Exception:
        fallback_exp = Path("/tmp/nexusforensics_cases") / active_case.case_id / "exports"
        fallback_exp.mkdir(parents=True, exist_ok=True)
        exp_dir = fallback_exp

    report_file = exp_dir / f"forensic_report_{int(time.time())}.json"
    coc_records = ingestor.get_chain_of_custody()
    artifacts = ingestor.get_all_artifacts()
    timeline = timeline_engine.get_timeline(limit=500)

    dossier = {
        "title": "NIST SP 800-86 Mobile Forensics Dossier",
        "generated_at": int(time.time()),
        "case": active_case.model_dump(),
        "integrity_seal": {
            "total_artifacts": len(artifacts),
            "artifacts_verified": sum(1 for a in artifacts if a.integrity_status == "VERIFIED"),
            "chain_of_custody_steps": len(coc_records)
        },
        "artifacts": [a.model_dump() for a in artifacts],
        "chain_of_custody": [c.model_dump() for c in coc_records],
        "ioc_findings": [f.model_dump() for f in all_findings],
        "timeline_events": [t.model_dump() for t in timeline]
    }

    report_file.write_text(json.dumps(dossier, indent=2), encoding="utf-8")
    report_sha = hashlib.sha256(report_file.read_bytes()).hexdigest()

    return {
        "status": "SUCCESS",
        "report_file": str(report_file),
        "sha256": report_sha,
        "dossier": dossier
    }

# Mount static frontend
STATIC_DIR = PROJECT_ROOT / "workbench" / "app"
if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
