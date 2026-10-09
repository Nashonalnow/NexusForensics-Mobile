# NexusForensics Mobile™

> **Enterprise Mobile Digital Forensics & Incident Response (DFIR) Platform**  
> Paired companion workbench for **NexusProxy-Mobile™** • NIST SP 800-86 Compliant • Copper Standard Certified

---

## 1. Overview & Mission

**NexusForensics Mobile™** is an on-device and workstation-grade digital forensics investigation workbench purpose-built for authorized mobile security testing, post-incident triage, and evidentiary artifact carving. 

While **NexusProxy-Mobile** operates inline as a live L7 traffic interception proxy, **NexusForensics-Mobile** functions as the forensic examination node:
1. Ingesting and cryptographically verifying NexusProxy engagement bundles (`engagement_*.zip`) with automated SHA-256 seal validation.
2. Carving SQLite databases with Write-Ahead Log (`-wal`) and Shared Memory (`-shm`) journal triage.
3. Auditing Android APK manifests, dangerous permissions, and live ADB hardware properties.
4. Parsing Apple iOS iTunes/Finder backups, binary plists, and `Manifest.db` domain mappings.
5. Reconstructing unified chronological forensic timelines across network, database, and filesystem telemetry.
6. Detecting commercial stalkerware, spyware implants, and mobile C2 indicators with MITRE ATT&CK for Mobile mappings.
7. Generating court-admissible forensic dossiers adhering to **NIST SP 800-86** Chain of Custody standards.

---

## 2. Architecture & Ecosystem

```
+───────────────────────────────────────────────────────────────────────────────+
|                        MOBILE DFIR INVESTIGATION SUITE                        |
+───────────────────────────────────────────────────────────────────────────────+
|                                                                               |
|   ┌──────────────────────────┐             ┌──────────────────────────────┐   |
|   │   NexusProxy-Mobile™     │             │    NexusForensics Mobile™    │   |
|   │   (Port 8095)            │             │    (Port 8096)               │   |
|   ├──────────────────────────┤             ├──────────────────────────────┤   |
|   │ • L7 HTTP/S Intercept    │             │ • NIST SP 800-86 Chain of    │   |
|   │ • Request Repeater       │  1-Click    │   Custody Ledger             │   |
|   │ • Root CA Trust Manager  │  Ingestion  │ • Forensic SQLite & WAL      │   |
|   │ • Evidence ZIP Export    ├────────────►│   Journal Inspector          │   |
|   │   (/tmp/nexusproxy_      │             │ • Threat & Stalkerware IoCs  │   |
|   │    exports)              │             │ • Chronological Timeline     │   |
|   └──────────────────────────┘             │ • Live ADB Testbed Triage    │   |
|                                            └──────────────────────────────┘   |
|                                                           │                   |
|                                                           ▼                   |
|                                            ┌──────────────────────────────┐   |
|                                            │ Signed Forensic Dossier      │   |
|                                            │ (JSON / HTML Export)         │   |
|                                            └──────────────────────────────┘   |
+───────────────────────────────────────────────────────────────────────────────+
```

---

## 3. Quickstart & Usage

### Launch Interactive Forensic Workbench
```bash
python3 workbench/launch_workbench.py 8096
```
Open your browser to: **`http://localhost:8096`**

### Command-Line Forensic Utility (`bin/forensics_cli`)
```bash
# Ingest any evidence file (hashes and logs chain of custody)
./bin/forensics_cli ingest /path/to/telephony.db --case CASE-2026-001

# 1-Click Ingest latest NexusProxy-Mobile engagement package
./bin/forensics_cli ingest-nexusproxy

# Forensic SQLite inspection
./bin/forensics_cli sqlite /path/to/sms.db

# Android APK security audit
./bin/forensics_cli apk /path/to/suspicious_app.apk

# iOS iTunes backup inspection
./bin/forensics_cli ios-backup /path/to/ios_backup_dir/

# Discover connected Android testbeds via ADB
./bin/forensics_cli devices
```

---

## 4. Standards & Compliance

- **NIST SP 800-86**: Adheres strictly to the National Institute of Standards and Technology Guide to Integrating Forensic Techniques into Incident Response. Every ingested artifact generates an immutable Chain of Custody entry recording timestamps, examiners, actions, and SHA-256 hashes.
- **Copper Standard Rule**: Never creates fake, simulated, or mock data. All file hashes, schemas, table records, and device parameters are 100% authentic and extracted directly from source artifacts.
- **Fail-Safe Sockets**: Implements automated port supervisors (`port_manager.py`) with pre-flight clearance and OS signal traps (`SIGINT`, `SIGTERM`, `atexit`), preventing lingering processes and `[Errno 98]` bind errors.
