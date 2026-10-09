"""
NexusForensics Mobile™ Core Package
Empirical Mobile Forensics, Evidence Ingestion, SQLite Carving & NIST SP 800-86 Chain of Custody
"""

from .models import (
    CaseMetadata,
    EvidenceArtifact,
    ChainOfCustodyRecord,
    TimelineEvent,
    ThreatIndicator,
    SQLiteTableInfo,
)

__version__ = "0.1.0"
