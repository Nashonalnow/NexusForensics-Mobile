"""
NexusForensics Mobile™ | Mobile Artifact Genome (Parser Registry)
Zimmerman-style ecosystem of single-purpose parsers.
Enforces the NEXUS Common Parser Contract: Hot-swappable parsers, deterministic processing,
uniform provenance, entity extraction, and self-validating testability.
"""

from pathlib import Path
from typing import List, Tuple, Optional

from .base_parser import BaseArtifactParser
from .android_sms import AndroidSMSParser
from .android_calllog import AndroidCallLogParser
from .ios_sms import IOSMobileSMSParser
from .ios_knowledgec import IOSKnowledgeCParser
from .ios_safari import IOSSafariHistoryParser
from .nexusproxy_bundle import NexusProxyBundleParser

# Wave 2 High-Investigative-Value Parsers
from .android_usagestats import AndroidUsageStatsParser
from .wifi_association import WiFiAssociationParser
from .device_state import DeviceStateParser
from .google_maps import GoogleMapsParser
from .ios_locations import IOSSignificantLocationsParser
from .whatsapp import WhatsAppParser
from .notes import NotesParser
from .calendar import CalendarParser
from .bluetooth import BluetoothParser
from .cell_tower import CellTowerParser
from .media_intelligence import MediaIntelligenceParser
from .messaging_metadata import MessagingAppMetadataParser
from .universal_parser import UniversalFileParser

from ..models import ArtifactModel, EventModel, ParseOutput

PARSERS: List[BaseArtifactParser] = [
    # Wave 1 Foundation Parsers
    AndroidSMSParser(),
    AndroidCallLogParser(),
    IOSMobileSMSParser(),
    IOSKnowledgeCParser(),
    IOSSafariHistoryParser(),
    NexusProxyBundleParser(),

    # Wave 2 Priority Parsers (MVP+1)
    AndroidUsageStatsParser(),
    WiFiAssociationParser(),
    DeviceStateParser(),
    GoogleMapsParser(),
    IOSSignificantLocationsParser(),
    WhatsAppParser(),
    NotesParser(),
    CalendarParser(),
    BluetoothParser(),
    CellTowerParser(),
    MediaIntelligenceParser(),
    MessagingAppMetadataParser(),

    # Universal Evidence Converter & Fallback Carving Engine
    UniversalFileParser()
]

class ParserRegistry:
    @staticmethod
    def get_all_parsers() -> List[BaseArtifactParser]:
        return PARSERS

    @staticmethod
    def find_parser(file_path: Path) -> Optional[BaseArtifactParser]:
        for p in PARSERS:
            try:
                if p.can_parse(file_path):
                    return p
            except Exception:
                continue
        return None

    @staticmethod
    def parse_file(file_path: Path, source_id: str, device_id: str) -> List[Tuple[ArtifactModel, List[EventModel]]]:
        p = ParserRegistry.find_parser(file_path)
        if p:
            return p.parse(file_path, source_id, device_id)
        return []

    @staticmethod
    def parse_file_output(file_path: Path, source_id: str, device_id: str) -> ParseOutput:
        p = ParserRegistry.find_parser(file_path)
        if p:
            if hasattr(p, "parse_output"):
                return p.parse_output(file_path, source_id, device_id)
            else:
                pairs = p.parse(file_path, source_id, device_id)
                artifacts = [a for a, _ in pairs]
                events = [e for _, evs in pairs for e in evs]
                return ParseOutput(artifacts=artifacts, events=events, entities=[], relationships=[])
        return ParseOutput()
