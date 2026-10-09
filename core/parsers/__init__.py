"""
NexusForensics Mobile™ | Mobile Artifact Genome (Parser Registry)
Zimmerman-style ecosystem of single-purpose parsers.
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
from ..models import ArtifactModel, EventModel

PARSERS: List[BaseArtifactParser] = [
    AndroidSMSParser(),
    AndroidCallLogParser(),
    IOSMobileSMSParser(),
    IOSKnowledgeCParser(),
    IOSSafariHistoryParser(),
    NexusProxyBundleParser()
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
