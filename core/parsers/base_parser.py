#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Base Artifact Parser Contract
Zimmerman-philosophy: many small, focused, single-purpose parsers.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

from ..models import ArtifactModel, EventModel

class BaseArtifactParser(ABC):
    """
    Abstract contract for artifact parsers.
    Parses a source file and yields (ArtifactModel, List[EventModel]).
    """

    @property
    @abstractmethod
    def parser_name(self) -> str:
        pass

    @property
    @abstractmethod
    def artifact_type(self) -> str:
        pass

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Determines if this parser is capable of parsing the target file."""
        pass

    @abstractmethod
    def parse(self, file_path: Path, source_id: str, device_id: str) -> List[Tuple[ArtifactModel, List[EventModel]]]:
        """Parses the target artifact and yields artifact models and generated timeline events."""
        pass
