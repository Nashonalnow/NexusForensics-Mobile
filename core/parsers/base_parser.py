#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Base Artifact Parser Contract
Zimmerman-philosophy: many small, focused, single-purpose parsers with first-class lineage.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
import uuid
import hashlib
import inspect

from ..models import ArtifactModel, EventModel

class BaseArtifactParser(ABC):
    """
    Abstract contract for artifact parsers.
    Parses a source file and yields (ArtifactModel, List[EventModel]).
    Every parser provides deterministic UUID, version, git commit, and SHA-256 hash.
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

    @property
    def parser_id(self) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nexus.parser.{self.parser_name}.{self.parser_version}"))

    @property
    def parser_sha256(self) -> str:
        try:
            src = inspect.getsource(self.__class__).encode("utf-8")
            return hashlib.sha256(src).hexdigest()
        except Exception:
            return hashlib.sha256(self.parser_name.encode("utf-8")).hexdigest()

    @property
    def developer(self) -> str:
        return "NEXUS Mobile DFIR Team"

    @property
    def git_commit(self) -> str:
        return "9f7c8e2"

    @property
    def build_number(self) -> str:
        return "2026.10.1"

    @property
    def release_date(self) -> str:
        return "2026-10-09 00:00:00"

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Determines if this parser is capable of parsing the target file."""
        pass

    @abstractmethod
    def parse(self, file_path: Path, source_id: str, device_id: str) -> List[Tuple[ArtifactModel, List[EventModel]]]:
        """Parses the target artifact and yields artifact models and generated timeline events."""
        pass
