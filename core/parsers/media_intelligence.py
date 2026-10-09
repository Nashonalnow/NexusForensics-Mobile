#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Media Intelligence & Screenshot Parser (Tier 5 Priority)
Parses Android MediaStore (media.db / external.db) and iOS Photos (Photos.sqlite) databases.
Answers investigator questions:
- Were screenshots captured (common in fraud, whistleblowing, credential theft, and illicit capture)?
- What photos or images were viewed or cached in thumbnail databases?
- What were the original file paths and capture timestamps?
Strict Copper Standard: 100% authentic schema parsing.
"""

import sqlite3
import hashlib
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

from .base_parser import BaseArtifactParser
from ..models import (
    ArtifactModel,
    EventModel,
    EntityModel,
    RelationshipModel,
    ParseOutput,
    EntityType,
    EventType,
    EventCategory
)

class MediaIntelligenceParser(BaseArtifactParser):
    @property
    def parser_name(self) -> str:
        return "media_intelligence_cache"

    @property
    def artifact_type(self) -> str:
        return "screenshot"

    @property
    def supported_platforms(self) -> List[str]:
        return ["android", "ios"]

    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if not (name.endswith(".db") or name.endswith(".sqlite")):
            return False
        if not ("media" in name or "photo" in name or "external" in name or "gallery" in name or "image" in name):
            return False
        try:
            conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
            c = conn.cursor()
            c.execute("""
                SELECT name FROM sqlite_master WHERE type='table' AND (
                    name='images' OR name='files' OR name='ZGENERICASSET' OR name='media'
                );
            """)
            has_tbl = c.fetchone() is not None
            conn.close()
            return has_tbl
        except Exception:
            return False

    def parse(self, file_path: Path, source_id: str, device_id: str) -> List[Tuple[ArtifactModel, List[EventModel]]]:
        out = self.parse_output(file_path, source_id, device_id)
        pairs: List[Tuple[ArtifactModel, List[EventModel]]] = []
        ev_map: Dict[str, List[EventModel]] = {}
        for ev in out.events:
            ev_map.setdefault(ev.artifact_id, []).append(ev)
        for art in out.artifacts:
            pairs.append((art, ev_map.get(art.artifact_id, [])))
        return pairs

    def parse_output(self, file_path: Path, source_id: str, device_id: str) -> ParseOutput:
        artifacts: List[ArtifactModel] = []
        events: List[EventModel] = []
        entities: List[EntityModel] = []
        relationships: List[RelationshipModel] = []

        conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        try:
            # 1. Android MediaStore (images or files table)
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name='images' OR name='files');")
            tbl = c.fetchone()
            if tbl:
                tname = tbl[0]
                c.execute(f"SELECT * FROM {tname} ORDER BY rowid ASC;")
                rows = c.fetchall()
                for r in rows:
                    raw = dict(r)
                    rec_hash = hashlib.sha256(str(raw).encode("utf-8")).hexdigest()

                    filepath = raw.get("_data") or raw.get("path") or ""
                    filename = raw.get("_display_name") or raw.get("title") or Path(filepath).name or "image.png"
                    is_screenshot = (
                        "screenshot" in filepath.lower() or "screenshot" in filename.lower() or
                        raw.get("is_screenshot") == 1
                    )

                    date_added = raw.get("date_added") or raw.get("date_modified") or time.time()
                    epoch_s = float(date_added) if float(date_added) < 10000000000 else float(date_added) / 1000.0
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))

                    ev_type = EventType.SCREENSHOT_CREATED.value if is_screenshot else EventType.PHOTO_CAPTURED.value
                    desc = f"{'Screenshot captured' if is_screenshot else 'Media asset indexed'}: {filename} ({filepath})"

                    art = ArtifactModel(
                        source_id=source_id,
                        parser_id=self.parser_id,
                        source_table=tname,
                        source_record_id=str(raw.get("_id") or raw.get("rowid") or len(artifacts) + 1),
                        artifact_type=self.artifact_type if is_screenshot else "photo",
                        parser_name=self.parser_name,
                        parser_version=self.parser_version,
                        artifact_timestamp=ts_str,
                        record_hash=rec_hash,
                        raw_data=raw,
                        normalized_data={"filename": filename, "path": filepath, "is_screenshot": is_screenshot}
                    )
                    artifacts.append(art)

                    ev = EventModel(
                        artifact_id=art.artifact_id,
                        device_id=device_id,
                        timestamp=ts_str,
                        event_type=ev_type,
                        category=EventCategory.MEDIA.value,
                        description=desc,
                        confidence=98 if is_screenshot else 95,
                        actor="Device User / Camera / Screen Grabber",
                        target=filename,
                        raw_payload={"path": filepath, "is_screenshot": is_screenshot}
                    )
                    events.append(ev)

            # 2. iOS Photos (ZGENERICASSET table)
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZGENERICASSET';")
            if c.fetchone():
                c.execute("SELECT * FROM ZGENERICASSET ORDER BY Z_PK ASC;")
                rows = c.fetchall()
                for r in rows:
                    raw = dict(r)
                    rec_hash = hashlib.sha256(str(raw).encode("utf-8")).hexdigest()
                    filename = raw.get("ZFILENAME") or "asset.png"
                    asset_type = raw.get("ZSAVEDASSETTYPE", 0)  # 2 = screenshot on iOS
                    is_screenshot = asset_type == 2 or "screenshot" in filename.lower()

                    date_created = raw.get("ZDATECREATED") or 0
                    epoch_s = float(date_created) + 978307200 if float(date_created) < 1000000000 else float(date_created)
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))

                    ev_type = EventType.SCREENSHOT_CREATED.value if is_screenshot else EventType.PHOTO_CAPTURED.value
                    desc = f"iOS {'Screenshot captured' if is_screenshot else 'Photo taken'}: {filename}"

                    art = ArtifactModel(
                        source_id=source_id,
                        parser_id=self.parser_id,
                        source_table="ZGENERICASSET",
                        source_record_id=str(raw.get("Z_PK") or len(artifacts) + 1),
                        artifact_type=self.artifact_type if is_screenshot else "photo",
                        parser_name=self.parser_name,
                        parser_version=self.parser_version,
                        artifact_timestamp=ts_str,
                        record_hash=rec_hash,
                        raw_data=raw,
                        normalized_data={"filename": filename, "asset_type": asset_type, "is_screenshot": is_screenshot}
                    )
                    artifacts.append(art)

                    ev = EventModel(
                        artifact_id=art.artifact_id,
                        device_id=device_id,
                        timestamp=ts_str,
                        event_type=ev_type,
                        category=EventCategory.MEDIA.value,
                        description=desc,
                        confidence=99,
                        actor="iOS User / SpringBoard",
                        target=filename,
                        raw_payload={"filename": filename, "asset_type": asset_type}
                    )
                    events.append(ev)
        finally:
            conn.close()

        return ParseOutput(
            artifacts=artifacts,
            events=events,
            entities=entities,
            relationships=relationships
        )
