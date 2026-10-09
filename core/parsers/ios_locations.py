#!/usr/bin/env python3
"""
NexusForensics Mobile™ | iOS Significant Locations & RoutineD Parser (Tier 1 Priority)
Parses Apple LocationD / RoutineD Cache.sqlite databases.
Answers investigator questions:
- Was the suspect device repeatedly present at a specific physical address?
- What were the arrival and departure timestamps of each visit?
- What was Apple's algorithmic visit confidence score?
Strict Copper Standard: 100% authentic schema parsing, Apple 2001 epoch handling.
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

class IOSSignificantLocationsParser(BaseArtifactParser):
    @property
    def parser_name(self) -> str:
        return "ios_significant_locations"

    @property
    def artifact_type(self) -> str:
        return "location"

    @property
    def supported_platforms(self) -> List[str]:
        return ["ios"]

    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if not (name.endswith(".db") or name.endswith(".sqlite")):
            return False
        if not ("cache" in name or "routined" in name or "location" in name or "visit" in name):
            return False
        try:
            conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
            c = conn.cursor()
            c.execute("""
                SELECT name FROM sqlite_master WHERE type='table' AND (
                    name LIKE '%RTVisitMO%' OR name LIKE '%RTLocationMO%' OR name LIKE '%ZRTVISITMO%' OR
                    name LIKE '%RTCachedLocationMO%' OR name LIKE '%location_history%'
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
            # Query CoreData visit tables
            c.execute("""
                SELECT name FROM sqlite_master WHERE type='table' AND (
                    name='ZRTVISITMO' OR name='RTVisitMO' OR name='RTCachedLocationMO' OR name='location_history'
                );
            """)
            tables = [row[0] for row in c.fetchall()]

            for tname in tables:
                c.execute(f"SELECT * FROM {tname} ORDER BY rowid ASC;")
                rows = c.fetchall()
                for r in rows:
                    raw = dict(r)
                    rec_hash = hashlib.sha256(str(raw).encode("utf-8")).hexdigest()

                    # Apple CoreData timestamps start Jan 1 2001 (add 978307200)
                    entry_date = raw.get("ZENTRYDATE") or raw.get("entry_date") or raw.get("timestamp") or 0
                    exit_date = raw.get("ZEXITDATE") or raw.get("exit_date")
                    lat = raw.get("ZLATITUDE") or raw.get("latitude") or raw.get("lat")
                    lon = raw.get("ZLONGITUDE") or raw.get("longitude") or raw.get("lon")
                    conf_raw = raw.get("ZCONFIDENCE") or raw.get("confidence") or 1.0

                    epoch_s = float(entry_date) + 978307200 if float(entry_date) < 1000000000 else float(entry_date)
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))

                    lat_f = float(lat) if lat is not None else None
                    lon_f = float(lon) if lon is not None else None
                    conf_pct = int(float(conf_raw) * 100) if float(conf_raw) <= 1.0 else int(conf_raw)
                    conf_pct = max(10, min(100, conf_pct))

                    desc = f"iOS Significant Location Visit recorded at ({lat_f:.5f}, {lon_f:.5f})" if lat_f and lon_f else "iOS Significant Location Visit recorded"
                    if exit_date:
                        exit_epoch = float(exit_date) + 978307200 if float(exit_date) < 1000000000 else float(exit_date)
                        exit_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exit_epoch))
                        desc += f" (Departed {exit_str})"

                    art = ArtifactModel(
                        source_id=source_id,
                        parser_id=self.parser_id,
                        source_table=tname,
                        source_record_id=str(raw.get("rowid") or raw.get("Z_PK") or len(artifacts) + 1),
                        artifact_type=self.artifact_type,
                        parser_name=self.parser_name,
                        parser_version=self.parser_version,
                        artifact_timestamp=ts_str,
                        record_hash=rec_hash,
                        raw_data=raw,
                        normalized_data={"latitude": lat_f, "longitude": lon_f, "confidence": conf_pct}
                    )
                    artifacts.append(art)

                    ev = EventModel(
                        artifact_id=art.artifact_id,
                        device_id=device_id,
                        timestamp=ts_str,
                        event_type=EventType.VISIT.value,
                        category=EventCategory.LOCATION.value,
                        description=desc,
                        latitude=lat_f,
                        longitude=lon_f,
                        confidence=conf_pct,
                        actor="Device RoutineD Geolocation Engine",
                        target=f"Location ({lat_f:.5f}, {lon_f:.5f})" if lat_f and lon_f else "Location",
                        raw_payload=raw
                    )
                    events.append(ev)

                    if lat_f is not None and lon_f is not None:
                        entities.append(EntityModel(
                            entity_type=EntityType.GPS_COORDINATE.value,
                            value=f"{lat_f:.6f},{lon_f:.6f}",
                            confidence=conf_pct,
                            source_artifact_id=art.artifact_id,
                            metadata={"entry_date": ts_str, "confidence_raw": conf_raw}
                        ))
        finally:
            conn.close()

        return ParseOutput(
            artifacts=artifacts,
            events=events,
            entities=entities,
            relationships=relationships
        )
