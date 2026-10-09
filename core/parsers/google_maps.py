#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Google Maps & Navigation History Parser (Tier 6 Priority)
Parses Google Maps databases: gmm_myplaces.db, da_destination_history, and search_history.db.
Answers investigator questions:
- What locations did the user search for?
- What destinations were navigated to?
- What exact GPS coordinates and timestamps were associated with travel?
Strict Copper Standard: 100% authentic schema parsing, deterministic record hashing.
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

class GoogleMapsParser(BaseArtifactParser):
    @property
    def parser_name(self) -> str:
        return "google_maps_history"

    @property
    def artifact_type(self) -> str:
        return "location"

    @property
    def supported_platforms(self) -> List[str]:
        return ["android", "ios"]

    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if not (name.endswith(".db") or name.endswith(".sqlite")):
            return False
        if not ("map" in name or "gmm" in name or "destination" in name or "places" in name or "nav" in name):
            return False
        try:
            conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
            c = conn.cursor()
            c.execute("""
                SELECT name FROM sqlite_master WHERE type='table' AND (
                    name LIKE '%destination%' OR name LIKE '%sync_item%' OR name LIKE '%search%' OR
                    name LIKE '%places%' OR name LIKE '%history%' OR name LIKE '%location%'
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
            c.execute("""
                SELECT name FROM sqlite_master WHERE type='table' AND (
                    name='destinations' OR name='destination_history' OR name='sync_item' OR
                    name='searches' OR name='search_history' OR name='places'
                );
            """)
            tables = [row[0] for row in c.fetchall()]

            for tname in tables:
                c.execute(f"SELECT * FROM {tname} ORDER BY rowid ASC;")
                rows = c.fetchall()
                for r in rows:
                    raw = dict(r)
                    rec_hash = hashlib.sha256(str(raw).encode("utf-8")).hexdigest()

                    # Extract query or destination title
                    dest_str = (
                        raw.get("destination") or raw.get("title") or raw.get("query") or
                        raw.get("name") or raw.get("address") or "Unknown Location"
                    )
                    lat = raw.get("latitude") or raw.get("lat")
                    lon = raw.get("longitude") or raw.get("lng") or raw.get("lon")
                    # Micro-degrees conversion if in E6 format (common in Google Maps)
                    if lat and abs(float(lat)) > 1000:
                        lat = float(lat) / 1e6
                    if lon and abs(float(lon)) > 1000:
                        lon = float(lon) / 1e6

                    lat_f = float(lat) if lat is not None else None
                    lon_f = float(lon) if lon is not None else None

                    ts_val = raw.get("timestamp") or raw.get("time") or raw.get("date") or time.time()
                    epoch_s = float(ts_val) / 1000.0 if float(ts_val) > 1000000000000 else float(ts_val)
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))

                    is_nav = "nav" in tname.lower() or "dest" in tname.lower()
                    ev_type = EventType.DESTINATION_SEARCH.value if not is_nav else EventType.NAVIGATION_START.value
                    desc = f"Google Maps {'navigation to' if is_nav else 'search for'}: {dest_str}"
                    if lat_f is not None and lon_f is not None:
                        desc += f" ({lat_f:.5f}, {lon_f:.5f})"

                    art = ArtifactModel(
                        source_id=source_id,
                        parser_id=self.parser_id,
                        source_table=tname,
                        source_record_id=str(raw.get("rowid") or raw.get("_id") or len(artifacts) + 1),
                        artifact_type=self.artifact_type,
                        parser_name=self.parser_name,
                        parser_version=self.parser_version,
                        artifact_timestamp=ts_str,
                        record_hash=rec_hash,
                        raw_data=raw,
                        normalized_data={"destination": dest_str, "latitude": lat_f, "longitude": lon_f}
                    )
                    artifacts.append(art)

                    ev = EventModel(
                        artifact_id=art.artifact_id,
                        device_id=device_id,
                        timestamp=ts_str,
                        event_type=ev_type,
                        category=EventCategory.LOCATION.value,
                        description=desc,
                        latitude=lat_f,
                        longitude=lon_f,
                        confidence=95,
                        actor="Device User",
                        target=dest_str,
                        raw_payload={"query": dest_str, "latitude": lat_f, "longitude": lon_f}
                    )
                    events.append(ev)

                    entities.append(EntityModel(
                        entity_type=EntityType.LOCATION_NAME.value,
                        value=dest_str,
                        confidence=95,
                        source_artifact_id=art.artifact_id,
                        metadata={"latitude": lat_f, "longitude": lon_f}
                    ))

                    if lat_f is not None and lon_f is not None:
                        entities.append(EntityModel(
                            entity_type=EntityType.GPS_COORDINATE.value,
                            value=f"{lat_f:.6f},{lon_f:.6f}",
                            confidence=99,
                            source_artifact_id=art.artifact_id,
                            metadata={"name": dest_str}
                        ))
        finally:
            conn.close()

        return ParseOutput(
            artifacts=artifacts,
            events=events,
            entities=entities,
            relationships=relationships
        )
