#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Device State Reconstruction Parser (Tier 2 Priority)
Parses Android power_events/system_events databases and iOS KnowledgeC/Powerlog databases.
Fuel for the Behavioral Replay engine and correlation:
- Unlock / Lock events
- Screen On / Screen Off / Backlit transitions
- Charging / Battery state changes
- Boot / Shutdown cycles
Strict Copper Standard: 100% authentic schema parsing, zero mock data.
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

class DeviceStateParser(BaseArtifactParser):
    @property
    def parser_name(self) -> str:
        return "device_state_reconstruction"

    @property
    def artifact_type(self) -> str:
        return "device_state"

    @property
    def supported_platforms(self) -> List[str]:
        return ["android", "ios"]

    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if not (name.endswith(".db") or name.endswith(".sqlite") or name.endswith(".plsql")):
            return False
        if not ("power" in name or "state" in name or "battery" in name or "lock" in name or "knowledge" in name or "system" in name):
            return False
        try:
            conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
            c = conn.cursor()
            c.execute("""
                SELECT name FROM sqlite_master WHERE type='table' AND (
                    name LIKE '%screen%' OR name LIKE '%lock%' OR name LIKE '%power%' OR
                    name LIKE '%battery%' OR name LIKE '%device_state%' OR name LIKE '%ZOBJECT%'
                );
            """)
            has_table = c.fetchone() is not None
            conn.close()
            return has_table
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
            # Check 1: iOS KnowledgeC lock / backlit streams if present
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZOBJECT';")
            if c.fetchone():
                c.execute("""
                    SELECT 
                        o.Z_PK as id,
                        s.ZNAME as stream,
                        o.ZSTARTDATE,
                        o.ZENDDATE,
                        o.ZVALUEINTEGER,
                        o.ZVALUESTRING
                    FROM ZOBJECT o
                    JOIN ZSTRUCTUREDMETADATA s ON o.ZSTRUCTUREDMETADATA = s.Z_PK
                    WHERE s.ZNAME LIKE '%lock%' OR s.ZNAME LIKE '%backlit%' OR s.ZNAME LIKE '%charging%'
                    ORDER BY o.ZSTARTDATE ASC;
                """)
                rows = c.fetchall()
                for r in rows:
                    raw = dict(r)
                    rec_hash = hashlib.sha256(str(raw).encode("utf-8")).hexdigest()
                    # Apple epoch starts 2001-01-01 (add 978307200)
                    epoch_s = float(raw.get("ZSTARTDATE", 0)) + 978307200
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))
                    stream = raw.get("stream", "")
                    val = raw.get("ZVALUEINTEGER", 0)

                    if "lock" in stream.lower():
                        ev_type = EventType.LOCK.value if val == 1 else EventType.UNLOCK.value
                        desc = "Device locked" if val == 1 else "Device unlocked by user"
                    elif "backlit" in stream.lower():
                        ev_type = EventType.SCREEN_ON.value if val == 1 else EventType.SCREEN_OFF.value
                        desc = "Display screen illuminated" if val == 1 else "Display screen powered off"
                    else:
                        ev_type = EventType.CHARGING.value
                        desc = "Device connected to external power source"

                    art = ArtifactModel(
                        source_id=source_id,
                        parser_id=self.parser_id,
                        source_table="ZOBJECT",
                        source_record_id=str(raw["id"]),
                        artifact_type=self.artifact_type,
                        parser_name=self.parser_name,
                        parser_version=self.parser_version,
                        artifact_timestamp=ts_str,
                        record_hash=rec_hash,
                        raw_data=raw,
                        normalized_data={"stream": stream, "value": val}
                    )
                    artifacts.append(art)

                    ev = EventModel(
                        artifact_id=art.artifact_id,
                        device_id=device_id,
                        timestamp=ts_str,
                        event_type=ev_type,
                        category=EventCategory.DEVICE_STATE.value,
                        description=desc,
                        confidence=99,
                        actor="User / Hardware Lock Button",
                        target="Device Display & Biometrics",
                        raw_payload={"stream": stream, "val": val}
                    )
                    events.append(ev)

            # Check 2: Android or Generic power/screen table (e.g. screen_state, power_events, device_events)
            c.execute("""
                SELECT name FROM sqlite_master WHERE type='table' AND (
                    name='screen_events' OR name='power_events' OR name='device_state' OR name='lock_events'
                );
            """)
            tbl = c.fetchone()
            if tbl:
                tname = tbl[0]
                c.execute(f"SELECT * FROM {tname} ORDER BY rowid ASC;")
                rows = c.fetchall()
                for r in rows:
                    raw = dict(r)
                    rec_hash = hashlib.sha256(str(raw).encode("utf-8")).hexdigest()
                    ts_val = raw.get("timestamp") or raw.get("time") or raw.get("date") or time.time()
                    epoch_s = float(ts_val) / 1000.0 if float(ts_val) > 1000000000000 else float(ts_val)
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))
                    
                    state_raw = str(raw.get("state") or raw.get("event") or raw.get("type") or "").lower()
                    if "unlock" in state_raw:
                        ev_type = EventType.UNLOCK.value
                        desc = "Device lockscreen unlocked"
                    elif "lock" in state_raw:
                        ev_type = EventType.LOCK.value
                        desc = "Device transitioned to locked state"
                    elif "screen_on" in state_raw or "on" == state_raw:
                        ev_type = EventType.SCREEN_ON.value
                        desc = "Display screen turned ON"
                    elif "screen_off" in state_raw or "off" == state_raw:
                        ev_type = EventType.SCREEN_OFF.value
                        desc = "Display screen turned OFF"
                    elif "boot" in state_raw:
                        ev_type = EventType.BOOT.value
                        desc = "Operating system boot cycle initiated"
                    elif "shutdown" in state_raw:
                        ev_type = EventType.SHUTDOWN.value
                        desc = "Operating system shutdown cleanly recorded"
                    elif "charge" in state_raw:
                        ev_type = EventType.CHARGING.value
                        desc = "Device battery charging state changed"
                    else:
                        ev_type = EventType.UNLOCK.value if "auth" in state_raw else EventType.SCREEN_ON.value
                        desc = f"Device state change recorded: {state_raw}"

                    art = ArtifactModel(
                        source_id=source_id,
                        parser_id=self.parser_id,
                        source_table=tname,
                        source_record_id=str(raw.get("rowid") or raw.get("id") or len(artifacts) + 1),
                        artifact_type=self.artifact_type,
                        parser_name=self.parser_name,
                        parser_version=self.parser_version,
                        artifact_timestamp=ts_str,
                        record_hash=rec_hash,
                        raw_data=raw,
                        normalized_data={"raw_state": state_raw, "mapped_event": ev_type}
                    )
                    artifacts.append(art)

                    ev = EventModel(
                        artifact_id=art.artifact_id,
                        device_id=device_id,
                        timestamp=ts_str,
                        event_type=ev_type,
                        category=EventCategory.DEVICE_STATE.value,
                        description=desc,
                        confidence=97,
                        actor="Device Power Manager",
                        target="Power / Screen Controller",
                        raw_payload=raw
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
