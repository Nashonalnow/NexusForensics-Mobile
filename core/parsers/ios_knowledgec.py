#!/usr/bin/env python3
"""
NexusForensics Mobile™ | KnowledgeC Super Decoder
Decodes Apple iOS CoreDuet KnowledgeC.db (/app/inFocus, /device/isLocked, /display/isBacklit).
Reconstructs user intent, foreground application focus, and lock/unlock behavioral states.
Strict Copper Standard: 100% authentic CoreDuet ZOBJECT records and Mac Cocoa epoch timestamps.
"""

import sqlite3
import hashlib
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any

from .base_parser import BaseArtifactParser
from ..models import ArtifactModel, EventModel

COCOA_EPOCH_OFFSET = 978307200

class IOSKnowledgeCParser(BaseArtifactParser):
    @property
    def parser_name(self) -> str:
        return "ios_knowledgec_decoder"

    @property
    def artifact_type(self) -> str:
        return "knowledgec_behavior"

    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if not ("knowledgec" in name or (name.endswith(".db") and "knowledge" in name)):
            return False
        try:
            conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZOBJECT';")
            has_table = c.fetchone() is not None
            conn.close()
            return has_table
        except Exception:
            return False

    def parse(self, file_path: Path, source_id: str, device_id: str) -> List[Tuple[ArtifactModel, List[EventModel]]]:
        results: List[Tuple[ArtifactModel, List[EventModel]]] = []
        conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        try:
            query = """
                SELECT 
                    ZOBJECT.Z_PK,
                    ZOBJECT.ZSTREAMNAME,
                    ZOBJECT.ZSTARTDATE,
                    ZOBJECT.ZENDDATE,
                    ZOBJECT.ZVALUESTRING,
                    ZOBJECT.ZVALUEINTEGER
                FROM ZOBJECT
                WHERE ZOBJECT.ZSTREAMNAME IN (
                    '/app/inFocus',
                    '/device/isLocked',
                    '/display/isBacklit',
                    '/device/isPluggedIn',
                    '/app/usage'
                )
                ORDER BY ZOBJECT.ZSTARTDATE ASC;
            """
            c.execute(query)
            rows = c.fetchall()

            for r in rows:
                raw_dict = dict(r)
                rec_hash = hashlib.sha256(str(raw_dict).encode("utf-8")).hexdigest()

                raw_start = raw_dict.get("ZSTARTDATE", 0)
                epoch_s = float(raw_start) + COCOA_EPOCH_OFFSET
                ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))

                stream = raw_dict.get("ZSTREAMNAME", "")
                val_str = raw_dict.get("ZVALUESTRING")
                val_int = raw_dict.get("ZVALUEINTEGER")

                event_type = "device_state_change"
                category = "device_state"
                desc = f"CoreDuet Event on {stream}"
                actor = "User"
                target = None

                # Specific stream logic
                if stream == "/app/inFocus":
                    event_type = "app_opened"
                    category = "app_activity"
                    app_name = val_str or "Unknown App"
                    desc = f"Application brought to foreground: {app_name}"
                    target = app_name

                elif stream == "/device/isLocked":
                    is_locked = val_int == 1
                    event_type = "lock" if is_locked else "unlock"
                    category = "device_state"
                    desc = f"Device {('LOCKED' if is_locked else 'UNLOCKED')} by user"

                elif stream == "/display/isBacklit":
                    is_backlit = val_int == 1
                    event_type = "screen_on" if is_backlit else "screen_off"
                    category = "device_state"
                    desc = f"Display backlight {('TURNED ON' if is_backlit else 'TURNED OFF')}"

                elif stream == "/device/isPluggedIn":
                    is_plugged = val_int == 1
                    event_type = "device_plugged_in" if is_plugged else "device_unplugged"
                    category = "device_state"
                    desc = f"Power cable {('CONNECTED' if is_plugged else 'DISCONNECTED')}"

                artifact = ArtifactModel(
                    source_id=source_id,
                    parser_id=self.parser_id,
                    source_table="ZOBJECT",
                    source_record_id=str(raw_dict.get("Z_PK", "")),
                    artifact_type=self.artifact_type,
                    parser_name=self.parser_name,
                    parser_version=self.parser_version,
                    artifact_timestamp=ts_str,
                    record_hash=rec_hash,
                    raw_data=raw_dict,
                    normalized_data={
                        "stream": stream,
                        "value_string": val_str,
                        "value_integer": val_int,
                        "start_time": ts_str
                    }
                )


                event = EventModel(
                    artifact_id=artifact.artifact_id,
                    device_id=device_id,
                    timestamp=ts_str,
                    event_type=event_type,
                    category=category,
                    description=desc,
                    confidence=100,
                    actor=actor,
                    target=target,
                    raw_payload={"stream": stream, "val_str": val_str, "val_int": val_int}
                )

                results.append((artifact, [event]))

        finally:
            conn.close()

        return results
