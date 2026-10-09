#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Android Call Log Parser
Zimmerman-style dedicated parser for Android telephony call logs.
"""

import sqlite3
import hashlib
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any

from .base_parser import BaseArtifactParser
from ..models import ArtifactModel, EventModel

CALL_TYPES = {
    1: "INCOMING",
    2: "OUTGOING",
    3: "MISSED",
    4: "VOICEMAIL",
    5: "REJECTED",
    6: "BLOCKED"
}

class AndroidCallLogParser(BaseArtifactParser):
    @property
    def parser_name(self) -> str:
        return "android_calllog"

    @property
    def artifact_type(self) -> str:
        return "call_log"

    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if not (name.endswith(".db") or name.endswith(".sqlite") or "call" in name):
            return False
        try:
            conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='calls';")
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
            c.execute("SELECT * FROM calls ORDER BY date ASC;")
            rows = c.fetchall()
            for r in rows:
                raw_dict = dict(r)
                rec_hash = hashlib.sha256(str(raw_dict).encode("utf-8")).hexdigest()

                date_val = raw_dict.get("date", 0)
                epoch_s = date_val / 1000.0 if date_val > 1000000000000 else float(date_val)
                ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))

                c_type_num = raw_dict.get("type", 1)
                c_type_str = CALL_TYPES.get(c_type_num, "UNKNOWN")
                number = raw_dict.get("number", "Unknown")
                duration = raw_dict.get("duration", 0)

                desc = f"{c_type_str} call with {number} (Duration: {duration}s)"
                actor = "Device Owner" if c_type_str == "OUTGOING" else number
                target = number if c_type_str == "OUTGOING" else "Device Owner"

                artifact = ArtifactModel(
                    source_id=source_id,
                    artifact_type=self.artifact_type,
                    parser_name=self.parser_name,
                    parser_version=self.parser_version,
                    artifact_timestamp=ts_str,
                    record_hash=rec_hash,
                    raw_data=raw_dict,
                    normalized_data={
                        "number": number,
                        "duration_seconds": duration,
                        "call_type": c_type_str,
                        "contact_name": raw_dict.get("name")
                    }
                )

                event = EventModel(
                    artifact_id=artifact.artifact_id,
                    device_id=device_id,
                    timestamp=ts_str,
                    event_type="call_started",
                    category="communication",
                    description=desc,
                    confidence=100,
                    actor=actor,
                    target=target,
                    raw_payload={"duration": duration, "call_type": c_type_str}
                )

                results.append((artifact, [event]))

        finally:
            conn.close()

        return results
