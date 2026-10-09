#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Android SMS/MMS/RCS Parser
Zimmerman-style dedicated parser for Android telephony and Google Messages databases.
"""

import sqlite3
import hashlib
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any

from .base_parser import BaseArtifactParser
from ..models import ArtifactModel, EventModel

class AndroidSMSParser(BaseArtifactParser):
    @property
    def parser_name(self) -> str:
        return "android_sms_telephony"

    @property
    def artifact_type(self) -> str:
        return "sms_message"

    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if not (name.endswith(".db") or name.endswith(".sqlite") or "telephony" in name or "mmssms" in name or "bugle" in name):
            return False
        try:
            conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name='sms' OR name='messages');")
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
            # Check for standard Android telephony sms table
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sms';")
            if c.fetchone():
                c.execute("SELECT * FROM sms ORDER BY date ASC;")
                rows = c.fetchall()
                for r in rows:
                    raw_dict = dict(r)
                    rec_hash = hashlib.sha256(str(raw_dict).encode("utf-8")).hexdigest()

                    date_ms = raw_dict.get("date", 0)
                    epoch_s = date_ms / 1000.0 if date_ms > 1000000000000 else float(date_ms)
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))

                    msg_type = raw_dict.get("type", 1)  # 1=received, 2=sent
                    is_sent = msg_type == 2
                    address = raw_dict.get("address", "Unknown")
                    body = raw_dict.get("body", "")

                    ev_type = "message_sent" if is_sent else "message_received"
                    actor = "Device Owner" if is_sent else address
                    target = address if is_sent else "Device Owner"

                    desc = f"{'Sent' if is_sent else 'Received'} SMS to/from {address}: {body[:80]}"

                    artifact = ArtifactModel(
                        source_id=source_id,
                        parser_id=self.parser_id,
                        source_table="sms",
                        source_record_id=str(raw_dict.get("_id", "")),
                        artifact_type=self.artifact_type,
                        parser_name=self.parser_name,
                        parser_version=self.parser_version,
                        artifact_timestamp=ts_str,
                        record_hash=rec_hash,
                        raw_data=raw_dict,
                        normalized_data={
                            "address": address,
                            "body": body,
                            "direction": "OUTBOUND" if is_sent else "INBOUND",
                            "read": bool(raw_dict.get("read", 1))
                        }
                    )


                    event = EventModel(
                        artifact_id=artifact.artifact_id,
                        device_id=device_id,
                        timestamp=ts_str,
                        event_type=ev_type,
                        category="communication",
                        description=desc,
                        confidence=100,
                        actor=actor,
                        target=target,
                        raw_payload={"body": body, "address": address, "thread_id": raw_dict.get("thread_id")}
                    )

                    results.append((artifact, [event]))

        finally:
            conn.close()

        return results
