#!/usr/bin/env python3
"""
NexusForensics Mobile™ | iOS MobileSMS Parser
Zimmerman-style dedicated parser for Apple iOS sms.db (iMessage & SMS).
"""

import sqlite3
import hashlib
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any

from .base_parser import BaseArtifactParser
from ..models import ArtifactModel, EventModel

# Cocoa Epoch offset: 2001-01-01 00:00:00 UTC
COCOA_EPOCH_OFFSET = 978307200

class IOSMobileSMSParser(BaseArtifactParser):
    @property
    def parser_name(self) -> str:
        return "ios_sms_mobilesms"

    @property
    def artifact_type(self) -> str:
        return "imessage_sms"


    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if not ("sms.db" in name or (name.endswith(".db") and "sms" in name)):
            return False
        try:
            conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='message';")
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
                SELECT m.ROWID AS msg_id, m.text, m.date, m.is_from_me, m.service,
                       h.id AS handle_id
                FROM message m
                LEFT JOIN handle h ON m.handle_id = h.ROWID
                WHERE m.text IS NOT NULL
                ORDER BY m.date ASC;
            """
            c.execute(query)
            rows = c.fetchall()

            for r in rows:
                raw_dict = dict(r)
                rec_hash = hashlib.sha256(str(raw_dict).encode("utf-8")).hexdigest()

                raw_date = raw_dict.get("date", 0)
                # Convert Cocoa epoch nanoseconds to Unix timestamp
                if raw_date > 100000000000000:  # nanoseconds
                    epoch_s = (raw_date / 1000000000.0) + COCOA_EPOCH_OFFSET
                elif raw_date > 100000000:  # seconds
                    epoch_s = raw_date + COCOA_EPOCH_OFFSET
                else:
                    epoch_s = raw_date

                ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))
                is_from_me = bool(raw_dict.get("is_from_me", 0))
                handle = raw_dict.get("handle_id") or "Unknown"
                body = raw_dict.get("text", "")
                service = raw_dict.get("service", "iMessage")

                ev_type = "message_sent" if is_from_me else "message_received"
                actor = "Device Owner" if is_from_me else handle
                target = handle if is_from_me else "Device Owner"

                desc = f"{'Sent' if is_from_me else 'Received'} {service} to/from {handle}: {body[:80]}"

                artifact = ArtifactModel(
                    source_id=source_id,
                    parser_id=self.parser_id,
                    source_table="message",
                    source_record_id=str(raw_dict.get("ROWID", "")),
                    artifact_type=self.artifact_type,
                    parser_name=self.parser_name,
                    parser_version=self.parser_version,
                    artifact_timestamp=ts_str,
                    record_hash=rec_hash,
                    raw_data=raw_dict,
                    normalized_data={
                        "handle": handle,
                        "text": body,
                        "is_from_me": is_from_me,
                        "service": service
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
                    raw_payload={"service": service, "handle": handle, "text": body}
                )

                results.append((artifact, [event]))

        finally:
            conn.close()

        return results

IOSSMSParser = IOSMobileSMSParser
