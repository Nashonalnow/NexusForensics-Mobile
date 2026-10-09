#!/usr/bin/env python3
"""
NexusForensics Mobile™ | iOS Safari History Parser
Zimmerman-style dedicated parser for Apple Safari History.db.
"""

import sqlite3
import hashlib
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any

from .base_parser import BaseArtifactParser
from ..models import ArtifactModel, EventModel

COCOA_EPOCH_OFFSET = 978307200

class IOSSafariHistoryParser(BaseArtifactParser):
    @property
    def parser_name(self) -> str:
        return "ios_safari_history"

    @property
    def artifact_type(self) -> str:
        return "web_history"

    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if not ("history.db" in name or (name.endswith(".db") and "safari" in name)):
            return False
        try:
            conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='history_visits';")
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
                SELECT hv.id AS visit_id, hv.visit_time, hv.title, hi.url
                FROM history_visits hv
                JOIN history_items hi ON hv.history_item = hi.id
                ORDER BY hv.visit_time ASC;
            """
            c.execute(query)
            rows = c.fetchall()

            for r in rows:
                raw_dict = dict(r)
                rec_hash = hashlib.sha256(str(raw_dict).encode("utf-8")).hexdigest()

                raw_time = raw_dict.get("visit_time", 0)
                epoch_s = float(raw_time) + COCOA_EPOCH_OFFSET
                ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))

                url = raw_dict.get("url", "")
                title = raw_dict.get("title") or url

                artifact = ArtifactModel(
                    source_id=source_id,
                    parser_id=self.parser_id,
                    source_table="history_items",
                    source_record_id=str(raw_dict.get("id", "")),
                    artifact_type=self.artifact_type,
                    parser_name=self.parser_name,
                    parser_version=self.parser_version,
                    artifact_timestamp=ts_str,
                    record_hash=rec_hash,
                    raw_data=raw_dict,
                    normalized_data={
                        "url": url,
                        "title": title
                    }
                )


                event = EventModel(
                    artifact_id=artifact.artifact_id,
                    device_id=device_id,
                    timestamp=ts_str,
                    event_type="web_visit",
                    category="app_activity",
                    description=f"Safari visited: {title[:70]} ({url[:50]})",
                    confidence=100,
                    actor="User",
                    target=url,
                    raw_payload={"url": url, "title": title}
                )

                results.append((artifact, [event]))

        finally:
            conn.close()

        return results
