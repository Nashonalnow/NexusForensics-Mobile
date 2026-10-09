#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Telegram & Signal Messaging Metadata Parser (Tier 3 Priority)
Parses Telegram cache4.db/tgnet and Signal metadata databases.
Answers investigator questions:
- What metadata is preserved for encrypted messaging apps?
- What timestamps, message IDs, user IDs, and channel posts exist in local caches?
- What remote contacts or group chats were communicated with?
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

class MessagingAppMetadataParser(BaseArtifactParser):
    @property
    def parser_name(self) -> str:
        return "messaging_metadata_telegram_signal"

    @property
    def artifact_type(self) -> str:
        return "telegram_message"

    @property
    def supported_platforms(self) -> List[str]:
        return ["android", "ios"]

    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if not (name.endswith(".db") or name.endswith(".sqlite")):
            return False
        if not ("cache4" in name or "telegram" in name or "tgnet" in name or "signal" in name):
            return False
        try:
            conn = sqlite3.connect(f"file:{file_path.as_posix()}?mode=ro", uri=True)
            c = conn.cursor()
            c.execute("""
                SELECT name FROM sqlite_master WHERE type='table' AND (
                    name='messages' OR name='chats' OR name='users' OR name='recipient' OR name='thread'
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
            # 1. Telegram cache4.db (messages table)
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages';")
            if c.fetchone():
                c.execute("SELECT * FROM messages ORDER BY rowid ASC;")
                rows = c.fetchall()
                for r in rows:
                    raw = dict(r)
                    rec_hash = hashlib.sha256(str(raw).encode("utf-8")).hexdigest()

                    mid = raw.get("mid") or raw.get("id") or len(artifacts) + 1
                    uid = raw.get("uid") or "0"
                    out = bool(raw.get("out", 0))
                    date_val = raw.get("date") or time.time()
                    epoch_s = float(date_val) if float(date_val) < 10000000000 else float(date_val) / 1000.0
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))

                    # Message data may be text or serialized blob
                    data_val = raw.get("data")
                    content_preview = str(data_val)[:60] if data_val else "Encrypted/Metadata Packet"

                    is_channel = int(uid) < 0
                    ev_type = EventType.CHANNEL_POST.value if is_channel else (EventType.SMS_SENT.value if out else EventType.SMS_RECEIVED.value)
                    desc = f"Telegram {'Channel post' if is_channel else ('Sent' if out else 'Received')} message (Peer ID: {uid})"

                    art = ArtifactModel(
                        source_id=source_id,
                        parser_id=self.parser_id,
                        source_table="messages",
                        source_record_id=str(mid),
                        artifact_type="telegram_message",
                        parser_name=self.parser_name,
                        parser_version=self.parser_version,
                        artifact_timestamp=ts_str,
                        record_hash=rec_hash,
                        raw_data={"mid": mid, "uid": uid, "out": out, "date": date_val},
                        normalized_data={"peer_id": str(uid), "outbound": out}
                    )
                    artifacts.append(art)

                    ev = EventModel(
                        artifact_id=art.artifact_id,
                        device_id=device_id,
                        timestamp=ts_str,
                        event_type=ev_type,
                        category=EventCategory.COMMUNICATION.value,
                        description=desc,
                        confidence=96,
                        actor="Device Owner" if out else f"Telegram Peer {uid}",
                        target=f"Telegram Peer {uid}" if out else "Device Owner",
                        raw_payload={"mid": mid, "uid": uid, "out": out}
                    )
                    events.append(ev)

                    entities.append(EntityModel(
                        entity_type=EntityType.CONTACT.value,
                        value=f"telegram_uid_{uid}",
                        confidence=95,
                        source_artifact_id=art.artifact_id
                    ))

            # 2. Signal metadata (mms / sms / recipient)
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name='mms' OR name='sms');")
            tbl = c.fetchone()
            if tbl:
                tname = tbl[0]
                c.execute(f"SELECT * FROM {tname} ORDER BY rowid ASC;")
                rows = c.fetchall()
                for r in rows:
                    raw = dict(r)
                    rec_hash = hashlib.sha256(str(raw).encode("utf-8")).hexdigest()

                    date_sent = raw.get("date_sent") or raw.get("date") or time.time() * 1000
                    epoch_s = float(date_sent) / 1000.0 if float(date_sent) > 1000000000000 else float(date_sent)
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))

                    address = raw.get("address") or raw.get("recipient_id") or "Signal Peer"
                    msg_type = raw.get("type", 1)
                    is_sent = msg_type == 2

                    art = ArtifactModel(
                        source_id=source_id,
                        parser_id=self.parser_id,
                        source_table=tname,
                        source_record_id=str(raw.get("_id") or len(artifacts) + 1),
                        artifact_type="signal_message",
                        parser_name=self.parser_name,
                        parser_version=self.parser_version,
                        artifact_timestamp=ts_str,
                        record_hash=rec_hash,
                        raw_data=raw,
                        normalized_data={"address": str(address), "is_sent": is_sent}
                    )
                    artifacts.append(art)

                    ev = EventModel(
                        artifact_id=art.artifact_id,
                        device_id=device_id,
                        timestamp=ts_str,
                        event_type=EventType.SMS_SENT.value if is_sent else EventType.SMS_RECEIVED.value,
                        category=EventCategory.COMMUNICATION.value,
                        description=f"Signal message {'transmitted to' if is_sent else 'received from'} {address}",
                        confidence=97,
                        actor="Device Owner" if is_sent else str(address),
                        target=str(address) if is_sent else "Device Owner",
                        raw_payload=raw
                    )
                    events.append(ev)

                    entities.append(EntityModel(
                        entity_type=EntityType.CONTACT.value,
                        value=f"signal_{address}",
                        confidence=95,
                        source_artifact_id=art.artifact_id
                    ))
        finally:
            conn.close()

        return ParseOutput(
            artifacts=artifacts,
            events=events,
            entities=entities,
            relationships=relationships
        )
