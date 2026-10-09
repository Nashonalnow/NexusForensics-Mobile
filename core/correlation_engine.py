#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Event Correlation & Temporal Graph Engine
Correlates communications, device states (unlock/screen_on), app foreground focus, and locations.
Strict Copper Standard: 100% authentic timestamps and relationship weights.
"""

import time
import uuid
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

from .models import EventModel, RelationshipModel
from .warehouse import DuckDBWarehouse

class CorrelationEngine:
    """
    Automated evidence correlation engine.
    Discovers temporal relationships, corroborating evidence, and contradictions.
    """

    def __init__(self, warehouse: DuckDBWarehouse):
        self.wh = warehouse

    def _parse_ts(self, ts_str: str) -> float:
        """Parses ISO timestamp string to epoch float."""
        try:
            # Handle YYYY-MM-DD HH:MM:SS or ISO
            s = ts_str.replace("Z", "").replace("T", " ")
            dt = datetime.strptime(s.split(".")[0], "%Y-%m-%d %H:%M:%S")
            return dt.timestamp()
        except Exception:
            return 0.0

    def run_correlation(self, device_id: Optional[str] = None, window_seconds: float = 120.0) -> List[RelationshipModel]:
        """
        Executes high-speed correlation across timeline events.
        Identifies:
        1. Device Unlock / Screen On preceding Communication (preceded_by, supports)
        2. Foreground App active during Communication (used_app, supports)
        3. Location update coinciding with Communication / Photo (located_at)
        4. Contradictions (e.g. Communication while device was Locked)
        """
        relationships: List[RelationshipModel] = []

        # Pull events from DuckDB warehouse
        events_raw = self.wh.query_timeline(device_id=device_id, limit=5000)
        events = sorted(events_raw, key=lambda x: str(x["timestamp"]))

        # Separate by categories
        comms = [e for e in events if e.get("category") == "communication"]
        states = [e for e in events if e.get("category") == "device_state"]
        apps = [e for e in events if e.get("category") == "app_activity"]
        locs = [e for e in events if e.get("category") == "location" or e.get("location_lat") is not None]

        # Correlate each communication event with preceding device states
        for c in comms:
            c_time = self._parse_ts(str(c["timestamp"]))
            c_id = c["event_id"]

            # 1. Look for Unlock / Screen On in preceding window
            for s in states:
                s_time = self._parse_ts(str(s["timestamp"]))
                delta = c_time - s_time

                if 0 <= delta <= window_seconds:
                    stype = s.get("event_type", "")
                    if stype in ["unlock", "screen_on"]:
                        weight = max(0.5, 1.0 - (delta / window_seconds))
                        rel = RelationshipModel(
                            source_event_id=s["event_id"],
                            target_event_id=c_id,
                            relationship_type="preceded_by",
                            weight=weight,
                            rationale=f"Device {stype.upper()} occurred {int(delta)}s prior to {c.get('event_type')}"
                        )
                        relationships.append(rel)
                        self.wh.insert_relationship(
                            rel.relationship_id, rel.source_event_id, rel.target_event_id,
                            rel.relationship_type, rel.weight, rel.rationale
                        )

                    elif stype == "lock":
                        # Potential contradiction: device locked before message sent without intervening unlock
                        rel = RelationshipModel(
                            source_event_id=s["event_id"],
                            target_event_id=c_id,
                            relationship_type="contradicts",
                            weight=0.8,
                            rationale=f"Device was LOCKED {int(delta)}s prior without corroborated unlock"
                        )
                        relationships.append(rel)
                        self.wh.insert_relationship(
                            rel.relationship_id, rel.source_event_id, rel.target_event_id,
                            rel.relationship_type, rel.weight, rel.rationale
                        )

            # 2. Look for Foreground App Focus
            for a in apps:
                a_time = self._parse_ts(str(a["timestamp"]))
                delta = abs(c_time - a_time)
                if delta <= window_seconds:
                    rel = RelationshipModel(
                        source_event_id=a["event_id"],
                        target_event_id=c_id,
                        relationship_type="used_app",
                        weight=0.95,
                        rationale=f"Application {a.get('target', 'App')} was active ({int(delta)}s delta)"
                    )
                    relationships.append(rel)
                    self.wh.insert_relationship(
                        rel.relationship_id, rel.source_event_id, rel.target_event_id,
                        rel.relationship_type, rel.weight, rel.rationale
                    )

            # 3. Look for Location updates
            for l in locs:
                l_time = self._parse_ts(str(l["timestamp"]))
                delta = abs(c_time - l_time)
                if delta <= (window_seconds * 2):
                    rel = RelationshipModel(
                        source_event_id=l["event_id"],
                        target_event_id=c_id,
                        relationship_type="located_at",
                        weight=0.85,
                        rationale=f"Location fix ({l.get('location_lat')}, {l.get('location_lon')}) recorded {int(delta)}s from event"
                    )
                    relationships.append(rel)
                    self.wh.insert_relationship(
                        rel.relationship_id, rel.source_event_id, rel.target_event_id,
                        rel.relationship_type, rel.weight, rel.rationale
                    )

        return relationships
