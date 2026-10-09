#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Unified Chronological Timeline Engine
Correlates network captures, SQLite database rows, filesystem MACB timestamps, and threat events.
Strict Copper Standard: 100% authentic timestamps and event ordering.
"""

import time
from typing import Dict, List, Any, Optional
from .models import TimelineEvent

class TimelineEngine:
    """
    Manages and normalizes chronological forensic events across disparate mobile telemetry sources.
    """

    def __init__(self):
        self.events: Dict[str, TimelineEvent] = {}

    def add_event(self, event: TimelineEvent) -> None:
        self.events[event.event_id] = event

    def add_events(self, events: List[TimelineEvent]) -> None:
        for e in events:
            self.events[e.event_id] = e

    def get_timeline(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        search_query: Optional[str] = None,
        start_epoch: Optional[float] = None,
        end_epoch: Optional[float] = None,
        limit: int = 200
    ) -> List[TimelineEvent]:
        """
        Returns chronological events sorted by timestamp descending, with optional filters.
        """
        filtered = list(self.events.values())

        if category:
            cat_upper = category.upper()
            filtered = [e for e in filtered if e.category.upper() == cat_upper]

        if severity:
            sev_upper = severity.upper()
            filtered = [e for e in filtered if e.severity.upper() == sev_upper]

        if start_epoch is not None:
            filtered = [e for e in filtered if e.epoch_timestamp >= start_epoch]

        if end_epoch is not None:
            filtered = [e for e in filtered if e.epoch_timestamp <= end_epoch]

        if search_query:
            q = search_query.lower()
            filtered = [
                e for e in filtered
                if q in e.summary.lower() or q in e.source_artifact.lower() or any(q in str(v).lower() for v in e.details.values())
            ]

        # Sort chronologically descending (newest first)
        filtered.sort(key=lambda x: x.epoch_timestamp, reverse=True)
        return filtered[:limit]

    def clear(self) -> None:
        self.events.clear()

    def get_summary_stats(self) -> Dict[str, Any]:
        categories: Dict[str, int] = {}
        severities: Dict[str, int] = {}

        for e in self.events.values():
            categories[e.category] = categories.get(e.category, 0) + 1
            severities[e.severity] = severities.get(e.severity, 0) + 1

        return {
            "total_events": len(self.events),
            "categories": categories,
            "severities": severities,
            "earliest_event": min((e.timestamp_utc for e in self.events.values()), default=None),
            "latest_event": max((e.timestamp_utc for e in self.events.values()), default=None)
        }
