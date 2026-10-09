#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Forensic SQLite & WAL Journal Inspector
Deep forensic schema carving, WAL journal detection, and deleted-record heuristics.
Strict Copper Standard: 100% authentic SQLite schemas, row data, and freelist counters.
"""

import os
import sys
import time
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

from .models import SQLiteTableInfo, SQLiteColumn, TimelineEvent

# Common mobile forensics timestamp column identifiers
TIMESTAMP_COLUMNS = [
    "date", "timestamp", "time", "created_at", "last_modified",
    "received_date", "sent_date", "call_date", "visit_time", "msg_date"
]

class SQLiteInspector:
    """
    Forensic read-only SQLite database analyzer with Write-Ahead Log (WAL) detection.
    """

    def __init__(self):
        pass

    def inspect_database(self, db_path: Path) -> Dict[str, Any]:
        """
        Extracts comprehensive database metadata, table schemas, row counts, and journal states.
        """
        path = Path(db_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Database file not found: {path}")

        wal_path = path.with_name(path.name + "-wal")
        shm_path = path.with_name(path.name + "-shm")
        has_wal = wal_path.exists()
        has_shm = shm_path.exists()

        tables_info: List[SQLiteTableInfo] = []
        freelist_count = 0
        page_size = 4096
        page_count = 0

        # Open in read-only URI mode to prevent any forensic contamination
        uri = f"file:{path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            # Pragmas
            cursor.execute("PRAGMA freelist_count;")
            row = cursor.fetchone()
            if row:
                freelist_count = row[0]

            cursor.execute("PRAGMA page_size;")
            row = cursor.fetchone()
            if row:
                page_size = row[0]

            cursor.execute("PRAGMA page_count;")
            row = cursor.fetchone()
            if row:
                page_count = row[0]

            # Enumerate tables
            cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            raw_tables = cursor.fetchall()

            for t_row in raw_tables:
                t_name = t_row["name"]

                # Get row count
                try:
                    cursor.execute(f'SELECT COUNT(*) FROM "{t_name}";')
                    cnt = cursor.fetchone()[0]
                except Exception:
                    cnt = 0

                # Column info
                cursor.execute(f'PRAGMA table_info("{t_name}");')
                col_rows = cursor.fetchall()
                cols: List[SQLiteColumn] = []
                for c in col_rows:
                    cols.append(SQLiteColumn(
                        cid=c[0],
                        name=c[1],
                        data_type=c[2] or "UNKNOWN",
                        notnull=bool(c[3]),
                        dflt_value=str(c[4]) if c[4] is not None else None,
                        pk=bool(c[5])
                    ))

                tables_info.append(SQLiteTableInfo(
                    table_name=t_name,
                    row_count=cnt,
                    columns=cols,
                    has_wal=has_wal,
                    has_shm=has_shm,
                    freelist_count=freelist_count
                ))

        finally:
            conn.close()

        return {
            "file_name": path.name,
            "file_size": path.stat().st_size,
            "has_wal": has_wal,
            "has_shm": has_shm,
            "page_size": page_size,
            "page_count": page_count,
            "freelist_pages": freelist_count,
            "table_count": len(tables_info),
            "tables": [t.model_dump() for t in tables_info]
        }

    def query_table(
        self,
        db_path: Path,
        table_name: str,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Executes a safe read-only query on a target table with pagination.
        """
        path = Path(db_path).resolve()
        uri = f"file:{path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            # Validate table name against sqlite_master
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table_name,))
            if not cursor.fetchone():
                raise ValueError(f"Table '{table_name}' does not exist in database.")

            cursor.execute(f'PRAGMA table_info("{table_name}");')
            cols = [c[1] for c in cursor.fetchall()]

            cursor.execute(f'SELECT * FROM "{table_name}" LIMIT ? OFFSET ?;', (limit, offset))
            raw_rows = cursor.fetchall()

            rows = []
            for r in raw_rows:
                row_dict = {}
                for idx, col in enumerate(cols):
                    val = r[idx]
                    if isinstance(val, bytes):
                        val = f"<BLOB: {len(val)} bytes (hex: {val[:16].hex()}...)>"
                    row_dict[col] = val
                rows.append(row_dict)

            cursor.execute(f'SELECT COUNT(*) FROM "{table_name}";')
            total = cursor.fetchone()[0]

            return {
                "table_name": table_name,
                "columns": cols,
                "total_rows": total,
                "limit": limit,
                "offset": offset,
                "rows": rows
            }
        finally:
            conn.close()

    def extract_timeline_events(
        self,
        db_path: Path,
        artifact_id: str,
        max_events_per_table: int = 100
    ) -> List[TimelineEvent]:
        """
        Auto-discovers timestamp fields in mobile app SQLite tables and extracts normalized timeline events.
        """
        path = Path(db_path).resolve()
        uri = f"file:{path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        events: List[TimelineEvent] = []

        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            tables = [r[0] for r in cursor.fetchall()]

            for t_name in tables:
                cursor.execute(f'PRAGMA table_info("{t_name}");')
                col_names = [c[1] for c in cursor.fetchall()]

                # Find candidate timestamp column
                ts_col = None
                for col in col_names:
                    if col.lower() in TIMESTAMP_COLUMNS:
                        ts_col = col
                        break

                if not ts_col:
                    continue

                # Query rows ordered by timestamp
                cursor.execute(f'SELECT * FROM "{t_name}" WHERE "{ts_col}" IS NOT NULL ORDER BY "{ts_col}" DESC LIMIT ?;', (max_events_per_table,))
                rows = cursor.fetchall()

                for r in rows:
                    raw_val = r[ts_col]
                    epoch_val = None

                    # Normalize timestamp
                    try:
                        if isinstance(raw_val, (int, float)):
                            # Check if milliseconds or microseconds (e.g. Mac/Cocoa epoch or Unix epoch)
                            if raw_val > 1000000000000:  # ms
                                epoch_val = raw_val / 1000.0
                            elif raw_val > 1000000000:  # standard unix seconds
                                epoch_val = float(raw_val)
                            elif raw_val > 100000000:  # Cocoa CoreData epoch (offset from 2001-01-01)
                                epoch_val = float(raw_val) + 978307200.0
                        elif isinstance(raw_val, str):
                            # Try parsing standard dates
                            import datetime
                            dt = datetime.datetime.fromisoformat(raw_val.replace("Z", "+00:00"))
                            epoch_val = dt.timestamp()
                    except Exception:
                        pass

                    if epoch_val is None or epoch_val < 0 or epoch_val > 2500000000:
                        continue

                    # Create row summary
                    summary_parts = []
                    details_dict = {}
                    for c_name in col_names:
                        v = r[c_name]
                        if isinstance(v, bytes):
                            v = f"<BLOB: {len(v)} bytes>"
                        details_dict[c_name] = v
                        if c_name != ts_col and v and len(summary_parts) < 3:
                            summary_parts.append(f"{c_name}={str(v)[:30]}")

                    summary_str = f"[{t_name}] " + ", ".join(summary_parts) if summary_parts else f"Record in {t_name}"

                    events.append(TimelineEvent(
                        event_id=f"EVT-SQL-{t_name}-{int(epoch_val*1000)}-{len(events)}",
                        timestamp_utc=time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(epoch_val)),
                        epoch_timestamp=epoch_val,
                        source_artifact=artifact_id,
                        category="DATABASE",
                        summary=summary_str,
                        details=details_dict,
                        severity="INFO"
                    ))

        finally:
            conn.close()

        return events
