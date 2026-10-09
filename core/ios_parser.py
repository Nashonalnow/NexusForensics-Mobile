#!/usr/bin/env python3
"""
NexusForensics Mobile™ | iOS Forensics & iTunes Backup Parser
Decodes Apple Property Lists (binary & XML plists), inspects Manifest.db, and maps iOS domains.
Strict Copper Standard: 100% authentic device UDIDs, iOS build versions, and plist structures.
"""

import os
import sys
import time
import plistlib
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

class IOSForensicsParser:
    """
    Parses iOS backup directories, decodes binary/XML property lists, and navigates Manifest.db domains.
    """

    def __init__(self):
        pass

    def parse_plist(self, plist_path: Path) -> Dict[str, Any]:
        """
        Parses an Apple property list file (supports both binary bplist00 and XML formats).
        """
        path = Path(plist_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Plist file not found: {path}")

        try:
            with open(path, "rb") as f:
                data = plistlib.load(f)

            # Sanitize data for JSON serialization (convert datetime & bytes)
            sanitized = self._sanitize_plist_obj(data)
            return {
                "file_name": path.name,
                "file_size": path.stat().st_size,
                "is_valid": True,
                "content": sanitized
            }
        except Exception as e:
            return {
                "file_name": path.name,
                "file_size": path.stat().st_size,
                "is_valid": False,
                "error": str(e)
            }

    def _sanitize_plist_obj(self, obj: Any) -> Any:
        import datetime
        if isinstance(obj, dict):
            return {k: self._sanitize_plist_obj(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._sanitize_plist_obj(item) for item in obj]
        elif isinstance(obj, bytes):
            return f"<BYTES: {len(obj)} bytes (hex: {obj[:16].hex()}...)>"
        elif isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        return obj

    def inspect_ios_backup(self, backup_dir: Path) -> Dict[str, Any]:
        """
        Inspects an Apple iTunes / Finder backup directory, extracting Info.plist, Status.plist,
        and Manifest.db file mapping records.
        """
        bdir = Path(backup_dir).resolve()
        if not bdir.exists() or not bdir.is_dir():
            raise NotADirectoryError(f"Backup directory not found: {bdir}")

        result: Dict[str, Any] = {
            "backup_path": str(bdir),
            "device_name": "Unknown iOS Device",
            "product_type": "Unknown",
            "ios_version": "Unknown",
            "build_version": "Unknown",
            "serial_number": "Unknown",
            "udid": "Unknown",
            "is_encrypted": False,
            "backup_date": None,
            "manifest_db_present": False,
            "mapped_domains": [],
            "total_files_in_manifest": 0
        }

        # Check Info.plist
        info_plist = bdir / "Info.plist"
        if info_plist.exists():
            info_data = self.parse_plist(info_plist).get("content", {})
            result["device_name"] = info_data.get("Device Name", result["device_name"])
            result["product_type"] = info_data.get("Product Type", result["product_type"])
            result["ios_version"] = info_data.get("Product Version", result["ios_version"])
            result["build_version"] = info_data.get("Build Version", result["build_version"])
            result["serial_number"] = info_data.get("Serial Number", result["serial_number"])
            result["udid"] = info_data.get("Unique Identifier", result["udid"])

        # Check Status.plist
        status_plist = bdir / "Status.plist"
        if status_plist.exists():
            status_data = self.parse_plist(status_plist).get("content", {})
            result["backup_date"] = status_data.get("Date")
            result["is_encrypted"] = status_data.get("IsFullBackup", False)

        # Check Manifest.db
        manifest_db = bdir / "Manifest.db"
        if manifest_db.exists():
            result["manifest_db_present"] = True
            try:
                uri = f"file:{manifest_db.as_posix()}?mode=ro"
                conn = sqlite3.connect(uri, uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM Files;")
                result["total_files_in_manifest"] = cursor.fetchone()[0]

                cursor.execute("SELECT domain, COUNT(*) FROM Files GROUP BY domain ORDER BY COUNT(*) DESC LIMIT 20;")
                result["mapped_domains"] = [{"domain": r[0], "file_count": r[1]} for r in cursor.fetchall()]
                conn.close()
            except Exception as e:
                result["manifest_error"] = str(e)

        return result
