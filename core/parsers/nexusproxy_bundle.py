#!/usr/bin/env python3
"""
NexusForensics Mobile™ | NexusProxy Bundle Parser
Dedicated parser for NexusProxy-Mobile engagement packages (engagement_*.zip).
"""

import zipfile
import json
import hashlib
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any

from .base_parser import BaseArtifactParser
from ..models import ArtifactModel, EventModel

class NexusProxyBundleParser(BaseArtifactParser):
    @property
    def parser_name(self) -> str:
        return "nexusproxy_engagement_bundle"

    @property
    def artifact_type(self) -> str:
        return "network_flow"

    def can_parse(self, file_path: Path) -> bool:
        if not file_path.name.endswith(".zip"):
            return False
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                names = z.namelist()
                return "metadata.json" in names and any(n.startswith("requests/") for n in names)
        except Exception:
            return False

    def parse(self, file_path: Path, source_id: str, device_id: str) -> List[Tuple[ArtifactModel, List[EventModel]]]:
        results: List[Tuple[ArtifactModel, List[EventModel]]] = []

        with zipfile.ZipFile(file_path, "r") as z:
            names = z.namelist()
            meta = {}
            if "metadata.json" in names:
                meta = json.loads(z.read("metadata.json").decode("utf-8"))

            export_ts = meta.get("exported_at", int(time.time()))

            req_files = sorted([n for n in names if n.startswith("requests/")])
            for idx, req_file in enumerate(req_files):
                raw_bytes = z.read(req_file)
                raw_text = raw_bytes.decode("utf-8", errors="replace")
                rec_hash = hashlib.sha256(raw_bytes).hexdigest()

                lines = raw_text.split("\n")
                first = lines[0] if lines else "GET / HTTP/1.1"
                parts = first.split(" ")
                method = parts[0] if parts else "GET"
                path = parts[1] if len(parts) > 1 else "/"

                host = "unknown"
                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break

                epoch_s = export_ts - (idx * 5)
                ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_s))

                artifact = ArtifactModel(
                    source_id=source_id,
                    parser_id=self.parser_id,
                    source_table="requests",
                    source_record_id=str(idx),
                    artifact_type=self.artifact_type,
                    parser_name=self.parser_name,
                    parser_version=self.parser_version,
                    artifact_timestamp=ts_str,
                    record_hash=rec_hash,
                    raw_data={"request": raw_text[:500]},
                    normalized_data={
                        "method": method,
                        "host": host,
                        "path": path,
                        "protocol": "HTTP/1.1"
                    }
                )


                event = EventModel(
                    artifact_id=artifact.artifact_id,
                    device_id=device_id,
                    timestamp=ts_str,
                    event_type="http_traffic",
                    category="network",
                    description=f"HTTP Traffic: {method} {host}{path}",
                    confidence=100,
                    actor="Device Network Stack",
                    target=host,
                    raw_payload={"method": method, "host": host, "path": path}
                )

                results.append((artifact, [event]))

        return results
