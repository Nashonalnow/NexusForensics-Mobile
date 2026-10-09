#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Workbench Launcher & Socket Supervisor
Runs the mobile digital forensics and incident response workbench daemon.
Automated Socket Management: Auto-clears stale processes and guarantees fail-safe shutdown.
Strict Copper Standard: Zero lingering listeners, zero [Errno 98] bind errors.
"""

import os
import sys
import time
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
API_DIR = PROJECT_ROOT / "workbench" / "api"
sys.path.insert(0, str(API_DIR))
sys.path.insert(0, str(PROJECT_ROOT))

from port_manager import ensure_port_free, register_cleanup, is_port_in_use

def main():
    parser = argparse.ArgumentParser(description="NexusForensics Mobile™ Workbench Launcher")
    parser.add_argument("port", type=int, nargs="?", default=8096, help="UI / Forensic Daemon port (default: 8096)")
    parser.add_argument("--kill", "--clean", action="store_true", dest="clean_only", help="Stop running instances and release ports without starting")
    parser.add_argument("--status", action="store_true", help="Check status of port without starting")
    args = parser.parse_args()

    port = args.port

    if args.status:
        busy = is_port_in_use(port)
        print(f"NexusForensics Mobile (Port {port}): {'BUSY' if busy else 'FREE'}")
        sys.exit(0 if not busy else 1)

    if args.clean_only:
        print(f"[Launcher] Cleaning up processes on port {port}...")
        ok = ensure_port_free(port)
        print(f"[Launcher] Cleanup result: Port {port}={ok}")
        sys.exit(0 if ok else 1)

    print("==================================================")
    print("🔬 NexusForensics Mobile™ Interactive Workbench")
    print(f"Target URL: http://localhost:{port}")
    print("Features: Artifact Carving, SQLite Inspector, Chain of Custody, IoC Guard")
    print("==================================================")
    print("[Launcher] Checking port availability...")

    if is_port_in_use(port):
        print(f"[Launcher] Notice: Port {port} is occupied. Performing automated cleanup...")
        if not ensure_port_free(port):
            print(f"[Launcher] ERROR: Could not free port {port}. Please check permissions.", file=sys.stderr)
            sys.exit(1)

    def on_shutdown():
        print(f"[Launcher] Stopping forensics service on port {port}...")

    register_cleanup(ports=[port], on_cleanup=on_shutdown)

    import uvicorn
    print(f"[Launcher] Starting server on 0.0.0.0:{port}...")

    config = uvicorn.Config(
        "server:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info",
        timeout_graceful_shutdown=2
    )
    server = uvicorn.Server(config)

    try:
        server.run()
    except KeyboardInterrupt:
        print("\n[Launcher] KeyboardInterrupt received. Shutting down cleanly...")
    finally:
        ensure_port_free(port, timeout=1.0)
        print(f"[Launcher] Port {port} released cleanly. Exiting.")

if __name__ == "__main__":
    main()
