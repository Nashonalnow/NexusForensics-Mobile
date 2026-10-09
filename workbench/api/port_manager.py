#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Automated Port Manager & Lifecycle Handlers
Ensures fail-safe cleanup, avoids lingering sockets, and guarantees clean process teardown.
Strict Copper Standard: Zero lingering processes, zero [Errno 98] bind errors.
"""

import os
import sys
import time
import socket
import signal
import atexit
import subprocess
from typing import List, Optional, Callable

def is_port_in_use(port: int, host: str = "0.0.0.0") -> bool:
    """Checks whether the specified TCP port is currently occupied."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(0.5)
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True

def get_pids_on_port(port: int) -> List[int]:
    """Retrieves PIDs of processes bound to the target TCP port using lsof or fuser."""
    pids = []
    # Try lsof
    try:
        out = subprocess.check_output(["lsof", "-t", f"-i:{port}"], stderr=subprocess.DEVNULL)
        for line in out.decode().strip().split("\n"):
            if line.strip():
                pids.append(int(line.strip()))
        return list(set(pids))
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Try fuser fallback
    try:
        out = subprocess.check_output(["fuser", f"{port}/tcp"], stderr=subprocess.DEVNULL)
        for part in out.decode().strip().split():
            if part.strip().isdigit():
                pids.append(int(part.strip()))
        return list(set(pids))
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return pids

def ensure_port_free(port: int, timeout: float = 3.0) -> bool:
    """
    Terminates any process occupying the target port.
    Sends SIGTERM first, followed by SIGKILL if necessary.
    """
    if not is_port_in_use(port):
        return True

    pids = get_pids_on_port(port)
    current_pid = os.getpid()
    target_pids = [p for p in pids if p != current_pid]

    if not target_pids:
        # Port might be in TIME_WAIT
        return not is_port_in_use(port)

    # 1. Graceful SIGTERM
    for pid in target_pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError as e:
            print(f"[PortManager] Warning: Cannot kill PID {pid}: {e}", file=sys.stderr)

    # Wait briefly
    start = time.time()
    while time.time() - start < timeout:
        if not is_port_in_use(port):
            return True
        time.sleep(0.1)

    # 2. Forceful SIGKILL
    for pid in target_pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    time.sleep(0.2)
    return not is_port_in_use(port)

def register_cleanup(ports: List[int], on_cleanup: Optional[Callable[[], None]] = None):
    """
    Registers OS signal handlers (SIGINT, SIGTERM, SIGHUP) and atexit hook
    to guarantee port release upon server shutdown.
    """
    def _handler(signum, frame):
        print(f"\n[PortManager] Caught signal {signum}. Releasing sockets...")
        if on_cleanup:
            try:
                on_cleanup()
            except Exception:
                pass
        for p in ports:
            ensure_port_free(p, timeout=1.0)
        sys.exit(0)

    for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass

    def _atexit_handler():
        if on_cleanup:
            try:
                on_cleanup()
            except Exception:
                pass
        for p in ports:
            ensure_port_free(p, timeout=1.0)

    atexit.register(_atexit_handler)
