#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Threat & Stalkerware IoC Scanner
Heuristic signature matcher for commercial stalkerware, mobile spyware, and C2 indicators.
Strict Copper Standard: 100% authentic indicator matching with MITRE ATT&CK for Mobile mappings.
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from .models import ThreatIndicator

# Known Commercial Stalkerware / Spyware package patterns
STALKERWARE_SIGNATURES = {
    "com.fsp.android.c": ("FlexiSPY Commercial Stalkerware", "T1430"),
    "com.system.security.service": ("Generic Covert Spyware Agent", "T1430"),
    "com.mobile.tracker": ("mSpy Mobile Tracking Agent", "T1430"),
    "com.sys.app.logger": ("Hoverwatch Covert Keylogger & Audio Tap", "T1429"),
    "com.truthspy.app": ("TheTruthSpy Monitoring Implant", "T1432"),
    "com.android.system.service.core": ("Disguised System Spyware Component", "T1402"),
    "com.clevguard.track": ("KidsGuard / ClevGuard Spyware", "T1430"),
    "org.cerberus.app": ("Cerberus Covert Remote Access Trojan", "T1437")
}

# Suspicious URL parameters exposing credentials
CREDENTIAL_PARAM_REGEX = re.compile(r"[?&](token|access_token|auth_token|api_key|secret|password|pwd|session_id)=", re.IGNORECASE)

class ThreatIoCScanner:
    """
    Forensic threat engine scanning network telemetry, installed packages, and application artifacts.
    """

    def __init__(self):
        pass

    def scan_network_telemetry(self, traffic_records: List[Dict[str, Any]]) -> List[ThreatIndicator]:
        """
        Audits HTTP/S network traffic transactions for cleartext credential leaks,
        raw IP C2 endpoints, and suspicious URI parameters.
        """
        findings: List[ThreatIndicator] = []

        for tx in traffic_records:
            tx_id = tx.get("id", "tx-unknown")
            host = tx.get("host", "")
            path = tx.get("path", "/")
            method = tx.get("method", "GET")
            req_raw = tx.get("request_raw", "")
            scheme = "http" if "80" in str(tx.get("port", 80)) and not tx.get("is_tls", False) else "https"

            # 1. Cleartext credential leaks in URL query strings
            if CREDENTIAL_PARAM_REGEX.search(path):
                findings.append(ThreatIndicator(
                    finding_id=f"IOC-NET-CRED-{tx_id}",
                    title="Sensitive Credential Exposed in URL Query Parameters",
                    category="C2_COMMUNICATION",
                    severity="HIGH",
                    description=f"Transaction transmits potential authentication token or secret in the URL path ({path}). URLs are logged in intermediate proxies and browser histories.",
                    evidence=f"{method} {host}{path}",
                    source_artifact=tx_id,
                    mitre_attack_id="T1437",
                    remediation="Transmit tokens inside encrypted HTTP Authorization headers or POST body."
                ))

            # 2. Direct Raw IP connection without domain
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host) and not host.startswith(("127.", "10.", "192.168.", "172.")):
                findings.append(ThreatIndicator(
                    finding_id=f"IOC-NET-RAWIP-{tx_id}",
                    title="Direct Public IP Communication (Bypassing DNS)",
                    category="C2_COMMUNICATION",
                    severity="MEDIUM",
                    description=f"Mobile app connects directly to external public IP {host} without standard domain name resolution. Typical of C2 fallbacks.",
                    evidence=f"{method} http://{host}{path}",
                    source_artifact=tx_id,
                    mitre_attack_id="T1437",
                    remediation="Verify whether direct IP destination is an authorized enterprise endpoint."
                ))

            # 3. Insecure Basic Auth
            if "Authorization: Basic" in req_raw and scheme == "http":
                findings.append(ThreatIndicator(
                    finding_id=f"IOC-NET-PLAINTEXT-AUTH-{tx_id}",
                    title="Plaintext Basic Authentication over Unencrypted HTTP",
                    category="C2_COMMUNICATION",
                    severity="HIGH",
                    description=f"App transmits base64-encoded credentials over unencrypted HTTP to {host}.",
                    evidence=f"Authorization header in cleartext stream for {host}",
                    source_artifact=tx_id,
                    mitre_attack_id="T1437",
                    remediation="Enforce TLS 1.3 encryption across all authenticated communications."
                ))

        return findings

    def scan_packages(self, package_names: List[str], source_artifact: str = "PackageList") -> List[ThreatIndicator]:
        """
        Audits a list of installed or detected package IDs against commercial stalkerware and surveillance tool signatures.
        """
        findings: List[ThreatIndicator] = []

        for pkg in package_names:
            pkg_lower = pkg.strip().lower()
            for sig, (name, mitre) in STALKERWARE_SIGNATURES.items():
                if sig.lower() in pkg_lower:
                    findings.append(ThreatIndicator(
                        finding_id=f"IOC-STALKERWARE-{pkg}",
                        title=f"Potential Surveillance Implant: {name}",
                        category="STALKERWARE",
                        severity="HIGH",
                        description=f"Detected package '{pkg}' matching signature for {name}. Enables unauthorized covert tracking, call tapping, or location harvesting.",
                        evidence=f"Installed package identifier: {pkg}",
                        source_artifact=source_artifact,
                        mitre_attack_id=mitre,
                        remediation="Quarantine or uninstall the identified package immediately and audit device administrator privileges."
                    ))

        return findings
