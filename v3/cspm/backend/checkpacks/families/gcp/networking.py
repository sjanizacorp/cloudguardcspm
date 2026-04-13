"""
CloudGuard Pro CSPM v3 — GCP Checks: Networking
Aniza Corp | Shahryar Jahangir

Source: CIS GCP 2.0.0 + Google SCC
Family file — replace this file to update this specific check family.
Custom checks go in: backend/custom_checks/store/
"""
from __future__ import annotations
from typing import Any, Dict, List, Tuple
from backend.check_engine.engine import CheckMeta, CheckResult, register_check

_SRC_CIS = "CIS Google Cloud Platform Foundation Benchmark v2.0.0"
_SRC_CIS_URL = "https://www.cisecurity.org/benchmark/google_cloud_computing_platform"
_SRC_SCC = "Google Cloud Security Command Center"
_SRC_SCC_URL = "https://cloud.google.com/security-command-center/docs"
_RETRIEVED = "2024-01-15"

def _check_gcp_firewall_no_ssh_world(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.6 — Firewall rules must not allow SSH from 0.0.0.0/0."""
    violations = []
    for rule in resource.get("allowed", []):
        if rule.get("IPProtocol") in ("tcp", "all"):
            ports = rule.get("ports", [])
            if not ports or "22" in ports or "0-65535" in ports:
                for src in resource.get("sourceRanges", []):
                    if src in ("0.0.0.0/0", "::/0"):
                        violations.append({"source": src})
    return len(violations) == 0, {"violations": violations, "direction": resource.get("direction")}

register_check(CheckMeta(
    check_id="gcp-compute-001",
    name="VPC Firewall: No SSH Access from 0.0.0.0/0",
    family="Networking",
    provider="gcp",
    service="compute",
    resource_type="firewall",
    severity="critical",
    description="GCP VPC firewall rules must not allow SSH (port 22) inbound from 0.0.0.0/0.",
    remediation="Remove or restrict firewall rules allowing port 22 from all sources. Use Cloud IAP for BeyondCorp SSH access instead.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS GCP 2.0", "control_id": "3.6"}],
    func=_check_gcp_firewall_no_ssh_world,
))
