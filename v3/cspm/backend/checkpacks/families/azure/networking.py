"""
CloudGuard Pro CSPM v3 — AZURE Checks: Networking
Aniza Corp | Shahryar Jahangir

Source: CIS Azure 2.0.0 + Microsoft MDFC
Family file — replace this file to update this specific check family.
Custom checks go in: backend/custom_checks/store/
"""
from __future__ import annotations
from typing import Any, Dict, List, Tuple
from backend.check_engine.engine import CheckMeta, CheckResult, register_check

_SRC_CIS = "CIS Microsoft Azure Foundations Benchmark v2.0.0"
_SRC_CIS_URL = "https://www.cisecurity.org/benchmark/azure"
_SRC_MDFC = "Microsoft Defender for Cloud"
_SRC_MDFC_URL = "https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference"
_RETRIEVED = "2024-01-15"

def _check_nsg_no_unrestricted_ssh(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 6.1 — NSG must not allow inbound SSH from Any."""
    violations = []
    for rule in resource.get("securityRules", []):
        direction = rule.get("properties", {}).get("direction", "")
        if direction != "Inbound":
            continue
        dest_port = rule.get("properties", {}).get("destinationPortRange", "")
        access = rule.get("properties", {}).get("access", "")
        source = rule.get("properties", {}).get("sourceAddressPrefix", "")
        if access == "Allow" and source in ("*", "Any", "Internet", "0.0.0.0/0"):
            if dest_port in ("22", "*") or (dest_port.replace(" ", "").startswith("22")):
                violations.append({"rule": rule.get("name"), "port": dest_port})
    return len(violations) == 0, {"violations": violations}

register_check(CheckMeta(
    check_id="azure-nsg-001",
    name="NSG: No Unrestricted Inbound SSH Access",
    family="Networking",
    provider="azure",
    service="network",
    resource_type="network_security_group",
    severity="critical",
    description="Azure Network Security Groups must not allow unrestricted inbound SSH access (port 22) from any source.",
    remediation="Remove or restrict NSG rules that allow SSH from Any/Internet/0.0.0.0/0. Restrict to specific management IP ranges.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "6.1"}],
    func=_check_nsg_no_unrestricted_ssh,
))

def _check_nsg_no_unrestricted_rdp(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 6.2 — NSG must not allow inbound RDP from Any."""
    violations = []
    for rule in resource.get("securityRules", []):
        direction = rule.get("properties", {}).get("direction", "")
        if direction != "Inbound":
            continue
        dest_port = rule.get("properties", {}).get("destinationPortRange", "")
        access = rule.get("properties", {}).get("access", "")
        source = rule.get("properties", {}).get("sourceAddressPrefix", "")
        if access == "Allow" and source in ("*", "Any", "Internet", "0.0.0.0/0"):
            if dest_port in ("3389", "*"):
                violations.append({"rule": rule.get("name"), "port": dest_port})
    return len(violations) == 0, {"violations": violations}

register_check(CheckMeta(
    check_id="azure-nsg-002",
    name="NSG: No Unrestricted Inbound RDP Access",
    family="Networking",
    provider="azure",
    service="network",
    resource_type="network_security_group",
    severity="critical",
    description="Azure NSGs must not allow unrestricted inbound RDP (port 3389) from any source.",
    remediation="Restrict or remove NSG rules that allow RDP from Any source. Use Azure Bastion for remote desktop access.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "6.2"}],
    func=_check_nsg_no_unrestricted_rdp,
))
