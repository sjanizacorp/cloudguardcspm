"""
CloudGuard Pro CSPM v3 — IBM Checks: Networking
Aniza Corp | Shahryar Jahangir

Source: CIS IBM Cloud / OCI Benchmarks
Family file — replace this file to update this specific check family.
Custom checks go in: backend/custom_checks/store/
"""
from __future__ import annotations
from typing import Any, Dict, List, Tuple
from backend.check_engine.engine import CheckMeta, CheckResult, register_check

_SRC_IBM = "IBM Cloud Security Best Practices"
_SRC_IBM_URL = "https://cloud.ibm.com/docs/security-compliance"
_RETRIEVED = "2024-01-15"
_SRC_CIS_OCI = "CIS Oracle Cloud Infrastructure Foundations Benchmark v2.0.0"
_SRC_CIS_OCI_URL = "https://www.cisecurity.org/benchmark/oracle_cloud"
_SRC_CLOUDGUARD = "OCI Cloud Guard"
_SRC_CLOUDGUARD_URL = "https://docs.oracle.com/en-us/iaas/cloud-guard/using/detect-recipes.htm"

def _check_ibm_vpc_sg_no_ssh_world(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """IBM VPC Security Group must not allow SSH from 0.0.0.0/0."""
    violations = []
    for rule in resource.get("rules", []):
        if rule.get("direction") != "inbound":
            continue
        protocol = rule.get("protocol", "")
        if protocol not in ("tcp", "all"):
            continue
        port_min = rule.get("port_min", 0)
        port_max = rule.get("port_max", 65535)
        if not (port_min <= 22 <= port_max):
            continue
        remote = rule.get("remote", {})
        if remote.get("cidr_block") in ("0.0.0.0/0", "::/0"):
            violations.append({"rule_id": rule.get("id"), "cidr": remote.get("cidr_block")})
    return len(violations) == 0, {"violations": violations}

register_check(CheckMeta(
    check_id="ibm-vpc-001",
    name="VPC Security Group: No SSH from Any",
    family="Networking",
    provider="ibm",
    service="vpc",
    resource_type="security_group",
    severity="critical",
    description="IBM Cloud VPC security groups must not allow inbound SSH (port 22) from 0.0.0.0/0.",
    remediation="VPC > Security groups > Edit rules. Remove inbound rules allowing port 22 from all sources.",
    source_type="vendor",
    source_vendor="IBM",
    source_product=_SRC_IBM,
    source_url=_SRC_IBM_URL,
    source_retrieved=_RETRIEVED,
    normalization_confidence="medium",
    func=_check_ibm_vpc_sg_no_ssh_world,
))
