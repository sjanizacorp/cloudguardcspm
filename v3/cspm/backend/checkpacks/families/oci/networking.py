"""
CloudGuard Pro CSPM v3 — OCI Checks: Networking
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

def _check_oci_vcn_flow_logs(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS OCI 3.13 — VCN flow logs must be enabled."""
    flow_log_enabled = resource.get("flowLogEnabled", False)
    return flow_log_enabled, {"flow_log_enabled": flow_log_enabled}

register_check(CheckMeta(
    check_id="oci-vcn-001",
    name="VCN Flow Logs Enabled",
    family="Networking",
    provider="oci",
    service="core",
    resource_type="subnet",
    severity="medium",
    description="OCI VCN subnet flow logs must be enabled to capture network traffic for security analysis.",
    remediation="OCI console > Networking > Virtual Cloud Networks > Subnet > Logs > Enable flow logs.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS_OCI,
    source_url=_SRC_CIS_OCI_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS OCI 2.0", "control_id": "3.13"}],
    func=_check_oci_vcn_flow_logs,
))
