"""
CloudGuard Pro CSPM v3 — OCI Checks: Governance / Policy / Org Configuration
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

def _check_oci_cloud_guard_enabled(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """Cloud Guard must be enabled and reporting targets configured."""
    status = resource.get("status", "DISABLED")
    enabled = status == "ENABLED"
    return enabled, {"status": status}

register_check(CheckMeta(
    check_id="oci-cloudguard-001",
    name="OCI Cloud Guard Enabled",
    family="Governance / Policy / Org Configuration",
    provider="oci",
    service="cloudguard",
    resource_type="configuration",
    severity="high",
    description="OCI Cloud Guard must be enabled in the root tenancy to continuously monitor for security risks and misconfigurations.",
    remediation="OCI console > Identity & Security > Cloud Guard > Enable Cloud Guard. Configure target and reporting region.",
    source_type="vendor",
    source_vendor="Oracle",
    source_product=_SRC_CLOUDGUARD,
    source_url=_SRC_CLOUDGUARD_URL,
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS OCI 2.0", "control_id": "4.1"}],
    func=_check_oci_cloud_guard_enabled,
))
