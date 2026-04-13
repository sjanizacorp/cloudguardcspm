"""
CloudGuard Pro CSPM v3 — OCI Checks: Identity & Access
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

def _check_oci_mfa_enabled(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS OCI 1.7 — MFA must be enabled for all users."""
    mfa_active = resource.get("isMfaActivated", False)
    return mfa_active, {"mfa_activated": mfa_active}

register_check(CheckMeta(
    check_id="oci-iam-001",
    name="OCI IAM User MFA Enabled",
    family="Identity & Access",
    provider="oci",
    service="iam",
    resource_type="user",
    severity="critical",
    description="All OCI IAM users must have MFA activated to prevent unauthorized console access.",
    remediation="OCI console > Identity > Users > Select user > Enable MFA. Users can self-enroll at profile > Security.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS_OCI,
    source_url=_SRC_CIS_OCI_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS OCI 2.0", "control_id": "1.7"}],
    func=_check_oci_mfa_enabled,
))
