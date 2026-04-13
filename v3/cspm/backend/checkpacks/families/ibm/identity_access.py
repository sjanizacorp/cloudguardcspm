"""
CloudGuard Pro CSPM v3 — IBM Checks: Identity & Access
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

def _check_ibm_iam_mfa(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """IBM IAM MFA enforcement level for users."""
    mfa_level = resource.get("mfa", "NONE")
    passed = mfa_level not in ("NONE", "")
    return passed, {"mfa_level": mfa_level}

register_check(CheckMeta(
    check_id="ibm-iam-001",
    name="IBM Cloud IAM MFA Enabled for All Users",
    family="Identity & Access",
    provider="ibm",
    service="iam",
    resource_type="account_settings",
    severity="critical",
    description="IBM Cloud account must enforce MFA (at minimum TOTP) for all users to protect against unauthorized access.",
    remediation="IBM Cloud IAM > Settings > Multifactor authentication > Set to TOTP or LEVEL1/LEVEL2/LEVEL3.",
    source_type="vendor",
    source_vendor="IBM",
    source_product=_SRC_IBM,
    source_url=_SRC_IBM_URL,
    source_retrieved=_RETRIEVED,
    normalization_confidence="medium",
    func=_check_ibm_iam_mfa,
))
