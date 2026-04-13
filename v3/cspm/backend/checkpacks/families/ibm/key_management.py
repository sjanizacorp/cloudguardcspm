"""
CloudGuard Pro CSPM v3 — IBM Checks: Key Management / Secrets
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

def _check_ibm_kp_rotation(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """IBM Key Protect keys must have rotation policy enabled."""
    rotation = resource.get("rotation", {})
    enabled = rotation.get("enabled", False)
    interval = rotation.get("interval_month", 0)
    passed = enabled and interval <= 12
    return passed, {"rotation_enabled": enabled, "interval_months": interval}

register_check(CheckMeta(
    check_id="ibm-kp-001",
    name="Key Protect Key Rotation Enabled",
    family="Key Management / Secrets",
    provider="ibm",
    service="kms",
    resource_type="key",
    severity="medium",
    description="IBM Key Protect keys must have automatic rotation enabled to reduce cryptographic risk.",
    remediation="IBM Cloud Key Protect > Key > Rotation policy > Enable with interval <= 12 months.",
    source_type="vendor",
    source_vendor="IBM",
    source_product=_SRC_IBM,
    source_url=_SRC_IBM_URL,
    source_retrieved=_RETRIEVED,
    normalization_confidence="medium",
    func=_check_ibm_kp_rotation,
))
