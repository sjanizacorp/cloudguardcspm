"""
CloudGuard Pro CSPM v3 — GCP Checks: Key Management / Secrets
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

def _check_gcp_kms_rotation(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 1.10 — KMS keys must have rotation period <= 90 days."""
    rotation_period = resource.get("rotationPeriod", None)
    if rotation_period is None:
        return False, {"rotation_period": None, "issue": "no rotation configured"}
    # rotation_period is in seconds (e.g., "7776000s" = 90 days)
    try:
        seconds = int(rotation_period.rstrip("s"))
        days = seconds / 86400
        passed = days <= 90
    except (ValueError, AttributeError):
        return False, {"rotation_period": rotation_period, "issue": "parse error"}
    return passed, {"rotation_period_days": days}

register_check(CheckMeta(
    check_id="gcp-kms-001",
    name="KMS Keys Have Rotation Period <= 90 Days",
    family="Key Management / Secrets",
    provider="gcp",
    service="kms",
    resource_type="crypto_key",
    severity="medium",
    description="GCP KMS cryptographic keys must have an automatic rotation period configured and set to 90 days or less.",
    remediation="Cloud KMS > Key ring > Key > Edit rotation period. Set to 7776000s (90 days) or less.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS GCP 2.0", "control_id": "1.10"}],
    func=_check_gcp_kms_rotation,
))
