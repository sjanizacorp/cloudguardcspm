"""
CloudGuard Pro CSPM v3 — OCI Checks: Key Management / Secrets
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

def _check_oci_kms_rotation(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS OCI 4.1 — KMS key rotation must be enabled."""
    rotation = resource.get("currentKeyVersion", {})
    # Check if rotation schedule is configured
    rotation_scheduled = resource.get("autoKeyRotationEnabled", False)
    return rotation_scheduled, {"auto_key_rotation_enabled": rotation_scheduled}

register_check(CheckMeta(
    check_id="oci-kms-001",
    name="OCI Vault Key Rotation Enabled",
    family="Key Management / Secrets",
    provider="oci",
    service="kms",
    resource_type="key",
    severity="medium",
    description="OCI Vault encryption keys must have automatic rotation enabled to reduce cryptographic key exposure.",
    remediation="OCI console > Security > Vault > Key > Enable automatic rotation.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS_OCI,
    source_url=_SRC_CIS_OCI_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS OCI 2.0", "control_id": "4.1"}],
    func=_check_oci_kms_rotation,
))
