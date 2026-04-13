"""
CloudGuard Pro CSPM v3 — AWS Checks: Key Management / Secrets
Aniza Corp | Shahryar Jahangir

Source: CIS AWS Foundations 1.5.0 + AWS FSBP
Family file — replace this file to update this specific check family.
Custom checks go in: backend/custom_checks/store/
"""
from __future__ import annotations
from typing import Any, Dict, List, Tuple
from backend.check_engine.engine import CheckMeta, CheckResult, register_check

_SRC_CIS = "CIS Amazon Web Services Foundations Benchmark v1.5.0"
_SRC_CIS_URL = "https://www.cisecurity.org/benchmark/amazon_web_services"
_SRC_FSBP = "AWS Foundational Security Best Practices"
_SRC_FSBP_URL = "https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html"
_RETRIEVED = "2024-01-15"

def _check_kms_key_rotation(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.7 — KMS CMK rotation must be enabled."""
    rotation = resource.get("KeyRotationEnabled", False)
    key_state = resource.get("KeyState", "")
    # Only applies to enabled, customer-managed keys
    if key_state not in ("Enabled",):
        return True, {"skipped": True, "reason": "Key not in Enabled state"}
    key_manager = resource.get("KeyManager", "CUSTOMER")
    if key_manager != "CUSTOMER":
        return True, {"skipped": True, "reason": "AWS managed key"}
    return rotation, {"key_rotation_enabled": rotation, "key_state": key_state}

register_check(CheckMeta(
    check_id="aws-kms-001",
    name="KMS Customer Managed Keys Have Rotation Enabled",
    family="Key Management / Secrets",
    provider="aws",
    service="kms",
    resource_type="key",
    severity="medium",
    description="AWS KMS customer-managed keys should have automatic annual rotation enabled to reduce the risk of key compromise.",
    remediation="Enable automatic key rotation: KMS console > Customer managed keys > Select key > Key rotation > Enable automatic key rotation.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "3.7"}],
    func=_check_kms_key_rotation,
))

def _check_secrets_manager_rotation(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """FSBP SecretsManager.1 — Secrets must have rotation enabled."""
    rotation_enabled = resource.get("RotationEnabled", False)
    return rotation_enabled, {"rotation_enabled": rotation_enabled}

register_check(CheckMeta(
    check_id="aws-secretsmanager-001",
    name="Secrets Manager Secret Rotation Enabled",
    family="Key Management / Secrets",
    provider="aws",
    service="secretsmanager",
    resource_type="secret",
    severity="high",
    description="Secrets Manager secrets should have automatic rotation enabled to reduce the risk from long-lived credentials.",
    remediation="Enable rotation in Secrets Manager console > Secret > Rotation > Enable automatic rotation. Configure rotation Lambda.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    func=_check_secrets_manager_rotation,
))
