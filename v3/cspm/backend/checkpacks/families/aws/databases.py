"""
CloudGuard Pro CSPM v3 — AWS Checks: Databases
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

def _check_rds_not_publicly_accessible(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """FSBP RDS.2 — RDS instances must not be publicly accessible."""
    public = resource.get("PubliclyAccessible", False)
    return not public, {"publicly_accessible": public}

register_check(CheckMeta(
    check_id="aws-rds-001",
    name="RDS Instance Not Publicly Accessible",
    family="Databases",
    provider="aws",
    service="rds",
    resource_type="db_instance",
    severity="critical",
    description="RDS database instances must not be publicly accessible. Public accessibility exposes database endpoints to the internet.",
    remediation="Disable public accessibility: RDS console > Instance > Modify > Connectivity > Public access > No. Place RDS in a private subnet.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "2.3.3"}],
    func=_check_rds_not_publicly_accessible,
))

def _check_rds_encryption_at_rest(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """FSBP RDS.3 — RDS instances must have encryption at rest enabled."""
    encrypted = resource.get("StorageEncrypted", False)
    return encrypted, {"storage_encrypted": encrypted}

register_check(CheckMeta(
    check_id="aws-rds-002",
    name="RDS Instance Encryption at Rest Enabled",
    family="Databases",
    provider="aws",
    service="rds",
    resource_type="db_instance",
    severity="high",
    description="RDS instances must have storage encryption enabled to protect data at rest.",
    remediation="RDS encryption must be set at instance creation. Create a new encrypted instance and migrate data, or use an encrypted snapshot to restore.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "2.3.1"}],
    func=_check_rds_encryption_at_rest,
))
