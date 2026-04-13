"""
CloudGuard Pro CSPM v3 — AWS Checks: Storage
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

def _check_s3_public_access_block(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """FSBP S3.1 — S3 Block Public Access must be enabled at bucket level."""
    pab = resource.get("public_access_block", {})
    required = [
        "BlockPublicAcls", "IgnorePublicAcls",
        "BlockPublicPolicy", "RestrictPublicBuckets",
    ]
    missing = [k for k in required if not pab.get(k, False)]
    return len(missing) == 0, {"missing_settings": missing, "public_access_block": pab}

register_check(CheckMeta(
    check_id="aws-s3-001",
    name="S3 Bucket Public Access Block Enabled",
    family="Storage",
    provider="aws",
    service="s3",
    resource_type="bucket",
    severity="high",
    description="S3 buckets must have all four public access block settings enabled to prevent accidental public exposure of data.",
    remediation="Enable S3 Block Public Access at bucket level: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets via S3 console or AWS CLI.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[
        {"framework": "CIS AWS 1.5", "control_id": "2.1.5"},
        {"framework": "NIST CSF", "control_id": "PR.DS-1"},
    ],
    test_cases=[
        {"input": {"public_access_block": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}, "expected_pass": True},
        {"input": {"public_access_block": {}}, "expected_pass": False},
    ],
    func=_check_s3_public_access_block,
))

def _check_s3_encryption(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """FSBP S3.4 — S3 buckets must have server-side encryption enabled."""
    encryption = resource.get("server_side_encryption_configuration", {})
    rules = encryption.get("Rules", [])
    has_encryption = len(rules) > 0
    algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "") if rules else ""
    return has_encryption, {"has_encryption": has_encryption, "algorithm": algo}

register_check(CheckMeta(
    check_id="aws-s3-002",
    name="S3 Bucket Server-Side Encryption Enabled",
    family="Storage",
    provider="aws",
    service="s3",
    resource_type="bucket",
    severity="high",
    description="S3 buckets must have server-side encryption enabled (AES256 or aws:kms) to protect data at rest.",
    remediation="Enable default encryption on the S3 bucket: S3 console > Bucket > Properties > Default encryption > Enable. Prefer aws:kms with a customer-managed key.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "2.1.1"}],
    func=_check_s3_encryption,
))

def _check_s3_versioning(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 2.1.3 — S3 bucket versioning enabled."""
    versioning = resource.get("versioning", {})
    enabled = versioning.get("Status", "") == "Enabled"
    return enabled, {"versioning_status": versioning.get("Status", "Disabled")}

register_check(CheckMeta(
    check_id="aws-s3-003",
    name="S3 Bucket Versioning Enabled",
    family="Storage",
    provider="aws",
    service="s3",
    resource_type="bucket",
    severity="medium",
    description="S3 bucket versioning should be enabled to protect against accidental deletion and allow point-in-time recovery.",
    remediation="Enable versioning: S3 console > Bucket > Properties > Bucket Versioning > Enable.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "2.1.3"}],
    func=_check_s3_versioning,
))

def _check_ebs_encryption_by_default(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """FSBP EC2.7 — EBS default encryption must be enabled."""
    encrypted = resource.get("EbsEncryptionByDefault", False)
    return encrypted, {"ebs_encryption_by_default": encrypted}

register_check(CheckMeta(
    check_id="aws-ec2-003",
    name="EBS Default Encryption Enabled",
    family="Storage",
    provider="aws",
    service="ec2",
    resource_type="ebs_encryption_settings",
    severity="high",
    description="AWS account-level EBS default encryption must be enabled so all new EBS volumes are encrypted automatically.",
    remediation="Enable EBS default encryption: EC2 console > Settings > EBS encryption > Enable. Existing volumes must be re-encrypted via snapshot copy.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "2.2.1"}],
    func=_check_ebs_encryption_by_default,
))
