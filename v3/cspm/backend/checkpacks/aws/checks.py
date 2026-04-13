"""
CloudGuard Pro CSPM — AWS Check Pack
Aniza Corp | Shahryar Jahangir

Sources:
- CIS Amazon Web Services Foundations Benchmark v1.5.0 (https://www.cisecurity.org/benchmark/amazon_web_services)
- AWS Security Hub FSBP (https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html)
- AWS Config Managed Rules (https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html)

License: CIS Benchmark content used for mapping only (not reproduced verbatim).
AWS documentation is public and attribution-friendly per AWS terms.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from backend.check_engine.engine import CheckMeta, CheckResult, register_check

_SRC_CIS = "CIS Amazon Web Services Foundations Benchmark v1.5.0"
_SRC_CIS_URL = "https://www.cisecurity.org/benchmark/amazon_web_services"
_SRC_FSBP = "AWS Foundational Security Best Practices"
_SRC_FSBP_URL = "https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html"
_RETRIEVED = "2024-01-15"

# ─── IAM ────────────────────────────────────────────────────────────────────

def _check_iam_root_mfa(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 1.5 — Ensure MFA is enabled for the root account."""
    has_mfa = resource.get("account_mfa_enabled", False)
    return has_mfa, {"account_mfa_enabled": has_mfa}

register_check(CheckMeta(
    check_id="aws-iam-001",
    name="Root Account MFA Enabled",
    family="Identity & Access",
    provider="aws",
    service="iam",
    resource_type="account_summary",
    severity="critical",
    description="The root account has unrestricted access to all AWS resources. MFA must be enabled to protect against unauthorized access.",
    remediation="Enable MFA on the root account via the IAM console > Security credentials > Assign MFA device. Use a hardware MFA device for root.",
    rationale="Root account compromise gives complete control of the AWS environment.",
    impact="Root account takeover leads to full environment compromise.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    license_notes="CIS Benchmark — mapping reference only.",
    normalization_confidence="high",
    logic_explanation="Checks AccountSummary.AccountMFAEnabled == 1 from IAM GetAccountSummary API call.",
    compliance_mappings=[
        {"framework": "CIS AWS 1.5", "control_id": "1.5"},
        {"framework": "NIST CSF", "control_id": "PR.AC-7"},
        {"framework": "SOC 2", "control_id": "CC6.1"},
    ],
    test_cases=[
        {"input": {"account_mfa_enabled": True}, "expected_pass": True},
        {"input": {"account_mfa_enabled": False}, "expected_pass": False},
    ],
    sample_payload={"account_mfa_enabled": False, "account_id": "123456789012"},
    func=_check_iam_root_mfa,
))


def _check_iam_password_policy(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 1.8–1.14 — IAM password policy checks."""
    policy = resource.get("password_policy", {})
    issues = []
    if not policy.get("RequireUppercaseCharacters", False):
        issues.append("no_uppercase_required")
    if not policy.get("RequireLowercaseCharacters", False):
        issues.append("no_lowercase_required")
    if not policy.get("RequireNumbers", False):
        issues.append("no_numbers_required")
    if not policy.get("RequireSymbols", False):
        issues.append("no_symbols_required")
    if policy.get("MinimumPasswordLength", 0) < 14:
        issues.append("min_length_too_short")
    if policy.get("PasswordReusePrevention", 0) < 24:
        issues.append("password_reuse_too_low")
    if policy.get("MaxPasswordAge", 999) > 90:
        issues.append("max_age_too_high")
    passed = len(issues) == 0
    return passed, {"issues": issues, "policy": policy}

register_check(CheckMeta(
    check_id="aws-iam-002",
    name="IAM Password Policy Meets Minimum Requirements",
    family="Identity & Access",
    provider="aws",
    service="iam",
    resource_type="password_policy",
    severity="high",
    description="The IAM account password policy must enforce strong password requirements: uppercase, lowercase, numbers, symbols, minimum 14 chars, max age 90 days, reuse prevention 24.",
    remediation="Update the IAM account password policy via IAM console > Account settings. Set minimum length 14, require complexity, max age 90, reuse prevention 24.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[
        {"framework": "CIS AWS 1.5", "control_id": "1.8"},
        {"framework": "NIST CSF", "control_id": "PR.AC-1"},
    ],
    test_cases=[
        {"input": {"password_policy": {"RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True, "RequireNumbers": True, "RequireSymbols": True, "MinimumPasswordLength": 14, "PasswordReusePrevention": 24, "MaxPasswordAge": 90}}, "expected_pass": True},
        {"input": {"password_policy": {}}, "expected_pass": False},
    ],
    func=_check_iam_password_policy,
))


def _check_iam_no_root_access_keys(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 1.4 — Root account must not have active access keys."""
    has_keys = resource.get("root_access_key_active", False)
    return not has_keys, {"root_access_key_active": has_keys}

register_check(CheckMeta(
    check_id="aws-iam-003",
    name="Root Account Has No Active Access Keys",
    family="Identity & Access",
    provider="aws",
    service="iam",
    resource_type="account_summary",
    severity="critical",
    description="The root account must not have active access keys. Access keys for root give programmatic full access to the account.",
    remediation="Delete root access keys via IAM console > Security credentials. Use IAM users with least-privilege policies instead.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "1.4"}],
    test_cases=[
        {"input": {"root_access_key_active": False}, "expected_pass": True},
        {"input": {"root_access_key_active": True}, "expected_pass": False},
    ],
    func=_check_iam_no_root_access_keys,
))


# ─── S3 ─────────────────────────────────────────────────────────────────────

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


# ─── Security Groups ─────────────────────────────────────────────────────────

def _check_sg_no_unrestricted_ssh(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 5.2 — No security group should allow unrestricted SSH (port 22) from 0.0.0.0/0."""
    violations = []
    for rule in resource.get("ip_permissions", []):
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        if not (from_port <= 22 <= to_port):
            continue
        for cidr in rule.get("IpRanges", []):
            if cidr.get("CidrIp") in ("0.0.0.0/0",):
                violations.append({"cidr": cidr.get("CidrIp"), "port": 22})
        for cidr6 in rule.get("Ipv6Ranges", []):
            if cidr6.get("CidrIpv6") in ("::/0",):
                violations.append({"cidr": cidr6.get("CidrIpv6"), "port": 22})
    return len(violations) == 0, {"violations": violations}

register_check(CheckMeta(
    check_id="aws-ec2-001",
    name="Security Groups: No Unrestricted SSH Access",
    family="Networking",
    provider="aws",
    service="ec2",
    resource_type="security_group",
    severity="critical",
    description="Security groups must not allow unrestricted inbound access on port 22 (SSH) from 0.0.0.0/0 or ::/0.",
    remediation="Edit the security group inbound rules to restrict SSH access to specific trusted IP ranges only. Remove any rules allowing 0.0.0.0/0 or ::/0 on port 22.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "5.2"}],
    func=_check_sg_no_unrestricted_ssh,
))


def _check_sg_no_unrestricted_rdp(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 5.3 — No security group should allow unrestricted RDP (port 3389)."""
    violations = []
    for rule in resource.get("ip_permissions", []):
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        if not (from_port <= 3389 <= to_port):
            continue
        for cidr in rule.get("IpRanges", []):
            if cidr.get("CidrIp") in ("0.0.0.0/0",):
                violations.append({"cidr": cidr.get("CidrIp"), "port": 3389})
    return len(violations) == 0, {"violations": violations}

register_check(CheckMeta(
    check_id="aws-ec2-002",
    name="Security Groups: No Unrestricted RDP Access",
    family="Networking",
    provider="aws",
    service="ec2",
    resource_type="security_group",
    severity="critical",
    description="Security groups must not allow unrestricted inbound access on port 3389 (RDP) from 0.0.0.0/0.",
    remediation="Edit security group rules to restrict RDP access to specific management IP ranges. Remove 0.0.0.0/0 entries on port 3389.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "5.3"}],
    func=_check_sg_no_unrestricted_rdp,
))


# ─── CloudTrail ──────────────────────────────────────────────────────────────

def _check_cloudtrail_enabled(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.1 — CloudTrail must be enabled in all regions."""
    is_multi = resource.get("IsMultiRegionTrail", False)
    is_logging = resource.get("IsLogging", False)
    include_global = resource.get("IncludeGlobalServiceEvents", False)
    passed = is_multi and is_logging and include_global
    return passed, {
        "is_multi_region": is_multi,
        "is_logging": is_logging,
        "include_global_service_events": include_global,
    }

register_check(CheckMeta(
    check_id="aws-cloudtrail-001",
    name="CloudTrail Enabled in All Regions",
    family="Logging & Monitoring",
    provider="aws",
    service="cloudtrail",
    resource_type="trail",
    severity="high",
    description="CloudTrail must be enabled as a multi-region trail that includes global service events and is actively logging.",
    remediation="Enable CloudTrail with multi-region logging: CloudTrail console > Create trail > Apply to all regions. Enable S3 server-side encryption and log file validation.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[
        {"framework": "CIS AWS 1.5", "control_id": "3.1"},
        {"framework": "NIST CSF", "control_id": "DE.CM-1"},
    ],
    func=_check_cloudtrail_enabled,
))


def _check_cloudtrail_log_validation(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.2 — CloudTrail log file validation must be enabled."""
    enabled = resource.get("LogFileValidationEnabled", False)
    return enabled, {"log_file_validation_enabled": enabled}

register_check(CheckMeta(
    check_id="aws-cloudtrail-002",
    name="CloudTrail Log File Validation Enabled",
    family="Logging & Monitoring",
    provider="aws",
    service="cloudtrail",
    resource_type="trail",
    severity="medium",
    description="CloudTrail log file validation ensures that log files have not been tampered with after delivery to S3.",
    remediation="Enable log file validation: CloudTrail console > Trail > Edit > Enable log file validation.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "3.2"}],
    func=_check_cloudtrail_log_validation,
))


# ─── KMS ─────────────────────────────────────────────────────────────────────

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


# ─── RDS ─────────────────────────────────────────────────────────────────────

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


# ─── EBS ─────────────────────────────────────────────────────────────────────

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


# ─── VPC ─────────────────────────────────────────────────────────────────────

def _check_vpc_flow_logs(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.9 — VPC flow logging must be enabled for all VPCs."""
    flow_logs = resource.get("flow_logs", [])
    active = [fl for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"]
    return len(active) > 0, {"active_flow_logs": len(active), "total_flow_logs": len(flow_logs)}

register_check(CheckMeta(
    check_id="aws-vpc-001",
    name="VPC Flow Logs Enabled",
    family="Networking",
    provider="aws",
    service="vpc",
    resource_type="vpc",
    severity="medium",
    description="VPC flow logs capture IP traffic information for network interface monitoring, security analysis, and troubleshooting.",
    remediation="Enable VPC flow logs: VPC console > Your VPCs > Select VPC > Flow logs > Create flow log. Send to CloudWatch Logs or S3.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "3.9"}],
    func=_check_vpc_flow_logs,
))


# ─── Lambda ──────────────────────────────────────────────────────────────────

def _check_lambda_no_admin_policy(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """FSBP Lambda.1 — Lambda functions must not have admin-equivalent permissions."""
    policies = resource.get("attached_policies", [])
    admin_policies = []
    for p in policies:
        arn = p.get("PolicyArn", "")
        if arn in ("arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/PowerUserAccess"):
            admin_policies.append(arn)
        # Check inline policy documents for *:* actions
        doc = p.get("PolicyDocument", {})
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if "*" in actions or "lambda:*" in actions:
                    admin_policies.append(f"inline:{stmt}")
    return len(admin_policies) == 0, {"admin_policies": admin_policies}

register_check(CheckMeta(
    check_id="aws-lambda-001",
    name="Lambda Functions Do Not Have Admin Permissions",
    family="Serverless",
    provider="aws",
    service="lambda",
    resource_type="function",
    severity="high",
    description="Lambda function execution roles must follow least privilege. Admin or wildcard policies grant excessive access.",
    remediation="Review Lambda execution role policies. Remove AdministratorAccess or wildcard Action policies. Apply minimum permissions needed for the function's purpose.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "1.22"}],
    func=_check_lambda_no_admin_policy,
))


# ─── EKS ─────────────────────────────────────────────────────────────────────

def _check_eks_private_endpoint(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """EKS cluster API endpoint should not be publicly accessible."""
    access = resource.get("resourcesVpcConfig", {})
    endpoint_public = access.get("endpointPublicAccess", True)
    endpoint_private = access.get("endpointPrivateAccess", False)
    # Best practice: private enabled, public disabled or restricted
    public_cidrs = access.get("publicAccessCidrs", ["0.0.0.0/0"])
    unrestricted_public = endpoint_public and "0.0.0.0/0" in public_cidrs
    passed = not unrestricted_public
    return passed, {
        "endpoint_public_access": endpoint_public,
        "endpoint_private_access": endpoint_private,
        "public_access_cidrs": public_cidrs,
    }

register_check(CheckMeta(
    check_id="aws-eks-001",
    name="EKS Cluster API Endpoint Not Unrestricted Public",
    family="Containers & Kubernetes",
    provider="aws",
    service="eks",
    resource_type="cluster",
    severity="high",
    description="EKS cluster Kubernetes API server endpoint should not be accessible from 0.0.0.0/0. Restrict to known CIDRs or disable public access entirely.",
    remediation="EKS console > Cluster > Networking > Manage networking: Disable public endpoint or restrict publicAccessCidrs to known IP ranges. Enable private endpoint.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS EKS Benchmark", "control_id": "3.1.1"}],
    func=_check_eks_private_endpoint,
))


# ─── CloudWatch / Alarms ─────────────────────────────────────────────────────

def _check_cloudwatch_root_usage_alarm(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 1.7 — Alarm must exist for root account usage."""
    has_alarm = resource.get("has_root_usage_alarm", False)
    return has_alarm, {"has_root_usage_alarm": has_alarm}

register_check(CheckMeta(
    check_id="aws-cloudwatch-001",
    name="CloudWatch Alarm for Root Account Usage",
    family="Logging & Monitoring",
    provider="aws",
    service="cloudwatch",
    resource_type="alarm_config",
    severity="medium",
    description="A CloudWatch alarm should exist that triggers on root account API usage to detect unauthorized root account activity.",
    remediation="Create a CloudWatch metric filter on CloudTrail logs for root user activity and set an alarm with SNS notification.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "1.7"}],
    func=_check_cloudwatch_root_usage_alarm,
))


# ─── ECR ─────────────────────────────────────────────────────────────────────

def _check_ecr_image_scan_on_push(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """FSBP ECR.1 — ECR repository must have scan-on-push enabled."""
    scan = resource.get("imageScanningConfiguration", {})
    scan_on_push = scan.get("scanOnPush", False)
    return scan_on_push, {"scan_on_push": scan_on_push}

register_check(CheckMeta(
    check_id="aws-ecr-001",
    name="ECR Repository Scan on Push Enabled",
    family="Containers & Kubernetes",
    provider="aws",
    service="ecr",
    resource_type="repository",
    severity="medium",
    description="ECR repositories should have image scanning on push enabled to detect known vulnerabilities in container images at upload time.",
    remediation="Enable scan on push: ECR console > Repository > Edit > Scan settings > Enable scan on push.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    func=_check_ecr_image_scan_on_push,
))


# ─── Secrets Manager ─────────────────────────────────────────────────────────

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
