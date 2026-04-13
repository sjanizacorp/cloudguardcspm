"""
CloudGuard Pro CSPM — IBM Cloud Check Pack
Aniza Corp | Shahryar Jahangir

Sources:
- IBM Cloud Security and Compliance Center Posture Management
  https://cloud.ibm.com/docs/security-compliance
- IBM Cloud Framework for Financial Services controls
  https://cloud.ibm.com/docs/framework-financial-services
- CIS IBM Cloud Foundations Benchmark (where available publicly)

NOTE: IBM Cloud SCC posture controls are proprietary and not publicly
enumerated in full. Checks here are based on IBM public documentation,
best practices, and publicly available security guidance.
Coverage gap: Proprietary IBM SCC posture profiles are NOT replicated here.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from backend.check_engine.engine import CheckMeta, CheckResult, register_check

_SRC_IBM = "IBM Cloud Security Best Practices"
_SRC_IBM_URL = "https://cloud.ibm.com/docs/security-compliance"
_RETRIEVED = "2024-01-15"


def _check_ibm_cos_bucket_not_public(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """IBM COS buckets must not have public access enabled."""
    public_access = resource.get("public_access_enabled", False)
    acl = resource.get("acl", "private")
    is_public = public_access or acl in ("public-read", "public-read-write")
    return not is_public, {"public_access_enabled": public_access, "acl": acl}

register_check(CheckMeta(
    check_id="ibm-cos-001",
    name="IBM Cloud Object Storage Bucket Not Public",
    family="Storage",
    provider="ibm",
    service="cloud-object-storage",
    resource_type="bucket",
    severity="high",
    description="IBM Cloud Object Storage buckets must not have public access enabled. Public buckets expose data to the internet without authentication.",
    remediation="IBM Cloud console > Object Storage > Bucket > Access policies > Disable public access. Set ACL to private.",
    source_type="vendor",
    source_vendor="IBM",
    source_product=_SRC_IBM,
    source_url=_SRC_IBM_URL,
    source_retrieved=_RETRIEVED,
    license_notes="Based on IBM public documentation. IBM SCC proprietary profiles not replicated.",
    normalization_confidence="medium",
    compliance_mappings=[{"framework": "NIST CSF", "control_id": "PR.DS-1"}],
    func=_check_ibm_cos_bucket_not_public,
))


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


def _check_ibm_activity_tracker(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """IBM Activity Tracker must be configured in each region."""
    active = resource.get("active", False)
    return active, {"activity_tracker_active": active}

register_check(CheckMeta(
    check_id="ibm-logging-001",
    name="IBM Activity Tracker Instance Active",
    family="Logging & Monitoring",
    provider="ibm",
    service="activity-tracker",
    resource_type="tracker_instance",
    severity="high",
    description="IBM Cloud Activity Tracker must be configured and active to capture API activity for audit and compliance.",
    remediation="IBM Cloud catalog > Activity Tracker > Provision an instance in each region. Configure log routing.",
    source_type="vendor",
    source_vendor="IBM",
    source_product=_SRC_IBM,
    source_url=_SRC_IBM_URL,
    source_retrieved=_RETRIEVED,
    normalization_confidence="medium",
    func=_check_ibm_activity_tracker,
))


def _check_ibm_vpc_sg_no_ssh_world(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """IBM VPC Security Group must not allow SSH from 0.0.0.0/0."""
    violations = []
    for rule in resource.get("rules", []):
        if rule.get("direction") != "inbound":
            continue
        protocol = rule.get("protocol", "")
        if protocol not in ("tcp", "all"):
            continue
        port_min = rule.get("port_min", 0)
        port_max = rule.get("port_max", 65535)
        if not (port_min <= 22 <= port_max):
            continue
        remote = rule.get("remote", {})
        if remote.get("cidr_block") in ("0.0.0.0/0", "::/0"):
            violations.append({"rule_id": rule.get("id"), "cidr": remote.get("cidr_block")})
    return len(violations) == 0, {"violations": violations}

register_check(CheckMeta(
    check_id="ibm-vpc-001",
    name="VPC Security Group: No SSH from Any",
    family="Networking",
    provider="ibm",
    service="vpc",
    resource_type="security_group",
    severity="critical",
    description="IBM Cloud VPC security groups must not allow inbound SSH (port 22) from 0.0.0.0/0.",
    remediation="VPC > Security groups > Edit rules. Remove inbound rules allowing port 22 from all sources.",
    source_type="vendor",
    source_vendor="IBM",
    source_product=_SRC_IBM,
    source_url=_SRC_IBM_URL,
    source_retrieved=_RETRIEVED,
    normalization_confidence="medium",
    func=_check_ibm_vpc_sg_no_ssh_world,
))


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


"""
============================================================
OCI Check Pack
============================================================
Sources:
- CIS Oracle Cloud Infrastructure Foundations Benchmark v2.0.0
  https://www.cisecurity.org/benchmark/oracle_cloud
- OCI Cloud Guard built-in detector rules (publicly documented)
  https://docs.oracle.com/en-us/iaas/cloud-guard/using/detect-recipes.htm
- OCI Security Zones policies
  https://docs.oracle.com/en-us/iaas/security-zone/using/security-zones.htm

NOTE: OCI Cloud Guard detector rules are documented but implementation
details are proprietary. Checks here implement the documented intent
based on OCI API-accessible configuration. Coverage gap noted.
"""

_SRC_CIS_OCI = "CIS Oracle Cloud Infrastructure Foundations Benchmark v2.0.0"
_SRC_CIS_OCI_URL = "https://www.cisecurity.org/benchmark/oracle_cloud"
_SRC_CLOUDGUARD = "OCI Cloud Guard"
_SRC_CLOUDGUARD_URL = "https://docs.oracle.com/en-us/iaas/cloud-guard/using/detect-recipes.htm"


def _check_oci_object_storage_not_public(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS OCI 5.1.1 — Object Storage buckets must not be public."""
    public_access = resource.get("publicAccessType", "NoPublicAccess")
    is_public = public_access != "NoPublicAccess"
    return not is_public, {"public_access_type": public_access}

register_check(CheckMeta(
    check_id="oci-objectstorage-001",
    name="Object Storage Bucket Not Public",
    family="Storage",
    provider="oci",
    service="objectstorage",
    resource_type="bucket",
    severity="critical",
    description="OCI Object Storage buckets must have publicAccessType set to NoPublicAccess to prevent unauthorized data access.",
    remediation="OCI console > Object Storage > Bucket > Edit visibility > Private. Or: oci os bucket update --name <bucket> --public-access-type NoPublicAccess",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS_OCI,
    source_url=_SRC_CIS_OCI_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS OCI 2.0", "control_id": "5.1.1"}],
    func=_check_oci_object_storage_not_public,
))


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


def _check_oci_audit_retention(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS OCI 3.1 — Audit log retention must be >= 365 days."""
    retention_days = resource.get("retentionPeriodDays", 0)
    passed = retention_days >= 365
    return passed, {"retention_period_days": retention_days}

register_check(CheckMeta(
    check_id="oci-audit-001",
    name="OCI Audit Log Retention >= 365 Days",
    family="Logging & Monitoring",
    provider="oci",
    service="audit",
    resource_type="configuration",
    severity="medium",
    description="OCI Audit service retention period must be set to at least 365 days for compliance and investigation purposes.",
    remediation="OCI console > Governance & Administration > Audit > Configuration > Audit retention > Set to 365.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS_OCI,
    source_url=_SRC_CIS_OCI_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS OCI 2.0", "control_id": "3.1"}],
    func=_check_oci_audit_retention,
))


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


def _check_oci_vcn_flow_logs(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS OCI 3.13 — VCN flow logs must be enabled."""
    flow_log_enabled = resource.get("flowLogEnabled", False)
    return flow_log_enabled, {"flow_log_enabled": flow_log_enabled}

register_check(CheckMeta(
    check_id="oci-vcn-001",
    name="VCN Flow Logs Enabled",
    family="Networking",
    provider="oci",
    service="core",
    resource_type="subnet",
    severity="medium",
    description="OCI VCN subnet flow logs must be enabled to capture network traffic for security analysis.",
    remediation="OCI console > Networking > Virtual Cloud Networks > Subnet > Logs > Enable flow logs.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS_OCI,
    source_url=_SRC_CIS_OCI_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS OCI 2.0", "control_id": "3.13"}],
    func=_check_oci_vcn_flow_logs,
))


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
