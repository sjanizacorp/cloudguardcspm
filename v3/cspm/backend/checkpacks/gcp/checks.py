"""
CloudGuard Pro CSPM — GCP Check Pack
Aniza Corp | Shahryar Jahangir

Sources:
- CIS Google Cloud Platform Foundation Benchmark v2.0.0
  https://www.cisecurity.org/benchmark/google_cloud_computing_platform
- Google Cloud Security Command Center recommendations
  https://cloud.google.com/security-command-center/docs/concepts-vulnerabilities-findings

License: GCP documentation public. CIS benchmark mapping reference only.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from backend.check_engine.engine import CheckMeta, CheckResult, register_check

_SRC_CIS = "CIS Google Cloud Platform Foundation Benchmark v2.0.0"
_SRC_CIS_URL = "https://www.cisecurity.org/benchmark/google_cloud_computing_platform"
_SRC_SCC = "Google Cloud Security Command Center"
_SRC_SCC_URL = "https://cloud.google.com/security-command-center/docs"
_RETRIEVED = "2024-01-15"


def _check_gcp_storage_bucket_not_public(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 5.1 — GCS buckets must not be publicly accessible."""
    iam_policy = resource.get("iam_policy", {})
    bindings = iam_policy.get("bindings", [])
    public_members = []
    for binding in bindings:
        members = binding.get("members", [])
        for m in members:
            if m in ("allUsers", "allAuthenticatedUsers"):
                public_members.append({"role": binding.get("role"), "member": m})
    return len(public_members) == 0, {"public_members": public_members}

register_check(CheckMeta(
    check_id="gcp-gcs-001",
    name="GCS Bucket Not Publicly Accessible",
    family="Storage",
    provider="gcp",
    service="storage",
    resource_type="bucket",
    severity="critical",
    description="GCS buckets must not grant access to allUsers or allAuthenticatedUsers, which makes bucket content publicly accessible.",
    remediation="Remove allUsers and allAuthenticatedUsers from bucket IAM policy. GCS console > Bucket > Permissions > Remove public principals.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[
        {"framework": "CIS GCP 2.0", "control_id": "5.1"},
        {"framework": "NIST CSF", "control_id": "PR.DS-1"},
    ],
    func=_check_gcp_storage_bucket_not_public,
))


def _check_gcp_firewall_no_ssh_world(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.6 — Firewall rules must not allow SSH from 0.0.0.0/0."""
    violations = []
    for rule in resource.get("allowed", []):
        if rule.get("IPProtocol") in ("tcp", "all"):
            ports = rule.get("ports", [])
            if not ports or "22" in ports or "0-65535" in ports:
                for src in resource.get("sourceRanges", []):
                    if src in ("0.0.0.0/0", "::/0"):
                        violations.append({"source": src})
    return len(violations) == 0, {"violations": violations, "direction": resource.get("direction")}

register_check(CheckMeta(
    check_id="gcp-compute-001",
    name="VPC Firewall: No SSH Access from 0.0.0.0/0",
    family="Networking",
    provider="gcp",
    service="compute",
    resource_type="firewall",
    severity="critical",
    description="GCP VPC firewall rules must not allow SSH (port 22) inbound from 0.0.0.0/0.",
    remediation="Remove or restrict firewall rules allowing port 22 from all sources. Use Cloud IAP for BeyondCorp SSH access instead.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS GCP 2.0", "control_id": "3.6"}],
    func=_check_gcp_firewall_no_ssh_world,
))


def _check_gcp_sql_no_public_ip(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 6.6 — Cloud SQL instances must not have public IPs."""
    ip_config = resource.get("settings", {}).get("ipConfiguration", {})
    assigned_ips = resource.get("ipAddresses", [])
    has_public = any(ip.get("type") == "PRIMARY" for ip in assigned_ips)
    return not has_public, {"has_public_ip": has_public, "ip_addresses": assigned_ips}

register_check(CheckMeta(
    check_id="gcp-cloudsql-001",
    name="Cloud SQL Instance Has No Public IP",
    family="Databases",
    provider="gcp",
    service="cloudsql",
    resource_type="database_instance",
    severity="high",
    description="Cloud SQL instances should not have public IP addresses assigned. Use private IP with VPC peering or Cloud SQL Auth Proxy.",
    remediation="Cloud SQL > Instance > Edit > Connections > Remove public IP. Enable private IP instead.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS GCP 2.0", "control_id": "6.6"}],
    func=_check_gcp_sql_no_public_ip,
))


def _check_gcp_logging_sink_enabled(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 2.1 — Cloud audit log export sink must exist."""
    has_sink = resource.get("has_export_sink", False)
    return has_sink, {"has_export_sink": has_sink}

register_check(CheckMeta(
    check_id="gcp-logging-001",
    name="Cloud Audit Log Export Sink Configured",
    family="Logging & Monitoring",
    provider="gcp",
    service="logging",
    resource_type="log_sink_config",
    severity="medium",
    description="GCP projects must have at least one log sink configured to export audit logs to a durable storage destination.",
    remediation="Cloud Logging > Log Router > Create sink. Export to Cloud Storage or BigQuery with appropriate retention.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS GCP 2.0", "control_id": "2.1"}],
    func=_check_gcp_logging_sink_enabled,
))


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


def _check_gcp_gke_dashboard_disabled(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 6.4.1 — GKE Kubernetes dashboard must be disabled."""
    addons = resource.get("addonsConfig", {})
    dashboard = addons.get("kubernetesDashboard", {})
    disabled = dashboard.get("disabled", True)
    return disabled, {"kubernetes_dashboard_disabled": disabled}

register_check(CheckMeta(
    check_id="gcp-gke-001",
    name="GKE Kubernetes Dashboard Disabled",
    family="Containers & Kubernetes",
    provider="gcp",
    service="container",
    resource_type="cluster",
    severity="high",
    description="The Kubernetes dashboard should be disabled on GKE clusters as it has been used in past cryptomining attacks and exposes cluster management.",
    remediation="Disable dashboard: gcloud container clusters update CLUSTER --update-addons=KubernetesDashboard=DISABLED",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS GCP 2.0", "control_id": "6.4.1"}],
    func=_check_gcp_gke_dashboard_disabled,
))


def _check_gcp_bigquery_dataset_not_public(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 7.1 — BigQuery datasets must not be publicly accessible."""
    access = resource.get("access", [])
    public = [e for e in access if e.get("specialGroup") in ("allUsers", "allAuthenticatedUsers")]
    return len(public) == 0, {"public_access_entries": public}

register_check(CheckMeta(
    check_id="gcp-bigquery-001",
    name="BigQuery Dataset Not Publicly Accessible",
    family="Databases",
    provider="gcp",
    service="bigquery",
    resource_type="dataset",
    severity="high",
    description="BigQuery datasets must not grant access to allUsers or allAuthenticatedUsers to prevent unauthorized access to data.",
    remediation="BigQuery > Dataset > Sharing > Remove allUsers and allAuthenticatedUsers. Apply granular IAM bindings.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS GCP 2.0", "control_id": "7.1"}],
    func=_check_gcp_bigquery_dataset_not_public,
))


def _check_gcp_sa_no_admin_roles(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 1.5 — Service accounts must not have admin roles."""
    roles = resource.get("roles", [])
    admin_roles = [r for r in roles if "admin" in r.lower() or r == "roles/owner" or r == "roles/editor"]
    return len(admin_roles) == 0, {"admin_roles": admin_roles}

register_check(CheckMeta(
    check_id="gcp-iam-001",
    name="Service Account Does Not Have Admin Roles",
    family="Identity & Access",
    provider="gcp",
    service="iam",
    resource_type="service_account",
    severity="high",
    description="GCP service accounts must not be granted primitive roles (owner, editor) or admin roles which grant excessive permissions.",
    remediation="Remove admin/primitive roles from service account IAM bindings. Apply the minimum required predefined roles.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS GCP 2.0", "control_id": "1.5"}],
    func=_check_gcp_sa_no_admin_roles,
))
