"""
CloudGuard Pro CSPM v3 — GCP Checks: Databases
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
