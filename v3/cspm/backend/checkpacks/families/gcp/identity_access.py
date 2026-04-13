"""
CloudGuard Pro CSPM v3 — GCP Checks: Identity & Access
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
