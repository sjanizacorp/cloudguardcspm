"""
CloudGuard Pro CSPM v3 — GCP Checks: Storage
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
