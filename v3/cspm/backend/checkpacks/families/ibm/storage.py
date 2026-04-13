"""
CloudGuard Pro CSPM v3 — IBM Checks: Storage
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
