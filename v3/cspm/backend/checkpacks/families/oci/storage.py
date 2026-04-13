"""
CloudGuard Pro CSPM v3 — OCI Checks: Storage
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
