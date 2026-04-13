"""
CloudGuard Pro CSPM v3 — IBM Checks: Logging & Monitoring
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
