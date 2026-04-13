"""
CloudGuard Pro CSPM v3 — OCI Checks: Logging & Monitoring
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
