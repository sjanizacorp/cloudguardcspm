"""
CloudGuard Pro CSPM v3 — AZURE Checks: Logging & Monitoring
Aniza Corp | Shahryar Jahangir

Source: CIS Azure 2.0.0 + Microsoft MDFC
Family file — replace this file to update this specific check family.
Custom checks go in: backend/custom_checks/store/
"""
from __future__ import annotations
from typing import Any, Dict, List, Tuple
from backend.check_engine.engine import CheckMeta, CheckResult, register_check

_SRC_CIS = "CIS Microsoft Azure Foundations Benchmark v2.0.0"
_SRC_CIS_URL = "https://www.cisecurity.org/benchmark/azure"
_SRC_MDFC = "Microsoft Defender for Cloud"
_SRC_MDFC_URL = "https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference"
_RETRIEVED = "2024-01-15"

def _check_sql_auditing_enabled(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 4.1.3 — SQL Server auditing must be enabled."""
    audit_state = resource.get("auditingPolicy", {}).get("state", "Disabled")
    enabled = audit_state == "Enabled"
    retention = resource.get("auditingPolicy", {}).get("retentionDays", 0)
    retention_ok = retention >= 90
    passed = enabled and retention_ok
    return passed, {"audit_state": audit_state, "retention_days": retention, "retention_ok": retention_ok}

register_check(CheckMeta(
    check_id="azure-sql-002",
    name="SQL Server Auditing Enabled with 90-Day Retention",
    family="Logging & Monitoring",
    provider="azure",
    service="sql",
    resource_type="sql_server",
    severity="medium",
    description="Azure SQL Server auditing must be enabled with at least 90 days retention to support security investigation and compliance.",
    remediation="SQL Server > Security > Auditing > Enable. Set storage retention to >= 90 days.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "4.1.3"}],
    func=_check_sql_auditing_enabled,
))

def _check_activity_log_retention(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 5.1.1 — Activity log retention must be at least 1 year."""
    days = resource.get("retentionPolicy", {}).get("days", 0)
    enabled = resource.get("retentionPolicy", {}).get("enabled", False)
    passed = enabled and days >= 365
    return passed, {"retention_days": days, "retention_enabled": enabled}

register_check(CheckMeta(
    check_id="azure-monitor-001",
    name="Activity Log Retention >= 365 Days",
    family="Logging & Monitoring",
    provider="azure",
    service="monitor",
    resource_type="log_profile",
    severity="medium",
    description="Azure Activity Log retention must be configured for at least 365 days to support incident investigation and compliance requirements.",
    remediation="Azure Monitor > Activity log > Export Activity Logs > Set retention to 365 days.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "5.1.1"}],
    func=_check_activity_log_retention,
))
