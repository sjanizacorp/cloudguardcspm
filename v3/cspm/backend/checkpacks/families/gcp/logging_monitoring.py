"""
CloudGuard Pro CSPM v3 — GCP Checks: Logging & Monitoring
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
