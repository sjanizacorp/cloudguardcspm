"""
CloudGuard Pro CSPM v3 — GCP Checks: Containers & Kubernetes
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
