"""
CloudGuard Pro CSPM v3 — AZURE Checks: Containers & Kubernetes
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

def _check_aks_rbac_enabled(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """Defender for Cloud — AKS cluster must have RBAC enabled."""
    rbac = resource.get("properties", {}).get("enableRBAC", False)
    return rbac, {"enable_rbac": rbac}

register_check(CheckMeta(
    check_id="azure-aks-001",
    name="AKS Cluster RBAC Enabled",
    family="Containers & Kubernetes",
    provider="azure",
    service="aks",
    resource_type="managed_cluster",
    severity="high",
    description="Azure Kubernetes Service (AKS) clusters must have Kubernetes RBAC enabled to enforce fine-grained access control on cluster resources.",
    remediation="Enable RBAC at cluster creation time. For existing clusters: az aks update --enable-aad --aad-admin-group-object-ids <group-id>.",
    source_type="vendor",
    source_vendor="Microsoft",
    source_product=_SRC_MDFC,
    source_url=_SRC_MDFC_URL,
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "5.1"}],
    func=_check_aks_rbac_enabled,
))
