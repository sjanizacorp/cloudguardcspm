"""
CloudGuard Pro CSPM v3 — AZURE Checks: Compute
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

def _check_mdc_defender_servers_on(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """Defender for Cloud — Defender for Servers must be On."""
    pricing = resource.get("pricingTier", "Free")
    enabled = pricing in ("Standard",)
    return enabled, {"pricing_tier": pricing}

register_check(CheckMeta(
    check_id="azure-defender-001",
    name="Microsoft Defender for Servers Enabled",
    family="Compute",
    provider="azure",
    service="security",
    resource_type="defender_plan",
    severity="high",
    description="Microsoft Defender for Servers must be enabled (Standard tier) to provide threat protection and security recommendations for VMs.",
    remediation="Azure portal > Microsoft Defender for Cloud > Environment settings > Subscription > Defender plans > Servers > Enable Standard.",
    source_type="vendor",
    source_vendor="Microsoft",
    source_product=_SRC_MDFC,
    source_url=_SRC_MDFC_URL,
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "2.1"}],
    func=_check_mdc_defender_servers_on,
))
