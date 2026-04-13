"""
CloudGuard Pro CSPM v3 — AZURE Checks: Key Management / Secrets
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

def _check_keyvault_soft_delete(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 8.1 — Key Vault must have soft delete enabled."""
    soft_delete = resource.get("properties", {}).get("enableSoftDelete", False)
    return soft_delete, {"enable_soft_delete": soft_delete}

register_check(CheckMeta(
    check_id="azure-keyvault-001",
    name="Key Vault Soft Delete Enabled",
    family="Key Management / Secrets",
    provider="azure",
    service="keyvault",
    resource_type="vault",
    severity="high",
    description="Azure Key Vault must have soft delete enabled to allow recovery of deleted keys, secrets, and certificates within the retention period.",
    remediation="Key Vault > Properties > Soft delete > Enable. Note: this property is now enabled by default in new vaults.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "8.1"}],
    func=_check_keyvault_soft_delete,
))

def _check_keyvault_purge_protection(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 8.2 — Key Vault must have purge protection enabled."""
    purge_protection = resource.get("properties", {}).get("enablePurgeProtection", False)
    return purge_protection, {"enable_purge_protection": purge_protection}

register_check(CheckMeta(
    check_id="azure-keyvault-002",
    name="Key Vault Purge Protection Enabled",
    family="Key Management / Secrets",
    provider="azure",
    service="keyvault",
    resource_type="vault",
    severity="high",
    description="Azure Key Vault must have purge protection enabled to prevent permanent deletion of vaults and their objects.",
    remediation="Enable purge protection: az keyvault update --name <vault> --enable-purge-protection true",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "8.2"}],
    func=_check_keyvault_purge_protection,
))
