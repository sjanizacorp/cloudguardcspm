"""
CloudGuard Pro CSPM v3 — AZURE Checks: Databases
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

def _check_sql_tde_enabled(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 4.1.1 — SQL Server databases must have TDE enabled."""
    tde_status = resource.get("transparentDataEncryption", {}).get("status", "Disabled")
    enabled = tde_status == "Enabled"
    return enabled, {"tde_status": tde_status}

register_check(CheckMeta(
    check_id="azure-sql-001",
    name="SQL Database Transparent Data Encryption Enabled",
    family="Databases",
    provider="azure",
    service="sql",
    resource_type="sql_database",
    severity="high",
    description="Azure SQL databases must have Transparent Data Encryption (TDE) enabled to encrypt data at rest.",
    remediation="Azure portal > SQL database > Transparent data encryption > On. Or via Bicep/ARM: set 'state': 'Enabled' in TDE configuration.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "4.1.1"}],
    func=_check_sql_tde_enabled,
))
