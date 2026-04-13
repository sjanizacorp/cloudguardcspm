"""
CloudGuard Pro CSPM v3 — AZURE Checks: Storage
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

def _check_storage_public_access_disabled(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.1 — Storage account public access must be disabled."""
    allow_blob_public = resource.get("allowBlobPublicAccess", True)
    return not allow_blob_public, {"allow_blob_public_access": allow_blob_public}

register_check(CheckMeta(
    check_id="azure-storage-001",
    name="Storage Account Public Blob Access Disabled",
    family="Storage",
    provider="azure",
    service="storage",
    resource_type="storage_account",
    severity="high",
    description="Azure Storage accounts must have public blob access disabled to prevent unauthorized read access to blob containers.",
    remediation="Azure portal > Storage account > Configuration > Allow Blob public access > Disabled. Or via ARM: set allowBlobPublicAccess=false.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[
        {"framework": "CIS Azure 2.0", "control_id": "3.1"},
        {"framework": "NIST CSF", "control_id": "PR.DS-1"},
    ],
    func=_check_storage_public_access_disabled,
))

def _check_storage_encryption_cmk(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.2 — Storage encryption with customer-managed key."""
    encryption = resource.get("encryption", {})
    key_source = encryption.get("keySource", "Microsoft.Storage")
    has_cmk = key_source == "Microsoft.Keyvault"
    return has_cmk, {"key_source": key_source, "has_customer_managed_key": has_cmk}

register_check(CheckMeta(
    check_id="azure-storage-002",
    name="Storage Account Uses Customer-Managed Key Encryption",
    family="Storage",
    provider="azure",
    service="storage",
    resource_type="storage_account",
    severity="medium",
    description="Azure Storage should use customer-managed keys (CMK) in Azure Key Vault for encryption at rest to provide greater control.",
    remediation="Configure CMK: Storage account > Encryption > Customer-managed keys > Select Key Vault and key.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "3.2"}],
    func=_check_storage_encryption_cmk,
))

def _check_storage_https_only(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.15 — Storage accounts should enable HTTPS-only traffic."""
    https_only = resource.get("supportsHttpsTrafficOnly", False)
    return https_only, {"supports_https_traffic_only": https_only}

register_check(CheckMeta(
    check_id="azure-storage-003",
    name="Storage Account HTTPS Traffic Only Enabled",
    family="Storage",
    provider="azure",
    service="storage",
    resource_type="storage_account",
    severity="high",
    description="Azure Storage accounts must enforce HTTPS-only traffic to prevent unencrypted data transmission.",
    remediation="Storage account > Configuration > Secure transfer required > Enabled.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "3.15"}],
    func=_check_storage_https_only,
))

def _check_disk_encryption_enabled(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """Defender for Cloud — OS disks must be encrypted."""
    encryption_type = resource.get("encryption", {}).get("type", "")
    encrypted = encryption_type in ("EncryptionAtRestWithPlatformKey", "EncryptionAtRestWithCustomerKey", "EncryptionAtRestWithPlatformAndCustomerKeys")
    return encrypted, {"encryption_type": encryption_type}

register_check(CheckMeta(
    check_id="azure-compute-001",
    name="Managed Disk Encryption Enabled",
    family="Storage",
    provider="azure",
    service="compute",
    resource_type="disk",
    severity="high",
    description="Azure managed disks must have encryption at rest enabled. All managed disks should use platform or customer-managed key encryption.",
    remediation="All Azure managed disks are encrypted by default with platform-managed keys. For CMK: Disk > Encryption > Customer-managed key.",
    source_type="vendor",
    source_vendor="Microsoft",
    source_product=_SRC_MDFC,
    source_url=_SRC_MDFC_URL,
    source_retrieved=_RETRIEVED,
    func=_check_disk_encryption_enabled,
))
