"""
CloudGuard Pro CSPM — Azure Check Pack
Aniza Corp | Shahryar Jahangir

Sources:
- CIS Microsoft Azure Foundations Benchmark v2.0.0
  https://www.cisecurity.org/benchmark/azure
- Microsoft Defender for Cloud Security Recommendations
  https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference
- Azure Policy built-in definitions (public, MIT-like terms)
  https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies

License: Azure documentation public. CIS benchmark mapping reference only.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from backend.check_engine.engine import CheckMeta, CheckResult, register_check

_SRC_CIS = "CIS Microsoft Azure Foundations Benchmark v2.0.0"
_SRC_CIS_URL = "https://www.cisecurity.org/benchmark/azure"
_SRC_MDFC = "Microsoft Defender for Cloud"
_SRC_MDFC_URL = "https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference"
_RETRIEVED = "2024-01-15"


# ─── Storage ─────────────────────────────────────────────────────────────────

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


# ─── SQL ─────────────────────────────────────────────────────────────────────

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


# ─── Key Vault ────────────────────────────────────────────────────────────────

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


# ─── Networking (NSG) ────────────────────────────────────────────────────────

def _check_nsg_no_unrestricted_ssh(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 6.1 — NSG must not allow inbound SSH from Any."""
    violations = []
    for rule in resource.get("securityRules", []):
        direction = rule.get("properties", {}).get("direction", "")
        if direction != "Inbound":
            continue
        dest_port = rule.get("properties", {}).get("destinationPortRange", "")
        access = rule.get("properties", {}).get("access", "")
        source = rule.get("properties", {}).get("sourceAddressPrefix", "")
        if access == "Allow" and source in ("*", "Any", "Internet", "0.0.0.0/0"):
            if dest_port in ("22", "*") or (dest_port.replace(" ", "").startswith("22")):
                violations.append({"rule": rule.get("name"), "port": dest_port})
    return len(violations) == 0, {"violations": violations}

register_check(CheckMeta(
    check_id="azure-nsg-001",
    name="NSG: No Unrestricted Inbound SSH Access",
    family="Networking",
    provider="azure",
    service="network",
    resource_type="network_security_group",
    severity="critical",
    description="Azure Network Security Groups must not allow unrestricted inbound SSH access (port 22) from any source.",
    remediation="Remove or restrict NSG rules that allow SSH from Any/Internet/0.0.0.0/0. Restrict to specific management IP ranges.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "6.1"}],
    func=_check_nsg_no_unrestricted_ssh,
))


def _check_nsg_no_unrestricted_rdp(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 6.2 — NSG must not allow inbound RDP from Any."""
    violations = []
    for rule in resource.get("securityRules", []):
        direction = rule.get("properties", {}).get("direction", "")
        if direction != "Inbound":
            continue
        dest_port = rule.get("properties", {}).get("destinationPortRange", "")
        access = rule.get("properties", {}).get("access", "")
        source = rule.get("properties", {}).get("sourceAddressPrefix", "")
        if access == "Allow" and source in ("*", "Any", "Internet", "0.0.0.0/0"):
            if dest_port in ("3389", "*"):
                violations.append({"rule": rule.get("name"), "port": dest_port})
    return len(violations) == 0, {"violations": violations}

register_check(CheckMeta(
    check_id="azure-nsg-002",
    name="NSG: No Unrestricted Inbound RDP Access",
    family="Networking",
    provider="azure",
    service="network",
    resource_type="network_security_group",
    severity="critical",
    description="Azure NSGs must not allow unrestricted inbound RDP (port 3389) from any source.",
    remediation="Restrict or remove NSG rules that allow RDP from Any source. Use Azure Bastion for remote desktop access.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="2.0.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS Azure 2.0", "control_id": "6.2"}],
    func=_check_nsg_no_unrestricted_rdp,
))


# ─── AKS ─────────────────────────────────────────────────────────────────────

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


# ─── Activity Logs ────────────────────────────────────────────────────────────

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


# ─── Disk Encryption ─────────────────────────────────────────────────────────

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


# ─── Security Center ──────────────────────────────────────────────────────────

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
