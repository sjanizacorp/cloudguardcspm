import logging
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class AzureCollector:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, subscription_id: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id
        self._credential = None
        self._init_clients()

    def _init_clients(self):
        try:
            from azure.identity import ClientSecretCredential
            self._credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
        except ImportError:
            logger.error("azure-identity not installed")

    def collect_all(self) -> List[Dict[str, Any]]:
        assets = []
        assets.extend(self.collect_virtual_machines())
        assets.extend(self.collect_storage_accounts())
        assets.extend(self.collect_sql_databases())
        assets.extend(self.collect_network_security_groups())
        assets.extend(self.collect_key_vaults())
        return assets

    def collect_virtual_machines(self) -> List[Dict]:
        assets = []
        try:
            from azure.mgmt.compute import ComputeManagementClient
            client = ComputeManagementClient(self._credential, self.subscription_id)
            for vm in client.virtual_machines.list_all():
                assets.append({
                    "id": f"azure-vm-{vm.name}",
                    "cloud_provider": "azure",
                    "account_id": self.subscription_id,
                    "region": vm.location,
                    "resource_type": "Virtual Machine",
                    "resource_id": vm.id,
                    "name": vm.name,
                    "tags": dict(vm.tags or {}),
                    "properties": {
                        "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else None,
                        "os_type": vm.storage_profile.os_disk.os_type if vm.storage_profile else None,
                        "provisioning_state": vm.provisioning_state,
                    },
                    "is_public": False,
                    "last_scanned": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"Azure VM collection error: {e}")
        return assets

    def collect_storage_accounts(self) -> List[Dict]:
        assets = []
        try:
            from azure.mgmt.storage import StorageManagementClient
            client = StorageManagementClient(self._credential, self.subscription_id)
            for account in client.storage_accounts.list():
                is_public = account.allow_blob_public_access or False
                assets.append({
                    "id": f"azure-storage-{account.name}",
                    "cloud_provider": "azure",
                    "account_id": self.subscription_id,
                    "region": account.location,
                    "resource_type": "Storage Account",
                    "resource_id": account.id,
                    "name": account.name,
                    "tags": dict(account.tags or {}),
                    "properties": {
                        "sku": account.sku.name if account.sku else None,
                        "allow_blob_public_access": account.allow_blob_public_access,
                        "https_only": account.enable_https_traffic_only,
                        "minimum_tls_version": account.minimum_tls_version,
                        "allow_shared_key_access": account.allow_shared_key_access,
                    },
                    "is_public": is_public,
                    "last_scanned": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"Azure storage collection error: {e}")
        return assets

    def collect_sql_databases(self) -> List[Dict]:
        assets = []
        try:
            from azure.mgmt.sql import SqlManagementClient
            client = SqlManagementClient(self._credential, self.subscription_id)
            for server in client.servers.list():
                rg = server.id.split("/")[4]
                for db in client.databases.list_by_server(rg, server.name):
                    assets.append({
                        "id": f"azure-sql-{db.name}",
                        "cloud_provider": "azure",
                        "account_id": self.subscription_id,
                        "region": db.location,
                        "resource_type": "SQL Database",
                        "resource_id": db.id,
                        "name": db.name,
                        "tags": dict(db.tags or {}),
                        "properties": {
                            "server_name": server.name,
                            "sku": db.sku.name if db.sku else None,
                            "status": db.status,
                        },
                        "is_public": False,
                        "last_scanned": datetime.utcnow().isoformat()
                    })
        except Exception as e:
            logger.error(f"Azure SQL collection error: {e}")
        return assets

    def collect_network_security_groups(self) -> List[Dict]:
        assets = []
        try:
            from azure.mgmt.network import NetworkManagementClient
            client = NetworkManagementClient(self._credential, self.subscription_id)
            for nsg in client.network_security_groups.list_all():
                open_rules = [
                    r for r in (nsg.security_rules or [])
                    if r.access == "Allow" and r.direction == "Inbound"
                    and r.source_address_prefix in ["*", "0.0.0.0/0", "Internet"]
                ]
                assets.append({
                    "id": f"azure-nsg-{nsg.name}",
                    "cloud_provider": "azure",
                    "account_id": self.subscription_id,
                    "region": nsg.location,
                    "resource_type": "Network Security Group",
                    "resource_id": nsg.id,
                    "name": nsg.name,
                    "tags": dict(nsg.tags or {}),
                    "properties": {
                        "open_inbound_rules": len(open_rules),
                        "total_rules": len(nsg.security_rules or []),
                    },
                    "is_public": len(open_rules) > 0,
                    "last_scanned": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"Azure NSG collection error: {e}")
        return assets

    def collect_key_vaults(self) -> List[Dict]:
        assets = []
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
            client = KeyVaultManagementClient(self._credential, self.subscription_id)
            for vault in client.vaults.list():
                assets.append({
                    "id": f"azure-kv-{vault.name}",
                    "cloud_provider": "azure",
                    "account_id": self.subscription_id,
                    "region": vault.location,
                    "resource_type": "Key Vault",
                    "resource_id": vault.id,
                    "name": vault.name,
                    "tags": dict(vault.tags or {}),
                    "properties": {
                        "soft_delete_enabled": getattr(vault.properties, "enable_soft_delete", None),
                        "purge_protection": getattr(vault.properties, "enable_purge_protection", None),
                    },
                    "is_public": False,
                    "last_scanned": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"Azure Key Vault collection error: {e}")
        return assets
