"""
CloudGuard Pro CSPM — Azure Collector
Aniza Corp | Shahryar Jahangir

Credentials: Service Principal via env vars or credential_ref JSON blob.
Required env vars:
  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
Or credential_ref = '{"tenant_id":"...","client_id":"...","client_secret":"..."}'

All collection is READ-ONLY.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

log = logging.getLogger(__name__)


class AzureCollector:
    def collect(self, conn) -> List[Dict[str, Any]]:
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential
            from azure.mgmt.resource import ResourceManagementClient
            from azure.mgmt.storage import StorageManagementClient
            from azure.mgmt.sql import SqlManagementClient
            from azure.mgmt.keyvault import KeyVaultManagementClient
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.containerservice import ContainerServiceClient
            from azure.mgmt.monitor import MonitorManagementClient
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.security import SecurityCenter
        except ImportError:
            log.warning("azure-mgmt libraries not installed. Azure collection skipped.")
            return []

        credential, sub_id = self._build_credential(conn)
        bundles = []

        try:
            bundles += self._collect_storage(credential, sub_id)
            bundles += self._collect_sql(credential, sub_id)
            bundles += self._collect_keyvault(credential, sub_id)
            bundles += self._collect_nsg(credential, sub_id)
            bundles += self._collect_aks(credential, sub_id)
            bundles += self._collect_disks(credential, sub_id)
        except Exception as e:
            log.error("Azure collection error: %s", e)

        return bundles

    def _build_credential(self, conn):
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential
        except ImportError:
            raise

        cred_type = (conn.credential_type or "env").strip().lower()
        cred_ref  = (conn.credential_ref  or "").strip()
        sub_id = conn.subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")

        # ── file: path to a credentials file ─────────────────────────────────
        if cred_type == "file" and cred_ref:
            path = os.path.expanduser(cred_ref)
            log.info("Azure: loading credentials from file '%s'", path)
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"Azure credentials file not found: {path}\n"
                    "Accepted formats:\n"
                    '  JSON:       {"tenant_id":"...","client_id":"...","client_secret":"..."}\n'
                    "  INI/props:  tenant_id=...\n"
                    "              client_id=...\n"
                    "              client_secret=..."
                )
            if os.path.isdir(path):
                raise IsADirectoryError(
                    f"'{path}' is a directory, not a credentials file."
                )
            with open(path) as f2:
                raw = f2.read().strip()

            if raw.startswith("{"):
                try:
                    creds_json = json.loads(raw)
                    log.info("Azure: parsed JSON credentials from %s", path)
                except json.JSONDecodeError as e:
                    raise ValueError(
                        f"Failed to parse Azure credentials file as JSON: {e}\n"
                        'Expected: {"tenant_id":"...","client_id":"...","client_secret":"..."}'
                    ) from e
            else:
                # INI / properties format (key = value, no section header needed)
                import configparser
                config = configparser.ConfigParser()
                config.read_string("[creds]\n" + raw)
                section = config["creds"]
                creds_json = {
                    "tenant_id":      section.get("tenant_id", "").strip(),
                    "client_id":      section.get("client_id", "").strip(),
                    "client_secret":  section.get("client_secret", "").strip(),
                    "subscription_id": section.get("subscription_id", "").strip(),
                }
                log.info("Azure: parsed INI/properties credentials from %s", path)

            missing = [k for k in ("tenant_id", "client_id", "client_secret") if not creds_json.get(k)]
            if missing:
                raise ValueError(f"Azure credentials file missing: {', '.join(missing)}")
            if creds_json.get("subscription_id") and not sub_id:
                sub_id = creds_json["subscription_id"]
            return ClientSecretCredential(
                tenant_id=creds_json["tenant_id"],
                client_id=creds_json["client_id"],
                client_secret=creds_json["client_secret"],
            ), sub_id

        # ── inline JSON in credential_ref ─────────────────────────────────────
        if cred_ref and cred_ref.startswith("{"):
            try:
                creds_json = json.loads(cred_ref)
                log.info("Azure: using inline JSON credentials")
                if creds_json.get("subscription_id") and not sub_id:
                    sub_id = creds_json["subscription_id"]
                return ClientSecretCredential(
                    tenant_id=creds_json["tenant_id"],
                    client_id=creds_json["client_id"],
                    client_secret=creds_json["client_secret"],
                ), sub_id
            except (json.JSONDecodeError, KeyError) as e:
                raise ValueError(f"Failed to parse inline JSON credential_ref: {e}") from e

        # ── env vars / workload identity / managed identity ───────────────────
        log.info("Azure: using DefaultAzureCredential (env vars / managed identity)")
        return DefaultAzureCredential(), sub_id

    def _collect_storage(self, cred, sub_id) -> List[Dict]:
        items = []
        try:
            from azure.mgmt.storage import StorageManagementClient
            client = StorageManagementClient(cred, sub_id)
            for account in client.storage_accounts.list():
                item = account.as_dict()
                item["id"] = account.id
                item["location"] = account.location
                items.append(item)
        except Exception as e:
            log.error("Azure Storage collection error: %s", e)
        return [{"service": "storage", "resource_type": "storage_account", "items": items}] if items else []

    def _collect_sql(self, cred, sub_id) -> List[Dict]:
        server_items = []
        db_items = []
        try:
            from azure.mgmt.sql import SqlManagementClient
            client = SqlManagementClient(cred, sub_id)
            for server in client.servers.list():
                srv = server.as_dict()
                srv["id"] = server.id
                # Get auditing policy
                try:
                    rg = server.id.split("/resourceGroups/")[1].split("/")[0]
                    audit = client.server_blob_auditing_policies.get(rg, server.name)
                    srv["auditingPolicy"] = audit.as_dict()
                except Exception:
                    srv["auditingPolicy"] = {}
                server_items.append(srv)

                # Get databases
                try:
                    for db in client.databases.list_by_server(rg, server.name):
                        db_item = db.as_dict()
                        db_item["id"] = db.id
                        try:
                            tde = client.transparent_data_encryptions.get(rg, server.name, db.name)
                            db_item["transparentDataEncryption"] = {"status": str(tde.status)}
                        except Exception:
                            db_item["transparentDataEncryption"] = {}
                        db_items.append(db_item)
                except Exception:
                    pass
        except Exception as e:
            log.error("Azure SQL collection error: %s", e)

        bundles = []
        if server_items:
            bundles.append({"service": "sql", "resource_type": "sql_server", "items": server_items})
        if db_items:
            bundles.append({"service": "sql", "resource_type": "sql_database", "items": db_items})
        return bundles

    def _collect_keyvault(self, cred, sub_id) -> List[Dict]:
        items = []
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
            client = KeyVaultManagementClient(cred, sub_id)
            for vault in client.vaults.list():
                item = vault.as_dict() if hasattr(vault, "as_dict") else {}
                item["id"] = vault.id
                items.append(item)
        except Exception as e:
            log.error("Azure KeyVault collection error: %s", e)
        return [{"service": "keyvault", "resource_type": "vault", "items": items}] if items else []

    def _collect_nsg(self, cred, sub_id) -> List[Dict]:
        items = []
        try:
            from azure.mgmt.network import NetworkManagementClient
            client = NetworkManagementClient(cred, sub_id)
            for nsg in client.network_security_groups.list_all():
                item = nsg.as_dict()
                item["id"] = nsg.id
                item["location"] = nsg.location
                items.append(item)
        except Exception as e:
            log.error("Azure NSG collection error: %s", e)
        return [{"service": "network", "resource_type": "network_security_group", "items": items}] if items else []

    def _collect_aks(self, cred, sub_id) -> List[Dict]:
        items = []
        try:
            from azure.mgmt.containerservice import ContainerServiceClient
            client = ContainerServiceClient(cred, sub_id)
            for cluster in client.managed_clusters.list():
                item = cluster.as_dict()
                item["id"] = cluster.id
                items.append(item)
        except Exception as e:
            log.error("Azure AKS collection error: %s", e)
        return [{"service": "aks", "resource_type": "managed_cluster", "items": items}] if items else []

    def _collect_disks(self, cred, sub_id) -> List[Dict]:
        items = []
        try:
            from azure.mgmt.compute import ComputeManagementClient
            client = ComputeManagementClient(cred, sub_id)
            for disk in client.disks.list():
                item = disk.as_dict()
                item["id"] = disk.id
                items.append(item)
        except Exception as e:
            log.error("Azure Disks collection error: %s", e)
        return [{"service": "compute", "resource_type": "disk", "items": items}] if items else []
