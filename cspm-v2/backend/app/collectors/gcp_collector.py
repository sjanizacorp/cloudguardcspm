import logging
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class GCPCollector:
    def __init__(self, project_id: str, credentials_json: dict = None):
        self.project_id = project_id
        self.credentials_json = credentials_json
        self._credentials = None
        self._init_credentials()

    def _init_credentials(self):
        try:
            if self.credentials_json:
                from google.oauth2 import service_account
                self._credentials = service_account.Credentials.from_service_account_info(
                    self.credentials_json,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
        except ImportError:
            logger.error("google-auth not installed")
        except Exception as e:
            logger.error(f"GCP credentials init error: {e}")

    def collect_all(self) -> List[Dict[str, Any]]:
        assets = []
        assets.extend(self.collect_compute_instances())
        assets.extend(self.collect_storage_buckets())
        assets.extend(self.collect_cloud_sql())
        assets.extend(self.collect_iam_service_accounts())
        assets.extend(self.collect_firewall_rules())
        return assets

    def collect_compute_instances(self) -> List[Dict]:
        assets = []
        try:
            from googleapiclient import discovery
            service = discovery.build("compute", "v1", credentials=self._credentials)
            result = service.instances().aggregatedList(project=self.project_id).execute()
            for zone_name, zone_data in result.get("items", {}).items():
                for instance in zone_data.get("instances", []):
                    has_public_ip = any(
                        ac.get("accessConfigs", [{}])[0].get("natIP")
                        for ni in instance.get("networkInterfaces", [])
                        for ac in ni.get("accessConfigs", [])
                    )
                    assets.append({
                        "id": f"gcp-vm-{instance['name']}",
                        "cloud_provider": "gcp",
                        "account_id": self.project_id,
                        "region": zone_name.replace("zones/", ""),
                        "resource_type": "Compute Instance",
                        "resource_id": str(instance["id"]),
                        "name": instance["name"],
                        "tags": instance.get("labels", {}),
                        "properties": {
                            "machine_type": instance.get("machineType", "").split("/")[-1],
                            "status": instance.get("status"),
                            "public_ip": has_public_ip,
                            "shielded_vm": instance.get("shieldedInstanceConfig", {}).get("enableSecureBoot"),
                            "service_accounts": [sa.get("email") for sa in instance.get("serviceAccounts", [])],
                        },
                        "is_public": has_public_ip,
                        "last_scanned": datetime.utcnow().isoformat()
                    })
        except Exception as e:
            logger.error(f"GCP compute collection error: {e}")
        return assets

    def collect_storage_buckets(self) -> List[Dict]:
        assets = []
        try:
            from googleapiclient import discovery
            service = discovery.build("storage", "v1", credentials=self._credentials)
            result = service.buckets().list(project=self.project_id).execute()
            for bucket in result.get("items", []):
                is_public = False
                try:
                    iam = service.buckets().getIamPolicy(bucket=bucket["name"]).execute()
                    for binding in iam.get("bindings", []):
                        if "allUsers" in binding.get("members", []) or "allAuthenticatedUsers" in binding.get("members", []):
                            is_public = True
                except Exception:
                    pass
                assets.append({
                    "id": f"gcp-gcs-{bucket['name']}",
                    "cloud_provider": "gcp",
                    "account_id": self.project_id,
                    "region": bucket.get("location", "global"),
                    "resource_type": "Cloud Storage Bucket",
                    "resource_id": bucket["name"],
                    "name": bucket["name"],
                    "tags": bucket.get("labels", {}),
                    "properties": {
                        "storage_class": bucket.get("storageClass"),
                        "versioning": bucket.get("versioning", {}).get("enabled", False),
                        "public_access": is_public,
                        "uniform_bucket_level_access": bucket.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled", False),
                    },
                    "is_public": is_public,
                    "last_scanned": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"GCP storage collection error: {e}")
        return assets

    def collect_cloud_sql(self) -> List[Dict]:
        assets = []
        try:
            from googleapiclient import discovery
            service = discovery.build("sqladmin", "v1beta4", credentials=self._credentials)
            result = service.instances().list(project=self.project_id).execute()
            for instance in result.get("items", []):
                is_public = any(
                    n.get("value") == "0.0.0.0/0"
                    for n in instance.get("settings", {}).get("ipConfiguration", {}).get("authorizedNetworks", [])
                )
                assets.append({
                    "id": f"gcp-sql-{instance['name']}",
                    "cloud_provider": "gcp",
                    "account_id": self.project_id,
                    "region": instance.get("region", "unknown"),
                    "resource_type": "Cloud SQL Instance",
                    "resource_id": instance["name"],
                    "name": instance["name"],
                    "tags": instance.get("settings", {}).get("userLabels", {}),
                    "properties": {
                        "database_version": instance.get("databaseVersion"),
                        "state": instance.get("state"),
                        "public_ip": is_public,
                        "backup_enabled": instance.get("settings", {}).get("backupConfiguration", {}).get("enabled"),
                        "ssl_required": instance.get("settings", {}).get("ipConfiguration", {}).get("requireSsl"),
                    },
                    "is_public": is_public,
                    "last_scanned": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"GCP SQL collection error: {e}")
        return assets

    def collect_iam_service_accounts(self) -> List[Dict]:
        assets = []
        try:
            from googleapiclient import discovery
            service = discovery.build("iam", "v1", credentials=self._credentials)
            result = service.projects().serviceAccounts().list(name=f"projects/{self.project_id}").execute()
            for sa in result.get("accounts", []):
                assets.append({
                    "id": f"gcp-sa-{sa['uniqueId']}",
                    "cloud_provider": "gcp",
                    "account_id": self.project_id,
                    "region": "global",
                    "resource_type": "Service Account",
                    "resource_id": sa["uniqueId"],
                    "name": sa["displayName"] or sa["email"],
                    "tags": {},
                    "properties": {
                        "email": sa["email"],
                        "disabled": sa.get("disabled", False),
                    },
                    "is_public": False,
                    "last_scanned": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"GCP service account collection error: {e}")
        return assets

    def collect_firewall_rules(self) -> List[Dict]:
        assets = []
        try:
            from googleapiclient import discovery
            service = discovery.build("compute", "v1", credentials=self._credentials)
            result = service.firewalls().list(project=self.project_id).execute()
            for rule in result.get("items", []):
                open_to_world = any(
                    r in rule.get("sourceRanges", []) for r in ["0.0.0.0/0", "::/0"]
                )
                assets.append({
                    "id": f"gcp-fw-{rule['name']}",
                    "cloud_provider": "gcp",
                    "account_id": self.project_id,
                    "region": "global",
                    "resource_type": "Firewall Rule",
                    "resource_id": str(rule["id"]),
                    "name": rule["name"],
                    "tags": {},
                    "properties": {
                        "direction": rule.get("direction"),
                        "action": "allow" if "allowed" in rule else "deny",
                        "source_ranges": rule.get("sourceRanges", []),
                        "allowed": rule.get("allowed", []),
                        "open_to_world": open_to_world,
                    },
                    "is_public": open_to_world,
                    "last_scanned": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"GCP firewall collection error: {e}")
        return assets
