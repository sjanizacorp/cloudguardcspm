"""
CloudGuard Pro CSPM — GCP Collector
Credentials: Application Default Credentials or service account JSON via credential_ref path.
All collection is READ-ONLY.
"""
from __future__ import annotations
import json, logging, os
from typing import Any, Dict, List

log = logging.getLogger(__name__)


class GCPCollector:
    def collect(self, conn) -> List[Dict[str, Any]]:
        try:
            from google.oauth2 import service_account
            from googleapiclient import discovery
            import google.auth
        except ImportError:
            log.warning("google-cloud libraries not installed. GCP collection skipped.")
            return []

        project_id = conn.project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        credentials = self._build_credentials(conn)
        bundles = []
        try:
            bundles += self._collect_gcs(credentials, project_id)
            bundles += self._collect_compute_firewalls(credentials, project_id)
            bundles += self._collect_cloudsql(credentials, project_id)
            bundles += self._collect_kms(credentials, project_id)
            bundles += self._collect_gke(credentials, project_id)
            bundles += self._collect_bigquery(credentials, project_id)
            bundles += self._collect_iam_service_accounts(credentials, project_id)
        except Exception as e:
            log.error("GCP collection error: %s", e)
        return bundles

    def _build_credentials(self, conn):
        try:
            cred_type = (conn.credential_type or "env").strip().lower()
            cred_ref  = (conn.credential_ref  or "").strip()

            # ── file: explicit path to service account JSON ───────────────────
            if cred_type == "file" and cred_ref:
                path = os.path.expanduser(cred_ref)
                log.info("GCP: loading service account from file '%s'", path)
                if not os.path.exists(path):
                    raise FileNotFoundError(
                        f"GCP credentials file not found: {path}\n"
                        "Expected: service account JSON key file from "
                        "Google Cloud Console → IAM → Service Accounts → Keys → Add Key → JSON"
                    )
                if os.path.isdir(path):
                    raise IsADirectoryError(
                        f"'{path}' is a directory, not a credentials file.\n"
                        "Point to the service account JSON key file."
                    )
                with open(path) as f2:
                    raw = f2.read().strip()
                try:
                    sa_data = json.loads(raw)
                except json.JSONDecodeError as e:
                    raise ValueError(
                        f"Failed to parse GCP credentials file as JSON: {e}\n"
                        "File must be a service account JSON key from Google Cloud Console."
                    ) from e
                from google.oauth2 import service_account
                log.info("GCP: loaded service account '%s' from %s",
                         sa_data.get("client_email", "unknown"), path)
                return service_account.Credentials.from_service_account_info(
                    sa_data,
                    scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
                )

            # ── inline JSON service account in credential_ref ─────────────────
            if cred_ref and cred_ref.startswith("{"):
                try:
                    sa_data = json.loads(cred_ref)
                    from google.oauth2 import service_account
                    log.info("GCP: using inline JSON service account credentials")
                    return service_account.Credentials.from_service_account_info(
                        sa_data,
                        scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
                    )
                except (json.JSONDecodeError, Exception) as e:
                    raise ValueError(f"Failed to parse inline GCP JSON credentials: {e}") from e

            # ── credential_ref as bare file path ──────────────────────────────
            if cred_ref:
                path = os.path.expanduser(cred_ref)
                if os.path.isfile(path):
                    log.info("GCP: loading service account from path: %s", path)
                    from google.oauth2 import service_account
                    return service_account.Credentials.from_service_account_file(
                        path,
                        scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
                    )

            # ── Application Default Credentials ───────────────────────────────
            log.info("GCP: using Application Default Credentials "
                     "(GOOGLE_APPLICATION_CREDENTIALS env var or gcloud auth)")
            import google.auth
            credentials, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
            )
            return credentials

        except Exception as e:
            log.error("GCP credential build error: %s", e)
            raise

    def _collect_gcs(self, creds, project_id) -> List[Dict]:
        items = []
        try:
            from google.cloud import storage
            client = storage.Client(project=project_id, credentials=creds)
            for bucket in client.list_buckets():
                item = {"name": bucket.name, "location": bucket.location, "region": bucket.location}
                try:
                    policy = bucket.get_iam_policy()
                    bindings = []
                    for role in policy:
                        members = list(policy[role])
                        bindings.append({"role": role, "members": members})
                    item["iam_policy"] = {"bindings": bindings}
                except Exception:
                    item["iam_policy"] = {}
                items.append(item)
        except Exception as e:
            log.error("GCS collection error: %s", e)
        return [{"service": "storage", "resource_type": "bucket", "items": items}] if items else []

    def _collect_compute_firewalls(self, creds, project_id) -> List[Dict]:
        items = []
        try:
            from googleapiclient import discovery
            service = discovery.build("compute", "v1", credentials=creds)
            request = service.firewalls().list(project=project_id)
            while request is not None:
                resp = request.execute()
                for fw in resp.get("items", []):
                    fw["region"] = "global"
                    items.append(fw)
                request = service.firewalls().list_next(previous_request=request, previous_response=resp)
        except Exception as e:
            log.error("GCP Firewall collection error: %s", e)
        return [{"service": "compute", "resource_type": "firewall", "items": items}] if items else []

    def _collect_cloudsql(self, creds, project_id) -> List[Dict]:
        items = []
        try:
            from googleapiclient import discovery
            service = discovery.build("sqladmin", "v1beta4", credentials=creds)
            resp = service.instances().list(project=project_id).execute()
            for instance in resp.get("items", []):
                instance["region"] = instance.get("region", "unknown")
                items.append(instance)
        except Exception as e:
            log.error("GCP CloudSQL collection error: %s", e)
        return [{"service": "cloudsql", "resource_type": "database_instance", "items": items}] if items else []

    def _collect_kms(self, creds, project_id) -> List[Dict]:
        items = []
        try:
            from google.cloud import kms
            client = kms.KeyManagementServiceClient(credentials=creds)
            parent = f"projects/{project_id}/locations/-"
            for key_ring in client.list_key_rings(request={"parent": parent}):
                for key in client.list_crypto_keys(request={"parent": key_ring.name}):
                    item = {"name": key.name, "rotationPeriod": str(key.rotation_period.total_seconds()) + "s" if key.rotation_period else None}
                    items.append(item)
        except Exception as e:
            log.error("GCP KMS collection error: %s", e)
        return [{"service": "kms", "resource_type": "crypto_key", "items": items}] if items else []

    def _collect_gke(self, creds, project_id) -> List[Dict]:
        items = []
        try:
            from google.cloud import container_v1
            client = container_v1.ClusterManagerClient(credentials=creds)
            resp = client.list_clusters(parent=f"projects/{project_id}/locations/-")
            for cluster in resp.clusters:
                item = type(cluster).to_dict(cluster)
                item["region"] = cluster.location
                items.append(item)
        except Exception as e:
            log.error("GCP GKE collection error: %s", e)
        return [{"service": "container", "resource_type": "cluster", "items": items}] if items else []

    def _collect_bigquery(self, creds, project_id) -> List[Dict]:
        items = []
        try:
            from google.cloud import bigquery
            client = bigquery.Client(project=project_id, credentials=creds)
            for dataset in client.list_datasets():
                item = {"datasetReference": {"datasetId": dataset.dataset_id}, "region": dataset.location}
                try:
                    full = client.get_dataset(dataset.reference)
                    item["access"] = [{"specialGroup": e.special_group, "role": e.role} for e in full.access_entries if e.special_group]
                except Exception:
                    item["access"] = []
                items.append(item)
        except Exception as e:
            log.error("GCP BigQuery collection error: %s", e)
        return [{"service": "bigquery", "resource_type": "dataset", "items": items}] if items else []

    def _collect_iam_service_accounts(self, creds, project_id) -> List[Dict]:
        items = []
        try:
            from googleapiclient import discovery
            service = discovery.build("iam", "v1", credentials=creds)
            resp = service.projects().serviceAccounts().list(name=f"projects/{project_id}").execute()
            resource = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            bindings_map = {}
            for b in resource.get("bindings", []):
                for member in b.get("members", []):
                    if member.startswith("serviceAccount:"):
                        sa_email = member.split(":", 1)[1]
                        bindings_map.setdefault(sa_email, []).append(b["role"])
            for sa in resp.get("accounts", []):
                sa["roles"] = bindings_map.get(sa.get("email", ""), [])
                items.append(sa)
        except Exception as e:
            log.error("GCP IAM SA collection error: %s", e)
        return [{"service": "iam", "resource_type": "service_account", "items": items}] if items else []


# ─────────────────────────────────────────────────────────────────────────────

class IBMCollector:
    """
    IBM Cloud collector using ibm-cloud-sdk-core and ibm-platform-services.
    Credentials: IBMCLOUD_API_KEY env var or credential_ref.
    """
    def collect(self, conn) -> List[Dict[str, Any]]:
        try:
            from ibm_platform_services import IamIdentityV1, GlobalCatalogV1
            from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
        except ImportError:
            log.warning("ibm-platform-services not installed. IBM collection skipped.")
            return []

        api_key = os.environ.get("IBMCLOUD_API_KEY") or conn.credential_ref or ""
        if not api_key:
            log.warning("No IBM API key. Collection skipped.")
            return []

        bundles = []
        try:
            bundles += self._collect_iam(api_key, conn)
            bundles += self._collect_cos(api_key, conn)
            bundles += self._collect_activity_tracker(api_key, conn)
        except Exception as e:
            log.error("IBM collection error: %s", e)
        return bundles

    def _collect_iam(self, api_key, conn) -> List[Dict]:
        items = []
        try:
            from ibm_platform_services import IamIdentityV1
            from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
            auth = IAMAuthenticator(api_key)
            client = IamIdentityV1(authenticator=auth)
            account_id = conn.ibm_account_id or ""
            settings = client.get_account_settings(account_id=account_id).get_result()
            items.append(settings)
        except Exception as e:
            log.warning("IBM IAM collection error: %s", e)
        return [{"service": "iam", "resource_type": "account_settings", "items": items}] if items else []

    def _collect_cos(self, api_key, conn) -> List[Dict]:
        items = []
        try:
            import ibm_boto3
            from ibm_botocore.client import Config
            cos = ibm_boto3.resource(
                "s3",
                ibm_api_key_id=api_key,
                ibm_service_instance_id=os.environ.get("IBM_COS_INSTANCE_ID", ""),
                config=Config(signature_version="oauth"),
                endpoint_url="https://s3.us.cloud-object-storage.appdomain.cloud",
            )
            for bucket in cos.buckets.all():
                item = {"name": bucket.name, "region": "us"}
                try:
                    acl = bucket.Acl().grants
                    item["public_access_enabled"] = any(
                        g.get("Grantee", {}).get("URI", "").endswith("AllUsers") for g in acl
                    )
                except Exception:
                    item["public_access_enabled"] = False
                items.append(item)
        except Exception as e:
            log.warning("IBM COS collection error: %s", e)
        return [{"service": "cloud-object-storage", "resource_type": "bucket", "items": items}] if items else []

    def _collect_activity_tracker(self, api_key, conn) -> List[Dict]:
        items = []
        try:
            from ibm_platform_services import ResourceControllerV2
            from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
            auth = IAMAuthenticator(api_key)
            rc = ResourceControllerV2(authenticator=auth)
            resp = rc.list_resource_instances(type="service_instance").get_result()
            trackers = [r for r in resp.get("resources", []) if "activity-tracker" in r.get("url", "").lower()]
            for t in trackers:
                items.append({"active": t.get("state") == "active", "name": t.get("name")})
        except Exception as e:
            log.warning("IBM Activity Tracker collection error: %s", e)
        return [{"service": "activity-tracker", "resource_type": "tracker_instance", "items": items}] if items else []


# ─────────────────────────────────────────────────────────────────────────────

class OCICollector:
    """
    OCI collector using oci-python-sdk.
    Credentials: ~/.oci/config or credential_ref path to config file.
    """
    def collect(self, conn) -> List[Dict[str, Any]]:
        try:
            import oci
        except ImportError:
            log.warning("oci SDK not installed. OCI collection skipped.")
            return []

        config = self._build_config(conn)
        tenancy_id = conn.tenancy_id or config.get("tenancy", "")
        bundles = []
        try:
            bundles += self._collect_object_storage(config, tenancy_id)
            bundles += self._collect_iam_users(config, tenancy_id)
            bundles += self._collect_audit(config, tenancy_id)
            bundles += self._collect_cloud_guard(config, tenancy_id)
        except Exception as e:
            log.error("OCI collection error: %s", e)
        return bundles

    def _build_config(self, conn) -> dict:
        import oci
        if conn.credential_ref and os.path.isfile(conn.credential_ref):
            return oci.config.from_file(file_location=conn.credential_ref)
        return oci.config.from_file()  # default ~/.oci/config

    def _collect_object_storage(self, config, tenancy_id) -> List[Dict]:
        items = []
        try:
            import oci
            namespace_client = oci.object_storage.ObjectStorageClient(config)
            namespace = namespace_client.get_namespace().data
            compartments = self._list_compartments(config, tenancy_id)
            for compartment_id in compartments:
                try:
                    buckets = namespace_client.list_buckets(namespace, compartment_id).data
                    for bucket_summary in buckets:
                        bucket = namespace_client.get_bucket(namespace, bucket_summary.name).data
                        items.append({
                            "name": bucket.name,
                            "publicAccessType": bucket.public_access_type,
                            "compartmentId": compartment_id,
                        })
                except Exception:
                    pass
        except Exception as e:
            log.error("OCI ObjectStorage collection error: %s", e)
        return [{"service": "objectstorage", "resource_type": "bucket", "items": items}] if items else []

    def _collect_iam_users(self, config, tenancy_id) -> List[Dict]:
        items = []
        try:
            import oci
            identity = oci.identity.IdentityClient(config)
            users = identity.list_users(tenancy_id).data
            for user in users:
                mfa_devices = identity.list_mfa_totp_devices(user.id).data
                items.append({
                    "id": user.id,
                    "name": user.name,
                    "isMfaActivated": len(mfa_devices) > 0,
                })
        except Exception as e:
            log.error("OCI IAM users collection error: %s", e)
        return [{"service": "iam", "resource_type": "user", "items": items}] if items else []

    def _collect_audit(self, config, tenancy_id) -> List[Dict]:
        items = []
        try:
            import oci
            audit = oci.audit.AuditClient(config)
            cfg = audit.get_configuration(tenancy_id).data
            items.append({"retentionPeriodDays": cfg.retention_period_days})
        except Exception as e:
            log.error("OCI Audit collection error: %s", e)
        return [{"service": "audit", "resource_type": "configuration", "items": items}] if items else []

    def _collect_cloud_guard(self, config, tenancy_id) -> List[Dict]:
        items = []
        try:
            import oci
            cg = oci.cloud_guard.CloudGuardClient(config)
            cfg = cg.get_configuration(tenancy_id).data
            items.append({"status": cfg.status})
        except Exception as e:
            log.error("OCI Cloud Guard collection error: %s", e)
        return [{"service": "cloudguard", "resource_type": "configuration", "items": items}] if items else []

    def _list_compartments(self, config, tenancy_id) -> List[str]:
        compartments = [tenancy_id]
        try:
            import oci
            identity = oci.identity.IdentityClient(config)
            sub = oci.pagination.list_call_get_all_results(
                identity.list_compartments, tenancy_id, compartment_id_in_subtree=True
            ).data
            compartments += [c.id for c in sub if c.lifecycle_state == "ACTIVE"]
        except Exception:
            pass
        return compartments
