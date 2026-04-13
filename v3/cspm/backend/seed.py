"""
CloudGuard Pro CSPM v3 — Demo Data Seeder
Aniza Corp | Shahryar Jahangir

Seeds realistic demo assets with intentionally misconfigured raw_config
so the check engine produces real findings without cloud credentials.
"""
from __future__ import annotations
import hashlib, logging, random
from datetime import datetime, timedelta

log = logging.getLogger(__name__)

# ─── Realistic failing raw configs per resource type ─────────────────────────
DEMO_CONFIGS = {
    # AWS
    ("aws", "s3", "bucket"): {
        "BucketName": "aniza-prod-data",
        "public_access_block": {},                          # FAIL: no block
        "server_side_encryption_configuration": {"Rules": []},  # FAIL: no encryption
        "versioning": {"Status": "Disabled"},               # FAIL
        "Tags": [{"Key": "env", "Value": "production"}],
        "region": "us-east-1",
    },
    ("aws", "ec2", "security_group"): {
        "GroupId": "sg-0abc12345",
        "GroupName": "sg-web-tier",
        "ip_permissions": [
            {"FromPort": 22,   "ToPort": 22,   "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},  # FAIL SSH
            {"FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},  # FAIL RDP
            {"FromPort": 443,  "ToPort": 443,  "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
        "region": "us-east-1",
    },
    ("aws", "rds", "db_instance"): {
        "DBInstanceIdentifier": "prod-postgres",
        "PubliclyAccessible": True,     # FAIL
        "StorageEncrypted": False,      # FAIL
        "region": "us-east-1",
    },
    ("aws", "iam", "account_summary"): {
        "account_mfa_enabled": False,   # FAIL: no root MFA
        "root_access_key_active": True, # FAIL
    },
    ("aws", "iam", "password_policy"): {
        "password_policy": {
            "MinimumPasswordLength": 8,         # FAIL: too short
            "RequireUppercaseCharacters": False, # FAIL
            "RequireLowercaseCharacters": True,
            "RequireNumbers": False,             # FAIL
            "RequireSymbols": False,             # FAIL
            "MaxPasswordAge": 180,               # FAIL: too long
            "PasswordReusePrevention": 5,        # FAIL: too low
        }
    },
    ("aws", "kms", "key"): {
        "KeyId": "mrk-abc000001",
        "KeyState": "Enabled",
        "KeyManager": "CUSTOMER",
        "KeyRotationEnabled": False,    # FAIL
        "region": "us-east-1",
    },
    ("aws", "vpc", "vpc"): {
        "VpcId": "vpc-0001aabb",
        "flow_logs": [],                # FAIL: no flow logs
        "region": "us-east-1",
    },
    ("aws", "lambda", "function"): {
        "FunctionName": "ProcessPayments",
        "Role": "arn:aws:iam::123:role/LambdaAdmin",
        "attached_policies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}],  # FAIL
        "region": "us-east-1",
    },
    ("aws", "eks", "cluster"): {
        "name": "prod-cluster",
        "resourcesVpcConfig": {
            "endpointPublicAccess": True,
            "endpointPrivateAccess": False,
            "publicAccessCidrs": ["0.0.0.0/0"],  # FAIL
        },
        "region": "us-east-1",
    },
    ("aws", "ecr", "repository"): {
        "repositoryName": "prod-app",
        "imageScanningConfiguration": {"scanOnPush": False},  # FAIL
        "region": "us-east-1",
    },
    ("aws", "secretsmanager", "secret"): {
        "Name": "prod/db/password",
        "RotationEnabled": False,       # FAIL
        "region": "us-east-1",
    },
    ("aws", "cloudtrail", "trail"): {
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/prod",
        "IsMultiRegionTrail": False,    # FAIL
        "IsLogging": True,
        "IncludeGlobalServiceEvents": False,  # FAIL
        "LogFileValidationEnabled": False,    # FAIL
        "region": "us-east-1",
    },
    # Azure
    ("azure", "storage", "storage_account"): {
        "id": "/subscriptions/aaaa/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/anizaprodstore",
        "allowBlobPublicAccess": True,          # FAIL
        "supportsHttpsTrafficOnly": False,      # FAIL
        "encryption": {"keySource": "Microsoft.Storage"},  # FAIL: no CMK
        "location": "eastus",
    },
    ("azure", "sql", "sql_database"): {
        "id": "/subscriptions/aaaa/resourceGroups/prod-rg/providers/Microsoft.Sql/servers/prod-srv/databases/prod-sqldb",
        "transparentDataEncryption": {"status": "Disabled"},  # FAIL
        "location": "eastus",
    },
    ("azure", "sql", "sql_server"): {
        "id": "/subscriptions/aaaa/resourceGroups/prod-rg/providers/Microsoft.Sql/servers/prod-srv",
        "auditingPolicy": {"state": "Disabled", "retentionDays": 0},  # FAIL
        "location": "eastus",
    },
    ("azure", "keyvault", "vault"): {
        "id": "/subscriptions/aaaa/resourceGroups/prod-rg/providers/Microsoft.KeyVault/vaults/aniza-prod-kv",
        "properties": {"enableSoftDelete": False, "enablePurgeProtection": False},  # FAIL both
        "location": "eastus",
    },
    ("azure", "network", "network_security_group"): {
        "id": "/subscriptions/aaaa/resourceGroups/prod-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-web",
        "securityRules": [
            {"name": "AllowSSH", "properties": {"direction": "Inbound", "access": "Allow", "destinationPortRange": "22",   "sourceAddressPrefix": "*"}},  # FAIL
            {"name": "AllowRDP", "properties": {"direction": "Inbound", "access": "Allow", "destinationPortRange": "3389", "sourceAddressPrefix": "*"}},  # FAIL
        ],
        "location": "eastus",
    },
    ("azure", "aks", "managed_cluster"): {
        "id": "/subscriptions/aaaa/resourceGroups/prod-rg/providers/Microsoft.ContainerService/managedClusters/prod-aks",
        "properties": {"enableRBAC": False},    # FAIL
        "location": "eastus",
    },
    ("azure", "monitor", "log_profile"): {
        "retentionPolicy": {"enabled": False, "days": 30},  # FAIL
    },
    ("azure", "compute", "disk"): {
        "id": "/subscriptions/aaaa/resourceGroups/prod-rg/providers/Microsoft.Compute/disks/prod-osdisk",
        "encryption": {"type": ""},             # FAIL
        "location": "eastus",
    },
    ("azure", "security", "defender_plan"): {
        "pricingTier": "Free",                  # FAIL: not Standard
    },
    # GCP
    ("gcp", "storage", "bucket"): {
        "name": "aniza-prod-gcs",
        "location": "US-CENTRAL1",
        "iam_policy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},  # FAIL: public
    },
    ("gcp", "compute", "firewall"): {
        "name": "default-allow-ssh",
        "direction": "INGRESS",
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
        "sourceRanges": ["0.0.0.0/0"],          # FAIL
    },
    ("gcp", "cloudsql", "database_instance"): {
        "name": "prod-pg-01",
        "region": "us-central1",
        "ipAddresses": [{"type": "PRIMARY", "ipAddress": "34.1.2.3"}],  # FAIL: public IP
        "settings": {"ipConfiguration": {}},
    },
    ("gcp", "container", "cluster"): {
        "name": "prod-gke",
        "location": "us-central1",
        "addonsConfig": {"kubernetesDashboard": {"disabled": False}},  # FAIL
    },
    ("gcp", "bigquery", "dataset"): {
        "datasetReference": {"datasetId": "prod_analytics"},
        "location": "US",
        "access": [{"specialGroup": "allUsers", "role": "READER"}],  # FAIL
    },
    ("gcp", "iam", "service_account"): {
        "email": "app-sa@aniza-prod.iam.gserviceaccount.com",
        "roles": ["roles/owner", "roles/editor"],  # FAIL: admin roles
    },
    ("gcp", "logging", "log_sink_config"): {
        "has_export_sink": False,               # FAIL
    },
    ("gcp", "kms", "crypto_key"): {
        "name": "projects/aniza-prod/locations/global/keyRings/prod/cryptoKeys/data-key",
        "rotationPeriod": "31536000s",          # FAIL: 365 days > 90
    },
    # IBM
    ("ibm", "cloud-object-storage", "bucket"): {
        "name": "aniza-ibm-data",
        "public_access_enabled": True,          # FAIL
        "acl": "public-read",
        "region": "us-south",
    },
    ("ibm", "iam", "account_settings"): {
        "mfa": "NONE",                          # FAIL
        "region": "global",
    },
    ("ibm", "activity-tracker", "tracker_instance"): {
        "active": False,                        # FAIL
        "name": "activity-tracker-us-south",
    },
    ("ibm", "vpc", "security_group"): {
        "id": "sg-ibm-web",
        "rules": [{"direction": "inbound", "protocol": "tcp", "port_min": 22, "port_max": 22, "remote": {"cidr_block": "0.0.0.0/0"}}],  # FAIL
    },
    ("ibm", "kms", "key"): {
        "id": "key-001",
        "rotation": {"enabled": False, "interval_month": 24},  # FAIL
    },
    # OCI
    ("oci", "objectstorage", "bucket"): {
        "name": "aniza-oci-bucket",
        "publicAccessType": "ObjectRead",       # FAIL
        "compartmentId": "ocid1.compartment.oc1..aaa",
    },
    ("oci", "iam", "user"): {
        "id": "ocid1.user.oc1..aaaa001",
        "name": "admin-user-01",
        "isMfaActivated": False,                # FAIL
    },
    ("oci", "audit", "configuration"): {
        "retentionPeriodDays": 90,              # FAIL: < 365
    },
    ("oci", "cloudguard", "configuration"): {
        "status": "DISABLED",                   # FAIL
    },
    ("oci", "core", "subnet"): {
        "id": "ocid1.subnet.oc1..aaa",
        "flowLogEnabled": False,                # FAIL
    },
    ("oci", "kms", "key"): {
        "id": "ocid1.key.oc1..aaa",
        "autoKeyRotationEnabled": False,        # FAIL
    },
}


def seed_demo_data():
    from backend.database import db_session
    from backend.models.models import (
        ProviderConnection, Asset, CheckDefinition, Finding,
        FindingStatus, ScanRun, ScanStatus, CloudProvider, Severity,
        CheckStatus, CheckType, CollectionMethod,
    )
    from backend.check_engine.engine import _REGISTRY, load_all_checkpacks
    import inspect, yaml

    with db_session() as db:
        if db.query(ProviderConnection).count() > 0:
            log.info("Demo data already seeded. Skipping.")
            return
        log.info("Seeding demo data...")

        # ─── Connections ──────────────────────────────────────────────────────
        connections = [
            ProviderConnection(id="demo-aws-001",   name="Production AWS (us-east-1)",   provider=CloudProvider.AWS,   account_id="123456789012",                                      alias="prod-aws",   enabled=True, regions=["us-east-1","us-west-2"], credential_type="env", tags={"env":"production"}),
            ProviderConnection(id="demo-azure-001", name="Azure Subscription — Aniza",   provider=CloudProvider.AZURE, subscription_id="aaaabbbb-cccc-dddd-eeee-ffffffffffff",        alias="prod-azure", enabled=True, credential_type="env"),
            ProviderConnection(id="demo-gcp-001",   name="GCP Project — aniza-prod",     provider=CloudProvider.GCP,   project_id="aniza-prod-12345",                                  alias="prod-gcp",   enabled=True, credential_type="env"),
            ProviderConnection(id="demo-ibm-001",   name="IBM Cloud Account",            provider=CloudProvider.IBM,   ibm_account_id="ibm-acct-0001",                                 alias="prod-ibm",   enabled=True, credential_type="env"),
            ProviderConnection(id="demo-oci-001",   name="OCI Tenancy — Aniza",          provider=CloudProvider.OCI,   tenancy_id="ocid1.tenancy.oc1..aaaa00001",                      alias="prod-oci",   enabled=True, credential_type="env"),
        ]
        db.add_all(connections)
        db.flush()

        # ─── Sync checks to DB ─────────────────────────────────────────────────
        load_all_checkpacks()
        for check_id, meta in _REGISTRY.items():
            if db.query(CheckDefinition).filter_by(check_id=check_id).first():
                continue
            code = meta.implementation_code
            if not code and meta.func:
                try:   code = inspect.getsource(meta.func)
                except: code = "# Source not available"
            yaml_def = yaml.dump({
                "check_id": meta.check_id, "name": meta.name,
                "family": meta.family, "provider": meta.provider,
                "service": meta.service, "resource_type": meta.resource_type,
                "severity": meta.severity,
                "source": {"vendor": meta.source_vendor, "url": meta.source_url, "version": meta.source_version},
                "compliance_mappings": meta.compliance_mappings,
            }, default_flow_style=False)
            c = CheckDefinition(
                id=hashlib.md5(check_id.encode()).hexdigest(),
                check_id=check_id, family=meta.family, provider=meta.provider,
                service=meta.service, resource_type=meta.resource_type,
                severity=meta.severity, check_type=CheckType.CODE,
                collection_method=CollectionMethod.API, name=meta.name,
                description=meta.description, remediation=meta.remediation,
                rationale=meta.rationale, impact=meta.impact,
                source_type=meta.source_type, source_vendor=meta.source_vendor,
                source_product=meta.source_product, source_url=meta.source_url,
                source_version=meta.source_version, source_retrieved=meta.source_retrieved,
                license_notes=meta.license_notes, normalization_confidence=meta.normalization_confidence,
                status=CheckStatus.IMPLEMENTED, enabled=meta.enabled, tags=meta.tags,
                logic_explanation=meta.logic_explanation, implementation_code=code,
                yaml_definition=yaml_def, test_cases=meta.test_cases, sample_payload=meta.sample_payload,
            )
            db.add(c)
        db.flush()

        # ─── Assets with realistic failing raw_config ─────────────────────────
        CONN_MAP = {"aws": "demo-aws-001", "azure": "demo-azure-001", "gcp": "demo-gcp-001", "ibm": "demo-ibm-001", "oci": "demo-oci-001"}
        ACCT_MAP = {"aws": "123456789012", "azure": "aaaa-subscription", "gcp": "aniza-prod-12345", "ibm": "ibm-acct-0001", "oci": "ocid1.tenancy.oc1"}
        PROV_ENUM = {"aws": CloudProvider.AWS, "azure": CloudProvider.AZURE, "gcp": CloudProvider.GCP, "ibm": CloudProvider.IBM, "oci": CloudProvider.OCI}

        assets = {}
        for (prov, svc, rtype), raw_config in DEMO_CONFIGS.items():
            region = raw_config.get("region") or raw_config.get("location") or "global"
            native_id = raw_config.get("id") or raw_config.get("name") or raw_config.get("BucketName") or raw_config.get("GroupId") or raw_config.get("DBInstanceIdentifier") or f"{svc}-{rtype}"
            urn = f"cspm://{prov}/{ACCT_MAP[prov]}/{region}/{svc}/{rtype}/{hashlib.md5(str(native_id).encode()).hexdigest()[:12]}"
            display = raw_config.get("name") or raw_config.get("BucketName") or raw_config.get("GroupName") or raw_config.get("FunctionName") or raw_config.get("DBInstanceIdentifier") or str(native_id)[:40]
            asset = Asset(
                id=hashlib.md5(urn.encode()).hexdigest()[:32],
                connection_id=CONN_MAP[prov],
                provider=PROV_ENUM[prov], service=svc, resource_type=rtype,
                region=region, display_name=display,
                native_id=str(native_id)[:255], universal_resource_name=urn,
                arn=str(native_id) if prov == "aws" else None,
                azure_resource_id=raw_config.get("id") if prov == "azure" else None,
                is_active=True, tags={}, raw_config=raw_config,
                config_hash=hashlib.sha256(str(raw_config).encode()).hexdigest(),
            )
            db.add(asset)
            assets[(prov, svc, rtype)] = asset
        db.flush()

        # ─── Run checks against demo assets to generate realistic findings ────
        from backend.check_engine.engine import CheckEngine, make_finding_id
        engine = CheckEngine()
        now = datetime.utcnow()
        check_def_map = {c.check_id: c for c in db.query(CheckDefinition).all()}
        finding_count = 0

        for (prov, svc, rtype), asset in assets.items():
            raw = asset.raw_config
            results = engine.run_checks_for_resource(raw, prov, svc, rtype)
            conn = next((c for c in connections if c.id == asset.connection_id), None)
            acct = ACCT_MAP[prov]

            for result in results:
                if result.passed or result.error:
                    continue
                meta = _REGISTRY.get(result.check_id)
                if not meta:
                    continue
                check_def = check_def_map.get(result.check_id)
                fid = make_finding_id(result.check_id, asset.universal_resource_name)
                days_ago = random.randint(0, 30)

                f = Finding(
                    id=hashlib.md5(f"{fid}{finding_count}".encode()).hexdigest()[:32],
                    finding_id=fid,
                    check_def_id=check_def.id if check_def else None,
                    check_id=result.check_id,
                    asset_id=asset.id,
                    family=meta.family,
                    severity=meta.severity,
                    status=FindingStatus.OPEN,
                    title=meta.name,
                    description=meta.description,
                    remediation=meta.remediation,
                    provider=meta.provider,
                    account_context=acct,
                    region=asset.region,
                    service=meta.service,
                    resource_type=meta.resource_type,
                    resource_display_name=asset.display_name,
                    native_id=asset.native_id,
                    arn=asset.arn,
                    azure_resource_id=asset.azure_resource_id,
                    universal_resource_name=asset.universal_resource_name,
                    evidence=result.evidence,
                    raw_evidence_blob=raw,
                    compliance_frameworks=[m.get("framework") for m in (meta.compliance_mappings or []) if m.get("framework")],
                    resource_tags={},
                    source_vendor=meta.source_vendor,
                    first_seen=now - timedelta(days=days_ago),
                    last_seen=now,
                )
                db.add(f)
                finding_count += 1

        log.info("Demo data seeded: %d assets, %d findings.", len(assets), finding_count)
