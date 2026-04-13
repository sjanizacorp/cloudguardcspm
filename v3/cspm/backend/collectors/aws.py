"""
CloudGuard Pro CSPM — AWS Collector
Aniza Corp | Shahryar Jahangir

Credential types:
  env                — AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (or instance role)
  profile            — credential_ref = AWS named profile
  role               — credential_ref = Role ARN to assume
  file               — credential_ref = path to ~/.aws/credentials (INI) or JSON file
  workload_identity  — default boto3 credential chain

All clients are created with 15s connect + 30s read timeouts to prevent hangs.
Regions default to us-east-1 if not specified — add regions in the connection settings.
"""
from __future__ import annotations
import configparser, json, logging, os
from typing import Any, Dict, List

log = logging.getLogger(__name__)

# Applied to every boto3 client to prevent indefinite hangs
_BOTO_CFG = None
def _boto_config():
    global _BOTO_CFG
    if _BOTO_CFG is None:
        from botocore.config import Config
        _BOTO_CFG = Config(
            connect_timeout=15,
            read_timeout=30,
            retries={"max_attempts": 2, "mode": "standard"},
        )
    return _BOTO_CFG


class AWSCollector:
    def collect(self, conn) -> List[Dict[str, Any]]:
        try:
            import boto3
        except ImportError:
            log.warning("boto3 not installed. Run: pip install boto3")
            return []

        session = self._build_session(conn)

        # Use configured regions, or default to us-east-1 only.
        # Auto-discovering all regions takes 30+ seconds and scans 20+ regions —
        # add specific regions in your connection settings instead.
        regions = list(conn.regions) if conn.regions else ["us-east-1"]
        log.info("AWS: scanning regions: %s", regions)

        bundles = []
        log.info("AWS: collecting IAM (global)...")
        bundles += self._collect_iam(session)

        for region in regions:
            log.info("AWS: collecting region=%s", region)
            log.info("AWS: [%s] S3...", region)
            bundles += self._collect_s3(session, region)
            log.info("AWS: [%s] EC2 security groups...", region)
            bundles += self._collect_ec2(session, region)
            log.info("AWS: [%s] RDS...", region)
            bundles += self._collect_rds(session, region)
            log.info("AWS: [%s] CloudTrail...", region)
            bundles += self._collect_cloudtrail(session, region)
            log.info("AWS: [%s] KMS...", region)
            bundles += self._collect_kms(session, region)
            log.info("AWS: [%s] VPC...", region)
            bundles += self._collect_vpc(session, region)
            log.info("AWS: [%s] Lambda...", region)
            bundles += self._collect_lambda(session, region)
            log.info("AWS: [%s] EKS...", region)
            bundles += self._collect_eks(session, region)
            log.info("AWS: [%s] ECR...", region)
            bundles += self._collect_ecr(session, region)
            log.info("AWS: [%s] Secrets Manager...", region)
            bundles += self._collect_secrets_manager(session, region)
            log.info("AWS: [%s] done", region)

        total = sum(len(b.get("items", [])) for b in bundles)
        log.info("AWS: collection complete — %d bundles, %d resources total", len(bundles), total)
        return bundles

    def _build_session(self, conn):
        import boto3
        cred_type = (conn.credential_type or "env").strip().lower()
        cred_ref  = (conn.credential_ref  or "").strip()

        if cred_type == "role" and cred_ref:
            log.info("AWS: assuming role %s", cred_ref)
            sts = boto3.client("sts", config=_boto_config())
            assumed = sts.assume_role(RoleArn=cred_ref, RoleSessionName="cloudguard-cspm")
            c = assumed["Credentials"]
            return boto3.Session(
                aws_access_key_id=c["AccessKeyId"],
                aws_secret_access_key=c["SecretAccessKey"],
                aws_session_token=c["SessionToken"],
            )

        elif cred_type == "profile" and cred_ref:
            log.info("AWS: using named profile '%s'", cred_ref)
            return boto3.Session(profile_name=cred_ref)

        elif cred_type == "file" and cred_ref:
            path = os.path.expanduser(cred_ref)
            log.info("AWS: loading credentials from file '%s'", path)
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"Credentials file not found: {path}\n"
                    "Accepted formats:\n"
                    "  INI  (~/.aws/credentials): [default] aws_access_key_id = ...\n"
                    '  JSON: {"aws_access_key_id":"...","aws_secret_access_key":"..."}'
                )
            if os.path.isdir(path):
                raise IsADirectoryError(
                    f"'{path}' is a directory, not a credentials file.\n"
                    "Use ~/.aws/credentials (the file) or credential_type=profile."
                )
            with open(path) as f:
                raw = f.read().strip()

            if raw.startswith("{"):
                try:
                    creds = json.loads(raw)
                    log.info("AWS: parsed JSON credentials from %s", path)
                    return boto3.Session(
                        aws_access_key_id=creds["aws_access_key_id"],
                        aws_secret_access_key=creds["aws_secret_access_key"],
                        aws_session_token=creds.get("aws_session_token"),
                    )
                except (json.JSONDecodeError, KeyError) as e:
                    raise ValueError(
                        f"Failed to parse credentials file as JSON: {e}\n"
                        'Expected: {"aws_access_key_id":"...","aws_secret_access_key":"..."}'
                    ) from e
            else:
                # Standard INI format (~/.aws/credentials)
                config = configparser.ConfigParser()
                config.read_string(raw)
                section = "default"
                if section not in config and config.sections():
                    section = config.sections()[0]
                    log.info("AWS: no [default] section, using [%s]", section)
                if section not in config:
                    raise ValueError(f"No usable profile in {path}")
                key_id = config[section].get("aws_access_key_id", "").strip()
                secret  = config[section].get("aws_secret_access_key", "").strip()
                token   = config[section].get("aws_session_token", "").strip() or None
                if not key_id or not secret:
                    raise ValueError(
                        f"Missing aws_access_key_id or aws_secret_access_key in [{section}] of {path}"
                    )
                log.info("AWS: loaded INI credentials from [%s] in %s", section, path)
                return boto3.Session(
                    aws_access_key_id=key_id,
                    aws_secret_access_key=secret,
                    aws_session_token=token,
                )

        else:
            log.info("AWS: using default credential chain (env vars / instance role)")
            return boto3.Session()

    def _client(self, session, service, region):
        """Create a boto3 client with timeouts applied."""
        return session.client(service, region_name=region, config=_boto_config())

    # ── IAM (global) ─────────────────────────────────────────────────────────
    def _collect_iam(self, session) -> List[Dict]:
        bundles = []
        try:
            iam = self._client(session, "iam", "us-east-1")
            summary = iam.get_account_summary()["SummaryMap"]
            bundles.append({"service": "iam", "resource_type": "account_summary", "items": [{
                "account_mfa_enabled": summary.get("AccountMFAEnabled", 0) == 1,
                "root_access_key_active": summary.get("AccountAccessKeysPresent", 0) > 0,
            }]})
            try:
                pp = iam.get_account_password_policy()["PasswordPolicy"]
                bundles.append({"service": "iam", "resource_type": "password_policy", "items": [{"password_policy": pp}]})
            except iam.exceptions.NoSuchEntityException:
                pass
            paginator = iam.get_paginator("list_users")
            users = []
            for page in paginator.paginate():
                for u in page["Users"]:
                    try:
                        u["mfa_active"] = len(iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]) > 0
                        u["access_keys"] = iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]
                        u["attached_policies"] = iam.list_attached_user_policies(UserName=u["UserName"])["AttachedPolicies"]
                    except Exception:
                        pass
                    users.append(u)
            if users:
                bundles.append({"service": "iam", "resource_type": "user", "items": users})
            log.info("AWS: IAM — %d users", len(users))
        except Exception as e:
            log.warning("AWS: IAM collection error: %s", e)
        return bundles

    # ── S3 ───────────────────────────────────────────────────────────────────
    def _collect_s3(self, session, region) -> List[Dict]:
        bundles = []
        try:
            s3 = self._client(session, "s3", region)
            buckets = s3.list_buckets().get("Buckets", [])
            items = []
            for b in buckets:
                name = b["Name"]
                item = {"BucketName": name, "region": region}
                try:
                    item["public_access_block"] = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                except Exception:
                    item["public_access_block"] = {}
                try:
                    item["server_side_encryption_configuration"] = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]
                except Exception:
                    item["server_side_encryption_configuration"] = {"Rules": []}
                try:
                    item["versioning"] = s3.get_bucket_versioning(Bucket=name)
                except Exception:
                    item["versioning"] = {}
                try:
                    item["Tags"] = s3.get_bucket_tagging(Bucket=name)["TagSet"]
                except Exception:
                    item["Tags"] = []
                items.append(item)
            log.info("AWS: S3 — %d buckets", len(items))
            if items:
                bundles.append({"service": "s3", "resource_type": "bucket", "items": items})
        except Exception as e:
            log.warning("AWS: S3 error region=%s: %s", region, e)
        return bundles

    # ── EC2 security groups ───────────────────────────────────────────────────
    def _collect_ec2(self, session, region) -> List[Dict]:
        bundles = []
        try:
            ec2 = self._client(session, "ec2", region)
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                sg["region"] = region
            log.info("AWS: EC2 — %d security groups in %s", len(sgs), region)
            if sgs:
                bundles.append({"service": "ec2", "resource_type": "security_group", "items": sgs})
        except Exception as e:
            log.warning("AWS: EC2 error region=%s: %s", region, e)
        return bundles

    # ── RDS ──────────────────────────────────────────────────────────────────
    def _collect_rds(self, session, region) -> List[Dict]:
        bundles = []
        try:
            rds = self._client(session, "rds", region)
            instances = rds.describe_db_instances().get("DBInstances", [])
            for i in instances:
                i["region"] = region
            log.info("AWS: RDS — %d instances in %s", len(instances), region)
            if instances:
                bundles.append({"service": "rds", "resource_type": "db_instance", "items": instances})
        except Exception as e:
            log.warning("AWS: RDS error region=%s: %s", region, e)
        return bundles

    # ── CloudTrail ────────────────────────────────────────────────────────────
    def _collect_cloudtrail(self, session, region) -> List[Dict]:
        bundles = []
        try:
            ct = self._client(session, "cloudtrail", region)
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
            for t in trails:
                t["region"] = region
                try:
                    status = ct.get_trail_status(Name=t["TrailARN"])
                    t["IsLogging"] = status.get("IsLogging", False)
                except Exception:
                    pass
            log.info("AWS: CloudTrail — %d trails in %s", len(trails), region)
            if trails:
                bundles.append({"service": "cloudtrail", "resource_type": "trail", "items": trails})
        except Exception as e:
            log.warning("AWS: CloudTrail error region=%s: %s", region, e)
        return bundles

    # ── KMS ──────────────────────────────────────────────────────────────────
    def _collect_kms(self, session, region) -> List[Dict]:
        bundles = []
        try:
            kms = self._client(session, "kms", region)
            keys_raw = kms.list_keys().get("Keys", [])
            items = []
            for k in keys_raw:
                try:
                    meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                    if meta.get("KeyManager") != "CUSTOMER":
                        continue
                    try:
                        rot = kms.get_key_rotation_status(KeyId=k["KeyId"])
                        meta["KeyRotationEnabled"] = rot.get("KeyRotationEnabled", False)
                    except Exception:
                        meta["KeyRotationEnabled"] = False
                    meta["region"] = region
                    items.append(meta)
                except Exception:
                    pass
            log.info("AWS: KMS — %d customer keys in %s", len(items), region)
            if items:
                bundles.append({"service": "kms", "resource_type": "key", "items": items})
        except Exception as e:
            log.warning("AWS: KMS error region=%s: %s", region, e)
        return bundles

    # ── VPC ──────────────────────────────────────────────────────────────────
    def _collect_vpc(self, session, region) -> List[Dict]:
        bundles = []
        try:
            ec2 = self._client(session, "ec2", region)
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            for vpc in vpcs:
                vpc["region"] = region
                try:
                    fl = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc["VpcId"]]}])
                    vpc["flow_logs"] = fl.get("FlowLogs", [])
                except Exception:
                    vpc["flow_logs"] = []
            log.info("AWS: VPC — %d VPCs in %s", len(vpcs), region)
            if vpcs:
                bundles.append({"service": "vpc", "resource_type": "vpc", "items": vpcs})
        except Exception as e:
            log.warning("AWS: VPC error region=%s: %s", region, e)
        return bundles

    # ── Lambda ────────────────────────────────────────────────────────────────
    def _collect_lambda(self, session, region) -> List[Dict]:
        bundles = []
        try:
            lmb = self._client(session, "lambda", region)
            fns = lmb.list_functions().get("Functions", [])
            for fn in fns:
                fn["region"] = region
                try:
                    fn["resource_policy"] = lmb.get_policy(FunctionName=fn["FunctionName"]).get("Policy", "{}")
                except Exception:
                    fn["resource_policy"] = "{}"
            log.info("AWS: Lambda — %d functions in %s", len(fns), region)
            if fns:
                bundles.append({"service": "lambda", "resource_type": "function", "items": fns})
        except Exception as e:
            log.warning("AWS: Lambda error region=%s: %s", region, e)
        return bundles

    # ── EKS ──────────────────────────────────────────────────────────────────
    def _collect_eks(self, session, region) -> List[Dict]:
        bundles = []
        try:
            eks = self._client(session, "eks", region)
            names = eks.list_clusters().get("clusters", [])
            items = []
            for name in names:
                try:
                    c = eks.describe_cluster(name=name)["cluster"]
                    c["region"] = region
                    items.append(c)
                except Exception:
                    pass
            log.info("AWS: EKS — %d clusters in %s", len(items), region)
            if items:
                bundles.append({"service": "eks", "resource_type": "cluster", "items": items})
        except Exception as e:
            log.warning("AWS: EKS error region=%s: %s", region, e)
        return bundles

    # ── ECR ──────────────────────────────────────────────────────────────────
    def _collect_ecr(self, session, region) -> List[Dict]:
        bundles = []
        try:
            ecr = self._client(session, "ecr", region)
            repos = ecr.describe_repositories().get("repositories", [])
            for r in repos:
                r["region"] = region
            log.info("AWS: ECR — %d repositories in %s", len(repos), region)
            if repos:
                bundles.append({"service": "ecr", "resource_type": "repository", "items": repos})
        except Exception as e:
            log.warning("AWS: ECR error region=%s: %s", region, e)
        return bundles

    # ── Secrets Manager ───────────────────────────────────────────────────────
    def _collect_secrets_manager(self, session, region) -> List[Dict]:
        bundles = []
        try:
            sm = self._client(session, "secretsmanager", region)
            secrets = sm.list_secrets().get("SecretList", [])
            for s in secrets:
                s["region"] = region
            log.info("AWS: SecretsManager — %d secrets in %s", len(secrets), region)
            if secrets:
                bundles.append({"service": "secretsmanager", "resource_type": "secret", "items": secrets})
        except Exception as e:
            log.warning("AWS: SecretsManager error region=%s: %s", region, e)
        return bundles
