import boto3
import uuid
from datetime import datetime
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class AWSCollector:
    def __init__(self, access_key: str = None, secret_key: str = None, session_token: str = None, regions: List[str] = None):
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )
        self.regions = regions or self._get_all_regions()
        self.account_id = self._get_account_id()

    def _get_account_id(self) -> str:
        try:
            sts = self.session.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception as e:
            logger.error(f"Failed to get AWS account ID: {e}")
            return "unknown"

    def _get_all_regions(self) -> List[str]:
        try:
            ec2 = self.session.client("ec2", region_name="us-east-1")
            regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
            return regions
        except Exception:
            return ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

    def collect_all(self) -> List[Dict[str, Any]]:
        assets = []
        assets.extend(self.collect_s3_buckets())
        assets.extend(self.collect_ec2_instances())
        assets.extend(self.collect_security_groups())
        assets.extend(self.collect_iam_users())
        assets.extend(self.collect_rds_instances())
        assets.extend(self.collect_lambda_functions())
        return assets

    def collect_s3_buckets(self) -> List[Dict]:
        assets = []
        try:
            s3 = self.session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                name = bucket["Name"]
                props = {"creation_date": str(bucket.get("CreationDate", ""))}
                is_public = False
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI", "") in [
                            "http://acs.amazonaws.com/groups/global/AllUsers",
                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                        ]:
                            is_public = True
                    props["acl"] = acl.get("Grants", [])
                except Exception:
                    pass

                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                    props["encryption"] = enc.get("ServerSideEncryptionConfiguration", {})
                except Exception:
                    props["encryption"] = None

                try:
                    versioning = s3.get_bucket_versioning(Bucket=name)
                    props["versioning"] = versioning.get("Status", "Disabled")
                except Exception:
                    props["versioning"] = "Unknown"

                try:
                    logging_cfg = s3.get_bucket_logging(Bucket=name)
                    props["logging_enabled"] = "LoggingEnabled" in logging_cfg
                except Exception:
                    props["logging_enabled"] = False

                try:
                    public_block = s3.get_public_access_block(Bucket=name)
                    cfg = public_block.get("PublicAccessBlockConfiguration", {})
                    props["public_access_block"] = cfg
                    if all(cfg.values()):
                        is_public = False
                except Exception:
                    props["public_access_block"] = None

                assets.append({
                    "id": f"aws-s3-{name}",
                    "cloud_provider": "aws",
                    "account_id": self.account_id,
                    "region": "global",
                    "resource_type": "S3 Bucket",
                    "resource_id": name,
                    "name": name,
                    "tags": {},
                    "properties": props,
                    "is_public": is_public,
                    "last_scanned": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"S3 collection error: {e}")
        return assets

    def collect_ec2_instances(self) -> List[Dict]:
        assets = []
        for region in self.regions[:5]:  # Limit to first 5 regions for speed
            try:
                ec2 = self.session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_instances")
                for page in paginator.paginate():
                    for reservation in page["Reservations"]:
                        for instance in reservation["Instances"]:
                            iid = instance["InstanceId"]
                            name = next((t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"), iid)
                            tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                            is_public = bool(instance.get("PublicIpAddress"))
                            assets.append({
                                "id": f"aws-ec2-{iid}",
                                "cloud_provider": "aws",
                                "account_id": self.account_id,
                                "region": region,
                                "resource_type": "EC2 Instance",
                                "resource_id": iid,
                                "name": name,
                                "tags": tags,
                                "properties": {
                                    "state": instance["State"]["Name"],
                                    "instance_type": instance.get("InstanceType"),
                                    "public_ip": instance.get("PublicIpAddress"),
                                    "private_ip": instance.get("PrivateIpAddress"),
                                    "imds_v2": instance.get("MetadataOptions", {}).get("HttpTokens", "optional"),
                                    "monitoring": instance.get("Monitoring", {}).get("State"),
                                    "ebs_optimized": instance.get("EbsOptimized"),
                                    "vpc_id": instance.get("VpcId"),
                                },
                                "is_public": is_public,
                                "last_scanned": datetime.utcnow().isoformat()
                            })
            except Exception as e:
                logger.error(f"EC2 collection error in {region}: {e}")
        return assets

    def collect_security_groups(self) -> List[Dict]:
        assets = []
        for region in self.regions[:5]:
            try:
                ec2 = self.session.client("ec2", region_name=region)
                sgs = ec2.describe_security_groups()["SecurityGroups"]
                for sg in sgs:
                    open_to_world = any(
                        perm.get("IpRanges", []) and
                        any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                        for perm in sg.get("IpPermissions", [])
                    )
                    assets.append({
                        "id": f"aws-sg-{sg['GroupId']}",
                        "cloud_provider": "aws",
                        "account_id": self.account_id,
                        "region": region,
                        "resource_type": "Security Group",
                        "resource_id": sg["GroupId"],
                        "name": sg.get("GroupName", sg["GroupId"]),
                        "tags": {t["Key"]: t["Value"] for t in sg.get("Tags", [])},
                        "properties": {
                            "description": sg.get("Description"),
                            "vpc_id": sg.get("VpcId"),
                            "inbound_rules": sg.get("IpPermissions", []),
                            "outbound_rules": sg.get("IpPermissionsEgress", []),
                            "open_to_world": open_to_world
                        },
                        "is_public": open_to_world,
                        "last_scanned": datetime.utcnow().isoformat()
                    })
            except Exception as e:
                logger.error(f"SG collection error in {region}: {e}")
        return assets

    def collect_iam_users(self) -> List[Dict]:
        assets = []
        try:
            iam = self.session.client("iam")
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                    access_keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                    assets.append({
                        "id": f"aws-iam-{username}",
                        "cloud_provider": "aws",
                        "account_id": self.account_id,
                        "region": "global",
                        "resource_type": "IAM User",
                        "resource_id": user["UserId"],
                        "name": username,
                        "tags": {t["Key"]: t["Value"] for t in user.get("Tags", [])},
                        "properties": {
                            "arn": user["Arn"],
                            "mfa_enabled": len(mfa_devices) > 0,
                            "access_key_count": len(access_keys),
                            "password_last_used": str(user.get("PasswordLastUsed", "Never")),
                        },
                        "is_public": False,
                        "last_scanned": datetime.utcnow().isoformat()
                    })
        except Exception as e:
            logger.error(f"IAM user collection error: {e}")
        return assets

    def collect_rds_instances(self) -> List[Dict]:
        assets = []
        for region in self.regions[:5]:
            try:
                rds = self.session.client("rds", region_name=region)
                paginator = rds.get_paginator("describe_db_instances")
                for page in paginator.paginate():
                    for db in page["DBInstances"]:
                        assets.append({
                            "id": f"aws-rds-{db['DBInstanceIdentifier']}",
                            "cloud_provider": "aws",
                            "account_id": self.account_id,
                            "region": region,
                            "resource_type": "RDS Instance",
                            "resource_id": db["DBInstanceIdentifier"],
                            "name": db["DBInstanceIdentifier"],
                            "tags": {t["Key"]: t["Value"] for t in db.get("TagList", [])},
                            "properties": {
                                "engine": db.get("Engine"),
                                "engine_version": db.get("EngineVersion"),
                                "publicly_accessible": db.get("PubliclyAccessible"),
                                "encrypted": db.get("StorageEncrypted"),
                                "multi_az": db.get("MultiAZ"),
                                "backup_retention": db.get("BackupRetentionPeriod"),
                                "deletion_protection": db.get("DeletionProtection"),
                            },
                            "is_public": db.get("PubliclyAccessible", False),
                            "last_scanned": datetime.utcnow().isoformat()
                        })
            except Exception as e:
                logger.error(f"RDS collection error in {region}: {e}")
        return assets

    def collect_lambda_functions(self) -> List[Dict]:
        assets = []
        for region in self.regions[:5]:
            try:
                lmb = self.session.client("lambda", region_name=region)
                paginator = lmb.get_paginator("list_functions")
                for page in paginator.paginate():
                    for fn in page["Functions"]:
                        assets.append({
                            "id": f"aws-lambda-{fn['FunctionName']}-{region}",
                            "cloud_provider": "aws",
                            "account_id": self.account_id,
                            "region": region,
                            "resource_type": "Lambda Function",
                            "resource_id": fn["FunctionArn"],
                            "name": fn["FunctionName"],
                            "tags": fn.get("Tags", {}),
                            "properties": {
                                "runtime": fn.get("Runtime"),
                                "memory": fn.get("MemorySize"),
                                "timeout": fn.get("Timeout"),
                                "last_modified": fn.get("LastModified"),
                            },
                            "is_public": False,
                            "last_scanned": datetime.utcnow().isoformat()
                        })
            except Exception as e:
                logger.error(f"Lambda collection error in {region}: {e}")
        return assets
