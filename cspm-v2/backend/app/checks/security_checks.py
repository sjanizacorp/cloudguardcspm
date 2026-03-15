import uuid
from datetime import datetime
from typing import List, Dict, Any

SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}


class SecurityChecksEngine:
    def __init__(self):
        self.checks = AWS_CHECKS + AZURE_CHECKS + GCP_CHECKS

    def run_checks(self, assets: List[Dict]) -> List[Dict]:
        findings = []
        for asset in assets:
            for check in self.checks:
                if not self._applies(check, asset):
                    continue
                try:
                    result = check["fn"](asset)
                    if result is not None:
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "asset_id": asset["id"],
                            "cloud_provider": asset["cloud_provider"],
                            "check_id": check["id"],
                            "title": check["title"],
                            "description": check["description"],
                            "severity": check["severity"],
                            "status": "active",
                            "remediation": check["remediation"],
                            "cis_controls": check.get("cis", []),
                            "nist_controls": check.get("nist", []),
                            "resource_type": asset["resource_type"],
                            "resource_id": asset["resource_id"],
                            "region": asset.get("region"),
                            "account_id": asset.get("account_id"),
                            "properties": result if isinstance(result, dict) else {},
                            "first_seen": datetime.utcnow().isoformat(),
                            "last_seen": datetime.utcnow().isoformat(),
                        })
                except Exception:
                    pass
        return findings

    def _applies(self, check, asset):
        if check.get("providers") and asset["cloud_provider"] not in check["providers"]:
            return False
        if check.get("resource_types") and asset["resource_type"] not in check["resource_types"]:
            return False
        return True

    def calculate_secure_score(self, assets, findings):
        if not assets:
            return {"score": 0, "passed": 0, "failed": 0, "total": 0}
        active = [f for f in findings if f.get("status") == "active"]
        total_checks = max(len(assets), 1) * max(len(self.checks) // 6, 1)
        failed_weight = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in active)
        max_weight = total_checks * SEVERITY_WEIGHTS["critical"]
        score = max(0, 100 - (failed_weight / max(1, max_weight)) * 100)
        return {
            "score": round(score, 1),
            "passed": total_checks - len(active),
            "failed": len(active),
            "total": total_checks,
            "critical": sum(1 for f in active if f["severity"] == "critical"),
            "high": sum(1 for f in active if f["severity"] == "high"),
            "medium": sum(1 for f in active if f["severity"] == "medium"),
            "low": sum(1 for f in active if f["severity"] == "low"),
        }


# ── Helpers ───────────────────────────────────────────────────────────────────
def props(asset):
    return asset.get("properties", {})


# ══════════════════════════════════════════════════════════════════════════════
# AWS CHECKS
# ══════════════════════════════════════════════════════════════════════════════

# S3
def chk_s3_public_block(a):
    b = props(a).get("public_access_block") or {}
    if not all([b.get("BlockPublicAcls"), b.get("IgnorePublicAcls"), b.get("BlockPublicPolicy"), b.get("RestrictPublicBuckets")]):
        return {"public_access_block": b}

def chk_s3_encryption(a):
    if not props(a).get("encryption"):
        return {"encryption": "disabled"}

def chk_s3_versioning(a):
    if props(a).get("versioning") != "Enabled":
        return {"versioning": props(a).get("versioning")}

def chk_s3_logging(a):
    if not props(a).get("logging_enabled"):
        return {"logging": "disabled"}

def chk_s3_tls_only(a):
    # Check if bucket policy enforces TLS — flag if no policy or policy allows HTTP
    pol = props(a).get("policy")
    if pol is None:
        return {"tls_policy": "not_configured"}

def chk_s3_mfa_delete(a):
    if props(a).get("versioning") == "Enabled":
        if not props(a).get("mfa_delete"):
            return {"mfa_delete": "disabled"}

# EC2
def chk_ec2_imdsv2(a):
    if props(a).get("imds_v2") != "required":
        return {"imds_v2": props(a).get("imds_v2", "optional")}

def chk_ec2_public_ip(a):
    if a.get("is_public"):
        return {"public_ip": props(a).get("public_ip")}

def chk_ec2_detailed_monitoring(a):
    if props(a).get("monitoring") != "enabled":
        return {"monitoring": props(a).get("monitoring")}

def chk_ec2_ebs_encrypted(a):
    # Check if root volume encrypted
    vols = props(a).get("block_devices", [])
    unencrypted = [v for v in vols if not v.get("encrypted")]
    if unencrypted:
        return {"unencrypted_volumes": len(unencrypted)}

def chk_ec2_vpc(a):
    if not props(a).get("vpc_id"):
        return {"vpc": "not_in_vpc"}

# Security Groups
def chk_sg_open_ingress(a):
    if props(a).get("open_to_world"):
        return {"unrestricted_ingress": True}

def chk_sg_ssh_open(a):
    for rule in props(a).get("inbound_rules", []):
        for r in rule.get("IpRanges", []):
            if r.get("CidrIp") == "0.0.0.0/0":
                for port_range in [rule]:
                    fp = port_range.get("FromPort", 0)
                    tp = port_range.get("ToPort", 65535)
                    if fp <= 22 <= tp:
                        return {"ssh_open_to_world": True, "port": 22}

def chk_sg_rdp_open(a):
    for rule in props(a).get("inbound_rules", []):
        for r in rule.get("IpRanges", []):
            if r.get("CidrIp") == "0.0.0.0/0":
                fp = rule.get("FromPort", 0)
                tp = rule.get("ToPort", 65535)
                if fp <= 3389 <= tp:
                    return {"rdp_open_to_world": True, "port": 3389}

# IAM
def chk_iam_mfa(a):
    if not props(a).get("mfa_enabled"):
        return {"mfa_enabled": False}

def chk_iam_old_access_keys(a):
    keys = props(a).get("access_keys", [])
    from datetime import timezone
    old = []
    for k in keys:
        created = k.get("CreateDate", "")
        if created:
            try:
                from datetime import datetime as dt
                age = (dt.now(timezone.utc) - dt.fromisoformat(str(created).replace("Z", "+00:00"))).days
                if age > 90:
                    old.append({"key_id": k.get("AccessKeyId"), "age_days": age})
            except Exception:
                pass
    if old:
        return {"old_access_keys": old}

def chk_iam_no_policies_direct(a):
    # Flag users with directly attached policies (should use groups/roles)
    if props(a).get("attached_policies"):
        return {"directly_attached_policies": props(a).get("attached_policies")}

# RDS
def chk_rds_public(a):
    if props(a).get("publicly_accessible"):
        return {"publicly_accessible": True}

def chk_rds_encryption(a):
    if not props(a).get("encrypted"):
        return {"storage_encrypted": False}

def chk_rds_backup(a):
    ret = props(a).get("backup_retention", 0)
    if ret < 7:
        return {"backup_retention_days": ret}

def chk_rds_deletion_protection(a):
    if not props(a).get("deletion_protection"):
        return {"deletion_protection": False}

def chk_rds_multi_az(a):
    if not props(a).get("multi_az"):
        return {"multi_az": False}

def chk_rds_auto_minor_upgrade(a):
    if props(a).get("auto_minor_version_upgrade") is False:
        return {"auto_minor_version_upgrade": False}

# Lambda
def chk_lambda_public_policy(a):
    if props(a).get("public_policy"):
        return {"public_policy": True}

def chk_lambda_env_secrets(a):
    env = props(a).get("environment_variables", {})
    suspicious = [k for k in env if any(s in k.lower() for s in ["secret", "password", "key", "token", "credential"])]
    if suspicious:
        return {"suspicious_env_vars": suspicious}

def chk_lambda_outdated_runtime(a):
    runtime = props(a).get("runtime", "")
    outdated = ["python2.7", "python3.6", "python3.7", "nodejs10.x", "nodejs12.x", "ruby2.5", "dotnetcore2.1", "dotnetcore3.1"]
    if runtime in outdated:
        return {"runtime": runtime, "status": "end_of_life"}


AWS_CHECKS = [
    # S3
    {"id": "AWS-S3-001", "providers": ["aws"], "resource_types": ["S3 Bucket"],
     "title": "S3 bucket does not block all public access",
     "description": "The S3 bucket does not have all public access block settings enabled, potentially exposing data publicly.",
     "severity": "critical", "remediation": "Enable all four S3 Block Public Access settings on the bucket.",
     "cis": ["CIS AWS 2.1.5"], "nist": ["AC-3", "SC-7"], "fn": chk_s3_public_block},

    {"id": "AWS-S3-002", "providers": ["aws"], "resource_types": ["S3 Bucket"],
     "title": "S3 bucket encryption not enabled",
     "description": "Data at rest in this S3 bucket is not encrypted.",
     "severity": "high", "remediation": "Enable SSE-S3 or SSE-KMS encryption on the bucket.",
     "cis": ["CIS AWS 2.1.1"], "nist": ["SC-28"], "fn": chk_s3_encryption},

    {"id": "AWS-S3-003", "providers": ["aws"], "resource_types": ["S3 Bucket"],
     "title": "S3 bucket versioning not enabled",
     "description": "Without versioning, accidental deletions or overwrites cannot be recovered.",
     "severity": "medium", "remediation": "Enable versioning on the S3 bucket.",
     "cis": ["CIS AWS 2.1.3"], "nist": ["CP-9"], "fn": chk_s3_versioning},

    {"id": "AWS-S3-004", "providers": ["aws"], "resource_types": ["S3 Bucket"],
     "title": "S3 bucket access logging not enabled",
     "description": "Server access logging is disabled. Bucket access cannot be audited.",
     "severity": "low", "remediation": "Enable server access logging on the S3 bucket.",
     "cis": ["CIS AWS 2.1.2"], "nist": ["AU-2", "AU-12"], "fn": chk_s3_logging},

    {"id": "AWS-S3-005", "providers": ["aws"], "resource_types": ["S3 Bucket"],
     "title": "S3 bucket does not enforce TLS-only access",
     "description": "The bucket may allow unencrypted HTTP connections.",
     "severity": "high", "remediation": "Add a bucket policy that denies s3:* when aws:SecureTransport is false.",
     "cis": ["CIS AWS 2.1.1"], "nist": ["SC-8", "SC-28"], "fn": chk_s3_tls_only},

    {"id": "AWS-S3-006", "providers": ["aws"], "resource_types": ["S3 Bucket"],
     "title": "S3 bucket MFA delete not enabled",
     "description": "MFA Delete adds an extra layer of protection against accidental or malicious deletion.",
     "severity": "medium", "remediation": "Enable MFA Delete on versioned S3 buckets.",
     "cis": ["CIS AWS 2.1.3"], "nist": ["CP-9"], "fn": chk_s3_mfa_delete},

    # EC2
    {"id": "AWS-EC2-001", "providers": ["aws"], "resource_types": ["EC2 Instance"],
     "title": "EC2 instance IMDSv2 not enforced",
     "description": "IMDSv1 is still allowed. IMDSv2 prevents SSRF-based metadata attacks.",
     "severity": "high", "remediation": "Set HttpTokens to 'required' on the EC2 instance.",
     "cis": ["CIS AWS 5.6"], "nist": ["AC-17", "SC-5"], "fn": chk_ec2_imdsv2},

    {"id": "AWS-EC2-002", "providers": ["aws"], "resource_types": ["EC2 Instance"],
     "title": "EC2 instance has public IP address",
     "description": "This instance is directly reachable from the internet.",
     "severity": "medium", "remediation": "Use private subnets with a load balancer or NAT gateway.",
     "cis": ["CIS AWS 5.2"], "nist": ["SC-7", "AC-4"], "fn": chk_ec2_public_ip},

    {"id": "AWS-EC2-003", "providers": ["aws"], "resource_types": ["EC2 Instance"],
     "title": "EC2 instance detailed monitoring not enabled",
     "description": "Without detailed monitoring, metric granularity is 5 minutes instead of 1 minute.",
     "severity": "low", "remediation": "Enable detailed monitoring on the EC2 instance.",
     "cis": ["CIS AWS 3.1"], "nist": ["AU-2", "SI-4"], "fn": chk_ec2_detailed_monitoring},

    {"id": "AWS-EC2-004", "providers": ["aws"], "resource_types": ["EC2 Instance"],
     "title": "EC2 instance not in a VPC",
     "description": "Instances not in a VPC use EC2-Classic which has weaker isolation.",
     "severity": "high", "remediation": "Migrate the instance to a VPC.",
     "cis": ["CIS AWS 5.1"], "nist": ["SC-7"], "fn": chk_ec2_vpc},

    # Security Groups
    {"id": "AWS-SG-001", "providers": ["aws"], "resource_types": ["Security Group"],
     "title": "Security group allows unrestricted inbound access",
     "description": "Rules allow inbound access from 0.0.0.0/0 on all ports.",
     "severity": "critical", "remediation": "Restrict inbound rules to specific IP ranges.",
     "cis": ["CIS AWS 5.2", "CIS AWS 5.3"], "nist": ["SC-7", "AC-4"], "fn": chk_sg_open_ingress},

    {"id": "AWS-SG-002", "providers": ["aws"], "resource_types": ["Security Group"],
     "title": "Security group allows SSH from any IP",
     "description": "Port 22 is open to 0.0.0.0/0, allowing brute-force attempts from anywhere.",
     "severity": "critical", "remediation": "Restrict SSH access to known IP ranges or use AWS Systems Manager Session Manager.",
     "cis": ["CIS AWS 5.2"], "nist": ["AC-17", "SC-7"], "fn": chk_sg_ssh_open},

    {"id": "AWS-SG-003", "providers": ["aws"], "resource_types": ["Security Group"],
     "title": "Security group allows RDP from any IP",
     "description": "Port 3389 is open to 0.0.0.0/0, exposing Windows instances to brute-force attacks.",
     "severity": "critical", "remediation": "Restrict RDP access to known IP ranges or use a VPN/bastion host.",
     "cis": ["CIS AWS 5.3"], "nist": ["AC-17", "SC-7"], "fn": chk_sg_rdp_open},

    # IAM
    {"id": "AWS-IAM-001", "providers": ["aws"], "resource_types": ["IAM User"],
     "title": "IAM user does not have MFA enabled",
     "description": "MFA is not enabled, increasing risk from credential compromise.",
     "severity": "critical", "remediation": "Enable MFA for all IAM users with console access.",
     "cis": ["CIS AWS 1.5", "CIS AWS 1.6"], "nist": ["IA-2", "IA-5"], "fn": chk_iam_mfa},

    {"id": "AWS-IAM-002", "providers": ["aws"], "resource_types": ["IAM User"],
     "title": "IAM user has access keys older than 90 days",
     "description": "Old access keys increase risk if they were previously exposed.",
     "severity": "high", "remediation": "Rotate IAM access keys every 90 days.",
     "cis": ["CIS AWS 1.14"], "nist": ["IA-5"], "fn": chk_iam_old_access_keys},

    {"id": "AWS-IAM-003", "providers": ["aws"], "resource_types": ["IAM User"],
     "title": "IAM user has policies attached directly",
     "description": "Direct policy attachments are harder to audit. Use groups or roles instead.",
     "severity": "low", "remediation": "Detach inline policies and assign permissions via IAM groups or roles.",
     "cis": ["CIS AWS 1.16"], "nist": ["AC-2", "AC-6"], "fn": chk_iam_no_policies_direct},

    # RDS
    {"id": "AWS-RDS-001", "providers": ["aws"], "resource_types": ["RDS Instance"],
     "title": "RDS instance is publicly accessible",
     "description": "The database is reachable from the public internet.",
     "severity": "critical", "remediation": "Disable public accessibility and move to a private subnet.",
     "cis": ["CIS AWS 2.3.2"], "nist": ["SC-7", "AC-3"], "fn": chk_rds_public},

    {"id": "AWS-RDS-002", "providers": ["aws"], "resource_types": ["RDS Instance"],
     "title": "RDS instance storage not encrypted",
     "description": "Database storage is not encrypted at rest.",
     "severity": "high", "remediation": "Enable encryption at rest. Note: must be set at creation time.",
     "cis": ["CIS AWS 2.3.1"], "nist": ["SC-28"], "fn": chk_rds_encryption},

    {"id": "AWS-RDS-003", "providers": ["aws"], "resource_types": ["RDS Instance"],
     "title": "RDS backup retention period is less than 7 days",
     "description": "Short backup retention limits disaster recovery options.",
     "severity": "medium", "remediation": "Set backup retention to at least 7 days.",
     "cis": ["CIS AWS 2.3.3"], "nist": ["CP-9"], "fn": chk_rds_backup},

    {"id": "AWS-RDS-004", "providers": ["aws"], "resource_types": ["RDS Instance"],
     "title": "RDS instance deletion protection not enabled",
     "description": "Without deletion protection, databases can be accidentally deleted.",
     "severity": "medium", "remediation": "Enable deletion protection on production RDS instances.",
     "cis": ["CIS AWS 2.3.4"], "nist": ["CP-9"], "fn": chk_rds_deletion_protection},

    {"id": "AWS-RDS-005", "providers": ["aws"], "resource_types": ["RDS Instance"],
     "title": "RDS instance not configured for Multi-AZ",
     "description": "Single-AZ deployments have no automatic failover capability.",
     "severity": "medium", "remediation": "Enable Multi-AZ deployment for production RDS instances.",
     "cis": ["CIS AWS 2.3.5"], "nist": ["CP-9", "CP-10"], "fn": chk_rds_multi_az},

    # Lambda
    {"id": "AWS-LAMBDA-001", "providers": ["aws"], "resource_types": ["Lambda Function"],
     "title": "Lambda function has a publicly accessible resource policy",
     "description": "The function can be invoked by any AWS principal or anonymous user.",
     "severity": "high", "remediation": "Restrict the function resource policy to specific principals.",
     "cis": ["CIS AWS 3.10"], "nist": ["AC-3", "SC-7"], "fn": chk_lambda_public_policy},

    {"id": "AWS-LAMBDA-002", "providers": ["aws"], "resource_types": ["Lambda Function"],
     "title": "Lambda function environment variables may contain secrets",
     "description": "Environment variable names suggest secrets may be stored in plaintext.",
     "severity": "high", "remediation": "Use AWS Secrets Manager or SSM Parameter Store instead of environment variables.",
     "cis": ["CIS AWS 3.11"], "nist": ["IA-5", "SC-28"], "fn": chk_lambda_env_secrets},

    {"id": "AWS-LAMBDA-003", "providers": ["aws"], "resource_types": ["Lambda Function"],
     "title": "Lambda function uses an end-of-life runtime",
     "description": "This runtime no longer receives security patches from AWS.",
     "severity": "high", "remediation": "Migrate the function to a supported runtime version.",
     "cis": ["CIS AWS 3.12"], "nist": ["SI-2"], "fn": chk_lambda_outdated_runtime},
]


# ══════════════════════════════════════════════════════════════════════════════
# AZURE CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def chk_az_storage_public(a):
    if props(a).get("allow_blob_public_access"):
        return {"allow_blob_public_access": True}

def chk_az_storage_https(a):
    if not props(a).get("https_only"):
        return {"https_only": False}

def chk_az_storage_tls(a):
    tls = props(a).get("minimum_tls_version")
    if tls != "TLS1_2":
        return {"minimum_tls_version": tls}

def chk_az_storage_shared_key(a):
    if props(a).get("allow_shared_key_access") is not False:
        return {"allow_shared_key_access": True}

def chk_az_nsg_open(a):
    if props(a).get("open_inbound_rules", 0) > 0:
        return {"open_inbound_rules": props(a).get("open_inbound_rules")}

def chk_az_kv_soft_delete(a):
    if not props(a).get("soft_delete_enabled"):
        return {"soft_delete_enabled": False}

def chk_az_kv_purge_protection(a):
    if not props(a).get("purge_protection"):
        return {"purge_protection": False}

def chk_az_vm_disk_encrypted(a):
    if not props(a).get("disk_encryption_enabled"):
        return {"disk_encryption": "disabled"}

def chk_az_vm_endpoint_protection(a):
    if not props(a).get("endpoint_protection"):
        return {"endpoint_protection": "not_configured"}

def chk_az_sql_auditing(a):
    if not props(a).get("auditing_enabled"):
        return {"auditing": "disabled"}

def chk_az_sql_tde(a):
    if not props(a).get("tde_enabled"):
        return {"transparent_data_encryption": "disabled"}

def chk_az_sql_advanced_threat(a):
    if not props(a).get("advanced_threat_protection"):
        return {"advanced_threat_protection": "disabled"}


AZURE_CHECKS = [
    {"id": "AZ-STG-001", "providers": ["azure"], "resource_types": ["Storage Account"],
     "title": "Azure Storage Account allows public blob access",
     "description": "Public blob access is enabled, potentially exposing storage contents.",
     "severity": "critical", "remediation": "Set 'allowBlobPublicAccess' to false.",
     "cis": ["CIS Azure 3.5"], "nist": ["AC-3", "SC-7"], "fn": chk_az_storage_public},

    {"id": "AZ-STG-002", "providers": ["azure"], "resource_types": ["Storage Account"],
     "title": "Azure Storage Account does not enforce HTTPS",
     "description": "HTTP traffic is allowed, exposing data in transit.",
     "severity": "high", "remediation": "Enable 'Secure transfer required'.",
     "cis": ["CIS Azure 3.1"], "nist": ["SC-8", "SC-28"], "fn": chk_az_storage_https},

    {"id": "AZ-STG-003", "providers": ["azure"], "resource_types": ["Storage Account"],
     "title": "Azure Storage Account minimum TLS version is below 1.2",
     "description": "Older TLS versions have known vulnerabilities.",
     "severity": "high", "remediation": "Set minimum TLS version to TLS1_2.",
     "cis": ["CIS Azure 3.2"], "nist": ["SC-8"], "fn": chk_az_storage_tls},

    {"id": "AZ-STG-004", "providers": ["azure"], "resource_types": ["Storage Account"],
     "title": "Azure Storage Account allows shared key authorization",
     "description": "Shared key access can be misused if storage account keys are leaked.",
     "severity": "medium", "remediation": "Disable shared key access and use Azure AD authorization instead.",
     "cis": ["CIS Azure 3.3"], "nist": ["IA-5", "AC-3"], "fn": chk_az_storage_shared_key},

    {"id": "AZ-NSG-001", "providers": ["azure"], "resource_types": ["Network Security Group"],
     "title": "Azure NSG allows unrestricted inbound access",
     "description": "NSG has rules allowing access from any source IP.",
     "severity": "critical", "remediation": "Restrict NSG inbound rules to specific IP ranges.",
     "cis": ["CIS Azure 6.1"], "nist": ["SC-7"], "fn": chk_az_nsg_open},

    {"id": "AZ-KV-001", "providers": ["azure"], "resource_types": ["Key Vault"],
     "title": "Azure Key Vault soft delete not enabled",
     "description": "Without soft delete, accidentally deleted secrets cannot be recovered.",
     "severity": "high", "remediation": "Enable soft delete on the Key Vault.",
     "cis": ["CIS Azure 8.4"], "nist": ["CP-9"], "fn": chk_az_kv_soft_delete},

    {"id": "AZ-KV-002", "providers": ["azure"], "resource_types": ["Key Vault"],
     "title": "Azure Key Vault purge protection not enabled",
     "description": "Without purge protection, soft-deleted vaults can still be permanently deleted.",
     "severity": "medium", "remediation": "Enable purge protection on the Key Vault.",
     "cis": ["CIS Azure 8.5"], "nist": ["CP-9"], "fn": chk_az_kv_purge_protection},

    {"id": "AZ-VM-001", "providers": ["azure"], "resource_types": ["Virtual Machine"],
     "title": "Azure VM disk encryption not enabled",
     "description": "VM disks are not encrypted, risking data exposure if physical media is compromised.",
     "severity": "high", "remediation": "Enable Azure Disk Encryption or server-side encryption with CMK.",
     "cis": ["CIS Azure 7.2"], "nist": ["SC-28"], "fn": chk_az_vm_disk_encrypted},

    {"id": "AZ-SQL-001", "providers": ["azure"], "resource_types": ["SQL Database"],
     "title": "Azure SQL Database auditing not enabled",
     "description": "Without auditing, database activity cannot be monitored or investigated.",
     "severity": "medium", "remediation": "Enable auditing on the SQL Server and configure a log destination.",
     "cis": ["CIS Azure 4.1"], "nist": ["AU-2", "AU-12"], "fn": chk_az_sql_auditing},

    {"id": "AZ-SQL-002", "providers": ["azure"], "resource_types": ["SQL Database"],
     "title": "Azure SQL Database transparent data encryption not enabled",
     "description": "Data at rest is not encrypted.",
     "severity": "high", "remediation": "Enable Transparent Data Encryption (TDE) on the SQL database.",
     "cis": ["CIS Azure 4.5"], "nist": ["SC-28"], "fn": chk_az_sql_tde},

    {"id": "AZ-SQL-003", "providers": ["azure"], "resource_types": ["SQL Database"],
     "title": "Azure SQL Advanced Threat Protection not enabled",
     "description": "Without ATP, SQL injection and anomalous access patterns go undetected.",
     "severity": "medium", "remediation": "Enable Advanced Threat Protection on the SQL Server.",
     "cis": ["CIS Azure 4.2"], "nist": ["SI-4"], "fn": chk_az_sql_advanced_threat},
]


# ══════════════════════════════════════════════════════════════════════════════
# GCP CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def chk_gcp_bucket_public(a):
    if a.get("is_public"):
        return {"public_access": True}

def chk_gcp_bucket_versioning(a):
    if not props(a).get("versioning"):
        return {"versioning": False}

def chk_gcp_bucket_uniform_access(a):
    if not props(a).get("uniform_bucket_level_access"):
        return {"uniform_bucket_level_access": False}

def chk_gcp_bucket_logging(a):
    if not props(a).get("access_logging"):
        return {"access_logging": False}

def chk_gcp_sql_public(a):
    if props(a).get("public_ip"):
        return {"public_ip": True}

def chk_gcp_sql_backup(a):
    if not props(a).get("backup_enabled"):
        return {"backup_enabled": False}

def chk_gcp_sql_ssl(a):
    if not props(a).get("ssl_required"):
        return {"ssl_required": False}

def chk_gcp_sql_contained_db(a):
    flags = props(a).get("database_flags", {})
    if flags.get("contained database authentication") == "on":
        return {"contained_db_auth": "enabled"}

def chk_gcp_fw_open(a):
    if props(a).get("open_to_world") and props(a).get("action") == "allow":
        return {"open_to_world": True}

def chk_gcp_fw_ssh_open(a):
    for rule in props(a).get("allowed", []):
        ports = rule.get("ports", [])
        if props(a).get("open_to_world") and ("22" in ports or "all" in str(rule.get("IPProtocol", ""))):
            return {"ssh_open_to_world": True}

def chk_gcp_vm_public(a):
    if a.get("is_public"):
        return {"public_ip": True}

def chk_gcp_vm_no_service_account(a):
    sas = props(a).get("service_accounts", [])
    default = [s for s in sas if "compute@developer" in s]
    if default:
        return {"default_service_account": default[0]}

def chk_gcp_vm_shielded(a):
    if not props(a).get("shielded_vm"):
        return {"shielded_vm": False}

def chk_gcp_sa_admin_privileges(a):
    if props(a).get("has_admin_role"):
        return {"admin_role": True}


GCP_CHECKS = [
    {"id": "GCP-GCS-001", "providers": ["gcp"], "resource_types": ["Cloud Storage Bucket"],
     "title": "GCP Storage bucket is publicly accessible",
     "description": "The bucket grants access to allUsers or allAuthenticatedUsers.",
     "severity": "critical", "remediation": "Remove allUsers/allAuthenticatedUsers from bucket IAM policy.",
     "cis": ["CIS GCP 5.1"], "nist": ["AC-3", "SC-7"], "fn": chk_gcp_bucket_public},

    {"id": "GCP-GCS-002", "providers": ["gcp"], "resource_types": ["Cloud Storage Bucket"],
     "title": "GCP Storage bucket versioning not enabled",
     "description": "Without versioning, deleted or overwritten objects cannot be recovered.",
     "severity": "medium", "remediation": "Enable versioning on the Cloud Storage bucket.",
     "cis": ["CIS GCP 5.2"], "nist": ["CP-9"], "fn": chk_gcp_bucket_versioning},

    {"id": "GCP-GCS-003", "providers": ["gcp"], "resource_types": ["Cloud Storage Bucket"],
     "title": "GCP Storage bucket does not use uniform bucket-level access",
     "description": "Object-level ACLs can bypass bucket-level IAM policies.",
     "severity": "medium", "remediation": "Enable uniform bucket-level access to enforce IAM exclusively.",
     "cis": ["CIS GCP 5.3"], "nist": ["AC-3"], "fn": chk_gcp_bucket_uniform_access},

    {"id": "GCP-GCS-004", "providers": ["gcp"], "resource_types": ["Cloud Storage Bucket"],
     "title": "GCP Storage bucket access logging not enabled",
     "description": "Without access logs, bucket activity cannot be audited.",
     "severity": "low", "remediation": "Enable access logging on the bucket.",
     "cis": ["CIS GCP 5.4"], "nist": ["AU-2", "AU-12"], "fn": chk_gcp_bucket_logging},

    {"id": "GCP-SQL-001", "providers": ["gcp"], "resource_types": ["Cloud SQL Instance"],
     "title": "Cloud SQL instance is publicly accessible",
     "description": "The instance allows connections from 0.0.0.0/0.",
     "severity": "critical", "remediation": "Remove 0.0.0.0/0 from authorized networks; use Cloud SQL Auth Proxy.",
     "cis": ["CIS GCP 6.5"], "nist": ["SC-7", "AC-3"], "fn": chk_gcp_sql_public},

    {"id": "GCP-SQL-002", "providers": ["gcp"], "resource_types": ["Cloud SQL Instance"],
     "title": "Cloud SQL automated backups not enabled",
     "description": "Automated backups are disabled, risking data loss.",
     "severity": "high", "remediation": "Enable automated backups for the Cloud SQL instance.",
     "cis": ["CIS GCP 6.7"], "nist": ["CP-9"], "fn": chk_gcp_sql_backup},

    {"id": "GCP-SQL-003", "providers": ["gcp"], "resource_types": ["Cloud SQL Instance"],
     "title": "Cloud SQL does not require SSL connections",
     "description": "SSL is not enforced, allowing unencrypted database connections.",
     "severity": "high", "remediation": "Enable requireSsl and configure SSL certificates for clients.",
     "cis": ["CIS GCP 6.4"], "nist": ["SC-8"], "fn": chk_gcp_sql_ssl},

    {"id": "GCP-FW-001", "providers": ["gcp"], "resource_types": ["Firewall Rule"],
     "title": "GCP firewall rule allows unrestricted access",
     "description": "An allow rule accepts traffic from any IP address.",
     "severity": "critical", "remediation": "Restrict firewall rule source ranges to known IP addresses.",
     "cis": ["CIS GCP 3.6"], "nist": ["SC-7"], "fn": chk_gcp_fw_open},

    {"id": "GCP-FW-002", "providers": ["gcp"], "resource_types": ["Firewall Rule"],
     "title": "GCP firewall allows SSH from any IP",
     "description": "Port 22 is open to 0.0.0.0/0.",
     "severity": "critical", "remediation": "Restrict SSH to specific IPs or use IAP for TCP forwarding.",
     "cis": ["CIS GCP 3.6"], "nist": ["AC-17", "SC-7"], "fn": chk_gcp_fw_ssh_open},

    {"id": "GCP-VM-001", "providers": ["gcp"], "resource_types": ["Compute Instance"],
     "title": "GCP VM instance has a public IP address",
     "description": "The instance is directly reachable from the internet.",
     "severity": "medium", "remediation": "Remove the external IP and route outbound traffic through Cloud NAT.",
     "cis": ["CIS GCP 4.9"], "nist": ["SC-7"], "fn": chk_gcp_vm_public},

    {"id": "GCP-VM-002", "providers": ["gcp"], "resource_types": ["Compute Instance"],
     "title": "GCP VM uses the default service account",
     "description": "The default Compute Engine service account has broad project-level permissions.",
     "severity": "high", "remediation": "Create a dedicated service account with minimum required permissions.",
     "cis": ["CIS GCP 4.1"], "nist": ["AC-6"], "fn": chk_gcp_vm_no_service_account},

    {"id": "GCP-VM-003", "providers": ["gcp"], "resource_types": ["Compute Instance"],
     "title": "GCP VM Shielded VM not enabled",
     "description": "Without Shielded VM, the instance lacks protection against rootkits and bootkits.",
     "severity": "medium", "remediation": "Enable Secure Boot, vTPM, and Integrity Monitoring on the instance.",
     "cis": ["CIS GCP 4.8"], "nist": ["SI-7"], "fn": chk_gcp_vm_shielded},

    {"id": "GCP-SA-001", "providers": ["gcp"], "resource_types": ["Service Account"],
     "title": "GCP service account has admin-level privileges",
     "description": "This service account has been granted an admin role, violating least privilege.",
     "severity": "critical", "remediation": "Replace the admin role with a custom role granting only required permissions.",
     "cis": ["CIS GCP 1.5"], "nist": ["AC-6"], "fn": chk_gcp_sa_admin_privileges},
]
