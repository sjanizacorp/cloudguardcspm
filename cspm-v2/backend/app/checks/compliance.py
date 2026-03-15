from typing import List, Dict
import uuid

# ── CIS Framework ─────────────────────────────────────────────────────────────
CIS_FRAMEWORK = {
    "aws": {
        "CIS AWS 1.5":  {"title": "Ensure MFA is enabled for the root account", "section": "1 - Identity and Access Management"},
        "CIS AWS 1.6":  {"title": "Ensure MFA is enabled for all IAM users that have a console password", "section": "1 - Identity and Access Management"},
        "CIS AWS 1.14": {"title": "Ensure access keys are rotated every 90 days or less", "section": "1 - Identity and Access Management"},
        "CIS AWS 1.16": {"title": "Ensure IAM policies are attached only to groups or roles", "section": "1 - Identity and Access Management"},
        "CIS AWS 2.1.1": {"title": "Ensure S3 bucket policy is set to deny HTTP requests", "section": "2 - Storage"},
        "CIS AWS 2.1.2": {"title": "Ensure MFA Delete is enabled on S3 buckets", "section": "2 - Storage"},
        "CIS AWS 2.1.3": {"title": "Ensure all data in S3 has been discovered, classified and secured", "section": "2 - Storage"},
        "CIS AWS 2.1.5": {"title": "Ensure S3 Public Access Block is enabled", "section": "2 - Storage"},
        "CIS AWS 2.3.1": {"title": "Ensure RDS encryption is enabled", "section": "2 - Storage"},
        "CIS AWS 2.3.2": {"title": "Ensure RDS instances are not publicly accessible", "section": "2 - Storage"},
        "CIS AWS 2.3.3": {"title": "Ensure RDS backup retention is set to at least 7 days", "section": "2 - Storage"},
        "CIS AWS 2.3.4": {"title": "Ensure RDS deletion protection is enabled", "section": "2 - Storage"},
        "CIS AWS 2.3.5": {"title": "Ensure RDS Multi-AZ deployment is enabled", "section": "2 - Storage"},
        "CIS AWS 3.1":  {"title": "Ensure CloudTrail is enabled in all regions", "section": "3 - Logging"},
        "CIS AWS 3.10": {"title": "Ensure Lambda functions have resource-based policies with least privilege", "section": "3 - Logging"},
        "CIS AWS 3.11": {"title": "Ensure Lambda environment variables do not contain sensitive data", "section": "3 - Logging"},
        "CIS AWS 3.12": {"title": "Ensure Lambda functions use supported runtimes", "section": "3 - Logging"},
        "CIS AWS 5.1":  {"title": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server ports", "section": "5 - Networking"},
        "CIS AWS 5.2":  {"title": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server ports", "section": "5 - Networking"},
        "CIS AWS 5.3":  {"title": "Ensure no security groups allow ingress from ::/0 to remote server ports", "section": "5 - Networking"},
        "CIS AWS 5.6":  {"title": "Ensure EC2 instance metadata service uses IMDSv2", "section": "5 - Networking"},
    },
    "azure": {
        "CIS Azure 3.1": {"title": "Ensure that 'Secure transfer required' is set to 'Enabled'", "section": "3 - Storage Accounts"},
        "CIS Azure 3.2": {"title": "Ensure that storage account access keys are periodically regenerated", "section": "3 - Storage Accounts"},
        "CIS Azure 3.3": {"title": "Ensure Storage logging is enabled for Queue service", "section": "3 - Storage Accounts"},
        "CIS Azure 3.5": {"title": "Ensure that 'Public access level' is set to Private for blob containers", "section": "3 - Storage Accounts"},
        "CIS Azure 4.1": {"title": "Ensure that 'Auditing' is set to 'On' for SQL Servers", "section": "4 - Database Services"},
        "CIS Azure 4.2": {"title": "Ensure that Microsoft Defender for SQL is set to 'On'", "section": "4 - Database Services"},
        "CIS Azure 4.5": {"title": "Ensure that Transparent Data Encryption is enabled on SQL Databases", "section": "4 - Database Services"},
        "CIS Azure 6.1": {"title": "Ensure that RDP access is restricted from the internet", "section": "6 - Networking"},
        "CIS Azure 7.2": {"title": "Ensure that 'OS disk' are encrypted", "section": "7 - Virtual Machines"},
        "CIS Azure 8.4": {"title": "Ensure that Azure Key Vault disables public network access", "section": "8 - Key Vault"},
        "CIS Azure 8.5": {"title": "Ensure that Azure Key Vault has purge protection enabled", "section": "8 - Key Vault"},
    },
    "gcp": {
        "CIS GCP 1.5": {"title": "Ensure that service account has no admin privileges", "section": "1 - Identity and Access Management"},
        "CIS GCP 3.6": {"title": "Ensure that SSH access is restricted from the internet", "section": "3 - Networking"},
        "CIS GCP 4.1": {"title": "Ensure that instances are not configured to use the default service account", "section": "4 - Virtual Machines"},
        "CIS GCP 4.8": {"title": "Ensure Compute instances are launched with Shielded VM enabled", "section": "4 - Virtual Machines"},
        "CIS GCP 4.9": {"title": "Ensure that Compute instances do not have public IP addresses", "section": "4 - Virtual Machines"},
        "CIS GCP 5.1": {"title": "Ensure that Cloud Storage bucket is not anonymously or publicly accessible", "section": "5 - Storage"},
        "CIS GCP 5.2": {"title": "Ensure that Cloud Storage buckets have versioning enabled", "section": "5 - Storage"},
        "CIS GCP 5.3": {"title": "Ensure that retention policies on Cloud Storage buckets are configured", "section": "5 - Storage"},
        "CIS GCP 5.4": {"title": "Ensure that Cloud Storage buckets have access logging configured", "section": "5 - Storage"},
        "CIS GCP 6.4": {"title": "Ensure that Cloud SQL database instances require all connections to use SSL", "section": "6 - Cloud SQL Database Services"},
        "CIS GCP 6.5": {"title": "Ensure that Cloud SQL database instances are not open to the world", "section": "6 - Cloud SQL Database Services"},
        "CIS GCP 6.7": {"title": "Ensure that Cloud SQL database instances have automated backups configured", "section": "6 - Cloud SQL Database Services"},
    }
}

# ── NIST 800-53 Controls ──────────────────────────────────────────────────────
NIST_CONTROLS = {
    "AC-2":  {"title": "Account Management", "family": "Access Control"},
    "AC-3":  {"title": "Access Enforcement", "family": "Access Control"},
    "AC-4":  {"title": "Information Flow Enforcement", "family": "Access Control"},
    "AC-6":  {"title": "Least Privilege", "family": "Access Control"},
    "AC-17": {"title": "Remote Access", "family": "Access Control"},
    "AU-2":  {"title": "Event Logging", "family": "Audit and Accountability"},
    "AU-12": {"title": "Audit Record Generation", "family": "Audit and Accountability"},
    "CP-9":  {"title": "System Backup", "family": "Contingency Planning"},
    "CP-10": {"title": "System Recovery and Reconstitution", "family": "Contingency Planning"},
    "IA-2":  {"title": "Identification and Authentication (Organizational Users)", "family": "Identification and Authentication"},
    "IA-5":  {"title": "Authenticator Management", "family": "Identification and Authentication"},
    "SC-5":  {"title": "Denial-of-Service Protection", "family": "System and Communications Protection"},
    "SC-7":  {"title": "Boundary Protection", "family": "System and Communications Protection"},
    "SC-8":  {"title": "Transmission Confidentiality and Integrity", "family": "System and Communications Protection"},
    "SC-28": {"title": "Protection of Information at Rest", "family": "System and Communications Protection"},
    "SI-2":  {"title": "Flaw Remediation", "family": "System and Information Integrity"},
    "SI-4":  {"title": "System Monitoring", "family": "System and Information Integrity"},
    "SI-7":  {"title": "Software, Firmware, and Information Integrity", "family": "System and Information Integrity"},
}


def build_compliance_results(findings: List[Dict], providers: List[str]) -> List[Dict]:
    results = []

    # CIS mapping
    finding_by_cis = {}
    for f in findings:
        if f.get("status") == "suppressed":
            continue
        for cis in f.get("cis_controls", []):
            finding_by_cis.setdefault(cis, []).append(f["id"])

    for provider in providers:
        framework = CIS_FRAMEWORK.get(provider, {})
        for control_id, info in framework.items():
            fids = finding_by_cis.get(control_id, [])
            results.append({
                "id": str(uuid.uuid4()),
                "framework": "CIS",
                "control_id": control_id,
                "control_title": info["title"],
                "section": info["section"],
                "status": "failed" if fids else "passed",
                "cloud_provider": provider,
                "finding_ids": fids,
            })

    # NIST mapping
    finding_by_nist = {}
    for f in findings:
        if f.get("status") == "suppressed":
            continue
        for nist in f.get("nist_controls", []):
            finding_by_nist.setdefault(nist, []).append(f["id"])

    for control_id, info in NIST_CONTROLS.items():
        fids = finding_by_nist.get(control_id, [])
        # Determine which providers this applies to based on findings
        relevant_providers = list({f_provider for fid in fids
                                    for f in findings if f["id"] == fid
                                    for f_provider in [f.get("cloud_provider", "multi")]})
        results.append({
            "id": str(uuid.uuid4()),
            "framework": "NIST",
            "control_id": control_id,
            "control_title": info["title"],
            "section": info["family"],
            "status": "failed" if fids else "passed",
            "cloud_provider": "multi",
            "finding_ids": fids,
        })

    return results


def get_compliance_summary(compliance_results: List[Dict]) -> Dict:
    by_framework = {}
    for r in compliance_results:
        fw = r["framework"]
        if fw not in by_framework:
            by_framework[fw] = {"passed": 0, "failed": 0, "total": 0}
        by_framework[fw]["total"] += 1
        if r["status"] == "passed":
            by_framework[fw]["passed"] += 1
        else:
            by_framework[fw]["failed"] += 1
    for fw in by_framework:
        t = by_framework[fw]["total"]
        by_framework[fw]["percentage"] = round(by_framework[fw]["passed"] / t * 100, 1) if t else 0
    return by_framework
