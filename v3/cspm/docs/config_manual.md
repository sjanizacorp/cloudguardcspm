# CloudGuard Pro CSPM — Configuration Manual

**Product:** CloudGuard Pro CSPM v1.0.0  
**Company:** Aniza Corp | Shahryar Jahangir  
**Audience:** System administrators, DevOps engineers, security engineers

---

## Table of Contents

1. [Environment Variables Reference](#1-environment-variables-reference)
2. [Database Configuration](#2-database-configuration)
3. [Provider Credential Setup](#3-provider-credential-setup)
4. [Credential Types Reference](#4-credential-types-reference)
5. [Region Configuration](#5-region-configuration)
6. [Report Storage Configuration](#6-report-storage-configuration)
7. [Docker Volume Configuration](#7-docker-volume-configuration)
8. [PostgreSQL Production Setup](#8-postgresql-production-setup)
9. [Installing Cloud SDK Dependencies](#9-installing-cloud-sdk-dependencies)
10. [Network and Firewall Requirements](#10-network-and-firewall-requirements)
11. [Security Hardening](#11-security-hardening)
12. [Scaling Configuration](#12-scaling-configuration)
13. [Logging Configuration](#13-logging-configuration)

---

## 1. Environment Variables Reference

All configuration is done through environment variables, loaded from the `.env` file.

```bash
cp .env.example .env
# Edit .env with your settings
```

### Core Application

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | IP address to bind the server |
| `PORT` | `8000` | TCP port for the web server |
| `WORKERS` | `1` | Number of Uvicorn worker processes (increase for production) |
| `LOG_LEVEL` | `info` | Logging verbosity: `debug`, `info`, `warning`, `error` |

### Database

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./cspm.db` | SQLAlchemy connection string |

### Application Behaviour

| Variable | Default | Description |
|---|---|---|
| `SEED_DEMO_DATA` | `true` | Seed demo data on startup (set `false` for production) |
| `REPORTS_DIR` | `/tmp/cspm_reports` | Directory for generated PDF reports |

### AWS Credentials

| Variable | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM access key ID |
| `AWS_SECRET_ACCESS_KEY` | IAM secret access key |
| `AWS_SESSION_TOKEN` | Session token (for assumed roles only) |
| `AWS_DEFAULT_REGION` | Default region for API calls |
| `AWS_PROFILE` | Named AWS profile (alternative to key/secret) |

### Azure Credentials

| Variable | Description |
|---|---|
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | Service principal application (client) ID |
| `AZURE_CLIENT_SECRET` | Service principal client secret |
| `AZURE_SUBSCRIPTION_ID` | Default subscription ID |

### GCP Credentials

| Variable | Description |
|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON key file |
| `GOOGLE_CLOUD_PROJECT` | Default GCP project ID |

### IBM Cloud Credentials

| Variable | Description |
|---|---|
| `IBMCLOUD_API_KEY` | IBM Cloud API key |
| `IBM_COS_INSTANCE_ID` | IBM Cloud Object Storage instance ID |

### OCI Credentials
OCI uses `~/.oci/config` by default. No env vars needed unless using a custom config path.

---

## 2. Database Configuration

### SQLite (Development / Demo)

```env
DATABASE_URL=sqlite:///./cspm.db
```

SQLite is zero-configuration and suitable for single-user, single-machine deployments. The database file (`cspm.db`) is created in the working directory. WAL mode is enabled automatically for better concurrent read performance.

**Limitations of SQLite:**
- No concurrent writes from multiple processes
- Not suitable for `WORKERS > 1`
- Not suitable for production with many simultaneous scans

### PostgreSQL (Production)

```env
DATABASE_URL=postgresql://cspm_user:your_password@localhost:5432/cspm_db
```

For Docker with the PostgreSQL profile:

```env
DATABASE_URL=postgresql://cspm_user:cspm_secure_password@postgres:5432/cspm_db
POSTGRES_PASSWORD=cspm_secure_password
```

Start with PostgreSQL profile:
```bash
docker compose --profile pg up -d
```

### Connection Pool Settings (PostgreSQL)

These are hardcoded in `backend/database.py` and can be tuned:

```python
engine = create_engine(
    DATABASE_URL,
    pool_size=10,       # permanent connections in pool
    max_overflow=20,    # extra connections allowed beyond pool_size
    pool_pre_ping=True, # test connections before use
)
```

---

## 3. Provider Credential Setup

### AWS — Best Practices

**Option A: Environment Variables (simplest)**
```env
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Option B: IAM Role (recommended for EC2/ECS/Lambda deployment)**  
No env vars needed. CloudGuard uses the instance profile automatically when `credential_type=env`.

**Option C: Cross-account role assumption**  
```
credential_type = role
credential_ref  = arn:aws:iam::TARGET_ACCOUNT:role/CloudGuardReadOnly
```

The IAM user running CloudGuard must have `sts:AssumeRole` permission on the target role ARN.

**Minimum required AWS permissions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "CloudGuardReadOnly",
    "Effect": "Allow",
    "Action": [
      "iam:GetAccountSummary",
      "iam:GetAccountPasswordPolicy",
      "iam:ListAccessKeys",
      "s3:ListAllMyBuckets",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketEncryption",
      "s3:GetBucketVersioning",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcs",
      "ec2:DescribeFlowLogs",
      "ec2:GetEbsEncryptionByDefault",
      "rds:DescribeDBInstances",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "kms:ListKeys",
      "kms:DescribeKey",
      "kms:GetKeyRotationStatus",
      "lambda:ListFunctions",
      "eks:ListClusters",
      "eks:DescribeCluster",
      "ecr:DescribeRepositories",
      "secretsmanager:ListSecrets"
    ],
    "Resource": "*"
  }]
}
```

### Azure — Service Principal Setup

```bash
# Create service principal
az ad sp create-for-rbac \
  --name "cloudguard-cspm-sp" \
  --role "Security Reader" \
  --scopes /subscriptions/SUBSCRIPTION_ID \
  --output json

# Output:
# { "appId": "CLIENT_ID", "password": "CLIENT_SECRET", "tenant": "TENANT_ID" }
```

Required roles at subscription level:
- `Security Reader` (for Defender for Cloud)
- `Reader` (for all resource data)

### GCP — Service Account Setup

```bash
# Create service account
gcloud iam service-accounts create cloudguard-cspm \
  --display-name="CloudGuard Pro CSPM"

# Grant roles
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:cloudguard-cspm@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/iam.securityReviewer"

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:cloudguard-cspm@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"

# Create key
gcloud iam service-accounts keys create ./cloudguard-sa-key.json \
  --iam-account=cloudguard-cspm@PROJECT_ID.iam.gserviceaccount.com
```

---

## 4. Credential Types Reference

When adding a connection in the UI, select the `Credential Type` that matches how you've stored your credentials.

| Type | Description | credential_ref value |
|---|---|---|
| `env` | Read from environment variables (recommended) | (leave blank) |
| `profile` | AWS named profile in `~/.aws/credentials` | Profile name, e.g. `prod-readonly` |
| `role` | Assume an IAM role (AWS) | Role ARN, e.g. `arn:aws:iam::123:role/Reader` |
| `file` | Read credentials from a file | File path, e.g. `/etc/cloudguard/sa-key.json` |
| `workload_identity` | GKE/EKS workload identity federation | (leave blank) |

---

## 5. Region Configuration

### AWS Region Scanning

In the connection form, enter a comma-separated list of regions:
```
us-east-1, us-west-2, eu-west-1, ap-southeast-1
```

Leave blank to auto-discover and scan **all enabled regions** in the account. This is comprehensive but slow for accounts with many regions.

### Azure Location Filtering

Azure uses locations rather than regions. Leave the regions field blank to scan all locations in the subscription.

### GCP Zone/Region Filtering

GCP collectors operate at the project level. Regional filtering is handled per-API call internally.

---

## 6. Report Storage Configuration

```env
REPORTS_DIR=/var/cloudguard/reports
```

Ensure this directory:
- Exists and is writable by the process user
- Has sufficient disk space (typical report: 100KB–2MB)
- Is backed up if you want to retain historical reports

For Docker:
```yaml
volumes:
  - /host/path/to/reports:/reports
```

And set:
```env
REPORTS_DIR=/reports
```

---

## 7. Docker Volume Configuration

The `docker-compose.yml` defines three volumes:

| Volume | Purpose |
|---|---|
| `cspm_data` | Application data including SQLite database |
| `cspm_reports` | Generated PDF reports |
| `pg_data` | PostgreSQL data (only with `--profile pg`) |

To use host-mounted directories instead of named volumes (for easier backup):

```yaml
# In docker-compose.yml, replace:
volumes:
  cspm_data:

# With:
services:
  cspm:
    volumes:
      - ./data:/app/data
      - ./reports:/reports
```

---

## 8. PostgreSQL Production Setup

### 1. Create database and user

```sql
CREATE DATABASE cspm_db;
CREATE USER cspm_user WITH ENCRYPTED PASSWORD 'your_strong_password_here';
GRANT ALL PRIVILEGES ON DATABASE cspm_db TO cspm_user;
```

### 2. Configure connection

```env
DATABASE_URL=postgresql://cspm_user:your_strong_password_here@localhost:5432/cspm_db
```

### 3. Connection pool tuning

For production with multiple workers:
```python
# In backend/database.py, adjust:
pool_size=20
max_overflow=40
```

### 4. Enable SSL for PostgreSQL connection

```env
DATABASE_URL=postgresql://cspm_user:password@db-host:5432/cspm_db?sslmode=require
```

---

## 9. Installing Cloud SDK Dependencies

CloudGuard Pro's requirements.txt installs only `boto3` (AWS) by default. To enable Azure, GCP, IBM, or OCI collection, install the relevant SDK group.

### Azure SDK
```bash
source venv/bin/activate  # or use venv\Scripts\activate on Windows
pip install \
  azure-identity==1.17.1 \
  azure-mgmt-resource==23.1.1 \
  azure-mgmt-storage==21.1.0 \
  azure-mgmt-sql==3.0.1 \
  azure-mgmt-keyvault==10.3.1 \
  azure-mgmt-network==25.4.0 \
  azure-mgmt-containerservice==31.0.0 \
  azure-mgmt-compute==31.0.0 \
  azure-mgmt-monitor==6.0.2 \
  azure-mgmt-security==7.0.0
```

### GCP SDK
```bash
pip install \
  google-cloud-storage==2.17.0 \
  google-cloud-kms==2.24.0 \
  google-cloud-container==2.44.0 \
  google-cloud-bigquery==3.25.0 \
  google-auth==2.32.0 \
  google-api-python-client==2.139.0
```

### IBM Cloud SDK
```bash
pip install \
  ibm-cloud-sdk-core==3.20.6 \
  ibm-platform-services==0.53.2
```

### OCI SDK
```bash
pip install oci==2.129.0
```

### Docker: Adding SDKs to the image

Uncomment the relevant lines in `requirements.txt`, then rebuild:
```bash
docker compose build --no-cache
docker compose up -d
```

---

## 10. Network and Firewall Requirements

CloudGuard Pro makes outbound HTTPS (port 443) calls to cloud provider APIs. The following endpoints must be reachable from the machine running CloudGuard.

### AWS
- `*.amazonaws.com` — all AWS service endpoints
- `sts.amazonaws.com` — for role assumption

### Azure
- `management.azure.com`
- `login.microsoftonline.com`
- `graph.microsoft.com`

### GCP
- `*.googleapis.com`
- `accounts.google.com`

### IBM Cloud
- `iam.cloud.ibm.com`
- `resource-controller.cloud.ibm.com`
- `*.cloud.ibm.com`

### OCI
- `identity.*.oraclecloud.com`
- `objectstorage.*.oraclecloud.com`
- `*.oraclecloud.com`

---

## 11. Security Hardening

### Secrets management
- Never commit `.env` to version control — add it to `.gitignore`
- Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) to inject credentials at runtime
- Rotate cloud credentials regularly

### Network exposure
- Do not expose port 8000 to the internet without authentication
- Use a reverse proxy (nginx, Caddy) with TLS in front of CloudGuard
- For Docker, bind to localhost only: change `ports` to `"127.0.0.1:8000:8000"`

### File permissions
```bash
chmod 600 .env
chmod 600 /path/to/gcp-sa-key.json
chmod 700 /var/cloudguard/reports
```

### Docker security
```yaml
# Already set in Dockerfile:
USER cspm  # non-root user
```

### Database security (PostgreSQL)
- Use a dedicated database user with `GRANT` only on `cspm_db`
- Enable SSL on the PostgreSQL connection
- Never use `postgres` superuser for application connections

---

## 12. Scaling Configuration

### Increasing scan throughput

For faster scans with PostgreSQL (not SQLite):

```env
WORKERS=4
```

This starts 4 Uvicorn worker processes. Each can run a scan concurrently.

### Large environments

For accounts with thousands of resources:
- Use region filtering in connections to scope scans
- Consider running one connection per major region
- Schedule scans during off-peak hours

### Report generation

Reports are generated asynchronously in FastAPI background tasks. For very large environments (10,000+ findings), report generation may take 30–60 seconds. The UI polls for completion automatically.

---

## 13. Logging Configuration

### Log levels

```env
LOG_LEVEL=info    # Recommended for production
LOG_LEVEL=debug   # For troubleshooting — very verbose
```

### Structured logging (Docker)

```bash
docker compose logs -f --tail=100 cspm
```

### Log to file (native)

```bash
./scripts/start.sh native 2>&1 | tee /var/log/cloudguard.log
```

### Key log messages to watch

| Message | Meaning |
|---|---|
| `Loaded N checks from registry` | Check packs loaded successfully (N should be ≥ 40) |
| `Starting scan run=... provider=...` | Scan started |
| `Collected N resources for provider=...` | Collection complete |
| `Scan run=... complete` | Scan finished with full stats |
| `PDF generation error` | Report generation failed — check REPORTS_DIR permissions |
| `boto3 not installed` | AWS SDK missing — install boto3 |
| `azure-mgmt libraries not installed` | Azure SDK missing |
