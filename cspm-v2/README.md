# CloudGuard CSPM

A multi-cloud Cloud Security Posture Management (CSPM) platform that connects to AWS, Azure, and GCP to discover assets, detect misconfigurations, and monitor compliance.

---

## What it does

- **Asset Inventory** — Discover all cloud resources across AWS, Azure, and GCP
- **Security Findings** — Run automated checks (30+ rules) to find misconfigurations
- **Secure Score** — Get a 0–100 posture score based on your findings
- **CIS Compliance** — Map findings to CIS Benchmark controls
- **Finding Details** — See remediation guidance for every issue

---

## Quick Start

### Option 1: Script (development)

```bash
chmod +x start.sh
./start.sh
```

Then open: http://localhost:3000

### Option 2: Docker (recommended)

```bash
docker-compose up --build
```

Then open: http://localhost:3000

---

## Manual Setup

### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

API docs available at: http://localhost:8000/docs

### Frontend

```bash
cd frontend
npm install
npm run dev
```

---

## Cloud Credentials

### AWS

You need an IAM user or role with **read-only** permissions. Recommended managed policies:
- `SecurityAudit`
- `ReadOnlyAccess`

Or create a custom policy with these permissions:
```
s3:ListAllMyBuckets, s3:GetBucketAcl, s3:GetBucketEncryption,
s3:GetBucketVersioning, s3:GetBucketLogging, s3:GetPublicAccessBlock,
ec2:DescribeInstances, ec2:DescribeSecurityGroups, ec2:DescribeRegions,
iam:ListUsers, iam:ListMFADevices, iam:ListAccessKeys,
rds:DescribeDBInstances,
lambda:ListFunctions
```

### Azure

Create a Service Principal with the **Reader** role:

```bash
az ad sp create-for-rbac --name "cloudguard-cspm" --role Reader \
  --scopes /subscriptions/{subscription-id}
```

This gives you: tenant_id, client_id, client_secret, subscription_id.

### GCP

Create a Service Account with the **Viewer** role:

```bash
gcloud iam service-accounts create cloudguard-cspm
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:cloudguard-cspm@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"
gcloud iam service-accounts keys create key.json \
  --iam-account=cloudguard-cspm@PROJECT_ID.iam.gserviceaccount.com
```

Paste the contents of `key.json` into the GCP credentials field in the UI.

---

## Security Checks

### AWS
| Check ID | Resource | Severity | CIS Control |
|---|---|---|---|
| AWS-S3-001 | S3 Bucket | Critical | CIS AWS 2.1.5 |
| AWS-S3-002 | S3 Bucket | High | CIS AWS 2.1.1 |
| AWS-S3-003 | S3 Bucket | Medium | CIS AWS 2.1.3 |
| AWS-S3-004 | S3 Bucket | Low | CIS AWS 2.1.2 |
| AWS-EC2-001 | EC2 Instance | High | CIS AWS 5.6 |
| AWS-EC2-002 | EC2 Instance | Medium | CIS AWS 5.2 |
| AWS-SG-001 | Security Group | Critical | CIS AWS 5.2 |
| AWS-IAM-001 | IAM User | Critical | CIS AWS 1.5 |
| AWS-RDS-001 | RDS Instance | Critical | CIS AWS 2.3.2 |
| AWS-RDS-002 | RDS Instance | High | CIS AWS 2.3.1 |
| AWS-RDS-003 | RDS Instance | Medium | CIS AWS 2.3.3 |

### Azure
| Check ID | Resource | Severity | CIS Control |
|---|---|---|---|
| AZ-STG-001 | Storage Account | Critical | CIS Azure 3.5 |
| AZ-STG-002 | Storage Account | High | CIS Azure 3.1 |
| AZ-STG-003 | Storage Account | High | CIS Azure 3.2 |
| AZ-NSG-001 | Network Security Group | Critical | CIS Azure 6.1 |
| AZ-KV-001 | Key Vault | High | CIS Azure 8.4 |
| AZ-KV-002 | Key Vault | Medium | CIS Azure 8.5 |

### GCP
| Check ID | Resource | Severity | CIS Control |
|---|---|---|---|
| GCP-GCS-001 | Cloud Storage | Critical | CIS GCP 5.1 |
| GCP-GCS-002 | Cloud Storage | Medium | CIS GCP 5.2 |
| GCP-SQL-001 | Cloud SQL | Critical | CIS GCP 6.5 |
| GCP-SQL-002 | Cloud SQL | High | CIS GCP 6.7 |
| GCP-SQL-003 | Cloud SQL | High | CIS GCP 6.4 |
| GCP-FW-001 | Firewall Rule | Critical | CIS GCP 3.6 |
| GCP-VM-001 | Compute Instance | Medium | CIS GCP 4.9 |

---

## Project Structure

```
cspm/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app
│   │   ├── scan_orchestrator.py # Scan coordinator
│   │   ├── api/
│   │   │   ├── scan.py          # Scan endpoints
│   │   │   ├── dashboard.py     # Dashboard summary
│   │   │   ├── assets.py        # Asset inventory
│   │   │   ├── findings.py      # Security findings
│   │   │   └── compliance.py    # CIS compliance
│   │   ├── collectors/
│   │   │   ├── aws_collector.py
│   │   │   ├── azure_collector.py
│   │   │   └── gcp_collector.py
│   │   ├── checks/
│   │   │   ├── security_checks.py  # 24+ security rules
│   │   │   └── compliance.py       # CIS framework mapping
│   │   └── models/
│   │       ├── db_models.py
│   │       └── database.py
│   └── requirements.txt
├── frontend/
│   └── src/
│       └── App.jsx              # Full React dashboard
├── docker-compose.yml
├── start.sh
└── README.md
```

---

## V2 Roadmap

- **Attack path analysis** — Graph-based lateral movement detection
- **Risk prioritization** — AI-driven risk scoring
- **Scheduled scans** — Automatic scanning on a cron schedule
- **Notifications** — Slack/email alerts for new critical findings
- **Suppression rules** — Mark findings as accepted risk
- **Export reports** — PDF/CSV compliance reports
- **NIST framework** — Full NIST 800-53 control mapping
- **Agentless VM scanning** — CVE detection for running instances

---

## API Reference

Full interactive docs at: http://localhost:8000/docs

Key endpoints:
- `POST /api/scan/start` — Start a new scan
- `GET /api/scan/status/{id}` — Poll scan status
- `GET /api/dashboard/summary` — Dashboard overview
- `GET /api/assets` — List all assets (filterable)
- `GET /api/findings` — List all findings (filterable by severity, cloud)
- `GET /api/compliance` — CIS compliance results
