# CloudGuard Pro CSPM — User Manual

**Product:** CloudGuard Pro CSPM v1.0.0  
**Company:** Aniza Corp  
**Author:** Shahryar Jahangir  
**Audience:** Non-technical users, security teams, compliance officers

---

## Table of Contents

1. [What is CloudGuard Pro?](#1-what-is-cloudguard-pro)
2. [Prerequisites](#2-prerequisites)
3. [Deployment — Choosing Your Method](#3-deployment--choosing-your-method)
4. [Native Deployment (Step by Step)](#4-native-deployment-step-by-step)
5. [Docker Deployment (Step by Step)](#5-docker-deployment-step-by-step)
6. [First Login and First Look](#6-first-login-and-first-look)
7. [Connecting AWS](#7-connecting-aws)
8. [Connecting Azure](#8-connecting-azure)
9. [Connecting GCP](#9-connecting-gcp)
10. [Connecting IBM Cloud](#10-connecting-ibm-cloud)
11. [Connecting OCI](#11-connecting-oracle-cloud-oci)
12. [Running Your First Scan](#12-running-your-first-scan)
13. [Reading the Dashboard](#13-reading-the-dashboard)
14. [Browsing Checks by Family](#14-browsing-checks-by-family)
15. [Inspecting Check Code](#15-inspecting-check-code)
16. [Reviewing Findings](#16-reviewing-findings)
17. [Understanding Resource Identifiers](#17-understanding-resource-identifiers)
18. [Suppressing a Finding](#18-suppressing-a-finding)
19. [Exporting PDF Reports](#19-exporting-pdf-reports)
20. [Stopping CloudGuard Pro](#20-stopping-cloudguard-pro)
21. [Uninstalling](#21-uninstalling)
22. [Troubleshooting](#22-troubleshooting)
23. [Frequently Asked Questions](#23-frequently-asked-questions)
24. [Glossary](#24-glossary)

---

## 1. What is CloudGuard Pro?

CloudGuard Pro is a **Cloud Security Posture Management (CSPM)** tool. In plain English: it connects to your cloud accounts (AWS, Azure, GCP, IBM Cloud, Oracle Cloud), reads the configuration of your cloud resources, and checks them against a library of security best practices. When it finds a misconfiguration — such as a storage bucket open to the public, or a database with no encryption — it creates a **finding** so your team can fix it.

**What CloudGuard Pro does:**
- Scans cloud resources across 5 major cloud providers
- Checks configurations against 50+ security rules with full source attribution
- Shows findings with the exact cloud resource identifier (ARN, Azure Resource ID, etc.)
- Generates PDF reports for executives and technical teams
- Lets you view the exact source code and rationale for every check

**What CloudGuard Pro does NOT do:**
- It does not make any changes to your cloud resources (read-only)
- It does not store your cloud credentials in plain text
- It does not send data to external parties

---

## 2. Prerequisites

Before you start, ensure you have the following available on your computer.

### For Native Deployment
| Requirement | Version | How to Check |
|---|---|---|
| Python | 3.9 or higher | Run `python3 --version` in a terminal |
| pip | Any recent version | Run `pip --version` |
| Node.js | 18 or higher | Run `node --version` |
| npm | 9 or higher | Run `npm --version` |
| Git | Any | Run `git --version` |

### For Docker Deployment
| Requirement | Version | How to Check |
|---|---|---|
| Docker Desktop | 4.x or higher | Run `docker --version` |
| Docker Compose | V2 (built into Docker Desktop) | Run `docker compose version` |

> **Windows Users:** All commands in this manual use Linux/macOS shell syntax. On Windows, use Git Bash, WSL2, or PowerShell with equivalent commands. Docker Desktop on Windows works identically.

---

## 3. Deployment — Choosing Your Method

CloudGuard Pro supports two deployment modes:

| Mode | Best For | Requires |
|---|---|---|
| **Native** | Developers, testing, full control | Python + Node.js installed locally |
| **Docker** | Production, easy setup, isolation | Docker Desktop |

If you are unsure, **choose Docker** — it requires fewer steps and isolates the software from your system.

---

## 4. Native Deployment (Step by Step)

### Step 1 — Download the package

Extract the CloudGuard Pro package to a folder on your computer:

```bash
unzip cloudguard-pro-cspm.zip
cd cloudguard-pro-cspm
```

### Step 2 — Run the deploy script

```bash
./scripts/deploy.sh native
```

This script will:
- Create a Python virtual environment
- Install all Python dependencies
- Build the React frontend
- Create a `.env` configuration file from the template

> **Screenshot placeholder:** Terminal showing successful dependency installation

### Step 3 — Review your configuration

Open the `.env` file in a text editor. The key settings are:

```
DATABASE_URL=sqlite:///./cspm.db    # SQLite for dev, change to PostgreSQL for production
SEED_DEMO_DATA=true                  # Set to false after reviewing demo data
PORT=8000                            # The web UI port
```

> **Important:** Do not share your `.env` file. It may contain cloud credentials.

### Step 4 — Start the application

```bash
./scripts/start.sh native
```

You will see output like:
```
INFO:     Started server process [12345]
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Step 5 — Open the dashboard

Open your browser and go to: **http://localhost:8000**

> **Screenshot placeholder:** CloudGuard Pro dashboard loading screen

---

## 5. Docker Deployment (Step by Step)

### Step 1 — Download and extract the package

```bash
unzip cloudguard-pro-cspm.zip
cd cloudguard-pro-cspm
```

### Step 2 — Run the deploy script

```bash
./scripts/deploy.sh docker
```

This will:
- Copy the `.env.example` to `.env`
- Build the Docker image (takes 2–5 minutes the first time)

### Step 3 — Start the container

```bash
./scripts/start.sh docker
```

You will see:
```
✓ Container started.
  Dashboard: http://localhost:8000
  API docs:  http://localhost:8000/docs
```

### Step 4 — Open the dashboard

Go to **http://localhost:8000** in your browser.

> **Screenshot placeholder:** Docker container running, browser showing dashboard

### Step 5 — View container logs (optional)

```bash
docker compose logs -f
```

Press `Ctrl+C` to stop viewing logs (the container keeps running).

---

## 6. First Login and First Look

CloudGuard Pro does not require a login by default (single-user local deployment). When you open the browser, you land directly on the **Dashboard**.

On first launch with `SEED_DEMO_DATA=true`, you will see realistic demo data across all five cloud providers. This lets you explore the UI immediately without connecting real accounts.

> **Screenshot placeholder:** Dashboard with demo data showing findings, charts, and provider breakdown

The left sidebar contains the main navigation:

| Section | What It Does |
|---|---|
| Dashboard | Overview of your security posture |
| Findings | Every security issue found, with full details |
| Assets | Every cloud resource discovered |
| Check Catalog | All 54+ security checks available |
| Connections | Your cloud account connections |
| Scans | Trigger and monitor scans |
| Reports | Generate and download PDF reports |

---

## 7. Connecting AWS

### What you need
An AWS IAM user or role with read-only permissions. We recommend creating a dedicated CloudGuard IAM policy.

### Recommended IAM Policy

Create an IAM policy with the following permissions (or use `SecurityAudit` managed policy):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:Get*", "iam:List*",
      "s3:Get*", "s3:List*",
      "ec2:Describe*",
      "rds:Describe*",
      "cloudtrail:Describe*", "cloudtrail:Get*",
      "kms:Describe*", "kms:List*", "kms:Get*",
      "lambda:List*", "lambda:Get*",
      "eks:Describe*", "eks:List*",
      "ecr:Describe*", "ecr:List*",
      "secretsmanager:List*", "secretsmanager:Describe*",
      "cloudwatch:Describe*", "cloudwatch:List*"
    ],
    "Resource": "*"
  }]
}
```

### Steps

1. In the `.env` file, set:
   ```
   AWS_ACCESS_KEY_ID=your_access_key_here
   AWS_SECRET_ACCESS_KEY=your_secret_key_here
   AWS_DEFAULT_REGION=us-east-1
   ```

2. In the CloudGuard UI, go to **Connections → Add Connection**

3. Fill in:
   - **Name:** Production AWS
   - **Provider:** AWS
   - **AWS Account ID:** Your 12-digit account ID
   - **Credential Type:** `env` (reads from environment variables above)
   - **Regions:** `us-east-1, us-west-2` (or leave blank to scan all regions)

4. Click **Add Connection**

> **Screenshot placeholder:** Connection form filled in for AWS

> **Security note:** Credentials are read from environment variables at scan time. They are never stored in the database.

---

## 8. Connecting Azure

### What you need
An Azure Service Principal with Reader role at the subscription level.

### Creating a Service Principal

In the Azure Portal or via CLI:

```bash
az ad sp create-for-rbac --name "cloudguard-cspm" --role Reader \
  --scopes /subscriptions/YOUR_SUBSCRIPTION_ID --output json
```

This outputs:
```json
{
  "appId": "...",      ← this is AZURE_CLIENT_ID
  "password": "...",   ← this is AZURE_CLIENT_SECRET
  "tenant": "..."      ← this is AZURE_TENANT_ID
}
```

### Steps

1. In `.env`, set:
   ```
   AZURE_TENANT_ID=your-tenant-id
   AZURE_CLIENT_ID=your-app-id
   AZURE_CLIENT_SECRET=your-password
   AZURE_SUBSCRIPTION_ID=your-subscription-id
   ```

2. Go to **Connections → Add Connection**

3. Fill in:
   - **Name:** Azure Production
   - **Provider:** Azure
   - **Subscription ID:** Your Azure subscription ID
   - **Credential Type:** `env`

4. Click **Add Connection**

---

## 9. Connecting GCP

### What you need
A GCP Service Account with `Security Reviewer` role (or `Viewer` + relevant read roles).

### Steps

1. In GCP Console: IAM & Admin → Service Accounts → Create Service Account
2. Grant role: `Security Reviewer` (`roles/iam.securityReviewer`)
3. Create and download a JSON key file
4. In `.env`, set:
   ```
   GOOGLE_APPLICATION_CREDENTIALS=/path/to/your/service-account.json
   GOOGLE_CLOUD_PROJECT=your-project-id
   ```

5. Go to **Connections → Add Connection**

6. Fill in:
   - **Name:** GCP Production
   - **Provider:** GCP
   - **Project ID:** Your GCP project ID
   - **Credential Type:** `file`
   - **Credential Ref:** `/path/to/your/service-account.json`

---

## 10. Connecting IBM Cloud

### What you need
An IBM Cloud API key with Viewer access.

### Steps

1. IBM Cloud Console → Manage → Access (IAM) → API keys → Create
2. In `.env`, set:
   ```
   IBMCLOUD_API_KEY=your_ibm_api_key
   ```

3. Go to **Connections → Add Connection**

4. Fill in:
   - **Name:** IBM Cloud Production
   - **Provider:** IBM
   - **IBM Account ID:** Your IBM account ID
   - **Credential Type:** `env`

---

## 11. Connecting Oracle Cloud (OCI)

### What you need
OCI API credentials configured in `~/.oci/config`.

### Steps

1. OCI Console → Profile → API Keys → Add API Key
2. Follow OCI's instructions to create `~/.oci/config` with your key
3. Go to **Connections → Add Connection**

4. Fill in:
   - **Name:** OCI Tenancy Production
   - **Provider:** OCI
   - **Tenancy OCID:** `ocid1.tenancy.oc1..aaaa...`
   - **Credential Type:** `file`
   - **Credential Ref:** (leave blank to use `~/.oci/config`)

---

## 12. Running Your First Scan

1. Navigate to **Scans** in the left sidebar
2. Under **Launch New Scan**, click the checkboxes for the connections you want to scan
3. Click **Start Scan**

> **Screenshot placeholder:** Scan launch panel with connection checkboxes selected

The scan will appear in the **Scan History** table with status `running`. The table refreshes automatically every 3 seconds.

When complete, the status changes to `completed` and you will see:
- **Assets:** How many cloud resources were discovered
- **Checks:** How many security checks were evaluated
- **New Findings:** New security issues found
- **Resolved:** Issues that no longer exist (auto-resolved)

> **Note:** A scan of a large AWS account with many regions can take 5–20 minutes. The scan runs in the background — you can browse other parts of the UI while it runs.

---

## 13. Reading the Dashboard

The Dashboard gives you an at-a-glance view of your security posture.

### Key Metrics Row
At the top, you see colored stat cards:

| Card | Meaning |
|---|---|
| Open Findings | Total unresolved security issues |
| Critical | Issues requiring immediate action |
| High | Serious issues to fix soon |
| Medium | Issues to plan remediation for |
| Low | Minor improvements |
| Total Assets | Number of cloud resources discovered |
| Checks Loaded | Number of security checks available |

### Charts

- **New Findings — Last 7 Days:** A line chart showing how many new findings were discovered each day. A rising trend means new misconfigurations are being discovered faster than they are fixed.

- **Severity Distribution:** A donut chart showing the proportion of Critical, High, Medium, Low, and Informational findings.

- **Findings by Provider:** A horizontal bar chart showing which cloud (AWS, Azure, GCP, IBM, OCI) has the most open findings.

- **Top Check Families:** Shows which security domains (Identity & Access, Storage, Networking, etc.) have the most issues.

- **Top Services by Findings:** The specific cloud services (s3, ec2, network, etc.) with the most issues.

- **Top Risky Accounts:** The cloud accounts or subscriptions with the most open findings.

> **Screenshot placeholder:** Full dashboard with all charts populated

---

## 14. Browsing Checks by Family

Navigate to **Check Catalog** in the left sidebar.

On the left, you see a panel listing all security check **families** with a count of checks in each:

| Family | Description |
|---|---|
| Identity & Access | IAM, roles, MFA, permissions |
| Storage | Buckets, disks, blob storage |
| Networking | Firewalls, security groups, VPCs |
| Databases | RDS, Cloud SQL, Azure SQL |
| Logging & Monitoring | CloudTrail, audit logs, flow logs |
| Key Management / Secrets | KMS keys, Key Vault, rotation |
| Containers & Kubernetes | EKS, GKE, AKS, ECR |
| Serverless | Lambda, Cloud Functions |
| Governance / Policy | Cloud Guard, Defender, org policies |

Click any family to filter the check table to that category.

You can also filter by:
- **Provider** (AWS, Azure, GCP, IBM, OCI)
- **Severity** (Critical, High, Medium, Low)
- **Search** (type any word to find matching checks)

> **Screenshot placeholder:** Check Catalog with "Identity & Access" family selected showing 8 checks

---

## 15. Inspecting Check Code

Every security check in CloudGuard Pro has full source code and provenance visible in the browser. This is the **"View Check Code"** feature.

### How to use it

1. Go to **Check Catalog**
2. Find any check (e.g., "S3 Bucket Public Access Block Enabled")
3. Click the **Code** button on the right side of the row

A modal window opens with four tabs:

| Tab | What You See |
|---|---|
| **Implementation** | The actual Python function that evaluates the check |
| **YAML Definition** | The check's machine-readable definition including all metadata |
| **Provenance** | Source information: which benchmark, version, URL, license notes |
| **Test Cases** | Input/output test examples proving the check works |

> **Screenshot placeholder:** Code viewer modal showing Python implementation of aws-s3-001

This feature is designed to answer: *"Why is this check here, and what is it actually doing?"*

The **Provenance** tab shows:
- **Source Vendor:** e.g., CIS, AWS, Microsoft
- **Source Product:** e.g., "CIS Amazon Web Services Foundations Benchmark v1.5.0"
- **Source URL:** Direct link to the original documentation
- **License Notes:** Any important licensing information

---

## 16. Reviewing Findings

Navigate to **Findings** in the sidebar.

### Filtering findings

Use the filter bar at the top to narrow results:
- **Search:** Type a keyword (e.g., "S3" or "encryption")
- **Severity:** Filter by Critical, High, Medium, Low
- **Provider:** Filter to one cloud provider
- **Status:** Open, Resolved, Suppressed, Risk Accepted

### Understanding the findings table

Each row shows:
| Column | Meaning |
|---|---|
| Severity | How serious the issue is (Critical = fix immediately) |
| Title | Name of the security check that failed |
| Provider | Which cloud this is in |
| Service | The cloud service (e.g., s3, rds, storage) |
| Resource | The name of the affected cloud resource |
| Status | Open, Resolved, Suppressed |
| First Seen | When CloudGuard first detected this issue |

### Drilling into a finding

Click any row to open the **Finding Detail** panel. This shows:

1. **Resource Identifiers** — The exact cloud-native identifier for the resource:
   - AWS: Amazon Resource Name (ARN), e.g., `arn:aws:s3:::my-bucket`
   - Azure: Full Azure Resource ID, e.g., `/subscriptions/.../storageAccounts/mystorage`
   - GCP: GCP Resource Name, e.g., `//storage.googleapis.com/my-bucket`
   - IBM: Cloud Resource Name (CRN)
   - OCI: Oracle Cloud ID (OCID)
   - All providers: Universal Resource Name (URN) in the format `cspm://provider/account/region/service/type/id`

2. **Description** — What the misconfiguration is and why it matters

3. **Remediation** — Step-by-step instructions to fix the issue

4. **Compliance Frameworks** — Which standards this finding maps to (CIS, NIST, SOC 2, etc.)

5. **Evidence** — The raw data that proved the check failed

> **Screenshot placeholder:** Finding detail panel showing ARN and remediation steps

---

## 17. Understanding Resource Identifiers

CloudGuard Pro shows you the **exact native identifier** for every affected resource, so you can immediately find it in your cloud console.

| Cloud | Identifier Type | Example |
|---|---|---|
| AWS | ARN | `arn:aws:s3:::my-bucket` |
| Azure | Resource ID | `/subscriptions/aaaa-bbbb/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/mystorage` |
| GCP | Resource Name | `//storage.googleapis.com/projects/_/buckets/my-bucket` |
| IBM | CRN | `crn:v1:bluemix:public:cloud-object-storage:global:a/abc123::bucket:my-bucket` |
| OCI | OCID | `ocid1.bucket.oc1.us-ashburn-1.aaaa...` |

CloudGuard also assigns every resource a **Universal Resource Name (URN)**:
```
cspm://provider/account/region/service/resource_type/resource_id
```

Example: `cspm://aws/123456789012/us-east-1/s3/bucket/my-bucket`

This lets you filter and search across all clouds consistently.

---

## 18. Suppressing a Finding

Sometimes a finding is a known exception — you may have a compensating control, or the finding is a deliberate architectural choice.

### How to suppress

1. Open a finding (click the row)
2. Click **Suppress** button in the top-right of the detail panel
3. Enter a reason for suppression
4. Optionally check **Mark as Risk Accepted** for findings where the risk is formally accepted
5. Click **Confirm Suppression**

The finding status changes to **Suppressed** or **Risk Accepted** and it no longer counts in your open findings total.

> **Note:** Suppression is recorded with the timestamp and reason. All suppression actions should be reviewed periodically.

---

## 19. Exporting PDF Reports

Navigate to **Reports** in the sidebar.

### Available report types

| Report | Who it's for | Contents |
|---|---|---|
| **Executive Summary** | Leadership, CISOs, auditors | KPIs, severity breakdown, provider distribution, top findings |
| **Technical Findings** | Security engineers | Full findings list with resource IDs, evidence, remediation |
| **Compliance Report** | Compliance officers | Findings grouped by framework (CIS, NIST, SOC 2) |
| **Asset Inventory** | IT operations | All discovered assets with identifiers |
| **Check Catalog** | Security architects | All 54+ checks with provenance |

### Generating a report

1. Optionally set filters (Provider, Severity) at the top of the Reports page
2. Click **Generate PDF** on your chosen report type
3. The report appears in the **Report History** table with status `generating`
4. When status changes to `completed`, click **Download** to save the PDF

> **Screenshot placeholder:** Reports page with history table showing completed reports

Reports are generated with your organization's branding (CloudGuard Pro / Aniza Corp header). Each page includes the generation timestamp.

---

## 20. Stopping CloudGuard Pro

### Native mode
```bash
./scripts/stop.sh native
```

Or press `Ctrl+C` in the terminal window where the application is running.

### Docker mode
```bash
./scripts/stop.sh docker
```

The application stops but your data (database, reports) is preserved in Docker volumes.

---

## 21. Uninstalling

### Native mode
```bash
./scripts/uninstall.sh native
```

This removes the virtual environment, database, and built frontend. It does **not** delete the source code folder.

### Docker mode
```bash
./scripts/uninstall.sh docker
```

This stops and removes all containers, volumes, and the Docker image.

> **Warning:** Uninstalling removes all your scan data and findings. Export any PDF reports you want to keep before uninstalling.

---

## 22. Troubleshooting

### "Port 8000 is already in use"
Another application is using port 8000. Change the port:
- Edit `.env`: `PORT=8080`
- Restart the application

### "No checks loaded" on the readiness page
The check packs failed to load. Check the logs:
```bash
# Native
./scripts/start.sh native  # check terminal output

# Docker
docker compose logs cspm
```

### "Database not found" error
The database file was deleted or the path is wrong. For SQLite, simply restart — it will be recreated. For PostgreSQL, verify `DATABASE_URL` in `.env`.

### AWS scan returns no results
- Verify `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are set in `.env`
- Ensure the IAM user/role has the required read permissions
- Check that the regions listed in the connection match regions with actual resources

### Azure scan returns no results
- Verify all four `AZURE_*` variables are set correctly
- Confirm the Service Principal has `Reader` role at the subscription scope
- Check the subscription ID matches the one you intended

### PDF report stays in "generating" status
- Check the `REPORTS_DIR` path exists and is writable
- For Docker, ensure the reports volume is mounted: `docker compose logs cspm`
- Verify `reportlab` is installed: `pip show reportlab`

### Frontend shows blank page
- Ensure the frontend was built: `cd frontend && npm run build`
- For Docker, rebuild the image: `docker compose build --no-cache`

---

## 23. Frequently Asked Questions

**Q: Does CloudGuard Pro store my cloud credentials?**  
A: No. Credentials are read from environment variables at scan time and are never written to the database. The `credential_ref` field in a connection stores a reference (like a role ARN or file path), not the secret itself.

**Q: Does CloudGuard Pro make changes to my cloud resources?**  
A: No. All collection is strictly read-only. CloudGuard Pro uses only read/list/describe/get API calls.

**Q: How often should I scan?**  
A: For active environments, daily or on-demand after infrastructure changes. For stable environments, weekly is sufficient.

**Q: Can I run CloudGuard Pro against production accounts?**  
A: Yes, and this is the primary use case. Because it is read-only, there is no risk to production workloads.

**Q: Why do some checks say "partially implemented" or "stubbed"?**  
A: Some checks require access to APIs that need additional SDK libraries installed. The check is registered and documented but will not generate findings until the SDK is installed. See the Configuration Manual for instructions.

**Q: Where are the PDF reports stored?**  
A: In the path set by `REPORTS_DIR` in `.env` (default: `/tmp/cspm_reports`). For Docker, this is inside the `cspm_reports` volume. For production, mount a persistent directory.

**Q: Can I add my own checks?**  
A: Yes. See the Developer Extension Guide for step-by-step instructions on adding custom checks.

**Q: What happens if a resource no longer exists?**  
A: On the next scan, the finding will be automatically resolved (status changes from `open` to `resolved`).

---

## 24. Glossary

| Term | Definition |
|---|---|
| **ARN** | Amazon Resource Name — the globally unique identifier for an AWS resource |
| **Asset** | A cloud resource (e.g., an S3 bucket, a virtual machine, a SQL database) |
| **CSPM** | Cloud Security Posture Management — the practice of continuously monitoring cloud configurations for security risks |
| **Check** | A single security rule that evaluates one aspect of a resource's configuration |
| **Check Family** | A category grouping related checks (e.g., "Storage", "Identity & Access") |
| **CIS** | Center for Internet Security — produces widely-used security benchmarks |
| **CRN** | Cloud Resource Name — IBM Cloud's globally unique resource identifier |
| **Finding** | A security issue discovered by a check (i.e., a check that failed) |
| **FSBP** | AWS Foundational Security Best Practices — AWS Security Hub's built-in standard |
| **Misconfiguration** | A cloud resource setting that deviates from security best practices |
| **OCID** | Oracle Cloud Identifier — OCI's unique resource identifier |
| **Posture** | The overall security configuration state of your cloud environment |
| **Provenance** | The documented source of a security check (which benchmark, vendor, URL) |
| **Remediation** | The steps required to fix a security finding |
| **Scan** | The process of collecting cloud resource configurations and evaluating them |
| **Severity** | How serious a finding is: Critical > High > Medium > Low > Informational |
| **Suppression** | Marking a finding as intentionally accepted or excluded |
| **URN** | Universal Resource Name — CloudGuard Pro's cross-cloud normalized identifier |
