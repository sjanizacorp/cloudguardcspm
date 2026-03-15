# cloudguard cspm
Poor mans CSPM

I put this together to help me get a quick understanding of my Cloud Infra .. thought it might come in handy for others as well :)

# DISCLAIMER: This software is provided "as is" and without warranty of any kind, express or implied. In no event shall the author be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software. Any action you take based on this code is strictly at your own risk.

# What you have:

Files forming a CSPM platform:
LayerWhat it does3 Cloud CollectorsDiscovers assets from AWS, Azure, GCP via their real APIs24+ Security ChecksRuns rules against every asset (S3 public access, SG open ports, IAM MFA, RDS encryption, etc.)CIS Compliance EngineMaps findings to CIS Benchmark controls for all 3 cloudsFastAPI Backend5 REST APIs: scan, dashboard, assets, findings, complianceReact Dashboard4 views: posture overview, asset inventory, findings list, compliance table

# How to run it
bash# Unzip/extract the project folder, then:
chmod +x start.sh
./start.sh

OR with Docker:
docker-compose up --build
Open http://localhost:3000 → click "New Scan" → enter your credentials → hit Start Scan.

# What you'll see

Secure Score (0–100 ring chart)
Assets by cloud (bar chart — AWS/Azure/GCP)
Findings by severity (pie chart — critical/high/medium/low)
CIS compliance % with pass/fail breakdown
Click any finding → see full description + remediation guidance

Persistent database — SQLite by default (zero setup), PostgreSQL-ready via DATABASE_URL env var. Scan history survives restarts.
49 security checks (was 24) — new checks covering SSH/RDP open to world, EC2 not in VPC, RDS deletion protection & Multi-AZ, Lambda runtime EOL & secret env vars, Azure VM disk encryption, Azure SQL auditing/TDE, GCP bucket uniform access & logging, GCP VM Shielded VM, GCP default service account.
NIST 800-53 mapping — 18 NIST controls mapped alongside CIS. Both frameworks visible in the Compliance tab with framework filter.
Suppress / Accept Risk — click any finding → add a reason → Suppress or Accept Risk. Suppressed findings are preserved across scans and excluded from scoring.
Scheduled scans — new Schedules tab, cron presets (every 6h, daily, weekly), enable/pause/delete. Schedules reload automatically on restart.
Scan History tab — full table of every scan with score, finding counts, trigger type (manual vs scheduled), timestamp.
Score trend chart — area chart on dashboard showing posture score over time as scans accumulate.
