# CloudGuard Pro CSPM — Developer Extension Guide

**Product:** CloudGuard Pro CSPM v1.0.0  
**Company:** Aniza Corp | Shahryar Jahangir  
**Audience:** Security engineers, developers extending the platform

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Adding a New Check](#2-adding-a-new-check)
3. [Check Metadata Reference](#3-check-metadata-reference)
4. [Adding a New Resource Type](#4-adding-a-new-resource-type)
5. [Adding a New Cloud Provider](#5-adding-a-new-cloud-provider)
6. [Adding a New Compliance Framework](#6-adding-a-new-compliance-framework)
7. [Writing Check Tests](#7-writing-check-tests)
8. [Check Provenance Rules](#8-check-provenance-rules)
9. [Frontend Extension](#9-frontend-extension)
10. [Running the Full Test Suite](#10-running-the-full-test-suite)

---

## 1. Architecture Overview

```
cloudguard-pro-cspm/
├── backend/
│   ├── main.py                    # FastAPI application entry point
│   ├── database.py                # DB engine, session factory
│   ├── models/
│   │   ├── models.py              # SQLAlchemy ORM entities
│   │   └── schemas.py             # Pydantic API schemas
│   ├── check_engine/
│   │   └── engine.py              # Registry, CheckMeta, CheckEngine
│   ├── checkpacks/                # Security check implementations
│   │   ├── aws/checks.py
│   │   ├── azure/checks.py
│   │   ├── gcp/checks.py
│   │   └── ibm_oci/checks.py
│   ├── collectors/                # Cloud resource collection
│   │   ├── aws.py
│   │   ├── azure.py
│   │   ├── gcp_ibm_oci.py
│   │   ├── gcp.py
│   │   ├── ibm.py
│   │   └── oci.py
│   ├── api/routes/                # FastAPI route handlers
│   ├── reports/pdf_generator.py   # PDF report generation
│   ├── workers/scan_worker.py     # Scan orchestration
│   └── seed.py                    # Demo data seeder
├── frontend/src/
│   ├── App.tsx                    # Layout + routing
│   ├── pages/                     # Page components
│   └── utils/api.ts               # API client
├── tests/test_suite.py            # Full test suite
├── docs/                          # Documentation
└── scripts/                       # Deployment scripts
```

### Data flow for a scan

```
1. User clicks "Start Scan"
   └─> POST /api/v1/scans
       └─> ScanRun created (status: pending)
           └─> Background task: scan_worker.execute_scan(run_id)

2. scan_worker.execute_scan()
   ├─> Load ProviderConnection from DB
   ├─> Instantiate provider Collector (AWSCollector / AzureCollector / ...)
   ├─> collector.collect(conn) → List[ResourceBundle]
   │     Each bundle: {service, resource_type, items: [...]}
   ├─> For each resource:
   │     ├─> _upsert_asset()             → Asset record
   │     ├─> engine.run_checks_for_resource() → List[CheckResult]
   │     └─> For each failing result:
   │           └─> _upsert_finding()     → Finding record (idempotent)
   └─> Update ScanRun (status: completed, stats)
```

---

## 2. Adding a New Check

This is the most common extension. Adding a check takes approximately 5 minutes.

### Step 1 — Choose the correct checkpack file

| Provider | File |
|---|---|
| AWS | `backend/checkpacks/aws/checks.py` |
| Azure | `backend/checkpacks/azure/checks.py` |
| GCP | `backend/checkpacks/gcp/checks.py` |
| IBM | `backend/checkpacks/ibm_oci/checks.py` |
| OCI | `backend/checkpacks/ibm_oci/checks.py` |

### Step 2 — Write the check function

The function receives a single `resource` dict (the raw API response for that resource type) and returns `(passed: bool, evidence: dict)`.

```python
def _check_my_new_check(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """
    Brief description of what this check evaluates.
    Source: [benchmark name and control ID]
    """
    some_value = resource.get("some_field", False)
    passed = some_value == expected_value
    return passed, {"some_field": some_value, "reason": "explain why if failed"}
```

**Rules:**
- Always return `(bool, dict)`. The dict is the evidence blob stored with the finding.
- Never raise exceptions — return `(True, {"error": "..."})` if the resource lacks expected data.
- Never mutate the resource dict.
- Keep the function pure (no DB calls, no API calls, no side effects).

### Step 3 — Register the check

Immediately after the function, call `register_check`:

```python
register_check(CheckMeta(
    check_id="aws-s3-999",          # MUST be unique across all checks
    name="S3 Bucket My New Check",  # Human-readable name
    family="Storage",               # Must match an existing family or a new one

    # Scope
    provider="aws",
    service="s3",
    resource_type="bucket",         # Must match what the collector emits

    # Severity
    severity="high",                # critical / high / medium / low / informational

    # Content
    description="Explain what misconfiguration this detects and why it matters.",
    remediation="Step-by-step fix instructions for an engineer.",
    rationale="Optional: why this check exists.",
    impact="Optional: what could happen if this is exploited.",

    # Provenance (REQUIRED — do not fabricate)
    source_type="benchmark",         # benchmark / vendor / opensource / internal
    source_vendor="CIS",
    source_product="CIS Amazon Web Services Foundations Benchmark v1.5.0",
    source_url="https://www.cisecurity.org/benchmark/amazon_web_services",
    source_version="1.5.0",
    source_retrieved="2024-01-15",   # ISO date you retrieved/verified this
    license_notes="CIS Benchmark — mapping reference only.",
    normalization_confidence="high", # high / medium / low

    # Status
    status="implemented",           # implemented / partial / stubbed

    # Compliance mappings
    compliance_mappings=[
        {"framework": "CIS AWS 1.5", "control_id": "2.1.7"},
        {"framework": "NIST CSF",    "control_id": "PR.DS-1"},
    ],

    # Test cases (required for CI validation)
    test_cases=[
        {"input": {"some_field": True},  "expected_pass": True},
        {"input": {"some_field": False}, "expected_pass": False},
    ],
    sample_payload={"some_field": False, "BucketName": "example-bucket"},

    logic_explanation="Checks that resource.some_field is True. If False, the resource is misconfigured.",

    # Register the implementation function
    func=_check_my_new_check,
))
```

### Step 4 — Ensure the resource type is collected

Open the collector file for your provider and verify that `service="s3"` and `resource_type="bucket"` are already collected, or add a new collection method (see [Section 4](#4-adding-a-new-resource-type)).

### Step 5 — Write tests

```python
class TestMyNewCheck:
    def test_pass(self):
        from backend.checkpacks.aws.checks import _check_my_new_check
        passed, evidence = _check_my_new_check({"some_field": True})
        assert passed is True

    def test_fail(self):
        from backend.checkpacks.aws.checks import _check_my_new_check
        passed, evidence = _check_my_new_check({"some_field": False})
        assert passed is False

    def test_missing_field_does_not_raise(self):
        from backend.checkpacks.aws.checks import _check_my_new_check
        passed, evidence = _check_my_new_check({})  # empty resource
        assert isinstance(passed, bool)  # must not raise
```

### Step 6 — Verify registration

```bash
PYTHONPATH=. python3 -c "
from backend.check_engine.engine import load_all_checkpacks, _REGISTRY
load_all_checkpacks()
print('aws-s3-999' in _REGISTRY)  # Should print: True
"
```

### Step 7 — Run the test suite

```bash
PYTHONPATH=. pytest tests/test_suite.py -v
```

---

## 3. Check Metadata Reference

Complete reference for all `CheckMeta` fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `check_id` | str | ✅ | Unique ID, format: `{provider}-{service}-{NNN}` |
| `name` | str | ✅ | Human-readable check name |
| `family` | str | ✅ | Check family (see families list below) |
| `provider` | str | ✅ | `aws`, `azure`, `gcp`, `ibm`, `oci` |
| `service` | str | ✅ | Cloud service slug (e.g., `s3`, `iam`, `storage`) |
| `resource_type` | str | ✅ | Resource type slug (e.g., `bucket`, `instance`) |
| `severity` | str | ✅ | `critical`, `high`, `medium`, `low`, `informational` |
| `description` | str | ✅ | What the check detects and why it matters |
| `remediation` | str | ✅ | How to fix it |
| `rationale` | str | — | Why this check exists |
| `impact` | str | — | Business impact if exploited |
| `source_type` | str | ✅ | `benchmark`, `vendor`, `opensource`, `internal` |
| `source_vendor` | str | ✅ | E.g., `CIS`, `AWS`, `Microsoft` |
| `source_product` | str | ✅ | Full benchmark/product name |
| `source_url` | str | ✅ | Direct URL to the source documentation |
| `source_version` | str | ✅ | Version or date of source |
| `source_retrieved` | str | ✅ | ISO date you verified this source |
| `license_notes` | str | — | Any licensing considerations |
| `normalization_confidence` | str | — | `high`, `medium`, `low` |
| `status` | str | ✅ | `implemented`, `partial`, `stubbed`, `deprecated` |
| `enabled` | bool | — | Default `True` |
| `check_type` | str | — | `code`, `declarative`, `graph`, `correlation` |
| `collection_method` | str | — | `api`, `agentless`, `graph`, `correlation` |
| `compliance_mappings` | list | — | `[{"framework": "...", "control_id": "..."}]` |
| `test_cases` | list | — | `[{"input": {...}, "expected_pass": bool}]` |
| `sample_payload` | dict | — | Example resource that triggers this check |
| `logic_explanation` | str | — | Plain-English description of evaluation logic |
| `func` | callable | ✅ | The Python evaluation function |

### Available Families

```
Identity & Access
Networking
Storage
Databases
Compute
Containers & Kubernetes
Serverless
Key Management / Secrets
Logging & Monitoring
Backup & Resilience
Data Protection
AI/ML Services
Messaging & Eventing
API / Edge / WAF / Load Balancing
Governance / Policy / Org Configuration
Vulnerability / Exposure / External Access
Compliance / Benchmark Mapping
```

---

## 4. Adding a New Resource Type

To support a new resource type (e.g., AWS ElastiCache clusters):

### Step 1 — Add collection in the collector

Open `backend/collectors/aws.py` and add a new method:

```python
def _collect_elasticache(self, session, region: str) -> List[Dict]:
    items = []
    try:
        client = session.client("elasticache", region_name=region)
        paginator = client.get_paginator("describe_cache_clusters")
        for page in paginator.paginate():
            for cluster in page["CacheClusters"]:
                cluster["region"] = region
                items.append(cluster)
    except Exception as e:
        log.error("ElastiCache collection error region=%s: %s", region, e)
    return [{"service": "elasticache", "resource_type": "cache_cluster", "items": items}] if items else []
```

### Step 2 — Call it from `collect()`

In the `_do_scan` regional loop:

```python
bundles += self._collect_elasticache(session, region)
```

### Step 3 — Write checks for the new resource type

```python
def _check_elasticache_encryption_in_transit(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    tls = resource.get("TransitEncryptionEnabled", False)
    return tls, {"transit_encryption_enabled": tls}

register_check(CheckMeta(
    check_id="aws-elasticache-001",
    name="ElastiCache Cluster Transit Encryption Enabled",
    family="Databases",
    provider="aws",
    service="elasticache",
    resource_type="cache_cluster",
    severity="high",
    ...
    func=_check_elasticache_encryption_in_transit,
))
```

The scan worker automatically routes resources with `service="elasticache"` and `resource_type="cache_cluster"` to checks with matching `service` and `resource_type` fields.

### Step 4 — Add to the demo seeder (optional)

In `backend/seed.py`, add an entry to `asset_templates` with your new service/resource_type to see it in demo mode.

---

## 5. Adding a New Cloud Provider

To add a new provider (e.g., Alibaba Cloud):

### Step 1 — Add the enum value

In `backend/models/models.py`:

```python
class CloudProvider(str, enum.Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    IBM = "ibm"
    OCI = "oci"
    ALIBABA = "alibaba"   # ← add this
```

### Step 2 — Create the collector

Create `backend/collectors/alibaba.py`:

```python
class AlibabaCollector:
    def collect(self, conn) -> List[Dict[str, Any]]:
        try:
            from alibabacloud_ecs20140526.client import Client
            # ... setup credentials from conn ...
        except ImportError:
            log.warning("aliyun SDK not installed.")
            return []
        bundles = []
        # ... collect resources ...
        return bundles
```

### Step 3 — Create a collector stub module

Create `backend/collectors/alibaba.py` with:
```python
from backend.collectors.alibaba import AlibabaCollector
```

### Step 4 — Register in scan worker

In `backend/workers/scan_worker.py`, add to the `_get_collector` dict:

```python
collectors = {
    "aws":     aws.AWSCollector,
    "azure":   azure.AzureCollector,
    "gcp":     gcp.GCPCollector,
    "ibm":     ibm.IBMCollector,
    "oci":     oci.OCICollector,
    "alibaba": alibaba.AlibabaCollector,  # ← add this
}
```

### Step 5 — Create a checkpack

Create `backend/checkpacks/alibaba/__init__.py` and `backend/checkpacks/alibaba/checks.py` following the same pattern as the existing checkpacks.

### Step 6 — Update the frontend

In `frontend/src/pages/`:
- Add `"alibaba"` to `PROVIDERS` arrays in Findings, Assets, Connections, Checks pages
- Add CSS color: `.provider-alibaba { color: #ff6a00; }` in `index.css`

### Step 7 — Migrate the database

If using PostgreSQL, run an Alembic migration to add the new enum value. For SQLite dev mode, delete `cspm.db` and restart to recreate the schema.

---

## 6. Adding a New Compliance Framework

To add a new framework (e.g., PCI DSS 4.0):

### Step 1 — Add mappings to existing checks

In each relevant check's `compliance_mappings`:

```python
compliance_mappings=[
    {"framework": "CIS AWS 1.5",  "control_id": "2.1.1"},
    {"framework": "PCI DSS 4.0",  "control_id": "3.5.1"},  # ← add this
],
```

### Step 2 — Sync to DB

The seeder and scan worker sync compliance mappings from the registry to the `compliance_controls` and `check_to_control_maps` tables automatically.

### Step 3 — The compliance PDF report

The existing compliance report in `backend/reports/pdf_generator.py` reads `Finding.compliance_frameworks` and groups findings by framework. No additional code is needed — the new framework appears automatically once findings with that mapping exist.

---

## 7. Writing Check Tests

All check tests follow the same pattern. Add them to `tests/test_suite.py`:

```python
class TestMyNewChecks:
    def test_my_check_pass(self):
        from backend.checkpacks.aws.checks import _check_my_new_check
        passed, evidence = _check_my_new_check({"field": "expected_value"})
        assert passed is True
        assert evidence["field"] == "expected_value"

    def test_my_check_fail(self):
        from backend.checkpacks.aws.checks import _check_my_new_check
        passed, evidence = _check_my_new_check({"field": "bad_value"})
        assert passed is False

    def test_my_check_missing_field(self):
        """Check must not raise when fields are missing."""
        from backend.checkpacks.aws.checks import _check_my_new_check
        passed, evidence = _check_my_new_check({})
        assert isinstance(passed, bool)

    def test_my_check_in_registry(self):
        from backend.check_engine.engine import _REGISTRY, load_all_checkpacks
        load_all_checkpacks()
        assert "aws-myservice-001" in _REGISTRY
        meta = _REGISTRY["aws-myservice-001"]
        assert meta.source_url   # provenance required
        assert meta.func          # implementation required
```

### Test coverage requirements

Every new check must have at minimum:
1. One test that proves it returns `True` (passing resource)
2. One test that proves it returns `False` (failing resource)
3. One test that proves it does not raise an exception on an empty resource dict

---

## 8. Check Provenance Rules

**CloudGuard Pro strictly enforces provenance. These rules are non-negotiable:**

### ✅ Acceptable sources

| Source Type | Examples | Requirements |
|---|---|---|
| `benchmark` | CIS Benchmarks, NIST SP 800-53 | Must cite version + URL |
| `vendor` | AWS FSBP, Microsoft MDFC, Google SCC | Must cite product + URL |
| `opensource` | Prowler rules, Steampipe checks | Must cite repo + license |
| `internal` | Aniza Corp custom checks | Must explain rationale |

### ❌ Never do this

```python
# BAD — fabricated check without source
register_check(CheckMeta(
    check_id="aws-s3-999",
    source_vendor="",
    source_url="",
    description="This check is based on general security best practice",  # NOT acceptable
    ...
))
```

### ✅ Always do this

```python
# GOOD — real source with verifiable URL
register_check(CheckMeta(
    check_id="aws-s3-999",
    source_type="benchmark",
    source_vendor="CIS",
    source_product="CIS Amazon Web Services Foundations Benchmark v1.5.0",
    source_url="https://www.cisecurity.org/benchmark/amazon_web_services",
    source_version="1.5.0",
    source_retrieved="2024-01-15",
    license_notes="CIS Benchmark — mapping reference only, not reproduced verbatim.",
    normalization_confidence="high",
    ...
))
```

### Coverage gaps

If a check cannot be fully implemented due to incomplete public documentation, set:
```python
status="partial"
normalization_confidence="low"
description="... NOTE: Full implementation requires access to [proprietary data source]. "
             "Current implementation covers the publicly documented subset only."
```

---

## 9. Frontend Extension

### Adding a new page

1. Create `frontend/src/pages/MyPage.tsx`
2. Add to `App.tsx`:
   ```tsx
   import MyPage from './pages/MyPage'
   // In NAV array:
   { to: '/mypage', label: 'My Page', icon: SomeIcon }
   // In Routes:
   <Route path="/mypage/*" element={<MyPage />} />
   ```
3. Add to `api.ts` any new API calls needed

### Adding a new API endpoint to the frontend

In `frontend/src/utils/api.ts`:

```typescript
export const api = {
  // ... existing methods ...
  myNewEndpoint: (params: Record<string, any>) =>
    request<MyResponseType>(`/my-endpoint?${new URLSearchParams(params)}`),
}
```

### Design system

All styling uses CSS variables defined in `frontend/src/index.css`. Use these variables for consistency:

```css
var(--navy)       /* background */
var(--surface)    /* card background */
var(--border)     /* borders */
var(--text)       /* primary text */
var(--text-2)     /* secondary text */
var(--blue)       /* primary action color */
var(--crit)       /* critical severity */
var(--high)       /* high severity */
var(--med)        /* medium severity */
var(--low)        /* low/success */
```

---

## 10. Running the Full Test Suite

```bash
# Activate virtual environment
source venv/bin/activate

# Install test dependencies
pip install pytest httpx pytest-asyncio

# Run all tests with verbose output
PYTHONPATH=. pytest tests/test_suite.py -v

# Run only check unit tests
PYTHONPATH=. pytest tests/test_suite.py::TestAWSChecks -v
PYTHONPATH=. pytest tests/test_suite.py::TestAzureChecks -v
PYTHONPATH=. pytest tests/test_suite.py::TestGCPChecks -v
PYTHONPATH=. pytest tests/test_suite.py::TestOCIChecks -v

# Run check engine tests
PYTHONPATH=. pytest tests/test_suite.py::TestCheckEngine -v

# Run API tests
PYTHONPATH=. pytest tests/test_suite.py::TestAPI -v

# Run with coverage report
PYTHONPATH=. pytest tests/test_suite.py --cov=backend --cov-report=term-missing

# Lint with ruff
ruff check backend/

# Type check with mypy
mypy backend/ --ignore-missing-imports
```

### Expected test output

```
tests/test_suite.py::TestAWSChecks::test_root_mfa_enabled_pass PASSED
tests/test_suite.py::TestAWSChecks::test_root_mfa_enabled_fail PASSED
tests/test_suite.py::TestAWSChecks::test_s3_public_access_block_pass PASSED
tests/test_suite.py::TestAWSChecks::test_s3_public_access_block_fail PASSED
...
tests/test_suite.py::TestCheckEngine::test_registry_populated PASSED
tests/test_suite.py::TestCheckEngine::test_all_providers_represented PASSED
tests/test_suite.py::TestCheckEngine::test_check_has_required_fields PASSED
...
tests/test_suite.py::TestAPI::test_health_endpoint PASSED
tests/test_suite.py::TestAPI::test_list_checks PASSED
tests/test_suite.py::TestAPI::test_check_code_has_provenance PASSED
...

======= 62 passed in 4.31s =======
```
