"""
CloudGuard Pro CSPM — Pydantic Schemas
Aniza Corp | Shahryar Jahangir
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.models.models import (
    CheckStatus, CheckType, CloudProvider, CollectionMethod,
    FindingStatus, ScanStatus, Severity,
)


class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    pages: int


# ─── Provider Connections ───────────────────────────────────────────────────

class ProviderConnectionCreate(BaseModel):
    name: str
    provider: CloudProvider
    alias: Optional[str] = None
    account_id: Optional[str] = None
    subscription_id: Optional[str] = None
    project_id: Optional[str] = None
    tenancy_id: Optional[str] = None
    ibm_account_id: Optional[str] = None
    credential_ref: Optional[str] = None
    credential_type: Optional[str] = None
    regions: List[str] = []
    tags: Dict[str, str] = {}
    notes: Optional[str] = None


class ProviderConnectionOut(BaseModel):
    id: str
    name: str
    provider: CloudProvider
    enabled: bool
    alias: Optional[str]
    account_id: Optional[str]
    subscription_id: Optional[str]
    project_id: Optional[str]
    tenancy_id: Optional[str]
    ibm_account_id: Optional[str]
    credential_type: Optional[str]
    regions: List[str]
    tags: Dict[str, Any]
    notes: Optional[str]
    created_at: datetime
    last_scan_at: Optional[datetime]

    class Config:
        from_attributes = True
        use_enum_values = True


# ─── Assets ────────────────────────────────────────────────────────────────

class AssetOut(BaseModel):
    id: str
    connection_id: str
    provider: CloudProvider
    service: str
    resource_type: str
    region: Optional[str]
    native_id: str
    arn: Optional[str]
    azure_resource_id: Optional[str]
    gcp_resource_name: Optional[str]
    ibm_crn: Optional[str]
    oci_ocid: Optional[str]
    universal_resource_name: str
    display_name: Optional[str]
    tags: Dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    is_active: bool

    class Config:
        from_attributes = True
        use_enum_values = True


# ─── Check Definitions ─────────────────────────────────────────────────────

class CheckDefinitionOut(BaseModel):
    id: str
    check_id: str
    family: str
    provider: CloudProvider
    service: str
    resource_type: str
    severity: Severity
    check_type: CheckType
    collection_method: CollectionMethod
    name: str
    description: str
    remediation: str
    rationale: Optional[str]
    impact: Optional[str]
    source_type: Optional[str]
    source_vendor: Optional[str]
    source_product: Optional[str]
    source_url: Optional[str]
    source_version: Optional[str]
    source_retrieved: Optional[str]
    license_notes: Optional[str]
    normalization_confidence: Optional[str]
    status: CheckStatus
    enabled: bool
    tags: Any = {}          # stored as dict in DB, serialise as-is
    logic_explanation: Optional[str]
    compliance_frameworks: Any = []   # stored as list or None
    created_at: datetime

    class Config:
        from_attributes = True
        use_enum_values = True


class CheckCodeOut(BaseModel):
    check_id: str
    name: str
    yaml_definition: Optional[str]
    implementation_code: Optional[str]
    test_cases: List[Any]
    sample_payload: Dict[str, Any]
    logic_explanation: Optional[str]
    source_vendor: Optional[str]
    source_url: Optional[str]
    license_notes: Optional[str]


# ─── Findings ──────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: str
    finding_id: str
    check_id: str
    family: str
    severity: Severity
    status: FindingStatus
    title: str
    description: str
    remediation: str
    provider: CloudProvider
    account_context: Optional[str]
    region: Optional[str]
    service: str
    resource_type: str
    resource_display_name: Optional[str]
    native_id: Optional[str]
    arn: Optional[str]
    azure_resource_id: Optional[str]
    gcp_resource_name: Optional[str]
    ibm_crn: Optional[str]
    oci_ocid: Optional[str]
    universal_resource_name: str
    evidence: Any = {}
    first_seen: datetime
    last_seen: datetime
    resolved_at: Optional[datetime]
    compliance_frameworks: Any = []
    owner: Optional[str]
    resource_tags: Any = {}
    suppressed_by: Optional[str]
    suppression_reason: Optional[str]
    source_vendor: Optional[str]

    class Config:
        from_attributes = True
        use_enum_values = True


class FindingSuppress(BaseModel):
    reason: str
    suppressed_by: str
    risk_accepted: bool = False
    expires_at: Optional[datetime] = None


# ─── Scans ─────────────────────────────────────────────────────────────────

class ScanJobCreate(BaseModel):
    name: Optional[str] = None
    connection_ids: List[str]
    check_families: List[str] = []
    regions: List[str] = []


class ScanRunOut(BaseModel):
    id: str
    connection_id: str
    status: ScanStatus
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    assets_discovered: int
    checks_run: int
    findings_created: int
    findings_resolved: int
    errors: List[Any]
    progress_pct: float
    created_at: datetime

    class Config:
        from_attributes = True
        use_enum_values = True


# ─── Reports ───────────────────────────────────────────────────────────────

class ReportRequestCreate(BaseModel):
    report_type: str = Field(..., pattern="^(executive|technical|compliance|inventory|catalog)$")
    filters: Dict[str, Any] = {}


class ReportRequestOut(BaseModel):
    id: str
    report_type: str
    filters: Dict[str, Any]
    status: str
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True
        use_enum_values = True


# ─── Dashboard Stats ────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_findings: int
    open_findings: int
    critical: int
    high: int
    medium: int
    low: int
    informational: int
    total_assets: int
    total_checks: int
    providers: Dict[str, int]
    families: Dict[str, int]
    top_services: List[Dict[str, Any]]
    top_risky_accounts: List[Dict[str, Any]]
    trend_7d: List[Dict[str, Any]]
    compliance_summary: Dict[str, Any]
