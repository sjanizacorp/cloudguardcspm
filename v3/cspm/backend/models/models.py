"""
CloudGuard Pro CSPM — Core Data Models
Aniza Corp | Shahryar Jahangir
All entities strongly typed with SQLAlchemy ORM + Pydantic schemas.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Enum, Float, ForeignKey, Index,
    Integer, String, Text, UniqueConstraint, event,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


def _uuid():
    return str(uuid.uuid4())


def _now():
    return datetime.utcnow()


# ─── Enums ─────────────────────────────────────────────────────────────────

class CloudProvider(str, enum.Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    IBM = "ibm"
    OCI = "oci"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class CheckStatus(str, enum.Enum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    STUBBED = "stubbed"
    DEPRECATED = "deprecated"
    EXPERIMENTAL = "experimental"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CheckType(str, enum.Enum):
    DECLARATIVE = "declarative"
    CODE = "code"
    GRAPH = "graph"
    CORRELATION = "correlation"


class CollectionMethod(str, enum.Enum):
    AGENTLESS = "agentless"
    API = "api"
    GRAPH = "graph"
    CORRELATION = "correlation"


# ─── Provider Connections ───────────────────────────────────────────────────

class ProviderConnection(Base):
    __tablename__ = "provider_connections"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    provider = Column(Enum(CloudProvider), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)
    last_scan_at = Column(DateTime, nullable=True)

    # Provider-specific identifiers
    account_id = Column(String(255), nullable=True)        # AWS account ID
    subscription_id = Column(String(255), nullable=True)   # Azure subscription ID
    project_id = Column(String(255), nullable=True)        # GCP project ID
    tenancy_id = Column(String(255), nullable=True)        # OCI tenancy OCID
    ibm_account_id = Column(String(255), nullable=True)    # IBM account ID

    # Encrypted credential blob (JSON, env-ref, or vault path)
    credential_ref = Column(Text, nullable=True)   # path/env var name, NOT raw secret
    credential_type = Column(String(64), nullable=True)  # env, file, iam_role, workload_identity

    # Display / org context
    alias = Column(String(255), nullable=True)
    tags = Column(JSON, default=dict)
    regions = Column(JSON, default=list)   # list of region strings to scan
    notes = Column(Text, nullable=True)

    # Relations
    assets = relationship("Asset", back_populates="connection", cascade="all, delete-orphan")
    scan_runs = relationship("ScanRun", back_populates="connection", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_pc_provider", "provider"),
        Index("ix_pc_enabled", "enabled"),
    )


# ─── Assets ────────────────────────────────────────────────────────────────

class Asset(Base):
    __tablename__ = "assets"

    id = Column(String, primary_key=True, default=_uuid)
    connection_id = Column(String, ForeignKey("provider_connections.id", ondelete="CASCADE"), nullable=False)

    provider = Column(Enum(CloudProvider), nullable=False)
    service = Column(String(128), nullable=False)          # e.g. "s3", "iam", "compute"
    resource_type = Column(String(128), nullable=False)    # e.g. "bucket", "instance"
    region = Column(String(128), nullable=True)

    # Native identifiers
    native_id = Column(Text, nullable=False)               # raw provider-specific ID
    arn = Column(Text, nullable=True)                      # AWS ARN
    azure_resource_id = Column(Text, nullable=True)        # /subscriptions/...
    gcp_resource_name = Column(Text, nullable=True)        # //compute.googleapis.com/...
    ibm_crn = Column(Text, nullable=True)                  # CRN
    oci_ocid = Column(Text, nullable=True)                 # ocid1.instance...

    # Normalized URN for cross-cloud consistency
    universal_resource_name = Column(Text, nullable=False)  # cspm://provider/account/region/service/type/id

    display_name = Column(String(512), nullable=True)
    tags = Column(JSON, default=dict)
    raw_config = Column(JSON, default=dict)               # full provider config snapshot
    config_hash = Column(String(64), nullable=True)       # SHA-256 of raw_config for dedup

    first_seen = Column(DateTime, default=_now)
    last_seen = Column(DateTime, default=_now)
    is_active = Column(Boolean, default=True)

    # Relations
    connection = relationship("ProviderConnection", back_populates="assets")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")
    snapshots = relationship("AssetSnapshot", back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_asset_provider", "provider"),
        Index("ix_asset_service", "service"),
        Index("ix_asset_resource_type", "resource_type"),
        Index("ix_asset_region", "region"),
        Index("ix_asset_connection", "connection_id"),
        Index("ix_asset_native_id", "native_id"),
        UniqueConstraint("connection_id", "universal_resource_name", name="uq_asset_urn"),
    )


class AssetSnapshot(Base):
    __tablename__ = "asset_snapshots"

    id = Column(String, primary_key=True, default=_uuid)
    asset_id = Column(String, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    scan_run_id = Column(String, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=True)
    captured_at = Column(DateTime, default=_now)
    raw_config = Column(JSON, default=dict)
    config_hash = Column(String(64), nullable=True)

    asset = relationship("Asset", back_populates="snapshots")

    __table_args__ = (
        Index("ix_snapshot_asset", "asset_id"),
        Index("ix_snapshot_captured", "captured_at"),
    )


# ─── Check Definitions ─────────────────────────────────────────────────────

class CheckDefinition(Base):
    __tablename__ = "check_definitions"

    id = Column(String, primary_key=True, default=_uuid)  # e.g. "aws-s3-001"
    check_id = Column(String(128), unique=True, nullable=False)

    # Classification
    family = Column(String(128), nullable=False)           # e.g. "Storage"
    provider = Column(Enum(CloudProvider), nullable=False)
    service = Column(String(128), nullable=False)
    resource_type = Column(String(128), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    check_type = Column(Enum(CheckType), default=CheckType.CODE)
    collection_method = Column(Enum(CollectionMethod), default=CollectionMethod.API)

    # Content
    name = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    rationale = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)

    # Source / Provenance
    source_type = Column(String(64), nullable=True)        # vendor, opensource, internal, benchmark
    source_vendor = Column(String(128), nullable=True)     # e.g. "CIS", "AWS", "Wiz"
    source_product = Column(String(128), nullable=True)    # e.g. "AWS Security Hub"
    source_url = Column(Text, nullable=True)
    source_version = Column(String(64), nullable=True)
    source_retrieved = Column(String(32), nullable=True)   # ISO date
    license_notes = Column(Text, nullable=True)
    normalization_confidence = Column(String(32), nullable=True)  # high/medium/low

    # Status
    status = Column(Enum(CheckStatus), default=CheckStatus.IMPLEMENTED)
    enabled = Column(Boolean, default=True)
    tags = Column(JSON, default=list)

    # Implementation code (stored as text for code-view feature)
    implementation_code = Column(Text, nullable=True)
    yaml_definition = Column(Text, nullable=True)
    test_cases = Column(JSON, default=list)
    sample_payload = Column(JSON, default=dict)
    logic_explanation = Column(Text, nullable=True)

    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)

    # Relations
    implementations = relationship("CheckImplementation", back_populates="check_def", cascade="all, delete-orphan")
    compliance_mappings = relationship("CheckToControlMap", back_populates="check_def", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="check_def")

    __table_args__ = (
        Index("ix_check_family", "family"),
        Index("ix_check_provider", "provider"),
        Index("ix_check_severity", "severity"),
        Index("ix_check_service", "service"),
        Index("ix_check_status", "status"),
        Index("ix_check_enabled", "enabled"),
    )


class CheckImplementation(Base):
    __tablename__ = "check_implementations"

    id = Column(String, primary_key=True, default=_uuid)
    check_def_id = Column(String, ForeignKey("check_definitions.id", ondelete="CASCADE"), nullable=False)
    language = Column(String(32), default="python")
    module_path = Column(String(512), nullable=True)
    function_name = Column(String(128), nullable=True)
    code_text = Column(Text, nullable=True)
    version = Column(String(32), nullable=True)
    created_at = Column(DateTime, default=_now)

    check_def = relationship("CheckDefinition", back_populates="implementations")


# ─── Compliance ────────────────────────────────────────────────────────────

class ComplianceControl(Base):
    __tablename__ = "compliance_controls"

    id = Column(String, primary_key=True, default=_uuid)
    framework = Column(String(128), nullable=False)        # e.g. "CIS AWS 1.5", "NIST CSF"
    control_id = Column(String(128), nullable=False)       # e.g. "1.1", "PR.AC-1"
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    section = Column(String(128), nullable=True)
    version = Column(String(64), nullable=True)
    url = Column(Text, nullable=True)

    mappings = relationship("CheckToControlMap", back_populates="control")

    __table_args__ = (
        UniqueConstraint("framework", "control_id", name="uq_control"),
        Index("ix_ctrl_framework", "framework"),
    )


class CheckToControlMap(Base):
    __tablename__ = "check_to_control_maps"

    id = Column(String, primary_key=True, default=_uuid)
    check_def_id = Column(String, ForeignKey("check_definitions.id", ondelete="CASCADE"), nullable=False)
    control_id = Column(String, ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False)
    mapping_type = Column(String(32), default="direct")    # direct, partial, indirect

    check_def = relationship("CheckDefinition", back_populates="compliance_mappings")
    control = relationship("ComplianceControl", back_populates="mappings")


# ─── Scan Jobs / Runs ──────────────────────────────────────────────────────

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String(255), nullable=True)
    connection_ids = Column(JSON, default=list)
    check_families = Column(JSON, default=list)   # empty = all
    regions = Column(JSON, default=list)           # empty = all configured
    scheduled = Column(Boolean, default=False)
    cron_expression = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=_now)
    created_by = Column(String(128), nullable=True)

    runs = relationship("ScanRun", back_populates="job")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(String, primary_key=True, default=_uuid)
    job_id = Column(String, ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)
    connection_id = Column(String, ForeignKey("provider_connections.id", ondelete="CASCADE"), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    assets_discovered = Column(Integer, default=0)
    checks_run = Column(Integer, default=0)
    findings_created = Column(Integer, default=0)
    findings_resolved = Column(Integer, default=0)
    errors = Column(JSON, default=list)
    progress_pct = Column(Float, default=0.0)
    log = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_now)

    job = relationship("ScanJob", back_populates="runs")
    connection = relationship("ProviderConnection", back_populates="scan_runs")

    __table_args__ = (
        Index("ix_run_connection", "connection_id"),
        Index("ix_run_status", "status"),
        Index("ix_run_created", "created_at"),
    )


# ─── Findings ──────────────────────────────────────────────────────────────

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=_uuid)
    finding_id = Column(String(128), unique=True, nullable=False)   # deterministic hash

    # Check reference
    check_def_id = Column(String, ForeignKey("check_definitions.id"), nullable=False)
    check_id = Column(String(128), nullable=False)        # denormalized for speed

    # Asset reference
    asset_id = Column(String, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)

    # Classification
    family = Column(String(128), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN)

    # Content
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)

    # Resource context (denormalized for fast queries)
    provider = Column(Enum(CloudProvider), nullable=False)
    account_context = Column(String(255), nullable=True)  # account/subscription/project/tenancy
    region = Column(String(128), nullable=True)
    service = Column(String(128), nullable=False)
    resource_type = Column(String(128), nullable=False)
    resource_display_name = Column(String(512), nullable=True)
    native_id = Column(Text, nullable=True)
    arn = Column(Text, nullable=True)
    azure_resource_id = Column(Text, nullable=True)
    gcp_resource_name = Column(Text, nullable=True)
    ibm_crn = Column(Text, nullable=True)
    oci_ocid = Column(Text, nullable=True)
    universal_resource_name = Column(Text, nullable=False)

    # Evidence
    evidence = Column(JSON, default=dict)
    raw_evidence_blob = Column(JSON, default=dict)

    # Lifecycle
    first_seen = Column(DateTime, default=_now)
    last_seen = Column(DateTime, default=_now)
    resolved_at = Column(DateTime, nullable=True)

    # Compliance
    compliance_frameworks = Column(JSON, default=list)

    # Owner / tagging
    owner = Column(String(255), nullable=True)
    resource_tags = Column(JSON, default=dict)

    # Suppression
    suppressed_by = Column(String(128), nullable=True)
    suppressed_at = Column(DateTime, nullable=True)
    suppression_reason = Column(Text, nullable=True)
    suppression_expires_at = Column(DateTime, nullable=True)

    # Source provenance
    source_vendor = Column(String(128), nullable=True)
    code_reference = Column(String(512), nullable=True)

    # Relations
    check_def = relationship("CheckDefinition", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")

    __table_args__ = (
        Index("ix_finding_check", "check_id"),
        Index("ix_finding_severity", "severity"),
        Index("ix_finding_status", "status"),
        Index("ix_finding_provider", "provider"),
        Index("ix_finding_service", "service"),
        Index("ix_finding_family", "family"),
        Index("ix_finding_asset", "asset_id"),
        Index("ix_finding_first_seen", "first_seen"),
    )


# ─── Reports ───────────────────────────────────────────────────────────────

class ReportRequest(Base):
    __tablename__ = "report_requests"

    id = Column(String, primary_key=True, default=_uuid)
    report_type = Column(String(64), nullable=False)  # executive, technical, compliance, inventory, catalog
    filters = Column(JSON, default=dict)
    status = Column(String(32), default="pending")
    created_at = Column(DateTime, default=_now)
    completed_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)

    artifact = relationship("ReportArtifact", back_populates="request", uselist=False)


class ReportArtifact(Base):
    __tablename__ = "report_artifacts"

    id = Column(String, primary_key=True, default=_uuid)
    request_id = Column(String, ForeignKey("report_requests.id", ondelete="CASCADE"), nullable=False)
    file_path = Column(Text, nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    mime_type = Column(String(64), default="application/pdf")
    created_at = Column(DateTime, default=_now)

    request = relationship("ReportRequest", back_populates="artifact")


# ─── Suppression / Risk Acceptance ─────────────────────────────────────────

class Suppression(Base):
    __tablename__ = "suppressions"

    id = Column(String, primary_key=True, default=_uuid)
    check_id = Column(String(128), nullable=True)
    universal_resource_name = Column(Text, nullable=True)
    reason = Column(Text, nullable=False)
    suppressed_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=_now)
    expires_at = Column(DateTime, nullable=True)
    risk_accepted = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
