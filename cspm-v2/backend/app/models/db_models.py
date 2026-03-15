from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, Boolean, Text, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

Base = declarative_base()


class Asset(Base):
    __tablename__ = "assets"
    id = Column(String, primary_key=True)
    cloud_provider = Column(String, nullable=False, index=True)
    account_id = Column(String, nullable=False, index=True)
    region = Column(String, index=True)
    resource_type = Column(String, nullable=False, index=True)
    resource_id = Column(String, nullable=False)
    name = Column(String)
    tags = Column(JSON, default={})
    properties = Column(JSON, default={})
    is_public = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    last_scanned = Column(DateTime)
    scan_id = Column(String, ForeignKey("scan_history.id"), index=True)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True)
    asset_id = Column(String, nullable=False, index=True)
    cloud_provider = Column(String, nullable=False, index=True)
    check_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String, nullable=False, index=True)
    status = Column(String, default="active", index=True)
    suppressed_reason = Column(Text)
    suppressed_by = Column(String)
    suppressed_at = Column(DateTime)
    remediation = Column(Text)
    cis_controls = Column(JSON, default=[])
    nist_controls = Column(JSON, default=[])
    resource_type = Column(String, index=True)
    resource_id = Column(String)
    region = Column(String)
    account_id = Column(String)
    properties = Column(JSON, default={})
    first_seen = Column(DateTime, server_default=func.now())
    last_seen = Column(DateTime, server_default=func.now())
    scan_id = Column(String, ForeignKey("scan_history.id"), index=True)


class ComplianceResult(Base):
    __tablename__ = "compliance_results"
    id = Column(String, primary_key=True)
    framework = Column(String, nullable=False, index=True)
    control_id = Column(String, nullable=False)
    control_title = Column(String)
    section = Column(String)
    status = Column(String, index=True)
    cloud_provider = Column(String, index=True)
    finding_ids = Column(JSON, default=[])
    last_evaluated = Column(DateTime, server_default=func.now())
    scan_id = Column(String, ForeignKey("scan_history.id"), index=True)


class ScanHistory(Base):
    __tablename__ = "scan_history"
    id = Column(String, primary_key=True)
    cloud_providers = Column(JSON)
    started_at = Column(DateTime, server_default=func.now(), index=True)
    completed_at = Column(DateTime)
    status = Column(String, default="running", index=True)
    assets_discovered = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    secure_score = Column(Float)
    triggered_by = Column(String, default="manual")
    error = Column(Text)
    config_snapshot = Column(JSON)


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    cron_expression = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    cloud_config = Column(JSON, nullable=False)
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())
    run_count = Column(Integer, default=0)


class CloudCredential(Base):
    __tablename__ = "cloud_credentials"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    cloud_provider = Column(String, nullable=False, index=True)
    config = Column(JSON, nullable=False)
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())
