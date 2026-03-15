from fastapi import APIRouter, Query, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.database import get_db
from app.models.db_models import Finding
from datetime import datetime

router = APIRouter()


@router.get("")
async def list_findings(
    severity: Optional[str] = None,
    cloud: Optional[str] = None,
    resource_type: Optional[str] = None,
    status: Optional[str] = "active",
    search: Optional[str] = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    q = db.query(Finding)
    if severity:
        q = q.filter(Finding.severity == severity)
    if cloud:
        q = q.filter(Finding.cloud_provider == cloud)
    if resource_type:
        q = q.filter(Finding.resource_type == resource_type)
    if status:
        q = q.filter(Finding.status == status)
    if search:
        s = f"%{search}%"
        q = q.filter(Finding.title.ilike(s) | Finding.resource_id.ilike(s))

    total = q.count()
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = q.offset(offset).limit(limit).all()
    findings_sorted = sorted(findings, key=lambda f: sev_order.get(f.severity, 5))

    return {
        "total": total,
        "findings": [_finding_dict(f) for f in findings_sorted]
    }


@router.get("/{finding_id}")
async def get_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.query(Finding).filter_by(id=finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    return _finding_dict(f)


class SuppressRequest(BaseModel):
    reason: str
    suppressed_by: Optional[str] = "user"


@router.post("/{finding_id}/suppress")
async def suppress_finding(finding_id: str, body: SuppressRequest, db: Session = Depends(get_db)):
    f = db.query(Finding).filter_by(id=finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    f.status = "suppressed"
    f.suppressed_reason = body.reason
    f.suppressed_by = body.suppressed_by
    f.suppressed_at = datetime.utcnow()
    db.commit()
    return {"status": "suppressed", "finding_id": finding_id}


@router.post("/{finding_id}/accept")
async def accept_risk(finding_id: str, body: SuppressRequest, db: Session = Depends(get_db)):
    f = db.query(Finding).filter_by(id=finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    f.status = "accepted"
    f.suppressed_reason = body.reason
    f.suppressed_by = body.suppressed_by
    f.suppressed_at = datetime.utcnow()
    db.commit()
    return {"status": "accepted", "finding_id": finding_id}


@router.post("/{finding_id}/reopen")
async def reopen_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.query(Finding).filter_by(id=finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    f.status = "active"
    f.suppressed_reason = None
    f.suppressed_by = None
    f.suppressed_at = None
    db.commit()
    return {"status": "active", "finding_id": finding_id}


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id, "asset_id": f.asset_id, "cloud_provider": f.cloud_provider,
        "check_id": f.check_id, "title": f.title, "description": f.description,
        "severity": f.severity, "status": f.status,
        "suppressed_reason": f.suppressed_reason, "suppressed_by": f.suppressed_by,
        "suppressed_at": f.suppressed_at.isoformat() if f.suppressed_at else None,
        "remediation": f.remediation, "cis_controls": f.cis_controls or [],
        "nist_controls": f.nist_controls or [], "resource_type": f.resource_type,
        "resource_id": f.resource_id, "region": f.region, "account_id": f.account_id,
        "properties": f.properties or {},
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        "scan_id": f.scan_id,
    }
