"""
CloudGuard Pro CSPM v3 — API Routes: Findings
Aniza Corp | Shahryar Jahangir
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, asc, desc

from backend.database import get_db
from backend.models.models import Finding, FindingStatus, Severity, CloudProvider
from backend.models.schemas import FindingOut, PaginatedResponse, FindingSuppress

router = APIRouter()

# Columns that are sortable
SORT_FIELDS = {
    "severity":    Finding.severity,
    "title":       Finding.title,
    "provider":    Finding.provider,
    "service":     Finding.service,
    "family":      Finding.family,
    "status":      Finding.status,
    "first_seen":  Finding.first_seen,
    "last_seen":   Finding.last_seen,
    "check_id":    Finding.check_id,
    "resource_display_name": Finding.resource_display_name,
    "account_context": Finding.account_context,
    "region":      Finding.region,
}

# Severity ordering for sorting
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


@router.get("/findings", response_model=PaginatedResponse)
def list_findings(
    page:        int            = Query(1, ge=1),
    page_size:   int            = Query(50, ge=1, le=500),
    provider:    Optional[str]  = None,
    severity:    Optional[str]  = None,
    status:      Optional[str]  = None,
    family:      Optional[str]  = None,
    service:     Optional[str]  = None,
    search:      Optional[str]  = None,
    sort_by:     Optional[str]  = Query("first_seen", description="Column to sort by"),
    sort_dir:    Optional[str]  = Query("desc", description="asc or desc"),
    hide_demo:   bool           = Query(False, description="Hide findings from demo connections"),
    db: Session = Depends(get_db),
):
    q = db.query(Finding)

    # Filters
    if provider:
        q = q.filter(Finding.provider == provider)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    if family:
        q = q.filter(Finding.family.ilike(f"%{family}%"))
    if service:
        q = q.filter(Finding.service == service)
    if search:
        q = q.filter(
            Finding.title.ilike(f"%{search}%") |
            Finding.check_id.ilike(f"%{search}%") |
            Finding.resource_display_name.ilike(f"%{search}%") |
            Finding.universal_resource_name.ilike(f"%{search}%")
        )
    if hide_demo:
        # Exclude findings from demo-prefixed connections
        from backend.models.models import Asset
        demo_asset_ids = db.query(Asset.id).join(
            __import__('backend.models.models', fromlist=['ProviderConnection']).ProviderConnection,
            Asset.connection_id == __import__('backend.models.models', fromlist=['ProviderConnection']).ProviderConnection.id
        ).filter(
            __import__('backend.models.models', fromlist=['ProviderConnection']).ProviderConnection.id.like('demo-%')
        ).subquery()
        q = q.filter(~Finding.asset_id.in_(demo_asset_ids))

    total = q.count()

    # Sorting
    sort_col = SORT_FIELDS.get(sort_by, Finding.first_seen)
    direction = asc if sort_dir == "asc" else desc
    q = q.order_by(direction(sort_col))

    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [FindingOut.from_orm(f) for f in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    return FindingOut.from_orm(f)


@router.post("/findings/{finding_id}/suppress")
def suppress_finding(finding_id: str, body: FindingSuppress, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    f.status = FindingStatus.RISK_ACCEPTED if body.risk_accepted else FindingStatus.SUPPRESSED
    f.suppressed_by = body.suppressed_by
    f.suppression_reason = body.reason
    f.suppressed_at = datetime.utcnow()
    f.suppression_expires_at = body.expires_at
    db.commit()
    return {"status": "ok"}


@router.post("/findings/bulk-suppress")
def bulk_suppress(
    body: dict,
    db: Session = Depends(get_db),
):
    """Suppress all demo findings (hide_demo mode)."""
    filter_type = body.get("filter_type", "demo")
    if filter_type == "demo":
        from backend.models.models import ProviderConnection, Asset
        demo_conn_ids = [c.id for c in db.query(ProviderConnection).filter(
            ProviderConnection.id.like('demo-%')
        ).all()]
        if demo_conn_ids:
            demo_asset_ids = [a.id for a in db.query(Asset).filter(
                Asset.connection_id.in_(demo_conn_ids)
            ).all()]
            count = db.query(Finding).filter(
                Finding.asset_id.in_(demo_asset_ids),
                Finding.status == FindingStatus.OPEN,
            ).update(
                {"status": FindingStatus.SUPPRESSED,
                 "suppressed_by": "system",
                 "suppression_reason": "Hidden: demo data suppressed by user"},
                synchronize_session=False,
            )
            db.commit()
            return {"suppressed": count}
    return {"suppressed": 0}


@router.get("/findings/stats/severity-breakdown")
def severity_breakdown(db: Session = Depends(get_db)):
    results = db.query(Finding.severity, func.count(Finding.id)).filter(
        Finding.status == FindingStatus.OPEN
    ).group_by(Finding.severity).all()
    return {row[0]: row[1] for row in results}
