"""
CloudGuard Pro CSPM v3 — API Routes: Assets (with sorting)
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import asc, desc

from backend.database import get_db
from backend.models.models import Asset
from backend.models.schemas import AssetOut, PaginatedResponse

router = APIRouter()

SORT_FIELDS = {
    "provider":       Asset.provider,
    "service":        Asset.service,
    "resource_type":  Asset.resource_type,
    "region":         Asset.region,
    "display_name":   Asset.display_name,
    "first_seen":     Asset.first_seen,
    "last_seen":      Asset.last_seen,
}


@router.get("/assets", response_model=PaginatedResponse)
def list_assets(
    page:          int           = Query(1, ge=1),
    page_size:     int           = Query(50, ge=1, le=500),
    provider:      Optional[str] = None,
    service:       Optional[str] = None,
    resource_type: Optional[str] = None,
    region:        Optional[str] = None,
    search:        Optional[str] = None,
    sort_by:       Optional[str] = Query("last_seen"),
    sort_dir:      Optional[str] = Query("desc"),
    hide_demo:     bool          = Query(False),
    db: Session = Depends(get_db),
):
    q = db.query(Asset)
    if provider:
        q = q.filter(Asset.provider == provider)
    if service:
        q = q.filter(Asset.service == service)
    if resource_type:
        q = q.filter(Asset.resource_type == resource_type)
    if region:
        q = q.filter(Asset.region == region)
    if search:
        q = q.filter(
            Asset.display_name.ilike(f"%{search}%") |
            Asset.native_id.ilike(f"%{search}%") |
            Asset.universal_resource_name.ilike(f"%{search}%")
        )
    if hide_demo:
        from backend.models.models import ProviderConnection
        demo_conn_ids = [c.id for c in db.query(ProviderConnection).filter(
            ProviderConnection.id.like('demo-%')
        ).all()]
        if demo_conn_ids:
            q = q.filter(~Asset.connection_id.in_(demo_conn_ids))

    total = q.count()
    sort_col = SORT_FIELDS.get(sort_by, Asset.last_seen)
    direction = asc if sort_dir == "asc" else desc
    q = q.order_by(direction(sort_col))
    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [AssetOut.from_orm(a) for a in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


@router.get("/assets/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: str, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Asset not found")
    return AssetOut.from_orm(a)


@router.get("/assets/{asset_id}/findings")
def get_asset_findings(asset_id: str, db: Session = Depends(get_db)):
    from backend.models.models import Finding
    from backend.models.schemas import FindingOut
    findings = db.query(Finding).filter(Finding.asset_id == asset_id).all()
    return [FindingOut.from_orm(f) for f in findings]
