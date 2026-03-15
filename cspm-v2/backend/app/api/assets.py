from fastapi import APIRouter, Query, HTTPException, Depends
from typing import Optional
from sqlalchemy.orm import Session
from app.models.database import get_db
from app.models.db_models import Asset

router = APIRouter()


@router.get("")
async def list_assets(
    cloud: Optional[str] = None,
    resource_type: Optional[str] = None,
    is_public: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    q = db.query(Asset)
    if cloud:
        q = q.filter(Asset.cloud_provider == cloud)
    if resource_type:
        q = q.filter(Asset.resource_type == resource_type)
    if is_public is not None:
        q = q.filter(Asset.is_public == is_public)
    if search:
        s = f"%{search}%"
        q = q.filter(Asset.name.ilike(s) | Asset.resource_id.ilike(s))
    total = q.count()
    assets = q.offset(offset).limit(limit).all()
    return {
        "total": total,
        "assets": [_asset_dict(a) for a in assets],
        "offset": offset, "limit": limit
    }


@router.get("/types")
async def get_resource_types(db: Session = Depends(get_db)):
    from sqlalchemy import func
    rows = db.query(Asset.cloud_provider, Asset.resource_type, func.count().label("count"))\
             .group_by(Asset.cloud_provider, Asset.resource_type).all()
    return [{"cloud_provider": r[0], "resource_type": r[1], "count": r[2]} for r in rows]


@router.get("/{asset_id}")
async def get_asset(asset_id: str, db: Session = Depends(get_db)):
    a = db.query(Asset).filter_by(id=asset_id).first()
    if not a:
        raise HTTPException(404, "Asset not found")
    return _asset_dict(a)


def _asset_dict(a: Asset) -> dict:
    return {
        "id": a.id, "cloud_provider": a.cloud_provider, "account_id": a.account_id,
        "region": a.region, "resource_type": a.resource_type, "resource_id": a.resource_id,
        "name": a.name, "tags": a.tags or {}, "properties": a.properties or {},
        "is_public": a.is_public,
        "last_scanned": a.last_scanned.isoformat() if a.last_scanned else None,
        "scan_id": a.scan_id,
    }
