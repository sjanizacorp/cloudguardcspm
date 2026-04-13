"""
CloudGuard Pro CSPM — API Routes: Connections
Aniza Corp | Shahryar Jahangir
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.models import ProviderConnection
from backend.models.schemas import ProviderConnectionCreate, ProviderConnectionOut, PaginatedResponse

router = APIRouter()


@router.get("/connections", response_model=PaginatedResponse)
def list_connections(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    provider: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(ProviderConnection)
    if provider:
        q = q.filter(ProviderConnection.provider == provider)
    total = q.count()
    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [ProviderConnectionOut.from_orm(c) for c in items],
        "total": total, "page": page, "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


@router.post("/connections", response_model=ProviderConnectionOut)
def create_connection(body: ProviderConnectionCreate, db: Session = Depends(get_db)):
    conn = ProviderConnection(**body.dict())
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return ProviderConnectionOut.from_orm(conn)


@router.get("/connections/{conn_id}", response_model=ProviderConnectionOut)
def get_connection(conn_id: str, db: Session = Depends(get_db)):
    c = db.query(ProviderConnection).filter(ProviderConnection.id == conn_id).first()
    if not c:
        raise HTTPException(404, "Connection not found")
    return ProviderConnectionOut.from_orm(c)


@router.put("/connections/{conn_id}", response_model=ProviderConnectionOut)
def update_connection(conn_id: str, body: dict, db: Session = Depends(get_db)):
    """Update an existing connection — all fields are optional."""
    c = db.query(ProviderConnection).filter(ProviderConnection.id == conn_id).first()
    if not c:
        raise HTTPException(404, "Connection not found")

    # Fields that can be updated
    updatable = [
        "name", "alias", "enabled", "notes",
        "credential_type", "credential_ref",
        "regions", "tags",
        "account_id", "subscription_id", "project_id",
        "tenancy_id", "ibm_account_id",
    ]
    for field in updatable:
        if field in body:
            setattr(c, field, body[field])

    c.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(c)
    return ProviderConnectionOut.from_orm(c)


@router.delete("/connections/{conn_id}")
def delete_connection(conn_id: str, db: Session = Depends(get_db)):
    c = db.query(ProviderConnection).filter(ProviderConnection.id == conn_id).first()
    if not c:
        raise HTTPException(404, "Connection not found")
    db.delete(c)
    db.commit()
    return {"status": "deleted"}
