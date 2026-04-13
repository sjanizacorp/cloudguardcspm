"""
CloudGuard Pro CSPM — Health / Readiness
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.database import get_db
from backend.check_engine.engine import _REGISTRY

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok", "service": "CloudGuard Pro CSPM"}


@router.get("/health/ready")
def readiness(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "status": "ready" if db_ok else "not_ready",
        "database": "ok" if db_ok else "error",
        "checks_loaded": len(_REGISTRY),
    }


@router.get("/health/metrics")
def metrics(db: Session = Depends(get_db)):
    from backend.models.models import Finding, Asset, ProviderConnection, ScanRun
    return {
        "findings": db.query(Finding).count(),
        "assets": db.query(Asset).count(),
        "connections": db.query(ProviderConnection).count(),
        "scan_runs": db.query(ScanRun).count(),
        "checks_registered": len(_REGISTRY),
    }
