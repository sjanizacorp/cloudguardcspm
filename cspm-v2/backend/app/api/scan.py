from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from app.models.database import get_db
from app.models.db_models import ScanHistory
from app.scan_orchestrator import ScanOrchestrator
import uuid

router = APIRouter()


class AWSConfig(BaseModel):
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    session_token: Optional[str] = None
    regions: Optional[List[str]] = None

class AzureConfig(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str

class GCPConfig(BaseModel):
    project_id: str
    credentials_json: Optional[Dict] = None

class ScanRequest(BaseModel):
    aws: Optional[AWSConfig] = None
    azure: Optional[AzureConfig] = None
    gcp: Optional[GCPConfig] = None


def _do_scan(config: dict, db: Session):
    try:
        orchestrator = ScanOrchestrator(db)
        orchestrator.run_scan(config)
    except Exception as e:
        # Mark any running scan as failed
        running = db.query(ScanHistory).filter_by(status="running").first()
        if running:
            running.status = "failed"
            running.error = str(e)
            db.commit()
    finally:
        db.close()


@router.post("/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not any([request.aws, request.azure, request.gcp]):
        raise HTTPException(400, "At least one cloud provider must be configured")

    config = {}
    if request.aws:
        config["aws"] = {k: v for k, v in request.aws.dict().items() if v}
    if request.azure:
        config["azure"] = request.azure.dict()
    if request.gcp:
        config["gcp"] = {k: v for k, v in request.gcp.dict().items() if v}

    from app.models.database import SessionLocal
    background_tasks.add_task(_do_scan, config, SessionLocal())
    return {"status": "started", "message": "Scan is running in the background"}


@router.get("/status/latest")
async def get_latest_scan_status(db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).order_by(ScanHistory.started_at.desc()).first()
    if not scan:
        return {"status": "no_scans"}
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "assets_count": scan.assets_discovered or 0,
        "findings_count": scan.findings_count or 0,
        "secure_score": scan.secure_score,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "triggered_by": scan.triggered_by,
        "error": scan.error,
    }


@router.get("/history")
async def get_scan_history(limit: int = 20, db: Session = Depends(get_db)):
    scans = db.query(ScanHistory).order_by(ScanHistory.started_at.desc()).limit(limit).all()
    return [{
        "scan_id": s.id,
        "status": s.status,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "assets_discovered": s.assets_discovered,
        "findings_count": s.findings_count,
        "critical_count": s.critical_count,
        "high_count": s.high_count,
        "secure_score": s.secure_score,
        "triggered_by": s.triggered_by,
        "cloud_providers": s.cloud_providers,
    } for s in scans]
