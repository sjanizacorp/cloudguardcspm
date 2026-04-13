"""
CloudGuard Pro CSPM — API Routes: Scans
"""
import asyncio
import logging
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.models import ScanJob, ScanRun, ProviderConnection, ScanStatus
from backend.models.schemas import ScanJobCreate, ScanRunOut, PaginatedResponse

log = logging.getLogger(__name__)
router = APIRouter()


@router.post("/scans", response_model=ScanRunOut)
def start_scan(
    body: ScanJobCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Kick off a scan job for one or more provider connections."""
    job = ScanJob(
        name=body.name or "ad-hoc scan",
        connection_ids=body.connection_ids,
        check_families=body.check_families,
        regions=body.regions,
    )
    db.add(job)
    db.flush()

    runs = []
    for conn_id in body.connection_ids:
        conn = db.query(ProviderConnection).filter(ProviderConnection.id == conn_id).first()
        if not conn:
            raise HTTPException(404, f"Connection {conn_id} not found")
        run = ScanRun(job_id=job.id, connection_id=conn_id)
        db.add(run)
        db.flush()
        runs.append(run.id)

    db.commit()

    # Launch background worker for each run
    for run_id in runs:
        background_tasks.add_task(_run_scan_worker, run_id)

    # Return first run for simplicity; multi-connection returns first
    first_run = db.query(ScanRun).filter(ScanRun.id == runs[0]).first()
    return ScanRunOut.from_orm(first_run)


@router.get("/scans", response_model=PaginatedResponse)
def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    connection_id: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(ScanRun)
    if connection_id:
        q = q.filter(ScanRun.connection_id == connection_id)
    if status:
        q = q.filter(ScanRun.status == status)
    total = q.count()
    items = q.order_by(ScanRun.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [ScanRunOut.from_orm(r) for r in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


@router.get("/scans/{run_id}", response_model=ScanRunOut)
def get_scan(run_id: str, db: Session = Depends(get_db)):
    r = db.query(ScanRun).filter(ScanRun.id == run_id).first()
    if not r:
        raise HTTPException(404, "Scan run not found")
    return ScanRunOut.from_orm(r)


def _run_scan_worker(run_id: str):
    """Background task: imports and runs the scan worker."""
    try:
        from backend.workers.scan_worker import execute_scan
        execute_scan(run_id)
    except Exception as e:
        log.error("Scan worker error for run %s: %s", run_id, e)
        from backend.database import db_session
        with db_session() as db:
            run = db.query(ScanRun).filter(ScanRun.id == run_id).first()
            if run:
                run.status = ScanStatus.FAILED
                run.errors = [str(e)]
