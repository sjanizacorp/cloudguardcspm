from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict
from sqlalchemy.orm import Session
from app.models.database import get_db, SessionLocal
from app.models.db_models import ScheduledScan
from app import scheduler as sched_module
import uuid
from datetime import datetime

router = APIRouter()


class ScheduleRequest(BaseModel):
    name: str
    cron_expression: str
    cloud_config: Dict
    enabled: bool = True


@router.get("")
async def list_schedules(db: Session = Depends(get_db)):
    schedules = db.query(ScheduledScan).order_by(ScheduledScan.created_at.desc()).all()
    return [_sched_dict(s) for s in schedules]


@router.post("")
async def create_schedule(body: ScheduleRequest, db: Session = Depends(get_db)):
    # Validate cron
    parts = body.cron_expression.strip().split()
    if len(parts) != 5:
        raise HTTPException(400, "cron_expression must have 5 fields: minute hour day month day_of_week")

    sid = str(uuid.uuid4())
    s = ScheduledScan(
        id=sid, name=body.name,
        cron_expression=body.cron_expression,
        enabled=body.enabled,
        cloud_config=body.cloud_config,
        created_at=datetime.utcnow(),
    )
    db.add(s)
    db.commit()

    if body.enabled:
        sched_module.add_scheduled_scan(sid, body.cron_expression, body.cloud_config, SessionLocal)
        next_run = sched_module.get_next_run_time(sid)
        if next_run:
            s.next_run = next_run
            db.commit()

    return _sched_dict(s)


@router.patch("/{schedule_id}/toggle")
async def toggle_schedule(schedule_id: str, db: Session = Depends(get_db)):
    s = db.query(ScheduledScan).filter_by(id=schedule_id).first()
    if not s:
        raise HTTPException(404, "Schedule not found")
    s.enabled = not s.enabled
    if s.enabled:
        sched_module.add_scheduled_scan(s.id, s.cron_expression, s.cloud_config, SessionLocal)
    else:
        sched_module.remove_scheduled_scan(s.id)
    db.commit()
    return _sched_dict(s)


@router.delete("/{schedule_id}")
async def delete_schedule(schedule_id: str, db: Session = Depends(get_db)):
    s = db.query(ScheduledScan).filter_by(id=schedule_id).first()
    if not s:
        raise HTTPException(404, "Schedule not found")
    sched_module.remove_scheduled_scan(schedule_id)
    db.delete(s)
    db.commit()
    return {"deleted": True}


def _sched_dict(s: ScheduledScan) -> dict:
    return {
        "id": s.id, "name": s.name, "cron_expression": s.cron_expression,
        "enabled": s.enabled,
        "last_run": s.last_run.isoformat() if s.last_run else None,
        "next_run": s.next_run.isoformat() if s.next_run else None,
        "run_count": s.run_count or 0,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }
