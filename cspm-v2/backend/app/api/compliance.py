from fastapi import APIRouter, Depends
from typing import Optional
from sqlalchemy.orm import Session
from app.models.database import get_db
from app.models.db_models import ComplianceResult

router = APIRouter()


@router.get("")
async def list_compliance(
    framework: Optional[str] = None,
    cloud: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    q = db.query(ComplianceResult)
    if framework:
        q = q.filter(ComplianceResult.framework == framework)
    if cloud:
        q = q.filter(ComplianceResult.cloud_provider == cloud)
    if status:
        q = q.filter(ComplianceResult.status == status)

    controls = q.all()
    passed = sum(1 for c in controls if c.status == "passed")
    failed = sum(1 for c in controls if c.status == "failed")
    total = len(controls)

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "percentage": round(passed / total * 100, 1) if total else 0,
        "controls": [_ctrl_dict(c) for c in controls]
    }


@router.get("/frameworks")
async def get_frameworks(db: Session = Depends(get_db)):
    from sqlalchemy import func, distinct
    rows = db.query(
        ComplianceResult.framework,
        func.count().label("total"),
        func.sum((ComplianceResult.status == "passed").cast(db.bind.dialect.type_descriptor(type(True)))).label("passed")
    ).group_by(ComplianceResult.framework).all()
    result = []
    for r in rows:
        t = r[1] or 0
        p = r[2] or 0
        result.append({"framework": r[0], "total": t, "passed": p, "failed": t - p,
                        "percentage": round(p / t * 100, 1) if t else 0})
    return result


def _ctrl_dict(c: ComplianceResult) -> dict:
    return {
        "id": c.id, "framework": c.framework, "control_id": c.control_id,
        "control_title": c.control_title, "section": c.section,
        "status": c.status, "cloud_provider": c.cloud_provider,
        "finding_ids": c.finding_ids or [],
        "last_evaluated": c.last_evaluated.isoformat() if c.last_evaluated else None,
    }
