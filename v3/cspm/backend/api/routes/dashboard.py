"""
CloudGuard Pro CSPM — API Routes: Dashboard
"""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import get_db
from backend.models.models import Finding, Asset, CheckDefinition, FindingStatus, Severity
from backend.models.schemas import DashboardStats

router = APIRouter()


@router.get("/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    open_q = db.query(Finding).filter(Finding.status == FindingStatus.OPEN)
    total_findings = db.query(Finding).count()
    open_findings = open_q.count()

    def _sev_count(sev):
        return open_q.filter(Finding.severity == sev).count()

    # Provider breakdown
    prov_rows = db.query(Finding.provider, func.count(Finding.id)).filter(
        Finding.status == FindingStatus.OPEN
    ).group_by(Finding.provider).all()

    # Family breakdown
    fam_rows = db.query(Finding.family, func.count(Finding.id)).filter(
        Finding.status == FindingStatus.OPEN
    ).group_by(Finding.family).all()

    # Top services
    svc_rows = db.query(Finding.service, func.count(Finding.id)).filter(
        Finding.status == FindingStatus.OPEN
    ).group_by(Finding.service).order_by(func.count(Finding.id).desc()).limit(10).all()

    # Top risky accounts
    acct_rows = db.query(Finding.account_context, func.count(Finding.id)).filter(
        Finding.status == FindingStatus.OPEN
    ).group_by(Finding.account_context).order_by(func.count(Finding.id).desc()).limit(10).all()

    # 7-day trend
    trend = []
    for i in range(6, -1, -1):
        day = datetime.utcnow().date() - timedelta(days=i)
        day_start = datetime.combine(day, datetime.min.time())
        day_end = day_start + timedelta(days=1)
        count = db.query(Finding).filter(
            Finding.first_seen >= day_start,
            Finding.first_seen < day_end,
        ).count()
        trend.append({"date": str(day), "count": count})

    return DashboardStats(
        total_findings=total_findings,
        open_findings=open_findings,
        critical=_sev_count(Severity.CRITICAL),
        high=_sev_count(Severity.HIGH),
        medium=_sev_count(Severity.MEDIUM),
        low=_sev_count(Severity.LOW),
        informational=_sev_count(Severity.INFO),
        total_assets=db.query(Asset).count(),
        total_checks=db.query(CheckDefinition).count(),
        providers={r[0]: r[1] for r in prov_rows},
        families={r[0]: r[1] for r in fam_rows},
        top_services=[{"service": r[0], "count": r[1]} for r in svc_rows],
        top_risky_accounts=[{"account": r[0], "count": r[1]} for r in acct_rows if r[0]],
        trend_7d=trend,
        compliance_summary={},
    )
