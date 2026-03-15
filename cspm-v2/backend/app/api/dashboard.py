from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.database import get_db
from app.models.db_models import Asset, Finding, ComplianceResult, ScanHistory

router = APIRouter()


@router.get("/summary")
async def get_dashboard_summary(db: Session = Depends(get_db)):
    latest_scan = db.query(ScanHistory).order_by(ScanHistory.started_at.desc()).first()
    if not latest_scan:
        return _empty()

    total_assets = db.query(func.count(Asset.id)).scalar() or 0
    public_resources = db.query(func.count(Asset.id)).filter(Asset.is_public == True).scalar() or 0

    # Active findings only
    active_findings = db.query(Finding).filter(Finding.status == "active").all()
    suppressed_count = db.query(func.count(Finding.id)).filter(Finding.status == "suppressed").scalar() or 0
    accepted_count = db.query(func.count(Finding.id)).filter(Finding.status == "accepted").scalar() or 0

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in active_findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    by_cloud = {}
    rows = db.query(Asset.cloud_provider, func.count(Asset.id)).group_by(Asset.cloud_provider).all()
    for row in rows:
        by_cloud[row[0]] = row[1]

    by_type = {}
    rows = db.query(Asset.resource_type, func.count(Asset.id)).group_by(Asset.resource_type).all()
    for row in rows:
        by_type[row[0]] = row[1]

    top_findings = sorted(active_findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 4))[:10]

    compliance = db.query(ComplianceResult).all()
    cis = [c for c in compliance if c.framework == "CIS"]
    nist = [c for c in compliance if c.framework == "NIST"]

    # Scan history trend (last 10)
    history = db.query(ScanHistory).order_by(ScanHistory.started_at.desc()).limit(10).all()
    trend = [{"date": s.started_at.isoformat(), "score": s.secure_score, "findings": s.findings_count}
             for s in reversed(history) if s.secure_score is not None]

    return {
        "secure_score": {
            "score": latest_scan.secure_score or 0,
            "critical": by_severity["critical"],
            "high": by_severity["high"],
            "medium": by_severity["medium"],
            "low": by_severity["low"],
        },
        "total_assets": total_assets,
        "total_findings": len(active_findings),
        "suppressed_findings": suppressed_count,
        "accepted_findings": accepted_count,
        "public_resources": public_resources,
        "assets_by_cloud": by_cloud,
        "assets_by_type": by_type,
        "findings_by_severity": by_severity,
        "top_findings": [_finding_dict(f) for f in top_findings],
        "last_scan": latest_scan.completed_at.isoformat() if latest_scan.completed_at else None,
        "last_scan_status": latest_scan.status,
        "providers_scanned": latest_scan.cloud_providers or [],
        "compliance_summary": {
            "CIS": _fw_summary(cis),
            "NIST": _fw_summary(nist),
        },
        "score_trend": trend,
    }


@router.get("/scan-history-trend")
async def score_trend(db: Session = Depends(get_db)):
    history = db.query(ScanHistory).filter(
        ScanHistory.status == "completed"
    ).order_by(ScanHistory.started_at.desc()).limit(30).all()
    return [{"date": s.started_at.isoformat(), "score": s.secure_score,
             "findings": s.findings_count, "critical": s.critical_count,
             "triggered_by": s.triggered_by} for s in reversed(history)]


def _fw_summary(controls):
    total = len(controls)
    passed = sum(1 for c in controls if c.status == "passed")
    return {"total": total, "passed": passed, "failed": total - passed,
            "percentage": round(passed / total * 100, 1) if total else 0}


def _finding_dict(f):
    return {
        "id": f.id, "title": f.title, "severity": f.severity,
        "cloud_provider": f.cloud_provider, "resource_type": f.resource_type,
        "resource_id": f.resource_id, "status": f.status,
        "cis_controls": f.cis_controls or [], "nist_controls": f.nist_controls or [],
        "remediation": f.remediation,
    }


def _empty():
    return {
        "secure_score": {"score": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "total_assets": 0, "total_findings": 0, "suppressed_findings": 0,
        "accepted_findings": 0, "public_resources": 0,
        "assets_by_cloud": {}, "assets_by_type": {}, "findings_by_severity": {},
        "top_findings": [], "last_scan": None, "last_scan_status": None,
        "providers_scanned": [], "compliance_summary": {}, "score_trend": [],
    }
