"""
CloudGuard Pro CSPM — API Routes: Reports
"""
import os
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.models import ReportRequest, ReportArtifact
from backend.models.schemas import ReportRequestCreate, ReportRequestOut

router = APIRouter()


@router.post("/reports", response_model=ReportRequestOut)
def create_report(body: ReportRequestCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    req = ReportRequest(report_type=body.report_type, filters=body.filters)
    db.add(req)
    db.commit()
    db.refresh(req)
    background_tasks.add_task(_generate_report, req.id)
    return ReportRequestOut.from_orm(req)


@router.get("/reports", response_model=list)
def list_reports(db: Session = Depends(get_db)):
    reqs = db.query(ReportRequest).order_by(ReportRequest.created_at.desc()).limit(50).all()
    return [ReportRequestOut.from_orm(r) for r in reqs]


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    req = db.query(ReportRequest).filter(ReportRequest.id == report_id).first()
    if not req:
        raise HTTPException(404, "Report not found")
    if req.status != "completed":
        raise HTTPException(400, f"Report status: {req.status}")
    art = db.query(ReportArtifact).filter(ReportArtifact.request_id == report_id).first()
    if not art or not art.file_path or not os.path.exists(art.file_path):
        raise HTTPException(404, "Report file not available")
    return FileResponse(
        path=art.file_path,
        media_type="application/pdf",
        filename=f"cloudguard-{req.report_type}-report.pdf",
    )


def _generate_report(request_id: str):
    from backend.reports.pdf_generator import generate_pdf
    generate_pdf(request_id)
