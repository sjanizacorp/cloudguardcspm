from fastapi import APIRouter, Query
from typing import Optional
from app.api.scan import scan_store

router = APIRouter()

def _get_latest():
    if not scan_store:
        return {}, []
    latest = max(scan_store.values(), key=lambda x: x.get("started_at", ""), default=None)
    return latest or {}, (latest or {}).get("findings", [])

findings_router = APIRouter()
compliance_router = APIRouter()

@findings_router.get("")
async def list_findings(
    severity: Optional[str] = None,
    cloud: Optional[str] = None,
    resource_type: Optional[str] = None,
    check_id: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, le=500),
    offset: int = 0
):
    _, findings = _get_latest()
    if severity:
        findings = [f for f in findings if f["severity"] == severity]
    if cloud:
        findings = [f for f in findings if f["cloud_provider"] == cloud]
    if resource_type:
        findings = [f for f in findings if f.get("resource_type") == resource_type]
    if check_id:
        findings = [f for f in findings if f["check_id"] == check_id]
    if search:
        s = search.lower()
        findings = [f for f in findings if s in f["title"].lower() or s in f.get("resource_id", "").lower()]

    total = len(findings)
    # Sort by severity
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(findings, key=lambda f: order.get(f["severity"], 5))
    return {"total": total, "findings": findings[offset:offset + limit]}

@findings_router.get("/{finding_id}")
async def get_finding(finding_id: str):
    _, findings = _get_latest()
    for f in findings:
        if f["id"] == finding_id:
            return f
    return {"error": "Finding not found"}


@compliance_router.get("")
async def list_compliance(framework: Optional[str] = None, cloud: Optional[str] = None, status: Optional[str] = None):
    latest, _ = _get_latest()
    compliance = latest.get("compliance", [])
    if framework:
        compliance = [c for c in compliance if c["framework"] == framework]
    if cloud:
        compliance = [c for c in compliance if c["cloud_provider"] == cloud]
    if status:
        compliance = [c for c in compliance if c["status"] == status]
    
    passed = sum(1 for c in compliance if c["status"] == "passed")
    failed = sum(1 for c in compliance if c["status"] == "failed")
    return {
        "total": len(compliance),
        "passed": passed,
        "failed": failed,
        "percentage": round(passed / len(compliance) * 100, 1) if compliance else 0,
        "controls": compliance
    }
