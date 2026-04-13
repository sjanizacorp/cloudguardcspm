"""
CloudGuard Pro CSPM — PDF Report Generator
Aniza Corp | Shahryar Jahangir

Generates PDF reports using ReportLab (open source, BSD license).
Report types: executive, technical, compliance, inventory, catalog
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, List

log = logging.getLogger(__name__)

REPORTS_DIR = os.environ.get("REPORTS_DIR", "/tmp/cspm_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Severity color map (R, G, B) 0-1 range
SEV_COLORS = {
    "critical": (0.85, 0.10, 0.10),
    "high":     (0.92, 0.40, 0.10),
    "medium":   (0.95, 0.75, 0.10),
    "low":      (0.20, 0.65, 0.30),
    "informational": (0.40, 0.55, 0.75),
}

BRAND_DARK  = (0.05, 0.10, 0.20)
BRAND_BLUE  = (0.10, 0.35, 0.75)
BRAND_LIGHT = (0.95, 0.97, 1.00)


def generate_pdf(request_id: str):
    """Called from background task. Generates PDF and updates DB."""
    from backend.database import db_session
    from backend.models.models import ReportRequest, ReportArtifact

    with db_session() as db:
        req = db.query(ReportRequest).filter(ReportRequest.id == request_id).first()
        if not req:
            return
        req.status = "generating"

    try:
        out_path = _generate(request_id)
        size = os.path.getsize(out_path)
        with db_session() as db:
            req = db.query(ReportRequest).filter(ReportRequest.id == request_id).first()
            req.status = "completed"
            req.completed_at = datetime.utcnow()
            art = ReportArtifact(request_id=request_id, file_path=out_path, file_size_bytes=size)
            db.add(art)
    except Exception as e:
        log.error("PDF generation error for %s: %s", request_id, e)
        with db_session() as db:
            req = db.query(ReportRequest).filter(ReportRequest.id == request_id).first()
            if req:
                req.status = "failed"
                req.error = str(e)


def _generate(request_id: str) -> str:
    from backend.database import db_session
    from backend.models.models import (
        ReportRequest, Finding, Asset, CheckDefinition,
        FindingStatus, Severity,
    )

    with db_session() as db:
        req = db.query(ReportRequest).filter(ReportRequest.id == request_id).first()
        report_type = req.report_type
        filters = req.filters or {}

        # Build base query with filters
        fq = db.query(Finding)
        if filters.get("provider"):
            fq = fq.filter(Finding.provider == filters["provider"])
        if filters.get("severity"):
            fq = fq.filter(Finding.severity == filters["severity"])
        if filters.get("family"):
            fq = fq.filter(Finding.family == filters["family"])
        if filters.get("status"):
            fq = fq.filter(Finding.status == filters["status"])
        else:
            fq = fq.filter(Finding.status == FindingStatus.OPEN)

        findings = fq.order_by(Finding.severity, Finding.first_seen.desc()).all()
        assets = db.query(Asset).limit(1000).all()
        checks = db.query(CheckDefinition).all()

        # Serialize while session is open
        findings_data = [_serialize_finding(f) for f in findings]
        assets_data = [_serialize_asset(a) for a in assets]
        checks_data = [_serialize_check(c) for c in checks]

    out_path = os.path.join(REPORTS_DIR, f"cloudguard-{report_type}-{request_id[:8]}.pdf")

    if report_type == "executive":
        _build_executive(out_path, findings_data, assets_data)
    elif report_type == "technical":
        _build_technical(out_path, findings_data)
    elif report_type == "compliance":
        _build_compliance(out_path, findings_data)
    elif report_type == "inventory":
        _build_inventory(out_path, assets_data)
    elif report_type == "catalog":
        _build_catalog(out_path, checks_data)
    else:
        _build_executive(out_path, findings_data, assets_data)

    return out_path


# ─── Report Builders ────────────────────────────────────────────────────────

def _build_executive(out_path: str, findings: List[Dict], assets: List[Dict]):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )
    except ImportError:
        _write_text_fallback(out_path, "executive", findings)
        return

    doc = SimpleDocTemplate(out_path, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("<b>CloudGuard Pro CSPM</b>", _h1(styles)))
    story.append(Paragraph("Executive Security Posture Report", _h2(styles)))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%"))
    story.append(Spacer(1, 0.5*cm))

    # Summary stats
    sev_counts = _count_by_key(findings, "severity")
    story.append(Paragraph("Summary", _h2(styles)))
    summary_data = [
        ["Total Findings", str(len(findings))],
        ["Critical", str(sev_counts.get("critical", 0))],
        ["High", str(sev_counts.get("high", 0))],
        ["Medium", str(sev_counts.get("medium", 0))],
        ["Low", str(sev_counts.get("low", 0))],
        ["Total Assets", str(len(assets))],
    ]
    t = Table(summary_data, colWidths=[8*cm, 4*cm])
    t.setStyle(_summary_table_style())
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    # Provider breakdown
    prov_counts = _count_by_key(findings, "provider")
    story.append(Paragraph("Findings by Cloud Provider", _h2(styles)))
    prov_data = [["Provider", "Findings"]] + [[k, str(v)] for k, v in sorted(prov_counts.items())]
    story.append(Table(prov_data, colWidths=[8*cm, 4*cm], style=_base_table_style()))
    story.append(Spacer(1, 0.5*cm))

    # Top findings
    story.append(Paragraph("Top Critical & High Findings", _h2(styles)))
    top = [f for f in findings if f["severity"] in ("critical", "high")][:20]
    if top:
        top_data = [["Severity", "Title", "Provider", "Resource"]]
        for f in top:
            top_data.append([
                f["severity"].upper(),
                f["title"][:50],
                f["provider"],
                (f.get("resource_display_name") or "")[:40],
            ])
        t2 = Table(top_data, colWidths=[2.5*cm, 8*cm, 2.5*cm, 4.5*cm])
        t2.setStyle(_findings_table_style())
        story.append(t2)

    doc.build(story)


def _build_technical(out_path: str, findings: List[Dict]):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, HRFlowable
    except ImportError:
        _write_text_fallback(out_path, "technical", findings)
        return

    doc = SimpleDocTemplate(out_path, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("<b>CloudGuard Pro CSPM — Technical Findings Report</b>", _h1(styles)))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    story.append(Spacer(1, 0.5*cm))

    for f in findings[:500]:  # cap at 500 for PDF sanity
        story.append(HRFlowable(width="100%"))
        story.append(Paragraph(f"<b>[{f['severity'].upper()}] {f['title']}</b>", _h3(styles)))
        rows = [
            ["Check ID", f.get("check_id", "")],
            ["Family", f.get("family", "")],
            ["Provider", f.get("provider", "")],
            ["Service", f.get("service", "")],
            ["Resource", f.get("universal_resource_name", "")[:80]],
            ["Native ID", (f.get("arn") or f.get("azure_resource_id") or f.get("gcp_resource_name") or f.get("native_id") or "")[:80]],
            ["First Seen", str(f.get("first_seen", ""))[:19]],
        ]
        t = Table(rows, colWidths=[4*cm, 13*cm])
        t.setStyle(_detail_table_style())
        story.append(t)
        story.append(Paragraph(f"<b>Description:</b> {f.get('description', '')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Remediation:</b> {f.get('remediation', '')}", styles["Normal"]))
        story.append(Spacer(1, 0.3*cm))

    doc.build(story)


def _build_compliance(out_path: str, findings: List[Dict]):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
    except ImportError:
        _write_text_fallback(out_path, "compliance", findings)
        return

    doc = SimpleDocTemplate(out_path, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("<b>CloudGuard Pro CSPM — Compliance Report</b>", _h1(styles)),
        Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]),
        Spacer(1, 0.5*cm),
    ]

    # Group by framework
    fw_map: Dict[str, List[Dict]] = {}
    for f in findings:
        for fw in (f.get("compliance_frameworks") or []):
            if fw:
                fw_map.setdefault(fw, []).append(f)

    if not fw_map:
        story.append(Paragraph("No compliance mappings found in current findings.", styles["Normal"]))
    else:
        for fw, fw_findings in sorted(fw_map.items()):
            story.append(Paragraph(f"Framework: {fw}", _h2(styles)))
            data = [["Severity", "Title", "Check ID"]]
            for f in fw_findings[:50]:
                data.append([f["severity"].upper(), f["title"][:55], f["check_id"]])
            t = Table(data, colWidths=[2.5*cm, 11*cm, 4*cm])
            t.setStyle(_findings_table_style())
            story.append(t)
            story.append(Spacer(1, 0.5*cm))

    doc.build(story)


def _build_inventory(out_path: str, assets: List[Dict]):
    try:
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
    except ImportError:
        _write_text_fallback(out_path, "inventory", assets)
        return

    doc = SimpleDocTemplate(out_path, pagesize=landscape(A4), topMargin=1.5*cm, bottomMargin=1.5*cm)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("<b>CloudGuard Pro CSPM — Asset Inventory Report</b>", _h1(styles)),
        Paragraph(f"Total Assets: {len(assets)} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]),
        Spacer(1, 0.4*cm),
    ]
    data = [["Provider", "Service", "Type", "Region", "Display Name", "URN"]]
    for a in assets[:2000]:
        data.append([
            a.get("provider", ""),
            a.get("service", ""),
            a.get("resource_type", ""),
            (a.get("region") or "")[:15],
            (a.get("display_name") or "")[:30],
            (a.get("universal_resource_name") or "")[:50],
        ])
    t = Table(data, colWidths=[2*cm, 2.5*cm, 2.5*cm, 2.5*cm, 5*cm, 9*cm])
    t.setStyle(_base_table_style())
    story.append(t)
    doc.build(story)


def _build_catalog(out_path: str, checks: List[Dict]):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, HRFlowable
    except ImportError:
        _write_text_fallback(out_path, "catalog", checks)
        return

    doc = SimpleDocTemplate(out_path, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("<b>CloudGuard Pro CSPM — Check Catalog</b>", _h1(styles)),
        Paragraph(f"Total Checks: {len(checks)} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]),
        Spacer(1, 0.5*cm),
    ]
    data = [["Check ID", "Family", "Provider", "Severity", "Status", "Source"]]
    for c in checks:
        data.append([
            c.get("check_id", "")[:20],
            c.get("family", "")[:20],
            c.get("provider", ""),
            c.get("severity", ""),
            c.get("status", ""),
            (c.get("source_vendor") or "")[:15],
        ])
    t = Table(data, colWidths=[3.5*cm, 3.5*cm, 2*cm, 2.5*cm, 2.5*cm, 3.5*cm])
    t.setStyle(_base_table_style())
    story.append(t)
    doc.build(story)


# ─── Table Styles ───────────────────────────────────────────────────────────

def _base_table_style():
    from reportlab.platypus import TableStyle
    from reportlab.lib import colors
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3a6e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f0f4ff"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ])


def _summary_table_style():
    from reportlab.platypus import TableStyle
    from reportlab.lib import colors
    return TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#eef2ff"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#aaaaaa")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ])


def _findings_table_style():
    from reportlab.platypus import TableStyle
    from reportlab.lib import colors
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3a6e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fff8f0"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ])


def _detail_table_style():
    from reportlab.platypus import TableStyle
    from reportlab.lib import colors
    return TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ff")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ])


# ─── Paragraph styles ───────────────────────────────────────────────────────

def _h1(styles):
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib import colors
    return ParagraphStyle("H1Brand", parent=styles["Heading1"],
                          textColor=colors.HexColor("#0f2a5e"), fontSize=18, spaceAfter=6)

def _h2(styles):
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib import colors
    return ParagraphStyle("H2Brand", parent=styles["Heading2"],
                          textColor=colors.HexColor("#1a3a6e"), fontSize=13, spaceAfter=4)

def _h3(styles):
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib import colors
    return ParagraphStyle("H3Brand", parent=styles["Heading3"],
                          textColor=colors.HexColor("#333333"), fontSize=10, spaceAfter=2)


# ─── Serializers ─────────────────────────────────────────────────────────────

def _serialize_finding(f) -> Dict:
    return {
        "id": f.id, "check_id": f.check_id, "family": f.family,
        "severity": str(f.severity.value if hasattr(f.severity, "value") else f.severity),
        "title": f.title, "description": f.description, "remediation": f.remediation,
        "provider": str(f.provider.value if hasattr(f.provider, "value") else f.provider),
        "service": f.service, "resource_type": f.resource_type,
        "resource_display_name": f.resource_display_name,
        "native_id": f.native_id, "arn": f.arn,
        "azure_resource_id": f.azure_resource_id,
        "gcp_resource_name": f.gcp_resource_name,
        "universal_resource_name": f.universal_resource_name,
        "first_seen": str(f.first_seen), "last_seen": str(f.last_seen),
        "compliance_frameworks": f.compliance_frameworks or [],
    }

def _serialize_asset(a) -> Dict:
    return {
        "id": a.id, "provider": str(a.provider.value if hasattr(a.provider, "value") else a.provider),
        "service": a.service, "resource_type": a.resource_type,
        "region": a.region, "display_name": a.display_name,
        "universal_resource_name": a.universal_resource_name,
        "native_id": a.native_id,
    }

def _serialize_check(c) -> Dict:
    return {
        "check_id": c.check_id, "family": c.family,
        "provider": str(c.provider.value if hasattr(c.provider, "value") else c.provider),
        "severity": str(c.severity.value if hasattr(c.severity, "value") else c.severity),
        "status": str(c.status.value if hasattr(c.status, "value") else c.status),
        "source_vendor": c.source_vendor,
    }

def _count_by_key(items: List[Dict], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        val = item.get(key, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts

def _write_text_fallback(out_path: str, report_type: str, data: List):
    """Fallback if ReportLab not available: write plain text."""
    out_path_txt = out_path.replace(".pdf", ".txt")
    with open(out_path_txt, "w") as f:
        f.write(f"CloudGuard Pro CSPM — {report_type.title()} Report\n")
        f.write(f"Generated: {datetime.utcnow().isoformat()}\n\n")
        f.write(f"Total items: {len(data)}\n\n")
        for item in data[:100]:
            f.write(str(item) + "\n")
    # rename so download still works
    import shutil
    shutil.copy(out_path_txt, out_path)
