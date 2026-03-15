import uuid
import logging
from datetime import datetime
from typing import List, Dict, Optional
from sqlalchemy.orm import Session

from app.collectors.aws_collector import AWSCollector
from app.collectors.azure_collector import AzureCollector
from app.collectors.gcp_collector import GCPCollector
from app.checks.security_checks import SecurityChecksEngine
from app.checks.compliance import build_compliance_results
from app.models.db_models import Asset, Finding, ComplianceResult, ScanHistory

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(self, db: Session):
        self.db = db
        self.engine = SecurityChecksEngine()

    def run_scan(self, config: Dict, triggered_by: str = "manual") -> Dict:
        scan_id = str(uuid.uuid4())
        scan = ScanHistory(
            id=scan_id,
            cloud_providers=list(config.keys()),
            started_at=datetime.utcnow(),
            status="running",
            triggered_by=triggered_by,
            config_snapshot={k: list(v.keys()) for k, v in config.items()},
        )
        self.db.add(scan)
        self.db.commit()

        all_assets = []
        providers_scanned = []
        errors = []

        # ── AWS ──
        if "aws" in config:
            try:
                logger.info("Collecting AWS assets...")
                c = AWSCollector(**{k: v for k, v in config["aws"].items() if v})
                assets = c.collect_all()
                all_assets.extend(assets)
                providers_scanned.append("aws")
                logger.info(f"AWS: {len(assets)} assets")
            except Exception as e:
                logger.error(f"AWS error: {e}")
                errors.append({"provider": "aws", "error": str(e)})

        # ── Azure ──
        if "azure" in config:
            try:
                logger.info("Collecting Azure assets...")
                c = AzureCollector(**config["azure"])
                assets = c.collect_all()
                all_assets.extend(assets)
                providers_scanned.append("azure")
                logger.info(f"Azure: {len(assets)} assets")
            except Exception as e:
                logger.error(f"Azure error: {e}")
                errors.append({"provider": "azure", "error": str(e)})

        # ── GCP ──
        if "gcp" in config:
            try:
                logger.info("Collecting GCP assets...")
                c = GCPCollector(**config["gcp"])
                assets = c.collect_all()
                all_assets.extend(assets)
                providers_scanned.append("gcp")
                logger.info(f"GCP: {len(assets)} assets")
            except Exception as e:
                logger.error(f"GCP error: {e}")
                errors.append({"provider": "gcp", "error": str(e)})

        # ── Run checks ──
        logger.info(f"Running checks on {len(all_assets)} assets...")
        findings = self.engine.run_checks(all_assets)
        compliance = build_compliance_results(findings, providers_scanned)
        secure_score = self.engine.calculate_secure_score(all_assets, findings)

        # ── Persist to DB ──
        self._persist_assets(all_assets, scan_id)
        self._persist_findings(findings, scan_id)
        self._persist_compliance(compliance, scan_id)

        # ── Update scan record ──
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.assets_discovered = len(all_assets)
        scan.findings_count = len(findings)
        scan.critical_count = sum(1 for f in findings if f["severity"] == "critical")
        scan.high_count = sum(1 for f in findings if f["severity"] == "high")
        scan.medium_count = sum(1 for f in findings if f["severity"] == "medium")
        scan.low_count = sum(1 for f in findings if f["severity"] == "low")
        scan.secure_score = secure_score["score"]
        scan.cloud_providers = providers_scanned
        if errors:
            scan.error = str(errors)
        self.db.commit()

        return {
            "scan_id": scan_id,
            "status": "completed",
            "started_at": scan.started_at.isoformat(),
            "completed_at": scan.completed_at.isoformat(),
            "assets_count": len(all_assets),
            "findings_count": len(findings),
            "secure_score": secure_score,
            "providers_scanned": providers_scanned,
            "errors": errors,
        }

    async def run_scan_async(self, config: Dict, triggered_by: str = "scheduled"):
        return self.run_scan(config, triggered_by)

    def _persist_assets(self, assets: List[Dict], scan_id: str):
        for a in assets:
            existing = self.db.query(Asset).filter_by(id=a["id"]).first()
            if existing:
                for k, v in a.items():
                    if hasattr(existing, k):
                        setattr(existing, k, v)
                existing.scan_id = scan_id
                existing.last_scanned = datetime.utcnow()
            else:
                self.db.add(Asset(
                    id=a["id"], cloud_provider=a["cloud_provider"],
                    account_id=a["account_id"], region=a.get("region"),
                    resource_type=a["resource_type"], resource_id=a["resource_id"],
                    name=a.get("name"), tags=a.get("tags", {}),
                    properties=a.get("properties", {}), is_public=a.get("is_public", False),
                    last_scanned=datetime.utcnow(), scan_id=scan_id,
                ))
        self.db.commit()

    def _persist_findings(self, findings: List[Dict], scan_id: str):
        # Mark all previous active findings as resolved before adding new ones
        self.db.query(Finding).filter(
            Finding.status == "active",
            Finding.scan_id != scan_id
        ).update({"status": "resolved"}, synchronize_session=False)

        for f in findings:
            # Check if suppressed version exists — preserve suppression
            existing = self.db.query(Finding).filter_by(
                asset_id=f["asset_id"], check_id=f["check_id"]
            ).first()
            if existing and existing.status == "suppressed":
                existing.last_seen = datetime.utcnow()
                existing.scan_id = scan_id
                continue
            if existing:
                existing.last_seen = datetime.utcnow()
                existing.status = "active"
                existing.scan_id = scan_id
                existing.severity = f["severity"]
            else:
                self.db.add(Finding(
                    id=f["id"], asset_id=f["asset_id"],
                    cloud_provider=f["cloud_provider"], check_id=f["check_id"],
                    title=f["title"], description=f["description"],
                    severity=f["severity"], status="active",
                    remediation=f["remediation"],
                    cis_controls=f.get("cis_controls", []),
                    nist_controls=f.get("nist_controls", []),
                    resource_type=f.get("resource_type"), resource_id=f.get("resource_id"),
                    region=f.get("region"), account_id=f.get("account_id"),
                    properties=f.get("properties", {}),
                    first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
                    scan_id=scan_id,
                ))
        self.db.commit()

    def _persist_compliance(self, compliance: List[Dict], scan_id: str):
        # Replace compliance results for this scan
        self.db.query(ComplianceResult).filter_by(scan_id=scan_id).delete()
        for c in compliance:
            self.db.add(ComplianceResult(
                id=c["id"], framework=c["framework"],
                control_id=c["control_id"], control_title=c.get("control_title"),
                section=c.get("section"), status=c["status"],
                cloud_provider=c.get("cloud_provider"),
                finding_ids=c.get("finding_ids", []),
                scan_id=scan_id,
            ))
        self.db.commit()
