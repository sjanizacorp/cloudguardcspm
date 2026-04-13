"""
CloudGuard Pro CSPM v3 — Scan Worker
Aniza Corp | Shahryar Jahangir

Two scan modes:
  LIVE:  collect from real cloud APIs then run checks
  DEMO:  run check engine against assets already in the DB
"""
from __future__ import annotations
import hashlib, json, logging, logging.handlers, traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.database import db_session
from backend.models.models import (
    Asset, AssetSnapshot, CheckDefinition, Finding, FindingStatus,
    ProviderConnection, ScanRun, ScanStatus,
)
from backend.check_engine.engine import CheckEngine, _REGISTRY, make_finding_id

log = logging.getLogger(__name__)
engine = CheckEngine()

# ── Dedicated scan log (separate from main app log) ───────────────────────────
def _get_scan_logger() -> logging.Logger:
    """Returns a logger that writes to logs/scans.log (rotating at 50 MB)."""
    scan_log = logging.getLogger("cloudguard.scans")
    if scan_log.handlers:
        return scan_log
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        log_dir / "scans.log",
        maxBytes=50 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-8s %(message)s"
    ))
    scan_log.setLevel(logging.DEBUG)
    scan_log.addHandler(handler)
    # Also write scan events to the main app log
    scan_log.propagate = True
    return scan_log


def _slog(run_id: str, level: str, msg: str, *args):
    """Write to both the main log and the dedicated scan log."""
    sl = _get_scan_logger()
    prefix = f"[scan:{run_id[:8]}] "
    getattr(sl, level)(prefix + msg, *args)


def execute_scan(run_id: str):
    _slog(run_id, "info", "─── Scan starting ───────────────────────────")
    with db_session() as db:
        run = db.query(ScanRun).filter(ScanRun.id == run_id).first()
        if not run:
            _slog(run_id, "error", "ScanRun not found in DB")
            return
        conn = db.query(ProviderConnection).filter(ProviderConnection.id == run.connection_id).first()
        if not conn:
            _slog(run_id, "error", "Connection %s not found", run.connection_id)
            return
        run.status = ScanStatus.RUNNING
        run.started_at = datetime.utcnow()
        conn_id   = conn.id
        conn_name = conn.name
        provider  = str(conn.provider.value if hasattr(conn.provider, "value") else conn.provider)
        cred_type = conn.credential_type or "env"
        cred_ref  = conn.credential_ref or ""

    _slog(run_id, "info", "connection=%r provider=%s cred_type=%s cred_ref=%s",
          conn_name, provider, cred_type, cred_ref or "(none)")

    # 30-minute hard timeout so scans never hang indefinitely
    import concurrent.futures
    TIMEOUT = 30 * 60
    _slog(run_id, "info", "Timeout: %d min. Add specific regions to your connection to speed up scans.", TIMEOUT // 60)

    def _run():
        if _has_credentials(provider, cred_type, cred_ref):
            _slog(run_id, "info", "Mode: LIVE — credentials detected, running real collection")
            _do_live_scan(run_id, conn_id, conn_name, provider)
        else:
            _slog(run_id, "info", "Mode: DEMO — no credentials configured, scanning seeded assets")
            _do_demo_scan(run_id, conn_id, conn_name, provider)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_run)
            future.result(timeout=TIMEOUT)
    except concurrent.futures.TimeoutError:
        msg = (f"Scan timed out after {TIMEOUT // 60} minutes. "
               "Add specific regions in your connection to limit scope.")
        _slog(run_id, "error", msg)
        with db_session() as db:
            run = db.query(ScanRun).filter(ScanRun.id == run_id).first()
            if run:
                run.status = ScanStatus.FAILED
                run.completed_at = datetime.utcnow()
                run.errors = [msg]
                run.log = msg
    except Exception as e:
        tb = traceback.format_exc()
        _slog(run_id, "error", "Scan FAILED:\n%s", tb)
        with db_session() as db:
            run = db.query(ScanRun).filter(ScanRun.id == run_id).first()
            if run:
                run.status = ScanStatus.FAILED
                run.completed_at = datetime.utcnow()
                run.errors = [str(e)]
                run.log = f"FAILED: {e}\n\n{tb}"


def _has_credentials(provider: str, cred_type: str, cred_ref: str) -> bool:
    import os
    if cred_type in ("role", "profile", "file", "workload_identity") and cred_ref:
        return True
    checks = {
        "aws":   ["AWS_ACCESS_KEY_ID", "AWS_PROFILE"],
        "azure": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID"],
        "gcp":   ["GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT"],
        "ibm":   ["IBMCLOUD_API_KEY"],
        "oci":   [],
    }
    if provider == "oci":
        import pathlib
        return pathlib.Path("~/.oci/config").expanduser().exists()
    for var in checks.get(provider, []):
        if os.environ.get(var, "").strip():
            return True
    return False


def _do_demo_scan(run_id: str, conn_id: str, conn_name: str, provider: str):
    with db_session() as db:
        assets = db.query(Asset).filter(Asset.connection_id == conn_id, Asset.is_active == True).all()
        asset_data = [
            {
                "id": a.id, "service": a.service, "resource_type": a.resource_type,
                "raw_config": a.raw_config or {}, "urn": a.universal_resource_name,
                "native_id": a.native_id, "arn": a.arn,
                "azure_resource_id": a.azure_resource_id,
                "display_name": a.display_name, "region": a.region, "tags": a.tags or {},
            }
            for a in assets
        ]
        conn = db.query(ProviderConnection).filter(ProviderConnection.id == conn_id).first()
        acct = (conn.account_id or conn.subscription_id or conn.project_id
                or conn.tenancy_id or conn.ibm_account_id or "demo")

    _slog(run_id, "info", "Demo scan: %d assets in DB for connection %r", len(asset_data), conn_name)
    checks_run = findings_created = findings_resolved = 0

    for a in asset_data:
        results = engine.run_checks_for_resource(a["raw_config"], provider, a["service"], a["resource_type"])
        checks_run += len(results)
        for result in results:
            if result.passed:
                with db_session() as db:
                    fid = make_finding_id(result.check_id, a["urn"])
                    f = db.query(Finding).filter(Finding.finding_id == fid).first()
                    if f and f.status == FindingStatus.OPEN:
                        f.status = FindingStatus.RESOLVED
                        f.resolved_at = datetime.utcnow()
                        findings_resolved += 1
            elif not result.error:
                with db_session() as db:
                    created = _upsert_finding(db, result, acct, provider, a)
                    if created:
                        findings_created += 1

    _slog(run_id, "info",
          "Demo scan complete: assets=%d checks=%d new_findings=%d resolved=%d",
          len(asset_data), checks_run, findings_created, findings_resolved)

    with db_session() as db:
        run = db.query(ScanRun).filter(ScanRun.id == run_id).first()
        conn = db.query(ProviderConnection).filter(ProviderConnection.id == conn_id).first()
        if run:
            run.status = ScanStatus.COMPLETED
            run.completed_at = datetime.utcnow()
            run.assets_discovered = len(asset_data)
            run.checks_run = checks_run
            run.findings_created = findings_created
            run.findings_resolved = findings_resolved
            run.progress_pct = 100.0
            run.log = (
                f"Demo scan completed successfully.\n"
                f"Assets evaluated: {len(asset_data)}\n"
                f"Checks run: {checks_run}\n"
                f"New findings: {findings_created}\n"
                f"Resolved findings: {findings_resolved}\n"
                f"Note: No cloud credentials configured — scanned seeded demo assets. "
                f"Set credentials in your connection to scan live infrastructure."
            )
        if conn:
            conn.last_scan_at = datetime.utcnow()


def _do_live_scan(run_id: str, conn_id: str, conn_name: str, provider: str):
    with db_session() as db:
        conn = db.query(ProviderConnection).filter(ProviderConnection.id == conn_id).first()
        conn_snap = {
            "id": conn.id, "provider": provider,
            "account_id": conn.account_id, "subscription_id": conn.subscription_id,
            "project_id": conn.project_id, "tenancy_id": conn.tenancy_id,
            "ibm_account_id": conn.ibm_account_id,
            "credential_type": conn.credential_type,
            "credential_ref": conn.credential_ref,
            "regions": list(conn.regions or []),
        }

    class ConnProxy:
        def __init__(self, d):
            self.__dict__.update(d)

    _slog(run_id, "info", "Live scan: collecting from %s (%s)...", provider.upper(), conn_name)

    try:
        collector = _get_collector(provider)
        bundles = collector.collect(ConnProxy(conn_snap))
    except Exception as e:
        tb = traceback.format_exc()
        _slog(run_id, "error", "Collection FAILED for %s:\n%s", provider.upper(), tb)
        with db_session() as db:
            run = db.query(ScanRun).filter(ScanRun.id == run_id).first()
            if run:
                run.status = ScanStatus.FAILED
                run.completed_at = datetime.utcnow()
                run.errors = [str(e)]
                run.log = (
                    f"Collection failed for {provider.upper()}:\n{e}\n\n"
                    f"Troubleshooting:\n"
                    f"  credential_type = {conn_snap['credential_type']}\n"
                    f"  credential_ref  = {conn_snap['credential_ref'] or '(none)'}\n\n"
                    f"Full traceback:\n{tb}"
                )
        raise

    total_bundles = len(bundles)
    total_items = sum(len(b.get("items", [])) for b in bundles)
    _slog(run_id, "info", "Collection done: %d resource bundles, %d total resources",
          total_bundles, total_items)

    acct = (conn_snap.get("account_id") or conn_snap.get("subscription_id")
            or conn_snap.get("project_id") or conn_snap.get("tenancy_id")
            or conn_snap.get("ibm_account_id") or "unknown")

    assets_discovered = checks_run = findings_created = findings_resolved = 0

    for bundle in bundles:
        svc   = bundle.get("service", "unknown")
        rtype = bundle.get("resource_type", "unknown")
        items = bundle.get("items", [])
        _slog(run_id, "debug", "  Evaluating %s/%s: %d resources", svc, rtype, len(items))

        for item in items:
            urn = _build_urn(provider, acct, svc, rtype, item)

            # Capture all needed asset fields inside the session to avoid
            # DetachedInstanceError when accessing attributes after session closes
            with db_session() as db:
                asset = _upsert_asset(db, conn_id, provider, svc, rtype, urn, item, run_id)
                db.flush()
                asset_id      = str(asset.id)
                asset_native  = asset.native_id or ""
                asset_arn     = asset.arn or ""
                asset_az_rid  = asset.azure_resource_id or ""
                asset_display = asset.display_name or ""

            assets_discovered += 1
            asset_dict = {
                "id": asset_id, "service": svc, "resource_type": rtype,
                "raw_config": item, "urn": urn,
                "native_id": asset_native, "arn": asset_arn,
                "azure_resource_id": asset_az_rid,
                "display_name": asset_display,
                "region": item.get("region") or item.get("location") or "global",
                "tags": item.get("Tags") or item.get("tags") or {},
            }

            results = engine.run_checks_for_resource(item, provider, svc, rtype)
            checks_run += len(results)

            for result in results:
                if result.error:
                    _slog(run_id, "debug", "  Check %s error on %s: %s",
                          result.check_id, urn[:60], result.error)
                    continue
                if result.passed:
                    with db_session() as db:
                        fid = make_finding_id(result.check_id, urn)
                        f = db.query(Finding).filter(Finding.finding_id == fid).first()
                        if f and f.status == FindingStatus.OPEN:
                            f.status = FindingStatus.RESOLVED
                            f.resolved_at = datetime.utcnow()
                            findings_resolved += 1
                else:
                    with db_session() as db:
                        created = _upsert_finding(db, result, acct, provider, asset_dict)
                        if created:
                            findings_created += 1
                            _slog(run_id, "info", "  NEW finding: %s on %s",
                                  result.check_id, asset_display or asset_native)

    _slog(run_id, "info",
          "Live scan complete: assets=%d checks=%d new_findings=%d resolved=%d",
          assets_discovered, checks_run, findings_created, findings_resolved)

    with db_session() as db:
        run = db.query(ScanRun).filter(ScanRun.id == run_id).first()
        conn = db.query(ProviderConnection).filter(ProviderConnection.id == conn_id).first()
        if run:
            run.status = ScanStatus.COMPLETED
            run.completed_at = datetime.utcnow()
            run.assets_discovered = assets_discovered
            run.checks_run = checks_run
            run.findings_created = findings_created
            run.findings_resolved = findings_resolved
            run.progress_pct = 100.0
            run.log = (
                f"Live scan completed successfully.\n"
                f"Provider: {provider.upper()}\n"
                f"Connection: {conn_name}\n"
                f"Assets discovered: {assets_discovered}\n"
                f"Checks evaluated: {checks_run}\n"
                f"New findings: {findings_created}\n"
                f"Resolved findings: {findings_resolved}\n"
                f"Resource bundles: {total_bundles} ({total_items} resources)\n"
            )
        if conn:
            conn.last_scan_at = datetime.utcnow()


def _upsert_finding(db, result, acct: str, provider: str, asset: Dict) -> bool:
    fid = make_finding_id(result.check_id, asset["urn"])
    existing = db.query(Finding).filter(Finding.finding_id == fid).first()
    meta = _REGISTRY.get(result.check_id)
    if not meta:
        return False
    check_def = db.query(CheckDefinition).filter(CheckDefinition.check_id == result.check_id).first()

    if existing:
        if existing.status in (FindingStatus.SUPPRESSED, FindingStatus.RISK_ACCEPTED):
            return False
        existing.last_seen = datetime.utcnow()
        existing.evidence  = result.evidence
        existing.status    = FindingStatus.OPEN
        return False

    f = Finding(
        id=hashlib.md5(f"{fid}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:32],
        finding_id=fid,
        check_def_id=check_def.id if check_def else None,
        check_id=result.check_id,
        asset_id=asset["id"],
        family=meta.family,
        severity=meta.severity,
        status=FindingStatus.OPEN,
        title=meta.name,
        description=meta.description,
        remediation=meta.remediation,
        provider=meta.provider,
        account_context=acct,
        region=asset.get("region", "global"),
        service=meta.service,
        resource_type=meta.resource_type,
        resource_display_name=asset.get("display_name"),
        native_id=asset.get("native_id"),
        arn=asset.get("arn"),
        azure_resource_id=asset.get("azure_resource_id"),
        universal_resource_name=asset["urn"],
        evidence=result.evidence,
        raw_evidence_blob=_sanitize(asset.get("raw_config", {})),
        compliance_frameworks=[
            m.get("framework") for m in (meta.compliance_mappings or []) if m.get("framework")
        ],
        resource_tags=asset.get("tags", {}),
        source_vendor=meta.source_vendor,
    )
    db.add(f)
    return True


def _sanitize(obj):
    """Recursively convert non-JSON-serializable types to safe equivalents.
    AWS API returns datetime, Decimal, and bytes in raw resource data."""
    from datetime import datetime as dt, date
    from decimal import Decimal
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize(v) for v in obj]
    if isinstance(obj, (dt, date)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return obj


def _upsert_asset(db, conn_id, provider, service, resource_type, urn, item, run_id):
    # Sanitize first: AWS/Azure/GCP APIs return datetime objects in many fields
    safe_item = _sanitize(item)
    config_hash = hashlib.sha256(
        json.dumps(safe_item, sort_keys=True, default=str).encode()
    ).hexdigest()
    asset = db.query(Asset).filter(Asset.universal_resource_name == urn).first()
    native_id = str(
        safe_item.get("ARN") or safe_item.get("id") or safe_item.get("name") or urn
    )[:255]
    display = _get_display_name(safe_item)
    if not asset:
        asset = Asset(
            connection_id=conn_id, provider=provider, service=service,
            resource_type=resource_type, native_id=native_id,
            universal_resource_name=urn,
            arn=safe_item.get("ARN"),
            azure_resource_id=safe_item.get("id") if provider == "azure" else None,
            display_name=display,
            region=safe_item.get("region") or safe_item.get("location") or "global",
            tags=safe_item.get("Tags") or safe_item.get("tags") or {},
            raw_config=safe_item, config_hash=config_hash,
        )
        db.add(asset)
        db.flush()
    else:
        asset.last_seen    = datetime.utcnow()
        asset.raw_config   = safe_item
        asset.config_hash  = config_hash
        asset.display_name = display or asset.display_name
    snap = AssetSnapshot(
        asset_id=asset.id, scan_run_id=run_id,
        raw_config=safe_item, config_hash=config_hash,
    )
    db.add(snap)
    return asset


def _build_urn(provider, acct, service, resource_type, item):
    region = item.get("region") or item.get("location") or "global"
    raw_id = (item.get("ARN") or item.get("id") or item.get("name")
              or item.get("BucketName") or str(item.get("_id", "")))
    safe_id = hashlib.md5(str(raw_id).encode()).hexdigest()[:16] if raw_id else "unknown"
    return f"cspm://{provider}/{acct}/{region}/{service}/{resource_type}/{safe_id}"


def _get_display_name(item) -> str:
    for k in ("Name", "name", "BucketName", "DBInstanceIdentifier",
              "FunctionName", "GroupName", "VpcId", "displayName", "title"):
        if item.get(k):
            return str(item[k])[:200]
    return ""


def _get_collector(provider: str):
    from backend.collectors import aws, azure, gcp, ibm, oci
    COLLECTORS = {
        "aws":   aws.AWSCollector,
        "azure": azure.AzureCollector,
        "gcp":   gcp.GCPCollector,
        "ibm":   ibm.IBMCollector,
        "oci":   oci.OCICollector,
    }
    cls = COLLECTORS.get(provider)
    if not cls:
        raise ValueError(f"No collector for provider '{provider}'")
    return cls()
