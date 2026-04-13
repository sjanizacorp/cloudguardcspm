"""
CloudGuard Pro CSPM v3 — API Routes: Checks
Aniza Corp | Shahryar Jahangir

Endpoints:
  GET  /checks               — list/filter/sort checks
  GET  /checks/families      — family list with counts
  GET  /checks/files         — list check family files on disk
  GET  /checks/export        — export checks as JSON or YAML
  POST /checks/update        — reload family files, detect changes
  POST /checks/import        — import checks from JSON/YAML
  GET  /checks/custom        — list custom checks
  POST /checks/custom        — create/update a custom check
  GET  /checks/custom/{id}   — get a single custom check
  PUT  /checks/custom/{id}   — update a custom check
  DEL  /checks/custom/{id}   — delete a custom check
  GET  /checks/custom/export — export custom checks only
  GET  /checks/{id}/code     — source + YAML + provenance
"""
from __future__ import annotations
import inspect, logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import asc, desc, func

from backend.database import get_db
from backend.models.models import CheckDefinition
from backend.models.schemas import CheckDefinitionOut as CheckOut, PaginatedResponse

router = APIRouter()
log = logging.getLogger(__name__)

SORT_FIELDS = {
    "check_id":          CheckDefinition.check_id,
    "name":              CheckDefinition.name,
    "provider":          CheckDefinition.provider,
    "family":            CheckDefinition.family,
    "severity":          CheckDefinition.severity,
    "service":           CheckDefinition.service,
    "resource_type":     CheckDefinition.resource_type,
    "source_vendor":     CheckDefinition.source_vendor,
    "source_version":    CheckDefinition.source_version,
    "status":            CheckDefinition.status,
    "collection_method": CheckDefinition.collection_method,
}


# ── List checks ────────────────────────────────────────────────────────────────
@router.get("/checks", response_model=PaginatedResponse)
def list_checks(
    page:          int           = Query(1, ge=1),
    page_size:     int           = Query(50, ge=1, le=500),
    provider:      Optional[str] = None,
    family:        Optional[str] = None,
    severity:      Optional[str] = None,
    service:       Optional[str] = None,
    search:        Optional[str] = None,
    custom_only:   bool          = Query(False),
    sort_by:       Optional[str] = Query("check_id"),
    sort_dir:      Optional[str] = Query("asc"),
    db: Session = Depends(get_db),
):
    q = db.query(CheckDefinition)
    if provider:
        q = q.filter(CheckDefinition.provider == provider)
    if family:
        q = q.filter(CheckDefinition.family.ilike(f"%{family}%"))
    if severity:
        q = q.filter(CheckDefinition.severity == severity)
    if service:
        q = q.filter(CheckDefinition.service == service)
    if search:
        q = q.filter(
            CheckDefinition.name.ilike(f"%{search}%") |
            CheckDefinition.check_id.ilike(f"%{search}%") |
            CheckDefinition.description.ilike(f"%{search}%")
        )
    if custom_only:
        q = q.filter(CheckDefinition.source_type == "custom")

    total = q.count()
    col = SORT_FIELDS.get(sort_by, CheckDefinition.check_id)
    direction = asc if sort_dir == "asc" else desc
    q = q.order_by(direction(col))
    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [CheckOut.from_orm(c) for c in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


# ── Family list ────────────────────────────────────────────────────────────────
@router.get("/checks/families")
def list_families(db: Session = Depends(get_db)):
    rows = db.query(CheckDefinition.family, func.count(CheckDefinition.id)).group_by(
        CheckDefinition.family
    ).order_by(CheckDefinition.family).all()
    return [{"family": r[0], "count": r[1]} for r in rows]


# ── Family file list ───────────────────────────────────────────────────────────
@router.get("/checks/files")
def list_check_files():
    """List all check family .py files on disk with metadata."""
    from backend.check_engine.family_loader import get_family_file_list
    return get_family_file_list()


# ── Export checks ──────────────────────────────────────────────────────────────
@router.get("/checks/export")
def export_checks(
    fmt:             str  = Query("json", description="json or yaml"),
    include_builtin: bool = Query(True),
    include_custom:  bool = Query(True),
    provider:        Optional[str] = None,
    family:          Optional[str] = None,
    severity:        Optional[str] = None,
):
    from backend.custom_checks.loader import export_checks as _export, _meta_to_dict
    from backend.check_engine.engine import _REGISTRY
    import json, yaml as _yaml

    checks = []
    for cid, meta in _REGISTRY.items():
        is_custom = getattr(meta, "custom", False) or getattr(meta, "source_type", "") == "custom"
        if is_custom and not include_custom:
            continue
        if not is_custom and not include_builtin:
            continue
        if provider and meta.provider != provider:
            continue
        if family and family.lower() not in (meta.family or "").lower():
            continue
        if severity and meta.severity != severity:
            continue
        checks.append(_meta_to_dict(meta))

    if fmt == "yaml":
        content = _yaml.dump(checks, default_flow_style=False, allow_unicode=True, sort_keys=False)
        media = "application/x-yaml"
        filename = "cloudguard_checks.yaml"
    else:
        content = json.dumps(checks, indent=2, default=str)
        media = "application/json"
        filename = "cloudguard_checks.json"

    return PlainTextResponse(content, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="{filename}"'
    })


# ── Update (reload family files) ───────────────────────────────────────────────
@router.post("/checks/update")
async def update_checks(force: bool = Query(False, description="Force reload all files even if unchanged")):
    """
    Reload check family files from disk. Detects changed/new/removed files.
    This endpoint allows you to update checks by dropping new .py files into
    checkpacks/families/{provider}/ and calling this endpoint.
    """
    from backend.check_engine.family_loader import load_family_files, check_for_updates
    from backend.custom_checks.loader import load_all_custom_checks
    from backend.check_engine.engine import load_all_checkpacks, _REGISTRY

    # First check what's changed
    update_info = check_for_updates()

    # Reload family files
    reload_stats = load_family_files(force=force)

    # Also reload custom checks
    custom_loaded = load_all_custom_checks()

    # Sync to DB
    from backend.database import db_session
    synced = _sync_registry_to_db()

    return {
        "status": "ok",
        "update_info": update_info,
        "reload_stats": reload_stats,
        "custom_checks_loaded": len(custom_loaded),
        "registry_total": len(_REGISTRY),
        "db_synced": synced,
        "message": (
            f"Reloaded {reload_stats['files_loaded'] + reload_stats['files_reloaded']} "
            f"family files. Registry now has {len(_REGISTRY)} checks."
        )
    }


# ── Import checks ──────────────────────────────────────────────────────────────
@router.post("/checks/import")
async def import_checks(body: dict):
    """
    Import checks from JSON or YAML content.
    Imported checks are saved as custom checks in backend/custom_checks/store/
    """
    from backend.custom_checks.loader import import_checks_from_string

    content   = body.get("content", "")
    fmt       = body.get("format", "json")
    overwrite = body.get("overwrite", False)

    if not content:
        raise HTTPException(400, "content is required")
    if fmt not in ("json", "yaml"):
        raise HTTPException(400, "format must be 'json' or 'yaml'")

    try:
        result = import_checks_from_string(content, fmt=fmt, overwrite=overwrite)
    except Exception as e:
        raise HTTPException(400, str(e))

    # Sync to DB
    _sync_registry_to_db()
    return result


# ── Custom checks CRUD ────────────────────────────────────────────────────────
@router.get("/checks/custom")
def list_custom():
    from backend.custom_checks.loader import list_custom_checks
    return list_custom_checks()


@router.post("/checks/custom")
async def create_custom(body: dict):
    from backend.custom_checks.loader import save_custom_check
    try:
        saved = save_custom_check(body)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _sync_registry_to_db()
    return saved


@router.get("/checks/custom/export")
def export_custom(fmt: str = Query("yaml")):
    from backend.custom_checks.loader import list_custom_checks
    import json, yaml as _yaml
    checks = list_custom_checks()
    if fmt == "yaml":
        content = _yaml.dump(checks, default_flow_style=False, allow_unicode=True, sort_keys=False)
        media = "application/x-yaml"
        fname = "cloudguard_custom_checks.yaml"
    else:
        content = json.dumps(checks, indent=2, default=str)
        media = "application/json"
        fname = "cloudguard_custom_checks.json"
    return PlainTextResponse(content, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="{fname}"'
    })


@router.get("/checks/custom/{check_id}")
def get_custom(check_id: str):
    from backend.custom_checks.loader import get_custom_check
    c = get_custom_check(check_id)
    if not c:
        raise HTTPException(404, f"Custom check '{check_id}' not found")
    return c


@router.put("/checks/custom/{check_id}")
async def update_custom(check_id: str, body: dict):
    from backend.custom_checks.loader import get_custom_check, save_custom_check, delete_custom_check
    existing = get_custom_check(check_id)
    if not existing:
        raise HTTPException(404, f"Custom check '{check_id}' not found")
    body["check_id"] = check_id  # enforce consistent ID
    if existing.get("created_at"):
        body["created_at"] = existing["created_at"]
    try:
        saved = save_custom_check(body)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _sync_registry_to_db()
    return saved


@router.delete("/checks/custom/{check_id}")
async def delete_custom(check_id: str):
    from backend.custom_checks.loader import delete_custom_check
    if not delete_custom_check(check_id):
        raise HTTPException(404, f"Custom check '{check_id}' not found")
    _sync_registry_to_db()
    return {"status": "deleted", "check_id": check_id}


# ── Check code/provenance ──────────────────────────────────────────────────────
@router.get("/checks/{check_id}/code")
def get_check_code(check_id: str, db: Session = Depends(get_db)):
    from backend.check_engine.engine import _REGISTRY
    import yaml as _yaml

    check_def = db.query(CheckDefinition).filter(CheckDefinition.check_id == check_id).first()
    meta = _REGISTRY.get(check_id)
    if not check_def and not meta:
        raise HTTPException(404, "Check not found")

    impl_code = ""
    if check_def:
        impl_code = check_def.implementation_code or ""
    if not impl_code and meta and meta.func:
        try:
            impl_code = inspect.getsource(meta.func)
        except Exception:
            pass

    yaml_def = ""
    if check_def and check_def.yaml_definition:
        yaml_def = check_def.yaml_definition
    elif meta:
        yaml_def = _yaml.dump({
            "check_id": check_id,
            "name": meta.name,
            "family": meta.family,
            "provider": meta.provider,
            "service": meta.service,
            "resource_type": meta.resource_type,
            "severity": meta.severity,
            "source": {"vendor": meta.source_vendor, "url": meta.source_url, "version": meta.source_version},
            "compliance_mappings": meta.compliance_mappings,
        }, default_flow_style=False)

    test_cases = []
    if check_def and check_def.test_cases:
        test_cases = check_def.test_cases
    elif meta and meta.test_cases:
        test_cases = meta.test_cases

    return {
        "check_id": check_id,
        "name":             check_def.name if check_def else (meta.name if meta else ""),
        "implementation_code": impl_code,
        "yaml_definition":  yaml_def,
        "source_vendor":    check_def.source_vendor if check_def else (meta.source_vendor if meta else ""),
        "source_url":       check_def.source_url    if check_def else (meta.source_url    if meta else ""),
        "source_version":   check_def.source_version if check_def else (meta.source_version if meta else ""),
        "license_notes":    check_def.license_notes if check_def else (meta.license_notes if meta else ""),
        "logic_explanation":check_def.logic_explanation if check_def else (meta.logic_explanation if meta else ""),
        "normalization_confidence": check_def.normalization_confidence if check_def else (meta.normalization_confidence if meta else ""),
        "test_cases":       test_cases,
        "custom":           getattr(meta, "custom", False) if meta else False,
        "family_file":      _get_family_file_path(check_id, check_def),
    }


def _get_family_file_path(check_id: str, check_def) -> str:
    """Return the disk path of the family file containing this check, if known."""
    from backend.checkpacks.families import __file__ as fam_init
    import os
    from pathlib import Path
    fam_dir = Path(fam_init).parent
    provider = check_def.provider if check_def else ""
    family = (check_def.family if check_def else "").lower().replace(" & ", "_").replace(" / ", "_").replace(" ", "_").replace("/", "_")
    candidate = fam_dir / provider / f"{family}.py"
    if candidate.exists():
        return str(candidate.relative_to(fam_dir.parent.parent.parent))
    return ""


def _sync_registry_to_db() -> int:
    """Sync checks in _REGISTRY to CheckDefinition table. Returns count synced."""
    from backend.check_engine.engine import _REGISTRY
    from backend.database import db_session
    from backend.models.models import CheckDefinition, CheckStatus, CheckType, CollectionMethod
    import hashlib, inspect, yaml as _yaml

    synced = 0
    with db_session() as db:
        for check_id, meta in _REGISTRY.items():
            existing = db.query(CheckDefinition).filter(CheckDefinition.check_id == check_id).first()
            code = meta.implementation_code
            if not code and meta.func:
                try:
                    code = inspect.getsource(meta.func)
                except Exception:
                    code = ""
            yaml_def = _yaml.dump({
                "check_id": meta.check_id, "name": meta.name,
                "family": meta.family, "provider": meta.provider,
                "source": {"vendor": meta.source_vendor, "url": meta.source_url},
            }, default_flow_style=False)

            if not existing:
                c = CheckDefinition(
                    id=hashlib.md5(check_id.encode()).hexdigest(),
                    check_id=check_id, family=meta.family, provider=meta.provider,
                    service=meta.service, resource_type=meta.resource_type,
                    severity=meta.severity, check_type=CheckType.CODE,
                    collection_method=CollectionMethod.API, name=meta.name,
                    description=meta.description, remediation=meta.remediation,
                    rationale=meta.rationale, impact=meta.impact,
                    source_type=getattr(meta, "source_type", "builtin"),
                    source_vendor=meta.source_vendor, source_product=getattr(meta,"source_product",""),
                    source_url=meta.source_url, source_version=meta.source_version,
                    source_retrieved=meta.source_retrieved, license_notes=meta.license_notes,
                    normalization_confidence=meta.normalization_confidence,
                    status=CheckStatus.IMPLEMENTED, enabled=meta.enabled,
                    tags=meta.tags, logic_explanation=meta.logic_explanation,
                    implementation_code=code, yaml_definition=yaml_def,
                    test_cases=meta.test_cases, sample_payload=meta.sample_payload,
                )
                db.add(c)
                synced += 1
            else:
                # Update mutable fields
                existing.name = meta.name
                existing.description = meta.description
                existing.remediation = meta.remediation
                existing.source_vendor = meta.source_vendor
                existing.source_url = meta.source_url
                existing.source_version = meta.source_version
                existing.implementation_code = code
                existing.logic_explanation = meta.logic_explanation
                existing.yaml_definition = yaml_def
                existing.test_cases = meta.test_cases
                synced += 1
    return synced
