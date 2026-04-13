"""
CloudGuard Pro CSPM v3 — Custom Check Loader
Aniza Corp | Shahryar Jahangir

Custom checks are stored as YAML files in backend/custom_checks/store/
They are loaded alongside the built-in family check files.
"""
from __future__ import annotations
import hashlib, json, logging, os, re, uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from backend.check_engine.engine import CheckMeta, register_check, _REGISTRY

log = logging.getLogger(__name__)

STORE_DIR = Path(__file__).parent / "store"
STORE_DIR.mkdir(exist_ok=True)

REQUIRED_FIELDS = {"check_id", "name", "family", "provider", "service", "resource_type", "severity"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
VALID_PROVIDERS  = {"aws", "azure", "gcp", "ibm", "oci", "custom"}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9_-]", "_", s.lower()).strip("_")


def load_all_custom_checks() -> List[Dict]:
    """Load and register all custom checks from the store directory."""
    loaded = []
    for path in sorted(STORE_DIR.glob("*.yaml")):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                continue
            meta = _dict_to_meta(data, path.stem)
            if meta:
                register_check(meta)
                loaded.append(data)
                log.debug("Loaded custom check: %s", data.get("check_id"))
        except Exception as e:
            log.warning("Failed to load custom check %s: %s", path.name, e)
    if loaded:
        log.info("Loaded %d custom checks from store.", len(loaded))
    return loaded


def save_custom_check(data: Dict) -> Dict:
    """Validate, save, and register a custom check. Returns saved dict."""
    # Validate required fields
    missing = REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(sorted(missing))}")

    check_id = data["check_id"].strip()
    if not re.match(r'^[a-z][a-z0-9\-]{2,60}$', check_id):
        raise ValueError("check_id must be lowercase alphanumeric with hyphens, 3-60 chars")
    if data.get("severity") not in VALID_SEVERITIES:
        raise ValueError(f"severity must be one of: {', '.join(VALID_SEVERITIES)}")

    # Add metadata
    data["custom"] = True
    data["source_vendor"] = data.get("source_vendor", "Aniza Corp — Custom")
    data["source_url"] = data.get("source_url", "")
    data["source_version"] = data.get("source_version", "1.0.0")
    data["created_at"] = data.get("created_at", datetime.utcnow().isoformat())
    data["updated_at"] = datetime.utcnow().isoformat()
    data["uid"] = data.get("uid") or str(uuid.uuid4())

    path = STORE_DIR / f"{_slug(check_id)}.yaml"
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    # Register in engine
    meta = _dict_to_meta(data, _slug(check_id))
    if meta:
        register_check(meta)

    log.info("Saved custom check: %s → %s", check_id, path.name)
    return data


def delete_custom_check(check_id: str) -> bool:
    slug = _slug(check_id)
    path = STORE_DIR / f"{slug}.yaml"
    if path.exists():
        path.unlink()
        # Remove from registry
        _REGISTRY.pop(check_id, None)
        log.info("Deleted custom check: %s", check_id)
        return True
    return False


def list_custom_checks() -> List[Dict]:
    results = []
    for path in sorted(STORE_DIR.glob("*.yaml")):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                results.append(data)
        except Exception as e:
            log.warning("Cannot read %s: %s", path.name, e)
    return results


def get_custom_check(check_id: str) -> Optional[Dict]:
    path = STORE_DIR / f"{_slug(check_id)}.yaml"
    if path.exists():
        with open(path) as f:
            return yaml.safe_load(f)
    return None


def export_checks(fmt: str = "json", include_builtin: bool = True, include_custom: bool = True) -> str:
    """Export checks as JSON or YAML string."""
    from backend.check_engine.engine import _REGISTRY
    checks = []

    if include_builtin:
        for cid, meta in _REGISTRY.items():
            if not getattr(meta, "custom", False):
                checks.append(_meta_to_dict(meta))

    if include_custom:
        for c in list_custom_checks():
            if c not in checks:
                checks.append(c)

    if fmt == "yaml":
        return yaml.dump(checks, default_flow_style=False, allow_unicode=True, sort_keys=False)
    return json.dumps(checks, indent=2, default=str)


def import_checks_from_string(content: str, fmt: str = "json", overwrite: bool = False) -> Dict:
    """Import checks from JSON or YAML string. Returns stats."""
    if fmt == "yaml":
        data = yaml.safe_load(content)
    else:
        data = json.loads(content)

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("Expected a list of check objects or a single check object")

    imported = skipped = errors = 0
    error_list = []

    for item in data:
        check_id = item.get("check_id", "")
        if not check_id:
            errors += 1
            error_list.append(f"Item missing check_id")
            continue

        # Check if it already exists
        existing_path = STORE_DIR / f"{_slug(check_id)}.yaml"
        if existing_path.exists() and not overwrite:
            skipped += 1
            continue

        # Force custom flag
        item["custom"] = True
        try:
            save_custom_check(item)
            imported += 1
        except Exception as e:
            errors += 1
            error_list.append(f"{check_id}: {e}")

    return {
        "imported": imported,
        "skipped": skipped,
        "errors": errors,
        "error_list": error_list,
    }


def _dict_to_meta(data: Dict, uid: str) -> Optional[CheckMeta]:
    """Convert a stored dict to a CheckMeta instance."""
    try:
        # Build a simple passthrough check function from the logic_explanation or description
        description = data.get("description", data.get("name", ""))
        logic = data.get("logic_explanation", "")

        def custom_check_fn(resource: Dict[str, Any]) -> tuple:
            # Custom checks without Python logic always pass (evidence-only)
            # Full Python logic can be added via implementation_code field
            return True, {"note": "Custom check — configure logic_explanation for evidence details"}

        # Try to compile implementation_code if provided
        impl = data.get("implementation_code", "")
        if impl and "def check(" in impl:
            try:
                ns = {}
                exec(compile(impl, "<custom>", "exec"), ns)
                if "check" in ns:
                    custom_check_fn = ns["check"]
            except Exception as e:
                log.warning("Could not compile implementation_code for %s: %s", data.get("check_id"), e)

        return CheckMeta(
            check_id=data["check_id"],
            name=data["name"],
            family=data.get("family", "Custom"),
            provider=data.get("provider", "custom"),
            service=data.get("service", "custom"),
            resource_type=data.get("resource_type", "custom"),
            severity=data.get("severity", "medium"),
            description=description,
            remediation=data.get("remediation", ""),
            rationale=data.get("rationale", ""),
            impact=data.get("impact", ""),
            source_type="custom",
            source_vendor=data.get("source_vendor", "Aniza Corp — Custom"),
            source_url=data.get("source_url", ""),
            source_version=data.get("source_version", "1.0.0"),
            source_retrieved=data.get("created_at", ""),
            license_notes=data.get("license_notes", ""),
            normalization_confidence=data.get("normalization_confidence", "custom"),
            enabled=data.get("enabled", True),
            tags=data.get("tags", {}),
            compliance_mappings=data.get("compliance_mappings", []),
            logic_explanation=logic,
            implementation_code=data.get("implementation_code", ""),
            yaml_definition=yaml.dump(data, default_flow_style=False),
            test_cases=data.get("test_cases", []),
            sample_payload=data.get("sample_payload", {}),
            func=custom_check_fn,
        )
    except Exception as e:
        log.warning("Cannot create CheckMeta from dict for %s: %s", data.get("check_id"), e)
        return None


def _meta_to_dict(meta) -> Dict:
    """Convert a CheckMeta to a dict for export."""
    return {
        "check_id": meta.check_id,
        "name": meta.name,
        "family": meta.family,
        "provider": meta.provider,
        "service": meta.service,
        "resource_type": meta.resource_type,
        "severity": meta.severity,
        "description": meta.description,
        "remediation": meta.remediation,
        "rationale": meta.rationale,
        "impact": meta.impact,
        "source_vendor": meta.source_vendor,
        "source_url": meta.source_url,
        "source_version": meta.source_version,
        "normalization_confidence": meta.normalization_confidence,
        "compliance_mappings": meta.compliance_mappings or [],
        "tags": meta.tags or {},
        "logic_explanation": meta.logic_explanation,
        "implementation_code": meta.implementation_code,
        "test_cases": meta.test_cases or [],
        "sample_payload": meta.sample_payload or {},
        "custom": getattr(meta, "custom", False),
    }
