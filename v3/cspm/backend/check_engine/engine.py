"""
CloudGuard Pro CSPM v3 — Check Engine
Aniza Corp | Shahryar Jahangir
"""
from __future__ import annotations
import hashlib, logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# ── Registry ──────────────────────────────────────────────────────────────────
_REGISTRY: Dict[str, "CheckMeta"] = {}


@dataclass
class CheckMeta:
    check_id:               str
    name:                   str
    family:                 str
    provider:               str
    service:                str
    resource_type:          str
    severity:               str
    description:            str = ""
    remediation:            str = ""
    rationale:              str = ""
    impact:                 str = ""
    source_type:            str = "builtin"
    source_vendor:          str = ""
    source_product:         str = ""
    source_url:             str = ""
    source_version:         str = ""
    source_retrieved:       str = ""
    license_notes:          str = ""
    normalization_confidence: str = "high"
    enabled:                bool = True
    tags:                   Dict  = field(default_factory=dict)
    compliance_mappings:    List  = field(default_factory=list)
    logic_explanation:      str = ""
    implementation_code:    str = ""
    yaml_definition:        str = ""
    test_cases:             List  = field(default_factory=list)
    sample_payload:         Dict  = field(default_factory=dict)
    func:                   Optional[Callable] = field(default=None, repr=False)
    custom:                 bool = False


def register_check(meta: CheckMeta) -> None:
    _REGISTRY[meta.check_id] = meta
    log.debug("Registered check: %s", meta.check_id)


@dataclass
class CheckResult:
    check_id:  str
    passed:    bool
    evidence:  Dict = field(default_factory=dict)
    error:     str  = ""


def make_finding_id(check_id: str, urn: str) -> str:
    return hashlib.sha256(f"{check_id}::{urn}".encode()).hexdigest()[:32]


class CheckEngine:
    def run_checks_for_resource(self, resource: Dict, provider: str, service: str, resource_type: str) -> List[CheckResult]:
        results = []
        for check_id, meta in _REGISTRY.items():
            if not meta.enabled:
                continue
            if meta.provider != provider:
                continue
            if meta.service != service and meta.service not in ("*", "any"):
                continue
            if meta.resource_type != resource_type and meta.resource_type not in ("*", "any"):
                continue
            if not meta.func:
                continue
            try:
                result = meta.func(resource)
                if isinstance(result, tuple) and len(result) == 2:
                    passed, evidence = result
                else:
                    passed, evidence = bool(result), {}
                results.append(CheckResult(check_id=check_id, passed=bool(passed), evidence=evidence or {}))
            except Exception as e:
                results.append(CheckResult(check_id=check_id, passed=False, evidence={}, error=str(e)))
        return results


def load_all_checkpacks() -> None:
    """Load from family files (preferred) then fall back to legacy monolithic files."""
    from backend.check_engine.family_loader import load_family_files
    stats = load_family_files()

    if stats.get("checks_total", 0) == 0:
        # Fallback to original monolithic files
        log.warning("No checks from family files — falling back to legacy checkpacks")
        _load_legacy()
    else:
        log.info("Loaded %d checks from %d family files", stats["checks_total"], stats["files_loaded"] + stats.get("files_skipped", 0))

    # Always load custom checks on top
    try:
        from backend.custom_checks.loader import load_all_custom_checks
        load_all_custom_checks()
    except Exception as e:
        log.warning("Custom check loader error: %s", e)


def _load_legacy():
    """Legacy loader for monolithic checkpack files."""
    try:
        from backend.checkpacks.aws import checks as _  # noqa
        from backend.checkpacks.azure import checks as __ # noqa
        from backend.checkpacks.gcp import checks as ___  # noqa
        from backend.checkpacks.ibm_oci import checks as ____ # noqa
    except Exception as e:
        log.error("Legacy checkpack load failed: %s", e)
    log.info("Loaded %d checks from legacy checkpacks", len(_REGISTRY))
