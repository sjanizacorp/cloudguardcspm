"""
CloudGuard Pro CSPM v3 — Family File Loader
Aniza Corp | Shahryar Jahangir

Loads checks from backend/checkpacks/families/{provider}/{family}.py
Each file can be replaced independently to update a check family.

Update process:
  1. Drop a new .py file into checkpacks/families/{provider}/
  2. Call the /checks/update endpoint (or restart)
  3. The engine re-loads the file and re-registers the checks
"""
from __future__ import annotations
import glob, importlib.util, logging, os, runpy, time
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

FAMILIES_DIR = Path(__file__).parent.parent / "checkpacks" / "families"

# Version manifest: tracks file mtimes to detect changes
_FILE_VERSIONS: Dict[str, float] = {}


def load_family_files(force: bool = False) -> Dict:
    """
    Load all check family files. Returns stats dict.
    If force=True, reloads all files even if unchanged.
    """
    from backend.check_engine.engine import _REGISTRY

    before = len(_REGISTRY)
    loaded = reloaded = skipped = errors = 0
    error_list = []
    files_scanned = 0

    family_files = sorted(FAMILIES_DIR.glob("**/*.py"))
    files_scanned = len(family_files)

    for fp in family_files:
        if fp.name == "__init__.py":
            continue
        key = str(fp)
        mtime = fp.stat().st_mtime

        if not force and key in _FILE_VERSIONS and _FILE_VERSIONS[key] == mtime:
            skipped += 1
            continue

        try:
            runpy.run_path(str(fp))
            if key in _FILE_VERSIONS:
                reloaded += 1
            else:
                loaded += 1
            _FILE_VERSIONS[key] = mtime
        except Exception as e:
            errors += 1
            error_list.append(f"{fp.parent.name}/{fp.name}: {e}")
            log.warning("Failed to load family file %s: %s", fp, e)

    after = len(_REGISTRY)
    new_checks = after - before

    stats = {
        "files_scanned": files_scanned,
        "files_loaded": loaded,
        "files_reloaded": reloaded,
        "files_skipped": skipped,
        "files_errored": errors,
        "checks_total": after,
        "checks_added": new_checks,
        "errors": error_list,
    }

    if loaded or reloaded:
        log.info(
            "Family loader: scanned=%d loaded=%d reloaded=%d errors=%d total_checks=%d",
            files_scanned, loaded, reloaded, errors, after
        )

    return stats


def get_family_file_list() -> List[Dict]:
    """List all family files with their metadata."""
    result = []
    for fp in sorted(FAMILIES_DIR.glob("**/*.py")):
        if fp.name == "__init__.py":
            continue
        stat = fp.stat()
        provider = fp.parent.name
        family_slug = fp.stem
        result.append({
            "path": str(fp.relative_to(FAMILIES_DIR.parent.parent)),
            "provider": provider,
            "family_slug": family_slug,
            "file_name": fp.name,
            "size_bytes": stat.st_size,
            "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
            "is_loaded": str(fp) in _FILE_VERSIONS,
            "is_stale": str(fp) in _FILE_VERSIONS and _FILE_VERSIONS[str(fp)] != stat.st_mtime,
        })
    return result


def check_for_updates() -> Dict:
    """
    Scan family files for changes (modified, new, removed).
    Returns a summary of what would change on reload.
    """
    changed = []
    new = []
    removed_keys = set(_FILE_VERSIONS.keys())

    for fp in sorted(FAMILIES_DIR.glob("**/*.py")):
        if fp.name == "__init__.py":
            continue
        key = str(fp)
        removed_keys.discard(key)
        mtime = fp.stat().st_mtime

        if key not in _FILE_VERSIONS:
            new.append(str(fp.relative_to(FAMILIES_DIR.parent.parent)))
        elif _FILE_VERSIONS[key] != mtime:
            changed.append(str(fp.relative_to(FAMILIES_DIR.parent.parent)))

    removed = [str(Path(k).relative_to(FAMILIES_DIR.parent.parent)) for k in removed_keys]

    return {
        "new_files": new,
        "changed_files": changed,
        "removed_files": removed,
        "update_available": bool(new or changed or removed),
    }
