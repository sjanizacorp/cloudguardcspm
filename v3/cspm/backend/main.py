"""
CloudGuard Pro CSPM v3 — FastAPI Application
Aniza Corp | Shahryar Jahangir
"""
import logging
import logging.handlers
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from backend.database import init_db
from backend.check_engine.engine import load_all_checkpacks
from backend.api.routes import (
    connections, assets, findings, checks, scans, reports, dashboard, health
)

# ── Logging: rotate at 100 MB ─────────────────────────────────────────────────
LOG_DIR = Path(os.environ.get("LOG_DIR", "logs"))
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "cloudguard.log"

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=100 * 1024 * 1024, backupCount=5, encoding="utf-8"
)
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s %(levelname)-8s %(name)s — %(message)s"
))
root_logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    "%(asctime)s %(levelname)s %(name)s — %(message)s"
))
root_logger.addHandler(console_handler)

log = logging.getLogger(__name__)

FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"
_INDEX = FRONTEND_DIST / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("CloudGuard Pro v3 starting up...")
    log.info("Log file: %s (rotating at 100 MB)", LOG_FILE.resolve())

    init_db()
    load_all_checkpacks()

    seed_enabled = os.environ.get("SEED_DEMO_DATA", "true").lower()
    if seed_enabled in ("true", "1", "yes"):
        from backend.seed import seed_demo_data
        seed_demo_data()
        log.info("Demo data seeding: ENABLED  (set SEED_DEMO_DATA=false in .env to disable)")
    else:
        log.info("Demo data seeding: DISABLED  (SEED_DEMO_DATA=%s)", seed_enabled)

    log.info("Startup complete.")
    yield
    log.info("CloudGuard Pro v3 shutting down.")


app = FastAPI(
    title="CloudGuard Pro CSPM API",
    description="Multi-cloud Cloud Security Posture Management — Aniza Corp",
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Routes ─────────────────────────────────────────────────────────────────
app.include_router(health.router,      prefix="/api/v1", tags=["Health"])
app.include_router(dashboard.router,   prefix="/api/v1", tags=["Dashboard"])
app.include_router(connections.router, prefix="/api/v1", tags=["Connections"])
app.include_router(assets.router,      prefix="/api/v1", tags=["Assets"])
app.include_router(findings.router,    prefix="/api/v1", tags=["Findings"])
app.include_router(checks.router,      prefix="/api/v1", tags=["Checks"])
app.include_router(scans.router,       prefix="/api/v1", tags=["Scans"])
app.include_router(reports.router,     prefix="/api/v1", tags=["Reports"])

# ── Frontend SPA ───────────────────────────────────────────────────────────────
# Serve our self-contained index.html for every non-API path.
# We deliberately do NOT mount /assets as a StaticFiles directory —
# that would allow old Vite build artifacts to override our index.html.
# Individual static files (svg, ico, etc.) in dist/ are served by the catch-all.

if _INDEX.exists():
    log.info("Frontend: %s", _INDEX.resolve())

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        # Serve a real file if it exists (e.g. shield.svg, favicon.ico)
        # but NEVER serve the assets/ directory's JS/CSS — those are stale Vite artifacts
        if full_path and not full_path.startswith("assets/"):
            requested = FRONTEND_DIST / full_path
            if requested.is_file():
                return FileResponse(str(requested))
        # Everything else → our self-contained SPA
        return FileResponse(str(_INDEX))

else:
    log.warning("frontend/dist/index.html not found. Re-extract the CloudGuard package.")

    @app.get("/", include_in_schema=False)
    async def serve_root():
        return HTMLResponse(
            "<h1>CloudGuard Pro CSPM v3</h1>"
            "<p>Frontend not found. Re-extract the package.</p>"
            "<p>API docs: <a href='/docs'>/docs</a></p>"
        )

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_fallback(full_path: str):
        return HTMLResponse("<h1>CloudGuard Pro</h1><p><a href='/docs'>API Docs</a></p>")
