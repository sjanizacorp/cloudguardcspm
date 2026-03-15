from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.models.database import init_db, SessionLocal
from app.api import assets, findings, compliance, dashboard, scan, schedules
import app.scheduler as sched_module
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing database...")
    init_db()
    logger.info("Starting scheduler...")
    sched_module.start_scheduler(SessionLocal)
    yield
    logger.info("Shutting down scheduler...")
    if sched_module.scheduler.running:
        sched_module.scheduler.shutdown(wait=False)


app = FastAPI(
    title="CloudGuard CSPM API",
    version="2.0.0",
    description="Multi-cloud Cloud Security Posture Management Platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard.router,   prefix="/api/dashboard",  tags=["Dashboard"])
app.include_router(assets.router,      prefix="/api/assets",     tags=["Assets"])
app.include_router(findings.router,    prefix="/api/findings",   tags=["Findings"])
app.include_router(compliance.router,  prefix="/api/compliance", tags=["Compliance"])
app.include_router(scan.router,        prefix="/api/scan",       tags=["Scan"])
app.include_router(schedules.router,   prefix="/api/schedules",  tags=["Schedules"])


@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0", "service": "CloudGuard CSPM"}
