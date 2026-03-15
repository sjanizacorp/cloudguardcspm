import logging
import uuid
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)
scheduler = AsyncIOScheduler()


def start_scheduler(db_factory):
    """Start the APScheduler and reload any saved scheduled scans from DB."""
    scheduler.start()
    try:
        db = db_factory()
        _reload_jobs(db, db_factory)
        db.close()
    except Exception as e:
        logger.error(f"Scheduler startup error: {e}")


def _reload_jobs(db: Session, db_factory):
    from app.models.db_models import ScheduledScan
    scans = db.query(ScheduledScan).filter_by(enabled=True).all()
    for s in scans:
        _add_job(s.id, s.cron_expression, s.cloud_config, db_factory)
    logger.info(f"Reloaded {len(scans)} scheduled scans")


def _add_job(scan_id: str, cron: str, cloud_config: dict, db_factory):
    try:
        parts = cron.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron: {cron}")
        minute, hour, day, month, day_of_week = parts
        scheduler.add_job(
            _run_scheduled_scan,
            CronTrigger(minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week),
            args=[scan_id, cloud_config, db_factory],
            id=scan_id,
            replace_existing=True,
            misfire_grace_time=300,
        )
        logger.info(f"Scheduled job added: {scan_id} ({cron})")
    except Exception as e:
        logger.error(f"Failed to add scheduled job {scan_id}: {e}")


async def _run_scheduled_scan(scan_id: str, cloud_config: dict, db_factory):
    from app.scan_orchestrator import ScanOrchestrator
    from app.models.db_models import ScheduledScan
    logger.info(f"Running scheduled scan: {scan_id}")
    db = db_factory()
    try:
        sched = db.query(ScheduledScan).filter_by(id=scan_id).first()
        if not sched or not sched.enabled:
            return
        orchestrator = ScanOrchestrator(db)
        await orchestrator.run_scan_async(cloud_config, triggered_by="scheduled")
        sched.last_run = datetime.utcnow()
        sched.run_count = (sched.run_count or 0) + 1
        db.commit()
    except Exception as e:
        logger.error(f"Scheduled scan {scan_id} failed: {e}")
    finally:
        db.close()


def add_scheduled_scan(scan_id: str, cron: str, cloud_config: dict, db_factory):
    _add_job(scan_id, cron, cloud_config, db_factory)


def remove_scheduled_scan(scan_id: str):
    try:
        scheduler.remove_job(scan_id)
        logger.info(f"Removed scheduled job: {scan_id}")
    except Exception:
        pass


def get_next_run_time(scan_id: str):
    try:
        job = scheduler.get_job(scan_id)
        return job.next_run_time if job else None
    except Exception:
        return None
