"""
app.py — Unified AI Advisory Pipeline
FastAPI service exposing all four modules + unified posture report.

Endpoints:
  POST /pipeline/run              — trigger full four-module run
  POST /pipeline/dry-run          — run with sample data, no Zscaler API calls
  GET  /pipeline/status           — last run summary
  GET  /reports                   — list all generated reports
  GET  /reports/{filename}        — download a report
  GET  /posture/latest            — latest unified posture report (JSON)
  GET  /health                    — service health + scheduler status

Scheduler: full pipeline runs every Monday 06:00 UTC automatically.
"""

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from unified_pipeline import run_all_modules, OUTPUT_DIR
from correlator import load_module_findings, correlate
from report_generator import generate_posture_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_last_run: dict = {}
scheduler = AsyncIOScheduler()


def _full_pipeline(dry_run: bool = False):
    """Complete pipeline: run modules → correlate → unified report."""
    global _last_run

    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    slug   = datetime.now(timezone.utc).strftime("%Y%m%d")

    # 1. Run all four modules
    logger.info(f"Pipeline start — dry_run={dry_run}")
    module_results = run_all_modules(dry_run=dry_run)

    # 2. Load findings and correlate
    findings = load_module_findings(OUTPUT_DIR, slug)
    combined = correlate(findings)
    logger.info(f"Correlation complete: {len(combined)} combined findings")

    # 3. Generate unified posture report
    posture_summary = generate_posture_report(
        module_results=module_results,
        combined_findings=combined,
        output_dir=OUTPUT_DIR,
        run_ts=run_ts,
        slug=slug,
    )

    _last_run = {
        "run_ts":       run_ts,
        "dry_run":      dry_run,
        "modules":      module_results,
        "correlation":  {"total": len(combined), "critical": posture_summary["combined_critical"]},
        "posture":      posture_summary,
    }
    logger.info(f"Pipeline complete: {_last_run}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.add_job(
        lambda: _full_pipeline(dry_run=False),
        CronTrigger(day_of_week="mon", hour=6, minute=0, timezone="UTC"),
        id="unified_weekly",
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Scheduler started — unified pipeline runs every Monday 06:00 UTC")
    yield
    scheduler.shutdown()


app = FastAPI(title="Unified AI Advisory Pipeline — CASB + DSPM + ZIA + ZPA", lifespan=lifespan)


@app.post("/pipeline/run")
async def trigger_run(background_tasks: BackgroundTasks):
    """Trigger full live pipeline run."""
    background_tasks.add_task(_full_pipeline, dry_run=False)
    return {"status": "started", "message": "Full pipeline running. Poll /pipeline/status."}


@app.post("/pipeline/dry-run")
async def trigger_dry_run(background_tasks: BackgroundTasks):
    """Trigger dry-run — sample data, no Zscaler API calls needed."""
    background_tasks.add_task(_full_pipeline, dry_run=True)
    return {"status": "started", "message": "Dry-run pipeline started. Poll /pipeline/status."}


@app.get("/pipeline/status")
def pipeline_status():
    if not _last_run:
        return {"status": "no_run_yet"}
    return {"status": "complete", **_last_run}


@app.get("/posture/latest")
def latest_posture():
    """Return the most recent unified posture report as JSON."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(OUTPUT_DIR.glob("posture_summary_*.json"), reverse=True)
    if not files:
        raise HTTPException(404, "No posture report generated yet")
    return json.loads(files[0].read_text())


@app.get("/reports")
def list_reports():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(OUTPUT_DIR.glob("*.md"), reverse=True)
    return [
        {"filename": f.name, "size_kb": round(f.stat().st_size / 1024, 1)}
        for f in files
    ]


@app.get("/reports/{filename}", response_class=PlainTextResponse)
def get_report(filename: str):
    path = OUTPUT_DIR / filename
    if not path.exists() or path.suffix not in (".md", ".json"):
        raise HTTPException(404, "Report not found")
    return path.read_text()


@app.get("/health")
def health():
    return {
        "status":           "ok",
        "scheduler_running": scheduler.running,
        "last_run":         _last_run.get("run_ts", "never"),
    }
