"""
unified_pipeline.py
Orchestrates CASB, DSPM, ZIA, and ZPA modules in a single weekly run.
Produces four individual digests + one unified posture report.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./reports"))


# ── Module imports (each module is self-contained) ────────────────────────────

def _import_modules():
    """Lazy import so missing optional modules don't break startup."""
    modules = {}
    try:
        from casb_pipeline import run_pipeline as casb_run
        modules["casb"] = casb_run
    except ImportError:
        logger.warning("CASB module not available")

    try:
        from dspm_pipeline import run_pipeline as dspm_run
        modules["dspm"] = dspm_run
    except ImportError:
        logger.warning("DSPM module not available")

    try:
        from zia_pipeline import run_pipeline as zia_run
        modules["zia"] = zia_run
    except ImportError:
        logger.warning("ZIA module not available")

    try:
        from zpa_pipeline import run_pipeline as zpa_run
        modules["zpa"] = zpa_run
    except ImportError:
        logger.warning("ZPA module not available")

    return modules


# ── Run sequence ───────────────────────────────────────────────────────────────

def run_all_modules(dry_run: bool = False) -> dict:
    """
    Run all four modules sequentially.
    Returns dict of {module: summary} for each completed module.

    Sequence: ZIA → CASB → DSPM → ZPA
      ZIA first  — produces threat context that enriches other modules
      CASB/DSPM  — data layer modules, independent of each other
      ZPA last   — access control module, can cross-reference CASB/DSPM findings
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    slug = datetime.now(timezone.utc).strftime("%Y%m%d")
    results = {}

    modules = _import_modules()
    run_order = ["zia", "casb", "dspm", "zpa"]

    for name in run_order:
        if name not in modules:
            logger.info(f"Skipping {name.upper()} — module not configured")
            continue

        logger.info(f"Starting {name.upper()} module...")
        try:
            summary = modules[name](dry_run=dry_run)
            results[name] = {"status": "ok", **summary}
            logger.info(f"{name.upper()} complete: {summary}")
        except Exception as e:
            logger.error(f"{name.upper()} failed: {e}")
            results[name] = {"status": "error", "error": str(e)}

    return results
