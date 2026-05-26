"""
report_generator.py
Generates the unified weekly posture report from all four module digests
plus cross-pillar correlation findings.

Outputs:
  - posture_summary_YYYYMMDD.md   (human-readable, CISO-ready)
  - posture_summary_YYYYMMDD.json (machine-readable, dashboard-ready)
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def generate_posture_report(
    module_results: dict,
    combined_findings: list[dict],
    output_dir: Path,
    run_ts: str,
    slug: str,
) -> dict:
    """
    Build the unified posture report from module summaries + combined findings.
    Returns a summary dict with paths to generated files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    md   = _build_markdown(module_results, combined_findings, run_ts)
    data = _build_json(module_results, combined_findings, run_ts)

    md_path   = output_dir / f"posture_summary_{slug}.md"
    json_path = output_dir / f"posture_summary_{slug}.json"

    md_path.write_text(md)
    json_path.write_text(json.dumps(data, indent=2))

    critical_count = sum(1 for f in combined_findings if f.get("tier") == "critical")
    high_count     = sum(1 for f in combined_findings if f.get("tier") == "high")

    logger.info(f"Posture report written: {critical_count} critical, {high_count} high combined findings")

    return {
        "posture_md":           str(md_path),
        "posture_json":         str(json_path),
        "combined_critical":    critical_count,
        "combined_high":        high_count,
        "combined_total":       len(combined_findings),
    }


# ── Markdown builder ───────────────────────────────────────────────────────────

def _build_markdown(module_results: dict, combined: list[dict], run_ts: str) -> str:
    lines = [
        "# Unified Security Posture Report",
        f"**Generated:** {run_ts}  ",
        f"**Modules run:** {', '.join(k.upper() for k, v in module_results.items() if v.get('status') == 'ok')}",
        "",
    ]

    # ── Executive summary ─────────────────────────────────────────────────────
    critical = [f for f in combined if f.get("tier") == "critical"]
    high     = [f for f in combined if f.get("tier") == "high"]

    lines += [
        "---",
        "## Executive summary",
        "",
    ]

    if critical:
        lines.append(
            f"**{len(critical)} critical cross-pillar finding(s)** require immediate action. "
            f"The highest-risk finding is: {critical[0].get('narrative', '')[:150]}..."
        )
    else:
        lines.append("No critical cross-pillar findings this week.")

    if high:
        lines.append(f"**{len(high)} high-risk** combined finding(s) require action within 24 hours.")

    lines += ["", "---", "## Module summaries", ""]

    # ── Per-module summaries ──────────────────────────────────────────────────
    module_labels = {
        "casb": ("CASB — Shadow IT & app risk",    ["total", "critical", "high"]),
        "dspm": ("DSPM — Data exposure",           ["total", "critical", "high"]),
        "zia":  ("ZIA — Threat telemetry",         ["total", "critical", "high"]),
        "zpa":  ("ZPA — Access posture",           ["total", "critical", "high"]),
    }

    for key, (label, fields) in module_labels.items():
        r = module_results.get(key, {})
        if not r or r.get("status") == "error":
            lines.append(f"### {label}")
            lines.append(f"_Module error: {r.get('error', 'not configured')}_")
            lines.append("")
            continue

        lines.append(f"### {label}")
        total    = r.get("total", 0)
        crit     = r.get("critical", 0)
        high_n   = r.get("high", 0)
        medium_n = r.get("medium", 0)
        low_n    = r.get("low", 0)
        lines.append(
            f"{total} findings — "
            f"**{crit} critical** · {high_n} high · {medium_n} medium · {low_n} low"
        )
        if r.get("report"):
            lines.append(f"_Full report: {Path(r['report']).name}_")
        lines.append("")

    # ── Cross-pillar combined findings ────────────────────────────────────────
    if combined:
        lines += ["---", "## Cross-pillar combined findings", ""]
        for f in combined:
            tier_label = {"critical": "CRITICAL", "high": "HIGH",
                          "medium": "MEDIUM", "low": "LOW"}.get(f.get("tier", ""), "—")
            lines += [
                f"### [{tier_label}] {f.get('type', 'Combined finding').replace('_', ' ').title()}",
                f"**Score:** {f.get('composite_score', '—')}/100  "
                f"| **Modules:** {' + '.join(m.upper() for m in f.get('modules', []))}  "
                f"| **User/scope:** {f.get('user', '—')}",
                "",
                f"_{f.get('narrative', '')}_",
                "",
                "**Actions:**",
            ]
            for action in f.get("actions", []):
                lines.append(f"- {action}")
            lines.append("")
    else:
        lines += ["---", "## Cross-pillar combined findings", "",
                  "_No cross-pillar findings this week — modules ran independently._", ""]

    # ── Recommended priority actions ──────────────────────────────────────────
    lines += ["---", "## Recommended priority actions", ""]

    all_actions = []
    for f in combined:
        tier_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.get("tier", ""), 1)
        for action in f.get("actions", [])[:2]:  # top 2 actions per finding
            all_actions.append((tier_weight, f.get("tier", ""), action))

    all_actions.sort(key=lambda x: -x[0])
    seen = set()
    for _, tier, action in all_actions[:10]:
        if action not in seen:
            lines.append(f"- **[{tier.upper()}]** {action}")
            seen.add(action)

    if not all_actions:
        lines.append("_No immediate actions required from combined findings._")

    lines += [
        "",
        "---",
        f"_Report generated by Unified AI Advisory Pipeline · {run_ts}_",
    ]

    return "\n".join(lines)


# ── JSON builder ───────────────────────────────────────────────────────────────

def _build_json(module_results: dict, combined: list[dict], run_ts: str) -> dict:
    return {
        "run_ts":            run_ts,
        "module_summaries":  module_results,
        "combined_findings": combined,
        "stats": {
            "combined_critical": sum(1 for f in combined if f.get("tier") == "critical"),
            "combined_high":     sum(1 for f in combined if f.get("tier") == "high"),
            "combined_total":    len(combined),
        },
    }
