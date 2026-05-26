"""
correlator.py
Cross-pillar correlation engine.

Joins findings from CASB, DSPM, ZIA, and ZPA by shared dimensions
(user, app/destination, timestamp window) to surface combined findings
that no single module would flag independently.

Combined finding examples:
  - CASB high-risk app + ZIA upload anomaly from same user → critical exfiltration finding
  - DSPM sensitive data finding + ZPA orphaned access to same data store → escalated IR finding
  - ZIA C2 beacon + ZPA lateral movement anomaly from same user → active compromise finding
  - CASB shadow AI usage + ZIA no AI Guard routing → policy gap + data risk combined finding
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ── Finding loaders ────────────────────────────────────────────────────────────

def _load_json(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def load_module_findings(output_dir: Path, slug: str) -> dict[str, list[dict]]:
    """Load the latest JSON findings from each module."""
    return {
        "casb": _load_json(output_dir / f"casb_risk_{slug}.json"),
        "dspm": _load_json(output_dir / f"dspm_risk_{slug}.json"),
        "zia":  _load_json(output_dir / f"zia_risk_{slug}.json"),
        "zpa":  _load_json(output_dir / f"zpa_risk_{slug}.json"),
    }


# ── Correlation rules ──────────────────────────────────────────────────────────

def correlate(findings: dict[str, list[dict]]) -> list[dict]:
    """
    Apply all correlation rules and return a list of combined findings,
    each with a composite_score, tier, narrative, and contributing modules.
    """
    combined = []

    casb = findings.get("casb", [])
    dspm = findings.get("dspm", [])
    zia  = findings.get("zia",  [])
    zpa  = findings.get("zpa",  [])

    # Build lookup indexes
    casb_by_user = _index_by(casb, "users")           # user → [apps]
    casb_high    = {a["name"] for a in casb if a.get("composite_score", 0) >= 50}
    casb_ai_apps = {a["name"] for a in casb if "AI" in a.get("category", "") or "LLM" in a.get("category", "")}

    dspm_by_path = _index_by(dspm, "location")        # location keyword → findings
    dspm_critical = [d for d in dspm if d.get("composite_score", 0) >= 75]

    zia_by_user  = _index_by(zia, "user")             # user → [events]
    zia_anomalies = [z for z in zia if z.get("tier") in ("critical", "high")]
    zia_c2       = [z for z in zia if "c2" in z.get("pattern", "").lower() or
                    "beacon" in z.get("pattern", "").lower()]
    zia_exfil    = [z for z in zia if "exfil" in z.get("pattern", "").lower() or
                    "upload" in z.get("pattern", "").lower()]

    zpa_by_user  = _index_by(zpa, "user")             # user → [access events]
    zpa_anomalies = [z for z in zpa if z.get("tier") in ("critical", "high")]
    zpa_orphaned = [z for z in zpa if z.get("type") == "orphaned_account"]

    # ── Rule 1: ZIA exfiltration + CASB high-risk app → same user ────────────
    for zia_event in zia_exfil:
        user = zia_event.get("user", "")
        user_casb = [a for a in casb if user and user in str(a.get("users_list", []))]
        high_risk_casb = [a for a in user_casb if a.get("composite_score", 0) >= 50]
        if high_risk_casb:
            combined.append({
                "id":             f"corr_exfil_casb_{user}",
                "type":           "exfiltration_via_shadow_app",
                "composite_score": min(100, zia_event.get("score", 70) + 15),
                "tier":           "critical",
                "modules":        ["zia", "casb"],
                "user":           user,
                "narrative": (
                    f"User {user or 'unknown'} triggered a ZIA data exfiltration pattern "
                    f"and simultaneously has access to {len(high_risk_casb)} high-risk "
                    f"shadow IT app(s) including {high_risk_casb[0].get('name', 'unknown')}. "
                    f"Combined signal indicates staged internal-to-external data movement."
                ),
                "actions": [
                    "Isolate user — restrict ZIA internet access pending investigation",
                    f"Block {high_risk_casb[0].get('name', 'app')} in ZIA Cloud App Control immediately",
                    "Pull ZIA full session log for user — last 24 hours",
                    "Cross-reference DSPM for sensitive data access by this user",
                ],
            })

    # ── Rule 2: DSPM critical finding + ZPA orphaned access to same data store ─
    for dspm_f in dspm_critical:
        location = dspm_f.get("location", "")
        # Look for orphaned ZPA users who could reach the same data store
        for orphan in zpa_orphaned:
            if _location_overlap(location, orphan.get("apps_accessible", [])):
                combined.append({
                    "id":             f"corr_dspm_orphan_{orphan.get('user','')}",
                    "type":           "sensitive_data_orphaned_access",
                    "composite_score": min(100, dspm_f.get("composite_score", 80) + 10),
                    "tier":           "critical",
                    "modules":        ["dspm", "zpa"],
                    "user":           orphan.get("user", "unknown"),
                    "narrative": (
                        f"A DSPM critical finding ({dspm_f.get('name', 'sensitive data')}) "
                        f"in {location} is reachable by orphaned ZPA account "
                        f"{orphan.get('user', 'unknown')} — {orphan.get('days_inactive', '?')} "
                        f"days after account deactivation. Confirmed access path exists."
                    ),
                    "actions": [
                        f"Revoke ZPA access for {orphan.get('user', 'user')} immediately",
                        "Audit DSPM data store access log for this account's history",
                        "Notify DPO — orphaned access to sensitive data may trigger breach notification",
                        "Check IdP deprovisioning workflow — close gap that allowed orphaned access",
                    ],
                })

    # ── Rule 3: ZIA C2 beacon + ZPA lateral movement (same user) ─────────────
    for c2 in zia_c2:
        user = c2.get("user", "")
        lateral = [z for z in zpa_anomalies
                   if z.get("user") == user and "lateral" in z.get("type", "").lower()]
        if lateral:
            combined.append({
                "id":             f"corr_c2_lateral_{user}",
                "type":           "active_compromise_c2_lateral",
                "composite_score": 99,
                "tier":           "critical",
                "modules":        ["zia", "zpa"],
                "user":           user,
                "narrative": (
                    f"ACTIVE COMPROMISE INDICATOR: User/device {user or 'unknown'} is "
                    f"simultaneously beaconing to a C2 endpoint (ZIA) and performing "
                    f"lateral movement across ZPA application segments. This combination "
                    f"strongly indicates a live threat actor with established persistence."
                ),
                "actions": [
                    "IMMEDIATE: Isolate device — remove from network / revoke ZCC tunnel",
                    "IMMEDIATE: Block C2 destination in ZIA Firewall Custom IP Blocklist",
                    "IMMEDIATE: Escalate to IR team — treat as active compromise",
                    "Revoke all ZPA segments for this user/device until IR investigation complete",
                    "Preserve all ZIA and ZPA logs for forensic chain of custody",
                ],
            })

    # ── Rule 4: Shadow AI (CASB) + No AI Guard routing (ZIA policy gap) ───────
    ai_guard_gap = any(
        "ai_guard" in z.get("gap_type", "").lower() or
        "llm" in z.get("gap_type", "").lower()
        for z in zia
    )
    if casb_ai_apps and ai_guard_gap:
        combined.append({
            "id":             "corr_shadow_ai_no_guard",
            "type":           "shadow_ai_no_inspection",
            "composite_score": 72,
            "tier":           "high",
            "modules":        ["casb", "zia"],
            "user":           "enterprise-wide",
            "narrative": (
                f"{len(casb_ai_apps)} consumer LLM service(s) are in active use "
                f"({', '.join(list(casb_ai_apps)[:3])}) but ZIA policy does not route this "
                f"traffic through AI Guard DaS. Prompt payloads are transiting without "
                f"DLP inspection or audit trail."
            ),
            "actions": [
                "Deploy AI Guard DaS — route all LLM category traffic through inspection",
                "Enable ZIA Cloud App Control for AI/LLM category requiring AI Guard routing",
                "Apply ZIA DLP policy on LLM upload path — detect code, PII, confidential content",
                "Define sanctioned LLM policy — approved tools with enterprise agreements only",
            ],
        })

    # ── Rule 5: DSPM sensitive data + ZPA over-scoped segment to same store ───
    for dspm_f in dspm_critical:
        location = dspm_f.get("location", "")
        overscoped = [z for z in zpa if z.get("type") == "overscoped_segment" and
                      _location_overlap(location, [z.get("destination", "")])]
        if overscoped:
            seg = overscoped[0]
            combined.append({
                "id":             f"corr_dspm_overscoped_{dspm_f.get('name','')}",
                "type":           "sensitive_data_overscoped_access",
                "composite_score": min(100, dspm_f.get("composite_score", 75) + 8),
                "tier":           "high",
                "modules":        ["dspm", "zpa"],
                "user":           "all ZPA users in segment",
                "narrative": (
                    f"DSPM has found sensitive data ({dspm_f.get('label', 'classified')}) "
                    f"in {location}. The ZPA segment providing access to this store is "
                    f"scoped to {seg.get('current_scope', 'broad range')} rather than the "
                    f"specific host(s) needed. Blast radius is unnecessarily large."
                ),
                "actions": [
                    f"Tighten ZPA segment scope to specific host(s) used: {seg.get('actual_scope', 'see ZPA logs')}",
                    f"Apply DSPM remediation for sensitive data in {location}",
                    "Review who has access to this ZPA segment — run entitlement sprawl check",
                ],
            })

    # Sort by composite score descending
    combined.sort(key=lambda x: -x.get("composite_score", 0))
    return combined


# ── Helpers ────────────────────────────────────────────────────────────────────

def _index_by(items: list[dict], key: str) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for item in items:
        val = str(item.get(key, "")).lower()
        if val:
            idx.setdefault(val, []).append(item)
    return idx


def _location_overlap(location: str, targets: list[str]) -> bool:
    """Rough overlap check — does location string share keywords with any target?"""
    loc = location.lower()
    for t in targets:
        words = set(t.lower().split())
        if any(w in loc for w in words if len(w) > 3):
            return True
    return False
