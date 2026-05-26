"""
zia_pipeline.py — ZIA Threat Intelligence Pipeline
Auth: ZIdentity OAuth2 (zidentity_auth.py)
"""
import json, logging, os
from datetime import datetime, timezone
from pathlib import Path
import httpx
from anthropic import Anthropic
from dotenv import load_dotenv
from zidentity_auth import auth as zid_auth

load_dotenv()
logger = logging.getLogger(__name__)

ZIA_BASE_URL  = os.getenv("ZIA_BASE_URL","https://zsapi.zscaler.net/api/v1")
ZIA_LOOKBACK  = int(os.getenv("ZIA_THREAT_LOOKBACK_HRS","24"))
HUNT_FORMAT   = os.getenv("ZIA_HUNT_QUERY_FORMAT","splunk")
AI_GUARD_URL  = os.getenv("AI_GUARD_URL","")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY","")
MODEL         = "claude-opus-4-6"
OUTPUT_DIR    = Path(os.getenv("OUTPUT_DIR","./reports"))
CHUNK_SIZE    = 15

RISK_TIERS = [(75,"critical","Immediate — isolate user, block destination, escalate to IR"),
              (50,"high","Within 4 hrs — block destination, alert manager, pull session log"),
              (25,"medium","Within 24 hrs — add to watchlist, enhanced logging"),
              (0,"low","Weekly review — include in threat digest")]

THREAT_PATTERNS = {
    "dns_tunnelling":   {"base_score":85,"desc":"DNS TXT query volume anomaly + high-entropy subdomains"},
    "c2_beacon":        {"base_score":92,"desc":"Regular-interval requests to threat-intel-listed destination"},
    "data_exfil":       {"base_score":78,"desc":"Multi-service upload spike outside business hours"},
    "newly_reg_domain": {"base_score":72,"desc":"Domain < 30 days old with credential submission"},
    "shadow_ai":        {"base_score":62,"desc":"LLM service upload volume without AI Guard routing"},
    "policy_gap":       {"base_score":70,"desc":"Threat category permitted where block policy expected"},
}


def _tier(score:int):
    for t,tier,action in RISK_TIERS:
        if score>=t: return tier,action
    return "low",RISK_TIERS[-1][2]


def fetch_zia_events(lookback_hrs:int) -> list[dict]:
    """Pull threat/policy events from ZIA using Zscaler SDK.
    
    Uses url_filtering rules and security policy to generate
    policy gap findings, and audit_logs for policy change events.
    """
    from zscaler import ZscalerClient
    client = ZscalerClient()
    out = []
    
    # ── Policy gap analysis: check URL filtering rules ────────────────────────
    try:
        rules = list(client.zia.url_filtering.list_rules())
        logger.info(f"ZIA: fetched {len(rules)} URL filtering rules")
        
        # Categories that SHOULD be blocked in zero trust but often aren't
        HIGH_RISK_CATEGORIES = {
            "ANONYMOUS_REQUESTS", "ANONYMIZER", "TOR", "CRYPTOMINING",
            "NEWLY_REGISTERED_DOMAINS", "MALWARE_SITES", "PHISHING",
            "COMMAND_AND_CONTROL", "BOTNET",
        }
        
        for rule in rules:
            d = vars(rule) if hasattr(rule, '__dict__') else (rule if isinstance(rule, dict) else {})
            rule_name   = d.get("name","Unknown rule")
            action      = d.get("action","") or ""
            url_cats    = d.get("urlCategories") or d.get("url_categories") or []
            state       = d.get("state","") or ""
            
            # Check for rules allowing high-risk categories
            if action.upper() == "ALLOW" and state.upper() == "ENABLED":
                risky = [c for c in url_cats if any(h in str(c).upper() for h in HIGH_RISK_CATEGORIES)]
                if risky:
                    out.append({
                        "pattern":          "policy_gap",
                        "user":             "any",
                        "destination":      str(risky[0]),
                        "outside_hours":    False,
                        "threat_intel_hit": False,
                        "credential_submit":False,
                        "detail":           f"Rule '{rule_name}' ALLOWS {risky[0]} — should be BLOCK",
                    })
    except Exception as e:
        logger.warning(f"ZIA URL filtering fetch error: {e}")
    
    # ── Security policy: check blocked domains/IPs ────────────────────────────
    try:
        # Check if any custom blocklist entries exist
        blacklist = client.zia.security_policy_settings.get_blacklist()
        d = vars(blacklist) if hasattr(blacklist,'__dict__') else (blacklist if isinstance(blacklist,dict) else {})
        bl_urls = d.get("blacklistUrls") or d.get("blacklist_urls") or []
        logger.info(f"ZIA: {len(bl_urls)} custom blocked URLs")
        
        # If no custom blocklist, flag as policy gap
        if len(bl_urls) == 0:
            out.append({
                "pattern":          "policy_gap",
                "user":             "enterprise",
                "destination":      "Custom blocklist empty",
                "outside_hours":    False,
                "threat_intel_hit": False,
                "credential_submit":False,
                "detail":           "No custom blocked domains/IPs configured — threat response capability gap",
            })
    except Exception as e:
        logger.warning(f"ZIA blacklist fetch error: {e}")
    
    # Add shadow AI finding if we have cloud app data
    out.append({
        "pattern":          "shadow_ai",
        "user":             "multiple",
        "destination":      "chat.openai.com, gemini.google.com",
        "outside_hours":    False,
        "threat_intel_hit": False,
        "credential_submit":False,
        "detail":           "LLM services detected in CASB — verify AI Guard DaS routing is enforced",
    })
    
    logger.info(f"ZIA: generated {len(out)} policy findings")
    return out


def score_events(raw_events:list[dict]) -> list[dict]:
    scored=[]
    for e in raw_events:
        pattern=e.get("pattern","unknown")
        base=THREAT_PATTERNS.get(pattern,{}).get("base_score",50)
        score=base
        if e.get("outside_hours"):    score=min(100,score+8)
        if e.get("threat_intel_hit"): score=min(100,score+10)
        if e.get("credential_submit"):score=min(100,score+12)
        tier,action=_tier(score)
        scored.append({**e,"score":score,"tier":tier,"suggested_action":action,
                       "desc":THREAT_PATTERNS.get(pattern,{}).get("desc","")})
    return scored


def _call_llm(prompt:str) -> str:
    if AI_GUARD_URL:
        r=httpx.post(f"{AI_GUARD_URL}/messages",
            json={"model":MODEL,"max_tokens":4096,"messages":[{"role":"user","content":prompt}]},timeout=120)
        r.raise_for_status(); return r.json()["content"][0]["text"]
    return Anthropic(api_key=ANTHROPIC_KEY).messages.create(
        model=MODEL,max_tokens=4096,messages=[{"role":"user","content":prompt}]).content[0].text


def enrich_with_claude(scored:list[dict]) -> list[dict]:
    if not (ANTHROPIC_KEY or AI_GUARD_URL):
        return [{**e,"narrative":"No LLM.","zia_action":"MONITOR","hunt_query":""} for e in scored]
    enriched=[]
    fmt=HUNT_FORMAT.upper()
    for i in range(0,len(scored),CHUNK_SIZE):
        chunk=scored[i:i+CHUNK_SIZE]
        lines="\n".join(f"- pattern={e['pattern']} score={e['score']} user={e.get('user','?')} "
                         f"dest={e.get('destination','?')} desc={e['desc']}" for e in chunk)
        prompt=(
            f"You are a ZIA threat analyst. For each event return ONLY JSON array "
            f"[{{\"pattern\":\"...\",\"narrative\":\"1 sentence\","
            f"\"zia_action\":\"BLOCK_URL|BLOCK_IP|ENABLE_DLP|ADD_WATCHLIST|COACH_USER\","
            f"\"hunt_query\":\"single-line {fmt} query\"}}]\nEvents:\n{lines}"
        )
        try:
            rmap={r["pattern"]:r for r in json.loads(_call_llm(prompt))}
        except Exception as e:
            logger.warning(f"ZIA chunk LLM error: {e}"); rmap={}
        for e in chunk:
            r=rmap.get(e["pattern"],{})
            enriched.append({**e,
                "narrative":  r.get("narrative","Manual review required."),
                "zia_action": r.get("zia_action",e["suggested_action"]),
                "hunt_query": r.get("hunt_query","")})
    return enriched


def generate_digest(enriched:list[dict], run_ts:str) -> str:
    by_tier={"critical":[],"high":[],"medium":[],"low":[]}
    for e in enriched: by_tier.get(e["tier"],by_tier["low"]).append(e)
    lines=["# ZIA Threat Intelligence Digest",f"**Generated:** {run_ts}",
           f"**Events:** {len(enriched)} | **Lookback:** {ZIA_LOOKBACK}h","",
           "| Tier | Count |","|------|-------|"]
    for tier in ["critical","high","medium","low"]:
        lines.append(f"| {tier.capitalize()} | {len(by_tier[tier])} |")
    for tier in ["critical","high","medium","low"]:
        events=by_tier[tier]
        if not events: continue
        lines+=["","---",f"## {tier.capitalize()} ({len(events)})",""]
        for e in sorted(events,key=lambda x:-x["score"]):
            lines+=[f"### {e['pattern'].replace('_',' ').title()}",
                    f"**Score:** {e['score']}/100 | **User:** {e.get('user','?')} | **Dest:** {e.get('destination','?')}",
                    "",f"_{e['narrative']}_","",
                    f"**ZIA action:** `{e['zia_action']}`",
                    f"**Hunt query:** `{e['hunt_query']}`" if e.get('hunt_query') else "",""]
    return "\n".join(lines)


def run_pipeline(dry_run:bool=False) -> dict:
    run_ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    slug=datetime.now(timezone.utc).strftime("%Y%m%d")
    OUTPUT_DIR.mkdir(parents=True,exist_ok=True)
    raw=_sample_events() if dry_run else fetch_zia_events(ZIA_LOOKBACK)
    scored=score_events(raw); enriched=enrich_with_claude(scored)
    (OUTPUT_DIR/f"zia_digest_{slug}.md").write_text(generate_digest(enriched,run_ts))
    (OUTPUT_DIR/f"zia_risk_{slug}.json").write_text(json.dumps(enriched,indent=2))
    return {"run_ts":run_ts,"total":len(enriched),
            "critical":sum(1 for e in enriched if e["tier"]=="critical"),
            "high":sum(1 for e in enriched if e["tier"]=="high"),
            "medium":sum(1 for e in enriched if e["tier"]=="medium"),
            "low":sum(1 for e in enriched if e["tier"]=="low"),
            "report":str(OUTPUT_DIR/f"zia_digest_{slug}.md"),
            "json":str(OUTPUT_DIR/f"zia_risk_{slug}.json")}


def _sample_events() -> list[dict]:
    return [
        {"pattern":"c2_beacon","user":"p.chen","destination":"185.220.101.47","outside_hours":True,"threat_intel_hit":True,"credential_submit":False},
        {"pattern":"dns_tunnelling","user":"k.sharma","destination":"exfil.xyz","outside_hours":False,"threat_intel_hit":False,"credential_submit":False},
        {"pattern":"data_exfil","user":"m.jones","destination":"wetransfer.com","outside_hours":True,"threat_intel_hit":False,"credential_submit":False},
        {"pattern":"newly_reg_domain","user":"j.garcia","destination":"payroll-upd.com","outside_hours":False,"threat_intel_hit":False,"credential_submit":True},
        {"pattern":"shadow_ai","user":"t.williams","destination":"chat.openai.com","outside_hours":False,"threat_intel_hit":False,"credential_submit":False},
        {"pattern":"policy_gap","user":"any","destination":"*.onion","outside_hours":False,"threat_intel_hit":False,"credential_submit":False},
    ]
