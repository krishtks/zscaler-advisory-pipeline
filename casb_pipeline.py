"""
casb_pipeline.py — CASB Shadow IT AI Risk Pipeline
Uses Zscaler Python SDK (ZscalerClient) for API access.
Auth via ZIdentity env vars: ZSCALER_CLIENT_ID, ZSCALER_CLIENT_SECRET,
                              ZSCALER_VANITY_DOMAIN, ZSCALER_CLOUD
"""
import json, logging, os
from datetime import datetime, timezone
from pathlib import Path
import httpx
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

AI_GUARD_URL  = os.getenv("AI_GUARD_URL", "")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODEL         = "claude-opus-4-6"
OUTPUT_DIR    = Path(os.getenv("OUTPUT_DIR", "./reports"))
CHUNK_SIZE    = 20

WEIGHTS = {"base_score":0.30,"user_spread":0.25,"data_volume":0.20,
           "no_cert":0.08,"breach_history":0.12,"pii_capable":0.05}
RISK_TIERS = [(75,"critical","Block immediately + user coaching"),
              (50,"high","Allow with DLP inspection + bandwidth cap"),
              (25,"medium","Conditional allow + logging"),
              (0,"low","Allow — recommend IT sanction for visibility")]


def _get_client():
    from zscaler import ZscalerClient
    return ZscalerClient()


def fetch_shadow_it_apps() -> list[dict]:
    """Pull shadow IT apps via Zscaler SDK.
    
    list_apps() returns a tuple: (list_of_apps, total_count, page_info)
    Each app in the list is a dict with keys: id, name
    We enrich with risk scoring since the shadow IT report API
    returns the app catalogue, not usage stats directly.
    """
    client = _get_client()
    result = client.zia.shadow_it_report.list_apps()
    
    # SDK returns tuple (apps_list, total, page_info)
    if isinstance(result, tuple):
        raw_apps = result[0] if result else []
    else:
        raw_apps = list(result)
    
    # Known high-risk app categories based on app names
    HIGH_RISK_NAMES = {
        "chatgpt", "openai", "dall-e", "midjourney", "jasper", "chatsonic",
        "character.ai", "writesonic", "neural blender", "runway", "synthesia",
        "andi", "deep dream", "gansonic",
    }
    FILE_SHARING = {
        "dropbox", "wetransfer", "box", "megaupload", "ziddu", "filesend",
        "amazon cloud drive", "elephantdrive", "storage made easy",
    }
    PRODUCTIVITY = {
        "notion", "trello", "asana", "monday", "wrike", "smartsheet",
    }
    
    apps = []
    for item in raw_apps:
        # Each item is a dict with id and name
        d = item if isinstance(item, dict) else (vars(item) if hasattr(item,'__dict__') else {})
        name = d.get("name","Unknown")
        name_lower = name.lower()
        
        # Assign risk score based on app type
        if any(h in name_lower for h in HIGH_RISK_NAMES):
            zs_score = 35  # High risk — AI/LLM
            category = "AI/LLM"
            pii_capable = True
        elif any(h in name_lower for h in FILE_SHARING):
            zs_score = 45  # High risk — file sharing
            category = "File Sharing"
            pii_capable = True
        elif "tor" in name_lower or "anonymizer" in name_lower or "vpn" in name_lower:
            zs_score = 20  # Critical — anonymizer
            category = "Anonymizer"
            pii_capable = False
        elif any(h in name_lower for h in PRODUCTIVITY):
            zs_score = 68
            category = "Productivity"
            pii_capable = True
        else:
            zs_score = 65  # Default medium risk
            category = d.get("category","Unknown")
            pii_capable = False
        
        apps.append({
            "name":          name,
            "category":      category,
            "zs_score":      zs_score,
            "users":         d.get("totalUsers") or 0,
            "upload_mb":     0,
            "download_mb":   0,
            "transactions":  0,
            "sanctioned":    False,
            "has_cert":      zs_score > 60,
            "breach_history":False,
            "pii_capable":   pii_capable,
        })
    
    logger.info(f"CASB: fetched {len(apps)} shadow IT apps from tenant")
    return apps


def compute_local_score(app: dict) -> dict:
    base    = round((100-app["zs_score"])*WEIGHTS["base_score"])
    users   = min(25,round((app["users"]/500)*100*WEIGHTS["user_spread"]))
    volume  = min(20,round((app["upload_mb"]/2000)*100*WEIGHTS["data_volume"]))
    no_cert = round(100*WEIGHTS["no_cert"]) if not app["has_cert"] else 0
    breach  = round(100*WEIGHTS["breach_history"]) if app["breach_history"] else 0
    pii     = round(100*WEIGHTS["pii_capable"]) if app["pii_capable"] else 0
    total   = min(100,base+users+volume+no_cert+breach+pii)
    tier,action = "low",RISK_TIERS[-1][2]
    for threshold,t,a in RISK_TIERS:
        if total>=threshold: tier,action=t,a; break
    return {**app,"composite_score":total,"tier":tier,"suggested_action":action,
            "score_breakdown":{"base_risk":base,"user_spread":users,"data_volume":volume,
                               "no_cert":no_cert,"breach":breach,"pii":pii}}


def _call_llm(prompt:str) -> str:
    if AI_GUARD_URL:
        r = httpx.post(f"{AI_GUARD_URL}/v1/messages",
            json={"model":MODEL,"max_tokens":4096,"messages":[{"role":"user","content":prompt}]},timeout=120)
        r.raise_for_status()
        return r.json()["content"][0]["text"]
    return Anthropic(api_key=ANTHROPIC_KEY).messages.create(
        model=MODEL,max_tokens=4096,
        messages=[{"role":"user","content":prompt}]).content[0].text


def analyse_apps_with_claude(scored_apps:list[dict]) -> list[dict]:
    enriched=[]
    for i in range(0,len(scored_apps),CHUNK_SIZE):
        chunk=scored_apps[i:i+CHUNK_SIZE]
        lines="\n".join(
            f"- {a['name']} ({a['category']}): score={a['composite_score']}/100 "
            f"users={a['users']} upload={a['upload_mb']}MB "
            f"cert={'yes' if a['has_cert'] else 'no'} "
            f"breach={'yes' if a['breach_history'] else 'no'} "
            f"pii={'yes' if a['pii_capable'] else 'no'}" for a in chunk)
        prompt=(
            "You are a Zscaler CASB security advisor. For each app return ONLY a JSON array "
            '[{"name":"...","risk_narrative":"1 sentence","zia_recommendation":"specific ZIA action",'
            '"action_code":"BLOCK|ALLOW_WITH_DLP|ALLOW_WITH_COACH|SANCTION|MONITOR"}]\n'
            f"Apps:\n{lines}"
        )
        try:
            rmap={a["name"]:a for a in json.loads(_call_llm(prompt))}
        except Exception as e:
            logger.warning(f"CASB chunk LLM error: {e}"); rmap={}
        for app in chunk:
            out=rmap.get(app["name"],{})
            enriched.append({**app,
                "risk_narrative":    out.get("risk_narrative","Manual review required."),
                "zia_recommendation":out.get("zia_recommendation",app["suggested_action"]),
                "action_code":       out.get("action_code","MONITOR")})
    return enriched


def generate_digest(enriched:list[dict], run_ts:str) -> str:
    by_tier={"critical":[],"high":[],"medium":[],"low":[]}
    for app in enriched: by_tier.get(app["tier"],by_tier["low"]).append(app)
    lines=["# CASB Shadow IT Risk Digest",f"**Generated:** {run_ts}",
           f"**Total apps:** {len(enriched)}","","| Tier | Count |","|------|-------|"]
    for tier in ["critical","high","medium","low"]:
        lines.append(f"| {tier.capitalize()} | {len(by_tier[tier])} |")
    for tier in ["critical","high","medium","low"]:
        apps=by_tier[tier]
        if not apps: continue
        lines+=["","---",f"## {tier.capitalize()} ({len(apps)})",""]
        for app in sorted(apps,key=lambda x:-x["composite_score"]):
            lines+=[f"### {app['name']}",
                    f"**Score:** {app['composite_score']}/100 | **Category:** {app['category']} | **Users:** {app['users']}",
                    "",f"_{app['risk_narrative']}_","",
                    f"**ZIA action:** `{app['action_code']}` — {app['zia_recommendation']}",""]
    return "\n".join(lines)


def run_pipeline(dry_run:bool=False) -> dict:
    run_ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    slug=datetime.now(timezone.utc).strftime("%Y%m%d")
    OUTPUT_DIR.mkdir(parents=True,exist_ok=True)
    raw=_sample_apps() if dry_run else fetch_shadow_it_apps()
    scored=[compute_local_score(a) for a in raw]
    enriched=analyse_apps_with_claude(scored) if (ANTHROPIC_KEY or AI_GUARD_URL) else [
        {**a,"risk_narrative":"No LLM.","zia_recommendation":a["suggested_action"],
         "action_code":"MONITOR"} for a in scored]
    (OUTPUT_DIR/f"casb_digest_{slug}.md").write_text(generate_digest(enriched,run_ts))
    (OUTPUT_DIR/f"casb_risk_{slug}.json").write_text(json.dumps(enriched,indent=2))
    return {"run_ts":run_ts,"total":len(enriched),
            "critical":sum(1 for a in enriched if a["tier"]=="critical"),
            "high":sum(1 for a in enriched if a["tier"]=="high"),
            "medium":sum(1 for a in enriched if a["tier"]=="medium"),
            "low":sum(1 for a in enriched if a["tier"]=="low"),
            "report":str(OUTPUT_DIR/f"casb_digest_{slug}.md"),
            "json":str(OUTPUT_DIR/f"casb_risk_{slug}.json")}


def _sample_apps() -> list[dict]:
    return [
        {"name":"ChatGPT (direct)","category":"AI/LLM","zs_score":42,"users":180,"upload_mb":850,"download_mb":200,"transactions":4200,"sanctioned":False,"has_cert":False,"breach_history":False,"pii_capable":True},
        {"name":"Dropbox personal","category":"File sharing","zs_score":55,"users":95,"upload_mb":1400,"download_mb":600,"transactions":2100,"sanctioned":False,"has_cert":True,"breach_history":True,"pii_capable":True},
        {"name":"Grammarly","category":"Productivity","zs_score":65,"users":220,"upload_mb":30,"download_mb":10,"transactions":8900,"sanctioned":False,"has_cert":True,"breach_history":True,"pii_capable":True},
        {"name":"Notion","category":"Collaboration","zs_score":70,"users":60,"upload_mb":200,"download_mb":150,"transactions":1200,"sanctioned":False,"has_cert":True,"breach_history":False,"pii_capable":True},
        {"name":"Slack (unmanaged)","category":"Messaging","zs_score":75,"users":40,"upload_mb":120,"download_mb":80,"transactions":3400,"sanctioned":False,"has_cert":True,"breach_history":False,"pii_capable":False},
        {"name":"Perplexity AI","category":"AI/LLM","zs_score":38,"users":55,"upload_mb":320,"download_mb":90,"transactions":980,"sanctioned":False,"has_cert":False,"breach_history":False,"pii_capable":True},
        {"name":"WeTransfer","category":"File sharing","zs_score":48,"users":30,"upload_mb":2800,"download_mb":100,"transactions":210,"sanctioned":False,"has_cert":False,"breach_history":False,"pii_capable":True},
        {"name":"Trello (personal)","category":"Project mgmt","zs_score":72,"users":25,"upload_mb":15,"download_mb":20,"transactions":540,"sanctioned":False,"has_cert":True,"breach_history":False,"pii_capable":False},
    ]
