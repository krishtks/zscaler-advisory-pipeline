"""
zpa_pipeline.py — ZPA Access Posture Pipeline
Uses Zscaler Python SDK (ZscalerClient) for API access.
Auth via env vars: ZSCALER_CLIENT_ID, ZSCALER_CLIENT_SECRET,
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

ZPA_LOOKBACK    = int(os.getenv("ZPA_LOOKBACK_DAYS","90"))
ZPA_LATENCY_SLA = int(os.getenv("ZPA_CONNECTOR_LATENCY_SLA_MS","1000"))
AI_GUARD_URL    = os.getenv("AI_GUARD_URL","")
ANTHROPIC_KEY   = os.getenv("ANTHROPIC_API_KEY","")
MODEL           = "claude-opus-4-6"
OUTPUT_DIR      = Path(os.getenv("OUTPUT_DIR","./reports"))
CHUNK_SIZE      = 15

RISK_TIERS=[(75,"critical","Immediate remediation required"),
            (50,"high","Remediate within 24 hours"),
            (25,"medium","Remediate within 1 week"),
            (0,"low","Quarterly review")]


def _tier(score:int):
    for t,tier,action in RISK_TIERS:
        if score>=t: return tier,action
    return "low",RISK_TIERS[-1][2]


def _get_client():
    from zscaler import ZscalerClient
    return ZscalerClient()


def _d(item) -> dict:
    """Safely convert SDK object to dict."""
    return vars(item) if hasattr(item,'__dict__') else (item if isinstance(item,dict) else {})


def fetch_zpa_findings() -> list[dict]:
    client = _get_client()
    findings = []

    # ── App segments — scope analysis ────────────────────────────────────────
    try:
        segs = list(client.zpa.application_segment.list_segments())
        logger.info(f"ZPA: {len(segs)} segments fetched")
        for seg in segs:
            d = _d(seg)
            name     = d.get("name","Unknown")
            # Check for over-broad scope: wildcard or large CIDR in server addresses
            servers  = d.get("serverGroups") or d.get("server_groups") or []
            enabled  = d.get("enabled",True)
            if not enabled: continue
            # Score based on segment characteristics
            score, excess = 30, 0
            desc = d.get("description","") or ""
            if "/8" in desc or "0.0.0.0" in str(d): score+=40; excess=99
            elif "/16" in desc: score+=25; excess=95
            elif "*" in str(d.get("domainNames","")): score+=20; excess=80
            tier,action = _tier(score)
            findings.append({
                "type":          "segment_scope",
                "name":          name,
                "enabled":       enabled,
                "server_count":  len(servers),
                "scope_excess_pct": excess,
                "score":         score,
                "tier":          tier,
                "suggested_action": action,
                "detail":        f"{len(servers)} server group(s)",
            })
    except Exception as e:
        logger.error(f"ZPA segments error: {e}")

    # ── App connectors — health & posture ─────────────────────────────────────
    try:
        conns = list(client.zpa.app_connectors.list_connectors())
        logger.info(f"ZPA: {len(conns)} connectors fetched")
        for conn in conns:
            d = _d(conn)
            name        = d.get("name","Unknown")
            enabled     = d.get("enabled",True)
            if not enabled: continue
            ctrl_chan    = d.get("controlChannelStatus","") or ""
            last_seen   = d.get("lastBrokerConnectTime") or d.get("lastSeen") or 0
            version     = d.get("zscalerBuildVersion") or d.get("version","") or ""
            offline_hrs = 0
            if ctrl_chan.upper() in ("DISCONNECTED","OFFLINE"):
                offline_hrs = 24  # conservative estimate

            score = score_connector(name, "Unknown", offline_hrs, 0, 0, 0)["score"]
            tier,action = _tier(score)
            findings.append({
                "type":         "connector_posture",
                "name":         name,
                "status":       ctrl_chan,
                "version":      version,
                "offline_hrs":  offline_hrs,
                "latency_ms":   0,
                "load_pct":     0,
                "score":        score,
                "tier":         tier,
                "suggested_action": action,
            })
    except Exception as e:
        logger.error(f"ZPA connectors error: {e}")

    logger.info(f"ZPA: {len(findings)} total findings")
    return findings


def score_segment_scope(name,current_scope,actual_scope,scope_excess_pct,app_sensitivity):
    sens={"critical":30,"high":20,"medium":10,"low":5}.get(app_sensitivity,10)
    score=min(100,int(scope_excess_pct*0.6+sens))
    tier,action=_tier(score)
    return {"type":"overscoped_segment","name":name,"current_scope":current_scope,
            "actual_scope":actual_scope,"scope_excess_pct":round(scope_excess_pct),
            "app_sensitivity":app_sensitivity,"score":score,"tier":tier,"suggested_action":action}


def score_access_anomaly(user,anomaly_type,app,new_geo,outside_hours,unmanaged_device,sensitive_app):
    score=min(100,40+(25 if new_geo else 0)+(15 if outside_hours else 0)+
              (15 if unmanaged_device else 0)+(15 if sensitive_app else 0))
    tier,action=_tier(score)
    return {"type":"access_anomaly","user":user,"anomaly_type":anomaly_type,"app":app,
            "new_geo":new_geo,"outside_hours":outside_hours,"unmanaged_device":unmanaged_device,
            "sensitive_app":sensitive_app,"score":score,"tier":tier,"suggested_action":action}


def score_orphan(user,days_inactive,active_segments,sensitive_segments):
    score=min(100,int(min(40,days_inactive*0.8)+min(30,active_segments*3)+min(30,sensitive_segments*10)))
    tier,action=_tier(score)
    return {"type":"orphaned_account","user":user,"days_inactive":days_inactive,
            "active_segments":active_segments,"sensitive_segments":sensitive_segments,
            "apps_accessible":[],"score":score,"tier":tier,"suggested_action":action}


def score_connector(name,region,offline_hrs,latency_ms,load_pct,version_behind):
    score=0
    if offline_hrs>0: score+=min(50,offline_hrs*5)
    if latency_ms>ZPA_LATENCY_SLA: score+=min(25,int((latency_ms/ZPA_LATENCY_SLA-1)*12))
    if load_pct>80: score+=15
    if version_behind>=2: score+=10
    score=min(100,score)
    tier,action=_tier(score)
    return {"type":"connector_posture","name":name,"region":region,"offline_hrs":offline_hrs,
            "latency_ms":latency_ms,"load_pct":load_pct,"version_behind":version_behind,
            "score":score,"tier":tier,"suggested_action":action}


def _call_llm(prompt:str) -> str:
    if AI_GUARD_URL:
        r=httpx.post(f"{AI_GUARD_URL}/v1/messages",
            json={"model":MODEL,"max_tokens":4096,"messages":[{"role":"user","content":prompt}]},timeout=120)
        r.raise_for_status(); return r.json()["content"][0]["text"]
    return Anthropic(api_key=ANTHROPIC_KEY).messages.create(
        model=MODEL,max_tokens=4096,messages=[{"role":"user","content":prompt}]).content[0].text


def enrich_with_claude(findings:list[dict]) -> list[dict]:
    if not (ANTHROPIC_KEY or AI_GUARD_URL):
        return [{**f,"narrative":"No LLM.","zpa_action":f.get("suggested_action","REVIEW")} for f in findings]
    enriched=[]
    for i in range(0,len(findings),CHUNK_SIZE):
        chunk=findings[i:i+CHUNK_SIZE]
        lines="\n".join(
            f"- type={f['type']} score={f['score']} tier={f['tier']} "
            f"id={f.get('user') or f.get('name','?')} detail={f.get('detail','')}" for f in chunk)
        prompt=(
            "You are a ZPA zero trust access advisor. For each finding return ONLY a JSON array "
            '[{"type":"...","user":"...","narrative":"1 sentence","zpa_action":"specific ZPA config step"}]\n'
            f"Findings:\n{lines}"
        )
        try:
            raw=_call_llm(prompt).strip()
            raw=raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            results=json.loads(raw)
            rmap={(r.get("type",""),r.get("user","") or r.get("name","")):r for r in results}
        except Exception as e:
            logger.warning(f"ZPA LLM error: {e}"); rmap={}
        for f in chunk:
            r=rmap.get((f.get("type",""),f.get("user","") or f.get("name","")),{})
            enriched.append({**f,
                "narrative":  r.get("narrative","Manual review required."),
                "zpa_action": r.get("zpa_action",f.get("suggested_action","REVIEW"))})
    return enriched


def generate_digest(enriched:list[dict], run_ts:str) -> str:
    by_tier={"critical":[],"high":[],"medium":[],"low":[]}
    for f in enriched: by_tier.get(f["tier"],by_tier["low"]).append(f)
    lines=["# ZPA Access Posture Digest",f"**Generated:** {run_ts}",
           f"**Lookback:** {ZPA_LOOKBACK} days","","| Tier | Count |","|------|-------|"]
    for tier in ["critical","high","medium","low"]:
        lines.append(f"| {tier.capitalize()} | {len(by_tier[tier])} |")
    for tier in ["critical","high","medium","low"]:
        items=by_tier[tier]
        if not items: continue
        lines+=["","---",f"## {tier.capitalize()} ({len(items)})",""]
        for f in sorted(items,key=lambda x:-x["score"]):
            identity=f.get("user") or f.get("name") or "—"
            lines+=[f"### {f['type'].replace('_',' ').title()} — {identity}",
                    f"**Score:** {f['score']}/100","",
                    f"_{f.get('narrative','Review required.')}_","",
                    f"**ZPA action:** {f.get('zpa_action',f.get('suggested_action','REVIEW'))}",""]
    return "\n".join(lines)


def run_pipeline(dry_run:bool=False) -> dict:
    run_ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    slug=datetime.now(timezone.utc).strftime("%Y%m%d")
    OUTPUT_DIR.mkdir(parents=True,exist_ok=True)
    raw=_sample_findings() if dry_run else fetch_zpa_findings()
    enriched=enrich_with_claude(raw)
    (OUTPUT_DIR/f"zpa_digest_{slug}.md").write_text(generate_digest(enriched,run_ts))
    (OUTPUT_DIR/f"zpa_risk_{slug}.json").write_text(json.dumps(enriched,indent=2))
    return {"run_ts":run_ts,"total":len(enriched),
            "critical":sum(1 for f in enriched if f["tier"]=="critical"),
            "high":sum(1 for f in enriched if f["tier"]=="high"),
            "medium":sum(1 for f in enriched if f["tier"]=="medium"),
            "low":sum(1 for f in enriched if f["tier"]=="low"),
            "report":str(OUTPUT_DIR/f"zpa_digest_{slug}.md"),
            "json":str(OUTPUT_DIR/f"zpa_risk_{slug}.json")}


def _sample_findings() -> list[dict]:
    return [
        score_segment_scope("SAP ERP","10.0.0.0/8:443","10.12.4.45,10.12.4.46",99.9,"critical"),
        score_segment_scope("Dev Tools","10.20.0.0/16:22,443","10.20.1.0/24",99.6,"high"),
        score_access_anomaly("c.okonkwo","new_geo_outside_hours","HRIS",True,True,True,True),
        score_access_anomaly("svc_account","lateral_movement","ERP",False,False,False,True),
        score_orphan("m.harrison",47,8,2),
        score_orphan("j.thomas",12,3,0),
        score_connector("EMEA-01","EMEA",0,4200,60,0),
        score_connector("EMEA-02","EMEA",144,1100,94,1),
        score_connector("APAC-01","APAC",0,850,45,2),
    ]
