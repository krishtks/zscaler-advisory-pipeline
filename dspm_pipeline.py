"""
dspm_pipeline.py — DSPM Sensitive Data Exposure Pipeline
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

DSPM_TENANT_ID    = os.getenv("DSPM_TENANT_ID","")
DSPM_SCAN_SOURCES = os.getenv("DSPM_SCAN_SOURCES","sharepoint,onedrive,s3,gcs,azure_blob").split(",")
DSPM_MIN_SCORE    = int(os.getenv("DSPM_MIN_SCORE","25"))
AI_GUARD_URL      = os.getenv("AI_GUARD_URL","")
ANTHROPIC_KEY     = os.getenv("ANTHROPIC_API_KEY","")
MODEL             = "claude-opus-4-6"
OUTPUT_DIR        = Path(os.getenv("OUTPUT_DIR","./reports"))
CHUNK_SIZE        = 20

# ZIdentity constructs the DSPM base URL from tenant ID
def _dspm_base() -> str:
    cloud = os.getenv("ZSCALER_CLOUD","zscaler.net")
    return f"https://api.{cloud}/dspm/v1/tenants/{DSPM_TENANT_ID}"

RISK_TIERS = [(75,"critical","Disable external sharing + notify DPO immediately"),
              (50,"high","Apply sensitivity label + enable DLP + alert data owner"),
              (25,"medium","Apply label + monitor + notify data steward"),
              (0,"low","Accept residual risk + document + quarterly review")]

REG_MAP = {
    "PII":       ("GDPR, UK DPA 2018, CCPA","72 hours to supervisory authority"),
    "PHI":       ("HIPAA Privacy & Security","60 days to HHS OCR"),
    "PCI DSS":   ("PCI DSS 4.0","Immediate to card brands"),
    "Gov ID":    ("GDPR Art. 9, UK biometrics","72 hours (special category)"),
    "Financial": ("SOX, FCA, MiFID II","Varies by incident type"),
    "HR":        ("GDPR Art. 88, employment law","Varies by jurisdiction"),
    "IP":        ("Company policy","N/A"),
    "Credentials":("All frameworks (indirect)","Assume full compromise — rotate immediately"),
}


def _tier(score: int):
    for t,tier,action in RISK_TIERS:
        if score>=t: return tier,action
    return "low",RISK_TIERS[-1][2]


def compute_score(ext_sharing:bool, has_mip_label:bool, reg_scope:int, volume_k:int) -> int:
    return min(100,
        (30 if ext_sharing else 0) +
        (0 if has_mip_label else 15) +
        round((reg_scope/3)*30) +
        min(25,round((volume_k/100)*25)))


def fetch_dspm_findings() -> list[dict]:
    url  = f"{_dspm_base()}/findings"
    resp = zid_auth.get(url, params={"pageSize":500,"status":"OPEN"})
    raw  = resp.json()
    out  = []
    for item in raw.get("findings",[]):
        label     = item.get("dataClassification","Unknown")
        ext       = item.get("externalSharingEnabled",False)
        mip       = item.get("sensitivityLabelApplied",False)
        reg_scope = item.get("regulatoryRiskLevel",1)
        vol_k     = round(item.get("recordCount",0)/1000,1)
        score     = compute_score(ext,mip,reg_scope,vol_k)
        tier,action = _tier(score)
        reg_info  = REG_MAP.get(label.split()[0],("Unknown","Unknown"))
        out.append({
            "name":             item.get("findingName","Unknown"),
            "location":         item.get("dataStorePath","Unknown"),
            "label":            label,
            "ext_sharing":      ext,
            "has_mip_label":    mip,
            "reg_scope":        reg_scope,
            "volume_k":         vol_k,
            "regulation":       reg_info[0],
            "notification_sla": reg_info[1],
            "composite_score":  score,
            "tier":             tier,
            "suggested_action": action,
        })
    logger.info(f"DSPM: fetched {len(out)} findings")
    return out


def _call_llm(prompt:str) -> str:
    if AI_GUARD_URL:
        r = httpx.post(f"{AI_GUARD_URL}/messages",
            json={"model":MODEL,"max_tokens":4096,"messages":[{"role":"user","content":prompt}]},timeout=120)
        r.raise_for_status(); return r.json()["content"][0]["text"]
    return Anthropic(api_key=ANTHROPIC_KEY).messages.create(
        model=MODEL,max_tokens=4096,messages=[{"role":"user","content":prompt}]).content[0].text


def enrich_with_claude(findings:list[dict]) -> list[dict]:
    if not (ANTHROPIC_KEY or AI_GUARD_URL):
        return [{**f,"risk_narrative":"No LLM.","zia_recommendation":f["suggested_action"],
                 "action_code":"MONITOR"} for f in findings]
    enriched=[]
    for i in range(0,len(findings),CHUNK_SIZE):
        chunk=findings[i:i+CHUNK_SIZE]
        lines="\n".join(f"- name={f['name']} location={f['location']} label={f['label']} "
                         f"score={f['composite_score']} ext={f['ext_sharing']} mip={f['has_mip_label']} "
                         f"reg={f['regulation']}" for f in chunk)
        prompt=(
            "You are a Zscaler DSPM advisor. For each finding return ONLY JSON array "
            "[{\"name\":\"...\",\"risk_narrative\":\"1 sentence\","
            "\"zia_recommendation\":\"specific action\","
            "\"action_code\":\"BLOCK|QUARANTINE|RESTRICT|LABEL|MONITOR\"}]\n"
            f"Findings:\n{lines}"
        )
        try:
            rmap={r["name"]:r for r in json.loads(_call_llm(prompt))}
        except Exception as e:
            logger.warning(f"DSPM chunk LLM error: {e}"); rmap={}
        for f in chunk:
            r=rmap.get(f["name"],{})
            enriched.append({**f,
                "risk_narrative":    r.get("risk_narrative","Manual review required."),
                "zia_recommendation":r.get("zia_recommendation",f["suggested_action"]),
                "action_code":       r.get("action_code","MONITOR")})
    return enriched


def generate_digest(enriched:list[dict], run_ts:str) -> str:
    by_tier={"critical":[],"high":[],"medium":[],"low":[]}
    for f in enriched: by_tier.get(f["tier"],by_tier["low"]).append(f)
    lines=["# DSPM Sensitive Data Exposure Digest",f"**Generated:** {run_ts}",
           f"**Sources:** {', '.join(DSPM_SCAN_SOURCES)}","","| Tier | Count |","|------|-------|"]
    for tier in ["critical","high","medium","low"]:
        lines.append(f"| {tier.capitalize()} | {len(by_tier[tier])} |")
    for tier in ["critical","high","medium","low"]:
        items=by_tier[tier]
        if not items: continue
        lines+=["","---",f"## {tier.capitalize()} ({len(items)})",""]
        for f in sorted(items,key=lambda x:-x["composite_score"]):
            lines+=[f"### {f['name']}",
                    f"**Score:** {f['composite_score']}/100 | **Location:** {f['location']} | **Label:** {f['label']}",
                    f"**Regulation:** {f['regulation']} | **SLA:** {f['notification_sla']}",
                    "",f"_{f['risk_narrative']}_","",
                    f"**Action:** `{f['action_code']}` — {f['zia_recommendation']}",""]
    return "\n".join(lines)


def run_pipeline(dry_run:bool=False) -> dict:
    run_ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    slug=datetime.now(timezone.utc).strftime("%Y%m%d")
    OUTPUT_DIR.mkdir(parents=True,exist_ok=True)
    raw=_sample_findings() if dry_run else fetch_dspm_findings()
    raw=[f for f in raw if f["composite_score"]>=DSPM_MIN_SCORE]
    enriched=enrich_with_claude(raw)
    (OUTPUT_DIR/f"dspm_digest_{slug}.md").write_text(generate_digest(enriched,run_ts))
    (OUTPUT_DIR/f"dspm_risk_{slug}.json").write_text(json.dumps(enriched,indent=2))
    return {"run_ts":run_ts,"total":len(enriched),
            "critical":sum(1 for f in enriched if f["tier"]=="critical"),
            "high":sum(1 for f in enriched if f["tier"]=="high"),
            "medium":sum(1 for f in enriched if f["tier"]=="medium"),
            "low":sum(1 for f in enriched if f["tier"]=="low"),
            "report":str(OUTPUT_DIR/f"dspm_digest_{slug}.md"),
            "json":str(OUTPUT_DIR/f"dspm_risk_{slug}.json")}


def _sample_findings() -> list[dict]:
    samples=[
        ("Passport scans","SharePoint Online / HR Docs","PII / Gov ID",True,False,3,12),
        ("Payment card numbers","OneDrive / Finance","PCI DSS",False,True,3,48),
        ("Patient records","AWS S3 — public-read ACL","PHI",True,False,3,100),
        ("API keys in commits","GitHub — public repo","Credentials",True,False,2,1),
        ("Employee salary data","Google Drive / All Staff","HR",False,False,2,21),
        ("Source code","Confluence / Engineering","IP",False,False,1,3),
        ("Audit reports","SharePoint / Finance only","Financial",False,True,1,5),
        ("Anonymised test data","Azure Blob / Dev sandbox","Low sensitivity",False,True,1,1),
    ]
    out=[]
    for name,location,label,ext,mip,reg,vol in samples:
        score=compute_score(ext,mip,reg,vol); tier,action=_tier(score)
        reg_info=REG_MAP.get(label.split()[0],("Unknown","Unknown"))
        out.append({"name":name,"location":location,"label":label,"ext_sharing":ext,
                    "has_mip_label":mip,"reg_scope":reg,"volume_k":vol,
                    "regulation":reg_info[0],"notification_sla":reg_info[1],
                    "composite_score":score,"tier":tier,"suggested_action":action})
    return out
