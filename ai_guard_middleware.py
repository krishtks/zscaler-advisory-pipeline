"""
ai_guard_middleware.py — AI Guard FastAPI Middleware
Sits between the unified pipeline and Anthropic/Claude.

Uses Zscaler AI Guard Detection-as-a-Service (DaS) mode:
  - Sends prompt to ZS_DAS_URL for policy inspection
  - Uses ZS_DAS_API_KEY directly as bearer token (no OAuth2 exchange)
  - Uses ZS_DAS_POLICY_ID to select the AI Guard policy to enforce
  - On ALLOW: forwards to Anthropic using ANTHROPIC_API_KEY
  - On BLOCK: returns 400 with violation detail

Credentials live in .env.middleware only.
Pipeline only knows this middleware's URL — never sees these keys.
"""

import json
import logging
import os
import time
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ── AI Guard DaS credentials ───────────────────────────────────────────────────
ZS_DAS_API_KEY         = os.getenv("ZS_DAS_API_KEY", "").strip()
ZS_DAS_POLICY_ID       = os.getenv("ZS_DAS_POLICY_ID", "1407").strip()
ZS_DAS_URL             = os.getenv("ZS_DAS_URL", "https://api.us1.zseclipse.net/v1/detection/execute-policy")
ZS_DAS_TIMEOUT         = int(os.getenv("ZS_DAS_TIMEOUT_SECONDS", "10"))

# ── Anthropic credentials ──────────────────────────────────────────────────────
# In DaS mode the pipeline calls Anthropic directly after inspection passes.
# Use ANTHROPIC_ZS_PROXY_API_KEY if routing via Zscaler proxy instead.
ANTHROPIC_API_KEY      = os.getenv("ANTHROPIC_API_KEY", "").strip()
ANTHROPIC_MODEL        = os.getenv("ANTHROPIC_MODEL", "claude-opus-4-6")
ANTHROPIC_URL          = "https://api.anthropic.com/v1/messages"

# ── Behaviour ──────────────────────────────────────────────────────────────────
AI_GUARD_MODE          = os.getenv("AI_GUARD_MODE", "BLOCK")   # BLOCK | DETECT
AUDIT_LOG              = os.getenv("AI_GUARD_AUDIT_LOG", "true").lower() == "true"
AUDIT_LOG_PATH         = Path(os.getenv("AUDIT_LOG_PATH", "/app/logs/ai_guard_audit.jsonl"))


# ── Audit logger ───────────────────────────────────────────────────────────────
def _audit(event: dict):
    if not AUDIT_LOG:
        return
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps({"ts": time.time(), **event}) + "\n")


# ── AI Guard DaS inspection ────────────────────────────────────────────────────
def _inspect(messages: list[dict], model: str) -> dict:
    """
    Call Zscaler AI Guard DaS endpoint.
    Correct payload: policyId + direction + content (plain string).
    Matches the working format from guardrails.py in ai-security-demo.
    """
    if not ZS_DAS_API_KEY:
        raise RuntimeError("ZS_DAS_API_KEY not set in .env.middleware")
    if not ZS_DAS_POLICY_ID:
        raise RuntimeError("ZS_DAS_POLICY_ID not set in .env.middleware")

    # DaS expects plain text in "content", not a messages array
    content_text = " ".join(
        m.get("content", "") if isinstance(m.get("content"), str)
        else str(m.get("content", ""))
        for m in messages
    ).strip()

    payload = {
        "policyId":  ZS_DAS_POLICY_ID,
        "direction": "IN",
        "content":   content_text,
    }

    resp = httpx.post(
        ZS_DAS_URL,
        json=payload,
        headers={
            "Authorization": f"Bearer {ZS_DAS_API_KEY}",
            "Content-Type":  "application/json",
        },
        timeout=ZS_DAS_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()

    # Parse DaS response — action at top level: ALLOW | BLOCK | DETECT
    action = data.get("action", "ALLOW").upper()

    # Body-level 500 means all detectors failed — fail open
    if data.get("statusCode") == 500:
        action    = "ALLOW"
        violation = data.get("errorMessage", "All detectors failed — failing open")
    else:
        detector_responses = data.get("detectorResponses", {})
        triggered = [
            name for name, d in detector_responses.items()
            if d.get("triggered") or d.get("action", "ALLOW").upper() == "BLOCK"
        ]
        violation = f"Detectors triggered: {', '.join(triggered)}" if triggered else ""

    policy = data.get("policyName") or ZS_DAS_POLICY_ID

    return {
        "action":       action,
        "violation":    violation,
        "policy":       policy,
        "raw_response": data,
    }


# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(title="AI Guard DaS Middleware")


@app.post("/v1/messages")
async def proxy_messages(request: Request):
    """
    Pipeline posts Anthropic-format message requests here.

    Flow:
      1. Extract messages from request body
      2. Send to AI Guard DaS for policy inspection
      3. BLOCK → return 400 with violation detail
      4. ALLOW/DETECT → forward to Anthropic, return response
    """
    body     = await request.json()
    messages = body.get("messages", [])
    model    = body.get("model", ANTHROPIC_MODEL)
    max_tok  = body.get("max_tokens", 4096)

    # ── Step 1: AI Guard DaS inspection ───────────────────────────────────────
    try:
        result = _inspect(messages, model)
        action    = result["action"]
        violation = result["violation"]
        policy    = result["policy"]

        _audit({
            "event":     "inspection",
            "action":    action,
            "violation": violation,
            "policy":    policy,
            "model":     model,
            "msg_count": len(messages),
        })
        logger.info(
            f"AI Guard DaS: policy={policy} action={action}"
            + (f" violation={violation}" if violation else "")
        )

    except Exception as e:
        logger.error(f"AI Guard DaS inspection failed: {e}")
        _audit({"event": "inspection_error", "error": str(e)})
        if AI_GUARD_MODE == "BLOCK":
            raise HTTPException(503, f"AI Guard DaS unavailable: {e}")
        # DETECT mode — fail open, log and continue
        action = "ALLOW"

    # ── Step 2: Enforce block ──────────────────────────────────────────────────
    if action == "BLOCK" and AI_GUARD_MODE == "BLOCK":
        _audit({"event": "blocked", "violation": violation, "policy": policy})
        logger.warning(f"Request BLOCKED by AI Guard policy: {policy} — {violation}")
        raise HTTPException(
            status_code=400,
            detail={
                "error":     "ai_guard_policy_violation",
                "violation": violation,
                "policy":    policy,
                "message":   "Request blocked by AI Guard DaS policy.",
            },
        )

    # ── Step 3: Forward to Anthropic ──────────────────────────────────────────
    payload = {
        "model":      model,
        "max_tokens": max_tok,
        "messages":   messages,
    }
    if body.get("system"):
        payload["system"] = body["system"]

    try:
        resp = httpx.post(
            ANTHROPIC_URL,
            json=payload,
            headers={
                "x-api-key":         ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type":      "application/json",
            },
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()

        _audit({
            "event":         "forwarded",
            "model":         model,
            "action":        action,
            "input_tokens":  data.get("usage", {}).get("input_tokens", 0),
            "output_tokens": data.get("usage", {}).get("output_tokens", 0),
        })
        return JSONResponse(content=data)

    except httpx.HTTPStatusError as e:
        logger.error(f"Anthropic API error: {e.response.status_code}")
        raise HTTPException(e.response.status_code, f"Anthropic error: {e.response.text}")


@app.get("/health")
def health():
    return {
        "status":          "ok",
        "mode":            "das",
        "ai_guard_mode":   AI_GUARD_MODE,
        "das_url":         ZS_DAS_URL,
        "policy_id":       ZS_DAS_POLICY_ID or "NOT SET",
        "api_key_set":     bool(ZS_DAS_API_KEY),
        "audit_log":       AUDIT_LOG,
    }
