# Zscaler AI Advisory Pipeline

An AI-powered security posture advisory system built on the Zscaler platform. It pulls live telemetry from four Zscaler pillars — CASB, DSPM, ZIA, and ZPA — runs all data through Zscaler AI Guard for DLP inspection, then uses Claude (Anthropic) to score findings, generate risk narratives, and produce a weekly unified posture report.

---

## What it does

Every Monday at 06:00 UTC the pipeline automatically:

1. **Pulls live data** from your Zscaler tenant across four modules
2. **Inspects all prompts** through Zscaler AI Guard DaS before they reach Claude — no sensitive data leaves uninspected
3. **Scores and narrates** every finding using Claude, producing plain-language risk assessments
4. **Correlates findings across pillars** — detecting combined threats no single module sees alone
5. **Generates a unified posture report** — markdown digest + JSON for dashboards

You can also trigger runs on demand via the REST API.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  APScheduler (weekly)                │
└─────────────────┬───────────────────────────────────┘
                  │
    ┌─────────────┼──────────────┐
    ▼             ▼              ▼              ▼
  CASB          DSPM            ZIA            ZPA
  Module        Module          Module         Module
  (Shadow IT)   (Data findings) (Policy/NSS)   (Access posture)
    │             │              │              │
    └─────────────┴──────────────┴──────────────┘
                  │
                  ▼
         FastAPI Middleware
         (normalise · chunk)
                  │
                  ▼
      ┌───────────────────────┐
      │  AI Guard Middleware  │  ◄── ZS_DAS_API_KEY
      │  DaS inspection       │      policy_id: <your policy id>
      │  DLP enforce · audit  │
      └───────────┬───────────┘
                  │
                  ▼
           Claude API (Anthropic)
           Risk score · narrative · recommendation
                  │
                  ▼
      Cross-pillar Correlation Engine
      (ZIA+CASB, DSPM+ZPA, C2+lateral, shadow AI)
                  │
                  ▼
         Unified Posture Report
         casb_digest · dspm_digest · zia_digest
         zpa_digest · posture_summary
```

---

## The four modules

### CASB — Shadow IT & App Risk
Pulls your full cloud app inventory from Zscaler CASB using the SDK `shadow_it_report.list_apps()`. Scores each app against six weighted signals: Zscaler base score, user spread, upload volume, compliance certification, breach history, and PII capability. Claude generates a risk narrative and ZIA policy recommendation (BLOCK / ALLOW_WITH_DLP / ALLOW_WITH_COACH / SANCTION / MONITOR) for each app.

### DSPM — Sensitive Data Exposure
Scans data classification findings from connected data stores (SharePoint Online, OneDrive, S3, Azure Blob). Scores each finding across four dimensions: external sharing status, MIP sensitivity label presence, regulatory scope (GDPR/HIPAA/PCI), and data volume. Claude generates a regulatory-mapped risk narrative with breach notification timelines and specific ZIA/ZPA remediation steps.

### ZIA — Internet Access Policy & Threat Telemetry
Analyses your ZIA URL filtering rules and security policy via the SDK. Identifies policy gaps — threat categories (Anonymizer, Tor, newly registered domains, cryptomining) that are permitted where zero-trust policy requires blocking. Also flags missing DLP coverage on high-risk upload paths and generates hunt queries in Splunk/Sentinel/Chronicle syntax.

### ZPA — Zero Trust Access Posture
Pulls app segment definitions and connector health from ZPA. Identifies:
- **Entitlement sprawl** — users with access to segments they never use
- **Over-scoped segments** — `/8` or wildcard definitions where only specific hosts are needed
- **Anomalous access** — new geography, outside hours, unmanaged device combinations
- **Orphaned accounts** — departed users still holding active ZPA entitlements
- **Connector posture** — offline connectors, latency above SLA, load imbalance, outdated versions

---

## AI Guard integration

All four modules route through the AI Guard middleware before reaching Claude. This is the critical data governance layer.

```
Pipeline → POST /v1/messages → AI Guard Middleware
                                      │
                                      ├─ 1. Fetch bearer token (ZS_DAS_API_KEY)
                                      ├─ 2. POST to DaS endpoint (policy_id: 'your policy id')
                                      ├─ 3. Check action: ALLOW | BLOCK | DETECT
                                      ├─ 4. Write to audit log (JSONL)
                                      └─ 5. Forward to Anthropic (if ALLOW)
```

**Why this matters:** CASB findings contain app names and user counts. DSPM findings contain data classification labels and file paths. ZIA findings contain destination IPs and user identifiers. ZPA findings contain application segment definitions. All of this is corporate security telemetry — it must be inspected before being sent to an external LLM. AI Guard DaS enforces your organisation's data policy on every prompt.

**AI Guard mode:**
- `BLOCK` (default, production) — violating requests are rejected, pipeline logs the block and continues
- `DETECT` (staging) — all requests pass through, violations are logged only

Every inspection is written to `/app/logs/ai_guard_audit.jsonl` with timestamp, action, violation type, policy name, model, and token counts.

---

## Cross-pillar correlation

The correlation engine joins findings across modules by user, application, and timestamp. Five correlation rules fire automatically:

| Rule | Signals | Combined finding |
|------|---------|-----------------|
| Exfiltration + Shadow App | ZIA upload anomaly + CASB high-risk app (same user) | Staged internal-to-external data movement |
| Sensitive Data + Orphaned Access | DSPM critical finding + ZPA orphaned account (same data store) | Breach risk — departed user has access to classified data |
| C2 + Lateral Movement | ZIA C2 beacon + ZPA lateral access anomaly (same user) | Active compromise indicator |
| Shadow AI + No Inspection | CASB LLM apps detected + ZIA no AI Guard routing | Uninspected LLM data egress |
| Sensitive Data + Over-scoped Segment | DSPM finding + ZPA broad segment to same store | Blast radius amplifier |

---

## Project structure

```
zscaler-advisory-pipeline/
├── app.py                    # FastAPI service — scheduler + REST API
├── unified_pipeline.py       # Orchestrator — runs all four modules in sequence
├── correlator.py             # Cross-pillar correlation engine
├── report_generator.py       # Unified posture report generator (MD + JSON)
│
├── casb_pipeline.py          # CASB module — shadow IT app risk
├── dspm_pipeline.py          # DSPM module — sensitive data exposure
├── zia_pipeline.py           # ZIA module — policy gaps + threat telemetry
├── zpa_pipeline.py           # ZPA module — access posture
│
├── zidentity_auth.py         # ZIdentity OAuth2 token manager (shared)
├── ai_guard_middleware.py    # AI Guard DaS proxy service
│
├── Dockerfile                # Pipeline container
├── Dockerfile.middleware     # AI Guard middleware container
├── docker-compose.yml        # Two-container deployment
├── requirements.txt          # Python dependencies
│
├── .env.example              # Pipeline credentials template
├── .env.middleware.example   # AI Guard credentials template
│
├── reports/                  # Generated report output (gitignored)
└── logs/                     # AI Guard audit logs (gitignored)
```

---

## Prerequisites

- Docker Desktop (Mac/Windows/Linux)
- Python 3.11+ (for running `setup_pipeline.py`)
- Zscaler tenant with ZIdentity API client configured
- Zscaler AI Guard with DaS mode enabled and an API key
- Anthropic API key

---

## Setup

### 1. Clone and configure

```bash
git clone https://github.com/YOUR_ORG/zscaler-advisory-pipeline.git
cd zscaler-advisory-pipeline

cp .env.example .env
cp .env.middleware.example .env.middleware
```

### 2. Fill in `.env` (pipeline credentials)

```env
ZSCALER_CLIENT_ID=your_zidentity_client_id
ZSCALER_CLIENT_SECRET=your_zidentity_client_secret
ZSCALER_VANITY_DOMAIN=your_vanity_domain        # e.g. Your vanity domain
ZSCALER_CLOUD= <your zscaler cloud -e.g. zscaler.net>                   # your cloud suffix
ANTHROPIC_API_KEY=sk-ant-...
AI_GUARD_URL=http://ai-guard-middleware:8000
OUTPUT_DIR=/app/reports
ZIA_THREAT_LOOKBACK_HRS=24
ZPA_LOOKBACK_DAYS=90
DSPM_SCAN_SOURCES=sharepoint,onedrive
DSPM_MIN_SCORE=25
```

**Where to find your ZIdentity credentials:**
- Log into your Zscaler admin portal
- Navigate to **ZIdentity → Administration → API Clients**
- Your `client_id` and `client_secret` are on the API client detail page
- Your `vanity_domain` is the prefix of your ZIdentity login URL (e.g. `vainity` from <vanity>.zslogin.net`)

### 3. Fill in `.env.middleware` (AI Guard credentials)

```env
ZS_DAS_API_KEY=your_ai_guard_api_key
ZS_DAS_URL= <insert DAS URL e.g /api.us1.zseclipse.net/>
ZS_DAS_POLICY_ID=<Your Policy ID
ZS_DAS_TIMEOUT_SECONDS=10
ANTHROPIC_API_KEY=sk-ant-...
AI_GUARD_MODE=BLOCK
AI_GUARD_AUDIT_LOG=true
```

**Where to find your AI Guard API key:**
- In ZIdentity console under **AI Security → API Clients**
- This is a separate credential from your standard ZIdentity API client

### 4. Build and start

```bash
docker compose up --build -d
```

### 5. Validate

```bash
# Check both containers are running
docker compose ps

# Check middleware (confirms AI Guard key is loaded)
curl http://localhost:8000/health

# Check pipeline (confirms scheduler is running)
curl http://localhost:8080/health
```

### 6. Run a dry-run (no Zscaler API calls)

```bash
curl -X POST http://localhost:8080/pipeline/dry-run
sleep 30
curl http://localhost:8080/pipeline/status | python3 -m json.tool
```

### 7. Run live against your tenant

```bash
curl -X POST http://localhost:8080/pipeline/run
sleep 90
curl http://localhost:8080/pipeline/status | python3 -m json.tool
```

### 8. View reports

```bash
# Copy reports to local filesystem
docker cp zscaler-advisory-pipeline:/app/reports ./reports-output
open ./reports-output   # macOS
```

---

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/pipeline/run` | Trigger full live pipeline run |
| `POST` | `/pipeline/dry-run` | Run with sample data (no API calls) |
| `GET` | `/pipeline/status` | Last run summary |
| `GET` | `/posture/latest` | Latest unified posture report (JSON) |
| `GET` | `/reports` | List all generated reports |
| `GET` | `/reports/{filename}` | Download a specific report |
| `GET` | `/health` | Service health + scheduler status |
| `GET` | `/` (middleware) | AI Guard middleware health |

---

## Report outputs

Each weekly run produces these files in `/app/reports/`:

| File | Format | Contents |
|------|--------|----------|
| `casb_digest_YYYYMMDD.md` | Markdown | Shadow IT app risk — tiered findings, narratives, ZIA actions |
| `casb_risk_YYYYMMDD.json` | JSON | Full CASB scoring data for dashboard ingestion |
| `dspm_digest_YYYYMMDD.md` | Markdown | Data exposure findings — regulatory mapping, remediation steps |
| `dspm_risk_YYYYMMDD.json` | JSON | Full DSPM scoring data |
| `zia_digest_YYYYMMDD.md` | Markdown | Policy gaps and threat findings — hunt queries included |
| `zia_risk_YYYYMMDD.json` | JSON | Full ZIA finding data |
| `zpa_digest_YYYYMMDD.md` | Markdown | Access posture — entitlement sprawl, segments, connectors |
| `zpa_risk_YYYYMMDD.json` | JSON | Full ZPA finding data |
| `posture_summary_YYYYMMDD.md` | Markdown | **Unified executive digest** — all four pillars + cross-pillar findings |
| `posture_summary_YYYYMMDD.json` | JSON | Machine-readable posture summary for SIEM/GRC integration |

---

## Scheduler

The pipeline runs automatically every Monday at 06:00 UTC. No manual intervention required. The schedule is configured in `app.py` using APScheduler:

```python
CronTrigger(day_of_week="mon", hour=6, minute=0, timezone="UTC")
```

To change the schedule, edit `app.py` and rebuild.

---

## Enabling DSPM

DSPM requires a connected Microsoft 365 data source in your Zscaler tenant:

1. In the Zscaler admin portal go to **Data Security → DSPM → Data Sources → Add**
2. Select **Microsoft 365** and authorise with a Global Admin account
3. Select **SharePoint Online** and **OneDrive for Business**
4. Trigger an initial scan and wait for completion
5. In `.env` set `DSPM_SCAN_SOURCES=sharepoint,onedrive` and ensure the module is not disabled
6. Restart: `docker compose down && docker compose up -d`

---

## Security notes

- **Credentials are never logged** — `.env` and `.env.middleware` are gitignored
- **All LLM prompts are AI Guard inspected** — no data reaches Anthropic without DaS clearance
- **Audit trail** — every AI Guard inspection is written to `/app/logs/ai_guard_audit.jsonl`
- **Fail-closed** — if AI Guard DaS is unreachable in BLOCK mode, the pipeline does not fall back to uninspected Anthropic calls
- **Token auto-refresh** — ZIdentity tokens are cached and refreshed 2 minutes before expiry

---

## Troubleshooting

**Middleware shows `(unhealthy)` in docker compose ps**
The health check timing is strict. The middleware is working if `curl http://localhost:8000/health` returns OK. Ensure `docker-compose.yml` has `condition: service_started` not `service_healthy` in the `depends_on` block.

**ZIA/DSPM returning 400 on token endpoint**
Remove any `scope` parameter from the ZIdentity token request. Your tenant does not require scope in the client credentials grant.

**CASB returns 1,000 apps with no usage data**
`list_apps()` returns the full Zscaler cloud app catalogue. For actual usage data (which users accessed which apps), use `export_shadow_it_report()` or `export_shadow_it_csv()` — these return traffic-based data from your tenant.

**ZPA returns 0 findings**
The ZPA module scores segments based on scope analysis. If all segments are narrowly scoped (good posture), findings will be low or zero. Check `zpa_digest_*.md` for details.

**`service_healthy` keeps coming back after setup_pipeline.py**
Run `sed -i '' 's/condition: service_healthy/condition: service_started/' docker-compose.yml` after each setup script run, or edit `docker-compose.yml` directly.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `zscaler-sdk-python` | Zscaler API access (CASB, ZIA, ZPA, DSPM) |
| `anthropic` | Claude API client |
| `fastapi` + `uvicorn` | REST API and web server |
| `apscheduler` | Weekly pipeline scheduler |
| `httpx` | HTTP client for AI Guard middleware |
| `python-dotenv` | Environment variable loading |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Test with dry-run before live: `curl -X POST http://localhost:8080/pipeline/dry-run`
4. Submit a pull request

---

## Licence

MIT — see `LICENSE` file.

---

*Built for Zscaler deployments using ZIdentity OneAPI, AI Guard DaS, and Anthropic Claude.*
