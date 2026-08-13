# Security Event Investigation

Security Events remain products of the local behavioral detectors. Threat Intelligence is persisted as post-detection enrichment, and Security AI is a manual, advisory-only operation. This feature does not enable threat-policy automation or automatic mitigation.

## API

Canonical authenticated routes:

- `GET /api/security/events/{event_id}`
- `GET /api/security/events/{event_id}/traffic?padding_seconds=600`
- `GET /api/security/events/{event_id}/sources?sort=packets&limit=100`
- `GET /api/security/events/{event_id}/evidence?sample_limit=100`
- `GET /api/security/events/{event_id}/ai-analysis`
- `POST /api/security/events/{event_id}/ai-analysis?force=false`

The existing `/security/events/...`, `/analyze-ai`, and `/reanalyze-ai` routes remain available for backward compatibility. A route accepts either the numeric database ID, the stable public ID (`GMJ-YYYYMMDD-XXXXXXXXXX`), or the canonical event key where applicable.

## Data and query limits

Each newly persisted event contains bounded snapshots for the top 50 sources, top 20 source/destination ports, protocol distribution, TCP flags, detector evidence, and score components. Existing events continue to render even if these snapshots are absent.

Timeline, source, port, protocol, and sample-conversation queries use `behavior_flow_10s`, an event-bounded time window, `PREWHERE` on the bucket, target/sensor/protocol filters, and explicit limits. Investigation endpoints never return or directly query unbounded `flow_raw` records. `GMJFLOW_SECURITY_EVENT_QUERY_MAX_SECONDS` caps the query window (default: 21,600 seconds).

## Manual Security AI

Security AI is disabled by default:

```dotenv
GMJFLOW_SECURITY_AI_ENABLED=false
GMJFLOW_SECURITY_AI_PROVIDER=groq
GMJFLOW_SECURITY_AI_MODEL=
GROQ_API_KEY=
GMJFLOW_SECURITY_AI_TIMEOUT_SECONDS=30
GMJFLOW_SECURITY_AI_MAX_PROMPT_CHARS=30000
GMJFLOW_SECURITY_AI_MAX_OUTPUT_TOKENS=1600
```

For an OpenAI-compatible endpoint, use `GMJFLOW_SECURITY_AI_PROVIDER=openai_compatible`, set `GMJFLOW_SECURITY_AI_BASE_URL`, and provide `GMJFLOW_SECURITY_AI_API_KEY` (or `OPENAI_API_KEY`). Calls happen only in the backend after an authorized user clicks Analyze.

The request contains structured, bounded event evidence rather than raw flows. Results and failures are recorded in `security_event_ai_analyses` with provider, model, event version, event/evidence fingerprints, status, timestamps, and sanitized errors. An unchanged event reuses its cached analysis. A new recurrence or changed evidence marks the previous result stale.

`GMJFLOW_THREAT_POLICY_AUTO_ENABLED=false` and `GMJFLOW_AUTO_MITIGATION_ENABLED=false` remain the safe defaults. Security AI never changes either setting and never executes mitigation.
