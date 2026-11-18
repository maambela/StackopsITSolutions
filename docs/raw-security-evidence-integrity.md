# Security Activity: live evidence, interpretation and diagnostics

New alerts are the priority. The default historical context is the previous **15 days**, retrieved from provider APIs. `SECURITY_EVIDENCE_HISTORY_DAYS` configures that lookback; provider retention and permissions still apply.

## Client presentation

Security Activity has six columns: Activity, Status, Severity, Affected entity, Source, Date and time. Activity descriptions and exact event times (seconds and time zone) are emphasized. Missing provider severity or timestamps show **Not provided**. An empty table is never evidence that an unavailable source has no activity.

Opening an activity shows what happened, involved identities/resources, time, origin, result and evidence-supported security context. Internal IDs, endpoints and original JSON belong to expandable Technical evidence. Provider text is escaped; JSON is rendered as text. Table pagination renders 100 rows at a time without reducing collection or discarding loaded records.

Clients see plain coverage warnings. Full counts, pages, attempts/completions, failures, rate limits, permission errors, storage state, limitations and collection metadata are in the separate **Data Source Health & Diagnostics** section. The server grants access only to an authenticated `admin` role; hiding HTML is not the authorization boundary. JSON, live streams, health responses and the explicit source-audit route enforce this distinction. Original evidence remains available to the authorized client within their own company.

## Interpretation boundary

Reusable deterministic backend interpreters live in `services/intelligence/raw-evidence-interpretation/`. Microsoft and Cloudflare event schemas are handled independently. This layer makes no external AI calls. Original parsed provider JSON remains in `rawPayload`; interpretation does not overwrite it or provider severity. Unsupported schemas remain unclassified and inspectable.

Supported families include Microsoft sign-ins, directory audit, alerts/incidents, identity risk and indicators; Cloudflare audit, Access, WAF/firewall, notifications, Security Center/CASB and Gateway/network/HTTP telemetry. Success, failure, interruption and policy blocks remain distinct. Risk levels are not invented severities; a blocked request is not automatically a confirmed attack. Category and MITRE bases are explicit in evidence details.

Client view filters only verified successful StackCTRL audit polling reads. `SECURITY_CLOUDFLARE_PLATFORM_TOKEN_IDS` must contain verified token IDs; matching requires the actual token ID, GET to an account audit endpoint, explicit success, HTTP 2xx and no supplied severity. A name alone is insufficient. All raw activity reveals these loaded records. Retrieval and original evidence are not filtered.

Incident correlation and AI generation logic are unchanged by this refinement. Directory audits remain raw evidence only. Other platform persistence and notification workflows are outside the raw activity storage policy.

## Live retrieval

`/api/security-events?stream=1` sends provider pages without waiting for storage, AI or WhatsApp. `/api/security-events/live` publishes polling, verified webhooks and Logpush deliveries. Authentication and company mapping remain mandatory. The legacy `/api/db/security-events` route also retrieves live data under the current policy.

Default background intervals are 30 seconds for alerts/incidents/Cloudflare, 60 for sign-ins/identity risk, 120 for directory audit and 300 for indicators. Each source has an independent overlap guard. Provider publication delay, throttling and collection duration affect actual latency. `SECURITY_RAW_POLL_ENABLED` and `SECURITY_RAW_POLL_INTERVAL_MS` control the independent raw scheduler.

Graph follows next links within source deadlines and preserves partial results and in-memory continuation state. Alert/incident live queries use modification time to include changes to older records. Completed collections advance a watermark with five-minute overlap, with a full lookback reconciliation at least hourly. Explicit historical searches use creation time. Cloudflare REST pages/cursors and adaptive firewall interval splitting remain intact. Sampling, saturated windows, missing permissions and unsupported products remain coverage limitations. Adaptive analytics does not establish complete unsampled delivery.

Logpush supports JSON, NDJSON, gzip and authenticated validation probes. Batches are limited to 20 MiB decompressed. Configure entitled unsampled/unfiltered delivery jobs and verified account/company mappings. A `202` acknowledges live acceptance, **not durable storage**.

## Database storage disabled

`services/intelligence/security-storage-policy.js` sets `SECURITY_ALERT_STORAGE_ENABLED = false`. Environment defaults cannot re-enable it. The server disables writes to the raw journal/checkpoints, Cloudflare Logpush events, real-time alert store, security dashboard payload cache and security evidence snapshots. The scheduled snapshot collector is disabled; the independent live raw poller remains enabled. Store constructors retain an explicit persistence override for legacy storage regression fixtures; production wiring passes the disabled policy.

No existing database records are deleted. Deploying and restarting the updated server is necessary to stop production writes; this code change does not reclaim database space. Tenant mappings/authentication still use configuration reads. Other application data and existing correlation/AI algorithms are not removed.

Recent original records are held only in a process-local cache bounded to 32 MiB / 2,000 records. `/api/security-events/record?uid=...` enforces company ownership and returns an explicit unavailable response after eviction. Original JSON is omitted from compact presentation rows and loaded on demand. `/history` replays available tenant-scoped memory records, including deliveries received before the dashboard opened; it has no database fallback. Provider collection supplies the historical lookback. In-memory checkpoints and originals disappear on restart. Logpush-only evidence cannot be replayed after eviction/restart unless the provider delivery/retention configuration supports it.

## Deployment and validation

Production permissions, subscriptions, Logpush jobs, mapping tables and hosting behavior must be verified in the deployment environment. These handlers do not create jobs/subscriptions. Always-running collector capacity is required for continuous polling. Fan-out is process-local; multiple replicas need same-instance routing or shared messaging. Disable proxy buffering on NDJSON routes.

No production deployment or database cleanup was performed in this workspace. Browser validation used an isolated fixture with no production credentials, AI calls or notifications. Tests cover no-database ingestion/snapshots, tenant isolation, client/admin projections, safe details, pagination, partial collection and incremental polling. The full suite reported 326 tests: 309 passed and the same 17 baseline failures, with no new failures.

## Provider schema references

- [Microsoft sign-in schema](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0)
- [Microsoft directory audit schema](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0)
- [Microsoft security alerts v2](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0)
- [Microsoft authentication error reference](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)
- [Cloudflare account audit](https://developers.cloudflare.com/fundamentals/account/account-security/audit-logs/)
- [Cloudflare firewall fields](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/firewall_events/)
- [Cloudflare HTTP Logpush setup](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/http/)
