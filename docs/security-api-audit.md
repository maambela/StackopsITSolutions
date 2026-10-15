# Sunbird security API audit

**Audit date:** 14 October 2026 (SAST)  
**Evidence reviewed:** Sunbird Security Alerts live dashboard snapshot supplied on 14 October 2026; current Stack CTRL implementation.  
**Scope:** Microsoft Graph security collection, identity-risk sources, Graph hunting readiness, and prerequisites for finding-based WhatsApp notification.

## Important interpretation rule

`Unavailable`, `partial`, `rate limited`, and `not assessed` are not equivalent to an empty result or a clean security state. Stack CTRL must preserve that distinction in the dashboard and in any notification decision.

## Permission configuration

The Entra application-permission screenshot shows tenant admin consent for the relevant application roles, including:

- `AuditLog.Read.All`
- `SecurityAlert.Read.All`
- `SecurityIncident.Read.All`
- `ThreatHunting.Read.All`
- `ThreatIndicators.Read.All`
- `IdentityRiskyUser.Read.All`
- `IdentityRiskEvent.Read.All`
- `Reports.Read.All`
- Supporting identity, device, application, group, and authentication-method read permissions.

The outstanding issues below are therefore not explained by a missing Graph permission grant alone.

## Observed endpoint audit

| Source / endpoint | Observed live response | Finding | Classification | Proposed resolution |
| --- | --- | --- | --- | --- |
| `GET /v1.0/security/alerts` | Seven Microsoft Graph anonymous-IP alerts are displayed as evidence-backed findings. The dashboard snapshot does not preserve the successful HTTP status code. | Alert collection is returning usable provider data. Each current finding has only the alert as evidence; it is not proof of authentication or compromise. | Data available; audit-response detail incomplete. | Retain per-request HTTP status, request ID, record count, pagination state, and collection timestamp in the audit response. Keep the seven events dashboard-only until corroborated. |
| `GET /v1.0/security/incidents` | No active incidents are displayed. The dashboard does not expose a source HTTP status for this run. | Zero incidents must only be treated as a valid zero if the endpoint completed successfully. | Not independently verifiable from the supplied UI. | Include endpoint status and record count in the API audit. Do not interpret the absence of an incident card as proof of no incidents. |
| `GET /v1.0/security/tiIndicators` | `400` reported: threat indicators unavailable. | The consented `ThreatIndicators.Read.All` role did not produce a usable collection. A 400 can indicate endpoint/query/provider or tenant-capability conditions; it is not a no-indicator result. | Tenant/API capability or request-shape investigation required. | Capture the bounded Graph error body and request ID in the audit. Validate the endpoint directly against the tenant and review the supported Defender threat-intelligence capability before changing detections. |
| `GET /v1.0/auditLogs/signIns` | `429 Too Many Requests` reported by Graph; dashboard marks sign-in collection rate limited. | Anonymous-IP and risky-user correlations are incomplete. The current absence of a matching sign-in is not a clean result. | Service throttling plus implementation resilience gap. | Implement `Retry-After` aware exponential backoff, scheduled collection, cache reuse, and pagination. Re-run until the source reports completed. Do not notify anonymous-IP-only findings. |
| `GET /v1.0/identityProtection/riskyUsers` | `403 Forbidden`: tenant not licensed for the feature. | Risky-user + successful-sign-in scenario cannot be validated with this source. | Tenant licensing / feature availability. | Confirm Entra ID Protection licensing and user assignment. If the tenant cannot provide the feed, retain the scenario as unavailable rather than infer risk. |
| `GET /v1.0/identityProtection/riskDetections` | No independent status/error was exposed in the supplied UI. | The dashboard must report this separately from risky users; a successful or failed detection feed cannot be inferred from the other endpoint. | Audit visibility gap. | Add separate response code, request ID, record count, and warning for risk detections in the API audit. |
| `POST /v1.0/security/runHuntingQuery` | Not yet executed against the Sunbird production token in this audit. The Stack CTRL route and bounded `IdentityLogonEvents` query are implemented and covered by unit tests. | Consent alone does not prove Defender hunting data or a supported table is available. | Live tenant validation outstanding. | In the deployed Stack CTRL environment, call `POST /api/security-events/hunting-query` with `{ "queryId": "identityLogons30d" }`. Record HTTP status, returned schema, record count, result-limit state, and any Graph error body/request ID. |
| Cloudflare posture / coverage | Posture and coverage records appear; no Cloudflare incident activity is represented. | This is useful context but is not incident evidence and must not increase a Microsoft finding's severity by itself. | Available, separate context. | Keep it in the evidence model as posture/coverage unless a concrete Cloudflare alert is received. |

## Live audit result — 15 October 2026

An authenticated production audit was completed at `2026-10-15T13:14:49.401Z` with hunting enabled.

| Source / endpoint | Response | Conclusion | Follow-up |
| --- | --- | --- | --- |
| `/v1.0/security/alerts` | `200`, 15 records, one attempt | Working. | Use as provider evidence only. |
| `/v1.0/security/incidents` | `200`, 0 records, one attempt | Valid empty response for this collection. | Keep collection active. |
| `/v1.0/auditLogs/signIns` | `200`, 100 records, one page; Graph supplied a next page | The former `429` did not occur in this run. The collection was incomplete because the implementation was limited to its first page. | Implement bounded next-link pagination and preserve the partial state if the page limit is reached. |
| `/v1.0/security/tiIndicators` | `400`, `Resource not found for the segment 'tiIndicators'` | This is a concrete resource/API availability problem, not an empty indicator set or a missing permission grant. | Do not treat internally extracted IOCs as a successful external threat-intelligence response. Confirm the supported replacement/source before enabling an external indicator collector. |
| `/v1.0/identityProtection/riskDetections` | 14 records reported | Identity risk detections are available. | Use only as cited identity-risk evidence. |
| `/v1.0/identityProtection/riskyUsers` | `403`, tenant not licensed | Risky-user scenario remains unavailable. | Tenant licensing decision required; do not infer risky-user state. |
| `/v1.0/security/runHuntingQuery` | `200`, expected schema, 0 rows | Endpoint, permission, and query all work. Defender has no `IdentityLogonEvents` records in the requested 30-day period. | Retain as an available but currently empty supplemental source; do not manufacture hunting correlation. |

## Detection-scenario status

| Scenario | Current status | Reason | Next validation evidence |
| --- | --- | --- | --- |
| Anonymous IP + authentication activity | Unavailable / incomplete | Sign-in query was throttled. Current seven findings cite only anonymous-IP alerts. | Completed sign-in collection, exact IP plus defensible time window, authentication result, affected user, and any available identity-risk record. |
| Impossible travel | Not assessed | Coordinates may be retained but the system has not validated coverage, distance/time thresholds, or VPN/proxy limitations. A raw `Atypical travel` provider alert is not a Stack CTRL validated impossible-travel detection. | Two successful sign-ins for the same stable user identity with valid coordinates and timestamps; documented speed/distance policy; VPN/proxy and native-provider-risk handling. |
| Risky user + successful sign-in | Unavailable / incomplete | Risky-user endpoint returned a licensing-related 403 and sign-in collection was rate limited. | A licensed risky-user or risk-detection record, stable user-ID/UPN match, successful sign-in, and any relevant device/security context. |

## Implementation gaps before WhatsApp

1. **Finding-based selection:** the current WhatsApp path still selects raw alerts/incidents by provider severity. It must select eligible Stack CTRL findings.
2. **Notification policy:** define severity, confidence, impact, aggregation, cooldown, escalation, and resolution rules. An unassessed, low-confidence anonymous-IP observation must not page recipients.
3. **Evidence reference:** every message must identify the Stack CTRL finding and provide a route back to the cited evidence.
4. **Collection resilience:** preserve HTTP response code, Graph request ID, `Retry-After`, pagination, timestamp, and error classification per source. Retry throttled sources safely.
5. **Finding lifecycle:** persist status, owner, resolution history, notification history, and deduplication/escalation state at the finding level.
6. **Hunting integration:** use successful, bounded hunting results only as additional cited correlation evidence; do not treat hunting as a replacement for normal Graph sources.

## Readiness decision

The current dashboard is suitable for investigation and source-coverage visibility. It is **not ready for automatic security WhatsApp escalation** until sign-ins have a completed collection, identity-risk availability is resolved or explicitly excluded, hunting is tested in the Sunbird tenant, and notification selection is moved from raw events to eligible findings.

## Running the live audit after deployment

An authenticated Sunbird operator can trigger a non-notifying audit with:

```http
POST /api/security-events/audit
Content-Type: application/json

{ "includeHunting": true }
```

This endpoint does not send WhatsApp notifications. It returns each collection source's endpoint, HTTP status, attempt count, Graph request IDs, `Retry-After` value, bounded error detail, record count, and scenario coverage. When requested, it also runs the bounded allow-listed `identityLogons30d` hunting query and returns its schema/record-count metadata without exposing hunting records in the audit summary.

For a `429`, Stack CTRL retries a bounded number of times, honours Graph's `Retry-After` response when supplied, and records the final result. Cloud Run logs can be correlated using `graphRequestId`, `clientRequestId`, and the `security_alerts:*` collection-stage messages.

## Sign-in collection remediation

Following the 15 October audit, Stack CTRL's sign-in collector was changed to request up to 1,000 records per Graph page, pace any follow-up page requests, and collect at most three pages by default. This reduces the request burst that caused the page-five `429` while retaining a bounded collection window.

If Microsoft throttles after one or more pages have returned, Stack CTRL keeps the returned records and marks the source and anonymous-IP scenario **partial**. It must not label that scenario unavailable or claim that no matching sign-in exists. `SECURITY_SIGNINS_MAX_PAGES` and `SECURITY_SIGNINS_PAGE_DELAY_MS` are bounded server-side configuration values for later tuning from production audit results.

## Latest production validation — 15 October 2026, 17:16 UTC

The follow-up audit completed the intended bounded sign-in collection successfully:

| Source / endpoint | Result | Interpretation |
| --- | --- | --- |
| `/v1.0/auditLogs/signIns` | `200`, 3,000 records across three pages, three attempts; Graph supplied an additional page | The `429` was not reproduced. Collection is deliberately **partial**, not failed: Stack CTRL stopped at its three-page safety limit and retained the returned evidence. |
| `/v1.0/security/alerts` | `200`, 15 records | Working provider-alert input. |
| `/v1.0/security/incidents` | `200`, zero records | Valid empty response for this collection. |
| `/v1.0/identityProtection/riskDetections` | 14 records | Available as cited identity-risk evidence. |
| `/v1.0/identityProtection/riskyUsers` | `403`, tenant not licensed | Still unavailable by tenant feature/licensing design. |
| `/v1.0/security/tiIndicators` | `400`, resource segment not found | Still unavailable as an external indicator source. |
| `/v1.0/security/runHuntingQuery` | `200`, expected schema, zero rows | Endpoint and permission work; there are no matching `IdentityLogonEvents` rows in the selected 30-day window. |

The audit response now also includes `scenarioFindings`. Its `anonymousIpAuthentication` section lists every anonymous-IP finding, its cited sign-in count, any returned sign-in outcomes, candidate users, evidence count, status, confidence, and recommended action. This is the validation output for Scenario A: it distinguishes a genuine, cited correlation from an alert that remains an observation only.

Use the authenticated, non-notifying audit endpoint after deploying this change. Preserve the `scenarioCoverage`, `scenarioFindings`, and `warnings` fields from that one run as the Scenario A evidence record. Avoid repeatedly running the audit during validation, because it intentionally reads a sizeable Graph sign-in window.
