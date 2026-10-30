# Cloudflare Logpush security ingestion

Stack CTRL accepts only the following Cloudflare Logpush datasets:

- `firewall_events`
- `access_requests`
- `audit_logs`
- `gateway_dns`
- `gateway_http`

It does not ingest general HTTP request traffic through this endpoint.

## Current no-administrator mode

Logpush is optional and is inactive until the administrator creates a verified mapping and delivery configuration. Until then, Stack CTRL continues to use its existing Cloudflare API collector without any Cloudflare administrator action. That collector can create evidence-backed findings from returned Access deny/block activity, security-relevant audit changes, Security Center insights, CASB findings, and application-security findings. It can also correlate a repeated Access-denial pattern with a Microsoft sign-in only where the same stable user, a 24-hour time window, and matching IP evidence when both sources provide it support the relationship.

This mode is not a full Cloudflare event stream. Missing API records or unavailable product endpoints remain a collection limitation rather than a clean result.

## Tenant mapping first

Before a Logpush job is created, add one verified mapping for each Cloudflare account. `CloudflareAccountID` is unique, so an account cannot be associated with more than one Stack CTRL customer. Store only a SHA-256 digest of the delivery secret.

```sql
INSERT INTO StackCTRLCloudflareTenantMappings
    (CompanyID, CloudflareAccountID, LogpushSecretSha256, IsEnabled)
VALUES
    (<STACKCTRL_COMPANY_ID>, '<CLOUDFLARE_ACCOUNT_ID>', SHA2('<LONG_RANDOM_DELIVERY_SECRET>', 256), 1);
```

The table is created automatically when Stack CTRL starts. The account ID and company ID must be verified by an administrator; the Logpush payload never determines tenant ownership.

## Destination

Configure an authenticated HTTPS Logpush destination for each approved dataset using:

```text
POST https://<stackctrl-host>/api/webhooks/cloudflare-logpush/<CLOUDFLARE_ACCOUNT_ID>/<DATASET>
```

The delivery must include either `cf-logpush-auth: <LONG_RANDOM_DELIVERY_SECRET>` or an `Authorization: Bearer <LONG_RANDOM_DELIVERY_SECRET>` header. Confirm the exact custom-header syntax supported by the selected Cloudflare Logpush destination before enabling production delivery.

Successful responses are `202`. Replays are safe: records are idempotent on company, account, dataset and event key. Unknown mappings, invalid secrets, or unsupported datasets are rejected and no evidence is stored.

## Processing and alerting

The current dashboard query considers the most recent 30 days of tenant-scoped Logpush evidence. A scheduled database retention cleanup is still required before production rollout. Stack CTRL currently creates a finding only when it sees at least five returned blocked/denied events for the same available resource or actor in one of the firewall/Gateway datasets. The finding is unassessed, explicitly does not claim a successful attack, and is passed through the existing Azure OpenAI assessment package with at most eight evidence rows.

The delivery endpoint does not send WhatsApp messages. Existing Stack CTRL eligibility and human-review safeguards remain in force.
