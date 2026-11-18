# Cloudflare Logpush security ingestion

Stack CTRL accepts only the following Cloudflare Logpush datasets:

- `firewall_events`
- `http_requests`
- `network_analytics_logs`
- `access_requests`
- `audit_logs`
- `gateway_dns`
- `gateway_http`

HTTP and network analytics records retain available DDoS and traffic evidence. Availability depends on the account's products and plan.

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

The mapping table must already exist (its schema is defined in `services/intelligence/cloudflare-logpush-store.js`). Automatic security storage schema creation is disabled. The account ID and company ID must be verified by an administrator; the Logpush payload never determines tenant ownership. Mapping configuration is separate from security alert storage.

## Destination

Configure an authenticated HTTPS Logpush destination for each approved dataset using:

```text
POST https://<stackctrl-host>/api/webhooks/cloudflare-logpush/<CLOUDFLARE_ACCOUNT_ID>/<DATASET>
```

The delivery must include either `cf-logpush-auth: <LONG_RANDOM_DELIVERY_SECRET>` or an `Authorization: Bearer <LONG_RANDOM_DELIVERY_SECRET>` header. Confirm the exact custom-header syntax supported by the selected Cloudflare Logpush destination before enabling production delivery.

Successful responses are `202`, meaning accepted for live delivery, not durable storage. Security alert database storage is disabled. Replays use stable company/account/dataset/event identities in the live view. Unknown mappings, invalid secrets, or unsupported datasets are rejected.

JSON, NDJSON and gzip are supported, including gzip files without Content-Encoding. Configure batches below the 20 MiB decompressed receiver limit. Authenticated `{"content":"tests"}` validation probes return `200` without creating evidence. Use unsampled, unfiltered jobs for complete delivery of an entitled dataset. See [Cloudflare HTTP destinations](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/http/).

New batches reach the live feed immediately. Recent original JSON is available under Technical evidence from bounded temporary memory; deterministic provider-specific interpretation runs locally without an AI call. Client view can filter verified platform audit reads using `SECURITY_CLOUDFLARE_PLATFORM_TOKEN_IDS`; All raw activity reveals loaded filtered records. Retrieval counts and errors are restricted to administrator diagnostics.

## Processing and alerting

The default raw historical context is 15 days, retrieved from provider APIs subject to availability and retention. Memory-only Logpush records are lost on restart or eviction; complete replay requires provider-side retention/delivery configuration. Existing database records are not deleted by this change. Correlation and AI assessment logic remain separate and unchanged.

The delivery endpoint does not send WhatsApp messages. Existing Stack CTRL eligibility and human-review safeguards remain in force.
