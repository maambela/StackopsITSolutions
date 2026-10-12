# Security Alerts

## Evidence model

Security Alerts keeps Microsoft/provider alerts, incidents, suspicious sign-ins, deterministic correlated findings, Cloudflare posture findings, and source-coverage warnings distinct. A finding is based on collected evidence and links back to its source rows; it does not claim compromise based on IP equality alone. Findings with unvalidated severity remain unassessed.

Internal observables are extracted only from explicit IOC fields (IP address, URL, domain, file hash, or sender address), and values are format-validated. User names, device names, alert titles, categories, and incidental strings are not treated as threat indicators. Internal observables are not reputation-checked unless an external enrichment source explicitly supplies that assessment.

Cloudflare configuration posture (for example, a disabled proxy), unavailable API sections, and permission gaps are displayed as posture or coverage information. They are not counted as provider incidents or alerts. Actual Cloudflare blocked/denied activity and provider findings retain their own evidence and source.

## Microsoft Defender hunting

The authenticated `POST /api/security-events/hunting-query` endpoint supports only server-defined query IDs. It currently accepts `identityLogons30d`, which runs a fixed `IdentityLogonEvents` query over the last 30 days and returns at most 100 rows with the Graph schema. Clients cannot submit arbitrary KQL.

The Microsoft Graph application registration must have the `ThreatHunting.Read.All` application permission, with tenant admin consent granted. The endpoint reports permission, timeout, and invalid-response failures explicitly; it does not treat unavailable hunting results as an empty or successful investigation. Live tenant behavior still requires a deployment with the required Microsoft tenant permission and data entitlement.
