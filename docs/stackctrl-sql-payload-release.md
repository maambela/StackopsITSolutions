# StackCTRL SQL payload diagnostics release

Release application commit `d3ae2505613dfd0bad48c5c2d57d1ca6ddb6d0a4`. Rollout target is Cloud Run service `stackops-backend` in `us-central1`, project `stackops-backend-475222`.

## 1. Deploy the reviewed image

1. In **Cloud Run → stackops-backend → Revisions**, record the currently serving revision and traffic split. If the reviewed image is already serving, go directly to verification. Confirm the preceding revision already has Phase 1 and Phase 2. If it predates Phase 2, use the separate bridge and drain procedure before changing writer versions.
2. Deploy the image built from the reviewed commit via the existing release mechanism. Use a Git-commit-based build to exclude unrelated local work. The checked-in [Cloud Build config](../cloudbuild.yaml#L22) reapplies 2 GiB memory, 1 CPU, minimum instances 0, CPU throttling, a 3,600-second timeout, and specific connection, environment and access settings. Use that trigger only when its settings match the serving service. If they differ, use the reviewed image from a build-only path and deploy it via **Edit and deploy new revision**, changing only the image.
3. Preserve the existing resource configuration and MySQL connection settings. Keep `NETWORK_EVIDENCE_COLLECTION_ENABLED=true` and leave Cloud SQL `max_allowed_packet` at 33,554,432 bytes. The reviewed commit continues to write legacy tenant snapshots. Record the new revision name from the Revisions tab.

## 2. Verify and return one report

Open the Network Security dashboard normally. Use the next scheduled tenant collection if it falls within the verification window. Otherwise, use **Create Snapshot** once for company 1 and keep its success snapshot ID or safe failure request ID. Avoid a repeated attempt after `SNAPSHOT_COMMIT_OUTCOME_UNKNOWN` until the latest committed snapshot is checked.

In **Cloud Shell**, paste the block below after entering the new revision name on the second line. It uses read-only commands. The exported JSON selects operational fields and leaves out complete log messages, evidence, SQL and credentials. The default window is six hours.

```bash
project='stackops-backend-475222'
revision='REPLACE_WITH_NEW_REVISION'
region='us-central1'
service='stackops-backend'
set -o pipefail

filter="resource.type=\"cloud_run_revision\"
resource.labels.service_name=\"$service\"
resource.labels.revision_name=\"$revision\"
(
  jsonPayload.event =~ \"^snapshot_(sql_(payload_(measured|warning|exceeds_limit)|execution_failed)|transaction_rollback_failed)$\"
  OR textPayload =~ \"snapshot_(sql_(payload_(measured|warning|exceeds_limit)|execution_failed)|transaction_rollback_failed)\"
  OR textPayload =~ \"network_evidence_refresh_skipped_(fresh|busy|disabled)|tenant_snapshot_storage_invalid|tenant_snapshot_hydrated\"
  OR jsonPayload.event =~ \"^network_evidence_refresh_skipped_(fresh|busy|disabled)$\"
  OR jsonPayload.collectionTrigger=\"dashboard_request\"
  OR textPayload : \"dashboard_request\"
  OR textPayload : \"[Network Evidence] Stored snapshot\"
  OR (httpRequest.requestMethod=\"POST\" AND httpRequest.requestUrl =~ \"/api/admin/intelligence/tenant/1/snapshot($|[?])\")
)"

revision_settings=$(gcloud run revisions describe "$revision" --project="$project" --region="$region" --format=json |
  jq '{revision: .metadata.name, image: .spec.containers[0].image,
    imageDigest: .status.imageDigest, resources: .spec.containers[0].resources.limits,
    timeoutSeconds: .spec.timeoutSeconds, concurrency: .spec.containerConcurrency,
    minimumInstances: .metadata.annotations["autoscaling.knative.dev/minScale"],
    cpuThrottling: .metadata.annotations["run.googleapis.com/cpu-throttling"],
    networkEvidenceCollectionEnabled: ([.spec.containers[0].env[]? |
      select(.name == "NETWORK_EVIDENCE_COLLECTION_ENABLED") | (.value // "indirect")][0] // "default_true")}')

if [ -n "$revision_settings" ]; then
gcloud logging read "$filter" --project="$project" --freshness=6h --limit=1000 --format=json |
jq --argjson settings "$revision_settings" 'def event_payload:
      .jsonPayload // ((.textPayload // "") | sub("^\\[Runtime\\] "; "") | fromjson? // {});
    {revisionSettings: $settings, events: (map(. as $entry | event_payload as $event |
      {timestamp, severity, revision: .resource.labels.revision_name}
      + (if $entry.httpRequest then
          {event: "admin_snapshot_http", status: $entry.httpRequest.status}
        elif $event.event then
          ($event | {event, operation, table, companyId, requestId, connectionId,
            sessionMaxAllowedPacket, globalMaxAllowedPacket, measurement, columns,
            commandBytes, wireBytes, headroomBytes, packetLimitPercent, evidenceCounts,
            metadataErrorCode, errorCode, mysqlErrno, stage, failedPhase, commitOutcomeUnknown,
            collectionTrigger, snapshotId, storageVersion} | with_entries(select(.value != null)))
        elif ($entry.textPayload // "" | contains("[Network Evidence] Stored snapshot")) then
          {event: "network_evidence_stored"}
          + ($entry.textPayload | capture("Stored snapshot (?<snapshotId>[0-9]+) with (?<recordCount>[0-9]+) processed") // {})
        elif ($entry.textPayload // "" | contains("tenant_snapshot_storage_invalid")) then
          {event: "tenant_snapshot_storage_invalid"}
        elif ($entry.textPayload // "" | contains("tenant_snapshot_hydrated")) then
          {event: "tenant_snapshot_hydrated"}
        elif ($entry.textPayload // "" | contains("dashboard_request")) then
          {event: "network_evidence_dashboard_request_marker", collectionTrigger: "dashboard_request"}
        else {event: "unparsed_matching_log"} end)
    ) | sort_by(.timestamp))}' > stackctrl-sql-payload-verification.json &&
  jq -c '{revisionSettings, events: (.events | length)}' stackctrl-sql-payload-verification.json
fi
```

Return `stackctrl-sql-payload-verification.json` and, if you ran the manual probe, its snapshot ID or request ID. No SQL Studio session is needed for this check.

| Expected evidence | Interpretation |
|---|---|
| The revision settings show the reviewed image, existing resources, and Network Evidence collection enabled | Confirms the relevant deployed settings. An omitted flag reports `default_true` because the runtime enables collection by default. |
| A measurable company 1 tenant INSERT with session and global limits of 33,554,432 bytes | Confirms the limit on the application connection. HTTP 201 confirms publication. |
| A measured rejection plus `SNAPSHOT_SQL_PAYLOAD_TOO_LARGE` for the same request | Confirms the guard identified the operation and refused the command. Send the report so the next storage fix can be sized. |
| A Network Evidence publication or a fresh/busy skip | Indicates an active Phase 2 path. A disabled event requires checking the deployed flag. |
| No `dashboard_request` collection marker and no canonical hydration or storage errors in the observation window | Expected on normal dashboard reads and legacy-only storage. Missing log entries alone cannot establish these guarantees. |
| Empty report or only unmatched entries | Verification is incomplete. Check the revision name and use one manual Create Snapshot probe if needed. |

Roll back by restoring the recorded traffic split if normal-size commands fail, verified dashboard reads regress, or the new revision shows a new pattern of SQL connection or rollback failures. A correctly blocked oversized command by itself supports the diagnosis. Roll back to the prior Phase 2 revision so ownership stays compatible.
