const crypto = require('crypto');

const SUPPORTED_DATASETS = new Set([
    'firewall_events',
    'access_requests',
    'audit_logs',
    'gateway_dns',
    'gateway_http'
]);

function text(value) {
    return value === null || value === undefined ? '' : String(value).trim();
}

function first(record = {}, keys = []) {
    for (const key of keys) {
        const value = record[key];
        if (value !== null && value !== undefined && value !== '') return value;
    }
    return null;
}

function eventTime(record = {}) {
    const value = first(record, ['datetime', 'Datetime', 'timestamp', 'Timestamp', 'CreatedAt', 'created_at', 'EdgeStartTimestamp']);
    if (typeof value === 'number') return new Date(value > 1e12 ? value : value * 1000).toISOString();
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

function normaliseDataset(value) {
    const dataset = text(value).toLowerCase();
    return SUPPORTED_DATASETS.has(dataset) ? dataset : null;
}

function normaliseCloudflareLogpushRecord(record = {}, { dataset, accountId } = {}) {
    const resolvedDataset = normaliseDataset(dataset || record.dataset || record.Dataset);
    if (!resolvedDataset || !record || typeof record !== 'object' || Array.isArray(record)) return null;
    const sourceEventId = text(first(record, ['RayID', 'ray_id', 'RequestID', 'request_id', 'ID', 'id', 'EventID', 'event_id'])) || null;
    const normalised = {
        dataset: resolvedDataset,
        cloudflareAccountId: text(accountId || first(record, ['AccountID', 'account_id', 'AccountId'])) || null,
        sourceEventId,
        eventTime: eventTime(record),
        action: text(first(record, ['Action', 'action', 'Allowed', 'allowed', 'Decision', 'decision'])) || null,
        user: text(first(record, ['Email', 'email', 'UserID', 'user_id', 'UserEmail', 'user_email'])) || null,
        ipAddress: text(first(record, ['ClientIP', 'client_ip', 'IPAddress', 'ip_address', 'SourceIP', 'source_ip'])) || null,
        resource: text(first(record, ['ZoneName', 'zone_name', 'AppDomain', 'app_domain', 'HTTPHost', 'http_host', 'URL', 'url', 'QueryName', 'query_name', 'PolicyName', 'policy_name'])) || null,
        policy: text(first(record, ['PolicyName', 'policy_name', 'RuleID', 'rule_id', 'RuleMessage', 'rule_message'])) || null,
        raw: record
    };
    const stable = sourceEventId || crypto.createHash('sha256').update(JSON.stringify({
        dataset: normalised.dataset,
        account: normalised.cloudflareAccountId,
        time: normalised.eventTime,
        action: normalised.action,
        user: normalised.user,
        ip: normalised.ipAddress,
        resource: normalised.resource,
        policy: normalised.policy
    })).digest('hex');
    return { ...normalised, eventKey: `${normalised.dataset}:${stable}` };
}

function normaliseCloudflareLogpushPayload(payload, options = {}) {
    const records = Array.isArray(payload) ? payload : [payload];
    const results = records.map(record => normaliseCloudflareLogpushRecord(record, options)).filter(Boolean);
    const unique = new Map(results.map(record => [record.eventKey, record]));
    return [...unique.values()];
}

function isBlocked(record = {}) {
    const action = text(record.action).toLowerCase();
    return action === 'false' || /block|deny|drop|challenge|reject|quarantine/.test(action);
}

function findingId(detectionId, anchor) {
    return crypto.createHash('sha256').update(`${detectionId}|${anchor}`).digest('hex').slice(0, 32);
}

function logpushEvidence(record, summary) {
    return {
        sourceType: 'cloudflare_logpush',
        sourceId: record.sourceEventId || record.eventKey,
        eventTime: record.eventTime,
        summary,
        details: {
            provider: 'Cloudflare',
            dataset: record.dataset,
            action: record.action,
            user: record.user || null,
            ipAddress: record.ipAddress || null,
            resource: record.resource || null,
            policy: record.policy || null
        }
    };
}

function buildCloudflareLogpushFindings(records = [], { minimumRepeatedBlocks = 5 } = {}) {
    const findings = [];
    const blockedGroups = new Map();
    records.filter(isBlocked).forEach(record => {
        if (!['firewall_events', 'gateway_dns', 'gateway_http'].includes(record.dataset)) return;
        const key = [record.dataset, record.resource || 'unknown-resource', record.ipAddress || record.user || 'unknown-actor'].join('|').toLowerCase();
        const group = blockedGroups.get(key) || [];
        group.push(record);
        blockedGroups.set(key, group);
    });
    blockedGroups.forEach(group => {
        if (group.length < minimumRepeatedBlocks) return;
        const firstRecord = group[0];
        const entity = firstRecord.resource || firstRecord.ipAddress || firstRecord.user || 'an unidentified entity';
        findings.push({
            id: findingId('cloudflare_repeated_security_blocks', `${firstRecord.dataset}|${entity}`),
            detectionId: 'cloudflare_repeated_security_blocks',
            title: `Repeated Cloudflare ${firstRecord.dataset.replace(/_/g, ' ')} blocks affecting ${entity}`,
            description: `${group.length} returned Cloudflare block or deny event(s) for the same available resource or actor in the collected batch. This is an aggregated provider pattern, not proof of a successful attack.`,
            impact: 'Repeated security blocks may indicate hostile probing, an application issue, or an overly broad policy. The available events show blocking, not successful compromise.',
            severity: 'unassessed',
            confidence: 'medium',
            confidenceReason: `The finding is based on ${group.length} separate Cloudflare events sharing the same dataset and available entity value. Historical baseline and full traffic coverage are not yet available.`,
            status: 'needs_investigation',
            source: 'Cloudflare',
            affectedEntities: {
                users: [...new Set(group.map(item => item.user).filter(Boolean))],
                devices: [],
                ipAddresses: [...new Set(group.map(item => item.ipAddress).filter(Boolean))],
                resources: [...new Set(group.map(item => item.resource).filter(Boolean))]
            },
            evidence: group.slice(0, 8).map(record => logpushEvidence(record, `${record.dataset} ${record.action || 'security'} event`)),
            recommendedAction: 'Review the affected resource, policy, actor context, and adjacent Cloudflare/Microsoft evidence before taking containment action.',
            assessmentBasis: 'Stack CTRL aggregated returned Cloudflare blocked events by dataset and the available resource or actor. It does not infer attack success or account compromise.',
            collectionLimitations: group.length > 8 ? [`${group.length - 8} additional grouped event(s) are retained in evidence storage but omitted from the AI package.`] : []
        });
    });
    return findings;
}

function apiEvidence(sourceType, record, summary) {
    return {
        sourceType,
        sourceId: text(record.id || record.rayId || record.uuid) || null,
        eventTime: record.timestamp || record.created_at || record.createdAt || record.updatedAt || null,
        summary,
        details: {
            provider: 'Cloudflare',
            action: record.action || record.decision || null,
            user: record.userEmail || record.email || null,
            ipAddress: record.ipAddress || record.ip || null,
            resource: record.appName || record.resource || record.zoneName || record.zone || null
        }
    };
}

function buildCloudflareApiFindings(summary = {}, { minimumRepeatedAccessDenials = 3 } = {}) {
    const findings = [];
    const deniedGroups = new Map();
    (Array.isArray(summary.accessLogs) ? summary.accessLogs : []).forEach(log => {
        if (!isBlocked(log)) return;
        const key = [log.appName || 'unknown-app', log.userEmail || log.ipAddress || 'unknown-actor'].join('|').toLowerCase();
        const group = deniedGroups.get(key) || [];
        group.push(log);
        deniedGroups.set(key, group);
    });
    deniedGroups.forEach(group => {
        if (group.length < minimumRepeatedAccessDenials) return;
        const firstLog = group[0];
        const resource = firstLog.appName || 'a protected application';
        const actor = firstLog.userEmail || firstLog.ipAddress || 'an unidentified actor';
        findings.push({
            id: findingId('cloudflare_repeated_access_denials', `${resource}|${actor}`),
            detectionId: 'cloudflare_repeated_access_denials',
            title: `Repeated Cloudflare Access denials for ${resource}`,
            description: `${group.length} denied or blocked Access request(s) for ${actor} were returned in the current Cloudflare collection. This does not establish unauthorised access or compromise.`,
            impact: 'Repeated denials can indicate a user access problem, probing, or a policy issue. The returned records show denied requests rather than successful access.',
            severity: 'unassessed',
            confidence: 'medium',
            confidenceReason: `${group.length} returned Cloudflare Access records share the same available application and actor. The current API collection is limited to returned records and is not a full event stream.`,
            status: 'needs_investigation',
            source: 'Cloudflare',
            affectedEntities: {
                users: [...new Set(group.map(item => item.userEmail).filter(Boolean))],
                devices: [],
                ipAddresses: [...new Set(group.map(item => item.ipAddress).filter(Boolean))],
                resources: [...new Set(group.map(item => item.appName).filter(Boolean))]
            },
            evidence: group.slice(0, 8).map(log => apiEvidence('cloudflare_access_log', log, `Access ${log.action || 'denied'} event`)),
            recommendedAction: 'Review the Access policy, the affected application, and the user or IP context before changing a policy or taking containment action.',
            assessmentBasis: 'Stack CTRL aggregated returned Cloudflare Access deny/block records with the same available application and actor. It does not infer successful access.',
            collectionLimitations: ['Access activity is limited to records returned by the configured Cloudflare API query.']
        });
    });

    (Array.isArray(summary.auditLogs) ? summary.auditLogs : []).forEach((record, index) => {
        const action = text(record.action || record.action_type || record.type || record.operation).toLowerCase();
        const resource = text(record.resource || record.resource_type || record.zone_name || record.zone || record.name);
        if (!/create|update|delete|modify|change/.test(action) || !/security|firewall|waf|gateway|access|policy|dns|rule/.test(`${action} ${resource}`.toLowerCase())) return;
        findings.push({
            id: findingId('cloudflare_security_configuration_change', record.id || `${action}|${resource}|${record.created_at || record.timestamp || index}`),
            detectionId: 'cloudflare_security_configuration_change',
            title: 'Cloudflare security configuration change observed',
            description: `Cloudflare returned an audit record for ${action || 'a change'}${resource ? ` affecting ${resource}` : ''}. The returned audit record does not by itself establish whether the change was authorised.`,
            impact: 'A security configuration change can affect protection or access controls. Authorisation and downstream impact require review.',
            severity: 'unassessed',
            confidence: 'low',
            confidenceReason: 'The current evidence is one Cloudflare audit record; change approval and before/after configuration are not available in the returned data.',
            status: 'needs_investigation',
            source: 'Cloudflare',
            affectedEntities: { users: [], devices: [], ipAddresses: [], resources: resource ? [resource] : [] },
            evidence: [apiEvidence('cloudflare_audit_log', record, `Audit ${action || 'change'}${resource ? ` — ${resource}` : ''}`)],
            recommendedAction: 'Verify the change against an approved request, identify the actor and affected control, and confirm the intended protection remains in place.',
            assessmentBasis: 'Cloudflare returned a security-relevant audit record. Stack CTRL does not infer intent or unauthorised activity from one record.'
        });
    });
    return findings;
}

module.exports = {
    SUPPORTED_DATASETS,
    normaliseCloudflareLogpushRecord,
    normaliseCloudflareLogpushPayload,
    buildCloudflareLogpushFindings,
    buildCloudflareApiFindings
};
