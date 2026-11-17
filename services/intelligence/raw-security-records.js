const { createHash } = require('node:crypto');
const { interpretRawEvidence } = require('./raw-evidence-interpretation');

function providerTimestamp(value) {
    if (typeof value === 'number' || (typeof value === 'string' && /^\d{10,20}$/.test(value))) {
        try {
            const digits = String(value).split('.')[0];
            const number = BigInt(digits);
            const milliseconds = digits.length > 16 ? number / 1000000n : digits.length > 13 ? number / 1000n : digits.length <= 10 ? number * 1000n : number;
            return new Date(Number(milliseconds)).toISOString();
        } catch (_) { return null; }
    }
    return typeof value === 'string' ? value : null;
}
// Presentation envelopes retain the untouched provider object. Missing values stay null.
function rawSecurityRecord(payload, { provider, endpoint, recordType, companyId, retrievedAt }) {
    const raw = payload && typeof payload === 'object' ? payload : { value: payload };
    let id = raw.id || (raw.alert_correlation_id ? [raw.alert_correlation_id, raw.ts, raw.alert_event].join(':') : null) || raw.uuid || raw.ray_id || raw.rayName || raw.RayID || createHash('sha256').update(JSON.stringify(raw)).digest('hex');
    if ((raw.RayID || raw.rayName || raw.ray_id) && (raw.RuleID || raw.ruleId || raw.rule_id)) id += ':' + createHash('sha256').update(JSON.stringify([raw.RuleID || raw.ruleId || raw.rule_id, raw.source || raw.Source, raw.datetime || raw.Datetime, raw.action || raw.Action])).digest('hex');
    const timestamp = providerTimestamp( raw.ts || raw.eventDateTime || raw.firstActivityDateTime || raw.activityDateTime || raw.datetime || raw.Datetime || raw.sent || raw.createdDateTime || raw.created_at || raw.created_on || raw.timestamp || raw.time || raw.action?.time || raw.detectedDateTime || raw.riskLastUpdatedDateTime || raw.Timestamp || raw.EdgeStartTimestamp || raw.CreatedAt || null);
    const status = typeof raw.status === 'object' ? raw.status?.errorCode ?? null : raw.status ?? (typeof raw.action === 'object' ? raw.action?.type : raw.action) ?? raw.Action ?? raw.decision ?? null;
    const record = {
        uid: `${companyId}:${provider}:${endpoint}:${id}`, id, companyId, provider, apiSource: provider,
        endpoint, recordType, retrievedAt, rawPayload: payload,
        providerVersion: Date.parse(raw.lastUpdateDateTime || raw.lastUpdatedDateTime || raw.lastModifiedDateTime || raw.riskLastUpdatedDateTime || raw.updated_at || raw.updated_on || '') || 0,
        originalCreatedAt: raw.createdDateTime || raw.created_at || raw.created_on || null,
        originalModifiedAt: raw.lastUpdateDateTime || raw.lastUpdatedDateTime || raw.lastModifiedDateTime || raw.riskLastUpdatedDateTime || raw.updated_at || raw.updated_on || null,
        title: raw.title || raw.data?.title || raw.data?.name || raw.text || raw.alert_body || raw.displayName || raw.name || raw.description || raw.message || raw.RuleMessage || raw.issue_type || raw.status?.failureReason || raw.action?.type || (typeof raw.action === 'string' ? raw.action : null) || raw.Action || null,
        description: raw.description || raw.alert_body || raw.status?.failureReason || raw.action?.description || null,
        timestamp, severity: raw.severity ?? raw.data?.severity ?? null, sourceSeverity: raw.severity ?? raw.data?.severity ?? null, status,
        category: raw.category ?? raw.alert_type ?? raw.source ?? raw.Source ?? (Array.isArray(raw.categories) ? raw.categories.join(', ') : null),
        mitreTechniques: raw.mitreTechniques || [],
        user: raw.data?.client_ip || raw.data?.zone_name || raw.userPrincipalName || raw.user_email || raw.actor?.email || raw.ipAddress || raw.ip_address || raw.clientIP || raw.ClientIP || raw.appDisplayName || raw.userStates?.[0]?.userPrincipalName || raw.userStates?.[0]?.accountName || raw.evidence?.find(item => item.userAccount)?.userAccount?.userPrincipalName || raw.evidence?.find(item => item.deviceDnsName)?.deviceDnsName || raw.networkIPv4 || raw.networkIPv6 || raw.domainName || raw.url || null,
        source: provider, vendor: provider
    };
    record.presentation = interpretRawEvidence(record);
    return record;
}

function uniqueRawRecords(records) {
    return [...new Map(records.map(record => [record.uid, record])).values()];
}
module.exports = { rawSecurityRecord, uniqueRawRecords, providerTimestamp };
