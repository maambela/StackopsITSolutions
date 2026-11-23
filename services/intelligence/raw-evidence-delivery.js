const { presentRawEvidence } = require('./raw-evidence-interpretation');
// Leave headroom below Cloud Run's 32 MiB non-streaming HTTP/1 response limit.
const SECURITY_DASHBOARD_RESPONSE_MAX_BYTES = 24 * 1024 * 1024;
const SECURITY_EVIDENCE_PREVIEW_MAX_BYTES = 2 * 1024 * 1024;
const SECURITY_EVIDENCE_PREVIEW_MAX_RECORDS = 500;
function canViewSecurityDiagnostics(user) { return String(user?.role || '').toLowerCase() === 'admin'; }
function securityCoverage(sources = [], payload = {}) {
    return ['Microsoft Graph', 'Cloudflare'].map(provider => {
        const rows = sources.filter(row => row.provider === provider);
        if (provider === 'Cloudflare' && payload.rawEvidence?.cloudflare?.status) rows.push({ status: payload.rawEvidence.cloudflare.status });
        if (provider === 'Microsoft Graph') for (const [name, row] of Object.entries(payload.collection?.sources || {})) {
            if (['alerts', 'incidents', 'signIns', 'identityRisk'].includes(name)) rows.push(row);
        }
        const unavailable = row => /unavailable|failed|error|not_configured/.test(String(row.status || ''));
        const limited = row => unavailable(row) || /partial|warning|not_observed/.test(String(row.status || '')) || Boolean(row.limitation);
        const status = rows.length && rows.every(unavailable) ? 'unavailable' : rows.some(limited) ? 'partial' : rows.some(row => /complete|available|receiving/.test(String(row.status || ''))) ? 'available' : 'checking';
        const label = provider === 'Microsoft Graph' ? 'Microsoft' : provider;
        const message = status === 'unavailable' ? `${label} security monitoring is unavailable. Recent activity may be missing.`
            : status === 'partial' ? `${label} security monitoring has partial coverage. Some security data is currently unavailable.`
            : status === 'checking' ? `${label} security monitoring coverage is being checked.` : null;
        return { provider, status, message };
    });
}
function presentSecurityPayload(payload, diagnostics = false) {
    const coverage = securityCoverage(payload.retrieval?.sources, payload);
    return { ...payload, rawRecords: (payload.rawRecords || []).map(presentRawEvidence), canViewDiagnostics: diagnostics,
        retrieval: diagnostics ? { ...payload.retrieval, coverage, storageMode: 'memory_only', storageMessage: 'Security alert database storage is disabled. Original evidence is held temporarily in bounded memory; history is retrieved from provider APIs.' } : { coverage },
        collection: diagnostics ? payload.collection : undefined,
        rawEvidence: diagnostics ? payload.rawEvidence : { cloudflare: { status: payload.rawEvidence?.cloudflare?.status || 'not_reported' } },
        warnings: diagnostics ? payload.warnings : coverage.map(row => row.message).filter(Boolean) };
}

function serializeSecurityDashboardResponse(payload, { diagnostics = false, tenant, range } = {}) {
    const records = payload.rawRecords || [];
    const dashboard = presentSecurityPayload({ ...payload, rawRecords: [] }, diagnostics);
    delete dashboard.rawRecords;
    const summary = JSON.stringify({ ...dashboard, tenant, source: 'api' });
    const query = range?.explicit ? '?' + new URLSearchParams({ since: range.since, until: range.until }) : '';
    const preview = {
        total: records.length,
        shown: records.length,
        truncated: false,
        historyEndpoint: '/api/security-events/history' + query
    };
    const prefix = summary.slice(0, -1) + ',"rawRecords":[';
    const suffix = () => '],"evidencePreview":' + JSON.stringify(preview) + '}';
    // The full count and false flag reserve at least as much space as the final metadata.
    const remaining = SECURITY_DASHBOARD_RESPONSE_MAX_BYTES - Buffer.byteLength(prefix) - Buffer.byteLength(suffix());
    if (remaining < 0) {
        const error = new Error('The Security dashboard summary exceeds the response budget. Use the live dashboard or paginated evidence history.');
        error.code = 'SECURITY_DASHBOARD_RESPONSE_TOO_LARGE';
        error.historyEndpoint = preview.historyEndpoint;
        throw error;
    }

    const encodedRecords = [];
    let availableBytes = Math.min(remaining, SECURITY_EVIDENCE_PREVIEW_MAX_BYTES);
    for (const record of records.slice(0, SECURITY_EVIDENCE_PREVIEW_MAX_RECORDS)) {
        const encoded = JSON.stringify(presentRawEvidence(record));
        const bytes = Buffer.byteLength(encoded) + Number(encodedRecords.length > 0);
        if (bytes > availableBytes) break;
        availableBytes -= bytes;
        encodedRecords.push(encoded);
    }
    preview.shown = encodedRecords.length;
    preview.truncated = preview.shown < preview.total;
    return prefix + encodedRecords.join(',') + suffix();
}

function presentSecurityEvent(event, diagnostics = false, sources = []) {
    if (!diagnostics && event.type === 'error') return { type: 'error', message: 'Security monitoring could not refresh. Some recent activity may be missing.' };
    if (event.type === 'complete') return { ...event, payload: presentSecurityPayload(event.payload, diagnostics) };
    const { source, ...safe } = event;
    return { ...safe, ...(event.records ? { records: event.records.map(presentRawEvidence) } : {}),
        ...(source ? { ...(diagnostics ? { source } : {}), coverage: securityCoverage(sources) } : {}) };
}
module.exports = { canViewSecurityDiagnostics, securityCoverage, presentSecurityPayload, serializeSecurityDashboardResponse, presentSecurityEvent };
