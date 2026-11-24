const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { rawSecurityRecord } = require('../services/intelligence/raw-security-records');
const { canViewSecurityDiagnostics, presentSecurityPayload, presentSecurityEvent, securityCoverage } = require('../services/intelligence/raw-evidence-delivery');
const source = { provider: 'Cloudflare', endpoint: '/accounts/private/audit', status: 'partial', pages: 12, recordsRetrieved: 300, error: 'Internal upstream failure', resumable: true };
const raw = { id: 'fixture', createdDateTime: '2026-11-17T10:12:34Z', status: { errorCode: 0 }, userDisplayName: 'Gary', appDisplayName: 'Loop' };
const record = rawSecurityRecord(raw, { companyId: 7, provider: 'Microsoft Graph', endpoint: '/v1.0/auditLogs/signIns', recordType: 'signin' });

test('one failed Graph authentication skips all dependent Security sources and a later bearer recovers', async () => {
    const server = fs.readFileSync(require.resolve('../server'), 'utf8');
    const start = server.indexOf('function runSecurityGraphSource');
    const end = server.indexOf('async function buildSecurityEventsPayloadFromApi', start);
    const run = vm.runInNewContext(server.slice(start, end) + '\nrunSecurityGraphSource;');
    const failure = { code: 'GRAPH_TOKEN_TIMEOUT', message: 'Microsoft Graph token request timed out after 12000ms' };
    const sources = ['alerts', 'incidents', 'signIns', 'directoryAudit', 'identityRisk'];
    let dispatches = 0;
    const collect = bearer => { dispatches++; assert.equal(bearer, 'recovered'); return { ok: true }; };
    const skipped = await Promise.all(sources.map(source => run(null, failure, collect, { [source]: [] })));
    assert.equal(dispatches, 0);
    assert.equal(new Set(skipped.flatMap(source => source.warnings)).size, 1);
    assert.ok(skipped.every(source => !source.ok && source.unavailable && source.httpStatus === null &&
        source.errorCode === failure.code && source.errorDetail === failure.message));
    await Promise.all(sources.map(source => run('recovered', null, collect, { [source]: [] })));
    assert.equal(dispatches, sources.length);
});

test('directory audit failures limit Microsoft coverage without leaking Graph diagnostics', () => {
    const client = presentSecurityPayload({ identityRisk: { sources: { riskyUsers: {
        status: 'unavailable', httpStatus: 403, errorDetail: 'Forbidden'
    } } }, collection: { sources: {
        alerts: { status: 'complete' },
        directoryAudit: { status: 'unavailable', audit: { httpStatus: 429, errorDetail: 'Too Many Requests' } }
    } } });
    assert.equal(client.retrieval.coverage[0].status, 'partial');
    assert.doesNotMatch(JSON.stringify(client), /429|Too Many Requests|403|Forbidden/);
});

test('Security Graph wrapper does not log capped successful pages as a complete collection', async () => {
    const server = fs.readFileSync(require.resolve('../server'), 'utf8');
    const start = server.indexOf('async function fetchGraphJsonWithTimeout');
    const end = server.indexOf('async function fetchSecurityAlertRows', start);
    const messages = [];
    const fetch = vm.runInNewContext(server.slice(start, end) + '\nfetchGraphJsonWithTimeout;', {
        console: { log: line => messages.push(line), warn: line => messages.push(line) }
    });
    await fetch({ stage: 'fixture', label: 'Alerts', collection: { graph: async () => ({
        ok: true, hasMore: true, recordsFetched: 1, httpStatus: 200, value: [{}], warnings: ['Page limit']
    }) } });
    assert.match(messages.join('\n'), /fixture:partial.*HTTP 200.*Page limit/);
    assert.doesNotMatch(messages.join('\n'), /fixture:complete/);
});

test('client delivery keeps all activity and plain coverage while administrator retains diagnostics', () => {
    const payload = { rawRecords: [record], retrieval: { sources: [source], deadline: 123 }, collection: { error: 'internal failure' }, warnings: ['Internal upstream failure'], rawEvidence: { cloudflare: { status: 'partial', recordsReturned: 300 } } };
    const client = presentSecurityPayload(payload);
    assert.equal(client.rawRecords.length, 1);
    assert.equal(client.rawRecords[0].timestamp, raw.createdDateTime);
    assert.equal(client.rawRecords[0].severity, null);
    assert.match(client.rawRecords[0].presentation.description, /Gary/);
    assert.deepEqual(client.retrieval.coverage.find(row => row.provider === 'Cloudflare'), { provider: 'Cloudflare', status: 'partial', message: 'Cloudflare security monitoring has partial coverage. Some security data is currently unavailable.' });
    assert.doesNotMatch(JSON.stringify(client.retrieval), /private|deadline|pages|Internal/);
    assert.equal(client.collection, undefined);
    assert.deepEqual(record.rawPayload, raw);
    const admin = presentSecurityPayload(payload, true);
    assert.deepEqual(admin.retrieval.sources, [source]);
    assert.equal(admin.retrieval.deadline, 123);
    assert.equal(admin.retrieval.storageMode, 'memory_only');
    assert.equal(canViewSecurityDiagnostics({ role: 'admin' }), true);
    for (const user of [undefined, {}, { role: 'client', canViewDiagnostics: true }, { role: 'administrator' }]) assert.equal(canViewSecurityDiagnostics(user), false);
});

test('live events redact retrieval errors and endpoints only outside administrator diagnostics', () => {
    const event = { type: 'records', records: [record], source };
    const client = presentSecurityEvent(event, false, [source]);
    assert.equal(client.source, undefined);
    assert.equal(client.records.length, 1);
    assert.equal(client.coverage[1].status, 'partial');
    assert.deepEqual(presentSecurityEvent(event, true, [source]).source, source);
    const error = { type: 'error', message: 'SQL table error private', stack: 'private' };
    assert.doesNotMatch(JSON.stringify(presentSecurityEvent(error)), /SQL|private/);
    assert.deepEqual(presentSecurityEvent(error, true), error);
    assert.equal(presentSecurityEvent({ type: 'complete', payload: { rawRecords: [record], retrieval: { sources: [source] } } }).payload.canViewDiagnostics, false);
});

test('missing and failed sources are coverage warnings even when zero records were received', () => {
    assert.equal(securityCoverage([])[0].status, 'checking');
    const rows = securityCoverage([{ provider: 'Microsoft Graph', status: 'unavailable', recordsRetrieved: 0 }, { provider: 'Cloudflare', status: 'complete', recordsRetrieved: 0 }]);
    assert.match(rows[0].message, /unavailable/);
    assert.equal(rows[1].status, 'available');
    assert.equal(rows[1].message, null);
});

test('diagnostics DOM is empty for clients and retains escaped technical details for admins', () => {
    const sourceText = fs.readFileSync(require.resolve('../js/clientportal.js'), 'utf8');
    const start = sourceText.indexOf('function renderSunbirdSecurityDiagnostics(');
    const end = sourceText.indexOf('\nfunction ', start + 1);
    const target = { hidden: false, innerHTML: '' };
    const context = vm.createContext({ document: { getElementById: () => target }, sunbirdSecurityEscape: value => String(value ?? '').replaceAll('<', '&lt;'), sunbirdSecurityFormatTime: value => value || 'Not provided' });
    vm.runInContext(sourceText.slice(start, end), context);
    context.renderSunbirdSecurityDiagnostics({ canViewDiagnostics: true, retrieval: { sources: [{ ...source, error: '<script>bad</script>' }] } });
    assert.equal(target.hidden, false);
    assert.match(target.innerHTML, /Data Source Health &amp; Diagnostics/);
    assert.match(target.innerHTML, /12|300/);
    assert.doesNotMatch(target.innerHTML, /<script>/);
    context.renderSunbirdSecurityDiagnostics({ canViewDiagnostics: false, retrieval: { sources: [source] } });
    assert.equal(target.hidden, true);
    assert.equal(target.innerHTML, '');
});
