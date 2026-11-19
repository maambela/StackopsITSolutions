const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { rawSecurityRecord, uniqueRawRecords } = require('../services/intelligence/raw-security-records');
const { fetchGraphCollectionPagesWithRetry } = require('../services/intelligence/microsoft-graph-collection');
const { fetchCloudflarePages } = require('../services/intelligence/cloudflare-collection');
const { deriveSecurityEvidence } = require('../services/intelligence/security-evidence-store');

test('raw record preserves missing severity, provider text, payload and tenant identity', () => {
    const payload = { id: 'same', createdDateTime: '2026-11-17T10:12:34Z', status: { errorCode: 50076, failureReason: 'User must register MFA.' } };
    const context = { provider: 'Microsoft Graph', endpoint: '/auditLogs/signIns', recordType: 'signin', companyId: 1 };
    const row = rawSecurityRecord(payload, context);
    assert.equal(row.severity, null);
    assert.equal(row.title, payload.status.failureReason);
    assert.equal(row.timestamp, payload.createdDateTime);
    assert.deepEqual(row.mitreTechniques, []);
    assert.deepEqual(row.rawPayload, payload);
    assert.equal(uniqueRawRecords([row, row, rawSecurityRecord(payload, { ...context, companyId: 2 })]).length, 2);
    const stored = deriveSecurityEvidence({ rawRecords: [row, row] }).evidenceRows.filter(item => item.kind === 'raw_provider');
    assert.equal(stored.length, 1);
    assert.equal(stored[0].severity, null);
    assert.deepEqual(stored[0].processed.rawPayload, payload);
});

test('Graph traverses more than 25 pages without a default page cap', async () => {
    let calls = 0;
    const result = await fetchGraphCollectionPagesWithRetry({ url: 'https://graph.microsoft.com/first', token: 'fixture', fetchImpl: async () => {
        calls++;
        return { ok: true, status: 200, json: async () => ({ value: [{ id: String(calls) }], ...(calls < 30 ? { '@odata.nextLink': `https://graph.microsoft.com/page/${calls}` } : {}) }) };
    } });
    assert.equal(result.recordsFetched, 30);
    assert.equal(result.hasMore, false);
});

test('Graph keeps prior pages and reports later permission failure', async () => {
    let calls = 0;
    const result = await fetchGraphCollectionPagesWithRetry({ url: 'https://graph.microsoft.com/first', token: 'fixture', fetchImpl: async () => ++calls === 1
        ? { ok: true, status: 200, json: async () => ({ value: [{ id: 'one' }], '@odata.nextLink': 'https://graph.microsoft.com/next' }) }
        : { ok: false, status: 403, text: async () => 'Forbidden' } });
    assert.equal(result.value.length, 1);
    assert.equal(result.partial, true);
    assert.match(result.warnings.join(' '), /403/);
});

test('Cloudflare supports numbered pages and nested Security Center issues', async () => {
    let calls = 0;
    const result = await fetchCloudflarePages({ get: async () => ({ data: { result: { issues: [{ id: ++calls }], page: calls, per_page: 1 }, result_info: { page: calls, total_pages: 3 } } }) }, '/insights');
    assert.equal(result.result.length, 3);
    assert.equal(result.collection.complete, true);
});

test('Cloudflare honors Retry-After, follows cursor, and keeps partial pages', async () => {
    const waits = []; let calls = 0;
    const result = await fetchCloudflarePages({ get: async (url, { params }) => {
        calls++;
        if (calls === 1) throw { response: { status: 429, headers: { 'retry-after': '2' } } };
        if (calls === 2) return { data: { result: [{ id: 'one' }], result_info: { cursor: 'next' } } };
        assert.equal(params.cursor, 'next');
        throw new Error('permission revoked');
    } }, '/access', {}, { wait: async ms => waits.push(ms) });
    assert.deepEqual(waits, [2000]);
    assert.equal(result.result.length, 1);
    assert.equal(result.collection.complete, false);
    assert.equal(result.collection.rateLimits, 1);
});

test('raw presentation shows seconds, missing fields and no keyword-based MITRE', () => {
    const source = fs.readFileSync(require.resolve('../js/clientportal.js'), 'utf8');
    const context = vm.createContext({ Intl, Date });
    for (const name of ['sunbirdSecurityFormatTime', 'getSunbirdSecurityMitre', 'getSunbirdSecurityEvents']) {
        const start = source.indexOf(`function ${name}(`), end = source.indexOf('\nfunction ', start + 1);
        vm.runInContext(source.slice(start, end), context);
    }
    assert.match(context.sunbirdSecurityFormatTime('2026-11-17T10:12:34Z'), /12:12:34/);
    assert.equal(context.sunbirdSecurityFormatTime('2026-11-17'), 'Not provided');
    assert.equal(context.getSunbirdSecurityMitre({ title: 'Password reset MFA' }).technique, 'Not provided');
    assert.equal(context.getSunbirdSecurityEvents({ rawRecords: [{ recordType: 'signin' }], alerts: [{ title: 'derived' }] }).length, 1);
});

test('raw table restores the full evidence columns and keeps provider details accessible', () => {
    const source = fs.readFileSync(require.resolve('../js/clientportal.js'), 'utf8');
    const body = {};
    const row = rawSecurityRecord({ id: 'one', status: { failureReason: 'User must register MFA.' } }, {
        provider: 'Microsoft Graph', companyId: 1, endpoint: '/auditLogs/signIns', recordType: 'signin'
    });
    const context = vm.createContext({
        Intl, Date, document: { getElementById: () => body },
        renderSunbirdSecurityRawEvidenceHeader: () => {},
        renderSunbirdSecurityDiagnostics: () => {},
        getFilteredSunbirdSecurityEvents: () => [row],
        escapeIdentityText: value => String(value ?? '').replace(/[<>&"']/g, character => `&#${character.charCodeAt(0)};`)
    });
    for (const name of ['renderSunbirdSecurityTable', 'getSunbirdSecurityReportingSystem', 'getSunbirdSecurityMitre', 'getSunbirdSecurityApiSource',
        'getSunbirdSecurityApiCategory', 'getSunbirdSecurityDisplayTitle', 'getSunbirdSecurityDisplayAsset',
        'sunbirdSecurityFormatTime', 'isSunbirdSecurityIdentifier']) {
        const start = source.indexOf(`function ${name}(`), end = source.indexOf('\nfunction ', start + 1);
        vm.runInContext(source.slice(start, end), context);
    }
    context.renderSunbirdSecurityTable({});
    assert.equal((body.innerHTML.match(/<td /g) || []).length, 11);
    assert.match(body.innerHTML, /data-label="Severity">.*Not provided/);
    assert.match(body.innerHTML, /data-label="Type">.*signin/);
    assert.match(body.innerHTML, /data-label="Incident \/ Alert">.*User must register MFA\./);
    assert.match(body.innerHTML, /User must register MFA\./);
    assert.match(body.innerHTML, /data-label="Source">Microsoft Entra ID/);
    assert.match(body.innerHTML, /data-label="API Source">Microsoft Graph/);
    assert.match(body.innerHTML, /data-label="Category">/);
    assert.match(body.innerHTML, /data-label="MITRE">Not mapped/);
    assert.match(body.innerHTML, /data-label="Evidence">.*>Open<\/button>/);
});
