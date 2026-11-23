const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');
const { serializeSecurityDashboardResponse } = require('../services/intelligence/raw-evidence-delivery');

const server = fs.readFileSync(require.resolve('../server'), 'utf8');
const routeStart = server.indexOf("app.get('/api/security-events', authenticateToken");
const routeEnd = server.indexOf("app.post('/api/security-events/audit'", routeStart);

test('large non-streaming Security responses retain dashboard data and advertise paginated history', async () => {
    const presentation = { description: 'é'.repeat(48 * 1024) };
    const rawRecords = Array.from({ length: 420 }, (_, i) => ({ uid: '7:' + i, presentation }));
    assert.ok(Buffer.byteLength(JSON.stringify(rawRecords)) > 32 * 1024 * 1024);
    const payload = {
        success: true,
        summary: { totalAlerts: 44, activeIncidents: 3 },
        alerts: [{ id: 'alert-1' }],
        incidents: [{ id: 'incident-1' }],
        mitre: [],
        signIns: { all: 45000, usersUnderAttack: [] },
        findings: [{ id: 'finding-1', evidence: [{ uid: '7:419' }] }],
        rawRecords,
        rawEvidence: { rawRecordCount: rawRecords.length },
        collection: { accounting: { recordsFetched: 45000 } }
    };
    const range = { explicit: true, since: '2026-11-01T00:00:00Z', until: '2026-11-23T00:00:00Z' };
    let route;
    vm.runInNewContext(server.slice(routeStart, routeEnd), {
        app: { get(path, auth, handler) { route = handler; } },
        authenticateToken() {},
        canViewSecurityDiagnostics: () => true,
        getTenantByEmail: () => ({ companyId: 7, clientId: 'sunbird' }),
        rawEvidencePoller: { register() {} },
        securityEvidenceRange: () => range,
        fetchSecurityEventsPayloadFromApi: async () => payload,
        buildSecurityDashboardPayload: ({ payload }) => payload,
        SECURITY_ALERT_STORAGE_ENABLED: false,
        serializeSecurityDashboardResponse,
        clearInterval,
        console: { log() {}, error() {} }
    });
    let body, type;
    await route({ query: {}, user: { email: 'fixture@example.test' } }, {
        set() {},
        type(value) { type = value; return this; },
        send(value) { body = value; }
    });
    assert.equal(type, 'application/json');
    assert.ok(Buffer.byteLength(body) <= 24 * 1024 * 1024);
    const response = JSON.parse(body);
    assert.deepEqual(response.findings, payload.findings);
    assert.deepEqual(response.summary, payload.summary);
    assert.deepEqual(response.collection.accounting, payload.collection.accounting);
    assert.equal(response.signIns.all, 45000);
    assert.equal(response.rawEvidence.rawRecordCount, 420);
    assert.equal(response.rawRecords[0].uid, '7:0');
    assert.ok(response.rawRecords.length > 0 && response.rawRecords.length < rawRecords.length);
    assert.equal(response.evidencePreview.total, 420);
    assert.equal(response.evidencePreview.shown, response.rawRecords.length);
    assert.equal(response.evidencePreview.truncated, true);
    const history = new URL(response.evidencePreview.historyEndpoint, 'https://fixture.example');
    assert.equal(history.pathname, '/api/security-events/history');
    assert.equal(history.searchParams.get('since'), range.since);
    assert.equal(history.searchParams.get('until'), range.until);
    assert.equal(payload.rawRecords.length, 420);
});

test('small Security payloads keep their preview and oversized summaries fail explicitly', () => {
    const body = JSON.parse(serializeSecurityDashboardResponse({
        rawRecords: [{ uid: '7:1', presentation: { title: 'Preview' } }]
    }));
    assert.equal(body.evidencePreview.truncated, false);
    assert.equal(body.evidencePreview.shown, 1);
    assert.throws(() => serializeSecurityDashboardResponse({ summary: { detail: 'x'.repeat(24 * 1024 * 1024) } }), {
        code: 'SECURITY_DASHBOARD_RESPONSE_TOO_LARGE',
        historyEndpoint: '/api/security-events/history'
    });
});
