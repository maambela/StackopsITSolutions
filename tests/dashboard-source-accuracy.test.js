const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');
const { identityAdapter } = require('../services/intelligence/source-adapters');

const server = fs.readFileSync(require.resolve('../server'), 'utf8');
const client = fs.readFileSync(require.resolve('../js/clientportal'), 'utf8');
function section(source, start, end) {
    const from = source.indexOf(start);
    const to = source.indexOf(end, from + start.length);
    assert.ok(from >= 0 && to > from);
    return source.slice(from, to);
}

test('dashboard snapshots reject an older collection and a previous signed-in session', () => {
    const storage = new Map([['userEmail', 'first@example.test'], ['loginTime', '100']]);
    const api = vm.runInNewContext(section(client, 'function microsoftDashboardSession()', 'function hasRealProjectMetrics(') +
        '\n({ read: readMicrosoftDashboardCache, write: writeMicrosoftDashboardCache, older: isOlderMicrosoftDashboardData });', {
        isSessionValid: () => true,
        sessionStorage: { getItem: key => storage.get(key), setItem: (key, value) => storage.set(key, value) }
    });
    const newest = { fetchedAt: '2026-11-23T21:00:00Z', count: 132 };
    const older = { fetchedAt: '2026-11-23T20:00:00Z', count: 48 };
    api.write('identity', newest);
    api.write('identity', older);
    assert.equal(api.older(older, newest), true);
    assert.equal(api.older({}, newest), true);
    assert.equal(api.read('identity').count, 132);
    storage.set('userEmail', 'second@example.test');
    storage.set('loginTime', '101');
    assert.equal(api.read('identity'), null);
});

test('shared Graph tenant guard rejects a mismatched company before retrieval', async () => {
    const guard = vm.runInNewContext(section(server, 'async function assertSharedGraphTenantForCompany', 'async function getSecurityAlertsGraphTokenForCompany') +
        '\nassertSharedGraphTenantForCompany;', {
        pool: { async query(sql, [companyId]) { return [[{ TenantID: companyId === 25 ? 'sunbird' : 'other' }]]; } },
        getMicrosoftGraphCredentials: async () => ({ tenantId: 'SUNBIRD' })
    });
    await guard(25);
    await assert.rejects(guard(26), { statusCode: 403 });
});

test('application inventory counts direct users and rejects an incomplete assignment collection', async () => {
    let fail = false;
    const load = vm.runInNewContext(section(server, 'async function fetchApplicationsPayloadFromApi', 'async function fetchEmailMetricsFromApi') +
        '\nfetchApplicationsPayloadFromApi;', {
        fetchMicrosoftServicePrincipals: async () => [{ id: 'app', publisherName: 'Microsoft' }],
        fetchMicrosoftUsers: async () => [],
        fetchMicrosoftGroups: async () => [],
        async fetchAppRoleAssignments() {
            if (fail) throw new Error('Graph 429');
            return [{ principalType: 'User' }, { principalType: 'Group', principalDisplayName: 'Staff' }, { principalType: 'ServicePrincipal' }];
        },
        mapWithConcurrency: (rows, limit, callback) => Promise.all(rows.map(callback)),
        console: { warn() {} }
    });
    const inventory = await load('fixture');
    assert.equal(inventory.applications[0].userCount, 1);
    assert.equal(inventory.applications[0].assignedGroups[0], 'Staff');
    fail = true;
    await assert.rejects(load('fixture'), /access evidence is incomplete/);
});

test('Identity cache-only refresh serves the authenticated company snapshot, never the legacy list', async () => {
    const users = Array.from({ length: 132 }, (_, index) => ({ id: String(index), userType: index < 48 ? 'Member' : 'Guest' }));
    const queries = [];
    let complete = true;
    let snapshotTenantId = 'tenant-25';
    let handler;
    const pool = {
        async query(sql, parameters) {
            queries.push(sql);
            if (sql.includes('CompanyMicrosoftMapping')) {
                assert.deepEqual(Array.from(parameters), [25]);
                return [[{ MicrosoftTenantID: 6, TenantID: 'tenant-25' }]];
            }
            if (sql.includes('StackCTRLIdentityEvidenceSnapshots')) {
                assert.deepEqual(Array.from(parameters), [25, 'sunbird']);
                return [complete ? [{
                    ID: 11558, CompanyID: 25, IsComplete: 1, CollectionStatus: 'complete',
                    EvidenceRecordCount: 132, CollectedAt: '2026-11-23T21:00:09Z',
                    SourceAuditJson: JSON.stringify({ tenantId: snapshotTenantId }),
                    DashboardMetricsJson: JSON.stringify({ totalUsers: 132, workforceUsers: 48, activeUsers: 5 })
                }] : []];
            }
            if (sql.includes('StackCTRLIdentityUserEvidence')) {
                assert.deepEqual(Array.from(parameters), [11558, 25, 'sunbird']);
                return [users.map(user => ({ ProcessedEvidenceJson: JSON.stringify(user) }))];
            }
            assert.fail('unexpected cache lookup');
        }
    };
    vm.runInNewContext(section(server, "app.get('/api/sunbird/identity-dashboard-cached'", '\napp.get('), {
        app: { get(path, auth, fn) { handler = fn; } },
        authenticateToken() {},
        verifySunbirdUser: async () => ({ clientId: 'sunbird', companyId: 25 }),
        async assertSharedGraphTenantForCompany(companyId) { assert.equal(companyId, 25); },
        pool, identityAdapter,
        async getCachedRoleAssignments(companyId) { assert.equal(companyId, 25); return { roleAssignments: [] }; },
        console: { log() {}, warn() {}, error() {} }
    });
    async function request(query = { cacheOnly: '1' }) {
        const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
        await handler({ query, user: { email: 'fixture@example.test' } }, res);
        return res;
    }
    const response = await request();
    assert.equal(response.statusCode, 200);
    assert.equal(response.body.summary.totalUsers, 132);
    assert.equal(response.body.summary.workforceUsers, 48);
    assert.equal(response.body.fetchedAt, '2026-11-23T21:00:09.000Z');
    assert.equal((await request({})).body.summary.totalUsers, 132);
    snapshotTenantId = 'different-tenant';
    const wrongTenant = await request();
    assert.equal(wrongTenant.statusCode, 503);
    assert.equal(wrongTenant.body.success, false);
    snapshotTenantId = 'tenant-25';
    complete = false;
    const missing = await request();
    assert.equal(missing.statusCode, 503);
    assert.equal(missing.body.success, false);
    assert.ok(queries.every(sql => !/\bidentity_users\b/i.test(sql)));
});

test('Email card displays zero only for covered sources and keeps mailbox activity separate', async () => {
    const project = { id: 5 };
    const calls = [];
    let payload;
    const card = vm.runInNewContext([
        section(client, 'async function fetchEmailCardData', '// Calculate simple risk logic'),
        section(client, 'function getEmailThreatDisplayMetrics', 'function buildSunbirdEmailModel'),
        section(client, 'function retainVerifiedEmailDashboard', 'function hasRealProjectMetrics'),
        'fetchEmailCardData;'
    ].join('\n'), {
        mockProjects: [project],
        latestEmailCardData: null,
        localStorage: { getItem: () => 'fixture' },
        hasRealProjectMetrics: () => true,
        isOlderMicrosoftDashboardData: () => false,
        microsoftDashboardUpdateText: () => 'Last updated',
        updateMicrosoftDashboardCardTimestamp: () => {},
        fetch: async endpoint => {
            calls.push(endpoint);
            return { ok: Boolean(payload), json: async () => payload || { success: false } };
        },
        getSunbirdMetricNumber: (values, keys, fallback) => fallback,
        buildSunbirdEmailThreatBreakdown: () => ({}),
        calculateSunbirdEmailResolutionRate: () => 0,
        calculateSunbirdEmailSecurityScore: () => 0,
        saveSunbirdEmailSnapshot() {},
        saveProjectCardToCache() {},
        displayCurrentProject() {},
        document: { getElementById: () => null },
        console: { error() {} }
    });
    const zeros = { activeThreats: 0, highSeverityAlerts: 0, affectedUsersCount: 0, activeIncidents: 0 };
    payload = {
        success: true,
        summary: { ...zeros, mailActivity: { activeMailboxes: 42, totalMailActivity: 14060 } },
        sourceAudit: { alertsOk: true, alertsComplete: false, incidentsComplete: true, warnings: ['More alerts are available'] }
    };
    const values = () => Array.from(project.cardMetrics, metric => metric.value);
    await card();
    assert.deepEqual(values(), [': Temporarily unavailable', ': Temporarily unavailable', ': Temporarily unavailable', ': 0']);
    assert.match(project.cardFooter, /Threat data incomplete.*42 active mailboxes.*14060 mail events/);
    payload = { ...payload, sourceAudit: { alertsComplete: true, incidentsComplete: true } };
    await card();
    assert.deepEqual(values(), [': 0', ': 0', ': 0', ': 0']);
    payload = { ...payload, sourceAudit: undefined };
    await card();
    assert.deepEqual(values(), Array(4).fill(': 0'));
    payload = null;
    await card();
    assert.deepEqual(values(), Array(4).fill(': 0'));
    assert.deepEqual(calls, Array(4).fill('/api/db/email-security'));
});
