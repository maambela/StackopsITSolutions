const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');
const { identityAdapter } = require('../services/intelligence/source-adapters');
const { buildSavedIdentityDashboard } = require('../services/intelligence/identity-dashboard-source');
const { mergeVerifiedEmailSources } = require('../services/intelligence/email-dashboard-processor');

const server = fs.readFileSync(require.resolve('../server'), 'utf8');
const client = fs.readFileSync(require.resolve('../js/clientportal'), 'utf8');
function section(source, start, end) {
    const from = source.indexOf(start);
    const to = source.indexOf(end, from + start.length);
    assert.ok(from >= 0 && to > from);
    return source.slice(from, to);
}

test('direct Microsoft dashboards read saved evidence, and browser fallback reads are cache-only', () => {
    const routes = {
        '/api/sunbird/identity-dashboard': /serveSavedSunbirdIdentity/,
        '/api/microsoft-devices': /readSavedDeviceDashboard/,
        '/api/email-security': /serveSavedMicrosoftPayload/,
        '/api/microsoft-applications': /serveSavedMicrosoftPayload/,
        '/api/backup-recovery': /serveSavedMicrosoftPayload/
    };
    for (const [route, savedReader] of Object.entries(routes)) {
        const handler = section(server, `app.get('${route}',`, '\n});');
        assert.match(handler, savedReader);
        assert.doesNotMatch(handler, /fetch\(|getMicrosoftGraphToken|runOwnedDashboardCacheMiss/);
    }
    for (const match of client.matchAll(/fetch\('\/api\/db\/(?:identity-(?:details|metrics)|device-metrics|email-security|applications|backup-recovery)[^']*'/g)) {
        assert.match(match[0], /\?cacheOnly=1'/);
    }
});

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
    const operationEvents = [];
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
    vm.runInNewContext(section(server, 'async function serveSavedSunbirdIdentity', '\napp.get(') +
        '\nhandler = serveSavedSunbirdIdentity;', {
        set handler(value) { handler = value; },
        app: { get(path, auth, fn) { handler = fn; } },
        authenticateToken() {},
        beginSunbirdOperation(req, operationName) {
            assert.equal(operationName, 'identity_dashboard');
            return {
                step(name) { operationEvents.push(`step:${name}`); },
                finish(status, details) { operationEvents.push(`finish:${status}:${details.statusCode}`); }
            };
        },
        verifySunbirdUser: async () => ({ clientId: 'sunbird', companyId: 25 }),
        async assertSharedGraphTenantForCompany(companyId) { assert.equal(companyId, 25); },
        pool, identityAdapter, buildSavedIdentityDashboard,
        readIdentityBackfill: async () => null,
        mergeBackfillUsers: rows => rows,
        async getCachedRoleAssignments(companyId) { assert.equal(companyId, 25); return { roleAssignments: [] }; },
        console: { log() {}, warn() {}, error() {} }
    });
    async function request(query = { cacheOnly: '1' }) {
        const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
        await handler({ query, user: { email: 'fixture@example.test' }, once(event) { assert.equal(event, 'aborted'); } }, res);
        return res;
    }
    const response = await request();
    assert.equal(response.statusCode, 200);
    assert.equal(response.body.summary.totalUsers, 132);
    assert.equal(response.body.summary.workforceUsers, 48);
    assert.equal(response.body.fetchedAt, '2026-11-23T21:00:09.000Z');
    assert.ok(operationEvents.includes('step:shared_tenant_validation_start'));
    assert.ok(operationEvents.includes('step:identity_snapshot_load_complete'));
    assert.ok(operationEvents.includes('step:backfill_load_complete'));
    assert.ok(operationEvents.includes('finish:success:200'));
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

test('saved Identity display restores scoped, verified MFA with its original timestamp', () => {
    const observedAt = '2026-11-24T17:00:00Z';
    const now = Date.parse('2026-11-24T18:00:00Z');
    const saved = { id: 'a', isWorkforce: true, userType: 'Member', rolesStatus: 'complete', roles: [],
        mfaStatus: 'unavailable', lastVerifiedMfa: { enabled: true, count: 2, observedAt, tenantId: 'tenant-a' } };
    const dashboard = buildSavedIdentityDashboard([saved], { activeUsers: null }, 'tenant-a', now);
    assert.equal(dashboard.metrics.mfaCoverage, 100);
    assert.equal(dashboard.metrics.securityScore, 100);
    assert.equal(dashboard.metrics.mfaOutdated, true);
    assert.equal(dashboard.metrics.mfaObservedAt, '2026-11-24T17:00:00.000Z');
    assert.equal(dashboard.metrics.activeUsers, null);
    assert.equal(dashboard.users[0].mfaStatus, 'stale');
    assert.equal(saved.mfaStatus, 'unavailable');
    assert.equal(buildSavedIdentityDashboard([saved], {}, 'tenant-b', now).metrics.mfaCoverage, null);
    assert.equal(buildSavedIdentityDashboard([{ ...saved, lastVerifiedMfa: null }], {}, 'tenant-a', now).metrics.securityScore, null);
    assert.equal(buildSavedIdentityDashboard([{ ...saved, rolesStatus: 'unavailable' }], {}, 'tenant-a', now).metrics.securityScore, null);
});

test('Email targeted users never use mailbox activity and an empty alert set stays unscored', () => {
    const element = {};
    const ui = vm.runInNewContext([
        section(client, 'function getEmailThreatDisplayMetrics', 'function getSecurityDashboardMetrics'),
        section(client, 'function getSunbirdEmailTargetedUserChartItems', 'function buildSunbirdEmailRecommendations'),
        section(client, 'function renderSunbirdEmailMetrics', 'function renderSunbirdEmailInsights'),
        '({ chart: getSunbirdEmailTargetedUserChartItems, metrics: renderSunbirdEmailMetrics });'
    ].join('\n'), { document: { getElementById: () => element }, escapeIdentityText: String });
    const model = { sourceAudit: { alertsComplete: true, incidentsComplete: true }, alerts: [],
        summary: { securityScore: 100, activeThreats: 0 },
        evidence: { affectedUsers: [], mailActivityUsers: [{ sendCount: 1258 }] } };
    assert.equal(ui.chart(model).length, 0);
    ui.metrics(model);
    assert.match(element.innerHTML, /Unknown/);
    assert.doesNotMatch(element.innerHTML, /100%/);
    model.evidence.affectedUsers.push({ user: 'fixture@example.test', threatCount: 2 });
    assert.equal(ui.chart(model)[0].value, 2);
});

test('Email snapshots publish each verified source independently and reject late results', () => {
    const date = minute => new Date(`2026-11-24T17:${minute}:00Z`);
    const alerts = { success: true, sourceAudit: { alertsComplete: true },
        alerts: [], summary: { activeThreats: 0, highSeverityAlerts: 0 } };
    const activity = { success: true, sourceAudit: { mailActivityOk: true },
        mailActivity: { users: [] }, summary: { activeMailboxes: 42 } };
    const incidents = { success: true, sourceAudit: { incidentsComplete: true },
        incidents: [], summary: { activeIncidents: 0 } };
    const first = mergeVerifiedEmailSources(null, activity, date('10'));
    const second = mergeVerifiedEmailSources(first, alerts, date('20'));
    assert.equal(second.summary.activeThreats, 0);
    assert.equal(second.summary.activeMailboxes, 42);
    assert.equal(second.sourceAudit.incidentsComplete, false);
    const third = mergeVerifiedEmailSources(second, incidents, date('15'));
    assert.equal(third.summary.activeIncidents, 0);
    assert.equal(third.sourceAudit.sourceTimestamps.mailActivity, date('10').toISOString());
    assert.equal(third.sourceAudit.sourceTimestamps.incidents, date('15').toISOString());
    assert.equal(third.fetchedAt, date('20').toISOString());
    assert.equal(mergeVerifiedEmailSources(third, activity, date('09')), null);
    assert.equal(mergeVerifiedEmailSources(third, { success: true, sourceAudit: {} }, date('25')), null);
    const updated = mergeVerifiedEmailSources(third, activity, date('30'));
    assert.equal(updated.sourceAudit.sourceTimestamps.alerts, date('20').toISOString());
    assert.equal(updated.summary.activeIncidents, 0);
});

test('a late download of an older Exchange report cannot replace newer mailbox activity', () => {
    const report = (reportRefreshDate, activeMailboxes) => ({
        success: true, sourceAudit: { mailActivityOk: true },
        mailActivity: { users: [{ reportRefreshDate }] }, summary: { activeMailboxes }
    });
    const saved = mergeVerifiedEmailSources(null, report('2026-11-24', 42), new Date('2026-11-24T20:00:00Z'));
    const incoming = { ...report('2026-11-23', 40), alerts: [],
        sourceAudit: { mailActivityOk: true, alertsComplete: true } };
    const merged = mergeVerifiedEmailSources(saved, incoming, new Date('2026-11-24T21:00:00Z'));
    assert.equal(merged.summary.activeMailboxes, 42);
    assert.equal(merged.mailActivity.users[0].reportRefreshDate, '2026-11-24');
    assert.equal(merged.sourceAudit.sourceTimestamps.mailActivity, '2026-11-24T20:00:00.000Z');
    assert.equal(merged.sourceAudit.alertsComplete, true);
});

test('active mailbox evidence matches the active population while mail events show all report rows', () => {
    const evidence = vm.runInNewContext(section(client, 'function getSunbirdEmailEvidenceRows', '\nfunction ') +
        '\ngetSunbirdEmailEvidenceRows;');
    const model = { sourceAudit: { mailActivityOk: true }, evidence: { mailActivityUsers: [
        { userPrincipalName: 'active@example.test', lastActivityDate: '2026-11-23' },
        { userPrincipalName: 'inactive@example.test', lastActivityDate: '' }
    ] } };
    assert.equal(evidence('activeMailboxes', model).length, 1);
    assert.equal(evidence('mailActivityUsers', model).length, 2);
    assert.equal(evidence('mailActivityUsers', { ...model, sourceAudit: {} }).length, 0);
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
    assert.deepEqual(values(), [': Unknown', ': Unknown', ': Unknown', ': 0']);
    assert.match(project.cardFooter, /Threat data incomplete.*42 active mailboxes.*14060 mail events/);
    payload = { ...payload, sourceAudit: { alertsOk: true, incidentsOk: true, warnings: [] } };
    await card();
    assert.deepEqual(values(), [': Unknown', ': Unknown', ': Unknown', ': 0']);
    payload = { ...payload, sourceAudit: { alertsComplete: true, incidentsComplete: true } };
    await card();
    assert.deepEqual(values(), [': 0', ': 0', ': 0', ': 0']);
    payload = { ...payload, sourceAudit: undefined };
    await card();
    assert.deepEqual(values(), Array(4).fill(': 0'));
    payload = null;
    await card();
    assert.deepEqual(values(), Array(4).fill(': 0'));
    assert.deepEqual(calls, Array(5).fill('/api/db/email-security?cacheOnly=1'));
});
