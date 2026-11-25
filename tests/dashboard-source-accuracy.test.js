const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');
const { identityAdapter } = require('../services/intelligence/source-adapters');
const { buildSavedIdentityDashboard } = require('../services/intelligence/identity-dashboard-source');
const { mergeVerifiedEmailSources, readEmailAlertTargets, countEmailAlertTargets, selectScopedEmailDashboard } = require('../services/intelligence/email-dashboard-processor');

const server = fs.readFileSync(require.resolve('../server'), 'utf8');
const client = fs.readFileSync(require.resolve('../js/clientportal'), 'utf8');
function section(source, start, end) {
    const from = source.indexOf(start);
    const to = source.indexOf(end, from + start.length);
    assert.ok(from >= 0 && to > from);
    return source.slice(from, to);
}

test('Email evidence keeps Defender alerts, mailbox activity and targeted users separate', () => {
    const elements = new Map();
    const state = { threat: 'all', search: '', severity: 'all', status: 'all', sort: 'newest' };
    let model;
    const { renderTable, renderVip, openUserEvidence } = vm.runInNewContext([
        section(client, 'function renderSunbirdEmailTable', 'function applySunbirdEmailTableFilter'),
        section(client, 'function renderSunbirdEmailVipPanel', 'function renderSunbirdEmailFeedPanel'),
        section(client, 'function openSunbirdEmailUserEvidence', '\nfunction '),
        '({ renderTable: renderSunbirdEmailTable, renderVip: renderSunbirdEmailVipPanel, openUserEvidence: openSunbirdEmailUserEvidence });'
    ].join('\n'), {
        document: { getElementById(id) {
            if (!elements.has(id)) elements.set(id, { classList: { add() {} }, setAttribute() {} });
            return elements.get(id);
        } },
        sunbirdEmailTableState: state,
        escapeIdentityText: String,
        formatSunbirdDeviceDate: String,
        getSunbirdEmailThreatType: () => 'phishing',
        getSunbirdEmailSender: () => 'Sender',
        getSunbirdEmailTargetUser: () => 'Target',
        getSunbirdEmailAction: () => 'Blocked',
        buildSunbirdEmailModel: () => model,
        getSunbirdEmailAlertsForUser: () => []
    });
    model = {
        alerts: [{ title: 'Defender phishing alert', severity: 'high', status: 'resolved' }],
        sourceAudit: { alertsComplete: true, mailActivityOk: true },
        mailActivity: { reportRefreshDate: '2026-11-23' },
        evidence: {
            affectedUsers: [],
            mailActivityUsers: [{ displayName: 'Mailbox A', lastActivityDate: '2026-11-22', sendCount: 0, receiveCount: 9, readCount: 3 }]
        }
    };
    const body = () => elements.get('sunbird-email-body').innerHTML;
    renderTable(model);
    assert.match(body(), /Defender phishing alert/);
    assert.doesNotMatch(body(), /Mailbox A/);
    assert.equal(elements.get('sunbird-email-activity-heading').hidden, true);
    assert.doesNotMatch(renderVip(model), /Mailbox A|mail activity event/);
    assert.match(renderVip(model), /No targeted mailbox evidence in collected alerts/);
    openUserEvidence('Mailbox A');
    const modal = elements.get('sunbird-email-evidence-modal').innerHTML;
    assert.match(modal, /No collected alerts match this mailbox/);
    assert.doesNotMatch(modal, /Mail activity|2026-11-22/);

    state.threat = 'mailflow';
    renderTable(model);
    assert.match(body(), /Mailbox A[\s\S]*2026-11-22[\s\S]*2026-11-23[\s\S]*data-label="Sent">0</);
    assert.doesNotMatch(body(), /Severity|Status|Defender phishing alert/);
    assert.equal(elements.get('sunbird-email-alert-heading').hidden, true);
    assert.equal(elements.get('sunbird-email-status-filter').disabled, true);
    model.sourceAudit.mailActivityOk = false;
    renderTable(model);
    assert.match(body(), /Mailbox activity is unavailable/);

    state.threat = 'all';
    model.alerts = [];
    model.sourceAudit.alertsComplete = false;
    renderTable(model);
    assert.match(body(), /Email alert evidence is unavailable or incomplete/);
    assert.match(renderVip(model), /Targeted mailbox evidence is unavailable/);
    assert.equal(elements.get('sunbird-email-status-filter').disabled, false);
});

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
        pool, identityAdapter,
        readIdentityDashboardMetrics: (_company, tenantId, users, metrics) =>
            buildSavedIdentityDashboard(users, metrics, tenantId),
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

test('incomplete Identity snapshots keep earlier verified aggregates and their original timestamps', async () => {
    const previousAt = '2026-11-23T12:00:00.000Z';
    const fetchedAt = '2026-11-24T12:00:00.000Z';
    const user = { id: 'a', userType: 'Member', isWorkforce: true, roles: [], rolesStatus: 'complete',
        mfaEnabled: true, mfaStatus: 'complete', mfaObservedAt: previousAt,
        lastSignIn: { observationStatus: 'no_recorded_sign_in' } };
    const read = vm.runInNewContext(section(server, 'async function readIdentityDashboardMetrics', 'async function collectIdentityDashboardPayload') +
        '\nreadIdentityDashboardMetrics;', {
        buildSavedIdentityDashboard,
        loadStoredIdentityUsers: async (company, tenant, options) => {
            assert.equal(company, 25);
            assert.equal(tenant, 'tenant-a');
            assert.equal(options.requireTenant, true);
            options.visitSnapshot([user], { activeUsers: 0, signInCollectionStatus: 'complete' }, previousAt);
        },
        console
    });
    const saved = await read(25, 'tenant-a', [{ ...user, mfaEnabled: null, rolesStatus: 'unavailable' }], {}, fetchedAt);
    assert.equal(saved.metrics.mfaCoverage, 100);
    assert.equal(saved.metrics.securityScore, 100);
    assert.equal(saved.metrics.activeUsers, 0);
    assert.equal(saved.metrics.verifiedMetricTimestamps.securityScore, previousAt);
    assert.equal(saved.metrics.verifiedMetricTimestamps.privilegedUsers, previousAt);
    assert.equal(saved.users[0].mfaEnabled, null);
});

test('Email targets combine native Graph user and mailbox evidence with legacy formats', () => {
    const first = { evidence: [
        { '@odata.type': '#microsoft.graph.security.userEvidence', userAccount: {
            azureAdUserId: 'object-id-A', userPrincipalName: 'target@example.test'
        } },
        { '@odata.type': '#microsoft.graph.security.mailboxEvidence', primaryAddress: 'Target@example.test' },
        { '@odata.type': '#microsoft.graph.security.ipEvidence' }
    ] };
    const second = { userStates: [{ aadUserId: 'object-id-a', accountName: 'new-name@example.test' }] };
    const third = { evidence: [{ '@odata.type': '#microsoft.graph.security.mailboxEvidence', primaryAddress: 'second@example.test' }] };
    const targets = countEmailAlertTargets([first, second, third].map(alert => ({ userStates: readEmailAlertTargets(alert) })));
    assert.deepEqual(targets, [
        { user: 'new-name@example.test', threatCount: 2 },
        { user: 'second@example.test', threatCount: 1 }
    ]);
});

test('reused Exchange data keeps its old provenance as Defender source evidence advances', () => {
    const activityAt = '2026-11-24T17:00:00.000Z';
    const incomingAt = '2026-11-24T17:05:00.000Z';
    const previous = { success: true, fetchedAt: activityAt, mailActivity: { users: [{ reportRefreshDate: '2026-11-23' }] },
        sourceAudit: { sourceTenantId: 'tenant-a', mailActivityOk: true, sourceTimestamps: { mailActivity: activityAt },
            sourceAttemptIds: { mailActivity: 'previous' } } };
    const incoming = { success: true, sourceAudit: { sourceTenantId: 'tenant-a', attemptId: 'new', mailActivityOk: true,
        alertsComplete: true, sourceOutcomes: { alerts: { status: 'complete' }, mailActivity: { status: 'reused' } } } };
    const merged = mergeVerifiedEmailSources(previous, incoming, new Date(incomingAt));
    assert.equal(merged.sourceAudit.sourceTimestamps.mailActivity, activityAt);
    assert.equal(merged.sourceAudit.sourceAttemptIds.mailActivity, 'previous');
    assert.equal(merged.sourceAudit.sourceAttemptIds.alerts, 'new');
    const isolated = mergeVerifiedEmailSources(previous, { ...incoming, sourceAudit: { ...incoming.sourceAudit, sourceTenantId: 'tenant-b' } }, new Date(incomingAt));
    assert.equal(isolated.sourceAudit.mailActivityOk, false);
    assert.equal(isolated.mailActivity, undefined);
});

test('Email Observed Alert Score uses only verified saved alert evidence and the historical weights', () => {
    const element = { classList: { add() {} }, setAttribute() {} };
    let model;
    const ui = vm.runInNewContext([
        section(client, 'function getEmailThreatDisplayMetrics', 'function getSecurityDashboardMetrics'),
        section(client, 'function getSunbirdEmailTargetedUserChartItems', 'function buildSunbirdEmailRecommendations'),
        section(client, 'function getSunbirdObservedAlertScore', 'function renderSunbirdEmailInsights'),
        section(client, 'function emailAlertChartStatus', 'function renderSunbirdEmailCharts'),
        section(client, 'function renderSunbirdEmailHealthGraph', 'function renderSunbirdEmailPanels'),
        section(client, 'function openSunbirdEmailEvidence', '\nfunction '),
        '({ chart: getSunbirdEmailTargetedUserChartItems, metrics: renderSunbirdEmailMetrics, health: renderSunbirdEmailHealthGraph, evidence: openSunbirdEmailEvidence, score: getSunbirdObservedAlertScore });'
    ].join('\n'), {
        document: { getElementById: () => element },
        escapeIdentityText: String,
        buildSunbirdEmailModel: () => model,
        getSunbirdEmailEvidenceRows: key => key === 'allAlerts' ? [{ title: 'Collected alert', subtitle: '', meta: 'High' }] : [],
        microsoftDashboardUpdateText: ({ fetchedAt }) => `Last updated ${fetchedAt}`,
        sunbirdEmailDashboardData: {}
    });
    model = { sourceAudit: { alertsComplete: true, incidentsComplete: true }, alerts: [],
        summary: { securityScore: 100, activeThreats: 0 },
        evidence: { affectedUsers: [], mailActivityUsers: [{ sendCount: 1258 }] } };
    assert.equal(ui.chart(model).length, 0);
    ui.metrics(model);
    assert.match(element.innerHTML, /Unknown/);
    assert.doesNotMatch(element.innerHTML, /100%/);
    assert.match(ui.health(model), /No collected alerts to resolve/);
    ui.evidence('observedAlertScore');
    assert.match(element.innerHTML, /No collected email alerts to score/);

    model.alerts.push({ severity: 'high' }, { severity: 'medium' });
    Object.assign(model.summary, { securityScore: 100, activeThreats: 1, threatResolutionRate: 50 });
    model.sourceAudit.sourceTimestamps = { alerts: '2026-11-25T01:00:00Z' };
    model.sourceAudit.sourceOutcomes = { alerts: { status: 'failed' } };
    model.fetchedAt = '2026-11-25T02:00:00Z';
    ui.metrics(model);
    assert.match(element.innerHTML, /83%[\s\S]*Observed Alert Score/);
    assert.match(element.innerHTML, />1<\/div>\s*<div[^>]+>Active Threats/);
    assert.doesNotMatch(element.innerHTML, /100%/);
    assert.match(ui.health(model), /Resolved[\s\S]*50%/);
    assert.doesNotMatch(ui.health(model), /83%|Exposure/);
    ui.evidence('observedAlertScore');
    assert.match(element.innerHTML, /18 per critical alert, 12 per high, 5 per medium and 2 per low/);
    assert.match(element.innerHTML, /83% from 2 collected alerts/);
    assert.match(element.innerHTML, /Refresh incomplete.*Last updated 2026-11-25T01:00:00Z/);
    assert.match(element.innerHTML, /Collected alert/);
    assert.doesNotMatch(element.innerHTML, /2026-11-25T02:00:00Z/);
    assert.doesNotMatch(element.innerHTML, /View in Table/);

    const score = severities => ui.score({ ...model, alerts: severities.map(severity => ({ severity })) });
    assert.equal(score(['critical', 'high', 'medium', 'low', 'unknown']).value, 61);
    assert.equal(score([...Array(30).fill('low'), 'critical']).value, 40);
    assert.equal(score(Array(7).fill('critical')).value, 0);
    model.sourceAudit.alertsComplete = false;
    assert.equal(ui.score(model), null);
    ui.evidence('observedAlertScore');
    assert.match(element.innerHTML, /Verified email alert coverage is unavailable/);
    assert.doesNotMatch(element.innerHTML, /83%|Collected alert/);

    model.sourceAudit.alertsComplete = true;
    model.evidence.affectedUsers.push({ user: 'fixture@example.test', threatCount: 2 });
    assert.equal(ui.chart(model)[0].value, 2);
});

test('Email charts distinguish verified zero, missing coverage, and an incomplete refresh', () => {
    const chart = vm.runInNewContext(section(client, 'function emailAlertChartStatus', 'function renderSunbirdEmailRiskTrendChart') +
        '\nemailAlertChartStatus;', { microsoftDashboardUpdateText: () => 'Outdated · Updated 23 Nov' });
    assert.equal(chart({}).verified, false);
    assert.equal(chart({ sourceAudit: { sourceOutcomes: { alerts: { status: 'failed' } } } }).label, 'Collection failed');
    assert.equal(chart({ sourceAudit: { alertsComplete: true, sourceTimestamps: { alerts: '2026-11-23T10:00Z' } } }).verified, true);
    assert.match(chart({ fetchedAt: '2026-11-23T10:00Z', sourceAudit: {
        alertsComplete: true, sourceOutcomes: { alerts: { status: 'partial' } }
    } }).label, /^Refresh incomplete · Outdated/);
});

test('Email merge rejects legacy and remapped evidence and publishes failure transitions without changing verified values', () => {
    const date = minute => new Date(`2026-11-24T17:${minute}:00Z`);
    const incoming = (tenant, status, count) => ({
        success: true, summary: { activeThreats: count },
        sourceAudit: { sourceTenantId: tenant, alertsComplete: status === 'complete', sourceOutcomes: { alerts: { status } } }
    });
    const legacy = { success: true, fetchedAt: date('00').toISOString(),
        sourceAudit: { alertsComplete: true }, summary: { activeThreats: 17 } };
    const unknown = mergeVerifiedEmailSources(legacy, incoming('tenant-a', 'failed', 0), date('01'));
    assert.equal(unknown.sourceAudit.alertsComplete, false);
    assert.equal(unknown.summary.activeThreats, undefined);
    assert.equal(unknown.fetchedAt, null);
    const partiallyTagged = selectScopedEmailDashboard({ ...legacy, sourceAudit: {
        ...legacy.sourceAudit, sourceTenantId: 'tenant-a', incidentsComplete: true, sourceAttemptIds: { incidents: 'known' }
    }, summary: { ...legacy.summary, activeIncidents: 2 } }, 'tenant-a');
    assert.equal(partiallyTagged.sourceAudit.alertsComplete, false);
    assert.equal(partiallyTagged.summary.activeThreats, undefined);
    assert.equal(partiallyTagged.summary.activeIncidents, 2);
    const first = mergeVerifiedEmailSources(unknown, incoming('tenant-a', 'complete', 3), date('02'));
    const failed = mergeVerifiedEmailSources(first, incoming('tenant-a', 'failed', 0), date('04'));
    assert.equal(failed.summary.activeThreats, 3);
    assert.equal(failed.fetchedAt, first.fetchedAt);
    assert.equal(failed.sourceAudit.sourceTimestamps.alerts, date('02').toISOString());
    assert.equal(failed.sourceAudit.sourceOutcomes.alerts.status, 'failed');
    assert.equal(failed.sourceAudit.sourceOutcomes.alerts.at, date('04').toISOString());
    assert.equal(mergeVerifiedEmailSources(failed, incoming('tenant-a', 'failed', 0), date('05')), null);
    const recovered = mergeVerifiedEmailSources(failed, incoming('tenant-a', 'complete', 0), date('06'));
    assert.equal(recovered.summary.activeThreats, 0);
    assert.equal(recovered.sourceAudit.sourceOutcomes.alerts.status, 'complete');
    assert.equal(mergeVerifiedEmailSources(recovered, incoming('tenant-a', 'failed', 0), date('05')), null);
    const remapped = mergeVerifiedEmailSources(recovered, incoming('tenant-b', 'failed', 0), date('07'));
    assert.equal(remapped.sourceAudit.alertsComplete, false);
    assert.equal(remapped.summary.activeThreats, undefined);
});

test('Email snapshots publish each verified source independently and reject late results', () => {
    const date = minute => new Date(`2026-11-24T17:${minute}:00Z`);
    const alerts = { success: true, sourceAudit: { sourceTenantId: 'tenant-a', alertsComplete: true },
        alerts: [], summary: { activeThreats: 0, highSeverityAlerts: 0 } };
    const activity = { success: true, sourceAudit: { sourceTenantId: 'tenant-a', mailActivityOk: true },
        mailActivity: { users: [] }, summary: { activeMailboxes: 42 } };
    const incidents = { success: true, sourceAudit: { sourceTenantId: 'tenant-a', incidentsComplete: true },
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
        success: true, sourceAudit: { sourceTenantId: 'tenant-a', mailActivityOk: true },
        mailActivity: { users: [{ reportRefreshDate }] }, summary: { activeMailboxes }
    });
    const saved = mergeVerifiedEmailSources(null, report('2026-11-24', 42), new Date('2026-11-24T20:00:00Z'));
    const incoming = { ...report('2026-11-23', 40), alerts: [],
        sourceAudit: { sourceTenantId: 'tenant-a', mailActivityOk: true, alertsComplete: true } };
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
        section(client, 'function shouldIgnoreEmailDashboard', 'function hasRealProjectMetrics'),
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
