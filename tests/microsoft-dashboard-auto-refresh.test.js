const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const server = fs.readFileSync(require.resolve('../server'), 'utf8');
const client = fs.readFileSync(require.resolve('../js/clientportal'), 'utf8');

function section(source, start, end) {
    const first = source.indexOf(start);
    const last = source.indexOf(end, first + start.length);
    assert.ok(first >= 0 && last > first, start);
    return source.slice(first, last);
}

function createRefreshContext(overrides = {}) {
    const applied = [];
    const scheduled = [];
    const state = {
        sessionValid: true,
        visibility: 'visible',
        token: 'token-A',
        scope: 'session-A:token-A',
        response: { success: true, companyId: 7, snapshots: { identity: { complete: true } } },
        fetchCalls: 0,
        ...overrides
    };
    const context = {
        AbortController,
        console: { warn() {} },
        setTimeout,
        clearTimeout,
        document: { visibilityState: state.visibility },
        localStorage: { getItem: key => key === 'authToken' ? state.token : null },
        fetch: async url => {
            state.fetchCalls++;
            state.url = url;
            if (state.fetchImpl) return state.fetchImpl(url);
            return { ok: true, status: 200, json: async () => state.response };
        },
        isSessionValid: () => state.sessionValid,
        isMicrosoftDashboardViewActive: () => state.viewActive !== false,
        microsoftDashboardRefreshScopeKey: () => state.scope,
        scheduleMicrosoftDashboardAutoRefresh: delay => scheduled.push(delay),
        stopMicrosoftDashboardAutoRefresh() {
            context.microsoftDashboardRefreshController?.abort();
            context.microsoftDashboardRefreshController = null;
            context.microsoftDashboardRefreshRequest = null;
            context.microsoftDashboardRefreshScope = null;
            context.microsoftDashboardRefreshCompanyId = null;
        },
        updateMicrosoftDashboardFreshnessStatus() {},
        applyMicrosoftDashboardSnapshots: snapshots => applied.push(snapshots),
        scheduled,
        applied,
        state,
        MICROSOFT_DASHBOARD_HIDDEN_REFRESH_INTERVAL_MS: 300000,
        MICROSOFT_DASHBOARD_REFRESH_INTERVAL_MS: 30000,
        MICROSOFT_DASHBOARD_REFRESH_MAX_BACKOFF_MS: 300000,
        microsoftDashboardRefreshFailureCount: 0,
        microsoftDashboardRefreshController: null,
        microsoftDashboardRefreshRequest: null,
        microsoftDashboardRefreshScope: null,
        microsoftDashboardRefreshCompanyId: null
    };
    context.document.visibilityState = state.visibility;
    vm.runInNewContext(
        section(client, 'async function refreshMicrosoftDashboardSnapshots()', 'function readMicrosoftDashboardCache'),
        context
    );
    return context;
}

test('polling checks saved snapshots and applies newer verified data only', async () => {
    const context = createRefreshContext();
    const refresh = context.refreshMicrosoftDashboardSnapshots;
    await refresh();
    assert.equal(context.state.url, '/api/db/microsoft-dashboard-snapshots');
    assert.equal(context.state.fetchCalls, 1);
    assert.equal(context.applied.length, 1);
    assert.equal(context.applied[0].identity.complete, true);

    const identityCard = {};
    const applier = vm.runInNewContext([
        section(client, 'function isNewerVerifiedMicrosoftDashboardSnapshot', 'function updateMicrosoftDashboardFreshnessStatus'),
        section(client, 'function shouldIgnoreEmailDashboard', 'function hasRealProjectMetrics'),
        section(client, 'function applyMicrosoftDashboardSnapshots', 'function microsoftProjectCardFooter'),
        'applyMicrosoftDashboardSnapshots;'
    ].join('\n'), {
        AbortController,
        document: { getElementById: () => null },
        localStorage: { getItem: () => 'token-A' },
        mockProjects: [],
        sunbirdDashboardData: { success: true, users: [{ id: 'old' }], fetchedAt: '2026-11-23T12:00:00Z' },
        latestDevicesCardData: null,
        sunbirdDevicesDashboardData: null,
        sunbirdSecurityDashboardData: null,
        latestEmailCardData: null,
        sunbirdEmailDashboardData: null,
        sunbirdApplicationsPayload: null,
        cachedSunbirdBackupData: null,
        microsoftUsersData: [],
        microsoftRolesData: [],
        microsoftDashboardRefreshScopeKey: () => 'session-A:token-A',
        microsoftDashboardSourceTime: data => Date.parse(data?.collectionStartedAt || data?.fetchedAt || data?.metrics?.LastUpdated || ''),
        normalizeSunbirdDashboardData: data => data,
        normalizeSunbirdEmailData: data => data,
        saveSunbirdEmailSnapshot: data => { identityCard.email = data; },
        normalizeSunbirdIdentityUser: user => user,
        buildUserRolesMap() {},
        saveSunbirdIdentitySnapshot: data => { identityCard.roles = data.roleAssignments; },
        updateIdentityProjectCardFromDashboard: data => { identityCard.updatedAt = data.fetchedAt; },
        renderSunbirdIdentityDashboard() {}
    });
    const incoming = {
        success: true,
        complete: true,
        companyId: 7,
        sourceTenantId: 'tenant-a',
        users: [{ id: 'new' }],
        fetchedAt: '2026-11-23T12:30:00Z'
    };
    assert.equal(applier({ identity: incoming }), true);
    assert.equal(identityCard.updatedAt, incoming.fetchedAt);
    const email = { success: true, fetchedAt: incoming.fetchedAt, summary: { activeThreats: 3 },
        sourceAudit: { sourceTenantId: 'tenant-a', cacheSequence: 1, alertsComplete: true } };
    assert.equal(applier({ email }), true);
    const failed = { ...email, sourceAudit: { ...email.sourceAudit, cacheSequence: 2,
        sourceOutcomes: { alerts: { status: 'failed' } } } };
    assert.equal(applier({ email: failed }), true);
    assert.equal(identityCard.email.sourceAudit.sourceOutcomes.alerts.status, 'failed');
    assert.equal(identityCard.email.fetchedAt, email.fetchedAt);
    assert.equal(identityCard.email.summary.activeThreats, 3);
    assert.equal(applier({ email }), false);
    assert.equal(applier({ email: { success: true, fetchedAt: null, sourceAudit: { sourceTenantId: 'tenant-b' } } }), true);
    assert.equal(identityCard.email.summary, undefined);
    const unavailable = { success: true, fetchedAt: null, sourceAudit: { scopeUnavailable: true } };
    assert.equal(applier({ email: unavailable }), true);
    assert.equal(applier({ email: unavailable }), false);
    assert.equal(applier({ identity: incoming }), false);
    assert.equal(identityCard.updatedAt, incoming.fetchedAt);
    assert.equal(applier({ identity: { ...incoming, fetchedAt: '2026-11-23T11:00:00Z' } }), false);
    assert.equal(applier({ identity: { ...incoming, complete: false, fetchedAt: '2026-11-23T13:00:00Z' } }), false);
    const roles = { ...incoming, roleAssignments: [{ id: 'role' }], roleAssignmentsFetchedAt: '2026-11-23T13:00:00Z' };
    assert.equal(applier({ identity: { ...roles, sourceTenantId: 'different-tenant' } }), false);
    assert.equal(applier({ identity: roles }), true);
    assert.equal(identityCard.roles[0].id, 'role');
    assert.equal(identityCard.updatedAt, incoming.fetchedAt);
});

test('saved snapshot route is authenticated, company-scoped, and never invokes Graph collection', () => {
    const route = section(server, "app.get('/api/db/microsoft-dashboard-snapshots'", '/**\n * Route: GET /api/microsoft-users');
    assert.match(route, /authenticateToken/);
    assert.match(route, /CompanyID = \?/);
    assert.match(route, /refreshMode: 'stored_only'/);
    assert.match(route, /complete: key !== 'email' \|\| \(hasCompleteEmailThreatCoverage\(snapshot\)/);
    assert.match(route, /selectScopedEmailDashboard\(payload, sourceTenantId\)/);
    assert.doesNotMatch(route, /fetch[A-Za-z]*FromApi|fetchGraph/);
});

test('overlapping checks share one request and failed checks preserve current data', async () => {
    let resolveFetch;
    const context = createRefreshContext({
        fetchImpl: () => new Promise(resolve => { resolveFetch = resolve; })
    });
    const first = context.refreshMicrosoftDashboardSnapshots();
    const second = context.refreshMicrosoftDashboardSnapshots();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(context.state.fetchCalls, 1);

    resolveFetch({ ok: true, status: 200, json: async () => context.state.response });
    await Promise.all([first, second]);
    assert.equal(context.applied.length, 1);

    const failed = createRefreshContext({
        fetchImpl: async () => { throw new Error('offline'); }
    });
    const verifiedDisplay = { value: 'last verified' };
    await failed.refreshMicrosoftDashboardSnapshots();
    assert.equal(verifiedDisplay.value, 'last verified');
    assert.equal(failed.applied.length, 0);
});

test('failed snapshot checks back off and a successful check resets the retry delay', async () => {
    const context = createRefreshContext({
        fetchImpl: async () => { throw new Error('offline'); }
    });

    await context.refreshMicrosoftDashboardSnapshots();
    assert.equal(context.microsoftDashboardRefreshFailureCount, 1);
    assert.deepEqual(context.scheduled, [60000]);

    context.scheduled.length = 0;
    await context.refreshMicrosoftDashboardSnapshots();
    assert.equal(context.microsoftDashboardRefreshFailureCount, 2);
    assert.deepEqual(context.scheduled, [120000]);

    context.state.fetchImpl = null;
    context.scheduled.length = 0;
    await context.refreshMicrosoftDashboardSnapshots();
    assert.equal(context.microsoftDashboardRefreshFailureCount, 0);
    assert.deepEqual(context.scheduled, [30000]);
});

test('hidden and signed-out views do not make a snapshot request', async () => {
    const hidden = createRefreshContext({ visibility: 'hidden' });
    await hidden.refreshMicrosoftDashboardSnapshots();
    assert.equal(hidden.state.fetchCalls, 0);
    assert.deepEqual(hidden.scheduled, [300000]);

    const signedOut = createRefreshContext({ sessionValid: false });
    await signedOut.refreshMicrosoftDashboardSnapshots();
    assert.equal(signedOut.state.fetchCalls, 0);
});

test('a company change invalidates the response before applying its snapshots', async () => {
    const context = createRefreshContext();
    context.microsoftDashboardRefreshCompanyId = 7;
    context.state.response = { success: true, companyId: 8, snapshots: { identity: { complete: true } } };
    await context.refreshMicrosoftDashboardSnapshots();
    assert.equal(context.applied.length, 0);
    assert.equal(context.microsoftDashboardRefreshCompanyId, 8);

    await context.refreshMicrosoftDashboardSnapshots();
    assert.equal(context.applied.length, 1);
});

test('a session change while a request is in flight discards its response', async () => {
    let resolveFetch;
    const context = createRefreshContext({
        fetchImpl: () => new Promise(resolve => { resolveFetch = resolve; })
    });
    const request = context.refreshMicrosoftDashboardSnapshots();
    await new Promise(resolve => setImmediate(resolve));
    context.state.scope = 'session-B:token-A';
    resolveFetch({ ok: true, status: 200, json: async () => context.state.response });
    await request;
    assert.equal(context.applied.length, 0);
});
