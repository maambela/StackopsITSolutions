const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');
const { hasEmailDashboardState, mergeVerifiedEmailSources, readEmailReportRefreshDate } = require('../services/intelligence/email-dashboard-processor');

const server = fs.readFileSync(require.resolve('../server'), 'utf8');
function section(start, end) {
    const from = server.indexOf(start);
    const to = server.indexOf(end, from + start.length);
    assert.ok(from >= 0 && to > from);
    return server.slice(from, to);
}

test('cache worker limits domain fan-out and persists healthy domains after another fails', async () => {
    const starts = [];
    const writes = new Map();
    const failures = [];
    const events = [];
    let failIdentity;
    let finishDevices;
    const email = {
        success: true,
        summary: { activeThreats: 1, highSeverityAlerts: 2, affectedUsersCount: 3, activeIncidents: 4 },
        sourceAudit: { attemptId: 'email-fixture', sourceTenantId: 'tenant-fixture', alertsComplete: true, incidentsComplete: true, mailActivityOk: true }
    };
    const refresh = vm.runInNewContext([
        section('async function mapWithConcurrency', 'async function getMicrosoftGraphCredentials'),
        section('async function writeMicrosoftDashboardCache', 'async function writeBackupRecoveryPayloadCache'),
        section('function hasCompleteEmailThreatCoverage', 'async function fetchEmailActivityReport'),
        section('async function runOwnedDashboardCollection', 'async function upsertDashboardMetricCaches'),
        section('async function upsertDashboardMetricCaches', 'let dashboardMetricRefreshRunning'),
        'upsertDashboardMetricCaches;'
    ].join('\n'), {
        crypto, readEmailReportRefreshDate, logRuntimeOperation: (event, details) => events.push({ event, ...details }),
        pool: {
            async query(sql, parameters) {
                if (sql.includes('FOR SHARE')) return [[{ TenantID: 'tenant-fixture' }]];
                if (sql.includes('SELECT')) return [[{ CompanyID: 7 }]];
                if (sql.startsWith('UPDATE EmailSecurityPayloadCache')) {
                    writes.set('EmailSecurityPayloadCache', JSON.parse(parameters[0]));
                    return;
                }
                writes.set(sql.match(/INSERT INTO (\w+)/)[1], Array.from(parameters));
            }
        },
        hasEmailDashboardState,
        mergeVerifiedEmailSources,
        parseReportJson: (value, fallback) => value ? JSON.parse(value) : fallback,
        console: { warn() {}, error: (...args) => failures.push(args.join(' ')) },
        async assertSharedGraphTenantForCompany(companyId) { assert.equal(companyId, 7); return 'tenant-fixture'; },
        runWithCollectionOwnership: async (_pool, _scope, collect) => collect(),
        withCollectionPublication: async (database, _company, publish) => publish(database),
        STACKCTRL_COLLECTOR_TIMEOUT_MS: 180000,
        identityMetricsRefreshAttempts: new Map(),
        getMicrosoftGraphToken: async () => 'fixture',
        fetchMicrosoftUsers() {
            starts.push('identity');
            return new Promise((resolve, reject) => { failIdentity = reject; });
        },
        fetchMicrosoftRoleAssignments: async () => [],
        async fetchIdentityMetricsFromApi(_token, inventory) { await inventory.users; },
        async fetchIdentityDetailsFromApi(_token, inventory) { await inventory.users; },
        fetchDeviceMetricsFromApi() {
            starts.push('devices');
            return new Promise(resolve => { finishDevices = resolve; });
        },
        fetchApplicationMetricsFromApi: async () => ({}),
        fetchApplicationsPayloadFromApi: async () => ({}),
        fetchEmailSecurityPayloadFromApi: async () => { starts.push('email'); return email; },
        fetchSecurityEventsPayloadFromApi: async () => ({}),
        fetchBackupRecoveryPayloadFromApi: async () => ({}),
        SECURITY_ALERT_STORAGE_ENABLED: true
    });
    const pending = refresh();
    await new Promise(setImmediate);
    assert.deepEqual([...starts].sort(), ['devices', 'identity']);
    failIdentity(new Error('Graph deadline'));
    finishDevices({ totalDevices: 12 });
    await pending;
    assert.match(failures[0], /identity for company 7.*Graph deadline/);
    assert.equal(writes.has('IdentityMetricsCache'), false);
    assert.equal(writes.get('DeviceMetricsCache')[1], 12);
    assert.equal(starts.filter(source => source === 'email').length, 1);
    assert.deepEqual(writes.get('EmailMetricsCache').slice(0, 5), [7, 1, 2, 3, 4]);
    const savedEmail = writes.get('EmailSecurityPayloadCache');
    assert.deepEqual(savedEmail.summary, email.summary);
    assert.ok(savedEmail.sourceAudit.sourceTimestamps.alerts);
    const publication = events.find(event => event.event === 'email_cache_publication');
    assert.equal(publication.outcome, 'saved');
    assert.equal(publication.cacheVersion, 'email-fixture');
    assert.equal(publication.sourceAttemptIds.alerts, 'email-fixture');
    assert.equal(publication.sourceTimestamps.alerts, savedEmail.sourceAudit.sourceTimestamps.alerts);
});

test('retired threat feed reports unavailable without an HTTP status or Graph request', async () => {
    const { collect, audit } = vm.runInNewContext([
        section('async function fetchSecurityThreatIndicatorRows', 'async function fetchSecuritySignInRows'),
        section('function securityCollectionSourceAudit', 'function buildSecurityScenarioAuditSummary'),
        '({ collect: fetchSecurityThreatIndicatorRows, audit: securityCollectionSourceAudit });'
    ].join('\n'));
    const result = await collect();
    assert.equal(result.errorCode, 'GRAPH_ENDPOINT_UNSUPPORTED');
    assert.equal(result.attempts, 0);
    assert.equal(result.threats.length, 0);
    const report = audit('/v1.0/security/tiIndicators', result);
    assert.equal(report.httpStatus, null);
    assert.equal(report.unavailable, true);
    assert.doesNotMatch(section('const rawEvidencePoller = createRawEvidencePoller', 'securityEvidenceService = createSecurityEvidenceStore'), /fetchSecurityThreatIndicatorRows/);
});

test('deducts queue time even when the abort timer has not fired', async () => {
    let now = 0;
    const events = [];
    const attempt = vm.runInNewContext(section('async function fetchMicrosoftGraphJsonAttempt', 'function isRetryableGraphError') +
        '\nfetchMicrosoftGraphJsonAttempt;', {
        process, AbortController, setTimeout, clearTimeout,
        performance: { now: () => now },
        MICROSOFT_GRAPH_REQUEST_TIMEOUT_MS: 15000,
        graphCoordinator: { async run(signal, next) { now = 15001; return next(15001); } },
        fetch() { assert.fail('request dispatched past its deadline'); },
        logRuntimeOperation: (event, fields) => events.push({ event, ...fields })
    });
    await assert.rejects(attempt('https://graph.microsoft.com/v1.0/users', 'fixture', 'Users'), { code: 'GRAPH_QUEUE_TIMEOUT' });
    assert.equal(events.length, 1);
    assert.equal(events[0].event, 'graph_request_failed');
    assert.equal(events[0].errorCode, 'GRAPH_QUEUE_TIMEOUT');
});

test('method timeout and queue expiry terminate, but Graph 429 still honors Retry-After', async () => {
    for (const code of ['GRAPH_REQUEST_TIMEOUT', 'GRAPH_QUEUE_TIMEOUT', 'GRAPH_HTTP_429']) {
        let attempts = 0;
        const waits = [];
        const read = vm.runInNewContext(section('function isRetryableGraphError', 'function beginSunbirdOperation') +
            '\nfetchMicrosoftGraphJson;', {
            crypto, microsoftGraphJsonCache: new Map(), microsoftGraphJsonPromises: new Map(),
            logRuntimeOperation() {},
            sleep: async ms => waits.push(ms),
            fetchMicrosoftGraphJsonAttempt: async () => {
                if (++attempts > 1) return { payload: { value: [] }, responseBytes: 12 };
                const error = new Error(code === 'GRAPH_HTTP_429' ? 'Graph failed (429)' : 'Graph timed out');
                error.code = code;
                error.retryAfterMs = 2500;
                throw error;
            }
        });
        const options = { shared: false, retries: 2, retryTimeouts: false };
        const pending = read('https://graph.microsoft.com/v1.0/users/id/authentication/methods', 'fixture', 'Methods', options);
        if (code === 'GRAPH_HTTP_429') {
            await pending;
            assert.equal(attempts, 2);
            assert.deepEqual(waits, [2500]);
        } else {
            await assert.rejects(pending, { code });
            assert.equal(attempts, 1);
            assert.deepEqual(waits, []);
        }
    }
});
