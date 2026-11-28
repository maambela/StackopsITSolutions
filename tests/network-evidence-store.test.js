const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const {
    NETWORK_EVIDENCE_SCHEMA,
    createNetworkEvidenceStore,
    deriveNetworkEvidence
} = require('../services/intelligence/network-evidence-store');
const {
    DEFAULT_NETWORK_EVIDENCE_INTERVAL_MS,
    createNetworkEvidenceAutomation
} = require('../services/intelligence/network-evidence-automation');
const { buildNetworkDashboardPayload } = require('../services/intelligence/network-dashboard-processor');
const { createTrackedCollectorRegistry } = require('../services/intelligence/collector-runtime');
const { cloudflareNetworkSecurityAdapter } = require('../services/intelligence/source-adapters');

const NOW = new Date('2026-06-23T08:00:00.000Z');
const server = fs.readFileSync(require.resolve('../server'), 'utf8');

function serverSection(start, end) {
    const from = server.indexOf(start);
    const to = server.indexOf(end, from + start.length);
    assert.ok(from >= 0 && to > from);
    return server.slice(from, to);
}

function insertValues(sql, params) {
    const columns = /INSERT INTO \w+ \(([^)]+)\)/.exec(sql)[1].split(', ');
    return Object.fromEntries(columns.map((column, index) => [column, params[index]]));
}

function networkDashboardPayload() {
    return buildNetworkDashboardPayload({
        tenantKey: 'sunbird',
        payload: {
            success: true,
            fetchedAt: NOW.toISOString(),
            overview: {
                protectedApps: 4,
                enrolledDevices: 12,
                gatewayPolicies: 8,
                activeGatewayPolicies: 7,
                identityProviders: 1,
                identityProvider: 'Azure AD',
                gatewayProxyEnabled: true,
                dlpProfiles: 2
            },
            sections: {
                apps: { status: 'ok' },
                devices: { status: 'ok' }
            },
            apps: Array.from({ length: 4 }, (_, index) => ({ id: `app-${index + 1}`, name: `App ${index + 1}` })),
            devices: Array.from({ length: 12 }, (_, index) => ({ id: `device-${index + 1}`, name: `Device ${index + 1}`, status: 'active' })),
            deviceRegistrations: Array.from({ length: 2 }, (_, index) => ({ id: `registration-${index + 1}`, name: `Registration ${index + 1}` })),
            devicePosture: [{ id: 'posture-1', name: 'Firewall enabled' }],
            gatewayRules: Array.from({ length: 8 }, (_, index) => ({ id: `rule-${index + 1}`, name: `Rule ${index + 1}`, enabled: index < 7 })),
            policies: Array.from({ length: 2 }, (_, index) => ({ id: `policy-${index + 1}`, name: `Access Policy ${index + 1}` })),
            accessLogs: Array.from({ length: 15 }, (_, index) => ({
                id: `log-${index + 1}`,
                action: index === 0 ? 'block' : 'allow',
                status: index === 0 ? 'deny' : 'ok'
            })),
            dlpProfiles: [{ id: 'dlp-1', name: 'Default DLP' }, { id: 'dlp-2', name: 'Finance DLP' }],
            warpProfiles: [{ id: 'warp-1', name: 'Default WARP' }],
            virtualNetworks: [{ id: 'vnet-1', name: 'Default virtual network' }],
            gatewayAppTypes: Array.from({ length: 5 }, (_, index) => ({ id: `category-${index + 1}`, name: `Gateway category ${index + 1}` })),
            permissionMatrix: Array.from({ length: 3 }, (_, index) => ({ id: `family-${index + 1}`, name: `API family ${index + 1}`, status: index === 2 ? 'permission_unavailable' : 'available' })),
            auditLogs: Array.from({ length: 6 }, (_, index) => ({ id: `audit-${index + 1}`, action: 'update', userEmail: `admin${index + 1}@example.com` })),
            accountLogs: Array.from({ length: 2 }, (_, index) => ({ id: `account-log-${index + 1}`, action: 'account_event' })),
            securityInsights: [{ id: 'insight-1', name: 'Security insight' }],
            tunnels: Array.from({ length: 2 }, (_, index) => ({ id: `tunnel-${index + 1}`, name: `Tunnel ${index + 1}` }))
        },
        now: () => NOW
    });
}

test('saved Network evidence metrics match the visible dashboard network model', () => {
    const payload = networkDashboardPayload();
    const evidence = deriveNetworkEvidence(payload);
    assert.equal(evidence.dashboardMetrics.protectedApps, 4);
    assert.equal(evidence.dashboardMetrics.enrolledDevices, 12);
    assert.equal(evidence.dashboardMetrics.gatewayPolicies, 8);
    assert.equal(evidence.dashboardMetrics.activeGatewayPolicies, 7);
    assert.equal(evidence.dashboardMetrics.deniedAccessEvents, 1);
    assert.equal(evidence.dashboardMetrics.dlpProfiles, 2);
    assert.equal(evidence.dashboardMetrics.appCategories, 5);
    assert.equal(evidence.dashboardMetrics.endpointFamilies, 3);
    assert.equal(evidence.dashboardMetrics.auditLogs, 6);
    assert.equal(evidence.dashboardMetrics.accountLogs, 2);
    assert.equal(evidence.dashboardMetrics.tunnels, 2);
    assert.equal(evidence.evidenceRows.length, 67);
    assert.equal(evidence.isComplete, true);
});

test('Network evidence storage writes one readable row per Cloudflare evidence item', async () => {
    const calls = [];
    const connection = {
        async beginTransaction() { calls.push({ sql: 'BEGIN', params: [] }); },
        async commit() { calls.push({ sql: 'COMMIT', params: [] }); },
        async rollback() { calls.push({ sql: 'ROLLBACK', params: [] }); },
        release() {},
        async query(sql, params = []) {
            calls.push({ sql, params });
            if (sql.includes('INSERT INTO StackCTRLNetworkEvidenceSnapshots')) return [{ insertId: 1001 }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const pool = {
        async query() { return [{ affectedRows: 0 }, []]; },
        async getConnection() { return connection; }
    };
    const store = createNetworkEvidenceStore({
        pool,
        logger: { log() {} },
        now: () => NOW
    });
    const payload = networkDashboardPayload();
    const result = await store.persistProcessedEvidence({
        companyId: 1,
        tenantKey: 'sunbird',
        payload,
        collectionTrigger: 'scheduled_hourly'
    });
    const snapshotWrite = calls.find(call => call.sql.includes('INSERT INTO StackCTRLNetworkEvidenceSnapshots'));
    const evidenceWrites = calls.filter(call => /INSERT INTO StackCTRLNetworkEvidence\s*\(/i.test(call.sql));
    assert.equal(result.snapshotId, 1001);
    assert.equal(result.recordCount, 67);
    assert.equal(evidenceWrites.length, 67);
    const snapshot = insertValues(snapshotWrite.sql, snapshotWrite.params);
    assert.equal(snapshot.EvidenceRecordCount, 67);
    assert.equal(snapshot.ProtectedApps, 4);
    assert.equal(snapshot.EnrolledDevices, 12);
    assert.equal(snapshot.DeniedAccessEvents, 1);
    const metrics = JSON.parse(snapshot.DashboardMetricsJson);
    assert.equal(metrics.auditLogs, 6);
    assert.equal(metrics.appCategories, 5);
    assert.equal(metrics.endpointFamilies, 3);
});

test('Network evidence schema uses explicit snapshot and evidence fields', () => {
    const schema = NETWORK_EVIDENCE_SCHEMA.join('\n');
    assert.match(schema, /StackCTRLNetworkEvidenceSnapshots/);
    assert.match(schema, /StackCTRLNetworkEvidence/);
    assert.match(schema, /NetworkSecurityScore/);
    assert.match(schema, /ProcessedEvidenceJson/);
});

test('authenticated Network dashboard GETs fetch live data and leave evidence storage untouched', async () => {
    const payload = networkDashboardPayload();
    const authenticateToken = () => {};
    const getSecret = () => {};
    let handler;
    let fetches = 0;
    let writes = 0;
    vm.runInNewContext(serverSection("app.get('/api/cloudflare/network-security/summary'", 'const SUNBIRD_REPORT_TIME_ZONE'), {
        app: { get(path, auth, route) {
            assert.equal(path, '/api/cloudflare/network-security/summary');
            assert.equal(auth, authenticateToken);
            handler = route;
        } },
        authenticateToken, getSecret, buildNetworkDashboardPayload,
        getTenantByEmail: () => ({ companyId: 7, clientId: 'sunbird' }),
        networkEvidenceService: { async persistProcessedEvidence() { writes += 1; } },
        async getCloudflareNetworkSecuritySummary(options) {
            assert.equal(options.getSecret, getSecret);
            fetches += 1;
            return payload;
        }
    });
    const responses = [];
    const res = { json: data => responses.push(data) };
    await Promise.all(Array.from({ length: 3 }, () => handler({ user: { email: 'user@example.test' } }, res)));
    assert.equal(fetches, 3);
    assert.deepEqual(responses, [payload, payload, payload]);
    assert.equal(writes, 0);
});

test('scheduled and enterprise paths create scoped Network evidence without dashboard visits', async () => {
    const snapshots = [];
    const children = [];
    const now = new Date();
    const connection = {
        async beginTransaction() {}, async commit() {}, async rollback() {}, release() {},
        async query(sql, params) {
            const row = insertValues(sql, params);
            if (sql.startsWith('INSERT INTO StackCTRLNetworkEvidenceSnapshots ')) {
                const ID = snapshots.length + 1;
                snapshots.push({ ...row, ID,
                    CollectedAt: new Date(`${row.CollectedAt.replace(' ', 'T')}Z`),
                    SourceFetchedAt: new Date(`${row.SourceFetchedAt.replace(' ', 'T')}Z`) });
                return [{ insertId: ID }];
            }
            assert.match(sql, /^INSERT INTO StackCTRLNetworkEvidence /);
            children.push(row);
            return [{ affectedRows: 1 }];
        }
    };
    const pool = {
        async getConnection() { return connection; },
        async query(sql, params) {
            if (sql.includes('FROM Companies company')) {
                assert.match(sql, /capability\.IsEnabled = 1/);
                return [[{ CompanyID: 7 }]];
            }
            if (sql.includes('FROM StackCTRLNetworkEvidenceSnapshots')) {
                assert.match(sql, /WHERE CompanyID = \? AND IsComplete = 1/);
                return [snapshots.filter(row => row.CompanyID === params[0] && row.IsComplete === 1).slice(-1)];
            }
            assert.match(sql, /FROM StackCTRLNetworkEvidence WHERE SnapshotID = \?/);
            return [children.filter(row => row.SnapshotID === params[0])];
        }
    };
    const logger = { log() {}, info() {} };
    const networkEvidenceService = createNetworkEvidenceStore({ pool, logger, now: () => now });
    const { scheduled, refresh } = vm.runInNewContext([
        serverSection('async function performNetworkEvidenceCollection', 'async function performBackupEvidenceCollection'),
        'async function refresh(sourceKey, companyId, collectorContext = {}) { switch (sourceKey) {',
        serverSection("        case 'cloudflare_network_security': {", "        case 'governance': {"),
        '} }',
        '({ scheduled: collectNetworkEvidenceForConfiguredTenants, refresh });'
    ].join('\n'), {
        pool, networkEvidenceService, buildNetworkDashboardPayload, getSecret: () => {},
        getCloudflareNetworkSecuritySummary: async () => ({ ...networkDashboardPayload(), fetchedAt: now.toISOString() }),
        networkEvidenceCollectors: createTrackedCollectorRegistry({ logger }),
        STACKCTRL_COLLECTOR_TIMEOUT_MS: 1000
    });
    const scheduledResult = await scheduled({ trigger: 'scheduled_hourly' });
    assert.equal(scheduledResult.results[0].isComplete, true);
    assert.equal(snapshots[0].CompanyID, 7);
    assert.equal(snapshots[0].CollectionTrigger, 'scheduled_hourly');

    const capability = { profileKey: 'sunbird', isExpected: true, isEnabled: true,
        refreshMode: 'refresh_if_stale', freshnessThresholdMinutes: 60 };
    const load = (companyId, refreshSource) => cloudflareNetworkSecurityAdapter({ pool, companyId, capability, refreshSource });
    assert.equal((await load(8)).status, 'missing');
    const first = await load(8, refresh);
    assert.equal(first.status, 'available');
    assert.equal(first.sourceLineage.evidenceSnapshotId, 2);
    assert.equal(first.sourceLineage.collectionTrigger, 'enterprise_refresh');
    assert.equal(first.sourceLineage.isComplete, true);
    assert.equal(snapshots[1].CompanyID, 8);
    assert.equal(children.filter(row => row.SnapshotID === 2 && row.CompanyID === 8).length, 67);
    assert.equal((await load(7, refresh)).sourceLineage.evidenceSnapshotId, 1);
    assert.equal(snapshots.length, 2);
});

test('Network evidence automation runs on a 60-minute interval by default', async () => {
    let runs = 0;
    const automation = createNetworkEvidenceAutomation({
        collectAll: async () => { runs += 1; return { ok: true }; },
        intervalMs: DEFAULT_NETWORK_EVIDENCE_INTERVAL_MS,
        startupDelayMs: 0
    });
    automation.start();
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(runs, 1);
    automation.stop();
});
