const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');

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
const { runWithCollectionOwnership, withCollectionPublication } = require('../services/intelligence/graph-collection-ownership');
const { fetchCloudflarePages } = require('../services/intelligence/cloudflare-collection');

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
        process: { env: { NETWORK_EVIDENCE_COLLECTION_ENABLED: 'false' } },
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

function networkCollectorFixture() {
    const snapshots = [];
    const children = [];
    const claims = new Map();
    const companies = new Set([7, 8]);
    const state = { accountId: 'account-a', now: 0, requests: 0, connections: 0, rollbacks: 0,
        queries: [], events: [], env: {} };
    let nextId = 1;
    const pool = {
        async getConnection() {
            state.connections++;
            if (state.connectionError) throw state.connectionError;
            const stagedSnapshots = [], stagedChildren = [];
            return {
                async beginTransaction() {}, release() {},
                async commit() { snapshots.push(...stagedSnapshots); children.push(...stagedChildren); },
                async rollback() { state.rollbacks++; stagedSnapshots.length = stagedChildren.length = 0; },
                async query(sql, params) {
                    if (!sql.startsWith('INSERT INTO StackCTRLNetworkEvidence')) return pool.query(sql, params);
                    const row = insertValues(sql, params);
                    if (sql.startsWith('INSERT INTO StackCTRLNetworkEvidenceSnapshots ')) {
                        const ID = nextId++;
                        stagedSnapshots.push({ ...row, ID,
                            CollectedAt: new Date(`${row.CollectedAt.replace(' ', 'T')}Z`),
                            SourceFetchedAt: new Date(`${row.SourceFetchedAt.replace(' ', 'T')}Z`) });
                        return [{ insertId: ID }];
                    }
                    await state.beforeChild?.();
                    stagedChildren.push(row);
                    return [{ affectedRows: 1 }];
                }
            };
        },
        async query(sql, params) {
            state.queries.push(sql);
            if (sql.includes('INSERT INTO StackCTRLIntelligenceScheduleRuns')) {
                const [, , , key, owner, ttl] = params;
                if (!claims.has(key) || claims.get(key).expiry <= state.now) claims.set(key, { owner, expiry: state.now + ttl });
                return [{}];
            }
            if (sql.includes('FROM StackCTRLIntelligenceScheduleRuns')) {
                const [key, , owner] = params;
                const claim = claims.get(key);
                return [claim?.owner === owner && claim.expiry > state.now ? [{ ID: 1 }] : []];
            }
            if (sql.includes('UPDATE StackCTRLIntelligenceScheduleRuns')) {
                const renew = sql.includes(' + ?');
                const [key, , owner] = renew ? params.slice(1) : params;
                const claim = claims.get(key);
                if (claim?.owner !== owner || (renew && claim.expiry <= state.now)) return [{ affectedRows: 0 }];
                claim.expiry = renew ? state.now + params[0] : 0;
                return [{ affectedRows: 1 }];
            }
            if (sql.includes('FROM Companies company')) {
                assert.match(sql, /capability\.IsEnabled = 1/);
                return [params ? (companies.has(params[0]) ? [{ ID: params[0] }] : []) : [{ CompanyID: 7 }]];
            }
            if (sql.includes('FROM StackCTRLNetworkEvidenceSnapshots')) {
                assert.match(sql, /WHERE CompanyID = \? AND IsComplete = 1/);
                let matching = snapshots.filter(row => row.CompanyID === params[0] && row.IsComplete === 1);
                matching = matching.slice(-1);
                if (params[1]) matching = matching.filter(row => row.CollectedAt > new Date(`${params[1].replace(' ', 'T')}Z`) ||
                    row.SourceFetchedAt > new Date(`${params[2].replace(' ', 'T')}Z`));
                return [matching.map(row => ({ ...row, AccountScope: JSON.parse(row.SourceAuditJson).accountScope }))];
            }
            assert.match(sql, /FROM StackCTRLNetworkEvidence WHERE SnapshotID = \?/);
            return [children.filter(row => row.SnapshotID === params[0])];
        }
    };
    const logger = { log() {}, info() {}, error() {}, warn() {} };
    const networkEvidenceService = createNetworkEvidenceStore({ pool, logger });
    const worker = () => vm.runInNewContext([
        serverSection('function isNetworkEvidenceCollectionEnabled', 'async function performBackupEvidenceCollection'),
        'async function refresh(sourceKey, companyId, collectorContext = {}) { switch (sourceKey) {',
        serverSection("        case 'cloudflare_network_security': {", "        case 'governance': {"),
        '} }',
        '({ scheduled: collectNetworkEvidenceForConfiguredTenants, refresh, collect: collectAndPersistNetworkEvidence });'
    ].join('\n'), {
        pool, networkEvidenceService, buildNetworkDashboardPayload, crypto, process: { env: state.env },
        console: logger, logRuntimeOperation: (event, details) => state.events.push({ event, ...details }), getSecret: () => state.accountId,
        runWithCollectionOwnership, withCollectionPublication,
        async getCloudflareNetworkSecuritySummary({ signal, accountId }) {
            state.requests++;
            await state.beforeFetch?.({ signal, accountId });
            return { ...networkDashboardPayload(), fetchedAt: new Date().toISOString() };
        },
        networkEvidenceCollectors: createTrackedCollectorRegistry({ logger, retainUntilSettled: true }),
        STACKCTRL_COLLECTOR_TIMEOUT_MS: 1000
    });
    return { worker, pool, state, snapshots, children, companies };
}

test('scheduled and enterprise paths create scoped Network evidence without dashboard visits', async () => {
    const { worker, pool, snapshots, children } = networkCollectorFixture();
    const { scheduled, refresh } = worker();
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

test('disabled network collection blocks every trigger and preserves archived evidence reads', async () => {
    const { worker, pool, snapshots, children, state } = networkCollectorFixture();
    const { scheduled, refresh, collect } = worker();
    const existing = await collect(7);
    assert.equal(existing.isComplete, true);
    const priorRows = children.length;
    state.env.NETWORK_EVIDENCE_COLLECTION_ENABLED = 'false';
    state.queries.length = 0;
    assert.equal((await scheduled({ trigger: 'startup' })).status, 'disabled');
    assert.equal((await scheduled({ trigger: 'scheduled_hourly' })).status, 'disabled');
    assert.equal((await refresh('cloudflare_network_security', 8)).status, 'disabled');
    assert.equal((await collect(8, 'forced', { forceRefresh: true })).status, 'disabled');
    assert.equal(state.queries.length, 0);

    const capability = { profileKey: 'sunbird', isExpected: true, isEnabled: true,
        refreshMode: 'refresh_if_stale', freshnessThresholdMinutes: 60 };
    const read = companyId => cloudflareNetworkSecurityAdapter({ pool, companyId, capability, refreshSource: refresh,
        refreshContext: { forceRefresh: true } });
    const saved = await read(7);
    assert.equal(saved.status, 'available');
    assert.equal(saved.sourceLineage.evidenceSnapshotId, existing.snapshotId);
    assert.match(saved.warnings.join(' '), /collection is disabled/i);
    const missing = await read(8);
    assert.equal(missing.status, 'missing');
    assert.equal(missing.errorMessage, null);
    assert.match(missing.warnings.join(' '), /archived network evidence is unavailable/i);
    assert.equal(state.queries.length, 3, 'read the stored header and children once, and check once for missing evidence');
    assert.equal(state.requests, 1);
    assert.equal(state.connections, 1);
    assert.equal(snapshots.length, 1);
    assert.equal(children.length, priorRows);
    assert.deepEqual(state.events.filter(event => event.event === 'network_evidence_refresh_skipped_disabled')
        .map(event => event.collectionTrigger), ['startup', 'scheduled_hourly', 'enterprise_refresh', 'forced', 'enterprise_refresh', 'enterprise_refresh']);

    state.env.NETWORK_EVIDENCE_COLLECTION_ENABLED = 'true';
    assert.equal((await read(8)).sourceLineage.isComplete, true);
    assert.equal(state.requests, 2);
    assert.equal(snapshots.length, 2);
});

function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}

test('overlapping network collectors share one company lease and recover after expiry', async () => {
    const { worker, state, snapshots } = networkCollectorFixture();
    const first = worker(), second = worker();
    const fetching = deferred(), unblock = deferred();
    state.beforeFetch = async () => {
        if (state.requests === 1) { fetching.resolve(); await unblock.promise; }
    };
    const original = first.scheduled();
    await fetching.promise;
    const joined = first.collect(7, 'enterprise_refresh');
    assert.equal((await second.collect(7, 'enterprise_refresh')).status, 'already_running');
    assert.equal((await second.collect(8)).isComplete, true);
    assert.equal(state.requests, 2);
    state.now += 60001;
    const replacement = await second.collect(7, 'enterprise_refresh');
    assert.equal(replacement.isComplete, true);
    const joinedFailure = assert.rejects(joined, { code: 'GRAPH_COLLECTION_OWNERSHIP_LOST' });
    unblock.resolve();
    await joinedFailure;
    assert.equal((await original).results[0].status, 'failed');
    assert.deepEqual(snapshots.filter(row => row.CompanyID === 7).map(row => row.ID), [replacement.snapshotId]);
    assert.equal((await first.collect(7)).status, 'fresh');
    const forced = await first.collect(7, 'enterprise_refresh', { forceRefresh: true });
    assert.equal(forced.isComplete, true);
    assert.equal(state.requests, 4);
});

test('cancellation during network retrieval and before connection acquisition prevents publication', async () => {
    const { worker, state, snapshots, pool } = networkCollectorFixture();
    const controller = new AbortController();
    state.beforeFetch = ({ signal }) => { assert.equal(signal.aborted, false); controller.abort(new Error('cancel retrieval')); };
    await assert.rejects(worker().collect(7, 'startup', { signal: controller.signal }), /cancel retrieval/);
    assert.equal(state.connections, 0);
    const cancelled = new AbortController();
    cancelled.abort(new Error('cancel before checkout'));
    const store = createNetworkEvidenceStore({ pool });
    await assert.rejects(store.persistProcessedEvidence({ companyId: 7, payload: networkDashboardPayload(), signal: cancelled.signal }), /cancel before checkout/);
    assert.equal(state.connections, 0);
    assert.equal(snapshots.length, 0);
});

test('network cancellation during persistence rolls back and preserves the last complete snapshot', async () => {
    const { worker, state, snapshots } = networkCollectorFixture();
    const first = worker(), second = worker();
    const saved = await first.collect(7);
    const controller = new AbortController(), writing = deferred(), unblock = deferred();
    state.beforeChild = async () => { writing.resolve(); await unblock.promise; };
    const pending = first.collect(7, 'enterprise_refresh', { forceRefresh: true, signal: controller.signal });
    const rejected = assert.rejects(pending, /cancel write/);
    await writing.promise;
    controller.abort(new Error('cancel write'));
    assert.equal((await second.collect(7)).status, 'already_running');
    unblock.resolve();
    await rejected;
    assert.equal(state.rollbacks, 1);
    assert.deepEqual(snapshots.map(row => row.ID), [saved.snapshotId]);
    assert.equal((await second.collect(7)).status, 'fresh');
});

test('network collector rejects company and account remapping and recovers from database failures', async () => {
    const { worker, state, snapshots, companies } = networkCollectorFixture();
    const { collect } = worker();
    await assert.rejects(collect(99), { code: 'NETWORK_EVIDENCE_SCOPE_UNAVAILABLE' });
    assert.equal(state.requests, 0);
    state.beforeFetch = () => { state.accountId = 'account-b'; };
    await assert.rejects(collect(7), { code: 'NETWORK_EVIDENCE_SCOPE_CHANGED' });
    assert.equal(state.connections, 0);
    state.beforeFetch = () => { companies.delete(7); };
    await assert.rejects(collect(7), { code: 'NETWORK_EVIDENCE_SCOPE_UNAVAILABLE' });
    assert.equal(state.rollbacks, 1);
    companies.add(7);
    state.beforeFetch = null;
    state.connectionError = new Error('database checkout failed');
    await assert.rejects(collect(7), /database checkout failed/);
    assert.equal(state.connections, 2);
    assert.equal(snapshots.length, 0);
    state.connectionError = null;
    assert.equal((await collect(7)).isComplete, true);
    state.accountId = 'account-c';
    assert.equal((await collect(7)).isComplete, true);
    assert.equal(snapshots.length, 2);
});

test('Cloudflare pagination observes cancellation and does not return partial evidence as success', async () => {
    const controller = new AbortController();
    let requests = 0;
    const client = { async get(_url, options) {
        assert.equal(options.signal, controller.signal);
        requests++;
        return { status: 200, data: { result: [{ id: 1 }], result_info: { total_pages: 2 } } };
    } };
    await assert.rejects(fetchCloudflarePages(client, '/fixture', {}, {
        signal: controller.signal, onPage: () => controller.abort(new Error('cancel pagination'))
    }), /cancel pagination/);
    assert.equal(requests, 1);
});

test('timed-out network registry entries stay joined until the underlying operation settles', async () => {
    const registry = createTrackedCollectorRegistry({ logger: {}, retainUntilSettled: true, timeoutMs: 1000 });
    const release = deferred();
    let signal;
    const context = { companyId: 7, sourceKey: 'cloudflare_network_security' };
    await assert.rejects(registry.run({ ...context, execute: work => { signal = work.signal; return release.promise; } }),
        { code: 'STACKCTRL_COLLECTOR_TIMEOUT' });
    assert.equal(signal.aborted, true);
    await assert.rejects(registry.run({ ...context, execute: () => assert.fail('overlapping work started') }),
        { code: 'STACKCTRL_COLLECTOR_TIMEOUT' });
    release.resolve();
    await new Promise(setImmediate);
    assert.equal(await registry.run({ ...context, execute: () => 'recovered' }), 'recovered');
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
