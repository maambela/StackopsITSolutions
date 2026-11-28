const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { randomUUID } = require('node:crypto');
const mysql = require('mysql2/promise');
const { acquireClaim, claimKey, renewClaim, releaseClaim, runWithCollectionOwnership, withCollectionPublication } =
    require('../services/intelligence/graph-collection-ownership');
const { hasEmailDashboardState, mergeVerifiedEmailSources, readEmailReportRefreshDate } =
    require('../services/intelligence/email-dashboard-processor');
const { NETWORK_EVIDENCE_SCHEMA, createNetworkEvidenceStore } = require('../services/intelligence/network-evidence-store');
const { buildNetworkDashboardPayload } = require('../services/intelligence/network-dashboard-processor');
const { createTrackedCollectorRegistry } = require('../services/intelligence/collector-runtime');
const { createHash } = require('node:crypto');

async function verifyNetworkPublication(pool) {
    for (const sql of NETWORK_EVIDENCE_SCHEMA) await pool.query(sql);
    const scope = { companyId: 7, tenantId: 'cloudflare-network', source: 'cloudflare_network_security' };
    const rows = async () => (await pool.query('SELECT ID, EvidenceRecordCount FROM StackCTRLNetworkEvidenceSnapshots ORDER BY ID'))[0];
    const publish = ({ observed = '2026-11-26T12:00:00Z', signal, afterChild, atCommit, ttlMs } = {}) => {
        const store = createNetworkEvidenceStore({ logger: { log() {} }, pool: {
            query: pool.query.bind(pool),
            async getConnection() {
                const db = await pool.getConnection();
                return {
                    beginTransaction: db.beginTransaction.bind(db), rollback: db.rollback.bind(db),
                    release: db.release.bind(db), destroy: db.destroy.bind(db),
                    async query(sql, params) {
                        const result = await db.query(sql, params);
                        if (sql.startsWith('INSERT INTO StackCTRLNetworkEvidence ')) await afterChild?.(db);
                        return result;
                    },
                    commit: () => atCommit ? atCommit(db) : db.commit()
                };
            }
        } });
        return runWithCollectionOwnership(pool, { ...scope, signal, ttlMs }, () => store.persistProcessedEvidence({
            companyId: scope.companyId, collectionStartedAt: new Date(), signal,
            payload: { success: true, fetchedAt: observed, overview: { identityProviders: 0 }, apps: [{ id: 'a', name: 'App' }] }
        }));
    };
    const first = await publish({ atCommit: async db => {
        // This hook runs after the store's final SELECT ... FOR UPDATE and before COMMIT.
        const contender = await pool.getConnection();
        try {
            assert.equal((await rows()).length, 0);
            await contender.query('SET SESSION innodb_lock_wait_timeout = 1');
            await assert.rejects(acquireClaim(contender, claimKey(7, scope.tenantId, scope.source),
                7, scope.source, 60000, 'commit-gap-contender'), { code: 'ER_LOCK_WAIT_TIMEOUT' });
            await db.commit();
        } finally {
            await contender.query('SET SESSION innodb_lock_wait_timeout = DEFAULT');
            contender.release();
        }
    } });
    assert.equal((await rows())[0].ID, first.snapshotId);

    const controller = new AbortController();
    await assert.rejects(publish({ signal: controller.signal, afterChild: () => controller.abort(new Error('cancelled in transaction')) }),
        /cancelled in transaction/);
    await assert.rejects(publish({ ttlMs: 500, afterChild: () => new Promise(resolve => setTimeout(resolve, 600)) }),
        { code: 'GRAPH_COLLECTION_OWNERSHIP_LOST' });
    await assert.rejects(publish({ afterChild: db => db.destroy() }), /closed state|closed connection|connection lost/i);
    assert.deepEqual((await rows()).map(row => row.ID), [first.snapshotId]);
    assert.equal((await pool.query('SELECT ID FROM StackCTRLNetworkEvidence'))[0].length, first.recordCount);

    await assert.rejects(publish({ observed: '2026-11-27T12:00:00Z', atCommit: async db => {
        await db.commit();
        db.destroy();
        throw new Error('simulated lost commit acknowledgement');
    } }), /simulated lost commit acknowledgement/);
    const committed = await rows();
    assert.equal(committed.length, 2, 'an ambiguous commit must not be replayed');
    assert.equal((await publish()).status, 'superseded');
    assert.deepEqual(await rows(), committed);
    assert.equal((await publish({ observed: '2026-11-28T12:00:00Z' })).isComplete, true);
}

async function verifyNetworkCollectorRefresh(pool, source) {
    await pool.query('CREATE TABLE Companies (ID BIGINT PRIMARY KEY, CompanyName VARCHAR(100)) ENGINE=InnoDB');
    await pool.query(`CREATE TABLE StackCTRLClientCapabilities (
        CompanyID BIGINT NOT NULL, SourceKey VARCHAR(100) NOT NULL, ProfileKey VARCHAR(30),
        IsExpected TINYINT, IsEnabled TINYINT, PRIMARY KEY (CompanyID, SourceKey)
    ) ENGINE=InnoDB`);
    await pool.query("INSERT INTO Companies VALUES (8, 'First company'), (9, 'Other company')");
    await pool.query(`INSERT INTO StackCTRLClientCapabilities VALUES
        (8, 'cloudflare_network_security', 'sunbird', 1, 1), (9, 'cloudflare_network_security', 'sunbird', 1, 1)`);
    const from = source.indexOf('function isNetworkEvidenceCollectionEnabled');
    const to = source.indexOf('async function collectNetworkEvidenceForConfiguredTenants', from);
    let requests = 0;
    const env = {};
    const logger = { log() {} };
    const collect = vm.runInNewContext(source.slice(from, to) + '\ncollectAndPersistNetworkEvidence;', {
        pool, buildNetworkDashboardPayload, runWithCollectionOwnership, withCollectionPublication,
        crypto: { createHash }, process: { env }, getSecret: () => 'fixture-account',
        logRuntimeOperation() {}, STACKCTRL_COLLECTOR_TIMEOUT_MS: 10000,
        networkEvidenceCollectors: createTrackedCollectorRegistry({ logger, retainUntilSettled: true }),
        networkEvidenceService: createNetworkEvidenceStore({ pool, logger }),
        async getCloudflareNetworkSecuritySummary({ accountId }) {
            assert.equal(accountId, 'fixture-account');
            requests++;
            return { success: true, fetchedAt: new Date().toISOString(), overview: { identityProviders: 0 } };
        }
    });
    const first = await collect(8, 'startup');
    assert.equal(first.isComplete, true);
    assert.equal((await collect(8)).status, 'fresh');
    assert.equal(requests, 1);
    env.NETWORK_EVIDENCE_COLLECTION_ENABLED = 'false';
    assert.equal((await collect(8, 'enterprise_refresh', { forceRefresh: true })).status, 'disabled');
    assert.equal((await collect(9, 'startup')).status, 'disabled');
    assert.equal(requests, 1);
    const [[disabledCounts]] = await pool.query(`SELECT
        (SELECT COUNT(*) FROM StackCTRLNetworkEvidenceSnapshots WHERE CompanyID IN (8, 9)) AS snapshots,
        (SELECT COUNT(*) FROM StackCTRLIntelligenceScheduleRuns WHERE CompanyID IN (8, 9)) AS claims`);
    assert.equal(disabledCounts.snapshots, 1);
    assert.equal(disabledCounts.claims, 1);
    env.NETWORK_EVIDENCE_COLLECTION_ENABLED = 'true';
    const other = await collect(9, 'startup');
    const forced = await collect(8, 'enterprise_refresh', { forceRefresh: true });
    assert.equal(other.isComplete, true);
    assert.equal(forced.isComplete, true);
    assert.notEqual(first.snapshotId, forced.snapshotId);
    assert.equal(requests, 3);
    const [rows] = await pool.query('SELECT ID, CompanyID FROM StackCTRLNetworkEvidenceSnapshots WHERE CompanyID IN (8, 9) ORDER BY ID');
    assert.deepEqual(rows.map(row => [row.ID, row.CompanyID]), [[first.snapshotId, 8], [other.snapshotId, 9], [forced.snapshotId, 8]]);
}

test('isolated MySQL serializes claims, fences old writers and rolls back failed publication', {
    skip: process.env.STACKCTRL_ISOLATED_MYSQL_TEST !== '1'
}, async () => {
    // This test only targets the explicitly started disposable local instance.
    // Snapshots store UTC DATETIME values. Mirror the UTC application runtime on local hosts too.
    const connectionOptions = { host: '127.0.0.1', port: 13387, user: 'root', password: '', timezone: 'Z' };
    const admin = await mysql.createConnection(connectionOptions);
    const database = 'stackctrl_test_' + randomUUID().replaceAll('-', '');
    let created = false;
    let pool;
    try {
        const [[instance]] = await admin.query('SELECT @@datadir AS dataDir');
        assert.match(instance.dataDir, /[\\/]stackctrl-mysql-test-[a-f0-9]{32}[\\/]data[\\/]?$/i,
            'Refusing to write outside the disposable local MySQL instance');
        await admin.query('CREATE DATABASE ??', [database]);
        created = true;
        pool = mysql.createPool({ ...connectionOptions, database, connectionLimit: 4 });
        const source = fs.readFileSync(require.resolve('../server'), 'utf8');
        const schema = source.match(/CREATE TABLE IF NOT EXISTS StackCTRLIntelligenceScheduleRuns \([\s\S]*?\) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4/)[0];
        await pool.query(schema);
        await pool.query('CREATE TABLE FixturePublication (ID INT PRIMARY KEY, Payload VARCHAR(20)) ENGINE=InnoDB');
        const firstConnection = await pool.getConnection();
        const secondConnection = await pool.getConnection();
        try {
            const key = claimKey(1, 'tenant-a', 'identity');
            const contenders = await Promise.all([
                acquireClaim(firstConnection, key, 1, 'identity', 60000, 'owner-a'),
                acquireClaim(secondConnection, key, 1, 'identity', 60000, 'owner-b')
            ]);
            const owned = contenders.filter(Boolean);
            assert.equal(owned.length, 1);
            const otherCompany = await acquireClaim(secondConnection, claimKey(2, 'tenant-a', 'identity'), 2, 'identity', 60000, 'other-company');
            const otherTenant = await acquireClaim(secondConnection, claimKey(1, 'tenant-b', 'identity'), 1, 'identity', 60000, 'other-tenant');
            assert.ok(otherCompany && otherTenant);
            await releaseClaim(firstConnection, owned[0]);
            await releaseClaim(secondConnection, otherCompany);
            await releaseClaim(secondConnection, otherTenant);
        } finally {
            firstConnection.release();
            secondConnection.release();
        }

        const scope = { companyId: 1, tenantId: 'tenant-a', source: 'identity', ttlMs: 500 };
        const lock = await pool.getConnection();
        const renewal = await pool.getConnection();
        try {
            const key = claimKey(1, 'tenant-a', 'identity');
            const claim = await acquireClaim(pool, key, 1, 'identity', 750, 'blocked-renewal');
            assert.ok(claim);
            assert.equal(await renewClaim(renewal, claim, 750), true);
            await renewal.query('SET SESSION innodb_lock_wait_timeout = 1');
            await lock.beginTransaction();
            await lock.query('SELECT ID FROM StackCTRLIntelligenceScheduleRuns WHERE DeduplicationKey = ? FOR UPDATE', [key]);
            await assert.rejects(renewClaim(renewal, claim, 60000), { code: 'ER_LOCK_WAIT_TIMEOUT' });
            await lock.rollback();
            assert.equal(await renewClaim(renewal, claim, 60000), false);
            const recovered = await acquireClaim(pool, key, 1, 'identity', 60000, 'recovered-after-lock');
            assert.ok(recovered);
            await releaseClaim(pool, recovered);
        } finally {
            await lock.rollback();
            await renewal.query('SET SESSION innodb_lock_wait_timeout = DEFAULT');
            renewal.release();
            lock.release();
        }
        let resume;
        const pause = new Promise(resolve => { resume = resolve; });
        let notifyStarted;
        const started = new Promise(resolve => { notifyStarted = resolve; });
        const publish = (company, label) => withCollectionPublication(pool, company,
            db => db.query('INSERT INTO FixturePublication VALUES (1, ?) ON DUPLICATE KEY UPDATE Payload = VALUES(Payload)', [label]));
        const oldRun = runWithCollectionOwnership(pool, scope, async () => {
            notifyStarted();
            await pause;
            await publish(1, 'old');
        });
        const oldRejected = assert.rejects(oldRun, { code: 'GRAPH_COLLECTION_OWNERSHIP_LOST' });
        try {
            await started;
            assert.equal((await runWithCollectionOwnership(pool, scope, () => assert.fail('duplicate ran'))).status, 'already_running');
            await new Promise(resolve => setTimeout(resolve, 650));
            assert.notEqual(await runWithCollectionOwnership(pool, scope, () => publish(1, 'new')), undefined);
        } finally {
            resume();
            await oldRejected;
        }
        await assert.rejects(runWithCollectionOwnership(pool, scope, () => withCollectionPublication(pool, 1, async db => {
            await db.query('UPDATE FixturePublication SET Payload = ?', ['failed']);
            throw new Error('publication failure');
        })), /publication failure/);
        const [[stored]] = await pool.query('SELECT Payload FROM FixturePublication WHERE ID = 1');
        assert.equal(stored.Payload, 'new');
        assert.equal(await runWithCollectionOwnership(pool, scope, () => 'available after rollback'), 'available after rollback');
        await assert.rejects(runWithCollectionOwnership(pool, scope, () => publish(2, 'wrong-company')), {
            code: 'GRAPH_COLLECTION_OWNERSHIP_LOST'
        });

        await pool.query('CREATE TABLE MicrosoftTenants (ID INT PRIMARY KEY, TenantID VARCHAR(50)) ENGINE=InnoDB');
        await pool.query('CREATE TABLE CompanyMicrosoftMapping (CompanyID INT PRIMARY KEY, MicrosoftTenantID INT, IsActive TINYINT) ENGINE=InnoDB');
        await pool.query('CREATE TABLE EmailSecurityPayloadCache (CompanyID INT PRIMARY KEY, Payload LONGTEXT, LastUpdated DATETIME(3)) ENGINE=InnoDB');
        await pool.query("INSERT INTO MicrosoftTenants VALUES (1, 'tenant-a'), (2, 'tenant-b')");
        await pool.query('INSERT INTO CompanyMicrosoftMapping VALUES (1, 1, 1)');
        const from = source.indexOf('async function writeVerifiedEmailDashboard');
        const to = source.indexOf('function hasCompleteSecurityDashboard', from);
        const writeEmail = vm.runInNewContext(source.slice(from, to) + '\nwriteVerifiedEmailDashboard;', {
            pool, hasEmailDashboardState, mergeVerifiedEmailSources, readEmailReportRefreshDate,
            withCollectionPublication, parseReportJson: (payload, fallback) => payload ? JSON.parse(payload) : fallback,
            crypto: { randomUUID }, logRuntimeOperation() {}
        });
        const email = (tenant, status) => ({ success: true, summary: { activeThreats: status === 'complete' ? 3 : 0 },
            sourceAudit: { sourceTenantId: tenant, alertsComplete: status === 'complete', sourceOutcomes: { alerts: { status } } } });
        const write = (tenant, status, minute) => runWithCollectionOwnership(pool, { ...scope, tenantId: tenant, ttlMs: 10000 },
            () => writeEmail(1, email(tenant, status), new Date(`2026-11-25T10:${minute}:00Z`)));
        const read = async () => {
            const [[row]] = await pool.query('SELECT Payload FROM EmailSecurityPayloadCache WHERE CompanyID = 1');
            return JSON.parse(row.Payload);
        };
        await write('tenant-a', 'complete', '00');
        await write('tenant-a', 'failed', '01');
        const retained = await read();
        assert.equal(retained.summary.activeThreats, 3);
        assert.equal(retained.sourceAudit.cacheSequence, 2);
        assert.equal(retained.sourceAudit.sourceOutcomes.alerts.status, 'failed');
        await write('tenant-a', 'failed', '02');
        assert.equal((await read()).sourceAudit.cacheSequence, 2);
        await pool.query('UPDATE CompanyMicrosoftMapping SET MicrosoftTenantID = 2 WHERE CompanyID = 1');
        await assert.rejects(write('tenant-a', 'complete', '03'), { code: 'EMAIL_CACHE_TENANT_MISMATCH' });
        await write('tenant-b', 'failed', '04');
        const isolated = await read();
        assert.equal(isolated.summary.activeThreats, undefined);
        assert.equal(isolated.sourceAudit.alertsComplete, false);
        assert.equal(isolated.sourceAudit.cacheSequence, 3);
        await verifyNetworkPublication(pool);
        await verifyNetworkCollectorRefresh(pool, source);
    } finally {
        await pool?.end();
        if (created) await admin.query('DROP DATABASE ??', [database]);
        await admin.end();
    }
});
