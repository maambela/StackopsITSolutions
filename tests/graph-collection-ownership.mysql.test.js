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

test('isolated MySQL serializes claims, fences old writers and rolls back failed publication', {
    skip: process.env.STACKCTRL_ISOLATED_MYSQL_TEST !== '1'
}, async () => {
    // This test only targets the explicitly started disposable local instance.
    const connectionOptions = { host: '127.0.0.1', port: 13387, user: 'root', password: '' };
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
    } finally {
        await pool?.end();
        if (created) await admin.query('DROP DATABASE ??', [database]);
        await admin.end();
    }
});
