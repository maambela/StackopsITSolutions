const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { performance } = require('node:perf_hooks');
const test = require('node:test');
const express = require('express');
const mysql = require('mysql2/promise');
const { createAdminIntelligenceRouter } = require('../routes/admin-intelligence');
const { createStackCTRLIntelligenceService } = require('../services/stackctrl-intelligence');
const { createStackCTRLIntelligenceScheduler } = require('../services/intelligence/scheduler');
const { measureQuery } = require('../services/intelligence/sql-payload-diagnostics');

test('real MySQL 8.4.7 packet preflight, rollback, pool recovery and schedule update', {
    skip: process.env.STACKCTRL_ISOLATED_MYSQL_TEST !== '1'
}, async t => {
    const options = { host: '127.0.0.1', port: 13387, user: 'root', password: '', timezone: 'Z' };
    const admin = await mysql.createConnection(options);
    const database = 'stackctrl_test_' + randomUUID().replaceAll('-', '');
    const limit = 32 * 1024 ** 2;
    let pool, server, created;
    try {
        const [[instance]] = await admin.query('SELECT VERSION() AS version, @@datadir AS datadir, @@global.max_allowed_packet AS packetLimit');
        assert.match(instance.datadir, /[\\/]stackctrl-mysql-test-[a-f0-9]{32}[\\/]data[\\/]?$/i);
        assert.equal(instance.version, '8.4.7');
        assert.equal(instance.packetLimit, limit);
        await admin.query('CREATE DATABASE ??', [database]);
        created = true;
        pool = mysql.createPool({ ...options, database, connectionLimit: 1 });

        const events = [];
        const log = message => events.push(JSON.parse(message));
        const logger = { info: log, warn: log, error: log };
        const inserts = [];
        const scheduleUpdates = [];
        let metadataLookups = 0;
        pool.on('connection', raw => {
            const write = raw.writePacket;
            raw.writePacket = function (packet) {
                if (packet.buffer[packet.start + 4] === 3) {
                    const prefix = packet.buffer.toString('utf8', packet.start + 5, Math.min(packet.end, packet.start + 77));
                    const size = packet.end - packet.start - 4;
                    if (prefix.startsWith('INSERT INTO StackCTRLTenantEvidenceSnapshots')) inserts.push(size);
                    if (prefix.startsWith('UPDATE StackCTRLIntelligenceScheduleRuns')) scheduleUpdates.push(size);
                    if (prefix.startsWith('SELECT CONNECTION_ID() AS connectionId')) metadataLookups++;
                }
                return write.call(this, packet);
            };
        });
        await pool.query('CREATE TABLE StackCTRLTenantEvidenceSnapshots (' +
            'ID BIGINT AUTO_INCREMENT PRIMARY KEY, CompanyID BIGINT, TenantKey VARCHAR(100), PeriodStart DATETIME, PeriodEnd DATETIME,' +
            'SnapshotType VARCHAR(80), SourceFreshnessJson JSON, MetricsJson JSON, EvidenceJson JSON, ContextJson JSON,' +
            'DataCompletenessScore INT, CreatedByUserID BIGINT, CreatedByEmail VARCHAR(255), CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB');
        await pool.query('CREATE TABLE StackCTRLIntelligenceSourceStatus (' +
            'ID BIGINT AUTO_INCREMENT PRIMARY KEY, CompanyID BIGINT, SnapshotID BIGINT, SourceKey VARCHAR(100), DisplayName VARCHAR(100),' +
            'Status VARCHAR(32), IsExpected INT, LastUpdated DATETIME, AgeMinutes INT, EvidenceCount INT, MetricsJson JSON,' +
            'WarningsJson JSON, RawReferenceJson JSON, ErrorMessage TEXT) ENGINE=InnoDB');
        await pool.query('CREATE TABLE StackCTRLIntelligenceMetrics (' +
            'ID BIGINT AUTO_INCREMENT PRIMARY KEY, CompanyID BIGINT, SnapshotID BIGINT, SourceStatusID BIGINT, SourceKey VARCHAR(100),' +
            'MetricName VARCHAR(150), MetricLabel VARCHAR(180), MetricType VARCHAR(32), NumericValue DOUBLE, TextValue LONGTEXT,' +
            'BooleanValue INT, JsonValue JSON, PeriodStart DATETIME, PeriodEnd DATETIME) ENGINE=InnoDB');
        await pool.query('CREATE TABLE StackCTRLIntelligenceScheduleRuns (' +
            'ID BIGINT AUTO_INCREMENT PRIMARY KEY, CompanyID BIGINT, ScheduleID BIGINT, ScheduleKey VARCHAR(64),' +
            'RunType VARCHAR(32), TriggerType VARCHAR(32), DeduplicationKey VARCHAR(120), ParentRunID BIGINT, RequestedOutputTypes JSON,' +
            'Status VARCHAR(32), CreatedByUserID BIGINT, CreatedByEmail VARCHAR(255), SnapshotID BIGINT, IntelligenceRunID BIGINT,' +
            'CollectionSummaryJson JSON, HistoricalContextJson JSON, ErrorMessage TEXT, CompletedAt DATETIME) ENGINE=InnoDB');

        const secret = 'fixture-secret café 😀 日 " \\\n\u0000';
        function build(bytes) {
            const evidence = [{ sourceKey: 'cloudflare_network_security', data: { note: secret + 'x'.repeat(bytes) } }];
            const source = { sourceKey: 'cloudflare_network_security', displayName: 'Network Security', status: 'available',
                isExpected: true, freshness: { ageMinutes: 0 }, metrics: { total: 16973 }, warnings: [],
                sourceLineage: { evidenceRecordCount: 16973 }, evidence };
            return {
                companyId: 1, tenantKey: 'fixture', sources: [source], sourceFreshness: {}, metrics: {}, evidence,
                context: { evidence, metrics: {}, sources: [source] },
                dataCompletenessScore: 100
            };
        }
        let selected = build(0);
        const writer = createStackCTRLIntelligenceService({ pool, azureOpenAI: {}, logger });
        const app = express();
        app.use('/api/admin/intelligence', createAdminIntelligenceRouter({
            authenticateToken(req, res, next) { req.user = { role: 'admin' }; next(); },
            adminIntelligenceService: { createSnapshot: () => writer.createSnapshotFromBuiltContext({ built: selected }) }
        }));
        server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
        const url = 'http://127.0.0.1:' + server.address().port + '/api/admin/intelligence/tenant/1/snapshot';
        const send = () => fetch(url, { method: 'POST' });
        const ok = await send();
        assert.equal(ok.status, 201);
        assert.equal((await ok.json()).snapshotId, 1);
        const normal = events.find(event => event.event === 'snapshot_sql_payload_measured');
        assert.equal(normal.commandBytes, inserts[0]);
        assert.equal(normal.columns.EvidenceJson.utf8Bytes, Buffer.byteLength(JSON.stringify(selected.evidence)));
        assert.equal(normal.columns.EvidenceJson.escapedBytes, Buffer.byteLength(pool.escape(JSON.stringify(selected.evidence))));
        assert.equal(normal.globalMaxAllowedPacket, limit);
        assert.equal(normal.sessionMaxAllowedPacket, limit);
        assert.equal(normal.headroomBytes, limit - inserts[0]);
        assert.deepEqual(normal.evidenceCounts, { cloudflare_network_security: 16973 });

        for (const size of [12, 22]) {
            selected = build(size * 1024 ** 2);
            const failed = await send();
            const body = await failed.json();
            assert.equal(failed.status, 500);
            assert.equal(body.code, 'SNAPSHOT_SQL_PAYLOAD_TOO_LARGE');
            const event = events.findLast(row => row.event === 'snapshot_sql_payload_exceeds_limit');
            assert.equal(event.requestId, body.requestId);
            assert.ok(event.commandBytes > limit);
            assert.equal(event.protocolHeaderBytes, 4 * (Math.floor(event.commandBytes / 0xffffff) + 1));
            assert.equal(event.wireBytes, event.commandBytes + event.protocolHeaderBytes);
            assert.equal(event.connectionId, normal.connectionId, 'the rejected command keeps the connection healthy');
            t.diagnostic('Rejected ' + event.commandBytes + ' command bytes at a ' + limit + '-byte session limit');
        }
        assert.equal(inserts.length, 1, 'oversized commands were never handed to the driver');
        const [committed] = await pool.query('SELECT ID FROM StackCTRLTenantEvidenceSnapshots');
        assert.deepEqual(committed, [{ ID: 1 }]);

        let schedulePayload = build(0);
        const schedulePool = {
            getConnection: () => pool.getConnection(),
            async query(sql, params) {
                if (sql.startsWith('INSERT INTO StackCTRLIntelligenceSchedules')) return [{}];
                if (sql.includes('SELECT * FROM StackCTRLIntelligenceSchedules')) return [[{ ID: 1, ScheduleKey: 'collection_15m', IsEnabled: 1 }]];
                if (sql.startsWith('UPDATE StackCTRLIntelligenceSchedules')) return [{}];
                return pool.query(sql, params);
            }
        };
        const scheduler = createStackCTRLIntelligenceScheduler({
            pool: schedulePool,
            intelligenceService: { async buildTenantAIContext() { return schedulePayload; } },
            logger: { ...logger, error(message) { if (message.startsWith('{')) log(message); } }
        });
        const tick = async minute => (await scheduler.runScheduledTick({ companyId: 1, now: new Date('2026-11-27T08:' + minute + ':00Z') })).companies[0].runs[0];
        assert.equal((await tick('15')).status, 'completed');
        const scheduleMeasured = events.find(event => event.operation === 'intelligence_schedule_update');
        assert.equal(scheduleMeasured.commandBytes, scheduleUpdates[0]);
        assert.deepEqual(scheduleMeasured.evidenceCounts, { cloudflare_network_security: 16973 });
        schedulePayload = build(17 * 1024 ** 2);
        assert.equal((await tick('30')).status, 'failed');
        const scheduleBlocked = events.findLast(event => event.event === 'snapshot_sql_payload_exceeds_limit');
        assert.equal(scheduleBlocked.operation, 'intelligence_schedule_update');
        assert.ok(scheduleBlocked.commandBytes > limit);
        assert.equal(scheduleUpdates.length, 2, 'only the small failure-status UPDATE follows the successful summary');

        let destroyed = 0;
        let released = 0;
        const failingPool = {
            async getConnection() {
                const connection = await pool.getConnection();
                const commit = connection.commit.bind(connection);
                const destroy = connection.destroy.bind(connection);
                const release = connection.release.bind(connection);
                connection.commit = async () => {
                    await admin.query('KILL CONNECTION ?', [connection.threadId]);
                    return commit();
                };
                connection.destroy = () => { destroyed++; return destroy(); };
                connection.release = () => { released++; return release(); };
                return connection;
            }
        };
        const uncertain = createStackCTRLIntelligenceService({ pool: failingPool, azureOpenAI: {}, logger });
        await assert.rejects(uncertain.createSnapshotFromBuiltContext({ built: build(0) }));
        assert.equal(destroyed, 1);
        assert.equal(released, 0);
        assert.equal(events.find(event => event.operation === 'tenant_snapshot_commit').commitOutcomeUnknown, true);
        const [[recovered]] = await pool.query('SELECT CONNECTION_ID() AS id, COUNT(*) AS count FROM StackCTRLTenantEvidenceSnapshots');
        assert.notEqual(recovered.id, normal.connectionId);
        assert.equal(recovered.count, 1);
        assert.equal(metadataLookups, 6, 'one session probe per measured transaction or schedule write');
        assert.doesNotMatch(JSON.stringify(events), /fixture-secret|INSERT INTO|UPDATE StackCTRL|café/);

        const connection = await pool.getConnection();
        try {
            const values = [JSON.stringify({ note: secret + 'é\\"'.repeat(2 * 1024 ** 2) })];
            const sql = 'SELECT LENGTH(?)';
            const run = callback => {
                const start = performance.now();
                const value = callback();
                return { value, ms: Math.round((performance.now() - start) * 100) / 100 };
            };
            const measured = run(() => measureQuery(connection, sql, values, { Json: 0 }));
            const formatted = run(() => Buffer.byteLength(connection.format(sql, values)) + 1);
            assert.equal(measured.value.commandBytes, formatted.value);
            t.diagnostic(JSON.stringify({ commandBytes: formatted.value, measurementMs: measured.ms, fullFormatMs: formatted.ms }));
        } finally {
            connection.release();
        }
    } finally {
        if (server) await new Promise(resolve => server.close(resolve));
        try {
            await pool?.end();
            if (created) await admin.query('DROP DATABASE ??', [database]);
        } finally {
            await admin.end();
        }
    }
});
