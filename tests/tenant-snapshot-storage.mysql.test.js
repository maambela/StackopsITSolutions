const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const mysql = require('mysql2/promise');
const { encodeCanonicalSnapshot } = require('../scripts/canonical-tenant-snapshot-prototype');
const { hydrateTenantSnapshot } = require('../services/intelligence/tenant-snapshot-storage');
const { createStackCTRLIntelligenceService } = require('../services/stackctrl-intelligence');
const { createStackCTRLIntelligenceScheduler } = require('../services/intelligence/scheduler');
const { createEnterpriseIntelligenceService } = require('../services/enterprise-intelligence');
const { createAdminIntelligenceService } = require('../services/admin-intelligence');

test('MySQL 8.4.7 native JSON through production tenant snapshot readers and legacy writer', {
    skip: process.env.STACKCTRL_ISOLATED_MYSQL_TEST !== '1'
}, async t => {
    const options = { host: '127.0.0.1', port: 13387, user: 'root', password: '', timezone: 'Z' };
    const admin = await mysql.createConnection(options);
    const database = 'stackctrl_test_' + randomUUID().replaceAll('-', '');
    let pool;
    let created = false;
    try {
        const [[instance]] = await admin.query('SELECT VERSION() AS version, @@datadir AS dataDir');
        assert.match(instance.dataDir, /[\\/]stackctrl-mysql-test-[a-f0-9]{32}[\\/]data[\\/]?$/i);
        assert.equal(instance.version, '8.4.7');
        await admin.query('CREATE DATABASE ??', [database]);
        created = true;
        pool = mysql.createPool({ ...options, database, connectionLimit: 4 });
        await pool.query(`CREATE TABLE StackCTRLTenantEvidenceSnapshots (
            ID BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, CompanyID BIGINT NOT NULL,
            TenantKey VARCHAR(128) NOT NULL, PeriodStart DATETIME, PeriodEnd DATETIME,
            SnapshotType VARCHAR(80), CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            DataCompletenessScore INT, CreatedByUserID BIGINT, CreatedByEmail VARCHAR(255),
            SourceFreshnessJson JSON, MetricsJson JSON, EvidenceJson JSON, ContextJson JSON,
            KEY company_snapshot (CompanyID, ID), KEY company_time (CompanyID, CreatedAt)
        ) ENGINE=InnoDB`);

        const companyId = 7;
        const tenantKey = 'test-tenant';
        const scope = { companyId, tenantKey };
        const observation = '2026-01-01T00:00:00.000Z';
        const evidence = [{ sourceKey: 'identity', displayName: 'Identity', data: {
            evidenceType: 'users', data: [{ userPrincipalName: 'reader@example.test', note: 'é😀'.repeat(500) }]
        } }];
        const metrics = { identity: { totalUsers: 1 }, stackctrl_risk: { overallRiskScore: 14 } };
        const sourceFreshness = { identity: { status: 'available', lastUpdated: observation } };
        const context = {
            previousIntelligence: [{ ContentJson: { summary: 'Frozen result' } }],
            sources: [{ sourceKey: 'identity', status: 'available', evidence: [evidence[0].data],
                sourceLineage: { sourceFetchedAt: observation, isComplete: true }, metrics: metrics.identity }],
            tenant: scope,
            evidence,
            metrics,
            dataCompleteness: { score: 100 },
            intelligenceSchemaVersion: 3,
            '日本語': { zz: true, a: 'value' }
        };
        const built = { ...scope, periodStart: new Date(observation), periodEnd: new Date(observation),
            sourceFreshness, metrics, evidence, context, sources: [], dataCompletenessScore: 100 };
        const prompts = [];
        const compactWrites = [];
        const snapshotReads = [];
        const analysisPool = {
            async query(sql, params) {
                if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots')) {
                    const result = await pool.query(sql, params);
                    snapshotReads.push(result[0][0]);
                    return result;
                }
                if (sql.includes('INSERT INTO StackCTRLCompactIntelligenceContexts')) {
                    compactWrites.push(params);
                    return [{ insertId: 3 }];
                }
                if (sql.includes('INSERT INTO StackCTRLIntelligenceRuns')) return [{ insertId: 4 }];
                if (sql.includes('SELECT * FROM StackCTRLCompactIntelligenceContexts')) return [[{ CompactContextSizeBytes: 100 }]];
                if (sql.includes('INSERT INTO StackCTRLIntelligencePeriods')) return [{ insertId: 6 }];
                if (sql.includes('SELECT * FROM StackCTRLIntelligencePeriods')) return [[{ ID: 6, Status: 'completed' }]];
                if (sql.includes('UPDATE StackCTRLIntelligenceRuns')) return [{}];
                return [[]];
            }
        };
        const writer = createStackCTRLIntelligenceService({ pool, azureOpenAI: {} });
        const service = createStackCTRLIntelligenceService({ pool: {
            ...analysisPool,
            async getConnection() {
                return { async beginTransaction() {}, async commit() {}, async rollback() {}, release() {},
                    async query() { return [{ insertId: 5 }]; } };
            }
        }, azureOpenAI: {
            async createJsonCompletion(request) {
                prompts.push(request.messages);
                return { data: { executive_summary: { summary: 'Test completion' } } };
            }
        } });

        const manual = await writer.createSnapshotFromBuiltContext({ built, snapshotType: 'manual_test' });
        const scheduled = await writer.createSnapshotFromBuiltContext({ built, snapshotType: 'scheduled_hourly' });
        const [[legacy]] = await pool.query('SELECT * FROM StackCTRLTenantEvidenceSnapshots WHERE ID = ?', [manual.snapshotId]);
        assert.equal(typeof legacy.ContextJson, 'object');
        assert.deepEqual(legacy.ContextJson, context);
        assert.notDeepEqual(Object.keys(legacy.ContextJson), Object.keys(context), 'native JSON normalizes key order');
        assert.equal(Object.hasOwn(legacy.ContextJson, '$stackctrlSnapshotStorage'), false);
        assert.equal(hydrateTenantSnapshot(legacy, scope), legacy);
        const [[scheduledRow]] = await pool.query('SELECT ContextJson FROM StackCTRLTenantEvidenceSnapshots WHERE ID = ?', [scheduled.snapshotId]);
        assert.deepEqual(scheduledRow.ContextJson, legacy.ContextJson);

        // Encode the original object so the marker's order differs from native JSON's key order.
        const encoded = encodeCanonicalSnapshot({ ...legacy, ContextJson: context }, scope);
        const [insert] = await pool.query(`INSERT INTO StackCTRLTenantEvidenceSnapshots
            (CompanyID, TenantKey, SnapshotType, PeriodStart, PeriodEnd, CreatedAt,
             DataCompletenessScore, SourceFreshnessJson, MetricsJson, EvidenceJson, ContextJson)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
            companyId, tenantKey, legacy.SnapshotType, legacy.PeriodStart, legacy.PeriodEnd, legacy.CreatedAt,
            100, JSON.stringify(sourceFreshness), JSON.stringify(metrics), JSON.stringify(evidence), JSON.stringify(encoded.ContextJson)
        ]);
        const canonicalId = insert.insertId;
        const [[canonical]] = await pool.query('SELECT * FROM StackCTRLTenantEvidenceSnapshots WHERE ID = ?', [canonicalId]);
        assert.deepEqual(canonical.EvidenceJson, legacy.EvidenceJson);
        assert.deepEqual(canonical.MetricsJson, legacy.MetricsJson);
        assert.equal(JSON.stringify(hydrateTenantSnapshot(canonical, scope).ContextJson), JSON.stringify(legacy.ContextJson));
        assert.throws(() => hydrateTenantSnapshot(canonical, { ...scope, tenantKey: 'wrong' }), { code: 'TENANT_SNAPSHOT_SCOPE_MISMATCH' });
        await assert.rejects(service.buildCompactContext({ companyId: 8, snapshotId: canonicalId }), /Snapshot not found/);

        const historicalQueries = [];
        const scheduler = createStackCTRLIntelligenceScheduler({ intelligenceService: service, pool: {
            async query(sql, params) {
                if (sql.includes('INSERT INTO StackCTRLIntelligenceHistoricalComparisons')) return [{}];
                historicalQueries.push(sql);
                return pool.query(sql, params);
            }
        } });
        const mixedHistory = await scheduler.getHistoricalSnapshotContext(companyId, canonicalId);
        assert.equal(mixedHistory.comparisons.previous.snapshot.snapshotId, scheduled.snapshotId);
        assert.equal(mixedHistory.comparisons.previous.metricChanges['identity.totalUsers'].change, 0);
        assert.equal(JSON.stringify(mixedHistory.currentSnapshot.context), JSON.stringify(mixedHistory.comparisons.previous.snapshot.context));
        assert.ok(historicalQueries.some(sql => sql.includes('AS EvidenceJson')));
        await assert.rejects(scheduler.getHistoricalSnapshotContext(8, canonicalId), /Current snapshot not found/);

        t.mock.timers.enable({ apis: ['Date'], now: new Date(observation) });
        for (const snapshotId of [manual.snapshotId, canonicalId]) {
            const compact = await service.buildCompactContext({ companyId, snapshotId });
            assert.ok(compact.evidenceIncludedCount > 0);
            await service.analyseSnapshot({ companyId, snapshotId, outputTypes: ['executive_summary'], analysisMode: 'full' });
        }
        assert.deepEqual(prompts[1], prompts[0], 'full AI prompt bytes match across native storage formats');
        const compactContexts = compactWrites.map(params => JSON.parse(params[5]));
        compactContexts[1].fullSnapshotId = manual.snapshotId;
        assert.equal(JSON.stringify(compactContexts[1]), JSON.stringify(compactContexts[0]));
        assert.equal(snapshotReads.find(row => row?.ID === manual.snapshotId).EvidenceJson, null);
        assert.ok(snapshotReads.find(row => row?.ID === canonicalId).EvidenceJson);
        const legacySize = await service.getCompactContext({ companyId, snapshotId: manual.snapshotId });
        const logicalSize = await service.getCompactContext({ companyId, snapshotId: canonicalId });
        assert.deepEqual(logicalSize, legacySize, 'metadata-only compact size and reduction match');

        const readsBeforePeriod = snapshotReads.length;
        for (const snapshotId of [manual.snapshotId, canonicalId]) {
            const period = await service.runPeriodIntelligence({ companyId, periodType: 'daily',
                referenceDate: new Date(observation), snapshotId, outputTypes: ['executive_summary'] });
            assert.equal(period.period.Status, 'completed');
            assert.ok(period.compactContext.evidenceIncludedCount > 0);
        }
        assert.equal(snapshotReads.length - readsBeforePeriod, 2, 'each period run reads its snapshot once');
        assert.equal(prompts[3][1].content.replace(`"fullSnapshotId":${canonicalId}`, `"fullSnapshotId":${manual.snapshotId}`),
            prompts[2][1].content);

        const projectedRows = [];
        const enterprise = createEnterpriseIntelligenceService({ azureOpenAI: {}, schedulerService: scheduler, pool: {
            async query(sql, params) {
                const result = await pool.query(sql, params);
                projectedRows.push(result[0][0]);
                return result;
            }
        } });
        const raw = await enterprise.getPowerBIRaw(companyId);
        assert.equal(raw.snapshotId, canonicalId);
        assert.deepEqual(raw.rawStackCTRLData, { metrics: legacy.MetricsJson, sources: legacy.ContextJson.sources });
        await assert.rejects(enterprise.getPowerBIRaw(8), { statusCode: 404 });

        const [sizes] = await pool.query(`SELECT ID,
            JSON_STORAGE_SIZE(ContextJson) AS contextStorage, JSON_STORAGE_SIZE(EvidenceJson) AS evidenceStorage,
            JSON_STORAGE_SIZE(MetricsJson) AS metricsStorage,
            OCTET_LENGTH(ContextJson) AS contextText, OCTET_LENGTH(EvidenceJson) AS evidenceText,
            OCTET_LENGTH(MetricsJson) AS metricsText
            FROM StackCTRLTenantEvidenceSnapshots WHERE ID IN (?) ORDER BY ID`, [[manual.snapshotId, canonicalId]]);
        assert.ok(sizes[1].contextStorage < sizes[0].contextStorage);
        assert.equal(sizes[1].evidenceStorage, sizes[0].evidenceStorage);
        assert.equal(sizes[1].metricsStorage, sizes[0].metricsStorage);
        assert.ok(projectedRows[0].EvidenceJson != null);
        const adminService = createAdminIntelligenceService({ azureOpenAI: {}, intelligenceService: service,
            schedulerService: scheduler, pool: { async query(sql, params) {
                if (sql.includes('FROM Companies WHERE ID')) return [[{ ID: companyId, CompanyName: 'Local fixture' }]];
                if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots')) return pool.query(sql, params);
                if (sql.includes('FROM StackCTRLCompactIntelligenceContexts') && !sql.includes('COUNT(')) {
                    return [[{ CompactContextSizeBytes: 100 }]];
                }
                return [[]];
            } } });
        const adminView = await adminService.getTenant(companyId);
        assert.equal(adminView.latestSnapshot.ContextSizeBytes, sizes[1].contextText);
        assert.equal(adminView.compactContexts[0].FullContextSizeBytes, sizes[0].contextText);
        assert.ok(!Object.hasOwn(adminView.latestSnapshot, 'LogicalContextSizeBytes'));
        t.diagnostic(JSON.stringify({ mysql: instance.version, nativeSizes: sizes }));

        await pool.query("UPDATE StackCTRLTenantEvidenceSnapshots SET MetricsJson = JSON_ARRAY() WHERE ID = ?", [canonicalId]);
        await assert.rejects(enterprise.getPowerBIRaw(companyId), { code: 'TENANT_SNAPSHOT_MISSING_METRICS' });
        await pool.query('UPDATE StackCTRLTenantEvidenceSnapshots SET MetricsJson = ? WHERE ID = ?', [JSON.stringify(metrics), canonicalId]);
        await pool.query('UPDATE StackCTRLTenantEvidenceSnapshots SET EvidenceJson = NULL WHERE ID = ?', [canonicalId]);
        await assert.rejects(enterprise.getPowerBIRaw(companyId), { code: 'TENANT_SNAPSHOT_MISSING_EVIDENCE' });
        await pool.query(`UPDATE StackCTRLTenantEvidenceSnapshots
            SET ContextJson = JSON_SET(ContextJson, '$."$stackctrlSnapshotStorage".version', 2) WHERE ID = ?`, [canonicalId]);
        await assert.rejects(service.buildCompactContext({ companyId, snapshotId: canonicalId }), { code: 'TENANT_SNAPSHOT_UNSUPPORTED_VERSION' });
        await pool.query(`UPDATE StackCTRLTenantEvidenceSnapshots
            SET ContextJson = JSON_SET(ContextJson, '$."$stackctrlSnapshotStorage"', NULL) WHERE ID = ?`, [canonicalId]);
        await assert.rejects(scheduler.getHistoricalSnapshotContext(companyId, canonicalId), { code: 'TENANT_SNAPSHOT_INVALID_MARKER' });
    } finally {
        try {
            await pool?.end();
            if (created) await admin.query('DROP DATABASE ??', [database]);
        } finally {
            await admin.end();
        }
    }
});
