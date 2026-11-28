const test = require('node:test');
const assert = require('node:assert/strict');

const { createStackCTRLIntelligenceScheduler } = require('../services/intelligence/scheduler');

function scheduleRows() {
    return [
        { ID: 1, ScheduleKey: 'collection_15m', IsEnabled: 1 },
        { ID: 2, ScheduleKey: 'snapshot_hourly', IsEnabled: 1 },
        {
            ID: 3,
            ScheduleKey: 'azure_analysis',
            IsEnabled: 1,
            OutputTypesJson: JSON.stringify(['executive_summary', 'trend_analysis'])
        }
    ];
}

test('08:00 weekday tick collects, freezes a snapshot, and analyses it with history', async () => {
    const queries = [];
    const analysisCalls = [];
    let scheduleRunId = 10;
    const currentSnapshot = {
        ID: 100,
        CompanyID: 7,
        SnapshotType: 'scheduled_hourly',
        CreatedAt: new Date('2026-06-22T06:00:00.000Z'),
        DataCompletenessScore: 90,
        MetricsJson: JSON.stringify({ devices: { TotalDevices: 20, NonCompliant: 1 } }),
        ContextJson: JSON.stringify({ tenant: { companyId: 7 }, metrics: { devices: { TotalDevices: 20 } } })
    };
    const previousSnapshot = {
        ID: 99,
        CompanyID: 7,
        SnapshotType: 'scheduled_hourly',
        CreatedAt: new Date('2026-06-19T15:00:00.000Z'),
        DataCompletenessScore: 85,
        MetricsJson: JSON.stringify({ devices: { TotalDevices: 18, NonCompliant: 2 } }),
        ContextJson: JSON.stringify({ tenant: { companyId: 7 }, metrics: { devices: { TotalDevices: 18 } } })
    };
    const pool = {
        async query(sql, params) {
            queries.push({ sql, params });
            if (sql.includes('SELECT * FROM StackCTRLIntelligenceSchedules')) return [scheduleRows(), []];
            if (sql.includes('INSERT INTO StackCTRLIntelligenceScheduleRuns')) return [{ insertId: scheduleRunId++ }, []];
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots') && sql.includes('ContextJson') && sql.includes('WHERE ID = ?')) {
                return [[currentSnapshot], []];
            }
            if (sql.includes('SELECT MAX(previous.ID)')) {
                return [[previousSnapshot], []];
            }
            if (sql.includes('MAX(CASE WHEN CreatedAt <= ?')) return [[{ BeforeTarget: null, AfterTarget: null }], []];
            if (sql.includes('SELECT MetricsJson FROM StackCTRLTenantEvidenceSnapshots') && sql.includes('ID < ?')) {
                return [[{ MetricsJson: previousSnapshot.MetricsJson }], []];
            }
            if (sql.includes('SELECT MetricsJson FROM StackCTRLTenantEvidenceSnapshots') && sql.includes('WHERE ID = ?')) {
                return [[{ MetricsJson: currentSnapshot.MetricsJson }], []];
            }
            return [{ affectedRows: 1 }, []];
        }
    };
    const intelligenceService = {
        async buildTenantAIContext() {
            return {
                dataCompleteness: { score: 90 },
                sources: [{ sourceKey: 'devices', status: 'available', isExpected: true, freshness: {}, warnings: [] }],
                context: { metrics: { devices: { TotalDevices: 20, NonCompliant: 1 } } }
            };
        },
        async createSnapshot() {
            return { snapshotId: 100, dataCompleteness: { score: 90 }, sourceStatuses: [] };
        },
        async analyseSnapshot(options) {
            analysisCalls.push(options);
            return { runId: 900, snapshotId: options.snapshotId, outputIds: { executive_summary: 1 } };
        }
    };
    const scheduler = createStackCTRLIntelligenceScheduler({ pool, intelligenceService });

    const result = await scheduler.runScheduledTick({
        companyId: 7,
        now: new Date('2026-06-22T06:00:00.000Z')
    });

    assert.equal(result.status, 'completed');
    assert.equal(result.companies[0].runs.filter(run => run.status === 'completed').length, 3);
    assert.equal(analysisCalls.length, 1);
    assert.equal(analysisCalls[0].snapshotId, 100);
    assert.equal(analysisCalls[0].historicalContext.currentSnapshot.snapshotId, 100);
    assert.equal(analysisCalls[0].historicalContext.comparisons.previous.snapshot.snapshotId, 99);
    assert.equal(analysisCalls[0].historicalContext.comparisons['24_hours'].availability, 'unavailable');
    assert.ok(queries.some(call => call.sql.includes('StackCTRLIntelligenceHistoricalComparisons')));
    assert.equal(queries.some(call => /ORDER BY\s+ABS\s*\(TIMESTAMPDIFF/i.test(call.sql)), false);
    const historicalAuditWrite = queries.find(call =>
        call.sql.includes('UPDATE StackCTRLIntelligenceScheduleRuns') && call.params?.[4]
    );
    const historicalAudit = JSON.parse(historicalAuditWrite.params[4]);
    assert.ok(historicalAudit.availability);
    assert.ok(historicalAudit.intelligence);
});

test('scheduler tick does no collection outside weekday business hours', async () => {
    let queryCount = 0;
    const scheduler = createStackCTRLIntelligenceScheduler({
        pool: {
            async query() {
                queryCount++;
                return [[], []];
            }
        },
        intelligenceService: {}
    });

    const result = await scheduler.runScheduledTick({
        now: new Date('2026-06-21T06:00:00.000Z')
    });

    assert.equal(result.status, 'outside_business_hours');
    assert.equal(queryCount, 0);
});

test('missing schedule table pauses automation and warns only once', async () => {
    const warnings = [];
    const scheduler = createStackCTRLIntelligenceScheduler({
        pool: {
            async query() {
                const error = new Error("Table 'consultation_db.StackCTRLIntelligenceSchedules' doesn't exist");
                error.code = 'ER_NO_SUCH_TABLE';
                throw error;
            }
        },
        intelligenceService: {},
        logger: { warn(message) { warnings.push(message); }, error() {} }
    });

    const first = await scheduler.runScheduledTick({
        companyId: 1,
        now: new Date('2026-06-22T06:00:00.000Z')
    });
    const second = await scheduler.runScheduledTick({
        companyId: 1,
        now: new Date('2026-06-22T06:15:00.000Z')
    });

    assert.equal(first.status, 'completed');
    assert.deepEqual(first.companies[0].runs, []);
    assert.deepEqual(second.companies[0].runs, []);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /schedule tables are not available/i);
});

test('15-minute collection tick stores data without calling Azure', async () => {
    let analysisCalls = 0;
    let snapshotCalls = 0;
    const pool = {
        async query(sql) {
            if (sql.includes('SELECT * FROM StackCTRLIntelligenceSchedules')) return [scheduleRows(), []];
            if (sql.includes('INSERT INTO StackCTRLIntelligenceScheduleRuns')) return [{ insertId: 40 }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const scheduler = createStackCTRLIntelligenceScheduler({
        pool,
        intelligenceService: {
            async buildTenantAIContext() {
                return {
                    dataCompleteness: { score: 100 },
                    sources: [],
                    context: { metrics: {}, evidence: [] },
                    companyId: 7
                };
            },
            async createSnapshot() { snapshotCalls++; return { snapshotId: 1 }; },
            async analyseSnapshot() { analysisCalls++; return { runId: 1 }; }
        }
    });

    const result = await scheduler.runScheduledTick({
        companyId: 7,
        now: new Date('2026-06-22T06:15:00.000Z')
    });

    assert.equal(result.companies[0].runs.length, 1);
    assert.equal(result.companies[0].runs[0].status, 'completed');
    assert.ok(result.companies[0].runs[0].collection);
    assert.equal(snapshotCalls, 0);
    assert.equal(analysisCalls, 0);
});

test('critical trigger detection covers security, Cloudflare, compliance, and devices', () => {
    const scheduler = createStackCTRLIntelligenceScheduler({
        pool: { query: async () => [[], []] },
        intelligenceService: {}
    });
    const signals = scheduler.findCriticalSignals({
        security_alerts: { highSeverityAlerts: 2, activeIncidents: 1 },
        cloudflare_network_security: { deniedAccessEvents: 25 },
        compliance: { score: 35 },
        devices: { TotalDevices: 20, NonCompliant: 8 }
    }, {
        cloudflare_network_security: { deniedAccessEvents: 5 },
        compliance: { score: 80 },
        devices: { TotalDevices: 20, NonCompliant: 1 }
    });

    assert.deepEqual(new Set(signals.map(signal => signal.eventType)), new Set([
        'critical_security_activity',
        'severe_access_spike',
        'major_compliance_drop',
        'major_device_compliance_drop'
    ]));
});

test('historical context continues in memory when the comparison table is missing', async () => {
    const currentSnapshot = {
        ID: 27,
        CompanyID: 1,
        SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-22T08:00:00.000Z'),
        DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ stackctrl_risk: { overallRiskScore: 30 } }),
        ContextJson: JSON.stringify({ tenant: { companyId: 1 } })
    };
    let comparisonInsertAttempts = 0;
    const warnings = [];
    const scheduler = createStackCTRLIntelligenceScheduler({
        pool: {
            async query(sql) {
                if (sql.includes('WHERE ID = ? AND CompanyID = ?')) return [[currentSnapshot], []];
                if (sql.includes('SELECT MAX(previous.ID)')) return [[], []];
                if (sql.includes('MAX(CASE WHEN CreatedAt <= ?')) return [[{ BeforeTarget: null, AfterTarget: null }], []];
                if (sql.includes('INSERT INTO StackCTRLIntelligenceHistoricalComparisons')) {
                    comparisonInsertAttempts += 1;
                    const error = new Error("Table 'consultation_db.StackCTRLIntelligenceHistoricalComparisons' doesn't exist");
                    error.code = 'ER_NO_SUCH_TABLE';
                    throw error;
                }
                return [[], []];
            }
        },
        intelligenceService: {},
        logger: { warn(message) { warnings.push(message); }, error() {} }
    });

    const context = await scheduler.getHistoricalSnapshotContext(1, 27);
    assert.equal(context.currentSnapshot.snapshotId, 27);
    assert.equal(context.persistence.historicalComparisonsStored, false);
    assert.match(context.persistence.warning, /not installed/i);
    assert.equal(comparisonInsertAttempts, 1);
    assert.equal(warnings.length, 1);
    assert.equal(context.comparisons['24_hours'].availability, 'unavailable');
});
