const test = require('node:test');
const assert = require('node:assert/strict');

const {
    EMAIL_EVIDENCE_SCHEMA,
    createEmailEvidenceStore,
    deriveEmailEvidence
} = require('../services/intelligence/email-evidence-store');
const {
    DEFAULT_EMAIL_EVIDENCE_INTERVAL_MS,
    createEmailEvidenceAutomation
} = require('../services/intelligence/email-evidence-automation');
const { buildEmailDashboardPayload } = require('../services/intelligence/email-dashboard-processor');

const NOW = new Date('2026-06-23T08:00:00.000Z');

function emailDashboardPayload() {
    const alerts = [
        ...Array.from({ length: 6 }, (_, index) => ({
            id: `alert-${index + 1}`,
            title: index === 0 ? 'Phishing attempt detected' : `Email threat ${index + 1}`,
            description: index === 0 ? 'Suspicious phishing link' : 'Suspicious email activity',
            severity: 'low',
            status: 'newalert',
            userStates: [{ accountName: index % 2 === 0 ? 'ryan' : 'gary' }]
        }))
    ];
    const incidents = [];
    const mailUsers = Array.from({ length: 36 }, (_, index) => ({
        userPrincipalName: `user${index + 1}@example.com`,
        sendCount: index < 10 ? 143 : 0,
        receiveCount: index < 10 ? 476 : 0,
        readCount: index < 10 ? 568 : 0,
        lastActivityDate: index < 30 ? '2026-06-22' : null
    }));
    return buildEmailDashboardPayload({
        tenantKey: 'sunbird',
        payload: {
            success: true,
            fetchedAt: NOW.toISOString(),
            sourceAudit: { alertsComplete: true, incidentsComplete: true, mailActivityOk: true },
            summary: {
                activeThreats: 6,
                highSeverityAlerts: 0,
                affectedUsersCount: 8,
                activeIncidents: 0,
                securityScore: 88,
                threatResolutionRate: 0,
                mailActivity: {
                    activeMailboxes: 36,
                    sendCount: 1430,
                    receiveCount: 4759,
                    readCount: 5678,
                    totalMailActivity: 11867
                }
            },
            alerts,
            incidents,
            affectedUsers: {
                all: ['ryan', 'gary', 'dave', 'notifications', 'marketing', 'alex', 'sam', 'lee'],
                mostTargeted: [
                    { user: 'ryan', threatCount: 6 },
                    { user: 'gary', threatCount: 4 }
                ]
            },
            mailActivity: {
                users: mailUsers,
                summary: {
                    activeMailboxes: 36,
                    sendCount: 1430,
                    receiveCount: 4759,
                    readCount: 5678,
                    totalMailActivity: 11867
                }
            },
            threats: {
                byType: { Phishing: 1, Other: 5 },
                bySeverity: { high: 0, medium: 0, low: 6 }
            }
        },
        now: () => NOW
    });
}

test('saved Email evidence metrics match the visible dashboard email model', () => {
    const payload = emailDashboardPayload();
    const evidence = deriveEmailEvidence(payload);
    assert.equal(evidence.dashboardMetrics.activeThreats, 6);
    assert.equal(evidence.dashboardMetrics.highSeverityAlerts, 0);
    assert.equal(evidence.dashboardMetrics.affectedUsersCount, 8);
    assert.equal(evidence.dashboardMetrics.securityScore, 88);
    assert.equal(evidence.dashboardMetrics.phishingCount, 1);
    assert.equal(evidence.dashboardMetrics.activeMailboxes, 36);
    assert.equal(evidence.dashboardMetrics.totalMailActivity, 11867);
    assert.equal(evidence.evidenceRows.length, 6 + 36);
    assert.equal(evidence.isComplete, true);
});

test('an incomplete threat collection is saved for diagnostics without becoming a verified Email snapshot', () => {
    const payload = emailDashboardPayload();
    payload.sourceAudit.alertsComplete = false;
    const evidence = deriveEmailEvidence(payload);
    assert.equal(evidence.isComplete, false);
    assert.ok(evidence.evidenceRows.length > 0);
});

test('Email evidence derivation accepts object-shaped alerts payloads', () => {
    const evidence = deriveEmailEvidence({
        success: true,
        fetchedAt: NOW.toISOString(),
        alerts: {
            alerts: [{
                id: 'alert-object-1',
                title: 'Phishing email detected',
                severity: 'high',
                status: 'newalert',
                userStates: [{ accountName: 'user@example.com' }]
            }]
        },
        incidents: [],
        mailActivity: { users: [], summary: {} },
        affectedUsers: { all: ['user@example.com'] }
    });

    assert.equal(evidence.dashboardMetrics.activeThreats, 1);
    assert.equal(evidence.dashboardMetrics.highSeverityAlerts, 1);
    assert.equal(evidence.dashboardMetrics.phishingCount, 1);
    assert.equal(evidence.evidenceRows.length, 1);
});

test('Email evidence storage writes one readable row per alert, incident, and mailbox activity record', async () => {
    const calls = [];
    const connection = {
        async beginTransaction() { calls.push({ sql: 'BEGIN', params: [] }); },
        async commit() { calls.push({ sql: 'COMMIT', params: [] }); },
        async rollback() { calls.push({ sql: 'ROLLBACK', params: [] }); },
        release() {},
        async query(sql, params = []) {
            calls.push({ sql, params });
            if (sql.includes('INSERT INTO StackCTRLEmailEvidenceSnapshots')) return [{ insertId: 901 }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const pool = {
        async query() { return [{ affectedRows: 0 }, []]; },
        async getConnection() { return connection; }
    };
    const store = createEmailEvidenceStore({
        pool,
        logger: { log() {} },
        now: () => NOW
    });
    const payload = emailDashboardPayload();
    const result = await store.persistProcessedEvidence({
        companyId: 1,
        tenantKey: 'sunbird',
        payload,
        collectionTrigger: 'scheduled_hourly'
    });
    const snapshotWrite = calls.find(call => call.sql.includes('INSERT INTO StackCTRLEmailEvidenceSnapshots'));
    const evidenceWrites = calls.filter(call => /INSERT INTO StackCTRLEmailEvidence\s*\(/i.test(call.sql));
    assert.equal(result.snapshotId, 901);
    assert.equal(result.recordCount, 42);
    assert.equal(evidenceWrites.length, 42);
    assert.equal(snapshotWrite.params[8], 42);
    assert.equal(snapshotWrite.params[12], 6);
    assert.equal(snapshotWrite.params[13], 0);
    assert.equal(snapshotWrite.params[14], 8);
    assert.equal(snapshotWrite.params[22], 36);
    assert.equal(snapshotWrite.params[23], 11867);
});

test('Email evidence schema uses explicit snapshot and evidence fields', () => {
    const schema = EMAIL_EVIDENCE_SCHEMA.join('\n');
    assert.match(schema, /StackCTRLEmailEvidenceSnapshots/);
    assert.match(schema, /StackCTRLEmailEvidence/);
    assert.match(schema, /SecurityScore/);
    assert.match(schema, /ProcessedEvidenceJson/);
});

test('Email evidence automation runs on a 60-minute interval by default', async () => {
    let runs = 0;
    const automation = createEmailEvidenceAutomation({
        collectAll: async () => { runs += 1; return { ok: true }; },
        intervalMs: DEFAULT_EMAIL_EVIDENCE_INTERVAL_MS,
        startupDelayMs: 0
    });
    automation.start();
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(runs, 1);
    automation.stop();
});
