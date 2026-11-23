const { isApiConnectedGovernanceRow, isApiSourcedComplianceControl, isApiSourcedOperationsTask } = require('../services/intelligence/api-evidence-filters');
const { buildGovernanceDashboardPayload } = require('../services/intelligence/governance-dashboard-processor');
const { GOVERNANCE_EVIDENCE_SCHEMA, createGovernanceEvidenceStore, deriveGovernanceEvidence } = require('../services/intelligence/governance-evidence-store');
const { buildComplianceDashboardPayload } = require('../services/intelligence/compliance-dashboard-processor');
const { COMPLIANCE_EVIDENCE_SCHEMA, createComplianceEvidenceStore, deriveComplianceEvidence } = require('../services/intelligence/compliance-evidence-store');
const { buildOperationsDashboardPayload } = require('../services/intelligence/operations-dashboard-processor');
const { OPERATIONS_EVIDENCE_SCHEMA, createOperationsEvidenceStore, deriveOperationsEvidence } = require('../services/intelligence/operations-evidence-store');
const { governanceAdapter, complianceAdapter, operationsAdapter } = require('../services/intelligence/source-adapters');

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const NO_API_EVIDENCE = 'No API-connected evidence rows found after filtering manual evidence.';
const silentLogger = { log() {}, error() {} };

test('governance evidence excludes manual attestation rows from Azure input', () => {
    const payload = buildGovernanceDashboardPayload({
        payload: {
            success: true,
            rows: [
                { area: 'Access review', activity: 'Review users', dataSource: 'Microsoft Graph users', connected: true, status: 'Connected' },
                { area: 'AI review', activity: 'AI policy', dataSource: 'Manual attestation', connected: false, status: 'Manual Review Required' },
                { area: 'MFA audit', activity: 'Identity check', dataSource: 'Microsoft Graph authentication methods', connected: true, status: 'Attention Required' }
            ]
        }
    });
    const evidence = deriveGovernanceEvidence(payload);
    assert.equal(evidence.evidenceRows.length, 2);
    assert.equal(evidence.dashboardMetrics.apiConnectedRows, 2);
    assert.equal(evidence.dashboardMetrics.manualRowsExcluded, 1);
    assert.equal(evidence.omittedRecordCount, 1);
    assert.equal(evidence.isComplete, true);
});

test('compliance evidence excludes manual attestation controls from Azure input', () => {
    const payload = buildComplianceDashboardPayload({
        payload: {
            success: true,
            controls: [
                { name: 'MFA on all accounts', area: 'Identity', insight: '🟢 MFA fully enforced', evidenceData: { total_users: 10 } },
                { name: 'Password manager enforced', area: 'Credentials', insight: '🔴 Credential sprawl risk', evidenceData: { data_source: 'Manual Attestation / Configuration' } }
            ]
        }
    });
    const evidence = deriveComplianceEvidence(payload);
    assert.equal(evidence.evidenceRows.length, 1);
    assert.equal(evidence.dashboardMetrics.apiControls, 1);
    assert.equal(evidence.dashboardMetrics.manualControlsExcluded, 1);
    assert.equal(evidence.isComplete, true);
});

test('compliance persistence stores a short status and preserves the full insight', async () => {
    const insight = 'MFA evidence collected successfully for every account in the current validation scope.';
    let stored;
    const pool = {
        async query(sql, parameters) {
            if (/INSERT INTO StackCTRLComplianceEvidence\s/.test(sql)) stored = parameters;
            return [{ insertId: 501 }];
        }
    };
    const result = await createComplianceEvidenceStore({ pool, logger: silentLogger }).persistProcessedEvidence({
        companyId: 1,
        payload: { success: true, controls: [{
            name: 'MFA on all accounts', area: 'Identity', complianceStatus: 'Compliant',
            insight, evidenceData: { total_users: 10 }
        }] }
    });
    assert.equal(result.isComplete, true);
    assert.equal(stored[7], 'Compliant');
    assert.equal(JSON.parse(stored[8]).insight, insight);
});

test('operations evidence excludes manual configuration tasks such as 1Password from Azure input', () => {
    const payload = buildOperationsDashboardPayload({
        payload: {
            success: true,
            tasks: [
                { task: 'Complete MFA rollout', area: 'Identity', priority: 'High', dataSource: 'Microsoft Graph authentication methods' },
                { task: 'Deploy 1Password', area: 'Credentials', priority: 'High', dataSource: 'Manual configuration review' },
                { task: 'Enable DNS filtering', area: 'Network', priority: 'High', dataSource: 'Manual configuration review' }
            ]
        }
    });
    const evidence = deriveOperationsEvidence(payload);
    assert.equal(evidence.evidenceRows.length, 1);
    assert.equal(evidence.dashboardMetrics.apiTasks, 1);
    assert.equal(evidence.dashboardMetrics.manualTasksExcluded, 2);
    assert.equal(evidence.isComplete, true);
});

test('api evidence filters identify manual-only records', () => {
    assert.equal(isApiConnectedGovernanceRow({ connected: true, dataSource: 'Microsoft Graph users' }), true);
    assert.equal(isApiConnectedGovernanceRow({ connected: false, dataSource: 'Manual attestation' }), false);
    assert.equal(isApiSourcedComplianceControl({ evidenceData: { data_source: 'Manual Attestation / Configuration' } }), false);
    assert.equal(isApiSourcedOperationsTask({ dataSource: 'Manual configuration review' }), false);
    assert.equal(isApiSourcedOperationsTask({ dataSource: 'Microsoft Graph sign-in logs' }), true);
});

test('manual-only dashboard payloads create explicit blocked evidence results', () => {
    const cases = [
        deriveGovernanceEvidence(buildGovernanceDashboardPayload({ payload: { success: true, rows: [{ area: 'AI', activity: 'Policy', dataSource: 'Manual attestation', connected: false }] } })),
        deriveComplianceEvidence(buildComplianceDashboardPayload({ payload: { success: true, controls: [{ name: 'Policy', area: 'Governance', evidenceData: { data_source: 'Manual Attestation / Configuration' } }] } })),
        deriveOperationsEvidence(buildOperationsDashboardPayload({ payload: { success: true, tasks: [{ task: 'Deploy password manager', area: 'Credentials', dataSource: 'Manual configuration review' }] } }))
    ];

    for (const evidence of cases) {
        assert.equal(evidence.evidenceRows.length, 0);
        assert.equal(evidence.isComplete, false);
        assert.equal(evidence.collectionStatus, 'blocked');
        assert.equal(evidence.incompleteReason, NO_API_EVIDENCE);
        assert.equal(evidence.completenessPercent, 0);
    }
});

test('stores persist manual-only snapshots as blocked with counts and ErrorMessage', async () => {
    const cases = [
        {
            createStore: createGovernanceEvidenceStore,
            payload: buildGovernanceDashboardPayload({ payload: { success: true, rows: [{ area: 'AI', activity: 'Policy', dataSource: 'Manual attestation', connected: false }] } }),
            total: 1
        },
        {
            createStore: createComplianceEvidenceStore,
            payload: buildComplianceDashboardPayload({ payload: { success: true, controls: [{ name: 'Policy', area: 'Governance', evidenceData: { data_source: 'Manual Attestation / Configuration' } }] } }),
            total: 1
        },
        {
            createStore: createOperationsEvidenceStore,
            payload: buildOperationsDashboardPayload({ payload: { success: true, tasks: [{ task: 'Deploy password manager', area: 'Credentials', dataSource: 'Manual configuration review' }] } }),
            total: 1
        }
    ];

    for (const item of cases) {
        const calls = [];
        const pool = {
            async query(sql, params = []) {
                calls.push({ sql, params });
                assert.equal((sql.match(/\?/g) || []).length, params.length);
                return [{ insertId: 501 }];
            }
        };
        const result = await item.createStore({ pool, logger: silentLogger }).persistProcessedEvidence({
            companyId: 1,
            payload: item.payload,
            collectionTrigger: 'dashboard_request'
        });
        const snapshotInsert = calls.find(call => /INSERT INTO StackCTRL.*EvidenceSnapshots/.test(call.sql));
        const sourceAudit = JSON.parse(snapshotInsert.params.find(value => typeof value === 'string' && value.includes('apiConnectedRowsKept')));

        assert.equal(result.snapshotId, 501);
        assert.equal(result.collectionStatus, 'blocked');
        assert.equal(result.isComplete, false);
        assert.equal(result.errorMessage, NO_API_EVIDENCE);
        assert.equal(snapshotInsert.params[4], 'blocked');
        assert.equal(snapshotInsert.params[5], 0);
        assert.equal(snapshotInsert.params.at(-1), NO_API_EVIDENCE);
        assert.equal(sourceAudit.sourcePayloadRowCount, item.total);
        assert.equal(sourceAudit.apiConnectedRowsKept, 0);
        assert.equal(sourceAudit.manualRowsExcluded, item.total);
        assert.equal(sourceAudit.collectionStatus, 'blocked');
    }
});

test('the six Governance, Compliance, and Operations evidence tables are declared', () => {
    const schema = [...GOVERNANCE_EVIDENCE_SCHEMA, ...COMPLIANCE_EVIDENCE_SCHEMA, ...OPERATIONS_EVIDENCE_SCHEMA].join('\n');
    for (const table of [
        'StackCTRLGovernanceEvidenceSnapshots', 'StackCTRLGovernanceEvidence',
        'StackCTRLComplianceEvidenceSnapshots', 'StackCTRLComplianceEvidence',
        'StackCTRLOperationsEvidenceSnapshots', 'StackCTRLOperationsEvidence'
    ]) assert.match(schema, new RegExp(`CREATE TABLE IF NOT EXISTS ${table} \\(`));
});

test('blocked saved snapshots expose total, API, manual, status, and reason lineage', async () => {
    const cases = [
        { adapter: governanceAdapter, sourceKey: 'governance', displayName: 'Governance', table: 'StackCTRLGovernanceEvidenceSnapshots', counts: { TotalRows: 12, ApiConnectedRows: 0, ManualRowsExcluded: 12 } },
        { adapter: complianceAdapter, sourceKey: 'compliance', displayName: 'Compliance Validation', table: 'StackCTRLComplianceEvidenceSnapshots', counts: { TotalControls: 9, ApiControls: 0, ManualControlsExcluded: 9 } },
        { adapter: operationsAdapter, sourceKey: 'operations', displayName: 'Operations', table: 'StackCTRLOperationsEvidenceSnapshots', counts: { TotalTasks: 7, ApiTasks: 0, ManualTasksExcluded: 7 } }
    ];

    for (const item of cases) {
        const pool = {
            async query(sql) {
                if (sql.includes('CompanyMicrosoftMapping')) return [[{ MicrosoftTenantID: 1 }]];
                if (sql.includes(item.table)) return [[{
                    ID: 77,
                    IsComplete: 0,
                    CollectionStatus: 'blocked',
                    EvidenceRecordCount: 0,
                    OmittedRecordCount: Object.values(item.counts)[2],
                    DashboardMetricsJson: {},
                    IncompleteReason: NO_API_EVIDENCE,
                    ErrorMessage: NO_API_EVIDENCE,
                    ...item.counts
                }]];
                throw new Error(`Unexpected query: ${sql}`);
            }
        };
        const result = await item.adapter({
            pool,
            companyId: 1,
            capability: { sourceKey: item.sourceKey, displayName: item.displayName, profileKey: 'sunbird', refreshMode: 'stored_only', isExpected: true, isEnabled: true, configuration: {} }
        });

        assert.equal(result.status, 'missing');
        assert.equal(result.sourceLineage.totalRows, Object.values(item.counts)[0]);
        assert.equal(result.sourceLineage.apiConnectedRows, 0);
        assert.equal(result.sourceLineage.manualRowsExcluded, Object.values(item.counts)[2]);
        assert.equal(result.sourceLineage.collectionStatus, 'blocked');
        assert.equal(result.sourceLineage.incompleteReason, NO_API_EVIDENCE);
        assert.match(result.warnings[0], /No API-connected evidence rows found/);
    }
});

test('latest complete API-connected snapshots are available to Enterprise adapters', async () => {
    const cases = [
        { adapter: governanceAdapter, sourceKey: 'governance', displayName: 'Governance', snapshotTable: 'StackCTRLGovernanceEvidenceSnapshots', evidenceTable: 'StackCTRLGovernanceEvidence WHERE', evidenceType: 'governanceRows', counts: { TotalRows: 5, ApiConnectedRows: 4, ManualRowsExcluded: 1 } },
        { adapter: complianceAdapter, sourceKey: 'compliance', displayName: 'Compliance Validation', snapshotTable: 'StackCTRLComplianceEvidenceSnapshots', evidenceTable: 'StackCTRLComplianceEvidence WHERE', evidenceType: 'controls', counts: { TotalControls: 6, ApiControls: 4, ManualControlsExcluded: 2 } },
        { adapter: operationsAdapter, sourceKey: 'operations', displayName: 'Operations', snapshotTable: 'StackCTRLOperationsEvidenceSnapshots', evidenceTable: 'StackCTRLOperationsEvidence WHERE', evidenceType: 'tasks', counts: { TotalTasks: 3, ApiTasks: 2, ManualTasksExcluded: 1 } }
    ];

    for (const item of cases) {
        const apiRows = Object.values(item.counts)[1];
        const evidenceRows = Array.from({ length: apiRows }, (_, index) => ({ ID: index + 1, ProcessedEvidenceJson: { id: index + 1 } }));
        const pool = {
            async query(sql) {
                if (sql.includes('CompanyMicrosoftMapping')) return [[{ MicrosoftTenantID: 1 }]];
                if (sql.includes(item.snapshotTable)) return [[{
                    ID: 88,
                    IsComplete: 1,
                    CollectionStatus: 'complete',
                    CollectedAt: new Date().toISOString(),
                    EvidenceRecordCount: apiRows,
                    OmittedRecordCount: Object.values(item.counts)[2],
                    DashboardMetricsJson: { apiConnectedRows: apiRows },
                    ...item.counts
                }]];
                if (sql.includes(item.evidenceTable)) return [evidenceRows];
                throw new Error(`Unexpected query: ${sql}`);
            }
        };
        const result = await item.adapter({
            pool,
            companyId: 1,
            capability: { sourceKey: item.sourceKey, displayName: item.displayName, profileKey: 'sunbird', refreshMode: 'stored_only', isExpected: true, isEnabled: true, configuration: {} }
        });

        assert.equal(result.status, 'available');
        assert.equal(result.sourceLineage.collectionStatus, 'complete');
        assert.equal(result.sourceLineage.apiConnectedRows, apiRows);
        assert.equal(result.evidence[0].evidenceType, item.evidenceType);
        assert.equal(result.evidence[0].data.length, apiRows);
        assert.deepEqual(result.warnings, []);
    }
});

test('dashboard_request and enterprise_refresh invoke all three evidence collectors', () => {
    const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
    for (const domain of ['Governance', 'Compliance', 'Operations']) {
        assert.match(server, new RegExp(`persist${domain}DashboardEvidence\\(companyId, cached\\.payload, 'dashboard_request'`));
        assert.match(server, new RegExp(`collectAndPersist${domain}Evidence\\(companyId, 'enterprise_refresh'\\)`));
    }
    assert.match(server, /GOVERNANCE_EVIDENCE_COLLECTION_INTERVAL_MS \|\| \(30 \* 60 \* 1000\)/);
    assert.match(server, /COMPLIANCE_EVIDENCE_COLLECTION_INTERVAL_MS \|\| \(30 \* 60 \* 1000\)/);
    assert.match(server, /OPERATIONS_EVIDENCE_COLLECTION_INTERVAL_MS \|\| \(30 \* 60 \* 1000\)/);
});
