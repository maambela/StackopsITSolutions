const crypto = require('crypto');
const { buildComplianceDashboardSource } = require('./compliance-dashboard-source');
const { buildRiskEngine } = require('./risk-engine');

const COMPLIANCE_EVIDENCE_SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRLComplianceEvidenceSnapshots (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        CompanyID BIGINT NOT NULL,
        TenantKey VARCHAR(100) NOT NULL,
        CollectionTrigger VARCHAR(50) NOT NULL,
        SourceSystem VARCHAR(100) NOT NULL DEFAULT 'Microsoft Graph via StackCTRL',
        SourceEndpoint VARCHAR(255) NOT NULL,
        CollectionStatus VARCHAR(30) NOT NULL,
        IsComplete TINYINT(1) NOT NULL DEFAULT 0,
        CollectedAt DATETIME(3) NOT NULL,
        SourceFetchedAt DATETIME(3) NULL,
        EvidenceRecordCount INT NOT NULL DEFAULT 0,
        ExpectedRecordCount INT NOT NULL DEFAULT 0,
        OmittedRecordCount INT NOT NULL DEFAULT 0,
        CompletenessPercent DECIMAL(6,2) NOT NULL DEFAULT 0,
        TotalControls INT NOT NULL DEFAULT 0,
        ApiControls INT NOT NULL DEFAULT 0,
        ManualControlsExcluded INT NOT NULL DEFAULT 0,
        FailingControls INT NOT NULL DEFAULT 0,
        PartialControls INT NOT NULL DEFAULT 0,
        PassingControls INT NOT NULL DEFAULT 0,
        ComplianceScore DECIMAL(6,2) NOT NULL DEFAULT 0,
        RecommendationsCount INT NOT NULL DEFAULT 0,
        StackCTRLRiskScore DECIMAL(6,2) NULL,
        StackCTRLHealthScore DECIMAL(6,2) NULL,
        DashboardMetricsJson JSON NOT NULL,
        SourceAuditJson JSON NULL,
        EvidenceSha256 CHAR(64) NULL,
        IncompleteReason TEXT NULL,
        ErrorMessage TEXT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        KEY ix_compliance_evidence_latest (CompanyID, IsComplete, CollectedAt, ID),
        KEY ix_compliance_evidence_status (CollectionStatus, CollectedAt)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRLComplianceEvidence (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        SnapshotID BIGINT UNSIGNED NOT NULL,
        CompanyID BIGINT NOT NULL,
        TenantKey VARCHAR(100) NOT NULL,
        EvidenceKind VARCHAR(30) NOT NULL,
        SourceID VARCHAR(255) NULL,
        Title VARCHAR(500) NOT NULL,
        Area VARCHAR(100) NULL,
        Status VARCHAR(50) NULL,
        ProcessedEvidenceJson JSON NOT NULL,
        CollectedAt DATETIME(3) NOT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        UNIQUE KEY uq_compliance_evidence_snapshot_source (SnapshotID, EvidenceKind, SourceID),
        KEY ix_compliance_evidence_snapshot (SnapshotID, ID),
        CONSTRAINT fk_compliance_evidence_snapshot
            FOREIGN KEY (SnapshotID) REFERENCES StackCTRLComplianceEvidenceSnapshots(ID)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

function mysqlDateTime(value) {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return date.toISOString().slice(0, 19).replace('T', ' ');
}

function complianceSourceId(control, index) {
    return String(`${control.area || 'area'}:${control.name || 'control'}`).slice(0, 255) || `control-${index + 1}`;
}

function deriveComplianceEvidence(payload = {}) {
    const dashboardSource = buildComplianceDashboardSource({
        controls: payload.controls || [],
        summary: payload.summary || payload.dashboardMetrics || {}
    });
    const metrics = dashboardSource.dashboardMetrics;
    const riskEngine = buildRiskEngine({
        sources: [{ sourceKey: 'compliance', status: 'available', isExpected: true, metrics, dashboardMetrics: metrics }],
        dataCompleteness: { score: 100 }
    });
    const stackctrlHealthScore = riskEngine.domainHealthScores.compliance;
    const stackctrlRiskScore = riskEngine.domainRiskScores.compliance;
    const dashboardMetrics = { ...metrics, stackctrlRiskScore, stackctrlHealthScore };
    const evidenceRows = dashboardSource.controls.map((control, index) => ({
        kind: 'control',
        sourceId: complianceSourceId(control, index),
        title: String(control.name || 'Compliance control').slice(0, 500),
        area: control.area || null,
        status: String(control.complianceStatus || 'unknown').slice(0, 50),
        processed: control
    }));
    const omittedRecordCount = metrics.manualControlsExcluded || 0;
    const sourceSucceeded = payload.success !== false;
    const isComplete = sourceSucceeded && evidenceRows.length > 0;
    const incompleteReason = !sourceSucceeded
        ? 'The processed Compliance Validation dashboard did not complete successfully.'
        : evidenceRows.length === 0
            ? 'No API-connected evidence rows found after filtering manual evidence.'
            : null;
    return {
        evidenceRows,
        dashboardMetrics,
        stackctrlRiskScore,
        stackctrlHealthScore,
        expectedRecordCount: evidenceRows.length,
        omittedRecordCount,
        completenessPercent: isComplete ? 100 : 0,
        isComplete,
        collectionStatus: isComplete ? 'complete' : 'blocked',
        incompleteReason
    };
}

function createComplianceEvidenceStore({ pool, logger = console, now = () => new Date() } = {}) {
    if (!pool?.query) throw new Error('Compliance evidence storage requires a database pool');
    async function ensureSchema() {
        for (const statement of COMPLIANCE_EVIDENCE_SCHEMA) await pool.query(statement);
        logger.log('[Compliance Evidence] Schema ready: StackCTRLComplianceEvidenceSnapshots, StackCTRLComplianceEvidence');
        return { tables: ['StackCTRLComplianceEvidenceSnapshots', 'StackCTRLComplianceEvidence'] };
    }
    async function persistProcessedEvidence({ companyId, tenantKey = 'sunbird', payload, collectionTrigger = 'scheduled_daily', sourceEndpoint = 'Microsoft Graph processed by StackCTRL Compliance Validation' } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        const evidence = deriveComplianceEvidence(payload);
        const collectedAt = now();
        logger.log('[Compliance Evidence] Preparing snapshot', {
            companyId: numericCompanyId,
            collectionTrigger,
            sourcePayloadRowCount: evidence.dashboardMetrics.totalControls,
            apiConnectedRowsKept: evidence.evidenceRows.length,
            manualRowsExcluded: evidence.omittedRecordCount,
            collectionStatus: evidence.collectionStatus,
            incompleteReason: evidence.incompleteReason
        });
        const connection = typeof pool.getConnection === 'function' ? await pool.getConnection() : pool;
        const ownsConnection = connection !== pool;
        let snapshotId = null;
        try {
            if (typeof connection.beginTransaction === 'function') await connection.beginTransaction();
            const metrics = evidence.dashboardMetrics;
            const [snapshotResult] = await connection.query(
                `INSERT INTO StackCTRLComplianceEvidenceSnapshots
                 (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete,
                  CollectedAt, SourceFetchedAt, EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount,
                  CompletenessPercent, TotalControls, ApiControls, ManualControlsExcluded, FailingControls,
                  PartialControls, PassingControls, ComplianceScore, RecommendationsCount,
                  StackCTRLRiskScore, StackCTRLHealthScore, DashboardMetricsJson, SourceAuditJson,
                  EvidenceSha256, IncompleteReason, ErrorMessage)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    numericCompanyId, tenantKey, collectionTrigger, sourceEndpoint,
                    evidence.collectionStatus, evidence.isComplete ? 1 : 0,
                    mysqlDateTime(collectedAt), mysqlDateTime(payload?.fetchedAt || collectedAt),
                    evidence.evidenceRows.length, evidence.expectedRecordCount, evidence.omittedRecordCount, evidence.completenessPercent,
                    metrics.totalControls, metrics.apiControls, metrics.manualControlsExcluded, metrics.failingControls,
                    metrics.partialControls, metrics.passingControls, metrics.complianceScore, metrics.recommendationsCount,
                    evidence.stackctrlRiskScore, evidence.stackctrlHealthScore, JSON.stringify(metrics),
                    JSON.stringify({ source: 'stackctrl_processed_compliance_dashboard', collectionTrigger, sourceEndpoint, sourcePayloadRowCount: metrics.totalControls, apiConnectedRowsKept: evidence.evidenceRows.length, manualRowsExcluded: evidence.omittedRecordCount, collectionStatus: evidence.collectionStatus, isComplete: evidence.isComplete, incompleteReason: evidence.incompleteReason, credentialSource: 'environment' }),
                    crypto.createHash('sha256').update(JSON.stringify({ rows: evidence.evidenceRows, dashboardMetrics: metrics })).digest('hex'),
                    evidence.incompleteReason,
                    evidence.incompleteReason
                ]
            );
            snapshotId = snapshotResult.insertId;
            for (const row of evidence.evidenceRows) {
                await connection.query(
                    `INSERT INTO StackCTRLComplianceEvidence
                     (SnapshotID, CompanyID, TenantKey, EvidenceKind, SourceID, Title, Area, Status, ProcessedEvidenceJson, CollectedAt)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [snapshotId, numericCompanyId, tenantKey, row.kind, row.sourceId, row.title, row.area, row.status, JSON.stringify(row.processed), mysqlDateTime(collectedAt)]
                );
            }
            if (typeof connection.commit === 'function') await connection.commit();
        } catch (error) {
            if (typeof connection.rollback === 'function') await connection.rollback();
            throw error;
        } finally {
            if (ownsConnection && typeof connection.release === 'function') connection.release();
        }
        logger.log('[Compliance Evidence] Snapshot stored', {
            snapshotId,
            companyId: numericCompanyId,
            sourcePayloadRowCount: evidence.dashboardMetrics.totalControls,
            apiConnectedRowsKept: evidence.evidenceRows.length,
            manualRowsExcluded: evidence.omittedRecordCount,
            collectionStatus: evidence.collectionStatus,
            isComplete: evidence.isComplete,
            errorMessage: evidence.incompleteReason
        });
        return { snapshotId, companyId: numericCompanyId, collectedAt: collectedAt.toISOString(), recordCount: evidence.evidenceRows.length, omittedRecordCount: evidence.omittedRecordCount, isComplete: evidence.isComplete, collectionStatus: evidence.collectionStatus, errorMessage: evidence.incompleteReason, dashboardMetrics: evidence.dashboardMetrics };
    }
    async function recordCollectionFailure({ companyId, tenantKey = 'sunbird', collectionTrigger = 'scheduled_daily', sourceEndpoint, error } = {}) {
        const [result] = await pool.query(
            `INSERT INTO StackCTRLComplianceEvidenceSnapshots
             (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete, CollectedAt,
              EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount, CompletenessPercent, DashboardMetricsJson, SourceAuditJson, IncompleteReason, ErrorMessage)
             VALUES (?, ?, ?, ?, 'failed', 0, ?, 0, 0, 0, 0, ?, ?, ?, ?)`,
            [Number(companyId), tenantKey, collectionTrigger, sourceEndpoint || 'Microsoft Graph processed by StackCTRL Compliance Validation', mysqlDateTime(now()), JSON.stringify({}), JSON.stringify({ sourcePayloadRowCount: 0, apiConnectedRowsKept: 0, manualRowsExcluded: 0, collectionStatus: 'failed', isComplete: false, incompleteReason: 'Compliance evidence collection did not complete.', credentialSource: 'environment' }), 'Compliance evidence collection did not complete.', String(error?.message || error).slice(0, 5000)]
        );
        logger.error('[Compliance Evidence] Collection failure stored', { snapshotId: result.insertId, companyId: Number(companyId), collectionTrigger, errorMessage: String(error?.message || error) });
        return { snapshotId: result.insertId, companyId: Number(companyId), status: 'failed' };
    }
    return { ensureSchema, persistProcessedEvidence, recordCollectionFailure, deriveComplianceEvidence };
}

module.exports = { COMPLIANCE_EVIDENCE_SCHEMA, createComplianceEvidenceStore, deriveComplianceEvidence };
