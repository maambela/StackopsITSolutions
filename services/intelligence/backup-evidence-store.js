const { assertCollectionOwner } = require('./graph-collection-ownership');
const crypto = require('crypto');
const { buildBackupDashboardSource } = require('./backup-dashboard-source');
const { buildRiskEngine } = require('./risk-engine');
const { runAbortableOperation, acquireConnectionWithDeadline, runDatabaseOperationWithDeadline } = require('./collector-runtime');

const BACKUP_EVIDENCE_SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRLBackupEvidenceSnapshots (
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
        TotalStorageGB DECIMAL(12,2) NOT NULL DEFAULT 0,
        OneDriveStorageGB DECIMAL(12,2) NOT NULL DEFAULT 0,
        SharePointStorageGB DECIMAL(12,2) NOT NULL DEFAULT 0,
        ExchangeStorageGB DECIMAL(12,2) NOT NULL DEFAULT 0,
        ActiveUsersCount INT NOT NULL DEFAULT 0,
        InactiveUsersCount INT NOT NULL DEFAULT 0,
        ServicesCovered INT NOT NULL DEFAULT 0,
        InactiveUserStorageGB DECIMAL(12,2) NOT NULL DEFAULT 0,
        BackupCoverageScore DECIMAL(6,2) NOT NULL DEFAULT 0,
        DataExposureRiskScore DECIMAL(6,2) NOT NULL DEFAULT 0,
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
        KEY ix_backup_evidence_latest (CompanyID, IsComplete, CollectedAt, ID),
        KEY ix_backup_evidence_status (CollectionStatus, CollectedAt)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRLBackupEvidence (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        SnapshotID BIGINT UNSIGNED NOT NULL,
        CompanyID BIGINT NOT NULL,
        TenantKey VARCHAR(100) NOT NULL,
        EvidenceKind VARCHAR(30) NOT NULL,
        SourceID VARCHAR(255) NULL,
        Title VARCHAR(500) NOT NULL,
        ServiceName VARCHAR(50) NULL,
        StorageGB DECIMAL(12,2) NOT NULL DEFAULT 0,
        ActivityAgeDays INT NULL,
        ProcessedEvidenceJson JSON NOT NULL,
        CollectedAt DATETIME(3) NOT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        UNIQUE KEY uq_backup_evidence_snapshot_source (SnapshotID, EvidenceKind, SourceID),
        KEY ix_backup_evidence_snapshot (SnapshotID, ID),
        CONSTRAINT fk_backup_evidence_snapshot
            FOREIGN KEY (SnapshotID) REFERENCES StackCTRLBackupEvidenceSnapshots(ID)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

function mysqlDateTime(value) {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return date.toISOString().slice(0, 19).replace('T', ' ');
}

function deriveBackupEvidence(payload = {}) {
    const dashboardSource = buildBackupDashboardSource({ payload });
    const metrics = dashboardSource.dashboardMetrics;
    const riskEngine = buildRiskEngine({
        sources: [{ sourceKey: 'backup', status: 'available', isExpected: true, metrics, dashboardMetrics: metrics }],
        dataCompleteness: { score: 100 }
    });
    const stackctrlHealthScore = riskEngine.domainHealthScores.backup;
    const stackctrlRiskScore = riskEngine.domainRiskScores.backup;
    const dashboardMetrics = { ...metrics, stackctrlRiskScore, stackctrlHealthScore };
    const evidenceRows = dashboardSource.rows.map(row => ({
        kind: row.kind,
        sourceId: row.sourceId,
        title: row.title,
        serviceName: row.service,
        storageGB: row.storageGB,
        activityAgeDays: row.activityAge,
        processed: row.processed
    }));
    const expectedRecordCount = evidenceRows.length;
    const isComplete = Boolean(payload.success !== false);
    return {
        evidenceRows,
        dashboardMetrics,
        stackctrlRiskScore,
        stackctrlHealthScore,
        expectedRecordCount,
        omittedRecordCount: 0,
        completenessPercent: expectedRecordCount > 0 || isComplete ? 100 : 0,
        isComplete,
        incompleteReason: isComplete ? null : 'The processed Backup and Recovery dashboard did not complete successfully.'
    };
}

function createBackupEvidenceStore({ pool, logger = console, now = () => new Date() } = {}) {
    if (!pool?.query) throw new Error('Backup evidence storage requires a database pool');
    async function ensureSchema() {
        for (const statement of BACKUP_EVIDENCE_SCHEMA) await pool.query(statement);
        return { tables: ['StackCTRLBackupEvidenceSnapshots', 'StackCTRLBackupEvidence'] };
    }
    async function persistProcessedEvidence({ companyId, tenantKey = 'sunbird', payload, collectionTrigger = 'scheduled_6_hour', sourceEndpoint = 'Microsoft Graph processed by StackCTRL Backup and Recovery', signal = null, timeoutMs = 30000 } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        const evidence = deriveBackupEvidence(payload);
        const collectedAt = payload?.collectionStartedAt ? new Date(payload.collectionStartedAt) : now();
        const connection = typeof pool.getConnection === 'function'
            ? await acquireConnectionWithDeadline(pool, { timeoutMs, signal, label: 'Backup evidence database connection' })
            : pool;
        const ownsConnection = connection !== pool;
        const db = (operation, label) => runDatabaseOperationWithDeadline({ connection, operation, timeoutMs, signal, label });
        let snapshotId = null;
        try {
            if (typeof connection.beginTransaction === 'function') await db(() => connection.beginTransaction(), 'Backup evidence transaction begin');
            await assertCollectionOwner(connection, companyId);
            const metrics = evidence.dashboardMetrics;
            const [snapshotResult] = await db(() => connection.query(
                `INSERT INTO StackCTRLBackupEvidenceSnapshots
                 (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete,
                  CollectedAt, SourceFetchedAt, EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount,
                  CompletenessPercent, TotalStorageGB, OneDriveStorageGB, SharePointStorageGB, ExchangeStorageGB,
                  ActiveUsersCount, InactiveUsersCount, ServicesCovered, InactiveUserStorageGB,
                  BackupCoverageScore, DataExposureRiskScore, RecommendationsCount,
                  StackCTRLRiskScore, StackCTRLHealthScore, DashboardMetricsJson, SourceAuditJson,
                  EvidenceSha256, IncompleteReason)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    numericCompanyId, tenantKey, collectionTrigger, sourceEndpoint,
                    evidence.isComplete ? 'complete' : 'incomplete', evidence.isComplete ? 1 : 0,
                    mysqlDateTime(collectedAt), mysqlDateTime(payload?.fetchedAt || collectedAt),
                    evidence.evidenceRows.length, evidence.expectedRecordCount, 0, evidence.completenessPercent,
                    metrics.totalStorageGB, metrics.oneDriveStorageGB, metrics.sharePointStorageGB, metrics.exchangeStorageGB,
                    metrics.activeUsersCount, metrics.inactiveUsersCount, metrics.servicesCovered, metrics.inactiveUserStorageGB,
                    metrics.backupCoverageScore, metrics.dataExposureRiskScore, metrics.recommendationsCount,
                    evidence.stackctrlRiskScore, evidence.stackctrlHealthScore, JSON.stringify(metrics),
                    JSON.stringify({ source: 'stackctrl_processed_backup_dashboard', collectionTrigger, sourceEndpoint, credentialSource: 'environment', credentialPath: 'MICROSOFT_CLIENT_SECRET (Azure Key Vault, shared with dashboard)' }),
                    crypto.createHash('sha256').update(JSON.stringify({ rows: evidence.evidenceRows, dashboardMetrics: metrics })).digest('hex'),
                    evidence.incompleteReason
                ]
            ), 'Backup evidence snapshot insert');
            snapshotId = snapshotResult.insertId;
            for (const row of evidence.evidenceRows) {
                await db(() => connection.query(
                    `INSERT INTO StackCTRLBackupEvidence
                     (SnapshotID, CompanyID, TenantKey, EvidenceKind, SourceID, Title, ServiceName, StorageGB, ActivityAgeDays, ProcessedEvidenceJson, CollectedAt)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [snapshotId, numericCompanyId, tenantKey, row.kind, row.sourceId, row.title, row.serviceName, row.storageGB, row.activityAgeDays, JSON.stringify(row.processed), mysqlDateTime(collectedAt)]
                ), 'Backup evidence row insert');
            }
            await assertCollectionOwner(connection, companyId);
            if (typeof connection.commit === 'function') await db(() => connection.commit(), 'Backup evidence transaction commit');
        } catch (error) {
            if (error?.code !== 'STACKCTRL_OPERATION_TIMEOUT' && typeof connection.rollback === 'function') await db(() => connection.rollback(), 'Backup evidence transaction rollback').catch(() => {});
            throw error;
        } finally {
            if (ownsConnection && typeof connection.release === 'function') connection.release();
        }
        logger.log(`[Backup Evidence] Stored snapshot ${snapshotId} with ${evidence.evidenceRows.length} processed backup records.`);
        return { snapshotId, companyId: numericCompanyId, collectedAt: collectedAt.toISOString(), recordCount: evidence.evidenceRows.length, isComplete: evidence.isComplete, dashboardMetrics: evidence.dashboardMetrics };
    }
    async function recordCollectionFailure({ companyId, tenantKey = 'sunbird', collectionTrigger = 'scheduled_6_hour', sourceEndpoint, error, signal = null, timeoutMs = 30000 } = {}) {
        const connection = typeof pool.getConnection === 'function'
            ? await acquireConnectionWithDeadline(pool, { timeoutMs, signal, label: 'Backup failure database connection' })
            : pool;
        const ownsConnection = connection !== pool;
        try {
            const [result] = await runDatabaseOperationWithDeadline({
                connection,
                timeoutMs,
                signal,
                label: 'Backup failure record insert',
                operation: () => connection.query(
                    `INSERT INTO StackCTRLBackupEvidenceSnapshots
                     (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete, CollectedAt,
                      EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount, CompletenessPercent, DashboardMetricsJson, SourceAuditJson, IncompleteReason, ErrorMessage)
                     VALUES (?, ?, ?, ?, 'failed', 0, ?, 0, 0, 0, 0, ?, ?, ?, ?)`,
                    [Number(companyId), tenantKey, collectionTrigger, sourceEndpoint || 'Microsoft Graph processed by StackCTRL Backup and Recovery', mysqlDateTime(now()), JSON.stringify({}), JSON.stringify({ credentialSource: 'environment' }), 'Backup evidence collection did not complete.', String(error?.message || error).slice(0, 5000)]
                )
            });
            return { snapshotId: result.insertId, companyId: Number(companyId), status: 'failed' };
        } finally {
            if (ownsConnection && typeof connection.release === 'function') connection.release();
        }
    }
    return { ensureSchema, persistProcessedEvidence, recordCollectionFailure, deriveBackupEvidence };
}

module.exports = { BACKUP_EVIDENCE_SCHEMA, createBackupEvidenceStore, deriveBackupEvidence };
