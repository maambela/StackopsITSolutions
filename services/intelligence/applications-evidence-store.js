const { assertCollectionOwner } = require('./graph-collection-ownership');
const crypto = require('crypto');
const { buildApplicationsDashboardSource, calculateAppRisk } = require('./applications-dashboard-source');
const { buildRiskEngine } = require('./risk-engine');

const APPLICATIONS_EVIDENCE_SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRLApplicationsEvidenceSnapshots (
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
        TotalApplications INT NOT NULL DEFAULT 0,
        ExternalApplications INT NOT NULL DEFAULT 0,
        HighRiskApps INT NOT NULL DEFAULT 0,
        HighAccessApps INT NOT NULL DEFAULT 0,
        ExcessivePermissionApps INT NOT NULL DEFAULT 0,
        GroupAssignedApps INT NOT NULL DEFAULT 0,
        ApplicationGovernanceScore DECIMAL(6,2) NOT NULL DEFAULT 0,
        UserCount INT NOT NULL DEFAULT 0,
        GroupCount INT NOT NULL DEFAULT 0,
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
        KEY ix_applications_evidence_latest (CompanyID, IsComplete, CollectedAt, ID),
        KEY ix_applications_evidence_status (CollectionStatus, CollectedAt)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRLApplicationsEvidence (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        SnapshotID BIGINT UNSIGNED NOT NULL,
        CompanyID BIGINT NOT NULL,
        TenantKey VARCHAR(100) NOT NULL,
        AppSourceID VARCHAR(255) NULL,
        AppName VARCHAR(500) NOT NULL,
        PublisherName VARCHAR(255) NULL,
        IsExternal TINYINT(1) NOT NULL DEFAULT 0,
        UserCount INT NOT NULL DEFAULT 0,
        ScopeCount INT NOT NULL DEFAULT 0,
        RoleCount INT NOT NULL DEFAULT 0,
        RiskLevel VARCHAR(50) NOT NULL,
        ProcessedEvidenceJson JSON NOT NULL,
        CollectedAt DATETIME(3) NOT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        UNIQUE KEY uq_applications_evidence_snapshot_source (SnapshotID, AppSourceID),
        KEY ix_applications_evidence_snapshot (SnapshotID, ID),
        CONSTRAINT fk_applications_evidence_snapshot
            FOREIGN KEY (SnapshotID) REFERENCES StackCTRLApplicationsEvidenceSnapshots(ID)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

function mysqlDateTime(value) {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return date.toISOString().slice(0, 19).replace('T', ' ');
}

function deriveApplicationsEvidence(payload = {}) {
    const dashboardSource = buildApplicationsDashboardSource({
        applicationsRows: payload.applications || [],
        summary: payload.summary || payload.dashboardMetrics || {},
        userCount: payload.userCount,
        groupCount: payload.groupCount
    });
    const metrics = dashboardSource.dashboardMetrics;
    const riskEngine = buildRiskEngine({
        sources: [{ sourceKey: 'applications', status: 'available', isExpected: true, metrics, dashboardMetrics: metrics }],
        dataCompleteness: { score: 100 }
    });
    const stackctrlHealthScore = riskEngine.domainHealthScores.applications;
    const stackctrlRiskScore = riskEngine.domainRiskScores.applications;
    const dashboardMetrics = { ...metrics, stackctrlRiskScore, stackctrlHealthScore };
    const evidenceRows = dashboardSource.apps.map((app, index) => ({
        sourceId: String(app.id || app.name || `app-${index + 1}`).slice(0, 255),
        name: app.displayName || app.name || 'Unknown App',
        publisherName: app.publisherName || 'Unknown',
        isExternal: Boolean(app.isExternal),
        userCount: app.userCount || 0,
        scopeCount: app.scopeCount || 0,
        roleCount: app.roleCount || 0,
        riskLevel: calculateAppRisk(app),
        processed: app
    }));
    const expectedRecordCount = evidenceRows.length;
    const verifiedEmpty = payload.success === true && Array.isArray(payload.applications) && payload.summary?.totalApplications === 0;
    const isComplete = payload.success !== false && (expectedRecordCount > 0 || verifiedEmpty);
    return {
        evidenceRows,
        dashboardMetrics,
        stackctrlRiskScore,
        stackctrlHealthScore,
        expectedRecordCount,
        omittedRecordCount: 0,
        completenessPercent: expectedRecordCount > 0 ? 100 : (isComplete ? 100 : 0),
        isComplete,
        incompleteReason: isComplete ? null : 'The processed Applications dashboard contained no application evidence.'
    };
}

function createApplicationsEvidenceStore({ pool, logger = console, now = () => new Date() } = {}) {
    if (!pool?.query) throw new Error('Applications evidence storage requires a database pool');
    async function ensureSchema() {
        for (const statement of APPLICATIONS_EVIDENCE_SCHEMA) await pool.query(statement);
        return { tables: ['StackCTRLApplicationsEvidenceSnapshots', 'StackCTRLApplicationsEvidence'] };
    }
    async function persistProcessedEvidence({ companyId, tenantKey = 'sunbird', payload, collectionTrigger = 'scheduled_hourly', sourceEndpoint = 'Microsoft Graph processed by StackCTRL Applications' } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        const evidence = deriveApplicationsEvidence(payload);
        const collectedAt = payload?.collectionStartedAt ? new Date(payload.collectionStartedAt) : now();
        const connection = typeof pool.getConnection === 'function' ? await pool.getConnection() : pool;
        const ownsConnection = connection !== pool;
        let snapshotId = null;
        try {
            if (typeof connection.beginTransaction === 'function') await connection.beginTransaction();
            await assertCollectionOwner(connection, companyId);
            const metrics = evidence.dashboardMetrics;
            const [snapshotResult] = await connection.query(
                `INSERT INTO StackCTRLApplicationsEvidenceSnapshots
                 (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete,
                  CollectedAt, SourceFetchedAt, EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount,
                  CompletenessPercent, TotalApplications, ExternalApplications, HighRiskApps, HighAccessApps,
                  ExcessivePermissionApps, GroupAssignedApps, ApplicationGovernanceScore, UserCount, GroupCount,
                  RecommendationsCount, StackCTRLRiskScore, StackCTRLHealthScore, DashboardMetricsJson,
                  SourceAuditJson, EvidenceSha256, IncompleteReason)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    numericCompanyId, tenantKey, collectionTrigger, sourceEndpoint,
                    evidence.isComplete ? 'complete' : 'incomplete', evidence.isComplete ? 1 : 0,
                    mysqlDateTime(collectedAt), mysqlDateTime(payload?.fetchedAt || collectedAt),
                    evidence.evidenceRows.length, evidence.expectedRecordCount, 0, evidence.completenessPercent,
                    metrics.totalApplications, metrics.externalApplications, metrics.highRiskApps, metrics.highAccessApps,
                    metrics.excessivePermissionApps, metrics.groupAssignedApps, metrics.applicationGovernanceScore,
                    metrics.userCount, metrics.groupCount, metrics.recommendationsCount,
                    evidence.stackctrlRiskScore, evidence.stackctrlHealthScore, JSON.stringify(metrics),
                    JSON.stringify({ source: 'stackctrl_processed_applications_dashboard', collectionTrigger, sourceEndpoint, credentialSource: 'environment', credentialPath: 'MICROSOFT_CLIENT_SECRET (Azure Key Vault, shared with dashboard)' }),
                    crypto.createHash('sha256').update(JSON.stringify({ rows: evidence.evidenceRows, dashboardMetrics: metrics })).digest('hex'),
                    evidence.incompleteReason
                ]
            );
            snapshotId = snapshotResult.insertId;
            for (const row of evidence.evidenceRows) {
                await connection.query(
                    `INSERT INTO StackCTRLApplicationsEvidence
                     (SnapshotID, CompanyID, TenantKey, AppSourceID, AppName, PublisherName, IsExternal,
                      UserCount, ScopeCount, RoleCount, RiskLevel, ProcessedEvidenceJson, CollectedAt)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [snapshotId, numericCompanyId, tenantKey, row.sourceId, row.name, row.publisherName, row.isExternal ? 1 : 0, row.userCount, row.scopeCount, row.roleCount, row.riskLevel, JSON.stringify(row.processed), mysqlDateTime(collectedAt)]
                );
            }
            await assertCollectionOwner(connection, companyId);
            if (typeof connection.commit === 'function') await connection.commit();
        } catch (error) {
            if (typeof connection.rollback === 'function') await connection.rollback();
            throw error;
        } finally {
            if (ownsConnection && typeof connection.release === 'function') connection.release();
        }
        logger.log(`[Applications Evidence] Stored snapshot ${snapshotId} with ${evidence.evidenceRows.length} processed application records.`);
        return { snapshotId, companyId: numericCompanyId, collectedAt: collectedAt.toISOString(), recordCount: evidence.evidenceRows.length, isComplete: evidence.isComplete, dashboardMetrics: evidence.dashboardMetrics };
    }
    async function recordCollectionFailure({ companyId, tenantKey = 'sunbird', collectionTrigger = 'scheduled_hourly', sourceEndpoint, error } = {}) {
        const [result] = await pool.query(
            `INSERT INTO StackCTRLApplicationsEvidenceSnapshots
             (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete, CollectedAt,
              EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount, CompletenessPercent, DashboardMetricsJson, SourceAuditJson, IncompleteReason, ErrorMessage)
             VALUES (?, ?, ?, ?, 'failed', 0, ?, 0, 0, 0, 0, ?, ?, ?, ?)`,
            [Number(companyId), tenantKey, collectionTrigger, sourceEndpoint || 'Microsoft Graph processed by StackCTRL Applications', mysqlDateTime(now()), JSON.stringify({}), JSON.stringify({ credentialSource: 'environment' }), 'Applications evidence collection did not complete.', String(error?.message || error).slice(0, 5000)]
        );
        return { snapshotId: result.insertId, companyId: Number(companyId), status: 'failed' };
    }
    return { ensureSchema, persistProcessedEvidence, recordCollectionFailure, deriveApplicationsEvidence };
}

module.exports = { APPLICATIONS_EVIDENCE_SCHEMA, createApplicationsEvidenceStore, deriveApplicationsEvidence };
