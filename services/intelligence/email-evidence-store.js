const crypto = require('crypto');
const { buildEmailDashboardSource, getEmailThreatType } = require('./email-dashboard-source');
const { buildRiskEngine } = require('./risk-engine');

const EMAIL_EVIDENCE_SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRLEmailEvidenceSnapshots (
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
        ActiveThreats INT NOT NULL DEFAULT 0,
        HighSeverityAlerts INT NOT NULL DEFAULT 0,
        UsersTargeted INT NOT NULL DEFAULT 0,
        ActiveIncidents INT NOT NULL DEFAULT 0,
        SecurityScore DECIMAL(6,2) NOT NULL DEFAULT 0,
        ThreatResolutionRate DECIMAL(6,2) NOT NULL DEFAULT 0,
        PhishingCount INT NOT NULL DEFAULT 0,
        MalwareCount INT NOT NULL DEFAULT 0,
        SpamCount INT NOT NULL DEFAULT 0,
        BecCount INT NOT NULL DEFAULT 0,
        ActiveMailboxes INT NOT NULL DEFAULT 0,
        TotalMailActivity INT NOT NULL DEFAULT 0,
        SendCount INT NOT NULL DEFAULT 0,
        ReceiveCount INT NOT NULL DEFAULT 0,
        ReadCount INT NOT NULL DEFAULT 0,
        RecommendationsCount INT NOT NULL DEFAULT 0,
        ThreatTypeDistributionJson JSON NOT NULL,
        SeverityDistributionJson JSON NOT NULL,
        MostTargetedUsersJson JSON NOT NULL,
        StackCTRLRiskScore DECIMAL(6,2) NULL,
        StackCTRLHealthScore DECIMAL(6,2) NULL,
        DashboardMetricsJson JSON NOT NULL,
        SourceAuditJson JSON NULL,
        EvidenceSha256 CHAR(64) NULL,
        IncompleteReason TEXT NULL,
        ErrorMessage TEXT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        KEY ix_email_evidence_latest (CompanyID, IsComplete, CollectedAt, ID),
        KEY ix_email_evidence_status (CollectionStatus, CollectedAt)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRLEmailEvidence (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        SnapshotID BIGINT UNSIGNED NOT NULL,
        CompanyID BIGINT NOT NULL,
        TenantKey VARCHAR(100) NOT NULL,
        EvidenceKind VARCHAR(30) NOT NULL,
        SourceID VARCHAR(255) NULL,
        Title VARCHAR(500) NOT NULL,
        Severity VARCHAR(50) NULL,
        Status VARCHAR(50) NULL,
        ThreatType VARCHAR(50) NULL,
        ProcessedEvidenceJson JSON NOT NULL,
        CollectedAt DATETIME(3) NOT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        UNIQUE KEY uq_email_evidence_snapshot_source (SnapshotID, EvidenceKind, SourceID),
        KEY ix_email_evidence_snapshot (SnapshotID, ID),
        KEY ix_email_evidence_company_kind (CompanyID, EvidenceKind),
        CONSTRAINT fk_email_evidence_snapshot
            FOREIGN KEY (SnapshotID) REFERENCES StackCTRLEmailEvidenceSnapshots(ID)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

function mysqlDateTime(value) {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return date.toISOString().slice(0, 19).replace('T', ' ');
}

function deriveEmailEvidence(payload = {}) {
    const dashboardSource = buildEmailDashboardSource({
        alertsRows: payload.alerts || [],
        incidentsRows: payload.incidents || [],
        mailActivity: payload.mailActivity || {},
        summary: payload.summary || payload.dashboardMetrics || {},
        threats: payload.threats || null,
        affectedUsers: payload.affectedUsers || {}
    });
    const metrics = dashboardSource.dashboardMetrics;
    const riskEngine = buildRiskEngine({
        sources: [{
            sourceKey: 'email_security',
            status: 'available',
            isExpected: true,
            metrics,
            dashboardMetrics: metrics
        }],
        dataCompleteness: { score: 100 }
    });
    const stackctrlHealthScore = riskEngine.domainHealthScores.email;
    const stackctrlRiskScore = riskEngine.domainRiskScores.email;
    const dashboardMetrics = {
        ...metrics,
        stackctrlRiskScore,
        stackctrlHealthScore
    };
    const evidenceRows = [
        ...dashboardSource.alerts.map((alert, index) => ({
            kind: 'alert',
            sourceId: String(alert.id || `alert-${index + 1}`).slice(0, 255),
            title: alert.title || 'Unknown Alert',
            severity: alert.severity || 'medium',
            status: alert.status || 'newalert',
            threatType: getEmailThreatType(alert),
            processed: alert
        })),
        ...dashboardSource.incidents.map((incident, index) => ({
            kind: 'incident',
            sourceId: String(incident.id || `incident-${index + 1}`).slice(0, 255),
            title: incident.displayName || 'Unknown Incident',
            severity: incident.severity || 'medium',
            status: incident.status || 'active',
            threatType: null,
            processed: incident
        })),
        ...dashboardSource.mailUsers.map((user, index) => ({
            kind: 'mail_activity',
            sourceId: String(user.userPrincipalName || `mail-${index + 1}`).slice(0, 255),
            title: user.userPrincipalName || 'Mailbox activity',
            severity: 'low',
            status: user.lastActivityDate ? 'active' : 'inactive',
            threatType: 'mailflow',
            processed: user
        }))
    ];
    const expectedRecordCount = evidenceRows.length;
    const omittedRecordCount = 0;
    const audit = payload.sourceAudit;
    const coverageComplete = !audit || (
        audit.alertsComplete === true && audit.incidentsComplete === true && audit.mailActivityOk === true
    );
    const isComplete = Boolean(payload.success !== false && coverageComplete);
    const completenessPercent = expectedRecordCount > 0 ? 100 : (isComplete ? 100 : 0);

    return {
        evidenceRows,
        dashboardMetrics,
        threatTypeDistribution: metrics.threatTypeDistribution,
        severityDistribution: metrics.severityDistribution,
        mostTargetedUsers: metrics.mostTargetedUsers,
        stackctrlRiskScore,
        stackctrlHealthScore,
        expectedRecordCount,
        omittedRecordCount,
        completenessPercent,
        isComplete,
        incompleteReason: isComplete ? null : 'The processed Email Security dashboard did not complete successfully.'
    };
}

function createEmailEvidenceStore({ pool, logger = console, now = () => new Date() } = {}) {
    if (!pool?.query) throw new Error('Email evidence storage requires a database pool');

    async function ensureSchema() {
        for (const statement of EMAIL_EVIDENCE_SCHEMA) await pool.query(statement);
        return { tables: ['StackCTRLEmailEvidenceSnapshots', 'StackCTRLEmailEvidence'] };
    }

    async function persistProcessedEvidence({
        companyId,
        tenantKey = 'sunbird',
        payload,
        collectionTrigger = 'scheduled_hourly',
        sourceEndpoint = 'Microsoft Graph processed by StackCTRL Email Security'
    } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        const evidence = deriveEmailEvidence(payload);
        const collectedAt = payload?.collectionStartedAt ? new Date(payload.collectionStartedAt) : now();
        const sourceFetchedAt = payload?.fetchedAt || collectedAt;
        const evidenceHash = crypto.createHash('sha256').update(JSON.stringify({
            rows: evidence.evidenceRows,
            dashboardMetrics: evidence.dashboardMetrics
        })).digest('hex');
        const connection = typeof pool.getConnection === 'function' ? await pool.getConnection() : pool;
        const ownsConnection = connection !== pool;
        let snapshotId = null;
        try {
            if (typeof connection.beginTransaction === 'function') await connection.beginTransaction();
            const metrics = evidence.dashboardMetrics;
            const [snapshotResult] = await connection.query(
                `INSERT INTO StackCTRLEmailEvidenceSnapshots
                 (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete,
                  CollectedAt, SourceFetchedAt, EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount,
                  CompletenessPercent, ActiveThreats, HighSeverityAlerts, UsersTargeted, ActiveIncidents,
                  SecurityScore, ThreatResolutionRate, PhishingCount, MalwareCount, SpamCount, BecCount,
                  ActiveMailboxes, TotalMailActivity, SendCount, ReceiveCount, ReadCount, RecommendationsCount,
                  ThreatTypeDistributionJson, SeverityDistributionJson, MostTargetedUsersJson,
                  StackCTRLRiskScore, StackCTRLHealthScore, DashboardMetricsJson, SourceAuditJson,
                  EvidenceSha256, IncompleteReason)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    numericCompanyId, tenantKey, collectionTrigger, sourceEndpoint,
                    evidence.isComplete ? 'complete' : 'incomplete', evidence.isComplete ? 1 : 0,
                    mysqlDateTime(collectedAt), mysqlDateTime(sourceFetchedAt), evidence.evidenceRows.length,
                    evidence.expectedRecordCount, evidence.omittedRecordCount, evidence.completenessPercent,
                    metrics.activeThreats, metrics.highSeverityAlerts, metrics.affectedUsersCount, metrics.activeIncidents,
                    metrics.securityScore, metrics.threatResolutionRate, metrics.phishingCount, metrics.malwareCount,
                    metrics.spamCount, metrics.becCount, metrics.activeMailboxes, metrics.totalMailActivity,
                    metrics.sendCount, metrics.receiveCount, metrics.readCount, metrics.recommendationsCount,
                    JSON.stringify(evidence.threatTypeDistribution), JSON.stringify(evidence.severityDistribution),
                    JSON.stringify(evidence.mostTargetedUsers), evidence.stackctrlRiskScore, evidence.stackctrlHealthScore,
                    JSON.stringify(metrics), JSON.stringify({
                        source: 'stackctrl_processed_email_dashboard',
                        dashboardFetchedAt: payload?.fetchedAt || null,
                        collectionTrigger,
                        sourceEndpoint,
                        credentialSource: 'environment',
                        credentialPath: 'MICROSOFT_CLIENT_SECRET (Azure Key Vault, shared with dashboard)'
                    }),
                    evidenceHash, evidence.incompleteReason
                ]
            );
            snapshotId = snapshotResult.insertId;

            for (const row of evidence.evidenceRows) {
                await connection.query(
                    `INSERT INTO StackCTRLEmailEvidence
                     (SnapshotID, CompanyID, TenantKey, EvidenceKind, SourceID, Title, Severity, Status,
                      ThreatType, ProcessedEvidenceJson, CollectedAt)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        snapshotId, numericCompanyId, tenantKey, row.kind, row.sourceId, row.title,
                        row.severity, row.status, row.threatType, JSON.stringify(row.processed),
                        mysqlDateTime(collectedAt)
                    ]
                );
            }
            if (typeof connection.commit === 'function') await connection.commit();
        } catch (error) {
            if (typeof connection.rollback === 'function') await connection.rollback();
            throw error;
        } finally {
            if (ownsConnection && typeof connection.release === 'function') connection.release();
        }

        logger.log(`[Email Evidence] Stored snapshot ${snapshotId} with ${evidence.evidenceRows.length} processed email records.`);
        return {
            snapshotId,
            companyId: numericCompanyId,
            collectedAt: collectedAt.toISOString(),
            recordCount: evidence.evidenceRows.length,
            omittedCount: evidence.omittedRecordCount,
            isComplete: evidence.isComplete,
            dashboardMetrics: evidence.dashboardMetrics
        };
    }

    async function recordCollectionFailure({
        companyId,
        tenantKey = 'sunbird',
        collectionTrigger = 'scheduled_hourly',
        sourceEndpoint = 'Microsoft Graph processed by StackCTRL Email Security',
        error
    } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        const message = String(error?.message || error || 'Email evidence collection failed').slice(0, 5000);
        const [result] = await pool.query(
            `INSERT INTO StackCTRLEmailEvidenceSnapshots
             (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete,
              CollectedAt, EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount,
              CompletenessPercent, ThreatTypeDistributionJson, SeverityDistributionJson,
              MostTargetedUsersJson, DashboardMetricsJson, SourceAuditJson,
              IncompleteReason, ErrorMessage)
             VALUES (?, ?, ?, ?, 'failed', 0, ?, 0, 0, 0, 0, ?, ?, ?, ?, ?, ?, ?)`,
            [
                numericCompanyId, tenantKey, collectionTrigger, sourceEndpoint, mysqlDateTime(now()),
                JSON.stringify({}), JSON.stringify({ high: 0, medium: 0, low: 0 }), JSON.stringify([]),
                JSON.stringify({}),
                JSON.stringify({
                    source: 'stackctrl_processed_email_dashboard',
                    collectionTrigger,
                    sourceEndpoint,
                    credentialSource: 'environment',
                    credentialPath: 'MICROSOFT_CLIENT_SECRET (Azure Key Vault, shared with dashboard)'
                }),
                'Email evidence collection did not complete.', message
            ]
        );
        return { snapshotId: result.insertId, companyId: numericCompanyId, status: 'failed', message };
    }

    return { ensureSchema, persistProcessedEvidence, recordCollectionFailure, deriveEmailEvidence };
}

module.exports = {
    EMAIL_EVIDENCE_SCHEMA,
    createEmailEvidenceStore,
    deriveEmailEvidence
};
