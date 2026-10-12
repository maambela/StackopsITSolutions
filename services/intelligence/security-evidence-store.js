const crypto = require('crypto');
const { buildSecurityDashboardSource } = require('./security-dashboard-source');
const { buildRiskEngine } = require('./risk-engine');

const SECURITY_EVIDENCE_SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRLSecurityEvidenceSnapshots (
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
        TotalAlerts INT NOT NULL DEFAULT 0,
        HighSeverityAlerts INT NOT NULL DEFAULT 0,
        ActiveIncidents INT NOT NULL DEFAULT 0,
        ThreatIndicators INT NOT NULL DEFAULT 0,
        UsersUnderAttack INT NOT NULL DEFAULT 0,
        SecurityScore DECIMAL(6,2) NOT NULL DEFAULT 0,
        SuspiciousSignIns INT NOT NULL DEFAULT 0,
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
        KEY ix_security_evidence_latest (CompanyID, IsComplete, CollectedAt, ID),
        KEY ix_security_evidence_status (CollectionStatus, CollectedAt)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRLSecurityEvidence (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        SnapshotID BIGINT UNSIGNED NOT NULL,
        CompanyID BIGINT NOT NULL,
        TenantKey VARCHAR(100) NOT NULL,
        EvidenceKind VARCHAR(30) NOT NULL,
        SourceID VARCHAR(255) NULL,
        Title VARCHAR(500) NOT NULL,
        Severity VARCHAR(50) NULL,
        Status VARCHAR(50) NULL,
        ProcessedEvidenceJson JSON NOT NULL,
        CollectedAt DATETIME(3) NOT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        UNIQUE KEY uq_security_evidence_snapshot_source (SnapshotID, EvidenceKind, SourceID),
        KEY ix_security_evidence_snapshot (SnapshotID, ID),
        CONSTRAINT fk_security_evidence_snapshot
            FOREIGN KEY (SnapshotID) REFERENCES StackCTRLSecurityEvidenceSnapshots(ID)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

function mysqlDateTime(value) {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return date.toISOString().slice(0, 19).replace('T', ' ');
}

function deriveSecurityEvidence(payload = {}) {
    const rawWarnings = [
        ...(Array.isArray(payload.warnings) ? payload.warnings : []),
        ...(Array.isArray(payload.collection?.warnings) ? payload.collection.warnings : []),
        ...(payload.collection?.incompleteReason ? [payload.collection.incompleteReason] : []),
        ...(payload.incompleteReason ? [payload.incompleteReason] : [])
    ];

    const dashboardSource = buildSecurityDashboardSource({
        alertsRows: payload.alerts || [],
        incidentsRows: payload.incidents || [],
        threatsRows: payload.threats || payload.threatIndicators || [],
        suspiciousSignInsRows: payload.signIns?.suspicious || payload.suspiciousSignIns || [],
        findingsRows: payload.findings || [],
        scenarioCoverage: payload.scenarioCoverage || {},
        riskDetectionsRows: payload.identityRisk?.riskDetections || [],
        riskyUsersRows: payload.identityRisk?.riskyUsers || [],
        summary: payload.summary || payload.dashboardMetrics || {},
        recommendations: payload.recommendations,
        warnings: rawWarnings
    });

    const metrics = dashboardSource.dashboardMetrics;

    const riskEngine = buildRiskEngine({
        sources: [{
            sourceKey: 'security_alerts',
            status: dashboardSource.warnings.length ? 'partial' : 'available',
            isExpected: true,
            metrics,
            dashboardMetrics: metrics
        }],
        dataCompleteness: { score: dashboardSource.warnings.length ? 85 : 100 }
    });

    const stackctrlHealthScore = riskEngine.domainHealthScores.security;
    const stackctrlRiskScore = riskEngine.domainRiskScores.security;
    const dashboardMetrics = { ...metrics, stackctrlRiskScore, stackctrlHealthScore };

    const evidenceRows = [
        ...dashboardSource.alerts.map((alert, index) => ({
            kind: 'alert',
            sourceId: String(alert.id || alert.alertId || `alert-${index + 1}`).slice(0, 255),
            title: alert.title || alert.alertName || alert.displayName || 'Unknown Alert',
            severity: alert.severity || 'medium',
            status: alert.status || 'newalert',
            processed: alert
        })),
        ...dashboardSource.incidents.map((incident, index) => ({
            kind: 'incident',
            sourceId: String(incident.id || incident.incidentId || `incident-${index + 1}`).slice(0, 255),
            title: incident.displayName || incident.title || incident.incidentName || 'Unknown Incident',
            severity: incident.severity || 'medium',
            status: incident.status || 'active',
            processed: incident
        })),
        ...dashboardSource.suspiciousSignIns.map((signIn, index) => ({
            kind: 'sign_in',
            sourceId: String(signIn.id || signIn.signInId || `signin-${index + 1}`).slice(0, 255),
            title: signIn.user || signIn.userPrincipalName || signIn.userEmail || 'Suspicious sign-in',
            severity: signIn.severity || (String(signIn.status || '').toLowerCase() === 'failed' ? 'medium' : 'low'),
            status: signIn.status || signIn.result || 'unknown',
            processed: signIn
        })),
        ...dashboardSource.threats.map((threat, index) => ({
            kind: 'threat_indicator',
            sourceId: String(threat.id || threat.indicator || threat.value || `threat-${index + 1}`).slice(0, 255),
            title: threat.indicator || threat.value || threat.indicatorValue || 'Threat indicator',
            severity: threat.severity || 'medium',
            status: threat.action || threat.status || 'Review',
            processed: threat
        })),
        ...dashboardSource.findings.map((finding, index) => ({
            kind: 'security_finding',
            sourceId: String(finding.id || `finding-${index + 1}`).slice(0, 255),
            title: finding.title || finding.detectionId || 'Security finding',
            severity: finding.severity || 'unassessed',
            status: finding.status || 'needs_investigation',
            processed: finding
        })),
        ...dashboardSource.riskDetections.map((detection, index) => ({
            kind: 'risk_detection',
            sourceId: String(detection.id || detection.requestId || `risk-detection-${index + 1}`).slice(0, 255),
            title: detection.riskEventType || 'Identity risk detection',
            severity: detection.riskLevel || 'unassessed',
            status: detection.riskState || 'unknown',
            processed: detection
        })),
        ...dashboardSource.riskyUsers.map((user, index) => ({
            kind: 'risky_user',
            sourceId: String(user.id || user.userPrincipalName || `risky-user-${index + 1}`).slice(0, 255),
            title: user.userPrincipalName || user.userDisplayName || 'Risky user',
            severity: user.riskLevel || 'unassessed',
            status: user.riskState || 'unknown',
            processed: user
        }))
    ];

    const hasPrimaryEvidence = Boolean(
        dashboardSource.alerts.length ||
        dashboardSource.incidents.length ||
        dashboardSource.suspiciousSignIns.length ||
        dashboardSource.findings.length
    );

    const hasAnyEvidence = Boolean(evidenceRows.length);
    const isComplete = hasPrimaryEvidence && dashboardSource.warnings.length === 0;
    const isPartial = hasPrimaryEvidence && dashboardSource.warnings.length > 0;

    const accounting = payload.collection?.accounting || {};
    const omittedRecordCount = Math.max(0, Number(
        accounting.recordsOmitted ||
        payload.summary?.recordsOmitted ||
        0
    ));

    const expectedRecordCount = Math.max(
        evidenceRows.length,
        Number(
            accounting.recordsFetched ||
            payload.summary?.recordsFetched ||
            evidenceRows.length
        )
    );

    const collectionStatus = isComplete
        ? 'complete'
        : isPartial
            ? 'completed_with_warnings'
            : 'failed_terminal';

    return {
        evidenceRows,
        dashboardMetrics,
        stackctrlRiskScore,
        stackctrlHealthScore,
        expectedRecordCount,
        omittedRecordCount,
        completenessPercent: expectedRecordCount
            ? Number(((evidenceRows.length / expectedRecordCount) * 100).toFixed(2))
            : (hasAnyEvidence ? 100 : 0),
        isComplete: isComplete || isPartial,
        collectionStatus,
        warnings: dashboardSource.warnings,
        sourceAudit: {
            ...(payload.collection || {}),
            warnings: dashboardSource.warnings,
            internalThreatIndicatorsExtracted: dashboardSource.internalThreatIndicators?.length || 0,
            hasPrimaryEvidence,
            hasAnyEvidence,
            scenarioCoverage: dashboardSource.scenarioCoverage
        },
        incompleteReason: dashboardSource.warnings.length
            ? dashboardSource.warnings.join('; ')
            : null
    };
}

function createSecurityEvidenceStore({ pool, logger = console, now = () => new Date() } = {}) {
    if (!pool?.query) throw new Error('Security evidence storage requires a database pool');
    async function ensureSchema() {
        for (const statement of SECURITY_EVIDENCE_SCHEMA) await pool.query(statement);
        return { tables: ['StackCTRLSecurityEvidenceSnapshots', 'StackCTRLSecurityEvidence'] };
    }
    async function persistProcessedEvidence({ companyId, tenantKey = 'sunbird', payload, collectionTrigger = 'scheduled_hourly', sourceEndpoint = 'Microsoft Graph processed by StackCTRL Security Alerts' } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        const evidence = deriveSecurityEvidence(payload);
        const collectedAt = now();
        const connection = typeof pool.getConnection === 'function' ? await pool.getConnection() : pool;
        const ownsConnection = connection !== pool;
        let snapshotId = null;
        try {
            if (typeof connection.beginTransaction === 'function') await connection.beginTransaction();
            const metrics = evidence.dashboardMetrics;
            const [snapshotResult] = await connection.query(
                `INSERT INTO StackCTRLSecurityEvidenceSnapshots
                 (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete,
                  CollectedAt, SourceFetchedAt, EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount,
                  CompletenessPercent, TotalAlerts, HighSeverityAlerts, ActiveIncidents, ThreatIndicators,
                  UsersUnderAttack, SecurityScore, SuspiciousSignIns, RecommendationsCount,
                  StackCTRLRiskScore, StackCTRLHealthScore, DashboardMetricsJson, SourceAuditJson,
                  EvidenceSha256, IncompleteReason)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    numericCompanyId, tenantKey, collectionTrigger, sourceEndpoint,
                    evidence.collectionStatus, evidence.isComplete ? 1 : 0,
                    mysqlDateTime(collectedAt), mysqlDateTime(payload?.fetchedAt || collectedAt),
                    evidence.evidenceRows.length, evidence.expectedRecordCount, evidence.omittedRecordCount, evidence.completenessPercent,
                    metrics.totalAlerts, metrics.highSeverityAlerts, metrics.activeIncidents, metrics.threatIndicators,
                    metrics.usersUnderAttack, metrics.securityScore, metrics.suspiciousSignIns, metrics.recommendationsCount,
                    evidence.stackctrlRiskScore, evidence.stackctrlHealthScore, JSON.stringify(metrics),
                    JSON.stringify({ source: 'stackctrl_processed_security_dashboard', collectionTrigger, sourceEndpoint, credentialSource: 'cached_secret_or_environment', credentialPath: 'MICROSOFT_CLIENT_SECRET (Azure Key Vault or environment)', warnings: evidence.warnings, collection: evidence.sourceAudit }),
                    crypto.createHash('sha256').update(JSON.stringify({ rows: evidence.evidenceRows, dashboardMetrics: metrics })).digest('hex'),
                    evidence.incompleteReason
                ]
            );
            snapshotId = snapshotResult.insertId;
            for (const row of evidence.evidenceRows) {
                await connection.query(
                    `INSERT INTO StackCTRLSecurityEvidence
                     (SnapshotID, CompanyID, TenantKey, EvidenceKind, SourceID, Title, Severity, Status, ProcessedEvidenceJson, CollectedAt)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [snapshotId, numericCompanyId, tenantKey, row.kind, row.sourceId, row.title, row.severity, row.status, JSON.stringify(row.processed), mysqlDateTime(collectedAt)]
                );
            }
            if (typeof connection.commit === 'function') await connection.commit();
        } catch (error) {
            if (typeof connection.rollback === 'function') await connection.rollback();
            throw error;
        } finally {
            if (ownsConnection && typeof connection.release === 'function') connection.release();
        }
        logger.log(`[Security Evidence] Stored snapshot ${snapshotId} with ${evidence.evidenceRows.length} processed security records.`);
        return { snapshotId, companyId: numericCompanyId, collectedAt: collectedAt.toISOString(), recordCount: evidence.evidenceRows.length, expectedRecordCount: evidence.expectedRecordCount, omittedRecordCount: evidence.omittedRecordCount, isComplete: evidence.isComplete, collectionStatus: evidence.collectionStatus, warnings: evidence.warnings, dashboardMetrics: evidence.dashboardMetrics };
    }
    async function recordCollectionFailure({ companyId, tenantKey = 'sunbird', collectionTrigger = 'scheduled_hourly', sourceEndpoint, error } = {}) {
        const [result] = await pool.query(
            `INSERT INTO StackCTRLSecurityEvidenceSnapshots
             (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete, CollectedAt,
              EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount, CompletenessPercent, DashboardMetricsJson, SourceAuditJson, IncompleteReason, ErrorMessage)
             VALUES (?, ?, ?, ?, 'failed_terminal', 0, ?, 0, 0, 0, 0, ?, ?, ?, ?)`,
            [Number(companyId), tenantKey, collectionTrigger, sourceEndpoint || 'Microsoft Graph processed by StackCTRL Security Alerts', mysqlDateTime(now()), JSON.stringify({}), JSON.stringify({ credentialSource: 'cached_secret_or_environment', terminalStage: error?.securityAlertsStage || null, stages: error?.securityAlertsStages || [] }), `Security evidence collection stopped at ${error?.securityAlertsStage || 'unknown_stage'}.`, String(error?.message || error).slice(0, 5000)]
        );
        return { snapshotId: result.insertId, companyId: Number(companyId), status: 'failed_terminal', stage: error?.securityAlertsStage || null };
    }
    return { ensureSchema, persistProcessedEvidence, recordCollectionFailure, deriveSecurityEvidence };
}

module.exports = { SECURITY_EVIDENCE_SCHEMA, createSecurityEvidenceStore, deriveSecurityEvidence };
