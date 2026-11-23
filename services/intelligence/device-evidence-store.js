const crypto = require('crypto');
const { buildDeviceDashboardSource, getDeviceRiskLevel, daysSinceLastSync } = require('./device-dashboard-source');
const { buildRiskEngine } = require('./risk-engine');

const DEVICE_EVIDENCE_SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRLDeviceEvidenceSnapshots (
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
        TotalDevices INT NOT NULL DEFAULT 0,
        CompliantDevices INT NOT NULL DEFAULT 0,
        NonCompliantDevices INT NOT NULL DEFAULT 0,
        UnknownDevices INT NOT NULL DEFAULT 0,
        EncryptedDevices INT NOT NULL DEFAULT 0,
        NotEncryptedDevices INT NOT NULL DEFAULT 0,
        ComplianceRatePercent DECIMAL(6,2) NOT NULL DEFAULT 0,
        EncryptionRatePercent DECIMAL(6,2) NOT NULL DEFAULT 0,
        ActiveDevices24h INT NOT NULL DEFAULT 0,
        StaleDevices INT NOT NULL DEFAULT 0,
        Dead30Days INT NOT NULL DEFAULT 0,
        HighRiskDevices INT NOT NULL DEFAULT 0,
        UnmanagedDevices INT NOT NULL DEFAULT 0,
        SecurityAlertsCount INT NOT NULL DEFAULT 0,
        DeviceSecurityScore DECIMAL(6,2) NOT NULL DEFAULT 0,
        ActivityBreakdownJson JSON NOT NULL,
        ComplianceBreakdownJson JSON NOT NULL,
        RiskDistributionJson JSON NOT NULL,
        StackCTRLRiskScore DECIMAL(6,2) NULL,
        StackCTRLHealthScore DECIMAL(6,2) NULL,
        DashboardMetricsJson JSON NOT NULL,
        SourceAuditJson JSON NULL,
        EvidenceSha256 CHAR(64) NULL,
        IncompleteReason TEXT NULL,
        ErrorMessage TEXT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        KEY ix_device_evidence_latest (CompanyID, IsComplete, CollectedAt, ID),
        KEY ix_device_evidence_status (CollectionStatus, CollectedAt)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRLDeviceEvidence (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        SnapshotID BIGINT UNSIGNED NOT NULL,
        CompanyID BIGINT NOT NULL,
        TenantKey VARCHAR(100) NOT NULL,
        DeviceSourceID VARCHAR(255) NULL,
        DeviceName VARCHAR(500) NOT NULL,
        OperatingSystem VARCHAR(255) NULL,
        ComplianceState VARCHAR(50) NOT NULL,
        IsEncrypted TINYINT(1) NOT NULL DEFAULT 0,
        ManagementAgent VARCHAR(255) NULL,
        LastSyncAt DATETIME NULL,
        DaysSinceLastSync INT NULL,
        RiskLevel VARCHAR(50) NOT NULL,
        ProcessedEvidenceJson JSON NOT NULL,
        CollectedAt DATETIME(3) NOT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        UNIQUE KEY uq_device_evidence_snapshot_source (SnapshotID, DeviceSourceID),
        KEY ix_device_evidence_snapshot (SnapshotID, ID),
        KEY ix_device_evidence_company_name (CompanyID, DeviceName),
        CONSTRAINT fk_device_evidence_snapshot
            FOREIGN KEY (SnapshotID) REFERENCES StackCTRLDeviceEvidenceSnapshots(ID)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

function mysqlDateTime(value) {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return date.toISOString().slice(0, 19).replace('T', ' ');
}

function deriveDeviceEvidence(payload = {}) {
    const devicesInput = Array.isArray(payload.devices) ? payload.devices : [];
    const alertsInput = Array.isArray(payload.alerts) ? payload.alerts : [];
    const warnings = [...new Set(Array.isArray(payload.warnings) ? payload.warnings : [])];
    const dashboardSource = buildDeviceDashboardSource({
        devicesRows: devicesInput,
        alertsRows: alertsInput,
        summary: payload.summary || {}
    });
    const devices = dashboardSource.devices;
    const metrics = dashboardSource.dashboardMetrics;
    const riskEngine = buildRiskEngine({
        sources: [{
            sourceKey: 'devices',
            status: 'available',
            isExpected: true,
            metrics,
            dashboardMetrics: metrics
        }],
        dataCompleteness: { score: 100 }
    });
    const stackctrlHealthScore = riskEngine.domainHealthScores.devices;
    const stackctrlRiskScore = riskEngine.domainRiskScores.devices;
    const dashboardMetrics = {
        ...metrics,
        stackctrlRiskScore,
        stackctrlHealthScore
    };
    const expectedRecordCount = Number(payload.summary?.totalDevices ?? devices.length) || 0;
    const omittedRecordCount = Math.max(0, expectedRecordCount - devices.length);
    const verifiedEmpty = payload.success === true && Array.isArray(payload.devices) && payload.summary?.totalDevices === 0;
    const isComplete = payload.success !== false && (devices.length > 0 || verifiedEmpty) && devices.length === expectedRecordCount;
    const completenessPercent = expectedRecordCount > 0
        ? Number(((devices.length / expectedRecordCount) * 100).toFixed(2))
        : (isComplete ? 100 : 0);

    return {
        devices,
        sourceDevices: devicesInput,
        alerts: alertsInput,
        dashboardMetrics,
        activityBreakdown: dashboardSource.activityBreakdown,
        complianceBreakdown: dashboardSource.complianceBreakdown,
        riskDistribution: dashboardSource.riskDistribution,
        stackctrlRiskScore,
        stackctrlHealthScore,
        expectedRecordCount,
        omittedRecordCount,
        completenessPercent,
        isComplete,
        warnings,
        collectionStatus: isComplete ? (warnings.length ? 'completed_with_warnings' : 'complete') : 'incomplete',
        incompleteReason: isComplete
            ? null
            : !devices.length ? 'The processed Device Protection dashboard contained no device evidence.'
                : `The processed Device Protection dashboard expected ${expectedRecordCount} devices but contained ${devices.length}.`
    };
}

function createDeviceEvidenceStore({ pool, logger = console, now = () => new Date() } = {}) {
    if (!pool?.query) throw new Error('Device evidence storage requires a database pool');

    async function ensureSchema() {
        for (const statement of DEVICE_EVIDENCE_SCHEMA) await pool.query(statement);
        return { tables: ['StackCTRLDeviceEvidenceSnapshots', 'StackCTRLDeviceEvidence'] };
    }

    async function persistProcessedEvidence({
        companyId,
        tenantKey = 'sunbird',
        payload,
        collectionTrigger = 'scheduled_30_minute',
        sourceEndpoint = '/api/microsoft-devices'
    } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        const evidence = deriveDeviceEvidence(payload);
        const collectedAt = payload?.collectionStartedAt ? new Date(payload.collectionStartedAt) : now();
        const sourceFetchedAt = payload?.fetchedAt || collectedAt;
        const evidenceHash = crypto.createHash('sha256').update(JSON.stringify({
            devices: evidence.sourceDevices,
            alerts: evidence.alerts,
            dashboardMetrics: evidence.dashboardMetrics
        })).digest('hex');
        const connection = typeof pool.getConnection === 'function' ? await pool.getConnection() : pool;
        const ownsConnection = connection !== pool;
        let snapshotId = null;
        try {
            if (typeof connection.beginTransaction === 'function') await connection.beginTransaction();
            const metrics = evidence.dashboardMetrics;
            const [snapshotResult] = await connection.query(
                `INSERT INTO StackCTRLDeviceEvidenceSnapshots
                 (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete,
                  CollectedAt, SourceFetchedAt, EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount,
                  CompletenessPercent, TotalDevices, CompliantDevices, NonCompliantDevices, UnknownDevices,
                  EncryptedDevices, NotEncryptedDevices, ComplianceRatePercent, EncryptionRatePercent,
                  ActiveDevices24h, StaleDevices, Dead30Days, HighRiskDevices, UnmanagedDevices,
                  SecurityAlertsCount, DeviceSecurityScore, ActivityBreakdownJson, ComplianceBreakdownJson,
                  RiskDistributionJson, StackCTRLRiskScore, StackCTRLHealthScore, DashboardMetricsJson,
                  SourceAuditJson, EvidenceSha256, IncompleteReason)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    numericCompanyId, tenantKey, collectionTrigger, sourceEndpoint,
                    evidence.collectionStatus, evidence.isComplete ? 1 : 0,
                    mysqlDateTime(collectedAt), mysqlDateTime(sourceFetchedAt), evidence.devices.length,
                    evidence.expectedRecordCount, evidence.omittedRecordCount, evidence.completenessPercent,
                    metrics.totalDevices, metrics.compliantDevices, metrics.nonCompliantDevices, metrics.unknownDevices,
                    metrics.encryptedDevices, metrics.notEncryptedDevices, metrics.complianceRate, metrics.encryptionRate,
                    metrics.activeDevices24h, metrics.staleDevices, metrics.dead30Days, metrics.highRiskDevices,
                    metrics.unmanagedDevices, metrics.securityAlerts, metrics.deviceSecurityScore,
                    JSON.stringify(evidence.activityBreakdown), JSON.stringify(evidence.complianceBreakdown),
                    JSON.stringify(evidence.riskDistribution), evidence.stackctrlRiskScore, evidence.stackctrlHealthScore,
                    JSON.stringify(metrics), JSON.stringify({
                        source: 'stackctrl_processed_device_dashboard',
                        dashboardFetchedAt: payload?.fetchedAt || null,
                        collectionTrigger,
                        sourceEndpoint,
                        warnings: evidence.warnings,
                        credentialSource: 'environment',
                        credentialPath: 'MICROSOFT_CLIENT_SECRET (Azure Key Vault, shared with dashboard)'
                    }),
                    evidenceHash, evidence.incompleteReason
                ]
            );
            snapshotId = snapshotResult.insertId;

            for (let index = 0; index < evidence.devices.length; index += 1) {
                const device = evidence.devices[index];
                const sourceDevice = evidence.sourceDevices[index] || device;
                const deviceSourceId = String(device.id || device.deviceName || `row-${index + 1}`).slice(0, 255);
                await connection.query(
                    `INSERT INTO StackCTRLDeviceEvidence
                     (SnapshotID, CompanyID, TenantKey, DeviceSourceID, DeviceName, OperatingSystem,
                      ComplianceState, IsEncrypted, ManagementAgent, LastSyncAt, DaysSinceLastSync,
                      RiskLevel, ProcessedEvidenceJson, CollectedAt)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        snapshotId, numericCompanyId, tenantKey, deviceSourceId, device.deviceName,
                        device.operatingSystem, device.complianceState, device.isEncrypted ? 1 : 0,
                        device.managementAgent, mysqlDateTime(device.lastSyncDateTime),
                        daysSinceLastSync(device), getDeviceRiskLevel(device),
                        JSON.stringify(sourceDevice), mysqlDateTime(collectedAt)
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

        logger.log(`[Device Evidence] Stored snapshot ${snapshotId} with ${evidence.devices.length} processed device records.`);
        return {
            snapshotId,
            companyId: numericCompanyId,
            collectedAt: collectedAt.toISOString(),
            recordCount: evidence.devices.length,
            omittedCount: evidence.omittedRecordCount,
            isComplete: evidence.isComplete,
            status: evidence.collectionStatus,
            warnings: evidence.warnings,
            dashboardMetrics: evidence.dashboardMetrics
        };
    }

    async function recordCollectionFailure({
        companyId,
        tenantKey = 'sunbird',
        collectionTrigger = 'scheduled_30_minute',
        sourceEndpoint = 'Microsoft Graph processed by StackCTRL Device Protection',
        error
    } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        const message = String(error?.message || error || 'Device evidence collection failed').slice(0, 5000);
        const [result] = await pool.query(
            `INSERT INTO StackCTRLDeviceEvidenceSnapshots
             (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete,
              CollectedAt, EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount,
              CompletenessPercent, ActivityBreakdownJson, ComplianceBreakdownJson,
              RiskDistributionJson, DashboardMetricsJson, SourceAuditJson,
              IncompleteReason, ErrorMessage)
             VALUES (?, ?, ?, ?, 'failed', 0, ?, 0, 0, 0, 0, ?, ?, ?, ?, ?, ?, ?)`,
            [
                numericCompanyId, tenantKey, collectionTrigger, sourceEndpoint, mysqlDateTime(now()),
                JSON.stringify({ active24h: 0, stale7days: 0, dead30days: 0 }),
                JSON.stringify({ compliant: 0, nonCompliant: 0, unknown: 0 }),
                JSON.stringify({ safe: 0, medium: 0, high: 0 }),
                JSON.stringify({}),
                JSON.stringify({
                    source: 'stackctrl_processed_device_dashboard',
                    collectionTrigger,
                    sourceEndpoint,
                    credentialSource: 'environment',
                    credentialPath: 'MICROSOFT_CLIENT_SECRET (Azure Key Vault, shared with dashboard)'
                }),
                'Device evidence collection did not complete.', message
            ]
        );
        return { snapshotId: result.insertId, companyId: numericCompanyId, status: 'failed', message };
    }

    return { ensureSchema, persistProcessedEvidence, recordCollectionFailure, deriveDeviceEvidence };
}

module.exports = {
    DEVICE_EVIDENCE_SCHEMA,
    createDeviceEvidenceStore,
    deriveDeviceEvidence
};
