const crypto = require('crypto');
const { buildIdentityDashboardSource } = require('./identity-dashboard-source');
const { buildRiskEngine } = require('./risk-engine');

const IDENTITY_EVIDENCE_SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRLIdentityEvidenceSnapshots (
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
        TotalUsers INT NOT NULL DEFAULT 0,
        MFAEnabledUsers INT NOT NULL DEFAULT 0,
        UsersWithoutMFA INT NOT NULL DEFAULT 0,
        MFACoveragePercent DECIMAL(6,2) NOT NULL DEFAULT 0,
        PrivilegedUsers INT NOT NULL DEFAULT 0,
        AdminsWithoutMFA INT NOT NULL DEFAULT 0,
        HighRiskUsers INT NOT NULL DEFAULT 0,
        SignInIssues INT NOT NULL DEFAULT 0,
        ExternalUsers INT NOT NULL DEFAULT 0,
        UnknownDevices INT NOT NULL DEFAULT 0,
        MultiplePrivilegedRoles INT NOT NULL DEFAULT 0,
        RiskDistributionJson JSON NOT NULL,
        AccessLevelCountsJson JSON NOT NULL,
        IdentityHealthScoresJson JSON NOT NULL,
        StackCTRLRiskScore DECIMAL(6,2) NULL,
        StackCTRLHealthScore DECIMAL(6,2) NULL,
        DashboardMetricsJson JSON NOT NULL,
        SourceAuditJson JSON NULL,
        EvidenceSha256 CHAR(64) NULL,
        IncompleteReason TEXT NULL,
        ErrorMessage TEXT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        KEY ix_identity_evidence_latest (CompanyID, IsComplete, CollectedAt, ID),
        KEY ix_identity_evidence_status (CollectionStatus, CollectedAt)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRLIdentityUserEvidence (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        SnapshotID BIGINT UNSIGNED NOT NULL,
        CompanyID BIGINT NOT NULL,
        TenantKey VARCHAR(100) NOT NULL,
        UserSourceID VARCHAR(255) NULL,
        Name VARCHAR(500) NOT NULL,
        Email VARCHAR(500) NULL,
        JobTitle VARCHAR(500) NULL,
        RolesText TEXT NULL,
        RolesJson JSON NOT NULL,
        UserType VARCHAR(50) NOT NULL,
        MFAEnabled TINYINT(1) NOT NULL DEFAULT 0,
        AuthMethodCount INT NOT NULL DEFAULT 0,
        RiskLevel VARCHAR(50) NOT NULL,
        AccountStatus VARCHAR(50) NOT NULL,
        LastSignInAt DATETIME NULL,
        DaysSinceLastSignIn INT NULL,
        SignInStatus VARCHAR(100) NULL,
        Location VARCHAR(500) NULL,
        Device VARCHAR(500) NULL,
        Phone VARCHAR(255) NULL,
        ProcessedEvidenceJson JSON NOT NULL,
        CollectedAt DATETIME(3) NOT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        UNIQUE KEY uq_identity_user_snapshot_source (SnapshotID, UserSourceID),
        KEY ix_identity_user_evidence_snapshot (SnapshotID, ID),
        KEY ix_identity_user_evidence_company_email (CompanyID, Email),
        CONSTRAINT fk_identity_user_evidence_snapshot
            FOREIGN KEY (SnapshotID) REFERENCES StackCTRLIdentityEvidenceSnapshots(ID)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

function roleName(role) {
    return typeof role === 'string' ? role : role?.name || role?.roleName || '';
}

function mysqlDateTime(value) {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return date.toISOString().slice(0, 19).replace('T', ' ');
}

function deriveIdentityEvidence(payload = {}) {
    const usersInput = Array.isArray(payload.users) ? payload.users : [];
    const dashboardSource = buildIdentityDashboardSource({
        metricsRow: {
            active_users_24h: payload.summary?.activeUsers24h,
            signInCollectionStatus: payload.signInCollection?.status
        },
        usersRows: usersInput
    });
    const users = dashboardSource.users;
    const mediumRiskUsers = users.filter(user => String(user.riskLevel).toUpperCase() === 'MEDIUM').length;
    const inactiveUsers = users.filter(user => Number.isFinite(user.lastSignIn?.daysSince) && user.lastSignIn.daysSince > 30).length;
    const riskDistribution = {
        safe: Math.max(0, users.length - dashboardSource.dashboardMetrics.highRiskUsers - mediumRiskUsers),
        medium: mediumRiskUsers,
        high: dashboardSource.dashboardMetrics.highRiskUsers
    };
    const accessLevelCounts = {
        privileged: dashboardSource.dashboardMetrics.privilegedUsers,
        standard: Math.max(0, users.length - dashboardSource.dashboardMetrics.privilegedUsers)
    };
    const identityHealthScores = {
        mfa: dashboardSource.dashboardMetrics.mfaCoverage,
        riskPosture: users.length
            ? Math.round(((riskDistribution.safe + (riskDistribution.medium * 0.5)) / users.length) * 100)
            : 0,
        recentActivity: users.length ? Math.round(((users.length - inactiveUsers) / users.length) * 100) : 0
    };
    const riskEngine = buildRiskEngine({
        sources: [{
            sourceKey: 'identity',
            status: 'available',
            isExpected: true,
            metrics: dashboardSource.dashboardMetrics,
            dashboardMetrics: dashboardSource.dashboardMetrics
        }],
        dataCompleteness: { score: 100 }
    });
    const stackctrlHealthScore = riskEngine.domainHealthScores.identity;
    const stackctrlRiskScore = riskEngine.domainRiskScores.identity;
    const dashboardMetrics = {
        ...dashboardSource.dashboardMetrics,
        mediumRiskUsers,
        safeUsers: riskDistribution.safe,
        inactiveUsers,
        riskDistribution,
        accessLevelCounts,
        identityHealthScores,
        stackctrlRiskScore,
        stackctrlHealthScore
    };
    const expectedRecordCount = Number(payload.summary?.totalUsers ?? users.length) || 0;
    const omittedRecordCount = Math.max(0, expectedRecordCount - users.length);
    const verifiedEmpty = payload.success === true && Array.isArray(payload.users) && payload.summary?.totalUsers === 0;
    const isComplete = payload.success !== false && (users.length > 0 || verifiedEmpty) && users.length === expectedRecordCount;
    const completenessPercent = expectedRecordCount > 0
        ? Number(((users.length / expectedRecordCount) * 100).toFixed(2))
        : 0;

    return {
        users,
        sourceUsers: usersInput,
        dashboardMetrics,
        riskDistribution,
        accessLevelCounts,
        identityHealthScores,
        stackctrlRiskScore,
        stackctrlHealthScore,
        expectedRecordCount,
        omittedRecordCount,
        completenessPercent,
        isComplete,
        incompleteReason: isComplete
            ? null
            : !users.length ? 'The processed Identity dashboard contained no user evidence.'
                : `The processed Identity dashboard expected ${expectedRecordCount} users but contained ${users.length}.`
    };
}

function createIdentityEvidenceStore({ pool, logger = console, now = () => new Date() } = {}) {
    if (!pool?.query) throw new Error('Identity evidence storage requires a database pool');

    async function ensureSchema() {
        for (const statement of IDENTITY_EVIDENCE_SCHEMA) await pool.query(statement);
        return { tables: ['StackCTRLIdentityEvidenceSnapshots', 'StackCTRLIdentityUserEvidence'] };
    }

    async function persistProcessedEvidence({
        companyId,
        tenantKey = 'sunbird',
        payload,
        collectionTrigger = 'scheduled_30_minute',
        sourceEndpoint = '/api/sunbird/identity-dashboard'
    } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        const evidence = deriveIdentityEvidence(payload);
        const collectedAt = payload?.collectionStartedAt ? new Date(payload.collectionStartedAt) : now();
        const sourceFetchedAt = payload?.fetchedAt || collectedAt;
        const evidenceHash = crypto.createHash('sha256').update(JSON.stringify({
            users: evidence.sourceUsers,
            dashboardMetrics: evidence.dashboardMetrics
        })).digest('hex');
        const connection = typeof pool.getConnection === 'function' ? await pool.getConnection() : pool;
        const ownsConnection = connection !== pool;
        let snapshotId = null;
        try {
            if (typeof connection.beginTransaction === 'function') await connection.beginTransaction();
            const metrics = evidence.dashboardMetrics;
            const [snapshotResult] = await connection.query(
                `INSERT INTO StackCTRLIdentityEvidenceSnapshots
                 (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete,
                  CollectedAt, SourceFetchedAt, EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount,
                  CompletenessPercent, TotalUsers, MFAEnabledUsers, UsersWithoutMFA, MFACoveragePercent,
                  PrivilegedUsers, AdminsWithoutMFA, HighRiskUsers, SignInIssues, ExternalUsers,
                  UnknownDevices, MultiplePrivilegedRoles, RiskDistributionJson, AccessLevelCountsJson,
                  IdentityHealthScoresJson, StackCTRLRiskScore, StackCTRLHealthScore, DashboardMetricsJson,
                  SourceAuditJson, EvidenceSha256, IncompleteReason)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    numericCompanyId, tenantKey, collectionTrigger, sourceEndpoint,
                    evidence.isComplete ? 'complete' : 'incomplete', evidence.isComplete ? 1 : 0,
                    mysqlDateTime(collectedAt), mysqlDateTime(sourceFetchedAt), evidence.users.length,
                    evidence.expectedRecordCount, evidence.omittedRecordCount, evidence.completenessPercent,
                    metrics.totalUsers, metrics.mfaEnabled, metrics.mfaMissing, metrics.mfaCoverage ?? 0,
                    metrics.privilegedUsers, metrics.adminsWithoutMfa, metrics.highRiskUsers,
                    metrics.signInIssues, metrics.externalUsers, metrics.unknownDevices,
                    metrics.multiplePrivilegedRoles, JSON.stringify(evidence.riskDistribution),
                    JSON.stringify(evidence.accessLevelCounts), JSON.stringify(evidence.identityHealthScores),
                    evidence.stackctrlRiskScore, evidence.stackctrlHealthScore,
                    JSON.stringify(metrics), JSON.stringify({
                        source: 'stackctrl_processed_identity_dashboard',
                        dashboardFetchedAt: payload?.fetchedAt || null,
                        tenantId: payload?.sourceTenantId || null,
                        collectionTrigger,
                        sourceEndpoint
                    }),
                    evidenceHash, evidence.incompleteReason
                ]
            );
            snapshotId = snapshotResult.insertId;

            for (let index = 0; index < evidence.users.length; index += 1) {
                const user = evidence.users[index];
                const sourceUser = evidence.sourceUsers[index] || user;
                const roles = user.roles.map(roleName).filter(Boolean);
                const userSourceId = String(user.id || user.userPrincipalName || user.mail || `row-${index + 1}`).slice(0, 255);
                await connection.query(
                    `INSERT INTO StackCTRLIdentityUserEvidence
                     (SnapshotID, CompanyID, TenantKey, UserSourceID, Name, Email, JobTitle, RolesText,
                      RolesJson, UserType, MFAEnabled, AuthMethodCount, RiskLevel, AccountStatus,
                      LastSignInAt, DaysSinceLastSignIn, SignInStatus, Location, Device, Phone,
                      ProcessedEvidenceJson, CollectedAt)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        snapshotId, numericCompanyId, tenantKey, userSourceId, user.displayName,
                        user.mail || user.userPrincipalName, user.jobTitle, roles.join(', '),
                        JSON.stringify(roles), user.isExternal ? 'External' : 'Internal',
                        user.mfaEnabled === true ? 1 : 0, user.authMethodCount ?? 0, user.riskLevel,
                        user.accountEnabled === false ? 'Disabled' : 'Active',
                        mysqlDateTime(user.lastSignIn?.dateTime), user.lastSignIn?.daysSince,
                        user.lastSignIn?.status || null, user.lastSignIn?.location || null,
                        user.lastSignIn?.device || null, user.mobilePhone || null,
                        JSON.stringify(sourceUser), mysqlDateTime(collectedAt)
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

        logger.log(`[Identity Evidence] Stored snapshot ${snapshotId} with ${evidence.users.length} processed user records.`);
        return {
            snapshotId,
            companyId: numericCompanyId,
            collectedAt: collectedAt.toISOString(),
            recordCount: evidence.users.length,
            omittedCount: evidence.omittedRecordCount,
            isComplete: evidence.isComplete,
            dashboardMetrics: evidence.dashboardMetrics
        };
    }

    async function recordCollectionFailure({
        companyId,
        tenantKey = 'sunbird',
        collectionTrigger = 'scheduled_30_minute',
        sourceEndpoint = 'Microsoft Graph processed by StackCTRL Identity Protection',
        error
    } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        const message = String(error?.message || error || 'Identity evidence collection failed').slice(0, 5000);
        const [result] = await pool.query(
            `INSERT INTO StackCTRLIdentityEvidenceSnapshots
             (CompanyID, TenantKey, CollectionTrigger, SourceEndpoint, CollectionStatus, IsComplete,
              CollectedAt, EvidenceRecordCount, ExpectedRecordCount, OmittedRecordCount,
              CompletenessPercent, RiskDistributionJson, AccessLevelCountsJson,
              IdentityHealthScoresJson, DashboardMetricsJson, SourceAuditJson,
              IncompleteReason, ErrorMessage)
             VALUES (?, ?, ?, ?, 'failed', 0, ?, 0, 0, 0, 0, ?, ?, ?, ?, ?, ?, ?)`,
            [
                numericCompanyId, tenantKey, collectionTrigger, sourceEndpoint, mysqlDateTime(now()),
                JSON.stringify({ safe: 0, medium: 0, high: 0 }),
                JSON.stringify({ privileged: 0, standard: 0 }),
                JSON.stringify({ mfa: 0, riskPosture: 0, recentActivity: 0 }),
                JSON.stringify({}),
                JSON.stringify({ source: 'stackctrl_processed_identity_dashboard', collectionTrigger, sourceEndpoint }),
                'Identity evidence collection did not complete.', message
            ]
        );
        return { snapshotId: result.insertId, companyId: numericCompanyId, status: 'failed', message };
    }

    return { ensureSchema, persistProcessedEvidence, recordCollectionFailure, deriveIdentityEvidence };
}

module.exports = {
    IDENTITY_EVIDENCE_SCHEMA,
    createIdentityEvidenceStore,
    deriveIdentityEvidence
};
