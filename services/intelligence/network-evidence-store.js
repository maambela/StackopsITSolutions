const crypto = require('crypto');
const { buildNetworkDashboardSource } = require('./network-dashboard-source');
const { buildRiskEngine } = require('./risk-engine');
const { assertCollectionOwner } = require('./graph-collection-ownership');

const NETWORK_EVIDENCE_SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRLNetworkEvidenceSnapshots (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        CompanyID BIGINT NOT NULL,
        TenantKey VARCHAR(100) NOT NULL,
        CollectionTrigger VARCHAR(50) NOT NULL,
        SourceSystem VARCHAR(100) NOT NULL DEFAULT 'Cloudflare Zero Trust via StackCTRL',
        SourceEndpoint VARCHAR(255) NOT NULL,
        CollectionStatus VARCHAR(30) NOT NULL,
        IsComplete TINYINT(1) NOT NULL DEFAULT 0,
        CollectedAt DATETIME(3) NOT NULL,
        SourceFetchedAt DATETIME(3) NULL,
        EvidenceRecordCount INT NOT NULL DEFAULT 0,
        ExpectedRecordCount INT NOT NULL DEFAULT 0,
        OmittedRecordCount INT NOT NULL DEFAULT 0,
        CompletenessPercent DECIMAL(6,2) NOT NULL DEFAULT 0,
        ProtectedApps INT NOT NULL DEFAULT 0,
        EnrolledDevices INT NOT NULL DEFAULT 0,
        GatewayPolicies INT NOT NULL DEFAULT 0,
        ActiveGatewayPolicies INT NOT NULL DEFAULT 0,
        DeniedAccessEvents INT NOT NULL DEFAULT 0,
        RecentAccessEvents INT NOT NULL DEFAULT 0,
        NetworkSecurityScore DECIMAL(6,2) NOT NULL DEFAULT 0,
        DlpProfiles INT NOT NULL DEFAULT 0,
        IdentityProviders INT NOT NULL DEFAULT 0,
        SectionErrors INT NOT NULL DEFAULT 0,
        PermissionGaps INT NOT NULL DEFAULT 0,
        ServiceCoverageJson JSON NOT NULL,
        AccessActivityJson JSON NOT NULL,
        StackCTRLRiskScore DECIMAL(6,2) NULL,
        StackCTRLHealthScore DECIMAL(6,2) NULL,
        DashboardMetricsJson JSON NOT NULL,
        SourceAuditJson JSON NULL,
        EvidenceSha256 CHAR(64) NULL,
        IncompleteReason TEXT NULL,
        ErrorMessage TEXT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        KEY ix_network_evidence_latest (CompanyID, IsComplete, CollectedAt, ID),
        KEY ix_network_evidence_status (CollectionStatus, CollectedAt)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRLNetworkEvidence (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        SnapshotID BIGINT UNSIGNED NOT NULL,
        CompanyID BIGINT NOT NULL,
        TenantKey VARCHAR(100) NOT NULL,
        EvidenceKind VARCHAR(30) NOT NULL,
        SourceID VARCHAR(255) NULL,
        Name VARCHAR(500) NOT NULL,
        Status VARCHAR(50) NULL,
        ProcessedEvidenceJson JSON NOT NULL,
        CollectedAt DATETIME(3) NOT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        UNIQUE KEY uq_network_evidence_snapshot_source (SnapshotID, EvidenceKind, SourceID),
        KEY ix_network_evidence_snapshot (SnapshotID, ID),
        KEY ix_network_evidence_company_kind (CompanyID, EvidenceKind),
        CONSTRAINT fk_network_evidence_snapshot
            FOREIGN KEY (SnapshotID) REFERENCES StackCTRLNetworkEvidenceSnapshots(ID)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

const NETWORK_EVIDENCE_KINDS = [
    { key: 'accessApps', kind: 'access_app', items: payload => payload.apps || [] },
    { key: 'devices', kind: 'device', items: payload => payload.devices || [] },
    { key: 'deviceRegistrations', kind: 'device_registration', items: payload => payload.deviceRegistrations || [] },
    { key: 'devicePosture', kind: 'device_posture', items: payload => payload.devicePosture || [] },
    { key: 'gatewayRules', kind: 'gateway_rule', items: payload => payload.gatewayRules || [] },
    { key: 'accessPolicies', kind: 'access_policy', items: payload => payload.policies || payload.accessPolicies || [] },
    { key: 'accessLogs', kind: 'access_log', items: payload => payload.accessLogs || [] },
    { key: 'dlpProfiles', kind: 'dlp_profile', items: payload => payload.dlpProfiles || [] },
    { key: 'warpProfiles', kind: 'warp_profile', items: payload => payload.warpProfiles || [] },
    { key: 'virtualNetworks', kind: 'virtual_network', items: payload => payload.virtualNetworks || [] },
    { key: 'gatewayAppTypes', kind: 'gateway_app_type', items: payload => payload.gatewayAppTypes || [] },
    { key: 'permissionMatrix', kind: 'permission_family', items: payload => payload.permissionMatrix || [] },
    { key: 'auditLogs', kind: 'audit_log', items: payload => payload.auditLogs || [] },
    { key: 'accountLogs', kind: 'account_log', items: payload => payload.accountLogs || [] },
    { key: 'securityInsights', kind: 'security_insight', items: payload => payload.securityInsights || [] },
    { key: 'applicationSecurityReports', kind: 'appsec_report', items: payload => payload.applicationSecurityReports || [] },
    { key: 'apiGatewayOperations', kind: 'api_gateway_operation', items: payload => payload.apiGatewayOperations || [] },
    { key: 'casbFindings', kind: 'casb_finding', items: payload => payload.casbFindings || [] },
    { key: 'tunnels', kind: 'tunnel', items: payload => payload.tunnels || [] },
    { key: 'cloudforceRequests', kind: 'cloudforce_one', items: payload => payload.cloudforceRequests || [] },
    { key: 'intelFeeds', kind: 'intel_feed', items: payload => payload.intelFeeds || [] },
    { key: 'dnsFirewallRules', kind: 'dns_firewall', items: payload => payload.dnsFirewallRules || [] },
    { key: 'loadBalancerPools', kind: 'load_balancer_pool', items: payload => payload.loadBalancerPools || [] },
    { key: 'loadBalancerMonitors', kind: 'load_balancer_monitor', items: payload => payload.loadBalancerMonitors || [] },
    { key: 'magicWanSites', kind: 'magic_wan_site', items: payload => payload.magicWanSites || [] },
    { key: 'magicWanRoutes', kind: 'magic_wan_route', items: payload => payload.magicWanRoutes || [] },
    { key: 'mtlsCertificates', kind: 'mtls_certificate', items: payload => payload.mtlsCertificates || [] },
    { key: 'accessGroups', kind: 'access_group', items: payload => payload.accessGroups || [] },
    { key: 'accessOrganizations', kind: 'access_organization', items: payload => payload.accessOrganizations || [] },
    { key: 'accessCertificates', kind: 'access_certificate', items: payload => payload.accessCertificates || [] },
    { key: 'warpConnectors', kind: 'warp_connector', items: payload => payload.warpConnectors || [] },
    { key: 'teamnetRoutes', kind: 'network_route', items: payload => payload.teamnetRoutes || [] },
    { key: 'teamsDexTests', kind: 'teams_dex_test', items: payload => payload.teamsDexTests || [] }
];

const NETWORK_SNAPSHOT_COMPAT_COLUMNS = Object.freeze([
    ['SourceFetchedAt', "DATETIME(3) NULL AFTER CollectedAt"],
    ['DlpProfiles', "INT NOT NULL DEFAULT 0 AFTER NetworkSecurityScore"],
    ['IdentityProviders', "INT NOT NULL DEFAULT 0 AFTER DlpProfiles"],
    ['SectionErrors', "INT NOT NULL DEFAULT 0 AFTER IdentityProviders"],
    ['PermissionGaps', "INT NOT NULL DEFAULT 0 AFTER SectionErrors"],
    ['StackCTRLRiskScore', "DECIMAL(6,2) NULL AFTER AccessActivityJson"],
    ['StackCTRLHealthScore', "DECIMAL(6,2) NULL AFTER StackCTRLRiskScore"],
    ['SourceAuditJson', "JSON NULL AFTER DashboardMetricsJson"],
    ['EvidenceSha256', "CHAR(64) NULL AFTER SourceAuditJson"],
    ['IncompleteReason', "TEXT NULL AFTER EvidenceSha256"],
    ['ErrorMessage', "TEXT NULL AFTER IncompleteReason"]
]);

function buildInsert(tableName, columnValues) {
    const entries = Object.entries(columnValues);
    if (!entries.length) throw new Error(`Cannot build INSERT for ${tableName} without columns`);
    const columns = entries.map(([column]) => column);
    const values = entries.map(([, value]) => value);
    return {
        sql: `INSERT INTO ${tableName} (${columns.join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`,
        values
    };
}

function mysqlDateTime(value) {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return date.toISOString().slice(0, 19).replace('T', ' ');
}

function deriveNetworkEvidence(payload = {}) {
    const dashboardSource = buildNetworkDashboardSource({
        overview: payload.overview || payload.dashboardMetrics || {},
        accessLogs: payload.accessLogs || [],
        sections: payload.sections || {},
        apps: payload.apps || [],
        devices: payload.devices || [],
        deviceRegistrations: payload.deviceRegistrations || [],
        devicePosture: payload.devicePosture || [],
        gatewayRules: payload.gatewayRules || [],
        accessPolicies: payload.policies || payload.accessPolicies || [],
        dlpProfiles: payload.dlpProfiles || [],
        warpProfiles: payload.warpProfiles || [],
        virtualNetworks: payload.virtualNetworks || [],
        gatewayAppTypes: payload.gatewayAppTypes || [],
        permissionMatrix: payload.permissionMatrix || [],
        auditLogs: payload.auditLogs || [],
        accountLogs: payload.accountLogs || [],
        securityInsights: payload.securityInsights || [],
        applicationSecurityReports: payload.applicationSecurityReports || [],
        apiGatewayOperations: payload.apiGatewayOperations || [],
        casbFindings: payload.casbFindings || [],
        tunnels: payload.tunnels || [],
        cloudforceRequests: payload.cloudforceRequests || [],
        intelFeeds: payload.intelFeeds || [],
        dnsFirewallRules: payload.dnsFirewallRules || [],
        loadBalancerPools: payload.loadBalancerPools || [],
        loadBalancerMonitors: payload.loadBalancerMonitors || [],
        magicWanSites: payload.magicWanSites || [],
        magicWanRoutes: payload.magicWanRoutes || [],
        mtlsCertificates: payload.mtlsCertificates || [],
        accessGroups: payload.accessGroups || [],
        accessOrganizations: payload.accessOrganizations || [],
        accessCertificates: payload.accessCertificates || [],
        warpConnectors: payload.warpConnectors || [],
        teamnetRoutes: payload.teamnetRoutes || [],
        teamsDexTests: payload.teamsDexTests || []
    });
    const metrics = dashboardSource.dashboardMetrics;
    const riskEngine = buildRiskEngine({
        sources: [{
            sourceKey: 'cloudflare_network_security',
            status: 'available',
            isExpected: true,
            metrics,
            dashboardMetrics: metrics
        }],
        dataCompleteness: { score: 100 }
    });
    const stackctrlHealthScore = riskEngine.domainHealthScores.network;
    const stackctrlRiskScore = riskEngine.domainRiskScores.network;
    const dashboardMetrics = {
        ...metrics,
        stackctrlRiskScore,
        stackctrlHealthScore
    };
    const evidenceRows = [];
    for (const section of NETWORK_EVIDENCE_KINDS) {
        const items = section.items(payload);
        items.forEach((item, index) => {
            evidenceRows.push({
                kind: section.kind,
                sourceId: String(item.id || item.name || `${section.kind}-${index + 1}`).slice(0, 255),
                name: item.name || item.displayName || item.userEmail || item.hostname || `${section.kind} ${index + 1}`,
                status: item.status || item.decision || item.action || null,
                processed: item
            });
        });
    }
    const expectedRecordCount = evidenceRows.length;
    const omittedRecordCount = 0;
    const isComplete = Boolean(payload.success !== false);
    const completenessPercent = expectedRecordCount > 0 ? 100 : (isComplete ? 100 : 0);

    return {
        evidenceRows,
        dashboardMetrics,
        serviceCoverage: dashboardSource.serviceCoverage,
        accessActivity: dashboardSource.accessActivity,
        stackctrlRiskScore,
        stackctrlHealthScore,
        expectedRecordCount,
        omittedRecordCount,
        completenessPercent,
        isComplete,
        incompleteReason: isComplete ? null : 'The processed Network Security dashboard did not complete successfully.'
    };
}

function createNetworkEvidenceStore({ pool, logger = console, now = () => new Date() } = {}) {
    if (!pool?.query) throw new Error('Network evidence storage requires a database pool');

    async function ensureSchema() {
        for (const statement of NETWORK_EVIDENCE_SCHEMA) await pool.query(statement);
        const [rows] = await pool.query(
            `SELECT COLUMN_NAME
             FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = 'StackCTRLNetworkEvidenceSnapshots'`
        );
        const existingColumns = new Set((rows || []).map(row => String(row.COLUMN_NAME || row.column_name || '').toLowerCase()));
        for (const [columnName, definition] of NETWORK_SNAPSHOT_COMPAT_COLUMNS) {
            if (existingColumns.has(columnName.toLowerCase())) continue;
            await pool.query(`ALTER TABLE StackCTRLNetworkEvidenceSnapshots ADD COLUMN ${columnName} ${definition}`);
        }
        try {
            await pool.query(
                `ALTER TABLE StackCTRLNetworkEvidenceSnapshots
                 MODIFY SourceSystem VARCHAR(100) NOT NULL DEFAULT 'Cloudflare Zero Trust via StackCTRL'`
            );
        } catch (error) {
            logger.warn?.('[Network Evidence] Could not normalize SourceSystem default; continuing with explicit inserts.', error.message);
        }
        return { tables: ['StackCTRLNetworkEvidenceSnapshots', 'StackCTRLNetworkEvidence'] };
    }

    async function persistProcessedEvidence({
        companyId,
        tenantKey = 'sunbird',
        payload,
        collectionTrigger = 'scheduled_hourly',
        sourceEndpoint = 'Cloudflare Zero Trust processed by StackCTRL Network Security',
        signal, collectionStartedAt, accountScope, verifyCompany
    } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        signal?.throwIfAborted();
        const evidence = deriveNetworkEvidence(payload);
        const collectedAt = now();
        const sourceFetchedAt = payload?.fetchedAt || collectedAt;
        const evidenceHash = crypto.createHash('sha256').update(JSON.stringify({
            rows: evidence.evidenceRows,
            dashboardMetrics: evidence.dashboardMetrics
        })).digest('hex');
        signal?.throwIfAborted();
        const connection = typeof pool.getConnection === 'function' ? await pool.getConnection() : pool;
        const ownsConnection = connection !== pool;
        let snapshotId = null;
        let transactionStarted = false;
        try {
            signal?.throwIfAborted();
            if (typeof connection.beginTransaction === 'function') {
                await connection.beginTransaction();
                transactionStarted = true;
            }
            await assertCollectionOwner(connection, numericCompanyId);
            if (collectionStartedAt) {
                const [newer] = await connection.query(
                    `SELECT latest.ID FROM (
                         SELECT ID, CollectedAt, SourceFetchedAt FROM StackCTRLNetworkEvidenceSnapshots
                         WHERE CompanyID = ? AND IsComplete = 1 ORDER BY CollectedAt DESC, ID DESC LIMIT 1
                     ) latest WHERE latest.CollectedAt > ? OR latest.SourceFetchedAt > ?`,
                    [numericCompanyId, collectionStartedAt.toISOString().slice(0, 23).replace('T', ' '), mysqlDateTime(sourceFetchedAt)]
                );
                if (newer.length) {
                    if (transactionStarted) await connection.rollback();
                    return { companyId: numericCompanyId, status: 'superseded' };
                }
            }
            signal?.throwIfAborted();
            const metrics = evidence.dashboardMetrics;
            const snapshotInsert = buildInsert('StackCTRLNetworkEvidenceSnapshots', {
                CompanyID: numericCompanyId,
                TenantKey: tenantKey,
                CollectionTrigger: collectionTrigger,
                SourceSystem: 'Cloudflare Zero Trust via StackCTRL',
                SourceEndpoint: sourceEndpoint,
                CollectionStatus: evidence.isComplete ? 'complete' : 'incomplete',
                IsComplete: evidence.isComplete ? 1 : 0,
                CollectedAt: mysqlDateTime(collectedAt),
                SourceFetchedAt: mysqlDateTime(sourceFetchedAt),
                EvidenceRecordCount: evidence.evidenceRows.length,
                ExpectedRecordCount: evidence.expectedRecordCount,
                OmittedRecordCount: evidence.omittedRecordCount,
                CompletenessPercent: evidence.completenessPercent,
                ProtectedApps: metrics.protectedApps,
                EnrolledDevices: metrics.enrolledDevices,
                GatewayPolicies: metrics.gatewayPolicies,
                ActiveGatewayPolicies: metrics.activeGatewayPolicies,
                DeniedAccessEvents: metrics.deniedAccessEvents,
                RecentAccessEvents: metrics.recentAccessEvents,
                NetworkSecurityScore: metrics.networkSecurityScore,
                DlpProfiles: metrics.dlpProfiles,
                IdentityProviders: metrics.identityProviders,
                SectionErrors: metrics.sectionErrors,
                PermissionGaps: metrics.permissionGaps,
                ServiceCoverageJson: JSON.stringify(evidence.serviceCoverage),
                AccessActivityJson: JSON.stringify(evidence.accessActivity),
                StackCTRLRiskScore: evidence.stackctrlRiskScore,
                StackCTRLHealthScore: evidence.stackctrlHealthScore,
                DashboardMetricsJson: JSON.stringify(metrics),
                SourceAuditJson: JSON.stringify({
                    source: 'stackctrl_processed_network_dashboard',
                    dashboardFetchedAt: payload?.fetchedAt || null,
                    collectionTrigger,
                    sourceEndpoint,
                    accountScope,
                    credentialSource: 'environment',
                    credentialPath: 'CLOUDFLARE_ACCOUNT_ID + CLOUDFLARE_API_TOKEN (Azure Key Vault, shared with dashboard)'
                }),
                EvidenceSha256: evidenceHash,
                IncompleteReason: evidence.incompleteReason
            });
            const [snapshotResult] = await connection.query(snapshotInsert.sql, snapshotInsert.values);
            snapshotId = snapshotResult.insertId;

            for (const row of evidence.evidenceRows) {
                signal?.throwIfAborted();
                const evidenceInsert = buildInsert('StackCTRLNetworkEvidence', {
                    SnapshotID: snapshotId,
                    CompanyID: numericCompanyId,
                    TenantKey: tenantKey,
                    EvidenceKind: row.kind,
                    SourceID: row.sourceId,
                    Name: row.name,
                    Status: row.status,
                    ProcessedEvidenceJson: JSON.stringify(row.processed),
                    CollectedAt: mysqlDateTime(collectedAt)
                });
                await connection.query(evidenceInsert.sql, evidenceInsert.values);
            }
            if (verifyCompany) await verifyCompany(connection);
            await assertCollectionOwner(connection, numericCompanyId);
            signal?.throwIfAborted();
            if (typeof connection.commit === 'function') await connection.commit();
        } catch (error) {
            if (transactionStarted) await connection.rollback().catch(() => connection.destroy?.());
            throw error;
        } finally {
            if (ownsConnection && typeof connection.release === 'function') connection.release();
        }

        logger.log(`[Network Evidence] Stored snapshot ${snapshotId} with ${evidence.evidenceRows.length} processed network records.`);
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
        sourceEndpoint = 'Cloudflare Zero Trust processed by StackCTRL Network Security',
        error, database = pool
    } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isFinite(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        const message = String(error?.message || error || 'Network evidence collection failed').slice(0, 5000);
        const failureInsert = buildInsert('StackCTRLNetworkEvidenceSnapshots', {
            CompanyID: numericCompanyId,
            TenantKey: tenantKey,
            CollectionTrigger: collectionTrigger,
            SourceSystem: 'Cloudflare Zero Trust via StackCTRL',
            SourceEndpoint: sourceEndpoint,
            CollectionStatus: 'failed',
            IsComplete: 0,
            CollectedAt: mysqlDateTime(now()),
            EvidenceRecordCount: 0,
            ExpectedRecordCount: 0,
            OmittedRecordCount: 0,
            CompletenessPercent: 0,
            ServiceCoverageJson: JSON.stringify({}),
            AccessActivityJson: JSON.stringify({ total: 0, denied: 0 }),
            DashboardMetricsJson: JSON.stringify({}),
            SourceAuditJson: JSON.stringify({
                source: 'stackctrl_processed_network_dashboard',
                collectionTrigger,
                sourceEndpoint,
                credentialSource: 'environment',
                credentialPath: 'CLOUDFLARE_ACCOUNT_ID + CLOUDFLARE_API_TOKEN (Azure Key Vault, shared with dashboard)'
            }),
            IncompleteReason: 'Network evidence collection did not complete.',
            ErrorMessage: message
        });
        const [result] = await database.query(failureInsert.sql, failureInsert.values);
        return { snapshotId: result.insertId, companyId: numericCompanyId, status: 'failed', message };
    }

    return { ensureSchema, persistProcessedEvidence, recordCollectionFailure, deriveNetworkEvidence, NETWORK_EVIDENCE_KINDS };
}

module.exports = {
    NETWORK_EVIDENCE_SCHEMA,
    NETWORK_EVIDENCE_KINDS,
    createNetworkEvidenceStore,
    deriveNetworkEvidence
};
