const test = require('node:test');
const assert = require('node:assert/strict');

const { cloudflareNetworkSecurityAdapter, identityAdapter } = require('../services/intelligence/source-adapters');
const { buildIdentityDashboardSource } = require('../services/intelligence/identity-dashboard-source');
const buildIdentityDashboardContext = require('../services/intelligence/dashboard-context/identityDashboardContext');
const buildDevicesDashboardContext = require('../services/intelligence/dashboard-context/devicesDashboardContext');
const buildCloudflareDashboardContext = require('../services/intelligence/dashboard-context/cloudflareDashboardContext');

function source(overrides = {}) {
    return {
        sourceKey: 'identity',
        displayName: 'Identity Protection',
        status: 'available',
        isExpected: true,
        freshness: { lastUpdated: new Date().toISOString(), ageMinutes: 0 },
        metrics: {},
        evidence: [],
        warnings: [],
        rawReference: { table: 'test', recordId: 1 },
        ...overrides
    };
}

test('Cloudflare adapter refreshes the dashboard service when backend evidence is missing', async () => {
    let refreshCalls = 0;
    const sqlCalls = [];
    const result = await cloudflareNetworkSecurityAdapter({
        pool: { query: async sql => { sqlCalls.push(sql); return [[], []]; } },
        companyId: 1,
        refresh: false,
        capability: {
            sourceKey: 'cloudflare_network_security',
            displayName: 'Cloudflare Network Security',
            isExpected: true,
            isEnabled: true,
            refreshMode: 'refresh_if_stale',
            freshnessThresholdMinutes: 60,
            configuration: {}
        },
        async refreshSource(sourceKey, companyId) {
            refreshCalls += 1;
            assert.equal(sourceKey, 'cloudflare_network_security');
            assert.equal(companyId, 1);
            return {
                success: true,
                fetchedAt: new Date().toISOString(),
                overview: { securityStatus: 'Active', protectedApps: 4, enrolledDevices: 12 },
                accessLogs: [{ action: 'block' }, { action: 'allow' }],
                apps: [{ id: 'app-1' }],
                devices: [{ id: 'device-1' }],
                sections: {}
            };
        }
    });

    assert.equal(refreshCalls, 1);
    assert.equal(result.status, 'available');
    assert.equal(result.evidence.length, 1);
    assert.equal(result.metrics.protectedApps, 4);
    assert.equal(result.metrics.deniedAccessEvents, 1);
    assert.equal(sqlCalls.some(sql => /ORDER BY|GROUP BY|DISTINCT|\bOVER\s*\(/i.test(sql)), false);
    assert.equal(sqlCalls.some(sql => /MAX\(latest\.ID\)/i.test(sql)), true);
});

test('Cloudflare stored-evidence sort failure becomes a warning when live metrics succeed', async () => {
    const result = await cloudflareNetworkSecurityAdapter({
        pool: {
            async query() {
                const error = new Error('Out of sort memory, consider increasing server sort buffer size');
                error.code = 'ER_OUT_OF_SORTMEMORY';
                throw error;
            }
        },
        companyId: 1,
        refresh: true,
        capability: {
            sourceKey: 'cloudflare_network_security',
            displayName: 'Cloudflare Network Security',
            isExpected: true,
            isEnabled: true,
            refreshMode: 'refresh_if_stale',
            freshnessThresholdMinutes: 60,
            configuration: {}
        },
        async refreshSource() {
            return {
                fetchedAt: new Date().toISOString(),
                overview: { securityStatus: 'Active', protectedApps: 2 },
                accessLogs: []
            };
        }
    });

    assert.equal(result.status, 'available');
    assert.equal(result.metrics.protectedApps, 2);
    assert.equal(result.errorMessage, null);
    assert.match(result.warnings.join(' '), /stored evidence could not be loaded.*Out of sort memory/i);
});

test('a stalled source refresh becomes an explicit adapter error instead of blocking snapshot creation', async () => {
    const result = await cloudflareNetworkSecurityAdapter({
        pool: { query: async () => [[], []] },
        companyId: 1,
        refresh: true,
        refreshTimeoutMs: 15,
        capability: {
            sourceKey: 'cloudflare_network_security',
            displayName: 'Cloudflare Network Security',
            isExpected: true,
            isEnabled: true,
            refreshMode: 'refresh_if_stale',
            freshnessThresholdMinutes: 60,
            configuration: {}
        },
        async refreshSource() {
            return new Promise(() => {});
        }
    });

    assert.equal(result.status, 'error');
    assert.match(result.errorMessage, /source refresh exceeded 15ms/i);
    assert.match(result.warnings.join(' '), /source refresh exceeded 15ms/i);
});

test('dashboard context builders include StackCTRL calculated metrics and evidence lists', () => {
    const identity = buildIdentityDashboardContext(source({
        evidence: [{
            evidenceType: 'users',
            data: [
                { id: 1, userType: 'Member', mfaEnabled: true, riskLevel: 'SAFE', roles: ['User'], lastSignIn: { device: 'Laptop', status: 'Success', dateTime: new Date().toISOString() } },
                { id: 2, userType: 'Guest', mfaEnabled: false, riskLevel: 'HIGH', roles: ['Global Administrator'], isExternal: true, lastSignIn: { device: 'Unknown', status: 'Failed' } }
            ]
        }]
    }));
    assert.equal(identity.dashboardMetrics.mfaCoverage, 100);
    assert.equal(identity.dashboardMetrics.adminsWithoutMfa, 0);
    assert.equal(identity.dashboardMetrics.signInIssues, 1);
    assert.equal(identity.chartsData.riskDistribution.high, 1);

    const devices = buildDevicesDashboardContext(source({
        sourceKey: 'devices',
        displayName: 'Device Security',
        evidence: [
            { deviceName: 'Managed', complianceState: 'compliant', isEncrypted: true, managementAgent: 'mdm', lastSyncDateTime: new Date().toISOString() },
            { deviceName: 'At risk', complianceState: 'noncompliant', isEncrypted: false, managementAgent: 'unknown', lastSyncDateTime: '2025-01-01T00:00:00.000Z' }
        ]
    }));
    assert.equal(devices.dashboardMetrics.complianceRate, 50);
    assert.equal(devices.dashboardMetrics.encryptionRate, 50);
    assert.equal(devices.dashboardMetrics.dead30Days, 1);
    assert.equal(devices.dashboardMetrics.unmanagedDevices, 1);
});

test('workforce MFA excludes Guests and unknown user types from the denominator', () => {
    const usersRows = [
        { id: 'm1', userType: 'Member', mfa_enabled: true },
        { id: 'm2', userType: 'Member', mfa_enabled: false },
        { id: 'm3', userType: 'Member', mfa_enabled: false },
        { id: 'g1', userType: 'Guest', mfa_enabled: false },
        { id: 'g2', userType: 'Guest', mfa_enabled: true },
        { id: 'u1', userType: 'Unknown', mfa_enabled: false }
    ];

    const processed = buildIdentityDashboardSource({
        metricsRow: { total_users: 6, mfa_enabled_users: 2, mfa_percentage: 33 },
        usersRows
    });

    assert.equal(processed.dashboardMetrics.workforceUsers, 3);
    assert.equal(processed.dashboardMetrics.externalUsers, 2);
    assert.equal(processed.dashboardMetrics.unknownUserTypes, 1);
    assert.equal(processed.dashboardMetrics.mfaEnabled, 1);
    assert.equal(processed.dashboardMetrics.mfaMissing, 2);
    assert.equal(processed.dashboardMetrics.mfaCoverage, 33);
    assert.equal(processed.dashboardMetrics.mfaAssessmentStatus, 'incomplete');
});

test('Identity dashboard and StackCTRL context share the exact user-derived premium dashboard metrics', () => {
    const usersRows = Array.from({ length: 57 }, (_, index) => ({
        id: `user-${index + 1}`,
        userType: index >= 53 ? 'Guest' : 'Member',
        mfa_enabled: index < 5 || (index >= 6 && index <= 46),
        roles: JSON.stringify(index < 5
            ? ['Global Administrator', 'Security Administrator']
            : index === 5 ? ['Exchange Administrator'] : []),
        risk_level: index === 0 ? 'HIGH' : 'SAFE',
        is_external: index >= 53,
        last_signin_device: index < 48 ? 'Unknown' : 'Managed Laptop',
        last_signin_location: 'Unknown',
        last_signin_status: 'Success',
        days_since_signin: 1
    }));
    const processed = buildIdentityDashboardSource({
        metricsRow: {
            total_users: 999, mfa_enabled_users: 999, mfa_percentage: 100,
            admin_users: 999, high_risk_users: 999, privileged_users_without_mfa: 999
        },
        usersRows
    });
    const identity = buildIdentityDashboardContext(source({
        metrics: processed.dashboardMetrics,
        dashboardSourceMetrics: processed.dashboardMetrics,
        evidence: [{ evidenceType: 'users', data: processed.users }]
    }));
    const expected = {
        totalUsers: 57,
        mfaEnabled: 46,
        mfaMissing: 7,
        mfaCoverage: 87,
        privilegedUsers: 6,
        highRiskUsers: 1,
        adminsWithoutMfa: 1,
        signInIssues: 57,
        externalUsers: 4,
        unknownDevices: 48,
        multiplePrivilegedRoles: 5
    };
    for (const [metric, value] of Object.entries(expected)) {
        assert.equal(processed.dashboardMetrics[metric], value, metric);
        assert.equal(identity.dashboardMetrics[metric], value, metric);
    }
});

test('Sunbird Identity adapter reads the latest complete saved StackCTRL evidence without recalculating metrics', async () => {
    const dashboardMetrics = {
        totalUsers: 20, mfaEnabled: 12, mfaMissing: 8, mfaCoverage: 60,
        privilegedUsers: 3, adminsWithoutMfa: 1, highRiskUsers: 1,
        signInIssues: 4, externalUsers: 2, unknownDevices: 4, multiplePrivilegedRoles: 1
    };
    const result = await identityAdapter({
        pool: {
            async query(sql) {
                if (sql.includes('FROM CompanyMicrosoftMapping')) return [[{ MicrosoftTenantID: 1, TenantName: 'Sunbird', TenantID: 'tenant' }], []];
                if (sql.includes('FROM StackCTRLIdentityEvidenceSnapshots')) return [[{
                    ID: 91,
                    CompanyID: 1,
                    IsComplete: 1,
                    CollectionStatus: 'complete',
                    CollectedAt: new Date(),
                    SourceFetchedAt: new Date(),
                    SourceEndpoint: '/api/sunbird/identity-dashboard',
                    CollectionTrigger: 'scheduled_30_minute',
                    EvidenceRecordCount: 20,
                    OmittedRecordCount: 0,
                    DashboardMetricsJson: JSON.stringify(dashboardMetrics)
                }], []];
                if (sql.includes('FROM StackCTRLIdentityUserEvidence')) return [[...Array.from({ length: 20 }, (_, index) => ({
                    ID: index + 1,
                    SnapshotID: 91,
                    ProcessedEvidenceJson: JSON.stringify({
                        id: `user-${index + 1}`,
                        displayName: `User ${index + 1}`,
                        mfaEnabled: false,
                        roles: [],
                        riskLevel: 'SAFE',
                        lastSignIn: { device: 'Managed', location: 'Office', status: 'Success', daysSince: 1 }
                    })
                }))], []];
                return [[], []];
            }
        },
        companyId: 1,
        refresh: false,
        capability: {
            profileKey: 'sunbird', sourceKey: 'identity', displayName: 'Identity Protection',
            isExpected: true, isEnabled: true, refreshMode: 'stored_only', freshnessThresholdMinutes: 60,
            configuration: {}
        }
    });
    assert.equal(result.metrics.mfaEnabled, 12);
    assert.equal(result.metrics.mfaCoverage, 60);
    assert.equal(result.metrics.unknownDevices, 4);
    assert.equal(result.metrics.signInIssues, 4);
    assert.equal(result.sourceLineage.sourceBuilder, 'storedStackCTRLIdentityEvidence');
    assert.equal(result.sourceLineage.evidenceSnapshotId, 91);
    assert.equal(result.sourceLineage.evidenceRecordCount, 20);
    assert.match(result.rawReference.table, /StackCTRLIdentityEvidenceSnapshots/);
    assert.equal(result.evidence.find(item => item.evidenceType === 'users').data.length, 20);
});

test('Cloudflare dashboard context exposes network metrics, evidence, and chart-ready values', () => {
    const result = buildCloudflareDashboardContext(source({
        sourceKey: 'cloudflare_network_security',
        displayName: 'Cloudflare Network Security',
        evidence: [{
            overview: {
                protectedApps: 3,
                enrolledDevices: 8,
                activeGatewayPolicies: 2,
                identityProvider: 'Azure AD',
                gatewayProxyEnabled: true,
                dlpProfiles: 1
            },
            apps: [{ id: 1 }],
            devices: [{ id: 1 }],
            gatewayRules: [{ id: 1 }],
            accessLogs: [{ action: 'block' }, { action: 'allow' }],
            sections: { apps: { label: 'Applications', status: 'ok' } }
        }]
    }));

    assert.equal(result.status, 'available');
    assert.equal(result.dashboardMetrics.deniedAccessEvents, 1);
    assert.equal(result.calculatedIndicators.networkSecurityScore, 100);
    assert.equal(result.chartsData.accessActivity.total, 2);
    assert.ok(result.evidence.length > 1);
});

test('not-expected sources do not gain artificial evidence from a dashboard builder', () => {
    const result = buildCloudflareDashboardContext(source({
        sourceKey: 'cloudflare_network_security',
        displayName: 'Cloudflare Network Security',
        status: 'not_expected',
        isExpected: false,
        evidence: []
    }));
    assert.equal(result.evidence.length, 0);
});
