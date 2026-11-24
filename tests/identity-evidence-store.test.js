const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
    IDENTITY_EVIDENCE_SCHEMA,
    createIdentityEvidenceStore,
    deriveIdentityEvidence
} = require('../services/intelligence/identity-evidence-store');
const {
    DEFAULT_IDENTITY_EVIDENCE_INTERVAL_MS,
    createIdentityEvidenceAutomation
} = require('../services/intelligence/identity-evidence-automation');
const { buildIdentityDashboardPayload } = require('../services/intelligence/identity-dashboard-processor');

function identityDashboardPayload() {
    const users = Array.from({ length: 57 }, (_, index) => ({
        id: `user-${index + 1}`,
        displayName: `User ${index + 1}`,
        mail: `user${index + 1}@sunbird.eu`,
        userPrincipalName: `user${index + 1}@sunbird.eu`,
        userType: index >= 53 ? 'Guest' : 'Member',
        jobTitle: index === 0 ? 'Administrator' : 'No Title',
        mobilePhone: index === 0 ? '+27000000000' : 'N/A',
        roles: index < 5
            ? [{ name: 'Global Administrator' }, { name: 'Security Administrator' }]
            : index === 5 ? [{ name: 'Exchange Administrator' }] : [],
        mfaEnabled: index < 5 || (index >= 6 && index <= 46),
        authMethodCount: index < 46 ? 3 : 1,
        riskLevel: index === 0 ? 'HIGH' : 'SAFE',
        isExternal: index >= 53,
        accountEnabled: true,
        lastSignIn: {
            dateTime: '2026-06-22T08:00:00.000Z',
            daysSince: 1,
            status: 'Success',
            location: 'Unknown',
            device: index < 48 ? 'Unknown' : 'Managed Laptop'
        }
    }));
    return {
        success: true,
        tenant: 'sunbird',
        fetchedAt: '2026-06-23T08:00:00.000Z',
        summary: { totalUsers: 57, activeUsers24h: 57 },
        users
    };
}

const EXPECTED_METRICS = {
    totalUsers: 57,
    mfaEnabled: 46,
    mfaMissing: 7,
    mfaCoverage: 87,
    privilegedUsers: 6,
    adminsWithoutMfa: 1,
    highRiskUsers: 1,
    signInIssues: 0,
    externalUsers: 4,
    unknownDevices: 48,
    multiplePrivilegedRoles: 5
};

test('saved Identity evidence metrics match the visible dashboard user model', () => {
    const evidence = deriveIdentityEvidence(identityDashboardPayload());
    for (const [metric, expected] of Object.entries(EXPECTED_METRICS)) {
        assert.equal(evidence.dashboardMetrics[metric], expected, metric);
    }
    assert.equal(evidence.users.length, 57);
    assert.equal(evidence.expectedRecordCount, 57);
    assert.equal(evidence.omittedRecordCount, 0);
    assert.equal(evidence.completenessPercent, 100);
    assert.equal(evidence.isComplete, true);
    assert.deepEqual(evidence.accessLevelCounts, { privileged: 6, standard: 51 });
    assert.ok(Number.isFinite(evidence.stackctrlRiskScore));
    assert.ok(Number.isFinite(evidence.stackctrlHealthScore));
});

test('the scheduled processor produces the same Identity metrics that are saved for Azure', async () => {
    const rawUsers = Array.from({ length: 57 }, (_, index) => ({
        id: `user-${index + 1}`,
        displayName: `User ${index + 1}`,
        mail: index >= 53 ? `guest${index}@example.com` : `user${index + 1}@sunbird.eu`,
        userPrincipalName: `user${index + 1}@sunbird.eu`,
        userType: index >= 53 ? 'Guest' : 'Member'
    }));
    const roleAssignments = [];
    for (let index = 0; index < 5; index += 1) {
        roleAssignments.push(
            { principalId: `user-${index + 1}`, roleDefinition: { id: `global-${index}`, displayName: 'Global Administrator' } },
            { principalId: `user-${index + 1}`, roleDefinition: { id: `security-${index}`, displayName: 'Security Administrator' } }
        );
    }
    roleAssignments.push({ principalId: 'user-6', roleDefinition: { id: 'exchange', displayName: 'Exchange Administrator' } });
    const signIns = rawUsers.map((user, index) => ({
        userPrincipalName: user.userPrincipalName,
        createdDateTime: '2026-06-22T08:00:00.000Z',
        location: {},
        deviceDetail: { displayName: index < 48 ? 'Unknown' : 'Managed Laptop' },
        status: { errorCode: '0' }
    }));
    const payload = await buildIdentityDashboardPayload({
        users: rawUsers,
        roleAssignments,
        signIns,
        loadAuthMethods: async user => {
            const index = Number(user.id.split('-')[1]) - 1;
            return index >= 1 && index <= 46
                ? [{ '@odata.type': '#microsoft.graph.passwordAuthenticationMethod' }, { '@odata.type': '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' }, { '@odata.type': '#microsoft.graph.phoneAuthenticationMethod' }]
                : [{ '@odata.type': '#microsoft.graph.passwordAuthenticationMethod' }];
        },
        hasRealMfaMethod: methods => methods.some(method => !String(method['@odata.type']).toLowerCase().includes('passwordauthenticationmethod')),
        now: () => new Date('2026-06-23T08:00:00.000Z')
    });
    const evidence = deriveIdentityEvidence(payload);
    for (const [metric, expected] of Object.entries(EXPECTED_METRICS)) {
        assert.equal(evidence.dashboardMetrics[metric], expected, metric);
    }
    assert.equal(evidence.users.length, payload.users.length);
    assert.equal(evidence.omittedRecordCount, 0);
});

test('Identity evidence storage writes one readable user row per displayed record', async () => {
    const calls = [];
    const connection = {
        async beginTransaction() { calls.push({ sql: 'BEGIN', params: [] }); },
        async commit() { calls.push({ sql: 'COMMIT', params: [] }); },
        async rollback() { calls.push({ sql: 'ROLLBACK', params: [] }); },
        release() {},
        async query(sql, params = []) {
            calls.push({ sql, params });
            assert.equal((sql.match(/\?/g) || []).length, params.length, `Placeholder mismatch in ${sql}`);
            if (sql.includes('INSERT INTO StackCTRLIdentityEvidenceSnapshots')) return [{ insertId: 701 }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const pool = {
        async query() { return [{ affectedRows: 0 }, []]; },
        async getConnection() { return connection; }
    };
    const store = createIdentityEvidenceStore({
        pool,
        logger: { log() {} },
        now: () => new Date('2026-06-23T08:00:00.000Z')
    });
    const result = await store.persistProcessedEvidence({
        companyId: 1,
        tenantKey: 'sunbird',
        payload: identityDashboardPayload(),
        collectionTrigger: 'scheduled_30_minute'
    });
    const snapshotWrite = calls.find(call => call.sql.includes('INSERT INTO StackCTRLIdentityEvidenceSnapshots'));
    const userWrites = calls.filter(call => call.sql.includes('INSERT INTO StackCTRLIdentityUserEvidence'));
    assert.equal(result.snapshotId, 701);
    assert.equal(result.recordCount, 57);
    assert.equal(result.omittedCount, 0);
    assert.equal(userWrites.length, 57);
    assert.equal(snapshotWrite.params[12], 57);
    assert.equal(snapshotWrite.params[13], 46);
    assert.equal(snapshotWrite.params[14], 7);
    assert.equal(snapshotWrite.params[15], 87);
    assert.equal(snapshotWrite.params[21], 48);
    assert.equal(snapshotWrite.params[22], 5);
    assert.equal(userWrites[0].params[4], 'User 1');
    assert.equal(userWrites[0].params[5], 'user1@sunbird.eu');
    assert.equal(userWrites[0].params[6], 'Administrator');
    assert.match(userWrites[0].params[7], /Global Administrator/);
    assert.equal(userWrites[0].params[9], 'Internal');
    assert.equal(userWrites[0].params[10], 1);
    assert.equal(userWrites[0].params[11], 3);
    assert.equal(userWrites[0].params[12], 'HIGH');
    assert.equal(userWrites[0].params[13], 'Active');
    assert.equal(userWrites[0].params[17], 'Unknown');
    assert.equal(userWrites[0].params[18], 'Unknown');
    assert.equal(userWrites[0].params[19], '+27000000000');
    assert.equal(JSON.parse(userWrites[0].params[20]).displayName, 'User 1');
});

test('Identity evidence schema uses explicit human-readable snapshot and user fields', () => {
    const schema = IDENTITY_EVIDENCE_SCHEMA.join('\n');
    for (const column of [
        'Name', 'Email', 'JobTitle', 'RolesText', 'RolesJson', 'UserType', 'MFAEnabled',
        'AuthMethodCount', 'RiskLevel', 'AccountStatus', 'LastSignInAt', 'Location', 'Device', 'Phone',
        'TotalUsers', 'MFAEnabledUsers', 'UsersWithoutMFA', 'MFACoveragePercent',
        'PrivilegedUsers', 'AdminsWithoutMFA', 'HighRiskUsers', 'SignInIssues',
        'ExternalUsers', 'UnknownDevices', 'MultiplePrivilegedRoles', 'StackCTRLRiskScore',
        'StackCTRLHealthScore', 'CollectedAt', 'SourceEndpoint', 'IsComplete'
    ]) assert.match(schema, new RegExp(`\\b${column}\\b`), column);

    const sql = fs.readFileSync(path.join(__dirname, '..', 'sql', 'stackctrl-enterprise-intelligence.sql'), 'utf8');
    assert.match(sql, /CREATE TABLE IF NOT EXISTS StackCTRLIdentityEvidenceSnapshots/);
    assert.match(sql, /CREATE TABLE IF NOT EXISTS StackCTRLIdentityUserEvidence/);
});

test('Identity evidence automation defaults to a 30-minute interval and prevents overlap', async () => {
    let resolveCollection;
    let calls = 0;
    const automation = createIdentityEvidenceAutomation({
        collectAll: async () => {
            calls += 1;
            await new Promise(resolve => { resolveCollection = resolve; });
            return { stored: 1 };
        }
    });
    assert.equal(automation.getStatus().intervalMs, DEFAULT_IDENTITY_EVIDENCE_INTERVAL_MS);
    assert.equal(DEFAULT_IDENTITY_EVIDENCE_INTERVAL_MS, 30 * 60 * 1000);
    const first = automation.runOnce('manual');
    const overlap = await automation.runOnce('manual');
    assert.equal(overlap.status, 'skipped_overlap');
    resolveCollection();
    assert.equal((await first).status, 'completed');
    assert.equal(calls, 1);
});
