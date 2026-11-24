const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const { buildIdentityDashboardPayload } = require('../services/intelligence/identity-dashboard-processor');
const { deriveIdentityEvidence } = require('../services/intelligence/identity-evidence-store');

const FIXED_NOW = new Date('2026-11-23T12:00:00.000Z');

function build(users, options = {}) {
    return buildIdentityDashboardPayload({
        users,
        hasRealMfaMethod: methods => methods.some(method => method.type === 'mfa'),
        loadAuthMethods: async () => [],
        now: () => FIXED_NOW,
        ...options
    });
}

test('24-hour partial refresh preserves newer verified events and rejects conflicting user IDs', async () => {
    const user = { id: 'user-1', userPrincipalName: 'user@example.com', userType: 'Member' };
    const verifiedAt = '2026-11-23T11:45:00.000Z';
    const payload = await build([user, { id: 'user-2', userPrincipalName: 'other@example.com' }], {
        signInWindowDays: 1,
        signInCollectionStatus: 'partial',
        previousUsers: [{
            ...user, lastSignIn: { dateTime: verifiedAt, status: 'Success' },
            failedSignIn: { dateTime: verifiedAt, status: 'Failed' }
        }],
        signIns: [
            { userId: 'user-1', createdDateTime: '2026-11-23T10:00:00Z', status: { errorCode: 50074 } },
            { userId: 'wrong-id', userPrincipalName: user.userPrincipalName, createdDateTime: '2026-11-23T11:55:00Z' },
            { userPrincipalName: 'OTHER@example.com', createdDateTime: '2026-11-23T11:55:00Z', status: { errorCode: 50074 } }
        ]
    });
    assert.equal(payload.users[0].lastSignIn.dateTime, verifiedAt);
    assert.equal(payload.users[0].failedSignIn.dateTime, verifiedAt);
    assert.equal(payload.users[1].failedSignIn.status, 'Failed');
    assert.equal(deriveIdentityEvidence(payload).dashboardMetrics.signInCollection.windowDays, 1);
});

test('the recent sign-in panel only confirms zero from a complete 24-hour result', () => {
    const source = fs.readFileSync(require.resolve('../js/clientportal'), 'utf8');
    const start = source.indexOf('function identityRecentSignInState');
    const end = source.indexOf('async function loadSunbirdIdentitySignInHistory', start);
    const state = vm.runInNewContext(source.slice(start, end) + '\nidentityRecentSignInState;');
    const model = { fetchedAt: FIXED_NOW.toISOString() };
    assert.equal(state(model).empty, false);
    assert.equal(state({ ...model, signInCollection: { windowDays: 30, status: 'complete', recordCount: 0 } }).empty, false);
    assert.equal(state({ ...model, signInCollection: { windowDays: 1, status: 'partial', recordCount: 0 } }).empty, false);
    assert.equal(state({ ...model, signInCollection: { windowDays: 1, status: 'complete', recordCount: 2 } }).empty, false);
    assert.equal(state({ ...model, signInCollection: { windowDays: 1, status: 'complete', recordCount: 0 } }).empty, true);
});

test('sign-ins are matched by tenant user ID and absent events are not labeled never-signed-in', async () => {
    const payload = await build([
        { id: 'user-1', userPrincipalName: 'current@example.com', userType: 'Member' },
        { id: 'user-2', userPrincipalName: 'quiet@example.com', userType: 'Member' }
    ], {
        signIns: [{
            userId: 'user-1',
            userPrincipalName: 'former@example.com',
            createdDateTime: '2026-11-23T11:00:00.000Z',
            status: { errorCode: 0 },
            location: { city: 'Cape Town', countryOrRegion: 'ZA' },
            deviceDetail: { displayName: 'Managed Laptop' }
        }]
    });

    assert.equal(payload.users[0].lastSignIn.dateTime, '2026-11-23T11:00:00.000Z');
    assert.equal(payload.users[0].lastSignIn.location, 'Cape Town, ZA');
    assert.equal(payload.users[1].lastSignIn.dateTime, null);
    assert.equal(payload.users[1].lastSignIn.daysSince, null);
    assert.equal(payload.users[1].lastSignIn.observationStatus, 'no_recorded_sign_in');
    assert.equal(payload.summary.highRiskBreakdown.noRecordedSignIn, 1);
    assert.equal(Object.hasOwn(payload.summary.highRiskBreakdown, 'neverSignedIn'), false);
    assert.equal(payload.summary.activeUsers24h, 1);
});

test('optional MFA and sign-in failures preserve the complete user inventory as unavailable', async () => {
    const payload = await build([
        { id: 'admin-1', userPrincipalName: 'admin@example.com', userType: 'Member' }
    ], {
        roleAssignments: [{
            principalId: 'admin-1',
            roleDefinition: { displayName: 'Global Administrator' }
        }],
        signInCollectionStatus: 'unavailable',
        loadAuthMethods: async () => {
            const error = new Error('Graph authentication-method request timed out');
            error.code = 'GRAPH_REQUEST_TIMEOUT';
            throw error;
        }
    });

    assert.equal(payload.success, true);
    assert.equal(payload.users.length, 1);
    assert.equal(payload.users[0].mfaEnabled, null);
    assert.equal(payload.users[0].mfaStatus, 'unavailable');
    assert.equal(payload.users[0].riskLevel, 'SAFE');
    assert.equal(payload.summary.mfaEnabledPercentage, null);
    assert.equal(payload.summary.mfaUnknownUsers, 1);
    assert.equal(payload.summary.activeUsers24h, null);
    assert.equal(payload.users[0].lastSignIn.observationStatus, 'unavailable');
});

test('partial sign-in collection retains only dated prior evidence and does not report complete activity metrics', async () => {
    const payload = await build([
        { id: 'user-1', userPrincipalName: 'user@example.com', userType: 'Member' }
    ], {
        signInCollectionStatus: 'partial',
        previousUsers: [{
            id: 'user-1',
            userPrincipalName: 'user@example.com',
            lastSignIn: {
                dateTime: '2026-09-01T10:00:00.000Z',
                daysSince: 83,
                status: 'Failed',
                location: 'Durban, ZA',
                device: 'Laptop'
            },
            failedSignIn: {
                dateTime: '2026-09-01T10:00:00.000Z',
                status: 'Failed'
            },
            roles: []
        }]
    });

    assert.equal(payload.users.length, 1);
    assert.equal(payload.users[0].lastSignIn.dateTime, '2026-09-01T10:00:00.000Z');
    assert.equal(payload.users[0].lastSignIn.observationStatus, 'stale');
    assert.equal(payload.users[0].failedSignIn.observationStatus, 'stale');
    assert.equal(payload.signInCollection.status, 'partial');
    assert.equal(payload.summary.activeUsers24h, null);
    assert.equal(payload.users[0].flags.inactiveOver30Days, true);
});

test('unknown location and device are not sign-in issues, but actual failures remain visible', async () => {
    const payload = await build([
        { id: 'user-1', userPrincipalName: 'user@example.com', userType: 'Member' }
    ], {
        signIns: [
            {
                userId: 'user-1',
                createdDateTime: '2026-11-23T10:00:00.000Z',
                status: { errorCode: 50074, failureReason: 'Strong authentication required' }
            },
            {
                userId: 'user-1',
                createdDateTime: '2026-11-23T11:00:00.000Z',
                status: { errorCode: 0 }
            }
        ]
    });
    const user = payload.users[0];
    const evidence = deriveIdentityEvidence(payload);

    assert.equal(user.lastSignIn.status, 'Success');
    assert.equal(user.failedSignIn.status, 'Failed');
    assert.equal(user.flags.newLocationLogin, false);
    assert.equal(payload.insights.failedSignInUsers.length, 1);
    assert.equal(evidence.dashboardMetrics.signInIssues, 1);
    assert.equal(evidence.dashboardMetrics.unknownDevices, 1);
});
