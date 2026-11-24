const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const { buildIdentityDashboardPayload } = require('../services/intelligence/identity-dashboard-processor');
const { deriveIdentityEvidence } = require('../services/intelligence/identity-evidence-store');

const FIXED_NOW = new Date('2026-11-23T12:00:00.000Z');

test('the client does not request full history and missing dates use a short label', () => {
    const source = fs.readFileSync(require.resolve('../js/clientportal'), 'utf8');
    assert.doesNotMatch(source, /signInHistory=30d|data-identity-sign-in-history/);
    const start = source.indexOf('function formatIdentityDate');
    const end = source.indexOf('function getIdentityRiskRank', start);
    const format = vm.runInNewContext(source.slice(start, end) + '\nformatIdentityDate;', {
        getIdentityLastSignInTime: () => 0
    });
    assert.equal(format({ lastSignIn: { observationStatus: 'partial' } }), 'Not available');
    assert.equal(format({ historyComplete: true }), 'No sign-in recorded in the last 30 days.');
});

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

test('30-day history restores older events and verifies absence only with complete coverage', () => {
    const source = fs.readFileSync(require.resolve('../js/clientportal'), 'utf8');
    const start = source.indexOf('function mergeIdentitySignInHistory');
    const end = source.indexOf('function buildSunbirdIdentityModel', start);
    const merge = vm.runInNewContext(source.slice(start, end) + '\nmergeIdentitySignInHistory;');
    const scope = { companyId: 7, sourceTenantId: 'tenant-a', fetchedAt: FIXED_NOW.toISOString() };
    const users = [{ id: 'two-days' }, { id: 'twenty-days' }, { id: 'missing' }, {
        id: 'saved', lastSignIn: { dateTime: '2026-11-23T11:00:00Z' }
    }];
    const history = { ...scope, since: '2026-10-24T12:00:00Z', status: 'partial', records: [
        { userId: 'two-days', createdDateTime: '2026-11-21T12:00:00Z' },
        { userId: 'twenty-days', createdDateTime: '2026-11-03T12:00:00Z' },
        { userId: 'saved', createdDateTime: '2026-11-21T12:00:00Z' }
    ] };
    const rows = merge(users, scope, history, FIXED_NOW.getTime());
    assert.equal(rows[0].lastSignIn.dateTime, '2026-11-21T12:00:00Z');
    assert.equal(rows[1].lastSignIn.dateTime, '2026-11-03T12:00:00Z');
    assert.equal(rows[2].historyComplete, false);
    assert.equal(rows[3].lastSignIn.dateTime, users[3].lastSignIn.dateTime);
    assert.equal(merge(users, scope, { ...history, status: 'complete' }, FIXED_NOW.getTime())[2].historyComplete, true);
    assert.equal(merge(users, scope, { ...history, companyId: 8 }, FIXED_NOW.getTime()), users);
});

test('full sign-in history is requested only on demand', () => {
    const source = fs.readFileSync(require.resolve('../server'), 'utf8');
    const route = source.slice(source.indexOf("app.get('/api/sunbird/identity-dashboard'"), source.indexOf("app.get('/api/sunbird/identity-dashboard-cached'"));
    assert.match(route, /if \(req\.query\?\.signInHistory === '30d'\) \{[\s\S]*?fetchMicrosoftSignIns\(token, 30/);
    assert.ok(route.includes('fetchMicrosoftSignIns(token, 1, { withStatus: true })'));
});

test('saved history fallback retains verified failures and excludes out-of-window events', () => {
    const source = fs.readFileSync(require.resolve('../server'), 'utf8');
    const start = source.indexOf('function savedIdentityHistoryEvents');
    const end = source.indexOf('async function runIdentityBackfillStep', start);
    const events = vm.runInNewContext(source.slice(start, end) + '\nsavedIdentityHistoryEvents;');
    const rows = events([{ id: 'user-1',
        lastSignIn: { dateTime: '2026-10-01T11:00:00Z', status: 'Success' },
        failedSignIn: { dateTime: '2026-11-21T11:00:00Z', status: 'Failed' }
    }], FIXED_NOW.getTime());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].userId, 'user-1');
    assert.equal(rows[0].status.errorCode, 'saved_failure');
});

test('Identity card distinguishes verified zero, a saved count, and a missing count', () => {
    const source = fs.readFileSync(require.resolve('../js/clientportal'), 'utf8');
    const start = source.indexOf('function identityCardCount');
    const end = source.indexOf('function updateIdentityProjectCardFromDashboard', start);
    const count = vm.runInNewContext(source.slice(start, end) + '\nidentityCardCount;', {
        microsoftDashboardUpdateText: () => 'Last updated 24 Nov'
    });
    const confirmed = count(0, null, FIXED_NOW.toISOString());
    assert.equal(confirmed.text, '0');
    assert.equal(count(null, confirmed.verified).text, '0*');
    assert.equal(count(null, null).title, 'Temporarily unavailable');
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
