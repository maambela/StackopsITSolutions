const test = require('node:test');
const assert = require('node:assert/strict');

const { buildSecurityFindings, getSignInOutcome } = require('../services/intelligence/security-findings');
const { buildSecurityDashboardPayload } = require('../services/intelligence/security-dashboard-processor');
const { deriveSecurityEvidence } = require('../services/intelligence/security-evidence-store');
const buildSecurityAlertsDashboardContext = require('../services/intelligence/dashboard-context/securityAlertsDashboardContext');
const { extractMicrosoftAlertEntities, describeMicrosoftAlertEntityShape } = require('../services/intelligence/microsoft-alert-entities');

test('Microsoft alert evidence exposes explicit nested IP and user entities without parsing alert text', () => {
    const entities = extractMicrosoftAlertEntities({
        title: 'Anonymous IP address detected',
        description: 'A string that looks like 203.0.113.200 must not become evidence.',
        evidence: [{
            '@odata.type': '#microsoft.graph.security.ipEvidence',
            ipAddress: '203.0.113.8'
        }, {
            '@odata.type': '#microsoft.graph.security.userEvidence',
            userPrincipalName: 'person@example.com'
        }]
    });

    assert.deepEqual(entities.ipAddresses, ['203.0.113.8']);
    assert.equal(entities.userPrincipalName, 'person@example.com');

    const diagnostic = describeMicrosoftAlertEntityShape({
        id: 'alert-1',
        evidence: [{ '@odata.type': '#microsoft.graph.security.ipEvidence', ipAddress: '203.0.113.8' }]
    });
    assert.equal(diagnostic.extractedEntityCounts.ipAddresses, 1);
    assert.deepEqual(diagnostic.evidence[0].fields, ['@odata.type', 'ipAddress']);
    assert.doesNotMatch(JSON.stringify(diagnostic), /203\.0\.113\.8/);
});

test('anonymous IP alert correlates exact IP sign-ins without asserting compromise', () => {
    const result = buildSecurityFindings({
        alerts: [{ id: 'alert-1', title: 'Anonymous IP sign-in detected', severity: 'medium', ipAddress: '203.0.113.8' }],
        signIns: [
            { id: 'signin-1', userId: 'user-1', userPrincipalName: 'user@example.com', ipAddress: '203.0.113.8', outcome: 'success' },
            { id: 'signin-2', userPrincipalName: 'other@example.com', ipAddress: '198.51.100.1', outcome: 'success' }
        ]
    });

    const [finding] = result.findings;
    assert.equal(finding.detectionId, 'anonymous_ip_authentication');
    assert.equal(finding.status, 'related_evidence');
    assert.equal(finding.severity, 'unassessed');
    assert.equal(finding.sourceSeverity, 'medium');
    assert.deepEqual(finding.affectedEntities.users, []);
    assert.deepEqual(finding.candidateUsers, ['user@example.com']);
    assert.equal(finding.evidence.filter(item => item.sourceType === 'sign_in').length, 1);
    assert.match(finding.description, /IP equality alone does not prove/);
});

test('anonymous IP finding correlates against all explicit IP evidence on an alert', () => {
    const result = buildSecurityFindings({
        alerts: [{
            id: 'alert-1',
            title: 'Anonymous IP sign-in detected',
            ipAddresses: ['198.51.100.1', '203.0.113.8']
        }],
        signIns: [{ id: 'signin-1', userPrincipalName: 'user@example.com', ipAddress: '203.0.113.8', outcome: 'success' }]
    });

    const [finding] = result.findings;
    assert.equal(finding.status, 'related_evidence');
    assert.deepEqual(finding.affectedEntities.ipAddresses, ['198.51.100.1', '203.0.113.8']);
    assert.deepEqual(finding.candidateUsers, ['user@example.com']);
});

test('legacy compatibility alerts remain visible but cannot become a correlation or notification finding', () => {
    const result = buildSecurityFindings({
        alerts: [{
            id: 'legacy-alert',
            title: 'Anonymous IP sign-in detected',
            ipAddress: '203.0.113.8',
            sourceSchema: 'legacy_alerts_compatibility'
        }],
        signIns: [{ id: 'signin-1', userPrincipalName: 'user@example.com', ipAddress: '203.0.113.8', outcome: 'success' }]
    });

    const [finding] = result.findings;
    assert.equal(finding.status, 'needs_investigation');
    assert.equal(finding.evidence.filter(item => item.sourceType === 'sign_in').length, 0);
    assert.match(finding.assessmentBasis, /excluded from correlation and notification/);
});

test('anonymous IP indicator remains an observation when no sign-in evidence matches', () => {
    const result = buildSecurityFindings({
        alerts: [{ id: 'alert-1', title: 'Anonymous IP address observed', severity: 'high' }],
        signIns: []
    });

    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].status, 'needs_investigation');
    assert.equal(result.findings[0].confidence, 'low');
    assert.deepEqual(result.findings[0].affectedEntities.users, []);
    assert.match(result.findings[0].description, /no matching sign-in record/);
});

test('risky user and successful sign-in correlate by stable user ID, while risk levels stay source evidence', () => {
    const result = buildSecurityFindings({
        riskyUsers: [{ id: 'user-1', userPrincipalName: 'person@example.com', riskLevel: 'high', riskState: 'atRisk' }],
        riskDetections: [{ id: 'risk-1', userId: 'user-1', riskEventType: 'anonymousIpAddress', riskLevel: 'high' }],
        signIns: [
            { id: 'signin-1', userId: 'user-1', userPrincipalName: 'person@example.com', outcome: 'success', ipAddress: '203.0.113.8' },
            { id: 'signin-2', userId: 'user-2', userPrincipalName: 'other@example.com', outcome: 'success' }
        ]
    });

    const [finding] = result.findings;
    assert.equal(finding.detectionId, 'risky_user_successful_sign_in');
    assert.equal(finding.status, 'correlated');
    assert.equal(finding.severity, 'unassessed');
    assert.equal(finding.sourceRiskLevel, 'high');
    assert.equal(finding.evidence.filter(item => item.sourceType === 'sign_in').length, 1);
    assert.equal(finding.evidence.filter(item => item.sourceType === 'risk_detection').length, 1);
    assert.match(finding.description, /not proof/);
});

test('available identity-risk detections can be correlated when the licensed risky-user feed is unavailable', () => {
    const result = buildSecurityFindings({
        riskDetections: [{
            id: 'risk-1',
            userId: 'user-1',
            userPrincipalName: 'person@example.com',
            riskEventType: 'anonymousIpAddress',
            riskLevel: 'high',
            activityDateTime: '2026-10-15T12:00:00.000Z'
        }],
        signIns: [{ id: 'signin-1', userId: 'user-1', userPrincipalName: 'person@example.com', outcome: 'success', eventTime: '2026-10-15T13:00:00.000Z' }],
        sourceStatuses: { riskyUsers: 'unavailable', riskDetections: 'complete', signIns: 'partial' }
    });

    const [finding] = result.findings;
    assert.equal(finding.detectionId, 'identity_risk_detection_successful_sign_in');
    assert.equal(finding.status, 'correlated');
    assert.equal(finding.sourceRiskLevel, 'high');
    assert.equal(finding.confidence, 'medium');
    assert.match(finding.assessmentBasis, /risky-user feed is unavailable/);
    assert.equal(result.scenarioCoverage.riskyUserSuccessfulSignIn.status, 'partial');
    assert.match(result.scenarioCoverage.riskyUserSuccessfulSignIn.reason, /identity-risk detections/);
});

test('identity-risk detections do not correlate a user’s unrelated historical sign-ins', () => {
    const result = buildSecurityFindings({
        riskDetections: [{
            id: 'risk-1', userId: 'user-1', userPrincipalName: 'person@example.com', activityDateTime: '2026-10-15T12:00:00.000Z'
        }],
        signIns: [{
            id: 'signin-1', userId: 'user-1', userPrincipalName: 'person@example.com', outcome: 'success', eventTime: '2026-10-10T12:00:00.000Z'
        }],
        sourceStatuses: { riskyUsers: 'unavailable', riskDetections: 'complete', signIns: 'complete' }
    });

    assert.equal(result.findings[0].status, 'needs_investigation');
    assert.equal(result.findings[0].confidence, 'low');
    assert.equal(result.findings[0].evidence.filter(item => item.sourceType === 'sign_in').length, 0);
});

test('sign-in outcome stays unknown when Graph omits status and impossible travel is explicitly unassessed', () => {
    assert.equal(getSignInOutcome({}), 'unknown');
    assert.equal(getSignInOutcome({ status: { errorCode: 0 } }), 'success');
    assert.equal(getSignInOutcome({ status: { errorCode: 50126 } }), 'failed');

    const result = buildSecurityFindings();
    assert.equal(result.scenarioCoverage.impossibleTravel.status, 'not_assessed');
    assert.match(result.scenarioCoverage.impossibleTravel.reason, /No successful sign-ins/);
});

test('travel-velocity candidates require valid same-user coordinates, countries, and a conservative speed', () => {
    const result = buildSecurityFindings({
        signIns: [
            {
                id: 'signin-1', userId: 'user-1', userPrincipalName: 'person@example.com', outcome: 'success',
                country: 'South Africa', location: 'Cape Town, South Africa', eventTime: '2026-10-15T08:00:00.000Z',
                locationCoordinates: { latitude: -33.9249, longitude: 18.4241 }, ipAddress: '203.0.113.8'
            },
            {
                id: 'signin-2', userId: 'user-1', userPrincipalName: 'person@example.com', outcome: 'success',
                country: 'United Kingdom', location: 'London, United Kingdom', eventTime: '2026-10-15T09:00:00.000Z',
                locationCoordinates: { latitude: 51.5074, longitude: -0.1278 }, ipAddress: '198.51.100.8'
            }
        ],
        sourceStatuses: { signIns: 'complete' }
    });

    const finding = result.findings.find(item => item.detectionId === 'impossible_travel_candidate');
    assert.ok(finding);
    assert.equal(finding.status, 'needs_investigation');
    assert.equal(finding.severity, 'unassessed');
    assert.match(finding.description, /not proof/);
    assert.equal(result.scenarioCoverage.impossibleTravel.status, 'evaluated');
    assert.equal(result.scenarioCoverage.impossibleTravel.findingCount, 1);
});

test('empty but successfully collected identity-risk feeds count as evaluated, not unavailable', () => {
    const result = buildSecurityFindings({
        sourceStatuses: {
            alerts: 'complete',
            signIns: 'complete',
            riskyUsers: 'complete'
        }
    });

    assert.equal(result.scenarioCoverage.anonymousIpAuthentication.status, 'evaluated');
    assert.equal(result.scenarioCoverage.riskyUserSuccessfulSignIn.status, 'evaluated');
    assert.equal(result.scenarioCoverage.riskyUserSuccessfulSignIn.reason, null);
});

test('returned sign-in evidence with a failed later page remains partial, not unavailable', () => {
    const result = buildSecurityFindings({
        alerts: [{ id: 'alert-1', title: 'Anonymous IP address observed', ipAddress: '203.0.113.9' }],
        signIns: [{ id: 'signin-1', ipAddress: '203.0.113.9', outcome: 'success' }],
        sourceStatuses: {
            alerts: 'complete',
            signIns: 'partial',
            riskyUsers: 'unavailable'
        }
    });

    assert.equal(result.scenarioCoverage.anonymousIpAuthentication.status, 'partial');
    assert.match(result.scenarioCoverage.anonymousIpAuthentication.reason, /incomplete/);
});

test('dashboard and evidence store preserve finding details and source coverage', () => {
    const detection = buildSecurityFindings({
        riskyUsers: [{ id: 'user-1', userPrincipalName: 'person@example.com', riskLevel: 'high', riskState: 'atRisk' }],
        signIns: [{ id: 'signin-1', userId: 'user-1', userPrincipalName: 'person@example.com', outcome: 'success' }]
    });
    const payload = buildSecurityDashboardPayload({
        payload: {
            identityRisk: { riskyUsers: [{ id: 'user-1', userPrincipalName: 'person@example.com', riskLevel: 'high' }] },
            findings: detection.findings,
            scenarioCoverage: detection.scenarioCoverage
        }
    });
    const evidence = deriveSecurityEvidence(payload);

    assert.equal(payload.findings.length, 1);
    assert.equal(payload.collection.hasPrimaryEvidence, true);
    assert.equal(payload.scenarioCoverage.impossibleTravel.status, 'not_assessed');
    assert.ok(evidence.evidenceRows.some(row => row.kind === 'security_finding'));
    assert.ok(evidence.evidenceRows.some(row => row.kind === 'risky_user'));
});

test('stored dashboard context exposes findings and scenario coverage', () => {
    const finding = {
        id: 'finding-1',
        detectionId: 'risky_user_successful_sign_in',
        title: 'Successful sign-in observed for risky user'
    };
    const context = buildSecurityAlertsDashboardContext({
        sourceKey: 'security_alerts',
        status: 'available',
        evidence: [
            { evidenceType: 'securityFindings', data: [finding] }
        ],
        sourceLineage: {
            scenarioCoverage: { impossibleTravel: { status: 'not_assessed' } }
        }
    });
    const dashboardEvidence = context.evidence.find(item => item.evidenceType === 'dashboard_evidence_lists');

    assert.deepEqual(dashboardEvidence.data.securityFindings, [finding]);
    assert.equal(dashboardEvidence.data.scenarioCoverage.impossibleTravel.status, 'not_assessed');
});
