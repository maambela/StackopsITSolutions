const test = require('node:test');
const assert = require('node:assert/strict');
const { selectSecurityFindingNotifications } = require('../services/security-finding-notifications');

function finding(overrides = {}) {
    return {
        id: 'finding-1',
        detectionId: 'identity_risk_detection_successful_sign_in',
        title: 'Validated identity-risk finding',
        status: 'correlated',
        severity: 'high',
        confidence: 'high',
        impact: 'A confirmed high-impact condition needs response.',
        recommendedAction: 'Contain the session and review the evidence.',
        affectedEntities: { users: ['person@example.com'], ipAddresses: ['203.0.113.8'] },
        evidence: [
            { sourceType: 'risk_detection', eventTime: '2026-10-16T10:00:00.000Z' },
            { sourceType: 'sign_in', eventTime: '2026-10-16T10:05:00.000Z' }
        ],
        ...overrides
    };
}

test('only a fully evaluated, high-confidence Stack CTRL finding is WhatsApp eligible', () => {
    const result = selectSecurityFindingNotifications({
        findings: [finding()],
        scenarioCoverage: { riskyUserSuccessfulSignIn: { status: 'evaluated' } }
    });

    assert.equal(result.eligible.length, 1);
    assert.equal(result.eligible[0].recordType, 'finding');
    assert.match(result.eligible[0].issue, /confirmed high-impact/);
    assert.equal(result.ineligible.length, 0);
});

test('a partial medium-confidence correlation remains dashboard-only', () => {
    const result = selectSecurityFindingNotifications({
        findings: [finding({ severity: 'unassessed', confidence: 'medium' })],
        scenarioCoverage: { riskyUserSuccessfulSignIn: { status: 'partial' } }
    });

    assert.equal(result.eligible.length, 0);
    assert.match(result.ineligible[0].reasons.join(' '), /severity is not high or critical/);
    assert.match(result.ineligible[0].reasons.join(' '), /scenario coverage is partial/);
});

test('legacy compatibility observations can never be WhatsApp eligible', () => {
    const result = selectSecurityFindingNotifications({
        findings: [finding({ assessmentBasis: 'Legacy Graph alert retained temporarily as an observation only; it is excluded from correlation and notification.' })],
        scenarioCoverage: { riskyUserSuccessfulSignIn: { status: 'evaluated' } }
    });

    assert.equal(result.eligible.length, 0);
    assert.match(result.ineligible[0].reasons.join(' '), /legacy compatibility evidence/);
});
