const test = require('node:test');
const assert = require('node:assert/strict');
const {
    createSecurityFindingAiAssessment,
    validateAssessment,
    buildFallbackDailyOverview,
    evidenceFingerprint,
    applyAssessmentToFinding
} = require('../services/intelligence/security-finding-ai-assessment');

function sampleFinding(overrides = {}) {
    return {
        id: 'finding-abc',
        detectionId: 'risky_user_successful_sign_in',
        title: 'Risky user sign-in',
        description: 'Microsoft lists the user as risky and a successful sign-in matched.',
        impact: 'Authentication occurred for a risky identity.',
        severity: 'unassessed',
        confidence: 'high',
        confidenceReason: 'User and sign-in matched.',
        status: 'correlated',
        recommendedAction: 'Review sign-in context.',
        assessmentBasis: 'Correlation only.',
        sourceRiskLevel: 'high',
        affectedEntities: { users: ['person@example.com'], devices: [], ipAddresses: ['203.0.113.1'] },
        evidence: [
            { sourceType: 'risky_user', sourceId: 'ru-1', eventTime: '2026-10-16T10:00:00.000Z', summary: 'Risky user' },
            { sourceType: 'sign_in', sourceId: 'si-1', eventTime: '2026-10-16T10:05:00.000Z', summary: 'Success sign-in', details: { outcome: 'success' } }
        ],
        ...overrides
    };
}

test('validateAssessment rejects unknown finding ids and normalizes severity', () => {
    const findingIds = new Set(['finding-abc']);
    const validated = validateAssessment({
        findingId: 'finding-abc',
        title: 'Successful sign-in for risky user person@example.com',
        aiSummary: 'A successful sign-in matched a Microsoft risky-user record for person@example.com.',
        severity: 'high',
        confidence: 'high',
        confidenceReason: 'User identity and successful sign-in both returned.',
        recommendedAction: 'Review the session and confirm whether the sign-in was expected.',
        requiresAction: true,
        actionPriority: 'immediate',
        whatHappened: 'A successful sign-in was recorded for a user Microsoft marks as risky.',
        whyItMatters: 'Unexpected access from a risky identity can indicate account misuse.',
        reasoning: 'The risky-user record and successful sign-in cite the same user.',
        supportingEvidence: ['Risky-user record returned by Microsoft', 'Successful sign-in within the collected period']
    }, findingIds);

    assert.ok(validated);
    assert.equal(validated.severity, 'high');
    assert.equal(validated.actionPriority, 'immediate');

    assert.equal(validateAssessment({ findingId: 'missing' }, findingIds), null);
});

test('applyAssessmentToFinding preserves provider values and stores ai metadata', () => {
    const finding = sampleFinding();
    const assessed = applyAssessmentToFinding(finding, {
        findingId: 'finding-abc',
        title: 'Review risky sign-in for person@example.com',
        aiSummary: 'person@example.com signed in successfully while Microsoft still reports the account as risky.',
        severity: 'high',
        confidence: 'high',
        confidenceReason: 'Both records cite the same user.',
        recommendedAction: 'Confirm whether this sign-in was expected.',
        requiresAction: true,
        actionPriority: 'immediate',
        whatHappened: 'Successful sign-in near risky-user state.',
        whyItMatters: 'Risky identities warrant prompt verification.',
        reasoning: 'Matching user on risky-user and sign-in records.',
        supportingEvidence: ['Risky-user record'],
        contradictoryEvidence: [],
        plausibleLegitimateExplanations: ['Expected travel or admin activity'],
        unknowns: [],
        limitations: [],
        relatedFindingIds: []
    }, { model: 'gpt-4.1-mini', assessedAt: '2026-10-16T12:00:00.000Z' });

    assert.equal(assessed.severity, 'high');
    assert.equal(assessed.sourceRiskLevel, 'high');
    assert.match(assessed.aiSummary, /person@example.com/);
    assert.equal(assessed.aiAssessmentStatus, 'assessed');
    assert.equal(assessed.aiAssessment.model, 'gpt-4.1-mini');
});

test('assessSecurityFindings uses Azure OpenAI and caches identical evidence packages', async () => {
    let callCount = 0;
    const azureOpenAI = {
        createJsonCompletion: async () => {
            callCount += 1;
            return {
                data: {
                    assessments: [{
                        findingId: 'finding-abc',
                        title: 'Risky sign-in needs review',
                        aiSummary: 'A successful sign-in matched a risky Microsoft user record.',
                        severity: 'high',
                        confidence: 'high',
                        confidenceReason: 'Both records cite the same user.',
                        recommendedAction: 'Verify the sign-in with the account owner.',
                        requiresAction: true,
                        actionPriority: 'immediate',
                        whatHappened: 'Successful sign-in for risky user.',
                        whyItMatters: 'Unexpected risky access may need response.',
                        reasoning: 'Matching identity on both records.',
                        supportingEvidence: ['Risky-user record', 'Successful sign-in']
                    }],
                    dailyOverview: {
                        summary: 'One assessed issue requires attention.',
                        requiresAttention: ['finding-abc'],
                        monitor: [],
                        noImmediateAction: [],
                        collectionGaps: []
                    }
                },
                model: 'gpt-4.1-mini',
                responseId: 'resp-1',
                usage: { total_tokens: 100 }
            };
        }
    };

    const service = createSecurityFindingAiAssessment({ azureOpenAI, now: () => 1_700_000_000_000 });
    const input = {
        companyId: 101,
        findings: [sampleFinding()],
        scenarioCoverage: { riskyUserSuccessfulSignIn: { status: 'evaluated' } },
        warnings: [],
        collectionStatus: 'complete'
    };

    const first = await service.assessSecurityFindings(input);
    const second = await service.assessSecurityFindings(input);

    assert.equal(callCount, 1);
    assert.equal(first.findings[0].severity, 'high');
    assert.equal(first.assessmentMeta.status, 'assessed');
    assert.equal(second.assessmentMeta.cached, true);
    assert.equal(first.dailyOverview.requiresAttention[0], 'finding-abc');
});

test('assessSecurityFindings falls back when Azure fails', async () => {
    const service = createSecurityFindingAiAssessment({
        azureOpenAI: {
            createJsonCompletion: async () => {
                throw new Error('rate limited');
            }
        }
    });
    const result = await service.assessSecurityFindings({ companyId: 101, findings: [sampleFinding()], scenarioCoverage: {} });
    assert.equal(result.assessmentMeta.status, 'failed');
    assert.equal(result.findings[0].severity, 'unassessed');
    assert.equal(result.findings[0].aiAssessmentStatus, 'failed');
    assert.ok(result.dailyOverview.summary);
});

test('assessSecurityFindings retains traceable findings when Azure times out', async () => {
    const service = createSecurityFindingAiAssessment({
        azureOpenAI: {
            createJsonCompletion: async () => {
                throw new Error('Security finding AI assessment timed out');
            }
        }
    });
    const result = await service.assessSecurityFindings({ companyId: 101, findings: [sampleFinding()], scenarioCoverage: {} });

    assert.equal(result.assessmentMeta.status, 'failed');
    assert.equal(result.findings[0].aiAssessmentStatus, 'failed');
    assert.equal(result.findings[0].evidence[0].sourceId, 'ru-1');
    assert.match(result.findings[0].aiAssessmentError, /timed out/i);
});

test('evidenceFingerprint changes when cited evidence changes', () => {
    const left = sampleFinding();
    const right = sampleFinding({ evidence: [...left.evidence, { sourceType: 'sign_in', sourceId: 'si-2', eventTime: '2026-10-16T11:00:00.000Z', summary: 'Another sign-in' }] });
    assert.notEqual(evidenceFingerprint(left), evidenceFingerprint(right));
    assert.ok(buildFallbackDailyOverview([applyAssessmentToFinding(left, null, { status: 'failed' })], {}, ['partial_source_collection']).collectionGaps.length);
});

test('assessment cache is partitioned by company even when the evidence is identical', async () => {
    let callCount = 0;
    const service = createSecurityFindingAiAssessment({
        azureOpenAI: {
            createJsonCompletion: async () => {
                callCount += 1;
                return {
                    data: {
                        assessments: [{
                            findingId: 'finding-abc',
                            title: `Assessment ${callCount}`,
                            aiSummary: `Tenant-specific assessment ${callCount}.`,
                            severity: 'medium', confidence: 'high', confidenceReason: 'Returned evidence was assessed.',
                            recommendedAction: 'Review the provider evidence.', requiresAction: true, actionPriority: 'monitor',
                            whatHappened: 'A provider finding was returned.', whyItMatters: 'It needs review.', reasoning: 'The cited evidence supports this assessment.'
                        }],
                        dailyOverview: { summary: 'One finding was assessed.', requiresAttention: [], monitor: ['finding-abc'], noImmediateAction: [], collectionGaps: [] }
                    },
                    model: 'gpt-4.1-mini', responseId: `response-${callCount}`
                };
            }
        }
    });
    const input = { findings: [sampleFinding()], scenarioCoverage: {}, warnings: [], collectionStatus: 'complete' };

    const firstTenant = await service.assessSecurityFindings({ ...input, companyId: 101 });
    const secondTenant = await service.assessSecurityFindings({ ...input, companyId: 202 });
    const firstTenantAgain = await service.assessSecurityFindings({ ...input, companyId: 101 });

    assert.equal(callCount, 2);
    assert.equal(firstTenant.findings[0].title, 'Assessment 1');
    assert.equal(secondTenant.findings[0].title, 'Assessment 2');
    assert.equal(firstTenantAgain.findings[0].title, 'Assessment 1');
    assert.equal(firstTenantAgain.assessmentMeta.cached, true);
});

test('missing company context never calls Azure or creates a reusable assessment', async () => {
    let called = false;
    const service = createSecurityFindingAiAssessment({
        azureOpenAI: { createJsonCompletion: async () => { called = true; return {}; } }
    });

    const result = await service.assessSecurityFindings({ findings: [sampleFinding()] });

    assert.equal(called, false);
    assert.equal(result.assessmentMeta.status, 'skipped_missing_tenant_context');
    assert.equal(result.findings[0].aiAssessmentStatus, 'unavailable');
});
