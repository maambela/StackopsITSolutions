const test = require('node:test');
const assert = require('node:assert/strict');

const {
    buildDataLineageComparison,
    buildEvidenceCatalog,
    computeInterDomainDelayMs,
    createEnterpriseIntelligenceService,
    DEVICE_LINEAGE_FIELDS,
    EMAIL_LINEAGE_FIELDS,
    NETWORK_LINEAGE_FIELDS,
    ENTERPRISE_DOMAINS,
    ACTIVE_ENTERPRISE_DOMAIN_KEYS,
    TEMPORARILY_DISABLED_DOMAIN_KEYS,
    ensureItemEvidence,
    flattenDomainEvidence,
    normalizeEvidenceBackedItem,
    normalizeDomainOutputForDisplay,
    normalizeMysqlDate,
    repairTruncatedJson,
    sourceAlignmentFailure,
    splitIntoBatches,
    splitSecurityAlertsIntoBatches
} = require('../services/enterprise-intelligence');
const { emailSecurityAdapter, securityAlertsAdapter } = require('../services/intelligence/source-adapters');

test('enterprise domain order keeps governance and compliance active with operations disabled', () => {
    assert.deepEqual(ENTERPRISE_DOMAINS.map(domain => domain.key), [
        'identity',
        'devices',
        'email_security',
        'cloudflare_network_security',
        'security_alerts',
        'applications',
        'backup',
        'governance',
        'operations',
        'compliance'
    ]);

    assert.deepEqual(ACTIVE_ENTERPRISE_DOMAIN_KEYS, [
        'identity',
        'devices',
        'email_security',
        'cloudflare_network_security',
        'security_alerts',
        'applications',
        'backup',
        'governance',
        'compliance'
    ]);

    assert.deepEqual(TEMPORARILY_DISABLED_DOMAIN_KEYS, [
        'operations'
    ]);
});

test('operations remains visible but cannot be selected while governance and compliance are active', async () => {
    const service = createEnterpriseIntelligenceService({
        pool: {},
        azureOpenAI: {},
        schedulerService: {}
    });

    const governance = service.domains.find(domain => domain.key === 'governance');
    const compliance = service.domains.find(domain => domain.key === 'compliance');

    assert.equal(governance.status, 'available');
    assert.equal(governance.selectable, true);
    assert.equal(governance.includedInCurrentPhase, true);

    assert.equal(compliance.status, 'available');
    assert.equal(compliance.selectable, true);
    assert.equal(compliance.includedInCurrentPhase, true);

    const disabled = service.domains.filter(domain =>
        TEMPORARILY_DISABLED_DOMAIN_KEYS.includes(domain.key)
    );

    assert.deepEqual(disabled.map(domain => domain.key), [
        'operations'
    ]);

    assert.ok(disabled.every(domain => domain.status === 'temporarily_disabled'));
    assert.ok(disabled.every(domain => domain.selectable === false));
    assert.ok(disabled.every(domain => domain.includedInCurrentPhase === false));

    const result = await service.runEnterpriseReport({
        companyId: 1,
        domainKeys: ['operations'],
        includeSynthesis: true
    });

    assert.equal(result.status, 'temporarily_disabled');
    assert.equal(result.runId, null);
    assert.equal(result.synthesisStatus, 'not_requested');
    assert.equal(result.domains[0].status, 'temporarily_disabled');
    assert.equal(result.domainRunSummary.failedDomains.length, 0);
});

test('heavy domains and large inputs enforce automation-safe cooldowns', () => {
    assert.equal(computeInterDomainDelayMs(1000, { domainDelayMs: 0 }, 'governance'), 120000);
    assert.equal(computeInterDomainDelayMs(30000, { domainDelayMs: 0 }, 'identity'), 60000);
    assert.equal(computeInterDomainDelayMs(50000, { domainDelayMs: 0 }, 'identity'), 180000);
});

test('enterprise output keeps real entity IDs and readable business values while isolating source paths', () => {
    const sourcePath = 'applications.evidence[0].data[2]';
    const entityId = '00f5434f-47f2-40e1-ac3e-4876dab2fc3e';
    const normalized = normalizeEvidenceBackedItem({
        title: 'Elevated application exposure',
        description: `Evidence from ${sourcePath} requires review.`,
        severity: 'high',
        sourceDomain: 'applications',
        sourceMetric: 'highRiskApps',
        businessReason: 'External application with elevated exposure',
        recommendation: 'Review access, permissions, and monitoring.',
        evidenceSource: sourcePath,
        affectedEntities: [{
            id: entityId,
            displayName: 'Microsoft Intune SCCM Connector',
            publisherName: 'Unknown',
            sourcePath
        }],
        affectedEntityIds: [sourcePath, entityId],
        recordIds: [sourcePath, entityId],
        sourceAlertIds: [sourcePath, 'alert-123'],
        evidenceRows: [{ sourcePath, data: { id: entityId, displayName: 'Microsoft Intune SCCM Connector', publisherName: 'Unknown' } }]
    }, ENTERPRISE_DOMAINS.find(domain => domain.key === 'applications'), 501);

    assert.deepEqual(normalized.affectedEntityIds, [entityId]);
    assert.deepEqual(normalized.recordIds, [entityId]);
    assert.deepEqual(normalized.sourceAlertIds, ['alert-123']);
    assert.equal(normalized.evidenceSource, 'stackctrl_dashboard_evidence');
    assert.deepEqual(normalized.internalSourcePaths, [sourcePath]);
    assert.doesNotMatch(normalized.description, /applications\.evidence/);
    assert.equal(normalized.affectedEntities[0].entityId, entityId);
    assert.equal(normalized.affectedEntities[0].entityName, 'Microsoft Intune SCCM Connector');
    assert.equal(normalized.affectedEntities[0].entityType, 'Application');
    assert.equal(normalized.affectedEntities[0].publisherName, 'Unknown');
    assert.equal(normalized.affectedEntities[0].businessReason, 'External application with elevated exposure');
    assert.equal(normalized.affectedEntities[0].recommendation, 'Review access, permissions, and monitoring.');
    assert.equal(normalized.affectedEntities[0].internalSourcePath, sourcePath);

    const service = createEnterpriseIntelligenceService({ pool: {}, azureOpenAI: {}, schedulerService: {} });
    const tables = service.flattenPowerBITables({
        domains: [{
            companyId: 1, snapshotId: 501, runId: 701, domainKey: 'applications', domainName: 'Applications',
            periodType: 'daily', periodStart: '2026-06-25', periodEnd: '2026-06-25', tokenUsage: {},
            intelligenceOutput: {
                risks: [{ ...normalized, riskId: 'risk-7' }],
                recommendations: [{ ...normalized, recommendationId: 'recommendation-9', riskId: 'risk-7' }]
            }
        }]
    });
    assert.equal(tables.RiskRegisterRows[0].riskId, 'risk-7');
    assert.equal(tables.RiskRegisterRows[0].title, 'Elevated application exposure');
    assert.equal(tables.RecommendationRows[0].recommendationId, 'recommendation-9');
    assert.equal(tables.AffectedEntityRows[0].riskId, 'risk-7');
    assert.equal(tables.AffectedEntityRows[0].entityId, entityId);
    assert.equal(tables.AffectedEntityRows[0].entityName, 'Microsoft Intune SCCM Connector');
    assert.equal(tables.AffectedEntityRows[0].entityDisplayName, 'Microsoft Intune SCCM Connector');
    assert.equal(tables.AffectedEntityRows[0].entityApplicationName, 'Microsoft Intune SCCM Connector');
    assert.equal(tables.AffectedEntityRows[0].publisherName, 'Unknown');
    assert.equal(tables.AffectedEntityRows[0].sourceMetric, 'highRiskApps');
    assert.equal(tables.AffectedEntityRows[0].internalSourcePath, sourcePath);
    assert.equal(tables.EvidenceRows[0].entityName, 'Microsoft Intune SCCM Connector');
    assert.equal(tables.EvidenceRows[0].internalSourcePath, sourcePath);
});

test('Email Security adapter freshness comes from Email evidence freshness', async () => {
    const pool = {
        async query(sql) {
            if (/CompanyMicrosoftMapping/i.test(sql)) {
                return [[{ MicrosoftTenantID: 1, TenantName: 'Sunbird', TenantID: 'tenant-1' }]];
            }
            if (/FROM StackCTRLEmailEvidenceSnapshots/i.test(sql)) {
                return [[{
                    ID: 77,
                    CompanyID: 1,
                    IsComplete: 1,
                    CollectionStatus: 'complete',
                    CollectedAt: '2026-06-24T05:16:14.000Z',
                    SourceFetchedAt: '2026-06-25T09:30:00.000Z',
                    CreatedAt: '2026-06-25T09:31:00.000Z',
                    EvidenceRecordCount: 1,
                    OmittedRecordCount: 0,
                    DashboardMetricsJson: JSON.stringify({ activeThreats: 1 })
                }]];
            }
            if (/FROM StackCTRLEmailEvidence WHERE SnapshotID/i.test(sql)) {
                return [[{
                    ID: 1,
                    SnapshotID: 77,
                    EvidenceKind: 'alert',
                    SourceID: 'alert-1',
                    ProcessedEvidenceJson: JSON.stringify({ id: 'alert-1', title: 'Phishing alert', severity: 'high' })
                }]];
            }
            return [[]];
        }
    };
    const result = await emailSecurityAdapter({
        pool,
        companyId: 1,
        capability: {
            sourceKey: 'email_security',
            displayName: 'Email Security',
            isExpected: true,
            isEnabled: true,
            profileKey: 'sunbird',
            refreshMode: 'stored_only',
            freshnessThresholdMinutes: 60
        }
    });

    assert.equal(result.freshness.lastUpdated, '2026-06-25T09:30:00.000Z');
    assert.equal(result.sourceLineage.sourceFetchedAt, '2026-06-25T09:30:00.000Z');
    assert.equal(result.sourceLineage.sourceLastUpdated, '2026-06-25T09:30:00.000Z');
});

test('Email Security adapter surfaces latest collection error when refresh has failed', async () => {
    const pool = {
        async query(sql) {
            if (/CompanyMicrosoftMapping/i.test(sql)) {
                return [[{ MicrosoftTenantID: 1, TenantName: 'Sunbird', TenantID: 'tenant-1' }]];
            }
            if (/IsComplete = 1 AND CollectionStatus = 'complete'/i.test(sql)) return [[]];
            if (/FROM StackCTRLEmailEvidenceSnapshots/i.test(sql)) {
                return [[{
                    ID: 88,
                    CompanyID: 1,
                    IsComplete: 0,
                    CollectionStatus: 'failed',
                    CollectedAt: '2026-06-25T10:00:00.000Z',
                    EvidenceRecordCount: 0,
                    DashboardMetricsJson: JSON.stringify({}),
                    IncompleteReason: 'Email evidence collection did not complete.',
                    ErrorMessage: 'Graph mailbox audit endpoint returned 403'
                }]];
            }
            return [[]];
        }
    };
    const result = await emailSecurityAdapter({
        pool,
        companyId: 1,
        capability: {
            sourceKey: 'email_security',
            displayName: 'Email Security',
            isExpected: true,
            isEnabled: true,
            profileKey: 'sunbird',
            refreshMode: 'stored_only',
            freshnessThresholdMinutes: 60
        }
    });

    assert.ok(['missing', 'stale'].includes(result.status));
    assert.match(result.errorMessage, /Graph mailbox audit endpoint returned 403/);
    assert.match(result.warnings.join(' '), /Graph mailbox audit endpoint returned 403/);
    assert.equal(result.sourceLineage.evidenceSnapshotId, 88);
    assert.equal(result.sourceLineage.collectionStatus, 'failed');
});

test('selected-domain visible output removes curated warning noise, positive risks, and empty fields', () => {
    const domain = ENTERPRISE_DOMAINS.find(item => item.key === 'applications');
    const normalized = normalizeDomainOutputForDisplay({
        domainExecutiveSummary: 'Applications posture is stable.',
        keyFindings: [
            { title: 'Curated Applications best-practice references were unavailable.', description: 'Ignore this.' },
            { title: 'External publisher apps need owner review', sourceMetric: 'externalApps', affectedEntities: [{ appId: 'app-1', displayName: 'Vendor App' }] }
        ],
        risks: [
            { title: 'No users assigned', description: 'No users assigned to this app.', sourceMetric: 'highAccessApps' },
            {
                title: 'Excessive permissions require review',
                sourceMetric: 'excessivePermissionApps',
                owner: null,
                status: null,
                category: '',
                priority: null,
                recommendedActions: [],
                evidenceUsed: [],
                affectedEntities: [{ appId: 'app-2', displayName: 'Mail Exporter', publisherName: 'Unknown' }],
                evidenceRows: [{ appId: 'app-2', displayName: 'Mail Exporter', publisherName: 'Unknown' }]
            }
        ],
        recommendations: [{ title: 'Curated Applications best-practice references were unavailable.' }],
        missingDataWarnings: ['Curated Applications best-practice references were unavailable.']
    }, domain, 501);

    assert.equal(normalized.keyFindings.length, 1);
    assert.equal(normalized.risks.length, 1);
    assert.equal(normalized.recommendations, undefined);
    assert.deepEqual(normalized.missingDataWarnings, []);
    const risk = normalized.risks[0];
    for (const field of ['owner', 'status', 'category', 'priority', 'recommendedActions', 'evidenceUsed']) {
        assert.equal(Object.hasOwn(risk, field), false, field);
    }
});

test('Cloudflare selected-domain entity fields are cleaned by entityType', () => {
    const domain = ENTERPRISE_DOMAINS.find(item => item.key === 'cloudflare_network_security');
    const normalized = normalizeDomainOutputForDisplay({
        risks: [{
            title: 'Cloudflare posture needs review',
            sourceMetric: 'gatewayPolicies',
            affectedEntities: [
                { entityId: 'app-1', entityName: 'Finance Access', entityType: 'Application', appName: 'Finance Access', deviceName: 'Laptop-1', profileName: 'DLP' },
                { entityId: 'dev-1', entityName: 'Laptop-1', entityType: 'Device', deviceName: 'Laptop-1', appName: 'Finance Access', policyName: 'Gateway Block' },
                { entityId: 'pol-1', entityName: 'Gateway Block', entityType: 'Policy', policyName: 'Gateway Block', appName: 'Finance Access', deviceName: 'Laptop-1', profileName: 'DLP' },
                { entityId: 'prof-1', entityName: 'DLP Profile', entityType: 'Profile', profileName: 'DLP Profile', appName: 'Finance Access', deviceName: 'Laptop-1', policyName: 'Gateway Block' }
            ]
        }]
    }, domain, 501);

    const [app, device, policy, profile] = normalized.risks[0].affectedEntities;
    assert.equal(app.appName, 'Finance Access');
    assert.equal(Object.hasOwn(app, 'deviceName'), false);
    assert.equal(Object.hasOwn(device, 'appName'), false);
    assert.equal(device.deviceName, 'Laptop-1');
    assert.equal(policy.policyName, 'Gateway Block');
    assert.equal(Object.hasOwn(policy, 'profileName'), false);
    assert.equal(profile.profileName, 'DLP Profile');
    assert.equal(Object.hasOwn(profile, 'policyName'), false);
});

test('selected-domain evidence linking keeps Backup and Applications risks on matching evidence groups', () => {
    const backupDomain = ENTERPRISE_DOMAINS.find(item => item.key === 'backup');
    const backupRisk = ensureItemEvidence({
        title: 'Backup coverage validation needs review',
        affectedEntities: [{ entityId: 'user-1', entityName: 'Large Mailbox User', entityType: 'User', sourceMetric: 'topStorageUsers' }]
    }, backupDomain, 501, [
        { evidenceType: 'topStorageUsers', sourceMetric: 'topStorageUsers', data: { entityId: 'user-1', entityName: 'Large Mailbox User', entityType: 'User' } },
        { evidenceType: 'backupCoverageGaps', sourceMetric: 'backupCoverageGaps', data: { entityId: 'backupCoverageGaps', entityName: 'Backup Coverage Validation', entityType: 'CoverageSummary', backupCoverageScore: 64 } }
    ]);
    assert.equal(backupRisk.sourceMetric, 'backupCoverageGaps');
    assert.equal(backupRisk.affectedEntities[0].entityId, 'backupCoverageGaps');
    assert.equal(backupRisk.affectedEntities[0].entityType, 'CoverageSummary');

    const applicationsDomain = ENTERPRISE_DOMAINS.find(item => item.key === 'applications');
    const appRisk = ensureItemEvidence({
        title: 'Excessive permissions require review',
        affectedEntities: [{ entityId: 'external-1', entityName: 'External Vendor App', sourceMetric: 'externalApps' }]
    }, applicationsDomain, 501, [
        { evidenceType: 'externalApps', sourceMetric: 'externalApps', data: { entityId: 'external-1', entityName: 'External Vendor App', entityType: 'Application' } },
        { evidenceType: 'excessivePermissionApps', sourceMetric: 'excessivePermissionApps', data: { entityId: 'perm-1', entityName: 'Mail Exporter', entityType: 'Application' } }
    ]);
    assert.equal(appRisk.sourceMetric, 'excessivePermissionApps');
    assert.equal(appRisk.affectedEntities[0].entityId, 'perm-1');
});

test('strict selected-domain packages keep curated-reference warnings internal when evidence exists', async () => {
    const service = createEnterpriseIntelligenceService({
        pool: { query: async () => [[]] },
        azureOpenAI: {},
        schedulerService: {}
    });

    const complianceMetrics = {
        totalControls: 4,
        apiControls: 3,
        manualControlsExcluded: 1,
        failingControls: 1,
        partialControls: 1,
        passingControls: 1,
        manualReviewControls: 0,
        complianceScore: 58
    };

    const cases = [
        {
            key: 'email_security',
            context: {
                sources: [{
                    sourceKey: 'email_security',
                    status: 'available',
                    isExpected: true,
                    metrics: { activeThreats: 1 },
                    dashboardMetrics: { activeThreats: 1 },
                    evidence: [{ evidenceType: 'alerts', data: [{ id: 'alert-1', title: 'Phishing alert', severity: 'high' }] }]
                }],
                riskEngine: { domainHealthScores: { email: 80 }, domainRiskScores: { email: 20 } }
            }
        },
        {
            key: 'backup',
            context: {
                sources: [{
                    sourceKey: 'backup',
                    status: 'available',
                    isExpected: true,
                    metrics: { backupCoverageScore: 80 },
                    dashboardMetrics: { backupCoverageScore: 80 },
                    evidence: [{ evidenceType: 'users', data: [{ id: 'user-1', displayName: 'Storage User', totalStorageGB: 200 }] }]
                }],
                riskEngine: { domainHealthScores: { backup: 80 }, domainRiskScores: { backup: 20 } }
            }
        },
        {
            key: 'applications',
            context: {
                sources: [{
                    sourceKey: 'applications',
                    status: 'available',
                    isExpected: true,
                    metrics: { excessivePermissionApps: 1 },
                    dashboardMetrics: { excessivePermissionApps: 1 },
                    evidence: [{ evidenceType: 'applications', data: [{ appId: 'app-1', displayName: 'Mail Exporter', permissionSummary: 'Mail.ReadWrite' }] }]
                }],
                riskEngine: { domainHealthScores: { applications: 80 }, domainRiskScores: { applications: 20 } }
            }
        },
        {
            key: 'compliance',
            context: {
                sources: [{
                    sourceKey: 'compliance',
                    status: 'available',
                    isExpected: true,
                    metrics: complianceMetrics,
                    dashboardMetrics: complianceMetrics,
                    sourceLineage: {
                        sourceBuilder: 'storedStackCTRLComplianceEvidence',
                        evidenceSnapshotId: 1201,
                        evidenceRecordCount: 3,
                        omittedRecordCount: 1,
                        manualRowsExcluded: 1
                    },
                    evidence: [{
                        evidenceType: 'controls',
                        data: [
                            {
                                controlId: 'compliance-control-1',
                                controlName: 'MFA coverage validation',
                                area: 'Identity',
                                status: 'Failed',
                                insight: '🔴 Failed',
                                evidenceSource: 'StackCTRL API Evidence'
                            },
                            {
                                controlId: 'compliance-control-2',
                                controlName: 'Device compliance validation',
                                area: 'Devices',
                                status: 'Partial',
                                insight: '🟡 Partial',
                                evidenceSource: 'StackCTRL API Evidence'
                            },
                            {
                                controlId: 'compliance-control-3',
                                controlName: 'Backup evidence validation',
                                area: 'Backup',
                                status: 'Passed',
                                insight: '🟢 Passing',
                                evidenceSource: 'StackCTRL API Evidence'
                            }
                        ]
                    }]
                }],
                riskEngine: { domainHealthScores: { compliance: 58 }, domainRiskScores: { compliance: 42 } }
            }
        }
    ];

    for (const item of cases) {
        const domain = ENTERPRISE_DOMAINS.find(candidate => candidate.key === item.key);

        const packageResult = await service.buildDomainPackage({
            companyId: 1,
            snapshot: {
                ID: 501,
                CreatedAt: '2026-06-25T10:00:00.000Z',
                MetricsJson: JSON.stringify({ stackctrl_risk: item.context.riskEngine }),
                ContextJson: JSON.stringify(item.context),
                SourceFreshnessJson: JSON.stringify({
                    [domain.sourceKey]: {
                        lastUpdated: '2026-06-25T09:55:00.000Z',
                        ageMinutes: 5,
                        status: 'available'
                    }
                })
            },
            runId: 701,
            domain,
            historicalContext: null
        });

        assert.equal(packageResult.audit.batchPlan.batchCount, 1, item.key);
        assert.equal(
            packageResult.package.limitations.missingDataWarnings.some(warning =>
                /curated|best-practice/i.test(String(warning))
            ),
            false,
            item.key
        );
    }
});

test('Security Alerts semantic batching preserves every record in a reasonable batch count', () => {
    const evidence = Array.from({ length: 100 }, (_, index) => ({
        evidenceType: index % 5 === 0 ? 'incidents' : 'alerts',
        sourceLabel: index % 5 === 0 ? 'incidents' : 'alerts',
        entityKey: `alert-${index + 1}`,
        data: {
            id: `alert-${index + 1}`,
            title: index % 2 ? 'Repeated malware alert 12345' : 'Repeated phishing alert 67890',
            severity: index < 10 ? 'critical' : index < 40 ? 'high' : 'medium',
            category: index % 2 ? 'malware' : 'phishing',
            source: 'Microsoft Defender',
            userPrincipalName: `user${index % 8}@example.com`
        }
    }));
    const batches = splitSecurityAlertsIntoBatches(evidence, { maxItems: 750, maxBytes: 350000, estimateBytes: items => Buffer.byteLength(JSON.stringify(items)) });
    assert.ok(batches.length >= 1 && batches.length <= 10);
    assert.equal(batches.flatMap(batch => batch.items).length, 100);
    assert.equal(new Set(batches.flatMap(batch => batch.items).map(item => item.data.id)).size, 100);
    assert.ok(batches.every(batch => batch.semanticGrouping.severities.length && batch.semanticGrouping.repeatedAlertPatterns.length));
});

function identityLikeEvidence() {
    return {
        users: Array.from({ length: 3000 }, (_, index) => ({ id: `user-${index + 1}`, enabled: true })),
        roles: Array.from({ length: 300 }, (_, index) => ({ id: `role-${index + 1}`, privileged: index < 20 })),
        signIns: Array.from({ length: 200 }, (_, index) => ({ id: `signin-${index + 1}`, risk: 'none' })),
        history: {
            daily: Array.from({ length: 90 }, (_, index) => ({ day: index + 1, riskySignIns: index % 3 }))
        }
    };
}

function domainResponse(domainKey) {
    return {
        domainExecutiveSummary: `${domainKey} requires evidence-based management attention.`,
        technicalSummary: 'Stored metrics and historical comparisons were assessed.',
        businessImpact: 'Control gaps may increase operational exposure.',
        currentPosture: 'partially controlled',
        evidenceUsed: ['StackCTRL metric evidence'],
        evidenceGaps: ['One control requires manual validation'],
        scoreJustification: 'The authoritative StackCTRL score is supported by the supplied metrics.',
        controlAssessment: { confirmed: ['MFA metrics'], unknown: ['Conditional Access policy detail'] },
        keyFindings: [{ title: 'Control gap', severity: 'high', evidenceSummary: 'Stored evidence supports this finding.' }],
        risks: [{ title: 'Domain risk', severity: 'high', businessImpact: 'Business exposure', evidenceSummary: 'Stored evidence', recommendation: 'Remediate' }],
        recommendations: [{ title: 'Remediate control', priority: 'high', suggestedOwner: 'IT Manager', suggestedDueDate: 'Ongoing' }],
        trendAnalysis: [{ metricName: 'Health score', currentValue: 75, previousValue: 70, changePercent: 7.14, direction: 'improving', comparisonPeriod: '24_hours' }],
        yesterdayVsToday: { direction: 'improving' },
        whatImproved: ['Health score'], whatDeteriorated: [], whatStayedTheSame: [],
        missingDataWarnings: [], assumptions: [], confidenceScore: 0.91,
        managementActions: [{ title: 'Approve remediation owner', priority: 'high', suggestedDueDate: 'ASAP' }],
        powerBiSummary: { status: 'attention' }
    };
}

function synthesisResponse() {
    return {
        enterpriseExecutiveSummary: { summary: 'Enterprise risk is moderate and evidence based.' },
        boardReport: { summary: 'Board attention is required for the highest risks.' },
        managementReport: { managementActions: [{ title: 'Assign remediation owners', priority: 'high' }] },
        riskRegister: [{ domainKey: 'identity', title: 'Identity risk', severity: 'high' }],
        recommendations: [{ domainKey: 'identity', title: 'Complete MFA', priority: 'high' }],
        trendAnalysis: [{ domainKey: 'identity', metricName: 'MFA', direction: 'improving', comparisonPeriod: '24_hours' }],
        complianceReview: {}, governanceReview: {}, domainScorecard: [], maturityAssessment: { level: 'defined' },
        businessImpactSummary: 'Cybersecurity gaps may disrupt operations.', topDecisionsRequired: ['Approve owners'],
        next30DaysPlan: ['Close critical gaps'], next90DaysPlan: ['Improve maturity'],
        evidenceJustificationSummary: { domains: 1 }, limitationsAndAssumptions: [],
        powerBiSummary: { risk_score: 35, risk_level: 'moderate' }
    };
}

test('enterprise pipeline queues domain analysis, stores audit rows, then synthesizes stored intelligence', async () => {
    const calls = [];
    const azurePrompts = [];
    let insertId = 100;
    const snapshot = {
        ID: 76, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-22T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ identity: { mfaCoverage: 90 }, stackctrl_risk: { domainRiskScores: { identity: 25 } }, executive_kpis: { identityHealth: 75 } }),
        ContextJson: JSON.stringify({
            secretRawContextMarker: 'must-not-reach-synthesis',
            riskEngine: { domainHealthScores: { identity: 75 }, domainRiskScores: { identity: 25 }, executiveKPIs: { identityHealth: 75 } },
            sources: [{ sourceKey: 'identity', status: 'available', isExpected: true, freshness: { ageMinutes: 2 }, metrics: { mfaCoverage: 90 }, evidence: [{ evidenceType: 'metric_summary', data: { usersWithoutMfa: 2 } }] }]
        })
    };
    const pool = {
        async query(sql, params = []) {
            calls.push({ sql, params });
            assert.equal((sql.match(/\?/g) || []).length, params.length, `Placeholder mismatch in ${sql}`);
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[{ Title: 'MFA guidance', SourceType: 'manual', ContentSummary: 'Require strong MFA.', BestPracticeJson: '{}' }], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (sql.includes('SELECT ID, CompanyID, SnapshotID, RunID, DomainKey')) {
                return [[{
                    ID: 200, CompanyID: 1, SnapshotID: 76, RunID: 100, DomainKey: 'identity', DomainName: 'Identity Protection',
                    HealthScore: 75, RiskScore: 25, RiskLevel: 'moderate', Status: 'completed',
                    DomainExecutiveSummary: 'Identity summary', TechnicalSummary: 'Technical summary', BusinessImpact: 'Impact', CurrentPosture: 'partial',
                    EvidenceSummary: 'Evidence', ScoreJustification: 'Justified', ControlAssessment: '{}', FindingsJson: '[]', RisksJson: '[]',
                    RecommendationsJson: '[]', TrendAnalysisJson: '[]', YesterdayVsTodayJson: '{}', MissingDataWarningsJson: '[]', AssumptionsJson: '[]'
                }], []];
            }
            if (sql.includes('FROM StackCTRLEnterpriseSynthesis synthesis')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const schedulerService = {
        async getHistoricalSnapshotContext() {
            return { comparisons: { '24_hours': { availability: 'unavailable', snapshot: null, metricChanges: {} } } };
        }
    };
    const azureOpenAI = {
        async createJsonCompletion(options) {
            assert.equal(options.maxRetriesOverride, 3);
            azurePrompts.push(options.messages[1].content);
            const data = azurePrompts.length === 1 ? domainResponse('identity') : synthesisResponse();
            return { data, requestSizeBytes: 1200, responseSizeBytes: 2400, retryCount: 0, usage: { input_tokens: 500, output_tokens: 250, total_tokens: 750 } };
        }
    };
    const service = createEnterpriseIntelligenceService({ pool, azureOpenAI, schedulerService, wait: async () => {}, config: { domainDelayMs: 0, maxInputBytes: 100000 } });
    const result = await service.runEnterpriseReport({ companyId: 1, snapshotId: 76, domainKeys: ['identity'], includeSynthesis: true });

    assert.equal(result.domains[0].status, 'completed');
    assert.ok(result.synthesisId);
    assert.equal(azurePrompts.length, 2);
    assert.match(azurePrompts[0], /stackctrl_enterprise_identity_table/);
    assert.match(azurePrompts[0], /evidenceUsed/);
    assert.match(azurePrompts[0], /Do not create layouts, visuals, HTML/);
    assert.match(azurePrompts[1], /synthesisUsesStoredIntelligenceOnly/);
    assert.doesNotMatch(azurePrompts[1], /secretRawContextMarker/);
    assert.ok(calls.some(call => call.sql.includes('StackCTRLIntelligenceEvidenceAudit')));
    assert.ok(calls.some(call => call.sql.includes('StackCTRLEnterpriseIntelligenceItems')));
    assert.ok(calls.some(call => call.sql.includes('StackCTRLEnterpriseSynthesis')));
    const itemWrites = calls.filter(call => call.sql.includes('INSERT INTO StackCTRLEnterpriseIntelligenceItems'));
    assert.ok(itemWrites.length);
    assert.equal(itemWrites.some(call => call.params.includes('Ongoing') || call.params.includes('ASAP')), false);
    assert.ok(itemWrites.some(call => call.params.includes(null)));
    assert.ok(calls.some(call => call.sql.includes('DELETE FROM StackCTRLEnterpriseIntelligenceItems WHERE RunID = ? AND DomainKey = ?')));
});

test('Identity sends 57 normal users as one compact Azure table even when the global item cap is one', async () => {
    const users = Array.from({ length: 57 }, (_, index) => ({
        id: `user-${index + 1}`,
        displayName: `User ${index + 1}`,
        mail: `user${index + 1}@example.com`,
        userPrincipalName: `user${index + 1}@example.com`,
        jobTitle: index % 2 ? 'Analyst' : 'Manager',
        roles: index < 3 ? [{ name: 'Global Administrator' }] : ['Employee'],
        userType: 'Member',
        mfaEnabled: index % 10 !== 0,
        authMethodCount: index % 3 + 1,
        riskLevel: index < 2 ? 'HIGH' : 'SAFE',
        accountEnabled: true,
        lastSignIn: {
            dateTime: '2026-06-24T08:00:00.000Z', daysSince: 1,
            location: 'Johannesburg, South Africa', device: `LAPTOP-${index + 1}`, status: 'Success'
        },
        flags: { adminWithoutMFA: index === 0, inactiveOver30Days: false }
    }));
    const snapshot = {
        ID: 570, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-25T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ stackctrl_risk: { domainRiskScores: { identity: 20 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { identity: 80 }, domainRiskScores: { identity: 20 } },
            sources: [{
                sourceKey: 'identity', status: 'available', isExpected: true, freshness: { ageMinutes: 2 },
                sourceLineage: { evidenceRecordCount: 57, omittedRecordCount: 0 },
                evidence: [{ evidenceType: 'users', data: users }]
            }]
        })
    };
    let insertId = 5700;
    const azurePackages = [];
    const prompts = [];
    const logMessages = [];
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: { '24_hours': { availability: 'available', snapshot: { ID: 1 }, metricChanges: { mfaCoverage: 1 } } } }; } },
        azureOpenAI: {
            async createJsonCompletion(options) {
                const prompt = options.messages[1].content;
                prompts.push(prompt);
                azurePackages.push(JSON.parse(prompt.split('STACKCTRL DOMAIN PACKAGE:\n')[1]));
                return {
                    data: {
                        ...domainResponse('identity'),
                        technicalReasoning: 'Privileged users without MFA create a stronger identity takeover path than normal users without MFA because role blast radius changes the business impact.',
                        riskPrioritization: [{
                            title: 'Privileged MFA gaps first',
                            reasoning: 'Global Administrator without MFA outranks normal-user MFA gaps.',
                            priority: 'critical'
                        }],
                        highestRiskPatterns: [{
                            title: 'Admin role combined with missing MFA',
                            severity: 'critical',
                            affectedEntities: [{
                                entityId: 'user-1',
                                entityName: 'User 1',
                                entityEmail: 'user1@example.com',
                                entityType: 'User',
                                userPrincipalName: 'user1@example.com',
                                roles: ['Global Administrator'],
                                hasAdminRole: true,
                                mfaEnabled: false,
                                riskLevel: 'HIGH',
                                accountStatus: 'enabled',
                                lastSignIn: { dateTime: '2026-06-24T08:00:00.000Z', device: 'LAPTOP-1' },
                                businessReason: 'Privileged account lacks MFA.',
                                recommendation: 'Require MFA before privileged access continues.'
                            }]
                        }],
                        risks: [{
                            riskId: 'identity-risk-1',
                            title: 'Privileged account without MFA',
                            severity: 'critical',
                            patternFound: 'Global Administrator without MFA',
                            reasoning: 'Admin role plus missing MFA is higher risk than a normal user without MFA.',
                            whyThisIsHighPriority: 'The account can change tenant-wide security settings.',
                            whyThisIsWorseThanLowerPriorityIssues: 'Normal users without MFA have narrower blast radius.',
                            evidenceUsed: ['User 1 has Global Administrator and missing MFA.'],
                            firstAction: 'Block privileged sign-in until MFA is registered.',
                            followUpAction: 'Review all privileged role assignments.',
                            businessImpact: 'Tenant-wide compromise risk.',
                            managementDecisionRequired: 'Should privileged accounts without MFA be blocked until MFA is enforced?',
                            whatCanWait: 'Normal-user MFA gaps can be grouped after privileged gaps.',
                            recommendedOwner: 'Identity Administrator',
                            suggestedDueDate: '2026-07-01',
                            affectedEntityIds: ['user-1', 'identity.evidence[0].data[0]'],
                            recordIds: ['user-1', 'identity.evidence[0].data[0]'],
                            sourceAlertIds: ['identity.evidence[0].data[0]'],
                            affectedEntities: [{
                                entityId: 'user-1',
                                entityName: 'User 1',
                                entityEmail: 'user1@example.com',
                                entityType: 'User',
                                userPrincipalName: 'user1@example.com',
                                roles: ['Global Administrator'],
                                hasAdminRole: true,
                                mfaEnabled: false,
                                riskLevel: 'HIGH',
                                accountStatus: 'enabled',
                                lastSignIn: { dateTime: '2026-06-24T08:00:00.000Z', device: 'LAPTOP-1' },
                                businessReason: 'Privileged account lacks MFA.',
                                recommendation: 'Require MFA before privileged access continues.',
                                internalSourcePath: 'identity.evidence[0].data[0]'
                            }]
                        }],
                        managementDecisionsRequired: [{
                            title: 'Block privileged users without MFA',
                            recommendedAction: 'Require MFA before privileged access continues.',
                            affectedEntityIds: ['user-1']
                        }],
                        whatCanWait: [{
                            title: 'Normal-user MFA cleanup',
                            detail: 'Normal users without MFA can be grouped after privileged remediation.'
                        }]
                    }, requestSizeBytes: Buffer.byteLength(prompt), responseSizeBytes: 1000,
                    usage: { input_tokens: 4000, output_tokens: 300, total_tokens: 4300 }
                };
            }
        },
        logger: {
            info(...values) { logMessages.push(values.join(' ')); },
            warn(...values) { logMessages.push(values.join(' ')); },
            error(...values) { logMessages.push(values.join(' ')); }
        },
        wait: async () => {},
        config: { domainDelayMs: 0, maxItemsPerBatch: 1, thresholdBatchMaxItems: 1, maxInputBytes: 150000 }
    });

    const result = await service.runEnterpriseReport({ companyId: 1, snapshotId: 570, domainKeys: ['identity'], includeSynthesis: false });
    const identityPackage = azurePackages[0];

    assert.equal(azurePackages.length, 1);
    assert.equal(identityPackage.evidence.length, 57);
    assert.equal(identityPackage.sharedContextIncluded, true);
    assert.equal(identityPackage.contextType, 'stackctrl_enterprise_identity_table');
    assert.equal(identityPackage.evidence[0].name, 'User 1');
    assert.equal(identityPackage.evidence[0].userPrincipalName, 'user1@example.com');
    assert.equal(identityPackage.evidence[0].mfaStatus, 'missing');
    assert.equal(identityPackage.evidence[0].authMethodCount, 1);
    assert.equal(identityPackage.evidence[0].device, 'LAPTOP-1');
    assert.ok(identityPackage.evidence[0].keyFlags.includes('adminWithoutMFA'));
    assert.equal(Object.prototype.hasOwnProperty.call(identityPackage, 'evidenceCatalog'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(identityPackage, 'historicalComparisons'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(identityPackage, 'previousDomainAnalysis'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(identityPackage, 'knowledgeGrounding'), false);
    assert.equal(result.domains[0].batchInfo.totalBatches, 1);
    assert.equal(result.domains[0].batchInfo.reasonForBatchCount, 'all_identity_rows_fit_safe_token_limit');
    assert.ok(result.domains[0].batchInfo.basePackageTokens > 0);
    assert.ok(result.domains[0].batchInfo.evidenceTokens > 0);
    assert.ok(result.domains[0].batchInfo.totalEstimatedTokens < result.domains[0].batchInfo.safeInputTokenLimit);
    assert.match(logMessages.join('\n'), /basePackageTokens=\d+.*evidenceTokens=\d+.*totalEstimatedTokens=\d+.*reasonForBatchCount=all_identity_rows_fit_safe_token_limit/);
    assert.match(prompts[0], /Pattern -> Reasoning -> Priority -> Evidence -> Action -> Business decision/);
    assert.match(prompts[0], /privileged MFA coverage matters more/i);
    assert.ok(result.domains[0].analysis.technicalReasoning.length <= 5);
    assert.equal(typeof result.domains[0].analysis.technicalReasoning[0].reasoning, 'string');
    assert.equal(result.domains[0].analysis.riskPrioritization[0].priority, 'critical');
    const risk = result.domains[0].analysis.risks[0];
    assert.equal(risk.patternFound, 'Global Administrator without MFA');
    assert.match(risk.reasoning, /Admin role plus missing MFA/i);
    assert.equal(risk.affectedEntityIds.some(value => /identity\.evidence/i.test(value)), false);
    assert.equal(risk.recordIds.some(value => /identity\.evidence/i.test(value)), false);
    assert.equal(risk.sourceAlertIds.some(value => /identity\.evidence/i.test(value)), false);
    assert.equal(risk.affectedEntities[0].entityName, 'User 1');
    assert.equal(risk.affectedEntities[0].entityEmail, 'user1@example.com');
    assert.equal(risk.affectedEntities[0].userPrincipalName, 'user1@example.com');
    assert.equal(risk.affectedEntities[0].roles[0], 'Global Administrator');
    assert.equal(risk.affectedEntities[0].hasAdminRole, true);
    assert.equal(risk.affectedEntities[0].mfaEnabled, false);
    assert.equal(risk.affectedEntities[0].internalSourcePath, 'identity.evidence[0].data[0]');
});

test('Device Protection sends 17 devices as one compact Azure table and keeps readable device output', async () => {
    const sourcePath = 'devices.evidence[0].data[2]';
    const devices = Array.from({ length: 17 }, (_, index) => ({
        id: `device-${index + 1}`,
        deviceName: index === 2 ? 'LAPTOP2023' : `LAPTOP-${index + 1}`,
        userPrincipalName: index === 2 ? 'ken@sunbird.eu' : `user${index + 1}@example.com`,
        operatingSystem: 'Windows',
        osVersion: '11.0.22631',
        complianceState: index === 2 ? 'nonCompliant' : 'compliant',
        isEncrypted: true,
        managementAgent: 'mdm',
        lastSyncDateTime: index === 2 ? '2026-05-20T08:00:00.000Z' : '2026-06-24T08:00:00.000Z',
        deviceEnrollmentType: 'windowsAzureADJoin',
        serialNumber: `SN-${index + 1}`,
        riskLevel: index === 2 ? 'High' : 'Safe',
        securityAlertCount: index === 2 ? 2 : 0
    }));
    const rawEvidence = [{ evidenceType: 'devices', data: devices }];
    const rawEvidenceBefore = JSON.stringify(rawEvidence);
    const snapshot = {
        ID: 617, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-25T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ stackctrl_risk: { domainRiskScores: { devices: 22 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { devices: 78 }, domainRiskScores: { devices: 22 } },
            sources: [{
                sourceKey: 'devices', status: 'stale', isExpected: true,
                freshness: { lastUpdated: '2026-06-24T05:16:14.000Z', ageMinutes: 1600 },
                warnings: ['Device Protection evidence is stale.', 'Device Protection evidence is stale.'],
                dashboardMetrics: {
                    totalDevices: 17, compliantDevices: 16, nonCompliantDevices: 1,
                    encryptedDevices: 17, notEncryptedDevices: 0, unmanagedDevices: 0,
                    activeDevices24h: 16, staleDevices: 0, dead30Days: 1,
                    highRiskDevices: 1, securityAlerts: 2, deviceSecurityScore: 82
                },
                sourceLineage: { evidenceRecordCount: 17, omittedRecordCount: 0, collectedAt: '2026-06-24T05:16:14.000Z' },
                evidence: rawEvidence
            }]
        })
    };
    let insertId = 6170;
    const azurePackages = [];
    const prompts = [];
    const logMessages = [];
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: {
            async createJsonCompletion(options) {
                const prompt = options.messages[1].content;
                prompts.push(prompt);
                azurePackages.push(JSON.parse(prompt.split('STACKCTRL DOMAIN PACKAGE:\n')[1]));
                return {
                    data: {
                        ...domainResponse('devices'),
                        domainExecutiveSummary: 'Device posture is mostly healthy, with one stale non-compliant high-risk endpoint requiring priority remediation.',
                        technicalReasoning: 'Non-compliant stale devices with assigned users are higher priority than encrypted, managed, recently synced devices.',
                        riskPrioritization: [{
                            title: 'Stale non-compliant assigned endpoint',
                            reasoning: 'Non-compliant plus dead sync age and assigned user creates direct business exposure.',
                            priority: 'critical'
                        }],
                        highestRiskPatterns: [{
                            title: 'Non-compliant stale assigned device',
                            severity: 'critical',
                            affectedEntities: [{
                                entityId: 'device-3',
                                entityName: 'LAPTOP2023',
                                entityType: 'Device',
                                entityDeviceName: 'LAPTOP2023',
                                assignedUser: 'ken@sunbird.eu',
                                operatingSystem: 'Windows',
                                osVersion: '11.0.22631',
                                complianceState: 'nonCompliant',
                                encryptionState: 'encrypted',
                                managementState: 'mdm',
                                lastSyncDateTime: '2026-05-20T08:00:00.000Z',
                                lastSyncDaysAgo: 36,
                                riskLevel: 'High',
                                businessReason: 'Assigned stale non-compliant endpoint increases compromise exposure.',
                                recommendation: 'Remediate, block, or retire the device.'
                            }]
                        }],
                        collectionWindow: {
                            sourceSystem: 'Microsoft Graph / Intune / StackCTRL Devices',
                            sourceLastUpdatedAt: '2026-06-24T05:16:14.000Z',
                            sourceAgeMinutes: 1600,
                            reportingWindow: 'current tenant device state from the frozen StackCTRL Device Protection snapshot'
                        },
                        missingDataWarnings: [
                            'Device Protection evidence is stale.',
                            'Device Protection evidence is stale.',
                            'Curated Device Protection best-practice references were unavailable.'
                        ],
                        risks: [{
                            riskId: 'device-risk-1',
                            title: 'Stale non-compliant endpoint',
                            severity: 'high',
                            patternFound: 'Non-compliant device stale over 30 days with assigned user',
                            reasoning: 'Non-compliant plus stale/dead sync is higher risk than non-compliance alone because policies may no longer be applying.',
                            whyThisIsHighPriority: 'The device is assigned to a user and has not synced recently.',
                            whyThisIsWorseThanLowerPriorityIssues: 'Compliant encrypted managed devices can wait because they are still receiving policy.',
                            businessReason: 'Non-compliant and stale device increases endpoint compromise risk.',
                            recommendation: 'Remediate compliance or retire the device.',
                            evidenceUsed: ['LAPTOP2023 is non-compliant, assigned, and stale.'],
                            firstAction: 'Investigate the device owner and current device state.',
                            followUpAction: 'Remediate, block, or retire the device.',
                            businessImpact: 'Endpoint compromise and policy drift exposure.',
                            managementDecisionRequired: 'Should stale non-compliant devices be remediated, blocked, or retired?',
                            whatCanWait: 'Encrypted MDM-managed devices with recent sync can wait.',
                            recommendedOwner: 'Endpoint Administrator',
                            suggestedDueDate: '2026-07-01',
                            affectedEntityIds: ['device-3', sourcePath],
                            recordIds: ['device-3', sourcePath],
                            sourceAlertIds: [sourcePath],
                            affectedEntities: [{
                                entityId: 'device-3',
                                entityName: 'LAPTOP2023',
                                entityType: 'Device',
                                entityDeviceName: 'LAPTOP2023',
                                entityUser: 'ken@sunbird.eu',
                                operatingSystem: 'Windows',
                                osVersion: '11.0.22631',
                                complianceState: 'nonCompliant',
                                encryptionState: 'encrypted',
                                managementState: 'mdm',
                                lastSyncDateTime: '2026-05-20T08:00:00.000Z',
                                lastSyncDaysAgo: 36,
                                riskLevel: 'High',
                                businessReason: 'Non-compliant and stale device increases endpoint compromise risk.',
                                recommendation: 'Remediate compliance or retire the device.',
                                internalSourcePath: sourcePath
                            }]
                        }],
                        managementDecisionsRequired: [{
                            title: 'Decide stale endpoint treatment',
                            recommendedAction: 'Choose remediate, block, or retire for LAPTOP2023.',
                            affectedEntityIds: ['device-3']
                        }],
                        whatCanWait: [{
                            title: 'Encryption coverage',
                            detail: 'Most devices are encrypted and MDM-managed, so encryption is not the immediate crisis.'
                        }]
                    },
                    requestSizeBytes: Buffer.byteLength(prompt),
                    responseSizeBytes: 1000,
                    usage: { input_tokens: 2000, output_tokens: 500, total_tokens: 2500 }
                };
            }
        },
        logger: {
            info(...values) { logMessages.push(values.join(' ')); },
            warn(...values) { logMessages.push(values.join(' ')); },
            error(...values) { logMessages.push(values.join(' ')); }
        },
        wait: async () => {},
        config: { domainDelayMs: 0, maxItemsPerBatch: 1, thresholdBatchMaxItems: 1, maxInputBytes: 150000 }
    });

    const result = await service.runEnterpriseReport({ companyId: 1, snapshotId: 617, domainKeys: ['devices'], includeSynthesis: false });
    const devicePackage = azurePackages[0];

    assert.equal(JSON.stringify(rawEvidence), rawEvidenceBefore);
    assert.equal(azurePackages.length, 1);
    assert.equal(devicePackage.contextType, 'stackctrl_enterprise_device_table');
    assert.equal(devicePackage.evidence.length, 17);
    assert.equal(devicePackage.evidence[2].deviceName, 'LAPTOP2023');
    assert.equal(devicePackage.evidence[2].assignedUser, 'ken@sunbird.eu');
    assert.equal(devicePackage.evidence[2].complianceState, 'nonCompliant');
    assert.equal(devicePackage.evidence[2].encryptionState, 'encrypted');
    assert.equal(devicePackage.evidence[2].managementState, 'mdm');
    assert.equal(Object.hasOwn(devicePackage, 'evidenceCatalog'), false);
    assert.equal(Object.hasOwn(devicePackage, 'historicalComparisons'), false);
    assert.equal(Object.hasOwn(devicePackage, 'previousDomainAnalysis'), false);
    assert.equal(Object.hasOwn(devicePackage, 'knowledgeGrounding'), false);
    assert.equal(result.domains[0].batchInfo.totalBatches, 1);
    assert.equal(result.domains[0].batchInfo.reasonForBatchCount, 'all_device_rows_fit_safe_token_limit');
    assert.ok(result.domains[0].batchInfo.deviceTableTokens > 0);
    assert.match(logMessages.join('\n'), /Device batch plan: basePackageTokens=\d+.*deviceTableTokens=\d+.*plannedBatchCount=1.*reasonForBatchCount=all_device_rows_fit_safe_token_limit/);
    assert.match(prompts[0], /Pattern -> Reasoning -> Priority -> Evidence -> Action -> Business decision/);
    assert.match(prompts[0], /non-compliant \+ stale\/dead/i);
    assert.match(result.domains[0].analysis.technicalReasoning, /Non-compliant stale devices/i);
    assert.equal(result.domains[0].analysis.riskPrioritization[0].priority, 'critical');

    const risk = result.domains[0].analysis.risks[0];
    assert.equal(risk.patternFound, 'Non-compliant device stale over 30 days with assigned user');
    assert.ok(risk.affectedEntityIds.includes('device-3'));
    assert.ok(risk.recordIds.includes('device-3'));
    assert.equal(risk.affectedEntityIds.some(value => /devices\.evidence/i.test(value)), false);
    assert.equal(risk.recordIds.some(value => /devices\.evidence/i.test(value)), false);
    assert.ok(risk.sourceAlertIds.includes('device-3'));
    assert.equal(risk.sourceAlertIds.some(value => /devices\.evidence/i.test(value)), false);
    assert.equal(risk.affectedEntities[0].entityName, 'LAPTOP2023');
    assert.equal(risk.affectedEntities[0].entityDeviceName, 'LAPTOP2023');
    assert.equal(risk.affectedEntities[0].assignedUser, 'ken@sunbird.eu');
    assert.equal(risk.affectedEntities[0].complianceState, 'nonCompliant');
    assert.equal(risk.affectedEntities[0].lastSyncDaysAgo, 36);
    assert.equal(risk.affectedEntities[0].internalSourcePath, sourcePath);
    assert.equal(result.domains[0].analysis.missingDataWarnings.filter(warning => /stale/i.test(warning)).length, 0);
    assert.equal(result.domains[0].analysis.missingDataInfo.filter(info => /Device Protection source is stale/i.test(info)).length, 1);
    assert.equal(result.domains[0].analysis.collectionWindow.sourceSystem, 'Microsoft Graph / Intune / StackCTRL Devices');

    const tables = service.flattenPowerBITables({ domains: [{
        companyId: 1,
        snapshotId: 617,
        runId: result.runId,
        domainKey: 'devices',
        domainName: 'Device Protection',
        intelligenceOutput: result.domains[0].analysis
    }] });
    const deviceRow = tables.AffectedEntityRows.find(row => row.entityId === 'device-3');
    assert.equal(deviceRow.entityName, 'LAPTOP2023');
    assert.equal(deviceRow.entityDeviceName, 'LAPTOP2023');
    assert.equal(deviceRow.assignedUser, 'ken@sunbird.eu');
    assert.equal(deviceRow.operatingSystem, 'Windows');
    assert.equal(deviceRow.complianceState, 'nonCompliant');
    assert.equal(deviceRow.encryptionState, 'encrypted');
    assert.equal(deviceRow.managementState, 'mdm');
    assert.equal(deviceRow.internalSourcePath, sourcePath);
});

test('Email Security selected-domain stops cleanly on Azure 429 without synthesis or evidence omission', async () => {
    const alerts = Array.from({ length: 43 }, (_, index) => ({
        id: `email-alert-${index + 1}`,
        title: `Phishing alert ${index + 1}`,
        severity: index < 3 ? 'high' : 'medium',
        userPrincipalName: `user${index + 1}@example.com`
    }));
    const mailflowUsers = Array.from({ length: 80 }, (_, index) => ({
        userPrincipalName: `mailbox${index + 1}@example.com`,
        sendCount: index + 1,
        receiveCount: 80 - index,
        readCount: index % 3,
        lastActivityDate: index < 70 ? '2026-06-24' : null
    }));
    const snapshot = {
        ID: 643, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-25T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ stackctrl_risk: { domainRiskScores: { email_security: 35 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { email_security: 65 }, domainRiskScores: { email_security: 35 } },
            sources: [{
                sourceKey: 'email_security', status: 'available', isExpected: true, freshness: { ageMinutes: 2 },
                dashboardMetrics: { activeThreats: 43, highSeverityAlerts: 3, affectedUsersCount: 43 },
                sourceLineage: { evidenceRecordCount: 43, omittedRecordCount: 0 },
                evidence: [
                    { evidenceType: 'alerts', data: { alerts } },
                    { evidenceType: 'mailActivityUsers', data: mailflowUsers }
                ]
            }]
        })
    };
    let insertId = 6430;
    let synthesisCalls = 0;
    let emailOptions = null;
    let emailPackage = null;
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: {
            async createJsonCompletion(options) {
                if (options.messages[1].content.includes('STACKCTRL DOMAIN PACKAGE')) {
                    emailOptions = options;
                    emailPackage = JSON.parse(options.messages[1].content.split('STACKCTRL DOMAIN PACKAGE:\n')[1]);
                    const error = new Error('Azure OpenAI rate limited the request with 429');
                    error.azureMetadata = { rateLimited: true, statusCode: 429, retryAfterMs: 90000, retryCount: 0 };
                    throw error;
                }
                synthesisCalls += 1;
                return { data: {}, usage: {} };
            }
        },
        logger: { info() {}, warn() {}, error() {} },
        wait: async () => {},
        config: { domainDelayMs: 0, maxItemsPerBatch: 100, maxInputBytes: 150000 }
    });

    const result = await service.runEnterpriseReport({ companyId: 1, snapshotId: 643, domainKeys: ['email_security'], includeSynthesis: true });

    assert.equal(emailOptions.maxRetriesOverride, 0);
    assert.deepEqual(emailOptions.retryDelaysMsOverride, []);
    assert.equal(emailPackage.contextType, 'stackctrl_enterprise_email_security_strict_compact');
    assert.equal(emailPackage.batchMetadata.totalBatches, 1);
    assert.equal(emailPackage.compactEvidenceSummary.mailflowIsContextOnly, true);
    assert.equal(Object.hasOwn(emailPackage, 'historicalComparisons'), false);
    assert.equal(Object.hasOwn(emailPackage, 'knowledgeGrounding'), false);
    assert.equal(Object.hasOwn(emailPackage, 'previousDomainAnalysis'), false);
    assert.equal(Object.hasOwn(emailPackage, 'dataLineage'), false);
    assert.equal(Object.hasOwn(emailPackage, 'domainRunAudit'), false);
    assert.equal(Object.hasOwn(emailPackage, 'tokenTracking'), false);
    assert.equal(Object.hasOwn(emailPackage, 'evidenceBatchPlan'), false);
    assert.equal(emailOptions.maxTokens, 6000);
    assert.equal(emailPackage.evidence.filter(row => row.evidenceType === 'securityAlerts').length, 25);
    assert.ok(emailPackage.evidence.filter(row => row.evidenceType === 'highVolumeMailboxes').length <= 10);
    assert.ok(emailPackage.evidence.filter(row => row.evidenceType === 'inactiveMailboxes').length <= 10);
    assert.equal(emailPackage.evidence.filter(row => row.evidenceType === 'mailActivityUsers').length, 0);
    assert.equal(emailPackage.evidence.some(row => row.evidenceType === 'mailflowSummary'), true);
    assert.equal(emailPackage.evidence.find(row => row.evidenceType === 'mailflowSummary').data.contextOnly, true);
    assert.equal(result.status, 'failed_rate_limited');
    assert.equal(result.rateLimited, true);
    assert.equal(result.synthesisStatus, 'skipped_rate_limited');
    assert.equal(result.domains[0].status, 'failed_rate_limited');
    assert.equal(result.domains[0].analysis, null);
    assert.equal(result.rateLimit.retryAfterMs, 90000);
    assert.equal(synthesisCalls, 0);
});

test('Cloudflare selected-domain prompt and output stay readable and domain-specific', async () => {
    const sourcePath = 'cloudflare_network_security.evidence[0].data[0]';
    const snapshot = {
        ID: 644, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-25T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ stackctrl_risk: { domainRiskScores: { cloudflare_network_security: 28 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { cloudflare_network_security: 72 }, domainRiskScores: { cloudflare_network_security: 28 } },
            sources: [{
                sourceKey: 'cloudflare_network_security', status: 'available', isExpected: true, freshness: { ageMinutes: 5 },
                dashboardMetrics: { protectedApps: 2, enrolledDevices: 3, gatewayPolicies: 2, recentAccessEvents: 10, dlpProfiles: 1, sectionErrors: 1 },
                sourceLineage: { evidenceRecordCount: 12, omittedRecordCount: 0 },
                evidence: [
                    { evidenceType: 'accessApps', data: [
                        { id: 'app-1', appName: 'Finance Portal', policyName: 'Finance Access Policy' },
                        { id: 'app-2', appName: 'HR Portal', policyName: 'HR Access Policy' }
                    ] },
                    { evidenceType: 'devices', data: [
                        { id: 'cf-device-1', deviceName: 'KEN-LAPTOP', userEmail: 'ken@sunbird.eu' },
                        { id: 'cf-device-2', deviceName: 'FINANCE-TABLET', userEmail: 'finance@sunbird.eu' }
                    ] },
                    { evidenceType: 'gatewayRules', data: [
                        { id: 'policy-1', gatewayPolicyName: 'Block Risky Domains' },
                        { id: 'policy-2', gatewayPolicyName: 'Require WARP for Finance' }
                    ] },
                    { evidenceType: 'accessLogs', data: [
                        { id: 'log-1', applicationName: 'Finance Portal', action: 'deny' },
                        { id: 'log-2', applicationName: 'HR Portal', action: 'allow' }
                    ] },
                    { evidenceType: 'dlpProfiles', data: [
                        { id: 'dlp-1', dlpProfileName: 'Finance DLP' },
                        { id: 'dlp-2', dlpProfileName: 'PII DLP' }
                    ] },
                    { evidenceType: 'warpProfiles', data: [{ id: 'warp-1', warpProfileName: 'Default WARP' }] },
                    { evidenceType: 'sectionErrors', data: [{ id: 'gateway', sectionName: 'Gateway', status: 'permission_unavailable', error: 'API scope missing' }] }
                ]
            }]
        })
    };
    let insertId = 6440;
    const prompts = [];
    const cloudflarePackages = [];
    let cloudflareOptions = null;
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: {
            async createJsonCompletion(options) {
                cloudflareOptions = options;
                const prompt = options.messages[1].content;
                prompts.push(prompt);
                cloudflarePackages.push(JSON.parse(prompt.split('STACKCTRL DOMAIN PACKAGE:\n')[1]));
                return {
                    data: {
                        ...domainResponse('cloudflare_network_security'),
                        missingDataWarnings: ['Curated Network Security / Cloudflare best-practice references were unavailable.'],
                        technicalReasoning: [{ title: 'Access coverage', reasoning: 'Finance Portal has a named access policy and recent deny logs.' }],
                        riskPrioritization: [{ title: 'Finance Portal policy review', priority: 'high', reasoning: 'Access logs show denied attempts against a protected app.' }],
                        risks: [{
                            riskId: 'cf-risk-1',
                            title: 'Finance Portal access policy needs review',
                            severity: 'high',
                            patternFound: 'Protected app with access denies and named policy',
                            reasoning: `Finance Portal and Finance Access Policy require review based on ${sourcePath}.`,
                            affectedEntityIds: ['app-1', sourcePath],
                            recordIds: ['app-1', sourcePath],
                            sourceAlertIds: [sourcePath],
                            affectedEntities: [{
                                entityId: 'app-1',
                                entityName: 'Finance Portal',
                                entityType: 'Application',
                                policyName: 'Finance Access Policy',
                                sourceDomain: 'cloudflare_network_security',
                                sourceMetric: 'protectedApps',
                                businessReason: 'Protected finance app has denied access activity.',
                                recommendation: 'Review access policy conditions.',
                                internalSourcePath: sourcePath
                            }]
                        }],
                        recommendations: [{
                            recommendationId: 'cf-rec-1',
                            title: 'Review Finance Access Policy',
                            priority: 'high',
                            recommendedAction: 'Validate Finance Portal access rules and Gateway policy alignment.',
                            affectedEntityIds: ['app-1']
                        }]
                    },
                    requestSizeBytes: Buffer.byteLength(prompt),
                    responseSizeBytes: 900,
                    usage: { input_tokens: 1500, output_tokens: 300, total_tokens: 1800 }
                };
            }
        },
        logger: { info() {}, warn() {}, error() {} },
        wait: async () => {},
        config: { domainDelayMs: 0, maxItemsPerBatch: 100, maxInputBytes: 150000 }
    });

    const result = await service.runEnterpriseReport({ companyId: 1, snapshotId: 644, domainKeys: ['cloudflare_network_security'], includeSynthesis: false });
    const risk = result.domains[0].analysis.risks[0];
    const preparedRows = cloudflarePackages[0].evidence;

    assert.equal(cloudflarePackages.length, 1);
    assert.equal(cloudflarePackages[0].contextType, 'stackctrl_enterprise_cloudflare_strict_compact');
    assert.equal(cloudflarePackages[0].batchMetadata.totalBatches, 1);
    assert.equal(preparedRows.length, 13);
    assert.ok(preparedRows.some(row => row.evidenceType === 'coverageSummaries' && row.sourceMetric === 'accessLogCount' && row.data.coverageStatus === 'sampled_compact_rows'));
    assert.equal(Object.hasOwn(cloudflarePackages[0], 'historicalComparisons'), false);
    assert.equal(Object.hasOwn(cloudflarePackages[0], 'knowledgeGrounding'), false);
    assert.equal(Object.hasOwn(cloudflarePackages[0], 'previousDomainAnalysis'), false);
    assert.equal(Object.hasOwn(cloudflarePackages[0], 'evidenceCatalog'), false);
    assert.equal(Object.hasOwn(cloudflarePackages[0], 'dataLineage'), false);
    assert.equal(Object.hasOwn(cloudflarePackages[0], 'domainRunAudit'), false);
    assert.equal(Object.hasOwn(cloudflarePackages[0], 'tokenTracking'), false);
    assert.equal(Object.hasOwn(cloudflarePackages[0], 'evidenceBatchPlan'), false);
    assert.equal(cloudflareOptions.maxTokens, 6000);
    assert.ok(Buffer.byteLength(prompts[0], 'utf8') < 40000);
    for (const forbidden of ['previousDomainAnalysis', 'historicalComparisons', 'domainRunAudit', 'tokenTracking', 'evidenceBatchPlan', 'dataLineage']) {
        assert.doesNotMatch(prompts[0], new RegExp(forbidden));
    }
    assert.match(prompts[0], /protected apps, Cloudflare devices, gateway policies, access policies, access logs, DLP profiles, WARP profiles/i);
    assert.ok(preparedRows.some(row => row.evidenceType === 'accessApps' && row.data.appName === 'Finance Portal'));
    assert.ok(preparedRows.some(row => row.evidenceType === 'devices' && row.data.deviceName === 'KEN-LAPTOP'));
    assert.ok(preparedRows.some(row => row.evidenceType === 'gatewayRules' && row.data.gatewayRuleName === 'Block Risky Domains'));
    assert.ok(preparedRows.some(row => row.evidenceType === 'accessLogs' && row.data.appName === 'Finance Portal'));
    assert.ok(preparedRows.some(row => row.evidenceType === 'dlpProfiles' && row.data.profileName === 'Finance DLP'));
    assert.ok(preparedRows.some(row => row.evidenceType === 'warpProfiles' && row.data.profileName === 'Default WARP'));
    assert.equal(result.domains[0].status, 'completed');
    assert.equal(result.domains[0].analysis.missingDataWarnings.some(warning => /curated.*cloudflare|best-practice references/i.test(String(warning))), false);
    assert.equal(risk.affectedEntities[0].entityName, 'Finance Portal');
    assert.equal(risk.affectedEntities[0].policyName, 'Finance Access Policy');
    for (const field of ['roles', 'mfaEnabled', 'lastSignIn', 'osVersion', 'serialNumber', 'complianceState']) {
        assert.equal(Object.hasOwn(risk.affectedEntities[0], field), false);
    }
    assert.equal(risk.affectedEntityIds.some(value => /cloudflare_network_security\.evidence/i.test(value)), false);
    assert.equal(risk.recordIds.some(value => /cloudflare_network_security\.evidence/i.test(value)), false);
    assert.equal(risk.sourceAlertIds.some(value => /cloudflare_network_security\.evidence/i.test(value)), false);
    assert.doesNotMatch(risk.reasoning, /cloudflare_network_security\.evidence/);
    assert.equal(risk.internalSourcePath, sourcePath);
});

test('Backup selected-domain preparation uses one strict compact exposure package', async () => {
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            throw new Error(`Unexpected query: ${sql}`);
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        azureOpenAI: { async createJsonCompletion() { throw new Error('Azure should not be called'); } },
        schedulerService: { async getHistoricalSnapshotContext() { return {}; } },
        config: { domainDelayMs: 0 }
    });
    const snapshot = {
        ID: 645, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-25T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ stackctrl_risk: { domainRiskScores: { backup: 32 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { backup: 68 }, domainRiskScores: { backup: 32 } },
            sources: [{
                sourceKey: 'backup', status: 'available', isExpected: true, freshness: { ageMinutes: 2 },
                dashboardMetrics: {
                    totalStorageGB: 900, oneDriveStorageGB: 300, sharePointStorageGB: 500, exchangeStorageGB: 100,
                    activeUsersCount: 50, inactiveUsersCount: 12, servicesCovered: 3,
                    backupCoverageScore: 64, exposureRiskScore: 36, recommendationsCount: 4
                },
                evidence: [
                    { evidenceType: 'users', data: Array.from({ length: 60 }, (_, index) => ({
                        id: `backup-user-${index + 1}`,
                        userPrincipalName: `backup${index + 1}@example.com`,
                        displayName: `Backup User ${index + 1}`,
                        totalStorageGB: 60 - index,
                        accountStatus: index < 12 ? 'inactive' : 'active',
                        daysSinceActivity: index < 20 ? 45 : 5
                    })) },
                    { evidenceType: 'sites', data: Array.from({ length: 25 }, (_, index) => ({
                        id: `site-${index + 1}`,
                        siteName: `Project Site ${index + 1}`,
                        storageGB: 100 - index
                    })) }
                ]
            }]
        })
    };
    const packageResult = await service.buildDomainPackage({
        companyId: 1,
        snapshot,
        runId: 6450,
        domain: ENTERPRISE_DOMAINS.find(domain => domain.key === 'backup'),
        historicalContext: { comparisons: {} }
    });
    const batchPackage = service.buildDomainBatchPackage(packageResult.package, packageResult.allEvidence, 1, 1);
    assert.equal(batchPackage.contextType, 'stackctrl_enterprise_backup_strict_compact');
    assert.equal(batchPackage.batchMetadata.totalBatches, 1);
    assert.ok(batchPackage.evidence.length <= 100);
    assert.ok(batchPackage.evidenceGroups.topStorageUsers.length <= 10);
    assert.ok(batchPackage.evidenceGroups.inactiveDataHolders.length <= 10);
    assert.ok(batchPackage.evidenceGroups.staleActivityUsers.length <= 10);
    assert.ok(batchPackage.evidenceGroups.topSharePointSites.length <= 10);
    for (const forbidden of ['previousDomainAnalysis', 'historicalComparisons', 'dataLineage', 'domainRunAudit', 'tokenTracking', 'evidenceBatchPlan']) {
        assert.equal(Object.hasOwn(batchPackage, forbidden), false);
    }
});

test('Applications selected-domain preparation uses one strict compact governance package', async () => {
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            throw new Error(`Unexpected query: ${sql}`);
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        azureOpenAI: { async createJsonCompletion() { throw new Error('Azure should not be called'); } },
        schedulerService: { async getHistoricalSnapshotContext() { return {}; } },
        config: { domainDelayMs: 0 }
    });
    const snapshot = {
        ID: 646, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-25T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ stackctrl_risk: { domainRiskScores: { applications: 34 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { applications: 66 }, domainRiskScores: { applications: 34 } },
            sources: [{
                sourceKey: 'applications', status: 'available', isExpected: true, freshness: { ageMinutes: 2 },
                dashboardMetrics: {
                    totalApplications: 80, externalApplications: 25, highRiskApps: 12, highAccessApps: 18,
                    excessivePermissionApps: 14, groupAssignedApps: 11, applicationGovernanceScore: 62,
                    userCount: 200, groupCount: 20, recommendationsCount: 5
                },
                evidence: [{ evidenceType: 'applications', data: Array.from({ length: 80 }, (_, index) => ({
                    id: `app-${index + 1}`,
                    appName: `Application ${index + 1}`,
                    publisherName: index % 2 === 0 ? 'Unknown External Publisher' : 'Contoso',
                    riskLevel: index < 12 ? 'high' : 'medium',
                    permissionSummary: index < 14 ? 'Directory.ReadWrite.All Mail.ReadWrite' : 'User.Read',
                    assignedUserCount: index < 18 ? 50 : 2,
                    assignedGroupCount: index < 11 ? 2 : 0,
                    reviewStatus: index < 10 ? 'unreviewed' : 'reviewed'
                })) }]
            }]
        })
    };
    const packageResult = await service.buildDomainPackage({
        companyId: 1,
        snapshot,
        runId: 6460,
        domain: ENTERPRISE_DOMAINS.find(domain => domain.key === 'applications'),
        historicalContext: { comparisons: {} }
    });
    const batchPackage = service.buildDomainBatchPackage(packageResult.package, packageResult.allEvidence, 1, 1);
    assert.equal(batchPackage.contextType, 'stackctrl_enterprise_applications_strict_compact');
    assert.equal(batchPackage.batchMetadata.totalBatches, 1);
    assert.ok(batchPackage.evidence.length <= 100);
    assert.ok(batchPackage.evidenceGroups.highRiskApps.length <= 10);
    assert.ok(batchPackage.evidenceGroups.externalApps.length <= 10);
    assert.ok(batchPackage.evidenceGroups.excessivePermissionApps.length <= 10);
    assert.ok(batchPackage.evidenceGroups.highAccessApps.length <= 10);
    assert.ok(batchPackage.evidenceGroups.groupAssignedApps.length <= 10);
    assert.ok(batchPackage.evidenceGroups.staleOrUnreviewedApps.length <= 10);
    for (const forbidden of ['previousDomainAnalysis', 'historicalComparisons', 'dataLineage', 'domainRunAudit', 'tokenTracking', 'evidenceBatchPlan']) {
        assert.equal(Object.hasOwn(batchPackage, forbidden), false);
    }
});

test('normalizeMysqlDate stores only real MySQL dates for enterprise AI date fields', () => {
    assert.equal(normalizeMysqlDate('Ongoing'), null);
    assert.equal(normalizeMysqlDate('ASAP'), null);
    assert.equal(normalizeMysqlDate('2026-07-15'), '2026-07-15');
    assert.equal(normalizeMysqlDate(new Date('2026-07-15T13:30:00.000Z')), '2026-07-15');
});

test('repairTruncatedJson closes a long unterminated Azure string without discarding completed fields', () => {
    const longNarrative = 'x'.repeat(38470);
    const truncated = `{"domainExecutiveSummary":"Complete summary","technicalSummary":"${longNarrative}`;
    const repaired = repairTruncatedJson(truncated);

    assert.equal(repaired.success, true);
    assert.equal(repaired.repaired, true);
    assert.equal(repaired.value.domainExecutiveSummary, 'Complete summary');
    assert.equal(repaired.value.technicalSummary.length, 38470);
    assert.doesNotThrow(() => JSON.parse(repaired.repairedText));
});

test('Enterprise Identity currentMetrics follow dynamic dashboard metrics and detect source mismatches', async () => {
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            throw new Error(`Unexpected query: ${sql}`);
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        azureOpenAI: { async createJsonCompletion() { throw new Error('Azure should not be called'); } },
        schedulerService: { async getHistoricalSnapshotContext() { return {}; } },
        config: { domainDelayMs: 0 }
    });

    for (const mfaEnabled of [46, 12]) {
        const totalUsers = 57;
        const dashboardMetrics = {
            totalUsers,
            mfaEnabled,
            mfaMissing: totalUsers - mfaEnabled,
            mfaCoverage: Math.round((mfaEnabled / totalUsers) * 100),
            privilegedUsers: 6,
            adminsWithoutMfa: 1,
            highRiskUsers: 1,
            signInIssues: 57,
            externalUsers: 4,
            unknownDevices: 48,
            multiplePrivilegedRoles: 5,
            securityScore: 82
        };
        const snapshot = {
            ID: 900 + mfaEnabled,
            CompanyID: 1,
            CreatedAt: new Date('2026-06-22T08:00:00.000Z'),
            MetricsJson: JSON.stringify({ identity: { mfaEnabled: 999 }, stackctrl_risk: { domainRiskScores: { identity: 22 } } }),
            ContextJson: JSON.stringify({
                riskEngine: { domainHealthScores: { identity: 78 }, domainRiskScores: { identity: 22 } },
                sources: [{
                    sourceKey: 'identity', status: 'available', isExpected: true,
                    freshness: { lastUpdated: '2026-06-22T07:55:00.000Z', ageMinutes: 5 },
                    metrics: { mfaEnabled: 999 }, dashboardMetrics,
                    sourceLineage: {
                        sourceBuilder: 'storedStackCTRLIdentityEvidence',
                        sourceLayer: 'StackCTRLIdentityEvidenceSnapshots + StackCTRLIdentityUserEvidence',
                        evidenceSnapshotId: 501,
                        evidenceRecordCount: 57,
                        omittedRecordCount: 0
                    },
                    evidence: [
                        { evidenceType: 'users', data: Array.from({ length: 57 }, (_, index) => ({ id: `user-${index + 1}` })) },
                        { evidenceType: 'dashboard_evidence_lists', data: { usersWithoutMfa: Array.from({ length: 11 }, (_, index) => ({ id: `user-${index + 1}` })) } }
                    ]
                }]
            })
        };
        const packageResult = await service.buildDomainPackage({
            companyId: 1,
            snapshot,
            runId: 70,
            domain: ENTERPRISE_DOMAINS[0],
            historicalContext: { comparisons: {} }
        });
        for (const [metric, value] of Object.entries(dashboardMetrics)) {
            assert.equal(packageResult.package.currentMetrics[metric], value, `currentMetrics.${metric}`);
            assert.equal(packageResult.package.dashboardMetrics[metric], value, `dashboardMetrics.${metric}`);
        }
        assert.equal(packageResult.package.dataLineage.sourceBuilder, 'storedStackCTRLIdentityEvidence');
        assert.equal(packageResult.package.dataLineage.evidenceSnapshotId, 501);
        assert.equal(packageResult.package.dataLineage.evidenceRecordCount, 57);
        assert.equal(packageResult.package.dataLineage.evidenceOmittedRecordCount, 0);
        assert.equal(packageResult.audit.stackCTRLDataCount, 57);
        assert.equal(packageResult.audit.evidenceIncludedCount, 57);
        assert.equal(packageResult.audit.omittedCount, 0);
        assert.equal(packageResult.sourceAlignment.mismatches.length, 0);
        assert.equal(packageResult.sourceAlignment.rows.find(row => row.metric === 'mfaEnabled').status, 'MATCH');
    }

    const mismatch = buildDataLineageComparison({
        fields: ['mfaEnabled'],
        sourceValues: { mfaEnabled: 46 },
        inputValues: { mfaEnabled: 12 }
    });
    const failure = sourceAlignmentFailure(mismatch, 'Identity Protection');
    assert.equal(failure.status, 'failed_source_mismatch');
    assert.deepEqual(failure.mismatchedFields, ['mfaEnabled']);
    assert.match(failure.errorMessage, /mfaEnabled/);
});

test('Enterprise warns on missing Identity evidence and continues with stale saved evidence', async () => {
    for (const sourceStatus of ['missing', 'stale']) {
        let insertId = 800;
        let azureCalls = 0;
        const source = {
            sourceKey: 'identity',
            status: sourceStatus,
            isExpected: true,
            freshness: sourceStatus === 'stale'
                ? { lastUpdated: '2026-06-22T05:00:00.000Z', ageMinutes: 180 }
                : { lastUpdated: null, ageMinutes: null },
            warnings: [sourceStatus === 'stale'
                ? 'Identity Protection evidence is stale.'
                : 'No complete StackCTRL Identity evidence snapshot is available. Enterprise analysis continued with limited data.'],
            metrics: sourceStatus === 'stale' ? { totalUsers: 57, mfaCoverage: 81 } : {},
            dashboardMetrics: sourceStatus === 'stale' ? { totalUsers: 57, mfaCoverage: 81 } : {},
            evidence: sourceStatus === 'stale' ? [{ evidenceType: 'users', data: [{ id: 'user-1' }] }] : [],
            sourceLineage: { sourceBuilder: 'storedStackCTRLIdentityEvidence', evidenceSnapshotId: 700 }
        };
        const snapshot = {
            ID: sourceStatus === 'stale' ? 702 : 701,
            CompanyID: 1,
            TenantKey: 'sunbird',
            SnapshotType: 'manual',
            CreatedAt: new Date('2026-06-22T08:00:00.000Z'),
            DataCompletenessScore: sourceStatus === 'stale' ? 100 : 0,
            MetricsJson: JSON.stringify({ stackctrl_risk: { domainRiskScores: { identity: 25 } } }),
            ContextJson: JSON.stringify({
                riskEngine: { domainHealthScores: { identity: 75 }, domainRiskScores: { identity: 25 } },
                sources: [source]
            })
        };
        const calls = [];
        const pool = {
            async query(sql, params = []) {
                calls.push({ sql, params });
                if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
                if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
                if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
                if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
                return [{ affectedRows: 1 }, []];
            }
        };
        const service = createEnterpriseIntelligenceService({
            pool,
            azureOpenAI: { async createJsonCompletion() { azureCalls += 1; return { data: domainResponse('identity') }; } },
            schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
            config: { domainDelayMs: 0 }
        });
        const result = await service.runEnterpriseReport({
            companyId: 1,
            snapshotId: snapshot.ID,
            domainKeys: ['identity'],
            includeSynthesis: false
        });
        assert.equal(azureCalls, sourceStatus === 'stale' ? 1 : 0, sourceStatus);
        assert.equal(result.domains[0].status, sourceStatus === 'stale' ? 'completed' : 'completed_with_warnings');
        const auditWrite = calls.find(call => call.sql.includes('INSERT INTO StackCTRLIntelligenceEvidenceAudit'));
        assert.ok(auditWrite);
        assert.equal(auditWrite.params[5], sourceStatus === 'stale' ? 1 : 0);
        if (sourceStatus === 'missing') {
            assert.match(result.domains[0].errorMessage, /no complete/i);
            assert.equal(result.status, 'completed_with_warnings');
            assert.equal(result.domains[0].analysis.evidenceLimitations.recordsSent, 0);
        } else {
            assert.match(result.domains[0].analysis.missingDataWarnings.join(' '), /source_stale.*180.*2026-06-22T05:00:00.000Z/i);
            assert.equal(result.domains[0].analysis.evidenceLimitations.recordsSent, 1);
        }
    }
});

test('enterprise batching splits 3,590 evidence items by count and byte budget', () => {
    const evidence = identityLikeEvidence();
    assert.equal(Object.keys(evidence).length, 4);
    const flattened = flattenDomainEvidence(evidence, { rootPath: 'identity.evidence' });
    assert.equal(flattened.length, 3590);
    assert.ok(flattened.some(item => item.internalSourcePath === 'identity.evidence.users[0]'));
    assert.ok(flattened.some(item => item.internalSourcePath === 'identity.evidence.history.daily[89]'));

    const groupedEvidence = Object.entries(evidence).map(([evidenceType, data]) => ({ evidenceType, data }));
    const flattenedGroups = flattenDomainEvidence(groupedEvidence, { rootPath: 'identity.evidence' });
    assert.equal(groupedEvidence.length, 4);
    assert.equal(flattenedGroups.length, 3590);
    assert.equal(flattenedGroups[0].sourceLabel, 'users');

    const countBatches = splitIntoBatches(flattened, { maxItems: 750 });
    assert.deepEqual(countBatches.map(batch => batch.items.length), [750, 750, 750, 750, 590]);

    const byteBatches = splitIntoBatches(
        Array.from({ length: 80 }, (_, index) => ({ id: index, detail: 'x'.repeat(1200) })),
        { maxItems: 750, maxBytes: 50000, estimateBytes: items => Buffer.byteLength(JSON.stringify(items), 'utf8') }
    );
    assert.ok(byteBatches.length > 1);
    assert.ok(byteBatches.every(batch => Buffer.byteLength(JSON.stringify(batch.items), 'utf8') <= 50000));
});

test('Identity domain packages keep user rows compact and include shared context only in the first batch', async () => {
    const snapshot = {
        ID: 80, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-22T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ identity: { mfaCoverage: 91 }, stackctrl_risk: { domainRiskScores: { identity: 25 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { identity: 75 }, domainRiskScores: { identity: 25 } },
            sources: [{
                sourceKey: 'identity', status: 'available', isExpected: true,
                metrics: { mfaCoverage: 91 }, dashboardMetrics: { privilegedUsers: 20 },
                calculatedIndicators: { usersWithoutMfa: 3 }, evidence: identityLikeEvidence()
            }]
        })
    };
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            throw new Error(`Unexpected query: ${sql}`);
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        azureOpenAI: { async createJsonCompletion() { throw new Error('Azure should not be called'); } },
        schedulerService: { async getHistoricalSnapshotContext() { return {}; } },
        config: { domainDelayMs: 0, maxItemsPerBatch: 750 }
    });
    const historicalContext = {
        comparisons: {
            '24_hours': {
                availability: 'available', differenceMinutes: 1440, metricChanges: {},
                snapshot: {
                    snapshotId: 79, createdAt: new Date('2026-06-21T08:00:00.000Z'),
                    context: { sources: [{ sourceKey: 'identity', status: 'available', metrics: { mfaCoverage: 90 } }], riskEngine: { domainHealthScores: { identity: 74 }, domainRiskScores: { identity: 26 } } },
                    metrics: { identity: { mfaCoverage: 90 } }
                }
            }
        }
    };

    const packageResult = await service.buildDomainPackage({
        companyId: 1,
        snapshot,
        runId: 900,
        domain: ENTERPRISE_DOMAINS[0],
        historicalContext
    });
    assert.equal(packageResult.audit.stackCTRLDataCount, 3000);
    assert.equal(packageResult.audit.evidenceIncludedCount, 3000);
    assert.equal(packageResult.package.evidence.length, 0);

    const batches = splitIntoBatches(packageResult.allEvidence, { maxItems: 750 });
    assert.equal(batches.length, 4);
    const batchPackages = batches.map((batch, index) => service.buildDomainBatchPackage(
        packageResult.package,
        batch.items,
        index + 1,
        batches.length
    ));
    for (const [index, batchPackage] of batchPackages.entries()) {
        assert.equal(batchPackage.batchMetadata.batchNumber, index + 1);
        assert.equal(batchPackage.batchMetadata.totalBatches, 4);
        assert.equal(batchPackage.evidence.length, batches[index].items.length);
        assert.equal(batchPackage.authoritativeScores.healthScore, 75);
        assert.equal(batchPackage.authoritativeScores.riskScore, 25);
        assert.equal(batchPackage.authoritativeScores.riskLevel, 'moderate');
        assert.equal(batchPackage.sharedContextIncluded, index === 0);
        assert.equal(Object.hasOwn(batchPackage, 'historicalComparisons'), false);
        assert.equal(Object.hasOwn(batchPackage, 'evidenceCatalog'), false);
        assert.equal(Object.hasOwn(batchPackage, 'previousDomainAnalysis'), false);
        assert.equal(Object.hasOwn(batchPackage, 'knowledgeGrounding'), false);
        if (index === 0) {
            assert.equal(batchPackage.currentMetrics.mfaCoverage, 91);
            assert.equal(batchPackage.contextType, 'stackctrl_enterprise_identity_table');
        } else {
            assert.equal(Object.hasOwn(batchPackage, 'currentMetrics'), false);
            assert.equal(batchPackage.contextType, 'stackctrl_enterprise_identity_table_continuation');
            assert.equal(batchPackage.baseContextReference.sharedContextSentInBatch, 1);
        }
        assert.ok(batchPackage.evidence.every(item => item.internalSourcePath && !Object.hasOwn(item, 'data')));
    }
});

test('enterprise rate-limit circuit stops remaining batches and records zero analysed items', async () => {
    const calls = [];
    let azureCalls = 0;
    let insertId = 500;
    const evidence = identityLikeEvidence();
    const snapshot = {
        ID: 79, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-22T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ stackctrl_risk: { domainRiskScores: { identity: 25, devices: 20 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { identity: 75, devices: 80 }, domainRiskScores: { identity: 25, devices: 20 } },
            sources: [
                { sourceKey: 'identity', status: 'available', evidence },
                { sourceKey: 'devices', status: 'available', evidence: [{ evidenceType: 'metric', data: { id: 1 } }] }
            ]
        })
    };
    const pool = {
        async query(sql, params = []) {
            calls.push({ sql, params });
            assert.equal((sql.match(/\?/g) || []).length, params.length, `Placeholder mismatch in ${sql}`);
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: {
            async createJsonCompletion(options) {
                azureCalls += 1;
                assert.equal(options.maxRetriesOverride, 0);
                const error = new Error('Azure capacity is temporarily unavailable');
                error.azureMetadata = {
                    statusCode: 429,
                    rateLimited: true,
                    retryAfterMs: 600000,
                    requestSizeBytes: 45000,
                    retryCount: 0
                };
                throw error;
            }
        },
        logger: { info() {}, warn() {}, error() {} },
        wait: async () => {},
        config: { domainDelayMs: 0, maxRetries: 0, maxItemsPerBatch: 750 }
    });

    const result = await service.runEnterpriseReport({
        companyId: 1,
        snapshotId: 79,
        domainKeys: ['identity', 'devices'],
        includeSynthesis: true
    });

    assert.equal(azureCalls, 1);
    assert.equal(result.status, 'failed_rate_limited', JSON.stringify(result));
    assert.equal(result.rateLimited, true);
    assert.equal(result.rateLimit.retryAfterMs, 600000);
    assert.equal(result.domains.length, 2);
    assert.equal(result.domains[0].status, 'failed_rate_limited');
    assert.equal(result.domains[1].status, 'skipped_rate_limited');
    assert.equal(result.synthesisId, null);

    const batchWrite = calls.find(call => call.sql.includes('INSERT INTO StackCTRLTenantDomainIntelligenceBatches'));
    assert.ok(batchWrite);
    assert.ok(batchWrite.params[6] >= 5);
    assert.equal(batchWrite.params[8], 3000);
    assert.ok(batchWrite.params[9] > 0 && batchWrite.params[9] <= 750);
    assert.equal(batchWrite.params[10], 0);
    assert.match(batchWrite.params[19], /"recommendedRetryAfterMs":600000/);

    const auditWrite = calls.find(call => call.sql.includes('INSERT INTO StackCTRLIntelligenceEvidenceAudit'));
    assert.ok(auditWrite);
    assert.equal(auditWrite.params[4], 3000);
    assert.equal(auditWrite.params[5], 0);
    assert.equal(auditWrite.params[8], 3000);

    await assert.rejects(
        service.runEnterpriseReport({ companyId: 1, snapshotId: 79, domainKeys: ['devices'], includeSynthesis: false }),
        error => error.enterpriseStatus === 'failed_rate_limited' && /circuit is open/.test(error.message)
    );
    assert.equal(azureCalls, 1);
});

test('enterprise invalid JSON triggers repair retry and stores repaired batch details', async () => {
    const calls = [];
    let azureCalls = 0;
    let insertId = 300;
    const snapshot = {
        ID: 77, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-22T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ identity: { mfaCoverage: 90 }, stackctrl_risk: { domainRiskScores: { identity: 25 } }, executive_kpis: { identityHealth: 75 } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { identity: 75 }, domainRiskScores: { identity: 25 }, executiveKPIs: { identityHealth: 75 } },
            sources: [{ sourceKey: 'identity', status: 'available', isExpected: true, evidence: [{ evidenceType: 'metric_summary', data: { usersWithoutMfa: 2 } }] }]
        })
    };
    const pool = {
        async query(sql, params = []) {
            calls.push({ sql, params });
            assert.equal((sql.match(/\?/g) || []).length, params.length, `Placeholder mismatch in ${sql}`);
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: {
            async createJsonCompletion() {
                azureCalls += 1;
                if (azureCalls === 1) return { data: '{"domainExecutiveSummary":', requestSizeBytes: 100, responseSizeBytes: 20, retryCount: 0, usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 } };
                return { data: domainResponse('identity'), requestSizeBytes: 50, responseSizeBytes: 200, retryCount: 0, usage: { input_tokens: 5, output_tokens: 20, total_tokens: 25 } };
            }
        },
        wait: async () => {},
        config: { domainDelayMs: 0 }
    });

    const result = await service.runEnterpriseReport({ companyId: 1, snapshotId: 77, domainKeys: ['identity'], includeSynthesis: false });
    assert.equal(result.status, 'completed_with_warnings');
    assert.equal(azureCalls, 2);
    const batchWrite = calls.find(call => call.sql.includes('StackCTRLTenantDomainIntelligenceBatches'));
    assert.ok(batchWrite);
    assert.match(batchWrite.params.join(' '), /"jsonRepaired":true/);
});

test('enterprise domain batch locally recovers a long unterminated Azure string', async () => {
    const calls = [];
    let azureCalls = 0;
    let insertId = 350;
    const snapshot = {
        ID: 775, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-23T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ identity: { mfaCoverage: 90 }, stackctrl_risk: { domainRiskScores: { identity: 25 } }, executive_kpis: { identityHealth: 75 } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { identity: 75 }, domainRiskScores: { identity: 25 }, executiveKPIs: { identityHealth: 75 } },
            sources: [{ sourceKey: 'identity', status: 'available', isExpected: true, evidence: [{ evidenceType: 'metric_summary', data: { usersWithoutMfa: 2 } }] }]
        })
    };
    const pool = {
        async query(sql, params = []) {
            calls.push({ sql, params });
            assert.equal((sql.match(/\?/g) || []).length, params.length, `Placeholder mismatch in ${sql}`);
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: {
            async createJsonCompletion(options) {
                azureCalls += 1;
                assert.equal(options.allowInvalidJsonResponse, true);
                return {
                    data: `{"domainExecutiveSummary":"Recovered domain summary","technicalSummary":"${'x'.repeat(38470)}`,
                    finishReason: 'length',
                    requestSizeBytes: 1000,
                    responseSizeBytes: 39000,
                    retryCount: 0,
                    usage: { input_tokens: 500, output_tokens: 5000, total_tokens: 5500 }
                };
            }
        },
        logger: { info() {}, warn() {}, error() {} },
        wait: async () => {},
        config: { domainDelayMs: 0 }
    });

    const result = await service.runEnterpriseReport({ companyId: 1, snapshotId: 775, domainKeys: ['identity'], includeSynthesis: false });
    assert.equal(azureCalls, 2);
    assert.equal(result.status, 'completed_with_warnings');
    assert.equal(result.domains[0].status, 'completed_with_warnings');
    assert.match(result.domains[0].analysis.missingDataWarnings.join(' '), /safely recovered/);
    const batchWrite = calls.find(call => call.sql.includes('StackCTRLTenantDomainIntelligenceBatches'));
    assert.match(batchWrite.params.join(' '), /"jsonRepairMethod":"azure_repair_then_local_closure"/);
});

test('enterprise invalid JSON fallback stores diagnostics, continues domains, and runs synthesis', async () => {
    const calls = [];
    let insertId = 400;
    let azureCalls = 0;
    const snapshot = {
        ID: 78, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-22T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ identity: { mfaCoverage: 90 }, stackctrl_risk: { domainRiskScores: { identity: 25, devices: 20 } }, executive_kpis: { identityHealth: 75, deviceHealth: 80 } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { identity: 75, devices: 80 }, domainRiskScores: { identity: 25, devices: 20 }, executiveKPIs: { identityHealth: 75, deviceHealth: 80 } },
            sources: [
                { sourceKey: 'identity', status: 'available', isExpected: true, evidence: [{ evidenceType: 'metric_summary', data: { usersWithoutMfa: 2 } }] },
                { sourceKey: 'devices', status: 'available', isExpected: true, evidence: [{ evidenceType: 'devices', data: [{ id: 'device-1', deviceName: 'Device One' }] }] }
            ]
        })
    };
    const pool = {
        async query(sql, params = []) {
            calls.push({ sql, params });
            assert.equal((sql.match(/\?/g) || []).length, params.length, `Placeholder mismatch in ${sql}`);
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (sql.includes('SELECT ID, CompanyID, SnapshotID, RunID, DomainKey')) {
                return [[
                    {
                        ID: 501, CompanyID: 1, SnapshotID: 78, RunID: 400, DomainKey: 'identity', DomainName: 'Identity Protection',
                        HealthScore: 75, RiskScore: 25, RiskLevel: 'moderate', Status: 'completed_with_warnings',
                        DomainExecutiveSummary: 'Identity Azure JSON was invalid.', TechnicalSummary: 'Local fallback stored.',
                        BusinessImpact: 'Raw evidence remains available.', CurrentPosture: 'warning', EvidenceSummary: '',
                        ScoreJustification: 'StackCTRL score retained.', ControlAssessment: '[]', FindingsJson: '[]', RisksJson: '[]',
                        RecommendationsJson: '[]', TrendAnalysisJson: '[]', YesterdayVsTodayJson: '{}',
                        MissingDataWarningsJson: '["azure_invalid_json"]', AssumptionsJson: '[]', ConfidenceScore: 0, ErrorMessage: null
                    },
                    {
                        ID: 502, CompanyID: 1, SnapshotID: 78, RunID: 400, DomainKey: 'devices', DomainName: 'Device Protection',
                        HealthScore: 80, RiskScore: 20, RiskLevel: 'low', Status: 'completed',
                        DomainExecutiveSummary: 'Devices completed.', TechnicalSummary: 'Device evidence analysed.',
                        BusinessImpact: 'Device posture available.', CurrentPosture: 'controlled', EvidenceSummary: '',
                        ScoreJustification: 'StackCTRL score retained.', ControlAssessment: '[]', FindingsJson: '[]', RisksJson: '[]',
                        RecommendationsJson: '[]', TrendAnalysisJson: '[]', YesterdayVsTodayJson: '{}',
                        MissingDataWarningsJson: '[]', AssumptionsJson: '[]', ConfidenceScore: 0.9, ErrorMessage: null
                    }
                ], []];
            }
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: {
            async createJsonCompletion() {
                azureCalls += 1;
                if (azureCalls <= 2) {
                    return { data: '{"domainExecutiveSummary":', requestSizeBytes: 100, responseSizeBytes: 20, retryCount: 0, usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 } };
                }
                if (azureCalls === 3) return { data: domainResponse('devices'), usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 } };
                return { data: synthesisResponse(), usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 } };
            }
        },
        wait: async () => {},
        config: { domainDelayMs: 0 }
    });

    const result = await service.runEnterpriseReport({ companyId: 1, snapshotId: 78, domainKeys: ['identity', 'devices'], includeSynthesis: true });
    assert.equal(result.status, 'completed_with_warnings');
    assert.equal(result.domains[0].status, 'completed_with_warnings');
    assert.equal(result.domains[0].analysis.warningType, 'azure_invalid_json');
    assert.equal(result.domains[0].analysis.rawAzureResponseStored, true);
    assert.equal(result.domains[0].analysis.recordsPrepared, 1);
    assert.match(result.domains[0].errorMessage, /JSON parse failed/);
    assert.equal(result.domains[1].status, 'completed');
    assert.equal(result.synthesisStatus, 'completed_with_warnings');
    assert.ok(result.synthesisId);
    assert.equal(result.terminalError, null);
    assert.equal(azureCalls, 4);
    const batchWrite = calls.find(call => call.sql.includes('StackCTRLTenantDomainIntelligenceBatches') && call.params[3] === 'identity');
    assert.ok(batchWrite.params.includes('completed_with_warnings'));
    assert.ok(batchWrite.params.includes('{"domainExecutiveSummary":'));
    assert.match(batchWrite.params.join(' '), /JSON parse failed/);
    assert.match(batchWrite.params.join(' '), /local_fallback_after_invalid_json/);
});

test('Enterprise synthesis recovers a long unterminated JSON string and completes with warnings', async () => {
    const calls = [];
    let azureCalls = 0;
    const periodStart = new Date('2026-06-23T00:00:00.000Z');
    const periodEnd = new Date('2026-06-23T23:59:59.000Z');
    const domainRow = {
        ID: 200,
        CompanyID: 1,
        SnapshotID: 76,
        RunID: 100,
        DomainKey: 'identity',
        DomainName: 'Identity Protection',
        HealthScore: 75,
        RiskScore: 25,
        RiskLevel: 'moderate',
        Status: 'completed',
        DomainExecutiveSummary: 'Identity summary',
        TechnicalSummary: 'Technical summary',
        BusinessImpact: 'Impact',
        CurrentPosture: 'partial',
        EvidenceSummary: 'Evidence',
        ScoreJustification: 'Justified',
        ControlAssessment: '{}',
        FindingsJson: '[]',
        RisksJson: '[]',
        RecommendationsJson: '[]',
        TrendAnalysisJson: '[]',
        YesterdayVsTodayJson: '{}',
        MissingDataWarningsJson: '[]',
        AssumptionsJson: '[]'
    };
    const pool = {
        async query(sql, params = []) {
            calls.push({ sql, params });
            assert.equal((sql.match(/\?/g) || []).length, params.length, `Placeholder mismatch in ${sql}`);
            if (sql.includes('FROM StackCTRLEnterpriseReportRuns WHERE ID')) return [[{ ID: 100, CompanyID: 1, SnapshotID: 76, PeriodType: 'daily', PeriodStart: periodStart, PeriodEnd: periodEnd, Mode: 'enterprise_deep', ProgressJson: '{}' }], []];
            if (sql.includes('SELECT ID, CompanyID, SnapshotID, RunID, DomainKey')) return [[domainRow], []];
            if (sql.includes('FROM StackCTRLEnterpriseSynthesis synthesis')) return [[], []];
            if (sql.includes('INSERT INTO StackCTRLEnterpriseSynthesis')) return [{ insertId: 901 }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return {}; } },
        azureOpenAI: {
            async createJsonCompletion(options) {
                azureCalls += 1;
                assert.equal(options.allowInvalidJsonResponse, true);
                return {
                    data: `{"enterpriseExecutiveSummary":{"summary":"Recovered summary"},"boardReport":{"summary":"${'x'.repeat(38470)}`,
                    finishReason: 'length',
                    requestSizeBytes: 1000,
                    responseSizeBytes: 39000,
                    retryCount: 0,
                    usage: { input_tokens: 500, output_tokens: 8000, total_tokens: 8500 }
                };
            }
        },
        logger: { info() {}, warn() {}, error() {} },
        config: { domainDelayMs: 0 }
    });

    const result = await service.runEnterpriseSynthesis({ companyId: 1, runId: 100 });
    assert.equal(azureCalls, 2);
    assert.equal(result.status, 'completed_with_warnings');
    assert.equal(result.synthesisId, 901);
    assert.equal(result.analysis.enterpriseExecutiveSummary.summary, 'Recovered summary');
    assert.match(result.analysis.limitationsAndAssumptions.join(' '), /safely recovered/);
    const synthesisWrite = calls.find(call => call.sql.includes('INSERT INTO StackCTRLEnterpriseSynthesis'));
    assert.equal(synthesisWrite.params[6], 'completed_with_warnings');
});

test('enterprise automation checks for an hourly run outside the former daily window', async () => {
    let queryCount = 0;
    const service = createEnterpriseIntelligenceService({
        pool: { async query() { queryCount++; return [[], []]; } },
        azureOpenAI: { async createJsonCompletion() { throw new Error('Azure should not be called'); } },
        schedulerService: { async getHistoricalSnapshotContext() { return {}; } },
        config: { domainDelayMs: 0 }
    });
    const result = await service.runScheduledTick({ now: new Date('2026-06-22T06:00:00.000Z') });
    assert.equal(result.status, 'completed');
    assert.equal(queryCount, 1);
});
test('enterprise daily automation waits until the configured Johannesburg hour, then catches up', async () => {
    const previousHour = process.env.ENTERPRISE_AI_DAILY_RUN_HOUR;
    process.env.ENTERPRISE_AI_DAILY_RUN_HOUR = '8';
    let queryCount = 0;
    try {
        const service = createEnterpriseIntelligenceService({
            pool: { async query() { queryCount++; return [[], []]; } },
            azureOpenAI: { async createJsonCompletion() { throw new Error('Azure should not be called'); } },
            schedulerService: { async getHistoricalSnapshotContext() { return {}; } },
            config: { domainDelayMs: 0 }
        });
        const before = await service.runDailyAutomationTick({ now: new Date('2026-06-22T05:00:00.000Z') });
        assert.equal(before.status, 'not_due');
        assert.equal(queryCount, 0);

        const after = await service.runDailyAutomationTick({ now: new Date('2026-06-22T08:00:00.000Z') });
        assert.equal(after.status, 'completed');
        assert.equal(after.cadence, 'daily');
        assert.equal(queryCount, 1);
    } finally {
        if (previousHour == null) delete process.env.ENTERPRISE_AI_DAILY_RUN_HOUR;
        else process.env.ENTERPRISE_AI_DAILY_RUN_HOUR = previousHour;
    }
});

test('Enterprise Device currentMetrics follow stored dashboard metrics and flatten per-device evidence', async () => {
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            throw new Error(`Unexpected query: ${sql}`);
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        azureOpenAI: { async createJsonCompletion() { throw new Error('Azure should not be called'); } },
        schedulerService: { async getHistoricalSnapshotContext() { return {}; } },
        config: { domainDelayMs: 0 }
    });
    const dashboardMetrics = {
        totalDevices: 17,
        compliantDevices: 13,
        nonCompliantDevices: 3,
        complianceRate: 76,
        encryptedDevices: 17,
        encryptionRate: 100,
        activeDevices24h: 12,
        staleDevices: 1,
        dead30Days: 4,
        highRiskDevices: 4,
        unmanagedDevices: 0,
        securityAlerts: 19,
        deviceSecurityScore: 82
    };
    const snapshot = {
        ID: 910,
        CompanyID: 1,
        CreatedAt: new Date('2026-06-22T08:00:00.000Z'),
        MetricsJson: JSON.stringify({ devices: { complianceRate: 99 }, stackctrl_risk: { domainRiskScores: { devices: 22 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { devices: 78 }, domainRiskScores: { devices: 22 } },
            sources: [{
                sourceKey: 'devices', status: 'available', isExpected: true,
                freshness: { lastUpdated: '2026-06-22T07:55:00.000Z', ageMinutes: 5 },
                metrics: { complianceRate: 99 }, dashboardMetrics,
                sourceLineage: {
                    sourceBuilder: 'storedStackCTRLDeviceEvidence',
                    sourceLayer: 'StackCTRLDeviceEvidenceSnapshots + StackCTRLDeviceEvidence',
                    evidenceSnapshotId: 801,
                    evidenceRecordCount: 17,
                    omittedRecordCount: 0
                },
                evidence: [
                    { evidenceType: 'devices', data: Array.from({ length: 17 }, (_, index) => ({ id: `device-${index + 1}`, deviceName: `Device ${index + 1}` })) }
                ]
            }]
        })
    };
    const packageResult = await service.buildDomainPackage({
        companyId: 1,
        snapshot,
        runId: 71,
        domain: ENTERPRISE_DOMAINS.find(domain => domain.key === 'devices'),
        historicalContext: { comparisons: {} }
    });
    for (const metric of DEVICE_LINEAGE_FIELDS.filter(field => !['healthScore', 'riskScore', 'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'].includes(field))) {
        assert.equal(packageResult.package.currentMetrics[metric], dashboardMetrics[metric], `currentMetrics.${metric}`);
        assert.equal(packageResult.package.dashboardMetrics[metric], dashboardMetrics[metric], `dashboardMetrics.${metric}`);
    }
    assert.equal(packageResult.package.dataLineage.sourceBuilder, 'storedStackCTRLDeviceEvidence');
    assert.equal(packageResult.package.dataLineage.evidenceSnapshotId, 801);
    assert.equal(packageResult.package.dataLineage.evidenceRecordCount, 17);
    assert.equal(packageResult.package.dataLineage.evidenceOmittedRecordCount, 0);
    assert.equal(packageResult.audit.stackCTRLDataCount, 17);
    assert.equal(packageResult.audit.evidenceIncludedCount, 17);
    assert.equal(packageResult.audit.omittedCount, 0);
    assert.equal(packageResult.sourceAlignment.mismatches.length, 0);
    assert.equal(packageResult.sourceAlignment.rows.find(row => row.metric === 'complianceRate').status, 'MATCH');
});

test('Enterprise Email currentMetrics follow stored dashboard metrics and prepare compact threat-focused evidence', async () => {
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            throw new Error(`Unexpected query: ${sql}`);
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        azureOpenAI: { async createJsonCompletion() { throw new Error('Azure should not be called'); } },
        schedulerService: { async getHistoricalSnapshotContext() { return {}; } },
        config: { domainDelayMs: 0 }
    });
    const dashboardMetrics = {
        activeThreats: 6,
        highSeverityAlerts: 0,
        affectedUsersCount: 8,
        activeIncidents: 0,
        securityScore: 88,
        threatResolutionRate: 0,
        phishingCount: 1,
        malwareCount: 0,
        spamCount: 0,
        becCount: 0,
        activeMailboxes: 36,
        totalMailActivity: 11867,
        sendCount: 1430,
        receiveCount: 4759,
        readCount: 5678,
        recommendationsCount: 3
    };
    const snapshot = {
        ID: 911,
        CompanyID: 1,
        CreatedAt: new Date('2026-06-22T08:00:00.000Z'),
        MetricsJson: JSON.stringify({ email_security: { activeThreats: 99 }, stackctrl_risk: { domainRiskScores: { email: 22 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { email: 78 }, domainRiskScores: { email: 22 } },
            sources: [{
                sourceKey: 'email_security', status: 'available', isExpected: true,
                freshness: { lastUpdated: '2026-06-22T07:55:00.000Z', ageMinutes: 5 },
                metrics: { activeThreats: 99 }, dashboardMetrics,
                sourceLineage: {
                    sourceBuilder: 'storedStackCTRLEmailEvidence',
                    sourceLayer: 'StackCTRLEmailEvidenceSnapshots + StackCTRLEmailEvidence',
                    evidenceSnapshotId: 901,
                    evidenceRecordCount: 42,
                    omittedRecordCount: 0
                },
                evidence: [
                    { evidenceType: 'alerts', data: Array.from({ length: 6 }, (_, index) => ({ id: `alert-${index + 1}` })) },
                    { evidenceType: 'incidents', data: [] },
                    { evidenceType: 'mailActivityUsers', data: Array.from({ length: 36 }, (_, index) => ({ userPrincipalName: `user${index + 1}` })) }
                ]
            }]
        })
    };
    const packageResult = await service.buildDomainPackage({
        companyId: 1,
        snapshot,
        runId: 72,
        domain: ENTERPRISE_DOMAINS.find(domain => domain.key === 'email_security'),
        historicalContext: { comparisons: {} }
    });
    for (const metric of EMAIL_LINEAGE_FIELDS.filter(field => !['healthScore', 'riskScore', 'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'].includes(field))) {
        assert.equal(packageResult.package.currentMetrics[metric], dashboardMetrics[metric], `currentMetrics.${metric}`);
    }
    assert.equal(packageResult.package.dataLineage.sourceBuilder, 'storedStackCTRLEmailEvidence');
    assert.equal(packageResult.audit.stackCTRLDataCount, 23);
    assert.equal(packageResult.audit.evidenceIncludedCount, 23);
    assert.equal(packageResult.audit.evidenceOmittedCount, 0);
    assert.equal(packageResult.allEvidence.filter(row => row.evidenceType === 'securityAlerts').length, 6);
    assert.equal(packageResult.allEvidence.some(row => row.evidenceType === 'mailActivityUsers'), false);
    assert.equal(packageResult.allEvidence.some(row => row.evidenceType === 'mailflowSummary'), true);
    assert.ok(packageResult.allEvidence.filter(row => row.evidenceType === 'highVolumeMailboxes').length <= 10);
    assert.equal(packageResult.sourceAlignment.mismatches.length, 0);
});

test('Enterprise Network currentMetrics follow stored dashboard metrics and flatten row-level evidence', async () => {
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            throw new Error(`Unexpected query: ${sql}`);
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        azureOpenAI: { async createJsonCompletion() { throw new Error('Azure should not be called'); } },
        schedulerService: { async getHistoricalSnapshotContext() { return {}; } },
        config: { domainDelayMs: 0 }
    });
    const dashboardMetrics = {
        protectedApps: 4,
        enrolledDevices: 12,
        gatewayPolicies: 8,
        activeGatewayPolicies: 7,
        deniedAccessEvents: 1,
        recentAccessEvents: 15,
        networkSecurityScore: 91,
        dlpProfiles: 2,
        identityProviders: 1,
        sectionErrors: 0,
        auditLogs: 52,
        endpointFamilies: 26,
        appCategories: 1574
    };
    const snapshot = {
        ID: 912,
        CompanyID: 1,
        CreatedAt: new Date('2026-06-22T08:00:00.000Z'),
        MetricsJson: JSON.stringify({ cloudflare_network_security: { protectedApps: 99 }, stackctrl_risk: { domainRiskScores: { network: 18 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { network: 82 }, domainRiskScores: { network: 18 } },
            sources: [{
                sourceKey: 'cloudflare_network_security', status: 'available', isExpected: true,
                freshness: { lastUpdated: '2026-06-22T07:55:00.000Z', ageMinutes: 5 },
                metrics: { protectedApps: 99 }, dashboardMetrics,
                sourceLineage: {
                    sourceBuilder: 'storedStackCTRLNetworkEvidence',
                    sourceLayer: 'StackCTRLNetworkEvidenceSnapshots + StackCTRLNetworkEvidence',
                    evidenceSnapshotId: 1001,
                    evidenceRecordCount: 42,
                    omittedRecordCount: 0
                },
                evidence: [
                    { evidenceType: 'accessApps', data: Array.from({ length: 4 }, (_, index) => ({ id: `app-${index + 1}` })) },
                    { evidenceType: 'devices', data: Array.from({ length: 12 }, (_, index) => ({ id: `device-${index + 1}` })) },
                    { evidenceType: 'gatewayRules', data: Array.from({ length: 8 }, (_, index) => ({ id: `rule-${index + 1}` })) },
                    { evidenceType: 'accessLogs', data: Array.from({ length: 15 }, (_, index) => ({ id: `log-${index + 1}` })) },
                    { evidenceType: 'dlpProfiles', data: [{ id: 'dlp-1' }, { id: 'dlp-2' }] },
                    { evidenceType: 'warpProfiles', data: [{ id: 'warp-1' }] }
                ]
            }]
        })
    };
    const packageResult = await service.buildDomainPackage({
        companyId: 1,
        snapshot,
        runId: 73,
        domain: ENTERPRISE_DOMAINS.find(domain => domain.key === 'cloudflare_network_security'),
        historicalContext: { comparisons: {} }
    });
    for (const metric of NETWORK_LINEAGE_FIELDS.filter(field => !['healthScore', 'riskScore', 'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'].includes(field))) {
        assert.equal(packageResult.package.currentMetrics[metric], dashboardMetrics[metric], `currentMetrics.${metric}`);
    }
    assert.equal(packageResult.package.dataLineage.sourceBuilder, 'storedStackCTRLNetworkEvidence');
    assert.equal(packageResult.audit.stackCTRLDataCount, 39);
    assert.equal(packageResult.audit.preparedForAzureCount, 39);
    assert.ok(packageResult.allEvidence.some(row => row.evidenceType === 'coverageSummaries' && row.sourceMetric === 'accessLogCount' && row.data.coverageStatus === 'sampled_compact_rows'));
    assert.ok(packageResult.allEvidence.some(row => row.evidenceType === 'coverageSummaries' && row.sourceMetric === 'auditLogs' && row.data.coverageStatus === 'count_only_no_raw_rows' && row.data.expectedRows === 52));
    assert.ok(packageResult.allEvidence.some(row => row.evidenceType === 'coverageSummaries' && row.sourceMetric === 'endpointFamilies' && row.data.coverageStatus === 'count_only_no_raw_rows' && row.data.expectedRows === 26));
    assert.ok(packageResult.allEvidence.some(row => row.evidenceType === 'coverageSummaries' && row.sourceMetric === 'appCategories' && row.data.coverageStatus === 'count_only_no_raw_rows' && row.data.expectedRows === 1574));
    assert.equal(packageResult.sourceAlignment.mismatches.length, 0);
});

test('Enterprise Governance, Compliance, and Operations use saved API rows and document manual exclusions', async () => {
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            throw new Error(`Unexpected query: ${sql}`);
        }
    };

    const service = createEnterpriseIntelligenceService({
        pool,
        azureOpenAI: {
            async createJsonCompletion() {
                throw new Error('Azure should not be called');
            }
        },
        schedulerService: {
            async getHistoricalSnapshotContext() {
                return {};
            }
        },
        config: {
            domainDelayMs: 0
        }
    });

    const cases = [
        {
            key: 'governance',
            builder: 'storedStackCTRLGovernanceEvidence',
            evidenceType: 'governanceRows',
            apiRows: 4,
            manualRows: 2,
            metrics: {
                totalRows: 6,
                apiConnectedRows: 4,
                manualRowsExcluded: 2,
                attentionRequiredRows: 2,
                connectedRows: 2,
                ownerMissingCount: 1,
                governanceScore: 68
            }
        },
        {
            key: 'compliance',
            builder: 'storedStackCTRLComplianceEvidence',
            evidenceType: 'controls',
            apiRows: 5,
            manualRows: 3,
            metrics: {
                totalControls: 8,
                apiControls: 5,
                manualControlsExcluded: 3,
                failingControls: 2,
                partialControls: 1,
                passingControls: 2,
                manualReviewControls: 0,
                complianceScore: 58,
                auditReadinessStatus: 'not_ready'
            }
        },
        {
            key: 'operations',
            builder: 'storedStackCTRLOperationsEvidence',
            evidenceType: 'tasks',
            apiRows: 3,
            manualRows: 4,
            metrics: {
                totalTasks: 7,
                apiTasks: 3,
                manualTasksExcluded: 4
            }
        }
    ];

    for (const [index, item] of cases.entries()) {
        const rows = Array.from({ length: item.apiRows }, (_, rowIndex) => {
            if (item.key === 'governance') {
                return {
                    id: `${item.key}-${rowIndex + 1}`,
                    area: rowIndex % 2 === 0 ? 'Privileged Access' : 'Policy Review',
                    activity: rowIndex % 2 === 0 ? 'Admin access review' : 'Security policy review',
                    status: rowIndex < 2 ? 'Attention Required' : 'Connected',
                    owner: rowIndex === 0 ? '' : 'Security Manager',
                    entityName: `Governance Item ${rowIndex + 1}`,
                    entityType: 'GovernanceItem',
                    dataSource: 'StackCTRL API Evidence'
                };
            }

            if (item.key === 'compliance') {
                const statuses = ['Failed', 'Failed', 'Partial', 'Passed', 'Passed'];
                const insights = ['🔴 Failed', '🔴 Failed', '🟡 Partial', '🟢 Passing', '🟢 Passing'];

                return {
                    id: `${item.key}-${rowIndex + 1}`,
                    controlId: `compliance-control-${rowIndex + 1}`,
                    controlName: `Compliance Control ${rowIndex + 1}`,
                    name: `Compliance Control ${rowIndex + 1}`,
                    area: rowIndex < 2 ? 'Identity' : rowIndex === 2 ? 'Devices' : 'Backup',
                    controlCategory: rowIndex < 2 ? 'Identity' : rowIndex === 2 ? 'Devices' : 'Backup',
                    status: statuses[rowIndex],
                    insight: insights[rowIndex],
                    evidenceSource: 'StackCTRL API Evidence',
                    validationReason: `Compliance Control ${rowIndex + 1} has API-connected validation evidence.`,
                    remediationAction: statuses[rowIndex] === 'Passed'
                        ? 'Maintain evidence for the next review cycle.'
                        : 'Remediate the control and collect closure evidence.',
                    auditImpact: statuses[rowIndex] === 'Passed'
                        ? 'Passing control supports audit readiness.'
                        : 'Control gap reduces audit readiness.'
                };
            }

            return {
                id: `${item.key}-${rowIndex + 1}`,
                title: `Operations Task ${rowIndex + 1}`,
                status: 'open',
                dataSource: 'StackCTRL API Evidence'
            };
        });

        const snapshot = {
            ID: 920 + index,
            CompanyID: 1,
            CreatedAt: new Date('2026-06-23T08:00:00.000Z'),
            MetricsJson: JSON.stringify({
                stackctrl_risk: {
                    domainRiskScores: {
                        [item.key]: 20
                    }
                }
            }),
            ContextJson: JSON.stringify({
                riskEngine: {
                    domainHealthScores: {
                        [item.key]: 80
                    },
                    domainRiskScores: {
                        [item.key]: 20
                    }
                },
                sources: [{
                    sourceKey: item.key,
                    status: 'available',
                    isExpected: true,
                    freshness: {
                        lastUpdated: '2026-06-23T07:55:00.000Z',
                        ageMinutes: 5
                    },
                    metrics: item.metrics,
                    dashboardMetrics: item.metrics,
                    sourceLineage: {
                        sourceBuilder: item.builder,
                        evidenceSnapshotId: 1100 + index,
                        collectionStatus: 'complete',
                        isComplete: true,
                        totalRows: item.apiRows + item.manualRows,
                        apiConnectedRows: item.apiRows,
                        manualRowsExcluded: item.manualRows,
                        evidenceRecordCount: item.apiRows,
                        omittedRecordCount: item.manualRows
                    },
                    evidence: [{
                        evidenceType: item.evidenceType,
                        data: rows
                    }]
                }]
            })
        };

        const packageResult = await service.buildDomainPackage({
            companyId: 1,
            snapshot,
            runId: 80 + index,
            domain: ENTERPRISE_DOMAINS.find(domain => domain.key === item.key),
            historicalContext: {
                comparisons: {}
            }
        });

        assert.equal(packageResult.package.dataLineage.sourceBuilder, item.builder, item.key);
        assert.equal(packageResult.audit.omittedCount, item.manualRows, item.key);
        assert.equal(packageResult.package.dataLineage.totalRows, item.apiRows + item.manualRows, item.key);
        assert.equal(packageResult.package.dataLineage.apiConnectedRows, item.apiRows, item.key);
        assert.equal(packageResult.package.dataLineage.manualRowsExcluded, item.manualRows, item.key);

        assert.match(
            packageResult.package.limitations.missingDataWarnings.join(' '),
            /intentionally excluded from Azure input/,
            item.key
        );

        if (item.key === 'governance') {
            assert.ok(packageResult.audit.stackCTRLDataCount >= item.apiRows, item.key);
            assert.ok(packageResult.audit.preparedForAzureCount >= item.apiRows, item.key);
            assert.ok(packageResult.allEvidence.length >= item.apiRows, item.key);

            assert.ok(
                packageResult.allEvidence.some(row => row.evidenceType === 'summaryMetrics'),
                'Governance should include summaryMetrics evidence'
            );

            assert.ok(
                packageResult.allEvidence.some(row => row.evidenceType === 'attentionRequiredGovernance'),
                'Governance should include attentionRequiredGovernance evidence'
            );

            assert.ok(
                packageResult.allEvidence.some(row => row.evidenceType === 'riskOwnershipGaps'),
                'Governance should include riskOwnershipGaps evidence'
            );

            assert.ok(
                packageResult.allEvidence.some(row => row.evidenceType === 'reviewGaps'),
                'Governance should include reviewGaps evidence'
            );
        } else if (item.key === 'compliance') {
            assert.ok(packageResult.audit.stackCTRLDataCount >= item.apiRows, item.key);
            assert.ok(packageResult.audit.preparedForAzureCount >= item.apiRows, item.key);
            assert.ok(packageResult.allEvidence.length >= item.apiRows, item.key);

            assert.ok(
                packageResult.allEvidence.some(row => row.evidenceType === 'summaryMetrics'),
                'Compliance should include summaryMetrics evidence'
            );

            assert.ok(
                packageResult.allEvidence.some(row => row.evidenceType === 'failedControls'),
                'Compliance should include failedControls evidence'
            );

            assert.ok(
                packageResult.allEvidence.some(row => row.evidenceType === 'partialControls'),
                'Compliance should include partialControls evidence'
            );

            assert.ok(
                packageResult.allEvidence.some(row => row.evidenceType === 'passedControls'),
                'Compliance should include passedControls evidence'
            );

            assert.ok(
                packageResult.allEvidence.some(row => row.evidenceType === 'remediationActions'),
                'Compliance should include remediationActions evidence'
            );

            assert.ok(
                packageResult.allEvidence.every(row => !Array.isArray(row.data?.rawEvidence)),
                'Compliance compact evidence must not include rawEvidence arrays'
            );
        } else {
            assert.equal(packageResult.audit.stackCTRLDataCount, item.apiRows, item.key);
            assert.equal(packageResult.audit.preparedForAzureCount, item.apiRows, item.key);
        }
    }
});

test('Enterprise warns on missing Device evidence and continues with stale saved Device evidence', async () => {
    for (const sourceStatus of ['missing', 'stale']) {
        let insertId = 900;
        let azureCalls = 0;
        const source = {
            sourceKey: 'devices',
            status: sourceStatus,
            isExpected: true,
            freshness: sourceStatus === 'stale'
                ? { lastUpdated: '2026-06-22T05:00:00.000Z', ageMinutes: 180 }
                : { lastUpdated: null, ageMinutes: null },
            warnings: [sourceStatus === 'stale'
                ? 'Device Protection evidence is stale.'
                : 'No complete StackCTRL Device Protection evidence snapshot is available. Enterprise analysis continued with limited data.'],
            metrics: sourceStatus === 'stale' ? { totalDevices: 17, complianceRate: 76 } : {},
            dashboardMetrics: sourceStatus === 'stale' ? { totalDevices: 17, complianceRate: 76 } : {},
            evidence: sourceStatus === 'stale' ? [{ evidenceType: 'devices', data: [{ id: 'device-1' }] }] : [],
            sourceLineage: { sourceBuilder: 'storedStackCTRLDeviceEvidence', evidenceSnapshotId: 801 }
        };
        const snapshot = {
            ID: sourceStatus === 'stale' ? 912 : 911,
            CompanyID: 1,
            TenantKey: 'sunbird',
            SnapshotType: 'manual',
            CreatedAt: new Date('2026-06-22T08:00:00.000Z'),
            DataCompletenessScore: sourceStatus === 'stale' ? 100 : 0,
            MetricsJson: JSON.stringify({ stackctrl_risk: { domainRiskScores: { devices: 25 } } }),
            ContextJson: JSON.stringify({
                riskEngine: { domainHealthScores: { devices: 75 }, domainRiskScores: { devices: 25 } },
                sources: [source]
            })
        };
        const calls = [];
        const pool = {
            async query(sql, params = []) {
                calls.push({ sql, params });
                if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
                if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
                if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
                if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
                return [{ affectedRows: 1 }, []];
            }
        };
        const service = createEnterpriseIntelligenceService({
            pool,
            azureOpenAI: { async createJsonCompletion() { azureCalls += 1; return { data: domainResponse('devices') }; } },
            schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
            config: { domainDelayMs: 0 }
        });
        const result = await service.runEnterpriseReport({
            companyId: 1,
            snapshotId: snapshot.ID,
            domainKeys: ['devices'],
            includeSynthesis: false
        });
        assert.equal(azureCalls, sourceStatus === 'stale' ? 1 : 0, sourceStatus);
        assert.equal(result.domains[0].status, sourceStatus === 'stale' ? 'completed' : 'completed_with_warnings');
        const auditWrite = calls.find(call => call.sql.includes('INSERT INTO StackCTRLIntelligenceEvidenceAudit'));
        assert.ok(auditWrite);
        assert.equal(auditWrite.params[5], sourceStatus === 'stale' ? 1 : 0);
        if (sourceStatus === 'missing') {
            assert.match(result.domains[0].errorMessage, /no complete/i);
            assert.equal(result.status, 'completed_with_warnings');
            assert.equal(result.domains[0].analysis.evidenceLimitations.recordsSent, 0);
            assert.match(result.domains[0].analysis.evidenceGaps.join(' '), /limited data|No complete/i);
        } else {
            assert.equal(result.domains[0].analysis.missingDataWarnings.filter(warning => /source_stale|evidence is stale/i.test(warning)).length, 0);
            assert.equal(result.domains[0].analysis.missingDataInfo.filter(info => /Device Protection source is stale.*2026-06-22T05:00:00.000Z/i.test(info)).length, 1);
            assert.equal(result.domains[0].analysis.evidenceLimitations.recordsSent, 1);
        }
    }
});

test('Enterprise pipeline continues to later domains when one domain has limited data', async () => {
    let insertId = 950;
    let azureCalls = 0;
    const snapshot = {
        ID: 950,
        CompanyID: 1,
        TenantKey: 'sunbird',
        SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-24T08:00:00.000Z'),
        DataCompletenessScore: 50,
        MetricsJson: JSON.stringify({ stackctrl_risk: { domainRiskScores: { devices: 30, applications: 20 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { devices: 70, applications: 80 }, domainRiskScores: { devices: 30, applications: 20 } },
            sources: [
                {
                    sourceKey: 'devices',
                    status: 'available',
                    isExpected: true,
                    warnings: ['Device Protection source returned no entity rows for this snapshot.'],
                    evidence: []
                },
                {
                    sourceKey: 'applications',
                    status: 'available',
                    isExpected: true,
                    metrics: { totalApplications: 2, externalApplications: 1 },
                    dashboardMetrics: { totalApplications: 2, externalApplications: 1 },
                    evidence: [{ evidenceType: 'applications', data: [
                        { id: 'app-1', displayName: 'Finance Portal', publisherName: 'Contoso' },
                        { id: 'app-2', displayName: 'External SaaS', publisherName: 'External Vendor' }
                    ] }]
                }
            ]
        })
    };
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: {
            async createJsonCompletion() {
                azureCalls += 1;
                return {
                    data: domainResponse('applications'),
                    requestSizeBytes: 1000,
                    responseSizeBytes: 1000,
                    usage: { input_tokens: 100, output_tokens: 50, total_tokens: 150 }
                };
            }
        },
        logger: { info() {}, warn() {}, error() {} },
        wait: async () => {},
        config: { domainDelayMs: 0 }
    });

    const result = await service.runEnterpriseReport({
        companyId: 1,
        snapshotId: snapshot.ID,
        domainKeys: ['devices', 'applications'],
        includeSynthesis: false
    });

    assert.equal(result.status, 'completed_with_warnings');
    assert.equal(result.domains[0].status, 'completed_with_warnings');
    assert.equal(result.domains[0].analysis.evidenceLimitations.recordsSent, 0);
    assert.equal(result.domains[1].status, 'completed');
    assert.equal(result.domains[1].analysis.evidenceLimitations.recordsSent, 2);
    assert.equal(azureCalls, 1);
    assert.equal(result.terminalError, null);
});

test('enterprise synthesis uses stored successful domain intelligence only', async () => {
    const azurePrompts = [];
    let insertId = 700;
    const snapshot = {
        ID: 80, CompanyID: 1, TenantKey: 'tenant-sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-22T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({ stackctrl_risk: { domainRiskScores: { identity: 25, devices: 20 } } }),
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { identity: 75, devices: 80 }, domainRiskScores: { identity: 25, devices: 20 } },
            sources: [
                { sourceKey: 'identity', status: 'available', metrics: { mfaCoverage: 90 }, evidence: [{ evidenceType: 'metric_summary', data: { usersWithoutMfa: 2 } }] },
                { sourceKey: 'devices', status: 'available', metrics: { complianceRate: 90 }, evidence: [{ evidenceType: 'metric_summary', data: { staleDevices: 1 } }] }
            ]
        })
    };
    const pool = {
        async query(sql, params = []) {
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (sql.includes('FROM StackCTRLEnterpriseReportRuns WHERE')) {
                return [[{
                    ID: 700, CompanyID: 1, SnapshotID: 80, PeriodType: 'daily',
                    PeriodStart: new Date('2026-06-22T00:00:00.000Z'),
                    PeriodEnd: new Date('2026-06-22T23:59:59.000Z'),
                    Mode: 'enterprise_deep_reporting',
                    ProgressJson: JSON.stringify({ domainQueue: [{ domainKey: 'identity' }, { domainKey: 'devices' }] })
                }], []];
            }
            if (sql.includes('SELECT ID, CompanyID, SnapshotID, RunID, DomainKey') && sql.includes('ErrorMessage')) {
                return [[
                    {
                        ID: 801, CompanyID: 1, SnapshotID: 80, RunID: 700, DomainKey: 'identity', DomainName: 'Identity Protection',
                        HealthScore: 75, RiskScore: 25, RiskLevel: 'moderate', Status: 'completed',
                        DomainExecutiveSummary: 'Identity summary', TechnicalSummary: 'Technical summary', BusinessImpact: 'Impact', CurrentPosture: 'partial',
                        EvidenceSummary: 'Evidence', ScoreJustification: 'Justified', ControlAssessment: '{}', FindingsJson: '[]', RisksJson: '[]',
                        RecommendationsJson: '[]', TrendAnalysisJson: '[]', YesterdayVsTodayJson: '{}', MissingDataWarningsJson: '[]', AssumptionsJson: '[]',
                        ErrorMessage: null
                    },
                    {
                        ID: 802, CompanyID: 1, SnapshotID: 80, RunID: 700, DomainKey: 'devices', DomainName: 'Device Protection',
                        HealthScore: null, RiskScore: null, RiskLevel: null, Status: 'failed_rate_limited',
                        DomainExecutiveSummary: null, TechnicalSummary: null, BusinessImpact: null, CurrentPosture: null,
                        EvidenceSummary: null, ScoreJustification: null, ControlAssessment: null, FindingsJson: null, RisksJson: null,
                        RecommendationsJson: null, TrendAnalysisJson: null, YesterdayVsTodayJson: null, MissingDataWarningsJson: null, AssumptionsJson: null,
                        ErrorMessage: 'Azure rate limit reached'
                    }
                ], []];
            }
            if (sql.includes('FROM StackCTRLEnterpriseSynthesis synthesis')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: {
            async createJsonCompletion(options) {
                azurePrompts.push(options.messages[1].content);
                return {
                    data: synthesisResponse(),
                    requestSizeBytes: 1200,
                    responseSizeBytes: 2400,
                    retryCount: 0,
                    usage: { input_tokens: 500, output_tokens: 250, total_tokens: 750 }
                };
            }
        },
        wait: async () => {},
        config: { domainDelayMs: 0 }
    });

    await service.runEnterpriseSynthesis({ companyId: 1, runId: 700 });
    assert.equal(azurePrompts.length, 1);
    const payload = azurePrompts[0].split('STORED STACKCTRL ENTERPRISE INTELLIGENCE:\n')[1];
    const synthesisInput = JSON.parse(payload);
    assert.equal(synthesisInput.domainIntelligence.length, 1);
    assert.equal(synthesisInput.domainIntelligence[0].domainKey, 'identity');
    assert.deepEqual(synthesisInput.domainRunSummary.successfulDomains, ['identity']);
    assert.equal(synthesisInput.domainRunSummary.failedDomains.length, 1);
    assert.equal(synthesisInput.limitations.excludedDomainStatuses[0].domainKey, 'devices');
});

test('enterprise evidence flattening preserves entity rows and builds categorized evidence catalog', () => {
    const users = [
        { id: 'admin-1', displayName: 'Break glass account', mail: 'admin@example.com', mfaEnabled: false, roles: ['Global Administrator'], riskLevel: 'HIGH' },
        { id: 'user-2', displayName: 'Chad Brown', mail: 'chad@example.com', mfaEnabled: true, roles: ['Standard'], riskLevel: 'MEDIUM' }
    ];
    const evidence = [
        { evidenceType: 'users', data: users },
        { evidenceType: 'dashboard_evidence_lists', data: { usersWithoutMfa: [users[0]], privilegedUsers: [users[0]], allUsers: users } }
    ];
    const flattened = flattenDomainEvidence(evidence, { rootPath: 'identity.evidence', domainKey: 'identity' });
    assert.equal(flattened.length, 2);
    assert.deepEqual(flattened[0].data.roles, ['Global Administrator']);
    assert.equal(flattened[0].entityKey, 'admin-1');

    const catalog = buildEvidenceCatalog(evidence, ENTERPRISE_DOMAINS[0], 501);
    assert.equal(catalog.primaryTable.count, 2);
    assert.equal(catalog.categories.find(category => category.key === 'usersWithoutMfa').count, 1);
    assert.equal(catalog.categories.find(category => category.key === 'usersWithoutMfa').sourceMetric, 'mfaMissing');
    assert.equal(catalog.categories.find(category => category.key === 'usersWithoutMfa').entities[0].displayName, 'Break glass account');
});

test('all required enterprise domain modes are registered', () => {
    assert.equal(ENTERPRISE_DOMAINS.length, 10);
    for (const domain of ENTERPRISE_DOMAINS) assert.match(domain.mode, /^enterprise_domain_/);
    assert.deepEqual(new Set(ENTERPRISE_DOMAINS.map(domain => domain.key)), new Set([
        'identity', 'devices', 'email_security', 'cloudflare_network_security', 'governance',
        'compliance', 'security_alerts', 'operations', 'backup', 'applications'
    ]));
});

test('enterprise token threshold switches later domains to safe batches instead of skipping Applications', async () => {
    let insertId = 9000;
    let azureCalls = 0;
    const snapshot = {
        ID: 990, CompanyID: 1, TenantKey: 'sunbird', SnapshotType: 'manual',
        CreatedAt: new Date('2026-06-24T08:00:00.000Z'), DataCompletenessScore: 100,
        MetricsJson: '{}',
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { identity: 80, applications: 75 }, domainRiskScores: { identity: 20, applications: 25 } },
            sources: [
                { sourceKey: 'identity', status: 'available', isExpected: true, evidence: [{ evidenceType: 'users', data: [{ id: 'user-1', displayName: 'User One' }] }] },
                { sourceKey: 'applications', status: 'available', isExpected: true, evidence: [{ evidenceType: 'applications', data: [
                    { id: 'app-1', displayName: 'App One' }, { id: 'app-2', displayName: 'App Two' }, { id: 'app-3', displayName: 'App Three' }
                ] }] }
            ]
        })
    };
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: {
            async createJsonCompletion(options) {
                azureCalls += 1;
                const domainKey = options.messages[1].content.includes('"key":"applications"') ? 'applications' : 'identity';
                return {
                    data: domainResponse(domainKey), requestSizeBytes: 1000, responseSizeBytes: 1000, retryCount: 0,
                    usage: azureCalls === 1
                        ? { input_tokens: 9000, output_tokens: 2000, total_tokens: 11000 }
                        : { input_tokens: 100, output_tokens: 50, total_tokens: 150 }
                };
            }
        },
        logger: { info() {}, warn() {}, error() {} }, wait: async () => {},
        config: { domainDelayMs: 0, maxTotalTokens: 10000, thresholdBatchMaxItems: 1 }
    });

    const result = await service.runEnterpriseReport({
        companyId: 1, snapshotId: snapshot.ID, domainKeys: ['identity', 'applications'], includeSynthesis: false
    });

    assert.equal(result.domains[1].domainKey, 'applications');
    assert.equal(result.domains[1].status, 'completed');
    assert.equal(result.domains[1].batchInfo.totalBatches, 3);
    assert.equal(result.domains[1].analysis.evidenceLimitations.recordsSent, 3);
    assert.equal(result.domains[1].analysis.evidenceLimitations.recordsOmitted, 0);
    assert.equal(azureCalls, 4);
    assert.ok(result.domains[1].analysis.recommendations.every(item => item.affectedEntities.length && item.evidenceRows.length));
    assert.equal(result.domains.some(domain => domain.status === 'skipped_token_threshold'), false);
});

test('Power BI read model returns full domain outputs, synthesis, raw labels, and evidence tables', async () => {
    const run = {
        ID: 700,
        CompanyID: 1,
        SnapshotID: 500,
        PeriodType: 'weekly',
        PeriodStart: '2026-06-15',
        PeriodEnd: '2026-06-21',
        Status: 'completed',
        StartedAt: '2026-06-21T18:00:00Z'
    };

    const domainRows = ENTERPRISE_DOMAINS.map((domain, index) => {
        const disabled = TEMPORARILY_DISABLED_DOMAIN_KEYS.includes(domain.key);

        const riskRows = disabled
            ? []
            : [{
                riskId: `${domain.key}-risk-1`,
                title: `${domain.name} risk`,
                severity: 'medium',
                sourceDomain: domain.key,
                sourceMetric: 'all',
                affectedEntities: [{
                    entityId: `${domain.key}-entity-1`,
                    entityName: `${domain.name} Entity 1`,
                    entityType: 'TestEntity',
                    sourceDomain: domain.key,
                    sourceMetric: 'all',
                    businessReason: `${domain.name} entity requires review.`,
                    recommendation: `Review ${domain.name} entity.`
                }],
                evidenceRows: [{
                    entityId: `${domain.key}-evidence-1`,
                    entityName: `${domain.name} Evidence 1`,
                    entityType: 'EvidenceRow',
                    sourceDomain: domain.key,
                    sourceMetric: 'all'
                }]
            }];

        const recommendationRows = disabled
            ? []
            : [{
                recommendationId: `${domain.key}-rec-1`,
                title: `${domain.name} recommendation`,
                priority: 'medium',
                sourceDomain: domain.key,
                sourceMetric: 'all',
                affectedEntities: [{
                    entityId: `${domain.key}-entity-2`,
                    entityName: `${domain.name} Entity 2`,
                    entityType: 'TestEntity',
                    sourceDomain: domain.key,
                    sourceMetric: 'all',
                    businessReason: `${domain.name} recommendation needs action.`,
                    recommendation: `Complete ${domain.name} recommendation.`
                }],
                evidenceRows: [{
                    entityId: `${domain.key}-evidence-2`,
                    entityName: `${domain.name} Evidence 2`,
                    entityType: 'EvidenceRow',
                    sourceDomain: domain.key,
                    sourceMetric: 'all'
                }]
            }];

        const analysis = {
            domain: {
                key: domain.key,
                name: domain.name
            },
            domainExecutiveSummary: disabled
                ? `${domain.name} is temporarily disabled.`
                : `${domain.name} summary`,
            technicalSummary: disabled
                ? null
                : `${domain.name} technical summary`,
            businessImpact: disabled
                ? null
                : `${domain.name} business impact`,
            currentPosture: disabled
                ? 'temporarily disabled'
                : 'managed',
            evidenceCatalog: {
                categories: [{
                    categoryKey: 'all',
                    entities: [{
                        id: `${domain.key}-1`,
                        name: `${domain.name} Entity`
                    }]
                }]
            },
            keyFindings: disabled
                ? []
                : [{
                    title: `${domain.name} finding`,
                    severity: 'medium',
                    sourceDomain: domain.key,
                    sourceMetric: 'all'
                }],
            risks: riskRows,
            recommendations: recommendationRows,
            controlAssessment: [],
            trendAnalysis: [],
            missingDataWarnings: [],
            assumptions: [],
            batchInfo: {
                complete: true
            },
            evidenceLimitations: {
                recordsSent: disabled ? 0 : 1,
                recordsOmitted: 0
            },
            powerBiSummary: {}
        };

        return {
            ID: 800 + index,
            CompanyID: 1,
            SnapshotID: 500,
            RunID: 700,
            DomainKey: domain.key,
            DomainName: domain.name,
            PeriodType: 'weekly',
            PeriodStart: '2026-06-15',
            PeriodEnd: '2026-06-21',
            HealthScore: disabled ? null : 80,
            RiskScore: disabled ? null : 20,
            RiskLevel: disabled ? null : 'low',
            Status: disabled ? 'temporarily_disabled' : 'completed',
            InputTokens: disabled ? 0 : 100,
            OutputTokens: disabled ? 0 : 50,
            TotalTokens: disabled ? 0 : 150,
            RetryCount: 0,
            CreatedAt: run.StartedAt,

            AnalysisJson: JSON.stringify(analysis),

            DomainExecutiveSummary: analysis.domainExecutiveSummary,
            TechnicalSummary: analysis.technicalSummary,
            BusinessImpact: analysis.businessImpact,
            CurrentPosture: analysis.currentPosture,
            EvidenceSummary: disabled ? null : `${domain.name} evidence summary`,
            ScoreJustification: disabled ? null : `${domain.name} score justification`,
            ControlAssessment: JSON.stringify(analysis.controlAssessment),
            FindingsJson: JSON.stringify(analysis.keyFindings),
            RisksJson: JSON.stringify(riskRows),
            RecommendationsJson: JSON.stringify(recommendationRows),
            TrendAnalysisJson: JSON.stringify(analysis.trendAnalysis),
            YesterdayVsTodayJson: '{}',
            MissingDataWarningsJson: JSON.stringify(analysis.missingDataWarnings),
            AssumptionsJson: JSON.stringify(analysis.assumptions),
            TokenUsageJson: JSON.stringify({
                inputTokens: disabled ? 0 : 100,
                outputTokens: disabled ? 0 : 50,
                totalTokens: disabled ? 0 : 150
            }),
            BatchInfoJson: JSON.stringify(analysis.batchInfo),
            PowerBISummaryJson: '{}'
        };
    });
    const synthesis = {
        ID: 900,
        CompanyID: 1,
        SnapshotID: 500,
        RunID: 700,
        PeriodType: 'weekly',
        PeriodStart: run.PeriodStart,
        PeriodEnd: run.PeriodEnd,
        Status: 'completed',
        CreatedAt: run.StartedAt,
        ExecutiveSummaryJson: JSON.stringify({
            summary: 'Full synthesis'
        }),
        BoardReportJson: '{}',
        ManagementReportJson: '{}',
        RiskRegisterJson: '[]',
        RecommendationsJson: '[]',
        TrendAnalysisJson: '[]',
        ComplianceReviewJson: '{}',
        GovernanceReviewJson: '{}',
        DomainScorecardJson: '[]',
        MaturityAssessmentJson: '{}',
        TopDecisionsRequiredJson: '[]',
        Next30DaysPlanJson: '[]',
        Next90DaysPlanJson: '[]',
        EvidenceJustificationJson: '{}',
        LimitationsJson: '[]',
        PowerBISummaryJson: '{}'
    };

    const snapshot = {
        ID: 500,
        CompanyID: 1,
        SnapshotType: 'weekly',
        CreatedAt: run.StartedAt,
        MetricsJson: '{"identity":{"totalUsers":1}}',
        ContextJson: JSON.stringify({
            sources: [{
                sourceKey: 'identity',
                evidence: [{ id: 'user-1' }]
            }]
        })
    };

    const pool = {
        async query(sql, params = []) {
            if (sql.includes('FROM StackCTRLEnterpriseReportRuns')) {
                return [[run], []];
            }

            if (sql.includes('FROM StackCTRLEnterpriseSynthesis')) {
                return [[synthesis], []];
            }

            if (sql.includes('FROM StackCTRLIntelligenceEvidenceAudit')) {
                return [[], []];
            }

            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots')) {
                return [[snapshot], []];
            }

            if (sql.includes('FROM StackCTRLTenantDomainIntelligence')) {
                const requestedDomainKey = params.find(value =>
                    ENTERPRISE_DOMAINS.some(domain => domain.key === value)
                );

                if (requestedDomainKey) {
                    return [[domainRows.find(row => row.DomainKey === requestedDomainKey)].filter(Boolean), []];
                }

                return [domainRows, []];
            }

            throw new Error(`Unexpected query: ${sql}`);
        }
    };

    const service = createEnterpriseIntelligenceService({
        pool,
        azureOpenAI: {},
        schedulerService: {}
    });

    const intelligence = await service.getPowerBIIntelligenceRun(1);
    const raw = await service.getPowerBIRaw(1, 'identity');
    assert.equal(intelligence.dataClassification, 'intelligent_azure_output');
    assert.equal(intelligence.domains.length, 10);
    assert.equal(intelligence.completeness.expectedDomains, 9);
    assert.equal(intelligence.completeness.disabledDomainCount, 1);
    assert.deepEqual(intelligence.completeness.activeDomainKeys, ACTIVE_ENTERPRISE_DOMAIN_KEYS);

    const finalSummary =
        intelligence.finalSynthesis?.synthesisOutput?.enterpriseExecutiveSummary?.summary ||
        intelligence.finalSynthesis?.enterpriseExecutiveSummary?.summary ||
        intelligence.finalSynthesis?.executiveSummary?.summary ||
        intelligence.finalSynthesis?.summary ||
        intelligence.finalSynthesis?.ExecutiveSummaryJson?.summary;

    assert.equal(finalSummary, 'Full synthesis');

    assert.equal(
        intelligence.tables.AffectedEntityRows.length,
        ACTIVE_ENTERPRISE_DOMAIN_KEYS.length * 2
    );

    assert.equal(
        intelligence.tables.EvidenceRows.length,
        ACTIVE_ENTERPRISE_DOMAIN_KEYS.length * 2
    );

    assert.equal(intelligence.tables.disabled_domains.length, 1);
    assert.equal(intelligence.tables.domain_status.length, 10);

    assert.equal(
        intelligence.tables.domain_status.find(row => row.domainKey === 'governance').domainStatus,
        'completed'
    );

    assert.equal(
        intelligence.tables.domain_status.find(row => row.domainKey === 'governance').includedInCurrentPhase,
        true
    );

    assert.equal(
        intelligence.tables.domain_status.find(row => row.domainKey === 'governance').selectable,
        true
    );

    assert.equal(
        intelligence.tables.domain_status.find(row => row.domainKey === 'operations').domainStatus,
        'temporarily_disabled'
    );

    assert.equal(
        intelligence.tables.domain_status.find(row => row.domainKey === 'compliance').domainStatus,
        'completed'
    );

    assert.equal(
        intelligence.tables.domain_status.find(row => row.domainKey === 'compliance').includedInCurrentPhase,
        true
    );
        
    assert.notEqual(
        intelligence.tables.domain_status.find(row => row.domainKey === 'compliance').domainStatus,
        'temporarily_disabled'
    );

    assert.equal(
        intelligence.tables.risk_register.some(row => TEMPORARILY_DISABLED_DOMAIN_KEYS.includes(row.domainKey)),
        false
    );

    const governanceDomain = await service.getPowerBIDomain(1, 'governance');
    assert.equal(governanceDomain.domain.domainKey, 'governance');
    assert.equal(governanceDomain.domain.status, 'completed');

    const operationsDomain = await service.getPowerBIDomain(1, 'operations');
    assert.equal(operationsDomain.domain.status, 'temporarily_disabled');
    assert.equal(operationsDomain.domain.selectable, false);

const complianceDomain = await service.getPowerBIDomain(1, 'compliance');
assert.equal(complianceDomain.domain.domainKey, 'compliance');
assert.equal(complianceDomain.domain.status, 'completed');
assert.notEqual(complianceDomain.domain.status, 'temporarily_disabled');

    assert.equal(raw.dataClassification, 'raw_non_intelligent_stackctrl');
    assert.match(raw.warning, /not been analysed/i);
});

test('admin enterprise progress excludes heavy JSON and returns polling counters only', async () => {
    const queries = [];
    const pool = {
        async query(sql) {
            queries.push(sql);
            if (sql.includes('FROM StackCTRLEnterpriseReportRuns')) return [[{
                ID: 50, CompanyID: 1, SnapshotID: 40, Status: 'running', Mode: 'enterprise_deep_reporting',
                TotalInputTokens: 100, TotalOutputTokens: 20, TotalTokens: 120, RetryCount: 0,
                ProgressJson: JSON.stringify({ currentDomainKey: 'security_alerts', counts: { completed: 4, failed: 0, partial: 0, skipped: 0 } })
            }], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence ')) return [[{ CompanyID: 1, SnapshotID: 40, RunID: 50, DomainKey: 'identity', Status: 'completed' }], []];
            if (sql.includes('FROM StackCTRLIntelligenceEvidenceAudit ')) return [[{ RunID: 50, DomainKey: 'security_alerts', EvidenceIncludedCount: 100, SentToAzureCount: 60, OmittedCount: 0, EvidenceOmittedCount: 0 }], []];
            if (sql.includes('FROM StackCTRLEnterpriseSynthesis ')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligenceBatches ')) return [[{ RunID: 50, DomainKey: 'security_alerts', BatchCount: 4, BatchNumber: 3, JsonRecoveryWarning: 1 }], []];
            throw new Error(`Unexpected query: ${sql}`);
        }
    };
    const service = createEnterpriseIntelligenceService({ pool, azureOpenAI: {}, schedulerService: {} });
    const progress = await service.getAdminProgress(1);
    const sql = queries.join('\n');
    for (const forbidden of ['AnalysisJson', 'AzureInputSummaryJson', 'OmittedSummaryJson', 'BatchSummaryJson', 'RawResponsePreview', 'FindingsJson', 'RisksJson']) {
        assert.doesNotMatch(sql, new RegExp(forbidden));
    }
    assert.equal(progress.payloadType, 'enterprise_progress_only');
    assert.equal(progress.progressSummary.currentDomain, 'security_alerts');
    assert.equal(progress.progressSummary.recordsPrepared, 100);
    assert.equal(progress.progressSummary.recordsSent, 60);
    assert.equal(progress.progressSummary.currentBatch, 3);
    assert.equal(progress.progressSummary.jsonRecoveryWarning, true);
    assert.equal(progress.progressSummary.finalSynthesisReady, false);
    assert.ok(Array.isArray(progress.domainRunAudits));
    assert.equal(progress.domainRunAudits[0].domainKey, 'security_alerts');
    assert.equal(progress.domainRunAudits[0].preparedRecordCount, 100);
});

test('Security Alerts selected-domain analysis sends compact groups and keeps output report-ready', async () => {
    let insertId = 12000;
    const prompts = [];
    const packages = [];
    const alertRows = Array.from({ length: 150 }, (_, index) => ({
        id: `source-alert-${index + 1}`, title: `Repeated alert pattern ${index % 3}`,
        severity: index < 10 ? 'critical' : 'high', category: index % 2 ? 'malware' : 'phishing',
        status: 'active', source: 'Microsoft Defender', deviceName: `device-${index % 12}`, userPrincipalName: `user${index % 20}@example.com`, ipAddress: `198.51.100.${index % 40 + 1}`, url: `https://evil${index % 3}.example-threat.test/path`, fileHash: 'a'.repeat(64), location: index % 2 ? 'Cape Town, ZA' : 'Johannesburg, ZA'
    }));
    const snapshot = {
        ID: 1200, CompanyID: 1, CreatedAt: new Date('2026-06-24T08:00:00Z'), MetricsJson: '{}',
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { security: 50 }, domainRiskScores: { security: 50 } },
            sources: [{
                sourceKey: 'security_alerts', status: 'available', isExpected: true,
                warnings: ['threat_indicators_unavailable: external threat indicator enrichment failed'],
                sourceLineage: { evidenceRecordCount: 150, omittedRecordCount: 0, sourceFetchedAt: '2026-06-24T08:05:00.000Z' },
                dashboardMetrics: { totalAlerts: 150, highSeverityAlerts: 150, activeIncidents: 0, suspiciousSignIns: 0 },
                evidence: [{ evidenceType: 'alerts', data: alertRows }]
            }]
        })
    };
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: {
            async createJsonCompletion(options) {
                prompts.push(options.messages[1].content);
                packages.push(JSON.parse(options.messages[1].content.split('STACKCTRL SECURITY ALERTS BATCH:\n')[1]));
                return {
                    data: {
                        domainExecutiveSummary: 'Security Alerts show repeated Defender alert patterns.',
                        technicalSummary: 'Repeated high-severity alerts are concentrated across users and devices.',
                        currentPosture: 'Active high-severity alert clusters require triage; resolved positives should remain posture notes.',
                        businessImpact: 'Repeated security alerts can delay containment decisions.',
                        keyFindings: Array.from({ length: 12 }, (_, index) => ({ title: `Repeated Defender alerts ${index}`, description: 'D'.repeat(900), severity: 'high', sourceMetric: 'repeatedAlertPatterns' })),
                        risks: [
                            { title: 'No critical alerts detected', severity: 'low', sourceMetric: 'summaryMetrics' },
                            ...Array.from({ length: 8 }, (_, index) => ({
                                title: `Alert risk ${index}`,
                                severity: 'high',
                                sourceMetric: index % 2 ? 'affectedUsers' : 'repeatedAlertPatterns',
                                affectedEntities: [{ userPrincipalName: `user${index}@example.com`, entityType: 'User' }],
                                evidenceRows: [{ title: `Repeated alert pattern ${index % 3}`, userPrincipalName: `user${index}@example.com`, deviceName: `device-${index % 12}` }]
                            }))
                        ],
                        recommendations: Array.from({ length: 15 }, (_, index) => ({ title: `Alert action ${index}`, priority: 'high', sourceMetric: 'repeatedAlertPatterns' })),
                        controlAssessment: [],
                        managementActions: Array.from({ length: 15 }, (_, index) => ({ title: `Management action ${index}`, sourceMetric: 'alerts' })),
                        trendAnalysis: Array.from({ length: 15 }, (_, index) => ({ title: `Alert trend ${index}`, sourceMetric: 'alerts' })),
                        evidenceUsed: [], evidenceGaps: [], missingDataWarnings: [], assumptions: [], confidenceScore: 0.9
                    },
                    requestSizeBytes: 20000, responseSizeBytes: 1000, usage: { input_tokens: 5000, output_tokens: 300, total_tokens: 5300 }
                };
            }
        },
        logger: { info() {}, warn() {}, error() {} }, wait: async () => {},
        config: { domainDelayMs: 0, maxInputBytes: 500000, maxItemsPerBatch: 750 }
    });
    const result = await service.runEnterpriseReport({ companyId: 1, snapshotId: 1200, domainKeys: ['security_alerts'], includeSynthesis: false });
    const finding = result.domains[0].analysis.keyFindings[0];
    assert.equal(result.domains[0].status, 'completed');
    assert.ok(result.domains[0].analysis.evidenceLimitations.recordsPrepared < 150);
    assert.ok(result.domains[0].analysis.evidenceLimitations.recordsSent < 150);
    assert.equal(result.domains[0].analysis.evidenceLimitations.recordsOmitted, 0);
    assert.ok(packages[0].compactEvidenceSummary.strictCompactSecurityAlertsPackage);
    assert.equal(packages[0].batchMetadata.totalBatches, 1);
    assert.ok(packages[0].evidence.length < 80);
    assert.ok(packages[0].evidenceGroups.summaryMetrics.length >= 1);
    assert.ok(packages[0].evidenceGroups.criticalAlerts.length <= 10);
    assert.ok(packages[0].evidenceGroups.highSeverityAlerts.length <= 10);
    assert.ok(packages[0].evidenceGroups.repeatedAlertPatterns.length <= 10);
    assert.ok(packages[0].evidenceGroups.threatIndicators.length > 0);
    assert.ok(packages[0].evidenceGroups.threatIndicators.some(row => row.data?.internalOnly === true));
    assert.ok(packages[0].evidenceGroups.threatIndicators.every(row =>
        ['IPAddress', 'URL', 'Domain', 'FileHash', 'SenderAddress'].includes(row.data?.indicatorType)
    ));
    assert.doesNotMatch(JSON.stringify(packages[0].sourceHealth.warnings), /threat_indicators_unavailable/);
    assert.equal(result.domains[0].analysis.keyFindings.length, 5);
    assert.equal(result.domains[0].analysis.risks.length, 5);
    assert.equal(result.domains[0].analysis.recommendations.length, 5);
    assert.doesNotMatch(JSON.stringify(result.domains[0].analysis.risks), /No critical alerts detected/);
    assert.ok(finding.description.length <= 520);
    assert.ok(prompts.length <= 2);
    assert.match(prompts[0], /Return valid JSON only/);
    assert.match(prompts[0], /summaryMetrics, criticalAlerts, highSeverityAlerts/);
    assert.match(prompts[0], /risks max 5/);
});

test('Security Alerts adapter uses actual evidence freshness timestamp', async () => {
    const pool = {
        async query(sql, params) {
            if (/CompanyMicrosoftMapping/i.test(sql)) return [[{ MicrosoftTenantID: 1 }], []];
            if (/IsComplete\s*=\s*1[\s\S]*CollectionStatus\s+IN/i.test(sql)) {
                return [[{
                    ID: 990,
                    CompanyID: params?.[0] || 1,
                    IsComplete: 1,
                    CollectionStatus: 'complete',
                    CollectedAt: '2026-06-25T08:00:00.000Z',
                    SourceFetchedAt: '2026-06-25T09:30:00.000Z',
                    CreatedAt: '2026-06-25T09:31:00.000Z',
                    EvidenceRecordCount: 1,
                    ExpectedRecordCount: 1,
                    OmittedRecordCount: 0,
                    DashboardMetricsJson: { totalAlerts: 1, highSeverityAlerts: 1 }
                }], []];
            }
            if (/FROM StackCTRLSecurityEvidence\s+WHERE SnapshotID/i.test(sql)) {
                return [[{
                    ID: 1,
                    SnapshotID: 990,
                    EvidenceKind: 'alert',
                    ProcessedEvidenceJson: { id: 'alert-1', title: 'Risky sign-in alert', severity: 'high' }
                }], []];
            }
            return [[], []];
        }
    };
    const result = await securityAlertsAdapter({
        pool,
        companyId: 1,
        capability: {
            sourceKey: 'security_alerts',
            displayName: 'Security Alerts',
            isExpected: true,
            isEnabled: true,
            profileKey: 'sunbird',
            refreshMode: 'stored_only',
            freshnessThresholdMinutes: 120
        }
    });

    assert.equal(result.freshness.lastUpdated, '2026-06-25T09:30:00.000Z');
    assert.equal(result.sourceLineage.sourceFetchedAt, '2026-06-25T09:30:00.000Z');
    assert.equal(result.sourceLineage.sourceLastUpdated, '2026-06-25T09:30:00.000Z');
});

test('Security Alerts adapter surfaces latest failed collection error', async () => {
    const pool = {
        async query(sql) {
            if (/CompanyMicrosoftMapping/i.test(sql)) return [[{ MicrosoftTenantID: 1 }], []];
            if (/IsComplete\s*=\s*1[\s\S]*CollectionStatus\s+IN/i.test(sql)) return [[], []];
            if (/FROM StackCTRLSecurityEvidenceSnapshots/i.test(sql)) {
                return [[{
                    ID: 991,
                    CompanyID: 1,
                    IsComplete: 0,
                    CollectionStatus: 'failed',
                    CollectedAt: '2026-06-25T10:00:00.000Z',
                    SourceFetchedAt: '2026-06-25T10:00:00.000Z',
                    EvidenceRecordCount: 0,
                    DashboardMetricsJson: {},
                    IncompleteReason: 'Security evidence collection did not complete.',
                    ErrorMessage: 'Microsoft Graph security alerts endpoint returned 403'
                }], []];
            }
            return [[], []];
        }
    };
    const result = await securityAlertsAdapter({
        pool,
        companyId: 1,
        capability: {
            sourceKey: 'security_alerts',
            displayName: 'Security Alerts',
            isExpected: true,
            isEnabled: true,
            profileKey: 'sunbird',
            refreshMode: 'stored_only',
            freshnessThresholdMinutes: 120
        }
    });

    assert.ok(['missing', 'stale'].includes(result.status));
    assert.match(result.errorMessage, /Microsoft Graph security alerts endpoint returned 403/);
    assert.match(result.warnings.join(' '), /Microsoft Graph security alerts endpoint returned 403/);
    assert.equal(result.sourceLineage.evidenceSnapshotId, 991);
    assert.equal(result.sourceLineage.collectionStatus, 'failed');
});

test('Security Alerts stale warning uses stored evidence timestamp', async () => {
    let insertId = 13000;
    const snapshot = {
        ID: 1300,
        CompanyID: 1,
        CreatedAt: new Date('2026-06-26T08:00:00Z'),
        SourceFreshnessJson: JSON.stringify({
            security_alerts: {
                status: 'stale',
                lastUpdated: '2026-06-24T05:16:14.000Z',
                ageMinutes: 2563
            }
        }),
        MetricsJson: '{}',
        ContextJson: JSON.stringify({
            riskEngine: { domainHealthScores: { security: 60 }, domainRiskScores: { security: 40 } },
            sources: [{
                sourceKey: 'security_alerts',
                status: 'available',
                isExpected: true,
                sourceLineage: { evidenceRecordCount: 1, sourceFetchedAt: '2026-06-24T05:16:14.000Z' },
                dashboardMetrics: { totalAlerts: 1, highSeverityAlerts: 1 },
                evidence: [{ evidenceType: 'alerts', data: [{ id: 'alert-1', title: 'High alert', severity: 'high', status: 'active' }] }]
            }]
        })
    };
    const pool = {
        async query(sql) {
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) return [[snapshot], []];
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        schedulerService: { async getHistoricalSnapshotContext() { return { comparisons: {} }; } },
        azureOpenAI: { async createJsonCompletion() { return { data: { domainExecutiveSummary: 'Security alert review.', risks: [], recommendations: [], keyFindings: [], missingDataWarnings: [] } }; } },
        logger: { info() {}, warn() {}, error() {} },
        wait: async () => {},
        config: { domainDelayMs: 0, maxInputBytes: 500000 }
    });

    const result = await service.runEnterpriseReport({ companyId: 1, snapshotId: 1300, domainKeys: ['security_alerts'], includeSynthesis: false });
    const warningText = result.domains[0].analysis.missingDataWarnings.join(' ');
    assert.match(warningText, /Security Alerts evidence is stale; latest stored evidence was used from 2026-06-24T05:16:14\.000Z\./);
    assert.doesNotMatch(warningText, /Security Alerts source_stale/);
});

test('Security Alerts visible output removes nulls and positive observations from risks', () => {
    const domain = ENTERPRISE_DOMAINS.find(item => item.key === 'security_alerts');
    const normalized = normalizeDomainOutputForDisplay({
        domainExecutiveSummary: 'Security alerts are mostly contained.',
        currentPosture: 'No critical alerts detected; high-severity repeated patterns remain under review.',
        risks: [
            { title: 'No critical alerts detected', severity: 'low', sourceMetric: 'summaryMetrics', empty: null },
            {
                title: 'Repeated high-severity Defender alerts',
                severity: 'high',
                sourceMetric: 'repeatedAlertPatterns',
                affectedEntities: [{ userPrincipalName: 'user@example.com', entityType: 'User', sourceMetric: 'repeatedAlertPatterns', unused: null }],
                evidenceRows: [{ title: 'Repeated Defender alert', userPrincipalName: 'user@example.com', severity: 'high', empty: null }]
            }
        ],
        recommendations: [{ title: 'Triage repeated alerts', priority: 'high', sourceMetric: 'repeatedAlertPatterns', empty: null }],
        keyFindings: [{ title: 'High severity alerts are concentrated', sourceMetric: 'highSeverityAlerts', empty: null }]
    }, domain, 1400);

    assert.equal(normalized.risks.length, 1);
    assert.equal(normalized.risks[0].title, 'Repeated high-severity Defender alerts');
    assert.doesNotMatch(JSON.stringify(normalized), /:null/);
});

test('Security Alerts affected entities are matched to the inferred evidence group', () => {
    const domain = ENTERPRISE_DOMAINS.find(item => item.key === 'security_alerts');
    const normalized = ensureItemEvidence({
        title: 'Anonymous IP sign-in pattern',
        severity: 'high',
        recommendation: 'Block or investigate anonymous IP activity.',
        affectedEntities: [{ userPrincipalName: 'wrong-user@example.com', entityType: 'User' }]
    }, domain, 1500, [
        {
            evidenceType: 'anonymousIpEvents',
            sourceMetric: 'anonymousIpEvents',
            internalSourcePath: 'security_alerts.evidence.signIns[0]',
            data: { id: 'sign-in-1', ipAddress: '203.0.113.10', userPrincipalName: 'target@example.com', riskLevel: 'high' }
        },
        {
            evidenceType: 'affectedUsers',
            sourceMetric: 'affectedUsers',
            internalSourcePath: 'security_alerts.evidence.users[0]',
            data: { userPrincipalName: 'wrong-user@example.com', alertCount: 4 }
        }
    ]);

    assert.equal(normalized.sourceMetric, 'anonymousIpEvents');
    assert.equal(normalized.affectedEntities[0].entityType, 'IPAddress');
    assert.equal(normalized.affectedEntities[0].ipAddress, '203.0.113.10');
    assert.equal(normalized.evidenceRows[0].sourceMetric, 'anonymousIpEvents');
});

test('Security Alerts Power BI flattening keeps risk, recommendation, entity, and evidence rows', () => {
    const service = createEnterpriseIntelligenceService({ pool: {}, azureOpenAI: {}, schedulerService: {} });
    const tables = service.flattenPowerBITables({
        domains: [{
            companyId: 1,
            snapshotId: 1600,
            runId: 160,
            domainKey: 'security_alerts',
            domainName: 'Security Alerts',
            periodType: 'daily',
            periodStart: '2026-06-26',
            periodEnd: '2026-06-26',
            tokenUsage: {},
            intelligenceOutput: {
                risks: [{
                    riskId: 'security-risk-1',
                    title: 'Anonymous IP sign-in pattern',
                    severity: 'high',
                    sourceDomain: 'security_alerts',
                    sourceMetric: 'anonymousIpEvents',
                    affectedEntities: [{ entityId: '203.0.113.10', entityName: '203.0.113.10', entityType: 'IPAddress', sourceMetric: 'anonymousIpEvents' }],
                    evidenceRows: [{ entityId: 'sign-in-1', entityName: '203.0.113.10', entityType: 'IPAddress', sourceMetric: 'anonymousIpEvents' }]
                }],
                recommendations: [{
                    recommendationId: 'security-rec-1',
                    title: 'Investigate anonymous IP activity',
                    priority: 'high',
                    sourceDomain: 'security_alerts',
                    sourceMetric: 'anonymousIpEvents',
                    affectedEntities: [{ entityId: '203.0.113.10', entityName: '203.0.113.10', entityType: 'IPAddress', sourceMetric: 'anonymousIpEvents' }],
                    evidenceRows: [{ entityId: 'sign-in-1', entityName: '203.0.113.10', entityType: 'IPAddress', sourceMetric: 'anonymousIpEvents' }]
                }]
            }
        }]
    });

    assert.equal(tables.RiskRegisterRows.length, 1);
    assert.equal(tables.RecommendationRows.length, 1);
    assert.equal(tables.AffectedEntityRows.length, 2);
    assert.equal(tables.EvidenceRows.length, 2);
});

function scheduledIdentitySnapshot(id = 1501) {
    return {
        ID: id,
        CompanyID: 1,
        TenantKey: 'sunbird',
        SnapshotType: 'enterprise_pipeline',
        CreatedAt: new Date('2026-08-13T00:00:00.000Z'),
        DataCompletenessScore: 100,
        MetricsJson: JSON.stringify({
            stackctrl_risk: {
                domainHealthScores: { identity: 90 },
                domainRiskScores: { identity: 10 }
            }
        }),
        ContextJson: JSON.stringify({
            riskEngine: {
                domainHealthScores: { identity: 90 },
                domainRiskScores: { identity: 10 }
            },
            sources: [{
                sourceKey: 'identity',
                status: 'available',
                isExpected: true,
                metrics: { totalUsers: 1 },
                evidence: [{ evidenceType: 'users', data: [{ id: 'user-1', displayName: 'Test User' }] }]
            }]
        })
    };
}

function createScheduledPipelineFixture({
    snapshot = scheduledIdentitySnapshot(),
    snapshotError = null,
    azureError = null,
    duplicate = false,
    activeRun = null
} = {}) {
    const events = [];
    const writes = [];
    let insertId = 2000;
    let finalizationCount = 0;
    const pool = {
        async query(sql, params = []) {
            writes.push({ sql, params });
            if (sql.includes('INSERT INTO StackCTRLEnterpriseReportRuns')) {
                events.push('pipeline_claimed');
                if (duplicate) {
                    const error = new Error('duplicate');
                    error.code = 'ER_DUP_ENTRY';
                    throw error;
                }
                return [{ insertId: 1901 }, []];
            }
            if (sql.includes('SELECT ID, SnapshotID, Status, PeriodType, Mode, StartedAt') && sql.includes("Status IN ('queued', 'running')")) {
                return [activeRun ? [activeRun] : [], []];
            }
            if (sql.includes('SELECT ID, SnapshotID, Status') && sql.includes('DeduplicationKey')) {
                return [[{ ID: 1901, SnapshotID: snapshot.ID, Status: 'completed' }], []];
            }
            if (sql.includes('FROM StackCTRLTenantEvidenceSnapshots WHERE')) {
                events.push('snapshot_verified');
                return [[snapshot], []];
            }
            if (sql.includes('FROM StackCTRLKnowledgeBase')) return [[], []];
            if (sql.includes('FROM StackCTRLTenantDomainIntelligence') && sql.includes('RunID <>')) return [[], []];
            if (/^\s*INSERT/i.test(sql)) return [{ insertId: insertId++ }, []];
            return [{ affectedRows: 1 }, []];
        }
    };
    const service = createEnterpriseIntelligenceService({
        pool,
        intelligenceService: {
            async createSnapshot() {
                events.push('snapshot_created');
                if (snapshotError) throw snapshotError;
                return { snapshotId: snapshot.ID, companyId: 1 };
            }
        },
        schedulerService: {
            async getHistoricalSnapshotContext() {
                return { comparisons: {} };
            }
        },
        azureOpenAI: {
            async createJsonCompletion() {
                events.push('analysis_executed');
                if (azureError) throw azureError;
                return { data: domainResponse('identity'), requestSizeBytes: 1200, responseSizeBytes: 2400, retryCount: 0, usage: { input_tokens: 500, output_tokens: 250, total_tokens: 750 } };
            }
        },
        onScheduledRunCompleted: async ({ run, duplicateTrigger }) => {
            events.push(duplicateTrigger ? 'duplicate_finalization_checked' : 'report_persisted');
            if (!duplicateTrigger) finalizationCount += 1;
            return {
                status: duplicateTrigger ? 'duplicate' : 'completed',
                reportId: 3001,
                runId: run.runId,
                snapshotId: run.snapshotId
            };
        },
        onCompletedEnterpriseRun: async ({ run }) => {
            events.push('manual_report_persisted');
            return { status: 'completed', reportId: 3002, runId: run.runId, snapshotId: run.snapshotId };
        },
        logger: { info() {}, warn() {}, error() {} },
        wait: async () => {},
        config: { domainDelayMs: 0, maxRetries: 0 }
    });
    return { service, events, writes, getFinalizationCount: () => finalizationCount };
}

test('an active enterprise run is returned immediately without creating a second run', async () => {
    const fixture = createScheduledPipelineFixture({
        activeRun: { ID: 133, SnapshotID: null, Status: 'running', PeriodType: 'daily', Mode: 'enterprise_deep_reporting' }
    });
    const result = await fixture.service.runEnterpriseReport({
        companyId: 1,
        domainKeys: ['identity'],
        includeSynthesis: false,
        refreshSnapshot: true
    });

    assert.equal(result.status, 'already_running');
    assert.equal(result.runId, 133);
    assert.equal(result.snapshotId, null);
    assert.equal(fixture.events.includes('snapshot_created'), false);
    assert.equal(fixture.writes.some(call => call.sql.includes('INSERT INTO StackCTRLEnterpriseReportRuns')), false);
});

test('a completed manual enterprise run automatically publishes its report record', async () => {
    const fixture = createScheduledPipelineFixture();
    const result = await fixture.service.runEnterpriseReport({
        companyId: 1, snapshotId: 1501, domainKeys: ['identity'], includeSynthesis: false,
        refreshSnapshot: false, publishReport: true
    });
    assert.equal(result.status, 'completed');
    assert.equal(result.reportAutomation.reportId, 3002);
    assert.ok(fixture.events.includes('manual_report_persisted'));
});

test('scheduled enterprise pipeline creates and verifies a fresh snapshot before analysis and report persistence', async () => {
    const fixture = createScheduledPipelineFixture();
    const result = await fixture.service.runScheduledTick({
        now: new Date('2026-08-13T00:00:00.000Z'),
        companyId: 1,
        cadence: 'daily',
        domainKeys: ['identity'],
        includeSynthesis: false,
        finalizeReport: true
    });

    assert.equal(result.status, 'completed');
    assert.deepEqual(
        fixture.events.filter(event => ['snapshot_created', 'snapshot_verified', 'analysis_executed', 'report_persisted'].includes(event)),
        ['snapshot_created', 'snapshot_verified', 'analysis_executed', 'report_persisted']
    );
    assert.equal(result.companies[0].runs[0].snapshotId, 1501);
    assert.equal(result.companies[0].runs[0].reportAutomation.reportId, 3001);
    assert.equal(fixture.getFinalizationCount(), 1);
    const snapshotBindingWrite = fixture.writes.find(call => call.sql.includes('SET SnapshotID = ?, ProgressJson = ?'));
    assert.ok(snapshotBindingWrite, 'fresh snapshot must be atomically bound to the running enterprise run');
    assert.equal(snapshotBindingWrite.params[0], 1501);
    assert.equal(snapshotBindingWrite.params.at(-2), 1901);

    const persistedPhases = fixture.writes
        .filter(call => call.sql.includes('ProgressJson = ?'))
        .flatMap(call => call.params)
        .filter(value => typeof value === 'string' && value.startsWith('{'))
        .map(value => JSON.parse(value).phase)
        .filter(Boolean);
    for (const phase of ['SNAPSHOT_CREATED', 'ANALYSIS_STARTED', 'ANALYSIS_COMPLETED', 'PIPELINE_COMPLETED']) {
        assert.ok(persistedPhases.includes(phase), `Expected persisted phase ${phase}`);
    }
});

test('scheduled enterprise pipeline stops after snapshot failure and persists the failure stage', async () => {
    const fixture = createScheduledPipelineFixture({ snapshotError: new Error('snapshot source unavailable') });
    const result = await fixture.service.runScheduledTick({
        now: new Date('2026-08-13T00:00:00.000Z'),
        companyId: 1,
        cadence: 'daily',
        domainKeys: ['identity'],
        includeSynthesis: false,
        finalizeReport: true
    });

    assert.equal(result.status, 'failed');
    assert.equal(fixture.events.includes('analysis_executed'), false);
    assert.equal(fixture.events.includes('report_persisted'), false);
    const failureWrite = fixture.writes.find(call =>
        call.sql.includes('ProgressJson = ?') &&
        call.params.some(param => typeof param === 'string' && param.includes('SNAPSHOT_CREATION_FAILED'))
    );
    assert.ok(failureWrite);
    const terminalRunWrite = fixture.writes.find(call => call.sql.includes("SET Status = ?, CompletedAt = NOW(), ErrorMessage = ?, ProgressJson = ?"));
    assert.ok(terminalRunWrite, 'snapshot failure must record a terminal run status');
    assert.notEqual(terminalRunWrite.params[0], 'running');

});

test('collector timeout produces a terminal failed run with snapshot failure progress', async () => {
    const timeout = new Error('backup collector exceeded 180000ms');
    timeout.code = 'STACKCTRL_COLLECTOR_TIMEOUT';
    const fixture = createScheduledPipelineFixture({ snapshotError: timeout });
    const result = await fixture.service.runScheduledTick({
        now: new Date('2026-08-13T00:00:00.000Z'), companyId: 1, cadence: 'daily', domainKeys: ['identity'], includeSynthesis: false, finalizeReport: true
    });
    assert.equal(result.status, 'failed');
    const terminal = fixture.writes.find(call => call.sql.includes('SET Status = ?, CompletedAt = NOW(), ErrorMessage = ?, ProgressJson = ?'));
    assert.ok(terminal, 'collector timeout must set a terminal status and completion timestamp');
    const progress = JSON.parse(terminal.params[2]);
    assert.equal(progress.failureStage, 'SNAPSHOT_CREATION_FAILED');
    assert.match(progress.error, /backup collector exceeded/);
});

test('scheduled enterprise pipeline reports analysis failure and does not publish a report', async () => {
    const fixture = createScheduledPipelineFixture({ azureError: new Error('Azure analysis failed') });
    const result = await fixture.service.runScheduledTick({
        now: new Date('2026-08-13T00:00:00.000Z'),
        companyId: 1,
        cadence: 'daily',
        domainKeys: ['identity'],
        includeSynthesis: false,
        finalizeReport: true
    });

    assert.equal(result.status, 'failed');
    assert.equal(fixture.events.includes('snapshot_created'), true);
    assert.equal(fixture.events.includes('analysis_executed'), true);
    assert.equal(fixture.events.includes('report_persisted'), false);
    assert.equal(result.companies[0].runs[0].pipelineFailure.failureStage, 'ENTERPRISE_DEEP_ANALYSIS_FAILED');
});

test('duplicate scheduled delivery reuses the existing run without another snapshot or analysis', async () => {
    const fixture = createScheduledPipelineFixture({ duplicate: true });
    const result = await fixture.service.runScheduledTick({
        now: new Date('2026-08-13T00:00:00.000Z'),
        companyId: 1,
        cadence: 'daily',
        domainKeys: ['identity'],
        includeSynthesis: false,
        finalizeReport: true
    });

    assert.equal(result.status, 'completed');
    assert.equal(result.companies[0].runs[0].status, 'duplicate');
    assert.equal(fixture.events.includes('snapshot_created'), false);
    assert.equal(fixture.events.includes('analysis_executed'), false);
    assert.equal(fixture.events.includes('duplicate_finalization_checked'), true);
    assert.equal(fixture.getFinalizationCount(), 0);
});

test('manual Enterprise Deep Analysis still uses an explicitly selected snapshot without creating another one', async () => {
    const fixture = createScheduledPipelineFixture();
    const result = await fixture.service.runEnterpriseReport({
        companyId: 1,
        snapshotId: 1501,
        domainKeys: ['identity'],
        includeSynthesis: false,
        refreshSnapshot: false
    });

    assert.equal(result.status, 'completed');
    assert.equal(result.snapshotId, 1501);
    assert.equal(fixture.events.includes('snapshot_created'), false);
    assert.equal(fixture.events.includes('snapshot_verified'), true);
    assert.equal(fixture.events.includes('analysis_executed'), true);
});
