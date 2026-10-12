const test = require('node:test');
const assert = require('node:assert/strict');

const { extractInternalThreatIndicators } = require('../services/intelligence/security-dashboard-source');
const {
    getExplicitSecurityIocs,
    getMicrosoftThreatIndicatorIocs,
    normalizeTypedSecurityIoc
} = require('../services/intelligence/security-ioc');
const { securityAlertsAdapter } = require('../services/intelligence/source-adapters');

test('explicit IOC extraction ignores titles, users, descriptions, and invalid fallback hashes', () => {
    const indicators = extractInternalThreatIndicators({
        alerts: [{
            title: 'Anonymous IP address alert contains 203.0.113.99 and malware',
            description: 'Hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            userPrincipalName: 'person@example.com',
            category: 'ThreatManagement',
            fileHash: 'Extracted from Security Alerts evidence because external threat indicators were unavailable.',
            ipAddress: '203.0.113.8'
        }]
    });

    assert.deepEqual(indicators.map(item => [item.indicatorType, item.indicator]), [
        ['IPAddress', '203.0.113.8']
    ]);
    assert.equal(indicators[0].confidence, 'medium');
});

test('explicit IOC extraction validates observable formats and only accepts designated IOC fields', () => {
    const iocs = getExplicitSecurityIocs({
        ipAddress: 'not-an-ip',
        url: 'https://bad.example.test/path',
        senderDomain: 'bad.example.test',
        sha256: 'A'.repeat(64),
        userPrincipalName: 'user@bad.example.test',
        title: 'https://title-only.example.test'
    });

    assert.deepEqual(iocs, [
        { type: 'URL', value: 'https://bad.example.test/path', sourceField: 'url' },
        { type: 'Domain', value: 'bad.example.test', sourceField: 'senderDomain' },
        { type: 'FileHash', value: 'a'.repeat(64), sourceField: 'sha256' }
    ]);
});

test('Microsoft Graph threat indicators require a valid observable and never become Unknown placeholders', () => {
    assert.deepEqual(getMicrosoftThreatIndicatorIocs({}), []);
    assert.deepEqual(getMicrosoftThreatIndicatorIocs({ fileHashValue: 'not-a-hash' }), []);
    assert.deepEqual(
        getMicrosoftThreatIndicatorIocs({ networkIPv4: '203.0.113.9', fileHashValue: 'a'.repeat(64) }),
        [
            { type: 'IPAddress', value: '203.0.113.9' },
            { type: 'FileHash', value: 'a'.repeat(64) }
        ]
    );
});

test('stored Security Alerts removes legacy non-IOC and placeholder indicator rows', async () => {
    const snapshot = {
        ID: 55,
        CompanyID: 1,
        IsComplete: 1,
        CollectionStatus: 'complete',
        CollectedAt: '2026-10-12T08:00:00.000Z',
        SourceFetchedAt: '2026-10-12T08:00:00.000Z',
        EvidenceRecordCount: 3,
        ExpectedRecordCount: 3,
        OmittedRecordCount: 0,
        DashboardMetricsJson: {}
    };
    const evidence = [
        { EvidenceKind: 'threat_indicator', ProcessedEvidenceJson: { indicatorType: 'UserPrincipalName', indicator: 'user@example.com' } },
        { EvidenceKind: 'threat_indicator', ProcessedEvidenceJson: { indicatorType: 'FileHash', indicator: 'Extracted from Security Alerts evidence because external threat indicators were unavailable.' } },
        { EvidenceKind: 'threat_indicator', ProcessedEvidenceJson: { indicatorType: 'IPAddress', indicator: '203.0.113.8' } }
    ];
    const pool = {
        async query(sql) {
            if (/CompanyMicrosoftMapping/i.test(sql)) return [[{ MicrosoftTenantID: 1 }], []];
            if (/FROM StackCTRLSecurityEvidenceSnapshots/i.test(sql)) return [[snapshot], []];
            if (/FROM StackCTRLSecurityEvidence\s+WHERE SnapshotID/i.test(sql)) return [evidence, []];
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
    const indicatorEvidence = result.evidence.find(item => item.evidenceType === 'threatIndicators');

    assert.deepEqual(indicatorEvidence.data.map(item => item.indicator), ['203.0.113.8']);
    assert.equal(normalizeTypedSecurityIoc('ThreatKeyword', 'Anonymous IP address'), null);
});
