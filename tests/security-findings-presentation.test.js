const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('js/clientportal.js', 'utf8');
function extract(name) {
    const start = source.indexOf(`function ${name}(`);
    assert.notEqual(start, -1, `Missing ${name}`);
    const next = source.indexOf('\nfunction ', start + 1);
    const nextAsync = source.indexOf('\nasync function ', start + 1);
    const end = [next, nextAsync].filter(index => index !== -1).sort((a, b) => a - b)[0];
    return source.slice(start, end);
}
const names = [
    'sunbirdSecurityFindingSource', 'normalizeSunbirdSecurityGroupingText',
    'sunbirdSecurityFindingProviderIdentity', 'sunbirdSecurityFindingExplanatorySignature',
    'sunbirdSecurityFindingCorrelationState', 'groupSunbirdSecurityFindings',
    'sunbirdSecurityFindingGroupTitle', 'sunbirdSecurityFindingGroupLimitation',
    'sunbirdSecurityFindingObservation', 'sunbirdSecurityFindingEventTime', 'sunbirdSecurityFindingPrimaryEntity', 'sunbirdSecuritySeverityClass',
    'getSunbirdSecurityFindingById', 'renderSunbirdSecurityEvidenceDetails',
    'renderSunbirdSecurityFindings', 'renderSunbirdSecurityAlertsOverview', 'renderSunbirdSecurityBillingSummary',
    'renderSunbirdSecurityAiAssessmentSection', 'renderSunbirdSecurityDetailList', 'renderSunbirdSecurityFindingDetail'
];
const context = vm.createContext({
    sunbirdSecurityEscape: (value, fallback = 'Not recorded') => String(value ?? fallback).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'),
    sunbirdSecurityDisplayText: (value, fallback = 'Not recorded') => String(value || fallback),
    sunbirdSecurityStatusLabel: (value, fallback = 'Not recorded') => String(value || fallback).replace(/_/g, ' '),
    sunbirdSecurityStatusClass: () => 'neutral',
    sunbirdSecurityReadableSourceLabel: value => String(value || 'Source not recorded'),
    sunbirdSecurityFormatTime: value => String(value || 'Not recorded'),
    sunbirdSecurityEntityLabels: entities => (entities?.users || []).map(label => ({ type: 'User', label })),
    getSunbirdSecurityIntegrationSources: () => []
});
vm.runInContext(names.map(extract).join('\n'), context);

test('outer card lists all findings, including Cloudflare, without raw events', () => {
    const findings = [
        { title: 'Identity risk', affectedEntities: { users: ['person@example.test'] }, status: 'correlated' },
        { title: 'Cloudflare event', evidence: [{ sourceType: 'cloudflare_alert' }], status: 'needs_investigation' },
        { title: '<unsafe>', status: 'needs_investigation' }
    ];
    const html = context.renderSunbirdSecurityBillingSummary({ findings, alerts: [{ title: 'Raw event' }], summary: {} });
    assert.match(html, /Identity risk/);
    assert.match(html, /person@example\.test/);
    assert.match(html, /Cloudflare event/);
    assert.match(html, /&lt;unsafe&gt;/);
    assert.doesNotMatch(html, /Raw event/);
    assert.match(html, /3 total/);
});

test('alerts overview stays compact and links to detail without inline evidence dumps', () => {
    const findings = [{
        id: 'alert-1',
        title: 'Risky sign-in',
        aiSummary: 'person@example.com signed in while Microsoft marks the account risky.',
        severity: 'high',
        status: 'correlated',
        recommendedAction: 'Verify the sign-in.',
        affectedEntities: { users: ['person@example.com'] },
        evidence: [{ sourceType: 'sign_in', summary: 'Hidden until detail', sourceId: 'si-1' }]
    }];
    const html = context.renderSunbirdSecurityAlertsOverview(findings, {});
    assert.match(html, /person@example.com signed in/);
    assert.match(html, /View details/);
    assert.match(html, /openSunbirdSecurityFindingDetail/);
    assert.doesNotMatch(html, /Hidden until detail/);
});

test('alert detail keeps assessment, rationale, action, evidence, and limitations separate from the overview', () => {
    const finding = {
        id: 'alert-1', title: 'Risky sign-in', severity: 'high', confidence: 'high', confidenceReason: 'Matching identity evidence.',
        status: 'needs_investigation', sourceSeverity: 'medium', recommendedAction: 'Verify the sign-in with the account owner.',
        affectedEntities: { users: ['person@example.com'] }, evidence: [{ sourceType: 'sign_in', sourceId: 'si-1', eventTime: '2026-10-20T10:00:00.000Z', summary: 'Successful sign-in' }],
        aiAssessment: {
            whatHappened: 'A successful sign-in matched a risky-user record.', reasoning: 'The provider records cite the same identity.',
            supportingEvidence: ['Risky-user record'], limitations: ['Device context was unavailable']
        }
    };
    const html = context.renderSunbirdSecurityFindingDetail(finding, { findings: [finding] });
    assert.match(html, /AI assessment/);
    assert.match(html, /Why the AI reached this conclusion/);
    assert.match(html, /Recommended next step/);
    assert.match(html, /Evidence and source records/);
    assert.match(html, /Limitations and unknowns/);
    assert.match(html, /Back to alerts/);
});

test('dashboard keeps each finding and every cited evidence reference accessible', () => {
    const findings = [{ title: 'Cloudflare event', detectionId: 'cloudflare_event', status: 'needs_investigation',
        evidence: [{ sourceType: 'cloudflare_alert', summary: 'First evidence', sourceId: 'cf-1' },
            { sourceType: 'cloudflare_alert', summary: 'Second evidence', sourceId: 'cf-2' }] }];
    const html = context.renderSunbirdSecurityFindings(findings, {});
    assert.match(html, /<details class="sunbird-security-finding-series"/);
    assert.match(html, /Cloudflare event/);
    assert.match(html, /First evidence/);
    assert.match(html, /Second evidence/);
    assert.match(html, /cf-1/);
    assert.match(html, /cf-2/);
});

test('empty state distinguishes incomplete coverage from a clean result', () => {
    const html = context.renderSunbirdSecurityBillingSummary({ findings: [], scenarioCoverage: { identity: { status: 'partial' } } });
    assert.match(html, /limited or unavailable/);
    assert.doesNotMatch(html, /Current findings/);
});

test('empty correlated layer directs operators to raw provider evidence without calling it clean', () => {
    const html = context.renderSunbirdSecurityAlertsOverview([], {
        rawEvidence: { displayedRecordCount: 4 },
        allEvents: [{}, {}, {}, {}],
        scenarioCoverage: { identity: { status: 'complete' } }
    });
    assert.match(html, /No correlated finding generated/);
    assert.match(html, /4 raw provider records/);
    assert.match(html, /View raw provider evidence/);
    assert.doesNotMatch(html, /clean result/i);
});

test('security shell names the two evidence layers explicitly', () => {
    assert.match(source, /Correlated findings &amp; AI assessment/);
    assert.match(source, /Raw provider evidence/);
    assert.match(source, /Raw provider activity does not automatically create a finding or AI summary/);
    assert.match(source, /sunbird-security-raw-evidence-header/);
});

test('raw evidence header keeps Cloudflare counts and the last evaluation time when collection is partial', () => {
    const target = { innerHTML: '' };
    const headerContext = vm.createContext({
        document: { getElementById: id => id === 'sunbird-security-raw-evidence-header' ? target : null },
        sunbirdSecurityEscape: value => String(value ?? ''),
        sunbirdSecurityStatusClass: value => String(value || ''),
        sunbirdSecurityStatusLabel: value => String(value || '').replace(/_/g, ' '),
        sunbirdSecurityFormatTime: value => `formatted:${value}`
    });
    vm.runInContext(extract('renderSunbirdSecurityRawEvidenceHeader'), headerContext);
    headerContext.renderSunbirdSecurityRawEvidenceHeader({
        allEvents: [{}],
        rawEvidence: {
            displayedRecordCount: 1,
            rawEvidenceUpdatedAt: '2026-10-30T12:15:00Z',
            correlationEvaluatedAt: '2026-10-30T12:00:00Z',
            correlationStatus: 'awaiting_next_evaluation',
            cloudflare: { status: 'partial', recordsReturned: 1, reason: 'Audit permission is unavailable.' }
        }
    });
    assert.match(target.innerHTML, /1 retained raw Cloudflare record/);
    assert.match(target.innerHTML, /Cloudflare collection is partial/);
    assert.match(target.innerHTML, /Last evaluated formatted:2026-10-30T12:00:00Z/);
    assert.match(target.innerHTML, /awaiting the next correlation and AI evaluation/);
});

test('a failed cached request falls back to live data and errors if both fail', async () => {
    const start = source.indexOf('async function fetchSunbirdSecurityEventsData(');
    const end = source.indexOf('\nasync function ', start + 1);
    const calls = [];
    const fetchContext = vm.createContext({
        localStorage: { getItem: () => 'token' },
        normalizeSunbirdSecurityData: data => data,
        fetch: async endpoint => {
            calls.push(endpoint);
            if (endpoint.includes('/db/')) throw new Error('cache unavailable');
            return { ok: true, json: async () => ({ success: true, findings: [{ title: 'Live finding' }] }) };
        }
    });
    vm.runInContext(source.slice(start, end), fetchContext);
    const result = await fetchContext.fetchSunbirdSecurityEventsData();
    assert.equal(result.findings[0].title, 'Live finding');
    assert.deepEqual(calls, ['/api/db/security-events', '/api/security-events']);
    fetchContext.fetch = async () => { throw new Error('network unavailable'); };
    await assert.rejects(fetchContext.fetchSunbirdSecurityEventsData(), /Security events data unavailable: network unavailable/);
});

test('Cloudflare provider and resource are identifiable and mobile excludes raw events', () => {
    const mobileContext = vm.createContext({
        isSunbirdUser: () => true,
        sunbirdSecurityDisplayText: (value, fallback = '') => String(value || fallback),
        sunbirdSecurityReadableSourceLabel: value => value
    });
    vm.runInContext(['sunbirdSecurityEntityLabels', 'sunbirdSecurityFindingSource', 'getPortalMobileAlertItems'].map(extract).join('\n'), mobileContext);
    const finding = { title: 'Cloudflare finding', source: 'Cloudflare', affectedEntities: { resources: ['example.test'] }, evidence: [{ sourceType: 'security_alert', details: { sourceSystem: 'Cloudflare' } }] };
    assert.equal(mobileContext.sunbirdSecurityEntityLabels(finding.affectedEntities)[0].label, 'example.test');
    assert.equal(mobileContext.sunbirdSecurityFindingSource(finding), 'Cloudflare');
    const items = mobileContext.getPortalMobileAlertItems({ findings: [finding], activityFeed: [{ title: 'Raw event' }], incidents: [{ title: 'Raw incident' }] });
    assert.equal(items.length, 1);
    assert.equal(items[0].source, 'Cloudflare');
    assert.equal(items[0].title, 'Cloudflare finding');
});
