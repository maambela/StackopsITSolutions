const test = require('node:test');
const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const PDFDocument = require('pdfkit');
const { encodeCanonicalSnapshot, decodeCanonicalSnapshot } = require('../scripts/canonical-tenant-snapshot-prototype');
const { buildCompactIntelligenceContext } = require('../services/intelligence/compact-context-builder');
const { createStackCTRLIntelligenceScheduler } = require('../services/intelligence/scheduler');
const { createEnterpriseIntelligenceService } = require('../services/enterprise-intelligence');
const { hydrateTenantSnapshot } = require('../services/intelligence/tenant-snapshot-storage');

const scope = { companyId: 7, tenantKey: 'fixture-tenant' };
const timestamp = '2026-11-28T10:00:00.000Z';
const markerKey = '$stackctrlSnapshotStorage';
const encode = row => encodeCanonicalSnapshot(row, scope);
const decode = row => decodeCanonicalSnapshot(row, scope);

function fixture(count = 4, targetBytes) {
    const users = Array.from({ length: count }, (_, i) => ({ id: `user-${i}`, displayName: `Test user ${i}`,
        userPrincipalName: `user${i}@example.test`, mfaEnabled: i % 2 === 0, riskLevel: 'LOW', notes: 'x'.repeat(targetBytes ? 350 : 8) }));
    const evidence = [{ sourceKey: 'identity', displayName: 'Identity Protection', data: { evidenceType: 'users', data: users } }];
    if (targetBytes) users.at(-1).notes += 'x'.repeat(targetBytes - Buffer.byteLength(JSON.stringify(evidence)));
    const metrics = { identity: { totalUsers: count, mfaCoverage: 50 }, stackctrl_risk: { overallRiskScore: 25 } };
    const freshness = { identity: { status: 'available', lastUpdated: timestamp, ageMinutes: 0 } };
    const context = {
        tenant: { companyId: 7, tenantKey: scope.tenantKey }, period: { generatedAt: timestamp },
        sources: [{ sourceKey: 'identity', displayName: 'Identity Protection', status: 'available', isExpected: true,
            evidence: [evidence[0].data], metrics: metrics.identity, freshness: freshness.identity,
            sourceLineage: { evidenceSnapshotId: 123, sourceFetchedAt: timestamp, isComplete: true },
            rawReference: { table: 'StackCTRLIdentityEvidenceSnapshots', recordId: 123 } }],
        metrics, evidence, dataCompleteness: { score: 100, expectedSources: 1, availableSources: 1 },
        warnings: [], previousIntelligence: [{ ID: 3, ContentJson: { summary: 'Prior frozen output' } }],
        intelligenceSchemaVersion: 3
    };
    return { ID: 209, CompanyID: 7, TenantKey: scope.tenantKey, SnapshotType: 'scheduled_hourly',
        PeriodStart: timestamp, PeriodEnd: timestamp, CreatedAt: timestamp, DataCompletenessScore: 100,
        SourceFreshnessJson: JSON.stringify(freshness), EvidenceJson: JSON.stringify(evidence),
        MetricsJson: JSON.stringify(metrics), ContextJson: JSON.stringify(context) };
}

test('canonical round trip preserves same-row evidence, source payloads, prior intelligence and field order', () => {
    const legacy = fixture();
    const canonical = encode(legacy);
    const stored = JSON.parse(canonical.ContextJson);
    assert.equal(stored[markerKey].version, 1);
    assert.equal(stored.intelligenceSchemaVersion, 3);
    assert.equal(Object.hasOwn(stored, 'evidence'), false);
    assert.equal(Object.hasOwn(stored, 'metrics'), false);
    assert.deepEqual(stored.sources, JSON.parse(legacy.ContextJson).sources);
    assert.deepEqual(stored.previousIntelligence, JSON.parse(legacy.ContextJson).previousIntelligence);
    assert.deepEqual([decode(legacy), decode(canonical), decode(legacy)], [legacy, legacy, legacy]);
    const parsed = { ...legacy, ContextJson: JSON.parse(legacy.ContextJson), EvidenceJson: JSON.parse(legacy.EvidenceJson) };
    assert.deepEqual(decode(encode(parsed)), parsed);
});

test('divergent, missing and incomplete evidence representations retain their old meaning', () => {
    const legacy = fixture();
    const context = JSON.parse(legacy.ContextJson);
    context.evidence = [{ data: 'different frozen evidence' }];
    context.sources[0].status = 'missing';
    context.sources[0].sourceLineage.isComplete = false;
    context.warnings = ['Partial upstream coverage'];
    const divergent = { ...legacy, ContextJson: JSON.stringify(context) };
    const stored = JSON.parse(encode(divergent).ContextJson);
    assert.deepEqual(stored[markerKey].fields, ['metrics']);
    assert.deepEqual(decode(encode(divergent)), divergent);
    assert.deepEqual(hydrateTenantSnapshot(encode(divergent), { ...scope, nativeJsonOrder: false }), divergent);
    delete context.metrics;
    delete context.evidence;
    const absent = { ...legacy, ContextJson: JSON.stringify(context), EvidenceJson: null };
    assert.equal(encode(absent), absent);
    assert.equal(decode(absent), absent);
    const unreadableLegacy = { ...legacy, ContextJson: 'invalid historical JSON' };
    assert.equal(decode(unreadableLegacy), unreadableLegacy);
    assert.equal(hydrateTenantSnapshot(unreadableLegacy, scope), unreadableLegacy);
});

test('production reader reserves only the exact top-level marker and rejects malformed versions', () => {
    const legacy = fixture();
    const context = JSON.parse(legacy.ContextJson);
    context.sources[0][markerKey] = { version: 99, fields: ['evidence'] };
    const nested = { ...legacy, ContextJson: context };
    assert.equal(hydrateTenantSnapshot(nested, scope), nested);
    assert.throws(() => hydrateTenantSnapshot({ ...nested, ContextJson: { ...context, [markerKey]: null } }, scope),
        { code: 'TENANT_SNAPSHOT_INVALID_MARKER' });

    const canonical = encode(nested);
    canonical.ContextJson.tenant = { ...context.tenant, tenantKey: 'other-tenant' };
    assert.throws(() => hydrateTenantSnapshot(canonical, scope), { code: 'TENANT_SNAPSHOT_SCOPE_MISMATCH' });
});

test('canonical decoding rejects wrong tenants, unknown versions, and incomplete projections', () => {
    const row = encode(fixture());
    assert.throws(() => decodeCanonicalSnapshot(row, { companyId: 8 }), /scope mismatch/);
    assert.throws(() => decodeCanonicalSnapshot(row, { ...scope, tenantKey: 'another-tenant' }), /scope mismatch/);
    assert.throws(() => decode({ ...row, EvidenceJson: undefined }), /Missing canonical evidence/);
    const context = JSON.parse(row.ContextJson);
    context[markerKey].version = 2;
    assert.throws(() => decode({ ...row, ContextJson: context }), /Unsupported snapshot storage version/);
    context[markerKey].version = 1;
    context[markerKey].order = ['evidence'];
    assert.throws(() => decode({ ...row, ContextJson: context }), /Invalid snapshot storage marker/);
});

test('real compact AI builder produces equivalent output after hydration', t => {
    t.mock.timers.enable({ apis: ['Date'], now: new Date(timestamp) });
    const legacy = fixture();
    const canonical = encode(legacy);
    const build = snapshot => buildCompactIntelligenceContext({ snapshot });
    const baseline = build(legacy);
    assert.deepEqual(build(decode(canonical)), baseline);
    assert.ok(baseline.evidenceIncludedCount > 0);
    assert.equal(build(canonical).evidenceIncludedCount, 0, 'a legacy reader silently drops evidence without hydration');
});

test('historical scheduler sees identical current and baseline snapshots in a mixed-format fixture', async t => {
    t.mock.timers.enable({ apis: ['Date'], now: new Date(timestamp) });
    const current = fixture();
    const baseline = { ...fixture(2), ID: 208, CreatedAt: '2026-11-27T10:00:00.000Z' };
    async function run(storedCurrent, storedBaseline) {
        const audit = [];
        const scheduler = createStackCTRLIntelligenceScheduler({ intelligenceService: {}, pool: {
            async query(sql, args) {
                if (sql.includes('INSERT INTO StackCTRLIntelligenceHistoricalComparisons')) { audit.push(args); return [{}]; }
                if (sql.includes('WHERE ID = ? AND CompanyID = ?')) {
                    assert.deepEqual(args, [current.ID, scope.companyId]);
                    return [[storedCurrent]];
                }
                if (sql.includes('SELECT MAX(previous.ID)')) return [[storedBaseline]];
                if (sql.includes('MAX(CASE WHEN CreatedAt <=')) return [[{ BeforeTarget: null, AfterTarget: null }]];
                throw new Error(`Unexpected SQL: ${sql}`);
            }
        } });
        return { result: await scheduler.getHistoricalSnapshotContext(scope.companyId, current.ID), audit };
    }
    const legacy = await run(current, baseline);
    assert.equal(legacy.result.comparisons.previous.snapshot.snapshotId, baseline.ID);
    assert.ok(legacy.audit.length > 0);
    assert.deepEqual(await run(encode(current), baseline), legacy);
    assert.deepEqual(await run(current, encode(baseline)), legacy);
});

test('Enterprise package, evidence audit inputs and raw Power BI export retain their frozen data', async () => {
    const legacy = fixture();
    const canonical = encode(legacy);
    async function run(stored) {
        let snapshotReads = 0;
        const service = createEnterpriseIntelligenceService({ azureOpenAI: {}, schedulerService: {}, pool: {
            async query(sql, params) {
                if (!sql.includes('StackCTRLTenantEvidenceSnapshots')) return [[]];
                assert.deepEqual(params, [scope.companyId]);
                snapshotReads++;
                assert.match(sql, /AS EvidenceJson/);
                return [[stored]];
            }
        } });
        const domain = service.domains.find(item => item.key === 'identity');
        const { audit, allEvidence, current } = await service.buildDomainPackage({
            companyId: scope.companyId, snapshot: hydrateTenantSnapshot(stored, { ...scope, nativeJsonOrder: false }),
            runId: 20, domain, historicalContext: { comparisons: {} }
        });
        const raw = await service.getPowerBIRaw(scope.companyId);
        assert.equal(snapshotReads, 1);
        return { audit, allEvidence, current, raw };
    }
    const baseline = await run(legacy);
    assert.equal(baseline.raw.snapshotId, legacy.ID);
    assert.equal(baseline.raw.rawStackCTRLData.sources[0].rawReference.recordId, 123);
    assert.deepEqual(await run(canonical), baseline);
});

test('frozen snapshot inputs produce equivalent report payload, dashboard view and rendered PDF', async t => {
    t.mock.timers.enable({ apis: ['Date'], now: new Date(timestamp) });
    const source = fs.readFileSync(require.resolve('../server'), 'utf8');
    const section = (start, end) => {
        const from = source.indexOf(start);
        const to = source.indexOf(end, from + start.length);
        assert.ok(from >= 0 && to > from);
        return source.slice(from, to);
    };
    const legacy = fixture();
    async function render(stored) {
        const reportContext = JSON.parse(hydrateTenantSnapshot(stored, { ...scope, nativeJsonOrder: false }).ContextJson);
        const source = reportContext.sources[0];
        const domainInsights = { latestRunId: 20, latestSnapshotId: stored.ID, domains: [{
            domainKey: 'identity', domainName: 'Identity Protection', status: 'completed', snapshotId: stored.ID,
            intelligenceOutput: { healthScore: 75, riskScore: 25, domainExecutiveSummary: `${source.metrics.totalUsers} frozen users` }
        }] };
        const functions = vm.runInNewContext([
            section('async function buildSunbirdReportPayload', 'async function loadSunbirdDailyReportSummaries'),
            section('function buildSunbirdDomainBreakdownFromPayload', 'function buildSunbirdLiveIntelligenceSnapshot'),
            section('function formatReportDate', 'function serializeReportListRow'),
            section('function buildSunbirdReportIdentityDomain', 'async function getReportContext'),
            '({ buildSunbirdReportPayload, buildSunbirdLatestReportSnapshot, generateSunbirdReportPdf });'
        ].join('\n'), {
            PDFDocument, Buffer, Date, fs, path, __dirname: path.dirname(require.resolve('../server')), console,
            SUNBIRD_REPORT_TIME_ZONE: 'Africa/Johannesburg',
            clampReportScore: Number, shortText: (value, limit) => String(value || '').slice(0, limit),
            shortMultilineText: (value, limit) => String(value || '').slice(0, limit),
            SUNBIRD_DASHBOARD_MAX_STRING_LENGTH: 1200, compactSunbirdDashboardValue: value => value,
            parseReportJson: JSON.parse,
            loadSunbirdReportEvidence: async () => ({ companyName: 'Fixture company', identity: { SecurityScore: 75 },
                security: {}, email: {}, emailMetrics: {}, backup: {}, devices: {}, applicationsMetrics: {}, applications: {},
                operations: {}, governance: {}, compliance: {}, sourceUpdatedAt: [timestamp] }),
            buildCloudflareReportSignals: () => ({ events: [], problems: [], postureFindings: [], coverageWarnings: [], recommendations: [] }),
            pool: { query: async () => [[]] }, loadSunbirdDailyReportSummaries: async () => [],
            loadSunbirdLatestDailyReportSummary: async () => null,
            fetchSunbirdPowerBIIntelligence: async () => domainInsights,
            fetchSunbirdPowerBIFinal: async () => ({ finalSynthesis: { summary: 'Frozen synthesis' } }),
            buildFinalSynthesisReportAnalysis: () => ({ executiveSummary: 'Frozen report summary' })
        });
        const report = await functions.buildSunbirdReportPayload(7, new Date(timestamp), new Date(timestamp), true, { enterpriseRunId: 20 });
        const payload = JSON.stringify(report);
        const dashboard = JSON.stringify(functions.buildSunbirdLatestReportSnapshot({ ID: 1, Payload: payload }));
        const pdf = await functions.generateSunbirdReportPdf(report, 1);
        assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
        return { payload, dashboard, pdf };
    }
    const baseline = await render(legacy);
    assert.match(baseline.payload, /4 frozen users/);
    assert.deepEqual(await render(encode(legacy)), baseline);
});

test('benchmark records serialized sizes and local encode/decode timings', t => {
    const legacy = fixture(3000, 1756472);
    const canonical = encode(legacy);
    function sizes(row) {
        return Object.fromEntries(['SourceFreshnessJson', 'EvidenceJson', 'MetricsJson', 'ContextJson']
            .map(key => [key, Buffer.byteLength(row[key])]));
    }
    const legacyBytes = sizes(legacy);
    const canonicalBytes = sizes(canonical);
    const sum = values => Object.values(values).reduce((a, b) => a + b, 0);
    assert.equal(legacyBytes.EvidenceJson, 1756472);
    assert.deepEqual(decode(canonical), legacy);
    function medianMs(fn) {
        for (let i = 0; i < 3; i++) fn();
        const values = Array.from({ length: 15 }, () => {
            const start = performance.now();
            fn();
            return performance.now() - start;
        }).sort((a, b) => a - b);
        return Number(values[7].toFixed(2));
    }
    t.diagnostic(JSON.stringify({
        legacyBytes, canonicalBytes, legacyTotal: sum(legacyBytes), canonicalTotal: sum(canonicalBytes),
        saved: sum(legacyBytes) - sum(canonicalBytes),
        legacyContextSerializationMs: medianMs(() => JSON.stringify(JSON.parse(legacy.ContextJson))),
        canonicalEncodeMs: medianMs(() => encode(legacy)), canonicalDecodeMs: medianMs(() => decode(canonical)),
        additionalDatabaseReads: 0
    }));
});
