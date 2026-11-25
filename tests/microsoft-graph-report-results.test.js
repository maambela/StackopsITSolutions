const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');
const { readEmailReportRefreshDate, getReusableEmailReport } = require('../services/intelligence/email-dashboard-processor');

const server = fs.readFileSync(require.resolve('../server'), 'utf8');

function section(start, end) {
    const from = server.indexOf(start);
    const to = server.indexOf(end, from + start.length);
    assert.ok(from >= 0 && to > from);
    return server.slice(from, to);
}

function emailActivity(fetchGraphResponseWithDeadline, rows = [], context = {}) {
    return vm.runInNewContext([
        section('async function fetchEmailActivityReport', 'function isEmailSecuritySignal'),
        section('    async function fetchEmailActivitySafe', '    const [alertsSettled'),
        'fetchEmailActivitySafe;'
    ].join('\n'), {
        token: 'fixture',
        signal: null,
        collectorContext: {},
        fetchGraphResponseWithDeadline,
        readEmailReportRefreshDate,
        parseGraphReportCSV: () => rows,
        console: { warn() {}, info() {} },
        ...context
    });
}

test('equivalent five-minute refreshes reuse the Exchange report for the verified company and tenant', async () => {
    const start = Date.parse('2026-11-25T01:00:00Z');
    const rows = [{ 'User Principal Name': 'fixture@example.test', 'Report Refresh Date': '2026-11-24' }];
    let baselineDownloads = 0;
    let newDownloads = 0;
    let saved;
    for (let tick = 0; tick < 12; tick++) {
        const now = start + tick * 5 * 60000;
        const response = { response: { ok: true, status: 200 }, body: 'fixture CSV' };
        await emailActivity(async () => { baselineDownloads++; return response; }, rows)();
        const report = await emailActivity(async () => { newDownloads++; return response; }, rows, {
            collectorContext: { companyId: 7, tenantId: 'tenant-a' },
            pool: { query: async (_sql, args) => {
                assert.equal(args[0], 7);
                return [[{ Payload: saved }]];
            } },
            parseReportJson: payload => payload,
            getReusableEmailReport: (payload, _now, tenant) => getReusableEmailReport(payload, now, tenant)
        })();
        if (!report.reused) saved = { mailActivity: { users: report.users, summary: report.summary },
            sourceAudit: { mailActivityOk: true, sourceTenantId: 'tenant-a', mailActivityTenantId: 'tenant-a',
                sourceTimestamps: { mailActivity: new Date(now).toISOString() } } };
    }
    assert.equal(baselineDownloads, 12);
    assert.equal(newDownloads, 1);
    assert.equal(getReusableEmailReport(saved, start + 5 * 60000, 'tenant-b'), null);
    assert.equal(getReusableEmailReport(saved, start + 60 * 60000, 'tenant-a'), null);
});

test('Email Activity reports HTTP errors and local deadlines as unavailable', async () => {
    const cases = [
        [async () => ({ response: { ok: false, status: 403 }, body: '' }), /returned HTTP 403/],
        [async () => ({ response: { ok: true, status: 206 }, body: 'partial CSV' }), /returned HTTP 206/],
        [async () => { throw new Error('Email activity Graph report exceeded 15000ms.'); }, /exceeded 15000ms/]
    ];
    for (const [request, warning] of cases) {
        const result = await emailActivity(request)();
        assert.equal(result.ok, false);
        assert.equal(result.recordsFetched, 0);
        assert.match(result.warnings[0], warning);
    }
});

test('Email Activity keeps successful empty and populated reports healthy', async () => {
    const request = async () => ({ response: { ok: true, status: 200 }, body: 'fixture CSV' });
    const empty = await emailActivity(request)();
    assert.equal(empty.ok, true);
    assert.equal(empty.recordsFetched, 0);
    const populated = await emailActivity(request, [{ 'User Principal Name': 'fixture@example.test', 'Send Count': '5' }])();
    assert.equal(populated.ok, true);
    assert.equal(populated.recordsFetched, 1);
    assert.equal(populated.summary.totalMailActivity, 5);
});

test('the report HTTP completion log records the actual status without logging its body', async () => {
    const logs = [];
    const helper = vm.runInNewContext(section('async function fetchGraphResponseWithDeadline', 'async function writeBackupRecoveryPayloadCache') +
        '\nfetchGraphResponseWithDeadline;', {
        MICROSOFT_GRAPH_REQUEST_TIMEOUT_MS: 15000,
        MICROSOFT_GRAPH_MAX_RESPONSE_BYTES: 1024,
        runAbortableOperation: ({ operation }) => operation({ signal: new AbortController().signal }),
        graphCoordinator: { run: (signal, operation) => operation() },
        fetch: async () => ({ status: 503, ok: false }),
        readBoundedResponseText: async () => 'private response content',
        logRuntimeOperation: (event, entry) => logs.push({ event, ...entry })
    });
    const result = await helper('https://graph.microsoft.com/v1.0/reports/fixture', 'fixture');
    assert.equal(result.response.status, 503);
    assert.equal(logs[1].httpStatus, 503);
    assert.equal(logs[1].httpOk, false);
    assert.doesNotMatch(JSON.stringify(logs), /private response content/);
});
