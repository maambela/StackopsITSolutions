const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const server = fs.readFileSync(require.resolve('../server'), 'utf8');

function section(start, end) {
    const from = server.indexOf(start);
    const to = server.indexOf(end, from + start.length);
    assert.ok(from >= 0 && to > from);
    return server.slice(from, to);
}

function emailActivity(fetchGraphResponseWithDeadline, rows = []) {
    return vm.runInNewContext([
        section('async function fetchEmailActivityReport', 'function isEmailSecuritySignal'),
        section('    async function fetchEmailActivitySafe', '    const [alertsSettled'),
        'fetchEmailActivitySafe;'
    ].join('\n'), {
        token: 'fixture',
        signal: null,
        collectorContext: {},
        fetchGraphResponseWithDeadline,
        parseGraphReportCSV: () => rows,
        console: { warn() {} }
    });
}

test('Email Activity reports HTTP errors and local deadlines as unavailable', async () => {
    const cases = [
        [async () => ({ response: { ok: false, status: 403 }, body: '' }), /returned HTTP 403/],
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
