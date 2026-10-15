const test = require('node:test');
const assert = require('node:assert/strict');

const {
    parseRetryAfterMs,
    retryDelayMs,
    fetchGraphCollectionWithRetry,
    fetchGraphCollectionPagesWithRetry
} = require('../services/intelligence/microsoft-graph-collection');

function response({ status = 200, body = {}, headers = {} } = {}) {
    const normalizedHeaders = new Map(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), String(value)]));
    return {
        ok: status >= 200 && status < 300,
        status,
        headers: { get(name) { return normalizedHeaders.get(String(name).toLowerCase()) || null; } },
        async json() { return body; },
        async text() { return typeof body === 'string' ? body : JSON.stringify(body); }
    };
}

test('parses Graph Retry-After values and bounds retry delays to the source deadline', () => {
    assert.equal(parseRetryAfterMs('4'), 4000);
    assert.equal(retryDelayMs({ retryAfterMs: 4000, attempt: 1, remainingMs: 1500 }), 1500);
    assert.equal(retryDelayMs({ attempt: 2, remainingMs: 10000, baseDelayMs: 1000 }), 2000);
});

test('retries a throttled Graph collection using Retry-After and preserves request metadata', async () => {
    const waits = [];
    let calls = 0;
    const result = await fetchGraphCollectionWithRetry({
        url: 'https://graph.microsoft.com/v1.0/auditLogs/signIns',
        token: 'graph-token',
        timeoutMs: 10000,
        fetchImpl: async () => {
            calls += 1;
            return calls === 1
                ? response({
                    status: 429,
                    body: { error: { message: 'Too Many Requests' } },
                    headers: { 'retry-after': '2', 'request-id': 'first-request' }
                })
                : response({
                    body: { value: [{ id: 'signin-1' }] },
                    headers: { 'request-id': 'second-request', 'client-request-id': 'client-request' }
                });
        },
        waitImpl: async milliseconds => { waits.push(milliseconds); }
    });

    assert.equal(calls, 2);
    assert.deepEqual(waits, [2000]);
    assert.equal(result.ok, true);
    assert.equal(result.attempts, 2);
    assert.equal(result.recordsFetched, 1);
    assert.equal(result.graphRequestId, 'second-request');
    assert.equal(result.clientRequestId, 'client-request');
});

test('returns a structured unavailable result for known optional endpoint failures', async () => {
    const result = await fetchGraphCollectionWithRetry({
        url: 'https://graph.microsoft.com/v1.0/security/tiIndicators',
        token: 'graph-token',
        optional: true,
        expectedUnavailableStatuses: [400, 403, 404],
        fetchImpl: async () => response({
            status: 400,
            body: { error: { code: 'BadRequest', message: 'Unsupported request' } },
            headers: { 'request-id': 'indicator-request' }
        })
    });

    assert.equal(result.ok, false);
    assert.equal(result.unavailable, true);
    assert.equal(result.httpStatus, 400);
    assert.equal(result.errorCode, 'GRAPH_HTTP_400');
    assert.equal(result.graphRequestId, 'indicator-request');
    assert.match(result.errorDetail, /Unsupported request/);
});

test('follows Graph next links up to the configured page limit and reports an incomplete collection', async () => {
    const requests = [];
    const result = await fetchGraphCollectionPagesWithRetry({
        url: 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=100',
        token: 'graph-token',
        maxPages: 2,
        fetchImpl: async url => {
            requests.push(url);
            return requests.length === 1
                ? response({
                    body: {
                        value: [{ id: 'page-one' }],
                        '@odata.nextLink': 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=next'
                    },
                    headers: { 'request-id': 'page-one-request' }
                })
                : response({
                    body: {
                        value: [{ id: 'page-two' }],
                        '@odata.nextLink': 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=still-more'
                    },
                    headers: { 'request-id': 'page-two-request' }
                });
        }
    });

    assert.equal(requests.length, 2);
    assert.deepEqual(result.value.map(row => row.id), ['page-one', 'page-two']);
    assert.equal(result.recordsFetched, 2);
    assert.equal(result.pageCount, 2);
    assert.equal(result.pageLimitReached, true);
    assert.equal(result.hasMore, true);
    assert.deepEqual(result.graphRequestIds, ['page-one-request', 'page-two-request']);
    assert.match(result.warnings[0], /limited to 2 page/);
});
