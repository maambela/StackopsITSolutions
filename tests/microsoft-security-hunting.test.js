const test = require('node:test');
const assert = require('node:assert/strict');

const {
    GRAPH_HUNTING_ENDPOINT,
    runMicrosoftSecurityHuntingQuery
} = require('../services/intelligence/microsoft-security-hunting');

function graphResponse({ status = 200, body = {} } = {}) {
    return {
        ok: status >= 200 && status < 300,
        status,
        async json() { return body; }
    };
}

test('runHuntingQuery posts the supported fixed identity query and preserves schema/results', async () => {
    let request;
    const response = await runMicrosoftSecurityHuntingQuery({
        token: 'graph-token',
        queryId: 'identityLogons30d',
        fetchImpl: async (url, options) => {
            request = { url, options };
            return graphResponse({
                body: {
                    schema: [{ name: 'AccountUpn', type: 'String' }],
                    results: [{ AccountUpn: 'user@example.com', IPAddress: '203.0.113.8' }]
                }
            });
        }
    });

    assert.equal(request.url, GRAPH_HUNTING_ENDPOINT);
    assert.equal(request.options.method, 'POST');
    assert.equal(request.options.headers.Authorization, 'Bearer graph-token');
    assert.equal(request.options.headers['Content-Type'], 'application/json');
    const body = JSON.parse(request.options.body);
    assert.match(body.Query, /^IdentityLogonEvents/);
    assert.equal(body.Timespan, 'P30D');
    assert.equal(response.recordsFetched, 1);
    assert.equal(response.results[0].AccountUpn, 'user@example.com');
    assert.equal(response.query.id, 'identityLogons30d');
});

test('runHuntingQuery refuses arbitrary query IDs', async () => {
    await assert.rejects(
        runMicrosoftSecurityHuntingQuery({
            token: 'graph-token',
            queryId: 'arbitrary',
            fetchImpl: async () => {
                throw new Error('must not send an arbitrary query');
            }
        }),
        error => error.code === 'UNSUPPORTED_SECURITY_HUNTING_QUERY'
    );
});

test('runHuntingQuery reports Graph permission and invalid response errors', async () => {
    await assert.rejects(
        runMicrosoftSecurityHuntingQuery({
            token: 'graph-token',
            queryId: 'identityLogons30d',
            fetchImpl: async () => graphResponse({
                status: 403,
                body: { error: { message: 'Admin consent is required' } }
            })
        }),
        error => error.status === 403 && /Admin consent is required/.test(error.message)
    );

    await assert.rejects(
        runMicrosoftSecurityHuntingQuery({
            token: 'graph-token',
            queryId: 'identityLogons30d',
            fetchImpl: async () => graphResponse({ body: { results: [] } })
        }),
        error => error.code === 'INVALID_SECURITY_HUNTING_RESPONSE'
    );
});

test('runHuntingQuery enforces its timeout and marks the 100-row response cap', async () => {
    await assert.rejects(
        runMicrosoftSecurityHuntingQuery({
            token: 'graph-token',
            queryId: 'identityLogons30d',
            timeoutMs: 5,
            fetchImpl: (_url, { signal }) => new Promise((resolve, reject) => {
                signal.addEventListener('abort', () => {
                    const error = new Error('Aborted');
                    error.name = 'AbortError';
                    reject(error);
                });
            })
        }),
        error => error.code === 'SECURITY_HUNTING_QUERY_TIMEOUT'
    );

    const result = await runMicrosoftSecurityHuntingQuery({
        token: 'graph-token',
        queryId: 'identityLogons30d',
        fetchImpl: async () => graphResponse({
            body: { schema: [], results: Array.from({ length: 100 }, (_, index) => ({ index })) }
        })
    });
    assert.equal(result.isResultLimitReached, true);
    assert.equal(result.resultLimit, 100);
});
