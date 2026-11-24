const test = require('node:test');
const assert = require('node:assert/strict');

const {
    GRAPH_HUNTING_ENDPOINT,
    runMicrosoftSecurityHuntingQuery
} = require('../services/intelligence/microsoft-security-hunting');
const { readEmailDetectionCounts, mergeVerifiedEmailSources } = require('../services/intelligence/email-dashboard-processor');

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

test('email hunting publishes aggregate detections without changing alert or incident counts', async () => {
    const row = { Observed: 30, Phishing: 4, Malware: 1, Spam: 5, Impersonation: 2 };
    const result = await runMicrosoftSecurityHuntingQuery({
        token: 'fixture', queryId: 'emailDetections30d',
        fetchImpl: async (_url, request) => {
            const body = JSON.parse(request.body);
            assert.equal(body.Timespan, 'P30D');
            assert.match(body.Query, /^EmailEvents/);
            assert.match(body.Query, /ago\(30d\)/);
            assert.match(body.Query, /by NetworkMessageId/);
            return graphResponse({ body: { schema: [], results: [row] } });
        }
    });
    const emailDetections = readEmailDetectionCounts(result);
    assert.deepEqual(emailDetections, { observed: 30, phishing: 4, malware: 1, spam: 5, impersonation: 2 });
    assert.equal(readEmailDetectionCounts({ ...result, results: [{ ...row, Observed: 0 }] }), null);
    assert.equal(readEmailDetectionCounts({ ...result, results: [] }), null);
    const prior = { success: true, fetchedAt: '2026-11-24T10:00:00Z',
        sourceAudit: { alertsComplete: true, incidentsComplete: true },
        summary: { activeThreats: 0, activeIncidents: 2 } };
    const saved = mergeVerifiedEmailSources(prior, {
        success: true, emailDetections, sourceAudit: { emailDetectionsComplete: true }
    }, new Date('2026-11-24T11:00:00Z'));
    assert.equal(saved.summary.activeThreats, 0);
    assert.equal(saved.summary.activeIncidents, 2);
    assert.equal(saved.emailDetections.phishing, 4);
    assert.equal(saved.sourceAudit.sourceTimestamps.alerts, prior.fetchedAt);
    const updatedAlerts = mergeVerifiedEmailSources(saved, prior, new Date('2026-11-24T11:30:00Z'));
    assert.deepEqual(updatedAlerts.emailDetections, emailDetections);
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
