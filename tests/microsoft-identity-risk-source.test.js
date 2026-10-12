const test = require('node:test');
const assert = require('node:assert/strict');

const {
    IDENTITY_RISK_ENDPOINTS,
    fetchGraphCollection,
    fetchMicrosoftIdentityRiskEvidence
} = require('../services/intelligence/microsoft-identity-risk-source');

function response({ status = 200, body = {} } = {}) {
    return {
        ok: status >= 200 && status < 300,
        status,
        async json() { return body; },
        async text() { return JSON.stringify(body); }
    };
}

test('identity risk collection calls both Graph sources with application bearer auth', async () => {
    const requests = [];
    const result = await fetchMicrosoftIdentityRiskEvidence('graph-token', {
        fetchImpl: async (url, options) => {
            requests.push({ url, options });
            return response({ body: { value: [{ id: url.includes('riskyUsers') ? 'user-1' : 'risk-1' }] } });
        }
    });

    assert.equal(requests.length, 2);
    assert.ok(requests.some(request => request.url.endsWith(IDENTITY_RISK_ENDPOINTS.riskyUsers)));
    assert.ok(requests.some(request => request.url.endsWith(IDENTITY_RISK_ENDPOINTS.riskDetections)));
    assert.ok(requests.every(request => request.options.headers.Authorization === 'Bearer graph-token'));
    assert.deepEqual(result.riskyUsers, [{ id: 'user-1' }]);
    assert.deepEqual(result.riskDetections, [{ id: 'risk-1' }]);
    assert.deepEqual(result.warnings, []);
});

test('identity risk collection surfaces permission or licensing failures without hiding other data', async () => {
    const result = await fetchMicrosoftIdentityRiskEvidence('graph-token', {
        fetchImpl: async url => url.includes('riskyUsers')
            ? response({ status: 403, body: { error: 'Forbidden' } })
            : response({ body: { value: [{ id: 'risk-1' }] } })
    });

    assert.equal(result.riskDetections.length, 1);
    assert.deepEqual(result.riskyUsers, []);
    assert.equal(result.sources.riskyUsers.status, 'unavailable');
    assert.match(result.warnings.join(' '), /Risky users unavailable.*403/);
});

test('identity risk collection marks truncated Graph result pages as partial', async () => {
    const result = await fetchGraphCollection({
        token: 'graph-token',
        path: IDENTITY_RISK_ENDPOINTS.riskyUsers,
        label: 'Risky users',
        fetchImpl: async () => response({ body: { value: [{ id: 'user-1' }], '@odata.nextLink': 'https://graph.microsoft.com/next' } })
    });

    assert.equal(result.status, 'partial');
    assert.equal(result.recordsFetched, 1);
    assert.match(result.warnings.join(' '), /first 1 records/);
});
