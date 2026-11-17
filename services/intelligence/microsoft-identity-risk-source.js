const GRAPH_ROOT = 'https://graph.microsoft.com/v1.0';

const IDENTITY_RISK_ENDPOINTS = Object.freeze({
    riskDetections: '/identityProtection/riskDetections?$top=100&$orderby=activityDateTime%20desc',
    riskyUsers: '/identityProtection/riskyUsers?$top=100'
});

async function fetchGraphCollection({
    path,
    label,
    token,
    fetchImpl = globalThis.fetch,
    graph,
    timeoutMs = 30000
} = {}) {
    const { fetchGraphCollectionPagesWithRetry } = require('./microsoft-graph-collection');
    const result = await (graph || fetchGraphCollectionPagesWithRetry)({ url: `${GRAPH_ROOT}${path}`, token, fetchImpl, timeoutMs, label, expectedUnavailableStatuses: [400, 403, 404] });
    return { ...result, records: result.value, status: result.ok && !result.hasMore ? 'complete' : result.value.length ? 'partial' : 'unavailable' };

}

async function fetchMicrosoftIdentityRiskEvidence(token, options = {}) {
    const [riskDetections, riskyUsers] = await Promise.all([
        fetchGraphCollection({
            ...options,
            token,
            path: IDENTITY_RISK_ENDPOINTS.riskDetections,
            label: 'Identity risk detections'
        }),
        fetchGraphCollection({
            ...options,
            token,
            path: IDENTITY_RISK_ENDPOINTS.riskyUsers,
            label: 'Risky users'
        })
    ]);

    return {
        riskDetections: riskDetections.records,
        riskyUsers: riskyUsers.records,
        sources: {
            riskDetections: {
                status: riskDetections.status,
                recordsFetched: riskDetections.recordsFetched
            },
            riskyUsers: {
                status: riskyUsers.status,
                recordsFetched: riskyUsers.recordsFetched
            }
        },
        warnings: [...riskDetections.warnings, ...riskyUsers.warnings]
    };
}

module.exports = {
    IDENTITY_RISK_ENDPOINTS,
    fetchGraphCollection,
    fetchMicrosoftIdentityRiskEvidence
};
