const GRAPH_ROOT = 'https://graph.microsoft.com/v1.0';

const IDENTITY_RISK_ENDPOINTS = Object.freeze({
    riskDetections: '/identityProtection/riskDetections?$top=100&$orderby=activityDateTime%20desc',
    riskyUsers: '/identityProtection/riskyUsers?$top=100&$select=id,userPrincipalName,userDisplayName,riskLevel,riskState,riskDetail,isDeleted,isProcessing'
});

async function fetchGraphCollection({
    path,
    label,
    token,
    fetchImpl = globalThis.fetch,
    timeoutMs = 30000
} = {}) {
    if (!token) throw new Error('A Microsoft Graph access token is required');
    if (typeof fetchImpl !== 'function') throw new Error('A fetch implementation is required');

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const response = await fetchImpl(`${GRAPH_ROOT}${path}`, {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${token}`,
                Accept: 'application/json'
            },
            signal: controller.signal
        });

        if (!response.ok) {
            const body = await response.text().catch(() => '');
            return {
                records: [],
                status: 'unavailable',
                recordsFetched: 0,
                warnings: [`${label} unavailable: Microsoft Graph returned ${response.status}${body ? `: ${body.slice(0, 240)}` : ''}`]
            };
        }

        const data = await response.json();
        if (!Array.isArray(data?.value)) {
            return {
                records: [],
                status: 'invalid_response',
                recordsFetched: 0,
                warnings: [`${label} unavailable: Microsoft Graph returned no value collection`]
            };
        }

        const hasMore = Boolean(data['@odata.nextLink']);
        return {
            records: data.value,
            status: hasMore ? 'partial' : 'complete',
            recordsFetched: data.value.length,
            warnings: hasMore ? [`${label} is limited to the first ${data.value.length} records; more results are available.`] : []
        };
    } catch (error) {
        const reason = error?.name === 'AbortError'
            ? `timed out after ${timeoutMs}ms`
            : error?.message || String(error);
        return {
            records: [],
            status: 'unavailable',
            recordsFetched: 0,
            warnings: [`${label} unavailable: ${reason}`]
        };
    } finally {
        clearTimeout(timeout);
    }
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
