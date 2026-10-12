const GRAPH_HUNTING_ENDPOINT = 'https://graph.microsoft.com/v1.0/security/runHuntingQuery';

const SECURITY_HUNTING_QUERIES = Object.freeze({
    identityLogons30d: Object.freeze({
        id: 'identityLogons30d',
        title: 'Recent Defender identity logons',
        description: 'Returns a bounded set of identity logon telemetry for correlation with Microsoft Entra sign-ins.',
        timespan: 'P30D',
        query: [
            'IdentityLogonEvents',
            '| where Timestamp >= ago(30d)',
            '| project Timestamp, AccountUpn, AccountObjectId, IPAddress, ActionType, Application, FailureReason, LogonType, Location, ISP',
            '| order by Timestamp desc',
            '| take 100'
        ].join('\n')
    })
});

function buildHuntingErrorMessage(status, body) {
    const graphMessage = body?.error?.message;
    const detail = typeof graphMessage === 'string' ? `: ${graphMessage.slice(0, 600)}` : '';
    return `Microsoft Graph hunting query failed (${status})${detail}`;
}

async function runMicrosoftSecurityHuntingQuery({
    token,
    queryId,
    fetchImpl = globalThis.fetch,
    timeoutMs = 60000
} = {}) {
    if (!token) throw new Error('A Microsoft Graph access token is required');
    if (typeof fetchImpl !== 'function') throw new Error('A fetch implementation is required');

    const queryDefinition = SECURITY_HUNTING_QUERIES[queryId];
    if (!queryDefinition) {
        const error = new Error('Unsupported security hunting query');
        error.code = 'UNSUPPORTED_SECURITY_HUNTING_QUERY';
        throw error;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const response = await fetchImpl(GRAPH_HUNTING_ENDPOINT, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                Accept: 'application/json'
            },
            body: JSON.stringify({
                Query: queryDefinition.query,
                Timespan: queryDefinition.timespan
            }),
            signal: controller.signal
        });

        if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            const error = new Error(buildHuntingErrorMessage(response.status, body));
            error.status = response.status;
            error.code = response.status === 403
                ? 'SECURITY_HUNTING_PERMISSION_DENIED'
                : 'SECURITY_HUNTING_QUERY_FAILED';
            throw error;
        }

        const body = await response.json();
        if (!Array.isArray(body?.results) || !Array.isArray(body?.schema)) {
            const error = new Error('Microsoft Graph hunting query returned an invalid results/schema response');
            error.code = 'INVALID_SECURITY_HUNTING_RESPONSE';
            throw error;
        }

        const results = body.results.slice(0, 100);
        return {
            query: {
                id: queryDefinition.id,
                title: queryDefinition.title,
                description: queryDefinition.description,
                timespan: queryDefinition.timespan
            },
            schema: body.schema,
            results,
            recordsFetched: results.length,
            resultLimit: 100,
            isResultLimitReached: body.results.length >= 100
        };
    } catch (error) {
        if (error?.name === 'AbortError') {
            const timeoutError = new Error(`Microsoft Graph hunting query timed out after ${timeoutMs}ms`);
            timeoutError.code = 'SECURITY_HUNTING_QUERY_TIMEOUT';
            throw timeoutError;
        }
        throw error;
    } finally {
        clearTimeout(timeout);
    }
}

module.exports = {
    GRAPH_HUNTING_ENDPOINT,
    SECURITY_HUNTING_QUERIES,
    runMicrosoftSecurityHuntingQuery
};
