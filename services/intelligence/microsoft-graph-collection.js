const RETRYABLE_GRAPH_STATUSES = new Set([408, 429, 500, 502, 503, 504]);

function numberInRange(value, minimum, maximum, fallback) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? Math.min(maximum, Math.max(minimum, parsed)) : fallback;
}

function headerValue(headers, name) {
    if (!headers || typeof headers.get !== 'function') return null;
    return headers.get(name) || null;
}

function parseRetryAfterMs(value, now = Date.now()) {
    if (!value) return null;
    const seconds = Number(value);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.round(seconds * 1000);
    const dateMs = Date.parse(value);
    return Number.isFinite(dateMs) ? Math.max(0, dateMs - now) : null;
}

function graphResponseMetadata(response = {}) {
    return {
        httpStatus: Number.isFinite(Number(response.status)) ? Number(response.status) : null,
        graphRequestId: headerValue(response.headers, 'request-id'),
        clientRequestId: headerValue(response.headers, 'client-request-id'),
        retryAfterMs: parseRetryAfterMs(headerValue(response.headers, 'retry-after'))
    };
}

function boundedErrorDetail(body) {
    const compact = String(body || '').replace(/\s+/g, ' ').trim();
    return compact ? compact.slice(0, 600) : null;
}

function retryDelayMs({ retryAfterMs, attempt, remainingMs, baseDelayMs = 1000, maxRetryDelayMs = 30000 } = {}) {
    const fallback = Math.min(maxRetryDelayMs, baseDelayMs * (2 ** Math.max(0, attempt - 1)));
    const requested = retryAfterMs === null || retryAfterMs === undefined ? fallback : retryAfterMs;
    return Math.max(0, Math.min(requested, Math.max(0, remainingMs)));
}

function wait(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch a bounded Microsoft Graph collection with a single source-level
 * deadline. It honours Graph's Retry-After response when present and returns
 * request metadata that can be shown in Stack CTRL's authenticated audit.
 */
async function fetchGraphCollectionWithRetry({
    url,
    token,
    fetchImpl = globalThis.fetch,
    timeoutMs = 60000,
    maxAttempts = 3,
    expectedUnavailableStatuses = [],
    optional = false,
    label = 'Microsoft Graph collection',
    baseDelayMs = 1000,
    maxRetryDelayMs = 30000,
    now = () => Date.now(),
    waitImpl = wait
} = {}) {
    if (!url) throw new Error('A Microsoft Graph collection URL is required');
    if (!token) throw new Error('A Microsoft Graph access token is required');
    if (typeof fetchImpl !== 'function') throw new Error('A fetch implementation is required');

    const deadline = now() + numberInRange(timeoutMs, 1000, 300000, 60000);
    const attemptsAllowed = numberInRange(maxAttempts, 1, 5, 3);
    let lastMetadata = { httpStatus: null, graphRequestId: null, clientRequestId: null, retryAfterMs: null };
    let lastErrorDetail = null;

    for (let attempt = 1; attempt <= attemptsAllowed; attempt += 1) {
        const remainingMs = deadline - now();
        if (remainingMs <= 0) break;

        const controller = new AbortController();
        const timeoutHandle = setTimeout(() => controller.abort(), remainingMs);
        try {
            const response = await fetchImpl(url, {
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                signal: controller.signal
            });
            lastMetadata = graphResponseMetadata(response);

            if (response.ok) {
                const data = await response.json();
                const value = Array.isArray(data?.value) ? data.value : [];
                const hasMore = Boolean(data?.['@odata.nextLink']);
                return {
                    ok: true,
                    optional,
                    value,
                    hasMore,
                    warnings: hasMore ? [`${label} returned the first ${value.length} records; Microsoft Graph has additional pages.`] : [],
                    recordsFetched: value.length,
                    attempts: attempt,
                    ...lastMetadata,
                    errorCode: null,
                    errorDetail: null
                };
            }

            const body = await response.text().catch(() => '');
            lastErrorDetail = boundedErrorDetail(body);
            const unavailable = expectedUnavailableStatuses.includes(response.status);
            const retryable = RETRYABLE_GRAPH_STATUSES.has(response.status);
            if (!unavailable && retryable && attempt < attemptsAllowed) {
                const delay = retryDelayMs({
                    retryAfterMs: lastMetadata.retryAfterMs,
                    attempt,
                    remainingMs: deadline - now(),
                    baseDelayMs,
                    maxRetryDelayMs
                });
                if (delay > 0 && deadline - now() > delay) {
                    await waitImpl(delay);
                    continue;
                }
            }

            const availability = unavailable ? 'unavailable' : 'failed';
            const detail = lastErrorDetail ? `: ${lastErrorDetail}` : '';
            return {
                ok: false,
                optional,
                unavailable,
                value: [],
                warnings: [`${label} ${availability}: Microsoft Graph returned ${response.status}${detail}`],
                recordsFetched: 0,
                attempts: attempt,
                ...lastMetadata,
                errorCode: `GRAPH_HTTP_${response.status}`,
                errorDetail: lastErrorDetail
            };
        } catch (error) {
            const aborted = error?.name === 'AbortError';
            lastErrorDetail = aborted
                ? `${label} timed out after ${timeoutMs}ms`
                : String(error?.message || error).slice(0, 600);
            if (!aborted && attempt < attemptsAllowed && deadline - now() > baseDelayMs) {
                await waitImpl(retryDelayMs({ attempt, remainingMs: deadline - now(), baseDelayMs, maxRetryDelayMs }));
                continue;
            }
            return {
                ok: false,
                optional,
                aborted,
                value: [],
                warnings: [`${label} failed: ${lastErrorDetail}`],
                recordsFetched: 0,
                attempts: attempt,
                ...lastMetadata,
                errorCode: aborted ? 'GRAPH_REQUEST_TIMEOUT' : 'GRAPH_REQUEST_FAILED',
                errorDetail: lastErrorDetail
            };
        } finally {
            clearTimeout(timeoutHandle);
        }
    }

    return {
        ok: false,
        optional,
        aborted: true,
        value: [],
        warnings: [`${label} timed out after ${timeoutMs}ms`],
        recordsFetched: 0,
        attempts: attemptsAllowed,
        ...lastMetadata,
        errorCode: 'GRAPH_REQUEST_TIMEOUT',
        errorDetail: lastErrorDetail || `${label} exceeded its collection deadline`
    };
}

module.exports = {
    RETRYABLE_GRAPH_STATUSES,
    parseRetryAfterMs,
    retryDelayMs,
    graphResponseMetadata,
    fetchGraphCollectionWithRetry
};
