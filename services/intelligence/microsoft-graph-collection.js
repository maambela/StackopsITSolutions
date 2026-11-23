const { graphCoordinator } = require('./microsoft-graph-coordinator');
const { performance } = require('node:perf_hooks');
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
    if (!Number.isNaN(seconds)) return Number.isFinite(seconds) && seconds >= 0 ? Math.ceil(seconds * 1000) : null;
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
    readJson = response => response.json(),
    timeoutMs = 60000,
    attemptTimeoutMs = timeoutMs,
    maxAttempts = 3,
    expectedUnavailableStatuses = [],
    optional = false,
    label = 'Microsoft Graph collection',
    baseDelayMs = 1000,
    maxRetryDelayMs = 30000,
    now = () => performance.now(),
    waitImpl = wait
} = {}) {
    if (!url) throw new Error('A Microsoft Graph collection URL is required');
    if (!token) throw new Error('A Microsoft Graph access token is required');
    if (typeof fetchImpl !== 'function') throw new Error('A fetch implementation is required');

    const deadline = now() + numberInRange(timeoutMs, 1, 300000, 60000);
    const attemptsAllowed = numberInRange(maxAttempts, 1, 5, 3);
    let lastMetadata = { httpStatus: null, graphRequestId: null, clientRequestId: null, retryAfterMs: null };
    let lastErrorDetail = null;
    let failedRequests = 0, rateLimits = 0;

    for (let attempt = 1; attempt <= attemptsAllowed; attempt += 1) {
        const remainingMs = deadline - now();
        if (remainingMs <= 0) break;

        const controller = new AbortController();
        const attemptBudgetMs = Math.min(remainingMs, numberInRange(attemptTimeoutMs, 1, 300000, remainingMs));
        const attemptDeadline = now() + attemptBudgetMs;
        const timeoutHandle = setTimeout(() => controller.abort(), attemptBudgetMs);
        try {
            const { response, payload } = await graphCoordinator.run(controller.signal, async () => {
                if (now() >= attemptDeadline) controller.abort();
                controller.signal.throwIfAborted();
                const response = await fetchImpl(url, {
                    method: 'GET',
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    signal: controller.signal
                });
                lastMetadata = graphResponseMetadata(response);
                if (!response.ok) failedRequests++;
                if (response.status === 429) rateLimits++;
                const payload = response.ok ? await readJson(response) : await response.text().catch(() => '');
                return { response, payload };
            });

            if (response.ok) {
                const data = payload;
                if (!Array.isArray(data?.value) || data.value.some(row => !row || typeof row !== 'object' || Array.isArray(row))) throw new Error('Microsoft Graph returned no value collection');
                const value = data.value;
                const hasMore = Boolean(data?.['@odata.nextLink']);
                return {
                    ok: true,
                    optional,
                    value,
                    hasMore,
                    nextLink: data?.['@odata.nextLink'] || null,
                    warnings: response.status === 206 ? [`${label} returned HTTP 206: provider coverage is partial.`] : hasMore ? [`${label} returned the first ${value.length} records; Microsoft Graph has additional pages.`] : [],
                    recordsFetched: value.length,
                    attempts: attempt,
                    ...lastMetadata, failedRequests, rateLimits,
                    errorCode: null,
                    errorDetail: null
                };
            }

            lastErrorDetail = boundedErrorDetail(payload);
            const unavailable = expectedUnavailableStatuses.includes(response.status);
            const retryable = RETRYABLE_GRAPH_STATUSES.has(response.status);
            if (!unavailable && retryable && attempt < attemptsAllowed) {
                const delay = retryDelayMs({
                    retryAfterMs: lastMetadata.retryAfterMs,
                    attempt,
                    remainingMs: deadline - now(),
                    baseDelayMs,
                    maxRetryDelayMs
                }) + (lastMetadata.retryAfterMs === null ? Math.random() * 250 : 0);
                if (deadline - now() > delay) {
                    clearTimeout(timeoutHandle);
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
                ...lastMetadata, failedRequests, rateLimits,
                errorCode: `GRAPH_HTTP_${response.status}`,
                errorDetail: lastErrorDetail
            };
        } catch (error) {
            const aborted = error?.name === 'AbortError';
            lastErrorDetail = aborted
                ? `${label} timed out within its ${Math.ceil(attemptBudgetMs)}ms attempt budget`
                : String(error?.message || error).slice(0, 600);
            const retryable = error instanceof TypeError && !controller.signal.aborted;
            const delay = retryDelayMs({ attempt, remainingMs: deadline - now(), baseDelayMs, maxRetryDelayMs }) + Math.random() * 250;
            if (!aborted && retryable && attempt < attemptsAllowed && deadline - now() > delay) {
                clearTimeout(timeoutHandle);
                await waitImpl(delay);
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
                ...lastMetadata, failedRequests, rateLimits,
                errorCode: aborted ? 'GRAPH_REQUEST_TIMEOUT' : error?.code === 'GRAPH_QUEUE_FULL' ? error.code : 'GRAPH_REQUEST_FAILED',
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
        ...lastMetadata, failedRequests, rateLimits,
        errorCode: 'GRAPH_REQUEST_TIMEOUT',
        errorDetail: lastErrorDetail || `${label} exceeded its collection deadline`
    };
}

/**
 * Reads a bounded number of Graph collection pages. A later-page failure keeps
 * the records that were safely returned but marks the source partial; callers
 * must never treat the partial collection as a clean result.
 */
async function fetchGraphCollectionPagesWithRetry({
    maxPages = Infinity,
    timeoutMs = 60000,
    betweenPagesDelayMs = 0,
    now = () => performance.now(),
    ...options
} = {}) {
    const pageLimit = maxPages === Infinity ? Infinity : numberInRange(maxPages, 1, Number.MAX_SAFE_INTEGER, Infinity);
    const deadline = now() + numberInRange(timeoutMs, 1000, 300000, 60000);
    const rows = [];
    const requestIds = [];
    let attempts = 0;
    let failedRequests = 0, rateLimits = 0;
    let pageCount = 0;
    let nextUrl = options.url;
    let lastResult = null;
    const visited = new Set();
    const identifiers = new Set();
    const providerWarnings = [];

    while (nextUrl && pageCount < pageLimit) {
        if (visited.has(nextUrl) || URL.parse(nextUrl)?.origin !== new URL(options.url).origin) {
            return { ...lastResult, ok: false, partial: true, value: rows, recordsFetched: rows.length, pageCount, hasMore: true,
                warnings: ['Graph pagination returned a repeated or invalid next link.'], errorCode: 'GRAPH_INVALID_NEXT_LINK' };
        }
        visited.add(nextUrl);
        const remainingMs = deadline - now();
        if (remainingMs <= 0) {
            return {
                ok: false,
                optional: Boolean(options.optional),
                value: rows,
                recordsFetched: rows.length,
                attempts, failedRequests, rateLimits,
                pageCount,
                pageLimitReached: true,
                hasMore: true,
                nextLink: nextUrl,
                graphRequestIds: requestIds,
                warnings: [`${options.label || 'Microsoft Graph collection'} is partial: page collection timed out after ${timeoutMs}ms.`],
                errorCode: 'GRAPH_COLLECTION_PAGINATION_TIMEOUT',
                errorDetail: 'The collection deadline was reached before the next page could be fetched.'
            };
        }

        const page = await fetchGraphCollectionWithRetry({
            ...options,
            url: nextUrl,
            timeoutMs: remainingMs,
            now
        });
        lastResult = page;
        providerWarnings.push(...(page.warnings || []).filter(warning => /HTTP 206/.test(warning)));
        pageCount += 1;
        attempts += page.attempts || 0;
        failedRequests += page.failedRequests || 0; rateLimits += page.rateLimits || 0;
        if (page.graphRequestId) requestIds.push(page.graphRequestId);

        if (!page.ok) {
            return {
                ...page,
                value: rows,
                recordsFetched: rows.length,
                attempts, failedRequests, rateLimits,
                pageCount,
                hasMore: Boolean(nextUrl),
                nextLink: nextUrl,
                graphRequestIds: requestIds,
                warnings: [
                    ...page.warnings,
                    ...(rows.length ? [`${options.label || 'Microsoft Graph collection'} is partial: ${rows.length} record(s) were returned before page ${pageCount} failed.`] : [])
                ],
                partial: rows.length > 0
            };
        }

        for (const row of page.value) {
            if (row?.id && identifiers.has(row.id)) continue;
            if (row?.id) identifiers.add(row.id);
            rows.push(row);
        }
        nextUrl = page.nextLink;
        options.onPage?.({ ...page, value: page.value, pageCount, recordsFetched: rows.length, failedRequests, rateLimits });
        if (!nextUrl) {
            return {
                ...page,
                value: rows,
                recordsFetched: rows.length,
                attempts, failedRequests, rateLimits,
                pageCount,
                pageLimitReached: false,
                hasMore: false,
                nextLink: null,
                graphRequestIds: requestIds,
                warnings: providerWarnings
            };
        }

        const pageDelay = numberInRange(betweenPagesDelayMs, 0, 60000, 0);
        if (pageDelay > 0) {
            const remainingAfterPage = deadline - now();
            if (remainingAfterPage <= pageDelay) {
                return {
                    ...page,
                    ok: false,
                    value: rows,
                    recordsFetched: rows.length,
                    attempts, failedRequests, rateLimits,
                    pageCount,
                    pageLimitReached: false,
                    hasMore: true,
                    nextLink: nextUrl,
                    graphRequestIds: requestIds,
                    warnings: [`${options.label || 'Microsoft Graph collection'} is partial: the source deadline was reached before its next paced page could be fetched.`],
                    errorCode: 'GRAPH_COLLECTION_PAGINATION_TIMEOUT',
                    errorDetail: 'The source deadline was reached while pacing Graph collection pages.'
                };
            }
            await (options.waitImpl || wait)(pageDelay);
        }
    }

    return {
        ...lastResult,
        ok: true,
        value: rows,
        recordsFetched: rows.length,
        attempts,
        pageCount,
        failedRequests,
        rateLimits,
        pageLimitReached: true,
        hasMore: true,
        nextLink: nextUrl,
        graphRequestIds: requestIds,
        warnings: [`${options.label || 'Microsoft Graph collection'} is limited to ${pageCount} page(s) and ${rows.length} record(s); Microsoft Graph has additional pages.`]
    };
}

module.exports = {
    RETRYABLE_GRAPH_STATUSES,
    parseRetryAfterMs,
    retryDelayMs,
    graphResponseMetadata,
    fetchGraphCollectionWithRetry,
    fetchGraphCollectionPagesWithRetry
};
