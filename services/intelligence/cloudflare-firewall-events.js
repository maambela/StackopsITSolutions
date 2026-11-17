const { parseRetryAfterMs } = require('./microsoft-graph-collection');
const waitDefault = ms => new Promise(resolve => setTimeout(resolve, ms));
// Adaptive analytics can be sampled by Cloudflare. Never describe this as an unsampled event stream.
const QUERY = `query SecurityEvents($zone: string, $filter: FirewallEventsAdaptiveFilter_InputObject, $limit: uint64!) {
 viewer { zones(filter: {zoneTag: $zone}) { firewallEventsAdaptive(limit: $limit, filter: $filter, orderBy: [datetime_DESC]) {
 action clientIP clientCountryName datetime source rayName clientRequestHTTPHost clientRequestPath ruleId
 } } } }`;

async function fetchFirewallEvents(client, { zoneId, since, until, pending, onPage = () => {}, timeoutMs = 60000,
    pageSize = 1000, now = Date.now, wait = waitDefault } = {}) {
    const start = Date.parse(since), end = Date.parse(until);
    if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) throw new Error('A valid firewall event time range is required');
    const windows = pending?.length ? pending.map(window => [...window]) : [];
    if (windows.length) windows.unshift([Math.max(start, end - 3600000), end]);
    if (!windows.length) for (let high = end; high > start; high -= 3600000) windows.push([Math.max(start, high - 3600000), high]);
    const rows = [], warnings = [], failedWindows = [];
    const deadline = now() + timeoutMs;
    let pages = 0, failedRequests = 0, rateLimits = 0, permissionErrors = 0;
    while (windows.length && now() < deadline) {
        const [low, high] = windows[0];
        let data;
        try {
            for (let attempt = 0; ; attempt++) {
                try {
                    data = (await client.post('/graphql', { query: QUERY, variables: { zone: zoneId, limit: pageSize,
                        filter: { datetime_geq: new Date(low).toISOString(), datetime_lt: new Date(high).toISOString() } } }, { timeout: Math.max(1, deadline - now()) })).data;
                    if (data.errors?.length) throw new Error(data.errors.map(error => error.message).join('; '));
                    break;
                } catch (error) {
                    failedRequests++;
                    const status = error.response?.status;
                    if ([401, 403].includes(status)) permissionErrors++;
                    if (status === 429) rateLimits++;
                    const delay = parseRetryAfterMs(error.response?.headers?.['retry-after']) ?? 1000 * 2 ** attempt;
                    if (attempt >= 2 || ![429, 500, 502, 503, 504].includes(status) || now() + delay >= deadline) throw error;
                    await wait(delay);
                }
            }
            const page = data?.data?.viewer?.zones?.[0]?.firewallEventsAdaptive;
            if (!Array.isArray(page)) throw new Error('Firewall dataset unavailable or invalid response; check Zone Analytics Read and plan access');
            pages++;
            windows.shift();
            if (page.length >= pageSize && high - low > 1000) {
                const middle = Math.floor((low + high) / 2000) * 1000;
                windows.unshift([middle, high], [low, middle]);
            } else {
                rows.push(...page);
                if (page.length >= pageSize) {
                    failedWindows.push([low, high]);
                    warnings.push(`Provider result limit reached within one second at ${new Date(low).toISOString()}; use unsampled Logpush for full coverage.`);
                }
                onPage({ value: page, pending: [...windows], pages, failedRequests, rateLimits, permissionErrors });
            }
        } catch (error) { warnings.push(error.message); break; }
    }
    if (windows.length && !warnings.length) warnings.push('Firewall history is partial; remaining time windows will resume on refresh.');
    return { value: rows, pending: windows, failedWindows, pages, failedRequests, rateLimits, permissionErrors,
        complete: !windows.length && !failedWindows.length && !warnings.length, warnings,
        limitation: 'Cloudflare firewallEventsAdaptive uses provider sampling. WAF, firewall and HTTP DDoS events appear only when returned by this dataset; unsampled coverage requires Logpush.' };
}
module.exports = { fetchFirewallEvents, QUERY };
