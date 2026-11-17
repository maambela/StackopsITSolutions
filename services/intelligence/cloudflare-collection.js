const { parseRetryAfterMs } = require('./microsoft-graph-collection');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function collectionRows(data) {
    if (Array.isArray(data?.result)) return data.result;
    if (Array.isArray(data?.result?.issues)) return data.result.issues;
    return null;
}

async function fetchCloudflarePages(client, url, query = {}, { wait = sleep, timeoutMs = 60000, now = Date.now, onPage = () => {}, resumeQuery = null, preview = false, requireCollection = false } = {}) {
    const rows = [], seen = new Set(), pageContents = new Set();
    let params = { ...(resumeQuery || query) }, pages = 0, retries = 0, rateLimits = 0;
    const deadline = now() + timeoutMs;
    try {
        while (true) {
            if (now() >= deadline) throw new Error('Cloudflare collection deadline reached');
            const key = JSON.stringify(params);
            if (seen.has(key)) throw new Error('Cloudflare repeated its pagination cursor');
            seen.add(key);
            let data;
            for (let attempt = 0; ; attempt++) {
                try {
                    data = (await client.get(url, { params, timeout: Math.max(1, deadline - now()) })).data;
                    if (data?.success === false) throw new Error(data.errors?.map(e => e.message).join('; ') || 'Cloudflare API failure');
                    break;
                } catch (error) {
                    const status = error.response?.status;
                    if (status === 429) rateLimits++;
                    if (attempt >= 2 || ![429, 500, 502, 503, 504].includes(status)) throw error;
                    const delay = parseRetryAfterMs(error.response?.headers?.['retry-after']) ?? 1000 * 2 ** attempt;
                    if (now() + delay >= deadline) throw error;
                    retries++;
                    await wait(delay);
                }
            }
            pages++;
            const pageRows = collectionRows(data);
            if (!pageRows && requireCollection) throw new Error('Cloudflare returned an unrecognized collection shape; coverage is incomplete');
            if (!pageRows) return { ...data, collection: { pages, retries, rateLimits, complete: true } };
            const signature = JSON.stringify(pageRows);
            if (pageRows.length && pageContents.has(signature)) throw new Error('Cloudflare returned a repeated page');
            pageContents.add(signature);
            rows.push(...pageRows);
            const info = data.result_info || (data.result?.issues ? data.result : {});
            const cursor = typeof info.cursor === 'string' ? info.cursor : info.cursor?.after || info.cursors?.after;
            const page = Number(info.page || params.page || 1);
            const pageSize = Number(info.per_page || params.per_page);
            const more = info.total_pages != null ? page < Number(info.total_pages)
                : info.total_count != null ? rows.length < Number(info.total_count)
                : pageSize > 0 && pageRows.length >= pageSize;
            if (cursor) params = { ...params, cursor };
            else if (!Object.hasOwn(info, 'cursor') && !info.cursors && more && pageRows.length) params = { ...params, page: page + 1 };
            else { onPage({ value: pageRows, nextQuery: null, pages, retries, rateLimits, recordsRetrieved: rows.length }); return { ...data, result: rows, collection: { pages, retries, rateLimits, complete: true } }; }
            onPage({ value: pageRows, nextQuery: params, pages, retries, rateLimits, recordsRetrieved: rows.length });
            if (preview) return { ...data, result: rows, collection: { pages, retries, rateLimits, complete: false, nextQuery: params } };
        }
    } catch (error) {
        if (!pages) throw error;
        return { result: rows, collection: { pages, retries, rateLimits, complete: false, nextQuery: params, error: error.message } };
    }
}
module.exports = { fetchCloudflarePages };
