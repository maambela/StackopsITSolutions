const { createHash } = require('node:crypto');
const { rawSecurityRecord } = require('./raw-security-records');
const { fetchGraphCollectionPagesWithRetry } = require('./microsoft-graph-collection');
const hash = value => createHash('sha256').update(String(value)).digest('hex');
const parse = value => typeof value === 'string' ? JSON.parse(value) : value;
const SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRLRawSecurityRecords (
        CompanyID BIGINT NOT NULL, RecordKey CHAR(64) NOT NULL, Provider VARCHAR(32) NOT NULL,
        Endpoint TEXT NOT NULL, ProviderRecordID TEXT NULL, EventTime VARCHAR(100) NULL,
        FirstRetrievedAt VARCHAR(40) NOT NULL, LastRetrievedAt VARCHAR(40) NOT NULL,
        ProviderVersion BIGINT NOT NULL DEFAULT 0, RecordJson JSON NOT NULL, PRIMARY KEY (CompanyID, RecordKey)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRLRawSecuritySync (
        CompanyID BIGINT NOT NULL, SourceKey CHAR(64) NOT NULL, StateJson JSON NOT NULL,
        PRIMARY KEY (CompanyID, SourceKey)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

function createRawEvidenceJournal({ pool, now = () => new Date(), logger = console } = {}) {
    const listeners = new Map();
    const storageFailures = new Set();
    const restored = new Map();
    const states = new Map(), queues = new Map(), hydration = new Map(), activeGraph = new Map();
    const key = (companyId, provider, endpoint) => `${companyId}:${hash(`${provider}:${endpoint}`)}`;
    let ready;
    function ensureSchema() {
        if (!ready) ready = (async () => { for (const sql of SCHEMA) await pool.query(sql); })().catch(error => { ready = null; throw error; });
        return ready;
    }
    function hydrate(companyId) {
        if (!hydration.has(companyId)) hydration.set(companyId, (async () => {
            await ensureSchema();
            const [rows] = await pool.query('SELECT StateJson FROM StackCTRLRawSecuritySync WHERE CompanyID = ?', [companyId]);
            for (const row of rows) {
                const state = parse(row.StateJson);
                const sourceKey = key(companyId, state.provider, state.endpoint);
                restored.set(sourceKey, state);
                if (!states.has(sourceKey)) states.set(sourceKey, state);
            }
        })().catch(error => { hydration.delete(companyId); logger.warn('[Raw evidence] Checkpoint load failed:', error.message); }));
        return hydration.get(companyId);
    }
    function queue(companyId, records, state) {
        if (!Number.isInteger(companyId) || companyId <= 0 || records.some(row => Number(row.companyId) !== companyId)) throw new Error('Raw evidence tenant mismatch');
        const task = (queues.get(companyId) || Promise.resolve()).then(async () => {
            await ensureSchema();
            const connection = await pool.getConnection();
            try {
                await connection.beginTransaction();
                for (const record of records) await connection.query(
                    `INSERT INTO StackCTRLRawSecurityRecords (CompanyID, RecordKey, Provider, Endpoint, ProviderRecordID, EventTime, FirstRetrievedAt, LastRetrievedAt, ProviderVersion, RecordJson)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE
                     EventTime = IF(VALUES(ProviderVersion) >= ProviderVersion, VALUES(EventTime), EventTime), LastRetrievedAt = VALUES(LastRetrievedAt), RecordJson = IF(VALUES(ProviderVersion) >= ProviderVersion, VALUES(RecordJson), RecordJson), ProviderVersion = GREATEST(ProviderVersion, VALUES(ProviderVersion))`,
                    [companyId, hash(record.uid), record.provider, record.endpoint, String(record.id), Number.isFinite(Date.parse(record.timestamp)) ? new Date(record.timestamp).toISOString() : null, record.retrievedAt, record.retrievedAt, record.providerVersion || 0, JSON.stringify(record)]);
                if (state && storageFailures.has(key(companyId, state.provider, state.endpoint))) { state.complete = false; state.status = 'partial'; state.continuation = null; state.storageError = 'An earlier page failed to store; a full replay is required.'; }
                if (state) await connection.query(
                    `INSERT INTO StackCTRLRawSecuritySync (CompanyID, SourceKey, StateJson) VALUES (?, ?, ?)
                     ON DUPLICATE KEY UPDATE StateJson = VALUES(StateJson)`, [companyId, hash(`${state.provider}:${state.endpoint}`), JSON.stringify({ ...state, storageStatus: 'stored' })]);
                await connection.commit();
            } catch (error) { await connection.rollback(); throw error; }
            finally { connection.release(); }
        });
        const handled = task.catch(error => {
            if (state) storageFailures.add(key(companyId, state.provider, state.endpoint));
            if (state) {
                const current = states.get(key(companyId, state.provider, state.endpoint));
                if (current) { current.storageStatus = 'failed'; current.storageError = error.message; current.continuation = null; }
            }
            logger.warn('[Raw evidence] Persistence failed:', error.message);
        });
        queues.set(companyId, handled);
        return task;
    }
    function collection(companyId, { onEvent = () => {}, range = {} } = {}) {
        if (!Number.isInteger(companyId) || companyId <= 0) throw new Error('A valid company is required');
        // Start hydration without delaying the first provider request.
        hydrate(companyId);
        const emit = event => { for (const listener of new Set([onEvent, ...(listeners.get(companyId) || [])])) { try { listener(event); } catch (error) { logger.warn('[Raw evidence] Stream listener:', error.message); } } };
        function publish(provider, endpoint, recordType, payloads, progress = {}) {
            const at = now().toISOString();
            const records = payloads.map(payload => rawSecurityRecord(payload, { companyId, provider, endpoint, recordType, retrievedAt: at }));
            const sourceKey = key(companyId, provider, endpoint);
            const prior = states.get(sourceKey) || {};
            const state = { ...prior, provider, endpoint, recordType, requestedRange: progress.status === 'receiving' ? prior.requestedRange || range : range, lastAttemptAt: at,
                ...progress, storageStatus: 'pending', recordsRetrieved: (progress.recordsRetrieved ?? prior.recordsRetrieved ?? 0),
                lastSuccessAt: progress.complete ? at : prior.lastSuccessAt || null };
            states.set(sourceKey, state);
            emit({ type: 'records', records, source: publicState(state) });
            queue(companyId, records, state).then(() => {
                if (states.get(sourceKey) === state) { state.storageStatus = storageFailures.has(sourceKey) ? 'partial' : 'stored'; if (!storageFailures.has(sourceKey)) delete state.storageError; }
                emit({ type: 'health', source: publicState(state) });
            }).catch(() => emit({ type: 'health', source: publicState(states.get(sourceKey)) }));
            return records;
        }
        function graph(options) {
            const scope = companyId + ':' + new URL(options.url).pathname + ':' + (range.explicit ? JSON.stringify(range) : 'live');
            if (activeGraph.has(scope)) return activeGraph.get(scope);
            const pending = collectGraph(options).finally(() => activeGraph.delete(scope));
            activeGraph.set(scope, pending);
            return pending;
        }
        async function collectGraph(options) {
            const requestedUrl = new URL(options.url);
            const endpoint = requestedUrl.pathname;
            if (range.since && ['/v1.0/security/alerts_v2', '/v1.0/security/incidents'].includes(endpoint)) {
                const field = range.explicit ? 'createdDateTime' : 'lastUpdateDateTime';
                requestedUrl.searchParams.set('$filter', field + ' ge ' + range.since + ' and ' + field + ' le ' + range.until);
                options = { ...options, url: requestedUrl.toString() };
            }
            const recordType = ({ alerts_v2: 'alert', incidents: 'incident', tiIndicators: 'indicator', signIns: 'signin', riskDetections: 'riskDetection', riskyUsers: 'riskyUser' })[endpoint.split('/').pop()] || 'event';
            const sourceKey = key(companyId, 'Microsoft Graph', endpoint);
            if (storageFailures.has(sourceKey)) { storageFailures.delete(sourceKey); const failed = states.get(sourceKey); if (failed) { failed.continuation = null; delete failed.storageError; } }
            const priorAtStart = states.get(sourceKey);
            let head;
            try {
                head = await fetchGraphCollectionPagesWithRetry({ ...options, maxPages: 1, onPage: page => {
                    publish('Microsoft Graph', endpoint, recordType, page.value, { complete: false, status: 'collecting',
                        continuation: priorAtStart?.continuation || restored.get(sourceKey)?.continuation || page.nextLink,
                        headIds: page.value.map(row => row.id).filter(Boolean), pages: 1, recordsRetrieved: page.value.length });
                } });
            } catch (error) { head = { ok: false, value: [], warnings: [error.message], errorCode: 'GRAPH_COLLECTION_FAILED' }; }
            // Hydration ran concurrently with the first API page; it never gates the first evidence.
            const prior = priorAtStart || restored.get(sourceKey);
            const resume = prior?.continuation && (range.explicit ? JSON.stringify(prior.requestedRange) === JSON.stringify(range) : !prior.requestedRange?.explicit) ? prior.continuation : null;
            if (resume && (typeof resume !== 'string' || new URL(resume).origin !== new URL(options.url).origin)) throw new Error('Invalid saved Graph continuation');
            // Resume an older backlog only after the newest page overlaps the last
            // observed head. Otherwise a burst larger than one page could be skipped.
            const headOverlaps = head.value?.some(row => prior?.headIds?.includes(row.id));
            const next = (resume && (!head.ok || headOverlaps || resume === head.nextLink)) ? resume : head.nextLink;
            let result = head;
            if (next && (head.ok || resume)) {
                result = await fetchGraphCollectionPagesWithRetry({ ...options, url: next, onPage: page => {
                    publish('Microsoft Graph', endpoint, recordType, page.value, { complete: false, status: 'collecting',
                        pages: page.pageCount + 1, recordsRetrieved: page.recordsFetched + head.value.length, continuation: page.nextLink,
                        failedRequests: page.failedRequests || 0, rateLimits: page.rateLimits || 0 });
                } });
                result.pageCount = (result.pageCount || 0) + (head.pageCount || 0);
            }
            const latest = head.value || [];
            if (!head.ok && result !== head) result.warnings = [...(result.warnings || []), ...(head.warnings || [])];
            const combined = [...new Map([...result.value, ...latest].map(row => [row.id || JSON.stringify(row), row])).values()];
            result.recordsFetched = combined.length;
            const complete = result.ok && !result.hasMore && !result.warnings?.length;
            publish('Microsoft Graph', endpoint, recordType, [], { complete, status: complete ? 'complete' : 'partial',
                pages: result.pageCount || 0, recordsRetrieved: result.recordsFetched || 0,
                continuation: result.nextLink || null, permissionErrors: [401, 403].includes(result.httpStatus) ? 1 : 0,
                failedRequests: result.failedRequests || (result.ok ? 0 : 1), rateLimits: result.rateLimits || 0,
                error: result.warnings?.join(' ') || null });
            return { ...result, value: combined };
        }
        return { graph, publish, getState: (provider, endpoint) => { const sourceKey = key(companyId, provider, endpoint); if (storageFailures.has(sourceKey)) { storageFailures.delete(sourceKey); return undefined; } const state = states.get(sourceKey); return state && (range.explicit ? JSON.stringify(state.requestedRange) === JSON.stringify(range) : !state.requestedRange?.explicit) ? state : undefined; }, health: () => healthMemory(companyId) };
    }
    function healthMemory(companyId) { return [...states.entries()].filter(([k]) => k.startsWith(`${companyId}:`)).map(([, value]) => publicState(value)); }
    async function health(companyId) {
        await hydrate(companyId);
        const [counts] = await pool.query('SELECT Provider AS provider, COUNT(*) AS recordsStored FROM StackCTRLRawSecurityRecords WHERE CompanyID = ? GROUP BY Provider', [companyId]);
        const sources = healthMemory(companyId);
        if (!sources.some(source => source.provider === 'Cloudflare' && source.endpoint.startsWith('/logpush/'))) sources.push({
            provider: 'Cloudflare', endpoint: '/logpush', status: 'not_observed', complete: false,
            limitation: 'No Logpush delivery has been observed for this company. Verify delivery jobs and account mapping for unsampled security event coverage.'
        });
        return { sources, stored: counts };
    }
    async function history(companyId, { after = '', since = null, until = null, pageSize = 500 } = {}) {
        const [rows] = await pool.query(
            `SELECT RecordKey, RecordJson FROM StackCTRLRawSecurityRecords WHERE CompanyID = ? AND RecordKey > ?
             AND (? IS NULL OR COALESCE(EventTime, LastRetrievedAt) >= ?) AND (? IS NULL OR COALESCE(EventTime, LastRetrievedAt) <= ?) ORDER BY RecordKey LIMIT ?`,
            [companyId, after, since, since, until, until, Math.min(1000, Math.max(1, Number(pageSize) || 500))]);
        return { records: rows.map(row => parse(row.RecordJson)), next: rows.length ? rows[rows.length - 1].RecordKey : null };
    }
    function subscribe(companyId, callback) {
        if (!listeners.has(companyId)) listeners.set(companyId, new Set());
        listeners.get(companyId).add(callback);
        return () => { listeners.get(companyId)?.delete(callback); if (!listeners.get(companyId)?.size) listeners.delete(companyId); };
    }
    return { ensureSchema, collection, queue, hydrate, health, history, subscribe, flush: companyId => queues.get(companyId) || Promise.resolve() };
}
function publicState(state = {}) {
    const { continuation, ...safe } = state;
    return { ...safe, resumable: Boolean(continuation) };
}
module.exports = { createRawEvidenceJournal, SCHEMA };
