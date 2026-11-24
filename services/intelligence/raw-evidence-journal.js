const { createHash } = require('node:crypto');
const { rawSecurityRecord } = require('./raw-security-records');
const { fetchGraphCollectionPagesWithRetry } = require('./microsoft-graph-collection');
const { SECURITY_ALERT_STORAGE_ENABLED } = require('./security-storage-policy');
const hash = value => createHash('sha256').update(String(value)).digest('hex');
const parse = value => typeof value === 'string' ? JSON.parse(value) : value;
const GRAPH_RESULT_CACHE_TTLS_MS = Object.freeze({
    '/v1.0/security/alerts_v2': 30000,
    '/v1.0/security/incidents': 30000,
    '/v1.0/auditLogs/signIns': 60000,
    '/v1.0/identityProtection/riskDetections': 60000,
    '/v1.0/identityProtection/riskyUsers': 60000,
    '/v1.0/auditLogs/directoryAudits': 120000,
    '/v1.0/security/tiIndicators': 300000
});
const GRAPH_RESULT_CACHE_MAX_ENTRIES = 256;
const GRAPH_RESULT_CACHE_MAX_BYTES = 32 * 1024 * 1024;
const GRAPH_RESULT_CACHE_MAX_ENTRY_BYTES = 8 * 1024 * 1024;
const SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRLRawSecurityRecords (
        CompanyID BIGINT NOT NULL, RecordKey CHAR(64) NOT NULL, Provider VARCHAR(32) NOT NULL,
        Endpoint TEXT NOT NULL, ProviderRecordID TEXT NULL, EventTime VARCHAR(100) NULL,
        FirstRetrievedAt VARCHAR(40) NOT NULL, LastRetrievedAt VARCHAR(40) NOT NULL,
        ProviderVersion BIGINT NOT NULL DEFAULT 0, RecordJson JSON NOT NULL, PRIMARY KEY (CompanyID, RecordKey),
        KEY ix_raw_company_time (CompanyID, EventTime, RecordKey)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRLRawSecuritySync (
        CompanyID BIGINT NOT NULL, SourceKey CHAR(64) NOT NULL, StateJson JSON NOT NULL,
        PRIMARY KEY (CompanyID, SourceKey)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

function createRawEvidenceJournal({ pool, now = () => new Date(), logger = console, persistenceEnabled = SECURITY_ALERT_STORAGE_ENABLED,
    withGraphOwnership, assertGraphOwner } = {}) {
    const listeners = new Map();
    const storageFailures = new Set();
    const restored = new Map();
    const recent = new Map();
    const persisted = new Map();
    const completedGraph = new Map();
    let completedGraphBytes = 0;
    let recentBytes = 0;
    function remember(record) {
        const prior = recent.get(record.uid);
        if (prior && Number(prior.record.providerVersion) > Number(record.providerVersion)) return;
        const bytes = Buffer.byteLength(JSON.stringify(record));
        if (prior) { recentBytes -= prior.bytes; recent.delete(record.uid); }
        recent.set(record.uid, { record, bytes }); recentBytes += bytes;
        while (recentBytes > 32 * 1024 * 1024 || recent.size > 2000) {
            const oldest = recent.keys().next().value;
            recentBytes -= recent.get(oldest).bytes; recent.delete(oldest);
        }
    }
    const states = new Map(), queues = new Map(), hydration = new Map(), activeGraph = new Map();
    const key = (companyId, provider, endpoint) => `${companyId}:${hash(`${provider}:${endpoint}`)}`;
    function removeCompletedGraph(scope) {
        const entry = completedGraph.get(scope);
        if (!entry) return;
        completedGraphBytes -= entry.bytes;
        completedGraph.delete(scope);
    }
    function readCompletedGraph(scope, at) {
        const entry = completedGraph.get(scope);
        if (!entry) return null;
        if (entry.expiresAt <= at) {
            removeCompletedGraph(scope);
            return null;
        }
        completedGraph.delete(scope);
        completedGraph.set(scope, entry);
        return JSON.parse(entry.serialized);
    }
    function cacheCompletedGraph(scope, endpoint, result, at) {
        const unlicensed = isUnlicensedRiskyUsers(endpoint, result);
        if (!unlicensed && (!result?.ok || result.hasMore || result.warnings?.length)) return;
        const serialized = JSON.stringify(result);
        const bytes = Buffer.byteLength(serialized);
        if (bytes > GRAPH_RESULT_CACHE_MAX_ENTRY_BYTES) return;
        removeCompletedGraph(scope);
        const ttlMs = unlicensed ? 15 * 60000 : GRAPH_RESULT_CACHE_TTLS_MS[endpoint] || 30000;
        completedGraph.set(scope, { serialized, bytes, expiresAt: at + ttlMs });
        completedGraphBytes += bytes;
        while (completedGraph.size > GRAPH_RESULT_CACHE_MAX_ENTRIES || completedGraphBytes > GRAPH_RESULT_CACHE_MAX_BYTES) {
            removeCompletedGraph(completedGraph.keys().next().value);
        }
    }
    function isUnlicensedRiskyUsers(endpoint, result) {
        return endpoint === '/v1.0/identityProtection/riskyUsers' && result?.httpStatus === 403 &&
            /your tenant is not licensed for this feature/i.test(result.errorDetail || '');
    }
    let ready;
    function ensureSchema() {
        if (!persistenceEnabled) return Promise.resolve({ storageMode: 'memory_only' });
        if (!ready) ready = (async () => {
            for (const sql of SCHEMA) await pool.query(sql);
            const [indexes] = await pool.query("SELECT INDEX_NAME FROM information_schema.statistics WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'StackCTRLRawSecurityRecords' AND INDEX_NAME = 'ix_raw_company_time'");
            if (!indexes.length) {
                try { await pool.query('ALTER TABLE StackCTRLRawSecurityRecords ADD INDEX ix_raw_company_time (CompanyID, EventTime, RecordKey)'); }
                catch (error) { if (error.code !== 'ER_DUP_KEYNAME') throw error; }
            }
        })().catch(error => { ready = null; throw error; });
        return ready;
    }
    function hydrate(companyId) {
        if (!persistenceEnabled) return Promise.resolve();
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
        records.forEach(remember);
        if (!persistenceEnabled) return Promise.resolve({ stored: 0, storageMode: 'memory_only' });
        const task = (queues.get(companyId) || Promise.resolve()).then(async () => {
            await ensureSchema();
            const connection = await pool.getConnection();
            try {
                await connection.beginTransaction();
                if (assertGraphOwner && state?.provider === 'Microsoft Graph') await assertGraphOwner(connection, companyId);
                const changed = records.map(record => ({ record, digest: hash(JSON.stringify(record.rawPayload)), prior: persisted.get(record.uid) }))
                    .filter(item => item.digest !== item.prior?.digest || now().getTime() - item.prior.at >= 300000);
                for (let offset = 0; offset < changed.length; offset += 100) {
                    const batch = changed.slice(offset, offset + 100);
                    await connection.query(
                    `INSERT INTO StackCTRLRawSecurityRecords (CompanyID, RecordKey, Provider, Endpoint, ProviderRecordID, EventTime, FirstRetrievedAt, LastRetrievedAt, ProviderVersion, RecordJson)
                     VALUES ${batch.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ')} ON DUPLICATE KEY UPDATE
                     EventTime = IF(VALUES(ProviderVersion) >= ProviderVersion, VALUES(EventTime), EventTime), LastRetrievedAt = VALUES(LastRetrievedAt), RecordJson = IF(VALUES(ProviderVersion) >= ProviderVersion, VALUES(RecordJson), RecordJson), ProviderVersion = GREATEST(ProviderVersion, VALUES(ProviderVersion))`,
                    batch.flatMap(({ record }) => [companyId, hash(record.uid), record.provider, record.endpoint, String(record.id), Number.isFinite(Date.parse(record.timestamp)) ? new Date(record.timestamp).toISOString() : null, record.retrievedAt, record.retrievedAt, record.providerVersion || 0, JSON.stringify(record)]));
                }
                if (state && storageFailures.has(key(companyId, state.provider, state.endpoint))) { state.complete = false; state.status = 'partial'; state.continuation = null; state.storageError = 'An earlier page failed to store; a full replay is required.'; }
                if (state) await connection.query(
                    `INSERT INTO StackCTRLRawSecuritySync (CompanyID, SourceKey, StateJson) VALUES (?, ?, ?)
                     ON DUPLICATE KEY UPDATE StateJson = VALUES(StateJson)`, [companyId, hash(`${state.provider}:${state.endpoint}`), JSON.stringify({ ...state, storageStatus: 'stored' })]);
                if (assertGraphOwner && state?.provider === 'Microsoft Graph') await assertGraphOwner(connection, companyId);
                await connection.commit();
                for (const { record, digest } of changed) { persisted.delete(record.uid); persisted.set(record.uid, { digest, at: now().getTime() }); }
                while (persisted.size > 10000) persisted.delete(persisted.keys().next().value);
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
    function collection(companyId, { onEvent = () => {}, range = {}, bypassGraphCache = false } = {}) {
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
                ...progress, storageStatus: persistenceEnabled ? 'pending' : 'memory_only', recordsRetrieved: (progress.recordsRetrieved ?? prior.recordsRetrieved ?? 0),
                lastSuccessAt: progress.complete ? at : prior.lastSuccessAt || null };
            states.set(sourceKey, state);
            emit({ type: 'records', records, source: publicState(state) });
            queue(companyId, records, state).then(() => {
                if (states.get(sourceKey) === state) { state.storageStatus = !persistenceEnabled ? 'memory_only' : storageFailures.has(sourceKey) ? 'partial' : 'stored'; if (!storageFailures.has(sourceKey)) delete state.storageError; }
                emit({ type: 'health', source: publicState(state) });
            }).catch(() => emit({ type: 'health', source: publicState(states.get(sourceKey)) }));
            return records;
        }
        function graph(options) {
            const scope = companyId + ':' + new URL(options.url).pathname + ':' +
                (range.explicit ? JSON.stringify(range) : 'live') + ':' + hash(options.token || '');
            const endpoint = new URL(options.url).pathname;
            if (activeGraph.has(scope)) return activeGraph.get(scope);
            const cacheable = !persistenceEnabled && !bypassGraphCache;
            const reuseLicenseFailure = !range.explicit && !bypassGraphCache && endpoint === '/v1.0/identityProtection/riskyUsers';
            const cached = cacheable || reuseLicenseFailure ? readCompletedGraph(scope, now().getTime()) : null;
            if (cached) return Promise.resolve(cached);
            const collect = async () => {
                const result = await collectGraph(options);
                if (withGraphOwnership && persistenceEnabled) await queues.get(companyId);
                return result;
            };
            const pending = Promise.resolve().then(() => withGraphOwnership
                ? withGraphOwnership(companyId, endpoint, collect) : collect()).then(result => {
                if (result?.status === 'already_running') {
                    return { ok: false, unavailable: true, value: [], recordsFetched: 0, attempts: 0, httpStatus: null,
                        errorCode: 'GRAPH_COLLECTION_ALREADY_RUNNING', warnings: ['This Security source is updating.'] };
                }
                if (cacheable || reuseLicenseFailure && isUnlicensedRiskyUsers(endpoint, result)) {
                    cacheCompletedGraph(scope, endpoint, result, now().getTime());
                }
                return result;
            }).finally(() => activeGraph.delete(scope));
            activeGraph.set(scope, pending);
            return pending;
        }
        async function collectGraph(options) {
            const monotonicNow = options.now || (() => performance.now());
            const timeoutMs = Math.min(300000, Math.max(1000, Number(options.timeoutMs) || 60000));
            const collectionDeadline = monotonicNow() + timeoutMs;
            options = { ...options, now: monotonicNow, collectionDeadline };
            const requestedUrl = new URL(options.url);
            const endpoint = requestedUrl.pathname;
            const previousState = states.get(key(companyId, 'Microsoft Graph', endpoint));
            const reconcile = !previousState?.lastReconciledAt || now().getTime() - Date.parse(previousState.lastReconciledAt) >= 3600000;
            const incremental = !range.explicit && !previousState?.requestedRange?.explicit && !reconcile && previousState?.completeThrough && ['stored', 'memory_only'].includes(previousState.storageStatus);
            const filterSince = incremental ? new Date(Math.max(Date.parse(range.since), Date.parse(previousState.completeThrough) - 300000)).toISOString() : range.since;
            if (range.since && ['/v1.0/security/alerts_v2', '/v1.0/security/incidents'].includes(endpoint)) {
                const field = range.explicit ? 'createdDateTime' : 'lastUpdateDateTime';
                requestedUrl.searchParams.set('$filter', field + ' ge ' + filterSince + ' and ' + field + ' le ' + range.until);
                options = { ...options, url: requestedUrl.toString() };
            }
            if (range.since && ['/v1.0/auditLogs/directoryAudits', '/v1.0/auditLogs/signIns'].includes(endpoint)) {
                const field = endpoint.endsWith('/signIns') ? 'createdDateTime' : 'activityDateTime';
                requestedUrl.searchParams.set('$filter', field + ' ge ' + filterSince + ' and ' + field + ' le ' + range.until);
                options = { ...options, url: requestedUrl.toString() };
            }
            const recordType = ({ alerts_v2: 'alert', incidents: 'incident', tiIndicators: 'indicator', signIns: 'signin', directoryAudits: 'directoryAudit', riskDetections: 'riskDetection', riskyUsers: 'riskyUser' })[endpoint.split('/').pop()] || 'event';
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
            const next = (resume && (!head.ok || (head.nextLink && (headOverlaps || resume === head.nextLink)))) ? resume : head.nextLink;
            let result = head;
            // A continuation cannot fix denied access or bypass Retry-After.
            const headBlocked = [401, 403, 429].includes(head.httpStatus);
            if (!headBlocked && next && (head.ok || resume) && monotonicNow() >= collectionDeadline) {
                result = { ...head, ok: false, hasMore: true, nextLink: next,
                    errorCode: 'GRAPH_COLLECTION_PAGINATION_TIMEOUT',
                    errorDetail: 'The Security source deadline was reached before its next page could be fetched.',
                    warnings: [...(head.warnings || []), 'The Security source deadline was reached before its next page could be fetched.'] };
            } else if (!headBlocked && next && (head.ok || resume)) {
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
                ...(complete && range.until && !range.explicit ? { completeThrough: range.until, ...(reconcile ? { lastReconciledAt: now().toISOString() } : {}) } : {}),
                pages: result.pageCount || 0, recordsRetrieved: result.recordsFetched || 0,
                continuation: headBlocked ? resume : result.nextLink || null,
                permissionErrors: [401, 403].includes(result.httpStatus) ? 1 : 0,
                failedRequests: result.failedRequests || (result.ok ? 0 : 1), rateLimits: result.rateLimits || 0,
                error: result.warnings?.join(' ') || null });
            return { ...result, value: combined };
        }
        return { graph, publish, getState: (provider, endpoint) => { const sourceKey = key(companyId, provider, endpoint); if (storageFailures.has(sourceKey)) { storageFailures.delete(sourceKey); return undefined; } const state = states.get(sourceKey); return state && (range.explicit ? JSON.stringify(state.requestedRange) === JSON.stringify(range) : !state.requestedRange?.explicit) ? state : undefined; }, health: () => healthMemory(companyId) };
    }
    function healthMemory(companyId) {
        const sources = [...states.entries()].filter(([k]) => k.startsWith(`${companyId}:`)).map(([, value]) => publicState(value));
        if (!sources.some(source => source.provider === 'Cloudflare' && source.endpoint.startsWith('/logpush/'))) sources.push({
            provider: 'Cloudflare', endpoint: '/logpush', status: 'not_observed', complete: false,
            limitation: 'No Logpush delivery has been observed for this company. Verify delivery jobs and account mapping for unsampled security event coverage.'
        });
        return sources;
    }
    async function health(companyId) {
        if (!persistenceEnabled) return { sources: healthMemory(companyId), stored: [], storageMode: 'memory_only', storageMessage: 'Security alert database storage is disabled. Recent originals are held temporarily in bounded memory; history comes from provider APIs.' };
        await hydrate(companyId);
        const [counts] = await pool.query('SELECT Provider AS provider, COUNT(*) AS recordsStored FROM StackCTRLRawSecurityRecords WHERE CompanyID = ? GROUP BY Provider', [companyId]);
        const sources = healthMemory(companyId);
        return { sources, stored: counts };
    }
    async function history(companyId, { after = '', since = null, until = null, pageSize = 500 } = {}) {
        if (!persistenceEnabled) {
            const limit = Math.min(1000, Math.max(1, Number(pageSize) || 500));
            const available = [...recent.values()].map(entry => entry.record).filter(record => {
                const eventTime = Date.parse(record.timestamp);
                const time = Number.isFinite(eventTime) ? eventTime : Date.parse(record.retrievedAt);
                return Number(record.companyId) === Number(companyId) && record.uid > after &&
                    (!since || time >= Date.parse(since)) && (!until || time <= Date.parse(until));
            }).sort((a, b) => a.uid < b.uid ? -1 : a.uid > b.uid ? 1 : 0);
            const records = available.slice(0, limit);
            return { records, next: available.length > limit ? records[records.length - 1].uid : null, storageMode: 'memory_only' };
        }
        const [rows] = await pool.query(
            `SELECT RecordKey, RecordJson FROM StackCTRLRawSecurityRecords WHERE CompanyID = ? AND RecordKey > ?
             AND (? IS NULL OR COALESCE(EventTime, LastRetrievedAt) >= ?) AND (? IS NULL OR COALESCE(EventTime, LastRetrievedAt) <= ?) ORDER BY RecordKey LIMIT ?`,
            [companyId, after, since, since, until, until, Math.min(1000, Math.max(1, Number(pageSize) || 500))]);
        return { records: rows.map(row => parse(row.RecordJson)), next: rows.length ? rows[rows.length - 1].RecordKey : null };
    }
    async function record(companyId, uid) {
        if (!Number.isInteger(companyId) || companyId <= 0 || typeof uid !== 'string' || !uid.startsWith(companyId + ':')) return null;
        const cached = recent.get(uid)?.record;
        if (cached) return cached;
        if (!persistenceEnabled) return null;
        const [rows] = await pool.query('SELECT RecordJson FROM StackCTRLRawSecurityRecords WHERE CompanyID = ? AND RecordKey = ? LIMIT 1', [companyId, hash(uid)]);
        const result = rows[0] ? parse(rows[0].RecordJson) : null;
        return result && Number(result.companyId) === companyId && result.uid === uid ? result : null;
    }
    function subscribe(companyId, callback) {
        if (!listeners.has(companyId)) listeners.set(companyId, new Set());
        listeners.get(companyId).add(callback);
        return () => { listeners.get(companyId)?.delete(callback); if (!listeners.get(companyId)?.size) listeners.delete(companyId); };
    }
    return { ensureSchema, collection, queue, hydrate, health, history, record, subscribe, sources: healthMemory, flush: companyId => queues.get(companyId) || Promise.resolve() };
}
function publicState(state = {}) {
    const { continuation, ...safe } = state;
    return { ...safe, resumable: Boolean(continuation) };
}
module.exports = { createRawEvidenceJournal, SCHEMA };
