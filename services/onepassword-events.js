const axios = require('axios');

const SECRET_NAME = 'ONEPASSWORD_EVENTS_BEARER_TOKEN';
const API_BASE_URL = 'https://events.1password.eu/api/v1';
const PAGE_SIZE = 100;
const INITIAL_LOOKBACK_DAYS = 120;
const REQUEST_TIMEOUT_MS = 15000;
const MAX_ANALYTICS_RANGE_DAYS = 366;
const EVENT_FEEDS = Object.freeze({
    signinattempts: {
        endpoint: 'signinattempts',
        fields: ['uuid', 'timestamp', 'category', 'type', 'client', 'location', 'target_user']
    },
    itemusages: {
        endpoint: 'itemusages',
        fields: ['uuid', 'timestamp', 'used_version', 'vault_uuid', 'item_uuid', 'action', 'user', 'client', 'location']
    },
    auditevents: {
        endpoint: 'auditevents',
        fields: ['uuid', 'timestamp', 'actor_uuid', 'actor_details', 'action', 'object_type', 'object_uuid', 'session', 'location']
    }
});

const EVENT_SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRL1PasswordEventSyncState (
        CompanyID BIGINT NOT NULL,
        EventType VARCHAR(32) NOT NULL,
        LastProcessedCursor TEXT NULL,
        LastSuccessfulSyncAt DATETIME(3) NULL,
        SyncStatus VARCHAR(20) NOT NULL DEFAULT 'idle',
        LastError VARCHAR(255) NULL,
        UpdatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (CompanyID, EventType),
        KEY ix_stackctrl_1password_sync_status (SyncStatus, UpdatedAt)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRL1PasswordEventMetadata (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        CompanyID BIGINT NOT NULL,
        EventType VARCHAR(32) NOT NULL,
        EventUUID VARCHAR(100) NOT NULL,
        EventTimestamp DATETIME(3) NULL,
        MetadataJson JSON NOT NULL,
        IngestedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        PRIMARY KEY (ID),
        UNIQUE KEY uq_stackctrl_1password_event (CompanyID, EventType, EventUUID),
        KEY ix_stackctrl_1password_timeline (CompanyID, EventTimestamp, ID),
        KEY ix_stackctrl_1password_event_type (CompanyID, EventType, EventTimestamp)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

class OnePasswordEventsError extends Error {
    constructor(code, publicMessage, statusCode = 502) {
        super(publicMessage);
        this.name = 'OnePasswordEventsError';
        this.code = code;
        this.statusCode = statusCode;
        this.publicMessage = publicMessage;
    }
}

function pickPrimitiveFields(value, allowedFields) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
    const result = {};
    for (const field of allowedFields) {
        const fieldValue = value[field];
        if (typeof fieldValue === 'string' || typeof fieldValue === 'number' || typeof fieldValue === 'boolean') {
            result[field] = typeof fieldValue === 'string' ? fieldValue.slice(0, 1000) : fieldValue;
        }
    }
    return Object.keys(result).length ? result : undefined;
}

function sanitizeEvent(feed, event) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) {
        throw new OnePasswordEventsError('invalid_event', '1Password returned an unexpected event format.');
    }

    const fields = EVENT_FEEDS[feed].fields;
    const metadata = {};
    for (const field of fields) {
        const value = event[field];
        if (['location'].includes(field)) {
            const safe = pickPrimitiveFields(value, ['country', 'region', 'city', 'latitude', 'longitude']);
            if (safe) metadata[field] = safe;
        } else if (['client'].includes(field)) {
            const safe = pickPrimitiveFields(value, [
                'name', 'app_name', 'app_version', 'platform', 'platform_version',
                'device_uuid', 'device_name', 'ip', 'ip_address'
            ]);
            if (safe) metadata[field] = safe;
        } else if (['target_user', 'actor_details', 'user'].includes(field)) {
            const safe = pickPrimitiveFields(value, ['uuid', 'name', 'email']);
            if (safe) metadata[field] = safe;
        } else if (field === 'session') {
            const safe = pickPrimitiveFields(value, ['uuid', 'login_time', 'device_uuid', 'ip']);
            if (safe) metadata[field] = safe;
        } else if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
            metadata[field] = typeof value === 'string' ? value.slice(0, 1000) : value;
        }
    }

    if (typeof metadata.uuid !== 'string' || !metadata.uuid) {
        throw new OnePasswordEventsError('invalid_event', '1Password returned an event without a valid identifier.');
    }
    return metadata;
}

function toMysqlDateTime(value) {
    if (typeof value !== 'string' || !value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date.toISOString().slice(0, 23).replace('T', ' ');
}

function analyticsText(value) {
    return ['string', 'number', 'boolean'].includes(typeof value) ? String(value).trim().slice(0, 160) : '';
}
function analyticsMetadata(value) {
    if (value && typeof value === 'object') return value;
    try { return JSON.parse(value) || {}; } catch (_) { return {}; }
}
function analyticsActor(metadata) {
    const actor = metadata.target_user || metadata.actor_details || metadata.user;
    return actor && typeof actor === 'object' ? analyticsText(actor.name || actor.email || actor.uuid) : analyticsText(actor);
}
function analyticsResult(metadata) {
    const value = `${analyticsText(metadata.category)} ${analyticsText(metadata.type)}`.toLowerCase();
    if (/fail|denied|reject|invalid|error|blocked/.test(value)) return 'failed';
    if (/success|succeed|allow|approved|complete|credentials_ok/.test(value)) return 'successful';
    return '';
}
function analyticsBuckets(map, limit = 12) {
    return [...map.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, limit).map(([label, count]) => ({ label, count }));
}

function classifyUpstreamError(error, feed, hadCursor, logger) {
    const status = Number(error?.response?.status) || 0;
    const code = String(error?.code || '');
    const detail = status ? `HTTP ${status}` : (code || 'network_error');
    logger.warn(`[1Password Events] ${feed} request failed (${detail}).`);

    if (status === 400 && hadCursor) {
        return new OnePasswordEventsError(
            'invalid_cursor',
            '1Password rejected the saved activity cursor. Contact an administrator to reset the sync checkpoint.'
        );
    }
    if (status === 400) {
        return new OnePasswordEventsError('bad_request', '1Password rejected the event request. Check the integration configuration.');
    }
    if (status === 401 || status === 403) {
        return new OnePasswordEventsError('upstream_auth', '1Password could not authorize access to this event feed.');
    }
    if (status === 404) {
        return new OnePasswordEventsError('upstream_not_found', 'The configured 1Password Events API endpoint was not found.');
    }
    if (error?.code === 'ECONNABORTED' || error?.code === 'ETIMEDOUT') {
        return new OnePasswordEventsError('upstream_timeout', '1Password did not respond in time. Please try again.');
    }
    return new OnePasswordEventsError('upstream_unavailable', '1Password activity is temporarily unavailable. Please try again.');
}

function createOnePasswordEventsService({ pool, getSecret, logger = console, post = axios.post } = {}) {
    if (!pool || typeof pool.query !== 'function') throw new Error('1Password Events integration requires a database pool.');
    if (typeof getSecret !== 'function') throw new Error('1Password Events integration requires the StackCTRL secret loader.');

    let schemaPromise = null;
    const activeSyncs = new Map();

    async function ensureSchema() {
        if (!schemaPromise) {
            schemaPromise = Promise.all(EVENT_SCHEMA.map(statement => pool.query(statement)))
                .catch(error => {
                    schemaPromise = null;
                    throw error;
                });
        }
        return schemaPromise;
    }

    async function readSyncState(companyId, feed) {
        const [rows] = await pool.query(
            'SELECT LastProcessedCursor, LastSuccessfulSyncAt, SyncStatus, LastError FROM StackCTRL1PasswordEventSyncState WHERE CompanyID = ? AND EventType = ? LIMIT 1',
            [companyId, feed]
        );
        return rows[0] || null;
    }

    async function setSyncStatus(companyId, feed, status, lastError = null, successAt = null) {
        await pool.query(
            `INSERT INTO StackCTRL1PasswordEventSyncState
                (CompanyID, EventType, SyncStatus, LastError, LastSuccessfulSyncAt)
             VALUES (?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                SyncStatus = VALUES(SyncStatus),
                LastError = VALUES(LastError),
                LastSuccessfulSyncAt = COALESCE(VALUES(LastSuccessfulSyncAt), LastSuccessfulSyncAt)`,
            [companyId, feed, status, lastError, successAt]
        );
    }

    async function persistPage(companyId, feed, cursor, events) {
        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();
            for (const metadata of events) {
                await connection.query(
                    `INSERT INTO StackCTRL1PasswordEventMetadata
                        (CompanyID, EventType, EventUUID, EventTimestamp, MetadataJson)
                     VALUES (?, ?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE
                        EventTimestamp = VALUES(EventTimestamp),
                        MetadataJson = VALUES(MetadataJson)`,
                    [companyId, feed, metadata.uuid, toMysqlDateTime(metadata.timestamp), JSON.stringify(metadata)]
                );
            }
            await connection.query(
                `INSERT INTO StackCTRL1PasswordEventSyncState
                    (CompanyID, EventType, LastProcessedCursor, SyncStatus, LastError)
                 VALUES (?, ?, ?, 'syncing', NULL)
                 ON DUPLICATE KEY UPDATE
                    LastProcessedCursor = VALUES(LastProcessedCursor),
                    SyncStatus = 'syncing',
                    LastError = NULL`,
                [companyId, feed, cursor]
            );
            await connection.commit();
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    }

    async function syncFeed(companyId, feed, token) {
        const initialState = await readSyncState(companyId, feed);
        let cursor = initialState?.LastProcessedCursor || null;
        let pages = 0;
        let processedEvents = 0;
        const seenCursors = new Set(cursor ? [cursor] : []);

        await setSyncStatus(companyId, feed, 'syncing');
        try {
            while (true) {
                const requestBody = cursor
                    ? { cursor }
                    : {
                        limit: PAGE_SIZE,
                        start_time: new Date(Date.now() - INITIAL_LOOKBACK_DAYS * 24 * 60 * 60 * 1000).toISOString()
                    };
                let response;
                try {
                    response = await post(`${API_BASE_URL}/${EVENT_FEEDS[feed].endpoint}`, requestBody, {
                        timeout: REQUEST_TIMEOUT_MS,
                        headers: {
                            Authorization: `Bearer ${token}`,
                            'Content-Type': 'application/json'
                        },
                        validateStatus: () => true
                    });
                } catch (error) {
                    throw classifyUpstreamError(error, feed, Boolean(cursor), logger);
                }

                const status = Number(response?.status) || 0;
                if (status < 200 || status >= 300) {
                    throw classifyUpstreamError({ response }, feed, Boolean(cursor), logger);
                }

                const page = response.data;
                if (!page || typeof page !== 'object' || !Array.isArray(page.items) ||
                    typeof page.has_more !== 'boolean' || typeof page.cursor !== 'string' || !page.cursor) {
                    throw new OnePasswordEventsError('invalid_response', '1Password returned an unexpected response format.');
                }

                const events = page.items.map(event => sanitizeEvent(feed, event));
                await persistPage(companyId, feed, page.cursor, events);
                pages += 1;
                processedEvents += events.length;
                cursor = page.cursor;

                if (!page.has_more) break;
                if (seenCursors.has(cursor)) {
                    throw new OnePasswordEventsError('repeated_cursor', '1Password repeated an activity cursor before pagination completed.');
                }
                seenCursors.add(cursor);
            }

            const completedAt = new Date();
            await setSyncStatus(companyId, feed, 'complete', null, completedAt);
            return {
                eventType: feed,
                pages,
                processedEvents,
                lastSuccessfulSyncAt: completedAt.toISOString()
            };
        } catch (error) {
            const publicMessage = error.publicMessage || 'Unable to synchronize 1Password activity.';
            try {
                await setSyncStatus(companyId, feed, 'failed', publicMessage);
            } catch (stateError) {
                logger.error(`[1Password Events] Could not persist ${feed} failure state (${stateError.code || 'database_error'}).`);
            }
            logger.error(`[1Password Events] ${feed} sync failed (${error.code || 'processing_error'}).`);
            throw error;
        }
    }

    async function readLatestEvents(companyId, limit = 36) {
        const [rows] = await pool.query(
            `SELECT EventType, EventTimestamp, MetadataJson
             FROM StackCTRL1PasswordEventMetadata
             WHERE CompanyID = ?
             ORDER BY EventTimestamp DESC, ID DESC
             LIMIT ?`,
            [companyId, limit]
        );
        return rows.map(row => {
            let metadata = row.MetadataJson;
            if (typeof metadata === 'string') metadata = JSON.parse(metadata);
            return {
                eventType: row.EventType,
                timestamp: metadata?.timestamp || row.EventTimestamp || null,
                metadata
            };
        });
    }

    async function getCompanyAnalytics(companyId, { startAt, endAt } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isInteger(numericCompanyId) || numericCompanyId <= 0) throw new OnePasswordEventsError('invalid_company', 'A valid tenant is required.', 400);
        const end = endAt ? new Date(endAt) : new Date();
        const start = startAt ? new Date(startAt) : new Date(end.getTime() - 7 * 86400000);
        if (Number.isNaN(start) || Number.isNaN(end) || start >= end) throw new OnePasswordEventsError('invalid_range', 'Choose a valid analytics date range.', 400);
        if (end - start > MAX_ANALYTICS_RANGE_DAYS * 86400000) throw new OnePasswordEventsError('range_too_large', 'The analytics date range cannot exceed 366 days.', 400);
        await ensureSchema();
        const [[rows], [states]] = await Promise.all([
            pool.query(`SELECT EventType, EventTimestamp, MetadataJson FROM StackCTRL1PasswordEventMetadata WHERE CompanyID = ? AND EventTimestamp >= ? AND EventTimestamp < ? ORDER BY EventTimestamp DESC, ID DESC`, [numericCompanyId, toMysqlDateTime(start.toISOString()), toMysqlDateTime(end.toISOString())]),
            pool.query(`SELECT EventType, LastProcessedCursor, LastSuccessfulSyncAt, SyncStatus, LastError, UpdatedAt FROM StackCTRL1PasswordEventSyncState WHERE CompanyID = ?`, [numericCompanyId])
        ]);
        const events = rows.map(row => { const metadata = analyticsMetadata(row.MetadataJson); return { eventType: row.EventType, timestamp: metadata.timestamp || row.EventTimestamp || null, metadata }; });
        const signIns = events.filter(event => event.eventType === 'signinattempts');
        const audits = events.filter(event => event.eventType === 'auditevents');
        const itemUsages = events.filter(event => event.eventType === 'itemusages');
        const users = new Set(), devices = new Set(), countries = new Map(), platforms = new Map(), eventTypes = new Map(), byUser = new Map(), byCountry = new Map(), byPlatform = new Map(), byType = new Map(), byHour = new Map(), timeline = new Map();
        const add = (map, value) => { if (value) map.set(value, (map.get(value) || 0) + 1); };
        let successful = 0, failed = 0, classified = 0;
        for (const event of events) {
            const metadata = event.metadata, client = metadata.client && typeof metadata.client === 'object' ? metadata.client : {};
            const actor = analyticsActor(metadata), country = analyticsText(metadata.location?.country), platform = analyticsText(client.platform || client.app_name || client.name), device = analyticsText(client.device_uuid || client.device_name);
            if (actor) users.add(actor); if (device) devices.add(device);
            add(countries, country); add(platforms, platform); add(eventTypes, analyticsText(metadata.action || metadata.type || metadata.category || metadata.object_type || event.eventType));
            if (event.eventType !== 'signinattempts') continue;
            add(byUser, actor); add(byCountry, country); add(byPlatform, platform); add(byType, analyticsText(metadata.type || metadata.category));
            const result = analyticsResult(metadata), date = new Date(event.timestamp);
            if (result) { classified += 1; if (result === 'successful') successful += 1; else failed += 1; }
            if (!Number.isNaN(date.getTime())) { add(byHour, `${String(date.getHours()).padStart(2, '0')}:00`); const bucket = date.toISOString().slice(0, 10), point = timeline.get(bucket) || { bucket, total: 0, successful: 0, failed: 0 }; point.total += 1; if (result) point[result] += 1; timeline.set(bucket, point); }
        }
        const location = metadata => [metadata.location?.city, metadata.location?.region, metadata.location?.country].map(analyticsText).filter(Boolean).join(', ') || null;
        const recentSignIns = signIns.slice(0, 50).map(event => ({ timestamp: event.timestamp, user: analyticsActor(event.metadata) || null, result: analyticsResult(event.metadata) || null, eventType: analyticsText(event.metadata.type || event.metadata.category) || null, platform: analyticsText(event.metadata.client?.platform || event.metadata.client?.app_name || event.metadata.client?.name) || null, location: location(event.metadata) }));
        const recentAudits = audits.slice(0, 50).map(event => ({ timestamp: event.timestamp, actor: analyticsActor(event.metadata) || null, action: analyticsText(event.metadata.action) || null, objectType: analyticsText(event.metadata.object_type) || null, objectId: analyticsText(event.metadata.object_uuid) || null, location: location(event.metadata) }));
        return { success: true, analytics: { range: { startAt: start.toISOString(), endAt: end.toISOString() }, metrics: { totalSignIns: signIns.length, ...(classified ? { successfulSignIns: successful, failedSignIns: failed } : {}), totalAuditEvents: audits.length, itemUsageEvents: itemUsages.length, ...(users.size ? { activeUsers: users.size } : {}), ...(devices.size ? { uniqueDevices: devices.size } : {}), totalEvents: events.length }, signIns: { total: signIns.length, ...(classified ? { successful, failed } : {}), timeline: [...timeline.values()].sort((a, b) => a.bucket.localeCompare(b.bucket)), byUser: analyticsBuckets(byUser), byCountry: analyticsBuckets(byCountry), byPlatform: analyticsBuckets(byPlatform), byType: analyticsBuckets(byType), byHour: analyticsBuckets(byHour, 24), recent: recentSignIns }, audit: { total: audits.length, recent: recentAudits }, summaries: { countries: analyticsBuckets(countries), platforms: analyticsBuckets(platforms), eventTypes: analyticsBuckets(eventTypes) } }, integration: states.map(row => ({ eventType: row.EventType, lastSuccessfulSyncAt: row.LastSuccessfulSyncAt || null, lastAttemptedSyncAt: row.UpdatedAt || null, status: row.SyncStatus || null, hasCursor: Boolean(row.LastProcessedCursor), lastError: row.LastError || null })) };
    }

    async function syncCompany(companyId) {
        const numericCompanyId = Number(companyId);
        if (!Number.isInteger(numericCompanyId) || numericCompanyId <= 0) {
            throw new OnePasswordEventsError('invalid_company', 'A valid tenant is required.', 400);
        }
        if (activeSyncs.has(numericCompanyId)) return activeSyncs.get(numericCompanyId);

        const syncPromise = (async () => {
            await ensureSchema();
            let token = '';
            try {
                token = String(await getSecret(SECRET_NAME) || '').trim();
            } catch (error) {
                logger.error(`[1Password Events] Secret lookup failed (${error.code || 'secret_manager_error'}).`);
            }
            if (!token) {
                const message = 'The 1Password integration is not configured. Contact an administrator.';
                await Promise.all(Object.keys(EVENT_FEEDS).map(feed =>
                    setSyncStatus(numericCompanyId, feed, 'failed', message)
                ));
                throw new OnePasswordEventsError(
                    'not_configured',
                    message,
                    503
                );
            }

            const feeds = [];
            for (const feed of Object.keys(EVENT_FEEDS)) {
                feeds.push(await syncFeed(numericCompanyId, feed, token));
            }
            const [states] = await pool.query(
                `SELECT EventType, LastSuccessfulSyncAt, SyncStatus, LastError
                 FROM StackCTRL1PasswordEventSyncState
                 WHERE CompanyID = ?`,
                [numericCompanyId]
            );
            return {
                success: true,
                tenant: { provider: '1Password', label: '1Password Tenant' },
                sync: feeds,
                state: states.map(row => ({
                    eventType: row.EventType,
                    lastSuccessfulSyncAt: row.LastSuccessfulSyncAt || null,
                    status: row.SyncStatus,
                    lastError: row.LastError || null
                })),
                events: await readLatestEvents(numericCompanyId)
            };
        })();
        activeSyncs.set(numericCompanyId, syncPromise);
        try {
            return await syncPromise;
        } finally {
            if (activeSyncs.get(numericCompanyId) === syncPromise) activeSyncs.delete(numericCompanyId);
        }
    }

    return { ensureSchema, syncCompany, getCompanyAnalytics };
}

module.exports = {
    API_BASE_URL,
    EVENT_FEEDS,
    EVENT_SCHEMA,
    INITIAL_LOOKBACK_DAYS,
    OnePasswordEventsError,
    createOnePasswordEventsService,
    sanitizeEvent
};
