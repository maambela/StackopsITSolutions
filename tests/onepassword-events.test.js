const test = require('node:test');
const assert = require('node:assert/strict');
const { createOnePasswordEventsService, sanitizeEvent } = require('../services/onepassword-events');
const { createOnePasswordEventsRouter } = require('../routes/onepassword-events');

function createMemoryPool() {
    const states = new Map();
    const events = new Map();
    const stateKey = (companyId, eventType) => `${companyId}:${eventType}`;
    const eventKey = (companyId, eventType, eventUuid) => `${companyId}:${eventType}:${eventUuid}`;

    function runQuery(sql, params = []) {
        if (sql.startsWith('CREATE TABLE')) return [[], []];

        if (sql.includes('SELECT LastProcessedCursor')) {
            const state = states.get(stateKey(params[0], params[1]));
            return [state ? [{ ...state }] : [], []];
        }

        if (sql.includes('SELECT EventType, LastSuccessfulSyncAt') || sql.includes('SELECT EventType, LastProcessedCursor, LastSuccessfulSyncAt')) {
            const rows = [...states.values()]
                .filter(row => row.CompanyID === params[0])
                .map(row => ({ ...row }));
            return [rows, []];
        }

        if (sql.includes('SELECT EventType, EventTimestamp, MetadataJson')) {
            const hasRange = params.length >= 3;
            const startAt = hasRange ? new Date(String(params[1]).replace(' ', 'T')) : null;
            const endAt = hasRange ? new Date(String(params[2]).replace(' ', 'T')) : null;
            const matchingRows = [...events.values()]
                .filter(row => row.CompanyID === params[0])
                .filter(row => !hasRange || (new Date(row.EventTimestamp) >= startAt && new Date(row.EventTimestamp) < endAt))
                .sort((a, b) => String(b.EventTimestamp || '').localeCompare(String(a.EventTimestamp || '')));
            const rows = (hasRange ? matchingRows : matchingRows.slice(0, Number(params[1])))
                .map(row => ({ ...row }));
            return [rows, []];
        }

        if (sql.includes('INSERT INTO StackCTRL1PasswordEventSyncState')) {
            const [companyId, eventType, status, lastError, successAt] = params;
            const key = stateKey(companyId, eventType);
            const previous = states.get(key) || { CompanyID: companyId, EventType: eventType, LastProcessedCursor: null };
            states.set(key, {
                ...previous,
                SyncStatus: status,
                LastError: lastError,
                LastSuccessfulSyncAt: successAt || previous.LastSuccessfulSyncAt || null
            });
            return [{ affectedRows: 1 }, []];
        }

        throw new Error(`Unexpected query: ${sql}`);
    }

    return {
        states,
        events,
        async query(sql, params) {
            return runQuery(sql, params);
        },
        async getConnection() {
            return {
                async beginTransaction() {},
                async commit() {},
                async rollback() {},
                release() {},
                async query(sql, params = []) {
                    if (sql.includes('INSERT INTO StackCTRL1PasswordEventMetadata')) {
                        const [companyId, eventType, eventUuid, eventTimestamp, metadataJson] = params;
                        events.set(eventKey(companyId, eventType, eventUuid), {
                            CompanyID: companyId,
                            EventType: eventType,
                            EventUUID: eventUuid,
                            EventTimestamp: eventTimestamp,
                            MetadataJson: metadataJson
                        });
                        return [{ affectedRows: 1 }, []];
                    }
                    if (sql.includes('INSERT INTO StackCTRL1PasswordEventSyncState')) {
                        const [companyId, eventType, cursor] = params;
                        const key = stateKey(companyId, eventType);
                        const previous = states.get(key) || { CompanyID: companyId, EventType: eventType, LastSuccessfulSyncAt: null };
                        states.set(key, {
                            ...previous,
                            LastProcessedCursor: cursor,
                            SyncStatus: 'syncing',
                            LastError: null
                        });
                        return [{ affectedRows: 1 }, []];
                    }
                    throw new Error(`Unexpected transaction query: ${sql}`);
                }
            };
        }
    };
}

test('1Password event sync paginates with cursor-only requests and resumes from each saved cursor', async () => {
    const pool = createMemoryPool();
    const requests = [];
    let round = 0;
    const service = createOnePasswordEventsService({
        pool,
        getSecret: async name => {
            assert.equal(name, 'ONEPASSWORD_EVENTS_BEARER_TOKEN');
            return 'unit-test-token';
        },
        logger: { warn() {}, error() {} },
        post: async (url, body, options) => {
            requests.push({ url, body, authorization: options.headers.Authorization });
            const feed = url.split('/').at(-1);
            if (round === 0 && body.limit === 100) {
                assert.equal(Number.isNaN(Date.parse(body.start_time)), false);
                assert.equal(Date.now() - Date.parse(body.start_time) < 120 * 24 * 60 * 60 * 1000 + 1000, true);
                return {
                    status: 200,
                    data: {
                        cursor: `${feed}-cursor-1`,
                        has_more: true,
                        items: feed === 'itemusages' ? [] : [{
                            uuid: `${feed}-event-1`,
                            timestamp: '2026-10-01T12:00:00Z',
                            action: 'login',
                            password: 'must-not-be-stored',
                            actor_details: { name: 'Test User', email: 'user@example.com', secret: 'excluded' }
                        }]
                    }
                };
            }
            if (round === 0) {
                assert.deepEqual(body, { cursor: `${feed}-cursor-1` });
                return {
                    status: 200,
                    data: {
                        cursor: `${feed}-cursor-2`,
                        has_more: false,
                        items: []
                    }
                };
            }
            assert.deepEqual(body, { cursor: `${feed}-cursor-2` });
            return {
                status: 200,
                data: { cursor: `${feed}-cursor-3`, has_more: false, items: [] }
            };
        }
    });

    const firstSync = await service.syncCompany(42);
    assert.equal(firstSync.success, true);
    assert.equal(firstSync.sync.length, 3);
    assert.equal(firstSync.sync.find(item => item.eventType === 'itemusages').processedEvents, 0);
    assert.equal(firstSync.events.length, 2);
    assert.equal(pool.states.get('42:itemusages').LastProcessedCursor, 'itemusages-cursor-2');
    assert.equal(pool.states.get('42:itemusages').SyncStatus, 'complete');

    for (const feed of ['signinattempts', 'itemusages', 'auditevents']) {
        const feedRequests = requests.filter(request => request.url.endsWith(`/${feed}`));
        assert.equal(feedRequests[0].body.limit, 100);
        assert.equal(typeof feedRequests[0].body.start_time, 'string');
        assert.deepEqual(feedRequests[1].body, { cursor: `${feed}-cursor-1` });
        assert.equal(feedRequests[0].authorization, 'Bearer unit-test-token');
    }
    round = 1;

    const secondSync = await service.syncCompany(42);
    assert.equal(secondSync.success, true);
    assert.equal(pool.states.get('42:itemusages').LastProcessedCursor, 'itemusages-cursor-3');
    assert.deepEqual(
        requests.filter(request => request.url.endsWith('/itemusages')).at(-1).body,
        { cursor: 'itemusages-cursor-2' }
    );
    assert.deepEqual(
        requests.filter(request => request.url.endsWith('/signinattempts')).at(-1).body,
        { cursor: 'signinattempts-cursor-2' }
    );
    assert.deepEqual(
        requests.filter(request => request.url.endsWith('/auditevents')).at(-1).body,
        { cursor: 'auditevents-cursor-2' }
    );

    for (const row of pool.events.values()) {
        const metadata = JSON.parse(row.MetadataJson);
        assert.equal('password' in metadata, false);
        assert.equal(metadata.actor_details?.secret, undefined);
    }
});

test('1Password upstream authentication errors are safe and never expose the token in logs or messages', async () => {
    const logged = [];
    const service = createOnePasswordEventsService({
        pool: createMemoryPool(),
        getSecret: async () => 'sensitive-test-token',
        logger: {
            warn: message => logged.push(message),
            error: message => logged.push(message)
        },
        post: async () => {
            const error = new Error('request failed');
            error.response = { status: 401 };
            throw error;
        }
    });

    await assert.rejects(service.syncCompany(42), error => {
        assert.equal(error.statusCode, 502);
        assert.match(error.publicMessage, /could not authorize/i);
        assert.equal(error.publicMessage.includes('sensitive-test-token'), false);
        return true;
    });
    assert.equal(logged.join('\n').includes('sensitive-test-token'), false);
});

test('1Password integration rejects malformed event pages without advancing the saved cursor', async () => {
    const pool = createMemoryPool();
    pool.states.set('42:signinattempts', {
        CompanyID: 42,
        EventType: 'signinattempts',
        LastProcessedCursor: 'old-cursor',
        LastSuccessfulSyncAt: null,
        SyncStatus: 'idle',
        LastError: null
    });
    const service = createOnePasswordEventsService({
        pool,
        getSecret: async () => 'unit-test-token',
        logger: { warn() {}, error() {} },
        post: async () => ({ status: 200, data: { cursor: 'new-cursor', has_more: true, items: 'invalid' } })
    });

    await assert.rejects(service.syncCompany(42), error => {
        assert.equal(error.code, 'invalid_response');
        return true;
    });
    assert.equal(pool.states.get('42:signinattempts').LastProcessedCursor, 'old-cursor');
    assert.equal(pool.states.get('42:signinattempts').SyncStatus, 'failed');
});

test('1Password item usage payloads are reduced to event metadata only', () => {
    const metadata = sanitizeEvent('itemusages', {
        uuid: 'event-1',
        timestamp: '2026-10-01T12:00:00Z',
        used_version: 3,
        vault_uuid: 'vault-1',
        item_uuid: 'item-1',
        action: 'reveal',
        user: { uuid: 'user-1', name: 'Test User', email: 'user@example.com', password: 'excluded' },
        client: { name: '1Password', platform: 'macOS', app_version: '8.0', vault_contents: 'excluded' },
        location: { country: 'ZA', city: 'Cape Town', latitude: -33.9, secret: 'excluded' },
        item_title: 'must-not-be-stored',
        item_secret: 'must-not-be-stored'
    });

    assert.deepEqual(metadata, {
        uuid: 'event-1',
        timestamp: '2026-10-01T12:00:00Z',
        used_version: 3,
        vault_uuid: 'vault-1',
        item_uuid: 'item-1',
        action: 'reveal',
        user: { uuid: 'user-1', name: 'Test User', email: 'user@example.com' },
        client: { name: '1Password', platform: 'macOS', app_version: '8.0' },
        location: { country: 'ZA', city: 'Cape Town', latitude: -33.9 }
    });
});

test('1Password sign-in payloads retain the requested metadata and filter nested fields', () => {
    const metadata = sanitizeEvent('signinattempts', {
        uuid: 'signin-1',
        timestamp: '2026-10-01T12:00:00Z',
        category: 'success',
        type: 'credentials_ok',
        client: { name: '1Password', platform: 'iOS', app_version: '8.0', access_token: 'excluded' },
        location: { country: 'ZA', city: 'Cape Town', token: 'excluded' },
        target_user: { uuid: 'user-1', name: 'Test User', email: 'user@example.com', secret: 'excluded' },
        password: 'excluded'
    });

    assert.deepEqual(metadata, {
        uuid: 'signin-1',
        timestamp: '2026-10-01T12:00:00Z',
        category: 'success',
        type: 'credentials_ok',
        client: { name: '1Password', platform: 'iOS', app_version: '8.0' },
        location: { country: 'ZA', city: 'Cape Town' },
        target_user: { uuid: 'user-1', name: 'Test User', email: 'user@example.com' }
    });
});

test('1Password sync maps upstream errors to safe client messages and retains an invalid cursor', async () => {
    const cases = [
        { status: 400, cursor: null, code: 'bad_request' },
        { status: 400, cursor: 'saved-cursor', code: 'invalid_cursor' },
        { status: 401, cursor: null, code: 'upstream_auth' },
        { status: 403, cursor: null, code: 'upstream_auth' },
        { status: 404, cursor: null, code: 'upstream_not_found' },
        { status: 503, cursor: null, code: 'upstream_unavailable' },
        { errorCode: 'ECONNABORTED', cursor: null, code: 'upstream_timeout' },
        { errorCode: 'ENOTFOUND', cursor: null, code: 'upstream_unavailable' }
    ];

    for (const [index, entry] of cases.entries()) {
        const pool = createMemoryPool();
        if (entry.cursor) {
            pool.states.set(`${index + 1}:signinattempts`, {
                CompanyID: index + 1,
                EventType: 'signinattempts',
                LastProcessedCursor: entry.cursor,
                LastSuccessfulSyncAt: null,
                SyncStatus: 'idle',
                LastError: null
            });
        }
        const service = createOnePasswordEventsService({
            pool,
            getSecret: async () => 'unit-test-token',
            logger: { warn() {}, error() {} },
            post: async () => {
                const error = new Error('opaque upstream failure');
                if (entry.status) error.response = { status: entry.status };
                if (entry.errorCode) error.code = entry.errorCode;
                throw error;
            }
        });

        await assert.rejects(service.syncCompany(index + 1), error => {
            assert.equal(error.code, entry.code);
            assert.equal(error.publicMessage.includes('unit-test-token'), false);
            return true;
        });
        if (entry.cursor) {
            assert.equal(pool.states.get(`${index + 1}:signinattempts`).LastProcessedCursor, entry.cursor);
        }
    }
});

test('1Password analytics derives an audit timeline and only reports explicit sign-in results', async () => {
    const pool = createMemoryPool();
    const service = createOnePasswordEventsService({ pool, getSecret: async () => 'unit-test-token', logger: { warn() {}, error() {} }, post: async () => ({}) });
    const addEvent = (key, eventType, timestamp, metadata) => pool.events.set(key, {
        CompanyID: 44,
        EventType: eventType,
        EventTimestamp: timestamp,
        MetadataJson: JSON.stringify({ timestamp, ...metadata })
    });

    addEvent('signin-success', 'signinattempts', '2026-09-29T08:00:00.000Z', { category: 'credentials_ok', actor_details: { name: 'Ava' } });
    addEvent('signin-failed', 'signinattempts', '2026-09-30T08:00:00.000Z', { category: 'login_failed', actor_details: { name: 'Ava' } });
    addEvent('signin-unclassified', 'signinattempts', '2026-09-30T09:00:00.000Z', { category: 'new_signin_signal' });
    addEvent('audit-first', 'auditevents', '2026-09-29T10:00:00.000Z', { action: 'item_updated' });
    addEvent('audit-second', 'auditevents', '2026-09-30T10:00:00.000Z', { action: 'item_created' });

    const result = await service.getCompanyAnalytics(44, {
        startAt: '2026-09-28T00:00:00.000Z',
        endAt: '2026-10-01T00:00:00.000Z'
    });

    assert.equal(result.analytics.metrics.totalSignIns, 3);
    assert.equal(result.analytics.metrics.successfulSignIns, 1);
    assert.equal(result.analytics.metrics.failedSignIns, 1);
    assert.deepEqual(result.analytics.audit.timeline, [
        { bucket: '2026-09-29', total: 1 },
        { bucket: '2026-09-30', total: 1 }
    ]);
});

test('1Password sync route requires a mapped Sunbird tenant and prevents response caching', async () => {
    let serviceCalls = 0;
    const router = createOnePasswordEventsRouter({
        authenticateToken(_req, _res, next) { next(); },
        getAccessContextByUser: async user => user.accessContext,
        onePasswordEventsService: {
            async syncCompany(companyId) {
                serviceCalls += 1;
                return { success: true, companyId };
            }
        },
        logger: { error() {} }
    });
    const route = router.stack.find(layer => layer.route?.path === '/sync').route.stack
        .find(layer => layer.method === 'post').handle;

    function makeResponse() {
        return {
            headers: {},
            statusCode: 200,
            body: null,
            set(name, value) { this.headers[name] = value; return this; },
            status(code) { this.statusCode = code; return this; },
            json(body) { this.body = body; return this; }
        };
    }

    const denied = makeResponse();
    await route({ user: { accessContext: { companyId: 55, accessType: 'standard' } } }, denied);
    assert.equal(denied.statusCode, 403);
    assert.equal(serviceCalls, 0);

    const allowed = makeResponse();
    await route({ user: { accessContext: { companyId: 55, hasSunbirdAccess: true } } }, allowed);
    assert.equal(allowed.statusCode, 200);
    assert.equal(allowed.headers['Cache-Control'], 'no-store');
    assert.deepEqual(allowed.body, { success: true, companyId: 55 });
    assert.equal(serviceCalls, 1);
});
