const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const server = fs.readFileSync(require.resolve('../server'), 'utf8');
function section(start, end) {
    const from = server.indexOf(start);
    const to = server.indexOf(end, from + start.length);
    assert.ok(from >= 0 && to > from);
    return server.slice(from, to);
}

test('authentication methods reuse successful results for five minutes, scoped by bearer and user', async () => {
    let now = 0;
    let fail = false;
    const requests = [];
    const authMethodsCache = new Map();
    const fetchMethods = vm.runInNewContext([
        section('function getCachedAuthMethods', 'function hasRealMfaMethod'),
        section('async function fetchUserAuthMethods', '// APPLICATIONS & SERVICE PRINCIPALS'),
        'fetchUserAuthMethods;'
    ].join('\n'), {
        crypto, authMethodsCache,
        AUTH_METHODS_CACHE_TTL_MS: 300000,
        AUTH_METHODS_CACHE_MAX_ENTRIES: 3,
        Date: { now: () => now },
        console: { error() {} },
        async fetchMicrosoftGraphJson(url, bearer, label, options) {
            requests.push({ url, bearer, options });
            if (fail) throw new Error('Graph failed (429)');
            return { value: url.includes('/empty/') ? [] : [{ id: bearer + ':' + url.split('/')[5] }] };
        }
    });
    const first = await fetchMethods('tenant-a-bearer', 'same-user');
    assert.equal(await fetchMethods('tenant-a-bearer', 'same-user'), first);
    assert.notDeepEqual(await fetchMethods('tenant-b-bearer', 'same-user'), first);
    assert.notDeepEqual(await fetchMethods('tenant-a-bearer', 'other-user'), first);
    now = 299999;
    assert.equal(await fetchMethods('tenant-a-bearer', 'same-user'), first);
    assert.equal(requests.length, 3);
    assert.equal(requests[0].options.retries, 2);
    assert.equal(requests[0].options.retryTimeouts, false);
    now = 300000;
    fail = true;
    assert.equal((await fetchMethods('tenant-a-bearer', 'same-user')).length, 0);
    assert.equal((await fetchMethods('tenant-a-bearer', 'same-user')).length, 0);
    assert.equal(requests.length, 5, 'a failure must never become a cached empty success');
    fail = false;
    assert.equal((await fetchMethods('tenant-a-bearer', 'empty')).length, 0);
    assert.equal((await fetchMethods('tenant-a-bearer', 'empty')).length, 0);
    assert.equal(requests.length, 6);
    await fetchMethods('tenant-a-bearer', 'another-user');
    assert.equal(authMethodsCache.size, 3);
    assert.ok([...authMethodsCache.keys()].every(key => !key.includes('bearer')));
});

test('standard sign-ins reuse the URL within a minute and keep different lookback windows distinct', async () => {
    let now = Date.parse('2026-11-23T07:30:00Z');
    const calls = [];
    const signIns = vm.runInNewContext(section('async function fetchMicrosoftSignIns', 'async function fetchUserAuthMethods') +
        '\nfetchMicrosoftSignIns;', {
        Date: class extends Date { static now() { return now; } },
        fetchMicrosoftGraphJson: async url => { calls.push(new URL(url)); return { value: [] }; }
    });
    await signIns('fixture');
    now += 59999;
    await signIns('fixture');
    await signIns('fixture', 1);
    now++;
    await signIns('fixture');

    assert.equal(calls[0].href, calls[1].href);
    assert.notEqual(calls[1].href, calls[2].href);
    assert.match(calls[0].searchParams.get('$filter'), /:30:00\.000Z$/);
    assert.match(calls[3].searchParams.get('$filter'), /:31:00\.000Z$/);
});

test('Identity sign-ins retain page-cap partial results and report request timeouts as unavailable', async () => {
    let fail = false;
    let options;
    const signIns = vm.runInNewContext(section('async function fetchMicrosoftSignIns', 'async function fetchUserAuthMethods') +
        '\nfetchMicrosoftSignIns;', {
        console: { error() {} },
        async fetchMicrosoftGraphJson(url, token, label, requestOptions) {
            options = requestOptions;
            if (fail) {
                const error = new Error('Graph sign-in request timed out');
                error.code = 'GRAPH_REQUEST_TIMEOUT';
                throw error;
            }
            return {
                value: [{ id: 'last-collected-page' }],
                collectionStatus: 'partial',
                collectionWarnings: ['Sign-in collection reached the 5,000-record page cap.'],
                collectionErrorCode: 'GRAPH_PAGE_LIMIT'
            };
        }
    });

    const partial = await signIns('fixture', 30, { withStatus: true });
    assert.equal(options.paginate, true);
    assert.equal(options.allowPartial, true);
    assert.equal(partial.status, 'partial');
    assert.deepEqual(partial.records.map(record => record.id), ['last-collected-page']);
    assert.equal(partial.errorCode, 'GRAPH_PAGE_LIMIT');
    assert.match(partial.warnings[0], /5,000-record page cap/);

    fail = true;
    const unavailable = await signIns('fixture', 30, { withStatus: true });
    assert.equal(unavailable.status, 'unavailable');
    assert.equal(unavailable.records.length, 0);
    assert.equal(unavailable.errorCode, 'GRAPH_REQUEST_TIMEOUT');
});

test('concurrent authentication-method cache misses still share one Graph request', async () => {
    let calls = 0;
    let finish;
    const load = vm.runInNewContext([
        section('function getCachedAuthMethods', 'function hasRealMfaMethod'),
        section('function isRetryableGraphError', 'function beginSunbirdOperation'),
        section('async function fetchUserAuthMethods', '// APPLICATIONS & SERVICE PRINCIPALS'),
        'fetchUserAuthMethods;'
    ].join('\n'), {
        crypto,
        authMethodsCache: new Map(),
        microsoftGraphJsonCache: new Map(),
        microsoftGraphJsonPromises: new Map(),
        AUTH_METHODS_CACHE_TTL_MS: 300000,
        AUTH_METHODS_CACHE_MAX_ENTRIES: 4096,
        MICROSOFT_GRAPH_SHARED_CACHE_TTL_MS: 60000,
        logRuntimeOperation() {},
        fetchMicrosoftGraphJsonAttempt() {
            calls++;
            return new Promise(resolve => { finish = resolve; });
        }
    });
    const first = load('tenant-a-bearer', 'same-user');
    const joined = load('tenant-a-bearer', 'same-user');
    assert.equal(calls, 1);
    const methods = [{ id: 'method' }];
    finish({ payload: { value: methods }, responseBytes: 27 });
    assert.equal(await first, methods);
    assert.equal(await joined, methods);
    assert.equal(await load('tenant-a-bearer', 'same-user'), methods);
    assert.equal(calls, 1);
});

test('Security history passes the exact requested sign-in instants through to Graph', async () => {
    const since = '2026-11-01T07:30:12.345Z';
    const until = '2026-11-23T07:30:54.321Z';
    let requested;
    const securitySignIns = vm.runInNewContext(section('async function fetchSecuritySignInRows', 'function ') +
        '\nfetchSecuritySignInRows;', {
        process: { env: {} },
        SECURITY_SIGNINS_FETCH_TIMEOUT_MS: 60000,
        SECURITY_SIGNINS_PAGE_DELAY_MS: 1000,
        fetchGraphCollectionPagesWithRetry: async ({ url }) => {
            requested = new URL(url);
            return { ok: true, value: [], warnings: [] };
        },
        console: { log() {} }
    });
    await securitySignIns('fixture', { range: { since, until, explicit: true } });
    assert.equal(requested.searchParams.get('$filter'), `createdDateTime ge ${since} and createdDateTime le ${until}`);
});
