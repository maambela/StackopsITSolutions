const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const server = fs.readFileSync(require.resolve('../server'), 'utf8');
const start = server.indexOf('async function getMicrosoftGraphToken(options');
const end = server.indexOf('const MICROSOFT_GRAPH_REQUEST_TIMEOUT_MS', start);

function createHarness(fetchToken, { fetchResponse, timers = { setTimeout, clearTimeout } } = {}) {
    let now = 0;
    const requests = [];
    const microsoftTokenCache = new Map();
    const getToken = vm.runInNewContext(`let microsoftGraphTokenPromise = null;\n${server.slice(start, end)}\ngetMicrosoftGraphToken;`, {
        microsoftTokenCache,
        MICROSOFT_GRAPH_TOKEN_TIMEOUT_MS: 1000,
        getMicrosoftGraphCredentials: async () => ({ tenantId: 'tenant', clientId: 'client', clientSecret: 'fixture' }),
        fetch: async (url, options) => {
            requests.push({ url, options });
            if (fetchResponse) return fetchResponse(options.signal, requests.length);
            return { ok: true, json: () => fetchToken(requests.length) };
        },
        Date: { now: () => now },
        console: { log() {}, error() {} },
        AbortController,
        URLSearchParams,
        ...timers
    });
    return { getToken, requests, microsoftTokenCache, advance: ms => { now += ms; } };
}

test('reuses a valid token and coalesces concurrent refreshes at the margin', async () => {
    const { getToken, requests, advance } = createHarness(call => ({ access_token: `token-${call}`, expires_in: '120' }));
    assert.deepEqual(await Promise.all([getToken(), getToken()]), ['token-1', 'token-1']);
    advance(59999);
    assert.equal(await getToken(), 'token-1');
    advance(1);
    assert.deepEqual(await Promise.all([getToken(), getToken()]), ['token-2', 'token-2']);
    assert.equal(requests.length, 2);
    const { url, options } = requests[0];
    assert.equal(url, 'https://login.microsoftonline.com/tenant/oauth2/v2.0/token');
    assert.equal(options.method, 'POST');
    const form = new URLSearchParams(options.body);
    assert.equal(form.get('grant_type'), 'client_credentials');
    assert.equal(form.get('scope'), 'https://graph.microsoft.com/.default');
});

function controlledDeadline() {
    let callback;
    return {
        setTimeout(handler, delay) {
            assert.equal(delay, 1000);
            callback = handler;
            return 1;
        },
        clearTimeout() { callback = undefined; },
        fire() {
            assert.ok(callback, 'deadline must be active');
            callback();
        },
        get active() { return Boolean(callback); }
    };
}

function stallUntilAborted(signal) {
    return new Promise((resolve, reject) => {
        signal.addEventListener('abort', () => {
            reject(new DOMException('This operation was aborted', 'AbortError'));
        }, { once: true });
    });
}

for (const phase of ['headers', 'success body', 'HTTP-error body']) {
    test(`times out during ${phase} and clears the shared acquisition`, async () => {
        const timers = controlledDeadline();
        let reachedStall;
        const stalled = new Promise(resolve => { reachedStall = resolve; });
        const stall = signal => {
            reachedStall();
            return stallUntilAborted(signal);
        };
        const { getToken, requests, microsoftTokenCache } = createHarness(undefined, {
            timers,
            fetchResponse(signal, call) {
                if (call > 1) return { ok: true, json: async () => ({ access_token: 'fresh', expires_in: 120 }) };
                if (phase === 'headers') return stall(signal);
                return { ok: phase === 'success body', json: () => stall(signal) };
            }
        });

        const results = Promise.allSettled([getToken(), getToken()]);
        await stalled;
        assert.equal(requests.length, 1);
        timers.fire();
        const [first, second] = await results;
        assert.equal(first.status, 'rejected');
        assert.equal(second.status, 'rejected');
        assert.equal(first.reason.code, 'GRAPH_TOKEN_TIMEOUT');
        assert.equal(second.reason, first.reason);
        assert.equal(timers.active, false);
        assert.equal(microsoftTokenCache.size, 0);
        assert.equal(await getToken(), 'fresh');
        assert.equal(requests.length, 2);
        assert.equal(timers.active, false);
    });
}

test('preserves a non-deadline failure code and clears the timer', async () => {
    const timers = controlledDeadline();
    const error = Object.assign(new Error('connection reset'), { code: 'ECONNRESET' });
    const { getToken } = createHarness(undefined, {
        timers,
        fetchResponse: async () => { throw error; }
    });
    await assert.rejects(getToken(), failure => failure === error);
    assert.equal(timers.active, false);
});

test('keeps the timer active until a complete response body arrives', async () => {
    const timers = controlledDeadline();
    const { getToken, requests } = createHarness(undefined, {
        timers,
        fetchResponse: async () => ({
            ok: true,
            json: async () => {
                assert.equal(timers.active, true);
                return { access_token: 'complete', expires_in: 120 };
            }
        })
    });
    assert.equal(await getToken(), 'complete');
    assert.equal(timers.active, false);
    assert.equal(await getToken(), 'complete');
    assert.equal(requests.length, 1);
});

test('rejects missing or unusable expiry metadata and allows the next acquisition', async () => {
    const invalidLifetimes = [undefined, null, '', 0, -1, 'invalid', 'Infinity', true];
    const { getToken, microsoftTokenCache } = createHarness(call => ({
        access_token: 'fixture', expires_in: call <= invalidLifetimes.length ? invalidLifetimes[call - 1] : 120
    }));
    for (const lifetime of invalidLifetimes) {
        await assert.rejects(getToken(), /invalid expires_in/, String(lifetime));
        assert.equal(microsoftTokenCache.size, 0);
    }
    assert.equal(await getToken(), 'fixture');
});

test('counts acquisition delay against token lifetime and never falls back to the expired cache entry', async () => {
    const harness = createHarness(call => {
        if (call === 2) harness.advance(61000);
        return { access_token: `token-${call}`, expires_in: 120 };
    });
    assert.equal(await harness.getToken(), 'token-1');
    harness.advance(120000);
    await assert.rejects(harness.getToken(), /60-second refresh window/);
    assert.equal(harness.microsoftTokenCache.size, 0);
    assert.equal(await harness.getToken(), 'token-3');
});
