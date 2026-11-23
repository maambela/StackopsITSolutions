const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { createGraphCoordinator } = require('../services/intelligence/microsoft-graph-coordinator');
const { fetchGraphCollectionPagesWithRetry } = require('../services/intelligence/microsoft-graph-collection');

test('bounds active requests and the queue, and never dispatches cancelled entries', async () => {
    const coordinator = createGraphCoordinator({ concurrency: 1, maxQueued: 1 });
    const signal = new AbortController().signal;
    let finish;
    const active = coordinator.run(signal, () => new Promise(resolve => { finish = resolve; }));
    const queued = new AbortController();
    const cancelled = coordinator.run(queued.signal, () => assert.fail('cancelled work was dispatched'));
    await assert.rejects(coordinator.run(signal, () => assert.fail('full queue accepted work')), { code: 'GRAPH_QUEUE_FULL' });
    queued.abort();
    await assert.rejects(cancelled, { name: 'AbortError' });
    let dispatched = false;
    const next = coordinator.run(signal, () => { dispatched = true; return 'next'; });
    assert.equal(dispatched, false);
    finish('first');
    assert.equal(await active, 'first');
    assert.equal(await next, 'next');
});

test('releases the permit after a failed operation', async () => {
    const coordinator = createGraphCoordinator({ concurrency: 1 });
    const signal = new AbortController().signal;
    const failed = coordinator.run(signal, async () => { throw new Error('body failed'); });
    const next = coordinator.run(signal, () => 'next');
    await assert.rejects(failed, /body failed/);
    assert.equal(await next, 'next');
});

test('dashboard collections join identical work, cache complete pages and isolate credentials', async () => {
    const source = fs.readFileSync(require.resolve('../server'), 'utf8');
    const start = source.indexOf('async function fetchMicrosoftGraphJson(url');
    const end = source.indexOf('function beginSunbirdOperation', start);
    const requests = [];
    const events = [];
    let continuation = 'https://graph.microsoft.com/v1.0/users?page=2';
    const load = vm.runInNewContext(source.slice(start, end) + '\nfetchMicrosoftGraphJson;', {
        crypto, Buffer,
        microsoftGraphJsonCache: new Map(),
        microsoftGraphJsonPromises: new Map(),
        MICROSOFT_GRAPH_MAX_RESPONSE_BYTES: 4096,
        MICROSOFT_GRAPH_REQUEST_TIMEOUT_MS: 15000,
        MICROSOFT_GRAPH_SHARED_CACHE_TTL_MS: 60000,
        logRuntimeOperation: (event, fields) => events.push({ event, ...fields }),
        readBoundedResponseText: async response => response.text(),
        fetchGraphCollectionPagesWithRetry: options => fetchGraphCollectionPagesWithRetry({
            ...options,
            fetchImpl: async (url, init) => {
                requests.push({ url, bearer: init.headers.Authorization });
                const firstPage = !new URL(url).searchParams.has('page');
                return new Response(JSON.stringify({
                    value: [{ id: firstPage ? 'first' : 'second' }],
                    ...(firstPage ? { '@odata.nextLink': continuation } : {})
                }));
            }
        })
    });
    const url = 'https://graph.microsoft.com/v1.0/users';
    const list = token => load(url, token, 'Microsoft Graph users', { paginate: true });
    const [first, joined] = await Promise.all([list('credential-a'), list('credential-a')]);
    assert.equal(first, joined);
    assert.deepEqual(first.value.map(row => row.id), ['first', 'second']);
    assert.equal(await list('credential-a'), first);
    assert.equal(requests.length, 2);
    await list('credential-b');
    assert.equal(requests.length, 4);
    assert.equal(requests[2].bearer, 'Bearer credential-b');

    continuation = 'https://example.invalid/users';
    await assert.rejects(list('credential-c'), /invalid next link/);
    await assert.rejects(list('credential-c'), /invalid next link/);
    assert.equal(requests.length, 6);
    assert.equal(events.filter(event => event.event === 'graph_collection_result' && !event.complete).length, 2);
});

test('the periodic cache worker skips overlap and runs again after failure', async () => {
    const source = fs.readFileSync(require.resolve('../server'), 'utf8');
    const start = source.indexOf('let dashboardMetricRefreshRunning');
    const end = source.indexOf("app.get('/api/db/identity-metrics'", start);
    const skipped = [];
    let tick;
    let finish;
    let calls = 0;
    vm.runInNewContext(source.slice(start, end), {
        setInterval: callback => { tick = callback; },
        logRuntimeOperation: event => skipped.push(event),
        console: { error() {} },
        upsertDashboardMetricCaches: () => {
            calls++;
            return new Promise(resolve => { finish = resolve; }).then(() => { throw new Error('fixture'); });
        }
    });
    const first = tick();
    await tick();
    assert.equal(calls, 1);
    assert.deepEqual(skipped, ['dashboard_cache_refresh_skipped_overlap']);
    finish();
    await first;
    const next = tick();
    assert.equal(calls, 2);
    finish();
    await next;
});
