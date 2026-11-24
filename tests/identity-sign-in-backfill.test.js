const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { backfillPlan, nextBackfillRange, finishBackfillRange, withBackfillLock, mergeBackfillUsers } =
    require('../services/intelligence/identity-sign-in-backfill');
const now = Date.parse('2026-11-24T12:00:00Z');
const day = 86400000;

test('daily automation awaits a bounded backfill without a browser trigger', async () => {
    const source = fs.readFileSync(require.resolve('../server'), 'utf8');
    const client = fs.readFileSync(require.resolve('../js/clientportal'), 'utf8');
    const start = source.indexOf('async function runScheduledIdentityBackfill');
    const end = source.indexOf('async function collectIdentityEvidenceForConfiguredTenants', start);
    let calls = 0;
    const run = vm.runInNewContext(source.slice(start, end) + '\nrunScheduledIdentityBackfill;', {
        getIdentityEvidenceCompanies: async () => [{ CompanyID: 42 }],
        runIdentityBackfillStep: async companyId => {
            assert.equal(companyId, 42);
            await new Promise(setImmediate);
            calls++;
            return true;
        }
    });
    assert.equal(await run(), 3);
    assert.equal(calls, 3);
    assert.match(source, /await runScheduledIdentityBackfill\(\)/);
    assert.doesNotMatch(client, /\/api\/sunbird\/identity-sign-in-backfill/);
});

test('completed ranges and verified 2-, 10-, and 25-day events survive a restart', () => {
    let state = backfillPlan(null, now);
    for (const age of [2, 10, 25]) {
        const time = now - age * day;
        const range = state.ranges.find(row => row.start <= time && time < row.end);
        finishBackfillRange(state, range, { ok: true, value: [{ userId: 'user-' + age, createdDateTime: new Date(time).toISOString() }] }, now);
    }
    state = backfillPlan(JSON.parse(JSON.stringify(state)), now);
    assert.equal(state.ranges.filter(range => range.status === 'complete').length, 3);
    const users = mergeBackfillUsers([2, 10, 25].map(age => ({ id: 'user-' + age })), state, null, null, now);
    assert.deepEqual(users.map(user => Date.parse(user.lastSignIn.dateTime)), [2, 10, 25].map(age => now - age * day));
    const newer = new Date(now - day).toISOString();
    assert.equal(mergeBackfillUsers([{ id: 'user-2', lastSignIn: { dateTime: newer } }], state, null, null, now)[0].lastSignIn.dateTime, newer);
});

test('timeouts retain progress, Retry-After gates the tenant, and capped pages split the range', () => {
    const state = backfillPlan(null, now);
    const first = nextBackfillRange(state, now);
    finishBackfillRange(state, first, { ok: false, errorCode: 'GRAPH_REQUEST_TIMEOUT' }, now);
    assert.equal(state.ranges[0].status, 'incomplete');
    assert.notDeepEqual(nextBackfillRange(state, now), first);
    const second = nextBackfillRange(state, now);
    finishBackfillRange(state, second, { ok: false, httpStatus: 429, retryAfterMs: 600000 }, now);
    assert.equal(nextBackfillRange(backfillPlan(state, now), now + 599999), undefined);
    const after = now + 600000;
    const third = nextBackfillRange(state, after);
    finishBackfillRange(state, third, { ok: true, hasMore: true, pageLimitReached: true }, after);
    assert.equal(state.ranges.length, 31);
    assert.equal(state.ranges.filter(range => range.status === 'complete').length, 0);
});

test('absence requires complete historical and recent sign-in coverage', () => {
    const state = backfillPlan(null, now);
    for (const range of state.ranges) range.status = 'complete';
    const users = [{ id: 'empty' }];
    const collection = { windowDays: 1, status: 'complete' };
    assert.equal(mergeBackfillUsers(users, state, new Date(now).toISOString(), collection, now)[0].historyComplete, true);
    assert.equal(mergeBackfillUsers(users, state, new Date(now).toISOString(), { ...collection, status: 'partial' }, now)[0].historyComplete, false);
    state.ranges[0].status = 'incomplete';
    assert.equal(mergeBackfillUsers(users, state, new Date(now).toISOString(), collection, now)[0].historyComplete, false);
});

test('database lock excludes another instance for one company and tenant', async () => {
    const running = new Set();
    const pool = { getConnection: async () => ({
        async query(sql, [key]) {
            if (sql.includes('RELEASE')) { running.delete(key); return [[{}]]; }
            if (running.has(key)) return [[{ locked: 0 }]];
            running.add(key);
            return [[{ locked: 1 }]];
        },
        release() {}
    }) };
    let release;
    const first = withBackfillLock(pool, 1, 'tenant-a', () => new Promise(resolve => { release = resolve; }));
    await new Promise(setImmediate);
    assert.equal(await withBackfillLock(pool, 1, 'TENANT-A', () => assert.fail('overlap')), undefined);
    assert.equal(await withBackfillLock(pool, 2, 'tenant-a', () => 'other company'), 'other company');
    assert.equal(await withBackfillLock(pool, 1, 'tenant-b', () => 'other tenant'), 'other tenant');
    release();
    await first;
    assert.equal(await withBackfillLock(pool, 1, 'tenant-a', () => 'resumed'), 'resumed');
});
