const test = require('node:test');
const assert = require('node:assert/strict');
const { acquireClaim, claimKey, renewClaim, releaseClaim, runWithCollectionOwnership, withCollectionPublication } =
    require('../services/intelligence/graph-collection-ownership');

function fakeDb() {
    const claims = new Map();
    let now = 0;
    const committed = [];
    async function query(sql, args) {
        if (sql.includes('INSERT INTO StackCTRLIntelligenceScheduleRuns')) {
            const [, , , key, owner, ttl] = args;
            if (!claims.has(key) || claims.get(key).expiry <= now) claims.set(key, { owner, expiry: now + ttl });
            return [{}];
        }
        if (sql.includes('SELECT ID')) {
            const [key, , owner] = args;
            const row = claims.get(key);
            return [row?.owner === owner && row.expiry > now ? [{ ID: 1 }] : []];
        }
        if (sql.includes('UPDATE StackCTRLIntelligenceScheduleRuns')) {
            const renew = sql.includes(' + ?');
            const [key, , owner] = renew ? args.slice(1) : args;
            const row = claims.get(key);
            if (row?.owner !== owner || renew && row.expiry <= now) return [{ affectedRows: 0 }];
            row.expiry = renew ? now + args[0] : 0;
            return [{ affectedRows: 1 }];
        }
        throw Error('Unexpected SQL');
    }
    const pool = {
        query, committed, advance: ms => { now += ms; },
        async getConnection() {
            let pending = [];
            return {
                query: async (sql, args) => sql === 'WRITE' ? pending.push(args) : query(sql, args),
                async beginTransaction() {}, async commit() { committed.push(...pending); },
                async rollback() { pending = []; }, release() {}
            };
        }
    };
    return pool;
}

test('one owner wins, renewal extends the lease, and a crashed owner cannot renew after takeover', async () => {
    const pool = fakeDb();
    const key = claimKey(1, 'TENANT-A', 'identity');
    assert.equal(key, claimKey(1, 'tenant-a', 'identity'));
    assert.notEqual(key, claimKey(2, 'tenant-a', 'identity'));
    assert.notEqual(key, claimKey(1, 'tenant-b', 'identity'));
    assert.notEqual(key, claimKey(1, 'tenant-a', 'devices'));
    const [first, second] = await Promise.all([
        acquireClaim(pool, key, 1, 'identity', 60, 'a'),
        acquireClaim(pool, key, 1, 'identity', 60, 'b')
    ]);
    assert.equal(first.owner, 'a');
    assert.equal(second, null);
    pool.advance(40);
    assert.equal(await renewClaim(pool, first, 60), true);
    pool.advance(21);
    assert.equal(await acquireClaim(pool, key, 1, 'identity', 60, 'b'), null);
    pool.advance(40);
    const newOwner = await acquireClaim(pool, key, 1, 'identity', 60, 'b');
    assert.equal(newOwner.owner, 'b');
    assert.equal(await renewClaim(pool, first, 60), false);
    await releaseClaim(pool, first);
    assert.equal(await acquireClaim(pool, key, 1, 'identity', 60, 'c'), null);
});

test('busy workers do not publish and a late or failed publication preserves the verified write', async () => {
    const pool = fakeDb();
    const scope = { companyId: 1, tenantId: 'tenant', source: 'identity', ttlMs: 50 };
    let finish;
    const paused = new Promise(resolve => { finish = resolve; });
    let claimed;
    const firstStarted = new Promise(resolve => { claimed = resolve; });
    const first = runWithCollectionOwnership(pool, scope, async () => {
        claimed();
        await paused;
        await withCollectionPublication(pool, 1, db => db.query('WRITE', 'old'));
    });
    await firstStarted;
    const rejection = assert.rejects(first, { code: 'GRAPH_COLLECTION_OWNERSHIP_LOST' });
    assert.equal((await runWithCollectionOwnership(pool, scope, () => assert.fail('duplicate started'))).status, 'already_running');
    pool.advance(51);
    await runWithCollectionOwnership(pool, scope, () => withCollectionPublication(pool, 1, db => db.query('WRITE', 'new')));
    finish();
    await rejection;
    await assert.rejects(runWithCollectionOwnership(pool, scope, () => withCollectionPublication(pool, 1, async db => {
        await db.query('WRITE', 'failed');
        throw Error('write failure');
    })), /write failure/);
    assert.deepEqual(pool.committed, ['new']);
});
