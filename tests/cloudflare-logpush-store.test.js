const test = require('node:test');
const assert = require('node:assert/strict');
const { createCloudflareLogpushStore, hashSecret } = require('../services/intelligence/cloudflare-logpush-store');

function createPool({ mapping = null, insertResults = [] } = {}) {
    const calls = [];
    return {
        calls,
        async query(sql, values) {
            calls.push({ sql, values });
            if (/FROM StackCTRLCloudflareTenantMappings/.test(sql)) {
                return [mapping && values?.[0] === mapping.CloudflareAccountID ? [mapping] : []];
            }
            if (/INSERT IGNORE INTO StackCTRLCloudflareLogpushEvents/.test(sql)) return [{ affectedRows: insertResults.shift() ?? 1 }];
            if (/SELECT ProcessedEventJson/.test(sql)) return [[]];
            return [[]];
        }
    };
}

test('Logpush authentication requires the mapped account and its delivery secret', async () => {
    const pool = createPool({ mapping: {
        CompanyID: 42,
        CloudflareAccountID: 'account-a',
        LogpushSecretSha256: hashSecret('secret-a')
    } });
    const store = createCloudflareLogpushStore({ pool });
    assert.deepEqual(await store.authenticate({ accountId: 'account-a', secret: 'secret-a' }), { companyId: 42, accountId: 'account-a' });
    assert.equal(await store.authenticate({ accountId: 'account-a', secret: 'wrong-secret' }), null);
    assert.equal(await store.authenticate({ accountId: 'account-b', secret: 'secret-a' }), null);
});

test('Logpush ingestion records the verified company scope and reports duplicates', async () => {
    const pool = createPool({ insertResults: [1, 0] });
    const store = createCloudflareLogpushStore({ pool, now: () => new Date('2026-10-30T12:00:00Z') });
    const result = await store.ingest({
        companyId: 42,
        accountId: 'account-a',
        dataset: 'firewall_events',
        payload: [
            { RayID: 'ray-1', Action: 'block', datetime: '2026-10-30T11:00:00Z' },
            { RayID: 'ray-2', Action: 'block', datetime: '2026-10-30T11:01:00Z' }
        ]
    });
    assert.deepEqual(result, { received: 2, inserted: 1, duplicates: 1 });
    const inserts = pool.calls.filter(call => /INSERT IGNORE/.test(call.sql));
    assert.equal(inserts.length, 2);
    assert.equal(inserts[0].values[0], 42);
    assert.equal(inserts[0].values[1], 'account-a');
});
