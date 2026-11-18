const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { createRawEvidenceJournal } = require('../services/intelligence/raw-evidence-journal');
const { createCloudflareLogpushStore, hashSecret } = require('../services/intelligence/cloudflare-logpush-store');
const { createSecurityEvidenceStore } = require('../services/intelligence/security-evidence-store');
const { SECURITY_ALERT_STORAGE_ENABLED } = require('../services/intelligence/security-storage-policy');
const forbiddenPool = { query() { assert.fail('Security evidence must not access the database'); }, getConnection() { assert.fail('Security evidence must not open a transaction'); } };

test('default raw pipeline streams and retains tenant-scoped originals without any database calls', async () => {
    assert.equal(SECURITY_ALERT_STORAGE_ENABLED, false);
    const journal = createRawEvidenceJournal({ pool: forbiddenPool });
    await journal.ensureSchema();
    await journal.hydrate(7);
    const events = [];
    const unsubscribe = journal.subscribe(7, event => events.push(event));
    const original = { id: 'alert', title: 'Provider alert', createdDateTime: '2026-11-17T10:12:34Z' };
    const [record] = journal.collection(7).publish('Microsoft Graph', '/v1.0/security/alerts_v2', 'alert', [original], { complete: true, status: 'complete' });
    await journal.flush(7);
    assert.equal(events[0].records.length, 1);
    assert.deepEqual((await journal.record(7, record.uid)).rawPayload, original);
    assert.equal(await journal.record(8, record.uid), null);
    assert.equal(await journal.record(7, '7:expired'), null);
    assert.deepEqual(await journal.history(7), { records: [record], next: null, storageMode: 'memory_only' });
    assert.deepEqual((await journal.history(8)).records, []);
    const [second] = journal.collection(7).publish('Cloudflare', '/logpush/account/firewall_events', 'firewall_events', [{ RayID: 'ray', Action: 'block', datetime: '2026-11-17T10:12:35Z' }]);
    const firstPage = await journal.history(7, { pageSize: 1 });
    assert.equal(firstPage.records.length, 1);
    const nextPage = await journal.history(7, { pageSize: 1, after: firstPage.next });
    assert.equal(new Set([...firstPage.records, ...nextPage.records].map(row => row.uid)).size, 2);
    assert.equal(nextPage.next, null);
    assert.deepEqual((await journal.history(7, { since: '2026-11-17T10:12:35Z', until: '2026-11-17T10:12:36Z' })).records, [second]);
    assert.equal((await journal.health(7)).storageMode, 'memory_only');
    assert.equal(journal.sources(7)[0].storageStatus, 'memory_only');
    assert.throws(() => journal.queue(8, [record]), /tenant mismatch/);
    unsubscribe();
});

test('Logpush validates configured tenant mapping but publishes batches without storing alerts', async () => {
    const calls = [], delivered = [];
    const store = createCloudflareLogpushStore({ pool: { async query(sql) {
        calls.push(sql);
        assert.match(sql, /^SELECT CompanyID/);
        return [[{ CompanyID: 7, CloudflareAccountID: 'account', LogpushSecretSha256: hashSecret('fixture') }]];
    } }, onRecords: batch => delivered.push(batch) });
    await store.ensureSchema();
    assert.equal((await store.authenticate({ accountId: 'account', secret: 'fixture' })).companyId, 7);
    assert.equal(await store.authenticate({ accountId: 'account', secret: 'wrong' }), null);
    const result = await store.ingest({ companyId: 7, accountId: 'account', dataset: 'firewall_events', payload: [{ RayID: 'ray', Action: 'block' }] });
    assert.equal(result.stored, false);
    assert.equal(result.received, 1);
    assert.equal(delivered[0].records.length, 1);
    assert.deepEqual(await store.recentEvents(7), []);
    assert.equal(calls.length, 2);
});

test('security snapshot and collection failure paths do not create schemas or write snapshots', async () => {
    const store = createSecurityEvidenceStore({ pool: forbiddenPool });
    await store.ensureSchema();
    assert.equal((await store.persistProcessedEvidence({ companyId: 7, payload: { rawRecords: [] } })).status, 'persistence_disabled');
    assert.equal((await store.recordCollectionFailure({ companyId: 7, error: new Error('unavailable') })).snapshotId, null);
});

test('server webhook and scheduled security snapshot entry points stop before accessing storage', async () => {
    const source = fs.readFileSync(require.resolve('../server.js'), 'utf8');
    const context = vm.createContext({ SECURITY_ALERT_STORAGE_ENABLED, pool: forbiddenPool });
    for (const name of ['persistRealtimeSecurityAlert', 'performSecurityEvidenceCollection', 'collectAndPersistSecurityEvidence']) {
        const start = source.indexOf('async function ' + name + '(');
        assert.ok(start >= 0);
        const end = source.indexOf('\n}', start) + 2;
        vm.runInContext(source.slice(start, end), context);
        const result = await context[name]({ companyId: 7 });
        assert.equal(result.storageMode, 'memory_only');
    }
});
