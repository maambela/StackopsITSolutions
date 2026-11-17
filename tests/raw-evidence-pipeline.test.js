const test = require('node:test');
const assert = require('node:assert/strict');
const { createRawEvidenceJournal } = require('../services/intelligence/raw-evidence-journal');
const { fetchFirewallEvents } = require('../services/intelligence/cloudflare-firewall-events');
const { rawSecurityRecord, providerTimestamp } = require('../services/intelligence/raw-security-records');
const { buildSecurityFindings } = require('../services/intelligence/security-findings');
const { buildCloudflareApiFindings, normaliseCloudflareLogpushPayload } = require('../services/intelligence/cloudflare-logpush');
const { getCloudflareNetworkSecuritySummary } = require('../services/cloudflare');
const { createRawEvidencePoller } = require('../services/intelligence/raw-evidence-poller');
const { parseCloudflareLogpushPayload } = require('../services/intelligence/cloudflare-logpush');

function fakePool() {
    const records = new Map(), states = new Map(), calls = [];
    let waitForWrite = null;
    return {
        records, states, calls, holdWrites(promise) { waitForWrite = promise; },
        async query(sql, values = []) {
            calls.push({ sql, values });
            if (sql.includes('SELECT StateJson')) return [[...states.entries()].filter(([key]) => key.startsWith(values[0] + ':')).map(([, StateJson]) => ({ StateJson }))];
            if (sql.includes('SELECT RecordKey')) return [[...records.entries()].filter(([key]) => key.startsWith(values[0] + ':')).map(([key, RecordJson]) => ({ RecordKey: key.split(':')[1], RecordJson })).filter(row => row.RecordKey > values[1]).sort((a,b) => a.RecordKey.localeCompare(b.RecordKey)).slice(0, values[6])];
            if (sql.includes('COUNT(*)')) return [[{ provider: 'Microsoft Graph', recordsStored: records.size }]];
            return [[]];
        },
        async getConnection() {
            const pendingRecords = [], pendingStates = [];
            return {
                async beginTransaction() {}, async rollback() {}, release() {},
                async query(sql, values) {
                    if (waitForWrite) await waitForWrite;
                    if (sql.includes('INSERT INTO StackCTRLRawSecurityRecords')) pendingRecords.push([values[0] + ':' + values[1], values[9]]);
                    if (sql.includes('INSERT INTO StackCTRLRawSecuritySync')) pendingStates.push([values[0] + ':' + values[1], values[2]]);
                },
                async commit() { pendingRecords.forEach(([k,v]) => records.set(k,v)); pendingStates.forEach(([k,v]) => states.set(k,v)); }
            };
        }
    };
}
const graphResponse = (value, nextLink) => ({ ok: true, status: 200, json: async () => ({ value, ...(nextLink ? { '@odata.nextLink': nextLink } : {}) }) });

test('API pages reach the subscriber before storage finishes; repeated sync upserts and isolates tenants', async () => {
    const pool = fakePool(), events = [];
    let release;
    pool.holdWrites(new Promise(resolve => { release = resolve; }));
    const journal = createRawEvidenceJournal({ pool });
    const collection = journal.collection(11, { onEvent: event => events.push(event) });
    const result = await collection.graph({ token: 'fixture', url: 'https://graph.microsoft.com/v1.0/security/alerts_v2', fetchImpl: async () => graphResponse([{ id: 'same', title: 'Provider title' }]) });
    assert.equal(result.value.length, 1);
    assert.equal(pool.records.size, 0);
    assert.equal(events.find(event => event.records?.length).records[0].title, 'Provider title');
    release(); await journal.flush(11);
    await collection.graph({ token: 'fixture', url: 'https://graph.microsoft.com/v1.0/security/alerts_v2', fetchImpl: async () => graphResponse([{ id: 'same', title: 'Updated title' }]) });
    await journal.flush(11);
    assert.equal(pool.records.size, 1);
    assert.equal((await journal.history(12)).records.length, 0);
    assert.equal((await journal.history(11)).records[0].title, 'Updated title');
    assert.throws(() => journal.queue(12, [(awaitableRecord(11))]), /tenant mismatch/);
});
function awaitableRecord(companyId) { return rawSecurityRecord({ id: 'id' }, { provider: 'Microsoft Graph', endpoint: '/alerts', recordType: 'alert', companyId, retrievedAt: new Date().toISOString() }); }

test('failed later page survives restart and resumes while the newest page still arrives first', async () => {
    const pool = fakePool(), url = 'https://graph.microsoft.com/v1.0/security/alerts_v2';
    let journal = createRawEvidenceJournal({ pool });
    const first = await journal.collection(11).graph({ token: 'fixture', url, fetchImpl: async requested => requested === url
        ? graphResponse([{ id: 'first' }], url + '?next=2')
        : { ok: false, status: 403, text: async () => 'Permission unavailable' } });
    assert.equal(first.ok, false); await journal.flush(11);
    journal = createRawEvidenceJournal({ pool });
    await journal.hydrate(11);
    const calls = [];
    const second = await journal.collection(11).graph({ token: 'fixture', url, fetchImpl: async requested => {
        calls.push(requested);
        return requested === url ? graphResponse([{ id: 'newest' }, { id: 'first' }], url + '?new=next') : graphResponse([{ id: 'old-page-two' }]);
    } });
    await journal.flush(11);
    assert.deepEqual(calls, [url, url + '?next=2']);
    assert.equal(second.ok, true);
    assert.equal(pool.records.size, 3);
    assert.equal((await journal.health(11)).sources[0].resumable, false);
});

test('firewall saturated intervals split without dropping events sharing timestamps', async () => {
    const since = '2026-11-17T10:00:00Z', until = '2026-11-17T10:00:04Z';
    const emitted = [];
    const result = await fetchFirewallEvents({ post: async (url, request) => {
        const filter = request.variables.filter;
        const width = Date.parse(filter.datetime_lt) - Date.parse(filter.datetime_geq);
        return { data: { data: { viewer: { zones: [{ firewallEventsAdaptive: width > 1000 ? [{ rayName: 'saturated' }, { rayName: 'saturated-2' }] : [{ rayName: filter.datetime_geq, datetime: filter.datetime_geq, action: 'block' }] }] } } } };
    } }, { zoneId: 'zone', since, until, pageSize: 2, onPage: page => emitted.push(...page.value) });
    assert.equal(result.complete, true);
    assert.equal(result.value.length, 4);
    assert.equal(emitted.length, 4);
    assert.match(result.limitation, /sampling/);
});

test('firewall one-second saturation and API failure remain explicitly partial and resumable', async () => {
    const options = { zoneId: 'zone', since: '2026-11-17T10:00:00Z', until: '2026-11-17T10:00:01Z', pageSize: 1 };
    const full = await fetchFirewallEvents({ post: async () => ({ data: { data: { viewer: { zones: [{ firewallEventsAdaptive: [{ rayName: 'one' }] }] } } } }) }, options);
    assert.equal(full.complete, false); assert.equal(full.failedWindows.length, 1);
    const failed = await fetchFirewallEvents({ post: async () => { throw { response: { status: 403 }, message: 'Forbidden' }; } }, options);
    assert.equal(failed.complete, false); assert.equal(failed.permissionErrors, 1); assert.equal(failed.pending.length, 1);
});

test('ordinary authentication failures, shared-IP distant events, duplicates and unrelated days do not create incidents', () => {
    assert.equal(buildSecurityFindings({ signIns: [{ id: 'mfa', status: 'Failed', failureReason: 'Register MFA' }, { id: 'password', status: 'Failed', failureReason: 'Invalid password' }] }).findings.length, 0);
    const alert = { id: 'alert', title: 'Anonymous IP observed', ipAddress: '203.0.113.1', eventTime: '2026-11-17T10:00:00Z' };
    const findings = buildSecurityFindings({ alerts: [alert, alert], signIns: [{ id: 'old', ipAddress: alert.ipAddress, eventTime: '2026-11-10T10:00:00Z', outcome: 'success' }] }).findings;
    assert.equal(findings.length, 1); assert.equal(findings[0].status, 'needs_investigation');
    const accessLogs = [1,2,3].map(day => ({ id: String(day), appName: 'app', userEmail: 'user@example.test', action: 'blocked', timestamp: `2026-11-0${day}T10:00:00Z` }));
    assert.equal(buildCloudflareApiFindings({ accessLogs }).length, 0);
});

test('Logpush supports HTTP/DDoS datasets, nanosecond timestamps and distinct rules on the same ray', () => {
    assert.equal(providerTimestamp('1794909600000000000'), '2026-11-17T10:00:00.000Z');
    const records = normaliseCloudflareLogpushPayload([{ RayID: 'ray', RuleID: 'one' }, { RayID: 'ray', RuleID: 'two' }], { dataset: 'firewall_events' });
    assert.equal(records.length, 2);
    assert.equal(normaliseCloudflareLogpushPayload([{ Timestamp: 1794909600 }], { dataset: 'network_analytics_logs' }).length, 1);
});

test('Cloudflare integration retrieves notifications and zone firewall events with account-scoped discovery', async () => {
    const published = [], calls = [];
    const client = {
        async get(url, config) {
            calls.push({ url, config });
            if (url === '/zones') return { data: { result: [{ id: 'zone-one', name: 'example.test' }] } };
            if (url.endsWith('/alerting/v3/history')) return { data: { result: [{ id: 'notification', alert_body: 'HTTP DDoS attack detected', alert_type: 'dos_attack_l7', sent: '2026-11-17T10:00:00Z' }] } };
            if (url.endsWith('/security-center/insights')) return { data: { result: { issues: [{ id: 'finding', severity: 'critical', issue_type: 'weak_authentication' }], page: 1, per_page: 100 } } };
            return { data: { result: [] } };
        },
        async post() { return { data: { data: { viewer: { zones: [{ firewallEventsAdaptive: [{ rayName: 'ray', action: 'block', source: 'waf', datetime: '2026-11-17T10:00:00Z' }] }] } } } }; }
    };
    const summary = await getCloudflareNetworkSecuritySummary({ client, accountId: 'account-one', apiToken: 'fixture', securityOnly: true,
        range: { since: '2026-11-17T10:00:00Z', until: '2026-11-17T11:00:00Z' },
        collection: { getState: () => null, publish: (...args) => published.push(args) } });
    assert.equal(calls.find(call => call.url === '/zones').config.params['account.id'], 'account-one');
    assert.ok(summary.rawSecurityRecords.some(row => row.recordType === 'notificationHistory'));
    assert.ok(summary.rawSecurityRecords.some(row => row.recordType === 'firewall_event'));
    assert.equal(summary.rawSecurityRecords.filter(row => row.recordType === 'zones').length, 0);
    assert.ok(published.some(args => args[2] === 'firewall_event' && args[3].length));
});

test('saved raw history is reachable beyond one API page and tenant boundaries remain enforced', async () => {
    const pool = fakePool(), journal = createRawEvidenceJournal({ pool });
    const records = Array.from({ length: 1005 }, (_, index) => rawSecurityRecord({ id: String(index) }, {
        provider: 'Cloudflare', endpoint: '/logpush/firewall_events', recordType: 'firewall_event', companyId: 11, retrievedAt: '2026-11-17T10:00:00Z'
    }));
    await journal.queue(11, records);
    let after = '', count = 0;
    do { const page = await journal.history(11, { after }); count += page.records.length; after = page.next; } while (after);
    assert.equal(count, 1005);
    assert.equal((await journal.history(12)).records.length, 0);
});

test('a saved continuation cannot send a Graph token to another host', async () => {
    const pool = fakePool(), journal = createRawEvidenceJournal({ pool });
    const collector = journal.collection(11);
    collector.publish('Microsoft Graph', '/v1.0/security/alerts_v2', 'alert', [], { continuation: 'https://attacker.invalid/collect' });
    let calls = 0;
    await assert.rejects(collector.graph({ url: 'https://graph.microsoft.com/v1.0/security/alerts_v2', token: 'fixture', fetchImpl: async () => {
        calls++; return graphResponse([{ id: 'one' }]);
    } }), /Invalid saved Graph continuation/);
    assert.equal(calls, 1);
    await journal.flush(11);
});

test('a burst beyond the newest page is drained before resuming an old backlog', async () => {
    const journal = createRawEvidenceJournal({ pool: fakePool() });
    const url = 'https://graph.microsoft.com/v1.0/security/alerts_v2';
    const collector = journal.collection(11);
    collector.publish('Microsoft Graph', '/v1.0/security/alerts_v2', 'alert', [], { headIds: ['older'], continuation: url + '?backlog=1' });
    const calls = [];
    const result = await collector.graph({ token: 'fixture', url, fetchImpl: async requested => {
        calls.push(requested);
        return requested === url ? graphResponse([{ id: 'new-one' }], url + '?new-page=2') : graphResponse([{ id: 'new-two' }, { id: 'older' }]);
    } });
    assert.deepEqual(calls, [url, url + '?new-page=2']);
    assert.equal(result.value.length, 3);
    await journal.flush(11);
});

test('failed storage cannot advance the saved cursor beyond a missing page; recovery replays it', async () => {
    const pool = fakePool(), getConnection = pool.getConnection;
    let fail = true;
    pool.getConnection = async () => { if (fail) throw new Error('Database unavailable'); return getConnection(); };
    const journal = createRawEvidenceJournal({ pool, logger: { warn() {} } });
    const collector = journal.collection(11), url = 'https://graph.microsoft.com/v1.0/security/alerts_v2';
    const fetchImpl = async requested => requested === url ? graphResponse([{ id: 'first' }], url + '?page=2') : graphResponse([{ id: 'second' }]);
    await collector.graph({ url, token: 'fixture', fetchImpl });
    await journal.flush(11);
    assert.equal(collector.health()[0].storageStatus, 'failed');
    fail = false;
    await collector.graph({ url, token: 'fixture', fetchImpl });
    await journal.flush(11);
    assert.equal(pool.records.size, 2);
    assert.equal(collector.health()[0].storageStatus, 'stored');
    assert.equal(collector.health()[0].resumable, false);
});

test('forward polling continues without a dashboard or database discovery and isolates slow sources', async () => {
    let release, graph = 0, cloudflare = 0;
    const slow = new Promise(resolve => { release = resolve; });
    const poller = createRawEvidencePoller({ discover: async () => { throw new Error('Database unavailable'); },
        sources: { graph: async () => { graph++; }, cloudflare: async () => { cloudflare++; await slow; } }, logger: { warn() {} } });
    poller.register(11);
    const first = poller.runOnce();
    await first[0];
    const second = poller.runOnce();
    await second[0];
    assert.equal(graph, 2);
    assert.equal(cloudflare, 1);
    release(); await Promise.all(second); poller.stop();
});

test('Logpush accepts compressed NDJSON and validation probes; distinct full records do not collapse', async () => {
    const { gzipSync } = require('node:zlib');
    const records = [{ Datetime: '2026-11-17T10:00:00Z', Action: 'block', detail: 'one' }, { Datetime: '2026-11-17T10:00:00Z', Action: 'block', detail: 'two' }];
    const compressed = gzipSync(records.map(row => JSON.stringify(row)).join('\n'));
    assert.deepEqual(parseCloudflareLogpushPayload(compressed), records);
    assert.equal(normaliseCloudflareLogpushPayload(compressed, { dataset: 'firewall_events', accountId: 'account' }).length, 2);
    assert.deepEqual(parseCloudflareLogpushPayload(gzipSync('{"content":"tests"}')), { content: 'tests' });
    assert.throws(() => parseCloudflareLogpushPayload('{"ok":1}\ninvalid'), SyntaxError);
    // Verify Express inflates the body before the normal JSON middleware runs.
    const express = require('express'), app = express();
    app.use('/logpush', express.raw({ type: () => true, limit: '20mb' }));
    app.use(express.json());
    app.post('/logpush', (req, res) => res.json(parseCloudflareLogpushPayload(req.body)));
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    try {
        const response = await fetch('http://127.0.0.1:' + server.address().port + '/logpush', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, body: compressed });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), records);
    } finally { await new Promise(resolve => server.close(resolve)); }
});

test('live Graph collection bounds history by modification time, retaining newly updated old alerts', async () => {
    const journal = createRawEvidenceJournal({ pool: fakePool() });
    const range = { since: '2026-11-02T10:00:00.000Z', until: '2026-11-17T10:00:00.000Z', explicit: false };
    await journal.collection(11, { range }).graph({ url: 'https://graph.microsoft.com/v1.0/security/alerts_v2', token: 'fixture', fetchImpl: async url => {
        assert.equal(new URL(url).searchParams.get('$filter'), 'lastUpdateDateTime ge ' + range.since + ' and lastUpdateDateTime le ' + range.until);
        return graphResponse([{ id: 'old-updated', createdDateTime: '2020-01-01T00:00:00Z', lastUpdateDateTime: range.until }]);
    } });
    await journal.flush(11);
});
