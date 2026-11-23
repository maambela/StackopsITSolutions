const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const server = fs.readFileSync(require.resolve('../server'), 'utf8');
const client = fs.readFileSync(require.resolve('../js/clientportal'), 'utf8');

function section(source, start, end) {
    const first = source.indexOf(start);
    const last = source.indexOf(end, first + start.length);
    assert.ok(first >= 0 && last > first, start);
    return source.slice(first, last);
}

test('dashboard cache writes keep the newest complete company snapshot and its original fetch timestamp', async () => {
    const write = vm.runInNewContext(
        section(server, 'async function writeMicrosoftDashboardCache', 'async function writeBackupRecoveryPayloadCache') +
        '\nwriteMicrosoftDashboardCache;', { console: { warn() {} } }
    );
    const rows = new Map();
    const connection = {
        async query(sql, [companyId, payload, collectedAt]) {
            assert.match(sql, /ON DUPLICATE KEY UPDATE Payload = IF\(LastUpdated IS NULL OR VALUES\(LastUpdated\) > LastUpdated, VALUES\(Payload\), Payload\)/);
            assert.match(sql, /, LastUpdated = IF\(/);
            if (!rows.has(companyId) || rows.get(companyId).collectedAt < collectedAt) {
                rows.set(companyId, { payload: JSON.parse(payload), collectedAt });
            }
        }
    };
    const save = (companyId, count, start, complete) => write(connection, 'EmailSecurityPayloadCache', 'CompanyID, Payload',
        [companyId, JSON.stringify({ count, fetchedAt: '2026-11-23T12:30:00Z' })], new Date(start), complete);
    await save(10, 8, '2026-11-23T12:20:00Z', true);
    await save(10, 3, '2026-11-23T12:10:00Z', true);
    await save(10, 0, '2026-11-23T12:40:00Z', false);
    await save(11, 22, '2026-11-23T12:30:00Z', true);
    assert.equal(rows.get(10).payload.count, 8);
    assert.equal(rows.get(10).collectedAt.toISOString(), '2026-11-23T12:20:00.000Z');
    assert.equal(rows.get(10).payload.fetchedAt, '2026-11-23T12:30:00Z');
    assert.equal(rows.get(11).payload.count, 22);
    await save(10, 0, '2026-11-23T12:50:00Z', true);
    assert.equal(rows.get(10).payload.count, 0);
});

test('dashboard freshness describes an available, outdated, updating, or unavailable collection', () => {
    const update = vm.runInNewContext(
        section(client, 'function microsoftDashboardUpdateText', 'function setMicrosoftDashboardUpdate') +
        '\nmicrosoftDashboardUpdateText;', { SUNBIRD_CARD_CACHE_TTL_MS: 300000 }
    );
    assert.match(update({ fetchedAt: new Date().toISOString() }), /^Last updated /);
    assert.match(update({ fetchedAt: new Date(Date.now() - 360000).toISOString() }), /^Outdated · Last updated /);
    assert.equal(update({ refreshing: true }), 'Updating…');
    assert.equal(update(null), 'Temporarily unavailable');
});

test('a Security refresh retains verified source counts and never treats a failed source as zero', () => {
    const { metrics, canReplace } = vm.runInNewContext([
        section(client, 'function getSecurityDashboardMetrics', 'function emailCardMetrics'),
        section(client, 'function microsoftDashboardSourceTime', 'function writeMicrosoftDashboardCache'),
        '({ metrics: getSecurityDashboardMetrics, canReplace: canReplaceSecurityDashboard });'
    ].join('\n'));
    const verified = {
        fetchedAt: '2026-11-23T12:20:00Z',
        dashboardCoverage: { alerts: true, incidents: true },
        summary: { activeIncidents: 0, totalAlerts: 0 }
    };
    const partial = { ...verified, fetchedAt: '2026-11-23T12:30:00Z', dashboardCoverage: { alerts: false, incidents: true } };
    assert.equal(metrics(verified).totalAlerts, 0);
    assert.equal(metrics(partial).activeIncidents, 0);
    assert.equal(metrics(partial).totalAlerts, 'Temporarily unavailable');
    assert.equal(metrics({ findingLoadState: 'loading' }).totalAlerts, 'Updating…');
    assert.equal(canReplace(partial, verified), false);
    assert.equal(canReplace({ ...verified, fetchedAt: '2026-11-23T12:00:00Z' }, verified), false);
    assert.equal(canReplace({ ...verified, fetchedAt: '2026-11-23T12:30:00Z' }, verified), true);
});

test('Microsoft 365 accepts a header-only report and rejects an unexpected successful response body', () => {
    const parse = vm.runInNewContext(
        section(server, 'function parseGraphCSVLine', '/**\n * Route: GET /api/backup-recovery') +
        '\nparseGraphReportCSV;', { console: { log() {}, error() {} } }
    );
    const columns = ['Site URL', 'Storage Used (Byte)'];
    assert.equal(parse(columns.join(','), 'SharePoint', columns).length, 0);
    assert.throws(() => parse('{"value":[]}', 'SharePoint', columns), /unexpected header/);
});

test('Intune card accepts a verified zero from dashboard details and rejects an older metrics response', () => {
    const project = {};
    const update = vm.runInNewContext([
        section(client, 'function updateDevicesProjectCard', 'async function fetchEmailCardData'),
        section(client, 'function microsoftDashboardSourceTime', 'function writeMicrosoftDashboardCache'),
        'updateDevicesProjectCard;'
    ].join('\n'), {
        latestDevicesCardData: null,
        updateMicrosoftDashboardCardTimestamp(project, data) { project.lastUpdate = data.fetchedAt; },
        saveProjectCardToCache() {},
        displayCurrentProject() {}
    });
    update(project, { fetchedAt: '2026-11-23T12:20:00Z', summary: { totalDevices: 0, nonCompliantDevices: 0 } });
    update(project, { fetchedAt: '2026-11-23T12:10:00Z', metrics: { TotalDevices: 34 } });
    assert.equal(project.cardMetrics[0].value, ': 0');
    assert.equal(project.cardMetrics[1].value, ': 0');
    assert.equal(project.cardMetrics[2].value, ': Temporarily unavailable');
    assert.equal(project.lastUpdate, '2026-11-23T12:20:00Z');
});
