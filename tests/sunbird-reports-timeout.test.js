const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadReportTimeoutHelper() {
    const source = fs.readFileSync('server.js', 'utf8');
    const start = source.indexOf('function withSunbirdReportTimeout(task, timeoutMs, label) {');
    const end = source.indexOf('async function fetchSunbirdPowerBIIntelligence', start);
    assert.ok(start >= 0 && end > start, 'report timeout helper must be present');
    return vm.runInNewContext(`${source.slice(start, end)}; withSunbirdReportTimeout;`, { setTimeout, clearTimeout, Promise, Error });
}

test('live report timeout rejects a stalled optional read with a classified error', async () => {
    const withSunbirdReportTimeout = loadReportTimeoutHelper();
    await assert.rejects(
        () => withSunbirdReportTimeout(() => new Promise(resolve => setTimeout(resolve, 50)), 10, 'Test live read'),
        error => error.code === 'SUNBIRD_REPORT_TIMEOUT' && /Test live read exceeded 10ms/.test(error.message)
    );
});

test('reports endpoint keeps live enrichment bounded and treats the view audit as optional', () => {
    const source = fs.readFileSync('server.js', 'utf8');
    const start = source.indexOf("app.get('/api/sunbird/reports'");
    const end = source.indexOf("app.get('/api/sunbird/reports/live-evidence'", start);
    const route = source.slice(start, end);
    assert.match(route, /domainTimeoutMs: SUNBIRD_REPORT_LIVE_DOMAIN_TIMEOUT_MS/);
    assert.match(route, /SUNBIRD_REPORT_LIVE_FINAL_TIMEOUT_MS/);
    assert.match(route, /SUNBIRD_REPORT_LIVE_IDENTITY_TIMEOUT_MS/);
    assert.match(route, /'Report view audit'/);
    assert.match(route, /saved_report_fallback/);
    const serviceSource = fs.readFileSync('services/enterprise-intelligence.js', 'utf8');
    assert.match(serviceSource, /queryTimeoutMs > 0 \? \{ sql, timeout:/);
    const schema = fs.readFileSync('sql/stackctrl-enterprise-intelligence.sql', 'utf8');
    assert.match(schema, /ix_domain_intelligence_latest_lookup/);
    assert.match(schema, /ix_enterprise_synthesis_latest_lookup/);
    assert.match(route, /client_request_aborted/);
    assert.match(route, /live_domain_intelligence_complete/);
    assert.match(route, /live_final_synthesis_complete/);
    assert.match(route, /report_load_failed/);
    assert.match(source, /traceId/);
    assert.match(source, /elapsedMs/);
});
test('enterprise intelligence schema migration is MySQL compatible', () => {
    const schema = fs.readFileSync('sql/stackctrl-enterprise-intelligence.sql', 'utf8');
    assert.doesNotMatch(schema, /CREATE\s+(UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS/i);
    assert.match(schema, /KEY ix_domain_intelligence_latest_lookup \(CompanyID, DomainKey, Status, ID\)/);
    assert.match(schema, /KEY ix_enterprise_synthesis_latest_lookup \(CompanyID, Status, ID\)/);
    const server = fs.readFileSync('server.js', 'utf8');
    assert.match(server, /async function ensureTableExists\(tableName\)/);
    assert.match(server, /async function ensureTableColumn\(tableName, columnName, definition\)/);
    assert.match(server, /error\.code === 'ER_DUP_FIELDNAME'/);
    assert.match(server, /Optional legacy invoice migrations must not prevent startup/);
});
test('enterprise daily automation includes active report tenants and supports a protected Cloud Scheduler trigger', () => {
    const enterpriseSource = fs.readFileSync('services/enterprise-intelligence.js', 'utf8');
    assert.match(enterpriseSource, /loadScheduledEnterpriseCompanyIds/);
    assert.match(enterpriseSource, /SELECT CompanyID FROM SunbirdReportSettings/);
    assert.match(enterpriseSource, /event: 'scheduled_tenant_discovery'/);
    const serverSource = fs.readFileSync('server.js', 'utf8');
    assert.match(serverSource, /STACKCTRL_AUTOMATION_TRIGGER_SECRET/);
    assert.match(serverSource, /\/api\/internal\/automation\/enterprise-hourly/);
    assert.match(serverSource, /enterprise_daily_trigger/);
    assert.match(serverSource, /finalizeSunbirdDailyAutomation/);
    assert.match(serverSource, /x-cloudscheduler-scheduletime/);
    assert.match(serverSource, /responseStatus = result\?\.status === 'failed' \? 500 : 200/);
    assert.match(serverSource, /ENTERPRISE_AI_AUTOMATION_ENABLED \|\| 'false'/);
});