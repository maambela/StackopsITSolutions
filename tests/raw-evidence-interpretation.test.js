const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { rawSecurityRecord } = require('../services/intelligence/raw-security-records');
const { interpretRawEvidence, presentRawEvidence } = require('../services/intelligence/raw-evidence-interpretation');
const { createRawEvidenceJournal } = require('../services/intelligence/raw-evidence-journal');
const { createRawEvidencePoller } = require('../services/intelligence/raw-evidence-poller');
const row = (payload, recordType = 'signin', provider = 'Microsoft Graph') => rawSecurityRecord(payload, { provider, recordType, companyId: 11, endpoint: '/fixture/' + recordType, retrievedAt: '2026-11-17T10:00:00Z' });
const signIn = { id: 'signin-one', userDisplayName: 'Gary Norton', userPrincipalName: 'gary@example.test', appDisplayName: 'Microsoft Loop App', ipAddress: '89.240.195.214',
    location: { city: 'Wincanton', countryOrRegion: 'United Kingdom' }, conditionalAccessStatus: 'success', createdDateTime: '2026-11-17T09:05:04.123Z',
    status: { errorCode: 0, failureReason: 'Other.', additionalDetails: 'MFA requirement satisfied by claim in the token' },
    deviceDetail: { isManaged: false, isCompliant: false }, authenticationDetails: [{ authenticationMethod: 'Previously satisfied', succeeded: true, authenticationStepResultDetail: 'MFA requirement satisfied by claim in the token' }] };
const audit = { id: 'audit-one', action: { description: 'Get account audit logs (Version 2)', type: 'get', result: 'success', time: '2026-11-17T10:00:00Z' },
    actor: { type: 'account', token: { id: 'verified-token', name: 'StackCTRL-Sunbird-CloudflareOne-ReadOnly' }, ip_address: '203.0.113.3' },
    raw: { method: 'GET', uri: '/client/v4/accounts/account-one/logs/audit?since=2026-11-02', status_code: 200 } };

test('successful Graph sign-in uses outcome fields, exact app/user/location and token MFA context', () => {
    const original = structuredClone(signIn), record = row(signIn), p = record.presentation;
    assert.equal(p.title, 'Successful Microsoft Loop App sign-in');
    assert.match(p.description, /Gary Norton signed in to Microsoft Loop App from Wincanton, United Kingdom/);
    assert.match(p.description, /existing token claim/);
    assert.doesNotMatch(p.description, /Other/);
    assert.equal(p.sourceLabel, 'Microsoft Entra ID'); assert.equal(p.category, 'Identity & Authentication');
    assert.equal(p.activityClass, 'informational'); assert.equal(p.routine, false);
    assert.equal(record.severity, null); assert.deepEqual(p.mitreTechniques, []);
    assert.equal(record.timestamp, original.createdDateTime); assert.deepEqual(record.rawPayload, original);
    assert.equal(p.sections.flatMap(s => s.fields).find(f => f.label === 'Managed device').value, 'false');
    assert.match(p.securitySignificance, /does not establish/);
});

test('missing status, failed credentials, interrupted MFA and explicit risk remain distinct', () => {
    assert.equal(row({ ...signIn, status: undefined }).presentation.outcome, 'Outcome not provided');
    const failed = row({ ...signIn, status: { errorCode: 50126, failureReason: 'Invalid username or password.' } });
    assert.equal(failed.presentation.outcome, 'Failed'); assert.equal(failed.presentation.activityClass, 'security');
    assert.equal(failed.presentation.routine, false); assert.equal(failed.severity, null); assert.deepEqual(failed.presentation.mitreTechniques, []);
    assert.equal(row({ ...signIn, status: { errorCode: 50076 } }).presentation.outcome, 'Interrupted');
    const risky = row({ ...signIn, riskState: 'atRisk', riskLevelDuringSignIn: 'high' });
    assert.equal(risky.presentation.activityClass, 'security'); assert.equal(risky.severity, null);
});

test('Cloudflare audit requires verified token identity, GET, success and 2xx before filtering noise', () => {
    const record = row(audit, 'accountLogs', 'Cloudflare');
    assert.equal(record.presentation.title, 'Cloudflare account audit logs accessed');
    assert.equal(record.presentation.activityClass, 'administrative'); assert.equal(record.presentation.routine, false);
    assert.doesNotMatch(record.presentation.description, /read-only/i);
    const p = interpretRawEvidence(record, { platformTokenIds: ['verified-token'] });
    assert.equal(p.routine, true); assert.equal(p.activityClass, 'platform');
    for (const payload of [
        { ...audit, action: { ...audit.action, result: 'failure' } },
        { ...audit, raw: { ...audit.raw, method: 'POST' } },
        { ...audit, raw: { ...audit.raw, status_code: 403 } },
        { ...audit, raw: { ...audit.raw, uri: '/accounts/other/resource' } },
        { ...audit, severity: 'high' }
    ]) assert.equal(interpretRawEvidence(row(payload, 'accountLogs', 'Cloudflare'), { platformTokenIds: ['verified-token'] }).routine, false);
    assert.deepEqual(record.rawPayload, audit);
});

test('provider severity/category/MITRE stay exact; no title-keyword mapping is invented', () => {
    const record = row({ title: 'Possible credential phishing', severity: 'HIGH', category: 'CredentialAccess', mitreTechniques: ['T1110.003'], status: 'new', description: 'Provider explanation' }, 'alert');
    assert.equal(record.sourceSeverity, 'HIGH'); assert.equal(record.presentation.category, 'CredentialAccess');
    assert.deepEqual(record.presentation.mitreTechniques, ['T1110.003']); assert.equal(record.presentation.mitreBasis, 'Provider supplied');
    assert.deepEqual(row({ title: 'Phishing brute force', status: 'new' }, 'alert').presentation.mitreTechniques, []);
});

test('firewall, Access, audit and directory events have different field priorities', () => {
    const firewall = row({ rayName: 'ray', source: 'waf', action: 'block', clientIP: '203.0.113.9', clientRequestHTTPHost: 'example.test', clientRequestPath: '/login', ruleId: 'rule-id' }, 'firewall_event', 'Cloudflare');
    assert.equal(firewall.presentation.sourceLabel, 'Cloudflare WAF'); assert.equal(firewall.presentation.outcome, 'Blocked'); assert.equal(firewall.presentation.category, 'Firewall & WAF');
    assert.match(firewall.presentation.description, /example.test\/login/); assert.equal(firewall.presentation.routine, false);
    const access = row({ allowed: false, user_email: 'user@example.test', app_domain: 'private.test', ip_address: '203.0.113.9' }, 'accessLogs', 'Cloudflare');
    assert.equal(access.presentation.outcome, 'Denied'); assert.equal(access.presentation.sourceLabel, 'Cloudflare Access');
    const directory = row({ activityDisplayName: 'Add member to role', result: 'success', category: 'RoleManagement', initiatedBy: { user: { displayName: 'Administrator' } }, targetResources: [{ displayName: 'User One', type: 'User', modifiedProperties: [{ displayName: 'Role.DisplayName', newValue: '"Global Administrator"' }] }] }, 'directoryAudit');
    assert.equal(directory.presentation.category, 'RoleManagement'); assert.equal(directory.presentation.actor, 'Administrator');
    assert.match(JSON.stringify(directory.presentation.sections), /Changed properties/); assert.deepEqual(directory.presentation.mitreTechniques, []);
    const http = row({ ClientIP: '203.0.113.9', SecurityActions: ['block'], SecuritySources: ['waf'], ClientRequestHost: 'example.test' }, 'http_requests', 'Cloudflare');
    assert.equal(http.presentation.activityClass, 'security'); assert.equal(http.presentation.outcome, 'Blocked'); assert.equal(http.severity, null);
});

test('unknown and malformed schemas remain inspectable unclassified records', () => {
    const record = row({ action: 'new_provider_operation', extra: { untouched: true } }, 'newType', 'Cloudflare');
    assert.match(record.presentation.title, /Unclassified activity: new_provider_operation/);
    assert.equal(record.presentation.category, 'Unclassified'); assert.deepEqual(record.rawPayload.extra, { untouched: true });
    assert.equal(row({ ...signIn, authenticationDetails: {} }).presentation.activityClass, 'unclassified');
});

test('compact presentation omits original JSON but memory inspection works before database persistence', async () => {
    let release;
    const blocked = new Promise(resolve => { release = resolve; });
    const journal = createRawEvidenceJournal({ pool: { query: async () => [[]], getConnection: async () => { await blocked; throw new Error('Unavailable'); } }, logger: { warn() {} } });
    const record = journal.collection(11).publish('Microsoft Graph', '/fixture/signin', 'signin', [signIn])[0];
    const compact = presentRawEvidence(record);
    assert.equal(compact.rawPayload, undefined); assert.ok(compact.presentation); assert.equal(compact.technicalAvailable, true);
    assert.deepEqual((await journal.record(11, record.uid)).rawPayload, signIn);
    assert.equal(await journal.record(12, record.uid), null);
    release(); await journal.flush(11);
});

test('structured details hide JSON/endpoints until technical evidence is requested and escape provider HTML', () => {
    const source = fs.readFileSync(require.resolve('../js/clientportal.js'), 'utf8');
    const context = vm.createContext({ escapeIdentityText: value => String(value ?? '').replace(/[<>&"']/g, character => `&#${character.charCodeAt(0)};`), sunbirdSecurityFormatTime: value => value });
    const start = source.indexOf('function renderSunbirdRawEvidenceDetails('), end = source.indexOf('\nasync function ', start);
    vm.runInContext(source.slice(start, end), context);
    const record = row({ ...signIn, userDisplayName: '<img onerror=alert(1)>' });
    const html = context.renderSunbirdRawEvidenceDetails(presentRawEvidence(record));
    assert.match(html, /What happened\?/); assert.match(html, /Identity and application/); assert.match(html, /Authentication/); assert.match(html, /Security context/);
    assert.doesNotMatch(html, /<img|"errorCode"/);
    assert.doesNotMatch(html.replace(/<[^>]+>/g, ''), /\/fixture\/signin/);
    assert.match(html, /<details[^>]+ontoggle/); assert.match(html, /Not mapped/); assert.match(html, /Not provided/);
});

test('activity visibility keeps every failure and allows explicit access to retained platform records', () => {
    const source = fs.readFileSync(require.resolve('../js/clientportal.js'), 'utf8');
    const state = { search: '', severity: 'all', status: 'all', source: 'all', activity: 'client', sort: 'newest' };
    const context = vm.createContext({ sunbirdSecurityTableState: state, getSunbirdSecurityMitre: () => ({}), getSunbirdSecurityTime: () => 0 });
    const start = source.indexOf('function getFilteredSunbirdSecurityEvents('), end = source.indexOf('\nfunction ', start + 1);
    vm.runInContext(source.slice(start, end), context);
    const routine = row(audit, 'accountLogs', 'Cloudflare'); routine.presentation = interpretRawEvidence(routine, { platformTokenIds: ['verified-token'] });
    const failed = row({ ...signIn, status: { errorCode: 50126 } });
    const model = { allEvents: [routine, failed, row(signIn)] };
    assert.equal(context.getFilteredSunbirdSecurityEvents(model).length, 2);
    state.activity = 'all'; assert.equal(context.getFilteredSunbirdSecurityEvents(model).length, 3);
    state.activity = 'platform'; assert.equal(context.getFilteredSunbirdSecurityEvents(model)[0].id, routine.id);
});

test('endpoint-specific polling cadence does not delay alerts behind administrative feeds', async () => {
    let time = 0, alerts = 0, auditCount = 0;
    const poller = createRawEvidencePoller({ discover: async () => [], now: () => time, sourceIntervals: { alerts: 30000, audit: 120000 }, sources: { alerts: async () => alerts++, audit: async () => auditCount++ } });
    poller.register(11); await Promise.all(poller.runOnce());
    time = 30000; await Promise.all(poller.runOnce());
    assert.equal(alerts, 2); assert.equal(auditCount, 1);
    time = 120000; await Promise.all(poller.runOnce()); assert.equal(auditCount, 2);
});
