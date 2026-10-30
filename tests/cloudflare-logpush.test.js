const test = require('node:test');
const assert = require('node:assert/strict');
const {
    normaliseCloudflareLogpushPayload,
    buildCloudflareLogpushFindings,
    buildCloudflareApiFindings
} = require('../services/intelligence/cloudflare-logpush');

test('normalises supported Cloudflare Logpush records and rejects unsupported datasets', () => {
    const records = normaliseCloudflareLogpushPayload([{ RayID: 'ray-1', Action: 'block', ClientIP: '203.0.113.8', ZoneName: 'app.example.com', datetime: '2026-10-30T09:00:00Z' }], {
        dataset: 'firewall_events', accountId: 'account-1'
    });
    assert.equal(records.length, 1);
    assert.equal(records[0].cloudflareAccountId, 'account-1');
    assert.equal(records[0].eventKey, 'firewall_events:ray-1');
    assert.equal(records[0].resource, 'app.example.com');
    assert.deepEqual(normaliseCloudflareLogpushPayload([{ hello: 'world' }], { dataset: 'http_requests' }), []);
});

test('aggregates current Cloudflare API Access denials without requiring Logpush', () => {
    const findings = buildCloudflareApiFindings({
        accessLogs: Array.from({ length: 3 }, (_, index) => ({
            id: `access-${index}`, action: 'blocked', userEmail: 'user@example.com', ipAddress: '203.0.113.8', appName: 'portal.example.com', timestamp: `2026-10-30T10:0${index}:00Z`
        })),
        auditLogs: [{ id: 'audit-1', action: 'update', resource_type: 'Gateway policy', created_at: '2026-10-30T11:00:00Z' }]
    });
    assert.equal(findings.length, 2);
    assert.equal(findings[0].detectionId, 'cloudflare_repeated_access_denials');
    assert.equal(findings[0].severity, 'unassessed');
    assert.match(findings[0].description, /does not establish/i);
    assert.equal(findings[1].detectionId, 'cloudflare_security_configuration_change');
});

test('aggregates repeated Cloudflare blocks without claiming compromise', () => {
    const records = normaliseCloudflareLogpushPayload(Array.from({ length: 5 }, (_, index) => ({
        RayID: `ray-${index}`, Action: 'block', ClientIP: '203.0.113.8', ZoneName: 'app.example.com', datetime: `2026-10-30T09:0${index}:00Z`
    })), { dataset: 'firewall_events', accountId: 'account-1' });
    const [finding] = buildCloudflareLogpushFindings(records);
    assert.equal(finding.detectionId, 'cloudflare_repeated_security_blocks');
    assert.equal(finding.severity, 'unassessed');
    assert.equal(finding.confidence, 'medium');
    assert.match(finding.description, /not proof/i);
    assert.equal(finding.evidence.length, 5);
});
