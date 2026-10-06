const assert = require('node:assert/strict');
const test = require('node:test');

const {
  getMicrosoftGraphSecurityNotificationIds,
  normalizeCloudflareWebhookAlert,
  normalizeMicrosoftGraphWebhookAlert
} = require('../services/security-alert-webhooks');

test('Cloudflare webhook alert keeps its correlation and reporting-system data', () => {
  const alert = normalizeCloudflareWebhookAlert({
    name: 'Gateway block',
    text: 'Gateway blocked a risky connection',
    ts: 1791280800,
    alert_type: 'gateway_block',
    alert_correlation_id: 'cf-correlation-123',
    data: { zone_name: 'example.com', client_ip: '203.0.113.8', severity: 'high' }
  });

  assert.equal(alert.id, 'cloudflare-webhook-cf-correlation-123');
  assert.equal(alert.source, 'Cloudflare');
  assert.equal(alert.reportingSecuritySystem, 'Cloudflare');
  assert.equal(alert.domain, 'example.com');
  assert.equal(alert.severity, 'high');
});

test('Microsoft Graph notifications extract the alert resource ID and use Microsoft Graph source', () => {
  const notifications = getMicrosoftGraphSecurityNotificationIds({
    value: [{ resource: 'security/alerts/alert-42', clientState: 'secret' }]
  });
  const alert = normalizeMicrosoftGraphWebhookAlert({
    id: notifications[0].id,
    title: 'Suspicious sign-in',
    severity: 'medium',
    createdDateTime: '2026-10-06T10:00:00Z'
  });

  assert.equal(notifications[0].id, 'alert-42');
  assert.equal(alert.source, 'Microsoft Graph');
  assert.equal(alert.reportingSecuritySystem, 'Microsoft Graph');
  assert.equal(alert.severity, 'medium');
});
