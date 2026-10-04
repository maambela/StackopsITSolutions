const assert = require('node:assert/strict');
const test = require('node:test');

const {
  buildSecurityAlertNotificationKey,
  getSecurityAlertSeverities,
  normalizeWhatsAppRecipient
} = require('../services/whatsapp');

test('WhatsApp notification key is stable for a Microsoft alert ID and recipient', () => {
  const original = {
    recordType: 'alert',
    id: 'microsoft-alert-123',
    issue: 'Initial title',
    updated: '2026-10-05T08:00:00Z'
  };
  const refreshed = {
    ...original,
    issue: 'Updated title from Microsoft',
    updated: '2026-10-05T08:05:00Z'
  };

  assert.equal(
    buildSecurityAlertNotificationKey(original, '076 260 9804'),
    buildSecurityAlertNotificationKey(refreshed, '27762609804')
  );
});

test('WhatsApp notification key is scoped to its recipient', () => {
  const alert = { recordType: 'incident', incidentId: 'incident-45' };
  assert.notEqual(
    buildSecurityAlertNotificationKey(alert, '27762609804'),
    buildSecurityAlertNotificationKey(alert, '27820000000')
  );
});

test('WhatsApp alerts include only critical, high, and medium severities', () => {
  assert.deepEqual(getSecurityAlertSeverities('critical,high,medium,low'), ['critical', 'high', 'medium']);
  assert.deepEqual(getSecurityAlertSeverities('HIGH, medium, critical'), ['high', 'medium', 'critical']);
  assert.deepEqual(getSecurityAlertSeverities('low'), ['critical', 'high', 'medium']);
  assert.equal(normalizeWhatsAppRecipient('076 260 9804'), '27762609804');
});
