const assert = require('node:assert/strict');
const test = require('node:test');
const axios = require('axios');

const {
  buildSecurityAlertNotificationKey,
  getSecurityReportingSystem,
  getSecurityAlertSeverities,
  normalizeWhatsAppRecipient,
  sendHelloWorldTest,
  sendSecurityAlert
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

test('security reporting system is normalised to Cloudflare or Microsoft Graph', () => {
  assert.equal(getSecurityReportingSystem({ source: 'Cloudflare One Gateway' }), 'Cloudflare');
  assert.equal(getSecurityReportingSystem({ vendor: 'Microsoft Defender for Endpoint' }), 'Microsoft Graph');
  assert.equal(getSecurityReportingSystem({ source: 'Microsoft Entra ID' }), 'Microsoft Graph');
});

test('WhatsApp security alert template uses its fixed Meta header and five body parameters', async () => {
  const originalPost = axios.post;
  let requestBody;
  axios.post = async (_url, body) => {
    requestBody = body;
    return { data: { messages: [{ id: 'wamid.test' }] } };
  };

  try {
    await sendSecurityAlert(
      { severity: 'high', issue: 'Test issue', source: 'StackOps', eventTime: '2026-10-05T10:00:00Z' },
      {
        token: 'test-token',
        phoneNumberId: 'test-phone-number'
      }
    );

    const components = requestBody.template.components;
    assert.equal(components.length, 1);
    assert.equal(components[0].type, 'body');
    assert.equal(components[0].parameters.length, 5);
    assert.equal(components[0].parameters[2].text, 'Microsoft Graph');
  } finally {
    axios.post = originalPost;
  }
});

test('WhatsApp hello_world test sends the fixed Meta template without security-alert components', async () => {
  const originalPost = axios.post;
  let requestBody;
  axios.post = async (_url, body) => {
    requestBody = body;
    return { data: { messages: [{ id: 'wamid.hello-world-test' }] } };
  };

  try {
    const response = await sendHelloWorldTest({
      token: 'test-token',
      phoneNumberId: 'test-phone-number',
      recipient: '27762609804'
    });

    assert.deepEqual(requestBody.template, {
      name: 'hello_world',
      language: { code: 'en_US' }
    });
    assert.equal(response.templateName, 'hello_world');
    assert.equal(response.recipient, '27762609804');
  } finally {
    axios.post = originalPost;
  }
});
