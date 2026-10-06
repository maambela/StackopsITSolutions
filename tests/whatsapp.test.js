const assert = require('node:assert/strict');
const test = require('node:test');
const axios = require('axios');

const {
  buildSecurityAlertNotificationKey,
  buildSecurityAlertSemanticNotificationKey,
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

test('semantic notification key groups recurring provider alerts but keeps different assets separate', () => {
  const original = {
    recordType: 'alert', id: 'cloudflare-1', source: 'Cloudflare One',
    issue: 'Gateway policy blocked 203.0.113.42', ipAddress: '203.0.113.42'
  };
  const repeated = { ...original, id: 'cloudflare-2', issue: 'Gateway policy blocked 203.0.113.99' };
  const differentAsset = { ...repeated, ipAddress: '198.51.100.8' };
  assert.equal(
    buildSecurityAlertSemanticNotificationKey(original, '27762609804'),
    buildSecurityAlertSemanticNotificationKey(repeated, '27762609804')
  );
  assert.notEqual(
    buildSecurityAlertSemanticNotificationKey(original, '27762609804'),
    buildSecurityAlertSemanticNotificationKey(differentAsset, '27762609804')
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
    const header = components.find(component => component.type === 'header');
    const body = components.find(component => component.type === 'body');
    assert.equal(components.length, 2);
    assert.equal(header.parameters[0].type, 'image');
    assert.equal(header.parameters[0].image.link, 'https://stackopsit.co.za/Images/Logos/MinimalistStackCTRL.png');
    assert.equal(body.parameters.length, 5);
    assert.equal(body.parameters[2].text, 'Microsoft Graph');
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
