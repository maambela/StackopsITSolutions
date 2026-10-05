const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const {
  constantTimeStringEqual,
  extractWhatsAppStatusEvents,
  verifyMetaWebhookSignature
} = require('../services/whatsapp-webhook');

test('webhook verify token equality handles only matching strings', () => {
  assert.equal(constantTimeStringEqual('verify-token', 'verify-token'), true);
  assert.equal(constantTimeStringEqual('verify-token', 'wrong-token'), false);
  assert.equal(constantTimeStringEqual(undefined, 'verify-token'), false);
});

test('Meta webhook signature validates the exact raw request body', () => {
  const body = JSON.stringify({ object: 'whatsapp_business_account', entry: [] });
  const appSecret = 'test-app-secret';
  const signature = `sha256=${crypto.createHmac('sha256', appSecret).update(body).digest('hex')}`;

  assert.equal(verifyMetaWebhookSignature(body, signature, appSecret), true);
  assert.equal(verifyMetaWebhookSignature(`${body} `, signature, appSecret), false);
  assert.equal(verifyMetaWebhookSignature(body, signature, ''), false);
});

test('status extraction retains delivery state and full failure errors', () => {
  const errors = [{ code: 131026, title: 'Message undeliverable', details: 'Recipient unavailable' }];
  const events = extractWhatsAppStatusEvents({
    entry: [{
      id: 'waba-1',
      changes: [{
        field: 'messages',
        value: {
          metadata: { phone_number_id: 'phone-1', display_phone_number: '+27633968828' },
          statuses: [
            { id: 'wamid.delivered', recipient_id: '27762609804', status: 'delivered', timestamp: '123' },
            { id: 'wamid.failed', recipient_id: '27762609804', status: 'failed', errors }
          ]
        }
      }]
    }]
  });

  assert.equal(events.length, 2);
  assert.equal(events[0].status, 'delivered');
  assert.equal(events[0].messageId, 'wamid.delivered');
  assert.deepEqual(events[1].errors, errors);
  assert.equal(events[1].phoneNumberId, 'phone-1');
  assert.equal(events[1].wabaId, 'waba-1');
});
