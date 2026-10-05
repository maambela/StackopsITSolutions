const crypto = require('crypto');

function constantTimeStringEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function verifyMetaWebhookSignature(rawBody, signature, appSecret) {
  if (typeof rawBody !== 'string' || !signature || !appSecret) return false;
  const expected = `sha256=${crypto.createHmac('sha256', appSecret).update(rawBody).digest('hex')}`;
  return constantTimeStringEqual(signature, expected);
}

function extractWhatsAppStatusEvents(payload) {
  const events = [];
  for (const entry of Array.isArray(payload?.entry) ? payload.entry : []) {
    for (const change of Array.isArray(entry?.changes) ? entry.changes : []) {
      const value = change?.value;
      for (const status of Array.isArray(value?.statuses) ? value.statuses : []) {
        events.push({
          field: change?.field || null,
          wabaId: entry?.id || null,
          phoneNumberId: value?.metadata?.phone_number_id || null,
          displayPhoneNumber: value?.metadata?.display_phone_number || null,
          messageId: status?.id || null,
          recipientId: status?.recipient_id || null,
          status: status?.status || 'unknown',
          timestamp: status?.timestamp || null,
          errors: Array.isArray(status?.errors) ? status.errors : []
        });
      }
    }
  }
  return events;
}

module.exports = {
  constantTimeStringEqual,
  extractWhatsAppStatusEvents,
  verifyMetaWebhookSignature
};
