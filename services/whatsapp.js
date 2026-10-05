const axios = require('axios');
const crypto = require('crypto');

const DEFAULT_COUNTRY_CODE = '27';
const DEFAULT_GRAPH_VERSION = process.env.WHATSAPP_GRAPH_VERSION || 'v25.0';
const DEFAULT_RECIPIENT = process.env.WHATSAPP_SECURITY_ALERT_RECIPIENT || '27762609804';
const DEFAULT_SECURITY_ALERT_TEMPLATE = process.env.WHATSAPP_SECURITY_ALERT_TEMPLATE || 'security_monitoring_alert';
const DEFAULT_TEMPLATE_LANGUAGE =
  process.env.WHATSAPP_SECURITY_ALERT_TEMPLATE_LANGUAGE ||
  process.env.WHATSAPP_TEMPLATE_LANGUAGE ||
  'en_US';

const SEVERITY_LABELS = {
  critical: '[CRITICAL]',
  high: '[HIGH]',
  medium: '[MEDIUM]',
  low: '[LOW]'
};

// Low-risk events are intentionally excluded from WhatsApp notifications. They
// remain visible in the security dashboard, but should not create alert noise.
const DEFAULT_SECURITY_ALERT_SEVERITIES = Object.freeze(['critical', 'high', 'medium']);

function normalizeSeverity(value) {
  const severity = String(value || 'medium').toLowerCase();
  if (severity === 'critical') return 'critical';
  if (severity === 'high') return 'high';
  if (severity === 'medium' || severity === 'mid') return 'medium';
  return 'low';
}

function getSecurityAlertSeverities(value) {
  const requested = String(value || DEFAULT_SECURITY_ALERT_SEVERITIES.join(','))
    .split(',')
    .map(item => normalizeSeverity(item.trim()));
  const allowed = new Set(DEFAULT_SECURITY_ALERT_SEVERITIES);
  const severities = [...new Set(requested.filter(severity => allowed.has(severity)))];
  return severities.length ? severities : [...DEFAULT_SECURITY_ALERT_SEVERITIES];
}

function normalizeWhatsAppRecipient(value, defaultCountryCode = DEFAULT_COUNTRY_CODE) {
  const digits = String(value || DEFAULT_RECIPIENT).replace(/\D/g, '');
  if (!digits) return DEFAULT_RECIPIENT;
  if (digits.startsWith('0')) return `${defaultCountryCode}${digits.slice(1)}`;
  return digits;
}

function buildSecurityAlertNotificationKey(alert = {}, recipient = '') {
  const recordType = String(alert.recordType || alert.type || 'security').toLowerCase();
  const stableId = alert.id || alert.uid || alert.alertId || alert.incidentId;
  const identity = stableId
    ? `id:${String(stableId)}`
    : JSON.stringify({
      issue: alert.issue || alert.title || alert.displayName || alert.name || 'Security alert',
      source: alert.source || alert.category || alert.vendor || '',
      created: alert.eventTime || alert.created || alert.createdDateTime || alert.timestamp || ''
    });
  const fingerprint = crypto
    .createHash('sha256')
    .update(`${recordType}|${normalizeWhatsAppRecipient(recipient)}|${identity}`)
    .digest('hex');
  return `security-alert:${fingerprint}`;
}

function formatDateTime(value, timeZone = 'Africa/Johannesburg') {
  const date = value ? new Date(value) : new Date();
  const safeDate = Number.isFinite(date.getTime()) ? date : new Date();
  const dateText = new Intl.DateTimeFormat('en-ZA', {
    timeZone,
    year: 'numeric',
    month: 'short',
    day: '2-digit'
  }).format(safeDate);
  const timeText = new Intl.DateTimeFormat('en-ZA', {
    timeZone,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).format(safeDate);
  return { dateText, timeText };
}

function buildSecurityAlertMessage(alert = {}, options = {}) {
  const severity = normalizeSeverity(alert.severity);
  const { dateText, timeText } = formatDateTime(
    alert.eventTime || alert.timestamp || alert.created || alert.updated,
    options.timeZone
  );
  const issue = alert.issue || alert.title || alert.displayName || alert.name || 'Security alert';
  const assignedTo = alert.assignedTo || alert.owner || alert.assignee;
  const status = alert.status ? `\nStatus: ${alert.status}` : '';
  const source = alert.source || alert.category || alert.vendor;

  return [
    'Security Alert',
    '',
    `Severity: ${SEVERITY_LABELS[severity]} ${severity.toUpperCase()}`,
    `Date: ${dateText}`,
    `Time: ${timeText}`,
    `Issue: ${issue}`,
    assignedTo ? `Assigned to: ${assignedTo}` : 'Assigned to: Unassigned',
    source ? `Source: ${source}` : '',
    status.trim()
  ].filter(Boolean).join('\n');
}

function toTemplateText(value, fallback) {
  const text = String(value || fallback || '')
    .replace(/\s+/g, ' ')
    .trim();
  return (text || String(fallback || '')).slice(0, 900);
}

function getSecurityAlertAction(alert = {}) {
  return alert.action ||
    alert.recommendedAction ||
    alert.remediation ||
    alert.nextStep ||
    alert.status ||
    "Review the event immediately";
}

async function sendWhatsAppText({ token, phoneNumberId, to, text, apiVersion = DEFAULT_GRAPH_VERSION }) {
  if (!token) throw new Error('WHATSAPP_ACCESS_TOKEN is not configured');
  if (!phoneNumberId) throw new Error('WHATSAPP_PHONE_NUMBER_ID is not configured');

  const recipient = normalizeWhatsAppRecipient(to);
  const url = `https://graph.facebook.com/${apiVersion}/${phoneNumberId}/messages`;
  const response = await axios.post(
    url,
    {
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to: recipient,
      type: 'text',
      text: {
        preview_url: false,
        body: text
      }
    },
    {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: 15000
    }
  );

  return {
    ...response.data,
    recipient,
    phoneNumberId
  };
}

async function sendSecurityAlertTemplate(alert = {}, config = {}) {
  if (!config.token) throw new Error('WHATSAPP_ACCESS_TOKEN is not configured');
  if (!config.phoneNumberId) throw new Error('WHATSAPP_PHONE_NUMBER_ID is not configured');

  const severity = normalizeSeverity(alert.severity).toUpperCase();
  const { dateText, timeText } = formatDateTime(
    alert.eventTime || alert.timestamp || alert.created || alert.updated,
    config.timeZone
  );
  const eventTime = dateText + " " + timeText;
  const recipient = normalizeWhatsAppRecipient(config.recipient || DEFAULT_RECIPIENT);
  const apiVersion = config.apiVersion || DEFAULT_GRAPH_VERSION;
  const templateName = config.templateName || DEFAULT_SECURITY_ALERT_TEMPLATE;
  const templateLanguage = config.templateLanguage || DEFAULT_TEMPLATE_LANGUAGE;
  const url = `https://graph.facebook.com/${apiVersion}/${config.phoneNumberId}/messages`;

  const response = await axios.post(
    url,
    {
      messaging_product: 'whatsapp',
      to: recipient,
      type: 'template',
      template: {
        name: templateName,
        language: { code: templateLanguage },
        components: [
          {
            type: 'body',
            parameters: [
              { type: "text", text: severity },
              { type: "text", text: toTemplateText(alert.issue || alert.title || alert.displayName || alert.name, "Security alert") },
              { type: "text", text: toTemplateText(alert.source || alert.category || alert.vendor, "StackOps Security") },
              { type: "text", text: eventTime },
              { type: "text", text: toTemplateText(getSecurityAlertAction(alert), "Review the event immediately") }
            ]
          }
        ]
      }
    },
    {
      headers: {
        Authorization: `Bearer ${config.token}`,
        'Content-Type': 'application/json'
      },
      timeout: 15000
    }
  );

  return {
    ...response.data,
    recipient,
    phoneNumberId: config.phoneNumberId,
    templateName,
    templateLanguage
  };
}

async function sendHelloWorldTest(config = {}) {
  if (!config.token) throw new Error('WHATSAPP_ACCESS_TOKEN is not configured');
  if (!config.phoneNumberId) throw new Error('WHATSAPP_PHONE_NUMBER_ID is not configured');

  const recipient = normalizeWhatsAppRecipient(config.recipient || DEFAULT_RECIPIENT);
  const apiVersion = config.apiVersion || DEFAULT_GRAPH_VERSION;
  const url = `https://graph.facebook.com/${apiVersion}/${config.phoneNumberId}/messages`;

  const response = await axios.post(
    url,
    {
      messaging_product: 'whatsapp',
      to: recipient,
      type: 'template',
      template: {
        name: 'hello_world',
        language: { code: 'en_US' }
      }
    },
    {
      headers: {
        Authorization: `Bearer ${config.token}`,
        'Content-Type': 'application/json'
      },
      timeout: 15000
    }
  );

  return {
    ...response.data,
    recipient,
    phoneNumberId: config.phoneNumberId,
    templateName: 'hello_world'
  };
}

async function sendSecurityAlert(alert, config) {
  return sendSecurityAlertTemplate(alert, config);
}

module.exports = {
  DEFAULT_SECURITY_ALERT_SEVERITIES,
  buildSecurityAlertNotificationKey,
  buildSecurityAlertMessage,
  formatDateTime,
  getSecurityAlertSeverities,
  normalizeSeverity,
  normalizeWhatsAppRecipient,
  sendHelloWorldTest,
  sendSecurityAlert,
  sendSecurityAlertTemplate,
  sendWhatsAppText
};
