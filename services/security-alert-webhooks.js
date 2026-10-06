const crypto = require('crypto');

function normalizeWebhookSeverity(value) {
  const text = String(value || '').toLowerCase();
  if (/critical|emergency|fatal/.test(text)) return 'critical';
  if (/high|error|danger/.test(text)) return 'high';
  if (/medium|warning|warn/.test(text)) return 'medium';
  return 'low';
}

function normalizeWebhookStatus(value) {
  const text = String(value || '').toLowerCase();
  if (/resolve|close|recover|clear|normal/.test(text)) return 'resolved';
  if (/progress/.test(text)) return 'inProgress';
  return 'active';
}

function shortText(value, fallback = '') {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  return (text || fallback).slice(0, 900);
}

function safeWebhookId(value, fallbackSource) {
  const text = String(value || '').trim();
  if (text) return text.slice(0, 240);
  return crypto.createHash('sha256').update(JSON.stringify(fallbackSource || {})).digest('hex').slice(0, 48);
}

function normalizeCloudflareWebhookAlert(payload = {}) {
  const data = payload?.data && typeof payload.data === 'object' ? payload.data : {};
  const alertEvent = payload.alert_event || data.alert_event || data.event || 'active';
  const correlationId = payload.alert_correlation_id || data.alert_correlation_id || data.id;
  const title = shortText(
    data.title || data.name || data.alert_name || payload.name || payload.alert_type,
    'Cloudflare security alert'
  );
  const description = shortText(data.description || data.message || payload.text, title);
  const domain = data.zone_name || data.zone || data.hostname || data.host || data.domain || null;
  const ipAddress = data.client_ip || data.ip || data.source_ip || null;
  const timestamp = payload.ts ? new Date(Number(payload.ts) * 1000) : new Date();
  const eventTime = Number.isFinite(timestamp.getTime()) ? timestamp.toISOString() : new Date().toISOString();

  return {
    id: `cloudflare-webhook-${safeWebhookId(correlationId, payload)}`,
    correlationId: correlationId || null,
    title,
    description,
    severity: normalizeWebhookSeverity(data.severity || payload.severity || data.level || payload.alert_type),
    status: normalizeWebhookStatus(alertEvent),
    created: eventTime,
    eventTime,
    category: shortText(payload.alert_type || data.alert_type || payload.policy_name, 'Cloudflare alert'),
    source: 'Cloudflare',
    reportingSecuritySystem: 'Cloudflare',
    vendor: 'Cloudflare',
    domain,
    zoneName: data.zone_name || null,
    ipAddress,
    cloudflareWebhook: true,
    rawAlertEvent: alertEvent
  };
}

function getMicrosoftGraphSecurityNotificationIds(body = {}) {
  const values = Array.isArray(body?.value) ? body.value : [];
  return values.map(item => {
    const resource = String(item?.resource || '');
    const id = item?.resourceData?.id || resource.split('/').filter(Boolean).pop();
    return { id: id ? String(id) : null, notification: item };
  }).filter(item => item.id);
}

function normalizeMicrosoftGraphWebhookAlert(alert = {}) {
  return {
    id: alert.id,
    title: shortText(alert.title || alert.alertName || alert.displayName, 'Microsoft Graph security alert'),
    description: shortText(alert.description || alert.message),
    severity: normalizeWebhookSeverity(alert.severity),
    status: normalizeWebhookStatus(alert.status),
    created: alert.createdDateTime || new Date().toISOString(),
    eventTime: alert.eventDateTime || alert.createdDateTime || new Date().toISOString(),
    category: shortText(alert.category || alert.serviceSource || alert.classification, 'Microsoft Graph alert'),
    source: 'Microsoft Graph',
    reportingSecuritySystem: 'Microsoft Graph',
    vendor: alert.vendorInformation?.provider || alert.serviceSource || 'Microsoft',
    user: (alert.userStates || [])[0]?.accountName || alert.userPrincipalName || alert.assignedTo || null,
    ipAddress: alert.ipAddress || alert.clientIpAddress || alert.sourceIpAddress || null,
    deviceName: alert.deviceName || alert.hostName || alert.hostname || null
  };
}

module.exports = {
  getMicrosoftGraphSecurityNotificationIds,
  normalizeCloudflareWebhookAlert,
  normalizeMicrosoftGraphWebhookAlert,
  normalizeWebhookSeverity,
  normalizeWebhookStatus
};
