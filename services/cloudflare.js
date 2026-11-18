const { fetchFirewallEvents } = require('./intelligence/cloudflare-firewall-events');
const { fetchCloudflarePages } = require('./intelligence/cloudflare-collection');
const axios = require('axios');

const CLOUDFLARE_BASE_URL = 'https://api.cloudflare.com/client/v4';

const CLOUDFLARE_PERMISSION_FAMILIES = [
  { id: 1, key: 'accountAnalytics', permission: 'Account Analytics - Read', endpointFamily: 'Account Analytics API / GraphQL Analytics', dataAvailable: 'Traffic analytics, requests, bandwidth, trends', module: 'Executive Dashboard' },
  { id: 2, key: 'accountLogs', permission: 'Account Logs - Read', endpointFamily: 'Account Logs API', dataAvailable: 'Platform logs', module: 'Logging' },
  { id: 3, key: 'auditLogs', permission: 'Audit Logs - Read', endpointFamily: 'Audit Logs API', dataAvailable: 'Administrative audit trail', module: 'Governance' },
  { id: 4, key: 'securityInsights', permission: 'Account Security Insights - Read', endpointFamily: 'Security Insights API', dataAvailable: 'Security posture, findings', module: 'Security Dashboard' },
  { id: 5, key: 'applicationSecurityReports', permission: 'Application Security Reports - Read', endpointFamily: 'Application Security Reports API', dataAvailable: 'Application security reports', module: 'Application Security' },
  { id: 6, key: 'apiGateway', permission: 'API Gateway - Read', endpointFamily: 'API Gateway API', dataAvailable: 'API discovery, API policies', module: 'API Security' },
  { id: 7, key: 'casb', permission: 'CASB - Read', endpointFamily: 'CASB API', dataAvailable: 'SaaS applications, findings', module: 'CASB Dashboard' },
  { id: 8, key: 'tunnels', permission: 'Cloudflare Tunnel - Read', endpointFamily: 'Tunnel API', dataAvailable: 'Tunnels, connectors, health', module: 'Infrastructure' },
  { id: 9, key: 'cloudforceOne', permission: 'Cloudforce One - Read', endpointFamily: 'Cloudforce One API', dataAvailable: 'Threat intelligence', module: 'Threat Intelligence' },
  { id: 10, key: 'devicePosture', permission: 'Device Posture - Read', endpointFamily: 'Device Posture API', dataAvailable: 'Device posture rules, compliance', module: 'Device Compliance' },
  { id: 11, key: 'dnsFirewall', permission: 'DNS Firewall - Read', endpointFamily: 'DNS Firewall API', dataAvailable: 'DNS Firewall policies', module: 'DNS Protection' },
  { id: 12, key: 'intel', permission: 'Intel - Read', endpointFamily: 'Intelligence API', dataAvailable: 'Threat indicators', module: 'Threat Intelligence' },
  { id: 13, key: 'loadBalancers', permission: 'Load Balancers & Monitors - Read', endpointFamily: 'Load Balancer API', dataAvailable: 'Pools, monitors, health', module: 'Infrastructure' },
  { id: 14, key: 'magicWan', permission: 'Magic WAN - Read', endpointFamily: 'Magic WAN API', dataAvailable: 'Sites, routes, WAN topology', module: 'Network Dashboard' },
  { id: 15, key: 'mtlsCertificates', permission: 'Mutual TLS Certificates - Read', endpointFamily: 'mTLS API', dataAvailable: 'Certificates', module: 'PKI Dashboard' },
  { id: 16, key: 'networks', permission: 'Networks - Read', endpointFamily: 'Networks API', dataAvailable: 'Networks, locations', module: 'Network Inventory' },
  { id: 17, key: 'teamsDex', permission: 'Teams DEX - Read', endpointFamily: 'Teams DEX API', dataAvailable: 'Device experience metrics', module: 'User Experience' },
  { id: 18, key: 'warpConnector', permission: 'WARP Connector - Read', endpointFamily: 'WARP Connector API', dataAvailable: 'WARP connectors, connector health', module: 'WARP Dashboard' },
  { id: 19, key: 'zeroTrust', permission: 'Zero Trust - Read', endpointFamily: 'Zero Trust API', dataAvailable: 'Tenant configuration', module: 'Zero Trust Overview' },
  { id: 20, key: 'accessApps', permission: 'Access: Apps & Policies - Read', endpointFamily: 'Access Applications API', dataAvailable: 'Protected Applications', module: 'Applications' },
  { id: 21, key: 'accessPolicies', permission: 'Access: Apps & Policies - Read', endpointFamily: 'Access Policies API', dataAvailable: 'Access Policies', module: 'Policy Dashboard' },
  { id: 22, key: 'accessAuditLogs', permission: 'Access: Audit Logs - Read', endpointFamily: 'Access Audit API', dataAvailable: 'Authentication events', module: 'Authentication Logs' },
  { id: 23, key: 'accessOrganizations', permission: 'Access: Organizations, Identity Providers & Groups - Read', endpointFamily: 'Organizations API', dataAvailable: 'Organization details', module: 'Tenant Overview' },
  { id: 24, key: 'identityProviders', permission: 'Access: Organizations, Identity Providers & Groups - Read', endpointFamily: 'Identity Providers API', dataAvailable: 'Entra ID, Google, Okta etc.', module: 'Identity' },
  { id: 25, key: 'accessGroups', permission: 'Access: Organizations, Identity Providers & Groups - Read', endpointFamily: 'Groups API', dataAvailable: 'Identity Groups', module: 'Identity' },
  { id: 26, key: 'accessMtlsCertificates', permission: 'Access: Mutual TLS Certificates - Read', endpointFamily: 'mTLS Certificates API', dataAvailable: 'Client Certificates', module: 'Certificates' }
];

const FAMILY_BY_KEY = Object.freeze(Object.fromEntries(CLOUDFLARE_PERMISSION_FAMILIES.map(family => [family.key, family])));

const CLOUDFLARE_ENDPOINTS = [
  { key: 'notificationHistory', familyKey: 'securityInsights', label: 'Notification history', path: accountId => `/accounts/${accountId}/alerting/v3/history`, query: () => ({ per_page: 100 }) },
  { key: 'account', familyKey: 'zeroTrust', label: 'Account Information', path: accountId => `/accounts/${accountId}` },
  { key: 'accountLogs', familyKey: 'accountLogs', label: 'Account Logs', emptyOnStatuses: [400, 404], path: accountId => `/accounts/${accountId}/logs/audit` },
  { key: 'auditLogs', familyKey: 'auditLogs', label: 'Audit Logs', path: accountId => `/accounts/${accountId}/audit_logs`, query: () => buildRecentCloudflareQuery({ per_page: 100 }) },
  { key: 'securityInsights', familyKey: 'securityInsights', label: 'Security Insights', path: accountId => `/accounts/${accountId}/security-center/insights` },
  { key: 'applicationSecurityReports', familyKey: 'applicationSecurityReports', label: 'Application Security Reports', path: accountId => `/accounts/${accountId}/security-center/insights` },
  { key: 'apiGateway', familyKey: 'apiGateway', label: 'API Gateway Discovery', scope: 'zone', path: zoneId => `/zones/${zoneId}/api_gateway/discovery/operations` },
  { key: 'casbFindings', familyKey: 'casb', label: 'CASB Findings', path: accountId => `/accounts/${accountId}/casb/findings` },
  { key: 'tunnels', familyKey: 'tunnels', label: 'Cloudflare Tunnels', path: accountId => `/accounts/${accountId}/cfd_tunnel` },
  { key: 'cloudforceRequests', familyKey: 'cloudforceOne', label: 'Cloudforce One Requests', method: 'post', path: accountId => `/accounts/${accountId}/cloudforce-one/requests`, body: {} },
  { key: 'intelFeeds', familyKey: 'intel', label: 'Intel Indicator Feeds', path: accountId => `/accounts/${accountId}/intel/indicator-feeds` },
  { key: 'dnsFirewall', familyKey: 'dnsFirewall', label: 'DNS Firewall', path: accountId => `/accounts/${accountId}/dns_firewall` },
  { key: 'loadBalancerPools', familyKey: 'loadBalancers', label: 'Load Balancer Pools', path: accountId => `/accounts/${accountId}/load_balancers/pools` },
  { key: 'loadBalancerMonitors', familyKey: 'loadBalancers', label: 'Load Balancer Monitors', path: accountId => `/accounts/${accountId}/load_balancers/monitors` },
  { key: 'magicWanSites', familyKey: 'magicWan', label: 'Magic WAN Sites', path: accountId => `/accounts/${accountId}/magic/sites` },
  { key: 'magicWanRoutes', familyKey: 'magicWan', label: 'Magic WAN Routes', path: accountId => `/accounts/${accountId}/magic/routes` },
  { key: 'mtlsCertificates', familyKey: 'mtlsCertificates', label: 'Mutual TLS Certificates', path: accountId => `/accounts/${accountId}/mtls_certificates` },
  { key: 'apps', familyKey: 'accessApps', label: 'Access Applications', path: accountId => `/accounts/${accountId}/access/apps` },
  { key: 'identityProviders', familyKey: 'identityProviders', label: 'Identity Providers', path: accountId => `/accounts/${accountId}/access/identity_providers` },
  { key: 'accessGroups', familyKey: 'accessGroups', label: 'Access Groups', path: accountId => `/accounts/${accountId}/access/groups` },
  { key: 'accessOrganizations', familyKey: 'accessOrganizations', label: 'Access Organizations', path: accountId => `/accounts/${accountId}/access/organizations` },
  { key: 'accessCertificates', familyKey: 'accessMtlsCertificates', label: 'Access mTLS Certificates', path: accountId => `/accounts/${accountId}/access/certificates` },
  { key: 'policies', familyKey: 'accessPolicies', label: 'Access Policies', path: accountId => `/accounts/${accountId}/access/policies` },
  { key: 'devices', familyKey: 'zeroTrust', label: 'Devices', path: accountId => `/accounts/${accountId}/devices` },
  { key: 'deviceRegistrations', familyKey: 'warpConnector', label: 'Device Registrations', path: accountId => `/accounts/${accountId}/devices/registrations` },
  { key: 'devicePosture', familyKey: 'devicePosture', label: 'Device Posture', path: accountId => `/accounts/${accountId}/devices/posture` },
  { key: 'warpProfiles', familyKey: 'warpConnector', label: 'WARP Profiles', path: accountId => `/accounts/${accountId}/devices/policies` },
  { key: 'warpConnectors', familyKey: 'warpConnector', label: 'WARP Connectors', path: accountId => `/accounts/${accountId}/warp_connector` },
  { key: 'gatewayRules', familyKey: 'zeroTrust', label: 'Gateway Rules', path: accountId => `/accounts/${accountId}/gateway/rules` },
  { key: 'gatewayConfig', familyKey: 'zeroTrust', label: 'Gateway Configuration', path: accountId => `/accounts/${accountId}/gateway/configuration` },
  { key: 'gatewayLogging', familyKey: 'zeroTrust', label: 'Gateway Logging Settings', path: accountId => `/accounts/${accountId}/gateway/logging` },
  { key: 'gatewayLists', familyKey: 'zeroTrust', label: 'Gateway Lists', path: accountId => `/accounts/${accountId}/gateway/lists` },
  { key: 'gatewayAppTypes', familyKey: 'zeroTrust', label: 'Gateway App Categories', path: accountId => `/accounts/${accountId}/gateway/app_types` },
  { key: 'deviceSettings', familyKey: 'zeroTrust', label: 'Device Settings', path: accountId => `/accounts/${accountId}/devices/settings` },
  { key: 'virtualNetworks', familyKey: 'networks', label: 'Virtual Networks', path: accountId => `/accounts/${accountId}/teamnet/virtual_networks` },
  { key: 'teamnetRoutes', familyKey: 'networks', label: 'Network Routes', path: accountId => `/accounts/${accountId}/teamnet/routes` },
  { key: 'accessLogs', familyKey: 'accessAuditLogs', label: 'Access Logs', path: accountId => `/accounts/${accountId}/access/logs/access_requests`, query: () => buildRecentCloudflareQuery({ per_page: 100 }) },
  { key: 'teamsDexTests', familyKey: 'teamsDex', label: 'Teams DEX Tests', path: accountId => `/accounts/${accountId}/dex/tests/overview` },
  { key: 'dlpProfiles', familyKey: 'zeroTrust', label: 'DLP Profiles', path: accountId => `/accounts/${accountId}/dlp/profiles` },
  { key: 'zones', familyKey: 'accountAnalytics', label: 'Zones', path: () => '/zones' }
];
function buildRecentCloudflareQuery({ days = Number(process.env.SECURITY_EVIDENCE_HISTORY_DAYS) || 15, limit = null, per_page = null } = {}) {
  const until = new Date().toISOString();
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const query = { since, until, direction: 'desc' };
  if (limit != null) query.limit = limit;
  if (per_page != null) query.per_page = per_page;
  return query;
}

function sanitizeGatewayList(list) {
  return {
    id: list.id || null,
    name: list.name || 'Gateway list',
    type: firstDefined(list.type, list.list_type, null),
    description: list.description || null,
    count: Array.isArray(list.items) ? list.items.length : Number(list.count || 0) || null
  };
}

function sanitizeGatewayLoggingSettings(logging) {
  const settings = logging?.result || logging || {};
  const byType = settings.settings_by_rule_type || {};
  return {
    id: 'gateway-logging',
    name: 'Gateway logging settings',
    redactPii: settings.redact_pii ?? null,
    dnsLogAll: byType.dns?.log_all ?? null,
    dnsLogBlocks: byType.dns?.log_blocks ?? null,
    httpLogAll: byType.http?.log_all ?? null,
    httpLogBlocks: byType.http?.log_blocks ?? null,
    l4LogAll: byType.l4?.log_all ?? null,
    l4LogBlocks: byType.l4?.log_blocks ?? null
  };
}

function sanitizeDeviceSettings(settings) {
  const result = settings?.result || settings || {};
  return {
    id: 'device-settings',
    name: 'Account device settings',
    gatewayProxyEnabled: result.gateway_proxy_enabled ?? null,
    udpProxyEnabled: result.gateway_udp_proxy_enabled ?? null,
    certificateEnabled: result.root_certificate_installation_enabled ?? null,
    useZtVirtualIp: result.use_zt_virtual_ip ?? null,
    disableForTime: result.disable_for_time ?? null
  };
}

function getList(result) {
  if (Array.isArray(result)) return result;
  if (Array.isArray(result?.result)) return result.result;
  if (Array.isArray(result?.result_info?.result)) return result.result_info.result;
  return [];
}

function firstDefined(...values) {
  return values.find(value => value !== undefined && value !== null && value !== '');
}

function formatWarpServiceMode(profile) {
  const modeV2 = profile?.service_mode_v2;
  if (modeV2 && typeof modeV2 === 'object') {
    const mode = firstDefined(modeV2.mode, modeV2.service_mode, null);
    const port = modeV2.port;
    if (mode && port) return `${mode} (port ${port})`;
    if (mode) return mode;
  }
  return firstDefined(
    profile.service_mode,
    profile.serviceMode,
    profile.service_mode_v2_mode,
    profile.tunnel_protocol,
    profile.tunnelProtocol,
    null
  );
}

function valueAtPath(input, path) {
  return String(path).split('.').reduce((current, part) => current?.[part], input);
}

function firstValueAtPath(input, paths = []) {
  for (const path of paths) {
    const value = valueAtPath(input, path);
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return null;
}

function boolFromCloudflareSetting(input, paths = []) {
  const value = firstValueAtPath(input, paths);
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  if (typeof value === 'string') return /^(true|enabled|active|on|yes|masked)$/i.test(value.trim());
  return Boolean(value);
}

function toIso(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

function getTimeValue(value) {
  const date = new Date(value || 0);
  return Number.isFinite(date.getTime()) ? date.getTime() : 0;
}

function maskSensitiveObject(input) {
  if (!input || typeof input !== 'object') return input;
  if (Array.isArray(input)) return input.map(maskSensitiveObject);

  const masked = {};
  Object.entries(input).forEach(([key, value]) => {
    if (/token|secret|private|certificate|cert|public_key|serial|mac|key/i.test(key)) {
      masked[key] = value ? 'masked' : value;
    } else if (value && typeof value === 'object') {
      masked[key] = maskSensitiveObject(value);
    } else {
      masked[key] = value;
    }
  });
  return masked;
}

function sanitizeAccount(data) {
  const result = data?.result || data || {};
  return {
    id: result.id || null,
    name: result.name || 'Cloudflare Account',
    type: result.type || null,
    createdOn: toIso(result.created_on),
    settings: maskSensitiveObject(result.settings || {})
  };
}

function sanitizeApp(app) {
  return {
    id: app.id || null,
    name: app.name || app.aud || 'Access app',
    type: app.type || app.app_launcher_visible || 'self_hosted',
    domain: app.domain || app.hostname || null,
    sessionDuration: app.session_duration || app.sessionDuration || null,
    policies: Array.isArray(app.policies) ? app.policies.map(policy => ({
      id: policy.id || null,
      name: policy.name || 'Policy',
      decision: policy.decision || null
    })) : []
  };
}

function sanitizeIdentityProvider(provider) {
  return {
    id: provider.id || null,
    name: provider.name || provider.type || 'Identity provider',
    type: provider.type || null,
    status: provider.id ? 'active' : 'configured'
  };
}

function sanitizePolicy(policy) {
  return {
    id: policy.id || null,
    name: policy.name || 'Access policy',
    decision: policy.decision || null,
    sessionDuration: policy.session_duration || null,
    includes: Array.isArray(policy.include) ? policy.include.map(maskSensitiveObject) : [],
    requires: Array.isArray(policy.require) ? policy.require.map(maskSensitiveObject) : []
  };
}

function sanitizeDevice(device) {
  return {
    id: device.id || device.device_id || null,
    name: firstDefined(device.name, device.hostname, device.device_name, device.serial_number, 'Device'),
    userEmail: firstDefined(device.user?.email, device.email, device.owner?.email, device.user_email, null),
    os: firstDefined(device.os, device.os_version, device.platform, device.device_type, null),
    model: firstDefined(device.model, device.manufacturer, null),
    warpVersion: firstDefined(device.warp_version, device.version, device.client_version, null),
    lastSeen: toIso(firstDefined(device.last_seen, device.last_seen_at, device.updated_at, device.created_at)),
    ipAddress: firstDefined(device.ip, device.ip_address, device.client_ip, null),
    status: firstDefined(device.status, device.active === false ? 'inactive' : 'active')
  };
}

function sanitizeRegistration(registration) {
  return {
    id: registration.id || null,
    deviceName: firstDefined(registration.device?.name, registration.name, registration.hostname, 'Registered device'),
    userEmail: firstDefined(registration.user?.email, registration.email, registration.user_email, null),
    virtualIpv4: firstDefined(registration.virtual_ipv4, registration.vnet_ipv4, registration.ipv4, null),
    virtualIpv6: firstDefined(registration.virtual_ipv6, registration.vnet_ipv6, registration.ipv6, null),
    tunnelType: firstDefined(registration.tunnel_type, registration.tunnelType, null),
    lastSeen: toIso(firstDefined(registration.last_seen, registration.last_seen_at, registration.updated_at)),
    status: firstDefined(registration.status, 'registered')
  };
}

function sanitizeGatewayRule(rule) {
  return {
    id: rule.id || null,
    name: rule.name || 'Gateway rule',
    action: rule.action || null,
    enabled: rule.enabled !== false,
    precedence: rule.precedence ?? null,
    traffic: rule.traffic || null,
    filters: Array.isArray(rule.filters) ? rule.filters : []
  };
}

function sanitizeWarpProfile(profile) {
  return {
    id: profile.id || null,
    name: profile.name || 'WARP profile',
    enabled: profile.enabled !== false,
    allowModeSwitch: profile.allow_mode_switch ?? null,
    allowUpdates: profile.allow_updates ?? null,
    allowedToLeave: profile.allowed_to_leave ?? null,
    autoConnect: profile.auto_connect ?? null,
    serviceMode: formatWarpServiceMode(profile),
    precedence: firstDefined(profile.precedence, profile.priority, profile.order, null)
  };
}

function sanitizeAccessLog(log) {
  return {
    id: log.id || log.ray_id || null,
    userEmail: firstDefined(log.user_email, log.email, log.actor?.email, log.user?.email, null),
    appName: firstDefined(log.app_name, log.application?.name, log.aud, 'Access request'),
    action: firstDefined(log.action, log.decision, log.allowed === false ? 'blocked' : 'allowed'),
    connection: firstDefined(log.connection, log.connection_method, log.login_method, null),
    country: firstDefined(log.country, log.location?.country, null),
    ipAddress: firstDefined(log.ip_address, log.ip, log.client_ip, null),
    allowed: log.allowed !== false && log.action !== 'blocked',
    timestamp: toIso(firstDefined(log.created_at, log.timestamp, log.datetime, log.time)),
    rayId: log.ray_id || null
  };
}

function sanitizeDlpProfile(profile) {
  return {
    id: profile.id || null,
    name: profile.name || 'DLP profile',
    enabled: profile.enabled !== false,
    entries: Array.isArray(profile.entries) ? profile.entries.length : 0,
    detections: Array.isArray(profile.allowed_match_count) ? profile.allowed_match_count.length : null
  };
}

function summarizeSectionError(error, endpoint = {}) {
  const response = error?.response;
  const status = response?.status || 500;
  const cfErrors = Array.isArray(response?.data?.errors) ? response.data.errors : [];
  const code = cfErrors[0]?.code || null;
  const message = cfErrors[0]?.message || error.message || 'Cloudflare request failed';
  const permissionUnavailable = status === 403 || Number(code) === 9109;
  const emptyStatus = Array.isArray(endpoint.emptyOnStatuses) && endpoint.emptyOnStatuses.includes(status);
  const featureUnavailable = emptyStatus || status === 404 || /not found|resource\.not_found|invalid HTTP method or path/i.test(message);

  return {
    status: permissionUnavailable ? 'permission_unavailable' : featureUnavailable ? 'unavailable' : 'error',
    httpStatus: status,
    code,
    message
  };
}

async function fetchCloudflareEndpoint(client, endpoint, accountId, options = {}) {
  const method = String(endpoint.method || 'get').toLowerCase();
  const url = endpoint.path(accountId);
  const collector = endpoint.key === 'zones' ? null : options.collection;
  const previous = collector?.getState('Cloudflare', url);
  const incremental = !options.range?.explicit && ['stored', 'memory_only'].includes(previous?.storageStatus) && previous.completeThrough && Date.now() - Date.parse(previous.lastReconciledAt || '') < 3600000;
  let query = typeof endpoint.query === 'function' ? endpoint.query(accountId) : endpoint.query;
  if (endpoint.key === 'zones') query = { ...query, 'account.id': accountId };
  if (['accessLogs', 'auditLogs', 'accountLogs', 'notificationHistory'].includes(endpoint.key)) {
    const range = options.range || { since: new Date(Date.now() - (Number(process.env.SECURITY_EVIDENCE_HISTORY_DAYS) || 15) * 86400000).toISOString(), until: new Date().toISOString() };
    const since = incremental ? new Date(Math.max(Date.parse(range.since), Date.parse(previous.completeThrough) - 300000)).toISOString() : range.since;
    query = { ...query, since, ...(['notificationHistory', 'accountLogs'].includes(endpoint.key) ? { before: range.until } : { until: range.until }) };
    if (['accessLogs', 'auditLogs', 'accountLogs'].includes(endpoint.key)) query.direction = 'desc';
  }
  if (method === 'post') return (await client.post(url, endpoint.body || {})).data;
  let latest = [];
  let resumeQuery = previous?.continuation || null, head;
  const recordKey = row => row.id || row.uuid || JSON.stringify(row);
  if (previous?.continuation) {
    head = await fetchCloudflarePages(client, url, query, { preview: true, requireCollection: options.securityOnly, onPage: page => collector?.publish('Cloudflare', url, endpoint.key, page.value, { complete: false, status: 'collecting', headIds: page.value.map(recordKey), continuation: previous.continuation }) });
    latest = getList(head);
    if (!latest.some(row => previous.headIds?.includes(recordKey(row)))) resumeQuery = head.collection?.nextQuery || null;
  }
  const result = head && !resumeQuery ? head : await fetchCloudflarePages(client, url, query, {
    requireCollection: options.securityOnly,
    resumeQuery,
    onPage: page => collector?.publish('Cloudflare', url, endpoint.key, page.value, { complete: false, status: 'collecting', ...(!head && page.pages === 1 ? { headIds: page.value.map(recordKey) } : {}), continuation: page.nextQuery, pages: page.pages, rateLimits: page.rateLimits, recordsRetrieved: page.recordsRetrieved })
  });
  if (latest.length) result.result = [...new Map([...getList(result), ...latest].map(row => [recordKey(row), row])).values()];
  collector?.publish('Cloudflare', url, endpoint.key, [], { ...result.collection, status: result.collection?.complete ? 'complete' : 'partial', continuation: result.collection?.nextQuery || null,
    ...(result.collection?.complete && options.range?.until && !options.range.explicit ? { completeThrough: options.range.until, ...(!incremental ? { lastReconciledAt: new Date().toISOString() } : {}) } : {}) });
  return result;
}

async function fetchCloudflareZoneEndpoint(client, endpoint, zones = []) {
  if (!zones.length) return { result: [] };
  const settled = await Promise.allSettled(zones.map(zone => fetchCloudflareEndpoint(client, endpoint, zone.id)));
  const fulfilled = settled.filter(result => result.status === 'fulfilled').map(result => result.value);
  if (fulfilled.length) return { result: fulfilled.flatMap(value => getList(value)) };
  throw settled.find(result => result.status === 'rejected')?.reason || new Error('Cloudflare zone endpoint failed');
}

function buildSectionStatuses(results) {
  return results.reduce((sections, item) => {
    sections[item.key] = {
      label: item.label,
      status: item.status,
      message: item.message || null,
      count: item.count ?? null
    };
    return sections;
  }, {});
}

function countEnabled(items) {
  return items.filter(item => item.enabled !== false).length;
}


function endpointDefinition(key) {
  return CLOUDFLARE_ENDPOINTS.find(endpoint => endpoint.key === key) || { key, label: key, familyKey: key };
}

function genericCloudflareRows(byKey, key) {
  return getList(byKey[key]?.data).map(maskSensitiveObject);
}

function buildCloudflareEndpointSummaries(raw) {
  const sectionResults = raw.map(item => {
    const endpoint = endpointDefinition(item.key);
    const family = FAMILY_BY_KEY[endpoint.familyKey] || {};
    return {
      key: item.key,
      familyKey: endpoint.familyKey || item.key,
      label: item.label || endpoint.label,
      permission: family.permission || endpoint.label || item.key,
      endpointFamily: family.endpointFamily || endpoint.label || item.key,
      dataAvailable: family.dataAvailable || 'Cloudflare records',
      module: family.module || 'Network Security',
      status: item.status,
      message: item.message,
      count: Array.isArray(getList(item.data)) ? getList(item.data).length : null
    };
  });

  const byFamily = new Map();
  CLOUDFLARE_PERMISSION_FAMILIES.forEach(family => {
    byFamily.set(family.key, { ...family, status: 'not_requested', endpointCount: 0, recordCount: 0, endpoints: [] });
  });

  sectionResults.forEach(section => {
    const group = byFamily.get(section.familyKey) || {
      id: null,
      key: section.familyKey,
      permission: section.permission,
      endpointFamily: section.endpointFamily,
      dataAvailable: section.dataAvailable,
      module: section.module,
      status: 'not_requested',
      endpointCount: 0,
      recordCount: 0,
      endpoints: []
    };
    group.endpointCount += 1;
    group.recordCount += Number(section.count || 0);
    group.endpoints.push(section);
    if (section.status === 'ok') group.status = 'available';
    else if (section.status === 'empty' && !['available'].includes(group.status)) group.status = 'empty';
    else if (section.status === 'permission_unavailable' && !['available', 'empty'].includes(group.status)) group.status = 'permission_unavailable';
    else if (section.status === 'error' && !['available', 'empty', 'permission_unavailable'].includes(group.status)) group.status = 'error';
    byFamily.set(section.familyKey, group);
  });

  const permissionMatrix = Array.from(byFamily.values()).sort((a, b) => Number(a.id || 999) - Number(b.id || 999));
  const endpointGroups = permissionMatrix.reduce((groups, family) => {
    const moduleName = family.module || 'Network Security';
    if (!groups[moduleName]) groups[moduleName] = [];
    groups[moduleName].push(family);
    return groups;
  }, {});

  return { sectionResults, permissionMatrix, endpointGroups };
}
function normalizeCloudflarePayload(raw) {
  const byKey = raw.reduce((acc, item) => {
    acc[item.key] = item;
    return acc;
  }, {});

  const apps = getList(byKey.apps?.data).map(sanitizeApp);
  const identityProviders = getList(byKey.identityProviders?.data).map(sanitizeIdentityProvider);
  const policies = getList(byKey.policies?.data).map(sanitizePolicy);
  const devices = getList(byKey.devices?.data).map(sanitizeDevice);
  const deviceRegistrations = getList(byKey.deviceRegistrations?.data).map(sanitizeRegistration);
  const devicePosture = getList(byKey.devicePosture?.data).map(item => ({
    id: item.id || null,
    name: item.name || item.type || 'Posture check',
    type: item.type || null,
    enabled: item.enabled !== false
  }));
  const gatewayRules = getList(byKey.gatewayRules?.data).map(sanitizeGatewayRule);
  const gatewayConfig = maskSensitiveObject(byKey.gatewayConfig?.data?.result || byKey.gatewayConfig?.data || {});
  const gatewayLists = getList(byKey.gatewayLists?.data).map(sanitizeGatewayList);
  const gatewayLogging = byKey.gatewayLogging?.status === 'ok'
    ? sanitizeGatewayLoggingSettings(byKey.gatewayLogging.data)
    : null;
  const deviceSettingsRow = byKey.deviceSettings?.status === 'ok'
    ? sanitizeDeviceSettings(byKey.deviceSettings.data)
    : null;
  const warpProfiles = getList(byKey.warpProfiles?.data).map(sanitizeWarpProfile);
  const gatewayAppTypes = getList(byKey.gatewayAppTypes?.data).map(item => ({
    id: item.id || item.name || null,
    name: item.name || item.type || 'App category'
  }));
  const virtualNetworks = getList(byKey.virtualNetworks?.data).map(network => ({
    id: network.id || null,
    name: network.name || 'Virtual network',
    isDefault: Boolean(network.is_default || network.default)
  }));
  const accessLogs = getList(byKey.accessLogs?.data)
    .map(sanitizeAccessLog)
    .sort((a, b) => getTimeValue(b.timestamp) - getTimeValue(a.timestamp));
  const dlpProfiles = getList(byKey.dlpProfiles?.data).map(sanitizeDlpProfile);
  const zones = getList(byKey.zones?.data).map(zone => ({ id: zone.id || null, name: zone.name || 'Zone' }));
  const auditLogs = genericCloudflareRows(byKey, 'auditLogs');
  const accountLogs = genericCloudflareRows(byKey, 'accountLogs');
  const securityInsights = genericCloudflareRows(byKey, 'securityInsights');
  const applicationSecurityReports = genericCloudflareRows(byKey, 'applicationSecurityReports');
  const apiGatewayOperations = genericCloudflareRows(byKey, 'apiGateway');
  const casbFindings = genericCloudflareRows(byKey, 'casbFindings');
  const tunnels = genericCloudflareRows(byKey, 'tunnels');
  const cloudforceRequests = genericCloudflareRows(byKey, 'cloudforceRequests');
  const intelFeeds = genericCloudflareRows(byKey, 'intelFeeds');
  const dnsFirewallRules = genericCloudflareRows(byKey, 'dnsFirewall');
  const loadBalancerPools = genericCloudflareRows(byKey, 'loadBalancerPools');
  const loadBalancerMonitors = genericCloudflareRows(byKey, 'loadBalancerMonitors');
  const magicWanSites = genericCloudflareRows(byKey, 'magicWanSites');
  const magicWanRoutes = genericCloudflareRows(byKey, 'magicWanRoutes');
  const mtlsCertificates = genericCloudflareRows(byKey, 'mtlsCertificates');
  const accessGroups = genericCloudflareRows(byKey, 'accessGroups');
  const accessOrganizations = genericCloudflareRows(byKey, 'accessOrganizations');
  const accessCertificates = genericCloudflareRows(byKey, 'accessCertificates');
  const warpConnectors = genericCloudflareRows(byKey, 'warpConnectors');
  const teamnetRoutes = genericCloudflareRows(byKey, 'teamnetRoutes');
  const teamsDexTests = genericCloudflareRows(byKey, 'teamsDexTests');
  const account = byKey.account?.status === 'ok' ? sanitizeAccount(byKey.account.data) : {};

  const activeGatewayPolicies = countEnabled(gatewayRules);
  const latestAccessEvent = accessLogs[0]?.timestamp || null;
  const identityProvider = identityProviders.find(provider => /azure/i.test(provider.name || provider.type || '')) || identityProviders[0] || null;
  const gatewayProxyEnabled = boolFromCloudflareSetting(gatewayConfig, ['gateway_proxy_enabled', 'settings.gateway_proxy.enabled', 'settings.gateway_proxy_enabled'])
    || boolFromCloudflareSetting(deviceSettingsRow, ['gatewayProxyEnabled']);
  const udpProxyEnabled = boolFromCloudflareSetting(gatewayConfig, ['gateway_udp_proxy_enabled', 'udp_proxy.enabled', 'settings.gateway_udp_proxy_enabled'])
    || boolFromCloudflareSetting(deviceSettingsRow, ['udpProxyEnabled']);
  const certificateEnabled = boolFromCloudflareSetting(gatewayConfig, ['root_certificate_installation_enabled', 'settings.root_certificate_installation_enabled', 'settings.certificate', 'certificate'])
    || boolFromCloudflareSetting(deviceSettingsRow, ['certificateEnabled']);
  const tlsDecryptEnabled = boolFromCloudflareSetting(gatewayConfig, ['tls_decrypt.enabled', 'settings.tls_decrypt.enabled']);

  const overview = {
    securityStatus: apps.length || devices.length || activeGatewayPolicies ? 'Active' : 'No data configured',
    protectedApps: apps.length,
    enrolledDevices: devices.length,
    registeredWarpDevices: deviceRegistrations.length,
    gatewayPolicies: gatewayRules.length,
    activeGatewayPolicies,
    identityProviders: identityProviders.length,
    identityProvider: identityProvider?.name || 'Not configured',
    recentAccessEvents: accessLogs.length,
    lastAccessEvent: latestAccessEvent,
    dlpProfiles: dlpProfiles.length,
    warpProfiles: warpProfiles.length,
    virtualNetworks: virtualNetworks.length,
    appCategories: gatewayAppTypes.length,
    gatewayProxyEnabled,
    udpProxyEnabled,
    certificateEnabled,
    tlsDecryptEnabled,
    zonesAvailable: zones.length,
    endpointFamilies: CLOUDFLARE_PERMISSION_FAMILIES.length,
    endpointFamiliesAvailable: 0,
    endpointFamiliesWithGaps: 0,
    auditLogs: auditLogs.length,
    accountLogs: accountLogs.length,
    securityInsights: securityInsights.length,
    applicationSecurityReports: applicationSecurityReports.length,
    apiGatewayOperations: apiGatewayOperations.length,
    casbFindings: casbFindings.length,
    tunnels: tunnels.length,
    cloudforceRequests: cloudforceRequests.length,
    intelFeeds: intelFeeds.length,
    dnsFirewallRules: dnsFirewallRules.length,
    loadBalancerPools: loadBalancerPools.length,
    loadBalancerMonitors: loadBalancerMonitors.length,
    magicWanSites: magicWanSites.length,
    magicWanRoutes: magicWanRoutes.length,
    mtlsCertificates: mtlsCertificates.length,
    accessGroups: accessGroups.length,
    accessOrganizations: accessOrganizations.length,
    accessCertificates: accessCertificates.length,
    warpConnectors: warpConnectors.length,
    teamnetRoutes: teamnetRoutes.length,
    teamsDexTests: teamsDexTests.length
  };

  const { sectionResults, permissionMatrix, endpointGroups } = buildCloudflareEndpointSummaries(raw);
  overview.endpointFamiliesAvailable = permissionMatrix.filter(item => ['available', 'empty'].includes(item.status)).length;
  overview.endpointFamiliesWithGaps = permissionMatrix.filter(item => ['permission_unavailable', 'error', 'not_requested'].includes(item.status)).length;

  return {
    success: true,
    fetchedAt: new Date().toISOString(),
    account,
    overview,
    apps,
    identityProviders,
    policies,
    devices,
    deviceRegistrations,
    devicePosture,
    gatewayRules,
    gatewayConfig,
    gatewayLists,
    gatewayLogging,
    deviceSettings: deviceSettingsRow,
    warpProfiles,
    accessLogs,
    virtualNetworks,
    gatewayAppTypes,
    dlpProfiles,
    zones,
    auditLogs,
    accountLogs,
    securityInsights,
    applicationSecurityReports,
    apiGatewayOperations,
    casbFindings,
    tunnels,
    cloudforceRequests,
    intelFeeds,
    dnsFirewallRules,
    loadBalancerPools,
    loadBalancerMonitors,
    magicWanSites,
    magicWanRoutes,
    mtlsCertificates,
    accessGroups,
    accessOrganizations,
    accessCertificates,
    warpConnectors,
    teamnetRoutes,
    teamsDexTests,
    permissionMatrix,
    endpointGroups,
    sections: buildSectionStatuses(sectionResults)
  };
}

async function resolveCloudflareSecret(secretName, getSecret) {
  if (typeof getSecret === 'function') {
    const value = await getSecret(secretName);
    if (value) return value;
  }
  return process.env[secretName] || null;
}

async function getCloudflareNetworkSecuritySummary(options = {}) {
  const accountId = options.accountId || await resolveCloudflareSecret('CLOUDFLARE_ACCOUNT_ID', options.getSecret);
  const apiToken = options.apiToken || await resolveCloudflareSecret('CLOUDFLARE_API_TOKEN', options.getSecret);

  if (!accountId || !apiToken) {
    const missing = [
      !accountId ? 'CLOUDFLARE_ACCOUNT_ID' : null,
      !apiToken ? 'CLOUDFLARE_API_TOKEN' : null
    ].filter(Boolean);

    const error = new Error(`Missing Cloudflare environment variable(s): ${missing.join(', ')}`);
    error.statusCode = 503;
    throw error;
  }

  const client = options.client || axios.create({
    baseURL: CLOUDFLARE_BASE_URL,
    timeout: 15000,
    headers: {
      Authorization: `Bearer ${apiToken}`,
      'Content-Type': 'application/json'
    }
  });

  const liveSecurityKeys = new Set(['accountLogs', 'auditLogs', 'securityInsights', 'casbFindings', 'accessLogs', 'notificationHistory', 'zones']);
  const accountEndpoints = CLOUDFLARE_ENDPOINTS.filter(endpoint => endpoint.scope !== 'zone' && (!options.securityOnly || liveSecurityKeys.has(endpoint.key)));
  const zoneEndpoints = options.securityOnly ? [] : CLOUDFLARE_ENDPOINTS.filter(endpoint => endpoint.scope === 'zone');
  const settled = await Promise.allSettled(
    accountEndpoints.map(endpoint => fetchCloudflareEndpoint(client, endpoint, accountId, options))
  );

  const raw = accountEndpoints.map((endpoint, index) => {
    const result = settled[index];
    if (result.status === 'fulfilled') {
      const count = getList(result.value).length;
      return {
        key: endpoint.key,
        label: endpoint.label,
        status: count === 0 && endpoint.key !== 'account' && endpoint.key !== 'gatewayConfig' ? 'empty' : 'ok',
        message: count === 0 && endpoint.key !== 'account' && endpoint.key !== 'gatewayConfig' ? 'No data configured' : null,
        httpStatus: endpoint.key === 'zones' ? (result.value?.collection?.httpStatus || 200) : null,
        code: null,
        zoneCount: endpoint.key === 'zones' ? count : null,
        graphQLAttempted: false,
        data: result.value
      };
    }

    const sectionError = summarizeSectionError(result.reason, endpoint);
    return {
      key: endpoint.key,
      label: endpoint.label,
      ...sectionError,
      zoneCount: endpoint.key === 'zones' ? 0 : null,
      graphQLAttempted: false,
      data: null
    };
  });

  const zonesResult = raw.find(item => item.key === 'zones' && item.status === 'ok')?.data;
  const zones = getList(zonesResult).map(zone => ({ id: zone.id, name: zone.name })).filter(zone => zone.id);
  const zoneSettled = await Promise.allSettled(
    zoneEndpoints.map(endpoint => fetchCloudflareZoneEndpoint(client, endpoint, zones))
  );
  zoneEndpoints.forEach((endpoint, index) => {
    const result = zoneSettled[index];
    if (!zones.length) {
      raw.push({ key: endpoint.key, label: endpoint.label, status: 'empty', message: 'No zones configured', data: { result: [] } });
      return;
    }
    if (result.status === 'fulfilled') {
      const count = getList(result.value).length;
      raw.push({
        key: endpoint.key,
        label: endpoint.label,
        status: count === 0 ? 'empty' : 'ok',
        message: count === 0 ? 'No data configured' : null,
        data: result.value
      });
      return;
    }
    raw.push({
      key: endpoint.key,
      label: endpoint.label,
      ...summarizeSectionError(result.reason, endpoint),
      data: null
    });
  });

  const summary = normalizeCloudflarePayload(raw);
  const securityKeys = new Set(['accountLogs', 'auditLogs', 'securityInsights', 'casbFindings', 'accessLogs', 'notificationHistory']);
  summary.rawSecurityRecords = raw.filter(item => securityKeys.has(item.key)).flatMap(item =>
    getList(item.data).map(payload => ({ payload, endpoint: endpointDefinition(item.key).path(accountId), recordType: item.key })));
  summary.retrieval = raw.filter(item => securityKeys.has(item.key) || item.key === 'zones').map(item => ({
    endpoint: endpointDefinition(item.key).path(accountId), status: item.status,
    ...item.data?.collection, httpStatus: item.httpStatus || item.data?.collection?.httpStatus || null,
    errorCode: item.code || null, zoneCount: item.zoneCount ?? (item.key === 'zones' ? getList(item.data).length : null),
    graphQLAttempted: item.graphQLAttempted || false,
    recordsRetrieved: getList(item.data).length, error: item.data?.collection?.error || (['error', 'unavailable', 'permission_unavailable'].includes(item.status) ? item.message : null)
  }));
  for (const item of raw) {
    if (securityKeys.has(item.key) && !item.data) options.collection?.publish('Cloudflare', endpointDefinition(item.key).path(accountId), item.key, [], { complete: false, status: item.status, error: item.message, failedRequests: 1, permissionErrors: item.status === 'permission_unavailable' ? 1 : 0 });
    if (item.data?.collection?.complete === false) summary.sections[item.key] = { ...summary.sections[item.key], status: 'error', message: item.data.collection.error };
  }
  if (options.securityOnly) {
    const since = options.range?.since || new Date(Date.now() - (Number(process.env.SECURITY_EVIDENCE_HISTORY_DAYS) || 15) * 86400000).toISOString();
    const until = options.range?.until || new Date().toISOString();
    const zoneDiscovery = raw.find(item => item.key === 'zones');
    await Promise.all(zones.map(async zone => {
      const endpoint = '/graphql/firewallEventsAdaptive/' + zone.id;
      const zoneRetrieval = summary.retrieval.find(item => item.endpoint === '/zones');
      if (zoneRetrieval) zoneRetrieval.graphQLAttempted = true;
      const previous = options.collection?.getState('Cloudflare', endpoint);
      const incremental = !options.range?.explicit && ['stored', 'memory_only'].includes(previous?.storageStatus) && previous.completeThrough && Date.now() - Date.parse(previous.lastReconciledAt || '') < 3600000;
      const firewallSince = incremental ? new Date(Math.max(Date.parse(since), Date.parse(previous.completeThrough) - 300000)).toISOString() : since;
      const result = await fetchFirewallEvents(client, { zoneId: zone.id, since: firewallSince, until, pending: previous?.continuation,
        onPage: page => options.collection?.publish('Cloudflare', endpoint, 'firewall_event', page.value, { complete: false, status: 'collecting', continuation: page.pending, pages: page.pages, rateLimits: page.rateLimits, recordsRetrieved: page.value.length }) });
      summary.rawSecurityRecords.push(...result.value.map(payload => ({ payload, endpoint, recordType: 'firewall_event' })));
      const state = { ...result, value: undefined, pending: undefined, endpoint, status: result.complete ? 'complete' : 'partial', graphQLAttempted: true, error: result.warnings.join('; ') || null, recordsRetrieved: result.value.length };
      summary.retrieval.push(state);
      options.collection?.publish('Cloudflare', endpoint, 'firewall_event', [], { ...state, continuation: result.pending.length ? result.pending : null,
        ...(result.complete && !options.range?.explicit ? { completeThrough: until, ...(!incremental ? { lastReconciledAt: new Date().toISOString() } : {}) } : {}) });
    }));
    if (!zones.length) summary.retrieval.push({
      endpoint: '/graphql/firewallEventsAdaptive',
      status: zoneDiscovery?.status || 'empty',
      complete: false,
      httpStatus: zoneDiscovery?.httpStatus || null,
      errorCode: zoneDiscovery?.code || null,
      zoneCount: zoneDiscovery?.zoneCount ?? 0,
      graphQLAttempted: false,
      recordsRetrieved: 0,
      error: zoneDiscovery?.status === 'empty'
        ? 'Zone discovery returned HTTP 200 with zero valid zones.'
        : (zoneDiscovery?.message || 'Zone discovery failed before GraphQL collection could be attempted.')
    });
  }
  return summary;
}

module.exports = {
  getCloudflareNetworkSecuritySummary
};
