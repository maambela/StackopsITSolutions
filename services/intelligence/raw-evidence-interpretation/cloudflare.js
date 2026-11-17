const { first, meaningful, readable, section, list, base } = require('./common');

function audit(record, { platformTokenIds = [] } = {}) {
    const r = record.rawPayload, p = base(record, 'Cloudflare', 'Account Audit', 'Administrative Activity', 'cloudflare.audit.v1');
    const action = typeof r.action === 'object' ? r.action : { type: r.action };
    const result = first(action.result, r.result), method = first(r.raw?.method).toUpperCase();
    const httpStatus = Number(r.raw?.status_code), uri = first(r.raw?.uri);
    const succeeded = result === 'success' || action.result === true;
    p.outcome = succeeded ? 'Successful' : result === 'failure' || action.result === false ? 'Failed' : result || (httpStatus ? 'HTTP ' + httpStatus : 'Outcome not provided');
    p.action = first(action.description, action.type);
    p.actor = first(r.actor?.email, r.actor?.token?.name, r.actor?.name);
    p.asset = first(r.resource?.display_name, r.resource?.name, r.resource?.type, r.resource?.product, r.account?.name);
    const auditRead = (method === 'GET' && /^\/(?:client\/v4\/)?accounts\/[^/]+\/(logs\/audit|audit_logs)(?:\?|$)/.test(uri)) || ['Get account audit logs (Version 2)', 'Get account audit logs'].includes(action.description);
    p.title = auditRead ? 'Cloudflare account audit logs accessed' : p.action || 'Unclassified Cloudflare account activity';
    p.description = `${p.actor || 'The recorded actor'}${p.action ? ' performed "' + p.action + '"' : ' generated an account audit record'}${p.asset ? ' involving ' + p.asset : ''}. ${result || action.result === true || action.result === false ? 'Cloudflare reported: ' + p.outcome.toLowerCase() + '.' : 'The operation outcome was not supplied.'}`;
    // A token name is not proof of ownership, scope or read-only permissions.
    const knownToken = Boolean(r.actor?.token?.id && platformTokenIds.includes(String(r.actor.token.id)));
    const auditedEndpoint = /^\/(?:client\/v4\/)?accounts\/[^/]+\/(logs\/audit|audit_logs)(?:\?|$)/.test(uri);
    p.routine = knownToken && auditedEndpoint && method === 'GET' && succeeded && httpStatus >= 200 && httpStatus < 300 && !record.severity;
    p.activityClass = p.routine ? 'platform' : p.outcome === 'Failed' || httpStatus >= 400 ? 'security' : 'administrative';
    p.securitySignificance = p.routine ? 'A configured StackCTRL token successfully read account audit logs. This matches platform polling; the full record remains retained.'
        : 'This audit record describes an administrative API operation. A successful request does not prove it was authorised. Token permissions cannot be inferred from its name.';
    p.sections = [section('Actor and action', [['Actor', p.actor], ['Actor type', r.actor?.type], ['API token', r.actor?.token?.name], ['Action', p.action], ['Result', p.outcome]]),
        section('Resource and origin', [['Account', r.account?.name], ['Resource', p.asset], ['IP address', r.actor?.ip_address], ['Interface', r.actor?.context], ['HTTP result', httpStatus || null]])];
    return p;
}
const ACTIONS = { block: 'Blocked', drop: 'Dropped', allow: 'Allowed', skip: 'Skipped', log: 'Logged', challenge: 'Challenged', jschallenge: 'JavaScript challenge issued', managed_challenge: 'Managed challenge issued', managedChallenge: 'Managed challenge issued', bypass: 'Bypassed' };
function firewall(record) {
    const r = record.rawPayload, source = first(r.source, r.Source), action = first(r.action, r.Action);
    const waf = ['waf', 'firewallrules', 'firewallRules', 'firewallmanaged', 'firewallManaged'].includes(source);
    const ddos = ['l7ddos', 'l4ddos', 'ddos'].includes(source);
    const p = base(record, waf ? 'Cloudflare WAF' : 'Cloudflare Firewall', waf ? 'WAF Security' : 'Firewall events', 'Firewall & WAF', 'cloudflare.firewall.v1');
    p.action = action; p.outcome = ACTIONS[action] || action || 'Action not provided';
    p.actor = first(r.clientIP, r.ClientIP, r.SourceIP);
    p.asset = [first(r.clientRequestHTTPHost, r.ClientRequestHost, r.HTTPHost, r.ZoneName), first(r.clientRequestPath, r.ClientRequestPath, r.ClientRequestURI)].filter(Boolean).join('');
    p.title = `${p.outcome === 'Action not provided' ? 'Recorded' : p.outcome} ${ddos ? 'Cloudflare DDoS security' : waf ? 'WAF' : 'firewall'} request`;
    p.description = `Cloudflare recorded${action ? ' action "' + action + '"' : ' a firewall event'}${p.actor ? ' for a request from ' + p.actor : ''}${p.asset ? ' to ' + p.asset : ''}${source ? ' through ' + source : ''}.`;
    p.activityClass = 'security';
    p.securitySignificance = ddos ? 'Cloudflare identified the event source as DDoS protection. The record describes the provider action, not the impact or success of an attack.'
        : 'The action describes how Cloudflare handled this request. A block or challenge does not by itself establish compromise; an allowed request is not automatically safe.';
    p.sections = [section('Request and protection', [['Resource', p.asset], ['Action', p.outcome], ['Protection source', source], ['Rule', first(r.description, r.RuleMessage)], ['Request method', first(r.clientRequestHTTPMethod, r.ClientRequestMethod)]]),
        section('Origin', [['IP address', p.actor], ['Country', first(r.clientCountryName, r.ClientCountry)], ['Zone', first(r.ZoneName, r.zoneName)]])];
    return p;
}
function access(record) {
    const r = record.rawPayload, p = base(record, 'Cloudflare Access', 'Access authentication', 'Identity & Authentication', 'cloudflare.access.v1');
    const allowed = r.allowed ?? r.Allowed;
    p.outcome = allowed === true || allowed === 'true' ? 'Allowed' : allowed === false || allowed === 'false' ? 'Denied' : first(r.action, r.Action) || 'Outcome not provided';
    p.actor = first(r.user_email, r.email, r.Email, r.UserEmail); p.asset = first(r.app_domain, r.AppDomain, r.app_name);
    p.action = 'Access authentication'; p.title = `${p.outcome === 'Outcome not provided' ? 'Recorded' : p.outcome} Cloudflare Access request${p.asset ? ' to ' + p.asset : ''}`;
    p.description = `Cloudflare Access recorded ${p.actor ? 'a request by ' + p.actor : 'an authentication request'}${p.asset ? ' for ' + p.asset : ''}. ${p.outcome}.`;
    p.activityClass = p.outcome === 'Allowed' ? 'informational' : 'security';
    p.securitySignificance = 'Access reports the authentication or policy result. It does not establish whether a denied request was an attack or an allowed request was legitimate.';
    p.sections = [section('Access request', [['User', p.actor], ['Application', p.asset], ['Result', p.outcome], ['Identity provider', r.idp], ['Non-identity request', r.non_identity]]),
        section('Origin', [['IP address', first(r.ip_address, r.ip, r.IPAddress, r.ClientIP)], ['Country', first(r.country, r.country_code, r.Country)]])];
    return p;
}
function notification(record) {
    const r = record.rawPayload, data = r.data || {}, p = base(record, 'Cloudflare', 'Provider notifications', null, 'cloudflare.notification.v1');
    p.title = first(data.title, data.name, r.name, r.title, r.alert_type) || 'Cloudflare provider notification';
    p.description = first(data.description, data.message, r.text, r.alert_body) || `Cloudflare issued a notification${r.alert_type ? ' of type ' + r.alert_type : ''}.`;
    p.asset = first(data.zone_name, data.hostname, data.app_domain); p.actor = first(data.user_email, data.client_ip);
    p.action = first(r.alert_type, data.alert_type); p.outcome = first(r.alert_event, data.alert_event, r.status);
    p.activityClass = 'security';
    p.securitySignificance = 'This is a Cloudflare provider notification. Interpret its supplied type and message; this layer does not infer an attack or assign severity.';
    p.sections = [section('Notification', [['Message', p.description], ['Type', p.action], ['State', p.outcome], ['Resource', p.asset], ['IP address', data.client_ip], ['Policy', r.policy_name]])];
    return p;
}
function finding(record) {
    const r = record.rawPayload, p = base(record, 'Cloudflare', record.recordType === 'casbFindings' ? 'CASB findings' : 'Security Center insights', 'Cloud Security', 'cloudflare.finding.v1');
    p.title = first(r.title, r.name, r.description, r.issue_type) || 'Cloudflare security finding';
    p.description = first(r.description, r.message) || `Cloudflare returned a ${first(r.issue_type, r.type) || 'security'} finding${r.status ? ' with status ' + r.status : ''}.`;
    p.asset = first(r.resource?.name, r.domain, r.hostname); p.outcome = first(r.status); p.activityClass = 'security'; p.action = 'Provider finding reported';
    p.securitySignificance = 'A provider finding describes the reported issue. It does not independently establish exploitation or a breach.';
    p.sections = [section('Provider finding', [['Issue', first(r.issue_type, r.type)], ['Description', p.description], ['Resource', p.asset], ['State', p.outcome], ['Recommended action', r.recommendation]])];
    return p;
}
function traffic(record) {
    const r = record.rawPayload, gateway = record.recordType.startsWith('gateway_');
    const p = base(record, gateway ? 'Cloudflare Gateway' : 'Cloudflare Network', readable(record.recordType), 'Network Security', 'cloudflare.traffic.v1');
    const actions = Array.isArray(r.SecurityActions) ? r.SecurityActions : [];
    const action = first(r.Action, r.action, r.SecurityAction, actions[0]); p.outcome = ACTIONS[action] || action;
    p.action = action; p.actor = first(r.Email, r.UserEmail, r.ClientIP, r.SourceIP);
    p.asset = first(r.URL, r.QueryName, r.ClientRequestHost, r.DestinationIP);
    p.title = `${p.outcome || 'Recorded'} ${gateway ? 'Gateway' : 'network'} activity${p.asset ? ': ' + p.asset : ''}`;
    p.description = `Cloudflare recorded ${readable(record.recordType)} activity${p.actor ? ' from ' + p.actor : ''}${p.asset ? ' involving ' + p.asset : ''}${action ? ' with action ' + action : ''}.`;
    p.activityClass = [action, ...actions].some(value => ['block', 'drop', 'challenge', 'managed_challenge', 'jschallenge'].includes(value)) ? 'security' : 'informational';
    p.securitySignificance = 'Traffic telemetry describes the observed request and supplied policy action. Traffic alone does not establish an attack or data exfiltration.';
    p.sections = [section(gateway ? 'Gateway request' : 'Network activity', [['User or source', p.actor], ['Resource', p.asset], ['Action', p.outcome], ['Security actions', list(r.SecurityActions)], ['Security sources', list(r.SecuritySources)], ['Policy', r.PolicyName], ['Rule', r.RuleName], ['Protocol', r.Protocol], ['Destination', r.DestinationIP], ['Provider categories', list(r.Categories || r.SecurityCategories)]])];
    return p;
}
function interpretCloudflare(record, options) {
    if (['accountLogs', 'auditLogs', 'audit_logs'].includes(record.recordType)) return audit(record, options);
    if (['accessLogs', 'access_requests'].includes(record.recordType)) return access(record);
    if (['firewall_event', 'firewall_events'].includes(record.recordType)) return firewall(record);
    if (['notificationHistory', 'alert'].includes(record.recordType) || record.endpoint.includes('/webhooks/')) return notification(record);
    if (['securityInsights', 'casbFindings'].includes(record.recordType)) return finding(record);
    if (['gateway_dns', 'gateway_http', 'http_requests', 'network_analytics_logs'].includes(record.recordType)) return traffic(record);
    return null;
}
module.exports = { interpretCloudflare };
