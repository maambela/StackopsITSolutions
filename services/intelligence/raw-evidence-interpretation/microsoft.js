const { scalar, first, readable, section, list, location, base } = require('./common');

function signIn(record) {
    const r = record.rawPayload, p = base(record, 'Microsoft Entra ID', 'Sign-ins', 'Identity & Authentication', 'graph.signin.v1');
    const code = r.status?.errorCode, hasCode = typeof code === 'number' || (typeof code === 'string' && /^\d+$/.test(code));
    const interrupted = [50058, 50072, 50074, 50076, 50079, 50125, 50140].includes(Number(code));
    p.outcome = !hasCode ? 'Outcome not provided' : Number(code) === 0 ? 'Successful' : Number(code) === 53003 ? 'Blocked' : interrupted ? 'Interrupted' : 'Failed';
    p.actor = first(r.userDisplayName, r.userPrincipalName, r.servicePrincipalName);
    p.asset = first(r.appDisplayName, r.resourceDisplayName);
    p.action = 'Sign-in';
    p.title = `${hasCode ? p.outcome + ' ' : ''}${p.asset || 'Microsoft'} sign-in${hasCode ? '' : ' (outcome not provided)'}`;
    const place = location(r.location), reason = first(r.status?.failureReason), details = first(r.status?.additionalDetails);
    p.description = `${p.actor || 'The recorded identity'} ${p.outcome === 'Successful' ? 'signed in' : 'attempted to sign in'}${p.asset ? ' to ' + p.asset : ''}${place ? ' from ' + place : ''}.`;
    if (p.outcome !== 'Successful' && reason) p.description += ' ' + reason;
    if (details) p.description += ' ' + (/^MFA requirement satisfied by claim in the token\.?$/i.test(details) ? 'Multifactor authentication requirements were satisfied through an existing token claim.' : details);
    const risk = ['low', 'medium', 'high'].includes(r.riskLevelDuringSignIn) || ['atRisk', 'confirmedCompromised'].includes(r.riskState);
    p.activityClass = risk || ['Blocked', 'Failed'].includes(p.outcome) ? 'security' : 'informational';
    p.securitySignificance = risk ? `Microsoft supplied a risk signal (${first(r.riskState, r.riskLevelDuringSignIn)}). Review the provider risk evidence; this interpretation does not establish an attack.`
        : p.outcome === 'Successful' ? 'Microsoft recorded a successful sign-in. Success alone does not establish that the access was authorised or safe.'
        : p.outcome === 'Interrupted' ? 'Authentication was interrupted or required another step. This record alone does not establish an attack.'
        : 'The authentication outcome alone does not establish an attack. Review the supplied reason and authentication context.';
    p.sections = [section('Identity and application', [['User', p.actor], ['Account', r.userPrincipalName], ['Application', p.asset], ['Resource', r.resourceDisplayName], ['Interactive', r.isInteractive]]),
        section('Authentication', [['Result', p.outcome], ['Provider reason', reason], ['Additional details', details], ['Requirement', readable(r.authenticationRequirement)], ['Conditional Access', readable(r.conditionalAccessStatus)],
            ['Authentication steps', list((r.authenticationDetails || []).map(step => [step.authenticationMethod, step.authenticationStepResultDetail, typeof step.succeeded === 'boolean' ? (step.succeeded ? 'succeeded' : 'did not succeed') : ''].filter(Boolean).join(': ')))]]),
        section('Origin and device', [['IP address', r.ipAddress], ['Location', place], ['Device', r.deviceDetail?.displayName], ['Operating system', r.deviceDetail?.operatingSystem], ['Browser', r.deviceDetail?.browser], ['Managed device', r.deviceDetail?.isManaged], ['Compliant device', r.deviceDetail?.isCompliant]]),
        section('Provider risk context', [['Risk during sign-in', r.riskLevelDuringSignIn], ['Risk state', r.riskState], ['Risk detail', r.riskDetail], ['Risk events', list(r.riskEventTypes_v2)]])];
    return p;
}
function directoryAudit(record) {
    const r = record.rawPayload, p = base(record, 'Microsoft Entra ID', 'Directory audit', 'Administrative Activity', 'graph.directory-audit.v1');
    p.action = first(r.activityDisplayName, r.operationType);
    p.actor = first(r.initiatedBy?.user?.displayName, r.initiatedBy?.user?.userPrincipalName, r.initiatedBy?.app?.displayName);
    p.asset = list((r.targetResources || []).map(target => first(target.displayName, target.userPrincipalName)));
    p.outcome = first(r.result) || 'Outcome not provided';
    p.title = p.action || 'Unclassified directory activity';
    p.description = `${p.actor || 'The recorded actor'}${p.action ? ' performed "' + p.action + '"' : ' generated a directory audit record'}${p.asset ? ' involving ' + p.asset : ''}. ${r.result ? 'Microsoft reported: ' + r.result + '.' : 'The outcome was not supplied.'}`;
    p.activityClass = r.result === 'failure' ? 'security' : 'administrative';
    p.securitySignificance = 'A directory audit record describes an operation, not its authorisation. Review the affected resources and changed properties against the approved change.';
    p.sections = [section('Actor and operation', [['Actor', p.actor], ['Account', r.initiatedBy?.user?.userPrincipalName], ['Action', p.action], ['Service', r.loggedByService], ['Result', p.outcome], ['Result reason', r.resultReason], ['IP address', r.initiatedBy?.user?.ipAddress]]),
        section('Affected resources', [['Resources', p.asset], ['Resource types', list((r.targetResources || []).map(target => target.type))], ['Changed properties', list((r.targetResources || []).flatMap(target => (target.modifiedProperties || []).map(property => property.displayName)))]] )];
    return p;
}
function security(record) {
    const r = record.rawPayload, incident = record.recordType === 'incident';
    const p = base(record, 'Microsoft Security', incident ? 'Provider incidents' : 'Security alerts', null, 'graph.security.v1');
    p.title = first(r.title, r.displayName) || `${first(r.serviceSource, r.productName) || 'Microsoft Security'} ${incident ? 'incident' : 'alert'}`;
    p.description = first(r.description) || `Microsoft Security returned a ${incident ? 'provider incident' : 'security alert'}${r.serviceSource ? ' from ' + r.serviceSource : ''}${r.status ? ' with status ' + readable(r.status) : ''}.`;
    p.actor = first(r.evidence?.find(item => item.userAccount)?.userAccount?.userPrincipalName, r.userStates?.[0]?.userPrincipalName);
    p.asset = first(r.evidence?.find(item => item.deviceDnsName)?.deviceDnsName, r.productName);
    p.outcome = first(r.status) || 'Status not provided'; p.action = incident ? 'Provider incident reported' : 'Provider security alert reported'; p.activityClass = 'security';
    p.securitySignificance = `This is a provider-issued ${incident ? 'incident' : 'security alert'}. Its classification and determination are provider evidence; this presentation adds no conclusion about compromise.`;
    p.sections = [section('Provider detection', [['Title', r.title], ['Description', r.description], ['Product', r.productName], ['Service', r.serviceSource], ['Status', r.status], ['Classification', r.classification], ['Determination', r.determination], ['Detection source', r.detectionSource]]),
        section('Affected entities', [['User', p.actor], ['Asset', p.asset], ['Evidence types', list((r.evidence || []).map(item => scalar(item['@odata.type']).replace('#microsoft.graph.security.', '')))]] )];
    return p;
}
function identityRisk(record) {
    const r = record.rawPayload, detection = record.recordType === 'riskDetection';
    const p = base(record, 'Microsoft Entra ID', detection ? 'Risk detections' : 'Risky users', 'Identity & Authentication', 'graph.identity-risk.v1');
    p.actor = first(r.userDisplayName, r.displayName, r.userPrincipalName);
    p.title = detection ? `Microsoft identity risk: ${readable(first(r.riskEventType)) || 'provider detection'}` : `Microsoft user risk${p.actor ? ': ' + p.actor : ''}`;
    p.description = `${p.actor || 'The recorded identity'} has a Microsoft identity-risk record${r.riskState ? ' with state ' + readable(r.riskState) : ''}${r.riskLevel ? ' and provider risk level ' + r.riskLevel : ''}.`;
    p.outcome = first(r.riskState); p.action = detection ? 'Risk detection reported' : 'User risk reported'; p.activityClass = 'security';
    p.securitySignificance = 'Provider risk level is shown separately from severity. A risk signal requires investigation and is not an independent finding of compromise.';
    p.sections = [section('Identity risk', [['User', p.actor], ['Account', r.userPrincipalName], ['Risk event', readable(r.riskEventType)], ['Risk state', r.riskState], ['Risk level', r.riskLevel], ['Risk detail', r.riskDetail], ['Detection timing', r.detectionTimingType]]), section('Origin', [['IP address', r.ipAddress], ['Location', location(r.location)]])];
    return p;
}
function indicator(record) {
    const r = record.rawPayload, p = base(record, 'Microsoft Security', 'Threat indicators', null, 'graph.indicator.v1');
    p.asset = first(r.networkIPv4, r.networkIPv6, r.domainName, r.url, r.fileHashValue);
    p.title = `${readable(first(r.threatType)) || 'Provider threat'} indicator${p.asset ? ': ' + p.asset : ''}`;
    p.description = first(r.description) || 'Microsoft returned a threat-intelligence indicator. This does not show that the indicator was encountered in this environment.';
    p.activityClass = 'security'; p.action = 'Indicator published';
    p.securitySignificance = 'An indicator is intelligence context, not proof of activity or compromise.';
    p.sections = [section('Indicator', [['Value', p.asset], ['Threat type', r.threatType], ['Action', r.action], ['Confidence', r.confidence], ['Valid until', r.expirationDateTime], ['Target product', r.targetProduct]])];
    return p;
}
function interpretMicrosoft(record) {
    if (record.recordType === 'signin') return signIn(record);
    if (record.recordType === 'directoryAudit' || /\/directoryAudits$/.test(record.endpoint)) return directoryAudit(record);
    if (['alert', 'incident'].includes(record.recordType)) return security(record);
    if (['riskDetection', 'riskyUser'].includes(record.recordType)) return identityRisk(record);
    if (record.recordType === 'indicator') return indicator(record);
    return null;
}
module.exports = { interpretMicrosoft };
