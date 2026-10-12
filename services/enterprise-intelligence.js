const { DateTime } = require('luxon');
const { buildDashboardIntelligenceContext } = require('./intelligence/dashboard-context');

const ENTERPRISE_DOMAINS = Object.freeze([
    { key: 'identity', name: 'Identity Protection', sourceKey: 'identity', mode: 'enterprise_domain_identity', riskKey: 'identity', healthKey: 'identityHealth', focus: ['MFA coverage', 'users without MFA', 'privileged accounts', 'admin roles', 'legacy authentication', 'risky sign-ins', 'external users', 'Conditional Access gaps'] },
    { key: 'devices', name: 'Device Protection', sourceKey: 'devices', mode: 'enterprise_domain_devices', riskKey: 'devices', healthKey: 'deviceHealth', focus: ['compliance rate', 'stale devices', 'non-compliant devices', 'unmanaged indicators', 'endpoint security risk', 'remediation actions'] },
    { key: 'email_security', name: 'Email Security', sourceKey: 'email_security', mode: 'enterprise_domain_email_security', riskKey: 'email', healthKey: 'emailHealth', focus: ['active threats', 'unresolved threats', 'phishing and malware indicators', 'response posture', 'resolution rate', 'user exposure'] },
    { key: 'cloudflare_network_security', name: 'Network Security / Cloudflare', sourceKey: 'cloudflare_network_security', mode: 'enterprise_domain_cloudflare_network_security', riskKey: 'network', healthKey: null, focus: ['network posture', 'WAF and firewall controls', 'DNS posture', 'SSL/TLS posture', 'bot protection', 'rate limiting', 'security events', 'unknown controls'] },
    { key: 'security_alerts', name: 'Security Alerts', sourceKey: 'security_alerts', mode: 'enterprise_domain_security_alerts', riskKey: 'security', healthKey: 'securityHealth', focus: ['alert severity', 'high-severity alerts', 'anonymous IP sign-ins', 'active incidents', 'incident response posture', 'containment actions'] },
    { key: 'applications', name: 'Applications', sourceKey: 'applications', mode: 'enterprise_domain_applications', riskKey: 'applications', healthKey: 'applicationsHealth', focus: ['external publishers', 'broad permissions', 'high-risk applications', 'shadow IT', 'consent risk', 'application governance'] },
    { key: 'backup', name: 'Backup and Recovery', sourceKey: 'backup', mode: 'enterprise_domain_backup', riskKey: 'backup', healthKey: 'backupHealth', focus: ['backup coverage', 'third-party backup', 'immutable storage', 'restore testing', 'ransomware recovery readiness', 'business continuity'] },
    { key: 'governance', name: 'Governance', sourceKey: 'governance', mode: 'enterprise_domain_governance', riskKey: 'governance', healthKey: 'governanceHealth', focus: ['access reviews', 'admin reviews', 'policy reviews', 'governance maturity', 'manual review needs', 'evidence gaps'] },
    { key: 'operations', name: 'Operations', sourceKey: 'operations', mode: 'enterprise_domain_operations', riskKey: 'operations', healthKey: 'operationsHealth', focus: ['data freshness', 'stale operational evidence', 'failed tasks', 'service health', 'operational risk', 'process gaps'] },
    { key: 'compliance', name: 'Compliance Validation', sourceKey: 'compliance', mode: 'enterprise_domain_compliance', riskKey: 'compliance', healthKey: 'complianceHealth', focus: ['control status', 'failed controls', 'partial controls', 'manual-review controls', 'compliance readiness', 'evidence gaps'] }
]);

const DOMAIN_BY_KEY = Object.freeze(Object.fromEntries(ENTERPRISE_DOMAINS.map(domain => [domain.key, domain])));
const TEMPORARILY_DISABLED_DOMAIN_KEYS = Object.freeze(['operations']);
const TEMPORARILY_DISABLED_DOMAIN_SET = Object.freeze(new Set(TEMPORARILY_DISABLED_DOMAIN_KEYS));
const ACTIVE_ENTERPRISE_DOMAIN_KEYS = Object.freeze(ENTERPRISE_DOMAINS.map(domain => domain.key).filter(key => !TEMPORARILY_DISABLED_DOMAIN_SET.has(key)));
const ACTIVE_ENTERPRISE_DOMAIN_SET = Object.freeze(new Set(ACTIVE_ENTERPRISE_DOMAIN_KEYS));
const CURRENT_REPORTING_PHASE = Object.freeze({
    key: 'selected_domain_intelligence_phase',
    status: 'domain_intelligence_active',
    activeDomainCount: ACTIVE_ENTERPRISE_DOMAIN_KEYS.length,
    totalDomainCount: ENTERPRISE_DOMAINS.length,
    message: 'Current reporting phase runs final enterprise synthesis across validated active domains. Operations remains temporarily disabled and is reported as a known limitation.'
});
const TEMPORARILY_DISABLED_DOMAIN_MESSAGE = 'This domain is temporarily disabled and will be enabled in a later reporting phase.';
const TEMPORARILY_DISABLED_DOMAIN_STATUS_MESSAGE = 'Temporarily disabled — will be enabled in a later reporting phase.';

function isTemporarilyDisabledDomain(domainKey) {
    return TEMPORARILY_DISABLED_DOMAIN_SET.has(String(domainKey || ''));
}

function disabledDomainState(domainKey) {
    const domain = DOMAIN_BY_KEY[domainKey] || { key: domainKey, name: domainKey, mode: null };
    return {
        domainKey: domain.key,
        key: domain.key,
        domainName: domain.name,
        name: domain.name,
        mode: domain.mode || null,
        status: 'temporarily_disabled',
        selectable: false,
        includedInCurrentPhase: false,
        message: TEMPORARILY_DISABLED_DOMAIN_MESSAGE
    };
}

function enterpriseDomainDescriptor(domain) {
    const disabled = isTemporarilyDisabledDomain(domain.key);
    return {
        key: domain.key,
        domainKey: domain.key,
        name: domain.name,
        domainName: domain.name,
        mode: domain.mode,
        selectable: !disabled,
        includedInCurrentPhase: !disabled,
        status: disabled ? 'temporarily_disabled' : 'available',
        message: disabled ? TEMPORARILY_DISABLED_DOMAIN_STATUS_MESSAGE : null
    };
}

function disabledDomainStates(keys = TEMPORARILY_DISABLED_DOMAIN_KEYS) {
    return [...new Set((Array.isArray(keys) ? keys : []).filter(isTemporarilyDisabledDomain))].map(disabledDomainState);
}

const LOWER_PERIOD = Object.freeze({ weekly: 'daily', monthly: 'weekly', yearly: 'monthly' });
const DEFAULT_DOMAIN_DELAY_MS = 60000;
const LARGE_DOMAIN_INPUT_TOKEN_THRESHOLD = 50000;
const SECURITY_ALERTS_DOMAIN_DELAY_MS = 90000;
const ENTITY_EVIDENCE_LIMITS = Object.freeze({ maxDepth: 8, maxArray: 50, maxString: 1200, maxObjectKeys: 100 });
const DEFAULT_MAX_INPUT_BYTES = 150000;
const DEFAULT_MAX_ITEMS_PER_BATCH = 100;
const IDENTITY_MAX_ITEMS_PER_BATCH = 500;
const DEVICE_MAX_ITEMS_PER_BATCH = 500;
const EMAIL_SECURITY_MAX_ITEMS_PER_BATCH = 500;
const SELECTED_DOMAIN_MAX_ITEMS_PER_BATCH = 500;
const CLOUDFLARE_MAX_ITEMS_PER_BATCH = 100;
const DEFAULT_HEAVY_DOMAIN_MAX_ITEMS_PER_BATCH = 50;
const DEFAULT_THRESHOLD_BATCH_MAX_ITEMS = 50;
const DEFAULT_MAX_TOTAL_TOKENS = 200000;
const DEFAULT_DOMAIN_OUTPUT_TOKENS = 12000;
const DEFAULT_SYNTHESIS_OUTPUT_TOKENS = 12000;
// Keep interactive report requests bounded. A rate limit is recorded for retry instead of
// leaving the browser connected through a 5/5/10-minute retry sequence.
const ENTERPRISE_RATE_LIMIT_RETRY_DELAYS_MS = Object.freeze([15000]);
const ENTERPRISE_CONNECTION_RETRY_DELAYS_MS = Object.freeze([0, 15000, 45000]);
const ENTERPRISE_RATE_LIMIT_RETRY_MAX_MS = 90 * 1000;
const EMAIL_SECURITY_RATE_LIMIT_RETRY_DELAYS_MS = Object.freeze([]);
const EMAIL_SECURITY_RATE_LIMIT_RETRY_MAX_MS = 0;
const STRICT_COMPACT_SELECTED_DOMAIN_KEYS = Object.freeze(new Set([
    'email_security',
    'cloudflare_network_security',
    'backup',
    'applications',
    'governance',
    'compliance'
]));

const COMPACT_SELECTED_DOMAIN_KEYS = Object.freeze(new Set([
    'identity',
    'security_alerts',
    ...STRICT_COMPACT_SELECTED_DOMAIN_KEYS
]));

const HEAVY_DOMAINS = Object.freeze(new Set(['governance', 'operations', 'compliance']));
const SUCCESSFUL_DOMAIN_STATUSES = Object.freeze(new Set(['completed', 'partial', 'completed_with_warnings']));
const SKIPPED_DOMAIN_STATUSES = Object.freeze(new Set(['skipped_rate_limited', 'skipped_token_threshold', 'skipped_pipeline_stop']));
const DOMAIN_SYSTEM_MESSAGE = 'You are StackCTRL Enterprise Intelligence. Return valid compact JSON only. No markdown. No code fences. No explanations outside JSON. Prefer short strings and omit optional narrative fields when evidence is already clear.';
const IDENTITY_LINEAGE_FIELDS = Object.freeze([
    'totalUsers', 'mfaEnabled', 'mfaMissing', 'mfaCoverage', 'privilegedUsers',
    'adminsWithoutMfa', 'highRiskUsers', 'signInIssues', 'externalUsers',
    'unknownDevices', 'multiplePrivilegedRoles', 'securityScore', 'healthScore',
    'riskScore', 'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'
]);
const DEVICE_LINEAGE_FIELDS = Object.freeze([
    'totalDevices', 'compliantDevices', 'nonCompliantDevices', 'complianceRate',
    'encryptedDevices', 'encryptionRate', 'activeDevices24h', 'staleDevices', 'dead30Days',
    'highRiskDevices', 'unmanagedDevices', 'securityAlerts', 'deviceSecurityScore',
    'healthScore', 'riskScore', 'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'
]);
const EMAIL_LINEAGE_FIELDS = Object.freeze([
    'activeThreats', 'highSeverityAlerts', 'affectedUsersCount', 'activeIncidents',
    'securityScore', 'threatResolutionRate', 'phishingCount', 'malwareCount', 'spamCount', 'becCount',
    'activeMailboxes', 'totalMailActivity', 'sendCount', 'receiveCount', 'readCount', 'recommendationsCount',
    'healthScore', 'riskScore', 'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'
]);
const NETWORK_LINEAGE_FIELDS = Object.freeze([
    'protectedApps', 'enrolledDevices', 'gatewayPolicies', 'activeGatewayPolicies', 'deniedAccessEvents',
    'recentAccessEvents', 'networkSecurityScore', 'dlpProfiles', 'identityProviders', 'sectionErrors',
    'healthScore', 'riskScore', 'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'
]);
const DASHBOARD_BACKED_ENTERPRISE_DOMAINS = Object.freeze(['identity', 'devices', 'email_security', 'cloudflare_network_security', 'backup', 'applications', 'security_alerts', 'governance', 'compliance', 'operations']);
const DOMAIN_EVIDENCE_TYPES = Object.freeze({
    identity: ['users', 'dashboard_evidence_lists'],
    devices: ['devices', 'dashboard_evidence_lists'],
    email_security: ['alerts', 'incidents', 'mailActivityUsers', 'dashboard_evidence_lists'],
    cloudflare_network_security: [
        'accessApps', 'applications', 'devices', 'deviceRegistrations', 'devicePosture', 'gatewayRules', 'accessPolicies',
        'accessLogs', 'dlpProfiles', 'warpProfiles', 'virtualNetworks', 'gatewayAppTypes', 'permissionMatrix',
        'auditLogs', 'accountLogs', 'securityInsights', 'applicationSecurityReports',
        'apiGatewayOperations', 'casbFindings', 'tunnels', 'cloudforceRequests', 'intelFeeds',
        'dnsFirewallRules', 'loadBalancerPools', 'loadBalancerMonitors', 'magicWanSites',
        'magicWanRoutes', 'mtlsCertificates', 'accessGroups', 'accessOrganizations',
        'accessCertificates', 'warpConnectors', 'teamnetRoutes', 'teamsDexTests',
        'endpointGroups', 'sectionStatus', 'sectionErrors', 'coverageSummaries', 'missingControls', 'dashboard_evidence_lists'
    ],
    backup: ['users', 'sites', 'dashboard_evidence_lists'],
    applications: ['applications', 'dashboard_evidence_lists'],
    security_alerts: ['alerts', 'incidents', 'signIns', 'threatIndicators', 'dashboard_evidence_lists'],
    governance: ['governanceRows', 'dashboard_evidence_lists'],
    compliance: ['controls', 'dashboard_evidence_lists'],
    operations: ['tasks', 'dashboard_evidence_lists']
});
const CLOUDFLARE_COMPACT_EVIDENCE_TYPES = Object.freeze([
    'accessApps',
    'devices',
    'deviceRegistrations',
    'devicePosture',
    'gatewayRules',
    'accessPolicies',
    'dlpProfiles',
    'warpProfiles',
    'virtualNetworks',
    'gatewayAppTypes',
    'accessLogs',
    'permissionMatrix',
    'auditLogs',
    'accountLogs',
    'securityInsights',
    'applicationSecurityReports',
    'apiGatewayOperations',
    'casbFindings',
    'tunnels',
    'cloudforceRequests',
    'intelFeeds',
    'dnsFirewallRules',
    'loadBalancerPools',
    'loadBalancerMonitors',
    'magicWanSites',
    'magicWanRoutes',
    'mtlsCertificates',
    'accessGroups',
    'accessOrganizations',
    'accessCertificates',
    'warpConnectors',
    'teamnetRoutes',
    'teamsDexTests',
    'endpointGroups',
    'sectionStatus',
    'sectionErrors',
    'coverageSummaries'
]);
const BACKUP_COMPACT_EVIDENCE_TYPES = Object.freeze([
    'topStorageUsers',
    'inactiveDataHolders',
    'staleActivityUsers',
    'topSharePointSites',
    'serviceStorageSummary',
    'backupCoverageGaps',
    'recommendations'
]);
const APPLICATIONS_COMPACT_EVIDENCE_TYPES = Object.freeze([
    'highRiskApps',
    'externalApps',
    'excessivePermissionApps',
    'highAccessApps',
    'groupAssignedApps',
    'staleOrUnreviewedApps',
    'recommendations'
]);
const SECURITY_ALERTS_COMPACT_EVIDENCE_TYPES = Object.freeze([
    'summaryMetrics',
    'criticalAlerts',
    'highSeverityAlerts',
    'activeIncidents',
    'suspiciousSignIns',
    'anonymousIpEvents',
    'threatIndicators',
    'repeatedAlertPatterns',
    'affectedUsers',
    'affectedDevices',
    'unresolvedAlerts',
    'recentResolvedAlerts',
    'recommendations'
]);
const COMPLIANCE_COMPACT_EVIDENCE_TYPES = Object.freeze([
    'summaryMetrics',
    'failedControls',
    'partialControls',
    'manualReviewControls',
    'passedControls',
    'controlValidationEvidence',
    'remediationActions',
    'evidenceReferences'
]);
const DOMAIN_EVIDENCE_CATEGORY_METRICS = Object.freeze({
    identity: {
        allUsers: 'totalUsers',
        usersWithoutMfa: 'mfaMissing',
        usersWithMfa: 'mfaEnabled',
        privilegedUsers: 'privilegedUsers',
        adminsWithoutMfa: 'adminsWithoutMfa',
        highRiskUsers: 'highRiskUsers',
        inactiveUsers: 'inactiveUsers',
        failedSignInUsers: 'signInIssues',
        externalUsers: 'externalUsers',
        unknownDeviceUsers: 'unknownDevices'
    },
    devices: {
        allDevices: 'totalDevices',
        nonCompliantDevices: 'nonCompliantDevices',
        notEncryptedDevices: 'notEncryptedDevices',
        staleDevices: 'staleDevices',
        deadDevices: 'dead30Days',
        unmanagedDevices: 'unmanagedDevices',
        unknownDevices: 'unknownDevices'
    },
    email_security: {
        allAlerts: 'activeThreats',
        highSeverityAlerts: 'highSeverityAlerts',
        activeIncidents: 'activeIncidents',
        phishingAlerts: 'phishingCount',
        malwareAlerts: 'malwareCount',
        affectedUsers: 'affectedUsersCount',
        mailActivityUsers: 'activeMailboxes'
    },
    cloudflare_network_security: {
        accessApps: 'protectedApps',
        applications: 'protectedApps',
        devices: 'enrolledDevices',
        deviceRegistrations: 'registeredWarpDevices',
        devicePosture: 'enrolledDevices',
        gatewayRules: 'gatewayPolicies',
        accessPolicies: 'protectedApps',
        accessLogs: 'recentAccessEvents',
        dlpProfiles: 'dlpProfiles',
        warpProfiles: 'enrolledDevices',
        virtualNetworks: 'virtualNetworks',
        gatewayAppTypes: 'appCategories',
        permissionMatrix: 'endpointFamiliesWithGaps',
        auditLogs: 'auditLogs',
        accountLogs: 'accountLogs',
        securityInsights: 'securityInsights',
        applicationSecurityReports: 'applicationSecurityReports',
        apiGatewayOperations: 'apiGatewayOperations',
        casbFindings: 'casbFindings',
        tunnels: 'tunnels',
        cloudforceRequests: 'cloudforceRequests',
        intelFeeds: 'intelFeeds',
        dnsFirewallRules: 'dnsFirewallRules',
        loadBalancerPools: 'loadBalancerPools',
        loadBalancerMonitors: 'loadBalancerMonitors',
        magicWanSites: 'magicWanSites',
        magicWanRoutes: 'magicWanRoutes',
        mtlsCertificates: 'mtlsCertificates',
        accessGroups: 'accessGroups',
        accessOrganizations: 'accessOrganizations',
        accessCertificates: 'accessCertificates',
        warpConnectors: 'warpConnectors',
        teamnetRoutes: 'teamnetRoutes',
        teamsDexTests: 'teamsDexTests',
        endpointGroups: 'endpointFamilies',
        sectionStatus: 'sectionErrors',
        sectionErrors: 'sectionErrors',
        coverageSummaries: 'evidenceCoverage'
    },
    compliance: {
        controls: 'totalControls',
        failedControls: 'failingControls',
        validationEvidence: 'partialControls'
    },
    governance: {
        governanceEvidence: 'totalRows',
        controls: 'connectedRows',
        risks: 'attentionRequiredRows'
    },
    applications: {
        allApplications: 'totalApplications',
        externalApps: 'externalApplications',
        highRiskApps: 'highRiskApps',
        excessivePermissionApps: 'excessivePermissionApps',
        highAccessApps: 'highAccessApps'
    },
    backup: {
        users: 'activeUsersCount',
        inactiveUsers: 'inactiveUsersCount',
        sites: 'servicesCovered'
    },
    security_alerts: {
        alerts: 'totalAlerts',
        highSeverityAlerts: 'highSeverityAlerts',
        activeIncidents: 'activeIncidents',
        suspiciousSignIns: 'suspiciousSignIns',
        threatIndicators: 'threatIndicators'
    },
    operations: {
        tasks: 'totalTasks',
        highPriorityTasks: 'highPriorityTasks'
    }
});
const BACKUP_LINEAGE_FIELDS = Object.freeze([
    'totalStorageGB', 'oneDriveStorageGB', 'sharePointStorageGB', 'exchangeStorageGB',
    'activeUsersCount', 'inactiveUsersCount', 'servicesCovered', 'inactiveUserStorageGB',
    'backupCoverageScore', 'dataExposureRiskScore', 'recommendationsCount',
    'healthScore', 'riskScore', 'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'
]);
const APPLICATIONS_LINEAGE_FIELDS = Object.freeze([
    'totalApplications', 'externalApplications', 'highRiskApps', 'highAccessApps',
    'excessivePermissionApps', 'groupAssignedApps', 'applicationGovernanceScore',
    'userCount', 'groupCount', 'recommendationsCount',
    'healthScore', 'riskScore', 'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'
]);
const SECURITY_LINEAGE_FIELDS = Object.freeze([
    'totalAlerts', 'highSeverityAlerts', 'activeIncidents', 'threatIndicators',
    'usersUnderAttack', 'securityScore', 'suspiciousSignIns', 'recommendationsCount',
    'healthScore', 'riskScore', 'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'
]);

const GOVERNANCE_LINEAGE_FIELDS = Object.freeze([
    'totalRows', 'apiConnectedRows', 'manualRowsExcluded', 'attentionRequiredRows', 'connectedRows',
    'governanceScore', 'recommendationsCount', 'healthScore', 'riskScore',
    'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'
]);

const COMPLIANCE_LINEAGE_FIELDS = Object.freeze([
    'totalControls', 'apiControls', 'manualControlsExcluded', 'failingControls', 'partialControls',
    'passingControls', 'complianceScore', 'recommendationsCount', 'healthScore', 'riskScore',
    'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'
]);

const OPERATIONS_LINEAGE_FIELDS = Object.freeze([
    'totalTasks', 'apiTasks', 'manualTasksExcluded', 'highPriorityTasks', 'mediumPriorityTasks',
    'lowPriorityTasks', 'operationsHealthScore', 'recommendationsCount', 'healthScore', 'riskScore',
    'sourceHealth.evidenceCount', 'snapshotId', 'sourceLastUpdated'
]);

function parseJson(value, fallback = null) {
    if (value == null) return fallback;
    if (Buffer.isBuffer(value)) value = value.toString('utf8');
    if (typeof value === 'object') return value;
    try { return JSON.parse(value); } catch (_) { return fallback; }
}

function bytes(value) {
    return Buffer.byteLength(JSON.stringify(value ?? null), 'utf8');
}

function numberOrNull(value) {
    if (value === null || value === undefined || value === '') return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
}

function textOrNull(value, maximum = 100000) {
    if (value === null || value === undefined || value === '') return null;
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    return text.slice(0, maximum);
}

function normalizeMysqlDate(value) {
    if (!value) return null;

    if (value instanceof Date && !Number.isNaN(value.getTime())) {
        return value.toISOString().slice(0, 10);
    }

    if (typeof value !== 'string') return null;

    const trimmed = value.trim();
    if (!trimmed) return null;

    if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
        return trimmed;
    }

    const invalidDateWords = new Set([
        'ongoing',
        'immediate',
        'asap',
        'tbd',
        'n/a',
        'na',
        'not applicable',
        'not specified',
        'continuous',
        'continual',
        'within 30 days',
        'within 60 days',
        'within 90 days',
        'next review cycle',
        'to be determined'
    ]);

    if (invalidDateWords.has(trimmed.toLowerCase())) {
        return null;
    }

    const parsed = new Date(trimmed);
    if (Number.isNaN(parsed.getTime())) return null;

    return parsed.toISOString().slice(0, 10);
}

function array(value) {
    return Array.isArray(value) ? value : [];
}

function safeValue(value, depth = 0, limits = {}) {
    const maxDepth = limits.maxDepth ?? 6;
    const maxArray = limits.maxArray ?? 20;
    const maxString = limits.maxString ?? 2000;
    if (value == null || typeof value === 'number' || typeof value === 'boolean') return value;
    if (typeof value === 'string') return value.slice(0, maxString);
    if (depth >= maxDepth) return Array.isArray(value) ? `[${value.length} items omitted]` : '[nested detail omitted]';
    if (Array.isArray(value)) return value.slice(0, maxArray).map(item => safeValue(item, depth + 1, limits));
    if (typeof value === 'object') {
        const maxObjectKeys = limits.maxObjectKeys ?? 80;
        return Object.fromEntries(Object.entries(value).slice(0, maxObjectKeys).map(([key, nested]) => [key, safeValue(nested, depth + 1, limits)]));
    }
    return String(value).slice(0, maxString);
}

function safeEvidenceEntity(value, limits = ENTITY_EVIDENCE_LIMITS) {
    return safeValue(value, 0, limits);
}

function entityRecordKey(value) {
    if (!value || typeof value !== 'object') return null;
    return value.id || value.userPrincipalName || value.mail || value.email || value.deviceName ||
        value.applicationId || value.controlId || value.alertId || value.serialNumber || value.name || null;
}

function isEntityRecord(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    return Boolean(
        entityRecordKey(value) ||
        value.displayName || value.userEmail || value.complianceState || value.severity ||
        value.title || value.subject || value.policyName
    );
}

const EVIDENCE_CONTAINER_METADATA_KEYS = new Set([
    'evidencetype', 'type', 'source', 'sourcekey', 'name', 'label', 'category',
    'title', 'count', 'total', 'status'
]);

function containsArray(value, seen = new Set()) {
    if (Array.isArray(value)) return true;
    if (!value || typeof value !== 'object' || seen.has(value)) return false;
    seen.add(value);
    return Object.values(value).some(nested => containsArray(nested, seen));
}

function flattenDomainEvidence(evidence, { rootPath = 'evidence', domainKey = null } = {}) {
    const flattened = [];

    function pathLabel(path) {
        const segments = String(path).replace(/\[\d+\]/g, '').split('.').filter(Boolean);
        return segments.at(-1) || 'evidence';
    }

    function containerContext(value, inherited) {
        const context = { ...inherited };
        if (!value || typeof value !== 'object' || Array.isArray(value)) return context;
        for (const [key, nested] of Object.entries(value)) {
            if (nested == null || !['string', 'number', 'boolean'].includes(typeof nested)) continue;
            if (EVIDENCE_CONTAINER_METADATA_KEYS.has(key.toLowerCase())) context[key] = nested;
        }
        if (value.evidenceType) context.evidenceType = value.evidenceType;
        return context;
    }

    function append(value, path, context, { preserveEntity = false } = {}) {
        const itemContext = containerContext(value, context);
        const sourceLabel = String(
            itemContext.listName || itemContext.evidenceType || itemContext.type ||
            itemContext.sourceKey || itemContext.source || pathLabel(path)
        );
        flattened.push({
            internalSourcePath: path,
            sourceLabel,
            evidenceType: String(itemContext.evidenceType || itemContext.type || sourceLabel || 'stored_evidence'),
            evidenceCategory: itemContext.listName || null,
            sourceMetric: itemContext.sourceMetric || null,
            entityKey: entityRecordKey(value?.data ?? value),
            data: preserveEntity
                ? safeEvidenceEntity(value?.data ?? value)
                : safeValue(value?.data ?? value, 0, { maxDepth: 7, maxArray: 50, maxString: 1600, maxObjectKeys: 100 })
        });
    }

    function walk(value, path, inherited = {}, isArrayItem = false) {
        if (Array.isArray(value)) {
            value.forEach((item, index) => walk(item, `${path}[${index}]`, inherited, true));
            return;
        }

        if (!value || typeof value !== 'object') {
            append(value, path, inherited);
            return;
        }

        if (value.evidenceType === 'dashboard_evidence_lists') {
            return;
        }

        if (isArrayItem && isEntityRecord(value)) {
            append(value, path, inherited, { preserveEntity: true });
            return;
        }

        if (Object.prototype.hasOwnProperty.call(value, 'data') && Array.isArray(value.data)) {
            const context = containerContext(value, inherited);
            value.data.forEach((item, index) => walk(item, `${path}.data[${index}]`, context, true));
            return;
        }

        const entries = Object.entries(value);
        const arrayBearingEntries = entries.filter(([, nested]) => containsArray(nested));
        if (!arrayBearingEntries.length) {
            append(value, path, inherited, { preserveEntity: isEntityRecord(value) });
            return;
        }

        const context = containerContext(value, inherited);
        if (isArrayItem && isEntityRecord(value)) {
            append(value, path, context, { preserveEntity: true });
            return;
        }

        for (const [key, nested] of arrayBearingEntries) {
            walk(nested, `${path}.${key}`, context, false);
        }
    }

    const normalizedEvidence = Array.isArray(evidence)
        ? evidence.filter(item => item?.evidenceType !== 'dashboard_evidence_lists')
        : evidence;
    walk(normalizedEvidence, rootPath);
    return flattened;
}

function filterDomainEvidence(sourceEvidence, domainKey) {
    if (!Array.isArray(sourceEvidence)) return sourceEvidence;
    const allowedTypes = DOMAIN_EVIDENCE_TYPES[domainKey];
    if (!allowedTypes?.length) return sourceEvidence;
    const filtered = sourceEvidence.filter(item => allowedTypes.includes(item?.evidenceType));
    return filtered.length ? filtered : sourceEvidence.filter(item => item?.evidenceType !== 'dashboard_evidence_lists');
}

function normalizeEmailAlertsPayload(alerts) {
    if (Array.isArray(alerts)) return alerts;
    if (Array.isArray(alerts?.alerts)) return alerts.alerts;
    return [];
}

function emailAddressFrom(value = {}) {
    return firstReadableValue(
        value.userPrincipalName, value.userEmail, value.email, value.mail, value.recipient,
        value.accountName, value.user, value.mailbox, value.displayName
    );
}

function emailThreatType(alert = {}) {
    const text = `${alert.title || ''} ${alert.description || ''} ${alert.category || ''}`.toLowerCase();
    if (/business email|bec|impersonation|spoof/.test(text)) return text.includes('spoof') ? 'spoofing' : 'bec';
    if (text.includes('phish')) return 'phishing';
    if (/malware|attachment|ransomware|virus/.test(text)) return 'malware';
    if (text.includes('spam')) return 'spam';
    return 'other';
}

function collectEmailEvidenceLists(sourceEvidence = [], flattenedEvidence = []) {
    const lists = { alerts: [], incidents: [], mailUsers: [] };
    for (const item of array(sourceEvidence)) {
        const type = String(item?.evidenceType || '').toLowerCase();
        const data = item?.data;
        if (type === 'alerts') lists.alerts.push(...normalizeEmailAlertsPayload(data));
        else if (type === 'incidents') lists.incidents.push(...array(data));
        else if (/mailactivity|mailflow|mailusers|mailbox/i.test(type)) lists.mailUsers.push(...array(data));
    }
    if (!lists.alerts.length) {
        lists.alerts.push(...flattenedEvidence
            .filter(row => /alert|threat/i.test(String(row.evidenceType || row.sourceLabel || '')))
            .map(row => row.data)
            .filter(Boolean));
    }
    if (!lists.mailUsers.length) {
        lists.mailUsers.push(...flattenedEvidence
            .filter(row => /mailactivity|mailflow|mailbox/i.test(String(row.evidenceType || row.sourceLabel || '')))
            .map(row => row.data)
            .filter(Boolean));
    }
    return lists;
}

function compactEmailSecurityEvidenceRows(sourceEvidence, flattenedEvidence, current = {}) {
    const { alerts, incidents, mailUsers } = collectEmailEvidenceLists(sourceEvidence, flattenedEvidence);
    const severityRank = value => ({ critical: 4, high: 3, medium: 2, low: 1 }[String(value || '').toLowerCase()] || 0);
    const alertPathById = new Map(flattenedEvidence
        .filter(row => /alert|threat/i.test(String(row.evidenceType || row.sourceLabel || '')))
        .map(row => [String(row.data?.id || row.data?.alertId || row.entityKey || ''), row.internalSourcePath]));
    const securityAlerts = alerts
        .slice()
        .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
        .slice(0, 25)
        .map((alert, index) => ({
            internalSourcePath: alertPathById.get(String(alert.id || alert.alertId || '')) || `email_security.compact.securityAlerts[${index}]`,
            sourceLabel: 'securityAlerts',
            evidenceType: 'securityAlerts',
            evidenceCategory: 'securityAlerts',
            sourceMetric: 'activeThreats',
            entityKey: alert.id || alert.alertId || alert.title || `email-alert-${index + 1}`,
            data: {
                id: alert.id || alert.alertId || null,
                title: firstReadableValue(alert.title, alert.name, alert.subject) || 'Email security alert',
                severity: firstReadableValue(alert.severity) || 'unknown',
                status: firstReadableValue(alert.status) || 'unknown',
                category: firstReadableValue(alert.category, emailThreatType(alert)),
                threatType: emailThreatType(alert),
                userEmail: emailAddressFrom(alert),
                createdDateTime: firstReadableValue(alert.createdDateTime, alert.eventDateTime),
                businessReason: 'Security alert from Microsoft email protection evidence',
                recommendation: 'Investigate alert status, impacted users, and remediation actions.'
            }
        }));
    const targeted = new Map();
    for (const alert of alerts) {
        const users = array(alert.userStates).length ? array(alert.userStates) : [alert];
        for (const user of users) {
            const email = emailAddressFrom(user);
            if (!email) continue;
            const item = targeted.get(email) || { userEmail: email, threatCount: 0, highSeverityCount: 0, threatTypes: new Set(), alertTitles: [] };
            item.threatCount += 1;
            if (severityRank(alert.severity) >= 3) item.highSeverityCount += 1;
            item.threatTypes.add(emailThreatType(alert));
            if (alert.title && item.alertTitles.length < 3) item.alertTitles.push(alert.title);
            targeted.set(email, item);
        }
    }
    const topTargetedUsers = [...targeted.values()]
        .sort((a, b) => b.highSeverityCount - a.highSeverityCount || b.threatCount - a.threatCount)
        .slice(0, 10)
        .map((user, index) => ({
            internalSourcePath: `email_security.compact.topTargetedUsers[${index}]`,
            sourceLabel: 'topTargetedUsers',
            evidenceType: 'topTargetedUsers',
            evidenceCategory: 'topTargetedUsers',
            sourceMetric: 'affectedUsersCount',
            entityKey: user.userEmail,
            data: {
                entityId: user.userEmail,
                entityName: user.userEmail,
                entityEmail: user.userEmail,
                entityType: 'User',
                userPrincipalName: user.userEmail,
                threatCount: user.threatCount,
                highSeverityCount: user.highSeverityCount,
                threatTypes: [...user.threatTypes],
                alertTitles: user.alertTitles,
                businessReason: 'Mailbox/user appears repeatedly in email threat evidence',
                recommendation: 'Prioritize mailbox review and user-focused remediation.'
            }
        }));
    const mailboxVolume = mailUsers.map((mailbox, index) => {
        const send = numberOrNull(mailbox.sendCount ?? mailbox.sentCount ?? mailbox.send) || 0;
        const receive = numberOrNull(mailbox.receiveCount ?? mailbox.receivedCount ?? mailbox.receive) || 0;
        const read = numberOrNull(mailbox.readCount ?? mailbox.read) || 0;
        return { mailbox, index, total: send + receive + read, send, receive, read };
    });
    const mailboxRow = (item, category, sourceMetric, index) => ({
        internalSourcePath: `email_security.compact.${category}[${index}]`,
        sourceLabel: category,
        evidenceType: category,
        evidenceCategory: category,
        sourceMetric,
        entityKey: emailAddressFrom(item.mailbox) || `mailbox-${index + 1}`,
        data: {
            entityId: emailAddressFrom(item.mailbox),
            entityName: firstReadableValue(item.mailbox.displayName, emailAddressFrom(item.mailbox)),
            entityEmail: emailAddressFrom(item.mailbox),
            entityType: 'User',
            sendCount: item.send,
            receiveCount: item.receive,
            readCount: item.read,
            totalMailActivity: item.total,
            lastActivityDate: firstReadableValue(item.mailbox.lastActivityDate),
            businessReason: category === 'inactiveMailboxes' ? 'Mailbox appears inactive in mailflow context' : 'High mail volume provides context for email security triage',
            recommendation: category === 'inactiveMailboxes' ? 'Review whether mailbox should remain active.' : 'Use as context only; investigate only if paired with threat evidence.'
        }
    });
    const highVolumeMailboxes = mailboxVolume
        .filter(item => item.total > 0)
        .sort((a, b) => b.total - a.total)
        .slice(0, 10)
        .map((item, index) => mailboxRow(item, 'highVolumeMailboxes', 'totalMailActivity', index));
    const mailActivityUsers = mailboxVolume
        .map((item, index) => mailboxRow(item, 'mailActivityUsers', 'activeMailboxes', index));
    const inactiveMailboxes = mailboxVolume
        .filter(item => item.total === 0 || !item.mailbox.lastActivityDate)
        .slice(0, 10)
        .map((item, index) => mailboxRow(item, 'inactiveMailboxes', 'activeMailboxes', index));
    const mailflowSummary = {
        internalSourcePath: 'email_security.compact.mailflowSummary',
        sourceLabel: 'mailflowSummary',
        evidenceType: 'mailflowSummary',
        evidenceCategory: 'mailflowSummary',
        sourceMetric: 'totalMailActivity',
        entityKey: 'mailflowSummary',
        data: {
            totalMailboxes: mailUsers.length,
            activeMailboxes: current.dashboardMetrics?.activeMailboxes ?? current.metrics?.activeMailboxes ?? mailUsers.filter(user => user.lastActivityDate).length,
            totalMailActivity: current.dashboardMetrics?.totalMailActivity ?? current.metrics?.totalMailActivity ?? mailboxVolume.reduce((sum, item) => sum + item.total, 0),
            sendCount: current.dashboardMetrics?.sendCount ?? current.metrics?.sendCount ?? mailboxVolume.reduce((sum, item) => sum + item.send, 0),
            receiveCount: current.dashboardMetrics?.receiveCount ?? current.metrics?.receiveCount ?? mailboxVolume.reduce((sum, item) => sum + item.receive, 0),
            readCount: current.dashboardMetrics?.readCount ?? current.metrics?.readCount ?? mailboxVolume.reduce((sum, item) => sum + item.read, 0),
            contextOnly: true,
            businessReason: 'Mailflow is context for exposure and mailbox activity, not a threat record by itself.',
            recommendation: 'Use mailflow context to prioritize threat investigation, not as standalone risk.'
        }
    };
    const evidenceSamples = flattenedEvidence
        .filter(row => !/mailactivity|mailflow|mailbox/i.test(String(row.evidenceType || row.sourceLabel || '')))
        .slice(0, 10)
        .map((row, index) => ({
            ...row,
            sourceLabel: 'evidenceSamples',
            evidenceType: 'evidenceSamples',
            evidenceCategory: 'evidenceSamples',
            sourceMetric: row.sourceMetric || 'evidenceSamples',
            internalSourcePath: row.internalSourcePath || `email_security.compact.evidenceSamples[${index}]`
        }));
    return [
        ...securityAlerts,
        ...topTargetedUsers,
        ...mailActivityUsers,
        ...highVolumeMailboxes,
        ...inactiveMailboxes,
        mailflowSummary,
        ...evidenceSamples
    ];
}

function securitySeverityRank(value) {
    return { critical: 5, high: 4, medium: 3, low: 2, informational: 1, info: 1 }[String(value || '').toLowerCase()] || 0;
}

function securityAlertStatus(value = {}) {
    return firstReadableValue(value.status, value.incidentStatus, value.alertStatus, value.state) || 'unknown';
}

function securityEntityName(value = {}) {
    return firstReadableValue(
        value.entityName, value.displayName, value.title, value.alertName, value.incidentName,
        value.userPrincipalName, value.userEmail, value.mail, value.email,
        value.deviceName, value.hostName, value.hostname, value.ipAddress, value.name
    );
}

function securityEventTimestamp(value = {}) {
    return firstReadableValue(
        value.createdDateTime, value.createdAt, value.eventDateTime, value.eventTime,
        value.lastUpdatedDateTime, value.updatedDateTime, value.updatedAt, value.resolvedDateTime,
        value.lastActivityDateTime, value.timeGenerated, value.timestamp
    );
}

function securityPatternKey(value = {}) {
    return String(firstReadableValue(value.title, value.alertName, value.displayName, value.category, value.classification, 'security alert') || '')
        .replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, '<id>')
        .replace(/\b\d+\b/g, '<n>')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 160);
}

function securityAlertRowData(value = {}, type = 'alerts') {
    const userPrincipalName = firstReadableValue(value.userPrincipalName, value.userEmail, value.mail, value.email, value.user, value.accountName);
    const deviceName = firstReadableValue(value.deviceName, value.hostName, value.hostname, value.machineName, value.computerName);
    const ipAddress = firstReadableValue(value.ipAddress, value.clientIpAddress, value.sourceIpAddress, value.ip);
    const alertName = firstReadableValue(value.alertName, value.title, value.displayName, value.name, value.subject) || 'Security alert';
    return compactNonEmptyObject({
        entityId: firstReadableValue(value.entityId, value.id, value.alertId, value.sourceAlertId, value.incidentId, userPrincipalName, deviceName, ipAddress, alertName),
        entityName: securityEntityName(value) || alertName,
        entityType: type === 'activeIncidents' ? 'Incident' : ipAddress && /sign/i.test(type) ? 'SignInEvent' : deviceName ? 'Device' : userPrincipalName ? 'User' : 'Alert',
        alertName,
        incidentName: firstReadableValue(value.incidentName),
        userPrincipalName,
        deviceName,
        ipAddress,
        severity: firstReadableValue(value.severity, value.alertSeverity) || 'unknown',
        status: securityAlertStatus(value),
        category: firstReadableValue(value.category, value.classification, value.detectionSource, value.serviceSource),
        timestamp: securityEventTimestamp(value),
        alertCount: numberOrNull(value.alertCount ?? value.count),
        sourceAlertId: firstReadableValue(value.sourceAlertId, value.alertId, value.id),
        riskReason: firstReadableValue(value.riskReason, value.description, value.reason),
        businessReason: 'Security operations evidence requires investigation or response decision.',
        recommendation: type === 'recentResolvedAlerts'
            ? 'Confirm resolution quality and recurring pattern suppression.'
            : 'Triage severity, affected entity, and containment status.'
    });
}

function securitySignInRowData(value = {}, type = 'suspiciousSignIns') {
    const userPrincipalName = firstReadableValue(value.userPrincipalName, value.userEmail, value.mail, value.email, value.userDisplayName, value.user);
    const ipAddress = firstReadableValue(value.ipAddress, value.clientIpAddress, value.sourceIpAddress, value.ip);
    const location = firstReadableValue(value.location, value.city, value.countryOrRegion, value.country);
    return compactNonEmptyObject({
        entityId: firstReadableValue(value.entityId, value.id, value.signInId, ipAddress, userPrincipalName),
        entityName: firstReadableValue(userPrincipalName, ipAddress, value.displayName, 'Suspicious sign-in'),
        entityType: type === 'anonymousIpEvents' || ipAddress ? 'IPAddress' : 'SignInEvent',
        userPrincipalName,
        ipAddress,
        location,
        riskLevel: firstReadableValue(value.riskLevel, value.riskState, value.riskDetail),
        status: firstReadableValue(value.status, value.result, value.resultDescription, value.failureReason),
        timestamp: securityEventTimestamp(value),
        alertCount: numberOrNull(value.alertCount ?? value.count),
        sourceAlertId: firstReadableValue(value.sourceAlertId, value.alertId, value.id, value.signInId),
        riskReason: type === 'anonymousIpEvents' ? 'Anonymous or suspicious IP sign-in evidence.' : firstReadableValue(value.riskReason, value.riskDetail, value.description),
        businessReason: 'Suspicious sign-in activity can indicate credential compromise.',
        recommendation: 'Review sign-in, user risk, conditional access outcome, and containment status.'
    });
}

function securityEvidenceRow(row, type, data, index, sourceMetric = type) {
    const compactData = type === 'suspiciousSignIns' || type === 'anonymousIpEvents'
        ? securitySignInRowData(data, type)
        : securityAlertRowData(data, type);
    return {
        internalSourcePath: row?.internalSourcePath || `security_alerts.compact.${type}[${index}]`,
        sourceLabel: type,
        evidenceType: type,
        evidenceCategory: type,
        sourceMetric,
        entityKey: compactData.entityId || compactData.entityName || `${type}-${index + 1}`,
        data: compactData
    };
}

function collectSecurityEvidenceRows(flattenedEvidence = []) {
    const rows = array(flattenedEvidence);
    return {
        alerts: rows.filter(row => /alert/i.test(String(row.evidenceType || row.sourceLabel || row.evidenceCategory || ''))),
        incidents: rows.filter(row => /incident/i.test(String(row.evidenceType || row.sourceLabel || row.evidenceCategory || ''))),
        signIns: rows.filter(row => /sign/i.test(String(row.evidenceType || row.sourceLabel || row.evidenceCategory || ''))),
        threatIndicators: rows.filter(row => /threat.?indicator|indicator/i.test(String(row.evidenceType || row.sourceLabel || row.evidenceCategory || ''))),
        findings: rows.filter(row => /security.?finding/i.test(String(row.evidenceType || row.sourceLabel || row.evidenceCategory || ''))),
        recommendations: rows.filter(row => /recommend/i.test(String(row.evidenceType || row.sourceLabel || row.evidenceCategory || '')))
    };
}

function threatIndicatorKey(type, value) {
    return `${String(type || '').toLowerCase()}:${String(value || '').trim().toLowerCase()}`;
}

function addThreatIndicator(map, type, value, sourceRow, sourceField = null, extra = {}) {
    const cleanedValue = visibleTextOrNull(value, 320);
    if (!cleanedValue) return;
    const key = threatIndicatorKey(type, cleanedValue);
    const existing = map.get(key) || {
        indicatorType: type,
        indicatorValue: cleanedValue,
        occurrenceCount: 0,
        sourceFields: new Set(),
        internalSourcePaths: new Set(),
        relatedUsers: new Set(),
        relatedDevices: new Set(),
        relatedAlerts: new Set(),
        confidence: extra.confidence || 'medium',
        source: extra.source || 'internal_security_alerts'
    };
    existing.occurrenceCount += 1;
    if (sourceField) existing.sourceFields.add(sourceField);
    if (sourceRow?.internalSourcePath) existing.internalSourcePaths.add(sourceRow.internalSourcePath);
    const data = sourceRow?.data && typeof sourceRow.data === 'object' ? sourceRow.data : {};
    const user = firstReadableValue(data.userPrincipalName, data.userEmail, data.mail, data.email, extra.userPrincipalName);
    const device = firstReadableValue(data.deviceName, data.hostName, data.hostname, extra.deviceName);
    const alertTitle = firstReadableValue(data.title, data.alertName, data.displayName, extra.alertTitle);
    if (user) existing.relatedUsers.add(user);
    if (device) existing.relatedDevices.add(device);
    if (alertTitle) existing.relatedAlerts.add(alertTitle);
    map.set(key, existing);
}

function extractSecurityThreatIndicators(flattenedEvidence = []) {
    const indicatorMap = new Map();
    const rows = array(flattenedEvidence);
    const keywordPattern = /\b(?:malware|phishing|phish|ransomware|trojan|credential theft|credential harvesting|bec|spoof|impossible travel|anonymous ip|risky sign[-\s]?in|brute force|password spray|suspicious inbox rule)\b/gi;
    for (const row of rows) {
        const data = row?.data && typeof row.data === 'object' ? row.data : {};
        const serialized = JSON.stringify(data).slice(0, 12000);
        for (const ip of serialized.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || []) {
            addThreatIndicator(indicatorMap, 'IPAddress', ip, row, 'text.ipAddress', { confidence: 'high' });
        }
        for (const url of serialized.match(/\bhttps?:\/\/[^\s"'<>]+/gi) || []) {
            addThreatIndicator(indicatorMap, 'URL', url.replace(/[),.;]+$/g, ''), row, 'text.url', { confidence: 'high' });
        }
        for (const hash of serialized.match(/\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi) || []) {
            addThreatIndicator(indicatorMap, 'FileHash', hash, row, 'text.fileHash', { confidence: 'high' });
        }
        for (const email of serialized.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || []) {
            const fieldType = /sender|from/i.test(serialized.slice(Math.max(0, serialized.indexOf(email) - 80), serialized.indexOf(email) + 80))
                ? 'SenderAddress'
                : 'UserPrincipalName';
            addThreatIndicator(indicatorMap, fieldType, email, row, 'text.email', { confidence: 'medium' });
        }
        for (const domain of serialized.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi) || []) {
            if (/microsoft\.com|windows\.net|example\.com|contoso\.com/i.test(domain)) continue;
            addThreatIndicator(indicatorMap, 'Domain', domain, row, 'text.domain', { confidence: 'medium' });
        }
        const structuredFields = [
            ['IPAddress', firstReadableValue(data.ipAddress, data.clientIpAddress, data.sourceIpAddress, data.ip)],
            ['URL', firstReadableValue(data.url, data.uri, data.link, data.maliciousUrl)],
            ['Domain', firstReadableValue(data.domain, data.senderDomain, data.urlDomain, data.hostname)],
            ['FileHash', firstReadableValue(data.fileHash, data.sha256, data.sha1, data.md5)],
            ['SenderAddress', firstReadableValue(data.senderAddress, data.senderEmail, data.sender, data.fromAddress, data.from)],
            ['UserPrincipalName', firstReadableValue(data.userPrincipalName, data.userEmail, data.mail, data.email, data.user)],
            ['DeviceName', firstReadableValue(data.deviceName, data.hostName, data.hostname, data.machineName, data.computerName)],
            ['AlertTitle', firstReadableValue(data.title, data.alertName, data.displayName, data.name)],
            ['RiskType', firstReadableValue(data.riskType, data.riskLevel, data.riskDetail, data.category, data.classification, data.detectionSource)],
            ['SignInLocation', firstReadableValue(data.location, data.city, data.countryOrRegion, data.country)]
        ];
        for (const [type, value] of structuredFields) {
            addThreatIndicator(indicatorMap, type, value, row, type, { confidence: ['IPAddress', 'URL', 'FileHash'].includes(type) ? 'high' : 'medium' });
        }
        for (const match of serialized.match(keywordPattern) || []) {
            addThreatIndicator(indicatorMap, 'Keyword', match.toLowerCase(), row, 'text.keyword', { confidence: 'low' });
        }
    }
    return [...indicatorMap.values()]
        .sort((left, right) => right.occurrenceCount - left.occurrenceCount || String(left.indicatorType).localeCompare(String(right.indicatorType)))
        .slice(0, 25)
        .map((indicator, index) => ({
            internalSourcePath: [...indicator.internalSourcePaths][0] || `security_alerts.compact.threatIndicators[${index}]`,
            sourceLabel: 'threatIndicators',
            evidenceType: 'threatIndicators',
            evidenceCategory: 'threatIndicators',
            sourceMetric: 'threatIndicators',
            entityKey: `${indicator.indicatorType}:${indicator.indicatorValue}`,
            data: compactNonEmptyObject({
                entityId: `${indicator.indicatorType}:${indicator.indicatorValue}`,
                entityName: indicator.indicatorValue,
                entityType: 'ThreatIndicator',
                indicatorType: indicator.indicatorType,
                indicatorValue: indicator.indicatorValue,
                occurrenceCount: indicator.occurrenceCount,
                source: indicator.source,
                confidence: indicator.confidence,
                sourceFields: [...indicator.sourceFields].slice(0, 6),
                relatedUsers: [...indicator.relatedUsers].slice(0, 5),
                relatedDevices: [...indicator.relatedDevices].slice(0, 5),
                relatedAlerts: [...indicator.relatedAlerts].slice(0, 5),
                internalOnly: true,
                businessReason: 'Indicator was extracted from Security Alerts evidence for internal triage context.',
                recommendation: 'Use this indicator to correlate affected alerts, sign-ins, users, and devices before external enrichment is available.'
            })
        }));
}

function compactSecurityAlertsEvidenceRows(flattenedEvidence, current = {}) {
    const { alerts, incidents, signIns, threatIndicators, findings, recommendations } = collectSecurityEvidenceRows(flattenedEvidence);
    const metricSource = { ...(current.metrics || {}), ...(current.dashboardMetrics || {}), ...(current.calculatedIndicators || {}) };
    const alertData = alerts.map(row => ({ row, data: row.data || {} }));
    const signInData = signIns.map(row => ({ row, data: row.data || {} }));
    const sortedAlerts = alertData.slice().sort((left, right) =>
        securitySeverityRank(right.data?.severity) - securitySeverityRank(left.data?.severity) ||
        String(securityEventTimestamp(right.data) || '').localeCompare(String(securityEventTimestamp(left.data) || ''))
    );
    const unresolvedStatuses = /active|new|open|inprogress|in_progress|investigating|unresolved/i;
    const resolvedStatuses = /resolved|closed|dismissed|remediated|completed/i;
    const activeIncidents = incidents
        .filter(item => unresolvedStatuses.test(securityAlertStatus(item.data || item)))
        .slice(0, 10)
        .map((row, index) => securityEvidenceRow(row, 'activeIncidents', row.data || {}, index, 'activeIncidents'));
    const criticalAlerts = sortedAlerts
        .filter(({ data }) => /^critical$/i.test(String(data.severity || data.alertSeverity || '')))
        .slice(0, 10)
        .map(({ row, data }, index) => securityEvidenceRow(row, 'criticalAlerts', data, index, 'highSeverityAlerts'));
    const highSeverityAlerts = sortedAlerts
        .filter(({ data }) => /^high$/i.test(String(data.severity || data.alertSeverity || '')))
        .slice(0, 10)
        .map(({ row, data }, index) => securityEvidenceRow(row, 'highSeverityAlerts', data, index, 'highSeverityAlerts'));
    const unresolvedAlerts = sortedAlerts
        .filter(({ data }) => unresolvedStatuses.test(securityAlertStatus(data)))
        .slice(0, 10)
        .map(({ row, data }, index) => securityEvidenceRow(row, 'unresolvedAlerts', data, index, 'totalAlerts'));
    const recentResolvedAlerts = sortedAlerts
        .filter(({ data }) => resolvedStatuses.test(securityAlertStatus(data)))
        .slice(0, 10)
        .map(({ row, data }, index) => securityEvidenceRow(row, 'recentResolvedAlerts', data, index, 'totalAlerts'));
    const suspiciousSignIns = signInData
        .filter(({ data }) => /risk|suspicious|failure|blocked|compromis|anonymous/i.test(itemSearchText(data)))
        .slice(0, 10)
        .map(({ row, data }, index) => securityEvidenceRow(row, 'suspiciousSignIns', data, index, 'suspiciousSignIns'));
    const anonymousIpEvents = signInData
        .filter(({ data }) => /anonymous|tor|proxy|vpn|risky ip|anonym/i.test(itemSearchText(data)))
        .slice(0, 10)
        .map(({ row, data }, index) => securityEvidenceRow(row, 'anonymousIpEvents', data, index, 'anonymousIpEvents'));
    const patterns = new Map();
    for (const { row, data } of alertData) {
        const key = securityPatternKey(data);
        if (!key) continue;
        const item = patterns.get(key) || { pattern: key, count: 0, highSeverityCount: 0, users: new Set(), devices: new Set(), latestTimestamp: null, row, data };
        item.count += 1;
        if (securitySeverityRank(data.severity) >= 4) item.highSeverityCount += 1;
        const user = firstReadableValue(data.userPrincipalName, data.userEmail, data.email, data.mail);
        const device = firstReadableValue(data.deviceName, data.hostName, data.hostname);
        if (user) item.users.add(user);
        if (device) item.devices.add(device);
        const timestamp = securityEventTimestamp(data);
        if (timestamp && (!item.latestTimestamp || String(timestamp) > String(item.latestTimestamp))) item.latestTimestamp = timestamp;
        patterns.set(key, item);
    }
    const repeatedAlertPatterns = [...patterns.values()]
        .filter(item => item.count > 1)
        .sort((left, right) => right.highSeverityCount - left.highSeverityCount || right.count - left.count)
        .slice(0, 10)
        .map((item, index) => securityEvidenceRow(item.row, 'repeatedAlertPatterns', {
            id: item.pattern,
            title: item.pattern,
            severity: item.highSeverityCount ? 'high' : 'medium',
            status: 'repeated',
            alertCount: item.count,
            userPrincipalName: [...item.users].slice(0, 3).join(', '),
            deviceName: [...item.devices].slice(0, 3).join(', '),
            createdDateTime: item.latestTimestamp,
            category: 'Repeated alert pattern',
            riskReason: `${item.count} alert rows matched this repeated pattern.`
        }, index, 'repeatedAlertPatterns'));
    const aggregateEntity = (rows, keyFn, type) => {
        const map = new Map();
        for (const { row, data } of rows) {
            const key = keyFn(data);
            if (!key) continue;
            const item = map.get(key) || { key, count: 0, highSeverityCount: 0, latestTimestamp: null, row, data };
            item.count += 1;
            if (securitySeverityRank(data.severity) >= 4) item.highSeverityCount += 1;
            const timestamp = securityEventTimestamp(data);
            if (timestamp && (!item.latestTimestamp || String(timestamp) > String(item.latestTimestamp))) item.latestTimestamp = timestamp;
            map.set(key, item);
        }
        return [...map.values()]
            .sort((left, right) => right.highSeverityCount - left.highSeverityCount || right.count - left.count)
            .slice(0, 10)
            .map((item, index) => securityEvidenceRow(item.row, type, {
                ...item.data,
                entityId: item.key,
                entityName: item.key,
                title: item.key,
                alertCount: item.count,
                severity: item.highSeverityCount ? 'high' : firstReadableValue(item.data.severity, 'medium'),
                createdDateTime: item.latestTimestamp,
                riskReason: `${item.count} related security alert/sign-in row(s).`
            }, index, type));
    };
    const affectedUsers = aggregateEntity([...alertData, ...signInData], data => firstReadableValue(data.userPrincipalName, data.userEmail, data.email, data.mail, data.user), 'affectedUsers');
    const affectedDevices = aggregateEntity(alertData, data => firstReadableValue(data.deviceName, data.hostName, data.hostname, data.machineName), 'affectedDevices');
    const externalThreatIndicators = threatIndicators.slice(0, 10).map((row, index) => {
        const data = row.data || {};
        const indicatorType = firstReadableValue(data.indicatorType, data.type, data.category, 'ExternalIndicator');
        const indicatorValue = firstReadableValue(data.indicatorValue, data.value, data.url, data.domain, data.ipAddress, data.fileHash, data.name, data.title);
        return {
            internalSourcePath: row?.internalSourcePath || `security_alerts.compact.threatIndicators.external[${index}]`,
            sourceLabel: 'threatIndicators',
            evidenceType: 'threatIndicators',
            evidenceCategory: 'threatIndicators',
            sourceMetric: 'threatIndicators',
            entityKey: `${indicatorType}:${indicatorValue || index + 1}`,
            data: compactNonEmptyObject({
                ...safeEvidenceEntity(data, { maxDepth: 2, maxArray: 5, maxString: 320, maxObjectKeys: 20 }),
                entityId: `${indicatorType}:${indicatorValue || index + 1}`,
                entityName: indicatorValue || firstReadableValue(data.title, data.name, 'External threat indicator'),
                entityType: 'ThreatIndicator',
                indicatorType,
                indicatorValue,
                source: 'external_threat_indicators',
                internalOnly: false,
                businessReason: 'External threat indicator enrichment is available for Security Alerts correlation.',
                recommendation: 'Correlate this indicator with affected alerts, sign-ins, users, and devices.'
            })
        };
    });
    const internalThreatIndicators = extractSecurityThreatIndicators(flattenedEvidence);
    const seenThreatIndicators = new Set(externalThreatIndicators.map(row => threatIndicatorKey(row.data?.indicatorType, row.data?.indicatorValue || row.data?.entityName)));
    const threatIndicatorRows = [
        ...externalThreatIndicators,
        ...internalThreatIndicators.filter(row => {
            const key = threatIndicatorKey(row.data?.indicatorType, row.data?.indicatorValue || row.data?.entityName);
            if (seenThreatIndicators.has(key)) return false;
            seenThreatIndicators.add(key);
            return true;
        })
    ].slice(0, 25);
    const recommendationRows = recommendations.slice(0, 10).map((row, index) => securityEvidenceRow(row, 'recommendations', row.data || {}, index, 'recommendations'));
    const securityFindingRows = findings.slice(0, 25).map((row, index) =>
        securityEvidenceRow(row, 'securityFindings', row.data || {}, index, 'securityFindings')
    );
    const summaryMetrics = {
        internalSourcePath: 'security_alerts.compact.summaryMetrics',
        sourceLabel: 'summaryMetrics',
        evidenceType: 'summaryMetrics',
        evidenceCategory: 'summaryMetrics',
        sourceMetric: 'summaryMetrics',
        entityKey: 'summaryMetrics',
        data: compactNonEmptyObject({
            totalAlerts: numberOrNull(metricSource.totalAlerts) ?? alerts.length,
            criticalAlerts: criticalAlerts.length,
            highSeverityAlerts: numberOrNull(metricSource.highSeverityAlerts) ?? highSeverityAlerts.length + criticalAlerts.length,
            activeIncidents: numberOrNull(metricSource.activeIncidents) ?? activeIncidents.length,
            suspiciousSignIns: numberOrNull(metricSource.suspiciousSignIns) ?? suspiciousSignIns.length,
            anonymousIpEvents: anonymousIpEvents.length,
            repeatedAlertPatterns: repeatedAlertPatterns.length,
            affectedUsers: affectedUsers.length,
            affectedDevices: affectedDevices.length,
            unresolvedAlerts: unresolvedAlerts.length,
            recentResolvedAlerts: recentResolvedAlerts.length,
            threatIndicators: numberOrNull(metricSource.threatIndicators) ?? threatIndicatorRows.length,
            internalThreatIndicators: internalThreatIndicators.length,
            externalThreatIndicators: externalThreatIndicators.length,
            threatIndicatorSource: externalThreatIndicators.length ? 'external' : (internalThreatIndicators.length ? 'internal_security_alerts' : 'unavailable'),
            securityFindings: numberOrNull(metricSource.securityFindings) ?? findings.length,
            usersUnderAttack: numberOrNull(metricSource.usersUnderAttack),
            securityScore: numberOrNull(metricSource.securityScore),
            healthScore: numberOrNull(current.healthScore),
            riskScore: numberOrNull(current.riskScore),
            recommendationsCount: numberOrNull(metricSource.recommendationsCount) ?? recommendationRows.length,
            sourceLastUpdated: current.source?.freshness?.lastUpdated || sourceLineageLastUpdated(current.source)
        })
    };
    return [
        summaryMetrics,
        ...criticalAlerts,
        ...highSeverityAlerts,
        ...activeIncidents,
        ...suspiciousSignIns,
        ...anonymousIpEvents,
        ...threatIndicatorRows,
        ...repeatedAlertPatterns,
        ...affectedUsers,
        ...affectedDevices,
        ...unresolvedAlerts,
        ...recentResolvedAlerts,
        ...securityFindingRows,
        ...recommendationRows
    ];
}

function normalizeCloudflareEvidenceForFlatten(evidence) {
    const output = [];
    for (const item of array(evidence)) {
        const type = String(item?.evidenceType || '').toLowerCase();
        const data = item?.data;
        if (type === 'live_cloudflare_dashboard' && data && typeof data === 'object') {
            output.push(
                { evidenceType: 'accessApps', data: array(data.apps || data.accessApps || data.protectedApps) },
                { evidenceType: 'devices', data: array(data.devices || data.cloudflareDevices) },
                { evidenceType: 'deviceRegistrations', data: array(data.deviceRegistrations || data.registrations) },
                { evidenceType: 'devicePosture', data: array(data.devicePosture || data.postureChecks || data.posture) },
                { evidenceType: 'gatewayRules', data: array(data.gatewayRules || data.gatewayPolicies || data.gateway_policies) },
                { evidenceType: 'accessPolicies', data: array(data.accessPolicies || data.policies) },
                { evidenceType: 'accessLogs', data: array(data.accessLogs || data.logs) },
                { evidenceType: 'dlpProfiles', data: array(data.dlpProfiles || data.dlp_profiles) },
                { evidenceType: 'warpProfiles', data: array(data.warpProfiles || data.warp_profiles) },
                { evidenceType: 'virtualNetworks', data: array(data.virtualNetworks || data.networks) },
                { evidenceType: 'gatewayAppTypes', data: array(data.gatewayAppTypes || data.appCategories) },
                { evidenceType: 'permissionMatrix', data: array(data.permissionMatrix) },
                { evidenceType: 'auditLogs', data: array(data.auditLogs) },
                { evidenceType: 'accountLogs', data: array(data.accountLogs) },
                { evidenceType: 'securityInsights', data: array(data.securityInsights) },
                { evidenceType: 'applicationSecurityReports', data: array(data.applicationSecurityReports) },
                { evidenceType: 'apiGatewayOperations', data: array(data.apiGatewayOperations || data.apiGateway) },
                { evidenceType: 'casbFindings', data: array(data.casbFindings) },
                { evidenceType: 'tunnels', data: array(data.tunnels) },
                { evidenceType: 'cloudforceRequests', data: array(data.cloudforceRequests) },
                { evidenceType: 'intelFeeds', data: array(data.intelFeeds) },
                { evidenceType: 'dnsFirewallRules', data: array(data.dnsFirewallRules) },
                { evidenceType: 'loadBalancerPools', data: array(data.loadBalancerPools) },
                { evidenceType: 'loadBalancerMonitors', data: array(data.loadBalancerMonitors) },
                { evidenceType: 'magicWanSites', data: array(data.magicWanSites) },
                { evidenceType: 'magicWanRoutes', data: array(data.magicWanRoutes) },
                { evidenceType: 'mtlsCertificates', data: array(data.mtlsCertificates) },
                { evidenceType: 'accessGroups', data: array(data.accessGroups) },
                { evidenceType: 'accessOrganizations', data: array(data.accessOrganizations) },
                { evidenceType: 'accessCertificates', data: array(data.accessCertificates) },
                { evidenceType: 'warpConnectors', data: array(data.warpConnectors) },
                { evidenceType: 'teamnetRoutes', data: array(data.teamnetRoutes) },
                { evidenceType: 'teamsDexTests', data: array(data.teamsDexTests) },
                { evidenceType: 'endpointGroups', data: Object.entries(data.endpointGroups || {}).map(([moduleName, families]) => ({ moduleName, families: array(families) })) }
            );
            const sectionRows = Object.entries(data.sections || {})
                .filter(([, section]) => section && typeof section === 'object' && ['error', 'permission_unavailable', 'missing'].includes(String(section.status || '').toLowerCase()))
                .map(([sectionName, section]) => ({ id: sectionName, sectionName, ...section }));
            if (sectionRows.length) output.push({ evidenceType: 'sectionErrors', data: sectionRows });
        } else {
            const aliases = {
                accessapplications: 'accessApps',
                applications: 'accessApps',
                protectedapps: 'accessApps',
                cloudflaredevices: 'devices',
                deviceregistrations: 'deviceRegistrations',
                deviceposture: 'devicePosture',
                posturechecks: 'devicePosture',
                gatewaypolicies: 'gatewayRules',
                gatewayrules: 'gatewayRules',
                accesspolicies: 'accessPolicies',
                accesslogs: 'accessLogs',
                dlpprofiles: 'dlpProfiles',
                warpprofiles: 'warpProfiles',
                virtualnetworks: 'virtualNetworks',
                gatewayapptypes: 'gatewayAppTypes',
                appcategories: 'gatewayAppTypes',
                permissionmatrix: 'permissionMatrix',
                endpointfamilies: 'permissionMatrix',
                auditlogs: 'auditLogs',
                accountlogs: 'accountLogs',
                securityinsights: 'securityInsights',
                applicationsecurityreports: 'applicationSecurityReports',
                apigateway: 'apiGatewayOperations',
                apigatewayoperations: 'apiGatewayOperations',
                casb: 'casbFindings',
                casbfindings: 'casbFindings',
                tunnels: 'tunnels',
                cloudforceone: 'cloudforceRequests',
                cloudforcerequests: 'cloudforceRequests',
                intelfeeds: 'intelFeeds',
                dnsfirewall: 'dnsFirewallRules',
                dnsfirewallrules: 'dnsFirewallRules',
                loadbalancerpools: 'loadBalancerPools',
                loadbalancermonitors: 'loadBalancerMonitors',
                magicwansites: 'magicWanSites',
                magicwanroutes: 'magicWanRoutes',
                mtlscertificates: 'mtlsCertificates',
                accessgroups: 'accessGroups',
                accessorganizations: 'accessOrganizations',
                accesscertificates: 'accessCertificates',
                warpconnectors: 'warpConnectors',
                networkroutes: 'teamnetRoutes',
                teamnetroutes: 'teamnetRoutes',
                teamsdextests: 'teamsDexTests',
                endpointgroups: 'endpointGroups',
                sectionstatus: 'sectionStatus',
                sectionerrors: 'sectionErrors',
                missingcontrols: 'sectionErrors',
                coveragesummaries: 'coverageSummaries',
                evidencecoverage: 'coverageSummaries',
                coverage: 'coverageSummaries'
            };
            const normalizedType = aliases[type.replace(/[_\s-]+/g, '')] || item?.evidenceType;
            output.push({ ...item, evidenceType: normalizedType });
        }
    }
    return output;
}

function compactCloudflareText(value, maximum = 180) {
    return visibleTextOrNull(firstReadableValue(value), maximum);
}

function compactCloudflareEntityData(type, data = {}) {
    const logTimestamp = firstReadableValue(data.timestamp, data.createdAt, data.created_at, data.datetime, data.dateTime, data.when, data.occurredAt);
    const logActor = firstReadableValue(data.userEmail, data.email, data.userPrincipalName, data.actor?.email, data.actor_email, data.actorEmail, data.actor?.id, data.actor);
    const logAction = firstReadableValue(data.action, data.event, data.eventType, data.operation, data.method, data.decision, data.outcome, data.status);
    const logTarget = firstReadableValue(data.resource?.name, data.resourceName, data.target, data.zoneName, data.appName, data.applicationName, data.ipAddress, data.ip, data.host, data.hostname);
    const logName = firstReadableValue(data.entityName, data.title, data.name, [logAction, logActor, logTarget, logTimestamp].filter(Boolean).join(' | '));
    const id = firstReadableValue(data.entityId, data.id, data.uid, data.policyId, data.ruleId, data.profileId, data.deviceId, data.applicationId, data.appId, data.operation_id, data.host, data.hostname, logName);
    const appName = firstReadableValue(data.appName, data.applicationName, data.protectedAppName, data.name, data.displayName, data.domain);
    const deviceName = firstReadableValue(data.deviceName, data.cloudflareDeviceName, data.hostname, data.hostName, data.host, data.name, data.displayName);
    const gatewayRuleName = firstReadableValue(data.gatewayRuleName, data.gatewayPolicyName, data.ruleName, data.policyName, data.name);
    const profileName = firstReadableValue(data.profileName, data.dlpProfileName, data.warpProfileName, data.name);
    const sectionName = firstReadableValue(data.sectionName, data.section, data.controlName, data.endpointFamily, data.permission, data.moduleName, data.module, data.name);
    const infrastructureName = firstReadableValue(data.tunnelName, data.tunnel_name, data.routeName, data.route_name, data.siteName, data.site_name, data.poolName, data.monitorName, data.certificateName, data.hostname, data.host, data.name, data.displayName);
    const findingName = firstReadableValue(data.findingName, data.title, data.summary, data.description, data.insight, data.name, data.displayName);
    const entityName = firstReadableValue(
        data.entityName,
        ['auditLogs', 'accountLogs', 'accessLogs'].includes(type) ? logName : null,
        type === 'accessApps' ? appName : null,
        type === 'devices' ? deviceName : null,
        type === 'gatewayRules' ? gatewayRuleName : null,
        ['dlpProfiles', 'warpProfiles'].includes(type) ? profileName : null,
        ['permissionMatrix', 'endpointGroups', 'sectionStatus', 'sectionErrors'].includes(type) ? sectionName : null,
        type === 'coverageSummaries' ? firstReadableValue(data.entityName, data.name, data.metricName) : null,
        ['securityInsights', 'applicationSecurityReports', 'apiGatewayOperations', 'casbFindings', 'cloudforceRequests', 'intelFeeds', 'dnsFirewallRules', 'teamsDexTests'].includes(type) ? findingName : null,
        ['tunnels', 'loadBalancerPools', 'loadBalancerMonitors', 'magicWanSites', 'magicWanRoutes', 'mtlsCertificates', 'accessGroups', 'accessOrganizations', 'accessCertificates', 'warpConnectors', 'teamnetRoutes', 'virtualNetworks', 'gatewayAppTypes', 'devicePosture'].includes(type) ? infrastructureName : null,
        appName,
        deviceName,
        gatewayRuleName,
        profileName,
        sectionName,
        findingName,
        infrastructureName,
        data.name,
        data.displayName
    );
    const compact = {
        entityId: id || entityName || null,
        entityName: compactCloudflareText(entityName),
        entityType: type === 'accessApps'
            ? 'Application'
            : ['devices', 'deviceRegistrations'].includes(type)
            ? 'Device'
            : ['gatewayRules', 'accessPolicies'].includes(type)
            ? 'Policy'
            : ['dlpProfiles', 'warpProfiles', 'devicePosture'].includes(type)
            ? 'Profile'
            : ['accessLogs', 'auditLogs', 'accountLogs'].includes(type)
            ? 'Log Event'
            : ['permissionMatrix', 'endpointGroups', 'sectionStatus', 'sectionErrors'].includes(type)
            ? 'Control Section'
            : type === 'coverageSummaries'
            ? 'Evidence Coverage'
            : ['securityInsights', 'applicationSecurityReports', 'apiGatewayOperations', 'casbFindings', 'cloudforceRequests', 'intelFeeds', 'dnsFirewallRules', 'teamsDexTests'].includes(type)
            ? 'Security Finding'
            : ['tunnels', 'loadBalancerPools', 'loadBalancerMonitors', 'magicWanSites', 'magicWanRoutes', 'mtlsCertificates', 'accessGroups', 'accessOrganizations', 'accessCertificates', 'warpConnectors', 'teamnetRoutes', 'virtualNetworks', 'gatewayAppTypes', 'devicePosture'].includes(type)
            ? 'Infrastructure'
            : 'Cloudflare Entity',
        appName: compactCloudflareText(appName || data.applicationName),
        policyName: compactCloudflareText(data.policyName || data.accessPolicyName || data.gatewayPolicyName || gatewayRuleName),
        deviceName: compactCloudflareText(deviceName),
        gatewayRuleName: compactCloudflareText(gatewayRuleName),
        profileName: compactCloudflareText(profileName),
        status: compactCloudflareText(data.status || data.action || data.decision || data.outcome || data.result || data.health),
        action: compactCloudflareText(logAction),
        userEmail: compactCloudflareText(logActor),
        ipAddress: compactCloudflareText(data.ipAddress || data.ip || data.clientIp || data.sourceIp),
        timestamp: compactCloudflareText(logTimestamp),
        target: compactCloudflareText(logTarget),
        severity: compactCloudflareText(data.severity || data.risk || data.priority || data.confidence),
        moduleName: compactCloudflareText(data.moduleName || data.module),
        endpointFamily: compactCloudflareText(data.endpointFamily || data.permission),
        recordCount: numberOrNull(data.recordCount ?? data.count ?? data.total),
        riskReason: compactCloudflareText(data.riskReason || data.reason || data.error || data.message || data.description || data.summary, 320),
        recommendation: compactCloudflareText(data.recommendation || data.remediation || data.suggestedAction, 320),
        sourceMetric: data.sourceMetric || DOMAIN_EVIDENCE_CATEGORY_METRICS.cloudflare_network_security[type] || type
    };
    if (type === 'accessLogs') {
        compact.action = compactCloudflareText(data.action || data.decision || data.outcome);
        compact.userEmail = compactCloudflareText(data.userEmail || data.email || data.userPrincipalName);
        compact.timestamp = compactCloudflareText(data.timestamp || data.createdAt || data.datetime || data.dateTime);
    }
    if (type === 'sectionErrors') {
        compact.sectionName = compactCloudflareText(sectionName);
        compact.errorCode = compactCloudflareText(data.errorCode || data.code);
    }
    return compactNonEmptyObject(compact);
}

function cloudflareEvidenceRows(flattenedEvidence, current = {}) {
    const typeByLower = new Map(CLOUDFLARE_COMPACT_EVIDENCE_TYPES.map(type => [type.toLowerCase(), type]));
    const grouped = new Map(CLOUDFLARE_COMPACT_EVIDENCE_TYPES.map(type => [type, []]));
    const categoryLimit = type => type === 'coverageSummaries'
        ? 20
        : ['permissionMatrix', 'endpointGroups', 'sectionStatus', 'sectionErrors'].includes(type)
        ? 30
        : (['accessLogs', 'auditLogs', 'accountLogs'].includes(type) ? 12 : 8);
    const rows = array(flattenedEvidence);
    for (const row of rows) {
        const evidenceType = String(row.evidenceType || row.sourceLabel || row.evidenceCategory || '').replace(/[_\s-]+/g, '').toLowerCase();
        const type = typeByLower.get(evidenceType) || typeByLower.get(String(row.sourceLabel || '').replace(/[_\s-]+/g, '').toLowerCase());
        if (!type || grouped.get(type).length >= categoryLimit(type)) continue;
        const data = compactCloudflareEntityData(type, row.data || {});
        if (!data.entityName && !data.entityId) continue;
        grouped.get(type).push({
            internalSourcePath: row.internalSourcePath || null,
            sourceLabel: type,
            evidenceType: type,
            evidenceCategory: type,
            sourceMetric: data.sourceMetric || row.sourceMetric || DOMAIN_EVIDENCE_CATEGORY_METRICS.cloudflare_network_security[type] || type,
            entityKey: data.entityId || data.entityName,
            data
        });
    }

    appendCloudflareCoverageRows(grouped, current);

    const compactRows = CLOUDFLARE_COMPACT_EVIDENCE_TYPES.flatMap(type => grouped.get(type));
    return compactRows.length ? compactRows : [];
}

function appendCloudflareCoverageRows(grouped, current = {}) {
    const metricSource = {
        ...(current.sourceMetrics || {}),
        ...(current.dashboardMetrics || {}),
        ...(current.metrics || {}),
        ...(current.calculatedIndicators || {})
    };
    const countFor = (...keys) => {
        for (const key of keys) {
            const value = numberOrNull(metricSource[key]);
            if (value != null) return value;
        }
        return null;
    };
    const rowCount = type => grouped.get(type)?.length || 0;
    const coverageDefinitions = [
        { type: 'auditLogs', metricKeys: ['auditLogs'], sourceMetric: 'auditLogs', entityName: 'Cloudflare audit log coverage', severity: 'medium', expectedLabel: 'audit log event(s)' },
        { type: 'accountLogs', metricKeys: ['accountLogs'], sourceMetric: 'accountLogs', entityName: 'Cloudflare account log coverage', severity: 'medium', expectedLabel: 'account log event(s)' },
        { type: 'accessLogs', metricKeys: ['accessLogCount', 'recentAccessEvents'], sourceMetric: 'accessLogCount', entityName: 'Cloudflare access log coverage', severity: 'medium', expectedLabel: 'access log event(s)' },
        { type: 'permissionMatrix', metricKeys: ['endpointFamilies'], sourceMetric: 'endpointFamilies', entityName: 'Cloudflare API permission family coverage', severity: 'high', expectedLabel: 'endpoint/API family row(s)' },
        { type: 'gatewayAppTypes', metricKeys: ['appCategories'], sourceMetric: 'appCategories', entityName: 'Cloudflare Gateway app catalog coverage', severity: 'low', expectedLabel: 'Gateway app categorisation row(s)' },
        { type: 'securityInsights', metricKeys: ['securityInsights'], sourceMetric: 'securityInsights', entityName: 'Cloudflare security insight coverage', severity: 'medium', expectedLabel: 'security insight row(s)' },
        { type: 'apiGatewayOperations', metricKeys: ['apiGatewayOperations'], sourceMetric: 'apiGatewayOperations', entityName: 'Cloudflare API Gateway operation coverage', severity: 'medium', expectedLabel: 'API Gateway operation row(s)' },
        { type: 'casbFindings', metricKeys: ['casbFindings'], sourceMetric: 'casbFindings', entityName: 'Cloudflare CASB finding coverage', severity: 'medium', expectedLabel: 'CASB finding row(s)' },
        { type: 'tunnels', metricKeys: ['tunnels'], sourceMetric: 'tunnels', entityName: 'Cloudflare tunnel coverage', severity: 'low', expectedLabel: 'tunnel row(s)' }
    ];
    const coverageRows = grouped.get('coverageSummaries');
    if (!coverageRows) return;
    for (const definition of coverageDefinitions) {
        const expected = countFor(...definition.metricKeys);
        if (!expected || expected <= 0) continue;
        const included = rowCount(definition.type);
        if (included >= expected) continue;
        const coverageStatus = included > 0 ? 'sampled_compact_rows' : 'count_only_no_raw_rows';
        const sourceMetric = definition.sourceMetric;
        const entityId = 'cloudflare-coverage-' + sourceMetric;
        const data = compactCloudflareEntityData('coverageSummaries', {
            entityId,
            entityName: definition.entityName,
            sourceMetric,
            status: coverageStatus,
            severity: definition.severity,
            recordCount: expected,
            count: expected,
            total: expected,
            metricName: sourceMetric,
            riskReason: included > 0
                ? 'StackCTRL reports ' + expected + ' ' + definition.expectedLabel + '; ' + included + ' compact row(s) were included for Azure analysis to avoid overloading the model.'
                : 'StackCTRL reports ' + expected + ' ' + definition.expectedLabel + ', but no raw ' + definition.type + ' evidence rows were available in the prepared package. Treat this as a confirmed coverage count and a raw-evidence gap; do not infer individual event details.',
            recommendation: included > 0
                ? 'Use the included compact samples for pattern context and use the metric count for scale; request raw evidence only for forensic review.'
                : 'Refresh or inspect the StackCTRL Cloudflare collection for this evidence family before making event-level conclusions.'
        });
        coverageRows.push({
            internalSourcePath: 'cloudflare_network_security.coverage.' + sourceMetric,
            sourceLabel: 'coverageSummaries',
            evidenceType: 'coverageSummaries',
            evidenceCategory: 'coverageSummaries',
            sourceMetric,
            entityKey: entityId,
            data: {
                ...data,
                expectedRows: expected,
                includedRows: included,
                missingRows: Math.max(0, expected - included),
                coverageStatus,
                coveredEvidenceType: definition.type
            }
        });
    }
}

function storageGb(value = {}) {
    return numberOrNull(
        value.totalStorageGB ?? value.storageGB ?? value.storageUsedGB ?? value.usedStorageGB ??
        value.oneDriveStorageGB ?? value.sharePointStorageGB ?? value.exchangeStorageGB ?? value.storage
    ) || 0;
}

function compactBackupUser(row, category, index) {
    const data = row?.data || row || {};
    const email = firstReadableValue(data.userPrincipalName, data.email, data.mail, data.userEmail, data.ownerEmail);
    const name = firstReadableValue(data.displayName, data.userDisplayName, data.entityName, data.name, email);
    const totalStorageGB = storageGb(data) ||
        (numberOrNull(data.oneDriveStorageGB) || 0) + (numberOrNull(data.exchangeStorageGB) || 0) + (numberOrNull(data.sharePointStorageGB) || 0);
    return {
        internalSourcePath: row?.internalSourcePath || `backup.compact.${category}[${index}]`,
        sourceLabel: category,
        evidenceType: category,
        evidenceCategory: category,
        sourceMetric: category === 'topStorageUsers' ? 'totalStorageGB'
            : category === 'inactiveDataHolders' ? 'inactiveUsersCount'
            : 'staleActivityUsers',
        entityKey: data.id || data.userId || email || name || `${category}-${index + 1}`,
        data: compactNonEmptyObject({
            entityId: data.id || data.userId || email || name,
            entityName: compactCloudflareText(name),
            entityType: 'User',
            emailAddress: compactCloudflareText(email),
            totalStorageGB: numberOrNull(totalStorageGB),
            oneDriveStorageGB: numberOrNull(data.oneDriveStorageGB),
            exchangeStorageGB: numberOrNull(data.exchangeStorageGB),
            sharePointStorageGB: numberOrNull(data.sharePointStorageGB),
            accountStatus: compactCloudflareText(data.accountStatus || (data.accountEnabled === false ? 'disabled' : data.accountEnabled === true ? 'enabled' : null)),
            lastActivityDate: compactCloudflareText(data.lastActivityDate || data.lastSignInDateTime || data.lastActivity),
            daysSinceActivity: numberOrNull(data.daysSinceActivity ?? data.daysInactive ?? data.inactiveDays),
            businessReason: category === 'inactiveDataHolders'
                ? 'Inactive account holds recoverable Microsoft 365 data exposure.'
                : category === 'staleActivityUsers'
                ? 'User activity appears stale while data remains in scope for recovery planning.'
                : 'Large data holder increases backup and recovery exposure.',
            recommendation: category === 'topStorageUsers'
                ? 'Confirm backup coverage and recovery objectives for this large data holder.'
                : 'Review retention, ownership, licensing, and backup requirements.'
        })
    };
}

function compactBackupSite(row, index) {
    const data = row?.data || row || {};
    const name = firstReadableValue(data.siteName, data.displayName, data.name, data.webUrl, data.url);
    return {
        internalSourcePath: row?.internalSourcePath || `backup.compact.topSharePointSites[${index}]`,
        sourceLabel: 'topSharePointSites',
        evidenceType: 'topSharePointSites',
        evidenceCategory: 'topSharePointSites',
        sourceMetric: 'sharePointStorageGB',
        entityKey: data.id || data.siteId || name || `site-${index + 1}`,
        data: compactNonEmptyObject({
            entityId: data.id || data.siteId || name,
            entityName: compactCloudflareText(name),
            entityType: 'SharePoint Site',
            siteUrl: compactCloudflareText(data.webUrl || data.url, 260),
            storageGB: numberOrNull(data.storageGB ?? data.storageUsedGB ?? data.sharePointStorageGB),
            lastActivityDate: compactCloudflareText(data.lastActivityDate || data.lastModifiedDateTime),
            businessReason: 'SharePoint site contributes to service-level backup exposure.',
            recommendation: 'Confirm site ownership, retention, and backup/recovery coverage.'
        })
    };
}

function compactBackupEvidenceRows(flattenedEvidence, current = {}) {
    const rows = array(flattenedEvidence);
    const userRows = rows.filter(row => /users|onedrive|exchange|mailbox/i.test(String(row.evidenceType || row.sourceLabel || '')));
    const siteRows = rows.filter(row => /sites|sharepoint/i.test(String(row.evidenceType || row.sourceLabel || '')));
    const recommendations = rows.filter(row => /recommend/i.test(String(row.evidenceType || row.sourceLabel || ''))).slice(0, 5);
    const activeLike = userRows.map(row => ({ row, storage: storageGb(row.data || row), days: numberOrNull(row.data?.daysSinceActivity ?? row.data?.daysInactive ?? row.data?.inactiveDays) }));
    const topStorageUsers = activeLike
        .filter(item => item.storage > 0)
        .sort((a, b) => b.storage - a.storage)
        .slice(0, 10)
        .map((item, index) => compactBackupUser(item.row, 'topStorageUsers', index));
    const inactiveDataHolders = activeLike
        .filter(item => item.storage > 0 && (/inactive|disabled/i.test(String(item.row.data?.status || item.row.data?.accountStatus || '')) || item.row.data?.accountEnabled === false || item.days >= 30))
        .slice(0, 10)
        .map((item, index) => compactBackupUser(item.row, 'inactiveDataHolders', index));
    const staleActivityUsers = activeLike
        .filter(item => item.days >= 30)
        .slice(0, 10)
        .map((item, index) => compactBackupUser(item.row, 'staleActivityUsers', index));
    const topSharePointSites = siteRows
        .slice()
        .sort((a, b) => storageGb(b.data || b) - storageGb(a.data || a))
        .slice(0, 10)
        .map((row, index) => compactBackupSite(row, index));
    const metrics = { ...(current.metrics || {}), ...(current.dashboardMetrics || {}) };
    const hasServiceStorageMetric = [
        'totalStorageGB', 'oneDriveStorageGB', 'sharePointStorageGB', 'exchangeStorageGB',
        'activeUsersCount', 'inactiveUsersCount', 'servicesCovered', 'backupCoverageScore',
        'exposureRiskScore', 'dataExposureRiskScore'
    ].some(name => numberOrNull(metrics[name]) !== null);
    const serviceStorageSummary = hasServiceStorageMetric ? {
        internalSourcePath: 'backup.compact.serviceStorageSummary',
        sourceLabel: 'serviceStorageSummary',
        evidenceType: 'serviceStorageSummary',
        evidenceCategory: 'serviceStorageSummary',
        sourceMetric: 'totalStorageGB',
        entityKey: 'serviceStorageSummary',
        data: compactNonEmptyObject({
            totalStorageGB: numberOrNull(metrics.totalStorageGB),
            oneDriveStorageGB: numberOrNull(metrics.oneDriveStorageGB),
            sharePointStorageGB: numberOrNull(metrics.sharePointStorageGB),
            exchangeStorageGB: numberOrNull(metrics.exchangeStorageGB),
            activeUsersCount: numberOrNull(metrics.activeUsersCount),
            inactiveUsersCount: numberOrNull(metrics.inactiveUsersCount),
            servicesCovered: numberOrNull(metrics.servicesCovered),
            backupCoverageScore: numberOrNull(metrics.backupCoverageScore),
            exposureRiskScore: numberOrNull(metrics.exposureRiskScore ?? metrics.dataExposureRiskScore),
            contextOnly: true,
            businessReason: 'Service storage totals summarize backup exposure context.',
            recommendation: 'Use service-level exposure to prioritize backup coverage and restore testing.'
        })
    } : null;
    const backupMetric = [
        ['backupCoverageScore', 'Backup coverage score'],
        ['servicesCovered', 'Services covered'],
        ['totalStorageGB', 'Total storage'],
        ['inactiveUsersCount', 'Inactive users']
    ].map(([name, label]) => ({ name, label, value: numberOrNull(metrics[name]) }))
        .find(metric => metric.value !== null) || null;
    const backupCoverageGaps = backupMetric ? [{
        internalSourcePath: 'backup.compact.backupCoverageGaps',
        sourceLabel: 'backupCoverageGaps',
        evidenceType: 'backupCoverageGaps',
        evidenceCategory: 'backupCoverageGaps',
        sourceMetric: backupMetric.name,
        entityKey: 'backup-metric-' + backupMetric.name,
        data: compactNonEmptyObject({
            entityId: 'backup-metric-' + backupMetric.name,
            entityName: backupMetric.label,
            entityType: 'SourceMetric',
            metricName: backupMetric.name,
            value: backupMetric.value,
            backupCoverageScore: numberOrNull(metrics.backupCoverageScore),
            servicesCovered: numberOrNull(metrics.servicesCovered),
            externalBackupConfigured: metrics.externalBackupConfigured ?? metrics.backupConfigured ?? null,
            restoreTestingStatus: metrics.restoreTestingStatus,
            immutabilityStatus: metrics.immutabilityStatus,
            recommendationsCount: numberOrNull(metrics.recommendationsCount),
            businessReason: 'Backup coverage controls are assessed at service level, not as individual mail/file events.',
            recommendation: 'Validate external backup coverage, retention, immutability, and restore testing.'
        })
    }] : [];
    const compactRecommendations = recommendations.map((row, index) => ({
        internalSourcePath: row.internalSourcePath || `backup.compact.recommendations[${index}]`,
        sourceLabel: 'recommendations',
        evidenceType: 'recommendations',
        evidenceCategory: 'recommendations',
        sourceMetric: 'recommendationsCount',
        entityKey: row.entityKey || row.data?.id || row.data?.title || `backup-recommendation-${index + 1}`,
        data: safeEvidenceEntity(row.data || row, { maxDepth: 2, maxArray: 5, maxString: 300, maxObjectKeys: 12 })
    }));
    return [
        ...topStorageUsers,
        ...inactiveDataHolders,
        ...staleActivityUsers,
        ...topSharePointSites,
        ...(serviceStorageSummary ? [serviceStorageSummary] : []),
        ...backupCoverageGaps,
        ...compactRecommendations.slice(0, 5)
    ];
}

function compactApplicationData(row, category, index) {
    const data = row?.data || row || {};
    const appName = firstReadableValue(data.appName, data.applicationName, data.displayName, data.name, data.entityName);
    const publisherName = firstReadableValue(data.publisherName, data.publisher, data.verifiedPublisher?.displayName, data.verifiedPublisherName);
    return {
        internalSourcePath: row?.internalSourcePath || `applications.compact.${category}[${index}]`,
        sourceLabel: category,
        evidenceType: category,
        evidenceCategory: category,
        sourceMetric: category,
        entityKey: data.id || data.appId || data.applicationId || appName || `${category}-${index + 1}`,
        data: compactNonEmptyObject({
            entityId: data.id || data.appId || data.applicationId || appName,
            entityName: compactCloudflareText(appName),
            entityType: 'Application',
            applicationName: compactCloudflareText(appName),
            publisherName: compactCloudflareText(publisherName),
            permissionSummary: compactCloudflareText(data.permissionSummary || data.permissions || data.scopes, 320),
            riskLevel: compactCloudflareText(data.riskLevel || data.risk),
            status: compactCloudflareText(data.status || data.reviewStatus),
            assignedUserCount: numberOrNull(data.assignedUserCount ?? data.userCount),
            assignedGroupCount: numberOrNull(data.assignedGroupCount ?? data.groupCount),
            lastReviewedAt: compactCloudflareText(data.lastReviewedAt || data.lastReviewDate || data.lastSignInDateTime),
            businessReason: category === 'externalApps'
                ? 'External publisher or unverified application increases consent and vendor exposure.'
                : category === 'excessivePermissionApps'
                ? 'Broad permissions can create excessive tenant access.'
                : category === 'groupAssignedApps'
                ? 'Group assignment can expand application access scope.'
                : category === 'staleOrUnreviewedApps'
                ? 'Application appears stale or lacks recent ownership review.'
                : 'Application is highlighted by StackCTRL application governance evidence.',
            recommendation: 'Review ownership, publisher trust, permissions, assignments, and ongoing business need.'
        })
    };
}

function compactApplicationsEvidenceRows(flattenedEvidence) {
    const rows = array(flattenedEvidence).filter(row => /applications|apps|serviceprincipals|recommend/i.test(String(row.evidenceType || row.sourceLabel || '')));
    const appRows = rows.filter(row => !/recommend/i.test(String(row.evidenceType || row.sourceLabel || '')));
    const recommendations = rows.filter(row => /recommend/i.test(String(row.evidenceType || row.sourceLabel || ''))).slice(0, 5);
    const category = predicate => appRows.filter(row => predicate(row.data || row)).slice(0, 10);
    const highRiskApps = category(data => /high|critical/i.test(String(data.riskLevel || data.risk || data.severity || '')) || data.highRisk === true)
        .map((row, index) => compactApplicationData(row, 'highRiskApps', index));
    const externalApps = category(data => data.isExternal === true || /external|unknown|unverified/i.test(String(data.publisherType || data.publisherName || data.publisher || data.verifiedPublisherName || '')))
        .map((row, index) => compactApplicationData(row, 'externalApps', index));
    const excessivePermissionApps = category(data => data.excessivePermissions === true || /excessive|adminconsent|directory\.|mail\.|files\.|full_access|readwrite/i.test(String(data.permissionSummary || data.permissions || data.scopes || '')))
        .map((row, index) => compactApplicationData(row, 'excessivePermissionApps', index));
    const highAccessApps = category(data => data.highAccess === true || Number(data.assignedUserCount || data.userCount || 0) > 25 || Number(data.assignedGroupCount || data.groupCount || 0) > 0)
        .map((row, index) => compactApplicationData(row, 'highAccessApps', index));
    const groupAssignedApps = category(data => Number(data.assignedGroupCount || data.groupCount || 0) > 0 || data.groupAssigned === true)
        .map((row, index) => compactApplicationData(row, 'groupAssignedApps', index));
    const staleOrUnreviewedApps = category(data => data.isStale === true || data.unreviewed === true || /stale|unreviewed|unknown/i.test(String(data.reviewStatus || data.status || data.lastReviewedAt || '')))
        .map((row, index) => compactApplicationData(row, 'staleOrUnreviewedApps', index));
    const compactRecommendations = recommendations.map((row, index) => ({
        internalSourcePath: row.internalSourcePath || `applications.compact.recommendations[${index}]`,
        sourceLabel: 'recommendations',
        evidenceType: 'recommendations',
        evidenceCategory: 'recommendations',
        sourceMetric: 'recommendationsCount',
        entityKey: row.entityKey || row.data?.id || row.data?.title || `application-recommendation-${index + 1}`,
        data: safeEvidenceEntity(row.data || row, { maxDepth: 2, maxArray: 5, maxString: 300, maxObjectKeys: 12 })
    }));
    const fallback = appRows.slice(0, 10).map((row, index) => compactApplicationData(row, 'highRiskApps', index));
    const compactRows = [
        ...highRiskApps,
        ...externalApps,
        ...excessivePermissionApps,
        ...highAccessApps,
        ...groupAssignedApps,
        ...staleOrUnreviewedApps,
        ...compactRecommendations
    ];
    return compactRows.length ? compactRows : fallback;
}

function governanceStatusRank(value) {
    const text = String(value || '').toLowerCase();

    if (/critical|failed|fail|overdue|attention|required|missing|blocked/.test(text)) return 5;
    if (/high|risk|partial|warning|review/.test(text)) return 4;
    if (/medium|manual|unknown|not verified/.test(text)) return 3;
    if (/connected|passed|complete|healthy|ok|good/.test(text)) return 1;

    return 2;
}

function compactGovernanceEvidenceRows(flattenedEvidence = [], current = {}) {
    const rows = array(flattenedEvidence)
        .filter(row => /governance|review|owner|policy|risk|control|evidence/i.test(
            String(row.evidenceType || row.sourceLabel || row.evidenceCategory || '')
        ));

    const metrics = { ...(current?.metrics || {}), ...(current?.dashboardMetrics || {}) };
    const sourceLineage = current?.source?.sourceLineage || current?.sourceLineage || {};

    const normalizedRows = rows.map((row, index) => {
        const data = row?.data || row || {};

        const area = firstReadableValue(
            data.area,
            data.controlArea,
            data.category,
            data.domain,
            data.group
        ) || 'Governance';

        const activity = firstReadableValue(
            data.activity,
            data.title,
            data.name,
            data.controlName,
            data.requirement
        ) || 'Governance review item';

        const status = firstReadableValue(
            data.status,
            data.state,
            data.result,
            data.validationStatus
        ) || 'unknown';

        const owner = firstReadableValue(
            data.owner,
            data.assignedTo,
            data.responsibleOwner,
            data.ownerName,
            data.ownerEmail
        );

        const source = firstReadableValue(
            data.dataSource,
            data.source,
            data.sourceSystem,
            data.system
        ) || 'StackCTRL evidence';

        const entityName = firstReadableValue(
            data.entityName,
            data.displayName,
            data.name,
            data.userPrincipalName,
            data.deviceName,
            data.appName,
            activity
        );

        const entityId = firstReadableValue(
            data.entityId,
            data.id,
            data.sourceId,
            data.controlId,
            data.policyId,
            data.userPrincipalName,
            data.deviceId,
            data.appId,
            entityName
        );

        const entityType = firstReadableValue(
            data.entityType,
            data.type,
            data.recordType
        ) || 'GovernanceItem';

        const rank = governanceStatusRank(status);

        return {
            row,
            rank,
            compact: {
                internalSourcePath: row?.internalSourcePath || `governance.compact.governanceRows[${index}]`,
                sourceLabel: 'governanceRows',
                evidenceType: 'governanceRows',
                evidenceCategory: 'governanceRows',
                sourceMetric: rank >= 4 ? 'attentionRequiredRows' : 'connectedRows',
                entityKey: entityId || `governance-row-${index + 1}`,
                data: compactNonEmptyObject({
                    entityId: entityId || `governance-row-${index + 1}`,
                    entityName,
                    entityType,
                    area,
                    activity,
                    status,
                    owner,
                    source,
                    ownerStatus: owner ? 'assigned' : 'missing_or_not_supplied',
                    governanceIssue: rank >= 4
                        ? `${area} requires management review: ${activity}`
                        : `${area} governance evidence is available for review.`,
                    businessReason: rank >= 4
                        ? 'Governance item is marked attention-required, failed, blocked, overdue, partial, or missing ownership.'
                        : 'Governance evidence supports the current management/control posture.',
                    managementAction: rank >= 4
                        ? 'Assign an owner, review the evidence, document the decision, and track remediation.'
                        : 'Maintain evidence and include in the next governance review cycle.',
                    dueDateRecommendation: rank >= 4 ? 'within 14 days' : 'next review cycle',
                    sourceMetric: rank >= 4 ? 'attentionRequiredRows' : 'connectedRows',
                    evidenceReference: row?.entityKey || entityId || row?.internalSourcePath || null,
                    rawStatus: status
                })
            }
        };
    });

    const attentionRequired = normalizedRows
        .filter(item => item.rank >= 4)
        .sort((a, b) => b.rank - a.rank)
        .slice(0, 20)
        .map(item => ({
            ...item.compact,
            evidenceType: 'attentionRequiredGovernance',
            evidenceCategory: 'attentionRequiredGovernance',
            sourceLabel: 'attentionRequiredGovernance',
            sourceMetric: 'attentionRequiredRows'
        }));

    const ownershipGaps = normalizedRows
        .filter(item => /missing_or_not_supplied/i.test(String(item.compact.data.ownerStatus || '')))
        .slice(0, 15)
        .map(item => ({
            ...item.compact,
            evidenceType: 'riskOwnershipGaps',
            evidenceCategory: 'riskOwnershipGaps',
            sourceLabel: 'riskOwnershipGaps',
            sourceMetric: 'ownerMissingCount',
            data: {
                ...item.compact.data,
                governanceIssue: 'Governance evidence does not show a responsible owner.',
                managementAction: 'Assign accountable owner and document responsibility.'
            }
        }));

    const reviewItems = normalizedRows
        .filter(item => /review|policy|access|admin|control/i.test(
            `${item.compact.data.area} ${item.compact.data.activity}`
        ))
        .slice(0, 15)
        .map(item => ({
            ...item.compact,
            evidenceType: 'reviewGaps',
            evidenceCategory: 'reviewGaps',
            sourceLabel: 'reviewGaps',
            sourceMetric: item.rank >= 4 ? 'attentionRequiredRows' : 'connectedRows'
        }));

    const connectedEvidence = normalizedRows
        .filter(item => item.rank <= 2)
        .slice(0, 10)
        .map(item => ({
            ...item.compact,
            evidenceType: 'connectedGovernanceEvidence',
            evidenceCategory: 'connectedGovernanceEvidence',
            sourceLabel: 'connectedGovernanceEvidence',
            sourceMetric: 'connectedRows'
        }));

    const governanceMetric = [
        ['governanceScore', 'Governance score'],
        ['totalRows', 'Total governance rows'],
        ['attentionRequiredRows', 'Attention-required rows'],
        ['ownerMissingCount', 'Owner-missing rows'],
        ['connectedRows', 'Connected rows']
    ].map(([name, label]) => ({ name, label, value: numberOrNull(metrics[name]) }))
        .find(metric => metric.value !== null) || null;
    const summaryRow = governanceMetric ? {
        internalSourcePath: 'governance.compact.summaryMetrics',
        sourceLabel: 'summaryMetrics',
        evidenceType: 'summaryMetrics',
        evidenceCategory: 'summaryMetrics',
        sourceMetric: governanceMetric.name,
        entityKey: 'governance-metric-' + governanceMetric.name,
        data: compactNonEmptyObject({
            entityId: 'governance-metric-' + governanceMetric.name,
            entityName: governanceMetric.label,
            entityType: 'SourceMetric',
            metricName: governanceMetric.name,
            value: governanceMetric.value,
            totalRows: numberOrNull(metrics.totalRows),
            apiConnectedRows: numberOrNull(metrics.apiConnectedRows),
            manualRowsExcluded: numberOrNull(metrics.manualRowsExcluded),
            attentionRequiredRows: numberOrNull(metrics.attentionRequiredRows),
            connectedRows: numberOrNull(metrics.connectedRows),
            ownerMissingCount: numberOrNull(metrics.ownerMissingCount),
            governanceScore: numberOrNull(metrics.governanceScore),
            stackctrlRiskScore: numberOrNull(metrics.stackctrlRiskScore),
            stackctrlHealthScore: numberOrNull(metrics.stackctrlHealthScore),
            evidenceSnapshotId: sourceLineage.evidenceSnapshotId || null,
            sourceFetchedAt: sourceLineage.sourceFetchedAt || sourceLineage.sourceLastUpdated || null,
            collectionStatus: sourceLineage.collectionStatus || null,
            governanceIssue: 'Governance summary provides management/accountability context across API-connected evidence.',
            managementAction: 'Use detailed findings to assign owners, schedule reviews, and record management decisions.'
        })
    } : null;

    const compactRows = [
        ...(summaryRow ? [summaryRow] : []),
        ...attentionRequired,
        ...ownershipGaps,
        ...reviewItems,
        ...connectedEvidence
    ];

    return compactRows.length
        ? compactRows
        : normalizedRows.slice(0, 25).map(item => item.compact);
}

function complianceStatusFromControl(value = {}, fallbackStatus = null) {
    const text = [
        value.status,
        value.insight,
        value.result,
        value.validationStatus,
        value.state,
        fallbackStatus
    ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();

    if (/🔴|critical|failed|fail|failing|non.?compliant|not met|attention|required|blocked|overdue|open/.test(text)) {
        return 'failed';
    }

    if (/🟡|partial|warning|review|needs follow.?up|needs review|in progress|unknown|insufficient/.test(text)) {
        return 'partial';
    }

    if (/🟢|passing|passed|pass|compliant|met|healthy|ok|complete|connected/.test(text)) {
        return 'passed';
    }

    if (/manual|attestation|not verified|not supplied|missing evidence/.test(text)) {
        return 'manual_review_required';
    }

    return 'manual_review_required';
}

function complianceSeverityForStatus(status) {
    if (status === 'failed') return 'high';
    if (status === 'partial') return 'medium';
    if (status === 'manual_review_required') return 'medium';
    return 'low';
}

function complianceMetricForStatus(status) {
    if (status === 'failed') return 'failingControls';
    if (status === 'partial') return 'partialControls';
    if (status === 'passed') return 'passingControls';
    return 'manualReviewControls';
}

function compactComplianceEvidenceRows(flattenedEvidence = [], current = {}) {
    const rows = array(flattenedEvidence)
        .filter(row => /compliance|control|validation|evidence|policy|mfa|device|backup|identity|security|application/i.test(
            String(row.evidenceType || row.sourceLabel || row.evidenceCategory || '')
        ));

    const metrics = { ...(current?.metrics || {}), ...(current?.dashboardMetrics || {}) };
    const sourceLineage = current?.source?.sourceLineage || current?.sourceLineage || {};

    const normalizedRows = rows.map((row, index) => {
        const data = row?.data || row || {};

        const controlName = firstReadableValue(
            data.controlName,
            data.name,
            data.title,
            data.requirement,
            data.activity,
            data.policyName
        ) || 'Compliance control';

        const controlCategory = firstReadableValue(
            data.controlCategory,
            data.area,
            data.category,
            data.domain,
            data.group
        ) || 'Compliance';

        const rawStatus = firstReadableValue(
            data.status,
            data.insight,
            data.result,
            data.validationStatus,
            data.state
        ) || 'unknown';

        const status = firstReadableValue(data.complianceStatus) || complianceStatusFromControl(data, rawStatus);

        const controlId = firstReadableValue(
            data.controlId,
            data.id,
            data.sourceId,
            data.policyId,
            data.requirementId,
            `${controlCategory}:${controlName}`
        );

        const evidenceSource = firstReadableValue(
            data.evidenceSource,
            data.dataSource,
            data.source,
            data.sourceSystem,
            data.system
        ) || 'StackCTRL compliance evidence';

        const owner = firstReadableValue(
            data.owner,
            data.assignedTo,
            data.responsibleOwner,
            data.ownerName,
            data.ownerEmail
        );

        const severity = firstReadableValue(data.severity) || complianceSeverityForStatus(status);
        const sourceMetric = complianceMetricForStatus(status);

        const validationReason = firstReadableValue(
            data.validationReason,
            data.reason,
            data.description,
            data.detail
        ) || (
            status === 'failed'
                ? `${controlName} is failing based on API-connected StackCTRL compliance evidence.`
                : status === 'partial'
                ? `${controlName} is partially satisfied and requires follow-up validation.`
                : status === 'passed'
                ? `${controlName} has API-connected evidence supporting a passing status.`
                : `${controlName} requires manual review because evidence is incomplete, unknown, or not fully API-validated.`
        );

        const remediationAction = firstReadableValue(
            data.remediationAction,
            data.recommendation,
            data.recommendedAction,
            data.managementAction
        ) || (
            status === 'failed'
                ? 'Remediate the failed control, collect evidence, and confirm closure.'
                : status === 'partial'
                ? 'Review the partial control, close evidence gaps, and confirm final status.'
                : status === 'passed'
                ? 'Maintain evidence and validate during the next compliance review cycle.'
                : 'Assign an owner and complete manual evidence validation.'
        );

        const auditImpact = firstReadableValue(
            data.auditImpact,
            data.businessImpact,
            data.impact
        ) || (
            status === 'failed'
                ? 'Failed controls can reduce audit readiness and increase compliance exposure.'
                : status === 'partial'
                ? 'Partial controls may require auditor explanation and remediation evidence.'
                : status === 'passed'
                ? 'Passing controls support audit readiness.'
                : 'Manual review controls require supporting evidence before audit reliance.'
        );

        const compact = {
            internalSourcePath: row?.internalSourcePath || `compliance.compact.controls[${index}]`,
            sourceLabel: 'controls',
            evidenceType: 'controls',
            evidenceCategory: 'controls',
            sourceMetric,
            entityKey: controlId || `compliance-control-${index + 1}`,
            data: compactNonEmptyObject({
                entityId: controlId || `compliance-control-${index + 1}`,
                entityName: controlName,
                entityType: 'ComplianceControl',
                controlId,
                controlName,
                controlCategory,
                status,
                rawStatus,
                severity,
                owner,
                ownerStatus: owner ? 'assigned' : 'missing_or_not_supplied',
                evidenceSource,
                validationReason,
                remediationAction,
                auditImpact,
                dueDateRecommendation: status === 'failed'
                    ? 'within 14 days'
                    : status === 'partial' || status === 'manual_review_required'
                    ? 'within 30 days'
                    : 'next review cycle',
                businessReason: status === 'passed'
                    ? 'Control has supporting API-connected evidence.'
                    : 'Control requires compliance management attention based on API-connected evidence.',
                sourceMetric,
                evidenceReference: row?.entityKey || controlId || row?.internalSourcePath || null
            })
        };

        return {
            row,
            status,
            compact
        };
    });

    const failedControls = normalizedRows
        .filter(item => item.status === 'failed')
        .slice(0, 20)
        .map(item => ({
            ...item.compact,
            evidenceType: 'failedControls',
            evidenceCategory: 'failedControls',
            sourceLabel: 'failedControls',
            sourceMetric: 'failingControls'
        }));

    const partialControls = normalizedRows
        .filter(item => item.status === 'partial')
        .slice(0, 20)
        .map(item => ({
            ...item.compact,
            evidenceType: 'partialControls',
            evidenceCategory: 'partialControls',
            sourceLabel: 'partialControls',
            sourceMetric: 'partialControls'
        }));

    const manualReviewControls = normalizedRows
        .filter(item => item.status === 'manual_review_required')
        .slice(0, 20)
        .map(item => ({
            ...item.compact,
            evidenceType: 'manualReviewControls',
            evidenceCategory: 'manualReviewControls',
            sourceLabel: 'manualReviewControls',
            sourceMetric: 'manualReviewControls'
        }));

    const passedControls = normalizedRows
        .filter(item => item.status === 'passed')
        .slice(0, 10)
        .map(item => ({
            ...item.compact,
            evidenceType: 'passedControls',
            evidenceCategory: 'passedControls',
            sourceLabel: 'passedControls',
            sourceMetric: 'passingControls'
        }));

    const remediationActions = normalizedRows
        .filter(item => ['failed', 'partial', 'manual_review_required'].includes(item.status))
        .slice(0, 20)
        .map((item, index) => ({
            ...item.compact,
            internalSourcePath: item.compact.internalSourcePath || `compliance.compact.remediationActions[${index}]`,
            evidenceType: 'remediationActions',
            evidenceCategory: 'remediationActions',
            sourceLabel: 'remediationActions',
            sourceMetric: item.compact.sourceMetric,
            data: {
                ...item.compact.data,
                entityType: 'ComplianceRemediationAction',
                remediationAction: item.compact.data.remediationAction,
                managementAction: item.compact.data.remediationAction,
                auditImpact: item.compact.data.auditImpact
            }
        }));

    const evidenceReferences = normalizedRows
        .slice(0, 25)
        .map((item, index) => ({
            ...item.compact,
            internalSourcePath: item.compact.internalSourcePath || `compliance.compact.evidenceReferences[${index}]`,
            evidenceType: 'evidenceReferences',
            evidenceCategory: 'evidenceReferences',
            sourceLabel: 'evidenceReferences',
            sourceMetric: item.compact.sourceMetric
        }));

    const complianceMetric = [
        ['complianceScore', 'Compliance score'],
        ['totalControls', 'Total controls'],
        ['failingControls', 'Failing controls'],
        ['partialControls', 'Partial controls'],
        ['passingControls', 'Passing controls'],
        ['manualReviewControls', 'Manual-review controls']
    ].map(([name, label]) => ({ name, label, value: numberOrNull(metrics[name]) }))
        .find(metric => metric.value !== null) || null;
    const failingCount = numberOrNull(metrics.failingControls);
    const partialCount = numberOrNull(metrics.partialControls);
    const manualReviewCount = numberOrNull(metrics.manualReviewControls);
    const readinessCountsComplete = [failingCount, partialCount, manualReviewCount].every(value => value !== null);
    const hasControlPopulation = numberOrNull(metrics.totalControls) !== null || numberOrNull(metrics.passingControls) !== null;
    const auditReadinessStatus = failingCount !== null && failingCount > 0
        ? 'not_ready'
        : (partialCount !== null && partialCount > 0) || (manualReviewCount !== null && manualReviewCount > 0)
            ? 'partially_ready'
            : readinessCountsComplete && hasControlPopulation
                ? 'ready'
                : null;
    const summaryRow = complianceMetric ? {
        internalSourcePath: 'compliance.compact.summaryMetrics',
        sourceLabel: 'summaryMetrics',
        evidenceType: 'summaryMetrics',
        evidenceCategory: 'summaryMetrics',
        sourceMetric: complianceMetric.name,
        entityKey: 'compliance-metric-' + complianceMetric.name,
        data: compactNonEmptyObject({
            entityId: 'compliance-metric-' + complianceMetric.name,
            entityName: complianceMetric.label,
            entityType: 'SourceMetric',
            metricName: complianceMetric.name,
            value: complianceMetric.value,
            totalControls: numberOrNull(metrics.totalControls),
            apiControls: numberOrNull(metrics.apiControls),
            manualControlsExcluded: numberOrNull(metrics.manualControlsExcluded),
            failingControls: numberOrNull(metrics.failingControls),
            partialControls: numberOrNull(metrics.partialControls),
            passingControls: numberOrNull(metrics.passingControls),
            manualReviewControls: numberOrNull(metrics.manualReviewControls),
            complianceScore: numberOrNull(metrics.complianceScore),
            auditReadinessStatus,
            stackctrlRiskScore: numberOrNull(metrics.stackctrlRiskScore),
            stackctrlHealthScore: numberOrNull(metrics.stackctrlHealthScore),
            evidenceSnapshotId: sourceLineage.evidenceSnapshotId || null,
            sourceFetchedAt: sourceLineage.sourceFetchedAt || sourceLineage.sourceLastUpdated || null,
            collectionStatus: sourceLineage.collectionStatus || null,
            validationReason: 'Compliance summary provides audit-readiness context across API-connected compliance controls.',
            remediationAction: 'Use failed, partial, and manual-review controls to drive remediation and audit evidence collection.'
        })
    } : null;

    return [
        ...(summaryRow ? [summaryRow] : []),
        ...failedControls,
        ...partialControls,
        ...manualReviewControls,
        ...remediationActions,
        ...evidenceReferences,
        ...passedControls
    ];
}

function enrichDomainEvidence(source, domain, evidence) {
    if (!Array.isArray(evidence)) return evidence;
    if (evidence.some(item => item?.evidenceType === 'dashboard_evidence_lists')) {
        return evidence;
    }
    try {
        const enriched = buildDashboardIntelligenceContext({
            sourceKey: domain.sourceKey,
            displayName: domain.name,
            status: source.status || 'available',
            isExpected: source.isExpected !== false,
            metrics: source.metrics || {},
            dashboardMetrics: source.dashboardMetrics || {},
            dashboardSourceMetrics: source.dashboardSourceMetrics || source.dashboardMetrics || {},
            evidence,
            warnings: source.warnings || [],
            freshness: source.freshness || {},
            sourceLineage: source.sourceLineage || null,
            rawReference: source.rawReference || null
        });
        const listPackage = array(enriched.evidence).find(item => item?.evidenceType === 'dashboard_evidence_lists');
        return listPackage ? [...array(evidence), listPackage] : evidence;
    } catch (_) {
        return evidence;
    }
}

function buildEvidenceCatalog(evidence, domain, snapshotId) {
    const evidenceItems = Array.isArray(evidence) ? evidence : [];
    const listContainer = evidenceItems.find(item => item?.evidenceType === 'dashboard_evidence_lists');
    const listData = listContainer?.data && typeof listContainer.data === 'object' ? listContainer.data : {};
    const metricMap = DOMAIN_EVIDENCE_CATEGORY_METRICS[domain.key] || {};
    let categories = Object.entries(listData).map(([key, rows]) => {
        const entities = array(rows).map(row => safeEvidenceEntity(row));
        return {
            key,
            label: key.replace(/([A-Z])/g, ' $1').replace(/^./, char => char.toUpperCase()).trim(),
            sourceMetric: metricMap[key] || null,
            count: entities.length,
            entities
        };
    }).filter(category => category.count > 0);

    if (!categories.length) {
        categories = evidenceItems
            .filter(item => item?.evidenceType !== 'dashboard_evidence_lists' && array(item?.data).length)
            .map(item => {
                const key = String(item.evidenceType || 'evidenceRows');
                const entities = array(item.data).map(row => safeEvidenceEntity(row));
                return {
                    key,
                    label: key.replace(/[_-]+/g, ' ').replace(/\b\w/g, char => char.toUpperCase()),
                    sourceMetric: metricMap[key] || key,
                    count: entities.length,
                    entities
                };
            });
    }

    const primaryTypes = (DOMAIN_EVIDENCE_TYPES[domain.key] || []).filter(type => type !== 'dashboard_evidence_lists');
    const primaryTable = primaryTypes.map(type => {
        const container = evidenceItems.find(item => item?.evidenceType === type);
        const rows = array(container?.data);
        return rows.length ? { evidenceType: type, count: rows.length, description: `StackCTRL ${domain.name} dashboard table (${type})` } : null;
    }).filter(Boolean)[0] || null;

    const catalogEntityCount = categories.reduce((total, category) => total + category.count, 0);
    return {
        snapshotId: Number(snapshotId),
        domainKey: domain.key,
        domainName: domain.name,
        primaryTable,
        categories,
        catalogEntityCount,
        categoryCount: categories.length
    };
}

function buildEvidenceBatchPlan(allEvidence, batches, diagnostics = {}) {
    const safeTokenLimit = numberOrNull(diagnostics.safeTokenLimit ?? diagnostics.safeInputTokenLimit);
    const identityTableTokens = numberOrNull(diagnostics.identityTableTokens ?? diagnostics.evidenceTokens);
    const deviceTableTokens = numberOrNull(diagnostics.deviceTableTokens ?? diagnostics.evidenceTokens);
    return {
        totalEntityRows: allEvidence.length,
        batchCount: batches.length,
        plannedBatchCount: numberOrNull(diagnostics.plannedBatchCount) ?? batches.length,
        itemsPerBatch: batches.map(batch => batch.items.length),
        batches: batches.map(batch => ({
            batchNumber: batch.number,
            itemCount: batch.items.length,
            evidenceTypes: [...new Set(batch.items.map(item => item.evidenceType))],
            semanticGrouping: batch.semanticGrouping || null
        })),
        basePackageTokens: numberOrNull(diagnostics.basePackageTokens),
        compactPackageTokens: numberOrNull(diagnostics.compactPackageTokens),
        evidenceTokens: numberOrNull(diagnostics.evidenceTokens),
        historicalTokens: numberOrNull(diagnostics.historicalTokens),
        knowledgeTokens: numberOrNull(diagnostics.knowledgeTokens),
        previousAnalysisTokens: numberOrNull(diagnostics.previousAnalysisTokens),
        excludedHistoricalTokens: numberOrNull(diagnostics.excludedHistoricalTokens),
        excludedPreviousAnalysisTokens: numberOrNull(diagnostics.excludedPreviousAnalysisTokens),
        identityTableTokens,
        deviceTableTokens,
        totalEstimatedTokens: numberOrNull(diagnostics.totalEstimatedTokens),
        safeInputTokenLimit: numberOrNull(diagnostics.safeInputTokenLimit),
        safeTokenLimit,
        reasonForBatchCount: diagnostics.reasonForBatchCount || null
    };
}

function identityRoleNames(roles) {
    const values = Array.isArray(roles)
        ? roles
        : typeof roles === 'string'
            ? parseJson(roles, String(roles).split(',').map(role => role.trim()).filter(Boolean))
            : [];
    return array(values).map(role => typeof role === 'string'
        ? role
        : role?.name || role?.roleName || role?.displayName || null).filter(Boolean).slice(0, 30);
}

function compactIdentityEvidenceRow(item, index = 0) {
    const data = item?.data && typeof item.data === 'object' && !Array.isArray(item.data) ? item.data : (item || {});
    const lastSignIn = data.lastSignIn && typeof data.lastSignIn === 'object' ? data.lastSignIn : {};
    const roles = identityRoleNames(data.roles || data.roleNames || data.assignedRoles);
    const mfaValue = data.mfaEnabled ?? data.isMfaRegistered ?? data.mfaRegistered;
    const accountEnabled = data.accountEnabled ?? data.isEnabled;
    const riskLevel = data.riskLevel || data.risk || data.userRiskLevel || 'unknown';
    const location = data.location || data.officeLocation || lastSignIn.location || data.lastSignInLocation || 'Unknown';
    const device = data.deviceName || data.device || lastSignIn.device || data.lastSignInDevice || 'Unknown';
    const lastSignInValue = data.lastSignInDateTime || data.lastSignInAt || lastSignIn.dateTime || lastSignIn.createdDateTime || null;
    const lastSignInDaysAgo = numberOrNull(data.daysSinceSignIn ?? lastSignIn.daysSince);
    const keyFlags = new Set();
    if (data.flags && typeof data.flags === 'object') {
        for (const [flag, enabled] of Object.entries(data.flags)) if (enabled) keyFlags.add(flag);
    }
    if (data.hasAdminRole || roles.some(role => /admin|global|privileged|security|directory/i.test(role))) keyFlags.add('privileged');
    if (data.isExternal || /guest|external/i.test(String(data.userType || data.type || ''))) keyFlags.add('external');
    if (mfaValue === false) keyFlags.add('mfaMissing');
    if (accountEnabled === false) keyFlags.add('accountDisabled');
    if (/high|critical/i.test(String(riskLevel))) keyFlags.add('highRisk');
    if (lastSignInDaysAgo != null && lastSignInDaysAgo > 30) keyFlags.add('inactiveOver30Days');
    if (/unknown|no sign-in|n\/a/i.test(String(location))) keyFlags.add('unknownLocation');
    if (/unknown|no sign-in|n\/a/i.test(String(device))) keyFlags.add('unknownDevice');
    if (/fail/i.test(String(lastSignIn.status || data.lastSignInStatus || ''))) keyFlags.add('failedSignIn');
    const authMethods = data.authenticationMethods || data.authMethods;
    const authMethodCount = numberOrNull(data.authMethodCount ?? data.authenticationMethodCount) ?? (Array.isArray(authMethods) ? authMethods.length : 0);
    const entityId = explicitEntityId(data);
    const userPrincipalName = firstReadableValue(data.userPrincipalName, data.upn);
    const displayName = firstReadableValue(data.displayName, data.name, data.userDisplayName);
    const mail = firstReadableValue(data.mail, data.email, userPrincipalName);
    const hasAdminRole = Boolean(data.hasAdminRole || roles.some(role => /admin|global|privileged|security|directory/i.test(role)));
    const isExternal = Boolean(data.isExternal || /guest|external/i.test(String(data.userType || data.type || '')));
    const normalizedLastSignIn = {
        dateTime: lastSignInValue,
        daysSince: lastSignInDaysAgo,
        location: typeof location === 'object' ? firstReadableValue(location.displayName, location.city, location.countryOrRegion) : firstReadableValue(location),
        device: typeof device === 'object' ? firstReadableValue(device.displayName, device.deviceName, device.id) : firstReadableValue(device)
    };
    const normalizedFlags = {
        adminWithoutMFA: Boolean(data.flags?.adminWithoutMFA || (hasAdminRole && mfaValue === false)),
        inactiveOver30Days: Boolean(data.flags?.inactiveOver30Days || (lastSignInDaysAgo != null && lastSignInDaysAgo > 30)),
        newLocationLogin: Boolean(data.flags?.newLocationLogin)
    };

    return {
        rowNumber: index + 1,
        id: entityId,
        entityId,
        displayName,
        name: displayName,
        mail,
        email: mail,
        userPrincipalName,
        jobTitle: firstReadableValue(data.jobTitle, data.title),
        roles,
        hasAdminRole,
        type: firstReadableValue(data.userType, data.accountType, data.type, data.isExternal ? 'Guest' : 'Member'),
        mfaEnabled: mfaValue == null ? null : Boolean(mfaValue),
        mfaStatus: mfaValue === true ? 'enabled' : mfaValue === false ? 'missing' : 'unknown',
        authMethodCount,
        riskLevel: firstReadableValue(riskLevel),
        accountEnabled: accountEnabled == null ? null : Boolean(accountEnabled),
        accountStatus: accountEnabled === false ? 'disabled' : accountEnabled === true ? 'enabled' : 'unknown',
        isExternal,
        lastSignIn: normalizedLastSignIn,
        flags: normalizedFlags,
        lastSignInDaysAgo,
        location: normalizedLastSignIn.location,
        device: normalizedLastSignIn.device,
        keyFlags: [...keyFlags],
        sourceMetric: item?.sourceMetric || null,
        internalSourcePath: item?.internalSourcePath || null
    };
}

function identityUserEvidenceRows(evidence) {
    const rows = array(evidence);
    const users = rows.filter(item => {
        const data = item?.data && typeof item.data === 'object' ? item.data : {};
        const label = String(item?.evidenceType || item?.evidenceCategory || item?.sourceLabel || '').toLowerCase();
        return /^(?:users|allusers|identityusers|user)$/.test(label.replace(/[_\s-]+/g, '')) || Boolean(
            data.userPrincipalName || data.mail || data.email || data.mfaEnabled != null ||
            data.authMethodCount != null || data.jobTitle || data.userType
        );
    });
    return users.length ? users : rows;
}

function identityMetricsSummaryFromRows(rows, basePackage = {}) {
    const tableRows = array(rows);
    const totalUsers = tableRows.length;
    const mfaEnabled = tableRows.filter(row => row.mfaEnabled === true || row.mfaStatus === 'enabled').length;
    const activeUsers = tableRows.filter(row => row.accountEnabled === true || row.accountStatus === 'enabled').length;
    const inactiveUsers = tableRows.filter(row => row.accountEnabled === false || row.accountStatus === 'disabled' || row.flags?.inactiveOver30Days).length;
    const privilegedUsers = tableRows.filter(row => row.hasAdminRole || array(row.roles).some(role => /admin|global|privileged|security|directory/i.test(role))).length;
    const adminsWithoutMfa = tableRows.filter(row => row.flags?.adminWithoutMFA || ((row.hasAdminRole || array(row.roles).some(role => /admin|global|privileged|security|directory/i.test(role))) && row.mfaEnabled === false)).length;
    const multiplePrivilegedRoles = tableRows.filter(row => array(row.roles).filter(role => /admin|global|privileged|security|directory/i.test(role)).length > 1).length;
    const highRiskUsers = tableRows.filter(row => /high|critical/i.test(String(row.riskLevel || ''))).length;
    const mediumRiskUsers = tableRows.filter(row => /medium|moderate/i.test(String(row.riskLevel || ''))).length;
    const unknownDevices = tableRows.filter(row => /unknown|no sign-in|n\/a/i.test(String(row.device || row.lastSignIn?.device || ''))).length;
    const signInIssues = tableRows.filter(row => row.flags?.inactiveOver30Days || row.flags?.newLocationLogin || /unknown|no sign-in|n\/a/i.test(String(row.location || row.lastSignIn?.location || ''))).length;
    const currentMetrics = basePackage.currentMetrics || {};
    const dashboardMetrics = basePackage.dashboardMetrics || {};
    return {
        totalUsers: numberOrNull(currentMetrics.totalUsers ?? dashboardMetrics.totalUsers) ?? totalUsers,
        activeUsers,
        inactiveUsers,
        mfaEnabled,
        mfaMissing: Math.max(0, totalUsers - mfaEnabled),
        mfaCoverage: totalUsers ? Math.round((mfaEnabled / totalUsers) * 1000) / 10 : null,
        privilegedUsers,
        adminsWithoutMfa,
        multiplePrivilegedRoles,
        externalUsers: tableRows.filter(row => row.isExternal).length,
        highRiskUsers,
        mediumRiskUsers,
        unknownDevices,
        signInIssues,
        stackctrlRiskScore: basePackage.authoritativeScores?.riskScore ?? null,
        stackctrlHealthScore: basePackage.authoritativeScores?.healthScore ?? null,
        securityScore: numberOrNull(currentMetrics.securityScore ?? dashboardMetrics.securityScore ?? basePackage.authoritativeScores?.healthScore),
        snapshotId: basePackage.snapshotId ?? null,
        sourceLastUpdated: basePackage.sourceHealth?.freshness?.lastUpdated || basePackage.snapshotCreatedAt || null,
        sourceAgeMinutes: numberOrNull(basePackage.sourceHealth?.freshness?.ageMinutes),
        collectionWindow: compactIdentityCollectionWindow(basePackage)
    };
}

function compactIdentityCollectionWindow(basePackage = {}) {
    const sourceLastUpdatedAt = basePackage.sourceHealth?.freshness?.lastUpdated || basePackage.snapshotCreatedAt || null;
    return {
        sourceSystem: 'Microsoft Graph / StackCTRL Identity',
        collectedAt: basePackage.snapshotCreatedAt || null,
        snapshotCapturedAt: basePackage.snapshotCreatedAt || null,
        sourceLastUpdatedAt,
        sourceAgeMinutes: numberOrNull(basePackage.sourceHealth?.freshness?.ageMinutes),
        reportingWindow: 'current tenant state, plus lastSignIn history where available'
    };
}

function compactIdentityBasePackage(basePackage) {
    return {
        contextType: 'stackctrl_enterprise_identity_table',
        schemaVersion: 2,
        mode: basePackage.mode,
        companyId: basePackage.companyId,
        snapshotId: basePackage.snapshotId,
        snapshotCreatedAt: basePackage.snapshotCreatedAt,
        domain: basePackage.domain,
        sourceHealth: basePackage.sourceHealth,
        identityMetricsSummary: basePackage.identityMetricsSummary || identityMetricsSummaryFromRows([], basePackage),
        collectionWindow: basePackage.collectionWindow || compactIdentityCollectionWindow(basePackage),
        authoritativeScores: basePackage.authoritativeScores,
        limitations: {
            rawVendorPayloadIncluded: false,
            rawSnapshotContextIncluded: false,
            evidenceCompleteness: basePackage.limitations?.evidenceCompleteness || null,
            missingDataWarnings: array(basePackage.limitations?.missingDataWarnings)
        },
        identityTableColumns: [
            'id', 'displayName', 'userPrincipalName', 'mail', 'jobTitle', 'roles', 'hasAdminRole',
            'type', 'mfaEnabled', 'mfaStatus', 'authMethodCount', 'riskLevel', 'accountEnabled',
            'accountStatus', 'isExternal', 'lastSignIn', 'flags', 'sourceMetric', 'internalSourcePath'
        ]
    };
}

function daysSinceIsoDate(value) {
    const direct = numberOrNull(value?.daysSince ?? value?.lastSyncDaysAgo);
    if (direct != null) return direct;
    const dateValue = typeof value === 'object' && value ? value.dateTime : value;
    if (!dateValue) return null;
    const time = new Date(dateValue).getTime();
    if (!Number.isFinite(time)) return null;
    return Math.max(0, Math.floor((Date.now() - time) / (24 * 60 * 60 * 1000)));
}

function normalizeDeviceCompliance(value) {
    const text = String(value || 'unknown').trim();
    if (/^non[-_\s]?compliant$/i.test(text)) return 'nonCompliant';
    if (/^compliant$/i.test(text)) return 'compliant';
    return text || 'unknown';
}

function normalizeDeviceEncryption(data) {
    const explicit = firstReadableValue(data.encryptionState, data.encryptionStatus);
    if (explicit) return explicit;
    if (data.isEncrypted === true || data.encrypted === true) return 'encrypted';
    if (data.isEncrypted === false || data.encrypted === false) return 'notEncrypted';
    return 'unknown';
}

function deviceEvidenceRows(evidence) {
    const rows = array(evidence);
    const devices = rows.filter(item => {
        const data = item?.data && typeof item.data === 'object' ? item.data : {};
        const label = String(item?.evidenceType || item?.evidenceCategory || item?.sourceLabel || '').toLowerCase();
        return /^(?:devices|alldevices|manageddevices|device)$/.test(label.replace(/[_\s-]+/g, '')) || Boolean(
            data.deviceName || data.managedDeviceName || data.operatingSystem || data.complianceState ||
            data.managementAgent || data.serialNumber || data.lastSyncDateTime
        );
    });
    return devices.length ? devices : rows;
}

function compactDeviceEvidenceRow(item, index = 0) {
    const data = item?.data && typeof item.data === 'object' && !Array.isArray(item.data) ? item.data : (item || {});
    const deviceId = explicitEntityId(data);
    const deviceName = firstReadableValue(data.deviceName, data.managedDeviceName, data.displayName, data.name, data.hostName, data.hostname);
    const assignedUser = firstReadableValue(data.assignedUser, data.userPrincipalName, data.primaryUser, data.userDisplayName, data.email, data.mail);
    const complianceState = normalizeDeviceCompliance(data.complianceState || data.complianceStatus);
    const encryptionState = normalizeDeviceEncryption(data);
    const managementState = firstReadableValue(data.managementState, data.managementAgent, data.managementStatus) || 'unknown';
    const lastSyncDateTime = firstReadableValue(data.lastSyncDateTime, data.lastSyncAt, data.lastSeenDateTime);
    const lastSyncDaysAgo = numberOrNull(data.lastSyncDaysAgo ?? data.daysSinceLastSync) ?? daysSinceIsoDate(lastSyncDateTime);
    const riskLevel = firstReadableValue(data.riskLevel, data.risk) || 'unknown';
    const securityAlertCount = numberOrNull(data.securityAlertCount ?? data.alertCount) ?? 0;
    const flags = new Set();
    if (!/^compliant$/i.test(complianceState)) flags.add('nonCompliant');
    if (/not|false|unencrypted/i.test(encryptionState)) flags.add('notEncrypted');
    if (/unknown|none|unmanaged/i.test(managementState)) flags.add('unmanaged');
    if (lastSyncDaysAgo != null && lastSyncDaysAgo > 30) flags.add('dead30Days');
    else if (lastSyncDaysAgo != null && lastSyncDaysAgo > 7) flags.add('staleDevice');
    if (/high|critical/i.test(riskLevel)) flags.add('highRisk');
    if (securityAlertCount > 0) flags.add('securityAlerts');
    if (data.hasPendingActions) flags.add('pendingActions');

    return {
        rowNumber: index + 1,
        deviceId,
        entityId: deviceId,
        deviceName,
        entityName: deviceName,
        assignedUser,
        userPrincipalName: firstReadableValue(data.userPrincipalName, assignedUser),
        operatingSystem: firstReadableValue(data.operatingSystem, data.os),
        osVersion: firstReadableValue(data.osVersion),
        complianceState,
        encryptionState,
        managementState,
        lastSyncDateTime,
        lastSyncDaysAgo,
        registrationDateTime: firstReadableValue(data.registrationDateTime, data.enrolledDateTime),
        enrollmentType: firstReadableValue(data.enrollmentType, data.deviceEnrollmentType),
        serialNumber: firstReadableValue(data.serialNumber),
        riskLevel,
        securityAlertCount,
        issueFlags: [...flags],
        sourceMetric: item?.sourceMetric || null,
        internalSourcePath: item?.internalSourcePath || null
    };
}

function compactDeviceCollectionWindow(basePackage = {}) {
    const sourceLastUpdatedAt = basePackage.sourceHealth?.freshness?.lastUpdated || basePackage.snapshotCreatedAt || null;
    return {
        sourceSystem: 'Microsoft Graph / Intune / StackCTRL Devices',
        collectedAt: basePackage.snapshotCreatedAt || null,
        snapshotCapturedAt: basePackage.snapshotCreatedAt || null,
        sourceLastUpdatedAt,
        sourceAgeMinutes: numberOrNull(basePackage.sourceHealth?.freshness?.ageMinutes),
        reportingWindow: 'current tenant device state from the frozen StackCTRL Device Protection snapshot'
    };
}

function deviceMetricsSummaryFromRows(rows, basePackage = {}) {
    const tableRows = array(rows);
    const totalDevices = tableRows.length;
    const compliantDevices = tableRows.filter(row => /^compliant$/i.test(String(row.complianceState || ''))).length;
    const encryptedDevices = tableRows.filter(row => /encrypted/i.test(String(row.encryptionState || '')) && !/not|un/i.test(String(row.encryptionState || ''))).length;
    const managedDevices = tableRows.filter(row => !/unknown|none|unmanaged/i.test(String(row.managementState || ''))).length;
    const activeDevices24h = tableRows.filter(row => row.lastSyncDaysAgo != null && row.lastSyncDaysAgo <= 1).length;
    const staleDevices = tableRows.filter(row => row.lastSyncDaysAgo != null && row.lastSyncDaysAgo > 7 && row.lastSyncDaysAgo <= 30).length;
    const dead30Days = tableRows.filter(row => row.lastSyncDaysAgo != null && row.lastSyncDaysAgo > 30).length;
    const highRiskDevices = tableRows.filter(row => /high|critical/i.test(String(row.riskLevel || ''))).length;
    const securityAlerts = tableRows.reduce((sum, row) => sum + Number(row.securityAlertCount || 0), 0);
    const osDistribution = {};
    for (const row of tableRows) {
        const os = row.operatingSystem || 'Unknown';
        osDistribution[os] = (osDistribution[os] || 0) + 1;
    }
    const currentMetrics = basePackage.currentMetrics || {};
    const dashboardMetrics = basePackage.dashboardMetrics || {};
    const metric = name => numberOrNull(currentMetrics[name] ?? dashboardMetrics[name]);
    return {
        totalDevices: metric('totalDevices') ?? totalDevices,
        compliantDevices: metric('compliantDevices') ?? compliantDevices,
        nonCompliantDevices: metric('nonCompliantDevices') ?? Math.max(0, totalDevices - compliantDevices),
        complianceRate: metric('complianceRate') ?? (totalDevices ? Math.round((compliantDevices / totalDevices) * 1000) / 10 : null),
        encryptedDevices: metric('encryptedDevices') ?? encryptedDevices,
        notEncryptedDevices: metric('notEncryptedDevices') ?? Math.max(0, totalDevices - encryptedDevices),
        encryptionRate: metric('encryptionRate') ?? (totalDevices ? Math.round((encryptedDevices / totalDevices) * 1000) / 10 : null),
        managedDevices,
        unmanagedDevices: metric('unmanagedDevices') ?? Math.max(0, totalDevices - managedDevices),
        activeDevices24h: metric('activeDevices24h') ?? activeDevices24h,
        staleDevices: metric('staleDevices') ?? staleDevices,
        dead30Days: metric('dead30Days') ?? dead30Days,
        highRiskDevices: metric('highRiskDevices') ?? highRiskDevices,
        securityAlerts: metric('securityAlerts') ?? securityAlerts,
        osDistribution,
        deviceSecurityScore: metric('deviceSecurityScore'),
        stackctrlRiskScore: basePackage.authoritativeScores?.riskScore ?? null,
        stackctrlHealthScore: basePackage.authoritativeScores?.healthScore ?? null,
        snapshotId: basePackage.snapshotId ?? null,
        sourceLastUpdated: basePackage.sourceHealth?.freshness?.lastUpdated || basePackage.snapshotCreatedAt || null,
        sourceAgeMinutes: numberOrNull(basePackage.sourceHealth?.freshness?.ageMinutes),
        collectionWindow: compactDeviceCollectionWindow(basePackage)
    };
}

function compactDeviceBasePackage(basePackage) {
    return {
        contextType: 'stackctrl_enterprise_device_table',
        schemaVersion: 2,
        mode: basePackage.mode,
        companyId: basePackage.companyId,
        snapshotId: basePackage.snapshotId,
        snapshotCreatedAt: basePackage.snapshotCreatedAt,
        domain: basePackage.domain,
        sourceHealth: basePackage.sourceHealth,
        deviceMetricsSummary: basePackage.deviceMetricsSummary || deviceMetricsSummaryFromRows([], basePackage),
        collectionWindow: basePackage.collectionWindow || compactDeviceCollectionWindow(basePackage),
        authoritativeScores: basePackage.authoritativeScores,
        limitations: {
            rawVendorPayloadIncluded: false,
            rawSnapshotContextIncluded: false,
            evidenceCompleteness: basePackage.limitations?.evidenceCompleteness || null,
            missingDataWarnings: array(basePackage.limitations?.missingDataWarnings),
            missingDataInfo: array(basePackage.missingDataInfo)
        },
        deviceTableColumns: [
            'deviceId', 'deviceName', 'assignedUser', 'userPrincipalName', 'operatingSystem',
            'osVersion', 'complianceState', 'encryptionState', 'managementState',
            'lastSyncDateTime', 'lastSyncDaysAgo', 'registrationDateTime', 'enrollmentType',
            'serialNumber', 'riskLevel', 'securityAlertCount', 'issueFlags', 'sourceMetric',
            'internalSourcePath'
        ]
    };
}

function computeInterBatchDelayMs(inputTokens, settings, domainKey = null) {
    const configured = Number(settings?.domainDelayMs);
    const baseDelay = Number.isFinite(configured) ? Math.max(0, configured) : DEFAULT_DOMAIN_DELAY_MS;
    // Take the largest applicable cooldown floor so a heavy domain with a large
    // payload never gets a shorter cooldown than the same domain with less data.
    let floor = 0;
    // Security Alerts gets 90 seconds between batches (heavy domain with significant data)
    if (domainKey === 'security_alerts') floor = Math.max(floor, SECURITY_ALERTS_DOMAIN_DELAY_MS);
    if (HEAVY_DOMAINS.has(domainKey)) floor = Math.max(floor, 120000);
    if (inputTokens >= LARGE_DOMAIN_INPUT_TOKEN_THRESHOLD) floor = Math.max(floor, 180000);
    else if (inputTokens >= 30000) floor = Math.max(floor, 60000);
    if (floor > 0) return Math.max(baseDelay, floor);
    if (baseDelay === 0) return 0;
    return Math.max(baseDelay, DEFAULT_DOMAIN_DELAY_MS);
}

function computeInterDomainDelayMs(inputTokens, settings, domainKey = null) {
    return computeInterBatchDelayMs(inputTokens, settings, domainKey);
}

const ENTITY_ID_FIELDS = Object.freeze([
    'entityId', 'recordId', 'sourceAlertId', 'alertId', 'SourceID', 'id', 'objectId',
    'userId', 'deviceId', 'applicationId', 'appId', 'servicePrincipalId', 'policyId',
    'controlId', 'incidentId', 'taskId', 'serialNumber'
]);

const SOURCE_PATH_PATTERN = /\b[A-Za-z_][\w-]*(?:(?:\.[A-Za-z_][\w-]*)|\[\d+\])*\[\d+\](?:(?:\.[A-Za-z_][\w-]*)|\[\d+\])*/g;

function isSourcePathValue(value) {
    if (typeof value !== 'string') return false;
    SOURCE_PATH_PATTERN.lastIndex = 0;
    const matches = value.match(SOURCE_PATH_PATTERN);
    return Boolean(matches?.some(match => match === value.trim() || /(?:^|\.)(?:evidence|data|entities|rows)\[\d+\]/i.test(match)));
}

function visibleTextOrNull(value, maximum = 100000) {
    const text = textOrNull(value, maximum);
    if (!text) return text;
    SOURCE_PATH_PATTERN.lastIndex = 0;
    return text.replace(SOURCE_PATH_PATTERN, 'internal evidence record').slice(0, maximum);
}

function explicitEntityId(value) {
    if (value === null || value === undefined || value === '') return null;
    if (typeof value === 'string' || typeof value === 'number') {
        const id = String(value).trim();
        return id && !isSourcePathValue(id) ? textOrNull(id, 255) : null;
    }
    if (typeof value !== 'object' || Array.isArray(value)) return null;
    const data = value.data && typeof value.data === 'object' && !Array.isArray(value.data) ? value.data : value;
    for (const field of ENTITY_ID_FIELDS) {
        const candidate = data[field] ?? value[field];
        if (candidate === null || candidate === undefined || candidate === '') continue;
        const id = String(candidate).trim();
        if (id && !isSourcePathValue(id)) return textOrNull(id, 255);
    }
    return null;
}

function compactReference(value) {
    return explicitEntityId(value);
}

function compactReferences(values, maximum = Number.POSITIVE_INFINITY) {
    const references = [...new Set(array(values).map(compactReference).filter(Boolean))];
    return Number.isFinite(maximum) ? references.slice(0, maximum) : references;
}

function firstReadableValue(...values) {
    for (const value of values) {
        if (value === null || value === undefined || value === '') continue;
        const text = visibleTextOrNull(value, 500)?.trim();
        if (text && text !== 'internal evidence record' && !isSourcePathValue(text)) return text;
    }
    return null;
}

function isOpaqueEntityId(value) {
    const text = String(value || '').trim();
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text) ||
        (/^[A-Za-z0-9]+(?:[-_:][A-Za-z0-9]+)+$/.test(text) && /\d/.test(text));
}

function inferEntityType(entity, domainKey = null) {
    const explicit = firstReadableValue(entity.entityType, entity['@odata.type'], entity.type);
    if (explicit && !/^(?:object|record|row|evidence)$/i.test(explicit)) {
        return explicit.replace(/^#?microsoft\.graph\./i, '').replace(/^./, character => character.toUpperCase());
    }
    if (domainKey === 'security_alerts') {
        if (entity.incidentId || entity.incidentName) return 'Incident';
        if (entity.signInId || entity.ipAddress || entity.clientIpAddress || entity.sourceIpAddress) return entity.ipAddress || entity.clientIpAddress || entity.sourceIpAddress ? 'IPAddress' : 'SignInEvent';
        if (entity.deviceId || entity.deviceName || entity.hostName || entity.hostname) return 'Device';
        if (entity.userId || entity.userPrincipalName || entity.userEmail || entity.mail || entity.email) return 'User';
        return 'Alert';
    }
    if (entity.alertId || entity.sourceAlertId || entity.alertName || entity.incidentId || domainKey === 'security_alerts') return 'Alert';
    if (entity.applicationId || entity.appId || entity.applicationName || entity.appDisplayName || entity.appName || entity.protectedAppName || entity.publisherName || domainKey === 'applications') return 'Application';
    if (entity.deviceId || entity.deviceName || entity.serialNumber || domainKey === 'devices') return 'Device';
    if (entity.policyId || entity.policyName || entity.gatewayPolicyName || entity.accessPolicyName) return 'Policy';
    if (entity.dlpProfileName || entity.warpProfileName || entity.profileName) return 'Profile';
    if (entity.controlId || entity.controlName || entity.control) return 'Control';
    if (entity.userId || entity.userPrincipalName || entity.userEmail || entity.mail || entity.email || domainKey === 'identity') return 'User';
    if (entity.taskId || domainKey === 'operations') return 'Task';
    return 'Entity';
}

function internalSourcePathFrom(value) {
    if (typeof value === 'string') return isSourcePathValue(value) ? textOrNull(value, 1000) : null;
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    return textOrNull(
        value.internalSourcePath || value.debugSourcePath || value.sourcePath || value.auditTrace?.sourcePath,
        1000
    );
}

function canonicalEntity(value, context = {}) {
    const wrapper = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    const entity = wrapper.data && typeof wrapper.data === 'object' && !Array.isArray(wrapper.data) ? wrapper.data : wrapper;
    const entityId = explicitEntityId(entity) || explicitEntityId(wrapper) || explicitEntityId(context.entityId) ||
        (typeof value === 'string' && isOpaqueEntityId(value) ? explicitEntityId(value) : null);
    const entityEmail = firstReadableValue(entity.entityEmail, entity.userPrincipalName, entity.userEmail, entity.mail, entity.email, entity.upn);
    const rawEntityDeviceName = firstReadableValue(entity.entityDeviceName, entity.deviceName, entity.cloudflareDeviceName, entity.managedDeviceName, entity.hostName, entity.hostname);
    const rawEntityApplicationName = firstReadableValue(entity.entityApplicationName, entity.applicationName, entity.appDisplayName, entity.appName, entity.protectedAppName, entity.servicePrincipalName);
    const alertName = firstReadableValue(entity.alertName, entity.alertTitle, entity.title, entity.subject);
    const policyName = firstReadableValue(entity.policyName, entity.gatewayPolicyName, entity.accessPolicyName, entity.controlName, entity.control);
    const profileName = firstReadableValue(entity.dlpProfileName, entity.warpProfileName, entity.profileName);
    const explicitName = typeof value === 'string' && !isSourcePathValue(value) && !isOpaqueEntityId(value) && String(value) !== String(entityId || '')
        ? value
        : null;
    let entityName = firstReadableValue(
        entity.entityName, entity.entityDisplayName, entity.displayName, entity.userDisplayName,
        entity.name, rawEntityApplicationName, rawEntityDeviceName, alertName, policyName, profileName, entityEmail, explicitName
    );
    if (entityId && entityName === String(entityId)) entityName = null;
    const sourceDomain = firstReadableValue(entity.sourceDomain, wrapper.sourceDomain, context.sourceDomain);
    const sourceMetric = firstReadableValue(entity.sourceMetric, wrapper.sourceMetric, context.sourceMetric);
    const entityType = inferEntityType(entity, sourceDomain);
    const entityDeviceName = rawEntityDeviceName || (entityType === 'Device' ? entityName : null);
    const entityApplicationName = rawEntityApplicationName || (entityType === 'Application' ? entityName : null);
    const publisherName = firstReadableValue(
        entity.publisherName, entity.publisher, entity.verifiedPublisher?.displayName,
        entity.verifiedPublisherName
    );
    const internalSourcePath = internalSourcePathFrom(wrapper) || internalSourcePathFrom(entity);
    const businessReason = firstReadableValue(entity.businessReason, context.businessReason, context.businessImpact, context.whyItMatters);
    const recommendation = firstReadableValue(entity.recommendation, entity.recommendedAction, context.recommendation, context.recommendedAction, context.detail);
    const complianceState = firstReadableValue(entity.complianceState, entity.complianceStatus);
    const encryptionState = firstReadableValue(entity.encryptionState, entity.encryptionStatus,
        entity.isEncrypted === true ? 'encrypted' : entity.isEncrypted === false ? 'not_encrypted' : null);
    const managementState = firstReadableValue(entity.managementState, entity.managementAgent, entity.managementStatus);
    const assignedUser = firstReadableValue(entity.assignedUser, entity.entityUser, entity.userPrincipalName, entity.primaryUser, entity.userDisplayName, entityEmail);
    const roles = array(entity.roles).map(role => firstReadableValue(role?.name, role?.displayName, role?.roleName, role)).filter(Boolean);
    const hasAdminRole = entity.hasAdminRole == null
        ? (roles.length ? roles.some(role => /admin|privileged|owner/i.test(role)) : null)
        : Boolean(entity.hasAdminRole);
    const mfaEnabled = entity.mfaEnabled == null ? null : Boolean(entity.mfaEnabled);
    const accountStatus = firstReadableValue(entity.accountStatus, entity.accountEnabled === true ? 'enabled' : entity.accountEnabled === false ? 'disabled' : null, entity.status);
    const lastSignIn = entity.lastSignIn && typeof entity.lastSignIn === 'object'
        ? sanitizeVisibleValue(entity.lastSignIn)
        : firstReadableValue(entity.lastSignIn, entity.lastSignInDateTime);

    if (!entityId && !entityName && !entityEmail && !entityDeviceName && !entityApplicationName) return null;
    return {
        entityId,
        entityName,
        entityType,
        sourceDomain,
        sourceMetric,
        businessReason,
        recommendation,
        entityDisplayName: firstReadableValue(entity.entityDisplayName, entity.displayName, entityName),
        entityEmail,
        entityDeviceName,
        entityApplicationName,
        publisherName,
        alertName,
        policyName,
        profileName,
        severity: firstReadableValue(entity.severity, context.severity),
        status: firstReadableValue(entity.status, context.status),
        roles,
        hasAdminRole,
        mfaEnabled,
        riskLevel: firstReadableValue(entity.riskLevel, entity.risk),
        accountStatus,
        lastSignIn,
        assignedUser,
        entityUser: firstReadableValue(entity.entityUser, assignedUser),
        operatingSystem: firstReadableValue(entity.operatingSystem, entity.os),
        osVersion: firstReadableValue(entity.osVersion),
        complianceState,
        encryptionState,
        managementState,
        lastSyncDateTime: firstReadableValue(entity.lastSyncDateTime, entity.lastSyncAt),
        registrationDateTime: firstReadableValue(entity.registrationDateTime, entity.enrolledDateTime),
        enrollmentType: firstReadableValue(entity.enrollmentType, entity.deviceEnrollmentType),
        serialNumber: firstReadableValue(entity.serialNumber),
        lastSyncDaysAgo: numberOrNull(entity.lastSyncDaysAgo ?? entity.daysSinceLastSync),
        securityAlertCount: numberOrNull(entity.securityAlertCount ?? entity.alertCount),
        signInId: firstReadableValue(entity.signInId),
        ipAddress: firstReadableValue(entity.ipAddress, entity.clientIpAddress, entity.sourceIpAddress, entity.ip),
        internalSourcePath,
        // Readable compatibility aliases retained for existing admin/report consumers.
        displayName: firstReadableValue(entity.displayName, entityName),
        userPrincipalName: firstReadableValue(entity.userPrincipalName, entityEmail),
        mail: firstReadableValue(entity.mail),
        email: firstReadableValue(entity.email),
        deviceName: firstReadableValue(entity.deviceName, entityDeviceName),
        applicationName: firstReadableValue(entity.applicationName, entityApplicationName),
        title: firstReadableValue(entity.title, alertName),
        name: firstReadableValue(entity.name)
    };
}

function compactNonEmptyObject(value) {
    return Object.fromEntries(Object.entries(value || {}).filter(([, nested]) => {
        if (nested == null) return false;
        if (Array.isArray(nested)) return nested.length > 0;
        if (typeof nested === 'string') return nested.trim().length > 0;
        return true;
    }));
}

function cloudflareEntityForOutput(entity) {
    if (!entity || typeof entity !== 'object') return null;
    const appName = firstReadableValue(entity.appName, entity.entityApplicationName, entity.applicationName, entity.protectedAppName);
    const deviceName = firstReadableValue(entity.deviceName, entity.entityDeviceName, entity.cloudflareDeviceName, entity.hostname, entity.hostName);
    const gatewayRuleName = firstReadableValue(entity.gatewayRuleName, entity.gatewayPolicyName, entity.ruleName);
    const policyName = firstReadableValue(entity.policyName, entity.accessPolicyName, entity.gatewayPolicyName, gatewayRuleName);
    const profileName = firstReadableValue(entity.profileName, entity.dlpProfileName, entity.warpProfileName);
    const entityName = firstReadableValue(
        entity.entityName,
        entity.entityDisplayName,
        entity.displayName,
        appName,
        policyName,
        deviceName,
        gatewayRuleName,
        profileName,
        entity.name
    );
    const inferredType = firstReadableValue(entity.entityType) || (
        appName ? 'Application'
            : deviceName ? 'Device'
            : (policyName || gatewayRuleName) ? 'Policy'
            : profileName ? 'Profile'
            : 'Cloudflare Entity'
    );
    const normalizedType = /app/i.test(inferredType) ? 'Application'
        : /device/i.test(inferredType) ? 'Device'
        : /policy|rule/i.test(inferredType) ? 'Policy'
        : /profile/i.test(inferredType) ? 'Profile'
        : inferredType;
    const riskReason = firstReadableValue(entity.riskReason, entity.businessReason, entity.reason, entity.reasoning, entity.whatHappened, entity.whyItMatters);
    const common = {
        entityId: entity.entityId,
        entityName,
        entityType: normalizedType,
        sourceDomain: entity.sourceDomain,
        sourceMetric: entity.sourceMetric,
        status: firstReadableValue(entity.status, entity.action, entity.outcome),
        severity: firstReadableValue(entity.severity),
        riskReason,
        businessReason: firstReadableValue(entity.businessReason, riskReason),
        recommendation: firstReadableValue(entity.recommendation, entity.recommendedAction),
        internalSourcePath: entity.internalSourcePath
    };
    const cleaned = normalizedType === 'Application'
        ? compactNonEmptyObject({
            ...common,
            appName,
            policyName: policyName && policyName !== appName ? policyName : null
        })
        : normalizedType === 'Device'
        ? compactNonEmptyObject({
            ...common,
            deviceName
        })
        : normalizedType === 'Policy'
        ? compactNonEmptyObject({
            ...common,
            policyName: policyName || gatewayRuleName,
            gatewayRuleName,
            action: firstReadableValue(entity.action, entity.outcome)
        })
        : normalizedType === 'Profile'
        ? compactNonEmptyObject({
            ...common,
            profileName
        })
        : compactNonEmptyObject(common);
    return cleaned.entityId || cleaned.entityName ? cleaned : null;
}

function emailEntityForOutput(entity) {
    if (!entity || typeof entity !== 'object') return null;
    const emailAddress = firstReadableValue(entity.emailAddress, entity.targetedUser, entity.entityEmail, entity.userPrincipalName, entity.userEmail, entity.mail, entity.email);
    const alertName = firstReadableValue(entity.alertName, entity.title, entity.entityName, entity.displayName, entity.name);
    const entityName = firstReadableValue(entity.entityName, alertName, emailAddress);
    const cleaned = compactNonEmptyObject({
        entityId: entity.entityId || emailAddress || entityName,
        entityName,
        entityType: firstReadableValue(entity.entityType) || (emailAddress ? 'User' : 'Email Security Entity'),
        emailAddress,
        targetedUser: firstReadableValue(entity.targetedUser, emailAddress),
        threatCount: numberOrNull(entity.threatCount),
        threatType: firstReadableValue(entity.threatType, entity.category),
        severity: firstReadableValue(entity.severity),
        status: firstReadableValue(entity.status),
        businessReason: firstReadableValue(entity.businessReason, entity.riskReason, entity.reason),
        recommendation: firstReadableValue(entity.recommendation, entity.recommendedAction),
        sourceMetric: entity.sourceMetric,
        internalSourcePath: entity.internalSourcePath
    });
    return cleaned.entityId || cleaned.entityName ? cleaned : null;
}

function backupEntityForOutput(entity) {
    if (!entity || typeof entity !== 'object') return null;
    const emailAddress = firstReadableValue(entity.emailAddress, entity.entityEmail, entity.userPrincipalName, entity.mail, entity.email);
    const entityName = firstReadableValue(entity.entityName, entity.displayName, entity.siteName, entity.name, emailAddress);
    const cleaned = compactNonEmptyObject({
        entityId: entity.entityId || emailAddress || entityName,
        entityName,
        entityType: firstReadableValue(entity.entityType) || (emailAddress ? 'User' : 'Backup Entity'),
        emailAddress,
        totalStorageGB: numberOrNull(entity.totalStorageGB ?? entity.storageGB),
        oneDriveStorageGB: numberOrNull(entity.oneDriveStorageGB),
        sharePointStorageGB: numberOrNull(entity.sharePointStorageGB),
        exchangeStorageGB: numberOrNull(entity.exchangeStorageGB),
        backupCoverageScore: numberOrNull(entity.backupCoverageScore),
        servicesCovered: numberOrNull(entity.servicesCovered),
        externalBackupConfigured: entity.externalBackupConfigured,
        restoreTestingStatus: firstReadableValue(entity.restoreTestingStatus),
        immutabilityStatus: firstReadableValue(entity.immutabilityStatus),
        lastActivityDate: firstReadableValue(entity.lastActivityDate),
        businessReason: firstReadableValue(entity.businessReason, entity.riskReason, entity.reason),
        recommendation: firstReadableValue(entity.recommendation, entity.recommendedAction),
        sourceMetric: entity.sourceMetric,
        internalSourcePath: entity.internalSourcePath
    });
    return cleaned.entityId || cleaned.entityName ? cleaned : null;
}

function applicationEntityForOutput(entity) {
    if (!entity || typeof entity !== 'object') return null;
    const appName = firstReadableValue(entity.applicationName, entity.entityApplicationName, entity.appName, entity.entityName, entity.displayName, entity.name);
    const cleaned = compactNonEmptyObject({
        entityId: entity.entityId || entity.applicationId || entity.appId || appName,
        entityName: firstReadableValue(entity.entityName, appName),
        entityType: 'Application',
        applicationName: appName,
        publisherName: firstReadableValue(entity.publisherName, entity.publisher),
        riskLevel: firstReadableValue(entity.riskLevel, entity.risk),
        status: firstReadableValue(entity.status),
        businessReason: firstReadableValue(entity.businessReason, entity.riskReason, entity.reason),
        recommendation: firstReadableValue(entity.recommendation, entity.recommendedAction),
        sourceMetric: entity.sourceMetric,
        internalSourcePath: entity.internalSourcePath
    });
    return cleaned.entityId || cleaned.entityName ? cleaned : null;
}

function securityAlertEntityForOutput(entity) {
    if (!entity || typeof entity !== 'object') return null;
    const userPrincipalName = firstReadableValue(entity.userPrincipalName, entity.entityEmail, entity.userEmail, entity.mail, entity.email, entity.user);
    const deviceName = firstReadableValue(entity.deviceName, entity.entityDeviceName, entity.hostName, entity.hostname, entity.machineName);
    const ipAddress = firstReadableValue(entity.ipAddress, entity.clientIpAddress, entity.sourceIpAddress, entity.ip);
    const incidentName = firstReadableValue(entity.incidentName, entity.incidentTitle);
    const alertName = firstReadableValue(entity.alertName, entity.title, entity.entityName, entity.displayName, entity.name);
    const sourceMetric = firstReadableValue(entity.sourceMetric);
    const explicitType = firstReadableValue(entity.entityType);
    const inferredType = explicitType && !/alert|entity/i.test(explicitType)
        ? explicitType
        : /incident/i.test(String(sourceMetric)) || entity.incidentId || incidentName
        ? 'Incident'
        : /anonymousip|ipaddress/i.test(String(sourceMetric)) || ipAddress
        ? 'IPAddress'
        : /signin/i.test(String(sourceMetric)) || entity.signInId
        ? 'SignInEvent'
        : deviceName
        ? 'Device'
        : userPrincipalName
        ? 'User'
        : 'Alert';
    const entityName = firstReadableValue(
        entity.entityName,
        inferredType === 'User' ? userPrincipalName : null,
        inferredType === 'Device' ? deviceName : null,
        inferredType === 'IPAddress' ? ipAddress : null,
        inferredType === 'Incident' ? incidentName : null,
        alertName,
        userPrincipalName,
        deviceName,
        ipAddress
    );
    const cleaned = compactNonEmptyObject({
        entityId: entity.entityId || entity.incidentId || entity.signInId || entity.sourceAlertId || entity.alertId || userPrincipalName || deviceName || ipAddress || entityName,
        entityName,
        entityType: inferredType,
        userPrincipalName,
        deviceName,
        ipAddress,
        incidentName,
        alertName,
        alertCount: numberOrNull(entity.alertCount ?? entity.securityAlertCount),
        severity: firstReadableValue(entity.severity),
        status: firstReadableValue(entity.status),
        riskLevel: firstReadableValue(entity.riskLevel),
        lastAlertTime: firstReadableValue(entity.lastAlertTime, entity.timestamp, entity.createdDateTime, entity.eventDateTime),
        sourceMetric,
        sourceDomain: firstReadableValue(entity.sourceDomain) || 'security_alerts',
        businessReason: firstReadableValue(entity.businessReason, entity.riskReason, entity.reason, entity.whyItMatters),
        recommendation: firstReadableValue(entity.recommendation, entity.recommendedAction),
        internalSourcePath: entity.internalSourcePath
    });
    return cleaned.entityId || cleaned.entityName ? cleaned : null;
}

function cleanEntityForDomain(entity, domainKey) {
    if (domainKey === 'email_security') return emailEntityForOutput(entity);
    if (domainKey === 'cloudflare_network_security') return cloudflareEntityForOutput(entity);
    if (domainKey === 'backup') return backupEntityForOutput(entity);
    if (domainKey === 'applications') return applicationEntityForOutput(entity);
    if (domainKey === 'security_alerts') return securityAlertEntityForOutput(entity);
    return entity;
}

function cleanEntitiesForDomain(values, domainKey) {
    return uniqueEntities(array(values).map(entity => cleanEntityForDomain(entity, domainKey)).filter(Boolean));
}

function isCuratedReferenceWarning(value) {
    return /curated\s+.*best-practice\s+references\s+were\s+unavailable|curated\s+.*references\s+unavailable/i.test(String(value || ''));
}

function sourceLineageLastUpdated(source = {}) {
    const lineage = source.sourceLineage || {};
    return lineage.sourceLastUpdated || lineage.sourceFetchedAt || lineage.collectedAt || lineage.updatedAt || lineage.createdAt || null;
}

function uniqueEntities(values) {
    const seen = new Set();
    return array(values).filter(Boolean).filter(entity => {
        const key = entity.entityId
            ? `id:${entity.entityId}`
            : `name:${entity.entityType}:${entity.entityName || entity.entityEmail || entity.entityDeviceName || entity.entityApplicationName}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

function sanitizeVisibleValue(value, path = []) {
    if (typeof value === 'string') {
        const namedPath = path.filter(segment => typeof segment === 'string');
        const key = namedPath.at(-1) || '';
        const parentKey = namedPath.at(-2) || '';
        if (/^(?:internal|debug)sourcepaths?$/i.test(key) || (key === 'sourcePath' && parentKey === 'auditTrace')) {
            return textOrNull(value, 1000);
        }
        return visibleTextOrNull(value);
    }
    if (Array.isArray(value)) return value.map((item, index) => sanitizeVisibleValue(item, [...path, index]));
    if (!value || typeof value !== 'object') return value;
    const result = {};
    for (const [key, nested] of Object.entries(value)) {
        if (key === 'sourcePath' && path.at(-1) !== 'auditTrace') {
            result.internalSourcePath = textOrNull(nested, 1000);
        } else {
            result[key] = sanitizeVisibleValue(nested, [...path, key]);
        }
    }
    return result;
}

function stripInternalPowerBIFields(value) {
    if (Array.isArray(value)) return value.map(stripInternalPowerBIFields).filter(item => item !== undefined);
    if (!value || typeof value !== 'object') return value;
    const result = {};
    const blockedKeys = new Set([
        'ContextJson',
        'CompactContextJson',
        'AuditOnlyContextJson',
        'contextJson',
        'compactContextJson',
        'auditOnlyContextJson',
        'rawVendorPayload',
        'rawVendorPayloads',
        'rawStackCTRLData',
        'internalSourcePath',
        'internalSourcePaths',
        'debugSourcePath'
    ]);
    for (const [key, nested] of Object.entries(value)) {
        if (blockedKeys.has(key)) continue;
        if (key === 'sourcePath' || key === 'auditTrace') continue;
        result[key] = stripInternalPowerBIFields(nested);
    }
    return result;
}

function entityMatchKeys(entity) {
    if (!entity || typeof entity !== 'object') return [];

    return [
        entity.entityId,
        entity.id,
        entity.recordId,
        entity.sourceAlertId,
        entity.alertId,
        entity.deviceId,
        entity.userId,
        entity.applicationId,
        entity.controlId,
        entity.taskId,
        entity.serialNumber,
        entity.entityName,
        entity.entityDisplayName,
        entity.displayName,
        entity.name,
        entity.entityDeviceName,
        entity.deviceName,
        entity.managedDeviceName,
        entity.hostName,
        entity.hostname,
        entity.entityEmail,
        entity.userPrincipalName,
        entity.mail,
        entity.email,
        entity.entityApplicationName,
        entity.applicationName,
        entity.appDisplayName,
        entity.publisherName,
        entity.alertName,
        entity.policyName
    ]
        .map(value => value == null ? null : String(value).trim().toLowerCase())
        .filter(Boolean)
        .filter(value => value !== 'internal evidence record')
        .filter(value => !isSourcePathValue(value));
}

function evidenceRowMatchesAffectedEntity(row, affectedEntityKeys) {
    if (!row || !affectedEntityKeys?.size) return false;

    const keys = entityMatchKeys(row);
    return keys.some(key => affectedEntityKeys.has(key));
}

function filterRowsToAffectedEntities(rows, affectedEntities) {
    const safeRows = uniqueEntities(array(rows));
    const safeAffectedEntities = uniqueEntities(array(affectedEntities));

    if (!safeRows.length) return safeRows;
    if (!safeAffectedEntities.length) return safeRows;

    const affectedEntityKeys = new Set(
        safeAffectedEntities.flatMap(entity => entityMatchKeys(entity))
    );

    if (!affectedEntityKeys.size) return safeRows;

    const filteredRows = safeRows.filter(row => evidenceRowMatchesAffectedEntity(row, affectedEntityKeys));

    return filteredRows.length ? filteredRows : safeRows;
}

function itemSearchText(item) {
    if (!item || typeof item !== 'object') return String(item || '').toLowerCase();
    return [
        item.title, item.description, item.detail, item.patternFound, item.reasoning,
        item.whatHappened, item.whyItMatters, item.businessImpact, item.businessReason,
        item.recommendation, item.recommendedAction, item.sourceMetric
    ].map(value => String(value || '')).join(' ').toLowerCase();
}

function isManufacturedValidationEntity(value) {
    const source = value?.data && typeof value.data === 'object' ? value.data : value || {};
    const label = [source.entityName, source.displayName, source.name, source.title, source.label]
        .map(item => String(item || '')).join(' ');
    return /validation summary|coverage validation/i.test(label);
}

function inferSelectedDomainSourceMetric(item, domainKey) {
    const text = String(item?.title || item?.patternFound || item?.description || '').toLowerCase();
    if (domainKey === 'identity') {
        if (/privileg|multiple (?:admin )?role/.test(text)) return 'privilegedUsers';
        if (/admin.*(?:without|missing).*mfa|break.?glass/.test(text)) return 'adminsWithoutMfa';
        if (/external|guest/.test(text)) return 'externalUsers';
        if (/inactive|dormant/.test(text)) return 'inactiveUsers';
        if (/unknown device|unknown location/.test(text)) return 'unknownDeviceUsers';
        if (/high risk/.test(text)) return 'highRiskUsers';
        if (/without mfa|missing mfa|mfa gap/.test(text)) return 'usersWithoutMfa';
    }
    if (domainKey === 'devices') {
        if (/non.?compliant/.test(text)) return 'nonCompliantDevices';
        if (/stale|dead|30 day/.test(text)) return 'deadDevices';
        if (/device|managed|encrypted/.test(text)) return 'totalDevices';
    }
    if (domainKey === 'email_security') {
        if (/mailbox|mailflow|mail activity/.test(text)) return 'activeMailboxes';
        if (/users? affected|targeting (?:key )?users?|affected users?/.test(text)) return null;
        if (/alert|phish|junk|threat/.test(text)) return 'alerts';
    }
    if (domainKey === 'governance') return /owner|governance|management review|access review/.test(text) ? 'governanceRows' : null;
    if (domainKey === 'compliance') return /control|compliance|audit|identity|device|application/.test(text) ? 'totalControls' : null;
    if (domainKey === 'security_alerts') {
        if (/anonymous|tor|proxy|vpn|ip address|risky ip|anonymous ip/.test(text)) return 'anonymousIpEvents';
        if (/sign[-\s]?in|credential|login/.test(text)) return 'suspiciousSignIns';
        if (/incident/.test(text)) return 'activeIncidents';
        if (/critical/.test(text)) return 'criticalAlerts';
        if (/high[-\s]?severity|high severity|high alert/.test(text)) return 'highSeverityAlerts';
        if (/repeat|pattern|recurring/.test(text)) return 'repeatedAlertPatterns';
        if (/unresolved|active|open|new alert/.test(text)) return 'unresolvedAlerts';
        if (/resolved|closed|remediated/.test(text)) return 'recentResolvedAlerts';
        if (/device|host|endpoint/.test(text)) return 'affectedDevices';
        if (/user|account|mail|upn/.test(text)) return 'affectedUsers';
    }
    if (domainKey === 'backup') {
        if (/large|storage|data holder|holder/.test(text)) return 'topStorageUsers';
        if (/inactive|disabled/.test(text)) return 'inactiveDataHolders';
        if (/stale|activity/.test(text)) return 'staleActivityUsers';
        if (/sharepoint|site/.test(text)) return 'topSharePointSites';
        if (/coverage|external backup|restore|immutab/.test(text)) return 'backupCoverageGaps';
    }    if (domainKey === 'applications') {
        if (/excessive|permission|scope|admin consent|directory\.|mail\.|files\./.test(text)) return 'excessivePermissionApps';
        if (/external|publisher|vendor|shadow/.test(text)) return 'externalApps';
        if (/high[-\s]?access|broad access/.test(text)) return 'highAccessApps';
        if (/group[-\s]?assigned|group assignment/.test(text)) return 'groupAssignedApps';
        if (/stale|unreviewed|unused|review/.test(text)) return 'staleOrUnreviewedApps';
        if (/high[-\s]?risk|critical/.test(text)) return 'highRiskApps';
    }
    if (domainKey === 'cloudflare_network_security') {
        if (/audit log|auditlogs|audit event|admin action|administrative audit/.test(text)) return 'auditLogs';
        if (/gateway app|app categor|app catalog/.test(text)) return 'appCategories';
        if (/permission matrix|endpoint famil|api family|api permission/.test(text)) return 'endpointFamilies';
        if (/device registration|registered warp/.test(text)) return 'registeredWarpDevices';
        if (/device posture|posture check/.test(text)) return 'enrolledDevices';
        if (/device|warp registration|enrolled/.test(text)) return 'enrolledDevices';
        if (/gateway polic|gateway rule|private traffic|roaming|inspect/.test(text)) return 'gatewayPolicies';
        if (/dlp|data loss|financial information|social security|identifier/.test(text)) return 'dlpProfiles';
        if (/warp profile|warp/.test(text)) return 'warpProfiles';
        if (/virtual network|vnet/.test(text)) return 'virtualNetworks';
        if (/access log|access event|deny|denied|allow|blocked/.test(text)) return 'accessLogCount';
        if (/protected app|application|sso app|login app/.test(text)) return 'protectedApps';
        if (/tunnel/.test(text)) return 'tunnels';
    }
    return null;
}

function filterSemanticEvidenceRows(rows, item, domainKey) {
    const text = itemSearchText(item);
    const data = row => row?.data && typeof row.data === 'object' ? row.data : row || {};
    let predicate = null;
    if (domainKey === 'identity' && /multiple (?:privileged |admin )?roles/.test(text)) predicate = value => Array.isArray(data(value).roles) && data(value).roles.length > 1;
    else if (domainKey === 'devices' && /all \d+ devices.*encrypted.*managed|encrypted and managed/.test(text)) predicate = value => (data(value).isEncrypted == null ? /encrypted/i.test(String(data(value).encryptionStatus || '')) && !/not encrypted/i.test(String(data(value).encryptionStatus || '')) : data(value).isEncrypted === true) && /mdm/i.test(String(data(value).managementAgent || ''));
    else if (domainKey === 'devices' && /no unmanaged|no unknown compliance/.test(text)) predicate = value => !/unmanaged|unknown/i.test(String(data(value).managementAgent || '')) && Boolean(String(data(value).managementAgent || '').trim()) && !/unknown/i.test(String(data(value).complianceState || data(value).complianceStatus || '')) && Boolean(String(data(value).complianceState || data(value).complianceStatus || '').trim());
    else if (domainKey === 'devices' && /not concentrated/.test(text)) predicate = () => false;
    else if (domainKey === 'devices' && /high.?risk/.test(text)) predicate = value => /high/i.test(String(data(value).riskLevel || data(value).risk || ''));
    else if (domainKey === 'devices' && /non.?compliant/.test(text)) predicate = value => /non.?compliant/i.test(String(data(value).complianceState || data(value).complianceStatus || ''));
    else if (domainKey === 'devices' && /unmanaged|unknown compliance/.test(text)) predicate = value => /unmanaged|unknown/i.test(String(data(value).managementAgent || data(value).complianceState || data(value).complianceStatus || ''));
    else if (domainKey === 'email_security' && /inactive mailbox/.test(text)) predicate = value => Number(data(value).readCount || 0) + Number(data(value).sendCount || 0) + Number(data(value).receiveCount || 0) === 0;
    else if ((domainKey === 'email_security' || domainKey === 'security_alerts') && /no (?:critical|high.?severity)|critical alert/.test(text)) predicate = value => !/critical|high/i.test(String(data(value).severity || ''));
    else if ((domainKey === 'email_security' || domainKey === 'security_alerts') && /low.?severity/.test(text)) predicate = value => /low/i.test(String(data(value).severity || '')) && !/resolved|closed|dismissed/i.test(String(data(value).status || ''));
    else if ((domainKey === 'email_security' || domainKey === 'security_alerts') && /unresolved|ongoing|active|open/.test(text)) predicate = value => !/resolved|closed|dismissed/i.test(String(data(value).status || ''));
    else if (domainKey === 'applications' && /no excessive permission|no high.?access/.test(text)) predicate = value => Number(data(value).roleCount) === 0 && Number(data(value).scopeCount) === 0 && data(value).roleCount != null && data(value).scopeCount != null;
    else if (domainKey === 'applications' && /unknown publisher/.test(text)) predicate = value => /unknown/i.test(String(data(value).publisherName || ''));
    else if (domainKey === 'applications' && /external/.test(text)) predicate = value => data(value).isExternal !== false;
    else if (domainKey === 'governance' && /manual evidence.*excluded/.test(text)) predicate = () => false;
    else if (domainKey === 'governance' && /management review/.test(text)) predicate = value => /attention required/i.test(String(data(value).status || ''));
    else if (domainKey === 'governance' && /access reviews?.*users and roles/.test(text)) predicate = value => /access review|admin review/i.test(String(data(value).area || data(value).title || ''));
    else if (domainKey === 'governance' && /missing ownership|no assigned owner|owner missing|without.*owner/.test(text)) predicate = value => /missing|unassigned|none/i.test(String(data(value).ownerStatus || data(value).owner || ''));
    else if (domainKey === 'cloudflare_network_security' && /audit/.test(text)) predicate = value => {
        const row = data(value);
        const actor = String(row.actor?.email || row.actor || '');
        const action = String(row.action?.type || row.action || '');
        return (!/support@stackopsit\.co\.za/.test(text) || /support@stackopsit\.co\.za/i.test(actor))
            && (!/successful/.test(text) || row.action?.result === true)
            && (!/update/.test(text) || /update/i.test(action));
    };
    else if (domainKey === 'compliance' && /identity/.test(text)) predicate = value => /identity/i.test(String(data(value).area || data(value).category || data(value).controlName || data(value).title || '')) && (!/fail|critical/.test(text) || /fail|critical|non.?compliant/i.test(String(data(value).complianceStatus || data(value).status || data(value).severity || '')));
    else if (domainKey === 'compliance' && /device/.test(text)) predicate = value => /device/i.test(String(data(value).area || data(value).category || data(value).controlName || data(value).title || '')) && (!/fail|critical/.test(text) || /fail|critical|non.?compliant/i.test(String(data(value).complianceStatus || data(value).status || data(value).severity || '')));
    else if (domainKey === 'compliance' && /application|shadow it/.test(text)) predicate = value => /application/i.test(String(data(value).area || data(value).category || data(value).controlName || data(value).title || ''));
    else if (domainKey === 'compliance' && /partial data visibility/.test(text)) predicate = value => /partial/i.test(String(data(value).complianceStatus || data(value).status || data(value).severity || ''));
    if (domainKey === 'backup' && /large|storage|data holder/.test(text)) return [...rows].sort((a, b) => Number(data(b).storage || data(b).storageGB || 0) - Number(data(a).storage || data(a).storageGB || 0)).slice(0, 5);
    return predicate ? rows.filter(predicate) : rows;
}
function normalizeEvidenceBackedItem(item, domain, snapshotId) {
    const value = item && typeof item === 'object' && !Array.isArray(item) ? item : { title: String(item || '') };
    const sourceDomain = textOrNull(value.sourceDomain || domain.key, 80);
    const sourceMetric = textOrNull(value.sourceMetric, 120);
    const businessReason = visibleTextOrNull(value.businessReason || value.businessImpact || value.whyItMatters, 1200);
    const recommendation = visibleTextOrNull(value.recommendation || value.recommendedAction || value.detail, 1200);
    const entityContext = { ...value, sourceDomain, sourceMetric, businessReason, recommendation };

    const suppliedEntityIds = compactReferences(value.affectedEntityIds);
    const affectedEntities = cleanEntitiesForDomain(uniqueEntities(array(value.affectedEntities)
        .map((entity, index) => canonicalEntity(entity, { ...entityContext, entityId: suppliedEntityIds[index] })))
        .filter(entity => !isManufacturedValidationEntity(entity)), domain.key);

    const rawEvidenceRows = cleanEntitiesForDomain(uniqueEntities(array(value.evidenceRows)
        .map(row => canonicalEntity(row, entityContext)))
        .filter(row => !isManufacturedValidationEntity(row)), domain.key);

    const evidenceRows = filterRowsToAffectedEntities(rawEvidenceRows, affectedEntities);

    const internalSourcePaths = [...new Set([
        ...array(value.internalSourcePaths),
        value.internalSourcePath,
        value.debugSourcePath,
        value.sourcePath,
        value.auditTrace?.sourcePath,
        isSourcePathValue(value.evidenceSource) ? value.evidenceSource : null,
        ...array(value.affectedEntities).map(internalSourcePathFrom),
        ...array(value.evidenceRows).map(internalSourcePathFrom)
    ].map(path => textOrNull(path, 1000)).filter(Boolean))];

    const {
        sourcePath: _sourcePath,
        debugSourcePath: _debugSourcePath,
        affectedEntities: _affectedEntities,
        affectedEntityIds: _affectedEntityIds,
        evidenceRows: _evidenceRows,
        recordIds: _recordIds,
        sourceAlertIds: _sourceAlertIds,
        internalSourcePaths: _internalSourcePaths,
        ...visibleValue
    } = value;

    const cleanAffectedEntityIds = affectedEntities.length
        ? compactReferences(affectedEntities)
        : compactReferences([...array(value.affectedEntityIds), ...evidenceRows]);

    const cleanRecordIds = evidenceRows.length
        ? compactReferences(evidenceRows)
        : compactReferences(array(value.recordIds));

    return {
        ...sanitizeVisibleValue(visibleValue),
        title: visibleTextOrNull(value.title || value.name || value.metricName, 255),
        description: visibleTextOrNull(value.description || value.detail || value.explanation, 1200),
        severity: textOrNull(value.severity, 50),
        status: textOrNull(value.status, 50),
        likelihood: textOrNull(value.likelihood, 80),
        impact: textOrNull(value.impact, 120),
        priority: textOrNull(value.priority, 50),
        category: textOrNull(value.category, 120),
        businessImpact: visibleTextOrNull(value.businessImpact || value.businessReason, 1200),
        businessReason,
        evidenceSummary: visibleTextOrNull(value.evidenceSummary, 1200),
        recommendation,
        detail: visibleTextOrNull(value.detail || value.recommendation, 1200),
        suggestedOwner: textOrNull(value.suggestedOwner || value.owner, 180),
        owner: textOrNull(value.owner || value.suggestedOwner, 180),
        suggestedDueDate: normalizeMysqlDate(value.suggestedDueDate || value.dueDate),
        sourceDomain,
        sourceMetric,
        snapshotId: numberOrNull(value.snapshotId ?? snapshotId),

        affectedEntities,
        affectedEntityIds: cleanAffectedEntityIds,

        evidenceRows,
        recordIds: cleanRecordIds,

        sourceAlertIds: compactReferences(value.sourceAlertIds),
        internalSourcePath: internalSourcePaths[0] || null,
        internalSourcePaths,
        sourceMetrics: [...new Set(array(value.sourceMetrics).map(metric => textOrNull(metric, 120)).filter(Boolean))],

        evidenceSource: isSourcePathValue(value.evidenceSource)
            ? textOrNull(value.sourceLabel || 'stackctrl_dashboard_evidence', 255)
            : visibleTextOrNull(value.evidenceSource || value.sourceLabel || 'stackctrl_dashboard_evidence', 255),

        whatHappened: visibleTextOrNull(value.whatHappened || value.description, 1200),
        whyItMatters: visibleTextOrNull(value.whyItMatters || value.businessImpact, 1200),
        recommendedAction: visibleTextOrNull(value.recommendedAction || value.recommendation || value.detail, 1200),
        recommendedActions: array(value.recommendedActions).map(action => visibleTextOrNull(action, 1200)).filter(Boolean),

        patternFound: visibleTextOrNull(value.patternFound, 1200),
        reasoning: visibleTextOrNull(value.reasoning, 1200),
        whyThisIsHighPriority: visibleTextOrNull(value.whyThisIsHighPriority, 1200),
        whyThisIsWorseThanLowerPriorityIssues: visibleTextOrNull(value.whyThisIsWorseThanLowerPriorityIssues, 1200),
        firstAction: visibleTextOrNull(value.firstAction, 1200),
        followUpAction: visibleTextOrNull(value.followUpAction, 1200),
        managementDecisionRequired: value.managementDecisionRequired == null
            ? null
            : value.managementDecisionRequired,
        whatCanWait: visibleTextOrNull(value.whatCanWait, 1200),
        recommendedOwner: textOrNull(value.recommendedOwner || value.suggestedOwner || value.owner, 180),

        metricName: textOrNull(value.metricName, 120),
        direction: textOrNull(value.direction, 50),
        currentValue: numberOrNull(value.currentValue),
        previousValue: numberOrNull(value.previousValue),
        changePercent: numberOrNull(value.changePercent),
        comparisonPeriod: textOrNull(value.comparisonPeriod, 80)
    };
}

function ensureItemEvidence(item, domain, snapshotId, availableEvidence = []) {
    const normalized = normalizeEvidenceBackedItem(item, domain, snapshotId);
    if (!availableEvidence.length) return normalized;

    const inferredSourceMetric = inferSelectedDomainSourceMetric(item, domain.key);
    if (inferredSourceMetric) normalized.sourceMetric = inferredSourceMetric;
    const requestedMetric = String(normalized.sourceMetric || '').toLowerCase();
    // sourceMetric describes an aggregate (for example totalUsers); it is not a
    // relationship to every record in that category. Resolve source rows only via
    // explicit entity/record/alert IDs, attached entity values, or source paths.
    const explicitReferenceKeys = new Set([
        ...array(normalized.affectedEntityIds),
        ...array(normalized.recordIds),
        ...array(normalized.sourceAlertIds),
        ...array(normalized.affectedEntities).flatMap(entity => entityMatchKeys(entity)),
        ...array(normalized.evidenceRows).flatMap(row => entityMatchKeys(row))
    ].map(value => String(value || '').trim().toLowerCase()).filter(Boolean));
    const explicitSourcePaths = new Set(array(normalized.internalSourcePaths)
        .map(value => String(value || '').trim().toLowerCase()).filter(Boolean));
    const matching = availableEvidence.filter(row => {
        const candidate = canonicalEntity({
            internalSourcePath: row?.internalSourcePath || null,
            sourceMetric: row?.sourceMetric || null,
            evidenceType: row?.evidenceType || null,
            data: row?.data ?? row
        }, normalized);
        const candidateKeys = entityMatchKeys(candidate).map(value => String(value || '').trim().toLowerCase());
        const candidatePath = String(row?.internalSourcePath || candidate?.internalSourcePath || '').trim().toLowerCase();
        return candidateKeys.some(key => explicitReferenceKeys.has(key)) ||
            (candidatePath && explicitSourcePaths.has(candidatePath));
    });
    const metricMatching = !requestedMetric ? [] : availableEvidence.filter(row => {
        const metrics = [row?.sourceMetric, row?.evidenceType, row?.evidenceCategory, row?.sourceLabel]
            .map(value => String(value || '').trim().toLowerCase()).filter(Boolean);
        return metrics.includes(requestedMetric);
    });
    const filteredMetricRows = filterSemanticEvidenceRows(metricMatching, item, domain.key);
    const semanticResolution = Boolean(inferredSourceMetric) && metricMatching.length > 0;
    const selected = semanticResolution ? filteredMetricRows : matching.length ? matching : filteredMetricRows;
    const entityContext = {
        ...normalized,
        sourceDomain: normalized.sourceDomain || domain.key,
        sourceMetric: normalized.sourceMetric,
        businessReason: normalized.businessReason,
        recommendation: normalized.recommendation
    };

    const rows = cleanEntitiesForDomain(uniqueEntities(selected.map(row => canonicalEntity({
        internalSourcePath: row?.internalSourcePath || null,
        sourceMetric: row?.sourceMetric || null,
        evidenceType: row?.evidenceType || null,
        data: row?.data ?? row
    }, entityContext))).filter(Boolean), domain.key);

    if (semanticResolution) {
        normalized.affectedEntities = rows;
        normalized.evidenceRows = rows;
    }

    const first = selected[0] || {};

    if (!normalized.sourceMetric) {
        normalized.sourceMetric = textOrNull(first.sourceMetric || first.sourceLabel || first.evidenceType, 120);
    }

    if (!normalized.evidenceSource || normalized.evidenceSource === 'stackctrl_dashboard_evidence') {
        normalized.evidenceSource = textOrNull(first.sourceLabel || first.evidenceType || 'stackctrl_dashboard_evidence', 255);
    }

    const rowsById = new Map(rows.filter(row => row.entityId).map(row => [String(row.entityId), row]));

    normalized.affectedEntities = uniqueEntities(normalized.affectedEntities.map(entity => {
        const sourceEntity = entity.entityId ? rowsById.get(String(entity.entityId)) : null;
        return sourceEntity
            ? { ...sourceEntity, ...entity, entityName: entity.entityName || sourceEntity.entityName }
            : entity;
    }));

    const enforceMetricMatchedEntities = (STRICT_COMPACT_SELECTED_DOMAIN_KEYS.has(domain.key) || domain.key === 'security_alerts') && requestedMetric && rows.length;
    if (enforceMetricMatchedEntities && normalized.affectedEntities.length) {
        const affectedEntityKeys = new Set(normalized.affectedEntities.flatMap(entity => entityMatchKeys(entity)));
        const hasMetricMatchedAffectedEntity = rows.some(row => evidenceRowMatchesAffectedEntity(row, affectedEntityKeys));
        if (!hasMetricMatchedAffectedEntity) {
            normalized.affectedEntities = rows;
        }
    }

    if (!normalized.affectedEntities.length || normalized.affectedEntities.every(entity => !entity.entityName)) {
        normalized.affectedEntities = rows;
    }

    const filteredRows = filterRowsToAffectedEntities(
        normalized.evidenceRows.length ? normalized.evidenceRows : rows,
        normalized.affectedEntities
    );

    normalized.evidenceRows = filteredRows;

    normalized.recordIds = normalized.evidenceRows.length
        ? compactReferences(normalized.evidenceRows)
        : compactReferences(normalized.recordIds);

    normalized.affectedEntityIds = normalized.affectedEntities.length
        ? compactReferences(normalized.affectedEntities)
        : compactReferences(normalized.affectedEntityIds);

    const sourceAlertIds = filteredRows.map(row => {
        return row?.sourceAlertId || row?.alertId || row?.SourceID || row?.entityId || null;
    }).filter(Boolean).map(String);

    normalized.sourceAlertIds = compactReferences([...array(item?.sourceAlertIds), ...sourceAlertIds]);

    normalized.internalSourcePaths = [...new Set([
        ...array(normalized.internalSourcePaths),
        ...filteredRows.map(row => row?.internalSourcePath).filter(Boolean)
    ])];

    normalized.internalSourcePath = normalized.internalSourcePaths[0] || null;

    if (domain.key === 'cloudflare_network_security' || domain.key === 'security_alerts') {
        normalized.affectedEntities = cleanEntitiesForDomain(normalized.affectedEntities, domain.key);
        normalized.evidenceRows = cleanEntitiesForDomain(normalized.evidenceRows, domain.key);
        normalized.affectedEntityIds = normalized.affectedEntities.length
            ? compactReferences(normalized.affectedEntities)
            : compactReferences(normalized.affectedEntityIds);
        normalized.recordIds = normalized.evidenceRows.length
            ? compactReferences(normalized.evidenceRows)
            : compactReferences(normalized.recordIds);
    }

    normalized.sourceMetrics = [...new Set([
        ...array(item?.sourceMetrics).map(String),
        normalized.sourceMetric
    ].filter(Boolean))];

    normalized.recommendedActions = array(item?.recommendedActions).length
        ? array(item.recommendedActions)
        : [normalized.recommendedAction].filter(Boolean);

    normalized.evidenceLinkVersion = 'explicit_v2';
    return normalized;
}
function normalizeControlAssessment(value, domain, snapshotId, availableEvidence) {
    if (Array.isArray(value)) return value.map(item => ensureItemEvidence(item, domain, snapshotId, availableEvidence));
    if (!value || typeof value !== 'object') return value || {};
    if (value.title || value.name || value.control || value.description || value.detail) {
        return ensureItemEvidence(value, domain, snapshotId, availableEvidence);
    }
    return Object.fromEntries(Object.entries(value).map(([key, nested]) => [
        key,
        Array.isArray(nested)
            ? nested.map(item => ensureItemEvidence(item, domain, snapshotId, availableEvidence))
            : (nested && typeof nested === 'object'
                ? normalizeControlAssessment(nested, domain, snapshotId, availableEvidence)
                : nested)
    ]));
}

function normalizeDomainOutputForDisplay(value, domain, snapshotId) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
    const normalized = sanitizeVisibleValue(value);
    const normalizeItems = items => array(items).map(item => normalizeEvidenceBackedItem(item, domain, snapshotId));
    const normalizeReasoningSection = section => Array.isArray(section)
        ? normalizeItems(section)
        : (section && typeof section === 'object' ? sanitizeVisibleValue(section) : visibleTextOrNull(section, 8000));
    return compactSelectedDomainAnalysis({
        ...normalized,
        domainExecutiveSummary: visibleTextOrNull(value.domainExecutiveSummary, 4000),
        technicalReasoning: Array.isArray(value.technicalReasoning)
            ? sanitizeVisibleValue(value.technicalReasoning)
            : visibleTextOrNull(value.technicalReasoning || value.technicalSummary, 8000),
        riskPrioritization: normalizeReasoningSection(value.riskPrioritization),
        technicalSummary: visibleTextOrNull(value.technicalSummary, 4000),
        businessImpact: visibleTextOrNull(value.businessImpact, 4000),
        currentPosture: visibleTextOrNull(value.currentPosture, 4000),
        scoreJustification: visibleTextOrNull(value.scoreJustification, 4000),
        controlAssessment: normalizeControlAssessment(value.controlAssessment || {}, domain, snapshotId, []),
        highestRiskPatterns: normalizeItems(value.highestRiskPatterns),
        keyFindings: normalizeItems(value.keyFindings),
        risks: normalizeItems(value.risks),
        recommendations: normalizeItems(value.recommendations),
        managementDecisionsRequired: normalizeItems(value.managementDecisionsRequired),
        whatCanWait: normalizeItems(value.whatCanWait),
        affectedEntities: cleanEntitiesForDomain(uniqueEntities(array(value.affectedEntities)
            .map(entity => canonicalEntity(entity, { sourceDomain: domain.key }))
            .filter(Boolean)), domain.key),
        trendAnalysis: normalizeItems(value.trendAnalysis),
        managementActions: normalizeItems(value.managementActions)
    }, domain);
}

function compactTextField(value, maximum = 420) {
    return visibleTextOrNull(value, maximum);
}

function compactTechnicalReasoning(value, fallback = null) {
    const source = Array.isArray(value)
        ? value
        : String(fallback || value || '')
            .split(/(?:\n+|(?<=\.)\s+(?=[A-Z]))/)
            .map(item => item.trim())
            .filter(Boolean);
    return source.slice(0, 5).map((item, index) => {
        if (item && typeof item === 'object' && !Array.isArray(item)) {
            return {
                title: compactTextField(item.title || item.pattern || `Reason ${index + 1}`, 140),
                reasoning: compactTextField(item.reasoning || item.point || item.detail || item.description, 420),
                priority: textOrNull(item.priority || item.severity, 60)
            };
        }
        return {
            title: `Reason ${index + 1}`,
            reasoning: compactTextField(item, 420),
            priority: null
        };
    }).filter(item => item.reasoning || item.title);
}

function stripEmptyVisibleFields(value) {
    if (Array.isArray(value)) {
        return value
            .map(stripEmptyVisibleFields)
            .filter(item => {
                if (item == null) return false;
                if (typeof item === 'string') return item.trim().length > 0;
                if (Array.isArray(item)) return item.length > 0;
                if (typeof item === 'object') return Object.keys(item).length > 0;
                return true;
            });
    }
    if (!value || typeof value !== 'object') return value;
    const result = {};
    for (const [key, nested] of Object.entries(value)) {
        const cleaned = stripEmptyVisibleFields(nested);
        if (cleaned == null) continue;
        if (typeof cleaned === 'string' && !cleaned.trim()) continue;
        if (Array.isArray(cleaned) && !cleaned.length) continue;
        if (typeof cleaned === 'object' && !Array.isArray(cleaned) && !Object.keys(cleaned).length) continue;
        result[key] = cleaned;
    }
    return result;
}

function isCuratedReferenceItem(item) {
    return isCuratedReferenceWarning(itemSearchText(item));
}

function isPositiveOrNeutralRisk(item, domainKey) {
    const text = itemSearchText(item);
    if (isCuratedReferenceWarning(text)) return true;
    if (domainKey === 'backup' && /backup coverage score is 100|coverage score is 100|100%\s+coverage|coverage is 100/.test(text)) return true;
    if (domainKey === 'applications' && /no users assigned|no group[-\s]?assigned|no high[-\s]?access|no .*applications detected|none detected/.test(text)) return true;
    if (domainKey === 'security_alerts' && /no critical alerts|no high[-\s]?severity alerts|no active incidents|all alerts resolved|most alerts resolved|nothing critical|no suspicious sign[-\s]?ins|none detected/.test(text)) return true;
    return false;
}

function compactReasonedItems(items, maximum = 5) {
    return array(items).slice(0, maximum).map(item => {
        if (!item || typeof item !== 'object' || Array.isArray(item)) return item;
        return stripEmptyVisibleFields({
            ...item,
            description: compactTextField(item.description, 520),
            detail: compactTextField(item.detail, 520),
            whatHappened: compactTextField(item.whatHappened, 520),
            whyItMatters: compactTextField(item.whyItMatters, 520),
            reasoning: compactTextField(item.reasoning, 520),
            whyThisIsHighPriority: compactTextField(item.whyThisIsHighPriority, 420),
            whyThisIsWorseThanLowerPriorityIssues: compactTextField(item.whyThisIsWorseThanLowerPriorityIssues, 420),
            businessImpact: compactTextField(item.businessImpact, 520),
            managementDecisionRequired: compactTextField(item.managementDecisionRequired, 420),
            whatCanWait: compactTextField(item.whatCanWait, 420),
            firstAction: compactTextField(item.firstAction, 300),
            followUpAction: compactTextField(item.followUpAction, 300),
            // Finding evidence is an explicit source link, not a presentation sample.
            // Keep the complete linked set so the modal can list every affected record.
            affectedEntities: array(item.affectedEntities),
            evidenceUsed: array(item.evidenceUsed).slice(0, 5).map(entry => sanitizeVisibleValue(entry)),
            evidenceRows: array(item.evidenceRows)
        });
    });
}

function compactSelectedDomainAnalysis(analysis, domain) {
    if (!analysis || typeof analysis !== 'object' || !COMPACT_SELECTED_DOMAIN_KEYS.has(domain?.key)) return analysis;
    const evidenceBackedFindings = array(analysis.keyFindings).filter(item => !isCuratedReferenceItem(item));
    const realRisks = array(analysis.risks).filter(item => !isPositiveOrNeutralRisk(item, domain.key));
    const evidenceBackedRecommendations = array(analysis.recommendations).filter(item => !isCuratedReferenceItem(item));
    const riskReasoningFallback = realRisks.map(risk => ({
        title: risk?.patternFound || risk?.title,
        reasoning: risk?.reasoning || risk?.whyThisIsHighPriority || risk?.businessReason || risk?.businessImpact,
        priority: risk?.severity || risk?.priority
    })).filter(item => item.title || item.reasoning);
    const technicalReasoningLooksGeneric = !Array.isArray(analysis.technicalReasoning) &&
        analysis.technicalReasoning &&
        analysis.technicalSummary &&
        String(analysis.technicalReasoning).trim() === String(analysis.technicalSummary).trim();
    const technicalReasoningSource = technicalReasoningLooksGeneric && riskReasoningFallback.length
        ? riskReasoningFallback
        : (analysis.technicalReasoning || (riskReasoningFallback.length ? riskReasoningFallback : analysis.technicalSummary));
    const compacted = stripEmptyVisibleFields({
        ...analysis,
        domainExecutiveSummary: compactTextField(analysis.domainExecutiveSummary, 700),
        technicalReasoning: compactTechnicalReasoning(technicalReasoningSource, analysis.technicalSummary),
        riskPrioritization: compactReasonedItems(analysis.riskPrioritization, 5),
        technicalSummary: compactTextField(analysis.technicalSummary, 700),
        businessImpact: compactTextField(analysis.businessImpact, 700),
        currentPosture: compactTextField(analysis.currentPosture, 700),
        scoreJustification: compactTextField(analysis.scoreJustification, 700),
        evidenceUsed: array(analysis.evidenceUsed).slice(0, 5).map(entry => sanitizeVisibleValue(entry)),
        highestRiskPatterns: compactReasonedItems(analysis.highestRiskPatterns, 5),
        keyFindings: compactReasonedItems(evidenceBackedFindings, 5),
        risks: compactReasonedItems(realRisks, 5),
        recommendations: compactReasonedItems(evidenceBackedRecommendations, 5),
        managementDecisionsRequired: compactReasonedItems(analysis.managementDecisionsRequired, 5),
        whatCanWait: compactReasonedItems(analysis.whatCanWait, 5),
        affectedEntities: array(analysis.affectedEntities),
        missingDataWarnings: array(analysis.missingDataWarnings).filter(warning => !isCuratedReferenceWarning(warning))
    });
    if (!Array.isArray(compacted.missingDataWarnings)) compacted.missingDataWarnings = [];
    return compacted;
}

function normalizeSynthesisOutputForDisplay(value, snapshotId = null) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
    const normalizeItems = items => array(items).map(item => {
        const domainKey = item?.domainKey || item?.sourceDomain || 'enterprise';
        const domain = DOMAIN_BY_KEY[domainKey] || { key: domainKey, name: item?.domainName || 'Enterprise' };
        return normalizeEvidenceBackedItem(item, domain, item?.snapshotId ?? snapshotId);
    });
    const managementReport = sanitizeVisibleValue(value.managementReport || {});
    if (managementReport && typeof managementReport === 'object' && !Array.isArray(managementReport)) {
        if (Array.isArray(value.managementReport?.managementActions)) managementReport.managementActions = normalizeItems(value.managementReport.managementActions);
        if (Array.isArray(value.managementReport?.actions)) managementReport.actions = normalizeItems(value.managementReport.actions);
    }
    return {
        ...sanitizeVisibleValue(value),
        managementReport,
        riskRegister: normalizeItems(value.riskRegister),
        recommendations: normalizeItems(value.recommendations),
        trendAnalysis: normalizeItems(value.trendAnalysis),
        businessImpactSummary: visibleTextOrNull(value.businessImpactSummary, 100000)
    };
}

function deepItemCount(value, depth = 0) {
    if (value == null || depth > 5) return 0;
    if (Array.isArray(value)) return value.length + value.reduce((total, item) => total + deepItemCount(item, depth + 1), 0);
    if (typeof value === 'object') return Object.values(value).reduce((total, item) => total + deepItemCount(item, depth + 1), 0);
    return 1;
}

function primitiveMetricCount(value, depth = 0) {
    if (value == null || depth > 6) return 0;
    if (Array.isArray(value)) return 0;
    if (typeof value === 'object') return Object.values(value).reduce((total, nested) => total + primitiveMetricCount(nested, depth + 1), 0);
    return 1;
}

function lineageValue(value, metric, depth = 0) {
    if (!value || typeof value !== 'object' || depth > 8) return null;
    if (Object.prototype.hasOwnProperty.call(value, metric)) return value[metric];
    const leaf = metric.split('.').at(-1).toLowerCase();
    const directKey = Object.keys(value).find(key => key.toLowerCase() === leaf);
    if (directKey) return value[directKey];
    for (const nested of Object.values(value)) {
        if (!nested || typeof nested !== 'object') continue;
        const found = lineageValue(nested, metric, depth + 1);
        if (found !== null && found !== undefined) return found;
    }
    return null;
}

function comparableLineageValue(value) {
    if (value === null || value === undefined || value === '') return null;
    if (typeof value === 'number' || typeof value === 'boolean') return value;
    const numeric = Number(value);
    return Number.isFinite(numeric) && String(value).trim() !== '' ? numeric : String(value);
}

function buildDataLineageComparison({ fields, sourceValues, inputValues, azureOutput = null, storedIntelligence = null }) {
    const rows = fields.map(metric => {
        const stackCTRLSource = comparableLineageValue(lineageValue(sourceValues, metric));
        const enterpriseAzureInput = comparableLineageValue(lineageValue(inputValues, metric));
        const azureValue = comparableLineageValue(lineageValue(azureOutput, metric));
        const storedValue = comparableLineageValue(lineageValue(storedIntelligence, metric));
        const sourceMissing = stackCTRLSource === null;
        const inputMissing = enterpriseAzureInput === null;
        return {
            metric,
            stackCTRLSource,
            enterpriseAzureInput,
            azureOutput: azureValue,
            storedIntelligence: storedValue,
            status: sourceMissing || inputMissing
                ? 'MISSING'
                : Object.is(stackCTRLSource, enterpriseAzureInput) ? 'MATCH' : 'MISMATCH',
            azureOutputStatus: azureValue === null ? 'NOT_APPLICABLE' : 'AVAILABLE'
        };
    });
    return {
        rows,
        mismatches: rows.filter(row => row.stackCTRLSource !== null && (row.enterpriseAzureInput === null || row.status === 'MISMATCH'))
    };
}

function sourceAlignmentFailure(comparison, domainName) {
    if (!comparison?.mismatches?.length) return null;
    const mismatchedFields = comparison.mismatches.map(row => row.metric);
    return {
        status: 'failed_source_mismatch',
        mismatchedFields,
        errorMessage: `StackCTRL source mismatch for ${domainName}: ${mismatchedFields.join(', ')}`
    };
}

function sourceStaleFailure(sourceHealth, domainName) {
    if (sourceHealth?.status !== 'stale') return null;
    const age = sourceHealth.freshness?.ageMinutes;
    const lastUpdated = sourceHealth.freshness?.lastUpdated;
    const ageDisplay = age != null ? `(${age} minutes old)` : '';
    const isSecurityAlerts = String(domainName || '').toLowerCase() === 'security alerts';
    return {
        status: 'source_stale',
        isStale: true,
        ageMinutes: age,
        lastUpdated,
        errorMessage: isSecurityAlerts
            ? `Security Alerts evidence is stale; latest stored evidence was used from ${lastUpdated || 'unknown refresh time'}.`
            : `${domainName} evidence is stale${ageDisplay ? ` ${ageDisplay}` : ''}; latest stored evidence was used from ${lastUpdated || 'unknown refresh time'}.`,
        reason: 'stored_evidence_fallback'
    };
}

function cleanRuntimeWarningForDisplay(warning, { domain = null, current = null, hasUsableEvidence = false } = {}) {
    const text = visibleTextOrNull(warning, 1200);
    if (!text) return null;
    const lower = text.toLowerCase();
    const domainName = domain?.name || current?.source?.displayName || 'Source';
    const lastUpdated = current?.source?.freshness?.lastUpdated || sourceLineageLastUpdated(current?.source || {}) || 'unknown refresh time';
    if (/^other[_\s-]?warning$/.test(lower) || lower.includes('other warning')) return null;
    if (lower.includes('partial_source_collection')) {
        return hasUsableEvidence
            ? null
            : `${domainName} source collection was partially completed; available API-connected evidence was used.`;
    }
    if (lower.includes('source_stale') || lower.includes('evidence is stale') || lower.includes('source is stale')) {
        return domain?.key === 'security_alerts'
            ? `Security Alerts evidence is stale; latest stored evidence was used from ${lastUpdated}.`
            : `${domainName} evidence is stale; latest stored evidence was used from ${lastUpdated}.`;
    }
    return text;
}

function sourceMissingFailure(sourceHealth, domainName) {
    const status = String(sourceHealth?.status || 'missing');
    if (!['missing', 'error', 'not_configured'].includes(status)) return null;
    const warning = array(sourceHealth?.warnings).find(Boolean);
    return {
        status: 'blocked_missing_source',
        errorMessage: warning || `${domainName} has no complete saved evidence snapshot. Enterprise Deep Reporting continued with limited-data warnings and no Azure call for this domain.`,
        reason: status
    };
}

function periodWindow(periodType, referenceDate = new Date()) {
    const type = String(periodType || 'daily').toLowerCase();
    if (!['daily', 'weekly', 'monthly', 'yearly'].includes(type)) throw new Error('Period type must be daily, weekly, monthly, or yearly');
    const local = DateTime.fromJSDate(referenceDate instanceof Date ? referenceDate : new Date(referenceDate), { zone: 'utc' }).setZone('Africa/Johannesburg');
    const start = type === 'daily' ? local.startOf('day') : type === 'weekly' ? local.startOf('week') : type === 'monthly' ? local.startOf('month') : local.startOf('year');
    const end = type === 'daily' ? local.endOf('day') : type === 'weekly' ? local.endOf('week') : type === 'monthly' ? local.endOf('month') : local.endOf('year');
    return { periodType: type, periodStart: start.toUTC().toJSDate(), periodEnd: end.toUTC().toJSDate() };
}

function johannesburgScheduleContext(referenceDate = new Date()) {
    const parsed = referenceDate instanceof Date
        ? DateTime.fromJSDate(referenceDate, { zone: 'utc' })
        : DateTime.fromISO(String(referenceDate || ''), { setZone: true });
    if (!parsed.isValid) throw new Error('A valid scheduler reference time is required');
    const local = parsed.setZone('Africa/Johannesburg');
    return {
        instant: parsed.toUTC().toJSDate(),
        local,
        scheduleKey: local.toFormat('yyyyLLdd')
    };
}

function jsonArray(value) {
    return JSON.stringify(array(value));
}

function responseUsage(response = {}) {
    const usage = response.usage || {};
    return {
        inputTokens: Number(usage.input_tokens ?? usage.inputTokens ?? 0) || 0,
        outputTokens: Number(usage.output_tokens ?? usage.outputTokens ?? 0) || 0,
        totalTokens: Number(usage.total_tokens ?? usage.totalTokens ?? 0) || 0,
        requestBytes: Number(response.requestSizeBytes || 0),
        responseBytes: Number(response.responseSizeBytes || 0),
        retries: Number(response.retryCount || 0)
    };
}

function responseFinishReason(response = {}) {
    return response.finish_reason || response.finishReason || response.data?.finish_reason || response.choices?.[0]?.finish_reason || null;
}

function safeResponsePreview(text, maximum = 1000000) {
    if (text === null || text === undefined) return null;
    const value = typeof text === 'string' ? text : JSON.stringify(text);
    return value.slice(0, maximum);
}

function domainFailureStatus(results = []) {
    const statuses = results.map(result => result.status).filter(Boolean);
    const reasons = results.map(result => result.failureReason || result.errorMessage || '').join(' ').toLowerCase();
    if (statuses.includes('blocked_missing_source')) return 'blocked_missing_source';
    if (statuses.includes('blocked_stale_source')) return 'blocked_stale_source';
    if (statuses.length && statuses.every(status => status === 'failed_invalid_json')) return 'failed_invalid_json';
    if (statuses.includes('failed_source_mismatch') || reasons.includes('source_mismatch')) return 'failed_source_mismatch';
    if (statuses.includes('failed_rate_limited') || reasons.includes('rate_limited') || reasons.includes('429') || reasons.includes('throttl')) return 'failed_rate_limited';
    if (statuses.includes('failed_terminal') || reasons.includes('evidence_prepare_failed')) return 'failed_terminal';
    if (reasons.includes('econnreset') || reasons.includes('connection_reset') || statuses.includes('failed_connection')) return 'failed_terminal';
    if ((statuses.length && statuses.every(status => status === 'failed_storage')) || reasons.includes('storage')) return 'failed_storage';
    return 'failed';
}

function isConnectionFailureResult(result) {
    const text = `${result?.failureReason || ''} ${result?.errorMessage || ''}`.toLowerCase();
    return text.includes('econnreset')
        || text.includes('connection_reset')
        || text.includes('connection error')
        || text.includes('failed_connection')
        || result?.failureReason === 'connection_reset';
}

function buildDomainRunAudit({
    domain,
    companyId,
    snapshot,
    packageResult,
    usage = {},
    status,
    batchResults = null,
    failureReason = null,
    warningReasons = [],
    azureAttemptDiagnostics = [],
    currentBatch = null
} = {}) {
    const preparedRecordCount = array(packageResult?.allEvidence).length || Number(packageResult?.audit?.preparedForAzureCount || 0);
    return {
        domainKey: domain?.key || null,
        companyId: Number(companyId),
        snapshotId: Number(snapshot?.ID || 0),
        collectionStatus: packageResult?.package?.sourceHealth?.collectionStatus
            || packageResult?.current?.source?.sourceLineage?.collectionStatus
            || null,
        sourceFreshness: packageResult?.current?.source?.freshness || packageResult?.package?.sourceHealth || null,
        stackctrlRecordCount: Number(packageResult?.audit?.stackCTRLDataCount || 0),
        preparedRecordCount,
        analysedRecordCount: Number(packageResult?.audit?.sentToAzureCount || 0),
        omittedRecordCount: Number(packageResult?.audit?.evidenceOmittedCount || 0) + Number(packageResult?.audit?.omittedCount || 0),
        omittedReasons: array(packageResult?.package?.limitations?.missingDataWarnings),
        batchCount: Number(batchResults?.batchCount || packageResult?.audit?.batchPlan?.batchCount || 0),
        currentBatch: currentBatch ?? batchResults?.currentBatch ?? null,
        azureAttemptCount: Number(usage?.retries || 0) + 1,
        azureStatus: status,
        storageStatus: status,
        finalDomainStatus: status,
        warningReasons: array(warningReasons),
        failureReason: failureReason || null,
        azureAttemptDiagnostics: array(azureAttemptDiagnostics)
    };
}

function classifyFailureStatus(error) {
    const message = String(error?.message || '').toLowerCase();
    if (message.includes('source mismatch') || message.includes('source_mismatch')) return 'failed_source_mismatch';
    if (message.includes('json')) return 'failed_invalid_json';
    if (error?.azureMetadata?.connectionReset || message.includes('econnreset') || error?.azureMetadata?.connectionError) return 'failed_connection';
    if (error?.azureMetadata?.rateLimited || error?.azureMetadata?.statusCode === 429 || message.includes('429') || message.includes('throttl') || message.includes('rate')) return 'failed_rate_limited';
    if (error?.code || message.includes('sql') || message.includes('mysql') || message.includes('database') || message.includes('storage')) return 'failed_storage';
    return 'failed';
}

function rollupRunStatus(results = []) {
    if (!results.length) return 'failed';
    if (results.every(result => result.status === 'completed')) return 'completed';
    if (results.every(result => /^(failed|blocked|skipped)/.test(String(result.status || '')))) return domainFailureStatus(results);
    return 'completed_with_warnings';
}

function isSuccessfulDomainStatus(status) {
    return SUCCESSFUL_DOMAIN_STATUSES.has(String(status || ''));
}

function buildDomainRunSummary(domainRows = [], queuedDomainKeys = []) {
    const byKey = new Map(domainRows.map(row => [row.domainKey, row]));
    const queue = queuedDomainKeys.length ? queuedDomainKeys : [...byKey.keys()];
    const summary = {
        totalDomains: queue.length,
        includedDomains: [],
        skippedDomains: [],
        blockedDomains: [],
        failedDomains: [],
        successfulDomains: [],
        pendingDomains: []
    };
    for (const domainKey of queue) {
        const row = byKey.get(domainKey);
        if (!row) {
            summary.pendingDomains.push(domainKey);
            continue;
        }
        const status = String(row.status || '');
        if (isSuccessfulDomainStatus(status)) summary.successfulDomains.push(domainKey);
        else if (SKIPPED_DOMAIN_STATUSES.has(status)) summary.skippedDomains.push({ domainKey, status, errorMessage: row.errorMessage || null });
        else if (status.startsWith('blocked')) summary.blockedDomains.push({ domainKey, status, errorMessage: row.errorMessage || null });
        else if (status.startsWith('failed')) summary.failedDomains.push({ domainKey, status, errorMessage: row.errorMessage || null });
        else summary.includedDomains.push({ domainKey, status });
    }
    return summary;
}

// Batch evidence into safe chunks for sequential Azure processing.
function splitIntoBatches(evidence, { maxItems = DEFAULT_MAX_ITEMS_PER_BATCH, maxBytes = DEFAULT_MAX_INPUT_BYTES, estimateBytes = null } = {}) {
    const batches = [];
    const items = array(evidence);
    let current = [];
    const safeMaxItems = Math.max(1, Number(maxItems) || DEFAULT_MAX_ITEMS_PER_BATCH);
    const safeMaxBytes = Math.max(50000, Number(maxBytes) || DEFAULT_MAX_INPUT_BYTES);

    function wouldExceed(candidate) {
        if (candidate.length > safeMaxItems) return true;
        if (typeof estimateBytes !== 'function') return false;
        return candidate.length > 1 && estimateBytes(candidate) > safeMaxBytes;
    }

    for (const item of items) {
        const candidate = [...current, item];
        if (current.length && wouldExceed(candidate)) {
            batches.push({ number: batches.length + 1, items: current });
            current = [item];
        } else {
            current = candidate;
        }
    }
    if (current.length || !batches.length) batches.push({ number: batches.length + 1, items: current });
    return batches;
}

function securityAlertSemantics(item) {
    const data = item?.data && typeof item.data === 'object' ? item.data : (item || {});
    const text = value => String(value || '').trim().toLowerCase();
    const severity = text(data.severity || data.alertSeverity || item?.severity || 'unknown');
    const category = text(data.category || data.alertCategory || data.classification || data.type || item?.evidenceType || 'uncategorized');
    const incidentType = text(data.incidentType || data.detectionSource || data.eventType || data.kind || item?.evidenceType || 'unknown');
    const source = text(data.source || data.sourceSystem || data.provider || data.serviceSource || item?.sourceLabel || 'stackctrl');
    const affectedEntity = text(
        data.affectedEntity || data.userPrincipalName || data.user || data.userName || data.deviceName ||
        data.device || data.hostName || data.ipAddress || item?.entityKey || 'unassigned'
    );
    const patternSource = text(data.title || data.displayName || data.alertName || data.description || category);
    const repeatedPattern = patternSource
        .replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, '<id>')
        .replace(/\b\d+\b/g, '<n>')
        .replace(/\s+/g, ' ')
        .slice(0, 160);
    return { severity, category, incidentType, source, affectedEntity, repeatedPattern };
}

function splitSecurityAlertsIntoBatches(evidence, options = {}) {
    const severityRank = { critical: 0, high: 1, medium: 2, low: 3, informational: 4, unknown: 5 };
    const ordered = array(evidence).map((item, originalIndex) => ({ item, originalIndex, semantics: securityAlertSemantics(item) }))
        .sort((left, right) => {
            const severityDifference = (severityRank[left.semantics.severity] ?? 5) - (severityRank[right.semantics.severity] ?? 5);
            if (severityDifference) return severityDifference;
            const leftKey = [left.semantics.category, left.semantics.incidentType, left.semantics.source, left.semantics.repeatedPattern, left.semantics.affectedEntity].join('|');
            const rightKey = [right.semantics.category, right.semantics.incidentType, right.semantics.source, right.semantics.repeatedPattern, right.semantics.affectedEntity].join('|');
            return leftKey.localeCompare(rightKey) || left.originalIndex - right.originalIndex;
        });
    const batches = splitIntoBatches(ordered.map(entry => entry.item), options);
    return batches.map(batch => {
        const semantics = batch.items.map(securityAlertSemantics);
        const values = key => [...new Set(semantics.map(item => item[key]).filter(Boolean))];
        return {
            ...batch,
            semanticGrouping: {
                severities: values('severity'), categories: values('category'), incidentTypes: values('incidentType'),
                sources: values('source'), affectedEntities: values('affectedEntity'), repeatedAlertPatterns: values('repeatedPattern')
            }
        };
    });
}

// Safely parse JSON with error diagnostics
function parseJsonWithDiagnostics(text, schema = null) {
    if (text && typeof text === 'object') {
        return { success: true, value: text, error: null };
    }
    try {
        const value = JSON.parse(text);
        return { success: true, value, error: null };
    } catch (error) {
        const preview = text ? text.slice(0, 200) + (text.length > 200 ? '...' : '') : '[empty response]';
        const suffix = text ? text.slice(-100) : '[empty response]';
        return {
            success: false,
            value: null,
            error: String(error.message),
            preview,
            suffix,
            fullLength: text?.length || 0
        };
    }
}

function repairTruncatedJson(text) {
    if (typeof text !== 'string' || !text.trim()) return { success: false, value: null, error: 'Response is empty' };
    const original = text.trim();
    const parsed = parseJsonWithDiagnostics(original);
    if (parsed.success) return { ...parsed, repairedText: original, repaired: false };

    const stack = [];
    let inString = false;
    let escaped = false;
    for (const character of original) {
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (character === '\\') {
                escaped = true;
            } else if (character === '"') {
                inString = false;
            }
            continue;
        }
        if (character === '"') {
            inString = true;
        } else if (character === '{' || character === '[') {
            stack.push(character);
        } else if (character === '}' || character === ']') {
            const expected = character === '}' ? '{' : '[';
            if (stack.at(-1) !== expected) return { success: false, value: null, error: parsed.error };
            stack.pop();
        }
    }

    if (!inString && !stack.length) return { success: false, value: null, error: parsed.error };
    let candidate = original;
    if (inString) {
        if (escaped) candidate += '\\';
        candidate += '"';
    } else {
        candidate = candidate.replace(/,\s*$/, '');
    }
    for (let index = stack.length - 1; index >= 0; index -= 1) {
        candidate += stack[index] === '{' ? '}' : ']';
    }
    const repaired = parseJsonWithDiagnostics(candidate);
    return repaired.success
        ? { ...repaired, repairedText: candidate, repaired: true }
        : { success: false, value: null, error: repaired.error || parsed.error };
}

// Request repair of truncated JSON from Azure
function createJsonRepairPrompt(invalidJson) {
    return `Repair the supplied response into valid JSON only.
Preserve readable alert names, user emails, device names, source metrics, findings, risks, recommendations, business impact, and evidence references already present.
Keep internal IDs alongside readable entity names, never as replacements for them.
If the response was truncated, discard only the incomplete trailing value and close the JSON structure. No markdown, code fences, or text outside JSON.

INVALID RESPONSE:
${safeResponsePreview(invalidJson, 24000)}`;
}

function createEnterpriseIntelligenceService({
    pool,
    azureOpenAI,
    schedulerService,
    intelligenceService = null,
    onScheduledRunCompleted = null,
    onCompletedEnterpriseRun = null,
    logger = console,
    wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)),
    config = {}
} = {}) {
    if (!pool || !azureOpenAI || !schedulerService) throw new Error('Enterprise Intelligence requires database, Azure, and historical scheduler services');
    const completedRunPublisher = onCompletedEnterpriseRun || onScheduledRunCompleted;

    const configuredDomainDelayMs = Number(config.domainDelayMs ?? process.env.ENTERPRISE_AI_DOMAIN_DELAY_MS);
    const configuredMaxRetries = Number(config.maxRetries ?? process.env.ENTERPRISE_AI_MAX_RETRIES);

    const settings = Object.freeze({
        domainDelayMs: Math.max(0, Number.isFinite(configuredDomainDelayMs) ? configuredDomainDelayMs : DEFAULT_DOMAIN_DELAY_MS),
        // One short retry is enough for an interactive request. Further retries are persisted as a rate-limited run instead of holding the browser open.
        maxRetries: Math.min(1, Math.max(0, Number.isFinite(configuredMaxRetries) ? configuredMaxRetries : 1)),
        concurrency: 1,
        maxInputBytes: Math.min(DEFAULT_MAX_INPUT_BYTES, Math.max(50000, Number(config.maxInputBytes ?? process.env.ENTERPRISE_AI_MAX_INPUT_BYTES_PER_DOMAIN) || DEFAULT_MAX_INPUT_BYTES)),
        maxItemsPerBatch: Math.min(DEFAULT_MAX_ITEMS_PER_BATCH, Math.max(1, Number(config.maxItemsPerBatch ?? process.env.ENTERPRISE_AI_MAX_ITEMS_PER_BATCH) || DEFAULT_MAX_ITEMS_PER_BATCH)),
        heavyDomainMaxItemsPerBatch: Math.min(DEFAULT_HEAVY_DOMAIN_MAX_ITEMS_PER_BATCH, Math.max(1, Number(config.heavyDomainMaxItemsPerBatch ?? process.env.ENTERPRISE_AI_HEAVY_MAX_ITEMS_PER_BATCH) || DEFAULT_HEAVY_DOMAIN_MAX_ITEMS_PER_BATCH)),
        thresholdBatchMaxItems: Math.min(DEFAULT_THRESHOLD_BATCH_MAX_ITEMS, Math.max(1, Number(config.thresholdBatchMaxItems ?? process.env.ENTERPRISE_AI_THRESHOLD_MAX_ITEMS_PER_BATCH) || DEFAULT_THRESHOLD_BATCH_MAX_ITEMS)),
        maxDomainOutputTokens: Math.max(1000, Number(config.maxDomainOutputTokens ?? process.env.ENTERPRISE_AI_MAX_OUTPUT_TOKENS_PER_DOMAIN) || DEFAULT_DOMAIN_OUTPUT_TOKENS),
        maxSynthesisOutputTokens: Math.max(2000, Number(config.maxSynthesisOutputTokens ?? process.env.ENTERPRISE_AI_MAX_OUTPUT_TOKENS_SYNTHESIS) || DEFAULT_SYNTHESIS_OUTPUT_TOKENS),
        maxTotalTokens: Math.max(10000, Number(config.maxTotalTokens ?? process.env.ENTERPRISE_AI_MAX_TOTAL_TOKENS) || DEFAULT_MAX_TOTAL_TOKENS),
        requestTimeoutMs: Math.max(60000, Number(config.requestTimeoutMs ?? process.env.ENTERPRISE_AI_REQUEST_TIMEOUT_MS) || 180000),
        terminalStaleMs: Math.max(5 * 60 * 1000, Number(config.terminalStaleMs ?? process.env.ENTERPRISE_AI_TERMINAL_STALE_MS) || (30 * 60 * 1000)),
        snapshotTimeoutMs: Math.max(30 * 1000, Number(config.snapshotTimeoutMs ?? process.env.ENTERPRISE_AI_SNAPSHOT_TIMEOUT_MS) || (15 * 60 * 1000)),
        sourceRefreshTimeoutMs: Math.max(10 * 1000, Number(config.sourceRefreshTimeoutMs ?? process.env.STACKCTRL_SOURCE_REFRESH_TIMEOUT_MS) || (180 * 1000))
    });
    let rateLimitCircuitOpenUntil = 0;

    function openRateLimitCircuit(retryAfterMs) {
        const delayMs = Math.max(1000, Number(retryAfterMs) || ENTERPRISE_RATE_LIMIT_RETRY_MAX_MS);
        rateLimitCircuitOpenUntil = Math.max(rateLimitCircuitOpenUntil, Date.now() + delayMs);
        return delayMs;
    }

    function assertRateLimitCircuitClosed() {
        const retryAfterMs = rateLimitCircuitOpenUntil - Date.now();
        if (retryAfterMs <= 0) return;
        const error = new Error(`Enterprise Azure rate-limit circuit is open. Retry after ${Math.ceil(retryAfterMs / 60000)} minute(s).`);
        error.enterpriseStatus = 'failed_rate_limited';
        error.azureMetadata = { rateLimited: true, retryAfterMs };
        throw error;
    }

    function captureRateLimit(error) {
        const metadata = error?.azureMetadata || {};
        const message = String(error?.message || '').toLowerCase();
        if (!metadata.rateLimited && metadata.statusCode !== 429 && !message.includes('429') && !message.includes('throttl')) return false;
        openRateLimitCircuit(metadata.retryAfterMs ?? metadata.lastRetryDelayMs);
        error.enterpriseStatus = 'failed_rate_limited';
        return true;
    }

    async function loadSnapshot(companyId, snapshotId = null) {
        const where = snapshotId ? 'ID = ? AND CompanyID = ?' : 'CompanyID = ? ORDER BY ID DESC LIMIT 1';
        const params = snapshotId ? [Number(snapshotId), Number(companyId)] : [Number(companyId)];
        const [rows] = await pool.query(
            `SELECT ID, CompanyID, TenantKey, SnapshotType, PeriodStart, PeriodEnd,
                    SourceFreshnessJson, MetricsJson, ContextJson, DataCompletenessScore, CreatedAt
             FROM StackCTRLTenantEvidenceSnapshots WHERE ${where}`,
            params
        );
        if (!rows.length) throw new Error('Create a frozen StackCTRL snapshot before running Enterprise Deep Reporting');
        return rows[0];
    }

    async function loadKnowledge(domainKey) {
        try {
            const [rows] = await pool.query(
                `SELECT Title, SourceType, SourceUrl, ContentSummary, BestPracticeJson
                 FROM StackCTRLKnowledgeBase
                 WHERE DomainKey = ? AND IsActive = 1
                 ORDER BY UpdatedAt DESC, ID DESC LIMIT 20`,
                [domainKey]
            );
            return rows.map(row => ({
                title: row.Title,
                sourceType: row.SourceType,
                sourceUrl: row.SourceUrl,
                contentSummary: row.ContentSummary,
                bestPractices: safeValue(parseJson(row.BestPracticeJson, {}), 0, { maxArray: 20 })
            }));
        } catch (error) {
            if (error?.code !== 'ER_NO_SUCH_TABLE') throw error;
            return [];
        }
    }

    async function loadPreviousDomain(companyId, domainKey, currentRunId) {
        const [rows] = await pool.query(
            `SELECT ID, PeriodType, PeriodStart, PeriodEnd, HealthScore, RiskScore, RiskLevel,
                    DomainExecutiveSummary, BusinessImpact, CurrentPosture, FindingsJson,
                    RisksJson, RecommendationsJson, TrendAnalysisJson, ConfidenceScore, CreatedAt
             FROM StackCTRLTenantDomainIntelligence
             WHERE CompanyID = ? AND DomainKey = ? AND Status = 'completed' AND RunID <> ?
             ORDER BY ID DESC LIMIT 1`,
            [companyId, domainKey, currentRunId]
        );
        if (!rows[0]) return null;
        const row = rows[0];
        return {
            id: row.ID,
            periodType: row.PeriodType,
            periodStart: row.PeriodStart,
            periodEnd: row.PeriodEnd,
            healthScore: row.HealthScore,
            riskScore: row.RiskScore,
            riskLevel: row.RiskLevel,
            executiveSummary: row.DomainExecutiveSummary,
            businessImpact: row.BusinessImpact,
            currentPosture: row.CurrentPosture,
            topFindings: array(parseJson(row.FindingsJson, [])).slice(0, 10),
            topRisks: array(parseJson(row.RisksJson, [])).slice(0, 10),
            topRecommendations: array(parseJson(row.RecommendationsJson, [])).slice(0, 10),
            trends: array(parseJson(row.TrendAnalysisJson, [])).slice(0, 10),
            confidenceScore: row.ConfidenceScore,
            createdAt: row.CreatedAt
        };
    }

    function domainFromSnapshot(snapshot, domain) {
        const context = parseJson(snapshot.ContextJson, {}) || {};
        const metrics = parseJson(snapshot.MetricsJson, {}) || {};
        const sourceFreshness = parseJson(snapshot.SourceFreshnessJson, {}) || {};
        const snapshotFreshness = sourceFreshness[domain.sourceKey] || sourceFreshness[domain.key] || null;
        const rawSource = array(context.sources).find(item => item.sourceKey === domain.sourceKey) || {};
        const source = { ...rawSource };
        if (snapshotFreshness && typeof snapshotFreshness === 'object') {
            source.freshness = {
                ...(rawSource.freshness || {}),
                lastUpdated: snapshotFreshness.lastUpdated ?? rawSource.freshness?.lastUpdated ?? null,
                ageMinutes: snapshotFreshness.ageMinutes ?? rawSource.freshness?.ageMinutes ?? null
            };
            if (snapshotFreshness.status) source.status = snapshotFreshness.status;
        }
        if (domain.key === 'email_security' || domain.key === 'security_alerts') {
            const actualSourceLastUpdated = sourceLineageLastUpdated(source);
            if (actualSourceLastUpdated && !source.freshness?.lastUpdated) {
                const updatedAt = new Date(actualSourceLastUpdated).getTime();
                source.freshness = {
                    ...(source.freshness || {}),
                    lastUpdated: actualSourceLastUpdated,
                    ageMinutes: Number.isFinite(updatedAt) ? Math.max(0, Math.floor((Date.now() - updatedAt) / 60000)) : null
                };
            }
        }
        const risk = context.riskEngine || metrics.stackctrl_risk || {};
        const health = risk.domainHealthScores?.[domain.riskKey] ?? risk.executiveKPIs?.[domain.healthKey] ?? metrics.executive_kpis?.[domain.healthKey] ?? null;
        const riskScore = risk.domainRiskScores?.[domain.riskKey] ?? metrics.stackctrl_risk?.domainRiskScores?.[domain.riskKey] ?? null;
        const sourceEvidence = source.evidence && typeof source.evidence === 'object' ? source.evidence : [];
        const evidence = filterDomainEvidence(sourceEvidence, domain.key);
        const sourceMetrics = source.metrics || metrics[domain.sourceKey] || {};
        const dashboardMetrics = source.dashboardMetrics || {};
        const dashboardBackedDomains = DASHBOARD_BACKED_ENTERPRISE_DOMAINS;
        const currentMetrics = dashboardBackedDomains.includes(domain.key) && Object.keys(dashboardMetrics).length
            ? { ...sourceMetrics, ...dashboardMetrics }
            : sourceMetrics;
        return {
            context,
            source,
            metrics: currentMetrics,
            sourceMetrics,
            dashboardMetrics,
            calculatedIndicators: source.calculatedIndicators || {},
            evidence,
            healthScore: numberOrNull(health),
            riskScore: numberOrNull(riskScore),
            riskLevel: riskScore == null ? 'not_scored' : riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'moderate' : 'low'
        };
    }

    function historicalDomainContext(historicalContext, domain) {
        const result = {};
        for (const [key, comparison] of Object.entries(historicalContext?.comparisons || {})) {
            const snapshot = comparison?.snapshot;
            if (!snapshot) {
                result[key] = { availability: 'unavailable', warning: `No ${key} baseline is available.` };
                continue;
            }
            const baselineContext = snapshot.context || {};
            const baselineSource = array(baselineContext.sources).find(source => source.sourceKey === domain.sourceKey) || {};
            const baselineRisk = baselineContext.riskEngine || {};
            result[key] = {
                availability: comparison.availability,
                snapshotId: snapshot.snapshotId,
                createdAt: snapshot.createdAt,
                differenceMinutes: comparison.differenceMinutes,
                sourceStatus: baselineSource.status || null,
                metrics: safeValue(baselineSource.metrics || snapshot.metrics?.[domain.sourceKey] || {}, 0, { maxArray: 0, maxString: 800 }),
                healthScore: numberOrNull(baselineRisk.domainHealthScores?.[domain.riskKey] ?? baselineRisk.executiveKPIs?.[domain.healthKey]),
                riskScore: numberOrNull(baselineRisk.domainRiskScores?.[domain.riskKey]),
                metricChanges: safeValue(Object.fromEntries(Object.entries(comparison.metricChanges || {}).filter(([name]) =>
                    name.startsWith(`${domain.sourceKey}.`) || name.endsWith(`domainRiskScores.${domain.riskKey}`) || (domain.healthKey && name.endsWith(domain.healthKey))
                )), 0, { maxArray: 0 })
            };
        }
        return result;
    }

    async function buildDomainPackage({ companyId, snapshot, runId, domain, historicalContext, strictCompactSelectedDomain = true }) {
        const current = domainFromSnapshot(snapshot, domain);
        current.evidence = enrichDomainEvidence(current.source, domain, current.evidence);
        const useStrictCompactPackage = strictCompactSelectedDomain && STRICT_COMPACT_SELECTED_DOMAIN_KEYS.has(domain.key);
        const useSecurityAlertsCompactPackage = strictCompactSelectedDomain && domain.key === 'security_alerts';
        const knowledge = await loadKnowledge(domain.key);
        const previousAnalysis = await loadPreviousDomain(companyId, domain.key, runId);
        const evidenceForFlattening = domain.key === 'cloudflare_network_security'
            ? normalizeCloudflareEvidenceForFlatten(current.evidence)
            : current.evidence;
        const flattenedDomainEvidence = flattenDomainEvidence(evidenceForFlattening, { rootPath: `${domain.sourceKey}.evidence`, domainKey: domain.key });
        const flattenedEvidence = domain.key === 'identity'
            ? identityUserEvidenceRows(flattenedDomainEvidence)
            : domain.key === 'devices'
            ? deviceEvidenceRows(flattenedDomainEvidence)
            : useStrictCompactPackage && domain.key === 'email_security'
            ? compactEmailSecurityEvidenceRows(evidenceForFlattening, flattenedDomainEvidence, current)
            : useStrictCompactPackage && domain.key === 'cloudflare_network_security'
            ? cloudflareEvidenceRows(flattenedDomainEvidence, current)
            : useStrictCompactPackage && domain.key === 'backup'
            ? compactBackupEvidenceRows(flattenedDomainEvidence, current)
            : useStrictCompactPackage && domain.key === 'applications'
            ? compactApplicationsEvidenceRows(flattenedDomainEvidence)
            : useStrictCompactPackage && domain.key === 'governance'
            ? compactGovernanceEvidenceRows(flattenedDomainEvidence, current)
            : useStrictCompactPackage && domain.key === 'compliance'
            ? compactComplianceEvidenceRows(flattenedDomainEvidence, current)
            : useSecurityAlertsCompactPackage
            ? compactSecurityAlertsEvidenceRows(flattenedDomainEvidence, current)
            : flattenedDomainEvidence;
        const compactIdentityRows = domain.key === 'identity'
            ? flattenedEvidence.map((item, index) => compactIdentityEvidenceRow(item, index))
            : [];
        const compactDeviceRows = domain.key === 'devices'
            ? flattenedEvidence.map((item, index) => compactDeviceEvidenceRow(item, index))
            : [];
        const evidenceCatalog = buildEvidenceCatalog(evidenceForFlattening, domain, snapshot.ID);
        const stackCTRLDataCount = flattenedEvidence.length;
        const sourceEvidenceLineage = current.source.sourceLineage || {};
        const manualFilteredDomain = ['governance', 'compliance', 'operations'].includes(domain.key);
        const manualExcludedCount = manualFilteredDomain ? Number(sourceEvidenceLineage.manualRowsExcluded || sourceEvidenceLineage.omittedRecordCount || 0) : 0;
        const expectedRecordCount = useStrictCompactPackage || useSecurityAlertsCompactPackage
            ? stackCTRLDataCount
            : Number(sourceEvidenceLineage.evidenceRecordCount || evidenceCatalog.primaryTable?.count || stackCTRLDataCount);
        const evidenceOmittedCount = expectedRecordCount > stackCTRLDataCount
            ? expectedRecordCount - stackCTRLDataCount
            : 0;
        
        const base = {
            contextType: 'stackctrl_enterprise_domain_intelligence',
            strictCompactSelectedDomain: useStrictCompactPackage,
            securityAlertsCompactPackage: useSecurityAlertsCompactPackage,
            schemaVersion: 1,
            mode: domain.mode,
            companyId,
            snapshotId: Number(snapshot.ID),
            snapshotCreatedAt: snapshot.CreatedAt,
            domain: { key: domain.key, name: domain.name, focusAreas: domain.focus },
            sourceHealth: {
                sourceKey: domain.sourceKey,
                status: current.source.status || 'missing',
                isExpected: Boolean(current.source.isExpected),
                freshness: safeValue(current.source.freshness || {}, 0, { maxArray: 0 }),
                warnings: array(current.source.warnings)
                    .map(warning => cleanRuntimeWarningForDisplay(warning, { domain, current, hasUsableEvidence: stackCTRLDataCount > 0 }))
                    .filter(Boolean)
                    .slice(0, 20),
                errorMessage: current.source.errorMessage || current.source.sourceLineage?.errorMessage || current.source.sourceLineage?.incompleteReason || null,
                evidenceCount: stackCTRLDataCount
            },
            currentMetrics: safeValue(current.metrics, 0, { maxDepth: 7, maxArray: 10, maxString: 1200 }),
            dashboardMetrics: safeValue(current.dashboardMetrics, 0, { maxDepth: 6, maxArray: 10 }),
            calculatedIndicators: safeValue(current.calculatedIndicators, 0, { maxDepth: 6, maxArray: 10 }),
            authoritativeScores: { healthScore: current.healthScore, riskScore: current.riskScore, riskLevel: current.riskLevel },
            historicalComparisons: historicalDomainContext(historicalContext, domain),
            previousDomainAnalysis: previousAnalysis,
            knowledgeGrounding: knowledge,
            knowledgeWarning: knowledge.length ? null : `No curated ${domain.name} knowledge references are currently available.`,
            evidenceCatalog,
            evidence: [],
            limitations: {
                rawVendorPayloadIncluded: false,
                rawSnapshotContextIncluded: false,
                evidenceCompleteness: {
                    expectedEntityRows: expectedRecordCount,
                    includedEntityRows: stackCTRLDataCount,
                    omittedEntityRows: evidenceOmittedCount,
                    catalogCategories: evidenceCatalog.categoryCount,
                    catalogEntityRows: evidenceCatalog.catalogEntityCount,
                    manualRowsExcluded: manualExcludedCount,
                    complete: evidenceOmittedCount === 0 && stackCTRLDataCount > 0
                },
                missingDataWarnings: [
                    ...array(current.source.warnings)
                        .map(warning => cleanRuntimeWarningForDisplay(warning, { domain, current, hasUsableEvidence: stackCTRLDataCount > 0 }))
                        .filter(Boolean),
                    ...(manualExcludedCount > 0 ? [`${manualExcludedCount} manual evidence row(s) were intentionally excluded from Azure input; only API-connected evidence was prepared.`] : []),
                    ...(evidenceOmittedCount > 0 ? [`${evidenceOmittedCount} expected dashboard entity row(s) were not included in the Azure evidence payload.`] : []),
                    ...(!knowledge.length && !['identity', 'devices'].includes(domain.key) && !(COMPACT_SELECTED_DOMAIN_KEYS.has(domain.key) && stackCTRLDataCount > 0)
                        ? [`Curated ${domain.name} best-practice references were unavailable.`]
                        : [])
                ]
            }
        };
        if (domain.key === 'identity') {
            base.identityMetricsSummary = identityMetricsSummaryFromRows(compactIdentityRows, base);
            base.collectionWindow = compactIdentityCollectionWindow(base);
            base.missingDataInfo = [
                'Historical baseline not available yet for 7/30/90-day trend analysis.',
                ...(!knowledge.length ? ['Curated Identity Protection best-practice references unavailable.'] : [])
            ];
            base.limitations.missingDataInfo = base.missingDataInfo;
        }
        if (domain.key === 'devices') {
            base.deviceMetricsSummary = deviceMetricsSummaryFromRows(compactDeviceRows, base);
            base.collectionWindow = compactDeviceCollectionWindow(base);
            base.missingDataInfo = [
                ...(!knowledge.length ? ['Curated Device Protection references unavailable.'] : [])
            ];
            base.limitations.missingDataInfo = base.missingDataInfo;
        }

        const sourceLineageValues = {
            ...(DASHBOARD_BACKED_ENTERPRISE_DOMAINS.includes(domain.key)
                ? { ...current.sourceMetrics, ...current.dashboardMetrics }
                : current.metrics),
            healthScore: current.healthScore,
            riskScore: current.riskScore,
            'sourceHealth.evidenceCount': stackCTRLDataCount,
            snapshotId: Number(snapshot.ID),
            sourceLastUpdated: current.source.freshness?.lastUpdated || (['email_security', 'security_alerts'].includes(domain.key) ? sourceLineageLastUpdated(current.source) : snapshot.CreatedAt) || null
        };
        const inputLineageValues = {
            ...base.currentMetrics,
            healthScore: base.authoritativeScores.healthScore,
            riskScore: base.authoritativeScores.riskScore,
            'sourceHealth.evidenceCount': base.sourceHealth.evidenceCount,
            snapshotId: base.snapshotId,
            sourceLastUpdated: base.sourceHealth.freshness?.lastUpdated || (['email_security', 'security_alerts'].includes(domain.key) ? sourceLineageLastUpdated(current.source) : base.snapshotCreatedAt) || null
        };
        const lineageFields = domain.key === 'identity'
            ? IDENTITY_LINEAGE_FIELDS
            : domain.key === 'devices'
            ? DEVICE_LINEAGE_FIELDS
            : domain.key === 'email_security'
            ? EMAIL_LINEAGE_FIELDS
            : domain.key === 'cloudflare_network_security'
            ? NETWORK_LINEAGE_FIELDS
            : domain.key === 'backup'
            ? BACKUP_LINEAGE_FIELDS
            : domain.key === 'applications'
            ? APPLICATIONS_LINEAGE_FIELDS
            : domain.key === 'security_alerts'
            ? SECURITY_LINEAGE_FIELDS
            : domain.key === 'governance'
            ? GOVERNANCE_LINEAGE_FIELDS
            : domain.key === 'compliance'
            ? COMPLIANCE_LINEAGE_FIELDS
            : domain.key === 'operations'
            ? OPERATIONS_LINEAGE_FIELDS
            : [...new Set([...Object.keys(sourceLineageValues), ...Object.keys(inputLineageValues)])];
        const sourceAlignment = buildDataLineageComparison({
            fields: lineageFields,
            sourceValues: sourceLineageValues,
            inputValues: inputLineageValues
        });
        base.dataLineage = {
            sourceKey: domain.sourceKey,
            sourceBuilder: current.source.sourceLineage?.sourceBuilder || (
                domain.key === 'identity' ? 'identityDashboardContext'
                    : domain.key === 'devices' ? 'deviceDashboardContext'
                    : domain.key === 'email_security' ? 'emailSecurityDashboardContext'
                    : domain.key === 'cloudflare_network_security' ? 'cloudflareDashboardContext'
                    : domain.key === 'backup' ? 'backupDashboardContext'
                    : domain.key === 'applications' ? 'applicationsDashboardContext'
                    : domain.key === 'security_alerts' ? 'securityAlertsDashboardContext'
                    : domain.key === 'governance' ? 'governanceDashboardContext'
                    : domain.key === 'compliance' ? 'complianceDashboardContext'
                    : domain.key === 'operations' ? 'operationsDashboardContext'
                    : 'dashboardContext'
            ),
            sourceLayer: current.source.sourceLineage?.sourceLayer || 'tenant_evidence_snapshot.dashboardMetrics',
            evidenceSnapshotId: current.source.sourceLineage?.evidenceSnapshotId || null,
            evidenceCollectedAt: current.source.sourceLineage?.collectedAt || null,
            sourceFetchedAt: current.source.sourceLineage?.sourceFetchedAt || null,
            sourceEndpoint: current.source.sourceLineage?.sourceEndpoint || null,
            collectionTrigger: current.source.sourceLineage?.collectionTrigger || null,
            collectionStatus: current.source.sourceLineage?.collectionStatus || null,
            evidenceIsComplete: current.source.sourceLineage?.isComplete ?? null,
            totalRows: current.source.sourceLineage?.totalRows ?? stackCTRLDataCount,
            apiConnectedRows: current.source.sourceLineage?.apiConnectedRows ?? stackCTRLDataCount,
            manualRowsExcluded: current.source.sourceLineage?.manualRowsExcluded ?? 0,
            evidenceRecordCount: current.source.sourceLineage?.evidenceRecordCount ?? stackCTRLDataCount,
            evidenceOmittedRecordCount: current.source.sourceLineage?.omittedRecordCount ?? 0,
            incompleteReason: current.source.sourceLineage?.incompleteReason || null,
            errorMessage: current.source.sourceLineage?.errorMessage || null,
            sourceName: domain.name,
            sourceLastUpdated: sourceLineageValues.sourceLastUpdated,
            sourceAge: current.source.freshness?.ageMinutes,
            sourceAgeLabel: current.source.freshness?.ageMinutes != null ? `${Math.floor(current.source.freshness.ageMinutes / 60)} hour(s) ${current.source.freshness.ageMinutes % 60} minute(s)` : null,
            sourceStatus: current.source.status || 'unknown',
            sourceIsStale: current.source.status === 'stale',
            snapshotId: Number(snapshot.ID),
            runId: Number(runId),
            rows: sourceAlignment.rows
        };

        // For batching: don't permanently reduce evidence, just use what we have
        const inputSizeBytes = bytes(base);
        const batchPlan = buildEvidenceBatchPlan(flattenedEvidence, splitIntoBatches(flattenedEvidence, {
            maxItems: domain.key === 'identity'
                ? IDENTITY_MAX_ITEMS_PER_BATCH
                : domain.key === 'devices'
                ? DEVICE_MAX_ITEMS_PER_BATCH
                : domain.key === 'cloudflare_network_security'
                ? CLOUDFLARE_MAX_ITEMS_PER_BATCH
                : useStrictCompactPackage || useSecurityAlertsCompactPackage
                ? SELECTED_DOMAIN_MAX_ITEMS_PER_BATCH
                : settings.maxItemsPerBatch,
            maxBytes: settings.maxInputBytes
        }));
        return {
            package: base,
            current,
            allEvidence: flattenedEvidence,
            evidenceCatalog,
            sourceAlignment,
            audit: {
                stackCTRLDataCount,
                preparedForAzureCount: flattenedEvidence.length,
                sentToAzureCount: 0, // Successfully analysed by Azure; updated after completed batches
                omittedCount: manualExcludedCount,
                metricsIncludedCount: primitiveMetricCount(base.currentMetrics) + primitiveMetricCount(base.dashboardMetrics) + primitiveMetricCount(base.calculatedIndicators),
                evidenceIncludedCount: stackCTRLDataCount,
                evidenceOmittedCount,
                catalogEntityCount: evidenceCatalog.catalogEntityCount,
                catalogCategoryCount: evidenceCatalog.categoryCount,
                historicalComparisonsIncluded: Object.values(base.historicalComparisons).filter(item => item.availability === 'available').length,
                inputSizeBytes,
                batchPlan,
                evidenceSample: flattenedEvidence.slice(0, 5).map(item => ({
                    internalSourcePath: item.internalSourcePath,
                    sourceLabel: item.sourceLabel,
                    evidenceType: item.evidenceType,
                    entityKey: item.entityKey || null
                }))
            }
        };
    }

    function securityAlertsBatchPrompt(packageValue) {
        return `Analyse this compact Security Alerts selected-domain package. Return valid JSON only; no markdown.
Use only the supplied compact evidence groups: summaryMetrics, criticalAlerts, highSeverityAlerts, activeIncidents, suspiciousSignIns, anonymousIpEvents, threatIndicators, repeatedAlertPatterns, affectedUsers, affectedDevices, unresolvedAlerts, recentResolvedAlerts, recommendations.
Do not request omitted raw alerts and do not echo raw full JSON. Each compact row is already readable and Power BI-ready.
Return only real operational/security risks in risks[]. Put positive observations, such as no critical alerts or resolved alerts, in keyFindings[], currentPosture, or scoreJustification.
Keep output compact: risks max 5, recommendations max 5, evidenceUsed max 5, technicalReasoning max 5 short objects.
Affected entities must match the risk's sourceMetric and evidence group. Use entityType User, Device, Incident, SignInEvent, or IPAddress where the evidence supports it. Do not attach the same unrelated users/devices to every risk.
Each finding, risk, recommendation, and management action should use these fields when relevant:
title, severity, category, status, sourceDomain, sourceMetric, sourceMetrics, snapshotId, evidenceSource,
sourceAlertIds, affectedEntities, affectedEntityIds, evidenceRows, recordIds, whatHappened, whyItMatters, businessImpact,
recommendedAction, recommendedActions, suggestedOwner, suggestedDueDate, patternFound, reasoning, firstAction, followUpAction, managementDecisionRequired, whatCanWait.
Every affectedEntities object must include entityId, entityName, entityType, sourceDomain, sourceMetric, businessReason, and recommendation. Include readable user email, device name, incident name, alert name, or IP address where present. IDs may supplement readable evidence but must never replace it. For every numerical entity claim, return every matching affectedEntityId and recordId from the supplied evidence; never return a representative sample. sourceMetric is a label, not evidence that every record in its category supports the finding.
Use source paths only in internalSourcePath, debugSourcePath, or auditTrace.sourcePath. Never place source paths in affectedEntities, affectedEntityIds, recordIds, or sourceAlertIds.
Return exactly:
{
  "domainExecutiveSummary": "one compact sentence",
  "technicalReasoning": [],
  "riskPrioritization": [],
  "technicalSummary": "",
  "currentPosture": "",
  "highestRiskPatterns": [],
  "keyFindings": [],
  "risks": [],
  "recommendations": [],
  "managementDecisionsRequired": [],
  "whatCanWait": [],
  "businessImpact": "",
  "controlAssessment": [],
  "managementActions": [],
  "trendAnalysis": [],
  "evidenceUsed": [],
  "evidenceGaps": [],
  "scoreJustification": "",
  "affectedEntities": [],
  "missingDataWarnings": [],
  "assumptions": [],
  "confidenceScore": null,
  "evidenceLimitations": {}
}
Prioritize accurate evidence, clear findings, risks, recommendations, business impact, and exact source references. Do not invent entities or convert healthy posture into risks. Omit null and empty visible fields.

STACKCTRL SECURITY ALERTS BATCH:
${JSON.stringify(packageValue)}`;
    }

function domainReasoningContract(domain) {
        if (domain.key === 'identity') {
            return `
Identity Protection reasoning requirements:
- Reason about combinations of evidence, not only user counts. Explain why privileged MFA gaps outrank normal-user MFA gaps.
- Critical: Global Admin/privileged/break-glass account without MFA; privileged user with risky sign-in signals.
- High: multiple privileged roles; external user without MFA; active user without MFA and recent sign-in activity.
- Medium: normal user without MFA; inactive account needing review; unknown sign-in/device information.
- Low: MFA enabled, active, no privileged role, no risk signals.
- Explicitly compare admin role + no MFA; admin role + no MFA + inactive account; privileged account + unknown location/device; external user + missing MFA; multiple privileged roles; disabled/inactive users with or without privileged access.
- Separate normal users without MFA from privileged users without MFA. State that MFA coverage matters, but privileged MFA coverage matters more.
- Identity affectedEntities must include entityId, entityName, entityEmail, entityType "User", userPrincipalName, roles, hasAdminRole, mfaEnabled, riskLevel, accountStatus, lastSignIn, businessReason, recommendation.`;
        }
        if (domain.key === 'devices') {
            return `
Device Protection reasoning requirements:
- Reason about combinations of device evidence, not only device counts. Separate compliance risk from encryption coverage.
- Critical: non-compliant + stale/dead over 30 days + assigned user; unmanaged device with active user or unknown compliance.
- High: non-compliant but recently synced; high-risk device with user assignment; device with security alerts.
- Medium: compliant but stale; missing encryption status; unknown owner/user.
- Low: compliant, encrypted, managed, recently synced.
- Explicitly compare non-compliant + stale/dead versus non-compliant alone; non-compliant + assigned user business exposure; stale but compliant hygiene risk; encrypted + managed + recently synced lower priority; unmanaged or unknown management state; old sync dates showing policies may not apply.
- Distinguish actions: remediate, block, retire, or investigate. Include what can wait, e.g. encrypted and MDM-managed devices are not the immediate crisis when a smaller stale non-compliant group exists.
- Device affectedEntities must include entityId, entityName, entityType "Device", entityDeviceName, assignedUser, operatingSystem, osVersion, complianceState, encryptionState, managementState, lastSyncDateTime, lastSyncDaysAgo, riskLevel, businessReason, recommendation.`;
        }
        if (domain.key === 'email_security') {
            return `
Email Security reasoning requirements:
- Treat prepared StackCTRL email records as valid evidence. Azure rate limits are processing failures, not data failures.
- Keep output compact: risks max 5, recommendations max 5, evidenceUsed max 5, technicalReasoning max 5 short bullet objects.
- Reason from patterns such as high-severity alerts, unresolved incidents, phishing/malware/BEC clusters, affected users, repeated senders/domains, and response posture.
- Return only real risks in risks[]. Put positive observations in keyFindings[] or currentPosture. Do not mention missing curated references as risks, findings, recommendations, affected entities, or warnings when Email evidence exists.
- Use one to two sentences for reasoning fields. Prefer short action language over long narrative.
- Affected entities must show readable alert names, incident names, user emails, sender/domain labels, and sourceMetric. IDs may be references only.`;
        }
        if (domain.key === 'cloudflare_network_security') {
            return `
Cloudflare Network Security reasoning requirements:
- Produce readable business intelligence, not generic Cloudflare prose.
- Analyse protected apps, Cloudflare devices, gateway policies, access policies, access logs, DLP profiles, WARP profiles, endpoint/API permission families, Cloudflare audit logs, Gateway app catalog evidence, and section errors/missing controls when present.
- Show real protected application names, policy names, device names, access decision labels, DLP profile names, WARP profile names, and readable risk reasons.
- Keep affectedEntities and evidenceRows relevant only to each risk; do not attach unrelated Cloudflare rows to every finding. Use sourceMetric protectedApps only for protected applications, enrolledDevices/registeredWarpDevices for devices, gatewayPolicies for gateway rules, dlpProfiles for DLP, warpProfiles for WARP, appCategories for Gateway app catalog, endpointFamilies for API permission-family coverage, and auditLogs for audit log coverage.
- coverageSummaries rows are evidence-grade accounting rows: use them to report confirmed counts, sampling, and raw-evidence gaps. Do not invent individual audit/access/account log events when the coverage row says count_only_no_raw_rows.
- Return only real risks in risks[]. Put positive observations in keyFindings[] or currentPosture. Do not mention missing curated references as risks, findings, recommendations, affected entities, or warnings when Cloudflare evidence exists.
- Use affected entities only from the matching evidence group; max 5 risks, and omit null/empty visible fields.
- Do not expose internal source paths visibly. Use internalSourcePath/internalSourcePaths only for traceability.`;
        }
        if (domain.key === 'backup') {
            return `
Backup & Recovery reasoning requirements:
- Treat Microsoft 365 storage/activity rows as backup exposure context, not one risk per user, site, mailbox, or file event.
- Focus on large data holders, inactive users holding recoverable data, stale activity, service-level storage exposure, missing external backup coverage, restore posture, and management actions.
- Use affected entities only from the matching evidence group: large data holder risks use topStorageUsers, inactive data holder risks use inactiveDataHolders, stale activity risks use staleActivityUsers, SharePoint/site risks use topSharePointSites, and coverage validation risks use backupCoverageGaps only.
- Do not create risks for positive observations such as a 100% backup coverage score; place them in keyFindings[], currentPosture, or scoreJustification. Do not mention missing curated references as risks/findings.
- Keep output compact: risks max 5, recommendations max 5, evidenceUsed max 5, and one to two sentences per reasoning field.`;
        }
        if (domain.key === 'applications') {
            return `
Applications reasoning requirements:
- Treat prepared application groups as governance evidence, not one risk per app.
- Focus on shadow IT, external publishers, broad permissions, unused/stale apps, consent risk, ownership/review gaps, and management decisions.
- Use affected entities only from the matching evidence group: external publisher/vendor/shadow IT risks use externalApps, excessive permission risks use excessivePermissionApps, high-access risks use highAccessApps, group-assigned risks use groupAssignedApps, and stale/unreviewed risks use staleOrUnreviewedApps.
- Do not create risks for positive or neutral observations such as no users assigned, no group-assigned or high-access apps detected, or missing curated references; place useful positives in keyFindings[], currentPosture, or scoreJustification.
- Keep output compact: risks max 5, recommendations max 5, evidenceUsed max 5, and one to two sentences per reasoning field.`;
        }
        if (domain.key === 'governance') {
                return `
            Governance reasoning requirements:
            - Governance is a management, accountability, ownership, review, escalation, and decision layer. Do not treat it as a raw technical scan.
            - Use only supplied StackCTRL Governance evidence. Do not invent owners, policies, control names, review dates, management decisions, or entities.
            - Focus on risk ownership, missing owners, overdue/attention-required items, admin/access review evidence, policy review gaps, unresolved issues requiring escalation, and decisions required by management.
            - Every governance finding must cite a real sourceDomain/sourceMetric and at least one affected entity where supplied.
            - Every risk must include entityId, entityName, entityType, ownerStatus, governanceIssue, businessImpact, managementAction, evidenceReference, sourceDomain, sourceMetric, and suggestedDueDate where possible.
            - Do not create generic governance advice without evidence. If evidence is missing or stale, report it as a limitation or manual-review item.
            - Put positive observations in keyFindings[] or currentPosture, not risks[].
            - Keep output compact: risks max 5, recommendations max 5, managementActions max 5.`;
        }
        if (domain.key === 'compliance') {
            return `
            Compliance Validation reasoning requirements:
            - Compliance is a control-validation and audit-readiness layer. Do not treat it as a generic risk scan.
            - Use only supplied StackCTRL Compliance evidence. Do not invent control names, frameworks, certification status, audit claims, owners, or evidence.
            - Classify controls as passed, failed, partial, or manual_review_required based only on supplied evidence.
            - Missing, stale, weak, unknown, or manually excluded evidence must become partial or manual_review_required. Never mark a control as passed without supplied API-connected evidence.
            - Focus on failed controls, partial controls, manual-review controls, evidence gaps, audit impact, remediation actions, and evidence references.
            - Every control result must include controlId, controlName, controlCategory, status, severity, sourceDomain, sourceMetric, evidenceReference, validationReason, remediationAction, auditImpact, and dueDateRecommendation where supplied.
            - Every risk must be tied to failed, partial, or manual-review controls. Positive control observations belong in keyFindings[], passedControls[], or currentPosture, not risks[].
            - Do not claim regulatory compliance, certification, or audit readiness beyond the supplied StackCTRL evidence.
            - Keep output compact: risks max 5, recommendations max 5, remediationActions max 5.`;
        }
        return '';
}

function domainOutputSchema(domain) {
    if (domain.key === 'compliance') {
        return `{
            "domainExecutiveSummary": "",
            "executiveComplianceSummary": "",
            "technicalReasoning": [],
            "riskPrioritization": [],
            "technicalSummary": "",
            "currentPosture": "",
            "auditReadinessStatus": "",
            "complianceScore": null,
            "highestRiskPatterns": [],
            "keyFindings": [],
            "controlResults": [],
            "passedControls": [],
            "failedControls": [],
            "partialControls": [],
            "manualReviewControls": [],
            "risks": [],
            "recommendations": [],
            "remediationActions": [],
            "evidenceReferences": [],
            "managementDecisionsRequired": [],
            "whatCanWait": [],
            "businessImpact": "",
            "evidenceUsed": [],
            "evidenceGaps": [],
            "evidenceLimitations": {},
            "scoreJustification": "",
            "affectedEntities": [],
            "collectionWindow": {},
            "missingDataInfo": [],
            "missingDataWarnings": [],
            "controlAssessment": {},
            "trendAnalysis": [],
            "yesterdayVsToday": {},
            "whatImproved": [],
            "whatDeteriorated": [],
            "whatStayedTheSame": [],
            "assumptions": [],
            "confidenceScore": null,
            "managementActions": [],
            "powerBiSummary": {}
            }`;
                }

                if (!['identity', 'devices', ...STRICT_COMPACT_SELECTED_DOMAIN_KEYS].includes(domain.key)) {
                    return `{
            "domainExecutiveSummary": "",
            "technicalSummary": "",
            "businessImpact": "",
            "currentPosture": "",
            "evidenceUsed": [],
            "evidenceGaps": [],
            "scoreJustification": "",
            "controlAssessment": {},
            "keyFindings": [],
            "risks": [],
            "recommendations": [],
            "trendAnalysis": [],
            "yesterdayVsToday": {},
            "whatImproved": [],
            "whatDeteriorated": [],
            "whatStayedTheSame": [],
            "missingDataWarnings": [],
            "assumptions": [],
            "confidenceScore": null,
            "managementActions": [],
            "powerBiSummary": {},
            "evidenceLimitations": {}
            }`;
                }

                return `{
            "domainExecutiveSummary": "",
            "technicalReasoning": [],
            "riskPrioritization": [],
            "technicalSummary": "",
            "currentPosture": "",
            "highestRiskPatterns": [],
            "keyFindings": [],
            "risks": [],
            "recommendations": [],
            "managementDecisionsRequired": [],
            "whatCanWait": [],
            "businessImpact": "",
            "evidenceUsed": [],
            "evidenceGaps": [],
            "evidenceLimitations": {},
            "scoreJustification": "",
            "affectedEntities": [],
            "collectionWindow": {},
            "missingDataInfo": [],
            "missingDataWarnings": [],
            "controlAssessment": {},
            "trendAnalysis": [],
            "yesterdayVsToday": {},
            "whatImproved": [],
            "whatDeteriorated": [],
            "whatStayedTheSame": [],
            "assumptions": [],
            "confidenceScore": null,
            "managementActions": [],
            "powerBiSummary": {}
            }`;
}

    function domainPrompt(domain, packageValue) {
        if (domain.key === 'security_alerts' && packageValue?.batchMetadata) {
            return securityAlertsBatchPrompt(packageValue);
        }
        const richReasoning = ['identity', 'devices', ...STRICT_COMPACT_SELECTED_DOMAIN_KEYS].includes(domain.key);
        const compactOutput = COMPACT_SELECTED_DOMAIN_KEYS.has(domain.key);
        const reasoningContract = domainReasoningContract(domain);
        return `You are StackCTRL Enterprise Intelligence. Analyse only the supplied frozen StackCTRL ${domain.name} package.
Azure builds structured enterprise intelligence; Power BI builds the final report. Do not create layouts, visuals, HTML, dashboard instructions, or Power BI files.
Do not claim direct access to Microsoft Graph, Cloudflare, or another vendor. Do not invent missing controls or evidence.
Every posture claim must identify supporting evidence, assessed areas, confirmed controls, unknown controls, gaps, movement, business impact, and recommended action.
StackCTRL authoritative scores must be justified but never recalculated or replaced.

Use BOTH summary metrics and entity-level evidence:
- currentMetrics, dashboardMetrics, and calculatedIndicators provide executive counts and scores.
${domain.key === 'identity'
    ? '- Identity evidence[] is a compact table. Each row already contains the readable user, MFA, authentication, risk, account, sign-in, location, device, role, and key-flag fields needed for analysis. Do not request or infer omitted dashboard/catalog/history objects.'
    : domain.key === 'devices'
    ? '- Device evidence[] is a compact table. Each row already contains readable device name, assigned user, OS, compliance, encryption, management, sync age, risk, alert count, and issue-flag fields. Reason over device posture patterns; do not repeat rows or request omitted catalog/history objects.'
    : domain.key === 'email_security'
    ? '- Email Security evidence[] contains compact threat-focused rows: security alerts, targeted users, high-volume/inactive mailbox context, mailflow summary, and evidence samples. Mailflow is summary context only, not individual threat evidence; rate limits are Azure processing failures, not evidence omissions.'
    : domain.key === 'cloudflare_network_security'
    ? '- Cloudflare evidence[] contains prepared protected apps, devices, gateway policies, access policies/logs, DLP profiles, WARP profiles, and section status/errors when present. Use readable names from each row.'
    : domain.key === 'backup'
    ? '- Backup evidence[] contains compact exposure groups: top storage users, inactive data holders, stale activity users, top SharePoint sites, service storage summary, coverage gaps, and recommendations. Do not request omitted raw storage/activity rows.'
    : domain.key === 'applications'
    ? '- Applications evidence[] contains compact governance groups: high-risk, external, excessive-permission, high-access, group-assigned, stale/unreviewed apps, and recommendations. Do not request omitted raw application rows.'
    : domain.key === 'governance'
    ? '- Governance evidence[] contains compact management, ownership, review, escalation, and accountability rows. Treat it as a management-control layer, not a raw technical scan.'
    : domain.key === 'compliance'
    ? '- Compliance evidence[] contains compact control-validation rows: summary metrics, failed controls, partial controls, manual-review controls, passed controls, remediation actions, and evidence references. Treat missing or weak evidence as partial/manual-review, not as passed.'
    : '- evidenceCatalog.categories contains categorized dashboard entity rows tied to sourceMetric keys.'}
- evidence[] contains individual entity rows from the StackCTRL dashboard table for this batch.
Every finding, risk, and recommendation MUST be evidence-backed. Do not state a gap without naming affected users, devices, apps, controls, policies, alerts, or other entities from the supplied evidence.
Visible output must be human-readable. Include userPrincipalName/email, device display name, alert title/display name, application/control/policy name, or another useful entity label whenever supplied. Keep internal IDs as evidence references alongside those names; never return an ID as the only description of an affected entity.
Every affectedEntities object must include entityId, entityName, entityType, sourceDomain, sourceMetric, businessReason, and recommendation. For every numerical claim about people, devices, apps, controls, alerts, policies, or other entities, return the complete matching affectedEntityIds and recordIds from the supplied evidence; do not return a sample. sourceMetric is a metric label, never proof that every record in a category supports the finding. If complete links are unavailable, state the evidence limitation and do not make an entity-level count claim. Use source paths only in internalSourcePath, debugSourcePath, or auditTrace.sourcePath; never use them as entity IDs, record IDs, alert IDs, or visible names.
${reasoningContract}
${richReasoning ? `
For this selected-domain analysis, move beyond Metric -> Risk -> Recommendation. Produce: Pattern -> Reasoning -> Priority -> Evidence -> Action -> Business decision.
Use these shared reasoning sections: domainExecutiveSummary, technicalReasoning, riskPrioritization, currentPosture, highestRiskPatterns, keyFindings, risks, recommendations, managementDecisionsRequired, whatCanWait, businessImpact, evidenceUsed, evidenceLimitations, scoreJustification, affectedEntities, collectionWindow, missingDataInfo.
Every risk must include: patternFound, reasoning, whyThisIsHighPriority, whyThisIsWorseThanLowerPriorityIssues, affectedEntities, evidenceUsed, firstAction, followUpAction, businessImpact, managementDecisionRequired, whatCanWait, recommendedOwner, suggestedDueDate.
Do not hardcode generic risks. Infer patterns and priorities from supplied evidence rows and summary metrics only.` : ''}
${compactOutput ? `
Compact narrative limits are mandatory: risks max 5; recommendations max 5; evidenceUsed max 5; technicalReasoning max 5 short bullet objects; no long paragraphs; reasoning fields one to two short sentences. These limits NEVER apply to explicit evidence links: for a numerical finding, return every matching affectedEntityId and recordId from the supplied evidence, and retain the matching affectedEntities/evidenceRows rather than a representative sample.` : ''}
${STRICT_COMPACT_SELECTED_DOMAIN_KEYS.has(domain.key) ? `
Selected-domain polish rules are mandatory: risks[] must contain only real risks; put positive/neutral observations in keyFindings[] or currentPosture; do not mention missing curated references as risks/findings/recommendations/warnings when evidence exists; do not duplicate the same affectedEntities across unrelated risks; keep evidenceRows matched to the risk's sourceMetric; omit null and empty visible fields.` : ''}

Return valid JSON only. No markdown. No code fences. No explanations outside JSON.
Return exactly these fields:
${domainOutputSchema(domain)}

Finding fields: title, description, severity, status, whatHappened, whyItMatters, businessImpact, businessReason, evidenceSummary, affectedEntities, affectedEntityIds, evidenceRows, recordIds, internalSourcePaths, sourceDomain, sourceMetric, snapshotId, evidenceSource, suggestedOwner, suggestedDueDate.
Risk fields: riskId, title, description, severity, likelihood, impact, patternFound, reasoning, whyThisIsHighPriority, whyThisIsWorseThanLowerPriorityIssues, whatHappened, whyItMatters, businessImpact, businessReason, evidenceUsed, evidenceSummary, affectedEntities, affectedEntityIds, evidenceRows, recordIds, internalSourcePaths, sourceDomain, sourceMetric, snapshotId, evidenceSource, recommendation, firstAction, followUpAction, managementDecisionRequired, whatCanWait, recommendedOwner, suggestedOwner, suggestedDueDate.
Recommendation/action fields: recommendationId, title, detail, priority, reasoning, whatHappened, whyItMatters, businessImpact, businessReason, recommendedAction, firstAction, followUpAction, managementDecisionRequired, whatCanWait, recommendedOwner, affectedEntities, affectedEntityIds, evidenceRows, recordIds, internalSourcePaths, sourceDomain, sourceMetric, snapshotId, evidenceSource, suggestedOwner, suggestedDueDate.
Control assessment items and trend fields must retain readable entity labels and the matching IDs whenever evidence exists.
Trend fields additionally include: metricName, currentValue, previousValue, changePercent, direction, comparisonPeriod, explanation.
evidenceUsed items: label, sourceMetric, entityCount, snapshotId, evidenceSource.
evidenceGaps items: gap, reason, omittedCount, sourceMetric.
evidenceLimitations: recordsSent, recordsOmitted, batchNumber, totalBatches, complete, omittedReasons.
Use empty arrays, objects, or null when evidence is unavailable. Clearly state limitations instead of filling gaps with assumptions.
Keep explanations clear and concise enough to return valid JSON for this smaller batch. Do not use markdown.

STACKCTRL DOMAIN PACKAGE:
${JSON.stringify(packageValue)}`;
    }

function synthesisPrompt(packageValue) {
    return `You are StackCTRL Enterprise Intelligence. Create the FINAL enterprise synthesis from stored successful domain intelligence only.

Azure creates structured intelligence. Power BI creates visuals. Do not create Power BI layouts, pages, styling, report files, HTML, or visual design instructions.

CRITICAL RULES:
- Do not repeat domain outputs one after another.
- Do not invent facts, entities, controls, incidents, scores, vendors, owners, or dates.
- Do not use raw vendor payloads.
- Do not recalculate StackCTRL health, risk, governance, compliance, or maturity scores.
- Use the domain outputs as ingredients and create the executive enterprise meaning.
- Connect related risks across domains into enterprise risk themes and risk chains.
- Governance and Compliance Validation are active if present in domainIntelligence.
- Operations is temporarily disabled and must only appear as a limitation, not as an analysed domain.
- Prefer concise decision-ready wording over long narrative.
- Every row-based item must preserve domain traceability using domainKey, sourceDomain, or sourceDomains.
- Keep the response compact enough to avoid truncation.

FINAL SYNTHESIS QUALITY BAR:
The final synthesis must answer:
1. What is the real enterprise risk?
2. Which risks are connected across domains?
3. What should leadership do first?
4. What requires management decision?
5. What can wait?
6. What evidence supports this?
7. What is the audit/compliance readiness position?
8. What should Power BI show as final report data?

Return valid JSON only. No markdown. No code fences. No explanations outside JSON.

Return exactly these top-level fields:
    {
    "enterpriseExecutiveSummary": {},
    "boardReport": {},
    "managementReport": {},
    "riskRegister": [],
    "recommendations": [],
    "trendAnalysis": [],
    "complianceReview": {},
    "governanceReview": {},
    "domainScorecard": [],
    "maturityAssessment": {},
    "businessImpactSummary": "",
    "topDecisionsRequired": [],
    "next30DaysPlan": [],
    "next90DaysPlan": [],
    "evidenceJustificationSummary": {},
    "limitationsAndAssumptions": [],
    "powerBiSummary": {}
    }

    FIELD CONTRACT:

    enterpriseExecutiveSummary:
    {
    "summary": "Maximum 5 sentences. Board-ready final enterprise story.",
    "enterpriseRiskNarrative": "Explain the strongest cross-domain risk pattern, not each domain separately.",
    "overallPosture": "stable | improving | declining | exposed | critical | unknown",
    "primaryEnterpriseConcern": "",
    "mostImportantAction": "",
    "confidence": "high | medium | low",
    "activeDomainsUsed": [],
    "knownLimitations": []
    }

    boardReport:
    {
    "boardSummary": "",
    "boardRisks": [],
    "boardActions": [],
    "decisionsRequired": [],
    "next30DaysFocus": [],
    "next90DaysFocus": [],
    "riskLevel": "",
    "riskScore": null,
    "messageToBoard": "Use business language, not technical dashboard wording."
    }

    managementReport:
    {
    "managementNarrative": "",
    "crossDomainRiskChains": [
        {
        "chainId": "chain-1",
        "title": "",
        "enterpriseTheme": "",
        "sourceDomains": [],
        "linkedFindings": [],
        "businessImpact": "",
        "whyItMatters": "",
        "managementDecisionRequired": "",
        "recommendedAction": "",
        "confidence": "high | medium | low"
        }
    ],
    "managementActions": [],
    "whatMustBeDoneNow": [],
    "whatCanWait": [],
    "ownershipGaps": [],
    "escalationRequired": []
    }

    riskRegister:
    Return maximum 8 ranked enterprise risks. Do not list every domain risk.
    Each risk must include:
    {
    "riskId": "enterprise-risk-1",
    "title": "",
    "enterpriseTheme": "",
    "severity": "critical | high | medium | low",
    "likelihood": "",
    "impact": "",
    "priorityRank": 1,
    "sourceDomains": [],
    "sourceDomain": "enterprise",
    "businessImpact": "",
    "description": "",
    "whyItMatters": "",
    "managementDecisionRequired": "",
    "recommendedAction": "",
    "evidenceRows": [],
    "affectedEntities": [],
    "confidence": "high | medium | low"
    }

    recommendations:
    Return maximum 12 recommendations. These must be final enterprise actions, not repeated domain suggestions.
    Each recommendation must include:
    {
    "recommendationId": "enterprise-rec-1",
    "title": "",
    "priority": "critical | high | medium | low",
    "sourceDomain": "enterprise",
    "sourceDomains": [],
    "businessReason": "",
    "recommendedAction": "",
    "suggestedOwner": "",
    "suggestedDueDate": null,
    "dependsOn": [],
    "evidenceRows": [],
    "affectedEntities": []
    }

    trendAnalysis:
    Use historical/lower-period reports only when supplied. If not supplied, say baseline unavailable.
    Return maximum 8 rows.

    complianceReview:
    {
    "auditReadinessStatus": "ready | mostly_ready | needs_attention | not_ready | unknown",
    "complianceNarrative": "",
    "failedOrWeakControlThemes": [],
    "manualReviewRequired": [],
    "evidenceGaps": [],
    "managementImpact": "",
    "priorityComplianceActions": []
    }

    governanceReview:
    {
    "governanceNarrative": "",
    "ownershipReadiness": "",
    "decisionReadiness": "",
    "accountabilityGaps": [],
    "policyOrReviewGaps": [],
    "priorityGovernanceActions": []
    }

    domainScorecard:
    Return one row for each active domain included in domainIntelligence, plus Operations as disabled if present in disabledDomains.
    Each row:
    {
    "domainKey": "",
    "domainName": "",
    "status": "",
    "healthScore": null,
    "riskScore": null,
    "riskLevel": "",
    "executiveInterpretation": "",
    "contributionToEnterpriseRisk": "",
    "priority": "critical | high | medium | low | informational",
    "includedInFinalSynthesis": true
    }

    maturityAssessment:
    {
    "securityMaturityNarrative": "",
    "maturityLevel": "",
    "strongestCapabilities": [],
    "weakestCapabilities": [],
    "maturityBlockers": [],
    "nextMaturityStep": ""
    }

    businessImpactSummary:
    One concise final business-impact paragraph. Explain risk to operations, audit readiness, leadership accountability, resilience, and client trust.

    topDecisionsRequired:
    Return maximum 8 board/management decisions. Each decision:
    {
    "decisionId": "decision-1",
    "decision": "",
    "whyRequired": "",
    "sourceDomains": [],
    "riskIfDelayed": "",
    "recommendedOwner": "",
    "recommendedTimeline": ""
    }

    next30DaysPlan:
    Return maximum 10 actions that must happen first.

    next90DaysPlan:
    Return maximum 10 strategic actions after urgent items are handled.

    evidenceJustificationSummary:
    {
    "evidenceConfidence": "high | medium | low",
    "evidenceUsed": [],
    "sourceDomainsUsed": [],
    "evidenceGaps": [],
    "whyThisSynthesisIsReliable": "",
    "knownLimitations": []
    }

    limitationsAndAssumptions:
    Include only real limitations from the package. Include Operations disabled if applicable. Do not say Governance or Compliance are disabled if they appear in domainIntelligence.

    powerBiSummary:
    {
    "finalReportTitle": "Enterprise Final Intelligence Report",
    "finalReportPurpose": "",
    "headlineKpis": [],
    "recommendedVisuals": [],
    "finalReportDataMap": {
        "executivePage": [],
        "boardPage": [],
        "riskPage": [],
        "complianceGovernancePage": [],
        "actionPlanPage": []
    },
    "primarySlicers": ["domainKey", "riskLevel", "priority", "sourceDomains"],
    "readyForPowerBI": true
    }

    STORED STACKCTRL ENTERPRISE INTELLIGENCE:
    ${JSON.stringify(packageValue)}`;
}

    function buildIdentityBatchPackage(basePackage, batchEvidence, batchNumber, totalBatches, semanticGrouping = null, evidenceStartIndex = 0) {
        const evidence = batchEvidence.map((item, index) => compactIdentityEvidenceRow(item, Number(evidenceStartIndex || 0) + index));
        const common = {
            contextType: batchNumber === 1
                ? 'stackctrl_enterprise_identity_table'
                : 'stackctrl_enterprise_identity_table_continuation',
            schemaVersion: 2,
            mode: basePackage.mode,
            companyId: basePackage.companyId,
            snapshotId: basePackage.snapshotId,
            domain: basePackage.domain,
            sourceHealth: basePackage.sourceHealth,
            identityMetricsSummary: basePackage.identityMetricsSummary || identityMetricsSummaryFromRows(evidence, basePackage),
            collectionWindow: basePackage.collectionWindow || compactIdentityCollectionWindow(basePackage),
            authoritativeScores: basePackage.authoritativeScores,
            missingDataInfo: array(basePackage.missingDataInfo),
            identityTableColumns: compactIdentityBasePackage(basePackage).identityTableColumns,
            evidence,
            batchMetadata: {
                batchNumber,
                totalBatches,
                recordsSent: evidence.length,
                evidenceRowsIncluded: evidence.length,
                semanticGrouping,
                evidenceStartIndex: Number(evidenceStartIndex || 0)
            },
            limitations: {
                rawVendorPayloadIncluded: false,
                rawSnapshotContextIncluded: false,
                evidenceCompleteness: basePackage.limitations?.evidenceCompleteness || null,
                missingDataWarnings: array(basePackage.limitations?.missingDataWarnings),
                missingDataInfo: array(basePackage.missingDataInfo),
                batchProcessing: true,
                batchNumber,
                totalBatches,
                recordsSent: evidence.length,
                recordsOmitted: 0,
                evidenceRowsIncluded: evidence.length
            }
        };
        if (batchNumber === 1) {
            return {
                ...common,
                currentMetrics: basePackage.currentMetrics || {},
                sharedContextIncluded: true
            };
        }
        return {
            ...common,
            sharedContextIncluded: false,
            baseContextReference: {
                contextType: 'stackctrl_enterprise_identity_table',
                snapshotId: basePackage.snapshotId,
                domainKey: basePackage.domain?.key || 'identity',
                sharedContextSentInBatch: 1
            }
        };
    }

    function buildDeviceBatchPackage(basePackage, batchEvidence, batchNumber, totalBatches, semanticGrouping = null, evidenceStartIndex = 0) {
        const evidence = batchEvidence.map((item, index) => compactDeviceEvidenceRow(item, Number(evidenceStartIndex || 0) + index));
        const common = {
            contextType: batchNumber === 1
                ? 'stackctrl_enterprise_device_table'
                : 'stackctrl_enterprise_device_table_continuation',
            schemaVersion: 2,
            mode: basePackage.mode,
            companyId: basePackage.companyId,
            snapshotId: basePackage.snapshotId,
            domain: basePackage.domain,
            sourceHealth: basePackage.sourceHealth,
            deviceMetricsSummary: basePackage.deviceMetricsSummary || deviceMetricsSummaryFromRows(evidence, basePackage),
            collectionWindow: basePackage.collectionWindow || compactDeviceCollectionWindow(basePackage),
            authoritativeScores: basePackage.authoritativeScores,
            missingDataInfo: array(basePackage.missingDataInfo),
            deviceTableColumns: compactDeviceBasePackage(basePackage).deviceTableColumns,
            evidence,
            batchMetadata: {
                batchNumber,
                totalBatches,
                recordsSent: evidence.length,
                evidenceRowsIncluded: evidence.length,
                semanticGrouping,
                evidenceStartIndex: Number(evidenceStartIndex || 0)
            },
            limitations: {
                rawVendorPayloadIncluded: false,
                rawSnapshotContextIncluded: false,
                evidenceCompleteness: basePackage.limitations?.evidenceCompleteness || null,
                missingDataWarnings: array(basePackage.limitations?.missingDataWarnings),
                missingDataInfo: array(basePackage.missingDataInfo),
                batchProcessing: true,
                batchNumber,
                totalBatches,
                recordsSent: evidence.length,
                recordsOmitted: 0,
                evidenceRowsIncluded: evidence.length
            }
        };
        if (batchNumber === 1) {
            return {
                ...common,
                currentMetrics: basePackage.currentMetrics || {},
                sharedContextIncluded: true
            };
        }
        return {
            ...common,
            sharedContextIncluded: false,
            baseContextReference: {
                contextType: 'stackctrl_enterprise_device_table',
                snapshotId: basePackage.snapshotId,
                domainKey: basePackage.domain?.key || 'devices',
                sharedContextSentInBatch: 1
            }
        };
    }

    function compactSelectedDomainBatchPackage(basePackage, batchEvidence, batchNumber, totalBatches, semanticGrouping = null, evidenceStartIndex = 0) {
        const domainKey = basePackage?.domain?.key || 'domain';
        if (domainKey === 'cloudflare_network_security') {
            const groupedEvidence = Object.fromEntries(CLOUDFLARE_COMPACT_EVIDENCE_TYPES.map(type => [type, []]));
            const evidence = batchEvidence
                .filter(item => CLOUDFLARE_COMPACT_EVIDENCE_TYPES.includes(String(item?.evidenceType || item?.sourceLabel || '')))
                .map((item, index) => {
                    const type = CLOUDFLARE_COMPACT_EVIDENCE_TYPES.includes(String(item?.evidenceType || ''))
                        ? String(item.evidenceType)
                        : String(item?.sourceLabel || 'sectionErrors');
                    const data = compactCloudflareEntityData(type, item?.data || {});
                    const row = {
                        evidenceNumber: Number(evidenceStartIndex || 0) + index + 1,
                        evidenceType: type,
                        sourceMetric: data.sourceMetric || item?.sourceMetric || type,
                        entityKey: data.entityId || data.entityName || item?.entityKey || null,
                        internalSourcePath: item?.internalSourcePath || null,
                        data
                    };
                    groupedEvidence[type].push(row);
                    return row;
                });
            const categoryCounts = Object.fromEntries(Object.entries(groupedEvidence).map(([type, rows]) => [type, rows.length]));
            const warningStrings = [
                ...array(basePackage.sourceHealth?.warnings),
                ...array(basePackage.limitations?.missingDataWarnings)
            ]
                .map(warning => visibleTextOrNull(warning, 240))
                .filter(Boolean)
                .filter(warning => !/curated.*reference|best-practice references|knowledge references/i.test(warning))
                .slice(0, 10);
            return {
                contextType: 'stackctrl_enterprise_cloudflare_strict_compact',
                schemaVersion: 3,
                mode: basePackage.mode,
                companyId: basePackage.companyId,
                snapshotId: basePackage.snapshotId,
                snapshotCreatedAt: basePackage.snapshotCreatedAt,
                domain: {
                    key: basePackage.domain?.key || 'cloudflare_network_security',
                    name: basePackage.domain?.name || 'Network Security / Cloudflare'
                },
                sourceFreshness: safeValue(basePackage.sourceHealth?.freshness || {}, 0, { maxArray: 0, maxString: 160 }),
                sourceHealth: {
                    status: basePackage.sourceHealth?.status || 'unknown',
                    isExpected: basePackage.sourceHealth?.isExpected ?? true,
                    evidenceCount: evidence.length,
                    warnings: warningStrings
                },
                authoritativeScores: basePackage.authoritativeScores || {},
                currentMetrics: safeValue(basePackage.currentMetrics || {}, 0, { maxDepth: 2, maxArray: 5, maxString: 180, maxObjectKeys: 40 }),
                dashboardMetrics: safeValue(basePackage.dashboardMetrics || {}, 0, { maxDepth: 2, maxArray: 5, maxString: 180, maxObjectKeys: 40 }),
                calculatedIndicators: safeValue(basePackage.calculatedIndicators || {}, 0, { maxDepth: 2, maxArray: 5, maxString: 180, maxObjectKeys: 40 }),
                compactEvidenceSummary: {
                    totalRows: evidence.length,
                    categoryCounts,
                    maxRowsPerCategory: { default: 8, logs: 12, controls: 30, coverageSummaries: 20 },
                    strictCompactCloudflarePackage: true
                },
                evidenceGroups: groupedEvidence,
                evidence,
                batchMetadata: {
                    batchNumber,
                    totalBatches,
                    recordsSent: evidence.length,
                    evidenceRowsIncluded: evidence.length,
                    semanticGrouping,
                    evidenceStartIndex: Number(evidenceStartIndex || 0),
                    expectedSingleCompactBatch: true
                },
                limitations: {
                    warnings: warningStrings,
                    recordsSent: evidence.length,
                    recordsOmitted: 0,
                    complete: Boolean(basePackage.limitations?.evidenceCompleteness?.complete ?? evidence.length > 0)
                },
                outputInstructions: {
                    maxRisks: 5,
                    maxRecommendations: 5,
                    maxAffectedEntitiesPerRisk: 5,
                    visibleFieldsOnly: 'Use Cloudflare app, policy, device, gateway rule, profile, status, risk reason, and recommendation values. Do not expose internal source paths in visible text.'
                }
            };
        }
        if (domainKey === 'security_alerts') {
            const groupedEvidence = Object.fromEntries(SECURITY_ALERTS_COMPACT_EVIDENCE_TYPES.map(type => [type, []]));
            const evidence = batchEvidence
                .filter(item => SECURITY_ALERTS_COMPACT_EVIDENCE_TYPES.includes(String(item?.evidenceType || item?.sourceLabel || '')))
                .map((item, index) => {
                    const type = SECURITY_ALERTS_COMPACT_EVIDENCE_TYPES.includes(String(item?.evidenceType || ''))
                        ? String(item.evidenceType)
                        : String(item?.sourceLabel || 'summaryMetrics');
                    const row = {
                        evidenceNumber: Number(evidenceStartIndex || 0) + index + 1,
                        evidenceType: type,
                        sourceMetric: item?.sourceMetric || type,
                        entityKey: item?.entityKey || entityRecordKey(item?.data ?? item),
                        internalSourcePath: item?.internalSourcePath || null,
                        data: safeEvidenceEntity(item?.data ?? item, { maxDepth: 3, maxArray: 8, maxString: 420, maxObjectKeys: 28 })
                    };
                    groupedEvidence[type].push(row);
                    return row;
                });
            const categoryCounts = Object.fromEntries(Object.entries(groupedEvidence).map(([type, rows]) => [type, rows.length]));
            const metricSource = { ...(basePackage.currentMetrics || {}), ...(basePackage.dashboardMetrics || {}), ...(basePackage.calculatedIndicators || {}) };
            const summaryKeys = [
                'totalAlerts', 'criticalAlerts', 'highSeverityAlerts', 'activeIncidents', 'suspiciousSignIns',
                'anonymousIpEvents', 'repeatedAlertPatterns', 'affectedUsers', 'affectedDevices', 'unresolvedAlerts',
                'recentResolvedAlerts', 'threatIndicators', 'usersUnderAttack', 'securityScore', 'recommendationsCount'
            ];
            const summaryMetrics = Object.fromEntries(summaryKeys
                .map(key => [key, numberOrNull(metricSource[key]) ?? groupedEvidence.summaryMetrics?.[0]?.data?.[key] ?? null])
                .filter(([, value]) => value != null));
            const hasSecurityEvidence = evidence.some(row => row.evidenceType && row.evidenceType !== 'summaryMetrics');
            const hasUsableThreatIndicators = groupedEvidence.threatIndicators.length > 0;
            const warningStrings = [
                ...array(basePackage.sourceHealth?.warnings),
                ...array(basePackage.limitations?.missingDataWarnings)
            ]
                .map(warning => visibleTextOrNull(warning, 240))
                .filter(Boolean)
                .filter(warning => !isCuratedReferenceWarning(warning))
                .filter(warning => {
                    const text = String(warning || '').toLowerCase();
                    const threatIndicatorWarning = text.includes('threat_indicators_unavailable') || text.includes('threat indicators');
                    if (!threatIndicatorWarning) return true;
                    return hasSecurityEvidence && !hasUsableThreatIndicators;
                })
                .slice(0, 10);
            return {
                contextType: 'stackctrl_enterprise_security_alerts_strict_compact',
                schemaVersion: 3,
                mode: basePackage.mode,
                companyId: basePackage.companyId,
                snapshotId: basePackage.snapshotId,
                snapshotCreatedAt: basePackage.snapshotCreatedAt,
                domain: {
                    key: 'security_alerts',
                    name: basePackage.domain?.name || 'Security Alerts'
                },
                sourceFreshness: safeValue(basePackage.sourceHealth?.freshness || {}, 0, { maxArray: 0, maxString: 160 }),
                sourceHealth: {
                    status: basePackage.sourceHealth?.status || 'unknown',
                    isExpected: basePackage.sourceHealth?.isExpected ?? true,
                    evidenceCount: evidence.length,
                    warnings: warningStrings,
                    errorMessage: basePackage.sourceHealth?.errorMessage || null
                },
                authoritativeScores: basePackage.authoritativeScores || {},
                summaryMetrics,
                compactEvidenceSummary: {
                    totalRows: evidence.length,
                    categoryCounts,
                    strictCompactSecurityAlertsPackage: true,
                    maxRowsPerCategory: 10,
                    rawFullJsonIncluded: false
                },
                evidenceGroups: groupedEvidence,
                evidence,
                batchMetadata: {
                    batchNumber,
                    totalBatches,
                    recordsSent: evidence.length,
                    evidenceRowsIncluded: evidence.length,
                    semanticGrouping,
                    evidenceStartIndex: Number(evidenceStartIndex || 0),
                    expectedSingleCompactBatch: true
                },
                limitations: {
                    warnings: warningStrings,
                    recordsSent: evidence.length,
                    recordsOmitted: 0,
                    complete: Boolean(basePackage.limitations?.evidenceCompleteness?.complete ?? evidence.length > 0)
                },
                outputInstructions: {
                    maxRisks: 5,
                    maxRecommendations: 5,
                    maxAffectedEntitiesPerRisk: 5,
                    maxEvidenceUsed: 5,
                    allowedGroups: SECURITY_ALERTS_COMPACT_EVIDENCE_TYPES,
                    requiredEntityTypes: ['User', 'Device', 'Incident', 'SignInEvent', 'IPAddress']
                }
            };
        }
        if (STRICT_COMPACT_SELECTED_DOMAIN_KEYS.has(domainKey)) {
            const typeList = domainKey === 'backup'
                ? BACKUP_COMPACT_EVIDENCE_TYPES
                : domainKey === 'applications'
                ? APPLICATIONS_COMPACT_EVIDENCE_TYPES
                : domainKey === 'compliance'
                ? COMPLIANCE_COMPACT_EVIDENCE_TYPES
                : null;

            const groupedEvidence = typeList
                ? Object.fromEntries(typeList.map(type => [type, []]))
                : {};

            const evidence = batchEvidence.map((item, index) => {
                const type = String(item?.evidenceType || item?.sourceLabel || 'evidenceRows');
                const row = {
                    evidenceNumber: Number(evidenceStartIndex || 0) + index + 1,
                    evidenceType: type,
                    sourceMetric: item?.sourceMetric || type,
                    entityKey: item?.entityKey || entityRecordKey(item?.data ?? item),
                    internalSourcePath: item?.internalSourcePath || null,
                    data: safeEvidenceEntity(item?.data ?? item, { maxDepth: 3, maxArray: 8, maxString: 420, maxObjectKeys: 24 })
                };
                if (groupedEvidence[type]) groupedEvidence[type].push(row);
                return row;
            });

            const categoryCounts = evidence.reduce((counts, row) => {
                counts[row.evidenceType] = (counts[row.evidenceType] || 0) + 1;
                return counts;
            }, {});

            const summaryKeys = domainKey === 'email_security'
                ? ['activeThreats', 'highSeverityAlerts', 'affectedUsersCount', 'activeIncidents', 'threatResolutionRate', 'phishingCount', 'malwareCount', 'spamCount', 'becCount', 'activeMailboxes', 'totalMailActivity', 'recommendationsCount']
                : domainKey === 'backup'
                ? ['totalStorageGB', 'oneDriveStorageGB', 'sharePointStorageGB', 'exchangeStorageGB', 'activeUsersCount', 'inactiveUsersCount', 'servicesCovered', 'backupCoverageScore', 'exposureRiskScore', 'dataExposureRiskScore', 'recommendationsCount']
                : domainKey === 'compliance'
                ? ['totalControls', 'apiControls', 'manualControlsExcluded', 'failingControls', 'partialControls', 'passingControls', 'manualReviewControls', 'complianceScore', 'auditReadinessStatus', 'recommendationsCount']
                : ['totalApplications', 'externalApplications', 'highRiskApps', 'highAccessApps', 'excessivePermissionApps', 'groupAssignedApps', 'applicationGovernanceScore', 'userCount', 'groupCount', 'recommendationsCount'];

            const metricSource = {
                ...(basePackage.currentMetrics || {}),
                ...(basePackage.dashboardMetrics || {}),
                ...(basePackage.calculatedIndicators || {})
            };

            const summaryMetrics = Object.fromEntries(summaryKeys
                .map(key => [key === 'dataExposureRiskScore' ? 'exposureRiskScore' : key, numberOrNull(metricSource[key]) ?? metricSource[key] ?? null])
                .filter(([, value]) => value != null));

            const warningStrings = array(basePackage.limitations?.missingDataWarnings)
                .map(warning => visibleTextOrNull(warning, 240))
                .filter(Boolean)
                .filter(warning => !isCuratedReferenceWarning(warning))
                .slice(0, 10);

            const contextType = domainKey === 'email_security'
                ? 'stackctrl_enterprise_email_security_strict_compact'
                : domainKey === 'backup'
                ? 'stackctrl_enterprise_backup_strict_compact'
                : domainKey === 'applications'
                ? 'stackctrl_enterprise_applications_strict_compact'
                : domainKey === 'governance'
                ? 'stackctrl_enterprise_governance_strict_compact'
                : domainKey === 'compliance'
                ? 'stackctrl_enterprise_compliance_strict_compact'
                : 'stackctrl_enterprise_selected_domain_strict_compact';

            return {
                contextType,
                schemaVersion: 3,
                mode: basePackage.mode,
                companyId: basePackage.companyId,
                snapshotId: basePackage.snapshotId,
                snapshotCreatedAt: basePackage.snapshotCreatedAt,
                domain: {
                    key: basePackage.domain?.key || domainKey,
                    name: basePackage.domain?.name || domainKey
                },
                sourceFreshness: safeValue(basePackage.sourceHealth?.freshness || {}, 0, { maxArray: 0, maxString: 160 }),
                sourceHealth: {
                    status: basePackage.sourceHealth?.status || 'unknown',
                    isExpected: basePackage.sourceHealth?.isExpected ?? true,
                    evidenceCount: evidence.length,
                    warnings: warningStrings
                },
                authoritativeScores: basePackage.authoritativeScores || {},
                summaryMetrics,
                compactEvidenceSummary: {
                    totalRows: evidence.length,
                    categoryCounts,
                    strictCompactSelectedDomainPackage: true,
                    mailflowIsContextOnly: domainKey === 'email_security' ? true : undefined,
                    maxRowsPerCategory: 10
                },
                evidenceGroups: typeList ? groupedEvidence : undefined,
                evidence,
                batchMetadata: {
                    batchNumber,
                    totalBatches,
                    recordsSent: evidence.length,
                    evidenceRowsIncluded: evidence.length,
                    semanticGrouping,
                    evidenceStartIndex: Number(evidenceStartIndex || 0),
                    expectedSingleCompactBatch: true
                },
                limitations: {
                    warnings: warningStrings,
                    recordsSent: evidence.length,
                    recordsOmitted: 0,
                    complete: Boolean(basePackage.limitations?.evidenceCompleteness?.complete ?? evidence.length > 0)
                },
                outputInstructions: {
                    maxRisks: 5,
                    maxRecommendations: 5,
                    maxAffectedEntitiesPerRisk: 5,
                    maxEvidenceUsed: 5,
                    reasoningStyle: 'Use one to two concise sentences per reasoning field.',
                    complianceRule: domainKey === 'compliance'
                        ? 'Only mark controls passed when supplied API-connected evidence supports passing status. Missing, weak, or manual-only evidence must be partial or manual_review_required.'
                        : undefined
                }
            };
        }
        const evidence = batchEvidence.map((item, index) => ({
            evidenceNumber: Number(evidenceStartIndex || 0) + index + 1,
            evidenceType: item?.evidenceType || item?.type || 'stored_evidence',
            sourceLabel: item?.sourceLabel || item?.evidenceType || null,
            evidenceCategory: item?.evidenceCategory || item?.sourceLabel || item?.evidenceType || null,
            sourceMetric: item?.sourceMetric || null,
            entityKey: item?.entityKey || entityRecordKey(item?.data ?? item),
            internalSourcePath: item?.internalSourcePath || null,
            data: safeEvidenceEntity(item?.data ?? item, { maxDepth: 4, maxArray: 10, maxString: 600, maxObjectKeys: 40 })
        }));
        const categoryCounts = evidence.reduce((counts, row) => {
            const key = row.evidenceType || 'evidenceRows';
            counts[key] = (counts[key] || 0) + 1;
            return counts;
        }, {});
        const isEmail = domainKey === 'email_security';
        return {
            contextType: isEmail
                ? 'stackctrl_enterprise_email_security_compact'
                : 'stackctrl_enterprise_cloudflare_compact',
            schemaVersion: 2,
            mode: basePackage.mode,
            companyId: basePackage.companyId,
            snapshotId: basePackage.snapshotId,
            snapshotCreatedAt: basePackage.snapshotCreatedAt,
            domain: basePackage.domain,
            sourceHealth: basePackage.sourceHealth,
            currentMetrics: basePackage.currentMetrics || {},
            dashboardMetrics: basePackage.dashboardMetrics || {},
            calculatedIndicators: basePackage.calculatedIndicators || {},
            authoritativeScores: basePackage.authoritativeScores,
            collectionWindow: basePackage.collectionWindow || null,
            compactEvidenceSummary: {
                totalRows: evidence.length,
                categoryCounts,
                rowsAreCompactSelectedDomainEvidence: true,
                mailflowIsContextOnly: isEmail ? true : undefined,
                noSharedEnterpriseContextIncluded: true,
                noHistoricalContextIncluded: true,
                noPreviousAnalysisIncluded: true,
                noKnowledgeCatalogIncluded: true
            },
            evidence,
            batchMetadata: {
                batchNumber,
                totalBatches,
                recordsSent: evidence.length,
                evidenceRowsIncluded: evidence.length,
                semanticGrouping,
                evidenceStartIndex: Number(evidenceStartIndex || 0),
                expectedSingleCompactBatch: true
            },
            limitations: {
                rawVendorPayloadIncluded: false,
                rawSnapshotContextIncluded: false,
                fullHistoricalContextIncluded: false,
                sharedEnterpriseEvidenceIncluded: false,
                fallbackRawPayloadsIncluded: false,
                evidenceCompleteness: basePackage.limitations?.evidenceCompleteness || null,
                missingDataWarnings: array(basePackage.limitations?.missingDataWarnings),
                missingDataInfo: array(basePackage.missingDataInfo),
                batchProcessing: true,
                batchNumber,
                totalBatches,
                recordsSent: evidence.length,
                recordsOmitted: 0,
                evidenceRowsIncluded: evidence.length
            }
        };
    }

    // Build a domain analysis package for a specific batch of evidence
    function buildDomainBatchPackage(basePackage, batchEvidence, batchNumber, totalBatches, semanticGrouping = null, evidenceStartIndex = 0) {
        if (basePackage?.domain?.key === 'identity') {
            return buildIdentityBatchPackage(basePackage, batchEvidence, batchNumber, totalBatches, semanticGrouping, evidenceStartIndex);
        }
        if (basePackage?.domain?.key === 'devices') {
            return buildDeviceBatchPackage(basePackage, batchEvidence, batchNumber, totalBatches, semanticGrouping, evidenceStartIndex);
        }
        if (basePackage?.strictCompactSelectedDomain || basePackage?.securityAlertsCompactPackage) {
            return compactSelectedDomainBatchPackage(basePackage, batchEvidence, batchNumber, totalBatches, semanticGrouping, evidenceStartIndex);
        }
        const categoryMap = new Map();
        for (const item of batchEvidence) {
            const key = String(item?.evidenceCategory || item?.sourceLabel || item?.evidenceType || 'evidenceRows');
            if (!categoryMap.has(key)) categoryMap.set(key, []);
            const data = item?.data ?? item;
            categoryMap.get(key).push({
                entityKey: item?.entityKey || entityRecordKey(data),
                internalSourcePath: item?.internalSourcePath || null,
                sourceAlertId: data?.sourceAlertId || data?.alertId || data?.SourceID || data?.id || null
            });
        }
        const batchCategories = [...categoryMap.entries()].map(([key, entities]) => ({
            key,
            label: key.replace(/[_-]+/g, ' ').replace(/\b\w/g, char => char.toUpperCase()),
            sourceMetric: batchEvidence.find(item => String(item?.evidenceCategory || item?.sourceLabel || item?.evidenceType || 'evidenceRows') === key)?.sourceMetric || key,
            count: entities.length,
            entities
        }));
        return {
            ...basePackage,
            evidenceCatalog: {
                ...basePackage.evidenceCatalog,
                categories: batchCategories,
                categoryCount: batchCategories.length,
                catalogEntityCount: batchEvidence.length,
                batchScoped: true
            },
            evidence: batchEvidence.map((item, index) => ({
                evidenceNumber: Number(evidenceStartIndex || 0) + index + 1,
                evidenceType: item?.evidenceType || item?.type || 'stored_evidence',
                sourceLabel: item?.sourceLabel || null,
                internalSourcePath: item?.internalSourcePath || null,
                evidenceCategory: item?.evidenceCategory || null,
                sourceMetric: item?.sourceMetric || null,
                entityKey: item?.entityKey || entityRecordKey(item?.data ?? item),
                data: safeEvidenceEntity(item?.data ?? item)
            })),
            current: {
                healthScore: basePackage.authoritativeScores?.healthScore ?? null,
                riskScore: basePackage.authoritativeScores?.riskScore ?? null,
                riskLevel: basePackage.authoritativeScores?.riskLevel || 'not_scored',
                metrics: basePackage.currentMetrics || {},
                dashboardMetrics: basePackage.dashboardMetrics || {},
                calculatedIndicators: basePackage.calculatedIndicators || {}
            },
            batchMetadata: {
                batchNumber,
                totalBatches,
                batchEvidentItemCount: batchEvidence.length,
                recordsSent: batchEvidence.length,
                evidenceRowsIncluded: batchEvidence.length,
                semanticGrouping
            },
            limitations: {
                ...basePackage.limitations,
                batchProcessing: true,
                batchNumber,
                totalBatches,
                recordsSent: batchEvidence.length,
                recordsOmitted: 0,
                evidenceRowsIncluded: batchEvidence.length
            }
        };
    }

    function domainMessages(domain, packageValue) {
        return [
            { role: 'system', content: DOMAIN_SYSTEM_MESSAGE },
            { role: 'user', content: domainPrompt(domain, packageValue) }
        ];
    }

    function estimateDomainRequestBytes(domain, packageValue) {
        return bytes({
            model: 'enterprise-deployment',
            input: domainMessages(domain, packageValue),
            temperature: 0.15,
            max_output_tokens: settings.maxDomainOutputTokens,
            store: false,
            text: { format: { type: 'json_object' } }
        });
    }

    // Store batch result in database
    async function storeBatch({
        companyId, snapshotId, runId, domain, batchNumber, totalBatches, batchEvidence, analysis, usage, status,
        errorMessage = null, failureReason = null, rawResponsePreview = null, azureFinishReason = null,
        jsonRepaired = false, jsonRepairMethod = null, recommendedRetryAfterMs = null, stackCTRLDataCount = 0,
        recordsRemaining: suppliedRecordsRemaining = null, semanticGrouping = null, attemptDiagnostics = null
    }) {
        const batchItemCount = batchEvidence.length;
        const recordsRemaining = suppliedRecordsRemaining == null
            ? Math.max(0, Number(stackCTRLDataCount || 0) - (batchNumber * batchItemCount))
            : Math.max(0, Number(suppliedRecordsRemaining));
        const rateLimitedFailure = failureReason === 'rate_limited' || status === 'failed_rate_limited';
        const omittedFromThisBatch = analysis || rateLimitedFailure ? 0 : batchItemCount;
        const sentToAzureCount = analysis ? batchItemCount : 0;
        const estimatedInputTokens = Math.ceil(Number(usage.requestBytes || 0) / 4);
        const batchSummary = {
            summary: analysis?.domainExecutiveSummary || '',
            findingsCount: array(analysis?.keyFindings).length,
            risksCount: array(analysis?.risks).length,
            recommendationsCount: array(analysis?.recommendations).length,
            trendsCount: array(analysis?.trendAnalysis).length,
            jsonRepaired: Boolean(jsonRepaired),
            jsonRepairMethod,
            recommendedRetryAfterMs: recommendedRetryAfterMs == null ? null : Number(recommendedRetryAfterMs),
            batchNumber,
            totalBatches,
            recordsSent: batchItemCount,
            recordsRemaining,
            recordsOmitted: omittedFromThisBatch,
            omissionReason: analysis || rateLimitedFailure ? null : (failureReason || errorMessage || 'batch_not_completed'),
            processingBlockedReason: rateLimitedFailure ? 'azure_rate_limited_retry_later' : null,
            evidenceRowsIncluded: analysis ? batchItemCount : 0,
            estimatedInputTokens,
            actualInputTokens: usage.inputTokens,
            actualOutputTokens: usage.outputTokens,
            inputTokens: usage.inputTokens,
            outputTokens: usage.outputTokens,
            totalTokens: usage.totalTokens,
            thresholdUsed: settings.maxTotalTokens,
            retryCount: usage.retries || 0,
            retryOrCooldownOccurred: Boolean((usage.retries || 0) > 0 || recommendedRetryAfterMs),
            attemptDiagnostics: array(attemptDiagnostics),
            semanticGrouping,
            evidenceTypes: [...new Set(batchEvidence.map(item => item?.evidenceType).filter(Boolean))],
            firstEvidenceNumber: batchEvidence.length ? 1 : 0,
            internalSourcePath: batchEvidence.at(-1)?.internalSourcePath || null
        };
        
        await pool.query(
            `INSERT INTO StackCTRLTenantDomainIntelligenceBatches
             (CompanyID, SnapshotID, RunID, DomainKey, DomainName, BatchNumber, BatchCount, Status,
              StackCTRLDataCount, BatchItemCount, SentToAzureCount, RemainingAfterBatch, OmittedFromThisBatch,
              InputSizeBytes, ResponseSizeBytes, InputTokens, OutputTokens, TotalTokens, RetryCount,
              BatchSummaryJson, FindingsJson, RisksJson, RecommendationsJson, TrendsJson,
              MissingDataWarningsJson, StartedAt, CompletedAt, ErrorMessage, FailureReason, RawResponsePreview, AzureFinishReason, CreatedAt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), ?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE
              Status = ?, StackCTRLDataCount = ?, BatchCount = ?, BatchItemCount = ?, SentToAzureCount = ?, RemainingAfterBatch = ?, OmittedFromThisBatch = ?, InputSizeBytes = ?, ResponseSizeBytes = ?,
              InputTokens = ?, OutputTokens = ?, TotalTokens = ?, RetryCount = ?,
              BatchSummaryJson = ?, FindingsJson = ?, RisksJson = ?, RecommendationsJson = ?, TrendsJson = ?,
              MissingDataWarningsJson = ?, CompletedAt = NOW(), ErrorMessage = ?, FailureReason = ?,
              RawResponsePreview = ?, AzureFinishReason = ?, UpdatedAt = NOW()`,
            [
                companyId, snapshotId, runId, domain.key, domain.name, batchNumber, totalBatches, status,
                stackCTRLDataCount, batchItemCount, sentToAzureCount, recordsRemaining, omittedFromThisBatch,
                usage.requestBytes || 0, usage.responseBytes, usage.inputTokens, usage.outputTokens, usage.totalTokens, usage.retries || 0,
                JSON.stringify(batchSummary || {}),
                analysis ? jsonArray(analysis.keyFindings) : null,
                analysis ? jsonArray(analysis.risks) : null,
                analysis ? jsonArray(analysis.recommendations) : null,
                analysis ? jsonArray(analysis.trendAnalysis) : null,
                analysis ? jsonArray(analysis.missingDataWarnings) : null,
                errorMessage, failureReason, rawResponsePreview, azureFinishReason,
                // ON DUPLICATE KEY UPDATE values
                status, stackCTRLDataCount, totalBatches, batchItemCount, sentToAzureCount, recordsRemaining, omittedFromThisBatch, usage.requestBytes || 0, usage.responseBytes,
                usage.inputTokens, usage.outputTokens, usage.totalTokens, usage.retries || 0,
                JSON.stringify(batchSummary || {}),
                analysis ? jsonArray(analysis.keyFindings) : null,
                analysis ? jsonArray(analysis.risks) : null,
                analysis ? jsonArray(analysis.recommendations) : null,
                analysis ? jsonArray(analysis.trendAnalysis) : null,
                analysis ? jsonArray(analysis.missingDataWarnings) : null,
                errorMessage, failureReason, rawResponsePreview, azureFinishReason
            ]
        );
    }

    // Analyze a single domain batch with JSON error handling and repair
    async function analyzeDomainBatch({ companyId, snapshot, run, domain, packageResult, batchEvidence, batchNumber, totalBatches, historicalContext, recordsRemaining = null, semanticGrouping = null, evidenceStartIndex = 0 }) {
        const batchPackage = buildDomainBatchPackage(packageResult.package, batchEvidence, batchNumber, totalBatches, semanticGrouping, evidenceStartIndex);
        let usage = { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: estimateDomainRequestBytes(domain, batchPackage), responseBytes: 0, retries: 0 };
        
        try {
            // First attempt: get JSON response from Azure
            const response = await azureOpenAI.createJsonCompletion({
                messages: domainMessages(domain, batchPackage),
                temperature: 0.15,
                maxTokens: packageResult.package?.strictCompactSelectedDomain
                    ? Math.min(settings.maxDomainOutputTokens, 10000)
                    : settings.maxDomainOutputTokens,
                maxRetriesOverride: domain.key === 'email_security' ? 0 : settings.maxRetries,
                retryDelaysMsOverride: domain.key === 'email_security' ? EMAIL_SECURITY_RATE_LIMIT_RETRY_DELAYS_MS : ENTERPRISE_RATE_LIMIT_RETRY_DELAYS_MS,
                retryMaxMsOverride: domain.key === 'email_security' ? EMAIL_SECURITY_RATE_LIMIT_RETRY_MAX_MS : ENTERPRISE_RATE_LIMIT_RETRY_MAX_MS,
                connectionRetryDelaysMsOverride: ENTERPRISE_CONNECTION_RETRY_DELAYS_MS,
                timeoutMs: settings.requestTimeoutMs,
                allowInvalidJsonResponse: true
            });
            
            usage = responseUsage(response);
            const rawResponsePreview = safeResponsePreview(response.data);
            
            const finishReason = responseFinishReason(response);
            let analysis = null;
            let jsonRepaired = false;
            let jsonRepairMethod = null;
            if (typeof response.data === 'string') {
                const jsonResult = parseJsonWithDiagnostics(response.data);
                if (!jsonResult.success) {
                    const localRepair = repairTruncatedJson(response.data);
                    logger.warn(`[StackCTRL Enterprise] Batch ${batchNumber} JSON parsing failed, attempting one Azure repair. Error: ${jsonResult.error}`);
                    let repairResponse = null;
                    try {
                        repairResponse = await azureOpenAI.createJsonCompletion({
                            messages: [
                                { role: 'system', content: 'Return valid JSON only. Preserve readable evidence names and their matching IDs; discard only incomplete trailing prose.' },
                                { role: 'user', content: createJsonRepairPrompt(response.data) }
                            ],
                            temperature: 0,
                            maxTokens: Math.min(settings.maxDomainOutputTokens, 4000),
                            maxRetriesOverride: 1,
                            retryDelaysMsOverride: ENTERPRISE_RATE_LIMIT_RETRY_DELAYS_MS,
                retryMaxMsOverride: ENTERPRISE_RATE_LIMIT_RETRY_MAX_MS,
                connectionRetryDelaysMsOverride: ENTERPRISE_CONNECTION_RETRY_DELAYS_MS,
                timeoutMs: settings.requestTimeoutMs,
                            allowInvalidJsonResponse: true
                        });
                    } catch (repairError) {
                        if (!localRepair.success) {
                            const errorMessage = `JSON parse failed: ${jsonResult.error}. Repair attempt failed: ${repairError.message}`;
                            const fallbackAnalysis = buildInvalidJsonFallbackAnalysis({
                                domain, snapshot, packageResult, batchEvidence, errorMessage,
                                rawResponseStored: rawResponsePreview != null
                            });
                            await storeBatch({
                                companyId, snapshotId: snapshot.ID, runId: run.id, domain,
                                batchNumber, totalBatches, batchEvidence, analysis: fallbackAnalysis, usage,
                                stackCTRLDataCount: packageResult.audit.stackCTRLDataCount,
                                status: 'completed_with_warnings', errorMessage,
                                failureReason: 'invalid_json_local_fallback', rawResponsePreview,
                                azureFinishReason: finishReason, jsonRepaired: true,
                                jsonRepairMethod: 'local_fallback_after_repair_error', recordsRemaining, semanticGrouping
                            });
                            return {
                                status: 'completed_with_warnings', batchNumber, batchItemCount: batchEvidence.length,
                                domain, analysis: fallbackAnalysis, usage, errorMessage,
                                failureReason: 'invalid_json_local_fallback', jsonRepaired: true,
                                jsonRepairMethod: 'local_fallback_after_repair_error'
                            };
                        }
                        logger.warn?.(`[StackCTRL Enterprise] Azure repair failed for batch ${batchNumber}; using locally recovered JSON with warnings.`);
                        jsonRepaired = true;
                        jsonRepairMethod = 'local_closure_after_azure_repair_error';
                        analysis = normalizedDomainResult(localRepair.value, domain, packageResult.current, snapshot.ID, batchEvidence);
                    }
                    if (repairResponse) {
                    const repairUsage = responseUsage(repairResponse);
                    usage.inputTokens += repairUsage.inputTokens;
                    usage.outputTokens += repairUsage.outputTokens;
                    usage.totalTokens += repairUsage.totalTokens;
                    usage.requestBytes += repairUsage.requestBytes;
                    usage.responseBytes += repairUsage.responseBytes;
                    usage.retries += repairUsage.retries;
                    const repairResult = parseJsonWithDiagnostics(repairResponse.data);
                    const repairedRepairResponse = repairResult.success ? null : repairTruncatedJson(repairResponse.data);
                    const recoveredValue = repairResult.success
                        ? repairResult.value
                        : repairedRepairResponse?.success ? repairedRepairResponse.value
                            : localRepair.success ? localRepair.value : null;
                    if (!recoveredValue) {
                        const failureReason = finishReason === 'length' ? 'output_truncated_unrepairable' : 'invalid_json_unrepairable';
                        const errorMessage = `JSON parse failed: ${jsonResult.error}. Repair attempt also failed: ${repairResult.error}`;
                        const fallbackAnalysis = buildInvalidJsonFallbackAnalysis({
                            domain, snapshot, packageResult, batchEvidence, errorMessage,
                            rawResponseStored: rawResponsePreview != null
                        });
                        await storeBatch({
                            companyId, snapshotId: snapshot.ID, runId: run.id, domain,
                            batchNumber, totalBatches, batchEvidence, analysis: fallbackAnalysis, usage,
                            stackCTRLDataCount: packageResult.audit.stackCTRLDataCount,
                            status: 'completed_with_warnings', errorMessage,
                            failureReason: 'invalid_json_local_fallback', rawResponsePreview,
                            azureFinishReason: finishReason, jsonRepaired: true,
                            jsonRepairMethod: 'local_fallback_after_invalid_json', recordsRemaining, semanticGrouping
                        });
                        return {
                            status: 'completed_with_warnings', batchNumber, batchItemCount: batchEvidence.length,
                            domain, analysis: fallbackAnalysis, usage, errorMessage,
                            failureReason: 'invalid_json_local_fallback', jsonRepaired: true,
                            jsonRepairMethod: 'local_fallback_after_invalid_json', originalFailureReason: failureReason
                        };
                    }
                    jsonRepaired = true;
                    jsonRepairMethod = repairResult.success
                        ? 'azure_repair'
                        : repairedRepairResponse?.success ? 'azure_repair_then_local_closure' : 'local_closure_after_azure_repair_failure';
                    analysis = normalizedDomainResult(recoveredValue, domain, packageResult.current, snapshot.ID, batchEvidence);
                    }
                } else {
                    analysis = normalizedDomainResult(jsonResult.value, domain, packageResult.current, snapshot.ID, batchEvidence);
                }
            } else {
                analysis = normalizedDomainResult(response.data, domain, packageResult.current, snapshot.ID, batchEvidence);
            }

            const locallyRecoveredJson = jsonRepaired && /local_closure|local_fallback/i.test(String(jsonRepairMethod || ''));
            const lengthLimitedStringResponse = finishReason === 'length' && typeof response.data === 'string';
            if (locallyRecoveredJson || lengthLimitedStringResponse) {
                analysis.missingDataWarnings = [
                    ...array(analysis.missingDataWarnings),
                    'Azure output ended before all closing JSON delimiters were returned. StackCTRL safely recovered the structured response; trailing narrative fields may be incomplete.'
                ];
            }
            
            const batchStatus = locallyRecoveredJson || lengthLimitedStringResponse ? 'completed_with_warnings' : 'completed';
            // Store successful batch. Recovered or length-limited JSON remains explicitly warning-bearing.
            await storeBatch({
                companyId, snapshotId: snapshot.ID, runId: run.id, domain,
                batchNumber, totalBatches, batchEvidence, analysis, usage, status: batchStatus,
                stackCTRLDataCount: packageResult.audit.stackCTRLDataCount,
                rawResponsePreview, azureFinishReason: finishReason, jsonRepaired, jsonRepairMethod, recordsRemaining, semanticGrouping
            });
            
            return { status: batchStatus, batchNumber, batchItemCount: batchEvidence.length, domain, analysis, usage, jsonRepaired, jsonRepairMethod };
        } catch (error) {
            const metadata = error.azureMetadata || {};
            const alreadyStored = /finish_reason: length/.test(error.message);
            usage = {
                inputTokens: Number(metadata.inputTokens || 0), outputTokens: Number(metadata.outputTokens || 0), totalTokens: Number(metadata.totalTokens || 0),
                requestBytes: Number(metadata.requestSizeBytes || estimateDomainRequestBytes(domain, batchPackage)), responseBytes: Number(metadata.responseSizeBytes || 0),
                retries: Number(metadata.retryCount || 0)
            };
            
            let failureReason = 'unknown_error';
            if (error.message.includes('finish_reason: length')) failureReason = 'output_truncated';
            else if (error.message.includes('JSON')) failureReason = 'invalid_json';
            else if (metadata.connectionReset || String(error.message).toLowerCase().includes('econnreset')) failureReason = 'connection_reset';
            else if (metadata.connectionError) failureReason = 'connection_reset';
            else if (metadata.rateLimited || metadata.statusCode === 429 || error.message.includes('429') || error.message.includes('throttl')) failureReason = 'rate_limited';
            const status = failureReason === 'output_truncated' || failureReason === 'invalid_json'
                ? 'failed_invalid_json'
                : failureReason === 'rate_limited' ? 'failed_rate_limited'
                    : failureReason === 'connection_reset' ? 'failed_connection'
                        : classifyFailureStatus(error);
            const recommendedRetryAfterMs = metadata.retryAfterMs ?? metadata.lastRetryDelayMs ?? null;
            if (failureReason === 'rate_limited') captureRateLimit(error);

            if (status === 'failed_invalid_json') {
                const rawResponsePreview = safeResponsePreview(metadata.rawResponse || metadata.responseText || '');
                const errorMessage = `Azure JSON response could not be parsed: ${error.message}`;
                const fallbackAnalysis = buildInvalidJsonFallbackAnalysis({
                    domain, snapshot, packageResult, batchEvidence, errorMessage,
                    rawResponseStored: rawResponsePreview != null
                });
                await storeBatch({
                    companyId, snapshotId: snapshot.ID, runId: run.id, domain,
                    batchNumber, totalBatches, batchEvidence, analysis: fallbackAnalysis, usage,
                    stackCTRLDataCount: packageResult.audit.stackCTRLDataCount,
                    status: 'completed_with_warnings', errorMessage,
                    failureReason: 'invalid_json_local_fallback', rawResponsePreview,
                    azureFinishReason: metadata.finishReason || null,
                    jsonRepaired: true, jsonRepairMethod: 'local_fallback_after_json_exception',
                    recordsRemaining, semanticGrouping
                });
                logger.warn?.(`[StackCTRL Enterprise] ${domain.name} batch ${batchNumber} used a local invalid-JSON fallback and the pipeline will continue.`);
                return {
                    status: 'completed_with_warnings', batchNumber, batchItemCount: batchEvidence.length,
                    domain, analysis: fallbackAnalysis, usage, errorMessage,
                    failureReason: 'invalid_json_local_fallback', jsonRepaired: true,
                    jsonRepairMethod: 'local_fallback_after_json_exception'
                };
            }
            
            if (!alreadyStored) {
                await storeBatch({
                    companyId, snapshotId: snapshot.ID, runId: run.id, domain,
                    batchNumber, totalBatches, batchEvidence, analysis: null, usage,
                    stackCTRLDataCount: packageResult.audit.stackCTRLDataCount,
                    status, errorMessage: error.message, failureReason,
                    rawResponsePreview: safeResponsePreview(metadata.rawResponse || metadata.responseText || ''),
                    azureFinishReason: metadata.finishReason || null,
                    recommendedRetryAfterMs,
                    attemptDiagnostics: metadata.attemptDiagnostics || [],
                    recordsRemaining,
                    semanticGrouping
                });
            }
            
            logger.error(`[StackCTRL Enterprise] ${domain.name} batch ${batchNumber} failed:`, error.message);
            return {
                status, batchNumber, batchItemCount: batchEvidence.length, domain, usage, failureReason,
                errorMessage: error.message, recommendedRetryAfterMs,
                attemptDiagnostics: metadata.attemptDiagnostics || [],
                connectionReset: Boolean(metadata.connectionReset || failureReason === 'connection_reset')
            };
        }
    }

    function mergeCompletedBatchAnalyses({ results, domain, packageResult, snapshotId, totalBatches }) {
        const completed = results.filter(result => isSuccessfulDomainStatus(result.status) && result.analysis);
        const flatten = field => completed.flatMap(result => array(result.analysis?.[field]));
        const controlAssessment = completed.flatMap(result => {
            const value = result.analysis?.controlAssessment;
            return Array.isArray(value) ? value : value && typeof value === 'object' ? [value] : [];
        });
        const processedItems = completed.reduce((total, result) => total + Number(result.batchItemCount || 0), 0);
        return normalizedDomainResult({
            status: 'running',
            domainExecutiveSummary: completed.map(result => result.analysis.domainExecutiveSummary).filter(Boolean).join(' '),
            technicalReasoning: flatten('technicalReasoning').length
                ? flatten('technicalReasoning')
                : completed.map(result => result.analysis.technicalReasoning || result.analysis.technicalSummary).filter(Boolean).join(' '),
            riskPrioritization: flatten('riskPrioritization'),
            technicalSummary: completed.map(result => result.analysis.technicalSummary).filter(Boolean).join(' '),
            businessImpact: completed.map(result => result.analysis.businessImpact).filter(Boolean).join(' '),
            currentPosture: completed.map(result => result.analysis.currentPosture).filter(Boolean).join(' '),
            scoreJustification: completed.map(result => result.analysis.scoreJustification).filter(Boolean).join(' '),
            evidenceUsed: flatten('evidenceUsed'),
            evidenceGaps: flatten('evidenceGaps'),
            controlAssessment,
            highestRiskPatterns: flatten('highestRiskPatterns'),
            keyFindings: flatten('keyFindings'),
            risks: flatten('risks'),
            recommendations: flatten('recommendations'),
            managementDecisionsRequired: flatten('managementDecisionsRequired'),
            whatCanWait: flatten('whatCanWait'),
            trendAnalysis: flatten('trendAnalysis'),
            whatImproved: flatten('whatImproved'),
            whatDeteriorated: flatten('whatDeteriorated'),
            whatStayedTheSame: flatten('whatStayedTheSame'),
            missingDataWarnings: [
                ...array(packageResult.package.limitations?.missingDataWarnings),
                ...flatten('missingDataWarnings')
            ],
            assumptions: flatten('assumptions'),
            managementActions: flatten('managementActions'),
            confidenceScore: completed.length
                ? completed.reduce((total, result) => total + Number(result.analysis.confidenceScore || 0), 0) / completed.length
                : null,
            powerBiSummary: completed.reduce((merged, result) => ({ ...merged, ...(result.analysis.powerBiSummary || {}) }), {}),
            evidenceLimitations: {
                recordsPrepared: packageResult.allEvidence.length,
                recordsSent: processedItems,
                recordsOmitted: 0,
                complete: completed.length === totalBatches,
                omittedReasons: array(packageResult.package.limitations?.missingDataWarnings)
            },
            batchInfo: {
                completedBatches: completed.length,
                totalBatches,
                processedItems,
                remainingItems: Math.max(0, packageResult.allEvidence.length - processedItems),
                complete: completed.length === totalBatches,
                basePackageTokens: packageResult.audit.batchPlan?.basePackageTokens ?? null,
                evidenceTokens: packageResult.audit.batchPlan?.evidenceTokens ?? null,
                identityTableTokens: packageResult.audit.batchPlan?.identityTableTokens ?? packageResult.audit.batchPlan?.evidenceTokens ?? null,
                deviceTableTokens: packageResult.audit.batchPlan?.deviceTableTokens ?? packageResult.audit.batchPlan?.evidenceTokens ?? null,
                totalEstimatedTokens: packageResult.audit.batchPlan?.totalEstimatedTokens ?? null,
                safeInputTokenLimit: packageResult.audit.batchPlan?.safeInputTokenLimit ?? null,
                safeTokenLimit: packageResult.audit.batchPlan?.safeTokenLimit ?? packageResult.audit.batchPlan?.safeInputTokenLimit ?? null,
                plannedBatchCount: packageResult.audit.batchPlan?.plannedBatchCount ?? totalBatches,
                reasonForBatchCount: packageResult.audit.batchPlan?.reasonForBatchCount || null
            }
        }, domain, packageResult.current, snapshotId, packageResult.allEvidence);
    }

    // Process all batches for a domain and aggregate results
    async function processBatchEvidenceWithRecovery({
        companyId, snapshot, run, domain, packageResult, batchEvidence, batchNumber, totalBatches,
        historicalContext, recordsRemaining, semanticGrouping, evidenceStartIndex = 0
    }) {
        const result = await analyzeDomainBatch({
            companyId, snapshot, run, domain, packageResult,
            batchEvidence, batchNumber, totalBatches, historicalContext,
            recordsRemaining, semanticGrouping, evidenceStartIndex
        });
        if (isSuccessfulDomainStatus(result.status)) return [result];
        if (isConnectionFailureResult(result) && batchEvidence.length > 1) {
            const splitAt = Math.max(1, Math.floor(batchEvidence.length / 2));
            logger.warn?.(`[StackCTRL Enterprise] Reducing ${domain.name} batch ${batchNumber} from ${batchEvidence.length} to ${splitAt}+${batchEvidence.length - splitAt} record(s) after connection reset.`);
            const firstHalf = batchEvidence.slice(0, splitAt);
            const secondHalf = batchEvidence.slice(splitAt);
            const firstResults = await processBatchEvidenceWithRecovery({
                companyId, snapshot, run, domain, packageResult,
                batchEvidence: firstHalf, batchNumber, totalBatches, historicalContext,
                recordsRemaining, semanticGrouping, evidenceStartIndex
            });
            const secondResults = await processBatchEvidenceWithRecovery({
                companyId, snapshot, run, domain, packageResult,
                batchEvidence: secondHalf, batchNumber, totalBatches, historicalContext,
                recordsRemaining: Math.max(0, Number(recordsRemaining || 0) - firstHalf.length),
                semanticGrouping, evidenceStartIndex: evidenceStartIndex + firstHalf.length
            });
            return [...firstResults, ...secondResults];
        }
        if (isConnectionFailureResult(result) && batchEvidence.length === 1) {
            const errorMessage = result.errorMessage || 'Azure connection reset after retries.';
            const fallbackAnalysis = buildInvalidJsonFallbackAnalysis({
                domain, snapshot, packageResult, batchEvidence: batchEvidence, errorMessage,
                rawResponseStored: false
            });
            fallbackAnalysis.missingDataWarnings = [
                ...array(fallbackAnalysis.missingDataWarnings),
                `Azure connection reset while analysing 1 evidence row: ${errorMessage}`
            ];
            await storeBatch({
                companyId, snapshotId: snapshot.ID, runId: run.id, domain,
                batchNumber, totalBatches, batchEvidence, analysis: fallbackAnalysis, usage: result.usage || {},
                stackCTRLDataCount: packageResult.audit.stackCTRLDataCount,
                status: 'completed_with_warnings', errorMessage,
                failureReason: 'connection_reset_local_fallback',
                attemptDiagnostics: result.attemptDiagnostics || [],
                recordsRemaining, semanticGrouping
            });
            return [{
                status: 'completed_with_warnings',
                batchNumber,
                batchItemCount: batchEvidence.length,
                domain,
                analysis: fallbackAnalysis,
                usage: result.usage || {},
                failureReason: 'connection_reset_local_fallback',
                errorMessage,
                attemptDiagnostics: result.attemptDiagnostics || []
            }];
        }
        return [result];
    }

    async function processDomainBatches({ companyId, snapshot, run, domain, packageResult, allEvidence, historicalContext, thresholdReached = false }) {
        if (domain.key === 'security_alerts') {
            logger.info?.('[security_alerts:azure_batch_plan:start] Building semantic Azure batch plan');
            await updateRunStageProgress(run.id, { stage: 'azure_batch_plan:start', lastSuccessfulStage: 'evidence_prepare:complete' });
        }
        const maxItems = domain.key === 'identity'
            ? IDENTITY_MAX_ITEMS_PER_BATCH
            : domain.key === 'devices'
            ? DEVICE_MAX_ITEMS_PER_BATCH
            : thresholdReached
            ? Math.min(settings.maxItemsPerBatch, settings.thresholdBatchMaxItems)
            : domain.key === 'cloudflare_network_security'
            ? CLOUDFLARE_MAX_ITEMS_PER_BATCH
            : packageResult.package?.strictCompactSelectedDomain || packageResult.package?.securityAlertsCompactPackage
            ? SELECTED_DOMAIN_MAX_ITEMS_PER_BATCH
            : HEAVY_DOMAINS.has(domain.key)
            ? Math.min(settings.maxItemsPerBatch, settings.heavyDomainMaxItemsPerBatch)
            : settings.maxItemsPerBatch;
        const batchOptions = {
            maxItems,
            maxBytes: settings.maxInputBytes,
            estimateBytes: items => estimateDomainRequestBytes(
                domain,
                buildDomainBatchPackage(packageResult.package, items, 1, Math.max(1, Math.ceil(allEvidence.length / maxItems)))
            )
        };
        
        let batches;
        let batchPlanDiagnostics = {};
        if (domain.key === 'identity') {
            const emptyRequestBytes = estimateDomainRequestBytes(
                domain,
                buildDomainBatchPackage(packageResult.package, [], 1, 1)
            );
            const combinedRequestBytes = estimateDomainRequestBytes(
                domain,
                buildDomainBatchPackage(packageResult.package, allEvidence, 1, 1)
            );
            batches = splitIntoBatches(allEvidence, batchOptions);
            const basePackageTokens = Math.ceil(emptyRequestBytes / 4);
            const totalEstimatedTokens = Math.ceil(combinedRequestBytes / 4);
            const identityTableTokens = Math.max(0, totalEstimatedTokens - basePackageTokens);
            const evidenceTokens = identityTableTokens;
            const safeTokenLimit = Math.floor(settings.maxInputBytes / 4);
            const safeInputTokenLimit = safeTokenLimit;
            let reasonForBatchCount;
            if (!allEvidence.length) {
                reasonForBatchCount = 'no_identity_evidence_rows';
            } else if (batches.length === 1) {
                reasonForBatchCount = 'all_identity_rows_fit_safe_token_limit';
            } else if (combinedRequestBytes > settings.maxInputBytes && allEvidence.length > maxItems) {
                reasonForBatchCount = 'identity_evidence_exceeds_safe_token_limit_and_row_safety_cap';
            } else if (combinedRequestBytes > settings.maxInputBytes) {
                reasonForBatchCount = 'identity_evidence_exceeds_safe_token_limit';
            } else {
                reasonForBatchCount = `identity_evidence_exceeds_${maxItems}_row_safety_cap`;
            }
            batchPlanDiagnostics = {
                basePackageTokens,
                evidenceTokens,
                identityTableTokens,
                totalEstimatedTokens,
                safeInputTokenLimit,
                safeTokenLimit,
                plannedBatchCount: batches.length,
                reasonForBatchCount
            };
            logger.info?.(
                `[StackCTRL Enterprise] Identity batch plan: basePackageTokens=${basePackageTokens}, evidenceTokens=${evidenceTokens}, identityTableTokens=${identityTableTokens}, totalEstimatedTokens=${totalEstimatedTokens}, safeTokenLimit=${safeTokenLimit}, plannedBatchCount=${batches.length}, reasonForBatchCount=${reasonForBatchCount}`
            );
            if (batches.length > 5) {
                logger.warn?.(
                    `[StackCTRL Enterprise] Identity required ${batches.length} batches for ${allEvidence.length} users. ` +
                    `Reason: ${reasonForBatchCount}; estimated ${totalEstimatedTokens} tokens versus safe limit ${safeTokenLimit}.`
                );
            }
        } else if (domain.key === 'devices') {
            const emptyRequestBytes = estimateDomainRequestBytes(
                domain,
                buildDomainBatchPackage(packageResult.package, [], 1, 1)
            );
            const combinedRequestBytes = estimateDomainRequestBytes(
                domain,
                buildDomainBatchPackage(packageResult.package, allEvidence, 1, 1)
            );
            batches = splitIntoBatches(allEvidence, batchOptions);
            const basePackageTokens = Math.ceil(emptyRequestBytes / 4);
            const totalEstimatedTokens = Math.ceil(combinedRequestBytes / 4);
            const deviceTableTokens = Math.max(0, totalEstimatedTokens - basePackageTokens);
            const evidenceTokens = deviceTableTokens;
            const safeTokenLimit = Math.floor(settings.maxInputBytes / 4);
            const safeInputTokenLimit = safeTokenLimit;
            let reasonForBatchCount;
            if (!allEvidence.length) {
                reasonForBatchCount = 'no_device_evidence_rows';
            } else if (batches.length === 1) {
                reasonForBatchCount = 'all_device_rows_fit_safe_token_limit';
            } else if (combinedRequestBytes > settings.maxInputBytes && allEvidence.length > maxItems) {
                reasonForBatchCount = 'device_evidence_exceeds_safe_token_limit_and_row_safety_cap';
            } else if (combinedRequestBytes > settings.maxInputBytes) {
                reasonForBatchCount = 'device_evidence_exceeds_safe_token_limit';
            } else {
                reasonForBatchCount = `device_evidence_exceeds_${maxItems}_row_safety_cap`;
            }
            batchPlanDiagnostics = {
                basePackageTokens,
                evidenceTokens,
                deviceTableTokens,
                totalEstimatedTokens,
                safeInputTokenLimit,
                safeTokenLimit,
                plannedBatchCount: batches.length,
                reasonForBatchCount
            };
            logger.info?.(
                `[StackCTRL Enterprise] Device batch plan: basePackageTokens=${basePackageTokens}, deviceTableTokens=${deviceTableTokens}, evidenceTokens=${evidenceTokens}, totalEstimatedTokens=${totalEstimatedTokens}, safeTokenLimit=${safeTokenLimit}, plannedBatchCount=${batches.length}, reasonForBatchCount=${reasonForBatchCount}`
            );
            if (batches.length > 5) {
                logger.warn?.(
                    `[StackCTRL Enterprise] Device Protection required ${batches.length} batches for ${allEvidence.length} devices. ` +
                    `Reason: ${reasonForBatchCount}; estimated ${totalEstimatedTokens} tokens versus safe limit ${safeTokenLimit}.`
                );
            }
        } else if (domain.key === 'security_alerts') {
            const emptyRequestBytes = estimateDomainRequestBytes(
                domain,
                buildDomainBatchPackage(packageResult.package, [], 1, 1)
            );
            const combinedRequestBytes = estimateDomainRequestBytes(
                domain,
                buildDomainBatchPackage(packageResult.package, allEvidence, 1, 1)
            );
            if (packageResult.package?.securityAlertsCompactPackage && allEvidence.length <= maxItems && combinedRequestBytes <= settings.maxInputBytes) {
                batches = [{ number: 1, items: allEvidence, bytes: combinedRequestBytes, semanticGrouping: null }];
            } else {
                batches = splitSecurityAlertsIntoBatches(allEvidence, batchOptions);
            }
            const basePackageTokens = Math.ceil(emptyRequestBytes / 4);
            const totalEstimatedTokens = Math.ceil(combinedRequestBytes / 4);
            batchPlanDiagnostics = {
                basePackageTokens,
                compactPackageTokens: totalEstimatedTokens,
                evidenceTokens: Math.max(0, totalEstimatedTokens - basePackageTokens),
                totalEstimatedTokens,
                safeInputTokenLimit: Math.floor(settings.maxInputBytes / 4),
                safeTokenLimit: Math.floor(settings.maxInputBytes / 4),
                plannedBatchCount: batches.length,
                reasonForBatchCount: batches.length === 1
                    ? 'all_compact_security_alerts_rows_fit_safe_token_limit'
                    : 'compact_security_alerts_evidence_exceeds_safe_limit'
            };
            logger.info?.(`[StackCTRL Enterprise] Security Alerts evidence (${allEvidence.length} compact items, ~${totalEstimatedTokens} tokens) planned as ${batches.length} safe batch(es).`);
        } else if (packageResult.package?.strictCompactSelectedDomain) {
            const emptyRequestBytes = estimateDomainRequestBytes(
                domain,
                buildDomainBatchPackage(packageResult.package, [], 1, 1)
            );
            const combinedRequestBytes = estimateDomainRequestBytes(
                domain,
                buildDomainBatchPackage(packageResult.package, allEvidence, 1, 1)
            );
            if (allEvidence.length <= 100 && combinedRequestBytes <= settings.maxInputBytes) {
                batches = [{ number: 1, items: allEvidence, bytes: combinedRequestBytes, semanticGrouping: null }];
            } else {
                batches = splitIntoBatches(allEvidence, batchOptions);
            }
            const basePackageTokens = Math.ceil(emptyRequestBytes / 4);
            const totalEstimatedTokens = Math.ceil(combinedRequestBytes / 4);
            const evidenceTokens = Math.max(0, totalEstimatedTokens - basePackageTokens);
            const safeTokenLimit = Math.floor(settings.maxInputBytes / 4);
            const safeInputTokenLimit = safeTokenLimit;
            const historicalTokens = 0;
            const knowledgeTokens = 0;
            const previousAnalysisTokens = 0;
            const compactPackageTokens = totalEstimatedTokens;
            const excludedHistoricalTokens = Math.ceil(bytes(packageResult.package?.historicalComparisons || {}) / 4);
            const excludedPreviousAnalysisTokens = Math.ceil(bytes(packageResult.package?.previousDomainAnalysis || {}) / 4);
            const label = domain.key === 'email_security' ? 'Email Security'
                : domain.key === 'cloudflare_network_security' ? 'Cloudflare'
                : domain.name;
            let reasonForBatchCount;
            if (!allEvidence.length) {
                reasonForBatchCount = `no_compact_${domain.key}_evidence_rows`;
            } else if (batches.length === 1) {
                reasonForBatchCount = domain.key === 'email_security'
                    ? 'all_compact_email_security_rows_fit_safe_token_limit'
                    : domain.key === 'cloudflare_network_security'
                    ? 'all_cloudflare_rows_fit_safe_token_limit'
                    : `all_${domain.key}_rows_fit_safe_token_limit`;
            } else if (combinedRequestBytes > settings.maxInputBytes && allEvidence.length > maxItems) {
                reasonForBatchCount = `compact_${domain.key}_evidence_exceeds_safe_token_limit_and_row_safety_cap`;
            } else if (combinedRequestBytes > settings.maxInputBytes) {
                reasonForBatchCount = `compact_${domain.key}_evidence_exceeds_safe_token_limit`;
            } else {
                reasonForBatchCount = `compact_${domain.key}_evidence_exceeds_${maxItems}_row_safety_cap`;
            }
            batchPlanDiagnostics = {
                basePackageTokens,
                compactPackageTokens,
                evidenceTokens,
                historicalTokens,
                knowledgeTokens,
                previousAnalysisTokens,
                excludedHistoricalTokens,
                excludedPreviousAnalysisTokens,
                totalEstimatedTokens,
                safeInputTokenLimit,
                safeTokenLimit,
                plannedBatchCount: batches.length,
                reasonForBatchCount
            };
            logger.info?.(
                packageResult.package?.strictCompactSelectedDomain
                    ? `[StackCTRL Enterprise] Selected domain batch plan: domainKey=${domain.key}, compactPackageTokens=${compactPackageTokens}, evidenceTokens=${evidenceTokens}, excludedHistoricalTokens=${excludedHistoricalTokens}, excludedPreviousAnalysisTokens=${excludedPreviousAnalysisTokens}, totalEstimatedTokens=${totalEstimatedTokens}, safeTokenLimit=${safeTokenLimit}, plannedBatchCount=${batches.length}, reasonForBatchCount=${reasonForBatchCount}`
                    : `[StackCTRL Enterprise] Selected domain batch plan: domainKey=${domain.key}, basePackageTokens=${basePackageTokens}, evidenceTokens=${evidenceTokens}, historicalTokens=${historicalTokens}, knowledgeTokens=${knowledgeTokens}, previousAnalysisTokens=${previousAnalysisTokens}, totalEstimatedTokens=${totalEstimatedTokens}, safeTokenLimit=${safeTokenLimit}, plannedBatchCount=${batches.length}, reasonForBatchCount=${reasonForBatchCount}`
            );
            if (packageResult.package?.strictCompactSelectedDomain && batches.length > 1) {
                logger.warn?.(`[StackCTRL Enterprise] ${label} selected-domain package required ${batches.length} compact batches for ${allEvidence.length} row(s). Reason: ${reasonForBatchCount}.`);
            }
        } else {
            batches = splitIntoBatches(allEvidence, batchOptions);
        }
        
        packageResult.audit.batchPlan = buildEvidenceBatchPlan(allEvidence, batches, batchPlanDiagnostics);
        if (domain.key === 'security_alerts') {
            logger.info?.(`[security_alerts:azure_batch_plan:complete] ${batches.length} batch(es) planned for ${allEvidence.length} evidence record(s)`);
            await updateRunStageProgress(run.id, { stage: 'azure_analysis:start', lastSuccessfulStage: 'azure_batch_plan:complete' });
        }
        if (domain.key === 'security_alerts' && batches.length > 10 && allEvidence.length < 1000) {
            logger.warn?.(`[StackCTRL Enterprise] Security Alerts required ${batches.length} safe batches because the complete evidence payload exceeded the configured byte budget.`);
        }
        const results = [];
        const totals = { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 };
        
        logger.info(`[StackCTRL Enterprise] Processing ${domain.name} in ${batches.length} batch(es)`);
        
        for (const batch of batches) {
            const evidenceStartIndex = batches
                .slice(0, batch.number - 1)
                .reduce((count, plannedBatch) => count + plannedBatch.items.length, 0);
            const recordsRemaining = Math.max(0, allEvidence.length - (evidenceStartIndex + batch.items.length));
            await updateRunBatchProgress(run.id, {
                domainKey: domain.key,
                batchNumber: batch.number,
                batchCount: batches.length,
                recordsPrepared: allEvidence.length,
                recordsRemaining: recordsRemaining + batch.items.length
            });
            if (domain.key === 'security_alerts') logger.info?.(`[security_alerts:azure_analysis:start] Batch ${batch.number}/${batches.length}`);
            const batchResults = await processBatchEvidenceWithRecovery({
                companyId, snapshot, run, domain, packageResult,
                batchEvidence: batch.items, batchNumber: batch.number, totalBatches: batches.length,
                historicalContext,
                recordsRemaining,
                evidenceStartIndex,
                semanticGrouping: batch.semanticGrouping || null
            });
            let stopDomainBatches = false;
            for (const result of batchResults) {
                results.push(result);
                if (domain.key === 'security_alerts') {
                    const warning = result.status === 'completed_with_warnings'
                        ? (result.jsonRepairMethod || result.failureReason || 'azure_analysis_warning')
                        : null;
                    logger.info?.(`[security_alerts:azure_analysis:complete] Batch ${batch.number}/${batches.length} ${result.status}`);
                    await updateRunStageProgress(run.id, {
                        stage: result.status,
                        lastSuccessfulStage: isSuccessfulDomainStatus(result.status)
                            ? `azure_analysis:complete:batch_${batch.number}`
                            : `azure_analysis:batch_${batch.number - 1}`,
                        warning,
                        failureReason: isSuccessfulDomainStatus(result.status)
                            ? null
                            : (result.failureReason || result.errorMessage || result.status)
                    });
                }
                for (const key of Object.keys(totals)) {
                    totals[key] += result.usage?.[key] || 0;
                }

                if (isSuccessfulDomainStatus(result.status)) {
                    const progressiveAnalysis = mergeCompletedBatchAnalyses({
                        results,
                        domain,
                        packageResult,
                        snapshotId: snapshot.ID,
                        totalBatches: batches.length
                    });
                    packageResult.audit.sentToAzureCount = progressiveAnalysis.evidenceLimitations.recordsSent;
                    await storeDomain({
                        run,
                        companyId,
                        snapshot,
                        domain,
                        packageResult,
                        analysis: progressiveAnalysis,
                        usage: totals,
                        status: 'running',
                        persistItems: false
                    });
                }

                if (result.status === 'failed_rate_limited') {
                    logger.warn?.(`[StackCTRL Enterprise] Stopping ${domain.name} after an exhausted Azure 429 retry budget.`);
                    stopDomainBatches = true;
                    break;
                }
                if (!isSuccessfulDomainStatus(result.status) && !isConnectionFailureResult(result)) {
                    logger.error?.(`[StackCTRL Enterprise] Stopping ${domain.name} after batch ${batch.number} failed with ${result.status}; remaining evidence is retained and recorded as omitted for this attempt.`);
                    stopDomainBatches = true;
                    break;
                }
            }
            if (stopDomainBatches) break;

            const lastBatchResult = batchResults.at(-1);
            if (batch.number < batches.length) {
                const delayMs = computeInterBatchDelayMs(lastBatchResult?.usage?.inputTokens || 0, settings, domain.key);
                if (delayMs > 0) await wait(delayMs);
            }
        }
        
        const completedCount = results.filter(result => isSuccessfulDomainStatus(result.status)).length;
        const processedItems = results.filter(result => isSuccessfulDomainStatus(result.status))
            .reduce((total, result) => total + Number(result.batchItemCount || 0), 0);
        const rateLimitedBatch = results.find(result => result.status === 'failed_rate_limited');
        const omittedItems = rateLimitedBatch ? 0 : Math.max(0, allEvidence.length - processedItems);
        return {
            results,
            batchCount: batches.length,
            totals,
            processedItems,
            omittedItems,
            complete: !rateLimitedBatch && completedCount === batches.length && omittedItems === 0,
            rateLimited: Boolean(rateLimitedBatch),
            recommendedRetryAfterMs: rateLimitedBatch?.recommendedRetryAfterMs || null
        };
    }

    async function findActiveEnterpriseRun(companyId) {
        const [rows] = await pool.query(
            `SELECT ID, SnapshotID, Status, PeriodType, Mode, StartedAt
             FROM StackCTRLEnterpriseReportRuns
             WHERE CompanyID = ? AND Status IN ('queued', 'running')
             ORDER BY ID DESC LIMIT 1`,
            [Number(companyId)]
        );
        return rows[0] || null;
    }

    async function createRun({ companyId, snapshotId, periodType, referenceDate, mode, deduplicationKey = null }) {
        const window = periodWindow(periodType, referenceDate);
        let result;
        try {
            [result] = await pool.query(
                `INSERT INTO StackCTRLEnterpriseReportRuns
                 (CompanyID, SnapshotID, PeriodType, PeriodStart, PeriodEnd, Status, Mode, DeduplicationKey, StartedAt)
                 VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, NOW())`,
                [companyId, snapshotId || null, window.periodType, window.periodStart, window.periodEnd, mode, deduplicationKey]
            );
        } catch (error) {
            if (error?.code !== 'ER_DUP_ENTRY' || !deduplicationKey) throw error;
            const [rows] = await pool.query(
                `SELECT ID, SnapshotID, Status
                 FROM StackCTRLEnterpriseReportRuns
                 WHERE DeduplicationKey = ? LIMIT 1`,
                [deduplicationKey]
            );
            const existing = rows[0] || {};
            const existingStatus = String(existing.Status || 'duplicate').toLowerCase();
            return {
                id: Number(existing.ID),
                snapshotId: existing.SnapshotID ? Number(existing.SnapshotID) : null,
                ...window,
                mode,
                duplicate: true,
                existingStatus
            };
        }
        await pool.query(`UPDATE StackCTRLEnterpriseReportRuns SET Status = 'running' WHERE ID = ?`, [result.insertId]);
        return { id: Number(result.insertId), ...window, mode };
    }

    async function recordPipelinePhase(runId, phase, metadata = {}) {
        if (!runId) return;
        await pool.query(
            `UPDATE StackCTRLEnterpriseReportRuns SET ProgressJson = ? WHERE ID = ?`,
            [JSON.stringify({ phase, ...metadata, timestamp: new Date().toISOString() }), Number(runId)]
        );
    }
    function buildRunProgress({
        run,
        domainKeys = [],
        results = [],
        currentDomainKey = null,
        phase = 'domains',
        synthesisStatus = null,
        rateLimit = null,
        snapshot = null,
        disabledDomainKeys = TEMPORARILY_DISABLED_DOMAIN_KEYS
    } = {}) {
        const completed = results.filter(result => result.status === 'completed').length;
        const partial = results.filter(result => result.status === 'partial').length;
        const failed = results.filter(result => String(result.status || '').startsWith('failed')).length;
        const blocked = results.filter(result => String(result.status || '').startsWith('blocked')).length;
        const skipped = results.filter(result => SKIPPED_DOMAIN_STATUSES.has(String(result.status || ''))).length;
        const successful = results.filter(result => isSuccessfulDomainStatus(result.status)).length;
        const disabledDomains = disabledDomainStates(disabledDomainKeys);
        const queue = domainKeys.map(key => {
            const result = results.find(item => item.domain?.key === key);
            return {
                domainKey: key,
                domainName: DOMAIN_BY_KEY[key]?.name || key,
                status: result?.status || (currentDomainKey === key ? 'running' : 'queued'),
                selectable: true,
                includedInCurrentPhase: true,
                errorMessage: result?.errorMessage || null
            };
        });
        return {
            phase,
            runId: run?.id || null,
            mode: run?.mode || null,
            snapshotId: snapshot?.ID || null,
            snapshotCreatedAt: snapshot?.CreatedAt || null,
            currentDomainKey,
            currentDomainName: currentDomainKey ? (DOMAIN_BY_KEY[currentDomainKey]?.name || currentDomainKey) : null,
            domainQueue: queue,
            disabledDomains,
            reportingPhase: CURRENT_REPORTING_PHASE,
            counts: {
                total: domainKeys.length,
                active: domainKeys.length,
                disabled: disabledDomains.length,
                completed,
                partial,
                successful,
                failed,
                blocked,
                skipped,
                processed: results.length
            },
            synthesisStatus,
            rateLimit: rateLimit ? {
                domainKey: rateLimit.domainKey || null,
                retryAfterMs: rateLimit.retryAfterMs || null,
                active: true
            } : null,
            updatedAt: new Date().toISOString()
        };
    }

    async function updateRunProgress(runId, progress, totals = null) {
        const params = [JSON.stringify(progress || {}), Number(runId)];
        let sql = `UPDATE StackCTRLEnterpriseReportRuns SET ProgressJson = ? WHERE ID = ?`;
        if (totals) {
            sql = `UPDATE StackCTRLEnterpriseReportRuns
                   SET ProgressJson = ?, TotalInputTokens = ?, TotalOutputTokens = ?, TotalTokens = ?,
                       TotalRequestBytes = ?, TotalResponseBytes = ?, RetryCount = ?
                   WHERE ID = ?`;
            params.splice(1, 0, totals.inputTokens, totals.outputTokens, totals.totalTokens, totals.requestBytes, totals.responseBytes, totals.retries);
        }
        try {
            await pool.query(sql, params);
        } catch (error) {
            if (error?.code !== 'ER_BAD_FIELD_ERROR') throw error;
            if (!totals) return;
            await pool.query(
                `UPDATE StackCTRLEnterpriseReportRuns
                 SET TotalInputTokens = ?, TotalOutputTokens = ?, TotalTokens = ?,
                     TotalRequestBytes = ?, TotalResponseBytes = ?, RetryCount = ?
                 WHERE ID = ?`,
                [totals.inputTokens, totals.outputTokens, totals.totalTokens, totals.requestBytes, totals.responseBytes, totals.retries, Number(runId)]
            );
        }
    }

    async function updateRunBatchProgress(runId, { domainKey, batchNumber, batchCount, recordsPrepared, recordsRemaining }) {
        await pool.query(
            `UPDATE StackCTRLEnterpriseReportRuns
             SET ProgressJson = JSON_SET(
                 COALESCE(ProgressJson, JSON_OBJECT()),
                 '$.currentDomainKey', ?, '$.currentBatch', ?, '$.batchCount', ?,
                 '$.recordsPrepared', ?, '$.recordsRemaining', ?, '$.updatedAt', ?
             ) WHERE ID = ?`,
            [domainKey, Number(batchNumber), Number(batchCount), Number(recordsPrepared), Number(recordsRemaining), new Date().toISOString(), Number(runId)]
        );
    }

    async function updateRunStageProgress(runId, { stage, lastSuccessfulStage = null, warning = null, failureReason = null }) {
        await pool.query(
            `UPDATE StackCTRLEnterpriseReportRuns
             SET ProgressJson = JSON_SET(
                 COALESCE(ProgressJson, JSON_OBJECT()),
                 '$.currentStage', ?, '$.lastSuccessfulStage', ?, '$.stageWarning', ?,
                 '$.stageFailureReason', ?, '$.updatedAt', ?
             ) WHERE ID = ?`,
            [stage, lastSuccessfulStage, warning, failureReason, new Date().toISOString(), Number(runId)]
        );
    }

    async function storeSkippedDomain({ run, companyId, snapshot, domain, status, errorMessage }) {
        const usage = { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 };
        const packageResult = await buildDomainPackage({ companyId, snapshot, runId: run.id, domain, historicalContext: { comparisons: {} } });
        packageResult.audit.sentToAzureCount = 0;
        await storeDomain({
            run, companyId, snapshot, domain, packageResult, analysis: null, usage,
            status, errorMessage
        });
        await storeAudit({
            run, companyId, snapshot, domain, packageResult, analysis: null, usage,
            status
        });
        return {
            status,
            domain,
            usage,
            audit: packageResult.audit,
            errorMessage
        };
    }

    function buildLimitedDataAnalysis({ domain, packageResult, reason }) {
        const warning = reason || `${domain.name} source data is limited or unavailable. Enterprise Deep Reporting continued with warning-only evidence.`;
        const warnings = [...new Set([
            ...array(packageResult.package.limitations?.missingDataWarnings),
            warning
        ].filter(Boolean))];
        return {
            domainExecutiveSummary: `${domain.name} could not be fully analysed because StackCTRL has limited source evidence for this snapshot.`,
            technicalSummary: 'No entity-level evidence was available for Azure analysis in this domain package.',
            businessImpact: 'This domain should be treated as unverified until the source connector produces a complete evidence snapshot.',
            currentPosture: 'limited evidence',
            evidenceUsed: [],
            evidenceGaps: [warning],
            scoreJustification: 'Authoritative StackCTRL scores were retained where available; no replacement score was calculated from missing evidence.',
            controlAssessment: [],
            keyFindings: [],
            risks: [{
                title: `${domain.name} evidence gap`,
                severity: 'medium',
                status: 'open',
                sourceDomain: domain.key,
                sourceMetric: 'sourceHealth',
                evidenceSummary: warning,
                businessImpact: 'Management reporting may understate this domain until evidence collection is restored.',
                recommendation: 'Refresh the source connector and rerun Enterprise Deep Reporting.'
            }],
            recommendations: [{
                title: `Refresh ${domain.name} evidence`,
                priority: 'medium',
                sourceDomain: domain.key,
                sourceMetric: 'sourceHealth',
                detail: 'Restore source collection, confirm a complete saved evidence snapshot, and rerun the enterprise report.',
                recommendedAction: 'Restore source collection, confirm a complete saved evidence snapshot, and rerun the enterprise report.'
            }],
            trendAnalysis: [],
            yesterdayVsToday: {},
            whatImproved: [],
            whatDeteriorated: [],
            whatStayedTheSame: [],
            missingDataWarnings: warnings,
            assumptions: ['No control gap was inferred beyond the missing source evidence.'],
            confidenceScore: 0,
            managementActions: [{
                title: `Confirm ${domain.name} data collection`,
                priority: 'medium',
                sourceDomain: domain.key,
                sourceMetric: 'sourceHealth',
                detail: 'Check connector credentials, permissions, and latest evidence snapshot status.'
            }],
            powerBiSummary: { status: 'limited_data', warning },
            evidenceCatalog: packageResult.evidenceCatalog,
            evidenceLimitations: {
                recordsPrepared: 0,
                recordsSent: 0,
                recordsOmitted: Number(packageResult.audit.evidenceOmittedCount || 0),
                totalEntityRows: Number(packageResult.audit.stackCTRLDataCount || 0),
                catalogEntityCount: Number(packageResult.audit.catalogEntityCount || 0),
                catalogCategoryCount: Number(packageResult.audit.catalogCategoryCount || 0),
                completedBatches: 0,
                totalBatches: 0,
                accountingComplete: true,
                complete: false,
                omittedReasons: warnings
            },
            authoritativeScores: {
                healthScore: packageResult.current.healthScore,
                riskScore: packageResult.current.riskScore,
                riskLevel: packageResult.current.riskLevel
            },
            domain: { key: domain.key, name: domain.name }
        };
    }

    function buildInvalidJsonFallbackAnalysis({ domain, snapshot, packageResult, batchEvidence, errorMessage, rawResponseStored }) {
        const recordsPrepared = array(batchEvidence).length;
        const omittedReasons = [...new Set([
            ...array(packageResult.package.limitations?.missingDataWarnings),
            errorMessage
        ].filter(Boolean))];
        const evidenceAvailable = recordsPrepared > 0;
        return normalizedDomainResult({
            domainKey: domain.key,
            status: 'completed_with_warnings',
            warningType: 'azure_invalid_json',
            snapshotId: snapshot.ID,
            recordsPrepared,
            recordsSent: recordsPrepared,
            recordsOmitted: 0,
            omittedReasons,
            evidenceAvailable,
            message: errorMessage,
            rawAzureResponseStored: Boolean(rawResponseStored),
            domainExecutiveSummary: `${domain.name} evidence was sent to Azure, but the returned JSON was invalid. StackCTRL preserved the raw response and continued the pipeline.`,
            technicalSummary: 'Azure returned malformed structured output after one compact repair attempt. A deterministic local warning object replaced that batch output.',
            businessImpact: 'Domain conclusions are unavailable from this batch, but complete StackCTRL raw evidence remains available to Power BI and later domains continue processing.',
            currentPosture: 'analysis completed with Azure JSON warning',
            evidenceUsed: [],
            evidenceGaps: [{ gap: 'Azure structured analysis unavailable', reason: errorMessage, omittedCount: 0, sourceMetric: 'azure_response' }],
            scoreJustification: 'Authoritative StackCTRL scores were retained; no Azure-derived score was accepted from malformed JSON.',
            controlAssessment: [],
            keyFindings: [],
            risks: [],
            recommendations: [],
            trendAnalysis: [],
            yesterdayVsToday: {},
            whatImproved: [],
            whatDeteriorated: [],
            whatStayedTheSame: [],
            missingDataWarnings: omittedReasons,
            assumptions: ['No malformed Azure content was promoted into domain findings, risks, or recommendations.'],
            confidenceScore: 0,
            managementActions: [],
            powerBiSummary: {
                domainKey: domain.key,
                status: 'completed_with_warnings',
                warningType: 'azure_invalid_json',
                snapshotId: snapshot.ID,
                recordsPrepared,
                recordsSent: recordsPrepared,
                recordsOmitted: 0,
                omittedReasons,
                evidenceAvailable,
                message: errorMessage,
                rawAzureResponseStored: Boolean(rawResponseStored)
            },
            evidenceLimitations: {
                recordsPrepared,
                recordsSent: recordsPrepared,
                recordsOmitted: 0,
                complete: false,
                accountingComplete: true,
                omittedReasons
            }
        }, domain, packageResult.current, snapshot.ID, batchEvidence);
    }

    async function refreshEnterpriseSnapshot(companyId, user = {}, collectorContext = {}) {
        if (!intelligenceService?.createSnapshot) return null;
        const timeoutMs = settings.snapshotTimeoutMs;
        const controller = new AbortController();
        let timer = null;
        const timeout = new Promise((_, reject) => {
            timer = setTimeout(() => {
                const error = new Error(`Enterprise snapshot creation exceeded ${timeoutMs}ms.`);
                error.enterpriseStatus = 'failed_snapshot_timeout';
                error.failureStage = 'SNAPSHOT_CREATION_FAILED';
                error.code = 'ENTERPRISE_SNAPSHOT_TIMEOUT';
                controller.abort(error);
                reject(error);
            }, timeoutMs);
        });
        try {
            return await Promise.race([
                intelligenceService.createSnapshot({
                    companyId: Number(companyId),
                    options: {
                        snapshotType: 'enterprise_pipeline',
                        refresh: true,
                        refreshTimeoutMs: settings.sourceRefreshTimeoutMs,
                        signal: controller.signal,
                        collectorContext
                    },
                    user
                }),
                timeout
            ]);
        } finally {
            clearTimeout(timer);
        }
    }

    async function bindSnapshotToRun(run, snapshot, phase, metadata = {}) {
        const progress = { phase, ...metadata, timestamp: new Date().toISOString() };
        const [result] = await pool.query(
            `UPDATE StackCTRLEnterpriseReportRuns
             SET SnapshotID = ?, ProgressJson = ?
             WHERE ID = ? AND CompanyID = ? AND Status = 'running' AND SnapshotID IS NULL`,
            [Number(snapshot.ID), JSON.stringify(progress), Number(run.id), Number(metadata.enterpriseId)]
        );
        if (Number(result?.affectedRows || 0) !== 1) {
            throw new Error(`Enterprise run #${run.id} could not be atomically bound to snapshot #${snapshot.ID}.`);
        }
    }

    function normalizedDomainResult(data, domain, current, snapshotId = null, availableEvidence = []) {
        const value = data && typeof data === 'object' && !Array.isArray(data) ? data : {};
        const resolvedSnapshotId = snapshotId ?? current?.snapshotId ?? null;
        const normalizeItems = items => array(items)
            .map(item => ensureItemEvidence(item, domain, resolvedSnapshotId, availableEvidence));
        const normalizeReasoningSection = section => Array.isArray(section)
            ? normalizeItems(section)
            : (section && typeof section === 'object' ? sanitizeVisibleValue(section) : visibleTextOrNull(section, 8000));
        const collectionWindow = domain.key === 'identity'
            ? (value.collectionWindow || {
                sourceSystem: 'Microsoft Graph / StackCTRL Identity',
                collectedAt: current?.source?.collectedAt || current?.source?.freshness?.lastUpdated || null,
                snapshotCapturedAt: current?.source?.snapshotCapturedAt || null,
                sourceLastUpdatedAt: current?.source?.freshness?.lastUpdated || current?.source?.lastUpdatedAt || null,
                sourceAgeMinutes: numberOrNull(current?.source?.freshness?.ageMinutes),
                reportingWindow: 'current tenant state, plus lastSignIn history where available'
            })
            : domain.key === 'devices'
            ? (value.collectionWindow || {
                sourceSystem: 'Microsoft Graph / Intune / StackCTRL Devices',
                collectedAt: current?.source?.sourceLineage?.collectedAt || current?.source?.freshness?.lastUpdated || null,
                snapshotCapturedAt: current?.source?.sourceLineage?.collectedAt || null,
                sourceLastUpdatedAt: current?.source?.freshness?.lastUpdated || current?.source?.sourceLineage?.sourceFetchedAt || null,
                sourceAgeMinutes: numberOrNull(current?.source?.freshness?.ageMinutes),
                reportingWindow: 'current tenant device state from the frozen StackCTRL Device Protection snapshot'
            })
            : (value.collectionWindow || null);
        const missingDataInfo = [...new Set([
            ...array(value.missingDataInfo).map(info => visibleTextOrNull(info, 1200)).filter(Boolean),
            ...(domain.key === 'identity' ? ['Historical baseline not available yet for 7/30/90-day trend analysis.'] : []),
            ...(domain.key === 'devices' && current?.source?.status === 'stale'
                ? [`Device Protection source is stale. Latest stored evidence was used from ${current?.source?.freshness?.lastUpdated || 'unknown refresh time'}.`]
                : []),
            ...(domain.key === 'devices' ? ['Curated Device Protection references unavailable.'].filter(info =>
                array(value.missingDataInfo).some(existing => /curated device protection/i.test(String(existing))) ||
                array(value.missingDataWarnings).some(existing => /curated device protection|best-practice/i.test(String(existing)))
            ) : [])
        ])];
        const missingDataWarnings = [...new Set(array(value.missingDataWarnings)
            .map(warning => cleanRuntimeWarningForDisplay(warning, { domain, current, hasUsableEvidence: availableEvidence.length > 0 }))
            .filter(Boolean)
            .filter(warning => !(domain.key === 'identity' && /historical baseline|7\/30\/90|best-practice references/i.test(warning)))
            .filter(warning => !(domain.key === 'devices' && /source_stale|source is stale|evidence is stale|curated.*reference|best-practice references/i.test(warning)))
            .filter(warning => !(domain.key === 'cloudflare_network_security' && /curated.*reference|best-practice references|knowledge references/i.test(warning))))];
        return compactSelectedDomainAnalysis({
            ...value,
            domainKey: value.domainKey || domain.key,
            status: textOrNull(value.status, 80),
            warningType: textOrNull(value.warningType, 120),
            snapshotId: numberOrNull(value.snapshotId ?? resolvedSnapshotId),
            recordsPrepared: numberOrNull(value.recordsPrepared),
            recordsSent: numberOrNull(value.recordsSent),
            recordsOmitted: numberOrNull(value.recordsOmitted),
            omittedReasons: array(value.omittedReasons).map(reason => textOrNull(reason, 1200)).filter(Boolean),
            evidenceAvailable: value.evidenceAvailable == null ? null : Boolean(value.evidenceAvailable),
            message: visibleTextOrNull(value.message, 1200),
            rawAzureResponseStored: Boolean(value.rawAzureResponseStored),
            domainExecutiveSummary: visibleTextOrNull(value.domainExecutiveSummary, 4000),
            technicalReasoning: Array.isArray(value.technicalReasoning)
                ? sanitizeVisibleValue(value.technicalReasoning)
                : visibleTextOrNull(value.technicalReasoning || value.technicalSummary, 8000),
            riskPrioritization: normalizeReasoningSection(value.riskPrioritization),
            technicalSummary: visibleTextOrNull(value.technicalSummary, 4000),
            businessImpact: visibleTextOrNull(value.businessImpact, 4000),
            currentPosture: visibleTextOrNull(value.currentPosture, 4000),
            scoreJustification: visibleTextOrNull(value.scoreJustification, 4000),
            evidenceUsed: sanitizeVisibleValue(array(value.evidenceUsed)),
            evidenceGaps: sanitizeVisibleValue(array(value.evidenceGaps)),
            controlAssessment: normalizeControlAssessment(value.controlAssessment || {}, domain, resolvedSnapshotId, availableEvidence),
            highestRiskPatterns: normalizeItems(value.highestRiskPatterns),
            keyFindings: normalizeItems(value.keyFindings),
            risks: normalizeItems(value.risks),
            recommendations: normalizeItems(value.recommendations),
            affectedEntities: uniqueEntities(array(value.affectedEntities)
                .map(entity => canonicalEntity(entity, {
                    sourceDomain: domain.key,
                    businessReason: entity?.reason || entity?.businessReason || value.businessImpact || value.currentPosture,
                    recommendation: entity?.recommendation || value.recommendation || value.recommendedAction
                }))
                .filter(Boolean)),
            trendAnalysis: normalizeItems(value.trendAnalysis),
            yesterdayVsToday: value.yesterdayVsToday || {},
            whatImproved: array(value.whatImproved),
            whatDeteriorated: array(value.whatDeteriorated),
            whatStayedTheSame: array(value.whatStayedTheSame),
            missingDataWarnings,
            missingDataInfo,
            assumptions: array(value.assumptions).map(assumption => visibleTextOrNull(assumption, 1200)).filter(Boolean),
            confidenceScore: numberOrNull(value.confidenceScore),
            managementActions: normalizeItems(value.managementActions),
            managementDecisionsRequired: normalizeItems(value.managementDecisionsRequired),
            whatCanWait: normalizeItems(value.whatCanWait),
            powerBiSummary: value.powerBiSummary || {},
            evidenceLimitations: value.evidenceLimitations || {},
            collectionWindow,
            evidenceCatalog: value.evidenceCatalog || null,
            batchInfo: value.batchInfo || null,
            authoritativeScores: { healthScore: current.healthScore, riskScore: current.riskScore, riskLevel: current.riskLevel },
            domain: { key: domain.key, name: domain.name }
        }, domain);
    }

    async function insertItem({ companyId, snapshotId, runId, domainKey, domainName, period, itemType, item, source }) {
        const title = item?.title || item?.metricName || item?.name || item?.action || `${domainName} ${itemType}`;
        const suggestedDueDate = normalizeMysqlDate(item?.suggestedDueDate || item?.dueDate || item?.targetDate || item?.actionDueDate || item?.reviewDate || item?.completionDate);
        const affectedEntities = array(item?.affectedEntities);
        const evidenceRows = array(item?.evidenceRows);
        const entityEvidence = affectedEntities.length ? affectedEntities : evidenceRows;
        const evidenceSummary = textOrNull(
            item?.evidenceSummary ||
            (entityEvidence.length ? `${entityEvidence.length} affected entity row(s) from ${item?.sourceMetric || item?.evidenceSource || domainKey}` : null),
            4000
        );
        await pool.query(
            `INSERT INTO StackCTRLEnterpriseIntelligenceItems
             (CompanyID, SnapshotID, RunID, DomainKey, DomainName, PeriodType, PeriodStart, PeriodEnd,
              ItemType, Title, Description, Severity, Priority, Status, Likelihood, Impact,
              BusinessImpact, EvidenceSummary, Recommendation, SuggestedOwner, SuggestedDueDate,
              Direction, CurrentValue, PreviousValue, ChangePercent, ComparisonPeriod, SourceStage, CreatedAt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
            [
                companyId, snapshotId || null, runId, domainKey, domainName,
                period.periodType, period.periodStart, period.periodEnd, itemType,
                textOrNull(title, 255), textOrNull(item?.description || item?.detail || item?.explanation),
                textOrNull(item?.severity, 50), textOrNull(item?.priority, 50), textOrNull(item?.status, 50),
                textOrNull(item?.likelihood, 80), textOrNull(item?.impact, 120),
                textOrNull(item?.businessImpact || item?.businessReason), evidenceSummary,
                textOrNull(item?.recommendation), textOrNull(item?.suggestedOwner || item?.owner, 180),
                suggestedDueDate, textOrNull(item?.direction, 50),
                numberOrNull(item?.currentValue), numberOrNull(item?.previousValue), numberOrNull(item?.changePercent),
                textOrNull(item?.comparisonPeriod, 50), source
            ]
        );
    }

    async function deleteItemsForDomainRun({ runId, domainKey }) {
        // Delete old items for this RunID + DomainKey before reinserting (prevents duplicates on reruns)
        await pool.query(
            `DELETE FROM StackCTRLEnterpriseIntelligenceItems WHERE RunID = ? AND DomainKey = ?`,
            [runId, domainKey]
        );
    }

    async function storeItems({ companyId, snapshotId, runId, domain, period, analysis, source = 'domain' }) {
        // Clean up old items for this domain run before inserting new ones (makes reruns idempotent)
        await deleteItemsForDomainRun({ runId, domainKey: domain.key });
        
        const groups = [
            ['finding', analysis.keyFindings],
            ['risk', analysis.risks || analysis.riskRegister],
            ['recommendation', analysis.recommendations],
            ['trend', analysis.trendAnalysis],
            ['management_action', analysis.managementActions],
            ['decision', analysis.topDecisionsRequired],
            ['management_action', analysis.next30DaysPlan],
            ['management_action', analysis.next90DaysPlan]
        ];
        for (const [itemType, items] of groups) {
            for (const itemValue of array(items)) {
                const item = typeof itemValue === 'string' ? { title: itemValue } : itemValue;
                await insertItem({ companyId, snapshotId, runId, domainKey: item?.domainKey || domain.key, domainName: item?.domainName || domain.name, period, itemType, item, source });
            }
        }
    }

    async function storeDomain({ run, companyId, snapshot, domain, packageResult, analysis, usage, status = 'completed', errorMessage = null, persistItems = true }) {
        const evidenceSummary = analysis ? textOrNull(analysis.evidenceUsed) : null;
        const [result] = await pool.query(
            `INSERT INTO StackCTRLTenantDomainIntelligence
             (CompanyID, SnapshotID, RunID, DomainKey, DomainName, PeriodType, PeriodStart, PeriodEnd,
              HealthScore, RiskScore, RiskLevel, InputSizeBytes, ResponseSizeBytes, InputTokens,
              OutputTokens, TotalTokens, RetryCount, Status, AnalysisJson, DomainExecutiveSummary,
              TechnicalSummary, BusinessImpact, CurrentPosture, EvidenceSummary, ScoreJustification,
              ControlAssessment, FindingsJson, RisksJson, RecommendationsJson, TrendAnalysisJson,
              YesterdayVsTodayJson, MissingDataWarningsJson, AssumptionsJson, ConfidenceScore, ErrorMessage)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
              HealthScore = VALUES(HealthScore), RiskScore = VALUES(RiskScore), RiskLevel = VALUES(RiskLevel),
              InputSizeBytes = VALUES(InputSizeBytes), ResponseSizeBytes = VALUES(ResponseSizeBytes),
              InputTokens = VALUES(InputTokens), OutputTokens = VALUES(OutputTokens), TotalTokens = VALUES(TotalTokens),
              RetryCount = VALUES(RetryCount), Status = VALUES(Status), AnalysisJson = VALUES(AnalysisJson),
              DomainExecutiveSummary = VALUES(DomainExecutiveSummary), TechnicalSummary = VALUES(TechnicalSummary),
              BusinessImpact = VALUES(BusinessImpact), CurrentPosture = VALUES(CurrentPosture),
              EvidenceSummary = VALUES(EvidenceSummary), ScoreJustification = VALUES(ScoreJustification),
              ControlAssessment = VALUES(ControlAssessment), FindingsJson = VALUES(FindingsJson),
              RisksJson = VALUES(RisksJson), RecommendationsJson = VALUES(RecommendationsJson),
              TrendAnalysisJson = VALUES(TrendAnalysisJson), YesterdayVsTodayJson = VALUES(YesterdayVsTodayJson),
              MissingDataWarningsJson = VALUES(MissingDataWarningsJson), AssumptionsJson = VALUES(AssumptionsJson),
              ConfidenceScore = VALUES(ConfidenceScore), ErrorMessage = VALUES(ErrorMessage)`,
            [
                companyId, snapshot.ID, run.id, domain.key, domain.name, run.periodType, run.periodStart, run.periodEnd,
                packageResult.current.healthScore, packageResult.current.riskScore, packageResult.current.riskLevel,
                usage.requestBytes || packageResult.audit.inputSizeBytes, usage.responseBytes, usage.inputTokens, usage.outputTokens, usage.totalTokens,
                usage.retries, status, analysis ? JSON.stringify(analysis) : null,
                analysis?.domainExecutiveSummary || null, analysis?.technicalSummary || null, analysis?.businessImpact || null,
                analysis?.currentPosture || null, evidenceSummary, analysis?.scoreJustification || null,
                analysis ? JSON.stringify(analysis.controlAssessment || {}) : null,
                analysis ? jsonArray(analysis.keyFindings) : null, analysis ? jsonArray(analysis.risks) : null,
                analysis ? jsonArray(analysis.recommendations) : null, analysis ? jsonArray(analysis.trendAnalysis) : null,
                analysis ? JSON.stringify(analysis.yesterdayVsToday || {}) : null,
                analysis ? jsonArray(analysis.missingDataWarnings) : null, analysis ? jsonArray(analysis.assumptions) : null,
                analysis?.confidenceScore ?? null, errorMessage ? String(errorMessage).slice(0, 5000) : null
            ]
        );
        if (analysis && persistItems) await storeItems({ companyId, snapshotId: snapshot.ID, runId: run.id, domain, period: run, analysis });
        return result.insertId || result.affectedRows;
    }

    async function storeAudit({ run, companyId, snapshot, domain, packageResult, analysis, usage, status, batchResults = null, failureReason = null, warningReasons = [], azureAttemptDiagnostics = [], currentBatch = null }) {
        const combinedText = JSON.stringify(analysis || {}).toLowerCase();
        const domainRunAudit = buildDomainRunAudit({
            domain,
            companyId,
            snapshot,
            packageResult,
            usage,
            status,
            batchResults,
            failureReason,
            warningReasons,
            azureAttemptDiagnostics,
            currentBatch
        });
            const auditInputValue = packageResult.package?.strictCompactSelectedDomain || packageResult.package?.securityAlertsCompactPackage
                ? {
                ...buildDomainBatchPackage(packageResult.package, array(packageResult.allEvidence).slice(0, 100), 1, 1),
                jsonStatus: analysis
                    ? (array(analysis.missingDataWarnings).some(warning => /recovered|incomplete json|closing json/i.test(String(warning))) ? 'recovered_with_warnings' : 'valid')
                    : 'not_available'
            }
            : {
                ...packageResult.package,
                domainRunAudit,
                evidenceBatchPlan: packageResult.audit.batchPlan,
                evidenceSample: packageResult.audit.evidenceSample,
                tokenTracking: {
                    estimatedInputTokens: Math.ceil(Number(usage.requestBytes || packageResult.audit.inputSizeBytes || 0) / 4),
                    actualInputTokens: usage.inputTokens,
                    actualOutputTokens: usage.outputTokens,
                    inputTokens: usage.inputTokens,
                    outputTokens: usage.outputTokens,
                    totalTokens: usage.totalTokens,
                    thresholdUsed: settings.maxTotalTokens,
                    retryCount: usage.retries || 0,
                    retryOrCooldownOccurred: Boolean((usage.retries || 0) > 0),
                    batchCount: packageResult.audit.batchPlan?.batchCount || 0,
                    recordsSent: packageResult.audit.sentToAzureCount,
                    recordsOmitted: packageResult.audit.evidenceOmittedCount,
                    evidenceRowsIncluded: packageResult.audit.sentToAzureCount,
                    catalogEntityCount: packageResult.audit.catalogEntityCount,
                    catalogCategoryCount: packageResult.audit.catalogCategoryCount
                },
                jsonStatus: analysis
                    ? (array(analysis.missingDataWarnings).some(warning => /recovered|incomplete json|closing json/i.test(String(warning))) ? 'recovered_with_warnings' : 'valid')
                    : 'not_available'
            };
        const auditInput = JSON.stringify(auditInputValue);
        const auditOmitted = JSON.stringify({
            stackCTRLDataCount: packageResult.audit.stackCTRLDataCount,
            sentToAzureCount: packageResult.audit.sentToAzureCount,
            omittedCount: packageResult.audit.omittedCount,
            evidenceOmittedCount: packageResult.audit.evidenceOmittedCount,
            catalogEntityCount: packageResult.audit.catalogEntityCount,
            catalogCategoryCount: packageResult.audit.catalogCategoryCount,
            batchPlan: packageResult.audit.batchPlan,
            detailReducedToMeetInputLimit: Boolean(packageResult.package.limitations?.detailReducedToMeetInputLimit),
            evidenceCompleteness: packageResult.package.limitations?.evidenceCompleteness || null,
            complete: packageResult.package.limitations?.evidenceCompleteness?.complete ?? null,
            omittedReasons: array(packageResult.package.limitations?.missingDataWarnings).slice(0, 20)
        });
        const azureMentioned = combinedText.includes(domain.key.replaceAll('_', ' ')) || combinedText.includes(domain.name.toLowerCase()) ? 1 : 0;
        const risksCount = array(analysis?.risks).length;
        const recommendationsCount = array(analysis?.recommendations).length;
        const trendsCount = array(analysis?.trendAnalysis).length;
        const inputBytes = usage.requestBytes || packageResult.audit.inputSizeBytes;
        await pool.query(
            `INSERT INTO StackCTRLIntelligenceEvidenceAudit
             (CompanyID, SnapshotID, RunID, DomainKey, StackCTRLDataCount, SentToAzureCount,
              OmittedCount, MetricsIncludedCount, EvidenceIncludedCount, EvidenceOmittedCount,
              HistoricalComparisonsIncluded, AzureMentionedDomain, RisksReturnedCount,
              RecommendationsReturnedCount, TrendsReturnedCount, InputSizeBytes, OutputSizeBytes,
              InputTokens, OutputTokens, RetryCount, Status, AzureInputSummaryJson,
              OmittedSummaryJson, CreatedAt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE
              StackCTRLDataCount = ?, SentToAzureCount = ?, OmittedCount = ?, MetricsIncludedCount = ?,
              EvidenceIncludedCount = ?, EvidenceOmittedCount = ?, HistoricalComparisonsIncluded = ?,
              AzureMentionedDomain = ?, RisksReturnedCount = ?, RecommendationsReturnedCount = ?,
              TrendsReturnedCount = ?, InputSizeBytes = ?, OutputSizeBytes = ?, InputTokens = ?,
              OutputTokens = ?, RetryCount = ?, Status = ?, AzureInputSummaryJson = ?, OmittedSummaryJson = ?`,
            [
                companyId, snapshot.ID, run.id, domain.key, packageResult.audit.stackCTRLDataCount,
                packageResult.audit.sentToAzureCount, packageResult.audit.omittedCount,
                packageResult.audit.metricsIncludedCount, packageResult.audit.evidenceIncludedCount,
                packageResult.audit.evidenceOmittedCount, packageResult.audit.historicalComparisonsIncluded,
                azureMentioned, risksCount, recommendationsCount,
                trendsCount, inputBytes, usage.responseBytes, usage.inputTokens, usage.outputTokens, usage.retries, status,
                auditInput, auditOmitted,
                // ON DUPLICATE KEY UPDATE values
                packageResult.audit.stackCTRLDataCount, packageResult.audit.sentToAzureCount,
                packageResult.audit.omittedCount, packageResult.audit.metricsIncludedCount,
                packageResult.audit.evidenceIncludedCount, packageResult.audit.evidenceOmittedCount,
                packageResult.audit.historicalComparisonsIncluded, azureMentioned, risksCount,
                recommendationsCount, trendsCount, inputBytes, usage.responseBytes, usage.inputTokens,
                usage.outputTokens, usage.retries, status, auditInput, auditOmitted
            ]
        );
    }

    async function analyseDomain({ companyId, snapshot, run, domain, historicalContext, thresholdReached = false, strictCompactSelectedDomain = false }) {
        if (domain.key === 'security_alerts') {
            logger.info?.('[security_alerts:start] Security Alerts enterprise domain processing starting');
            logger.info?.('[security_alerts:evidence_prepare:start] Preparing stored Security Alerts evidence for Azure');
            await updateRunStageProgress(run.id, { stage: 'evidence_prepare:start', lastSuccessfulStage: 'snapshot_collection:complete' });
        }
        const packageResult = await buildDomainPackage({ companyId, snapshot, runId: run.id, domain, historicalContext, strictCompactSelectedDomain });
        if (domain.key === 'security_alerts') {
            logger.info?.(`[security_alerts:evidence_prepare:complete] Prepared ${packageResult.audit.preparedForAzureCount} stored evidence record(s)`);
            await updateRunStageProgress(run.id, { stage: 'evidence_prepare:complete', lastSuccessfulStage: 'evidence_prepare:complete' });
        }
        const missingFailure = DASHBOARD_BACKED_ENTERPRISE_DOMAINS.includes(domain.key)
            ? sourceMissingFailure(packageResult.package.sourceHealth, domain.name)
            : null;
        if (missingFailure) {
            const usage = { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 };
            packageResult.audit.sentToAzureCount = 0;
            const limitedAnalysis = buildLimitedDataAnalysis({ domain, packageResult, reason: missingFailure.errorMessage });
            await storeDomain({
                run, companyId, snapshot, domain, packageResult, analysis: limitedAnalysis, usage,
                status: 'completed_with_warnings', errorMessage: missingFailure.errorMessage
            });
            await storeAudit({
                run, companyId, snapshot, domain, packageResult, analysis: limitedAnalysis, usage,
                status: 'completed_with_warnings'
            });
            if (domain.key === 'security_alerts') {
                logger.warn?.(`[security_alerts:complete_or_completed_with_warnings_or_failed] completed_with_warnings: ${missingFailure.errorMessage}`);
                await updateRunStageProgress(run.id, {
                    stage: 'completed_with_warnings',
                    lastSuccessfulStage: 'evidence_prepare:complete',
                    warning: missingFailure.errorMessage
                });
            }
            return {
                status: 'completed_with_warnings',
                domain,
                usage,
                audit: packageResult.audit,
                analysis: limitedAnalysis,
                errorMessage: missingFailure.errorMessage,
                sourceHealth: packageResult.package.sourceHealth,
                limitedData: true
            };
        }
        const alignmentFailure = sourceAlignmentFailure(packageResult.sourceAlignment, domain.name);
        if (alignmentFailure) {
            const usage = { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 };
            packageResult.audit.sentToAzureCount = 0;
            await storeDomain({
                run, companyId, snapshot, domain, packageResult, analysis: null, usage,
                status: alignmentFailure.status, errorMessage: alignmentFailure.errorMessage
            });
            await storeAudit({
                run, companyId, snapshot, domain, packageResult, analysis: null, usage,
                status: alignmentFailure.status
            });
            if (domain.key === 'security_alerts') {
                await updateRunStageProgress(run.id, { stage: 'failed_terminal', lastSuccessfulStage: 'evidence_prepare:complete', failureReason: alignmentFailure.errorMessage });
            }
            return {
                status: alignmentFailure.status, domain, usage, audit: packageResult.audit,
                errorMessage: alignmentFailure.errorMessage, sourceAlignment: packageResult.sourceAlignment
            };
        }

        const staleFailure = sourceStaleFailure(packageResult.package.sourceHealth, domain.name);
        if (staleFailure) {
            const staleMessage = domain.key === 'devices'
                ? `Device Protection source is stale. Latest stored evidence was used from ${staleFailure.lastUpdated || 'unknown refresh time'}.`
                : staleFailure.errorMessage;
            packageResult.package.sourceHealth = {
                ...packageResult.package.sourceHealth,
                source_stale: true,
                ageMinutes: staleFailure.ageMinutes,
                lastRefreshTime: staleFailure.lastUpdated,
                warnings: [...new Set([...array(packageResult.package.sourceHealth?.warnings), staleMessage])]
            };
            packageResult.package.limitations.missingDataWarnings = [
                ...new Set([...array(packageResult.package.limitations?.missingDataWarnings), staleMessage])
            ];
            logger.warn?.(`[StackCTRL Enterprise] ${staleMessage}`);
        }

        if (domain.key === 'security_alerts' && !packageResult.package?.securityAlertsCompactPackage) {
            const expectedSourceRecords = Number(packageResult.current.source?.sourceLineage?.evidenceRecordCount ?? packageResult.audit.preparedForAzureCount);
            const preparedRecords = Number(packageResult.audit.preparedForAzureCount || 0);
            if (expectedSourceRecords !== preparedRecords) {
                const errorMessage = `Security Alerts evidence validation failed: ${expectedSourceRecords} stored source record(s) were expected but ${preparedRecords} record(s) were prepared for Azure.`;
                packageResult.audit.evidenceOmittedCount = Math.max(0, expectedSourceRecords - preparedRecords);
                packageResult.package.limitations.missingDataWarnings.push(errorMessage);
                logger.warn?.(`[security_alerts:evidence_prepare:warning] ${errorMessage} Continuing with all prepared evidence and preserving the discrepancy in limitations.`);
                await updateRunStageProgress(run.id, {
                    stage: 'evidence_prepare:warning',
                    lastSuccessfulStage: 'evidence_prepare:complete',
                    warning: errorMessage
                });
            }
        }

        const preparedRecordCount = array(packageResult.allEvidence).length;
        const stackctrlRecordCount = Number(packageResult.audit.stackCTRLDataCount || 0);
        if (stackctrlRecordCount > 0 && preparedRecordCount === 0) {
            const omittedReasons = array(packageResult.package.limitations?.missingDataWarnings);
            const errorMessage = `evidence_prepare_failed: ${stackctrlRecordCount} StackCTRL source record(s) exist but 0 were prepared for Azure.${omittedReasons.length ? ` Omitted reasons: ${omittedReasons.join('; ')}` : ' No omission reason was recorded.'}`;
            const usage = { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 };
            packageResult.audit.sentToAzureCount = 0;
            await storeDomain({
                run, companyId, snapshot, domain, packageResult, analysis: null, usage,
                status: 'failed_terminal', errorMessage
            });
            await storeAudit({
                run, companyId, snapshot, domain, packageResult, analysis: null, usage,
                status: 'failed_terminal',
                failureReason: 'evidence_prepare_failed',
                warningReasons: omittedReasons
            });
            if (domain.key === 'security_alerts') {
                await updateRunStageProgress(run.id, {
                    stage: 'failed_terminal',
                    lastSuccessfulStage: 'evidence_prepare:complete',
                    failureReason: errorMessage
                });
            }
            return {
                status: 'failed_terminal',
                domain,
                usage,
                audit: packageResult.audit,
                errorMessage,
                failureReason: 'evidence_prepare_failed'
            };
        }

        if (!array(packageResult.allEvidence).length) {
            const usage = { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 };
            const warning = `${domain.name} has no entity-level evidence rows in this snapshot. Enterprise Deep Reporting continued with warning-only output for this domain.`;
            packageResult.audit.sentToAzureCount = 0;
            packageResult.package.limitations.missingDataWarnings.push(warning);
            const limitedAnalysis = buildLimitedDataAnalysis({ domain, packageResult, reason: warning });
            await storeDomain({
                run, companyId, snapshot, domain, packageResult, analysis: limitedAnalysis, usage,
                status: 'completed_with_warnings', errorMessage: warning
            });
            await storeAudit({
                run, companyId, snapshot, domain, packageResult, analysis: limitedAnalysis, usage,
                status: 'completed_with_warnings'
            });
            if (domain.key === 'security_alerts') {
                logger.warn?.(`[security_alerts:complete_or_completed_with_warnings_or_failed] completed_with_warnings: ${warning}`);
                await updateRunStageProgress(run.id, {
                    stage: 'completed_with_warnings',
                    lastSuccessfulStage: 'evidence_prepare:complete',
                    warning
                });
            }
            return {
                status: 'completed_with_warnings',
                domain,
                usage,
                audit: packageResult.audit,
                analysis: limitedAnalysis,
                errorMessage: warning,
                limitedData: true
            };
        }
        
        try {
            // Process domain in batches instead of reducing evidence
            const batchResults = await processDomainBatches({
                companyId, snapshot, run, domain,
                packageResult,
                allEvidence: packageResult.allEvidence,
                historicalContext,
                thresholdReached
            });
            
            // Check if all batches completed successfully
            const failedBatches = batchResults.results.filter(r => !isSuccessfulDomainStatus(r.status));
            const completedBatches = batchResults.results.filter(r => isSuccessfulDomainStatus(r.status));
            
            if (completedBatches.length === 0) {
                const failedStatus = domainFailureStatus(failedBatches);
                const failedMessage = failedBatches.map(batch => batch.errorMessage).filter(Boolean).join(' | ') || `All ${batchResults.batchCount} batches failed`;
                packageResult.audit.sentToAzureCount = 0;
                // All batches failed
                await storeDomain({
                    run, companyId, snapshot, domain, packageResult, analysis: null,
                    usage: batchResults.totals, status: failedStatus,
                    errorMessage: failedMessage
                });
                await storeAudit({
                    run, companyId, snapshot, domain, packageResult, analysis: null,
                    usage: batchResults.totals, status: failedStatus
                });
                return {
                    status: failedStatus,
                    domain,
                    usage: batchResults.totals,
                    audit: packageResult.audit,
                    errorMessage: failedMessage,
                    rateLimited: batchResults.rateLimited,
                    recommendedRetryAfterMs: batchResults.recommendedRetryAfterMs
                };
            }
            
            // Aggregate batch results into domain-level analysis
            const mergeByTitle = items => {
                const merged = new Map();
                const uniqueValues = values => {
                    const seen = new Set();
                    return array(values).filter(value => {
                        const key = typeof value === 'string' ? value : JSON.stringify(value);
                        if (seen.has(key)) return false;
                        seen.add(key);
                        return true;
                    });
                };
                for (const item of array(items)) {
                    const key = `${item?.title || ''}|${item?.sourceMetric || ''}|${item?.severity || ''}`;
                    if (!merged.has(key)) {
                        merged.set(key, { ...item });
                        continue;
                    }
                    const current = merged.get(key);
                    merged.set(key, {
                        ...current,
                        ...item,
                        affectedEntities: uniqueValues([...array(current.affectedEntities), ...array(item.affectedEntities)]),
                        evidenceRows: uniqueValues([...array(current.evidenceRows), ...array(item.evidenceRows)]),
                        sourceAlertIds: uniqueValues([...array(current.sourceAlertIds), ...array(item.sourceAlertIds)]),
                        sourceMetrics: uniqueValues([...array(current.sourceMetrics), ...array(item.sourceMetrics)]),
                        recommendedActions: uniqueValues([...array(current.recommendedActions), ...array(item.recommendedActions)])
                    });
                }
                return [...merged.values()];
            };
            const controlAssessments = completedBatches.map(batch => batch.analysis?.controlAssessment).filter(Boolean);
            const mergedControlAssessment = controlAssessments.some(Array.isArray)
                ? mergeByTitle(controlAssessments.flatMap(value => array(value)))
                : controlAssessments.reduce((merged, value) => ({ ...merged, ...value }), {});
            const confidenceScores = completedBatches
                .map(batch => numberOrNull(batch.analysis?.confidenceScore))
                .filter(score => score != null);
            const recordsPrepared = Number(packageResult.audit.preparedForAzureCount || packageResult.audit.stackCTRLDataCount || 0);
            const recordsSent = Number(batchResults.processedItems || 0);
            const batchRecordsOmitted = Number(batchResults.omittedItems || 0);
            const sourceRecordsOmitted = Number(packageResult.audit.evidenceOmittedCount || 0);
            const batchAccountingComplete = recordsSent + batchRecordsOmitted === recordsPrepared;
            const batchFailureReasons = failedBatches.map(batch => batch.failureReason || batch.errorMessage).filter(Boolean);
            const invalidJsonFallbacks = completedBatches
                .map(batch => batch.analysis)
                .filter(analysis => analysis?.warningType === 'azure_invalid_json');
            const aggregatedRawAnalysis = {
                domainKey: domain.key,
                status: invalidJsonFallbacks.length ? 'completed_with_warnings' : null,
                warningType: invalidJsonFallbacks.length ? 'azure_invalid_json' : null,
                snapshotId: snapshot.ID,
                recordsPrepared,
                recordsSent,
                recordsOmitted: batchRecordsOmitted + sourceRecordsOmitted,
                omittedReasons: [...array(packageResult.package.limitations?.missingDataWarnings), ...batchFailureReasons],
                evidenceAvailable: recordsPrepared > 0,
                message: invalidJsonFallbacks.map(item => item.message).filter(Boolean).join(' | ') || null,
                rawAzureResponseStored: invalidJsonFallbacks.length > 0 && invalidJsonFallbacks.every(item => item.rawAzureResponseStored),
                domainExecutiveSummary: completedBatches
                    .map(b => b.analysis?.domainExecutiveSummary)
                    .filter(Boolean)
                    .join(' '),

                technicalReasoning: completedBatches.some(b => array(b.analysis?.technicalReasoning).length)
                    ? completedBatches.flatMap(b => array(b.analysis?.technicalReasoning))
                    : completedBatches
                        .map(b => b.analysis?.technicalReasoning || b.analysis?.technicalSummary)
                        .filter(Boolean)
                        .join(' '),

                riskPrioritization: completedBatches
                    .flatMap(b => array(b.analysis?.riskPrioritization || [])),

                technicalSummary: completedBatches
                    .map(b => b.analysis?.technicalSummary)
                    .filter(Boolean)
                    .join(' '),

                businessImpact: completedBatches
                    .map(b => b.analysis?.businessImpact)
                    .filter(Boolean)
                    .join(' '),

                currentPosture: completedBatches
                    .map(b => b.analysis?.currentPosture)
                    .filter(Boolean)
                    .join(' '),

                highestRiskPatterns: mergeByTitle(
                    completedBatches.flatMap(b => b.analysis?.highestRiskPatterns || [])
                ),

                managementDecisionsRequired: mergeByTitle(
                    completedBatches.flatMap(b => b.analysis?.managementDecisionsRequired || [])
                ),

                whatCanWait: mergeByTitle(
                    completedBatches.flatMap(b => b.analysis?.whatCanWait || [])
                ),
                evidenceUsed: completedBatches.flatMap(b => b.analysis?.evidenceUsed || []),
                evidenceGaps: completedBatches.flatMap(b => b.analysis?.evidenceGaps || []),
                scoreJustification: completedBatches.map(b => b.analysis?.scoreJustification).filter(Boolean).join(' '),
                controlAssessment: mergedControlAssessment,
                keyFindings: mergeByTitle(completedBatches.flatMap(b => b.analysis?.keyFindings || [])),
                risks: mergeByTitle(completedBatches.flatMap(b => b.analysis?.risks || [])),
                recommendations: mergeByTitle(completedBatches.flatMap(b => b.analysis?.recommendations || [])),
                trendAnalysis: mergeByTitle(completedBatches.flatMap(b => b.analysis?.trendAnalysis || [])),
                yesterdayVsToday: completedBatches[0]?.analysis?.yesterdayVsToday || {},
                whatImproved: completedBatches.flatMap(b => b.analysis?.whatImproved || []),
                whatDeteriorated: completedBatches.flatMap(b => b.analysis?.whatDeteriorated || []),
                whatStayedTheSame: completedBatches.flatMap(b => b.analysis?.whatStayedTheSame || []),
                missingDataWarnings: [
                    ...array(packageResult.package.limitations?.missingDataWarnings),
                    ...completedBatches.flatMap(b => b.analysis?.missingDataWarnings || []),
                    ...(batchResults.omittedItems > 0 ? [`${batchResults.omittedItems} evidence row(s) were not analysed because ${failedBatches.length} batch(es) failed.`] : []),
                    ...(batchResults.complete ? [] : ['Domain analysis is incomplete; do not treat this output as fully complete.'])
                ],
                assumptions: completedBatches.flatMap(b => b.analysis?.assumptions || []),
                confidenceScore: confidenceScores.length
                    ? Number((confidenceScores.reduce((total, score) => total + score, 0) / confidenceScores.length).toFixed(2))
                    : completedBatches[0]?.analysis?.confidenceScore ?? null,
                managementActions: mergeByTitle(completedBatches.flatMap(b => b.analysis?.managementActions || [])),
                powerBiSummary: completedBatches.reduce((merged, batch) => ({ ...merged, ...(batch.analysis?.powerBiSummary || {}) }), {}),
                evidenceCatalog: packageResult.evidenceCatalog,
                evidenceLimitations: {
                    recordsPrepared,
                    recordsSent,
                    recordsOmitted: batchRecordsOmitted + sourceRecordsOmitted,
                    totalEntityRows: packageResult.audit.stackCTRLDataCount,
                    catalogEntityCount: packageResult.audit.catalogEntityCount,
                    catalogCategoryCount: packageResult.audit.catalogCategoryCount,
                    completedBatches: completedBatches.length,
                    totalBatches: batchResults.batchCount,
                    accountingComplete: batchAccountingComplete,
                    complete: batchResults.complete && sourceRecordsOmitted === 0 && batchAccountingComplete,
                    omittedReasons: [...array(packageResult.package.limitations?.missingDataWarnings), ...batchFailureReasons]
                },
                authoritativeScores: { healthScore: packageResult.current.healthScore, riskScore: packageResult.current.riskScore, riskLevel: packageResult.current.riskLevel },
                domain: { key: domain.key, name: domain.name },
                batchInfo: {
                    completedBatches: completedBatches.length,
                    totalBatches: batchResults.batchCount,
                    failedBatches: failedBatches.length,
                    processedItems: batchResults.processedItems,
                    omittedItems: batchResults.omittedItems,
                    complete: batchResults.complete,
                    basePackageTokens: packageResult.audit.batchPlan?.basePackageTokens ?? null,
                    evidenceTokens: packageResult.audit.batchPlan?.evidenceTokens ?? null,
                    identityTableTokens: packageResult.audit.batchPlan?.identityTableTokens ?? packageResult.audit.batchPlan?.evidenceTokens ?? null,
                    deviceTableTokens: packageResult.audit.batchPlan?.deviceTableTokens ?? packageResult.audit.batchPlan?.evidenceTokens ?? null,
                    totalEstimatedTokens: packageResult.audit.batchPlan?.totalEstimatedTokens ?? null,
                    safeInputTokenLimit: packageResult.audit.batchPlan?.safeInputTokenLimit ?? null,
                    safeTokenLimit: packageResult.audit.batchPlan?.safeTokenLimit ?? packageResult.audit.batchPlan?.safeInputTokenLimit ?? null,
                    plannedBatchCount: packageResult.audit.batchPlan?.plannedBatchCount ?? batchResults.batchCount,
                    reasonForBatchCount: packageResult.audit.batchPlan?.reasonForBatchCount || null
                }
            };
            const aggregatedAnalysis = normalizedDomainResult(
                aggregatedRawAnalysis,
                domain,
                packageResult.current,
                snapshot.ID,
                packageResult.allEvidence
            );
            aggregatedAnalysis.dataLineageComparison = buildDataLineageComparison({
                fields: packageResult.sourceAlignment.rows.map(row => row.metric),
                sourceValues: Object.fromEntries(packageResult.sourceAlignment.rows.map(row => [row.metric, row.stackCTRLSource])),
                inputValues: Object.fromEntries(packageResult.sourceAlignment.rows.map(row => [row.metric, row.enterpriseAzureInput])),
                azureOutput: aggregatedAnalysis,
                storedIntelligence: aggregatedAnalysis
            }).rows;
            
            const recoveredBatches = completedBatches.filter(batch => batch.status === 'completed_with_warnings');
            const securityAccountingFailure = domain.key === 'security_alerts' && !batchAccountingComplete;
            const finalStatus = failedBatches.length > 0 && completedBatches.length === 0
                ? (failedBatches.every(batch => isConnectionFailureResult(batch)) ? 'failed_terminal' : 'partial')
                : securityAccountingFailure
                    ? 'completed_with_warnings'
                    : failedBatches.length > 0
                        ? 'partial'
                        : recoveredBatches.length > 0 ? 'completed_with_warnings' : 'completed';
            const successfullyAnalysedCount = completedBatches.reduce((total, batch) => total + Number(batch.batchItemCount || 0), 0);
            packageResult.audit.sentToAzureCount = successfullyAnalysedCount;
            packageResult.audit.evidenceOmittedCount = sourceRecordsOmitted + batchRecordsOmitted;
            const partialErrorMessage = securityAccountingFailure
                ? `Security Alerts batch accounting failed: ${recordsPrepared} prepared, ${recordsSent} sent, ${batchRecordsOmitted} omitted.`
                : failedBatches.length
                ? `${failedBatches.length} of ${batchResults.batchCount} batch(es) failed. ${failedBatches.map(batch => batch.errorMessage).filter(Boolean).join(' | ')}`.slice(0, 5000)
                : invalidJsonFallbacks.length
                    ? invalidJsonFallbacks.map(item => item.message).filter(Boolean).join(' | ').slice(0, 5000)
                    : null;
            const domainIntelligenceId = await storeDomain({
                run, companyId, snapshot, domain, packageResult,
                analysis: aggregatedAnalysis, usage: batchResults.totals,
                status: finalStatus,
                errorMessage: partialErrorMessage
            });
            
            // Store aggregate audit info showing all data was processed in batches
            const updatedAudit = {
                ...packageResult.audit,
                batchCount: batchResults.batchCount,
                completedBatches: completedBatches.length
            };
            await storeAudit({
                run, companyId, snapshot, domain, packageResult,
                analysis: aggregatedAnalysis, usage: batchResults.totals,
                status: finalStatus,
                batchResults,
                failureReason: partialErrorMessage,
                warningReasons: array(aggregatedAnalysis.missingDataWarnings),
                azureAttemptDiagnostics: failedBatches.flatMap(batch => batch.attemptDiagnostics || [])
            });
            if (domain.key === 'security_alerts') {
                logger.info?.(`[security_alerts:storage:complete] Stored Security Alerts domain intelligence ${domainIntelligenceId}`);
                logger.info?.(`[security_alerts:complete_or_completed_with_warnings_or_failed] ${finalStatus}`, {
                    recordsPrepared, recordsSent, recordsOmitted: batchRecordsOmitted + sourceRecordsOmitted,
                    batchCount: batchResults.batchCount, warnings: aggregatedAnalysis.missingDataWarnings
                });
                await updateRunStageProgress(run.id, {
                    stage: finalStatus,
                    lastSuccessfulStage: 'storage:complete',
                    warning: finalStatus === 'completed_with_warnings' || finalStatus === 'partial'
                        ? aggregatedAnalysis.missingDataWarnings.join(' | ').slice(0, 2000) : null,
                    failureReason: finalStatus.startsWith('failed') ? partialErrorMessage : null
                });
            }
            
            const response = {
                status: finalStatus,
                domain,
                domainIntelligenceId,
                analysis: aggregatedAnalysis,
                usage: batchResults.totals,
                audit: updatedAudit,
                batchInfo: {
                    completedBatches: completedBatches.length,
                    totalBatches: batchResults.batchCount,
                    failedBatches: failedBatches.length,
                    basePackageTokens: packageResult.audit.batchPlan?.basePackageTokens ?? null,
                    evidenceTokens: packageResult.audit.batchPlan?.evidenceTokens ?? null,
                    identityTableTokens: packageResult.audit.batchPlan?.identityTableTokens ?? packageResult.audit.batchPlan?.evidenceTokens ?? null,
                    deviceTableTokens: packageResult.audit.batchPlan?.deviceTableTokens ?? packageResult.audit.batchPlan?.evidenceTokens ?? null,
                    totalEstimatedTokens: packageResult.audit.batchPlan?.totalEstimatedTokens ?? null,
                    safeInputTokenLimit: packageResult.audit.batchPlan?.safeInputTokenLimit ?? null,
                    safeTokenLimit: packageResult.audit.batchPlan?.safeTokenLimit ?? packageResult.audit.batchPlan?.safeInputTokenLimit ?? null,
                    plannedBatchCount: packageResult.audit.batchPlan?.plannedBatchCount ?? batchResults.batchCount,
                    reasonForBatchCount: packageResult.audit.batchPlan?.reasonForBatchCount || null
                },
                errorMessage: partialErrorMessage,
                rateLimited: batchResults.rateLimited,
                recommendedRetryAfterMs: batchResults.recommendedRetryAfterMs
            };
            return response;
        } catch (error) {
            logger.error(`[StackCTRL Enterprise] ${domain.name} analysis failed:`, error.message);
            const failureStatus = error.enterpriseStatus || classifyFailureStatus(error);
            packageResult.audit.sentToAzureCount = 0;
            await storeDomain({
                run, companyId, snapshot, domain, packageResult,
                analysis: null, usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 },
                status: failureStatus, errorMessage: error.message
            });
            await storeAudit({
                run, companyId, snapshot, domain, packageResult,
                analysis: null, usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 },
                status: failureStatus
            });
            if (domain.key === 'security_alerts') {
                logger.error?.(`[security_alerts:complete_or_completed_with_warnings_or_failed] failed_terminal: ${error.message}`);
                await updateRunStageProgress(run.id, { stage: 'failed_terminal', lastSuccessfulStage: 'evidence_prepare:complete', failureReason: error.message }).catch(() => {});
            }
            return { status: failureStatus, domain, usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 }, audit: packageResult.audit, errorMessage: error.message };
        }
    }

    async function loadDomainRows(runId, { successfulOnly = false } = {}) {
        const [rows] = await pool.query(
            `SELECT ID, CompanyID, SnapshotID, RunID, DomainKey, DomainName, HealthScore, RiskScore,
                    RiskLevel, Status, DomainExecutiveSummary, TechnicalSummary, BusinessImpact,
                    CurrentPosture, EvidenceSummary, ScoreJustification, ControlAssessment,
                    FindingsJson, RisksJson, RecommendationsJson, TrendAnalysisJson,
                    YesterdayVsTodayJson, MissingDataWarningsJson, AssumptionsJson, ConfidenceScore,
                    ErrorMessage
             FROM StackCTRLTenantDomainIntelligence WHERE RunID = ? ORDER BY ID`,
            [runId]
        );
        const mapped = rows.map(row => ({
            domainKey: row.DomainKey, domainName: row.DomainName, healthScore: row.HealthScore,
            riskScore: row.RiskScore, riskLevel: row.RiskLevel, status: row.Status,
            domainExecutiveSummary: row.DomainExecutiveSummary, technicalSummary: row.TechnicalSummary,
            businessImpact: row.BusinessImpact, currentPosture: row.CurrentPosture,
            evidenceSummary: row.EvidenceSummary, scoreJustification: row.ScoreJustification,
            controlAssessment: safeValue(parseJson(row.ControlAssessment, {}), 0, { maxArray: 20, maxString: 2000 }),
            findings: array(parseJson(row.FindingsJson, [])).slice(0, 20),
            risks: array(parseJson(row.RisksJson, [])).slice(0, 20),
            recommendations: array(parseJson(row.RecommendationsJson, [])).slice(0, 20),
            trends: array(parseJson(row.TrendAnalysisJson, [])).slice(0, 20),
            yesterdayVsToday: safeValue(parseJson(row.YesterdayVsTodayJson, {}), 0, { maxArray: 20 }),
            missingDataWarnings: array(parseJson(row.MissingDataWarningsJson, [])).slice(0, 30),
            assumptions: array(parseJson(row.AssumptionsJson, [])).slice(0, 30),
            confidenceScore: row.ConfidenceScore,
            errorMessage: row.ErrorMessage || null
        }));
        return successfulOnly ? mapped.filter(row => isSuccessfulDomainStatus(row.status)) : mapped;
    }

    async function loadRollups(companyId, periodType, periodStart, periodEnd) {
        const lowerPeriod = LOWER_PERIOD[periodType];
        if (!lowerPeriod) return [];
        const lowerPeriods = periodType === 'monthly' ? ['weekly', 'daily'] : [lowerPeriod];
        const periodPlaceholders = lowerPeriods.map(() => '?').join(', ');
        const [rows] = await pool.query(
            `SELECT synthesis.ID, synthesis.PeriodType, synthesis.PeriodStart, synthesis.PeriodEnd,
                    synthesis.ExecutiveSummaryJson, synthesis.BoardReportJson, synthesis.ManagementReportJson,
                    synthesis.DomainScorecardJson, synthesis.MaturityAssessmentJson,
                    synthesis.EvidenceJustificationJson, synthesis.LimitationsJson, synthesis.PowerBISummaryJson
             FROM StackCTRLEnterpriseSynthesis synthesis
             WHERE synthesis.CompanyID = ? AND synthesis.Status = 'completed'
               AND synthesis.PeriodType IN (${periodPlaceholders})
               AND synthesis.PeriodStart <= ? AND synthesis.PeriodEnd >= ?
             ORDER BY synthesis.PeriodStart ASC LIMIT 400`,
            [companyId, ...lowerPeriods, periodEnd, periodStart]
        );
        return rows.map(row => ({
            synthesisId: row.ID, periodType: row.PeriodType, periodStart: row.PeriodStart, periodEnd: row.PeriodEnd,
            executiveSummary: parseJson(row.ExecutiveSummaryJson, {}), boardReport: parseJson(row.BoardReportJson, {}),
            managementReport: parseJson(row.ManagementReportJson, {}), domainScorecard: parseJson(row.DomainScorecardJson, []),
            maturityAssessment: parseJson(row.MaturityAssessmentJson, {}), evidenceJustification: parseJson(row.EvidenceJustificationJson, {}),
            limitations: parseJson(row.LimitationsJson, []), powerBiSummary: parseJson(row.PowerBISummaryJson, {})
        }));
    }

    async function runSynthesis({ companyId, snapshotId, run, existingTotals = null, queuedDomainKeys = null }) {
        const allDomainRows = await loadDomainRows(run.id);
        const domainRows = await loadDomainRows(run.id, { successfulOnly: true });
        const rollups = await loadRollups(companyId, run.periodType, run.periodStart, run.periodEnd);
        if (!domainRows.length && !rollups.length) throw new Error('Enterprise synthesis requires stored domain intelligence or completed lower-period reports');
        const domainRunSummary = buildDomainRunSummary(allDomainRows, queuedDomainKeys || allDomainRows.map(row => row.domainKey));
        const activeDomainKeys = ACTIVE_ENTERPRISE_DOMAIN_KEYS.filter(key => allDomainRows.some(row => row.domainKey === key));
        const synthesizedDomainKeys = domainRows.map(row => row.domainKey).filter(key => ACTIVE_ENTERPRISE_DOMAIN_SET.has(key));
        const disabledDomains = disabledDomainStates();
        const visibleDomainIntelligence = domainRows.map(row => stripInternalPowerBIFields(safeValue({
            domainKey: row.domainKey,
            domainName: row.domainName,
            status: row.status,
            healthScore: row.healthScore,
            riskScore: row.riskScore,
            riskLevel: row.riskLevel,
            confidenceScore: row.confidenceScore,
            domainExecutiveSummary: row.domainExecutiveSummary,
            technicalSummary: row.technicalSummary,
            businessImpact: row.businessImpact,
            currentPosture: row.currentPosture,
            evidenceSummary: row.evidenceSummary,
            scoreJustification: row.scoreJustification,
            controlAssessment: row.controlAssessment,
            findings: row.findings,
            risks: row.risks,
            recommendations: row.recommendations,
            trends: row.trends,
            yesterdayVsToday: row.yesterdayVsToday,
            missingDataWarnings: row.missingDataWarnings,
            assumptions: row.assumptions,
            errorMessage: row.errorMessage
        }, 0, { maxDepth: 6, maxArray: 20, maxString: 1800, maxObjectKeys: 80 })));
        const allWarnings = [...new Set(domainRows
            .flatMap(row => array(row.missingDataWarnings))
            .map(warning => visibleTextOrNull(warning, 300))
            .filter(Boolean))];
        const synthesisPackage = {
            contextType: 'stackctrl_enterprise_synthesis',
            schemaVersion: 2,
            companyId,
            snapshotId: snapshotId || null,
            period: {
                periodType: run.periodType,
                periodStart: run.periodStart,
                periodEnd: run.periodEnd,
                runId: run.id
            },
            reportingPhase: {
                ...CURRENT_REPORTING_PHASE,
                activeDomainKeys,
                synthesizedDomainKeys,
                disabledDomains,
                disabledDomainNote: 'Operations is disabled and must only appear as a limitation, not as an analysed risk source.'
            },
            synthesisObjective: {
                useStoredSuccessfulDomainIntelligenceOnly: true,
                doNotUseRawVendorPayloads: true,
                doNotRecalculateStackCTRLScores: true,
                connectDomainsIntoEnterpriseRiskThemes: true,
                includeBoardDecisions: true,
                includeBusinessImpact: true,
                includeAuditReadiness: true,
                includeManagementActions: true,
                producePowerBIReadyFinalReportData: true,
                avoidRepeatingDomainOutputs: true
            },
            domainIntelligence: visibleDomainIntelligence,
            historicalContext: {
                lowerPeriodReports: rollups
            },
            lowerPeriodReports: rollups,
            sourceHealthSummary: domainRows.map(row => ({
                domainKey: row.domainKey,
                domainName: row.domainName,
                status: row.status,
                healthScore: row.healthScore,
                riskScore: row.riskScore,
                riskLevel: row.riskLevel,
                confidenceScore: row.confidenceScore,
                warningCount: array(row.missingDataWarnings).length
            })),
            warnings: allWarnings,
            disabledDomainStates: disabledDomains,
            domainRunSummary: { ...domainRunSummary, disabledDomains },
            missingDataWarnings: allWarnings,
            limitations: {
                rawSnapshotIncluded: false,
                rawVendorPayloadIncluded: false,
                synthesisUsesStoredIntelligenceOnly: true,
                disabledDomains,
                currentPhaseLimitation: disabledDomains.length
                    ? 'Operations is temporarily disabled in this reporting phase. Governance and Compliance Validation are active and must be included in the final synthesis when their stored domain intelligence exists.'
                    : null,
                excludedDomainStatuses: allDomainRows
                    .filter(row => !isSuccessfulDomainStatus(row.status))
                    .map(row => ({ domainKey: row.domainKey, status: row.status, errorMessage: row.errorMessage || null }))
            }
        };
        const response = await azureOpenAI.createJsonCompletion({
            messages: [
                { role: 'system', content: DOMAIN_SYSTEM_MESSAGE },
                { role: 'user', content: synthesisPrompt(safeValue(synthesisPackage, 0, { maxDepth: 8, maxArray: 100, maxString: 5000 })) }
            ],
            temperature: 0.15,
            maxTokens: settings.maxSynthesisOutputTokens,
            maxRetriesOverride: settings.maxRetries,
            retryDelaysMsOverride: ENTERPRISE_RATE_LIMIT_RETRY_DELAYS_MS,
                retryMaxMsOverride: ENTERPRISE_RATE_LIMIT_RETRY_MAX_MS,
                connectionRetryDelaysMsOverride: ENTERPRISE_CONNECTION_RETRY_DELAYS_MS,
                timeoutMs: settings.requestTimeoutMs,
            allowInvalidJsonResponse: true
        });
        const usage = responseUsage(response);
        const finishReason = responseFinishReason(response);
        let analysis = response.data || {};
        let synthesisJsonRecovered = false;
        let synthesisJsonRecoveryMethod = null;
        if (typeof response.data === 'string') {
            const parsed = parseJsonWithDiagnostics(response.data);
            if (!parsed.success) {
                const localRepair = repairTruncatedJson(response.data);
                logger.warn(`[StackCTRL Enterprise] Synthesis JSON parsing failed, attempting one Azure repair. Error: ${parsed.error}`);
                let repairResponse = null;
                try {
                    repairResponse = await azureOpenAI.createJsonCompletion({
                    messages: [
                        { role: 'system', content: 'You are a JSON repair tool. Return valid JSON only. Preserve complete evidence fields and arrays. No markdown. No code fences. No explanations outside JSON.' },
                        { role: 'user', content: createJsonRepairPrompt(response.data.slice(0, 60000)) }
                    ],
                    temperature: 0,
                    maxTokens: settings.maxSynthesisOutputTokens,
                    maxRetriesOverride: 1,
                    retryDelaysMsOverride: ENTERPRISE_RATE_LIMIT_RETRY_DELAYS_MS,
                retryMaxMsOverride: ENTERPRISE_RATE_LIMIT_RETRY_MAX_MS,
                connectionRetryDelaysMsOverride: ENTERPRISE_CONNECTION_RETRY_DELAYS_MS,
                timeoutMs: settings.requestTimeoutMs,
                    allowInvalidJsonResponse: true
                    });
                } catch (repairError) {
                    if (!localRepair.success) throw repairError;
                    analysis = localRepair.value;
                    synthesisJsonRecovered = true;
                    synthesisJsonRecoveryMethod = 'local_closure_after_repair_error';
                }
                if (repairResponse) {
                    const repairUsage = responseUsage(repairResponse);
                    usage.inputTokens += repairUsage.inputTokens;
                    usage.outputTokens += repairUsage.outputTokens;
                    usage.totalTokens += repairUsage.totalTokens;
                    usage.requestBytes += repairUsage.requestBytes;
                    usage.responseBytes += repairUsage.responseBytes;
                    usage.retries += repairUsage.retries;
                    const repaired = parseJsonWithDiagnostics(repairResponse.data);
                    const locallyRepairedResponse = repaired.success ? null : repairTruncatedJson(repairResponse.data);
                    const recovered = repaired.success
                        ? repaired.value
                        : locallyRepairedResponse?.success ? locallyRepairedResponse.value
                            : localRepair.success ? localRepair.value : null;
                    if (!recovered) {
                        const error = new Error(`Enterprise synthesis JSON parse failed: ${parsed.error}. Repair attempt also failed: ${repaired.error}`);
                        error.enterpriseStatus = 'failed_invalid_json';
                        throw error;
                    }
                    analysis = recovered;
                    synthesisJsonRecovered = true;
                    synthesisJsonRecoveryMethod = repaired.success
                        ? 'azure_repair'
                        : locallyRepairedResponse?.success ? 'azure_repair_then_local_closure' : 'local_closure_after_azure_repair_failure';
                }
            } else {
                analysis = parsed.value;
            }
        }
        const locallyRecoveredSynthesisJson = synthesisJsonRecovered && /local_closure|local_fallback/i.test(String(synthesisJsonRecoveryMethod || ''));
        const lengthLimitedSynthesisStringResponse = finishReason === 'length' && typeof response.data === 'string';
        if (locallyRecoveredSynthesisJson || lengthLimitedSynthesisStringResponse) {
            analysis.limitationsAndAssumptions = [
                ...array(analysis.limitationsAndAssumptions),
                'Azure response was safely recovered. Some optional narrative fields may be incomplete.'
            ];
        }
        analysis = normalizeSynthesisOutputForDisplay(analysis, snapshotId);
        const finalRunStatus = locallyRecoveredSynthesisJson || lengthLimitedSynthesisStringResponse || allDomainRows.some(row => row.status !== 'completed')
            ? 'completed_with_warnings'
            : 'completed';
        const [result] = await pool.query(
            `INSERT INTO StackCTRLEnterpriseSynthesis
             (CompanyID, SnapshotID, RunID, PeriodType, PeriodStart, PeriodEnd, Status,
              ExecutiveSummaryJson, BoardReportJson, ManagementReportJson, RiskRegisterJson,
              RecommendationsJson, TrendAnalysisJson, ComplianceReviewJson, GovernanceReviewJson,
              DomainScorecardJson, MaturityAssessmentJson, BusinessImpactSummary,
              TopDecisionsRequiredJson, Next30DaysPlanJson, Next90DaysPlanJson,
              EvidenceJustificationJson, LimitationsJson, PowerBISummaryJson, InputSizeBytes,
              ResponseSizeBytes, InputTokens, OutputTokens, TotalTokens, RetryCount, CreatedAt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE
              Status = VALUES(Status), ExecutiveSummaryJson = VALUES(ExecutiveSummaryJson),
              BoardReportJson = VALUES(BoardReportJson), ManagementReportJson = VALUES(ManagementReportJson),
              RiskRegisterJson = VALUES(RiskRegisterJson), RecommendationsJson = VALUES(RecommendationsJson),
              TrendAnalysisJson = VALUES(TrendAnalysisJson), ComplianceReviewJson = VALUES(ComplianceReviewJson),
              GovernanceReviewJson = VALUES(GovernanceReviewJson), DomainScorecardJson = VALUES(DomainScorecardJson),
              MaturityAssessmentJson = VALUES(MaturityAssessmentJson), BusinessImpactSummary = VALUES(BusinessImpactSummary),
              TopDecisionsRequiredJson = VALUES(TopDecisionsRequiredJson), Next30DaysPlanJson = VALUES(Next30DaysPlanJson),
              Next90DaysPlanJson = VALUES(Next90DaysPlanJson), EvidenceJustificationJson = VALUES(EvidenceJustificationJson),
              LimitationsJson = VALUES(LimitationsJson), PowerBISummaryJson = VALUES(PowerBISummaryJson),
              InputSizeBytes = VALUES(InputSizeBytes), ResponseSizeBytes = VALUES(ResponseSizeBytes),
              InputTokens = VALUES(InputTokens), OutputTokens = VALUES(OutputTokens), TotalTokens = VALUES(TotalTokens),
              RetryCount = VALUES(RetryCount)`,
            [
                companyId, snapshotId || null, run.id, run.periodType, run.periodStart, run.periodEnd, finalRunStatus,
                JSON.stringify(analysis.enterpriseExecutiveSummary || {}), JSON.stringify(analysis.boardReport || {}),
                JSON.stringify(analysis.managementReport || {}), jsonArray(analysis.riskRegister),
                jsonArray(analysis.recommendations), jsonArray(analysis.trendAnalysis),
                JSON.stringify(analysis.complianceReview || {}), JSON.stringify(analysis.governanceReview || {}),
                jsonArray(analysis.domainScorecard), JSON.stringify(analysis.maturityAssessment || {}),
                textOrNull(analysis.businessImpactSummary), jsonArray(analysis.topDecisionsRequired),
                jsonArray(analysis.next30DaysPlan), jsonArray(analysis.next90DaysPlan),
                JSON.stringify(analysis.evidenceJustificationSummary || {}), jsonArray(analysis.limitationsAndAssumptions),
                JSON.stringify(analysis.powerBiSummary || {}), usage.requestBytes || bytes(synthesisPackage), usage.responseBytes,
                usage.inputTokens, usage.outputTokens, usage.totalTokens, usage.retries
            ]
        );
        await storeItems({
            companyId, snapshotId, runId: run.id,
            domain: { key: 'enterprise', name: 'Overall Risks' }, period: run,
            analysis: {
                riskRegister: analysis.riskRegister,
                recommendations: analysis.recommendations,
                trendAnalysis: analysis.trendAnalysis,
                managementActions: [...array(analysis.managementReport?.managementActions), ...array(analysis.managementReport?.actions)],
                topDecisionsRequired: analysis.topDecisionsRequired,
                next30DaysPlan: analysis.next30DaysPlan,
                next90DaysPlan: analysis.next90DaysPlan
            },
            source: 'synthesis'
        });
        const totals = existingTotals || { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 };
        for (const key of Object.keys(totals)) totals[key] += usage[key] || 0;
        await pool.query(
            `UPDATE StackCTRLEnterpriseReportRuns
             SET Status = ?, CompletedAt = NOW(), TotalInputTokens = ?, TotalOutputTokens = ?,
                 TotalTokens = ?, TotalRequestBytes = ?, TotalResponseBytes = ?, RetryCount = ?
             WHERE ID = ?`,
            [finalRunStatus, totals.inputTokens, totals.outputTokens, totals.totalTokens, totals.requestBytes, totals.responseBytes, totals.retries, run.id]
        );
        return { synthesisId: result.insertId || run.id, status: finalRunStatus, analysis, usage };
    }

    async function processDomains({ companyId, snapshot, run, domainKeys, disabledDomainKeys = TEMPORARILY_DISABLED_DOMAIN_KEYS, isSingleDomainRun = false }) {
        const historicalContext = await schedulerService.getHistoricalSnapshotContext(companyId, snapshot.ID);
        const selected = domainKeys.map(key => DOMAIN_BY_KEY[key]).filter(Boolean);
        const results = [];
        const totals = { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 };
        let rateLimit = null;
        let terminalError = null;

        await updateRunProgress(run.id, buildRunProgress({
            run,
            domainKeys,
            disabledDomainKeys,
            results,
            phase: 'domains',
            snapshot
        }), totals);

        for (let index = 0; index < selected.length; index += 1) {
            const domain = selected[index];
            await updateRunProgress(run.id, buildRunProgress({
                run,
                domainKeys,
                disabledDomainKeys,
                results,
                currentDomainKey: domain.key,
                phase: 'domain',
                snapshot
            }), totals);

            const thresholdReached = totals.totalTokens >= settings.maxTotalTokens;
            if (thresholdReached) {
                logger.warn?.(`[StackCTRL Enterprise] Advisory token threshold reached before ${domain.name}; continuing with smaller safe evidence batches.`);
            }

            const result = await analyseDomain({ companyId, snapshot, run, domain, historicalContext, thresholdReached, strictCompactSelectedDomain: true });
            results.push(result);
            for (const key of Object.keys(totals)) totals[key] += result.usage?.[key] || 0;

            await updateRunProgress(run.id, buildRunProgress({
                run,
                domainKeys,
                disabledDomainKeys,
                results,
                currentDomainKey: null,
                phase: 'domain',
                rateLimit: result.rateLimited ? {
                    domainKey: result.domain.key,
                    retryAfterMs: result.recommendedRetryAfterMs || Math.max(0, rateLimitCircuitOpenUntil - Date.now())
                } : null,
                snapshot
            }), totals);

            if (result.rateLimited || result.status === 'failed_rate_limited') {
                rateLimit = {
                    domainKey: result.domain.key,
                    retryAfterMs: result.recommendedRetryAfterMs || Math.max(0, rateLimitCircuitOpenUntil - Date.now())
                };
                for (let pendingIndex = index + 1; pendingIndex < selected.length; pendingIndex += 1) {
                    results.push(await storeSkippedDomain({
                        run, companyId, snapshot, domain: selected[pendingIndex],
                        status: 'skipped_rate_limited',
                        errorMessage: `Azure rate limit reached while processing ${result.domain.name}. Retry this domain after cooldown.`
                    }));
                }
                break;
            }

            if (['failed', 'failed_storage'].includes(String(result.status || ''))) {
                terminalError = {
                    domainKey: result.domain.key,
                    status: result.status,
                    errorMessage: result.errorMessage || `${result.domain.name} failed and the enterprise pipeline was stopped.`
                };
                for (let pendingIndex = index + 1; pendingIndex < selected.length; pendingIndex += 1) {
                    results.push({
                        status: 'skipped_pipeline_stop',
                        domain: selected[pendingIndex],
                        usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 },
                        audit: null,
                        errorMessage: `Pipeline stopped after ${result.domain.name}: ${terminalError.errorMessage}`
                    });
                }
                break;
            }

            if (index < selected.length - 1) {
                const nextDomain = selected[index + 1];
                const delayMs = Math.max(
                    computeInterDomainDelayMs(result.usage?.inputTokens || 0, settings, domain.key),
                    computeInterDomainDelayMs(result.usage?.inputTokens || 0, settings, nextDomain?.key)
                );
                if (delayMs > 0) await wait(delayMs);
            }
        }

        await updateRunProgress(run.id, buildRunProgress({
            run,
            domainKeys,
            disabledDomainKeys,
            results,
            phase: rateLimit ? 'rate_limited' : terminalError ? 'failed' : 'domains_complete',
            rateLimit,
            snapshot
        }), totals);

        return { results, totals, rateLimited: Boolean(rateLimit), rateLimit, terminalError };
    }

    async function runEnterpriseReport({ companyId, snapshotId = null, periodType = 'daily', referenceDate = new Date(), domainKeys = null, includeSynthesis = null, deduplicationKey = null, refreshSnapshot = null, user = null, publishReport = false } = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isInteger(numericCompanyId) || numericCompanyId <= 0) throw new Error('A valid companyId is required');
        assertRateLimitCircuitClosed();
        const requestedKeys = Array.isArray(domainKeys) && domainKeys.length ? [...new Set(domainKeys)] : [...ACTIVE_ENTERPRISE_DOMAIN_KEYS];
        const invalid = requestedKeys.filter(key => !DOMAIN_BY_KEY[key]);
        if (invalid.length) throw new Error(`Unsupported enterprise domains: ${invalid.join(', ')}`);
        const disabledSelectedKeys = requestedKeys.filter(isTemporarilyDisabledDomain);
        const selectedKeys = requestedKeys.filter(key => ACTIVE_ENTERPRISE_DOMAIN_SET.has(key));
        const disabledDomains = disabledDomainStates(disabledSelectedKeys.length ? disabledSelectedKeys : TEMPORARILY_DISABLED_DOMAIN_KEYS);
        if (!selectedKeys.length) {
            return {
                status: 'temporarily_disabled',
                runId: null,
                snapshotId: snapshotId || null,
                snapshotRefresh: null,
                periodType,
                mode: 'enterprise_domain_temporarily_disabled',
                reportingPhase: CURRENT_REPORTING_PHASE,
                domains: disabledSelectedKeys.map(key => disabledDomainState(key)),
                disabledDomains,
                domainRunSummary: { ...buildDomainRunSummary([], []), disabledDomains },
                synthesisId: null,
                synthesisStatus: 'not_requested',
                totals: { inputTokens: 0, outputTokens: 0, totalTokens: 0, requestBytes: 0, responseBytes: 0, retries: 0 },
                rateLimited: false,
                rateLimit: null,
                terminalError: null,
                message: TEMPORARILY_DISABLED_DOMAIN_MESSAGE
            };
        }
        const isSingleDomainRun = selectedKeys.length === 1;
        const isEnterpriseDeepRun = selectedKeys.length > 1;
        const activeRun = await findActiveEnterpriseRun(numericCompanyId);
        if (activeRun) {
            logger.info('[StackCTRL Enterprise Pipeline]', {
                event: 'active_run_reused',
                companyId: numericCompanyId,
                runId: Number(activeRun.ID),
                snapshotId: activeRun.SnapshotID == null ? null : Number(activeRun.SnapshotID),
                status: activeRun.Status,
                timestamp: new Date().toISOString()
            });
            return {
                status: 'already_running',
                existingStatus: activeRun.Status,
                runId: Number(activeRun.ID),
                snapshotId: activeRun.SnapshotID == null ? null : Number(activeRun.SnapshotID),
                periodType: activeRun.PeriodType || periodType,
                mode: activeRun.Mode || null,
                message: 'Enterprise run #' + activeRun.ID + ' is already in progress.'
            };
        }
        const shouldRefreshSnapshot = refreshSnapshot === true || (refreshSnapshot !== false && isEnterpriseDeepRun);
        const shouldIncludeSynthesis = includeSynthesis === true || (includeSynthesis !== false && isEnterpriseDeepRun);
        const pipelineId = deduplicationKey || null;
        const scheduleKey = pipelineId ? String(pipelineId).split(':').at(-1) || null : null;
        const mode = isSingleDomainRun ? DOMAIN_BY_KEY[selectedKeys[0]].mode : 'enterprise_deep_reporting';
        const run = await createRun({
            companyId: numericCompanyId,
            snapshotId: null,
            periodType,
            referenceDate,
            mode,
            deduplicationKey
        });
        if (run.duplicate) {
            logger.info('[StackCTRL Enterprise Pipeline]', {
                event: 'duplicate_trigger_ignored',
                enterpriseId: numericCompanyId,
                pipelineExecutionId: pipelineId,
                analysisExecutionId: run.id,
                snapshotId: run.snapshotId,
                status: run.existingStatus,
                timestamp: new Date().toISOString()
            });
            return {
                status: 'duplicate',
                existingStatus: run.existingStatus,
                runId: run.id,
                snapshotId: run.snapshotId,
                periodType: run.periodType,
                pipelineExecutionId: pipelineId
            };
        }

        let resolvedSnapshotId = snapshotId;
        let snapshotRefresh = null;
        let snapshot = null;
        let failureStage = shouldRefreshSnapshot ? 'SNAPSHOT_CREATION_FAILED' : 'SNAPSHOT_VERIFICATION_FAILED';
        try {
            logger.info('[StackCTRL Enterprise Pipeline]', {
                event: 'pipeline_started',
                enterpriseId: numericCompanyId,
                pipelineExecutionId: pipelineId,
                analysisExecutionId: run.id,
                timestamp: new Date().toISOString()
            });
            if (shouldRefreshSnapshot) {
                await recordPipelinePhase(run.id, 'SNAPSHOT_CREATION_STARTED', {
                    enterpriseId: numericCompanyId,
                    analysisExecutionId: run.id,
                    pipelineExecutionId: pipelineId,
                    scheduleKey
                });
                logger.info('[StackCTRL Enterprise Pipeline]', {
                    event: 'snapshot_creation_started',
                    companyId: numericCompanyId,
                    enterpriseId: numericCompanyId,
                    runId: run.id,
                    pipelineExecutionId: pipelineId,
                    scheduleKey,
                    analysisExecutionId: run.id,
                    timestamp: new Date().toISOString()
                });
                snapshotRefresh = await refreshEnterpriseSnapshot(numericCompanyId, user, {
                    runId: run.id,
                    pipelineExecutionId: pipelineId,
                    scheduleKey
                });
                if (snapshotRefresh?.snapshotId) {
                    resolvedSnapshotId = snapshotRefresh.snapshotId;
                } else if (!resolvedSnapshotId) {
                    throw new Error('Enterprise snapshot creation did not return a persisted snapshot ID');
                } else {
                    failureStage = 'SNAPSHOT_VERIFICATION_FAILED';
                }
            }
            snapshot = await loadSnapshot(numericCompanyId, resolvedSnapshotId);
            if (!snapshot?.ID || Number(snapshot.CompanyID) !== numericCompanyId) {
                throw new Error('The persisted enterprise snapshot does not belong to the requested enterprise');
            }
            await bindSnapshotToRun(run, snapshot, snapshotRefresh?.snapshotId ? 'SNAPSHOT_CREATED' : 'SNAPSHOT_VERIFIED', {
                enterpriseId: numericCompanyId,
                snapshotId: Number(snapshot.ID),
                analysisExecutionId: run.id,
                pipelineExecutionId: pipelineId
            });
            logger.info('[StackCTRL Enterprise Pipeline]', {
                event: snapshotRefresh?.snapshotId ? 'snapshot_created' : 'snapshot_verified',
                companyId: numericCompanyId,
                enterpriseId: numericCompanyId,
                runId: run.id,
                pipelineExecutionId: pipelineId,
                scheduleKey,
                analysisExecutionId: run.id,
                snapshotId: Number(snapshot.ID),
                timestamp: new Date().toISOString()
            });

            failureStage = 'ENTERPRISE_DEEP_ANALYSIS_FAILED';
            await recordPipelinePhase(run.id, 'ANALYSIS_STARTED', {
                enterpriseId: numericCompanyId,
                snapshotId: Number(snapshot.ID),
                analysisExecutionId: run.id,
                pipelineExecutionId: pipelineId
            });
            logger.info('[StackCTRL Enterprise Pipeline]', {
                event: 'analysis_started',
                enterpriseId: numericCompanyId,
                pipelineExecutionId: pipelineId,
                analysisExecutionId: run.id,
                snapshotId: Number(snapshot.ID),
                timestamp: new Date().toISOString()
            });
            const domains = await processDomains({ companyId: numericCompanyId, snapshot, run, domainKeys: selectedKeys, disabledDomainKeys: disabledDomains.map(domain => domain.domainKey), isSingleDomainRun });
            const runStatusBeforeSynthesis = rollupRunStatus(domains.results);
            const successfulDomains = domains.results.filter(result => isSuccessfulDomainStatus(result.status));
            const allDomainsStored = domains.results.length === selectedKeys.length;
            let synthesis = null;
            const canSynthesize = shouldIncludeSynthesis
                && !domains.rateLimited
                && !domains.terminalError
                && allDomainsStored
                && successfulDomains.length > 0;
            if (canSynthesize) {
                await updateRunProgress(run.id, buildRunProgress({
                    run,
                    domainKeys: selectedKeys,
                    disabledDomainKeys: disabledDomains.map(domain => domain.domainKey),
                    results: domains.results,
                    phase: 'synthesis',
                    synthesisStatus: 'running',
                    snapshot
                }), domains.totals);
                synthesis = await runSynthesis({
                    companyId: numericCompanyId,
                    snapshotId: snapshot.ID,
                    run,
                    existingTotals: domains.totals,
                    queuedDomainKeys: selectedKeys
                });
                await updateRunProgress(run.id, buildRunProgress({
                    run,
                    domainKeys: selectedKeys,
                    disabledDomainKeys: disabledDomains.map(domain => domain.domainKey),
                    results: domains.results,
                    phase: 'complete',
                    synthesisStatus: synthesis.status,
                    snapshot
                }), domains.totals);
            } else {
                const incompleteCount = domains.results.filter(result => !isSuccessfulDomainStatus(result.status)).length;
                const errorMessage = domains.rateLimited
                    ? `Azure rate limit reached at ${domains.rateLimit?.domainKey || 'unknown domain'}. Completed domains were stored; synthesis was not run.`
                    : domains.terminalError
                        ? `Enterprise pipeline stopped at ${domains.terminalError.domainKey}: ${domains.terminalError.errorMessage}`
                    : runStatusBeforeSynthesis === 'completed'
                        ? null
                        : `${incompleteCount} domain analysis request(s) did not complete successfully.`;
                await pool.query(
                    `UPDATE StackCTRLEnterpriseReportRuns
                     SET Status = ?, CompletedAt = NOW(), TotalInputTokens = ?, TotalOutputTokens = ?, TotalTokens = ?,
                         TotalRequestBytes = ?, TotalResponseBytes = ?, RetryCount = ?, ErrorMessage = ? WHERE ID = ?`,
                    [runStatusBeforeSynthesis, domains.totals.inputTokens, domains.totals.outputTokens,
                        domains.totals.totalTokens, domains.totals.requestBytes, domains.totals.responseBytes, domains.totals.retries,
                        errorMessage, run.id]
                );
                await updateRunProgress(run.id, buildRunProgress({
                    run,
                    domainKeys: selectedKeys,
                    disabledDomainKeys: disabledDomains.map(domain => domain.domainKey),
                    results: domains.results,
                    phase: domains.rateLimited ? 'rate_limited' : domains.terminalError ? 'failed' : 'domains_complete',
                    synthesisStatus: shouldIncludeSynthesis ? 'skipped' : 'not_requested',
                    rateLimit: domains.rateLimit,
                    snapshot
                }), domains.totals);
            }
            const finalStatus = synthesis?.status || runStatusBeforeSynthesis;
            const pipelineSucceeded = ['completed', 'completed_with_warnings'].includes(String(finalStatus || '').toLowerCase());
            const pipelineFailure = pipelineSucceeded ? null : {
                phase: 'PIPELINE_FAILED',
                failureStage: 'ENTERPRISE_DEEP_ANALYSIS_FAILED',
                enterpriseId: numericCompanyId,
                snapshotId: Number(snapshot.ID),
                analysisExecutionId: run.id,
                pipelineExecutionId: pipelineId,
                timestamp: new Date().toISOString(),
                error: domains.terminalError?.errorMessage || `Enterprise Deep Analysis ended with status ${finalStatus}`
            };
            if (pipelineFailure && pipelineId) {
                await pool.query(
                    `UPDATE StackCTRLEnterpriseReportRuns SET ErrorMessage = ?, ProgressJson = ? WHERE ID = ?`,
                    [pipelineFailure.error.slice(0, 5000), JSON.stringify(pipelineFailure), run.id]
                );
                logger.error('[StackCTRL Enterprise Pipeline]', { event: 'pipeline_failed', ...pipelineFailure });
            }
            const domainRunSummary = buildDomainRunSummary(
                domains.results.map(result => ({
                    domainKey: result.domain.key,
                    status: result.status,
                    errorMessage: result.errorMessage || null
                })),
                selectedKeys
            );
            const response = {
                status: finalStatus,
                runId: run.id,
                snapshotId: snapshot.ID,
                snapshotRefresh,
                periodType: run.periodType,
                mode: run.mode,
                enterpriseDeepRun: isEnterpriseDeepRun,
                refreshSnapshotRequested: shouldRefreshSnapshot,
                includeSynthesisRequested: shouldIncludeSynthesis,
                requestedDomainKeys: requestedKeys,
                activeDomainKeys: selectedKeys,
                disabledDomains,
                powerBiUrlHints: {
                    latest: `/api/powerbi/intelligence/latest/${numericCompanyId}`,
                    final: `/api/powerbi/intelligence/final/${numericCompanyId}`,
                    tables: `/api/powerbi/tables/latest/${numericCompanyId}`,
                    latestForRun: `/api/powerbi/intelligence/latest/${numericCompanyId}?runId=${run.id}`,
                    finalForRun: `/api/powerbi/intelligence/final/${numericCompanyId}?runId=${run.id}`,
                    tablesForRun: `/api/powerbi/tables/latest/${numericCompanyId}?runId=${run.id}`
                },
                reportingPhase: CURRENT_REPORTING_PHASE,
                domains: domains.results.map(result => ({
                    domainKey: result.domain.key,
                    domainName: result.domain.name,
                    status: result.status,
                    domainIntelligenceId: result.domainIntelligenceId || null,
                    analysis: result.analysis || null,
                    errorMessage: result.errorMessage || null,
                    batchInfo: result.batchInfo || null
                })),
                domainRunSummary: { ...domainRunSummary, disabledDomains },
                synthesisId: synthesis?.synthesisId || null,
                synthesisStatus: synthesis?.status || (shouldIncludeSynthesis ? (domains.rateLimited ? 'skipped_rate_limited' : domains.terminalError ? 'skipped_pipeline_stop' : (successfulDomains.length ? 'skipped' : 'skipped_no_successful_domains')) : 'not_requested'),
                totals: domains.totals,
                rateLimited: domains.rateLimited,
                rateLimit: domains.rateLimit,
                terminalError: domains.terminalError,
                pipelineExecutionId: pipelineId,
                pipelineFailure
            };
            if (pipelineSucceeded) {
                await recordPipelinePhase(run.id, 'ANALYSIS_COMPLETED', {
                    enterpriseId: numericCompanyId,
                    snapshotId: Number(snapshot.ID),
                    analysisExecutionId: run.id,
                    pipelineExecutionId: pipelineId,
                    status: finalStatus
                });
                logger.info('[StackCTRL Enterprise Pipeline]', {
                    event: 'analysis_completed', enterpriseId: numericCompanyId,
                    pipelineExecutionId: pipelineId, analysisExecutionId: run.id,
                    snapshotId: Number(snapshot.ID), status: finalStatus, timestamp: new Date().toISOString()
                });
                if (publishReport && typeof completedRunPublisher === 'function') {
                    try {
                        logger.info('[StackCTRL Enterprise Pipeline]', {
                            event: 'analysis_result_persistence_started', enterpriseId: numericCompanyId,
                            analysisExecutionId: run.id, snapshotId: Number(snapshot.ID), pipelineExecutionId: pipelineId,
                            timestamp: new Date().toISOString()
                        });
                        response.reportAutomation = await completedRunPublisher({
                            companyId: numericCompanyId,
                            run: { ...response, status: finalStatus },
                            now: referenceDate,
                            pipelineExecutionId: pipelineId,
                            cadence: 'manual'
                        });
                        if (!response.reportAutomation?.reportId) throw new Error('Completed enterprise run did not publish an automated report.');
                    } catch (reportError) {
                        response.reportAutomation = { status: 'failed', reportId: null, error: String(reportError.message || reportError) };
                        logger.error('[StackCTRL Enterprise Pipeline]', {
                            event: 'analysis_result_persistence_failed', enterpriseId: numericCompanyId,
                            analysisExecutionId: run.id, snapshotId: Number(snapshot.ID), pipelineExecutionId: pipelineId,
                            error: response.reportAutomation.error, timestamp: new Date().toISOString()
                        });
                    }
                }
            }
            return response;
        } catch (error) {
            captureRateLimit(error);
            const failure = {
                phase: 'PIPELINE_FAILED',
                failureStage,
                enterpriseId: numericCompanyId,
                snapshotId: snapshot?.ID || resolvedSnapshotId || null,
                analysisExecutionId: run.id,
                pipelineExecutionId: pipelineId,
                timestamp: new Date().toISOString(),
                error: String(error.message || error).slice(0, 5000)
            };
            if (String(failureStage).startsWith('SNAPSHOT_')) {
                logger.error('[StackCTRL Enterprise Pipeline]', {
                    event: 'snapshot_creation_failed',
                    companyId: numericCompanyId,
                    runId: run.id,
                    analysisExecutionId: run.id,
                    pipelineExecutionId: pipelineId,
                    scheduleKey,
                    failureStage,
                    error: failure.error,
                    timestamp: failure.timestamp
                });
            }
            await pool.query(
                `UPDATE StackCTRLEnterpriseReportRuns
                 SET Status = ?, CompletedAt = NOW(), ErrorMessage = ?, ProgressJson = ?
                 WHERE ID = ?`,
                [error.enterpriseStatus || classifyFailureStatus(error), failure.error, JSON.stringify(failure), run.id]
            );
            logger.error('[StackCTRL Enterprise Pipeline]', { event: 'pipeline_failed', ...failure });
            error.enterprisePipelineFailure = failure;
            throw error;
        }
    }

    async function publishCompletedRun({ companyId, runId, now = new Date(), pipelineExecutionId = null } = {}) {
        if (typeof completedRunPublisher !== 'function') throw new Error('Completed enterprise report publication is not configured.');
        const numericCompanyId = Number(companyId);
        const numericRunId = Number(runId);
        if (!Number.isInteger(numericCompanyId) || numericCompanyId <= 0 || !Number.isInteger(numericRunId) || numericRunId <= 0) throw new Error('A valid companyId and runId are required.');
        const [rows] = await pool.query(
            `SELECT ID, CompanyID, SnapshotID, Status, PeriodType, StartedAt, CompletedAt
             FROM StackCTRLEnterpriseReportRuns WHERE ID = ? AND CompanyID = ? LIMIT 1`,
            [numericRunId, numericCompanyId]
        );
        const row = rows[0];
        if (!row) throw new Error('Enterprise run was not found for this company.');
        const status = String(row.Status || '').toLowerCase();
        if (!['completed', 'completed_with_warnings'].includes(status) || !row.SnapshotID) throw new Error('Only a completed enterprise run with a persisted snapshot can be published.');
        return completedRunPublisher({
            companyId: numericCompanyId,
            run: { runId: Number(row.ID), snapshotId: Number(row.SnapshotID), status, periodType: row.PeriodType || 'daily' },
            now, pipelineExecutionId, cadence: 'reconciliation'
        });
    }

    async function runEnterpriseSynthesis({ companyId, runId }) {
        assertRateLimitCircuitClosed();
        const [rows] = await pool.query(`SELECT * FROM StackCTRLEnterpriseReportRuns WHERE ID = ? AND CompanyID = ? LIMIT 1`, [Number(runId), Number(companyId)]);
        if (!rows.length) throw new Error('Enterprise run not found');
        const row = rows[0];
        const run = { id: row.ID, periodType: row.PeriodType, periodStart: row.PeriodStart, periodEnd: row.PeriodEnd, mode: row.Mode };
        const progress = parseJson(row.ProgressJson, {});
        const queuedDomainKeys = array(progress.domainQueue).map(item => item.domainKey).filter(Boolean);
        try {
            return await runSynthesis({
                companyId: Number(companyId),
                snapshotId: row.SnapshotID,
                run,
                queuedDomainKeys: queuedDomainKeys.length ? queuedDomainKeys : null
            });
        } catch (error) {
            captureRateLimit(error);
            throw error;
        }
    }

    async function runRollupReport({ companyId, periodType, referenceDate = new Date(), deduplicationKey = null }) {
        if (!LOWER_PERIOD[periodType]) throw new Error('Rollup period must be weekly, monthly, or yearly');
        assertRateLimitCircuitClosed();
        const latestSnapshot = await loadSnapshot(companyId, null);
        const run = await createRun({ companyId: Number(companyId), snapshotId: latestSnapshot.ID, periodType, referenceDate, mode: `enterprise_${periodType}_synthesis`, deduplicationKey });
        if (run.duplicate) return { status: 'duplicate', runId: run.id, periodType };
        try {
            const synthesis = await runSynthesis({ companyId: Number(companyId), snapshotId: latestSnapshot.ID, run });
            return { status: synthesis.status, runId: run.id, synthesisId: synthesis.synthesisId, periodType };
        } catch (error) {
            captureRateLimit(error);
            await pool.query(`UPDATE StackCTRLEnterpriseReportRuns SET Status = ?, CompletedAt = NOW(), ErrorMessage = ? WHERE ID = ?`, [error.enterpriseStatus || classifyFailureStatus(error), String(error.message).slice(0, 5000), run.id]);
            throw error;
        }
    }

    function isLastBusinessDay(local, unit) {
        let next = local.plus({ days: 1 });
        while (next.weekday > 5) next = next.plus({ days: 1 });
        return unit === 'month' ? next.month !== local.month : next.year !== local.year;
    }

    async function loadScheduledEnterpriseCompanyIds() {
        // The report centre can legitimately be active before a legacy capability
        // row exists. Use the same tenant signals as reporting, rather than
        // silently scheduling zero companies and leaving the client at
        // "Awaiting first run" forever.
        try {
            const [rows] = await pool.query(`
                SELECT DISTINCT candidates.CompanyID
                FROM (
                    SELECT CompanyID
                    FROM StackCTRLClientCapabilities
                    WHERE ProfileKey = 'sunbird' AND IsEnabled = 1
                    UNION
                    SELECT CompanyID FROM SunbirdReportSettings
                    UNION
                    SELECT CompanyID FROM StackCTRLEnterpriseReportRuns
                ) candidates
                JOIN Companies company ON company.ID = candidates.CompanyID
                LEFT JOIN Users user_account ON user_account.CompanyID = candidates.CompanyID
                LEFT JOIN TenantAccessControl access_control ON access_control.UserID = user_account.ID
                LEFT JOIN StackCTRLClientCapabilities active_capability
                    ON active_capability.CompanyID = candidates.CompanyID
                    AND active_capability.ProfileKey = 'sunbird'
                    AND active_capability.IsEnabled = 1
                WHERE candidates.CompanyID IS NOT NULL
                  AND (
                    active_capability.CompanyID IS NOT NULL
                    OR LOWER(COALESCE(access_control.AccessType, '')) = 'sunbird'
                    OR LOWER(COALESCE(company.CompanyName, company.companyname, '')) LIKE '%sunbird%'
                  )
            `);
            return rows.map(row => Number(row.CompanyID)).filter(Boolean);
        } catch (error) {
            // Older installations may not yet have the report-settings table.
            // Preserve capability-based scheduling while schema migration catches up.
            logger.warn('[StackCTRL Enterprise] Report-aware tenant discovery fell back to capabilities:', error.message);
            const [rows] = await pool.query(`
                SELECT DISTINCT CompanyID
                FROM StackCTRLClientCapabilities
                WHERE ProfileKey = 'sunbird' AND IsEnabled = 1
            `);
            return rows.map(row => Number(row.CompanyID)).filter(Boolean);
        }
    }
    async function runScheduledTick({ now = new Date(), companyId = null, cadence = 'hourly', finalizeReport = true, domainKeys = null, includeSynthesis = true } = {}) {
        const schedule = johannesburgScheduleContext(now);
        const local = schedule.local;
        const normalizedCadence = String(cadence || 'hourly').toLowerCase() === 'daily' ? 'daily' : 'hourly';
        const scheduleKey = normalizedCadence === 'daily'
            ? schedule.scheduleKey
            : local.toFormat('yyyyLLddHH');
        let companyIds = companyId ? [Number(companyId)] : [];
        if (!companyIds.length) {
            companyIds = await loadScheduledEnterpriseCompanyIds();
        }
        logger.info('[StackCTRL Enterprise Pipeline]', {
            event: 'scheduled_tenant_discovery',
            cadence: normalizedCadence,
            scheduleKey,
            enterpriseIds: companyIds,
            enterpriseCount: companyIds.length,
            timestamp: new Date().toISOString()
        });

        const results = [];
        let hasFailure = false;
        for (const id of companyIds) {
            const pipelineExecutionId = `${id}:enterprise:${normalizedCadence}:${scheduleKey}`;
            try {
                const daily = await runEnterpriseReport({
                    companyId: id,
                    periodType: 'daily',
                    referenceDate: now,
                    deduplicationKey: pipelineExecutionId,
                    refreshSnapshot: true,
                    domainKeys,
                    includeSynthesis
                });
                const companyRuns = [{ periodType: 'daily', ...daily }];
                const effectiveStatus = daily.status === 'duplicate' ? daily.existingStatus : daily.status;
                const analysisSucceeded = ['completed', 'completed_with_warnings'].includes(String(effectiveStatus || '').toLowerCase());

                if (!analysisSucceeded) {
                    hasFailure = true;
                    logger.error('[StackCTRL Enterprise Pipeline]', {
                        event: 'pipeline_failed',
                        failureStage: daily.pipelineFailure?.failureStage || 'ENTERPRISE_DEEP_ANALYSIS_FAILED',
                        enterpriseId: id,
                        snapshotId: daily.snapshotId || null,
                        analysisExecutionId: daily.runId || null,
                        pipelineExecutionId,
                        timestamp: new Date().toISOString(),
                        error: daily.pipelineFailure?.error || `Enterprise Deep Analysis ended with status ${effectiveStatus || 'unknown'}`
                    });
                    results.push({ companyId: id, runs: companyRuns });
                    continue;
                }

                if (finalizeReport && typeof onScheduledRunCompleted !== 'function') {
                    throw new Error('Scheduled enterprise report finalization is not configured.');
                }
                if (finalizeReport && typeof onScheduledRunCompleted === 'function') {
                    logger.info('[StackCTRL Enterprise Pipeline]', {
                        event: 'analysis_result_persistence_started',
                        enterpriseId: id,
                        snapshotId: daily.snapshotId,
                        analysisExecutionId: daily.runId,
                        pipelineExecutionId,
                        timestamp: new Date().toISOString()
                    });
                    companyRuns[0].reportAutomation = await onScheduledRunCompleted({
                        companyId: id,
                        run: { ...daily, status: effectiveStatus },
                        now,
                        localTime: local.toISO(),
                        duplicateTrigger: daily.status === 'duplicate',
                        cadence: normalizedCadence,
                        pipelineExecutionId
                    });
                }

                if (finalizeReport && !companyRuns[0].reportAutomation?.reportId) {
                    throw new Error('Scheduled enterprise report finalization did not publish a report.');
                }

                if (daily.rateLimited) {
                    results.push({ companyId: id, runs: companyRuns });
                    hasFailure = true;
                    break;
                }

                if (local.weekday === 5) {
                    companyRuns.push({
                        periodType: 'weekly',
                        ...(await runRollupReport({
                            companyId: id,
                            periodType: 'weekly',
                            referenceDate: now,
                            deduplicationKey: `${id}:enterprise:weekly:${local.weekNumber}:${local.weekYear}`
                        }))
                    });
                }
                if (isLastBusinessDay(local, 'month')) {
                    companyRuns.push({
                        periodType: 'monthly',
                        ...(await runRollupReport({
                            companyId: id,
                            periodType: 'monthly',
                            referenceDate: now,
                            deduplicationKey: `${id}:enterprise:monthly:${local.toFormat('yyyyLL')}`
                        }))
                    });
                }
                if (isLastBusinessDay(local, 'year')) {
                    companyRuns.push({
                        periodType: 'yearly',
                        ...(await runRollupReport({
                            companyId: id,
                            periodType: 'yearly',
                            referenceDate: now,
                            deduplicationKey: `${id}:enterprise:yearly:${local.year}`
                        }))
                    });
                }

                await recordPipelinePhase(daily.runId, 'PIPELINE_COMPLETED', {
                    enterpriseId: id,
                    snapshotId: daily.snapshotId,
                    analysisExecutionId: daily.runId,
                    pipelineExecutionId,
                    reportId: companyRuns[0].reportAutomation?.reportId || null,
                    status: effectiveStatus
                });
                if (normalizedCadence === 'daily' && companyRuns[0].reportAutomation?.reportId) {
                    logger.info('[StackCTRL Enterprise Pipeline]', {
                        event: 'enterprise_daily_pipeline_completed',
                        companyId: id,
                        pipelineExecutionId,
                        runId: daily.runId,
                        snapshotId: daily.snapshotId,
                        analysisExecutionId: daily.runId,
                        scheduleKey,
                        reportPublished: true,
                        reportId: companyRuns[0].reportAutomation.reportId,
                        localDate: local.toISODate(),
                        localTime: local.toFormat('HH:mm:ss')
                    });
                }
                logger.info('[StackCTRL Enterprise Pipeline]', {
                    event: 'pipeline_completed',
                    enterpriseId: id,
                    snapshotId: daily.snapshotId,
                    analysisExecutionId: daily.runId,
                    pipelineExecutionId,
                    duplicateTrigger: daily.status === 'duplicate',
                    timestamp: new Date().toISOString()
                });
                results.push({ companyId: id, runs: companyRuns });
            } catch (error) {
                hasFailure = true;
                const failure = error.enterprisePipelineFailure || {
                    failureStage: 'REPORT_PERSISTENCE_FAILED',
                    enterpriseId: id,
                    snapshotId: null,
                    analysisExecutionId: null,
                    pipelineExecutionId,
                    timestamp: new Date().toISOString(),
                    error: String(error.message || error)
                };
                if (failure.analysisExecutionId) {
                    await recordPipelinePhase(failure.analysisExecutionId, 'PIPELINE_FAILED', failure).catch(progressError => {
                        logger.error('[StackCTRL Enterprise Pipeline]', {
                            event: 'pipeline_failure_status_write_failed',
                            enterpriseId: id,
                            pipelineExecutionId,
                            error: progressError.message
                        });
                    });
                }
                logger.error('[StackCTRL Enterprise Pipeline]', { event: 'pipeline_failed', ...failure });
                results.push({
                    companyId: id,
                    runs: [{
                        periodType: 'daily',
                        status: 'failed',
                        message: failure.error,
                        pipelineFailure: failure
                    }]
                });
            }
        }
        return {
            status: hasFailure ? 'failed' : 'completed',
            cadence: normalizedCadence,
            scheduleKey,
            localTime: local.toISO(),
            companies: results
        };
    }
    async function runDailyAutomationTick({ now = new Date(), companyId = null, force = false } = {}) {
        const local = johannesburgScheduleContext(now).local;
        const configuredHour = Math.min(23, Math.max(0, Number(process.env.ENTERPRISE_AI_DAILY_RUN_HOUR) || 0));
        // If the instance was asleep or restarting at the exact scheduled hour,
        // keep the run eligible for the rest of that Johannesburg day. The daily
        // deduplication key still guarantees at most one run per tenant.
        if (!force && local.hour < configuredHour) {
            return { status: 'not_due', cadence: 'daily', localTime: local.toISO(), scheduledHour: configuredHour, companies: [] };
        }
        return runScheduledTick({ now, companyId, cadence: 'daily', finalizeReport: true });
    }

    async function getAdminData(companyId, runId = null) {
        const params = [Number(companyId)];
        const runFilter = runId ? ' AND RunID = ?' : '';
        if (runId) params.push(Number(runId));
        const [[runs], [domains], [audits], [synthesis], [items], [batches]] = await Promise.all([
            pool.query(`SELECT * FROM StackCTRLEnterpriseReportRuns WHERE CompanyID = ? ORDER BY ID DESC LIMIT 50`, [Number(companyId)]),
            pool.query(`SELECT * FROM StackCTRLTenantDomainIntelligence WHERE CompanyID = ?${runFilter}
                        ORDER BY RunID DESC,
                         CASE
                           WHEN Status IN ('failed', 'failed_invalid_json', 'failed_storage', 'failed_rate_limited', 'failed_source_mismatch') THEN 0
                           WHEN Status IN ('partial', 'completed_with_warnings') THEN 1
                           WHEN Status IN ('running', 'queued') THEN 2
                           WHEN Status = 'completed' THEN 3
                           ELSE 4
                         END,
                         ID DESC LIMIT 200`, params),
            pool.query(`SELECT * FROM StackCTRLIntelligenceEvidenceAudit WHERE CompanyID = ?${runFilter}
                        ORDER BY RunID DESC,
                         CASE
                           WHEN Status IN ('failed', 'failed_invalid_json', 'failed_storage', 'failed_rate_limited', 'failed_source_mismatch') THEN 0
                           WHEN Status IN ('partial', 'completed_with_warnings') THEN 1
                           WHEN Status IN ('running', 'queued') THEN 2
                           WHEN Status = 'completed' THEN 3
                           ELSE 4
                         END,
                         ID DESC LIMIT 200`, params),
            pool.query(`SELECT * FROM StackCTRLEnterpriseSynthesis WHERE CompanyID = ?${runFilter} ORDER BY ID DESC LIMIT 50`, params),
            pool.query(`SELECT * FROM StackCTRLEnterpriseIntelligenceItems WHERE CompanyID = ?${runFilter} ORDER BY ID DESC LIMIT 500`, params),
            pool.query(`SELECT * FROM StackCTRLTenantDomainIntelligenceBatches WHERE CompanyID = ?${runFilter}
                        ORDER BY RunID DESC, DomainKey ASC, BatchNumber ASC LIMIT 1000`, params)
        ]);
        return {
            settings: { ...settings },
            domains: ENTERPRISE_DOMAINS.map(enterpriseDomainDescriptor),
            runs: runs.map(row => ({ ...row, ProgressJson: parseJson(row.ProgressJson, {}) })),
            domainIntelligence: domains.map(row => ({ ...row, AnalysisJson: parseJson(row.AnalysisJson, {}) })),
            evidenceAudit: audits.map(row => ({
                ...row,
                AzureInputSummaryJson: parseJson(row.AzureInputSummaryJson, {}),
                OmittedSummaryJson: parseJson(row.OmittedSummaryJson, {})
            })),
            synthesis: synthesis.map(row => ({
                ...row,
                ExecutiveSummaryJson: parseJson(row.ExecutiveSummaryJson, {}),
                BoardReportJson: parseJson(row.BoardReportJson, {}),
                ManagementReportJson: parseJson(row.ManagementReportJson, {}),
                RiskRegisterJson: parseJson(row.RiskRegisterJson, []),
                RecommendationsJson: parseJson(row.RecommendationsJson, []),
                TrendAnalysisJson: parseJson(row.TrendAnalysisJson, []),
                ComplianceReviewJson: parseJson(row.ComplianceReviewJson, {}),
                GovernanceReviewJson: parseJson(row.GovernanceReviewJson, {}),
                DomainScorecardJson: parseJson(row.DomainScorecardJson, []),
                MaturityAssessmentJson: parseJson(row.MaturityAssessmentJson, {}),
                TopDecisionsRequiredJson: parseJson(row.TopDecisionsRequiredJson, []),
                Next30DaysPlanJson: parseJson(row.Next30DaysPlanJson, []),
                Next90DaysPlanJson: parseJson(row.Next90DaysPlanJson, []),
                EvidenceJustificationJson: parseJson(row.EvidenceJustificationJson, {}),
                LimitationsJson: parseJson(row.LimitationsJson, []),
                PowerBISummaryJson: parseJson(row.PowerBISummaryJson, {})
            })),
            items,
            batches: batches.map(row => ({
                ...row,
                BatchSummaryJson: parseJson(row.BatchSummaryJson, {}),
                FindingsJson: parseJson(row.FindingsJson, []),
                RisksJson: parseJson(row.RisksJson, []),
                RecommendationsJson: parseJson(row.RecommendationsJson, []),
                TrendsJson: parseJson(row.TrendsJson, []),
                MissingDataWarningsJson: parseJson(row.MissingDataWarningsJson, [])
            }))
        };
    }

    async function getAdminProgress(companyId, runId = null) {
        const numericCompanyId = Number(companyId);
        const params = [numericCompanyId];
        const runFilter = runId ? ' AND RunID = ?' : '';
        if (runId) params.push(Number(runId));
        const [[runs], [domains], [audits], [synthesis], [batches]] = await Promise.all([
            pool.query(`SELECT ID, CompanyID, SnapshotID, PeriodType, PeriodStart, PeriodEnd, Status, Mode,
                               StartedAt, CompletedAt, TotalInputTokens, TotalOutputTokens, TotalTokens,
                               TotalRequestBytes, TotalResponseBytes, RetryCount, ErrorMessage, ProgressJson
                        FROM StackCTRLEnterpriseReportRuns WHERE CompanyID = ? ORDER BY ID DESC LIMIT 50`, [numericCompanyId]),
            pool.query(`SELECT ID, CompanyID, SnapshotID, RunID, DomainKey, DomainName, PeriodType, PeriodStart,
                               PeriodEnd, HealthScore, RiskScore, RiskLevel, InputSizeBytes, ResponseSizeBytes,
                               InputTokens, OutputTokens, TotalTokens, RetryCount, Status, ErrorMessage,
                               MissingDataWarningsJson, CreatedAt
                        FROM StackCTRLTenantDomainIntelligence WHERE CompanyID = ?${runFilter}
                        ORDER BY RunID DESC, ID DESC LIMIT 200`, params),
            pool.query(`SELECT ID, CompanyID, SnapshotID, RunID, DomainKey, StackCTRLDataCount, SentToAzureCount,
                               OmittedCount, MetricsIncludedCount, EvidenceIncludedCount, EvidenceOmittedCount,
                               HistoricalComparisonsIncluded, RisksReturnedCount, RecommendationsReturnedCount,
                               TrendsReturnedCount, InputSizeBytes, OutputSizeBytes, InputTokens, OutputTokens,
                               RetryCount, Status, CreatedAt
                        FROM StackCTRLIntelligenceEvidenceAudit WHERE CompanyID = ?${runFilter}
                        ORDER BY RunID DESC, ID DESC LIMIT 200`, params),
            pool.query(`SELECT ID, CompanyID, SnapshotID, RunID, PeriodType, PeriodStart, PeriodEnd, Status,
                               InputSizeBytes, ResponseSizeBytes, InputTokens, OutputTokens, TotalTokens,
                               RetryCount, CreatedAt
                        FROM StackCTRLEnterpriseSynthesis WHERE CompanyID = ?${runFilter} ORDER BY ID DESC LIMIT 50`, params),
            pool.query(`SELECT CompanyID, SnapshotID, RunID, DomainKey, MAX(DomainName) AS DomainName,
                               MAX(BatchCount) AS BatchCount, MAX(BatchNumber) AS BatchNumber,
                               SUM(Status IN ('completed', 'completed_with_warnings')) AS CompletedBatches,
                               SUM(Status NOT IN ('completed', 'completed_with_warnings')) AS FailedBatches,
                               CASE
                                   WHEN SUM(Status NOT IN ('completed', 'completed_with_warnings')) > 0
                                       AND SUM(Status IN ('completed', 'completed_with_warnings')) > 0 THEN 'partial'
                                   WHEN SUM(Status NOT IN ('completed', 'completed_with_warnings')) > 0 THEN 'failed'
                                   WHEN SUM(Status = 'completed_with_warnings') > 0 THEN 'completed_with_warnings'
                                   ELSE 'completed'
                               END AS Status,
                               SUM(BatchItemCount) AS BatchItemCount, SUM(SentToAzureCount) AS SentToAzureCount,
                               SUM(OmittedFromThisBatch) AS OmittedFromThisBatch,
                               MIN(RemainingAfterBatch) AS RemainingAfterBatch,
                               SUM(InputTokens) AS InputTokens, SUM(OutputTokens) AS OutputTokens,
                               SUM(TotalTokens) AS TotalTokens, SUM(RetryCount) AS RetryCount,
                               MAX(Status = 'completed_with_warnings' OR AzureFinishReason = 'length') AS JsonRecoveryWarning,
                               MAX(CASE WHEN Status NOT IN ('completed', 'completed_with_warnings') THEN ErrorMessage END) AS ErrorMessage,
                               MAX(CASE WHEN Status NOT IN ('completed', 'completed_with_warnings') THEN FailureReason END) AS FailureReason
                        FROM StackCTRLTenantDomainIntelligenceBatches WHERE CompanyID = ?${runFilter}
                        GROUP BY CompanyID, SnapshotID, RunID, DomainKey ORDER BY RunID DESC, DomainKey LIMIT 200`, params)
        ]);
        if (runs[0] && ['running', 'queued'].includes(String(runs[0].Status || ''))) {
            const progress = parseJson(runs[0].ProgressJson, {});
            const lastProgressAt = new Date(progress.updatedAt || runs[0].StartedAt || 0).getTime();
            if (lastProgressAt && Date.now() - lastProgressAt > settings.terminalStaleMs) {
                const stuckStage = progress.currentStage || progress.phase || progress.currentDomainKey || 'unknown_stage';
                const lastSuccessfulStage = progress.lastSuccessfulStage || 'unknown';
                const reason = `No enterprise progress for ${Math.ceil((Date.now() - lastProgressAt) / 60000)} minute(s). Stuck stage: ${stuckStage}. Last successful stage: ${lastSuccessfulStage}.`;
                await pool.query(
                    `UPDATE StackCTRLEnterpriseReportRuns SET Status = 'failed_terminal', CompletedAt = NOW(), ErrorMessage = ?,
                     ProgressJson = JSON_SET(COALESCE(ProgressJson, JSON_OBJECT()), '$.phase', 'failed_terminal', '$.stageFailureReason', ?, '$.updatedAt', ?)
                     WHERE ID = ? AND Status IN ('running', 'queued')`,
                    [reason, reason, new Date().toISOString(), runs[0].ID]
                );
                runs[0].Status = 'failed_terminal';
                runs[0].ErrorMessage = reason;
                runs[0].ProgressJson = { ...progress, phase: 'failed_terminal', stageFailureReason: reason, updatedAt: new Date().toISOString() };
            }
        }
        const classifyWarning = warning => {
            const text = String(warning || '');
            if (/permission|forbidden|unauthori[sz]ed|403/i.test(text)) return 'missing_api_permissions';
            if (/cloudflare.*field|missing.*field|unknown control/i.test(text)) return 'missing_cloudflare_fields';
            if (/stale|source_too_old|refresh.*source/i.test(text)) return 'stale_source';
            if (/recovered|closing json|truncated json|invalid json|json parse|azure_invalid_json/i.test(text)) return 'azure_recovered_json';
            if (/partial|omitted|incomplete/i.test(text)) return 'partial_evidence';
            if (/optional|unavailable|not configured/i.test(text)) return 'optional_source_unavailable';
            return 'general_warning';
        };
        const normalizedRuns = runs.map(row => ({ ...row, ProgressJson: parseJson(row.ProgressJson, {}) }));
        const lightweightDomains = domains.map(row => {
            const warningReasons = array(parseJson(row.MissingDataWarningsJson, [])).map(String);
            return {
                ...row,
                WarningReasons: warningReasons,
                WarningCategories: [...new Set(warningReasons.map(classifyWarning))]
            };
        });
        const latestRun = normalizedRuns[0] || null;
        const latestRunId = latestRun?.ID == null ? null : Number(latestRun.ID);
        let latestDomains = latestRunId ? lightweightDomains.filter(row => Number(row.RunID) === latestRunId) : [];
        const progress = latestRun?.ProgressJson || {};
        const lastProgressAt = new Date(progress.updatedAt || latestRun?.StartedAt || 0).getTime();
        if (latestRunId && lastProgressAt && Date.now() - lastProgressAt > settings.terminalStaleMs) {
            for (const row of latestDomains) {
                if (String(row.Status || '') !== 'running') continue;
                const reason = `Domain ${row.DomainKey} remained RUNNING for ${Math.ceil((Date.now() - lastProgressAt) / 60000)} minute(s) without progress. Marked failed_terminal.`;
                await pool.query(
                    `UPDATE StackCTRLTenantDomainIntelligence
                     SET Status = 'failed_terminal', ErrorMessage = ?
                     WHERE ID = ? AND Status = 'running'`,
                    [reason, row.ID]
                );
                row.Status = 'failed_terminal';
                row.ErrorMessage = reason;
            }
        }
        const latestAudits = latestRunId ? audits.filter(row => Number(row.RunID) === latestRunId) : [];
        const latestBatches = latestRunId ? batches.filter(row => Number(row.RunID) === latestRunId) : [];
        const domainRunAudits = latestAudits.map(row => ({
            domainKey: row.DomainKey,
            companyId: numericCompanyId,
            snapshotId: row.SnapshotID,
            collectionStatus: null,
            sourceFreshness: null,
            stackctrlRecordCount: row.StackCTRLDataCount,
            preparedRecordCount: row.EvidenceIncludedCount,
            analysedRecordCount: row.SentToAzureCount,
            omittedRecordCount: Number(row.OmittedCount || 0) + Number(row.EvidenceOmittedCount || 0),
            omittedReasons: [],
            batchCount: latestBatches.find(batch => batch.DomainKey === row.DomainKey)?.BatchCount || null,
            currentBatch: progress.currentDomainKey === row.DomainKey ? (progress.currentBatch || null) : null,
            azureAttemptCount: Number(row.RetryCount || 0) + 1,
            azureStatus: row.Status,
            storageStatus: row.Status,
            finalDomainStatus: row.Status,
            warningReasons: [],
            failureReason: null
        }));
        return {
            payloadType: 'enterprise_progress_only',
            companyId: numericCompanyId,
            settings: {
                domainDelayMs: settings.domainDelayMs,
                maxTotalTokens: settings.maxTotalTokens,
                maxItemsPerBatch: settings.maxItemsPerBatch,
                heavyDomainMaxItemsPerBatch: settings.heavyDomainMaxItemsPerBatch
            },
            domains: ENTERPRISE_DOMAINS.map(enterpriseDomainDescriptor),
            runs: normalizedRuns,
            domainIntelligence: lightweightDomains,
            evidenceAudit: audits,
            domainRunAudits,
            synthesis,
            batches,
            progressSummary: latestRun ? {
                runId: latestRunId,
                snapshotId: latestRun.SnapshotID == null ? null : Number(latestRun.SnapshotID),
                companyId: numericCompanyId,
                currentDomain: progress.currentDomainKey || null,
                currentStage: progress.currentStage || progress.phase || null,
                lastSuccessfulStage: progress.lastSuccessfulStage || null,
                stuckReason: progress.stageFailureReason || latestRun.ErrorMessage || null,
                domainStatuses: latestDomains.map(row => ({ domainKey: row.DomainKey, status: row.Status, errorMessage: row.ErrorMessage || null })),
                counts: progress.counts || {},
                recordsPrepared: latestAudits.reduce((total, row) => total + Number(row.EvidenceIncludedCount || 0), 0),
                recordsSent: latestAudits.reduce((total, row) => total + Number(row.SentToAzureCount || 0), 0),
                recordsOmitted: latestAudits.reduce((total, row) => total + Number(row.OmittedCount || 0) + Number(row.EvidenceOmittedCount || 0), 0),
                batchCount: latestBatches.reduce((total, row) => total + Number(row.BatchCount || 0), 0),
                currentDomainBatchCount: progress.batchCount || latestBatches.find(row => row.DomainKey === progress.currentDomainKey)?.BatchCount || null,
                currentBatch: progress.currentBatch || latestBatches.find(row => row.DomainKey === progress.currentDomainKey)?.BatchNumber || null,
                tokenSummary: {
                    inputTokens: Number(latestRun.TotalInputTokens || 0), outputTokens: Number(latestRun.TotalOutputTokens || 0),
                    totalTokens: Number(latestRun.TotalTokens || 0), retryCount: Number(latestRun.RetryCount || 0)
                },
                evidenceCountSummary: latestAudits.map(row => ({
                    domainKey: row.DomainKey, recordsPrepared: Number(row.EvidenceIncludedCount || 0),
                    recordsSent: Number(row.SentToAzureCount || 0),
                    recordsOmitted: Number(row.OmittedCount || 0) + Number(row.EvidenceOmittedCount || 0)
                })),
                domainRunAudits,
                jsonRecoveryWarning: latestBatches.some(row => Boolean(Number(row.JsonRecoveryWarning))),
                finalSynthesisReady: synthesis.some(row => Number(row.RunID) === latestRunId && ['completed', 'completed_with_warnings'].includes(row.Status))
            } : null
        };
    }

    async function latestRunIdForCompany(companyId, requestedRunId = null) {
        if (requestedRunId) return Number(requestedRunId);
        const [rows] = await pool.query('SELECT ID FROM StackCTRLEnterpriseReportRuns WHERE CompanyID = ? ORDER BY ID DESC LIMIT 1', [Number(companyId)]);
        if (!rows[0]) { const error = new Error('Enterprise intelligence run not found'); error.statusCode = 404; throw error; }
        return Number(rows[0].ID);
    }

    async function getAdminDomainDetail(companyId, domainKey, runId = null) {
        if (!DOMAIN_BY_KEY[domainKey]) { const error = new Error(`Unsupported enterprise domain: ${domainKey}`); error.statusCode = 400; throw error; }
        const resolvedRunId = await latestRunIdForCompany(companyId, runId);
        const [rows] = await pool.query('SELECT * FROM StackCTRLTenantDomainIntelligence WHERE CompanyID = ? AND RunID = ? AND DomainKey = ? ORDER BY ID DESC LIMIT 1', [Number(companyId), resolvedRunId, domainKey]);
        if (!rows[0]) { const error = new Error('Domain intelligence detail not found'); error.statusCode = 404; throw error; }
        return {
            ...rows[0],
            AnalysisJson: normalizeDomainOutputForDisplay(
                parseJson(rows[0].AnalysisJson, {}),
                DOMAIN_BY_KEY[domainKey],
                rows[0].SnapshotID
            )
        };
    }

    async function getAdminAuditDetail(companyId, domainKey, runId = null) {
        const resolvedRunId = await latestRunIdForCompany(companyId, runId);
        const [rows] = await pool.query('SELECT * FROM StackCTRLIntelligenceEvidenceAudit WHERE CompanyID = ? AND RunID = ? AND DomainKey = ? ORDER BY ID DESC LIMIT 1', [Number(companyId), resolvedRunId, domainKey]);
        if (!rows[0]) { const error = new Error('Enterprise evidence audit detail not found'); error.statusCode = 404; throw error; }
        return {
            ...rows[0],
            AzureInputSummaryJson: parseJson(rows[0].AzureInputSummaryJson, {}),
            OmittedSummaryJson: parseJson(rows[0].OmittedSummaryJson, {}),
            domainRunAudit: parseJson(rows[0].AzureInputSummaryJson, {}).domainRunAudit || null
        };
    }

    async function getAdminBatchDetails(companyId, domainKey, runId = null) {
        const resolvedRunId = await latestRunIdForCompany(companyId, runId);
        const [rows] = await pool.query('SELECT * FROM StackCTRLTenantDomainIntelligenceBatches WHERE CompanyID = ? AND RunID = ? AND DomainKey = ? ORDER BY BatchNumber', [Number(companyId), resolvedRunId, domainKey]);
        const domain = DOMAIN_BY_KEY[domainKey] || { key: domainKey, name: domainKey };
        return rows.map(row => ({
            ...row,
            BatchSummaryJson: sanitizeVisibleValue(parseJson(row.BatchSummaryJson, {})),
            FindingsJson: array(parseJson(row.FindingsJson, [])).map(item => normalizeEvidenceBackedItem(item, domain, row.SnapshotID)),
            RisksJson: array(parseJson(row.RisksJson, [])).map(item => normalizeEvidenceBackedItem(item, domain, row.SnapshotID)),
            RecommendationsJson: array(parseJson(row.RecommendationsJson, [])).map(item => normalizeEvidenceBackedItem(item, domain, row.SnapshotID)),
            TrendsJson: array(parseJson(row.TrendsJson, [])).map(item => normalizeEvidenceBackedItem(item, domain, row.SnapshotID)),
            MissingDataWarningsJson: sanitizeVisibleValue(parseJson(row.MissingDataWarningsJson, []))
        }));
    }

    async function getAdminSynthesisDetail(companyId, runId = null) {
        const resolvedRunId = await latestRunIdForCompany(companyId, runId);
        const [rows] = await pool.query('SELECT * FROM StackCTRLEnterpriseSynthesis WHERE CompanyID = ? AND RunID = ? ORDER BY ID DESC LIMIT 1', [Number(companyId), resolvedRunId]);
        if (!rows[0]) { const error = new Error('Enterprise synthesis detail not found'); error.statusCode = 404; throw error; }
        return powerBISynthesisRow(rows[0]);
    }

    function powerBIDomainRow(row) {
        const domain = DOMAIN_BY_KEY[row.DomainKey] || { key: row.DomainKey, name: row.DomainName };
        const intelligenceOutput = normalizeDomainOutputForDisplay(parseJson(row.AnalysisJson, null), domain, row.SnapshotID);
        return {
            companyId: Number(row.CompanyID),
            snapshotId: row.SnapshotID == null ? null : Number(row.SnapshotID),
            runId: Number(row.RunID),
            domainKey: row.DomainKey,
            domainName: row.DomainName,
            periodType: row.PeriodType,
            periodStart: row.PeriodStart,
            periodEnd: row.PeriodEnd,
            createdAt: row.CreatedAt,
            status: row.Status,
            tokenUsage: {
                estimatedInputTokens: Math.ceil(Number(row.InputSizeBytes || 0) / 4),
                inputTokens: Number(row.InputTokens || 0),
                outputTokens: Number(row.OutputTokens || 0),
                totalTokens: Number(row.TotalTokens || 0),
                retryCount: Number(row.RetryCount || 0)
            },
            batchInfo: intelligenceOutput?.batchInfo || null,
            evidenceLimitations: intelligenceOutput?.evidenceLimitations || null,
            errorMessage: row.ErrorMessage || null,
            intelligenceOutput
        };
    }

    function powerBISynthesisRow(row) {
        if (!row) return null;
        const synthesisOutput = normalizeSynthesisOutputForDisplay({
            enterpriseExecutiveSummary: parseJson(row.ExecutiveSummaryJson, {}),
            boardReport: parseJson(row.BoardReportJson, {}),
            managementReport: parseJson(row.ManagementReportJson, {}),
            riskRegister: parseJson(row.RiskRegisterJson, []),
            recommendations: parseJson(row.RecommendationsJson, []),
            trendAnalysis: parseJson(row.TrendAnalysisJson, []),
            complianceReview: parseJson(row.ComplianceReviewJson, {}),
            governanceReview: parseJson(row.GovernanceReviewJson, {}),
            domainScorecard: parseJson(row.DomainScorecardJson, []),
            maturityAssessment: parseJson(row.MaturityAssessmentJson, {}),
            businessImpactSummary: row.BusinessImpactSummary || null,
            topDecisionsRequired: parseJson(row.TopDecisionsRequiredJson, []),
            next30DaysPlan: parseJson(row.Next30DaysPlanJson, []),
            next90DaysPlan: parseJson(row.Next90DaysPlanJson, []),
            evidenceJustificationSummary: parseJson(row.EvidenceJustificationJson, {}),
            limitationsAndAssumptions: parseJson(row.LimitationsJson, []),
            powerBiSummary: parseJson(row.PowerBISummaryJson, {})
        }, row.SnapshotID);
        return {
            companyId: Number(row.CompanyID), snapshotId: row.SnapshotID == null ? null : Number(row.SnapshotID),
            runId: Number(row.RunID), synthesisId: Number(row.ID), periodType: row.PeriodType,
            periodStart: row.PeriodStart, periodEnd: row.PeriodEnd, createdAt: row.CreatedAt,
            status: row.Status,
            tokenUsage: {
                estimatedInputTokens: Math.ceil(Number(row.InputSizeBytes || 0) / 4),
                inputTokens: Number(row.InputTokens || 0), outputTokens: Number(row.OutputTokens || 0),
                totalTokens: Number(row.TotalTokens || 0), retryCount: Number(row.RetryCount || 0)
            },
            synthesisOutput
        };
    }

    function powerBIAuditRow(row) {
        return {
            ...row,
            AzureInputSummaryJson: parseJson(row.AzureInputSummaryJson, {}),
            OmittedSummaryJson: parseJson(row.OmittedSummaryJson, {})
        };
    }

    function powerBIRunRow(row) {
        if (!row) return null;
        return stripInternalPowerBIFields(compactNonEmptyObject({
            runId: Number(row.ID ?? row.runId),
            companyId: row.CompanyID == null && row.companyId == null ? null : Number(row.CompanyID ?? row.companyId),
            snapshotId: row.SnapshotID == null && row.snapshotId == null ? null : Number(row.SnapshotID ?? row.snapshotId),
            periodType: row.PeriodType || row.periodType || null,
            periodStart: row.PeriodStart || row.periodStart || null,
            periodEnd: row.PeriodEnd || row.periodEnd || null,
            status: row.Status || row.status || null,
            progress: parseJson(row.ProgressJson, row.progress || {}),
            startedAt: row.StartedAt || row.startedAt || null,
            completedAt: row.CompletedAt || row.completedAt || null,
            createdAt: row.CreatedAt || row.createdAt || row.StartedAt || row.startedAt || null,
            errorMessage: row.ErrorMessage || row.errorMessage || null,
            tokenUsage: {
                inputTokens: Number(row.TotalInputTokens || row.InputTokens || row.tokenUsage?.inputTokens || 0),
                outputTokens: Number(row.TotalOutputTokens || row.OutputTokens || row.tokenUsage?.outputTokens || 0),
                totalTokens: Number(row.TotalTokens || row.tokenUsage?.totalTokens || 0),
                retryCount: Number(row.RetryCount || row.tokenUsage?.retryCount || 0)
            }
        }));
    }
    function flattenPowerBITables({ domains = [], finalSynthesis = null, audits = [], runs = [] } = {}) {
        const DomainScorecardRows = sanitizeVisibleValue(array(finalSynthesis?.synthesisOutput?.domainScorecard));
        const reportableDomains = domains.filter(domain => ACTIVE_ENTERPRISE_DOMAIN_SET.has(domain.domainKey));
        const flattenControls = (value, category = null) => {
            if (Array.isArray(value)) return value.flatMap(item => flattenControls(item, category));
            if (!value || typeof value !== 'object') return [];
            if (value.title || value.name || value.control || value.description || value.detail) return [{ category, ...value }];
            return Object.entries(value).flatMap(([key, nested]) => flattenControls(nested, category ? `${category}.${key}` : key));
        };
        const sectionRows = (section, itemType) => reportableDomains.flatMap(domain => array(domain.intelligenceOutput?.[section]).map((item, index) => ({
            companyId: domain.companyId, snapshotId: domain.snapshotId, runId: domain.runId,
            periodType: domain.periodType, periodStart: domain.periodStart, periodEnd: domain.periodEnd,
            domainKey: domain.domainKey, domainName: domain.domainName, rowNumber: index + 1,
            itemType, item: sanitizeVisibleValue(item)
        })));
        const relationshipId = (row, type) => textOrNull(
            row.item?.[`${type}Id`] || row.item?.id || `${row.runId}:${row.domainKey}:${type}:${row.rowNumber}`,
            255
        );
        const flatItemFields = row => ({
            title: row.item?.title || row.item?.metricName || null,
            description: row.item?.description || row.item?.detail || null,
            severity: row.item?.severity || null,
            priority: row.item?.priority || null,
            status: row.item?.status || null,
            likelihood: row.item?.likelihood || null,
            impact: row.item?.impact || null,
            businessReason: row.item?.businessReason || row.item?.businessImpact || row.item?.whyItMatters || null,
            recommendation: row.item?.recommendation || row.item?.recommendedAction || row.item?.detail || null,
            sourceDomain: row.item?.sourceDomain || row.domainKey,
            sourceMetric: row.item?.sourceMetric || null,
            affectedEntityIds: compactReferences(row.item?.affectedEntityIds),
            recordIds: compactReferences(row.item?.recordIds),
            sourceAlertIds: compactReferences(row.item?.sourceAlertIds),
            internalSourcePaths: array(row.item?.internalSourcePaths)
        });
        const riskRows = sectionRows('risks', 'risk');
        const recommendationRows = sectionRows('recommendations', 'recommendation');
        const RiskRegisterRows = riskRows.map(row => ({
            ...row,
            riskId: relationshipId(row, 'risk'),
            ...flatItemFields(row),
            risk: row.item
        }));
        const RecommendationRows = recommendationRows.map(row => ({
            ...row,
            recommendationId: relationshipId(row, 'recommendation'),
            riskId: row.item?.riskId || null,
            ...flatItemFields(row),
            recommendationDetail: row.item
        }));
        const ControlAssessmentRows = reportableDomains.flatMap(domain => {
            const assessment = domain.intelligenceOutput?.controlAssessment;
            const rows = flattenControls(assessment);
            return rows.map((control, index) => ({ companyId: domain.companyId, snapshotId: domain.snapshotId, runId: domain.runId, domainKey: domain.domainKey, rowNumber: index + 1, ...control, control }));
        });
        const TrendRows = sectionRows('trendAnalysis', 'trend').map(row => ({ ...row, trendId: relationshipId(row, 'trend'), ...flatItemFields(row), trend: row.item }));
        const evidenceBearingRows = [
            ...sectionRows('keyFindings', 'finding'), ...riskRows,
            ...recommendationRows, ...sectionRows('managementActions', 'managementAction'),
            ...sectionRows('trendAnalysis', 'trend')
        ];
        const AffectedEntityRows = evidenceBearingRows.flatMap(row => array(row.item?.affectedEntities).map((value, index) => {
            const affectedEntity = canonicalEntity(value, row.item) || {};
            return {
                companyId: row.companyId,
                runId: row.runId,
                snapshotId: row.snapshotId,
                domainKey: row.domainKey,
                riskId: row.itemType === 'risk' ? relationshipId(row, 'risk') : (row.item?.riskId || null),
                itemType: row.itemType,
                itemTitle: row.item?.title || row.item?.metricName || null,
                rowNumber: index + 1,
                entityId: affectedEntity.entityId || null,
                entityName: affectedEntity.entityName || null,
                entityType: affectedEntity.entityType || 'Entity',
                entityDisplayName: affectedEntity.entityDisplayName || affectedEntity.entityName || null,
                entityEmail: affectedEntity.entityEmail || null,
                entityDeviceName: affectedEntity.entityDeviceName || null,
                entityApplicationName: affectedEntity.entityApplicationName || null,
                assignedUser: affectedEntity.assignedUser || affectedEntity.entityUser || affectedEntity.entityEmail || null,
                operatingSystem: affectedEntity.operatingSystem || null,
                osVersion: affectedEntity.osVersion || null,
                complianceState: affectedEntity.complianceState || null,
                encryptionState: affectedEntity.encryptionState || null,
                managementState: affectedEntity.managementState || null,
                lastSyncDateTime: affectedEntity.lastSyncDateTime || null,
                riskLevel: affectedEntity.riskLevel || null,
                publisherName: affectedEntity.publisherName || null,
                severity: affectedEntity.severity || row.item?.severity || null,
                businessReason: affectedEntity.businessReason || row.item?.businessReason || row.item?.businessImpact || row.item?.whyItMatters || null,
                recommendation: affectedEntity.recommendation || row.item?.recommendation || row.item?.recommendedAction || row.item?.detail || null,
                sourceDomain: affectedEntity.sourceDomain || row.item?.sourceDomain || row.domainKey,
                sourceMetric: affectedEntity.sourceMetric || row.item?.sourceMetric || null,
                internalSourcePath: affectedEntity.internalSourcePath || null,
                affectedEntity
            };
        }));
        const EvidenceRows = evidenceBearingRows.flatMap(row => array(row.item?.evidenceRows).map((value, index) => {
            const evidenceRow = canonicalEntity(value, row.item) || {};
            return {
                companyId: row.companyId,
                runId: row.runId,
                snapshotId: row.snapshotId,
                domainKey: row.domainKey,
                riskId: row.itemType === 'risk' ? relationshipId(row, 'risk') : (row.item?.riskId || null),
                evidenceId: evidenceRow.entityId || `${row.runId}:${row.domainKey}:${row.itemType}:${row.rowNumber}:evidence:${index + 1}`,
                itemType: row.itemType,
                itemTitle: row.item?.title || row.item?.metricName || null,
                rowNumber: index + 1,
                entityId: evidenceRow.entityId || null,
                entityName: evidenceRow.entityName || null,
                entityType: evidenceRow.entityType || 'Entity',
                entityDeviceName: evidenceRow.entityDeviceName || null,
                assignedUser: evidenceRow.assignedUser || evidenceRow.entityUser || evidenceRow.entityEmail || null,
                operatingSystem: evidenceRow.operatingSystem || null,
                osVersion: evidenceRow.osVersion || null,
                complianceState: evidenceRow.complianceState || null,
                encryptionState: evidenceRow.encryptionState || null,
                managementState: evidenceRow.managementState || null,
                lastSyncDateTime: evidenceRow.lastSyncDateTime || null,
                riskLevel: evidenceRow.riskLevel || null,
                evidenceSource: row.item?.evidenceSource || null,
                sourceDomain: evidenceRow.sourceDomain || row.item?.sourceDomain || row.domainKey,
                sourceMetric: evidenceRow.sourceMetric || row.item?.sourceMetric || null,
                businessReason: evidenceRow.businessReason || row.item?.businessReason || row.item?.businessImpact || null,
                recommendation: evidenceRow.recommendation || row.item?.recommendation || row.item?.recommendedAction || null,
                internalSourcePath: evidenceRow.internalSourcePath || null,
                evidenceRow
            };
        }));
        const TokenUsageRows = reportableDomains.map(domain => ({ companyId: domain.companyId, snapshotId: domain.snapshotId, runId: domain.runId, domainKey: domain.domainKey, ...domain.tokenUsage }));
        const domainRowsByKey = new Map(domains.map(domain => [domain.domainKey, domain]));
        const activeDomainRows = ACTIVE_ENTERPRISE_DOMAIN_KEYS.map(key => domainRowsByKey.get(key)).filter(Boolean);
        const latestRunForDomain = domain => domain?.createdAt || domain?.periodEnd || domain?.periodStart || null;
        const warningValues = domain => [
            ...array(domain?.intelligenceOutput?.missingDataWarnings),
            ...array(domain?.evidenceLimitations?.missingDataWarnings),
            ...(domain?.errorMessage ? [domain.errorMessage] : [])
        ].map(String).filter(Boolean);
        const domainCounts = domain => {
            const output = domain?.intelligenceOutput || {};
            const limitations = output.evidenceLimitations || domain?.evidenceLimitations || {};
            const batch = output.batchInfo || domain?.batchInfo || {};
            const warnings = warningValues(domain);
            return {
                totalStackCTRLRows: numberOrNull(limitations.totalStackCTRLRows ?? limitations.stackctrlRows ?? limitations.recordsPrepared),
                preparedRows: numberOrNull(limitations.recordsPrepared ?? limitations.preparedRows),
                analysedRows: numberOrNull(limitations.recordsSent ?? limitations.analysedRows),
                omittedRows: numberOrNull(limitations.recordsOmitted ?? limitations.omittedRows),
                affectedEntityCount: AffectedEntityRows.filter(row => row.domainKey === domain?.domainKey).length,
                riskCount: array(output.risks).length,
                recommendationCount: array(output.recommendations).length,
                evidenceRowCount: EvidenceRows.filter(row => row.domainKey === domain?.domainKey).length,
                warningCount: warnings.length,
                batchCount: numberOrNull(batch.totalBatches ?? batch.batchCount),
                completedBatchCount: numberOrNull(batch.completedBatches ?? batch.completedBatchCount),
                failedBatchCount: numberOrNull(batch.failedBatches ?? batch.failedBatchCount),
                jsonStatus: batch.jsonStatus || (batch.jsonRecoveryWarning ? 'recovered' : null)
            };
        };
        const sourceFreshnessForDomain = domain => {
            const sourceHealth = domain?.intelligenceOutput?.sourceHealth || {};
            const lineage = domain?.intelligenceOutput?.sourceLineage || {};
            return {
                sourceFreshnessStatus: sourceHealth.status || sourceHealth.freshnessStatus || null,
                sourceLastUpdated: sourceHealth.sourceLastUpdated || sourceHealth.lastUpdated || lineage.sourceLastUpdated || lineage.sourceFetchedAt || null
            };
        };
        const DomainStatusRows = ENTERPRISE_DOMAINS.map(domainDef => {
            if (isTemporarilyDisabledDomain(domainDef.key)) {
                return compactNonEmptyObject({
                    domainKey: domainDef.key,
                    domainName: domainDef.name,
                    domainStatus: 'temporarily_disabled',
                    selectable: false,
                    includedInCurrentPhase: false,
                    message: TEMPORARILY_DISABLED_DOMAIN_MESSAGE
                });
            }
            const domain = domainRowsByKey.get(domainDef.key);
            const counts = domainCounts(domain);
            const freshness = sourceFreshnessForDomain(domain);
            return compactNonEmptyObject({
                companyId: domain?.companyId,
                snapshotId: domain?.snapshotId,
                runId: domain?.runId,
                domainKey: domainDef.key,
                domainName: domainDef.name,
                domainStatus: domain?.status || 'pending',
                selectable: true,
                includedInCurrentPhase: true,
                healthScore: numberOrNull(domain?.intelligenceOutput?.healthScore ?? domain?.intelligenceOutput?.score ?? domain?.intelligenceOutput?.scoreSummary?.healthScore),
                riskScore: numberOrNull(domain?.intelligenceOutput?.riskScore ?? domain?.intelligenceOutput?.scoreSummary?.riskScore),
                maturityScore: numberOrNull(domain?.intelligenceOutput?.maturityScore ?? domain?.intelligenceOutput?.maturityAssessment?.score),
                ...counts,
                ...freshness,
                inputTokens: numberOrNull(domain?.tokenUsage?.inputTokens),
                outputTokens: numberOrNull(domain?.tokenUsage?.outputTokens),
                totalTokens: numberOrNull(domain?.tokenUsage?.totalTokens),
                latestRunId: domain?.runId,
                latestSnapshotId: domain?.snapshotId,
                latestRunTime: latestRunForDomain(domain)
            });
        });
        const DomainCompletenessRows = DomainStatusRows.map(row => compactNonEmptyObject({
            domainKey: row.domainKey,
            domainName: row.domainName,
            domainStatus: row.domainStatus,
            includedInCurrentPhase: row.includedInCurrentPhase,
            preparedRows: row.preparedRows,
            analysedRows: row.analysedRows,
            omittedRows: row.omittedRows,
            riskCount: row.riskCount,
            recommendationCount: row.recommendationCount,
            evidenceRowCount: row.evidenceRowCount,
            complete: row.domainStatus === 'completed' || row.domainStatus === 'completed_with_warnings' || row.domainStatus === 'partial' || row.domainStatus === 'temporarily_disabled'
        }));
        const SourceFreshnessRows = activeDomainRows.map(domain => compactNonEmptyObject({
            companyId: domain.companyId,
            snapshotId: domain.snapshotId,
            runId: domain.runId,
            domainKey: domain.domainKey,
            domainName: domain.domainName,
            ...sourceFreshnessForDomain(domain)
        }));
        const WarningSummaryRows = activeDomainRows.flatMap(domain => warningValues(domain).map((warning, index) => compactNonEmptyObject({
            companyId: domain.companyId,
            snapshotId: domain.snapshotId,
            runId: domain.runId,
            domainKey: domain.domainKey,
            domainName: domain.domainName,
            warningNumber: index + 1,
            warning
        })));
        const BatchTelemetryRows = activeDomainRows.map(domain => {
            const batch = domain.intelligenceOutput?.batchInfo || domain.batchInfo || {};
            return compactNonEmptyObject({
                companyId: domain.companyId,
                snapshotId: domain.snapshotId,
                runId: domain.runId,
                domainKey: domain.domainKey,
                domainName: domain.domainName,
                batchCount: numberOrNull(batch.totalBatches ?? batch.batchCount),
                completedBatchCount: numberOrNull(batch.completedBatches ?? batch.completedBatchCount),
                failedBatchCount: numberOrNull(batch.failedBatches ?? batch.failedBatchCount),
                jsonStatus: batch.jsonStatus || (batch.jsonRecoveryWarning ? 'recovered' : null),
                inputTokens: numberOrNull(domain.tokenUsage?.inputTokens),
                outputTokens: numberOrNull(domain.tokenUsage?.outputTokens),
                totalTokens: numberOrNull(domain.tokenUsage?.totalTokens)
            });
        });
        const DomainLimitationsRows = activeDomainRows.flatMap(domain => array(domain.intelligenceOutput?.limitationsAndAssumptions || domain.evidenceLimitations?.limitations || domain.evidenceLimitations?.missingDataWarnings).map((limitation, index) => compactNonEmptyObject({
            companyId: domain.companyId,
            snapshotId: domain.snapshotId,
            runId: domain.runId,
            domainKey: domain.domainKey,
            domainName: domain.domainName,
            limitationNumber: index + 1,
            limitation: typeof limitation === 'string' ? limitation : JSON.stringify(sanitizeVisibleValue(limitation))
        })));
        const DomainScorecardPhaseRows = DomainStatusRows.map(row => compactNonEmptyObject({
            domainKey: row.domainKey,
            domainName: row.domainName,
            domainStatus: row.domainStatus,
            healthScore: row.healthScore,
            riskScore: row.riskScore,
            maturityScore: row.maturityScore,
            includedInCurrentPhase: row.includedInCurrentPhase,
            selectable: row.selectable,
            message: row.message
        }));
        const DisabledDomainRows = disabledDomainStates().map(domain => compactNonEmptyObject(domain));
        const finalOutput = finalSynthesis?.synthesisOutput || {};
        const finalBase = {
            companyId: finalSynthesis?.companyId || domains[0]?.companyId || null,
            runId: finalSynthesis?.runId || domains[0]?.runId || null,
            snapshotId: finalSynthesis?.snapshotId || domains[0]?.snapshotId || null,
            periodType: finalSynthesis?.periodType || domains[0]?.periodType || null,
            createdAt: finalSynthesis?.createdAt || domains[0]?.createdAt || null
        };
        const asText = (value, maximum = 1200) => visibleTextOrNull(value, maximum);
        const sourceDomainsText = item => array(item?.sourceDomains || item?.activeDomainsUsed || item?.sourceDomainsUsed)
            .map(value => textOrNull(value, 80))
            .filter(Boolean)
            .join(', ') || textOrNull(item?.sourceDomain || item?.domainKey, 80);
        const finalItemBase = (item, index) => compactNonEmptyObject({
            ...finalBase,
            rowNumber: index + 1,
            domainKey: textOrNull(item?.domainKey || item?.sourceDomain, 80),
            sourceDomains: sourceDomainsText(item),
            priority: textOrNull(item?.priority || item?.priorityRank, 80),
            riskLevel: textOrNull(item?.riskLevel || item?.severity, 80),
            severity: textOrNull(item?.severity, 80),
            title: asText(item?.title || item?.decision || item?.action || item?.metricName, 255),
            businessImpact: asText(item?.businessImpact || item?.businessReason || item?.riskIfDelayed, 1000),
            recommendedAction: asText(item?.recommendedAction || item?.action || item?.decision, 1000),
            managementDecisionRequired: asText(item?.managementDecisionRequired || item?.decision || item?.whyRequired, 1000),
            evidenceConfidence: textOrNull(item?.evidenceConfidence || item?.confidence, 80)
        });
        const finalRows = (items, mapper) => array(items).map((item, index) => stripInternalPowerBIFields(compactNonEmptyObject({
            ...finalItemBase(item, index),
            ...mapper(item, index)
        })));
        const FinalSummaryRows = finalSynthesis ? [stripInternalPowerBIFields(compactNonEmptyObject({
            ...finalBase,
            title: asText(finalOutput.enterpriseExecutiveSummary?.primaryEnterpriseConcern || finalOutput.powerBiSummary?.finalReportTitle || 'Enterprise Final Intelligence Report', 255),
            summary: asText(finalOutput.enterpriseExecutiveSummary?.summary, 1800),
            enterpriseRiskNarrative: asText(finalOutput.enterpriseExecutiveSummary?.enterpriseRiskNarrative, 1800),
            overallPosture: textOrNull(finalOutput.enterpriseExecutiveSummary?.overallPosture, 80),
            primaryEnterpriseConcern: asText(finalOutput.enterpriseExecutiveSummary?.primaryEnterpriseConcern, 1000),
            mostImportantAction: asText(finalOutput.enterpriseExecutiveSummary?.mostImportantAction, 1000),
            businessImpact: asText(finalOutput.businessImpactSummary, 1800),
            evidenceConfidence: textOrNull(finalOutput.enterpriseExecutiveSummary?.confidence || finalOutput.evidenceJustificationSummary?.evidenceConfidence, 80),
            activeDomainsUsed: array(finalOutput.enterpriseExecutiveSummary?.activeDomainsUsed).join(', ')
        }))] : [];
        const FinalBoardReportRows = finalSynthesis ? [stripInternalPowerBIFields(compactNonEmptyObject({
            ...finalBase,
            title: 'Board report',
            summary: asText(finalOutput.boardReport?.boardSummary, 1800),
            messageToBoard: asText(finalOutput.boardReport?.messageToBoard, 1800),
            riskLevel: textOrNull(finalOutput.boardReport?.riskLevel, 80),
            riskScore: numberOrNull(finalOutput.boardReport?.riskScore),
            boardRisks: array(finalOutput.boardReport?.boardRisks).map(item => asText(item, 240)).filter(Boolean).join(' | '),
            boardActions: array(finalOutput.boardReport?.boardActions).map(item => asText(item, 240)).filter(Boolean).join(' | '),
            managementDecisionRequired: array(finalOutput.boardReport?.decisionsRequired).map(item => asText(item, 240)).filter(Boolean).join(' | ')
        }))] : [];
        const FinalEnterpriseRiskRows = finalRows(finalOutput.riskRegister, (item, index) => ({
            riskId: textOrNull(item?.riskId || `enterprise-risk-${index + 1}`, 120),
            priorityRank: numberOrNull(item?.priorityRank) || index + 1,
            enterpriseTheme: asText(item?.enterpriseTheme, 255),
            description: asText(item?.description || item?.whyItMatters, 1200),
            impact: asText(item?.impact, 800)
        }));
        const FinalRecommendationRows = finalRows(finalOutput.recommendations, (item, index) => ({
            recommendationId: textOrNull(item?.recommendationId || `enterprise-rec-${index + 1}`, 120),
            suggestedOwner: textOrNull(item?.suggestedOwner || item?.recommendedOwner, 180),
            suggestedDueDate: normalizeMysqlDate(item?.suggestedDueDate),
            dependsOn: array(item?.dependsOn).join(', '),
            businessReason: asText(item?.businessReason, 1000)
        }));
        const FinalCrossDomainRiskChainRows = finalRows(finalOutput.managementReport?.crossDomainRiskChains, (item, index) => ({
            chainId: textOrNull(item?.chainId || `chain-${index + 1}`, 120),
            enterpriseTheme: asText(item?.enterpriseTheme, 255),
            linkedFindings: array(item?.linkedFindings).map(value => asText(value, 160)).filter(Boolean).join(' | '),
            whyItMatters: asText(item?.whyItMatters, 1000)
        }));
        const FinalDecisionRows = finalRows(finalOutput.topDecisionsRequired, (item, index) => ({
            decisionId: textOrNull(item?.decisionId || `decision-${index + 1}`, 120),
            whyRequired: asText(item?.whyRequired, 1000),
            riskIfDelayed: asText(item?.riskIfDelayed, 1000),
            recommendedOwner: textOrNull(item?.recommendedOwner, 180),
            recommendedTimeline: textOrNull(item?.recommendedTimeline, 180)
        }));
        const finalPlanRows = (items, planWindow) => finalRows(items, (item, index) => ({
            planWindow,
            actionId: textOrNull(item?.actionId || item?.planId || `${planWindow}-${index + 1}`, 120),
            owner: textOrNull(item?.owner || item?.recommendedOwner || item?.suggestedOwner, 180),
            timeline: textOrNull(item?.timeline || item?.recommendedTimeline, 180),
            status: textOrNull(item?.status, 80)
        }));
        const Final30DayPlanRows = finalPlanRows(finalOutput.next30DaysPlan, '30_day');
        const Final90DayPlanRows = finalPlanRows(finalOutput.next90DaysPlan, '90_day');
        const FinalDomainScorecardRows = finalRows(finalOutput.domainScorecard, item => ({
            domainName: textOrNull(item?.domainName, 180),
            domainStatus: textOrNull(item?.status || item?.domainStatus, 80),
            healthScore: numberOrNull(item?.healthScore),
            riskScore: numberOrNull(item?.riskScore),
            executiveInterpretation: asText(item?.executiveInterpretation, 1000),
            contributionToEnterpriseRisk: asText(item?.contributionToEnterpriseRisk, 1000),
            includedInFinalSynthesis: item?.includedInFinalSynthesis == null ? null : Boolean(item.includedInFinalSynthesis)
        }));
        const FinalComplianceGovernanceRows = finalSynthesis ? ['complianceReview', 'governanceReview'].map(section => {
            const item = finalOutput[section] || {};
            return stripInternalPowerBIFields(compactNonEmptyObject({
                ...finalBase,
                section,
                title: section === 'complianceReview' ? 'Compliance readiness' : 'Governance readiness',
                status: textOrNull(item.auditReadinessStatus || item.ownershipReadiness || item.decisionReadiness, 120),
                summary: asText(item.complianceNarrative || item.governanceNarrative, 1800),
                businessImpact: asText(item.managementImpact, 1200),
                recommendedAction: array(item.priorityComplianceActions || item.priorityGovernanceActions).map(value => asText(value, 240)).filter(Boolean).join(' | '),
                evidenceGaps: array(item.evidenceGaps || item.policyOrReviewGaps || item.accountabilityGaps).map(value => asText(value, 240)).filter(Boolean).join(' | ')
            }));
        }) : [];
        const FinalEvidenceConfidenceRows = finalSynthesis ? [stripInternalPowerBIFields(compactNonEmptyObject({
            ...finalBase,
            evidenceConfidence: textOrNull(finalOutput.evidenceJustificationSummary?.evidenceConfidence, 80),
            sourceDomains: array(finalOutput.evidenceJustificationSummary?.sourceDomainsUsed).join(', '),
            evidenceUsed: array(finalOutput.evidenceJustificationSummary?.evidenceUsed).map(value => asText(value, 240)).filter(Boolean).join(' | '),
            evidenceGaps: array(finalOutput.evidenceJustificationSummary?.evidenceGaps).map(value => asText(value, 240)).filter(Boolean).join(' | '),
            summary: asText(finalOutput.evidenceJustificationSummary?.whyThisSynthesisIsReliable, 1800),
            limitations: array(finalOutput.evidenceJustificationSummary?.knownLimitations).map(value => asText(value, 240)).filter(Boolean).join(' | ')
        }))] : [];
        const FinalLimitationRows = finalRows(finalOutput.limitationsAndAssumptions, (item, index) => ({
            limitationNumber: index + 1,
            limitation: typeof item === 'string' ? asText(item, 1000) : asText(item?.limitation || item?.assumption || JSON.stringify(stripInternalPowerBIFields(sanitizeVisibleValue(item))), 1000)
        }));
        const FinalPowerBISummaryRows = finalSynthesis ? [stripInternalPowerBIFields(compactNonEmptyObject({
            ...finalBase,
            title: asText(finalOutput.powerBiSummary?.finalReportTitle || 'Enterprise Final Intelligence Report', 255),
            purpose: asText(finalOutput.powerBiSummary?.finalReportPurpose, 1200),
            headlineKpis: array(finalOutput.powerBiSummary?.headlineKpis).map(value => asText(value, 240)).filter(Boolean).join(' | '),
            primarySlicers: array(finalOutput.powerBiSummary?.primarySlicers).join(', '),
            readyForPowerBI: finalOutput.powerBiSummary?.readyForPowerBI == null ? null : Boolean(finalOutput.powerBiSummary.readyForPowerBI)
        }))] : [];
        return {
            FinalSummaryRows,
            FinalBoardReportRows,
            FinalEnterpriseRiskRows,
            FinalRecommendationRows,
            FinalCrossDomainRiskChainRows,
            FinalDecisionRows,
            Final30DayPlanRows,
            Final90DayPlanRows,
            FinalDomainScorecardRows,
            FinalComplianceGovernanceRows,
            FinalEvidenceConfidenceRows,
            FinalLimitationRows,
            FinalPowerBISummaryRows,
            DomainScorecardRows,
            DomainStatusRows,
            DomainCompletenessRows,
            RiskRegisterRows,
            RecommendationRows,
            AffectedEntityRows,
            EvidenceRows,
            SourceFreshnessRows,
            WarningSummaryRows,
            BatchTelemetryRows,
            TokenUsageRows,
            RunHistoryRows: runs,
            DisabledDomainRows,
            DomainLimitationsRows,
            ControlAssessmentRows,
            TrendRows,
            AuditCompletenessRows: audits.map(powerBIAuditRow),
            final_summary: FinalSummaryRows,
            final_board_report: FinalBoardReportRows,
            final_enterprise_risks: FinalEnterpriseRiskRows,
            final_recommendations: FinalRecommendationRows,
            final_cross_domain_risk_chains: FinalCrossDomainRiskChainRows,
            final_decisions_required: FinalDecisionRows,
            final_30_day_plan: Final30DayPlanRows,
            final_90_day_plan: Final90DayPlanRows,
            final_domain_scorecard: FinalDomainScorecardRows,
            final_compliance_governance_readiness: FinalComplianceGovernanceRows,
            final_evidence_confidence: FinalEvidenceConfidenceRows,
            final_limitations: FinalLimitationRows,
            final_powerbi_summary: FinalPowerBISummaryRows,
            domain_scorecard: DomainScorecardPhaseRows,
            domain_status: DomainStatusRows,
            domain_completeness: DomainCompletenessRows,
            risk_register: RiskRegisterRows,
            recommendations: RecommendationRows,
            affected_entities: AffectedEntityRows,
            evidence_rows: EvidenceRows,
            source_freshness: SourceFreshnessRows,
            warning_summary: WarningSummaryRows,
            batch_telemetry: BatchTelemetryRows,
            token_usage: TokenUsageRows,
            run_history: runs,
            disabled_domains: DisabledDomainRows,
            domain_limitations: DomainLimitationsRows
        };
    }

    async function getPowerBIIntelligenceRun(companyId, runId = null, { periodType = null, publishedOnly = false } = {}) {
        const numericCompanyId = Number(companyId);
        const params = [numericCompanyId];
        let where = 'runs.CompanyID = ?';
        let reportJoin = '';
        let orderBy = 'runs.ID DESC';
        if (runId) {
            where += ' AND runs.ID = ?';
            params.push(Number(runId));
        } else {
            where += ` AND runs.Status IN ('completed', 'completed_with_warnings')
                       AND (
                           SELECT COUNT(DISTINCT completedDomain.DomainKey)
                           FROM StackCTRLTenantDomainIntelligence completedDomain
                           WHERE completedDomain.RunID = runs.ID
                             AND completedDomain.DomainKey IN (${ACTIVE_ENTERPRISE_DOMAIN_KEYS.map(() => '?').join(',')})
                             AND completedDomain.Status IN ('completed', 'completed_with_warnings', 'partial')
                       ) >= ?`;
            params.push(...ACTIVE_ENTERPRISE_DOMAIN_KEYS, ACTIVE_ENTERPRISE_DOMAIN_KEYS.length);
            if (publishedOnly) {
                reportJoin = ` JOIN SunbirdReports publishedReport
                    ON publishedReport.CompanyID = runs.CompanyID
                   AND publishedReport.EnterpriseRunID = runs.ID
                   AND publishedReport.ReportType = 'daily'
                   AND publishedReport.IsCurrent = 1 `;
                orderBy = 'COALESCE(publishedReport.PublishedAt, publishedReport.CreatedAt) DESC, runs.ID DESC';
            }
        }
        if (periodType) { where += ' AND runs.PeriodType = ?'; params.push(String(periodType)); }
        const [runRows] = await pool.query(`SELECT runs.* FROM StackCTRLEnterpriseReportRuns runs${reportJoin} WHERE ${where} ORDER BY ${orderBy} LIMIT 1`, params);
        const run = runRows[0];
        if (!run) {
            const error = new Error('Enterprise intelligence run not found');
            error.statusCode = 404;
            throw error;
        }
        const [[domainRows], [synthesisRows], [auditRows]] = await Promise.all([
            pool.query('SELECT * FROM StackCTRLTenantDomainIntelligence WHERE CompanyID = ? AND RunID = ? ORDER BY ID', [numericCompanyId, run.ID]),
            pool.query('SELECT * FROM StackCTRLEnterpriseSynthesis WHERE CompanyID = ? AND RunID = ? ORDER BY ID DESC LIMIT 1', [numericCompanyId, run.ID]),
            pool.query('SELECT * FROM StackCTRLIntelligenceEvidenceAudit WHERE CompanyID = ? AND RunID = ? ORDER BY DomainKey', [numericCompanyId, run.ID])
        ]);
        const domains = domainRows.map(powerBIDomainRow);
        const finalSynthesis = powerBISynthesisRow(synthesisRows[0]);
        const audits = auditRows.map(powerBIAuditRow);
        return {
            dataClassification: 'intelligent_azure_output',
            companyId: numericCompanyId,
            latestSnapshotId: run.SnapshotID == null ? null : Number(run.SnapshotID),
            latestRunId: Number(run.ID),
            periodType: run.PeriodType, periodStart: run.PeriodStart, periodEnd: run.PeriodEnd,
            createdAt: run.CreatedAt || run.StartedAt,
            reportingPhase: CURRENT_REPORTING_PHASE,
            domains,
            finalSynthesis,
            completeness: {
                expectedDomains: ACTIVE_ENTERPRISE_DOMAIN_KEYS.length,
                disabledDomainCount: TEMPORARILY_DISABLED_DOMAIN_KEYS.length,
                totalDefinedDomains: ENTERPRISE_DOMAINS.length,
                activeDomainKeys: ACTIVE_ENTERPRISE_DOMAIN_KEYS,
                disabledDomains: disabledDomainStates(),
                returnedDomains: domains.length,
                successfulDomains: domains.filter(domain => isSuccessfulDomainStatus(domain.status)).length,
                recordsSent: audits.reduce((total, audit) => total + Number(audit.SentToAzureCount || 0), 0),
                recordsOmitted: audits.reduce((total, audit) => total + Number(audit.OmittedCount || 0) + Number(audit.EvidenceOmittedCount || 0), 0),
                audits
            },
            tables: flattenPowerBITables({ domains, finalSynthesis, audits, runs: [powerBIRunRow(run)].filter(Boolean) })
        };
    }

    async function getPowerBIDomain(companyId, domainKey, { runId = null, periodType = null, queryTimeoutMs = 0 } = {}) {
        if (!DOMAIN_BY_KEY[domainKey]) {
            const error = new Error(`Unsupported enterprise domain: ${domainKey}`);
            error.statusCode = 400;
            throw error;
        }
        if (isTemporarilyDisabledDomain(domainKey)) {
            return {
                dataClassification: 'intelligent_azure_output',
                reportingPhase: CURRENT_REPORTING_PHASE,
                domain: disabledDomainState(domainKey)
            };
        }
        const params = [Number(companyId), domainKey];
        let where = 'CompanyID = ? AND DomainKey = ?';
        if (runId) { where += ' AND RunID = ?'; params.push(Number(runId)); }
        else where += ` AND Status IN ('completed', 'completed_with_warnings', 'partial')`;
        if (periodType) { where += ' AND PeriodType = ?'; params.push(String(periodType)); }
        const sql = `SELECT * FROM StackCTRLTenantDomainIntelligence WHERE ${where} ORDER BY ID DESC LIMIT 1`;
        const [rows] = await pool.query(
            queryTimeoutMs > 0 ? { sql, timeout: Math.max(1, Number(queryTimeoutMs)) } : sql,
            params
        );
        if (!rows[0]) { const error = new Error('Domain intelligence output not found'); error.statusCode = 404; throw error; }
        return { dataClassification: 'intelligent_azure_output', domain: powerBIDomainRow(rows[0]) };
    }
    async function getPowerBIFinal(companyId, runId = null, { periodType = null, queryTimeoutMs = 0 } = {}) {
        const params = [Number(companyId)];
        let where = 'CompanyID = ?';
        if (runId) { where += ' AND RunID = ?'; params.push(Number(runId)); }
        else where += ` AND Status IN ('completed', 'completed_with_warnings')`;
        if (periodType) { where += ' AND PeriodType = ?'; params.push(String(periodType)); }
        const sql = `SELECT * FROM StackCTRLEnterpriseSynthesis WHERE ${where} ORDER BY ID DESC LIMIT 1`;
        const [rows] = await pool.query(
            queryTimeoutMs > 0 ? { sql, timeout: Math.max(1, Number(queryTimeoutMs)) } : sql,
            params
        );
        if (!rows[0]) {
            return {
                dataClassification: 'intelligent_azure_output',
                status: runId ? 'not_ready' : 'not_requested',
                reportingPhase: CURRENT_REPORTING_PHASE,
                finalSynthesis: null,
                limitations: ['Operations is temporarily disabled in this reporting phase. Governance and Compliance Validation are active and must be included in the final synthesis when their stored domain intelligence exists.'],
                message: 'Final enterprise synthesis is not primary for the current reporting phase; validated per-domain intelligence is the active Power BI focus.'
            };
        }
        return { dataClassification: 'intelligent_azure_output', status: rows[0].Status || 'available', reportingPhase: CURRENT_REPORTING_PHASE, limitations: ['Operations is temporarily disabled in this reporting phase. Governance and Compliance Validation are active and must be included in the final synthesis when their stored domain intelligence exists.'], finalSynthesis: powerBISynthesisRow(rows[0]) };
    }
    async function getPowerBIRaw(companyId, domainKey = null) {
        if (domainKey && !DOMAIN_BY_KEY[domainKey]) { const error = new Error(`Unsupported enterprise domain: ${domainKey}`); error.statusCode = 400; throw error; }
        const [rows] = await pool.query('SELECT * FROM StackCTRLTenantEvidenceSnapshots WHERE CompanyID = ? ORDER BY ID DESC LIMIT 1', [Number(companyId)]);
        const snapshot = rows[0];
        if (!snapshot) { const error = new Error('StackCTRL evidence snapshot not found'); error.statusCode = 404; throw error; }
        const context = parseJson(snapshot.ContextJson, {});
        const sources = array(context.sources);
        const selectedSources = domainKey ? sources.filter(source => source.sourceKey === DOMAIN_BY_KEY[domainKey].sourceKey) : sources;
        return {
            dataClassification: 'raw_non_intelligent_stackctrl',
            warning: 'Raw StackCTRL evidence. This payload has not been analysed by Azure OpenAI.',
            companyId: Number(companyId), snapshotId: Number(snapshot.ID), runId: null,
            periodType: snapshot.SnapshotType || 'snapshot', periodStart: snapshot.PeriodStart || null,
            periodEnd: snapshot.PeriodEnd || null, createdAt: snapshot.CreatedAt,
            domainKey: domainKey || null,
            rawStackCTRLData: domainKey ? selectedSources[0] || null : { metrics: parseJson(snapshot.MetricsJson, {}), sources: selectedSources }
        };
    }

    function powerBIDomainHistoryRow(row) {
        if (!row) return null;
        return stripInternalPowerBIFields(compactNonEmptyObject({
            domainIntelligenceId: row.ID == null ? null : Number(row.ID),
            companyId: row.CompanyID == null ? null : Number(row.CompanyID),
            snapshotId: row.SnapshotID == null ? null : Number(row.SnapshotID),
            runId: row.RunID == null ? null : Number(row.RunID),
            domainKey: row.DomainKey || null,
            domainName: row.DomainName || null,
            periodType: row.PeriodType || null,
            periodStart: row.PeriodStart || null,
            periodEnd: row.PeriodEnd || null,
            createdAt: row.CreatedAt || null,
            status: row.Status || null,
            healthScore: numberOrNull(row.HealthScore),
            riskScore: numberOrNull(row.RiskScore),
            riskLevel: row.RiskLevel || null,
            confidenceScore: numberOrNull(row.ConfidenceScore),
            domainExecutiveSummary: visibleTextOrNull(row.DomainExecutiveSummary, 1600),
            technicalSummary: visibleTextOrNull(row.TechnicalSummary, 1600),
            businessImpact: visibleTextOrNull(row.BusinessImpact, 1200),
            currentPosture: visibleTextOrNull(row.CurrentPosture, 1200),
            evidenceSummary: visibleTextOrNull(row.EvidenceSummary, 1200),
            scoreJustification: visibleTextOrNull(row.ScoreJustification, 1200),
            errorMessage: visibleTextOrNull(row.ErrorMessage, 1000),
            tokenUsage: {
                inputTokens: Number(row.InputTokens || 0),
                outputTokens: Number(row.OutputTokens || 0),
                totalTokens: Number(row.TotalTokens || 0),
                retryCount: Number(row.RetryCount || 0)
            }
        }));
    }

    function powerBISynthesisHistoryRow(row) {
        if (!row) return null;
        const powerBiSummary = parseJson(row.PowerBISummaryJson, {});
        return stripInternalPowerBIFields(compactNonEmptyObject({
            synthesisId: row.ID == null ? null : Number(row.ID),
            companyId: row.CompanyID == null ? null : Number(row.CompanyID),
            snapshotId: row.SnapshotID == null ? null : Number(row.SnapshotID),
            runId: row.RunID == null ? null : Number(row.RunID),
            periodType: row.PeriodType || null,
            periodStart: row.PeriodStart || null,
            periodEnd: row.PeriodEnd || null,
            createdAt: row.CreatedAt || null,
            status: row.Status || null,
            title: visibleTextOrNull(powerBiSummary.finalReportTitle || powerBiSummary.title, 255),
            purpose: visibleTextOrNull(powerBiSummary.finalReportPurpose || powerBiSummary.purpose, 1200),
            businessImpactSummary: visibleTextOrNull(row.BusinessImpactSummary, 1600),
            tokenUsage: {
                inputTokens: Number(row.InputTokens || 0),
                outputTokens: Number(row.OutputTokens || 0),
                totalTokens: Number(row.TotalTokens || 0),
                retryCount: Number(row.RetryCount || 0)
            }
        }));
    }
    async function getPowerBIHistory(companyId, { periodType = null, limit = 25 } = {}) {
        const numericCompanyId = Number(companyId);
        const requestedLimit = Math.min(100, Math.max(1, Number(limit) || 25));
        const params = [numericCompanyId];
        const periodFilter = periodType ? ' AND PeriodType = ?' : '';
        if (periodType) params.push(String(periodType));
        params.push(requestedLimit);
        const [runs] = await pool.query(
            `SELECT ID, CompanyID, SnapshotID, PeriodType, PeriodStart, PeriodEnd, Status, ProgressJson,
                    TotalInputTokens, TotalOutputTokens, TotalTokens, RetryCount, StartedAt, CompletedAt, CreatedAt, ErrorMessage
             FROM StackCTRLEnterpriseReportRuns
             WHERE CompanyID = ?${periodFilter}
             ORDER BY ID DESC
             LIMIT ?`,
            params
        );
        const runIds = runs.map(run => Number(run.ID)).filter(Boolean);
        if (!runIds.length) return { dataClassification: 'intelligent_azure_output', companyId: numericCompanyId, periodType: periodType || 'all', reportingPhase: CURRENT_REPORTING_PHASE, activeDomainKeys: ACTIVE_ENTERPRISE_DOMAIN_KEYS, disabledDomains: disabledDomainStates(), runs: [], domains: [], finalSyntheses: [] };
        const placeholders = runIds.map(() => '?').join(',');
        const [[domainRows], [synthesisRows]] = await Promise.all([
            pool.query(`SELECT ID, CompanyID, SnapshotID, RunID, DomainKey, DomainName, PeriodType, PeriodStart, PeriodEnd,
                               HealthScore, RiskScore, RiskLevel, InputTokens, OutputTokens, TotalTokens, RetryCount,
                               Status, DomainExecutiveSummary, TechnicalSummary, BusinessImpact, CurrentPosture,
                               EvidenceSummary, ScoreJustification, ConfidenceScore, ErrorMessage, CreatedAt
                        FROM StackCTRLTenantDomainIntelligence
                        WHERE CompanyID = ? AND RunID IN (${placeholders})
                        ORDER BY RunID DESC, ID`, [numericCompanyId, ...runIds]),
            pool.query(`SELECT ID, CompanyID, SnapshotID, RunID, PeriodType, PeriodStart, PeriodEnd, Status,
                               BusinessImpactSummary, PowerBISummaryJson, InputTokens, OutputTokens, TotalTokens,
                               RetryCount, CreatedAt
                        FROM StackCTRLEnterpriseSynthesis
                        WHERE CompanyID = ? AND RunID IN (${placeholders})
                        ORDER BY RunID DESC, ID DESC`, [numericCompanyId, ...runIds])
        ]);
        return {
            dataClassification: 'intelligent_azure_output',
            companyId: numericCompanyId,
            periodType: periodType || 'all',
            reportingPhase: CURRENT_REPORTING_PHASE,
            activeDomainKeys: ACTIVE_ENTERPRISE_DOMAIN_KEYS,
            disabledDomains: disabledDomainStates(),
            limit: requestedLimit,
            runs: runs.map(powerBIRunRow).filter(Boolean),
            domains: domainRows.map(powerBIDomainHistoryRow).filter(Boolean),
            finalSyntheses: synthesisRows.map(powerBISynthesisHistoryRow).filter(Boolean)
        };
    }
    return {
        settings,
        domains: ENTERPRISE_DOMAINS.map(domain => ({ ...domain, ...enterpriseDomainDescriptor(domain) })),
        buildDomainPackage,
        buildDomainBatchPackage,
        runEnterpriseReport,
        runEnterpriseSynthesis,
        publishCompletedRun,
        runRollupReport,
        runScheduledTick,
        runDailyAutomationTick,
        getAdminData,
        getAdminProgress,
        getAdminDomainDetail,
        getAdminAuditDetail,
        getAdminBatchDetails,
        getAdminSynthesisDetail,
        getPowerBIIntelligenceRun,
        getPowerBIDomain,
        getPowerBIFinal,
        getPowerBIRaw,
        getPowerBIHistory,
        flattenPowerBITables
    };
}

module.exports = {
    ENTERPRISE_DOMAINS,
    DOMAIN_BY_KEY,
    ACTIVE_ENTERPRISE_DOMAIN_KEYS,
    TEMPORARILY_DISABLED_DOMAIN_KEYS,
    CURRENT_REPORTING_PHASE,
    IDENTITY_LINEAGE_FIELDS,
    DEVICE_LINEAGE_FIELDS,
    EMAIL_LINEAGE_FIELDS,
    NETWORK_LINEAGE_FIELDS,
    BACKUP_LINEAGE_FIELDS,
    APPLICATIONS_LINEAGE_FIELDS,
    SECURITY_LINEAGE_FIELDS,
    GOVERNANCE_LINEAGE_FIELDS,
    COMPLIANCE_LINEAGE_FIELDS,
    OPERATIONS_LINEAGE_FIELDS,
    DASHBOARD_BACKED_ENTERPRISE_DOMAINS,
    DOMAIN_EVIDENCE_TYPES,
    buildDataLineageComparison,
    buildDomainRunAudit,
    sourceAlignmentFailure,
    createEnterpriseIntelligenceService,
    flattenDomainEvidence,
    filterDomainEvidence,
    buildEvidenceCatalog,
    compactBackupEvidenceRows,
    compactGovernanceEvidenceRows,
    compactComplianceEvidenceRows,
    repairTruncatedJson,
    splitIntoBatches,
    securityAlertSemantics,
    splitSecurityAlertsIntoBatches,
    computeInterBatchDelayMs,
    computeInterDomainDelayMs,
    periodWindow,
    normalizeMysqlDate,
    normalizeEvidenceBackedItem,
    ensureItemEvidence,
    normalizeDomainOutputForDisplay,
    johannesburgScheduleContext
};
