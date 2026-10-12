const { getExplicitSecurityIocs } = require('./security-ioc');

function numberValue(value, fallback = 0) {
    if (value === null || value === undefined || value === '') return fallback;
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
}

function arrayValue(value) {
    return Array.isArray(value) ? value : [];
}

function firstValue(...values) {
    return values.find(value => value !== null && value !== undefined && value !== '') ?? null;
}

function textValue(value, max = 500) {
    if (value === null || value === undefined || value === '') return null;
    return String(value).trim().slice(0, max) || null;
}

function stableKey(type, value) {
    return `${String(type || '').toLowerCase()}:${String(value || '').toLowerCase().trim()}`;
}

function addIndicator(map, type, value, source = {}, extra = {}) {
    const cleanValue = textValue(value, 500);
    if (!cleanValue) return;

    const key = stableKey(type, cleanValue);
    const existing = map.get(key) || {
        id: key,
        indicatorType: type,
        indicator: cleanValue,
        value: cleanValue,
        severity: extra.severity || source.severity || 'medium',
        confidence: extra.confidence || 'medium',
        source: extra.source || 'internal_security_alerts',
        action: extra.action || 'Review',
        occurrenceCount: 0,
        relatedAlerts: [],
        relatedUsers: [],
        relatedDevices: []
    };

    existing.occurrenceCount += 1;

    const alertTitle = firstValue(source.title, source.alertName, source.displayName, source.name);
    const user = firstValue(source.userPrincipalName, source.userEmail, source.mail, source.email, source.user);
    const device = firstValue(source.deviceName, source.hostName, source.hostname, source.machineName, source.computerName);

    if (alertTitle && !existing.relatedAlerts.includes(alertTitle)) existing.relatedAlerts.push(alertTitle);
    if (user && !existing.relatedUsers.includes(user)) existing.relatedUsers.push(user);
    if (device && !existing.relatedDevices.includes(device)) existing.relatedDevices.push(device);

    existing.relatedAlerts = existing.relatedAlerts.slice(0, 5);
    existing.relatedUsers = existing.relatedUsers.slice(0, 5);
    existing.relatedDevices = existing.relatedDevices.slice(0, 5);

    map.set(key, existing);
}

function extractInternalThreatIndicators({ alerts = [], incidents = [], suspiciousSignIns = [] } = {}) {
    const indicatorMap = new Map();
    const rows = [...arrayValue(alerts), ...arrayValue(incidents), ...arrayValue(suspiciousSignIns)];

    for (const row of rows) {
        if (!row || typeof row !== 'object') continue;

        for (const { type, value } of getExplicitSecurityIocs(row)) {
            addIndicator(indicatorMap, type, value, row, {
                severity: row.severity || row.riskLevel || 'medium',
                confidence: 'medium'
            });
        }
    }

    return [...indicatorMap.values()]
        .sort((a, b) => b.occurrenceCount - a.occurrenceCount)
        .slice(0, 25);
}

function cleanSecurityWarnings(warnings = [], {
    hasAlertEvidence,
    hasIncidentEvidence,
    hasSignInEvidence,
    hasFindingEvidence = false,
    hasThreatIndicators
}) {
    const unique = [...new Set(arrayValue(warnings).map(warning => String(warning || '').trim()).filter(Boolean))];

    return unique.filter(warning => {
        const lower = warning.toLowerCase();

        if (lower.includes('threat indicators') || lower.includes('threat_indicators_unavailable')) {
            return !hasThreatIndicators;
        }

        if (lower.includes('alerts fetch failed') || lower.includes('alerts_unavailable')) {
            return !hasAlertEvidence;
        }

        if (lower.includes('incidents fetch failed') || lower.includes('incidents_unavailable')) {
            return !hasIncidentEvidence;
        }

        if (lower.includes('sign-ins fetch failed') || lower.includes('signins_unavailable')) {
            return !hasSignInEvidence;
        }

        if (lower === 'partial_source_collection' || lower.includes('partial_source_collection')) {
            return !(hasAlertEvidence || hasIncidentEvidence || hasSignInEvidence || hasFindingEvidence);
        }

        return true;
    });
}

function buildSecurityRecommendations(summary, evidence = {}) {
    const recs = [];

    if (numberValue(summary.highSeverityAlerts) > 0) {
        recs.push({
            priority: 'critical',
            title: 'Review high severity alerts',
            detail: `${summary.highSeverityAlerts} high or critical alert(s) need analyst review.`
        });
    }

    if (numberValue(summary.usersUnderAttack) > 0) {
        recs.push({
            priority: 'high',
            title: 'Investigate repeated suspicious sign-ins',
            detail: `${summary.usersUnderAttack} user(s) show repeated failed or risky access attempts.`
        });
    }

    if (numberValue(summary.activeIncidents) > 0) {
        recs.push({
            priority: 'high',
            title: 'Triage active incidents',
            detail: `${summary.activeIncidents} active incident(s) are still open.`
        });
    }

    if (numberValue(summary.threatIndicators) > 0) {
        recs.push({
            priority: 'medium',
            title: 'Validate threat indicators',
            detail: `${summary.threatIndicators} threat indicator(s) were extracted from alert evidence.`
        });
    }

    if (!recs.length) {
        recs.push({
            priority: 'low',
            title: 'Maintain SOC monitoring baseline',
            detail: 'No urgent security alert recommendations from current evidence.'
        });
    }

    return recs;
}

function buildSecurityDashboardSource({
    alertsRows = [],
    incidentsRows = [],
    threatsRows = [],
    suspiciousSignInsRows = [],
    findingsRows = [],
    scenarioCoverage = {},
    riskDetectionsRows = [],
    riskyUsersRows = [],
    summary = {},
    recommendations: inputRecommendations = null,
    warnings: inputWarnings = []
} = {}) {
    const alerts = arrayValue(alertsRows);
    const incidents = arrayValue(incidentsRows);
    const suspiciousSignIns = arrayValue(suspiciousSignInsRows);
    const findings = arrayValue(findingsRows);
    const riskDetections = arrayValue(riskDetectionsRows);
    const riskyUsers = arrayValue(riskyUsersRows);

    const internalThreats = extractInternalThreatIndicators({
        alerts,
        incidents,
        suspiciousSignIns
    });

    const externalThreats = arrayValue(threatsRows);
    const mergedThreatsByKey = new Map();

    for (const threat of [...externalThreats, ...internalThreats]) {
        const key = stableKey(
            threat.indicatorType || threat.type || 'Indicator',
            threat.indicator || threat.value || threat.indicatorValue || threat.id
        );
        if (!mergedThreatsByKey.has(key)) mergedThreatsByKey.set(key, threat);
    }

    const threats = [...mergedThreatsByKey.values()];

    const highSeverityAlerts = alerts.filter(alert =>
        ['critical', 'high'].includes(String(alert.severity || '').toLowerCase())
    ).length;

    const activeIncidents = incidents.filter(incident =>
        ['active', 'inprogress', 'newalert', 'new', 'open'].includes(String(incident.status || '').toLowerCase())
    ).length;

    const usersFromAlerts = new Set();
    for (const row of [...alerts, ...suspiciousSignIns]) {
        const user = firstValue(row.userPrincipalName, row.userEmail, row.mail, row.email, row.user);
        if (user) usersFromAlerts.add(user);
    }

    const usersUnderAttack = numberValue(
        summary.usersUnderAttack,
        Array.isArray(summary.usersUnderAttack) ? summary.usersUnderAttack.length : usersFromAlerts.size
    );

    const recommendations = Array.isArray(inputRecommendations) && inputRecommendations.length
        ? inputRecommendations
        : buildSecurityRecommendations({
            highSeverityAlerts: numberValue(summary.highSeverityAlerts, highSeverityAlerts),
            usersUnderAttack,
            activeIncidents: numberValue(summary.activeIncidents, activeIncidents),
            threatIndicators: numberValue(summary.threatIndicators, threats.length)
        });

    const dashboardMetrics = {
        totalAlerts: numberValue(summary.totalAlerts, alerts.length),
        highSeverityAlerts: numberValue(summary.highSeverityAlerts, highSeverityAlerts),
        activeIncidents: numberValue(summary.activeIncidents, activeIncidents),
        threatIndicators: numberValue(summary.threatIndicators, threats.length),
        usersUnderAttack,
        securityScore: numberValue(summary.securityScore),
        suspiciousSignIns: numberValue(summary.suspiciousSignIns, suspiciousSignIns.length),
        securityFindings: findings.length,
        recommendationsCount: recommendations.length
    };

    const warnings = cleanSecurityWarnings(inputWarnings, {
        hasAlertEvidence: alerts.length > 0,
        hasIncidentEvidence: incidents.length > 0,
        hasSignInEvidence: suspiciousSignIns.length > 0,
        hasFindingEvidence: findings.length > 0,
        hasThreatIndicators: threats.length > 0
    });

    return {
        alerts,
        incidents,
        threats,
        suspiciousSignIns,
        findings,
        riskDetections,
        riskyUsers,
        scenarioCoverage,
        recommendations,
        dashboardMetrics,
        warnings,
        internalThreatIndicators: internalThreats
    };
}

module.exports = {
    buildSecurityDashboardSource,
    buildSecurityRecommendations,
    extractInternalThreatIndicators,
    cleanSecurityWarnings
};