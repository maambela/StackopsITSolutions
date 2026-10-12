const { buildSecurityDashboardSource } = require('./security-dashboard-source');

function buildSecurityDashboardPayload({
    tenantKey = 'sunbird',
    payload = {},
    fetchedAt,
    success = true,
    now = () => new Date()
} = {}) {
    const collectedAt = fetchedAt || payload.fetchedAt || now().toISOString();

    const rawWarnings = [
        ...(Array.isArray(payload.warnings) ? payload.warnings : []),
        ...(Array.isArray(payload.collection?.warnings) ? payload.collection.warnings : []),
        ...(payload.collection?.incompleteReason ? [payload.collection.incompleteReason] : []),
        ...(payload.incompleteReason ? [payload.incompleteReason] : [])
    ];

    const dashboardSource = buildSecurityDashboardSource({
        alertsRows: payload.alerts || [],
        incidentsRows: payload.incidents || [],
        threatsRows: payload.threats || payload.threatIndicators || [],
        suspiciousSignInsRows: payload.signIns?.suspicious || payload.suspiciousSignIns || [],
        findingsRows: payload.findings || [],
        scenarioCoverage: payload.scenarioCoverage || {},
        riskDetectionsRows: payload.identityRisk?.riskDetections || [],
        riskyUsersRows: payload.identityRisk?.riskyUsers || [],
        summary: payload.summary || {},
        recommendations: payload.recommendations,
        warnings: rawWarnings
    });

    const hasPrimaryEvidence = Boolean(
        dashboardSource.alerts.length ||
        dashboardSource.incidents.length ||
        dashboardSource.suspiciousSignIns.length ||
        dashboardSource.findings.length
    );

    return {
        success: success !== false && hasPrimaryEvidence,
        tenant: tenantKey,
        fetchedAt: collectedAt,
        ...payload,
        summary: {
            ...(payload.summary || {}),
            ...dashboardSource.dashboardMetrics
        },
        alerts: dashboardSource.alerts,
        incidents: dashboardSource.incidents,
        threats: dashboardSource.threats,
        threatIndicators: dashboardSource.threats,
        findings: dashboardSource.findings,
        scenarioCoverage: dashboardSource.scenarioCoverage,
        identityRisk: {
            ...(payload.identityRisk || {}),
            riskDetections: dashboardSource.riskDetections,
            riskyUsers: dashboardSource.riskyUsers
        },
        signIns: payload.signIns || {
            suspicious: dashboardSource.suspiciousSignIns
        },
        recommendations: dashboardSource.recommendations,
        dashboardMetrics: dashboardSource.dashboardMetrics,
        warnings: dashboardSource.warnings,
        collectionStatus: dashboardSource.warnings.length ? 'completed_with_warnings' : 'complete',
        collection: {
            ...(payload.collection || {}),
            warnings: dashboardSource.warnings,
            internalThreatIndicatorsExtracted: dashboardSource.internalThreatIndicators?.length || 0,
            hasPrimaryEvidence
        }
    };
}

module.exports = { buildSecurityDashboardPayload };
