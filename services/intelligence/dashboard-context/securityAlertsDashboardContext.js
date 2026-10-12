const { asArray, buildContext, numberFrom, payloadFromSource } = require('./common');

function buildSecurityAlertsDashboardContext(source) {
    const payload = payloadFromSource(source);
    const storedMetrics = source.dashboardMetrics || source.dashboardSourceMetrics || {};
    const summary = { ...(payload.summary || {}), ...storedMetrics };
    const alerts = asArray(payload.alerts);
    const incidents = asArray(payload.incidents);
    const suspiciousSignIns = asArray(payload.signIns?.suspicious);
    const storedEvidence = asArray(source.evidence);
    const findings = asArray(payload.findings).length
        ? asArray(payload.findings)
        : storedEvidence.filter(item => item?.evidenceType === 'securityFindings').flatMap(item => asArray(item.data));
    const scenarioCoverage = payload.scenarioCoverage || source.sourceLineage?.scenarioCoverage || {};
    const highSeverityAlerts = alerts.filter(alert => ['critical', 'high'].includes(String(alert.severity || '').toLowerCase()));
    const activeIncidents = incidents.filter(incident => ['active', 'inprogress', 'newalert'].includes(String(incident.status || '').toLowerCase()));

    return buildContext(source, {
        dashboardMetrics: {
            totalAlerts: numberFrom(summary, ['totalAlerts'], alerts.length),
            highSeverityAlerts: numberFrom(summary, ['highSeverityAlerts'], highSeverityAlerts.length),
            criticalAlerts: alerts.filter(alert => String(alert.severity || '').toLowerCase() === 'critical').length,
            activeIncidents: numberFrom(summary, ['activeIncidents'], activeIncidents.length),
            suspiciousSignIns: numberFrom(summary, ['suspiciousSignIns'], suspiciousSignIns.length),
            threatIndicators: numberFrom(summary, ['threatIndicators'], asArray(payload.threats).length),
            usersUnderAttack: numberFrom(summary, ['usersUnderAttack'], asArray(payload.signIns?.usersUnderAttack).length),
            securityScore: numberFrom(summary, ['securityScore']),
            recommendationsCount: numberFrom(summary, ['recommendationsCount'], asArray(payload.recommendations).length)
        },
        calculatedIndicators: {
            highRiskSignalCount: highSeverityAlerts.length + activeIncidents.length + suspiciousSignIns.length,
            securityFindingCount: findings.length,
            incidentResponseRequired: activeIncidents.length > 0,
            attackTechniqueCount: asArray(payload.mitre).length,
            attackRegionCount: asArray(payload.regionDistribution).length
        },
        evidenceLists: {
            allAlerts: alerts,
            highSeverityAlerts,
            activeIncidents,
            suspiciousSignIns,
            securityFindings: findings,
            scenarioCoverage,
            identityRiskDetections: storedEvidence.filter(item => item?.evidenceType === 'riskDetections').flatMap(item => asArray(item.data)),
            riskyUsers: storedEvidence.filter(item => item?.evidenceType === 'riskyUsers').flatMap(item => asArray(item.data)),
            threats: asArray(payload.threats),
            usersUnderAttack: asArray(payload.signIns?.usersUnderAttack),
            mitreTechniques: asArray(payload.mitre),
            attackRegions: asArray(payload.regionDistribution),
            topTargetedUsers: asArray(payload.topTargetedUsers),
            attackTimeline: asArray(payload.attackTimeline),
            recommendations: asArray(payload.recommendations)
        },
        chartsData: {
            sourceDistribution: asArray(payload.sourceDistribution),
            categoryDistribution: asArray(payload.categoryDistribution),
            regionDistribution: asArray(payload.regionDistribution),
            mitre: asArray(payload.mitre),
            attackTimeline: asArray(payload.attackTimeline)
        }
    });
}

module.exports = buildSecurityAlertsDashboardContext;
