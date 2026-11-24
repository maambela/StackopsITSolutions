const { buildEmailDashboardSource } = require('./email-dashboard-source');

function buildEmailDashboardPayload({
    tenantKey = 'sunbird',
    payload = {},
    fetchedAt,
    success = true,
    now = () => new Date()
} = {}) {
    const collectedAt = fetchedAt || payload.fetchedAt || now().toISOString();

    const warnings = [
        ...(Array.isArray(payload.warnings) ? payload.warnings : []),
        ...(Array.isArray(payload.sourceAudit?.warnings) ? payload.sourceAudit.warnings : [])
    ]
        .map(item => String(item || '').trim())
        .filter(Boolean);

    const dashboardSource = buildEmailDashboardSource({
        alertsRows: payload.alerts || [],
        incidentsRows: payload.incidents || [],
        mailActivity: payload.mailActivity || {},
        summary: payload.summary || {},
        threats: payload.threats || null,
        affectedUsers: payload.affectedUsers || {}
    });

    return {
        success,
        tenant: tenantKey,
        fetchedAt: collectedAt,
        collectionStatus: warnings.length ? 'completed_with_warnings' : 'complete',
        warnings: [...new Set(warnings)],
        sourceAudit: {
            ...(payload.sourceAudit || {}),
            warnings: [...new Set(warnings)],
            fetchedAt: collectedAt
        },
        summary: {
            ...payload.summary,
            ...dashboardSource.dashboardMetrics
        },
        alerts: dashboardSource.alerts,
        incidents: dashboardSource.incidents,
        threats: dashboardSource.threatBreakdown,
        affectedUsers: payload.affectedUsers || {},
        mailActivity: {
            users: dashboardSource.mailUsers,
            summary: dashboardSource.dashboardMetrics
        },
        insights: Array.isArray(payload.insights) ? payload.insights : [],
        recommendations: dashboardSource.recommendations,
        dashboardMetrics: dashboardSource.dashboardMetrics
    };
}

const emailSources = {
    emailDetections: { coverage: 'emailDetectionsComplete', fields: ['emailDetections'], metrics: [] },
    alerts: { coverage: 'alertsComplete', fields: ['alerts', 'threats', 'affectedUsers', 'insights'],
        metrics: ['activeThreats', 'highSeverityAlerts', 'affectedUsersCount', 'threatResolutionRate',
            'phishingCount', 'malwareCount', 'spamCount', 'becCount', 'securityScore'] },
    incidents: { coverage: 'incidentsComplete', fields: ['incidents'], metrics: ['activeIncidents'] },
    mailActivity: { coverage: 'mailActivityOk', fields: ['mailActivity'],
        metrics: ['activeMailboxes', 'totalMailActivity', 'sendCount', 'receiveCount', 'readCount', 'mailActivity'] }
};

function readEmailReportRefreshDate(users = []) {
    return users.reduce((latest, user) => {
        const date = user.reportRefreshDate;
        if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return latest;
        const time = Date.parse(date);
        return Number.isFinite(time) && new Date(time).toISOString().slice(0, 10) === date && date > (latest || '')
            ? date : latest;
    }, null);
}

function hasVerifiedEmailSource(payload) {
    return payload?.success === true && Object.values(emailSources).some(({ coverage }) =>
        payload.sourceAudit?.[coverage] === true);
}

function mergeVerifiedEmailSources(previous, incoming, startedAt) {
    if (!hasVerifiedEmailSource(incoming)) return null;
    const merged = {
        ...previous,
        ...incoming,
        summary: { ...previous?.summary, ...incoming.summary },
        sourceAudit: { ...previous?.sourceAudit, ...incoming.sourceAudit, sourceTimestamps: {} }
    };
    let updated = false;
    for (const [source, { coverage, fields, metrics }] of Object.entries(emailSources)) {
        const priorTime = previous?.sourceAudit?.[coverage] === true
            ? previous.sourceAudit.sourceTimestamps?.[source] || previous.fetchedAt : null;
        const priorReportDate = source === 'mailActivity' && priorTime
            ? readEmailReportRefreshDate(previous.mailActivity?.users) : null;
        const newReportDate = priorReportDate ? readEmailReportRefreshDate(incoming.mailActivity?.users) : null;
        const update = incoming.sourceAudit[coverage] === true &&
            (!priorReportDate || (newReportDate && newReportDate >= priorReportDate)) &&
            (!Number.isFinite(Date.parse(priorTime)) || startedAt.getTime() > Date.parse(priorTime));
        const chosen = update ? incoming : Number.isFinite(Date.parse(priorTime)) ? previous : null;
        merged.sourceAudit[coverage] = Boolean(chosen);
        if (chosen) merged.sourceAudit.sourceTimestamps[source] = update ? startedAt.toISOString() : priorTime;
        for (const field of fields) merged[field] = chosen?.[field];
        for (const metric of metrics) merged.summary[metric] = chosen?.summary?.[metric];
        updated ||= update;
    }
    if (!updated) return null;
    const timestamps = Object.values(merged.sourceAudit.sourceTimestamps);
    merged.fetchedAt = new Date(Math.max(...timestamps.map(Date.parse))).toISOString();
    merged.sourceAudit.fetchedAt = merged.fetchedAt;
    delete merged.dashboardMetrics;
    return merged;
}

function readEmailDetectionCounts(result) {
    if (result?.results?.length !== 1 || result.isResultLimitReached) return null;
    const row = result.results[0];
    const keys = ['Observed', 'Phishing', 'Malware', 'Spam', 'Impersonation'];
    if (!row || !keys.every(key => Number.isSafeInteger(row[key]) && row[key] >= 0 && row[key] <= row.Observed) ||
        row.Observed === 0) return null;
    return { observed: row.Observed, phishing: row.Phishing, malware: row.Malware, spam: row.Spam,
        impersonation: row.Impersonation };
}

module.exports = { buildEmailDashboardPayload, hasVerifiedEmailSource, mergeVerifiedEmailSources, readEmailDetectionCounts, readEmailReportRefreshDate };
