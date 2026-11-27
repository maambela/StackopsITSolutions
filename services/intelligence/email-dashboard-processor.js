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
    return (Array.isArray(users) ? users : []).reduce((latest, user) => {
        const date = user?.reportRefreshDate;
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

function hasEmailDashboardState(payload) {
    return payload?.success === true && Boolean(payload.sourceAudit?.sourceTenantId) &&
        (hasVerifiedEmailSource(payload) || Object.keys(payload.sourceAudit.sourceOutcomes || {}).length > 0);
}

function selectScopedEmailDashboard(payload, tenantId) {
    const audit = payload?.sourceAudit;
    if (!tenantId || audit?.sourceTenantId !== tenantId || !hasEmailDashboardState(payload)) {
        return { success: true, fetchedAt: null, sourceAudit: { sourceTenantId: tenantId } };
    }
    const scoped = { ...payload, summary: { ...payload.summary }, sourceAudit: {
        ...audit, sourceTimestamps: { ...audit.sourceTimestamps }, sourceAttemptIds: { ...audit.sourceAttemptIds }
    } };
    let stripped = false;
    for (const [source, { coverage, fields, metrics }] of Object.entries(emailSources)) {
        if (audit[coverage] !== true) continue;
        // The previous version tagged the row, but only newly collected sources received an attempt ID.
        const sourceTenant = audit.sourceTenantIds?.[source];
        if (sourceTenant === tenantId || (!sourceTenant && audit.sourceAttemptIds?.[source])) continue;
        scoped.sourceAudit[coverage] = false;
        delete scoped.sourceAudit.sourceTimestamps[source];
        delete scoped.sourceAudit.sourceAttemptIds[source];
        for (const field of fields) delete scoped[field];
        for (const metric of metrics) delete scoped.summary[metric];
        stripped = true;
    }
    if (stripped) {
        const times = Object.values(scoped.sourceAudit.sourceTimestamps).map(Date.parse).filter(Number.isFinite);
        scoped.fetchedAt = times.length ? new Date(Math.max(...times)).toISOString() : null;
        scoped.sourceAudit.fetchedAt = scoped.fetchedAt;
        delete scoped.dashboardMetrics;
    }
    return scoped;
}

function getReusableEmailReport(payload, now = Date.now(), tenantId) {
    const savedAt = Date.parse(payload?.sourceAudit?.sourceTimestamps?.mailActivity);
    const age = now - savedAt;
    const report = payload?.mailActivity;
    return Boolean(tenantId) && payload?.sourceAudit?.sourceTenantId === tenantId &&
        payload.sourceAudit.mailActivityTenantId === tenantId &&
        payload?.sourceAudit?.mailActivityOk === true && age >= 0 && age < 60 * 60000 &&
        Array.isArray(report?.users) && report.summary && readEmailReportRefreshDate(report.users)
        ? report : null;
}

function readEmailAlertTargets(alert) {
    const targets = (Array.isArray(alert.userStates) ? alert.userStates : []).map(user => ({
        aadUserId: user.aadUserId || user.userId || null,
        accountName: user.accountName || user.userPrincipalName || null
    }));
    for (const item of Array.isArray(alert.evidence) ? alert.evidence : []) {
        const type = String(item?.['@odata.type'] || '').split('.').at(-1);
        if (!['userEvidence', 'mailboxEvidence'].includes(type)) continue;
        targets.push({
            aadUserId: item.userAccount?.azureAdUserId || null,
            accountName: item.userAccount?.userPrincipalName || item.upn || item.primaryAddress || item.userAccount?.accountName || null
        });
    }
    return targets.filter(target => target.aadUserId || target.accountName);
}

function countEmailAlertTargets(alerts) {
    const aliases = new Map();
    const nameOf = target => typeof target?.accountName === 'string' ? target.accountName.trim().toLowerCase() : '';
    for (const alert of alerts) {
        for (const target of alert.userStates) {
            const name = nameOf(target);
            if (!name || !target.aadUserId) continue;
            const id = String(target.aadUserId).toLowerCase();
            aliases.set(name, aliases.has(name) && aliases.get(name) !== id ? null : id);
        }
    }
    const counts = new Map();
    for (const alert of alerts) {
        const seen = new Set();
        const targets = alert.userStates.length ? alert.userStates : [{ accountName: alert.recipient }];
        for (const target of targets) {
            const name = nameOf(target);
            const id = target.aadUserId ? String(target.aadUserId).toLowerCase() : aliases.get(name);
            if (!id && (!name || name === 'unknown user' || name === 'unknown')) continue;
            const key = id ? `id:${id}` : `name:${name}`;
            if (seen.has(key)) continue;
            seen.add(key);
            const current = counts.get(key);
            counts.set(key, { user: name || current?.user || id, threatCount: (current?.threatCount || 0) + 1 });
        }
    }
    return [...counts.values()].sort((a, b) => b.threatCount - a.threatCount);
}

function mergeVerifiedEmailSources(previous, incoming, startedAt) {
    if (!hasEmailDashboardState(incoming)) return null;
    if (previous?.sourceAudit?.sourceTenantId !== incoming.sourceAudit.sourceTenantId) previous = null;
    else previous = selectScopedEmailDashboard(previous, incoming.sourceAudit.sourceTenantId);
    const merged = {
        ...previous,
        ...incoming,
        summary: { ...previous?.summary, ...incoming.summary },
        sourceAudit: { ...previous?.sourceAudit, ...incoming.sourceAudit, sourceTimestamps: {},
            sourceAttemptIds: {}, sourceTenantIds: {}, sourceOutcomes: { ...previous?.sourceAudit?.sourceOutcomes } }
    };
    let updated = false;
    for (const [source, { coverage, fields, metrics }] of Object.entries(emailSources)) {
        const priorTime = previous?.sourceAudit?.[coverage] === true
            ? previous.sourceAudit.sourceTimestamps?.[source] || previous.fetchedAt : null;
        const priorReportDate = source === 'mailActivity' && priorTime
            ? readEmailReportRefreshDate(previous.mailActivity?.users) : null;
        const newReportDate = priorReportDate ? readEmailReportRefreshDate(incoming.mailActivity?.users) : null;
        const received = incoming.sourceAudit.sourceOutcomes?.[source];
        const latestAttempt = previous?.sourceAudit?.sourceOutcomes?.[source];
        const attemptIsNewer = startedAt.getTime() > Math.max(Date.parse(priorTime) || 0, Date.parse(latestAttempt?.at) || 0);
        if (received && received.status !== 'reused' && attemptIsNewer && received.status !== latestAttempt?.status) {
            merged.sourceAudit.sourceOutcomes[source] = { ...received, at: startedAt.toISOString() };
            updated = true;
        }
        const update = incoming.sourceAudit[coverage] === true && received?.status !== 'reused' &&
            (!priorReportDate || (newReportDate && newReportDate >= priorReportDate)) &&
            (!Number.isFinite(Date.parse(priorTime)) || startedAt.getTime() > Date.parse(priorTime));
        const chosen = update ? incoming : Number.isFinite(Date.parse(priorTime)) ? previous : null;
        merged.sourceAudit[coverage] = Boolean(chosen);
        if (chosen) {
            merged.sourceAudit.sourceTimestamps[source] = update ? startedAt.toISOString() : priorTime;
            merged.sourceAudit.sourceAttemptIds[source] = update
                ? incoming.sourceAudit.attemptId : previous.sourceAudit.sourceAttemptIds?.[source];
            merged.sourceAudit.sourceTenantIds[source] = incoming.sourceAudit.sourceTenantId;
        }
        if (source === 'mailActivity') {
            merged.sourceAudit.mailActivityTenantId = update
                ? incoming.sourceAudit.sourceTenantId : chosen?.sourceAudit?.mailActivityTenantId;
        }
        for (const field of fields) merged[field] = chosen?.[field];
        for (const metric of metrics) merged.summary[metric] = chosen?.summary?.[metric];
        updated ||= update;
    }
    if (!updated) return null;
    const timestamps = Object.values(merged.sourceAudit.sourceTimestamps);
    merged.fetchedAt = timestamps.length ? new Date(Math.max(...timestamps.map(Date.parse))).toISOString() : null;
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
    const counts = { observed: row.Observed, phishing: row.Phishing, malware: row.Malware, spam: row.Spam,
        impersonation: row.Impersonation };
    const outcomes = { PhishingInInbox: row.Phishing, MalwareInInbox: row.Malware,
        ThreatsBlocked: Math.min(row.Observed, row.Phishing + row.Malware),
        ThreatsQuarantined: Math.min(row.Observed, row.Phishing + row.Malware) };
    for (const [key, maximum] of Object.entries(outcomes)) {
        if (!Object.hasOwn(row, key)) continue;
        if (!Number.isSafeInteger(row[key]) || row[key] < 0 || row[key] > maximum) return null;
        counts[key[0].toLowerCase() + key.slice(1)] = row[key];
    }
    return counts;
}

module.exports = {
    buildEmailDashboardPayload, hasVerifiedEmailSource, hasEmailDashboardState, mergeVerifiedEmailSources, readEmailDetectionCounts,
    readEmailReportRefreshDate, getReusableEmailReport, readEmailAlertTargets, countEmailAlertTargets, selectScopedEmailDashboard
};
