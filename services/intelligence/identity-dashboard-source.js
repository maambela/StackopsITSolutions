function normalizeUserType(value) {
    const normalized = String(value ?? '').trim().toLowerCase();
    if (normalized === 'member') return 'Member';
    if (normalized === 'guest') return 'Guest';
    return 'Unknown';
}

function numberValue(value, fallback = 0) {
    if (value === null || value === undefined || value === '') return fallback;
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
}

function parseArray(value) {
    if (Array.isArray(value)) return value;
    if (typeof value !== 'string' || !value.trim()) return [];
    try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
        return [];
    }
}

function booleanValue(value) {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return value > 0;
    return ['1', 'true', 'yes', 'enabled'].includes(String(value || '').trim().toLowerCase());
}

function nullableBoolean(value) {
    return value === null || value === undefined || value === '' ? null : booleanValue(value);
}

function normalizeIdentityDashboardUser(row = {}) {
    const userType = normalizeUserType(row.userType ?? row.user_type ?? row.UserType ?? row.type ?? row.accountType);
    const rawMfa = row.mfaEnabled ?? row.mfa_enabled ?? row.mfaRegistered ?? row.hasMfa;
    const mfaEnabled = nullableBoolean(rawMfa);
    const rawDateTime = row.lastSignIn?.dateTime || row.last_signin_datetime || null;
    const rawDaysSince = row.lastSignIn?.daysSince ?? row.days_since_signin;
    const daysSince = rawDaysSince === null || rawDaysSince === undefined || rawDaysSince === ''
        ? (rawDateTime ? daysSinceValue(rawDateTime) : null)
        : numberValue(rawDaysSince, null);
    return {
        ...row,
        id: row.id || row.ID || null,
        displayName: row.displayName || row.display_name || 'Unknown User',
        mail: row.mail || null,
        userPrincipalName: row.userPrincipalName || row.user_principal_name || null,
        userType,
        jobTitle: row.jobTitle || row.job_title || 'No Title',
        mobilePhone: row.mobilePhone || row.mobile_phone || 'N/A',
        roles: parseArray(row.roles),
        mfaEnabled,
        mfaStatus: row.mfaStatus || (mfaEnabled === null ? 'unavailable' : 'complete'),
        authMethodCount: row.authMethodCount === null || row.authMethodCount === undefined
            ? (row.auth_method_count === undefined ? null : numberValue(row.auth_method_count, null))
            : numberValue(row.authMethodCount, null),
        riskLevel: row.riskLevel || row.risk_level || 'SAFE',
        isExternal: row.isExternal ?? (userType === 'Guest'),
        isWorkforce: row.isWorkforce ?? (userType === 'Member'),
        accountEnabled: row.accountEnabled ?? row.account_enabled ?? true,
        assignedLicenses: Array.isArray(row.assignedLicenses) ? row.assignedLicenses : [],
        licenseAssignmentStates: Array.isArray(row.licenseAssignmentStates) ? row.licenseAssignmentStates : [],
        lastSignIn: {
            ...row.lastSignIn,
            dateTime: rawDateTime,
            daysSince,
            location: row.lastSignIn?.location || row.last_signin_location || null,
            device: row.lastSignIn?.device || row.last_signin_device || null,
            status: row.lastSignIn?.status || row.last_signin_status || null,
            observationStatus: row.lastSignIn?.observationStatus ||
                (rawDateTime ? 'observed' : 'unavailable')
        },
        failedSignIn: row.failedSignIn || null
    };
}

function daysSinceValue(value) {
    const time = new Date(value).getTime();
    return Number.isFinite(time) ? Math.max(0, Math.floor((Date.now() - time) / 86400000)) : null;
}

function roleName(role) {
    return typeof role === 'string' ? role : role?.name || role?.roleName || '';
}

function privilegedRoleNames(user) {
    return user.roles.map(roleName).filter(role => /(admin|global|privileged|security|directory|exchange|sharepoint|compliance)/i.test(role));
}

function mergeRoleAssignments(users, roleAssignments) {
    const assignmentsByPrincipal = new Map();
    for (const assignment of roleAssignments) {
        const principal = assignment.principalId || assignment.userId || assignment.userPrincipalName || assignment.principalName;
        const name = assignment.roleName || assignment.name || assignment.displayName;
        if (!principal || !name) continue;
        if (!assignmentsByPrincipal.has(principal)) assignmentsByPrincipal.set(principal, []);
        assignmentsByPrincipal.get(principal).push(name);
    }
    return users.map(user => {
        const assigned = assignmentsByPrincipal.get(user.id) || assignmentsByPrincipal.get(user.userPrincipalName) || [];
        return { ...user, roles: [...new Set([...user.roles.map(roleName), ...assigned].filter(Boolean))] };
    });
}

function hasFailedSignIn(user) {
    return String(user.failedSignIn?.status || user.lastSignIn.status || '').toLowerCase().includes('fail');
}

function buildIdentityDashboardSource({ metricsRow = {}, usersRows = [], riskRow = {}, signInRow = {}, roleAssignments = [] } = {}) {
    const users = mergeRoleAssignments(usersRows.map(normalizeIdentityDashboardUser), roleAssignments);
    const hasUsers = users.length > 0;
    const totalUsers = hasUsers ? users.length : numberValue(metricsRow.total_users);
    const workforceUsers = users.filter(user => user.isWorkforce);
    const externalUsers = users.filter(user => user.isExternal);
    const unknownUserTypes = users.filter(user => user.userType === 'Unknown').length;
    const mfaEnabled = workforceUsers.filter(user => user.mfaEnabled === true).length;
    const mfaMissing = workforceUsers.filter(user => user.mfaEnabled === false).length;
    const mfaUnknown = workforceUsers.length - mfaEnabled - mfaMissing;
    const mfaCoverage = workforceUsers.length && !mfaUnknown ? Math.round((mfaEnabled / workforceUsers.length) * 100) : null;
    const privilegedUsersList = workforceUsers.filter(user => privilegedRoleNames(user).length > 0);
    const privilegedUsers = hasUsers ? privilegedUsersList.length : numberValue(metricsRow.admin_users);
    const highRiskUsers = hasUsers ? users.filter(user => String(user.riskLevel).toUpperCase() === 'HIGH').length : numberValue(metricsRow.high_risk_users);
    const unknownDevices = hasUsers
        ? users.filter(user => user.lastSignIn.dateTime && (!user.lastSignIn.device || /unknown|n\/a/i.test(user.lastSignIn.device))).length
        : numberValue(riskRow.device_unknown);
    const signInIssues = hasUsers ? users.filter(hasFailedSignIn).length : numberValue(signInRow.failed_signin_count_24h);
    const adminsWithoutMfa = hasUsers ? privilegedUsersList.filter(user => user.mfaEnabled === false).length : numberValue(metricsRow.privileged_users_without_mfa);
    const multiplePrivilegedRoles = hasUsers ? users.filter(user =>
        user.roles.map(roleName).filter(role => /(admin|global|privileged|security|directory)/i.test(role)).length > 1
    ).length : 0;
    const mfaAssessmentStatus = unknownUserTypes || mfaUnknown
        ? 'incomplete'
        : workforceUsers.length ? 'complete' : 'not_applicable';
    const signInCollectionStatus = metricsRow.signInCollectionStatus ||
        (users.some(user => ['partial', 'unavailable'].includes(user.lastSignIn.observationStatus)) ? 'incomplete' : 'complete');
    const activeUsers = signInCollectionStatus === 'complete'
        ? numberValue(metricsRow.active_users_24h, users.filter(user => user.lastSignIn.daysSince !== null && user.lastSignIn.daysSince <= 1).length)
        : null;
    const securityScore = mfaCoverage === null ? null : Math.round(
        (mfaCoverage * 0.4) +
        ((100 - (totalUsers > 0 ? (highRiskUsers / totalUsers) * 100 : 0)) * 0.3) +
        ((privilegedUsers <= 5 ? 100 : 50) * 0.3)
    );
    const dashboardMetrics = {
        totalUsers,
        workforceUsers: workforceUsers.length,
        externalUsers: externalUsers.length,
        unknownUserTypes,
        activeUsers,
        signInCollectionStatus,
        mfaEnabled,
        mfaMissing,
        mfaUnknown,
        mfaCoverage,
        mfaAssessmentStatus,
        privilegedUsers,
        adminsWithoutMfa,
        highRiskUsers,
        signInIssues,
        unknownDevices,
        multiplePrivilegedRoles,
        securityScore
    };
    return {
        users,
        dashboardMetrics,
        legacyMetrics: {
            totalUsers,
            adminUsers: privilegedUsers,
            mfaEnabledUsers: mfaEnabled,
            mfaPercentage: mfaCoverage,
            highRiskUsers,
            mediumRiskUsers: numberValue(metricsRow.medium_risk_users),
            activeUsers24h: numberValue(metricsRow.active_users_24h),
            usersWithCompleteProfile: numberValue(metricsRow.users_with_complete_profile),
            privilegedUsersWithoutMFA: dashboardMetrics.adminsWithoutMfa,
            identityRiskScore: numberValue(metricsRow.identity_risk_score)
        }
    };
}

function buildSavedIdentityDashboard(users, metrics, tenantId, now = Date.now()) {
    const tenant = String(tenantId || '').trim().toLowerCase();
    const displayUsers = users.map(user => {
        const saved = user.lastVerifiedMfa;
        const observedAt = Date.parse(saved?.observedAt);
        if (typeof user.mfaEnabled === 'boolean' || !user.id || !tenant ||
            String(saved?.tenantId || '').trim().toLowerCase() !== tenant ||
            typeof saved?.enabled !== 'boolean' || !Number.isInteger(saved.count) || saved.count < 0 ||
            !Number.isFinite(observedAt) || observedAt > now) return user;
        return {
            ...user, mfaEnabled: saved.enabled, authMethodCount: saved.count,
            mfaStatus: 'stale', mfaObservedAt: saved.observedAt
        };
    });
    const workforce = displayUsers.filter(user => user.isWorkforce === true);
    const complete = workforce.length > 0 &&
        displayUsers.every(user => user.isWorkforce === true || user.isExternal === true) &&
        workforce.every(user => typeof user.mfaEnabled === 'boolean' && ['complete', 'stale'].includes(user.mfaStatus));
    const observations = workforce.map(user => Date.parse(user.mfaObservedAt));
    const oldest = complete && observations.every(time => Number.isFinite(time) && time <= now)
        ? Math.min(...observations) : null;
    const mfaOutdated = complete && (workforce.some(user => user.mfaStatus === 'stale') ||
        (oldest !== null && now - oldest >= 30 * 60000));
    const enabled = workforce.filter(user => user.mfaEnabled === true).length;
    const mfaCoverage = complete ? Math.round(enabled / workforce.length * 100) : null;
    const derived = buildIdentityDashboardSource({ usersRows: displayUsers }).dashboardMetrics;
    const scoreInputsVerified = complete && displayUsers.every(user => user.rolesStatus === 'complete');
    const highRiskUsers = displayUsers.filter(user => String(user.riskLevel).toUpperCase() === 'HIGH' ||
        (user.mfaStatus === 'stale' && user.mfaEnabled === false && user.hasAdminRole === true)).length;
    const securityScore = scoreInputsVerified ? Math.round(
        (mfaCoverage * 0.4) + ((100 - highRiskUsers / displayUsers.length * 100) * 0.3) +
        ((derived.privilegedUsers <= 5 ? 100 : 50) * 0.3)
    ) : null;
    return {
        users: displayUsers,
        metrics: {
            ...metrics, mfaCoverage, securityScore, mfaOutdated,
            mfaObservedAt: oldest === null ? null : new Date(oldest).toISOString(),
            mfaEnabled: enabled,
            mfaMissing: workforce.filter(user => user.mfaEnabled === false).length
        }
    };
}

module.exports = {
    buildIdentityDashboardSource,
    buildSavedIdentityDashboard,
    normalizeIdentityDashboardUser
};
