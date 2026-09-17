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

function normalizeIdentityDashboardUser(row = {}) {
    const userType = normalizeUserType(row.userType ?? row.user_type ?? row.UserType ?? row.type ?? row.accountType);
    const isWorkforce = userType === 'Member';
    const isExternal = userType === 'Guest';
    return {
        id: row.id || row.ID || null,
        displayName: row.displayName || row.display_name || 'Unknown User',
        mail: row.mail || null,
        userPrincipalName: row.userPrincipalName || row.user_principal_name || null,
        userType,
        jobTitle: row.jobTitle || row.job_title || 'No Title',
        mobilePhone: row.mobilePhone || row.mobile_phone || 'N/A',
        roles: parseArray(row.roles),
        mfaEnabled: booleanValue(row.mfaEnabled ?? row.mfa_enabled ?? row.mfaRegistered ?? row.hasMfa),
        authMethodCount: numberValue(row.authMethodCount ?? row.auth_method_count),
        riskLevel: row.riskLevel || row.risk_level || 'SAFE',
        isExternal,
        isWorkforce,
        accountEnabled: row.accountEnabled ?? row.account_enabled ?? true,
        assignedLicenses: Array.isArray(row.assignedLicenses) ? row.assignedLicenses : [],
        licenseAssignmentStates: Array.isArray(row.licenseAssignmentStates) ? row.licenseAssignmentStates : [],
        lastSignIn: {
            dateTime: row.lastSignIn?.dateTime || row.last_signin_datetime || null,
            daysSince: numberValue(row.lastSignIn?.daysSince ?? row.days_since_signin, 999),
            location: row.lastSignIn?.location || row.last_signin_location || 'Unknown',
            device: row.lastSignIn?.device || row.last_signin_device || 'Unknown',
            status: row.lastSignIn?.status || row.last_signin_status || null
        }
    };
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

function hasSignInIssue(user) {
    const status = String(user.lastSignIn.status || '').toLowerCase();
    const location = String(user.lastSignIn.location || '').toLowerCase();
    const device = String(user.lastSignIn.device || '').toLowerCase();
    const risk = String(user.riskLevel || '').toUpperCase();
    return status.includes('fail') || risk === 'HIGH' ||
        location.includes('unknown') || location === 'no sign-in' ||
        device.includes('unknown') || device === 'no sign-in' ||
        user.lastSignIn.daysSince > 30;
}

function buildIdentityDashboardSource({ metricsRow = {}, usersRows = [], riskRow = {}, signInRow = {}, roleAssignments = [] } = {}) {
    const users = mergeRoleAssignments(usersRows.map(normalizeIdentityDashboardUser), roleAssignments);
    const hasUsers = users.length > 0;
    const totalUsers = hasUsers ? users.length : numberValue(metricsRow.total_users);
    const workforceUsers = users.filter(user => user.isWorkforce);
    const externalUsers = users.filter(user => user.isExternal);
    const unknownUserTypes = users.filter(user => user.userType === 'Unknown').length;
    const mfaEnabled = workforceUsers.filter(user => user.mfaEnabled).length;
    const mfaMissing = workforceUsers.filter(user => user.mfaEnabled === false).length;
    const mfaUnknown = workforceUsers.length - mfaEnabled - mfaMissing;
    const mfaCoverage = workforceUsers.length ? Math.round((mfaEnabled / workforceUsers.length) * 100) : 0;
    const privilegedUsersList = workforceUsers.filter(user => privilegedRoleNames(user).length > 0);
    const privilegedUsers = hasUsers ? privilegedUsersList.length : numberValue(metricsRow.admin_users);
    const highRiskUsers = hasUsers ? users.filter(user => String(user.riskLevel).toUpperCase() === 'HIGH').length : numberValue(metricsRow.high_risk_users);
    const unknownDevices = hasUsers
        ? users.filter(user => /unknown|no sign-in|n\/a/i.test(String(user.lastSignIn.device || 'Unknown'))).length
        : numberValue(riskRow.device_unknown);
    const signInIssues = hasUsers ? users.filter(hasSignInIssue).length : numberValue(signInRow.failed_signin_count_24h);
    const adminsWithoutMfa = hasUsers ? privilegedUsersList.filter(user => !user.mfaEnabled).length : numberValue(metricsRow.privileged_users_without_mfa);
    const multiplePrivilegedRoles = hasUsers ? users.filter(user =>
        user.roles.map(roleName).filter(role => /(admin|global|privileged|security|directory)/i.test(role)).length > 1
    ).length : 0;
    const mfaAssessmentStatus = unknownUserTypes || mfaUnknown ? 'incomplete' : workforceUsers.length ? 'complete' : 'not_applicable';
    const securityScore = Math.round(
        (mfaCoverage * 0.4) +
        ((100 - (totalUsers > 0 ? (highRiskUsers / totalUsers) * 100 : 0)) * 0.3) +
        ((privilegedUsers <= 5 ? 100 : 50) * 0.3)
    );
    const dashboardMetrics = {
        totalUsers,
        workforceUsers: workforceUsers.length,
        externalUsers: externalUsers.length,
        unknownUserTypes,
        activeUsers: numberValue(metricsRow.active_users_24h),
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

module.exports = {
    buildIdentityDashboardSource,
    normalizeIdentityDashboardUser
};
