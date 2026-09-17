const { asArray, booleanFrom, buildContext, daysSince, numberFrom } = require('./common');

function getRoleNames(user) {
    const roles = user?.roles || user?.assignedRoles || user?.roleNames || [];
    return asArray(roles).map(role => typeof role === 'string' ? role : role.displayName || role.name || '').filter(Boolean);
}

function isPrivileged(user) {
    return Boolean(user?.hasAdminRole || user?.isPrivileged) ||
        getRoleNames(user).some(role => /(admin|global|privileged|security|directory|exchange|sharepoint|compliance)/i.test(role));
}

function getLastSignIn(user) {
    return user?.lastSignIn?.dateTime || user?.signInActivity?.lastSignInDateTime || user?.lastSignInDateTime || null;
}

function buildIdentityDashboardContext(source) {
    const users = asArray(source.evidence?.find(item => item?.evidenceType === 'users')?.data);
    const stored = source.metrics || {};
    const totalUsers = users.length || numberFrom(stored, ['TotalUsers', 'totalUsers']);
    const workforceUsers = users.filter(user => user?.isWorkforce || String(user?.userType || '').toLowerCase() === 'member');
    const privilegedUsers = workforceUsers.filter(isPrivileged);
    const usersWithoutMfa = workforceUsers.filter(user => !booleanFrom(user.mfaEnabled ?? user.hasMfa ?? user.mfaRegistered));
    const highRiskUsers = users.filter(user => String(user.riskLevel || '').toUpperCase() === 'HIGH');
    const mediumRiskUsers = users.filter(user => String(user.riskLevel || '').toUpperCase() === 'MEDIUM');
    const externalUsers = users.filter(user => Boolean(user.isExternal) || String(user.userType || '').toLowerCase() === 'guest');
    const inactiveUsers = users.filter(user => daysSince(getLastSignIn(user)) > 30);
    const unknownDeviceUsers = users.filter(user => /unknown|no sign-in|n\/a/i.test(String(user?.lastSignIn?.device || user?.device || 'Unknown')));
    const failedSignInUsers = users.filter(user => {
        const status = String(user?.lastSignIn?.status || user?.signInStatus || '').toLowerCase();
        const location = String(user?.lastSignIn?.location || user?.location || '').toLowerCase();
        const device = String(user?.lastSignIn?.device || user?.device || '').toLowerCase();
        const risk = String(user.riskLevel || '').toUpperCase();
        return status.includes('fail') || risk === 'HIGH' ||
            location.includes('unknown') || location === 'no sign-in' ||
            device.includes('unknown') || device === 'no sign-in' ||
            daysSince(getLastSignIn(user)) > 30;
    });
    const adminsWithoutMfa = privilegedUsers.filter(user => usersWithoutMfa.includes(user));
    const mfaEnabled = workforceUsers.length ? workforceUsers.length - usersWithoutMfa.length : numberFrom(stored, ['MFAEnabled', 'mfaEnabled']);
    const mfaMissing = workforceUsers.length ? usersWithoutMfa.length : Math.max(0, totalUsers - mfaEnabled);
    const mfaCoverage = workforceUsers.length ? Math.round((mfaEnabled / workforceUsers.length) * 100) : 0;
    const dashboardSource = source.dashboardSourceMetrics || {};
    const dashboardMetrics = {
        totalUsers: numberFrom(dashboardSource, ['totalUsers'], totalUsers),
        workforceUsers: numberFrom(dashboardSource, ['workforceUsers'], workforceUsers.length),
        externalUsers: numberFrom(dashboardSource, ['externalUsers'], externalUsers.length),
        unknownUserTypes: numberFrom(dashboardSource, ['unknownUserTypes'], users.filter(user => String(user.userType || '').toLowerCase() === 'unknown').length),
        activeUsers: numberFrom(dashboardSource, ['activeUsers'], users.length ? users.filter(user => daysSince(getLastSignIn(user)) <= 30).length : numberFrom(stored, ['ActiveUsers', 'activeUsers'])),
        mfaEnabled: numberFrom(dashboardSource, ['mfaEnabled'], mfaEnabled),
        mfaMissing: numberFrom(dashboardSource, ['mfaMissing'], mfaMissing),
        mfaCoverage: numberFrom(dashboardSource, ['mfaCoverage'], mfaCoverage),
        privilegedUsers: numberFrom(dashboardSource, ['privilegedUsers'], workforceUsers.length ? privilegedUsers.length : numberFrom(stored, ['AdminRoles', 'adminRoles'])),
        highRiskUsers: numberFrom(dashboardSource, ['highRiskUsers'], highRiskUsers.length),
        mediumRiskUsers: numberFrom(dashboardSource, ['mediumRiskUsers'], mediumRiskUsers.length),
        inactiveUsers: numberFrom(dashboardSource, ['inactiveUsers'], inactiveUsers.length),
        signInIssues: numberFrom(dashboardSource, ['signInIssues'], failedSignInUsers.length),
        unknownDevices: numberFrom(dashboardSource, ['unknownDevices'], unknownDeviceUsers.length),
        adminsWithoutMfa: numberFrom(dashboardSource, ['adminsWithoutMfa'], adminsWithoutMfa.length),
        multiplePrivilegedRoles: numberFrom(dashboardSource, ['multiplePrivilegedRoles'], users.filter(user =>
            getRoleNames(user).filter(role => /(admin|global|privileged|security|directory)/i.test(role)).length > 1
        ).length),
        securityScore: numberFrom(dashboardSource, ['securityScore'], numberFrom(stored, ['SecurityScore', 'securityScore']))
    };

    return buildContext(source, {
        dashboardMetrics,
        calculatedIndicators: {
            mfaCoverageStatus: dashboardMetrics.mfaCoverage >= 90 ? 'healthy' : dashboardMetrics.mfaCoverage >= 70 ? 'attention' : 'high_risk',
            privilegedMfaGap: dashboardMetrics.adminsWithoutMfa,
            identityRiskUsers: dashboardMetrics.highRiskUsers + dashboardMetrics.signInIssues
        },
        evidenceLists: {
            allUsers: users,
            usersWithoutMfa,
            privilegedUsers,
            highRiskUsers,
            adminsWithoutMfa,
            inactiveUsers,
            failedSignInUsers,
            externalUsers,
            unknownDeviceUsers
        },
        chartsData: {
            mfaCoverage: { enabled: dashboardMetrics.mfaEnabled, missing: dashboardMetrics.mfaMissing },
            riskDistribution: {
                high: dashboardMetrics.highRiskUsers,
                medium: dashboardMetrics.mediumRiskUsers,
                safe: Math.max(0, dashboardMetrics.totalUsers - dashboardMetrics.highRiskUsers - dashboardMetrics.mediumRiskUsers)
            },
            privilegeDistribution: {
                privileged: dashboardMetrics.privilegedUsers,
                standard: Math.max(0, dashboardMetrics.totalUsers - dashboardMetrics.privilegedUsers)
            }
        }
    });
}

module.exports = buildIdentityDashboardContext;
