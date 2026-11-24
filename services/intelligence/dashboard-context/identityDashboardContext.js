const { asArray, booleanFrom, buildContext, numberFrom } = require('./common');

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

function getLastSignInDays(user) {
    const raw = user?.lastSignIn?.daysSince;
    if (raw !== null && raw !== undefined && raw !== '' && Number.isFinite(Number(raw))) return Number(raw);
    const value = getLastSignIn(user);
    if (!value) return null;
    const time = new Date(value).getTime();
    return Number.isFinite(time) ? Math.max(0, Math.floor((Date.now() - time) / 86400000)) : null;
}

function hasMfaEvidence(user) {
    const value = user?.mfaEnabled ?? user?.hasMfa ?? user?.mfaRegistered;
    return value !== null && value !== undefined && value !== '';
}

function buildIdentityDashboardContext(source) {
    const users = asArray(source.evidence?.find(item => item?.evidenceType === 'users')?.data);
    const stored = source.metrics || {};
    const totalUsers = users.length || numberFrom(stored, ['TotalUsers', 'totalUsers']);
    const workforceUsers = users.filter(user => user?.isWorkforce || String(user?.userType || '').toLowerCase() === 'member');
    const privilegedUsers = workforceUsers.filter(isPrivileged);
    const usersWithoutMfa = workforceUsers.filter(user => hasMfaEvidence(user) && !booleanFrom(user.mfaEnabled ?? user.hasMfa ?? user.mfaRegistered));
    const usersWithUnknownMfa = workforceUsers.filter(user => !hasMfaEvidence(user));
    const highRiskUsers = users.filter(user => String(user.riskLevel || '').toUpperCase() === 'HIGH');
    const mediumRiskUsers = users.filter(user => String(user.riskLevel || '').toUpperCase() === 'MEDIUM');
    const externalUsers = users.filter(user => Boolean(user.isExternal) || String(user.userType || '').toLowerCase() === 'guest');
    const inactiveUsers = users.filter(user => {
        const days = getLastSignInDays(user);
        return days !== null && days > 30;
    });
    const unknownDeviceUsers = users.filter(user => {
        const device = String(user?.lastSignIn?.device || user?.device || '').trim();
        return Boolean(getLastSignIn(user) && (!device || /unknown|n\/a/i.test(device)));
    });
    const failedSignInUsers = users.filter(user => {
        const status = String(user?.failedSignIn?.status || user?.lastSignIn?.status || user?.signInStatus || '').toLowerCase();
        return status.includes('fail');
    });
    const adminsWithoutMfa = privilegedUsers.filter(user => usersWithoutMfa.includes(user));
    const mfaEnabled = workforceUsers.length ? workforceUsers.length - usersWithoutMfa.length : numberFrom(stored, ['MFAEnabled', 'mfaEnabled']);
    const mfaMissing = workforceUsers.length ? usersWithoutMfa.length : Math.max(0, totalUsers - mfaEnabled);
    const mfaCoverage = workforceUsers.length && !usersWithUnknownMfa.length
        ? Math.round((mfaEnabled / workforceUsers.length) * 100)
        : null;
    const dashboardSource = source.dashboardSourceMetrics || {};
    const dashboardMetrics = {
        totalUsers: numberFrom(dashboardSource, ['totalUsers'], totalUsers),
        workforceUsers: numberFrom(dashboardSource, ['workforceUsers'], workforceUsers.length),
        externalUsers: numberFrom(dashboardSource, ['externalUsers'], externalUsers.length),
        unknownUserTypes: numberFrom(dashboardSource, ['unknownUserTypes'], users.filter(user => String(user.userType || '').toLowerCase() === 'unknown').length),
        activeUsers: dashboardSource.signInCollectionStatus && dashboardSource.signInCollectionStatus !== 'complete'
            ? null
            : numberFrom(dashboardSource, ['activeUsers'], users.length
                ? users.filter(user => {
                    const days = getLastSignInDays(user);
                    return days !== null && days <= 30;
                }).length
                : numberFrom(stored, ['ActiveUsers', 'activeUsers'])),
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
            mfaCoverageStatus: dashboardMetrics.mfaCoverage === null
                ? 'temporarily_unavailable'
                : dashboardMetrics.mfaCoverage >= 90 ? 'healthy' : dashboardMetrics.mfaCoverage >= 70 ? 'attention' : 'high_risk',
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
