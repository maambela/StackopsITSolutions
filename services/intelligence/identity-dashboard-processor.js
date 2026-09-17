function defaultMapWithConcurrency(items, limit, worker) {
    const safeLimit = Math.max(1, Number(limit) || 1);
    let index = 0;
    const results = new Array(items.length);
    const workers = Array.from({ length: Math.min(safeLimit, items.length) }, async () => {
        while (index < items.length) {
            const currentIndex = index++;
            results[currentIndex] = await worker(items[currentIndex], currentIndex);
        }
    });
    return Promise.all(workers).then(() => results);
}

async function buildIdentityDashboardPayload({
    tenantKey = 'sunbird',
    users = [],
    roleAssignments = [],
    signIns = [],
    loadAuthMethods,
    hasRealMfaMethod,
    mapWithConcurrency = defaultMapWithConcurrency,
    concurrency = 8,
    now = () => new Date()
} = {}) {
    if (typeof loadAuthMethods !== 'function' || typeof hasRealMfaMethod !== 'function') {
        throw new Error('Identity dashboard processing requires authentication-method helpers');
    }

    const userRoleMap = {};
    roleAssignments.forEach(assignment => {
        const principalId = assignment.principalId;
        if (!userRoleMap[principalId]) userRoleMap[principalId] = [];
        userRoleMap[principalId].push({
            id: assignment.roleDefinition?.id,
            name: assignment.roleDefinition?.displayName || 'Unknown Role'
        });
    });

    const latestSignInMap = {};
    signIns.forEach(signIn => {
        const upn = signIn.userPrincipalName;
        if (!upn) return;
        if (!latestSignInMap[upn] || new Date(signIn.createdDateTime) > new Date(latestSignInMap[upn].createdDateTime)) {
            latestSignInMap[upn] = {
                createdDateTime: signIn.createdDateTime,
                appDisplayName: signIn.appDisplayName,
                clientAppUsed: signIn.clientAppUsed,
                ipAddress: signIn.ipAddress,
                location: signIn.location?.city ? `${signIn.location.city}, ${signIn.location.countryOrRegion}` : 'Unknown Location',
                deviceDetail: signIn.deviceDetail,
                status: signIn.status?.errorCode === '0' ? 'Success' : 'Failed'
            };
        }
    });

    const collectedAt = now();
    const enrichedUsers = await mapWithConcurrency(users, concurrency, async user => {
        const userRoles = userRoleMap[user.id] || [];
        const hasAdminRole = userRoles.some(role => {
            const name = String(role.name || '').toLowerCase();
            return name.includes('admin') || name.includes('global');
        });
        const authMethods = await loadAuthMethods(user);
        const hasMFA = hasRealMfaMethod(authMethods);
        const lastSignIn = latestSignInMap[user.userPrincipalName];
        const lastSignInDate = lastSignIn?.createdDateTime ? new Date(lastSignIn.createdDateTime) : null;
        const daysSinceSignIn = lastSignInDate
            ? Math.floor((collectedAt.getTime() - lastSignInDate.getTime()) / (1000 * 60 * 60 * 24))
            : 999;
        let riskLevel = 'SAFE';
        if (hasAdminRole && !hasMFA) riskLevel = 'HIGH';
        else if (daysSinceSignIn > 30) riskLevel = 'MEDIUM';
        const isNewLocation = Boolean(lastSignIn && lastSignIn.location === 'Unknown Location');
        const rawUserType = String(user.userType || user.UserType || '').trim().toLowerCase();
        const isGuest = rawUserType === 'guest' || (user.userPrincipalName && user.userPrincipalName.includes('#EXT#'));
        const isWorkforce = rawUserType === 'member' || (!rawUserType && user.userPrincipalName && !user.userPrincipalName.includes('#EXT#'));

        return {
            id: user.id,
            displayName: user.displayName || 'Unknown User',
            mail: user.mail,
            userPrincipalName: user.userPrincipalName,
            userType: isGuest ? 'Guest' : isWorkforce ? 'Member' : 'Unknown',
            jobTitle: user.jobTitle || 'No Title',
            mobilePhone: user.mobilePhone || 'N/A',
            roles: userRoles,
            hasAdminRole,
            isExternal: isGuest,
            isWorkforce,
            mfaEnabled: hasMFA,
            authMethodCount: authMethods.length,
            riskLevel,
            accountEnabled: user.accountEnabled !== false,
            lastSignIn: {
                dateTime: lastSignInDate?.toISOString() || null,
                daysSince: daysSinceSignIn,
                location: lastSignIn?.location || 'No sign-in',
                device: lastSignIn?.deviceDetail?.displayName || 'Unknown',
                appDisplayName: lastSignIn?.appDisplayName,
                clientAppUsed: lastSignIn?.clientAppUsed,
                status: lastSignIn?.status || 'No activity'
            },
            flags: {
                adminWithoutMFA: hasAdminRole && !hasMFA,
                inactiveOver30Days: daysSinceSignIn > 30,
                newLocationLogin: isNewLocation
            }
        };
    });

    const totalUsers = enrichedUsers.length;
    const workforceUsers = enrichedUsers.filter(user => user.isWorkforce === true);
    const externalUsers = enrichedUsers.filter(user => user.isExternal === true);
    const unknownUserTypes = enrichedUsers.filter(user => !user.isWorkforce && !user.isExternal).length;
    const adminUsers = workforceUsers.filter(user => user.hasAdminRole).length;
    const mfaEnabledUsers = workforceUsers.filter(user => user.mfaEnabled).length;
    const mfaMissingUsers = workforceUsers.filter(user => user.mfaEnabled === false).length;
    const mfaUnknownUsers = workforceUsers.length - mfaEnabledUsers - mfaMissingUsers;
    const mfaPercentage = workforceUsers.length ? ((mfaEnabledUsers / workforceUsers.length) * 100).toFixed(1) : '0.0';
    const highRiskUsers = enrichedUsers.filter(user => user.riskLevel === 'HIGH').length;
    const mediumRiskUsers = enrichedUsers.filter(user => user.riskLevel === 'MEDIUM').length;
    const activeUsers24h = enrichedUsers.filter(user => user.lastSignIn.daysSince <= 1).length;
    const usersWithCompleteProfile = enrichedUsers.filter(user =>
        user.jobTitle !== 'No Title' && user.mobilePhone !== 'N/A'
    ).length;
    const privilegedUsersWithoutMFA = workforceUsers.filter(user => user.hasAdminRole && !user.mfaEnabled).length;

    let identityRiskScore = 0;
    enrichedUsers.forEach(user => {
        if (user.hasAdminRole && !user.mfaEnabled) identityRiskScore += 40;
        if (user.lastSignIn.daysSince > 999) identityRiskScore += 25;
        if (user.authMethodCount === 0) identityRiskScore += 20;
        if (user.isExternal) identityRiskScore += 15;
        if (user.riskLevel === 'MEDIUM') identityRiskScore += 10;
        if (user.riskLevel === 'HIGH') identityRiskScore += 30;
    });
    identityRiskScore = totalUsers
        ? Math.min(100, Math.round((identityRiskScore / (totalUsers * 40)) * 100))
        : 0;

    const inactiveBreakdown = {
        '0-7days': enrichedUsers.filter(user => user.lastSignIn.daysSince >= 0 && user.lastSignIn.daysSince <= 7).length,
        '7-30days': enrichedUsers.filter(user => user.lastSignIn.daysSince > 7 && user.lastSignIn.daysSince <= 30).length,
        '30-90days': enrichedUsers.filter(user => user.lastSignIn.daysSince > 30 && user.lastSignIn.daysSince <= 90).length,
        '90+days': enrichedUsers.filter(user => user.lastSignIn.daysSince > 90).length
    };
    const deviceTrustAnalysis = { managed: 0, unmanaged: 0, unknown: 0 };
    enrichedUsers.forEach(user => {
        const device = String(user.lastSignIn?.device || '').toLowerCase();
        if (!device || device.includes('unknown')) deviceTrustAnalysis.unknown += 1;
        else if (device.includes('managed') || device.includes('iphone') || device.includes('ipad') || device.includes('android')) deviceTrustAnalysis.managed += 1;
        else deviceTrustAnalysis.unmanaged += 1;
    });
    const authenticationStrength = { passwordOnly: 0, basicMFA: 0, strongMFA: 0 };
    enrichedUsers.forEach(user => {
        if (user.authMethodCount <= 1) authenticationStrength.passwordOnly += 1;
        else if (user.mfaEnabled) authenticationStrength.basicMFA += 1;
    });
    authenticationStrength.strongMFA = enrichedUsers.filter(user => user.authMethodCount > 2).length;

    const roleDistribution = {};
    enrichedUsers.forEach(user => user.roles.forEach(role => {
        roleDistribution[role.name] = (roleDistribution[role.name] || 0) + 1;
    }));
    const topRoles = Object.entries(roleDistribution)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([role, count]) => ({ role, count }));
    const profileCompleteness = totalUsers ? Math.round((enrichedUsers.filter(user => user.jobTitle !== 'No Title').length / totalUsers) * 100) : 0;
    const authCompleteness = totalUsers ? Math.round((mfaEnabledUsers / totalUsers) * 100) : 0;
    const activityCompleteness = totalUsers ? Math.round((enrichedUsers.filter(user => user.lastSignIn.daysSince <= 90).length / totalUsers) * 100) : 0;
    const identityHygieneScore = Math.round((profileCompleteness + authCompleteness + activityCompleteness) / 3);
    const systemHealth = {
        performance: totalUsers ? Math.round((enrichedUsers.filter(user => user.lastSignIn.status === 'Success').length / totalUsers) * 100) : 0,
        availability: totalUsers ? Math.round((activeUsers24h / totalUsers) * 100) : 0,
        security: totalUsers ? Math.round((mfaEnabledUsers / totalUsers) * 100) : 0,
        compliance: totalUsers ? Math.round((usersWithCompleteProfile / totalUsers) * 100) : 0,
        backup: totalUsers ? Math.round((enrichedUsers.filter(user => user.authMethodCount > 1).length / totalUsers) * 100) : 0
    };
    const insights = {
        adminsWithoutMFA: enrichedUsers.filter(user => user.flags.adminWithoutMFA),
        inactiveUsers: enrichedUsers.filter(user => user.flags.inactiveOver30Days),
        newLocationLogins: enrichedUsers.filter(user => user.flags.newLocationLogin)
    };
    const deviceBreakdown = {};
    const locationBreakdown = {};
    enrichedUsers.forEach(user => {
        const device = String(user.lastSignIn?.device || '').toLowerCase();
        if (device) deviceBreakdown[device] = (deviceBreakdown[device] || 0) + 1;
        const location = user.lastSignIn?.location;
        if (location && location !== 'No sign-in') locationBreakdown[location] = (locationBreakdown[location] || 0) + 1;
    });
    const topLocations = Object.entries(locationBreakdown)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([location, count]) => ({ location, count }));
    const securityScore = Math.round(
        (Number(mfaPercentage) * 0.4) +
        ((100 - (totalUsers ? (highRiskUsers / totalUsers * 100) : 0)) * 0.3) +
        ((adminUsers <= 5 ? 100 : 50) * 0.3)
    );

    return {
        success: true,
        tenant: tenantKey,
        fetchedAt: collectedAt.toISOString(),
        summary: {
            totalUsers,
            workforceUsers: workforceUsers.length,
            externalUsers: externalUsers.length,
            unknownUserTypes,
            activeUsers24h,
            activeUsersPercentage: totalUsers ? Math.round((activeUsers24h / totalUsers) * 100) : 0,
            adminUsers,
            mfaEnabledPercentage: mfaPercentage,
            mfaEnabledUsers,
            mfaMissingUsers,
            mfaUnknownUsers,
            highRiskUsers,
            highRiskBreakdown: {
                adminWithoutMFA: privilegedUsersWithoutMFA,
                neverSignedIn: enrichedUsers.filter(user => user.lastSignIn.daysSince > 999).length,
                externalUser: externalUsers.length
            },
            securityScore,
            identityRiskScore,
            identityHygieneScore,
            mediumRiskUsers,
            privilegedUsersWithoutMFA
        },
        systemHealth,
        users: enrichedUsers,
        riskDistribution: { HIGH: highRiskUsers, MEDIUM: mediumRiskUsers, SAFE: totalUsers - highRiskUsers - mediumRiskUsers },
        insights,
        inactiveBreakdown,
        deviceTrustAnalysis,
        authenticationStrength,
        topRoles,
        hygieneLevels: { profileCompleteness, authCompleteness, activityCompleteness },
        signInPatterns: {
            topLocations,
            deviceBreakdown,
            avgSignInsPerUser: totalUsers ? signIns.length / totalUsers : 0
        },
        roleInsights: {
            globalAdmins: enrichedUsers.filter(user => user.roles.some(role => role.name.toLowerCase().includes('global'))).length,
            privilegedUsers: enrichedUsers.filter(user => user.roles.length > 0).length,
            usersWithMultipleRoles: enrichedUsers.filter(user => user.roles.length > 1).length,
            roleDistribution: topRoles
        }
    };
}

module.exports = { buildIdentityDashboardPayload };
