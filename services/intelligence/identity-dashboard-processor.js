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

function identityRoleName(role) {
    return typeof role === 'string' ? role : role?.name || role?.displayName || '';
}

async function buildIdentityDashboardPayload({
    tenantKey = 'sunbird',
    sourceTenantId = null,
    users = [],
    roleAssignments = [],
    signIns = [],
    previousUsers = [],
    roleAssignmentsStatus = 'complete',
    signInCollectionStatus = 'complete',
    signInWindowDays = 30,
    signInRecordCount = signIns.length,
    collectionWarnings = [],
    loadAuthMethods,
    hasRealMfaMethod,
    mapWithConcurrency = defaultMapWithConcurrency,
    concurrency = 8,
    now = () => new Date()
} = {}) {
    if (typeof loadAuthMethods !== 'function' || typeof hasRealMfaMethod !== 'function') {
        throw new Error('Identity dashboard processing requires authentication-method helpers');
    }

    const userRoleMap = new Map();
    roleAssignments.forEach(assignment => {
        const principalId = String(assignment.principalId || '').trim();
        if (!principalId) return;
        if (!userRoleMap.has(principalId)) userRoleMap.set(principalId, []);
        userRoleMap.get(principalId).push({
            id: assignment.roleDefinition?.id,
            name: assignment.roleDefinition?.displayName || 'Unknown Role'
        });
    });

    const previousById = new Map();
    const previousByUpn = new Map();
    previousUsers.forEach(user => {
        if (user?.id) previousById.set(String(user.id), user);
        const upn = String(user?.userPrincipalName || '').trim().toLowerCase();
        if (upn) previousByUpn.set(upn, user);
    });

    const currentById = new Map();
    const currentByUpn = new Map();
    users.forEach(user => {
        if (user?.id) currentById.set(String(user.id), user);
        const upn = String(user?.userPrincipalName || '').trim().toLowerCase();
        if (upn) currentByUpn.set(upn, user);
    });

    const latestSignInMap = new Map();
    const latestFailedSignInMap = new Map();
    const matchedSignIns = [];
    signIns.forEach(signIn => {
        const user = signIn.userId
            ? currentById.get(String(signIn.userId))
            : currentByUpn.get(String(signIn.userPrincipalName || '').trim().toLowerCase());
        const createdAt = signIn.createdDateTime ? new Date(signIn.createdDateTime) : null;
        if (!user || !createdAt || Number.isNaN(createdAt.getTime())) return;
        const key = String(user.id || user.userPrincipalName || '');
        const errorCode = signIn.status?.errorCode;
        const status = errorCode === 0 || errorCode === '0'
            ? 'Success'
            : errorCode === null || errorCode === undefined ? 'Unknown' : 'Failed';
        const locationParts = [signIn.location?.city, signIn.location?.countryOrRegion].filter(Boolean);
        const event = {
            dateTime: createdAt.toISOString(),
            appDisplayName: signIn.appDisplayName || null,
            clientAppUsed: signIn.clientAppUsed || null,
            ipAddress: signIn.ipAddress || null,
            location: locationParts.length ? locationParts.join(', ') : null,
            device: signIn.deviceDetail?.displayName || null,
            status,
            errorCode: errorCode ?? null,
            failureReason: signIn.status?.failureReason || null
        };
        matchedSignIns.push({ user, event });
        const latest = latestSignInMap.get(key);
        if (!latest || createdAt.getTime() > Date.parse(latest.dateTime)) latestSignInMap.set(key, event);
        if (status === 'Failed') {
            const latestFailed = latestFailedSignInMap.get(key);
            if (!latestFailed || createdAt.getTime() > Date.parse(latestFailed.dateTime)) latestFailedSignInMap.set(key, event);
        }
    });

    const collectedAt = now();
    const enrichedUsers = await mapWithConcurrency(users, concurrency, async user => {
        const key = String(user.id || user.userPrincipalName || '');
        const previousByName = previousByUpn.get(String(user.userPrincipalName || '').trim().toLowerCase());
        const previous = (user.id && previousById.get(String(user.id))) ||
            ((!user.id || !previousByName?.id) ? previousByName : null);
        const previousLastSignIn = previous?.lastSignIn;
        const assignedRoles = user.id ? userRoleMap.get(String(user.id)) : null;
        const rolesStatus = roleAssignmentsStatus === 'complete'
            ? 'complete'
            : Array.isArray(previous?.roles) ? 'stale' : 'unavailable';
        const userRoles = roleAssignmentsStatus === 'complete'
            ? (assignedRoles || [])
            : (Array.isArray(previous?.roles) ? previous.roles : []);
        const hasAdminRole = rolesStatus === 'unavailable'
            ? null
            : userRoles.some(role => {
                const name = identityRoleName(role).toLowerCase();
                return name.includes('admin') || name.includes('global');
            });
        let mfa = null;
        const mfaCollectionStartedAt = now().toISOString();
        try {
            const methods = await loadAuthMethods(user);
            if (Array.isArray(methods)) {
                mfa = { enabled: hasRealMfaMethod(methods), count: methods.length, observedAt: mfaCollectionStartedAt };
            } else mfa = methods;
        } catch (_) {
            // MFA is optional enrichment; preserve the user inventory and expose its unavailable state.
        }
        const mfaStatus = typeof mfa?.enabled === 'boolean' ? 'complete' : 'unavailable';
        const hasMFA = mfa?.enabled ?? null;
        const currentSignIn = latestSignInMap.get(key) || null;
        const currentFailure = latestFailedSignInMap.get(key);
        const priorFailure = previous?.failedSignIn;
        const latestFailure = priorFailure?.dateTime && (!currentFailure || Date.parse(priorFailure.dateTime) > Date.parse(currentFailure.dateTime))
            ? { ...priorFailure, observationStatus: 'stale' } : currentFailure || null;
        const previousEvent = previousLastSignIn?.dateTime
            ? {
                dateTime: previousLastSignIn.dateTime,
                appDisplayName: previousLastSignIn.appDisplayName || null,
                clientAppUsed: previousLastSignIn.clientAppUsed || null,
                ipAddress: previousLastSignIn.ipAddress || null,
                location: previousLastSignIn.location || null,
                device: previousLastSignIn.device || null,
                status: previousLastSignIn.status || 'Unknown',
                errorCode: previousLastSignIn.errorCode ?? null,
                failureReason: previousLastSignIn.failureReason || null
            }
            : null;
        const lastSignIn = previousEvent && (!currentSignIn || Date.parse(previousEvent.dateTime) > Date.parse(currentSignIn.dateTime))
            ? previousEvent : currentSignIn;
        const lastSignInDate = lastSignIn?.dateTime ? new Date(lastSignIn.dateTime) : null;
        const daysSinceSignIn = lastSignInDate && !Number.isNaN(lastSignInDate.getTime())
            ? Math.max(0, Math.floor((collectedAt.getTime() - lastSignInDate.getTime()) / 86400000))
            : null;
        const signInStatus = currentSignIn && lastSignIn === currentSignIn
            ? 'observed'
            : previousEvent
                ? (signInCollectionStatus === 'complete' ? 'no_recent_sign_in' : 'stale')
                : signInCollectionStatus === 'complete'
                    ? 'no_recorded_sign_in'
                    : signInCollectionStatus;
        let riskLevel = 'SAFE';
        if (rolesStatus === 'complete' && hasAdminRole === true && mfaStatus === 'complete' && hasMFA === false) riskLevel = 'HIGH';
        else if (daysSinceSignIn !== null && daysSinceSignIn > 30) riskLevel = 'MEDIUM';
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
            rolesStatus,
            isExternal: isGuest,
            isWorkforce,
            mfaEnabled: hasMFA,
            mfaStatus,
            mfaObservedAt: mfaStatus === 'complete' ? mfa.observedAt : null,
            mfaSourceTenantId: mfaStatus === 'complete' ? sourceTenantId : null,
            lastVerifiedMfa: mfa?.lastVerifiedMfa,
            authMethodCount: mfa?.count ?? null,
            riskLevel,
            accountEnabled: user.accountEnabled !== false,
            lastSignIn: {
                dateTime: lastSignInDate?.toISOString() || null,
                daysSince: daysSinceSignIn,
                location: lastSignIn?.location || null,
                device: lastSignIn?.device || null,
                appDisplayName: lastSignIn?.appDisplayName || null,
                clientAppUsed: lastSignIn?.clientAppUsed || null,
                status: lastSignIn?.status || null,
                errorCode: lastSignIn?.errorCode ?? null,
                failureReason: lastSignIn?.failureReason || null,
                observationStatus: signInStatus,
                windowDays: signInWindowDays
            },
            failedSignIn: latestFailure,
            flags: {
                adminWithoutMFA: rolesStatus === 'complete' && hasAdminRole === true && mfaStatus === 'complete' && hasMFA === false,
                inactiveOver30Days: daysSinceSignIn !== null && daysSinceSignIn > 30,
                newLocationLogin: false
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
    const mfaAssessmentStatus = mfaUnknownUsers ? 'incomplete' : workforceUsers.length ? 'complete' : 'not_applicable';
    const mfaPercentage = workforceUsers.length && !mfaUnknownUsers
        ? ((mfaEnabledUsers / workforceUsers.length) * 100).toFixed(1)
        : null;
    const highRiskUsers = enrichedUsers.filter(user => user.riskLevel === 'HIGH').length;
    const mediumRiskUsers = enrichedUsers.filter(user => user.riskLevel === 'MEDIUM').length;
    const activityCutoff = collectedAt.getTime() - 86400000;
    const activeUsers24h = signInCollectionStatus === 'complete'
        ? enrichedUsers.filter(user => {
            const observedAt = Date.parse(latestSignInMap.get(String(user.id || user.userPrincipalName || ''))?.dateTime);
            return observedAt >= activityCutoff && observedAt <= collectedAt.getTime();
        }).length
        : null;
    const usersWithCompleteProfile = enrichedUsers.filter(user =>
        user.jobTitle !== 'No Title' && user.mobilePhone !== 'N/A'
    ).length;
    const privilegedUsersWithoutMFA = workforceUsers.filter(user => user.flags.adminWithoutMFA).length;

    let identityRiskScore = 0;
    enrichedUsers.forEach(user => {
        if (user.flags.adminWithoutMFA) identityRiskScore += 40;
        if (user.authMethodCount === 0) identityRiskScore += 20;
        if (user.isExternal) identityRiskScore += 15;
        if (user.riskLevel === 'MEDIUM') identityRiskScore += 10;
        if (user.riskLevel === 'HIGH') identityRiskScore += 30;
    });
    identityRiskScore = totalUsers
        ? Math.min(100, Math.round((identityRiskScore / (totalUsers * 40)) * 100))
        : 0;

    const inactiveBreakdown = {
        '0-7days': enrichedUsers.filter(user => user.lastSignIn.daysSince !== null && user.lastSignIn.daysSince <= 7).length,
        '7-30days': enrichedUsers.filter(user => user.lastSignIn.daysSince !== null && user.lastSignIn.daysSince > 7 && user.lastSignIn.daysSince <= 30).length,
        '30-90days': enrichedUsers.filter(user => user.lastSignIn.daysSince !== null && user.lastSignIn.daysSince > 30 && user.lastSignIn.daysSince <= 90).length,
        '90+days': enrichedUsers.filter(user => user.lastSignIn.daysSince !== null && user.lastSignIn.daysSince > 90).length
    };
    const deviceTrustAnalysis = { managed: 0, unmanaged: 0, unknown: 0 };
    enrichedUsers.forEach(user => {
        const device = String(user.lastSignIn?.device || '').toLowerCase();
        if (!user.lastSignIn?.dateTime) return;
        if (!device) deviceTrustAnalysis.unknown += 1;
        else if (device.includes('managed') || device.includes('iphone') || device.includes('ipad') || device.includes('android')) deviceTrustAnalysis.managed += 1;
        else deviceTrustAnalysis.unmanaged += 1;
    });
    const authenticationStrength = { passwordOnly: 0, basicMFA: 0, strongMFA: 0 };
    enrichedUsers.forEach(user => {
        if (user.mfaStatus !== 'complete') return;
        if (user.authMethodCount <= 1) authenticationStrength.passwordOnly += 1;
        else if (user.mfaEnabled) authenticationStrength.basicMFA += 1;
    });
    authenticationStrength.strongMFA = enrichedUsers.filter(user => user.mfaStatus === 'complete' && user.authMethodCount > 2).length;

    const roleDistribution = {};
    enrichedUsers.forEach(user => user.roles.forEach(role => {
        const name = identityRoleName(role);
        if (!name) return;
        roleDistribution[name] = (roleDistribution[name] || 0) + 1;
    }));
    const topRoles = Object.entries(roleDistribution)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([role, count]) => ({ role, count }));
    const profileCompleteness = totalUsers ? Math.round((enrichedUsers.filter(user => user.jobTitle !== 'No Title').length / totalUsers) * 100) : 0;
    const authCompleteness = mfaAssessmentStatus === 'complete' && totalUsers ? Math.round((mfaEnabledUsers / totalUsers) * 100) : null;
    const activityCompleteness = signInCollectionStatus === 'complete' && totalUsers
        ? Math.round((enrichedUsers.filter(user => user.lastSignIn.daysSince !== null && user.lastSignIn.daysSince <= 90).length / totalUsers) * 100)
        : null;
    const identityHygieneScore = authCompleteness === null || activityCompleteness === null
        ? null
        : Math.round((profileCompleteness + authCompleteness + activityCompleteness) / 3);
    const systemHealth = {
        performance: signInCollectionStatus === 'complete' && totalUsers
            ? Math.round((enrichedUsers.filter(user => user.lastSignIn.status === 'Success').length / totalUsers) * 100)
            : null,
        availability: activeUsers24h !== null && totalUsers ? Math.round((activeUsers24h / totalUsers) * 100) : null,
        security: authCompleteness,
        compliance: totalUsers ? Math.round((usersWithCompleteProfile / totalUsers) * 100) : 0,
        backup: mfaAssessmentStatus === 'complete' && totalUsers
            ? Math.round((enrichedUsers.filter(user => user.authMethodCount > 1).length / totalUsers) * 100)
            : null
    };
    const insights = {
        adminsWithoutMFA: enrichedUsers.filter(user => user.flags.adminWithoutMFA),
        inactiveUsers: enrichedUsers.filter(user => user.flags.inactiveOver30Days),
        failedSignInUsers: enrichedUsers.filter(user => user.failedSignIn?.status === 'Failed')
    };
    const deviceBreakdown = {};
    const locationBreakdown = {};
    enrichedUsers.forEach(user => {
        const device = String(user.lastSignIn?.device || '').toLowerCase();
        if (device && user.lastSignIn?.dateTime) deviceBreakdown[device] = (deviceBreakdown[device] || 0) + 1;
        const location = user.lastSignIn?.location;
        if (location && user.lastSignIn?.dateTime) locationBreakdown[location] = (locationBreakdown[location] || 0) + 1;
    });
    const topLocations = Object.entries(locationBreakdown)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([location, count]) => ({ location, count }));
    const securityScore = mfaPercentage === null ? null : Math.round(
        (Number(mfaPercentage) * 0.4) +
        ((100 - (totalUsers ? (highRiskUsers / totalUsers * 100) : 0)) * 0.3) +
        ((adminUsers <= 5 ? 100 : 50) * 0.3)
    );
    const fetchedAt = now();

    return {
        success: true,
        tenant: tenantKey,
        sourceTenantId,
        fetchedAt: fetchedAt.toISOString(),
        roleAssignmentsStatus,
        signInCollection: {
            status: signInCollectionStatus,
            windowDays: signInWindowDays,
            recordCount: signInRecordCount,
            warnings: collectionWarnings
        },
        warnings: collectionWarnings,
        mfaCollection: {
            status: mfaAssessmentStatus,
            failedUserCount: enrichedUsers.filter(user => user.mfaStatus !== 'complete').length
        },
        summary: {
            totalUsers,
            workforceUsers: workforceUsers.length,
            externalUsers: externalUsers.length,
            unknownUserTypes,
            activeUsers24h,
            activeUsers24hStatus: signInCollectionStatus,
            activeUsersPercentage: activeUsers24h !== null && totalUsers ? Math.round((activeUsers24h / totalUsers) * 100) : null,
            adminUsers,
            mfaEnabledPercentage: mfaPercentage,
            mfaAssessmentStatus,
            mfaEnabledUsers,
            mfaMissingUsers,
            mfaUnknownUsers,
            highRiskUsers,
            highRiskBreakdown: {
                adminWithoutMFA: privilegedUsersWithoutMFA,
                noRecordedSignIn: enrichedUsers.filter(user => user.lastSignIn.observationStatus === 'no_recorded_sign_in').length,
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
            avgSignInsPerUser: signInCollectionStatus === 'complete' && totalUsers ? matchedSignIns.length / totalUsers : null,
            failedSignInCount: matchedSignIns.filter(({ event }) => event.status === 'Failed').length
        },
        roleInsights: {
            globalAdmins: enrichedUsers.filter(user => user.roles.some(role => identityRoleName(role).toLowerCase().includes('global'))).length,
            privilegedUsers: enrichedUsers.filter(user => user.roles.length > 0).length,
            usersWithMultipleRoles: enrichedUsers.filter(user => user.roles.length > 1).length,
            roleDistribution: topRoles
        }
    };
}

module.exports = { buildIdentityDashboardPayload };
