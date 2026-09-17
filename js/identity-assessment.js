(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.StackCTRLIdentity = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const MFA_SCOPE = 'entra_members_v1';
    const MFA_SCOPE_LABEL = 'Workforce MFA registration (Entra Members)';

    // Native Entra userType is authoritative. Legacy email/isExternal guesses are not evidence.
    function userType(user = {}) {
        const value = String(user.userType ?? user.user_type ?? user.UserType ?? '').trim().toLowerCase();
        return value === 'member' ? 'Member' : value === 'guest' ? 'Guest' : 'Unknown';
    }
    function isWorkforce(user) { return userType(user) === 'Member'; }
    function isGuest(user) { return userType(user) === 'Guest'; }
    function typeLabel(user) {
        return isWorkforce(user) ? 'Workforce (Member)' : isGuest(user) ? 'External (Guest)' : 'User type unknown';
    }
    function mfaValue(user = {}) {
        if (['unknown', 'unavailable', 'stale'].includes(String(user.mfaStatus || '').toLowerCase())) return null;
        const value = user.mfaEnabled ?? user.mfa_enabled ?? user.mfaRegistered ?? user.hasMfa;
        if (value === true || value === 1 || value === '1' || value === 'true') return true;
        if (value === false || value === 0 || value === '0' || value === 'false') return false;
        return null;
    }
    function isMissingMfa(user) { return isWorkforce(user) && mfaValue(user) === false; }
    function mfaLabel(user) {
        if (isGuest(user)) return 'Outside workforce scope';
        if (!isWorkforce(user)) return 'Scope unknown';
        const value = mfaValue(user);
        return value === true ? 'Registered' : value === false ? 'Not registered' : 'Unknown';
    }
    function isPrivileged(user = {}) {
        let roles = user.roles || user.assignedRoles || user.roleNames || [];
        if (typeof roles === 'string') {
            try { roles = JSON.parse(roles); } catch (_) { roles = []; }
        }
        return user.hasAdminRole === true || user.isPrivileged === true || (Array.isArray(roles) && roles.some(role =>
            /(admin|global|privileged|security|directory|exchange|sharepoint|compliance)/i.test(
                typeof role === 'string' ? role : role?.name || role?.displayName || role?.roleName || ''
            )
        ));
    }
    function assessWorkforce(users = []) {
        const workforce = users.filter(isWorkforce);
        const privileged = workforce.filter(isPrivileged);
        const mfaEnabled = workforce.filter(user => mfaValue(user) === true).length;
        const mfaMissing = workforce.filter(isMissingMfa).length;
        const mfaUnknown = workforce.length - mfaEnabled - mfaMissing;
        const unknownUserTypes = users.filter(user => userType(user) === 'Unknown').length;
        const privilegedMfaUnknown = privileged.filter(user => mfaValue(user) === null).length;
        const adminsWithoutMfa = privileged.filter(isMissingMfa).length;
        const complete = workforce.length > 0 && mfaUnknown === 0 && unknownUserTypes === 0;
        return {
            mfaScope: MFA_SCOPE,
            mfaScopeLabel: MFA_SCOPE_LABEL,
            workforceUsers: workforce.length,
            externalUsers: users.filter(isGuest).length,
            unknownUserTypes,
            mfaEnabled, mfaMissing, mfaUnknown,
            mfaCoverage: complete ? Math.round((mfaEnabled / workforce.length) * 100) : null,
            mfaAssessmentStatus: unknownUserTypes || mfaUnknown ? 'incomplete' : workforce.length ? 'complete' : 'not_applicable',
            privilegedWorkforceUsers: privileged.length,
            privilegedGuestUsers: users.filter(user => isGuest(user) && isPrivileged(user)).length,
            privilegedMfaUnknown,
            adminsWithoutMfa,
            privilegedMfaCoverage: privileged.length && !privilegedMfaUnknown && !unknownUserTypes
                ? Math.round(((privileged.length - adminsWithoutMfa) / privileged.length) * 100) : null
        };
    }
    function methodType(method) { return String(method?.['@odata.type'] || '').split('.').pop().toLowerCase(); }
    function hasMfaMethod(methods) {
        if (!Array.isArray(methods)) return null;
        return methods.some(method => [
            'microsoftauthenticatorauthenticationmethod', 'phoneauthenticationmethod',
            'fido2authenticationmethod', 'windowshelloforbusinessauthenticationmethod',
            'softwareoathauthenticationmethod', 'hardwareoathauthenticationmethod',
            'platformcredentialauthenticationmethod'
        ].includes(methodType(method)));
    }
    function hasPhishingResistantMethod(methods) {
        if (!Array.isArray(methods)) return null;
        return methods.some(method => [
            'fido2authenticationmethod', 'windowshelloforbusinessauthenticationmethod',
            'platformcredentialauthenticationmethod'
        ].includes(methodType(method)));
    }
    function normalizeUser(user = {}) {
        const type = userType(user);
        const mfa = mfaValue(user);
        return { ...user, userType: type, isExternal: type === 'Guest', isWorkforce: type === 'Member',
            mfaEnabled: mfa, mfaStatus: mfa === null ? 'unknown' : mfa ? 'registered' : 'not_registered' };
    }
    function scopeDescription(metrics) {
        const coverage = metrics.mfaCoverage == null ? 'Coverage unavailable' : `Coverage ${metrics.mfaCoverage}%`;
        return `${metrics.mfaEnabled} of ${metrics.workforceUsers} workforce accounts have registered MFA. ` +
            `${metrics.mfaMissing} not registered; ${metrics.mfaUnknown} unknown. ${coverage}. ` +
            `${metrics.externalUsers} Guests excluded; ${metrics.unknownUserTypes} user types unknown. ` +
            'Registration evidence does not confirm MFA enforcement.';
    }
    return { MFA_SCOPE, MFA_SCOPE_LABEL, userType, isWorkforce, isGuest, typeLabel, mfaValue,
        isMissingMfa, mfaLabel, isPrivileged, assessWorkforce, hasMfaMethod, hasPhishingResistantMethod,
        normalizeUser, scopeDescription };
});
