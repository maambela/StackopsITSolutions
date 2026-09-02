/* ============================================================================
 * StackOps Mock Dashboard
 * ----------------------------------------------------------------------------
 * Gives ONE tenant (user id 36 / company id 5) the exact Sunbird client-portal
 * experience, but driven entirely by the hard-coded mock data in this file -
 * no API calls leave the page.
 *
 * How it works:
 *  1. `window.isStackOpsMockUser()` - true only for user 36 / company 5.
 *  2. `js/clientportal.js`'s `isSunbirdUser()` gains one extra clause so it also
 *     returns true for the mock user. That lights up every Sunbird layout gate
 *     (66 call sites) with zero further edits.
 *  3. This file installs a scoped `window.fetch` wrapper. For the mock user, any
 *     request to a known dashboard endpoint is answered from `STACKOPS_MOCK`
 *     below. Everything else (auth, chatbot, other users) hits the real server
 *     unchanged.
 *  4. The header logo is swapped to the StackOps logo (see
 *     `updateSunbirdLogoVisibility()` in clientportal.js).
 *
 * Nothing here runs for real Sunbird / Sedfa / any other user.
 * ==========================================================================*/
(function () {
  'use strict';

  var MOCK_USER_ID = 36;
  var MOCK_COMPANY_ID = 5;

  function isStackOpsMockUser() {
    try {
      var raw = localStorage.getItem('user');
      if (!raw) return false;
      var u = JSON.parse(raw);
      var id = Number(u && u.id);
      var companyId = Number(
        (u && (u.companyId != null ? u.companyId : u.company_id != null ? u.company_id : u.company && u.company.id))
      );
      return id === MOCK_USER_ID && companyId === MOCK_COMPANY_ID;
    } catch (e) {
      return false;
    }
  }
  window.isStackOpsMockUser = isStackOpsMockUser;

  /* ------------------------------------------------------------------ */
  /* Deterministic helpers so the mock data is stable between reloads   */
  /* ------------------------------------------------------------------ */
  function seeded(seed) {
    var s = seed % 2147483647;
    if (s <= 0) s += 2147483646;
    return function () {
      s = (s * 16807) % 2147483647;
      return (s - 1) / 2147483646;
    };
  }
  var rnd = seeded(3605);
  function pick(list, r) { return list[Math.floor((r == null ? rnd() : r) * list.length) % list.length]; }
  function daysAgoISO(days) { return new Date(Date.now() - days * 86400000).toISOString(); }
  function hoursAgoISO(hours) { return new Date(Date.now() - hours * 3600000).toISOString(); }

  var FIRST = ['Amara', 'Thabo', 'Lerato', 'Sipho', 'Naledi', 'Kagiso', 'Zanele', 'Bongani', 'Palesa', 'Mandla',
    'Nomsa', 'Tshepo', 'Refilwe', 'Kabelo', 'Lindiwe', 'Tumelo', 'Ayanda', 'Katlego', 'Nokuthula', 'Sibusiso',
    'Dineo', 'Themba', 'Zodwa', 'Lungelo', 'Precious', 'Andile', 'Bianca', 'Marius', 'Chantelle', 'Ruan',
    'Farhana', 'Yusuf', 'Priya', 'Deon', 'Gugu', 'Karabo', 'Hendrik', 'Zinhle', 'Ntando', 'Musa'];
  var LAST = ['Sandani', 'Mokoena', 'Nkosi', 'Dlamini', 'Khumalo', 'Botha', 'Van Wyk', 'Naidoo', 'Pillay', 'Mahlangu',
    'Ndlovu', 'Molefe', 'Zulu', 'Sithole', 'Jacobs', 'Petersen', 'Maluleke', 'Radebe', 'Cele', 'Mabaso'];
  var TITLES = ['Software Engineer', 'IT Administrator', 'Finance Manager', 'HR Business Partner', 'Operations Lead',
    'Support Analyst', 'Security Analyst', 'Account Executive', 'Project Manager', 'Data Analyst', 'Systems Architect',
    'Service Desk Agent', 'Compliance Officer', 'Procurement Specialist', 'Marketing Coordinator'];
  var LOCATIONS = ['Johannesburg, ZA', 'Cape Town, ZA', 'Durban, ZA', 'Pretoria, ZA', 'Remote', 'London, GB', 'Amsterdam, NL'];
  var DEVICES = ['Windows 11 Laptop', 'MacBook Pro', 'iPhone 15', 'Samsung Galaxy S23', 'Windows 10 Desktop', 'iPad Air'];
  var ADMIN_ROLES = ['Global Administrator', 'Security Administrator', 'Exchange Administrator', 'SharePoint Administrator',
    'User Administrator', 'Helpdesk Administrator'];

  /* ---- Identity users (93 total, 21 active in 24h, 6 admins) --------- */
  function buildIdentityUsers() {
    var TOTAL = 93, ACTIVE_24H = 21, ADMINS = 6, HIGH_RISK = 4, MEDIUM_RISK = 11;
    var users = [];
    for (var i = 0; i < TOTAL; i++) {
      var first = FIRST[i % FIRST.length];
      var last = LAST[(i * 7) % LAST.length];
      var name = first + ' ' + last;
      var upn = (first + '.' + last).toLowerCase().replace(/[^a-z.]/g, '') + i + '@stackopsdemo.co.za';
      var isAdmin = i < ADMINS;
      var daysSince = i < ACTIVE_24H ? 0 : i < 55 ? 3 + (i % 20) : 40 + (i % 120);
      var mfaEnabled = !(i === 2 || i === 4 || (i > 30 && i % 9 === 0));
      var risk = i < HIGH_RISK ? 'HIGH' : i < HIGH_RISK + MEDIUM_RISK ? 'MEDIUM' : 'SAFE';
      var authMethods = mfaEnabled ? (i % 3 === 0 ? 3 : 2) : 1;
      var lastSignIn = daysAgoISO(daysSince) ;
      var roles = isAdmin ? [ADMIN_ROLES[i % ADMIN_ROLES.length]] : [];
      if (i === 0) roles = ['Global Administrator', 'Security Administrator'];
      users.push({
        id: 'usr-' + (1000 + i),
        displayName: name,
        givenName: first,
        surname: last,
        mail: upn,
        userPrincipalName: upn,
        jobTitle: TITLES[i % TITLES.length],
        department: pick(['IT', 'Finance', 'Operations', 'Sales', 'HR', 'Security', 'Executive'], (i % 7) / 7),
        mobilePhone: '+27 82 ' + (100 + i) + ' ' + (2000 + i * 3),
        officeLocation: LOCATIONS[i % LOCATIONS.length],
        accountEnabled: i !== 88,
        isExternal: i === 90 || i === 91,
        createdDateTime: daysAgoISO(120 + i * 3),
        roles: roles,
        mfaEnabled: mfaEnabled,
        authMethodCount: authMethods,
        authMethods: mfaEnabled ? ['Microsoft Authenticator', authMethods > 2 ? 'FIDO2 security key' : 'SMS'] : ['Password only'],
        riskLevel: risk,
        riskState: risk === 'HIGH' ? 'atRisk' : risk === 'MEDIUM' ? 'confirmedCompromised' : 'none',
        lastSignInDateTime: lastSignIn,
        signInActivity: { lastSignInDateTime: lastSignIn, lastNonInteractiveSignInDateTime: lastSignIn },
        lastSignIn: {
          dateTime: lastSignIn,
          daysSince: daysSince,
          location: LOCATIONS[i % LOCATIONS.length],
          device: (i % 11 === 0 && daysSince > 60) ? 'Unknown Device' : DEVICES[i % DEVICES.length],
          ipAddress: '196.25.' + (i % 255) + '.' + ((i * 13) % 255),
          status: (i === 3 || i === 7 || i === 19) ? 'Failure' : 'Success',
          failureReason: (i === 3 || i === 7 || i === 19) ? 'Invalid credentials' : ''
        }
      });
    }
    return users;
  }

  function buildRoleAssignments(users) {
    var out = [];
    users.filter(function (u) { return u.roles && u.roles.length; }).forEach(function (u) {
      u.roles.forEach(function (role) {
        out.push({
          userId: u.id, userDisplayName: u.displayName, userPrincipalName: u.userPrincipalName,
          roleName: role, roleId: 'role-' + role.replace(/\s+/g, '-').toLowerCase(),
          assignedDateTime: daysAgoISO(90), scope: 'Directory'
        });
      });
    });
    return out;
  }

  var IDENTITY_USERS = buildIdentityUsers();
  var IDENTITY_ROLES = buildRoleAssignments(IDENTITY_USERS);
  var IDENTITY_ADMIN_COUNT = IDENTITY_USERS.filter(function (u) { return u.roles.length; }).length;
  var IDENTITY_ACTIVE_24H = IDENTITY_USERS.filter(function (u) { return u.lastSignIn.daysSince <= 1; }).length;
  var IDENTITY_MFA_MISSING = IDENTITY_USERS.filter(function (u) { return !u.mfaEnabled; }).length;
  var IDENTITY_HIGH_RISK = IDENTITY_USERS.filter(function (u) { return u.riskLevel === 'HIGH'; }).length;
  var IDENTITY_MED_RISK = IDENTITY_USERS.filter(function (u) { return u.riskLevel === 'MEDIUM'; }).length;
  var IDENTITY_SECURITY_SCORE = 70;

  function identityDashboardPayload() {
    return {
      success: true,
      source: 'stackops_mock',
      tenant: 'stackops-demo',
      companyName: 'StackOps Demo (Pty) Ltd',
      fetchedAt: new Date().toISOString(),
      liveSource: '/api/sunbird/identity-dashboard',
      users: IDENTITY_USERS,
      roleAssignments: IDENTITY_ROLES,
      topRoles: ADMIN_ROLES.slice(0, 5).map(function (r, i) { return { role: r, count: i === 0 ? 2 : 1 }; }),
      summary: {
        totalUsers: IDENTITY_USERS.length,
        activeUsers: IDENTITY_ACTIVE_24H,
        activeUsers24h: IDENTITY_ACTIVE_24H,
        activeUsersPercentage: Math.round((IDENTITY_ACTIVE_24H / IDENTITY_USERS.length) * 100),
        adminUsers: IDENTITY_ADMIN_COUNT,
        securityScore: IDENTITY_SECURITY_SCORE,
        identityRiskScore: 46,
        identityHygieneScore: 68,
        highRiskUsers: IDENTITY_HIGH_RISK,
        mediumRiskUsers: IDENTITY_MED_RISK,
        privilegedUsersWithoutMFA: 1,
        mfaCoverage: Math.round(((IDENTITY_USERS.length - IDENTITY_MFA_MISSING) / IDENTITY_USERS.length) * 100),
        mfaMissing: IDENTITY_MFA_MISSING,
        externalUsers: IDENTITY_USERS.filter(function (u) { return u.isExternal; }).length,
        inactiveUsers: IDENTITY_USERS.filter(function (u) { return u.lastSignIn.daysSince > 30; }).length,
        disabledUsers: IDENTITY_USERS.filter(function (u) { return !u.accountEnabled; }).length
      },
      metrics: {
        totalUsers: IDENTITY_USERS.length, activeUsers24h: IDENTITY_ACTIVE_24H,
        adminUsers: IDENTITY_ADMIN_COUNT, securityScore: IDENTITY_SECURITY_SCORE,
        highRiskUsers: IDENTITY_HIGH_RISK, mediumRiskUsers: IDENTITY_MED_RISK,
        privilegedUsersWithoutMFA: 1,
        TotalUsers: IDENTITY_USERS.length, ActiveUsers: IDENTITY_ACTIVE_24H,
        AdminRoles: IDENTITY_ADMIN_COUNT, SecurityScore: IDENTITY_SECURITY_SCORE
      },
      riskDistribution: { HIGH: IDENTITY_HIGH_RISK, MEDIUM: IDENTITY_MED_RISK, SAFE: IDENTITY_USERS.length - IDENTITY_HIGH_RISK - IDENTITY_MED_RISK },
      authenticationStrength: {
        passwordOnly: IDENTITY_MFA_MISSING,
        basicMFA: IDENTITY_USERS.filter(function (u) { return u.mfaEnabled && u.authMethodCount < 3; }).length,
        strongMFA: IDENTITY_USERS.filter(function (u) { return u.mfaEnabled && u.authMethodCount >= 3; }).length
      },
      inactiveBreakdown: {
        '0-7days': IDENTITY_USERS.filter(function (u) { return u.lastSignIn.daysSince <= 7; }).length,
        '7-30days': IDENTITY_USERS.filter(function (u) { return u.lastSignIn.daysSince > 7 && u.lastSignIn.daysSince <= 30; }).length,
        '30-90days': IDENTITY_USERS.filter(function (u) { return u.lastSignIn.daysSince > 30 && u.lastSignIn.daysSince <= 90; }).length,
        '90+days': IDENTITY_USERS.filter(function (u) { return u.lastSignIn.daysSince > 90; }).length
      },
      systemHealth: { performance: 82, availability: 97, security: 70, compliance: 84, backup: 91 },
      deviceTrustAnalysis: { managed: 21, unmanaged: 3, unknown: 1 },
      hygieneLevels: { profileCompleteness: 88, authCompleteness: 82, activityCompleteness: 74 },
      signInPatterns: {
        topLocations: LOCATIONS.slice(0, 4).map(function (l, i) { return { location: l, count: 30 - i * 6 }; }),
        deviceBreakdown: { Windows: 48, macOS: 21, iOS: 15, Android: 9 }
      }
    };
  }

  /* ---- Devices (25 total, 3 non-compliant, all encrypted) ----------- */
  function buildDevices() {
    var TOTAL = 25, NON_COMPLIANT = 3;
    var out = [];
    for (var i = 0; i < TOTAL; i++) {
      var user = IDENTITY_USERS[i % IDENTITY_USERS.length];
      var os = pick(['Windows', 'Windows', 'macOS', 'iOS', 'Android'], (i % 5) / 5);
      var compliant = i >= NON_COMPLIANT;
      out.push({
        id: 'dev-' + (500 + i),
        deviceName: (os === 'Windows' ? 'DESKTOP-' : os + '-') + user.surname.toUpperCase().replace(/\s/g, '') + '-' + i,
        userPrincipalName: user.userPrincipalName,
        userDisplayName: user.displayName,
        operatingSystem: os,
        osVersion: os === 'Windows' ? '10.0.22631.4169' : os === 'macOS' ? '14.5' : os === 'iOS' ? '17.5.1' : '14',
        complianceState: compliant ? 'compliant' : 'noncompliant',
        isCompliant: compliant,
        isEncrypted: true,
        encryptionStatus: 'Encrypted',
        managementAgent: 'mdm',
        managedDeviceOwnerType: i % 6 === 0 ? 'personal' : 'company',
        enrolledDateTime: daysAgoISO(60 + i * 4),
        lastSyncDateTime: hoursAgoISO(i < 20 ? (i % 12) : 24 + i),
        azureADRegistered: true,
        deviceEnrollmentType: 'windowsAzureADJoin',
        deviceType: os === 'iOS' || os === 'Android' ? 'phone' : 'desktop',
        serialNumber: 'SN' + (100000 + i * 37),
        jailBroken: 'Unknown',
        model: os === 'macOS' ? 'MacBook Pro 14"' : os === 'Windows' ? 'Latitude 5540' : os === 'iOS' ? 'iPhone 15' : 'Galaxy S23',
        manufacturer: os === 'macOS' || os === 'iOS' ? 'Apple' : os === 'Windows' ? 'Dell Inc.' : 'Samsung',
        complianceGracePeriodExpirationDateTime: compliant ? null : daysAgoISO(-3),
        nonComplianceReasons: compliant ? [] : [pick(['Device not encrypted at policy level', 'OS version below minimum', 'Defender signature out of date'], (i % 3) / 3)]
      });
    }
    return out;
  }
  var DEVICES_LIST = buildDevices();

  function devicesPayload() {
    return {
      success: true, source: 'stackops_mock', tenant: 'stackops-demo', fetchedAt: new Date().toISOString(),
      devices: DEVICES_LIST,
      alerts: [
        { id: 'dalert-1', title: 'Device fell out of compliance', severity: 'medium', deviceName: DEVICES_LIST[0].deviceName, createdDateTime: hoursAgoISO(6), status: 'active' },
        { id: 'dalert-2', title: 'Personal device enrolled without Defender', severity: 'low', deviceName: DEVICES_LIST[1].deviceName, createdDateTime: hoursAgoISO(30), status: 'active' }
      ],
      policies: [
        { id: 'dpol-1', displayName: 'Baseline compliance - Windows', assigned: 22, compliant: 21 },
        { id: 'dpol-2', displayName: 'Baseline compliance - macOS/iOS', assigned: 8, compliant: 7 }
      ],
      summary: {
        totalDevices: DEVICES_LIST.length,
        nonCompliantDevices: DEVICES_LIST.filter(function (d) { return d.complianceState === 'noncompliant'; }).length,
        notEncryptedDevices: 0,
        compliantDevices: DEVICES_LIST.filter(function (d) { return d.complianceState === 'compliant'; }).length,
        encryptedDevices: DEVICES_LIST.length,
        staleDevices: 0,
        highRiskDevices: 1,
        deviceSecurityScore: 88
      },
      metrics: {
        TotalDevices: DEVICES_LIST.length, NonCompliant: 3, NotEncrypted: 0, StaleDevices: 0,
        totalDevices: DEVICES_LIST.length, nonCompliant: 3, notEncrypted: 0, staleDevices: 0
      },
      activityBreakdown: { active24h: 20, stale7days: 0, dead30days: 0 }
    };
  }

  /* ---- Email security (10 threats, 14 users targeted) --------------- */
  function emailPayload() {
    var targeted = IDENTITY_USERS.slice(0, 14).map(function (u) {
      return { user: u.userPrincipalName, displayName: u.displayName, threatCount: 1 + (u.id.charCodeAt(5) % 3), lastSeen: hoursAgoISO(u.id.charCodeAt(6) % 40) };
    });
    var alerts = [];
    var kinds = ['Phishing', 'Malware', 'Spam', 'Impersonation', 'Business Email Compromise', 'Malicious URL'];
    for (var i = 0; i < 10; i++) {
      alerts.push({
        id: 'ealert-' + i,
        title: kinds[i % kinds.length] + ' campaign detected',
        category: kinds[i % kinds.length],
        severity: i < 2 ? 'medium' : 'low',
        status: i < 8 ? 'inProgress' : 'resolved',
        recipient: targeted[i % targeted.length].user,
        sender: pick(['no-reply@secure-docs-verify.com', 'billing@invoice-share.net', 'it-support@0ffice365-alerts.com'], (i % 3) / 3),
        subject: pick(['Action required: verify your mailbox', 'Unpaid invoice #48213', 'Your password expires today'], (i % 3) / 3),
        detectedDateTime: hoursAgoISO(i * 5 + 2),
        deliveryAction: i % 4 === 0 ? 'Delivered' : 'Blocked'
      });
    }
    return {
      success: true, source: 'stackops_mock', tenant: 'stackops-demo', fetchedAt: new Date().toISOString(),
      alerts: alerts,
      incidents: [],
      threats: {
        Phishing: 5, Malware: 2, Spam: 1, Impersonation: 1, 'Malicious URL': 1
      },
      affectedUsers: { all: targeted.map(function (t) { return t.user; }) },
      mailActivity: {
        users: targeted,
        summary: { totalMessages: 18450, blocked: 264, delivered: 18186, quarantined: 41 }
      },
      insights: [
        'Phishing remains the dominant email threat vector this period.',
        'No high-severity alerts are currently open.'
      ],
      summary: {
        activeThreats: 10, highSeverityAlerts: 0, affectedUsersCount: 14, activeIncidents: 0,
        threatResolutionRate: 82, securityScore: 76,
        mailActivity: { totalMessages: 18450, blocked: 264, delivered: 18186, quarantined: 41 }
      },
      metrics: {
        ActiveThreats: 10, HighSeverity: 0, UsersTargeted: 14, OpenIncidents: 0,
        activeThreats: 10, highSeverity: 0, usersTargeted: 14, openIncidents: 0
      }
    };
  }

  /* ---- Security & Events -------------------------------------------
   * The single high incident + "gateway / TLS / UDP disabled" activity feed
   * items shown in the panel are derived by clientportal.js's Cloudflare
   * augmentation from networkPayload() (gatewayProxyEnabled/tls/udp = false),
   * so the base payload here carries NO alerts/incidents of its own. That keeps
   * the panel headline at exactly "High Severity Alerts: 1 / Security Incidents: 1".
   */
  function securityEventsPayload() {
    var now = new Date();
    var stamp = now.toLocaleTimeString('en-GB', { hour12: false });
    return {
      success: true, source: 'stackops_mock', tenant: 'stackops-demo', fetchedAt: new Date().toISOString(),
      alerts: [],
      incidents: [],
      threats: [
        { id: 'ti-1', displayName: 'known-phish-domain.example', type: 'DomainName', confidence: 80, source: 'Microsoft Defender TI' }
      ],
      signIns: {
        suspicious: [
          { user: IDENTITY_USERS[3].userPrincipalName, ipAddress: '45.146.11.20', country: 'RU', location: 'Moscow, RU', riskLevel: 'high', dateTime: hoursAgoISO(9), status: 'Failure' },
          { user: IDENTITY_USERS[7].userPrincipalName, ipAddress: '103.9.76.4', country: 'CN', location: 'Shenzhen, CN', riskLevel: 'medium', dateTime: hoursAgoISO(21), status: 'Failure' }
        ],
        usersUnderAttack: [IDENTITY_USERS[3].userPrincipalName]
      },
      activityFeed: [
        { title: 'CF Cloudflare Gateway proxy disabled', message: 'CF Cloudflare Gateway proxy disabled', timestamp: hoursAgoISO(2), time: stamp, eventType: 'cloudflare-incident', severity: 'high' },
        { title: 'CF Cloudflare TLS decrypt disabled', message: 'CF Cloudflare TLS decrypt disabled', timestamp: hoursAgoISO(2), time: stamp, eventType: 'cloudflare-alert', severity: 'medium' },
        { title: 'CF Cloudflare UDP proxy disabled', message: 'CF Cloudflare UDP proxy disabled', timestamp: hoursAgoISO(2), time: stamp, eventType: 'cloudflare-alert', severity: 'low' },
        { title: 'Risky sign-in blocked for ' + IDENTITY_USERS[3].displayName, message: 'Risky sign-in blocked', timestamp: hoursAgoISO(9), time: stamp, eventType: 'identity-protection', severity: 'high' }
      ],
      recommendations: [
        'Re-enable the Cloudflare Gateway HTTP proxy to restore web traffic inspection.',
        'Turn TLS decryption back on so encrypted threats are scanned.',
        'Confirm the risky sign-in for ' + IDENTITY_USERS[3].displayName + ' and reset credentials if needed.'
      ],
      aiSummary: 'One high-severity incident is open: Cloudflare Gateway proxy has been disabled, alongside related TLS and UDP protection alerts. One user is being targeted by password-spray attempts from foreign IPs.',
      summary: {
        activeIncidents: 0, highSeverityAlerts: 0, totalAlerts: 0,
        threatIndicators: 1, usersUnderAttack: 1, securityScore: 62
      },
      metrics: { ActiveIncidents: 0, HighAlerts: 0, activeIncidents: 0, highAlerts: 0 }
    };
  }

  /* ---- Network security (Cloudflare) ------------------------------- */
  function networkPayload() {
    return {
      success: true, source: 'stackops_mock', fetchedAt: new Date().toISOString(),
      account: { id: 'cf-acct-demo', name: 'StackOps Demo' },
      overview: {
        securityStatus: 'Infrastructure healthy - monitoring active',
        protectedApps: 2,
        enrolledDevices: 12,
        registeredWarpDevices: 12,
        gatewayPolicies: 3,
        activeGatewayPolicies: 3,
        identityProviders: 1,
        identityProvider: 'Azure',
        recentAccessEvents: 2,
        lastAccessEvent: hoursAgoISO(1),
        dlpProfiles: 2,
        warpProfiles: 1,
        virtualNetworks: 1,
        appCategories: 4,
        gatewayProxyEnabled: false,
        udpProxyEnabled: false,
        certificateEnabled: true,
        tlsDecryptEnabled: false,
        zonesAvailable: 1,
        auditLogs: 2,
        accountLogs: 0,
        securityInsights: 3,
        casbFindings: 4,
        tunnels: 1,
        dnsFirewallRules: 2
      },
      apps: [
        { id: 'app-1', name: 'Internal Wiki', domain: 'wiki.stackopsdemo.co.za', type: 'self_hosted', sessionDuration: '24h', policies: 2 },
        { id: 'app-2', name: 'Finance Portal', domain: 'finance.stackopsdemo.co.za', type: 'self_hosted', sessionDuration: '8h', policies: 3 }
      ],
      identityProviders: [{ id: 'idp-azure', name: 'Azure AD', type: 'azureAD', status: 'active' }],
      policies: [
        { id: 'pol-1', name: 'Require Azure AD + WARP', decision: 'allow', appName: 'Internal Wiki' },
        { id: 'pol-2', name: 'Finance - MFA + managed device', decision: 'allow', appName: 'Finance Portal' }
      ],
      devices: DEVICES_LIST.slice(0, 12).map(function (d) {
        return { id: d.id, name: d.deviceName, user: d.userPrincipalName, osVersion: d.osVersion, lastSeen: d.lastSyncDateTime, warpEnabled: true, posture: 'compliant' };
      }),
      deviceRegistrations: DEVICES_LIST.slice(0, 12).map(function (d) { return { deviceId: d.id, user: d.userPrincipalName, createdAt: d.enrolledDateTime }; }),
      gatewayRules: [
        { id: 'gr-1', name: 'Block known malware domains', action: 'block', enabled: true, precedence: 1, filters: 'security_categories' },
        { id: 'gr-2', name: 'Block newly registered domains', action: 'block', enabled: true, precedence: 2, filters: 'domain_age' },
        { id: 'gr-3', name: 'Isolate risky browsing', action: 'isolate', enabled: false, precedence: 3, filters: 'content_categories' }
      ],
      warpProfiles: [{ id: 'warp-default', name: 'Default', enabled: true, mode: 'warp' }],
      dlpProfiles: [
        { id: 'dlp-1', name: 'South Africa ID numbers', entries: 3 },
        { id: 'dlp-2', name: 'Credit card numbers', entries: 2 }
      ],
      accessLogs: [
        { user: IDENTITY_USERS[0].userPrincipalName, appName: 'Finance Portal', action: 'login', allowed: true, createdAt: hoursAgoISO(1), country: 'ZA', ipAddress: '196.25.10.4' },
        { user: IDENTITY_USERS[5].userPrincipalName, appName: 'Internal Wiki', action: 'login', allowed: true, createdAt: hoursAgoISO(4), country: 'ZA', ipAddress: '196.25.10.9' }
      ],
      auditLogs: [
        { id: 'cfaudit-1', actor: 'admin@stackopsdemo.co.za', action: 'gateway.proxy.disabled', when: hoursAgoISO(2), resource: 'Gateway settings' },
        { id: 'cfaudit-2', actor: 'admin@stackopsdemo.co.za', action: 'gateway.tls_decrypt.disabled', when: hoursAgoISO(2), resource: 'Gateway settings' }
      ],
      accountLogs: [],
      securityInsights: [
        { id: 'ins-1', title: 'Gateway HTTP proxy disabled', severity: 'medium', description: 'Web traffic is not being filtered.' },
        { id: 'ins-2', title: 'TLS decryption off', severity: 'medium', description: 'Encrypted traffic is not inspected.' },
        { id: 'ins-3', title: 'Isolation policy disabled', severity: 'low', description: 'Risky browsing isolation rule is turned off.' }
      ],
      casbFindings: [
        { id: 'casb-1', integration: 'Microsoft 365', title: 'External sharing link with no expiry', severity: 'medium' },
        { id: 'casb-2', integration: 'Microsoft 365', title: 'Anonymous access enabled on a SharePoint site', severity: 'medium' },
        { id: 'casb-3', integration: 'Google Workspace', title: 'OAuth app with broad Drive scope', severity: 'low' },
        { id: 'casb-4', integration: 'Microsoft 365', title: 'Inactive admin account', severity: 'low' }
      ],
      tunnels: [{ id: 'tun-1', name: 'stackops-dc-tunnel', status: 'healthy', connections: 2 }],
      dnsFirewallRules: [
        { id: 'dfr-1', name: 'Block malware', action: 'block' },
        { id: 'dfr-2', name: 'Block phishing', action: 'block' }
      ],
      sections: {
        access: { status: 'ok' }, gateway: { status: 'ok' }, devices: { status: 'ok' },
        dlp: { status: 'ok' }, casb: { status: 'ok' }, tunnels: { status: 'ok' }
      }
    };
  }

  /* ---- Backup & Recovery ----------------------------------------- */
  function backupPayload() {
    var users = IDENTITY_USERS.slice(0, 30).map(function (u, i) {
      return {
        user: u.userPrincipalName, displayName: u.displayName,
        onedriveGB: Number((0.5 + (i % 12) * 0.8).toFixed(1)),
        mailboxGB: Number((0.3 + (i % 8) * 0.6).toFixed(1)),
        lastActivity: i < 24 ? daysAgoISO(i % 20) : daysAgoISO(45 + i)
      };
    });
    var onedrive = Number(users.reduce(function (a, u) { return a + u.onedriveGB; }, 0).toFixed(1));
    var exchange = Number(users.reduce(function (a, u) { return a + u.mailboxGB; }, 0).toFixed(1));
    var sharepoint = 320.4;
    return {
      success: true, source: 'stackops_mock', tenant: 'stackops-demo', fetchedAt: new Date().toISOString(),
      summary: {
        totalStorageGB: Number((onedrive + exchange + sharepoint).toFixed(1)),
        oneDriveStorageGB: onedrive, sharePointStorageGB: sharepoint, exchangeStorageGB: exchange,
        activeUsersCount: users.filter(function (u) { return u.lastActivity; }).length,
        inactiveUsersCount: 6, servicesCovered: 3, backupConfigured: true,
        protectedUsers: 93, retentionDays: 365, lastBackup: hoursAgoISO(5), lastRestoreTest: daysAgoISO(21)
      },
      storage: {
        byService: { onedrive: onedrive, sharepoint: sharepoint, exchange: exchange },
        users: users,
        sites: [
          { site: 'Finance', storageGB: 140.2, lastActivity: daysAgoISO(1) },
          { site: 'HR', storageGB: 88.1, lastActivity: daysAgoISO(2) },
          { site: 'IT', storageGB: 92.1, lastActivity: daysAgoISO(0) }
        ],
        inactiveUsers: users.filter(function (u) { return new Date(u.lastActivity).getTime() < Date.now() - 30 * 86400000; }).map(function (u) { return { user: u.user, lastActivity: u.lastActivity, storageGB: u.onedriveGB + u.mailboxGB }; }),
        inactiveUserStorageGB: 42.6
      },
      insights: [
        'All three Microsoft 365 workloads (Exchange, OneDrive, SharePoint) are covered by backup.',
        'Last successful backup completed 5 hours ago; last restore test was 21 days ago.'
      ],
      recommendations: [
        'Schedule the next quarterly restore test.',
        'Review 6 inactive mailboxes still consuming licensed backup storage.'
      ],
      evidenceRows: [
        { title: 'Backup coverage', detail: 'Exchange, OneDrive and SharePoint all protected', status: 'Pass' },
        { title: 'Retention policy', detail: '365-day retention enforced', status: 'Pass' },
        { title: 'Restore testing', detail: 'Last verified restore 21 days ago', status: 'Review' }
      ]
    };
  }

  /* ---- Applications --------------------------------------------- */
  function buildApplications() {
    var defs = [
      { name: 'Microsoft 365', publisherName: 'Microsoft', type: 'Microsoft', users: 93, groups: 6, scopes: 8, roles: 4 },
      { name: 'Microsoft Teams', publisherName: 'Microsoft', type: 'Microsoft', users: 90, groups: 5, scopes: 6, roles: 2 },
      { name: 'Azure Portal', publisherName: 'Microsoft', type: 'Microsoft', users: 12, groups: 2, scopes: 5, roles: 3 },
      { name: 'Power BI', publisherName: 'Microsoft', type: 'Microsoft', users: 34, groups: 3, scopes: 4, roles: 2 },
      { name: 'Defender for Endpoint', publisherName: 'Microsoft', type: 'Microsoft', users: 8, groups: 1, scopes: 6, roles: 3 },
      { name: 'SharePoint Online', publisherName: 'Microsoft', type: 'Microsoft', users: 88, groups: 7, scopes: 5, roles: 2 },
      { name: 'Salesforce', publisherName: 'Salesforce.com', type: 'External', users: 22, groups: 3, scopes: 9, roles: 4 },
      { name: 'Slack', publisherName: 'Slack Technologies', type: 'External', users: 41, groups: 4, scopes: 7, roles: 2 },
      { name: 'Zoom', publisherName: 'Zoom Video', type: 'External', users: 63, groups: 2, scopes: 5, roles: 1 },
      { name: 'DocuSign', publisherName: 'DocuSign Inc.', type: 'External', users: 15, groups: 2, scopes: 4, roles: 2 },
      { name: 'Xero', publisherName: 'Xero Limited', type: 'External', users: 6, groups: 1, scopes: 6, roles: 3 },
      { name: 'Adobe Acrobat Sign', publisherName: 'Adobe Inc.', type: 'External', users: 9, groups: 1, scopes: 3, roles: 1 }
    ];
    return defs.map(function (d, i) {
      return {
        id: 'sp-' + (7000 + i), spId: 'sp-' + (7000 + i), appId: 'app-' + (7000 + i),
        name: d.name, displayName: d.name, publisherName: d.publisherName,
        type: d.type, isExternal: d.type === 'External',
        userCount: d.users, assignmentCount: d.users, scopeCount: d.scopes, roleCount: d.roles,
        assignedGroups: Array.from({ length: d.groups }).map(function (_, g) { return d.name.split(' ')[0] + ' Group ' + (g + 1); }),
        createdDateTime: daysAgoISO(200 + i * 10),
        lastSignInDateTime: hoursAgoISO(i * 3 + 1),
        homepageUrl: 'https://' + d.name.toLowerCase().replace(/[^a-z]/g, '') + '.example.com',
        permissions: Array.from({ length: d.scopes }).map(function (_, s) { return { value: pick(['User.Read', 'Mail.Read', 'Files.ReadWrite.All', 'Directory.Read.All', 'offline_access', 'Group.Read.All'], s / d.scopes), type: s % 2 ? 'Application' : 'Delegated' }; })
      };
    });
  }
  var APPLICATIONS_LIST = buildApplications();

  function applicationsPayload() {
    var external = APPLICATIONS_LIST.filter(function (a) { return a.isExternal; }).length;
    return {
      success: true, source: 'stackops_mock', tenant: 'stackops-demo', fetchedAt: new Date().toISOString(),
      applications: APPLICATIONS_LIST,
      summary: {
        totalApplications: APPLICATIONS_LIST.length,
        externalApplications: external,
        highRiskApps: 3,
        highAccessApps: APPLICATIONS_LIST.filter(function (a) { return a.userCount >= 20; }).length,
        userCount: 93, groupCount: 24
      },
      dashboardMetrics: { totalApplications: APPLICATIONS_LIST.length, externalApplications: external, highRiskApps: 3 }
    };
  }
  function applicationMetricsPayload() {
    var external = APPLICATIONS_LIST.filter(function (a) { return a.isExternal; }).length;
    return {
      success: true,
      metrics: {
        TotalApps: APPLICATIONS_LIST.length, ExternalApps: external, HighRiskApps: 3, HighAccessApps: 6,
        totalApps: APPLICATIONS_LIST.length, externalApps: external, highRiskApps: 3, highAccessApps: 6
      }
    };
  }
  function appAccessPayload(spId) {
    var app = APPLICATIONS_LIST.find(function (a) { return a.id === spId || a.spId === spId || a.appId === spId; }) || APPLICATIONS_LIST[0];
    var count = Math.min(app.userCount, 25);
    return {
      success: true,
      application: { id: app.id, name: app.name, displayName: app.name },
      users: IDENTITY_USERS.slice(0, count).map(function (u) {
        return { id: u.id, displayName: u.displayName, userPrincipalName: u.userPrincipalName, jobTitle: u.jobTitle, assignedVia: pick(['Direct', 'Group', 'Group'], Math.random()), roles: [] };
      }),
      groups: app.assignedGroups.map(function (g) { return { name: g, memberCount: 5 + (g.length % 20) }; })
    };
  }

  /* ---- Governance / Compliance / Operations --------------------- */
  function governancePayload() {
    return {
      success: true, source: 'stackctrl_governance_dashboard', fetchedAt: new Date().toISOString(),
      summary: { score: 78, total: 9, completed: 6, overdue: 2, pending: 1 },
      dashboardMetrics: { governanceScore: 78, reviewsCompleted: 6, reviewsOverdue: 2 },
      recommendations: [
        'Complete the overdue quarterly access review for privileged users.',
        'Attach evidence to the software review before the next audit window.'
      ],
      rows: [
        { area: 'Access review', activity: 'Review users', source: 'Framework', frequency: 'Quarterly', status: 'Completed', lastReviewed: daysAgoISO(20), evidence: 'All 93 user accounts reviewed against HR active-employee list on ' + new Date(Date.now() - 20 * 86400000).toLocaleDateString('en-ZA') + '. 2 leaver accounts disabled.' },
        { area: 'Admin review', activity: 'Review roles', source: 'Framework', frequency: 'Quarterly', status: 'Overdue', lastReviewed: daysAgoISO(140), evidence: 'Privileged role membership last reviewed 140 days ago. 6 directory-role holders identified; 1 without MFA. Review is overdue.' },
        { area: 'MFA audit', activity: 'Verify MFA coverage', source: 'Checklist', frequency: 'Monthly', status: 'Completed', lastReviewed: daysAgoISO(8), evidence: 'MFA enforced on ' + (93 - IDENTITY_MFA_MISSING) + ' of 93 accounts. ' + IDENTITY_MFA_MISSING + ' exceptions logged with owner sign-off.' },
        { area: 'Device audit', activity: 'Review device compliance', source: 'Checklist', frequency: 'Monthly', status: 'Completed', lastReviewed: daysAgoISO(6), evidence: '25 managed devices; 3 non-compliant with remediation tickets raised. 100% disk-encrypted.' },
        { area: 'Log review', activity: 'Review security logs', source: 'Checklist', frequency: 'Monthly', status: 'Completed', lastReviewed: daysAgoISO(3), evidence: 'SOC reviewed sign-in and Cloudflare audit logs. 1 high incident (Gateway proxy disabled) raised to Operations.' },
        { area: 'Backup review', activity: 'Verify backup coverage', source: 'Checklist', frequency: 'Monthly', status: 'Completed', lastReviewed: daysAgoISO(5), evidence: 'Exchange, OneDrive and SharePoint all covered; last backup 5h ago.' },
        { area: 'Restore testing', activity: 'Test recovery', source: 'Checklist', frequency: 'Quarterly', status: 'Overdue', lastReviewed: daysAgoISO(112), evidence: 'Last successful restore test 112 days ago - a new quarterly test is due.' },
        { area: 'Software review', activity: 'Review connected apps', source: 'Framework', frequency: 'Quarterly', status: 'Pending', lastReviewed: null, evidence: '12 enterprise applications (6 external). OAuth scope review not yet started for this quarter.' },
        { area: 'Policy review', activity: 'Review security policies', source: 'Checklist', frequency: 'Annual', status: 'Completed', lastReviewed: daysAgoISO(190), evidence: 'Information Security Policy set reviewed and re-approved by management 190 days ago.' }
      ]
    };
  }

  function compliancePayload() {
    return {
      success: true, source: 'stackctrl_compliance_dashboard', fetchedAt: new Date().toISOString(),
      summary: { score: 71, total: 8, passing: 5, failing: 3 },
      dashboardMetrics: { complianceScore: 71, controlsPassing: 5, controlsFailing: 3 },
      recommendations: [
        'Enforce MFA on the remaining accounts to close the credential-theft exposure.',
        'Reduce standing privileged access - 6 directory admins is above the recommended baseline for 93 users.'
      ],
      controls: [
        { name: 'MFA on all accounts', area: 'Identity', insight: '🔴 Users exposed to credential theft', evidenceData: { status: 'Fail', detail: 'MFA is enforced on ' + (93 - IDENTITY_MFA_MISSING) + ' of 93 accounts. ' + IDENTITY_MFA_MISSING + ' accounts (including 1 privileged) still sign in with a password only.', users: IDENTITY_USERS.filter(function (u) { return !u.mfaEnabled; }).slice(0, 10).map(function (u) { return u.userPrincipalName; }) } },
        { name: 'Admin accounts limited', area: 'Identity', insight: '🔴 Too many privileged users', evidenceData: { status: 'Fail', detail: '6 accounts hold Azure AD directory roles. Recommended baseline for this tenant size is 2-3. 1 admin lacks MFA.', users: IDENTITY_USERS.filter(function (u) { return u.roles.length; }).map(function (u) { return u.userPrincipalName; }) } },
        { name: 'Devices encrypted', area: 'Devices', insight: '🟢 All managed devices encrypted', evidenceData: { status: 'Pass', detail: '25 of 25 managed devices report full-disk encryption (BitLocker / FileVault).' } },
        { name: 'Device compliance enforced', area: 'Devices', insight: '🟡 3 devices out of compliance', evidenceData: { status: 'Review', detail: '3 of 25 devices are non-compliant. Remediation tickets are open.' } },
        { name: 'Email threat protection active', area: 'Email', insight: '🟢 Defender for Office 365 enforcing policy', evidenceData: { status: 'Pass', detail: 'Anti-phishing, Safe Links and Safe Attachments policies are on for all users. 264 messages blocked this period.' } },
        { name: 'Backup coverage complete', area: 'Backup', insight: '🟢 All workloads protected', evidenceData: { status: 'Pass', detail: 'Exchange, OneDrive and SharePoint are all covered with 365-day retention.' } },
        { name: 'Web traffic filtered', area: 'Network', insight: '🔴 Gateway proxy disabled', evidenceData: { status: 'Fail', detail: 'The Cloudflare Gateway HTTP proxy is currently switched off, so outbound web traffic is not being inspected.' } },
        { name: 'Privileged access reviewed', area: 'Governance', insight: '🟡 Review overdue', evidenceData: { status: 'Review', detail: 'The quarterly privileged-role review is 140 days old.' } }
      ]
    };
  }

  function operationsPayload() {
    return {
      success: true, source: 'stackctrl_operations_dashboard', fetchedAt: new Date().toISOString(),
      summary: { open: 5, high: 2, medium: 2, low: 1 },
      dashboardMetrics: { openTasks: 5, highPriority: 2 },
      recommendations: ['Address the two high-priority Cloudflare items first - they reduce active protection.'],
      tasks: [
        { task: 'Re-enable Cloudflare Gateway HTTP proxy', area: 'Network', priority: 'High', insight: 'Web traffic is currently un-inspected', evidence: 'Gateway proxy was disabled ~2 hours ago via the Cloudflare dashboard by admin@stackopsdemo.co.za.', dueDate: daysAgoISO(-1) },
        { task: 'Investigate risky sign-in for ' + IDENTITY_USERS[3].displayName, area: 'Identity', priority: 'High', insight: 'Password-spray from RU/CN IPs', evidence: 'Two failed sign-ins from 45.146.11.20 (Moscow) and 103.9.76.4 (Shenzhen) in the last 24h.', dueDate: daysAgoISO(-1) },
        { task: 'Enforce MFA on 4 remaining accounts', area: 'Identity', priority: 'Medium', insight: 'Credential-theft exposure', evidence: IDENTITY_MFA_MISSING + ' accounts still password-only. Owners notified.', dueDate: daysAgoISO(-5) },
        { task: 'Remediate 3 non-compliant devices', area: 'Devices', priority: 'Medium', insight: 'Compliance policy failing', evidence: 'Devices DESKTOP-SANDANI-0/1/2 failing OS-version / Defender checks.', dueDate: daysAgoISO(-4) },
        { task: 'Schedule quarterly restore test', area: 'Backup', priority: 'Low', insight: 'Last test 112 days ago', evidence: 'Restore testing cadence is quarterly; the last verified restore is now overdue.', dueDate: daysAgoISO(-10) }
      ]
    };
  }

  /* ---- Reports (static list, sample PDF) ------------------------ */
  function reportsPayload(range) {
    var reports = [];
    var titles = ['Monthly security posture report', 'Weekly executive summary', 'Governance & compliance evidence pack', 'Identity risk report', 'Backup assurance report'];
    for (var i = 0; i < 8; i++) {
      reports.push({
        id: 'rep-' + (900 + i),
        type: i % 3 === 0 ? 'daily' : 'monthly',
        title: titles[i % titles.length],
        range: range || '30d',
        generatedAt: daysAgoISO(i * 4 + 1),
        createdAt: daysAgoISO(i * 4 + 1),
        status: 'ready',
        score: [70, 72, 68, 74, 71][i % 5],
        summary: 'Security score ' + [70, 72, 68, 74, 71][i % 5] + '/100. 1 open high incident. MFA at ' + Math.round(((93 - IDENTITY_MFA_MISSING) / 93) * 100) + '%.',
        highlights: [
          { title: 'Open incidents', detail: '1 high (Cloudflare Gateway proxy disabled)' },
          { title: 'MFA coverage', detail: (93 - IDENTITY_MFA_MISSING) + ' / 93 accounts' },
          { title: 'Device compliance', detail: '22 / 25 compliant' }
        ]
      });
    }
    return {
      success: true, source: 'stackops_mock', selectedRange: range || '30d', fetchedAt: new Date().toISOString(),
      reports: reports,
      logs: [
        { id: 'log-1', message: 'Report rep-900 generated', eventType: 'report.generated', timestamp: daysAgoISO(1), actor: 'system' },
        { id: 'log-2', message: 'Weekly report emailed to nsegroupit@gmail.com', eventType: 'report.emailed', timestamp: daysAgoISO(5), actor: 'system' }
      ],
      overview: {
        events: [
          { title: 'Security score', detail: '70 / 100', tone: 'warn' },
          { title: 'High incidents', detail: '1 open', tone: 'bad' },
          { title: 'Governance', detail: '6 of 9 reviews complete', tone: 'warn' }
        ],
        score: 70
      },
      settings: { recipientEmail: 'nsegroupit@gmail.com', weeklyEnabled: true, schedule: 'weekly' }
    };
  }
  function reportsSettingsPayload() {
    return { success: true, settings: { recipientEmail: 'nsegroupit@gmail.com', weeklyEnabled: true, schedule: 'weekly' } };
  }
  function reportsLiveEvidencePayload() {
    return {
      success: true,
      sections: [
        { title: 'Identity', value: 'MFA enforced on ' + (93 - IDENTITY_MFA_MISSING) + ' of 93 accounts; 6 directory admins.', rows: IDENTITY_USERS.slice(0, 6).map(function (u) { return { title: u.displayName, detail: u.roles.join(', ') || u.jobTitle, entityId: u.userPrincipalName }; }) },
        { title: 'Devices', value: '22 of 25 devices compliant; 100% encrypted.', rows: DEVICES_LIST.slice(0, 5).map(function (d) { return { title: d.deviceName, detail: d.complianceState, entityId: d.id }; }) },
        { title: 'Network', value: 'Cloudflare Gateway proxy disabled - web filtering inactive.', rows: [{ title: 'Gateway proxy', detail: 'Disabled 2h ago', entityId: 'cf-gateway' }] }
      ],
      findings: [
        { title: 'Cloudflare Gateway proxy disabled', impact: 'Outbound web traffic is not inspected.', whyItMatters: 'Malware and phishing domains are no longer blocked at the network edge.' }
      ]
    };
  }

  /* ---- Latest invoice (Billing Statement) ---------------------- */
  function latestInvoicePayload() {
    return {
      ID: 'INV-2026-0042', InvoiceNumber: 'INV-2026-0042',
      TotalAmount: 5000, Status: 'Overdue',
      DueDate: '2026-03-30', IssueDate: '2026-03-01',
      CompanyID: MOCK_COMPANY_ID, CompanyName: 'StackOps Demo (Pty) Ltd',
      items: [
        { Description: 'Managed Security Operations - Monthly', ServiceCategory: 'Monthly Subscription', Category: 'Subscription', Quantity: 1, UnitPrice: 5000, Total: 5000 }
      ]
    };
  }

  /* ================================================================ */
  /*  Endpoint router                                                  */
  /* ================================================================ */
  function resolveStackOpsMock(rawUrl, init) {
    var path = String(rawUrl || '');
    // strip origin
    path = path.replace(/^https?:\/\/[^/]+/i, '');
    // strip query + hash
    path = path.split('#')[0].split('?')[0];

    var method = String((init && init.method) || 'GET').toUpperCase();

    // Never intercept auth / non-dashboard traffic
    if (/^\/api\/auth\//.test(path) || /^\/api\/whatsapp\//.test(path)) return undefined;

    // ---- Sunbird dashboard endpoints ----
    if (path === '/api/sunbird/identity-dashboard' || path === '/api/sunbird/identity-dashboard-cached') return identityDashboardPayload();
    if (path === '/api/sunbird/governance') return governancePayload();
    if (path === '/api/sunbird/compliance-controls') return compliancePayload();
    if (path === '/api/sunbird/operations') return operationsPayload();
    if (path === '/api/sunbird/reports') return reportsPayload('30d');
    if (path === '/api/sunbird/reports/live-evidence') return reportsLiveEvidencePayload();
    if (path === '/api/sunbird/reports/settings') {
      if (method === 'PUT' || method === 'POST') return { success: true, saved: true, settings: reportsSettingsPayload().settings };
      return reportsSettingsPayload();
    }
    if (path === '/api/sunbird/reports/generate') {
      return { success: true, message: 'Demo mode - a sample report was produced from mock evidence.', report: { id: 'rep-demo-' + Date.now(), title: 'On-demand security report', generatedAt: new Date().toISOString(), status: 'ready', score: 70 } };
    }
    if (/^\/api\/sunbird\/reports\/[^/]+\/pdf$/.test(path)) return { __blob: SAMPLE_PDF, __type: 'application/pdf', __filename: 'StackOps-Demo-Report.pdf' };

    // ---- DB metric endpoints ----
    if (path === '/api/db/identity-metrics') {
      return { success: true, metrics: { TotalUsers: IDENTITY_USERS.length, ActiveUsers: IDENTITY_ACTIVE_24H, AdminRoles: IDENTITY_ADMIN_COUNT, SecurityScore: IDENTITY_SECURITY_SCORE, totalUsers: IDENTITY_USERS.length, activeUsers: IDENTITY_ACTIVE_24H, adminRoles: IDENTITY_ADMIN_COUNT, securityScore: IDENTITY_SECURITY_SCORE } };
    }
    if (path === '/api/db/identity-details') return identityDashboardPayload();
    if (path === '/api/db/device-metrics') return devicesPayload();
    if (path === '/api/microsoft-devices') return devicesPayload();
    if (path === '/api/db/email-metrics' || path === '/api/db/email-security' || path === '/api/email-security') return emailPayload();
    if (path === '/api/db/security-events' || path === '/api/security-events') return securityEventsPayload();
    if (path === '/api/db/applications') return applicationsPayload();
    if (path === '/api/db/application-metrics') return applicationMetricsPayload();
    if (/^\/api\/app-access\//.test(path)) return appAccessPayload(decodeURIComponent(path.split('/api/app-access/')[1] || ''));
    if (path === '/api/db/backup-recovery') return backupPayload();
    if (path === '/api/cloudflare/network-security/summary') return networkPayload();
    if (path === '/api/client/latest-invoice') return latestInvoicePayload();

    return undefined; // -> fall through to the real server
  }
  window.resolveStackOpsMock = resolveStackOpsMock;

  /* A tiny but valid single-page PDF used for the "download report" action. */
  var SAMPLE_PDF = [
    '%PDF-1.4',
    '1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj',
    '2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj',
    '3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 300]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>endobj',
    '4 0 obj<</Length 132>>stream',
    'BT /F1 20 Tf 60 220 Td (StackOps - Demo Security Report) Tj',
    '0 -34 Td /F1 12 Tf (Generated from mock evidence. Not a real report.) Tj ET',
    'endstream endobj',
    '5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj',
    'trailer<</Root 1 0 R>>',
    '%%EOF'
  ].join('\n');

  /* ================================================================ */
  /*  Mock Response + fetch shim                                       */
  /* ================================================================ */
  function makeMockResponse(payload) {
    var isBlob = payload && payload.__blob != null;
    var bodyText = isBlob ? String(payload.__blob) : JSON.stringify(payload == null ? {} : payload);
    var headerMap = {
      'content-type': isBlob ? (payload.__type || 'application/octet-stream') : 'application/json'
    };
    if (isBlob && payload.__filename) headerMap['content-disposition'] = 'attachment; filename="' + payload.__filename + '"';

    var headers = {
      get: function (k) { return headerMap[String(k).toLowerCase()] || null; },
      has: function (k) { return Object.prototype.hasOwnProperty.call(headerMap, String(k).toLowerCase()); },
      forEach: function (cb) { Object.keys(headerMap).forEach(function (k) { cb(headerMap[k], k); }); },
      entries: function () { return Object.keys(headerMap).map(function (k) { return [k, headerMap[k]]; }); }
    };

    function build() {
      return {
        ok: true, status: 200, statusText: 'OK', redirected: false, type: 'basic',
        url: '', bodyUsed: false, headers: headers,
        json: function () { return Promise.resolve(isBlob ? {} : JSON.parse(bodyText)); },
        text: function () { return Promise.resolve(bodyText); },
        blob: function () {
          try { return Promise.resolve(new Blob([bodyText], { type: headerMap['content-type'] })); }
          catch (e) { return Promise.resolve({ size: bodyText.length, type: headerMap['content-type'] }); }
        },
        arrayBuffer: function () {
          var buf = new ArrayBuffer(bodyText.length);
          var view = new Uint8Array(buf);
          for (var i = 0; i < bodyText.length; i++) view[i] = bodyText.charCodeAt(i) & 0xff;
          return Promise.resolve(buf);
        },
        formData: function () { return Promise.resolve(new FormData()); },
        clone: function () { return build(); }
      };
    }
    return build();
  }
  window.makeStackOpsMockResponse = makeMockResponse;

  function installStackOpsMockFetch() {
    if (typeof window.fetch !== 'function' || window.__stackOpsMockFetchInstalled) return;
    var nativeFetch = window.fetch.bind(window);
    window.__stackOpsMockFetchInstalled = true;
    window.__stackOpsNativeFetch = nativeFetch;

    window.fetch = function (input, init) {
      try {
        if (isStackOpsMockUser()) {
          var url = typeof input === 'string'
            ? input
            : (input && (input.url || (typeof input.toString === 'function' && input.toString()))) || '';
          var payload = resolveStackOpsMock(url, init || (input && typeof input === 'object' ? input : null));
          if (payload !== undefined) {
            if (window.console && console.debug) console.debug('[StackOps Mock] served', url);
            return Promise.resolve(makeMockResponse(payload));
          }
        }
      } catch (err) {
        if (window.console) console.warn('[StackOps Mock] shim error, falling back to network:', err && err.message);
      }
      return nativeFetch(input, init);
    };
  }

  installStackOpsMockFetch();

  if (isStackOpsMockUser() && window.console) {
    console.info('[StackOps Mock] Demo dashboard active for user ' + MOCK_USER_ID + ' / company ' + MOCK_COMPANY_ID + '. All dashboard data is local mock data.');
  }
})();
