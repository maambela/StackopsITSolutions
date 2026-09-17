const bcrypt = require('bcryptjs');
const express = require('express');
const mysql = require('mysql2/promise');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const {SecretManagerServiceClient} = require('@google-cloud/secret-manager');
const { Webhook } = require('svix');
const SVGtoPDF = require('svg-to-pdfkit');
const { ClientSecretCredential } = require('@azure/identity');
const {
    normalizeSeverity: normalizeWhatsAppSeverity,
    normalizeWhatsAppRecipient,
    sendSecurityAlert
} = require('./services/whatsapp');
const { getCloudflareNetworkSecuritySummary } = require('./services/cloudflare');
const { createAzureOpenAIService } = require('./services/azure-openai');
const { createStackCTRLIntelligenceService } = require('./services/stackctrl-intelligence');
const { createStackCTRLIntelligenceScheduler, DEFAULT_OUTPUT_TYPES } = require('./services/intelligence/scheduler');
const { buildIdentityDashboardSource } = require('./services/intelligence/identity-dashboard-source');
const { buildIdentityDashboardPayload } = require('./services/intelligence/identity-dashboard-processor');
const { createIdentityEvidenceStore } = require('./services/intelligence/identity-evidence-store');
const { createIdentityEvidenceAutomation } = require('./services/intelligence/identity-evidence-automation');
const { buildDeviceDashboardPayload, normalizeDeviceAlertsPayload } = require('./services/intelligence/device-dashboard-processor');
const { createDeviceEvidenceStore } = require('./services/intelligence/device-evidence-store');
const { createDeviceEvidenceAutomation } = require('./services/intelligence/device-evidence-automation');
const { buildEmailDashboardPayload } = require('./services/intelligence/email-dashboard-processor');
const { createEmailEvidenceStore } = require('./services/intelligence/email-evidence-store');
const { createEmailEvidenceAutomation } = require('./services/intelligence/email-evidence-automation');
const { buildNetworkDashboardPayload } = require('./services/intelligence/network-dashboard-processor');
const { createNetworkEvidenceStore } = require('./services/intelligence/network-evidence-store');
const { createNetworkEvidenceAutomation } = require('./services/intelligence/network-evidence-automation');
const { buildBackupDashboardPayload } = require('./services/intelligence/backup-dashboard-processor');
const { createBackupEvidenceStore } = require('./services/intelligence/backup-evidence-store');
const { createTrackedCollectorRegistry, runAbortableOperation, acquireConnectionWithDeadline, runDatabaseOperationWithDeadline } = require('./services/intelligence/collector-runtime');
const { createBackupEvidenceAutomation } = require('./services/intelligence/backup-evidence-automation');
const { buildApplicationsDashboardPayload } = require('./services/intelligence/applications-dashboard-processor');
const { createApplicationsEvidenceStore } = require('./services/intelligence/applications-evidence-store');
const { createApplicationsEvidenceAutomation } = require('./services/intelligence/applications-evidence-automation');
const { buildSecurityDashboardPayload } = require('./services/intelligence/security-dashboard-processor');
const { createSecurityEvidenceStore } = require('./services/intelligence/security-evidence-store');
const { createSecurityEvidenceAutomation } = require('./services/intelligence/security-evidence-automation');
const { buildGovernanceDashboardPayload } = require('./services/intelligence/governance-dashboard-processor');
const { createGovernanceEvidenceStore } = require('./services/intelligence/governance-evidence-store');
const { createGovernanceEvidenceAutomation } = require('./services/intelligence/governance-evidence-automation');
const { buildComplianceDashboardPayload } = require('./services/intelligence/compliance-dashboard-processor');
const { createComplianceEvidenceStore } = require('./services/intelligence/compliance-evidence-store');
const { createComplianceEvidenceAutomation } = require('./services/intelligence/compliance-evidence-automation');
const { buildOperationsDashboardPayload } = require('./services/intelligence/operations-dashboard-processor');
const { createOperationsEvidenceStore } = require('./services/intelligence/operations-evidence-store');
const { createOperationsEvidenceAutomation } = require('./services/intelligence/operations-evidence-automation');
const { createStackCTRLServerAutomation } = require('./services/intelligence/server-automation');
const { createAdminIntelligenceService } = require('./services/admin-intelligence');
const { createEnterpriseIntelligenceService } = require('./services/enterprise-intelligence');
const { DateTime } = require('luxon');
const { createStackCTRLIntelligenceRouter } = require('./routes/stackctrl-intelligence');
const { createAdminIntelligenceRouter } = require('./routes/admin-intelligence');
const { createPowerBIReportingService } = require('./services/powerbi-reporting');
const { createPowerBIReportingRouter } = require('./routes/powerbi-reporting');

// invoice payment endpoints 
require("dotenv").config();

const ACCESS_TOKEN_SECRET = '7a076e42670cfe26193655fe5f48b776defe078754ca16fb9ae0a054b354d335';
const accessContextCache = new Map();

function getTenantByEmail(email) {
  const key = String(email || '').toLowerCase();
  const cached = accessContextCache.get(key);
  if (!cached) return null;
  return {
    clientId: cached.accessType || 'standard',
    tenantId: cached.tenantId || null,
    companyId: cached.companyId || null
  };
}

// ===============================
// MICROSOFT GRAPH -  Identity Protection
// ===============================
// Token cache (in production, use Redis or database)
const microsoftTokenCache = new Map();
let microsoftGraphCredentialsCache = null;
let microsoftGraphCredentialsPromise = null;
let microsoftGraphTokenPromise = null;
let microsoftGraphStartupWarningShown = false;
const MICROSOFT_GRAPH_CREDENTIAL_TIMEOUT_MS = Math.max(3000, Number(process.env.MICROSOFT_GRAPH_CREDENTIAL_TIMEOUT_MS) || 12000);
const MICROSOFT_GRAPH_TOKEN_TIMEOUT_MS = Math.max(3000, Number(process.env.MICROSOFT_GRAPH_TOKEN_TIMEOUT_MS) || 12000);
const STACKCTRL_COLLECTOR_TIMEOUT_MS = Math.max(15000, Number(process.env.STACKCTRL_COLLECTOR_TIMEOUT_MS) || 180000);
const BACKUP_DATABASE_TIMEOUT_MS = Math.max(5000, Number(process.env.BACKUP_DATABASE_TIMEOUT_MS) || 30000);
const authMethodsCache = new Map();
const AUTH_METHODS_CACHE_TTL_MS = 5 * 60 * 1000;
let identityEvidenceService = null;
let deviceEvidenceService = null;
let emailEvidenceService = null;
let networkEvidenceService = null;
let backupEvidenceService = null;
let applicationsEvidenceService = null;
let securityEvidenceService = null;
let governanceEvidenceService = null;
let complianceEvidenceService = null;
let operationsEvidenceService = null;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function getCachedAuthMethods(userId) {
  const cached = authMethodsCache.get(userId);
  if (!cached) return null;
  if (cached.expiresAt <= Date.now()) {
    authMethodsCache.delete(userId);
    return null;
  }
  return cached.methods;
}

function setCachedAuthMethods(userId, methods) {
  authMethodsCache.set(userId, {
    methods: Array.isArray(methods) ? methods : [],
    expiresAt: Date.now() + AUTH_METHODS_CACHE_TTL_MS
  });
}

function hasRealMfaMethod(authMethods) {
  if (!Array.isArray(authMethods) || authMethods.length === 0) return false;
  return authMethods.some(method => {
    const type = String(method?.['@odata.type'] || '').toLowerCase();
    // Password alone is not MFA; anything else counts as extra factor.
    return type && !type.includes('passwordauthenticationmethod');
  });
}

async function mapWithConcurrency(items, limit, worker) {
  const safeLimit = Math.max(1, Number(limit) || 1);
  const output = new Array(items.length);
  let cursor = 0;

  async function runner() {
    while (cursor < items.length) {
      const index = cursor++;
      output[index] = await worker(items[index], index);
    }
  }

  await Promise.all(Array.from({ length: Math.min(safeLimit, items.length) }, () => runner()));
  return output;
}

async function getMicrosoftGraphCredentials({ securityAlerts = false } = {}) {
  if (microsoftGraphCredentialsCache) return { ...microsoftGraphCredentialsCache, source: 'cache' };
  if (microsoftGraphCredentialsPromise) return microsoftGraphCredentialsPromise;
  if (securityAlerts) console.log('[security_alerts:graph_credentials:start] Loading Microsoft Graph credentials');
  const load = (async () => {
    try {
      const [tenantId, clientId, clientSecret] = await promiseWithTimeout(
        Promise.all([
          getSecret('MICROSOFT_TENANT_ID'),
          getSecret('MICROSOFT_CLIENT_ID'),
          getSecret('MICROSOFT_CLIENT_SECRET')
        ]),
        MICROSOFT_GRAPH_CREDENTIAL_TIMEOUT_MS,
        'Microsoft Graph credential loading'
      );
      if (!tenantId || !clientId || !clientSecret) {
        const error = new Error('Missing Microsoft Graph credentials: MICROSOFT_TENANT_ID, MICROSOFT_CLIENT_ID, and MICROSOFT_CLIENT_SECRET are required');
        error.code = 'GRAPH_CREDENTIALS_UNAVAILABLE';
        throw error;
      }
      microsoftGraphCredentialsCache = { tenantId, clientId, clientSecret };
      if (securityAlerts) console.log('[security_alerts:graph_credentials:complete_or_failed] complete (credentials cached)');
      return { ...microsoftGraphCredentialsCache, source: 'secret_or_environment' };
    } catch (error) {
      if (microsoftGraphCredentialsCache) {
        if (securityAlerts) console.warn('[security_alerts:graph_credentials:complete_or_failed] Secret refresh failed; using cached credentials:', error.message);
        return { ...microsoftGraphCredentialsCache, source: 'stale_cache', warning: error.message };
      }
      if (securityAlerts) console.error('[security_alerts:graph_credentials:complete_or_failed] failed:', error.message);
      if (!error.code) error.code = 'GRAPH_CREDENTIALS_UNAVAILABLE';
      throw error;
    }
  })();
  microsoftGraphCredentialsPromise = load;
  try { return await load; }
  finally { if (microsoftGraphCredentialsPromise === load) microsoftGraphCredentialsPromise = null; }
}

async function validateMicrosoftGraphCredentialsAtStartup() {
  try {
    await getMicrosoftGraphCredentials();
    console.log('[Microsoft Graph] Credential startup validation completed; credentials cached.');
    return { available: true };
  } catch (error) {
    if (!microsoftGraphStartupWarningShown) {
      microsoftGraphStartupWarningShown = true;
      console.warn(`[Microsoft Graph] Credential startup validation failed: ${error.message}`);
    }
    return { available: false, message: error.message };
  }
}

async function getMicrosoftGraphToken(options = {}) {
  const cacheKey = 'microsoft_graph_token';
  const cachedToken = microsoftTokenCache.get(cacheKey);
  if (cachedToken && cachedToken.expiresAt > Date.now()) {
    console.log('[Microsoft Graph] Using cached token');
    return cachedToken.token;
  }
  if (microsoftGraphTokenPromise) {
    console.log('[Microsoft Graph] Reusing token request already in progress');
    return microsoftGraphTokenPromise;
  }

  const load = (async () => {
    try {
      const { tenantId, clientId, clientSecret } = await getMicrosoftGraphCredentials({ securityAlerts: Boolean(options.securityAlerts) });
      console.log('[Microsoft Graph] Requesting new token...');
      const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
      const controller = new AbortController();
      const timeoutHandle = setTimeout(() => controller.abort(), MICROSOFT_GRAPH_TOKEN_TIMEOUT_MS);
      let response;
      try {
        response = await fetch(tokenUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId,
            scope: 'https://graph.microsoft.com/.default',
            client_secret: clientSecret,
            grant_type: 'client_credentials'
          }).toString(),
          signal: controller.signal
        });
      } finally {
        clearTimeout(timeoutHandle);
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`Token request failed: ${errorData.error_description || response.statusText}`);
      }

      const data = await response.json();
      const expiresInMs = Math.max(60, Number(data.expires_in) || 3600) * 1000;
      microsoftTokenCache.set(cacheKey, {
        token: data.access_token,
        expiresAt: Date.now() + expiresInMs - 60000
      });
      console.log('[Microsoft Graph] Token obtained successfully');
      return data.access_token;
    } catch (error) {
      console.error('[Microsoft Graph] Token generation failed:', error.message);
      if (!error.code && error.name === 'AbortError') error.code = 'GRAPH_TOKEN_TIMEOUT';
      throw error;
    }
  })();

  microsoftGraphTokenPromise = load;
  try {
    return await load;
  } finally {
    if (microsoftGraphTokenPromise === load) microsoftGraphTokenPromise = null;
  }
}

const MICROSOFT_GRAPH_REQUEST_TIMEOUT_MS = Math.max(
    3000,
    Number(process.env.MICROSOFT_GRAPH_REQUEST_TIMEOUT_MS) || 15000
);
const MICROSOFT_GRAPH_MAX_RESPONSE_BYTES = Math.max(
    256 * 1024,
    Number(process.env.MICROSOFT_GRAPH_MAX_RESPONSE_BYTES) || 4 * 1024 * 1024
);
const MICROSOFT_GRAPH_SHARED_CACHE_TTL_MS = Math.max(
    1000,
    Number(process.env.MICROSOFT_GRAPH_SHARED_CACHE_TTL_MS) || 60000
);
const microsoftGraphJsonCache = new Map();
const microsoftGraphJsonPromises = new Map();
let sunbirdOperationSequence = 0;

function runtimeSnapshot() {
    const memory = process.memoryUsage();
    return {
        rssMb: Math.round(memory.rss / 1024 / 1024),
        heapUsedMb: Math.round(memory.heapUsed / 1024 / 1024),
        heapTotalMb: Math.round(memory.heapTotal / 1024 / 1024),
        externalMb: Math.round(memory.external / 1024 / 1024)
    };
}

function logRuntimeOperation(event, details = {}) {
    console.log('[Runtime]', JSON.stringify({ event, at: new Date().toISOString(), ...runtimeSnapshot(), ...details }));
}

const collectorRuntimeLogger = {
    info(_prefix, details) { logRuntimeOperation(details.event, details); }
};
const identityEvidenceCollectors = createTrackedCollectorRegistry({ logger: collectorRuntimeLogger, timeoutMs: STACKCTRL_COLLECTOR_TIMEOUT_MS });
const deviceEvidenceCollectors = createTrackedCollectorRegistry({ logger: collectorRuntimeLogger, timeoutMs: STACKCTRL_COLLECTOR_TIMEOUT_MS });
const emailEvidenceCollectors = createTrackedCollectorRegistry({ logger: collectorRuntimeLogger, timeoutMs: STACKCTRL_COLLECTOR_TIMEOUT_MS });
const networkEvidenceCollectors = createTrackedCollectorRegistry({ logger: collectorRuntimeLogger, timeoutMs: STACKCTRL_COLLECTOR_TIMEOUT_MS });
const backupEvidenceCollectors = createTrackedCollectorRegistry({ logger: collectorRuntimeLogger, timeoutMs: STACKCTRL_COLLECTOR_TIMEOUT_MS });
const applicationsEvidenceCollectors = createTrackedCollectorRegistry({ logger: collectorRuntimeLogger, timeoutMs: STACKCTRL_COLLECTOR_TIMEOUT_MS });
const securityEvidenceCollectors = createTrackedCollectorRegistry({ logger: collectorRuntimeLogger, timeoutMs: STACKCTRL_COLLECTOR_TIMEOUT_MS });
const governanceEvidenceCollectors = createTrackedCollectorRegistry({ logger: collectorRuntimeLogger, timeoutMs: STACKCTRL_COLLECTOR_TIMEOUT_MS });
const complianceEvidenceCollectors = createTrackedCollectorRegistry({ logger: collectorRuntimeLogger, timeoutMs: STACKCTRL_COLLECTOR_TIMEOUT_MS });
const operationsEvidenceCollectors = createTrackedCollectorRegistry({ logger: collectorRuntimeLogger, timeoutMs: STACKCTRL_COLLECTOR_TIMEOUT_MS });

async function fetchGraphResponseWithDeadline(url, token, { signal = null, collectorContext = {}, label = 'Microsoft Graph request' } = {}) {
    const context = { companyId: Number(collectorContext.companyId) || null, runId: collectorContext.runId || null, pipelineExecutionId: collectorContext.pipelineExecutionId || null, sourceKey: collectorContext.sourceKey || null, label };
    const startedAt = Date.now();
    logRuntimeOperation('snapshot_source_http_started', context);
    try {
        const result = await runAbortableOperation({
            timeoutMs: MICROSOFT_GRAPH_REQUEST_TIMEOUT_MS,
            signal,
            label,
            operation: async ({ signal: requestSignal }) => {
                const response = await fetch(url, { headers: { 'Authorization': `Bearer ${token}` }, signal: requestSignal });
                const body = await readBoundedResponseText(response, MICROSOFT_GRAPH_MAX_RESPONSE_BYTES, label);
                return { response, body };
            }
        });
        logRuntimeOperation('snapshot_source_http_completed', { ...context, elapsedMs: Date.now() - startedAt });
        return result;
    } catch (error) {
        logRuntimeOperation(error?.code === 'STACKCTRL_OPERATION_TIMEOUT' ? 'snapshot_source_http_timeout' : 'snapshot_source_http_failed', { ...context, elapsedMs: Date.now() - startedAt, error: String(error?.message || error) });
        throw error;
    }
}

async function writeBackupRecoveryPayloadCache(companyId, payload, { signal = null, collectorContext = {} } = {}) {
    const connection = typeof pool.getConnection === 'function'
        ? await acquireConnectionWithDeadline(pool, { timeoutMs: BACKUP_DATABASE_TIMEOUT_MS, signal, label: 'BackupRecoveryPayloadCache connection' })
        : pool;
    const ownsConnection = connection !== pool;
    try {
        return await runDatabaseOperationWithDeadline({
            connection,
            timeoutMs: BACKUP_DATABASE_TIMEOUT_MS,
            signal,
            label: 'BackupRecoveryPayloadCache write',
            operation: () => connection.query(`REPLACE INTO BackupRecoveryPayloadCache (CompanyID, Payload, LastUpdated) VALUES (?, ?, NOW())`, [companyId, JSON.stringify(payload)])
        });
    } finally {
        if (ownsConnection && typeof connection.release === 'function') connection.release();
    }
}

async function readBoundedResponseText(response, maxBytes, label) {
    const advertisedLength = Number(response.headers.get('content-length') || 0);
    if (advertisedLength > maxBytes) {
        throw new Error(`${label} response exceeds the ${maxBytes}-byte limit`);
    }
    if (!response.body) return '';

    const reader = response.body.getReader();
    const chunks = [];
    let totalBytes = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            totalBytes += value.byteLength;
            if (totalBytes > maxBytes) {
                await reader.cancel();
                throw new Error(`${label} response exceeds the ${maxBytes}-byte limit`);
            }
            chunks.push(Buffer.from(value));
        }
    } finally {
        reader.releaseLock();
    }
    return Buffer.concat(chunks, totalBytes).toString('utf8');
}

async function fetchMicrosoftGraphJsonAttempt(url, token, label) {
    const startedAt = process.hrtime.bigint();
    const cpuStart = process.cpuUsage();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), MICROSOFT_GRAPH_REQUEST_TIMEOUT_MS);
    logRuntimeOperation('graph_request_start', { label });
    try {
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            signal: controller.signal
        });
        const body = await readBoundedResponseText(response, MICROSOFT_GRAPH_MAX_RESPONSE_BYTES, label);
        if (!response.ok) {
            throw new Error(`${label} failed (${response.status}): ${body.slice(0, 300) || response.statusText}`);
        }
        const payload = body ? JSON.parse(body) : {};
        logRuntimeOperation('graph_request_complete', {
            label,
            responseBytes: Buffer.byteLength(body),
            durationMs: Number(process.hrtime.bigint() - startedAt) / 1e6,
            cpuUserMicros: process.cpuUsage(cpuStart).user
        });
        return payload;
    } catch (error) {
        const message = error.name === 'AbortError'
            ? `${label} timed out after ${MICROSOFT_GRAPH_REQUEST_TIMEOUT_MS}ms`
            : error.message;
        logRuntimeOperation('graph_request_failed', {
            label,
            durationMs: Number(process.hrtime.bigint() - startedAt) / 1e6,
            cpuUserMicros: process.cpuUsage(cpuStart).user,
            error: message
        });
        throw new Error(message);
    } finally {
        clearTimeout(timeout);
    }
}

function isRetryableGraphError(error) {
    return /\((?:408|429|5\d\d)\)|timed out|network|fetch failed/i.test(String(error?.message || ''));
}

async function fetchMicrosoftGraphJson(url, token, label, { shared = true, retries = 1 } = {}) {
    const cached = microsoftGraphJsonCache.get(url);
    if (shared && cached && cached.expiresAt > Date.now()) {
        logRuntimeOperation('graph_request_cache_hit', { label, responseBytes: cached.responseBytes });
        return cached.payload;
    }
    if (shared && microsoftGraphJsonPromises.has(url)) {
        logRuntimeOperation('graph_request_joined', { label });
        return microsoftGraphJsonPromises.get(url);
    }

    const request = (async () => {
        let lastError;
        for (let attempt = 0; attempt <= retries; attempt += 1) {
            try {
                const payload = await fetchMicrosoftGraphJsonAttempt(url, token, label);
                if (shared) {
                    const responseBytes = Buffer.byteLength(JSON.stringify(payload));
                    microsoftGraphJsonCache.set(url, {
                        payload,
                        responseBytes,
                        expiresAt: Date.now() + MICROSOFT_GRAPH_SHARED_CACHE_TTL_MS
                    });
                }
                return payload;
            } catch (error) {
                lastError = error;
                if (attempt >= retries || !isRetryableGraphError(error)) break;
                const retryDelayMs = 250 * (attempt + 1);
                logRuntimeOperation('graph_request_retry', { label, attempt: attempt + 1, retryDelayMs, error: error.message });
                await sleep(retryDelayMs);
            }
        }
        throw lastError;
    })();

    if (shared) microsoftGraphJsonPromises.set(url, request);
    try {
        return await request;
    } finally {
        if (shared && microsoftGraphJsonPromises.get(url) === request) {
            microsoftGraphJsonPromises.delete(url);
        }
    }
}

function beginSunbirdOperation(req, operation) {
    const requestId = `${operation}-${++sunbirdOperationSequence}`;
    const startedAt = process.hrtime.bigint();
    const cpuStart = process.cpuUsage();
    const tenant = req.user?.companyId || req.user?.tenantId || null;
    const traceId = String(req.get?.('x-cloud-trace-context') || '').split('/')[0] || null;
    const log = (event, details = {}) => logRuntimeOperation(event, {
        requestId,
        traceId,
        operation,
        endpoint: req.path,
        tenant,
        elapsedMs: Math.round(Number(process.hrtime.bigint() - startedAt) / 1e6),
        ...details
    });    log('sunbird_operation_start');
    return {
        step(name, details = {}) { log('sunbird_operation_step', { step: name, ...details }); },
        finish(status, details = {}) {
            log('sunbird_operation_finish', {
                status,
                durationMs: Number(process.hrtime.bigint() - startedAt) / 1e6,
                cpuUserMicros: process.cpuUsage(cpuStart).user,
                ...details
            });
        }
    };
}

function sendSunbirdJson(res, payload, operation) {
    operation.step('response_serialization_start');
    const body = JSON.stringify(payload);
    if (Buffer.byteLength(body) > SUNBIRD_DASHBOARD_MAX_RESPONSE_BYTES) {
        throw new Error(`Sunbird dashboard response exceeds the ${SUNBIRD_DASHBOARD_MAX_RESPONSE_BYTES}-byte limit`);
    }
    operation.step('response_serialization_complete', { responseBytes: Buffer.byteLength(body) });
    res.type('application/json').send(body);
}

async function fetchMicrosoftUsers(token) {
  try {
        const data = await fetchMicrosoftGraphJson(
            'https://graph.microsoft.com/v1.0/users?$top=250&$select=displayName,mail,jobTitle,mobilePhone,userPrincipalName,id,userType,accountEnabled,assignedLicenses,licenseAssignmentStates',
            token,
            'Microsoft Graph users'
        );
    return data.value || [];
  } catch (error) {
    console.error('[Microsoft Graph] Failed to fetch users:', error.message);
    throw error;
  }
}

// Fetch all role assignments from Microsoft Graph
async function fetchMicrosoftRoleAssignments(token) {
  try {
        const data = await fetchMicrosoftGraphJson(
            'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$top=250&$expand=roleDefinition',
            token,
            'Microsoft Graph role assignments'
        );
    return data.value || [];
  } catch (error) {
    console.error('[Microsoft Graph] Failed to fetch role assignments:', error.message);
    throw error;
  }
}

// Fetch sign-in logs from Microsoft Graph
async function fetchMicrosoftSignIns(token, daysBack = 30) {
  try {
    const since = new Date();
    since.setDate(since.getDate() - daysBack);
    const filterDate = since.toISOString();

        const data = await fetchMicrosoftGraphJson(
            `https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=createdDateTime ge ${filterDate}&$orderby=createdDateTime desc&$top=250&$select=createdDateTime,userPrincipalName,userId,appDisplayName,clientAppUsed,ipAddress,location,deviceDetail,status`,
            token,
            'Microsoft Graph sign-ins'
    );
    return data.value || [];
  } catch (error) {
    console.error('[Microsoft Graph] Failed to fetch sign-ins:', error.message);
    return []; // Return empty array if sign-ins not available
  }
}

// Fetch authentication methods for a specific user
async function fetchUserAuthMethods(token, userId, retries = 2) {
  try {
        const data = await fetchMicrosoftGraphJson(
      `https://graph.microsoft.com/v1.0/users/${userId}/authentication/methods`,
            token,
            `Microsoft Graph authentication methods for ${userId}`,
            { retries }
    );
    const methods = data.value || [];
    setCachedAuthMethods(userId, methods);
    return methods;
  } catch (error) {
    console.error(`[Microsoft Graph] Failed to fetch auth methods for ${userId}:`, error.message);
    const cached = getCachedAuthMethods(userId);
    if (cached) return cached;
    return [];
  }
}

// ===============================
// APPLICATIONS & SERVICE PRINCIPALS
// ===============================
// Fetch service principals (applications) from Microsoft Graph
async function fetchMicrosoftServicePrincipals(token) {
  try {
        const data = await fetchMicrosoftGraphJson(
            'https://graph.microsoft.com/v1.0/servicePrincipals?$top=250&$select=id,displayName,servicePrincipalType,publisherName,createdDateTime,appOwnerOrganizationId,appRoles,oauth2PermissionScopes',
            token,
            'Microsoft Graph service principals'
        );
    return data.value || [];
  } catch (error) {
    console.error('[Microsoft Graph] Failed to fetch service principals:', error.message);
    throw error;
  }
}

// Fetch groups from Microsoft Graph
async function fetchMicrosoftGroups(token) {
  try {
        const data = await fetchMicrosoftGraphJson(
            'https://graph.microsoft.com/v1.0/groups?$top=250&$select=id,displayName,mailNickname',
            token,
            'Microsoft Graph groups'
        );
    return data.value || [];
  } catch (error) {
    console.error('[Microsoft Graph] Failed to fetch groups:', error.message);
    return [];
  }
}

// Fetch app role assignments for a service principal
async function fetchAppRoleAssignments(token, servicePrincipalId) {
  try {
        const data = await fetchMicrosoftGraphJson(
            `https://graph.microsoft.com/v1.0/servicePrincipals/${servicePrincipalId}/appRoleAssignedTo?$top=250`,
            token,
            `Microsoft Graph app assignments for ${servicePrincipalId}`
        );
    return data.value || [];
  } catch (error) {
    console.error('[Microsoft Graph] Failed to fetch app role assignments:', error.message);
    return [];
  }
}

const app = express();
// Middleware for parsing bodies with raw support (critical for payment signatures)
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString();
    }
}));
app.use(express.urlencoded({ 
    extended: true,
    verify: (req, res, buf) => {
        req.rawBody = buf.toString();
    }
}));

// GLOBAL REQUEST LOGGER for PayFast/Yoco Debugging
app.use((req, res, next) => {
    if (req.path.includes('payfast') || req.path.includes('yoco')) {
        console.log(`[DEBUG] Incoming ${req.method} request to ${req.path} from ${req.ip}`);
        console.log(`[DEBUG] Headers: ${JSON.stringify(req.headers)}`);
    }
    next();
});

app.use(cors());

// Rate limiting for chatbot - simple in-memory store (consider Redis for production)
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 30; // 30 requests per minute per user

// Rate limiting middleware for chatbot
function chatRateLimit(req, res, next) {
    const userId = req.user?.id;
    if (!userId) return next();
    
    const now = Date.now();
    const userKey = `chat_${userId}`;
    const userRequests = rateLimitStore.get(userKey) || [];
    
    // Remove requests outside the time window
    const recentRequests = userRequests.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
    
    if (recentRequests.length >= RATE_LIMIT_MAX_REQUESTS) {
        return res.status(429).json({ 
            text: "Rate limit exceeded. Please wait a moment before sending another message.",
            buttons: null
        });
    }
    
    recentRequests.push(now);
    rateLimitStore.set(userKey, recentRequests);
    next();
}

// Supabase disabled as MySQL credentials were provided
let useSupabase = false; 
let supabase = null;

// Supabase client initialization skipped since useSupabase is false

let pool = null;

if (!useSupabase) {
    const requiredDatabaseSettings = ['DB_USER', 'DB_PASSWORD', 'DB_NAME'];
    const missingDatabaseSettings = requiredDatabaseSettings.filter(name => !String(process.env[name] || '').trim());
    if (missingDatabaseSettings.length) {
        throw new Error(`Missing required database configuration: ${missingDatabaseSettings.join(', ')}`);
    }
    const dbConfig = {
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        enableKeepAlive: true,            // Enable TCP keepalive to prevent stale connections
        keepAliveInitialDelay: 0,         // Start keepalive immediately
        decimalNumbers: true,             // Return DECIMAL values as numbers
        supportBigNumbers: true,          // Support large numbers
        bigNumberStrings: false,          // Convert large numbers to strings if needed
        connectTimeout: 30000,            // 30 second connection timeout
        
        /*
        authPlugins: {
            'caching_sha2_password': () => require('mysql2/lib/auth_plugins/caching_sha2_password')
        } */
    };

    const cloudSqlConnectionName = String(process.env.CLOUD_SQL_CONNECTION_NAME || '').trim();
    const socketPath = String(process.env.DB_SOCKET_PATH || (cloudSqlConnectionName ? `/cloudsql/${cloudSqlConnectionName}` : '')).trim();
    if (socketPath) dbConfig.socketPath = socketPath;
    else {
        dbConfig.host = process.env.DB_HOST || '127.0.0.1';
        dbConfig.port = Number(process.env.DB_PORT || 3306);
    }
    console.log(`\n[DB] Attempting to connect via ${socketPath ? 'Cloud SQL socket' : 'configured TCP host'}`);
    console.log('[DB] Config: connectTimeout=30s');

    try {
        // Use mysql.createPool (promise-based) for modern Node.js
        pool = mysql.createPool(dbConfig);
        
        // Add pool error handlers
        pool.on('error', (err) => {
            console.error('[POOL] ❌ Unexpected pool error:', err.message);
            console.error('[POOL] Error code:', err.code);
            console.error('[POOL] Error errno:', err.errno);
        });

        pool.on('connection', (connection) => {
            console.log('[POOL] ✅ New connection created to Cloud SQL');
        });

        console.log('[POOL] ✅ MySQL pool created with settings:');
        console.log('[POOL]   - connectionLimit: 10');
        console.log('[POOL]   - queueLimit: 0 (unlimited queue)');
        console.log('[POOL]   - keepAliveInitialDelay: 0 (keepalive enabled)');
        console.log('[POOL]   - connectionTimeout: 30 seconds');
        
        // Try a simple test connection immediately (don't wait for result)
        pool.getConnection()
            .then(conn => {
                console.log('[DB] ✅ Test connection successful - Cloud SQL is reachable');
                conn.release();
            })
            .catch(err => {
                console.error('[DB] ❌ Test connection failed:', err.message);
                console.error('[DB] ❌ Cloud SQL may not be accessible from Cloud Run');
                console.error('[DB] ❌ Check: 1) IAM permissions (Cloud SQL Client role)');
                console.error('[DB] ❌        2) IAM bindings for Cloud Run service account');
                console.error('[DB] ❌        3) Cloud SQL instance status (should be RUNNABLE)');
                console.error('[DB] ❌        4) Socket path matches instance: ' + socketPath);
                console.error('[DB] Error code:', err.code, 'Errno:', err.errno);
            });
        
    } catch (error) {
        console.error('❌ Failed to create MySQL pool.', error);
        // Fallback logic removed since Supabase is disabled
    }
}

if (!pool) {
    console.warn('MySQL pool unavailable.');
}

function formatDateToMySQL(date) {
    return date.toISOString().slice(0, 19).replace('T', ' ');
}

/**
 * Generate PayFast signature
 * @param {Object} data - The data to sign
 * @param {string} passphrase - PayFast passphrase
 * @returns {string} - MD5 signature
 */

function generatePayFastSignature(data, passphrase = null) {
    let pfOutput = "";
    
    // PayFast ITN signature requires fields to be in the same order they were received.
    // For ITN specifically, it's safer to iterate through all fields provided except 'signature'.
    // For link generation, the order we set in the object is preserved.
    for (let key in data) {
        if (Object.prototype.hasOwnProperty.call(data, key) && key !== "signature") {
            const value = data[key];
            if (value !== "" && value !== null && value !== undefined) {
                pfOutput += `${key}=${encodeURIComponent(String(value).trim()).replace(/%20/g, "+")}&`;
            }
        }
    }

    let getString = pfOutput.slice(0, -1);
    if (passphrase && passphrase.trim() !== "") {
        getString += `&passphrase=${encodeURIComponent(passphrase.trim()).replace(/%20/g, "+")}`;
    }

    const signature = crypto.createHash("md5").update(getString).digest("hex");
    // Detailed logging for ITN debugging
    if (data.m_payment_id || data.pf_payment_id) {
        console.log(`[PAYFAST SIGNATURE DEBUG] Data Keys: ${Object.keys(data).join(", ")}`);
        console.log(`[PAYFAST SIGNATURE DEBUG] String to hash: "${getString}"`);
        console.log(`[PAYFAST SIGNATURE DEBUG] Resulting signature: "${signature}"`);
    }
    return signature;
}

/**
 * Generate PayFast payment link
 */


async function generatePayFastLink(paymentData) {
    try {
        const merchantId = await getSecret('PAYFAST_MERCHANT_ID');
        const merchantKey = await getSecret('PAYFAST_MERCHANT_KEY');
        const passphrase = await getSecret('PAYFAST_PASSPHRASE');
        const mode = await getSecret('PAYFAST_MODE') || 'live';
        
        const baseUrl = mode === 'sandbox' 
            ? 'https://sandbox.payfast.co.za/eng/process' 
            : 'https://www.payfast.co.za/eng/process';

        // Order of properties is important for consistency with signature loop
        const data = {
            merchant_id: merchantId,
            merchant_key: merchantKey,
            return_url: 'https://stackopsit.co.za/success',
            cancel_url: 'https://stackopsit.co.za/cancel',
            notify_url: 'https://stackopsit.co.za/api/payfast/itn',
            name_first: paymentData.name_first,
            name_last: paymentData.name_last,
            email_address: paymentData.email_address,
            m_payment_id: paymentData.m_payment_id,
            amount: parseFloat(paymentData.amount).toFixed(2),
            item_name: paymentData.item_name,
            item_description: paymentData.item_description,
            custom_int1: paymentData.custom_int1,
            custom_str1: paymentData.custom_str1
        };

            const signature = generatePayFastSignature(data, passphrase); // Generate signature for PayFast
        data.signature = signature;

        const queryString = Object.keys(data)
            .filter(key => data[key] !== "" && data[key] !== null && data[key] !== undefined)
            .map(key => `${key}=${encodeURIComponent(String(data[key]).trim()).replace(/%20/g, "+")}`)
            .join('&');

        return `${baseUrl}?${queryString}`;
    } catch (error) {
        console.error('Error generating PayFast link:', error);
        return null;
    }
}

// ===============================
// Azure AD + Microsoft Graph API for Email
// ===============================
// Credentials are fetched from Google Secret Manager
let azureCredential = null;
let graphTokenCache = {
  token: null,
  expiresAt: 0
};

function readConfiguredSecret(...names) {
  for (const name of names) {
    const value = String(process.env[name] || '').trim();
    if (value) return value;
  }
  return null;
}

async function getConfiguredSecret(...names) {
  const environmentValue = readConfiguredSecret(...names);
  if (environmentValue) return environmentValue;

  for (const name of names) {
    const value = await getSecret(name);
    if (value) return value;
  }
  return null;
}

function getAzureEmailCredentialStatus() {
  const tenantId = readConfiguredSecret('AZURE_TENANT_ID', 'MICROSOFT_TENANT_ID');
  const clientId = readConfiguredSecret('AZURE_CLIENT_ID', 'MICROSOFT_CLIENT_ID');
  const clientSecret = readConfiguredSecret('AZURE_CLIENT_SECRET', 'MICROSOFT_CLIENT_SECRET');
  const missing = [];

  if (!tenantId) missing.push('AZURE_TENANT_ID or MICROSOFT_TENANT_ID');
  if (!clientId) missing.push('AZURE_CLIENT_ID or MICROSOFT_CLIENT_ID');
  if (!clientSecret) missing.push('AZURE_CLIENT_SECRET or MICROSOFT_CLIENT_SECRET');

  return {
    ready: missing.length === 0,
    missing,
    acceptedNames: {
      tenantId: ['AZURE_TENANT_ID', 'MICROSOFT_TENANT_ID'],
      clientId: ['AZURE_CLIENT_ID', 'MICROSOFT_CLIENT_ID'],
      clientSecret: ['AZURE_CLIENT_SECRET', 'MICROSOFT_CLIENT_SECRET']
    }
  };
}

async function initializeAzureCredential() {
  if (azureCredential) return;
  
  const tenantId = await getConfiguredSecret('AZURE_TENANT_ID', 'MICROSOFT_TENANT_ID');
  const clientId = await getConfiguredSecret('AZURE_CLIENT_ID', 'MICROSOFT_CLIENT_ID');
  const clientSecret = await getConfiguredSecret('AZURE_CLIENT_SECRET', 'MICROSOFT_CLIENT_SECRET');
  
  if (!tenantId || !clientId || !clientSecret) {
    const missing = getAzureEmailCredentialStatus().missing.join(', ');
    const error = new Error(`Missing Azure email credentials: ${missing}`);
    error.code = 'AZURE_EMAIL_CREDENTIALS_UNAVAILABLE';
    throw error;
  }
  
  azureCredential = new ClientSecretCredential(tenantId, clientId, clientSecret);
}

async function getGraphAccessToken() {
  // Return cached token if still valid (expires in 1 hour, refresh at 50 min)
  if (graphTokenCache.token && graphTokenCache.expiresAt > Date.now()) {
    return graphTokenCache.token;
  }
  
  try {
    await initializeAzureCredential();
    const tokenResponse = await azureCredential.getToken('https://graph.microsoft.com/.default');
    graphTokenCache.token = tokenResponse.token;
    graphTokenCache.expiresAt = Date.now() + (50 * 60 * 1000); // Cache for 50 minutes
    return tokenResponse.token;
  } catch (error) {
    console.error('[Graph API] Failed to get access token:', error.message);
    throw new Error('Failed to authenticate with Microsoft Graph: ' + error.message);
  }
}

// Helper function to send email via Microsoft Graph API
async function sendGraphEmail(to, subject, body, isHtml = true, fromAddress = 'noreply@stackopsit.co.za', attachments = []) {
  const maxRetries = 2;
  let lastError = null;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`[Graph Email] Attempting to send email to ${to}... (attempt ${attempt})`);
      
      const token = await getGraphAccessToken();
      
      const finalizedBody = isHtml
        ? applyStackOpsEmailEnding(applyStackOpsEmailBranding(body, subject), true)
        : applyStackOpsEmailEnding(body, false);
      const graphAttachments = (Array.isArray(attachments) ? attachments : [])
        .filter(attachment => attachment?.name && (attachment.contentBytes || attachment.content))
        .map(attachment => ({
          '@odata.type': '#microsoft.graph.fileAttachment',
          name: attachment.name,
          contentType: attachment.contentType || 'application/octet-stream',
          contentBytes: attachment.contentBytes ||
            (Buffer.isBuffer(attachment.content)
              ? attachment.content.toString('base64')
              : Buffer.from(String(attachment.content)).toString('base64'))
        }));
      const emailPayload = {
        message: {
          subject: subject,
          body: {
            contentType: isHtml ? 'HTML' : 'Text',
            content: finalizedBody
          },
          toRecipients: [
            {
              emailAddress: {
                address: to
              }
            }
          ],
          ...(graphAttachments.length ? { attachments: graphAttachments } : {})
        }
      };
      
      await axios.post(
        `https://graph.microsoft.com/v1.0/users/${fromAddress}/sendMail`,
        emailPayload,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          timeout: 10000
        }
      );
      
      console.log(`[Graph Email] Email successfully sent to ${to}`);
      return; // Success
    } catch (error) {
      lastError = error;
      const errorCode = error?.response?.status || error?.code || 'UNKNOWN';
      const errorMsg = error?.response?.data?.error?.message || error?.message || error;
      
      console.error(`[Graph Email] Failed to send email to ${to} (attempt ${attempt}):`, errorCode, errorMsg);
      
      // Retry logic for transient errors
      const retryableStatuses = [408, 429, 500, 502, 503, 504];
      const retryableCodes = ['ETIMEDOUT', 'ECONNECTION', 'ENOTFOUND', 'ESOCKET'];
      
      const shouldRetry = retryableStatuses.includes(errorCode) || 
                         retryableCodes.includes(error?.code);
      
      if (attempt < maxRetries && shouldRetry) {
        const delayMs = 1000 + (attempt * 500); // 1.5s, then 2s
        console.log(`[Graph Email] Retrying in ${delayMs}ms...`);
        await new Promise(r => setTimeout(r, delayMs));
      } else {
        throw lastError;
      }
    }
  }
  
  throw lastError;
}

// function to send email from noreply@stackopsit.co.za
const sendEmail = async (to, subject, body, isHtml = false, attachments = []) => {
  try {
    await sendGraphEmail(to, subject, body, isHtml, 'noreply@stackopsit.co.za', attachments);
  } catch (error) {
    console.error('[sendEmail] Error:', error.message);
    // Check if it's a credential error
    if (error.message && error.message.includes('Missing Azure credentials')) {
      console.error('[sendEmail] ⚠️ Azure credentials not configured. Please set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET in Google Secret Manager');
    }
    throw error;
  }
};

// function to send email from billing@stackopsit.co.za
const sendBillingEmail = async (to, subject, body, isHtml = false, attachments = []) => {
  try {
    await sendGraphEmail(to, subject, body, isHtml, 'billing@stackopsit.co.za', attachments);
  } catch (error) {
    console.error('[sendBillingEmail] Error:', error.message);
    // Check if it's a credential error
    if (error.message && error.message.includes('Missing Azure credentials')) {
      console.error('[sendBillingEmail] ⚠️ Azure credentials not configured. Please set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET in Google Secret Manager');
    }
    throw error;
  }
};

// function to send email from info@stackopsit.co.za
const sendInfoEmail = async (to, subject, body, isHtml = false, attachments = []) => {
  try {
    await sendGraphEmail(to, subject, body, isHtml, 'info@stackopsit.co.za', attachments);
  } catch (error) {
    console.error('[sendInfoEmail] Error:', error.message);
    if (error.message && error.message.includes('Missing Azure credentials')) {
      console.error('[sendInfoEmail] ⚠️ Azure credentials not configured. Please set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET in Google Secret Manager');
    }
    throw error;
  }
};

const STACKOPS_LEGAL_SIGNATURE = `StackOps IT Solutions (Pty) Ltd | Reg. No: 2016/120370/07 | B-BBEE Level: 1 Contributor: 135% | CSD Supplier: MAAA164124. Legally registered in South Africa, providing IT support, cybersecurity, governance, infrastructure, consulting services, and procurement of IT hardware in compliance with all applicable laws and regulations. All client information is protected in accordance with the Protection of Personal Information Act (POPIA) and our internal privacy and security policies. We are committed to safeguarding your data and ensuring confidentiality, integrity, and lawful processing at all times. All information, proposals, and pricing are accurate at the time of sending and governed by our Master Service Agreement (MSA) or client-specific contracts. Prices may be subject to change due to economic, regulatory, or supplier factors, with clients notified in advance. This email and attachments are confidential and intended solely for the named recipient(s). If received in error, please notify the sender immediately, delete the message, and do not disclose, copy, or distribute its contents. Unauthorized use of this communication is strictly prohibited. Emails are not guaranteed virus-free; StackOps IT Solutions accepts no liability for any damage, loss, or unauthorized access arising from this communication. StackOps IT Solutions is committed to business continuity, data security, and reliable technology operations. Our team provides professional, ethical, and transparent IT services, ensuring measurable value, operational efficiency, and compliance with industry best practices. View our Privacy Policy and Terms of Service here: StackOps IT Solutions | Your Complete IT Force`;
const STACKOPS_EMAIL_CLOSING_TEXT = 'Kind regards,\nThe StackOps IT Solutions Team';
const STACKOPS_EMAIL_SIGNATURE_MARKER = 'CSD Supplier: MAAA164124.';
const STACKOPS_EMAIL_LOGO_URL = 'https://i.postimg.cc/JzqbDrFn/Removed-Stack-Ops.png';
const STACKCTRL_EMAIL_LOGO_URL = 'https://i.postimg.cc/NjqZp4bp/Ctrl-big.png';
const STACKOPS_SUPPORT_EMAIL = 'support@stackopsit.co.za';

function renderStackCtrlLockOutline() {
  return `
    <div role="img" aria-label="Protected padlock" style="width:116px; height:112px; margin:0 auto; text-align:center;">
      <div style="width:52px; height:38px; margin:0 auto; border:4px solid #ff6b00; border-bottom:0; border-radius:32px 32px 0 0; line-height:0; font-size:0;">&nbsp;</div>
      <div style="width:84px; height:58px; margin:-1px auto 0 auto; border:4px solid #ff6b00; border-radius:12px; line-height:0; font-size:0;">
        <div style="width:10px; height:10px; margin:15px auto 0 auto; border:4px solid #ff6b00; border-radius:50%; line-height:0; font-size:0;">&nbsp;</div>
        <div style="width:4px; height:15px; margin:0 auto; background:#ff6b00; border-radius:3px; line-height:0; font-size:0;">&nbsp;</div>
      </div>
    </div>
  `;
}

function hasStackOpsSignature(content = '') {
  return String(content).includes(STACKOPS_EMAIL_SIGNATURE_MARKER) &&
    String(content).includes('Your Complete IT Force');
}

function hasStackOpsTeamClosing(content = '') {
  return String(content).includes('The StackOps IT Solutions Team');
}

function applyStackOpsEmailEnding(body = '', isHtml = false) {
  const content = String(body || '');
  const needsClosing = !hasStackOpsTeamClosing(content);
  const needsSignature = !hasStackOpsSignature(content);

  if (!needsClosing && !needsSignature) return content;

  if (!isHtml) {
    const footerParts = [];
    if (needsClosing) footerParts.push(STACKOPS_EMAIL_CLOSING_TEXT);
    if (needsSignature) footerParts.push(STACKOPS_LEGAL_SIGNATURE);
    return `${content.trim()}\n\n${footerParts.join('\n\n')}`;
  }

  const footerParts = [];
  if (needsClosing) {
    footerParts.push('<p style="margin:0 0 12px 0;">Kind regards,<br>The StackOps IT Solutions Team</p>');
  }
  if (needsSignature) {
    footerParts.push(`<div style="font-size:11px; color:#4b5563; line-height:1.5; border-top:1px solid #e5e7eb; padding-top:14px;">${escapeHtml(STACKOPS_LEGAL_SIGNATURE)}</div>`);
  }

  const footerHtml = `<div style="margin-top:24px; padding:18px 0 0 0;">${footerParts.join('')}</div>`;
  if (/<\/body>/i.test(content)) {
    return content.replace(/<\/body>/i, `${footerHtml}</body>`);
  }
  return `${content}${footerHtml}`;
}

function hasStackOpsBrandHeader(content = '') {
  return String(content).includes(STACKOPS_EMAIL_LOGO_URL) ||
    String(content).includes('data-stackops-email-brand');
}

function buildStackOpsBrandHeader(title = 'StackOps IT Solutions') {
  return `
    <div data-stackops-email-brand="true" style="background:#18212b; padding:24px 28px 0 28px;">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;">
        <tr>
          <td style="vertical-align:middle;">
            <img src="${STACKOPS_EMAIL_LOGO_URL}" alt="StackOps IT Solutions" style="display:block; max-width:160px; height:auto; border:0;">
          </td>
          <td style="vertical-align:middle; text-align:right; color:#dbeafe; font-family:Arial, sans-serif; font-size:17px; font-weight:700; line-height:1.4;">
            ${escapeHtml(title)}
          </td>
        </tr>
      </table>
    </div>
  `;
}

function applyStackOpsEmailBranding(body = '', subject = '') {
  const content = String(body || '');
  if (!/<\/body>/i.test(content) || hasStackOpsBrandHeader(content)) return content;

  const title = subject || 'StackOps IT Solutions';
  const headerHtml = buildStackOpsBrandHeader(title);

  if (/<body[^>]*>/i.test(content)) {
    return content.replace(/<body[^>]*>/i, match => `${match}${headerHtml}`);
  }

  return headerHtml + content;
}

function renderStackCtrlPlatformPanel({ title = 'StackCTRL Platform', detail = 'Protected client portal access' } = {}) {
  return `
    <div style="margin:24px 0; padding:28px 20px 26px 20px; background:#111820; border:1px solid rgba(255,112,27,0.28); border-radius:8px; text-align:center; overflow:hidden;">
      <table role="presentation" align="center" cellspacing="0" cellpadding="0" style="border-collapse:collapse; margin:0 auto 14px auto;">
        <tr>
          <td style="vertical-align:middle; text-align:right; padding:0 0 0 0;">
            <img src="${STACKCTRL_EMAIL_LOGO_URL}" alt="StackCTRL" style="display:block; width:170px; max-width:170px; height:auto; border:0;">
          </td>
          <td style="vertical-align:middle; width:132px; padding:0 0 0 12px;">
            ${renderStackCtrlLockOutline()}
          </td>
        </tr>
      </table>
      <div style="color:#f8fafc; font-size:15px; font-weight:700; letter-spacing:0.2px; margin-top:8px;">${escapeHtml(title)}</div>
      <div style="color:#cbd5e1; font-size:12px; margin-top:4px;">${escapeHtml(detail)}</div>
    </div>
  `;
}

function renderMfaStackCtrlHeaderBanner() {
  return `
<div class="mfa-stackctrl-banner" style="margin:18px 0 0 0; padding:12px; background:#111820; border:1px solid #4b2c1e; border-radius:8px; text-align:center; overflow:hidden; font-family:Arial, Helvetica, sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="width:100%; height:94px; border-collapse:collapse; margin:0;">
    <tr>
      <td style="width:54px; vertical-align:top; line-height:0; font-size:0;">&nbsp;</td>
      <td style="vertical-align:middle; text-align:center;">
        <img class="mfa-stackctrl-logo" src="https://i.postimg.cc/NjqZp4bp/Ctrl-big.png" alt="StackCTRL" style="display:block; width:125px; max-width:125px; height:auto; margin:0 auto; border:0;">
      </td>
      <td style="width:54px; vertical-align:top; text-align:right; line-height:0; font-size:0;">
        <div class="mfa-lock-wrap" style="display:inline-block; width:40px; height:54px; text-align:left; line-height:0; font-size:0;">
          <div class="mfa-lock-shackle" style="width:22px; height:18px; margin:0 0 0 8px; border:1px solid #dbdbdb; border-bottom:0; border-radius:14px 14px 0 0; line-height:0; font-size:0;">&nbsp;</div>
          <div class="mfa-lock-body" style="position:relative; width:38px; height:27px; margin:-1px 0 0 0; border:1px solid #dbdbdb; border-radius:6px; line-height:0; font-size:0;">
            <div class="mfa-keyhole-dot" style="width:4px; height:4px; margin:8px auto 0 auto; border:1px solid #dbdbdb; border-radius:50%; line-height:0; font-size:0;">&nbsp;</div>
            <div class="mfa-keyhole-stem" style="width:1px; height:8px; margin:0 auto; background:#dbdbdb; border-radius:1px; line-height:0; font-size:0;">&nbsp;</div>
          </div>
        </div>
      </td>
    </tr>
  </table>
</div>
  `;
}

function escapeHtml(value = '') {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderCorporateEmail({ title, greeting = 'Dear Client,', bodyHtml, headerFeatureHtml = '' }) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body { margin: 0; padding: 0; background: #f2f4f7; color: #1f2937; font-family: Arial, sans-serif; line-height: 1.6; }
        .email-container { max-width: 680px; margin: 24px auto; background: #ffffff; border: 1px solid #d9e2ec; border-radius: 6px; overflow: hidden; }
        .header { background: #111820; padding: 24px 28px 26px 28px; }
        .brand-table { width: 100%; border-collapse: collapse; }
        .brand-logo { display: block; max-width: 160px; height: auto; border: 0; }
        .header h1 { margin: 0; color: #dbeafe; font-size: 18px; font-weight: 200; text-align: right; line-height: 1.4; }
        .content { padding: 28px; }
        .highlight-box { margin: 22px 0; padding: 18px; border: 1px solid #c7d2fe; background: #f8fafc; border-radius: 6px; text-align: center; }
        .code { display: inline-block; font-family: Consolas, Monaco, monospace; font-size: 30px; letter-spacing: 6px; color: #1d4ed8; font-weight: 200; }
        .button { display: inline-block; padding: 11px 18px; background: #1d4ed8; color: #ffffff !important; text-decoration: none; border-radius: 4px; font-weight: 200; }
        .security-note { margin: 18px 0; padding: 14px; background: #fff7ed; border-left: 4px solid #f59e0b; color: #5f370e; }
        .signature { padding: 20px 28px; background: #f8fafc; border-top: 1px solid #e5e7eb; font-size: 11px; color: #4b5563; line-height: 1.5; }
        @media only screen and (max-width: 520px) {
          .email-container { width: 100% !important; max-width: 100% !important; margin: 0 auto !important; border-radius: 0 !important; }
          .header { padding: 16px 12px 18px 12px !important; }
          .brand-table, .brand-table tbody, .brand-table tr, .brand-table td { display: block !important; width: 100% !important; text-align: center !important; }
          .brand-logo { max-width: 108px !important; margin: 0 auto 8px auto !important; }
          .header h1 { text-align: center !important; font-size: 13px !important; line-height: 1.25 !important; margin: 0 auto !important; max-width: 230px !important; }
          .mfa-stackctrl-banner { margin: 12px 0 0 0 !important; padding: 8px !important; border-radius: 6px !important; }
          .mfa-stackctrl-logo { width: 92px !important; max-width: 92px !important; margin: 0 auto !important; }
          .mfa-lock-wrap { width: 32px !important; height: 42px !important; text-align: left !important; }
          .mfa-lock-shackle { width: 18px !important; height: 14px !important; margin: 0 0 0 6px !important; border-width: 1px !important; border-radius: 12px 12px 0 0 !important; }
          .mfa-lock-body { width: 30px !important; height: 22px !important; margin: -1px 0 0 0 !important; border-width: 1px !important; border-radius: 5px !important; }
          .mfa-keyhole-dot { width: 3px !important; height: 3px !important; margin: 6px auto 0 auto !important; border-width: 1px !important; }
          .mfa-keyhole-stem { width: 1px !important; height: 6px !important; }
          .content { padding: 20px 16px !important; }
          .code { font-size: 24px !important; letter-spacing: 4px !important; }
        }
      </style>
    </head>
    <body>
      <div class="email-container">
        <div class="header" data-stackops-email-brand="true">
          <table role="presentation" class="brand-table" cellspacing="0" cellpadding="0">
            <tr>
              <td style="vertical-align:middle;">
                <img src="${STACKOPS_EMAIL_LOGO_URL}" alt="StackOps IT Solutions" class="brand-logo">
              </td>
              <td style="vertical-align:middle;">
                <h1>${escapeHtml(title)}</h1>
              </td>
            </tr>
          </table>
          ${headerFeatureHtml}
        </div>
        <div class="content">
          <p>${escapeHtml(greeting)}</p>
          ${bodyHtml}
          <p>Kind regards,<br>The StackOps IT Solutions Team</p>
        </div>
        <div class="signature">${escapeHtml(STACKOPS_LEGAL_SIGNATURE)}</div>
      </div>
    </body>
    </html>
  `;
}

function buildMfaEmail(user, mfaCode) {
  const firstName = user?.firstname || user?.firstName || '';
  const greeting = firstName ? `Dear ${firstName},` : 'Dear Client,';
  return renderCorporateEmail({
    title: 'Multi-Factor Authentication Verification',
    greeting,
    headerFeatureHtml: renderMfaStackCtrlHeaderBanner(),
    bodyHtml: `
      <p>We have received your request to sign in to the StackOps IT Solutions Client Portal. To complete your login securely, please use the multi-factor authentication code below.</p>
      <div class="highlight-box">
        <div class="code">${escapeHtml(mfaCode)}</div>
      </div>
      <div class="security-note">This MFA code will expire after 10 minutes. If you did not request this login code, please do not share it with anyone and contact us immediately at <a href="mailto:${STACKOPS_SUPPORT_EMAIL}" style="color:#1d4ed8; font-weight:700;">${STACKOPS_SUPPORT_EMAIL}</a>.</div>
    `
  });
}

function buildPasswordResetEmail(user, resetLink) {
  const firstName = user?.firstname || user?.firstName || '';
  const greeting = firstName ? `Dear ${firstName},` : 'Dear Client,';
  return renderCorporateEmail({
    title: 'Password Reset Request',
    greeting,
    bodyHtml: `
      <p>We received a request to reset the password for your StackOps IT Solutions Client Portal account.</p>
      <p>To set a new password, please use the secure link below. This link is unique to your account and will expire after 1 hour.</p>
      <p><a href="${escapeHtml(resetLink)}" class="button">Reset Password</a></p>
      <p>If the button does not open, copy and paste this link into your browser:</p>
      <p><a href="${escapeHtml(resetLink)}">${escapeHtml(resetLink)}</a></p>
      <div class="security-note">If you did not request a password reset, you can safely ignore this email. Your existing password will remain unchanged. If you are concerned about account security, contact <a href="mailto:${STACKOPS_SUPPORT_EMAIL}" style="color:#1d4ed8; font-weight:700;">${STACKOPS_SUPPORT_EMAIL}</a>.</div>
    `
  });
}

function buildClientCredentialsEmail({ firstName, lastName, email, password, loginLink, forgotPasswordLink }) {
  const fullName = `${firstName || ''} ${lastName || ''}`.trim();
  return renderCorporateEmail({
    title: 'StackOps IT Solutions Client Portal Access',
    greeting: fullName ? `Dear ${fullName},` : 'Dear Client,',
    bodyHtml: `
      ${renderStackCtrlPlatformPanel({
        title: 'Welcome to StackCTRL',
        detail: 'Your secure client portal access has been provisioned inside the StackOps IT Solutions platform.'
      })}
      <p>Your StackOps IT Solutions Client Portal account has been created. This portal provides secure access to your account information and client services.</p>
      <p>Please use the credentials below to sign in for the first time:</p>
      <div class="highlight-box" style="text-align: left;">
        <p><strong>Email:</strong> ${escapeHtml(email)}</p>
        <p><strong>Temporary password:</strong> <span style="font-family: Consolas, Monaco, monospace; font-weight: 200;">${escapeHtml(password)}</span></p>
      </div>
      <p><a href="${escapeHtml(loginLink)}" class="button">Open Client Portal</a></p>
      <div class="security-note">For your protection, please reset your temporary password after your first login. You can use the password reset page at any time if you need to update your password.</div>
      <p>Password reset page: <a href="${escapeHtml(forgotPasswordLink)}">${escapeHtml(forgotPasswordLink)}</a></p>
      <p>If you have any questions or if this account was not expected, please contact <a href="mailto:${STACKOPS_SUPPORT_EMAIL}" style="color:#1d4ed8; font-weight:700;">${STACKOPS_SUPPORT_EMAIL}</a> for assistance.</p>
    `
  });
}

// function to generate invoice PDF - REDESIGNED to match professional layout
async function generateInvoicePDF(invoiceData, items, companyData, clientData) {
    return new Promise((resolve, reject) => {
        try {
            const doc = new PDFDocument({ margin: 40, size: 'A4' });
            let buffers = [];
            
            doc.on('data', buffers.push.bind(buffers));
            doc.on('end', () => {
                let pdfData = Buffer.concat(buffers);
                resolve(pdfData);
            });
            
            doc.on('error', (err) => {
                reject(err);
            });

            const formatDate = (dateStr) => {
                const date = new Date(dateStr);
                return isNaN(date.getTime()) ? 'N/A' : date.toLocaleDateString('en-ZA');
            };

            // ==================== HEADER SECTION ====================
            
            // Right side: Logo with black background (Narrow and Tall)
            const logoBoxWidth = 95;
            const logoBoxHeight = 100; // Decreased height
            const logoBoxX = 480; // Pushed more to the left
            
            doc.rect(logoBoxX, 0, logoBoxWidth, logoBoxHeight).fill('#000000');
            
            // StackOps logo in the black box
            const logoPath = path.join(__dirname, 'Images', 'Logos', 'RemovedStackOps.png');
            if (fs.existsSync(logoPath)) {
                doc.image(logoPath, logoBoxX + 3, 30, { width: 80 });
            }

            // INVOICE title and Horizontal Line
            doc.fontSize(22).fillColor('#4a4a4a').font('Helvetica');
            const invoiceText = 'INVOICE';
            const invoiceWidth = doc.widthOfString(invoiceText);
            const invoiceX = logoBoxX - invoiceWidth - 70;
            const invoiceY = 30;
            
            doc.text(invoiceText, invoiceX, invoiceY + 10);
            
            // Horizontal line from beginning of page (full width: 0) to INVOICE - HEADER ZONE FULL WIDTH
            doc.moveTo(0, invoiceY + 18).lineTo(invoiceX - 10, invoiceY + 18).stroke('#333333');

            // Left side: Company info - starting straight from the beginning of the page (MARGIN 0)
            const startX = 0;
            doc.fontSize(10).fillColor('#333333').font('Helvetica');
            doc.text('Stackops IT Solutions Pty(Ltd)', startX, 75);
            doc.fontSize(9).text('Reg No: 2016/120370/07', startX, 90);
            doc.text('Mia Drive, Waterfall City', startX, 102);
            doc.text('Johannesburg, 1685', startX, 114);
            
            // QR Code to the right of company details
            const qrCodePath = path.join(__dirname, 'Images', 'QRCode.jpeg');
            if (fs.existsSync(qrCodePath)) {
                doc.image(qrCodePath, 170, 75, { width: 55, height: 55 });
            }
            
            // Horizontal line separator (only extends to 250 from left edge)
            doc.moveTo(startX, 135).lineTo(250, 135).stroke('#cccccc');
            
            // Contact details below company info
            doc.fontSize(8).fillColor('#666666');
            doc.text('Tel: 011 568 9337', startX + 110, 145);
            doc.text('Email: billing@stackopsit.co.za', startX + 110, 157);
            doc.text('Web: www.stackopsit.co.za', startX + 110, 169);
            
            // Horizontal line separator
            doc.moveTo(startX, 185).lineTo(250, 185).stroke('#cccccc');

            // ==================== BILL TO SECTION ====================
            
            doc.fontSize(8).fillColor('#333333').font('Helvetica-Bold');
            doc.text('Bill to', startX, 195);
            
            doc.fontSize(8).fillColor('#666666');
            doc.text(companyData.CompanyName, startX + 110, 195);
            doc.text(`${clientData.firstname} ${clientData.lastname}`, startX + 110, 210);
            doc.text(clientData.email || '', startX + 110, 225);

            // Horizontal line under Bill to section
            doc.moveTo(startX, 240).lineTo(250, 240).stroke('#cccccc');

            // Invoice details
            doc.fontSize(9).font('Helvetica-Bold');
            doc.text('Invoice Ref:', startX, 250);
            doc.font('Helvetica').text(`#${invoiceData.InvoiceNumber || 'N/A'}`, startX + 70, 250);
            
            doc.font('Helvetica-Bold').text('Date:', startX, 265);
            doc.font('Helvetica').text(formatDate(invoiceData.InvoiceDate), startX + 70, 265);
            // Horizontal line separator before table (MAIN CONTENT STARTS HERE - MARGIN 20-575)
            doc.moveTo(20, 300).lineTo(575, 300).stroke('#cccccc');

            // ==================== INVOICE ITEMS TABLE ====================
            
            const tableTop = 340;
            const colWidths = {
                category: 100,
                deliverables: 160,
                frequency: 85,
                rate: 85,
                total: 85
            };
            
            const col1 = 20;
            const col2 = col1 + colWidths.category;
            const col3 = col2 + colWidths.deliverables;
            const col4 = col3 + colWidths.frequency;
            const col5 = col4 + colWidths.rate;

            // Table header
            const tableLeftEdge = 20;
            const tableRightEdge = 575;
            const headerHeight = 25;
            
            // Border lines - top and bottom
            doc.moveTo(tableLeftEdge, tableTop).lineTo(tableRightEdge, tableTop).stroke('#cccccc');
            doc.moveTo(tableLeftEdge, tableTop + headerHeight).lineTo(tableRightEdge, tableTop + headerHeight).stroke('#cccccc');
            
            // Left and right vertical lines
            doc.moveTo(tableLeftEdge, tableTop).lineTo(tableLeftEdge, tableTop + headerHeight).stroke('#cccccc');
            doc.moveTo(tableRightEdge, tableTop).lineTo(tableRightEdge, tableTop + headerHeight).stroke('#cccccc');
            
            // Vertical lines between columns
            doc.moveTo(col2, tableTop).lineTo(col2, tableTop + headerHeight).stroke('#cccccc');
            doc.moveTo(col3, tableTop).lineTo(col3, tableTop + headerHeight).stroke('#cccccc');
            doc.moveTo(col4, tableTop).lineTo(col4, tableTop + headerHeight).stroke('#cccccc');
            doc.moveTo(col5, tableTop).lineTo(col5, tableTop + headerHeight).stroke('#cccccc');
            
            doc.fontSize(8).fillColor('#000000').font('Helvetica-Bold');
            doc.text('SERVICE CATEGORY', col1 + 5, tableTop + 8);
            doc.text('DELIVERABLES', col2 + 5, tableTop + 8);
            doc.text('FREQUENCY', col3 + 5, tableTop + 8);
            doc.text('RATE', col4 + 5, tableTop + 8);
            doc.text('TOTAL', col5 + 5, tableTop + 8);

            // Table rows
            doc.font('Helvetica');
            let currentY = tableTop + headerHeight;
            const rowHeight = 25;

            items.forEach((item, index) => {
                const y = currentY + (index * rowHeight);
                
                doc.fontSize(8).fillColor('#333333');
                
                // Service Category
                doc.text((item.ServiceCategory || item.Description || ''), col1 + 5, y + 8, { 
                    width: colWidths.category - 10,
                    align: 'left'
                });
                
                // Deliverables
                doc.text((item.Deliverables || ''), col2 + 5, y + 8, { 
                    width: colWidths.deliverables - 10,
                    align: 'left'
                });
                
                // Frequency
                doc.text((item.Frequency || 'Once-off'), col3 + 5, y + 8, { 
                    width: colWidths.frequency - 10,
                    align: 'left'
                });
                
                // Rate
                doc.text((item.Rate || ''), col4 + 5, y + 8, { 
                    width: colWidths.rate - 10,
                    align: 'left'
                });
                
                // Total
                doc.text(`R${parseFloat(item.Total || item.UnitPrice || 0).toFixed(2)}`, col5 + 5, y + 8, { 
                    width: colWidths.total - 10,
                    align: 'left'
                });
                
                // Horizontal line for this cell/row
                doc.moveTo(tableLeftEdge, y + rowHeight).lineTo(tableRightEdge, y + rowHeight).stroke('#cccccc');

                // Vertical lines for each row to ensure they are continuous
                doc.moveTo(tableLeftEdge, y).lineTo(tableLeftEdge, y + rowHeight).stroke('#cccccc');
                doc.moveTo(col2, y).lineTo(col2, y + rowHeight).stroke('#cccccc');
                doc.moveTo(col3, y).lineTo(col3, y + rowHeight).stroke('#cccccc');
                doc.moveTo(col4, y).lineTo(col4, y + rowHeight).stroke('#cccccc');
                doc.moveTo(col5, y).lineTo(col5, y + rowHeight).stroke('#cccccc');
                doc.moveTo(tableRightEdge, y).lineTo(tableRightEdge, y + rowHeight).stroke('#cccccc');
            });

            const itemsEndY = currentY + (items.length * rowHeight);

            // Bottom border of table - perfectly aligned with vertical lines
            doc.moveTo(tableLeftEdge, itemsEndY).lineTo(tableRightEdge, itemsEndY).stroke('#cccccc');
            doc.moveTo(tableLeftEdge, itemsEndY).lineTo(tableLeftEdge, itemsEndY).stroke('#cccccc');
            doc.moveTo(tableRightEdge, itemsEndY).lineTo(tableRightEdge, itemsEndY).stroke('#cccccc');

            // ==================== BANKING DETAILS & TOTALS (Combined Section) ====================
            
            // Horizontal line separator before table (MAIN CONTENT STARTS HERE - MARGIN 20-575)
            //doc.moveTo(20, 300).lineTo(575, 300).stroke('#cccccc');

            const bankingY = itemsEndY + 20;
            const contentX = 20;
            
            // Banking details (left side)
            doc.fontSize(9).font('Helvetica-Bold').fillColor('#000000');
            doc.text('BANKING DETAILS', contentX, bankingY);
            
            doc.fontSize(8).font('Helvetica').fillColor('#333333');
            doc.text('Bank: Standard Bank Business', contentX, bankingY + 16);
            doc.text('Account Name: StackOps IT Solutions', contentX, bankingY + 28);
            doc.text('Acc Number: 10255699752', contentX, bankingY + 40);
            doc.text('Branch Code: 050205', contentX, bankingY + 52);
            doc.text('Acc Type: Current', contentX, bankingY + 64);

            // Totals (right side, aligned with banking details)
            doc.fontSize(9).font('Helvetica').fillColor('#000000');
            const totalsRightX = 380;
            doc.text('SUB TOTAL:', totalsRightX, bankingY, { align: 'left', width: 80 });
            doc.text(`R${parseFloat(invoiceData.TotalAmount).toFixed(2)}`, totalsRightX + 85, bankingY, { align: 'left' });

            doc.text('VAT TAX:', totalsRightX, bankingY + 16, { align: 'left', width: 80 });
            doc.text('N/A', totalsRightX + 85, bankingY + 16, { align: 'left' });

            doc.fontSize(10).font('Helvetica-Bold');
            doc.text('TOTAL:', totalsRightX, bankingY + 32, { align: 'left', width: 80 });
            doc.text(`R${parseFloat(invoiceData.TotalAmount).toFixed(2)}`, totalsRightX + 85, bankingY + 32, { align: 'left' });

            // ==================== TERMS & CONDITIONS ====================
            
            const termsY = bankingY + 110;
            const mainContentLeft = 20;
            const mainContentRight = 575;
            const mainContentWidth = mainContentRight - mainContentLeft;
            
            doc.moveTo(mainContentLeft, termsY - 30).lineTo(mainContentRight, termsY - 30).stroke('#cccccc');
            doc.moveTo(mainContentLeft, termsY - 120).lineTo(mainContentRight, termsY - 120).stroke('#cccccc');
            
            // Container size
            const boxWidth = 60;
            const boxHeight = 20;

            const boxX = 7;
            const boxY = termsY - 28;

            const svg = fs.readFileSync('Images/yoco.svg', 'utf8');

            SVGtoPDF(doc, svg, boxX + 6, boxY + 6, {
            width: boxWidth - 12,
            height: boxHeight - 12,
            preserveAspectRatio: 'xMidYMid meet'
            });

            const payfastPath = path.join(__dirname, 'Images', 'Payfast.jpg');
            if (fs.existsSync(payfastPath)) {
                doc.image(payfastPath, boxX + boxWidth + 2, boxY + 3, { 
                    width: boxWidth - 10, 
                    height: boxHeight - 5,
                    align: 'center',
                    valign: 'center'
                });
            }

            doc.moveTo(mainContentLeft, termsY - 5).lineTo(mainContentRight, termsY - 5).stroke('#cccccc');
            doc.moveTo(mainContentLeft, termsY + 180).lineTo(mainContentRight, termsY + 180).stroke('#cccccc');

    

            doc.fontSize(8).font('Helvetica-Bold').fillColor('#000000');
            doc.text('TERMS & CONDITIONS', mainContentLeft, termsY);
            
            doc.fontSize(9).font('Helvetica').fillColor('#555555');
            
            // Build terms as one continuous flowing paragraph
            const termsTextStart = termsY + 16;
            const termsFont = 'Helvetica';
            const termsBold = 'Helvetica-Bold';
            const options = { width: mainContentWidth, align: 'justify', lineGap: 1, continued: true };

            doc.font(termsFont).text('All quotations are valid for 10 days from date of issue and subject to stock availability. Prices may change without prior notice. Ownership of goods remains with StackOps IT Solutions until payment is received in full. ', mainContentLeft, termsTextStart, options)
            .font(termsBold).text('Payment Terms: ', options)
            .font(termsFont).text('All quotations are based on cash payment into our bank account prior to processing any orders. No goods or services will be released until full cleared payment is received. (This is subject to specific projects). ', options)
            .font(termsBold).text('Proof of payment ', options)
            .font(termsFont).text('must be sent to ', options)
            .font(termsBold).text('sales@stackopsit.co.za ', options)
            .font(termsFont).text('to avoid delays. Orders will only be processed once full cleared payment reflects in StackOps IT Solutions Bank account. ', options)
            .font(termsBold).text('Confidentiality: ', options)
            .font(termsFont).text('This quotation is intended solely for the recipient and may not be shared with third parties without written consent from StackOps IT Solutions. SLA & Service Commitment: All services and deliveries are subject to StackOps Service Level Commitments unless otherwise agreed in writing. ', options)
            .font(termsBold).text('Support: ', options)
            .font(termsFont).text('Manufacturer warranties apply unless otherwise stated. We remain available for clarification or support regarding this quotation. ', options)
            .font(termsBold).text('Data Protection: ', options)
            .font(termsFont).text('All Client information is handled in strict compliance with the Protection of Personal Information Act(POPIA). Non-Liability for Delays: StackOps IT Solutions cannot be held liable for delays caused by suppliers, manufacturers, or circumstances beyond our control. Professional Procurement: StackOps IT Solutions (Pty) Ltd is a registered South African entity, fully compliant with CIPC, SARS, and applicable procurement regulations. ', options)
            .font(termsBold).text('Pricing: ', options)
            // Set continued to false for the final segment
            .font(termsFont).text('Prices quoted are exclusive of VAT (unless otherwise stated). Delivery, installation, and additional services are quoted separately where applicable. Acceptance: By accepting this quotation, the client acknowledges and agrees to the above terms and conditions.', { ...options, continued: false });
                        // ==================== FOOTER ====================
            
            // ==================== FOOTER ZONE (Own margins: 50-545 for equal padding) ====================
            
            const footerY = 750;
            const footerLeftMargin = 50;
            const footerRightMargin = 545;
            const footerContentWidth = footerRightMargin - footerLeftMargin;
            
            // Thank you message - centered within footer margins
            doc.fontSize(12).font('Helvetica-Bold').fillColor('#000000');
            doc.text('THANK YOU FOR', footerLeftMargin, footerY + 20, { align: 'center', width: footerContentWidth });
            doc.text('YOUR BUSINESS', footerLeftMargin, footerY + 35, { align: 'center', width: footerContentWidth });

            // Small logo in bottom right corner - aligned to footer right margin
            const smallLogoPath = path.join(__dirname, 'Images', 'Logos', 'RemovedStackOpsONLY.png');
            if (fs.existsSync(smallLogoPath)) {
                doc.image(smallLogoPath, footerRightMargin + 28, 818, { width: 25, height: 25 });
            }

            // Add full-page invoice image
            doc.addPage();
            const invoiceImagePath = path.join(__dirname, 'Images', 'Invoice.png');
            if (fs.existsSync(invoiceImagePath)) {
                doc.image(invoiceImagePath, 0, 0, { width: 595, height: 842 });
            }

            doc.end();
        } catch (err) {
            reject(err);
        }
    });
}

async function getUserByEmail(email) {
    try {
        if (!pool) {
            throw new Error('MySQL pool is not available.');
        }
        // Normalize column names so we can reliably use user.id, user.email, user.role in code
        const [rows] = await pool.query(
            `SELECT 
                ID        AS id,
                FirstName AS firstName,
                LastName  AS lastName,
                Email     AS email,
                Contact   AS contact,
                Position  AS position,
                password,
                isActive  AS isActive,
                Role      AS role,
                CompanyID AS companyId,
                CreatedAt AS createdAt
             FROM Users
             WHERE Email = ?`,
            [email]
        );
        return rows[0] || null;
    } catch (err) {
        console.error('getUserByEmail error:', err);
        throw err;
    }
}

async function getUserAccessContextByEmail(email) {
    if (!pool) {
        throw new Error('MySQL pool is not available.');
    }

    const [rows] = await pool.query(
        `SELECT 
            u.ID AS userId,
            u.Email AS email,
            u.CompanyID AS companyId,
            CASE 
                WHEN uda.user_id IS NOT NULL THEN 'duo'
                WHEN EXISTS (
                    SELECT 1 FROM TenantAccessControl taSunbird
                    WHERE taSunbird.UserID = u.ID AND LOWER(taSunbird.AccessType) = 'sunbird'
                ) THEN 'sunbird'
                ELSE COALESCE(
                    (SELECT taPrimary.AccessType FROM TenantAccessControl taPrimary WHERE taPrimary.UserID = u.ID ORDER BY taPrimary.ID ASC LIMIT 1),
                    'standard'
                )
            END AS accessType,
            EXISTS (
                SELECT 1 FROM TenantAccessControl taSunbirdFlag
                WHERE taSunbirdFlag.UserID = u.ID AND LOWER(taSunbirdFlag.AccessType) = 'sunbird'
            ) AS hasSunbirdAccess,
            mt.ID AS microsoftTenantPk,
            mt.TenantName AS tenantName,
            mt.TenantID AS tenantId,
            mt.ClientID AS clientId,
            mt.ClientSecret AS clientSecret
         FROM Users u
         LEFT JOIN user_duo_accounts uda ON uda.user_id = u.ID
         LEFT JOIN CompanyMicrosoftMapping cm ON cm.CompanyID = u.CompanyID AND cm.IsActive = 1
         LEFT JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID
         WHERE LOWER(u.Email) = LOWER(?)
         LIMIT 1`,
        [email]
    );

    const context = rows[0] || null;
    if (context) {
        context.hasSunbirdAccess = Boolean(Number(context.hasSunbirdAccess));
    }
    return context;
}

async function getAccessContextByUser(reqUser) {
    if (!reqUser || !reqUser.email) return null;
    try {
        const databaseContext = await getUserAccessContextByEmail(reqUser.email);
        if (databaseContext?.companyId) return databaseContext;
        if (databaseContext) {
            return {
                ...databaseContext,
                companyId: reqUser.companyId || databaseContext.companyId || null,
                accessType: databaseContext.accessType || reqUser.access || 'standard',
                tenantId: databaseContext.tenantId || reqUser.tenantId || null
            };
        }
    } catch (error) {
        console.warn('[Access Context] Database lookup failed, using verified token context:', error.message);
    }

    const cached = accessContextCache.get(String(reqUser.email || '').toLowerCase()) || {};
    const companyId = reqUser.companyId || cached.companyId || null;
    if (!companyId) return null;
    return {
        userId: reqUser.id || reqUser.userId || null,
        email: reqUser.email,
        companyId,
        accessType: reqUser.access || cached.accessType || 'standard',
        tenantId: reqUser.tenantId || cached.tenantId || null
    };
}

async function checkMfaCode(user_id, code) {
    try {
        if (!pool) {
            throw new Error('MySQL pool is not available.');
        }
        const [codes] = await pool.query('SELECT * FROM mfa_codes WHERE user_id = ? AND code = ? AND expires_at > NOW()', [user_id, code]);
        return codes[0]; 
    } catch (err) {
        console.error('checkMfaCode error:', err);
        throw err;
    }
}

async function insertMfaCode(user_id, code, expires_at) {
    try {
        if (!pool) {
            throw new Error('MySQL pool is not available.');
        }
        await pool.query(
            'INSERT INTO mfa_codes (user_id, code, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE code = VALUES(code), expires_at = VALUES(expires_at)',
            [user_id, code, expires_at]
        );
    } catch (err) {
        console.error('insertMfaCode error:', err);
        throw err;
    }
}

// Seed initial availability data for the next 30 days (updated from original)
async function seedAvailability() {
    try {
        console.log('Checking for existing appointments...');

        let count = 0;

        if (!pool) {
            throw new Error('MySQL pool is not available.');
        }
        const [rows] = await pool.query('SELECT COUNT(*) AS count FROM appointment');
        count = rows[0].count;

        if (count === 0) {
            console.log('No appointments found. Seeding availability data...');

            const today = new Date();
            const dates = [];
            for (let i = 0; i < 30; i++) {  // Updated to 30 days (from original)
                const date = new Date(today);
                date.setDate(today.getDate() + i);
                dates.push(date.toISOString().split('T')[0]); 
            }
            
            const times = ['09:00:00', '10:00:00', '11:00:00', '14:00:00', '15:00:00']; 

            for (const date of dates) {
                for (const time of times) {
                    if (!pool) {
                        throw new Error('MySQL pool is not available.');
                    }
                    await pool.query('INSERT INTO appointment (date, time, is_available) VALUES (?, ?, ?)', [date, time, true]);
                }
            }

            console.log(`Seeded ${dates.length * times.length} available slots.`);
        } else {
            console.log(`Found ${count} existing appointments. Skipping seed.`);
        }
    } catch (err) {
        console.error('seedAvailability error:', err);
        throw err;
    }
}

async function applySqlMigration(relativePath) {
    const migrationPath = path.join(__dirname, relativePath);
    const migrationSql = fs.readFileSync(migrationPath, 'utf8')
        .split(/\r?\n/)
        .filter(line => !line.trim().startsWith('--'))
        .join('\n');
    const statements = migrationSql.split(';').map(statement => statement.trim()).filter(Boolean);
    for (const statement of statements) await pool.query(statement);
}

// Function to ensure database schema is up to date for automation
async function ensureDatabaseSchema() {
    try {
        if (!pool) return;
        console.log('Ensuring database schema for automation...');

        // Intelligence automation scheduler tables must exist before the one-minute tick starts.
        await pool.query(`
            CREATE TABLE IF NOT EXISTS StackCTRLIntelligenceSchedules (
                ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                CompanyID BIGINT NOT NULL,
                ScheduleKey VARCHAR(100) NOT NULL,
                ScheduleType VARCHAR(50) NOT NULL,
                CronExpression VARCHAR(100) NOT NULL,
                TimeZone VARCHAR(100) NOT NULL DEFAULT 'Africa/Johannesburg',
                BusinessDaysJson JSON NULL,
                BusinessStartTime TIME NULL,
                BusinessEndTime TIME NULL,
                IntervalMinutes INT NULL,
                AnalysisHoursJson JSON NULL,
                OutputTypesJson JSON NULL,
                IsEnabled TINYINT(1) NOT NULL DEFAULT 1,
                LastRunAt DATETIME NULL,
                CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (ID),
                UNIQUE KEY uq_stackctrl_schedule_company_key (CompanyID, ScheduleKey),
                KEY ix_stackctrl_schedule_enabled (CompanyID, IsEnabled, ScheduleType)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS StackCTRLIntelligenceScheduleRuns (
                ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                CompanyID BIGINT NOT NULL,
                ScheduleID BIGINT UNSIGNED NULL,
                ScheduleKey VARCHAR(100) NOT NULL,
                RunType VARCHAR(50) NOT NULL,
                TriggerType VARCHAR(50) NOT NULL,
                DeduplicationKey VARCHAR(255) NOT NULL,
                ParentRunID BIGINT UNSIGNED NULL,
                RequestedOutputTypes JSON NULL,
                Status VARCHAR(50) NOT NULL DEFAULT 'started',
                SnapshotID BIGINT UNSIGNED NULL,
                IntelligenceRunID BIGINT UNSIGNED NULL,
                CollectionSummaryJson JSON NULL,
                HistoricalContextJson JSON NULL,
                ErrorMessage TEXT NULL,
                CreatedByUserID BIGINT NULL,
                CreatedByEmail VARCHAR(255) NULL,
                StartedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CompletedAt DATETIME NULL,
                CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (ID),
                UNIQUE KEY uq_stackctrl_schedule_run_dedupe (DeduplicationKey),
                KEY ix_stackctrl_schedule_runs_company_started (CompanyID, StartedAt),
                KEY ix_stackctrl_schedule_runs_status (Status, StartedAt),
                KEY ix_stackctrl_schedule_runs_schedule (ScheduleID, StartedAt)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        `);

        await applySqlMigration('sql/stackctrl-enterprise-intelligence.sql');
        
        // Add PaidEmailSent column if it doesn't exist
        const [columns] = await pool.query("SHOW COLUMNS FROM Invoices LIKE 'PaidEmailSent'");
        if (columns.length === 0) {
            console.log('Adding PaidEmailSent column to Invoices table...');
            await pool.query("ALTER TABLE Invoices ADD COLUMN PaidEmailSent BOOLEAN DEFAULT FALSE");
        }
        
        // Add LastReminderDate column to track daily reminders
        const [columns2] = await pool.query("SHOW COLUMNS FROM Invoices LIKE 'LastReminderDate'");
        if (columns2.length === 0) {
            console.log('Adding LastReminderDate column to Invoices table...');
            await pool.query("ALTER TABLE Invoices ADD COLUMN LastReminderDate DATE DEFAULT NULL");
        }

        // Create payfast_payments table if it doesn't exist
        await pool.query(`
            CREATE TABLE IF NOT EXISTS payfast_payments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                invoice_id INT,
                m_payment_id VARCHAR(100),
                pf_payment_id VARCHAR(100),
                payment_status VARCHAR(50),
                amount DECIMAL(10, 2),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX (invoice_id),
                INDEX (m_payment_id)
            )
        `);

        // Create yoco_payments table if it doesn't exist
        await pool.query(`
            CREATE TABLE IF NOT EXISTS yoco_payments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                invoice_id INT,
                yoco_checkout_id VARCHAR(100),
                redirect_url TEXT,
                amount INT,
                status VARCHAR(50),
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX (invoice_id),
                INDEX (yoco_checkout_id)
            )
        `);

        // Create mfa_codes table if it doesn't exist
        await pool.query(`
            CREATE TABLE IF NOT EXISTS mfa_codes (
                user_id INT PRIMARY KEY,
                code VARCHAR(10) NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create password_resets table if it doesn't exist
        await pool.query(`
            CREATE TABLE IF NOT EXISTS password_resets (
                user_id INT PRIMARY KEY,
                token VARCHAR(255) NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Core hybrid-architecture tables
        await pool.query(`
            CREATE TABLE IF NOT EXISTS MicrosoftTenants (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                TenantName VARCHAR(255),
                TenantID VARCHAR(255),
                ClientID VARCHAR(255),
                ClientSecret TEXT,
                CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS CompanyMicrosoftMapping (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                MicrosoftTenantID INT,
                IsActive TINYINT DEFAULT 1,
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID),
                FOREIGN KEY (MicrosoftTenantID) REFERENCES MicrosoftTenants(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS TenantAccessControl (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                UserID INT,
                AccessType VARCHAR(50),
                FOREIGN KEY (UserID) REFERENCES Users(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS IdentityMetricsCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                TotalUsers INT,
                ActiveUsers INT,
                AdminRoles INT,
                SecurityScore INT,
                LastUpdated DATETIME,
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS IdentityUserDetailsCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                UsersPayload LONGTEXT,
                LastUpdated DATETIME,
                UNIQUE KEY uq_identity_user_details_company (CompanyID),
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS MicrosoftRoleAssignmentsCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                AssignmentsPayload LONGTEXT,
                LastUpdated DATETIME,
                UNIQUE KEY uq_role_assignments_company (CompanyID),
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS DeviceMetricsCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                TotalDevices INT,
                NonCompliant INT,
                NotEncrypted INT,
                StaleDevices INT,
                LastUpdated DATETIME,
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS EmailMetricsCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                ActiveThreats INT,
                HighSeverity INT,
                UsersTargeted INT,
                OpenIncidents INT,
                LastUpdated DATETIME,
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS EmailSecurityPayloadCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                Payload LONGTEXT,
                LastUpdated DATETIME,
                UNIQUE KEY uq_email_security_payload_company (CompanyID),
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS SecurityEventsPayloadCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                Payload LONGTEXT,
                LastUpdated DATETIME,
                UNIQUE KEY uq_security_events_payload_company (CompanyID),
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS BackupRecoveryPayloadCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                Payload LONGTEXT,
                LastUpdated DATETIME,
                UNIQUE KEY uq_backup_recovery_company (CompanyID),
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS ApplicationMetricsCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                TotalApps INT,
                ExternalApps INT,
                HighRiskApps INT,
                HighAccessApps INT,
                LastUpdated DATETIME,
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS ApplicationPayloadCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                Payload LONGTEXT,
                LastUpdated DATETIME,
                UNIQUE KEY uq_application_payload_company (CompanyID),
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS SunbirdComplianceControlsCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                Payload LONGTEXT,
                LastUpdated DATETIME,
                UNIQUE KEY uq_sunbird_compliance_company (CompanyID),
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS SunbirdOperationsPayloadCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                Payload LONGTEXT,
                LastUpdated DATETIME,
                UNIQUE KEY uq_sunbird_operations_company (CompanyID),
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS SunbirdGovernancePayloadCache (
                ID INT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT,
                Payload LONGTEXT,
                LastUpdated DATETIME,
                UNIQUE KEY uq_sunbird_governance_company (CompanyID),
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS SunbirdReportSettings (
                CompanyID INT PRIMARY KEY,
                WeeklyEnabled TINYINT DEFAULT 1,
                RecipientEmail VARCHAR(255),
                RecipientConfirmed TINYINT DEFAULT 0,
                DeliveryDay TINYINT DEFAULT 5,
                DeliveryHour TINYINT DEFAULT 8,
                ActiveSince DATETIME DEFAULT CURRENT_TIMESTAMP,
                LastDailyCollectionDate DATE DEFAULT NULL,
                LastWeeklyReportDate DATE DEFAULT NULL,
                LastAutomationStartNoticeDate DATE DEFAULT NULL,
                LastHourlyAutomationAt DATETIME DEFAULT NULL,
                LastHourlyAutomationStatus VARCHAR(30) DEFAULT NULL,
                LastHourlyAutomationMessage VARCHAR(1000) DEFAULT NULL,
                LastHourlyAutomationRunID BIGINT DEFAULT NULL,
                LastHourlyAutomationSnapshotID BIGINT DEFAULT NULL,
                LastHourlyAutomationReportID BIGINT DEFAULT NULL,
                UpdatedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID)
            )
        `);

        try {
            const [reportSettingsColumns] = await pool.query("SHOW COLUMNS FROM SunbirdReportSettings LIKE 'RecipientConfirmed'");
            if (reportSettingsColumns.length === 0) {
                await pool.query("ALTER TABLE SunbirdReportSettings ADD COLUMN RecipientConfirmed TINYINT DEFAULT 0 AFTER RecipientEmail");
            }
        } catch (err) {
            console.warn('[Database] SunbirdReportSettings RecipientConfirmed migration attempted:', err.message);
        }

        try {
            const [reportSettingsNoticeColumns] = await pool.query("SHOW COLUMNS FROM SunbirdReportSettings LIKE 'LastAutomationStartNoticeDate'");
            if (reportSettingsNoticeColumns.length === 0) {
                await pool.query("ALTER TABLE SunbirdReportSettings ADD COLUMN LastAutomationStartNoticeDate DATE DEFAULT NULL AFTER LastWeeklyReportDate");
            }
        } catch (err) {
            console.warn('[Database] SunbirdReportSettings LastAutomationStartNoticeDate migration attempted:', err.message);
        }

        for (const [column, definition] of [
            ['LastHourlyAutomationAt', 'DATETIME DEFAULT NULL'],
            ['LastHourlyAutomationStatus', 'VARCHAR(30) DEFAULT NULL'],
            ['LastHourlyAutomationMessage', 'VARCHAR(1000) DEFAULT NULL'],
            ['LastHourlyAutomationRunID', 'BIGINT DEFAULT NULL'],
            ['LastHourlyAutomationSnapshotID', 'BIGINT DEFAULT NULL'],
            ['LastHourlyAutomationReportID', 'BIGINT DEFAULT NULL']
        ]) {
            try {
                const [existing] = await pool.query(`SHOW COLUMNS FROM SunbirdReportSettings LIKE '${column}'`);
                if (!existing.length) await pool.query(`ALTER TABLE SunbirdReportSettings ADD COLUMN ${column} ${definition}`);
            } catch (err) {
                console.warn(`[Database] SunbirdReportSettings ${column} migration attempted:`, err.message);
            }
        }
        await pool.query(`
            CREATE TABLE IF NOT EXISTS SunbirdReports (
                ID BIGINT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT NOT NULL,
                ReportType VARCHAR(20) NOT NULL,
                PeriodStart DATETIME NOT NULL,
                PeriodEnd DATETIME NOT NULL,
                HealthScore INT DEFAULT 0,
                ReportStatus VARCHAR(30) DEFAULT 'ready',
                Payload LONGTEXT NOT NULL,
                GeneratedByUserID INT DEFAULT NULL,
                EmailStatus VARCHAR(30) DEFAULT 'not-sent',
                SentAt DATETIME DEFAULT NULL,
                CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_sunbird_reports_company_created (CompanyID, CreatedAt),
                INDEX idx_sunbird_reports_company_type (CompanyID, ReportType),
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID),
                FOREIGN KEY (GeneratedByUserID) REFERENCES Users(ID)
            )
        `);

        for (const [column, definition] of [
            ['EnterpriseRunID', 'BIGINT DEFAULT NULL'],
            ['EnterpriseSnapshotID', 'BIGINT DEFAULT NULL'],
            ['IsCurrent', 'TINYINT(1) NOT NULL DEFAULT 0'],
            ['PublishedAt', 'DATETIME DEFAULT NULL']
        ]) {
            const [existing] = await pool.query(`SHOW COLUMNS FROM SunbirdReports LIKE '${column}'`);
            if (!existing.length) await pool.query(`ALTER TABLE SunbirdReports ADD COLUMN ${column} ${definition}`);
        }
        try {
            await pool.query('CREATE INDEX idx_sunbird_reports_current ON SunbirdReports (CompanyID, ReportType, IsCurrent, PublishedAt, CreatedAt)');
        } catch (error) {
            if (error.code !== 'ER_DUP_KEYNAME') console.warn('[Database] Current Sunbird report index migration:', error.message);
        }

        await pool.query(`
            CREATE TABLE IF NOT EXISTS SunbirdReportAuditLogs (
                ID BIGINT AUTO_INCREMENT PRIMARY KEY,
                CompanyID INT NOT NULL,
                ReportID BIGINT DEFAULT NULL,
                EventType VARCHAR(60) NOT NULL,
                EventStatus VARCHAR(30) NOT NULL,
                Message VARCHAR(500) NOT NULL,
                Metadata LONGTEXT,
                ActorUserID INT DEFAULT NULL,
                CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_sunbird_report_logs_company_created (CompanyID, CreatedAt),
                INDEX idx_sunbird_report_logs_report (ReportID),
                FOREIGN KEY (CompanyID) REFERENCES Companies(ID),
                FOREIGN KEY (ReportID) REFERENCES SunbirdReports(ID) ON DELETE SET NULL,
                FOREIGN KEY (ActorUserID) REFERENCES Users(ID) ON DELETE SET NULL
            )
        `);

        // User constraints/indexes for faster login and tenant lookups
        try {
            await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_company ON Users(CompanyID)`);
        } catch (idxErr) {
            if (idxErr.code !== 'ER_DUP_KEYNAME') {
                console.warn('[Database] Index idx_users_company creation attempted (may already exist)');
            }
        }
        
        try {
            await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON Users(Email)`);
        } catch (idxErr) {
            if (idxErr.code !== 'ER_DUP_KEYNAME') {
                console.warn('[Database] Index idx_users_email creation attempted (may already exist)');
            }
        }
        
        try {
            await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email ON Users(Email)`);
        } catch (idxErr) {
            if (idxErr.code !== 'ER_DUP_KEYNAME') {
                console.warn('[Database] Unique index uq_users_email creation attempted (may already exist)');
            }
        }
    } catch (err) {
        console.error('ensureDatabaseSchema error:', err);
        throw err;
    }
}

// Call seed availability and schema check NON-BLOCKING with retry logic
setTimeout(() => {
    console.log('[STARTUP] Running deferred startup tasks (seedAvailability, ensureDatabaseSchema)...');
    
    if (!pool) {
        console.warn('[STARTUP] ⚠️  Skipping startup tasks - database pool not available');
        return;
    }

    // Add retry logic for database startup tasks
    let retries = 0;
    const MAX_RETRIES = 3;
    const RETRY_DELAY = 5000; // 5 seconds between retries

    function runStartupTasks() {
        Promise.all([
            seedAvailability().catch((error) => {
                console.error(`[STARTUP] seedAvailability failed (attempt ${retries + 1}/${MAX_RETRIES}):`, error.message);
                if (error.code) console.error('[STARTUP] Error code:', error.code);
                if (error.errno) console.error('[STARTUP] Error errno:', error.errno);
                return Promise.reject(error);
            }),
            ensureDatabaseSchema().catch((error) => {
                console.error(`[STARTUP] ensureDatabaseSchema failed (attempt ${retries + 1}/${MAX_RETRIES}):`, error.message);
                if (error.code) console.error('[STARTUP] Error code:', error.code);
                if (error.errno) console.error('[STARTUP] Error errno:', error.errno);
                return Promise.reject(error);
            })
        ])
        .then(() => {
            console.log('[STARTUP] ✅ All startup tasks completed successfully');
        })
        .catch((error) => {
            retries++;
            if (retries < MAX_RETRIES) {
                console.warn(`[STARTUP] ⚠️  Retrying startup tasks in ${RETRY_DELAY}ms... (${retries}/${MAX_RETRIES})`);
                setTimeout(runStartupTasks, RETRY_DELAY);
            } else {
                console.error('[STARTUP] ❌ Startup tasks failed after all retries. Server continuing without these features.');
                console.error('[STARTUP] Other features should still work. Check Cloud SQL connection.');
            }
        });
    }

    runStartupTasks();
}, 2000);  // Bump delay to 2 seconds to allow pool initialization

// --- INVOICE AUTOMATION ---

/**
 * CONFIGURATION FOR TESTING:
 * To test immediately, set:
 * - TEST_MODE: true
 * - INTERVAL_MS: 300000 (5 minutes)
 * This will ignore the hour checks and send emails every 5 minutes.
 * 
 * FOR PRODUCTION:
 * - TEST_MODE: false
 * - INTERVAL_MS: 3600000 (1 hour)
 */
const AUTOMATION_CONFIG = {
    ENABLED: true,
    CHECK_HOUR: 0,             // 00:00 for status updates (Pending -> Overdue)
    EMAIL_HOUR: 6,             // 08:00 for email reminders (8 hours after check)
    FINE_DAYS_THRESHOLD: 3,     // 3 days overdue for fine message
    TEST_MODE: false,          // If true, ignores hour checks and allows repeat emails
    INTERVAL_MS: 60 * 60 * 1000 // Check frequency (default: 1 hour)
};

async function runInvoiceAutomation() {
    if (!AUTOMATION_CONFIG.ENABLED || !pool) return;

    const now = new Date();
    const currentHour = now.getHours();
    const todayStr = now.toISOString().split('T')[0];

    console.log(`[Automation] Running check at ${now.toLocaleString()}${AUTOMATION_CONFIG.TEST_MODE ? ' (TEST MODE)' : ''}`);

    try {
        // 1. STATUS UPDATES (Runs every interval)
        if (AUTOMATION_CONFIG.ENABLED) {
            console.log('[Automation] Checking for overdue invoices...');
            // Find Pending or Unpaid invoices where DueDate <= current date
            const [pendingInvoices] = await pool.query(
                "SELECT InvoiceID, InvoiceNumber FROM Invoices WHERE Status IN ('Pending', 'Unpaid') AND DueDate <= CURDATE()"
            );

            for (const invoice of pendingInvoices) {
                console.log(`[Automation] Marking Invoice #${invoice.InvoiceNumber} as Overdue`);
                await pool.query(
                    "UPDATE Invoices SET Status = 'Overdue' WHERE InvoiceID = ?",
                    [invoice.InvoiceID]
                );
            }
        }

        // 2. EMAIL REMINDERS (Runs at EMAIL_HOUR or in TEST_MODE)
        if (currentHour === AUTOMATION_CONFIG.EMAIL_HOUR || AUTOMATION_CONFIG.TEST_MODE) {
            console.log('[Automation] Processing email reminders...');

            // A. Handle PAID confirmations
            const [paidInvoices] = await pool.query(
                `SELECT i.*, c.companyname as CompanyName, u.firstname, u.lastname, u.email 
                 FROM Invoices i
                 JOIN Companies c ON i.CompanyID = c.ID
                 LEFT JOIN Users u ON u.CompanyID = c.ID AND u.Role = 'Client'
                 WHERE LOWER(i.Status) = 'paid' 
                   AND (i.PaidEmailSent = FALSE OR ? = TRUE)
                   AND NOT EXISTS (SELECT 1 FROM Payments p WHERE p.InvoiceID = i.InvoiceID AND p.Method = 'PayFast')`, 
                [AUTOMATION_CONFIG.TEST_MODE]
            );

            // Group paid invoices by email to send consolidated confirmations
            const paidByEmail = {};
            for (const inv of paidInvoices) {
                if (!inv.email) {
                    console.warn(`[Automation] Invoice #${inv.InvoiceNumber} has no email contact - skipping paid confirmation`);
                    continue;
                }
                if (!paidByEmail[inv.email]) {
                    paidByEmail[inv.email] = {
                        firstname: inv.firstname,
                        lastname: inv.lastname,
                        invoices: []
                    };
                }
                // Avoid duplicates in the group if multiple users share an email (though rare with Client role)
                if (!paidByEmail[inv.email].invoices.some(i => i.InvoiceID === inv.InvoiceID)) {
                    paidByEmail[inv.email].invoices.push(inv);
                }
            }
            
            for (const email in paidByEmail) {
                const data = paidByEmail[email];
                const invoiceNumbers = data.invoices.map(i => i.InvoiceNumber).join(', #');
                
                const totalPaid = data.invoices.reduce((sum, inv) => sum + parseFloat(inv.TotalAmount || 0), 0);
                const receiptHtml = `
                    <div style="margin-top: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9; max-width: 400px;">
                        <h3 style="margin-top: 0; color: #333; border-bottom: 1px solid #ccc; padding-bottom: 10px;">Payment Receipt</h3>
                        <table style="width: 100%; border-collapse: collapse;">
                            <thead>
                                <tr>
                                    <th style="text-align: left; padding: 5px 0;">Description</th>
                                    <th style="text-align: right; padding: 5px 0;">Amount</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${data.invoices.map(inv => `
                                    <tr>
                                        <td style="padding: 5px 0;">Invoice #${inv.InvoiceNumber}</td>
                                        <td style="text-align: right; padding: 5px 0;">R ${parseFloat(inv.TotalAmount).toFixed(2)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                            <tfoot>
                                <tr style="border-top: 2px solid #333; font-weight: bold;">
                                    <td style="padding: 10px 0 5px 0;">TOTAL PAID</td>
                                    <td style="text-align: right; padding: 10px 0 5px 0;">R ${totalPaid.toFixed(2)}</td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                `;

                console.log(`[Automation] Sending consolidated payment confirmation for Invoices #${invoiceNumbers} to ${email}`);
                const emailBody = `
                    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                        <p>Dear ${data.firstname},</p> 
                        <p>I hope you are well.</p>
                        <p>This is a confirmation that your payment for <b>Invoice #${invoiceNumbers}</b> has been received and confirmed.</p>
                        <p>Thank you for your business!</p>
                        ${receiptHtml}
                        <p>Best regards,<br><b>StackOps IT Solutions Team</b></p>
                        <img
                            src=https://i.postimg.cc/Pr25Gv6k/signature.png
                            alt="StackOps IT Solutions"
                            width="400"
                            style="display:block; max-width:400px; width:100%; height:auto; margin-top:10px;"
                        >

                            <p style="
                                font-size:8.5px;
                                line-height:1.4;
                                color:#666666;
                                font-family:'Avenir Next LT Pro Light','Avenir Next',Avenir,Helvetica,Arial,sans-serif;
                                margin:0.5px 0 0 0;
                            ">
                                <strong>StackOps IT Solutions (Pty) Ltd</strong> |
                                <strong>Reg. No:</strong> 2016/120370/07 |
                                <strong>B-BBEE Level</strong>: 1 Contributor: 135% |
                                <strong>CSD Supplier:</strong> MAAA164124.
                                Legally registered in South Africa, providing IT support, cybersecurity, governance, infrastructure, consulting services,
                                and procurement of IT hardware in compliance with all applicable laws and regulations.
                                All client information is protected in accordance with the
                                <strong>Protection of Personal Information Act (POPIA)</strong> and our internal
                                privacy and security policies. We are committed to safeguarding your data and ensuring confidentiality, integrity, and lawful
                                processing at all times.
                                All information, proposals, and pricing are accurate at the time of sending and governed by our Master Service Agreement (MSA)
                                or client-specific contracts. Prices may be subject to change due to economic, regulatory, or supplier factors, with clients
                                notified in advance.
                                This email and attachments are confidential and intended solely for the named recipient(s). If received in error, please
                                notify the sender immediately, delete the message, and do not disclose, copy, or distribute its contents.
                                Unauthorized use of this communication is strictly prohibited.
                                Emails are not guaranteed virus-free; StackOps IT Solutions accepts no liability for any damage, loss, or unauthorized access
                                arising from this communication.
                                StackOps IT Solutions is committed to business continuity, data security, and reliable technology operations.
                                Our team provides professional, ethical, and transparent IT services, ensuring measurable value, operational efficiency,
                                and compliance with industry best practices.
                                <strong>View our Privacy Policy and Terms of Service here:</strong>
                                <a href="https://stackopsit.co.za/"
                                style="color:#1a73e8; text-decoration:underline;">
                                    StackOps IT Solutions | Your Complete IT Force
                                </a>
                            </p>
                    </div>
                `;
                
                try {
                    await sendBillingEmail(email, `Payment Confirmed - Invoice #${invoiceNumbers}`, emailBody, true);
                    for (const inv of data.invoices) {
                        await pool.query("UPDATE Invoices SET PaidEmailSent = TRUE WHERE InvoiceID = ?", [inv.InvoiceID]);
                    }
                } catch (e) {
                    console.error(`[Automation] Failed to send consolidated paid email to ${email}:`, e);
                }
            }

            // B. Handle OVERDUE reminders
            const [overdueInvoices] = await pool.query(
                `SELECT DISTINCT i.*, c.companyname as CompanyName, u.firstname, u.lastname, u.email 
                 FROM Invoices i
                 JOIN Companies c ON i.CompanyID = c.ID
                 LEFT JOIN Users u ON c.ID = u.CompanyID AND u.Role = 'Client'
                 WHERE LOWER(i.Status) = 'overdue' 
                   AND (i.LastReminderDate IS NULL OR i.LastReminderDate < ? OR ? = TRUE)
                 ORDER BY i.InvoiceID`,
                [todayStr, AUTOMATION_CONFIG.TEST_MODE]
            );

            // Group overdue invoices by email to send consolidated reminders
            const overdueByEmail = {};
            for (const inv of overdueInvoices) {
                if (!inv.email) {
                    console.warn(`[Automation] Invoice #${inv.InvoiceNumber} has no email contact - skipping`);
                    continue;
                }
                if (!overdueByEmail[inv.email]) {
                    overdueByEmail[inv.email] = {
                        firstname: inv.firstname,
                        lastname: inv.lastname,
                        invoices: []
                    };
                }
                if (!overdueByEmail[inv.email].invoices.some(i => i.InvoiceID === inv.InvoiceID)) {
                    overdueByEmail[inv.email].invoices.push(inv);
                }
            }

            for (const email in overdueByEmail) {
                const data = overdueByEmail[email];
                const invoiceNumbers = data.invoices.map(i => i.InvoiceNumber).join(', #');
                
                let subject = `Overdue Payment Reminder - Invoice #${invoiceNumbers}`;
                let messagePrefix = `<p>This is a reminder that your payment for <b>Invoice #${invoiceNumbers}</b> is overdue.</p>`;
                let totalDue = 0;
                let hasUrgent = false;

                data.invoices.forEach(inv => {
                    totalDue += parseFloat(inv.TotalAmount);
                    const dueDate = new Date(inv.DueDate);
                    const diffDays = Math.ceil(Math.abs(now - dueDate) / (1000 * 60 * 60 * 24));
                    if (diffDays >= AUTOMATION_CONFIG.FINE_DAYS_THRESHOLD) {
                        hasUrgent = true;
                    }
                });

                if (hasUrgent) {
                    subject = `URGENT: Overdue Payment & Fine Warning - Invoice #${invoiceNumbers}`;
                    messagePrefix = `
                        <p style="color: red; font-weight: bold;">URGENT NOTICE</p>
                        <p>This is a final reminder that your payment for <b>Invoice #${invoiceNumbers}</b> is significantly overdue.</p>
                        <p>Please note that as per our terms, a fine is now being applied to your account due to the delay.</p>
                    `;
                }

                console.log(`[Automation] Sending consolidated overdue reminder for Invoices #${invoiceNumbers} to ${email}`);
                const emailBody = `
                    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                        <p>Dear ${data.lastname},</p>
                        <p>I hope this email finds you well.</p>
                        ${messagePrefix}
                        <p>Total Amount Due: R${totalDue.toFixed(2)}</p>
                        <p>Please settle this amount as soon as possible to avoid further action.</p>
                        <p>If you have already made payment, please ignore this email.</p>
                        <p>Kind regards,<br><b>StackOps IT Solutions Team</b></p>
                        <img
                            src=https://i.postimg.cc/Pr25Gv6k/signature.png
                            alt="StackOps IT Solutions"
                            width="400"
                            style="display:block; max-width:400px; width:100%; height:auto; margin-top:10px;"
                            >

                            <p style="
                                font-size:8.5px;
                                line-height:1.4;
                                color:#666666;
                                font-family:'Avenir Next LT Pro Light','Avenir Next',Avenir,Helvetica,Arial,sans-serif;
                                margin:0.5px 0 0 0;
                            ">
                                <strong>StackOps IT Solutions (Pty) Ltd</strong> |
                                <strong>Reg. No:</strong> 2016/120370/07 |
                                <strong>B-BBEE Level</strong>: 1 Contributor: 135% |
                                <strong>CSD Supplier:</strong> MAAA164124.
                                Legally registered in South Africa, providing IT support, cybersecurity, governance, infrastructure, consulting services,
                                and procurement of IT hardware in compliance with all applicable laws and regulations.
                                All client information is protected in accordance with the
                                <strong>Protection of Personal Information Act (POPIA)</strong> and our internal
                                privacy and security policies. We are committed to safeguarding your data and ensuring confidentiality, integrity, and lawful
                                processing at all times.
                                All information, proposals, and pricing are accurate at the time of sending and governed by our Master Service Agreement (MSA)
                                or client-specific contracts. Prices may be subject to change due to economic, regulatory, or supplier factors, with clients
                                notified in advance.
                                This email and attachments are confidential and intended solely for the named recipient(s). If received in error, please
                                notify the sender immediately, delete the message, and do not disclose, copy, or distribute its contents.
                                Unauthorized use of this communication is strictly prohibited.
                                Emails are not guaranteed virus-free; StackOps IT Solutions accepts no liability for any damage, loss, or unauthorized access
                                arising from this communication.
                                StackOps IT Solutions is committed to business continuity, data security, and reliable technology operations.
                                Our team provides professional, ethical, and transparent IT services, ensuring measurable value, operational efficiency,
                                and compliance with industry best practices.
                                <strong>View our Privacy Policy and Terms of Service here:</strong>
                                <a href="https://stackopsit.co.za/"
                                style="color:#1a73e8; text-decoration:underline;">
                                    StackOps IT Solutions | Your Complete IT Force
                                </a>
                            </p>
                    </div>
                `;
                
                try {
                    await sendBillingEmail(email, subject, emailBody, true);
                    for (const inv of data.invoices) {
                        await pool.query("UPDATE Invoices SET LastReminderDate = ? WHERE InvoiceID = ?", [todayStr, inv.InvoiceID]);
                    }
                } catch (e) {
                    console.error(`[Automation] Failed to send consolidated overdue email to ${email}:`, e);
                }
            }
        }
    } catch (error) {
        console.error('[Automation] Error during invoice automation:', error.message);
        if (error.code) console.error('[Automation] Error code:', error.code);
        if (error.errno) console.error('[Automation] Error errno:', error.errno);
        // Don't crash - let it retry on next interval
    }
}

// Wrap automation to handle connection timeouts
const automationWithErrorHandling = async () => {
    try {
        if (!pool) {
            console.warn('[Automation] ⚠️  Skipping automation - database pool not available');
            return;
        }
        await runInvoiceAutomation();
    } catch (err) {
        console.error('[Automation] ❌ Fatal automation error:', err.message);
        console.error('[Automation] Check database connectivity - is Cloud SQL accessible?');
    }
};

// Start the automation loop with error handling
setInterval(automationWithErrorHandling, AUTOMATION_CONFIG.INTERVAL_MS);
// Also run once on startup after a delay (only if pool is ready)
setTimeout(() => {
    if (!pool) {
        console.warn('[Automation] ⚠️  Skipping startup automation run - database pool not ready');
        return;
    }
    automationWithErrorHandling().catch(err => {
        console.error('[Automation] Startup automation failed:', err.message);
    });
}, 8000);

setInterval(runSunbirdReportAutomation, 60 * 60 * 1000);
setTimeout(() => {
    runSunbirdReportAutomation().catch(error => {
        console.error('[Reports Automation] Startup run failed:', error.message);
    });
}, 30000);

// --- END INVOICE AUTOMATION ---

// Serve static files from the root directory (for CSS, JS, images)
app.use(express.static(path.join(__dirname)));

// Health check endpoint for Cloud Run and monitoring
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy',
        timestamp: new Date().toISOString(),
        database: pool ? 'available' : 'unavailable'
    });
});

// Database connectivity diagnostic endpoint
app.get('/api/db-status', async (req, res) => {
    const diagnostics = {
        timestamp: new Date().toISOString(),
        poolExists: !!pool,
        poolStatus: null,
        connectionTest: null,
        usersTableCheck: null,
        error: null
    };

    try {
        if (!pool) {
            diagnostics.error = 'Database pool not initialized';
            return res.status(503).json(diagnostics);
        }

        // Try to get a connection from the pool
        console.log('[DIAG] Testing database connectivity...');
        const connection = await pool.getConnection();
        diagnostics.connectionTest = 'success';
        console.log('[DIAG] ✅ Got connection from pool');

        // Test a simple query
        try {
            const [result] = await connection.query('SELECT 1 as test');
            diagnostics.poolStatus = 'connected';
            console.log('[DIAG] ✅ Simple query successful');
        } catch (queryErr) {
            diagnostics.poolStatus = 'error';
            diagnostics.error = queryErr.message;
            console.error('[DIAG] ❌ Query failed:', queryErr.message);
        }

        // Check Users table exists
        try {
            const [result] = await connection.query('SELECT COUNT(*) as count FROM Users LIMIT 1');
            diagnostics.usersTableCheck = {
                exists: true,
                count: result[0].count
            };
            console.log('[DIAG] ✅ Users table found with', result[0].count, 'records');
        } catch (tableErr) {
            diagnostics.usersTableCheck = {
                exists: false,
                error: tableErr.message
            };
            console.error('[DIAG] ❌ Users table error:', tableErr.message);
        }

        // Release connection back to pool
        try {
            await connection.release();
            console.log('[DIAG] ✅ Connection released back to pool');
        } catch (releaseErr) {
            console.error('[DIAG] ⚠️  Error releasing connection:', releaseErr.message);
        }

    } catch (err) {
        diagnostics.error = err.message;
        diagnostics.connectionTest = 'failed';
        console.error('[DIAG] ❌ Diagnostics error:', err.message);
        console.error('[DIAG] Error code:', err.code);
        console.error('[DIAG] Error errno:', err.errno);
    }

    // Return 200 to show diagnostics even on error (can see the error details in the response)
    res.status(200).json(diagnostics);
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Home.html'));
});

app.get('/admin/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/success', (req, res) => {
    res.sendFile(path.join(__dirname, 'success.html'));
});

app.get('/cancel', (req, res) => {
    res.redirect('/Home.html');
});

// API endpoint to get available time slots for a given date (updated from original)
app.get('/api/schedule', async (req, res) => {
    const { date } = req.query;

    if (!date) {
        return res.status(400).send('Date is required.');
    }

    try {
        let availableTimes;

        // First, ensure default slots exist for the date (auto-create if missing, from original)
        const standardTimes = ['09:00:00', '10:00:00', '11:00:00', '14:00:00', '15:00:00'];
        if (!pool) {
            throw new Error('MySQL pool is not available.');
        }
        const [existingRows] = await pool.query(
            'SELECT time FROM appointment WHERE date = ?',
            [date]
        );
        const existingTimes = new Set(existingRows.map(row => row.time));
        const slotsToInsert = standardTimes
            .filter(time => !existingTimes.has(time))
            .map(time => [date, time, true, null, null, null, null]);

        if (slotsToInsert.length > 0) {
            await pool.query(
                'INSERT INTO appointment (date, time, is_available, clientname, email, service, message) VALUES ?',
                [slotsToInsert]
            );
        }

        // Now fetch available times
        const [rows] = await pool.query(
            'SELECT time FROM appointment WHERE date = ? AND is_available = TRUE AND clientname IS NULL',
            [date]
        );
        availableTimes = rows.map(row => row.time);

        res.json(availableTimes);

    } catch (error) {
        console.error('Error fetching schedule:', error);
        res.status(500).send('Server error.');
    }
});

// function to book a consultation from consultation.html page (updated from original)
app.post('/api/book', async (req, res) => {
    const { date, time, name, email, service, message, companyName, title, phone } = req.body;
    
    let updateSuccessful = false;
    let result; 

    try {
        if (!pool) {
            throw new Error('MySQL pool is not available.');
        }
        [result] = await pool.query(
            'UPDATE appointment SET is_available = FALSE, clientname = ?, companyName = ?, title = ?, email = ?, phone = ?, service = ?, message = ? WHERE date = ? AND time = ? AND is_available = TRUE',
            [name, companyName || '', title || '', email, phone || '', service, message, date, time]
        );
        
        if (result.affectedRows > 0) {
            updateSuccessful = true;
        }
        
        if (!updateSuccessful) {
            return res.status(409).send('The selected time slot is no longer available. Please choose another.');
        }

        const clientConfirmation = renderCorporateEmail({
            title: 'Consultation Booking Confirmation',
            greeting: `Dear ${name},`,
            bodyHtml: `
                <p>Your consultation with StackOps IT Solutions has been successfully booked for <strong>${escapeHtml(date)} at ${escapeHtml(time)}</strong>.</p>
                <p>We look forward to speaking with you about your <strong>${escapeHtml(service)}</strong> inquiry and assisting you with the next steps.</p>
                <p>If you need to reschedule or cancel, please contact us by replying to this email.</p>
            `
        });
        
        const adminNotification = `New Consultation Booking:

- Name: ${name}
- Company: ${companyName || 'N/A'}
- Title: ${title || 'N/A'}
- Email: ${email}
- Phone: ${phone || 'N/A'}
- Date: ${date}
- Time: ${time}
- Service: ${service}
- Notes: ${message || 'N/A'}`;
        
        await sendInfoEmail(email, 'Booking Confirmation', clientConfirmation, true);
        await sendInfoEmail('info@stackopsit.co.za', 'New Consultation Booking', adminNotification);
        
        res.status(200).send('Booking successful!');
        
    } catch (error) {
        console.error('Booking error:', error);
        res.status(500).send('Failed to book consultation.');
    }
});


const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        if (req.originalUrl.startsWith('/api')) {
             return res.status(401).json({ success: false, message: 'Unauthorized: No token provided.' });
        }
        return res.redirect('/signin.html');
    }

    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            if (req.originalUrl.startsWith('/api')) {
                return res.status(403).json({ success: false, message: 'Forbidden: Invalid or expired token.' });
            }
            return res.redirect('/signin.html');
        }
        req.user = user;
        accessContextCache.set(String(user.email || '').toLowerCase(), {
            accessType: user.access || 'standard',
            tenantId: user.tenantId || null,
            companyId: user.companyId || null
        });
        next();
    });
};

app.get('/api/cloudflare/network-security/summary', authenticateToken, async (req, res) => {
    try {
        const summary = await getCloudflareNetworkSecuritySummary({ getSecret });
        const tenant = getTenantByEmail(req.user?.email);
        if (networkEvidenceService && tenant?.companyId) {
            const dashboardPayload = buildNetworkDashboardPayload({
                tenantKey: tenant.clientId || 'sunbird',
                payload: summary
            });
            networkEvidenceService.persistProcessedEvidence({
                companyId: tenant.companyId,
                tenantKey: tenant.clientId || 'sunbird',
                payload: dashboardPayload,
                collectionTrigger: 'dashboard_request',
                sourceEndpoint: '/api/cloudflare/network-security/summary'
            }).catch(error => {
                console.warn('[Network Evidence] Dashboard response could not be stored:', error.message);
            });
        }
        res.json(summary);
    } catch (error) {
        const statusCode = error.statusCode || 500;
        console.error('[Cloudflare] Network security summary failed:', error.message);
        res.status(statusCode).json({
            success: false,
            message: statusCode === 503 ? error.message : 'Cloudflare Network Security data is unavailable.',
            fetchedAt: new Date().toISOString(),
            overview: {},
            apps: [],
            identityProviders: [],
            policies: [],
            devices: [],
            deviceRegistrations: [],
            gatewayRules: [],
            gatewayConfig: {},
            warpProfiles: [],
            accessLogs: [],
            virtualNetworks: [],
            dlpProfiles: [],
            sections: {}
        });
    }
});

const SUNBIRD_REPORT_TIME_ZONE = 'Africa/Johannesburg';
const SUNBIRD_REPORT_AUTOMATION_INTERVAL_MS = 60 * 60 * 1000;
const SUNBIRD_REPORT_OVERVIEW_MAX_PAYLOAD_BYTES = 512 * 1024;
const SUNBIRD_REPORT_DETAILS_MAX_PAYLOAD_BYTES = 1024 * 1024;
const SUNBIRD_REPORT_OVERVIEW_MAX_ITEMS = 40;

function parseReportJson(value, fallback = {}) {
    if (!value) return fallback;
    if (typeof value === 'object') return value;
    try {
        return JSON.parse(value);
    } catch (_) {
        return fallback;
    }
}

function clampReportScore(value) {
    return Math.max(0, Math.min(100, Math.round(Number(value) || 0)));
}

function shortText(value, max = 140) {
    if (value == null) return '';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        const s = String(value).replace(/\s+/g, ' ').trim();
        return s.length > max ? s.slice(0, max - 1) + '…' : s;
    }
    try {
        const text = JSON.stringify(value, Object.keys(value).slice(0, 12)).replace(/["\[\]{}]/g, '')
            .replace(/:,/g, ': ').replace(/,\s*/g, '; ').replace(/\s+/g, ' ').trim();
        return text.length > max ? text.slice(0, max - 1) + '…' : text;
    } catch (_) {
        return String(value).slice(0, max - 1);
    }
}

function shortMultilineText(value, max = 140) {
    if (value == null) return '';
    const normalizeLine = line => String(line || '').replace(/\s+/g, ' ').trim();
    const combined = String(value)
        .replace(/\r\n/g, '\n')
        .split('\n')
        .map(normalizeLine)
        .join('\n')
        .trim();
    if (!combined) return '';
    return combined.length > max ? combined.slice(0, max - 1) + '…' : combined;
}
async function writeSunbirdReportLog({
    companyId,
    reportId = null,
    eventType,
    status = 'info',
    message,
    metadata = null,
    actorUserId = null
}) {
    const entry = {
        companyId,
        reportId,
        eventType,
        status,
        message,
        metadata,
        actorUserId,
        timestamp: new Date().toISOString()
    };
    console.log('[Reports Audit]', JSON.stringify(entry));
    if (!pool || !companyId) return;
    try {
        await pool.query(
            `INSERT INTO SunbirdReportAuditLogs
             (CompanyID, ReportID, EventType, EventStatus, Message, Metadata, ActorUserID)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                companyId,
                reportId,
                eventType,
                status,
                String(message || '').slice(0, 500),
                metadata ? JSON.stringify(metadata) : null,
                actorUserId
            ]
        );
    } catch (error) {
        console.warn('[Reports Audit] Could not persist log:', error.message);
    }
}

function serializeReportAuditLog(row) {
    return {
        id: row.ID,
        reportId: row.ReportID,
        eventType: row.EventType,
        status: row.EventStatus,
        message: row.Message,
        metadata: parseReportJson(row.Metadata, null),
        actorUserId: row.ActorUserID,
        createdAt: row.CreatedAt
    };
}

function getJohannesburgDateParts(date = new Date()) {
    const parts = new Intl.DateTimeFormat('en-CA', {
        timeZone: SUNBIRD_REPORT_TIME_ZONE,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        hourCycle: 'h23',
        weekday: 'short'
    }).formatToParts(date);
    return Object.fromEntries(parts.map(part => [part.type, part.value]));
}

function getReportRange(query = {}, activeSince = null) {
    const end = query.to ? new Date(`${query.to}T23:59:59.999Z`) : new Date();
    let start;
    if (query.from) {
        start = new Date(`${query.from}T00:00:00.000Z`);
    } else if (query.range === 'since' && activeSince) {
        start = new Date(activeSince);
    } else {
        const days = query.range === '7d' ? 7 : query.range === '90d' ? 90 : 30;
        start = new Date(end);
        start.setUTCDate(start.getUTCDate() - days);
        start.setUTCHours(0, 0, 0, 0);
    }
    if (Number.isNaN(start.getTime())) start = new Date(Date.now() - (30 * 86400000));
    if (Number.isNaN(end.getTime())) return { start, end: new Date() };
    return start <= end ? { start, end } : { start: end, end: start };
}

function normalizeReportEvent(event = {}, source = 'Dashboard') {
    const timestamp = event.timestamp || event.createdDateTime || event.lastModifiedDateTime ||
        event.activityDateTime || event.time || event.date || null;
    const parsedTimestamp = timestamp ? new Date(timestamp) : null;
    const severity = String(event.severity || event.riskLevel || event.priority || 'info').toLowerCase();
    const status = String(event.status || event.state || event.result || 'observed').toLowerCase();
    return {
        timestamp: parsedTimestamp && Number.isFinite(parsedTimestamp.getTime()) ? parsedTimestamp.toISOString() : null,
        severity,
        status,
        source,
        title: event.title || event.displayName || event.name || event.message || 'Dashboard event',
        detail: event.detail || event.description || event.subtitle || event.category || event.type || source,
        asset: event.user || event.userPrincipalName || event.assignedTo || event.asset || event.location || ''
    };
}

async function getMicrosoftGraphTokenForCompany(companyId) {
  const cacheKey = `microsoft_graph_company_${companyId}`;
  const cachedToken = microsoftTokenCache.get(cacheKey);
  if (cachedToken && cachedToken.expiresAt > Date.now()) return cachedToken.token;

  const [rows] = await pool.query(
    `SELECT mt.TenantID, mt.ClientID, mt.ClientSecret
     FROM CompanyMicrosoftMapping cm
     INNER JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID
     WHERE cm.CompanyID = ? AND cm.IsActive = 1
     LIMIT 1`,
    [companyId]
  );
  const tenant = rows[0];
  if (!tenant?.TenantID || !tenant?.ClientID || !tenant?.ClientSecret) {
    const error = new Error('Microsoft Graph is not configured for this tenant');
    error.statusCode = 503;
    throw error;
  }

  const credential = new ClientSecretCredential(tenant.TenantID, tenant.ClientID, tenant.ClientSecret);
  const tokenResponse = await credential.getToken('https://graph.microsoft.com/.default');
  microsoftTokenCache.set(cacheKey, {
    token: tokenResponse.token,
    expiresAt: Math.min(tokenResponse.expiresOnTimestamp || Date.now() + (30 * 60 * 1000), Date.now() + (30 * 60 * 1000))
  });
  return tokenResponse.token;
}

function isReportEventWithinRange(event, start, end) {
    if (!event.timestamp) return true;
    const time = new Date(event.timestamp).getTime();
    return Number.isFinite(time) && time >= start.getTime() && time <= end.getTime();
}

function normalizeCloudflareReportData(data = {}) {
    const overview = data.overview || {};
    return {
        success: data.success !== false,
        fetchedAt: data.fetchedAt || new Date().toISOString(),
        message: data.message || '',
        overview: {
            securityStatus: overview.securityStatus || 'No data configured',
            protectedApps: Number(overview.protectedApps || 0),
            enrolledDevices: Number(overview.enrolledDevices || 0),
            registeredWarpDevices: Number(overview.registeredWarpDevices || 0),
            gatewayPolicies: Number(overview.gatewayPolicies || 0),
            activeGatewayPolicies: Number(overview.activeGatewayPolicies || overview.gatewayPolicies || 0),
            identityProviders: Number(overview.identityProviders || 0),
            recentAccessEvents: Number(overview.recentAccessEvents || 0),
            lastAccessEvent: overview.lastAccessEvent || null,
            dlpProfiles: Number(overview.dlpProfiles || 0),
            warpProfiles: Number(overview.warpProfiles || 0),
            virtualNetworks: Number(overview.virtualNetworks || 0),
            gatewayProxyEnabled: Boolean(overview.gatewayProxyEnabled),
            udpProxyEnabled: Boolean(overview.udpProxyEnabled),
            tlsDecryptEnabled: Boolean(overview.tlsDecryptEnabled)
        },
        apps: Array.isArray(data.apps) ? data.apps : [],
        identityProviders: Array.isArray(data.identityProviders) ? data.identityProviders : [],
        gatewayRules: Array.isArray(data.gatewayRules) ? data.gatewayRules : [],
        accessLogs: Array.isArray(data.accessLogs) ? data.accessLogs : [],
        dlpProfiles: Array.isArray(data.dlpProfiles) ? data.dlpProfiles : [],
        sections: data.sections || {}
    };
}

function hasCloudflareReportEvidence(data = {}) {
    if (!data) return false;
    if (data.success === false && data.message) return true;
    const overview = data.overview || {};
    return Object.keys(overview).length > 0 ||
        ['apps', 'identityProviders', 'gatewayRules', 'accessLogs', 'dlpProfiles'].some(key => Array.isArray(data[key]) && data[key].length > 0) ||
        Object.keys(data.sections || {}).length > 0;
}

function getCloudflareReportScore(data = {}) {
    const overview = normalizeCloudflareReportData(data).overview;
    let score = 70;
    if (overview.protectedApps > 0) score += 8;
    if (overview.identityProviders > 0) score += 8;
    if (overview.gatewayPolicies > 0) score += 6;
    if (overview.dlpProfiles > 0) score += 5;
    if (overview.gatewayProxyEnabled) score += 5;
    if (overview.tlsDecryptEnabled) score += 4;
    if (overview.udpProxyEnabled) score += 2;
    return clampReportScore(score);
}

function buildCloudflareReportSignals(inputData = null) {
    if (!hasCloudflareReportEvidence(inputData)) {
        return {
            hasReportableEvidence: false,
            score: null,
            summary: null,
            events: [],
            problems: [],
            recommendations: []
        };
    }

    const data = normalizeCloudflareReportData(inputData);
    const overview = data.overview;
    const timestamp = data.fetchedAt || new Date().toISOString();
    const events = [];
    const problems = [];
    const recommendations = [];
    const addSignal = ({ title, detail, severity = 'medium', status = 'observed', category = 'Cloudflare One', problem = false, recommendation }) => {
        const event = {
            title,
            detail,
            severity,
            status,
            source: 'Cloudflare One',
            category,
            timestamp
        };
        events.push(event);
        if (problem) {
            problems.push({
                title,
                detail,
                severity,
                status: 'Action required',
                source: 'Cloudflare One',
                asset: category
            });
        }
        if (recommendation) {
            recommendations.push({
                priority: severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : 'medium',
                title: recommendation,
                detail,
                source: 'Cloudflare One'
            });
        }
    };

    if (data.success === false) {
        addSignal({
            title: 'Cloudflare One evidence unavailable',
            detail: data.message || 'Cloudflare Zero Trust evidence could not be collected.',
            severity: 'high',
            status: 'failed',
            category: 'Cloudflare API',
            problem: true,
            recommendation: 'Restore Cloudflare API evidence collection'
        });
    }

    [
        !overview.gatewayProxyEnabled && {
            title: 'Cloudflare Gateway proxy disabled',
            detail: 'Gateway traffic inspection is not currently enabled in the Cloudflare One snapshot.',
            severity: 'high',
            category: 'Gateway',
            recommendation: 'Enable Cloudflare Gateway proxy or document the exception'
        },
        !overview.tlsDecryptEnabled && {
            title: 'Cloudflare TLS decrypt disabled',
            detail: 'TLS inspection is disabled, limiting visibility into encrypted web traffic.',
            severity: 'medium',
            category: 'Gateway',
            recommendation: 'Review TLS decrypt policy readiness'
        },
        !overview.udpProxyEnabled && {
            title: 'Cloudflare UDP proxy disabled',
            detail: 'UDP proxy support is disabled, which may leave selected traffic outside Gateway inspection.',
            severity: 'medium',
            category: 'Gateway',
            recommendation: 'Validate whether UDP proxy should be enabled'
        },
        !overview.dlpProfiles && {
            title: 'Cloudflare DLP profiles missing',
            detail: 'No DLP profiles were returned, so sensitive data detection is not evidenced.',
            severity: 'medium',
            category: 'DLP',
            recommendation: 'Create or verify Cloudflare DLP profiles'
        },
        !overview.protectedApps && {
            title: 'No Cloudflare protected apps evidenced',
            detail: 'Cloudflare Access did not return protected applications for this snapshot.',
            severity: 'medium',
            category: 'Access',
            recommendation: 'Confirm Cloudflare Access app coverage'
        },
        !overview.identityProviders && {
            title: 'Cloudflare identity provider not evidenced',
            detail: 'No Cloudflare Access identity provider was returned in the latest snapshot.',
            severity: 'high',
            category: 'Identity',
            recommendation: 'Connect or verify the Cloudflare Access identity provider'
        }
    ].filter(Boolean).forEach(signal => addSignal({ ...signal, problem: signal.severity === 'high' }));

    data.accessLogs
        .filter(log => /block|deny|fail/i.test(String(log.action || log.status || '')))
        .slice(0, 4)
        .forEach(log => {
            addSignal({
                title: `Cloudflare Access ${log.action || 'blocked'} event`,
                detail: [log.userEmail, log.appName, log.country, log.ipAddress].filter(Boolean).join(' | ') || 'Cloudflare Access returned a denied or blocked request.',
                severity: 'high',
                status: 'active',
                category: 'Access',
                problem: true,
                recommendation: 'Review denied Cloudflare Access activity'
            });
        });

    Object.entries(data.sections || {}).forEach(([key, section]) => {
        if (!section || !['error', 'permission_unavailable'].includes(section.status)) return;
        addSignal({
            title: `Cloudflare ${section.label || key} evidence needs attention`,
            detail: section.message || 'Cloudflare returned an incomplete section for this control.',
            severity: section.status === 'error' ? 'high' : 'medium',
            status: section.status,
            category: 'Cloudflare API',
            problem: section.status === 'error',
            recommendation: 'Review Cloudflare API permissions for this evidence section'
        });
    });

    const score = getCloudflareReportScore(data);
    return {
        hasReportableEvidence: true,
        score: clampReportScore(score - (problems.filter(item => ['critical', 'high'].includes(String(item.severity || '').toLowerCase())).length * 6) - Math.max(0, events.length - problems.length) * 2),
        summary: {
            protectedApps: overview.protectedApps,
            enrolledDevices: overview.enrolledDevices,
            gatewayPolicies: overview.gatewayPolicies,
            dlpProfiles: overview.dlpProfiles,
            recentAccessEvents: overview.recentAccessEvents,
            lastAccessEvent: overview.lastAccessEvent,
            problems: problems.length,
            events: events.length
        },
        events,
        problems,
        recommendations
    };
}

function buildDeterministicReportAnalysis(report) {
    const critical = report.failures.filter(item => item.severity === 'critical').length;
    const high = report.failures.filter(item => item.severity === 'high').length;
    const score = report.summary.healthScore;
    const posture = score >= 85 ? 'strong' : score >= 70 ? 'stable with attention areas' : 'at risk';
    const issueText = critical || high
        ? `${critical} critical and ${high} high-priority signal${critical + high === 1 ? '' : 's'} require attention.`
        : 'No critical or high-priority failures were recorded in the selected period.';
    return {
        executiveSummary: `Overall dashboard health is ${posture} at ${score}%. ${issueText}`,
        successes: report.successes.slice(0, 6),
        failures: report.failures.slice(0, 8),
        recommendations: report.recommendations.slice(0, 6),
        generatedBy: 'StackCTRL evidence engine'
    };
}

function buildHistoricalNarrativeFromSynthesis(output = {}, report = null) {
    const normaliseText = value => {
        if (value == null) return '';
        if (typeof value === 'object') return '';
        return String(value).replace(/\s+/g, ' ').trim();
    };    const asNumber = value => {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : null;
    };
    const textOf = (value, fields = []) => {
        if (typeof value === 'string' || typeof value === 'number') return normaliseText(value);
        if (!value || typeof value !== 'object') return '';
        for (const field of fields) {
            const candidate = normaliseText(value[field]);
            if (candidate) return candidate;
        }
        return '';
    };
    const unique = values => [...new Set(values.map(value => normaliseText(value)).filter(Boolean).map(value => value.toLowerCase()))]
        .map(value => values.find(item => normaliseText(item).toLowerCase() === value));
    const timestamp = row => new Date(row?.periodEnd || row?.date || row?.createdAt || 0).getTime() || 0;
    const dailyReports = (Array.isArray(report?.dailyReports) ? report.dailyReports : [])
        .filter(row => timestamp(row) > 0)
        .sort((left, right) => timestamp(left) - timestamp(right));
    // Daily reports saved inside the selected period are preferred. During a new
    // daily generation the current report is not saved yet, so compare its live
    // summary with the latest completed predecessor instead.
    const currentDaily = dailyReports[dailyReports.length - 1] || report?.currentDailyReport || null;
    const previousDaily = dailyReports[dailyReports.length - 2] || report?.previousDailyReport || null;
    const changes = [];
    const trendNarratives = [];
    const improved = [];
    const worsened = [];

    const addMovement = (label, currentValue, previousValue, format = value => String(value)) => {
        if (currentValue == null || previousValue == null) return;
        const delta = currentValue - previousValue;
        if (delta === 0) {
            trendNarratives.push(`${label} remained at ${format(currentValue)}.`);
            return;
        }
        const direction = delta > 0 ? 'increased' : 'decreased';
        changes.push(`${label} ${direction} from ${format(previousValue)} to ${format(currentValue)}.`);
        trendNarratives.push(`${label} ${direction} by ${format(Math.abs(delta))} compared with the prior completed report.`);
        if (label === 'Health score') (delta > 0 ? improved : worsened).push(label);
        if (label === 'Open findings') (delta < 0 ? improved : worsened).push(label);
        if (label === 'Successful controls') (delta > 0 ? improved : worsened).push(label);
    };

    if (currentDaily && previousDaily) {
        addMovement('Health score', asNumber(currentDaily.healthScore), asNumber(previousDaily.healthScore), value => `${value}%`);
        addMovement('Open findings', asNumber(currentDaily.failures), asNumber(previousDaily.failures));
        addMovement('Successful controls', asNumber(currentDaily.successes), asNumber(previousDaily.successes));
        addMovement('Events reviewed', asNumber(currentDaily.events), asNumber(previousDaily.events));
    }

    const sourceTrends = Array.isArray(output.trendAnalysis) ? output.trendAnalysis : [];
    sourceTrends.forEach(item => {
        const detail = textOf(item, ['explanation', 'detail', 'description', 'whatHappened', 'reasoning']);
        const title = textOf(item, ['metricName', 'title', 'trend']);
        const currentValue = asNumber(item?.currentValue ?? item?.current ?? item?.latest ?? item?.valueAfter);
        const previousValue = asNumber(item?.previousValue ?? item?.previous ?? item?.baseline ?? item?.valueBefore);
        const delta = asNumber(item?.delta ?? item?.change ?? item?.difference);
        const direction = normaliseText(item?.direction).toLowerCase();
        const baselineOnly = /baseline unavailable|insufficient historical|no historical/i.test(detail);
        if (baselineOnly || (!title && currentValue == null && previousValue == null && delta == null) || (!direction && currentValue == null && previousValue == null && delta == null)) return;
        if (title && currentValue != null && previousValue != null) {
            const unit = normaliseText(item?.unit) || '';
            const movement = currentValue - previousValue;
            trendNarratives.push(`${title} moved from ${previousValue}${unit} to ${currentValue}${unit} (${movement > 0 ? '+' : ''}${movement}${unit}).`);
            if (movement !== 0) (movement > 0 ? worsened : improved).push(title);
            return;
        }
        if (title && delta != null) {
            trendNarratives.push(`${title} shifted by ${delta > 0 ? '+' : ''}${delta}${normaliseText(item?.unit) || ''}.`);
            if (delta !== 0) (delta > 0 ? worsened : improved).push(title);
            return;
        }
        if (title && detail) trendNarratives.push(`${title}: ${detail}`);
    });

    const complianceReview = output.complianceReview || {};
    const remainsOpen = unique([
        ...(Array.isArray(complianceReview.failedOrWeakControlThemes) ? complianceReview.failedOrWeakControlThemes : []),
        ...(Array.isArray(complianceReview.evidenceGaps) ? complianceReview.evidenceGaps : [])
    ].map(item => textOf(item, ['gap', 'title', 'description', 'detail'])));

    return {
        whatChangedSinceLastReport: unique(changes).join(' '),
        historicalTrendAnalysis: unique(trendNarratives).join(' '),
        // Individual gaps are returned separately so the PDF can render one readable
        // bullet per real gap, without a synthetic lead-in sentence.
        controlGapsAndRemediationProgress: '',
        improved: unique(improved),
        worsened: unique(worsened),
        remainsOpen
    };
}
const SUNBIRD_REPORT_LIVE_DOMAIN_TIMEOUT_MS = 6500;
const SUNBIRD_REPORT_LIVE_FINAL_TIMEOUT_MS = 3000;
const SUNBIRD_REPORT_LIVE_IDENTITY_TIMEOUT_MS = 2500;
// The report dashboard must remain usable when a historical report row is large
// or an audit query is slow. These reads are presentation-only; a timeout must
// degrade to the remaining available report data, never a 500 response.
const SUNBIRD_REPORT_SAVED_QUERY_TIMEOUT_MS = 3500;

function withSunbirdReportTimeout(task, timeoutMs, label) {
    let timer = null;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
            const error = new Error(`${label} exceeded ${timeoutMs}ms`);
            error.code = 'SUNBIRD_REPORT_TIMEOUT';
            reject(error);
        }, timeoutMs);
    });
    return Promise.race([Promise.resolve().then(task), timeout]).finally(() => clearTimeout(timer));
}

async function fetchSunbirdPowerBIIntelligence(companyId, { domainTimeoutMs = SUNBIRD_REPORT_LIVE_DOMAIN_TIMEOUT_MS, runId = null } = {}) {
    if (!enterpriseIntelligenceService?.getPowerBIIntelligenceRun) return null;
    try {
        // A dashboard report is an atomic enterprise execution. Never compose it
        // from unrelated “latest” domain rows: that can leave an old completed run
        // visible while a new daily execution is running or awaiting publication.
        const intelligence = await withSunbirdReportTimeout(
            () => enterpriseIntelligenceService.getPowerBIIntelligenceRun(companyId, runId || null, { publishedOnly: !runId }),
            Math.max(domainTimeoutMs, 9000),
            'Published enterprise intelligence'
        );
        const domains = Array.isArray(intelligence?.domains) ? intelligence.domains : [];
        if (!domains.length) return null;
        const domainManifest = domains.map(domain => ({
            domainKey: domain.domainKey,
            domainName: domain.domainName,
            runId: Number(domain.runId || intelligence.latestRunId || 0) || null,
            snapshotId: domain.snapshotId == null ? null : Number(domain.snapshotId),
            status: domain.status || 'available',
            analysedAt: domain.createdAt || null,
            periodStart: domain.periodStart || intelligence.periodStart || null,
            periodEnd: domain.periodEnd || intelligence.periodEnd || null
        }));
        return {
            ...intelligence,
            latestRunId: Number(intelligence.latestRunId || 0) || null,
            latestSnapshotId: intelligence.latestSnapshotId == null ? null : Number(intelligence.latestSnapshotId),
            domainManifest,
            perDomainLatest: false,
            source: 'enterprise_published_run',
            available: true
        };
    } catch (error) {
        console.warn('[Reports] Published enterprise intelligence unavailable:', error.message);
        return null;
    }
}

async function fetchSunbirdIdentityDomainIntelligence(companyId, { timeoutMs = 0 } = {}) {
    if (!enterpriseIntelligenceService?.getPowerBIDomain) return null;
    try {
        const result = await enterpriseIntelligenceService.getPowerBIDomain(companyId, 'identity', timeoutMs > 0 ? { queryTimeoutMs: timeoutMs } : {});
        return result?.domain || null;
    } catch (error) {
        console.warn('[Reports] Identity domain intelligence unavailable:', error.message);
        return null;
    }
}

async function fetchSunbirdPowerBIFinal(companyId, runId = null, { timeoutMs = 0 } = {}) {
    if (!enterpriseIntelligenceService) return null;
    try {
        const finalReport = timeoutMs > 0
            ? await withSunbirdReportTimeout(
                () => enterpriseIntelligenceService.getPowerBIFinal(companyId, runId, { queryTimeoutMs: timeoutMs }),
                timeoutMs,
                'Live enterprise synthesis'
            )
            : await enterpriseIntelligenceService.getPowerBIFinal(companyId, runId);
        if (!finalReport || !finalReport.finalSynthesis || !finalReport.finalSynthesis.synthesisOutput) return null;
        return {
            ...finalReport,
            source: 'enterprise_final_synthesis',
            available: true
        };
    } catch (error) {
        console.warn('[Reports] Power BI final synthesis unavailable:', error.message);
        return null;
    }
}
async function readSunbirdReportRows(label, sql, params) {
    try {
        const [rows] = await withSunbirdReportTimeout(
            () => pool.query({ sql, timeout: SUNBIRD_REPORT_SAVED_QUERY_TIMEOUT_MS }, params),
            SUNBIRD_REPORT_SAVED_QUERY_TIMEOUT_MS + 250,
            label
        );
        return Array.isArray(rows) ? rows : [];
    } catch (error) {
        // A list, overview, or audit-history read is not allowed to make the
        // entire Reports page unavailable. The operation log retains the exact
        // reason for diagnosis while the client receives the data that did load.
        console.warn(`[Reports] ${label} unavailable:`, error.message);
        return [];
    }
}
function safelyBuildSunbirdReportView(label, builder, fallback = null) {
    try {
        return builder();
    } catch (error) {
        console.warn(`[Reports] ${label} skipped:`, error.message);
        return typeof fallback === 'function' ? fallback() : fallback;
    }
}
function buildFinalSynthesisReportAnalysis(report, powerBiFinal = null) {
    const fallback = buildDeterministicReportAnalysis(report);
    const finalSynthesis = powerBiFinal?.finalSynthesis;
    if (!finalSynthesis?.synthesisOutput) return fallback;
    const output = finalSynthesis.synthesisOutput || {};
    const managementReport = output.managementReport || {};
    const confidence = String(output.enterpriseExecutiveSummary?.confidence || output.evidenceJustificationSummary?.evidenceConfidence || 'medium');
    const historical = buildHistoricalNarrativeFromSynthesis(output, report);
    const executiveSummaryBase = String(output.enterpriseExecutiveSummary?.summary || fallback.executiveSummary);
    const executiveSummary = [
        executiveSummaryBase,
        historical.whatChangedSinceLastReport ? `What changed since the last report:\n${historical.whatChangedSinceLastReport}` : '',
        historical.historicalTrendAnalysis ? `Historical trend analysis:\n${historical.historicalTrendAnalysis}` : '',
        historical.controlGapsAndRemediationProgress ? `Control gaps and remediation progress:\n${historical.controlGapsAndRemediationProgress}` : '',
        confidence ? `Confidence:\n${confidence}.` : ''
    ].filter(Boolean).join('\n\n');
    const resolvedEvents = Array.isArray(report.events)
        ? report.events.filter(event => ['resolved', 'closed', 'success', 'succeeded', 'healthy'].includes(String(event.status || '').toLowerCase()))
        : [];
    const missingMfaUsers = Array.isArray(report.identityUsers)
        ? report.identityUsers.filter(user => !toBooleanMfa(user.mfaEnabled ?? user.hasMfa ?? user.hasMfaMethod)).slice(0, 12)
        : [];
    return {
        executiveSummary,
        boardReportSummary: String(output.boardReport?.boardSummary || output.boardReport?.summary || ''),
        managementReportItems: Array.isArray(managementReport.managementActions)
            ? managementReport.managementActions
            : Array.isArray(managementReport.actions)
                ? managementReport.actions
                : [],
        historicalChanges: {
            whatChangedSinceLastReport: historical.whatChangedSinceLastReport,
            historicalTrendAnalysis: historical.historicalTrendAnalysis,
            controlGapsAndRemediationProgress: historical.controlGapsAndRemediationProgress,
            whatImproved: historical.improved,
            whatWorsened: historical.worsened,
            whatRemainsOpen: historical.remainsOpen,
            confidence
        },
        businessImpactSummary: String(output.businessImpactSummary || ''),
        resolvedEvents: resolvedEvents.slice(0, 10),
        mfaMissingUsers: missingMfaUsers,
        backupCoverage: {
            activeUsersCount: Number(report.backup?.summary?.activeUsersCount || 0),
            servicesCovered: Number(report.backup?.summary?.servicesCovered || 0),
            inactiveUsersCount: Number(report.backup?.summary?.inactiveUsersCount || 0)
        },
        successes: report.successes.slice(0, 6),
        failures: report.failures.slice(0, 8),
        recommendations: report.recommendations.slice(0, 6),
        generatedBy: 'Final enterprise synthesis'
    };
}

function buildSunbirdDomainBreakdownFromPayload(payload = {}) {
    const domains = Array.isArray(payload?.domainInsights?.domains) ? payload.domainInsights.domains : [];
    if (!domains.length) return [];

    const asText = (value, fallback = '') => {
        if (value == null) return fallback;
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value).trim() || fallback;
        if (Array.isArray(value)) return value.map(item => asText(item)).filter(Boolean).join('; ') || fallback;
        return asText(value.title || value.name || value.summary || value.detail || value.description || value.message, fallback);
    };
    const scoreOrNull = value => {
        const n = Number(value);
        return Number.isFinite(n) ? clampReportScore(n) : null;
    };
    function unwrapEvidenceRecord(evidence) {
        if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) return { value: evidence };
        return ['evidenceRow', 'affectedEntity', 'data', 'entity', 'record', 'ProcessedEvidenceJson'].reduce((record, key) => {
            const nested = record?.[key];
            return nested && typeof nested === 'object' && !Array.isArray(nested) ? { ...record, ...nested } : record;
        }, { ...evidence });
    }
    const evidenceRecordKeys = evidence => {
        const source = unwrapEvidenceRecord(evidence);
        return [...new Set([
            source.entityId, source.id, source.recordId, source.sourceAlertId, source.alertId,
            source.SourceID, source.controlId, source.applicationId, source.deviceId, source.userId,
            source.entityEmail, source.mail, source.userPrincipalName, source.entityName,
            source.displayName, source.name, source.title, source.label
        ].map(value => asText(value).toLowerCase()).filter(Boolean))];
    };
    const evidenceRecordIdentity = evidence => evidenceRecordKeys(evidence)[0] || null;
    const evidenceStrongRecordKeys = evidence => {
        const source = unwrapEvidenceRecord(evidence);
        const entityId = asText(source.entityId);
        return [...new Set([
            source.id, source.recordId, source.sourceAlertId, source.alertId, source.SourceID,
            source.controlId, source.applicationId, source.deviceId, source.userId,
            entityId && !/[\s@]/.test(entityId) ? entityId : null
        ].map(value => asText(value).toLowerCase()).filter(Boolean))];
    };
    const evidenceValueScore = value => {
        if (value == null || value === '') return 0;
        if (Array.isArray(value)) return value.length ? 150 + value.length : 0;
        if (typeof value === 'object') return Object.keys(value).length ? 200 + Object.keys(value).length : 0;
        return Math.min(String(value).trim().length, 100);
    };
    const mergeEvidenceRecord = (current, candidate) => {
        const merged = { ...current };
        Object.entries(candidate && typeof candidate === 'object' ? candidate : {}).forEach(([key, value]) => {
            if (value == null || value === '') return;
            if (merged[key] == null || merged[key] === '' || evidenceValueScore(value) > evidenceValueScore(merged[key])) {
                merged[key] = value;
            }
        });
        return merged;
    };
    const isAggregateEvidenceRecord = evidence => {
        const source = unwrapEvidenceRecord(evidence);
        const type = asText(source.entityType || source.evidenceType || source.kind).toLowerCase();
        const id = asText(source.entityId || source.id || source.recordId).toLowerCase();
        return /(?:summary|score|coverage)/.test(type) || /(?:summary|score)$/.test(id);
    };
    const isManufacturedValidationRecord = evidence => {
        const source = unwrapEvidenceRecord(evidence);
        const label = [source.entityName, source.displayName, source.name, source.title, source.label].map(asText).join(' ');
        return /validation summary|coverage validation/i.test(label);
    };
    const isOpaqueEvidenceValue = value => {
        const text = asText(value);
        return !text || /^\d+$/.test(text) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(text)
            || /(?:internalSourcePath|sourcePath|snapshotId|runId)/i.test(text);
    };
    const humanizeEvidenceLabel = value => asText(value).replace(/[_-]+/g, ' ').replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/\b\w/g, char => char.toUpperCase());
    const normalizeEvidence = (evidence, finding = {}) => {
        const source = unwrapEvidenceRecord(evidence);
        const auditActor = asText(source.actor?.email || source.actor?.id);
        const auditAction = asText(source.action?.type || source.action);
        const auditResource = asText(source.resource?.type || source.resource);
        const auditLabel = auditActor && auditAction ? auditActor + ' — ' + humanizeEvidenceLabel(auditAction) : auditActor || auditAction || auditResource;
        const name = [source.displayName, source.entityName, source.entityDisplayName, source.deviceName, source.entityDeviceName,
            source.title, source.alertName, source.controlName, source.applicationName, source.profileName, source.activity, source.endpointFamily, source.module, source.key, source.name,
            source.userPrincipalName, source.entityEmail, source.mail, source.userEmail, source.user, auditLabel, source.actor, source.resource,
            source.recipient, source.sender, source.entityId].map(asText).find(value => value && !isOpaqueEvidenceValue(value)) || '';
        const signIn = source.lastSignIn && typeof source.lastSignIn === 'object'
            ? [source.lastSignIn.location ? `Sign-in location: ${source.lastSignIn.location}` : '', source.lastSignIn.device ? `Sign-in device: ${source.lastSignIn.device}` : '',
                source.lastSignIn.daysSince == null || source.lastSignIn.daysSince === '' ? '' : `${source.lastSignIn.daysSince} days since sign-in`,
                source.lastSignIn.status ? `Sign-in status: ${source.lastSignIn.status}` : ''].filter(Boolean).join(' | ')
            : '';
        const details = [];
        const add = (label, value) => {
            const text = Array.isArray(value) ? value.map(asText).filter(Boolean).join(', ') : asText(value);
            if (!text || text.toLowerCase() === name.toLowerCase()) return;
            const entry = label ? `${label}: ${text}` : text;
            if (!details.some(current => current.toLowerCase() === entry.toLowerCase())) details.push(entry);
        };
        add('User', source.entityEmail || source.mail || source.userPrincipalName || source.userEmail || source.user);
        add('Sender', source.sender); add('Recipient', source.recipient);
        add('Device', source.deviceName && source.deviceName !== name ? source.deviceName : source.entityDeviceName);
        add('Operating system', [source.operatingSystem, source.osVersion].filter(Boolean).join(' '));
        add('Compliance', source.complianceState || source.complianceStatus); add('Encryption', source.encryptionStatus); add('Management', source.managementAgent);
        add('Publisher', source.publisherName); add('Application type', source.type); add('Roles', source.roles); add('Policies', source.policies);
        add('Actor', auditActor); add('Action', auditAction || source.managementAction || source.remediationAction); add('Resource', auditResource); add('Area', source.area); add('Owner', source.ownerStatus);
        add('Control', source.controlName || source.policyName); add('Category', source.category); add('Status', source.status || source.state);
        add('Severity', source.severity || source.riskLevel); add('Location', source.location); add('IP address', source.ipAddress); add('Failure reason', source.failureReason);
        add('Files', source.files); add('Storage', source.storage); add('Role count', source.roleCount); add('User count', source.userCount); add('Scope count', source.scopeCount); add('Observed count', source.count);
        if (source.mfaEnabled != null) add('MFA', source.mfaEnabled ? 'Enabled' : 'Not enabled');
        if (source.hasAdminRole != null) add('Administrator role', source.hasAdminRole ? 'Present' : 'Not present');
        if (source.isExternal != null) add('External application', source.isExternal ? 'Yes' : 'No');
        if (source.enabled != null) add('Enabled', source.enabled ? 'Yes' : 'No');
        add('', source.description || source.detail || source.validationReason || source.governanceIssue || source.auditImpact || source.evidenceSummary);
        add('Last sign-in', typeof source.lastSignIn === 'string' ? source.lastSignIn : ''); if (signIn) add('', signIn);
        add('Last sync', source.lastSyncDateTime); add('Event time', source.eventTime || source.when); add('Created', source.createdDateTime); add('Last seen', source.lastSeen); add('Last activity', source.lastActivity);
        return {
            id: shortText(evidenceRecordIdentity(source) || '', 260),
            name: shortText(name, 220),
            detail: shortText(details.join(' | '), 520),
            severity: shortText(asText(source.severity || source.riskLevel || source.priority || ''), 80),
            status: shortText(asText(source.status || source.state || source.complianceState || (source.action?.result === true ? 'Successful' : '')), 120),
            source: shortText(humanizeEvidenceLabel(source.sourceMetric || source.evidenceSource || source.category || finding.sourceMetric || ''), 160)
        };
    };
    const catalogCategoryAliases = (domainKey, item = {}) => {
        const text = `${item.title || item.patternFound || item.description || ''}`.toLowerCase();
        const aliases = [];
        const add = value => { if (value && !aliases.includes(value)) aliases.push(value); };
        if (domainKey === 'identity') {
            if (/privileg|multiple (?:admin )?role/.test(text)) add('privilegedUsers');
            else if (/admin.*(?:without|missing).*mfa|break.?glass/.test(text)) add('adminsWithoutMfa');
            else if (/external|guest/.test(text)) add('externalUsers');
            else if (/inactive|dormant/.test(text)) add('inactiveUsers');
            else if (/unknown device|unknown location/.test(text)) add('unknownDeviceUsers');
            else if (/high risk/.test(text)) add('highRiskUsers');
            else if (/without mfa|missing mfa|mfa gap/.test(text)) add('usersWithoutMfa');
        } else if (domainKey === 'devices') {
            if (/non.?compliant/.test(text)) add('nonCompliantDevices');
            if (/stale|dead|30 day/.test(text)) add('deadDevices');
            if (/device|managed|encrypted/.test(text)) add('allDevices');
        } else if (domainKey === 'email_security') {
            if (/mailbox|mailflow|mail activity/.test(text)) add('mailActivityUsers');
            else if (!/users? affected|targeting (?:key )?users?|affected users?/.test(text) && /alert|phish|junk|threat/.test(text)) add('alerts');
        } else if (domainKey === 'security_alerts') {
            if (/anonymous|sign.?in|ip address/.test(text)) add('signIns');
            if (/threat indicator/.test(text)) add('threatIndicators');
            if (!/repeated|pattern|affected users?/.test(text) && /alert|phish|threat/.test(text)) add('alerts');
        } else if (domainKey === 'cloudflare_network_security') {
            if (/permission|endpoint famil|api/.test(text)) add('permissionMatrix');
            else if (/audit/.test(text)) add('auditLogs');
            else if (/protected app|sso app|login app/.test(text)) add('accessApps');
            else if (/registered warp/.test(text)) add('deviceRegistrations');
            else if (/device|enrolled/.test(text)) add('devices');
            else if (/gateway polic|gateway rule/.test(text)) add('gatewayRules');
            else if (/dlp|data loss/.test(text)) add('dlpProfiles');
            else if (/warp profile/.test(text)) add('warpProfiles');
        } else if (domainKey === 'applications' && !/recommendation|governance score/.test(text) && /external|publisher|assigned users?|excessive permission|high.?access/.test(text)) add('applications');
        else if (domainKey === 'backup' && /large|storage|data holder/.test(text)) add('users');
        else if (domainKey === 'governance') add('governanceRows');
        else if (domainKey === 'compliance') add('controls');
        return aliases;
    };
    const filterCatalogRowsForFinding = (rows, item = {}, domainKey = '') => {
        const text = `${item.title || ''} ${item.patternFound || ''} ${item.description || ''}`.toLowerCase();
        let predicate = null;
        if (domainKey === 'identity' && /multiple (?:privileged |admin )?roles/.test(text)) predicate = row => Array.isArray(row.roles) && row.roles.length > 1;
        else if (domainKey === 'devices' && /all \d+ devices.*encrypted.*managed|encrypted and managed/.test(text)) predicate = row => (row.isEncrypted == null ? /encrypted/i.test(String(row.encryptionStatus || '')) && !/not encrypted/i.test(String(row.encryptionStatus || '')) : row.isEncrypted === true) && /mdm/i.test(String(row.managementAgent || ''));
        else if (domainKey === 'devices' && /no unmanaged|no unknown compliance/.test(text)) predicate = row => !/unmanaged|unknown/i.test(String(row.managementAgent || '')) && Boolean(String(row.managementAgent || '').trim()) && !/unknown/i.test(String(row.complianceState || row.complianceStatus || '')) && Boolean(String(row.complianceState || row.complianceStatus || '').trim());
        else if (domainKey === 'devices' && /not concentrated/.test(text)) predicate = () => false;
        else if (domainKey === 'devices' && /high.?risk/.test(text)) predicate = row => /high/i.test(String(row.riskLevel || row.risk || ''));
        else if (domainKey === 'devices' && /non.?compliant/.test(text)) predicate = row => /non.?compliant/i.test(String(row.complianceState || row.complianceStatus || ''));
        else if (domainKey === 'devices' && /unmanaged|unknown compliance/.test(text)) predicate = row => /unmanaged|unknown/i.test(String(row.managementAgent || row.complianceState || row.complianceStatus || ''));

        else if (domainKey === 'email_security' && /inactive mailbox/.test(text)) predicate = row => Number(row.readCount || 0) + Number(row.sendCount || 0) + Number(row.receiveCount || 0) === 0;
        else if ((domainKey === 'email_security' || domainKey === 'security_alerts') && /no (?:critical|high.?severity)|critical alert/.test(text)) predicate = row => !/critical|high/i.test(String(row.severity || ''));
        else if ((domainKey === 'email_security' || domainKey === 'security_alerts') && /low.?severity/.test(text)) predicate = row => /low/i.test(String(row.severity || '')) && (!/unresolved|ongoing|active|open/.test(text) || !/resolved|closed|dismissed/i.test(String(row.status || '')));
        else if ((domainKey === 'email_security' || domainKey === 'security_alerts') && /unresolved|ongoing|active|open/.test(text)) predicate = row => !/resolved|closed|dismissed/i.test(String(row.status || ''));
        else if (domainKey === 'applications' && /unknown publisher/.test(text)) predicate = row => /unknown/i.test(String(row.publisherName || ''));
        else if (domainKey === 'applications' && /external/.test(text)) predicate = row => row.isExternal !== false;
        else if (domainKey === 'applications' && /no assigned users|no users assigned/.test(text)) predicate = row => Number(row.userCount || row.assignmentCount || 0) === 0;
        else if (domainKey === 'applications' && /no excessive permission|no high.?access/.test(text)) predicate = row => Number(row.roleCount) === 0 && Number(row.scopeCount) === 0 && row.roleCount != null && row.scopeCount != null;
        else if (domainKey === 'governance' && /manual evidence.*excluded/.test(text)) predicate = () => false;
        else if (domainKey === 'governance' && /management review/.test(text)) predicate = row => /attention required/i.test(String(row.status || ''));
        else if (domainKey === 'governance' && /access reviews?.*users and roles/.test(text)) predicate = row => /access review|admin review/i.test(String(row.area || row.title || ''));
        else if (domainKey === 'governance' && /missing ownership|no assigned owner|owner missing|without.*owner/.test(text)) predicate = row => /missing|unassigned|none/i.test(String(row.ownerStatus || row.owner || ''));
        else if (domainKey === 'compliance' && /identity/.test(text)) predicate = row => /identity/i.test(String(row.area || row.category || row.controlName || row.title || '')) && (!/fail|critical/.test(text) || /fail|critical|non.?compliant/i.test(String(row.complianceStatus || row.status || row.severity || '')));
        else if (domainKey === 'compliance' && /device/.test(text)) predicate = row => /device/i.test(String(row.area || row.category || row.controlName || row.title || '')) && (!/fail|critical/.test(text) || /fail|critical|non.?compliant/i.test(String(row.complianceStatus || row.status || row.severity || '')));
        else if (domainKey === 'compliance' && /application|shadow it/.test(text)) predicate = row => /application/i.test(String(row.area || row.category || row.controlName || row.title || ''));
        else if (domainKey === 'compliance' && /partial data visibility/.test(text)) predicate = row => /partial/i.test(String(row.complianceStatus || row.status || row.severity || ''));
        else if (domainKey === 'compliance' && /fail|critical/.test(text)) predicate = row => /fail|critical|non.?compliant/i.test(String(row.complianceStatus || row.status || row.severity || ''));
        else if (domainKey === 'cloudflare_network_security' && /audit/.test(text)) predicate = row => {
            const actor = String(row.actor?.email || row.actor || '');
            const action = String(row.action?.type || row.action || '');
            return (!/support@stackopsit\.co\.za/.test(text) || /support@stackopsit\.co\.za/i.test(actor))
                && (!/successful/.test(text) || row.action?.result === true)
                && (!/update/.test(text) || /update/i.test(action));
        };
        else if (domainKey === 'cloudflare_network_security' && /active/.test(text)) predicate = row => !/inactive|disabled/i.test(String(row.status || row.enabled || ''));
        if (domainKey === 'backup' && /large|storage|data holder/.test(text)) {
            return [...rows].sort((a, b) => Number(unwrapEvidenceRecord(b).storage || unwrapEvidenceRecord(b).storageGB || 0) - Number(unwrapEvidenceRecord(a).storage || unwrapEvidenceRecord(a).storageGB || 0)).slice(0, 5);
        }
        return predicate ? rows.filter(value => predicate(unwrapEvidenceRecord(value))) : rows;
    };
    const resolveCatalogEvidence = (item, domainKey, categories) => {
        const metric = asText(item?.sourceMetric).toLowerCase();
        const exact = metric ? categories.filter(category => [category?.key, category?.sourceMetric].some(value => asText(value).toLowerCase() === metric)) : [];
        const aliases = catalogCategoryAliases(domainKey, item);
        const semantic = aliases.flatMap(alias => categories.filter(category => [category?.key, category?.sourceMetric].some(value => asText(value).toLowerCase() === alias.toLowerCase())));
        const chosen = [...new Set([...semantic, ...exact])][0];
        if (!chosen) return { resolved: false, rows: [] };
        const rows = Array.isArray(chosen.entities) ? chosen.entities.filter(row => row && typeof row === 'object') : [];
        if (rows.length) return { resolved: true, rows: filterCatalogRowsForFinding(rows, item, domainKey) };
        const count = Number(chosen.count);
        if (!Number.isFinite(count) || count <= 0) return { resolved: true, rows: [] };
        return { resolved: true, rows: [{ name: chosen.label || humanizeEvidenceLabel(chosen.sourceMetric || chosen.key), count, sourceMetric: chosen.sourceMetric || chosen.key }] };
    };    // This view model is already field-bounded below. Do not pass it through the generic
    // depth limiter: evidence and evidenceIds sit at depth four and were replaced by
    // "[Detail omitted]" for every domain before the modal could render them.
    return domains.map(domain => {
        const output = domain?.intelligenceOutput || domain?.output || {};
        const evidenceCategories = Array.isArray(output?.evidenceCatalog?.categories) ? output.evidenceCatalog.categories : [];
        const rawMetrics = evidenceCategories.reduce((metrics, category) => {
            const key = String(category?.sourceMetric || category?.key || category?.label || '').trim();
            if (key) metrics[key] = Number(category?.count || (Array.isArray(category?.entities) ? category.entities.length : 0) || 0);
            return metrics;
        }, {});
        const risks = Array.isArray(output.risks) ? output.risks : [];
        const keyFindings = Array.isArray(output.keyFindings) ? output.keyFindings : [];
        const explicitFindings = Array.isArray(output.findings) ? output.findings : [];
        // Keep the source type so a low-priority risk is not presented as a
        // positive outcome merely because of its severity label.
        const rawFindings = [
            ...explicitFindings.map(item => ({ item, findingType: 'finding' })),
            ...risks.map(item => ({ item, findingType: 'risk' })),
            ...keyFindings.map(item => ({ item, findingType: 'finding' }))
        ];
        const dedupe = new Set();
        const findings = rawFindings
            .map(({ item, findingType }, index) => {
                const title = asText(item?.title || item?.patternFound || item?.controlName || item?.metricName, 'Domain finding');
                const key = `${String(title).toLowerCase()}|${String(item?.description || item?.detail || '').toLowerCase()}`;
                if (dedupe.has(key)) return null;
                dedupe.add(key);

                // These arrays are the finding's explicit evidence links. They may
                // contain the same record twice: once as an AI summary and once as a
                // richer source row. Merge by stable record identity before rendering.
                const explicitRecordRows = [
                    ...(Array.isArray(item?.evidenceRecords) ? item.evidenceRecords : []),
                    ...(Array.isArray(item?.affectedEntities) ? item.affectedEntities : []),
                    ...(Array.isArray(item?.evidence) ? item.evidence : []),
                    ...(Array.isArray(item?.evidenceRows) ? item.evidenceRows : [])
                ].filter(row => !isManufacturedValidationRecord(row));
                // evidenceUsed is a descriptive fallback only. It must never widen a
                // finding to a metric category or to the entire domain.
                const catalogResolution = resolveCatalogEvidence(item, String(domain?.domainKey || '').toLowerCase(), evidenceCategories);
                // A strong semantic/category match is authoritative because stored AI
                // arrays may be capped or linked to a broad Azure metric. A category
                // that resolves to zero is still an honest resolution and must not
                // fall back to unrelated explicit rows. Finding-specific embedded
                // subcategories remain intact when no catalog category applies.
                const evidencePool = catalogResolution.resolved
                    ? catalogResolution.rows
                    : explicitRecordRows;
                const evidenceIds = [...new Set([
                    ...(Array.isArray(item?.affectedEntityIds) ? item.affectedEntityIds : []),
                    ...(Array.isArray(item?.recordIds) ? item.recordIds : []),
                    ...(Array.isArray(item?.sourceAlertIds) ? item.sourceAlertIds : []),
                    ...(Array.isArray(item?.evidenceIds) ? item.evidenceIds : []),
                    ...(Array.isArray(item?.entityIds) ? item.entityIds : [])
                ].map(value => String(value || '').trim()).filter(Boolean))];
                const mergedRecordEntries = [];
                const unkeyedRecords = [];
                evidencePool.forEach(row => {
                    if (!row || typeof row !== 'object') {
                        if (String(row || '').trim()) unkeyedRecords.push({ label: String(row).trim() });
                        return;
                    }
                    const keys = evidenceRecordKeys(row);
                    const strongKeys = evidenceStrongRecordKeys(row);
                    if (!keys.length) {
                        unkeyedRecords.push(row);
                        return;
                    }
                    const existing = mergedRecordEntries.find(entry => {
                        const sameStrongRecord = strongKeys.some(key => entry.strongKeys.has(key));
                        const aliasCanBeUsed = !strongKeys.length || !entry.strongKeys.size;
                        return sameStrongRecord || (aliasCanBeUsed && keys.some(key => entry.keys.has(key)));
                    });
                    if (existing) {
                        existing.record = mergeEvidenceRecord(existing.record, row);
                        keys.forEach(key => existing.keys.add(key));
                        strongKeys.forEach(key => existing.strongKeys.add(key));
                        return;
                    }
                    mergedRecordEntries.push({ record: mergeEvidenceRecord({}, row), keys: new Set(keys), strongKeys: new Set(strongKeys) });
                });
                const mergedRecords = [...mergedRecordEntries.map(entry => entry.record), ...unkeyedRecords];
                // Summary/coverage objects are useful only when they are the sole
                // attached evidence. Prefer the underlying people, devices, controls,
                // applications, alerts, or governance items whenever they are present.
                const specificRecords = mergedRecords.filter(row => !isAggregateEvidenceRecord(row));
                const displayRecords = specificRecords.length ? specificRecords : mergedRecords;
                const uniqueEvidence = displayRecords.map(row => normalizeEvidence(row, item)).filter(row => row.name);
                return {
                    findingId: `${String(domain?.domainKey || domain?.domainName || 'domain').toLowerCase()}-${index + 1}`,
                    title: shortText(title, 260),
                    severity: shortText(asText(item?.severity || item?.priority || item?.riskLevel || item?.impact || 'Observed'), 80),
                    status: shortText(asText(item?.status || item?.state || item?.outcome || ''), 80),
                    findingType,
                    impact: shortText(asText(item?.impact || item?.businessImpact || item?.description || item?.detail), 900),
                    whyItMatters: shortText(asText(item?.whyItMatters || item?.reasoning || item?.businessImpact || item?.impact), 900),
                    recommendation: shortText(asText(item?.firstAction || item?.recommendedAction || item?.recommendation || item?.remediationAction || item?.detail), 900),
                    sourceMetric: shortText(asText(item?.sourceMetric || ''), 120),
                    evidenceCount: uniqueEvidence.length,
                    evidenceIds,
                    evidence: uniqueEvidence
                };
            })
            .filter(Boolean);

        const recommendations = (Array.isArray(output.recommendations) ? output.recommendations : [])
            .map(item => shortText(asText(item?.title || item?.firstAction || item?.recommendation || item?.detail || item), 420))
            .filter(Boolean);

        return {
            domainKey: shortText(asText(domain?.domainKey || ''), 120),
            domainName: shortText(asText(domain?.domainName || domain?.domainKey || 'Domain'), 180),
            runId: Number(domain?.runId || 0) || null,
            snapshotId: domain?.snapshotId == null ? null : Number(domain.snapshotId),
            analysedAt: domain?.createdAt || null,
            periodEnd: domain?.periodEnd || null,
            healthScore: scoreOrNull(output?.healthScore ?? output?.authoritativeScores?.healthScore ?? output?.scoreSummary?.healthScore ?? domain?.healthScore ?? domain?.score),
            riskScore: scoreOrNull(output?.riskScore ?? output?.authoritativeScores?.riskScore ?? output?.scoreSummary?.riskScore ?? domain?.riskScore),
            riskLevel: shortText(asText(output?.riskLevel || output?.authoritativeScores?.riskLevel || output?.scoreSummary?.riskLevel || ''), 80),
            summary: shortText(asText(output?.domainExecutiveSummary || output?.executiveSummary || output?.technicalSummary || output?.currentPosture || ''), 1200),
            businessImpact: shortText(asText(output?.businessImpact || output?.businessImpactSummary || ''), 1200),
            rawMetrics,
            recommendations,
            findings
        };
    });
}

function buildSunbirdLatestReportSnapshot(reportRow = null) {
    if (!reportRow) return null;
    const payload = parseReportJson(reportRow.Payload, {});
    const summary = payload?.summary || {};
    const analysis = payload?.analysis || {};
    const generatedWithAi = Number(reportRow?.HasIntelligence) === 1 || payload?.generatedWithAi === true || /Final enterprise synthesis/i.test(String(analysis?.generatedBy || ''));
    return {
        id: reportRow.ID,
        type: reportRow.ReportType,
        periodStart: reportRow.PeriodStart,
        periodEnd: reportRow.PeriodEnd,
        createdAt: reportRow.CreatedAt,
        healthScore: clampReportScore(reportRow.HealthScore ?? summary.healthScore ?? 0),
        generatedWithAi,
        summary: {
            healthScore: clampReportScore(summary.healthScore ?? reportRow.HealthScore ?? 0),
            failures: Number(summary.failures || payload?.failures?.length || analysis?.failures?.length || 0),
            successes: Number(summary.successes || payload?.successes?.length || analysis?.successes?.length || 0),
            totalEvents: Number(summary.totalEvents || payload?.events?.length || 0),
            status: shortText(summary.status || reportRow.ReportStatus || 'Collected', 120)
        },
        analysis: {
            executiveSummary: shortMultilineText(analysis.executiveSummary || '', 6000),
            businessImpactSummary: shortText(analysis.businessImpactSummary || '', SUNBIRD_DASHBOARD_MAX_STRING_LENGTH),
            boardReportSummary: shortText(analysis.boardReportSummary || '', SUNBIRD_DASHBOARD_MAX_STRING_LENGTH),
            historicalChanges: compactSunbirdDashboardValue(analysis.historicalChanges || {})
        },
        domainBreakdown: buildSunbirdDomainBreakdownFromPayload(payload)
    };
}

function buildSunbirdLiveIntelligenceSnapshot(intelligence = null, finalReport = null) {
    const domains = Array.isArray(intelligence?.domains) ? intelligence.domains : [];
    if (!domains.length) return null;
    const domainBreakdown = buildSunbirdDomainBreakdownFromPayload({ domainInsights: { domains } });
    const healthValues = domainBreakdown.map(domain => Number(domain.healthScore)).filter(Number.isFinite);
    const healthScore = healthValues.length
        ? clampReportScore(healthValues.reduce((total, value) => total + value, 0) / healthValues.length)
        : 0;
    const findings = domainBreakdown.flatMap(domain => (domain.findings || []).map(finding => ({
        ...finding,
        domainKey: domain.domainKey,
        domainName: domain.domainName,
        source: domain.domainName
    })));
    const recommendations = domainBreakdown.flatMap(domain => (domain.recommendations || []).map(item => ({
        title: item,
        source: domain.domainName,
        priority: domain.riskLevel || 'medium'
    })));
    const synthesis = finalReport?.finalSynthesis?.synthesisOutput || {};
    const executiveSummary = String(synthesis?.enterpriseExecutiveSummary?.summary || '').trim();
    const historicalChanges = buildHistoricalNarrativeFromSynthesis(synthesis, {
        period: { end: intelligence.periodEnd || intelligence.createdAt || new Date() }
    });
    // The client Executive brief must use the stored enterprise synthesis verbatim;
    // trend/detail sections are rendered elsewhere and must not replace this summary.
    const fullExecutiveSummary = executiveSummary
        ? executiveSummary
        : 'This executive view combines the newest completed Azure analysis for each active domain. Domains refresh independently and display their own analysis time and run ID; no older complete enterprise run is used as a substitute.';
    const failures = findings.filter(finding => finding.findingType === 'risk' || /critical|high|severe|failed/i.test(String(finding.severity || '')));
    const positiveTerms = /healthy|good|passed|pass|compliant|resolved|remediated|closed|success|succeeded|complete|connected|enabled|operational/i;
    const negativeTerms = /\b(no|not|missing|disabled|inactive|increase|risk|exposure|gap|fail|failed|attention|degraded|unavailable)\b/i;
    const successes = findings
        .filter(finding => finding.findingType !== 'risk')
        .filter(finding => {
            const text = `${finding.title || ''} ${finding.status || ''} ${finding.severity || ''}`;
            return positiveTerms.test(text) && !negativeTerms.test(text);
        })
        .map(finding => ({ ...finding, source: finding.source || finding.domainName || 'Enterprise intelligence' }));
    const domainSuccesses = domainBreakdown
        .filter(domain => Number(domain.healthScore) >= 80)
        .map(domain => ({
            title: `${domain.domainName} health is strong`,
            detail: `Latest collected evidence gives this domain a ${Math.round(Number(domain.healthScore))}% health score.`,
            source: domain.domainName,
            status: 'validated'
        }));
    const successKeys = new Set();
    const allSuccesses = [...successes, ...domainSuccesses].filter(item => {
        const key = `${String(item.title || '').trim().toLowerCase()}|${String(item.source || '').trim().toLowerCase()}`;
        if (!key || successKeys.has(key)) return false;
        successKeys.add(key);
        return true;
    });
    return {
        id: `enterprise-run-${Number(intelligence.latestRunId || 0)}`,
        enterpriseRunId: Number(intelligence.latestRunId || 0),
        snapshotId: intelligence.latestSnapshotId == null ? null : Number(intelligence.latestSnapshotId),
        type: intelligence.periodType || 'daily',
        periodStart: intelligence.periodStart || null,
        periodEnd: intelligence.periodEnd || null,
        createdAt: intelligence.createdAt || null,
        generatedWithAi: true,
        summary: {
            healthScore,
            failures: failures.length,
            successes: allSuccesses.length,
            totalEvents: findings.length,
            status: failures.some(finding => /critical/i.test(String(finding.severity || '')))
                ? 'critical'
                : failures.length ? 'attention' : 'healthy'
        },
        analysis: {
            executiveSummary: fullExecutiveSummary,
            businessImpactSummary: String(synthesis?.businessImpactSummary || ''),
            boardReportSummary: String(synthesis?.boardReport?.boardSummary || synthesis?.boardReport?.summary || ''),
            historicalChanges
        },
        failures,
        successes: allSuccesses,
        recommendations,
        domainBreakdown
    };
}

function buildSunbirdLiveOverview(liveReport = null) {
    if (!liveReport) return null;
    const domainScores = Object.fromEntries((liveReport.domainBreakdown || []).map(domain => [
        domain.domainKey || domain.domainName,
        domain.healthScore
    ]));
    return {
        summary: { ...liveReport.summary },
        analysis: {
            executiveSummary: liveReport.analysis?.executiveSummary || '',
            businessImpactSummary: liveReport.analysis?.businessImpactSummary || '',
            failures: liveReport.failures || [],
            successes: liveReport.successes || [],
            recommendations: liveReport.recommendations || []
        },
        failures: liveReport.failures || [],
        successes: liveReport.successes || [],
        recommendations: liveReport.recommendations || [],
        events: (liveReport.failures || []).map(finding => ({
            title: finding.title,
            detail: finding.impact || finding.whyItMatters || '',
            severity: finding.severity || 'observed',
            source: finding.source || finding.domainName || 'Enterprise intelligence',
            status: 'observed'
        })),
        domainScores,
        trend: []
    };
}

async function generateAiReportAnalysis(report, powerBiIntelligence = null) {
    const fallback = buildDeterministicReportAnalysis(report);
    try {
        const evidence = {
            period: report.period,
            summary: report.summary,
            successes: report.successes.slice(0, 8),
            failures: report.failures.slice(0, 12),
            recommendations: report.recommendations.slice(0, 8),
            recentEvents: report.events.slice(0, 20)
        };
        if (powerBiIntelligence?.domains?.length) {
            evidence.domainSummaries = powerBiIntelligence.domains.map(domain => ({
                domainKey: domain.domainKey,
                domainName: domain.domainName,
                status: domain.status,
                healthScore: domain.intelligenceOutput?.healthScore ?? domain.intelligenceOutput?.score ?? null,
                riskCount: Array.isArray(domain.intelligenceOutput?.risks) ? domain.intelligenceOutput.risks.length : null,
                recommendationCount: Array.isArray(domain.intelligenceOutput?.recommendations) ? domain.intelligenceOutput.recommendations.length : null,
                topRisks: (domain.intelligenceOutput?.risks || []).slice(0, 3).map(risk => risk?.title || risk?.name || risk?.detail || 'Risk').filter(Boolean),
                topRecommendations: (domain.intelligenceOutput?.recommendations || []).slice(0, 3).map(rec => rec?.title || rec?.name || rec?.detail || 'Recommendation').filter(Boolean)
            }));
        }
        if (powerBiIntelligence?.finalSynthesis) {
            evidence.finalSynthesisSummary = {
                status: powerBiIntelligence.finalSynthesis.status,
                summary: powerBiIntelligence.finalSynthesis.synthesisOutput?.enterpriseExecutiveSummary?.summary || null,
                boardReportTitle: powerBiIntelligence.finalSynthesis.synthesisOutput?.boardReport?.boardSummary || null
            };
        }
        const completion = await azureOpenAIService.createJsonCompletion({
            temperature: 0.1,
            maxTokens: 700,
            messages: [
                {
                    role: 'system',
                    content: 'You are a cybersecurity reporting analyst. Use only supplied evidence and any included domain intelligence output. Return JSON with executiveSummary, successes, failures, recommendations. Keep each list concise and actionable. Never invent facts, dates, people, or incidents.'
                },
                { role: 'user', content: JSON.stringify(evidence) }
            ]
        });
        const parsed = completion.data || {};
        const result = {
            executiveSummary: String(parsed.executiveSummary || fallback.executiveSummary),
            successes: Array.isArray(parsed.successes) ? parsed.successes.slice(0, 6) : fallback.successes,
            failures: Array.isArray(parsed.failures) ? parsed.failures.slice(0, 8) : fallback.failures,
            recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations.slice(0, 6) : fallback.recommendations,
            generatedBy: 'Evidence summary engine',
            rawAiResponse: parsed,
            domainIntelligenceInfo: powerBiIntelligence ? {
                available: true,
                domainCount: powerBiIntelligence.domains.length,
                latestRunId: powerBiIntelligence.latestRunId || null
            } : null
        };
        console.log('[Reports] AI analysis completed successfully', { successes: result.successes.length, failures: result.failures.length, recommendations: result.recommendations.length });
        return result;
    } catch (error) {
        console.warn('[Reports] AI analysis fallback:', error.message);
        return {
            ...fallback,
            generatedBy: 'Evidence summary engine'
        };
    }
}

let sunbirdReportsPublicationSchemaPromise = null;

async function ensureSunbirdReportsPublicationSchema() {
    if (sunbirdReportsPublicationSchemaPromise) return sunbirdReportsPublicationSchemaPromise;
    sunbirdReportsPublicationSchemaPromise = (async () => {
        for (const [column, definition] of [
            ['EnterpriseRunID', 'BIGINT DEFAULT NULL'],
            ['EnterpriseSnapshotID', 'BIGINT DEFAULT NULL'],
            ['IsCurrent', 'TINYINT(1) NOT NULL DEFAULT 0'],
            ['PublishedAt', 'DATETIME DEFAULT NULL']
        ]) {
            const [existing] = await pool.query(`SHOW COLUMNS FROM SunbirdReports LIKE '${column}'`);
            if (!existing.length) {
                await pool.query(`ALTER TABLE SunbirdReports ADD COLUMN ${column} ${definition}`);
                console.log(`[Reports] Added missing SunbirdReports.${column} column.`);
            }
        }
        try {
            await pool.query('CREATE INDEX idx_sunbird_reports_current ON SunbirdReports (CompanyID, ReportType, IsCurrent, PublishedAt, CreatedAt)');
        } catch (error) {
            if (error.code !== 'ER_DUP_KEYNAME') throw error;
        }
    })().catch(error => {
        sunbirdReportsPublicationSchemaPromise = null;
        throw error;
    });
    return sunbirdReportsPublicationSchemaPromise;
}

async function ensureSunbirdReportSettings(companyId, recipientEmail = null) {
    await pool.query(
        `INSERT INTO SunbirdReportSettings (CompanyID, RecipientEmail)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE RecipientEmail = COALESCE(RecipientEmail, VALUES(RecipientEmail))`,
        [companyId, recipientEmail]
    );
    const [rows] = await pool.query('SELECT * FROM SunbirdReportSettings WHERE CompanyID = ? LIMIT 1', [companyId]);
    return rows[0] || null;
}

function normalizeReportRecipientEmails(value) {
    const rawRecipients = Array.isArray(value)
        ? value
        : String(value || '').split(/[;,]/);
    const seen = new Set();
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    return rawRecipients
        .map(item => String(item || '').trim())
        .filter(Boolean)
        .filter(email => emailPattern.test(email))
        .filter(email => {
            const key = email.toLowerCase();
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
}

function hasInvalidReportRecipients(value) {
    const rawRecipients = Array.isArray(value)
        ? value
        : String(value || '').split(/[;,]/);
    return rawRecipients
        .map(item => String(item || '').trim())
        .filter(Boolean)
        .some(email => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email));
}

function formatReportRecipientList(recipients = []) {
    return normalizeReportRecipientEmails(recipients).join(', ');
}

function isSunbirdReportAccessContext(context) {
    const accessType = String(context?.accessType || context?.clientId || '').toLowerCase();
    const email = String(context?.email || '').toLowerCase();
    return accessType === 'sunbird' || email.includes('@sunbird.eu') || email.includes('@stackopsit.co.za');
}

async function loadSunbirdReportEvidence(companyId) {
    // Live Cloudflare enrichment is useful, but the completed enterprise run already
    // contains its current domain evidence. Never let one external request prevent
    // a report row (and therefore its PDF) from being persisted.
    const cloudflarePromise = withSunbirdReportTimeout(
        () => getCloudflareNetworkSecuritySummary({ getSecret }),
        12000,
        'Cloudflare report evidence'
    ).catch(error => {
        console.warn('[Reports] Cloudflare evidence skipped:', error.message);
        return null;
    });
    const [
        companyRows,
        identityRows,
        identityUserDetailsRows,
        deviceRows,
        emailRows,
        emailPayloadRows,
        securityRows,
        backupRows,
        applicationRows,
        applicationPayloadRows,
        operationsRows,
        governanceRows,
        complianceRows,
        cloudflare
    ] = await Promise.all([
        pool.query('SELECT CompanyName FROM Companies WHERE ID = ? LIMIT 1', [companyId]),
        pool.query('SELECT * FROM IdentityMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        pool.query('SELECT UsersPayload, LastUpdated FROM IdentityUserDetailsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        pool.query('SELECT * FROM DeviceMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        pool.query('SELECT * FROM EmailMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        pool.query('SELECT Payload, LastUpdated FROM EmailSecurityPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        pool.query('SELECT Payload, LastUpdated FROM SecurityEventsPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        pool.query('SELECT Payload, LastUpdated FROM BackupRecoveryPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        pool.query('SELECT * FROM ApplicationMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        pool.query('SELECT Payload, LastUpdated FROM ApplicationPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        pool.query('SELECT Payload, LastUpdated FROM SunbirdOperationsPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        pool.query('SELECT Payload, LastUpdated FROM SunbirdGovernancePayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        pool.query('SELECT Payload, LastUpdated FROM SunbirdComplianceControlsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
        cloudflarePromise
    ]);
    return {
        companyName: companyRows[0][0]?.CompanyName || 'Client',
        identity: identityRows[0][0] || {},
        identityUsers: parseReportJson(identityUserDetailsRows[0]?.UsersPayload, []),
        devices: deviceRows[0][0] || {},
        emailMetrics: emailRows[0][0] || {},
        email: parseReportJson(emailPayloadRows[0][0]?.Payload, {}),
        security: parseReportJson(securityRows[0][0]?.Payload, {}),
        backup: parseReportJson(backupRows[0][0]?.Payload, {}),
        applicationsMetrics: applicationRows[0][0] || {},
        applications: parseReportJson(applicationPayloadRows[0][0]?.Payload, {}),
        operations: parseReportJson(operationsRows[0][0]?.Payload, {}),
        governance: parseReportJson(governanceRows[0][0]?.Payload, {}),
        compliance: parseReportJson(complianceRows[0][0]?.Payload, {}),
        cloudflare,
        sourceUpdatedAt: [
            identityRows[0][0]?.LastUpdated,
            deviceRows[0][0]?.LastUpdated,
            emailRows[0][0]?.LastUpdated,
            emailPayloadRows[0][0]?.LastUpdated,
            securityRows[0][0]?.LastUpdated,
            backupRows[0][0]?.LastUpdated,
            applicationRows[0][0]?.LastUpdated,
            applicationPayloadRows[0][0]?.LastUpdated,
            operationsRows[0][0]?.LastUpdated,
            governanceRows[0][0]?.LastUpdated,
            complianceRows[0][0]?.LastUpdated,
            cloudflare?.fetchedAt
        ].filter(Boolean)
    };
}

async function buildSunbirdReportPayload(companyId, periodStart, periodEnd, includeAi = false, { enterpriseRunId = null } = {}) {
    const evidence = await loadSunbirdReportEvidence(companyId);
    const securitySummary = evidence.security.summary || {};
    const emailSummary = evidence.email.summary || {};
    const backupSummary = evidence.backup.summary || {};
    const deviceTotal = Number(evidence.devices.TotalDevices || 0);
    const deviceIssues = Number(evidence.devices.NonCompliant || 0) +
        Number(evidence.devices.NotEncrypted || 0) +
        Number(evidence.devices.StaleDevices || 0);
    const deviceScore = deviceTotal
        ? clampReportScore(100 - ((deviceIssues / Math.max(1, deviceTotal * 3)) * 100))
        : null;
    const appTotal = Number(evidence.applicationsMetrics.TotalApps || evidence.applications.summary?.totalApplications || 0);
    const riskyApps = Number(evidence.applicationsMetrics.HighRiskApps || evidence.applications.summary?.highRiskApps || 0);
    const appScore = appTotal ? clampReportScore(100 - ((riskyApps / appTotal) * 100)) : null;
    const emailRiskSignals = Number(emailSummary.highSeverityAlerts || evidence.emailMetrics.HighSeverity || 0) +
        Number(emailSummary.activeIncidents || evidence.emailMetrics.OpenIncidents || 0);
    const emailScore = emailSummary.securityScore != null
        ? clampReportScore(emailSummary.securityScore)
        : clampReportScore(100 - (emailRiskSignals * 12));
    const cloudflareSignals = buildCloudflareReportSignals(evidence.cloudflare);
    const scores = [
        securitySummary.securityScore,
        evidence.identity.SecurityScore,
        deviceScore,
        appScore,
        emailScore,
        evidence.operations.summary?.healthScore,
        evidence.governance.summary?.score,
        evidence.compliance.summary?.score,
        cloudflareSignals.score
    ].filter(value => value != null && Number.isFinite(Number(value))).map(clampReportScore);
    const healthScore = scores.length
        ? clampReportScore(scores.reduce((sum, value) => sum + value, 0) / scores.length)
        : 0;

    const events = [];
    (evidence.security.activityFeed || []).forEach(item => events.push(normalizeReportEvent(item, 'Security')));
    (evidence.security.incidents || []).forEach(item => events.push(normalizeReportEvent(item, 'Security incident')));
    (evidence.security.alerts || []).forEach(item => events.push(normalizeReportEvent(item, 'Security alert')));
    (evidence.security.signIns?.suspicious || []).forEach(item => events.push(normalizeReportEvent(item, 'Identity sign-in')));
    (evidence.email.alerts || []).forEach(item => events.push(normalizeReportEvent(item, 'Email security')));
    (evidence.email.incidents || []).forEach(item => events.push(normalizeReportEvent(item, 'Email incident')));
    (evidence.operations.events || evidence.operations.activity || []).forEach(item => events.push(normalizeReportEvent(item, 'Operations')));
    cloudflareSignals.events.forEach(item => events.push(normalizeReportEvent(item, 'Cloudflare One')));
    const filteredEvents = events
        .filter(event => isReportEventWithinRange(event, periodStart, periodEnd))
        .sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0))
        .slice(0, 120);
    const failureEvents = filteredEvents.filter(event =>
        ['critical', 'high'].includes(event.severity) ||
        ['failed', 'failure', 'active', 'open', 'newalert'].includes(event.status)
    );
    const resolvedEvents = filteredEvents.filter(event =>
        ['resolved', 'closed', 'success', 'succeeded', 'healthy'].includes(event.status)
    );
    const successes = [
        ...(resolvedEvents.length ? [{
            title: `${resolvedEvents.length} event${resolvedEvents.length === 1 ? '' : 's'} resolved or completed`,
            detail: 'Recorded dashboard evidence shows successful closure during the selected period.'
        }] : []),
        ...(!failureEvents.some(event => event.severity === 'critical') ? [{
            title: 'No critical failures recorded',
            detail: 'No critical-severity event was present in the collected dashboard evidence.'
        }] : []),
        ...(Number(backupSummary.activeUsersCount || 0) > 0 ? [{
            title: 'Backup coverage active',
            detail: `${Number(backupSummary.activeUsersCount || 0)} active user${Number(backupSummary.activeUsersCount || 0) === 1 ? '' : 's'} included in backup evidence.`
        }] : []),
        ...(deviceTotal && !Number(evidence.devices.NonCompliant || 0) ? [{
            title: 'Device compliance clear',
            detail: `${deviceTotal} managed device${deviceTotal === 1 ? '' : 's'} with no non-compliant devices reported.`
        }] : []),
        ...(cloudflareSignals.hasReportableEvidence && !cloudflareSignals.problems.length ? [{
            title: 'Cloudflare One evidence reviewed',
            detail: `${cloudflareSignals.summary.protectedApps} protected app${cloudflareSignals.summary.protectedApps === 1 ? '' : 's'}, ${cloudflareSignals.summary.gatewayPolicies} Gateway polic${cloudflareSignals.summary.gatewayPolicies === 1 ? 'y' : 'ies'}, and ${cloudflareSignals.summary.dlpProfiles} DLP profile${cloudflareSignals.summary.dlpProfiles === 1 ? '' : 's'} were evidenced.`
        }] : [])
    ].slice(0, 8);
    const nonCloudflareFailureEvents = failureEvents.filter(event => event.source !== 'Cloudflare One');
    const failures = [
        ...cloudflareSignals.problems,
        ...nonCloudflareFailureEvents.map(event => ({
            title: event.title,
            detail: event.detail,
            severity: event.severity,
            status: event.status,
            timestamp: event.timestamp,
            source: event.source,
            asset: event.asset
        }))
    ].slice(0, 12);
    const recommendations = [
        ...cloudflareSignals.recommendations,
        ...(failureEvents.some(event => event.severity === 'critical') ? [{
            priority: 'critical',
            title: 'Triage critical evidence immediately',
            detail: 'Validate ownership, containment, and closure evidence for every critical event.'
        }] : []),
        ...(Number(securitySummary.activeIncidents || 0) > 0 ? [{
            priority: 'high',
            title: 'Close active security incidents',
            detail: `${Number(securitySummary.activeIncidents || 0)} active incident${Number(securitySummary.activeIncidents || 0) === 1 ? '' : 's'} remain in the security feed.`
        }] : []),
        ...(Number(evidence.devices.NonCompliant || 0) > 0 ? [{
            priority: 'high',
            title: 'Remediate non-compliant devices',
            detail: `${Number(evidence.devices.NonCompliant || 0)} device${Number(evidence.devices.NonCompliant || 0) === 1 ? '' : 's'} require compliance remediation.`
        }] : []),
        ...(riskyApps > 0 ? [{
            priority: 'medium',
            title: 'Review high-risk application access',
            detail: `${riskyApps} application${riskyApps === 1 ? '' : 's'} are marked high risk.`
        }] : []),
        {
            priority: healthScore >= 85 ? 'low' : 'medium',
            title: 'Maintain daily evidence collection',
            detail: 'Use the report history to confirm that health scores and open failures improve week over week.'
        }
    ].slice(0, 8);
    const sourceFreshness = evidence.sourceUpdatedAt.length
        ? new Date(Math.max(...evidence.sourceUpdatedAt.map(value => new Date(value).getTime()).filter(Number.isFinite))).toISOString()
        : null;
    const report = {
        version: 1,
        companyName: evidence.companyName,
        period: { start: periodStart.toISOString(), end: periodEnd.toISOString() },
        generatedAt: new Date().toISOString(),
        summary: {
            healthScore,
            status: failures.some(item => item.severity === 'critical') ? 'critical' :
                failures.some(item => item.severity === 'high') ? 'attention' : 'healthy',
            totalEvents: filteredEvents.length,
            failures: failures.length,
            successes: successes.length,
            activeIncidents: Number(securitySummary.activeIncidents || 0),
            highSeverityAlerts: Number(securitySummary.highSeverityAlerts || 0),
            sourceFreshness
        },
        domainScores: {
            security: securitySummary.securityScore != null ? clampReportScore(securitySummary.securityScore) : null,
            identity: evidence.identity.SecurityScore != null ? clampReportScore(evidence.identity.SecurityScore) : null,
            devices: deviceScore,
            email: emailScore,
            applications: appScore,
            backup: evidence.backup.success ? 100 : null,
            cloudflare: cloudflareSignals.score
        },
        cloudflare: cloudflareSignals.hasReportableEvidence ? {
            score: cloudflareSignals.score,
            summary: cloudflareSignals.summary,
            problems: cloudflareSignals.problems,
            recommendations: cloudflareSignals.recommendations,
            events: cloudflareSignals.events.slice(0, 10)
        } : null,
        successes,
        failures,
        recommendations,
        events: filteredEvents,
        collection: {
            sources: [
                'Identity',
                'Devices',
                'Email',
                'Security',
                'Backup',
                'Applications',
                'Operations',
                'Governance',
                ...(cloudflareSignals.hasReportableEvidence ? ['Cloudflare One'] : [])
            ],
            evidenceUpdatedAt: sourceFreshness
        }
    };

    const [trendRows] = await pool.query(
        `SELECT HealthScore, PeriodEnd
         FROM SunbirdReports
         WHERE CompanyID = ? AND ReportType = 'daily' AND PeriodEnd BETWEEN ? AND ?
         ORDER BY PeriodEnd ASC`,
        [companyId, periodStart, periodEnd]
    );
    report.trend = trendRows.map(row => ({
        date: new Date(row.PeriodEnd).toISOString(),
        healthScore: clampReportScore(row.HealthScore)
    }));
    report.dailyReports = await loadSunbirdDailyReportSummaries(companyId, periodStart, periodEnd);
    report.currentDailyReport = {
        periodEnd,
        healthScore: report.summary.healthScore,
        failures: report.summary.failures,
        successes: report.summary.successes,
        events: report.summary.totalEvents
    };
    report.previousDailyReport = await loadSunbirdLatestDailyReportSummary(companyId, periodEnd);
    const expectedEnterpriseRunId = Number(enterpriseRunId || 0) || null;
    const powerBiIntelligence = includeAi ? await fetchSunbirdPowerBIIntelligence(companyId, { runId: expectedEnterpriseRunId }) : null;
    if (expectedEnterpriseRunId && Number(powerBiIntelligence?.latestRunId || 0) !== expectedEnterpriseRunId) {
        throw new Error(`Daily report could not be bound to enterprise run #${expectedEnterpriseRunId}.`);
    }
    // Domain metrics and evidence remain pinned to each domain's newest completed
    // analysis. The executive narrative is taken from the latest completed enterprise
    // synthesis, rather than replaced with a fabricated per-domain placeholder.
    const powerBiFinal = includeAi
        ? await fetchSunbirdPowerBIFinal(companyId, expectedEnterpriseRunId || powerBiIntelligence?.latestRunId || null, { timeoutMs: 12000 })
        : null;
    report.domainInsights = powerBiIntelligence;
    // A report may be a composite of independently completed domains. Persist the
    // manifest so the PDF and automated delivery retain exact freshness lineage.
    report.enterpriseRunId = Number(powerBiIntelligence?.latestRunId || 0) || null;
    report.enterpriseRunManifest = Array.isArray(powerBiIntelligence?.domainManifest)
        ? powerBiIntelligence.domainManifest
        : (powerBiIntelligence?.domains || []).map(domain => ({
            domainKey: domain.domainKey,
            runId: Number(domain.runId || 0) || null,
            snapshotId: domain.snapshotId == null ? null : Number(domain.snapshotId),
            analysedAt: domain.createdAt || null,
            status: domain.status || null
        }));
    report.finalSynthesis = powerBiFinal;
    report.analysis = includeAi
        ? (powerBiFinal?.finalSynthesis
            ? buildFinalSynthesisReportAnalysis(report, powerBiFinal)
            : await withSunbirdReportTimeout(
                () => generateAiReportAnalysis(report, powerBiIntelligence),
                15000,
                'Report AI fallback'
            ).catch(error => {
                console.warn('[Reports] AI fallback skipped:', error.message);
                return buildDeterministicReportAnalysis(report);
            }))
        : buildDeterministicReportAnalysis(report);
    return report;
}

async function loadSunbirdDailyReportSummaries(companyId, periodStart, periodEnd) {
    const [rows] = await pool.query(
        `SELECT ID, PeriodStart, PeriodEnd, HealthScore, ReportStatus, Payload, CreatedAt
         FROM SunbirdReports
         WHERE CompanyID = ? AND ReportType = 'daily' AND PeriodEnd BETWEEN ? AND ?
         ORDER BY PeriodEnd ASC`,
        [companyId, periodStart, periodEnd]
    );
    return rows.map(row => {
        const payload = parseReportJson(row.Payload, {});
        const summary = payload.summary || {};
        const failures = payload.analysis?.failures || payload.failures || [];
        const successes = payload.analysis?.successes || payload.successes || [];
        const recommendations = payload.analysis?.recommendations || payload.recommendations || [];
        return {
            id: row.ID,
            date: row.PeriodEnd,
            periodStart: row.PeriodStart,
            periodEnd: row.PeriodEnd,
            createdAt: row.CreatedAt,
            healthScore: clampReportScore(row.HealthScore ?? summary.healthScore ?? 0),
            status: row.ReportStatus || summary.status || 'collected',
            failures: Number(summary.failures || failures.length || 0),
            successes: Number(summary.successes || successes.length || 0),
            events: Number(summary.totalEvents || payload.events?.length || 0),
            topFailure: failures[0]?.title || failures[0] || '',
            topRecommendation: recommendations[0]?.title || recommendations[0] || '',
            topSuccess: successes[0]?.title || successes[0] || ''
        };
    });
}

async function loadSunbirdLatestDailyReportSummary(companyId, before) {
    const [rows] = await pool.query(
        `SELECT ID, PeriodStart, PeriodEnd, HealthScore, ReportStatus, Payload, CreatedAt
         FROM SunbirdReports
         WHERE CompanyID = ? AND ReportType = 'daily' AND PeriodEnd < ?
         ORDER BY PeriodEnd DESC
         LIMIT 1`,
        [companyId, before]
    );
    const row = rows[0];
    if (!row) return null;
    const payload = parseReportJson(row.Payload, {});
    const summary = payload.summary || {};
    const failures = payload.analysis?.failures || payload.failures || [];
    const successes = payload.analysis?.successes || payload.successes || [];
    return {
        id: row.ID,
        date: row.PeriodEnd,
        periodStart: row.PeriodStart,
        periodEnd: row.PeriodEnd,
        createdAt: row.CreatedAt,
        healthScore: clampReportScore(row.HealthScore ?? summary.healthScore ?? 0),
        status: row.ReportStatus || summary.status || 'collected',
        failures: Number(summary.failures || failures.length || 0),
        successes: Number(summary.successes || successes.length || 0),
        events: Number(summary.totalEvents || payload.events?.length || 0)
    };
}
async function saveSunbirdReport(companyId, reportType, periodStart, periodEnd, generatedByUserId = null, includeAi = false, { enterpriseRunId = null, publishCurrent = false } = {}) {
    await writeSunbirdReportLog({
        companyId,
        eventType: `${reportType}_report_generation_started`,
        status: 'started',
        message: `${reportType === 'daily' ? 'Daily evidence collection' : `${reportType} report generation`} started.`,
        metadata: { periodStart, periodEnd, includeAi, enterpriseRunId: enterpriseRunId || null, publishCurrent: Boolean(publishCurrent) },
        actorUserId: generatedByUserId
    });
    try {
        const payload = await buildSunbirdReportPayload(companyId, periodStart, periodEnd, includeAi, { enterpriseRunId });
        payload.generatedWithAi = includeAi;
        const payloadJson = JSON.stringify(payload);
        console.log('[Reports Generate] payload prepared', JSON.stringify({
            companyId,
            reportType,
            payloadBytes: Buffer.byteLength(payloadJson),
            domainCount: Array.isArray(payload?.domainInsights?.domains) ? payload.domainInsights.domains.length : 0,
            enterpriseRunId: payload.enterpriseRunId || null,
            hasFinalSynthesis: Boolean(payload?.finalSynthesis?.finalSynthesis)
        }));
        const [result] = await pool.query(
            `INSERT INTO SunbirdReports
             (CompanyID, ReportType, PeriodStart, PeriodEnd, HealthScore, ReportStatus, Payload, GeneratedByUserID, EnterpriseRunID, EnterpriseSnapshotID, IsCurrent, PublishedAt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)`,
            [
                companyId,
                reportType,
                periodStart,
                periodEnd,
                payload.summary.healthScore,
                payload.summary.status,
                payloadJson,
                generatedByUserId,
                Number(payload.enterpriseRunId || enterpriseRunId || 0) || null,
                Number(payload.domainInsights?.latestSnapshotId || 0) || null
            ]
        );
        if (publishCurrent && reportType === 'daily') {
            await pool.query("UPDATE SunbirdReports SET IsCurrent = 0 WHERE CompanyID = ? AND ReportType = 'daily'", [companyId]);
            await pool.query("UPDATE SunbirdReports SET IsCurrent = 1, PublishedAt = NOW() WHERE ID = ? AND CompanyID = ?", [result.insertId, companyId]);
        }
        await writeSunbirdReportLog({
            companyId,
            reportId: result.insertId,
            eventType: `${reportType}_report_generated`,
            status: 'success',
            message: `${reportType === 'daily' ? 'Daily evidence snapshot' : `${reportType} report`} completed with a ${payload.summary.healthScore}% health score.`,
            metadata: {
                periodStart,
                periodEnd,
                healthScore: payload.summary.healthScore,
                events: payload.summary.totalEvents,
                failures: payload.summary.failures,
                successes: payload.summary.successes
            },
            actorUserId: generatedByUserId
        });
        return { id: result.insertId, payload };
    } catch (error) {
        await writeSunbirdReportLog({
            companyId,
            eventType: `${reportType}_report_generation_failed`,
            status: 'failed',
            message: `${reportType} report generation failed: ${error.message}`,
            metadata: { periodStart, periodEnd },
            actorUserId: generatedByUserId
        });
        throw error;
    }
}

const SUNBIRD_AUTOMATION_NOTIFICATION_EMAIL = process.env.STACKCTRL_AUTOMATION_NOTIFICATION_EMAIL || 'maambelanduni@stackopsit.co.za';

async function updateSunbirdHourlyAutomationState(companyId, state = {}) {
    await pool.query(`UPDATE SunbirdReportSettings SET LastHourlyAutomationAt = NOW(), LastHourlyAutomationStatus = ?, LastHourlyAutomationMessage = ?, LastHourlyAutomationRunID = ?, LastHourlyAutomationSnapshotID = ?, LastHourlyAutomationReportID = ? WHERE CompanyID = ?`, [String(state.status || 'unknown').slice(0, 30), String(state.message || '').slice(0, 1000) || null, state.runId || null, state.snapshotId || null, state.reportId || null, Number(companyId)]);
}

async function notifySunbirdHourlyAutomation({ companyId, report = null, run = {}, status, message, cadence = 'hourly' }) {
    const recipients = normalizeReportRecipientEmails(SUNBIRD_AUTOMATION_NOTIFICATION_EMAIL);
    if (!recipients.length) throw new Error(`No ${cadence} automation notification recipient is configured`);
    const companyName = report?.payload?.companyName || `Company #${companyId}`;
    const successful = status === 'completed' || status === 'completed_with_warnings';
    const cadenceLabel = cadence === 'weekly' ? 'Weekly' : 'Hourly';
    const pdf = successful && report?.payload
        ? await Promise.race([
            generateSunbirdReportPdf(report.payload, report.id),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Automatic PDF generation exceeded 60 seconds')), 60000))
        ])
        : null;
    const html = renderCorporateEmail({
        title: `${cadenceLabel} StackCTRL automation ${successful ? 'completed' : 'failed'}`,
        greeting: 'Dear Maambelanduni,',
        bodyHtml: [
            `<p>${successful
                ? escapeHtml(message || 'A latest per-domain StackCTRL report was generated.')
                : 'The StackCTRL collection or Azure enterprise analysis did not complete.'}</p>`,
            `<p><strong>Company:</strong> ${escapeHtml(companyName)}<br>`
                + `<strong>Run:</strong> #${escapeHtml(run.runId || 'Not created')}<br>`
                + `<strong>Snapshot:</strong> #${escapeHtml(run.snapshotId || 'Not created')}<br>`
                + `<strong>Status:</strong> ${escapeHtml(status)}<br>`
                + `<strong>Detail:</strong> ${escapeHtml(message || 'No additional detail was supplied.')}</p>`,
            successful
                ? `<p>A newly generated ${cadence} PDF report is attached and is also available in the client report history.</p>`
                : '<p>The client dashboard retains its last verified report and shows this failure in Automation status.</p>'
        ].join('')    });
    for (const recipient of recipients) {
        await sendEmail(
            recipient,
            `StackCTRL ${cadence} automation ${successful ? 'completed' : 'failed'} | ${companyName}`,
            html,
            true,
            pdf ? [{
                name: `StackCTRL-${cadenceLabel}-Report-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.pdf`,
                contentType: 'application/pdf',
                content: pdf
            }] : []
        );
    }
    return { recipients, pdfBytes: pdf?.length || 0 };
}
async function finalizeSunbirdHourlyAutomation({ companyId, run = {}, now = new Date() } = {}) {
    const status = String(run.status || 'failed').toLowerCase();
    const success = ['completed', 'completed_with_warnings'].includes(status);
    const state = { runId: run.runId || null, snapshotId: run.snapshotId || null, reportId: null };
    if (!run.runId) {
        const message = run.terminalError?.errorMessage || (run.rateLimit ? 'Azure rate limit reached; no report was generated for this hour.' : `Enterprise run ended with ${status}.`);
        await writeSunbirdReportLog({ companyId, eventType: 'hourly_automation_failed', status: 'failed', message, metadata: { runId: state.runId, snapshotId: state.snapshotId, status } });
        try { await notifySunbirdHourlyAutomation({ companyId, run, status, message }); await updateSunbirdHourlyAutomationState(companyId, { ...state, status: 'failed', message }); }
        catch (notificationError) { await updateSunbirdHourlyAutomationState(companyId, { ...state, status: 'failed_notification', message: `${message} Notification failed: ${notificationError.message}` }); }
        return { status: 'failed', ...state, message };
    }
    try {
        const report = await saveSunbirdReport(companyId, 'hourly', new Date(new Date(now).getTime() - 60 * 60 * 1000), now, null, true);
        const domainManifest = Array.isArray(report.payload?.enterpriseRunManifest) ? report.payload.enterpriseRunManifest : [];
        const refreshedDomains = domainManifest.filter(domain => Number(domain?.runId || 0) === Number(run.runId || 0));
        if (!refreshedDomains.length) throw new Error(`Hourly report contains no completed domain from enterprise run #${run.runId}.`);
        const deliveryStatus = success ? status : 'completed_with_warnings';
        const deliveryMessage = success
            ? 'Fresh report and PDF generated successfully.'
            : `The enterprise run ended ${status}, but ${refreshedDomains.length} domain(s) completed and a latest per-domain report and PDF were generated.`;
        const delivery = await notifySunbirdHourlyAutomation({ companyId, report, run, status: deliveryStatus, message: deliveryMessage });
        await pool.query(`UPDATE SunbirdReports SET EmailStatus = 'sent', SentAt = NOW() WHERE ID = ?`, [report.id]);
        await writeSunbirdReportLog({ companyId, reportId: report.id, eventType: 'hourly_pdf_emailed', status: 'success', message: `Hourly PDF emailed to ${delivery.recipients.join(', ')}.`, metadata: { runId: run.runId, snapshotId: run.snapshotId, pdfBytes: delivery.pdfBytes } });
        await updateSunbirdHourlyAutomationState(companyId, { ...state, reportId: report.id, status: deliveryStatus, message: deliveryMessage });
        return { status: deliveryStatus, ...state, reportId: report.id, notificationSent: true, completedWithWarnings: !success };
    } catch (error) {
        const message = `Hourly report finalization failed: ${error.message}`;
        await writeSunbirdReportLog({ companyId, eventType: 'hourly_automation_failed', status: 'failed', message, metadata: { runId: state.runId, snapshotId: state.snapshotId } });
        try { await notifySunbirdHourlyAutomation({ companyId, run, status: 'failed', message }); } catch (_) {}
        await updateSunbirdHourlyAutomationState(companyId, { ...state, status: 'failed', message });
        throw error;
    }
}
async function finalizeSunbirdDailyAutomation({ companyId, run = {}, now = new Date(), pipelineExecutionId = null } = {}) {
    const status = String(run.status || 'failed').toLowerCase();
    if (!run.runId || !['completed', 'completed_with_warnings'].includes(status)) {
        throw new Error(`Enterprise Deep Analysis did not complete successfully (status: ${status}).`);
    }

    const state = {
        runId: Number(run.runId),
        snapshotId: run.snapshotId ? Number(run.snapshotId) : null,
        reportId: null
    };
    let report = null;
    try {
        const settings = await ensureSunbirdReportSettings(companyId, null);
        const sameExecution = Number(settings?.LastHourlyAutomationRunID || 0) === state.runId;
        if (sameExecution && settings?.LastHourlyAutomationReportID) {
            const [rows] = await pool.query(
                `SELECT ID, Payload, EmailStatus FROM SunbirdReports WHERE ID = ? AND CompanyID = ? LIMIT 1`,
                [settings.LastHourlyAutomationReportID, Number(companyId)]
            );
            if (rows[0]) {
                report = {
                    id: Number(rows[0].ID),
                    payload: parseReportJson(rows[0].Payload, {}),
                    emailStatus: rows[0].EmailStatus || 'not-sent'
                };
                state.reportId = report.id;
                if (['completed', 'completed_with_warnings'].includes(String(settings.LastHourlyAutomationStatus || '').toLowerCase())) {
                    return { status: 'duplicate', ...state, reportId: report.id, notificationSent: report.emailStatus === 'sent' };
                }
            }
        }

        if (!report) {
            report = await saveSunbirdReport(
                companyId,
                'daily',
                new Date(new Date(now).getTime() - 24 * 60 * 60 * 1000),
                now,
                null,
                true,
                { enterpriseRunId: state.runId, publishCurrent: true }
            );
            state.reportId = Number(report.id);
            await updateSunbirdHourlyAutomationState(companyId, {
                ...state,
                status: 'report_validation_pending',
                message: 'The daily report was persisted and is being verified against the completed enterprise run.'
            });
        }

        const domainManifest = Array.isArray(report.payload?.enterpriseRunManifest)
            ? report.payload.enterpriseRunManifest
            : [];
        const refreshedDomains = domainManifest.filter(domain => Number(domain?.runId || 0) === state.runId);
        if (!refreshedDomains.length) {
            throw new Error(`Daily report contains no completed domain from enterprise run #${state.runId}.`);
        }
        await updateSunbirdHourlyAutomationState(companyId, {
            ...state,
            status: 'report_persisted',
            message: 'Enterprise Deep Analysis completed and the daily dashboard report was persisted.'
        });

        const localWeekday = new Intl.DateTimeFormat('en-US', {
            timeZone: SUNBIRD_REPORT_TIME_ZONE,
            weekday: 'short'
        }).format(new Date(now));
        let notificationSent = report.emailStatus === 'sent';
        if (localWeekday === 'Fri' && !notificationSent) {
            const delivery = await notifySunbirdHourlyAutomation({
                companyId,
                report,
                run,
                status,
                message: 'The weekly StackCTRL enterprise report completed successfully.',
                cadence: 'weekly'
            });
            await pool.query(`UPDATE SunbirdReports SET EmailStatus = 'sent', SentAt = NOW() WHERE ID = ?`, [report.id]);
            notificationSent = true;
            await writeSunbirdReportLog({
                companyId,
                reportId: report.id,
                eventType: 'weekly_enterprise_pdf_emailed',
                status: 'success',
                message: `Weekly PDF emailed to ${delivery.recipients.join(', ')}.`,
                metadata: {
                    runId: state.runId,
                    snapshotId: state.snapshotId,
                    pipelineExecutionId,
                    pdfBytes: delivery.pdfBytes
                }
            });
        }

        const completionMessage = notificationSent
            ? 'Enterprise Deep Reporting completed; the daily report was persisted and the Friday email was sent.'
            : 'Enterprise Deep Reporting completed; the daily report was persisted. Weekly email remains scheduled for Friday.';
        await updateSunbirdHourlyAutomationState(companyId, {
            ...state,
            status,
            message: completionMessage
        });
        await writeSunbirdReportLog({
            companyId,
            reportId: report.id,
            eventType: 'daily_enterprise_pipeline_completed',
            status: 'success',
            message: completionMessage,
            metadata: {
                runId: state.runId,
                snapshotId: state.snapshotId,
                pipelineExecutionId,
                notificationSent
            }
        });
        return { status, ...state, reportId: report.id, notificationSent };
    } catch (error) {
        const message = `Daily enterprise report finalization failed: ${error.message}`;
        await writeSunbirdReportLog({
            companyId,
            reportId: state.reportId,
            eventType: 'daily_enterprise_pipeline_failed',
            status: 'failed',
            message,
            metadata: {
                runId: state.runId,
                snapshotId: state.snapshotId,
                pipelineExecutionId,
                failureStage: 'REPORT_PERSISTENCE_FAILED'
            }
        });
        await updateSunbirdHourlyAutomationState(companyId, { ...state, status: 'failed', message });
        error.enterprisePipelineFailure = {
            failureStage: 'REPORT_PERSISTENCE_FAILED',
            enterpriseId: Number(companyId),
            snapshotId: state.snapshotId,
            analysisExecutionId: state.runId,
            pipelineExecutionId,
            timestamp: new Date().toISOString(),
            error: message
        };
        throw error;
    }
}
function formatReportDate(value, includeTime = false) {
    if (!value) return 'Not available';
    return new Intl.DateTimeFormat('en-ZA', {
        timeZone: SUNBIRD_REPORT_TIME_ZONE,
        dateStyle: 'medium',
        ...(includeTime ? { timeStyle: 'short' } : {})
    }).format(new Date(value));
}

function generateSunbirdReportPdf(report, reportId = null) {
    return new Promise((resolve, reject) => {
        try {
            const doc = new PDFDocument({
                size: 'A4',
                margin: 40,
                bufferPages: true,
                info: { Title: 'Security Assessment Report', Author: 'StackOps IT Solutions' },
                compression: true
            });
            const chunks = [];
            doc.on('data', chunk => chunks.push(chunk));
            doc.on('end', () => resolve(Buffer.concat(chunks)));
            doc.on('error', reject);

            const orange = '#f97316';
            const navy = '#17212b';
            const slate = '#52606d';
            const pale = '#f3f5f7';
            const green = '#16a34a';
            const red = '#dc2626';
            const pageWidth = doc.page.width;
            const pageHeight = doc.page.height;
            const left = 40;
            const contentWidth = pageWidth - 80;
            const bottom = pageHeight - 54;
            const sunbirdLogo = path.join(__dirname, 'Images', 'Sunbird.png');
            const stackCtrlLogo = path.join(__dirname, 'Images', 'Logos', 'Ctrl big.png');
            const analysis = report.analysis || buildDeterministicReportAnalysis(report);

            const cleanText = (value, fallback = '') => {
                if (value == null) return fallback;
                if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value).replace(/\s+/g, ' ').trim() || fallback;
                if (Array.isArray(value)) return value.map(item => cleanText(item)).filter(Boolean).join('; ') || fallback;
                const selected = value.title || value.name || value.displayName || value.summary || value.detail || value.description || value.message || value.findings || value.value || value.email || value.userPrincipalName || value.id;
                return cleanText(selected, fallback);
            };
            const isSuppressedFailedStatus = value => /^(failed|failure)$/i.test(cleanText(value));
            const displayStatus = value => {
                const normalized = cleanText(value);
                if (!normalized) return '';
                return isSuppressedFailedStatus(normalized) ? '' : normalized;
            };
            const recordText = value => {
                if (value == null) return '';
                if (typeof value !== 'object' || Array.isArray(value)) return cleanText(value);

                const pick = (...keys) => {
                    for (const k of keys) {
                        if (k in value && value[k] != null) return value[k];
                        const found = Object.keys(value).find(f => String(f).toLowerCase() === String(k).toLowerCase());
                        if (found && value[found] != null) return value[found];
                    }
                    return null;
                };

                const user = pick('displayName', 'entityName', 'entityDisplayName', 'name', 'user', 'userPrincipalName', 'userPrincipal', 'entityEmail', 'userEmail', 'email', 'emailAddress', 'mail', 'username');
                const device = pick('deviceName', 'device', 'assetName', 'computerName', 'hostname', 'deviceId', 'asset');
                const finding = pick('title', 'finding', 'risk', 'description', 'detail', 'message', 'summary', 'findingTitle');
                const status = pick('status', 'state', 'severity', 'complianceState', 'compliant');
                const evidenceField = pick('evidenceSummary', 'evidence', 'evidenceItems', 'source', 'sourceMetric', 'sourceName', 'sourceId');
                const valueField = pick('value', 'count', 'metricValue', 'score');
                const roles = pick('roles', 'roleNames', 'role');
                const mfa = pick('mfaEnabled', 'mfa', 'multiFactorEnabled');
                const riskLevel = pick('riskLevel', 'riskState');
                const lastSignIn = pick('lastSignIn', 'lastSignInDateTime', 'signInActivity');
                const signInText = lastSignIn && typeof lastSignIn === 'object'
                    ? [lastSignIn.dateTime, lastSignIn.lastSignInDateTime, lastSignIn.location, lastSignIn.device, lastSignIn.status].filter(Boolean).join(', ')
                    : lastSignIn;

                const fields = [
                    ['User', user],
                    ['Device', device],
                    ['Roles', roles],
                    ['MFA', mfa],
                    ['Risk', riskLevel],
                    ['Last sign-in', signInText],
                    ['Finding', finding],
                    ['Status', displayStatus(status)],
                    ['Evidence', evidenceField],
                    ['Value', valueField]
                ].filter(([, field]) => field != null && cleanText(field));

                const text = fields.map(([label, field]) => `${label}: ${cleanText(field)}`).join(' | ');
                if (text) return text;

                // Try nested objects (e.g. { user: { email: ... } } or { device: { name: ... } })
                if (value.user && typeof value.user === 'object') {
                    const nested = recordText(value.user);
                    if (nested) return nested;
                }
                if (value.device && typeof value.device === 'object') {
                    const nestedDev = recordText(value.device);
                    if (nestedDev) return nestedDev;
                }

                return Object.entries(value)
                    .filter(([, field]) => field != null && (typeof field === 'string' || typeof field === 'number' || typeof field === 'boolean'))
                    .slice(0, 12)
                    .map(([key, field]) => `${key.replace(/([A-Z])/g, ' $1')}: ${cleanText(field)}`)
                    .join(' | ') || cleanText(value);
            };
            const asItems = (output, keys, limit = 1000) => {
                const items = [];
                keys.forEach(key => {
                    const value = output?.[key];
                    if (Array.isArray(value)) items.push(...value);
                    else if (value != null) items.push(value);
                });
                return items.map(item => recordText(item)).filter(Boolean).filter((item, index, all) => all.indexOf(item) === index).slice(0, limit);
            };
            const riskForDomain = domain => {
                const output = domain.intelligenceOutput || domain.output || {};
                const score = output.riskScore ?? output.authoritativeScores?.riskScore ?? output.scoreSummary?.riskScore ?? domain.riskScore;
                return Number.isFinite(Number(score)) ? clampReportScore(score) : null;
            };
            const tableItemsForDomain = (domain, tableNames) => {
                const tables = report.domainInsights?.tables || {};
                return tableNames.flatMap(tableName => Array.isArray(tables[tableName]) ? tables[tableName] : [])
                    .filter(row => String(row.domainKey || row.DomainKey || '').toLowerCase() === String(domain.domainKey || '').toLowerCase())
                    .map(row => recordText(row))
                    .filter(Boolean);
            };
            const uniqueItems = (...groups) => Array.from(new Set(groups.flat().filter(Boolean)));
            const scoreForDomain = domain => {
                const output = domain.intelligenceOutput || domain.output || {};
                const score = output.healthScore ?? output.authoritativeScores?.healthScore ?? output.score ?? output.scoreSummary?.healthScore ?? domain.healthScore ?? domain.score;
                return Number.isFinite(Number(score)) ? clampReportScore(score) : null;
            };
            const labelForDomain = domain => domain.domainName || String(domain.domainKey || 'Domain').replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
            const addPageIfNeeded = height => {
                if (doc.y + height > bottom) {
                    doc.addPage();
                    doc.y = 42;
                }
            };
            const sectionTitle = title => {
                addPageIfNeeded(42);
                doc.font('Helvetica-Bold').fontSize(11).fillColor(navy).text(String(title).toUpperCase(), left, doc.y, { width: contentWidth });
                doc.moveTo(left, doc.y + 4).lineTo(pageWidth - left, doc.y + 4).strokeColor('#d9dee3').lineWidth(0.8).stroke();
                doc.y += 12;
            };
            const drawMetric = (x, y, width, label, value, detail) => {
                doc.roundedRect(x, y, width, 64, 7).fill('#f8fafc').strokeColor('#e1e6ea').lineWidth(0.8).stroke();
                doc.font('Helvetica-Bold').fontSize(8).fillColor(navy).text(label, x + 10, y + 9, { width: width - 20, height: 10 });
                doc.font('Helvetica-Bold').fontSize(19).fillColor(orange).text(String(value), x + 10, y + 23, { width: width - 20, height: 23 });
                doc.font('Helvetica').fontSize(7.3).fillColor(slate).text(detail, x + 10, y + 49, { width: width - 20, height: 10 });
            };
            const drawBar = (x, y, width, score) => {
                const tone = score >= 85 ? green : score >= 70 ? orange : red;
                doc.roundedRect(x, y, width, 7, 3.5).fill('#e1e6ea');
                doc.roundedRect(x, y, Math.max(3, width * score / 100), 7, 3.5).fill(tone);
            };
            const drawList = (title, items, x, y, width, maxRows = 3) => {
                doc.font('Helvetica-Bold').fontSize(7.8).fillColor(orange).text(title, x, y, { width, height: 10 });
                let rowY = y + 12;
                const rows = items.slice(0, maxRows);
                if (!rows.length) {
                    doc.font('Helvetica').fontSize(7.2).fillColor(slate).text('No stored entries.', x, rowY, { width, height: 18 });
                    return rowY + 20;
                }
                rows.forEach(item => {
                    doc.circle(x + 2, rowY + 4, 1.5).fillColor(navy).fill();
                    doc.font('Helvetica').fontSize(7.2).fillColor(slate).text(shortText(item, 125), x + 8, rowY, { width: width - 8, height: 18, lineGap: 1 });
                    rowY += 19;
                });
                return rowY;
            };
            const drawEvidenceTable = (rows, x, y, width, maxRows = 5) => {
                const safeRows = rows.slice(0, maxRows);
                doc.font('Helvetica-Bold').fontSize(7.8).fillColor(orange).text('Evidence and affected entities', x, y, { width, height: 10 });
                let rowY = y + 12;
                if (!safeRows.length) {
                    doc.font('Helvetica').fontSize(7.2).fillColor(slate).text('No stored evidence rows for this domain.', x, rowY, { width, height: 16 });
                    return rowY + 18;
                }
                safeRows.forEach((row, index) => {
                    const fill = index % 2 ? '#ffffff' : '#f3f5f7';
                    doc.rect(x, rowY, width, 18).fill(fill);
                    doc.font('Helvetica').fontSize(7.1).fillColor(slate).text(shortText(row, 180), x + 7, rowY + 4, { width: width - 14, height: 10 });
                    rowY += 19;
                });
                return rowY;
            };
            const drawFlowList = (title, items) => {
                if (!items.length) return;
                addPageIfNeeded(24);
                doc.font('Helvetica-Bold').fontSize(8.5).fillColor(orange).text(title, left + 12, doc.y, { width: contentWidth - 24 });
                doc.y += 12;
                items.forEach((item, index) => {
                    doc.font('Helvetica').fontSize(7.8);
                    const rowHeight = Math.max(20, doc.heightOfString(item, { width: contentWidth - 42, lineGap: 1 }) + 7);
                    addPageIfNeeded(rowHeight + 3);
                    const rowY = doc.y;
                    if (index % 2 === 0) doc.rect(left + 8, rowY - 2, contentWidth - 16, rowHeight).fill('#f8fafc');
                    doc.circle(left + 16, rowY + 5, 1.5).fillColor(navy).fill();
                    doc.font('Helvetica').fontSize(7.8).fillColor(slate).text(item, left + 24, rowY, { width: contentWidth - 36, lineGap: 1 });
                    doc.y = rowY + rowHeight + 1;
                });
                doc.y += 4;
            };
            // Classify free-form AI content by reporting concepts, not by a fixed prompt schema.
            const executiveSectionDefinitions = [
                ['summary', 'Executive Summary', /\b(executive|overall|enterprise|posture|organisation|organization)\b/i],
                ['risks', 'Key Risks', /\b(risk|threat|exposure|critical|severity|vulnerabilit|concern)\b/i],
                ['changes', 'What Changed Since Last Report', /\b(change|shift|movement|delta|since|previous|last\s+(?:report|period|review)|evidence\s+shift)\b/i],
                ['trend', 'Historical Trend', /\b(histor|baseline|trend|trajectory|over\s+time|compared\s+with)\b/i],
                ['gaps', 'Open Control Gaps', /\b(control|compliance|governance|security)\b[\s\S]{0,70}\b(gap|open|missing|deficien|remediat)\b|\b(gap|deficien|unresolved|outstanding)\b/i],
                ['actions', 'Priority Remediation Actions', /\b(action|priority|remediat|mitigat|next\s+step|immediate|enable|disable|retire|investigat|assign|review)\b/i],
                ['recommendation', 'Executive Recommendation', /\b(recommend|decision|should|advise|propose|endorse)\b/i],
                ['impact', 'Business Impact', /\b(business|operational|financial|customer)\s+impact\b/i]
            ].map(([id, title, cue]) => ({ id, title, cue }));
            const executiveSectionFor = (text, fallback = 'summary') => executiveSectionDefinitions.filter(section => section.id !== 'summary').find(section => section.cue.test(cleanText(text)))?.id || fallback;
            const executiveMetricLabel = label => {
                const key = String(label || '').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').toLowerCase();
                if (/\b(confidence|certainty|assurance)\b/.test(key)) return 'Confidence';
                if (/\b(audit|assessment|compliance)\b.*\b(readiness|ready|prepared)\b/.test(key)) return 'Audit Readiness';
                if (/\b(overall|enterprise|organisation|organization)\b.*\brisk\b|\brisk\b.*\b(overall|enterprise)\b/.test(key)) return 'Overall Risk';
                if (/\b(domain|area|scope)\b.*\b(count|analysed|analyzed|assessed|reviewed)\b/.test(key)) return 'Domains Analysed';
                if (/\b(operation|service|platform)\b.*\b(status|state|health|availability)\b/.test(key)) return 'Operations Status';
                return '';
            };
            const buildExecutiveOverview = () => {
                const sections = Object.fromEntries(executiveSectionDefinitions.map(section => [section.id, []]));
                const sectionOrder = executiveSectionDefinitions.map(section => section.id);
                const sectionTitles = new Map(executiveSectionDefinitions.map(section => [section.id, section.title]));
                const addCustomSection = heading => {
                    const title = cleanText(heading).replace(/[_-]+/g, ' ').replace(/\b\w/g, character => character.toUpperCase());
                    const id = `custom-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')}`;
                    if (!sections[id]) {
                        sections[id] = [];
                        sectionOrder.push(id);
                        sectionTitles.set(id, title || 'Additional Executive Detail');
                    }
                    return id;
                };
                const metrics = new Map();
                const addMetric = (label, value) => {
                    const metric = executiveMetricLabel(label);
                    const display = cleanText(value).replace(/[_-]+/g, ' ').replace(/\b\w/g, character => character.toUpperCase());
                    if (!metric || !display || /^(null|undefined|n\/a|not available)$/i.test(display)) return;
                    const levels = metric === 'Confidence'
                        ? display.match(/\b(high|medium|low)\b/i)
                        : metric === 'Overall Risk'
                            ? display.match(/\b(critical|high|moderate|medium|low)\b/i)
                            : metric === 'Audit Readiness'
                                ? display.match(/\b(not ready|currently not met|partially ready|ready)\b/i)
                                : metric === 'Operations Status'
                                    ? display.match(/\b(enabled|disabled|healthy|degraded|operational|unavailable)\b/i)
                                    : null;
                    const compact = levels?.[1] || (metric === 'Domains Analysed' ? display.match(/\d+/)?.[0] : '') || display.slice(0, 56).replace(/\s+\S*$/, '').trim();
                    if (compact) metrics.set(metric, compact);
                };
                const addText = (section, value) => {
                    const text = cleanText(value);
                    if (!text || /^((no|not)\s+(stored|available)|n\/a)$/i.test(text)) return;
                    const key = section in sections ? section : executiveSectionFor(text);
                    if (!sections[key].some(item => item.toLowerCase() === text.toLowerCase())) sections[key].push(text);
                };
                const readNarrative = (value, fallback = 'summary') => {
                    const source = cleanText(value);
                    if (!source) return;
                    const lines = String(value).replace(/\r/g, '').split(/\n+/).map(line => line.trim()).filter(Boolean);
                    let active = fallback;
                    for (let index = 0; index < lines.length; index += 1) {
                        const line = lines[index];
                        const labelled = line.match(/^([^:]{2,80}):\s*(.*)$/);
                        if (labelled && executiveMetricLabel(labelled[1])) {
                            const metricValue = labelled[2] || lines[++index];
                            addMetric(labelled[1], metricValue);
                            // Preserve explanatory metric detail in the narrative while keeping the status table compact.
                            if (cleanText(metricValue).length > 70) addText('summary', `${labelled[1]}: ${metricValue}`);
                            continue;
                        }
                        if (labelled && !executiveSectionFor(labelled[1], null)) {
                            active = addCustomSection(labelled[1]);
                            if (labelled[2]) addText(active, labelled[2]);
                            continue;
                        }
                        if (labelled && !labelled[2]) {
                            active = executiveSectionFor(labelled[1], active);
                            continue;
                        }
                        line.split(/(?<=[.!?])\s+(?=[A-Z0-9])/).map(sentence => sentence.trim()).filter(Boolean)
                            .forEach(sentence => addText(executiveSectionFor(sentence, active), sentence));
                    }
                    [
                        ['Overall Risk', /\b(?:overall|enterprise)\s+risk\s*(?:is|:|=)?\s*([^.;\n]{1,45})/i],
                        ['Audit Readiness', /\baudit\s+(?:readiness|status)\s*(?:is|:|=)?\s*([^.;\n]{1,45})/i],
                        ['Confidence', /\bconfidence\s*(?:is|:|=)?\s*([^.;\n]{1,45})/i],
                        ['Domains Analysed', /\b(\d+)\s+domains?\s+(?:analysed|analyzed|assessed|reviewed)\b/i],
                        ['Operations Status', /\boperations?\s+(?:status\s+)?(?:is|:|=)\s*([^.;\n]{1,45})/i]
                    ].forEach(([label, pattern]) => {
                        const match = source.match(pattern);
                        if (match?.[1]) addMetric(label, match[1]);
                    });
                };
                const readMetrics = (value, depth = 0, label = '') => {
                    if (value == null || depth > 4) return;
                    if (typeof value !== 'object') return addMetric(label, value);
                    if (!Array.isArray(value)) Object.entries(value).forEach(([key, nested]) => readMetrics(nested, depth + 1, `${label} ${key}`.trim()));
                };
                const addItems = (value, section) => (Array.isArray(value) ? value : value == null ? [] : [value]).map(recordText).filter(Boolean).forEach(item => addText(section, item));
                const itemText = (item, fields = []) => {
                    if (typeof item === 'string' || typeof item === 'number') return cleanText(item);
                    if (!item || typeof item !== 'object') return '';
                    for (const field of fields) {
                        const value = cleanText(item[field]);
                        if (value) return value;
                    }
                    return '';
                };
                const isPlaceholder = value => /^(?:finding:\s*)?(?:\d+[.)]?|n\/a|null|undefined)$/i.test(cleanText(value));
                const addStructuredItems = (value, section, fields = []) => {
                    const items = Array.isArray(value) ? value : value == null ? [] : [value];
                    items.map(item => itemText(item, fields)).filter(item => item && !isPlaceholder(item)).forEach(item => addText(section, item));
                };
                const addNarrativeSentences = (value, section) => String(value || '')
                    .split(/\r?\n+|(?<=[.!?])\s+(?=[A-Z0-9])/)
                    .map(sentence => cleanText(sentence))
                    .filter(sentence => sentence && !isPlaceholder(sentence))
                    .forEach(sentence => addText(section, sentence));
                const finalOutput = report.finalSynthesis?.finalSynthesis?.synthesisOutput || report.finalSynthesis?.synthesisOutput || {};
                const executive = finalOutput.enterpriseExecutiveSummary || {};
                const historical = analysis.historicalChanges || {};
                const hasFinalSynthesis = Object.keys(finalOutput).length > 0;

                if (hasFinalSynthesis) {
                    // These sections are intentionally sourced from the stored Azure
                    // synthesis. Raw evidence stays in the dedicated evidence/domain pages.
                    addText('summary', executive.summary);
                    addText('impact', finalOutput.businessImpactSummary);
                    addStructuredItems(finalOutput.riskRegister, 'risks', ['title', 'whatHappened', 'description', 'detail']);
                    const prioritisedActions = Array.isArray(finalOutput.recommendations) && finalOutput.recommendations.length
                        ? finalOutput.recommendations
                        : [
                            ...(Array.isArray(finalOutput.managementReport?.whatMustBeDoneNow) ? finalOutput.managementReport.whatMustBeDoneNow : []),
                            ...(Array.isArray(finalOutput.managementReport?.managementActions) ? finalOutput.managementReport.managementActions : []),
                            ...(Array.isArray(finalOutput.managementReport?.actions) ? finalOutput.managementReport.actions : []),
                            ...(Array.isArray(finalOutput.boardReport?.boardActions) ? finalOutput.boardReport.boardActions : [])
                        ];
                    addStructuredItems(prioritisedActions, 'actions', ['recommendedAction', 'recommendation', 'detail', 'title']);
                    addText('recommendation', finalOutput.boardReport?.messageToBoard || finalOutput.boardReport?.boardSummary);
                    addMetric('overall risk', executive.overallPosture || finalOutput.boardReport?.riskLevel);
                    addMetric('audit readiness', finalOutput.complianceReview?.auditReadinessStatus);
                    addMetric('confidence', executive.confidence || finalOutput.evidenceJustificationSummary?.evidenceConfidence);
                    addMetric('domains analysed', Array.isArray(executive.activeDomainsUsed) ? executive.activeDomainsUsed.length : '');
                    addMetric('operations status', Array.isArray(executive.knownLimitations) ? executive.knownLimitations.join(' ') : executive.knownLimitations);
                } else {
                    // A graceful fallback is used only when no completed synthesis exists.
                    addText('summary', analysis.executiveSummary);
                    addText('recommendation', analysis.boardReportSummary);
                    addText('impact', analysis.businessImpactSummary);
                    addStructuredItems(analysis.failures || report.failures, 'risks', ['title', 'description', 'detail']);
                    addStructuredItems(analysis.recommendations || report.recommendations, 'actions', ['recommendedAction', 'recommendation', 'detail', 'title']);
                }

                addNarrativeSentences(historical.whatChangedSinceLastReport, 'changes');
                addNarrativeSentences(historical.historicalTrendAnalysis, 'trend');
                addNarrativeSentences(historical.controlGapsAndRemediationProgress, 'gaps');
                addStructuredItems(historical.whatRemainsOpen, 'gaps');
                readMetrics(report.riskEngine || report.summary || {});
                if (!metrics.has('Domains Analysed') && Array.isArray(report.domainInsights?.domains) && report.domainInsights.domains.length) addMetric('domains analysed', report.domainInsights.domains.length);
                return { sections, sectionOrder, sectionTitles, metrics: [...metrics].map(([label, value]) => ({ label, value })) };
            };
            const executiveListParts = value => {
                const text = cleanText(value).replace(/^[\s\u2022\-*\d.)]+/, '').trim();
                const tidy = item => item.replace(/^\s*(?:and\s+)?/, '').replace(/[.;]+$/, '').trim();
                const semicolon = text.split(/\s*;\s*/).map(tidy).filter(Boolean);
                if (semicolon.length > 1) {
                    const intro = semicolon[0].match(/^(.{3,70}?(?:include|includes|are|is|for|of|:))\s*(.+)$/i);
                    return intro ? { lead: tidy(intro[1]), items: [tidy(intro[2]), ...semicolon.slice(1)] } : { lead: '', items: semicolon };
                }
                const ownership = text.match(/^(.{3,100}?\b(?:for|of|across|to)\s+)([^.]+)$/i);
                if (ownership) {
                    const items = ownership[2].split(/\s*,\s*|\s+and\s+/i).map(tidy).filter(Boolean);
                    if (items.length >= 3) return { lead: ownership[1].trim(), items };
                }
                const comma = text.split(/\s*,\s*/).map(tidy).filter(Boolean);
                const action = /^(?:enable|disable|retire|remove|remediate|investigate|assign|review|validate|implement|configure|document|establish|monitor|restrict|require|update|close|resolve|assess|confirm|prioritise|prioritize)\b/i;
                return comma.length >= 3 && comma.filter(item => action.test(item)).length >= Math.ceil(comma.length * 0.66) ? { lead: '', items: comma } : null;
            };
            const drawExecutiveOverview = overview => {
                const wrap = (text, width, size) => {
                    const lines = [];
                    let line = '';
                    doc.font('Helvetica').fontSize(size);
                    cleanText(text).split(/\s+/).filter(Boolean).forEach(word => {
                        const candidate = line ? `${line} ${word}` : word;
                        if (line && doc.widthOfString(candidate) > width) {
                            lines.push(line);
                            line = word;
                        } else line = candidate;
                    });
                    if (line) lines.push(line);
                    return lines;
                };
                const drawHeader = (title, continued, bodyHeight) => {
                    if (doc.y + 31 + bodyHeight > bottom) {
                        doc.addPage();
                        doc.y = 42;
                    }
                    const y = doc.y;
                    doc.roundedRect(left, y, contentWidth, 22, 6).fill('#f3f5f7');
                    doc.font('Helvetica-Bold').fontSize(9.7).fillColor(navy).text(`${title}${continued ? ' (continued)' : ''}`, left + 12, y + 6, { width: contentWidth - 24, lineBreak: false });
                    doc.moveTo(left + 12, y + 27).lineTo(pageWidth - left - 12, y + 27).strokeColor('#d9dee3').lineWidth(0.7).stroke();
                    doc.y = y + 34;
                };
                const drawItem = (title, text, state, marker = '') => {
                    const width = marker ? contentWidth - 50 : contentWidth - 28;
                    const size = marker ? 8.8 : 9;
                    const lines = wrap(text, width, size);
                    while (lines.length) {
                        const chunk = lines.splice(0, marker ? 6 : 7);
                        const height = doc.font('Helvetica').fontSize(size).heightOfString(chunk.join('\n'), { width, lineGap: 2 }) + 3;
                        if (!state.started || doc.y + height > bottom) {
                            drawHeader(title, state.started, height);
                            state.started = true;
                        }
                        if (marker === 'bullet') doc.circle(left + 20, doc.y + 5, 1.8).fillColor(orange).fill();
                        else if (marker) doc.font('Helvetica-Bold').fontSize(8.6).fillColor(navy).text(marker, left + 14, doc.y, { width: 18 });
                        const itemY = doc.y;
                        doc.font('Helvetica').fontSize(size).fillColor(slate).text(chunk.join('\n'), left + (marker ? 30 : 14), itemY, { width, lineGap: 2 });
                        doc.y = itemY + height + 4;
                        marker = marker ? 'bullet' : '';
                    }
                };
                if (overview.metrics.length) {
                    const labelWidth = contentWidth * 0.35;
                    const valueX = left + labelWidth + 18;
                    const valueWidth = contentWidth - labelWidth - 30;
                    const metricRows = overview.metrics.map(metric => {
                        const labelHeight = doc.font('Helvetica-Bold').fontSize(8.4).heightOfString(metric.label, { width: labelWidth - 12, lineGap: 1 });
                        const valueHeight = doc.font('Helvetica').fontSize(8.4).heightOfString(metric.value, { width: valueWidth, lineGap: 1 });
                        return { ...metric, height: Math.max(19, labelHeight + 10, valueHeight + 10) };
                    });
                    const tableHeight = 28 + metricRows.reduce((total, row) => total + row.height, 0);
                    if (doc.y + tableHeight > bottom) {
                        doc.addPage();
                        doc.y = 42;
                    }
                    const y = doc.y;
                    doc.roundedRect(left, y, contentWidth, 20, 6).fill(navy);
                    doc.font('Helvetica-Bold').fontSize(9.5).fillColor('#ffffff').text('Enterprise Status', left + 12, y + 6, { width: contentWidth - 24, lineBreak: false });
                    let rowY = y + 20;
                    metricRows.forEach((metric, index) => {
                        if (index % 2 === 0) doc.rect(left, rowY, contentWidth, metric.height).fill('#f8fafc');
                        doc.font('Helvetica-Bold').fontSize(8.4).fillColor(navy).text(metric.label, left + 12, rowY + 5, { width: labelWidth - 12, lineGap: 1 });
                        doc.font('Helvetica').fontSize(8.4).fillColor(slate).text(metric.value, valueX, rowY + 5, { width: valueWidth, lineGap: 1 });
                        rowY += metric.height;
                    });
                    doc.roundedRect(left, y, contentWidth, tableHeight - 8, 6).strokeColor('#e1e6ea').lineWidth(0.7).stroke();
                    doc.y = y + tableHeight + 8;
                }
                overview.sectionOrder.forEach(sectionId => {
                    const values = overview.sections[sectionId];
                    if (!values.length) return;
                    const title = overview.sectionTitles.get(sectionId);
                    const state = { started: false };
                    let number = 1;
                    values.forEach(value => {
                        const list = executiveListParts(value);
                        if (!list) {
                            const marker = sectionId === 'actions' ? `${number++}.` : sectionId === 'summary' || sectionId === 'recommendation' || sectionId === 'impact' ? '' : 'bullet';
                            return drawItem(title, value, state, marker);
                        }
                        if (list.lead) {
                            if (!state.started || doc.y + 18 > bottom) {
                                drawHeader(title, state.started, 18);
                                state.started = true;
                            }
                            const leadY = doc.y;
                            const leadHeight = doc.font('Helvetica-Bold').fontSize(8.9).heightOfString(list.lead, { width: contentWidth - 28, lineGap: 2 });
                            doc.text(list.lead, left + 14, leadY, { width: contentWidth - 28, lineGap: 2 });
                            doc.y = leadY + leadHeight + 3;
                        }
                        list.items.forEach(item => drawItem(title, item, state, sectionId === 'actions' ? `${number++}.` : 'bullet'));
                    });
                    doc.y += 8;
                });
            };
            const isIdentityDomain = domain => String(domain?.domainKey || domain?.domainName || '').trim().toLowerCase() === 'identity' || /identity protection/i.test(String(domain?.domainName || ''));
            const renderIdentityProtectionReport = domain => {
                if (!domain) return;

                const output = buildSunbirdReportIdentityDomain(domain).intelligenceOutput;
                const healthScore = clampReportScore(output.healthScore ?? 0);
                const riskScore = clampReportScore(output.riskScore ?? 0);
                const riskLevel = cleanText(output.riskLevel || 'Unrated');
                const summary = cleanText(
                    output.domainExecutiveSummary,
                    'Latest Azure identity evidence is summarized below.'
                );
                const severityColor = severity => {
                    const normalized = String(severity || '').toLowerCase();
                    if (/critical|high|severe/.test(normalized)) return red;
                    if (/moderate|medium|warn/.test(normalized)) return orange;
                    if (/low|safe|healthy|good/.test(normalized)) return green;
                    return '#2563eb';
                };
                const identitySectionTitle = (title, tone = navy) => {
                    addPageIfNeeded(34);
                    doc.font('Helvetica').fontSize(10.5).fillColor(tone).text(title.toUpperCase(), left, doc.y, { width: contentWidth });
                    doc.moveTo(left, doc.y + 4).lineTo(pageWidth - left, doc.y + 4).strokeColor('#d9dee3').lineWidth(0.8).stroke();
                    doc.y += 12;
                };
                const drawIdentityMetric = (x, y, width, label, value, detail, tone) => {
                    doc.roundedRect(x, y, width, 62, 7).fill('#f8fafc').strokeColor('#e1e6ea').lineWidth(0.8).stroke();
                    doc.font('Helvetica').fontSize(7.4).fillColor(slate).text(label, x + 10, y + 10, { width: width - 20, height: 10 });
                    doc.font('Helvetica').fontSize(18).fillColor(tone).text(String(value), x + 10, y + 23, { width: width - 20, height: 21 });
                    doc.font('Helvetica').fontSize(7.1).fillColor(slate).text(detail, x + 10, y + 48, { width: width - 20, height: 9 });
                };
                const drawIdentityText = (title, text, tone = navy) => {
                    if (!text) return;
                    const bodyHeight = doc.font('Helvetica').fontSize(8).heightOfString(text, { width: contentWidth - 24, lineGap: 2 });
                    addPageIfNeeded(bodyHeight + 38);
                    identitySectionTitle(title, tone);
                    doc.font('Helvetica').fontSize(8).fillColor(slate).text(text, left + 12, doc.y, { width: contentWidth - 24, lineGap: 2 });
                    doc.y += bodyHeight + 10;
                };
                const splitRecommendationPoints = action => {
                    const normalized = cleanText(action);
                    if (!normalized) return [];
                    return normalized
                        .split(/(?:;|\.(?=\s+[A-Z])|,\s+(?=(?:and\s+)?(?:review|remove|require|restrict|validate|document|investigate|confirm|assign|disable|enable)\b))/i)
                        .map(point => point.replace(/^and\s+/i, '').trim().replace(/[.]+$/, ''))
                        .filter(Boolean);
                };
                const formatIdentityEvidence = entity => {
                    const identity = cleanText(entity.entityName || entity.displayName || entity.entityDisplayName || entity.userPrincipalName || entity.mail || entity.entityEmail, 'Unnamed account');
                    const email = cleanText(entity.entityEmail || entity.mail || entity.userPrincipalName || entity.entityUser);
                    const roles = (Array.isArray(entity.roles) ? entity.roles : []).map(role => cleanText(typeof role === 'object' ? role.name || role.displayName : role)).filter(Boolean);
                    const lastSignIn = entity.lastSignIn && typeof entity.lastSignIn === 'object' ? entity.lastSignIn : {};
                    const posture = [
                        entity.mfaEnabled == null ? '' : entity.mfaEnabled ? 'MFA enabled' : 'MFA not enabled',
                        entity.riskLevel ? `Risk ${cleanText(entity.riskLevel)}` : '',
                        roles.length ? roles.join(', ') : '',
                        lastSignIn.daysSince == null || lastSignIn.daysSince === '' ? '' : `${lastSignIn.daysSince} days since sign-in`
                    ].filter(Boolean).join(' | ');
                    const signIn = [lastSignIn.location, lastSignIn.device, displayStatus(lastSignIn.status)].map(value => cleanText(value)).filter(Boolean).join(' | ');
                    return { identity, email, posture, signIn };
                };
                const drawFindingEvidence = entities => {
                    if (!entities.length) {
                        doc.font('Helvetica').fontSize(7.4).fillColor(slate).text('No supporting account details were returned with this finding.', left + 30, doc.y, { width: contentWidth - 42 });
                        doc.y += 16;
                        return;
                    }
                    entities.forEach((entity, index) => {
                        const evidence = formatIdentityEvidence(entity);
                        const detail = [evidence.email, evidence.posture, evidence.signIn].filter(Boolean).join('\n');
                        const titleHeight = doc.font('Helvetica-Bold').fontSize(7.8).heightOfString(evidence.identity, { width: contentWidth - 56 });
                        const detailHeight = detail ? doc.font('Helvetica').fontSize(7.2).heightOfString(detail, { width: contentWidth - 56, lineGap: 1 }) : 0;
                        const rowHeight = Math.max(23, titleHeight + detailHeight + 11);
                        addPageIfNeeded(rowHeight + 6);
                        const rowY = doc.y;
                        if (index % 2 === 0) doc.rect(left + 22, rowY - 2, contentWidth - 34, rowHeight).fill('#fbfcfd');
                        doc.circle(left + 31, rowY + 4, 1.4).fillColor('#2563eb').fill();
                        doc.font('Helvetica-Bold').fontSize(7.8).fillColor(navy).text(evidence.identity, left + 38, rowY, { width: contentWidth - 56 });
                        if (detail) doc.font('Helvetica').fontSize(7.2).fillColor(slate).text(detail, left + 38, rowY + titleHeight + 2, { width: contentWidth - 56, lineGap: 1 });
                        doc.y = rowY + rowHeight + 3;
                    });
                };
                const rawFindings = Array.isArray(output.findings) ? output.findings.slice(0, 8) : [];
                const findings = rawFindings.map(item => {
                    const evidenceSource = Array.isArray(item.evidenceRecords) && item.evidenceRecords.length
                        ? item.evidenceRecords
                        : (Array.isArray(item.affectedEntities) && item.affectedEntities.length ? item.affectedEntities : item.evidenceRows);
                    const evidenceByIdentity = new Map();
                    (Array.isArray(evidenceSource) ? evidenceSource : []).forEach(entity => {
                        const identity = String(entity?.entityId || entity?.id || entity?.entityEmail || entity?.mail || entity?.userPrincipalName || entity?.entityName || entity?.displayName || '').toLowerCase();
                        if (identity && !evidenceByIdentity.has(identity)) evidenceByIdentity.set(identity, entity);
                    });
                    const evidenceEntities = Array.from(evidenceByIdentity.values()).slice(0, 10);
                    return {
                        title: cleanText(item.title, 'Identity finding'),
                        severity: cleanText(item.severity, 'Observed'),
                        impact: cleanText(item.impact),
                        detail: cleanText(item.description),
                        rationale: cleanText(item.whyItMatters),
                        evidenceEntities,
                        evidenceRecordCount: Number(item.evidenceRecordCount || evidenceEntities.length),
                        affectedEntities: Array.isArray(item.affectedEntities) ? item.affectedEntities : [],
                        actionPoints: splitRecommendationPoints(item.firstAction || item.recommendation)
                    };
                });
                const affectedByIdentity = new Map();
                findings.flatMap(finding => finding.affectedEntities).forEach(entity => {
                    const identity = String(entity.entityEmail || entity.userPrincipalName || entity.entityName || entity.displayName || '').toLowerCase();
                    if (identity && !affectedByIdentity.has(identity)) affectedByIdentity.set(identity, entity);
                });
                const topAffectedEntities = Array.from(affectedByIdentity.values()).slice(0, 10);

                addPageIfNeeded(120);
                identitySectionTitle('Identity Protection Report', severityColor(riskLevel));
                doc.font('Helvetica').fontSize(8.1).fillColor(slate).text('Current identity security posture', left, doc.y, { width: contentWidth });
                doc.y += 16;

                const metricGap = 12;
                const metricWidth = (contentWidth - metricGap) / 2;
                const metricY = doc.y;
                drawIdentityMetric(left, metricY, metricWidth, 'HEALTH SCORE', `${healthScore}%`, 'Current identity health score', healthScore >= 80 ? green : orange);
                drawIdentityMetric(left + metricWidth + metricGap, metricY, metricWidth, 'RISK SCORE', `${riskScore}%`, `${riskLevel} risk level`, severityColor(riskLevel));
                doc.y = metricY + 76;

                drawIdentityText('Domain summary', summary, severityColor(riskLevel));
                drawIdentityText('Business impact', cleanText(output.businessImpact, 'Business impact is detailed within the current findings below.'), severityColor(riskLevel));

                if (findings.length) {
                    identitySectionTitle(`Key identity findings (${findings.length})`);
                    findings.forEach((finding, index) => {
                        const fields = [
                            ['FINDING', finding.detail],
                            ['SEVERITY', finding.severity],
                            ['IMPACT', finding.impact],
                            ['WHY IT MATTERS', finding.rationale]
                        ].filter(([, value]) => value);
                        const fieldHeight = fields.reduce((height, [, value]) => height + doc.font('Helvetica').fontSize(7.5).heightOfString(value, { width: contentWidth - 48, lineGap: 1 }) + 14, 0);
                        const evidenceHeight = finding.evidenceEntities.reduce((height, entity) => {
                            const evidence = formatIdentityEvidence(entity);
                            const detail = [evidence.email, evidence.posture, evidence.signIn].filter(Boolean).join('\n');
                            return height
                                + doc.font('Helvetica-Bold').fontSize(7.8).heightOfString(evidence.identity, { width: contentWidth - 56 })
                                + (detail ? doc.font('Helvetica').fontSize(7.2).heightOfString(detail, { width: contentWidth - 56, lineGap: 1 }) : 0)
                                + 14;
                        }, 0);
                        const recommendationHeight = finding.actionPoints.reduce((height, point) => height + doc.font('Helvetica').fontSize(7.4).heightOfString(point, { width: contentWidth - 56, lineGap: 1 }) + 8, 0);
                        const blockHeight = 32 + fieldHeight + evidenceHeight + (finding.actionPoints.length ? recommendationHeight + 23 : 0);
                        addPageIfNeeded(Math.min(blockHeight, 220));
                        const blockY = doc.y;
                        if (index % 2 === 0) doc.rect(left, blockY - 3, contentWidth, Math.min(blockHeight, bottom - blockY)).fill('#f8fafc');
                        const tone = severityColor(finding.severity);
                        doc.circle(left + 9, doc.y + 5, 2).fillColor(tone).fill();
                        doc.font('Helvetica-Bold').fontSize(8.5).fillColor(tone).text(finding.title, left + 18, doc.y, { width: contentWidth - 30, lineGap: 1 });
                        doc.y += doc.heightOfString(finding.title, { width: contentWidth - 30, lineGap: 1 }) + 7;
                        fields.forEach(([label, value]) => {
                            addPageIfNeeded(24);
                            doc.font('Helvetica-Bold').fontSize(7.2).fillColor(tone).text(label, left + 18, doc.y, { width: contentWidth - 30 });
                            doc.y += 10;
                            doc.font('Helvetica').fontSize(7.5).fillColor(slate).text(value, left + 18, doc.y, { width: contentWidth - 30, lineGap: 1 });
                            doc.y += doc.heightOfString(value, { width: contentWidth - 30, lineGap: 1 }) + 5;
                        });
                        addPageIfNeeded(22);
                        doc.font('Helvetica-Bold').fontSize(7.2).fillColor(tone).text('EVIDENCE', left + 18, doc.y, { width: contentWidth - 30 });
                        doc.y += 11;
                        drawFindingEvidence(finding.evidenceEntities);
                        const remainingEvidence = Math.max(0, finding.evidenceRecordCount - finding.evidenceEntities.length);
                        if (remainingEvidence) {
                            doc.font('Helvetica').fontSize(7.1).fillColor(slate).text(`${remainingEvidence} additional affected identity record${remainingEvidence === 1 ? '' : 's'} are available in the Identity dashboard.`, left + 38, doc.y, { width: contentWidth - 56 });
                            doc.y += 15;
                        }
                        if (finding.actionPoints.length) {
                            addPageIfNeeded(24);
                            doc.font('Helvetica-Bold').fontSize(7.2).fillColor(green).text('RECOMMENDATIONS', left + 18, doc.y, { width: contentWidth - 30 });
                            doc.y += 11;
                            finding.actionPoints.forEach(point => {
                                const pointHeight = doc.font('Helvetica').fontSize(7.4).heightOfString(point, { width: contentWidth - 56, lineGap: 1 });
                                addPageIfNeeded(pointHeight + 8);
                                doc.circle(left + 25, doc.y + 4, 1.4).fillColor(green).fill();
                                doc.font('Helvetica').fontSize(7.4).fillColor(slate).text(point, left + 32, doc.y, { width: contentWidth - 56, lineGap: 1 });
                                doc.y += pointHeight + 5;
                            });
                        }
                        doc.y += 8;
                    });
                }

                if (topAffectedEntities.length) {
                    identitySectionTitle('Top affected entities');
                    doc.font('Helvetica').fontSize(7.5).fillColor(slate).text('Entities associated with the current identity findings.', left, doc.y, { width: contentWidth });
                    doc.y += 14;
                    drawFindingEvidence(topAffectedEntities);
                }
                doc.y += 4;
            };
            const isDevicesDomain = domain => String(domain?.domainKey || domain?.domainName || '').trim().toLowerCase() === 'devices' || /device protection/i.test(String(domain?.domainName || ''));
            const renderDeviceProtectionReport = domain => {
                if (!domain) return;

                const output = domain.intelligenceOutput || domain.output || {};
                const scores = output.authoritativeScores || output.scoreSummary || {};
                const categories = Array.isArray(output.evidenceCatalog?.categories) ? output.evidenceCatalog.categories : [];
                const healthScore = clampReportScore(scores.healthScore ?? output.healthScore ?? domain.healthScore ?? 0);
                const riskScore = clampReportScore(scores.riskScore ?? output.riskScore ?? domain.riskScore ?? 0);
                const riskLevel = cleanText(scores.riskLevel || output.riskLevel || 'Unrated');
                const deviceTone = value => {
                    const normalized = String(value || '').toLowerCase();
                    if (/critical|high/.test(normalized)) return red;
                    if (/medium|moderate|warning/.test(normalized)) return orange;
                    if (/low|safe|good|compliant/.test(normalized)) return green;
                    return '#2563eb';
                };
                const section = (title, tone = navy) => {
                    addPageIfNeeded(34);
                    doc.font('Helvetica').fontSize(10.5).fillColor(tone).text(title.toUpperCase(), left, doc.y, { width: contentWidth });
                    doc.moveTo(left, doc.y + 4).lineTo(pageWidth - left, doc.y + 4).strokeColor('#d9dee3').lineWidth(0.8).stroke();
                    doc.y += 12;
                };
                const metric = (x, y, width, label, value, detail, tone) => {
                    doc.roundedRect(x, y, width, 62, 7).fill('#f8fafc').strokeColor('#e1e6ea').lineWidth(0.8).stroke();
                    doc.font('Helvetica').fontSize(7.4).fillColor(slate).text(label, x + 10, y + 10, { width: width - 20, height: 10 });
                    doc.font('Helvetica').fontSize(18).fillColor(tone).text(String(value), x + 10, y + 23, { width: width - 20, height: 21 });
                    doc.font('Helvetica').fontSize(7.1).fillColor(slate).text(detail, x + 10, y + 48, { width: width - 20, height: 9 });
                };
                const textBlock = (title, text, tone = navy) => {
                    const value = cleanText(text);
                    if (!value) return;
                    const height = doc.font('Helvetica').fontSize(8).heightOfString(value, { width: contentWidth - 24, lineGap: 2 });
                    addPageIfNeeded(height + 38);
                    section(title, tone);
                    doc.font('Helvetica').fontSize(8).fillColor(slate).text(value, left + 12, doc.y, { width: contentWidth - 24, lineGap: 2 });
                    doc.y += height + 10;
                };
                const requestedCount = item => {
                    const text = `${item?.title || ''} ${item?.description || ''}`.toLowerCase();
                    const words = { one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17 };
                    const match = text.match(/\b(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen)\s+(?:[a-z-]+\s+){0,2}devices?\b/i);
                    if (!match) return null;
                    const numeric = Number(match[1]);
                    return Number.isFinite(numeric) && numeric > 0 ? numeric : words[match[1].toLowerCase()];
                };
                const categoryForFinding = item => {
                    const text = `${item?.title || ''} ${item?.description || ''}`.toLowerCase();
                    const keys = [
                        item?.sourceMetric,
                        text.includes('non-compliant') ? 'nonCompliantDevices' : '',
                        text.includes('unknown compliance') ? 'unknownDevices' : '',
                        text.includes('dead') || text.includes('over 30 days') ? 'deadDevices' : '',
                        text.includes('stale') ? 'staleDevices' : '',
                        'allDevices'
                    ].filter(Boolean);
                    return keys.map(key => categories.find(category =>
                        String(category?.key || '').toLowerCase() === String(key).toLowerCase() ||
                        String(category?.sourceMetric || '').toLowerCase() === String(key).toLowerCase()
                    )).find(Boolean) || null;
                };
                const deviceRowsForFinding = item => {
                    const directRows = [
                        ...(Array.isArray(item?.evidenceRecords) ? item.evidenceRecords : []),
                        ...(Array.isArray(item?.affectedEntities) ? item.affectedEntities : []),
                        ...(Array.isArray(item?.evidenceRows) ? item.evidenceRows : [])
                    ];
                    const category = categoryForFinding(item);
                    const source = directRows.length ? directRows : (Array.isArray(category?.entities) ? category.entities : []);
                    const unique = new Map();
                    source.forEach(device => {
                        const key = String(device?.entityId || device?.id || device?.entityDeviceName || device?.deviceName || device?.displayName || '').toLowerCase();
                        if (key && !unique.has(key)) unique.set(key, device);
                    });
                    const total = requestedCount(item) || Number(category?.count || unique.size || 0);
                    return { rows: Array.from(unique.values()).slice(0, Math.min(10, total || 10)), total };
                };
                const formatDevice = device => {
                    const name = cleanText(device.entityDeviceName || device.deviceName || device.entityName || device.displayName, 'Unnamed device');
                    const user = cleanText(device.assignedUser || device.entityUser || device.userPrincipalName || device.entityEmail || device.mail);
                    const os = [cleanText(device.operatingSystem), cleanText(device.osVersion)].filter(Boolean).join(' ');
                    const compliance = cleanText(device.complianceState || device.status);
                    const encrypted = device.isEncrypted == null ? cleanText(device.encryptionStatus || device.encryptionState) : device.isEncrypted ? 'Encrypted' : 'Not encrypted';
                    const management = cleanText(device.managementAgent || device.managementState);
                    const sync = cleanText(device.lastSyncDateTime || device.lastSync || device.lastSeen);
                    const serial = cleanText(device.serialNumber);
                    const details = [
                        user ? `Assigned user: ${user}` : '',
                        os ? `OS: ${os}` : '',
                        compliance ? `Compliance: ${compliance}` : '',
                        encrypted ? `Encryption: ${encrypted}` : '',
                        management ? `Management: ${management}` : '',
                        sync ? `Last sync: ${formatReportDate(sync, true)}` : '',
                        serial ? `Serial: ${serial}` : ''
                    ].filter(Boolean);
                    return { name, details };
                };
                const drawDevices = devices => {
                    if (!devices.length) {
                        doc.font('Helvetica').fontSize(7.4).fillColor(slate).text('No supporting device details were returned with this finding.', left + 30, doc.y, { width: contentWidth - 42 });
                        doc.y += 16;
                        return;
                    }
                    devices.forEach((device, index) => {
                        const value = formatDevice(device);
                        const detail = value.details.join('\n');
                        const titleHeight = doc.font('Helvetica-Bold').fontSize(7.8).heightOfString(value.name, { width: contentWidth - 56 });
                        const detailHeight = detail ? doc.font('Helvetica').fontSize(7.2).heightOfString(detail, { width: contentWidth - 56, lineGap: 1 }) : 0;
                        const rowHeight = Math.max(23, titleHeight + detailHeight + 11);
                        addPageIfNeeded(rowHeight + 6);
                        const rowY = doc.y;
                        if (index % 2 === 0) doc.rect(left + 22, rowY - 2, contentWidth - 34, rowHeight).fill('#fbfcfd');
                        doc.circle(left + 31, rowY + 4, 1.4).fillColor('#2563eb').fill();
                        doc.font('Helvetica-Bold').fontSize(7.8).fillColor(navy).text(value.name, left + 38, rowY, { width: contentWidth - 56 });
                        if (detail) doc.font('Helvetica').fontSize(7.2).fillColor(slate).text(detail, left + 38, rowY + titleHeight + 2, { width: contentWidth - 56, lineGap: 1 });
                        doc.y = rowY + rowHeight + 3;
                    });
                };
                const splitActions = action => cleanText(action).split(/(?:;|\.(?=\s+[A-Z])|,\s+(?=(?:and\s+)?(?:review|remove|require|retire|initiate|investigate|notify|validate|enforce)\b))/i)
                    .map(point => point.replace(/^and\s+/i, '').trim().replace(/[.]+$/, '')).filter(Boolean);
                const findings = [...(Array.isArray(output.risks) ? output.risks : []), ...(Array.isArray(output.keyFindings) ? output.keyFindings : [])]
                    .slice(0, 8)
                    .map(item => {
                        const evidence = deviceRowsForFinding(item);
                        return {
                            title: cleanText(item.title || item.patternFound, 'Device finding'),
                            severity: cleanText(item.severity || item.priority || item.impact || 'Observed'),
                            detail: cleanText(item.description || item.detail || item.whatHappened || item.title),
                            impact: cleanText(item.impact || item.businessImpact),
                            rationale: cleanText(item.whyItMatters || item.reasoning),
                            devices: evidence.rows,
                            deviceCount: evidence.total,
                            actions: splitActions(item.firstAction || item.recommendedAction || item.recommendation)
                        };
                    });

                addPageIfNeeded(120);
                section('Device Protection Report', deviceTone(riskLevel));
                doc.font('Helvetica').fontSize(8.1).fillColor(slate).text('Current device security posture', left, doc.y, { width: contentWidth });
                doc.y += 16;
                const gap = 12;
                const width = (contentWidth - gap) / 2;
                const metricY = doc.y;
                metric(left, metricY, width, 'HEALTH SCORE', `${healthScore}%`, 'Current device health score', healthScore >= 80 ? green : orange);
                metric(left + width + gap, metricY, width, 'RISK SCORE', `${riskScore}%`, `${riskLevel} risk level`, deviceTone(riskLevel));
                doc.y = metricY + 76;
                textBlock('Domain summary', output.domainExecutiveSummary || output.technicalSummary || output.currentPosture, deviceTone(riskLevel));
                textBlock('Business impact', output.businessImpact || output.businessImpactSummary, deviceTone(riskLevel));

                if (findings.length) {
                    section(`Key device findings (${findings.length})`);
                    findings.forEach((finding, index) => {
                        const tone = deviceTone(finding.severity);
                        const fields = [
                            ['FINDING', finding.detail],
                            ['SEVERITY', finding.severity],
                            ['IMPACT', finding.impact],
                            ['WHY IT MATTERS', finding.rationale]
                        ].filter(([, value]) => value);
                        addPageIfNeeded(70);
                        if (index % 2 === 0) doc.rect(left, doc.y - 3, contentWidth, Math.min(190, bottom - doc.y)).fill('#f8fafc');
                        doc.circle(left + 9, doc.y + 5, 2).fillColor(tone).fill();
                        doc.font('Helvetica-Bold').fontSize(8.5).fillColor(tone).text(finding.title, left + 18, doc.y, { width: contentWidth - 30, lineGap: 1 });
                        doc.y += doc.heightOfString(finding.title, { width: contentWidth - 30, lineGap: 1 }) + 7;
                        fields.forEach(([label, value]) => {
                            addPageIfNeeded(24);
                            doc.font('Helvetica-Bold').fontSize(7.2).fillColor(tone).text(label, left + 18, doc.y, { width: contentWidth - 30 });
                            doc.y += 10;
                            doc.font('Helvetica').fontSize(7.5).fillColor(slate).text(value, left + 18, doc.y, { width: contentWidth - 30, lineGap: 1 });
                            doc.y += doc.heightOfString(value, { width: contentWidth - 30, lineGap: 1 }) + 5;
                        });
                        addPageIfNeeded(22);
                        doc.font('Helvetica-Bold').fontSize(7.2).fillColor(tone).text('EVIDENCE', left + 18, doc.y, { width: contentWidth - 30 });
                        doc.y += 11;
                        drawDevices(finding.devices);
                        const remaining = Math.max(0, finding.deviceCount - finding.devices.length);
                        if (remaining) {
                            doc.font('Helvetica').fontSize(7.1).fillColor(slate).text(`${remaining} additional affected device${remaining === 1 ? '' : 's'} are available in the Device Protection dashboard.`, left + 38, doc.y, { width: contentWidth - 56 });
                            doc.y += 15;
                        }
                        if (finding.actions.length) {
                            addPageIfNeeded(24);
                            doc.font('Helvetica-Bold').fontSize(7.2).fillColor(green).text('RECOMMENDATIONS', left + 18, doc.y, { width: contentWidth - 30 });
                            doc.y += 11;
                            finding.actions.forEach(action => {
                                const actionHeight = doc.font('Helvetica').fontSize(7.4).heightOfString(action, { width: contentWidth - 56, lineGap: 1 });
                                addPageIfNeeded(actionHeight + 8);
                                doc.circle(left + 25, doc.y + 4, 1.4).fillColor(green).fill();
                                doc.font('Helvetica').fontSize(7.4).fillColor(slate).text(action, left + 32, doc.y, { width: contentWidth - 56, lineGap: 1 });
                                doc.y += actionHeight + 5;
                            });
                        }
                        doc.y += 8;
                    });
                }
                doc.y += 4;
            };
            const isEmailSecurityDomain = domain => String(domain?.domainKey || domain?.domainName || '').trim().toLowerCase() === 'email_security' || /^email security$/i.test(String(domain?.domainName || ''));
            const isCloudflareDomain = domain => String(domain?.domainKey || '').trim().toLowerCase() === 'cloudflare_network_security' || /cloudflare|network security/i.test(String(domain?.domainName || ''));
            const isApplicationsDomain = domain => String(domain?.domainKey || domain?.domainName || '').trim().toLowerCase() === 'applications' || /^applications$/i.test(String(domain?.domainName || ''));
            const isSecurityAlertsDomain = domain => String(domain?.domainKey || domain?.domainName || '').trim().toLowerCase() === 'security_alerts' || /^security alerts$/i.test(String(domain?.domainName || ''));
            const isBackupDomain = domain => String(domain?.domainKey || domain?.domainName || '').trim().toLowerCase() === 'backup' || /backup and recovery/i.test(String(domain?.domainName || ''));
            const isGovernanceDomain = domain => String(domain?.domainKey || domain?.domainName || '').trim().toLowerCase() === 'governance' || /^governance$/i.test(String(domain?.domainName || ''));
            const isComplianceDomain = domain => String(domain?.domainKey || domain?.domainName || '').trim().toLowerCase() === 'compliance' || /compliance validation/i.test(String(domain?.domainName || ''));
            const renderEmailOrCloudflareReport = (domain, reportType) => {
                if (!domain) return;

                const output = domain.intelligenceOutput || domain.output || {};
                const scores = output.authoritativeScores || output.scoreSummary || {};
                const categories = Array.isArray(output.evidenceCatalog?.categories) ? output.evidenceCatalog.categories : [];
                const healthScore = clampReportScore(scores.healthScore ?? output.healthScore ?? domain.healthScore ?? 0);
                const riskScore = clampReportScore(scores.riskScore ?? output.riskScore ?? domain.riskScore ?? 0);
                const riskLevel = cleanText(scores.riskLevel || output.riskLevel || 'Unrated');
                const isEmail = reportType === 'email';
                const isApplications = reportType === 'applications';
                const isSecurityAlerts = reportType === 'security-alerts';
                const isBackup = reportType === 'backup';
                const isGovernance = reportType === 'governance';
                const isCompliance = reportType === 'compliance';
                const tone = value => {
                    const normalized = String(value || '').toLowerCase();
                    if (/critical|high/.test(normalized)) return red;
                    if (/medium|moderate|warning/.test(normalized)) return orange;
                    if (/low|safe|good|active|enabled/.test(normalized)) return green;
                    return '#2563eb';
                };
                const sectionTone = reportType === 'cloudflare' ? orange : tone(riskLevel);
                const reportLabel = isEmail ? 'Email Security' : isApplications ? 'Applications' : isSecurityAlerts ? 'Security Alerts' : isBackup ? 'Backup and Recovery' : isGovernance ? 'Governance' : isCompliance ? 'Compliance Validation' : 'Network Security / Cloudflare';
                const postureLabel = isEmail ? 'email' : isApplications ? 'application governance' : isSecurityAlerts ? 'security alert' : isBackup ? 'backup and recovery' : isGovernance ? 'governance' : isCompliance ? 'compliance validation' : 'network';
                const dashboardLabel = isEmail ? 'Email Security' : isApplications ? 'Applications' : isSecurityAlerts ? 'Security Alerts' : isBackup ? 'Backup and Recovery' : isGovernance ? 'Governance' : isCompliance ? 'Compliance Validation' : 'Network Security';
                const section = (title, color = navy) => {
                    addPageIfNeeded(34);
                    doc.font('Helvetica').fontSize(10.5).fillColor(color).text(title.toUpperCase(), left, doc.y, { width: contentWidth });
                    doc.moveTo(left, doc.y + 4).lineTo(pageWidth - left, doc.y + 4).strokeColor('#d9dee3').lineWidth(0.8).stroke();
                    doc.y += 12;
                };
                const metric = (x, y, width, label, value, detail, color) => {
                    doc.roundedRect(x, y, width, 62, 7).fill('#f8fafc').strokeColor('#e1e6ea').lineWidth(0.8).stroke();
                    doc.font('Helvetica').fontSize(7.3).fillColor(slate).text(label, x + 10, y + 10, { width: width - 20, height: 10 });
                    doc.font('Helvetica').fontSize(17).fillColor(color).text(String(value), x + 10, y + 23, { width: width - 20, height: 20 });
                    doc.font('Helvetica').fontSize(7).fillColor(slate).text(detail, x + 10, y + 48, { width: width - 20, height: 9 });
                };
                const textBlock = (title, text, color = navy) => {
                    const value = cleanText(text);
                    if (!value) return;
                    const height = doc.font('Helvetica').fontSize(8).heightOfString(value, { width: contentWidth - 24, lineGap: 2 });
                    addPageIfNeeded(height + 38);
                    section(title, color);
                    doc.font('Helvetica').fontSize(8).fillColor(slate).text(value, left + 12, doc.y, { width: contentWidth - 24, lineGap: 2 });
                    doc.y += height + 10;
                };
                const category = key => categories.find(item => String(item?.key || '').toLowerCase() === key.toLowerCase()) || null;
                const categoryCount = key => Number(category(key)?.count || 0);
                const categoryEntities = key => Array.isArray(category(key)?.entities) ? category(key).entities : [];
                const statementCount = pattern => {
                    const text = [output.domainExecutiveSummary, output.currentPosture, output.technicalSummary, output.scoreJustification, ...(Array.isArray(output.risks) ? output.risks : []), ...(Array.isArray(output.keyFindings) ? output.keyFindings : [])]
                        .map(item => typeof item === 'object' ? `${item.title || ''} ${item.description || ''}` : String(item || '')).join(' ');
                    const match = text.match(pattern);
                    return match ? Number(match[1]) : 0;
                };
                const applicationEntities = categoryEntities('applications');
                const backupLineageMetric = key => {
                    const item = Array.isArray(output.dataLineageComparison) ? output.dataLineageComparison.find(entry => entry?.metric === key) : null;
                    return Number(item?.stackCTRLSource ?? item?.storedIntelligence ?? item?.azureOutput ?? 0);
                };
                // Backup values are supplied as structured lineage metrics. Prefer them to
                // AI wording so total storage and coverage stay exact.
                const backupStorageGb = backupLineageMetric('totalStorageGB') || statementCount(/(\d+(?:\.\d+)?)\s*GB\s+total storage/i);
                const backupCoverage = backupLineageMetric('backupCoverageScore') || statementCount(/(?:coverage score of|coverage is|coverage at)\s*(\d+)%/i);
                const backupExposure = backupLineageMetric('dataExposureRiskScore') || statementCount(/exposure risk(?: score)?(?:\s+is|\s+of)?(?:\s+\w+){0,3}?\s+(\d+)/i);
                const backupDataHolders = backupLineageMetric('activeUsersCount') || categoryCount('users');
                const governanceEntities = categoryEntities('governanceRows');
                const complianceControls = categoryEntities('controls');
                const lineageMetric = key => {
                    const item = Array.isArray(output.dataLineageComparison) ? output.dataLineageComparison.find(entry => entry?.metric === key) : null;
                    return Number(item?.stackCTRLSource ?? item?.storedIntelligence ?? item?.azureOutput ?? 0);
                };
                const metricItems = isEmail
                    ? [
                        { label: 'ACTIVE ALERTS', value: categoryCount('alerts'), detail: 'User-reported email alerts', color: categoryCount('alerts') ? orange : green },
                        { label: 'REPEATEDLY TARGETED', value: statementCount(/(\d+)\s+users?\s+repeatedly/i), detail: 'Users requiring review', color: orange },
                        { label: 'ACTIVE MAILBOXES', value: categoryCount('mailActivityUsers'), detail: 'Mailboxes with current activity', color: '#2563eb' },
                        { label: 'INACTIVE MAILBOXES', value: statementCount(/(\d+)\s+inactive mailboxes?/i), detail: 'Mailboxes for review', color: orange }
                    ]
                    : isApplications
                        ? [
                            { label: 'APPLICATIONS', value: categoryCount('applications'), detail: 'Applications in the inventory', color: '#2563eb' },
                            { label: 'EXTERNAL APPS', value: applicationEntities.filter(item => item?.isExternal || /^external$/i.test(String(item?.type || ''))).length || categoryCount('applications'), detail: 'Applications marked external', color: orange },
                            { label: 'UNKNOWN PUBLISHERS', value: applicationEntities.filter(item => /^unknown$/i.test(String(item?.publisherName || ''))).length, detail: 'Publishers requiring verification', color: orange },
                            { label: 'ASSIGNED USERS', value: applicationEntities.reduce((total, item) => total + Number(item?.userCount || 0), 0), detail: 'Users assigned to sampled apps', color: '#2563eb' }
                        ]
                        : isSecurityAlerts
                            ? [
                                { label: 'TOTAL ALERTS', value: categoryCount('alerts'), detail: 'Security alerts in the period', color: red },
                                { label: 'UNRESOLVED ALERTS', value: statementCount(/(\d+)\s+unresolved alerts?/i), detail: 'Alerts requiring action', color: red },
                                { label: 'SIGN-IN SIGNALS', value: categoryCount('signIns'), detail: 'Correlated sign-in events', color: orange },
                                { label: 'THREAT INDICATORS', value: categoryCount('threatIndicators'), detail: 'Indicators available for correlation', color: orange }
                            ]
                            : isBackup
                                ? [
                                    { label: 'TOTAL STORAGE', value: backupStorageGb ? `${backupStorageGb.toLocaleString()} GB` : 'Recorded', detail: 'Storage across protected services', color: '#2563eb' },
                                    { label: 'BACKUP COVERAGE', value: backupCoverage ? `${backupCoverage}%` : 'Recorded', detail: 'Service coverage score', color: green },
                                    { label: 'EXPOSURE RISK', value: backupExposure ? `${backupExposure}%` : 'High', detail: 'Risk from large data holders', color: red },
                                    { label: 'DATA HOLDERS', value: backupDataHolders, detail: 'Active users in recovery scope', color: orange }
                                ]
                                : isGovernance
                                    ? [
                                        { label: 'OWNERLESS ITEMS', value: statementCount(/(\d+)\s+owner-missing/i) || governanceEntities.filter(item => /missing/i.test(String(item?.ownerStatus || ''))).length, detail: 'Items without an assigned owner', color: red },
                                        { label: 'ATTENTION REQUIRED', value: statementCount(/(\d+)\s+attention-required/i) || governanceEntities.filter(item => /attention required/i.test(String(item?.status || ''))).length, detail: 'Items requiring management review', color: red },
                                        { label: 'GOVERNANCE ITEMS', value: categoryCount('governanceRows'), detail: 'Evidence-backed review activities', color: orange },
                                        { label: 'CONNECTED REVIEWS', value: lineageMetric('connectedRows') || governanceEntities.filter(item => item?.connected).length, detail: 'Reviews with connected evidence', color: '#2563eb' }
                                    ]
                                    : isCompliance
                                        ? [
                                            { label: 'FAILED CONTROLS', value: lineageMetric('failingControls'), detail: 'Controls requiring remediation', color: red },
                                            { label: 'PARTIAL CONTROLS', value: lineageMetric('partialControls'), detail: 'Controls needing evidence closure', color: orange },
                                            { label: 'PASSED CONTROLS', value: lineageMetric('passingControls'), detail: 'API-backed controls passing', color: green },
                                            { label: 'API CONTROLS', value: lineageMetric('apiControls') || categoryCount('controls'), detail: 'Controls backed by connected evidence', color: '#2563eb' }
                                        ]
                    : [
                        { label: 'WARP DEVICES', value: categoryCount('devices'), detail: 'Enrolled and protected devices', color: '#2563eb' },
                        { label: 'GATEWAY RULES', value: categoryCount('gatewayRules'), detail: 'Configured network controls', color: '#2563eb' },
                        { label: 'DLP PROFILES', value: categoryCount('dlpProfiles'), detail: 'Sensitive-data protections', color: '#2563eb' },
                        { label: 'PROTECTED APPS', value: categoryCount('accessApps'), detail: 'Active protected applications', color: '#2563eb' }
                    ];
                const categoryForFinding = item => {
                    const text = `${item?.title || ''} ${item?.description || ''}`.toLowerCase();
                    const keys = isEmail
                        ? [item?.sourceMetric, /alert|junk|mail|phish|spam|bec/.test(text) ? 'alerts' : '', /mailbox|mail activity/.test(text) ? 'mailActivityUsers' : '', 'alerts']
                        : isApplications
                            ? [item?.sourceMetric, 'applications']
                            : isSecurityAlerts
                                ? [
                                    item?.sourceMetric,
                                    /sign-in|sign in|anonymous ip|failed sign/.test(text) ? 'signIns' : '',
                                    /indicator|correlat/.test(text) ? 'threatIndicators' : '',
                                    'alerts'
                                ]
                                : isBackup
                                    ? [item?.sourceMetric, 'users']
                                    : isGovernance
                                        ? [item?.sourceMetric, 'governanceRows']
                                            : isCompliance
                                                ? [item?.sourceMetric, 'controls']
                        : [
                            item?.sourceMetric,
                            /audit/.test(text) ? 'auditLogs' : '',
                            /permission|api/.test(text) ? 'endpointFamilies' : '',
                            /gateway|inspect/.test(text) ? 'gatewayRules' : '',
                            /dlp/.test(text) ? 'dlpProfiles' : '',
                            /protected application|sso|warp login/.test(text) ? 'accessApps' : '',
                            /warp|enrolled device/.test(text) ? 'devices' : '',
                            /app categor/.test(text) ? 'gatewayAppTypes' : '',
                            'devices'
                        ];
                    return keys.filter(Boolean).map(key => category(key)).find(Boolean) || null;
                };
                const evidenceForFinding = item => {
                    const direct = [
                        ...(Array.isArray(item?.evidenceRecords) ? item.evidenceRecords : []),
                        ...(Array.isArray(item?.affectedEntities) ? item.affectedEntities : []),
                        ...(Array.isArray(item?.evidence) ? item.evidence : []),
                        ...(Array.isArray(item?.evidenceRows) ? item.evidenceRows : [])
                    ];
                    // Backup and Governance links are compact IDs. Enrich only those
                    // IDs from their matching domain evidence catalog before PDF layout.
                    const linkedCatalog = (isBackup || isGovernance) ? categoryForFinding(item) : null;
                    // These two domains have one authoritative record catalog. An aggregate
                    // source metric must not shadow that catalog when resolving named evidence.
                    const evidenceCatalog = isBackup ? (category('users') || linkedCatalog) : isGovernance ? (category('governanceRows') || linkedCatalog) : linkedCatalog;
                    const catalogEntities = Array.isArray(evidenceCatalog?.entities) ? evidenceCatalog.entities : [];
                    const evidenceKeys = entry => [...new Set([
                        entry?.entityId, entry?.id, entry?.recordId, entry?.sourceAlertId, entry?.alertId,
                        entry?.controlId, entry?.applicationId, entry?.deviceId, entry?.userId,
                        entry?.entityEmail, entry?.mail, entry?.userPrincipalName, entry?.entityName,
                        entry?.displayName, entry?.name, entry?.title
                    ].map(value => String(value || '').trim().toLowerCase()).filter(Boolean))];
                    const catalogByEvidenceKey = new Map();
                    catalogEntities.forEach(catalogEntry => {
                        evidenceKeys(catalogEntry).forEach(key => {
                            if (!catalogByEvidenceKey.has(key)) catalogByEvidenceKey.set(key, catalogEntry);
                        });
                    });
                    const enrichedDirect = catalogEntities.length
                        ? direct.map(entry => {
                            const catalogEntry = evidenceKeys(entry).map(key => catalogByEvidenceKey.get(key)).find(Boolean);
                            return catalogEntry
                                ? { ...catalogEntry, ...Object.fromEntries(Object.entries(entry || {}).filter(([, value]) => value != null && value !== '')) }
                                : entry;
                        })
                        : direct;
                    const findingText = [item?.title, item?.description, item?.detail, item?.whatHappened, item?.patternFound]
                        .map(value => String(value || '')).join(' ').toLowerCase();
                    const evidenceLabels = (Array.isArray(item?.evidenceUsed) ? item.evidenceUsed : [])
                        .map(value => String(value?.label || value || '').trim().toLowerCase()).filter(Boolean);
                    const backupEvidenceRows = () => {
                        const evidenceText = `${findingText} ${evidenceLabels.join(' ')}`;
                        if (/large data holder|top storage|storage volume|storage user|backup window/.test(evidenceText)) {
                            const linkedStorageRows = enrichedDirect.filter(entry => Number(entry?.storage) > 0);
                            if (linkedStorageRows.length) return linkedStorageRows;
                            const namedRows = catalogEntities.filter(entry => evidenceLabels.some(label => label.includes(String(entry?.displayName || entry?.entityName || '').toLowerCase())));
                            return namedRows.length ? namedRows : [...catalogEntities].filter(entry => Number(entry?.storage) > 0).sort((leftEntry, rightEntry) => Number(rightEntry.storage) - Number(leftEntry.storage)).slice(0, 5);
                        }
                        if (/coverage|external backup|restore/.test(evidenceText)) {
                            const score = lineageMetric('backupCoverageScore');
                            return score == null ? [] : [{ entityName: 'Backup coverage score', entityType: 'SourceMetric', metricName: 'backupCoverageScore', sourceMetric: 'backupCoverageScore', value: score, servicesCovered: lineageMetric('servicesCovered'), totalStorageGB: lineageMetric('totalStorageGB'), dataExposureRiskScore: lineageMetric('dataExposureRiskScore') }];
                        }
                        return null;
                    };
                    const governanceEvidenceRows = () => {
                        if (/access review/.test(findingText)) return catalogEntities.filter(entry => /review users|review roles/i.test(String(entry?.activity || '')));
                        if (/owner.*missing|governance ownership|critical review/.test(findingText)) return catalogEntities.filter(entry => /full stack|threat landscape|app review|identity check|device posture/i.test(String(entry?.activity || '')));
                        if (/incident review|sign-in logs|backup check|policy review|data review/.test(findingText)) {
                            const requested = [[/incident review/i, /post-incident/i], [/sign-in logs/i, /sign-in logs/i], [/backup check/i, /backup check/i], [/policy review/i, /ca and compliance policies/i], [/data review/i, /sharepoint usage/i]];
                            return catalogEntities.filter(entry => requested.some(([needle, activity]) => needle.test(findingText) && activity.test(String(entry?.activity || ''))));
                        }
                        if (/owner missing counts|governance summary/.test(findingText)) return catalogEntities.filter(entry => /missing|unassigned|none/i.test(String(entry?.ownerStatus || entry?.owner || '')));
                        if (/manual evidence rows were excluded/.test(findingText)) {
                            const count = lineageMetric('manualRowsExcluded');
                            return count == null ? [] : [{ entityName: 'Manual governance rows excluded', entityType: 'SourceMetric', metricName: 'manualRowsExcluded', sourceMetric: 'manualRowsExcluded', value: count, status: 'Observed' }];
                        }
                        const matchedLabels = catalogEntities.filter(entry => evidenceLabels.some(label => label.includes(String(entry?.activity || entry?.entityName || '').toLowerCase())));
                        if (matchedLabels.length) return matchedLabels;
                        const activityMatches = catalogEntities.filter(entry => String(entry?.activity || '').trim() && findingText.includes(String(entry.activity).toLowerCase()));
                        return activityMatches.length ? activityMatches : null;
                    };
                    const semanticRows = isBackup ? backupEvidenceRows() : isGovernance ? governanceEvidenceRows() : null;
                    const evidenceRows = Array.isArray(semanticRows) ? semanticRows : enrichedDirect;
                    const strongEvidenceKeys = entry => [...new Set([
                        entry?.id, entry?.recordId, entry?.sourceAlertId, entry?.alertId, entry?.SourceID,
                        entry?.controlId, entry?.applicationId, entry?.deviceId, entry?.userId,
                        entry?.entityId && !/[\s@]/.test(String(entry.entityId)) ? entry.entityId : null
                    ].map(value => String(value || '').trim().toLowerCase()).filter(Boolean))];
                    const isSummaryEvidence = entry => /(?:summary|score|coverage)/i.test(String(entry?.entityType || entry?.evidenceType || '')) || /(?:summary|score)$/i.test(String(entry?.entityId || entry?.id || ''));
                    const specific = evidenceRows.filter(entry => !isSummaryEvidence(entry));
                    const source = specific.length ? specific : evidenceRows;
                    const entries = [];
                    source.forEach(entry => {
                        const keys = evidenceKeys(entry);
                        const strongKeys = strongEvidenceKeys(entry);
                        if (!keys.length) return;
                        const existing = entries.find(candidate => {
                            const sameStrongRecord = strongKeys.some(key => candidate.strongKeys.has(key));
                            const aliasCanBeUsed = !strongKeys.length || !candidate.strongKeys.size;
                            return sameStrongRecord || (aliasCanBeUsed && keys.some(key => candidate.keys.has(key)));
                        });
                        if (existing) {
                            existing.record = { ...existing.record, ...Object.fromEntries(Object.entries(entry || {}).filter(([, value]) => value != null && value !== '')) };
                            keys.forEach(key => existing.keys.add(key));
                            strongKeys.forEach(key => existing.strongKeys.add(key));
                            return;
                        }
                        entries.push({ record: { ...entry }, keys: new Set(keys), strongKeys: new Set(strongKeys) });
                    });
                    const rows = entries.map(entry => entry.record);
                    return { rows, total: rows.length };
                };
                const formatEvidence = entry => {
                    const name = cleanText(entry.controlName || entry.displayName || entry.applicationName || entry.entityName || entry.name || entry.title || entry.indicator || entry.value || entry.user || entry.deviceName || ((isBackup || isGovernance) ? entry.entityId : ''), isEmail ? 'Email security alert' : isApplications ? 'Application' : isSecurityAlerts ? 'Security alert' : isBackup ? 'Data holder' : isGovernance ? 'Governance review' : isCompliance ? 'Compliance control' : 'Cloudflare control');
                    const fields = isEmail
                        ? [
                            entry.recipient ? `Recipient: ${cleanText(entry.recipient)}` : '',
                            entry.sender ? `Sender: ${cleanText(entry.sender)}` : '',
                            entry.severity ? `Severity: ${cleanText(entry.severity)}` : '',
                            displayStatus(entry.status) ? `Status: ${displayStatus(entry.status)}` : '',
                            entry.created ? `Reported: ${formatReportDate(entry.created, true)}` : '',
                            entry.source ? `Source: ${cleanText(entry.source)}` : ''
                        ]
                        : isApplications
                            ? [
                                entry.type || entry.entityType ? `Type: ${cleanText(entry.type || entry.entityType)}` : '',
                                entry.publisherName ? `Publisher: ${cleanText(entry.publisherName)}` : '',
                                entry.userCount == null ? '' : `Assigned users: ${entry.userCount}`,
                                entry.roleCount == null ? '' : `Roles: ${entry.roleCount}`,
                                entry.scopeCount == null ? '' : `Permission scopes: ${entry.scopeCount}`,
                                entry.createdDateTime ? `Created: ${formatReportDate(entry.createdDateTime, true)}` : ''
                            ]
                            : isSecurityAlerts && (entry.indicator || entry.indicatorType || entry.occurrenceCount != null)
                                ? [
                                    entry.indicatorType || entry.type ? `Type: ${cleanText(entry.indicatorType || entry.type)}` : '',
                                    entry.severity ? `Severity: ${cleanText(entry.severity)}` : '',
                                    entry.confidence ? `Confidence: ${cleanText(entry.confidence)}` : '',
                                    entry.occurrenceCount == null ? '' : `Occurrences: ${entry.occurrenceCount}`,
                                    entry.action ? `Action: ${cleanText(entry.action)}` : '',
                                    Array.isArray(entry.relatedUsers) && entry.relatedUsers.length ? `Users: ${entry.relatedUsers.join(', ')}` : ''
                                ]
                                : isSecurityAlerts && (entry.ipAddress || entry.failureReason || entry.location)
                                    ? [
                                        entry.user || entry.userPrincipalName ? `User: ${cleanText(entry.user || entry.userPrincipalName)}` : '',
                                        displayStatus(entry.status) ? `Status: ${displayStatus(entry.status)}` : '',
                                        entry.location || entry.country ? `Location: ${cleanText(entry.location || entry.country)}` : '',
                                        entry.ipAddress ? `IP address: ${cleanText(entry.ipAddress)}` : '',
                                        entry.timestamp ? `Occurred: ${formatReportDate(entry.timestamp, true)}` : '',
                                        entry.failureReason ? `Reason: ${cleanText(entry.failureReason)}` : ''
                                    ]
                                    : isSecurityAlerts
                                        ? [
                                            entry.user ? `User: ${cleanText(entry.user)}` : '',
                                            entry.severity ? `Severity: ${cleanText(entry.severity)}` : '',
                                                displayStatus(entry.status) ? `Status: ${displayStatus(entry.status)}` : '',
                                            entry.category ? `Category: ${cleanText(entry.category)}` : '',
                                            entry.created ? `Reported: ${formatReportDate(entry.created, true)}` : '',
                                            entry.source ? `Source: ${cleanText(entry.source)}` : ''
                                        ]
                                        : isBackup
                                            ? [
                                                entry.user ? `Account: ${cleanText(entry.user)}` : '',
                                                entry.files == null ? '' : `Files: ${Number(entry.files).toLocaleString()}`,
                                                entry.storage == null ? '' : `Storage: ${(Number(entry.storage) / (1024 ** 3)).toFixed(1)} GB`,
                                                entry.backupCoverageScore == null ? '' : `Coverage: ${Number(entry.backupCoverageScore)}% across ${Number(entry.servicesCovered || 0)} services`,
                                                entry.totalStorageGB == null ? '' : `Total protected storage: ${Number(entry.totalStorageGB).toLocaleString()} GB`,
                                                entry.dataExposureRiskScore == null ? '' : `Exposure risk: ${Number(entry.dataExposureRiskScore)}%`,
                                                entry.lastActivity ? `Last activity: ${formatReportDate(entry.lastActivity, true)}` : '',
                                                entry.sourceMetric ? `Source: ${cleanText(entry.sourceMetric)}` : ''
                                            ]
                                            : isGovernance
                                                ? [
                                                    entry.area ? `Area: ${cleanText(entry.area)}` : '',
                                                    displayStatus(entry.status) ? `Status: ${displayStatus(entry.status)}` : '',
                                                    entry.ownerStatus ? `Owner: ${cleanText(entry.ownerStatus).replace(/_/g, ' ')}` : '',
                                                    entry.frequency ? `Review cycle: ${cleanText(entry.frequency)}` : '',
                                                    entry.source || entry.dataSource ? `Source: ${cleanText(entry.source || entry.dataSource)}` : '',
                                                    entry.evidence ? `Evidence: ${cleanText(entry.evidence)}` : '',
                                                    entry.managementAction ? `Action: ${cleanText(entry.managementAction)}` : ''
                                                ]
                                                : isCompliance
                                                    ? [
                                                        entry.controlCategory || entry.area ? `Area: ${cleanText(entry.controlCategory || entry.area)}` : '',
                                                        entry.complianceStatus || entry.status ? `Status: ${displayStatus(cleanText(entry.complianceStatus || entry.status).replace(/[🟢🟡🔴]/g, '').trim())}` : '',
                                                        entry.severity ? `Severity: ${cleanText(entry.severity)}` : '',
                                                        entry.auditImpact ? `Audit impact: ${cleanText(entry.auditImpact)}` : '',
                                                        entry.validationReason ? `Evidence: ${cleanText(entry.validationReason)}` : '',
                                                        entry.remediationAction ? `Action: ${cleanText(entry.remediationAction)}` : ''
                                                    ]
                        : [
                            entry.entityType ? `Type: ${cleanText(entry.entityType)}` : '',
                            entry.action ? `Action: ${cleanText(entry.action)}` : '',
                            entry.enabled == null ? '' : `Enabled: ${entry.enabled ? 'Yes' : 'No'}`,
                            entry.status ? `Status: ${cleanText(entry.status)}` : '',
                            entry.userPrincipalName || entry.assignedUser ? `User: ${cleanText(entry.userPrincipalName || entry.assignedUser)}` : '',
                            entry.sourceMetric ? `Source: ${cleanText(entry.sourceMetric)}` : ''
                        ];
                    return { name, details: fields.filter(Boolean) };
                };
                const drawEvidence = rows => {
                    if (!rows.length) {
                        doc.font('Helvetica').fontSize(7.4).fillColor(slate).text('No supporting evidence details were returned with this finding.', left + 30, doc.y, { width: contentWidth - 42 });
                        doc.y += 16;
                        return;
                    }
                    rows.forEach((entry, index) => {
                        const evidence = formatEvidence(entry);
                        const detail = evidence.details.join('\n');
                        const titleHeight = doc.font('Helvetica-Bold').fontSize(7.8).heightOfString(evidence.name, { width: contentWidth - 56 });
                        const detailHeight = detail ? doc.font('Helvetica').fontSize(7.2).heightOfString(detail, { width: contentWidth - 56, lineGap: 1 }) : 0;
                        const rowHeight = Math.max(23, titleHeight + detailHeight + 11);
                        addPageIfNeeded(rowHeight + 6);
                        const rowY = doc.y;
                        if (index % 2 === 0) doc.rect(left + 22, rowY - 2, contentWidth - 34, rowHeight).fill('#fbfcfd');
                        doc.circle(left + 31, rowY + 4, 1.4).fillColor('#2563eb').fill();
                        doc.font('Helvetica-Bold').fontSize(7.8).fillColor(navy).text(evidence.name, left + 38, rowY, { width: contentWidth - 56 });
                        if (detail) doc.font('Helvetica').fontSize(7.2).fillColor(slate).text(detail, left + 38, rowY + titleHeight + 2, { width: contentWidth - 56, lineGap: 1 });
                        doc.y = rowY + rowHeight + 3;
                    });
                };
                const splitActions = value => cleanText(value).split(/(?:;|\.(?=\s+[A-Z])|,\s+(?=(?:and\s+)?(?:review|remove|require|retire|initiate|investigate|notify|validate|enforce|obtain)\b))/i)
                    .map(point => point.replace(/^and\s+/i, '').trim().replace(/[.]+$/, '')).filter(Boolean);
                const domainActions = (Array.isArray(output.recommendations) ? output.recommendations : [])
                    .flatMap(item => splitActions(typeof item === 'object' ? item.title || item.firstAction || item.recommendation || item.detail : item))
                    .slice(0, 5);
                const findings = (isCompliance
                    ? [...complianceControls].sort((leftControl, rightControl) => {
                        const rank = value => /failed/i.test(String(value)) ? 0 : /partial/i.test(String(value)) ? 1 : 2;
                        return rank(leftControl.complianceStatus) - rank(rightControl.complianceStatus);
                    })
                    : [...(Array.isArray(output.risks) ? output.risks : []), ...(Array.isArray(output.keyFindings) ? output.keyFindings : [])])
                    .slice(0, 8)
                    .map(item => {
                        const evidence = evidenceForFinding(item);
                        return {
                            title: cleanText(item.controlName || item.title || item.patternFound, `${reportLabel} finding`),
                            severity: cleanText(item.severity || item.priority || item.impact || 'Observed'),
                            detail: cleanText(isCompliance ? item.validationReason || item.insight || item.title : item.description || item.detail || item.whatHappened || item.title),
                            impact: cleanText(isCompliance ? item.auditImpact : item.impact || item.businessImpact),
                            rationale: cleanText(isCompliance ? item.remediationAction : item.whyItMatters || item.reasoning),
                            evidence: isCompliance ? [item] : evidence.rows,
                            evidenceCount: isCompliance ? 1 : evidence.total,
                            actions: splitActions(isCompliance ? item.remediationAction : item.firstAction || item.recommendedAction || item.recommendation).length
                                ? splitActions(isCompliance ? item.remediationAction : item.firstAction || item.recommendedAction || item.recommendation)
                                : (isApplications || isSecurityAlerts || isBackup || isGovernance || isCompliance ? domainActions : [])
                        };
                    });

                addPageIfNeeded(120);
                section(`${reportLabel} Report`, sectionTone);
                doc.font('Helvetica').fontSize(8.1).fillColor(slate).text(`Current ${postureLabel} posture`, left, doc.y, { width: contentWidth });
                doc.y += 16;
                const metricGap = 10;
                const metricWidth = (contentWidth - metricGap * 2) / 3;
                const metricY = doc.y;
                const allMetrics = [
                    { label: 'HEALTH SCORE', value: `${healthScore}%`, detail: 'Current domain health score', color: healthScore >= 80 ? green : orange },
                    { label: 'RISK SCORE', value: `${riskScore}%`, detail: `${riskLevel} risk level`, color: tone(riskLevel) },
                    ...metricItems
                ];
                allMetrics.forEach((item, index) => {
                    const column = index % 3;
                    const row = Math.floor(index / 3);
                    metric(left + (metricWidth + metricGap) * column, metricY + row * 72, metricWidth, item.label, item.value, item.detail, item.color);
                });
                doc.y = metricY + 148;
                textBlock('Domain summary', output.domainExecutiveSummary || output.technicalSummary || output.currentPosture, sectionTone);
                textBlock('Business impact', output.businessImpact || output.businessImpactSummary, sectionTone);

                if (findings.length) {
                    section(`Key ${isEmail ? 'email' : 'network'} findings (${findings.length})`);
                    findings.forEach((finding, index) => {
                        const findingTone = tone(finding.severity);
                        const fields = [
                            ['FINDING', finding.detail],
                            ['SEVERITY', finding.severity],
                            ['IMPACT', finding.impact],
                            ['WHY IT MATTERS', finding.rationale]
                        ].filter(([, value]) => value);
                        addPageIfNeeded(70);
                        if (index % 2 === 0) doc.rect(left, doc.y - 3, contentWidth, Math.min(190, bottom - doc.y)).fill('#f8fafc');
                        doc.circle(left + 9, doc.y + 5, 2).fillColor(findingTone).fill();
                        doc.font('Helvetica-Bold').fontSize(8.5).fillColor(findingTone).text(finding.title, left + 18, doc.y, { width: contentWidth - 30, lineGap: 1 });
                        doc.y += doc.heightOfString(finding.title, { width: contentWidth - 30, lineGap: 1 }) + 7;
                        fields.forEach(([label, value]) => {
                            addPageIfNeeded(24);
                            doc.font('Helvetica-Bold').fontSize(7.2).fillColor(findingTone).text(label, left + 18, doc.y, { width: contentWidth - 30 });
                            doc.y += 10;
                            doc.font('Helvetica').fontSize(7.5).fillColor(slate).text(value, left + 18, doc.y, { width: contentWidth - 30, lineGap: 1 });
                            doc.y += doc.heightOfString(value, { width: contentWidth - 30, lineGap: 1 }) + 5;
                        });
                        addPageIfNeeded(22);
                        doc.font('Helvetica-Bold').fontSize(7.2).fillColor(findingTone).text('EVIDENCE', left + 18, doc.y, { width: contentWidth - 30 });
                        doc.y += 11;
                        drawEvidence(finding.evidence);
                        const remaining = Math.max(0, finding.evidenceCount - finding.evidence.length);
                        if (remaining) {
                            doc.font('Helvetica').fontSize(7.1).fillColor(slate).text(`${remaining} additional evidence record${remaining === 1 ? '' : 's'} are available in the ${dashboardLabel} dashboard.`, left + 38, doc.y, { width: contentWidth - 56 });
                            doc.y += 15;
                        }
                        if (finding.actions.length) {
                            addPageIfNeeded(24);
                            doc.font('Helvetica-Bold').fontSize(7.2).fillColor(green).text('RECOMMENDATIONS', left + 18, doc.y, { width: contentWidth - 30 });
                            doc.y += 11;
                            finding.actions.forEach(action => {
                                const height = doc.font('Helvetica').fontSize(7.4).heightOfString(action, { width: contentWidth - 56, lineGap: 1 });
                                addPageIfNeeded(height + 8);
                                doc.circle(left + 25, doc.y + 4, 1.4).fillColor(green).fill();
                                doc.font('Helvetica').fontSize(7.4).fillColor(slate).text(action, left + 32, doc.y, { width: contentWidth - 56, lineGap: 1 });
                                doc.y += height + 5;
                            });
                        }
                        doc.y += 8;
                    });
                }
                doc.y += 4;
            };
            const renderDomain = domain => {
                const output = domain.intelligenceOutput || domain.output || {};
                const score = scoreForDomain(domain);
                const risk = riskForDomain(domain);
                const findings = uniqueItems(
                    asItems(output, ['keyFindings', 'findings', 'topFindings', 'risks', 'riskRegister', 'attentionItems', 'securityFindings']),
                    tableItemsForDomain(domain, ['findings', 'risks', 'risk_register'])
                );
                const recommendations = uniqueItems(
                    asItems(output, ['recommendations', 'priorityRecommendations', 'actions', 'nextActions', 'remediationActions', 'remediationPlan', 'actionPlan']),
                    tableItemsForDomain(domain, ['recommendations', 'management_actions'])
                );
                const affected = uniqueItems(
                    asItems(output, ['affectedUsers', 'users', 'usersMissingMfa', 'usersWithoutMfa', 'missingMfaUsers', 'privilegedUsers', 'affectedEntities', 'entities', 'affectedDevices', 'enrolledUsers', 'mfaMissingUsers']),
                    tableItemsForDomain(domain, ['affected_entities', 'entities', 'users'])
                );
                const evidence = uniqueItems(
                    asItems(output, ['evidenceRows', 'evidence', 'evidenceItems', 'evidenceCatalog', 'sourceEvidence', 'controlAssessment', 'evidenceSummary', 'sourceMetrics', 'currentMetrics', 'scoreJustification', 'activeMailboxes', 'activeThreats', 'enrolledDevices', 'gatewayPolicies', 'dlpProfiles', 'appCategories', 'auditLogs', 'endpointFamilies', 'backupCoverageScore', 'totalStorageGB']),
                    tableItemsForDomain(domain, ['evidence_rows', 'evidence', 'source_metrics'])
                );
                const summary = cleanText(output.domainExecutiveSummary || output.executiveSummary || output.summary || output.currentPosture || domain.domainExecutiveSummary, 'No stored executive summary is available.');
                const impact = cleanText(output.businessImpact || output.businessImpactSummary || output.technicalSummary);
                sectionTitle(labelForDomain(domain));
                doc.font('Helvetica').fontSize(8.3);
                const summaryHeight = doc.heightOfString(summary, { width: contentWidth - 24, lineGap: 2 });
                addPageIfNeeded(62 + summaryHeight);
                const bandY = doc.y;
                doc.roundedRect(left, bandY, contentWidth, 42, 7).fill('#f8fafc').strokeColor('#e1e6ea').stroke();
                if (score != null) {
                    doc.font('Helvetica-Bold').fontSize(8).fillColor(navy).text(`HEALTH ${score}%`, left + 12, bandY + 10, { width: 100 });
                    drawBar(left + 108, bandY + 12, 128, score);
                }
                if (risk != null) {
                    const riskTone = risk >= 70 ? red : risk >= 40 ? orange : green;
                    doc.font('Helvetica-Bold').fontSize(8).fillColor(navy).text(`RISK ${risk}%`, left + 270, bandY + 10, { width: 90 });
                    doc.roundedRect(left + 348, bandY + 12, 148, 7, 3.5).fill('#e1e6ea');
                    doc.roundedRect(left + 348, bandY + 12, Math.max(3, 148 * risk / 100), 7, 3.5).fill(riskTone);
                }
                doc.font('Helvetica-Bold').fontSize(8.5).fillColor(navy).text('Domain executive summary', left + 12, bandY + 53, { width: contentWidth - 24 });
                doc.font('Helvetica').fontSize(8.3).fillColor(slate).text(summary, left + 12, bandY + 66, { width: contentWidth - 24, lineGap: 2 });
                doc.y = bandY + 66 + summaryHeight + 8;
                if (impact) {
                    doc.font('Helvetica-Bold').fontSize(8).fillColor(navy).text('Business impact', left + 12, doc.y, { width: contentWidth - 24 });
                    doc.font('Helvetica').fontSize(7.8).fillColor(slate).text(impact, left + 12, doc.y + 10, { width: contentWidth - 24, lineGap: 1 });
                    doc.moveDown(0.5);
                }
                if (findings.length) drawFlowList('Key findings', findings);
                if (affected.length) drawFlowList('Affected entities', affected);
                if (evidence.length) drawFlowList('Evidence rows and source metrics', evidence);
                if (recommendations.length) drawFlowList('Recommended actions', recommendations);
                doc.moveDown(0.7);
            };
            doc.rect(0, 0, pageWidth, 118).fill(navy);
            if (fs.existsSync(sunbirdLogo)) doc.image(sunbirdLogo, left, 25, { fit: [150, 42] });
            if (fs.existsSync(stackCtrlLogo)) doc.image(stackCtrlLogo, pageWidth - 174, 23, { fit: [134, 44], align: 'right' });
            doc.font('Helvetica').fontSize(8).fillColor('#c8d0d8').text('SECURITY ASSESSMENT REPORT', left, 79, { characterSpacing: 1.1 });
            doc.font('Helvetica').fontSize(8).fillColor('#d9dee3').text(`${formatReportDate(report.period.start)} - ${formatReportDate(report.period.end)}`, pageWidth - 220, 96, { width: 180, align: 'right' });

            const metricY = 132;
            const metricGap = 10;
            const metricWidth = (contentWidth - metricGap * 3) / 4;
            drawMetric(left, metricY, metricWidth, 'HEALTH SCORE', `${report.summary.healthScore}%`, `${report.summary.failures} findings needing attention`);
            drawMetric(left + (metricWidth + metricGap), metricY, metricWidth, 'SUCCESSFUL CONTROLS', report.summary.successes, `${report.summary.totalEvents} events reviewed`);
            drawMetric(left + (metricWidth + metricGap) * 2, metricY, metricWidth, 'ACTIVE INCIDENTS', report.summary.activeIncidents, 'Open or recent issues');
            drawMetric(left + (metricWidth + metricGap) * 3, metricY, metricWidth, 'HIGH ALERTS', report.summary.highSeverityAlerts, 'Critical signal count');

            doc.y = 218;
            const executiveOverview = buildExecutiveOverview();
            if (executiveOverview.metrics.length || Object.values(executiveOverview.sections).some(items => items.length)) {
                sectionTitle('Executive overview');
                drawExecutiveOverview(executiveOverview);
            }

            const allDomainRows = Array.isArray(report.domainInsights?.domains) ? report.domainInsights.domains : [];
            const domainHasRenderableContent = domain => {
                const output = domain.intelligenceOutput || domain.output || {};
                const score = scoreForDomain(domain);
                const risk = riskForDomain(domain);
                const findings = uniqueItems(
                    asItems(output, ['keyFindings', 'findings', 'topFindings', 'risks', 'riskRegister', 'attentionItems', 'securityFindings']),
                    tableItemsForDomain(domain, ['findings', 'risks', 'risk_register'])
                );
                const recommendations = uniqueItems(
                    asItems(output, ['recommendations', 'priorityRecommendations', 'actions', 'nextActions', 'remediationActions', 'remediationPlan', 'actionPlan']),
                    tableItemsForDomain(domain, ['recommendations', 'management_actions'])
                );
                const affected = uniqueItems(
                    asItems(output, ['affectedUsers', 'users', 'usersMissingMfa', 'usersWithoutMfa', 'missingMfaUsers', 'privilegedUsers', 'affectedEntities', 'entities', 'affectedDevices', 'enrolledUsers', 'mfaMissingUsers']),
                    tableItemsForDomain(domain, ['affected_entities', 'entities', 'users'])
                );
                const evidence = uniqueItems(
                    asItems(output, ['evidenceRows', 'evidence', 'evidenceItems', 'evidenceCatalog', 'sourceEvidence', 'controlAssessment', 'evidenceSummary', 'sourceMetrics', 'currentMetrics', 'scoreJustification', 'activeMailboxes', 'activeThreats', 'enrolledDevices', 'gatewayPolicies', 'dlpProfiles', 'appCategories', 'auditLogs', 'endpointFamilies', 'backupCoverageScore', 'totalStorageGB']),
                    tableItemsForDomain(domain, ['evidence_rows', 'evidence', 'source_metrics'])
                );
                return (score != null || risk != null) || (findings.length || affected.length || evidence.length || recommendations.length);
            };
            const identityDomain = allDomainRows.find(isIdentityDomain);
            const devicesDomain = allDomainRows.find(isDevicesDomain);
            const emailSecurityDomain = allDomainRows.find(isEmailSecurityDomain);
            const cloudflareDomain = allDomainRows.find(isCloudflareDomain);
            const applicationsDomain = allDomainRows.find(isApplicationsDomain);
            const securityAlertsDomain = allDomainRows.find(isSecurityAlertsDomain);
            const backupDomain = allDomainRows.find(isBackupDomain);
            const governanceDomain = allDomainRows.find(isGovernanceDomain);
            const complianceDomain = allDomainRows.find(isComplianceDomain);
            const scorecardDomains = allDomainRows.filter(domainHasRenderableContent);
            const domainRows = scorecardDomains.filter(domain => !isIdentityDomain(domain) && !isDevicesDomain(domain) && !isEmailSecurityDomain(domain) && !isCloudflareDomain(domain) && !isApplicationsDomain(domain) && !isSecurityAlertsDomain(domain) && !isBackupDomain(domain) && !isGovernanceDomain(domain) && !isComplianceDomain(domain));
            if (allDomainRows.length && !scorecardDomains.length) {
                console.warn('[Reports] No domain rows considered renderable for PDF; check domain intelligence keys or scores.', { availableKeys: allDomainRows.map(d => d.domainKey || d.domainName) });
            }
            if (scorecardDomains.length) {
                sectionTitle('Enterprise domain scorecard');
                doc.font('Helvetica').fontSize(7.8).fillColor(slate).text('Health is better when higher. Risk requires attention when higher.', left, doc.y, { width: contentWidth });
                doc.y += 14;
                scorecardDomains.forEach(domain => {
                    const health = scoreForDomain(domain);
                    const risk = riskForDomain(domain);
                    addPageIfNeeded(34);
                    const rowY = doc.y;
                    const label = labelForDomain(domain);
                    doc.font('Helvetica-Bold').fontSize(7.5).fillColor(navy).text(label, left, rowY, { width: 142, height: 20 });
                    if (health != null) {
                        doc.font('Helvetica').fontSize(7).fillColor(slate).text('Health', left + 148, rowY, { width: 35 });
                        drawBar(left + 184, rowY + 2, 132, health);
                        doc.font('Helvetica-Bold').fontSize(7).fillColor(navy).text(`${health}%`, left + 320, rowY - 1, { width: 35, align: 'right' });
                    }
                    if (risk != null) {
                        doc.font('Helvetica').fontSize(7).fillColor(slate).text('Risk', left + 365, rowY, { width: 25 });
                        const riskTone = risk >= 70 ? red : risk >= 40 ? orange : green;
                        doc.roundedRect(left + 392, rowY + 2, 105, 7, 3.5).fill('#e1e6ea');
                        doc.roundedRect(left + 392, rowY + 2, Math.max(3, 105 * risk / 100), 7, 3.5).fill(riskTone);
                        doc.font('Helvetica-Bold').fontSize(7).fillColor(navy).text(`${risk}%`, left + 500, rowY - 1, { width: 35, align: 'right' });
                    }
                    doc.y = rowY + 24;
                });
                doc.y += 8;
                sectionTitle('Domain intelligence and evidence');
                doc.font('Helvetica').fontSize(8.2).fillColor(slate).text('Each domain below is drawn from the latest saved intelligence output and keeps findings, affected entities, evidence, and actions together.', left, doc.y, { width: contentWidth, lineGap: 2 });
                doc.moveDown(0.7);
                renderIdentityProtectionReport(identityDomain);
                renderDeviceProtectionReport(devicesDomain);
                renderEmailOrCloudflareReport(emailSecurityDomain, 'email');
                renderEmailOrCloudflareReport(cloudflareDomain, 'cloudflare');
                renderEmailOrCloudflareReport(applicationsDomain, 'applications');
                renderEmailOrCloudflareReport(securityAlertsDomain, 'security-alerts');
                renderEmailOrCloudflareReport(backupDomain, 'backup');
                renderEmailOrCloudflareReport(governanceDomain, 'governance');
                renderEmailOrCloudflareReport(complianceDomain, 'compliance');
                domainRows.forEach(renderDomain);
            } else {
                sectionTitle('Domain intelligence and evidence');
                if (identityDomain || devicesDomain || emailSecurityDomain || cloudflareDomain || applicationsDomain || securityAlertsDomain || backupDomain || governanceDomain || complianceDomain) {
                    renderIdentityProtectionReport(identityDomain);
                    renderDeviceProtectionReport(devicesDomain);
                    renderEmailOrCloudflareReport(emailSecurityDomain, 'email');
                    renderEmailOrCloudflareReport(cloudflareDomain, 'cloudflare');
                    renderEmailOrCloudflareReport(applicationsDomain, 'applications');
                    renderEmailOrCloudflareReport(securityAlertsDomain, 'security-alerts');
                    renderEmailOrCloudflareReport(backupDomain, 'backup');
                    renderEmailOrCloudflareReport(governanceDomain, 'governance');
                    renderEmailOrCloudflareReport(complianceDomain, 'compliance');
                } else {
                    doc.font('Helvetica').fontSize(8.5).fillColor(slate).text('No saved domain intelligence was available for the selected reporting period.', { width: contentWidth });
                }
            }

            const enterpriseOutput = report.finalSynthesis?.finalSynthesis?.synthesisOutput || {};
            const enterpriseActions = asItems(enterpriseOutput.managementReport || {}, ['managementActions', 'actions']);
            const riskRegister = asItems(enterpriseOutput, ['riskRegister', 'recommendations', 'trendAnalysis']);
            if (enterpriseActions.length || riskRegister.length) {
                sectionTitle('Enterprise actions');
                drawFlowList('Management actions', enterpriseActions);
                drawFlowList('Enterprise risks and trends', riskRegister);
            }

            const pageRange = doc.bufferedPageRange();
            for (let pageIndex = 0; pageIndex < pageRange.count; pageIndex += 1) {
                doc.switchToPage(pageIndex);
                const footerY = pageHeight - 50;
                doc.font('Helvetica').fontSize(7).fillColor('#7d8790').text('StackOps IT Solutions | StackCTRL | Security assessment', left, footerY, { width: 330, lineBreak: false });
                doc.text(`Page ${pageIndex + 1}${reportId ? ` | Report #${reportId}` : ''}`, pageWidth - 140, footerY, { width: 100, align: 'right', lineBreak: false });
            }
            doc.end();
        } catch (error) {
            reject(error);
        }
    });
}
function serializeReportListRow(row) {
    return {
        id: row.ID,
        type: row.ReportType,
        periodStart: row.PeriodStart,
        periodEnd: row.PeriodEnd,
        healthScore: row.HealthScore,
        status: row.ReportStatus,
        emailStatus: row.EmailStatus,
        sentAt: row.SentAt,
        createdAt: row.CreatedAt,
        summary: {
            healthScore: Number(row.SummaryHealthScore ?? row.HealthScore ?? 0),
            failures: Number(row.SummaryFailures ?? 0),
            successes: Number(row.SummarySuccesses ?? 0),
            totalEvents: Number(row.SummaryTotalEvents ?? 0)
        }
    };
}

function buildSunbirdReportListOverview(reportRow = null) {
    const payload = parseReportJson(reportRow?.Payload, {});
    const summary = payload.summary || {};
    const analysis = payload.analysis || {};
    return {
        summary: {
            healthScore: clampReportScore(summary.healthScore ?? reportRow?.HealthScore ?? 0),
            status: summary.status || reportRow?.ReportStatus || 'Collecting evidence',
            failures: Number(summary.failures || payload.failures?.length || analysis.failures?.length || 0),
            successes: Number(summary.successes || payload.successes?.length || analysis.successes?.length || 0),
            totalEvents: Number(summary.totalEvents || payload.events?.length || 0)
        },
        analysis: {
            executiveSummary: shortMultilineText(analysis.executiveSummary || 'The latest saved report is ready for review.', 6000),
            successes: compactSunbirdDashboardValue(Array.isArray(analysis.successes) ? analysis.successes.slice(0, SUNBIRD_REPORT_OVERVIEW_MAX_ITEMS) : []),
            failures: compactSunbirdDashboardValue(Array.isArray(analysis.failures) ? analysis.failures.slice(0, SUNBIRD_REPORT_OVERVIEW_MAX_ITEMS) : []),
            recommendations: compactSunbirdDashboardValue(Array.isArray(analysis.recommendations) ? analysis.recommendations.slice(0, SUNBIRD_REPORT_OVERVIEW_MAX_ITEMS) : [])
        },
        successes: compactSunbirdDashboardValue(Array.isArray(payload.successes) ? payload.successes.slice(0, SUNBIRD_REPORT_OVERVIEW_MAX_ITEMS) : []),
        failures: compactSunbirdDashboardValue(Array.isArray(payload.failures) ? payload.failures.slice(0, SUNBIRD_REPORT_OVERVIEW_MAX_ITEMS) : []),
        recommendations: compactSunbirdDashboardValue(Array.isArray(payload.recommendations) ? payload.recommendations.slice(0, SUNBIRD_REPORT_OVERVIEW_MAX_ITEMS) : []),
        events: compactSunbirdDashboardValue(Array.isArray(payload.events) ? payload.events.slice(0, SUNBIRD_REPORT_OVERVIEW_MAX_ITEMS) : []),
        domainScores: compactSunbirdDashboardValue(payload.domainScores || {}),
        trend: compactSunbirdDashboardValue(Array.isArray(payload.trend) ? payload.trend.slice(0, SUNBIRD_REPORT_OVERVIEW_MAX_ITEMS) : [])
    };
}

function buildSunbirdReportIdentityDomain(domain) {
    const source = domain?.intelligenceOutput || {};
    const authoritativeScores = source.authoritativeScores || source.scoreSummary || {};
    const evidenceLimit = 10;
    const entityLimit = 10;
    const compactText = (value, maximum = SUNBIRD_DASHBOARD_MAX_STRING_LENGTH) => String(value || '').slice(0, maximum);
    const evidenceCategories = Array.isArray(source.evidenceCatalog?.categories) ? source.evidenceCatalog.categories : [];
    const compactEntity = (entity = {}) => {
        const lastSignIn = entity.lastSignIn && typeof entity.lastSignIn === 'object' ? entity.lastSignIn : {};
        return {
            entityId: compactText(entity.entityId || entity.id, 160),
            entityName: compactText(entity.entityName || entity.displayName || entity.entityDisplayName, 320),
            entityEmail: compactText(entity.entityEmail || entity.mail || entity.userPrincipalName || entity.entityUser, 320),
            userPrincipalName: compactText(entity.userPrincipalName || entity.entityUser || entity.assignedUser, 320),
            roles: (Array.isArray(entity.roles) ? entity.roles : []).slice(0, 20)
                .map(role => compactText(typeof role === 'object' ? role?.name || role?.displayName : role, 160))
                .filter(Boolean),
            mfaEnabled: entity.mfaEnabled ?? null,
            riskLevel: compactText(entity.riskLevel, 80),
            accountStatus: compactText(entity.accountStatus, 80),
            lastSignIn: {
                device: compactText(lastSignIn.device, 320),
                location: compactText(lastSignIn.location, 320),
                daysSince: lastSignIn.daysSince ?? null,
                status: compactText(lastSignIn.status, 80),
                dateTime: compactText(lastSignIn.dateTime, 80)
            }
        };
    };
    const compactEvidence = (entry = {}) => ({
        label: compactText(entry.label || entry.title || entry.evidenceSource || entry.sourceMetric, 320),
        sourceMetric: compactText(entry.sourceMetric, 160),
        evidenceSource: compactText(entry.evidenceSource || entry.sourceLabel, 320),
        entityCount: Number(entry.entityCount || 0),
        snapshotId: entry.snapshotId ?? domain?.snapshotId ?? null
    });
    const identityEvidenceCategory = (item = {}) => {
        const normalizedMetric = String(item.sourceMetric || '').toLowerCase();
        const title = String(item.title || '').toLowerCase();
        const text = `${item.title || ''} ${item.description || ''} ${item.patternFound || ''}`.toLowerCase();
        const preferredKeys = [
            ...(normalizedMetric ? [normalizedMetric] : []),
            ...(title.includes('missing mfa') ? ['usersWithoutMfa'] : []),
            ...((title.includes('break-glass') || title.includes('global administrator')) && text.includes('mfa') ? ['adminsWithoutMfa'] : []),
            ...(text.includes('external') || text.includes('guest') ? ['externalUsers'] : []),
            ...(text.includes('privileg') || text.includes('multiple role') ? ['privilegedUsers'] : []),
            ...(text.includes('admin') && text.includes('mfa') ? ['adminsWithoutMfa'] : []),
            ...(text.includes('mfa') ? ['usersWithoutMfa'] : []),
            ...(text.includes('inactive') ? ['inactiveUsers'] : []),
            ...(text.includes('high risk') ? ['highRiskUsers'] : []),
            'allUsers'
        ];
        return preferredKeys.map(key => evidenceCategories.find(category =>
            String(category?.key || '').toLowerCase() === key.toLowerCase() ||
            String(category?.sourceMetric || '').toLowerCase() === key.toLowerCase()
        )).find(Boolean) || null;
    };
    const identityFindingEntityCount = item => {
        const text = `${item.title || ''} ${item.description || ''} ${item.patternFound || ''}`.toLowerCase();
        const wordCounts = {
            one: 1, two: 2, three: 3, four: 4, five: 5,
            six: 6, seven: 7, eight: 8, nine: 9, ten: 10,
            eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15,
            twenty: 20, thirty: 30, forty: 40, fifty: 50
        };
        const match = text.match(/\b(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|twenty|thirty|forty|fifty)\s+(?:[a-z-]+\s+){0,3}(?:users?|accounts?|identities|administrators?)\b/i);
        if (!match) return null;
        const value = Number(match[1]);
        return Number.isFinite(value) && value > 0 ? value : (wordCounts[match[1].toLowerCase()] || null);
    };
    const evidenceRecordsForFinding = (item = {}, affectedEntities = []) => {
        const category = identityEvidenceCategory(item);
        const categoryEntities = Array.isArray(category?.entities) ? category.entities : [];
        const affectedIds = new Set(affectedEntities.map(entity => String(entity?.entityId || entity?.id || '')).filter(Boolean));
        const affectedEmails = new Set(affectedEntities.map(entity => String(entity?.entityEmail || entity?.mail || entity?.userPrincipalName || '').toLowerCase()).filter(Boolean));
        const matchingEntities = categoryEntities.filter(entity =>
            affectedIds.has(String(entity?.entityId || entity?.id || '')) ||
            affectedEmails.has(String(entity?.entityEmail || entity?.mail || entity?.userPrincipalName || '').toLowerCase())
        );
        const candidates = categoryEntities.length > matchingEntities.length
            ? categoryEntities
            : (matchingEntities.length ? matchingEntities : (affectedEntities.length ? affectedEntities : categoryEntities));
        const requestedCount = identityFindingEntityCount(item) || Number(category?.count || 0) || candidates.length || affectedEntities.length;
        const uniqueRecords = [];
        const seen = new Set();
        for (const entity of candidates) {
            const key = String(entity?.entityId || entity?.id || entity?.entityEmail || entity?.mail || entity?.userPrincipalName || entity?.displayName || '').toLowerCase();
            if (!key || seen.has(key)) continue;
            seen.add(key);
            uniqueRecords.push(compactEntity(entity));
            if (uniqueRecords.length >= Math.min(evidenceLimit, requestedCount)) break;
        }
        return {
            records: uniqueRecords,
            total: identityFindingEntityCount(item) || Number(category?.count || candidates.length || affectedEntities.length || 0),
            categoryLabel: compactText(category?.label || 'Identity evidence', 160)
        };
    };
    const fallbackRecommendation = (item = {}) => {
        const text = `${item.title || ''} ${item.description || ''} ${item.patternFound || ''}`.toLowerCase();
        if (/mfa|multi-factor|multifactor/.test(text) && /privileg|admin|global/.test(text)) {
            return 'Require MFA for every privileged account, review each privileged role assignment, and remove roles that are not required.';
        }
        if (/mfa|multi-factor|multifactor/.test(text)) {
            return 'Require MFA registration for the affected accounts and restrict access until enrollment is complete.';
        }
        if (/privileg|admin|global administrator|multiple roles/.test(text)) {
            return 'Review privileged role assignments, remove unnecessary roles, and document an approved access-review owner.';
        }
        if (/sign-in|signin|device|location/.test(text)) {
            return 'Investigate the affected sign-ins and devices, then require known, compliant devices for continued access.';
        }
        if (/external|guest/.test(text)) {
            return 'Review external account access, confirm the business owner, and remove access that is no longer required.';
        }
        return 'Review the affected identity records, assign an owner, and complete the remediation supported by this evidence.';
    };
    const compactFinding = (item = {}, findingType) => {
        const evidenceUsed = Array.isArray(item.evidenceUsed) ? item.evidenceUsed : [];
        const evidenceRows = Array.isArray(item.evidenceRows) ? item.evidenceRows : [];
        const affectedEntities = Array.isArray(item.affectedEntities) ? item.affectedEntities : evidenceRows;
        const evidenceRecords = evidenceRecordsForFinding(item, affectedEntities);
        const severity = compactText(item.severity || item.priority || item.riskLevel || (findingType === 'risk' ? 'Unrated' : 'Observed'), 80);
        const impact = compactText(item.impact || item.businessImpact || item.whyItMatters || item.description || item.detail || item.title, SUNBIRD_DASHBOARD_MAX_STRING_LENGTH);
        const suppliedRecommendation = item.firstAction || item.recommendedAction || item.recommendation || item.detail;
        const recommendation = compactText(suppliedRecommendation || fallbackRecommendation(item), SUNBIRD_DASHBOARD_MAX_STRING_LENGTH);
        const evidence = evidenceUsed.length
            ? evidenceUsed.slice(0, evidenceLimit).map(compactEvidence)
            : (evidenceRows.length
                ? [compactEvidence({
                    label: 'StackCTRL Identity Protection evidence',
                    sourceMetric: item.sourceMetric,
                    evidenceSource: item.evidenceSource,
                    entityCount: evidenceRows.length,
                    snapshotId: item.snapshotId
                })]
                : []);
        return {
            findingType,
            title: compactText(item.title || item.patternFound || item.metricName, SUNBIRD_DASHBOARD_MAX_STRING_LENGTH),
            severity,
            impact,
            description: compactText(item.description || item.detail || item.whatHappened, SUNBIRD_DASHBOARD_MAX_STRING_LENGTH),
            whyItMatters: compactText(item.whyItMatters || item.reasoning || item.businessImpact || item.description || item.detail, SUNBIRD_DASHBOARD_MAX_STRING_LENGTH),
            recommendation,
            recommendationSource: suppliedRecommendation ? 'azure' : 'stackctrl_evidence_fallback',
            firstAction: recommendation,
            evidenceSummary: compactText(item.evidenceSummary || (evidence.length ? '' : `${evidenceRows.length || affectedEntities.length} StackCTRL evidence row(s) support this finding.`), SUNBIRD_DASHBOARD_MAX_STRING_LENGTH),
            evidence,
            evidenceRecords: evidenceRecords.records,
            evidenceRecordCount: evidenceRecords.total,
            evidenceCategory: evidenceRecords.categoryLabel,
            affectedEntities: affectedEntities.slice(0, entityLimit).map(compactEntity),
            evidenceRows: evidenceRows.slice(0, evidenceLimit).map(compactEntity),
            sourceMetric: compactText(item.sourceMetric, 160),
            snapshotId: item.snapshotId ?? domain?.snapshotId ?? null
        };
    };
    const risks = (Array.isArray(source.risks) ? source.risks : []).slice(0, 5);
    const keyFindings = (Array.isArray(source.keyFindings) ? source.keyFindings : []).slice(0, 5);
    const findings = [
        ...risks.map(item => compactFinding(item, 'risk')),
        ...keyFindings.map(item => compactFinding(item, 'finding'))
    ];
    const businessImpact = compactText(
        source.businessImpact || source.currentPosture || risks.map(risk => risk.businessImpact || risk.impact || risk.whyItMatters).filter(Boolean).join(' '),
        SUNBIRD_DASHBOARD_MAX_STRING_LENGTH
    );
    return {
        domainKey: domain?.domainKey || 'identity',
        intelligenceOutput: {
            domainExecutiveSummary: compactText(source.domainExecutiveSummary || source.technicalSummary || source.currentPosture),
            businessImpact,
            healthScore: source.healthScore ?? authoritativeScores.healthScore ?? domain?.healthScore ?? null,
            riskScore: source.riskScore ?? authoritativeScores.riskScore ?? domain?.riskScore ?? null,
            riskLevel: compactText(authoritativeScores.riskLevel || source.riskLevel, 80),
            findings,
            risks: findings.filter(finding => finding.findingType === 'risk'),
            recommendations: (Array.isArray(source.recommendations) ? source.recommendations : []).slice(0, 5).map(item => compactFinding(item, 'recommendation'))
        }
    };
}

async function getReportContext(req, res) {
    if (!pool) {
        res.status(503).json({ success: false, message: 'Report database is temporarily unavailable' });
        return null;
    }
    const context = await getAccessContextByUser(req.user);
    if (!context?.companyId) {
        console.warn('[Reports] Company context missing for verified user:', req.user?.email);
        res.status(403).json({
            success: false,
            message: 'Your signed-in account does not include a company ID. Please sign out and sign in again.'
        });
        return null;
    }
    if (!isSunbirdReportAccessContext(context)) {
        res.status(403).json({ success: false, message: 'Sunbird reports are not available for this account' });
        return null;
    }
    const settings = await ensureSunbirdReportSettings(context.companyId, null);
    return { context, settings };
}

app.get('/api/sunbird/reports', authenticateToken, async (req, res) => {
    const operation = beginSunbirdOperation(req, 'reports');
    req.once('aborted', () => operation.step('client_request_aborted'));
    try {
        const reportContext = await getReportContext(req, res);
        if (!reportContext) {
            operation.finish(res.statusCode, { reason: 'report_context_unavailable' });
            return;
        }
        const { context, settings } = reportContext;
        await ensureSunbirdReportsPublicationSchema();
        operation.step('report_context_resolved', { companyId: context.companyId });
        const range = getReportRange(req.query, settings.ActiveSince);
        const limit = Math.max(1, Math.min(50, Number(req.query.limit) || 12));
        // Reconcile a real completed pipeline only when this tenant has no current
        // published daily report. This restores pre-publication runs without fabricating data.
        try {
            const [currentRows] = await pool.query(
                `SELECT ID FROM SunbirdReports WHERE CompanyID = ? AND ReportType = 'daily' AND IsCurrent = 1 LIMIT 1`,
                [context.companyId]
            );
            if (!currentRows.length && typeof enterpriseIntelligenceService?.publishCompletedRun === 'function') {
                const [completedRuns] = await pool.query(
                    `SELECT ID, SnapshotID FROM StackCTRLEnterpriseReportRuns
                     WHERE CompanyID = ? AND SnapshotID IS NOT NULL
                       AND Status IN ('completed', 'completed_with_warnings')
                     ORDER BY CompletedAt DESC, ID DESC LIMIT 1`,
                    [context.companyId]
                );
                if (completedRuns[0]) {
                    const publication = await enterpriseIntelligenceService.publishCompletedRun({
                        companyId: context.companyId,
                        runId: Number(completedRuns[0].ID)
                    });
                    operation.step('completed_pipeline_report_reconciled', {
                        runId: Number(completedRuns[0].ID),
                        snapshotId: Number(completedRuns[0].SnapshotID),
                        reportId: publication.reportId || null
                    });
                }
            }
        } catch (reconciliationError) {
            console.error('[Reports] Completed pipeline reconciliation failed:', reconciliationError.message);
            operation.step('completed_pipeline_report_reconciliation_failed', { error: reconciliationError.message });
        }
        // Load independent saved-data panels in parallel. Each read has its own SQL
        // and application deadline and returns an empty list on failure, so a slow
        // audit/payload query cannot take down the report dashboard.
        const [rows, overviewRows, detailedRows, logRows] = await Promise.all([
            readSunbirdReportRows(
                'Report list',
                `SELECT ID, ReportType, PeriodStart, PeriodEnd, HealthScore, ReportStatus, EmailStatus, SentAt, CreatedAt,
                        CASE WHEN JSON_VALID(Payload) THEN JSON_UNQUOTE(JSON_EXTRACT(Payload, '$.summary.healthScore')) END AS SummaryHealthScore,
                        CASE WHEN JSON_VALID(Payload) THEN JSON_UNQUOTE(JSON_EXTRACT(Payload, '$.summary.failures')) END AS SummaryFailures,
                        CASE WHEN JSON_VALID(Payload) THEN JSON_UNQUOTE(JSON_EXTRACT(Payload, '$.summary.successes')) END AS SummarySuccesses,
                        CASE WHEN JSON_VALID(Payload) THEN JSON_UNQUOTE(JSON_EXTRACT(Payload, '$.summary.totalEvents')) END AS SummaryTotalEvents
                 FROM SunbirdReports
                 WHERE CompanyID = ?
                 ORDER BY IsCurrent DESC, PublishedAt DESC, CreatedAt DESC
                 LIMIT ?`,
                [context.companyId, limit]
            ),
            readSunbirdReportRows(
                'Report overview',
                `SELECT ID, ReportType, PeriodStart, PeriodEnd, HealthScore, ReportStatus, CreatedAt,
                        CASE WHEN OCTET_LENGTH(Payload) <= ? THEN Payload ELSE NULL END AS Payload
                 FROM SunbirdReports
                 WHERE CompanyID = ?
                 ORDER BY IsCurrent DESC, PublishedAt DESC, CreatedAt DESC
                 LIMIT 1`,
                [SUNBIRD_REPORT_OVERVIEW_MAX_PAYLOAD_BYTES, context.companyId]
            ),
            readSunbirdReportRows(
                'Detailed report history',
                `SELECT ID, ReportType, PeriodStart, PeriodEnd, HealthScore, ReportStatus, CreatedAt,
                        CASE WHEN OCTET_LENGTH(Payload) <= ? THEN Payload ELSE NULL END AS Payload
                 FROM SunbirdReports
                 WHERE CompanyID = ?
                 ORDER BY IsCurrent DESC, PublishedAt DESC, CreatedAt DESC
                 LIMIT 8`,
                [SUNBIRD_REPORT_DETAILS_MAX_PAYLOAD_BYTES, context.companyId]
            ),
            readSunbirdReportRows(
                'Report audit history',
                `SELECT ID, ReportID, EventType, EventStatus, Message,
                        CASE WHEN OCTET_LENGTH(Metadata) <= 16384 THEN Metadata ELSE NULL END AS Metadata,
                        ActorUserID, CreatedAt
                 FROM SunbirdReportAuditLogs
                 WHERE CompanyID = ? AND CreatedAt BETWEEN ? AND ?
                 ORDER BY CreatedAt DESC
                 LIMIT 120`,
                [context.companyId, range.start, range.end]
            )
        ]);
        const detailedReports = detailedRows.map(row => {
            const payload = parseReportJson(row.Payload, {});
            const analysis = payload?.analysis || {};
            return {
                ...row,
                HasIntelligence: payload?.generatedWithAi === true
                    || Boolean(payload?.finalSynthesis)
                    || /Final enterprise synthesis/i.test(String(analysis?.generatedBy || ''))
                    ? 1
                    : 0
            };
        });
        operation.step('saved_report_data_loaded', { reports: rows.length, auditLogs: logRows.length, detailedReports: detailedReports.length });
        // Live intelligence enriches the page but cannot block the saved report/history
        // response. Slow domains are omitted for this request and recover next refresh.
        operation.step('live_domain_intelligence_start');
        const liveIntelligence = await fetchSunbirdPowerBIIntelligence(context.companyId, {
            domainTimeoutMs: SUNBIRD_REPORT_LIVE_DOMAIN_TIMEOUT_MS
        });
        operation.step('live_domain_intelligence_complete', { domains: liveIntelligence?.domains?.length || 0, timedOutDomains: liveIntelligence?.completeness?.timedOutDomains || [] });
        operation.step('live_final_synthesis_start');
        const liveFinal = liveIntelligence
            ? await fetchSunbirdPowerBIFinal(
                context.companyId,
                liveIntelligence.perDomainLatest ? null : (liveIntelligence.latestRunId || null),
                { timeoutMs: SUNBIRD_REPORT_LIVE_FINAL_TIMEOUT_MS }
            )
            : null;
        operation.step('live_final_synthesis_complete', { available: Boolean(liveFinal?.finalSynthesis) });
        const liveReport = safelyBuildSunbirdReportView(
            'Live intelligence snapshot',
            () => buildSunbirdLiveIntelligenceSnapshot(liveIntelligence, liveFinal)
        );
        const liveIdentityDomain = Array.isArray(liveIntelligence?.domains)
            ? liveIntelligence.domains.find(domain => String(domain?.domainKey || '').toLowerCase() === 'identity')
            : null;
        const fallbackIdentityDomain = liveIdentityDomain
            ? null
            : await withSunbirdReportTimeout(
                () => fetchSunbirdIdentityDomainIntelligence(context.companyId, { timeoutMs: SUNBIRD_REPORT_LIVE_IDENTITY_TIMEOUT_MS }),
                SUNBIRD_REPORT_LIVE_IDENTITY_TIMEOUT_MS,
                'Live identity intelligence'
            ).catch(error => {
                console.warn('[Reports] Identity live read skipped:', error.message);
                return null;
            });
        const identityDomain = safelyBuildSunbirdReportView(
            'Identity report view',
            () => buildSunbirdReportIdentityDomain(liveIdentityDomain || fallbackIdentityDomain),
            () => buildSunbirdReportIdentityDomain(null)
        );
        operation.step('identity_intelligence_loaded', { risks: identityDomain.intelligenceOutput.risks.length });
        const preferredDetailedRow =
            detailedReports.find(row => Number(row.HasIntelligence) === 1 && parseReportJson(row.Payload, null)?.domainInsights?.domains?.length) ||
            detailedReports.find(row => parseReportJson(row.Payload, null)?.domainInsights?.domains?.length) ||
            detailedReports.find(row => Number(row.HasIntelligence) === 1) ||
            detailedReports[0] ||
            null;
        const latestReport = liveReport || safelyBuildSunbirdReportView(
            'Saved latest-report snapshot',
            () => buildSunbirdLatestReportSnapshot(preferredDetailedRow)
        );
        const overview = safelyBuildSunbirdReportView(
            'Report overview',
            () => buildSunbirdLiveOverview(liveReport)
                || buildSunbirdReportListOverview(preferredDetailedRow || overviewRows[0] || rows[0]),
            () => buildSunbirdReportListOverview(null)
        );
        try {
            await withSunbirdReportTimeout(
                () => writeSunbirdReportLog({
                    companyId: context.companyId,
                    eventType: 'report_center_viewed',
                    status: 'success',
                    message: `Report center loaded for ${req.query.range || '30d'}.`,
                    metadata: { rangeStart: range.start, rangeEnd: range.end },
                    actorUserId: req.user.id || null
                }),
                1500,
                'Report view audit'
            );
        } catch (auditError) {
            // The dashboard must remain available even if a non-essential audit insert fails.
            console.warn('[Reports] Unable to record report-center view:', auditError.message);
        }
        operation.step('audit_log_written', {
            liveRunId: liveReport?.enterpriseRunId || null,
            liveSnapshotId: liveReport?.snapshotId || null,
            source: liveReport ? 'enterprise_run' : 'saved_report_fallback'
        });
        const responsePayload = {
            success: true,
            settings: {
                weeklyEnabled: Boolean(settings.WeeklyEnabled && Number(settings.RecipientConfirmed) === 1 && normalizeReportRecipientEmails(settings.RecipientEmail).length),
                recipientEmail: settings.RecipientEmail || '',
                deliveryDay: settings.DeliveryDay,
                deliveryHour: settings.DeliveryHour,
                activeSince: settings.ActiveSince,
                lastDailyCollectionDate: settings.LastDailyCollectionDate,
                lastWeeklyReportDate: settings.LastWeeklyReportDate,
                timeZone: SUNBIRD_REPORT_TIME_ZONE,
                timeZoneLabel: 'SAST (UTC+02:00)',
                lastHourlyAutomationAt: settings.LastHourlyAutomationAt || null,
                lastHourlyAutomationStatus: settings.LastHourlyAutomationStatus || null,
                lastHourlyAutomationMessage: settings.LastHourlyAutomationMessage || null,
                lastHourlyAutomationRunId: settings.LastHourlyAutomationRunID || null,
                lastHourlyAutomationSnapshotId: settings.LastHourlyAutomationSnapshotID || null,
                lastHourlyAutomationReportId: settings.LastHourlyAutomationReportID || null
            },
            range: { start: range.start, end: range.end },
            overview,
            latestReport,
            identityDomain,
            reports: rows.map(serializeReportListRow),
            logs: logRows.map(serializeReportAuditLog)
        };
        // This endpoint is the live report source; a cached GET can otherwise keep an
        // older domain run visible after a newer domain analysis completes.
        res.set('Cache-Control', 'no-store, max-age=0');
        sendSunbirdJson(res, responsePayload, operation);
        operation.finish(200, { reports: rows.length, auditLogs: logRows.length });
    } catch (error) {
        operation.step('report_load_failed', { error: error.message, code: error.code || null, stack: String(error.stack || '').slice(0, 1800) });
        console.error('[Reports] List error:', error);
        operation.finish(500, { error: error.message });
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/sunbird/reports/live-evidence', authenticateToken, async (req, res) => {
    try {
        const reportContext = await getReportContext(req, res);
        if (!reportContext) return;
        const { context } = reportContext;
        const domainKey = String(req.query.domainKey || '').trim();
        const evidenceIds = [...new Set(String(req.query.evidenceIds || '')
            .split(',').map(value => value.trim().toLowerCase()).filter(Boolean))];
        if (!domainKey) {
            return res.status(400).json({ success: false, message: 'A domain key is required for live evidence.' });
        }
        // A metric/category is not a link to an individual record. With no explicit
        // IDs, deliberately return no rows instead of exposing unrelated domain data.
        if (!evidenceIds.length) {
            return res.json({
                success: true,
                strictLinking: true,
                domainKey,
                evidence: [],
                message: 'No specific source evidence was attached to this finding.'
            });
        }
        const intelligence = await fetchSunbirdPowerBIIntelligence(context.companyId);
        const domain = (intelligence?.domains || []).find(item => String(item?.domainKey || '').toLowerCase() === domainKey.toLowerCase());
        if (!domain) {
            return res.status(404).json({ success: false, message: 'No current completed intelligence is available for this domain.' });
        }
        const output = domain.intelligenceOutput || domain.output || {};
        const categories = Array.isArray(output?.evidenceCatalog?.categories) ? output.evidenceCatalog.categories : [];
        const categoryRows = categories.flatMap(category => (Array.isArray(category?.entities) ? category.entities : []).map(entity => ({
            ...entity,
            sourceMetric: entity?.sourceMetric || category?.sourceMetric || category?.key || '',
            evidenceSource: entity?.evidenceSource || category?.label || category?.sourceMetric || category?.key || ''
        })));
        const tableRows = Object.entries(intelligence?.tables || {})
            .filter(([tableName]) => /evidence|entities|affected|control/i.test(tableName))
            .flatMap(([, table]) => Array.isArray(table) ? table : [])
            .filter(row => String(row?.domainKey || row?.DomainKey || '').toLowerCase() === String(domain.domainKey || '').toLowerCase());
        const rowIds = row => {
            const source = ['evidenceRow', 'affectedEntity', 'data', 'entity', 'record', 'ProcessedEvidenceJson'].reduce((record, key) => {
                const nested = record?.[key];
                return nested && typeof nested === 'object' && !Array.isArray(nested) ? { ...record, ...nested } : record;
            }, { ...(row || {}) });
            return [
                source.entityId, source.id, source.recordId, source.sourceAlertId, source.alertId,
                source.SourceID, source.userId, source.deviceId, source.controlId, source.applicationId,
                source.entityEmail, source.mail, source.userPrincipalName, source.entityName,
                source.displayName, source.deviceName, source.controlName, source.applicationName,
                source.alertName, source.name, source.title, source.label
            ].map(value => String(value || '').trim().toLowerCase()).filter(Boolean);
        };
        const seen = new Set();
        const evidence = [...categoryRows, ...tableRows].filter(row => {
            const matchedId = rowIds(row).find(id => evidenceIds.includes(id));
            if (!matchedId || seen.has(matchedId)) return false;
            seen.add(matchedId);
            return true;
        });
        res.json({
            success: true,
            strictLinking: true,
            enterpriseRunId: Number(domain.runId || 0),
            snapshotId: domain.snapshotId == null ? null : Number(domain.snapshotId),
            domainKey: domain.domainKey,
            domainName: domain.domainName,
            evidence
        });
    } catch (error) {
        console.error('[Reports] Live evidence error:', error);
        res.status(500).json({ success: false, message: 'Live evidence could not be loaded.' });
    }
});
app.post('/api/sunbird/reports/generate', authenticateToken, async (req, res) => {
    const operation = beginSunbirdOperation(req, 'report_generate');
    try {
        const reportContext = await getReportContext(req, res);
        if (!reportContext) {
            operation.finish(res.statusCode, { reason: 'report_context_unavailable' });
            return;
        }
        const { context, settings } = reportContext;
        const includeAi = !(
            req.body?.includeAi === false ||
            String(req.body?.includeAi).toLowerCase() === 'false'
        );
        const range = getReportRange(req.body || {}, settings.ActiveSince);
        await writeSunbirdReportLog({
            companyId: context.companyId,
            eventType: 'manual_report_requested',
            status: 'started',
            message: 'On-demand ' + (req.body?.range || '30d') + ' report requested.' + (includeAi ? ' AI-enabled' : ''),
            metadata: { rangeStart: range.start, rangeEnd: range.end, includeAi },
            actorUserId: req.user.id || null
        });
        operation.step('report_build_started', { companyId: context.companyId, includeAi });
        const report = await saveSunbirdReport(context.companyId, 'manual', range.start, range.end, req.user.id || null, includeAi);
        operation.step('report_persisted', {
            reportId: report.id,
            payloadBytes: Buffer.byteLength(JSON.stringify(report.payload)),
            domainCount: Array.isArray(report.payload?.domainInsights?.domains) ? report.payload.domainInsights.domains.length : 0,
            enterpriseRunId: report.payload?.enterpriseRunId || null
        });
        res.status(201).json({
            success: true,
            report: {
                id: report.id,
                generatedWithAi: includeAi,
                summary: report.payload.summary,
                enterpriseRunId: report.payload.enterpriseRunId || null,
                domainCount: Array.isArray(report.payload?.domainInsights?.domains) ? report.payload.domainInsights.domains.length : 0
            }
        });
        operation.finish(201, { reportId: report.id });
    } catch (error) {
        operation.step('report_generation_failed', { error: error.message, code: error.code || null, stack: String(error.stack || '').slice(0, 1800) });
        operation.finish(500, { error: error.message });
        console.error('[Reports] Generate error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/sunbird/reports/:id/pdf', authenticateToken, async (req, res) => {
    const startTime = Date.now();
    try {
        const reportContext = await getReportContext(req, res);
        if (!reportContext) return;
        const { context } = reportContext;
        
        console.log(`[Reports] PDF generation starting for report #${req.params.id}`);
        
        const [rows] = await pool.query(
            'SELECT * FROM SunbirdReports WHERE ID = ? AND CompanyID = ? LIMIT 1',
            [req.params.id, context.companyId]
        );
        if (!rows.length) return res.status(404).json({ success: false, message: 'Report not found' });
        
        const report = parseReportJson(rows[0].Payload, {});
        report.period = {
            ...(report.period || {}),
            start: rows[0].PeriodStart ? new Date(rows[0].PeriodStart).toISOString() : report.period?.start,
            end: rows[0].PeriodEnd ? new Date(rows[0].PeriodEnd).toISOString() : report.period?.end
        };
        
        // Generate PDF with timeout protection
        let pdf;
        try {
            pdf = await Promise.race([
                generateSunbirdReportPdf(report, rows[0].ID),
                new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('PDF generation timeout (>60s)')), 60000)
                )
            ]);
        } catch (genErr) {
            console.error(`[Reports] PDF generation failed for report #${req.params.id}:`, genErr.message);
            return res.status(503).json({ 
                success: false, 
                message: `PDF generation failed: ${genErr.message}. Please try again in a moment.`,
                error: process.env.NODE_ENV === 'development' ? genErr.message : undefined
            });
        }
        
        const filename = `StackCTRL-${String(report.companyName || 'report').replace(/[^a-z0-9]+/gi, '-')}-${new Date(rows[0].PeriodEnd).toISOString().slice(0, 10)}.pdf`;
        
        console.log(`[Reports] PDF generated successfully for report #${req.params.id} (${pdf.length} bytes, ${Date.now() - startTime}ms)`);
        
        await writeSunbirdReportLog({
            companyId: context.companyId,
            reportId: rows[0].ID,
            eventType: 'pdf_downloaded',
            status: 'success',
            message: `${filename} downloaded from the report center.`,
            metadata: { filename, bytes: pdf.length },
            actorUserId: req.user.id || null
        });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Length', pdf.length);
        res.send(pdf);
    } catch (error) {
        console.error('[Reports] PDF endpoint error:', error);
        const duration = Date.now() - startTime;
        
        // Check if it's a memory issue
        if (error.message && error.message.includes('memory')) {
            return res.status(503).json({ 
                success: false, 
                message: 'Server memory limit reached. Please try again in a moment.',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
        
        res.status(500).json({ 
            success: false, 
            message: error.message || 'Failed to generate PDF',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

app.put('/api/sunbird/reports/settings', authenticateToken, async (req, res) => {
    try {
        const reportContext = await getReportContext(req, res);
        if (!reportContext) return;
        const { context } = reportContext;
        const requestedRecipientEmail = req.body?.recipientEmail || '';
        if (hasInvalidReportRecipients(requestedRecipientEmail)) {
            return res.status(400).json({ success: false, message: 'Only valid report recipient email addresses are allowed' });
        }
        const recipientEmail = formatReportRecipientList(requestedRecipientEmail);
        const weeklyEnabled = req.body?.weeklyEnabled === false ? 0 : 1;
        if (weeklyEnabled && !recipientEmail) {
            return res.status(400).json({ success: false, message: 'Choose at least one report recipient before enabling weekly email' });
        }
        await pool.query(
            `UPDATE SunbirdReportSettings
             SET WeeklyEnabled = ?, RecipientEmail = ?, RecipientConfirmed = ?
             WHERE CompanyID = ?`,
            [weeklyEnabled, recipientEmail || null, recipientEmail ? 1 : 0, context.companyId]
        );
        await writeSunbirdReportLog({
            companyId: context.companyId,
            eventType: 'automation_settings_updated',
            status: 'success',
            message: recipientEmail
                ? `Weekly report email ${weeklyEnabled ? 'enabled' : 'paused'} for ${recipientEmail}.`
                : 'Weekly report email paused with no chosen recipient.',
            metadata: { weeklyEnabled: Boolean(weeklyEnabled), recipientEmail: recipientEmail || null },
            actorUserId: req.user.id || null
        });
        res.json({ success: true, weeklyEnabled: Boolean(weeklyEnabled), recipientEmail });
    } catch (error) {
        console.error('[Reports] Settings error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

async function getSunbirdReportCompanyIds() {
    const [rows] = await pool.query(`
        SELECT DISTINCT report_companies.CompanyID FROM (
            SELECT CompanyID FROM SecurityEventsPayloadCache
            UNION SELECT CompanyID FROM IdentityMetricsCache
            UNION SELECT CompanyID FROM BackupRecoveryPayloadCache
            UNION SELECT CompanyID FROM ApplicationMetricsCache
            UNION SELECT CompanyID FROM SunbirdReportSettings
        ) report_companies
        JOIN Companies c ON c.ID = report_companies.CompanyID
        LEFT JOIN Users u ON u.CompanyID = report_companies.CompanyID
        LEFT JOIN TenantAccessControl ta ON ta.UserID = u.ID
        WHERE report_companies.CompanyID IS NOT NULL
          AND (
            LOWER(COALESCE(ta.AccessType, '')) = 'sunbird'
            OR LOWER(COALESCE(c.CompanyName, c.companyname, '')) LIKE '%sunbird%'
          )
    `);
    return rows.map(row => row.CompanyID);
}

function renderWeeklyDailyReportEmailRows(dailyReports = []) {
    if (!Array.isArray(dailyReports) || !dailyReports.length) {
        return `
            <tr>
                <td colspan="5" style="padding:12px;border:1px solid #d9e1e8;color:#64748b;">
                    No saved daily report snapshots were available for this weekly period yet.
                </td>
            </tr>
        `;
    }
    return dailyReports.slice(0, 7).map(day => {
        const health = Number(day.healthScore || 0);
        const tone = health >= 85 ? '#15803d' : health >= 70 ? '#b45309' : '#b91c1c';
        const signal = day.topFailure || day.topRecommendation || day.topSuccess || 'Daily evidence collected.';
        return `
            <tr>
                <td style="padding:10px;border:1px solid #d9e1e8;color:#334155;">${escapeHtml(formatReportDate(day.periodEnd || day.date))}</td>
                <td style="padding:10px;border:1px solid #d9e1e8;color:${tone};font-weight:700;text-align:center;">${health}%</td>
                <td style="padding:10px;border:1px solid #d9e1e8;color:#334155;text-align:center;">${Number(day.failures || 0)}</td>
                <td style="padding:10px;border:1px solid #d9e1e8;color:#334155;text-align:center;">${Number(day.successes || 0)}</td>
                <td style="padding:10px;border:1px solid #d9e1e8;color:#475569;">${escapeHtml(signal)}</td>
            </tr>
        `;
    }).join('');
}

function renderWeeklyCloudflareReportEmailSection(report) {
    const cloudflare = report?.cloudflare;
    if (!cloudflare?.summary) return '';

    const summary = cloudflare.summary;
    const problems = Array.isArray(cloudflare.problems) ? cloudflare.problems.slice(0, 4) : [];
    const recommendations = Array.isArray(cloudflare.recommendations) ? cloudflare.recommendations.slice(0, 3) : [];
    const problemRows = problems.length
        ? problems.map(item => `
            <li style="margin:0 0 7px;">
                <strong>${escapeHtml(item.title || 'Cloudflare item')}</strong><br>
                <span style="color:#475569;">${escapeHtml(item.detail || item.source || 'Review Cloudflare One evidence.')}</span>
            </li>
        `).join('')
        : '<li style="margin:0;color:#475569;">No high-severity Cloudflare problems were recorded for this period.</li>';
    const recommendationRows = recommendations.length
        ? `<p style="margin:10px 0 0;color:#334155;"><strong>Recommended:</strong> ${escapeHtml(recommendations.map(item => item.title || item.detail).filter(Boolean).join('; '))}</p>`
        : '';

    return `
        <div style="margin:18px 0;padding:16px;border:1px solid #d9e1e8;border-left:4px solid #f97316;background:#fffaf5;">
            <h3 style="margin:0 0 10px;color:#17212b;font-size:16px;">Cloudflare One / Zero Trust</h3>
            <p style="margin:0 0 10px;color:#334155;">
                <strong>Network security score:</strong> ${escapeHtml(String(cloudflare.score ?? 'N/A'))}%
                &nbsp;|&nbsp; <strong>Protected apps:</strong> ${Number(summary.protectedApps || 0)}
                &nbsp;|&nbsp; <strong>Gateway policies:</strong> ${Number(summary.gatewayPolicies || 0)}
                &nbsp;|&nbsp; <strong>DLP profiles:</strong> ${Number(summary.dlpProfiles || 0)}
            </p>
            <ul style="margin:0 0 0 18px;padding:0;color:#334155;">${problemRows}</ul>
            ${recommendationRows}
        </div>
    `;
}

async function sendWeeklySunbirdReport(companyId, settings, reportRecord) {
    const pdf = await generateSunbirdReportPdf(reportRecord.payload, reportRecord.id);
    if (Number(settings.RecipientConfirmed) !== 1) throw new Error('Report recipient must be chosen and saved before weekly email can be sent');
    const recipients = normalizeReportRecipientEmails(settings.RecipientEmail);
    if (!recipients.length) throw new Error('No explicitly chosen report recipient is configured');
    const recipientList = recipients.join(', ');
    await writeSunbirdReportLog({
        companyId,
        reportId: reportRecord.id,
        eventType: 'weekly_email_sending',
        status: 'started',
        message: `Weekly PDF email is being sent to ${recipientList}.`,
        metadata: { recipients }
    });
    const report = reportRecord.payload;
    const subject = `Weekly StackCTRL Report | ${report.companyName} | ${formatReportDate(report.period.end)}`;
    const html = renderCorporateEmail({
        title: 'Your weekly StackCTRL report',
        greeting: `Dear ${report.companyName} Team,`,
        bodyHtml: `
            <p>Your automated weekly dashboard report is attached.</p>
            <div style="margin:18px 0;padding:16px;border:1px solid #d9e1e8;border-left:4px solid #f97316;background:#f7f9fb;">
                <p style="margin:0 0 8px;"><strong>Security health:</strong> ${report.summary.healthScore}%</p>
                <p style="margin:0 0 8px;"><strong>Failures:</strong> ${report.summary.failures}</p>
                <p style="margin:0;"><strong>Period:</strong> ${formatReportDate(report.period.start)} - ${formatReportDate(report.period.end)}</p>
            </div>
            ${renderWeeklyCloudflareReportEmailSection(report)}
            <h3 style="margin:20px 0 8px;color:#17212b;font-size:16px;">Daily report summary for the week</h3>
            <table role="presentation" cellspacing="0" cellpadding="0" style="width:100%;border-collapse:collapse;margin:0 0 18px;font-size:13px;">
                <thead>
                    <tr>
                        <th style="padding:9px;border:1px solid #d9e1e8;background:#eef2f6;color:#334155;text-align:left;">Day</th>
                        <th style="padding:9px;border:1px solid #d9e1e8;background:#eef2f6;color:#334155;text-align:center;">Health</th>
                        <th style="padding:9px;border:1px solid #d9e1e8;background:#eef2f6;color:#334155;text-align:center;">Problems</th>
                        <th style="padding:9px;border:1px solid #d9e1e8;background:#eef2f6;color:#334155;text-align:center;">Successes</th>
                        <th style="padding:9px;border:1px solid #d9e1e8;background:#eef2f6;color:#334155;text-align:left;">Main signal</th>
                    </tr>
                </thead>
                <tbody>${renderWeeklyDailyReportEmailRows(report.dailyReports)}</tbody>
            </table>
            <p>${escapeHtml(report.analysis?.executiveSummary || '')}</p>
            <p>The attached PDF includes the weekly executive summary, evidence timeline, recommendations, and the full daily report breakdown for the week.</p>
            <p>Open the Reports tab in StackCTRL to review the complete history, generate a fresh PDF, or download any saved report.</p>
        `
    });
    for (const recipient of recipients) {
        await sendEmail(recipient, subject, html, true, [{
            name: `StackCTRL-Weekly-Report-${new Date(report.period.end).toISOString().slice(0, 10)}.pdf`,
            contentType: 'application/pdf',
            content: pdf
        }]);
    }
    await pool.query(
        `UPDATE SunbirdReports SET EmailStatus = 'sent', SentAt = NOW() WHERE ID = ?`,
        [reportRecord.id]
    );
    await writeSunbirdReportLog({
        companyId,
        reportId: reportRecord.id,
        eventType: 'weekly_email_sent',
        status: 'success',
        message: `Weekly PDF report emailed to ${recipientList}.`,
        metadata: { recipients, bytes: pdf.length }
    });
}

async function sendSunbirdAutomationStartNotice(companyId, companyName, localDate) {
    const recipient = 'maambelanduni@stackopsit.co.za';
    const subject = `StackCTRL automation started | ${companyName} | ${localDate}`;
    const html = renderCorporateEmail({
        title: 'Daily StackCTRL automation started',
        greeting: 'Dear Maambelanduni,',
        bodyHtml: `
            <p>The daily Sunbird automation cycle has started successfully.</p>
            <div style="margin:18px 0;padding:16px;border:1px solid #d9e1e8;border-left:4px solid #f97316;background:#f7f9fb;">
                <p style="margin:0 0 8px;"><strong>Company:</strong> ${escapeHtml(companyName || `Company #${companyId}`)}</p>
                <p style="margin:0 0 8px;"><strong>Cycle date:</strong> ${escapeHtml(localDate)}</p>
                <p style="margin:0;"><strong>Status:</strong> Started</p>
            </div>
            <p>This notification confirms start-of-day activation. Report generation and delivery will continue through the configured automation schedule.</p>
        `
    });
    await sendEmail(recipient, subject, html, true);
}

async function runSunbirdReportAutomation() {
    if (!pool) return;
    const now = new Date();
    const local = getJohannesburgDateParts(now);
    const localDate = `${local.year}-${local.month}-${local.day}`;
    const localHour = Number(local.hour || 0);
    const isFriday = local.weekday === 'Fri';
    try {
        const companyIds = await getSunbirdReportCompanyIds();
        for (const companyId of companyIds) {
            const settings = await ensureSunbirdReportSettings(companyId, null);
            const chosenRecipients = normalizeReportRecipientEmails(settings.RecipientEmail);
            const recipientConfirmed = Number(settings.RecipientConfirmed) === 1;
            const [companyRows] = await pool.query('SELECT CompanyName FROM Companies WHERE ID = ? LIMIT 1', [companyId]);
            const companyName = companyRows[0]?.CompanyName || `Company #${companyId}`;
            const lastDaily = settings.LastDailyCollectionDate
                ? new Date(settings.LastDailyCollectionDate).toISOString().slice(0, 10)
                : null;
            const lastAutomationStartNoticeDate = settings.LastAutomationStartNoticeDate
                ? new Date(settings.LastAutomationStartNoticeDate).toISOString().slice(0, 10)
                : null;
            if (lastDaily !== localDate) {
                if (lastAutomationStartNoticeDate !== localDate) {
                    try {
                        await sendSunbirdAutomationStartNotice(companyId, companyName, localDate);
                        await pool.query(
                            'UPDATE SunbirdReportSettings SET LastAutomationStartNoticeDate = ? WHERE CompanyID = ?',
                            [localDate, companyId]
                        );
                    } catch (noticeError) {
                        console.warn(`[Reports Automation] Start notice email failed for company ${companyId}:`, noticeError.message);
                    }
                }
                const dayStart = new Date(now);
                dayStart.setUTCDate(dayStart.getUTCDate() - 1);
                try {
                    await saveSunbirdReport(companyId, 'daily', dayStart, now, null, true);
                } catch (aiError) {
                    console.warn(`[Reports Automation] Daily AI report generation failed for company ${companyId}; retrying with deterministic fallback:`, aiError.message);
                    await saveSunbirdReport(companyId, 'daily', dayStart, now, null, false);
                }
                await pool.query(
                    'UPDATE SunbirdReportSettings SET LastDailyCollectionDate = ? WHERE CompanyID = ?',
                    [localDate, companyId]
                );
            }
            const lastWeekly = settings.LastWeeklyReportDate
                ? new Date(settings.LastWeeklyReportDate).toISOString().slice(0, 10)
                : null;
            if (settings.WeeklyEnabled && recipientConfirmed && chosenRecipients.length && isFriday && localHour >= Number(settings.DeliveryHour || 8) && lastWeekly !== localDate) {
                const weekStart = new Date(now);
                weekStart.setUTCDate(weekStart.getUTCDate() - 7);
                const reportRecord = await saveSunbirdReport(companyId, 'weekly', weekStart, now, null, true);
                try {
                    await sendWeeklySunbirdReport(companyId, settings, reportRecord);
                    await pool.query(
                        'UPDATE SunbirdReportSettings SET LastWeeklyReportDate = ? WHERE CompanyID = ?',
                        [localDate, companyId]
                    );
                } catch (emailError) {
                    await pool.query(
                        `UPDATE SunbirdReports SET EmailStatus = 'failed' WHERE ID = ?`,
                        [reportRecord.id]
                    );
                    await writeSunbirdReportLog({
                        companyId,
                        reportId: reportRecord.id,
                        eventType: 'weekly_email_failed',
                        status: 'failed',
                        message: `Weekly report email failed: ${emailError.message}`,
                        metadata: { recipients: chosenRecipients }
                    });
                    throw emailError;
                }
            }
        }
    } catch (error) {
        console.error('[Reports Automation] Error:', error.message);
    }
}

// API endpoint for admin to get all bookings (updated from original)
app.get('/api/admin/bookings', authenticateToken, async (req, res) => {
    try {
        let bookings;

        if (!pool) {
            throw new Error('MySQL pool is not available.');
        }
        const [rows] = await pool.query('SELECT date, time, clientname as name, email, service, message FROM appointment WHERE clientname IS NOT NULL ORDER BY date DESC, time ASC');
        bookings = rows;

        res.json(bookings);
    } catch (error) {
        console.error('Error fetching admin bookings:', error);
        res.status(500).send('Server error.');
    }
});

// API endpoint for admin to get schedule for a date (added from original)
app.get('/api/admin/schedule', authenticateToken, async (req, res) => {
    const { date } = req.query;

    if (!date) {
        return res.status(400).send('Date is required.');
    }

    try {
        let bookings;

        if (!pool) {
            throw new Error('MySQL pool is not available.');
        }
        const [rows] = await pool.query(
            'SELECT * FROM appointment WHERE date = ? ORDER BY time ASC',
            [date]
        );
        bookings = rows;

        // Standard times array for comparison to ensure all standard slots are present
        const standardTimes = ['09:00:00', '10:00:00', '11:00:00', '14:00:00', '15:00:00'];
        const existingTimes = new Set(bookings.map(b => b.time));
        
        // Add default available slots if they don't exist for the day
        for (const time of standardTimes) {
            if (!existingTimes.has(time)) {
                // Insert new available slot
                const newSlot = { date, time, is_available: true, clientname: null, email: null, service: null, message: null };
                if (!pool) {
                    throw new Error('MySQL pool is not available.');
                }
                await pool.query('INSERT INTO appointment (date, time, is_available) VALUES (?, ?, ?)', [date, time, true]);
                bookings.push(newSlot); // Add to the array for the response
            }
        }
        
        // Sort the final list by time
        bookings.sort((a, b) => a.time.localeCompare(b.time));

        res.json(bookings);

    } catch (error) {
        console.error('Error fetching admin schedule:', error);
        res.status(500).send('Server error.');
    }
});

// managing admin availability (updated from original, FIXED syntax error)
app.post('/api/admin/availability', authenticateToken, async (req, res) => {
    const { date, time } = req.body;
    let { isAvailable } = req.body; 
    
    if (isAvailable !== undefined) {  // FIXED: Added 'undefined'
        isAvailable = (isAvailable === true || isAvailable === 'true');
    }

    if (!date || !time || isAvailable === undefined) {
        return res.status(400).send('Missing required availability data.');
    }

    try {
        if (!pool) {
            throw new Error('MySQL pool is not available.');
        }
        await pool.query(
            'UPDATE appointment SET is_available = ?, clientname = NULL, email = NULL, service = NULL, message = NULL WHERE date = ? AND time = ?',
            [isAvailable, date, time]
        );

        res.status(200).send('Availability updated successfully.');
    } catch (error) {
        console.error('Error updating availability:', error);
        res.status(500).send('Server error.');
    }
});

const MICROSOFT_PORTAL_OAUTH_COOKIE = 'stackctrl_microsoft_oauth';
const MICROSOFT_PORTAL_BOOTSTRAP_COOKIE = 'stackctrl_microsoft_login';
const MICROSOFT_PORTAL_OAUTH_TTL_MS = 10 * 60 * 1000;
const MICROSOFT_PORTAL_BOOTSTRAP_TTL_MS = 2 * 60 * 1000;
const MICROSOFT_PORTAL_PUBLIC_HOSTS = new Set(['stackopsit.co.za', 'stackopsit.com']);
const microsoftPortalOidcMetadataCache = new Map();
const microsoftPortalOidcJwksCache = new Map();
let microsoftPortalAuthConfigPromise = null;

function microsoftPortalCookieOptions(maxAge, path = '/') {
    return { httpOnly: true, secure: Boolean(process.env.K_SERVICE) || process.env.NODE_ENV === 'production', sameSite: 'lax', path, maxAge };
}

function readRequestCookie(req, name) {
    const cookieHeader = String(req.headers.cookie || '');
    const prefix = `${name}=`;
    const match = cookieHeader.split(';').map(item => item.trim()).find(item => item.startsWith(prefix));
    return match ? decodeURIComponent(match.slice(prefix.length)) : null;
}

function base64UrlJson(value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function parseBase64UrlJson(value) {
    try { return JSON.parse(Buffer.from(String(value || ''), 'base64url').toString('utf8')); } catch (_) { return null; }
}

function safeSecretString(value) {
    return String(value || '').trim();
}

async function getMicrosoftPortalAuthConfig() {
    if (microsoftPortalAuthConfigPromise) return microsoftPortalAuthConfigPromise;
    microsoftPortalAuthConfigPromise = (async () => {
        const [clientId, clientSecret, redirectUri] = await Promise.all([
            getSecret('ENTRA_PORTAL_CLIENT_ID'),
            getSecret('ENTRA_PORTAL_CLIENT_SECRET'),
            getSecret('ENTRA_PORTAL_REDIRECT_URI')
        ]);
        const config = { clientId: safeSecretString(clientId), clientSecret: safeSecretString(clientSecret), redirectUri: safeSecretString(redirectUri) };
        if (!config.clientId || !config.clientSecret || !config.redirectUri) throw new Error('Microsoft portal sign-in is not configured. ENTRA_PORTAL_CLIENT_ID, ENTRA_PORTAL_CLIENT_SECRET, and ENTRA_PORTAL_REDIRECT_URI are required.');
        const redirectUrl = new URL(config.redirectUri);
        if (redirectUrl.protocol !== 'https:' && process.env.NODE_ENV === 'production') throw new Error('ENTRA_PORTAL_REDIRECT_URI must use HTTPS in production.');
        return config;
    })();
    try { return await microsoftPortalAuthConfigPromise; } catch (error) { microsoftPortalAuthConfigPromise = null; throw error; }
}

function getMicrosoftPortalRedirectUri(req, config) {
    const redirectUrl = new URL(config.redirectUri);
    const requestHost = String(req.hostname || '').toLowerCase();
    if (redirectUrl.protocol !== 'https:' || redirectUrl.pathname !== '/api/auth/microsoft/callback' || !MICROSOFT_PORTAL_PUBLIC_HOSTS.has(requestHost)) throw new Error('Microsoft portal redirect host is not allowed.');
    redirectUrl.hostname = requestHost;
    return redirectUrl.toString();
}

async function fetchMicrosoftPortalOidcMetadata() {
    const authority = 'organizations';
    const cached = microsoftPortalOidcMetadataCache.get(authority);
    if (cached && cached.expiresAt > Date.now()) return cached.value;
    const response = await fetch(`https://login.microsoftonline.com/${authority}/v2.0/.well-known/openid-configuration`);
    if (!response.ok) throw new Error(`Microsoft OpenID configuration request failed (${response.status}).`);
    const metadata = await response.json();
    if (!metadata?.authorization_endpoint || !metadata?.token_endpoint || !metadata?.jwks_uri || !metadata?.issuer) throw new Error('Microsoft OpenID configuration is incomplete.');
    microsoftPortalOidcMetadataCache.set(authority, { value: metadata, expiresAt: Date.now() + (6 * 60 * 60 * 1000) });
    return metadata;
}

async function fetchMicrosoftPortalSigningKeys(metadata) {
    const cached = microsoftPortalOidcJwksCache.get(metadata.jwks_uri);
    if (cached && cached.expiresAt > Date.now()) return cached.value;
    const response = await fetch(metadata.jwks_uri);
    if (!response.ok) throw new Error(`Microsoft signing-key request failed (${response.status}).`);
    const body = await response.json();
    if (!Array.isArray(body?.keys)) throw new Error('Microsoft signing keys are unavailable.');
    microsoftPortalOidcJwksCache.set(metadata.jwks_uri, { value: body.keys, expiresAt: Date.now() + (60 * 60 * 1000) });
    return body.keys;
}
function secureStringEquals(left, right) {
    const leftBuffer = Buffer.from(String(left || ''));
    const rightBuffer = Buffer.from(String(right || ''));
    return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

async function validateMicrosoftPortalIdToken(idToken, config, metadata, expectedNonce) {
    const [headerPart, payloadPart, signaturePart, extraPart] = String(idToken || '').split('.');
    const header = parseBase64UrlJson(headerPart);
    const claims = parseBase64UrlJson(payloadPart);
    const tenantIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (extraPart || !header || !claims || header.alg !== 'RS256' || !header.kid || !tenantIdPattern.test(String(claims.tid || ''))) throw new Error('Microsoft returned an invalid organizational identity token.');
    const signingKeys = await fetchMicrosoftPortalSigningKeys(metadata);
    const signingKey = signingKeys.find(key => key.kid === header.kid && key.kty === 'RSA');
    if (!signingKey || !crypto.verify('RSA-SHA256', Buffer.from(`${headerPart}.${payloadPart}`), crypto.createPublicKey({ key: signingKey, format: 'jwk' }), Buffer.from(signaturePart, 'base64url'))) throw new Error('Microsoft identity token signature is invalid.');
    const expectedIssuer = String(metadata.issuer).replace('{tenantid}', claims.tid);
    const now = Math.floor(Date.now() / 1000);
    if (claims.aud !== config.clientId || claims.iss !== expectedIssuer || !secureStringEquals(claims.nonce, expectedNonce)) throw new Error('Microsoft identity token is not for this portal.');
    if (!Number.isFinite(Number(claims.exp)) || Number(claims.exp) <= now - 60 || (claims.nbf && Number(claims.nbf) > now + 60)) throw new Error('Microsoft identity token is expired or not yet valid.');
    return claims;
}

let entraIdentitySchemaPromise = null;
async function ensureUserEntraIdentitiesTable() {
    if (entraIdentitySchemaPromise) return entraIdentitySchemaPromise;
    entraIdentitySchemaPromise = pool.query(`
        CREATE TABLE IF NOT EXISTS UserEntraIdentities (
            UserID INT NOT NULL,
            TenantID CHAR(36) NOT NULL,
            ObjectID CHAR(36) NOT NULL,
            CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (UserID),
            UNIQUE KEY uq_user_entra_tenant_object (TenantID, ObjectID)
        )
    `).catch(error => { entraIdentitySchemaPromise = null; throw error; });
    return entraIdentitySchemaPromise;
}


async function getCompanyForEntraTenant(tenantId) {
    const [rows] = await pool.query(
        `SELECT cm.CompanyID AS companyId
         FROM CompanyMicrosoftMapping cm
         INNER JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID
         WHERE cm.IsActive = 1 AND LOWER(mt.TenantID) = LOWER(?)
         LIMIT 2`,
        [tenantId]
    );
    if (rows.length > 1) throw new Error('Microsoft tenant is mapped to more than one StackCTRL company.');
    return rows[0] || null;
}

async function getUserByEntraIdentity(tenantId, objectId) {
    const [rows] = await pool.query(
        `SELECT u.ID AS id, u.FirstName AS firstName, u.LastName AS lastName, u.Email AS email, u.Role AS role, u.CompanyID AS companyId
         FROM UserEntraIdentities ei
         INNER JOIN Users u ON u.ID = ei.UserID
         WHERE ei.TenantID = ? AND ei.ObjectID = ?
         LIMIT 1`,
        [tenantId, objectId]
    );
    return rows[0] || null;
}


async function resolveApprovedEntraUser(identity) {
    const tenantId = String(identity.tid || '').toLowerCase();
    const objectId = String(identity.oid || '').toLowerCase();
    const email = safeSecretString(identity.email || identity.preferred_username).toLowerCase();
    if (!tenantId || !objectId) throw new Error('Microsoft identity is missing its tenant or user object ID.');
    await ensureUserEntraIdentitiesTable();
    const company = await getCompanyForEntraTenant(tenantId);
    if (!company?.companyId) throw new Error('Microsoft tenant is not approved for StackCTRL access.');
    let user = await getUserByEntraIdentity(tenantId, objectId);
    if (user) {
        if (company?.companyId && Number(user.companyId) !== Number(company.companyId)) throw new Error('Microsoft identity is not assigned to the approved company.');
        return user;
    }
    if (!email) throw new Error('Microsoft did not provide an email for first-time account matching.');
    user = await getUserByEmail(email);
    if (!user) throw new Error('Microsoft user is not pre-approved for StackCTRL access.');
    if (company?.companyId && Number(user.companyId) !== Number(company.companyId)) throw new Error('Microsoft user is not pre-approved for this StackCTRL company.');
    try {
        await pool.query('INSERT INTO UserEntraIdentities (UserID, TenantID, ObjectID) VALUES (?, ?, ?)', [user.id, tenantId, objectId]);
    } catch (error) {
        if (error.code !== 'ER_DUP_ENTRY') throw error;
        const existingUser = await getUserByEntraIdentity(tenantId, objectId);
        if (!existingUser || Number(existingUser.id) !== Number(user.id)) throw new Error('Microsoft identity is already linked to another StackCTRL user.');
    }
    return user;
}
async function buildPortalAuthentication(user) {
    const accessContext = await getUserAccessContextByEmail(user.email);
    const effectiveAccess = accessContext?.hasSunbirdAccess ? 'sunbird' : (accessContext?.accessType || 'standard');
    const jwtPayload = { id: user.id, email: user.email, role: user.role, companyId: accessContext?.companyId || user.companyId || null, access: effectiveAccess, hasSunbirdAccess: Boolean(accessContext?.hasSunbirdAccess), tenantId: accessContext?.tenantId || null };
    const accessToken = jwt.sign(jwtPayload, ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
    accessContextCache.set(String(user.email || '').toLowerCase(), { accessType: effectiveAccess, tenantId: jwtPayload.tenantId, companyId: jwtPayload.companyId });
    return {
        accessToken,
        redirect: String(user.role || '').toLowerCase() === 'admin' ? '/Admin.html' : '/ClientPortal.html',
        user: { id: user.id, email: user.email, firstName: user.firstName || '', lastName: user.lastName || '', role: user.role || 'client', companyId: jwtPayload.companyId, access: jwtPayload.access, hasSunbirdAccess: jwtPayload.hasSunbirdAccess, tenantId: jwtPayload.tenantId }
    };
}

app.get('/api/auth/microsoft/signin', async (req, res) => {
    try {
        const config = await getMicrosoftPortalAuthConfig();
        const metadata = await fetchMicrosoftPortalOidcMetadata(config);
        const redirectUri = getMicrosoftPortalRedirectUri(req, config);
        const state = crypto.randomBytes(32).toString('base64url');
        const nonce = crypto.randomBytes(32).toString('base64url');
        const codeVerifier = crypto.randomBytes(64).toString('base64url');
        const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
        res.cookie(MICROSOFT_PORTAL_OAUTH_COOKIE, base64UrlJson({ state, nonce, codeVerifier, redirectUri, expiresAt: Date.now() + MICROSOFT_PORTAL_OAUTH_TTL_MS }), microsoftPortalCookieOptions(MICROSOFT_PORTAL_OAUTH_TTL_MS, '/api/auth/microsoft/callback'));
        const authorizeUrl = new URL(metadata.authorization_endpoint);
        authorizeUrl.search = new URLSearchParams({ client_id: config.clientId, response_type: 'code', redirect_uri: redirectUri, response_mode: 'query', scope: 'openid profile email', state, nonce, code_challenge: codeChallenge, code_challenge_method: 'S256' }).toString();
        return res.redirect(authorizeUrl.toString());
    } catch (error) {
        console.error('[Microsoft Portal Auth] Unable to start sign-in:', error.message);
        return res.status(503).json({ success: false, message: 'Microsoft sign-in is not available. Please contact StackOps support.' });
    }
});

app.get('/api/auth/microsoft/callback', async (req, res) => {
    const clearOauthCookie = () => res.clearCookie(MICROSOFT_PORTAL_OAUTH_COOKIE, microsoftPortalCookieOptions(0, '/api/auth/microsoft/callback'));
    try {
        if (req.query.error) { clearOauthCookie(); return res.redirect('/microsoft-auth-complete.html?error=cancelled'); }
        const oauthState = parseBase64UrlJson(readRequestCookie(req, MICROSOFT_PORTAL_OAUTH_COOKIE));
        const returnedState = String(req.query.state || '');
        const code = String(req.query.code || '');
        const callbackHost = String(req.hostname || '').toLowerCase();
        const callbackDiagnostics = {
            hasStateCookie: Boolean(oauthState),
            hasAuthorizationCode: Boolean(code),
            hasRedirectUri: Boolean(oauthState?.redirectUri),
            stateExpired: Boolean(oauthState?.expiresAt && oauthState.expiresAt < Date.now()),
            callbackHost
        };
        let stateIsValid = false;
        let callbackHostIsValid = false;
        try {
            stateIsValid = Boolean(oauthState?.state) && secureStringEquals(oauthState.state, returnedState);
            callbackHostIsValid = Boolean(oauthState?.redirectUri) && new URL(oauthState.redirectUri).hostname === callbackHost;
        } catch (_) { callbackHostIsValid = false; }
        if (!oauthState || !code || !oauthState.redirectUri || !oauthState.expiresAt || oauthState.expiresAt < Date.now() || !callbackHostIsValid || !stateIsValid) {
            console.warn('[Microsoft Portal Auth] Callback rejected before token exchange:', { ...callbackDiagnostics, stateIsValid, callbackHostIsValid });
            clearOauthCookie(); return res.redirect('/microsoft-auth-complete.html?error=invalid_request');
        }
        const config = await getMicrosoftPortalAuthConfig();
        const metadata = await fetchMicrosoftPortalOidcMetadata(config);
        const tokenResponse = await fetch(metadata.token_endpoint, {
            method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ client_id: config.clientId, client_secret: config.clientSecret, grant_type: 'authorization_code', code, redirect_uri: oauthState.redirectUri, code_verifier: oauthState.codeVerifier })
        });
        const tokenPayload = await tokenResponse.json();
        if (!tokenResponse.ok || !tokenPayload.id_token) throw new Error(`Microsoft token exchange failed (${tokenResponse.status}).`);
        const identity = await validateMicrosoftPortalIdToken(tokenPayload.id_token, config, metadata, oauthState.nonce);
        const user = await resolveApprovedEntraUser(identity);
        const userRole = String(user?.role || '').toLowerCase();
        if (userRole !== 'client' && userRole !== 'admin') {
            clearOauthCookie();
            return res.redirect('/microsoft-auth-complete.html?error=not_authorized');
        }
        const bootstrapToken = jwt.sign({
            purpose: 'microsoft-portal-bootstrap',
            userId: user.id,
            email: user.email,
            tenantId: identity.tid,
            oid: identity.oid
        }, ACCESS_TOKEN_SECRET, { expiresIn: '2m' });
        clearOauthCookie();
        res.cookie(MICROSOFT_PORTAL_BOOTSTRAP_COOKIE, bootstrapToken, microsoftPortalCookieOptions(MICROSOFT_PORTAL_BOOTSTRAP_TTL_MS, '/api/auth/microsoft/complete'));
        return res.redirect('/microsoft-auth-complete.html');
    } catch (error) {
        clearOauthCookie();
        console.error('[Microsoft Portal Auth] Callback failed:', error.message);
        return res.redirect('/microsoft-auth-complete.html?error=failed');
    }
});

app.get('/api/auth/microsoft/complete', async (req, res) => {
    const clearBootstrapCookie = () => res.clearCookie(MICROSOFT_PORTAL_BOOTSTRAP_COOKIE, microsoftPortalCookieOptions(0, '/api/auth/microsoft/complete'));
    try {
        const token = readRequestCookie(req, MICROSOFT_PORTAL_BOOTSTRAP_COOKIE);
        if (!token) return res.status(401).json({ success: false, message: 'Your Microsoft sign-in session has expired. Please try again.' });
        const bootstrap = jwt.verify(token, ACCESS_TOKEN_SECRET);
        if (bootstrap?.purpose !== 'microsoft-portal-bootstrap' || !bootstrap?.email) throw new Error('Invalid Microsoft sign-in session.');
        const user = await getUserByEmail(bootstrap.email);
        if (!user || Number(user.id) !== Number(bootstrap.userId)) throw new Error('The portal user is no longer available.');
        const portalAuthentication = await buildPortalAuthentication(user);
        clearBootstrapCookie();
        return res.json({ success: true, ...portalAuthentication });
    } catch (error) {
        clearBootstrapCookie();
        console.error('[Microsoft Portal Auth] Completion failed:', error.message);
        return res.status(401).json({ success: false, message: 'Unable to complete Microsoft sign-in. Please try again.' });
    }
});
app.get('/api/auth/email-config', (req, res) => {
    res.json({
        success: true,
        graphEmail: getAzureEmailCredentialStatus()
    });
});
app.post('/api/auth/signin', async (req, res) => {
    try {
        console.log('Signin attempt:', req.body.email);
        const { email, password } = req.body;
        console.log('Calling getUserByEmail...');
        const user = await getUserByEmail(email);
        console.log('User found:', !!user, user ? user.id : 'N/A');
        
        // Security: Don't reveal if email exists - use same message for both cases
        if (!user) {
            return res.status(400).json({ success: false, message: "Invalid email or password. Please check your credentials and try again." });
        }

        // Check if user is a client (for Client Portal access)
        // Allow both 'client' role and 'admin' role to sign in
        const userRole = user.role ? user.role.toLowerCase() : '';
        if (userRole !== 'client' && userRole !== 'admin') {
            return res.status(403).json({ success: false, message: "Access denied. This portal is only available for authorized clients and administrators." });
        }

        // Hybrid password verification:
        // 1) Prefer bcrypt (new Node.js hashing, hashes start with `$2`)
        // 2) Fallback to legacy C# SHA1 (40-char hex, sometimes truncated) for older accounts
        let validPassword = false;
        try {
            if (user.password && user.password.startsWith('$2')) {
                // New bcrypt-based accounts
                validPassword = await bcrypt.compare(password, user.password);
            } else if (user.password) {
                // Legacy SHA1-based accounts (old C# logic we had before)
                const sha1Hash = crypto.createHash('sha1').update(password).digest('hex').slice(0, -2);
                validPassword = (sha1Hash === user.password);
            }
        } catch (compareErr) {
            console.error('Password compare error:', compareErr);
            // Treat as invalid credentials instead of 500
            validPassword = false;
        }
        
        // Security: Use same message for invalid password (don't reveal if email exists)
        if (!validPassword) {
            return res.status(400).json({ success: false, message: "Invalid email or password. Please check your credentials and try again." });
        }
        
        const mfaCode = Math.floor(100000 + Math.random() * 900000);
        const createdAt = new Date();
        const expiresAt = new Date(createdAt.getTime() + 10 * 60000); // 10 minutes
        
        await insertMfaCode(user.id, mfaCode, expiresAt);

        try {
            await sendEmail(
                user.email,
                'Your StackOps IT Solutions MFA Verification Code',
                buildMfaEmail(user, mfaCode),
                true
            );
        } catch (mailErr) {
            console.error('[Auth] Failed to send MFA email:', mailErr?.code || mailErr?.message || mailErr);
            return res.status(503).json({
                success: false,
                message: "We couldn't send your verification code right now. Please try again in a minute."
            });
        }
        console.log('Signin successful');
        res.json({ success: true, message: "MFA code sent. Please check your email to verify your login." });
    } catch (err) {
        console.error('Signin error details:', err.message, err.stack);
        res.status(500).json({ success: false, message: "An error occurred during sign-in. Please try again later." });
    }
});

// Resend MFA code endpoint
app.post('/api/auth/send-mfa', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email address is required.' });
        }
        
        const user = await getUserByEmail(email);
        
        if (!user) {
            return res.status(400).json({ success: false, message: 'Unable to send verification code. Please check your email address and try again.' });
        }
        
        // Generate new MFA code
        const mfaCode = Math.floor(100000 + Math.random() * 900000);
        const createdAt = new Date();
        const expiresAt = new Date(createdAt.getTime() + 10 * 60000); // 10 minutes
        
        await insertMfaCode(user.id, mfaCode, expiresAt);

        try {
            await sendEmail(
                user.email,
                'Your StackOps IT Solutions MFA Verification Code',
                buildMfaEmail(user, mfaCode),
                true
            );
        } catch (mailErr) {
            console.error('[Auth] Failed to resend MFA email:', mailErr?.code || mailErr?.message || mailErr);
            return res.status(503).json({
                success: false,
                message: "We couldn't send your verification code right now. Please try again in a minute."
            });
        }
        
        res.json({ success: true, message: 'A new verification code has been sent to your email address.' });
    } catch (error) {
        console.error('Send MFA error:', error);
        res.status(500).json({ success: false, message: 'An error occurred while sending the verification code. Please try again later.' });
    }
});

//  MFA issues the JWT token upon success (from original)
app.post('/api/auth/verify-mfa', async (req, res) => {
    try {
        const { email, code } = req.body;
        
        if (!email || !code) {
            return res.status(400).json({ success: false, message: 'Email and verification code are required.' });
        }
        
        const user = await getUserByEmail(email);
        
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid verification code. Please try again.' });
        }
        
        const validCode = await checkMfaCode(user.id, code);

        if (!validCode) {
            return res.status(400).json({ success: false, message: 'Invalid or expired verification code. Please request a new code.' });
        }
        
        // MySQL Delete MFA
        await pool.query('DELETE FROM mfa_codes WHERE user_id = ?', [user.id]);

        const accessContext = await getUserAccessContextByEmail(user.email);
        const effectiveAccess = accessContext?.hasSunbirdAccess ? 'sunbird' : (accessContext?.accessType || 'standard');
        const jwtPayload = {
            id: user.id,
            email: user.email,
            role: user.role,
            companyId: accessContext?.companyId || user.companyId || null,
            access: effectiveAccess,
            hasSunbirdAccess: Boolean(accessContext?.hasSunbirdAccess),
            tenantId: accessContext?.tenantId || null
        };
        const accessToken = jwt.sign(jwtPayload, ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
        accessContextCache.set(String(user.email || '').toLowerCase(), {
            accessType: effectiveAccess,
            tenantId: jwtPayload.tenantId,
            companyId: jwtPayload.companyId
        });

        // Use role from Users table instead of hard-coded email list
        const isAdmin = (user.role && user.role.toLowerCase() === 'admin');

        res.json({
            success: true,
            message: 'Authentication successful!',
            accessToken: accessToken,
            redirect: isAdmin ? '/Admin.html' : '/ClientPortal.html',
            user: {
                id: user.id,
                email: user.email,
                firstName: user.firstName || '',
                lastName: user.lastName || '',
                role: user.role || 'client',
                companyId: jwtPayload.companyId,
                access: jwtPayload.access,
                hasSunbirdAccess: jwtPayload.hasSunbirdAccess,
                tenantId: jwtPayload.tenantId
            }
        });
        
    } catch (error) {
        console.error('MFA verification error:', error);
        res.status(500).json({ success: false, message: 'An error occurred during verification. Please try again later.' });
    }
});

app.get('/api/auth/session', authenticateToken, async (req, res) => {
    try {
        const accessContext = await getUserAccessContextByEmail(req.user.email);
        if (!accessContext) {
            return res.status(404).json({ success: false, message: 'User access context not found.' });
        }
        const effectiveAccess = accessContext.hasSunbirdAccess ? 'sunbird' : (accessContext.accessType || 'standard');
        accessContextCache.set(String(req.user.email || '').toLowerCase(), {
            accessType: effectiveAccess,
            tenantId: accessContext.tenantId,
            companyId: accessContext.companyId
        });
        const userPayload = {
            id: req.user.id,
            email: req.user.email,
            role: req.user.role,
            companyId: accessContext.companyId || req.user.companyId || null,
            access: effectiveAccess,
            hasSunbirdAccess: Boolean(accessContext.hasSunbirdAccess),
            tenantId: accessContext.tenantId || null
        };
        const accessChanged = String(req.user.access || '') !== String(effectiveAccess)
            || Boolean(req.user.hasSunbirdAccess) !== Boolean(accessContext.hasSunbirdAccess);
        let accessToken = null;
        if (accessChanged) {
            accessToken = jwt.sign({
                id: userPayload.id,
                email: userPayload.email,
                role: userPayload.role,
                companyId: userPayload.companyId,
                access: userPayload.access,
                hasSunbirdAccess: userPayload.hasSunbirdAccess,
                tenantId: userPayload.tenantId
            }, ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
        }
        return res.json({
            success: true,
            user: userPayload,
            accessToken,
            accessChanged
        });
    } catch (error) {
        console.error('[Auth Session] Failed to refresh access context:', error.message);
        return res.status(500).json({ success: false, message: 'Unable to refresh session access.' });
    }
});

// Allow unauthenticated access to Client Portal (signin form is built in)
app.get('/ClientPortal.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'ClientPortal.html'));
});

//=============================================================================================================================================================//
//                                     SYNTHETIC MONITORING LOGIN ENDPOINT (for New Relic Synthetics) - added from original                                    //
//=============================================================================================================================================================//
app.post('/api/auth/synthetic-login', async (req, res) => {
  try {
    const providedKey = req.headers['x-synthetic-key'];
    const expectedKey = await getSecret('SYNTHETIC_MONITOR_KEY');

    if (!providedKey || providedKey !== expectedKey) {
      return res.status(403).json({
        success: false,
        message: 'Forbidden'
      });
    }

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    const user = await getUserByEmail(email);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const userRole = user.role ? user.role.toLowerCase() : '';

    if (userRole !== 'client' && userRole !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    let validPassword = false;

    try {
      if (user.password && user.password.startsWith('$2')) {
        validPassword = await bcrypt.compare(password, user.password);
      } else if (user.password) {
        const sha1Hash = crypto
          .createHash('sha1')
          .update(password)
          .digest('hex')
          .slice(0, -2);

        validPassword = sha1Hash === user.password;
      }
    } catch (compareErr) {
      console.error('[Synthetic Login] Password compare error:', compareErr);
      validPassword = false;
    }

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const accessContext = await getUserAccessContextByEmail(user.email);

    const jwtPayload = {
      id: user.id,
      email: user.email,
      role: user.role,
      companyId: accessContext?.companyId || user.companyId || null,
      access: accessContext?.accessType || 'standard',
      tenantId: accessContext?.tenantId || null
    };

    const accessToken = jwt.sign(
      jwtPayload,
      ACCESS_TOKEN_SECRET,
      { expiresIn: '1h' }
    );

    accessContextCache.set(String(user.email || '').toLowerCase(), {
      accessType: jwtPayload.access,
      tenantId: jwtPayload.tenantId,
      companyId: jwtPayload.companyId
    });

    return res.json({
      success: true,
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName || user.firstname || user.FirstName || '',
        lastName: user.lastName || user.lastname || user.LastName || '',
        role: user.role,
        access: jwtPayload.access,
        tenantId: jwtPayload.tenantId,
        companyId: jwtPayload.companyId
      }
    });
  } catch (error) {
    console.error('[Synthetic Login] Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Synthetic login failed'
    });
  }
});

// Wrapped the entire transaction logic for dual-database support (adapted for MySQL-only, from original)
app.post('/api/admin/register-client', async (req, res) => {
    const {
        firstName, lastName, email, contact, password,
        companyName, website, industry, address, city, state, zipCode, country
    } = req.body;
    
    if (!firstName || !lastName || !email || !password || !companyName) {
        return res.status(400).json({ success: false, message: 'Missing required client or company details.' });
    }
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    let registrationSuccessful = false;

    try {
        // MySQL Registration
        const connection = await pool.getConnection();
        
        try {
            await connection.beginTransaction();

            // Check if company already exists (case-insensitive match on company name)
            const [existingCompany] = await connection.query(
                `SELECT ID FROM Companies WHERE LOWER(companyname) = LOWER(?) LIMIT 1`,
                [companyName]
            );

            let companyId;
            
            if (existingCompany && existingCompany.length > 0) {
                // Company exists - reuse its ID
                companyId = existingCompany[0].ID;
                console.log(`Reusing existing company ID ${companyId} for "${companyName}"`);
            } else {
                // Company doesn't exist - create new one
                const [companyResult] = await connection.query(
                    `INSERT INTO Companies (companyname, website, industry, address, city, state, zipcode, country)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [companyName, website, industry, address, city, state, zipCode, country]
                );
                companyId = companyResult.insertId;
                console.log(`Created new company ID ${companyId} for "${companyName}"`);
            }
            
            await connection.query(
                `INSERT INTO Users (firstname, lastname, email, contact, password, isactive, role, companyid)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [firstName, lastName, email, contact, hashedPassword, 1, 'client', companyId]
            );
            
            await connection.commit();
            registrationSuccessful = true;

        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
        
        if (registrationSuccessful) {
            const loginLink = "https://stackopsit.co.za/ClientPortal.html";
            const forgotPasswordLink = "https://stackopsit.co.za/forgot-password.html";
            const emailBody = buildClientCredentialsEmail({
                firstName,
                lastName,
                email,
                password,
                loginLink,
                forgotPasswordLink
            });
            
            await sendEmail(email, 'Your StackOps IT Client Portal Credentials', emailBody, true);
            
            res.status(200).json({ success: true, message: 'Client and company registered successfully. Login credentials emailed.' });
        }
        
    } catch (error) {
        console.error('Registration failed:', error);
        res.status(500).json({ success: false, message: 'Failed to register client. Please check the provided information.' });
    }
});

// Add a new GET endpoint to serve the forgot-password page (from original)
app.get('/forgot-password.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'forgot_password.html'));
});

// Endpoint to handle the password reset request (Step 1: Send token, from original)
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    try {
        const user = await getUserByEmail(email);

        if (!user) {
            return res.status(200).json({ success: true, message: 'If an account with that email exists, a password reset link has been sent.' });
        }

        const resetToken = Math.random().toString(36).substring(2) + Date.now().toString(36);
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

        await pool.query(
            `INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)
                ON DUPLICATE KEY UPDATE token = VALUES(token), expires_at = VALUES(expires_at)`,
            [user.id, resetToken, expiresAt] 
        );

        const resetLink = `https://stackopsit.co.za/reset-password.html?token=${resetToken}`;

        const emailBody = buildPasswordResetEmail(user, resetLink);

        await sendEmail(email, 'Password Reset Request', emailBody, true);

        res.status(200).json({ success: true, message: 'If an account with that email exists, a password reset link has been sent.' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
});

// Endpoint to verify the token and serve the password change page (from original)
app.get('/reset-password.html', async (req, res) => {
    const { token } = req.query;

    if (!token) {
        return res.status(400).send('Invalid or missing token.');
    }

    try {
        let tokens;
        
        if (!pool) {
            throw new Error('MySQL pool is not available.');
        }
        [tokens] = await pool.query(
            'SELECT * FROM password_resets WHERE token = ? AND expires_at > NOW()',
            [token]
        );

        if (tokens.length === 0) {
            return res.status(400).send('Invalid or expired password reset link.');
        }

        res.sendFile(path.join(__dirname, 'reset-password.html'));
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(500).send('Server error. Please try again.');
    }
});

// Endpoint to handle the password update (Step 2: Update password, from original)
app.post('/api/auth/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ success: false, message: 'Token and new password are required.' });
    }

    try {
        let userId;

        const connection = await pool.getConnection();

        try {
            await connection.beginTransaction();

            const [tokens] = await connection.query(
                'SELECT user_id FROM password_resets WHERE token = ? AND expires_at > NOW()',
                [token]
            );

            if (tokens.length === 0) {
                await connection.rollback();
                return res.status(400).json({ success: false, message: 'Invalid or expired token.' });
            }

            userId = tokens[0].user_id;

            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(newPassword, salt);

            await connection.query('UPDATE Users SET password = ? WHERE ID = ?', [hashedPassword, userId]);

            await connection.query('DELETE FROM password_resets WHERE token = ?', [token]);

            await connection.commit();
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
        
        res.status(200).json({ success: true, message: 'Password has been successfully updated!' });

    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ success: false, message: 'Failed to reset password.' });
    }
});

// Contact message endpoint (from original)
app.post('/api/contact-message', async (req, res) => {
    const { firstName, lastName, company, email, contact, service, message } = req.body;

    if (
        !firstName?.trim() ||
        !lastName?.trim() ||
        !company?.trim() ||
        !email?.trim() ||
        !contact?.trim() ||
        !service?.trim() ||
        !message?.trim()
    ) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const emailBody = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>New Contact Inquiry | StackOps IT</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 20px auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05); border-top: 5px solid #007bff; }
                .header { background-color: #007bff; padding: 20px 30px; border-radius: 8px 8px 0 0; text-align: center; }
                .header h1 { margin: 0; font-size: 24px; color: #ffffff; }
                .content { padding: 30px; }
                .section-title { font-size: 18px; color: #007bff; border-bottom: 2px solid #f4f4f4; padding-bottom: 5px; margin-top: 20px; margin-bottom: 15px; font-weight: bold; }
                .data-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
                .data-table tr:nth-child(even) { background-color: #f9f9f9; }
                .data-table th, .data-table td { padding: 10px 15px; text-align: left; border-bottom: 1px solid #eee; }
                .data-table th { width: 35%; color: #555; font-weight: normal; }
                .message-box { background-color: #fff8e1; border: 1px solid #ffecb3; padding: 20px; border-radius: 5px; margin-top: 15px; }
                .footer { padding: 20px 30px; text-align: center; font-size: 12px; color: #888; border-top: 1px solid #eee; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>&#128231; New Contact Inquiry: ${company}</h1>
                </div>
                
                <div class="content">
                    <p style="font-size: 16px;">
                        A new message has been received from **${firstName} ${lastName}** at **${company}**.
                        The inquiry is for **${service}**.
                    </p>

                    <div class="section-title">Client & Contact Details</div>
                    <table class="data-table">
                        <tr>
                            <th>Name:</th>
                            <td>${firstName} ${lastName}</td>
                        </tr>
                        <tr>
                            <th>Company:</th>
                            <td>${company}</td>
                        </tr>
                        <tr>
                            <th>Email:</th>
                            <td><a href="mailto:${email}" style="color: #007bff;">${email}</a></td>
                        </tr>
                        <tr>
                            <th>Contact Number:</th>
                            <td>${contact}</td>
                        </tr>
                    </table>

                    <div class="section-title">Service Interest</div>
                    <table class="data-table">
                        <tr>
                            <th>Service Requested:</th>
                            <td>**${service}**</td>
                        </tr>
                    </table>
                    
                    <div class="section-title">Message Details</div>
                    <div class="message-box">
                        <p style="margin: 0; white-space: pre-wrap;">${message}</p>
                    </div>

                </div>
                <div class="footer">
                    <p>&copy; ${new Date().getFullYear()} StackOps IT Solutions. All rights reserved. | Automated Contact Alert</p>
                </div>
            </div>
        </body>
        </html>
    `;

    try {
        await sendInfoEmail('info@stackopsit.co.za', `New Inquiry: ${company} - ${service}`, emailBody, true);

        res.json({ success: true });
    } catch (error) {
        console.error('Contact message error:', error);
        res.status(500).json({ success: false, message: 'Failed to send message.' });
    }
});

// ============================================
// ADMIN API ENDPOINTS - INVOICES & MANAGEMENT
// ============================================

// Get all companies
app.get('/api/admin/companies', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const [companies] = await pool.query('SELECT * FROM Companies ORDER BY CompanyName');
        res.json(companies);
    } catch (error) {
        console.error('Error fetching companies:', error);
        res.status(500).json({ error: 'Failed to fetch companies' });
    }
});

// Get company by ID
app.get('/api/admin/companies/:id', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const [companies] = await pool.query('SELECT * FROM Companies WHERE ID = ?', [req.params.id]);
        if (companies.length === 0) {
            return res.status(404).json({ error: 'Company not found' });
        }
        res.json(companies[0]);
    } catch (error) {
        console.error('Error fetching company:', error);
        res.status(500).json({ error: 'Failed to fetch company' });
    }
});

// Get client by ID
app.get('/api/admin/clients/:id', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const [clients] = await pool.query(
            `SELECT u.*, c.CompanyName, c.ID as CompanyID
             FROM Users u
             LEFT JOIN Companies c ON u.companyid = c.ID
             WHERE u.id = ?`,
            [req.params.id]
        );
        if (clients.length === 0) {
            return res.status(404).json({ error: 'Client not found' });
        }
        res.json(clients[0]);
    } catch (error) {
        console.error('Error fetching client:', error);
        res.status(500).json({ error: 'Failed to fetch client' });
    }
});

// Create client
app.post('/api/admin/clients', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const { companyId, firstName, lastName, email, contact, role, isActive } = req.body;
        
        // Generate a default password (user should reset it)
        const defaultPassword = `@${firstName.substring(0, 3)}${lastName.substring(0, 3)}${new Date().getFullYear()}!`;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(defaultPassword, salt);
        
        const [result] = await pool.query(
            `INSERT INTO Users (firstname, lastname, email, contact, password, isactive, role, companyid)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [firstName, lastName, email, contact, hashedPassword, isActive || 1, role || 'client', companyId]
        );
        
        res.json({ id: result.insertId });
    } catch (error) {
        console.error('Error creating client:', error);
        res.status(500).json({ error: 'Failed to create client' });
    }
});

// Update client
app.put('/api/admin/clients/:id', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const { companyId, firstName, lastName, email, contact, role, isActive } = req.body;
        
        await pool.query(
            `UPDATE Users 
             SET firstname = ?, lastname = ?, email = ?, contact = ?, role = ?, isactive = ?, companyid = ?
             WHERE id = ?`,
            [firstName, lastName, email, contact, role, isActive, companyId, req.params.id]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating client:', error);
        res.status(500).json({ error: 'Failed to update client' });
    }
});

// Get clients (users) - optionally filtered by company
app.get('/api/admin/clients', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        let query = `
            SELECT u.id, u.firstname, u.lastname, u.email, u.contact, u.role, u.isactive, 
                   c.CompanyName, c.ID as CompanyID
            FROM Users u
            LEFT JOIN Companies c ON u.companyid = c.ID
        `;
        const params = [];
        
        if (req.query.companyId) {
            query += ' WHERE u.companyid = ?';
            params.push(req.query.companyId);
        }
        
        query += ' ORDER BY u.lastname, u.firstname';
        const [clients] = await pool.query(query, params);
        res.json(clients);
    } catch (error) {
        console.error('Error fetching clients:', error);
        res.status(500).json({ error: 'Failed to fetch clients' });
    }
});

// ==================== QUICK ADD CLIENT FOR INVOICING ====================
// This endpoint creates a lightweight client record without full registration
// Ideal for automation and quick invoice creation workflows
app.post('/api/admin/clients/quick-add', authenticateToken, async (req, res) => {
    const { name, email, companyId, companyName } = req.body;

    if (!name || (!companyId && !companyName)) {
        return res.status(400).json({ error: 'Client name and company (ID or Name) are required' });
    }

    const parts = name.trim().split(' ');
    const firstName = parts.shift();
    const lastName = parts.join(' ') || '';

    try {
        let finalCompanyId = companyId;
        let createdCompany = null;

        if (!finalCompanyId && companyName) {
            // Create new company
            const [companyResult] = await pool.query(
                `INSERT INTO Companies (CompanyName) VALUES (?)`,
                [companyName]
            );
            finalCompanyId = companyResult.insertId;
            createdCompany = { id: finalCompanyId, name: companyName };
        }

        const [result] = await pool.query(
            `INSERT INTO Users (firstname, lastname, email, role, companyid, isactive)
             VALUES (?, ?, ?, 'invoice_client', ?, 1)`,
            [firstName, lastName, email || null, finalCompanyId]
        );

        res.json({
            success: true,
            client: {
                id: result.insertId,
                firstname: firstName,
                lastname: lastName,
                email
            },
            company: createdCompany
        });

    } catch (err) {
        console.error('Quick add client error:', err);
        res.status(500).json({ error: 'Failed to create client' });
    }
});


// Get invoices - optionally filtered by company or client
app.get('/api/admin/invoices', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        let query = `
            SELECT i.*, 
                   c.CompanyName
            FROM Invoices i
            LEFT JOIN Companies c ON i.CompanyID = c.ID
            WHERE 1=1
        `;
        const params = [];
        
        if (req.query.companyId) {
            query += ' AND i.CompanyID = ?';
            params.push(req.query.companyId);
        }
        
        query += ' ORDER BY i.InvoiceDate DESC';
        const [invoices] = await pool.query(query, params);
        
        // Get client names for each invoice (from Users table based on CompanyID)
        for (let invoice of invoices) {
            const [users] = await pool.query(
                'SELECT CONCAT(firstname, " ", lastname) as ClientName FROM Users WHERE companyid = ? LIMIT 1',
                [invoice.CompanyID]
            );
            invoice.ClientName = users[0]?.ClientName || '-';
        }
        
        res.json(invoices);
    } catch (error) {
        console.error('Error fetching invoices:', error);
        res.status(500).json({ error: 'Failed to fetch invoices' });
    }
});

// Preview invoice PDF
app.post('/api/admin/invoices/preview', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const { CompanyID, UserID, InvoiceDate, DueDate, TotalAmount, Items } = req.body;
        
        // Fetch company and client details for PDF
        const [companyRows] = await pool.query(
            'SELECT companyname AS CompanyName, address, city, state, zipcode FROM Companies WHERE ID = ?', 
            [CompanyID]
        );
        const [clientRows] = await pool.query(
            'SELECT firstname, lastname, email FROM Users WHERE ID = ?', 
            [UserID]
        );
        
        const companyData = companyRows[0];
        const clientData = clientRows[0];

        if (!clientData) {
            return res.status(404).json({ error: `Client with ID ${UserID} not found` });
        }
        if (!companyData) {
            return res.status(404).json({ error: `Company with ID ${CompanyID} not found` });
        }

        // Get temporary invoice number (last + 1)
        const [maxInvoice] = await pool.query('SELECT MAX(InvoiceNumber) as maxNum FROM Invoices');
        const nextInvoiceNumber = (maxInvoice[0]?.maxNum || 0) + 1;

        const invoiceData = {
            InvoiceNumber: nextInvoiceNumber,
            InvoiceDate,
            DueDate,
            TotalAmount
        };
        
        // Generate PDF
        const pdfBuffer = await generateInvoicePDF(invoiceData, Items, companyData, clientData);

        // Return PDF as base64
        res.json({ 
            pdf: pdfBuffer.toString('base64'),
            InvoiceNumber: nextInvoiceNumber
        });
    } catch (error) {
        console.error('Error previewing invoice:', error);
        res.status(500).json({ error: 'Failed to generate invoice preview' });
    }
});

app.post('/api/admin/invoices', authenticateToken, async (req, res) => {
  try {
    if (!pool) {
      return res.status(500).json({ error: 'Database connection unavailable' });
    }
    const { CompanyID, UserID, InvoiceDate, DueDate, TotalAmount, Status, Items } = req.body;
    
    // Get next invoice number
    const [maxInvoice] = await pool.query('SELECT MAX(InvoiceNumber) as maxNum FROM Invoices');
    const nextInvoiceNumber = (maxInvoice[0]?.maxNum || 0) + 1;
    
    // Use a transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      const [result] = await connection.query(
        `INSERT INTO Invoices (CompanyID, InvoiceDate, DueDate, TotalAmount, Status, InvoiceNumber)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [CompanyID, InvoiceDate, DueDate, TotalAmount, Status || 'Pending', nextInvoiceNumber]
      );
      
      const invoiceId = result.insertId;

      // Insert items if provided - Updated to handle new structure
      if (Items && Items.length > 0) {
        for (const item of Items) {
          // Support both old and new formats
          if (item.ServiceCategory) {
            // New format: ServiceCategory, Deliverables, Frequency, Rate, Total
            await connection.query(
              `INSERT INTO InvoiceItems (InvoiceID, ServiceCategory, Deliverables, Frequency, Rate, Total)
               VALUES (?, ?, ?, ?, ?, ?)`,
              [invoiceId, item.ServiceCategory, item.Deliverables, item.Frequency, item.Rate, item.Total]
            );
          } else {
            // Old format: Description, Quantity, UnitPrice (for backward compatibility)
            await connection.query(
              `INSERT INTO InvoiceItems (InvoiceID, Description, Quantity, UnitPrice)
               VALUES (?, ?, ?, ?)`,
              [invoiceId, item.Description, item.Quantity, item.UnitPrice]
            );
          }
        }
      }

      // NEW: Create Payment Links (PayFast and YOCO)
      let yocoPaymentUrl = null;
      let payfastPaymentUrl = null;
      
      // Fetch client details first for payment links
      const [clientRows] = await connection.query(
        'SELECT firstname, lastname, email FROM Users WHERE ID = ?', 
        [UserID]
      );
      const clientDataForLinks = clientRows[0];

      // 1. PayFast Integration (Primary)
      try {
        if (clientDataForLinks) {
          payfastPaymentUrl = await generatePayFastLink({
            amount: TotalAmount,
            item_name: `Invoice #${nextInvoiceNumber}`,
            item_description: `Payment for StackOps IT Solutions Invoice #${nextInvoiceNumber}`,
            name_first: clientDataForLinks.firstname,
            name_last: clientDataForLinks.lastname,
            email_address: clientDataForLinks.email,
            m_payment_id: `INV-${nextInvoiceNumber}-${invoiceId}`,
            custom_int1: invoiceId,
            custom_str1: nextInvoiceNumber.toString()
          });

          if (payfastPaymentUrl) {
            // Store in payfast_payments table
            await connection.query(
              "INSERT INTO payfast_payments (invoice_id, m_payment_id, amount, payment_status) VALUES (?, ?, ?, 'pending')",
              [invoiceId, `INV-${nextInvoiceNumber}-${invoiceId}`, TotalAmount]
            );
          }
        }
      } catch (payfastError) {
        console.error("Error creating PayFast payment:", payfastError);
      }

      // 2. YOCO Integration (Secondary)
      try {
        const yocoSecretKey = await getSecret('YOCO_SECRET_KEY');
        if (yocoSecretKey) {
          const amountInCents = Math.round(parseFloat(TotalAmount) * 100);
          const yocoResponse = await fetch("https://payments.yoco.com/api/checkouts", {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${yocoSecretKey}`,
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              amount: amountInCents,
              currency: "ZAR",
              description: `Payment for Invoice #${nextInvoiceNumber}`,
              metadata: {
                invoiceId: invoiceId.toString()
              }
            })
          });

          const yocoData = await yocoResponse.json();
          if (yocoData.id && yocoData.redirectUrl) {
            yocoPaymentUrl = yocoData.redirectUrl;
            await connection.query(
              "INSERT INTO yoco_payments (invoice_id, yoco_checkout_id, redirect_url, amount, status) VALUES (?, ?, ?, ?, 'pending')",
              [invoiceId, yocoData.id, yocoPaymentUrl, amountInCents]
            );
          }
        }
      } catch (yocoError) {
        console.error("Error creating YOCO payment:", yocoError);
      }

      // Fetch company and client details for PDF and Email
      const [companyRows] = await connection.query(
        'SELECT companyname AS CompanyName, address, city, state, zipcode FROM Companies WHERE ID = ?', 
        [CompanyID]
      );
      
      const companyData = companyRows[0];
      const clientData = clientDataForLinks;

      if (!clientData) {
        throw new Error(`Client with ID ${UserID} not found`);
      }
      if (!companyData) {
        throw new Error(`Company with ID ${CompanyID} not found`);
      }

      await connection.commit();
      const invoiceData = {
        InvoiceNumber: nextInvoiceNumber,
        InvoiceDate,
        DueDate,
        TotalAmount
      };
      
      // Generate PDF
      const pdfBuffer = await generateInvoicePDF(invoiceData, Items, companyData, clientData);

      // UPDATED: Send Email with Payment Links
      const emailBody = `
       <div style="
                font-family: 'Avenir Next LT Pro Light', 'Avenir Next', Avenir, Helvetica, Arial, sans-serif;
                line-height: 1.6;
                color: #333;
            ">
            <p>Dear ${clientData.lastname},</p>

            <p>I hope you are well.</p>

            <p>Please find attached invoice <strong>[#${nextInvoiceNumber}]</strong>.</p>

            <p><strong>Invoice Summary:</strong></p>

            <table style="width:100%; border-collapse:collapse; margin-top:20px; font-family:'Avenir Next LT Pro Light','Avenir Next',Avenir,Helvetica,Arial,sans-serif;">
                <tr>
                    <td style="padding:10px; border:1px solid #ddd; font-weight:600; width:150px;">Invoice Number:</td>
                    <td style="padding:10px; border:1px solid #ddd;">#${nextInvoiceNumber}</td>
                </tr>
                <tr>
                    <td style="padding:10px; border:1px solid #ddd; font-weight:600;">Invoice Date:</td>
                    <td style="padding:10px; border:1px solid #ddd;">${new Date(InvoiceDate).toLocaleDateString()}</td>
                </tr>
                <tr>
                    <td style="padding:10px; border:1px solid #ddd; font-weight:600;">Due Date:</td>
                    <td style="padding:10px; border:1px solid #ddd;">${new Date(DueDate).toLocaleDateString()}</td>
                </tr>
                <tr>
                    <td style="padding:10px; border:1px solid #ddd; font-weight:600;">Total Amount:</td>
                    <td style="padding:10px; border:1px solid #ddd;">R${parseFloat(TotalAmount).toFixed(2)}</td>
                </tr>
            </table>

            <p style="margin-top:20px;">
                To make payment quick and convenient, you may use the secure payment links below:
            </p>

            <div style="margin-top:20px; padding:15px; border:1px solid #eee; border-radius:8px; background-color:#fcfcfc;">
                <h3 style="margin-top:0; color:#333; font-size:16px;">Option 1: Pay via PayFast (Instant EFT, Cards, etc.)</h3>
                ${
                payfastPaymentUrl
                    ? `<p style="margin-top:10px;">
                    <a href="${payfastPaymentUrl}" target="_blank" style="display:inline-block; padding:10px 20px; background-color:#bf2026; color:white; text-decoration:none; border-radius:5px; font-weight:bold;">Pay Now via PayFast</a>
                    </p>`
                    : `<p style="margin-top:10px; color:red;">
                    Note: PayFast link could not be generated.
                    </p>`
                }
            </div>

            <div style="margin-top:20px; padding:15px; border:1px solid #eee; border-radius:8px; background-color:#fcfcfc;">
                <h3 style="margin-top:0; color:#333; font-size:16px;">Option 2: Pay via YOCO (Cards)</h3>
                ${
                yocoPaymentUrl
                    ? `<p style="margin-top:10px;">
                    <a href="${yocoPaymentUrl}" target="_blank" style="display:inline-block; padding:10px 20px; background-color:#0070ba; color:white; text-decoration:none; border-radius:5px; font-weight:bold;">Pay Now via YOCO</a>
                    </p>`
                    : `<p style="margin-top:10px; color:red;">
                    Note: YOCO link could not be generated.
                    </p>`
                }
            </div>

            <p style="margin-top:20px;">
                If you have any questions, please contact us at
                <a href="mailto:billing@stackopsit.co.za">billing@stackopsit.co.za</a>
                or 011 568 9337.
            </p>

            <p>
                Best regards,<br>
            </p>


            <img 
                src="https://i.postimg.cc/Pr25Gv6k/signature.png" 
                width="425" 
                style="display:block; width:425px; max-width:100%; height:auto;"
                >

            <p style="
                font-size:8.5px;
                line-height:1.4;
                color:#666666;
                font-family:'Avenir Next LT Pro Light','Avenir Next',Avenir,Helvetica,Arial,sans-serif;
                margin:0.5px 0 0 0;
            ">
                <strong>StackOps IT Solutions (Pty) Ltd</strong> |
                <strong>Reg. No:</strong> 2016/120370/07 |
                <strong>B-BBEE Level</strong>: 1 Contributor: 135% |
                <strong>CSD Supplier:</strong> MAAA164124.
                Legally registered in South Africa, providing IT support, cybersecurity, governance, infrastructure, consulting services,
                and procurement of IT hardware in compliance with all applicable laws and regulations.
                All client information is protected in accordance with the
                <strong>Protection of Personal Information Act (POPIA)</strong> and our internal
                privacy and security policies. We are committed to safeguarding your data and ensuring confidentiality, integrity, and lawful
                processing at all times.
                All information, proposals, and pricing are accurate at the time of sending and governed by our Master Service Agreement (MSA)
                or client-specific contracts. Prices may be subject to change due to economic, regulatory, or supplier factors, with clients
                notified in advance.
                This email and attachments are confidential and intended solely for the named recipient(s). If received in error, please
                notify the sender immediately, delete the message, and do not disclose, copy, or distribute its contents.
                Unauthorized use of this communication is strictly prohibited.
                Emails are not guaranteed virus-free; StackOps IT Solutions accepts no liability for any damage, loss, or unauthorized access
                arising from this communication.
                StackOps IT Solutions is committed to business continuity, data security, and reliable technology operations.
                Our team provides professional, ethical, and transparent IT services, ensuring measurable value, operational efficiency,
                and compliance with industry best practices.
                <strong>View our Privacy Policy and Terms of Service here:</strong>
                <a href="https://stackopsit.co.za/"
                style="color:#1a73e8; text-decoration:underline;">
                    StackOps IT Solutions | Your Complete IT Force
                </a>
            </p>

        </div>

      `;

      try {
        await sendBillingEmail(
          clientData.email, 
          `Invoice #${nextInvoiceNumber} from StackOps IT Solutions`, 
          emailBody, 
          true,
          [{
            filename: `StackOpsInvoice_${nextInvoiceNumber}.pdf`,
            content: pdfBuffer
          }]
        );
        res.json({ InvoiceID: invoiceId, InvoiceNumber: nextInvoiceNumber, message: 'Invoice created and sent successfully' });
      } catch (emailError) {
        console.error('Invoice created but email failed:', emailError);
        res.json({ 
          InvoiceID: invoiceId, 
          InvoiceNumber: nextInvoiceNumber, 
          message: 'Invoice created successfully, but there was an error sending the email. Please send it manually.',
          emailError: emailError.message 
        });
      }
    } catch (innerError) {
      if (connection) await connection.rollback();
      throw innerError;
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Error creating invoice:', error);
    res.status(500).json({ error: 'Failed to create invoice' });
  }
});

// Get invoice items
app.get('/api/admin/invoice-items/:invoiceId', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const [items] = await pool.query(
            'SELECT * FROM InvoiceItems WHERE InvoiceID = ?',
            [req.params.invoiceId]
        );
        res.json(items);
    } catch (error) {
        console.error('Error fetching invoice items:', error);
        res.status(500).json({ error: 'Failed to fetch invoice items' });
    }
});

// Create invoice item
app.post('/api/admin/invoice-items', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const { InvoiceID, Description, Quantity, UnitPrice } = req.body;
        
        const [result] = await pool.query(
            `INSERT INTO InvoiceItems (InvoiceID, Description, Quantity, UnitPrice)
             VALUES (?, ?, ?, ?)`,
            [InvoiceID, Description, Quantity, UnitPrice]
        );
        
        // Update invoice total
        const [items] = await pool.query(
            'SELECT SUM(Amount) as total FROM InvoiceItems WHERE InvoiceID = ?',
            [InvoiceID]
        );
        const totalAmount = items[0]?.total || 0;
        await pool.query(
            'UPDATE Invoices SET TotalAmount = ? WHERE InvoiceID = ?',
            [totalAmount, InvoiceID]
        );
        
        res.json({ ItemID: result.insertId });
    } catch (error) {
        console.error('Error creating invoice item:', error);
        res.status(500).json({ error: 'Failed to create invoice item' });
    }
});

// Get payments
app.get('/api/admin/payments', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        let query = `
            SELECT p.*, i.InvoiceNumber, i.CompanyID,
                   CONCAT(u.firstname, ' ', u.lastname) as ClientName,
                   c.CompanyName
            FROM Payments p
            LEFT JOIN Invoices i ON p.InvoiceID = i.InvoiceID
            LEFT JOIN Companies c ON i.CompanyID = c.ID
            LEFT JOIN Users u ON i.CompanyID = (SELECT companyid FROM Users WHERE id = u.id LIMIT 1)
            WHERE 1=1
        `;
        const params = [];
        
        if (req.query.invoiceId) {
            query += ' AND p.InvoiceID = ?';
            params.push(req.query.invoiceId);
        }
        
        query += ' ORDER BY p.PaymentDate DESC';
        const [payments] = await pool.query(query, params);
        res.json(payments);
    } catch (error) {
        console.error('Error fetching payments:', error);
        res.status(500).json({ error: 'Failed to fetch payments' });
    }
});

// Create payment
app.post('/api/admin/payments', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const { InvoiceID, AmountPaid, PaymentDate, Method } = req.body;
        
        const [result] = await pool.query(
            `INSERT INTO Payments (InvoiceID, AmountPaid, PaymentDate, Method)
             VALUES (?, ?, ?, ?)`,
            [InvoiceID, AmountPaid, PaymentDate || new Date().toISOString().split('T')[0], Method]
        );
        
        // Check if invoice is fully paid
        const [invoice] = await pool.query('SELECT TotalAmount FROM Invoices WHERE InvoiceID = ?', [InvoiceID]);
        const [payments] = await pool.query(
            'SELECT SUM(AmountPaid) as totalPaid FROM Payments WHERE InvoiceID = ?',
            [InvoiceID]
        );
        
        const totalPaid = parseFloat(payments[0]?.totalPaid || 0);
        const totalAmount = parseFloat(invoice[0]?.TotalAmount || 0);
        
        // Update invoice status
        let status = 'Pending';
        if (totalPaid >= totalAmount) {
            status = 'Paid';
        } else if (totalPaid > 0) {
            status = 'Partially Paid';
        }
        
        await pool.query('UPDATE Invoices SET Status = ? WHERE InvoiceID = ?', [status, InvoiceID]);
        
        res.json({ PaymentID: result.insertId });
    } catch (error) {
        console.error('Error creating payment:', error);
        res.status(500).json({ error: 'Failed to create payment' });
    }
});

// ============================================
// APPOINTMENT MANAGEMENT ENDPOINTS
// ============================================

// Get all appointments
app.get('/api/admin/appointments', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        
        const [appointments] = await pool.query(`
            SELECT * FROM appointment 
            WHERE is_available = 0
            ORDER BY date DESC, time ASC
        `);
        
        res.json(appointments);
    } catch (error) {
        console.error('Error fetching appointments:', error);
        res.status(500).json({ error: 'Failed to fetch appointments' });
    }
});

// Get completed appointments
app.get('/api/admin/appointments/completed', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        
        const [appointments] = await pool.query(`
            SELECT * FROM appointment 
            WHERE is_available = 0 AND clientName IS NOT NULL
            ORDER BY date DESC, time ASC
            LIMIT 0
        `);
        
        res.json(appointments);
    } catch (error) {
        console.error('Error fetching completed appointments:', error);
        res.status(500).json({ error: 'Failed to fetch completed appointments' });
    }
});

// Get appointments by date
app.get('/api/admin/appointments/date/:date', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        
        const { date } = req.params;
        const [appointments] = await pool.query(`
            SELECT * FROM appointment 
            WHERE date = ?
            ORDER BY time ASC
        `, [date]);
        
        res.json(appointments);
    } catch (error) {
        console.error('Error fetching appointments:', error);
        res.status(500).json({ error: 'Failed to fetch appointments' });
    }
});

// Clear all appointments (MUST come before :id route to match correctly)
app.delete('/api/admin/appointments/clear-all', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        
        const [result] = await pool.query(`
            DELETE FROM appointment
        `);
        
        res.json({ 
            message: 'All appointments cleared successfully',
            deletedCount: result.affectedRows
        });
    } catch (error) {
        console.error('Error clearing appointments:', error);
        res.status(500).json({ error: 'Failed to clear appointments' });
    }
});

// Mark appointment as complete (update status, don't delete)
app.put('/api/admin/appointments/:id/complete', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        
        const { id } = req.params;
        const [result] = await pool.query(`
            UPDATE appointment SET status = 'completed' WHERE id = ?
        `, [id]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Appointment not found' });
        }
        
        res.json({ message: 'Appointment marked as complete' });
    } catch (error) {
        console.error('Error completing appointment:', error);
        res.status(500).json({ error: 'Failed to complete appointment' });
    }
});

// Delete appointment
app.delete('/api/admin/appointments/:id', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        
        const { id } = req.params;
        const [result] = await pool.query(`
            DELETE FROM appointment WHERE id = ?
        `, [id]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Appointment not found' });
        }
        
        res.json({ message: 'Appointment deleted successfully' });
    } catch (error) {
        console.error('Error deleting appointment:', error);
        res.status(500).json({ error: 'Failed to delete appointment' });
    }
});

// Get projects (if Projects table exists)
app.get('/api/admin/projects', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        // Check if Projects table exists
        const [tables] = await pool.query(
            "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'Projects'",
            ['consultation_db']
        );
        
        if (tables.length === 0) {
            return res.json([]); // Return empty array if table doesn't exist
        }
        
        let query = `
            SELECT p.*, c.CompanyName,
                   CONCAT(u.firstname, ' ', u.lastname) as AssignedToName
            FROM Projects p
            LEFT JOIN Companies c ON p.CompanyID = c.ID
            LEFT JOIN Users u ON p.AssignedTo = u.id
            WHERE 1=1
        `;
        const params = [];
        
        if (req.query.companyId) {
            query += ' AND p.CompanyID = ?';
            params.push(req.query.companyId);
        }
        
        query += ' ORDER BY p.DueDate DESC';
        const [projects] = await pool.query(query, params);
        res.json(projects);
    } catch (error) {
        console.error('Error fetching projects:', error);
        res.status(500).json({ error: 'Failed to fetch projects' });
    }
});

// Get project by ID
app.get('/api/admin/projects/:id', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        // Check if Projects table exists
        const [tables] = await pool.query(
            "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'Projects'",
            ['consultation_db']
        );
        
        if (tables.length === 0) {
            return res.status(404).json({ error: 'Projects table does not exist' });
        }
        
        const [projects] = await pool.query(
            `SELECT p.*, c.CompanyName,
                    CONCAT(u.firstname, ' ', u.lastname) as AssignedToName
             FROM Projects p
             LEFT JOIN Companies c ON p.CompanyID = c.ID
             LEFT JOIN Users u ON p.AssignedTo = u.id
             WHERE p.ProjectID = ?`,
            [req.params.id]
        );
        
        if (projects.length === 0) {
            return res.status(404).json({ error: 'Project not found' });
        }
        
        res.json(projects[0]);
    } catch (error) {
        console.error('Error fetching project:', error);
        res.status(500).json({ error: 'Failed to fetch project' });
    }
});

// Create project
app.post('/api/admin/projects', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        // Check if Projects table exists
        const [tables] = await pool.query(
            "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'Projects'",
            ['consultation_db']
        );
        
        if (tables.length === 0) {
            return res.status(400).json({ error: 'Projects table does not exist. Please create it first.' });
        }
        
        const { ProjectName, CompanyID, AssignedTo, Status, DueDate, Description } = req.body;
        
        const [result] = await pool.query(
            `INSERT INTO Projects (ProjectName, CompanyID, AssignedTo, Status, DueDate, Description)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [ProjectName, CompanyID, AssignedTo, Status || 'Active', DueDate, Description]
        );
        
        res.json({ ProjectID: result.insertId });
    } catch (error) {
        console.error('Error creating project:', error);
        res.status(500).json({ error: 'Failed to create project' });
    }
});

// Update project
app.put('/api/admin/projects/:id', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const { ProjectName, CompanyID, AssignedTo, Status, DueDate, Description } = req.body;
        
        await pool.query(
            `UPDATE Projects 
             SET ProjectName = ?, CompanyID = ?, AssignedTo = ?, Status = ?, DueDate = ?, Description = ?
             WHERE ProjectID = ?`,
            [ProjectName, CompanyID, AssignedTo, Status, DueDate, Description, req.params.id]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating project:', error);
        res.status(500).json({ error: 'Failed to update project' });
    }
});

// Get project updates
app.get('/api/admin/project-updates', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        // Check if ProjectUpdates table exists
        const [tables] = await pool.query(
            "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'ProjectUpdates'",
            ['consultation_db']
        );
        
        if (tables.length === 0) {
            return res.json([]); // Return empty array if table doesn't exist
        }
        
        let query = 'SELECT * FROM ProjectUpdates WHERE 1=1';
        const params = [];
        
        if (req.query.projectId) {
            query += ' AND ProjectID = ?';
            params.push(req.query.projectId);
        }
        
        query += ' ORDER BY UpdateDate DESC';
        const [updates] = await pool.query(query, params);
        res.json(updates);
    } catch (error) {
        console.error('Error fetching project updates:', error);
        res.status(500).json({ error: 'Failed to fetch project updates' });
    }
});

// Create project update
app.post('/api/admin/project-updates', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        // Check if ProjectUpdates table exists
        const [tables] = await pool.query(
            "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'ProjectUpdates'",
            ['consultation_db']
        );
        
        if (tables.length === 0) {
            return res.status(400).json({ error: 'ProjectUpdates table does not exist. Please create it first.' });
        }
        
        const { ProjectID, UpdateText, UpdateDate } = req.body;
        
        const [result] = await pool.query(
            `INSERT INTO ProjectUpdates (ProjectID, UpdateText, UpdateDate)
             VALUES (?, ?, ?)`,
            [ProjectID, UpdateText, UpdateDate || new Date().toISOString().split('T')[0]]
        );
        
        res.json({ UpdateID: result.insertId });
    } catch (error) {
        console.error('Error creating project update:', error);
        res.status(500).json({ error: 'Failed to create project update' });
    }
});

// Delete project update
app.delete('/api/admin/project-updates/:id', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        await pool.query('DELETE FROM ProjectUpdates WHERE UpdateID = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting project update:', error);
        res.status(500).json({ error: 'Failed to delete project update' });
    }
});

// Get latest invoice for client (Client Portal)
app.get('/api/client/latest-invoice', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        
        const userId = req.user.id;
        
        // Get user's company ID
        const [users] = await pool.query(
            'SELECT CompanyID FROM Users WHERE ID = ?',
            [userId]
        );
        
        if (users.length === 0 || !users[0].CompanyID) {
            return res.status(404).json({ error: 'Company not found for this user' });
        }
        
        const companyId = users[0].CompanyID;
        
        // Get latest invoice for this company
        const [invoices] = await pool.query(
            `SELECT i.*, c.CompanyName
             FROM Invoices i
             LEFT JOIN Companies c ON i.CompanyID = c.ID
             WHERE i.CompanyID = ?
             ORDER BY i.InvoiceDate DESC
             LIMIT 1`,
            [companyId]
        );
        
        if (invoices.length === 0) {
            return res.json(null); // No invoice found
        }
        
        const invoice = invoices[0];
        
        // Get invoice items
        const [items] = await pool.query(
            'SELECT * FROM InvoiceItems WHERE InvoiceID = ?',
            [invoice.InvoiceID]
        );
        
        res.json({
            ...invoice,
            items
        });
    } catch (error) {
        console.error('Error fetching latest invoice:', error);
        res.status(500).json({ error: 'Failed to fetch invoice' });
    }
});

// Get invoice by ID with items
app.get('/api/admin/invoices/:id', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const [invoices] = await pool.query(
            `SELECT i.*, c.CompanyName
             FROM Invoices i
             LEFT JOIN Companies c ON i.CompanyID = c.ID
             WHERE i.InvoiceID = ?`,
            [req.params.id]
        );
        
        if (invoices.length === 0) {
            return res.status(404).json({ error: 'Invoice not found' });
        }
        
        const invoice = invoices[0];
        
        // Get invoice items
        const [items] = await pool.query(
            'SELECT * FROM InvoiceItems WHERE InvoiceID = ?',
            [req.params.id]
        );
        
        // Get payments
        const [payments] = await pool.query(
            'SELECT * FROM Payments WHERE InvoiceID = ? ORDER BY PaymentDate DESC',
            [req.params.id]
        );
        
        res.json({
            ...invoice,
            items,
            payments
        });
    } catch (error) {
        console.error('Error fetching invoice:', error);
        res.status(500).json({ error: 'Failed to fetch invoice' });
    }
});

// Get company details with all related data
app.get('/api/admin/companies/:id/details', authenticateToken, async (req, res) => {
    try {
        if (!pool) {
            return res.status(500).json({ error: 'Database connection unavailable' });
        }
        const companyId = req.params.id;
        
        // Get company info
        const [companies] = await pool.query('SELECT * FROM Companies WHERE ID = ?', [companyId]);
        if (companies.length === 0) {
            return res.status(404).json({ error: 'Company not found' });
        }
        
        const company = companies[0];
        
        // Get clients
        const [clients] = await pool.query(
            'SELECT * FROM Users WHERE companyid = ?',
            [companyId]
        );
        
        // Get invoices
        const [invoices] = await pool.query(
            'SELECT * FROM Invoices WHERE CompanyID = ? ORDER BY InvoiceDate DESC',
            [companyId]
        );
        
        // Get payments
        const [payments] = await pool.query(
            `SELECT p.*, i.InvoiceNumber 
             FROM Payments p
             JOIN Invoices i ON p.InvoiceID = i.InvoiceID
             WHERE i.CompanyID = ?
             ORDER BY p.PaymentDate DESC`,
            [companyId]
        );
        
        res.json({
            company,
            clients,
            invoices,
            payments
        });
    } catch (error) {
        console.error('Error fetching company details:', error);
        res.status(500).json({ error: 'Failed to fetch company details' });
    }
});

//=====================================================================================================================================//
//                                                          Payment integration                                                        //
//=====================================================================================================================================//

// YOCO Payment Creation
app.post("/api/create-payment", authenticateToken, async (req, res) => {
    const { amount, description, invoiceId } = req.body;

    if (!amount || !invoiceId) {
        return res.status(400).json({ error: "Amount and Invoice ID are required" });
    }

    try {
        // 1. Get Secret Key
        const yocoSecretKey = await getSecret('YOCO_SECRET_KEY');

        // 2. Create Yoco Checkout with Metadata
        const response = await fetch("https://payments.yoco.com/api/checkouts", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${yocoSecretKey.trim()}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                amount: Math.round(parseFloat(amount) * 100), // Convert to cents
                currency: "ZAR",
                description: description || `Payment for Invoice #${invoiceId}`,
                // THE FIX: We pass the invoiceId here. Yoco will send it back in the webhook.
                metadata: {
                    invoiceId: invoiceId.toString()
                },
                redirectUrl: `https://stackopsit.co.za/payment-success.html?invoiceId=${invoiceId}`
            })
        });

        const data = await response.json();

        if (data.id) {
            // 3. Save to database (we still save the checkout_id for logs, but we won't rely on it)
            await pool.query(
                "INSERT INTO yoco_payments (yoco_checkout_id, invoice_id, amount, description, status) VALUES (?, ?, ?, ?, ?)",
                [data.id, invoiceId, Math.round(parseFloat(amount) * 100), description, "pending"]
            );

            res.json({ paymentUrl: data.redirectUrl });
        } else {
            throw new Error(data.errorMessage || "Failed to create Yoco checkout");
        }
    } catch (err) {
        console.error("❌ Payment Error:", err.message);
        res.status(500).json({ error: "Payment creation failed" });
    }
});

app.post("/api/payfast/itn", async (req, res) => {
  // 1️⃣ ACKNOWLEDGE IMMEDIATELY (PayFast requires a 200 OK within seconds)
  res.sendStatus(200);

  console.log("[PAYFAST ITN] 📥 Notification received & acknowledged:", JSON.stringify(req.body, null, 2));

  const data = req.body;

    (async () => {
    try {
      const rawBody = req.rawBody || "";
      console.log("[PAYFAST ITN] 📦 Raw Body for signature check:", rawBody);

      const passphrase = await getSecret("PAYFAST_PASSPHRASE");
      console.log("[PAYFAST ITN] Passphrase retrieved:", passphrase ? "YES" : "NO");

      /* ===============================
         1️⃣ VERIFY PAYFAST SIGNATURE
      =============================== */
      const receivedSignature = data.signature;
      
      // Standard PayFast ITN signature check: Take raw POST string, remove signature, append passphrase.
      // 1. Remove the signature field from the raw body string
      let signaturePos = rawBody.indexOf('&signature=');
      if (signaturePos === -1) {
          // Fallback: Check if it's the first param or at the end
          signaturePos = rawBody.indexOf('signature=');
      }

      let stringToHash = rawBody;
      if (signaturePos > -1) {
          // If signature is the last param (most common)
          stringToHash = rawBody.substring(0, signaturePos);
          // If signature was in the middle, handle the trailing part
          const rest = rawBody.substring(signaturePos + 11 + (receivedSignature?.length || 0));
          if (rest && rest.startsWith('&')) {
              stringToHash += rest;
          } else if (rest) {
              stringToHash += rest;
          }
      }

      // 2. Append Passphrase
      if (passphrase && passphrase.trim() !== "") {
          stringToHash += `&passphrase=${encodeURIComponent(passphrase.trim()).replace(/%20/g, "+")}`;
      }

      const generatedSignature = crypto.createHash("md5").update(stringToHash).digest("hex");

      console.log(`[PAYFAST ITN] Signature Check - Received: ${receivedSignature}, Generated: ${generatedSignature}`);
      console.log(`[PAYFAST ITN] String used for hash: "${stringToHash}"`);

      if (receivedSignature !== generatedSignature) {
        console.error("[PAYFAST ITN] ❌ Invalid signature - Background processing aborted");
        
        // Final fallback: Try the reconstruction logic again but with more fields if needed
        const secondTry = generatePayFastSignature(data, passphrase);
        if (receivedSignature === secondTry) {
            console.log("[PAYFAST ITN] ✅ Signature matched on secondary reconstruction logic");
        } else {
            return;
        }
      } else {
        console.log("[PAYFAST ITN] ✅ Signature verified using rawBody");
      }

    /* ===============================
       2️⃣ EXTRACT PAYFAST DATA
    =============================== */
    const {
      m_payment_id,
      pf_payment_id,
      payment_status,
      amount_gross,
      custom_int1
    } = data;

    let invoiceId = custom_int1;

    console.log(`[PAYFAST ITN] Data: Status=${payment_status}, m_payment_id=${m_payment_id}, amount=${amount_gross}, custom_int1=${invoiceId}`);

    if (!invoiceId && m_payment_id) {
       console.log(`[PAYFAST ITN] 🔍 Attempting to find invoiceId from m_payment_id: ${m_payment_id}`);
       // m_payment_id format is INV-Number-ID
       const parts = m_payment_id.split("-");
       if (parts.length >= 3) {
         invoiceId = parts[parts.length - 1];
         console.log(`[PAYFAST ITN] Found invoiceId: ${invoiceId} from m_payment_id`);
       }
    }

    if (!invoiceId) {
      console.error("[PAYFAST ITN] ❌ Missing invoice reference");
      return res.sendStatus(200);
    }

    const connection = await pool.getConnection();
    console.log("[PAYFAST ITN] 🔌 Database connection established");

    try {
      await connection.beginTransaction();
      console.log("[PAYFAST ITN] 🏁 Transaction started");

      /* ===============================
         3️⃣ ENSURE payfast_payments EXISTS
      =============================== */
      console.log(`[PAYFAST ITN] 🔍 Checking if m_payment_id ${m_payment_id} exists in payfast_payments`);
      const [existingPayment] = await connection.query(
        "SELECT payment_status FROM payfast_payments WHERE m_payment_id = ?",
        [m_payment_id]
      );

      if (!existingPayment.length) {
        console.log("[PAYFAST ITN] ➕ Inserting new record into payfast_payments");
        await connection.query(
          `INSERT INTO payfast_payments
           (m_payment_id, invoice_id, pf_payment_id, amount, payment_status, created_at)
           VALUES (?, ?, ?, ?, ?, NOW())`,
          [
            m_payment_id,
            invoiceId,
            pf_payment_id || null,
            parseFloat(amount_gross),
            payment_status
          ]
        );
      } else {
        console.log("[PAYFAST ITN] 🔄 Updating existing record in payfast_payments");
        await connection.query(
          `UPDATE payfast_payments
           SET pf_payment_id = ?,
               payment_status = ?,
               updated_at = NOW()
           WHERE m_payment_id = ?`,
          [pf_payment_id, payment_status, m_payment_id]
        );
      }

      /* ===============================
         4️⃣ PROCESS SUCCESSFUL PAYMENT
      =============================== */
      console.log(`[PAYFAST ITN] Processing payment status: ${payment_status}`);
      if (payment_status === "COMPLETE") {

        // 🔒 Prevent double processing
        console.log(`[PAYFAST ITN] 🔒 Checking if Invoice ${invoiceId} is already marked as paid via PayFast`);
        const [alreadyPaid] = await connection.query(
          "SELECT 1 FROM Payments WHERE InvoiceID = ? AND Method = 'PayFast' LIMIT 1",
          [invoiceId]
        );

        if (!alreadyPaid.length) {
          console.log(`[PAYFAST ITN] 🆗 Invoice ${invoiceId} not processed yet. Updating...`);

          // ✅ Mark invoice as PAID (overrides Pending / Overdue)
          const [invUpdate] = await connection.query(
            "UPDATE Invoices SET Status = 'Paid' WHERE InvoiceID = ?",
            [invoiceId]
          );
          console.log(`[PAYFAST ITN] 📝 Invoices table update result:`, invUpdate);

          // ✅ Insert payment history
          const [payInsert] = await connection.query(
            `INSERT INTO Payments
             (InvoiceID, AmountPaid, PaymentDate, Method)
             VALUES (?, ?, NOW(), 'PayFast')`,
            [invoiceId, parseFloat(amount_gross)]
          );
          console.log(`[PAYFAST ITN] 📝 Payments table insert result:`, payInsert);

          console.log(`[PAYFAST ITN] ✅ Invoice ${invoiceId} marked as PAID`);

          // 📧 Send Confirmation Email (Immediately)
          console.log(`[PAYFAST ITN] 📧 Fetching details for confirmation email for Invoice ${invoiceId}`);
          const [details] = await connection.query(
            `SELECT i.InvoiceNumber, u.email, u.firstname
             FROM Invoices i
             JOIN Companies c ON i.CompanyID = c.ID
             JOIN Users u ON c.ID = u.CompanyID
             WHERE i.InvoiceID = ? AND u.Role = 'Client'
             LIMIT 1`,
            [invoiceId]
          );

          if (details.length) {
            const targetClient = details[0];
            console.log(`[PAYFAST ITN] 📧 Found client: ${targetClient.email}. Sending email...`);
            const receiptHtml = `
              <div style="margin-top: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9; max-width: 400px;">
                <h3 style="margin-top: 0; color: #333; border-bottom: 1px solid #ccc; padding-bottom: 10px;">Payment Receipt</h3>
                <table style="width: 100%; border-collapse: collapse;">
                  <thead>
                    <tr>
                      <th style="text-align: left; padding: 5px 0;">Description</th>
                      <th style="text-align: right; padding: 5px 0;">Amount</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td style="padding: 5px 0;">Invoice #${targetClient.InvoiceNumber}</td>
                      <td style="text-align: right; padding: 5px 0;">R ${parseFloat(amount_gross).toFixed(2)}</td>
                    </tr>
                  </tbody>
                  <tfoot>
                    <tr style="border-top: 2px solid #333; font-weight: bold;">
                      <td style="padding: 10px 0 5px 0;">TOTAL PAID</td>
                      <td style="text-align: right; padding: 10px 0 5px 0;">R ${parseFloat(amount_gross).toFixed(2)}</td>
                    </tr>
                  </tfoot>
                </table>
                <p style="font-size: 12px; color: #666; margin-top: 15px; font-style: italic;">Payment Method: PayFast Online Payment</p>
              </div>
            `;

            try {
              await sendBillingEmail(
                targetClient.email,
                `Payment Received - Invoice #${targetClient.InvoiceNumber}`,
                `<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                 <p>Dear ${targetClient.firstname},</p>
                 <p>We have successfully received your payment for <strong>Invoice #${targetClient.InvoiceNumber}</strong> via PayFast. Thank you for your business!</p>
                 ${receiptHtml}
                 <p>
                    If you have any questions, please contact us at
                    <a href="mailto:billing@stackopsit.co.za">billing@stackopsit.co.za</a>
                    or 011 568 9337.
                 </p>
                 <img
                src=https://i.postimg.cc/Pr25Gv6k/signature.png
                alt="StackOps IT Solutions"
                width="400"
                style="display:block; max-width:400px; width:100%; height:auto; margin-top:10px;"
                >
                <p style="
                    font-size:8.5px;
                    line-height:1.4;
                    color:#666666;
                    font-family:'Avenir Next LT Pro Light','Avenir Next',Avenir,Helvetica,Arial,sans-serif;
                    margin:0.5px 0 0 0;
                ">
                    <strong>StackOps IT Solutions (Pty) Ltd</strong> |
                    <strong>Reg. No:</strong> 2016/120370/07 |
                    <strong>B-BBEE Level</strong>: 1 Contributor: 135% |
                    <strong>CSD Supplier:</strong> MAAA164124.
                    Legally registered in South Africa, providing IT support, cybersecurity, governance, infrastructure, consulting services,
                    and procurement of IT hardware in compliance with all applicable laws and regulations.
                    All client information is protected in accordance with the
                    <strong>Protection of Personal Information Act (POPIA)</strong> and our internal
                    privacy and security policies. We are committed to safeguarding your data and ensuring confidentiality, integrity, and lawful
                    processing at all times.
                    All information, proposals, and pricing are accurate at the time of sending and governed by our Master Service Agreement (MSA)
                    or client-specific contracts. Prices may be subject to change due to economic, regulatory, or supplier factors, with clients
                    notified in advance.
                    This email and attachments are confidential and intended solely for the named recipient(s). If received in error, please
                    notify the sender immediately, delete the message, and do not disclose, copy, or distribute its contents.
                    Unauthorized use of this communication is strictly prohibited.
                    Emails are not guaranteed virus-free; StackOps IT Solutions accepts no liability for any damage, loss, or unauthorized access
                    arising from this communication.
                    StackOps IT Solutions is committed to business continuity, data security, and reliable technology operations.
                    Our team provides professional, ethical, and transparent IT services, ensuring measurable value, operational efficiency,
                    and compliance with industry best practices.
                    <strong>View our Privacy Policy and Terms of Service here:</strong>
                    <a href="https://stackopsit.co.za/"
                    style="color:#1a73e8; text-decoration:underline;">
                        StackOps IT Solutions | Your Complete IT Force
                    </a>
                </p>
                </div>`,
                true
              );
              console.log(`[PAYFAST ITN] 📧 Confirmation email sent to ${targetClient.email}`);
              // Mark as sent to prevent morning automation
              await connection.query("UPDATE Invoices SET PaidEmailSent = TRUE WHERE InvoiceID = ?", [invoiceId]);
              console.log(`[PAYFAST ITN] 📝 Marked PaidEmailSent = TRUE for Invoice ${invoiceId}`);
            } catch (e) {
              console.error(`[PAYFAST ITN] ❌ Failed to send confirmation email:`, e);
            }
          } else {
            console.warn(`[PAYFAST ITN] ⚠️ Could not find client details for Invoice ${invoiceId}`);
          }
        } else {
          console.log(`[PAYFAST ITN] ℹ️ Invoice ${invoiceId} was already marked as PAID. Skipping duplicate processing.`);
        }
      } else {
        console.log(`[PAYFAST ITN] ℹ️ Payment status is not COMPLETE (Status: ${payment_status}). No invoice update performed.`);
      }

      await connection.commit();
      console.log("[PAYFAST ITN] ✅ Transaction committed successfully");
    } catch (dbErr) {
      if (connection) await connection.rollback();
      console.error("[PAYFAST ITN] ❌ DATABASE ERROR:", dbErr);
    } finally {
      if (connection) connection.release();
    }
  } catch (err) {
    console.error("[PAYFAST ITN] ❌ ITN BACKGROUND ERROR:", err);
  }
 })();
});



app.post("/webhook/yoco", express.raw({ type: "application/json" }), async (req, res) => {
  console.log("[YOCO WEBHOOK] 📥 Event received");

  try {
    const event = Buffer.isBuffer(req.body)
      ? JSON.parse(req.body.toString("utf8"))
      : req.body;

    console.log("[YOCO WEBHOOK] Event type:", event?.type);

    // Yoco sometimes uses event.payload and sometimes event.data.payment
    const payment = event?.payload || event?.data?.payment;

    if (!payment) {
      console.error("[YOCO WEBHOOK] ❌ Invalid payload - Full event:", JSON.stringify(event, null, 2));
      return res.sendStatus(200);
    }

    // Invoice ID from metadata (we set this in checkout creation)
    let invoiceId = payment?.metadata?.invoiceId || payment?.metadata?.invoice_id;
    let invoiceIds = payment?.metadata?.invoice_ids ? payment.metadata.invoice_ids.split(',') : [];

    // Fallback: If no invoice ID in metadata, try to find it via checkout ID
    if (!invoiceId && invoiceIds.length === 0) {
      const checkoutId = payment.checkoutId || payment.id;
      if (checkoutId) {
        console.log(`[YOCO WEBHOOK] 🔍 Searching for invoices linked to checkout ${checkoutId}`);
        const [linkedPayments] = await pool.query(
          "SELECT invoice_id FROM yoco_payments WHERE yoco_checkout_id = ?",
          [checkoutId]
        );
        if (linkedPayments.length > 0) {
          invoiceIds = linkedPayments.map(p => p.invoice_id);
          console.log(`[YOCO WEBHOOK] Found ${invoiceIds.length} linked invoices: ${invoiceIds.join(', ')}`);
        }
      }
    } else if (invoiceId && invoiceIds.length === 0) {
      invoiceIds = [invoiceId];
    }

    // Yoco status can be 'paid' or 'succeeded'
    const isPaid = payment.status === "paid" || payment.status === "succeeded";
    
    if (!isPaid) {
      console.log(`[YOCO WEBHOOK] ℹ️ Payment status: ${payment.status}`);
      return res.sendStatus(200);
    }

    if (invoiceIds.length === 0) {
       console.error("[YOCO WEBHOOK] ❌ No invoices found to process. Event:", JSON.stringify(event, null, 2));
       return res.sendStatus(200);
    }

    const connection = await pool.getConnection();

    try {
      await connection.beginTransaction();

      const processedInvoices = [];
      let targetClient = null;
      const paymentReceiptItems = [];

      for (const invId of invoiceIds) {
        const [existing] = await connection.query(
          "SELECT status FROM yoco_payments WHERE invoice_id = ? LIMIT 1",
          [invId]
        );

        if (existing.length && existing[0].status === "paid") {
          console.log(`[YOCO WEBHOOK] ℹ️ Invoice ${invId} already processed`);
          continue;
        }

        await connection.query(
          "UPDATE Invoices SET Status = 'Paid' WHERE InvoiceID = ?",
          [invId]
        );

        await connection.query(
          "UPDATE yoco_payments SET status = 'paid', updated_at = NOW() WHERE invoice_id = ?",
          [invId]
        );

        const [paymentRow] = await connection.query(
          "SELECT amount FROM yoco_payments WHERE invoice_id = ? LIMIT 1",
          [invId]
        );

        let amountPaid = 0;
        if (paymentRow.length) {
          amountPaid = paymentRow[0].amount / 100;
          await connection.query(
            "INSERT INTO Payments (InvoiceID, AmountPaid, PaymentDate, Method) VALUES (?, ?, NOW(), 'YOCO')",
            [invId, amountPaid]
          );
        }

        const [details] = await connection.query(
          `SELECT i.InvoiceNumber, u.email, u.firstname
           FROM Invoices i
           JOIN Companies c ON i.CompanyID = c.ID
           JOIN Users u ON c.ID = u.CompanyID
           WHERE i.InvoiceID = ? AND u.Role = 'Client'
           LIMIT 1`,
          [invId]
        );

        console.log(`[YOCO WEBHOOK] 🎉 SUCCESS: Invoice ${invId} PAID`);

        if (details.length) {
          processedInvoices.push(details[0].InvoiceNumber);
          if (!targetClient) targetClient = details[0];
          paymentReceiptItems.push({
            number: details[0].InvoiceNumber,
            amount: amountPaid
          });
        }
      }

      if (targetClient && processedInvoices.length > 0) {
        const invoiceNumbers = processedInvoices.length > 1 
          ? processedInvoices.join(', #') 
          : processedInvoices[0];

        const totalPaid = paymentReceiptItems.reduce((sum, item) => sum + item.amount, 0);
        const receiptHtml = `
          <div style="margin-top: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9; max-width: 400px;">
            <h3 style="margin-top: 0; color: #333; border-bottom: 1px solid #ccc; padding-bottom: 10px;">Payment Receipt</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <thead>
                <tr>
                  <th style="text-align: left; padding: 5px 0;">Description</th>
                  <th style="text-align: right; padding: 5px 0;">Amount</th>
                </tr>
              </thead>
              <tbody>
                ${paymentReceiptItems.map(item => `
                  <tr>
                    <td style="padding: 5px 0;">Invoice #${item.number}</td>
                    <td style="text-align: right; padding: 5px 0;">R ${item.amount.toFixed(2)}</td>
                  </tr>
                `).join('')}
              </tbody>
              <tfoot>
                <tr style="border-top: 2px solid #333; font-weight: bold;">
                  <td style="padding: 10px 0 5px 0;">TOTAL PAID</td>
                  <td style="text-align: right; padding: 10px 0 5px 0;">R ${totalPaid.toFixed(2)}</td>
                </tr>
              </tfoot>
            </table>
            <p style="font-size: 12px; color: #666; margin-top: 15px; font-style: italic;">Payment Method: YOCO Card Payment</p>
          </div>
        `;

        try {
          await sendBillingEmail(
            targetClient.email,
            `Payment Received - Invoice #${invoiceNumbers}`,
            `<p>Dear ${targetClient.firstname},</p>
             <p>We have successfully received your payment for <strong>Invoice #${invoiceNumbers}</strong>. Thank you for your business!</p>
             <p>Please allow us <strong>24 hours</strong> to process your payment. We will send a final confirmation once the process is complete.</p>
             ${receiptHtml}
             <p>
                If you have any questions, please contact us at
                <a href="mailto:billing@stackopsit.co.za">billing@stackopsit.co.za</a>
                or 011 568 9337.
             </p>
             <img
            src=https://i.postimg.cc/Pr25Gv6k/signature.png
            alt="StackOps IT Solutions"
            width="400"
            style="display:block; max-width:400px; width:100%; height:auto; margin-top:10px;"
            >

            <p style="
                font-size:8.5px;
                line-height:1.4;
                color:#666666;
                font-family:'Avenir Next LT Pro Light','Avenir Next',Avenir,Helvetica,Arial,sans-serif;
                margin:0.5px 0 0 0;
            ">
                <strong>StackOps IT Solutions (Pty) Ltd</strong> |
                <strong>Reg. No:</strong> 2016/120370/07 |
                <strong>B-BBEE Level</strong>: 1 Contributor: 135% |
                <strong>CSD Supplier:</strong> MAAA164124.
                Legally registered in South Africa, providing IT support, cybersecurity, governance, infrastructure, consulting services,
                and procurement of IT hardware in compliance with all applicable laws and regulations.
                All client information is protected in accordance with the
                <strong>Protection of Personal Information Act (POPIA)</strong> and our internal
                privacy and security policies. We are committed to safeguarding your data and ensuring confidentiality, integrity, and lawful
                processing at all times.
                All information, proposals, and pricing are accurate at the time of sending and governed by our Master Service Agreement (MSA)
                or client-specific contracts. Prices may be subject to change due to economic, regulatory, or supplier factors, with clients
                notified in advance.
                This email and attachments are confidential and intended solely for the named recipient(s). If received in error, please
                notify the sender immediately, delete the message, and do not disclose, copy, or distribute its contents.
                Unauthorized use of this communication is strictly prohibited.
                Emails are not guaranteed virus-free; StackOps IT Solutions accepts no liability for any damage, loss, or unauthorized access
                arising from this communication.
                StackOps IT Solutions is committed to business continuity, data security, and reliable technology operations.
                Our team provides professional, ethical, and transparent IT services, ensuring measurable value, operational efficiency,
                and compliance with industry best practices.
                <strong>View our Privacy Policy and Terms of Service here:</strong>
                <a href="https://stackopsit.co.za/"
                style="color:#1a73e8; text-decoration:underline;">
                    StackOps IT Solutions | Your Complete IT Force
                </a>
            </p>
             `,
            true
          );
          // Mark as sent so the automation doesn't send it again
          for (const invId of invoiceIds) {
            await connection.query("UPDATE Invoices SET PaidEmailSent = TRUE WHERE InvoiceID = ?", [invId]);
          }
        } catch (e) {
          console.error(`[YOCO WEBHOOK] Failed to send consolidated email:`, e);
        }
      }

      await connection.commit();
      return res.sendStatus(200);
    } catch (dbErr) {
      await connection.rollback();
      console.error("[YOCO WEBHOOK] ❌ DB Error:", dbErr);
      return res.sendStatus(200);
    } finally {
      connection.release();
    }
  } catch (err) {
    console.error("[YOCO WEBHOOK] ❌ Webhook Error:", err);
    return res.sendStatus(200);
  }
});


//===========================================================================================================//
//                                       DUO API INTEGRATION                                                 //
//===========================================================================================================//
/**
 * Helper: Sign Duo Request
 * Essential for authenticating with Duo's Admin API.
 */
function signDuoRequest(method, host, path, params, skey, date) {
    // 1. Sort the keys alphabetically (Duo requirement)
    const sortedKeys = Object.keys(params).sort();
    
    // 2. Map to 'key=value' format with URL encoding
    const paramString = sortedKeys
        .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`)
        .join('&');
        
    // 3. Create the canonical string for hashing
    const canon = [date, method.toUpperCase(), host.toLowerCase(), path, paramString].join('\n');
    
    // 4. Return the HMAC-SHA1 signature
    return crypto.createHmac('sha1', skey).update(canon).digest('hex');
}

// Helper: Map Duo Edition to Marketing Name
function mapDuoEditionToMarketingName(edition) {
    if (!edition) return 'Unknown';

    const editionMap = {
        ENTERPRISE: 'Essentials',
        PLATFORM: 'Advantage',
        BEYOND: 'Premier',
        PERSONAL: 'Free'
    };

    return editionMap[edition.toUpperCase()] || edition;
}

/**
 * Main Task: Sync Duo Data
 * Fetches user counts and editions for all active clients.
 */
async function syncDuoData() {
    console.log('[Duo Sync] Awakening Engine... 🤖');
    try {
        const ikey = await getSecret('DUO_IKEY');
        const skey = await getSecret('DUO_SKEY');
        if (!ikey || !skey) return;

        const [clients] = await pool.query("SELECT * FROM client_duo_stats WHERE status = 'active' OR status = 'Active'");
        
        for (const client of clients) {
            const date = new Date().toUTCString();
            const host = client.duo_api_hostname.trim();
            const accId = client.duo_account_id.trim();

            // --- PART A: FETCH USED LICENSES (Active Users) ---
            const userPath = "/admin/v1/users";
            const userParams = { account_id: accId };
            const userSig = signDuoRequest("GET", host, userPath, userParams, skey, date);
            const userUrl = `https://${host}${userPath}?account_id=${encodeURIComponent(accId)}`;

            let userCount = client.used_licenses; 
            try {
                const userRes = await fetch(userUrl, {
                    headers: {
                        'Date': date,
                        'Authorization': 'Basic ' + Buffer.from(`${ikey}:${userSig}`).toString('base64')
                    }
                });
                const userData = await userRes.json();
                if (userData.stat === 'OK') {
                    userCount = userData.metadata?.total_objects || 0;
                }
            } catch (e) { console.error(`[Duo Sync] User count error:`, e.message); }

            // --- PART B: FETCH EDITION ---
            const edPath = "/admin/v1/billing/edition";
            const edParams = { account_id: accId };
            const edSig = signDuoRequest("GET", host, edPath, edParams, skey, date);
            const edUrl = `https://${host}${edPath}?account_id=${encodeURIComponent(accId)}`;

            let edition = client.edition;
            try {
                const edRes = await fetch(edUrl, {
                    headers: {
                        'Date': date,
                        'Authorization': 'Basic ' + Buffer.from(`${ikey}:${edSig}`).toString('base64')
                    }
                });
                const edData = await edRes.json();
                if (edData.stat === 'OK') {
                    edition = edData.response?.edition || edition;
                }
            } catch (e) { console.warn(`[Duo Sync] Edition fetch error:`, e.message); }

            // --- PART D: FETCH TOTAL LICENSES (The New Working Endpoint!) ---
            const limitPath = "/admin/v1/billing/user_limit";
            const limitParams = { account_id: accId };
            const limitSig = signDuoRequest("GET", host, limitPath, limitParams, skey, date);
            const limitUrl = `https://${host}${limitPath}?account_id=${encodeURIComponent(accId)}`;

            let totalLicenses = client.total_licenses;

            try {
                const limitRes = await fetch(limitUrl, {
                    headers: {
                        'Date': date,
                        'Authorization': 'Basic ' + Buffer.from(`${ikey}:${limitSig}`).toString('base64')
                    }
                });

                const limitData = await limitRes.json();

                if (limitData.stat === 'OK') {
                    // Mapping 'user_limit' from API to 'total_licenses' in DB
                    totalLicenses = limitData.response?.user_limit || totalLicenses;
                    // Note: current_user_count is also available here if Part A fails
                    userCount = limitData.response?.current_user_count || userCount;
                } else {
                    console.error(`[Duo Sync] Limit API Error for ${client.name}:`, limitData.message);
                }
            } catch (e) {
                console.error(`[Duo Sync] Limit fetch failure:`, e.message);
            }

            // --- PART C: UPDATE DATABASE ---
            await pool.query(
                "UPDATE client_duo_stats SET used_licenses = ?, total_licenses = ?, edition = ?, last_updated = NOW() WHERE id = ?",
                [userCount, totalLicenses, edition, client.id]
            );
            console.log(`[Duo Sync Success] ${client.name} -> Used: ${userCount}, Total: ${totalLicenses} 📊`);
        }
    } catch (error) {
        console.error('[Duo Sync] Critical Failure:', error);
    }
}

/**
 * Endpoint: Get Duo Stats for Logged-in Client
 * Route: GET /api/duo-stats
 */
app.get('/api/duo-stats', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id; // From JWT token

        const [rows] = await pool.query(
            `SELECT cds.used_licenses, cds.total_licenses, cds.edition, cds.last_updated, cds.duo_account_id, cds.status 
             FROM client_duo_stats cds
             JOIN user_duo_accounts uda ON cds.id = uda.duo_id
             WHERE uda.user_id = ?`,
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: "No Duo stats found for this account." });
        }

        const stats = rows[0];

        // --- MATH ENGINE START ---
        const used = stats.used_licenses || 0;
        const total = stats.total_licenses || 0;
        const remaining = Math.max(0, total - used); // Use Math.max to avoid negative numbers if over-limit
        const percentUsed = total > 0 ? Math.round((used / total) * 100) : 0;
        // --- MATH ENGINE END ---

        // Format the date for the client's local timezone
        const formattedDate = new Date(stats.last_updated).toLocaleString();

        res.json({
            used_licenses: used,
            total_licenses: total,
            remaining_licenses: remaining, // 🆕 The requested field
            usage_percent: percentUsed,    // 🆕 Great for UI progress bars
            edition: mapDuoEditionToMarketingName(stats.edition),
            status: stats.status,
            last_sync: formattedDate,
            account_id: stats.duo_account_id
        });

    } catch (error) {
        console.error('Error fetching Duo stats:', error);
        res.status(500).json({ error: 'Failed to retrieve Duo security data.' });
    }
});

// Trigger immediately on startup (for testing)
setTimeout(() => {
    console.log('[Test] Running DUO sync on startup...');
    syncDuoData();
}, 1000);

// Hourly loop
setInterval(syncDuoData, 60 * 60 * 1000);

// ====================================================================================================//
//                             MICROSOFT GRAPH -  Identity Protection                                  //
// ====================================================================================================//

async function fetchIdentityMetricsFromApi(tokenOverride = null) {
    const token = tokenOverride || await getMicrosoftGraphToken();
    const [users, roleAssignments, signIns] = await Promise.all([
        fetchMicrosoftUsers(token),
        fetchMicrosoftRoleAssignments(token),
        fetchMicrosoftSignIns(token, 1)
    ]);

    const totalUsers = users.length;
    const activeUserIds = new Set(signIns.map(s => s.userId).filter(Boolean));
    const activeUsers = activeUserIds.size;
    const adminRoles = roleAssignments.length;
    const score = Math.max(0, Math.min(100, Math.round(100 - (adminRoles * 0.4) - ((totalUsers - activeUsers) * 0.2))));
    return { totalUsers, activeUsers, adminRoles, securityScore: score };
}

function processMicrosoftRoleAssignments(roleAssignments) {
    return (roleAssignments || []).map(assignment => {
        const roleName = assignment.roleDefinition?.displayName || assignment.roleName || 'Unknown Role';
        return {
            id: assignment.id,
            principalId: assignment.principalId,
            roleId: assignment.roleDefinition?.id || assignment.roleDefinitionId || assignment.roleId,
            roleName,
            principalType: assignment.principalType,
            resourceScope: assignment.resourceScope,
            directoryScopeId: assignment.directoryScopeId
        };
    });
}

function buildRolesByPrincipal(roleAssignments) {
    const rolesByPrincipal = {};
    (roleAssignments || []).forEach(assignment => {
        const principalId = assignment.principalId;
        if (!principalId) return;

        if (!rolesByPrincipal[principalId]) rolesByPrincipal[principalId] = [];
        const role = {
            id: assignment.roleId,
            name: assignment.roleName || 'Unknown Role'
        };

        if (!rolesByPrincipal[principalId].some(existing => existing.name === role.name)) {
            rolesByPrincipal[principalId].push(role);
        }
    });
    return rolesByPrincipal;
}

function mergeUsersWithRoleAssignments(users, roleAssignments) {
    const rolesByPrincipal = buildRolesByPrincipal(roleAssignments);
    return (users || []).map(user => {
        const roles = rolesByPrincipal[user.id] || user.roles || [];
        return {
            ...user,
            roles,
            hasAdminRole: roles.some(role => {
                const name = String(role?.name || role || '').toLowerCase();
                return name.includes('admin') || name.includes('global');
            })
        };
    });
}

async function upsertRoleAssignmentsCache(companyId, roleAssignments) {
    if (!pool || !companyId) return;
    await pool.query(
        `REPLACE INTO MicrosoftRoleAssignmentsCache (CompanyID, AssignmentsPayload, LastUpdated)
         VALUES (?, ?, NOW())`,
        [companyId, JSON.stringify(roleAssignments || [])]
    );
}

async function getCachedRoleAssignments(companyId) {
    if (!pool || !companyId) return null;
    const [rows] = await pool.query(
        'SELECT AssignmentsPayload, LastUpdated FROM MicrosoftRoleAssignmentsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1',
        [companyId]
    );
    if (!rows.length || !rows[0].AssignmentsPayload) return null;

    try {
        return {
            roleAssignments: JSON.parse(rows[0].AssignmentsPayload) || [],
            fetchedAt: rows[0].LastUpdated
        };
    } catch (error) {
        console.warn('[Microsoft Roles Cache] Failed to parse cached roles:', error.message);
        return null;
    }
}

async function fetchRoleAssignmentsFromApi(companyId) {
    const token = await getMicrosoftGraphToken();
    const rawAssignments = await fetchMicrosoftRoleAssignments(token);
    const roleAssignments = processMicrosoftRoleAssignments(rawAssignments);
    if (companyId) {
        await upsertRoleAssignmentsCache(companyId, roleAssignments);
    }
    return roleAssignments;
}

function isWorkforceMicrosoftUser(user) {
    const userType = String(user?.userType || user?.UserType || '').trim().toLowerCase();
    const principal = String(user?.userPrincipalName || user?.mail || '').toLowerCase();
    if (userType === 'member') return true;
    if (userType === 'guest') return false;
    return false;
}

function isGuestMicrosoftUser(user) {
    const userType = String(user?.userType || user?.UserType || '').trim().toLowerCase();
    const principal = String(user?.userPrincipalName || user?.mail || '').toLowerCase();
    if (userType === 'guest') return true;
    if (principal.includes('#ext#') || principal.includes('onmicrosoft.com#ext#')) return true;
    return false;
}

function normalizeMicrosoftUsers(users) {
    return (users || []).map(user => {
        const isGuest = isGuestMicrosoftUser(user);
        const isMember = isWorkforceMicrosoftUser(user);
        const userType = String(user.userType || user.UserType || '').trim().toLowerCase();
        return {
            id: user.id,
            displayName: user.displayName || 'Unknown User',
            mail: user.mail || user.userPrincipalName || 'N/A',
            jobTitle: user.jobTitle || 'No Title',
            mobilePhone: user.mobilePhone || 'N/A',
            userPrincipalName: user.userPrincipalName,
            userType: isMember ? 'Member' : isGuest ? 'Guest' : userType ? userType.charAt(0).toUpperCase() + userType.slice(1) : 'Unknown',
            isExternal: isGuest,
            isWorkforce: isMember,
            status: 'active',
            lastSync: new Date().toISOString(),
            assignedLicenses: Array.isArray(user.assignedLicenses) ? user.assignedLicenses : [],
            licenseAssignmentStates: Array.isArray(user.licenseAssignmentStates) ? user.licenseAssignmentStates : []
        };
    });
}

async function fetchIdentityDetailsFromApi(tokenOverride = null) {
    const token = tokenOverride || await getMicrosoftGraphToken();
    const [users, rawRoleAssignments] = await Promise.all([
        fetchMicrosoftUsers(token),
        fetchMicrosoftRoleAssignments(token)
    ]);
    const processedUsers = normalizeMicrosoftUsers(users);
    const roleAssignments = processMicrosoftRoleAssignments(rawRoleAssignments);
    return {
        totalUsers: processedUsers.length,
        users: mergeUsersWithRoleAssignments(processedUsers, roleAssignments),
        roleAssignments
    };
}

async function fetchDeviceIntelligenceEvidenceFromApi(tokenOverride = null) {
    const token = tokenOverride || await getMicrosoftGraphToken();
    const devices = await fetchMicrosoftDevices(token);
    const totalDevices = devices.length;
    const normalizeCompliance = value => String(value || 'unknown').toLowerCase().replace(/[_\s-]/g, '');
    const nonCompliant = devices.filter(d => normalizeCompliance(d.complianceState) === 'noncompliant').length;
    const notEncrypted = devices.filter(d => !d.isEncrypted).length;
    const staleDevices = devices.filter(d => {
        if (!d.lastSyncDateTime) return true;
        const daysSinceSync = (Date.now() - new Date(d.lastSyncDateTime).getTime()) / (1000 * 60 * 60 * 24);
        return daysSinceSync > 7;
    }).length;
    return { totalDevices, nonCompliant, notEncrypted, staleDevices, devices };
}

async function fetchDeviceMetricsFromApi() {
    const evidence = await fetchDeviceIntelligenceEvidenceFromApi();
    return {
        totalDevices: evidence.totalDevices,
        nonCompliant: evidence.nonCompliant,
        notEncrypted: evidence.notEncrypted,
        staleDevices: evidence.staleDevices
    };
}

async function fetchApplicationMetricsFromApi(tokenOverride = null) {
    const token = tokenOverride || await getMicrosoftGraphToken();
    const servicePrincipals = await fetchMicrosoftServicePrincipals(token);
    const totalApps = servicePrincipals.length;
    const externalApps = servicePrincipals.filter(sp => !(sp.publisherName || '').toLowerCase().includes('microsoft')).length;
    const highRiskApps = servicePrincipals.filter(sp => (sp.oauth2PermissionScopes || []).length + (sp.appRoles || []).length > 10).length;
    const highAccessApps = servicePrincipals.filter(sp => (sp.appRoles || []).length > 5).length;
    return { totalApps, externalApps, highRiskApps, highAccessApps };
}

async function fetchApplicationsPayloadFromApi(tokenOverride = null) {
    const token = tokenOverride || await getMicrosoftGraphToken();
    const [servicePrincipalsRaw, users, groups] = await Promise.all([
        fetchMicrosoftServicePrincipals(token),
        fetchMicrosoftUsers(token),
        fetchMicrosoftGroups(token)
    ]);

    const processedApps = await mapWithConcurrency(servicePrincipalsRaw, 5, async (sp) => {
        const publisherName = sp.publisherName ? sp.publisherName.toLowerCase() : '';
        const isExternal = !publisherName.includes('microsoft');
        const scopeCount = sp.oauth2PermissionScopes ? sp.oauth2PermissionScopes.length : 0;
        const roleCount = sp.appRoles ? sp.appRoles.length : 0;
        let assignedCount = 0;
        let assignedGroups = [];

        try {
            const assignments = await fetchAppRoleAssignments(token, sp.id);
            assignedCount = assignments.length;
            assignedGroups = assignments
                .filter(a => a.principalType === 'Group')
                .map(a => a.principalDisplayName)
                .filter((value, index, array) => value && array.indexOf(value) === index);
        } catch (error) {
            console.warn(`[Applications] Failed assignments for ${sp.displayName}:`, error.message);
        }

        return {
            id: sp.id,
            name: sp.displayName || 'Unknown App',
            displayName: sp.displayName || 'Unknown App',
            type: isExternal ? 'External' : 'Microsoft',
            isExternal,
            createdDateTime: sp.createdDateTime,
            scopeCount,
            roleCount,
            userCount: assignedCount,
            assignedGroups,
            publisherName: sp.publisherName || 'Unknown'
        };
    });

    const totalApplications = processedApps.length;
    const externalApplications = processedApps.filter(app => app.isExternal).length;
    const highRiskApps = processedApps.filter(app => app.isExternal || ((app.scopeCount || 0) + (app.roleCount || 0)) > 10 || (app.userCount || 0) > 50).length;
    const highAccessApps = processedApps.filter(app => (app.userCount || 0) >= 20 || (app.assignedGroups || []).length >= 3).length;

    return {
        success: true,
        fetchedAt: new Date().toISOString(),
        totalApplications,
        externalApplications,
        highRiskApps,
        highAccessApps,
        applications: processedApps,
        topAppsByUsers: processedApps.slice().sort((a, b) => (b.userCount || 0) - (a.userCount || 0)).slice(0, 10),
        userCount: users.length,
        groupCount: groups.length,
        summary: {
            totalApplications,
            externalApplications,
            highRiskApps,
            highAccessApps,
            userCount: users.length,
            groupCount: groups.length
        }
    };
}

async function fetchEmailMetricsFromApi() {
    const payload = await fetchEmailSecurityPayloadFromApi();
    return {
        activeThreats: payload.summary.activeThreats,
        highSeverity: payload.summary.highSeverityAlerts,
        usersTargeted: payload.summary.affectedUsersCount,
        openIncidents: payload.summary.activeIncidents
    };
}

async function fetchEmailActivityReport(token, { signal = null, collectorContext = {} } = {}) {
    try {
        const { response, body: csv } = await fetchGraphResponseWithDeadline("https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D7')", token, {
            signal,
            collectorContext,
            label: 'Email activity Graph report'
        });
        if (!response.ok) {
            console.warn('[Email Security] Email activity report returned:', response.status);
            return { users: [], summary: {} };
        }
        const rows = parseGraphReportCSV(csv, 'Email Activity');
        const users = rows
            .filter(row => row['User Principal Name'])
            .map(row => ({
                userPrincipalName: row['User Principal Name'],
                displayName: row['Display Name'] || row['User Principal Name'],
                lastActivityDate: row['Last Activity Date'] || '',
                sendCount: Number(row['Send Count'] || 0),
                receiveCount: Number(row['Receive Count'] || 0),
                readCount: Number(row['Read Count'] || 0),
                reportRefreshDate: row['Report Refresh Date'] || '',
                reportPeriod: row['Report Period'] || '7'
            }));
        const summary = users.reduce((acc, user) => {
            acc.activeMailboxes += user.lastActivityDate ? 1 : 0;
            acc.sendCount += user.sendCount;
            acc.receiveCount += user.receiveCount;
            acc.readCount += user.readCount;
            return acc;
        }, { activeMailboxes: 0, sendCount: 0, receiveCount: 0, readCount: 0 });
        summary.totalMailActivity = summary.sendCount + summary.receiveCount + summary.readCount;
        return { users, summary };
    } catch (error) {
        console.warn('[Email Security] Email activity report failed:', error.message);
        return { users: [], summary: {} };
    }
}

function isEmailSecuritySignal(item = {}) {
    const text = [
        item.title,
        item.description,
        item.category,
        item.serviceSource,
        item.detectionSource,
        item.vendorInformation?.provider
    ].filter(Boolean).join(' ').toLowerCase();
    return /(email|mail|exchange|phish|spam|spoof|malware|attachment|safe links|safe attachments|impersonation|business email|quarantine)/.test(text);
}

function normalizeGraphCollectionPayload(value, preferredKey = null) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    if (preferredKey && Array.isArray(value[preferredKey])) return value[preferredKey];
    if (Array.isArray(value.alerts)) return value.alerts;
    if (Array.isArray(value.incidents)) return value.incidents;
    if (Array.isArray(value.value)) return value.value;
    if (Array.isArray(value.data)) return value.data;
    return [];
}

async function fetchEmailSecurityPayloadFromApi(tokenOverride = null, { signal = null, collectorContext = {} } = {}) {
    const token = tokenOverride || await getMicrosoftGraphToken({ securityAlerts: true });
    const fetchedAt = new Date().toISOString();

    function cleanWarning(value) {
        return String(value || '').trim();
    }

    function uniqueWarnings(items = []) {
        return [...new Set(items.map(cleanWarning).filter(Boolean))];
    }

    function normalizeCollection(value, preferredKey = null) {
        return normalizeGraphCollectionPayload(value, preferredKey);
    }

    async function fetchEmailAlertsSafe() {
        try {
            if (typeof fetchSecurityAlertRows === 'function') {
                const result = await fetchSecurityAlertRows(token);
                return {
                    records: normalizeCollection(result?.alerts || result, 'alerts'),
                    warnings: Array.isArray(result?.warnings) ? result.warnings : [],
                    recordsFetched: Number(result?.recordsFetched || 0),
                    ok: result?.ok !== false,
                    sourceFunction: 'fetchSecurityAlertRows'
                };
            }

            if (typeof fetchSecurityAlerts === 'function') {
                const result = await fetchSecurityAlerts(token);
                return {
                    records: normalizeCollection(result, 'alerts'),
                    warnings: [],
                    recordsFetched: normalizeCollection(result, 'alerts').length,
                    ok: true,
                    sourceFunction: 'fetchSecurityAlerts'
                };
            }

            return {
                records: [],
                warnings: ['Email Security alerts unavailable: no alert fetch function is defined.'],
                recordsFetched: 0,
                ok: false,
                sourceFunction: null
            };
        } catch (error) {
            return {
                records: [],
                warnings: [`Email Security alerts fetch failed: ${error.message || error}`],
                recordsFetched: 0,
                ok: false,
                sourceFunction: 'alerts_fetch_failed'
            };
        }
    }

    async function fetchEmailIncidentsSafe() {
        try {
            if (typeof fetchSecurityIncidentRows === 'function') {
                const result = await fetchSecurityIncidentRows(token);
                return {
                    records: normalizeCollection(result?.incidents || result, 'incidents'),
                    warnings: Array.isArray(result?.warnings) ? result.warnings : [],
                    recordsFetched: Number(result?.recordsFetched || 0),
                    ok: result?.ok !== false,
                    sourceFunction: 'fetchSecurityIncidentRows'
                };
            }

            if (typeof fetchSecurityIncidents === 'function') {
                const result = await fetchSecurityIncidents(token);
                return {
                    records: normalizeCollection(result?.incidents || result, 'incidents'),
                    warnings: Array.isArray(result?.warnings) ? result.warnings : [],
                    recordsFetched: normalizeCollection(result?.incidents || result, 'incidents').length,
                    ok: true,
                    sourceFunction: 'fetchSecurityIncidents'
                };
            }

            return {
                records: [],
                warnings: ['Email Security incidents unavailable: no incident fetch function is defined.'],
                recordsFetched: 0,
                ok: false,
                sourceFunction: null
            };
        } catch (error) {
            return {
                records: [],
                warnings: [`Email Security incidents fetch failed: ${error.message || error}`],
                recordsFetched: 0,
                ok: false,
                sourceFunction: 'incidents_fetch_failed'
            };
        }
    }

    async function fetchEmailActivitySafe() {
        try {
            const result = await fetchEmailActivityReport(token, { signal, collectorContext });
            const users = Array.isArray(result?.users) ? result.users : [];

            return {
                users,
                summary: result?.summary || {},
                warnings: Array.isArray(result?.warnings) ? result.warnings : [],
                recordsFetched: users.length,
                ok: true,
                sourceFunction: 'fetchEmailActivityReport'
            };
        } catch (error) {
            return {
                users: [],
                summary: {},
                warnings: [`Email activity report failed: ${error.message || error}`],
                recordsFetched: 0,
                ok: false,
                sourceFunction: 'fetchEmailActivityReport'
            };
        }
    }

    const [alertsSettled, incidentsSettled, activitySettled] = await Promise.allSettled([
        fetchEmailAlertsSafe(),
        fetchEmailIncidentsSafe(),
        fetchEmailActivitySafe()
    ]);

    const alertsResult = alertsSettled.status === 'fulfilled'
        ? alertsSettled.value
        : {
            records: [],
            warnings: [`Email Security alerts fetch failed: ${alertsSettled.reason?.message || alertsSettled.reason}`],
            recordsFetched: 0,
            ok: false,
            sourceFunction: 'alerts_settled_failure'
        };

    const incidentsResult = incidentsSettled.status === 'fulfilled'
        ? incidentsSettled.value
        : {
            records: [],
            warnings: [`Email Security incidents fetch failed: ${incidentsSettled.reason?.message || incidentsSettled.reason}`],
            recordsFetched: 0,
            ok: false,
            sourceFunction: 'incidents_settled_failure'
        };

    const mailActivity = activitySettled.status === 'fulfilled'
        ? activitySettled.value
        : {
            users: [],
            summary: {},
            warnings: [`Email activity report failed: ${activitySettled.reason?.message || activitySettled.reason}`],
            recordsFetched: 0,
            ok: false,
            sourceFunction: 'activity_settled_failure'
        };

    const alerts = normalizeCollection(alertsResult.records, 'alerts');
    const incidents = normalizeCollection(incidentsResult.records, 'incidents');

    const emailKeywords = [
        'phishing',
        'malware',
        'spam',
        'email',
        'mail',
        'exchange',
        'attachment',
        'suspicious mail',
        'ransomware',
        'spoof',
        'impersonation',
        'business email',
        'bec',
        'safe links',
        'safe attachments',
        'quarantine'
    ];

    const emailAlerts = alerts.filter(isEmailSecuritySignal);

    const emailIncidents = incidents.filter(incident => {
        const text = [
            incident.displayName,
            incident.title,
            incident.description,
            incident.category,
            incident.classification,
            incident.determination
        ].filter(Boolean).join(' ').toLowerCase();

        return emailKeywords.some(keyword => text.includes(keyword));
    });

    const processedAlerts = emailAlerts.map((alert, index) => {
        const userStates = Array.isArray(alert.userStates) ? alert.userStates : [];
        const firstUser = userStates[0] || {};

        return {
            id: alert.id || `email-alert-${index + 1}`,
            title: alert.title || alert.alertName || alert.displayName || 'Unknown Email Alert',
            description: alert.description || '',
            severity: String(alert.severity || 'medium').toLowerCase(),
            status: String(alert.status || 'newAlert').toLowerCase(),
            created: alert.createdDateTime || alert.eventDateTime || alert.lastModifiedDateTime || fetchedAt,
            updated: alert.lastModifiedDateTime || alert.resolvedDateTime || alert.createdDateTime || fetchedAt,
            category: alert.category || alert.serviceSource || 'Email Security Alert',
            sender: alert.senderAddress || alert.senderEmail || alert.fromAddress || alert.mailFrom || 'Unknown sender',
            recipient: firstUser.accountName || alert.userPrincipalName || alert.userEmail || alert.recipientEmailAddress || 'Unknown user',
            source: alert.serviceSource || alert.vendorInformation?.provider || 'Microsoft Security',
            vendorInformation: alert.vendorInformation?.provider || 'Microsoft Security',
            detectionSource: alert.detectionSource || null,
            userStates: userStates.map(user => ({
                aadUserId: user.aadUserId || user.userId || null,
                accountName: user.accountName || user.userPrincipalName || 'Unknown'
            }))
        };
    });

    const processedIncidents = emailIncidents.map((incident, index) => ({
        id: incident.id || `email-incident-${index + 1}`,
        displayName: incident.displayName || incident.title || 'Unknown Email Incident',
        description: incident.description || '',
        severity: String(incident.severity || 'medium').toLowerCase(),
        status: String(incident.status || 'active').toLowerCase(),
        created: incident.createdDateTime || fetchedAt,
        updated: incident.lastUpdateDateTime || incident.lastUpdatedDateTime || incident.createdDateTime || fetchedAt,
        assignedTo: incident.assignedTo || 'Unassigned',
        classification: incident.classification || null,
        determination: incident.determination || null
    }));

    const activeThreats = processedAlerts.filter(alert =>
        ['newalert', 'new', 'inprogress', 'active'].includes(String(alert.status || '').toLowerCase())
    ).length;

    const highSeverityAlerts = processedAlerts.filter(alert =>
        ['critical', 'high'].includes(String(alert.severity || '').toLowerCase())
    ).length;

    const activeIncidents = processedIncidents.filter(incident =>
        ['active', 'inprogress', 'new', 'open'].includes(String(incident.status || '').toLowerCase())
    ).length;

    const resolvedAlerts = processedAlerts.filter(alert =>
        ['resolved', 'dismissed', 'closed'].includes(String(alert.status || '').toLowerCase())
    ).length;

    const threatResolutionRate = processedAlerts.length
        ? Math.round((resolvedAlerts / processedAlerts.length) * 100)
        : 100;

    const affectedUsersSet = new Set();
    const userThreatCount = {};

    processedAlerts.forEach(alert => {
        const users = Array.isArray(alert.userStates) && alert.userStates.length
            ? alert.userStates
            : [{ accountName: alert.recipient }];

        users.forEach(user => {
            const name = user.accountName || user.userPrincipalName || alert.recipient;
            if (!name || name === 'Unknown user') return;

            affectedUsersSet.add(name);
            userThreatCount[name] = (userThreatCount[name] || 0) + 1;
        });
    });

    const affectedUsers = Array.from(affectedUsersSet);

    const mostTargeted = Object.entries(userThreatCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([user, threatCount]) => ({ user, threatCount }));

    const byType = {};
    const bySeverity = { high: 0, medium: 0, low: 0 };

    processedAlerts.forEach(alert => {
        const text = `${alert.title || ''} ${alert.description || ''} ${alert.category || ''}`.toLowerCase();

        let type = 'Other';
        if (text.includes('phish')) type = 'Phishing';
        else if (text.includes('malware') || text.includes('attachment') || text.includes('ransomware')) type = 'Malware';
        else if (text.includes('spam')) type = 'Spam';
        else if (text.includes('spoof')) type = 'Spoofing';
        else if (text.includes('impersonation') || text.includes('business email') || text.includes('bec')) type = 'BEC';

        byType[type] = (byType[type] || 0) + 1;

        if (alert.severity === 'critical' || alert.severity === 'high') bySeverity.high += 1;
        else if (alert.severity === 'medium') bySeverity.medium += 1;
        else bySeverity.low += 1;
    });

    let securityScore = 100;
    const severityScores = { critical: 18, high: 12, medium: 5, low: 2 };

    processedAlerts.slice(0, 30).forEach(alert => {
        securityScore -= severityScores[alert.severity] || 2;
    });

    securityScore = Math.max(0, Math.min(100, securityScore));

    const mailUsers = Array.isArray(mailActivity.users) ? mailActivity.users : [];
    const mailSummary = mailActivity.summary || {};

    const warnings = uniqueWarnings([
        ...(Array.isArray(alertsResult.warnings) ? alertsResult.warnings : []),
        ...(Array.isArray(incidentsResult.warnings) ? incidentsResult.warnings : []),
        ...(Array.isArray(mailActivity.warnings) ? mailActivity.warnings : [])
    ]);

    const recordsFetched =
        Number(alertsResult.recordsFetched || alerts.length || 0) +
        Number(incidentsResult.recordsFetched || incidents.length || 0) +
        Number(mailActivity.recordsFetched || mailUsers.length || 0);

    const recordsPrepared = processedAlerts.length + processedIncidents.length + mailUsers.length;

    const hasUsableEvidence = Boolean(recordsPrepared > 0 || mailUsers.length > 0);

    if (!hasUsableEvidence) {
        const error = new Error(
            warnings.length
                ? `Email evidence refresh failed: ${warnings.join('; ')}`
                : 'Email evidence refresh failed: no usable Email Security evidence was returned.'
        );

        error.isRefreshError = true;
        error.emailSecurityStage = 'email_security_source_collection';
        error.emailSecurityWarnings = warnings;

        throw error;
    }

    const insights = [];

    if (highSeverityAlerts > 0) {
        insights.push({
            type: 'critical',
            message: `${highSeverityAlerts} high-severity email threat(s) detected`,
            action: 'Review Alerts',
            count: highSeverityAlerts
        });
    }

    if (affectedUsers.length > 0) {
        insights.push({
            type: 'info',
            message: `${affectedUsers.length} user(s) affected by email threats`,
            action: 'View Users',
            count: affectedUsers.length
        });
    }

    if (activeIncidents > 0) {
        insights.push({
            type: 'critical',
            message: `${activeIncidents} unresolved email incident(s) requiring attention`,
            action: 'View Incidents',
            count: activeIncidents
        });
    }

    if (threatResolutionRate < 50) {
        insights.push({
            type: 'warning',
            message: `Only ${threatResolutionRate}% of email threats have been resolved`,
            action: 'Improve Response',
            count: threatResolutionRate
        });
    }

    return {
        success: true,
        fetchedAt,
        collectionStatus: warnings.length ? 'completed_with_warnings' : 'complete',
        warnings,
        summary: {
            activeThreats,
            highSeverityAlerts,
            activeIncidents,
            affectedUsersCount: affectedUsers.length,
            threatResolutionRate,
            securityScore,
            phishingCount: processedAlerts.filter(alert => /phish/i.test(`${alert.title} ${alert.description} ${alert.category}`)).length,
            malwareCount: processedAlerts.filter(alert => /malware|ransomware|virus|trojan|attachment/i.test(`${alert.title} ${alert.description} ${alert.category}`)).length,
            spamCount: processedAlerts.filter(alert => /spam/i.test(`${alert.title} ${alert.description} ${alert.category}`)).length,
            becCount: processedAlerts.filter(alert => /business email|bec|impersonation|spoof/i.test(`${alert.title} ${alert.description} ${alert.category}`)).length,
            activeMailboxes: mailSummary.activeMailboxes || 0,
            totalMailActivity: mailSummary.totalMailActivity || 0,
            sendCount: mailSummary.sendCount || 0,
            receiveCount: mailSummary.receiveCount || 0,
            readCount: mailSummary.readCount || 0,
            recordsFetched,
            recordsPrepared,
            recordsOmitted: Math.max(0, alerts.length + incidents.length - processedAlerts.length - processedIncidents.length),
            mailActivity: mailSummary
        },
        alerts: processedAlerts,
        incidents: processedIncidents,
        threats: { byType, bySeverity },
        affectedUsers: { all: affectedUsers, mostTargeted },
        mailActivity: {
            users: mailUsers,
            summary: mailSummary
        },
        insights,
        sourceAudit: {
            source: 'stackctrl_email_security_graph_collection',
            fetchedAt,
            alertsFunction: alertsResult.sourceFunction,
            incidentsFunction: incidentsResult.sourceFunction,
            mailActivityFunction: mailActivity.sourceFunction,
            alertsOk: alertsResult.ok !== false,
            incidentsOk: incidentsResult.ok !== false,
            mailActivityOk: mailActivity.ok !== false,
            warnings
        }
    };
}

async function fetchBackupRecoveryPayloadFromApi(tokenOverride = null, { signal = null, collectorContext = {} } = {}) {
    const token = tokenOverride || await getMicrosoftGraphToken();

    // Fetch OneDrive usage (returns CSV)
    const oneDriveUrl = 'https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period=\'D7\')';
    const oneDriveCSV = await fetchGraphReportCSV(oneDriveUrl, token, 'OneDrive', { signal, collectorContext });
    const oneDriveData = parseGraphReportCSV(oneDriveCSV, 'OneDrive');

    // Fetch SharePoint usage (returns CSV)
    const sharePointUrl = 'https://graph.microsoft.com/v1.0/reports/getSharePointSiteUsageDetail(period=\'D7\')';
    const sharePointCSV = await fetchGraphReportCSV(sharePointUrl, token, 'SharePoint', { signal, collectorContext });
    const sharePointData = parseGraphReportCSV(sharePointCSV, 'SharePoint');

    // Fetch Exchange (Mailbox) usage (returns CSV)
    const exchangeUrl = 'https://graph.microsoft.com/v1.0/reports/getMailboxUsageDetail(period=\'D7\')';
    const exchangeCSV = await fetchGraphReportCSV(exchangeUrl, token, 'Exchange', { signal, collectorContext });
    const exchangeData = parseGraphReportCSV(exchangeCSV, 'Exchange');

    // Process OneDrive storage (in bytes)
    let oneDriveStorageBytes = 0;
    const oneDriveUsers = [];
    oneDriveData.forEach(item => {
        const storageBytes = parseGraphReportNumber(item['Storage Used (Byte)']);
        oneDriveStorageBytes += storageBytes;
        if (item['Owner Principal Name'] && storageBytes > 0) {
            oneDriveUsers.push({
                user: item['Owner Principal Name'],
                displayName: item['Owner Display Name'] || item['Owner Principal Name'],
                storage: storageBytes,
                lastActivity: item['Last Activity Date'],
                files: parseInt(item['File Count'] || 0)
            });
        }
    });

    // Process SharePoint storage (in bytes)
    let sharePointStorageBytes = 0;
    const sharePointSites = [];
    sharePointData.forEach(item => {
        const storageBytes = parseGraphReportNumber(item['Storage Used (Byte)']);
        sharePointStorageBytes += storageBytes;
        if (item['Site URL'] && storageBytes > 0) {
            sharePointSites.push({
                url: item['Site URL'],
                owner: item['Owner Display Name'] || item['Owner Principal Name'],
                storage: storageBytes,
                lastActivity: item['Last Activity Date'],
                files: parseInt(item['File Count'] || 0)
            });
        }
    });

    // Process Exchange storage (in bytes)
    let exchangeStorageBytes = 0;
    const exchangeUsers = [];
    exchangeData.forEach(item => {
        const storageBytes = parseGraphReportNumber(item['Storage Used (Byte)']);
        exchangeStorageBytes += storageBytes;
        if (item['User Principal Name'] && storageBytes > 0) {
            exchangeUsers.push({
                user: item['User Principal Name'],
                displayName: item['Display Name'] || item['User Principal Name'],
                storage: storageBytes,
                lastActivity: item['Last Activity Date'],
                items: parseInt(item['Item Count'] || 0)
            });
        }
    });

    const totalStorageBytes = oneDriveStorageBytes + sharePointStorageBytes + exchangeStorageBytes;
    const totalStorageGB = parseFloat((totalStorageBytes / (1024 ** 3)).toFixed(1));
    const oneDriveStorageGB = parseFloat((oneDriveStorageBytes / (1024 ** 3)).toFixed(1));
    const sharePointStorageGB = parseFloat((sharePointStorageBytes / (1024 ** 3)).toFixed(1));
    const exchangeStorageGB = parseFloat((exchangeStorageBytes / (1024 ** 3)).toFixed(1));

    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const allUsers = [...oneDriveUsers, ...exchangeUsers];
    const userActivity = new Map();
    allUsers.forEach(u => {
        const key = String(u.user || '').toLowerCase();
        if (!key) return;
        const lastActivityTime = u.lastActivity ? new Date(u.lastActivity).getTime() : 0;
        const current = userActivity.get(key) || { latest: 0 };
        userActivity.set(key, { latest: Math.max(current.latest, Number.isFinite(lastActivityTime) ? lastActivityTime : 0) });
    });
    const activeUserKeys = new Set();
    const inactiveUserKeys = new Set();
    userActivity.forEach((activity, key) => {
        if (activity.latest && activity.latest >= thirtyDaysAgo.getTime()) activeUserKeys.add(key);
        else inactiveUserKeys.add(key);
    });
    const inactiveUsers = allUsers.filter(u => inactiveUserKeys.has(String(u.user || '').toLowerCase()));
    const activeUsersCount = activeUserKeys.size;
    const inactiveUsersCount = inactiveUserKeys.size;
    const inactiveUserStorageBytes = inactiveUsers.reduce((sum, u) => sum + u.storage, 0);
    const inactiveUserStorageGB = parseFloat((inactiveUserStorageBytes / (1024 ** 3)).toFixed(1));

    const backupConfigured = false;

    const summary = {
        totalStorageGB,
        oneDriveStorageGB,
        sharePointStorageGB,
        exchangeStorageGB,
        activeUsersCount,
        inactiveUsersCount,
        servicesCovered: 3,
        backupConfigured
    };

    const storage = {
        byService: {
            onedrive: oneDriveStorageGB,
            sharepoint: sharePointStorageGB,
            exchange: exchangeStorageGB
        },
        inactiveUserStorageGB,
        sites: sharePointSites.sort((a, b) => b.storage - a.storage).slice(0, 10),
        users: allUsers.sort((a, b) => b.storage - a.storage).slice(0, 20),
        inactiveUsers: inactiveUsers.sort((a, b) => b.storage - a.storage)
    };

    const insights = [];
    if (totalStorageGB > 1000) {
        insights.push({ type: 'warning', message: 'Large data volume detected', detail: `${totalStorageGB}GB across Microsoft 365 services` });
    }
    if (inactiveUsersCount > 0) {
        insights.push({ type: 'info', message: `${inactiveUsersCount} inactive users holding data`, detail: `${inactiveUserStorageGB}GB in inactive user accounts` });
    }
    if (!backupConfigured) {
        insights.push({ type: 'critical', message: 'No external backup configured', detail: 'Only Microsoft-native retention policies are protecting your data' });
    }

    return {
        success: true,
        fetchedAt: new Date().toISOString(),
        summary,
        storage,
        insights
    };
}

async function upsertDashboardMetricCaches() {
    if (!pool) return;
    const [rows] = await pool.query(
        `SELECT CompanyID, MicrosoftTenantID
         FROM CompanyMicrosoftMapping
         WHERE IsActive = 1`
    );
    for (const row of rows) {
        const companyId = row.CompanyID;
        try {
            const [identity, identityDetails, devices, apps, appPayload, email, emailSecurity, securityEvents, backup] = await Promise.all([
                fetchIdentityMetricsFromApi(),
                fetchIdentityDetailsFromApi(),
                fetchDeviceMetricsFromApi(),
                fetchApplicationMetricsFromApi(),
                fetchApplicationsPayloadFromApi(),
                fetchEmailMetricsFromApi(),
                fetchEmailSecurityPayloadFromApi(),
                fetchSecurityEventsPayloadFromApi(),
                fetchBackupRecoveryPayloadFromApi()
            ]);

            await pool.query(
                `REPLACE INTO IdentityMetricsCache (CompanyID, TotalUsers, ActiveUsers, AdminRoles, SecurityScore, LastUpdated)
                 VALUES (?, ?, ?, ?, ?, NOW())`,
                [companyId, identity.totalUsers, identity.activeUsers, identity.adminRoles, identity.securityScore]
            );
            await pool.query(
                `REPLACE INTO IdentityUserDetailsCache (CompanyID, UsersPayload, LastUpdated)
                 VALUES (?, ?, NOW())`,
                [companyId, JSON.stringify(identityDetails.users || [])]
            );
            await upsertRoleAssignmentsCache(companyId, identityDetails.roleAssignments || []);
            await pool.query(
                `REPLACE INTO DeviceMetricsCache (CompanyID, TotalDevices, NonCompliant, NotEncrypted, StaleDevices, LastUpdated)
                 VALUES (?, ?, ?, ?, ?, NOW())`,
                [companyId, devices.totalDevices, devices.nonCompliant, devices.notEncrypted, devices.staleDevices]
            );
            await pool.query(
                `REPLACE INTO ApplicationMetricsCache (CompanyID, TotalApps, ExternalApps, HighRiskApps, HighAccessApps, LastUpdated)
                 VALUES (?, ?, ?, ?, ?, NOW())`,
                [companyId, apps.totalApps, apps.externalApps, apps.highRiskApps, apps.highAccessApps]
            );
            await pool.query(
                `REPLACE INTO ApplicationPayloadCache (CompanyID, Payload, LastUpdated)
                 VALUES (?, ?, NOW())`,
                [companyId, JSON.stringify(appPayload)]
            );
            await pool.query(
                `REPLACE INTO EmailMetricsCache (CompanyID, ActiveThreats, HighSeverity, UsersTargeted, OpenIncidents, LastUpdated)
                 VALUES (?, ?, ?, ?, ?, NOW())`,
                [companyId, email.activeThreats, email.highSeverity, email.usersTargeted, email.openIncidents]
            );

            await pool.query(
                `REPLACE INTO EmailSecurityPayloadCache (CompanyID, Payload, LastUpdated)
                 VALUES (?, ?, NOW())`,
                [companyId, JSON.stringify(emailSecurity)]
            );

            await pool.query(
                `REPLACE INTO SecurityEventsPayloadCache (CompanyID, Payload, LastUpdated)
                 VALUES (?, ?, NOW())`,
                [companyId, JSON.stringify(securityEvents)]
            );

            await pool.query(
                `REPLACE INTO BackupRecoveryPayloadCache (CompanyID, Payload, LastUpdated)
                 VALUES (?, ?, NOW())`,
                [companyId, JSON.stringify(backup)]
            );
        } catch (error) {
            console.error(`[Cache Worker] Failed to refresh company ${companyId}:`, error.message);
        }
    }
}

setInterval(() => {
    upsertDashboardMetricCaches().catch(error => {
        console.error('[Cache Worker] Refresh loop failed:', error.message);
    });
}, 5 * 60 * 1000);

app.get('/api/db/identity-metrics', authenticateToken, async (req, res) => {
    try {
        const context = await getAccessContextByUser(req.user);
        if (!context?.companyId) return res.status(403).json({ success: false, message: 'Access mapping not configured' });
        const [rows] = await pool.query('SELECT * FROM IdentityMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [context.companyId]);
        if (rows.length > 0) return res.json({ success: true, source: 'db', metrics: rows[0] });

        const api = await fetchIdentityMetricsFromApi();
        await pool.query(
            `REPLACE INTO IdentityMetricsCache (CompanyID, TotalUsers, ActiveUsers, AdminRoles, SecurityScore, LastUpdated)
             VALUES (?, ?, ?, ?, ?, NOW())`,
            [context.companyId, api.totalUsers, api.activeUsers, api.adminRoles, api.securityScore]
        );
        return res.json({ success: true, source: 'api-fallback', metrics: api });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/db/identity-details', authenticateToken, async (req, res) => {
    try {
        const context = await getAccessContextByUser(req.user);
        if (!context?.companyId) return res.status(403).json({ success: false, message: 'Access mapping not configured' });

        const [rows] = await pool.query(
            'SELECT UsersPayload, LastUpdated FROM IdentityUserDetailsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1',
            [context.companyId]
        );

        if (rows.length > 0 && rows[0].UsersPayload) {
            let users = [];
            try {
                users = JSON.parse(rows[0].UsersPayload) || [];
            } catch (error) {
                users = [];
            }
            if (Array.isArray(users) && users.length > 0) {
                let cachedRoles = await getCachedRoleAssignments(context.companyId);
                if (!cachedRoles || cachedRoles.roleAssignments.length === 0) {
                    try {
                        const liveRoles = await fetchRoleAssignmentsFromApi(context.companyId);
                        cachedRoles = { roleAssignments: liveRoles, fetchedAt: new Date().toISOString() };
                    } catch (roleError) {
                        console.warn('[Identity Details] Failed to refresh role cache:', roleError.message);
                    }
                }

                const roleAssignments = cachedRoles?.roleAssignments || [];
                const usersWithRoles = mergeUsersWithRoleAssignments(users, roleAssignments);

                return res.json({
                    success: true,
                    source: 'db',
                    totalUsers: usersWithRoles.length,
                    users: usersWithRoles,
                    roleAssignments,
                    fetchedAt: rows[0].LastUpdated
                });
            }
        }

        const api = await fetchIdentityDetailsFromApi();
        await pool.query(
            `REPLACE INTO IdentityUserDetailsCache (CompanyID, UsersPayload, LastUpdated)
             VALUES (?, ?, NOW())`,
            [context.companyId, JSON.stringify(api.users || [])]
        );
        await upsertRoleAssignmentsCache(context.companyId, api.roleAssignments || []);
        return res.json({
            success: true,
            source: 'api-fallback',
            totalUsers: api.totalUsers,
            users: api.users,
            roleAssignments: api.roleAssignments || [],
            fetchedAt: new Date().toISOString()
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/db/device-metrics', authenticateToken, async (req, res) => {
    try {
        const context = await getAccessContextByUser(req.user);
        if (!context?.companyId) return res.status(403).json({ success: false, message: 'Access mapping not configured' });
        const [rows] = await pool.query('SELECT * FROM DeviceMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [context.companyId]);
        if (rows.length > 0) return res.json({ success: true, source: 'db', metrics: rows[0] });
        const api = await fetchDeviceMetricsFromApi();
        await pool.query(
            `REPLACE INTO DeviceMetricsCache (CompanyID, TotalDevices, NonCompliant, NotEncrypted, StaleDevices, LastUpdated)
             VALUES (?, ?, ?, ?, ?, NOW())`,
            [context.companyId, api.totalDevices, api.nonCompliant, api.notEncrypted, api.staleDevices]
        );
        return res.json({ success: true, source: 'api-fallback', metrics: api });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/db/email-metrics', authenticateToken, async (req, res) => {
    try {
        const context = await getAccessContextByUser(req.user);
        if (!context?.companyId) return res.status(403).json({ success: false, message: 'Access mapping not configured' });
        const [rows] = await pool.query('SELECT * FROM EmailMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [context.companyId]);
        if (rows.length > 0) {
            const cached = rows[0];
            const hasSignals = Number(cached.ActiveThreats || 0) + Number(cached.HighSeverity || 0) + Number(cached.UsersTargeted || 0) + Number(cached.OpenIncidents || 0) > 0;
            const ageMs = cached.LastUpdated ? Date.now() - new Date(cached.LastUpdated).getTime() : Number.POSITIVE_INFINITY;
            const isFresh = Number.isFinite(ageMs) && ageMs < 5 * 60 * 1000;
            if (hasSignals) return res.json({ success: true, source: 'db', metrics: cached });
            if (isFresh) return res.json({ success: true, source: 'db', metrics: cached });
        }
        const api = await fetchEmailMetricsFromApi();
        await pool.query(
            `REPLACE INTO EmailMetricsCache (CompanyID, ActiveThreats, HighSeverity, UsersTargeted, OpenIncidents, LastUpdated)
             VALUES (?, ?, ?, ?, ?, NOW())`,
            [context.companyId, api.activeThreats, api.highSeverity, api.usersTargeted, api.openIncidents]
        );
        return res.json({ success: true, source: 'api-fallback', metrics: api });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/db/email-security', authenticateToken, async (req, res) => {
    try {
        const context = await getAccessContextByUser(req.user);
        if (!context?.companyId) return res.status(403).json({ success: false, message: 'Access mapping not configured' });

        const [rows] = await pool.query(
            'SELECT Payload, LastUpdated FROM EmailSecurityPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1',
            [context.companyId]
        );

        if (rows.length > 0 && rows[0].Payload) {
            try {
                const payload = JSON.parse(rows[0].Payload);
                if (payload && payload.success) {
                    const summary = payload.summary || {};
                    const hasMailActivityShape = Array.isArray(payload.mailActivity?.users);
                    const hasSignals = (payload.alerts || []).length > 0 ||
                        (payload.incidents || []).length > 0 ||
                        (payload.mailActivity?.users || []).length > 0 ||
                        Number(summary.activeThreats || 0) +
                        Number(summary.highSeverityAlerts || 0) +
                        Number(summary.affectedUsersCount || 0) +
                        Number(summary.activeIncidents || 0) +
                        Number(summary.mailActivity?.totalMailActivity || 0) > 0;
                    if (hasSignals && hasMailActivityShape) {
                        return res.json({
                            ...payload,
                            source: 'db',
                            fetchedAt: rows[0].LastUpdated
                        });
                    }
                }
            } catch (_) {}
        }

        const api = await fetchEmailSecurityPayloadFromApi();
        await pool.query(
            `REPLACE INTO EmailSecurityPayloadCache (CompanyID, Payload, LastUpdated)
             VALUES (?, ?, NOW())`,
            [context.companyId, JSON.stringify(api)]
        );
        return res.json({ ...api, source: 'api-fallback' });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/db/application-metrics', authenticateToken, async (req, res) => {
    try {
        const context = await getAccessContextByUser(req.user);
        if (!context?.companyId) return res.status(403).json({ success: false, message: 'Access mapping not configured' });
        const [rows] = await pool.query('SELECT * FROM ApplicationMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [context.companyId]);
        if (rows.length > 0) return res.json({ success: true, source: 'db', metrics: rows[0] });
        const api = await fetchApplicationMetricsFromApi();
        await pool.query(
            `REPLACE INTO ApplicationMetricsCache (CompanyID, TotalApps, ExternalApps, HighRiskApps, HighAccessApps, LastUpdated)
             VALUES (?, ?, ?, ?, ?, NOW())`,
            [context.companyId, api.totalApps, api.externalApps, api.highRiskApps, api.highAccessApps]
        );
        return res.json({ success: true, source: 'api-fallback', metrics: api });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/db/applications', authenticateToken, async (req, res) => {
    try {
        const context = await getAccessContextByUser(req.user);
        if (!context?.companyId) return res.status(403).json({ success: false, message: 'Access mapping not configured' });

        const [rows] = await pool.query(
            'SELECT Payload, LastUpdated FROM ApplicationPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1',
            [context.companyId]
        );

        if (rows.length > 0 && rows[0].Payload) {
            try {
                const payload = JSON.parse(rows[0].Payload);
                if (payload && payload.success && Array.isArray(payload.applications)) {
                    return res.json({ ...payload, source: 'db', fetchedAt: rows[0].LastUpdated });
                }
            } catch (_) {}
        }

        const api = await fetchApplicationsPayloadFromApi();
        await pool.query(
            `REPLACE INTO ApplicationPayloadCache (CompanyID, Payload, LastUpdated)
             VALUES (?, ?, NOW())`,
            [context.companyId, JSON.stringify(api)]
        );
        return res.json({ ...api, source: 'api-fallback' });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

function isBackupRecoveryPayloadComplete(payload) {
    if (!payload || !payload.success || !payload.summary || !payload.storage) return false;
    if (!Array.isArray(payload.storage.sites)) return false;
    if (!Array.isArray(payload.storage.users)) return false;
    if (!Array.isArray(payload.storage.inactiveUsers)) return false;
    return true;
}

app.get('/api/db/backup-recovery', authenticateToken, async (req, res) => {
    try {
        const context = await getAccessContextByUser(req.user);
        if (!context?.companyId) return res.status(403).json({ success: false, message: 'Access mapping not configured' });

        const [rows] = await pool.query(
            'SELECT Payload, LastUpdated FROM BackupRecoveryPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1',
            [context.companyId]
        );

        if (rows.length > 0 && rows[0].Payload) {
            try {
                const payload = JSON.parse(rows[0].Payload);
                if (isBackupRecoveryPayloadComplete(payload)) {
                    return res.json({
                        ...payload,
                        source: 'db',
                        fetchedAt: rows[0].LastUpdated
                    });
                }
                console.warn('[Backup Recovery Cache] Cached payload is missing evidence arrays; refreshing from Graph.');
            } catch (_) {}
        }

        const api = await fetchBackupRecoveryPayloadFromApi();
        await pool.query(
            `REPLACE INTO BackupRecoveryPayloadCache (CompanyID, Payload, LastUpdated)
             VALUES (?, ?, NOW())`,
            [context.companyId, JSON.stringify(api)]
        );
        return res.json({ ...api, source: 'api-fallback' });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

/**
 * Route: GET /api/microsoft-users
 * Returns: List of users from Microsoft Graph (filtered by tenant/client)
 */
app.get('/api/microsoft-users', authenticateToken, async (req, res) => {
    try {
        const userEmail = req.user.email;
        console.log(`[Microsoft Graph] Fetching users for: ${userEmail}`);

        // Get the tenant for this user
        const tenant = getTenantByEmail(userEmail);
        if (!tenant) {
            console.warn(`[Microsoft Graph] User ${userEmail} does not belong to any configured tenant`);
            return res.status(403).json({ 
                error: 'User does not have access to Microsoft Graph data',
                message: 'Your email is not associated with any tenant'
            });
        }

        console.log(`[Microsoft Graph] User belongs to tenant: ${tenant.clientId}`);

        // Get Microsoft Graph token
        const token = await getMicrosoftGraphToken();

        // Fetch users from Microsoft Graph
        const users = await fetchMicrosoftUsers(token);

        // Process and enrich the data
        const processedUsers = users.map(user => ({
          id: user.id,
          displayName: user.displayName || 'Unknown User',
          mail: user.mail || user.userPrincipalName || 'N/A',
          jobTitle: user.jobTitle || 'No Title',
          mobilePhone: user.mobilePhone || 'N/A',
          userPrincipalName: user.userPrincipalName,
          isExternal: user.userPrincipalName && user.userPrincipalName.includes('#EXT#'),
          status: 'active',
          lastSync: new Date().toISOString()
        }));

        console.log(`[Microsoft Graph] Successfully retrieved ${processedUsers.length} users`);

        res.json({
          success: true,
          tenant: tenant.clientId,
          totalUsers: processedUsers.length,
          users: processedUsers,
          fetchedAt: new Date().toISOString()
        });

    } catch (error) {
        console.error('[Microsoft Graph] Error fetching users:', error.message);
        
        if (error.message.includes('Missing Microsoft Graph credentials')) {
            return res.status(500).json({ 
                error: 'Microsoft Graph not configured',
                message: 'Credentials missing from environment'
            });
        }

        res.status(500).json({ 
            error: 'Failed to fetch Microsoft Graph users',
            message: error.message
        });
    }
});

/**
 * Route: GET /api/microsoft-roles
 * Returns: List of role assignments and directory roles from Microsoft Graph
 */
app.get('/api/microsoft-roles', authenticateToken, async (req, res) => {
    try {
        const userEmail = req.user.email;
        console.log(`[Microsoft Graph] Fetching role assignments for: ${userEmail}`);

        const context = await getAccessContextByUser(req.user);
        if (!context?.companyId) {
            console.warn(`[Microsoft Graph] User ${userEmail} does not belong to any configured tenant`);
            return res.status(403).json({ 
                error: 'User does not have access to Microsoft Graph data',
                message: 'Your email is not associated with any tenant'
            });
        }

        console.log(`[Microsoft Graph] User belongs to tenant: ${context.accessType || context.clientId || 'standard'}`);

        let processedAssignments = [];
        let source = 'api';
        let fetchedAt = new Date().toISOString();
        try {
            processedAssignments = await fetchRoleAssignmentsFromApi(context.companyId);
        } catch (apiError) {
            console.warn('[Microsoft Graph] Live role fetch failed, trying DB cache:', apiError.message);
            const cached = await getCachedRoleAssignments(context.companyId);
            if (!cached) throw apiError;
            processedAssignments = cached.roleAssignments;
            source = 'db-cache';
            fetchedAt = cached.fetchedAt;
        }

        // Extract unique roles for summary
        const uniqueRoles = [...new Set(processedAssignments.map(a => a.roleName))];

        console.log(`[Microsoft Graph] Successfully retrieved ${processedAssignments.length} role assignments covering ${uniqueRoles.length} unique roles`);

        res.json({
            success: true,
            tenant: context.accessType || context.clientId || 'standard',
            source,
            totalAssignments: processedAssignments.length,
            totalRoles: uniqueRoles.length,
            roleAssignments: processedAssignments,
            uniqueRoles: uniqueRoles,
            fetchedAt
        });

    } catch (error) {
        console.error('[Microsoft Graph] Error fetching roles:', error.message);
        
        if (error.message.includes('Missing Microsoft Graph credentials')) {
            return res.status(500).json({ 
                error: 'Microsoft Graph not configured',
                message: 'Credentials missing from environment'
            });
        }

        res.status(500).json({ 
            error: 'Failed to fetch Microsoft Graph roles',
            message: error.message
        });
    }
});

/**
 * Route: GET /api/microsoft-applications
 * Returns: List of applications and service principals from Microsoft Graph
 */
app.get('/api/microsoft-applications', authenticateToken, async (req, res) => {
    try {
        const userEmail = req.user.email;
        const tenant = getTenantByEmail(userEmail);
        
        if (!tenant) {
            return res.status(403).json({ error: 'Access denied' });
        }

        const payload = await fetchApplicationsPayloadFromApi();
        const dashboardPayload = buildApplicationsDashboardPayload({ tenantKey: tenant.clientId || 'sunbird', payload });
        if (applicationsEvidenceService && tenant.companyId) {
            applicationsEvidenceService.persistProcessedEvidence({
                companyId: tenant.companyId,
                tenantKey: tenant.clientId || 'sunbird',
                payload: dashboardPayload,
                collectionTrigger: 'dashboard_request',
                sourceEndpoint: '/api/microsoft-applications'
            }).catch(error => console.warn('[Applications Evidence] Dashboard response could not be stored:', error.message));
        }
        res.json({ ...dashboardPayload, tenant: tenant.clientId, source: 'api' });

    } catch (error) {
        console.error('[Microsoft Graph] Error fetching applications:', error);
        res.status(500).json({ error: 'Failed to fetch Microsoft Graph applications' });
    }
});

/**
 * Route: GET /api/sunbird/identity-dashboard
 * SUNBIRD CLIENT ONLY - Complete  Identity Protection dashboard data aggregation
 * Returns: Merged users, roles, sign-ins, auth methods with calculated metrics
 */
app.get('/api/app-access/:spId', authenticateToken, async (req, res) => {
  try {
    const spId = req.params.spId;
    const userEmail = req.user.email;

    // Verify Sunbird tenant access only
    const tenant = getTenantByEmail(userEmail);
    if (!tenant || tenant.clientId !== 'sunbird') {
      return res.status(403).json({ 
        error: 'Access denied',
        message: 'App access details only available for authorized Sunbird users'
      });
    }

    console.log(`[App Access] Fetching access details for SP ${spId}`);

    // Get Microsoft Graph token
    const token = await getMicrosoftGraphToken();

    // Fetch app role assignments
    const assignments = await fetchAppRoleAssignments(token, spId);

    // Process assignments to count users and extract groups
    let userCount = 0;
    const groupNames = new Set();
    
    assignments.forEach(assignment => {
      if (assignment.principalType === 'User') {
        userCount++;
      } else if (assignment.principalType === 'Group' && assignment.principalDisplayName) {
        groupNames.add(assignment.principalDisplayName);
      }
    });

    const groups = Array.from(groupNames);

    const responseData = {
      success: true,
      spId: spId,
      users: userCount,
      groups: groups,
      hasDirect: userCount > 0 || groups.length > 0,
      totalAssignments: assignments.length,
      message: userCount === 0 && groups.length === 0 
        ? 'No direct user or group assignments detected for this app'
        : `App has ${userCount} direct users and ${groups.length} groups assigned`
    };

    console.log(`[App Access] SP ${spId}: ${userCount} users, ${groups.length} groups`);
    res.json(responseData);

  } catch (error) {
    console.error(`[App Access] Error for SP ${req.params.spId}:`, error.message);
    
    if (error.message.includes('Missing Microsoft Graph credentials')) {
      return res.status(503).json({ 
        error: 'Microsoft Graph unavailable',
        message: 'Service temporarily unavailable'
      });
    }

    res.status(500).json({ 
      error: 'Failed to fetch app access details',
      message: error.message
    });
  }
});

const SUNBIRD_DASHBOARD_CACHE_TTL_MS = 10 * 60 * 1000;
const SUNBIRD_DASHBOARD_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const SUNBIRD_PAYLOAD_CACHE_TABLES = new Set([
    'SunbirdComplianceControlsCache',
    'SunbirdOperationsPayloadCache',
    'SunbirdGovernancePayloadCache'
]);

function getSunbirdCacheAgeMs(lastUpdated) {
    if (!lastUpdated) return Number.POSITIVE_INFINITY;
    const updatedAt = new Date(lastUpdated).getTime();
    if (!Number.isFinite(updatedAt)) return Number.POSITIVE_INFINITY;
    return Date.now() - updatedAt;
}

async function getSunbirdPayloadCache(tableName, companyId, { allowStale = false } = {}) {
    if (!pool || !companyId || !SUNBIRD_PAYLOAD_CACHE_TABLES.has(tableName)) return null;

    try {
        const [rows] = await pool.query(
            `SELECT Payload, LastUpdated FROM ${tableName}
             WHERE CompanyID = ? AND OCTET_LENGTH(Payload) <= ?
             ORDER BY LastUpdated DESC LIMIT 1`,
            [companyId, SUNBIRD_DASHBOARD_MAX_RESPONSE_BYTES]
        );

        if (!rows.length || !rows[0].Payload) return null;

        const payload = JSON.parse(rows[0].Payload);
        const ageMs = getSunbirdCacheAgeMs(rows[0].LastUpdated);
        const isFresh = ageMs <= SUNBIRD_DASHBOARD_CACHE_TTL_MS;
        if (!allowStale && !isFresh) return null;

        return {
            payload,
            isFresh,
            ageMs,
            lastUpdated: rows[0].LastUpdated
        };
    } catch (error) {
        console.warn(`[Sunbird Cache] Unable to read ${tableName}:`, error.message);
        return null;
    }
}

async function upsertSunbirdPayloadCache(tableName, companyId, payload) {
    if (!pool || !companyId || !payload || !SUNBIRD_PAYLOAD_CACHE_TABLES.has(tableName)) return;

    try {
        await pool.query(
            `REPLACE INTO ${tableName} (CompanyID, Payload, LastUpdated) VALUES (?, ?, NOW())`,
            [companyId, JSON.stringify(payload)]
        );
    } catch (error) {
        console.warn(`[Sunbird Cache] Unable to write ${tableName}:`, error.message);
    }
}

const SUNBIRD_DASHBOARD_MAX_ROWS = 80;
const SUNBIRD_DASHBOARD_MAX_ARRAY_ITEMS = 20;
const SUNBIRD_DASHBOARD_MAX_OBJECT_KEYS = 30;
const SUNBIRD_DASHBOARD_MAX_STRING_LENGTH = 1200;

function compactSunbirdDashboardValue(value, depth = 0, seen = new WeakSet()) {
    if (value == null || typeof value === 'number' || typeof value === 'boolean') return value;
    if (typeof value === 'string') return value.slice(0, SUNBIRD_DASHBOARD_MAX_STRING_LENGTH);
    if (depth >= 4) return '[Detail omitted]';
    if (typeof value !== 'object') return String(value).slice(0, SUNBIRD_DASHBOARD_MAX_STRING_LENGTH);
    if (seen.has(value)) return '[Circular detail omitted]';
    seen.add(value);
    if (Array.isArray(value)) {
        return value.slice(0, SUNBIRD_DASHBOARD_MAX_ARRAY_ITEMS)
            .map(item => compactSunbirdDashboardValue(item, depth + 1, seen));
    }
    return Object.fromEntries(
        Object.entries(value)
            .slice(0, SUNBIRD_DASHBOARD_MAX_OBJECT_KEYS)
            .map(([key, item]) => [key, compactSunbirdDashboardValue(item, depth + 1, seen)])
    );
}

function compactSunbirdGovernancePayload(payload = {}, overrides = {}) {
    const rows = Array.isArray(payload.rows) ? payload.rows : [];
    return {
        success: payload.success !== false,
        source: overrides.source || payload.source || 'api',
        fetchedAt: overrides.fetchedAt || payload.fetchedAt || new Date().toISOString(),
        ...(overrides.warning ? { warning: overrides.warning } : {}),
        warnings: compactSunbirdDashboardValue(payload.warnings || []),
        summary: compactSunbirdDashboardValue(payload.summary || {}),
        rows: rows.slice(0, SUNBIRD_DASHBOARD_MAX_ROWS).map(row => ({
            area: row.area || '',
            activity: row.activity || '',
            source: row.source || '',
            dataSource: row.dataSource || '',
            frequency: row.frequency || '',
            lastReviewed: row.lastReviewed || null,
            status: row.status || '',
            connected: Boolean(row.connected),
            evidence: String(row.evidence || '').slice(0, SUNBIRD_DASHBOARD_MAX_STRING_LENGTH),
            evidenceData: compactSunbirdDashboardValue(row.evidenceData || {})
        }))
    };
}

function compactSunbirdCompliancePayload(payload = {}, overrides = {}) {
    const controls = Array.isArray(payload.controls) ? payload.controls : [];
    return {
        success: payload.success !== false,
        source: overrides.source || payload.source || 'api',
        fetchedAt: overrides.fetchedAt || payload.fetchedAt || new Date().toISOString(),
        ...(overrides.warning ? { warning: overrides.warning } : {}),
        warnings: compactSunbirdDashboardValue(payload.warnings || []),
        summary: compactSunbirdDashboardValue(payload.summary || {}),
        controls: controls.slice(0, SUNBIRD_DASHBOARD_MAX_ROWS).map(control => ({
            name: control.name || '',
            area: control.area || '',
            insight: String(control.insight || '').slice(0, SUNBIRD_DASHBOARD_MAX_STRING_LENGTH),
            status: control.status || '',
            evidenceData: compactSunbirdDashboardValue(control.evidenceData || {})
        }))
    };
}

// ============================================================================
async function fetchGovernancePayloadFromApi() {
        const token = await getMicrosoftGraphToken();
        const fetchedAt = new Date().toISOString();
        const lastReviewed = fetchedAt.split('T')[0];
        const rows = [];

        const addRow = ({ area, activity, dataSource, frequency, status, evidence, evidenceData = {}, connected = true }) => {
            rows.push({
                area,
                activity,
                source: dataSource,
                dataSource,
                frequency,
                lastReviewed: connected ? lastReviewed : null,
                status,
                connected,
                evidence,
                evidenceData
            });
        };

        const addManualRow = (area, activity, frequency, evidence) => {
            addRow({
                area,
                activity,
                dataSource: 'Manual attestation',
                frequency,
                status: 'Manual Review Required',
                connected: false,
                evidence,
                evidenceData: {
                    data_source: 'Manual governance process',
                    graph_api_available: 'No',
                    reason: 'This control depends on policy approval, business sign-off, training records, or test evidence outside Microsoft Graph.'
                }
            });
        };

        let users = [];
        let roleAssignments = [];
        let signIns = [];
        let devices = [];
        let apps = [];
        let policies = [];
        let alerts = [];

        try { users = await fetchMicrosoftUsers(token); } catch (e) { console.warn('[Governance] Users unavailable:', e.message); }
        try { roleAssignments = await fetchMicrosoftRoleAssignments(token); } catch (e) { console.warn('[Governance] Roles unavailable:', e.message); }
        try { signIns = await fetchMicrosoftSignIns(token, 30); } catch (e) { console.warn('[Governance] Sign-ins unavailable:', e.message); }
        try { devices = await fetchMicrosoftDevices(token); } catch (e) { console.warn('[Governance] Devices unavailable:', e.message); }
        try { apps = await fetchMicrosoftServicePrincipals(token); } catch (e) { console.warn('[Governance] Applications unavailable:', e.message); }
        try { policies = await fetchCompliancePolicies(token); } catch (e) { console.warn('[Governance] Compliance policies unavailable:', e.message); }
        try { alerts = await fetchSecurityAlerts(token); } catch (e) { console.warn('[Governance] Security alerts unavailable:', e.message); }

        const adminIds = new Set();
        roleAssignments.forEach(assignment => {
            const roleName = assignment.roleDefinition?.displayName || assignment.roleName || '';
            if (/admin|global/i.test(roleName)) adminIds.add(assignment.principalId);
        });

        const userBrief = user => ({
            name: user.displayName || user.userPrincipalName || user.mail || 'Unknown user',
            email: user.mail || user.userPrincipalName || 'N/A',
            id: user.id || 'N/A'
        });
        const deviceBrief = device => ({
            name: device.deviceName || device.managedDeviceName || device.id || 'Unknown device',
            user: device.userPrincipalName || device.emailAddress || 'N/A',
            compliance: device.complianceState || 'unknown',
            encrypted: device.isEncrypted ? 'Yes' : 'No',
            lastSync: device.lastSyncDateTime || device.lastContactedDateTime || 'N/A'
        });
        const appBrief = app => ({
            name: app.displayName || 'Unknown app',
            publisher: app.publisherName || 'Unknown publisher',
            type: app.servicePrincipalType || 'Unknown',
            permissions: ((app.oauth2PermissionScopes || []).length + (app.appRoles || []).length)
        });
        const signInBrief = signIn => ({
            user: signIn.userPrincipalName || 'Unknown user',
            app: signIn.appDisplayName || 'Unknown app',
            client: signIn.clientAppUsed || 'Unknown client',
            time: signIn.createdDateTime || 'N/A',
            status: signIn.status?.errorCode && signIn.status.errorCode !== 0 ? 'Failed' : 'Success'
        });
        const alertBrief = alert => ({
            title: alert.title || alert.displayName || alert.alertWebUrl || 'Security alert',
            severity: alert.severity || 'unknown',
            status: alert.status || 'unknown'
        });

        const workforceUsers = users.filter(user => isWorkforceMicrosoftUser(user));
        let mfaRegistered = 0;
        const usersWithoutMfa = [];
        if (workforceUsers.length) {
            await mapWithConcurrency(workforceUsers, 8, async (user) => {
                const authMethods = await fetchUserAuthMethods(token, user.id);
                if (hasRealMfaMethod(authMethods)) {
                    mfaRegistered++;
                } else {
                    usersWithoutMfa.push(userBrief(user));
                }
            });
        }

        const externalUserRows = users.filter(user => isGuestMicrosoftUser(user)).map(userBrief);
        const mfaCoverage = workforceUsers.length ? Math.round((mfaRegistered / workforceUsers.length) * 100) : 0;
        const adminUserRows = workforceUsers.filter(user => adminIds.has(user.id)).map(userBrief);
        const nonCompliantDeviceRows = devices.filter(device => String(device.complianceState || '').toLowerCase() !== 'compliant').map(deviceBrief);
        const staleDeviceRows = devices.filter(device => {
            const lastSync = new Date(device.lastSyncDateTime || device.lastContactedDateTime || 0).getTime();
            if (!Number.isFinite(lastSync) || lastSync <= 0) return false;
            return (Date.now() - lastSync) / (1000 * 60 * 60 * 24) > 30;
        }).map(deviceBrief);
        const externalAppRows = apps.filter(app => !(app.publisherName || '').toLowerCase().includes('microsoft')).map(appBrief);
        const highPermissionAppRows = apps.filter(app => ((app.oauth2PermissionScopes || []).length + (app.appRoles || []).length) > 10).map(appBrief);
        const failedSignInRows = signIns.filter(signIn => signIn.status?.errorCode && signIn.status.errorCode !== 0).map(signInBrief);
        const legacySignInRows = signIns.filter(signIn => signIn.clientAppUsed && signIn.clientAppUsed !== 'Browser' && signIn.clientAppUsed !== 'Mobile Apps and Desktop clients').map(signInBrief);
        const highAlertRows = alerts.filter(alert => /high|critical/i.test(alert.severity || '')).map(alertBrief);

        addRow({
            area: 'Access review',
            activity: 'Review users',
            dataSource: 'Microsoft Graph users',
            frequency: 'Quarterly',
            status: users.length ? 'Connected' : 'No Graph Evidence',
            evidence: `${users.length} user accounts are available for review, including ${externalUserRows.length} guest/external accounts.`,
            evidenceData: {
                total_users: users.length,
                external_users: externalUserRows.length,
                users: users.slice(0, 20).map(userBrief),
                external_user_sample: externalUserRows.slice(0, 20)
            }
        });

        addRow({
            area: 'Admin review',
            activity: 'Review roles',
            dataSource: 'Microsoft Graph directory roles',
            frequency: 'Quarterly',
            status: roleAssignments.length ? 'Connected' : 'No Graph Evidence',
            evidence: `${adminIds.size} privileged accounts were detected from role assignments. Review these accounts against approved admin access.`,
            evidenceData: {
                role_assignments: roleAssignments.length,
                privileged_principals: adminIds.size,
                privileged_users: adminUserRows.slice(0, 20)
            }
        });

        addRow({
            area: 'Security review',
            activity: 'Full stack review',
            dataSource: 'Microsoft Graph security alerts',
            frequency: 'Annual',
            status: highAlertRows.length > 0 ? 'Attention Required' : 'Connected',
            evidence: `${alerts.length} security alert records were checked, with ${highAlertRows.length} high or critical alerts.`,
            evidenceData: {
                total_alerts: alerts.length,
                high_or_critical_alerts: highAlertRows.length,
                alerts: highAlertRows.slice(0, 20)
            }
        });

        addRow({
            area: 'Threat review',
            activity: 'Threat landscape',
            dataSource: 'Microsoft Graph sign-in and security telemetry',
            frequency: 'Annual',
            status: failedSignInRows.length > 0 || highAlertRows.length > 0 ? 'Attention Required' : 'Connected',
            evidence: `${signIns.length} sign-in events were reviewed from the last 30 days. ${failedSignInRows.length} failed sign-ins and ${highAlertRows.length} high/critical alerts were found.`,
            evidenceData: {
                sign_in_events_30_days: signIns.length,
                failed_sign_ins_30_days: failedSignInRows.length,
                high_or_critical_alerts: highAlertRows.length,
                failed_sign_ins: failedSignInRows.slice(0, 20),
                alerts: highAlertRows.slice(0, 20)
            }
        });

        addManualRow(
            'AI review',
            'AI policy',
            'Ongoing',
            'Microsoft Graph does not confirm whether staff have accepted internal AI usage rules. Evidence should come from approved AI policy documents, acceptance records, and exception approvals.'
        );

        addRow({
            area: 'Software review',
            activity: 'App review',
            dataSource: 'Microsoft Graph enterprise applications',
            frequency: 'Annual',
            status: externalAppRows.length > 10 || highPermissionAppRows.length > 0 ? 'Attention Required' : 'Connected',
            evidence: `${apps.length} enterprise applications were found. ${externalAppRows.length} are non-Microsoft publishers and ${highPermissionAppRows.length} have broad permission surfaces.`,
            evidenceData: {
                total_enterprise_apps: apps.length,
                external_publishers: externalAppRows.length,
                high_permission_apps: highPermissionAppRows.length,
                external_apps: externalAppRows.slice(0, 20),
                high_permission_app_sample: highPermissionAppRows.slice(0, 20)
            }
        });

        addRow({
            area: 'Incident review',
            activity: 'Post-incident',
            dataSource: 'Microsoft Graph security alerts',
            frequency: 'Triggered',
            status: alerts.length ? 'Connected' : 'No Open Evidence',
            evidence: alerts.length
                ? `${alerts.length} alert records are available to support incident review and post-incident follow-up.`
                : 'No security alerts were returned by Microsoft Graph for this review window.',
            evidenceData: {
                alert_records: alerts.length,
                alerts: alerts.slice(0, 20).map(alertBrief)
            }
        });

        addRow({
            area: 'MFA audit',
            activity: 'Identity check',
            dataSource: 'Microsoft Graph authentication methods',
            frequency: 'Quarterly',
            status: mfaCoverage >= 90 ? 'Connected' : 'Attention Required',
            evidence: `${mfaRegistered} of ${workforceUsers.length} workforce users have a registered MFA method. Guest users remain visible but are excluded from workforce MFA scope. Current MFA coverage is ${mfaCoverage}%.`,
            evidenceData: {
                scope: 'workforce_member_only',
                total_workforce_users: workforceUsers.length,
                total_guest_users: externalUserRows.length,
                mfa_registered: mfaRegistered,
                mfa_missing: Math.max(0, workforceUsers.length - mfaRegistered),
                mfa_coverage: `${mfaCoverage}%`,
                users_without_mfa: usersWithoutMfa.slice(0, 50),
                guest_users_sample: externalUserRows.slice(0, 20)
            }
        });

        addRow({
            area: 'Device audit',
            activity: 'Device posture',
            dataSource: 'Microsoft Graph Intune devices',
            frequency: 'Monthly',
            status: nonCompliantDeviceRows.length > 0 || staleDeviceRows.length > 0 ? 'Attention Required' : 'Connected',
            evidence: `${devices.length} managed devices were found. ${nonCompliantDeviceRows.length} are non-compliant and ${staleDeviceRows.length} have not synced in more than 30 days.`,
            evidenceData: {
                managed_devices: devices.length,
                non_compliant_devices: nonCompliantDeviceRows.length,
                stale_devices_30_days: staleDeviceRows.length,
                non_compliant_device_list: nonCompliantDeviceRows.slice(0, 50),
                stale_device_list: staleDeviceRows.slice(0, 50)
            }
        });

        addRow({
            area: 'Log review',
            activity: 'Sign-in logs',
            dataSource: 'Microsoft Graph sign-in logs',
            frequency: 'Monthly',
            status: signIns.length ? 'Connected' : 'No Graph Evidence',
            evidence: `${signIns.length} sign-in records were available for the last 30 days, including ${failedSignInRows.length} failed sign-in attempts.`,
            evidenceData: {
                sign_in_events_30_days: signIns.length,
                failed_sign_ins_30_days: failedSignInRows.length,
                failed_sign_ins: failedSignInRows.slice(0, 50),
                legacy_sign_ins: legacySignInRows.slice(0, 50)
            }
        });

        try {
            const backup = await fetchBackupRecoveryPayloadFromApi();
            const summary = backup.summary || {};
            addRow({
                area: 'Backup review',
                activity: 'Backup check',
                dataSource: 'Microsoft Graph usage reports',
                frequency: 'Monthly',
                status: backup.success ? 'Connected' : 'No Graph Evidence',
                evidence: `Microsoft 365 usage evidence is available for backup scope review: ${summary.totalStorageGB || 0} GB total storage and ${summary.activeUsersCount || 0} active users represented in report data.`,
                evidenceData: {
                    total_storage_gb: summary.totalStorageGB || 0,
                    active_users: summary.activeUsersCount || 0,
                    report_sources: 'OneDrive, SharePoint, Exchange usage reports'
                }
            });
        } catch (e) {
            addRow({
                area: 'Backup review',
                activity: 'Backup check',
                dataSource: 'Microsoft Graph usage reports',
                frequency: 'Monthly',
                status: 'No Graph Evidence',
                evidence: 'Microsoft 365 usage reports were not available during this refresh. Backup tool success/failure status must still come from the backup platform.',
                evidenceData: {
                    graph_available: 'No',
                    reason: e.message
                }
            });
        }

        addManualRow(
            'Restore testing',
            'Recovery test',
            'Quarterly',
            'Restore testing cannot be proven by Microsoft Graph alone. Evidence should be a restore test record showing date, scope, result, owner, and any issues found.'
        );

        addRow({
            area: 'Policy review',
            activity: 'CA and compliance policies',
            dataSource: 'Microsoft Graph compliance policies',
            frequency: 'Quarterly',
            status: policies.length ? 'Connected' : 'No Graph Evidence',
            evidence: `${policies.length} Intune compliance policies returned by Microsoft Graph. Conditional Access policy detail may require additional Graph permissions before it can be included.`,
            evidenceData: {
                compliance_policies: policies.length,
                graph_endpoint: '/deviceManagement/deviceCompliancePolicies',
                note: 'Conditional Access policies require policy/read permissions not currently used by this endpoint.'
            }
        });

        addRow({
            area: 'Data review',
            activity: 'SharePoint usage',
            dataSource: 'Microsoft Graph usage reports',
            frequency: 'Quarterly',
            status: 'Connected',
            evidence: 'SharePoint and OneDrive usage reports can support data footprint review. They do not replace a full permissions or sensitivity-label audit.',
            evidenceData: {
                graph_reports: 'SharePoint site usage and OneDrive account usage',
                limitation: 'Permissions exposure and sensitivity labels require additional dedicated report logic.'
            }
        });

        addManualRow(
            'Awareness review',
            'Training',
            'Annual',
            'Security awareness completion is not available from Microsoft Graph in this dashboard. Evidence should come from the training platform or signed attendance/completion records.'
        );

        return {
            success: true,
            rows,
            source: 'api',
            fetchedAt
        };
}

// SUNBIRD ONLY: GOVERNANCE EVIDENCE REGISTER
// ============================================================================
app.get('/api/sunbird/governance', authenticateToken, async (req, res) => {
    let companyId = null;
    const operation = beginSunbirdOperation(req, 'governance');
    try {
        const userEmail = req.user.email;
        const tenant = getTenantByEmail(userEmail);

        if (!tenant || tenant.clientId !== 'sunbird') {
            operation.finish(403, { reason: 'access_denied' });
            return res.status(403).json({ error: 'Access denied. Sunbird only.' });
        }

        companyId = tenant.companyId || req.user.companyId || null;
        operation.step('tenant_resolved', { companyId });
        const cached = await getSunbirdPayloadCache('SunbirdGovernancePayloadCache', companyId);
        if (cached?.payload?.success && Array.isArray(cached.payload.rows)) {
            operation.step('cache_hit', { cacheAgeMs: cached.ageMs, rows: cached.payload.rows.length });
            cached.payload = compactSunbirdGovernancePayload(cached.payload, {
                source: 'db',
                fetchedAt: cached.lastUpdated
            });
            if (governanceEvidenceService && companyId) {
                persistGovernanceDashboardEvidence(companyId, cached.payload, 'dashboard_request', '/api/sunbird/governance')
                    .catch(error => console.warn('[Governance Evidence] Cached dashboard payload could not be stored:', error.message));
            }
            sendSunbirdJson(res, cached.payload, operation);
            operation.finish(200, { source: 'cache', rows: cached.payload.rows.length });
            return;
        }

        operation.step('live_collection_start');
        const payload = compactSunbirdGovernancePayload(await fetchGovernancePayloadFromApi());
        operation.step('live_collection_complete', { rows: payload.rows.length });
        await upsertSunbirdPayloadCache('SunbirdGovernancePayloadCache', companyId, payload);
        operation.step('cache_write_complete');
        if (governanceEvidenceService && companyId) {
            persistGovernanceDashboardEvidence(companyId, payload, 'dashboard_request', '/api/sunbird/governance')
                .catch(error => console.warn('[Governance Evidence] Dashboard persist failed:', error.message));
        }
        sendSunbirdJson(res, payload, operation);
        operation.finish(200, { source: 'live', rows: payload.rows.length });
    } catch (error) {
        console.error('[Governance API] Critical Error:', error);
        const stale = await getSunbirdPayloadCache('SunbirdGovernancePayloadCache', companyId, { allowStale: true });
        if (stale?.payload?.success && Array.isArray(stale.payload.rows)) {
            const payload = compactSunbirdGovernancePayload(stale.payload, {
                source: 'db-stale',
                fetchedAt: stale.lastUpdated,
                warning: 'Serving stale cached governance data because live refresh failed.'
            });
            operation.step('stale_cache_served', { rows: payload.rows.length, error: error.message });
            sendSunbirdJson(res, payload, operation);
            operation.finish(200, { source: 'stale', rows: payload.rows.length });
            return;
        }
        operation.finish(500, { error: error.message });
        res.status(500).json({ error: 'Failed to aggregate governance data' });
    }
});

// ============================================================================
async function fetchComplianceControlsFromApi() {
        const token = await getMicrosoftGraphToken();
        const controls = [];

        // Helper function for Graph API calls
        const fetchGraph = async (endpoint) => {
            const version = endpoint.startsWith('/beta') ? '' : '/v1.0';
            try {
                return await fetchMicrosoftGraphJson(
                    `https://graph.microsoft.com${version}${endpoint}`,
                    token,
                    `Microsoft Graph compliance ${endpoint}`,
                    { shared: false }
                );
            } catch (error) {
                console.warn('[Compliance Graph] Endpoint unavailable:', endpoint, error.message);
                return { value: [] };
            }
        };
        const userBrief = user => ({
            name: user.displayName || user.userPrincipalName || user.mail || 'Unknown user',
            email: user.mail || user.userPrincipalName || 'N/A',
            id: user.id || 'N/A'
        });
        const deviceBrief = device => ({
            name: device.deviceName || device.managedDeviceName || device.id || 'Unknown device',
            user: device.userPrincipalName || device.emailAddress || 'N/A',
            compliance: device.complianceState || 'unknown',
            encrypted: device.isEncrypted ? 'Yes' : 'No',
            management: device.managementAgent || 'unknown'
        });
        const appBrief = app => ({
            name: app.displayName || 'Unknown app',
            publisher: app.publisherName || 'Unknown publisher',
            type: app.servicePrincipalType || 'Unknown',
            permissions: ((app.oauth2PermissionScopes || []).length + (app.appRoles || []).length)
        });
        const signInBrief = signIn => ({
            user: signIn.userPrincipalName || 'Unknown user',
            app: signIn.appDisplayName || 'Unknown app',
            client: signIn.clientAppUsed || 'Unknown client',
            time: signIn.createdDateTime || 'N/A'
        });

        // Helper for Manual/Hybrid controls
        const addManualControl = (name, area, insight, status = "Pending Review", additionalEvidence = {}) => {
            controls.push({
                name, area, insight,
                evidenceData: {
                    status,
                    data_source: "Manual Attestation / Configuration",
                    last_verified: "Requires manual audit",
                    ...additionalEvidence
                }
            });
        };

        // =========================================================
        // 🟦 IDENTITY CONTROLS
        // =========================================================
        
        // 1. MFA ON ALL ACCOUNTS (API)
        try {
            const users = await fetchMicrosoftUsers(token);
            const workforceUsers = users.filter(user => isWorkforceMicrosoftUser(user));
            let mfaRegistered = 0;
            const totalUsers = workforceUsers.length;
            const usersWithoutMfa = [];

            await mapWithConcurrency(workforceUsers, 8, async (user) => {
                const authMethods = await fetchUserAuthMethods(token, user.id);
                if (hasRealMfaMethod(authMethods)) {
                    mfaRegistered++;
                } else {
                    usersWithoutMfa.push(userBrief(user));
                }
            });

            const coverage = totalUsers > 0 ? Math.round((mfaRegistered / totalUsers) * 100) : 0;
            let insight = coverage === 100 ? "🟢 Workforce MFA fully enforced" : 
                         (coverage >= 80 ? "🟡 Workforce MFA partially enforced" : "🔴 Workforce users exposed to credential theft");

            controls.push({
                name: "MFA on all accounts", area: "Identity", insight: `${insight} (scope: workforce Member accounts only; Guests excluded)`,
                evidenceData: { scope: 'workforce_member_only', total_users: totalUsers, guest_users: users.filter(user => isGuestMicrosoftUser(user)).length, mfa_registered: mfaRegistered, mfa_missing: totalUsers - mfaRegistered, coverage: `${coverage}%`, users_without_mfa: usersWithoutMfa.slice(0, 50) }
            });
        } catch (e) { console.error('MFA Control Error', e); }

        // 2. ADMIN COUNT (API)
        try {
            const roleAssignments = await fetchMicrosoftRoleAssignments(token);
            const users = await fetchMicrosoftUsers(token).catch(() => []);
            const userMap = new Map(users.map(user => [user.id, userBrief(user)]));
            const adminSet = new Set();
            roleAssignments.forEach(assignment => {
                const roleName = assignment.roleDefinition?.displayName || '';
                if (roleName.toLowerCase().includes('admin') || roleName.toLowerCase().includes('global')) {
                    adminSet.add(assignment.principalId);
                }
            });
            const adminCount = adminSet.size;
            controls.push({
                name: "Admin accounts limited", area: "Identity",
                insight: adminCount > 5 ? "🔴 Too many privileged users" : "🟢 Admin count within limits",
                evidenceData: { privileged_users: adminCount, recommended_limit: "5", admin_accounts: Array.from(adminSet).map(id => userMap.get(id) || { name: id, email: 'Directory principal', id }).slice(0, 50) }
            });
        } catch (e) { console.error('Admin Count Error', e); }

        // 3. LEGACY AUTHENTICATION (API)
        try {
            const signIns = await fetchMicrosoftSignIns(token);
            const legacySignIns = signIns.filter(s => s.clientAppUsed && s.clientAppUsed !== 'Browser' && s.clientAppUsed !== 'Mobile Apps and Desktop clients');
            controls.push({
                name: "Legacy authentication blocked", area: "Identity",
                insight: legacySignIns.length > 0 ? "🔴 Legacy auth risk" : "🟢 Legacy auth blocked",
                evidenceData: { events_analyzed: signIns.length, legacy_auth_events: legacySignIns.length, legacy_sign_ins: legacySignIns.slice(0, 50).map(signInBrief) }
            });
        } catch (e) { console.error('Legacy Auth Error', e); }

        // 4. IDENTITY MANUAL/HYBRID CONTROLS
        addManualControl("Phishing-resistant MFA (admins)", "Identity", "🔴 Admins vulnerable to phishing");
        addManualControl("Admin accounts separated", "Identity", "🟡 Privilege misuse risk");
        addManualControl("Admin MFA strongest", "Identity", "🔴 Admin compromise risk");
        addManualControl("Least privilege enforced", "Identity", "🟡 Over-permissioned users");
        addManualControl("Access revoked immediately", "Identity", "🔴 Access persists after exit");
        addManualControl("Conditional Access enforced", "Identity", "🔴 No identity protection layer");

        // =========================================================
        // 🟩 DEVICE CONTROLS
        // =========================================================
        
        // 5. DEVICE COMPLIANCE, ENCRYPTION & WORK PROFILE (API)
        try {
            const devices = await fetchMicrosoftDevices(token);
            const totalDevices = devices.length;
            const nonCompliantDevices = devices.filter(d => d.complianceState !== 'compliant');
            const unencryptedDevices = devices.filter(d => !d.isEncrypted);
            const unmanagedDevices = devices.filter(d => !d.managementAgent || d.managementAgent === 'unknown');
            const compliant = totalDevices - nonCompliantDevices.length;
            const encrypted = totalDevices - unencryptedDevices.length;
            const managed = totalDevices - unmanagedDevices.length;

            const compCoverage = totalDevices > 0 ? Math.round((compliant / totalDevices) * 100) : 0;
            const encCoverage = totalDevices > 0 ? Math.round((encrypted / totalDevices) * 100) : 0;
            const manCoverage = totalDevices > 0 ? Math.round((managed / totalDevices) * 100) : 0;

            controls.push({
                name: "Device compliance", area: "Devices",
                insight: compCoverage < 95 ? "🔴 Non-compliant devices" : "🟢 Devices compliant",
                evidenceData: { total_devices: totalDevices, compliant_devices: compliant, non_compliant: nonCompliantDevices.length, compliance_rate: `${compCoverage}%`, non_compliant_devices: nonCompliantDevices.slice(0, 50).map(deviceBrief) }
            });

            controls.push({
                name: "Device encryption", area: "Devices",
                insight: encCoverage < 100 ? "🔴 Data loss risk" : "🟢 All devices encrypted",
                evidenceData: { total_devices: totalDevices, encrypted_devices: encrypted, unencrypted_devices: unencryptedDevices.length, encryption_rate: `${encCoverage}%`, unencrypted_device_list: unencryptedDevices.slice(0, 50).map(deviceBrief) }
            });

            controls.push({
                name: "Work profile on devices", area: "Devices",
                insight: manCoverage < 100 ? "🔴 Uncontrolled devices" : "🟢 Devices managed",
                evidenceData: { total_devices: totalDevices, managed_devices: managed, unmanaged_devices: unmanagedDevices.length, unmanaged_device_list: unmanagedDevices.slice(0, 50).map(deviceBrief) }
            });
        } catch (e) { console.error('Device Controls Error', e); }

        // 6. DEVICE MANUAL/HYBRID CONTROLS
        addManualControl("Endpoint protection", "Devices", "🔴 Unprotected endpoints", "Pending Configuration");
        addManualControl("Work/personal separation", "Devices", "🔴 Data leakage risk");
        addManualControl("Remote wipe (work only)", "Devices", "🔴 Data exposure risk");

        // =========================================================
        // 🟨 APPLICATION CONTROLS
        // =========================================================
        
        // 7. APPROVED APPLICATIONS ONLY (API)
        try {
            const apps = await fetchMicrosoftServicePrincipals(token);
            const externalApps = apps.filter(app => !app.publisherName || !app.publisherName.toLowerCase().includes('microsoft'));
            controls.push({
                name: "Approved tools only", area: "Applications",
                insight: externalApps.length > 10 ? "🔴 Shadow IT risk" : "🟢 App ecosystem secured",
                evidenceData: { total_enterprise_apps: apps.length, external_publishers: externalApps.length, external_applications: externalApps.slice(0, 50).map(appBrief) }
            });
        } catch (e) { console.error('Apps Control Error', e); }

        // 8. APPLICATION MANUAL CONTROLS
        addManualControl("Software register maintained", "Applications", "🔴 No control over tools");
        addManualControl("Third-party risk assessed", "Applications", "🟡 Supply chain risk");

        // =========================================================
        // 🟥 EMAIL & CREDENTIAL CONTROLS (Manual)
        // =========================================================
        addManualControl("Secure email protection", "Email", "🔴 Email threat exposure");
        addManualControl("Anti-phishing controls", "Email", "🔴 Phishing risk");
        addManualControl("Mailbox auditing", "Email", "🟡 No audit visibility");
        addManualControl("External forwarding restricted", "Email", "🔴 Data exfiltration risk");
        
        addManualControl("Password manager enforced", "Credentials", "🔴 Credential sprawl risk", "Pending Integration (Phase 2)");
        addManualControl("Secure credential sharing", "Credentials", "🔴 Credential leakage risk");

        // =========================================================
        // 🟪 NETWORK, AI & GOVERNANCE (Manual)
        // =========================================================
        addManualControl("Encrypted work traffic", "Network", "🔴 Hostile network exposure");
        addManualControl("Zero Trust network", "Network", "🔴 No network protection");
        addManualControl("DNS filtering", "Network", "🔴 Malicious domain risk");

        addManualControl("AI tools restricted", "AI", "🔴 AI data leakage risk");
        addManualControl("Approved AI tools list", "AI", "🟡 Uncontrolled AI usage");
        addManualControl("AI data policy", "AI", "🔴 Sensitive data exposure");

        addManualControl("Microsoft 365 primary platform", "Governance", "🟡 Security boundary broken");
        addManualControl("Verification codeword", "Governance", "🔴 Impersonation risk");
        
        addManualControl("Incident reporting awareness", "People", "🟡 Delayed response risk");
        addManualControl("Suspicious activity reporting", "People", "🔴 Threats not escalated");

        // =========================================================
        // ⬜ BACKUP & DATA CONTROLS (Manual / API)
        // =========================================================
        addManualControl("Backup configured", "Backup", "🔴 No recovery capability");
        addManualControl("Backup coverage", "Backup", "🟡 Partial protection");
        addManualControl("Backup tested", "Backup", "🔴 Recovery unproven");

        addManualControl("Data visibility", "Data", "🟡 Requires data governance review", "Partial Graph Coverage", {
            data_source: "Microsoft 365 usage reports / manual data governance review",
            graph_api_available: "Partial",
            limitation: "Usage reports can show activity and storage footprint, but this control still needs permissions, sensitivity, and retention review evidence."
        });

        return {
            success: true,
            controls,
            source: 'api',
            fetchedAt: new Date().toISOString()
        };
}

// SUNBIRD ONLY: STRICT COMPLIANCE VALIDATION ENGINE (FULL MATRIX)
// ============================================================================
app.get('/api/sunbird/compliance-controls', authenticateToken, async (req, res) => {
    let companyId = null;
    const operation = beginSunbirdOperation(req, 'compliance-controls');
    try {
        const userEmail = req.user.email;
        const tenant = getTenantByEmail(userEmail);
        
        // 🚨 STRICT SCOPE CONTROL
        if (!tenant || tenant.clientId !== 'sunbird') {
            operation.finish(403, { reason: 'access_denied' });
            return res.status(403).json({ error: 'Access denied. Sunbird only.' });
        }

        companyId = tenant.companyId || req.user.companyId || null;
        operation.step('tenant_resolved', { companyId });
        const cached = await getSunbirdPayloadCache('SunbirdComplianceControlsCache', companyId);
        if (cached?.payload?.success && Array.isArray(cached.payload.controls)) {
            operation.step('cache_hit', { cacheAgeMs: cached.ageMs, controls: cached.payload.controls.length });
            cached.payload = compactSunbirdCompliancePayload(cached.payload, {
                source: 'db',
                fetchedAt: cached.lastUpdated
            });
            if (complianceEvidenceService && companyId) {
                persistComplianceDashboardEvidence(companyId, cached.payload, 'dashboard_request', '/api/sunbird/compliance-controls')
                    .catch(error => console.warn('[Compliance Evidence] Cached dashboard payload could not be stored:', error.message));
            }
            sendSunbirdJson(res, cached.payload, operation);
            operation.finish(200, { source: 'cache', controls: cached.payload.controls.length });
            return;
        }

        operation.step('live_collection_start');
        const payload = compactSunbirdCompliancePayload(await fetchComplianceControlsFromApi());
        operation.step('live_collection_complete', { controls: payload.controls.length });
        await upsertSunbirdPayloadCache('SunbirdComplianceControlsCache', companyId, payload);
        operation.step('cache_write_complete');
        if (complianceEvidenceService && companyId) {
            persistComplianceDashboardEvidence(companyId, payload, 'dashboard_request', '/api/sunbird/compliance-controls')
                .catch(error => console.warn('[Compliance Evidence] Dashboard persist failed:', error.message));
        }
        sendSunbirdJson(res, payload, operation);
        operation.finish(200, { source: 'live', controls: payload.controls.length });

    } catch (error) {
        console.error('[Compliance API] Critical Error:', error);
        const stale = await getSunbirdPayloadCache('SunbirdComplianceControlsCache', companyId, { allowStale: true });
        if (stale?.payload?.success && Array.isArray(stale.payload.controls)) {
            const payload = compactSunbirdCompliancePayload(stale.payload, {
                source: 'db-stale',
                fetchedAt: stale.lastUpdated,
                warning: 'Serving stale cached compliance data because live refresh failed.'
            });
            operation.step('stale_cache_served', { controls: payload.controls.length, error: error.message });
            sendSunbirdJson(res, payload, operation);
            operation.finish(200, { source: 'stale', controls: payload.controls.length });
            return;
        }
        operation.finish(500, { error: error.message });
        res.status(500).json({ error: 'Failed to aggregate compliance data' });
    }
});

// ============================================================================
async function fetchOperationsPayloadFromApi({ signal = null, collectorContext = {} } = {}) {
        const token = await getMicrosoftGraphToken();
        const tasks = [];

        // Helper function for Graph API calls
        const fetchGraph = async (endpoint) => {
            const version = endpoint.startsWith('/beta') ? '' : '/v1.0';
            const { response, body } = await fetchGraphResponseWithDeadline(`https://graph.microsoft.com${version}${endpoint}`, token, {
                signal,
                collectorContext,
                label: 'Operations Graph request'
            });
            if (!response.ok) return { value: [] };
            try { return JSON.parse(body); } catch (_) { return { value: [] }; }
        };

        const userBrief = user => ({
            name: user.displayName || user.userPrincipalName || user.mail || 'Unknown user',
            email: user.mail || user.userPrincipalName || 'N/A',
            id: user.id || 'N/A'
        });
        const deviceBrief = device => ({
            name: device.deviceName || device.managedDeviceName || device.id || 'Unknown device',
            user: device.userPrincipalName || device.emailAddress || 'N/A',
            compliance: device.complianceState || 'unknown',
            encrypted: device.isEncrypted ? 'Yes' : 'No'
        });
        const signInBrief = signIn => ({
            user: signIn.userPrincipalName || 'Unknown user',
            app: signIn.appDisplayName || 'Unknown app',
            client: signIn.clientAppUsed || 'Unknown client',
            time: signIn.createdDateTime || 'N/A'
        });
        const alertBrief = alert => ({
            title: alert.title || alert.displayName || 'Security alert',
            severity: alert.severity || 'unknown',
            status: alert.status || 'unknown'
        });

        const addTask = (task, area, priority, insight, why, affected, remediation, dataSource = 'Manual configuration review', evidenceRows = []) => {
            tasks.push({ task, area, priority, insight, why, affected, remediation, dataSource, evidenceRows });
        };

        // ---------------------------------------------------------
        // 1. IDENTITY TASKS
        // ---------------------------------------------------------
        try {
            const users = await fetchMicrosoftUsers(token);
            const workforceUsers = users.filter(user => isWorkforceMicrosoftUser(user));
            let mfaMissingCount = 0;
            let weakAdminCount = 0;
            let mixedAdminCount = 0;
            const usersWithoutMfa = [];
            const weakAdminUsers = [];
            const mixedAdminUsers = [];

            const roleAssignments = await fetchMicrosoftRoleAssignments(token);
            const adminIds = new Set();
            roleAssignments.forEach(assignment => {
                const roleName = assignment.roleDefinition?.displayName || '';
                if (roleName.toLowerCase().includes('admin') || roleName.toLowerCase().includes('global')) {
                    adminIds.add(assignment.principalId);
                }
            });

            await mapWithConcurrency(workforceUsers, 8, async (user) => {
                const authMethods = await fetchUserAuthMethods(token, user.id);
                const hasMfa = hasRealMfaMethod(authMethods);
                const isAdmin = adminIds.has(user.id);

                if (!hasMfa) {
                    mfaMissingCount++;
                    usersWithoutMfa.push(userBrief(user));
                }

                if (isAdmin) {
                    if (!hasMfa || authMethods.length < 2) {
                        weakAdminCount++;
                        weakAdminUsers.push(userBrief(user));
                    }

                    const upn = (user.userPrincipalName || '').toLowerCase();
                    if (!upn.includes('admin') && !upn.includes('adm-')) {
                        mixedAdminCount++;
                        mixedAdminUsers.push(userBrief(user));
                    }
                }
            });

            if (mfaMissingCount > 0) {
                addTask("Complete MFA rollout", "Identity", "High", "🔴 Workforce users vulnerable",
                    "Workforce users without MFA are highly susceptible to credential stuffing and phishing attacks. Guest accounts remain visible but are excluded from the workforce rollout scope.",
                    `${mfaMissingCount} workforce users without MFA registered.`,
                    "1. Open Azure AD Conditional Access.\n2. Enforce MFA for all workforce Member accounts.\n3. Run registration campaign and keep Guests excluded from the workforce rollout metric.",
                    "Microsoft Graph authentication methods",
                    usersWithoutMfa.slice(0, 50)
                );
            }

            // Task 2: Enforce admin MFA
            if (weakAdminCount > 0) {
                addTask("Enforce strong admin MFA", "Identity", "High", "🔴 Admin risk",
                    "Administrators are using weak authentication methods, risking complete tenant compromise.",
                    `${weakAdminCount} admin accounts lack phishing-resistant MFA.`,
                    "1. Require FIDO2 or Microsoft Authenticator for admin roles.\n2. Disable SMS/Voice for privileged accounts.",
                    "Microsoft Graph role assignments and authentication methods",
                    weakAdminUsers.slice(0, 50)
                );
            }

            // Task 3: Separate admin accounts
            if (mixedAdminCount > 0) {
                addTask("Separate admin accounts", "Identity", "High", "🔴 Privilege misuse",
                    "Admin accounts are being used for day-to-day productivity (email, browsing), increasing the attack surface.",
                    `${mixedAdminCount} admin accounts detected as primary user accounts.`,
                    "1. Create dedicated 'admin-username@' accounts.\n2. Strip admin privileges from standard daily accounts.",
                    "Microsoft Graph directory roles and user principal names",
                    mixedAdminUsers.slice(0, 50)
                );
            }

            // Task 4: Block legacy authentication
            const signIns = await fetchMicrosoftSignIns(token);
            const legacySignIns = signIns.filter(s => s.clientAppUsed && s.clientAppUsed !== 'Browser' && s.clientAppUsed !== 'Mobile Apps and Desktop clients');
            if (legacySignIns.length > 0) {
                addTask("Block legacy authentication", "Identity", "High", "🔴 Legacy auth risk",
                    "Legacy protocols (POP, IMAP) bypass MFA and are actively being exploited.",
                    `${legacySignIns.length} legacy sign-in attempts detected.`,
                    "1. Create Conditional Access policy to block legacy authentication.\n2. Disable legacy protocols in Exchange Admin Center.",
                    "Microsoft Graph sign-in logs",
                    legacySignIns.slice(0, 50).map(signInBrief)
                );
            }
        } catch (e) { console.error('Operations: Identity Error', e); }

        // ---------------------------------------------------------
        // 2. DEVICE & ENDPOINT TASKS
        // ---------------------------------------------------------
        try {
            const devices = await fetchMicrosoftDevices(token);
            const nonCompliantDevices = devices.filter(d => d.complianceState !== 'compliant');
            const unencryptedDevices = devices.filter(d => !d.isEncrypted);
            const nonCompliant = nonCompliantDevices.length;
            const unencrypted = unencryptedDevices.length;

            // Task 7: Enforce device compliance
            if (nonCompliant > 0) {
                addTask("Enforce device compliance", "Devices", "High", "🔴 Unmanaged devices",
                    "Devices are accessing corporate data without meeting baseline security requirements.",
                    `${nonCompliant} devices are currently non-compliant.`,
                    "1. Review Intune compliance policies.\n2. Setup Conditional Access to require compliant devices.",
                    "Microsoft Graph Intune managed devices",
                    nonCompliantDevices.slice(0, 50).map(deviceBrief)
                );
            }

            // Task 8: Enable BitLocker
            if (unencrypted > 0) {
                addTask("Enable BitLocker encryption", "Devices", "High", "🔴 Data loss risk",
                    "Unencrypted devices expose local data if the physical device is lost or stolen.",
                    `${unencrypted} devices are not encrypted.`,
                    "1. Deploy BitLocker configuration profile via Intune.\n2. Force silent encryption for Windows endpoints.",
                    "Microsoft Graph Intune managed devices",
                    unencryptedDevices.slice(0, 50).map(deviceBrief)
                );
            }

            // Task 9: Deploy endpoint protection
            const alerts = await fetchSecurityAlerts(token);
            if (alerts.length > 0) {
                addTask("Deploy endpoint protection", "Devices", "High", "🔴 Malware risk",
                    "Active threats detected on endpoints indicating potential protection gaps.",
                    `${alerts.length} active endpoint security alerts.`,
                    "1. Review Microsoft Defender for Endpoint coverage.\n2. Isolate affected devices immediately.",
                    "Microsoft Graph security alerts",
                    alerts.slice(0, 50).map(alertBrief)
                );
            }
        } catch (e) { console.error('Operations: Device Error', e); }

        // ---------------------------------------------------------
        // 3. MANUAL / CONFIGURATION TASKS
        // Evaluated as TRUE (Needs Action) until configured in Phase 2
        // ---------------------------------------------------------
        addTask("Conduct access review", "Identity", "Medium", "🟡 Access drift", "Quarterly access reviews are overdue. Users may retain permissions they no longer need.", "All users and guest accounts.", "1. Export user entitlement list.\n2. Have managers approve current access.\n3. Revoke unneeded roles.");
        addTask("Implement Conditional Access", "Identity", "High", "🔴 No identity protection", "Basic security defaults are insufficient. Explicit CA policies are required.", "Entire tenant.", "1. Enforce MFA for all users.\n2. Block legacy auth.\n3. Require compliant devices.");
        addTask("Enforce BYOD model", "Devices", "High", "🔴 Boundary risk", "Personal devices lack containerization, allowing corporate data to mix with personal apps.", "Mobile devices (iOS/Android).", "1. Deploy App Protection Policies (MAM) in Intune.\n2. Require managed apps for corporate email.");
        addTask("Deploy 1Password", "Credentials", "High", "🔴 Credential exposure", "Users are likely re-using passwords or storing them insecurely.", "All staff.", "1. Provision 1Password enterprise accounts.\n2. Enforce company-wide password manager adoption.");
        addTask("Configure 1Password SSO", "Credentials", "High", "🔴 Access unmanaged", "1Password is not integrated with Azure AD, resulting in disconnected identity lifecycle.", "1Password tenant.", "1. Setup Azure AD Enterprise Application for 1Password.\n2. Configure SAML/OIDC SSO.");
        addTask("Implement Zero Trust", "Network", "High", "🔴 Network exposure", "Internal network assumes trust, making lateral movement easy for attackers.", "Corporate network.", "1. Segment network zones.\n2. Implement micro-segmentation.\n3. Require identity validation for internal resources.");
        addTask("Enable DNS filtering", "Network", "High", "🔴 Malicious traffic risk", "Endpoints can resolve and connect to known malicious domains without restriction.", "All endpoints.", "1. Deploy DNS filtering agent (e.g., Cisco Umbrella, Defender).\n2. Block malware/phishing categories.");
        addTask("Restrict AI tools", "AI", "Medium", "🟡 AI leakage risk", "Employees may be pasting sensitive corporate data into unapproved public AI models.", "Web browsers & endpoints.", "1. Publish acceptable AI usage policy.\n2. Block unsanctioned AI tools via web filtering.");
        addTask("Enable backup", "Backup", "High", "🔴 No recovery", "Microsoft 365 data is not actively backed up to an immutable third-party vault.", "Exchange, SharePoint, OneDrive.", "1. Connect third-party backup provider.\n2. Configure daily retention policies.");
        addTask("Test restore", "Backup", "High", "🔴 Recovery unproven", "Backups are useless if they cannot be reliably restored during an incident.", "Backup infrastructure.", "1. Perform a file-level restore test.\n2. Perform a mailbox restore test.\n3. Document RTO metrics.");
        addTask("Maintain software register", "Applications", "Medium", "🟡 Unknown tools risk", "No central repository exists for approved software, risking supply chain attacks.", "IT Procurement.", "1. Audit current installed software.\n2. Create an approved software catalog.");

        // ---------------------------------------------------------
        // SORTING: Priority -> Severity
        // ---------------------------------------------------------
        const priorityWeight = { 'High': 3, 'Medium': 2, 'Low': 1 };
        tasks.sort((a, b) => priorityWeight[b.priority] - priorityWeight[a.priority]);

        return {
            success: true,
            tasks,
            source: 'api',
            fetchedAt: new Date().toISOString()
        };
}

// SUNBIRD ONLY: OPERATIONS REMEDIATION ENGINE
// ============================================================================
app.get('/api/sunbird/operations', authenticateToken, async (req, res) => {
    let companyId = null;
    try {
        const userEmail = req.user.email;
        const tenant = getTenantByEmail(userEmail);
        
        // 🚨 STRICT SCOPE CONTROL
        if (!tenant || tenant.clientId !== 'sunbird') {
            return res.status(403).json({ error: 'Access denied. Sunbird only.' });
        }

        companyId = tenant.companyId || req.user.companyId || null;
        const cached = await getSunbirdPayloadCache('SunbirdOperationsPayloadCache', companyId);
        if (cached?.payload?.success && Array.isArray(cached.payload.tasks)) {
            if (operationsEvidenceService && companyId) {
                persistOperationsDashboardEvidence(companyId, cached.payload, 'dashboard_request', '/api/sunbird/operations')
                    .catch(error => console.warn('[Operations Evidence] Cached dashboard payload could not be stored:', error.message));
            }
            return res.json({
                ...cached.payload,
                source: 'db',
                fetchedAt: cached.lastUpdated
            });
        }

        const payload = await fetchOperationsPayloadFromApi();
        await upsertSunbirdPayloadCache('SunbirdOperationsPayloadCache', companyId, payload);
        if (operationsEvidenceService && companyId) {
            persistOperationsDashboardEvidence(companyId, payload, 'dashboard_request', '/api/sunbird/operations')
                .catch(error => console.warn('[Operations Evidence] Dashboard persist failed:', error.message));
        }
        res.json(payload);

    } catch (error) {
        console.error('[Operations API] Critical Error:', error);
        const stale = await getSunbirdPayloadCache('SunbirdOperationsPayloadCache', companyId, { allowStale: true });
        if (stale?.payload?.success && Array.isArray(stale.payload.tasks)) {
            return res.json({
                ...stale.payload,
                source: 'db-stale',
                fetchedAt: stale.lastUpdated,
                warning: 'Serving stale cached operations data because live refresh failed.'
            });
        }
        res.status(500).json({ error: 'Failed to generate operations queue' });
    }
});

app.get('/api/sunbird/identity-dashboard', authenticateToken, async (req, res) => {
    const operation = beginSunbirdOperation(req, 'identity-dashboard');
    try {
        const userEmail = req.user.email;
        console.log(`[Sunbird Dashboard] Fetching dashboard data for: ${userEmail}`);

        // Verify this is Sunbird client only (checks cache first, then database)
        const tenant = await verifySunbirdUser(userEmail);
        if (!tenant || tenant.clientId !== 'sunbird') {
            console.warn(`[Sunbird Dashboard] Access denied for ${userEmail}`);
            operation.finish(403, { reason: 'access_denied' });
            return res.status(403).json({ 
                success: false,
                error: 'Access denied',
                message: 'This feature is only available for Sunbird client'
            });
        }

        console.log('[Sunbird Dashboard] User verified as Sunbird client');
    operation.step('tenant_verified', { companyId: tenant.companyId || null });

        // Get Microsoft Graph token
        const token = await getMicrosoftGraphToken();
    operation.step('graph_token_loaded');

        // Fetch all data in parallel
        const [users, roleAssignments, signIns] = await Promise.all([
            fetchMicrosoftUsers(token),
            fetchMicrosoftRoleAssignments(token),
            fetchMicrosoftSignIns(token)
        ]);
        operation.step('graph_aggregates_loaded', {
            users: users.length,
            roleAssignments: roleAssignments.length,
            signIns: signIns.length
        });

        console.log(`[Sunbird Dashboard] Fetched ${users.length} users, ${roleAssignments.length} role assignments, ${signIns.length} sign-ins`);

        // Build user-role map
        const userRoleMap = {};
        roleAssignments.forEach(assignment => {
            const principalId = assignment.principalId;
            if (!userRoleMap[principalId]) {
                userRoleMap[principalId] = [];
            }
            userRoleMap[principalId].push({
                id: assignment.roleDefinition?.id,
                name: assignment.roleDefinition?.displayName || 'Unknown Role'
            });
        });

        // Build sign-in map (latest sign-in per user)
        const latestSignInMap = {};
        signIns.forEach(signin => {
            const upn = signin.userPrincipalName;
            if (!latestSignInMap[upn] || new Date(signin.createdDateTime) > new Date(latestSignInMap[upn].createdDateTime)) {
                latestSignInMap[upn] = {
                    createdDateTime: signin.createdDateTime,
                    appDisplayName: signin.appDisplayName,
                    clientAppUsed: signin.clientAppUsed,
                    ipAddress: signin.ipAddress,
                    location: signin.location?.city ? `${signin.location.city}, ${signin.location.countryOrRegion}` : 'Unknown Location',
                    deviceDetail: signin.deviceDetail,
                    status: signin.status?.errorCode === '0' ? 'Success' : 'Failed'
                };
            }
        });

        // Enrich user data with roles, sign-ins, and calculate risks.
        // Use controlled concurrency to avoid Graph throttling on auth-method calls.
        const enrichedUsers = await mapWithConcurrency(users, 8, async (user) => {
            const userRoles = userRoleMap[user.id] || [];
            const hasAdminRole = userRoles.some(r => 
                r.name.toLowerCase().includes('admin') || 
                r.name.toLowerCase().includes('global')
            );

            // Fetch auth methods for MFA status
            const authMethods = await fetchUserAuthMethods(token, user.id);
            const hasMFA = hasRealMfaMethod(authMethods);

            // Get latest sign-in
            const lastSignIn = latestSignInMap[user.userPrincipalName];
            const lastSignInDate = lastSignIn?.createdDateTime ? new Date(lastSignIn.createdDateTime) : null;
            const daysSinceSignIn = lastSignInDate ? Math.floor((Date.now() - lastSignInDate) / (1000 * 60 * 60 * 24)) : 999;

            // Calculate risk level
            let riskLevel = 'SAFE';
            if (hasAdminRole && !hasMFA) {
                riskLevel = 'HIGH';
            } else if (daysSinceSignIn > 30) {
                riskLevel = 'MEDIUM';
            }

            // Check for unusual location (simple logic - can be enhanced)
            const isNewLocation = lastSignIn && lastSignIn.location === 'Unknown Location';

            const userType = String(user.userType || user.UserType || '').trim().toLowerCase();
            const isGuest = isGuestMicrosoftUser(user);
            const isWorkforce = isWorkforceMicrosoftUser(user);

            return {
                id: user.id,
                displayName: user.displayName || 'Unknown User',
                mail: user.mail,
                userPrincipalName: user.userPrincipalName,
                userType: isGuest ? 'Guest' : isWorkforce ? 'Member' : 'Unknown',
                jobTitle: user.jobTitle || 'No Title',
                mobilePhone: user.mobilePhone || 'N/A',
                roles: userRoles,
                hasAdminRole: hasAdminRole,
                isExternal: isGuest,
                isWorkforce,
                mfaEnabled: hasMFA,
                authMethodCount: authMethods.length,
                riskLevel: riskLevel,
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
        operation.step('users_enriched', { users: enrichedUsers.length });

        // Calculate dashboard metrics using native Entra workforce scope.
        const totalUsers = enrichedUsers.length;
        const workforceUsers = enrichedUsers.filter(u => u.isWorkforce === true);
        const externalUsers = enrichedUsers.filter(u => u.isExternal === true);
        const unknownUserTypes = enrichedUsers.filter(u => !u.isWorkforce && !u.isExternal).length;
        const adminUsers = workforceUsers.filter(u => u.hasAdminRole).length;
        const mfaEnabledUsers = workforceUsers.filter(u => u.mfaEnabled).length;
        const mfaMissingUsers = workforceUsers.filter(u => u.mfaEnabled === false).length;
        const mfaUnknownUsers = workforceUsers.length - mfaEnabledUsers - mfaMissingUsers;
        const mfaPercentage = workforceUsers.length ? ((mfaEnabledUsers / workforceUsers.length) * 100).toFixed(1) : '0.0';
        const highRiskUsers = enrichedUsers.filter(u => u.riskLevel === 'HIGH').length;
        const mediumRiskUsers = enrichedUsers.filter(u => u.riskLevel === 'MEDIUM').length;
        const activeUsers24h = enrichedUsers.filter(u => u.lastSignIn.daysSince <= 1).length;
        const usersWithCompleteProfile = enrichedUsers.filter(u => 
            u.jobTitle !== 'No Title' && u.mobilePhone !== 'N/A'
        ).length;

        // 🎯 NEW: A. Privileged Risk - Admins without MFA
        const privilegedUsersWithoutMFA = workforceUsers.filter(u => u.hasAdminRole && !u.mfaEnabled).length;

        // 🎯 NEW: B. Identity Risk Score (calculated, not random)
        let identityRiskScore = 0;
        enrichedUsers.forEach(user => {
            if (user.hasAdminRole && !user.mfaEnabled) identityRiskScore += 40;
            if (user.lastSignIn.daysSince > 999) identityRiskScore += 25; // Never signed in
            if (user.authMethodCount === 0) identityRiskScore += 20;
            if (user.isExternal) identityRiskScore += 15;
            if (user.riskLevel === 'MEDIUM') identityRiskScore += 10;
            if (user.riskLevel === 'HIGH') identityRiskScore += 30;
        });
        identityRiskScore = Math.min(100, Math.round((identityRiskScore / (totalUsers * 40)) * 100)); // Normalize to 0-100

        // 🎯 NEW: C. Inactive Users Breakdown
        const inactiveBreakdown = {
            '0-7days': enrichedUsers.filter(u => u.lastSignIn.daysSince >= 0 && u.lastSignIn.daysSince <= 7).length,
            '7-30days': enrichedUsers.filter(u => u.lastSignIn.daysSince > 7 && u.lastSignIn.daysSince <= 30).length,
            '30-90days': enrichedUsers.filter(u => u.lastSignIn.daysSince > 30 && u.lastSignIn.daysSince <= 90).length,
            '90+days': enrichedUsers.filter(u => u.lastSignIn.daysSince > 90).length
        };

        // 🎯 NEW: E. Device Trust Analysis
        const deviceTrustAnalysis = {
            managed: 0,
            unmanaged: 0,
            unknown: 0
        };
        enrichedUsers.forEach(user => {
            if (user.lastSignIn && user.lastSignIn.device) {
                const device = user.lastSignIn.device.toLowerCase();
                if (device.includes('unknown') || device === 'unknown') {
                    deviceTrustAnalysis.unknown++;
                } else if (device.includes('managed') || device.includes('iphone') || device.includes('ipad') || device.includes('android')) {
                    deviceTrustAnalysis.managed++;
                } else {
                    deviceTrustAnalysis.unmanaged++;
                }
            } else {
                deviceTrustAnalysis.unknown++;
            }
        });

        // 🎯 NEW: F. Authentication Strength
        const authenticationStrength = {
            passwordOnly: 0,
            basicMFA: 0,
            strongMFA: 0 // FIDO2, Authenticator app
        };
        enrichedUsers.forEach(user => {
            if (user.authMethodCount === 0 || user.authMethodCount === 1) {
                authenticationStrength.passwordOnly++;
            } else if (user.mfaEnabled && user.authMethodCount >= 2) {
                authenticationStrength.basicMFA++;
                // Note: would need detailed auth method data to differentiate strongMFA
            }
        });
        authenticationStrength.strongMFA = Math.round(enrichedUsers.filter(u => u.authMethodCount > 2).length);

        // 🎯 NEW: G. Role Distribution (Top roles)
        const roleDistribution = {};
        enrichedUsers.forEach(user => {
            user.roles.forEach(role => {
                roleDistribution[role.name] = (roleDistribution[role.name] || 0) + 1;
            });
        });
        const topRoles = Object.entries(roleDistribution)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8)
            .map(([role, count]) => ({ role, count }));

        // 🎯 NEW: H. Identity Hygiene Score
        const profileCompleteness = Math.round((enrichedUsers.filter(u => u.jobTitle !== 'No Title').length / totalUsers) * 100);
        const workforceBase = Math.max(1, workforceUsers.length);
        const authCompleteness = Math.round((mfaEnabledUsers / workforceBase) * 100);
        const activityCompleteness = Math.round((workforceUsers.filter(u => u.lastSignIn.daysSince <= 90).length / workforceBase) * 100);
        const identityHygieneScore = Math.round((profileCompleteness + authCompleteness + activityCompleteness) / 3);

        const systemHealth = {
            performance: Math.round((workforceUsers.filter(u => u.lastSignIn.status === 'Success').length / workforceBase) * 100) || 0,
            availability: Math.round(((workforceUsers.filter(u => u.lastSignIn.daysSince <= 1).length / workforceBase) * 100) || 0),
            security: Math.round((mfaEnabledUsers / workforceBase) * 100) || 0,
            compliance: Math.round((workforceUsers.filter(u => u.jobTitle !== 'No Title' && u.mobilePhone !== 'N/A').length / workforceBase) * 100) || 0,
            backup: Math.round((workforceUsers.filter(u => u.authMethodCount > 1).length / workforceBase) * 100) || 0
        };

        // Smart insights
        const toInsightEvidence = user => ({
            id: user.id,
            displayName: user.displayName,
            userPrincipalName: user.userPrincipalName,
            riskLevel: user.riskLevel
        });
        const insights = {
            adminsWithoutMFA: enrichedUsers.filter(u => u.flags.adminWithoutMFA).slice(0, 20).map(toInsightEvidence),
            inactiveUsers: enrichedUsers.filter(u => u.flags.inactiveOver30Days).slice(0, 20).map(toInsightEvidence),
            newLocationLogins: enrichedUsers.filter(u => u.flags.newLocationLogin).slice(0, 20).map(toInsightEvidence)
        };

        // Device breakdown
        const deviceBreakdown = {};
        enrichedUsers.forEach(user => {
            if (user.lastSignIn.device) {
                const device = user.lastSignIn.device.toLowerCase();
                deviceBreakdown[device] = (deviceBreakdown[device] || 0) + 1;
            }
        });

        // Top locations
        const locationBreakdown = {};
        enrichedUsers.forEach(user => {
            if (user.lastSignIn.location && user.lastSignIn.location !== 'No sign-in') {
                locationBreakdown[user.lastSignIn.location] = (locationBreakdown[user.lastSignIn.location] || 0) + 1;
            }
        });

        const topLocations = Object.entries(locationBreakdown)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([location, count]) => ({ location, count }));

        // Calculate security score (0-100)
        const securityScore = Math.round(
            (mfaPercentage * 0.4) +  // MFA is 40% of score
            ((100 - (highRiskUsers / totalUsers * 100)) * 0.3) +  // Low risk is 30%
            ((adminUsers <= 5 ? 100 : 50) * 0.3)  // Admin count is 30%
        );

        console.log('[Sunbird Dashboard] Dashboard data compiled successfully');

        const dashboardPayload = {
            success: true,
            tenant: tenant.clientId,
            fetchedAt: new Date().toISOString(),
            summary: {
                totalUsers,
                workforceUsers: workforceUsers.length,
                externalUsers: externalUsers.length,
                unknownUserTypes,
                activeUsers24h,
                activeUsersPercentage: Math.round((activeUsers24h / totalUsers) * 100),
                adminUsers,
                mfaEnabledPercentage: mfaPercentage,
                mfaEnabledUsers,
                mfaMissingUsers,
                highRiskUsers,
                highRiskBreakdown: {
                    adminWithoutMFA: privilegedUsersWithoutMFA,
                    neverSignedIn: enrichedUsers.filter(u => u.lastSignIn.daysSince > 999).length,
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
            riskDistribution: {
                HIGH: highRiskUsers,
                MEDIUM: mediumRiskUsers,
                SAFE: totalUsers - highRiskUsers - mediumRiskUsers
            },
            insights,
            inactiveBreakdown,
            deviceTrustAnalysis,
            authenticationStrength,
            topRoles,
            hygieneLevels: {
                profileCompleteness,
                authCompleteness,
                activityCompleteness
            },
            signInPatterns: {
                topLocations,
                deviceBreakdown,
                avgSignInsPerUser: signIns.length / totalUsers
            },
            roleInsights: {
                globalAdmins: enrichedUsers.filter(u => u.roles.some(r => r.name.toLowerCase().includes('global'))).length,
                privilegedUsers: enrichedUsers.filter(u => u.roles.length > 0).length,
                usersWithMultipleRoles: enrichedUsers.filter(u => u.roles.length > 1).length,
                roleDistribution: topRoles
            }
        };

        if (identityEvidenceService && tenant.companyId) {
            operation.step('evidence_persist_scheduled');
            identityEvidenceService.persistProcessedEvidence({
                companyId: tenant.companyId,
                tenantKey: tenant.clientId,
                payload: dashboardPayload,
                collectionTrigger: 'dashboard_request',
                sourceEndpoint: '/api/sunbird/identity-dashboard'
            }).catch(error => {
                console.warn('[Identity Evidence] Dashboard response could not be stored:', error.message);
            });
        }

        sendSunbirdJson(res, dashboardPayload, operation);
        operation.finish(200, { users: enrichedUsers.length, signIns: signIns.length });

    } catch (error) {
        console.error('[Sunbird Dashboard] Error:', error.message);
        operation.finish(500, { error: error.message });
        
        res.status(500).json({ 
            error: 'Failed to fetch dashboard data',
            message: error.message
        });
    }
});

// ============================================================================
// ADMIN: Manage User Access Types (Set Sunbird or other tenant access)
// ============================================================================
app.post('/api/admin/users/access-type', authenticateToken, async (req, res) => {
    try {
        const { email, accessType } = req.body;
        
        if (!email || !accessType) {
            return res.status(400).json({ 
                success: false,
                error: 'Missing email or accessType'
            });
        }

        // Get user by email
        const [userRows] = await pool.query(
            'SELECT ID FROM Users WHERE LOWER(Email) = LOWER(?)',
            [email]
        );

        if (userRows.length === 0) {
            return res.status(404).json({ 
                success: false,
                error: 'User not found'
            });
        }

        const userId = userRows[0].ID;

        // Check if access record exists
        const [existingRows] = await pool.query(
            'SELECT ID FROM TenantAccessControl WHERE UserID = ?',
            [userId]
        );

        if (existingRows.length > 0) {
            // Update existing record
            await pool.query(
                'UPDATE TenantAccessControl SET AccessType = ? WHERE UserID = ?',
                [accessType, userId]
            );
            console.log(`[Admin] Updated ${email} access type to ${accessType}`);
        } else {
            // Insert new record
            await pool.query(
                'INSERT INTO TenantAccessControl (UserID, AccessType) VALUES (?, ?)',
                [userId, accessType]
            );
            console.log(`[Admin] Created ${email} access type as ${accessType}`);
        }

        // Clear cache for this user
        accessContextCache.delete(String(email || '').toLowerCase());

        res.json({ 
            success: true,
            message: `User access type updated to ${accessType}`,
            email,
            accessType
        });

    } catch (error) {
        console.error('[Admin] Error updating access type:', error.message);
        res.status(500).json({ 
            success: false,
            error: 'Failed to update user access type',
            message: error.message
        });
    }
});

// ============================================================================
// HELPER FUNCTION: Convert various types to boolean for MFA
// ============================================================================
function toBooleanMfa(value) {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return value > 0;
    if (typeof value === 'string') {
        const normalized = value.trim().toLowerCase();
        return normalized === 'true' || normalized === 'yes' || normalized === 'enabled' || normalized === '1';
    }
    return false;
}

// ============================================================================
// SUNBIRD IDENTITY DASHBOARD - CACHED VERSION (Database-Backed)
// ============================================================================
// This endpoint serves cached identity dashboard data from MySQL tables
// for faster loading and reduced Microsoft Graph API calls
// ============================================================================

/**
 * Verify user is Sunbird client - checks cache first, then database
 */
async function verifySunbirdUser(userEmail) {
    try {
        // Check cache first
        const cachedTenant = getTenantByEmail(userEmail);
        if (cachedTenant && cachedTenant.clientId === 'sunbird') {
            return cachedTenant;
        }

        // If not in cache, check database directly
        const accessContext = await getUserAccessContextByEmail(userEmail);
        const hasSunbirdAccess = Boolean(
            accessContext?.hasSunbirdAccess
            || accessContext?.accessType === 'sunbird'
            || accessContext?.clientId === 'sunbird'
        );
        if (accessContext && hasSunbirdAccess) {
            // Update cache for future requests
            accessContextCache.set(String(userEmail || '').toLowerCase(), {
                accessType: 'sunbird',
                tenantId: accessContext.tenantId,
                companyId: accessContext.companyId
            });
            return {
                clientId: 'sunbird',
                tenantId: accessContext.tenantId,
                companyId: accessContext.companyId
            };
        }

        return null;
    } catch (error) {
        console.error('[Sunbird Verification] Error checking user:', error.message);
        return null;
    }
}

app.get('/api/sunbird/identity-dashboard-cached', authenticateToken, async (req, res) => {
    try {
        const userEmail = req.user.email;
        console.log(`[Sunbird Cached Dashboard] Fetching cached data for: ${userEmail}`);

        // Verify this is Sunbird client only
        const tenant = await verifySunbirdUser(userEmail);
        if (!tenant || tenant.clientId !== 'sunbird') {
            console.warn(`[Sunbird Cached Dashboard] Access denied for ${userEmail}`);
            return res.status(403).json({ 
                success: false,
                error: 'Access denied',
                message: 'This feature is only available for Sunbird client'
            });
        }

        console.log('[Sunbird Cached Dashboard] User verified as Sunbird client');

        // Fetch data from MySQL cache tables
        let metricsRows = [];
        let usersRows = [];
        let riskRows = [];
        let cacheMetadataRows = [];
        let signinActivityRows = [];

        try {
            [metricsRows] = await pool.query(
                'SELECT * FROM identity_metrics WHERE tenant_id = ? ORDER BY last_updated DESC LIMIT 1',
                ['sunbird']
            );
        } catch (e) {
            console.warn('[Sunbird Cached Dashboard] Failed to fetch identity_metrics:', e.message);
        }

        try {
            [usersRows] = await pool.query(
                'SELECT * FROM identity_users WHERE 1=1 ORDER BY last_updated DESC'
            );
        } catch (e) {
            console.warn('[Sunbird Cached Dashboard] Failed to fetch identity_users:', e.message);
        }

        try {
            [riskRows] = await pool.query(
                'SELECT * FROM identity_risk_scores WHERE tenant_id = ? ORDER BY last_updated DESC LIMIT 1',
                ['sunbird']
            );
        } catch (e) {
            console.warn('[Sunbird Cached Dashboard] Failed to fetch identity_risk_scores:', e.message);
        }

        try {
            [cacheMetadataRows] = await pool.query(
                'SELECT * FROM identity_cache_metadata WHERE tenant_id = ? LIMIT 1',
                ['sunbird']
            );
        } catch (e) {
            console.warn('[Sunbird Cached Dashboard] Failed to fetch identity_cache_metadata:', e.message);
        }

        try {
            [signinActivityRows] = await pool.query(
                'SELECT * FROM identity_signin_activity WHERE tenant_id = ? ORDER BY last_updated DESC LIMIT 1',
                ['sunbird']
            );
        } catch (e) {
            console.warn('[Sunbird Cached Dashboard] Failed to fetch identity_signin_activity:', e.message);
        }

        const cacheHasUsableMetrics = metricsRows.length > 0 && (
            Number(metricsRows[0].total_users || 0) > 0 ||
            Number(metricsRows[0].admin_users || 0) > 0 ||
            Number(metricsRows[0].active_users_24h || 0) > 0
        );

        // Cache-only callers must not restart the slow Microsoft Graph refresh they are avoiding.
        const cacheOnly = String(req.query?.cacheOnly || '').toLowerCase() === 'true' || String(req.query?.cacheOnly || '') === '1';
        if (!cacheHasUsableMetrics && !cacheOnly) {
            try {
                console.log('[Sunbird Cached Dashboard] Cache empty, hydrating identity metrics from Microsoft Graph');
                const liveMetrics = await fetchIdentityMetricsFromApi();
                const liveDetails = await fetchIdentityDetailsFromApi();
                const normalizedUsers = Array.isArray(liveDetails.users) ? liveDetails.users : [];
                const externalUsers = normalizedUsers.filter(user => user.isExternal).length;
                const usersWithCompleteProfile = normalizedUsers.filter(user =>
                    user.jobTitle && user.jobTitle !== 'No Title' &&
                    user.mobilePhone && user.mobilePhone !== 'N/A'
                ).length;

                metricsRows = [{
                    total_users: liveMetrics.totalUsers,
                    admin_users: liveMetrics.adminRoles,
                    mfa_enabled_users: 0,
                    mfa_percentage: 0,
                    high_risk_users: 0,
                    medium_risk_users: externalUsers,
                    active_users_24h: liveMetrics.activeUsers,
                    users_with_complete_profile: usersWithCompleteProfile,
                    privileged_users_without_mfa: 0,
                    identity_risk_score: Math.max(0, 100 - liveMetrics.securityScore)
                }];

                usersRows = normalizedUsers.map(user => ({
                    id: user.id,
                    display_name: user.displayName,
                    mail: user.mail,
                    user_principal_name: user.userPrincipalName,
                    job_title: user.jobTitle,
                    mobile_phone: user.mobilePhone,
                    roles: JSON.stringify(user.roles || []),
                    mfa_enabled: false,
                    auth_method_count: 0,
                    risk_level: user.isExternal ? 'MEDIUM' : 'SAFE',
                    is_external: user.isExternal,
                    account_enabled: true,
                    last_signin_datetime: null,
                    days_since_signin: 999,
                    last_signin_location: 'Unknown',
                    last_signin_device: 'Unknown'
                }));

                if (tenant.companyId) {
                    await pool.query(
                        `REPLACE INTO IdentityMetricsCache (CompanyID, TotalUsers, ActiveUsers, AdminRoles, SecurityScore, LastUpdated)
                         VALUES (?, ?, ?, ?, ?, NOW())`,
                        [tenant.companyId, liveMetrics.totalUsers, liveMetrics.activeUsers, liveMetrics.adminRoles, liveMetrics.securityScore]
                    ).catch(e => console.warn('[Sunbird Cached Dashboard] Failed to mirror IdentityMetricsCache:', e.message));

                    await pool.query(
                        `REPLACE INTO IdentityUserDetailsCache (CompanyID, UsersPayload, LastUpdated)
                         VALUES (?, ?, NOW())`,
                        [tenant.companyId, JSON.stringify(normalizedUsers)]
                    ).catch(e => console.warn('[Sunbird Cached Dashboard] Failed to mirror IdentityUserDetailsCache:', e.message));

                    await upsertRoleAssignmentsCache(tenant.companyId, liveDetails.roleAssignments || [])
                        .catch(e => console.warn('[Sunbird Cached Dashboard] Failed to mirror roles cache:', e.message));
                }
            } catch (e) {
                console.warn('[Sunbird Cached Dashboard] Microsoft Graph hydration failed:', e.message);
            }
        }

        // Build metrics object
        let metrics = metricsRows.length > 0 ? {
            totalUsers: metricsRows[0].total_users || 0,
            adminUsers: metricsRows[0].admin_users || 0,
            mfaEnabledUsers: metricsRows[0].mfa_enabled_users || 0,
            mfaPercentage: parseFloat(metricsRows[0].mfa_percentage) || 0,
            highRiskUsers: metricsRows[0].high_risk_users || 0,
            mediumRiskUsers: metricsRows[0].medium_risk_users || 0,
            activeUsers24h: metricsRows[0].active_users_24h || 0,
            usersWithCompleteProfile: metricsRows[0].users_with_complete_profile || 0,
            privilegedUsersWithoutMFA: metricsRows[0].privileged_users_without_mfa || 0,
            identityRiskScore: metricsRows[0].identity_risk_score || 0
        } : {
            totalUsers: 0,
            adminUsers: 0,
            mfaEnabledUsers: 0,
            mfaPercentage: 0,
            highRiskUsers: 0,
            mediumRiskUsers: 0,
            activeUsers24h: 0,
            usersWithCompleteProfile: 0,
            privilegedUsersWithoutMFA: 0,
            identityRiskScore: 0
        };

        // Build risk breakdown object
        const riskBreakdown = riskRows.length > 0 ? {
            inactivity: {
                '0-7days': riskRows[0].inactive_0_7_days || 0,
                '7-30days': riskRows[0].inactive_7_30_days || 0,
                '30-90days': riskRows[0].inactive_30_90_days || 0,
                '90+days': riskRows[0].inactive_90_plus_days || 0
            },
            deviceTrust: {
                managed: riskRows[0].device_managed || 0,
                unmanaged: riskRows[0].device_unmanaged || 0,
                unknown: riskRows[0].device_unknown || 0
            },
            authenticationStrength: {
                passwordOnly: riskRows[0].auth_password_only || 0,
                basicMFA: riskRows[0].auth_basic_mfa || 0,
                strongMFA: riskRows[0].auth_strong_mfa || 0
            }
        } : {
            inactivity: { '0-7days': 0, '7-30days': 0, '30-90days': 0, '90+days': 0 },
            deviceTrust: { managed: 0, unmanaged: 0, unknown: 0 },
            authenticationStrength: { passwordOnly: 0, basicMFA: 0, strongMFA: 0 }
        };

        // Helper function for safe JSON parsing
        function safeJsonParse(str, defaultValue = []) {
            // Check if str is a string and has content
            if (typeof str !== 'string' || !str.trim()) return defaultValue;
            try {
                return JSON.parse(str);
            } catch (e) {
                console.warn('[Sunbird Cached Dashboard] JSON parse error:', e.message, 'for value:', str);
                return defaultValue;
            }
        }

        // Build users array with enriched data
        let users = usersRows.map(user => ({
            id: user.id,
            displayName: user.display_name || 'Unknown User',
            mail: user.mail,
            userPrincipalName: user.user_principal_name,
            jobTitle: user.job_title || 'No Title',
            mobilePhone: user.mobile_phone || 'N/A',
            roles: safeJsonParse(user.roles, []),
            mfaEnabled: toBooleanMfa(user.mfa_enabled),
            authMethodCount: user.auth_method_count || 0,
            riskLevel: user.risk_level || 'SAFE',
            isExternal: user.is_external || false,
            accountEnabled: user.account_enabled !== false,
            lastSignIn: {
                dateTime: user.last_signin_datetime ? new Date(user.last_signin_datetime).toISOString() : null,
                daysSince: user.days_since_signin || 999,
                location: user.last_signin_location || 'Unknown',
                device: user.last_signin_device || 'Unknown'
            }
        }));

        let roleAssignments = [];
        if (tenant.companyId) {
            const cachedRoles = await getCachedRoleAssignments(tenant.companyId);
            roleAssignments = cachedRoles?.roleAssignments || [];
        }

        const usersMissingRoles = users.length > 0 && users.every(user => !Array.isArray(user.roles) || user.roles.length === 0);
        if (usersMissingRoles && roleAssignments.length === 0 && tenant.companyId) {
            try {
                roleAssignments = await fetchRoleAssignmentsFromApi(tenant.companyId);
            } catch (roleError) {
                console.warn('[Sunbird Cached Dashboard] Failed to hydrate roles from Microsoft Graph:', roleError.message);
            }
        }

        if (usersMissingRoles && roleAssignments.length > 0) {
            users = mergeUsersWithRoleAssignments(users, roleAssignments);
        }

        const processedIdentitySource = buildIdentityDashboardSource({
            metricsRow: metricsRows[0] || {},
            usersRows: users,
            riskRow: riskRows[0] || {},
            signInRow: signinActivityRows[0] || {},
            roleAssignments
        });
        users = processedIdentitySource.users;
        metrics = processedIdentitySource.legacyMetrics;

        const topRoles = Object.entries(
            roleAssignments.reduce((acc, assignment) => {
                const roleName = assignment.roleName || 'Unknown Role';
                acc[roleName] = (acc[roleName] || 0) + 1;
                return acc;
            }, {})
        )
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8)
            .map(([role, count]) => ({ role, count }));

        // Build cache metadata
        const cacheMetadata = cacheMetadataRows.length > 0 ? {
            lastSyncTime: cacheMetadataRows[0].last_sync_time,
            nextSyncTime: cacheMetadataRows[0].next_sync_time,
            syncStatus: cacheMetadataRows[0].sync_status,
            syncErrorMessage: cacheMetadataRows[0].sync_error_message,
            totalUsersSynced: cacheMetadataRows[0].total_users_synced,
            syncDurationSeconds: cacheMetadataRows[0].sync_duration_seconds
        } : null;

        // Build signin activity
        const signinActivity = signinActivityRows.length > 0 ? {
            signInCount24h: signinActivityRows[0].sign_in_count_24h || 0,
            failedSigninCount24h: signinActivityRows[0].failed_signin_count_24h || 0,
            uniqueLocationsCount: signinActivityRows[0].unique_locations_count || 0,
            topLocations: safeJsonParse(signinActivityRows[0].top_locations, []),
            recentSignins: safeJsonParse(signinActivityRows[0].recent_signings, [])
        } : null;

        console.log(`[Sunbird Cached Dashboard] Loaded ${users.length} users from cache`);

        res.json({
            success: true,
            tenant: tenant.clientId,
            fetchedAt: new Date().toISOString(),
            source: 'database_cache',
            cacheMetadata,
            metrics,
            stackctrlMetrics: processedIdentitySource.dashboardMetrics,
            riskBreakdown,
            users,
            roleAssignments,
            topRoles,
            signinActivity,
            summary: {
                totalUsers: metrics.totalUsers,
                activeUsers24h: metrics.activeUsers24h,
                activeUsersPercentage: metrics.totalUsers > 0 ? Math.round((metrics.activeUsers24h / metrics.totalUsers) * 100) : 0,
                adminUsers: metrics.adminUsers,
                mfaEnabledPercentage: metrics.mfaPercentage,
                highRiskUsers: metrics.highRiskUsers,
                highRiskBreakdown: {
                    adminWithoutMFA: metrics.privilegedUsersWithoutMFA,
                    neverSignedIn: users.filter(u => u.lastSignIn.daysSince > 999).length,
                    externalUser: users.filter(u => u.isExternal).length
                },
                securityScore: Math.round(
                    (metrics.mfaPercentage * 0.4) +
                    ((100 - (metrics.totalUsers > 0 ? (metrics.highRiskUsers / metrics.totalUsers) * 100 : 0)) * 0.3) +
                    ((metrics.adminUsers <= 5 ? 100 : 50) * 0.3)
                ),
                identityRiskScore: metrics.identityRiskScore,
                mediumRiskUsers: metrics.mediumRiskUsers,
                privilegedUsersWithoutMFA: metrics.privilegedUsersWithoutMFA
            }
        });

    } catch (error) {
        console.error('[Sunbird Cached Dashboard] Error:', error.message);
        console.error('[Sunbird Cached Dashboard] Stack:', error.stack);
        
        // Always return valid JSON to prevent "Unexpected end of JSON input" errors
        return res.status(500).json({ 
            success: false,
            error: 'Failed to fetch cached dashboard data',
            message: error.message || 'An unexpected error occurred',
            timestamp: new Date().toISOString()
        });
    }
});

// ====================================================================================================//
//                        MICROSOFT GRAPH - DEVICES & SECURITY                                        //
// ====================================================================================================//

/**
 * Fetch managed devices from Microsoft Intune/Device Management
 */
async function fetchMicrosoftDevices(token) {
    const url = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=250';
    
    try {
        const data = await fetchMicrosoftGraphJson(url, token, 'Microsoft Graph managed devices');
        return data.value || [];
    } catch (error) {
        console.error('[Microsoft Graph] Devices fetch failed:', error.message);
        throw error;
    }
}

/**
 * Fetch device compliance policies
 */
async function fetchCompliancePolicies(token) {
    const url = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$top=250';
    
    try {
        const data = await fetchMicrosoftGraphJson(url, token, 'Microsoft Graph compliance policies');
        return data.value || [];
    } catch (error) {
        console.error('[Microsoft Graph] Compliance policies fetch failed:', error.message);
        throw error;
    }
}

/**
 * Fetch security alerts
 */
async function fetchSecurityAlerts(token) {
    const url = 'https://graph.microsoft.com/v1.0/security/alerts?$top=50';
    
    try {
        const data = await fetchMicrosoftGraphJson(url, token, 'Microsoft Graph security alerts');
        return data.value || [];
    } catch (error) {
        console.error('[Microsoft Graph] Security alerts fetch failed:', error.message);
        return []; // Return empty array if alerts API fails
    }
}

/**
 * Route: GET /api/microsoft-devices
 * Returns: Complete devices, compliance, and security data for Devices dashboard
 */
app.get('/api/microsoft-devices', authenticateToken, async (req, res) => {
    try {
        const userEmail = req.user.email;
        console.log(`[Devices Dashboard] Fetching device data for: ${userEmail}`);

        // Get the tenant for this user
        const tenant = getTenantByEmail(userEmail);
        if (!tenant) {
            console.warn(`[Devices Dashboard] User ${userEmail} does not belong to any configured tenant`);
            return res.status(403).json({ 
                error: 'User does not have access to device data',
                message: 'Your email is not associated with any tenant'
            });
        }

        // Get Microsoft Graph token
        const token = await getMicrosoftGraphToken();

        // Fetch all required data in parallel
        const [devices, policies, alerts] = await Promise.all([
            fetchMicrosoftDevices(token),
            fetchCompliancePolicies(token),
            fetchSecurityAlerts(token)
        ]);

        // Process devices data
        const normalizeCompliance = value => String(value || 'unknown').toLowerCase().replace(/[_\s-]/g, '');
        const processedDevices = devices.map(device => ({
            id: device.id,
            deviceName: device.deviceName || 'Unknown Device',
            userPrincipalName: device.userPrincipalName || 'N/A',
            operatingSystem: device.operatingSystem || 'Unknown',
            osVersion: device.osVersion || 'N/A',
            complianceState: normalizeCompliance(device.complianceState),
            isEncrypted: device.isEncrypted || false,
            encryptionStatus: device.isEncrypted ? 'Encrypted' : 'Not Encrypted',
            managementAgent: device.managementAgent || 'Unknown',
            lastSyncDateTime: device.lastSyncDateTime ? new Date(device.lastSyncDateTime) : null,
            azureADRegistered: device.azureADRegistered || false,
            deviceEnrollmentType: device.deviceEnrollmentType || 'Unknown',
            deviceType: device.deviceType || 'Unknown',
            activationLockEnabled: device.activationLockEnabled || false,
            serialNumber: device.serialNumber || 'N/A',
            physicalIds: device.physicalIds || [],
            hasPendingActions: device.hasPendingActions || false,
            complianceGracePeriodExpirationDateTime: device.complianceGracePeriodExpirationDateTime || null
        }));

        // Calculate device metrics
        const totalDevices = processedDevices.length;
        const compliantDevices = processedDevices.filter(d => d.complianceState === 'compliant').length;
        const encryptedDevices = processedDevices.filter(d => d.isEncrypted).length;
        const registeredDevices = processedDevices.filter(d => d.azureADRegistered).length;
        const staleDevices = processedDevices.filter(d => {
            if (!d.lastSyncDateTime) return true;
            const daysSinceSync = (Date.now() - new Date(d.lastSyncDateTime).getTime()) / (1000 * 60 * 60 * 24);
            return daysSinceSync > 7;
        }).length;

        // Device breakdown by OS
        const osDistribution = {};
        processedDevices.forEach(device => {
            const os = device.operatingSystem || 'Unknown';
            osDistribution[os] = (osDistribution[os] || 0) + 1;
        });

        // Device breakdown by management status
        const managementStatus = {
            managed: processedDevices.filter(d => d.managementAgent && d.managementAgent !== 'unknown').length,
            unmanaged: processedDevices.filter(d => !d.managementAgent || d.managementAgent === 'unknown').length,
            aadRegistered: registeredDevices
        };

        // Compliance breakdown
        const complianceBreakdown = {
            compliant: compliantDevices,
            nonCompliant: processedDevices.filter(d => d.complianceState === 'noncompliant').length,
            unknown: processedDevices.filter(d => d.complianceState === 'unknown').length
        };

        // High risk devices (not encrypted OR non-compliant OR stale)
        const highRiskDevices = processedDevices.filter(d => 
            !d.isEncrypted || d.complianceState !== 'compliant' || 
            (d.lastSyncDateTime && (Date.now() - new Date(d.lastSyncDateTime).getTime()) / (1000 * 60 * 60 * 24) > 7)
        );

        // Activity breakdown
        const activityBreakdown = {
            active24h: processedDevices.filter(d => {
                if (!d.lastSyncDateTime) return false;
                const daysSinceSync = (Date.now() - new Date(d.lastSyncDateTime).getTime()) / (1000 * 60 * 60 * 24);
                return daysSinceSync <= 1;
            }).length,
            stale7days: processedDevices.filter(d => {
                if (!d.lastSyncDateTime) return false;
                const daysSinceSync = (Date.now() - new Date(d.lastSyncDateTime).getTime()) / (1000 * 60 * 60 * 24);
                return daysSinceSync > 7 && daysSinceSync <= 30;
            }).length,
            dead30days: processedDevices.filter(d => {
                if (!d.lastSyncDateTime) return true;
                const daysSinceSync = (Date.now() - new Date(d.lastSyncDateTime).getTime()) / (1000 * 60 * 60 * 24);
                return daysSinceSync > 30;
            }).length
        };

        // Device security score (0-100)
        const encryptionPercent = totalDevices > 0 ? (encryptedDevices / totalDevices) * 100 : 0;
        const compliancePercent = totalDevices > 0 ? (compliantDevices / totalDevices) * 100 : 0;
        const activePercent = totalDevices > 0 ? (activityBreakdown.active24h / totalDevices) * 100 : 0;
        const registeredPercent = totalDevices > 0 ? (registeredDevices / totalDevices) * 100 : 0;

        const deviceSecurityScore = Math.round(
            (encryptionPercent * 0.25) +
            (compliancePercent * 0.25) +
            (activePercent * 0.25) +
            (registeredPercent * 0.25)
        );

        // Process optional security alerts (limit to 20). Alerts support device context but must not block device refresh.
        const normalizedAlertPayload = normalizeDeviceAlertsPayload(alerts, { logger: console });
        const processedAlerts = normalizedAlertPayload.alerts.slice(0, 20).map(alert => ({
            id: alert.id,
            title: alert.title || 'Unknown Alert',
            description: alert.description || '',
            severity: alert.severity || 'medium',
            status: alert.status || 'newAlert',
            createdDateTime: alert.createdDateTime || new Date().toISOString(),
            eventDateTime: alert.eventDateTime || new Date().toISOString(),
            sourceMaterials: alert.sourceMaterials || [],
            vendorInformation: alert.vendorInformation?.provider || 'Unknown'
        }));

        console.log(`[Devices Dashboard] Successfully compiled device data: ${totalDevices} devices, ${processedAlerts.length} alerts`);

        const dashboardPayload = {
            success: true,
            tenant: tenant.clientId,
            fetchedAt: new Date().toISOString(),
            summary: {
                totalDevices,
                compliantDevices,
                encryptedDevices,
                registeredDevices,
                staleDevices: activityBreakdown.stale7days,
                highRiskDevices: highRiskDevices.length,
                compliancePercentage: totalDevices > 0 ? Math.round((compliantDevices / totalDevices) * 100) : 0,
                encryptionPercentage: totalDevices > 0 ? Math.round((encryptedDevices / totalDevices) * 100) : 0,
                deviceSecurityScore,
                securityAlerts: processedAlerts.length
            },
            devices: processedDevices,
            compliance: complianceBreakdown,
            osDistribution,
            managementStatus,
            activityBreakdown,
            highRiskDevices: highRiskDevices.slice(0, 10),
            alerts: processedAlerts,
            policies: policies.slice(0, 10),
            warnings: [...new Set(normalizedAlertPayload.warnings)]
        };

        if (deviceEvidenceService && tenant.companyId) {
            deviceEvidenceService.persistProcessedEvidence({
                companyId: tenant.companyId,
                tenantKey: tenant.clientId,
                payload: dashboardPayload,
                collectionTrigger: 'dashboard_request',
                sourceEndpoint: '/api/microsoft-devices'
            }).catch(error => {
                console.warn('[Device Evidence] Dashboard response could not be stored:', error.message);
            });
        }

        res.json(dashboardPayload);

    } catch (error) {
        console.error('[Devices Dashboard] Error:', error.message);
        
        res.status(500).json({ 
            error: 'Failed to fetch devices dashboard data',
            message: error.message
        });
    }
});

// ====================================================================================================//
//                         MICROSOFT GRAPH - Threat & Activity (SOC)                                  //
// ====================================================================================================//

const SECURITY_ALERTS_FETCH_TIMEOUT_MS = Math.max(
    30000,
    Number(process.env.SECURITY_ALERTS_FETCH_TIMEOUT_MS) || 60000
);

const SECURITY_INCIDENTS_FETCH_TIMEOUT_MS = Math.max(
    30000,
    Number(process.env.SECURITY_INCIDENTS_FETCH_TIMEOUT_MS) || 60000
);

const THREAT_INDICATORS_FETCH_TIMEOUT_MS = Math.max(
    10000,
    Number(process.env.THREAT_INDICATORS_FETCH_TIMEOUT_MS) || 20000
);

const SECURITY_SIGNINS_FETCH_TIMEOUT_MS = Math.max(
    30000,
    Number(process.env.SECURITY_SIGNINS_FETCH_TIMEOUT_MS) || 60000
);

const SECURITY_ALERTS_PIPELINE_TIMEOUT_MS = Math.max(
    120000,
    Number(process.env.SECURITY_ALERTS_PIPELINE_TIMEOUT_MS) || 180000
);

function graphAbortMessage(error, timeoutMs, label) {
    if (error?.name === 'AbortError' || /aborted/i.test(String(error?.message || ''))) {
        return `${label} timed out after ${timeoutMs}ms`;
    }
    return error?.message || String(error || `${label} failed`);
}

async function fetchGraphJsonWithTimeout({
    url,
    token,
    timeoutMs,
    stage,
    label,
    optional = false,
    expectedUnavailableStatuses = []
}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => {
        console.warn(`[security_alerts:${stage}:timeout] ${label} exceeded ${timeoutMs}ms`);
        controller.abort();
    }, timeoutMs);

    try {
        console.log(`[security_alerts:${stage}:start] ${label}...`);

        const response = await fetch(url, {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            signal: controller.signal
        });

        if (expectedUnavailableStatuses.includes(response.status)) {
            console.log(`[security_alerts:${stage}:optional_unavailable] ${label} returned ${response.status}; continuing.`);
            return {
                ok: false,
                optional,
                unavailable: true,
                status: response.status,
                value: [],
                warnings: [`${label} unavailable: Microsoft Graph returned ${response.status}`],
                recordsFetched: 0
            };
        }

        if (!response.ok) {
            const body = await response.text().catch(() => '');
            const message = body
                ? `${label} returned ${response.status}: ${body.slice(0, 300)}`
                : `${label} returned ${response.status}`;

            if (optional) {
                console.warn(`[security_alerts:${stage}:optional_http_error] ${message}`);
                return {
                    ok: false,
                    optional,
                    status: response.status,
                    value: [],
                    warnings: [message],
                    recordsFetched: 0
                };
            }

            console.warn(`[security_alerts:${stage}:http_error] ${message}`);
            return {
                ok: false,
                optional,
                status: response.status,
                value: [],
                warnings: [message],
                recordsFetched: 0
            };
        }

        const data = await response.json();
        const value = Array.isArray(data?.value) ? data.value : [];

        console.log(`[security_alerts:${stage}:complete] ${label} retrieved ${value.length} record(s).`);

        return {
            ok: true,
            optional,
            status: response.status,
            value,
            warnings: [],
            recordsFetched: value.length
        };
    } catch (error) {
        const message = graphAbortMessage(error, timeoutMs, label);

        if (optional) {
            console.warn(`[security_alerts:${stage}:optional_error] ${message}`);
            return {
                ok: false,
                optional,
                aborted: error?.name === 'AbortError' || /aborted/i.test(String(error?.message || '')),
                value: [],
                warnings: [`${label} unavailable: ${message}`],
                recordsFetched: 0
            };
        }

        console.error(`[security_alerts:${stage}:error] ${message}`);
        return {
            ok: false,
            optional,
            aborted: error?.name === 'AbortError' || /aborted/i.test(String(error?.message || '')),
            value: [],
            warnings: [`${label} failed: ${message}`],
            recordsFetched: 0
        };
    } finally {
        clearTimeout(timeout);
    }
}

async function fetchSecurityAlertRows(token) {
    const result = await fetchGraphJsonWithTimeout({
        url: 'https://graph.microsoft.com/v1.0/security/alerts?$top=50&$orderby=createdDateTime desc',
        token,
        timeoutMs: SECURITY_ALERTS_FETCH_TIMEOUT_MS,
        stage: 'microsoft_graph_alerts_fetch',
        label: 'Alerts fetch'
    });

    return {
        alerts: result.value,
        warnings: result.warnings,
        recordsFetched: result.recordsFetched,
        ok: result.ok,
        status: result.status,
        aborted: result.aborted || false
    };
}

async function fetchSecurityIncidentRows(token) {
    const result = await fetchGraphJsonWithTimeout({
        url: 'https://graph.microsoft.com/v1.0/security/incidents?$top=50&$orderby=createdDateTime desc',
        token,
        timeoutMs: SECURITY_INCIDENTS_FETCH_TIMEOUT_MS,
        stage: 'microsoft_graph_incidents_fetch',
        label: 'Incidents fetch'
    });

    return {
        incidents: result.value,
        warnings: result.warnings,
        recordsFetched: result.recordsFetched,
        ok: result.ok,
        status: result.status,
        aborted: result.aborted || false
    };
}

async function fetchSecurityThreatIndicatorRows(token) {
    const result = await fetchGraphJsonWithTimeout({
        url: 'https://graph.microsoft.com/v1.0/security/tiIndicators?$top=50&$orderby=createdDateTime desc',
        token,
        timeoutMs: THREAT_INDICATORS_FETCH_TIMEOUT_MS,
        stage: 'threat_indicators_fetch',
        label: 'Threat indicators',
        optional: true,
        expectedUnavailableStatuses: [400, 403, 404]
    });

    return {
        threats: result.value,
        warnings: result.warnings,
        recordsFetched: result.recordsFetched,
        ok: result.ok,
        status: result.status,
        aborted: result.aborted || false,
        optional: true
    };
}

async function fetchSecuritySignInRows(token) {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const filter = `createdDateTime ge ${thirtyDaysAgo.toISOString().split('T')[0]}`;
    const select = [
        'id',
        'createdDateTime',
        'userPrincipalName',
        'userId',
        'appDisplayName',
        'clientAppUsed',
        'ipAddress',
        'location',
        'deviceDetail',
        'status',
        'riskDetail',
        'riskLevelAggregated',
        'riskLevelDuringSignIn',
        'riskState'
    ].join(',');

    const result = await fetchGraphJsonWithTimeout({
        url: `https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=${encodeURIComponent(filter)}&$top=100&$orderby=createdDateTime desc&$select=${encodeURIComponent(select)}`,
        token,
        timeoutMs: SECURITY_SIGNINS_FETCH_TIMEOUT_MS,
        stage: 'security_signins_fetch',
        label: 'Sign-ins fetch'
    });

    return {
        signIns: result.value,
        warnings: result.warnings,
        recordsFetched: result.recordsFetched,
        ok: result.ok,
        status: result.status,
        aborted: result.aborted || false
    };
}

function normalizeSecuritySeverity(value) {
    return String(value || 'medium').toLowerCase();
}

function normalizeSecurityStatus(value) {
    return String(value || 'newAlert').toLowerCase();
}

function getSecurityEventTime(item) {
    return item?.created || item?.createdDateTime || item?.eventTime || item?.timestamp || item?.updated || new Date().toISOString();
}

function getSecuritySeverityRank(value) {
    return { critical: 5, high: 4, medium: 3, low: 2, informational: 1, info: 1 }[String(value || '').toLowerCase()] || 0;
}

function getSecurityMitreMapping(item = {}) {
    const text = `${item.title || ''} ${item.displayName || ''} ${item.description || ''} ${item.category || ''} ${item.failureReason || ''} ${item.riskLevel || ''}`.toLowerCase();

    if (/phish|credential|password|spray|brute/.test(text)) {
        return { tactic: 'Credential Access', technique: 'Phishing / Password Attack' };
    }

    if (/anonymous|tor|proxy|vpn|impossible|risky sign/.test(text)) {
        return { tactic: 'Initial Access', technique: 'Suspicious Sign-in Infrastructure' };
    }

    if (/malware|trojan|ransomware|virus/.test(text)) {
        return { tactic: 'Execution', technique: 'Malware Execution' };
    }

    if (/inbox rule|forwarding|mailbox/.test(text)) {
        return { tactic: 'Collection', technique: 'Email Collection' };
    }

    return { tactic: 'Security Monitoring', technique: 'Alert / Incident Review' };
}

function countSecurityGroups(rows, getter) {
    const grouped = {};

    for (const row of Array.isArray(rows) ? rows : []) {
        const key = getter(row) || 'Unknown';
        grouped[key] = (grouped[key] || 0) + 1;
    }

    return Object.entries(grouped)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count);
}

function extractInternalSecurityThreatIndicators({ alerts = [], incidents = [], signIns = [] } = {}) {
    const indicators = new Map();

    function add(type, value, source = {}, confidence = 'medium') {
        if (value === null || value === undefined || value === '') return;

        const cleanValue = String(value).trim().slice(0, 500);
        if (!cleanValue) return;

        const key = `${type}:${cleanValue}`.toLowerCase();

        const existing = indicators.get(key) || {
            id: key,
            indicator: cleanValue,
            value: cleanValue,
            type,
            indicatorType: type,
            severity: normalizeSecuritySeverity(source.severity || source.riskLevel || 'medium'),
            action: 'Review',
            confidence,
            source: 'internal_security_alerts',
            description: 'Extracted from Security Alerts evidence because external threat indicators were unavailable.',
            created: getSecurityEventTime(source),
            relatedAlerts: [],
            relatedUsers: [],
            relatedDevices: [],
            occurrenceCount: 0
        };

        existing.occurrenceCount += 1;

        const alertTitle = source.title || source.alertName || source.displayName || source.name;
        const user = source.user || source.userPrincipalName || source.userEmail || source.mail || source.email;
        const device = source.deviceName || source.hostName || source.hostname || source.machineName || source.computerName;

        if (alertTitle && !existing.relatedAlerts.includes(alertTitle)) existing.relatedAlerts.push(alertTitle);
        if (user && !existing.relatedUsers.includes(user)) existing.relatedUsers.push(user);
        if (device && !existing.relatedDevices.includes(device)) existing.relatedDevices.push(device);

        existing.relatedAlerts = existing.relatedAlerts.slice(0, 5);
        existing.relatedUsers = existing.relatedUsers.slice(0, 5);
        existing.relatedDevices = existing.relatedDevices.slice(0, 5);

        indicators.set(key, existing);
    }

    for (const row of [...alerts, ...incidents, ...signIns]) {
        if (!row || typeof row !== 'object') continue;

        add('IPAddress', row.ipAddress || row.clientIpAddress || row.sourceIpAddress || row.ip, row, 'high');
        add('UserPrincipalName', row.userPrincipalName || row.userEmail || row.mail || row.email || row.user, row);
        add('DeviceName', row.deviceName || row.hostName || row.hostname || row.machineName || row.computerName, row);
        add('AlertTitle', row.title || row.alertName || row.displayName || row.name, row);
        add('RiskType', row.riskType || row.riskLevel || row.riskLevelDuringSignIn || row.riskDetail || row.category || row.classification, row);

        const serialized = JSON.stringify(row).slice(0, 12000);

        for (const ip of serialized.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || []) {
            add('IPAddress', ip, row, 'high');
        }

        for (const url of serialized.match(/\bhttps?:\/\/[^\s"'<>]+/gi) || []) {
            add('URL', url.replace(/[),.;]+$/g, ''), row, 'high');
        }

        for (const hash of serialized.match(/\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi) || []) {
            add('FileHash', hash, row, 'high');
        }

        for (const email of serialized.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || []) {
            add('UserPrincipalName', email, row);
        }

        const keywords = serialized.match(/\b(?:malware|phishing|phish|ransomware|trojan|credential theft|bec|spoof|impossible travel|anonymous ip|risky sign[-\s]?in|brute force|password spray|suspicious inbox rule)\b/gi) || [];
        for (const keyword of keywords.slice(0, 10)) {
            add('ThreatKeyword', keyword, row);
        }
    }

    return [...indicators.values()]
        .sort((a, b) => b.occurrenceCount - a.occurrenceCount)
        .slice(0, 25);
}

function cleanSecurityCollectionWarnings(warnings = [], { alerts = [], incidents = [], signIns = [], threats = [] } = {}) {
    const hasAlerts = alerts.length > 0;
    const hasIncidents = incidents.length > 0;
    const hasSignIns = signIns.length > 0;
    const hasThreats = threats.length > 0;
    const hasPrimaryEvidence = hasAlerts || hasIncidents || hasSignIns;

    return [...new Set((Array.isArray(warnings) ? warnings : [])
        .map(warning => String(warning || '').trim())
        .filter(Boolean))]
        .filter(warning => {
            const lower = warning.toLowerCase();

            if (lower.includes('threat indicators')) {
                return !hasThreats;
            }

            if (lower.includes('alerts fetch failed') || lower.includes('alerts_unavailable')) {
                return !hasAlerts;
            }

            if (lower.includes('incidents fetch failed') || lower.includes('incidents_unavailable')) {
                return !hasIncidents;
            }

            if (lower.includes('sign-ins fetch failed') || lower.includes('signins_unavailable')) {
                return !hasSignIns;
            }

            if (lower.includes('partial_source_collection')) {
                return !hasPrimaryEvidence;
            }

            return true;
        });
}

const sentWhatsAppSecurityAlertKeys = new Set();
const MAX_WHATSAPP_SECURITY_ALERT_KEYS = 500;

async function readWhatsAppConfigValue(name, fallback = null) {
    if (process.env[name]) return process.env[name];
    return await getSecret(name) || fallback;
}

async function readFirstWhatsAppConfigValue(names, fallback = null) {
    for (const name of names) {
        const value = await readWhatsAppConfigValue(name);
        if (value) return value;
    }
    return fallback;
}

async function getWhatsAppSecurityAlertConfig({ requireEnabled = false } = {}) {
    try {
        const [
            enabledValue,
            token,
            phoneNumberId,
            recipientValue,
            apiVersion,
            templateName,
            templateLanguage,
            limitValue
        ] = await Promise.all([
            readWhatsAppConfigValue('WHATSAPP_SECURITY_ALERTS_ENABLED', 'false'),
            readWhatsAppConfigValue('WHATSAPP_ACCESS_TOKEN'),
            readWhatsAppConfigValue('WHATSAPP_PHONE_NUMBER_ID'),
            readFirstWhatsAppConfigValue(['WHATSAPP_SECURITY_ALERT_RECIPIENT', 'WHATSAPP_RECIPIENT'], '27762609804'),
            readWhatsAppConfigValue('WHATSAPP_GRAPH_VERSION', 'v25.0'),
            readWhatsAppConfigValue('WHATSAPP_SECURITY_ALERT_TEMPLATE', 'security_alert'),
            readFirstWhatsAppConfigValue(['WHATSAPP_SECURITY_ALERT_TEMPLATE_LANGUAGE', 'WHATSAPP_TEMPLATE_LANGUAGE'], 'en_US'),
            readWhatsAppConfigValue('WHATSAPP_SECURITY_ALERT_LIMIT', '20')
        ]);

        const enabled = String(enabledValue || 'false').toLowerCase() === 'true';
        if (!enabledValue) {
            console.log('[security_alerts:whatsapp_security_alerts_enabled_missing_default_false] WHATSAPP_SECURITY_ALERTS_ENABLED not found, defaulting to false');
        }
        if (requireEnabled && !enabled) return { enabled: false };

        const recipient = normalizeWhatsAppRecipient(recipientValue);
        const limit = Math.max(1, Number(limitValue || 20));

        return { enabled, token, phoneNumberId, recipient, apiVersion, templateName, templateLanguage, limit };
    } catch (error) {
        console.warn('[security_alerts:whatsapp_config_error] Failed to read WhatsApp config, defaulting to disabled:', error.message);
        return { enabled: false };
    }
}

function getWhatsAppSecurityAlertTime(item = {}) {
    return item.eventTime || item.timestamp || item.created || item.updated || item.createdDateTime || new Date().toISOString();
}

function getWhatsAppSecurityAlertKey(item = {}) {
    const stableId = item.id || item.uid || item.alertId || item.incidentId;
    if (stableId) return `${item.recordType || item.type || 'security'}:${stableId}`;
    return `${item.recordType || item.type || 'security'}:${item.title || item.displayName || item.name}:${getWhatsAppSecurityAlertTime(item)}`;
}

function rememberWhatsAppSecurityAlertKey(key) {
    sentWhatsAppSecurityAlertKeys.add(key);
    if (sentWhatsAppSecurityAlertKeys.size <= MAX_WHATSAPP_SECURITY_ALERT_KEYS) return;
    const firstKey = sentWhatsAppSecurityAlertKeys.values().next().value;
    sentWhatsAppSecurityAlertKeys.delete(firstKey);
}

function getWhatsAppSecurityAlertCandidates(payload = {}) {
    const alerts = (payload.alerts || []).map(alert => ({
        ...alert,
        recordType: 'alert',
        issue: alert.title || alert.name || 'Security alert',
        assignedTo: alert.assignedTo || alert.owner || 'Unassigned',
        timestamp: getWhatsAppSecurityAlertTime(alert)
    }));
    const incidents = (payload.incidents || []).map(incident => ({
        ...incident,
        recordType: 'incident',
        issue: incident.displayName || incident.title || 'Security incident',
        assignedTo: incident.assignedTo || 'Unassigned',
        timestamp: getWhatsAppSecurityAlertTime(incident),
        source: incident.source || 'Microsoft Security Incident'
    }));

    return [...alerts, ...incidents]
        .map(item => ({ ...item, severity: normalizeWhatsAppSeverity(item.severity) }))
        .sort((a, b) => new Date(getWhatsAppSecurityAlertTime(b)) - new Date(getWhatsAppSecurityAlertTime(a)));
}

async function notifySecurityAlertsViaWhatsApp(payload, options = {}) {
    const config = await getWhatsAppSecurityAlertConfig({ requireEnabled: options.requireEnabled });
    if (options.requireEnabled && !config.enabled) {
        return { enabled: false, sent: 0, skipped: 0, failed: 0, results: [] };
    }
    if (!config.token || !config.phoneNumberId) {
        throw new Error('WhatsApp credentials are missing. Configure WHATSAPP_ACCESS_TOKEN and WHATSAPP_PHONE_NUMBER_ID.');
    }

    const severities = new Set((options.severities || ['critical', 'high', 'medium', 'low']).map(normalizeWhatsAppSeverity));
    const limit = Math.max(1, Number(options.limit || config.limit || 20));
    const types = new Set((options.types || ['alert', 'incident']).map(type => String(type || '').toLowerCase()));
    const candidates = getWhatsAppSecurityAlertCandidates(payload)
        .filter(item => types.has(String(item.recordType || item.type || '').toLowerCase()))
        .filter(item => severities.has(normalizeWhatsAppSeverity(item.severity)))
        .slice(0, limit);

    const results = [];
    for (const alert of candidates) {
        const key = getWhatsAppSecurityAlertKey(alert);
        if (!options.force && sentWhatsAppSecurityAlertKeys.has(key)) {
            results.push({ key, issue: alert.issue, severity: alert.severity, status: 'skipped-duplicate' });
            continue;
        }

        try {
            const response = await sendSecurityAlert(alert, config);
            rememberWhatsAppSecurityAlertKey(key);
            results.push({
                key,
                issue: alert.issue,
                severity: alert.severity,
                status: 'sent',
                recipient: response.recipient || config.recipient,
                messageId: response.messages?.[0]?.id || null,
                response
            });
        } catch (error) {
            const detail = error.response?.data || error.message;
            console.error('[WhatsApp Security Alerts] Failed to send alert:', detail);
            results.push({ key, issue: alert.issue, severity: alert.severity, status: 'failed', error: detail });
        }
    }

    return {
        enabled: config.enabled,
        recipient: config.recipient,
        sent: results.filter(item => item.status === 'sent').length,
        skipped: results.filter(item => item.status === 'skipped-duplicate').length,
        failed: results.filter(item => item.status === 'failed').length,
        results
    };
}

async function buildSecurityEventsPayloadFromApi(options = {}) {
    console.log('[security_alerts:start] Security Alerts domain processing starting');

    const allMetrics = {
        recordsFetched: 0,
        recordsStored: 0,
        recordsPrepared: 0,
        recordsSentToAzure: 0,
        recordsAnalysed: 0,
        recordsOmitted: 0,
        omittedReasons: []
    };

    const stages = [{ stage: 'security_alerts:start', status: 'complete', at: new Date().toISOString() }];

    let token;

    try {
        token = options.token || await getMicrosoftGraphToken({ securityAlerts: true });
        stages.push({
            stage: 'graph_credentials:complete_or_failed',
            status: 'complete',
            at: new Date().toISOString()
        });
    } catch (error) {
        stages.push({
            stage: 'graph_credentials:complete_or_failed',
            status: 'failed_terminal',
            reason: error.message,
            at: new Date().toISOString()
        });

        console.error('[security_alerts:complete_or_completed_with_warnings_or_failed] failed_terminal:', error.message);

        error.securityAlertsStatus = 'failed_terminal';
        error.securityAlertsStage = 'graph_credentials';
        error.securityAlertsStages = stages;
        throw error;
    }

    console.log('[security_alerts:prepare_fetch:start] Preparing to fetch from 4 Microsoft Graph sources');

    const sourceSettled = await Promise.allSettled([
        fetchSecurityAlertRows(token),
        fetchSecurityIncidentRows(token),
        fetchSecurityThreatIndicatorRows(token),
        fetchSecuritySignInRows(token)
    ]);

    function resolvedSource(index, fallback) {
        const settled = sourceSettled[index];

        if (settled.status === 'fulfilled') return settled.value;

        const message = settled.reason?.message || String(settled.reason || 'Unknown source failure');

        return {
            ...fallback,
            warnings: [`${fallback.label || 'Source'} failed: ${message}`],
            recordsFetched: 0,
            ok: false
        };
    }

    const alertsResult = resolvedSource(0, { label: 'Alerts fetch', alerts: [] });
    const incidentsResult = resolvedSource(1, { label: 'Incidents fetch', incidents: [] });
    const threatIndicatorsResult = resolvedSource(2, { label: 'Threat indicators', threats: [], optional: true });
    const signInsResult = resolvedSource(3, { label: 'Sign-ins fetch', signIns: [] });

    stages.push(
        {
            stage: 'microsoft_graph_alerts_fetch:complete_or_timeout',
            status: alertsResult.warnings?.length ? 'warning' : 'complete',
            recordsFetched: alertsResult.recordsFetched || 0,
            at: new Date().toISOString()
        },
        {
            stage: 'microsoft_graph_incidents_fetch:complete_or_timeout',
            status: incidentsResult.warnings?.length ? 'warning' : 'complete',
            recordsFetched: incidentsResult.recordsFetched || 0,
            at: new Date().toISOString()
        },
        {
            stage: 'threat_indicators_fetch:warning_or_complete',
            status: threatIndicatorsResult.warnings?.length ? 'warning' : 'complete',
            recordsFetched: threatIndicatorsResult.recordsFetched || 0,
            at: new Date().toISOString()
        },
        {
            stage: 'security_signins_fetch:complete_or_timeout',
            status: signInsResult.warnings?.length ? 'warning' : 'complete',
            recordsFetched: signInsResult.recordsFetched || 0,
            at: new Date().toISOString()
        }
    );

    const alerts = Array.isArray(alertsResult.alerts) ? alertsResult.alerts : [];
    const incidents = Array.isArray(incidentsResult.incidents) ? incidentsResult.incidents : [];
    const externalThreatIndicators = Array.isArray(threatIndicatorsResult.threats) ? threatIndicatorsResult.threats : [];
    const signIns = Array.isArray(signInsResult.signIns) ? signInsResult.signIns : [];

    allMetrics.recordsFetched =
        (alertsResult.recordsFetched || 0) +
        (incidentsResult.recordsFetched || 0) +
        (threatIndicatorsResult.recordsFetched || 0) +
        (signInsResult.recordsFetched || 0);

    stages.push({
        stage: 'evidence_prepare:start',
        status: 'started',
        at: new Date().toISOString()
    });

    console.log(`[security_alerts:evidence_prepare:start] Preparing evidence: ${alerts.length} alerts, ${incidents.length} incidents, ${externalThreatIndicators.length} external threats, ${signIns.length} sign-ins`);

    const processedAlerts = alerts.map(alert => ({
        id: alert.id,
        title: alert.title || alert.alertName || alert.displayName || 'Unknown Alert',
        description: alert.description || '',
        severity: normalizeSecuritySeverity(alert.severity),
        status: normalizeSecurityStatus(alert.status),
        created: alert.createdDateTime || new Date().toISOString(),
        eventTime: alert.eventDateTime || alert.createdDateTime || new Date().toISOString(),
        category: alert.category || alert.serviceSource || alert.classification || 'Other',
        vendor: alert.vendorInformation?.provider || alert.serviceSource || 'Microsoft',
        source: alert.serviceSource || alert.vendorInformation?.provider || 'Microsoft Security',
        user: (alert.userStates || [])[0]?.accountName ||
            alert.userPrincipalName ||
            alert.assignedTo ||
            'Unknown user',
        ipAddress: alert.ipAddress || alert.clientIpAddress || alert.sourceIpAddress || null,
        deviceName: alert.deviceName || alert.hostName || alert.hostname || null
    }));

    const processedIncidents = incidents.map(incident => ({
        id: incident.id,
        displayName: incident.displayName || incident.title || 'Unknown Incident',
        description: incident.description || '',
        severity: normalizeSecuritySeverity(incident.severity),
        status: normalizeSecurityStatus(incident.status || 'active'),
        created: incident.createdDateTime || new Date().toISOString(),
        updated: incident.lastUpdateDateTime || incident.lastUpdatedDateTime || new Date().toISOString(),
        assignedTo: incident.assignedTo || 'Unassigned',
        redirectUrl: incident.incidentUrl || incident.webUrl || '#'
    }));

    const suspiciousSignIns = signIns
        .filter(signIn => {
            const riskLevel = signIn.riskLevelDuringSignIn || signIn.riskLevelAggregated || signIn.riskState;
            const status = signIn.status?.errorCode === 0 ? 'Success' : 'Failed';
            return (riskLevel && !['none', 'hidden', 'unknownfuturevalue'].includes(String(riskLevel).toLowerCase())) || status === 'Failed';
        })
        .map(signIn => ({
            id: signIn.id,
            user: signIn.userPrincipalName || 'Unknown',
            userPrincipalName: signIn.userPrincipalName || 'Unknown',
            timestamp: signIn.createdDateTime || new Date().toISOString(),
            ipAddress: signIn.ipAddress || 'Unknown',
            location: signIn.location?.city
                ? `${signIn.location.city}, ${signIn.location.countryOrRegion}`
                : (signIn.location?.countryOrRegion || 'Unknown Location'),
            country: signIn.location?.countryOrRegion || 'Unknown',
            riskLevel: signIn.riskLevelDuringSignIn || signIn.riskLevelAggregated || signIn.riskState || 'none',
            status: signIn.status?.errorCode === 0 ? 'Success' : 'Failed',
            errorCode: signIn.status?.errorCode || 0,
            failureReason: signIn.status?.failureReason || (signIn.status?.errorCode ? `Sign-in error ${signIn.status.errorCode}` : 'Suspicious sign-in')
        }));

    const externalThreats = externalThreatIndicators.map(threat => ({
        id: threat.id,
        indicator: threat.networkIPv4 || threat.networkIPv6 || threat.domainName || threat.fileHashValue || threat.url || 'Unknown',
        value: threat.networkIPv4 || threat.networkIPv6 || threat.domainName || threat.fileHashValue || threat.url || 'Unknown',
        type: threat.networkIPv4
            ? 'IPv4'
            : threat.networkIPv6
                ? 'IPv6'
                : threat.domainName
                    ? 'Domain'
                    : threat.url
                        ? 'URL'
                        : 'FileHash',
        indicatorType: threat.networkIPv4
            ? 'IPv4'
            : threat.networkIPv6
                ? 'IPv6'
                : threat.domainName
                    ? 'Domain'
                    : threat.url
                        ? 'URL'
                        : 'FileHash',
        severity: normalizeSecuritySeverity(threat.severity),
        action: threat.targetProduct || threat.action || 'Block',
        description: threat.description || 'External threat indicator from Microsoft Graph',
        created: threat.createdDateTime || new Date().toISOString(),
        source: 'microsoft_graph_tiIndicators',
        confidence: threat.confidence || 'medium'
    }));

    const internalThreats = extractInternalSecurityThreatIndicators({
        alerts: processedAlerts,
        incidents: processedIncidents,
        signIns: suspiciousSignIns
    });

    const threatMap = new Map();

    for (const threat of [...externalThreats, ...internalThreats]) {
        const key = `${threat.type || threat.indicatorType || 'Indicator'}:${threat.indicator || threat.value || threat.id}`.toLowerCase();
        if (!threatMap.has(key)) threatMap.set(key, threat);
    }

    const processedThreats = [...threatMap.values()];

    let rawWarnings = [
        ...(alertsResult.warnings || []),
        ...(incidentsResult.warnings || []),
        ...(threatIndicatorsResult.warnings || []),
        ...(signInsResult.warnings || [])
    ];

    rawWarnings = cleanSecurityCollectionWarnings(rawWarnings, {
        alerts: processedAlerts,
        incidents: processedIncidents,
        signIns: suspiciousSignIns,
        threats: processedThreats
    });

    const hasPrimaryEvidence = Boolean(processedAlerts.length || processedIncidents.length || suspiciousSignIns.length);

    const allWarnings = [...new Set([
        ...(!hasPrimaryEvidence && rawWarnings.length ? ['partial_source_collection'] : []),
        ...rawWarnings
    ])];

    const activeIncidents = processedIncidents.filter(i => ['active', 'inprogress', 'new', 'open', 'newalert'].includes(i.status));
    const highSeverityAlerts = processedAlerts.filter(a => ['critical', 'high'].includes(a.severity));

    const userFailureMap = {};

    suspiciousSignIns.forEach(signIn => {
        if (signIn.status === 'Failed') {
            userFailureMap[signIn.user] = (userFailureMap[signIn.user] || 0) + 1;
        }
    });

    const usersUnderAttack = Object.entries(userFailureMap)
        .filter(([, count]) => count >= 3)
        .map(([user, failedAttempts]) => ({ user, failedAttempts }))
        .sort((a, b) => b.failedAttempts - a.failedAttempts)
        .slice(0, 10);

    const severityScores = { critical: 25, high: 15, medium: 5, low: 2 };
    let securityScore = 100;

    processedThreats.forEach(threat => { securityScore -= severityScores[threat.severity] || 2; });
    processedAlerts.slice(0, 20).forEach(alert => { securityScore -= severityScores[alert.severity] || 2; });
    usersUnderAttack.forEach(user => { securityScore -= user.failedAttempts * 2; });

    securityScore = Math.max(0, Math.min(100, securityScore));

    const activityFeed = [
        ...processedIncidents.slice(0, 8).map(incident => ({
            type: 'incident',
            message: `${incident.severity.toUpperCase()} Incident: ${incident.displayName}`,
            timestamp: incident.created,
            severity: incident.severity
        })),
        ...highSeverityAlerts.slice(0, 8).map(alert => ({
            type: 'alert',
            message: `${alert.severity.toUpperCase()}: ${alert.title}`,
            timestamp: alert.created,
            severity: alert.severity
        })),
        ...suspiciousSignIns.slice(0, 8).map(signIn => ({
            type: 'signin',
            message: `${signIn.status} sign-in: ${signIn.user} from ${signIn.location}`,
            timestamp: signIn.timestamp,
            severity: signIn.status === 'Failed' ? 'medium' : 'low'
        }))
    ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    const allSecurityEvents = [
        ...processedAlerts.map(alert => ({
            ...alert,
            recordType: 'alert',
            name: alert.title,
            timestamp: getSecurityEventTime(alert)
        })),
        ...processedIncidents.map(incident => ({
            ...incident,
            recordType: 'incident',
            name: incident.displayName,
            timestamp: getSecurityEventTime(incident)
        })),
        ...suspiciousSignIns.map(signIn => ({
            ...signIn,
            recordType: 'signin',
            name: `${signIn.status} sign-in`,
            severity: signIn.status === 'Failed' ? 'medium' : 'low',
            timestamp: signIn.timestamp
        })),
        ...processedThreats.map(threat => ({
            ...threat,
            recordType: 'indicator',
            name: threat.indicator || threat.value,
            timestamp: getSecurityEventTime(threat)
        }))
    ];

    const mitreMap = {};

    allSecurityEvents.forEach(event => {
        const mapping = getSecurityMitreMapping(event);
        const key = `${mapping.tactic}::${mapping.technique}`;

        if (!mitreMap[key]) {
            mitreMap[key] = {
                tactic: mapping.tactic,
                technique: mapping.technique,
                count: 0,
                severity: 'low',
                evidence: []
            };
        }

        mitreMap[key].count += 1;

        if (getSecuritySeverityRank(event.severity) > getSecuritySeverityRank(mitreMap[key].severity)) {
            mitreMap[key].severity = event.severity || 'medium';
        }

        mitreMap[key].evidence.push({
            title: event.name || event.title || event.displayName || 'Security event',
            subtitle: event.user || event.source || event.location || event.category || 'Microsoft Security',
            timestamp: event.timestamp || getSecurityEventTime(event),
            severity: event.severity || 'medium'
        });

        mitreMap[key].evidence = mitreMap[key].evidence.slice(0, 10);
    });

    const alertUsers = processedAlerts
        .map(alert => alert.user)
        .filter(user => user && user !== 'Unknown user')
        .map(user => ({ user, signal: 'alert' }));

    const signInUsers = suspiciousSignIns.map(signIn => ({ user: signIn.user, signal: 'sign-in' }));
    const targetedCounts = {};

    [...alertUsers, ...signInUsers].forEach(item => {
        targetedCounts[item.user] = targetedCounts[item.user] || {
            user: item.user,
            alerts: 0,
            signIns: 0,
            total: 0,
            evidence: []
        };

        targetedCounts[item.user].total += 1;
        if (item.signal === 'alert') targetedCounts[item.user].alerts += 1;
        if (item.signal === 'sign-in') targetedCounts[item.user].signIns += 1;
    });

    processedAlerts.forEach(alert => {
        if (!targetedCounts[alert.user]) return;
        targetedCounts[alert.user].evidence.push({
            title: alert.title,
            subtitle: alert.category || alert.source || 'Security alert',
            timestamp: alert.created,
            severity: alert.severity
        });
    });

    suspiciousSignIns.forEach(signIn => {
        if (!targetedCounts[signIn.user]) return;
        targetedCounts[signIn.user].evidence.push({
            title: signIn.failureReason || 'Suspicious sign-in',
            subtitle: `${signIn.ipAddress} | ${signIn.location}`,
            timestamp: signIn.timestamp,
            severity: signIn.status === 'Failed' ? 'medium' : 'low'
        });
    });

    const topTargetedUsers = Object.values(targetedCounts)
        .map(user => ({ ...user, evidence: user.evidence.slice(0, 5) }))
        .sort((a, b) => b.total - a.total)
        .slice(0, 15);

    const sourceDistribution = countSecurityGroups(processedAlerts, alert => alert.source || alert.vendor || 'Microsoft Security');
    const categoryDistribution = countSecurityGroups(processedAlerts, alert => alert.category || 'Other');
    const regionDistribution = countSecurityGroups(suspiciousSignIns, signIn => signIn.country || signIn.location || 'Unknown');

    const attackTimeline = allSecurityEvents
        .sort((a, b) => new Date(b.timestamp || getSecurityEventTime(b)) - new Date(a.timestamp || getSecurityEventTime(a)))
        .slice(0, 50)
        .map(event => ({
            type: event.recordType,
            title: event.name || event.title || event.displayName || 'Security event',
            subtitle: event.user || event.source || event.location || event.category || 'Microsoft Security',
            timestamp: event.timestamp || getSecurityEventTime(event),
            severity: event.severity || 'medium',
            mitre: getSecurityMitreMapping(event)
        }));

    const highRiskSignals = highSeverityAlerts.length + activeIncidents.length + usersUnderAttack.length;

    const aiSummary = highRiskSignals > 0
        ? `Security attention is required. ${highSeverityAlerts.length} high or critical alert(s), ${activeIncidents.length} active incident(s), and ${usersUnderAttack.length} user attack pattern(s) were found.`
        : hasPrimaryEvidence
            ? 'Security posture is currently stable across available Microsoft security signals.'
            : 'Security posture could not be fully assessed because primary Security Alerts evidence was unavailable.';

    const recommendations = [
        highSeverityAlerts.length
            ? {
                priority: 'critical',
                title: 'Review high severity alerts',
                detail: `${highSeverityAlerts.length} high or critical alert(s) need analyst review.`
            }
            : null,
        usersUnderAttack.length
            ? {
                priority: 'high',
                title: 'Investigate repeated suspicious sign-ins',
                detail: `${usersUnderAttack.length} user(s) show repeated failed or risky access attempts.`
            }
            : null,
        activeIncidents.length
            ? {
                priority: 'high',
                title: 'Triage active incidents',
                detail: `${activeIncidents.length} active incident(s) are still open.`
            }
            : null,
        processedThreats.length
            ? {
                priority: 'medium',
                title: 'Validate threat indicators',
                detail: `${processedThreats.length} threat indicator(s) were extracted from Security Alerts evidence.`
            }
            : null,
        {
            priority: highRiskSignals ? 'medium' : 'low',
            title: 'Keep cached SOC data fresh',
            detail: 'The dashboard reads cached security evidence first and refreshes through the backend Graph connector.'
        }
    ].filter(Boolean);

    const payload = {
        success: hasPrimaryEvidence,
        fetchedAt: new Date().toISOString(),
        collectionStatus: allWarnings.length ? 'completed_with_warnings' : 'complete',
        warnings: allWarnings,
        collection: {
            status: allWarnings.length ? 'completed_with_warnings' : 'complete',
            warnings: allWarnings,
            stages,
            sources: {
                alerts: {
                    recordsFetched: alerts.length,
                    recordsPrepared: processedAlerts.length,
                    status: alertsResult.warnings?.length && !processedAlerts.length ? 'warning' : 'complete'
                },
                incidents: {
                    recordsFetched: incidents.length,
                    recordsPrepared: processedIncidents.length,
                    status: incidentsResult.warnings?.length && !processedIncidents.length ? 'warning' : 'complete'
                },
                threatIndicators: {
                    recordsFetched: externalThreatIndicators.length,
                    recordsPrepared: processedThreats.length,
                    internalExtracted: internalThreats.length,
                    status: processedThreats.length ? 'complete' : (threatIndicatorsResult.warnings?.length ? 'warning' : 'complete')
                },
                signIns: {
                    recordsFetched: signIns.length,
                    recordsPrepared: suspiciousSignIns.length,
                    status: signInsResult.warnings?.length && !suspiciousSignIns.length ? 'warning' : 'complete'
                }
            },
            accounting: allMetrics,
            hasPrimaryEvidence,
            internalThreatIndicatorsExtracted: internalThreats.length
        },
        summary: {
            activeIncidents: activeIncidents.length,
            highSeverityAlerts: highSeverityAlerts.length,
            totalAlerts: processedAlerts.length,
            threatIndicators: processedThreats.length,
            usersUnderAttack: usersUnderAttack.length,
            suspiciousSignIns: suspiciousSignIns.length,
            securityScore
        },
        incidents: processedIncidents,
        alerts: processedAlerts,
        threats: processedThreats,
        threatIndicators: processedThreats,
        signIns: {
            all: signIns.length,
            suspicious: suspiciousSignIns,
            usersUnderAttack
        },
        activityFeed: activityFeed.slice(0, 30),
        mitre: Object.values(mitreMap).sort((a, b) => b.count - a.count).slice(0, 20),
        topTargetedUsers,
        sourceDistribution,
        categoryDistribution,
        regionDistribution,
        attackTimeline,
        aiSummary,
        recommendations
    };

    allMetrics.recordsPrepared =
        processedAlerts.length +
        processedIncidents.length +
        suspiciousSignIns.length +
        processedThreats.length;

    allMetrics.recordsStored = allMetrics.recordsPrepared;
    allMetrics.recordsOmitted = Math.max(0, allMetrics.recordsFetched - allMetrics.recordsPrepared);

    if (allMetrics.recordsOmitted > 0) {
        allMetrics.omittedReasons.push('non_suspicious_signins_not_prepared_as_security_evidence');
    }

    payload.summary.recordsFetched = allMetrics.recordsFetched;
    payload.summary.recordsPrepared = allMetrics.recordsPrepared;
    payload.summary.recordsOmitted = allMetrics.recordsOmitted;
    payload.collection.accounting = { ...allMetrics };

    stages.push({
        stage: 'evidence_prepare:complete',
        status: 'complete',
        recordsPrepared: allMetrics.recordsPrepared,
        recordsOmitted: allMetrics.recordsOmitted,
        at: new Date().toISOString()
    });

    console.log('[security_alerts:evidence_prepare:complete] Evidence preparation complete with accounting:', {
        totalAlerts: processedAlerts.length,
        totalIncidents: processedIncidents.length,
        totalThreats: processedThreats.length,
        externalThreats: externalThreats.length,
        internalThreats: internalThreats.length,
        suspiciousSignIns: suspiciousSignIns.length,
        warnings: payload.warnings
    });

    if (!options.skipWhatsAppAuto) {
        try {
            console.log('[security_alerts:whatsapp_secret_check:start] Checking WhatsApp configuration...');
            const whatsappResult = await notifySecurityAlertsViaWhatsApp(payload, { requireEnabled: true });
            console.log('[security_alerts:whatsapp_secret_check:complete] WhatsApp check complete');

            if (whatsappResult.enabled) {
                console.log('[security_alerts:whatsapp_send:complete] WhatsApp sent:', {
                    sent: whatsappResult.sent,
                    skipped: whatsappResult.skipped,
                    failed: whatsappResult.failed
                });
            }
        } catch (error) {
            console.warn('[security_alerts:whatsapp_secret_check:warning] WhatsApp notification failed (non-blocking):', error.message);
        }
    }

    console.log(`[security_alerts:complete_or_completed_with_warnings_or_failed] ${payload.collectionStatus}`, {
        recordsFetched: allMetrics.recordsFetched,
        recordsPrepared: allMetrics.recordsPrepared,
        recordsOmitted: allMetrics.recordsOmitted,
        warnings: payload.warnings
    });

    return payload;
}

async function fetchSecurityEventsPayloadFromApi(options = {}) {
    try {
        return await promiseWithTimeout(
            buildSecurityEventsPayloadFromApi(options),
            SECURITY_ALERTS_PIPELINE_TIMEOUT_MS,
            'Security Alerts collection pipeline'
        );
    } catch (error) {
        if (!error.securityAlertsStatus) error.securityAlertsStatus = 'failed_terminal';
        if (!error.securityAlertsStage) error.securityAlertsStage = /credential/i.test(error.message) ? 'graph_credentials' : 'security_alerts_pipeline';
        console.error(`[security_alerts:complete_or_completed_with_warnings_or_failed] ${error.securityAlertsStatus} at ${error.securityAlertsStage}: ${error.message}`);
        throw error;
    }
}

app.get('/api/db/security-events', authenticateToken, async (req, res) => {
    try {
        const context = await getAccessContextByUser(req.user);
        if (!context?.companyId) return res.status(403).json({ success: false, message: 'Access mapping not configured' });

        const [rows] = await pool.query(
            'SELECT Payload, LastUpdated FROM SecurityEventsPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1',
            [context.companyId]
        );

        if (rows.length > 0 && rows[0].Payload) {
            try {
                const payload = JSON.parse(rows[0].Payload);
                if (payload && payload.success) {
                    return res.json({ ...payload, source: 'db', fetchedAt: rows[0].LastUpdated });
                }
            } catch (_) {}
        }

        const api = await fetchSecurityEventsPayloadFromApi();
        await pool.query(
            `REPLACE INTO SecurityEventsPayloadCache (CompanyID, Payload, LastUpdated)
             VALUES (?, ?, NOW())`,
            [context.companyId, JSON.stringify(api)]
        );
        return res.json({ ...api, source: 'api-fallback' });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

/**
 * Route: GET /api/security-events
 * Comprehensive SOC dashboard aggregating alerts, incidents, threat indicators, and sign-ins
 */
app.get('/api/security-events', authenticateToken, async (req, res) => {
    try {
        const userEmail = req.user.email;
        console.log(`[Security Events] Fetching dashboard data for: ${userEmail}`);

        const tenant = getTenantByEmail(userEmail);
        if (!tenant || tenant.clientId !== 'sunbird') {
            console.warn(`[Security Events] Access denied for ${userEmail}`);
            return res.status(403).json({ 
                error: 'Access denied',
                message: 'This feature is only available for Sunbird client'
            });
        }

        const payload = await fetchSecurityEventsPayloadFromApi();
        console.log(`[Security Events] Compiled cached/live SOC payload for ${userEmail}:`, {
            alerts: payload.alerts.length,
            incidents: payload.incidents.length,
            mitre: payload.mitre.length,
            usersUnderAttack: payload.signIns.usersUnderAttack.length
        });

        const dashboardPayload = buildSecurityDashboardPayload({ tenantKey: tenant.clientId || 'sunbird', payload });
        if (securityEvidenceService && tenant.companyId) {
            securityEvidenceService.persistProcessedEvidence({
                companyId: tenant.companyId,
                tenantKey: tenant.clientId || 'sunbird',
                payload: dashboardPayload,
                collectionTrigger: 'dashboard_request',
                sourceEndpoint: '/api/security-events'
            }).catch(error => console.warn('[Security Evidence] Dashboard response could not be stored:', error.message));
        }

        res.json({
            ...dashboardPayload,
            tenant: tenant.clientId,
            source: 'api'
        });

    } catch (error) {
        console.error('[Security Events] ❌ Error:', error.message);
        
        res.status(500).json({ 
            error: 'Failed to fetch security events data',
            message: error.message
        });
    }
});

/**
 * Route: POST /api/whatsapp/test-hello
 * Sends the configured security_alert template with safe sample values.
 */
app.post("/api/whatsapp/test-hello", authenticateToken, async (req, res) => {
    let recipient = null;
    try {
        const config = await getWhatsAppSecurityAlertConfig({ requireEnabled: false });
        if (!config.token || !config.phoneNumberId) {
            throw new Error("WhatsApp credentials are missing. Configure WHATSAPP_ACCESS_TOKEN and WHATSAPP_PHONE_NUMBER_ID.");
        }

        recipient = normalizeWhatsAppRecipient(config.recipient);
        const sampleAlert = {
            severity: req.body?.severity || "HIGH",
            issue: req.body?.issue || "Security integration test alert",
            source: req.body?.source || "StackOps Security",
            eventTime: req.body?.time || new Date().toISOString(),
            action: req.body?.action || "Review the event immediately"
        };

        console.log(`[WhatsApp Test] Sending ${config.templateName || "security_alert"} to ${recipient}`);

        const response = await sendSecurityAlert(sampleAlert, { ...config, recipient });
        const messageId = response.messages?.[0]?.id || null;
        console.log("[WhatsApp Test] Meta accepted message", {
            messageId,
            recipient,
            templateName: response.templateName,
            templateLanguage: response.templateLanguage
        });

        res.json({
            success: true,
            recipient,
            messageId,
            templateName: response.templateName,
            templateLanguage: response.templateLanguage,
            response
        });
    } catch (error) {
        const detail = error.response?.data || error.message;
        console.error("[WhatsApp Test] Failed", detail);
        res.status(error.response?.status || 500).json({
            success: false,
            error: "Failed to send WhatsApp security_alert test",
            message: error.response?.data?.error?.message || error.message,
            details: error.response?.data || null,
            recipient
        });
    }
});

/**
 * Route: POST /api/security-events/whatsapp-alerts
 * Sends current Microsoft security alerts/incidents to the configured WhatsApp recipient.
 * Outbound-only: no WhatsApp webhook or inbound message handling is required.
 */
app.post('/api/security-events/whatsapp-alerts', authenticateToken, async (req, res) => {
    try {
        const userEmail = req.user.email;
        const tenant = getTenantByEmail(userEmail);
        if (!tenant || tenant.clientId !== 'sunbird') {
            return res.status(403).json({
                success: false,
                error: 'Access denied',
                message: 'This feature is only available for Sunbird client'
            });
        }

        const payload = await fetchSecurityEventsPayloadFromApi({ skipWhatsAppAuto: true });
        const severities = String(req.body?.severities || req.query.severities || 'critical,high,medium,low')
            .split(',')
            .map(item => item.trim())
            .filter(Boolean);
        const types = String(req.body?.types || req.query.types || 'alert,incident')
            .split(',')
            .map(item => item.trim())
            .filter(Boolean);
        const limit = Number(req.body?.limit || req.query.limit || process.env.WHATSAPP_SECURITY_ALERT_LIMIT || 20);
        const force = String(req.body?.force || req.query.force || 'false').toLowerCase() === 'true';
        const result = await notifySecurityAlertsViaWhatsApp(payload, {
            force,
            limit,
            severities,
            types
        });

        res.json({
            success: true,
            message: `WhatsApp security alert send complete: ${result.sent} sent, ${result.skipped} skipped, ${result.failed} failed.`,
            ...result
        });
    } catch (error) {
        console.error('[WhatsApp Security Alerts] Manual send route failed:', error.response?.data || error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to send WhatsApp security alerts',
            message: error.message,
            details: error.response?.data || null
        });
    }
});

/**
 * Route: GET /api/email-security
 * Email Security dashboard aggregating email-specific alerts and incidents
 */
app.get('/api/email-security', authenticateToken, async (req, res) => {
    try {
        const userEmail = req.user.email;
        console.log(`[Email Security] Fetching dashboard data for: ${userEmail}`);

        const tenant = getTenantByEmail(userEmail);
        if (!tenant || tenant.clientId !== 'sunbird') {
            console.warn(`[Email Security] Access denied for ${userEmail}`);
            return res.status(403).json({ 
                error: 'Access denied',
                message: 'This feature is only available for Sunbird client'
            });
        }

        const payload = await fetchEmailSecurityPayloadFromApi();
        console.log(`[Email Security] Compiled: ${payload.alerts.length} email alerts, ${payload.incidents.length} incidents, ${payload.summary.affectedUsersCount} affected users`);

        if (emailEvidenceService && tenant.companyId) {
            const dashboardPayload = buildEmailDashboardPayload({
                tenantKey: tenant.clientId || 'sunbird',
                payload
            });
            emailEvidenceService.persistProcessedEvidence({
                companyId: tenant.companyId,
                tenantKey: tenant.clientId || 'sunbird',
                payload: dashboardPayload,
                collectionTrigger: 'dashboard_request',
                sourceEndpoint: '/api/email-security'
            }).catch(error => {
                console.warn('[Email Evidence] Dashboard response could not be stored:', error.message);
            });
        }

        res.json({
            ...payload,
            tenant: tenant.clientId,
            source: 'api'
        });

    } catch (error) {
        console.error('[Email Security] Error:', error.message);
        
        res.status(500).json({ 
            error: 'Failed to fetch email security data',
            message: error.message
        });
    }
});

/**
 * Helper: Parse CSV response from Microsoft Graph Reports API
 * Handles both comma-separated and tab-separated formats
 */
async function fetchGraphReportCSV(url, token, reportType = 'unknown', { signal = null, collectorContext = {} } = {}) {
    const { response, body } = await fetchGraphResponseWithDeadline(url, token, {
        signal,
        collectorContext,
        label: `${reportType} Graph report`
    });
    if (!response.ok) throw new Error(`${reportType} Graph report failed (${response.status}): ${body.slice(0, 240)}`);
    return body;
}

function parseGraphReportNumber(value) {
    const parsed = Number(String(value ?? '').replace(/[^0-9.-]/g, ''));
    return Number.isFinite(parsed) ? parsed : 0;
}

function parseGraphCSVLine(line, delimiter) {
    const values = [];
    let current = '';
    let inQuotes = false;

    for (let index = 0; index < line.length; index += 1) {
        const char = line[index];
        const next = line[index + 1];

        if (char === '"' && inQuotes && next === '"') {
            current += '"';
            index += 1;
        } else if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === delimiter && !inQuotes) {
            values.push(current.trim());
            current = '';
        } else {
            current += char;
        }
    }

    values.push(current.trim());
    return values;
}

function parseGraphReportCSV(csvText, reportType = 'unknown') {
    try {
        const lines = csvText.trim().split('\n');
        if (lines.length < 2) {
            console.log(`[CSV Parser] ${reportType} - No data rows (only ${lines.length} lines)`);
            return [];
        }

        // Detect delimiter: comma or tab
        const headerLine = lines[0];
        const isCommaDelimited = headerLine.includes(',') && !headerLine.includes('\t');
        const delimiter = isCommaDelimited ? ',' : '\t';
        console.log(`[CSV Parser] ${reportType} - Detected delimiter: ${delimiter === ',' ? 'COMMA' : 'TAB'}`);

        // Parse header
        const header = parseGraphCSVLine(headerLine.replace(/^\uFEFF/, ''), delimiter);
        console.log(`[CSV Parser] ${reportType} - Headers: ${header.join(', ')}`);
        
        // Parse rows
        const data = [];
        for (let i = 1; i < lines.length; i++) {
            if (!lines[i].trim()) continue;
            
            const values = parseGraphCSVLine(lines[i], delimiter);
            const row = {};
            
            header.forEach((key, index) => {
                row[key] = values[index] || '';
            });
            
            data.push(row);
        }
        
        console.log(`[CSV Parser] ${reportType} - Parsed ${data.length} rows`);
        if (data.length > 0) {
            console.log(`[CSV Parser] ${reportType} - First row:`, JSON.stringify(data[0]));
        }
        
        return data;
    } catch (error) {
        console.error('[CSV Parser] Error parsing CSV:', error);
        return [];
    }
}

/**
 * Route: GET /api/backup-recovery
 * Fetch backup and recovery data from Microsoft Graph Reports
 * Uses: OneDrive, SharePoint, Exchange storage reports
 */
app.get('/api/backup-recovery', authenticateToken, async (req, res) => {
    try {
        const context = await getAccessContextByUser(req.user);
        const payload = await fetchBackupRecoveryPayloadFromApi();
        if (context?.companyId) {
            const dashboardPayload = buildBackupDashboardPayload({ tenantKey: 'sunbird', payload });
            await pool.query(`REPLACE INTO BackupRecoveryPayloadCache (CompanyID, Payload, LastUpdated) VALUES (?, ?, NOW())`, [context.companyId, JSON.stringify(dashboardPayload)]);
            if (backupEvidenceService) {
                backupEvidenceService.persistProcessedEvidence({
                    companyId: context.companyId,
                    tenantKey: 'sunbird',
                    payload: dashboardPayload,
                    collectionTrigger: 'dashboard_request',
                    sourceEndpoint: '/api/backup-recovery'
                }).catch(error => console.warn('[Backup Evidence] Dashboard response could not be stored:', error.message));
            }
            return res.json(dashboardPayload);
        }
        res.json(payload);

    } catch (error) {
        console.error('[Backup Recovery] Error:', error.message);
        
        res.status(500).json({ 
            error: 'Failed to fetch backup recovery data',
            message: error.message
        });
    }
});

const secretClient = new SecretManagerServiceClient();
const secretValueCache = new Map();
const secretReadPromises = new Map();
const secretWarningKeys = new Set();
const SECRET_READ_TIMEOUT_MS = Math.max(1000, Number(process.env.SECRET_MANAGER_READ_TIMEOUT_MS) || 5000);
const SECRET_READ_RETRY_DELAY_MS = Math.max(50, Number(process.env.SECRET_MANAGER_RETRY_DELAY_MS) || 250);

function promiseWithTimeout(promise, timeoutMs, label) {
    let timeoutHandle;
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            timeoutHandle = setTimeout(() => {
                const error = new Error(`${label} timed out after ${timeoutMs}ms`);
                error.code = 'DEADLINE_EXCEEDED';
                reject(error);
            }, timeoutMs);
        })
    ]).finally(() => clearTimeout(timeoutHandle));
}

// Function to get secret from Google Cloud Secret Manager
async function getSecret(secretName) {
    if (secretValueCache.has(secretName)) return secretValueCache.get(secretName);
    const environmentValue = String(process.env[secretName] || '').trim();
    if (environmentValue) {
        secretValueCache.set(secretName, environmentValue);
        return environmentValue;
    }
    if (secretReadPromises.has(secretName)) return secretReadPromises.get(secretName);

    const projectId = 'stackops-backend-475222';
    const name = `projects/${projectId}/secrets/${secretName}/versions/latest`;
    const load = (async () => {
        let lastError = null;
        for (let attempt = 0; attempt < 2; attempt += 1) {
            try {
                const [version] = await promiseWithTimeout(
                    secretClient.accessSecretVersion({ name }, { timeout: SECRET_READ_TIMEOUT_MS }),
                    SECRET_READ_TIMEOUT_MS,
                    `Secret Manager read for ${secretName}`
                );
                const value = version?.payload?.data?.toString().trim() || null;
                if (value) {
                    secretValueCache.set(secretName, value);
                    secretWarningKeys.delete(secretName);
                }
                return value;
            } catch (error) {
                lastError = error;
                if (attempt === 0) await sleep(SECRET_READ_RETRY_DELAY_MS);
            }
        }
        if (!secretWarningKeys.has(secretName)) {
            secretWarningKeys.add(secretName);
            console.warn(`[Secret Manager] ${secretName} unavailable after one retry: ${lastError?.code || lastError?.message || 'unknown error'}.`);
        }
        return secretValueCache.get(secretName) || null;
    })();
    secretReadPromises.set(secretName, load);
    try {
        return await load;
    } finally {
        if (secretReadPromises.get(secretName) === load) secretReadPromises.delete(secretName);
    }
}

async function performIdentityEvidenceCollection(companyId, collectionTrigger) {
    if (!identityEvidenceService) throw new Error('Identity evidence storage is not initialized');
    const sourceEndpoint = 'Microsoft Graph processed by StackCTRL Identity Protection';
    try {
        const token = await getMicrosoftGraphToken();
        const [users, roleAssignments, signIns] = await Promise.all([
            fetchMicrosoftUsers(token),
            fetchMicrosoftRoleAssignments(token),
            fetchMicrosoftSignIns(token)
        ]);
        const payload = await buildIdentityDashboardPayload({
            tenantKey: 'sunbird',
            users,
            roleAssignments,
            signIns,
            loadAuthMethods: user => fetchUserAuthMethods(token, user.id),
            hasRealMfaMethod,
            mapWithConcurrency,
            concurrency: Number(process.env.IDENTITY_EVIDENCE_AUTH_CONCURRENCY || 4)
        });
        return identityEvidenceService.persistProcessedEvidence({
            companyId,
            tenantKey: 'sunbird',
            payload,
            collectionTrigger,
            sourceEndpoint
        });
    } catch (error) {
        await identityEvidenceService.recordCollectionFailure({
            companyId,
            tenantKey: 'sunbird',
            collectionTrigger,
            sourceEndpoint,
            error
        }).catch(auditError => {
            console.warn('[Identity Evidence] Collection failure could not be audited:', auditError.message);
        });
        throw error;
    }
}

async function collectAndPersistIdentityEvidence(companyId, collectionTrigger = 'scheduled_30_minute', collectorContext = {}) {
    return identityEvidenceCollectors.run({ companyId, sourceKey: 'identity', collectionTrigger, runId: collectorContext.runId || null, pipelineExecutionId: collectorContext.pipelineExecutionId || null, signal: collectorContext.signal || null, timeout: collectorContext.timeoutMs || STACKCTRL_COLLECTOR_TIMEOUT_MS, execute: ({ signal }) => performIdentityEvidenceCollection(companyId, collectionTrigger, { ...collectorContext, signal }) });
}

async function collectIdentityEvidenceForConfiguredTenants({ trigger = 'scheduled_30_minute' } = {}) {
    const [companies] = await pool.query(
        `SELECT DISTINCT company.ID AS CompanyID, company.CompanyName
         FROM Companies company
         LEFT JOIN StackCTRLClientCapabilities capability
           ON capability.CompanyID = company.ID
          AND capability.SourceKey = 'identity'
         WHERE LOWER(company.CompanyName) LIKE '%sunbird%'
            OR (capability.ProfileKey = 'sunbird' AND capability.IsExpected = 1 AND capability.IsEnabled = 1)`
    );
    const results = [];
    for (const company of companies) {
        try {
            results.push(await collectAndPersistIdentityEvidence(company.CompanyID, trigger));
        } catch (error) {
            console.error(`[Identity Evidence] Company ${company.CompanyID} collection failed:`, error.message);
            results.push({ companyId: company.CompanyID, status: 'failed', message: error.message });
        }
    }
    return { companyCount: companies.length, results };
}

async function performDeviceEvidenceCollection(companyId, collectionTrigger) {
    if (!deviceEvidenceService) throw new Error('Device evidence storage is not initialized');
    const sourceEndpoint = 'Microsoft Graph processed by StackCTRL Device Protection';
    try {
        const token = await getMicrosoftGraphToken();
        const alertsPromise = fetchSecurityAlerts(token).catch(error => {
            console.warn('[Device Evidence] Device security alerts unavailable; continuing device refresh:', error.message);
            return { alerts: [], warnings: ['device_security_alerts_unavailable'], recordsFetched: 0 };
        });
        const [devices, policies, alerts] = await Promise.all([
            fetchMicrosoftDevices(token),
            fetchCompliancePolicies(token),
            alertsPromise
        ]);
        const payload = buildDeviceDashboardPayload({
            tenantKey: 'sunbird',
            devices,
            alerts,
            policies
        });
        return deviceEvidenceService.persistProcessedEvidence({
            companyId,
            tenantKey: 'sunbird',
            payload,
            collectionTrigger,
            sourceEndpoint
        });
    } catch (error) {
        console.error(`[Device Evidence] Collection failed for CompanyID ${companyId}: ${error.message}`, {
            errorCode: error.code,
            errorType: error.constructor.name
        });
        await deviceEvidenceService.recordCollectionFailure({
            companyId,
            tenantKey: 'sunbird',
            collectionTrigger,
            sourceEndpoint,
            error
        }).catch(auditError => {
            console.warn('[Device Evidence] Collection failure could not be audited:', auditError.message);
        });
        throw error;
    }
}

async function collectAndPersistDeviceEvidence(companyId, collectionTrigger = 'scheduled_30_minute', collectorContext = {}) {
    return deviceEvidenceCollectors.run({ companyId, sourceKey: 'devices', collectionTrigger, runId: collectorContext.runId || null, pipelineExecutionId: collectorContext.pipelineExecutionId || null, signal: collectorContext.signal || null, timeout: collectorContext.timeoutMs || STACKCTRL_COLLECTOR_TIMEOUT_MS, execute: ({ signal }) => performDeviceEvidenceCollection(companyId, collectionTrigger, { ...collectorContext, signal }) });
}

async function collectDeviceEvidenceForConfiguredTenants({ trigger = 'scheduled_30_minute' } = {}) {
    const [companies] = await pool.query(
        `SELECT DISTINCT company.ID AS CompanyID, company.CompanyName
         FROM Companies company
         LEFT JOIN StackCTRLClientCapabilities capability
           ON capability.CompanyID = company.ID
          AND capability.SourceKey = 'devices'
         WHERE LOWER(company.CompanyName) LIKE '%sunbird%'
            OR (capability.ProfileKey = 'sunbird' AND capability.IsExpected = 1 AND capability.IsEnabled = 1)`
    );
    const results = [];
    for (const company of companies) {
        try {
            results.push(await collectAndPersistDeviceEvidence(company.CompanyID, trigger));
        } catch (error) {
            console.error(`[Device Evidence] Company ${company.CompanyID} collection failed:`, error.message);
            results.push({ companyId: company.CompanyID, status: 'failed', message: error.message });
        }
    }
    return { companyCount: companies.length, results };
}

async function performEmailEvidenceCollection(companyId, collectionTrigger, collectorContext = {}) {
    if (!emailEvidenceService) throw new Error('Email evidence storage is not initialized');
    const sourceEndpoint = 'Microsoft Graph processed by StackCTRL Email Security';
    try {
        const payload = await fetchEmailSecurityPayloadFromApi(null, { signal: collectorContext.signal || null, collectorContext: { ...collectorContext, companyId, sourceKey: 'email_security' } });
        const dashboardPayload = buildEmailDashboardPayload({
            tenantKey: 'sunbird',
            payload
        });
        await pool.query(
            `REPLACE INTO EmailMetricsCache
             (CompanyID, ActiveThreats, HighSeverity, UsersTargeted, OpenIncidents, LastUpdated)
             VALUES (?, ?, ?, ?, ?, NOW())`,
            [
                companyId,
                dashboardPayload.summary.activeThreats || 0,
                dashboardPayload.summary.highSeverityAlerts || 0,
                dashboardPayload.summary.affectedUsersCount || 0,
                dashboardPayload.summary.activeIncidents || 0
            ]
        );
        await pool.query(
            `REPLACE INTO EmailSecurityPayloadCache (CompanyID, Payload, LastUpdated)
             VALUES (?, ?, NOW())`,
            [companyId, JSON.stringify(dashboardPayload)]
        );
        return emailEvidenceService.persistProcessedEvidence({
            companyId,
            tenantKey: 'sunbird',
            payload: dashboardPayload,
            collectionTrigger,
            sourceEndpoint
        });
    } catch (error) {
        console.error(`[Email Evidence] Collection failed for CompanyID ${companyId}: ${error.message}`);
        await emailEvidenceService.recordCollectionFailure({
            companyId,
            tenantKey: 'sunbird',
            collectionTrigger,
            sourceEndpoint,
            error
        }).catch(auditError => {
            console.warn('[Email Evidence] Collection failure could not be audited:', auditError.message);
        });
        throw error;
    }
}

async function collectAndPersistEmailEvidence(companyId, collectionTrigger = 'scheduled_hourly', collectorContext = {}) {
    return emailEvidenceCollectors.run({ companyId, sourceKey: 'email_security', collectionTrigger, runId: collectorContext.runId || null, pipelineExecutionId: collectorContext.pipelineExecutionId || null, signal: collectorContext.signal || null, timeout: collectorContext.timeoutMs || STACKCTRL_COLLECTOR_TIMEOUT_MS, execute: ({ signal }) => performEmailEvidenceCollection(companyId, collectionTrigger, { ...collectorContext, signal }) });
}

async function collectEmailEvidenceForConfiguredTenants({ trigger = 'scheduled_hourly' } = {}) {
    const [companies] = await pool.query(
        `SELECT DISTINCT company.ID AS CompanyID, company.CompanyName
         FROM Companies company
         LEFT JOIN StackCTRLClientCapabilities capability
           ON capability.CompanyID = company.ID
          AND capability.SourceKey = 'email_security'
         WHERE LOWER(company.CompanyName) LIKE '%sunbird%'
            OR (capability.ProfileKey = 'sunbird' AND capability.IsExpected = 1 AND capability.IsEnabled = 1)`
    );
    const results = [];
    for (const company of companies) {
        try {
            results.push(await collectAndPersistEmailEvidence(company.CompanyID, trigger));
        } catch (error) {
            console.error(`[Email Evidence] Company ${company.CompanyID} collection failed:`, error.message);
            results.push({ companyId: company.CompanyID, status: 'failed', message: error.message });
        }
    }
    return { companyCount: companies.length, results };
}

async function performNetworkEvidenceCollection(companyId, collectionTrigger) {
    if (!networkEvidenceService) throw new Error('Network evidence storage is not initialized');
    const sourceEndpoint = 'Cloudflare Zero Trust processed by StackCTRL Network Security';
    try {
        const summary = await getCloudflareNetworkSecuritySummary({ getSecret });
        const dashboardPayload = buildNetworkDashboardPayload({
            tenantKey: 'sunbird',
            payload: summary
        });
        return networkEvidenceService.persistProcessedEvidence({
            companyId,
            tenantKey: 'sunbird',
            payload: dashboardPayload,
            collectionTrigger,
            sourceEndpoint
        });
    } catch (error) {
        console.error(`[Network Evidence] Collection failed for CompanyID ${companyId}: ${error.message}`);
        await networkEvidenceService.recordCollectionFailure({
            companyId,
            tenantKey: 'sunbird',
            collectionTrigger,
            sourceEndpoint,
            error
        }).catch(auditError => {
            console.warn('[Network Evidence] Collection failure could not be audited:', auditError.message);
        });
        throw error;
    }
}

async function collectAndPersistNetworkEvidence(companyId, collectionTrigger = 'scheduled_hourly', collectorContext = {}) {
    return networkEvidenceCollectors.run({ companyId, sourceKey: 'cloudflare_network_security', collectionTrigger, runId: collectorContext.runId || null, pipelineExecutionId: collectorContext.pipelineExecutionId || null, signal: collectorContext.signal || null, timeout: collectorContext.timeoutMs || STACKCTRL_COLLECTOR_TIMEOUT_MS, execute: ({ signal }) => performNetworkEvidenceCollection(companyId, collectionTrigger, { ...collectorContext, signal }) });
}

async function collectNetworkEvidenceForConfiguredTenants({ trigger = 'scheduled_hourly' } = {}) {
    const [companies] = await pool.query(
        `SELECT DISTINCT company.ID AS CompanyID, company.CompanyName
         FROM Companies company
         LEFT JOIN StackCTRLClientCapabilities capability
           ON capability.CompanyID = company.ID
          AND capability.SourceKey = 'cloudflare_network_security'
         WHERE LOWER(company.CompanyName) LIKE '%sunbird%'
            OR (capability.ProfileKey = 'sunbird' AND capability.IsExpected = 1 AND capability.IsEnabled = 1)`
    );
    const results = [];
    for (const company of companies) {
        try {
            results.push(await collectAndPersistNetworkEvidence(company.CompanyID, trigger));
        } catch (error) {
            console.error(`[Network Evidence] Company ${company.CompanyID} collection failed:`, error.message);
            results.push({ companyId: company.CompanyID, status: 'failed', message: error.message });
        }
    }
    return { companyCount: companies.length, results };
}

async function performBackupEvidenceCollection(companyId, collectionTrigger, collectorContext = {}) {
    if (!backupEvidenceService) throw new Error('Backup evidence storage is not initialized');
    const sourceEndpoint = 'Microsoft Graph processed by StackCTRL Backup and Recovery';
    try {
        const payload = await fetchBackupRecoveryPayloadFromApi(null, { signal: collectorContext.signal || null, collectorContext: { ...collectorContext, companyId, sourceKey: 'backup' } });
        const dashboardPayload = buildBackupDashboardPayload({ tenantKey: 'sunbird', payload });
        await writeBackupRecoveryPayloadCache(companyId, dashboardPayload, { signal: collectorContext.signal || null, collectorContext });
        return backupEvidenceService.persistProcessedEvidence({ companyId, tenantKey: 'sunbird', payload: dashboardPayload, collectionTrigger, sourceEndpoint, signal: collectorContext.signal || null, timeoutMs: BACKUP_DATABASE_TIMEOUT_MS });
    } catch (error) {
        await backupEvidenceService.recordCollectionFailure({ companyId, tenantKey: 'sunbird', collectionTrigger, sourceEndpoint, error, timeoutMs: BACKUP_DATABASE_TIMEOUT_MS }).catch(() => {});
        throw error;
    }
}

async function collectAndPersistBackupEvidence(companyId, collectionTrigger = 'scheduled_6_hour', collectorContext = {}) {
    return backupEvidenceCollectors.run({ companyId, sourceKey: 'backup', collectionTrigger, runId: collectorContext.runId || null, pipelineExecutionId: collectorContext.pipelineExecutionId || null, signal: collectorContext.signal || null, timeout: collectorContext.timeoutMs || STACKCTRL_COLLECTOR_TIMEOUT_MS, execute: ({ signal }) => performBackupEvidenceCollection(companyId, collectionTrigger, { ...collectorContext, signal }) });
}

async function collectBackupEvidenceForConfiguredTenants({ trigger = 'scheduled_6_hour' } = {}) {
    const [companies] = await pool.query(`SELECT DISTINCT company.ID AS CompanyID FROM Companies company LEFT JOIN StackCTRLClientCapabilities capability ON capability.CompanyID = company.ID AND capability.SourceKey = 'backup' WHERE LOWER(company.CompanyName) LIKE '%sunbird%' OR (capability.ProfileKey = 'sunbird' AND capability.IsExpected = 1 AND capability.IsEnabled = 1)`);
    const results = [];
    for (const company of companies) {
        try { results.push(await collectAndPersistBackupEvidence(company.CompanyID, trigger)); }
        catch (error) { results.push({ companyId: company.CompanyID, status: 'failed', message: error.message }); }
    }
    return { companyCount: companies.length, results };
}

async function performApplicationsEvidenceCollection(companyId, collectionTrigger) {
    if (!applicationsEvidenceService) throw new Error('Applications evidence storage is not initialized');
    const sourceEndpoint = 'Microsoft Graph processed by StackCTRL Applications';
    try {
        const payload = await fetchApplicationsPayloadFromApi();
        const dashboardPayload = buildApplicationsDashboardPayload({ tenantKey: 'sunbird', payload });
        await pool.query(`REPLACE INTO ApplicationMetricsCache (CompanyID, TotalApps, ExternalApps, HighRiskApps, HighAccessApps, LastUpdated) VALUES (?, ?, ?, ?, ?, NOW())`, [companyId, dashboardPayload.summary.totalApplications, dashboardPayload.summary.externalApplications, dashboardPayload.summary.highRiskApps, dashboardPayload.summary.highAccessApps]);
        await pool.query(`REPLACE INTO ApplicationPayloadCache (CompanyID, Payload, LastUpdated) VALUES (?, ?, NOW())`, [companyId, JSON.stringify(dashboardPayload)]);
        return applicationsEvidenceService.persistProcessedEvidence({ companyId, tenantKey: 'sunbird', payload: dashboardPayload, collectionTrigger, sourceEndpoint });
    } catch (error) {
        await applicationsEvidenceService.recordCollectionFailure({ companyId, tenantKey: 'sunbird', collectionTrigger, sourceEndpoint, error }).catch(() => {});
        throw error;
    }
}

async function collectAndPersistApplicationsEvidence(companyId, collectionTrigger = 'scheduled_hourly', collectorContext = {}) {
    return applicationsEvidenceCollectors.run({ companyId, sourceKey: 'applications', collectionTrigger, runId: collectorContext.runId || null, pipelineExecutionId: collectorContext.pipelineExecutionId || null, signal: collectorContext.signal || null, timeout: collectorContext.timeoutMs || STACKCTRL_COLLECTOR_TIMEOUT_MS, execute: ({ signal }) => performApplicationsEvidenceCollection(companyId, collectionTrigger, { ...collectorContext, signal }) });
}

async function collectApplicationsEvidenceForConfiguredTenants({ trigger = 'scheduled_hourly' } = {}) {
    const [companies] = await pool.query(`SELECT DISTINCT company.ID AS CompanyID FROM Companies company LEFT JOIN StackCTRLClientCapabilities capability ON capability.CompanyID = company.ID AND capability.SourceKey = 'applications' WHERE LOWER(company.CompanyName) LIKE '%sunbird%' OR (capability.ProfileKey = 'sunbird' AND capability.IsExpected = 1 AND capability.IsEnabled = 1)`);
    const results = [];
    for (const company of companies) {
        try { results.push(await collectAndPersistApplicationsEvidence(company.CompanyID, trigger)); }
        catch (error) { results.push({ companyId: company.CompanyID, status: 'failed', message: error.message }); }
    }
    return { companyCount: companies.length, results };
}

async function performSecurityEvidenceCollection(companyId, collectionTrigger) {
    if (!securityEvidenceService) throw new Error('Security evidence storage is not initialized');
    const sourceEndpoint = 'Microsoft Graph processed by StackCTRL Security Alerts';
    try {
        const payload = await fetchSecurityEventsPayloadFromApi({ skipWhatsAppAuto: true });
        const dashboardPayload = buildSecurityDashboardPayload({ tenantKey: 'sunbird', payload });
        await pool.query(`REPLACE INTO SecurityEventsPayloadCache (CompanyID, Payload, LastUpdated) VALUES (?, ?, NOW())`, [companyId, JSON.stringify(dashboardPayload)]);
        const stored = await securityEvidenceService.persistProcessedEvidence({ companyId, tenantKey: 'sunbird', payload: dashboardPayload, collectionTrigger, sourceEndpoint });
        console.log('[security_alerts:storage:complete] Security Alerts evidence stored', {
            snapshotId: stored.snapshotId,
            recordsFetched: dashboardPayload.collection?.accounting?.recordsFetched || 0,
            recordsPrepared: stored.recordCount,
            recordsOmitted: stored.omittedRecordCount || 0,
            status: stored.collectionStatus
        });
        console.log(`[security_alerts:complete_or_completed_with_warnings_or_failed] ${stored.collectionStatus}`, { snapshotId: stored.snapshotId, warnings: stored.warnings || [] });
        return stored;
    } catch (error) {
        const terminal = await securityEvidenceService.recordCollectionFailure({ companyId, tenantKey: 'sunbird', collectionTrigger, sourceEndpoint, error }).catch(() => null);
        console.error('[security_alerts:complete_or_completed_with_warnings_or_failed] failed_terminal', { snapshotId: terminal?.snapshotId || null, stage: error.securityAlertsStage || 'unknown', reason: error.message });
        throw error;
    }
}

async function collectAndPersistSecurityEvidence(companyId, collectionTrigger = 'scheduled_hourly', collectorContext = {}) {
    return securityEvidenceCollectors.run({ companyId, sourceKey: 'security_alerts', collectionTrigger, runId: collectorContext.runId || null, pipelineExecutionId: collectorContext.pipelineExecutionId || null, signal: collectorContext.signal || null, timeout: collectorContext.timeoutMs || STACKCTRL_COLLECTOR_TIMEOUT_MS, execute: ({ signal }) => performSecurityEvidenceCollection(companyId, collectionTrigger, { ...collectorContext, signal }) });
}

async function collectSecurityEvidenceForConfiguredTenants({ trigger = 'scheduled_hourly' } = {}) {
    const [companies] = await pool.query(`SELECT DISTINCT company.ID AS CompanyID FROM Companies company LEFT JOIN StackCTRLClientCapabilities capability ON capability.CompanyID = company.ID AND capability.SourceKey = 'security_alerts' WHERE LOWER(company.CompanyName) LIKE '%sunbird%' OR (capability.ProfileKey = 'sunbird' AND capability.IsExpected = 1 AND capability.IsEnabled = 1)`);
    const results = [];
    for (const company of companies) {
        try { results.push(await collectAndPersistSecurityEvidence(company.CompanyID, trigger)); }
        catch (error) { results.push({ companyId: company.CompanyID, status: 'failed', message: error.message }); }
    }
    return { companyCount: companies.length, results };
}

async function requireEvidenceSchema(schemaReady, domainLabel) {
    const schema = await schemaReady;
    if (schema?.error) throw new Error(`${domainLabel} evidence schema is unavailable: ${schema.error.message}`);
    return schema;
}

async function persistGovernanceDashboardEvidence(companyId, rawPayload, collectionTrigger, sourceEndpoint) {
    await requireEvidenceSchema(governanceEvidenceSchemaReady, 'Governance');
    const sourcePayloadRowCount = Array.isArray(rawPayload?.rows) ? rawPayload.rows.length : 0;
    console.log('[Governance Evidence] Collector received payload', { companyId, collectionTrigger, sourcePayloadRowCount });
    const dashboardPayload = buildGovernanceDashboardPayload({ tenantKey: 'sunbird', payload: rawPayload });
    const result = await governanceEvidenceService.persistProcessedEvidence({ companyId, tenantKey: 'sunbird', payload: dashboardPayload, collectionTrigger, sourceEndpoint });
    console.log('[Governance Evidence] Collector completed', { companyId, collectionTrigger, sourcePayloadRowCount, apiConnectedRowsKept: result.recordCount, manualRowsExcluded: result.omittedRecordCount, snapshotId: result.snapshotId, collectionStatus: result.collectionStatus, isComplete: result.isComplete });
    return result;
}

async function persistComplianceDashboardEvidence(companyId, rawPayload, collectionTrigger, sourceEndpoint) {
    await requireEvidenceSchema(complianceEvidenceSchemaReady, 'Compliance Validation');
    const sourcePayloadRowCount = Array.isArray(rawPayload?.controls) ? rawPayload.controls.length : 0;
    console.log('[Compliance Evidence] Collector received payload', { companyId, collectionTrigger, sourcePayloadRowCount });
    const dashboardPayload = buildComplianceDashboardPayload({ tenantKey: 'sunbird', payload: rawPayload });
    const result = await complianceEvidenceService.persistProcessedEvidence({ companyId, tenantKey: 'sunbird', payload: dashboardPayload, collectionTrigger, sourceEndpoint });
    console.log('[Compliance Evidence] Collector completed', { companyId, collectionTrigger, sourcePayloadRowCount, apiConnectedRowsKept: result.recordCount, manualRowsExcluded: result.omittedRecordCount, snapshotId: result.snapshotId, collectionStatus: result.collectionStatus, isComplete: result.isComplete });
    return result;
}

async function persistOperationsDashboardEvidence(companyId, rawPayload, collectionTrigger, sourceEndpoint) {
    await requireEvidenceSchema(operationsEvidenceSchemaReady, 'Operations');
    const sourcePayloadRowCount = Array.isArray(rawPayload?.tasks) ? rawPayload.tasks.length : 0;
    console.log('[Operations Evidence] Collector received payload', { companyId, collectionTrigger, sourcePayloadRowCount });
    const dashboardPayload = buildOperationsDashboardPayload({ tenantKey: 'sunbird', payload: rawPayload });
    const result = await operationsEvidenceService.persistProcessedEvidence({ companyId, tenantKey: 'sunbird', payload: dashboardPayload, collectionTrigger, sourceEndpoint });
    console.log('[Operations Evidence] Collector completed', { companyId, collectionTrigger, sourcePayloadRowCount, apiConnectedRowsKept: result.recordCount, manualRowsExcluded: result.omittedRecordCount, snapshotId: result.snapshotId, collectionStatus: result.collectionStatus, isComplete: result.isComplete });
    return result;
}

async function performGovernanceEvidenceCollection(companyId, collectionTrigger) {
    if (!governanceEvidenceService) throw new Error('Governance evidence storage is not initialized');
    const sourceEndpoint = 'Microsoft Graph processed by StackCTRL Governance';
    try {
        const payload = compactSunbirdGovernancePayload(await fetchGovernancePayloadFromApi());
        await upsertSunbirdPayloadCache('SunbirdGovernancePayloadCache', companyId, payload);
        return persistGovernanceDashboardEvidence(companyId, payload, collectionTrigger, sourceEndpoint);
    } catch (error) {
        console.error('[Governance Evidence] Collector failed', { companyId, collectionTrigger, errorMessage: error.message });
        await governanceEvidenceService.recordCollectionFailure({ companyId, tenantKey: 'sunbird', collectionTrigger, sourceEndpoint, error }).catch(() => {});
        throw error;
    }
}

async function collectAndPersistGovernanceEvidence(companyId, collectionTrigger = 'scheduled_daily', collectorContext = {}) {
    return governanceEvidenceCollectors.run({ companyId, sourceKey: 'governance', collectionTrigger, runId: collectorContext.runId || null, pipelineExecutionId: collectorContext.pipelineExecutionId || null, signal: collectorContext.signal || null, timeout: collectorContext.timeoutMs || STACKCTRL_COLLECTOR_TIMEOUT_MS, execute: ({ signal }) => performGovernanceEvidenceCollection(companyId, collectionTrigger, { ...collectorContext, signal }) });
}

async function collectGovernanceEvidenceForConfiguredTenants({ trigger = 'scheduled_daily' } = {}) {
    const [companies] = await pool.query(`SELECT DISTINCT company.ID AS CompanyID FROM Companies company LEFT JOIN StackCTRLClientCapabilities capability ON capability.CompanyID = company.ID AND capability.SourceKey = 'governance' WHERE LOWER(company.CompanyName) LIKE '%sunbird%' OR (capability.ProfileKey = 'sunbird' AND capability.IsExpected = 1 AND capability.IsEnabled = 1)`);
    const results = [];
    for (const company of companies) {
        try { results.push(await collectAndPersistGovernanceEvidence(company.CompanyID, trigger)); }
        catch (error) { results.push({ companyId: company.CompanyID, status: 'failed', message: error.message }); }
    }
    return { companyCount: companies.length, results };
}

async function performComplianceEvidenceCollection(companyId, collectionTrigger) {
    if (!complianceEvidenceService) throw new Error('Compliance evidence storage is not initialized');
    const sourceEndpoint = 'Microsoft Graph processed by StackCTRL Compliance Validation';
    try {
        const payload = compactSunbirdCompliancePayload(await fetchComplianceControlsFromApi());
        await upsertSunbirdPayloadCache('SunbirdComplianceControlsCache', companyId, payload);
        return persistComplianceDashboardEvidence(companyId, payload, collectionTrigger, sourceEndpoint);
    } catch (error) {
        console.error('[Compliance Evidence] Collector failed', { companyId, collectionTrigger, errorMessage: error.message });
        await complianceEvidenceService.recordCollectionFailure({ companyId, tenantKey: 'sunbird', collectionTrigger, sourceEndpoint, error }).catch(() => {});
        throw error;
    }
}

async function collectAndPersistComplianceEvidence(companyId, collectionTrigger = 'scheduled_daily', collectorContext = {}) {
    return complianceEvidenceCollectors.run({ companyId, sourceKey: 'compliance', collectionTrigger, runId: collectorContext.runId || null, pipelineExecutionId: collectorContext.pipelineExecutionId || null, signal: collectorContext.signal || null, timeout: collectorContext.timeoutMs || STACKCTRL_COLLECTOR_TIMEOUT_MS, execute: ({ signal }) => performComplianceEvidenceCollection(companyId, collectionTrigger, { ...collectorContext, signal }) });
}

async function collectComplianceEvidenceForConfiguredTenants({ trigger = 'scheduled_daily' } = {}) {
    const [companies] = await pool.query(`SELECT DISTINCT company.ID AS CompanyID FROM Companies company LEFT JOIN StackCTRLClientCapabilities capability ON capability.CompanyID = company.ID AND capability.SourceKey = 'compliance' WHERE LOWER(company.CompanyName) LIKE '%sunbird%' OR (capability.ProfileKey = 'sunbird' AND capability.IsExpected = 1 AND capability.IsEnabled = 1)`);
    const results = [];
    for (const company of companies) {
        try { results.push(await collectAndPersistComplianceEvidence(company.CompanyID, trigger)); }
        catch (error) { results.push({ companyId: company.CompanyID, status: 'failed', message: error.message }); }
    }
    return { companyCount: companies.length, results };
}

async function performOperationsEvidenceCollection(companyId, collectionTrigger) {
    if (!operationsEvidenceService) throw new Error('Operations evidence storage is not initialized');
    const sourceEndpoint = 'Microsoft Graph processed by StackCTRL Operations';
    try {
        const rawPayload = await fetchOperationsPayloadFromApi();
        await upsertSunbirdPayloadCache('SunbirdOperationsPayloadCache', companyId, rawPayload);
        return persistOperationsDashboardEvidence(companyId, rawPayload, collectionTrigger, sourceEndpoint);
    } catch (error) {
        console.error('[Operations Evidence] Collector failed', { companyId, collectionTrigger, errorMessage: error.message });
        await operationsEvidenceService.recordCollectionFailure({ companyId, tenantKey: 'sunbird', collectionTrigger, sourceEndpoint, error }).catch(() => {});
        throw error;
    }
}

async function collectAndPersistOperationsEvidence(companyId, collectionTrigger = 'scheduled_hourly', collectorContext = {}) {
    return operationsEvidenceCollectors.run({ companyId, sourceKey: 'operations', collectionTrigger, runId: collectorContext.runId || null, pipelineExecutionId: collectorContext.pipelineExecutionId || null, signal: collectorContext.signal || null, timeout: collectorContext.timeoutMs || STACKCTRL_COLLECTOR_TIMEOUT_MS, execute: ({ signal }) => performOperationsEvidenceCollection(companyId, collectionTrigger, { ...collectorContext, signal }) });
}

async function collectOperationsEvidenceForConfiguredTenants({ trigger = 'scheduled_hourly' } = {}) {
    const [companies] = await pool.query(`SELECT DISTINCT company.ID AS CompanyID FROM Companies company LEFT JOIN StackCTRLClientCapabilities capability ON capability.CompanyID = company.ID AND capability.SourceKey = 'operations' WHERE LOWER(company.CompanyName) LIKE '%sunbird%' OR (capability.ProfileKey = 'sunbird' AND capability.IsExpected = 1 AND capability.IsEnabled = 1)`);
    const results = [];
    for (const company of companies) {
        try { results.push(await collectAndPersistOperationsEvidence(company.CompanyID, trigger)); }
        catch (error) { results.push({ companyId: company.CompanyID, status: 'failed', message: error.message }); }
    }
    return { companyCount: companies.length, results };
}

async function refreshStackCTRLIntelligenceSource(sourceKey, companyId, collectorContext = {}) {
    switch (sourceKey) {
        case 'identity': {
            if (identityEvidenceService) {
                try {
                    await collectAndPersistIdentityEvidence(companyId, 'enterprise_refresh', { ...collectorContext, sourceKey });
                    // Returning null makes the source adapter reload the committed evidence snapshot.
                    return null;
                } catch (error) {
                    const refreshError = new Error(`Identity evidence refresh failed: ${error.message}`);
                    refreshError.statusCode = error.statusCode || 500;
                    refreshError.isRefreshError = true;
                    refreshError.sourceKey = 'identity';
                    throw refreshError;
                }
            }
            try {
                // Use environment credentials (like dashboard does) for consistent, working access
                // This ensures Enterprise refresh uses the same validated credentials as the dashboard
                const token = await getMicrosoftGraphToken();
                const [metrics, details] = await Promise.all([
                    fetchIdentityMetricsFromApi(token),
                    fetchIdentityDetailsFromApi(token)
                ]);
                
                // Update Azure cache
                await pool.query(
                    `REPLACE INTO IdentityMetricsCache
                     (CompanyID, TotalUsers, ActiveUsers, AdminRoles, SecurityScore, LastUpdated)
                     VALUES (?, ?, ?, ?, ?, NOW())`,
                    [companyId, metrics.totalUsers, metrics.activeUsers, metrics.adminRoles, metrics.securityScore]
                );
                await pool.query(
                    `REPLACE INTO IdentityUserDetailsCache (CompanyID, UsersPayload, LastUpdated)
                     VALUES (?, ?, NOW())`,
                    [companyId, JSON.stringify(details.users || [])]
                );
                await upsertRoleAssignmentsCache(companyId, details.roleAssignments || []);
                
                // ALSO update Sunbird dashboard tables for fresh identity source
                try {
                    const totalUsers = details.users?.length || 0;
                    const mfaEnabledUsers = details.users?.filter(u => u.mfaEnabled)?.length || 0;
                    const mfaCoverage = totalUsers > 0 ? Math.round((mfaEnabledUsers / totalUsers) * 100) : 0;
                    const privilegedUsers = details.users?.filter(u => u.roles?.length > 0)?.length || 0;
                    const highRiskUsers = details.users?.filter(u => u.riskLevel === 'HIGH')?.length || 0;
                    const externalUsers = details.users?.filter(u => u.isExternal)?.length || 0;
                    const unknownDevices = details.users?.filter(u => /unknown|n\/a/i.test(String(u.lastSignIn?.device || '')))?.length || 0;
                    
                    // Update identity_metrics with fresh data
                    await pool.query(
                        `REPLACE INTO identity_metrics 
                         (tenant_id, total_users, mfa_enabled_users, mfa_percentage, admin_users, high_risk_users, 
                          active_users_24h, users_with_complete_profile, privileged_users_without_mfa, 
                          identity_risk_score, last_updated)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
                        ['sunbird', totalUsers, mfaEnabledUsers, mfaCoverage, privilegedUsers, highRiskUsers, 
                         totalUsers, Math.max(0, totalUsers - unknownDevices), 0, 50]
                    );
                    
                    // Update identity_users with fresh user data
                    if (details.users && details.users.length > 0) {
                        const userInserts = details.users.map(u => [
                            'sunbird',
                            u.id,
                            u.displayName,
                            u.mail,
                            u.userPrincipalName,
                            u.jobTitle || 'No Title',
                            u.mobilePhone || 'N/A',
                            JSON.stringify(u.roles || []),
                            u.mfaEnabled ? 1 : 0,
                            u.authMethodCount || 0,
                            u.riskLevel || 'SAFE',
                            u.isExternal ? 1 : 0,
                            JSON.stringify(u.lastSignIn || {}),
                            new Date().toISOString()
                        ]);
                        
                        // Batch insert users
                        for (const userRow of userInserts) {
                            try {
                                await pool.query(
                                    `REPLACE INTO identity_users 
                                     (tenant_id, user_id, display_name, mail, user_principal_name, job_title, mobile_phone, 
                                      roles, mfa_enabled, auth_method_count, risk_level, is_external, last_signin, last_updated)
                                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                                    userRow
                                );
                            } catch (userError) {
                                console.warn(`[Identity Refresh] Failed to update user ${userRow[2]}: ${userError.message}`);
                            }
                        }
                    }
                    
                    console.log(`[Identity Refresh] Successfully updated Sunbird identity_metrics and identity_users for CompanyID ${companyId}`);
                } catch (sunbirdError) {
                    console.warn(`[Identity Refresh] Failed to update Sunbird tables: ${sunbirdError.message}. Using Azure cache only.`);
                }
                
                // Return the processed data for fromRefresh handler
                return {
                    metrics: {
                        totalUsers: metrics.totalUsers,
                        activeUsers: metrics.activeUsers,
                        adminRoles: metrics.adminRoles,
                        securityScore: metrics.securityScore
                    },
                    evidence: details.users || [],
                    users: details.users || [],
                    roleAssignments: details.roleAssignments || [],
                    lastUpdated: new Date().toISOString()
                };
            } catch (error) {
                console.error(`[Identity Refresh] Refresh failed for CompanyID ${companyId}: ${error.message}`, {
                    errorCode: error.code,
                    errorType: error.constructor.name,
                    stack: error.stack
                });
                const refreshError = new Error(`Identity source refresh failed: ${error.message}`);
                refreshError.statusCode = error.statusCode || 500;
                refreshError.isRefreshError = true;
                refreshError.sourceKey = 'identity';
                throw refreshError;
            }
        }
        case 'devices': {
            if (deviceEvidenceService) {
                try {
                    await collectAndPersistDeviceEvidence(companyId, 'enterprise_refresh', { ...collectorContext, sourceKey });
                    return null;
                } catch (error) {
                    console.error('[Device Evidence] Enterprise refresh failed:', error.message);
                    const refreshError = new Error(`Device source refresh failed: ${error.message}`);
                    refreshError.statusCode = error.statusCode || 500;
                    refreshError.isRefreshError = true;
                    refreshError.sourceKey = 'devices';
                    throw refreshError;
                }
            }
            const token = await getMicrosoftGraphToken();
            const result = await fetchDeviceIntelligenceEvidenceFromApi(token);
            await pool.query(
                `REPLACE INTO DeviceMetricsCache
                 (CompanyID, TotalDevices, NonCompliant, NotEncrypted, StaleDevices, LastUpdated)
                 VALUES (?, ?, ?, ?, ?, NOW())`,
                [companyId, result.totalDevices, result.nonCompliant, result.notEncrypted, result.staleDevices]
            );
            return {
                metrics: {
                    totalDevices: result.totalDevices,
                    nonCompliant: result.nonCompliant,
                    notEncrypted: result.notEncrypted,
                    staleDevices: result.staleDevices
                },
                evidence: result.devices || [],
                lastUpdated: new Date().toISOString()
            };
        }
        case 'email_security': {
            if (emailEvidenceService) {
                try {
                    await collectAndPersistEmailEvidence(companyId, 'enterprise_refresh', { ...collectorContext, sourceKey });
                    return null;
                } catch (error) {
                    const refreshError = new Error(`Email evidence refresh failed: ${error.message}`);
                    refreshError.statusCode = error.statusCode || 500;
                    refreshError.isRefreshError = true;
                    refreshError.sourceKey = 'email_security';
                    throw refreshError;
                }
            }
            const payload = await fetchEmailSecurityPayloadFromApi();
            const metrics = {
                activeThreats: payload.summary?.activeThreats || 0,
                highSeverity: payload.summary?.highSeverityAlerts || 0,
                usersTargeted: payload.summary?.affectedUsersCount || 0,
                openIncidents: payload.summary?.activeIncidents || 0
            };
            await pool.query(
                `REPLACE INTO EmailMetricsCache
                 (CompanyID, ActiveThreats, HighSeverity, UsersTargeted, OpenIncidents, LastUpdated)
                 VALUES (?, ?, ?, ?, ?, NOW())`,
                [companyId, metrics.activeThreats, metrics.highSeverity, metrics.usersTargeted, metrics.openIncidents]
            );
            await pool.query(
                `REPLACE INTO EmailSecurityPayloadCache (CompanyID, Payload, LastUpdated)
                 VALUES (?, ?, NOW())`,
                [companyId, JSON.stringify(payload)]
            );
            return null;
        }
        case 'security_alerts': {
            if (securityEvidenceService) {
                try {
                    await collectAndPersistSecurityEvidence(companyId, 'enterprise_refresh', { ...collectorContext, sourceKey });
                    return null;
                } catch (error) {
                    const refreshError = new Error(`Security evidence refresh failed: ${error.message}`);
                    refreshError.statusCode = error.statusCode || 500;
                    refreshError.isRefreshError = true;
                    refreshError.sourceKey = 'security_alerts';
                    throw refreshError;
                }
            }
            const payload = await fetchSecurityEventsPayloadFromApi({ skipWhatsAppAuto: true });
            await pool.query(`REPLACE INTO SecurityEventsPayloadCache (CompanyID, Payload, LastUpdated) VALUES (?, ?, NOW())`, [companyId, JSON.stringify(payload)]);
            return null;
        }
        case 'backup': {
            if (backupEvidenceService) {
                try {
                    await collectAndPersistBackupEvidence(companyId, 'enterprise_refresh', { ...collectorContext, sourceKey });
                    return null;
                } catch (error) {
                    const refreshError = new Error(`Backup evidence refresh failed: ${error.message}`);
                    refreshError.statusCode = error.statusCode || 500;
                    refreshError.isRefreshError = true;
                    refreshError.sourceKey = 'backup';
                    throw refreshError;
                }
            }
            const payload = await fetchBackupRecoveryPayloadFromApi(null, { signal: collectorContext.signal || null, collectorContext: { ...collectorContext, companyId, sourceKey: 'backup' } });
            await writeBackupRecoveryPayloadCache(companyId, payload, { signal: collectorContext.signal || null, collectorContext });
            return null;
        }
        case 'applications': {
            if (applicationsEvidenceService) {
                try {
                    await collectAndPersistApplicationsEvidence(companyId, 'enterprise_refresh', { ...collectorContext, sourceKey });
                    return null;
                } catch (error) {
                    const refreshError = new Error(`Applications evidence refresh failed: ${error.message}`);
                    refreshError.statusCode = error.statusCode || 500;
                    refreshError.isRefreshError = true;
                    refreshError.sourceKey = 'applications';
                    throw refreshError;
                }
            }
            const [metrics, payload] = await Promise.all([fetchApplicationMetricsFromApi(), fetchApplicationsPayloadFromApi()]);
            await pool.query(`REPLACE INTO ApplicationMetricsCache (CompanyID, TotalApps, ExternalApps, HighRiskApps, HighAccessApps, LastUpdated) VALUES (?, ?, ?, ?, ?, NOW())`, [companyId, metrics.totalApps, metrics.externalApps, metrics.highRiskApps, metrics.highAccessApps]);
            await pool.query(`REPLACE INTO ApplicationPayloadCache (CompanyID, Payload, LastUpdated) VALUES (?, ?, NOW())`, [companyId, JSON.stringify(payload)]);
            return null;
        }
        case 'cloudflare_network_security': {
            if (networkEvidenceService) {
                try {
                    await collectAndPersistNetworkEvidence(companyId, 'enterprise_refresh', { ...collectorContext, sourceKey });
                    return null;
                } catch (error) {
                    const refreshError = new Error(`Network evidence refresh failed: ${error.message}`);
                    refreshError.statusCode = error.statusCode || 500;
                    refreshError.isRefreshError = true;
                    refreshError.sourceKey = 'cloudflare_network_security';
                    throw refreshError;
                }
            }
            return getCloudflareNetworkSecuritySummary({ getSecret });
        }
        case 'governance': {
            if (governanceEvidenceService) {
                try {
                    await collectAndPersistGovernanceEvidence(companyId, 'enterprise_refresh');
                    return null;
                } catch (error) {
                    const refreshError = new Error(`Governance evidence refresh failed: ${error.message}`);
                    refreshError.statusCode = error.statusCode || 500;
                    refreshError.isRefreshError = true;
                    refreshError.sourceKey = 'governance';
                    throw refreshError;
                }
            }
            const payload = compactSunbirdGovernancePayload(await fetchGovernancePayloadFromApi());
            await upsertSunbirdPayloadCache('SunbirdGovernancePayloadCache', companyId, payload);
            return null;
        }
        case 'compliance': {
            if (complianceEvidenceService) {
                try {
                    await collectAndPersistComplianceEvidence(companyId, 'enterprise_refresh');
                    return null;
                } catch (error) {
                    const refreshError = new Error(`Compliance evidence refresh failed: ${error.message}`);
                    refreshError.statusCode = error.statusCode || 500;
                    refreshError.isRefreshError = true;
                    refreshError.sourceKey = 'compliance';
                    throw refreshError;
                }
            }
            const payload = compactSunbirdCompliancePayload(await fetchComplianceControlsFromApi());
            await upsertSunbirdPayloadCache('SunbirdComplianceControlsCache', companyId, payload);
            return null;
        }
        case 'operations': {
            if (operationsEvidenceService) {
                try {
                    await collectAndPersistOperationsEvidence(companyId, 'enterprise_refresh');
                    return null;
                } catch (error) {
                    const refreshError = new Error(`Operations evidence refresh failed: ${error.message}`);
                    refreshError.statusCode = error.statusCode || 500;
                    refreshError.isRefreshError = true;
                    refreshError.sourceKey = 'operations';
                    throw refreshError;
                }
            }
            const payload = await fetchOperationsPayloadFromApi({ signal: collectorContext.signal || null, collectorContext: { ...collectorContext, companyId, sourceKey: 'operations' } });
            await upsertSunbirdPayloadCache('SunbirdOperationsPayloadCache', companyId, payload);
            return null;
        }
        case 'duo_licences':
            await syncDuoData();
            return null;
        default:
            return null;
    }
}
// ====================================================================================================//
//                                       CHATBOT CONFIGURATION                                         //
// ====================================================================================================//

// Azure configuration is loaded through getSecret(), which already falls back to environment variables.
const azureOpenAIService = createAzureOpenAIService({
    getSecret,
    maxRetries: process.env.AZURE_OPENAI_MAX_RETRIES,
    retryMaxMs: process.env.AZURE_OPENAI_RETRY_MAX_MS
});
identityEvidenceService = createIdentityEvidenceStore({ pool });
const identityEvidenceSchemaReady = identityEvidenceService.ensureSchema().catch(error => {
    console.error('[Identity Evidence] Schema initialization failed:', error.message);
    return { error };
});
const identityEvidenceAutomation = createIdentityEvidenceAutomation({
    collectAll: async options => {
        const schema = await identityEvidenceSchemaReady;
        if (schema?.error) throw schema.error;
        return collectIdentityEvidenceForConfiguredTenants(options);
    },
    enabled: !['false', '0', 'no'].includes(String(process.env.IDENTITY_EVIDENCE_COLLECTION_ENABLED || 'true').toLowerCase()),
    intervalMs: process.env.IDENTITY_EVIDENCE_COLLECTION_INTERVAL_MS || (30 * 60 * 1000),
    startupDelayMs: process.env.IDENTITY_EVIDENCE_COLLECTION_STARTUP_DELAY_MS || (5 * 60 * 1000)
});
deviceEvidenceService = createDeviceEvidenceStore({ pool });
const deviceEvidenceSchemaReady = deviceEvidenceService.ensureSchema().catch(error => {
    console.error('[Device Evidence] Schema initialization failed:', error.message);
    return { error };
});
const deviceEvidenceAutomation = createDeviceEvidenceAutomation({
    collectAll: async options => {
        const schema = await deviceEvidenceSchemaReady;
        if (schema?.error) throw schema.error;
        return collectDeviceEvidenceForConfiguredTenants(options);
    },
    enabled: !['false', '0', 'no'].includes(String(process.env.DEVICE_EVIDENCE_COLLECTION_ENABLED || 'true').toLowerCase()),
    intervalMs: process.env.DEVICE_EVIDENCE_COLLECTION_INTERVAL_MS || (30 * 60 * 1000),
    startupDelayMs: process.env.DEVICE_EVIDENCE_COLLECTION_STARTUP_DELAY_MS || (7 * 60 * 1000)
});
emailEvidenceService = createEmailEvidenceStore({ pool });
const emailEvidenceSchemaReady = emailEvidenceService.ensureSchema().catch(error => {
    console.error('[Email Evidence] Schema initialization failed:', error.message);
    return { error };
});
const emailEvidenceAutomation = createEmailEvidenceAutomation({
    collectAll: async options => {
        const schema = await emailEvidenceSchemaReady;
        if (schema?.error) throw schema.error;
        return collectEmailEvidenceForConfiguredTenants(options);
    },
    enabled: !['false', '0', 'no'].includes(String(process.env.EMAIL_EVIDENCE_COLLECTION_ENABLED || 'true').toLowerCase()),
    intervalMs: process.env.EMAIL_EVIDENCE_COLLECTION_INTERVAL_MS || (60 * 60 * 1000),
    startupDelayMs: process.env.EMAIL_EVIDENCE_COLLECTION_STARTUP_DELAY_MS || (9 * 60 * 1000)
});
networkEvidenceService = createNetworkEvidenceStore({ pool });
const networkEvidenceSchemaReady = networkEvidenceService.ensureSchema().catch(error => {
    console.error('[Network Evidence] Schema initialization failed:', error.message);
    return { error };
});
const networkEvidenceAutomation = createNetworkEvidenceAutomation({
    collectAll: async options => {
        const schema = await networkEvidenceSchemaReady;
        if (schema?.error) throw schema.error;
        return collectNetworkEvidenceForConfiguredTenants(options);
    },
    enabled: !['false', '0', 'no'].includes(String(process.env.NETWORK_EVIDENCE_COLLECTION_ENABLED || 'true').toLowerCase()),
    intervalMs: process.env.NETWORK_EVIDENCE_COLLECTION_INTERVAL_MS || (60 * 60 * 1000),
    startupDelayMs: process.env.NETWORK_EVIDENCE_COLLECTION_STARTUP_DELAY_MS || (11 * 60 * 1000)
});
backupEvidenceService = createBackupEvidenceStore({ pool });
const backupEvidenceSchemaReady = backupEvidenceService.ensureSchema().catch(error => {
    console.error('[Backup Evidence] Schema initialization failed:', error.message);
    return { error };
});
const backupEvidenceAutomation = createBackupEvidenceAutomation({
    collectAll: async options => {
        const schema = await backupEvidenceSchemaReady;
        if (schema?.error) throw schema.error;
        return collectBackupEvidenceForConfiguredTenants(options);
    },
    enabled: !['false', '0', 'no'].includes(String(process.env.BACKUP_EVIDENCE_COLLECTION_ENABLED || 'true').toLowerCase()),
    intervalMs: process.env.BACKUP_EVIDENCE_COLLECTION_INTERVAL_MS || (6 * 60 * 60 * 1000),
    startupDelayMs: process.env.BACKUP_EVIDENCE_COLLECTION_STARTUP_DELAY_MS || (13 * 60 * 1000)
});
applicationsEvidenceService = createApplicationsEvidenceStore({ pool });
const applicationsEvidenceSchemaReady = applicationsEvidenceService.ensureSchema().catch(error => {
    console.error('[Applications Evidence] Schema initialization failed:', error.message);
    return { error };
});
const applicationsEvidenceAutomation = createApplicationsEvidenceAutomation({
    collectAll: async options => {
        const schema = await applicationsEvidenceSchemaReady;
        if (schema?.error) throw schema.error;
        return collectApplicationsEvidenceForConfiguredTenants(options);
    },
    enabled: !['false', '0', 'no'].includes(String(process.env.APPLICATIONS_EVIDENCE_COLLECTION_ENABLED || 'true').toLowerCase()),
    intervalMs: process.env.APPLICATIONS_EVIDENCE_COLLECTION_INTERVAL_MS || (60 * 60 * 1000),
    startupDelayMs: process.env.APPLICATIONS_EVIDENCE_COLLECTION_STARTUP_DELAY_MS || (15 * 60 * 1000)
});
securityEvidenceService = createSecurityEvidenceStore({ pool });
const securityEvidenceSchemaReady = securityEvidenceService.ensureSchema().catch(error => {
    console.error('[Security Evidence] Schema initialization failed:', error.message);
    return { error };
});
const securityEvidenceAutomation = createSecurityEvidenceAutomation({
    collectAll: async options => {
        const schema = await securityEvidenceSchemaReady;
        if (schema?.error) throw schema.error;
        return collectSecurityEvidenceForConfiguredTenants(options);
    },
    enabled: !['false', '0', 'no'].includes(String(process.env.SECURITY_EVIDENCE_COLLECTION_ENABLED || 'true').toLowerCase()),
    intervalMs: process.env.SECURITY_EVIDENCE_COLLECTION_INTERVAL_MS || (60 * 60 * 1000),
    startupDelayMs: process.env.SECURITY_EVIDENCE_COLLECTION_STARTUP_DELAY_MS || (17 * 60 * 1000)
});
governanceEvidenceService = createGovernanceEvidenceStore({ pool });
const governanceEvidenceSchemaReady = governanceEvidenceService.ensureSchema().catch(error => {
    console.error('[Governance Evidence] Schema initialization failed:', error.message);
    return { error };
});
const governanceEvidenceAutomation = createGovernanceEvidenceAutomation({
    collectAll: async options => {
        const schema = await governanceEvidenceSchemaReady;
        if (schema?.error) throw schema.error;
        return collectGovernanceEvidenceForConfiguredTenants(options);
    },
    enabled: !['false', '0', 'no'].includes(String(process.env.GOVERNANCE_EVIDENCE_COLLECTION_ENABLED || 'true').toLowerCase()),
    intervalMs: process.env.GOVERNANCE_EVIDENCE_COLLECTION_INTERVAL_MS || (30 * 60 * 1000),
    startupDelayMs: process.env.GOVERNANCE_EVIDENCE_COLLECTION_STARTUP_DELAY_MS || (19 * 60 * 1000)
});
complianceEvidenceService = createComplianceEvidenceStore({ pool });
const complianceEvidenceSchemaReady = complianceEvidenceService.ensureSchema().catch(error => {
    console.error('[Compliance Evidence] Schema initialization failed:', error.message);
    return { error };
});
const complianceEvidenceAutomation = createComplianceEvidenceAutomation({
    collectAll: async options => {
        const schema = await complianceEvidenceSchemaReady;
        if (schema?.error) throw schema.error;
        return collectComplianceEvidenceForConfiguredTenants(options);
    },
    enabled: !['false', '0', 'no'].includes(String(process.env.COMPLIANCE_EVIDENCE_COLLECTION_ENABLED || 'true').toLowerCase()),
    intervalMs: process.env.COMPLIANCE_EVIDENCE_COLLECTION_INTERVAL_MS || (30 * 60 * 1000),
    startupDelayMs: process.env.COMPLIANCE_EVIDENCE_COLLECTION_STARTUP_DELAY_MS || (21 * 60 * 1000)
});
operationsEvidenceService = createOperationsEvidenceStore({ pool });
const operationsEvidenceSchemaReady = operationsEvidenceService.ensureSchema().catch(error => {
    console.error('[Operations Evidence] Schema initialization failed:', error.message);
    return { error };
});
const operationsEvidenceAutomation = createOperationsEvidenceAutomation({
    collectAll: async options => {
        const schema = await operationsEvidenceSchemaReady;
        if (schema?.error) throw schema.error;
        return collectOperationsEvidenceForConfiguredTenants(options);
    },
    enabled: !['false', '0', 'no'].includes(String(process.env.OPERATIONS_EVIDENCE_COLLECTION_ENABLED || 'true').toLowerCase()),
    intervalMs: process.env.OPERATIONS_EVIDENCE_COLLECTION_INTERVAL_MS || (30 * 60 * 1000),
    startupDelayMs: process.env.OPERATIONS_EVIDENCE_COLLECTION_STARTUP_DELAY_MS || (23 * 60 * 1000)
});
const stackCTRLIntelligenceService = createStackCTRLIntelligenceService({
    pool,
    azureOpenAI: azureOpenAIService,
    refreshSource: refreshStackCTRLIntelligenceSource
});
const stackCTRLIntelligenceScheduler = createStackCTRLIntelligenceScheduler({
    pool,
    intelligenceService: stackCTRLIntelligenceService
});
const enterpriseIntelligenceService = createEnterpriseIntelligenceService({
    pool,
    azureOpenAI: azureOpenAIService,
    schedulerService: stackCTRLIntelligenceScheduler,
    intelligenceService: stackCTRLIntelligenceService,
    onScheduledRunCompleted: finalizeSunbirdDailyAutomation
});
const stackCTRLIntelligenceAutomation = createStackCTRLServerAutomation({
    schedulerService: stackCTRLIntelligenceScheduler,
    enabled: !['false', '0', 'no'].includes(String(process.env.STACKCTRL_SERVER_AUTOMATION_ENABLED || 'true').toLowerCase()),
    intervalMs: process.env.STACKCTRL_SERVER_AUTOMATION_INTERVAL_MS,
    startupDelayMs: process.env.STACKCTRL_SERVER_AUTOMATION_STARTUP_DELAY_MS
});
const enterpriseDailyIntelligenceScheduler = {
    runScheduledTick: options => enterpriseIntelligenceService.runDailyAutomationTick(options)
};
const enterpriseIntelligenceAutomation = createStackCTRLServerAutomation({
    schedulerService: enterpriseDailyIntelligenceScheduler,
    enabled: ['true', '1', 'yes'].includes(String(process.env.ENTERPRISE_AI_AUTOMATION_ENABLED || 'false').toLowerCase()),
    intervalMs: process.env.ENTERPRISE_AI_AUTOMATION_INTERVAL_MS || (15 * 60 * 1000),
    startupDelayMs: process.env.ENTERPRISE_AI_AUTOMATION_STARTUP_DELAY_MS || (60 * 1000)
});
function parseCloudSchedulerScheduleTime(value, receivedAt = new Date()) {
    const received = DateTime.fromJSDate(receivedAt instanceof Date ? receivedAt : new Date(receivedAt), { zone: 'utc' });
    const raw = String(value || '').trim();
    if (!raw || !received.isValid) return received.isValid ? received.toJSDate() : new Date();
    const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw);
    const parsed = DateTime.fromISO(raw, hasZone
        ? { setZone: true }
        : { zone: SUNBIRD_REPORT_TIME_ZONE });
    if (!parsed.isValid) return received.toJSDate();
    const scheduled = parsed.toUTC();
    // A Scheduler retry carries its original time and is valid. A manual/forced
    // request can carry a future nominal schedule time; never let that move a
    // daily key into tomorrow. Use the actual received instant in that case.
    if (scheduled > received.plus({ minutes: 5 })) {
        console.warn('[StackCTRL Enterprise Pipeline]', {
            event: 'future_scheduler_time_rejected',
            scheduledTime: scheduled.toISO(),
            receivedAt: received.toISO(),
            timeZone: SUNBIRD_REPORT_TIME_ZONE
        });
        return received.toJSDate();
    }
    return scheduled.toJSDate();
}

function hasValidEnterpriseAutomationTrigger(req) {
    const expected = String(process.env.STACKCTRL_AUTOMATION_TRIGGER_SECRET || '');
    const provided = String(req.get('x-stackctrl-automation-key') || '');
    if (!expected || !provided) return false;
    const expectedBuffer = Buffer.from(expected, 'utf8');
    const providedBuffer = Buffer.from(provided, 'utf8');
    return expectedBuffer.length === providedBuffer.length
        && crypto.timingSafeEqual(expectedBuffer, providedBuffer);
}

// Cloud Run can suspend an idle instance, so a secure Cloud Scheduler request is
// the reliable trigger. The legacy hourly path remains compatible, but now obeys
// the daily Johannesburg schedule; use the explicit daily path for a forced retry.
app.post(['/api/internal/automation/enterprise-hourly', '/api/internal/automation/enterprise-daily'], async (req, res) => {
    if (!String(process.env.STACKCTRL_AUTOMATION_TRIGGER_SECRET || '')) {
        return res.status(503).json({ success: false, message: 'Enterprise automation trigger is not configured.' });
    }
    if (!hasValidEnterpriseAutomationTrigger(req)) {
        return res.status(403).json({ success: false, message: 'Invalid enterprise automation trigger.' });
    }
    const isExplicitDailyTrigger = req.path.endsWith('/enterprise-daily');
    const scheduledTimeHeader = String(req.get('x-cloudscheduler-scheduletime') || '').trim();
    const triggerTime = parseCloudSchedulerScheduleTime(scheduledTimeHeader);
    const operation = beginSunbirdOperation(req, 'enterprise_daily_trigger');
    try {
        const result = await enterpriseIntelligenceService.runDailyAutomationTick({ now: triggerTime, force: isExplicitDailyTrigger });
        const companies = Array.isArray(result?.companies) ? result.companies : [];
        const responseStatus = result?.status === 'failed' ? 500 : 200;
        operation.finish(responseStatus, { companies: companies.length, localTime: result?.localTime || null, status: result?.status || null });
        return res.status(responseStatus).json({ success: responseStatus < 400, ...result });
    } catch (error) {
        operation.step('enterprise_daily_trigger_failed', { error: error.message, stack: String(error.stack || '').slice(0, 1800) });
        operation.finish(500, { error: error.message });
        return res.status(500).json({ success: false, message: error.message });
    }
});
const adminIntelligenceService = createAdminIntelligenceService({
    pool,
    azureOpenAI: azureOpenAIService,
    intelligenceService: stackCTRLIntelligenceService,
    schedulerService: stackCTRLIntelligenceScheduler,
    automationService: stackCTRLIntelligenceAutomation,
    defaultOutputTypes: DEFAULT_OUTPUT_TYPES
});
const powerBIReportingService = createPowerBIReportingService({
    pool,
    getSecret
});

app.use('/api/stackctrl/intelligence', createStackCTRLIntelligenceRouter({
    authenticateToken,
    getAccessContextByUser,
    intelligenceService: stackCTRLIntelligenceService,
    schedulerService: stackCTRLIntelligenceScheduler,
    automationService: stackCTRLIntelligenceAutomation
}));
app.use('/api/admin/intelligence', createAdminIntelligenceRouter({
    authenticateToken,
    adminIntelligenceService,
    enterpriseIntelligenceService
}));
app.use('/api/powerbi', createPowerBIReportingRouter({
    reportingService: powerBIReportingService,
    enterpriseIntelligenceService
}));
app.get('/admin/intelligence', (_req, res) => {
    res.set('Cache-Control', 'no-store');
    res.sendFile(path.join(__dirname, 'admin-intelligence.html'));
});

// We freeze currently stored tenant data after deployment so the intelligence history starts immediately.
setTimeout(() => {
    stackCTRLIntelligenceService.bootstrapAvailableTenants().catch(error => {
        console.error('[StackCTRL Intelligence] Deployment bootstrap failed:', error.message);
    });
}, 15000);

// ============================================
// SYSTEM PROMPT
// ============================================
const CHATBOT_SYSTEM_PROMPT = `You are StackOn, AI Assistant for Stack Ops IT Solutions. Communicate as a team member using "we", "us", "our". Be professional, friendly, concise (1-3 lines).

CORE RULES:
1. NEVER hallucinate client data - only use data explicitly provided in system messages
2. Dates, amounts, invoice numbers must match database exactly - never infer or guess
3. Present data naturally: "Invoice #12345, R5,000.00 due January 15" not "invoice_number: 12345, total_amount: 5000"
4. Always end responses with relevant buttons: [[View Latest Invoice]] [[Make Payments]] [[Project Updates]] [[Ticket Status]]
5. When user needs data, output ONLY pure JSON: {"type":"action","action":"get_latest_invoice","params":{},"confidence":0.9,"needs_clarification":false}
6. NEVER mix JSON with text - no "I will fetch..." or "Here's the request..." - JSON only

ACTIONS: get_latest_invoice, get_all_invoices, get_invoice_details, get_project_updates, get_security_analytics, get_ticket_status, get_payment_info

BUTTONS: [[View Latest Invoice]] [[View All Invoices]] [[Make Payments]] [[Project Updates]] [[Security Analytics]] [[Ticket Status]]

If data unavailable, say: "I don't have that information. Would you like me to check your records?"`;

async function saveChatMessage(userId, role, content) {
    try {
        await pool.query(
            "INSERT INTO ChatHistory (UserID, Role, Content) VALUES (?, ?, ?)",
            [userId, role, content.slice(0, 2000)]
        );
    } catch (error) {
        console.error('Error saving chat message:', error);
        // Don't throw - allow conversation to continue even if history save fails
    }
}

async function getChatHistory(userId, limit = 12) {
    try {
        // Fixed query - more efficient ordering
        const [rows] = await pool.query(
            `SELECT Role, Content FROM ChatHistory
             WHERE UserID = ?
             ORDER BY ID ASC
             LIMIT ?`,
            [userId, limit]
        );

        return rows.map(r => ({
            role: r.Role,
            content: r.Content
        }));
    } catch (error) {
        console.error('Error getting chat history:', error);
        return []; // Return empty array on error to allow conversation to continue
    }
}

// Store and retrieve user context from database
async function getUserContext(userId) {
    try {
        const [rows] = await pool.query(
            `SELECT ContextData FROM UserContext WHERE UserID = ? LIMIT 1`,
            [userId]
        );
        
        if (rows.length > 0 && rows[0].ContextData) {
            return JSON.parse(rows[0].ContextData);
        }
        return {};
    } catch (error) {
        // If table doesn't exist, return empty context
        if (error.code === 'ER_NO_SUCH_TABLE') {
            return {};
        }
        console.error('Error getting user context:', error);
        return {};
    }
}

async function saveUserContext(userId, context) {
    try {
        const contextJson = JSON.stringify(context);
        await pool.query(
            `INSERT INTO UserContext (UserID, ContextData, UpdatedAt) 
             VALUES (?, ?, NOW()) 
             ON DUPLICATE KEY UPDATE ContextData = ?, UpdatedAt = NOW()`,
            [userId, contextJson, contextJson]
        );
    } catch (error) {
        // If table doesn't exist, silently fail (graceful degradation)
        if (error.code === 'ER_NO_SUCH_TABLE') {
            console.warn('UserContext table does not exist. Context will not be persisted.');
            return;
        }
        console.error('Error saving user context:', error);
        // Don't throw - context is not critical
    }
}

// ============================================
// DATA FETCHING
// ============================================

async function fetchClientData(action, companyId, params = {}) {
    if (!pool) throw new Error('Database connection unavailable');
    
    // Validate companyId is provided
    if (!companyId) {
        return { message: "Company information is required to fetch data." };
    }

    switch (action) {
        case "get_latest_invoice":
            return getLatestInvoice(companyId);
        case "get_all_invoices":
            return getAllInvoices(companyId);
        case "get_invoice_details":
            const invoiceNumber = params.invoice_number;
            if (!invoiceNumber) return { message: "Invoice number is required." };
            return getInvoiceDetails(companyId, invoiceNumber);
        case "get_project_updates":
            return getProjectUpdates(companyId);
        case "get_security_analytics":
            return getSecurityAnalytics(companyId);
        case "get_ticket_status":
            return getTicketStatus(companyId);
        case "get_payment_info":
            return getPaymentInfo(companyId, params.invoice_number || null);
        default:
            return { message: "No data available for this request." };
    }
}

async function getLatestInvoice(companyId) {
    const [invoices] = await pool.query(
        `SELECT i.InvoiceID, i.InvoiceNumber, i.InvoiceDate, i.DueDate,
                i.TotalAmount, i.Status, c.CompanyName
         FROM Invoices i
         LEFT JOIN Companies c ON i.CompanyID = c.ID
         WHERE i.CompanyID = ?
         ORDER BY i.InvoiceDate DESC
         LIMIT 1`,
        [companyId]
    );

    if (!invoices.length) return { 
        has_data: false,
        data_type: "invoice",
        message: "No invoices found in your account."
    };

    const invoice = invoices[0];

    // Fetch invoice items
    const [items] = await pool.query(
        `SELECT Description, Quantity, UnitPrice, Amount
         FROM InvoiceItems
         WHERE InvoiceID = ?`,
        [invoice.InvoiceID]
    );

    // Fetch payments and calculate total paid
    const [payments] = await pool.query(
        `SELECT AmountPaid, PaymentDate, Method
         FROM Payments
         WHERE InvoiceID = ?
         ORDER BY PaymentDate DESC`,
        [invoice.InvoiceID]
    );

    const totalPaid = payments.reduce((sum, p) => sum + parseFloat(p.AmountPaid || 0), 0);
    const balance = parseFloat(invoice.TotalAmount) - totalPaid;
    
    // Format dates - convert ISO strings to YYYY-MM-DD format
    const formatDate = (dateValue) => {
        if (!dateValue) return '';
        if (dateValue instanceof Date) {
            return dateValue.toISOString().split('T')[0];
        }
        const dateStr = String(dateValue);
        // If it's an ISO string like "2026-01-09T00:00:00.000Z", extract just the date part
        if (dateStr.includes('T')) {
            return dateStr.split('T')[0];
        }
        return dateStr;
    };
    
    const invoiceDate = formatDate(invoice.InvoiceDate);
    const dueDate = formatDate(invoice.DueDate);
    
    console.log('DEBUG getLatestInvoice: Date formatting:', {
        InvoiceNumber_raw: invoice.InvoiceNumber,
        InvoiceNumber_formatted: String(invoice.InvoiceNumber || ''),
        InvoiceDate_raw: invoice.InvoiceDate,
        InvoiceDate_formatted: invoiceDate,
        DueDate_raw: invoice.DueDate,
        DueDate_formatted: dueDate
    });

    return {
        has_data: true,
        data_type: "invoice",
        invoice_number: String(invoice.InvoiceNumber || ''),
        invoice_date: invoiceDate,
        due_date: dueDate,
        total_amount: parseFloat(invoice.TotalAmount).toFixed(2),
        status: invoice.Status,
        company_name: invoice.CompanyName,
        items: items.map(i => ({
            description: i.Description,
            quantity: i.Quantity,
            unit_price: parseFloat(i.UnitPrice).toFixed(2),
            amount: parseFloat(i.Amount).toFixed(2)
        })),
        payments: payments.map(p => ({
            amount_paid: parseFloat(p.AmountPaid).toFixed(2),
            payment_date: p.PaymentDate,
            method: p.Method
        })),
        total_paid: totalPaid.toFixed(2),
        outstanding_balance: balance.toFixed(2)
    };
}

async function getAllInvoices(companyId) {
    const [invoices] = await pool.query(
        `SELECT InvoiceID, InvoiceNumber, InvoiceDate, DueDate, TotalAmount, Status
         FROM Invoices
         WHERE CompanyID = ?
         ORDER BY InvoiceDate DESC`,
        [companyId]
    );

    if (!invoices.length) return { 
        has_data: false,
        data_type: "invoices",
        message: "No invoices found in your account."
    };

    const results = [];
    for (const invoice of invoices) {
        // Fetch payments for each invoice
        const [payments] = await pool.query(
            `SELECT AmountPaid
             FROM Payments
             WHERE InvoiceID = ?`,
            [invoice.InvoiceID]
        );

        const totalPaid = payments.reduce((sum, p) => sum + parseFloat(p.AmountPaid || 0), 0);
        const balance = parseFloat(invoice.TotalAmount) - totalPaid;

        results.push({
            invoice_number: invoice.InvoiceNumber,
            invoice_date: invoice.InvoiceDate,
            due_date: invoice.DueDate,
            total_amount: parseFloat(invoice.TotalAmount).toFixed(2),
            status: invoice.Status,
            total_paid: totalPaid.toFixed(2),
            outstanding_balance: balance.toFixed(2)
        });
    }

    return {
        has_data: true,
        data_type: "invoices",
        total_count: invoices.length,
        invoices: results
    };
}

async function getInvoiceDetails(companyId, invoiceNumber) {
    const [invoices] = await pool.query(
        `SELECT i.InvoiceID, i.InvoiceNumber, i.InvoiceDate, i.DueDate,
                i.TotalAmount, i.Status, c.CompanyName
         FROM Invoices i
         LEFT JOIN Companies c ON i.CompanyID = c.ID
         WHERE i.CompanyID = ? AND i.InvoiceNumber = ?`,
        [companyId, invoiceNumber]
    );

    if (!invoices.length) return { 
        has_data: false,
        data_type: "invoice",
        invoice_number: invoiceNumber,
        message: `Invoice #${invoiceNumber} not found in your account.`
    };

    const invoice = invoices[0];

    // Fetch items and payments as in getLatestInvoice
    const [items] = await pool.query(
        `SELECT Description, Quantity, UnitPrice, Amount
         FROM InvoiceItems
         WHERE InvoiceID = ?`,
        [invoice.InvoiceID]
    );

    const [payments] = await pool.query(
        `SELECT AmountPaid, PaymentDate, Method
         FROM Payments
         WHERE InvoiceID = ?`,
        [invoice.InvoiceID]
    );

    const totalPaid = payments.reduce((sum, p) => sum + parseFloat(p.AmountPaid || 0), 0);
    const balance = parseFloat(invoice.TotalAmount) - totalPaid;
    
    // Format dates - convert ISO strings to YYYY-MM-DD format
    const formatDate = (dateValue) => {
        if (!dateValue) return '';
        if (dateValue instanceof Date) {
            return dateValue.toISOString().split('T')[0];
        }
        const dateStr = String(dateValue);
        // If it's an ISO string like "2026-01-09T00:00:00.000Z", extract just the date part
        if (dateStr.includes('T')) {
            return dateStr.split('T')[0];
        }
        return dateStr;
    };
    
    const invoiceDate = formatDate(invoice.InvoiceDate);
    const dueDate = formatDate(invoice.DueDate);
    
    console.log('DEBUG getInvoiceDetails: Date formatting:', {
        InvoiceNumber_raw: invoice.InvoiceNumber,
        InvoiceNumber_formatted: String(invoice.InvoiceNumber || ''),
        InvoiceDate_raw: invoice.InvoiceDate,
        InvoiceDate_formatted: invoiceDate,
        DueDate_raw: invoice.DueDate,
        DueDate_formatted: dueDate
    });

    return {
        has_data: true,
        data_type: "invoice",
        invoice_number: String(invoice.InvoiceNumber || ''),
        invoice_date: invoiceDate,
        due_date: dueDate,
        total_amount: parseFloat(invoice.TotalAmount).toFixed(2),
        status: invoice.Status,
        company_name: invoice.CompanyName,
        items: items.map(i => ({
            description: i.Description,
            quantity: i.Quantity,
            unit_price: parseFloat(i.UnitPrice).toFixed(2),
            amount: parseFloat(i.Amount).toFixed(2)
        })),
        payments: payments.map(p => ({
            amount_paid: parseFloat(p.AmountPaid).toFixed(2),
            payment_date: p.PaymentDate,
            method: p.Method
        })),
        total_paid: totalPaid.toFixed(2),
        outstanding_balance: balance.toFixed(2)
    };
}

async function getProjectUpdates(companyId) {
    const [projects] = await pool.query(
        `SELECT ProjectID, ProjectName, Status, EndDate
         FROM Projects
         WHERE CompanyID = ?
         ORDER BY EndDate DESC`,
        [companyId]
    );

    if (!projects.length) return { 
        has_data: false,
        data_type: "projects",
        message: "No projects found in your account."
    };

    const results = [];
    for (const project of projects) {
        const [updates] = await pool.query(
            `SELECT UpdateText, UpdateDate
             FROM ProjectUpdates
             WHERE ProjectID = ?
             ORDER BY UpdateDate DESC
             LIMIT 3`,
            [project.ProjectID]
        );
        results.push({
            project_name: project.ProjectName,
            status: project.Status,
            due_date: project.DueDate,
            latest_updates: updates.map(u => ({
                text: u.UpdateText,
                date: u.UpdateDate
            }))
        });
    }

    return { 
        has_data: true,
        data_type: "projects",
        projects: results 
    };
}

async function getSecurityAnalytics(companyId) {
    // Placeholder as tables don't exist yet
    return { 
        message: "Security analytics data is currently being integrated. Please check back soon for real-time risk scores and audit reports.",
        status: "Coming Soon"
    };
}

async function getTicketStatus(companyId) {
    return {
        message: "Support ticket tracking is currently being migrated. For urgent issues, please contact support@stackopsit.co.za.",
        status: "Coming Soon"
    };
}

async function getPaymentInfo(companyId, invoiceNumber = null) {
    try {
        // Get latest invoice if no invoice number provided
        if (!invoiceNumber) {
            const latestInvoice = await getLatestInvoice(companyId);
            if (!latestInvoice.has_data) {
                return {
                    has_data: false,
                    data_type: "payment_info",
                    message: "No invoices found. Payment information will be available once you have an invoice."
                };
            }
            invoiceNumber = latestInvoice.invoice_number;
        }

        // Get company details for payment reference
        let companyName = 'Your Company';
        try {
            const [companies] = await pool.query('SELECT CompanyName FROM Companies WHERE ID = ?', [companyId]);
            companyName = companies[0]?.CompanyName || 'Your Company';
        } catch (error) {
            console.error('Error fetching company name:', error);
        }

        // Try to get payment info from database (CompanySettings table) or use defaults
        let paymentConfig = {
            bank_name: process.env.PAYMENT_BANK_NAME || "Standard Bank",
            account_name: process.env.PAYMENT_ACCOUNT_NAME || "Stack Ops IT Solutions",
            account_number: process.env.PAYMENT_ACCOUNT_NUMBER || "1234567890",
            branch_code: process.env.PAYMENT_BRANCH_CODE || "051001",
            swift_code: process.env.PAYMENT_SWIFT_CODE || "SBZAJJXXX",
            payment_link_base: process.env.PAYMENT_LINK_BASE || "https://payments.stackopsit.co.za/invoice/"
        };

        // Try to get from CompanySettings table if it exists
        try {
            const [settings] = await pool.query(
                `SELECT SettingKey, SettingValue FROM CompanySettings 
                 WHERE CompanyID = ? AND SettingKey IN ('bank_name', 'account_name', 'account_number', 'branch_code', 'swift_code', 'payment_link_base')`,
                [companyId]
            );
            
            settings.forEach(setting => {
                if (paymentConfig.hasOwnProperty(setting.SettingKey)) {
                    paymentConfig[setting.SettingKey] = setting.SettingValue;
                }
            });
        } catch (error) {
            // Table might not exist, use environment variables or defaults
            if (error.code !== 'ER_NO_SUCH_TABLE') {
                console.error('Error fetching payment settings:', error);
            }
        }

        return {
            has_data: true,
            data_type: "payment_info",
            invoice_number: invoiceNumber,
            company_name: companyName,
            payment_reference: `INV-${invoiceNumber}`,
            bank_name: paymentConfig.bank_name,
            account_name: paymentConfig.account_name,
            account_number: paymentConfig.account_number,
            branch_code: paymentConfig.branch_code,
            payment_link: paymentConfig.payment_link_base + invoiceNumber,
            swift_code: paymentConfig.swift_code,
            instructions: `Please use invoice number ${invoiceNumber} as your payment reference when making payment.`
        };
    } catch (error) {
        console.error('Error in getPaymentInfo:', error);
        throw error;
    }
}

const ALLOWED_ACTIONS = [
    "get_latest_invoice",
    "get_all_invoices",
    "get_project_updates",
    "get_security_analytics",
    "get_ticket_status",
    "get_invoice_details",
    "get_payment_info"
];

function sanitizeResponse(text) {
    if (!text || typeof text !== 'string') {
        return "I apologize, but I'm having trouble processing that request. Could you please rephrase your question?";
    }
    
    let trimmed = text.trim();
    
    // Reject pure JSON responses
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || 
        (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        try {
            JSON.parse(trimmed);
            return "I apologize, but I encountered an issue processing that. Could you please rephrase your question?";
        } catch (e) {
            // Not valid JSON, continue
        }
    }
    
    // Remove only action JSON patterns that leaked through - be very specific
    let cleaned = text.replace(/\{\s*"type"\s*:\s*"action"[^}]*\}/g, '');
    
    // Remove system markers
    cleaned = cleaned.replace(/SYSTEM\s*DATA[\s\S]*?(\n\n|$)/gi, "");
    cleaned = cleaned.replace(/Database\s*Data[\s\S]*?(\n\n|$)/gi, "");
    
    // Clean whitespace
    cleaned = cleaned.replace(/\s{3,}/g, ' ').trim();
    
    // Validate result
    if (cleaned.length < 3 || cleaned.includes('"type"') && cleaned.includes('"action"')) {
        return "I apologize, but I'm having trouble processing that request. Could you please rephrase your question?";
    }
    
    return cleaned.slice(0, 1500);
}

//==================================================================================================================================//
//                                                        Chatbot setup here                                                        //                
//==================================================================================================================================//

// Chatbot helper functions
function getClientData(clientId) {
    return new Promise(async (resolve, reject) => {
        try {
            // Get client from Users table
            const [users] = await pool.query(`
                SELECT 
                    ID AS id,
                    CompanyID AS companyId,
                    FirstName AS firstName,
                    LastName AS lastName,
                    Email AS email,
                    Contact AS contact
                FROM Users 
                WHERE ID = ? AND Role = 'client'
            `, [clientId]);
            
            if (users.length === 0) {
                return reject(new Error('Client not found'));
            }

            const companyId = users[0].companyId;
            
            const [projects] = await pool.query('SELECT * FROM Projects WHERE CompanyID = ?', [companyId]);
            const [invoices] = await pool.query('SELECT * FROM Invoices WHERE CompanyID = ?', [companyId]);
            
            // Get Duo Stats
            const [duoRows] = await pool.query(`
                SELECT cds.used_licenses, cds.total_licenses, cds.edition, cds.last_updated, cds.status 
                FROM client_duo_stats cds
                JOIN user_duo_accounts uda ON cds.id = uda.duo_id
                WHERE uda.user_id = ?
            `, [clientId]);

            resolve({
                client: {
                    id: users[0].id,
                    companyId: companyId,
                    name: `${users[0].firstName} ${users[0].lastName}`.trim(),
                    email: users[0].email,
                    phone: users[0].contact
                },
                projects: projects,
                invoices: invoices,
                duoStats: duoRows.length > 0 ? duoRows[0] : null
            });
        } catch (err) {
            reject(err);
        }
    });
}

function detectPaymentIntent(message) {
    const paymentKeywords = [
        'pay', 'payment', 'make payment', 'pay invoice', 'settle',
        'pay now', 'payment link', 'how to pay', 'where to pay',
        'want to pay', 'pay my invoice', 'clear my balance'
    ];
    
    const lowerMessage = message.toLowerCase();
    return paymentKeywords.some(keyword => lowerMessage.includes(keyword));
}

async function createPaymentLink(invoiceId, clientId, companyId, amount, description) {
    try {
        const [invoices] = await pool.query(
            'SELECT * FROM Invoices WHERE InvoiceID = ? AND CompanyID = ?',
            [invoiceId, companyId]
        );

        if (invoices.length === 0) {
            throw new Error('Invoice not found');
        }

        const invoice = invoices[0];

        if (invoice.Status === 'Paid') {
            throw new Error('Invoice is already paid');
        }

        // Get Yoco secret key
        const yocoSecretKey = process.env.YOCO_SECRET_KEY || await getSecret('YOCO_SECRET_KEY');
        if (!yocoSecretKey) {
            throw new Error('YOCO secret key not configured');
        }

        const response = await fetch('https://payments.yoco.com/api/checkouts', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${yocoSecretKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                amount: Math.round(parseFloat(amount) * 100),
                currency: 'ZAR',
                description: description || `Invoice #${invoiceId} Payment`,
                metadata: {
                    invoiceId: invoiceId.toString(),
                    client_id: clientId.toString()
                }
            })
        });

        if (!response.ok) {
            throw new Error('Failed to create payment link');
        }

        const data = await response.json();

        // Store in yoco_payments table
        await pool.query(
            "INSERT INTO yoco_payments (invoice_id, yoco_checkout_id, redirect_url, amount, status) VALUES (?, ?, ?, ?, 'pending')",
            [invoiceId, data.id, data.redirectUrl, Math.round(parseFloat(amount) * 100)]
        );

        return {
            success: true,
            paymentUrl: data.redirectUrl,
            checkoutId: data.id,
            amount: amount,
            invoiceId: invoiceId
        };

    } catch (error) {
        console.error('Payment link creation error:', error);
        throw error;
    }
}

async function createBulkPaymentLink(clientId, companyId, invoiceIds) {
    try {
        const [invoices] = await pool.query(
            `SELECT * FROM Invoices 
            WHERE InvoiceID IN (?) AND CompanyID = ? AND Status IN ('Unpaid', 'Overdue')`,
            [invoiceIds, companyId]
        );

        if (invoices.length === 0) {
            throw new Error('No unpaid invoices found');
        }

        const totalAmount = invoices.reduce((sum, inv) => sum + parseFloat(inv.TotalAmount), 0);
        const yocoSecretKey = process.env.YOCO_SECRET_KEY || await getSecret('YOCO_SECRET_KEY');
        
        if (!yocoSecretKey) {
            throw new Error('YOCO secret key not configured');
        }

        const response = await fetch('https://payments.yoco.com/api/checkouts', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${yocoSecretKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                amount: Math.round(totalAmount * 100),
                currency: 'ZAR',
                description: `Bulk Payment for ${invoices.length} Invoices`,
                metadata: {
                    invoice_ids: invoiceIds.join(','),
                    client_id: clientId.toString()
                }
            })
        });

        if (!response.ok) {
            throw new Error('Failed to create bulk payment link');
        }

        const data = await response.json();

        // Store each invoice payment
        for (const invoice of invoices) {
            await pool.query(
                "INSERT INTO yoco_payments (invoice_id, yoco_checkout_id, redirect_url, amount, status) VALUES (?, ?, ?, ?, 'pending')",
                [invoice.InvoiceID, data.id, data.redirectUrl, Math.round(parseFloat(invoice.TotalAmount) * 100)]
            );
        }

        return {
            success: true,
            paymentUrl: data.redirectUrl,
            checkoutId: data.id,
            totalAmount: totalAmount,
            invoiceCount: invoices.length
        };

    } catch (error) {
        console.error('Bulk payment link creation error:', error);
        throw error;
    }
}

// Chatbot endpoint
app.post('/api/chat', authenticateToken, chatRateLimit, async (req, res) => {
    const { message } = req.body;
    const clientId = req.user.id;
    
    if (!message) {
        return res.status(400).json({ 
            success: false,
            error: 'Message is required' 
        });
    }
    
    try {
        const clientData = await getClientData(clientId);
        
        const unpaidInvoices = clientData.invoices.filter(
            inv => inv.Status === 'Unpaid' || inv.Status === 'Overdue'
        );
        const totalOwed = unpaidInvoices.reduce(
            (sum, inv) => sum + parseFloat(inv.TotalAmount), 0
        );
        
        const wantsToMakePayment = detectPaymentIntent(message);
        
        if (wantsToMakePayment && unpaidInvoices.length > 0) {
            let paymentResponse = '';
            let paymentUrl = null;
            
            if (unpaidInvoices.length === 1) {
                const invoice = unpaidInvoices[0];
                try {
                    const payment = await createPaymentLink(
                        invoice.InvoiceID,
                        clientId,
                        clientData.client.companyId,
                        invoice.TotalAmount,
                        `Payment for Invoice #${invoice.InvoiceID}`
                    );
                    
                    paymentUrl = payment.paymentUrl;
                    paymentResponse = `I've generated a secure payment link for your invoice #${invoice.InvoiceID} (R${parseFloat(invoice.TotalAmount).toFixed(2)}).`;
                    
                } catch (error) {
                    console.error('Payment link generation error:', error);
                    paymentResponse = `I encountered an issue generating your payment link. Please contact support or try again later.`;
                }
            } else {
                try {
                    const invoiceIds = unpaidInvoices.map(inv => inv.InvoiceID);
                    const payment = await createBulkPaymentLink(
                        clientId,
                        clientData.client.companyId,
                        invoiceIds
                    );
                    
                    paymentUrl = payment.paymentUrl;
                    paymentResponse = `I've generated a payment link to settle all your outstanding invoices (${payment.invoiceCount} invoices totaling R${payment.totalAmount.toFixed(2)}).`;
                    
                } catch (error) {
                    console.error('Bulk payment link generation error:', error);
                    paymentResponse = `I encountered an issue generating your payment link. Please contact support or try again later.`;
                }
            }
            
            return res.json({
                success: true,
                message: paymentResponse,
                hasPaymentLink: true,
                paymentUrl: paymentUrl,
                totalAmount: totalOwed.toFixed(2),
                invoiceCount: unpaidInvoices.length
            });
        }
        
        const systemPrompt = `You are a helpful assistant for StackOn, a project management company. 
You have access to the following client data:

CLIENT INFO:
- Name: ${clientData.client.name}
- Email: ${clientData.client.email}
- Phone: ${clientData.client.phone}

PROJECTS (${clientData.projects.length} total):
${clientData.projects.map(p => `- "${p.Name}" - Status: ${p.Status} - ${p.Description}`).join('\n') || 'No projects yet'}

INVOICES (${clientData.invoices.length} total):
${clientData.invoices.map(i => `- Invoice #${i.InvoiceID}: R${i.TotalAmount} (${i.Status.toUpperCase()}) - Due: ${i.DueDate}`).join('\n') || 'No invoices yet'}

TOTAL OWED: R${totalOwed.toFixed(2)}

CISCO DUO STATS:
${clientData.duoStats ? `
- Edition: ${clientData.duoStats.edition}
- Status: ${clientData.duoStats.status}
- Used Licenses: ${clientData.duoStats.used_licenses}
- Total Licenses: ${clientData.duoStats.total_licenses}
- Remaining Licenses: ${Math.max(0, clientData.duoStats.total_licenses - clientData.duoStats.used_licenses)}
- Last Updated: ${clientData.duoStats.last_updated}
` : 'No Cisco Duo information available for this account.'}

Answer questions about their projects, invoices, payments, account status, and Cisco Duo license usage. 
Be friendly, helpful, and professional. Use South African Rand (R) for currency.

IMPORTANT: If they ask about making a payment, tell them you can generate a secure payment link for them instantly.`;

        const completion = await azureOpenAIService.createChatCompletion({
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: message }
            ],
            temperature: 0.7,
            maxTokens: 500
        });
        
        const aiResponse = completion.content;
        
        res.json({
            success: true,
            message: aiResponse,
            clientName: clientData.client.name,
            hasPaymentLink: false
        });
        
    } catch (error) {
        console.error('❌ Chat error:', error.message);
        res.status(500).json({ 
            success: false,
            error: 'Failed to process your message', 
            details: error.message 
        });
    }
});

//==================================================================================================================================//
//                                         public Chatbot setup here                                                                //                
//==================================================================================================================================//

// Serve static files from the project root directory
app.use(express.static(__dirname));

// Fallback to signin.html for root requests
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'signin.html'));
});

// ==================== TEST INVOICE PDF ENDPOINT (No Auth Required) ====================
app.get('/test-invoice-pdf', async (req, res) => {
    try {
        const testInvoiceData = {
            InvoiceNumber: '11',
            InvoiceDate: '2026-02-05',
            DueDate: '2026-02-12',
            TotalAmount: 100.00
        };

        const testItems = [
            {
                ServiceCategory: 'Security Audit',
                Deliverables: '0324 Audition',
                Frequency: 'Once-off',
                Rate: '12 hours',
                Total: 10.00
            },
            {
                ServiceCategory: 'Penetration Testing',
                Deliverables: 'Network Pen Test',
                Frequency: 'Once-off',
                Rate: '8 hours',
                Total: 40.00
            },
            {
                ServiceCategory: 'Vulnerability Assessment',
                Deliverables: 'Web App VA',
                Frequency: 'Once-off',
                Rate: '10 hours',
                Total: 50.00
            }
        ];

        const testCompanyData = {
            CompanyName: 'Sands Web',
            address: 'Waterfall City',
            city: 'Johannesburg',
            state: 'GP',
            zipcode: '1685'
        };

        const testClientData = {
            firstname: 'Sands',
            lastname: 'MusiQ',
            email: 'support@stackopsit.co.za'
        };

        const pdfBuffer = await generateInvoicePDF(testInvoiceData, testItems, testCompanyData, testClientData);
        
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'inline; filename="test-invoice.pdf"');
        res.send(pdfBuffer);
    } catch (error) {
        console.error('Error generating test PDF:', error);
        res.status(500).json({ error: 'Failed to generate test PDF', details: error.message });
    }
});

// Serve test HTML page
app.get('/test-invoice', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Invoice PDF Test</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    padding: 20px;
                    background: #f5f5f5;
                }
                .container {
                    max-width: 800px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                h1 {
                    color: #333;
                }
                .button {
                    display: inline-block;
                    background: #007bff;
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 4px;
                    margin: 10px 0;
                    border: none;
                    cursor: pointer;
                    font-size: 16px;
                }
                .button:hover {
                    background: #0056b3;
                }
                .instructions {
                    background: #e7f3ff;
                    border-left: 4px solid #2196F3;
                    padding: 15px;
                    margin: 20px 0;
                }
                .pdf-viewer {
                    margin-top: 30px;
                    width: 100%;
                    height: 800px;
                    border: 1px solid #ddd;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📋 Invoice PDF Test</h1>
                <p>Click the button below to preview the invoice PDF with sample data:</p>
                
                <a href="/test-invoice-pdf" target="_blank" class="button">View Test Invoice PDF</a>
                
                <div class="instructions">
                    <strong>ℹ️ How to use:</strong>
                    <ul>
                        <li>Click "View Test Invoice PDF" to open the PDF in your browser</li>
                        <li>Check the layout, spacing, and formatting</li>
                        <li>No authentication required - this is for local testing only</li>
                        <li>Edit the test data in the endpoint to test different scenarios</li>
                        <li>Make changes to the generateInvoicePDF function and reload to see updates</li>
                    </ul>
                </div>

                <h2>Live Preview:</h2>
                <iframe src="/test-invoice-pdf" class="pdf-viewer"></iframe>
            </div>
        </body>
        </html>
    `);
});

// ────────────────────────────────────────────────────────────────────
// Server Startup
// ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;  // Use PORT env var for Cloud Run

function logProcessFault(event, error) {
    const details = error instanceof Error
        ? { name: error.name, message: error.message, stack: String(error.stack || '').slice(0, 8000) }
        : { message: String(error).slice(0, 2000) };
    console.error('[Process]', JSON.stringify({ event, at: new Date().toISOString(), ...runtimeSnapshot(), ...details }));
}

// Add global error handlers before starting server
process.on('uncaughtException', (error) => {
    logProcessFault('uncaught_exception', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason) => {
    logProcessFault('unhandled_rejection', reason);
});

process.on('warning', (warning) => {
    logProcessFault('node_warning', warning);
});

process.on('exit', (code) => {
    logRuntimeOperation('process_exit', { code });
});

if (require.main === module) {
    const server = app.listen(PORT, async () => {
    let intelligenceSchemaReady = true;
    try {
        await ensureDatabaseSchema();
        console.log('[STARTUP] Intelligence schema is ready before automation startup.');
    } catch (error) {
        intelligenceSchemaReady = false;
        console.error('[STARTUP] Database schema validation failed before automation startup:', error.message);
    }
    const evidenceSchemaResults = await Promise.all([
        identityEvidenceSchemaReady,
        deviceEvidenceSchemaReady,
        emailEvidenceSchemaReady,
        networkEvidenceSchemaReady,
        backupEvidenceSchemaReady,
        applicationsEvidenceSchemaReady,
        securityEvidenceSchemaReady,
        governanceEvidenceSchemaReady,
        complianceEvidenceSchemaReady,
        operationsEvidenceSchemaReady
    ]);
    const evidenceSchemaFailure = evidenceSchemaResults.find(result => result?.error)?.error;
    if (evidenceSchemaFailure) {
        intelligenceSchemaReady = false;
        console.error('[STARTUP] Evidence schema validation failed before automation startup:', evidenceSchemaFailure.message);
    }
    await validateMicrosoftGraphCredentialsAtStartup();
    if (!intelligenceSchemaReady) {
        console.error('[STARTUP] Intelligence automations are stopped because required database schema initialization failed.');
        return;
    }
    identityEvidenceAutomation.start();
    deviceEvidenceAutomation.start();
    emailEvidenceAutomation.start();
    networkEvidenceAutomation.start();
    backupEvidenceAutomation.start();
    applicationsEvidenceAutomation.start();
    securityEvidenceAutomation.start();
    governanceEvidenceAutomation.start();
    complianceEvidenceAutomation.start();
    operationsEvidenceAutomation.start();
    // StackCTRL automation runs inside this server and uses database deduplication across instances.
    stackCTRLIntelligenceAutomation.start();
    // Enterprise reporting runs separately because domain batches may take much longer than compact intelligence.
    enterpriseIntelligenceAutomation.start();
    const memUsage = process.memoryUsage();
    console.log(`\n${'='.repeat(60)}`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📡 Database: ${pool ? 'Connected' : 'Not Available'}`);
    console.log(`🔐 Supabase mode: ${useSupabase ? 'ON' : 'OFF'}`);
    console.log(`💾 Memory: ${Math.round(memUsage.heapUsed / 1024 / 1024)} MB used / ${Math.round(memUsage.heapTotal / 1024 / 1024)} MB allocated`);
    console.log(`📋 Test Invoice PDF: http://localhost:${PORT}/test-invoice`);
    console.log(`${'='.repeat(60)}\n`);
    });

    server.on('error', (error) => {
        console.error('❌ Server error:', error);
        process.exit(1);
    });

    function stopServer(signal) {
    console.log(`[StackCTRL] ${signal} received. Stopping server automation.`);
    identityEvidenceAutomation.stop();
    deviceEvidenceAutomation.stop();
    emailEvidenceAutomation.stop();
    networkEvidenceAutomation.stop();
    backupEvidenceAutomation.stop();
    applicationsEvidenceAutomation.stop();
    securityEvidenceAutomation.stop();
    governanceEvidenceAutomation.stop();
    complianceEvidenceAutomation.stop();
    operationsEvidenceAutomation.stop();
    stackCTRLIntelligenceAutomation.stop();
    enterpriseIntelligenceAutomation.stop();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
    }

    process.once('SIGTERM', () => stopServer('SIGTERM'));
    process.once('SIGINT', () => stopServer('SIGINT'));

}

// Export PDF generator for testing and tooling when required as a module
exports.generateSunbirdReportPdf = generateSunbirdReportPdf;
